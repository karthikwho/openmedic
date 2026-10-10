"""CLI behaviour: exit codes, JSON mode, and secret-safe output.

These tests drive the real console entry point (``openmedic.cli.app:run``) rather than a
raw Click command, because that is where domain errors are mapped to the documented exit
codes. Testing a different object would silently skip the mapping.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import sys
from pathlib import Path

import pytest

from openmedic.cli.app import run
from openmedic.cli.exit_codes import (
    EXIT_CODES,
    HUMAN_REVIEW_REQUIRED,
    INTEGRATION_UNAVAILABLE,
    INVALID_INPUT,
    OK,
    UNRESOLVED_REPAIR,
    USAGE_ERROR,
    VALIDATION_FAILED,
    exit_code_help,
)
from openmedic.cli.output import (
    Output,
    RedactingFilter,
    RedactingFormatter,
    strip_ansi,
)
from openmedic.domain.errors import HumanReviewRequiredError, OpenMedicError


def run_cli(
    args: list[str], *, stdin_text: str | None = None, cwd: Path | None = None
) -> tuple[int, str, str]:
    """Invoke the console entry point and return (exit_code, stdout, stderr)."""
    old_argv, old_stdin, old_cwd = sys.argv, sys.stdin, Path.cwd()
    sys.argv = ["openmedic", *args]
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    if cwd is not None:
        os.chdir(cwd)

    out, err = io.StringIO(), io.StringIO()
    code: object = 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            run()
    except SystemExit as exc:
        code = exc.code
    finally:
        sys.argv, sys.stdin = old_argv, old_stdin
        os.chdir(old_cwd)
    return (code if isinstance(code, int) else 0), out.getvalue(), err.getvalue()


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENMEDIC_DB", str(tmp_path / "cli-test.db"))
    monkeypatch.delenv("OPENMEDIC_LOG_LEVEL", raising=False)
    monkeypatch.delenv("OPENMEDIC_PROVIDER_TYPE", raising=False)
    monkeypatch.delenv("OPENMEDIC_GITHUB_TOKEN", raising=False)
    return tmp_path


def test_help_lists_commands_and_exit_codes(isolated: Path) -> None:
    code, out, _ = run_cli(["--help"])
    assert code == OK
    for command in ("init", "diagnose", "ingest", "repair", "validate", "benchmark"):
        assert command in out
    for exit_code, _ in EXIT_CODES:
        assert str(exit_code) in out


def test_version_flag_prints_the_distribution_version(isolated: Path) -> None:
    code, out, _ = run_cli(["--version"])
    assert code == OK
    assert out.strip() == "0.1.0"


def test_bare_invocation_shows_help_without_error(isolated: Path) -> None:
    code, out, _ = run_cli([])
    assert code == OK
    assert "Usage:" in out


def test_missing_argument_is_a_usage_error(isolated: Path) -> None:
    code, _, _ = run_cli(["diagnose"])
    assert code == USAGE_ERROR


def test_missing_log_file_reports_invalid_input(isolated: Path) -> None:
    code, _, err = run_cli(["diagnose", "/nonexistent/nope.log"])
    assert code == INVALID_INPUT
    assert "not found" in err


def test_empty_stdin_reports_invalid_input(isolated: Path) -> None:
    code, _, _ = run_cli(["diagnose", "-"], stdin_text="")
    assert code == INVALID_INPUT


def test_diagnose_from_stdin(isolated: Path) -> None:
    code, _, _ = run_cli(
        ["diagnose", "-"],
        stdin_text="ERROR: ModuleNotFoundError: No module named 'requests'\n",
    )
    assert code == OK


def test_json_mode_emits_parseable_json(isolated: Path, tmp_path: Path) -> None:
    log = tmp_path / "build.log"
    log.write_text("ERROR: ModuleNotFoundError: No module named 'requests'\n", encoding="utf-8")
    code, out, _ = run_cli(["--json", "diagnose", str(log)])
    assert code == OK
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:  # pragma: no cover - reported as a hard failure
        pytest.fail(f"stdout was not valid JSON: {out[:400]!r}")
    assert isinstance(payload, dict)


def test_json_mode_keeps_stdout_clean_of_diagnostics(isolated: Path, tmp_path: Path) -> None:
    log = tmp_path / "build.log"
    log.write_text("ERROR: ModuleNotFoundError: No module named 'requests'\n", encoding="utf-8")
    code, out, _ = run_cli(["--json", "diagnose", str(log)])
    assert code == OK
    # Nothing that is not JSON may appear on stdout.
    json.loads(out)


def test_init_is_non_destructive_and_json_serialisable(isolated: Path) -> None:
    before = sorted(p.name for p in isolated.iterdir())
    code, out, _ = run_cli(["--json", "init"])
    assert code == OK
    payload = json.loads(out)
    assert payload["runtimes"]
    after = sorted(p.name for p in isolated.iterdir())
    # init may create the configured local store (gitignored) and its WAL files, but it
    # must never create source, tests, or docs in the working directory.
    created = set(after) - set(before)
    allowed = {name for name in created if name.startswith("cli-test.db") or name == "data"}
    assert allowed == created, f"unexpected entries created by init: {created - allowed}"


def test_init_reports_honest_docker_limitation(isolated: Path) -> None:
    code, out, _ = run_cli(["init"])
    assert code == OK
    assert "Docker" in out
    assert "NOT a hardened sandbox" in out


def test_init_write_refuses_to_overwrite(isolated: Path) -> None:
    (isolated / ".openmedic.toml").write_text("[openmedic]\nlog_level = 'INFO'\n", encoding="utf-8")
    code, _, err = run_cli(["init", "--write"])
    assert code == USAGE_ERROR
    assert "refusing to overwrite" in err


def test_redacting_formatter_strips_secrets() -> None:
    formatter = RedactingFormatter("%(levelname)s %(message)s")
    record = logging.LogRecord(
        "openmedic", logging.INFO, __file__, 1, "token=abcdef1234567890", None, None
    )
    assert "abcdef1234567890" not in formatter.format(record)


def test_redacting_filter_strips_secrets_from_message_and_args() -> None:
    record = logging.LogRecord(
        "openmedic",
        logging.INFO,
        __file__,
        1,
        "key %s",
        ("sk-abcdefghijklmnopqrstuvwxyz012345",),
        None,
    )
    assert RedactingFilter().filter(record) is True
    assert "sk-abcdefghijklmnop" not in str(record.msg) + str(record.args)


def test_strip_ansi_removes_escape_sequences() -> None:
    assert strip_ansi("\x1b[31mred\x1b[0m") == "red"


def test_output_json_mode_writes_only_the_payload() -> None:
    stream = io.StringIO()
    out = Output(json_mode=True, color=False, stream=stream)
    out.emit("human text that should not appear", {"ok": True, "count": 2})
    assert json.loads(stream.getvalue()) == {"ok": True, "count": 2}


def test_output_human_mode_writes_the_text() -> None:
    stream = io.StringIO()
    out = Output(json_mode=False, color=False, stream=stream)
    out.emit("some diagnosis text")
    assert stream.getvalue().strip() == "some diagnosis text"


def test_output_error_goes_to_stderr() -> None:
    stream = io.StringIO()
    out = Output(json_mode=True, stream=stream)
    out.error("something failed", {"detail": "x"})
    assert stream.getvalue() == ""


def test_repair_defaults_to_a_dry_run_and_only_stages_with_apply(isolated: Path) -> None:
    """``repair`` must never write unless ``--apply`` is asked for.

    The flag is declared ``--dry-run/--apply`` and the command hands it to
    ``Services.repair`` as ``apply=...``. Inverting that mapping would make the *default*
    path stage a patch and run checks against a worktree nobody asked for, while
    ``--dry-run`` would silently do the opposite of its name — so the mapping is pinned
    from the outside, through the real entry point.
    """
    from openmedic.domain.enums import FailureType
    from openmedic.ingestion import dump_event_json
    from tests.conftest import make_event

    event = make_event(
        failure_type=FailureType.DEPENDENCY_ERROR,
        logs=(
            "Run python -m pytest tests -q\n"
            "Traceback (most recent call last):\n"
            '  File "tests/test_client.py", line 3, in <module>\n'
            "    import requests\n"
            "ModuleNotFoundError: No module named 'requests'\n"
        ),
    )
    (isolated / "event.json").write_text(dump_event_json(event), encoding="utf-8")
    (isolated / "requirements.txt").write_text("flask\n", encoding="utf-8")

    code, out, _ = run_cli(["ingest", "event.json"])
    assert code == OK, out
    incident_id = out.split()[2]

    code, out, _ = run_cli(["--json", "repair", incident_id])
    assert code == OK, out
    proposed = json.loads(out)
    assert proposed["attempt_id"], "a dry run still records the candidate patch"
    assert "checks_executed" not in proposed, "a dry run must not have run any checks"
    assert (isolated / "requirements.txt").read_text(encoding="utf-8") == "flask\n"

    # --apply is the only path that reaches the worktree and the checks. This tree has
    # no tests, so the required pytest check cannot pass and the command must say so
    # with its documented exit code rather than reporting success.
    code, _, err = run_cli(["--json", "repair", incident_id, "--apply"])
    assert code == VALIDATION_FAILED, err
    assert (isolated / "requirements.txt").read_text(encoding="utf-8") == "flask\n"


def test_repair_reports_human_review_when_the_diagnosis_requires_it(isolated: Path) -> None:
    """A refusal on an incident flagged for review exits 7, not success.

    ``7`` is documented as "the action requires explicit human review before
    proceeding". An automation that only checks the status must not be told that a
    conflicting, human-flagged dependency failure was handled.
    """
    from openmedic.domain.enums import FailureType
    from openmedic.ingestion import dump_event_json
    from tests.conftest import make_event

    event = make_event(
        failure_type=FailureType.DEPENDENCY_ERROR,
        logs=(
            "pip install -r requirements.txt\n"
            "ERROR: Could not find a version that satisfies the requirement requests==99.0.0\n"
            "ERROR: No matching distribution found for requests==99.0.0\n"
        ),
    )
    (isolated / "event.json").write_text(dump_event_json(event), encoding="utf-8")
    (isolated / "requirements.txt").write_text("requests==99.0.0\n", encoding="utf-8")

    code, out, _ = run_cli(["ingest", "event.json"])
    assert code == OK, out
    incident_id = out.split()[2]

    code, out, _ = run_cli(["--json", "repair", incident_id])
    payload = json.loads(out)
    assert code == HUMAN_REVIEW_REQUIRED
    assert payload["proposal"] is None
    assert payload["reason"], "the refusal must explain itself"


def test_repair_reports_an_unresolved_repair_when_it_cannot_propose(isolated: Path) -> None:
    """No playbook applies (nothing to patch), so the repair is unresolved, not a success."""
    from openmedic.domain.enums import FailureType
    from openmedic.ingestion import dump_event_json
    from tests.conftest import make_event

    event = make_event(
        failure_type=FailureType.DEPENDENCY_ERROR,
        logs=(
            "Traceback (most recent call last):\n"
            '  File "tests/test_client.py", line 3, in <module>\n'
            "    import requests\n"
            "ModuleNotFoundError: No module named 'requests'\n"
        ),
    )
    # Deliberately no dependency manifest: there is nothing a playbook may write to.
    (isolated / "event.json").write_text(dump_event_json(event), encoding="utf-8")

    code, out, _ = run_cli(["ingest", "event.json"])
    assert code == OK, out
    incident_id = out.split()[2]

    code, out, _ = run_cli(["--json", "repair", incident_id])
    payload = json.loads(out)
    assert code == UNRESOLVED_REPAIR
    assert payload["proposal"] is None
    assert payload["reason"]


def test_exit_codes_are_unique() -> None:
    codes = [code for code, _ in EXIT_CODES]
    assert len(codes) == len(set(codes))
    assert OK == 0 and USAGE_ERROR == 2


def test_domain_error_carries_its_documented_exit_code() -> None:
    assert HumanReviewRequiredError("x").exit_code == HUMAN_REVIEW_REQUIRED
    assert OpenMedicError("x").exit_code == 1
    assert OpenMedicError("x", detail="d").to_dict()["detail"] == "d"


def test_exit_code_help_renders_every_code() -> None:
    text = exit_code_help()
    for code in (
        OK,
        INVALID_INPUT,
        VALIDATION_FAILED,
        INTEGRATION_UNAVAILABLE,
        UNRESOLVED_REPAIR,
        HUMAN_REVIEW_REQUIRED,
    ):
        assert str(code) in text


def test_unknown_command_is_an_error(isolated: Path) -> None:
    """An unrecognised command must fail loudly, never look like success."""
    code, _, _ = run_cli(["definitely-not-a-command"])
    assert code != 0


def _write_benchmark_corpus(directory: Path, *, log: str, label: str) -> Path:
    """Write a one-case corpus whose label can be made to disagree with the engine."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "case.json").write_text(
        json.dumps(
            {
                "case_id": "cli-case",
                "log": log,
                "expected_failure_type": label,
                "expected_rule_id": None,
                "min_confidence": 0.0,
                "tags": [],
            }
        ),
        encoding="utf-8",
    )
    (directory / "expected.json").write_text(
        json.dumps(
            {
                "targets": {
                    "type_accuracy_min": 1.0,
                    "evidence_verification_rate_min": 1.0,
                    "false_recovery_count_max": 0,
                },
                "cases": {
                    "cli-case": {
                        "expected_failure_type": label,
                        "expected_rule_id": None,
                        "min_confidence": 0.0,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return directory


def test_benchmark_passes_and_reports_its_targets(isolated: Path) -> None:
    """The default corpus meets its targets, so the command succeeds and says so."""
    code, out, _ = run_cli(["benchmark"])

    assert code == OK, out
    assert "targets met" in out
    assert "type accuracy: 1.0000" in out


def test_benchmark_json_payload_carries_the_verdict(isolated: Path) -> None:
    """Automation gets the same verdict as a human, in JSON."""
    code, out, _ = run_cli(["--json", "benchmark"])
    payload = json.loads(out)

    assert code == OK
    assert payload["passed"] is True
    assert payload["type_accuracy"] == 1.0
    assert all(check["passed"] for check in payload["target_checks"])


def test_benchmark_exits_validation_failed_when_a_target_is_missed(isolated: Path) -> None:
    """A corpus the engine cannot meet must exit 4 rather than report and shrug."""
    directory = _write_benchmark_corpus(
        isolated / "cases",
        log="the runner stopped for reasons it did not explain\n",
        label="test_failure",
    )

    code, out, err = run_cli(["benchmark", str(directory)])

    assert code == VALIDATION_FAILED
    assert "TARGETS NOT MET" in out
    assert "type_accuracy" in err


def test_benchmark_rejects_a_directory_that_is_not_a_corpus(isolated: Path) -> None:
    """A missing corpus is an input error with the documented exit code."""
    code, _, err = run_cli(["benchmark", str(isolated / "nope")])

    assert code == INVALID_INPUT
    assert "not found" in err
