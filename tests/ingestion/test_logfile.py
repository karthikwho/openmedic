"""Behavioural tests for local log ingestion: classification, files, and stdin.

These tests assert the two properties the rest of the pipeline depends on:

1. Ingestion is *honest* — the classified failure type is either well-supported by
   the log or ``unknown``, and a bad input raises an :class:`InvalidInputError`
   with a non-empty, actionable message.
2. Ingestion is *non-destructive* — the raw log survives verbatim in
   ``FailureEvent.logs`` so a diagnosis quote can still be verified against it.
"""

from __future__ import annotations

import io
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from openmedic.domain import FailureEvent, FailureType, InvalidInputError, UsageError, utc_now
from openmedic.ingestion import (
    classification_scores,
    classify_log_text,
    describe_classification,
    detect_failed_step,
    detect_job_name,
    ingest_log_file,
    ingest_log_text,
    ingest_stdin,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

#: Every committed log fixture and the failure type it must classify to. The
#: ambiguous fixture is the negative control: no signature means ``unknown``.
FIXTURE_EXPECTATIONS: dict[str, FailureType] = {
    "sample_pytest.log": FailureType.TEST_FAILURE,
    "python_import_error.log": FailureType.SYNTAX_OR_IMPORT_ERROR,
    "npm_dependency_error.log": FailureType.DEPENDENCY_ERROR,
    "build_config_error.log": FailureType.BUILD_OR_CONFIG_ERROR,
    "secret_bearing.log": FailureType.DEPENDENCY_ERROR,
    "ambiguous.log": FailureType.UNKNOWN,
}


def fixture_path(name: str) -> Path:
    """Return the path of a committed fixture inside this test package."""
    path = FIXTURE_DIR / name
    assert path.is_file(), f"missing committed fixture: {path}"
    return path


def read_fixture(name: str) -> str:
    """Return the raw text of a committed fixture, exactly as stored on disk."""
    return fixture_path(name).read_text(encoding="utf-8")


class _FakeTTY:
    """A stream that behaves like an interactive terminal."""

    def __init__(self) -> None:
        self.read_calls = 0

    def isatty(self) -> bool:
        return True

    def read(self) -> str:
        self.read_calls += 1
        return "OPENMEDIC_PROVIDER_API_KEY=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


class _BrokenStream:
    """A stream whose descriptor cannot be read."""

    def isatty(self) -> bool:
        return False

    def read(self) -> str:
        msg = "bad file descriptor"
        raise OSError(msg)


class _NoIsattyStream:
    """A stream-like object without ``isatty`` (some CI shims pass these)."""

    def __init__(self, payload: str) -> None:
        self._payload = payload

    def read(self) -> str:
        return self._payload


# --------------------------------------------------------------------------- #
# Failure-type classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("name", "expected"), sorted(FIXTURE_EXPECTATIONS.items()))
def test_committed_fixtures_classify_as_labelled(name: str, expected: FailureType) -> None:
    """Every fixture ingests to the type labelled next to it in the test table."""
    event = ingest_log_file(fixture_path(name))
    assert event.failure_type is expected, (
        f"{name} classified as {event.failure_type.value!r}, expected {expected.value!r}"
    )


def test_ambiguous_fixture_is_explicitly_unknown() -> None:
    """A log with no failure signature must not be forced into a category."""
    event = ingest_log_file(fixture_path("ambiguous.log"))
    assert event.failure_type is FailureType.UNKNOWN
    assert event.failure_type.value == "unknown"
    # A step name is still recoverable even when the cause is unknown.
    assert event.failed_step == "Run ./scripts/smoke.sh --target staging"


def test_classification_scores_expose_the_competition() -> None:
    """Scores are capped and ordered, so a caller can see how close the call was."""
    scores = classification_scores(read_fixture("sample_pytest.log"))
    assert scores[FailureType.TEST_FAILURE] == 3
    assert scores[FailureType.UNKNOWN] == 0
    assert all(0 <= score <= 3 for score in scores.values())
    assert classification_scores("") == {}


def test_describe_classification_is_readable_and_honest() -> None:
    """The explanation names the selected type, its score, and the rule's wording."""
    ambiguous = describe_classification(read_fixture("ambiguous.log"))
    assert ambiguous.startswith("unknown:")
    assert "no signature" in ambiguous
    failing = describe_classification(read_fixture("sample_pytest.log"))
    assert failing.startswith("test_failure: 3 signature line(s) - ")
    assert "test framework" in failing


def test_classify_log_text_unknown_for_empty_or_unrelated_input() -> None:
    """Classification never raises and never guesses on input without signatures."""
    assert classify_log_text("") is FailureType.UNKNOWN
    assert classify_log_text("   \n\t\n") is FailureType.UNKNOWN
    assert classify_log_text("all checks green, shipping it\n") is FailureType.UNKNOWN


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            # An absent module is an environment/manifest problem, not a defect in the
            # source: this matches the DEP-001 diagnosis the engine reports for it.
            "Traceback (most recent call last):\nModuleNotFoundError: No module named 'pydantic'",
            FailureType.DEPENDENCY_ERROR,
        ),
        (
            '  File "app.py", line 7\n    def f(\nSyntaxError: invalid syntax',
            FailureType.SYNTAX_OR_IMPORT_ERROR,
        ),
        (
            "npm error code ERESOLVE\nnpm error ERESOLVE unable to resolve dependency tree",
            FailureType.DEPENDENCY_ERROR,
        ),
        (
            "ERROR: Could not find a version that satisfies the requirement pytest==9.9",
            FailureType.DEPENDENCY_ERROR,
        ),
        (
            "=== FAILURES ===\nFAILED tests/test_a.py::test_b - AssertionError",
            FailureType.TEST_FAILURE,
        ),
        ("make[1]: *** No rule to make target 'release'. Stop.", FailureType.BUILD_OR_CONFIG_ERROR),
        (
            "ERROR: failed to solve: failed to read dockerfile: open Dockerfile.prod: "
            "no such file or directory",
            FailureType.BUILD_OR_CONFIG_ERROR,
        ),
    ],
)
def test_classification_signatures(text: str, expected: FailureType) -> None:
    """Each documented signature resolves to its own failure type."""
    assert classify_log_text(text) is expected


def test_classification_prefers_the_more_specific_signature_on_a_tie() -> None:
    """With equal scores the earlier (more specific) rule wins, deterministically."""
    tied = (
        "ERROR: could not load config: missing 'version' key\n"
        "ImportError: cannot import name 'x' from 'y'\n"
        "not ok 1 some assertion\n"
    )
    assert classify_log_text(tied) is FailureType.SYNTAX_OR_IMPORT_ERROR


def test_ci_trailer_line_alone_is_not_a_classification() -> None:
    """'Process completed with exit code 1' says nothing about the cause."""
    trailer = "##[group]Run ./deploy.sh\nError: Process completed with exit code 1."
    assert classify_log_text(trailer) is FailureType.UNKNOWN


# --------------------------------------------------------------------------- #
# ingest_log_text
# --------------------------------------------------------------------------- #


def test_ingest_log_text_builds_a_complete_event() -> None:
    """Metadata, classification, and a UTC timestamp all land on the contract."""
    before = utc_now()
    event = ingest_log_text(
        read_fixture("sample_pytest.log"),
        repository="acme/openmedic",
        commit_sha="a" * 40,
        workflow_name="ci",
        run_id="182736451",
        failed_step="Run pytest -q",
        job_name="test-suite (ubuntu-latest)",
    )
    after = utc_now()

    assert isinstance(event, FailureEvent)
    assert event.repository == "acme/openmedic"
    assert event.commit_sha == "a" * 40
    assert event.workflow_name == "ci"
    assert event.run_id == "182736451"
    assert event.failed_step == "Run pytest -q"
    assert event.job_name == "test-suite (ubuntu-latest)"
    assert event.failure_type is FailureType.TEST_FAILURE
    assert event.schema_version == "1.0.0"
    assert event.incident_id is None
    assert before <= event.timestamp <= after
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset() == timedelta(0)


def test_logs_are_kept_raw_and_redacted_copy_redacts() -> None:
    """Ingestion preserves the secret-bearing evidence; only ``redacted()`` cleans it."""
    raw = read_fixture("secret_bearing.log")
    event = ingest_log_text(raw, repository="acme/openmedic", run_id="1")

    assert event.logs == raw.strip(), "raw evidence must survive ingestion for quote verification"
    display = event.redacted()
    assert "npm_aBcD1234567890EfGhIjKlMnOpQrStUv" in event.logs
    assert "npm_aBcD1234567890EfGhIjKlMnOpQrStUv" not in display.logs
    assert "[REDACTED]" in display.logs
    # The original event object is untouched by the redaction helper.
    assert event.logs == raw.strip()


def test_whitespace_only_text_is_rejected() -> None:
    """An empty body is a caller error, not a failure event."""
    for payload in ("", "   ", "\n\n\t  \n"):
        with pytest.raises(InvalidInputError) as excinfo:
            ingest_log_text(payload)
        assert excinfo.value.message.strip(), "the rejection must explain itself"


def test_non_string_log_text_is_rejected() -> None:
    """Bytes must be decoded explicitly; silent decoding hides encoding bugs."""
    with pytest.raises(InvalidInputError) as excinfo:
        ingest_log_text(b"FAILED tests/test_a.py::test_b\n")  # type: ignore[arg-type]
    assert "str" in excinfo.value.message


def test_naive_timestamp_is_rejected_with_a_contract_pointer() -> None:
    """A naive timestamp would silently become a wrong instant; refuse it."""
    with pytest.raises(InvalidInputError) as excinfo:
        naive = datetime(2026, 10, 5, 9, 14, 22)
        ingest_log_text("FAILED tests/test_a.py::test_b\n", timestamp=naive)
    assert "timezone" in excinfo.value.message
    assert "API_CONTRACTS.md" in excinfo.value.message


def test_aware_timestamp_is_preserved_verbatim() -> None:
    """An explicit instant is stored as given, not re-labelled as local time."""
    stamp = datetime(2026, 10, 5, 11, 14, 22, tzinfo=timezone(timedelta(hours=2)))
    event = ingest_log_text("FAILED tests/test_a.py::test_b\n", timestamp=stamp)
    assert event.timestamp == stamp


def test_invalid_metadata_type_is_rejected() -> None:
    """Non-string metadata is a caller error rather than a silently coerced value."""
    with pytest.raises(InvalidInputError) as excinfo:
        ingest_log_text("FAILED tests/test_a.py::test_b\n", run_id=12345)  # type: ignore[arg-type]
    assert "run_id" in excinfo.value.message


# --------------------------------------------------------------------------- #
# Step and job detection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("##[group]Run pytest -q\noutput...", "Run pytest -q"),
        ("##[section]Starting: Run tests\noutput...", "Run tests"),
        ("##[group]Run make build\n##[endgroup]\n##[group]Run make test\noutput", "Run make test"),
        ("Run ./scripts/check.sh\noutput", "Run ./scripts/check.sh"),
        ("setup done\nRun ./scripts/check.sh\nfailing output", "Run ./scripts/check.sh"),
    ],
)
def test_detect_failed_step_recognises_ci_markers(text: str, expected: str) -> None:
    """The last step marker is the one that failed; earlier ones already ended."""
    assert detect_failed_step(text) == expected


def test_detect_failed_step_returns_none_without_markers() -> None:
    """No marker means no invented step name; the GitHub API supplies the real one."""
    assert detect_failed_step("plain output\nno markers here\n") is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("##[job]test-suite (ubuntu-latest)\noutput", "test-suite (ubuntu-latest)"),
        ("Job name: test-suite (ubuntu-latest)\noutput", "test-suite (ubuntu-latest)"),
        ("# job-name: lint\noutput", "lint"),
        ("Starting job: build-dist\noutput", "build-dist"),
        ("##[section]Starting: Job smoke\noutput", "smoke"),
        ("##[job]first\n##[job]second\noutput", "first"),
    ],
)
def test_detect_job_name_recognises_ci_markers(text: str, expected: str) -> None:
    """The first job header wins, because it precedes the job's own output."""
    assert detect_job_name(text) == expected


def test_detect_job_name_returns_none_without_markers() -> None:
    """A missing job name must stay unknown: it is part of the idempotency key."""
    assert detect_job_name("##[group]Run pytest -q\nFAILED tests/test_a.py::test_b\n") is None


def test_explicit_metadata_overrides_detection() -> None:
    """Caller-supplied values win over heuristics; detection only fills gaps."""
    event = ingest_log_text(
        read_fixture("sample_pytest.log"),
        failed_step="Run pytest -q --junitxml=reports/junit.xml",
        job_name="verify",
    )
    assert event.failed_step == "Run pytest -q --junitxml=reports/junit.xml"
    assert event.job_name == "verify"


def test_detection_fills_only_the_missing_values() -> None:
    """One supplied value does not suppress detection of the other."""
    event = ingest_log_text(read_fixture("sample_pytest.log"), failed_step="explicit-step")
    assert event.failed_step == "explicit-step"
    assert event.job_name == "test-suite (ubuntu-latest)"


# --------------------------------------------------------------------------- #
# ingest_log_file
# --------------------------------------------------------------------------- #


def test_ingest_log_file_reads_the_fixture_and_derives_metadata() -> None:
    """A fixture on disk ingests identically to the same text pasted inline."""
    path = fixture_path("npm_dependency_error.log")
    from_file = ingest_log_file(path, repository="acme/openmedic", run_id="77")
    from_text = ingest_log_text(
        path.read_text(encoding="utf-8"), repository="acme/openmedic", run_id="77"
    )
    assert from_file.failure_type is FailureType.DEPENDENCY_ERROR
    assert from_file.logs == from_text.logs
    assert from_file.failure_type == from_text.failure_type
    assert from_file.failed_step == from_text.failed_step


def test_ingest_log_file_accepts_a_string_path() -> None:
    """The CLI hands us strings; accepting them avoids a needless crash."""
    event = ingest_log_file(str(fixture_path("python_import_error.log")))
    assert event.failure_type is FailureType.SYNTAX_OR_IMPORT_ERROR


def test_ingest_log_file_rejects_a_missing_path() -> None:
    """A missing file is reported with its path, not a bare strerror."""
    missing = FIXTURE_DIR / "does_not_exist.log"
    with pytest.raises(InvalidInputError) as excinfo:
        ingest_log_file(missing)
    assert str(missing) in excinfo.value.message
    assert excinfo.value.message.strip()


def test_ingest_log_file_rejects_a_directory() -> None:
    """Reading a directory is an input error, not an empty event."""
    with pytest.raises(InvalidInputError) as excinfo:
        ingest_log_file(FIXTURE_DIR)
    assert str(FIXTURE_DIR) in excinfo.value.message


def test_ingest_log_file_rejects_an_unreadable_path(tmp_path: Path) -> None:
    """An unreadable file raises InvalidInputError instead of returning partial data."""
    path = tmp_path / "locked.log"
    path.write_text("FAILED tests/test_a.py::test_b\n", encoding="utf-8")
    os.chmod(path, 0o000)
    try:
        with pytest.raises(InvalidInputError) as excinfo:
            ingest_log_file(path)
        assert str(path) in excinfo.value.message
    finally:
        os.chmod(path, 0o600)


def test_ingest_log_file_rejects_invalid_utf8(tmp_path: Path) -> None:
    """Undecodable bytes are rejected rather than replaced with garbage evidence."""
    path = tmp_path / "binary.log"
    path.write_bytes(b"FAILED tests/test_a.py::test_b\n\xff\xfe\x00binary\n")
    with pytest.raises(InvalidInputError) as excinfo:
        ingest_log_file(path)
    assert str(path) in excinfo.value.message


def test_ingest_log_file_rejects_unknown_metadata() -> None:
    """An unrecognised keyword is reported, not silently dropped."""
    with pytest.raises(UsageError) as excinfo:
        ingest_log_file(fixture_path("sample_pytest.log"), source_arn="arn:example")  # type: ignore[call-arg]
    assert "source_arn" in excinfo.value.message


def test_source_path_is_not_part_of_the_contract() -> None:
    """``source_path`` is transport context, so it must never reach FailureEvent."""
    assert "source_path" not in FailureEvent.model_fields
    event = ingest_log_file(fixture_path("sample_pytest.log"))
    assert not hasattr(event, "source_path")


def test_ingest_log_file_error_message_names_the_path(tmp_path: Path) -> None:
    """A blank log file fails with the path attached, so the user can find it."""
    path = tmp_path / "empty.log"
    path.write_text("\n   \n", encoding="utf-8")
    with pytest.raises(InvalidInputError) as excinfo:
        ingest_log_file(path)
    assert str(path) in excinfo.value.message


# --------------------------------------------------------------------------- #
# ingest_stdin
# --------------------------------------------------------------------------- #


def test_ingest_stdin_reads_a_piped_log() -> None:
    """A piped stream produces the same event the text API produces."""
    text = read_fixture("sample_pytest.log")
    event = ingest_stdin(io.StringIO(text))
    assert event is not None
    assert event.failure_type is FailureType.TEST_FAILURE
    assert event.logs == text.strip()


def test_ingest_stdin_returns_none_for_an_empty_stream() -> None:
    """An empty pipe is "no input", not a failure to parse."""
    assert ingest_stdin(io.StringIO("")) is None
    assert ingest_stdin(io.StringIO("   \n\n")) is None


def test_ingest_stdin_does_not_block_on_a_terminal() -> None:
    """An interactive terminal is not input; nothing is read from it."""
    stream = _FakeTTY()
    assert ingest_stdin(stream) is None
    assert stream.read_calls == 0


def test_ingest_stdin_reports_an_unreadable_stream() -> None:
    """A broken pipe is a real error, distinct from an empty one."""
    with pytest.raises(InvalidInputError) as excinfo:
        ingest_stdin(_BrokenStream())
    assert excinfo.value.message.strip()


def test_ingest_stdin_accepts_a_stream_without_isatty() -> None:
    """Objects without ``isatty`` are treated as non-interactive and read."""
    event = ingest_stdin(_NoIsattyStream("make: *** No rule to make target 'release'. Stop.\n"))
    assert event is not None
    assert event.failure_type is FailureType.BUILD_OR_CONFIG_ERROR


# --------------------------------------------------------------------------- #
# Idempotency
# --------------------------------------------------------------------------- #


def _ingest_twice(*, run_id: str | None = "182736451") -> tuple[FailureEvent, FailureEvent]:
    """Ingest the same source event twice, with the same metadata both times."""
    metadata: dict[str, Any] = {
        "repository": "acme/openmedic",
        "workflow_name": "ci",
        "job_name": "test-suite (ubuntu-latest)",
        "failed_step": "Run pytest -q",
    }
    first = ingest_log_text(read_fixture("sample_pytest.log"), run_id=run_id, **metadata)
    second = ingest_log_text(read_fixture("sample_pytest.log"), run_id=run_id, **metadata)
    return first, second


def test_same_source_event_produces_a_stable_idempotency_key() -> None:
    """Duplicate delivery of one run must collapse to one incident."""
    first, second = _ingest_twice()
    assert first.idempotency_key == second.idempotency_key
    assert first.resolved_incident_id == second.resolved_incident_id


def test_different_run_id_changes_the_idempotency_key() -> None:
    """A different run is a different incident even with identical content."""
    first, _ = _ingest_twice()
    other, _ = _ingest_twice(run_id="999999999")
    assert first.idempotency_key != other.idempotency_key
    assert first.resolved_incident_id != other.resolved_incident_id


def test_idempotency_key_covers_every_identity_component() -> None:
    """Each identifying field must influence the key, or duplicates would merge."""
    log = read_fixture("sample_pytest.log")
    base = {"repository": "a/b", "run_id": "1"}
    reference = ingest_log_text(log, **base)
    variants = {
        "repository": "c/d",
        "workflow_name": "nightly",
        "job_name": "other",
        "failed_step": "Run lint",
        "run_id": "2",
    }
    for field, value in variants.items():
        changed = ingest_log_text(log, **{**base, field: value})
        assert changed.idempotency_key != reference.idempotency_key, f"{field} must affect the key"
