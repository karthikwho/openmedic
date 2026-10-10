"""Runner tests: real execution, honest statuses, and truthful metadata.

Every check in these tests is spawned for real. No assertion here depends on a check being
simulated, because a simulated check cannot prove the runner executed anything.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from openmedic.domain.contracts import (
    MAX_EXCERPT_CHARS,
    RemediationAttempt,
    ValidationResult,
    utc_now,
)
from openmedic.domain.enums import CheckStatus, RemediationStatus, RiskLevel
from openmedic.validation import runner as runner_module
from openmedic.validation.isolation import (
    KIND_DOCKER,
    KIND_LOCAL_SUBPROCESS,
    LOCAL_SUBPROCESS_LIMITATIONS,
    IsolationDecision,
    detect_isolation,
    disposable_worktree,
)
from openmedic.validation.policy import CheckDefinition, CheckPolicy
from openmedic.validation.runner import (
    ValidationRunner,
    is_stale,
    run_validation,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "hello_repo"


def _attempt(patch_hash: str | None = "patch-hash-1") -> RemediationAttempt:
    """Build a minimal remediation attempt for the incident under test."""
    return RemediationAttempt(
        attempt_id="attempt-1",
        incident_id="incident-1",
        status=RemediationStatus.APPLIED,
        rule_id="rule-1",
        summary="bump the dependency",
        rationale="the resolver failed on a missing pin",
        risk_level=RiskLevel.LOW,
        requires_human_review=False,
        files_changed=["pyproject.toml"],
        patch_unified_diff="--- a/pyproject.toml\n+++ b/pyproject.toml\n",
        patch_hash=patch_hash,
        created_at=utc_now(),
    )


def _policy(*checks: CheckDefinition, max_output_bytes: int | None = None) -> CheckPolicy:
    """Build a policy from check definitions."""
    if max_output_bytes is None:
        return CheckPolicy(checks=checks)
    return CheckPolicy(checks=checks, max_output_bytes=max_output_bytes)


def _echo(script: str, name: str = "echo", **kwargs: object) -> CheckDefinition:
    """Build a check that runs ``script`` with this interpreter."""
    return CheckDefinition(name=name, command=[sys.executable, "-c", script], **kwargs)  # type: ignore[arg-type]


def _local() -> IsolationDecision:
    """Return an explicit constrained-local-subprocess decision.

    Uses the real limitation text so tests that assert on honesty wording are actually
    exercising what production will report.
    """
    return IsolationDecision(
        kind=KIND_LOCAL_SUBPROCESS,
        available=True,
        limitations=list(LOCAL_SUBPROCESS_LIMITATIONS),
        reason="test",
    )


def test_passing_check_passes_validation(tmp_path: Path) -> None:
    """A check that exits zero yields PASSED and an overall pass."""
    runner = ValidationRunner(_policy(_echo("print('fine')")), isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)

    assert result.passed is True
    assert result.failed_checks == []
    assert len(result.checks_executed) == 1
    check = result.checks_executed[0]
    assert check.status is CheckStatus.PASSED
    assert check.exit_code == 0
    assert check.duration_seconds is not None
    assert "fine" in check.stdout_excerpt
    assert check.command == [sys.executable, "-c", "print('fine')"]


def test_failing_check_blocks_the_pass(tmp_path: Path) -> None:
    """A non-zero exit is FAILED, is reported, and cannot pass."""
    definition = _echo("import sys; sys.stderr.write('boom\\n'); sys.exit(3)")
    runner = ValidationRunner(_policy(definition), isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)

    assert result.passed is False
    assert result.failed_checks == ["echo"]
    check = result.checks_executed[0]
    assert check.status is CheckStatus.FAILED
    assert check.exit_code == 3
    assert "boom" in check.stderr_excerpt
    assert result.summary


def test_timeout_is_reported_as_timed_out(tmp_path: Path) -> None:
    """A check that overruns its timeout is TIMED_OUT, not a pass."""
    definition = _echo("import time; time.sleep(30)", timeout_seconds=0.5)
    runner = ValidationRunner(_policy(definition), isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)

    check = result.checks_executed[0]
    assert check.status is CheckStatus.TIMED_OUT
    assert result.passed is False
    assert check.duration_seconds is not None
    assert check.duration_seconds < 10.0


def test_missing_executable_is_never_a_pass(tmp_path: Path) -> None:
    """An unresolvable check name is MISSING and blocks validation."""
    definition = CheckDefinition(name="ghost", command=["openmedic-no-such-executable-xyz"])
    runner = ValidationRunner(_policy(definition), isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)

    check = result.checks_executed[0]
    assert check.status is CheckStatus.MISSING
    assert check.exit_code is None
    assert check.required is True
    assert result.passed is False
    assert "openmedic-no-such-executable-xyz" in check.stderr_excerpt


def test_launcher_failure_is_errored_or_missing(tmp_path: Path) -> None:
    """A broken interpreter is an error, never a fabricated success."""
    broken = tmp_path / "broken-check"
    broken.write_text("#!/nonexistent/interpreter\nexit 0\n", encoding="utf-8")
    broken.chmod(0o755)
    definition = CheckDefinition(name="broken", command=[str(broken)])
    runner = ValidationRunner(_policy(definition), isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)

    check = result.checks_executed[0]
    assert check.status in {CheckStatus.ERRORED, CheckStatus.MISSING}
    assert result.passed is False


def test_unknown_check_name_is_required_and_missing(tmp_path: Path) -> None:
    """A name outside the allowlist is rejected as a required MISSING check."""
    runner = ValidationRunner(_policy(_echo("print('fine')")), isolation=_local())
    results = runner.run_checks(["pytest", "not-a-check", "pytest"], worktree=tmp_path)

    assert [check.name for check in results] == ["pytest", "not-a-check"]
    unknown = results[1]
    assert unknown.status is CheckStatus.MISSING
    assert unknown.required is True
    assert unknown.command == []


def test_optional_check_failure_does_not_block_a_pass(tmp_path: Path) -> None:
    """``required=False`` is respected: only a required check can veto a pass."""
    policy = _policy(
        _echo("print('tests ok')"),
        _echo("import sys; sys.exit(1)", name="lint", required=False),
    )
    runner = ValidationRunner(policy, isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)

    assert result.passed is True
    assert result.failed_checks == []
    assert [check.status for check in result.checks_executed] == [
        CheckStatus.PASSED,
        CheckStatus.FAILED,
    ]


def test_missing_workspace_skips_every_required_check(tmp_path: Path) -> None:
    """Validating against a workspace that is not there cannot pass."""
    runner = ValidationRunner(_policy(_echo("print('fine')")), isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path / "absent")

    assert result.passed is False
    check = result.checks_executed[0]
    assert check.status is CheckStatus.SKIPPED
    assert check.required is True
    assert result.failed_checks == ["echo"]


def test_empty_required_check_set_cannot_pass(tmp_path: Path) -> None:
    """An empty policy produces no evidence, so the result cannot pass."""
    runner = ValidationRunner(CheckPolicy(), isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)

    assert result.passed is False
    assert result.checks_executed == []
    assert "no validation checks" in result.summary


def test_real_pytest_check_runs_in_the_disposable_copy() -> None:
    """A real pytest run against the copied fixture passes for the right reason."""
    pytest_binary = shutil.which("pytest")
    if pytest_binary is None:  # pragma: no cover - depends on the environment
        pytest.skip("pytest is not on PATH")

    policy = CheckPolicy.detect(FIXTURE_ROOT)
    runner = ValidationRunner(policy, isolation=_local())
    with tempfile.TemporaryDirectory() as scratch:
        worktree = disposable_worktree(FIXTURE_ROOT, Path(scratch) / "worktree")
        results = runner.run_checks(["pytest"], worktree=worktree)

    assert results[0].status is CheckStatus.PASSED
    assert results[0].exit_code == 0
    assert "1 passed" in results[0].stdout_excerpt


def test_result_is_bound_to_the_candidate_patch(tmp_path: Path) -> None:
    """The result records the exact patch identity and honest execution metadata."""
    runner = ValidationRunner(_policy(_echo("print('fine')")), isolation=_local())
    result = runner.validate(_attempt(patch_hash="hash-abc"), worktree=tmp_path)

    assert result.candidate_patch_hash == "hash-abc"
    assert result.incident_id == "incident-1"
    assert result.execution.isolation_kind == KIND_LOCAL_SUBPROCESS
    assert result.execution.worktree_path == str(tmp_path)
    assert result.execution.docker_available is False
    assert result.execution.sandbox_id
    assert result.execution.limitations
    assert result.started_at is not None
    assert result.completed_at is not None
    assert result.started_at.tzinfo is not None
    assert result.completed_at.tzinfo is not None


def test_candidate_hash_override_changes_the_binding(tmp_path: Path) -> None:
    """An explicit ``candidate_hash`` wins over the attempt's own hash."""
    runner = ValidationRunner(_policy(_echo("print('fine')")), isolation=_local())
    result = runner.validate(
        _attempt(patch_hash="hash-abc"), worktree=tmp_path, candidate_hash="hash-xyz"
    )
    assert result.candidate_patch_hash == "hash-xyz"


def test_metadata_limitations_state_that_local_is_not_a_sandbox(tmp_path: Path) -> None:
    """The local fallback's limitations travel with the result."""
    runner = ValidationRunner(_policy(_echo("print('fine')")), isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)

    joined = " ".join(result.execution.limitations).lower()
    assert "not a sandbox" in joined
    assert "must not be presented as equivalent" in joined


def test_is_stale_detects_a_changed_patch(tmp_path: Path) -> None:
    """``is_stale`` is the runner-side view of the staleness invariant."""
    attempt = _attempt(patch_hash="hash-abc")
    runner = ValidationRunner(_policy(_echo("print('fine')")), isolation=_local())
    current = runner.validate(attempt, worktree=tmp_path)
    superseded = runner.validate(attempt, worktree=tmp_path, candidate_hash="hash-old")

    assert is_stale(attempt, current) is False
    assert is_stale(attempt, superseded) is True


def test_is_stale_for_an_unbound_result() -> None:
    """A result with no patch identity can never justify recovery."""
    unbound = ValidationResult(incident_id="incident-1", passed=False)
    assert is_stale(_attempt(patch_hash="hash-abc"), unbound) is True
    assert is_stale(_attempt(patch_hash=None), unbound) is True


def test_run_validation_forces_local_subprocess_without_docker(tmp_path: Path) -> None:
    """The convenience helper honours an explicit "no Docker" request."""
    result = run_validation(
        _attempt(),
        worktree=tmp_path,
        policy=_policy(_echo("print('fine')")),
        docker_available=False,
    )
    assert result.passed is True
    assert result.execution.isolation_kind == KIND_LOCAL_SUBPROCESS


def test_child_runs_in_the_candidate_workspace(tmp_path: Path) -> None:
    """Checks execute with the candidate tree as their working directory."""
    script = "import os; print(os.getcwd())"
    runner = ValidationRunner(_policy(_echo(script)), isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)

    reported = result.checks_executed[0].stdout_excerpt.strip()
    assert Path(reported).resolve() == tmp_path.resolve()


def test_child_never_inherits_the_original_working_tree(tmp_path: Path) -> None:
    """A change made by a check does not touch the source tree it was copied from."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "keep.txt").write_text("original\n", encoding="utf-8")
    worktree = tmp_path / "worktree"
    disposable_worktree(source, worktree)

    script = f"from pathlib import Path; Path({str(worktree / 'keep.txt')!r}).write_text('changed')"
    runner = ValidationRunner(_policy(_echo(script)), isolation=_local())
    result = runner.validate(_attempt(), worktree=worktree)

    assert result.passed is True
    assert (worktree / "keep.txt").read_text(encoding="utf-8") == "changed"
    assert (source / "keep.txt").read_text(encoding="utf-8") == "original\n"


def test_child_stdin_is_closed(tmp_path: Path) -> None:
    """A check that reads stdin sees an immediate EOF instead of hanging."""
    script = "import sys; data = sys.stdin.read(); print('EOF' if data == '' else 'DATA')"
    runner = ValidationRunner(_policy(_echo(script)), isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)

    assert result.passed is True
    assert "EOF" in result.checks_executed[0].stdout_excerpt


def test_output_is_bounded_and_redacted(tmp_path: Path) -> None:
    """Only a bounded excerpt survives, and it is redacted."""
    policy = _policy(
        _echo("for i in range(5000): print('line %d' % i)", name="loud"),
        max_output_bytes=65536,
    )
    runner = ValidationRunner(policy, isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)

    excerpt = result.checks_executed[0].stdout_excerpt
    assert len(excerpt) <= MAX_EXCERPT_CHARS + 64
    assert excerpt.endswith("[truncated]")
    assert "line 0" in excerpt

    token = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
    secret_policy = _policy(_echo(f"print({token!r})", name="leak"))
    runner = ValidationRunner(secret_policy, isolation=_local())
    secret_result = runner.validate(_attempt(), worktree=tmp_path)
    leak_excerpt = secret_result.checks_executed[0].stdout_excerpt

    assert token not in leak_excerpt
    assert "[REDACTED]" in leak_excerpt


def test_docker_mode_builds_container_argv_and_reports_the_truth(tmp_path: Path) -> None:
    """Selecting Docker changes the argv; without a daemon the check still fails honestly."""
    decision = IsolationDecision(
        kind=KIND_DOCKER,
        available=True,
        limitations=["container requested by the test"],
        reason="test",
    )
    runner = ValidationRunner(_policy(_echo("print('fine')")), isolation=decision)
    result = runner.validate(_attempt(), worktree=tmp_path)

    check = result.checks_executed[0]
    assert check.status in {CheckStatus.ERRORED, CheckStatus.MISSING}
    assert result.passed is False
    assert check.command[0] == "docker"
    assert check.command[1] == "run"
    assert result.execution.isolation_kind == KIND_DOCKER
    assert result.execution.docker_available is True


def test_local_venv_mode_creates_and_removes_its_scratch_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A local-venv run prepares a venv, exposes it on PATH, and cleans it up."""
    created: list[Path] = []
    real_mkdtemp = tempfile.mkdtemp

    def fake_mkdtemp(*args: object, **kwargs: object) -> str:
        target = tmp_path / f"scratch-{len(created)}"
        target.mkdir(parents=True)
        created.append(target)
        return str(target)

    monkeypatch.setattr(runner_module.tempfile, "mkdtemp", fake_mkdtemp)
    decision = IsolationDecision(
        kind="local-venv",
        available=True,
        limitations=["venv requested by the test"],
        reason="test",
    )
    script = "import os; print(os.environ['PATH'])"
    try:
        runner = ValidationRunner(_policy(_echo(script)), isolation=decision)
        result = runner.validate(_attempt(), worktree=tmp_path)
    finally:
        monkeypatch.setattr(runner_module.tempfile, "mkdtemp", real_mkdtemp)

    assert result.passed is True
    assert result.execution.isolation_kind == "local-venv"
    path_entries = result.checks_executed[0].stdout_excerpt.strip().split(os.pathsep)
    assert path_entries[0].endswith("venv" + os.sep + "bin")
    assert created
    assert not created[0].exists(), "the venv scratch directory must be removed"


def test_validate_and_cleanup_removes_the_workspace(tmp_path: Path) -> None:
    """Cleanup runs after validation and its outcome is reported."""
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / "marker.txt").write_text("candidate\n", encoding="utf-8")
    runner = ValidationRunner(_policy(_echo("print('fine')")), isolation=_local())

    outcome = runner.validate_and_cleanup(_attempt(), worktree=worktree)

    assert outcome.cleanup_ok is True
    assert outcome.result.passed is True
    assert not worktree.exists()


def test_injected_clock_is_used_for_timestamps(tmp_path: Path) -> None:
    """Timestamps come from the injected clock and stay timezone-aware."""
    moment = datetime(2030, 1, 1, 12, 0, tzinfo=UTC)
    runner = ValidationRunner(
        _policy(_echo("print('fine')")),
        isolation=_local(),
        clock=lambda: moment,
    )
    result = runner.validate(_attempt(), worktree=tmp_path)

    assert result.started_at == moment
    assert result.completed_at == moment


def test_default_clock_produces_aware_utc_timestamps(tmp_path: Path) -> None:
    """The default clock produces timezone-aware, current timestamps."""
    before = utc_now() - timedelta(seconds=1)
    runner = ValidationRunner(_policy(_echo("print('fine')")), isolation=_local())
    result = runner.validate(_attempt(), worktree=tmp_path)
    after = utc_now() + timedelta(seconds=1)

    assert result.started_at is not None
    assert result.completed_at is not None
    assert before <= result.started_at <= after
    assert before <= result.completed_at <= after
    assert result.started_at.utcoffset() == timedelta(0)


def test_detected_isolation_metadata_is_recorded_verbatim(tmp_path: Path) -> None:
    """The isolation module's decision is what the result reports."""
    decision = detect_isolation(prefer_docker=False)
    runner = ValidationRunner(_policy(_echo("print('fine')")), isolation=decision)
    result = runner.validate(_attempt(), worktree=tmp_path)

    assert result.execution.isolation_kind == decision.kind
    assert result.execution.limitations[: len(decision.limitations)] == decision.limitations
