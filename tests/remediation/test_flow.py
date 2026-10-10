"""End-to-end repair: propose, apply, validate, and land the right lifecycle state.

Milestone 7's exit gate asks for at least one repair class with a reproducible test that
proves *both* a successful and an unsuccessful validation outcome. This file is that test.

Nothing in it is simulated: a committed-shaped CI log is diagnosed by the real rules, a
real playbook writes a real patch into a real disposable worktree, and the checks are
spawned as real subprocesses. The pipeline under test is

    log -> diagnosis -> playbook proposal -> disposable worktree -> subprocess checks
        -> lifecycle transition

The successful half has to reach ``recovered``. The unsuccessful half must not, and the
refusal has to be the recorded reason rather than a guess.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from openmedic.diagnosis import DiagnosisEngine
from openmedic.domain.contracts import (
    FailureEvent,
    IncidentRecord,
    RemediationAttempt,
    utc_now,
)
from openmedic.domain.enums import LifecycleState, RemediationStatus
from openmedic.domain.errors import ContractError
from openmedic.domain.lifecycle import apply_transition
from openmedic.ingestion import ingest_log_text
from openmedic.persistence import IncidentRepository
from openmedic.remediation import apply_patch_proposal, propose_remediation
from openmedic.validation import ValidationRunner, disposable_worktree
from openmedic.validation.isolation import (
    KIND_LOCAL_SUBPROCESS,
    LOCAL_SUBPROCESS_LIMITATIONS,
    IsolationDecision,
)
from openmedic.validation.policy import CheckDefinition, CheckPolicy

#: A log that names exactly one missing third-party module and nothing else.
_MISSING_MODULE_LOG = (
    "Run python -m pytest tests -q\n"
    "Traceback (most recent call last):\n"
    '  File "tests/test_client.py", line 3, in <module>\n'
    "    import requests\n"
    "ModuleNotFoundError: No module named 'requests'\n"
    "Error: Process completed with exit code 1.\n"
)


def _source_repo(root: Path) -> Path:
    """Build the tiny project the patch will be applied to."""
    source = root / "dep_repo"
    source.mkdir()
    (source / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (source / "app.py").write_text("import flask\n", encoding="utf-8")
    return source


def _event() -> FailureEvent:
    """Ingest the missing-module fixture exactly as a real run would."""
    return ingest_log_text(
        _MISSING_MODULE_LOG,
        repository="acme/widget",
        run_id="7",
        workflow_name="CI",
        job_name="test",
        failed_step="tests",
    )


def _isolation() -> IsolationDecision:
    """Return an explicit constrained-local decision with the real limitation wording."""
    return IsolationDecision(
        kind=KIND_LOCAL_SUBPROCESS,
        available=True,
        limitations=list(LOCAL_SUBPROCESS_LIMITATIONS),
        reason="test",
    )


def _check(name: str, script: str) -> CheckDefinition:
    """Return a required check that runs ``script`` under the current interpreter."""
    return CheckDefinition(name=name, command=[sys.executable, "-c", script])


def _has_requests() -> CheckDefinition:
    """Return a check that passes only once ``requests`` reaches the manifest."""
    script = (
        "import pathlib, sys; "
        "sys.exit(0 if 'requests' in pathlib.Path('requirements.txt').read_text() else 1)"
    )
    return _check("requests-declared", script)


def _store(root: Path, event: FailureEvent, diagnosis: object) -> IncidentRepository:
    """Open a repository and walk the incident up to ``diagnosed``."""
    repository = IncidentRepository(root / "incidents.db")
    record = IncidentRecord(
        incident_id=event.resolved_incident_id,
        event=event,  # type: ignore[arg-type]
        state=LifecycleState.RECEIVED,
        created_at=utc_now(),
        updated_at=utc_now(),
        idempotency_key=event.idempotency_key,
    )
    repository.upsert_incident(record)
    repository.record_diagnosis(  # type: ignore[arg-type]
        event.resolved_incident_id, diagnosis, at=utc_now()
    )
    return repository


def test_missing_dependency_repair_passes_validation_and_recovers(tmp_path: Path) -> None:
    """The successful half of the Milestone 7 gate, with no step faked."""
    source = _source_repo(tmp_path)
    event = _event()
    diagnosis = DiagnosisEngine().diagnose(event)
    assert diagnosis.rule_id == "DEP-001"
    assert diagnosis.failure_type.value == "dependency_error"

    outcome = propose_remediation(event, diagnosis, repo_root=source)
    attempt = outcome.attempt
    assert attempt is not None, outcome.rejected_reason
    assert outcome.rejected_reason is None
    assert attempt.status is RemediationStatus.PROPOSED
    assert attempt.files_changed == ["requirements.txt"]
    assert attempt.risk_level.value == "low"
    assert attempt.requires_human_review is False
    assert attempt.patch_hash
    assert "+requests" in attempt.patch_unified_diff

    # The patch is staged only in a disposable copy, never in the source tree.
    worktree = disposable_worktree(source, tmp_path / "wt")
    written = apply_patch_proposal(outcome.proposal, worktree=worktree)  # type: ignore[arg-type]
    assert [path.relative_to(worktree).as_posix() for path in written] == ["requirements.txt"]
    assert (source / "requirements.txt").read_text(encoding="utf-8") == "flask\n"
    assert (worktree / "requirements.txt").read_text(encoding="utf-8").splitlines() == [
        "flask",
        "requests",
    ]

    runner = ValidationRunner(CheckPolicy(checks=(_has_requests(),)), isolation=_isolation())
    result = runner.validate(attempt, worktree=worktree, candidate_hash=attempt.patch_hash)

    assert result.passed is True
    assert result.failed_checks == []
    assert result.candidate_patch_hash == attempt.patch_hash
    assert result.execution.isolation_kind == KIND_LOCAL_SUBPROCESS

    repository = _store(tmp_path, event, diagnosis)
    try:
        record = repository.record_attempt(event.resolved_incident_id, attempt, at=utc_now())
        # A recorded proposal is pending, not yet applied: nothing has touched a tree.
        assert record.state is LifecycleState.REMEDIATION_PENDING
        record = repository.record_validation(event.resolved_incident_id, result, at=utc_now())
        assert record.state is LifecycleState.VALIDATING

        apply_transition(record, LifecycleState.RECOVERED, reason=result.summary, at=utc_now())
        assert record.state is LifecycleState.RECOVERED
        assert record.latest_validation is not None
        assert record.latest_validation.passed is True
    finally:
        repository.close()


def test_a_failing_check_blocks_recovery_and_the_refusal_is_recorded(tmp_path: Path) -> None:
    """The unsuccessful half: real execution says no, so ``recovered`` stays closed."""
    source = _source_repo(tmp_path)
    event = _event()
    diagnosis = DiagnosisEngine().diagnose(event)
    outcome = propose_remediation(event, diagnosis, repo_root=source)
    attempt = outcome.attempt
    assert attempt is not None, outcome.rejected_reason

    worktree = disposable_worktree(source, tmp_path / "wt")
    apply_patch_proposal(outcome.proposal, worktree=worktree)  # type: ignore[arg-type]

    broken = _check(
        "suite",
        "import sys; sys.stderr.write('1 failed\\n'); sys.exit(1)",
    )
    result = ValidationRunner(CheckPolicy(checks=(broken,)), isolation=_isolation()).validate(
        attempt, worktree=worktree, candidate_hash=attempt.patch_hash
    )

    assert result.passed is False
    assert result.failed_checks == ["suite"]
    assert result.checks_executed[0].exit_code == 1

    repository = _store(tmp_path, event, diagnosis)
    try:
        record = repository.record_attempt(event.resolved_incident_id, attempt, at=utc_now())
        record = repository.record_validation(event.resolved_incident_id, result, at=utc_now())

        with pytest.raises(ContractError, match="validation did not pass"):
            apply_transition(record, LifecycleState.RECOVERED, reason=result.summary, at=utc_now())
        assert record.state is LifecycleState.VALIDATING

        # The incident still moves — to the honest terminal state, not to success.
        apply_transition(record, LifecycleState.FAILED, reason=result.summary, at=utc_now())
        assert record.state is LifecycleState.FAILED
        assert [t.to_state for t in record.state_history][-2:] == [
            LifecycleState.VALIDATING,
            LifecycleState.FAILED,
        ]
    finally:
        repository.close()


def test_a_changed_patch_invalidates_a_previously_passing_validation(tmp_path: Path) -> None:
    """Recovery is bound to the exact candidate patch, not to a remembered pass."""
    source = _source_repo(tmp_path)
    event = _event()
    diagnosis = DiagnosisEngine().diagnose(event)
    outcome = propose_remediation(event, diagnosis, repo_root=source)
    attempt = outcome.attempt
    assert attempt is not None, outcome.rejected_reason

    worktree = disposable_worktree(source, tmp_path / "wt")
    apply_patch_proposal(outcome.proposal, worktree=worktree)  # type: ignore[arg-type]
    passing = ValidationRunner(
        CheckPolicy(checks=(_has_requests(),)), isolation=_isolation()
    ).validate(attempt, worktree=worktree, candidate_hash=attempt.patch_hash)
    assert passing.passed is True

    repository = _store(tmp_path, event, diagnosis)
    try:
        record = repository.record_attempt(event.resolved_incident_id, attempt, at=utc_now())

        # The candidate patch changes after the checks ran. Recording the replacement
        # keeps the old, still-passing validation attached to the incident, which is
        # exactly the state a stale recovery would have to be refused from.
        moved: RemediationAttempt = record.attempts[-1].model_copy(update={"patch_hash": "0" * 64})
        repository.record_attempt(event.resolved_incident_id, moved, at=utc_now())
        record = repository.record_validation(event.resolved_incident_id, passing, at=utc_now())
        assert record.state is LifecycleState.VALIDATING
        assert record.attempts[-1].patch_hash == "0" * 64
        assert record.latest_validation is not None
        assert record.latest_validation.passed is True

        with pytest.raises(ContractError, match="validation is stale"):
            apply_transition(record, LifecycleState.RECOVERED, reason="checks passed", at=utc_now())
        assert record.state is not LifecycleState.RECOVERED
    finally:
        repository.close()


def test_a_failure_no_playbook_matches_is_left_alone(tmp_path: Path) -> None:
    """A container build failure is out of scope: nothing is guessed for it."""
    event = ingest_log_text(
        "Step 5/9 : RUN pip install -r requirements.txt\n"
        "The command '/bin/sh -c pip install -r requirements.txt' returned a "
        "non-zero code: 1\n"
        "Error: Process completed with exit code 1.\n",
        repository="acme/widget",
        run_id="1",
    )
    diagnosis = DiagnosisEngine().diagnose(event)
    assert diagnosis.rule_id == "BUILD-001"

    outcome = propose_remediation(event, diagnosis, repo_root=tmp_path)
    assert outcome.attempt is None
    assert outcome.proposal is None
    assert outcome.rejected_reason is not None
    assert "no deterministic playbook matched" in outcome.rejected_reason


def test_no_dependency_manifest_is_never_invented(tmp_path: Path) -> None:
    """The playbook must not create a dependency file for a project that has none."""
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "app.py").write_text("x = 1\n", encoding="utf-8")

    event = _event()
    diagnosis = DiagnosisEngine().diagnose(event)
    assert diagnosis.rule_id == "DEP-001"

    outcome = propose_remediation(event, diagnosis, repo_root=plain)
    assert outcome.attempt is None
    assert outcome.rejected_reason is not None
    assert sorted(path.name for path in plain.iterdir()) == ["app.py"]
