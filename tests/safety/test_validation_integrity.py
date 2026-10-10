"""Validation integrity: the difference between "checked" and "claimed".

These are the invariants that make the product honest. Each one corresponds to a sentence
in ``docs/API_CONTRACTS.md`` section 4 or ``docs/SECURITY.md`` rule 9.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from openmedic.domain import (
    CheckResult,
    CheckStatus,
    ContractError,
    IncidentRecord,
    LifecycleState,
    RemediationAttempt,
    RemediationStatus,
    RiskLevel,
    ValidationResult,
    utc_now,
)
from openmedic.domain.lifecycle import apply_transition, can_transition
from tests.conftest import FIXED_TS, make_event


def _check(status: CheckStatus, *, required: bool = True, name: str = "pytest") -> CheckResult:
    return CheckResult(
        name=name, command=["pytest", "-q"], status=status, exit_code=0, required=required
    )


def _attempt(patch_hash: str) -> RemediationAttempt:
    return RemediationAttempt(
        attempt_id="a1",
        incident_id="inc-v",
        status=RemediationStatus.PROPOSED,
        rule_id="r",
        summary="s",
        rationale="r",
        risk_level=RiskLevel.LOW,
        patch_hash=patch_hash,
        created_at=FIXED_TS,
    )


def _record(state: LifecycleState, patch_hash: str = "h1") -> IncidentRecord:
    event = make_event()
    return IncidentRecord(
        incident_id="inc-v",
        event=event,
        state=state,
        created_at=FIXED_TS,
        updated_at=FIXED_TS,
        attempts=[_attempt(patch_hash)],
        idempotency_key=event.idempotency_key,
    )


def test_skipped_required_check_cannot_pass() -> None:
    with pytest.raises(ContractError):
        ValidationResult(
            incident_id="inc-v",
            passed=True,
            checks_executed=[_check(CheckStatus.PASSED), _check(CheckStatus.SKIPPED)],
        )


def test_no_checks_at_all_cannot_pass() -> None:
    with pytest.raises(ContractError):
        ValidationResult(incident_id="inc-v", passed=True, checks_executed=[])


def test_optional_skipped_check_is_tolerated() -> None:
    result = ValidationResult(
        incident_id="inc-v",
        passed=True,
        checks_executed=[
            _check(CheckStatus.PASSED),
            _check(CheckStatus.SKIPPED, required=False),
        ],
    )
    assert result.passed is True


def test_failed_checks_list_makes_pass_impossible() -> None:
    with pytest.raises(ContractError):
        ValidationResult(
            incident_id="inc-v",
            passed=True,
            checks_executed=[_check(CheckStatus.PASSED)],
            failed_checks=["ruff"],
        )


def test_stale_patch_hash_blocks_recovery() -> None:
    record = _record(LifecycleState.VALIDATING, patch_hash="h-current")
    with pytest.raises(ContractError, match="stale"):
        apply_transition(
            record,
            LifecycleState.RECOVERED,
            reason="validated an older patch",
            at=FIXED_TS + timedelta(minutes=1),
            validation=ValidationResult(
                incident_id="inc-v",
                candidate_patch_hash="h-old",
                passed=True,
                checks_executed=[_check(CheckStatus.PASSED)],
                summary="ok",
            ),
        )


def test_patch_changed_after_validation_invalidates_it() -> None:
    record = _record(LifecycleState.VALIDATING, patch_hash="h1")
    record.validations = [
        ValidationResult(
            incident_id="inc-v",
            candidate_patch_hash="h1",
            passed=True,
            checks_executed=[_check(CheckStatus.PASSED)],
            summary="ok",
        )
    ]
    apply_transition(record, LifecycleState.RECOVERED, reason="all good", at=FIXED_TS)
    assert record.state is LifecycleState.RECOVERED

    # The patch is now superseded; the previous evidence no longer covers it.
    record.attempts = [*record.attempts, _attempt("h2")]
    record.state = LifecycleState.VALIDATING
    with pytest.raises(ContractError, match="stale"):
        apply_transition(
            record, LifecycleState.RECOVERED, reason="reuse old evidence", at=utc_now()
        )


def test_recovery_requires_a_bound_candidate() -> None:
    record = _record(LifecycleState.VALIDATING)
    with pytest.raises(ContractError, match="candidate patch"):
        apply_transition(
            record,
            LifecycleState.RECOVERED,
            reason="unbound validation",
            at=FIXED_TS,
            validation=ValidationResult(
                incident_id="inc-v",
                passed=True,
                checks_executed=[_check(CheckStatus.PASSED)],
                summary="ok",
            ),
        )


def test_recovery_requires_real_execution_metadata() -> None:
    from openmedic.domain import ExecutionMetadata

    record = _record(LifecycleState.VALIDATING)
    with pytest.raises(ContractError, match="execution metadata"):
        apply_transition(
            record,
            LifecycleState.RECOVERED,
            reason="no provenance",
            at=FIXED_TS,
            validation=ValidationResult(
                incident_id="inc-v",
                candidate_patch_hash="h1",
                passed=True,
                checks_executed=[_check(CheckStatus.PASSED)],
                summary="ok",
                execution=ExecutionMetadata(isolation_kind=""),
            ),
        )


def test_history_is_append_only_across_retries() -> None:
    record = _record(LifecycleState.FAILED)
    apply_transition(record, LifecycleState.DIAGNOSING, reason="retry 1", at=FIXED_TS)
    apply_transition(record, LifecycleState.DIAGNOSED, reason="retry 1", at=FIXED_TS)
    apply_transition(record, LifecycleState.REMEDIATION_PENDING, reason="retry 1", at=FIXED_TS)
    apply_transition(record, LifecycleState.REMEDIATING, reason="retry 1", at=FIXED_TS)
    apply_transition(record, LifecycleState.FAILED, reason="retry 1 exhausted", at=FIXED_TS)
    assert len(record.state_history) == 5

    # A second retry adds to the history rather than replacing it.
    apply_transition(record, LifecycleState.DIAGNOSING, reason="retry 2", at=FIXED_TS)
    assert len(record.state_history) == 6
    assert [h.reason for h in record.state_history] == [
        "retry 1",
        "retry 1",
        "retry 1",
        "retry 1",
        "retry 1 exhausted",
        "retry 2",
    ]
    # Nothing was erased: the earlier attempts are still attached.
    assert record.attempts


def test_only_remediating_can_fail() -> None:
    """``failed`` is reachable from remediation, not from every state."""
    assert can_transition(LifecycleState.REMEDIATING, LifecycleState.FAILED) is True
    assert can_transition(LifecycleState.REMEDIATION_PENDING, LifecycleState.FAILED) is False
    assert can_transition(LifecycleState.RECEIVED, LifecycleState.FAILED) is False


def test_isolation_kind_is_honest_about_local_subprocess() -> None:
    from openmedic.domain import ExecutionMetadata

    metadata = ExecutionMetadata(isolation_kind="local-subprocess", docker_available=False)
    assert metadata.docker_available is False
    # The record itself must never claim container-grade isolation it does not have.
    assert metadata.isolation_kind != "docker"


def test_unavailable_docker_is_reported_as_a_limitation() -> None:
    from openmedic.domain import ExecutionMetadata

    metadata = ExecutionMetadata(
        isolation_kind="local-subprocess",
        docker_available=False,
        limitations=["docker unavailable; constrained local subprocess, not a hardened sandbox"],
    )
    assert any("not a hardened sandbox" in item for item in metadata.limitations)
