"""Lifecycle integrity: who may reach ``recovered``, and why.

Recovery is the one state where a bug turns into a false claim. These tests pin down
that only a real, complete, non-stale validation can reach it.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from openmedic.domain import (
    CheckResult,
    CheckStatus,
    ContractError,
    DiagnosisResult,
    FailureType,
    IncidentRecord,
    LifecycleState,
    RecommendedAction,
    RemediationAttempt,
    RemediationStatus,
    RiskLevel,
    ValidationResult,
    apply_transition,
    can_transition,
    utc_now,
)
from tests.conftest import FIXED_TS, make_event

LATER = FIXED_TS + timedelta(hours=1)


def _diagnosis() -> DiagnosisResult:
    return DiagnosisResult(
        incident_id="inc-1",
        failure_type=FailureType.TEST_FAILURE,
        probable_cause="assertion failed",
        confidence=0.9,
        recommended_action=RecommendedAction.FIX_FAILING_TEST,
        risk_level=RiskLevel.LOW,
        limitations=["single case"],
    )


def _attempt(patch_hash: str = "hash-a") -> RemediationAttempt:
    return RemediationAttempt(
        attempt_id="att-1",
        incident_id="inc-1",
        status=RemediationStatus.PROPOSED,
        rule_id="playbook.dep",
        summary="pin requests",
        rationale="missing module",
        risk_level=RiskLevel.LOW,
        files_changed=["requirements.txt"],
        patch_unified_diff="--- a/requirements.txt\n+++ b/requirements.txt\n",
        patch_hash=patch_hash,
        created_at=FIXED_TS,
    )


def _validation(patch_hash: str = "hash-a", *, passed: bool = True) -> ValidationResult:
    check = CheckResult(
        name="pytest", command=["pytest", "-q"], status=CheckStatus.PASSED, exit_code=0
    )
    return ValidationResult(
        incident_id="inc-1",
        candidate_patch_hash=patch_hash,
        passed=passed,
        checks_executed=[check],
        summary="1 check passed",
        started_at=FIXED_TS,
        completed_at=LATER,
    )


def _record(**overrides: object) -> IncidentRecord:
    event = make_event()
    defaults: dict[str, object] = {
        "incident_id": "inc-1",
        "event": event,
        "state": LifecycleState.VALIDATING,
        "created_at": FIXED_TS,
        "updated_at": FIXED_TS,
        "attempts": [_attempt()],
        "validations": [_validation()],
        "idempotency_key": event.idempotency_key,
    }
    defaults.update(overrides)
    return IncidentRecord(**defaults)  # type: ignore[arg-type]


def test_every_documented_transition_is_legal() -> None:
    pairs = [
        (LifecycleState.RECEIVED, LifecycleState.DIAGNOSING),
        (LifecycleState.DIAGNOSING, LifecycleState.DIAGNOSED),
        (LifecycleState.DIAGNOSING, LifecycleState.REQUIRES_HUMAN_REVIEW),
        (LifecycleState.DIAGNOSED, LifecycleState.REMEDIATION_PENDING),
        (LifecycleState.REMEDIATION_PENDING, LifecycleState.REMEDIATING),
        (LifecycleState.REMEDIATING, LifecycleState.VALIDATING),
        (LifecycleState.REMEDIATING, LifecycleState.FAILED),
        (LifecycleState.VALIDATING, LifecycleState.RECOVERED),
        (LifecycleState.VALIDATING, LifecycleState.FAILED),
        (LifecycleState.FAILED, LifecycleState.DIAGNOSING),
    ]
    for source, target in pairs:
        assert can_transition(source, target) is True, f"{source} -> {target}"


@pytest.mark.parametrize(
    "source,target",
    [
        (LifecycleState.RECEIVED, LifecycleState.RECOVERED),
        (LifecycleState.RECEIVED, LifecycleState.VALIDATING),
        (LifecycleState.DIAGNOSED, LifecycleState.VALIDATING),
        (LifecycleState.RECOVERED, LifecycleState.FAILED),
        (LifecycleState.REQUIRES_HUMAN_REVIEW, LifecycleState.RECOVERED),
    ],
)
def test_skipping_validation_is_impossible(source: LifecycleState, target: LifecycleState) -> None:
    assert can_transition(source, target) is False


def test_self_transition_is_rejected() -> None:
    assert can_transition(LifecycleState.VALIDATING, LifecycleState.VALIDATING) is False


def test_apply_transition_records_history_and_advances_updated_at() -> None:
    event = make_event()
    record = IncidentRecord(
        incident_id="inc-1",
        event=event,
        state=LifecycleState.RECEIVED,
        created_at=FIXED_TS,
        updated_at=FIXED_TS,
        idempotency_key=event.idempotency_key,
    )
    transition = apply_transition(record, LifecycleState.DIAGNOSING, reason="start", at=LATER)
    assert record.state is LifecycleState.DIAGNOSING
    assert record.updated_at == LATER
    assert record.state_history[-1] == transition
    assert transition.from_state is LifecycleState.RECEIVED


def test_recovery_without_validation_raises() -> None:
    record = _record(validations=[])
    with pytest.raises(ContractError):
        apply_transition(record, LifecycleState.RECOVERED, reason="done", at=LATER)


def test_recovery_with_failed_validation_raises() -> None:
    record = _record()
    record.validations = [_validation(passed=False)]
    with pytest.raises(ContractError):
        apply_transition(record, LifecycleState.RECOVERED, reason="done", at=LATER)


def test_recovery_with_stale_patch_hash_raises() -> None:
    """The patch changed after validation — the evidence is stale."""
    record = _record(attempts=[_attempt("hash-a")])
    record.validations = [_validation("hash-old")]
    with pytest.raises(ContractError, match="stale"):
        apply_transition(record, LifecycleState.RECOVERED, reason="done", at=LATER)


def test_recovery_with_no_binding_hash_raises() -> None:
    record = _record()
    record.validations = [_validation(None)]
    with pytest.raises(ContractError):
        apply_transition(record, LifecycleState.RECOVERED, reason="done", at=LATER)


def test_recovery_with_real_binding_succeeds() -> None:
    record = _record()
    apply_transition(record, LifecycleState.RECOVERED, reason="all checks passed", at=LATER)
    assert record.state is LifecycleState.RECOVERED
    assert len(record.state_history) == 1


def test_retry_adds_a_history_entry_and_does_not_erase_it() -> None:
    event = make_event()
    record = IncidentRecord(
        incident_id="inc-1",
        event=event,
        state=LifecycleState.FAILED,
        created_at=FIXED_TS,
        updated_at=FIXED_TS,
        idempotency_key=event.idempotency_key,
    )
    apply_transition(record, LifecycleState.DIAGNOSING, reason="retry", at=utc_now())
    apply_transition(record, LifecycleState.DIAGNOSED, reason="done", at=utc_now())
    apply_transition(record, LifecycleState.REMEDIATION_PENDING, reason="plan", at=utc_now())
    assert len(record.state_history) == 3
    assert [h.to_state for h in record.state_history] == [
        LifecycleState.DIAGNOSING,
        LifecycleState.DIAGNOSED,
        LifecycleState.REMEDIATION_PENDING,
    ]
