"""Safety-critical contract invariants.

These tests assert that the *impossible* states really are impossible: a passing
validation without real checks, a naive timestamp, a recovery with no justification.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from openmedic.domain import (
    CheckResult,
    CheckStatus,
    ContractError,
    DiagnosisResult,
    FailureEvent,
    FailureType,
    IncidentRecord,
    LifecycleState,
    RecommendedAction,
    RiskLevel,
    ValidationResult,
    utc_now,
    validate_transition,
)
from openmedic.domain.contracts import SCHEMA_VERSION
from tests.conftest import make_event


def _passed(name: str = "pytest") -> CheckResult:
    return CheckResult(
        name=name, command=["pytest", "-q"], status=CheckStatus.PASSED, exit_code=0, required=True
    )


def test_timestamp_must_be_timezone_aware() -> None:
    with pytest.raises(ContractError):
        make_event(timestamp=datetime(2026, 10, 9, 12, 0))  # naive — no tzinfo


def test_timestamp_with_offset_is_accepted() -> None:
    event = make_event(timestamp=datetime(2026, 10, 9, 12, 0, tzinfo=UTC))
    assert event.timestamp.utcoffset() is not None


def test_idempotency_key_is_stable_and_distinguishes_runs() -> None:
    first = make_event(run_id="1001")
    same = make_event(run_id="1001", commit_sha="b" * 40)
    other = make_event(run_id="1002")
    assert first.idempotency_key == same.idempotency_key
    assert first.resolved_incident_id == same.resolved_incident_id
    assert first.idempotency_key != other.idempotency_key


def test_incident_id_is_derived_when_absent() -> None:
    supplied = make_event(incident_id="custom-id")
    assert supplied.resolved_incident_id == "custom-id"


def test_extra_fields_are_forbidden() -> None:
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError
        FailureEvent(
            logs="x",
            timestamp=utc_now(),
            definitely_not_a_field="surprise",
        )


# --------------------------------------------------------------------------
# ValidationResult: passing without passing must be impossible
# --------------------------------------------------------------------------


def test_passing_validation_requires_executed_checks() -> None:
    with pytest.raises(ContractError):
        ValidationResult(incident_id="inc-1", passed=True, checks_executed=[])


def test_passing_validation_rejects_skipped_required_check() -> None:
    skipped = _passed().model_copy(update={"status": CheckStatus.SKIPPED})
    with pytest.raises(ContractError):
        ValidationResult(incident_id="inc-1", passed=True, checks_executed=[_passed(), skipped])


@pytest.mark.parametrize(
    "status",
    [CheckStatus.FAILED, CheckStatus.ERRORED, CheckStatus.TIMED_OUT, CheckStatus.MISSING],
)
def test_passing_validation_rejects_any_non_success(status: CheckStatus) -> None:
    bad = _passed().model_copy(update={"status": status})
    with pytest.raises(ContractError):
        ValidationResult(incident_id="inc-1", passed=True, checks_executed=[bad])


def test_passing_validation_rejects_nonempty_failed_checks() -> None:
    with pytest.raises(ContractError):
        ValidationResult(
            incident_id="inc-1",
            passed=True,
            checks_executed=[_passed()],
            failed_checks=["pytest"],
        )


def test_empty_optional_check_does_not_block_pass() -> None:
    optional = _passed().model_copy(update={"status": CheckStatus.SKIPPED, "required": False})
    result = ValidationResult(
        incident_id="inc-1", passed=True, checks_executed=[_passed(), optional]
    )
    assert result.passed is True


def test_failed_validation_without_blocking_checks_needs_a_summary() -> None:
    with pytest.raises(ContractError):
        ValidationResult(incident_id="inc-1", passed=False, checks_executed=[_passed()], summary="")
    result = ValidationResult(
        incident_id="inc-1", passed=False, checks_executed=[_passed()], summary="runner aborted"
    )
    assert result.passed is False


# --------------------------------------------------------------------------
# DiagnosisResult
# --------------------------------------------------------------------------


def _diagnosis(**overrides: object) -> DiagnosisResult:
    defaults: dict[str, object] = {
        "incident_id": "inc-1",
        "failure_type": FailureType.DEPENDENCY_ERROR,
        "probable_cause": "requests is not installed",
        "confidence": 0.8,
        "recommended_action": RecommendedAction.FIX_DEPENDENCY,
        "risk_level": RiskLevel.LOW,
        "limitations": ["single rule matched"],
    }
    defaults.update(overrides)
    return DiagnosisResult(**defaults)  # type: ignore[arg-type]


def test_limitations_are_mandatory() -> None:
    with pytest.raises(ContractError):
        _diagnosis(limitations=[])


def test_confidence_is_bounded() -> None:
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError
        _diagnosis(confidence=1.5)
    assert _diagnosis(confidence=0.5).confidence == 0.5


def test_unverified_evidence_is_detected() -> None:
    from openmedic.domain import Evidence

    verified = Evidence(source="logs:1", quote="line one", explanation="present")
    inferred = Evidence(source="inferred", quote="not in text", explanation="guess", inferred=True)
    diagnosis = _diagnosis(evidence=[verified, inferred])
    unverified = diagnosis.verify_evidence("prefix\nline one\nsuffix")
    assert unverified == []
    unverified = diagnosis.verify_evidence("nothing matching")
    assert [e.quote for e in unverified] == ["line one"]


def test_inferred_evidence_is_never_reported_as_unverified() -> None:
    from openmedic.domain import Evidence

    inferred = Evidence(
        source="inferred", quote="totally absent", explanation="guess", inferred=True
    )
    diagnosis = _diagnosis(evidence=[inferred])
    assert diagnosis.verify_evidence("unrelated text") == []


# --------------------------------------------------------------------------
# IncidentRecord redaction
# --------------------------------------------------------------------------


def test_incident_redaction_removes_secrets_from_logs() -> None:
    event = make_event(logs="token=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nfailure output")
    record = IncidentRecord(
        incident_id="inc-1",
        event=event,
        state=LifecycleState.RECEIVED,
        created_at=utc_now(),
        updated_at=utc_now(),
        idempotency_key=event.idempotency_key,
    )
    assert "sk-aaaa" in record.event.logs
    redacted = record.redacted()
    assert "sk-aaaa" not in redacted.event.logs


def test_schema_version_is_present() -> None:
    event = make_event()
    assert event.schema_version == SCHEMA_VERSION


def test_lifecycle_rejects_direct_recovery_from_received() -> None:
    with pytest.raises(ContractError):
        validate_transition(LifecycleState.RECEIVED, LifecycleState.RECOVERED)
