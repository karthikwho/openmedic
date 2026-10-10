"""Shared fixtures for the reporting-layer tests.

The reporting layer is only as honest as the incidents it is handed, so these builders
produce deliberately awkward records: an inferred evidence item, a rejected attempt, a
validated attempt, a failed validation, a skipped required check, and a record whose state
claims recovery while its validation is stale.

Every free-text field plants :data:`REDACTION_PROBE`, a value the domain redactor always
recognises, so a test can assert that redaction reached *every* one of them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from openmedic.domain.contracts import (
    CheckResult,
    DiagnosisResult,
    Evidence,
    ExecutionMetadata,
    FailureEvent,
    IncidentRecord,
    RemediationAttempt,
    StateTransition,
    ValidationResult,
)
from openmedic.domain.enums import (
    CheckStatus,
    FailureType,
    LifecycleState,
    RecommendedAction,
    RemediationStatus,
    RiskLevel,
)

#: Matches the domain redactor's ``aws_access_key`` pattern. Never a real credential.
REDACTION_PROBE = "AKIAIOSFODNN7EXAMPLE"

INCIDENT_ID = "inc-9f2c1d"

PATCH_HASH_REJECTED = "a" * 64
PATCH_HASH_VALIDATED = "b" * 64
PATCH_HASH_NEWER = "c" * 64

#: Raw log evidence. The verified evidence quote below must be verbatim in here.
LOGS = (
    "##[group]Run pytest\n"
    "$ pytest -q tests/\n"
    "============================= test session starts ==============================\n"
    "collected 3 items\n"
    "\n"
    "tests/test_app.py::test_add FAILED\n"
    "E   AssertionError: assert 4 == 5\n"
    "=========================== 1 failed, 2 passed =========================\n"
)

VERIFIED_QUOTE = "E   AssertionError: assert 4 == 5"


def _ts(minutes: int) -> datetime:
    """Return a deterministic timezone-aware UTC timestamp ``minutes`` past the base."""
    return datetime(2026, 10, 9, 12, 0, tzinfo=UTC) + timedelta(minutes=minutes)


def planted(text: str) -> str:
    """Return ``text`` with the redaction probe appended."""
    return f"{text} (probe {REDACTION_PROBE})"


def build_event() -> FailureEvent:
    """Return the originating failure event."""
    return FailureEvent(
        incident_id=INCIDENT_ID,
        repository=planted("acme/widgets"),
        commit_sha="0f1e2d3c4b5a69788796a5b4c3d2e1f009182736",
        workflow_name="CI",
        run_id="418",
        failed_step="Run tests",
        job_name="build",
        failure_type=FailureType.TEST_FAILURE,
        logs=planted(LOGS),
        timestamp=_ts(0),
    )


def build_diagnosis() -> DiagnosisResult:
    """Return a diagnosis with one verified quote and one inferred one."""
    return DiagnosisResult(
        incident_id=INCIDENT_ID,
        failure_type=FailureType.TEST_FAILURE,
        probable_cause=planted("Off-by-one in add()"),
        evidence=[
            Evidence(
                source="logs:6",
                quote=VERIFIED_QUOTE,
                explanation=planted("The assertion states the observed value directly."),
                inferred=False,
            ),
            Evidence(
                source="inference (no log line)",
                quote=planted("The regression was introduced by the arithmetic change."),
                explanation=planted("No log line states this; it follows from the diff only."),
                inferred=True,
            ),
        ],
        confidence=0.62,
        recommended_action=RecommendedAction.FIX_FAILING_TEST,
        risk_level=RiskLevel.MEDIUM,
        requires_human_review=True,
        limitations=[planted("Only the failing step log was available.")],
        rule_id="deterministic/test/assertion",
        rule_version="2",
        provider_used=False,
    )


def build_rejected_attempt() -> RemediationAttempt:
    """Return an attempt the safety policy rejected."""
    return RemediationAttempt(
        attempt_id="att-1",
        incident_id=INCIDENT_ID,
        status=RemediationStatus.REJECTED,
        rule_id="remediation/delete-failing-test",
        summary=planted("Delete the failing test"),
        rationale=planted("Removing the assertion removes the failure signal."),
        risk_level=RiskLevel.HIGH,
        requires_human_review=True,
        files_changed=[planted("tests/test_app.py")],
        patch_unified_diff=planted("--- a/tests/test_app.py\n-    assert add(2, 2) == 5\n"),
        patch_hash=PATCH_HASH_REJECTED,
        created_at=_ts(3),
        rejection_reason=planted("The patch deletes a test, which the policy rejects."),
    )


def build_validated_attempt() -> RemediationAttempt:
    """Return the attempt that was applied and then validated."""
    return RemediationAttempt(
        attempt_id="att-2",
        incident_id=INCIDENT_ID,
        status=RemediationStatus.APPLIED,
        rule_id="remediation/fix-off-by-one",
        summary=planted("Fix the off-by-one in add()"),
        rationale=planted("The assertion shows the wrong observed value."),
        risk_level=RiskLevel.LOW,
        requires_human_review=True,
        files_changed=["src/app.py"],
        patch_unified_diff=planted("--- a/src/app.py\n-    return a + b\n+    return a + b + 1\n"),
        patch_hash=PATCH_HASH_VALIDATED,
        validation_id="val-2",
        created_at=_ts(4),
    )


def build_newer_attempt() -> RemediationAttempt:
    """Return a subsequent attempt whose patch has never been validated."""
    return RemediationAttempt(
        attempt_id="att-3",
        incident_id=INCIDENT_ID,
        status=RemediationStatus.APPLIED,
        rule_id="remediation/fix-off-by-one",
        summary=planted("Second attempt at the off-by-one"),
        rationale=planted("The first patch missed a second call site."),
        risk_level=RiskLevel.MEDIUM,
        requires_human_review=True,
        files_changed=["src/app.py", "src/legacy.py"],
        patch_unified_diff=planted(
            "--- a/src/legacy.py\n-    return a + b\n+    return a + b + 1\n"
        ),
        patch_hash=PATCH_HASH_NEWER,
        validation_id=None,
        created_at=_ts(9),
    )


def build_failed_validation() -> ValidationResult:
    """Return a validation that failed."""
    return ValidationResult(
        incident_id=INCIDENT_ID,
        candidate_patch_hash=PATCH_HASH_REJECTED,
        passed=False,
        checks_executed=[
            CheckResult(
                name="unit-tests",
                command=["pytest", "-q"],
                status=CheckStatus.FAILED,
                exit_code=1,
                duration_seconds=1.2,
                required=True,
                stdout_excerpt=planted("1 failed, 2 passed"),
                stderr_excerpt=planted("E   AssertionError: assert 4 == 5"),
            )
        ],
        failed_checks=["unit-tests"],
        summary=planted("unit-tests failed for the candidate patch"),
        started_at=_ts(5),
        completed_at=_ts(6),
        execution=ExecutionMetadata(
            isolation_kind="local-subprocess",
            sandbox_id=None,
            worktree_path=planted("/tmp/openmedic/att-1"),  # noqa: S108 - planted probe text
            docker_available=False,
            timeout_seconds=300.0,
            limitations=[planted("No network access was available during validation.")],
        ),
    )


def build_passing_validation() -> ValidationResult:
    """Return a passing validation bound to the validated attempt's patch."""
    return ValidationResult(
        incident_id=INCIDENT_ID,
        candidate_patch_hash=PATCH_HASH_VALIDATED,
        passed=True,
        checks_executed=[
            CheckResult(
                name="unit-tests",
                command=["pytest", "-q"],
                status=CheckStatus.PASSED,
                exit_code=0,
                duration_seconds=0.9,
                required=True,
            ),
            CheckResult(
                name="ruff-check",
                command=["ruff", "check", "."],
                status=CheckStatus.PASSED,
                exit_code=0,
                duration_seconds=0.4,
                required=True,
            ),
        ],
        failed_checks=[],
        summary=planted("All required checks passed for the exact candidate patch"),
        started_at=_ts(7),
        completed_at=_ts(8),
        execution=ExecutionMetadata(
            isolation_kind="local-subprocess",
            sandbox_id="sbx-1",
            worktree_path=planted("/tmp/openmedic/att-2"),  # noqa: S108 - planted probe text
            docker_available=False,
            timeout_seconds=600.0,
            limitations=[
                planted("local-subprocess shares the host filesystem; it is not a sandbox."),
                "No network access was available during validation.",
            ],
        ),
    )


def build_skipped_validation() -> ValidationResult:
    """Return a validation whose only required check was skipped.

    A skipped required check is an explicit non-success, so this result can never pass.
    """
    return ValidationResult(
        incident_id=INCIDENT_ID,
        candidate_patch_hash=PATCH_HASH_VALIDATED,
        passed=False,
        checks_executed=[
            CheckResult(
                name="lint",
                command=["ruff", "check", "."],
                status=CheckStatus.SKIPPED,
                exit_code=None,
                duration_seconds=None,
                required=True,
                stdout_excerpt="",
                stderr_excerpt="",
            )
        ],
        failed_checks=[],
        summary=planted("lint was skipped, so nothing is proven"),
        started_at=_ts(7),
        completed_at=_ts(8),
        execution=ExecutionMetadata(
            isolation_kind="local-subprocess",
            docker_available=False,
            timeout_seconds=600.0,
            limitations=[planted("No network access was available during validation.")],
        ),
    )


def build_state_history(final: LifecycleState = LifecycleState.RECOVERED) -> list[StateTransition]:
    """Return an audited transition history ending at ``final``."""
    path = [
        (None, LifecycleState.RECEIVED, planted("ingested from a local log file")),
        (LifecycleState.RECEIVED, LifecycleState.DIAGNOSING, "deterministic diagnosis started"),
        (LifecycleState.DIAGNOSING, LifecycleState.DIAGNOSED, planted("test failure rule matched")),
        (LifecycleState.DIAGNOSED, LifecycleState.REMEDIATION_PENDING, "action proposal ready"),
        (
            LifecycleState.REMEDIATION_PENDING,
            LifecycleState.REMEDIATING,
            planted("second attempt applied in a disposable worktree"),
        ),
        (LifecycleState.REMEDIATING, LifecycleState.VALIDATING, "checks started"),
        (
            LifecycleState.VALIDATING,
            final,
            planted("all required checks passed for the exact candidate patch"),
        ),
    ]
    return [
        StateTransition(from_state=origin, to_state=target, reason=reason, at=_ts(minutes))
        for minutes, (origin, target, reason) in enumerate(path)
    ]


def build_record(
    *,
    state: LifecycleState = LifecycleState.RECOVERED,
    attempts: list[RemediationAttempt] | None = None,
    validations: list[ValidationResult] | None = None,
    history: list[StateTransition] | None = None,
    with_diagnosis: bool = True,
) -> IncidentRecord:
    """Return an incident record assembled from the shared builders."""
    resolved_attempts = (
        [build_rejected_attempt(), build_validated_attempt()] if attempts is None else attempts
    )
    resolved_validations = (
        [build_failed_validation(), build_passing_validation()]
        if validations is None
        else validations
    )
    resolved_history = build_state_history() if history is None else history
    return IncidentRecord(
        incident_id=INCIDENT_ID,
        event=build_event(),
        state=state,
        created_at=_ts(0),
        updated_at=_ts(8),
        diagnoses=[build_diagnosis()] if with_diagnosis else [],
        attempts=resolved_attempts,
        validations=resolved_validations,
        state_history=resolved_history,
        idempotency_key="acme/widgets|CI|build|418|Run tests",
    )


def build_stale_recovery_record() -> IncidentRecord:
    """Return a record whose state says recovered while its validation is stale.

    The last validation passed, but it is bound to the *previous* patch; a newer attempt
    has since changed the patch. Recovery must be revoked until validation is rerun.
    """
    record = build_record()
    return record.model_copy(
        update={
            "attempts": [*record.attempts, build_newer_attempt()],
            "updated_at": _ts(10),
        }
    )


def build_all_status_attempts() -> list[RemediationAttempt]:
    """Return one attempt for every remediation status, with distinct patch hashes."""
    statuses = [
        RemediationStatus.PROPOSED,
        RemediationStatus.AWAITING_REVIEW,
        RemediationStatus.REJECTED,
        RemediationStatus.APPLIED,
        RemediationStatus.SUPERSEDED,
        RemediationStatus.FAILED,
    ]
    return [
        RemediationAttempt(
            attempt_id=f"att-{index}",
            incident_id=INCIDENT_ID,
            status=status,
            rule_id=f"remediation/rule-{status.value}",
            summary=planted(f"attempt for status {status.value}"),
            rationale=planted("deterministic rationale"),
            risk_level=RiskLevel.LOW,
            requires_human_review=True,
            files_changed=["src/app.py"],
            patch_hash=str(index) * 64,
            created_at=_ts(index),
            superseded_by="att-1" if status is RemediationStatus.SUPERSEDED else None,
            rejection_reason=(
                planted("rejected by policy") if status is RemediationStatus.REJECTED else None
            ),
        )
        for index, status in enumerate(statuses, start=1)
    ]
