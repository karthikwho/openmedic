"""Machine-readable incident report and the shared honesty vocabulary.

Three renderers consume the same incident: the terminal report
(:mod:`openmedic.reporting.terminal`), the JSON payload built here, and the
GitHub-commentable markdown (:mod:`openmedic.reporting.markdown`). They must never
disagree about what happened, so the two questions that decide honesty are answered
here, once, and imported by the other two:

* :func:`recovery_status` — is this incident *actually* recovered? It requires a passing
  validation bound to the exact patch currently recorded on the incident, which is the
  same invariant :mod:`openmedic.domain.lifecycle` enforces when entering ``recovered``.
  A record that claims ``recovered`` but whose validation is stale cannot be reported as
  recovered, however the state field reads.
* :func:`attempt_status_label` — what do we call this attempt? ``suggested``,
  ``attempted``, ``rejected``, ``failed``, ``awaiting review`` and ``validated`` are
  distinct words because FR-007 requires the reader to be able to tell them apart.

Redaction is a property of the payload rather than of each renderer: :func:`report_dict`
walks the finished payload and redacts every free-text string except the identifiers and
controlled vocabularies in :data:`_VERBATIM_KEYS`. The walk is deliberately recursive. A
hand-maintained per-field list is exactly how a field added later silently leaks a secret
into a report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from ..domain.enums import CheckStatus, LifecycleState, RemediationStatus
from ..domain.redaction import redact

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..domain.contracts import (
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

#: Version of the *report envelope*. Distinct from the domain contract version because a
#: report may gain convenience keys without breaking any consumer of the contracts.
REPORT_SCHEMA_VERSION: Final = "1.0.0"

#: Human-readable label for every attempt status. These are the words a reader sees, so
#: they must stay distinct: FR-007 requires suggested, attempted, rejected, failed,
#: awaiting review and validated to be distinguishable at a glance.
ATTEMPT_STATUS_LABELS: Final[dict[RemediationStatus, str]] = {
    RemediationStatus.PROPOSED: "SUGGESTED",
    RemediationStatus.AWAITING_REVIEW: "AWAITING REVIEW",
    RemediationStatus.REJECTED: "REJECTED",
    RemediationStatus.APPLIED: "ATTEMPTED",
    RemediationStatus.SUPERSEDED: "SUPERSEDED",
    RemediationStatus.FAILED: "FAILED",
}

#: Keys whose values are identifiers, control vocabularies, or timestamps. Redacting them
#: would corrupt the report without protecting anything, so they are emitted verbatim.
#: Everything else — every prose field, every log excerpt, every argv entry — is redacted.
_VERBATIM_KEYS: Final[frozenset[str]] = frozenset(
    {
        "at",
        "attempt_id",
        "blocking_failure",
        "candidate_patch_hash",
        "commit_sha",
        "completed_at",
        "contract_schema_version",
        "created_at",
        "current_patch_hash",
        "docker_available",
        "duration_seconds",
        "exit_code",
        "failed_checks_count",
        "from_state",
        # Note: `idempotency_key` is deliberately *not* verbatim. It is a composite of
        # repository, workflow, job and step names — free text, not a digest — so it is
        # redacted like those fields already are. Correlation still works because
        # `incident_id`, the digest derived from it, stays verbatim.
        "incident_id",
        "isolation_kind",
        # The candidate patch identity. It is a content digest, not a credential, and a
        # consumer must be able to compare it with `current_patch_hash` above.
        "patch_hash",
        "provider_used",
        "recovered",
        "recorded_state",
        "redacted",
        "rule_id",
        "rule_version",
        "run_id",
        "schema_version",
        "stale_validation",
        "started_at",
        "state",
        "state_claims_recovery",
        "status",
        "status_label",
        "superseded_by",
        "timestamp",
        "to_state",
        "timeout_seconds",
        "validation_id",
        "validated_patch_hash",
        # Controlled vocabularies from openmedic.domain.enums.
        "failure_type",
        "recommended_action",
        "risk_level",
        "requires_human_review",
    }
)


# --------------------------------------------------------------------------------------
# Honest recovery determination
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RecoveryStatus:
    """The single honest answer to "is this incident recovered?".

    ``verified`` is the only value a renderer may turn into a claim of recovery. It is
    true only when the recorded state is ``recovered`` *and* a passing validation is
    bound to the patch the incident currently records, which is the invariant in
    ``docs/API_CONTRACTS.md`` section 6.
    """

    recorded_state: LifecycleState
    validation: ValidationResult | None
    current_attempt_patch_hash: str | None

    @property
    def state_claims_recovery(self) -> bool:
        """Return whether the recorded lifecycle state claims recovery."""
        return self.recorded_state is LifecycleState.RECOVERED

    @property
    def validated_patch_hash(self) -> str | None:
        """Return the patch hash the latest validation is bound to."""
        return None if self.validation is None else self.validation.candidate_patch_hash

    @property
    def verified(self) -> bool:
        """Return whether recovery is proven for the patch currently recorded."""
        validation = self.validation
        if not self.state_claims_recovery or validation is None:
            return False
        if not validation.passed or not validation.checks_executed:
            return False
        if self.current_attempt_patch_hash is None:
            return False
        return self.current_attempt_patch_hash == validation.candidate_patch_hash

    @property
    def stale(self) -> bool:
        """Return whether a passing validation exists but for a different patch."""
        validation = self.validation
        if validation is None or not validation.passed:
            return False
        if validation.candidate_patch_hash is None or self.current_attempt_patch_hash is None:
            return False
        return validation.candidate_patch_hash != self.current_attempt_patch_hash

    @property
    def reason(self) -> str | None:
        """Return why a claimed recovery is not reported as one, or None if proven.

        A proven recovery has nothing to explain, so ``reason`` must stay ``None`` even
        though the final branch below would otherwise describe the matching hashes as a
        mismatch. Consumers read ``recovered`` and ``reason`` together, and two
        contradictory answers are worse than no answer.
        """
        if not self.state_claims_recovery or self.verified:
            return None
        validation = self.validation
        if validation is None:
            return "the recorded state claims recovery but no validation result exists"
        if not validation.passed:
            summary = validation.summary or "no summary recorded"
            return f"the latest validation did not pass ({summary})"
        if not validation.checks_executed:
            return "the latest validation executed no checks"
        if self.current_attempt_patch_hash is None:
            return "no remediation attempt records the current patch identity"
        # The two hashes are reported verbatim as `validated_patch_hash` and
        # `current_patch_hash` beside this field, so repeating them here would only have
        # them redacted to `[REDACTED]` in a redacted report.
        return (
            "the latest validation is bound to a different patch than the one the "
            "incident currently records (stale validation)"
        )


def recovery_status(record: IncidentRecord) -> RecoveryStatus:
    """Build the :class:`RecoveryStatus` for ``record``.

    The current patch is the last recorded attempt, because a retry adds an attempt
    rather than overwriting history (API_CONTRACTS.md section 6, rule 4).
    """
    current = record.attempts[-1] if record.attempts else None
    return RecoveryStatus(
        recorded_state=record.state,
        validation=record.latest_validation,
        current_attempt_patch_hash=None if current is None else current.patch_hash,
    )


def attempt_status_label(status: RemediationStatus) -> str:
    """Return the human-readable label for a remediation status."""
    return ATTEMPT_STATUS_LABELS.get(status, str(status).upper())


def attempt_label(attempt: RemediationAttempt, *, validated: bool) -> str:
    """Return the label for ``attempt``, appending ``VALIDATED`` when proven."""
    label = attempt_status_label(attempt.status)
    return f"{label} / VALIDATED" if validated else label


# --------------------------------------------------------------------------------------
# Serialisation helpers
# --------------------------------------------------------------------------------------


def _iso(value: datetime | None) -> str | None:
    """Return ``value`` as a UTC ISO-8601 string, or None."""
    if value is None:
        return None
    return value.astimezone(UTC).isoformat()


def _outcome_dict(status: RecoveryStatus) -> dict[str, object]:
    """Return the honest outcome block shared by every renderer."""
    payload: dict[str, object] = {
        "recovered": status.verified,
        "recorded_state": status.recorded_state.value,
        "state_claims_recovery": status.state_claims_recovery,
        "stale_validation": status.stale,
        "current_patch_hash": status.current_attempt_patch_hash,
        "validated_patch_hash": status.validated_patch_hash,
        "reason": status.reason,
    }
    return payload


def _evidence_dict(item: Evidence) -> dict[str, object]:
    """Return one evidence item, preserving its inferred/verified distinction."""
    return {
        "source": item.source,
        "quote": item.quote,
        "explanation": item.explanation,
        "inferred": item.inferred,
        "verified_quote": not item.inferred,
    }


def diagnosis_dict(diagnosis: DiagnosisResult) -> dict[str, object]:
    """Return the machine-readable payload for one diagnosis result."""
    return {
        "schema_version": diagnosis.schema_version,
        "incident_id": diagnosis.incident_id,
        "failure_type": diagnosis.failure_type.value,
        "probable_cause": diagnosis.probable_cause,
        "evidence": [_evidence_dict(item) for item in diagnosis.evidence],
        "confidence": diagnosis.confidence,
        "recommended_action": diagnosis.recommended_action.value,
        "risk_level": diagnosis.risk_level.value,
        "requires_human_review": diagnosis.requires_human_review,
        "limitations": list(diagnosis.limitations),
        "rule_id": diagnosis.rule_id,
        "rule_version": diagnosis.rule_version,
        "provider_used": diagnosis.provider_used,
    }


def _check_dict(check: CheckResult) -> dict[str, object]:
    """Return one executed check with its honest non-success status."""
    return {
        "name": check.name,
        "command": list(check.command),
        "status": check.status.value,
        "passed": check.passed,
        "required": check.required,
        "blocking_failure": check.is_blocking_failure,
        "exit_code": check.exit_code,
        "duration_seconds": check.duration_seconds,
        "stdout_excerpt": check.stdout_excerpt,
        "stderr_excerpt": check.stderr_excerpt,
    }


def _execution_dict(execution: ExecutionMetadata) -> dict[str, object]:
    """Return how and where the candidate ran, including its honest limitations."""
    return {
        "isolation_kind": execution.isolation_kind,
        "sandbox_id": execution.sandbox_id,
        "worktree_path": execution.worktree_path,
        "docker_available": execution.docker_available,
        "timeout_seconds": execution.timeout_seconds,
        "limitations": list(execution.limitations),
    }


def validation_dict(validation: ValidationResult | None) -> dict[str, object]:
    """Return the machine-readable payload for a validation, or ``{}`` when absent."""
    if validation is None:
        return {}

    checks = list(validation.checks_executed)
    not_success = [c.name for c in checks if not c.passed]
    blocking = [c.name for c in checks if c.is_blocking_failure]
    payload: dict[str, object] = {
        "schema_version": validation.schema_version,
        "incident_id": validation.incident_id,
        "candidate_patch_hash": validation.candidate_patch_hash,
        "passed": validation.passed,
        "checks_executed": [_check_dict(c) for c in checks],
        "failed_checks": list(validation.failed_checks),
        "summary": validation.summary,
        "started_at": _iso(validation.started_at),
        "completed_at": _iso(validation.completed_at),
        "execution": _execution_dict(validation.execution),
        "checks_summary": {
            "total": len(checks),
            "passed": sum(1 for c in checks if c.passed),
            "not_success": not_success,
            "required_not_success": blocking,
            "all_required_checks_passed": not blocking,
        },
    }
    return payload


def _attempt_dict(attempt: RemediationAttempt, *, validated: bool) -> dict[str, object]:
    """Return one remediation attempt, including the safety review decision."""
    return {
        "schema_version": attempt.schema_version,
        "attempt_id": attempt.attempt_id,
        "incident_id": attempt.incident_id,
        "status": attempt.status.value,
        "status_label": attempt_status_label(attempt.status),
        "validated": validated,
        "rule_id": attempt.rule_id,
        "summary": attempt.summary,
        "rationale": attempt.rationale,
        "risk_level": attempt.risk_level.value,
        "requires_human_review": attempt.requires_human_review,
        "files_changed": list(attempt.files_changed),
        "patch_hash": attempt.patch_hash,
        "patch_unified_diff": attempt.patch_unified_diff,
        "validation_id": attempt.validation_id,
        "created_at": _iso(attempt.created_at),
        "superseded_by": attempt.superseded_by,
        "rejection_reason": attempt.rejection_reason,
    }


def _event_dict(event: FailureEvent) -> dict[str, object]:
    """Return the originating event, keeping the raw log available for verification."""
    return {
        "schema_version": event.schema_version,
        "incident_id": event.incident_id,
        "repository": event.repository,
        "commit_sha": event.commit_sha,
        "workflow_name": event.workflow_name,
        "run_id": event.run_id,
        "failed_step": event.failed_step,
        "job_name": event.job_name,
        "failure_type": event.failure_type.value,
        "timestamp": _iso(event.timestamp),
        "logs": event.logs,
        "idempotency_key": event.idempotency_key,
    }


def _transition_dict(transition: StateTransition) -> dict[str, object]:
    """Return one audited lifecycle transition."""
    return {
        "from_state": None if transition.from_state is None else transition.from_state.value,
        "to_state": transition.to_state.value,
        "at": _iso(transition.at),
        "reason": transition.reason,
    }


def _validated_attempt_ids(record: IncidentRecord) -> set[str]:
    """Return the ids of attempts whose patch a passing validation is bound to."""
    validated: set[str] = set()
    for validation in record.validations:
        if not validation.passed:
            continue
        for attempt in record.attempts:
            if (
                validation.candidate_patch_hash is not None
                and attempt.patch_hash == validation.candidate_patch_hash
            ):
                validated.add(attempt.attempt_id)
    return validated


def report_dict(record: IncidentRecord, *, redact: bool = True) -> dict[str, object]:
    """Return the full machine-readable payload for ``record``.

    With ``redact=True`` the domain redactor runs over every free-text field in the
    finished payload and the top-level ``redacted`` flag is set, so a consumer never has
    to guess whether it is looking at redacted output.
    """
    status = recovery_status(record)
    validated_ids = _validated_attempt_ids(record)
    payload: dict[str, object] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "contract_schema_version": record.schema_version,
        "redacted": redact,
        "incident_id": record.incident_id,
        "state": record.state.value,
        "outcome": _outcome_dict(status),
        "event": _event_dict(record.event),
        "diagnosis": (
            None if record.latest_diagnosis is None else diagnosis_dict(record.latest_diagnosis)
        ),
        "diagnosis_history": [diagnosis_dict(d) for d in record.diagnoses],
        "remediation_attempts": [
            _attempt_dict(a, validated=a.attempt_id in validated_ids) for a in record.attempts
        ],
        "validation": validation_dict(record.latest_validation),
        "validation_history": [validation_dict(v) for v in record.validations],
        "state_history": [_transition_dict(t) for t in record.state_history],
    }
    if not redact:
        return payload
    redacted = _redact_payload(payload)
    return redacted if isinstance(redacted, dict) else {}


def report_json(record: IncidentRecord, *, redact: bool = True, indent: int | None = 2) -> str:
    """Return :func:`report_dict` serialised as JSON text."""
    payload = report_dict(record, redact=redact)
    # ``default=str`` is a final guard so a report can never fail to serialise: losing a
    # field is bad, but a report that raises is worse.
    return json.dumps(payload, indent=indent, ensure_ascii=True, sort_keys=False, default=str)


# --------------------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------------------


def _redact_text(value: str) -> str:
    """Return ``value`` with every detected secret replaced."""
    return redact(value).text


def _redact_payload(value: Any) -> Any:
    """Recursively redact every string outside :data:`_VERBATIM_KEYS`.

    Structure and key order are preserved exactly, so a redacted payload has the same
    shape as an unredacted one.
    """
    if isinstance(value, dict):
        return {
            key: (item if key in _VERBATIM_KEYS else _redact_payload(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_payload(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def check_status_label(status: CheckStatus) -> str:
    """Return the label for a check status, marking every non-success as such."""
    if status is CheckStatus.PASSED:
        return "PASSED"
    return f"{status.value.upper()} (not success)"
