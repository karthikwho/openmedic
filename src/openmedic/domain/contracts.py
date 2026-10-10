"""Domain contracts.

These models implement the field sets, enums, and invariants published in
``docs/API_CONTRACTS.md``. They are deliberately the lowest layer in the dependency
graph: nothing here imports any other OpenMedic layer, so ingestion, diagnosis,
remediation, persistence, and the CLI can all depend on them without creating a cycle.

Two invariants are enforced structurally rather than by convention, because getting them
wrong silently would be a safety failure:

1. :class:`ValidationResult` cannot be constructed with ``passed=True`` unless every
   executed required check actually succeeded and at least one check ran.
2. :class:`DiagnosisResult` clamps ``confidence`` into ``[0.0, 1.0]`` so downstream
   consumers never have to re-range-check it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from .enums import (
    CheckStatus,
    FailureType,
    LifecycleState,
    RecommendedAction,
    RemediationStatus,
    RiskLevel,
)
from .errors import ContractError
from .redaction import RedactionResult, redact

#: Bumped only for a breaking contract change. See docs/API_CONTRACTS.md section 8.
SCHEMA_VERSION: Final = "1.0.0"

#: Maximum characters of any command output retained in a persisted record.
MAX_EXCERPT_CHARS: Final = 2000


def _require_tz_aware(value: datetime) -> datetime:
    """Reject timezone-naive datetimes.

    ``docs/API_CONTRACTS.md`` requires timezone-aware timestamps normalised to UTC. A
    naive datetime is rejected outright rather than silently assumed to be local time,
    because "assumed local" has produced real ordering bugs.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        msg = "timestamps must be timezone-aware (API_CONTRACTS.md section 1)"
        raise ContractError(msg)
    return value


class _Contract(BaseModel):
    """Shared configuration for every contract model."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_assignment=True,
        str_strip_whitespace=True,
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable payload using the canonical field names."""
        return self.model_dump(mode="json")


class _Aggregate(BaseModel):
    """Base for the incident aggregate, which evolves over its lifetime.

    :class:`~openmedic.domain.contracts.IncidentRecord` is deliberately mutable because
    a lifecycle transition, a new diagnosis, or a retry must be recorded in place. Every
    value object in this module is frozen instead; only the aggregate is allowed to
    change.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=False,
        validate_assignment=True,
        str_strip_whitespace=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class Evidence(_Contract):
    """One piece of traceable evidence supporting a diagnosis."""

    source: str = Field(description="Where the quote came from (e.g. 'logs:42').")
    quote: str = Field(description="Verbatim text, or a clearly-marked inference.")
    explanation: str = Field(description="Why this quote supports the probable cause.")
    inferred: bool = Field(
        default=False,
        description=(
            "True when the quote is not verbatim from the source and must not be "
            "treated as a verified reference."
        ),
    )


class FailureEvent(_Contract):
    """A normalised CI failure event (API_CONTRACTS.md section 2)."""

    schema_version: str = SCHEMA_VERSION
    incident_id: str | None = Field(
        default=None,
        description=(
            "Stable incident identifier. Optional on input: when absent it is derived "
            "deterministically from the idempotency key so repeated ingestion of the "
            "same source event maps to the same incident."
        ),
    )
    repository: str | None = None
    commit_sha: str | None = None
    workflow_name: str | None = None
    run_id: str | None = None
    failed_step: str | None = None
    job_name: str | None = Field(default=None, description="Optional GitHub job name.")
    failure_type: FailureType = FailureType.UNKNOWN
    logs: str = Field(description="Raw log evidence, unredacted, for quote verification.")
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def _check_timestamp(cls, value: datetime) -> datetime:
        return _require_tz_aware(value)

    @property
    def idempotency_key(self) -> str:
        """Stable key used to deduplicate ingestion (API_CONTRACTS.md section 1)."""
        return "|".join(
            [
                self.repository or "-",
                self.workflow_name or "-",
                self.job_name or "-",
                self.run_id or "-",
                self.failed_step or "-",
            ]
        )

    @property
    def resolved_incident_id(self) -> str:
        """Incident id, derived from the idempotency key when not supplied."""
        return self.incident_id or f"inc-{_short_hash(self.idempotency_key)}"

    def redacted(self) -> FailureEvent:
        """Return a copy whose ``logs`` have secrets redacted."""
        return self.model_copy(update={"logs": redact(self.logs).text})


class CheckResult(_Contract):
    """One executed validation check."""

    name: str = Field(description="Allowlisted check identifier, not the raw command.")
    command: list[str] = Field(description="The exact argv that was executed.")
    status: CheckStatus
    exit_code: int | None = None
    duration_seconds: float | None = None
    required: bool = Field(
        default=True,
        description="A skipped required check can never contribute to a passing result.",
    )
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""

    @property
    def passed(self) -> bool:
        """Return whether this check passed."""
        return self.status is CheckStatus.PASSED

    @property
    def is_blocking_failure(self) -> bool:
        """True when this check prevents an overall pass.

        A skipped *optional* check is tolerated. A skipped, missing, errored, or timed
        out *required* check is not, per API_CONTRACTS.md section 4.
        """
        if self.status is CheckStatus.PASSED:
            return False
        return self.required


class ExecutionMetadata(_Contract):
    """How and where the validation candidate was executed."""

    isolation_kind: str = Field(
        default="local-subprocess",
        description=(
            "One of 'local-subprocess', 'local-venv', or 'docker'. Honest by design: "
            "'local-subprocess' is NOT a hardened sandbox and must never be presented "
            "as equivalent to one."
        ),
    )
    sandbox_id: str | None = None
    worktree_path: str | None = None
    docker_available: bool = False
    timeout_seconds: float | None = None
    limitations: list[str] = Field(default_factory=list)


class ValidationResult(_Contract):
    """Result of validating a specific candidate patch (API_CONTRACTS.md section 4).

    The structural invariant is enforced in :meth:`_enforce_honest_pass`: it is
    impossible to construct a passing result without real, complete checks.
    """

    schema_version: str = SCHEMA_VERSION
    incident_id: str
    candidate_patch_hash: str | None = Field(
        default=None,
        description="Identity of the exact patch this result applies to.",
    )
    passed: bool = False
    checks_executed: list[CheckResult] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    summary: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None
    execution: ExecutionMetadata = Field(default_factory=ExecutionMetadata)

    @field_validator("started_at", "completed_at")
    @classmethod
    def _check_ts(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _require_tz_aware(value)

    @model_validator(mode="after")
    def _enforce_honest_pass(self) -> ValidationResult:
        return _validate_honesty(self)


def _validate_honesty(result: ValidationResult) -> ValidationResult:
    """Make a dishonest ``passed`` value unrepresentable.

    Raises :class:`ContractError` rather than coercing, so a bug surfaces loudly instead
    of being silently repaired into a plausible-looking record.
    """
    blocking = [c for c in result.checks_executed if c.is_blocking_failure]
    if result.passed:
        if not result.checks_executed:
            msg = "passed=True requires at least one executed check (empty checks_executed)"
            raise ContractError(msg)
        if blocking:
            msg = f"passed=True while required checks did not pass: {[c.name for c in blocking]!r}"
            raise ContractError(msg)
        if result.failed_checks:
            msg = f"passed=True while failed_checks is non-empty: {result.failed_checks!r}"
            raise ContractError(msg)
        return result

    # A constructed failure must be self-consistent too.
    # Every check passed or was optionally skipped, yet the result says it failed. That
    # is allowed only when the caller supplies a summary explaining why.
    if not blocking and result.checks_executed and not result.failed_checks and not result.summary:
        msg = "failed validation with no blocking checks requires an explanatory summary"
        raise ContractError(msg)
    return result


class DiagnosisResult(_Contract):
    """A diagnosis with traceable evidence (API_CONTRACTS.md section 3)."""

    schema_version: str = SCHEMA_VERSION
    incident_id: str
    failure_type: FailureType
    probable_cause: str
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_action: RecommendedAction
    risk_level: RiskLevel
    requires_human_review: bool = False
    limitations: list[str] = Field(default_factory=list)
    rule_id: str = Field(
        default="deterministic",
        description="Identifier of the rule that produced this result.",
    )
    rule_version: str = "1"
    provider_used: bool = Field(
        default=False,
        description="True only when a configured model provider contributed.",
    )

    @field_validator("confidence")
    @classmethod
    def _clamp_confidence(cls, value: float) -> float:
        # Pydantic enforces [0,1] via ge/le; this guard documents the intent and keeps
        # the contract honest if the bounds ever move.
        if value != value:  # NaN
            msg = "confidence must be a real number"
            raise ContractError(msg)
        return min(max(value, 0.0), 1.0)

    @model_validator(mode="after")
    def _require_limitations(self) -> DiagnosisResult:
        """``limitations`` must be populated, per API_CONTRACTS.md section 3."""
        if not self.limitations:
            msg = "limitations must be populated (API_CONTRACTS.md section 3)"
            raise ContractError(msg)
        return self

    def verify_evidence(self, source_text: str) -> list[Evidence]:
        """Return the evidence items whose quote is **not** verbatim in ``source_text``.

        An inference is not a defect — it is marked as one — so a quote from an
        ``inferred=True`` item is never reported as unverified.
        """
        unverified: list[Evidence] = []
        for item in self.evidence:
            if item.inferred:
                continue
            if item.quote not in source_text:
                unverified.append(item)
        return unverified


class RemediationAttempt(_Contract):
    """One bounded remediation proposal (API_CONTRACTS.md section 5)."""

    schema_version: str = SCHEMA_VERSION
    attempt_id: str
    incident_id: str
    status: RemediationStatus
    rule_id: str
    summary: str
    rationale: str
    risk_level: RiskLevel
    requires_human_review: bool = True
    files_changed: list[str] = Field(default_factory=list)
    patch_unified_diff: str = ""
    patch_hash: str | None = Field(
        default=None,
        description="SHA-256 of the unified diff. Binds validation to this exact patch.",
    )
    validation_id: str | None = None
    created_at: datetime
    superseded_by: str | None = None
    rejection_reason: str | None = None

    @field_validator("created_at")
    @classmethod
    def _check_ts(cls, value: datetime) -> datetime:
        return _require_tz_aware(value)


class StateTransition(_Contract):
    """An audited lifecycle transition."""

    from_state: LifecycleState | None
    to_state: LifecycleState
    reason: str
    at: datetime

    @field_validator("at")
    @classmethod
    def _check_ts(cls, value: datetime) -> datetime:
        return _require_tz_aware(value)


class IncidentRecord(_Aggregate):
    """The durable incident aggregate (API_CONTRACTS.md section 5)."""

    schema_version: str = SCHEMA_VERSION
    incident_id: str
    event: FailureEvent
    state: LifecycleState = LifecycleState.RECEIVED
    created_at: datetime
    updated_at: datetime
    diagnoses: list[DiagnosisResult] = Field(default_factory=list)
    attempts: list[RemediationAttempt] = Field(default_factory=list)
    validations: list[ValidationResult] = Field(default_factory=list)
    state_history: list[StateTransition] = Field(default_factory=list)
    idempotency_key: str

    @field_validator("created_at", "updated_at")
    @classmethod
    def _check_ts(cls, value: datetime) -> datetime:
        return _require_tz_aware(value)

    @property
    def latest_diagnosis(self) -> DiagnosisResult | None:
        """Return the most recent diagnosis, or None when none was recorded."""
        return self.diagnoses[-1] if self.diagnoses else None

    @property
    def latest_validation(self) -> ValidationResult | None:
        """Return the most recent validation, or None when none was recorded."""
        return self.validations[-1] if self.validations else None

    def redacted(self) -> IncidentRecord:
        """Return a copy with secret material removed from all free text."""
        event = self.event.redacted()
        validations = [
            v.model_copy(
                update={
                    "summary": redact(v.summary).text,
                    "checks_executed": [
                        c.model_copy(
                            update={
                                "stdout_excerpt": redact(c.stdout_excerpt).text,
                                "stderr_excerpt": redact(c.stderr_excerpt).text,
                            }
                        )
                        for c in v.checks_executed
                    ],
                }
            )
            for v in self.validations
        ]
        return self.model_copy(update={"event": event, "validations": validations})


def _short_hash(value: str) -> str:
    """Return a short, stable, non-cryptographic display hash.

    Used only for idempotency keys and fingerprints, never for security decisions.
    """
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def redact_excerpt(text: str, *, limit: int = MAX_EXCERPT_CHARS) -> str:
    """Redact and truncate command output for safe persistence."""
    redacted = redact(text)
    excerpt = redacted.text
    if len(excerpt) > limit:
        excerpt = excerpt[:limit] + "\n...[truncated]"
    result = RedactionResult(text=excerpt, detections=redacted.detections)
    return result.text


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)
