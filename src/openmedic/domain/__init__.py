"""OpenMedic domain layer: contracts, enums, errors, lifecycle, redaction.

Nothing in this package imports any other OpenMedic layer.
"""

from __future__ import annotations

from .contracts import (
    MAX_EXCERPT_CHARS,
    SCHEMA_VERSION,
    CheckResult,
    DiagnosisResult,
    Evidence,
    ExecutionMetadata,
    FailureEvent,
    IncidentRecord,
    RemediationAttempt,
    StateTransition,
    ValidationResult,
    redact_excerpt,
    utc_now,
)
from .enums import (
    CheckStatus,
    FailureType,
    LifecycleState,
    RecommendedAction,
    RemediationStatus,
    RiskLevel,
)
from .errors import (
    ContractError,
    HumanReviewRequiredError,
    IntegrationUnavailableError,
    InvalidInputError,
    OpenMedicError,
    PersistenceError,
    PolicyViolationError,
    UnresolvedRepairError,
    UsageError,
    ValidationFailedError,
)
from .lifecycle import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    apply_transition,
    can_transition,
    validate_transition,
)
from .redaction import PLACEHOLDER, SecretDetection, redact, redact_one_line

__all__ = [
    "ALLOWED_TRANSITIONS",
    "MAX_EXCERPT_CHARS",
    "PLACEHOLDER",
    "SCHEMA_VERSION",
    "TERMINAL_STATES",
    "CheckResult",
    "CheckStatus",
    "ContractError",
    "DiagnosisResult",
    "Evidence",
    "ExecutionMetadata",
    "FailureEvent",
    "FailureType",
    "HumanReviewRequiredError",
    "IncidentRecord",
    "IntegrationUnavailableError",
    "InvalidInputError",
    "LifecycleState",
    "OpenMedicError",
    "PersistenceError",
    "PolicyViolationError",
    "RecommendedAction",
    "RemediationAttempt",
    "RemediationStatus",
    "RiskLevel",
    "SecretDetection",
    "StateTransition",
    "UnresolvedRepairError",
    "UsageError",
    "ValidationFailedError",
    "ValidationResult",
    "apply_transition",
    "can_transition",
    "redact",
    "redact_excerpt",
    "redact_one_line",
    "utc_now",
    "validate_transition",
]
