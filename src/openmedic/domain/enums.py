"""Domain enumerations.

These values are part of the public contract in ``docs/API_CONTRACTS.md``. Renaming a
member is a breaking change and requires a ``schema_version`` bump plus a coordinated
update of every consumer, fixture, and document.
"""

from __future__ import annotations

from enum import StrEnum


class _StrEnum(StrEnum):
    """String enum that serialises as its value in JSON."""


class FailureType(_StrEnum):
    """Coarse classification of a CI failure."""

    DEPENDENCY_ERROR = "dependency_error"
    SYNTAX_OR_IMPORT_ERROR = "syntax_or_import_error"
    TEST_FAILURE = "test_failure"
    BUILD_OR_CONFIG_ERROR = "build_or_config_error"
    UNKNOWN = "unknown"


class RiskLevel(_StrEnum):
    """How dangerous the recommended or proposed action is."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LifecycleState(_StrEnum):
    """Incident lifecycle states from ``docs/API_CONTRACTS.md`` section 5."""

    RECEIVED = "received"
    DIAGNOSING = "diagnosing"
    DIAGNOSED = "diagnosed"
    REMEDIATION_PENDING = "remediation_pending"
    REMEDIATING = "remediating"
    VALIDATING = "validating"
    RECOVERED = "recovered"
    FAILED = "failed"
    REQUIRES_HUMAN_REVIEW = "requires_human_review"


class CheckStatus(_StrEnum):
    """Outcome of one executed validation check.

    ``PASSED`` is the only status that can contribute to a passing validation. Every
    other member is an explicit non-success and must be reported honestly.
    """

    PASSED = "passed"
    FAILED = "failed"
    ERRORED = "errored"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"
    MISSING = "missing"


class RemediationStatus(_StrEnum):
    """State of a single remediation attempt."""

    PROPOSED = "proposed"
    REJECTED = "rejected"
    AWAITING_REVIEW = "awaiting_review"
    APPLIED = "applied"
    SUPERSEDED = "superseded"
    FAILED = "failed"


class RecommendedAction(_StrEnum):
    """What OpenMedic recommends the human do next.

    ``NO_ACTION`` covers cases where the honest answer is that OpenMedic cannot help.
    """

    INVESTIGATE_MANUALLY = "investigate_manually"
    FIX_DEPENDENCY = "fix_dependency"
    FIX_SYNTAX_OR_IMPORT = "fix_syntax_or_import"
    FIX_FAILING_TEST = "fix_failing_test"
    FIX_BUILD_OR_CONFIG = "fix_build_or_config"
    FLAKY_TEST_RERUN = "flaky_test_rerun"
    NO_ACTION = "no_action"
