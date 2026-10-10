"""Intelligence layer: recurrence tracking, cascade grouping, and benchmarking.

Implements FR-014 (recurrence intelligence), FR-015 (cascade grouping), and FR-016
(benchmarking) from the PRD, and roadmap Milestone 10.

The layer reads the persisted
:class:`~openmedic.domain.contracts.IncidentRecord` aggregate and imports no diagnosis
engine, provider, remediation, or persistence code. The benchmark takes the engine under
test as injected callables, so nothing here can accidentally become a dependency of the
engine it measures.
"""

from __future__ import annotations

from .benchmark import (
    BenchmarkCase,
    BenchmarkReport,
    BenchmarkRun,
    BenchmarkTargets,
    CaseOutcome,
    TargetCheck,
    TargetVerdict,
    check_targets,
    default_cases_dir,
    load_cases,
    load_expected,
    load_targets,
    run_benchmark,
    validate_expected_matches_cases,
)
from .grouping import (
    GROUPING_RULE,
    MAX_GROUP_CONFIDENCE,
    CascadeGroup,
    group_cascades,
)
from .recurrence import (
    RecurrenceGroup,
    failure_type_of,
    find_recurrences,
    fingerprint_incident,
    group_by_fingerprint,
    unique_records,
)

__all__ = [
    "GROUPING_RULE",
    "MAX_GROUP_CONFIDENCE",
    "BenchmarkCase",
    "BenchmarkReport",
    "BenchmarkRun",
    "BenchmarkTargets",
    "CascadeGroup",
    "CaseOutcome",
    "RecurrenceGroup",
    "TargetCheck",
    "TargetVerdict",
    "check_targets",
    "default_cases_dir",
    "failure_type_of",
    "find_recurrences",
    "fingerprint_incident",
    "group_by_fingerprint",
    "group_cascades",
    "load_cases",
    "load_expected",
    "load_targets",
    "run_benchmark",
    "unique_records",
    "validate_expected_matches_cases",
]
