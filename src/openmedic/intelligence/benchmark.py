"""Repeatable diagnosis benchmark (FR-016, TRD section 13).

The benchmark measures a *diagnosis engine*. The engine is not imported here: it is
injected as a ``diagnose`` callable together with a ``build_event`` callable, so this
module stays decoupled from the engine under test and can benchmark any engine that
satisfies the ``DiagnosisResult`` contract.

Metrics are always computed from the outcomes. Nothing is hard-coded, no network or
model provider is used, and running the same cases twice produces an identical report.

Three honest limits are built in rather than assumed away:

* ``false_recovery`` is detected, not asserted. A diagnosis that claims a completed or
  validated fix -- a recovery without validation evidence -- is reported per case and
  counted in ``false_recovery_count``. The detector is a documented marker scan over
  the result's free text, so it is recorded as a limitation of the measurement itself
  rather than presented as proof.
* ``evidence_verified`` uses the engine's own :meth:`DiagnosisResult.verify_evidence`
  against the *event* log that was actually diagnosed, not against the fixture text.
* Every outcome carries limitations, including a statement that no remediation or
  validation ran during the benchmark.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..domain.contracts import DiagnosisResult, FailureEvent
from ..domain.enums import FailureType
from ..domain.errors import InvalidInputError

__all__ = [
    "BenchmarkCase",
    "BenchmarkReport",
    "BenchmarkRun",
    "BenchmarkTargets",
    "CaseOutcome",
    "TargetCheck",
    "TargetVerdict",
    "check_targets",
    "load_cases",
    "load_expected",
    "load_targets",
    "run_benchmark",
    "validate_expected_matches_cases",
]

#: Keys a case file may carry. Unknown keys are rejected rather than ignored, so a typo
#: in a committed label surfaces immediately instead of silently changing a metric.
_CASE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "case_id",
        "log",
        "expected_failure_type",
        "expected_rule_id",
        "min_confidence",
        "tags",
        "note",
    }
)

#: Files in the case directory that are not cases.
_NON_CASE_FILES: Final[frozenset[str]] = frozenset({"expected.json"})

#: Targets every committed expectation file must declare.
_REQUIRED_TARGETS: Final[tuple[str, ...]] = (
    "type_accuracy_min",
    "evidence_verification_rate_min",
    "false_recovery_count_max",
)

#: Targets a committed expectation file may additionally declare.
_OPTIONAL_TARGETS: Final[tuple[str, ...]] = (
    "mean_confidence_min",
    "rule_id_match_rate_min",
)

#: Free-text markers that assert a repair is already done. A diagnosis that says any of
#: these is claiming recovery without validation evidence, which the contract forbids.
_RECOVERY_CLAIM_MARKERS: Final[tuple[str, ...]] = (
    "is fixed",
    "has been fixed",
    "was fixed",
    "fix confirmed",
    "fix is confirmed",
    "fix validated",
    "fix is validated",
    "validated the fix",
    "has recovered",
    "recovered successfully",
    "now passes",
    "validation passed",
    "resolved the failure",
    "no further action is required",
)

_SCOPE_LIMITATION: Final[str] = (
    "This is a diagnosis-only benchmark: no remediation was proposed, no patch was "
    "applied, and no validation check ran, so it measures classification and evidence "
    "quality and nothing about repair success."
)

_DETECTOR_LIMITATION: Final[str] = (
    "The false-recovery detector scans free text for claim markers and cannot detect a "
    "paraphrased recovery claim."
)


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    """One labelled failure case: a log plus what a correct engine must return."""

    case_id: str
    log: str
    expected_failure_type: FailureType
    expected_rule_id: str | None = None
    min_confidence: float = 0.0
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable payload using the canonical field names."""
        return {
            "case_id": self.case_id,
            "expected_failure_type": self.expected_failure_type.value,
            "expected_rule_id": self.expected_rule_id,
            "min_confidence": self.min_confidence,
            "tags": list(self.tags),
            "log": self.log,
        }


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    """The measured result of running one case through the injected engine."""

    case_id: str
    expected_failure_type: FailureType
    actual_failure_type: FailureType
    correct_type: bool
    confidence: float
    evidence_verified: bool
    false_recovery: bool
    limitations: tuple[str, ...]
    expected_rule_id: str | None = None
    rule_id_matched: bool | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable payload using the canonical field names."""
        return {
            "case_id": self.case_id,
            "expected_failure_type": self.expected_failure_type.value,
            "actual_failure_type": self.actual_failure_type.value,
            "correct_type": self.correct_type,
            "confidence": self.confidence,
            "evidence_verified": self.evidence_verified,
            "false_recovery": self.false_recovery,
            "expected_rule_id": self.expected_rule_id,
            "rule_id_matched": self.rule_id_matched,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    """Aggregate metrics over a set of outcomes.

    ``false_recovery_count`` has a required target of zero (PRD section 9): a non-zero
    value means the engine claimed a recovery it had no validation evidence for.
    """

    total: int
    type_accuracy: float
    evidence_verification_rate: float
    false_recovery_count: int
    mean_confidence: float
    outcomes: tuple[CaseOutcome, ...]
    rule_id_match_rate: float = 1.0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable payload using the canonical field names."""
        return {
            "total": self.total,
            "type_accuracy": self.type_accuracy,
            "evidence_verification_rate": self.evidence_verification_rate,
            "false_recovery_count": self.false_recovery_count,
            "mean_confidence": self.mean_confidence,
            "rule_id_match_rate": self.rule_id_match_rate,
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }

    def to_text(self) -> str:
        """Return a human-readable report with every outcome listed."""
        lines = [
            "OpenMedic diagnosis benchmark",
            f"  cases: {self.total}",
            f"  type accuracy: {self.type_accuracy:.4f}",
            f"  evidence verification rate: {self.evidence_verification_rate:.4f}",
            f"  rule id match rate: {self.rule_id_match_rate:.4f}",
            f"  false recovery count: {self.false_recovery_count}",
            f"  mean confidence: {self.mean_confidence:.4f}",
            "",
            "  outcomes:",
        ]
        for outcome in self.outcomes:
            marker = "ok " if outcome.correct_type else "BAD"
            lines.append(
                f"    [{marker}] {outcome.case_id}: "
                f"expected={outcome.expected_failure_type.value} "
                f"actual={outcome.actual_failure_type.value} "
                f"confidence={outcome.confidence:.2f} "
                f"evidence_verified={outcome.evidence_verified}"
            )
            for limitation in outcome.limitations:
                lines.append(f"          - {limitation}")
        return "\n".join(lines)


def load_cases(directory: Path) -> tuple[BenchmarkCase, ...]:
    """Load every labelled case JSON in ``directory``, sorted by ``case_id``.

    ``expected.json`` is skipped: it holds the committed targets, not a case. The result
    is canonicalised by case id so a benchmark run does not depend on directory order.
    """
    if not directory.is_dir():
        msg = f"benchmark case directory not found: {directory}"
        raise InvalidInputError(msg)

    cases: list[BenchmarkCase] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.json")):
        if path.name in _NON_CASE_FILES:
            continue
        case = _load_case(path)
        if case.case_id in seen:
            msg = f"duplicate case_id {case.case_id!r} in {path}"
            raise InvalidInputError(msg)
        seen.add(case.case_id)
        cases.append(case)

    cases.sort(key=lambda case: case.case_id)
    return tuple(cases)


def load_expected(path: Path) -> dict[str, object]:
    """Load and validate a committed expectations file.

    The file records the hand-reviewed labels and the metric targets the benchmark must
    meet, per TRD section 13 ("benchmark labels and expected outcomes must be committed
    with fixtures").
    """
    if not path.is_file():
        msg = f"benchmark expectations file not found: {path}"
        raise InvalidInputError(msg)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"benchmark expectations file is not valid JSON: {path}"
        raise InvalidInputError(msg) from exc

    if not isinstance(payload, dict):
        msg = f"benchmark expectations must be a JSON object: {path}"
        raise InvalidInputError(msg)
    cases = payload.get("cases")
    if not isinstance(cases, dict) or not cases:
        msg = f"benchmark expectations must contain a non-empty 'cases' object: {path}"
        raise InvalidInputError(msg)
    targets = payload.get("targets")
    if not isinstance(targets, dict):
        msg = f"benchmark expectations must contain a 'targets' object: {path}"
        raise InvalidInputError(msg)
    for key in _REQUIRED_TARGETS:
        if not isinstance(targets.get(key), (int, float)) or isinstance(targets.get(key), bool):
            msg = f"benchmark expectations target {key!r} must be numeric: {path}"
            raise InvalidInputError(msg)
    return payload


@dataclass(frozen=True, slots=True)
class BenchmarkTargets:
    """The acceptance bar a committed corpus holds its engine to.

    Targets are read from ``expected.json`` beside the cases, never derived from the
    measured report: a bar that moves with the result is not a bar.
    """

    type_accuracy_min: float
    evidence_verification_rate_min: float
    false_recovery_count_max: int
    mean_confidence_min: float | None = None
    rule_id_match_rate_min: float | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable payload using the canonical field names."""
        payload: dict[str, object] = {
            "type_accuracy_min": self.type_accuracy_min,
            "evidence_verification_rate_min": self.evidence_verification_rate_min,
            "false_recovery_count_max": self.false_recovery_count_max,
        }
        if self.mean_confidence_min is not None:
            payload["mean_confidence_min"] = self.mean_confidence_min
        if self.rule_id_match_rate_min is not None:
            payload["rule_id_match_rate_min"] = self.rule_id_match_rate_min
        return payload


def load_targets(path: Path) -> BenchmarkTargets:
    """Read and validate the committed targets in ``path`` (an ``expected.json``)."""
    return _parse_targets(load_expected(path), source=path)


def default_cases_dir() -> Path:
    """Return the labelled corpus shipped inside this package.

    The corpus is package data rather than test data, so an installed wheel carries it
    and ``openmedic benchmark`` works outside a source checkout. Wheel installs are
    unpacked onto the filesystem, so resolving a directory beside this module is valid
    for both a source checkout and an installed distribution.
    """
    return Path(__file__).resolve().parent / "cases"


def _parse_targets(payload: dict[str, object], *, source: Path) -> BenchmarkTargets:
    """Parse the ``targets`` object, rejecting unknown, missing, or malformed entries."""
    targets = payload.get("targets")
    if not isinstance(targets, dict):
        msg = f"benchmark expectations must contain a 'targets' object: {source}"
        raise InvalidInputError(msg)

    known = sorted((*_REQUIRED_TARGETS, *_OPTIONAL_TARGETS))
    unknown = sorted(set(targets) - set(known))
    if unknown:
        msg = (
            f"benchmark expectations declare unknown target(s): {', '.join(unknown)}; "
            f"the known targets are {', '.join(known)}"
        )
        raise InvalidInputError(msg)
    missing = sorted(key for key in _REQUIRED_TARGETS if key not in targets)
    if missing:
        msg = (
            f"benchmark expectations are missing required target(s): {', '.join(missing)}: {source}"
        )
        raise InvalidInputError(msg)

    def _number(key: str, *, integer: bool = False) -> float:
        value = targets.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            msg = f"benchmark expectations target {key!r} must be numeric: {source}"
            raise InvalidInputError(msg)
        if value < 0:
            msg = f"benchmark expectations target {key!r} must not be negative: {source}"
            raise InvalidInputError(msg)
        if integer and not float(value).is_integer():
            msg = f"benchmark expectations target {key!r} must be a whole number: {source}"
            raise InvalidInputError(msg)
        return float(value)

    def _optional(key: str) -> float | None:
        return None if key not in targets else _number(key)

    return BenchmarkTargets(
        type_accuracy_min=_number("type_accuracy_min"),
        evidence_verification_rate_min=_number("evidence_verification_rate_min"),
        false_recovery_count_max=int(_number("false_recovery_count_max", integer=True)),
        mean_confidence_min=_optional("mean_confidence_min"),
        rule_id_match_rate_min=_optional("rule_id_match_rate_min"),
    )


def validate_expected_matches_cases(
    expected: dict[str, object],
    cases: Sequence[BenchmarkCase],
    *,
    source: Path,
) -> None:
    """Reject a corpus whose two committed label sources disagree.

    ``expected.json`` repeats every case's label so the bar can be read without opening
    each file. That repetition is only safe if divergence is an error: a label that
    silently disagrees with its case file would make the benchmark's own configuration
    the thing being measured.
    """
    labelled = expected.get("cases")
    if not isinstance(labelled, dict):
        msg = f"benchmark expectations must contain a 'cases' object: {source}"
        raise InvalidInputError(msg)

    by_id = {case.case_id: case for case in cases}
    unlabelled = sorted(set(by_id) - set(labelled))
    unknown = sorted(set(labelled) - set(by_id))
    if unlabelled or unknown:
        parts: list[str] = []
        if unlabelled:
            parts.append(f"no label for case(s) {', '.join(unlabelled)}")
        if unknown:
            parts.append(f"label(s) for case(s) that do not exist: {', '.join(unknown)}")
        joined = "; ".join(parts)
        msg = f"benchmark expectations disagree with the case directory ({joined}): {source}"
        raise InvalidInputError(msg)

    for case_id, label in sorted(labelled.items()):
        if not isinstance(label, dict):
            msg = f"benchmark expectation label for {case_id!r} must be an object: {source}"
            raise InvalidInputError(msg)
        case = by_id[case_id]
        declared_type = label.get("expected_failure_type")
        if declared_type != case.expected_failure_type.value:
            msg = (
                f"contradictory benchmark labels for {case_id!r}: the expectations file "
                f"says {declared_type!r} but the case file says "
                f"{case.expected_failure_type.value!r}: {source}"
            )
            raise InvalidInputError(msg)
        if label.get("expected_rule_id") != case.expected_rule_id:
            msg = (
                f"contradictory benchmark labels for {case_id!r}: the expectations file "
                f"says rule {label.get('expected_rule_id')!r} but the case file says "
                f"{case.expected_rule_id!r}: {source}"
            )
            raise InvalidInputError(msg)
        floor = label.get("min_confidence")
        if (
            isinstance(floor, bool)
            or not isinstance(floor, (int, float))
            or abs(float(floor) - case.min_confidence) > 1e-9
        ):
            msg = (
                f"contradictory benchmark labels for {case_id!r}: the expectations file "
                f"says min_confidence {floor!r} but the case file says "
                f"{case.min_confidence!r}: {source}"
            )
            raise InvalidInputError(msg)


@dataclass(frozen=True, slots=True)
class TargetCheck:
    """One measured metric compared against one committed target."""

    name: str
    actual: float | int
    required: float | int
    comparison: str
    passed: bool

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable payload using the canonical field names."""
        return {
            "name": self.name,
            "actual": self.actual,
            "required": self.required,
            "comparison": self.comparison,
            "passed": self.passed,
        }

    def render(self) -> str:
        """Render one ``[ok ]``/``[BAD]`` line for the human report."""
        marker = "ok " if self.passed else "BAD"
        actual = _format(self.actual)
        required = _format(self.required)
        return f"[{marker}] {self.name}: {actual} {self.comparison} {required}"


@dataclass(frozen=True, slots=True)
class TargetVerdict:
    """Whether a report cleared its targets, showing every check either way."""

    checks: tuple[TargetCheck, ...]

    @property
    def failures(self) -> tuple[TargetCheck, ...]:
        """Return only the checks that were missed."""
        return tuple(check for check in self.checks if not check.passed)

    @property
    def passed(self) -> bool:
        """Return whether every declared target was met."""
        return not self.failures

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable payload using the canonical field names."""
        return {
            "passed": self.passed,
            "checks": [check.to_dict() for check in self.checks],
        }

    def to_text(self) -> str:
        """Return a human-readable verdict with every target listed."""
        lines = ["  targets:"]
        lines.extend(f"    {check.render()}" for check in self.checks)
        lines.append("  targets met" if self.passed else "  TARGETS NOT MET")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class BenchmarkRun:
    """One benchmark execution: the measurement, the bar, and the verdict.

    ``passed`` is the only thing CI needs, but the run keeps the full report and the
    individual checks so a failure can be explained rather than merely observed.
    """

    cases_dir: Path
    report: BenchmarkReport
    targets: BenchmarkTargets
    verdict: TargetVerdict

    @property
    def passed(self) -> bool:
        """Return whether every committed target was met."""
        return self.verdict.passed

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable payload using the canonical field names."""
        payload = self.report.to_dict()
        payload["cases_dir"] = str(self.cases_dir)
        payload["targets"] = self.targets.to_dict()
        payload["target_checks"] = [check.to_dict() for check in self.verdict.checks]
        payload["passed"] = self.verdict.passed
        return payload

    def to_text(self) -> str:
        """Return the human-readable report followed by the target verdict."""
        return f"{self.report.to_text()}\n\n{self.verdict.to_text()}"


def _format(value: float | int) -> str:
    """Render a whole number without decimals and a ratio with four."""
    if isinstance(value, int) or float(value).is_integer():
        return str(int(value))
    return f"{value:.4f}"


def check_targets(report: BenchmarkReport, targets: BenchmarkTargets) -> TargetVerdict:
    """Compare ``report`` against every declared target.

    This is the gate: a run that misses any target is a failed run, whatever its
    headline accuracy says. Rates have a floor and counts have a ceiling, so each
    metric is compared in the direction that actually constrains it.
    """
    checks = [
        TargetCheck(
            name="type_accuracy",
            actual=report.type_accuracy,
            required=targets.type_accuracy_min,
            comparison="at least",
            passed=report.type_accuracy >= targets.type_accuracy_min,
        ),
        TargetCheck(
            name="evidence_verification_rate",
            actual=report.evidence_verification_rate,
            required=targets.evidence_verification_rate_min,
            comparison="at least",
            passed=report.evidence_verification_rate >= targets.evidence_verification_rate_min,
        ),
        TargetCheck(
            name="false_recovery_count",
            actual=report.false_recovery_count,
            required=targets.false_recovery_count_max,
            comparison="at most",
            passed=report.false_recovery_count <= targets.false_recovery_count_max,
        ),
    ]
    if targets.mean_confidence_min is not None:
        checks.append(
            TargetCheck(
                name="mean_confidence",
                actual=report.mean_confidence,
                required=targets.mean_confidence_min,
                comparison="at least",
                passed=report.mean_confidence >= targets.mean_confidence_min,
            )
        )
    if targets.rule_id_match_rate_min is not None:
        checks.append(
            TargetCheck(
                name="rule_id_match_rate",
                actual=report.rule_id_match_rate,
                required=targets.rule_id_match_rate_min,
                comparison="at least",
                passed=report.rule_id_match_rate >= targets.rule_id_match_rate_min,
            )
        )
    return TargetVerdict(tuple(checks))


def run_benchmark(
    cases: Sequence[BenchmarkCase],
    *,
    diagnose: Callable[[FailureEvent], DiagnosisResult],
    build_event: Callable[[str], FailureEvent],
) -> BenchmarkReport:
    """Run ``cases`` through the injected engine and compute the metrics.

    ``diagnose`` receives a :class:`FailureEvent` and returns a
    :class:`DiagnosisResult`. ``build_event`` turns a case log into that event, so the
    benchmark never assumes how an engine wants its input constructed. Cases are
    evaluated in case-id order, making the report independent of input ordering. A case
    whose engine raises is recorded as a non-diagnosis with ``UNKNOWN`` and
    ``correct_type=False``, so a crashed engine can never look accurate.
    """
    outcomes = tuple(
        _evaluate(case, diagnose=diagnose, build_event=build_event)
        for case in sorted(cases, key=lambda case: case.case_id)
    )
    # Cases that declare no expected rule (the honest unknowns) cannot violate a rule-id
    # label, so they are excluded from the rate rather than counted as matches. A corpus
    # that declares none at all therefore reports 1.0, and the target stays vacuous for
    # it rather than failing spuriously.
    declared = tuple(outcome for outcome in outcomes if outcome.expected_rule_id is not None)
    return BenchmarkReport(
        total=len(outcomes),
        type_accuracy=_ratio(sum(1 for o in outcomes if o.correct_type), len(outcomes)),
        evidence_verification_rate=_ratio(
            sum(1 for o in outcomes if o.evidence_verified), len(outcomes)
        ),
        false_recovery_count=sum(1 for o in outcomes if o.false_recovery),
        mean_confidence=_ratio(sum(o.confidence for o in outcomes), len(outcomes)),
        outcomes=outcomes,
        rule_id_match_rate=(
            _ratio(sum(1 for o in declared if o.rule_id_matched), len(declared))
            if declared
            else 1.0
        ),
    )


def _ratio(numerator: float, denominator: int) -> float:
    """Return ``numerator / denominator``, or 0.0 when there is nothing to measure."""
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _evaluate(
    case: BenchmarkCase,
    *,
    diagnose: Callable[[FailureEvent], DiagnosisResult],
    build_event: Callable[[str], FailureEvent],
) -> CaseOutcome:
    """Run one case and derive its outcome and limitations."""
    try:
        event = build_event(case.log)
        result = diagnose(event)
    except Exception as exc:
        return CaseOutcome(
            case_id=case.case_id,
            expected_failure_type=case.expected_failure_type,
            actual_failure_type=FailureType.UNKNOWN,
            correct_type=False,
            confidence=0.0,
            evidence_verified=False,
            false_recovery=False,
            limitations=(
                f"Diagnosing this case raised {type(exc).__name__}. The exception message "
                "is deliberately omitted so log content cannot leak into a report. The "
                "case is recorded as UNKNOWN and incorrect: a crashed diagnosis is not a "
                "diagnosis.",
                _SCOPE_LIMITATION,
            ),
            expected_rule_id=case.expected_rule_id,
            rule_id_matched=False if case.expected_rule_id is not None else None,
        )

    limitations: list[str] = []
    correct = result.failure_type == case.expected_failure_type
    rule_id_matched = (
        None if case.expected_rule_id is None else result.rule_id == case.expected_rule_id
    )
    unverified = result.verify_evidence(event.logs)
    evidence_verified = not unverified
    false_recovery = _asserts_recovery(result)

    if not correct:
        limitations.append(
            f"Expected {case.expected_failure_type.value} but the engine returned "
            f"{result.failure_type.value}."
        )
    if not evidence_verified:
        limitations.append(
            f"{len(unverified)} evidence quote(s) were not verbatim in the event log, so "
            "the diagnosis is not fully traceable to its source."
        )
    if case.expected_rule_id is not None and result.rule_id != case.expected_rule_id:
        limitations.append(
            f"Expected rule {case.expected_rule_id!r} but the engine produced {result.rule_id!r}."
        )
    if result.confidence < case.min_confidence:
        limitations.append(
            f"Confidence {result.confidence:.2f} is below the required minimum "
            f"{case.min_confidence:.2f} for this case."
        )
    if false_recovery:
        limitations.append(
            "The engine asserted a completed or validated repair, which is a "
            "recovery-without-validation signal."
        )
    limitations.append(_SCOPE_LIMITATION)
    limitations.append(_DETECTOR_LIMITATION)

    return CaseOutcome(
        case_id=case.case_id,
        expected_failure_type=case.expected_failure_type,
        actual_failure_type=result.failure_type,
        correct_type=correct,
        confidence=result.confidence,
        evidence_verified=evidence_verified,
        false_recovery=false_recovery,
        limitations=tuple(limitations),
        expected_rule_id=case.expected_rule_id,
        rule_id_matched=rule_id_matched,
    )


def _asserts_recovery(result: DiagnosisResult) -> bool:
    """Return whether ``result`` claims a repair is already done or validated.

    The scan covers the probable cause, every evidence explanation, and the result's own
    limitations. Contract structure already prevents the worst case: the
    :class:`RecommendedAction` enum has no member that executes anything, so a diagnosis
    cannot authorise a repair by construction.
    """
    texts = [result.probable_cause]
    texts.extend(item.explanation for item in result.evidence)
    texts.extend(result.limitations)
    haystack = " ".join(texts).lower()
    return any(marker in haystack for marker in _RECOVERY_CLAIM_MARKERS)


def _load_case(path: Path) -> BenchmarkCase:
    """Parse and validate one case file."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"benchmark case file is not valid JSON: {path}"
        raise InvalidInputError(msg) from exc

    if not isinstance(payload, dict):
        msg = f"benchmark case must be a JSON object: {path}"
        raise InvalidInputError(msg)

    unknown = sorted(set(payload) - _CASE_KEYS)
    if unknown:
        msg = f"benchmark case {path} has unknown key(s): {', '.join(unknown)}"
        raise InvalidInputError(msg)

    for key in ("case_id", "log", "expected_failure_type"):
        if key not in payload:
            msg = f"benchmark case {path} is missing required key {key!r}"
            raise InvalidInputError(msg)
    if not isinstance(payload["case_id"], str) or not payload["case_id"]:
        msg = f"benchmark case {path} needs a non-empty 'case_id' string"
        raise InvalidInputError(msg)
    if not isinstance(payload["log"], str) or not payload["log"]:
        msg = f"benchmark case {path} needs a non-empty 'log' string"
        raise InvalidInputError(msg)

    try:
        failure_type = FailureType(payload["expected_failure_type"])
    except ValueError as exc:
        msg = (
            f"benchmark case {path} has unknown expected_failure_type "
            f"{payload['expected_failure_type']!r}"
        )
        raise InvalidInputError(msg) from exc

    rule_id = payload.get("expected_rule_id")
    if rule_id is not None and not isinstance(rule_id, str):
        msg = f"benchmark case {path} needs 'expected_rule_id' to be a string or null"
        raise InvalidInputError(msg)

    min_confidence = payload.get("min_confidence", 0.0)
    if not isinstance(min_confidence, (int, float)) or isinstance(min_confidence, bool):
        msg = f"benchmark case {path} needs 'min_confidence' to be a number"
        raise InvalidInputError(msg)

    tags = payload.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        msg = f"benchmark case {path} needs 'tags' to be a list of strings"
        raise InvalidInputError(msg)

    return BenchmarkCase(
        case_id=payload["case_id"],
        log=payload["log"],
        expected_failure_type=failure_type,
        expected_rule_id=rule_id,
        min_confidence=float(min_confidence),
        tags=tuple(tags),
    )
