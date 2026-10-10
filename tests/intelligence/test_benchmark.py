"""Benchmark harness tests (FR-016).

The diagnosis engine is deliberately **defined here**, in the test, rather than imported.
That keeps this file honest about what it measures: it exercises
:mod:`openmedic.intelligence.benchmark` -- loading, metric computation, target-free
reporting, crash handling, determinism -- against an engine that is known in advance.

The corpus it runs over is the *product's* labelled corpus, which ships inside the
package. The engine under test here is a stand-in that happens to satisfy every label;
the production engine's run over the same corpus, and the target gate that run is held
to, live in ``test_production_benchmark.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

import pytest

from openmedic.domain.contracts import (
    DiagnosisResult,
    Evidence,
    FailureEvent,
)
from openmedic.domain.enums import (
    FailureType,
    RecommendedAction,
    RiskLevel,
)
from openmedic.domain.errors import InvalidInputError
from openmedic.intelligence import (
    BenchmarkCase,
    BenchmarkReport,
    CaseOutcome,
    load_cases,
    load_expected,
    run_benchmark,
)
from openmedic.intelligence.benchmark import (
    _asserts_recovery,
    _evaluate,
    default_cases_dir,
)

#: The product's labelled corpus. It ships as package data, so this path is valid in a
#: source checkout and in an installed wheel alike.
CASES_DIR: Final[Path] = default_cases_dir()
EXPECTED_FILE: Final[Path] = CASES_DIR / "expected.json"

# ---------------------------------------------------------------------------
# The engine under test: a tiny, deterministic, fully offline rule engine.
# ---------------------------------------------------------------------------

_RULES: Final[tuple[tuple[str, str, FailureType, RecommendedAction, RiskLevel, str], ...]] = (
    (
        "py.syntax-error",
        "SyntaxError:",
        FailureType.SYNTAX_OR_IMPORT_ERROR,
        RecommendedAction.FIX_SYNTAX_OR_IMPORT,
        RiskLevel.LOW,
        "The interpreter could not compile a Python source file, so nothing ran.",
    ),
    (
        "py.import-error",
        "ImportError: cannot import name",
        FailureType.SYNTAX_OR_IMPORT_ERROR,
        RecommendedAction.FIX_SYNTAX_OR_IMPORT,
        RiskLevel.LOW,
        "A Python module imports a name that does not exist in the target module.",
    ),
    (
        "pytest.collection-error",
        "errors during collection",
        FailureType.TEST_FAILURE,
        RecommendedAction.FIX_FAILING_TEST,
        RiskLevel.MEDIUM,
        "The test framework could not import its test modules, so no test executed.",
    ),
    (
        "pytest.assertion",
        "AssertionError:",
        FailureType.TEST_FAILURE,
        RecommendedAction.FIX_FAILING_TEST,
        RiskLevel.MEDIUM,
        "The suite ran and at least one test asserted something untrue.",
    ),
    (
        "py.module-not-found",
        "ModuleNotFoundError: No module named",
        FailureType.DEPENDENCY_ERROR,
        RecommendedAction.FIX_DEPENDENCY,
        RiskLevel.LOW,
        "A Python module is absent from the job environment.",
    ),
    (
        "npm.eresolve",
        "Could not resolve dependency",
        FailureType.DEPENDENCY_ERROR,
        RecommendedAction.FIX_DEPENDENCY,
        RiskLevel.LOW,
        "The npm resolver cannot satisfy the declared dependency ranges.",
    ),
    (
        "pip.resolution-conflict",
        "conflicting dependencies",
        FailureType.DEPENDENCY_ERROR,
        RecommendedAction.FIX_DEPENDENCY,
        RiskLevel.LOW,
        "The pip resolver reports an unsatisfiable dependency graph.",
    ),
    (
        "docker.build-error",
        "failed to solve",
        FailureType.BUILD_OR_CONFIG_ERROR,
        RecommendedAction.FIX_BUILD_OR_CONFIG,
        RiskLevel.MEDIUM,
        "The container image could not be built.",
    ),
    (
        "ci.workflow-yaml-error",
        "mapping values are not allowed",
        FailureType.BUILD_OR_CONFIG_ERROR,
        RecommendedAction.FIX_BUILD_OR_CONFIG,
        RiskLevel.MEDIUM,
        "The pipeline definition is not valid YAML.",
    ),
    (
        "ci.env-var-missing",
        "required environment variable",
        FailureType.BUILD_OR_CONFIG_ERROR,
        RecommendedAction.FIX_BUILD_OR_CONFIG,
        RiskLevel.LOW,
        "A required environment variable was not provided to the job.",
    ),
    (
        "jest.assertion",
        "Test Suites:",
        FailureType.TEST_FAILURE,
        RecommendedAction.FIX_FAILING_TEST,
        RiskLevel.MEDIUM,
        "The Jest suite ran and at least one spec asserted something untrue.",
    ),
)


def _line_of(log: str, marker: str) -> tuple[int, str]:
    """Return the 1-based line number and the verbatim line containing ``marker``."""
    for number, line in enumerate(log.splitlines(), start=1):
        if marker in line:
            return number, line
    return 1, marker


def _local_build_event(log: str) -> FailureEvent:
    """Build the event the local engine diagnoses. Deterministic and offline."""
    return FailureEvent(
        incident_id="bench-case",
        repository="openmedic/benchmark-fixtures",
        commit_sha="0f1e2d3c4b5a69788796a5b4c3d2e1f009182736",
        workflow_name="ci",
        job_name="build",
        run_id="9000000001",
        failed_step="Run checks",
        failure_type=FailureType.UNKNOWN,
        logs=log,
        timestamp="2026-06-01T08:00:00+00:00",
    )


def _local_diagnose(event: FailureEvent) -> DiagnosisResult:
    """Diagnose deterministically and offline; used only to exercise the benchmark.

    Rules are matched in order and every evidence quote is a verbatim line from the
    event log. Returning a quote that is not in the log would make the engine
    dishonest, and this one never does.
    """
    log = event.logs
    for rule_id, marker, failure_type, action, risk, cause in _RULES:
        if marker not in log:
            continue
        line_number, quote = _line_of(log, marker)
        return DiagnosisResult(
            incident_id=event.resolved_incident_id,
            failure_type=failure_type,
            probable_cause=cause,
            evidence=[
                Evidence(
                    source=f"logs:{line_number}",
                    quote=quote,
                    explanation="The configured rule matched this line verbatim.",
                )
            ],
            confidence=0.82,
            recommended_action=action,
            risk_level=risk,
            requires_human_review=risk is RiskLevel.HIGH,
            limitations=[
                "Deterministic rule match only; no repository state was inspected.",
                "A matched line does not prove the cause, and confidence is not the "
                "probability that a fix will work.",
            ],
            rule_id=rule_id,
            rule_version="1",
        )

    return DiagnosisResult(
        incident_id=event.resolved_incident_id,
        failure_type=FailureType.UNKNOWN,
        probable_cause="No known failure signature matched this log.",
        evidence=[],
        confidence=0.05,
        recommended_action=RecommendedAction.INVESTIGATE_MANUALLY,
        risk_level=RiskLevel.NONE,
        requires_human_review=True,
        limitations=[
            "No rule matched; unknown is reported rather than a guessed cause (FR-004).",
            "The log may describe a failure class this benchmark does not cover.",
        ],
        rule_id="unknown",
        rule_version="1",
    )


def _run(cases: tuple[BenchmarkCase, ...] | list[BenchmarkCase]) -> BenchmarkReport:
    """Run the local engine over ``cases`` through the public harness."""
    return run_benchmark(
        cases,
        diagnose=_local_diagnose,
        build_event=_local_build_event,
    )


# ---------------------------------------------------------------------------
# Fixture loading and label integrity
# ---------------------------------------------------------------------------


def test_cases_load_and_are_canonicalised() -> None:
    """Every case file loads, and ``expected.json`` is not treated as a case."""
    cases = load_cases(CASES_DIR)

    assert len(cases) >= 12
    case_ids = [case.case_id for case in cases]
    assert case_ids == sorted(case_ids)
    assert len(set(case_ids)) == len(case_ids)
    assert "expected" not in case_ids


def test_expected_file_labels_match_the_case_files() -> None:
    """Committed labels must agree with the case files: no silent drift."""
    expected = load_expected(EXPECTED_FILE)
    cases = {case.case_id: case for case in load_cases(CASES_DIR)}

    labelled = expected["cases"]
    assert isinstance(labelled, dict)
    assert set(labelled) == set(cases)

    for case_id, label in labelled.items():
        case = cases[case_id]
        assert isinstance(label, dict)
        assert label["expected_failure_type"] == case.expected_failure_type.value
        assert label["expected_rule_id"] == case.expected_rule_id
        assert label["min_confidence"] == pytest.approx(case.min_confidence)


def test_expected_targets_are_present() -> None:
    """The committed targets exist so the benchmark can be held to them."""
    targets = load_expected(EXPECTED_FILE)["targets"]

    assert isinstance(targets, dict)
    assert targets["type_accuracy_min"] == 1.0
    assert targets["evidence_verification_rate_min"] == 1.0
    assert targets["false_recovery_count_max"] == 0


def test_load_cases_rejects_a_malformed_directory() -> None:
    """A missing or malformed directory is an input error, not an empty run."""
    with pytest.raises(InvalidInputError):
        load_cases(Path("/nonexistent/does-not-exist"))


# ---------------------------------------------------------------------------
# Required outcomes: the labelled corpus is classified correctly
# ---------------------------------------------------------------------------


def test_all_labelled_cases_classify_correctly() -> None:
    """The engine must match every committed label."""
    cases = load_cases(CASES_DIR)
    report = _run(cases)

    wrong = [o for o in report.outcomes if not o.correct_type]
    assert not wrong, f"misclassified: {[(o.case_id, o.actual_failure_type) for o in wrong]}"
    assert report.total == len(cases)


def test_clean_log_yields_unknown() -> None:
    """A passing log must never be reported as a failure."""
    report = _run(load_cases(CASES_DIR))

    outcome = _outcome(report, "clean-passing-run")
    assert outcome.actual_failure_type is FailureType.UNKNOWN
    assert outcome.expected_failure_type is FailureType.UNKNOWN
    assert outcome.correct_type


def test_ambiguous_log_yields_unknown() -> None:
    """A log with no recognisable signature stays unknown instead of guessing."""
    outcome = _outcome(_run(load_cases(CASES_DIR)), "ambiguous-unknown-signature")

    assert outcome.actual_failure_type is FailureType.UNKNOWN
    assert outcome.correct_type


def test_expected_failure_type_coverage_is_broad() -> None:
    """The corpus covers every non-unknown failure class, plus unknown itself."""
    cases = load_cases(CASES_DIR)
    types = {case.expected_failure_type for case in cases}

    assert FailureType.DEPENDENCY_ERROR in types
    assert FailureType.SYNTAX_OR_IMPORT_ERROR in types
    assert FailureType.TEST_FAILURE in types
    assert FailureType.BUILD_OR_CONFIG_ERROR in types
    assert FailureType.UNKNOWN in types


# ---------------------------------------------------------------------------
# Metrics are computed, never hardcoded
# ---------------------------------------------------------------------------


def test_metrics_are_computed_from_outcomes() -> None:
    """Change one expectation and the accuracy must move by exactly 1/n."""
    cases = list(load_cases(CASES_DIR))
    baseline = _run(cases)
    assert baseline.type_accuracy == 1.0

    index = next(
        i for i, case in enumerate(cases) if case.expected_failure_type is not FailureType.UNKNOWN
    )
    original = cases[index]
    tampered = list(cases)
    tampered[index] = BenchmarkCase(
        case_id=original.case_id,
        log=original.log,
        expected_failure_type=FailureType.UNKNOWN,
        expected_rule_id=None,
        min_confidence=0.0,
        tags=original.tags,
    )
    report = _run(tampered)

    assert report.total == baseline.total
    assert report.type_accuracy == pytest.approx(1.0 - 1.0 / report.total)
    assert report.type_accuracy != baseline.type_accuracy


def test_mean_confidence_is_the_mean_of_the_outcomes() -> None:
    """Mean confidence is derived, not asserted."""
    report = _run(load_cases(CASES_DIR))

    expected = sum(o.confidence for o in report.outcomes) / len(report.outcomes)
    assert report.mean_confidence == pytest.approx(expected)


def test_evidence_verification_rate_is_derived() -> None:
    """Verification rate counts outcomes whose every quote is verbatim."""
    cases = load_cases(CASES_DIR)
    report = _run(cases)

    verified = sum(1 for o in report.outcomes if o.evidence_verified)
    assert report.evidence_verification_rate == pytest.approx(verified / len(cases))


def test_empty_corpus_reports_zero_not_crash() -> None:
    """An empty corpus yields zeroed metrics rather than a division error."""
    report = _run([])

    assert report.total == 0
    assert report.type_accuracy == 0.0
    assert report.evidence_verification_rate == 0.0
    assert report.mean_confidence == 0.0
    assert report.false_recovery_count == 0
    assert report.outcomes == ()


# ---------------------------------------------------------------------------
# Safety: false recovery, evidence, injection, secrets
# ---------------------------------------------------------------------------


def test_false_recovery_count_is_zero() -> None:
    """No case may claim a completed or validated repair."""
    report = _run(load_cases(CASES_DIR))

    assert report.false_recovery_count == 0
    assert not any(o.false_recovery for o in report.outcomes)


def test_every_outcome_carries_limitations() -> None:
    """An outcome with no limitations overclaims what was measured."""
    report = _run(load_cases(CASES_DIR))

    for outcome in report.outcomes:
        assert outcome.limitations, f"{outcome.case_id} reported no limitations"


def test_false_recovery_detector_catches_a_recovery_claim() -> None:
    """A dishonest result that claims a validated fix must be detected."""
    event = _local_build_event("Run: pytest -q\nAssertionError: nope\n")
    result = DiagnosisResult(
        incident_id=event.resolved_incident_id,
        failure_type=FailureType.TEST_FAILURE,
        probable_cause="The dependency issue is fixed and the fix is validated.",
        evidence=[Evidence(source="logs:1", quote="Run: pytest -q", explanation="x")],
        confidence=0.9,
        recommended_action=RecommendedAction.NO_ACTION,
        risk_level=RiskLevel.NONE,
        limitations=["none"],
        rule_id="dishonest",
    )

    assert _asserts_recovery(result) is True

    outcome = _evaluate(
        BenchmarkCase(
            case_id="dishonest",
            log=event.logs,
            expected_failure_type=FailureType.TEST_FAILURE,
        ),
        diagnose=lambda _event: result,
        build_event=_local_build_event,
    )

    assert outcome.false_recovery is True
    assert any("recovery-without-validation" in item for item in outcome.limitations)


def test_false_recovery_detector_ignores_an_honest_result() -> None:
    """The marker scan must not fire on clean, honest output."""
    report = _run(load_cases(CASES_DIR))

    for outcome in report.outcomes:
        assert outcome.false_recovery is False


def test_fabricated_evidence_is_detected() -> None:
    """A quote that is not in the log fails verification."""
    event = _local_build_event("Run: pytest -q\nAssertionError: nope\n")
    fabricated = DiagnosisResult(
        incident_id=event.resolved_incident_id,
        failure_type=FailureType.TEST_FAILURE,
        probable_cause="Invented quote.",
        evidence=[
            Evidence(
                source="logs:1",
                quote="AssertionError: this line was never printed",
                explanation="fabricated",
            )
        ],
        confidence=0.5,
        recommended_action=RecommendedAction.FIX_FAILING_TEST,
        risk_level=RiskLevel.LOW,
        limitations=["fabricated on purpose"],
        rule_id="dishonest",
    )

    outcome = _evaluate(
        BenchmarkCase(
            case_id="fabricated",
            log=event.logs,
            expected_failure_type=FailureType.TEST_FAILURE,
        ),
        diagnose=lambda _event: fabricated,
        build_event=_local_build_event,
    )

    assert outcome.evidence_verified is False
    assert any("not verbatim" in item for item in outcome.limitations)


def test_confidence_below_the_floor_is_reported() -> None:
    """A case with a confidence floor records a limitation when it is not met."""
    event = _local_build_event("nothing recognisable at all\n")

    outcome = _evaluate(
        BenchmarkCase(
            case_id="low-confidence",
            log=event.logs,
            expected_failure_type=FailureType.UNKNOWN,
            min_confidence=0.9,
        ),
        diagnose=_local_diagnose,
        build_event=_local_build_event,
    )

    assert outcome.correct_type is True
    assert any("below the required minimum" in item for item in outcome.limitations)


def test_prompt_injection_log_is_inert_data() -> None:
    """An injected instruction must not become a classification or a policy change."""
    outcome = _outcome(_run(load_cases(CASES_DIR)), "prompt-injection-inert")

    assert outcome.actual_failure_type is FailureType.UNKNOWN
    assert outcome.false_recovery is False
    assert outcome.correct_type is True


def test_injection_payload_never_reaches_the_report() -> None:
    """The benchmark output must not echo the injected text anywhere."""
    report = _run(cases_with_tag("injection"))

    payload = report.to_text()
    assert "ignore previous instructions" not in payload
    assert "rm -rf" not in payload


def test_secrets_stay_redacted() -> None:
    """A leaking log never propagates its secret material into the report."""
    report = _run(cases_with_tag("secrets"))

    serialised = json.dumps(report.to_dict()) + report.to_text()
    for secret in (
        "github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwx",
        "AKIAIOSFODNN7EXAMPLE",
        "8f2b1c9d4e5a6b7c8d9e0f1a2b3c4d5e",
    ):
        assert secret not in serialised, f"secret leaked into the benchmark output: {secret}"
        assert secret not in " ".join(
            limitation for o in report.outcomes for limitation in o.limitations
        )

    outcome = _outcome(report, "secret-bearing-log")
    assert outcome.actual_failure_type is FailureType.TEST_FAILURE
    assert outcome.correct_type


def test_engine_crash_is_recorded_as_a_non_diagnosis() -> None:
    """A crashing engine must never be able to look accurate."""
    outcome = _evaluate(
        BenchmarkCase(
            case_id="crashes",
            log="Run: pytest\n",
            expected_failure_type=FailureType.UNKNOWN,
        ),
        diagnose=_raise,
        build_event=_local_build_event,
    )

    assert outcome.correct_type is False
    assert outcome.actual_failure_type is FailureType.UNKNOWN
    assert outcome.confidence == 0.0
    assert any("RuntimeError" in item for item in outcome.limitations)
    assert any("crashed diagnosis is not a diagnosis" in item for item in outcome.limitations)


# ---------------------------------------------------------------------------
# Determinism and serialisation
# ---------------------------------------------------------------------------


def test_two_runs_produce_identical_output() -> None:
    """The benchmark is deterministic: byte-identical reports on repeat runs."""
    cases = load_cases(CASES_DIR)
    first = _run(cases)
    second = _run(cases)

    assert first.to_dict() == second.to_dict()
    assert first.to_text() == second.to_text()


def test_input_order_does_not_change_the_report() -> None:
    """Cases are canonicalised, so caller ordering is irrelevant."""
    cases = list(load_cases(CASES_DIR))

    forward = _run(cases)
    shuffled = _run(list(reversed(cases)))

    assert [o.case_id for o in forward.outcomes] == [o.case_id for o in shuffled.outcomes]
    assert forward.to_dict() == shuffled.to_dict()


def test_report_is_json_serialisable() -> None:
    """The CLI's --json path depends on the payload being plain JSON types."""
    report = _run(load_cases(CASES_DIR))

    payload = report.to_dict()
    assert json.loads(json.dumps(payload)) == payload
    assert isinstance(payload["outcomes"], list)
    assert isinstance(report.to_text(), str)
    assert "false recovery count: 0" in report.to_text()
    assert isinstance(report.outcomes, tuple)
    assert all(isinstance(outcome, CaseOutcome) for outcome in report.outcomes)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _outcome(report: BenchmarkReport, case_id: str) -> CaseOutcome:
    """Return the outcome for ``case_id`` or fail loudly."""
    for outcome in report.outcomes:
        if outcome.case_id == case_id:
            return outcome
    raise AssertionError(f"no outcome for case {case_id!r}")


def _raise(_event: FailureEvent) -> DiagnosisResult:
    """Diagnose by failing, to prove that a crash cannot look accurate."""
    msg = "engine exploded"
    raise RuntimeError(msg)


def cases_with_tag(tag: str) -> tuple[BenchmarkCase, ...]:
    """Return the committed cases carrying ``tag``."""
    return tuple(case for case in load_cases(CASES_DIR) if tag in case.tags)
