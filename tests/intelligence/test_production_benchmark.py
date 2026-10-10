"""The production diagnosis benchmark gate (FR-016).

This is the corpus holding the *shipped* engine to its bar: the same engine, corpus and
targets ``openmedic benchmark`` runs. A failure here is a failure of the documented
command, so the gate cannot drift away from the product.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

import pytest

from openmedic.application.services import Services
from openmedic.cli.config import AppConfig
from openmedic.domain.enums import FailureType
from openmedic.domain.errors import InvalidInputError
from openmedic.intelligence import (
    BenchmarkReport,
    BenchmarkTargets,
    check_targets,
    default_cases_dir,
    load_cases,
    load_expected,
    load_targets,
    validate_expected_matches_cases,
)

CORPUS: Final[Path] = default_cases_dir()

#: A log the production engine cannot classify: an honest unknown.
UNRECOGNISED_LOG: Final[str] = "Everything completed, and then the runner stopped.\n"

#: A log the engine classifies as a missing dependency, used to build synthetic corpora.
MISSING_MODULE_LOG: Final[str] = """\
Run python -m pytest tests -q
Traceback (most recent call last):
  File "tests/test_client.py", line 3, in <module>
    import requests
ModuleNotFoundError: No module named 'requests'
Error: Process completed with exit code 1.
"""


@pytest.fixture
def services(tmp_path: Path) -> Iterator[Services]:
    """Provide a real Services instance over a temporary database."""
    config = AppConfig(
        database_path=tmp_path / "incidents.db",
        color=False,
        json_output=False,
    )
    with Services.from_config(config) as svc:
        yield svc


def _write_corpus(
    directory: Path,
    *,
    log: str = MISSING_MODULE_LOG,
    expected_failure_type: str = "dependency_error",
    expected_rule_id: str | None = "DEP-001",
    min_confidence: float = 0.5,
    targets: dict[str, Any] | None = None,
    label: dict[str, Any] | None = None,
) -> Path:
    """Write a one-case corpus, optionally overriding targets or the expected label."""
    directory.mkdir(parents=True, exist_ok=True)
    case = {
        "case_id": "synthetic-case",
        "log": log,
        "expected_failure_type": expected_failure_type,
        "expected_rule_id": expected_rule_id,
        "min_confidence": min_confidence,
        "tags": ["synthetic"],
    }
    (directory / "synthetic-case.json").write_text(json.dumps(case), encoding="utf-8")
    expected = {
        "schema_version": "1.0.0",
        "description": "Synthetic corpus written by the test suite.",
        "targets": targets
        if targets is not None
        else {
            "type_accuracy_min": 1.0,
            "evidence_verification_rate_min": 1.0,
            "false_recovery_count_max": 0,
        },
        "cases": {
            "synthetic-case": label
            if label is not None
            else {
                "expected_failure_type": expected_failure_type,
                "expected_rule_id": expected_rule_id,
                "min_confidence": min_confidence,
            }
        },
    }
    (directory / "expected.json").write_text(json.dumps(expected), encoding="utf-8")
    return directory


# ---------------------------------------------------------------------------
# The corpus ships with the package
# ---------------------------------------------------------------------------


def test_default_corpus_is_package_data_not_test_data() -> None:
    """An installed wheel must carry the corpus, so it cannot live under tests/."""
    assert CORPUS.is_dir()
    assert CORPUS.name == "cases"
    assert CORPUS.parent.name == "intelligence"
    assert "tests" not in CORPUS.parts
    assert (CORPUS / "expected.json").is_file()
    assert len(load_cases(CORPUS)) >= 12


def test_default_targets_are_readable() -> None:
    """The committed bar exists and is the one the CLI enforces."""
    targets = load_targets(CORPUS / "expected.json")

    assert targets.type_accuracy_min == 1.0
    assert targets.evidence_verification_rate_min == 1.0
    assert targets.false_recovery_count_max == 0
    assert targets.rule_id_match_rate_min == 1.0


def test_both_committed_label_sources_agree() -> None:
    """``expected.json`` and the case files describe the same bar."""
    validate_expected_matches_cases(
        load_expected(CORPUS / "expected.json"),
        load_cases(CORPUS),
        source=CORPUS / "expected.json",
    )


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def test_production_engine_meets_every_committed_target(services: Services) -> None:
    """The shipped engine clears the corpus's own bar, or the command would fail."""
    run = services.benchmark()

    assert run.passed, run.verdict.to_text()
    assert run.report.total == len(load_cases(CORPUS))
    assert run.report.type_accuracy == 1.0
    assert run.report.evidence_verification_rate == 1.0
    assert run.report.rule_id_match_rate == 1.0
    assert run.report.false_recovery_count == 0


def test_every_declared_target_is_checked(services: Services) -> None:
    """A target that is declared must appear in the verdict, passed or not."""
    run = services.benchmark()

    checked = {check.name for check in run.verdict.checks}
    assert checked == {
        "type_accuracy",
        "evidence_verification_rate",
        "false_recovery_count",
        "mean_confidence",
        "rule_id_match_rate",
    }


def test_honest_unknowns_stay_unknown(services: Services) -> None:
    """A clean run, an ambiguous log and an injected instruction stay unclassified."""
    outcomes = {o.case_id: o for o in services.benchmark().report.outcomes}

    for case_id in (
        "clean-passing-run",
        "ambiguous-unknown-signature",
        "prompt-injection-inert",
    ):
        outcome = outcomes[case_id]
        assert outcome.actual_failure_type is FailureType.UNKNOWN
        assert outcome.correct_type


def test_repeated_runs_are_byte_identical(services: Services) -> None:
    """Two runs over the same corpus produce the same report and verdict."""
    first = services.benchmark()
    second = services.benchmark()

    assert first.to_dict() == second.to_dict()
    assert first.to_text() == second.to_text()


def test_run_payload_is_plain_json(services: Services) -> None:
    """``--json`` depends on the payload being serialisable and self-describing."""
    payload = services.benchmark().to_dict()

    assert json.loads(json.dumps(payload)) == payload
    assert payload["passed"] is True
    assert isinstance(payload["target_checks"], list)
    assert payload["cases_dir"] == str(CORPUS)


# ---------------------------------------------------------------------------
# Targets are enforced, not merely reported
# ---------------------------------------------------------------------------


def test_a_missed_target_fails_the_run(services: Services, tmp_path: Path) -> None:
    """A corpus the engine cannot meet is a failed run, not a number to read."""
    directory = _write_corpus(
        tmp_path / "cases",
        log=UNRECOGNISED_LOG,
        expected_failure_type="test_failure",
        expected_rule_id=None,
    )

    run = services.benchmark(directory)

    assert run.passed is False
    assert [check.name for check in run.verdict.failures] == ["type_accuracy"]
    assert run.report.type_accuracy == 0.0
    assert "TARGETS NOT MET" in run.verdict.to_text()


def test_check_targets_passes_when_every_target_is_met() -> None:
    """The comparison itself, independent of any engine."""
    report = BenchmarkReport(
        total=1,
        type_accuracy=1.0,
        evidence_verification_rate=1.0,
        false_recovery_count=0,
        mean_confidence=0.9,
        outcomes=(),
    )
    verdict = check_targets(
        report,
        BenchmarkTargets(
            type_accuracy_min=1.0,
            evidence_verification_rate_min=1.0,
            false_recovery_count_max=0,
        ),
    )

    assert verdict.passed is True
    assert verdict.failures == ()
    assert "targets met" in verdict.to_text()


def test_check_targets_enforces_each_metric_direction() -> None:
    """Rates have a floor, counts have a ceiling; each is checked the right way round."""
    report = BenchmarkReport(
        total=3,
        type_accuracy=0.66,
        evidence_verification_rate=0.0,
        false_recovery_count=2,
        mean_confidence=0.9,
        outcomes=(),
    )
    verdict = check_targets(
        report,
        BenchmarkTargets(
            type_accuracy_min=0.5,
            evidence_verification_rate_min=1.0,
            false_recovery_count_max=0,
            mean_confidence_min=0.4,
        ),
    )

    assert verdict.passed is False
    assert {check.name for check in verdict.failures} == {
        "evidence_verification_rate",
        "false_recovery_count",
    }


def test_optional_targets_are_only_checked_when_declared() -> None:
    """An undeclared optional target constrains nothing; a declared one does."""
    report = BenchmarkReport(
        total=1,
        type_accuracy=1.0,
        evidence_verification_rate=1.0,
        false_recovery_count=0,
        mean_confidence=0.1,
        outcomes=(),
        rule_id_match_rate=0.0,
    )
    loose = check_targets(
        report,
        BenchmarkTargets(
            type_accuracy_min=1.0,
            evidence_verification_rate_min=1.0,
            false_recovery_count_max=0,
        ),
    )
    strict = check_targets(
        report,
        BenchmarkTargets(
            type_accuracy_min=1.0,
            evidence_verification_rate_min=1.0,
            false_recovery_count_max=0,
            mean_confidence_min=0.5,
            rule_id_match_rate_min=1.0,
        ),
    )

    assert loose.passed is True
    assert {check.name for check in strict.failures} == {
        "mean_confidence",
        "rule_id_match_rate",
    }


# ---------------------------------------------------------------------------
# Configuration errors are explicit
# ---------------------------------------------------------------------------


def test_a_directory_without_expectations_is_an_input_error(
    services: Services, tmp_path: Path
) -> None:
    """A corpus with no committed bar cannot be benchmarked, and says so."""
    directory = _write_corpus(tmp_path / "cases")
    (directory / "expected.json").unlink()

    with pytest.raises(InvalidInputError, match=r"expected\.json"):
        services.benchmark(directory)


def test_an_unknown_target_key_is_rejected(services: Services, tmp_path: Path) -> None:
    """A typo in a target name must not silently lower the bar."""
    directory = _write_corpus(
        tmp_path / "cases",
        targets={
            "type_accuracy_min": 1.0,
            "evidence_verification_rate_min": 1.0,
            "false_recovery_count_max": 0,
            "type_acuracy_min": 0.5,
        },
    )

    with pytest.raises(InvalidInputError, match="type_acuracy_min"):
        services.benchmark(directory)


@pytest.mark.parametrize(
    "targets",
    (
        {"evidence_verification_rate_min": 1.0, "false_recovery_count_max": 0},
        {
            "type_accuracy_min": "1.0",
            "evidence_verification_rate_min": 1.0,
            "false_recovery_count_max": 0,
        },
        {
            "type_accuracy_min": -0.1,
            "evidence_verification_rate_min": 1.0,
            "false_recovery_count_max": 0,
        },
        {
            "type_accuracy_min": 1.0,
            "evidence_verification_rate_min": 1.0,
            "false_recovery_count_max": 0.5,
        },
    ),
    ids=("missing", "non-numeric", "negative", "fractional-count"),
)
def test_malformed_targets_are_rejected(
    services: Services, tmp_path: Path, targets: dict[str, Any]
) -> None:
    """Missing, mistyped, negative and fractional targets are all configuration errors."""
    directory = _write_corpus(tmp_path / "cases", targets=targets)

    with pytest.raises(InvalidInputError):
        services.benchmark(directory)


def test_a_contradictory_label_is_rejected(services: Services, tmp_path: Path) -> None:
    """The two committed label sources must agree; divergence is an error."""
    directory = _write_corpus(
        tmp_path / "cases",
        label={
            "expected_failure_type": "test_failure",
            "expected_rule_id": "TEST-001",
            "min_confidence": 0.5,
        },
    )

    with pytest.raises(InvalidInputError, match="contradictory"):
        services.benchmark(directory)


def test_a_label_for_an_absent_case_is_rejected(services: Services, tmp_path: Path) -> None:
    """A label pointing at a case that does not exist means the corpus is inconsistent."""
    directory = _write_corpus(tmp_path / "cases")
    expected_path = directory / "expected.json"
    payload = json.loads(expected_path.read_text(encoding="utf-8"))
    payload["cases"]["ghost-case"] = {
        "expected_failure_type": "test_failure",
        "expected_rule_id": "TEST-001",
        "min_confidence": 0.5,
    }
    expected_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(InvalidInputError, match="ghost-case"):
        services.benchmark(directory)


def test_a_case_missing_from_expectations_is_rejected(services: Services, tmp_path: Path) -> None:
    """A case file with no committed label is an inconsistent corpus, not an extra case."""
    directory = _write_corpus(tmp_path / "cases")
    (directory / "unlabelled.json").write_text(
        json.dumps(
            {
                "case_id": "unlabelled-case",
                "log": MISSING_MODULE_LOG,
                "expected_failure_type": "dependency_error",
                "expected_rule_id": "DEP-001",
                "min_confidence": 0.5,
                "tags": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInputError, match="unlabelled-case"):
        services.benchmark(directory)


def test_an_unsupported_failure_type_is_rejected(services: Services, tmp_path: Path) -> None:
    """A label naming a failure class the product has no enum for is a hard error."""
    directory = _write_corpus(
        tmp_path / "cases",
        expected_failure_type="quantum_error",
        label={
            "expected_failure_type": "quantum_error",
            "expected_rule_id": None,
            "min_confidence": 0.0,
        },
    )

    with pytest.raises(InvalidInputError, match="quantum_error"):
        services.benchmark(directory)


def test_an_empty_corpus_is_an_input_error(services: Services, tmp_path: Path) -> None:
    """An empty run would look like a perfect score, so it is refused instead."""
    directory = tmp_path / "empty"
    directory.mkdir()
    (directory / "expected.json").write_text(
        json.dumps(
            {
                "targets": {
                    "type_accuracy_min": 1.0,
                    "evidence_verification_rate_min": 1.0,
                    "false_recovery_count_max": 0,
                },
                "cases": {},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInputError):
        services.benchmark(directory)
