"""Application services: the orchestration the CLI and API share.

These tests exercise real layers against a temporary database. No network, no mocks of
OpenMedic's own code.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from openmedic.application.services import Outcome, Services
from openmedic.cli.config import AppConfig
from openmedic.domain.enums import LifecycleState
from openmedic.domain.errors import (
    IntegrationUnavailableError,
    InvalidInputError,
    ValidationFailedError,
)

DEPENDENCY_LOG = """\
2026-10-09T12:00:01Z ##[group]Run actions/checkout@v4
2026-10-09T12:00:02Z ##[group]Install dependencies
pip install -r requirements.txt
ERROR: Could not find a version that satisfies the requirement requests==99.0.0
ERROR: No matching distribution found for requests==99.0.0
2026-10-09T12:00:03Z ##[error]Process completed with exit code 1.
"""

#: One unambiguous import failure. Its rule (DEP-001) does not require human review, so
#: it is the case that exercises the plain ``diagnosing -> diagnosed`` path rather than
#: the ``requires_human_review`` branch.
MISSING_MODULE_LOG = """\
Run python -m pytest tests -q
Traceback (most recent call last):
  File "tests/test_client.py", line 3, in <module>
    import requests
ModuleNotFoundError: No module named 'requests'
Error: Process completed with exit code 1.
"""


@pytest.fixture
def services(tmp_path: Path) -> Services:
    config = AppConfig(
        database_path=tmp_path / "incidents.db",
        color=False,
        json_output=False,
    )
    with Services.from_config(config) as svc:
        yield svc


def test_diagnose_text_is_offline_and_structured(services: Services) -> None:
    diagnosis = services.diagnose_text(DEPENDENCY_LOG, repository="example/app", run_id="7")
    assert diagnosis.failure_type.value in {
        "dependency_error",
        "build_or_config_error",
        "test_failure",
        "unknown",
    }
    assert 0.0 <= diagnosis.confidence <= 1.0
    assert diagnosis.limitations


def test_diagnose_text_rejects_empty_input(services: Services) -> None:
    with pytest.raises(InvalidInputError):
        services.diagnose_text("   ")


def test_ingest_event_json_round_trips_through_storage(services: Services) -> None:
    from openmedic.ingestion import dump_event_json
    from tests.conftest import make_event

    event = make_event(logs="ERROR: ModuleNotFoundError: No module named 'requests'\n")
    services.ingest_event_json(dump_event_json(event))
    stored = services.get_incident(event.resolved_incident_id)
    assert stored.event.logs == event.logs


def test_ingest_event_json_rejects_malformed_payload(services: Services) -> None:
    with pytest.raises(InvalidInputError):
        services.ingest_event_json("{not json")


def test_duplicate_ingestion_is_idempotent(services: Services) -> None:
    from openmedic.ingestion import dump_event_json
    from tests.conftest import make_event

    event = make_event(logs="ERROR: boom\n")
    services.ingest_event_json(dump_event_json(event))
    services.ingest_event_json(dump_event_json(event))
    assert len(services.list_incidents(limit=100)) == 1


def test_reingesting_a_progressed_incident_does_not_erase_its_history(
    services: Services, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repeated arrival is not a reset: existing progress must survive a duplicate.

    Ingestion used to build a fresh ``RECEIVED`` record and overwrite the stored row, so
    the same event arriving twice silently discarded the diagnosis, the remediation
    attempt, and every recorded transition — erasing exactly the append-only history the
    rest of the product promises to keep, and turning a ``failed`` incident back into a
    freshly ``diagnosing`` one as though nothing had been learned. The duplicate has to
    return the incident as it stands instead.
    """
    from openmedic.ingestion import dump_event_json

    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    services.ingest_log(MISSING_MODULE_LOG, repository="example/app", run_id="21")
    incident_id = services.list_incidents(limit=1)[0].incident_id
    services.diagnose_stored(incident_id)
    services.repair(incident_id, apply=False)

    before = services.get_incident(incident_id)
    payload = dump_event_json(before.event)
    assert before.state is LifecycleState.REMEDIATION_PENDING
    assert len(before.diagnoses) == 1
    assert len(before.attempts) == 1
    history_before = [t.to_state for t in before.state_history]

    returned = services.ingest_event_json(payload)

    assert returned.incident_id == incident_id
    assert len(services.list_incidents(limit=100)) == 1, (
        "a duplicate must not open a second incident"
    )
    after = services.get_incident(incident_id)
    assert after.state is LifecycleState.REMEDIATION_PENDING
    assert len(after.diagnoses) == 1, "the diagnosis was erased by a repeat ingestion"
    assert len(after.attempts) == 1, "the candidate patch was erased by a repeat ingestion"
    assert [t.to_state for t in after.state_history] == history_before, (
        "state history is append-only; a re-arrival may not rewrite it"
    )


def test_reingesting_a_review_required_incident_leaves_it_waiting_for_a_human(
    services: Services,
) -> None:
    """A terminal verdict must not be undone by the same event arriving again."""
    from openmedic.ingestion import dump_event_json

    services.ingest_log(DEPENDENCY_LOG, repository="example/app", run_id="22")
    incident_id = services.list_incidents(limit=1)[0].incident_id
    services.diagnose_stored(incident_id)
    before = services.get_incident(incident_id)
    assert before.state is LifecycleState.REQUIRES_HUMAN_REVIEW
    payload = dump_event_json(before.event)

    services.ingest_event_json(payload)

    after = services.get_incident(incident_id)
    assert after.state is LifecycleState.REQUIRES_HUMAN_REVIEW, (
        "a duplicate arrival must not put an incident needing a human back into triage"
    )
    assert len(after.diagnoses) == 1
    assert len(services.list_incidents(limit=100)) == 1


def test_listing_filters_by_state(services: Services) -> None:
    from openmedic.domain.errors import InvalidInputError as Bad

    with pytest.raises(Bad):
        services.list_incidents(state="not-a-state")


def test_get_unknown_incident_raises(services: Services) -> None:
    with pytest.raises(InvalidInputError):
        services.get_incident("inc-does-not-exist")


def test_diagnose_stored_advances_the_lifecycle(services: Services) -> None:
    services.ingest_log(DEPENDENCY_LOG, repository="example/app", run_id="8")
    records = services.list_incidents(limit=10)
    assert records, "ingest_log must store an incident"
    record = services.diagnose_stored(records[0].incident_id)
    assert len(record.diagnoses) == 1
    assert record.state in {LifecycleState.DIAGNOSED, LifecycleState.REQUIRES_HUMAN_REVIEW}


def test_diagnose_stored_handles_a_diagnosis_that_needs_no_review(services: Services) -> None:
    """The ordinary path must not request a state the record is already in.

    ``record_diagnosis`` walks ``diagnosing -> diagnosed`` itself, so re-applying
    ``diagnosed`` would be an illegal self-transition. Only a review-requiring diagnosis
    has a second transition left to make.
    """
    services.ingest_log(MISSING_MODULE_LOG, repository="example/app", run_id="13")
    record = services.list_incidents(limit=1)[0]
    assert record.state is LifecycleState.DIAGNOSING

    diagnosed = services.diagnose_stored(record.incident_id)

    assert diagnosed.state is LifecycleState.DIAGNOSED
    assert len(diagnosed.diagnoses) == 1
    assert diagnosed.latest_diagnosis is not None
    assert diagnosed.latest_diagnosis.requires_human_review is False
    assert [t.to_state for t in diagnosed.state_history] == [
        LifecycleState.DIAGNOSING,
        LifecycleState.DIAGNOSED,
    ]


def test_repair_dry_run_parks_the_incident_at_remediation_pending(
    services: Services, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recording a proposal must not claim that remediation already started.

    A dry run writes nothing, so the incident has to rest at ``remediation_pending`` —
    the state between ``diagnosed`` and ``remediating`` — with the attempt persisted for
    a later ``validate`` to find.
    """
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    services.ingest_log(MISSING_MODULE_LOG, repository="example/app", run_id="14")
    incident_id = services.list_incidents(limit=1)[0].incident_id

    outcome = services.repair(incident_id, apply=False)

    assert isinstance(outcome, Outcome)
    assert "attempt_id" in outcome.payload, outcome.message
    assert outcome.payload["patch_hash"]
    after = services.get_incident(incident_id)
    assert after.state is LifecycleState.REMEDIATION_PENDING
    assert len(after.attempts) == 1
    # The source tree is untouched by a dry run.
    assert (tmp_path / "requirements.txt").read_text(encoding="utf-8") == "flask\n"


def test_validate_walks_from_pending_through_remediating_to_an_honest_verdict(
    services: Services, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The service path reaches the checks, and an empty policy cannot read as success."""
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    services.ingest_log(MISSING_MODULE_LOG, repository="example/app", run_id="15")
    incident_id = services.list_incidents(limit=1)[0].incident_id
    services.repair(incident_id, apply=False)

    # An empty project has no required checks to run, so validation must not pass.
    with pytest.raises(ValidationFailedError):
        services.validate(incident_id)

    after = services.get_incident(incident_id)
    # The walk the state machine promises: pending -> remediating -> validating -> verdict.
    assert [t.to_state for t in after.state_history] == [
        LifecycleState.DIAGNOSING,
        LifecycleState.DIAGNOSED,
        LifecycleState.REMEDIATION_PENDING,
        LifecycleState.REMEDIATING,
        LifecycleState.VALIDATING,
        after.state,
    ]
    assert after.state in {LifecycleState.FAILED, LifecycleState.REQUIRES_HUMAN_REVIEW}
    assert after.state is not LifecycleState.RECOVERED


def test_doctored_stored_diff_is_refused_before_anything_is_written(
    services: Services, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The persisted patch text is the patch: altering it must not silently change it.

    Everything downstream writes from ``patch_unified_diff``, so the rebuild has to
    reproduce the recorded ``patch_hash``. A diff that replays to a different patch is
    refused, which keeps a tampered incident record from reaching the worktree.
    """
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    services.ingest_log(MISSING_MODULE_LOG, repository="example/app", run_id="16")
    incident_id = services.list_incidents(limit=1)[0].incident_id
    services.repair(incident_id, apply=False)

    record = services.get_incident(incident_id)
    attempt = record.attempts[-1]
    tampered = attempt.model_copy(
        update={
            "patch_unified_diff": attempt.patch_unified_diff.replace(
                "+requests", "+requests==99.0.0"
            )
        }
    )
    assert tampered.patch_unified_diff != attempt.patch_unified_diff
    services.repository.record_attempt(incident_id, tampered, at=tampered.created_at)

    with pytest.raises(InvalidInputError, match="recorded patch hash"):
        services.validate(incident_id)

    # Nothing in the disposable tree was ever written from the doctored text.
    assert (tmp_path / "requirements.txt").read_text(encoding="utf-8") == "flask\n"


def test_incident_survives_a_reprocess(services: Services) -> None:
    services.ingest_log(DEPENDENCY_LOG, repository="example/app", run_id="9")
    first = services.list_incidents(limit=1)[0]
    reopened = services.get_incident(first.incident_id)
    assert reopened.incident_id == first.incident_id


def test_markdown_report_is_honest_about_state(services: Services) -> None:
    services.ingest_log(DEPENDENCY_LOG, repository="example/app", run_id="10")
    record = services.list_incidents(limit=1)[0]
    markdown = services.markdown_report(record)
    assert isinstance(markdown, str)
    # An unrecovered incident must be reported as unrecovered.
    if record.state is not LifecycleState.RECOVERED:
        assert "not recovered" in markdown.lower()
    assert "not automatically merged" in markdown.lower()


def test_provider_payload_reports_deterministic_only_without_config(services: Services) -> None:
    payload = services.provider_payload()
    assert "available" in payload
    assert payload["available"] == []


def test_github_ingestion_without_a_token_fails_closed(services: Services) -> None:
    with pytest.raises(IntegrationUnavailableError):
        services.ingest_github_run("example/app", "1")
    with pytest.raises(IntegrationUnavailableError):
        services.ingest_github_run("example/app", "1")


def test_render_incident_table_handles_empty_store(services: Services) -> None:
    assert "No incidents" in services.render_incident_table([])


def test_render_incident_table_lists_incidents(services: Services) -> None:
    services.ingest_log(DEPENDENCY_LOG, repository="example/app", run_id="11")
    text = services.render_incident_table(services.list_incidents(limit=5))
    assert "inc-" in text


def test_repair_without_stored_incident_raises(services: Services) -> None:
    from openmedic.domain.errors import InvalidInputError as Bad

    with pytest.raises(Bad):
        services.repair("inc-nope", apply=False)


def test_repair_without_diagnosis_diagnoses_first(services: Services) -> None:
    services.ingest_log(DEPENDENCY_LOG, repository="example/app", run_id="12")
    record = services.list_incidents(limit=1)[0]
    outcome = services.repair(record.incident_id, apply=False)
    assert isinstance(outcome, Outcome)
    # Either a proposal or an honest refusal — never a fake success.
    after = services.get_incident(record.incident_id)
    assert after.state in {
        LifecycleState.REMEDIATION_PENDING,
        LifecycleState.REQUIRES_HUMAN_REVIEW,
        LifecycleState.DIAGNOSED,
    }


def test_benchmark_default_cases_dir_resolves(services: Services) -> None:
    """``openmedic benchmark`` with no argument must find the committed corpus.

    The corpus is package data resolved from the intelligence layer, so the same path
    works from a source checkout and from an installed wheel. A regression here makes a
    documented command fail with "directory not found" before it classifies a single
    case — and the failure is easy to miss, because nothing else in the product invokes
    the benchmark.
    """
    from openmedic.application.services import _default_cases_dir

    directory = _default_cases_dir()
    assert directory.is_dir(), f"default benchmark corpus missing: {directory}"
    assert (directory / "expected.json").is_file()
    assert "tests" not in directory.parts

    run = services.benchmark()

    assert run.report.total > 0
    assert run.cases_dir == directory
    # The committed targets are the corpus's own bar, and they are enforced: a run that
    # misses one reports ``passed`` as False rather than merely printing a number.
    assert run.targets.false_recovery_count_max == 0
    assert run.verdict.passed
    assert run.passed
