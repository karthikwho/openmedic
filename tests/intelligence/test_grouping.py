"""Cascade grouping honesty tests (FR-015, roadmap Milestone 10).

The roadmap exit gate for this milestone reads: "grouping tests include unrelated
failures that must not be merged". These tests exist to fail loudly if grouping ever
becomes eager enough to present unrelated failures as a cascade.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from openmedic.domain.contracts import FailureEvent, IncidentRecord
from openmedic.domain.enums import LifecycleState
from openmedic.intelligence import group_cascades
from openmedic.intelligence.grouping import GROUPING_RULE, MAX_GROUP_CONFIDENCE

_EPOCH = datetime(2026, 6, 1, 8, 0, 0, tzinfo=UTC)

_COMMIT_ALPHA = "11a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4"
_COMMIT_BETA = "99f8e7d6c5b4a3928170695112233445566778899"
_COMMIT_GAMMA = "5c4b3a29182736455647382910a1b2c3d4e5f6071"

_MODULE_LOG = (
    "Run: python -m pytest tests/test_api.py -q\n"
    "2026-06-01T08:00:00Z Collected 1 item\n"
    "rootdir: /tmp/pytest-of-runner/pytest-77/app\n"
    "E   ModuleNotFoundError: No module named 'requests'\n"
    "=============================== 1 error in 0.42s ===============================\n"
    "Error: Process completed with exit code 1.\n"
)

_DEPLOY_LOG = (
    "Run: ./scripts/deploy.sh --target\n"
    "2026-06-01T08:00:00Z resolving context\n"
    "rootdir: /home/runner/work/app/app\n"
    "deploy: error: required environment variable DEPLOY_TARGET is not set\n"
    "=============================== 1 error in 3.10s ===============================\n"
    "Error: Process completed with exit code 1.\n"
)

_JOB_LOG = (
    "Run: python -m pytest tests/test_billing.py -q\n"
    "2026-06-01T08:00:00Z Collected 4 items\n"
    "rootdir: /home/runner/work/app/app\n"
    "E   AssertionError: assert 39.99 == 42.5\n"
    "========================= 1 failed, 3 passed in 1.83s =========================\n"
    "Error: Process completed with exit code 1.\n"
)


def _record(
    incident_id: str,
    *,
    log: str,
    at: datetime = _EPOCH,
    repository: str = "acme/checkout-service",
    commit_sha: str | None = _COMMIT_ALPHA,
    workflow_name: str | None = "ci",
    job_name: str | None = "build",
    run_id: str | None = "5123456789",
    failed_step: str | None = "Run tests",
) -> IncidentRecord:
    """Build a minimal but contract-valid incident record."""
    event = FailureEvent(
        incident_id=incident_id,
        repository=repository,
        commit_sha=commit_sha,
        workflow_name=workflow_name,
        job_name=job_name,
        run_id=run_id,
        failed_step=failed_step,
        logs=log,
        timestamp=at,
    )
    return IncidentRecord(
        incident_id=incident_id,
        event=event,
        state=LifecycleState.RECEIVED,
        created_at=at,
        updated_at=at,
        idempotency_key="|".join(
            [
                repository or "-",
                workflow_name or "-",
                job_name or "-",
                run_id or "-",
                failed_step or "-",
            ]
        ),
    )


def test_unrelated_failures_are_never_merged() -> None:
    """Different signatures, repos, runs, steps, and commits produce no groups."""
    records = [
        _record(
            "inc-a",
            log=_MODULE_LOG,
            at=_EPOCH,
            repository="acme/checkout-service",
            commit_sha=_COMMIT_ALPHA,
            run_id="7000000001",
            job_name="build",
            failed_step="Run tests",
        ),
        _record(
            "inc-b",
            log=_DEPLOY_LOG,
            at=_EPOCH + timedelta(minutes=1),
            repository="acme/deployer",
            commit_sha=_COMMIT_BETA,
            run_id="7000000002",
            job_name="deploy",
            failed_step="Deploy to staging",
        ),
        _record(
            "inc-c",
            log=_JOB_LOG,
            at=_EPOCH + timedelta(minutes=2),
            repository="acme/billing",
            commit_sha=_COMMIT_GAMMA,
            run_id="7000000003",
            job_name="test",
            failed_step="Run unit tests",
        ),
    ]

    assert group_cascades(records) == []


def test_context_similarity_is_not_enough_to_merge() -> None:
    """Same repo, same failure type, same workflow, same job: still unrelated.

    This is the core honesty case. Repository and failure-type are contextual signals:
    they are reported in ``shared_signals`` but never counted toward ``min_shared``.
    """
    shared_repo = "acme/checkout-service"
    records = [
        _record(
            "inc-a",
            log=_MODULE_LOG,
            at=_EPOCH,
            repository=shared_repo,
            job_name="build",
            run_id="1000000001",
            commit_sha=None,
        ),
        _record(
            "inc-b",
            log=_JOB_LOG,
            at=_EPOCH + timedelta(seconds=30),
            repository=shared_repo,
            job_name="build",
            run_id="1000000002",
            commit_sha=None,
        ),
        _record(
            "inc-c",
            log=_DEPLOY_LOG,
            at=_EPOCH + timedelta(seconds=90),
            repository=shared_repo,
            job_name="build",
            run_id="1000000003",
            commit_sha=None,
        ),
    ]

    assert group_cascades(records, min_shared=2) == []


def test_requires_two_identifying_signals_by_default() -> None:
    """One signal (the job-and-step pair) is below the default threshold of two."""
    records = [
        _record(
            "inc-a",
            log=_MODULE_LOG,
            at=_EPOCH,
            repository="org/one",
            commit_sha=None,
            run_id="3000000001",
        ),
        _record(
            "inc-b",
            log=_JOB_LOG,
            at=_EPOCH + timedelta(seconds=60),
            repository="org/two",
            commit_sha=None,
            run_id="3000000002",
        ),
    ]

    assert group_cascades(records) == []
    groups = group_cascades(records, min_shared=1)
    assert len(groups) == 1
    assert "job-step=build|Run tests" in groups[0].shared_signals


def test_identical_fingerprint_and_commit_forms_one_group() -> None:
    """Two genuinely linked failures group with both signals recorded."""
    records = [
        _record("inc-a", log=_MODULE_LOG, at=_EPOCH, commit_sha=_COMMIT_BETA),
        _record(
            "inc-b",
            log=_MODULE_LOG,
            at=_EPOCH + timedelta(minutes=10),
            commit_sha=_COMMIT_BETA,
        ),
    ]

    groups = group_cascades(records)

    assert len(groups) == 1
    group = groups[0]
    assert group.incident_ids == ("inc-a", "inc-b")
    assert any(signal.startswith("fingerprint=") for signal in group.shared_signals)
    assert f"commit={_COMMIT_BETA}" in group.shared_signals
    assert group.time_span == (_EPOCH, _EPOCH + timedelta(minutes=10))
    assert group.repositories == ("acme/checkout-service",)
    assert 0.0 < group.confidence <= MAX_GROUP_CONFIDENCE


def test_time_window_is_enforced() -> None:
    """Failures outside the window are not grouped even with identical signals."""
    records = [
        _record("inc-a", log=_MODULE_LOG, at=_EPOCH),
        _record("inc-b", log=_MODULE_LOG, at=_EPOCH + timedelta(hours=2)),
    ]

    assert group_cascades(records, window_seconds=1800) == []
    assert len(group_cascades(records, window_seconds=7200)) == 1


def test_shared_signals_are_the_intersection_over_all_members() -> None:
    """A signal is shared only if *every* member carries it."""
    records = [
        _record("inc-a", log=_MODULE_LOG, at=_EPOCH, commit_sha=_COMMIT_ALPHA),
        _record(
            "inc-b",
            log=_MODULE_LOG,
            at=_EPOCH + timedelta(minutes=5),
            commit_sha=_COMMIT_ALPHA,
        ),
        _record(
            "inc-c",
            log=_MODULE_LOG,
            at=_EPOCH + timedelta(minutes=9),
            commit_sha=_COMMIT_BETA,
        ),
    ]

    groups = group_cascades(records)

    assert len(groups) == 1
    group = groups[0]
    assert group.incident_ids == ("inc-a", "inc-b", "inc-c")
    assert f"commit={_COMMIT_ALPHA}" not in group.shared_signals
    assert f"commit={_COMMIT_BETA}" not in group.shared_signals
    assert "run=5123456789" in group.shared_signals


def test_every_group_reports_evidence_and_the_correlation_limitation() -> None:
    """No group may exist without shared evidence and an honest caveat."""
    records = [
        _record("inc-a", log=_MODULE_LOG, at=_EPOCH),
        _record("inc-b", log=_MODULE_LOG, at=_EPOCH + timedelta(minutes=3)),
    ]

    for group in group_cascades(records):
        assert group.shared_signals, "a group with no shared signal is unfounded"
        assert group.limitations, "a group with no limitations overclaims"
        joined = " ".join(group.limitations).lower()
        assert "correlat" in joined
        assert "does not establish that any incident caused another" in joined
        assert f"capped at {MAX_GROUP_CONFIDENCE:.2f}" in joined


def test_single_incident_is_never_a_cascade() -> None:
    """One failure is not a cascade, however it is parameterised."""
    only = _record("inc-a", log=_MODULE_LOG, at=_EPOCH)

    assert group_cascades([only], min_shared=1) == []
    assert group_cascades([only], min_shared=1, window_seconds=1) == []


def test_group_ids_are_stable_and_independent_of_input_order() -> None:
    """The same incidents in any order must produce an identical result."""
    records = [
        _record("inc-a", log=_MODULE_LOG, at=_EPOCH),
        _record("inc-b", log=_MODULE_LOG, at=_EPOCH + timedelta(minutes=4)),
        _record(
            "inc-c",
            log=_DEPLOY_LOG,
            at=_EPOCH + timedelta(minutes=6),
            commit_sha=_COMMIT_GAMMA,
        ),
    ]

    forward = group_cascades(records)
    backwards = group_cascades(list(reversed(records)))

    assert forward == backwards
    assert [group.group_id for group in forward] == [group.group_id for group in backwards]
    assert forward[0].group_id.startswith("cascade-")


def test_different_repositories_form_one_group_and_list_both() -> None:
    """A shared fingerprint across repositories still groups, with both listed."""
    records = [
        _record(
            "inc-a",
            log=_MODULE_LOG,
            at=_EPOCH,
            repository="acme/web",
            commit_sha=_COMMIT_ALPHA,
        ),
        _record(
            "inc-b",
            log=_MODULE_LOG,
            at=_EPOCH + timedelta(minutes=1),
            repository="acme/api",
            commit_sha=_COMMIT_ALPHA,
        ),
    ]

    groups = group_cascades(records)

    assert len(groups) == 1
    assert groups[0].repositories == ("acme/api", "acme/web")
    assert any("multiple repositories" in item for item in groups[0].limitations)


def test_duplicate_incident_ids_do_not_inflate_a_group() -> None:
    """Repeated ingestion is an idempotency concern; grouping must not double-count."""
    record = _record("inc-a", log=_MODULE_LOG, at=_EPOCH)

    assert group_cascades([record, record], min_shared=1) == []


def test_published_rule_documents_the_counted_signals() -> None:
    """The rule is published text, not tribal knowledge."""
    assert "identifying" in GROUPING_RULE
    assert "never counted" in GROUPING_RULE
    assert "min_shared" in GROUPING_RULE
    assert "window_seconds" in GROUPING_RULE


def test_invalid_parameters_are_rejected() -> None:
    """A zero window and a zero threshold are nonsense, not defaults."""
    records = [_record("inc-a", log=_MODULE_LOG, at=_EPOCH)]

    for kwargs in ({"window_seconds": 0}, {"min_shared": 0}):
        try:
            group_cascades(records, **kwargs)
        except ValueError as exc:
            assert "must be" in str(exc)
        else:  # pragma: no cover - the raise above is the assertion
            raise AssertionError(f"expected ValueError for {kwargs}")


def test_group_can_be_serialised() -> None:
    """The reporting layer needs a JSON-safe payload."""
    records = [
        _record("inc-a", log=_MODULE_LOG, at=_EPOCH),
        _record("inc-b", log=_MODULE_LOG, at=_EPOCH + timedelta(minutes=2)),
    ]

    payload = group_cascades(records)[0].to_dict()

    assert payload["incident_ids"] == ["inc-a", "inc-b"]
    assert isinstance(payload["time_span"], list)
    assert len(payload["time_span"]) == 2
    assert payload["confidence"] <= MAX_GROUP_CONFIDENCE
