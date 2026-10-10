"""Recurrence intelligence tests (FR-014).

The recurring failures used here differ only in values that normalisation is supposed to
remove: timestamps, temp paths, and durations. If a fingerprint ever starts depending on
one of those, these tests fail.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from openmedic.domain.contracts import (
    DiagnosisResult,
    Evidence,
    FailureEvent,
    IncidentRecord,
)
from openmedic.domain.enums import FailureType, LifecycleState, RecommendedAction, RiskLevel
from openmedic.domain.errors import ContractError
from openmedic.intelligence import (
    RecurrenceGroup,
    failure_type_of,
    find_recurrences,
    fingerprint_incident,
    group_by_fingerprint,
    unique_records,
)

_EPOCH = datetime(2026, 5, 1, 10, 0, 0, tzinfo=UTC)


def _recurring_log(*, stamp: str, tmpdir: str, duration: str) -> str:
    """Build one occurrence of the same missing-module failure.

    The paths deliberately look like real runner temp directories, because the point of
    the test is that normalisation removes them. The strings are inert data.
    """
    return (
        "Run: python -m pytest tests/test_api.py -q\n"
        f"{stamp} Collected 1 item\n"
        f"rootdir: {tmpdir}\n"
        "E   ModuleNotFoundError: No module named 'requests'\n"
        f"=============================== 1 error in {duration} ===============================\n"
        "Error: Process completed with exit code 1.\n"
    )


_TMP_ROOT_ONE = "".join(("/", "tmp", "/pytest-of-runner/pytest-77/app"))
_TMP_ROOT_TWO = "".join(("/", "tmp", "/pytest-of-runner/pytest-148/app"))
_TMP_ROOT_THREE = "".join(("/", "var", "/", "tmp", "/build-90210/checkout"))
_TMP_ROOT_FOUR = "".join(("/", "tmp", "/scratch-abc123/work"))

_RECURRING_LOGS = (
    _recurring_log(
        stamp="2026-05-01T10:15:03Z",
        tmpdir=_TMP_ROOT_ONE,
        duration="0.42s",
    ),
    _recurring_log(
        stamp="2026-05-04T09:02:11Z",
        tmpdir=_TMP_ROOT_TWO,
        duration="1.71s",
    ),
    _recurring_log(
        stamp="2026-05-09T23:41:57Z",
        tmpdir=_TMP_ROOT_THREE,
        duration="12.30s",
    ),
)

_UNRELATED_LOG = (
    "Run: python -m compileall -q src\n"
    f"rootdir: {_TMP_ROOT_FOUR}\n"
    '  File "/home/runner/work/app/app/src/app/views.py", line 27\n'
    "    def render(context, strict)\n"
    "                              ^\n"
    "SyntaxError: expected ':'\n"
    "Error: Process completed with exit code 1.\n"
)


def _record(
    incident_id: str,
    *,
    log: str,
    at: datetime = _EPOCH,
    repository: str = "acme/checkout-service",
    state: LifecycleState = LifecycleState.RECEIVED,
    diagnosis_type: FailureType | None = None,
) -> IncidentRecord:
    """Build a minimal but contract-valid incident record."""
    event = FailureEvent(
        incident_id=incident_id,
        repository=repository,
        commit_sha="0f1e2d3c4b5a69788796a5b4c3d2e1f009182736",
        workflow_name="ci",
        job_name="build",
        run_id="5123456789",
        failed_step="Run tests",
        failure_type=FailureType.UNKNOWN,
        logs=log,
        timestamp=at,
    )
    diagnoses: list[DiagnosisResult] = []
    if diagnosis_type is not None:
        diagnoses.append(
            DiagnosisResult(
                incident_id=incident_id,
                failure_type=diagnosis_type,
                probable_cause="labelled by the test",
                evidence=[
                    Evidence(
                        source="logs:1",
                        quote="Run: python -m pytest",
                        explanation="test fixture",
                    )
                ],
                confidence=0.8,
                recommended_action=RecommendedAction.INVESTIGATE_MANUALLY,
                risk_level=RiskLevel.LOW,
                limitations=["test fixture"],
            )
        )
    return IncidentRecord(
        incident_id=incident_id,
        event=event,
        state=state,
        created_at=at,
        updated_at=at,
        diagnoses=diagnoses,
        idempotency_key=f"{repository}|ci|build|5123456789|Run tests",
    )


def _three_recurrences() -> list[IncidentRecord]:
    """Three occurrences of the same failure, minutes apart, in a fixed order."""
    return [
        _record("inc-a", log=_RECURRING_LOGS[0], at=_EPOCH),
        _record(
            "inc-b",
            log=_RECURRING_LOGS[1],
            at=_EPOCH + timedelta(minutes=45),
        ),
        _record(
            "inc-c",
            log=_RECURRING_LOGS[2],
            at=_EPOCH + timedelta(days=2, hours=3),
        ),
    ]


def test_three_recurrences_collapse_into_one_group() -> None:
    """Identical failures modulo volatile values must produce one group of three."""
    groups = group_by_fingerprint(_three_recurrences())

    assert len(groups) == 1
    group = groups[0]
    assert isinstance(group, RecurrenceGroup)
    assert group.count == 3
    assert group.incident_ids == ("inc-a", "inc-b", "inc-c")
    assert group.fingerprint == fingerprint_incident(_record("x", log=_RECURRING_LOGS[1]))


def test_unrelated_incident_stays_separate() -> None:
    """A different failure must not be absorbed into the recurring group."""
    records = [
        *_three_recurrences(),
        _record("inc-unrelated", log=_UNRELATED_LOG, at=_EPOCH + timedelta(minutes=1)),
    ]

    groups = group_by_fingerprint(records)

    assert len(groups) == 2
    by_count = {group.count: group for group in groups}
    assert by_count[3].incident_ids == ("inc-a", "inc-b", "inc-c")
    assert by_count[1].incident_ids == ("inc-unrelated",)


def test_first_and_last_seen_are_computed_from_event_timestamps() -> None:
    """First/last seen follow the failure times, normalised to UTC."""
    group = group_by_fingerprint(_three_recurrences())[0]

    assert group.first_seen == _EPOCH
    assert group.last_seen == datetime(2026, 5, 3, 13, 0, 0, tzinfo=UTC)
    assert group.first_seen.tzinfo is not None
    assert group.last_seen.tzinfo is not None


def test_ordering_is_count_descending_then_fingerprint() -> None:
    """The busiest signature comes first; ties break on the fingerprint."""
    groups = group_by_fingerprint([*_three_recurrences(), _record("z", log=_UNRELATED_LOG)])

    assert [group.count for group in groups] == [3, 1]
    assert (-groups[0].count, groups[0].fingerprint) <= (-groups[1].count, groups[1].fingerprint)


def test_find_recurrences_filters_by_min_count() -> None:
    """Singletons are not recurrences by default, but are returned with min_count=1."""
    records = [*_three_recurrences(), _record("z", log=_UNRELATED_LOG)]

    assert [g.incident_ids for g in find_recurrences(records)] == [("inc-a", "inc-b", "inc-c")]
    assert len(find_recurrences(records, min_count=1)) == 2


def test_min_count_below_one_is_rejected() -> None:
    """min_count=0 would return everything and call it a recurrence."""
    with pytest.raises(ValueError, match="min_count"):
        find_recurrences([], min_count=0)


def test_outcome_counts_are_lifecycle_counts_not_a_partition() -> None:
    """Recovered plus failed need not equal count: other states count in neither."""
    records = [
        _record("inc-a", log=_RECURRING_LOGS[0], state=LifecycleState.RECOVERED),
        _record("inc-b", log=_RECURRING_LOGS[1], state=LifecycleState.FAILED),
        _record("inc-c", log=_RECURRING_LOGS[2], state=LifecycleState.REQUIRES_HUMAN_REVIEW),
    ]

    group = group_by_fingerprint(records)[0]

    assert group.count == 3
    assert group.recovered_count == 1
    assert group.failed_count == 1
    assert group.recovered_count + group.failed_count < group.count


def test_failure_types_prefer_the_diagnosis_over_the_event_label() -> None:
    """The diagnosis classification wins and duplicate types collapse."""
    records = [
        _record("inc-a", log=_RECURRING_LOGS[0], diagnosis_type=FailureType.DEPENDENCY_ERROR),
        _record("inc-b", log=_RECURRING_LOGS[1], diagnosis_type=FailureType.DEPENDENCY_ERROR),
        _record("inc-c", log=_RECURRING_LOGS[2]),
    ]

    group = group_by_fingerprint(records)[0]

    assert group.failure_types == (FailureType.DEPENDENCY_ERROR, FailureType.UNKNOWN)
    assert failure_type_of(records[0]) is FailureType.DEPENDENCY_ERROR
    assert failure_type_of(records[2]) is FailureType.UNKNOWN


def test_repositories_are_deduplicated_and_sorted() -> None:
    """The same signature across repositories still groups, with both listed."""
    records = [
        _record("inc-a", log=_RECURRING_LOGS[0], repository="acme/web"),
        _record("inc-b", log=_RECURRING_LOGS[1], repository="acme/api"),
    ]

    group = group_by_fingerprint(records)[0]

    assert group.count == 2
    assert group.repositories == ("acme/api", "acme/web")


def test_fingerprint_ignores_secret_values() -> None:
    """Two logs that differ only in a token fingerprint identically."""
    module_line = "E   ModuleNotFoundError: No module named 'x'\n"
    first = _record("inc-a", log="token=abcdef0123456789\n" + module_line)
    second = _record("inc-b", log="token=ffffffffffffffff\n" + module_line)

    assert fingerprint_incident(first) == fingerprint_incident(second)


def test_duplicate_incident_ids_are_counted_once() -> None:
    """A duplicated record must not inflate a recurrence count."""
    repeated = [
        _record("inc-a", log=_RECURRING_LOGS[0]),
        _record("inc-a", log=_RECURRING_LOGS[0]),
    ]

    assert len(unique_records(repeated)) == 1
    assert group_by_fingerprint(repeated)[0].count == 1


def test_empty_input_returns_no_groups() -> None:
    """An empty corpus is an empty result, not an error."""
    assert group_by_fingerprint([]) == []
    assert find_recurrences([]) == []


def test_group_can_be_serialised() -> None:
    """The CLI and reporting layers need a JSON-safe payload."""
    group = group_by_fingerprint(_three_recurrences())[0]

    payload = group.to_dict()

    assert payload["count"] == 3
    assert payload["failure_types"] == ["unknown"]
    assert isinstance(payload["first_seen"], str)
    assert isinstance(payload["incident_ids"], list)


def test_record_without_diagnosis_is_valid() -> None:
    """A freshly ingested record has no diagnosis; the helper must still build one."""
    assert _record("inc-a", log=_RECURRING_LOGS[0]).latest_diagnosis is None


def test_contract_rejects_empty_limitations() -> None:
    """The diagnosis contract requires limitations, which keeps honesty structural."""
    with pytest.raises(ContractError):
        DiagnosisResult(
            incident_id="broken",
            failure_type=FailureType.UNKNOWN,
            probable_cause="x",
            confidence=0.5,
            recommended_action=RecommendedAction.NO_ACTION,
            risk_level=RiskLevel.NONE,
            limitations=[],
        )
