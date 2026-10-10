"""Repository tests: round trips, idempotency, redaction, lifecycle, and rollback."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from openmedic.domain.contracts import (
    CheckResult,
    LifecycleState,
)
from openmedic.domain.enums import CheckStatus
from openmedic.domain.errors import ContractError, InvalidInputError, PersistenceError
from openmedic.persistence import db_info
from openmedic.persistence.database import connect
from openmedic.persistence.repository import IncidentRepository
from tests.persistence.conftest import (
    BASE_TIME,
    LEAKED_BEARER,
    LEAKED_VALUE,
    OTHER_PATCH_HASH,
    PATCH_HASH,
)

# -- round trip ---------------------------------------------------------------


def test_rich_incident_survives_a_save_and_load_exactly(
    repo: IncidentRepository,
    make_incident,
    make_diagnosis,
    make_attempt,
    make_validation,
) -> None:
    incident = make_incident()
    rich = incident.model_copy(
        update={
            "diagnoses": [make_diagnosis(incident)],
            "attempts": [
                make_attempt(incident),
                make_attempt(incident, attempt_id="attempt-2", patch_hash=OTHER_PATCH_HASH),
            ],
            "validations": [make_validation(incident)],
        }
    )

    repo.upsert_incident(rich)
    loaded = repo.get_incident(incident.incident_id)

    assert loaded is not None
    assert loaded.model_dump() == rich.model_dump()
    assert loaded.diagnoses == rich.diagnoses
    assert [a.attempt_id for a in loaded.attempts] == ["attempt-1", "attempt-2"]
    assert loaded.validations == rich.validations


def test_restart_persistence(
    db_path, repo: IncidentRepository, make_incident, make_diagnosis
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    repo.record_diagnosis(incident.incident_id, make_diagnosis(incident), at=BASE_TIME)
    repo.close()

    reopened = IncidentRepository(db_path)
    try:
        loaded = reopened.get_incident(incident.incident_id)
        assert loaded is not None
        assert loaded.model_dump(mode="json") == repo_stored_dump(reopened, incident.incident_id)
        assert len(loaded.diagnoses) == 1
        assert loaded.state is LifecycleState.DIAGNOSED
    finally:
        reopened.close()


def repo_stored_dump(repo: IncidentRepository, incident_id: str) -> dict:
    """Return the payload the repository persisted, for before/after comparisons."""
    row = repo.conn.execute(
        "SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)
    ).fetchone()
    return json.loads(row[0])


def test_export_and_import_round_trip(
    db_path, repo: IncidentRepository, make_incident, make_diagnosis
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    repo.record_diagnosis(incident.incident_id, make_diagnosis(incident), at=BASE_TIME)
    document = repo.export_json(incident.incident_id)

    assert json.loads(document)["incident_id"] == incident.incident_id

    repo.delete_incident(incident.incident_id)
    assert repo.get_incident(incident.incident_id) is None

    restored = repo.import_json(document)
    assert restored.incident_id == incident.incident_id
    reloaded = repo.get_incident(incident.incident_id)
    assert reloaded is not None
    # The restored copy must match what was stored, diagnosis and all -- not the
    # original object, which predates the recorded diagnosis.
    assert restored.model_dump(mode="json") == reloaded.model_dump(mode="json")
    assert len(restored.diagnoses) == 1
    assert restored.state is LifecycleState.DIAGNOSED


def test_import_json_rejects_malformed_payloads(repo: IncidentRepository) -> None:
    with pytest.raises(InvalidInputError):
        repo.import_json("{not json")
    with pytest.raises(InvalidInputError):
        repo.import_json(json.dumps({"incident_id": "inc-1"}))


# -- idempotency --------------------------------------------------------------


def test_re_ingesting_the_same_event_yields_one_row_and_one_id(
    repo: IncidentRepository, make_incident
) -> None:
    incident = make_incident()

    first = repo.upsert_incident(incident)
    second = repo.upsert_incident(make_incident())

    assert repo.count_incidents() == 1
    assert first.incident_id == second.incident_id
    rows = repo.conn.execute("SELECT count(*) FROM incidents").fetchone()[0]
    assert rows == 1


def test_duplicate_idempotency_key_keeps_the_stored_incident_id(
    repo: IncidentRepository, make_incident
) -> None:
    repo.upsert_incident(make_incident())

    # A different incident ID for the same source event must not fork a second incident.
    clash = make_incident(incident_id="inc-someone-elses-id")
    stored = repo.upsert_incident(clash)

    assert repo.count_incidents() == 1
    assert stored.incident_id != "inc-someone-elses-id"
    assert repo.find_by_idempotency_key(clash.idempotency_key) is not None
    assert repo.get_incident("inc-someone-elses-id") is None


def test_find_by_idempotency_key(repo: IncidentRepository, make_incident) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)

    found = repo.find_by_idempotency_key(incident.idempotency_key)
    assert found is not None
    assert found.incident_id == incident.incident_id
    assert repo.find_by_idempotency_key("nope|-|-|-|-") is None


def test_upsert_updates_the_same_incident_in_place(
    repo: IncidentRepository, make_incident, make_diagnosis
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    with_diagnosis = repo.record_diagnosis(
        incident.incident_id, make_diagnosis(incident), at=BASE_TIME
    )

    again = repo.upsert_incident(with_diagnosis)

    assert repo.count_incidents() == 1
    assert len(again.diagnoses) == 1
    assert again.model_dump() == repo.get_incident(incident.incident_id).model_dump()


def test_re_recording_an_attempt_is_idempotent_but_a_retry_is_a_new_attempt(
    repo: IncidentRepository, make_incident, make_attempt
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    repo.record_attempt(incident.incident_id, make_attempt(incident), at=BASE_TIME)

    # Re-recording the same attempt ID replaces that attempt.
    updated = make_attempt(incident, summary="revised summary")
    repo.record_attempt(incident.incident_id, updated, at=BASE_TIME)

    # A retry adds a second attempt instead of replacing the first.
    retry = make_attempt(incident, attempt_id="attempt-2")
    final = repo.record_attempt(incident.incident_id, retry, at=BASE_TIME)

    assert [a.attempt_id for a in final.attempts] == ["attempt-1", "attempt-2"]
    assert final.attempts[0].summary == "revised summary"


def test_re_recording_the_same_diagnosis_does_not_duplicate_it(
    repo: IncidentRepository, make_incident, make_diagnosis
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    diagnosis = make_diagnosis(incident)
    repo.record_diagnosis(incident.incident_id, diagnosis, at=BASE_TIME)
    after = repo.record_diagnosis(incident.incident_id, diagnosis, at=BASE_TIME)

    assert len(after.diagnoses) == 1


# -- listing and deletion -----------------------------------------------------


def test_list_incidents_is_newest_first_and_stable(repo: IncidentRepository, make_incident) -> None:
    first = make_incident(run_id="1", updated_at=BASE_TIME)
    second = make_incident(run_id="2", updated_at=BASE_TIME + timedelta(hours=1))
    third = make_incident(run_id="3", updated_at=BASE_TIME + timedelta(hours=2))
    repo.upsert_incident(first)
    repo.upsert_incident(second)
    repo.upsert_incident(third)

    assert [i.incident_id for i in repo.list_incidents()] == [
        third.incident_id,
        second.incident_id,
        first.incident_id,
    ]
    assert [i.incident_id for i in repo.list_incidents()] == [
        i.incident_id for i in repo.list_incidents()
    ]


def test_list_incidents_filters_by_state_and_pages(repo: IncidentRepository, make_incident) -> None:
    for index in range(3):
        repo.upsert_incident(
            make_incident(run_id=str(index), updated_at=BASE_TIME + timedelta(hours=index))
        )
    target = repo.list_incidents()[1].incident_id
    repo.append_transition(target, LifecycleState.DIAGNOSING, reason="start", at=BASE_TIME)

    assert repo.count_incidents(state=LifecycleState.DIAGNOSING) == 1
    assert [i.incident_id for i in repo.list_incidents(state=LifecycleState.DIAGNOSING)] == [target]
    assert repo.count_incidents(state=LifecycleState.RECEIVED) == 2

    page = repo.list_incidents(limit=1, offset=1)
    assert [i.incident_id for i in page] == [repo.list_incidents()[1].incident_id]
    assert repo.list_incidents(limit=0) == []
    assert len(repo.all_incidents()) == 3


def test_list_incidents_rejects_negative_paging(repo: IncidentRepository) -> None:
    with pytest.raises(InvalidInputError):
        repo.list_incidents(limit=-1)
    with pytest.raises(InvalidInputError):
        repo.list_incidents(offset=-1)


def test_all_incidents_shows_every_attempt(
    repo: IncidentRepository, make_incident, make_attempt
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    repo.record_attempt(incident.incident_id, make_attempt(incident), at=BASE_TIME)
    repo.record_attempt(
        incident.incident_id,
        make_attempt(incident, attempt_id="attempt-2"),
        at=BASE_TIME + timedelta(minutes=5),
    )

    stored = repo.all_incidents()[0]
    assert [a.attempt_id for a in stored.attempts] == ["attempt-1", "attempt-2"]


def test_delete_incident_is_explicit(repo: IncidentRepository, make_incident) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)

    assert repo.delete_incident(incident.incident_id) is True
    assert repo.delete_incident(incident.incident_id) is False
    assert repo.get_incident(incident.incident_id) is None
    assert repo.count_incidents() == 0


def test_operations_on_a_missing_incident_raise(
    repo: IncidentRepository, make_diagnosis, make_incident, make_attempt, make_validation
) -> None:
    incident = make_incident()
    with pytest.raises(PersistenceError, match="does not exist"):
        repo.record_diagnosis(incident.incident_id, make_diagnosis(incident), at=BASE_TIME)
    with pytest.raises(PersistenceError, match="does not exist"):
        repo.record_attempt(incident.incident_id, make_attempt(incident), at=BASE_TIME)
    with pytest.raises(PersistenceError, match="does not exist"):
        repo.record_validation(incident.incident_id, make_validation(incident), at=BASE_TIME)
    with pytest.raises(PersistenceError, match="does not exist"):
        repo.append_transition(
            incident.incident_id, LifecycleState.DIAGNOSING, reason="x", at=BASE_TIME
        )
    with pytest.raises(PersistenceError, match="does not exist"):
        repo.export_json(incident.incident_id)


def test_child_data_belonging_to_another_incident_is_refused(
    repo: IncidentRepository, make_incident, make_attempt
) -> None:
    incident = make_incident()
    other = make_incident(run_id="other")
    repo.upsert_incident(incident)

    with pytest.raises(InvalidInputError, match="but was supplied for"):
        repo.record_attempt(other.incident_id, make_attempt(incident), at=BASE_TIME)


# -- redaction and safety -----------------------------------------------------


def test_secrets_never_reach_the_database(
    repo: IncidentRepository, make_incident, make_diagnosis
) -> None:
    logs = f"start\nAuthorization: Bearer {LEAKED_BEARER}\nbuild failed\n"
    event = make_incident(logs=logs).event
    incident = make_incident(event=event)
    diagnosis = make_diagnosis(
        incident,
        probable_cause=f"credential {LEAKED_VALUE} was rejected",
        evidence=[],
    )

    repo.upsert_incident(incident)
    repo.record_diagnosis(incident.incident_id, diagnosis, at=BASE_TIME)

    payload = repo.conn.execute("SELECT payload FROM incidents").fetchone()[0]
    assert LEAKED_BEARER not in payload
    assert LEAKED_VALUE not in payload

    loaded = repo.get_incident(incident.incident_id)
    assert loaded is not None
    assert LEAKED_BEARER not in loaded.event.logs
    assert "[REDACTED]" in loaded.event.logs
    assert LEAKED_BEARER in incident.event.logs
    assert LEAKED_VALUE in diagnosis.probable_cause
    assert LEAKED_VALUE not in loaded.diagnoses[0].probable_cause


def test_every_free_text_field_is_redacted(
    repo: IncidentRepository, make_incident, make_attempt, make_validation
) -> None:
    incident = make_incident(logs=f"logs {LEAKED_VALUE}\n")
    repo.upsert_incident(incident)
    repo.record_attempt(
        incident.incident_id,
        make_attempt(
            incident,
            summary=f"summary {LEAKED_VALUE}",
            rationale=f"rationale {LEAKED_VALUE}",
            patch_unified_diff=f"--- a/x\n+++ b/x\n@@ -1 +1 @@\n-{LEAKED_VALUE}\n+ok\n",
        ),
        at=BASE_TIME,
    )
    repo.record_validation(
        incident.incident_id,
        make_validation(
            incident,
            summary=f"summary {LEAKED_VALUE}",
            checks_executed=[
                CheckResult(
                    name="pytest",
                    command=["pytest", "-q"],
                    status=CheckStatus.PASSED,
                    exit_code=0,
                    stdout_excerpt=f"stdout {LEAKED_VALUE}",
                    stderr_excerpt=f"stderr {LEAKED_VALUE}",
                )
            ],
            execution=make_validation(incident).execution.__class__(
                isolation_kind="local-subprocess",
                limitations=[f"limited by {LEAKED_VALUE}"],
            ),
        ),
        at=BASE_TIME,
    )
    repo.append_transition(
        incident.incident_id,
        LifecycleState.REQUIRES_HUMAN_REVIEW,
        reason=f"needs review because {LEAKED_VALUE}",
        at=BASE_TIME,
    )

    payload = repo.conn.execute("SELECT payload FROM incidents").fetchone()[0]
    assert LEAKED_VALUE not in payload

    loaded = repo.get_incident(incident.incident_id)
    assert loaded is not None
    assert LEAKED_VALUE not in loaded.event.logs
    assert LEAKED_VALUE not in loaded.attempts[0].summary
    assert LEAKED_VALUE not in loaded.attempts[0].rationale
    assert LEAKED_VALUE not in loaded.attempts[0].patch_unified_diff
    assert LEAKED_VALUE not in loaded.validations[0].summary
    assert LEAKED_VALUE not in loaded.validations[0].checks_executed[0].stdout_excerpt
    assert LEAKED_VALUE not in loaded.validations[0].checks_executed[0].stderr_excerpt
    assert LEAKED_VALUE not in loaded.validations[0].execution.limitations[0]
    assert LEAKED_VALUE not in loaded.state_history[-1].reason
    # Identifiers are never redacted: a commit SHA is not a secret.
    assert loaded.event.commit_sha == incident.event.commit_sha
    assert loaded.attempts[0].patch_hash == PATCH_HASH


def test_export_is_redacted(repo: IncidentRepository, make_incident) -> None:
    incident = make_incident(logs=f"logs {LEAKED_VALUE}\n")
    repo.upsert_incident(incident)

    document = repo.export_json(incident.incident_id)

    assert LEAKED_VALUE not in document


# -- lifecycle ----------------------------------------------------------------


def test_illegal_transition_raises_and_writes_nothing(
    repo: IncidentRepository, make_incident
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)

    with pytest.raises(ContractError, match="illegal lifecycle transition"):
        repo.append_transition(
            incident.incident_id, LifecycleState.RECOVERED, reason="jump", at=BASE_TIME
        )
    with pytest.raises(ContractError, match="illegal lifecycle transition"):
        repo.append_transition(
            incident.incident_id, LifecycleState.FAILED, reason="skip", at=BASE_TIME
        )

    stored = repo.get_incident(incident.incident_id)
    assert stored is not None
    assert stored.state is LifecycleState.RECEIVED
    assert stored.state_history == []


def test_recovered_requires_a_passing_validation(
    repo: IncidentRepository, make_incident, make_attempt, make_validation
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    repo.record_attempt(incident.incident_id, make_attempt(incident), at=BASE_TIME)
    # Recording the attempt parks the incident at `remediation_pending`; applying it
    # moves to `remediating`, and only there do checks start.
    repo.append_transition(
        incident.incident_id,
        LifecycleState.REMEDIATING,
        reason="patch staged",
        at=BASE_TIME,
    )
    # Walk to `validating` without recording a result: checks claimed to have started
    # but produced nothing.
    repo.append_transition(
        incident.incident_id,
        LifecycleState.VALIDATING,
        reason="checks started",
        at=BASE_TIME,
    )

    with pytest.raises(ContractError, match="without a validation result"):
        repo.append_transition(
            incident.incident_id, LifecycleState.RECOVERED, reason="sure", at=BASE_TIME
        )

    failing = make_validation(incident, passed=False)
    with pytest.raises(ContractError, match="validation did not pass"):
        repo.append_transition(
            incident.incident_id,
            LifecycleState.RECOVERED,
            reason="sure",
            at=BASE_TIME,
            validation=failing,
        )


def test_recovered_requires_a_validation_bound_to_the_current_patch(
    repo: IncidentRepository, make_incident, make_attempt, make_validation
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    repo.record_attempt(incident.incident_id, make_attempt(incident), at=BASE_TIME)
    repo.append_transition(
        incident.incident_id,
        LifecycleState.REMEDIATING,
        reason="patch staged",
        at=BASE_TIME,
    )
    repo.append_transition(
        incident.incident_id,
        LifecycleState.VALIDATING,
        reason="checks started",
        at=BASE_TIME,
    )
    stale = make_validation(incident, candidate_patch_hash=OTHER_PATCH_HASH)

    with pytest.raises(ContractError, match="stale"):
        repo.append_transition(
            incident.incident_id,
            LifecycleState.RECOVERED,
            reason="sure",
            at=BASE_TIME,
            validation=stale,
        )

    unbound = make_validation(incident, candidate_patch_hash=None)
    with pytest.raises(ContractError, match="not bound"):
        repo.append_transition(
            incident.incident_id,
            LifecycleState.RECOVERED,
            reason="sure",
            at=BASE_TIME,
            validation=unbound,
        )

    stored = repo.get_incident(incident.incident_id)
    assert stored is not None
    assert stored.state is LifecycleState.VALIDATING


def test_recovery_is_reachable_with_a_passing_bound_validation(
    repo: IncidentRepository, make_incident, make_attempt, make_validation
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    repo.record_attempt(incident.incident_id, make_attempt(incident), at=BASE_TIME)
    validation = make_validation(incident)
    recorded = repo.record_validation(incident.incident_id, validation, at=BASE_TIME)

    recovered = repo.append_transition(
        incident.incident_id,
        LifecycleState.RECOVERED,
        reason="every required check passed for the current patch",
        at=BASE_TIME,
        validation=validation,
    )

    assert recovered.state is LifecycleState.RECOVERED
    assert recovered.state_history[-1].to_state is LifecycleState.RECOVERED
    assert recovered.state_history[-1].from_state is LifecycleState.VALIDATING
    assert len(recovered.state_history) == len(recorded.state_history) + 1

    reloaded = repo.get_incident(incident.incident_id)
    assert reloaded is not None
    assert reloaded.model_dump() == recovered.model_dump()
    assert repo.count_incidents(state=LifecycleState.RECOVERED) == 1


def test_recording_data_walks_the_incident_forward_through_legal_states(
    repo: IncidentRepository, make_incident, make_diagnosis, make_attempt, make_validation
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    assert incident.state is LifecycleState.RECEIVED

    diagnosed = repo.record_diagnosis(incident.incident_id, make_diagnosis(incident), at=BASE_TIME)
    assert diagnosed.state is LifecycleState.DIAGNOSED
    assert [t.to_state for t in diagnosed.state_history] == [
        LifecycleState.DIAGNOSING,
        LifecycleState.DIAGNOSED,
    ]

    attempted = repo.record_attempt(incident.incident_id, make_attempt(incident), at=BASE_TIME)
    assert attempted.state is LifecycleState.REMEDIATION_PENDING

    validated = repo.record_validation(
        incident.incident_id, make_validation(incident), at=BASE_TIME
    )
    assert validated.state is LifecycleState.VALIDATING
    assert len(validated.state_history) == 5


def test_terminal_states_are_not_moved_by_later_writes(
    repo: IncidentRepository, make_incident, make_diagnosis
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    repo.append_transition(
        incident.incident_id, LifecycleState.DIAGNOSING, reason="start", at=BASE_TIME
    )
    repo.append_transition(
        incident.incident_id, LifecycleState.DIAGNOSED, reason="done", at=BASE_TIME
    )
    repo.append_transition(
        incident.incident_id,
        LifecycleState.REQUIRES_HUMAN_REVIEW,
        reason="needs a human",
        at=BASE_TIME,
    )

    stored = repo.record_diagnosis(incident.incident_id, make_diagnosis(incident), at=BASE_TIME)
    assert stored.state is LifecycleState.REQUIRES_HUMAN_REVIEW
    assert len(stored.diagnoses) == 1


def test_retry_from_failed_keeps_history(
    repo: IncidentRepository, make_incident, make_diagnosis
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    # First pass: diagnose, then walk the incident into a failed remediation.
    repo.record_diagnosis(incident.incident_id, make_diagnosis(incident), at=BASE_TIME)
    repo.append_transition(
        incident.incident_id,
        LifecycleState.REMEDIATION_PENDING,
        reason="proposal",
        at=BASE_TIME,
    )
    repo.append_transition(
        incident.incident_id, LifecycleState.REMEDIATING, reason="applied", at=BASE_TIME
    )
    repo.append_transition(
        incident.incident_id, LifecycleState.FAILED, reason="validation failed", at=BASE_TIME
    )

    retried = repo.record_diagnosis(
        incident.incident_id,
        make_diagnosis(incident, probable_cause="second look"),
        at=BASE_TIME,
    )
    assert retried.state is LifecycleState.DIAGNOSED
    # FAILED -> DIAGNOSING -> DIAGNOSED: a retry is recorded, never rewritten.
    assert len(retried.state_history) == 7
    assert [d.probable_cause for d in retried.diagnoses] == [
        "the assertion no longer matches the expected total",
        "second look",
    ]


# -- transactional writes -----------------------------------------------------


def test_a_failed_write_leaves_the_incident_unchanged(
    repo: IncidentRepository, make_incident, make_diagnosis
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    repo.record_diagnosis(incident.incident_id, make_diagnosis(incident), at=BASE_TIME)
    before = repo.get_incident(incident.incident_id)

    # A trigger makes SQLite itself refuse the UPDATE halfway through the write.
    repo.conn.execute(
        "CREATE TRIGGER block_update BEFORE UPDATE ON incidents "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
    )
    with pytest.raises(PersistenceError):
        repo.record_diagnosis(
            incident.incident_id,
            make_diagnosis(incident, probable_cause="should not be stored"),
            at=BASE_TIME,
        )

    after = repo.get_incident(incident.incident_id)
    assert after is not None
    assert after.model_dump() == before.model_dump()
    assert len(after.diagnoses) == 1
    assert (
        "should not be stored"
        not in repo.conn.execute("SELECT payload FROM incidents").fetchone()[0]
    )

    # The store still works once the obstruction is gone.
    repo.conn.execute("DROP TRIGGER block_update")
    repo.record_diagnosis(
        incident.incident_id,
        make_diagnosis(incident, probable_cause="now it works"),
        at=BASE_TIME,
    )
    final = repo.get_incident(incident.incident_id)
    assert final is not None
    assert final.diagnoses[-1].probable_cause == "now it works"


def test_a_failed_transition_leaves_nothing_behind(repo: IncidentRepository, make_incident) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    before = repo.conn.execute("SELECT payload FROM incidents").fetchone()[0]

    repo.conn.execute(
        "CREATE TRIGGER block_update BEFORE UPDATE ON incidents "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
    )
    with pytest.raises(ContractError, match="illegal lifecycle transition"):
        repo.append_transition(
            incident.incident_id, LifecycleState.RECOVERED, reason="nope", at=BASE_TIME
        )
    assert repo.conn.execute("SELECT payload FROM incidents").fetchone()[0] == before


# -- schema versioning --------------------------------------------------------


def test_an_unknown_contract_version_is_refused_rather_than_guessed(
    repo: IncidentRepository, make_incident
) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    repo.conn.execute(
        "UPDATE incidents SET schema_version = '9.9.9' WHERE incident_id = ?",
        (incident.incident_id,),
    )

    with pytest.raises(PersistenceError, match="contract schema version"):
        repo.get_incident(incident.incident_id)


def test_payload_records_the_contract_version(repo: IncidentRepository, make_incident) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)

    row = repo.conn.execute(
        "SELECT schema_version, created_at, updated_at, event_timestamp, state FROM incidents"
    ).fetchone()
    assert row[0] == incident.schema_version
    assert row[1] == BASE_TIME.isoformat()
    assert row[2] == BASE_TIME.isoformat()
    assert row[3] == BASE_TIME.isoformat()
    assert row[4] == LifecycleState.RECEIVED.value


# -- database helpers ---------------------------------------------------------


def test_connect_configures_wal_and_foreign_keys(db_path) -> None:
    conn = connect(db_path)
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        conn.close()


def test_connect_without_create_refuses_a_missing_database(db_path) -> None:
    with pytest.raises(PersistenceError, match="does not exist"):
        connect(db_path, create=False)


def test_db_info_reports_version_counts_and_size(db_path, repo, make_incident) -> None:
    incident = make_incident()
    repo.upsert_incident(incident)
    repo.append_transition(
        incident.incident_id, LifecycleState.DIAGNOSING, reason="start", at=BASE_TIME
    )

    info = db_info(db_path)

    assert info["exists"] is True
    assert info["schema_version"] == 2
    assert info["latest_schema_version"] == 2
    assert info["pending_migrations"] == []
    assert info["incidents"] == 1
    assert info["by_state"] == {"diagnosing": 1}
    assert info["file_size_bytes"] > 0


def test_db_info_on_a_missing_database_does_not_create_it(db_path) -> None:
    info = db_info(db_path)

    assert info["exists"] is False
    assert info["schema_version"] == 0
    assert info["incidents"] == 0
    assert info["pending_migrations"] == [1, 2]
    assert db_path.exists() is False


def test_repository_is_a_context_manager(db_path, make_incident) -> None:
    with IncidentRepository(db_path) as repo:
        repo.upsert_incident(make_incident())
    with pytest.raises(PersistenceError, match="repository is closed"):
        _ = repo.conn  # reading the property is the whole assertion


def test_db_info_reports_every_state(db_path, repo, make_incident) -> None:
    repo.upsert_incident(make_incident(run_id="1"))
    repo.upsert_incident(make_incident(run_id="2"))

    assert db_info(db_path)["by_state"] == {"received": 2}
