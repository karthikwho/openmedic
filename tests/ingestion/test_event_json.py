"""Behavioural tests for ``FailureEvent`` JSON ingestion and serialisation.

The round trip is the core guarantee: :func:`dump_event_json` output must be
accepted by :func:`ingest_event_json` and reproduce the same event, so a stored or
transported payload can never quietly change meaning. Everything that breaks the
contract — malformed JSON, unknown fields, a timezone-naive timestamp — must be
rejected with a message that names the problem.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from openmedic.domain import FailureEvent, FailureType, InvalidInputError
from openmedic.ingestion import (
    KNOWN_FIELDS,
    dump_event_json,
    ingest_event_json,
    parse_event_dict,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def read_fixture(name: str) -> str:
    """Return the raw text of a committed fixture inside this test package."""
    path = FIXTURE_DIR / name
    assert path.is_file(), f"missing committed fixture: {path}"
    return path.read_text(encoding="utf-8")


def load_payload(name: str) -> dict[str, Any]:
    """Return a committed fixture decoded as a JSON object."""
    return json.loads(read_fixture(name))


# --------------------------------------------------------------------------- #
# Round trip
# --------------------------------------------------------------------------- #


def test_round_trip_preserves_every_field() -> None:
    """``ingest_event_json(dump_event_json(event))`` reproduces the event exactly."""
    event = ingest_event_json(read_fixture("valid_event.json"))
    assert event.logs, "a fixture with no evidence would make the test meaningless"
    assert ingest_event_json(dump_event_json(event)) == event


def test_round_trip_preserves_an_explicit_incident_id() -> None:
    """A caller-assigned incident id must not be re-derived or lost."""
    event = ingest_event_json(read_fixture("valid_event.json"))
    titled = event.model_copy(update={"incident_id": "inc-manual-0001"})
    assert titled.incident_id == "inc-manual-0001"
    assert ingest_event_json(dump_event_json(titled)) == titled


def test_round_trip_preserves_a_non_utc_offset() -> None:
    """An instant expressed with a non-zero offset survives as the same instant."""
    event = ingest_event_json(read_fixture("valid_event.json"))
    shifted = event.model_copy(
        update={"timestamp": datetime(2026, 10, 5, 11, 14, 22, tzinfo=timezone(timedelta(hours=2)))}
    )
    assert ingest_event_json(dump_event_json(shifted)) == shifted


def test_dumped_json_is_a_stable_canonical_form() -> None:
    """The dump is deterministic and byte-identical across runs."""
    event = ingest_event_json(read_fixture("valid_event.json"))
    first = dump_event_json(event)
    assert dump_event_json(event) == first
    assert first.endswith("\n")
    assert json.loads(first) == event.to_dict()


def test_valid_fixture_is_exactly_the_canonical_dump() -> None:
    """The committed fixture is a real ``dump_event_json`` output, not a hand-written shape."""
    text = read_fixture("valid_event.json")
    assert dump_event_json(ingest_event_json(text)) == text


def test_valid_fixture_ingests_with_expected_fields() -> None:
    """The committed fixture carries the full failure-event field set."""
    event = ingest_event_json(read_fixture("valid_event.json"))
    assert event.schema_version == "1.0.0"
    assert event.repository == "acme/openmedic"
    assert event.commit_sha == "9f2c1ab4d5e6f7089a0b1c2d3e4f5061728394a5"
    assert event.workflow_name == "ci"
    assert event.run_id == "182736451"
    assert event.failed_step == "Run pytest -q tests/test_lifecycle.py"
    assert event.job_name == "test-suite (ubuntu-latest)"
    assert event.failure_type is FailureType.TEST_FAILURE
    assert "FAILED tests/test_lifecycle.py::test_retry_appends_attempt" in event.logs
    assert event.timestamp == datetime(2026, 10, 5, 9, 14, 22, tzinfo=UTC)
    assert event.resolved_incident_id.startswith("inc-")
    assert event.incident_id is None


# --------------------------------------------------------------------------- #
# Rejection: structure
# --------------------------------------------------------------------------- #


def test_malformed_json_is_rejected() -> None:
    """A truncated payload is a syntax error the caller can fix."""
    for payload in ("{", "not json at all", '{"logs": ', "[1, 2"):
        with pytest.raises(InvalidInputError) as excinfo:
            ingest_event_json(payload)
        assert excinfo.value.message.strip()
        assert "JSON" in excinfo.value.message


def test_empty_input_is_rejected() -> None:
    """Nothing to parse is a caller error, not an empty event."""
    for payload in ("", "   \n  ", b""):
        with pytest.raises(InvalidInputError) as excinfo:
            ingest_event_json(payload)
        assert excinfo.value.message.strip()


@pytest.mark.parametrize("payload", ["[]", '"a log line"', "42", "null", "true"])
def test_non_object_payloads_are_rejected(payload: str) -> None:
    """A bare list/scalar is not an event payload."""
    with pytest.raises(InvalidInputError) as excinfo:
        ingest_event_json(payload)
    assert "object" in excinfo.value.message


def test_payload_without_logs_is_rejected() -> None:
    """Evidence-less events cannot be diagnosed, so they never enter the pipeline."""
    payload = {"repository": "acme/openmedic", "timestamp": "2026-10-05T09:14:22Z"}
    with pytest.raises(InvalidInputError) as excinfo:
        parse_event_dict(payload)
    assert "logs" in excinfo.value.message


def test_malformed_json_error_reports_the_location() -> None:
    """Line and column information is what lets a user fix the file."""
    with pytest.raises(InvalidInputError) as excinfo:
        ingest_event_json('{\n  "logs": oops,\n}')
    assert "line 2" in excinfo.value.message


# --------------------------------------------------------------------------- #
# Rejection: fields
# --------------------------------------------------------------------------- #


def test_unknown_field_is_rejected_and_named() -> None:
    """The rejecting message must name every field that is not part of the contract."""
    with pytest.raises(InvalidInputError) as excinfo:
        parse_event_dict(
            {
                "logs": "FAILED tests/test_a.py::test_b\n",
                "timestamp": "2026-10-05T09:14:22Z",
                "source_path": "/var/log/ci.log",
            }
        )
    assert "source_path" in excinfo.value.message
    assert "logs" in list(KNOWN_FIELDS)


def test_unknown_field_rejection_names_every_offender() -> None:
    """All offending keys are reported at once rather than one per round trip."""
    with pytest.raises(InvalidInputError) as excinfo:
        parse_event_dict(
            {
                "logs": "FAILED tests/test_a.py::test_b\n",
                "timestamp": "2026-10-05T09:14:22Z",
                "job": "test-suite",
                "severity": "high",
            }
        )
    assert "job" in excinfo.value.message
    assert "severity" in excinfo.value.message


def test_invalid_event_fixture_is_rejected_for_a_naive_timestamp() -> None:
    """The committed invalid fixture is missing its UTC offset."""
    with pytest.raises(InvalidInputError) as excinfo:
        ingest_event_json(read_fixture("invalid_event.json"))
    assert "timezone-naive" in excinfo.value.message
    assert "API_CONTRACTS.md" in excinfo.value.message


def test_naive_datetime_object_is_rejected() -> None:
    """A naive ``datetime`` is refused even when it never went through JSON."""
    with pytest.raises(InvalidInputError) as excinfo:
        payload = {"logs": "FAILED tests/test_a.py::test_b\n", "timestamp": datetime(2026, 10, 5)}
        parse_event_dict(payload)
    assert "timezone-naive" in excinfo.value.message


@pytest.mark.parametrize("stamp", ["not-a-timestamp", "2026-13-45T99:00:00Z", "05/10/2026 09:14"])
def test_unparseable_timestamp_is_rejected(stamp: str) -> None:
    """A timestamp that cannot be parsed is reported as such, not as a naive one."""
    with pytest.raises(InvalidInputError) as excinfo:
        parse_event_dict({"logs": "FAILED tests/test_a.py::test_b\n", "timestamp": stamp})
    assert "timestamp" in excinfo.value.message


def test_timestamp_of_the_wrong_type_is_rejected() -> None:
    """Epoch numbers and booleans are ambiguous; demand an ISO-8601 string."""
    with pytest.raises(InvalidInputError) as excinfo:
        parse_event_dict({"logs": "FAILED tests/test_a.py::test_b\n", "timestamp": 1_797_000_000})
    assert "timestamp" in excinfo.value.message


def test_unknown_failure_type_is_rejected_with_the_valid_values() -> None:
    """The error lists the locked enum values so the fix is obvious."""
    with pytest.raises(InvalidInputError) as excinfo:
        parse_event_dict(
            {
                "logs": "FAILED tests/test_a.py::test_b\n",
                "timestamp": "2026-10-05T09:14:22Z",
                "failure_type": "flaky_network",
            }
        )
    for value in (candidate.value for candidate in FailureType):
        assert value in excinfo.value.message


def test_failure_type_accepts_the_enum_member_directly() -> None:
    """Programmatic payloads may pass an already-validated enum member."""
    payload = {
        "logs": "FAILED tests/test_a.py::test_b\n",
        "timestamp": datetime(2026, 10, 5, 9, 14, 22, tzinfo=UTC),
        "failure_type": FailureType.TEST_FAILURE,
    }
    event = parse_event_dict(payload)
    assert event.failure_type is FailureType.TEST_FAILURE


def test_invalid_contract_value_is_reported_without_log_content() -> None:
    """A contract violation names the field but never dumps the raw log into the message."""
    with pytest.raises(InvalidInputError) as excinfo:
        parse_event_dict(
            {
                "logs": "FAILED tests/test_a.py::test_b\n",
                "timestamp": "2026-10-05T09:14:22Z",
                "run_id": ["not", "a", "string"],
            }
        )
    assert "run_id" in excinfo.value.message
    assert "FAILED tests" not in excinfo.value.message


# --------------------------------------------------------------------------- #
# Payload handling
# --------------------------------------------------------------------------- #


def test_incident_id_may_be_null_or_absent() -> None:
    """Derivation happens in the model, so ingestion accepts both spellings."""
    for payload in (
        {
            "logs": "FAILED tests/test_a.py::test_b\n",
            "timestamp": "2026-10-05T09:14:22Z",
            "incident_id": None,
        },
        {"logs": "FAILED tests/test_a.py::test_b\n", "timestamp": "2026-10-05T09:14:22Z"},
    ):
        event = parse_event_dict(payload)
    assert event.incident_id is None
    assert event.resolved_incident_id == event.model_copy(update={}).resolved_incident_id


def test_minimal_payload_uses_the_contract_defaults() -> None:
    """Only ``logs`` and ``timestamp`` are required; the rest has defaults."""
    event = parse_event_dict(
        {
            "logs": "collected 4 items\nendpoint /health returned 200\n",
            "timestamp": "2026-10-05T09:14:22Z",
        }
    )
    assert event.failure_type is FailureType.UNKNOWN
    assert event.repository is None
    assert event.schema_version == "1.0.0"


def test_absent_failure_type_is_derived_from_the_logs() -> None:
    """A payload that omits the type classifies the same way a raw log would."""
    payload = {
        "logs": "FAILED tests/test_a.py::test_b - AssertionError\n",
        "timestamp": "2026-10-05T09:14:22Z",
    }
    assert parse_event_dict(payload).failure_type is FailureType.TEST_FAILURE


def test_explicit_unknown_failure_type_is_respected() -> None:
    """An explicit claim is the producer's, even when the logs look classifiable."""
    payload = {
        "logs": "FAILED tests/test_a.py::test_b - AssertionError\n",
        "timestamp": "2026-10-05T09:14:22Z",
        "failure_type": "unknown",
    }
    assert parse_event_dict(payload).failure_type is FailureType.UNKNOWN


def test_bytes_payload_is_accepted() -> None:
    """UTF-8 bytes are the common webhook body form."""
    payload = b'{"logs": "FAILED tests/test_a.py::test_b\\n", "timestamp": "2026-10-05T09:14:22Z"}'
    event = ingest_event_json(payload)
    assert event.failure_type is FailureType.TEST_FAILURE


def test_invalid_utf8_bytes_are_rejected() -> None:
    """Undecodable bytes are refused rather than replaced with replacement characters."""
    with pytest.raises(InvalidInputError) as excinfo:
        ingest_event_json(b'{"logs": "\xff\xfe", "timestamp": "2026-10-05T09:14:22Z"}')
    assert "UTF-8" in excinfo.value.message


def test_parse_event_dict_does_not_mutate_the_input() -> None:
    """The caller's dict is left exactly as it was handed over."""
    payload = {
        "logs": "FAILED tests/test_a.py::test_b\n",
        "timestamp": "2026-10-05T09:14:22Z",
        "failure_type": "test_failure",
    }
    snapshot = dict(payload)
    parse_event_dict(payload)
    assert payload == snapshot


def test_non_mapping_payload_is_rejected() -> None:
    """``parse_event_dict`` is only ever given a mapping."""
    with pytest.raises(InvalidInputError) as excinfo:
        parse_event_dict(["logs", "timestamp"])  # type: ignore[arg-type]
    assert "object" in excinfo.value.message


def test_dump_event_json_rejects_a_non_event() -> None:
    """Dumping something that is not an event is a caller error, not a silent "{}"."""
    with pytest.raises(InvalidInputError) as excinfo:
        dump_event_json({"logs": "x\n"})  # type: ignore[arg-type]
    assert "FailureEvent" in excinfo.value.message


def test_known_fields_matches_the_contract() -> None:
    """The exported field list is exactly the model's field set, in contract order."""
    assert list(KNOWN_FIELDS) == list(FailureEvent.model_fields)
    assert "timestamp" in KNOWN_FIELDS
    assert "logs" in KNOWN_FIELDS
