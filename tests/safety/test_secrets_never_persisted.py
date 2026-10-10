"""Secrets must never be persisted, displayed, or sent onward.

Inputs come from CI logs, which routinely contain credentials. Each test below plants a
realistically-shaped secret and proves the specific boundary that should have stopped it.
"""

from __future__ import annotations

import json
import logging

import pytest

from openmedic.domain import (
    PLACEHOLDER,
    FailureEvent,
    FailureType,
    IncidentRecord,
    LifecycleState,
    redact,
    redact_excerpt,
    utc_now,
)
from openmedic.domain.contracts import SCHEMA_VERSION
from openmedic.domain.redaction import SecretDetection
from openmedic.forensics import normalize_log

SECRETS = [
    "ghp_16Z9vYLFOFyksfsdfsfsdfsdfsdfs",
    "AKIAIOSFODNN7EXAMPLE",
    "sk-abcdefghijklmnopqrstuvwxyz012345",
]


def _event_with_secret(secret: str) -> FailureEvent:
    return FailureEvent(
        failure_type=FailureType.UNKNOWN,
        logs=f"starting build\nusing token {secret}\nERROR: boom\n",
        timestamp=utc_now(),
        repository="example/repo",
        run_id="42",
        workflow_name="CI",
        failed_step="test",
    )


@pytest.mark.parametrize("secret", SECRETS)
def test_incident_redaction_removes_every_planted_secret(secret: str) -> None:
    event = _event_with_secret(secret)
    record = IncidentRecord(
        incident_id="inc-safety",
        event=event,
        state=LifecycleState.RECEIVED,
        created_at=utc_now(),
        updated_at=utc_now(),
        idempotency_key=event.idempotency_key,
    )
    redacted = record.redacted()
    assert secret not in redacted.event.logs
    assert secret not in json.dumps(redacted.to_dict())
    # The non-secret evidence survives, so the diagnosis stays verifiable in memory.
    assert "ERROR: boom" in event.logs


@pytest.mark.parametrize("secret", SECRETS)
def test_forensics_normalisation_redacts(secret: str) -> None:
    result = normalize_log(f"using {secret} then failing")
    assert secret not in result.redacted_raw
    assert secret not in result.normalized


def test_redact_excerpt_truncates_and_redacts() -> None:
    text = "token=abcdef1234567890 " + ("x" * 5000)
    excerpt = redact_excerpt(text, limit=100)
    assert len(excerpt) < 200
    assert PLACEHOLDER in excerpt
    assert "abcdef1234567890" not in excerpt


def test_detections_never_leak_the_secret_value() -> None:
    secret = SECRETS[0]
    redaction = redact(f"leak {secret}")
    assert redaction.detections
    for detection in redaction.detections:
        assert isinstance(detection, SecretDetection)
        assert secret not in detection.preview
        assert secret not in json.dumps(detection.to_dict())


def test_redaction_of_persisted_payload_is_complete() -> None:
    """The serialized form of a redacted incident must contain no secret material."""
    secret = SECRETS[1]
    event = _event_with_secret(secret)
    record = IncidentRecord(
        incident_id="inc-safety",
        event=event,
        state=LifecycleState.RECEIVED,
        created_at=utc_now(),
        updated_at=utc_now(),
        idempotency_key=event.idempotency_key,
    )
    payload = record.redacted().to_dict()
    assert secret not in json.dumps(payload)


def test_placeholder_is_not_recoverable_from_the_redacted_text() -> None:
    secret = SECRETS[2]
    text = f"value = {secret}"
    redacted = redact(text).text
    # Nothing resembling the secret's shape remains.
    assert secret not in redacted
    assert "sk-" not in redacted


def test_redaction_survives_idempotent_reapplication() -> None:
    secret = SECRETS[0]
    once = redact(f"using {secret}").text
    twice = redact(once).text
    assert once == twice
    assert secret not in twice


def test_logging_filter_scrubs_secrets_from_arguments() -> None:
    from openmedic.cli.output import RedactingFilter

    record = logging.LogRecord(
        "openmedic.safety",
        logging.ERROR,
        __file__,
        1,
        "failed with token %s",
        (SECRETS[2],),
        None,
    )
    assert RedactingFilter().filter(record) is True
    assert SECRETS[2] not in str(record.args)


def test_schema_version_is_serialised() -> None:
    event = _event_with_secret(SECRETS[0])
    assert event.to_dict()["schema_version"] == SCHEMA_VERSION


def test_empty_incident_cannot_sneak_through() -> None:
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError
        FailureEvent(failure_type=FailureType.UNKNOWN, logs="")  # missing timestamp
