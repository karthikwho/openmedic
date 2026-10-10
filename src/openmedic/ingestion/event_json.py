"""FailureEvent JSON ingestion and serialisation.

Two directions, one shape:

* :func:`ingest_event_json` / :func:`parse_event_dict` accept untrusted payloads
  (CLI argument, file, webhook body, test fixture) and turn them into a validated
  :class:`~openmedic.domain.FailureEvent`.
* :func:`dump_event_json` emits the canonical JSON for a validated event, so
  ``ingest_event_json(dump_event_json(event))`` round-trips.

Validation is deliberately *opinionated about clarity*: every rejection names the
offending field and the rule it broke, because "invalid input" with no reason is
not an actionable error for a CLI user or a colleague debugging a fixture.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Final

from pydantic import ValidationError

from ..domain import ContractError, FailureEvent, FailureType, InvalidInputError
from .logfile import classify_log_text

#: The complete, ordered set of fields a ``FailureEvent`` payload may carry.
#: ``FailureEvent`` forbids extras; this tuple exists so an unknown field can be
#: named in the error instead of being reported as an anonymous schema failure.
KNOWN_FIELDS: Final[tuple[str, ...]] = tuple(FailureEvent.model_fields)

#: Fields that are required in an inbound payload even though the model gives them
#: a default, because an event without them is not evidence of anything.
_REQUIRED_FIELDS: Final[tuple[str, ...]] = ("logs",)


def parse_event_dict(data: dict) -> FailureEvent:
    """Validate and normalise a ``FailureEvent`` payload held as a mapping.

    Unknown fields, non-ISO timestamps, timezone-naive timestamps, and unknown
    ``failure_type`` values are rejected with :class:`InvalidInputError`. The
    ``incident_id`` may be absent or ``null`` — the model derives a stable id
    from the idempotency key in that case. The input mapping is never mutated.
    """
    if not isinstance(data, dict):
        msg = f"event payload must be a JSON object (mapping), got {type(data).__name__}"
        raise InvalidInputError(msg)

    payload = dict(data)
    _reject_unknown_fields(payload)
    _reject_missing_required(payload)
    _normalize_timestamp(payload)
    _normalize_failure_type(payload)

    try:
        return FailureEvent(**payload)
    except (ValidationError, ContractError) as exc:
        msg = f"event payload failed FailureEvent validation: {_describe(exc)}"
        raise InvalidInputError(msg, detail=_detail_of(exc)) from exc


def ingest_event_json(text: str | bytes) -> FailureEvent:
    """Parse a ``FailureEvent`` from JSON text (or UTF-8 bytes).

    Empty input, malformed JSON, and JSON that does not decode to an object all
    raise :class:`InvalidInputError`. Anything that decodes is validated by
    :func:`parse_event_dict`.
    """
    payload = _decode_json(text)
    return parse_event_dict(payload)


def dump_event_json(event: FailureEvent) -> str:
    """Serialise ``event`` to canonical JSON that :func:`ingest_event_json` round-trips."""
    if not isinstance(event, FailureEvent):
        msg = f"dump_event_json expects a FailureEvent, got {type(event).__name__}"
        raise InvalidInputError(msg)
    return json.dumps(event.to_dict(), indent=2, ensure_ascii=False) + "\n"


def _decode_json(text: str | bytes) -> dict[str, Any]:
    """Decode ``text`` into a JSON object, rejecting every alternative explicitly."""
    if isinstance(text, bytes | bytearray):
        try:
            text = bytes(text).decode("utf-8")
        except UnicodeDecodeError as exc:
            msg = f"event payload is not valid UTF-8: {exc}"
            raise InvalidInputError(msg) from exc
    if not isinstance(text, str):
        msg = f"event payload must be str or bytes, got {type(text).__name__}"
        raise InvalidInputError(msg)
    if not text.strip():
        msg = "event payload is empty; expected a JSON object describing a FailureEvent"
        raise InvalidInputError(msg)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"event payload is not valid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}"
        raise InvalidInputError(msg) from exc
    if not isinstance(data, dict):
        msg = f"event payload must decode to a JSON object, got {type(data).__name__}"
        raise InvalidInputError(msg)
    return data


def _reject_unknown_fields(payload: dict[str, Any]) -> None:
    """Reject any key outside :data:`KNOWN_FIELDS`, naming each offender."""
    unknown = [key for key in payload if key not in KNOWN_FIELDS]
    if not unknown:
        return
    msg = (
        f"unknown field(s) {sorted(unknown)!r}; FailureEvent accepts only "
        f"{list(KNOWN_FIELDS)} (docs/API_CONTRACTS.md section 2)"
    )
    raise InvalidInputError(msg)


def _reject_missing_required(payload: dict[str, Any]) -> None:
    """Reject a payload that carries no evidence to diagnose."""
    missing = [name for name in _REQUIRED_FIELDS if name not in payload]
    if missing:
        msg = f"missing required field(s) {missing!r}; a FailureEvent must carry raw logs"
        raise InvalidInputError(msg)


def _normalize_timestamp(payload: dict[str, Any]) -> None:
    """Replace the payload timestamp with a validated, timezone-aware datetime."""
    if "timestamp" not in payload:
        return
    value = payload["timestamp"]
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            msg = (
                f"timestamp {value!r} is not a valid ISO-8601 timestamp "
                f"(docs/API_CONTRACTS.md section 1): {exc}"
            )
            raise InvalidInputError(msg) from exc
    else:
        msg = (
            f"timestamp must be an ISO-8601 string, got "
            f"{type(value).__name__} (docs/API_CONTRACTS.md section 1)"
        )
        raise InvalidInputError(msg)
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        msg = (
            f"timestamp {value!r} is timezone-naive; every FailureEvent timestamp must "
            "carry an explicit UTC offset such as 'Z' or '+00:00' "
            "(docs/API_CONTRACTS.md section 1, 'All timestamps are timezone-aware')"
        )
        raise InvalidInputError(msg)
    payload["timestamp"] = parsed


def _normalize_failure_type(payload: dict[str, Any]) -> None:
    """Validate or derive ``failure_type``, listing valid values on failure.

    A payload that *omits* the field is classified from its logs, because ingesting
    the same run as a raw log classifies it heuristically: two transports of one
    event must not disagree about its failure type. An explicit value — including
    an explicit ``unknown`` — is the producer's claim and is respected.
    """
    if "failure_type" not in payload:
        logs = payload.get("logs")
        payload["failure_type"] = (
            classify_log_text(logs) if isinstance(logs, str) else FailureType.UNKNOWN
        )
        return
    value = payload["failure_type"]
    if isinstance(value, FailureType):
        return
    if isinstance(value, str):
        try:
            payload["failure_type"] = FailureType(value)
        except ValueError:
            msg = (
                f"unknown failure_type {value!r}; expected one of "
                f"{[candidate.value for candidate in FailureType]}"
            )
            raise InvalidInputError(msg) from None
        return
    msg = f"failure_type must be a string, got {type(value).__name__}"
    raise InvalidInputError(msg)


def _describe(exc: Exception) -> str:
    """Summarise a pydantic/contract failure without leaking any log content."""
    if isinstance(exc, ValidationError):
        parts: list[str] = []
        for error in exc.errors():
            location = ".".join(str(item) for item in error.get("loc", ())) or "event"
            parts.append(f"{location}: {error.get('msg', 'invalid')}")
        return "; ".join(parts) if parts else "invalid payload"
    return str(exc)


def _detail_of(exc: Exception) -> str | None:
    """Return the raw validator message as ``detail`` for structured CLI output."""
    return None if isinstance(exc, ValidationError) else str(exc)
