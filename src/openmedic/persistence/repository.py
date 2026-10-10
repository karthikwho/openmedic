"""SQLite repository for the incident aggregate.

The store keeps one row per incident: the whole
:class:`~openmedic.domain.contracts.IncidentRecord` as a JSON payload plus the few
columns needed to query it without deserialising everything (``state``, timestamps, the
idempotency key, and the contract schema version the payload was written with).

Design rules this module enforces:

* **Redaction before persistence.** Free text is redacted with
  :func:`~openmedic.domain.redaction.redact` before it is written, so the database never
  contains a credential. The caller keeps the raw copy in memory for quote verification.
* **One transaction per write.** An incident update and its audit trail land together or
  not at all, so a failed write leaves the incident exactly as it was.
* **Append-only history.** Retries add attempts, validations, and transitions. Nothing is
  overwritten except by an explicit re-save of the same aggregate, and ``updated_at``
  never rewrites ``created_at`` or the incident ID.
* **The lifecycle is the domain's, not the store's.** ``append_transition`` delegates to
  :func:`~openmedic.domain.lifecycle.apply_transition`, so ``recovered`` can only be
  earned by a passing validation bound to the current patch. ``record_diagnosis``,
  ``record_attempt``, and ``record_validation`` additionally walk the incident forward to
  the state that matches the data just recorded — a diagnosis means ``diagnosed``, a
  recorded attempt means ``remediation_pending``, a recorded validation means
  ``validating`` — using only legal transitions; they never invent a state that the
  transition table forbids, and each step is audited with the reason that caused it.

One deviation from the domain layer is worth stating explicitly: ``domain.contracts``
freezes every model, while ``apply_transition`` documents itself as mutating a record in
place. :class:`_MutableIncidentRecord` below removes that freeze so this repository can
reuse the single implementation of the transition rules instead of re-deriving them.
"""

from __future__ import annotations

import json
import sqlite3
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final

from pydantic import ConfigDict, ValidationError

from ..domain.contracts import SCHEMA_VERSION, IncidentRecord
from ..domain.enums import LifecycleState
from ..domain.errors import InvalidInputError, PersistenceError
from ..domain.lifecycle import ALLOWED_TRANSITIONS, TERMINAL_STATES, apply_transition
from ..domain.redaction import redact
from .database import init_db
from .migrations import transaction

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..domain.contracts import (
        DiagnosisResult,
        RemediationAttempt,
        ValidationResult,
    )

_TABLE: Final = "incidents"

_UPSERT: Final = """
INSERT INTO incidents (
    incident_id, idempotency_key, state, schema_version, payload,
    created_at, updated_at, event_timestamp
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (incident_id) DO UPDATE SET
    idempotency_key = excluded.idempotency_key,
    state = excluded.state,
    schema_version = excluded.schema_version,
    payload = excluded.payload,
    updated_at = excluded.updated_at,
    event_timestamp = excluded.event_timestamp
"""

_SELECT: Final = "SELECT incident_id, payload, schema_version FROM incidents"

_COUNT_ALL: Final = "SELECT count(*) FROM incidents"

_COUNT_BY_STATE: Final = "SELECT count(*) FROM incidents WHERE state = ?"

_DELETE: Final = "DELETE FROM incidents WHERE incident_id = ?"


class _MutableIncidentRecord(IncidentRecord):
    """An :class:`IncidentRecord` whose fields may be assigned.

    Only used as the working copy handed to ``apply_transition``; the persisted and
    returned value is always a plain frozen ``IncidentRecord``.
    """

    model_config = ConfigDict(frozen=False)


class IncidentRepository:
    """Durable access to incidents, attempts, validations, and transition history."""

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = init_db(self._db_path)

    @property
    def conn(self) -> sqlite3.Connection:
        """Return the live connection, for diagnostics and tests."""
        if self._conn is None:
            msg = "repository is closed"
            raise PersistenceError(msg)
        return self._conn

    @property
    def db_path(self) -> Path:
        """Return the path of the database this repository reads and writes."""
        return self._db_path

    def __enter__(self) -> IncidentRepository:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying connection. Closing twice is harmless."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # -- ingestion ---------------------------------------------------------

    def upsert_incident(self, record: IncidentRecord) -> IncidentRecord:
        """Persist ``record``, keyed by its incident ID.

        This is the write half of persistence: it stores whatever record it is handed,
        which is how a transition applied in memory reaches the database. It is *not*
        where ingestion decides whether an event is a duplicate — handing it a fresh
        ``RECEIVED`` record for an incident that already has history would overwrite that
        history. ``Services._store`` makes that decision before it gets here. The only
        case this method resolves itself is an idempotency key already bound to a
        different incident, where the stored incident is returned rather than replaced.
        """
        existing = self.find_by_idempotency_key(record.idempotency_key)
        if existing is not None and existing.incident_id != record.incident_id:
            return existing
        return self._save(record)

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        """Return the stored incident, or ``None`` when the ID is unknown."""
        return self._load(incident_id)

    def find_by_idempotency_key(self, key: str) -> IncidentRecord | None:
        """Return the incident produced by the source event with this idempotency key."""
        row = self._select("WHERE idempotency_key = ?", (key,))
        return None if row is None else _decode(row)

    def list_incidents(
        self,
        *,
        state: LifecycleState | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[IncidentRecord]:
        """Return incidents newest first, optionally filtered by lifecycle state.

        "Newest" means most recently updated, which is the order an operator wants from
        ``incidents list``. ``incident_id`` breaks ties so the order is stable across
        calls.
        """
        if limit is not None and limit < 0:
            msg = f"limit must not be negative, got {limit}"
            raise InvalidInputError(msg)
        if offset < 0:
            msg = f"offset must not be negative, got {offset}"
            raise InvalidInputError(msg)

        clauses: list[str] = []
        params: list[object] = []
        if state is not None:
            clauses.append("state = ?")
            params.append(state.value)
        sql = _SELECT
        if clauses:
            sql = f"{sql} WHERE {' AND '.join(clauses)}"
        sql = f"{sql} ORDER BY updated_at DESC, incident_id ASC"
        if limit is not None:
            sql = f"{sql} LIMIT ?"
            params.append(limit)
        if offset > 0:
            sql = f"{sql} LIMIT -1 OFFSET ?" if limit is None else f"{sql} OFFSET ?"
            params.append(offset)
        return [_decode(row) for row in self._rows(sql, tuple(params))]

    def count_incidents(self, *, state: LifecycleState | None = None) -> int:
        """Return how many incidents are stored, optionally per lifecycle state."""
        if state is None:
            return int(self.conn.execute(_COUNT_ALL).fetchone()[0])
        return int(self.conn.execute(_COUNT_BY_STATE, (state.value,)).fetchone()[0])

    def all_incidents(self) -> list[IncidentRecord]:
        """Return every stored incident, newest first. Used by recurrence analysis."""
        return self.list_incidents()

    def delete_incident(self, incident_id: str) -> bool:
        """Delete one incident and all of its history. Explicitly destructive."""
        with transaction(self.conn):
            cursor = self.conn.execute(_DELETE, (incident_id,))
            return cursor.rowcount > 0

    # -- lifecycle and audit ----------------------------------------------

    def record_diagnosis(
        self, incident_id: str, diagnosis: DiagnosisResult, *, at: datetime
    ) -> IncidentRecord:
        """Append a diagnosis and walk the incident to ``diagnosed``.

        The diagnosis is appended to the existing list; an identical diagnosis is not
        recorded twice. The lifecycle state moves only through legal transitions.
        """
        _check_child_id("diagnosis", diagnosis.incident_id, incident_id)
        record = self._require(incident_id)
        updated = _advance(
            _append_diagnosis(record, diagnosis),
            LifecycleState.DIAGNOSED,
            reason=f"diagnosis recorded by rule {diagnosis.rule_id}",
            at=at,
        )
        return self._save(updated)

    def record_attempt(
        self, incident_id: str, attempt: RemediationAttempt, *, at: datetime
    ) -> IncidentRecord:
        """Append a remediation attempt and walk the incident to ``remediation_pending``.

        Recording an attempt says a candidate patch now exists; it does not say anything
        has been applied, so the incident rests at ``remediation_pending`` — the state
        that ``docs/ARCHITECTURE.md`` section 7 puts between ``diagnosed`` and
        ``remediating``. The walk into ``remediating`` happens when checks are actually
        run, via :meth:`record_validation`.

        An attempt with an ``attempt_id`` that is already recorded replaces that attempt
        rather than adding a second one, so re-recording is idempotent. Prior attempts are
        never removed.
        """
        _check_child_id("attempt", attempt.incident_id, incident_id)
        record = self._require(incident_id)
        updated = _advance(
            _record_attempt(record, attempt),
            LifecycleState.REMEDIATION_PENDING,
            reason=f"remediation attempt {attempt.attempt_id} recorded",
            at=at,
        )
        return self._save(updated)

    def record_validation(
        self, incident_id: str, validation: ValidationResult, *, at: datetime
    ) -> IncidentRecord:
        """Append a validation result and walk the incident to ``validating``.

        Validation history is append-only: a retry that re-runs the checks adds a result
        instead of replacing the earlier one.
        """
        _check_child_id("validation", validation.incident_id, incident_id)
        record = self._require(incident_id)
        updated = _advance(
            _append_validation(record, validation),
            LifecycleState.VALIDATING,
            reason="validation result recorded",
            at=at,
        )
        return self._save(updated)

    def append_transition(
        self,
        incident_id: str,
        to_state: LifecycleState,
        *,
        reason: str,
        at: datetime,
        validation: ValidationResult | None = None,
    ) -> IncidentRecord:
        """Apply a lifecycle transition, validating it against the domain state machine.

        An illegal transition, or ``recovered`` without a passing validation bound to the
        current patch hash, raises :class:`~openmedic.domain.errors.ContractError` and
        writes nothing.
        """
        record = self._require(incident_id)
        working = _mutable_copy(record)
        apply_transition(working, to_state, reason=reason, at=at, validation=validation)
        return self._save(_frozen_copy(working))

    # -- portability ------------------------------------------------------

    def export_json(self, incident_id: str) -> str:
        """Return the incident as a JSON document, already redacted."""
        record = self._require(incident_id)
        return json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True)

    def import_json(self, text: str) -> IncidentRecord:
        """Load an exported incident back into the store.

        Malformed JSON or a payload that does not satisfy the contract raises
        :class:`~openmedic.domain.errors.InvalidInputError` without touching the store.
        """
        try:
            record = IncidentRecord.model_validate_json(text)
        except (ValidationError, ValueError) as exc:
            msg = "imported payload is not a valid IncidentRecord"
            raise InvalidInputError(msg, detail=_error_detail(exc)) from exc
        return self.upsert_incident(record)

    # -- internals --------------------------------------------------------

    def _save(self, record: IncidentRecord) -> IncidentRecord:
        """Write the redacted payload for ``record`` in a single transaction."""
        _require_known_schema_version(record.schema_version)
        blob = json.dumps(_redacted_payload(record), sort_keys=True, separators=(",", ":"))
        params = (
            record.incident_id,
            record.idempotency_key,
            record.state.value,
            record.schema_version,
            blob,
            _stamp(record.created_at),
            _stamp(record.updated_at),
            _stamp(record.event.timestamp),
        )
        try:
            with transaction(self.conn):
                self.conn.execute(_UPSERT, params)
        except sqlite3.Error as exc:
            msg = f"cannot persist incident {record.incident_id}: {type(exc).__name__}: {exc}"
            raise PersistenceError(msg) from exc
        return record

    def _select(self, clause: str, params: tuple[object, ...]) -> tuple[Any, ...] | None:
        """Return the first row matching ``clause``."""
        return self.conn.execute(f"{_SELECT} {clause}", params).fetchone()

    def _rows(self, sql: str, params: tuple[object, ...]) -> list[tuple[Any, ...]]:
        """Return every row produced by ``sql``."""
        return list(self.conn.execute(sql, params).fetchall())

    def _load(self, incident_id: str) -> IncidentRecord | None:
        """Load one incident by ID, or return ``None``."""
        row = self._select("WHERE incident_id = ?", (incident_id,))
        return None if row is None else _decode(row)

    def _require(self, incident_id: str) -> IncidentRecord:
        """Load one incident or raise, because a write cannot target a missing row."""
        record = self._load(incident_id)
        if record is None:
            msg = f"incident {incident_id} does not exist"
            raise PersistenceError(msg)
        return record


def _decode(row: tuple[Any, ...]) -> IncidentRecord:
    """Rebuild an incident from a stored row, refusing an unknown contract version."""
    incident_id = str(row[0])
    payload = str(row[1])
    _require_known_schema_version(str(row[2]))
    try:
        return IncidentRecord.model_validate_json(payload)
    except ValidationError as exc:
        msg = (
            f"stored incident {incident_id} does not satisfy the contract it was written "
            "with; migrate it deliberately instead of guessing"
        )
        raise PersistenceError(msg, detail=_error_detail(exc)) from exc


def _require_known_schema_version(version: str) -> None:
    """Refuse to read or write a payload written by an unknown contract version."""
    if version == SCHEMA_VERSION:
        return
    msg = (
        f"contract schema version {version!r} is not the version this build reads and "
        f"writes ({SCHEMA_VERSION!r}); migrate the payload deliberately"
    )
    raise PersistenceError(msg)


def _redact_text(value: str | None) -> str | None:
    """Return ``value`` with secrets replaced by the redaction placeholder."""
    if value is None:
        return None
    return redact(value).text


def _redact_all(values: list[str]) -> list[str]:
    """Return every element of ``values`` redacted."""
    return [redact(value).text for value in values]


def _redact_field(container: dict[str, Any], key: str) -> None:
    """Redact ``container[key]`` in place when it is a string."""
    value = container.get(key)
    if isinstance(value, str):
        container[key] = _redact_text(value)


def _redacted_payload(record: IncidentRecord) -> dict[str, Any]:
    """Return the JSON payload for ``record`` with every free-text field redacted."""
    payload = record.model_dump(mode="json")

    event = payload.get("event")
    if isinstance(event, dict):
        _redact_field(event, "logs")

    for diagnosis in payload.get("diagnoses") or []:
        if not isinstance(diagnosis, dict):
            continue
        _redact_field(diagnosis, "probable_cause")
        for item in diagnosis.get("evidence") or []:
            if isinstance(item, dict):
                for key in ("source", "quote", "explanation"):
                    _redact_field(item, key)

    for attempt in payload.get("attempts") or []:
        if not isinstance(attempt, dict):
            continue
        for key in ("summary", "rationale", "rejection_reason", "patch_unified_diff"):
            _redact_field(attempt, key)

    for validation in payload.get("validations") or []:
        if not isinstance(validation, dict):
            continue
        _redact_field(validation, "summary")
        for check in validation.get("checks_executed") or []:
            if isinstance(check, dict):
                for key in ("stdout_excerpt", "stderr_excerpt"):
                    _redact_field(check, key)
        execution = validation.get("execution")
        if isinstance(execution, dict) and isinstance(execution.get("limitations"), list):
            execution["limitations"] = _redact_all([str(item) for item in execution["limitations"]])

    for transition in payload.get("state_history") or []:
        if isinstance(transition, dict):
            _redact_field(transition, "reason")

    return payload


def _stamp(value: datetime) -> str:
    """Normalise a timezone-aware datetime to a canonical UTC ISO-8601 string.

    A fixed string form keeps ``ORDER BY`` lexicographic and avoids the deprecated
    implicit datetime adapter in ``sqlite3``, which emits a ``DeprecationWarning``.
    """
    return value.astimezone(UTC).isoformat()


def _mutable_copy(record: IncidentRecord) -> _MutableIncidentRecord:
    """Return an assignable working copy of ``record``."""
    return _MutableIncidentRecord.model_validate(record.model_dump())


def _frozen_copy(record: IncidentRecord) -> IncidentRecord:
    """Return an immutable ``IncidentRecord`` with the same contents."""
    return IncidentRecord.model_validate(record.model_dump())


def _shortest_path(current: LifecycleState, target: LifecycleState) -> list[LifecycleState] | None:
    """Return the shortest legal transition path from ``current`` to ``target``.

    ``None`` means the target is unreachable from the current state. The search is a BFS
    over the fixed transition table, so the result is deterministic.
    """
    if current is target:
        return []
    queue: deque[tuple[LifecycleState, list[LifecycleState]]] = deque([(current, [])])
    seen = {current}
    while queue:
        state, path = queue.popleft()
        for successor in ALLOWED_TRANSITIONS.get(state, ()):
            if successor in seen:
                continue
            if successor is target:
                return [*path, successor]
            seen.add(successor)
            queue.append((successor, [*path, successor]))
    return None


def _advance(
    record: IncidentRecord, target: LifecycleState, *, reason: str, at: datetime
) -> IncidentRecord:
    """Walk ``record`` forward to ``target`` through legal transitions, if possible.

    Terminal states and unreachable targets leave the record untouched: the caller drives
    those explicitly through :meth:`IncidentRepository.append_transition`.
    """
    if record.state is target or record.state in TERMINAL_STATES:
        return record
    path = _shortest_path(record.state, target)
    if not path:
        return record
    working = _mutable_copy(record)
    for step in path:
        apply_transition(working, step, reason=reason, at=at)
    return _frozen_copy(working)


def _append_diagnosis(record: IncidentRecord, diagnosis: DiagnosisResult) -> IncidentRecord:
    """Return ``record`` with ``diagnosis`` appended unless it is already recorded."""
    if diagnosis in record.diagnoses:
        return record
    return record.model_copy(update={"diagnoses": [*record.diagnoses, diagnosis]})


def _append_validation(record: IncidentRecord, validation: ValidationResult) -> IncidentRecord:
    """Return ``record`` with ``validation`` appended unless it is already recorded."""
    if validation in record.validations:
        return record
    return record.model_copy(update={"validations": [*record.validations, validation]})


def _record_attempt(record: IncidentRecord, attempt: RemediationAttempt) -> IncidentRecord:
    """Return ``record`` with ``attempt`` appended, or replaced in place by ``attempt_id``."""
    attempts = list(record.attempts)
    for index, existing in enumerate(attempts):
        if existing.attempt_id == attempt.attempt_id:
            attempts[index] = attempt
            break
    else:
        attempts.append(attempt)
    return record.model_copy(update={"attempts": attempts})


def _check_child_id(kind: str, child_id: str, incident_id: str) -> None:
    """Reject data that belongs to a different incident before it is attached."""
    if child_id == incident_id:
        return
    msg = f"{kind} is recorded against incident {child_id!r} but was supplied for {incident_id!r}"
    raise InvalidInputError(msg)


def _error_detail(exc: ValidationError) -> str:
    """Summarise a validation error by location and type only.

    Pydantic error strings can quote the rejected value, and the payload being validated
    is untrusted log content, so only field paths and error codes are ever surfaced.
    """
    parts = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ())) or "<root>"
        parts.append(f"{location}: {error.get('type')}")
    return "; ".join(parts)
