"""Recurrence intelligence over normalised failure fingerprints (FR-014).

Two incidents are *the same recurring failure* when their logs normalise to the same
text, which is exactly what :func:`~openmedic.forensics.forensics.fingerprint` decides.
Recurrence is therefore computed from the normalised log only. Run ids, timestamps,
temporary paths, ports, and durations are already gone by the time the fingerprint is
taken, so the same defect recurring on a different runner still lands in one group.

Honesty rules this module enforces rather than promises:

* A recurrence group states "this signature has been seen N times". It does not claim
  the incidents share a root cause, and it never carries a remediation.
* ``recovered_count`` and ``failed_count`` are literal lifecycle-state counts. Every
  other state (``requires_human_review``, ``diagnosed``, ``validating`` ...) is counted
  in neither, so ``recovered_count + failed_count`` need not equal ``count``.
* Fingerprints are taken over the *redacted* normalised log, so secret material cannot
  influence grouping and is never part of the fingerprint input.
* Callers pass one record per incident occurrence. Repeated ingestion is an idempotency
  concern owned by the ingestion layer (FR-009); this layer de-duplicates on
  ``incident_id`` so a duplicated record cannot inflate a count.

This module imports no diagnosis engine, provider, or remediation code. It reads the
already-persisted :class:`~openmedic.domain.contracts.IncidentRecord` aggregate.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from ..domain.contracts import IncidentRecord
from ..domain.enums import FailureType, LifecycleState
from ..forensics import fingerprint, normalize_log

__all__ = [
    "RecurrenceGroup",
    "failure_type_of",
    "fingerprint_incident",
    "group_by_fingerprint",
    "unique_records",
]


@dataclass(frozen=True, slots=True)
class RecurrenceGroup:
    """One recurring failure signature and the incidents that carry it.

    ``count`` is the number of distinct incidents in the group, ``first_seen`` and
    ``last_seen`` are the earliest and latest observation timestamps normalised to UTC,
    and the two outcome counters are lifecycle-state counts, not a partition of the
    group (see the module docstring).
    """

    fingerprint: str
    incident_ids: tuple[str, ...]
    count: int
    first_seen: datetime
    last_seen: datetime
    failure_types: tuple[FailureType, ...]
    recovered_count: int
    failed_count: int
    repositories: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable payload using the canonical field names."""
        return {
            "fingerprint": self.fingerprint,
            "incident_ids": list(self.incident_ids),
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "failure_types": [ft.value for ft in self.failure_types],
            "recovered_count": self.recovered_count,
            "failed_count": self.failed_count,
            "repositories": list(self.repositories),
        }


def fingerprint_incident(record: IncidentRecord) -> str:
    """Return the stable fingerprint of ``record`` taken over its normalised log.

    The input to the fingerprint is the normalised *and redacted* log, so the same
    failure fingerprints identically across runs and secret material never reaches
    the hash.
    """
    normalized = normalize_log(record.event.logs).normalized
    return fingerprint(normalized)


def unique_records(records: Sequence[IncidentRecord]) -> list[IncidentRecord]:
    """Return ``records`` with repeated ``incident_id`` values collapsed.

    The last occurrence wins because an incident record is append-only history: a later
    copy carries more attempts and a more advanced lifecycle state than an earlier one.
    Input order is otherwise preserved, and the result is deterministic for a given
    input.
    """
    by_id: dict[str, IncidentRecord] = {}
    for record in records:
        by_id[record.incident_id] = record
    return list(by_id.values())


def failure_type_of(record: IncidentRecord) -> FailureType:
    """Return the classified failure type of ``record``.

    The latest diagnosis wins over the type declared on the ingested event, because the
    event label is provisional at ingestion time and the diagnosis is produced from the
    log evidence.
    """
    diagnosis = record.latest_diagnosis
    if diagnosis is not None:
        return diagnosis.failure_type
    return record.event.failure_type


def group_by_fingerprint(records: Sequence[IncidentRecord]) -> list[RecurrenceGroup]:
    """Group ``records`` by normalised-log fingerprint.

    The result is sorted by descending count and then by ascending fingerprint, so the
    most frequent signature is first and the output is stable across runs.
    """
    buckets: dict[str, list[IncidentRecord]] = {}
    for record in unique_records(records):
        buckets.setdefault(fingerprint_incident(record), []).append(record)
    groups = [_build_group(value, bucket) for value, bucket in buckets.items()]
    groups.sort(key=lambda group: (-group.count, group.fingerprint))
    return groups


def find_recurrences(
    records: Sequence[IncidentRecord], *, min_count: int = 2
) -> list[RecurrenceGroup]:
    """Return only the fingerprint groups seen at least ``min_count`` times.

    ``min_count=1`` returns every group, including signatures seen once.
    """
    if min_count < 1:
        msg = "min_count must be at least 1"
        raise ValueError(msg)
    return [group for group in group_by_fingerprint(records) if group.count >= min_count]


def _observed_at(record: IncidentRecord) -> datetime:
    """Return when the failure occurred, normalised to UTC.

    The event timestamp is used rather than ``created_at`` because it records when the
    upstream run failed, which is the moment a human cares about for recurrence.
    """
    return record.event.timestamp.astimezone(UTC)


def _failure_types(records: Sequence[IncidentRecord]) -> tuple[FailureType, ...]:
    """Return the distinct failure types in ``records``, ordered by enum value."""
    distinct = {failure_type_of(record) for record in records}
    return tuple(sorted(distinct, key=lambda failure_type: failure_type.value))


def _build_group(value: str, records: Sequence[IncidentRecord]) -> RecurrenceGroup:
    """Assemble one :class:`RecurrenceGroup` from ``records`` sharing ``value``."""
    stamps = sorted(_observed_at(record) for record in records)
    repositories = sorted(
        {record.event.repository for record in records if record.event.repository}
    )
    return RecurrenceGroup(
        fingerprint=value,
        incident_ids=tuple(sorted(record.incident_id for record in records)),
        count=len(records),
        first_seen=stamps[0],
        last_seen=stamps[-1],
        failure_types=_failure_types(records),
        recovered_count=sum(1 for record in records if record.state is LifecycleState.RECOVERED),
        failed_count=sum(1 for record in records if record.state is LifecycleState.FAILED),
        repositories=tuple(repositories),
    )
