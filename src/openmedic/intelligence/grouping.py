"""Conservative cascade grouping over correlated incidents (FR-015).

Grouping is *correlation*, never *causation*. The published rule below is the contract
this module implements; it is deliberately narrow so that unrelated failures cannot be
merged by accident.

Grouping rule (:data:`GROUPING_RULE`)
-------------------------------------

A cascade group forms only when **every** incident in it:

1. shares at least ``min_shared`` *identifying* signals with every other member, and
2. falls inside ``window_seconds`` of every other member.

Identifying signals are the ones specific enough to separate a cascade from coincidence:

    ``fingerprint=<hex>``          identical normalised-log fingerprint
    ``commit=<sha>``               identical commit SHA
    ``run=<run-id>``               identical workflow run id
    ``job-step=<job>|<step>``      identical job name *and* failing step
    ``workflow-step=<wf>|<step>``  identical workflow name *and* failing step

*Contextual* similarities -- repository, failure type, workflow, job, step name -- are
reported in ``shared_signals`` because they are part of what the incidents share, but
they are **never counted** toward ``min_shared``: two unrelated test failures in the same
repository share both of those and nothing else.

Incidents are attached chronologically, each to the existing group with the strongest
signal overlap that still fits the window. A group is emitted only when it holds two or
more incidents, so a single failure is never presented as a cascade.

Confidence is capped at :data:`MAX_GROUP_CONFIDENCE` (0.90) because correlation can be
strong but never certain, and every group carries :attr:`CascadeGroup.limitations`
stating that no causal relationship is established.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from ..domain.contracts import IncidentRecord
from .recurrence import failure_type_of, fingerprint_incident, unique_records

__all__ = [
    "GROUPING_RULE",
    "MAX_GROUP_CONFIDENCE",
    "CascadeGroup",
    "group_cascades",
]


@dataclass(frozen=True, slots=True)
class CascadeGroup:
    """A set of incidents that share evidence and occurred close together in time.

    ``shared_signals`` lists every signal (identifying and contextual) that *all*
    members share, each one traceable back to a field on the member events.
    ``confidence`` is capped below 1.0 and ``limitations`` always includes the
    correlation-not-causation statement.
    """

    group_id: str
    incident_ids: tuple[str, ...]
    shared_signals: tuple[str, ...]
    repositories: tuple[str, ...]
    time_span: tuple[datetime, datetime]
    confidence: float
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable payload using the canonical field names."""
        return {
            "group_id": self.group_id,
            "incident_ids": list(self.incident_ids),
            "shared_signals": list(self.shared_signals),
            "repositories": list(self.repositories),
            "time_span": [self.time_span[0].isoformat(), self.time_span[1].isoformat()],
            "confidence": self.confidence,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class _Signals:
    """Signals extracted from one incident, split by how much weight they carry."""

    incident_id: str
    observed_at: datetime
    repository: str | None
    identity: frozenset[str]
    context: frozenset[str]


@dataclass(slots=True)
class _Cluster:
    """A growing group plus the signals all of its members share so far."""

    signals: list[_Signals]
    shared: frozenset[str]
    starts_at: datetime
    ends_at: datetime

    def span_seconds(self) -> float:
        """Return the number of seconds between the first and last member."""
        return (self.ends_at - self.starts_at).total_seconds()


#: Published grouping rule. See the module docstring for the full statement.
GROUPING_RULE: Final[str] = (
    "A cascade group forms only when every incident in it shares at least `min_shared` "
    "identifying signals with every other member and falls inside `window_seconds` of "
    "every other member. Identifying signals are the normalised-log fingerprint, the "
    "commit SHA, the workflow run id, the job+failing-step pair, and the "
    "workflow+failing-step pair. Contextual similarities (repository, failure type, "
    "job, workflow, step name) are reported but never counted, because they are too "
    "common to separate a cascade from unrelated noise. Incidents attach "
    "chronologically to the existing group with the strongest signal overlap that still "
    "fits the window, and a group is emitted only when it holds two or more incidents."
)

#: Correlation can be strong but never certain, so confidence never reaches 1.0.
MAX_GROUP_CONFIDENCE: Final[float] = 0.90

#: How much each identifying signal contributes to group confidence.
_SIGNAL_WEIGHTS: Final[dict[str, float]] = {
    "fingerprint": 0.40,
    "commit": 0.25,
    "run": 0.20,
    "job-step": 0.15,
    "workflow-step": 0.12,
}

#: Ceiling on the summed identifying-signal weight, leaving room for temporal support.
_MAX_IDENTIFYING_STRENGTH: Final[float] = 0.80

#: Weight of temporal tightness: incidents seconds apart warrant more confidence than
#: incidents at the far edge of the window.
_TEMPORAL_WEIGHT: Final[float] = 0.10

_CORRELATION_NOT_CAUSATION: Final[str] = (
    "Grouping is correlational: the incidents share signals and may share a cause, but "
    "this grouping does not establish that any incident caused another."
)

_CLOCK_SKEW_LIMITATION: Final[str] = (
    "Incident timestamps come from the source events and are not corrected for clock "
    "skew between runners, so the reported time span is approximate."
)


def group_cascades(
    records: Sequence[IncidentRecord],
    *,
    window_seconds: int = 1800,
    min_shared: int = 2,
) -> list[CascadeGroup]:
    """Group ``records`` into correlated cascades using the published grouping rule.

    Unrelated failures are never merged: a group requires at least ``min_shared``
    identifying signals shared by every member and a total time span no wider than
    ``window_seconds``.
    """
    if window_seconds <= 0:
        msg = "window_seconds must be positive"
        raise ValueError(msg)
    if min_shared < 1:
        msg = "min_shared must be at least 1"
        raise ValueError(msg)

    prepared = sorted(
        (_extract(record) for record in unique_records(records)),
        key=lambda item: (item.observed_at, item.incident_id),
    )

    clusters: list[_Cluster] = []
    for item in prepared:
        chosen: tuple[frozenset[str], _Cluster] | None = None
        for cluster in clusters:
            common = cluster.shared & item.identity
            if len(common) < min_shared:
                continue
            starts_at = min(cluster.starts_at, item.observed_at)
            ends_at = max(cluster.ends_at, item.observed_at)
            if (ends_at - starts_at).total_seconds() > window_seconds:
                continue
            if chosen is None or len(common) > len(chosen[0]):
                chosen = (common, cluster)
        if chosen is None:
            clusters.append(
                _Cluster(
                    signals=[item],
                    shared=item.identity,
                    starts_at=item.observed_at,
                    ends_at=item.observed_at,
                )
            )
            continue
        common, cluster = chosen
        cluster.signals.append(item)
        cluster.shared = common
        cluster.starts_at = min(cluster.starts_at, item.observed_at)
        cluster.ends_at = max(cluster.ends_at, item.observed_at)

    return [
        _build_group(cluster, window_seconds) for cluster in clusters if len(cluster.signals) > 1
    ]


def _extract(record: IncidentRecord) -> _Signals:
    """Pull the identifying and contextual signals out of one incident record."""
    event = record.event
    identity = {f"fingerprint={fingerprint_incident(record)}"}
    if event.commit_sha:
        identity.add(f"commit={event.commit_sha}")
    if event.run_id:
        identity.add(f"run={event.run_id}")
    if event.failed_step:
        if event.job_name:
            identity.add(f"job-step={event.job_name}|{event.failed_step}")
        elif event.workflow_name:
            identity.add(f"workflow-step={event.workflow_name}|{event.failed_step}")

    context = {f"failure-type={failure_type_of(record).value}"}
    if event.repository:
        context.add(f"repository={event.repository}")
    if event.workflow_name:
        context.add(f"workflow={event.workflow_name}")
    if event.job_name:
        context.add(f"job={event.job_name}")
    if event.failed_step:
        context.add(f"failed-step={event.failed_step}")

    return _Signals(
        incident_id=record.incident_id,
        observed_at=record.event.timestamp.astimezone(UTC),
        repository=event.repository,
        identity=frozenset(identity),
        context=frozenset(context),
    )


def _build_group(cluster: _Cluster, window_seconds: int) -> CascadeGroup:
    """Assemble one :class:`CascadeGroup` from a finished cluster."""
    members = cluster.signals
    incident_ids = tuple(sorted(member.incident_id for member in members))
    repositories = tuple(sorted({member.repository for member in members if member.repository}))
    shared_context = frozenset.intersection(*(member.context for member in members))
    time_span = (cluster.starts_at, cluster.ends_at)

    shared_signals = tuple(sorted(cluster.shared | shared_context))
    limitations = _limitations(
        identifying=cluster.shared,
        context=shared_context,
        repositories=repositories,
    )
    return CascadeGroup(
        group_id=f"cascade-{_short_hash('|'.join(incident_ids))}",
        incident_ids=incident_ids,
        shared_signals=shared_signals,
        repositories=repositories,
        time_span=time_span,
        confidence=_confidence(cluster, window_seconds),
        limitations=limitations,
    )


def _confidence(cluster: _Cluster, window_seconds: int) -> float:
    """Compute an honest, capped confidence for a finished cluster.

    Confidence is the summed weight of the identifying signals the cluster actually
    shares, plus a small bonus for temporal tightness. It never reaches 1.0.
    """
    strength = 0.0
    for signal in cluster.shared:
        kind = signal.split("=", 1)[0]
        strength += _SIGNAL_WEIGHTS.get(kind, 0.0)
    strength = min(strength, _MAX_IDENTIFYING_STRENGTH)

    span = cluster.span_seconds()
    tightness = 1.0 - (span / window_seconds) if window_seconds > 0 else 0.0
    tightness = min(max(tightness, 0.0), 1.0)

    value = strength + _TEMPORAL_WEIGHT * tightness
    return round(min(max(value, 0.0), MAX_GROUP_CONFIDENCE), 4)


def _limitations(
    *,
    identifying: frozenset[str],
    context: frozenset[str],
    repositories: tuple[str, ...],
) -> tuple[str, ...]:
    """Build the limitations every group must carry, plus the case-specific ones."""
    limitations = [_CORRELATION_NOT_CAUSATION]

    if any(signal.startswith("fingerprint=") for signal in identifying):
        limitations.append(
            "Identical normalised-log fingerprints show repeated occurrences of the "
            "same failure signature; a repeat is not evidence that one run triggered "
            "another."
        )
    if len(repositories) > 1:
        limitations.append(
            "The group spans multiple repositories and no dependency graph was "
            "analysed, so even the direction of a possible causal relationship is "
            "unknown."
        )
    if context:
        limitations.append(
            "Contextual similarities reported in shared_signals (repository, failure "
            "type, workflow stage) were not counted as evidence because they are too "
            "common to distinguish a cascade from coincidence."
        )
    limitations.append(_CLOCK_SKEW_LIMITATION)
    limitations.append(
        f"Confidence is capped at {MAX_GROUP_CONFIDENCE:.2f}: correlation can be strong "
        "but never certain."
    )
    return tuple(limitations)


def _short_hash(value: str) -> str:
    """Return a short, stable, non-cryptographic hash for display identifiers.

    Used only to build group ids, never for a security decision.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
