"""Deterministic diagnosis engine.

The engine is the offline path required by PRD FR-004/FR-008 and TRD §6: it classifies a
``FailureEvent`` from its log text alone, with no network access, no model provider and
no credentials.

Contract guarantees enforced in code rather than by convention:

1. **Quotes are verified.** Every evidence item published in a ``DiagnosisResult`` is a
   literal substring of ``event.logs``. The :class:`DiagnosisEngine` re-checks each
   candidate quote and drops it otherwise; a rule that claims a quote it does not have
   is reported through ``limitations`` instead of being silently published.
2. **Nothing is invented.** When no rule matches, the result stays ``UNKNOWN`` with low
   confidence and a probable cause that says so. Confidence is never raised to make a
   diagnosis look more certain than the log supports.
3. **Determinism.** The same event always produces an identical ``DiagnosisResult``,
   including rule ordering and evidence ordering. There is no timestamp, randomness or
   iteration over unordered collections anywhere in the path.
4. **Secrets never travel.** A quote that redaction flags as containing a credential is
   dropped, because publishing it would violate the "no secrets in reports, logs or
   persisted records" rule.

The engine also exposes :meth:`DiagnosisEngine.fingerprint_of`, which reuses the
forensics layer so incident recurrence tracking works without a second implementation.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from ..domain.contracts import DiagnosisResult, Evidence, FailureEvent
from ..domain.enums import FailureType, RecommendedAction, RiskLevel
from ..domain.redaction import redact
from ..forensics import fingerprint, normalize_log
from .rules import DiagnosisRule, RuleMatch, UnknownRule, default_rules


@dataclass(frozen=True, slots=True)
class _ScoredMatch:
    """A rule match plus the data the engine needs to promote it deterministically."""

    rule: DiagnosisRule
    match: RuleMatch
    order: int


@dataclass(slots=True)
class _Assembly:
    """Mutable accumulator used while one diagnosis is being assembled."""

    limitations: list[str] = field(default_factory=list)

    def add(self, text: str) -> None:
        """Record ``text`` as a limitation unless it is already recorded."""
        if text not in self.limitations:
            self.limitations.append(text)


class DiagnosisEngine:
    """Deterministic, offline classifier for CI/CD failure events.

    The engine is stateless between calls: all mutable bookkeeping lives in a per-call
    :class:`_Assembly`, so one instance can be reused across many events without sharing
    state, and the rules themselves are immutable.
    """

    __slots__ = ("_rules",)

    def __init__(self, rules: Sequence[DiagnosisRule] | None = None) -> None:
        """Create an engine over ``rules``, or over the built-in set when none are given."""
        selected = list(rules) if rules is not None else default_rules()
        if not any(rule.rule_id == UnknownRule().rule_id for rule in selected):
            # An unclassified failure must still be reportable as UNKNOWN, never dropped.
            selected = [*selected, UnknownRule()]
        self._rules: tuple[DiagnosisRule, ...] = tuple(selected)

    # -- public API ---------------------------------------------------------

    def diagnose(self, event: FailureEvent) -> DiagnosisResult:
        """Return the deterministic diagnosis for ``event``.

        The event's own ``failure_type`` is treated as an ingestion hint only: rules are
        matched against the log text and may disagree with it. Disagreement is recorded
        in ``limitations`` rather than hidden.
        """
        assembly = _Assembly()
        best = self._best(event)
        if best is None:
            return self._unclassified(event, assembly)

        match = best.match
        evidence = self._verified_evidence(event, match, assembly)
        limitations = self._limitations(event, match, assembly)
        confidence = self._bounded_confidence(match.confidence, evidence, assembly)
        return DiagnosisResult(
            incident_id=event.resolved_incident_id,
            failure_type=match.failure_type,
            probable_cause=match.probable_cause,
            evidence=evidence,
            confidence=confidence,
            recommended_action=match.recommended_action,
            risk_level=match.risk_level,
            requires_human_review=match.requires_human_review,
            limitations=limitations,
            rule_id=match.rule_id,
            rule_version=match.rule_version,
            provider_used=False,
        )

    def describe(self) -> list[dict[str, str]]:
        """Return one ``rule_id``/``rule_version``/``description`` row per active rule."""
        return [
            {
                "rule_id": rule.rule_id,
                "rule_version": rule.rule_version,
                "description": rule.description,
            }
            for rule in self._rules
        ]

    def fingerprint_of(self, event: FailureEvent) -> str:
        """Return the stable fingerprint of the event's normalised log.

        Computed from the normalised (secret-redacted and volatility-stripped) text so
        two runs of the same failure with different timestamps, ports or paths collide,
        and so no credential can ever reach the fingerprint.
        """
        return fingerprint(normalize_log(event.logs).normalized)

    # -- internals ----------------------------------------------------------

    def _best(self, event: FailureEvent) -> _ScoredMatch | None:
        """Return the highest-confidence rule match for ``event``.

        Confidence decides. The ingestion hint only separates rules that scored exactly
        equally, and rule order breaks any remaining tie, so the outcome never depends on
        dict or set iteration order.
        """
        lines = event.logs.splitlines()
        candidates: list[_ScoredMatch] = []
        for order, rule in enumerate(self._rules):
            match = rule.match(event, lines)
            if match is not None:
                candidates.append(_ScoredMatch(rule=rule, match=match, order=order))
        if not candidates:
            return None
        return min(
            candidates,
            key=lambda item: (
                -item.match.confidence,
                0 if item.match.failure_type is event.failure_type else 1,
                item.order,
            ),
        )

    def _verified_evidence(
        self, event: FailureEvent, match: RuleMatch, assembly: _Assembly
    ) -> list[Evidence]:
        """Return only the evidence items that survive verification.

        Three independent checks decide survival: the quote must literally appear in the
        raw log, redaction must not flag it as a credential, and its claimed line number
        must actually contain it. Everything else is dropped and reported.
        """
        verified: list[Evidence] = []
        seen: set[str] = set()
        for source, quote, explanation in match.evidence:
            if not quote:
                assembly.add(
                    f"Rule {match.rule_id} emitted an empty evidence quote, which was dropped."
                )
                continue
            if quote not in event.logs:
                assembly.add(
                    f"Rule {match.rule_id} claimed evidence that is not verbatim in the log; "
                    "the quote was dropped."
                )
                continue
            if redact(quote).had_secrets:
                assembly.add(
                    f"Evidence from {source} was withheld because it may contain a credential."
                )
                continue
            line = _claimed_line(source)
            if line is not None and not _line_contains(event.logs, line, quote):
                assembly.add(
                    f"Evidence from {source} does not appear on the line it cites; the "
                    "line reference was dropped."
                )
                source = "logs"
            if quote in seen:
                assembly.add(
                    f"Rule {match.rule_id} repeated an evidence quote; the duplicate was dropped."
                )
                continue
            seen.add(quote)
            verified.append(
                Evidence(source=source, quote=quote, explanation=explanation, inferred=False)
            )
        return verified

    def _limitations(self, event: FailureEvent, match: RuleMatch, assembly: _Assembly) -> list[str]:
        """Return the merged, de-duplicated limitation list for a diagnosis."""
        for text in match.limitations:
            assembly.add(text)
        if (
            event.failure_type is not FailureType.UNKNOWN
            and event.failure_type is not match.failure_type
        ):
            assembly.add(
                "Ingestion classified this event as "
                f"'{event.failure_type.value}', but the deterministic rules determined "
                f"'{match.failure_type.value}'; the log evidence was preferred."
            )
        if not assembly.limitations:
            assembly.add("No limitations were reported by the matching rule.")
        return list(assembly.limitations)

    def _bounded_confidence(
        self, confidence: float, evidence: list[Evidence], assembly: _Assembly
    ) -> float:
        """Return ``confidence`` capped to what the surviving evidence can support.

        A rule may be optimistic; the published number may not exceed what its verified
        evidence justifies, so a dropped quote costs certainty.
        """
        if not evidence and confidence > 0.25:
            assembly.add(
                "All of the matching rule's evidence was withheld as unverified or "
                "secret-bearing, so confidence was capped."
            )
            return min(confidence, 0.25)
        return min(max(confidence, 0.0), 1.0)

    def _unclassified(self, event: FailureEvent, assembly: _Assembly) -> DiagnosisResult:
        """Return an UNKNOWN diagnosis when no rule fired at all.

        Unreachable with the built-in rule set, because :class:`UnknownRule` always
        matches. It exists so a custom rule set that omits a fallback cannot make the
        engine raise instead of reporting honestly.
        """
        assembly.add("No configured rule fired for this log.")
        return DiagnosisResult(
            incident_id=event.resolved_incident_id,
            failure_type=FailureType.UNKNOWN,
            probable_cause=(
                "No deterministic rule fired for this log, so the failure signature is "
                "unrecognised and no root cause is claimed."
            ),
            evidence=[],
            confidence=0.0,
            recommended_action=RecommendedAction.INVESTIGATE_MANUALLY,
            risk_level=RiskLevel.HIGH,
            requires_human_review=True,
            limitations=assembly.limitations,
            rule_id="deterministic",
            rule_version="1",
            provider_used=False,
        )


def _claimed_line(source: str) -> int | None:
    """Return the 1-based line number encoded in ``source`` as ``logs:<n>``."""
    prefix = "logs:"
    if not source.startswith(prefix) or source == prefix:
        return None
    remainder = source[len(prefix) :]
    return int(remainder) if remainder.isdigit() else None


def _line_contains(logs: str, number: int, quote: str) -> bool:
    """Return whether 1-based line ``number`` of ``logs`` contains ``quote``."""
    lines = logs.splitlines()
    return 1 <= number <= len(lines) and quote in lines[number - 1]
