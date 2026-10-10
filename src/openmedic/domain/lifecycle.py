"""Incident lifecycle state machine.

The transition table is transcribed from ``docs/ARCHITECTURE.md`` section 7 and
``docs/API_CONTRACTS.md`` section 5. Invalid transitions raise :class:`ContractError`
rather than being silently accepted, so a bug in a caller shows up as a loud failure
instead of an incident that quietly skips validation.

Recovery is deliberately not a transition that any code path can take on its own: it
requires a passing :class:`~openmedic.domain.contracts.ValidationResult` bound to the
exact patch currently recorded on the incident.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Final

from .enums import LifecycleState
from .errors import ContractError

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from .contracts import IncidentRecord, StateTransition, ValidationResult

#: Legal transitions, transcribed from ARCHITECTURE.md section 7.
ALLOWED_TRANSITIONS: Final[dict[LifecycleState, tuple[LifecycleState, ...]]] = {
    LifecycleState.RECEIVED: (LifecycleState.DIAGNOSING,),
    LifecycleState.DIAGNOSING: (
        LifecycleState.DIAGNOSED,
        LifecycleState.REQUIRES_HUMAN_REVIEW,
    ),
    LifecycleState.DIAGNOSED: (
        LifecycleState.REMEDIATION_PENDING,
        LifecycleState.REQUIRES_HUMAN_REVIEW,
    ),
    LifecycleState.REMEDIATION_PENDING: (
        LifecycleState.REMEDIATING,
        LifecycleState.REQUIRES_HUMAN_REVIEW,
    ),
    LifecycleState.REMEDIATING: (
        LifecycleState.VALIDATING,
        LifecycleState.FAILED,
    ),
    LifecycleState.VALIDATING: (
        LifecycleState.RECOVERED,
        LifecycleState.FAILED,
        LifecycleState.REQUIRES_HUMAN_REVIEW,
    ),
    LifecycleState.FAILED: (LifecycleState.DIAGNOSING,),
    LifecycleState.RECOVERED: (),
    LifecycleState.REQUIRES_HUMAN_REVIEW: (),
}

#: States an incident can rest in. ``RECOVERED`` and ``REQUIRES_HUMAN_REVIEW`` are
#: terminal in this table; retries out of them are a deliberate, separate action.
TERMINAL_STATES: Final[frozenset[LifecycleState]] = frozenset(
    {LifecycleState.RECOVERED, LifecycleState.REQUIRES_HUMAN_REVIEW}
)


def can_transition(current: LifecycleState, target: LifecycleState) -> bool:
    """Return whether ``current -> target`` is a legal transition."""
    if current == target:
        return False
    return target in ALLOWED_TRANSITIONS.get(current, ())


def validate_transition(current: LifecycleState, target: LifecycleState) -> None:
    """Raise :class:`ContractError` if the transition is not legal."""
    if not can_transition(current, target):
        msg = f"illegal lifecycle transition {current.value} -> {target.value}"
        raise ContractError(msg)


def _recovery_justified(
    record: IncidentRecord, validation: ValidationResult | None
) -> ValidationResult:
    """Return the validation that justifies recovery, or raise.

    This is the single place where ``recovered`` can be earned, and it requires all of:

    * a validation result must exist for this incident;
    * it must have passed with no blocking check failures;
    * its candidate patch hash must match the current recorded attempt, so a patch
      change after validation makes the result stale;
    * the validation must carry real execution metadata, so a hand-built "all checks
      passed" object cannot satisfy it.
    """
    if validation is None:
        msg = "cannot enter 'recovered' without a validation result"
        raise ContractError(msg)
    if not validation.passed:
        msg = f"cannot enter 'recovered': validation did not pass ({validation.summary})"
        raise ContractError(msg)
    if not validation.checks_executed:
        msg = "cannot enter 'recovered' from a validation with no executed checks"
        raise ContractError(msg)

    current_attempt = record.attempts[-1] if record.attempts else None
    if current_attempt is None:
        msg = "cannot enter 'recovered' without a current remediation attempt"
        raise ContractError(msg)
    if validation.candidate_patch_hash is None:
        msg = "cannot enter 'recovered': validation is not bound to a candidate patch hash"
        raise ContractError(msg)
    if current_attempt.patch_hash != validation.candidate_patch_hash:
        msg = (
            "cannot enter 'recovered': validation is stale — it was produced for patch "
            f"{validation.candidate_patch_hash} but the current patch is "
            f"{current_attempt.patch_hash}"
        )
        raise ContractError(msg)
    if validation.execution.isolation_kind in {"", "unknown"}:
        msg = "cannot enter 'recovered': validation has no recorded execution metadata"
        raise ContractError(msg)
    return validation


def apply_transition(
    record: IncidentRecord,
    target: LifecycleState,
    *,
    reason: str,
    at: datetime,
    validation: ValidationResult | None = None,
) -> StateTransition:
    """Apply ``target`` to ``record`` in place, returning the recorded transition.

    The mutated record is returned for chaining. ``updated_at`` is always advanced.
    ``validation`` defaults to the record's most recent validation, which is what a
    recovery decision must actually be based on.
    """
    from .contracts import StateTransition  # local import keeps the module acyclic

    validate_transition(record.state, target)

    if target is LifecycleState.RECOVERED:
        if validation is None:
            validation = record.latest_validation
        _recovery_justified(record, validation)

    transition = StateTransition(
        from_state=record.state,
        to_state=target,
        reason=reason,
        at=at,
    )
    record.state = target
    record.state_history = [*record.state_history, transition]
    record.updated_at = at
    return transition
