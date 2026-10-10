"""The bounded remediation engine.

The engine is the only path from a diagnosis to a proposal. It is deliberately small:
it asks each playbook in turn, applies the safety policy and the risk policy, and
records what happened as a :class:`~openmedic.domain.contracts.RemediationAttempt`.

What the engine never does:

* write to the caller's working tree — :func:`apply_patch_proposal` is the only writer,
  and it writes only into a worktree the caller supplies;
* execute a shell command, a ``git`` invocation, or anything derived from model output;
* lower a risk level or clear a human-review flag;
* let a playbook that raises produce a proposal. A broken playbook is a "no proposal",
  never a guessed fix.

Statuses recorded by :meth:`RemediationEngine.propose`:

* ``PROPOSED`` — safe and below the review threshold.
* ``AWAITING_REVIEW`` — safe, but at or above the review threshold or flagged by the
  risk policy.
* ``REJECTED`` — unsafe, or wider than the configured file limit. ``rejection_reason``
  is always populated in that case, and the proposal is returned alongside it so a
  report can show *what* was refused.
* ``attempt`` is ``None`` only when no playbook applied at all, which is an honest
  "nothing to propose".
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from ..domain.contracts import RemediationAttempt, utc_now
from ..domain.enums import RemediationStatus, RiskLevel
from .patches import PatchProposal, evaluate_patch_safety
from .playbooks import Playbook, default_playbooks
from .risk import RiskAssessment, score_risk

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..domain.contracts import DiagnosisResult, FailureEvent

__all__ = ["RemediationEngine", "RemediationOutcome", "propose_remediation"]

#: Risk levels ordered from least to most dangerous.
_LEVEL_ORDER: Final[tuple[RiskLevel, ...]] = (
    RiskLevel.NONE,
    RiskLevel.LOW,
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
)


@dataclass(slots=True)
class RemediationOutcome:
    """The result of asking for a remediation proposal.

    Attributes:
        attempt: The recorded attempt, or ``None`` when no playbook applied at all.
        proposal: The proposal that produced the attempt, retained even when rejected
            so a report can show what was refused and why.
        rejected_reason: Why nothing was proposed, or ``None`` on success.

    """

    attempt: RemediationAttempt | None
    proposal: PatchProposal | None
    rejected_reason: str | None


class RemediationEngine:
    """Ask deterministic playbooks for a bounded, audited proposal."""

    def __init__(
        self,
        playbooks: Sequence[Playbook] | None = None,
        *,
        max_files_changed: int = 5,
        require_review_above: RiskLevel = RiskLevel.MEDIUM,
    ) -> None:
        """Create an engine.

        Args:
            playbooks: Playbooks in evaluation order. Defaults to
                :func:`~openmedic.remediation.playbooks.default_playbooks`.
            max_files_changed: Hard ceiling on the number of files one proposal may
                touch. Must be at least 1.
            require_review_above: Risk level at or above which a proposal must be
                reviewed by a human instead of being accepted as ``PROPOSED``.

        Raises:
            ValueError: If ``max_files_changed`` is below 1.

        """
        if max_files_changed < 1:
            msg = f"max_files_changed must be at least 1, got {max_files_changed}"
            raise ValueError(msg)
        self.playbooks: tuple[Playbook, ...] = tuple(
            default_playbooks() if playbooks is None else playbooks
        )
        self.max_files_changed = max_files_changed
        self.require_review_above = require_review_above

    def propose(
        self,
        event: FailureEvent,
        diagnosis: DiagnosisResult,
        *,
        repo_root: Path | None = None,
    ) -> RemediationOutcome:
        """Return the remediation outcome for ``event`` and ``diagnosis``.

        Args:
            event: The normalised failure event carrying the raw log evidence.
            diagnosis: The diagnosis that classified the failure.
            repo_root: Optional repository root, used by playbooks to read and patch
                files. The engine never writes here.

        Returns:
            A :class:`RemediationOutcome`.

        """
        failure: str | None = None
        for playbook in self.playbooks:
            try:
                proposal = playbook.build(event, diagnosis, repo_root=repo_root)
            except Exception as exc:
                # A playbook that fails yields no proposal. Only the exception type is
                # recorded: its text can contain file contents, and it must never be
                # turned into a patch.
                failure = f"{playbook.playbook_id} raised {type(exc).__name__}"
                continue
            if proposal is None:
                continue
            return self._assess(event, proposal, playbook, diagnosis, repo_root=repo_root)

        return RemediationOutcome(attempt=None, proposal=None, rejected_reason=_no_match(failure))

    def _assess(
        self,
        event: FailureEvent,
        proposal: PatchProposal,
        playbook: Playbook,
        diagnosis: DiagnosisResult,
        *,
        repo_root: Path | None,
    ) -> RemediationOutcome:
        """Apply the safety, scope, and risk policies to one proposal."""
        incident_id = event.resolved_incident_id
        patch_hash = proposal.patch_hash()
        attempt_id = _attempt_id(incident_id, patch_hash, playbook.playbook_id)
        files = [file_patch.path for file_patch in proposal.files]
        assessment = score_risk(proposal, diagnosis, repo_root=repo_root)

        if len(set(files)) != len(files):
            reason = (
                "proposal changes the same file more than once, which makes the "
                "resulting content ambiguous"
            )
            return self._reject(
                attempt_id, incident_id, proposal, playbook, assessment, patch_hash, reason
            )

        reasons = evaluate_patch_safety(proposal)
        if reasons:
            reason = "unsafe patch: " + "; ".join(reasons)
            return self._reject(
                attempt_id, incident_id, proposal, playbook, assessment, patch_hash, reason
            )

        if len(files) > self.max_files_changed:
            reason = (
                f"proposal touches {len(files)} files, above the configured limit of "
                f"{self.max_files_changed}"
            )
            return self._reject(
                attempt_id, incident_id, proposal, playbook, assessment, patch_hash, reason
            )

        requires_review = assessment.requires_human_review or (
            _rank(assessment.level) >= _rank(self.require_review_above)
        )
        status = (
            RemediationStatus.AWAITING_REVIEW if requires_review else RemediationStatus.PROPOSED
        )
        attempt = RemediationAttempt(
            attempt_id=attempt_id,
            incident_id=incident_id,
            status=status,
            rule_id=playbook.playbook_id,
            summary=proposal.summary,
            rationale=_rationale(proposal, playbook, assessment),
            risk_level=assessment.level,
            requires_human_review=requires_review,
            files_changed=files,
            patch_unified_diff=proposal.unified_diff,
            patch_hash=patch_hash,
            created_at=utc_now(),
        )
        return RemediationOutcome(attempt=attempt, proposal=proposal, rejected_reason=None)

    def _reject(
        self,
        attempt_id: str,
        incident_id: str,
        proposal: PatchProposal,
        playbook: Playbook,
        assessment: RiskAssessment,
        patch_hash: str | None,
        reason: str,
    ) -> RemediationOutcome:
        """Build a REJECTED outcome with a populated ``rejection_reason``."""
        attempt = RemediationAttempt(
            attempt_id=attempt_id,
            incident_id=incident_id,
            status=RemediationStatus.REJECTED,
            rule_id=playbook.playbook_id,
            summary=proposal.summary,
            rationale=_rationale(proposal, playbook, assessment),
            risk_level=assessment.level,
            requires_human_review=True,
            files_changed=[file_patch.path for file_patch in proposal.files],
            patch_unified_diff=proposal.unified_diff,
            patch_hash=patch_hash,
            created_at=utc_now(),
            rejection_reason=reason,
        )
        return RemediationOutcome(attempt=attempt, proposal=proposal, rejected_reason=reason)


def propose_remediation(
    event: FailureEvent,
    diagnosis: DiagnosisResult,
    *,
    repo_root: Path | None = None,
) -> RemediationOutcome:
    """Return a remediation outcome using the default playbooks and defaults.

    Args:
        event: The normalised failure event carrying the raw log evidence.
        diagnosis: The diagnosis that classified the failure.
        repo_root: Optional repository root. Never written to.

    Returns:
        A :class:`RemediationOutcome`.

    """
    return RemediationEngine().propose(event, diagnosis, repo_root=repo_root)


def _no_match(failure: str | None) -> str:
    """Return why no proposal was produced."""
    if failure:
        return (
            "no remediation proposed: playbook "
            f"{failure} while building a proposal, so nothing was guessed"
        )
    return (
        "no remediation proposed: no deterministic playbook matched this failure with "
        "enough certainty, which requires human investigation"
    )


def _rationale(proposal: PatchProposal, playbook: Playbook, assessment: RiskAssessment) -> str:
    """Return the attempt rationale, including playbook and risk provenance."""
    parts = [proposal.rationale.rstrip()]
    parts.append(f"[playbook {playbook.playbook_id} version {playbook.version}]")
    if assessment.reasons:
        parts.append("Risk assessment: " + "; ".join(assessment.reasons))
    return "\n\n".join(part for part in parts if part)


def _attempt_id(incident_id: str, patch_hash: str | None, rule_id: str) -> str:
    """Return a deterministic attempt id for the given inputs."""
    identity = "\n".join([incident_id, patch_hash or "no-patch", rule_id])
    return f"att-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16]}"


def _rank(level: RiskLevel) -> int:
    """Return the comparable rank of ``level``."""
    return _LEVEL_ORDER.index(level)
