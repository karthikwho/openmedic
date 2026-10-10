"""Bounded, auditable remediation proposals.

This package turns a diagnosis into a candidate patch, scores its risk, and records the
decision. It is layered from the inside out:

* :mod:`~openmedic.remediation.patches` — patch identity (``patch_hash``), the only
  function that writes a patch, and the safety-rejection policy.
* :mod:`~openmedic.remediation.risk` — deterministic, documented risk scoring.
* :mod:`~openmedic.remediation.playbooks` — the narrow, certain repairs.
* :mod:`~openmedic.remediation.engine` — the orchestration that produces a
  :class:`~openmedic.domain.contracts.RemediationAttempt`.

Nothing here executes a shell command, writes to the caller's working tree, or treats
model output as an instruction.
"""

from __future__ import annotations

from ..domain.contracts import RemediationAttempt
from .engine import RemediationEngine, RemediationOutcome, propose_remediation
from .patches import (
    FilePatch,
    PatchProposal,
    apply_patch_proposal,
    evaluate_patch_safety,
    normalize_relative_path,
    parse_unified_diff,
)
from .playbooks import Playbook, default_playbooks
from .risk import RiskAssessment, score_risk

__all__ = [
    "FilePatch",
    "PatchProposal",
    "Playbook",
    "RemediationAttempt",
    "RemediationEngine",
    "RemediationOutcome",
    "RiskAssessment",
    "apply_patch_proposal",
    "default_playbooks",
    "evaluate_patch_safety",
    "normalize_relative_path",
    "parse_unified_diff",
    "propose_remediation",
    "score_risk",
]
