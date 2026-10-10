"""Deterministic risk classification for a candidate patch.

The rules below are the whole policy. They are evaluated in a fixed order, they only
ever *raise* the risk level that the diagnosis already reported, and every escalation
carries a human-readable justification in :attr:`RiskAssessment.reasons`, because a
risk decision nobody can explain is the same as no decision.

Two invariants are worth stating explicitly:

* Risk scoring never lowers risk. The level is the maximum of the diagnosis level and
  every rule that fired, so an optimistic playbook cannot talk a high-risk diagnosis
  down.
* ``requires_human_review`` is monotone too: it is the OR of the diagnosis flag and
  every rule that fired. Clearing a human-review flag is not something a scoring
  function may do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import TYPE_CHECKING

from ..domain.enums import RiskLevel
from .patches import (
    FilePatch,
    PatchProposal,
    is_ci_config_path,
    is_dependency_manifest_path,
    is_lockfile_path,
    is_test_path,
    normalize_relative_path,
)

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps this module importable standalone
    from ..domain.contracts import DiagnosisResult

__all__ = ["RiskAssessment", "score_risk"]

#: Risk levels ordered from least to most dangerous. The index is the rank used by
#: :func:`score_risk`; it must stay sorted.
_LEVEL_RANK: tuple[RiskLevel, ...] = (
    RiskLevel.NONE,
    RiskLevel.LOW,
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
)

#: A single added requirement line is a LOW-risk change. Two or more changed lines in a
#: dependency manifest is a MEDIUM-risk change.
_MAX_PIN_LINES_FOR_LOW: int = 2

#: Below this diagnosis confidence the evidence is too weak to be treated as a certain
#: fix, whatever the patch itself looks like.
_WEAK_EVIDENCE_CONFIDENCE: float = 0.5


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """The outcome of scoring one proposal.

    Attributes:
        level: The maximum risk level implied by the diagnosis and the patch.
        requires_human_review: True when a human must approve before application.
        reasons: One justification per rule that fired, including the baseline.

    """

    level: RiskLevel
    requires_human_review: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable payload using the contract field names."""
        return {
            "level": self.level.value,
            "requires_human_review": self.requires_human_review,
            "reasons": list(self.reasons),
        }


def score_risk(
    proposal: PatchProposal, diagnosis: DiagnosisResult, *, repo_root: Path | None = None
) -> RiskAssessment:
    """Return the deterministic risk assessment for ``proposal``.

    Args:
        proposal: The candidate patch.
        diagnosis: The diagnosis that produced it. Its risk level and human-review
            flag are the floor: this function can raise them, never lower them.
        repo_root: Optional repository root. When supplied, each changed path is
            verified against the repository, and a proposal that does not match the
            working tree is escalated.

    Returns:
        A :class:`RiskAssessment` with one reason per rule that fired.

    """
    findings: list[tuple[RiskLevel, bool, str]] = []
    findings.extend(_manifest_findings(proposal))
    findings.extend(_ci_findings(proposal))
    findings.extend(_test_findings(proposal))
    findings.extend(_lockfile_findings(proposal))
    findings.extend(_source_findings(proposal))
    findings.extend(_scope_findings(proposal))
    findings.extend(_diagnosis_findings(diagnosis))
    findings.extend(_repository_findings(proposal, repo_root))

    baseline_reason = (
        f"baseline: diagnosis {diagnosis.rule_id!r} reported risk_level "
        f"{diagnosis.risk_level.value} with requires_human_review="
        f"{str(diagnosis.requires_human_review).lower()}"
    )
    levels = [diagnosis.risk_level, *(level for level, _, _ in findings)]
    reviews = [diagnosis.requires_human_review, *(flag for _, flag, _ in findings)]
    return RiskAssessment(
        level=max(levels, key=_rank),
        requires_human_review=any(reviews),
        reasons=[baseline_reason, *(reason for _, _, reason in findings)],
    )


def _rank(level: RiskLevel) -> int:
    """Return the comparable rank of ``level``."""
    return _LEVEL_RANK.index(level)


def _changed_line_counts(file_patch: FilePatch) -> tuple[int, int]:
    """Return the number of added and removed lines implied by ``file_patch``.

    Line counts are derived from the file contents rather than parsed out of the diff,
    so a line that happens to look like a diff header cannot skew the count.
    """
    before = file_patch.before.splitlines()
    after = file_patch.after.splitlines()
    matcher = SequenceMatcher(a=before, b=after, autojunk=False)
    added = 0
    removed = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in {"delete", "replace"}:
            removed += i2 - i1
        if tag in {"insert", "replace"}:
            added += j2 - j1
    return added, removed


def _manifest_findings(proposal: PatchProposal) -> list[tuple[RiskLevel, bool, str]]:
    """Score changes to dependency manifests."""
    manifests = [f for f in proposal.files if is_dependency_manifest_path(f.path)]
    if not manifests:
        return []

    findings: list[tuple[RiskLevel, bool, str]] = []
    if len(manifests) > 1:
        findings.append(
            (
                RiskLevel.MEDIUM,
                True,
                "escalate to medium: the patch edits "
                f"{len(manifests)} dependency manifests at once",
            )
        )
        return findings

    file_patch = manifests[0]
    added, removed = _changed_line_counts(file_patch)
    changed = added + removed
    if removed or changed > _MAX_PIN_LINES_FOR_LOW:
        findings.append(
            (
                RiskLevel.MEDIUM,
                False,
                "dependency manifest edit: "
                f"{added} line(s) added and {removed} removed in "
                f"{normalize_relative_path(file_patch.path)}",
            )
        )
        return findings

    findings.append(
        (
            RiskLevel.LOW,
            False,
            f"dependency pin added in {normalize_relative_path(file_patch.path)} "
            f"({added} line(s) added, none removed)",
        )
    )
    return findings


def _ci_findings(proposal: PatchProposal) -> list[tuple[RiskLevel, bool, str]]:
    """Score changes to CI configuration, which are never low-risk."""
    paths = [normalize_relative_path(f.path) for f in proposal.files if is_ci_config_path(f.path)]
    paths = [path for path in paths if path is not None]
    if not paths:
        return []
    return [
        (
            RiskLevel.HIGH,
            True,
            "escalate to high: the patch changes CI configuration "
            f"({', '.join(paths)}), which decides which checks run at all",
        )
    ]


def _test_findings(proposal: PatchProposal) -> list[tuple[RiskLevel, bool, str]]:
    """Score changes to test code, which define the evidence of a fix."""
    paths = [normalize_relative_path(f.path) for f in proposal.files if is_test_path(f.path)]
    paths = [path for path in paths if path is not None]
    if not paths:
        return []
    return [
        (
            RiskLevel.HIGH,
            True,
            "escalate to high: the patch changes test code "
            f"({', '.join(paths)}), and a remediation must not judge its own homework",
        )
    ]


def _lockfile_findings(proposal: PatchProposal) -> list[tuple[RiskLevel, bool, str]]:
    """Score changes to lockfiles, which pin an entire dependency graph."""
    paths = [normalize_relative_path(f.path) for f in proposal.files if is_lockfile_path(f.path)]
    paths = [path for path in paths if path is not None]
    if not paths:
        return []
    return [
        (
            RiskLevel.HIGH,
            True,
            "escalate to high: the patch rewrites a lockfile "
            f"({', '.join(paths)}), which changes far more than the reported failure",
        )
    ]


def _source_findings(proposal: PatchProposal) -> list[tuple[RiskLevel, bool, str]]:
    """Score changes to ordinary source files."""
    source_paths = [
        path
        for path in (
            normalize_relative_path(f.path)
            for f in proposal.files
            if not (
                is_dependency_manifest_path(f.path)
                or is_ci_config_path(f.path)
                or is_test_path(f.path)
                or is_lockfile_path(f.path)
            )
        )
        if path is not None
    ]
    if not source_paths:
        return []
    return [
        (
            RiskLevel.MEDIUM,
            False,
            f"source change outside any manifest or configuration file: {', '.join(source_paths)}",
        )
    ]


def _scope_findings(proposal: PatchProposal) -> list[tuple[RiskLevel, bool, str]]:
    """Score the breadth of the change rather than its content."""
    findings: list[tuple[RiskLevel, bool, str]] = []
    file_count = len({f.path for f in proposal.files})
    if file_count > 1:
        findings.append(
            (
                RiskLevel.MEDIUM,
                True,
                f"escalate to medium: the patch spans {file_count} files, so the "
                "blast radius is wider than the reported failure",
            )
        )
    changed_lines = sum(
        added + removed for f in proposal.files for added, removed in [_changed_line_counts(f)]
    )
    if changed_lines > 20:
        findings.append(
            (
                RiskLevel.MEDIUM,
                True,
                f"escalate to medium: the patch changes {changed_lines} lines, which is "
                "a rewrite rather than a bounded fix",
            )
        )
    return findings


def _diagnosis_findings(
    diagnosis: DiagnosisResult,
) -> list[tuple[RiskLevel, bool, str]]:
    """Score the diagnosis itself, independently of the patch."""
    findings: list[tuple[RiskLevel, bool, str]] = []
    if diagnosis.requires_human_review:
        findings.append(
            (
                diagnosis.risk_level,
                True,
                "the diagnosis already requires human review "
                f"(rule_id={diagnosis.rule_id!r}), so that flag is preserved rather "
                "than cleared",
            )
        )
    if diagnosis.confidence < _WEAK_EVIDENCE_CONFIDENCE:
        findings.append(
            (
                RiskLevel.MEDIUM,
                True,
                "weak evidence: diagnosis confidence "
                f"{diagnosis.confidence:.2f} is below {_WEAK_EVIDENCE_CONFIDENCE:.2f}, so "
                "the proposed fix is a guess rather than a diagnosis",
            )
        )
    limitations = [item for item in diagnosis.limitations if item.strip()]
    if limitations:
        findings.append(
            (
                RiskLevel.NONE,
                False,
                f"the diagnosis reports {len(limitations)} limitation(s); they are "
                "recorded here rather than dropped, and do not themselves raise risk",
            )
        )
    return findings


def _repository_findings(
    proposal: PatchProposal, repo_root: Path | None
) -> list[tuple[RiskLevel, bool, str]]:
    """Verify the proposal against the repository on disk, when one is supplied."""
    if repo_root is None:
        return []

    findings: list[tuple[RiskLevel, bool, str]] = []
    for file_patch in proposal.files:
        normalized = normalize_relative_path(file_patch.path)
        if normalized is None:
            findings.append(
                (
                    RiskLevel.HIGH,
                    True,
                    f"unusable path {file_patch.path!r} in the proposal",
                )
            )
            continue
        target = repo_root / normalized
        if not target.exists():
            if file_patch.before.strip():
                findings.append(
                    (
                        RiskLevel.HIGH,
                        True,
                        f"the proposal edits {normalized}, which does not exist in the repository",
                    )
                )
            continue
        try:
            current = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            findings.append(
                (
                    RiskLevel.MEDIUM,
                    True,
                    f"{normalized} could not be read to confirm the patch matches the repository",
                )
            )
            continue
        if current != file_patch.before:
            findings.append(
                (
                    RiskLevel.HIGH,
                    True,
                    f"the contents of {normalized} in the repository do not match the "
                    "content the patch was generated from, so the patch is stale",
                )
            )
    return findings
