"""Deterministic remediation playbooks.

A playbook is a *narrow*, *well-understood* repair expressed as ordinary Python code. It
reads the evidence that a diagnosis already verified, and it either produces a bounded
:class:`~openmedic.remediation.patches.PatchProposal` or produces nothing.

The central rule is that ``None`` is a correct and expected answer. Every playbook here
returns ``None`` when:

* the evidence is ambiguous (more than one candidate cause, no cause at all, or a
  traceback frame that cannot be located in the repository);
* the fix would require a judgement call rather than a rule (naming an undefined
  symbol in a test, choosing a dependency version, editing a lockfile);
* the repository on disk does not match the evidence (a stale traceback).

A playbook never executes anything. It does not run ``pip``, ``git``, or the failing
command, and it never interprets model output as instructions: the only inputs are the
normalised :class:`~openmedic.domain.contracts.FailureEvent`, the
:class:`~openmedic.domain.contracts.DiagnosisResult`, and files read from the repository.
"""

from __future__ import annotations

import difflib
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

from ..domain.enums import FailureType, RecommendedAction
from .patches import FilePatch, PatchProposal, is_test_path, normalize_relative_path

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps runtime imports minimal
    from ..domain.contracts import DiagnosisResult, FailureEvent

__all__ = ["Playbook", "default_playbooks"]

#: The two failure classes an import problem can be reported under. Different diagnosis
#: rules label the same traceback differently, so both import playbooks accept both.
_IMPORT_FAILURE_TYPES: Final[frozenset[FailureType]] = frozenset(
    {FailureType.DEPENDENCY_ERROR, FailureType.SYNTAX_OR_IMPORT_ERROR}
)

#: Diagnosis recommendations that license a dependency change.
_DEPENDENCY_ACTIONS: Final[frozenset[RecommendedAction]] = frozenset(
    {
        RecommendedAction.FIX_DEPENDENCY,
        RecommendedAction.FIX_SYNTAX_OR_IMPORT,
        RecommendedAction.INVESTIGATE_MANUALLY,
    }
)

#: Diagnosis recommendations that license correcting an import statement.
_IMPORT_ACTIONS: Final[frozenset[RecommendedAction]] = frozenset(
    {
        RecommendedAction.FIX_SYNTAX_OR_IMPORT,
        RecommendedAction.FIX_DEPENDENCY,
        RecommendedAction.INVESTIGATE_MANUALLY,
    }
)

#: Similarity a module name must reach before it counts as the correction of a typo.
_TYPO_CUTOFF: Final = 0.85

_MODULE_NOT_FOUND_RE: Final = re.compile(
    r"(?:ModuleNotFoundError|ImportError)\s*:\s*No module named\s+['\"](?P<name>[^'\"]+)['\"]"
)
_NAME_ERROR_RE: Final = re.compile(
    r"NameError\s*:\s*name\s+['\"](?P<name>[^'\"]+)['\"]\s+is not defined"
)
_IDENTIFIER_RE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_FRAME_RE: Final = re.compile(
    r"^\s*File\s+\"(?P<file>[^\"]+)\",\s+line\s+(?P<line>\d+)(?:,\s+in\s+(?P<scope>.+?))?\s*$"
)
_IMPORT_LINE_RE: Final = re.compile(r"^\s*(?:from\s+[\w.]+\s+import\b|import\s+[\w.]+)")
_PYPROJECT_DEPENDENCIES_RE: Final = re.compile(r"^(\s*)dependencies\s*=\s*\[\s*$")
_STDLIB_MODULE_NAMES: Final[frozenset[str]] = frozenset(sys.stdlib_module_names)

#: Directories that never contain the repository's own importable modules.
_SKIPPED_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {
        ".eggs",
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "env",
        "node_modules",
        "venv",
    }
)


@dataclass(frozen=True, slots=True)
class Playbook:
    """A named, versioned, narrow repair strategy.

    Instances of this base class are intentionally inert: :meth:`build` raises, so a
    playbook that was never implemented fails loudly instead of silently returning
    ``None`` and being mistaken for "no fix applies". Use :func:`default_playbooks`
    for the implemented set.

    Attributes:
        playbook_id: Stable identifier recorded in ``RemediationAttempt.rule_id``.
        version: Playbook rule version, so a behaviour change is auditable.
        failure_type: The primary failure class this playbook is registered for.
        description: What the playbook does and when it declines.

    """

    playbook_id: str
    version: str
    failure_type: FailureType
    description: str

    def build(
        self,
        event: FailureEvent,
        diagnosis: DiagnosisResult,
        *,
        repo_root: Path | None = None,
    ) -> PatchProposal | None:
        """Return a bounded proposal for ``event``, or ``None``.

        Args:
            event: The normalised failure event carrying the raw log evidence.
            diagnosis: The diagnosis that classified the failure.
            repo_root: Optional repository root used to read the files being patched.

        Returns:
            A proposal, or ``None`` when this playbook does not apply with certainty.

        Raises:
            NotImplementedError: Always, on the base class.

        """
        msg = (
            f"playbook {self.playbook_id!r} does not implement build(); "
            "use default_playbooks() for the implemented set"
        )
        raise NotImplementedError(msg)

    def accepts(self, event: FailureEvent) -> bool:
        """Return whether this playbook is allowed to act on ``event``.

        A playbook acts on events of its own declared class. The two import playbooks
        additionally accept each other's class, because a ``ModuleNotFoundError`` is
        reported as either ``dependency_error`` or ``syntax_or_import_error`` depending
        on which diagnosis rule fired.
        """
        if event.failure_type is self.failure_type:
            return True
        return (
            self.failure_type in _IMPORT_FAILURE_TYPES
            and event.failure_type in _IMPORT_FAILURE_TYPES
        )


@dataclass(frozen=True, slots=True)
class _ImportTypoPlaybook(Playbook):
    """Correct a single misspelled module name in an import statement.

    Requires all of the following, and declines on anything less:

    * exactly one missing module named in the evidence;
    * exactly one available module (standard library or declared in this repository)
      that is a close match for the misspelling;
    * exactly one traceback frame importing that name, with its source line present;
    * a repository file at that frame whose line content still matches the evidence.

    Anything else — two plausible corrections, no source line, a moved file — leaves the
    incident for a human.
    """

    def build(
        self,
        event: FailureEvent,
        diagnosis: DiagnosisResult,
        *,
        repo_root: Path | None = None,
    ) -> PatchProposal | None:
        if not self.accepts(event):
            return None
        if diagnosis.recommended_action not in _IMPORT_ACTIONS:
            return None
        name = _single_missing_module(event.logs)
        if name is None:
            return None
        if name in _STDLIB_MODULE_NAMES:
            return None

        corrections = _typo_corrections(name, repo_root)
        if len(corrections) != 1:
            return None
        replacement = corrections[0]

        frames = _import_frames(event.logs, name)
        if len(frames) != 1:
            return None
        raw_path, line_number, source = frames[0]

        relative = _resolve_repository_path(raw_path, repo_root)
        if relative is None:
            return None
        content = _read_file(repo_root / relative)
        if content is None:
            return None

        after = _correct_identifier(content, line_number, source, name, replacement)
        if after is None or after == content:
            return None

        quote = _evidence_line(event.logs, name)
        return PatchProposal(
            files=(FilePatch(path=relative, before=content, after=after),),
            summary=f"Correct the misspelled import {name!r} to {replacement!r}",
            rationale=(
                f"The evidence names exactly one missing module, {name!r}, and exactly "
                f"one available module is a close match: {replacement!r}. "
                f"Offending statement: {quote!r}. "
                f"The change is a single identifier in {relative} line {line_number}."
            ),
        )


@dataclass(frozen=True, slots=True)
class _MissingModuleDependencyPlaybook(Playbook):
    """Declare a missing third-party module in the project's dependency manifest.

    Declines when the module is part of the standard library, when it already exists in
    this repository (an internal name, not a dependency), when it is a near-match of an
    available module (a misspelling, not a missing package), or when the repository has
    no manifest to add it to.

    No version is asserted: the evidence carries none, and inventing a version would be
    a guess dressed up as a fix.
    """

    def build(
        self,
        event: FailureEvent,
        diagnosis: DiagnosisResult,
        *,
        repo_root: Path | None = None,
    ) -> PatchProposal | None:
        if not self.accepts(event):
            return None
        if diagnosis.recommended_action not in _DEPENDENCY_ACTIONS:
            return None
        name = _single_missing_module(event.logs)
        if name is None:
            return None
        if name in _STDLIB_MODULE_NAMES:
            return None
        if _module_declared_in_repo(name, repo_root):
            return None
        if _typo_corrections(name, repo_root):
            # A close match means the name is misspelled, not missing. Adding the
            # misspelling to a manifest would install nothing and hide the real defect.
            return None

        manifest = _manifest_target(repo_root)
        if manifest is None:
            return None
        content = "" if repo_root is None else _read_file(repo_root / manifest)
        if content is None:
            return None
        if _already_declared(manifest, content, name):
            return None

        after = (
            _insert_pyproject_dependency(content, name)
            if manifest.endswith(".toml")
            else _append_requirement(content, name)
        )
        if after is None or after == content:
            return None

        quote = _evidence_line(event.logs, name)
        return PatchProposal(
            files=(FilePatch(path=manifest, before=content, after=after),),
            summary=f"Declare {name} in {manifest}",
            rationale=(
                f"The evidence names exactly one missing module, {name!r} "
                f"({quote!r}), and it is neither part of the standard library nor "
                "already present in this repository. The patch adds it to the project's "
                "dependency manifest with no version constraint, because the evidence "
                "carries no version to pin to. Validation decides whether that is "
                "enough; if the module does not exist, install will fail and the "
                "proposal is wrong."
            ),
        )


@dataclass(frozen=True, slots=True)
class _UndefinedNameInTestPlaybook(Playbook):
    """Recognise an undefined name in a test and deliberately propose nothing.

    This playbook exists so that the decision is explicit and auditable rather than an
    accident of no playbook matching. Introducing the missing name means changing what
    the test defines or expects, which is precisely the kind of change a remediation
    must not invent on its own.
    """

    def build(
        self,
        event: FailureEvent,
        diagnosis: DiagnosisResult,
        *,
        repo_root: Path | None = None,
    ) -> PatchProposal | None:
        if not self.accepts(event):
            return None
        if diagnosis.recommended_action is not RecommendedAction.FIX_FAILING_TEST:
            return None
        if _NAME_ERROR_RE.search(event.logs) is None:
            return None
        if repo_root is not None and not _failing_frame_is_test(event.logs, repo_root):
            # The undefined name is not in test code, so this playbook does not apply.
            return None
        return None


def default_playbooks() -> list[Playbook]:
    """Return the implemented playbooks in evaluation order.

    The order matters: the misspelling playbook is tried first because a correction is
    strictly safer than declaring a new dependency, and the dependency playbook
    declines on any name that has a close match.
    """
    return [
        _ImportTypoPlaybook(
            playbook_id="import-module-typo",
            version="1",
            failure_type=FailureType.SYNTAX_OR_IMPORT_ERROR,
            description=(
                "Corrects a misspelled module name in a single import statement, and "
                "only when exactly one missing module and exactly one close correction "
                "can be identified from the evidence."
            ),
        ),
        _MissingModuleDependencyPlaybook(
            playbook_id="missing-module-dependency",
            version="1",
            failure_type=FailureType.DEPENDENCY_ERROR,
            description=(
                "Declares a missing third-party module in requirements.txt or the "
                "[project] dependencies of pyproject.toml. Declines for standard-library "
                "names, modules already in the repository, misspellings, and "
                "repositories without a manifest."
            ),
        ),
        _UndefinedNameInTestPlaybook(
            playbook_id="undefined-name-in-test",
            version="1",
            failure_type=FailureType.TEST_FAILURE,
            description=(
                "Recognises NameError inside a test file and proposes nothing. "
                "Introducing the name changes what the test asserts, which requires a "
                "human decision."
            ),
        ),
    ]


def _single_missing_module(logs: str) -> str | None:
    """Return the single module named missing in ``logs``, or ``None`` if ambiguous."""
    names: list[str] = []
    for match in _MODULE_NOT_FOUND_RE.finditer(logs):
        name = match.group("name")
        if name not in names:
            names.append(name)
    if len(names) != 1:
        return None
    name = names[0]
    if _IDENTIFIER_RE.fullmatch(name) is None:
        # Dotted or otherwise irregular names ('pkg.mod') mean part of a package exists,
        # which is a different and much less certain repair.
        return None
    return name


def _evidence_line(logs: str, name: str) -> str:
    """Return the log line that named ``name`` as missing, for traceability."""
    for line in logs.splitlines():
        if "No module named" in line and name in line:
            return line.strip()
    return ""


def _import_frames(logs: str, name: str) -> list[tuple[str, int, str]]:
    """Return every traceback frame whose source line imports ``name``.

    Each entry is ``(path, line_number, source_line)``. A frame without a source line is
    skipped: that is the common CI case, and guessing the file to edit would not be a
    certain fix.
    """
    lines = logs.splitlines()
    frames: list[tuple[str, int, str]] = []
    for index, line in enumerate(lines):
        match = _FRAME_RE.match(line)
        if match is None or index + 1 >= len(lines):
            continue
        source = lines[index + 1]
        if not source.startswith((" ", "\t")):
            continue
        if not _imports_name(source, name):
            continue
        frames.append((match.group("file"), int(match.group("line")), source))
    return frames


def _imports_name(source: str, name: str) -> bool:
    """Return whether ``source`` is an import statement that imports ``name``."""
    stripped = source.strip()
    if _IMPORT_LINE_RE.match(stripped) is None:
        return False
    return re.search(rf"\b{re.escape(name)}\b", stripped) is not None


def _typo_corrections(name: str, repo_root: Path | None) -> list[str]:
    """Return the available modules that ``name`` could be a misspelling of."""
    available = set(_STDLIB_MODULE_NAMES)
    if repo_root is not None:
        available |= set(_repository_modules(repo_root))
    available.discard(name)
    matches = difflib.get_close_matches(name, sorted(available), n=2, cutoff=_TYPO_CUTOFF)
    return list(matches)


def _repository_modules(repo_root: Path) -> list[str]:
    """Return the importable top-level module names declared in the repository."""
    names: set[str] = set()
    for base in (repo_root, repo_root / "src"):
        if not base.is_dir():
            continue
        try:
            entries = sorted(base.iterdir(), key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in entries:
            if entry.name in _SKIPPED_DIRECTORIES or entry.name.startswith("."):
                continue
            if entry.is_dir() and (entry / "__init__.py").is_file():
                names.add(entry.name)
            elif entry.is_file() and entry.suffix == ".py":
                names.add(entry.stem)
    return sorted(names)


def _module_declared_in_repo(name: str, repo_root: Path | None) -> bool:
    """Return whether ``name`` is a module of this repository rather than a dependency."""
    if repo_root is None:
        return False
    return name in _repository_modules(repo_root)


def _resolve_repository_path(raw_path: str, repo_root: Path | None) -> str | None:
    """Map a traceback path onto a repository-relative path.

    CI runners report absolute paths such as ``/home/runner/work/repo/repo/src/app.py``.
    The mapping walks the path suffixes from longest to shortest and returns the first
    one that exists in the repository, which is why ``src/app.py`` wins over ``app.py``.
    """
    if repo_root is None:
        return None
    text = raw_path.strip().replace("\\", "/")
    if not text:
        return None
    pure = PurePosixPath(text)
    if pure.is_absolute():
        parts = [part for part in pure.parts if part not in {"/", "\\"}]
        for start in range(len(parts)):
            candidate = normalize_relative_path(PurePosixPath(*parts[start:]).as_posix())
            if candidate is not None and (repo_root / candidate).is_file():
                return candidate
        return None
    normalized = normalize_relative_path(text)
    if normalized is None:
        return None
    return normalized if (repo_root / normalized).is_file() else None


def _correct_identifier(
    content: str, line_number: int, source: str, old: str, new: str
) -> str | None:
    """Return ``content`` with ``old`` replaced by ``new`` on one line.

    The repository's line must still match the traceback's source line, otherwise the
    repository has moved on since the failure and the patch would be stale.
    """
    lines = content.splitlines(keepends=True)
    if line_number < 1 or line_number > len(lines):
        return None
    index = line_number - 1
    if lines[index].strip() != source.strip():
        return None
    pattern = re.compile(rf"\b{re.escape(old)}\b")
    occurrences = len(pattern.findall(lines[index]))
    if occurrences != 1:
        return None
    lines[index] = pattern.sub(lambda _match: new, lines[index], count=1)
    return "".join(lines)


def _failing_frame_is_test(logs: str, repo_root: Path) -> bool:
    """Return whether a traceback frame resolves to test code in ``repo_root``."""
    for match in _FRAME_RE.finditer(logs):
        relative = _resolve_repository_path(match.group("file"), repo_root)
        if relative is not None and is_test_path(relative):
            return True
    return False


def _manifest_target(repo_root: Path | None) -> str | None:
    """Return the repository-relative path of the dependency manifest to edit.

    Without a repository root the default is ``requirements.txt`` at the repository root.
    With one, the manifest must already exist: creating a dependency file for a project
    that has none is a decision for a human, not for a playbook.
    """
    if repo_root is None:
        return "requirements.txt"
    if (repo_root / "requirements.txt").is_file():
        return "requirements.txt"
    try:
        globbed = sorted(repo_root.glob("requirements*.txt"), key=lambda entry: entry.name)
    except OSError:
        globbed = []
    for entry in globbed:
        if entry.is_file():
            return entry.name
    if (repo_root / "pyproject.toml").is_file():
        return "pyproject.toml"
    return None


def _already_declared(manifest: str, content: str, name: str) -> bool:
    """Return whether ``name`` is already declared in ``manifest``."""
    if manifest.endswith(".toml"):
        return re.search(rf"[\"']{re.escape(name)}[\"']", content) is not None
    line_re = re.compile(rf"(?im)^\s*{re.escape(name)}\s*(?:[=<>!~@\[;#].*)?$")
    return line_re.search(content) is not None


def _append_requirement(content: str, name: str) -> str:
    """Return ``content`` with ``name`` appended as an unpinned requirement."""
    after = content
    if after and not after.endswith("\n"):
        after += "\n"
    return f"{after}{name}\n"


def _insert_pyproject_dependency(content: str, name: str) -> str | None:
    """Return ``content`` with ``name`` inserted into the ``[project]`` dependency list.

    Only the multi-line form is supported. A single-line list, a missing ``[project]``
    table, or an unclosed list returns ``None``: reflowing a compact array into a patch
    is more edit than a bounded repair should make.
    """
    lines = content.splitlines(keepends=True)
    in_project = False
    declaration: int | None = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_project = stripped == "[project]"
            continue
        match = _PYPROJECT_DEPENDENCIES_RE.match(line)
        if in_project and match is not None and declaration is None:
            declaration = index
            break
    if declaration is None:
        return None

    closing: int | None = None
    for index in range(declaration + 1, len(lines)):
        if lines[index].strip().startswith("]"):
            closing = index
            break
    if closing is None:
        return None

    indent = " " * (len(lines[declaration]) - len(lines[declaration].lstrip())) + "    "
    lines.insert(closing, f'{indent}"{name}",\n')
    return "".join(lines)


def _read_file(path: Path) -> str | None:
    """Return the UTF-8 content of ``path``, or ``None`` when it cannot be read."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
