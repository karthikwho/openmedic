"""Unified diff construction and the deterministic patch-safety policy.

This module owns the immutable description of a candidate change (:class:`FilePatch`,
:class:`PatchProposal`), the *only* place in OpenMedic that writes a patch to disk
(:func:`apply_patch_proposal`), and the rejection policy
(:func:`evaluate_patch_safety`).

Three properties are load-bearing and are therefore enforced here rather than assumed:

1. **Patch identity.** ``patch_hash`` is a SHA-256 over the exact unified diff string
   that the caller can see. It is what binds a :class:`ValidationResult` to a specific
   candidate, so it must never be recomputed a different way.
2. **Diff text and hash cannot disagree.** The rendered diff is trimmed at both ends so
   that ``sha256(attempt.patch_unified_diff)`` equals ``attempt.patch_hash``. See
   :func:`render_unified_diff` for the one consequence of that trimming.
3. **Nothing is ever executed.** Applying a patch writes the literal ``after`` text into
   a worktree the caller supplies. No shell, no parser, no hook, no ``git``.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Final

from ..domain.errors import InvalidInputError, PolicyViolationError
from ..domain.redaction import redact

__all__ = [
    "MAX_CHANGED_LINES",
    "TEST_FILE_DIRECTORIES",
    "TEST_FILE_GLOBS",
    "FilePatch",
    "PatchProposal",
    "apply_patch_proposal",
    "evaluate_patch_safety",
    "is_ci_config_path",
    "is_dependency_manifest_path",
    "is_lockfile_path",
    "is_sensitive_path",
    "is_test_path",
    "normalize_relative_path",
    "parse_unified_diff",
    "render_unified_diff",
]

#: Upper bound on the number of added plus removed lines in one proposal. A patch that
#: is larger than this is a rewrite, not a bounded remediation.
MAX_CHANGED_LINES: Final = 500

#: Basenames that mark a file as test code. Matching is done with :mod:`fnmatch` on the
#: file name only, so a directory can never change the answer.
TEST_FILE_GLOBS: Final[tuple[str, ...]] = (
    "test.py",
    "test_*.py",
    "tests.py",
    "conftest.py",
    "test_*.js",
    "*.test.js",
    "*.spec.js",
    "test_*.ts",
    "*.spec.ts",
    "test_*.jsx",
    "*.test.jsx",
    "test_*.tsx",
    "*_test.go",
    "*_test.rs",
    "*.Test.java",
    "*Test.java",
    "test_*.rb",
    "*_spec.rb",
    "test_*.php",
)

#: Directory names whose contents are test code.
TEST_FILE_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {"test", "tests", "spec", "__tests__", "e2e", "testdata"}
)

#: Paths that configure the CI pipeline itself. Touching these is not automatically
#: unsafe, but it is never low-risk (see ``remediation.risk``).
_CI_CONFIG_TOP_LEVEL: Final[frozenset[str]] = frozenset(
    {".github", ".gitlab-ci.yml", ".circleci", "azure-pipelines.yml", "Jenkinsfile"}
)
_CI_CONFIG_EXACT: Final[frozenset[str]] = frozenset(
    {
        ".appveyor.yml",
        ".buildkite/pipeline.yml",
        ".drone.yml",
        ".gitea/workflows",
        ".forgejo/workflows",
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
        ".semaphore/semaphore.yml",
        ".travis.yml",
        ".woodpecker.yml",
        "Jenkinsfile",
        "appveyor.yml",
        "azure-pipelines.yml",
        "bitbucket-pipelines.yml",
        "cloudbuild.yaml",
        "codecov.yml",
        "netlify.toml",
        "tox.ini",
        ".codecov.yml",
    }
)

#: Files that declare dependencies rather than implement behaviour.
_DEPENDENCY_MANIFEST_BASENAMES: Final[frozenset[str]] = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "requirements_dev.txt",
        "requirements-base.txt",
        "dev-requirements.txt",
        "setup.cfg",
        "setup.py",
        "Pipfile",
    }
)
_REQUIREMENTS_FILENAME_RE: Final = re.compile(r"^requirements(?:[-_.][A-Za-z0-9_.-]+)?\.txt$")

#: Lockfiles pin an entire dependency graph; editing one by hand is never a small fix.
_LOCKFILE_BASENAMES: Final[frozenset[str]] = frozenset(
    {
        "Cargo.lock",
        "Gemfile.lock",
        "Pipfile.lock",
        "composer.lock",
        "go.sum",
        "package-lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "yarn.lock",
    }
)

#: Paths that hold credentials or repository plumbing. A patch must never touch these.
_SENSITIVE_BASENAMES: Final[frozenset[str]] = frozenset(
    {
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "id_ed25519",
    }
)
_SENSITIVE_SUFFIXES: Final[tuple[str, ...]] = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")
_SENSITIVE_SEGMENTS: Final[frozenset[str]] = frozenset({".git", ".ssh", ".gnupg", ".aws"})

_ASSERTION_HINT_RE: Final = re.compile(
    r"\bassert\b|assert[A-Z]\w*\s*\(|\bexpect\s*\(|\bpytest\.raises\b"
)
_TEST_DEFINITION_RE: Final = re.compile(r"^\s*(?:async\s+)?def\s+(?:test\w*)\s*\(", re.MULTILINE)
_SILENT_SWALLOW_RE: Final = re.compile(r"except\s+(?:Exception|BaseException)\b")
_PASS_ONLY_RE: Final = re.compile(r"^\s*pass\s*$")

#: (label, pattern) pairs for lines that switch a check off or hide its failure.
_SUPPRESSION_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("a blanket lint suppression", re.compile(r"#\s*(?:ruff|flake8)\s*:\s*noqa")),
    ("a 'noqa' lint suppression", re.compile(r"#\s*noqa\b")),
    ("a 'nosec' security-check suppression", re.compile(r"#\s*nosec\b")),
    ("a 'type: ignore' suppression", re.compile(r"#\s*type\s*:\s*ignore\b")),
    ("a pylint suppression", re.compile(r"#\s*pylint\s*:\s*disable")),
    ("a pytest deselector", re.compile(r"""-k\s*=?\s*['"]?\s*not\s""")),
    ("a git pre-commit bypass", re.compile(r"--no-verify\b")),
    ("a shell exit-code mask", re.compile(r"\|\|\s*(?:true|:|0|exit\s+0)\b")),
    ("a disabled errexit", re.compile(r"\bset\s+\+e\b")),
    ("CI error tolerance", re.compile(r"continue-on-error\s*:\s*true")),
    ("a disabled pytest plugin", re.compile(r"-p\s+no:")),
    ("a pytest skip/xfail marker", re.compile(r"@pytest\.mark\.(?:skip|skipif|xfail)\b")),
    ("a unittest skip marker", re.compile(r"@unittest\.skip")),
)

#: Added lines that introduce code execution inside the patched tree. A remediation
#: playbook never needs to add these; a proposal that does is not a bounded fix.
_EXECUTION_HINT_RE: Final = re.compile(
    r"(?:\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\()"
    r"|(?:\bos\.(?:system|popen|exec[lvpe]+|spawn[lvpe]+|fork)\s*\()"
    r"|(?:(?<![\w.])eval\s*\()"
    r"|(?:(?<![\w.])exec\s*\()"
    r"|(?:\bshell\s*=\s*True)"
)


@dataclass(frozen=True, slots=True)
class FilePatch:
    """One file's before and after content.

    ``path`` is always relative to the repository root, using forward slashes. The
    class deliberately does not validate the path: a malformed path is *reported* by
    :func:`evaluate_patch_safety` and refused by :func:`apply_patch_proposal` rather
    than raising at construction time, so that a malicious proposal stays inspectable.
    """

    path: str
    before: str
    after: str

    @property
    def unified_diff(self) -> str:
        """Return the deterministic unified diff for this file.

        The diff is trimmed at both ends (see :func:`render_unified_diff`). It is empty
        exactly when ``before == after``.
        """
        return render_unified_diff(self.path, self.before, self.after)

    @property
    def patch_hash(self) -> str | None:
        """Return the SHA-256 of :attr:`unified_diff`, or ``None`` for no change."""
        diff = self.unified_diff
        return hashlib.sha256(diff.encode("utf-8")).hexdigest() if diff else None


@dataclass(frozen=True, slots=True)
class PatchProposal:
    """A bounded set of file changes with its rationale."""

    files: tuple[FilePatch, ...]
    summary: str
    rationale: str

    @property
    def unified_diff(self) -> str:
        """Return the concatenation of every file diff, in proposal order."""
        return "\n".join(diff for diff in (f.unified_diff for f in self.files) if diff)

    def patch_hash(self) -> str | None:
        """Return the SHA-256 of :attr:`unified_diff`, or ``None`` for no change."""
        diff = self.unified_diff
        return hashlib.sha256(diff.encode("utf-8")).hexdigest() if diff else None

    def touches_file(self, path: str) -> bool:
        """Return whether this proposal changes ``path``.

        Paths are compared after normalisation, so ``./src/app.py`` and ``src/app.py``
        are the same file.
        """
        wanted = normalize_relative_path(path)
        return any(normalize_relative_path(f.path) == wanted for f in self.files)

    def is_noop(self) -> bool:
        """Return whether every file in the proposal keeps its current content."""
        return all(f.before == f.after for f in self.files)


def render_unified_diff(path: str, before: str, after: str) -> str:
    """Return a unified diff from ``before`` to ``after`` for ``path``.

    The diff is generated with :func:`difflib.unified_diff` and trimmed at both ends.
    The trimming exists so the text can never disagree with its own hash:
    ``RemediationAttempt.patch_unified_diff`` is a contract field declared with
    ``str_strip_whitespace=True``, which strips surrounding whitespace on validation.
    Without trimming here, that field would store a different string from the one that
    was hashed.

    The only visible consequence is that a blank line at the very end of a changed file
    is not repeated as the last line of the diff text. Application is unaffected:
    :func:`apply_patch_proposal` writes ``after`` verbatim instead of parsing the diff.

    Args:
        path: Repository-relative path of the changed file.
        before: Current file content.
        after: Target file content.

    Returns:
        The unified diff, or an empty string when there is no change.

    """
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    )
    return "".join(diff).strip()


#: ``@@ -old_start,old_count +new_start,new_count @@`` with either count optional.
_HUNK_HEADER_RE: Final = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(text: str, *, contents: Mapping[str, str | None]) -> tuple[FilePatch, ...]:
    """Rebuild the file patches that ``text`` describes.

    This is the inverse of :func:`render_unified_diff`, and it exists because a
    :class:`~openmedic.domain.contracts.RemediationAttempt` stores only the diff text: a
    command running in a different process from the one that proposed the patch has to
    recover literal file content before it can write anything.

    A unified diff is *not* self-contained — it carries changed regions plus three lines
    of context, so everything outside that window is missing from it. ``contents``
    supplies the current content of each file, and the hunks are replayed onto it. That
    also makes the check honest: if the file no longer matches the diff, the reconstruction
    does not match the stored text and the patch is refused as stale.

    Every rebuilt file is re-rendered and compared with the text it came from, so a diff
    that was truncated, doctored, or written by another tool is refused rather than
    approximated — writing an approximation would put content on disk that nobody
    reviewed.

    Args:
        text: A diff previously produced by :func:`render_unified_diff`.
        contents: Current content per repository-relative path, or ``None`` when the file
            does not exist. Paths absent from the mapping are treated as missing.

    Returns:
        One :class:`FilePatch` per file, in the order they appear.

    Raises:
        InvalidInputError: If ``text`` is empty, structurally malformed, does not match
            ``contents``, or does not render back to itself.

    """
    if not text.strip():
        msg = "cannot rebuild a patch from empty diff text"
        raise InvalidInputError(msg)

    lines = text.split("\n")
    files: list[FilePatch] = []
    index = 0
    while index < len(lines):
        header_start = index
        if not lines[index].startswith("--- "):
            msg = f"malformed diff: expected a file header, found {lines[index][:60]!r}"
            raise InvalidInputError(msg)
        if index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
            msg = "malformed diff: a '--- ' header is not followed by a '+++ ' header"
            raise InvalidInputError(msg)
        path = _diff_target_path(lines[index + 1])
        index += 2

        before = contents.get(path) or ""
        before_lines = _content_lines(before)
        after_lines, index = _replay_hunks(path, lines, index, before_lines)

        segment = "\n".join(lines[header_start:index])
        patch = FilePatch(path=path, before=before, after=_content(after_lines, before))
        rendered = render_unified_diff(patch.path, patch.before, patch.after)
        if rendered != segment:
            msg = (
                f"refusing to rebuild {path}: replaying its diff produces different text "
                "than the diff itself, so the stored patch cannot be trusted"
            )
            raise InvalidInputError(msg)
        files.append(patch)

    if not files:
        msg = "malformed diff: no file headers found"
        raise InvalidInputError(msg)
    return tuple(files)


def _replay_hunks(
    path: str, lines: list[str], index: int, before_lines: list[str]
) -> tuple[list[str], int]:
    """Return the rebuilt ``after`` lines and the index just past the file's hunks."""
    after_lines: list[str] = []
    cursor = 0
    while index < len(lines) and lines[index].startswith("@@"):
        old_start, old_count, new_count = _hunk_header(lines[index])
        index += 1
        start = 0 if old_start == 0 else old_start - 1
        if start < cursor or start > len(before_lines):
            msg = (
                f"malformed diff for {path}: hunk starts at line {old_start}, which does "
                f"not follow the content before it"
            )
            raise InvalidInputError(msg)
        # Lines the diff does not mention are unchanged, so they pass through.
        after_lines.extend(before_lines[cursor:start])
        cursor = start

        old_seen = 0
        new_seen = 0
        while old_seen < old_count or new_seen < new_count:
            if index >= len(lines):
                msg = f"malformed diff for {path}: a hunk ends before its counts"
                raise InvalidInputError(msg)
            line = lines[index]
            index += 1
            if line.startswith("\\"):
                continue  # "\ No newline at end of file" carries no content
            if line.startswith("+"):
                after_lines.append(line[1:])
                new_seen += 1
                continue
            if line.startswith("-"):
                expected = line[1:]
            else:
                # Context: a leading space, or nothing at all when .strip() removed the
                # single trailing space of the diff's final line.
                expected = line[1:] if line.startswith(" ") else line
                after_lines.append(expected)
                new_seen += 1
            if cursor >= len(before_lines) or before_lines[cursor] != expected:
                msg = (
                    f"refusing to rebuild {path}: the stored diff does not match the "
                    "content it would be applied to"
                )
                raise InvalidInputError(msg)
            cursor += 1
            old_seen += 1

    after_lines.extend(before_lines[cursor:])
    return after_lines, index


def _hunk_header(header: str) -> tuple[int, int, int]:
    """Return the old start line and the old and new line counts of a hunk header."""
    match = _HUNK_HEADER_RE.match(header)
    if match is None:
        msg = f"malformed diff: unparseable hunk header {header[:60]!r}"
        raise InvalidInputError(msg)
    old_start = int(match.group(1))
    old_count = 1 if match.group(2) is None else int(match.group(2))
    new_count = 1 if match.group(4) is None else int(match.group(4))
    return old_start, old_count, new_count


def _diff_target_path(header: str) -> str:
    """Return the repository-relative path named by a ``+++`` diff header."""
    path = header[4:].strip()
    return path[2:] if path.startswith(("a/", "b/")) else path


def _content_lines(content: str) -> list[str]:
    """Split ``content`` into lines, without inventing a trailing empty one."""
    if not content:
        return []
    lines = content.split("\n")
    if content.endswith("\n"):
        lines.pop()
    return lines


def _content(lines: list[str], like: str) -> str:
    """Join ``lines`` back into file content, mirroring ``like``'s final newline.

    A diff cannot say whether the last line ended with a newline — the rendered text is
    trimmed, and the contract field trims it again — so the convention is inherited from
    the file the patch was applied to rather than guessed.
    """
    if not lines:
        return ""
    joined = "\n".join(lines)
    if like.endswith("\n") or not like:
        return joined + "\n"
    return joined


def normalize_relative_path(path: str) -> str | None:
    """Return ``path`` as a clean POSIX relative path, or ``None`` when unusable.

    Absolute paths, home-relative paths, Windows drive letters, empty paths, and any
    path containing a ``..`` segment are rejected.
    """
    if not isinstance(path, str):
        return None
    candidate = path.strip().replace("\\", "/")
    if not candidate or candidate.startswith(("/", "~")) or "\x00" in candidate:
        return None
    if re.match(r"^[A-Za-z]:", candidate):
        return None
    parts = [part for part in PurePosixPath(candidate).parts if part not in {".", ""}]
    if not parts or any(part == ".." for part in parts):
        return None
    return PurePosixPath(*parts).as_posix()


def is_test_path(path: str) -> bool:
    """Return whether ``path`` is test code, by name or by parent directory."""
    normalized = normalize_relative_path(path)
    if normalized is None:
        return False
    pure = PurePosixPath(normalized)
    if any(fnmatch(pure.name, pattern) for pattern in TEST_FILE_GLOBS):
        return True
    return any(part in TEST_FILE_DIRECTORIES for part in pure.parts[:-1])


def is_ci_config_path(path: str) -> bool:
    """Return whether ``path`` configures the CI pipeline."""
    normalized = normalize_relative_path(path)
    if normalized is None:
        return False
    pure = PurePosixPath(normalized)
    if pure.parts[0] in _CI_CONFIG_TOP_LEVEL:
        return True
    return normalized in _CI_CONFIG_EXACT


def is_dependency_manifest_path(path: str) -> bool:
    """Return whether ``path`` declares dependencies."""
    normalized = normalize_relative_path(path)
    if normalized is None:
        return False
    pure = PurePosixPath(normalized)
    if _REQUIREMENTS_FILENAME_RE.match(pure.name):
        return True
    if pure.name in _DEPENDENCY_MANIFEST_BASENAMES:
        return True
    # pip accepts ``-r requirements/base.txt``, so a file inside a requirements/
    # directory declares dependencies whatever it happens to be called. Over-classifying
    # is the safe direction: dependency paths are scored as higher risk, not lower.
    return any(part == "requirements" for part in pure.parts[:-1])


def is_lockfile_path(path: str) -> bool:
    """Return whether ``path`` is a lockfile."""
    normalized = normalize_relative_path(path)
    if normalized is None:
        return False
    return PurePosixPath(normalized).name in _LOCKFILE_BASENAMES


def is_sensitive_path(path: str) -> bool:
    """Return whether ``path`` holds credentials or repository plumbing."""
    normalized = normalize_relative_path(path)
    if normalized is None:
        return False
    pure = PurePosixPath(normalized)
    if any(part in _SENSITIVE_SEGMENTS for part in pure.parts):
        return True
    if pure.name in _SENSITIVE_BASENAMES:
        return True
    if pure.name.startswith(".env"):
        return True
    return pure.name.endswith(_SENSITIVE_SUFFIXES)


def evaluate_patch_safety(proposal: PatchProposal) -> list[str]:
    """Return every reason ``proposal`` must not be applied.

    An empty list means the proposal is allowed to be *proposed*. It still has to clear
    the risk policy in :mod:`openmedic.remediation.risk` and the file-count policy in
    :class:`~openmedic.remediation.engine.RemediationEngine`, and it still has to pass
    validation before anything is claimed fixed.

    Args:
        proposal: The candidate patch to inspect.

    Returns:
        A list of human-readable reasons. Empty means safe.

    """
    if not proposal.files:
        return ["proposal changes no files"]

    reasons: list[str] = []
    changed_lines = 0
    for file_patch in proposal.files:
        normalized = normalize_relative_path(file_patch.path)
        if normalized is None:
            reasons.append(f"unusable file path {file_patch.path!r}")
            continue
        added, removed = _changed_lines(file_patch.before, file_patch.after)
        changed_lines += len(added) + len(removed)
        reasons.extend(_file_reasons(normalized, file_patch, added, removed))

    if proposal.is_noop():
        reasons.append("proposal produces no change")
    if changed_lines > MAX_CHANGED_LINES:
        reasons.append(
            f"proposal changes {changed_lines} lines, above the "
            f"{MAX_CHANGED_LINES}-line bound for a bounded remediation"
        )
    return reasons


def apply_patch_proposal(proposal: PatchProposal, *, worktree: Path) -> list[Path]:
    """Write ``proposal`` into ``worktree`` and return the paths that were written.

    This is the only function in OpenMedic that writes a patch, and it is deliberately
    narrow: it validates the proposal against the safety policy, resolves every target
    path inside ``worktree``, refuses stale patches, and writes literal text. It never
    spawns a process, calls ``git``, or interprets anything derived from model output.

    Args:
        proposal: The candidate patch to apply. It must already be safe.
        worktree: The disposable directory to write into. It is created if missing and
            must never be the caller's live working tree.

    Returns:
        The resolved paths that were written.

    Raises:
        PolicyViolationError: If the proposal is unsafe, escapes the worktree, targets a
            secret-bearing path, or does not match the content already present.

    """
    reasons = evaluate_patch_safety(proposal)
    if reasons:
        msg = "refusing to apply an unsafe patch: " + "; ".join(reasons)
        raise PolicyViolationError(msg)

    root = worktree.resolve()
    written: list[Path] = []
    for file_patch in proposal.files:
        target = _resolve_within(root, file_patch.path)
        existing = target.read_text(encoding="utf-8") if target.is_file() else None
        if existing is not None and existing != file_patch.before:
            msg = (
                f"refusing to apply a stale patch: {file_patch.path} does not contain "
                "the content the patch was generated from"
            )
            raise PolicyViolationError(msg)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(file_patch.after, encoding="utf-8", newline="")
        written.append(target)
    return written


def _file_reasons(
    normalized: str, file_patch: FilePatch, added: list[str], removed: list[str]
) -> list[str]:
    """Return the safety reasons contributed by a single file patch."""
    reasons: list[str] = []
    if is_sensitive_path(normalized):
        reasons.append(f"touches a secret-bearing or VCS-internal path: {normalized}")

    if not added and not removed:
        reasons.append(f"{normalized}: the patch changes nothing")
        return reasons
    if not file_patch.after.strip():
        reasons.append(f"deletes the entire contents of {normalized}")
        return reasons

    if is_test_path(normalized):
        reasons.extend(_test_integrity_reasons(normalized, file_patch.before, file_patch.after))
    reasons.extend(_suppression_reasons(normalized, added))
    reasons.extend(_assertion_reasons(normalized, removed))
    reasons.extend(_secret_reasons(normalized, added))
    reasons.extend(_execution_reasons(normalized, added))
    return reasons


def _test_integrity_reasons(normalized: str, before: str, after: str) -> list[str]:
    """Return reasons why a change to a test file would weaken its coverage."""
    reasons: list[str] = []
    before_defs = len(_TEST_DEFINITION_RE.findall(before))
    after_defs = len(_TEST_DEFINITION_RE.findall(after))
    if after_defs < before_defs:
        reasons.append(
            f"removes {before_defs - after_defs} test function(s) from the test file {normalized}"
        )
    before_asserts = _count_assertions(before)
    after_asserts = _count_assertions(after)
    if after_asserts < before_asserts:
        reasons.append(
            f"removes {before_asserts - after_asserts} assertion(s) from the test file {normalized}"
        )
    before_lines = len(before.splitlines())
    after_lines = len(after.splitlines())
    if before_lines and after_lines < before_lines / 2:
        reasons.append(
            f"truncates the test file {normalized} from {before_lines} to {after_lines} lines"
        )
    return reasons


def _count_assertions(text: str) -> int:
    """Return the number of assertion-like lines in ``text``."""
    return sum(1 for line in text.splitlines() if _ASSERTION_HINT_RE.search(line))


def _suppression_reasons(normalized: str, added: list[str]) -> list[str]:
    """Return reasons for added lines that switch a check off or hide a failure."""
    reasons: list[str] = []
    for line in added:
        for label, pattern in _SUPPRESSION_PATTERNS:
            if pattern.search(line):
                reasons.append(f"{normalized}: introduces {label}: {line.strip()!r}")
    swallows = [line for line in added if _SILENT_SWALLOW_RE.search(line)]
    passes = [line for line in added if _PASS_ONLY_RE.match(line)]
    if swallows and passes:
        reasons.append(f"{normalized}: swallows {swallows[0].strip()!r} and continues with 'pass'")
    return reasons


def _assertion_reasons(normalized: str, removed: list[str]) -> list[str]:
    """Return reasons for removed lines that carried an assertion."""
    reasons: list[str] = []
    for line in removed:
        if _ASSERTION_HINT_RE.search(line):
            reasons.append(f"{normalized}: removes an assertion: {line.strip()!r}")
    return reasons


def _secret_reasons(normalized: str, added: list[str]) -> list[str]:
    """Return reasons for added lines that contain secret-like material."""
    reasons: list[str] = []
    for line in added:
        detections = redact(line).detections
        if detections:
            kinds = sorted({detection.kind for detection in detections})
            reasons.append(
                f"{normalized}: introduces secret-like material ({', '.join(kinds)}) "
                "which must never be persisted or sent to a provider"
            )
    return reasons


def _execution_reasons(normalized: str, added: list[str]) -> list[str]:
    """Return reasons for added lines that introduce code or command execution."""
    reasons: list[str] = []
    for line in added:
        if _EXECUTION_HINT_RE.search(line):
            reasons.append(
                f"{normalized}: introduces code or command execution, which no bounded "
                f"playbook should do: {line.strip()!r}"
            )
    return reasons


def _changed_lines(before: str, after: str) -> tuple[list[str], list[str]]:
    """Return the exact ``(added, removed)`` lines between two texts.

    Computed with :class:`difflib.SequenceMatcher` on line lists rather than by parsing
    the rendered diff, so a content line that happens to start with ``---`` or ``+++``
    (a YAML document separator, for example) is never mistaken for a diff header.
    """
    old_lines = before.splitlines()
    new_lines = after.splitlines()
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    removed: list[str] = []
    added: list[str] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in {"delete", "replace"}:
            removed.extend(old_lines[i1:i2])
        if tag in {"insert", "replace"}:
            added.extend(new_lines[j1:j2])
    return added, removed


def _resolve_within(root: Path, raw_path: str) -> Path:
    """Resolve ``raw_path`` inside ``root``, refusing anything that escapes it.

    Args:
        root: The already-resolved worktree root.
        raw_path: The repository-relative path to resolve.

    Returns:
        The resolved absolute path, guaranteed to be inside ``root``.

    Raises:
        PolicyViolationError: If the path is unusable or escapes the worktree.

    """
    normalized = normalize_relative_path(raw_path)
    if normalized is None:
        msg = f"refusing to write to an unusable path: {raw_path!r}"
        raise PolicyViolationError(msg)
    if is_sensitive_path(normalized):
        msg = f"refusing to write to a secret-bearing path: {normalized}"
        raise PolicyViolationError(msg)
    target = (root / normalized).resolve()
    if target != root and root not in target.parents:
        msg = f"refusing to write outside the disposable worktree: {raw_path!r}"
        raise PolicyViolationError(msg)
    return target
