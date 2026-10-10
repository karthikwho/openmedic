"""Rebuilding a patch from its stored diff.

``RemediationAttempt`` persists only unified diff text, so every later ``repair --apply``
or ``validate`` run has to recover literal file content from that text before it can
write anything. This file pins the inverse of :func:`render_unified_diff`: it must be
exact, and anything it cannot replay exactly must be refused rather than approximated.
"""

from __future__ import annotations

import hashlib

import pytest

from openmedic.domain.errors import InvalidInputError
from openmedic.remediation.patches import (
    FilePatch,
    PatchProposal,
    parse_unified_diff,
    render_unified_diff,
)


def _round_trip(*changes: tuple[str, str, str]) -> None:
    """Assert that rendering each change and parsing it back recovers all of them."""
    patches = tuple(
        FilePatch(path=path, before=before, after=after) for path, before, after in changes
    )
    proposal = PatchProposal(files=patches, summary="s", rationale="r")
    contents = {patch.path: patch.before for patch in patches}

    rebuilt = parse_unified_diff(proposal.unified_diff, contents=contents)

    assert rebuilt == patches


def test_a_single_line_addition_round_trips() -> None:
    """The shape the dependency playbook actually produces."""
    _round_trip(("requirements.txt", "flask\n", "flask\nrequests\n"))


def test_content_outside_the_context_window_is_recovered_from_the_file() -> None:
    """A diff carries three context lines, not the whole file, so the file fills the gap.

    This is why ``contents`` exists: replaying the diff alone would silently drop every
    line the diff never mentioned.
    """
    _round_trip(
        (
            "src/app.py",
            "import os\nimport sys\n" + "".join(f"# filler {i}\n" for i in range(10)),
            "import os\nimport json\n" + "".join(f"# filler {i}\n" for i in range(10)),
        ),
    )


def test_hunks_and_files_are_separated_correctly() -> None:
    """Both hunk boundaries and file boundaries survive the round trip."""
    _round_trip(
        (
            "src/a.py",
            "import os\nimport sys\n" + "".join(f"# filler {i}\n" for i in range(10)),
            "import os\nimport json\n" + "".join(f"# filler {i}\n" for i in range(10)),
        ),
        ("tests/test_a.py", "def test_a():\n    assert 1\n", "def test_a():\n    assert 2\n"),
        ("requirements.txt", "", "requests\n"),
    )


def test_file_creation_and_removal_round_trip() -> None:
    """An empty side of the diff is rebuilt as an empty file, not as a newline."""
    _round_trip(
        ("new.txt", "", "hello\n"),
        ("gone.txt", "bye\n", ""),
    )


def test_the_rebuilt_diff_keeps_the_recorded_patch_hash() -> None:
    """Patch identity is a hash of the diff text, so rebuilding must preserve it."""
    original = FilePatch(path="requirements.txt", before="flask\n", after="flask\nrequests\n")
    proposal = PatchProposal(files=(original,), summary="s", rationale="r")

    rebuilt = parse_unified_diff(proposal.unified_diff, contents={"requirements.txt": "flask\n"})
    rebuilt_proposal = PatchProposal(files=rebuilt, summary="s", rationale="r")

    assert rebuilt_proposal.patch_hash() == proposal.patch_hash()
    assert (
        proposal.patch_hash() == hashlib.sha256(proposal.unified_diff.encode("utf-8")).hexdigest()
    )


def test_empty_diff_text_is_refused() -> None:
    """There is nothing to rebuild, and guessing would invent content."""
    for text in ("", "   ", "\n"):
        with pytest.raises(InvalidInputError, match="empty diff text"):
            parse_unified_diff(text, contents={})


def test_text_without_a_file_header_is_refused() -> None:
    """Prose or a truncated header must not be read as a patch."""
    with pytest.raises(InvalidInputError, match="expected a file header"):
        parse_unified_diff("this is not a diff at all", contents={})


def test_a_hunk_that_ends_early_is_refused() -> None:
    """A cut-off hunk is refused instead of being applied with fewer lines."""
    diff = render_unified_diff("a.txt", "one\ntwo\nthree\n", "one\nTWO\nthree\n")
    truncated = "\n".join(diff.split("\n")[:5])

    with pytest.raises(InvalidInputError, match="ends before its counts"):
        parse_unified_diff(truncated, contents={"a.txt": "one\ntwo\nthree\n"})


def test_a_diff_that_does_not_replay_to_itself_is_refused() -> None:
    """A doctored diff is refused instead of being applied.

    ``RemediationAttempt.patch_unified_diff`` is what a later process writes from, so a
    diff whose text does not replay exactly must never become a patch on disk.
    """
    contents = {"requirements.txt": "flask\n"}
    honest = render_unified_diff("requirements.txt", "flask\n", "flask\nrequests\n")

    # A hunk header claiming more lines than the diff actually carries.
    inflated = honest.replace("@@ -1 +1,2 @@", "@@ -1 +1,3 @@")
    with pytest.raises(InvalidInputError, match="ends before its counts"):
        parse_unified_diff(inflated, contents=contents)

    # The added line dropped entirely, so the file would be written unchanged.
    dropped = "\n".join(line for line in honest.split("\n") if line != "+requests")
    with pytest.raises(InvalidInputError, match="ends before its counts"):
        parse_unified_diff(dropped, contents=contents)


def test_a_diff_that_does_not_match_the_file_is_refused() -> None:
    """Replaying against content the diff was not generated from cannot succeed."""
    honest = render_unified_diff("requirements.txt", "flask\n", "flask\nrequests\n")

    with pytest.raises(InvalidInputError, match="does not match the content"):
        parse_unified_diff(honest, contents={"requirements.txt": "django\n"})


def test_a_file_the_worktree_does_not_contain_is_refused() -> None:
    """An absent file reads as empty, which cannot satisfy a diff with context lines."""
    honest = render_unified_diff("requirements.txt", "flask\n", "flask\nrequests\n")

    with pytest.raises(InvalidInputError, match="does not match the content"):
        parse_unified_diff(honest, contents={})


def test_a_hunk_header_that_does_not_parse_is_refused() -> None:
    """A corrupted header cannot be turned into line counts."""
    with pytest.raises(InvalidInputError, match="unparseable hunk header"):
        parse_unified_diff("--- a/x\n+++ b/x\n@@ nonsense @@\n", contents={"x": ""})
