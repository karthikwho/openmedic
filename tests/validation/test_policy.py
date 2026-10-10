"""Policy tests: allowlisting, argv hygiene, and read-only detection.

The policy is the boundary that stops a command from ever coming from an untrusted source,
so these tests focus on what it refuses to accept as much as what it accepts.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from openmedic.domain.errors import PolicyViolationError
from openmedic.validation.policy import (
    CHECK_PYTEST,
    CHECK_RUFF,
    DEFAULT_POLICY,
    CheckDefinition,
    CheckPolicy,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "hello_repo"


def _snapshot(root: Path) -> set[str]:
    """Return the set of relative paths under ``root``."""
    return {str(path.relative_to(root)) for path in root.rglob("*")}


def test_default_policy_exposes_pytest_and_ruff() -> None:
    """The default policy names its checks and marks pytest as the required gate."""
    assert DEFAULT_POLICY.names == (CHECK_PYTEST, CHECK_RUFF)
    assert DEFAULT_POLICY.allow(CHECK_PYTEST) is not None
    assert DEFAULT_POLICY.allow(CHECK_PYTEST).required is True
    assert DEFAULT_POLICY.allow(CHECK_RUFF).required is False
    assert DEFAULT_POLICY.max_output_bytes > 0
    assert DEFAULT_POLICY.default_timeout_seconds > 0


def test_allow_returns_only_exact_matches() -> None:
    """A near-miss name is never resolved to a similar check."""
    policy = CheckPolicy(checks=(CheckDefinition(name=CHECK_PYTEST, command=["pytest", "-q"]),))
    for near_miss in ("", " ", "PYTEST", "pytest2", " pytest", "pytest ", "pytest/check"):
        assert policy.allow(near_miss) is None, near_miss
    assert policy.allow(CHECK_PYTEST) is not None
    assert policy.allow(CHECK_PYTEST).command == ["pytest", "-q"]


def test_command_must_be_argv_not_a_command_string() -> None:
    """A single opaque string containing shell syntax is a configuration error."""
    with pytest.raises(PolicyViolationError):
        CheckDefinition(name="pytest", command=["pytest -q"])
    with pytest.raises(PolicyViolationError):
        CheckDefinition(name="pytest", command=["pytest; rm -rf /"])
    with pytest.raises(PolicyViolationError):
        CheckDefinition(name="pytest", command=["pytest", ""])


def test_empty_command_is_rejected() -> None:
    """A check with no argv could never be executed."""
    with pytest.raises(PolicyViolationError):
        CheckDefinition(name="pytest", command=[])


def test_non_positive_timeout_is_rejected() -> None:
    """A zero or negative timeout would mean "no limit", which is not a bound."""
    with pytest.raises(PolicyViolationError):
        CheckDefinition(name="pytest", command=["pytest"], timeout_seconds=0.0)
    with pytest.raises(PolicyViolationError):
        CheckDefinition(name="pytest", command=["pytest"], timeout_seconds=-1.0)


def test_duplicate_check_names_are_rejected() -> None:
    """Two checks sharing a name would make a record ambiguous."""
    with pytest.raises(PolicyViolationError):
        CheckPolicy(
            checks=(
                CheckDefinition(name="pytest", command=["pytest"]),
                CheckDefinition(name="pytest", command=["pytest", "-q"]),
            )
        )


def test_definition_copies_mutable_fields() -> None:
    """Mutating the caller's list or dict cannot change an approved definition."""
    command = ["pytest", "-q"]
    extra_env = {"MODE": "strict"}
    definition = CheckDefinition(name="pytest", command=command, env=extra_env)
    command.append("--tb=short")
    extra_env["MODE"] = "relaxed"
    assert definition.command == ["pytest", "-q"]
    assert definition.env == {"MODE": "strict"}


def test_detect_reads_the_fixture_project() -> None:
    """Detection discovers the fixture's pytest and Ruff configuration."""
    policy = CheckPolicy.detect(FIXTURE_ROOT)
    assert policy.names == (CHECK_PYTEST, CHECK_RUFF)
    assert policy.allow(CHECK_PYTEST).command == ["pytest", "-q"]
    assert policy.allow(CHECK_RUFF).command == ["ruff", "check", "."]


def test_detect_finds_pytest_from_a_tests_directory(tmp_path: Path) -> None:
    """A ``tests`` directory alone is enough to enable the test-suite check."""
    (tmp_path / "tests").mkdir()
    policy = CheckPolicy.detect(tmp_path)
    assert policy.names == (CHECK_PYTEST,)
    assert policy.allow(CHECK_RUFF) is None


def test_detect_without_signals_returns_no_checks(tmp_path: Path) -> None:
    """An unrecognised project yields an empty, therefore unsatisfiable, policy."""
    policy = CheckPolicy.detect(tmp_path)
    assert policy.checks == ()
    assert policy.required_names() == ()


def test_detect_survives_a_malformed_pyproject(tmp_path: Path) -> None:
    """A broken ``pyproject.toml`` must not raise and must not invent checks."""
    (tmp_path / "pyproject.toml").write_text("this is not = valid toml ][", encoding="utf-8")
    policy = CheckPolicy.detect(tmp_path)
    assert policy.checks == ()


def test_detect_is_read_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Detection executes nothing and writes nothing, even against untrusted input."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n[tool.ruff]\n", encoding="utf-8"
    )
    (project / "src").mkdir()
    (project / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    before = _snapshot(project)

    def _forbid(*args: object, **kwargs: object) -> None:
        msg = "detection must not execute a process"
        raise AssertionError(msg)

    monkeypatch.setattr(subprocess, "run", _forbid)
    monkeypatch.setattr(subprocess, "Popen", _forbid)

    policy = CheckPolicy.detect(project)

    assert policy.names == (CHECK_PYTEST, CHECK_RUFF)
    assert _snapshot(project) == before
