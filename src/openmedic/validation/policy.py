"""Allowlisted validation-check policy.

The validation runner never accepts a command string from a caller, a model, a log, or a
patch. It executes only checks that are named in a :class:`CheckPolicy`, and each check
carries its own argv. Two rules follow from that and are enforced here rather than by
convention:

1. **Exact-name allowlisting.** :meth:`CheckPolicy.allow` looks a check up by its exact
   name. An unknown name yields ``None`` — it is never substituted with a "similar"
   check, and never widened into "run whatever the project defines".
2. **No shell surface.** A declared command is a list of argv entries. The first entry
   must look like a real executable name, so an accidental ``"pytest -q"`` (one opaque
   string) is a configuration error instead of a confusing "file not found".

Detection is read-only: :meth:`CheckPolicy.detect` parses ``pyproject.toml`` and looks at
directory names, and never executes a tool, never imports the candidate project, and
never writes to disk.

Note on trust: the child ``PATH`` is inherited from the operator's environment (see
:func:`openmedic.validation.isolation.sanitized_environment`), so executable *resolution*
is an operator-environment concern while executable *selection* is not. Everything else in
the child environment is dropped.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from ..domain.errors import PolicyViolationError

#: Canonical name of the project test-suite check.
CHECK_PYTEST: Final = "pytest"

#: Canonical name of the lint check. Optional by default: a lint finding is a code-quality
#: signal, not proof that a repair is unsafe, so it must not silently gate recovery.
CHECK_RUFF: Final = "ruff"

#: Characters that cannot appear in a real executable name. They are shell syntax or
#: whitespace, so their presence means the entry was written as a command line rather than
#: as argv.
_FORBIDDEN_EXECUTABLE_CHARS: Final = frozenset(";|&`$><\n\r\t \\\"'*?[]{}()")

#: Default wall-clock budget for a single check, in seconds.
DEFAULT_TIMEOUT_SECONDS: Final = 300.0

#: Default bound on captured stdout/stderr bytes retained per check.
DEFAULT_MAX_OUTPUT_BYTES: Final = 65536


def _reject(message: str) -> None:
    """Raise a :class:`PolicyViolationError` for a malformed check definition."""
    raise PolicyViolationError(message)


def _validate_executable(name: str, executable: str) -> None:
    """Reject an executable entry that could never name a real program."""
    if not executable:
        _reject(f"check {name!r} declares an empty executable name")
    if "\x00" in executable:
        _reject(f"check {name!r} declares a NUL byte in its executable name")
    bad = sorted(_FORBIDDEN_EXECUTABLE_CHARS.intersection(executable))
    if bad:
        _reject(
            f"check {name!r} declares executable {executable!r} containing shell "
            f"syntax characters {bad!r}; declare argv as a list, not a command string"
        )


def _validate_definition(check: CheckDefinition) -> None:
    """Validate one check definition, raising :class:`PolicyViolationError` on defects."""
    name = check.name
    if not name or not name.strip():
        _reject("a check name must be a non-empty string")
    if any(character.isspace() for character in name):
        _reject(f"check name {name!r} must not contain whitespace")
    if check.timeout_seconds <= 0:
        _reject(f"check {name!r} must declare a positive timeout_seconds")
    if not check.command:
        _reject(f"check {name!r} declares no command")
    _validate_executable(name, check.command[0])
    for argument in check.command:
        if not isinstance(argument, str):
            _reject(f"check {name!r} declares a non-string argv entry: {argument!r}")
        if not argument:
            _reject(f"check {name!r} declares an empty argv entry")
        if "\x00" in argument:
            _reject(f"check {name!r} declares a NUL byte in an argv entry")
    for key, value in check.env.items():
        if not key or "\x00" in key or "=" in key:
            _reject(f"check {name!r} declares an invalid environment variable name {key!r}")
        if not isinstance(value, str) or "\x00" in value:
            _reject(f"check {name!r} declares an invalid environment value for {key!r}")


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    """One allowlisted validation check.

    ``name`` is the stable identifier used by records and reports; ``command`` is the exact
    argv that will be executed. Nothing here is derived from repository content, model
    output, or environment variables supplied by an untrusted source.
    """

    name: str
    command: list[str]
    required: bool = True
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    description: str = ""
    env: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate the definition and copy mutable fields defensively."""
        # Copying prevents a caller from mutating a policy after it has been approved.
        object.__setattr__(self, "command", list(self.command))
        object.__setattr__(self, "env", dict(self.env))
        _validate_definition(self)

    @property
    def executable(self) -> str:
        """Return the declared executable name (``command[0]``)."""
        return self.command[0]

    def argv(self) -> list[str]:
        """Return a fresh copy of the exact argv to execute."""
        return list(self.command)


def _has_tool_section(config: dict[str, Any], tool: str) -> bool:
    """Return whether ``config`` declares a ``[tool.<tool>]`` table."""
    tools = config.get("tool")
    return isinstance(tools, dict) and isinstance(tools.get(tool), dict)


def _read_pyproject(path: Path) -> dict[str, Any]:
    """Parse ``path`` as TOML, returning an empty mapping when it is absent or invalid.

    A malformed ``pyproject.toml`` is not a validation failure in itself; it simply means
    detection has nothing to go on, which yields a policy with no checks. That is the safe
    direction: no checks means no pass.
    """
    try:
        raw = path.read_bytes()
    except (OSError, ValueError):
        return {}
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


@dataclass(frozen=True, slots=True)
class CheckPolicy:
    """The set of checks a candidate patch may be validated against.

    An empty policy is legal and deliberately unsatisfiable: with no checks there is no
    evidence, so :class:`~openmedic.domain.contracts.ValidationResult` cannot pass.
    """

    checks: tuple[CheckDefinition, ...] = ()
    default_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    allow_network: bool = False

    def __post_init__(self) -> None:
        """Validate the policy and normalise ``checks`` to a tuple."""
        object.__setattr__(self, "checks", tuple(self.checks))
        seen: set[str] = set()
        for check in self.checks:
            if not isinstance(check, CheckDefinition):
                _reject(f"policy entries must be CheckDefinition instances, got {check!r}")
            if check.name in seen:
                _reject(f"duplicate check name {check.name!r} in policy")
            seen.add(check.name)
        if self.default_timeout_seconds <= 0:
            _reject("policy default_timeout_seconds must be positive")
        if self.max_output_bytes <= 0:
            _reject("policy max_output_bytes must be positive")

    @classmethod
    def detect(cls, project_root: Path) -> CheckPolicy:
        """Discover a policy for ``project_root`` by reading files only.

        The project's own test and lint tools are discovered from ``pyproject.toml`` and the
        presence of a ``tests`` directory. Detection performs no execution, no import, and
        no writes, so it is safe to call against an untrusted checkout.
        """
        root = Path(project_root)
        config = _read_pyproject(root / "pyproject.toml")

        checks: list[CheckDefinition] = []
        uses_pytest = _has_tool_section(config, "pytest") or (root / "tests").is_dir()
        if uses_pytest:
            checks.append(
                CheckDefinition(
                    name=CHECK_PYTEST,
                    command=["pytest", "-q"],
                    required=True,
                    description="Run the project test suite with pytest.",
                )
            )
        if _has_tool_section(config, "ruff"):
            checks.append(
                CheckDefinition(
                    name=CHECK_RUFF,
                    command=["ruff", "check", "."],
                    required=False,
                    description="Lint the candidate tree with Ruff.",
                )
            )
        return cls(checks=tuple(checks))

    def allow(self, name: str) -> CheckDefinition | None:
        """Return the check named exactly ``name``, or ``None`` when it is not allowlisted.

        A near-miss name is not resolved to a similar check. Callers must treat ``None`` as
        "this check may not run", never as "run something sensible instead".
        """
        for check in self.checks:
            if check.name == name:
                return check
        return None

    @property
    def names(self) -> tuple[str, ...]:
        """Return the allowlisted check names in declaration order."""
        return tuple(check.name for check in self.checks)

    def required_names(self) -> tuple[str, ...]:
        """Return the names of checks whose omission blocks a pass."""
        return tuple(check.name for check in self.checks if check.required)


#: The policy used when a caller does not supply one.
DEFAULT_POLICY: Final[CheckPolicy] = CheckPolicy(
    checks=(
        CheckDefinition(
            name=CHECK_PYTEST,
            command=["pytest", "-q"],
            required=True,
            description="Run the project test suite with pytest.",
        ),
        CheckDefinition(
            name=CHECK_RUFF,
            command=["ruff", "check", "."],
            required=False,
            description="Lint the candidate tree with Ruff.",
        ),
    ),
)

__all__ = [
    "CHECK_PYTEST",
    "CHECK_RUFF",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_POLICY",
    "DEFAULT_TIMEOUT_SECONDS",
    "CheckDefinition",
    "CheckPolicy",
]
