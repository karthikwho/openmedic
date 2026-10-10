"""Isolation decisions and disposable workspaces.

This module answers two questions honestly: *what* isolation is actually available, and
*what* the candidate patch will be executed against. It deliberately does not let the
answer drift towards "container-safe" when no container exists.

The local fallback is a **constrained local subprocess**: the check is executed in a
disposable copy of the candidate tree with a scrubbed environment, a wall-clock timeout,
a bounded output capture, no shell, and no inherited stdin. That is a meaningful reduction
in blast radius and it is *not* a sandbox — it runs with the OpenMedic process's uid,
filesystem access, and kernel privileges, and it enforces no CPU, memory, disk, process,
or network limit. :data:`LOCAL_SUBPROCESS_LIMITATIONS` states this in the words that end
up in :class:`~openmedic.domain.contracts.ExecutionMetadata.limitations`, so a report can
never quietly imply equivalence with container isolation.

Two things this module never does, per ``docs/SECURITY.md`` rule 5:

* it never starts a Docker daemon, never uses ``--privileged``, and never mounts the host
  Docker socket;
* it never copies an SSH agent socket or any credential material into a workspace.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from ..domain.errors import OpenMedicError
from .policy import CheckDefinition

#: Isolation kinds recorded in ``ExecutionMetadata.isolation_kind``.
KIND_LOCAL_SUBPROCESS: Final = "local-subprocess"
KIND_LOCAL_VENV: Final = "local-venv"
KIND_DOCKER: Final = "docker"

#: Bound on the Docker availability probe. Probing must never hang a validation run.
DOCKER_PROBE_TIMEOUT_SECONDS: Final = 10.0

#: Bound on virtual-environment creation.
VENV_TIMEOUT_SECONDS: Final = 180.0

#: Default image for container execution. The image must already exist locally; OpenMedic
#: never pulls images over the network.
DOCKER_IMAGE: Final = "python:3.12-slim"

#: Environment variables a child process is allowed to see. Anything not listed here is
#: dropped, which is what makes a planted secret invisible to a check.
_ENV_ALLOWLIST: Final = (
    # Process essentials.
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "TEMP",
    "TMP",
    # Locale and terminal behaviour only.
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TZ",
    "NO_COLOR",
    # Windows process essentials (absent on POSIX, harmless when unset).
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "PATHEXT",
    "COMSPEC",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMFILES",
    "PROGRAMDATA",
)

#: Environment variable name fragments that are dropped even if they appear elsewhere.
_ENV_DENY_PREFIXES: Final = (
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "GITHUB_",
    "GH_",
    "GITLAB_",
    "OPENAI_",
    "ANTHROPIC_",
    "CLAUDE_",
    "DOCKER_",
    "SSH_",
    "GPG_",
    "KUBE",
    "VAULT_",
    "NPM_",
    "PYPI_",
    "NETRC",
    "TWILIO_",
    "STRIPE_",
    "SLACK_",
)

_ENV_DENY_SUFFIXES: Final = (
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
    "_API_KEY",
    "_APIKEY",
    "_ACCESS_KEY",
    "_PRIVATE_KEY",
    "_CREDENTIAL",
    "_CREDENTIALS",
    "_SESSION_KEY",
    "_KEY",
)

_ENV_DENY_EXACT: Final = frozenset(
    {
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "SSH_ASKPASS",
        "GPG_AGENT_INFO",
        "NETRC",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "FTP_PROXY",
    }
)

#: Directory and file names never reproduced in a disposable copy. VCS metadata, caches,
#: build output, local databases, and conventional credential files are excluded.
_COPY_EXCLUDED_NAMES: Final = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        ".coverage",
        "htmlcov",
        ".ipynb_checkpoints",
    }
)

#: Glob-style suffixes never copied. Credential files are excluded even when a project
#: commits them, because a repair environment must never receive production secrets.
_COPY_EXCLUDED_SUFFIXES: Final = (
    ".pyc",
    ".pyo",
    ".pyd",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".db-wal",
    ".db-shm",
    ".env",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".egg-info",
)

#: Honest limitations of a constrained local subprocess, surfaced in every result.
LOCAL_SUBPROCESS_LIMITATIONS: Final = (
    "local-subprocess is not a sandbox: checks run with this process's user, filesystem "
    "access, and kernel privileges.",
    "only wall-clock timeouts and output size bounds are enforced; CPU, memory, process, "
    "disk, and network limits are not.",
    "the candidate tree is a disposable copy so the original working tree stays untouched, "
    "but the rest of the filesystem is not protected.",
    "this mode must not be presented as equivalent to container isolation.",
)

#: Honest limitations of container execution.
DOCKER_LIMITATIONS: Final = (
    "container isolation depends on the host Docker daemon configuration, which OpenMedic "
    "cannot verify.",
    "the image must already exist locally; OpenMedic does not pull images over a network.",
    "no network access is granted unless the check policy explicitly allows it.",
    "the disposable candidate tree is bind-mounted rather than copied into the image, so "
    "container writes are visible on the host.",
)


class IsolationError(OpenMedicError):
    """A disposable workspace or isolation mode could not be prepared."""

    exit_code = 5


@dataclass(frozen=True, slots=True)
class IsolationDecision:
    """What isolation mode is in force for a validation run.

    ``kind`` is recorded verbatim in ``ExecutionMetadata.isolation_kind``. ``available``
    means "this mode can be used here"; it never means "this mode is secure".
    """

    kind: str
    available: bool
    limitations: list[str] = field(default_factory=list)
    reason: str = ""

    def __post_init__(self) -> None:
        """Copy ``limitations`` so a shared tuple or list cannot be mutated."""
        object.__setattr__(self, "limitations", list(self.limitations))


def _is_denied(name: str) -> bool:
    """Return whether an environment variable name is credential-shaped."""
    upper = name.upper()
    if upper in _ENV_DENY_EXACT:
        return True
    if any(upper.startswith(prefix) for prefix in _ENV_DENY_PREFIXES):
        return True
    return any(upper.endswith(suffix) for suffix in _ENV_DENY_SUFFIXES)


def sanitized_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the environment a check child process is allowed to see.

    The result is constructed from an explicit allowlist, so a variable is invisible to the
    child unless it is deliberately permitted — regardless of how sensitive its name looks.
    Credential-shaped names are dropped even if someone adds them to the allowlist.

    ``base`` defaults to the current process environment, which keeps ``PATH`` and ``HOME``
    usable while discarding everything else.
    """
    source: Mapping[str, str] = os.environ if base is None else base

    env: dict[str, str] = {}
    for name in _ENV_ALLOWLIST:
        value = source.get(name)
        if not isinstance(value, str) or not value or _is_denied(name):
            continue
        env[name] = value

    if not env.get("PATH"):
        env["PATH"] = os.defpath
    # Deterministic, colour-free, bytecode-free child output keeps excerpts comparable and
    # keeps writes inside the disposable tree.
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["NO_COLOR"] = "1"
    return env


def docker_available() -> bool:
    """Return whether a locally reachable Docker daemon can be used.

    The probe is read-only, bounded by a timeout, and never starts a daemon. ``DOCKER_HOST``
    is intentionally not honoured: only a daemon reachable through the default local socket
    counts, and a scrubbed environment is used for the probe so no host credential is
    involved in the decision.
    """
    executable = shutil.which("docker")
    if executable is None:
        return False
    argv = [executable, "version", "--format", "{{.Server.Version}}"]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, scrubbed env
            argv,
            capture_output=True,
            text=True,
            timeout=DOCKER_PROBE_TIMEOUT_SECONDS,
            env=sanitized_environment(),
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0 and bool(completed.stdout.strip())


def detect_isolation(prefer_docker: bool = True) -> IsolationDecision:
    """Return the strongest isolation mode that is honestly usable right now.

    When Docker is unavailable or not preferred the result is ``local-subprocess`` carrying
    :data:`LOCAL_SUBPROCESS_LIMITATIONS`, so the limitation travels with the record instead
    of living only in this module's docstring.
    """
    if prefer_docker and docker_available():
        return IsolationDecision(
            kind=KIND_DOCKER,
            available=True,
            limitations=list(DOCKER_LIMITATIONS),
            reason="Docker daemon reachable; checks will run in a disposable container.",
        )
    if prefer_docker:
        reason = (
            "Docker is unavailable in this environment (no docker executable or no "
            "reachable daemon); falling back to a constrained local subprocess."
        )
    else:
        reason = "Docker was not requested by the caller; using a constrained local subprocess."
    return IsolationDecision(
        kind=KIND_LOCAL_SUBPROCESS,
        available=True,
        limitations=list(LOCAL_SUBPROCESS_LIMITATIONS),
        reason=reason,
    )


def _excluded(name: str) -> bool:
    """Return whether a file or directory name is excluded from a disposable copy."""
    if name in _COPY_EXCLUDED_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in _COPY_EXCLUDED_SUFFIXES)


def _tracked_files(source: Path) -> list[str] | None:
    """Return the relative paths git tracks in ``source``, or ``None`` when unavailable.

    Using ``git ls-files`` keeps untracked files — including a developer's ``.env`` — out
    of the disposable copy. The command is read-only.
    """
    if not (source / ".git").exists():
        return None
    git = shutil.which("git")
    if git is None:
        return None
    argv = [git, "-C", str(source), "ls-files", "-z"]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, scrubbed env
            argv,
            capture_output=True,
            text=True,
            timeout=60.0,
            env=sanitized_environment(),
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    entries = [entry for entry in completed.stdout.split("\0") if entry]
    return entries or None


def _copy_into(source_root: Path, relative: str, target_root: Path) -> None:
    """Copy one source-relative path into ``target_root``, creating parents as needed."""
    destination = target_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    source = source_root / relative
    if source.is_dir():
        destination.mkdir(parents=True, exist_ok=True)
        return
    shutil.copyfile(source, destination)


def _copy_tree(source_root: Path, target_root: Path) -> None:
    """Copy a directory tree, skipping excluded names and all symlinks.

    Symlinks are not reproduced: a link that escapes the source tree would otherwise carry
    a host path into the disposable workspace.
    """
    for current, directories, files in os.walk(source_root, followlinks=False):
        directories[:] = sorted(name for name in directories if not _excluded(name))
        relative_dir = Path(current).relative_to(source_root)
        for name in sorted(files):
            if _excluded(name):
                continue
            candidate = Path(current) / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            destination = target_root / relative_dir / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate, destination)


def disposable_worktree(source: Path, target: Path) -> Path:
    """Create a disposable copy of ``source`` at ``target`` and return ``target``.

    Tracked files are preferred when ``source`` is a git checkout; otherwise the tree is
    walked directly. In both cases VCS metadata, caches, build output, local databases, and
    conventional credential files are excluded, and symlinks are not reproduced.

    The destination is never overwritten: an existing ``target`` is an error, so a caller
    cannot accidentally validate inside a real working tree.
    """
    root = Path(source)
    destination = Path(target)
    if not root.is_dir():
        msg = f"cannot copy a disposable worktree from {root}: not a directory"
        raise IsolationError(msg)
    if destination.exists():
        msg = f"refusing to overwrite existing disposable worktree {destination}"
        raise IsolationError(msg)

    destination.mkdir(parents=True)
    tracked = _tracked_files(root)
    if tracked is None:
        _copy_tree(root, destination)
        return destination
    for relative in tracked:
        if _excluded(Path(relative).name):
            continue
        _copy_into(root, relative, destination)
    return destination


def cleanup_workspace(path: Path) -> bool:
    """Remove ``path`` and report whether it is gone afterwards.

    Returns ``False`` instead of raising so a caller can record ``cleanup_ok`` truthfully
    while still returning the validation result it already produced.
    """
    target = Path(path)
    if target.is_symlink() or target.is_file():
        try:
            target.unlink()
        except OSError:
            return False
        return not target.exists()
    if not target.exists():
        return True
    try:
        shutil.rmtree(target)
    except OSError:
        return False
    return not target.exists()


def make_venv(target: Path, interpreter: str | None = None) -> Path:
    """Create a virtual environment at ``target`` and return its path.

    Creation is bounded by :data:`VENV_TIMEOUT_SECONDS` and runs with the sanitized
    environment. Failure raises :class:`IsolationError` rather than returning a path that
    does not contain a working interpreter, because a half-built venv would silently change
    what a check executes.
    """
    executable = interpreter or sys.executable
    destination = Path(target)
    if destination.exists():
        msg = f"refusing to overwrite existing venv target {destination}"
        raise IsolationError(msg)
    destination.parent.mkdir(parents=True, exist_ok=True)

    argv = [executable, "-m", "venv", str(destination)]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, scrubbed env
            argv,
            capture_output=True,
            text=True,
            timeout=VENV_TIMEOUT_SECONDS,
            env=sanitized_environment(),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        msg = f"venv creation timed out after {VENV_TIMEOUT_SECONDS}s for {destination}"
        raise IsolationError(msg) from exc
    except OSError as exc:
        msg = f"cannot run {executable} to create a venv at {destination}: {exc}"
        raise IsolationError(msg) from exc

    interpreter_dir = "Scripts" if os.name == "nt" else "bin"
    if completed.returncode != 0 or not (destination / interpreter_dir).is_dir():
        msg = (
            f"venv creation failed for {destination} "
            f"(exit {completed.returncode}): {completed.stderr.strip()[:500]}"
        )
        raise IsolationError(msg)
    return destination


def docker_argv(
    check: CheckDefinition,
    worktree: Path,
    *,
    image: str = DOCKER_IMAGE,
    allow_network: bool = False,
    memory: str = "1g",
    cpus: str = "1",
    pids_limit: int = 256,
) -> list[str]:
    """Build the ``docker run`` argv for ``check`` inside ``worktree``.

    The argv is constructed here rather than as a string so a command can never be
    reinterpreted by a shell. Resource limits, capability dropping, and
    ``no-new-privileges`` are always present; there is no option for ``--privileged``, a
    host Docker socket mount, ``--network host``, or host PID/IPC namespaces, and no host
    environment variable is forwarded — only ``check.env``.
    """
    tree = str(Path(worktree).resolve())
    argv = [
        "docker",
        "run",
        "--rm",
        "--network",
        "bridge" if allow_network else "none",
        "--pids-limit",
        str(pids_limit),
        "--memory",
        memory,
        "--cpus",
        cpus,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65534:65534" if os.name != "nt" else "ContainerUser",
        # A small private tmpfs gives checks a writable scratch area without touching the
        # bind-mounted candidate tree's parent directories.
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",  # noqa: S108 - container-internal tmpfs, size-bounded
        "--mount",
        f"type=bind,source={tree},target={tree}",
        "--workdir",
        tree,
    ]
    for key, value in check.env.items():
        argv.extend(["--env", f"{key}={value}"])
    argv.append(image)
    argv.extend(list(check.command))
    return argv


def venv_bin_directory(venv_path: Path) -> Path:
    """Return the ``bin`` (POSIX) or ``Scripts`` (Windows) directory of a venv."""
    name = "Scripts" if os.name == "nt" else "bin"
    return Path(venv_path) / name
