"""OpenMedic validation layer: allowlisted checks, isolation, and honest results.

The runner in :mod:`openmedic.validation.runner` is the only place a check is executed.
It depends on the domain layer for contracts and on :mod:`openmedic.validation.policy` for
the allowlist; no other layer reaches into it.
"""

from __future__ import annotations

from .isolation import (
    DOCKER_LIMITATIONS,
    KIND_DOCKER,
    KIND_LOCAL_SUBPROCESS,
    KIND_LOCAL_VENV,
    LOCAL_SUBPROCESS_LIMITATIONS,
    IsolationDecision,
    IsolationError,
    cleanup_workspace,
    detect_isolation,
    disposable_worktree,
    docker_argv,
    docker_available,
    make_venv,
    sanitized_environment,
    venv_bin_directory,
)
from .policy import (
    CHECK_PYTEST,
    CHECK_RUFF,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_POLICY,
    DEFAULT_TIMEOUT_SECONDS,
    CheckDefinition,
    CheckPolicy,
)
from .runner import (
    ValidationOutcome,
    ValidationRunner,
    is_stale,
    run_validation,
)

__all__ = [
    "CHECK_PYTEST",
    "CHECK_RUFF",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_POLICY",
    "DEFAULT_TIMEOUT_SECONDS",
    "DOCKER_LIMITATIONS",
    "KIND_DOCKER",
    "KIND_LOCAL_SUBPROCESS",
    "KIND_LOCAL_VENV",
    "LOCAL_SUBPROCESS_LIMITATIONS",
    "CheckDefinition",
    "CheckPolicy",
    "IsolationDecision",
    "IsolationError",
    "ValidationOutcome",
    "ValidationRunner",
    "cleanup_workspace",
    "detect_isolation",
    "disposable_worktree",
    "docker_argv",
    "docker_available",
    "is_stale",
    "make_venv",
    "run_validation",
    "sanitized_environment",
    "venv_bin_directory",
]
