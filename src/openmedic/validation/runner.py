"""Validation runner.

This layer turns a :class:`~openmedic.domain.contracts.RemediationAttempt` plus a
disposable candidate workspace into an honest
:class:`~openmedic.domain.contracts.ValidationResult`.

The rules it exists to enforce:

* **Every check really runs.** Each check is spawned as argv with :func:`subprocess.Popen`
  (never ``shell=True``), with ``stdin`` closed, a per-check wall-clock timeout, and a
  sanitized environment. Output is captured through temporary files so a check that emits
  gigabytes of text cannot exhaust memory, and only a bounded, redacted excerpt is kept.
* **No fake passes.** ``passed`` is computed here, never trusted from a caller: it is true
  only when at least one check ran and none is a blocking failure. A skipped, missing,
  timed-out, or errored *required* check, or a non-zero exit, yields ``passed=False``. An
  empty policy yields an empty ``checks_executed`` and therefore cannot pass — the same
  thing :func:`openmedic.domain.contracts._validate_honesty` already refuses to represent.
* **Staleness is detectable.** The result records ``candidate_patch_hash``, and
  :func:`is_stale` reports a result produced for a different patch. Recovery through
  :func:`openmedic.domain.lifecycle.apply_transition` rejects it.
* **Cleanup is reported.** A timeout or crash still cleans the disposable workspace, and a
  failed cleanup is recorded as ``cleanup_ok=False`` rather than assumed.

A timeout kills the child's whole process group on POSIX, so a check that spawns its own
children cannot outlive the check.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from contextlib import suppress as _suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from ..domain.contracts import (
    CheckResult,
    ExecutionMetadata,
    RemediationAttempt,
    ValidationResult,
    redact_excerpt,
    utc_now,
)
from ..domain.enums import CheckStatus
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
    docker_argv,
    docker_available,
    make_venv,
    sanitized_environment,
)
from .policy import DEFAULT_POLICY, CheckDefinition, CheckPolicy

#: Bound on how long a killed child is given to be reaped after a timeout.
_REAP_TIMEOUT_SECONDS: Final = 5.0

#: Limitations appended to every result, describing the runner's own residual risk.
_RUNNER_LIMITATIONS: Final = (
    "checks are resolved from the sanitized child PATH; executable selection is "
    "allowlisted, but resolution still depends on the operator's PATH",
    "output excerpts are bounded and redacted, so a failing detail outside the bound may "
    "not appear in the record",
)

_POSIX: Final = os.name == "posix"


@dataclass(slots=True)
class ValidationOutcome:
    """A validation result plus whether the disposable workspace was cleaned up."""

    result: ValidationResult
    cleanup_ok: bool


def is_stale(attempt: RemediationAttempt, result: ValidationResult) -> bool:
    """Return whether ``result`` was produced for a different patch than ``attempt``.

    A result is stale when its ``candidate_patch_hash`` is absent — an unbound result can
    never justify recovery — or when it differs from the attempt's ``patch_hash``. Callers
    use this before handing a result to
    :func:`openmedic.domain.lifecycle.apply_transition`, which enforces the same rule.
    """
    if result.candidate_patch_hash is None:
        return True
    if attempt.patch_hash is None:
        return True
    return attempt.patch_hash != result.candidate_patch_hash


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    """Kill a timed-out child and, on POSIX, its whole process group."""
    if _POSIX:
        with _suppress(OSError):
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            return
    with _suppress(OSError):
        process.kill()


@dataclass(slots=True)
class _Run:
    """Raw outcome of one child process."""

    exit_code: int | None
    timed_out: bool
    launch_error: str | None
    duration_seconds: float


@dataclass(slots=True)
class _Context:
    """Everything one batch of checks needs, including the venv scratch dir."""

    isolation: IsolationDecision
    worktree: Path
    venv: Path | None = None
    staging: Path | None = None
    venv_error: str | None = None


class ValidationRunner:
    """Execute allowlisted checks against a disposable candidate workspace."""

    def __init__(
        self,
        policy: CheckPolicy = DEFAULT_POLICY,
        *,
        isolation: IsolationDecision | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Store the policy, isolation decision, and clock.

        ``isolation`` defaults to :func:`~openmedic.validation.isolation.detect_isolation`
        at validation time rather than construction time, so a runner built while Docker was
        reachable does not silently keep claiming a container after it disappears. ``clock``
        is injectable so timestamps can be deterministic in tests.
        """
        self.policy = policy
        self.isolation = isolation
        self._clock = clock or utc_now
        self._docker_probe: bool | None = None

    # ------------------------------------------------------------------ public

    def run_checks(self, names: Sequence[str], *, worktree: Path) -> list[CheckResult]:
        """Execute the named checks in ``worktree``, returning one result per name.

        An empty ``names`` runs the whole policy. A name the policy does not allow yields a
        ``MISSING`` **required** result: a check the caller asked for must block a pass
        rather than disappear. A missing or unreadable ``worktree`` makes every check
        ``SKIPPED`` with its configured ``required`` flag intact, so nothing passes.
        """
        with self._execution_context(worktree) as context:
            return self._run_named(list(names), context)

    def validate(
        self,
        attempt: RemediationAttempt,
        *,
        worktree: Path,
        candidate_hash: str | None = None,
    ) -> ValidationResult:
        """Run the whole policy against ``worktree`` and build the result for ``attempt``.

        ``candidate_hash`` overrides the patch identity recorded on the result. When absent
        it falls back to ``attempt.patch_hash``; when both are absent the result is left
        unbound and carries a limitation saying so, which keeps recovery impossible rather
        than guessing an identity.
        """
        started = self._clock()
        with self._execution_context(worktree) as context:
            checks = self._run_named([], context)
        completed = self._clock()
        return self._build_result(
            attempt=attempt,
            checks=checks,
            candidate_hash=candidate_hash,
            context=context,
            started=started,
            completed=completed,
        )

    def validate_and_cleanup(
        self,
        attempt: RemediationAttempt,
        *,
        worktree: Path,
        candidate_hash: str | None = None,
    ) -> ValidationOutcome:
        """Validate ``attempt`` and then remove the disposable ``worktree``.

        Cleanup happens after validation regardless of outcome, so a timeout or crash does
        not leave the candidate tree behind. ``cleanup_ok`` is ``False`` when removal could
        not be completed; the validation result itself is still returned.
        """
        result = self.validate(attempt, worktree=worktree, candidate_hash=candidate_hash)
        return ValidationOutcome(result=result, cleanup_ok=cleanup_workspace(Path(worktree)))

    # --------------------------------------------------------------- internals

    def _resolve_isolation(self) -> IsolationDecision:
        """Return the configured isolation decision, detecting one when necessary."""
        if self.isolation is not None:
            return self.isolation
        return detect_isolation()

    def _docker_seen(self, isolation: IsolationDecision) -> bool:
        """Return whether Docker was used or reachable, probing at most once."""
        if isolation.kind == KIND_DOCKER:
            return True
        if self._docker_probe is None:
            self._docker_probe = docker_available()
        return self._docker_probe

    @contextmanager
    def _execution_context(self, worktree: Path) -> Iterator[_Context]:
        """Prepare a validation batch and always tear down its scratch venv."""
        context = _Context(isolation=self._resolve_isolation(), worktree=Path(worktree))
        if context.isolation.kind == KIND_LOCAL_VENV:
            staging = Path(tempfile.mkdtemp(prefix="openmedic-venv-"))
            context.staging = staging
            try:
                context.venv = make_venv(staging / "venv")
            except IsolationError as exc:
                context.venv_error = exc.message
                cleanup_workspace(staging)
                context.staging = None
        try:
            yield context
        finally:
            if context.staging is not None:
                cleanup_workspace(context.staging)

    def _run_named(self, names: Sequence[str], context: _Context) -> list[CheckResult]:
        """Execute the named checks (or the whole policy) inside ``context``."""
        requested = list(names) or list(self.policy.names)

        workspace_usable = context.worktree.is_dir() and os.access(
            context.worktree, os.R_OK | os.X_OK
        )

        results: list[CheckResult] = []
        seen: set[str] = set()
        for name in requested:
            if name in seen:
                continue
            seen.add(name)
            check = self.policy.allow(name)
            if check is None:
                results.append(self._unknown_result(name))
                continue
            if context.venv_error is not None:
                results.append(
                    self._errored_result(
                        check,
                        f"could not prepare the local venv: {context.venv_error}",
                    )
                )
                continue
            if not workspace_usable:
                results.append(
                    self._skipped_result(
                        check,
                        f"candidate workspace {context.worktree} is missing or "
                        "unreadable; the check was not executed",
                    )
                )
                continue
            results.append(self._execute(check, context))
        return results

    def _child_env(self, check: CheckDefinition, context: _Context) -> dict[str, str]:
        """Build the child environment: sanitized ambient env plus declared extras."""
        env = sanitized_environment()
        if context.venv is not None:
            venv_bin = context.venv / ("Scripts" if os.name == "nt" else "bin")
            if venv_bin.is_dir():
                env["PATH"] = os.pathsep.join([str(venv_bin), env.get("PATH", "")])
        for key, value in check.env.items():
            env[key] = value
        return env

    def _execute(self, check: CheckDefinition, context: _Context) -> CheckResult:
        """Run one check and translate the outcome into a :class:`CheckResult`."""
        isolation = context.isolation
        env = self._child_env(check, context)

        argv: list[str]
        if isolation.kind == KIND_DOCKER:
            argv = docker_argv(
                check,
                context.worktree,
                allow_network=self.policy.allow_network,
            )
        else:
            argv = check.argv()
            if shutil.which(check.command[0], path=env.get("PATH")) is None:
                return self._missing_tool_result(
                    check,
                    f"executable {check.command[0]!r} was not found on the sanitized PATH",
                )

        with tempfile.TemporaryDirectory(prefix="openmedic-check-") as scratch:
            scratch_dir = Path(scratch)
            stdout_path = scratch_dir / "stdout.txt"
            stderr_path = scratch_dir / "stderr.txt"
            run = self._spawn(
                argv=argv,
                cwd=context.worktree,
                env=env,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                timeout=check.timeout_seconds,
            )
            stdout_text = _read_bounded(stdout_path, self.policy.max_output_bytes)
            stderr_text = _read_bounded(stderr_path, self.policy.max_output_bytes)

        status = _status_for(run)
        return CheckResult(
            name=check.name,
            command=argv,
            status=status,
            exit_code=run.exit_code,
            duration_seconds=round(run.duration_seconds, 6),
            required=check.required,
            stdout_excerpt=redact_excerpt(stdout_text),
            stderr_excerpt=redact_excerpt(stderr_text),
        )

    def _spawn(
        self,
        *,
        argv: list[str],
        cwd: Path,
        env: dict[str, str],
        stdout_path: Path,
        stderr_path: Path,
        timeout: float,
    ) -> _Run:
        """Run ``argv`` with bounded output files, returning its raw outcome."""
        started = time.monotonic()
        try:
            with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
                process = subprocess.Popen(  # noqa: S603 - fixed argv list, never a shell
                    argv,
                    cwd=str(cwd),
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    close_fds=True,
                    start_new_session=_POSIX,
                )
        except FileNotFoundError:
            return _Run(None, False, f"executable {argv[0]!r} was not found", 0.0)
        except (OSError, ValueError) as exc:
            return _Run(None, False, f"could not start {argv[0]!r}: {exc}", 0.0)

        try:
            exit_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_group(process)
            try:
                exit_code = process.wait(timeout=_REAP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                exit_code = None
            return _Run(exit_code, True, None, time.monotonic() - started)
        except OSError as exc:
            return _Run(
                None, False, f"could not wait for {argv[0]!r}: {exc}", time.monotonic() - started
            )
        return _Run(exit_code, False, None, time.monotonic() - started)

    # ------------------------------------------------------------- result build

    def _unknown_result(self, name: str) -> CheckResult:
        """Return the record for a check name that is not allowlisted."""
        return CheckResult(
            name=name,
            command=[],
            status=CheckStatus.MISSING,
            exit_code=None,
            duration_seconds=0.0,
            required=True,
            stdout_excerpt="",
            stderr_excerpt=redact_excerpt(
                f"check {name!r} is not allowlisted by the validation policy and was not executed"
            ),
        )

    def _missing_tool_result(self, check: CheckDefinition, reason: str) -> CheckResult:
        """Return the record for a check whose executable cannot be launched."""
        return CheckResult(
            name=check.name,
            command=check.argv(),
            status=CheckStatus.MISSING,
            exit_code=None,
            duration_seconds=0.0,
            required=check.required,
            stdout_excerpt="",
            stderr_excerpt=redact_excerpt(reason),
        )

    def _skipped_result(self, check: CheckDefinition, reason: str) -> CheckResult:
        """Return the record for a check the runner deliberately did not execute."""
        return CheckResult(
            name=check.name,
            command=check.argv(),
            status=CheckStatus.SKIPPED,
            exit_code=None,
            duration_seconds=0.0,
            required=check.required,
            stdout_excerpt="",
            stderr_excerpt=redact_excerpt(reason),
        )

    def _errored_result(
        self, check: CheckDefinition, reason: str, duration: float = 0.0
    ) -> CheckResult:
        """Return the record for a check that could not be executed."""
        return CheckResult(
            name=check.name,
            command=check.argv(),
            status=CheckStatus.ERRORED,
            exit_code=None,
            duration_seconds=duration,
            required=check.required,
            stdout_excerpt="",
            stderr_excerpt=redact_excerpt(reason),
        )

    def _build_result(
        self,
        *,
        attempt: RemediationAttempt,
        checks: list[CheckResult],
        candidate_hash: str | None,
        context: _Context,
        started: datetime,
        completed: datetime,
    ) -> ValidationResult:
        """Assemble the honest :class:`ValidationResult` for this run.

        ``passed`` is derived here and nowhere else. If the contract refuses the value it
        means this function is wrong, which is exactly when it should fail loudly.
        """
        isolation = context.isolation
        blocking = [check for check in checks if check.is_blocking_failure]
        passed = bool(checks) and not blocking
        candidate = candidate_hash if candidate_hash is not None else attempt.patch_hash

        limitations = [*isolation.limitations, *_RUNNER_LIMITATIONS]
        if candidate is None:
            limitations.append(
                "validation is not bound to a candidate patch hash, so it cannot justify recovery"
            )

        execution = ExecutionMetadata(
            isolation_kind=isolation.kind,
            sandbox_id=_sandbox_id(isolation.kind, context.worktree),
            worktree_path=str(context.worktree),
            docker_available=self._docker_seen(isolation),
            timeout_seconds=self.policy.default_timeout_seconds,
            limitations=limitations,
        )

        return ValidationResult(
            incident_id=attempt.incident_id,
            candidate_patch_hash=candidate,
            passed=passed,
            checks_executed=checks,
            failed_checks=[check.name for check in blocking],
            summary=_summarize(
                checks=checks, blocking=blocking, passed=passed, kind=isolation.kind
            ),
            started_at=started,
            completed_at=completed,
            execution=execution,
        )


def _status_for(run: _Run) -> CheckStatus:
    """Map a raw child outcome onto a :class:`CheckStatus`."""
    if run.timed_out:
        return CheckStatus.TIMED_OUT
    if run.launch_error is not None:
        return CheckStatus.ERRORED
    if run.exit_code is None:
        return CheckStatus.ERRORED
    if run.exit_code == 0:
        return CheckStatus.PASSED
    return CheckStatus.FAILED


def _read_bounded(path: Path, limit: int) -> str:
    """Read at most ``limit`` bytes from ``path``, marking any remainder as truncated."""
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return ""
    truncated = len(data) > limit
    text = data[:limit].decode("utf-8", errors="replace")
    if truncated:
        text = f"{text}\n...[output truncated at {limit} bytes]"
    return text


def _sandbox_id(kind: str, worktree: Path) -> str:
    """Return an opaque identifier for the disposable workspace.

    A digest of the workspace path keeps the record auditable without embedding a host
    path twice or leaking anything about the host filesystem layout.
    """
    digest = hashlib.sha256(str(Path(worktree)).encode("utf-8")).hexdigest()[:12]
    return f"{kind}-{digest}"


def _summarize(
    *,
    checks: list[CheckResult],
    blocking: list[CheckResult],
    passed: bool,
    kind: str,
) -> str:
    """Describe the outcome without ever implying more than the checks proved."""
    if not checks:
        return (
            f"no validation checks were configured or executable under {kind}; no "
            "evidence was produced and validation cannot pass"
        )
    succeeded = [check for check in checks if check.status is CheckStatus.PASSED]
    parts = [
        f"{len(checks)} check(s) executed under {kind}, {len(succeeded)} passed",
    ]
    if passed:
        parts.append("all required checks passed")
    if blocking:
        detail = ", ".join(f"{check.name}={check.status.value}" for check in blocking)
        parts.append(f"blocking failures: {detail}")
    elif not passed:
        parts.append("validation did not pass")
    return "; ".join(parts)


def run_validation(
    attempt: RemediationAttempt,
    *,
    worktree: Path,
    policy: CheckPolicy = DEFAULT_POLICY,
    docker_available: bool | None = None,
) -> ValidationResult:
    """Validate ``attempt`` with a one-shot runner.

    ``docker_available`` selects the isolation mode explicitly when given: ``True``
    requests container execution, ``False`` forces the constrained local subprocess, and
    ``None`` probes the environment. In every case the recorded
    ``ExecutionMetadata.isolation_kind`` is the mode that actually ran.
    """
    if docker_available is None:
        isolation = detect_isolation()
    elif docker_available:
        isolation = IsolationDecision(
            kind=KIND_DOCKER,
            available=True,
            limitations=list(DOCKER_LIMITATIONS),
            reason="container execution was requested by the caller",
        )
    else:
        isolation = IsolationDecision(
            kind=KIND_LOCAL_SUBPROCESS,
            available=True,
            limitations=list(LOCAL_SUBPROCESS_LIMITATIONS),
            reason="container execution was not requested by the caller",
        )
    runner = ValidationRunner(policy, isolation=isolation)
    return runner.validate(attempt, worktree=worktree)


__all__ = [
    "ValidationOutcome",
    "ValidationRunner",
    "is_stale",
    "run_validation",
]
