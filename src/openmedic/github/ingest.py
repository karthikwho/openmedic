"""GitHub Actions ingestion adapter.

Turns a failed workflow run into the shared :class:`~openmedic.domain.contracts.FailureEvent`
contract, so the application services, diagnosis engine, and persistence layer never
need to know that the evidence came from GitHub (TRD §3, FR-009, FR-018).

Two rules shape this module:

* **Only failing jobs are read.** A successful job's log is never requested, which
  keeps the credential's rate-limit budget and the amount of untrusted text pulled
  into memory to the minimum TRD §11 requires.
* **No failure is fabricated.** A run whose jobs all succeeded raises
  :class:`~openmedic.domain.errors.InvalidInputError` instead of producing an event.

Logs are stored **raw** in the event because the contract keeps raw evidence
available for quote verification (API_CONTRACTS.md §1). Redaction happens on the way
to persistence and reporting, via ``FailureEvent.redacted()`` and
``IncidentRecord.redacted()``.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from ..domain.contracts import FailureEvent, utc_now
from ..domain.enums import FailureType
from ..domain.errors import InvalidInputError
from .client import (
    FAILED_JOB_CONCLUSIONS,
    GitHubClient,
    JobInfo,
    WorkflowRun,
)

# Coarse log markers, ordered most-specific first. They classify a failure *before*
# diagnosis runs; they are deliberately narrow so an ambiguous log stays `unknown`.
# The deterministic diagnosis engine (FR-004) remains the authority: this is a hint
# so an obviously dependency-shaped event is never persisted as `unknown`.
_DEPENDENCY_MARKERS: tuple[str, ...] = (
    "modulenotfounderror",
    "no module named",
    "no matching distribution",
    "could not find a version",
    "unresolved dependency",
    "cannot find module",
    "npm err!",
    "yarn error",
)
_SYNTAX_MARKERS: tuple[str, ...] = (
    "syntaxerror",
    "invalid syntax",
    "indentationerror",
    "unexpected token",
    "cannot import name",
    "unterminated string",
)
_TEST_MARKERS: tuple[str, ...] = (
    "assertionerror",
    "assertion failed",
    "tests failed",
    "test failed",
    "failed,",
    "failed in",
)
_BUILD_MARKERS: tuple[str, ...] = (
    "build failed",
    "compilation failed",
    "make: ***",
    "webpack",
    "configuration error",
    "command errored",
    "gradle",
    "maven",
)


def classify_failure(log_text: str) -> FailureType:
    """Return a coarse :class:`FailureType` hinted by ``log_text``.

    This is an ingestion-time hint, not a diagnosis: when nothing matches, the
    honest answer is ``FailureType.UNKNOWN`` rather than a guess.
    """
    haystack = (log_text or "").lower()
    if not haystack.strip():
        return FailureType.UNKNOWN
    for marker in _DEPENDENCY_MARKERS:
        if marker in haystack:
            return FailureType.DEPENDENCY_ERROR
    for marker in _SYNTAX_MARKERS:
        if marker in haystack:
            return FailureType.SYNTAX_OR_IMPORT_ERROR
    for marker in _TEST_MARKERS:
        if marker in haystack:
            return FailureType.TEST_FAILURE
    for marker in _BUILD_MARKERS:
        if marker in haystack:
            return FailureType.BUILD_OR_CONFIG_ERROR
    return FailureType.UNKNOWN


def is_failed_job(job: JobInfo) -> bool:
    """Report whether GitHub marked this job, or one of its steps, as failed."""
    return job.conclusion in FAILED_JOB_CONCLUSIONS or bool(job.failed_steps)


def first_failed_job(jobs: Sequence[JobInfo]) -> JobInfo | None:
    """Return the first failed job in API order, or ``None`` when none failed."""
    for job in jobs:
        if is_failed_job(job):
            return job
    return None


def event_from_run(
    repository: str,
    run: WorkflowRun,
    jobs: Sequence[JobInfo],
    *,
    timestamp: datetime | None = None,
    logs: str = "",
) -> FailureEvent:
    """Build a :class:`FailureEvent` from a run and its jobs.

    The first failed job in GitHub's ordering wins, and its first failed step becomes
    ``failed_step``. Together with the repository, workflow, job, and run identifiers
    that produces the stable idempotency key required by API_CONTRACTS.md §1.

    Raises :class:`~openmedic.domain.errors.InvalidInputError` when no job failed: a
    successful run is not a failure event, and inventing one would be fabrication.
    """
    job = first_failed_job(jobs)
    if job is None:
        msg = "no failed job in this workflow run; there is no failure event to build"
        raise InvalidInputError(
            msg,
            detail=f"repository={repository} run_id={run.run_id} jobs={len(jobs)}",
        )
    failed_step = job.failed_steps[0] if job.failed_steps else None
    return FailureEvent(
        repository=repository,
        commit_sha=run.commit_sha or None,
        workflow_name=run.workflow_name or None,
        run_id=run.run_id,
        failed_step=failed_step,
        job_name=job.name or None,
        failure_type=classify_failure(logs),
        logs=logs,
        timestamp=timestamp if timestamp is not None else utc_now(),
    )


def ingest_run(client: GitHubClient, repository: str, run_id: str) -> FailureEvent:
    """Fetch a failed workflow run through ``client`` and normalise it.

    ``client`` is always injected, never constructed here, so the whole flow is
    testable against a mock transport and cannot open a real network connection as
    a side effect of importing this module.
    """
    run = client.get_workflow_run(repository, run_id)
    jobs = client.list_jobs(repository, run_id)
    job = first_failed_job(jobs)
    if job is None:
        msg = "workflow run has no failed job; nothing to ingest"
        raise InvalidInputError(
            msg,
            detail=f"repository={repository} run_id={run_id} jobs={len(jobs)}",
        )
    logs = client.get_job_log(repository, job.job_id)
    return event_from_run(repository, run, jobs, logs=logs)


def log_to_event(
    log_text: str,
    *,
    repository: str,
    run_id: str,
    workflow_name: str,
    commit_sha: str,
    failed_step: str,
    job_name: str | None = None,
    timestamp: datetime | None = None,
) -> FailureEvent:
    """Build a :class:`FailureEvent` directly from an already-fetched log.

    This is the path used when a log arrived from somewhere else (a local file, a
    fixture, or a previous run of OpenMedic). It performs no I/O and no redaction;
    ``failed_step`` is required because it is part of the idempotency key.
    """
    return FailureEvent(
        repository=repository,
        commit_sha=commit_sha,
        workflow_name=workflow_name,
        run_id=run_id,
        failed_step=failed_step,
        job_name=job_name,
        failure_type=classify_failure(log_text),
        logs=log_text,
        timestamp=timestamp if timestamp is not None else utc_now(),
    )
