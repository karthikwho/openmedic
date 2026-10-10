"""GitHub Actions adapter: client, ingestion, and reporting.

Read operations (:class:`GitHubClient`, :func:`openmedic.github.ingest.ingest_run`)
are the default surface. Write operations
(:class:`~openmedic.github.report.GitHubReporter`) are explicit opt-ins and require a
separately credential-bearing client.
"""

from __future__ import annotations

from .client import (
    API_VERSION,
    DEFAULT_AUTH_ENV,
    FAILED_JOB_CONCLUSIONS,
    FAILED_STEP_CONCLUSIONS,
    GitHubApiError,
    GitHubAuth,
    GitHubAuthError,
    GitHubClient,
    GitHubNotFoundError,
    GitHubRateLimitError,
    JobInfo,
    WorkflowRun,
    is_allowed_url,
    parse_json_object,
    validate_branch,
    validate_path_segment,
    validate_repository,
)
from .ingest import (
    classify_failure,
    event_from_run,
    first_failed_job,
    ingest_run,
    is_failed_job,
    log_to_event,
)
from .report import GitHubReporter, ReportRequest

__all__ = [
    "API_VERSION",
    "DEFAULT_AUTH_ENV",
    "FAILED_JOB_CONCLUSIONS",
    "FAILED_STEP_CONCLUSIONS",
    "GitHubApiError",
    "GitHubAuth",
    "GitHubAuthError",
    "GitHubClient",
    "GitHubNotFoundError",
    "GitHubRateLimitError",
    "GitHubReporter",
    "JobInfo",
    "ReportRequest",
    "WorkflowRun",
    "classify_failure",
    "event_from_run",
    "first_failed_job",
    "ingest_run",
    "is_allowed_url",
    "is_failed_job",
    "log_to_event",
    "parse_json_object",
    "validate_branch",
    "validate_path_segment",
    "validate_repository",
]
