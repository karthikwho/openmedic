"""Typed, read-first GitHub Actions HTTP adapter.

This module is the only place in OpenMedic that knows the shape of the GitHub REST
API. It uses ``httpx`` directly rather than a GitHub SDK so the dependency footprint
stays small (TRD §2) and so every request can be inspected in tests.

Properties enforced here, because getting them wrong would be a safety failure:

* Authentication is ``Authorization: Bearer <token>`` only, and the token comes from
  an explicit argument or an environment variable (SECURITY.md rule 2). The token
  never appears in an exception message, a ``detail`` string, a returned value, or a
  log line.
* Pagination follows the ``Link: rel="next"`` header, bounded by ``max_pages`` and by
  an allowlist of GitHub hosts. A response cannot redirect the crawler to an
  arbitrary third-party host (SSRF guard).
* Log downloads follow redirects only to allowlisted GitHub hosts.
* Every GitHub-specific failure maps onto a domain error so the CLI can translate it
  into a documented exit code, and no error message ever echoes response bodies.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from ..domain.errors import IntegrationUnavailableError, InvalidInputError

#: Name of the environment variable consulted when no token is passed explicitly.
#: The *name* of the variable is public configuration; its value never is.
DEFAULT_AUTH_ENV: Final[str] = "OPENMEDIC_GITHUB_TOKEN"

#: GitHub REST API version pinned by this adapter.
API_VERSION: Final[str] = "2022-11-28"

#: Upper bound on redirects followed while downloading a job log.
MAX_LOG_REDIRECTS: Final[int] = 5

#: Job conclusions that mean "this job failed".
FAILED_JOB_CONCLUSIONS: Final[frozenset[str]] = frozenset(
    {"failure", "timed_out", "startup_failure"}
)

#: Step conclusions that mean "this step failed".
FAILED_STEP_CONCLUSIONS: Final[frozenset[str]] = frozenset({"failure", "timed_out"})

_REPOSITORY_RE: Final = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")
_SEGMENT_RE: Final = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_BRANCH_RE: Final = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")
_LINK_RE: Final = re.compile(r"<(?P<target>[^>]+)>(?:[^,]|,[^<])*")
_LINK_REL_RE: Final = re.compile(r'rel\s*=\s*"?([^";,]+)"?')


class GitHubApiError(IntegrationUnavailableError):
    """A GitHub API call failed in a way OpenMedic cannot work around."""


class GitHubAuthError(GitHubApiError):
    """GitHub refused the credential or the scope (HTTP 401, or a 403 without rate limit)."""


class GitHubNotFoundError(GitHubApiError):
    """The requested GitHub resource does not exist (HTTP 404).

    The common case is a job log that GitHub has already deleted or expired, which
    TRD §11 requires to be reported rather than silently ignored.
    """


class GitHubRateLimitError(GitHubApiError):
    """GitHub rate-limited the request.

    Raised for HTTP 403 with ``X-RateLimit-Remaining: 0`` and for HTTP 429. The
    reset time is reported in ``detail``; the credential never is.
    """


@dataclass(frozen=True, slots=True)
class GitHubAuth:
    """Where the credential comes from and which scopes it needs.

    This record deliberately contains no secret material: only the name of the
    environment variable and the least-privilege scope list to document in setup.
    """

    token_env: str = DEFAULT_AUTH_ENV
    scopes: tuple[str, ...] = ("repo:status", "actions:read")


@dataclass(frozen=True, slots=True)
class WorkflowRun:
    """The subset of a workflow run that ingestion needs."""

    run_id: str
    repository: str
    workflow_name: str
    commit_sha: str
    conclusion: str
    html_url: str
    jobs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class JobInfo:
    """One job of a workflow run, including the steps GitHub marked as failed."""

    job_id: str
    name: str
    conclusion: str
    failed_steps: tuple[str, ...]


def validate_repository(repository: str) -> str:
    """Return ``repository`` when it is a safe ``owner/repo`` pair.

    The repository name is untrusted input that ends up in a URL path, so it is
    validated before use. The rejected value is never echoed back into the error,
    which keeps untrusted text out of logs and exception messages.
    """
    if not isinstance(repository, str) or not _REPOSITORY_RE.match(repository):
        msg = "repository must be a GitHub 'owner/repo' pair"
        raise InvalidInputError(msg, detail="received a value that is not an owner/repo pair")
    return repository


def validate_path_segment(value: str, name: str) -> str:
    """Return ``value`` when it is a single safe URL path segment.

    Rejects empty values, path separators, ``.``/``..`` traversal, and whitespace so
    caller-supplied identifiers cannot escape the intended API path.
    """
    if not isinstance(value, str) or not _SEGMENT_RE.match(value):
        msg = f"{name} must be a single safe path segment"
        raise InvalidInputError(msg, detail=f"rejected a {name} containing unsafe characters")
    return value


def validate_branch(value: str, name: str) -> str:
    """Return ``value`` when it looks like a real Git branch name.

    Branch names legitimately contain ``/``, so this is weaker than
    :func:`validate_path_segment`: it rejects control characters, whitespace, ``..``,
    and leading or trailing separators rather than forbidding the separator itself.
    The rejected value is never echoed back into the error message.
    """
    candidate = value if isinstance(value, str) else ""
    ok = bool(_BRANCH_RE.match(candidate))
    if ok:
        ok = not candidate.startswith("/") and not candidate.endswith("/") and ".." not in candidate
    if not ok:
        msg = f"{name} must be a Git branch name"
        raise InvalidInputError(msg, detail=f"rejected a {name} that is not a usable branch name")
    return candidate


def parse_json_object(response: httpx.Response, what: str) -> dict[str, Any]:
    """Parse a GitHub JSON response body into an object or fail loudly.

    A non-object or unparsable body is an integration failure, never a silent empty
    result: returning ``{}`` here would let a truncated API response look like a
    workflow run with no jobs.
    """
    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        msg = f"GitHub returned a non-JSON body for the {what} request"
        raise GitHubApiError(msg, detail=type(exc).__name__) from exc
    if not isinstance(payload, dict):
        msg = f"GitHub returned an unexpected body type for the {what} request"
        raise GitHubApiError(msg, detail=f"expected a JSON object, got {type(payload).__name__}")
    return payload


def is_allowed_url(url: str) -> bool:
    """Return True when ``url`` points at an official GitHub host over HTTPS.

    Used as the SSRF guard for both pagination links and log redirects: anything
    else is treated as hostile and is never requested.
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        return False
    host = (parts.hostname or "").lower()
    if not host:
        return False
    if host in {"api.github.com", "github.com"}:
        return True
    return host.endswith(".githubusercontent.com")


def _epoch_to_iso(value: object) -> str | None:
    """Convert a GitHub epoch-seconds value to a UTC ISO-8601 string.

    GitHub sends the reset time both as an integer (JSON) and as a digit string
    (header), so both are accepted; anything else is honestly reported as unknown.
    """
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, int):
        return datetime.fromtimestamp(value, tz=UTC).isoformat()
    return None


def _iter_links(header: str) -> Iterator[tuple[str, str]]:
    """Yield ``(url, rel)`` pairs from a GitHub ``Link`` header.

    Each link segment runs from one ``<url>`` up to the next one, so a ``rel`` that
    is not the first attribute of a link is still found.
    """
    for match in _LINK_RE.finditer(header):
        rel_match = _LINK_REL_RE.search(match.group(0))
        if rel_match is not None:
            yield match.group("target").strip(), rel_match.group(1).strip()


def _as_str(value: object) -> str:
    """Coerce a JSON scalar to a trimmed string, mapping ``None`` to ``""``."""
    if value is None:
        return ""
    return str(value)


def _job_from_payload(raw: dict[str, Any]) -> JobInfo:
    """Build a :class:`JobInfo` from one entry of a GitHub job list."""
    steps = raw.get("steps")
    failed_steps: list[str] = []
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            if _as_str(step.get("conclusion")) in FAILED_STEP_CONCLUSIONS:
                name = _as_str(step.get("name"))
                if name:
                    failed_steps.append(name)
    return JobInfo(
        job_id=_as_str(raw.get("id")),
        name=_as_str(raw.get("name")),
        conclusion=_as_str(raw.get("conclusion")),
        failed_steps=tuple(failed_steps),
    )


def _run_from_payload(
    repository: str,
    payload: dict[str, Any],
    fallback_run_id: str,
) -> WorkflowRun:
    """Build a :class:`WorkflowRun` from a GitHub run payload."""
    embedded = payload.get("jobs")
    job_ids: list[str] = []
    if isinstance(embedded, list):
        for entry in embedded:
            if isinstance(entry, dict) and entry.get("id") is not None:
                job_ids.append(_as_str(entry.get("id")))
    return WorkflowRun(
        run_id=_as_str(payload.get("id")) or fallback_run_id,
        repository=repository,
        workflow_name=_as_str(payload.get("name")) or _as_str(payload.get("path")),
        commit_sha=_as_str(payload.get("head_sha")),
        conclusion=_as_str(payload.get("conclusion")) or _as_str(payload.get("status")),
        html_url=_as_str(payload.get("html_url")),
        jobs=tuple(job_ids),
    )


def _jobs_from_payload(payload: dict[str, Any]) -> list[JobInfo]:
    """Build the job list for one page of a GitHub job-list response."""
    entries = payload.get("jobs")
    if entries is None:
        return []
    if not isinstance(entries, list):
        msg = "GitHub returned a malformed job list"
        raise GitHubApiError(msg, detail="the 'jobs' member is not a list")
    jobs: list[JobInfo] = []
    for entry in entries:
        if not isinstance(entry, dict):
            msg = "GitHub returned a malformed job entry"
            raise GitHubApiError(msg, detail=f"expected an object, got {type(entry).__name__}")
        jobs.append(_job_from_payload(entry))
    return jobs


class GitHubClient:
    """Minimal typed client for the GitHub Actions REST API.

    The client is read-first: the methods here only issue GET requests. Write
    operations live in :class:`openmedic.github.report.GitHubReporter`, which is
    constructed separately so a read-only run can never turn into a write by
    accident.
    """

    BASE_URL: str = "https://api.github.com"

    def __init__(
        self,
        token: str | None = None,
        *,
        token_env: str = DEFAULT_AUTH_ENV,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
        max_pages: int = 10,
    ) -> None:
        """Create a client.

        ``token`` falls back to the ``token_env`` environment variable. Passing an
        empty string, or an unset variable, produces an unauthenticated client that
        can still read public repositories at the lower unauthenticated rate limit.
        """
        if timeout <= 0:
            msg = "timeout must be a positive number of seconds"
            raise InvalidInputError(msg, detail=f"received timeout={timeout!r}")
        if max_pages < 1:
            msg = "max_pages must be at least 1"
            raise InvalidInputError(msg, detail=f"received max_pages={max_pages!r}")
        self._token = token if token is not None else os.environ.get(token_env)
        self._token = self._token or None
        self._token_env = token_env
        self._max_pages = max_pages
        self._client = httpx.Client(
            base_url=self.BASE_URL,
            timeout=httpx.Timeout(timeout),
            transport=transport,
            follow_redirects=False,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "openmedic-github-adapter",
            },
        )

    def __repr__(self) -> str:
        """Return a representation that shows auth state, never the credential."""
        return (
            f"GitHubClient(base_url={self.BASE_URL!r}, "
            f"authenticated={self.is_authenticated}, max_pages={self._max_pages})"
        )

    @property
    def is_authenticated(self) -> bool:
        """True when a non-empty credential is available for requests."""
        return self._token is not None

    @property
    def token_env(self) -> str:
        """Name of the environment variable the credential is read from."""
        return self._token_env

    @property
    def max_pages(self) -> int:
        """Upper bound on API pages fetched for one paginated listing."""
        return self._max_pages

    def _headers(self) -> dict[str, str]:
        """Build per-request headers, adding the credential only when present."""
        headers = {"Accept": "application/vnd.github+json"}
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        """Issue one API request and translate failures into domain errors."""
        try:
            response = self._client.request(method, path, headers=self._headers(), **kw)
        except httpx.TimeoutException as exc:
            msg = f"GitHub request timed out: {method} {path}"
            raise GitHubApiError(msg, detail=type(exc).__name__) from exc
        except httpx.RequestError as exc:
            msg = f"GitHub request could not be completed: {method} {path}"
            raise GitHubApiError(msg, detail=type(exc).__name__) from exc
        self._raise_for_status(response)
        return response

    @staticmethod
    def _describe(response: httpx.Response) -> str:
        """Describe a response by method and path only, never by body or header."""
        request = response.request
        return f"{request.method} {request.url.path}"

    def _raise_for_status(self, response: httpx.Response) -> None:
        """Map a non-2xx response onto the matching domain error."""
        status = response.status_code
        if status < 400:
            return
        if status == 401:
            msg = f"GitHub rejected the credential for: {self._describe(response)}"
            raise GitHubAuthError(msg)
        if status == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
            reset = _epoch_to_iso(response.headers.get("X-RateLimit-Reset"))
            msg = "GitHub rate limit exhausted for the primary API resource"
            raise GitHubRateLimitError(msg, detail=f"rate limit resets at {reset}")
        if status == 429:
            retry_after = response.headers.get("Retry-After")
            msg = "GitHub rate limited the request (secondary rate limit)"
            raise GitHubRateLimitError(msg, detail=f"retry after {retry_after} seconds")
        if status == 403:
            msg = f"GitHub refused the request (insufficient scope): {self._describe(response)}"
            raise GitHubAuthError(msg)
        if status == 404:
            msg = f"GitHub resource not found: {self._describe(response)}"
            raise GitHubNotFoundError(msg)
        msg = f"GitHub API returned HTTP {status} for: {self._describe(response)}"
        raise GitHubApiError(msg, detail=f"unhandled HTTP status {status}")

    def _next_page(self, response: httpx.Response) -> str | None:
        """Return the allowlisted ``rel="next"`` URL of a response, if any."""
        header = response.headers.get("Link")
        if not header:
            return None
        for target, rel in _iter_links(header):
            if rel != "next":
                continue
            if not is_allowed_url(target):
                host = (urlsplit(target).hostname or "unknown").lower()
                msg = "refusing to follow a pagination link to a non-GitHub host"
                raise GitHubApiError(msg, detail=f"blocked host: {host}")
            return target
        return None

    def get_workflow_run(self, repository: str, run_id: str) -> WorkflowRun:
        """Fetch one workflow run and return the fields ingestion needs."""
        repo = validate_repository(repository)
        run = validate_path_segment(run_id, "run_id")
        response = self._request("GET", f"/repos/{repo}/actions/runs/{run}")
        payload = parse_json_object(response, "workflow run")
        return _run_from_payload(repo, payload, run)

    def list_jobs(self, repository: str, run_id: str) -> list[JobInfo]:
        """List the jobs of a workflow run, following ``Link`` pagination.

        At most ``max_pages`` pages are fetched; a truncated listing is reported by
        returning fewer jobs rather than by silently claiming completeness.
        """
        repo = validate_repository(repository)
        run = validate_path_segment(run_id, "run_id")
        jobs: list[JobInfo] = []
        url: str | None = f"/repos/{repo}/actions/runs/{run}/jobs"
        pages = 0
        first = True
        while url is not None and pages < self._max_pages:
            params = {"per_page": 100} if first else None
            response = self._request("GET", url, params=params)
            first = False
            pages += 1
            jobs.extend(_jobs_from_payload(parse_json_object(response, "job list")))
            url = self._next_page(response)
        return jobs

    def get_job_log(self, repository: str, job_id: str) -> str:
        """Return the plain-text log of one job.

        Raises :class:`GitHubNotFoundError` when GitHub has deleted or expired the
        log, and refuses redirects to hosts outside the GitHub allowlist.
        """
        repo = validate_repository(repository)
        job = validate_path_segment(job_id, "job_id")
        url: str | None = f"/repos/{repo}/actions/jobs/{job}/logs"
        for _ in range(MAX_LOG_REDIRECTS + 1):
            response = self._request("GET", url)
            if not response.is_redirect:
                return response.text
            location = response.headers.get("Location", "")
            if not is_allowed_url(location):
                host = (urlsplit(location).hostname or "unknown").lower()
                msg = "refusing to follow a job log redirect to a non-GitHub host"
                raise GitHubApiError(msg, detail=f"blocked host: {host}")
            url = location
        msg = "too many redirects while fetching a GitHub job log"
        raise GitHubApiError(msg, detail=f"stopped after {MAX_LOG_REDIRECTS} redirects")

    def check_rate_limit(self) -> dict[str, object]:
        """Return the current primary rate-limit budget as a plain dictionary."""
        response = self._request("GET", "/rate_limit")
        payload = parse_json_object(response, "rate limit")
        resources = payload.get("resources")
        core = resources.get("core") if isinstance(resources, dict) else None
        if not isinstance(core, dict):
            core = {}
        return {
            "resource": "core",
            "limit": core.get("limit"),
            "remaining": core.get("remaining"),
            "used": core.get("used"),
            "reset_at": _epoch_to_iso(core.get("reset")),
        }
