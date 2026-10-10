"""GitHub reporting adapter: opt-in comment and pull-request writes.

Everything in this module is a **write** operation, and write operations are the
sharp edge of the security model (SECURITY.md rules 3, 11, and 12; PRD FR-013):

* A reporter is only created when the caller explicitly wants to write. Nothing in
  the ingest or diagnose path constructs one, so report-only mode is the default.
* Both operations require an authenticated client. There is no anonymous write path.
* There is no merge, no deploy, and no auto-anything. Creating a pull request is the
  end of what OpenMedic does; a human reviews and merges it.
* The comment body must already be redacted. This module deliberately does no
  redaction of its own: the shared ``redact`` patterns would also mangle legitimate
  report content such as commit SHAs, and silently rewriting a report is worse than
  requiring the caller to build it from redacted data.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domain.errors import InvalidInputError
from .client import (
    GitHubApiError,
    GitHubClient,
    parse_json_object,
    validate_branch,
    validate_path_segment,
    validate_repository,
)


@dataclass(frozen=True, slots=True)
class ReportRequest:
    """A request to publish a report against a workflow run.

    ``body`` must already be redacted by the caller (for example via
    ``IncidentRecord.redacted()``). ``comment_id`` makes the post idempotent: when
    set, the existing comment is updated instead of a new one being created.
    """

    repository: str
    run_id: str
    body: str
    comment_id: str | None = None


class GitHubReporter:
    """Explicit write operations for GitHub reporting."""

    def __init__(self, client: GitHubClient) -> None:
        """Bind the reporter to an already-configured client."""
        self._client = client

    def _require_writable(self) -> None:
        """Refuse to write without a credential rather than sending an anonymous call."""
        if not self._client.is_authenticated:
            msg = "GitHub write operations require an authenticated client"
            raise GitHubApiError(
                msg,
                detail=f"set {self._client.token_env} with a write-scoped token",
            )

    def post_comment(self, request: ReportRequest) -> dict[str, object]:
        """Post or update the diagnosis comment for a run.

        With ``request.comment_id`` set the existing comment is patched, so a rerun
        updates one comment instead of stacking duplicates. GitHub accepts a workflow
        run identifier in place of an issue number, which is how a report attaches to
        the run that produced it.
        """
        self._require_writable()
        repository = validate_repository(request.repository)
        body = request.body
        if not body.strip():
            msg = "report body must not be empty"
            raise InvalidInputError(msg, detail="received an empty or whitespace-only body")
        if request.comment_id is not None:
            comment = validate_path_segment(request.comment_id, "comment_id")
            response = self._client._request(
                "PATCH",
                f"/repos/{repository}/issues/comments/{comment}",
                json={"body": body},
            )
        else:
            run = validate_path_segment(request.run_id, "run_id")
            response = self._client._request(
                "POST",
                f"/repos/{repository}/issues/{run}/comments",
                json={"body": body},
            )
        return parse_json_object(response, "issue comment")

    def create_pull_request(
        self,
        *,
        repository: str,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> dict[str, object]:
        """Open a reviewable pull request for a remediated incident.

        The request contains only title, body, head, and base: no merge method, no
        auto-merge flag, and no deploy step. Merging stays a human action, per
        SECURITY.md rule 11.
        """
        self._require_writable()
        repo = validate_repository(repository)
        if not title.strip():
            msg = "pull request title must not be empty"
            raise InvalidInputError(msg, detail="received an empty title")
        if not body.strip():
            msg = "pull request body must not be empty"
            raise InvalidInputError(msg, detail="received an empty body")
        head_branch = validate_branch(head, "head")
        base_branch = validate_branch(base, "base")
        response = self._client._request(
            "POST",
            f"/repos/{repo}/pulls",
            json={"title": title, "body": body, "head": head_branch, "base": base_branch},
        )
        return parse_json_object(response, "pull request")
