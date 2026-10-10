"""Tests for the typed GitHub client and the opt-in reporter.

Every request is served by ``httpx.MockTransport``, so nothing here performs network
I/O. The safety cases are the point of this file: the credential must never reach an
exception message, and a hostile ``Link`` or ``Location`` header must never be
followed off the GitHub hosts.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime

import httpx
import pytest

from openmedic.domain.errors import InvalidInputError
from openmedic.github.client import (
    GitHubApiError,
    GitHubAuthError,
    GitHubNotFoundError,
    GitHubRateLimitError,
)
from openmedic.github.report import GitHubReporter, ReportRequest

REPOSITORY = "acme/widget"
RUN_ID = "4242"
RUN_PATH = f"/repos/{REPOSITORY}/actions/runs/{RUN_ID}"
JOBS_PATH = f"{RUN_PATH}/jobs"
JOB_LOG_PATH = f"/repos/{REPOSITORY}/actions/jobs/1002/logs"


def test_get_workflow_run_parses_payload(
    make_client, router, make_json_response, load_json
) -> None:
    """A run payload is normalised into the fields ingestion needs."""
    client, recorder = make_client(
        router({RUN_PATH: make_json_response(load_json("run_test_failure.json"))})
    )

    run = client.get_workflow_run(REPOSITORY, RUN_ID)

    assert run.run_id == "4242"
    assert run.repository == REPOSITORY
    assert run.workflow_name == "CI"
    assert run.commit_sha == "9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c"
    assert run.conclusion == "failure"
    assert run.html_url.endswith("/actions/runs/4242")
    assert recorder.paths == [RUN_PATH]


def test_requests_carry_bearer_authorization_only(
    make_client, router, make_json_response, load_json, fake_credential
) -> None:
    """The credential travels in the Authorization header and nowhere else."""
    client, recorder = make_client(
        router({RUN_PATH: make_json_response(load_json("run_test_failure.json"))})
    )

    client.get_workflow_run(REPOSITORY, RUN_ID)

    request = recorder.requests[0]
    assert request.headers["Authorization"] == f"Bearer {fake_credential}"
    assert request.headers["Accept"] == "application/vnd.github+json"
    assert fake_credential not in str(request.url)


def test_unauthenticated_client_omits_authorization_header(
    make_client, router, make_json_response, load_json
) -> None:
    """An empty credential produces a client that sends no Authorization header."""
    client, recorder = make_client(
        router({RUN_PATH: make_json_response(load_json("run_test_failure.json"))}),
        credential="",
    )

    assert client.is_authenticated is False
    client.get_workflow_run(REPOSITORY, RUN_ID)
    assert "Authorization" not in recorder.requests[0].headers


def test_credential_is_read_from_the_environment(
    make_client, router, make_json_response, load_json, monkeypatch, fake_credential
) -> None:
    """The token comes from the environment variable when not passed explicitly."""
    monkeypatch.setenv("OPENMEDIC_GITHUB_TOKEN", fake_credential)
    client, recorder = make_client(
        router({RUN_PATH: make_json_response(load_json("run_test_failure.json"))}),
        credential=None,
    )

    assert client.is_authenticated is True
    env_name = "OPENMEDIC_GITHUB_TOKEN"
    assert client.token_env == env_name
    client.get_workflow_run(REPOSITORY, RUN_ID)
    assert recorder.requests[0].headers["Authorization"] == f"Bearer {fake_credential}"


def test_missing_environment_variable_yields_unauthenticated_client(
    make_client, router, make_json_response, load_json, monkeypatch
) -> None:
    """A missing environment variable is not an error: reads go out unauthenticated."""
    monkeypatch.delenv("OPENMEDIC_GITHUB_TOKEN", raising=False)
    client, recorder = make_client(
        router({RUN_PATH: make_json_response(load_json("run_test_failure.json"))}),
        credential=None,
    )

    assert client.is_authenticated is False
    client.get_workflow_run(REPOSITORY, RUN_ID)
    assert "Authorization" not in recorder.requests[0].headers


def test_list_jobs_returns_jobs_and_failed_steps(
    make_client, router, make_json_response, load_json
) -> None:
    """Job entries and their failed steps are parsed from the jobs payload."""
    client, _ = make_client(
        router({JOBS_PATH: make_json_response(load_json("jobs_response.json"))})
    )

    jobs = client.list_jobs(REPOSITORY, RUN_ID)

    assert [job.job_id for job in jobs] == ["1001", "1002", "1003"]
    assert jobs[1].name == "test (3.11)"
    assert jobs[1].conclusion == "failure"
    assert jobs[1].failed_steps == ("Run pytest",)
    assert jobs[0].failed_steps == ()


def test_list_jobs_follows_link_pagination(make_client, make_json_response, load_json) -> None:
    """A rel="next" link is followed until the listing ends."""
    page_two_url = (
        "https://api.github.com/repos/acme/multi-page/actions/runs/7777/jobs?page=2&per_page=100"
    )
    prev_url = "https://api.github.com/repos/acme/multi-page/actions/runs/7777/jobs?page=1"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2":
            return make_json_response(load_json("pagination_page2.json"))
        link = f'<{page_two_url}>; rel="next", <{prev_url}>; rel="prev"'
        return make_json_response(load_json("pagination_page1.json"), headers={"Link": link})

    client, recorder = make_client(handler)

    jobs = client.list_jobs("acme/multi-page", "7777")

    assert [job.job_id for job in jobs] == ["3001", "3002"]
    assert jobs[1].failed_steps == ("Run integration suite",)
    assert len(recorder.requests) == 2


def test_list_jobs_parses_link_header_with_leading_attributes(
    make_client, make_json_response, load_json
) -> None:
    """A Link header whose rel is not the first attribute is still parsed."""
    page_two_url = "https://api.github.com/repos/acme/multi-page/actions/runs/7777/jobs?page=2"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2":
            return make_json_response(load_json("pagination_page2.json"))
        link = f'<{page_two_url}>; results="1", rel="next"'
        return make_json_response(load_json("pagination_page1.json"), headers={"Link": link})

    client, recorder = make_client(handler)

    jobs = client.list_jobs("acme/multi-page", "7777")

    assert [job.job_id for job in jobs] == ["3001", "3002"]
    assert len(recorder.requests) == 2


def test_list_jobs_caps_pages_at_max_pages(make_client, make_json_response, load_json) -> None:
    """max_pages bounds the crawl even when the server keeps offering more pages."""
    page_two_url = (
        "https://api.github.com/repos/acme/multi-page/actions/runs/7777/jobs?page=2&per_page=100"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2":
            return make_json_response(load_json("pagination_page2.json"))
        return make_json_response(
            load_json("pagination_page1.json"),
            headers={"Link": f'<{page_two_url}>; rel="next"'},
        )

    client, recorder = make_client(handler, max_pages=1)

    jobs = client.list_jobs("acme/multi-page", "7777")

    assert [job.job_id for job in jobs] == ["3001"]
    assert len(recorder.requests) == 1


def test_list_jobs_refuses_non_github_link_host(
    make_client, make_json_response, load_json, fake_credential
) -> None:
    """A Link header pointing off the GitHub hosts is never followed."""
    page_two_url = (
        "https://attacker.example.com/repos/acme/multi-page/actions/runs/7777/jobs?page=2"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return make_json_response(
            load_json("pagination_page1.json"),
            headers={"Link": f'<{page_two_url}>; rel="next"'},
        )

    client, recorder = make_client(handler)

    with pytest.raises(GitHubApiError) as excinfo:
        client.list_jobs("acme/multi-page", "7777")

    assert "attacker.example.com" not in recorder.hosts
    assert len(recorder.requests) == 1
    assert fake_credential not in str(excinfo.value)


def test_authentication_failure_raises_auth_error_without_leaking_credential(
    make_client, router, make_json_response, fake_credential
) -> None:
    """HTTP 401 maps to GitHubAuthError and never echoes the credential."""
    client, _ = make_client(
        router({RUN_PATH: make_json_response({"message": "Bad credentials"}, status=401)})
    )

    with pytest.raises(GitHubAuthError) as excinfo:
        client.get_workflow_run(REPOSITORY, RUN_ID)

    error = excinfo.value
    assert fake_credential not in str(error)
    assert fake_credential not in (error.detail or "")
    assert fake_credential not in repr(error)
    assert fake_credential not in json.dumps(error.to_dict())


def test_rate_limit_failure_exposes_reset_time_not_credential(
    make_client, router, make_json_response, fake_credential
) -> None:
    """HTTP 403 with an exhausted budget reports the reset time, not the token."""
    reset_at = int(time.time()) + 900
    headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset_at)}
    client, _ = make_client(
        router({RUN_PATH: make_json_response({"message": "limit"}, status=403, headers=headers)})
    )

    with pytest.raises(GitHubRateLimitError) as excinfo:
        client.get_workflow_run(REPOSITORY, RUN_ID)

    error = excinfo.value
    expected = datetime.fromtimestamp(reset_at, tz=UTC).isoformat()
    assert error.detail is not None
    assert expected in error.detail
    assert fake_credential not in str(error)
    assert fake_credential not in (error.detail or "")
    assert fake_credential not in repr(error)


def test_missing_job_log_raises_not_found(
    make_client, router, make_json_response, fake_credential
) -> None:
    """A deleted or expired job log is a typed 404, not an empty string."""
    client, _ = make_client(
        router({JOB_LOG_PATH: make_json_response({"message": "Not Found"}, status=404)})
    )

    with pytest.raises(GitHubNotFoundError) as excinfo:
        client.get_job_log(REPOSITORY, "1002")

    error = excinfo.value
    assert fake_credential not in str(error)
    assert fake_credential not in (error.detail or "")


def test_get_job_log_returns_text(make_client, router, make_text_response, load_log) -> None:
    """A job log is returned as plain text, including ANSI-ish runner noise."""
    log = load_log("logs_test_failure.txt")
    client, _ = make_client(router({JOB_LOG_PATH: make_text_response(log)}))

    assert client.get_job_log(REPOSITORY, "1002") == log


def test_job_log_follows_allowlisted_redirect(make_client, make_text_response, load_log) -> None:
    """A log redirect to a GitHub asset host is followed exactly once."""
    log = load_log("logs_test_failure.txt")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "objects.githubusercontent.com":
            return make_text_response(log)
        location = "https://objects.githubusercontent.com/github-production-job-logs/abc123?token=x"
        return make_text_response("", status=302, headers={"Location": location})

    client, recorder = make_client(handler)

    assert client.get_job_log(REPOSITORY, "1002") == log
    assert recorder.hosts == ["api.github.com", "objects.githubusercontent.com"]


def test_job_log_refuses_non_allowlisted_redirect(
    make_client, make_text_response, fake_credential
) -> None:
    """A log redirect off the GitHub hosts is refused, so no log fetch becomes SSRF."""
    location = "https://attacker.example.com/collect?token=stolen"

    def handler(request: httpx.Request) -> httpx.Response:
        return make_text_response("", status=302, headers={"Location": location})

    client, recorder = make_client(handler)

    with pytest.raises(GitHubApiError) as excinfo:
        client.get_job_log(REPOSITORY, "1002")

    assert "attacker.example.com" not in recorder.hosts
    assert fake_credential not in str(excinfo.value)


def test_check_rate_limit_reports_core_budget(make_client, make_json_response) -> None:
    """The rate-limit endpoint is summarised into a plain dictionary."""
    payload = {
        "resources": {"core": {"limit": 5000, "remaining": 4321, "used": 679, "reset": 1790000000}}
    }
    client, _ = make_client(lambda _request: make_json_response(payload))

    status = client.check_rate_limit()

    assert status["limit"] == 5000
    assert status["remaining"] == 4321
    assert status["used"] == 679
    assert status["reset_at"] == datetime.fromtimestamp(1790000000, tz=UTC).isoformat()


def test_network_failure_raises_api_error_without_credential(
    make_client, make_json_response, fake_credential
) -> None:
    """A transport failure is reported without the credential or a raw exception dump."""

    def handler(_request: httpx.Request) -> httpx.Response:
        message = "simulated network failure"
        raise httpx.ConnectTimeout(message)

    client, _ = make_client(handler)

    with pytest.raises(GitHubApiError) as excinfo:
        client.get_workflow_run(REPOSITORY, RUN_ID)

    error = excinfo.value
    assert "simulated network failure" not in str(error)
    assert fake_credential not in str(error)
    assert fake_credential not in (error.detail or "")


def test_malformed_json_raises_api_error(make_client, make_text_response) -> None:
    """A non-JSON body is an integration failure rather than an empty run."""
    client, _ = make_client(lambda _request: make_text_response("<html>not json</html>"))

    with pytest.raises(GitHubApiError):
        client.get_workflow_run(REPOSITORY, RUN_ID)


def test_rejects_repository_outside_owner_repo_form(make_client, make_json_response) -> None:
    """A repository value that is not owner/repo is rejected before any request."""
    client, recorder = make_client(lambda _request: make_json_response({}))

    with pytest.raises(InvalidInputError):
        client.get_workflow_run("../../etc/passwd", RUN_ID)

    assert recorder.requests == []


def test_rejects_run_id_with_path_traversal(make_client, make_json_response) -> None:
    """A run id containing path separators cannot escape the intended API path."""
    client, recorder = make_client(lambda _request: make_json_response({}))

    with pytest.raises(InvalidInputError):
        client.get_workflow_run(REPOSITORY, "../../secrets")

    assert recorder.requests == []


def test_client_repr_hides_credential(make_client, make_json_response, fake_credential) -> None:
    """Show auth state in repr, never the credential."""
    client, _ = make_client(lambda _request: make_json_response({}))

    assert fake_credential not in repr(client)
    assert "authenticated=True" in repr(client)


# ---------------------------------------------------------------------------
# Reporter: write operations are explicit opt-ins.
# ---------------------------------------------------------------------------


def test_reporter_requires_authentication_for_comments(make_client, make_json_response) -> None:
    """Posting a comment without a credential is refused before any request."""
    client, recorder = make_client(lambda _request: make_json_response({}), credential="")
    reporter = GitHubReporter(client)

    with pytest.raises(GitHubApiError):
        reporter.post_comment(ReportRequest(repository=REPOSITORY, run_id=RUN_ID, body="report"))

    assert recorder.requests == []


def test_reporter_requires_authentication_for_pull_requests(
    make_client, make_json_response
) -> None:
    """Opening a pull request without a credential is refused before any request."""
    client, recorder = make_client(lambda _request: make_json_response({}), credential="")
    reporter = GitHubReporter(client)

    with pytest.raises(GitHubApiError):
        reporter.create_pull_request(
            repository=REPOSITORY, title="fix", body="body", head="fix-branch", base="main"
        )

    assert recorder.requests == []


def test_post_comment_creates_comment_for_the_run(make_client, make_json_response) -> None:
    """A new comment is posted against the run identifier."""
    client, recorder = make_client(
        lambda _request: make_json_response({"id": 555, "html_url": "https://github.com/x"})
    )
    reporter = GitHubReporter(client)

    result = reporter.post_comment(
        ReportRequest(repository=REPOSITORY, run_id=RUN_ID, body="## Diagnosis\n- test_failure")
    )

    assert result == {"id": 555, "html_url": "https://github.com/x"}
    request = recorder.requests[0]
    assert request.method == "POST"
    assert request.url.path == f"/repos/{REPOSITORY}/issues/{RUN_ID}/comments"
    assert json.loads(request.content) == {"body": "## Diagnosis\n- test_failure"}


def test_post_comment_updates_existing_comment(make_client, make_json_response) -> None:
    """An existing comment id turns the post into an idempotent update."""
    client, recorder = make_client(lambda _request: make_json_response({"id": 555}))
    reporter = GitHubReporter(client)

    result = reporter.post_comment(
        ReportRequest(repository=REPOSITORY, run_id=RUN_ID, body="updated", comment_id="555")
    )

    assert result == {"id": 555}
    request = recorder.requests[0]
    assert request.method == "PATCH"
    assert request.url.path == f"/repos/{REPOSITORY}/issues/comments/555"
    assert json.loads(request.content) == {"body": "updated"}


def test_post_comment_rejects_empty_body(make_client, make_json_response) -> None:
    """An empty report body is rejected instead of posting an empty comment."""
    client, recorder = make_client(lambda _request: make_json_response({}))
    reporter = GitHubReporter(client)

    with pytest.raises(InvalidInputError):
        reporter.post_comment(ReportRequest(repository=REPOSITORY, run_id=RUN_ID, body="   "))

    assert recorder.requests == []


def test_create_pull_request_sends_no_merge_fields(make_client, make_json_response) -> None:
    """The pull request payload carries no merge or deploy intent."""
    client, recorder = make_client(lambda _request: make_json_response({"number": 12}))
    reporter = GitHubReporter(client)

    result = reporter.create_pull_request(
        repository=REPOSITORY, title="Fix failing test", body="body", head="fix/tests", base="main"
    )

    assert result == {"number": 12}
    request = recorder.requests[0]
    assert request.method == "POST"
    assert request.url.path == f"/repos/{REPOSITORY}/pulls"
    payload = json.loads(request.content)
    assert payload == {
        "title": "Fix failing test",
        "body": "body",
        "head": "fix/tests",
        "base": "main",
    }
    assert "merge_method" not in payload
    assert "auto_merge" not in payload


def test_create_pull_request_rejects_unusable_branch_names(make_client, make_json_response) -> None:
    """A branch name that is not a real branch never reaches the API."""
    client, recorder = make_client(lambda _request: make_json_response({}))
    reporter = GitHubReporter(client)

    with pytest.raises(InvalidInputError):
        reporter.create_pull_request(
            repository=REPOSITORY, title="fix", body="body", head="../../evil", base="main"
        )

    assert recorder.requests == []
