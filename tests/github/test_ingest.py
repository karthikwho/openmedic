"""Tests for GitHub Actions ingestion.

The whole flow runs against ``httpx.MockTransport``: fetch run, list jobs, fetch the
log of the failing job, and normalise it into the shared FailureEvent contract. The
safety cases assert that no failure is fabricated and that logs are only fetched for
jobs that actually failed.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from openmedic.domain.contracts import FailureEvent
from openmedic.domain.enums import FailureType
from openmedic.domain.errors import ContractError, InvalidInputError
from openmedic.github.client import GitHubNotFoundError, JobInfo, WorkflowRun
from openmedic.github.ingest import (
    classify_failure,
    event_from_run,
    ingest_run,
    log_to_event,
)

REPOSITORY = "acme/widget"
RUN_ID = "4242"
RUN_PATH = f"/repos/{REPOSITORY}/actions/runs/{RUN_ID}"
JOBS_PATH = f"{RUN_PATH}/jobs"
JOB_LOG_PATH = "/repos/acme/widget/actions/jobs/1002/logs"


def test_ingest_run_happy_path(
    make_client, router, make_json_response, make_text_response, load_json, load_log
) -> None:
    """Run + jobs + log are combined into one normalised failure event."""
    log = load_log("logs_test_failure.txt")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == RUN_PATH:
            return make_json_response(load_json("run_test_failure.json"))
        if request.url.path == JOBS_PATH:
            return make_json_response(load_json("jobs_response.json"))
        if request.url.path == JOB_LOG_PATH:
            return make_text_response(log)
        return make_json_response({"message": "Not Found"}, status=404)

    client, _ = make_client(handler)

    event = ingest_run(client, REPOSITORY, RUN_ID)

    assert isinstance(event, FailureEvent)
    assert event.repository == REPOSITORY
    assert event.run_id == "4242"
    assert event.commit_sha == "9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c"
    assert event.workflow_name == "CI"
    assert event.job_name == "test (3.11)"
    assert event.failed_step == "Run pytest"
    assert event.failure_type is FailureType.TEST_FAILURE
    # The contract normalises surrounding whitespace on string fields, so the
    # trailing newline of the fixture is not part of the stored evidence.
    assert event.logs == log.strip()
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset().total_seconds() == 0


def test_ingest_run_classifies_dependency_failures(
    make_client, make_json_response, make_text_response, load_json, load_log
) -> None:
    """A dependency-shaped log is classified as a dependency error."""
    log = load_log("logs_dependency_error.txt")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == JOBS_PATH:
            return make_json_response(
                {"jobs": [_job_payload(1002, "build", "failure", ["Install dependencies"])]}
            )
        if request.url.path == JOB_LOG_PATH:
            return make_text_response(log)
        return make_json_response(_run_payload(conclusion="failure"))

    client, _ = make_client(handler)

    event = ingest_run(client, REPOSITORY, RUN_ID)

    assert event.failure_type is FailureType.DEPENDENCY_ERROR
    assert event.failed_step == "Install dependencies"


def test_ingest_run_fetches_logs_only_for_failing_jobs(
    make_client, make_json_response, make_text_response, load_json, load_log
) -> None:
    """Only the failing job's log is requested (TRD §11)."""
    log = load_log("logs_test_failure.txt")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == RUN_PATH:
            return make_json_response(load_json("run_test_failure.json"))
        if request.url.path == JOBS_PATH:
            return make_json_response(load_json("jobs_response.json"))
        if request.url.path.endswith("/logs"):
            return make_text_response(log)
        return make_json_response({"message": "Not Found"}, status=404)

    client, recorder = make_client(handler)

    ingest_run(client, REPOSITORY, RUN_ID)

    log_requests = [path for path in recorder.paths if path.endswith("/logs")]
    assert log_requests == [JOB_LOG_PATH]


def test_ingest_run_without_failed_jobs_raises(
    make_client, make_json_response, make_text_response, load_json
) -> None:
    """A successful run raises instead of fabricating a failure event."""
    jobs = {
        "jobs": [
            _job_payload(1001, "build", "success", []),
            _job_payload(1002, "test (3.11)", "success", []),
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == JOBS_PATH:
            return make_json_response(jobs)
        if request.url.path.endswith("/logs"):
            return make_text_response("should never be fetched")
        return make_json_response(load_json("run_success.json"))

    client, recorder = make_client(handler)

    with pytest.raises(InvalidInputError):
        ingest_run(client, REPOSITORY, RUN_ID)

    assert not [path for path in recorder.paths if path.endswith("/logs")]


def test_ingest_run_propagates_missing_log(make_client, make_json_response, load_json) -> None:
    """A deleted or expired job log is surfaced, not swallowed."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == JOBS_PATH:
            return make_json_response(load_json("jobs_response.json"))
        if request.url.path == JOB_LOG_PATH:
            return make_json_response({"message": "Not Found"}, status=404)
        return make_json_response(load_json("run_test_failure.json"))

    client, _ = make_client(handler)

    with pytest.raises(GitHubNotFoundError):
        ingest_run(client, REPOSITORY, RUN_ID)


def test_ingest_run_is_idempotent(
    make_client, make_json_response, make_text_response, load_json, load_log
) -> None:
    """Ingesting the same run twice yields the same idempotency key."""
    log = load_log("logs_test_failure.txt")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == RUN_PATH:
            return make_json_response(load_json("run_test_failure.json"))
        if request.url.path == JOBS_PATH:
            return make_json_response(load_json("jobs_response.json"))
        return make_text_response(log)

    client, _ = make_client(handler)

    first = ingest_run(client, REPOSITORY, RUN_ID)
    second = ingest_run(client, REPOSITORY, RUN_ID)

    assert first.idempotency_key == second.idempotency_key
    assert first.resolved_incident_id == second.resolved_incident_id
    assert first.idempotency_key == f"{REPOSITORY}|CI|test (3.11)|{RUN_ID}|Run pytest"


def test_event_from_run_picks_the_first_failed_job() -> None:
    """The first failed job in API order supplies the failed step."""
    run = WorkflowRun(
        run_id="77",
        repository=REPOSITORY,
        workflow_name="CI",
        commit_sha="abc",
        conclusion="failure",
        html_url="https://github.com/acme/widget/runs/77",
        jobs=("2001", "2002"),
    )
    jobs = [
        JobInfo(job_id="2001", name="build", conclusion="success", failed_steps=()),
        JobInfo(job_id="2002", name="unit", conclusion="failure", failed_steps=("Run pytest",)),
        JobInfo(job_id="2003", name="integration", conclusion="failure", failed_steps=("Smoke",)),
    ]

    event = event_from_run(REPOSITORY, run, jobs, logs="FAILED tests/test_x.py::test_y")

    assert event.job_name == "unit"
    assert event.failed_step == "Run pytest"
    assert event.failed_step != "Smoke"


def test_event_from_run_without_failed_jobs_raises() -> None:
    """No failed job means no failure event, even with logs in hand."""
    run = WorkflowRun(
        run_id="78",
        repository=REPOSITORY,
        workflow_name="CI",
        commit_sha="abc",
        conclusion="success",
        html_url="https://github.com/acme/widget/runs/78",
        jobs=("3001",),
    )
    jobs = [JobInfo(job_id="3001", name="build", conclusion="success", failed_steps=())]

    with pytest.raises(InvalidInputError):
        event_from_run(REPOSITORY, run, jobs, logs="1 failed")


def test_log_to_event_builds_a_complete_event(load_log) -> None:
    """A raw log plus explicit metadata produces a valid contract event."""
    event = log_to_event(
        load_log("logs_test_failure.txt"),
        repository=REPOSITORY,
        run_id="4242",
        workflow_name="CI",
        commit_sha="9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c",
        failed_step="Run pytest",
        job_name="test (3.11)",
        timestamp=datetime(2026, 10, 9, 12, 4, 31, tzinfo=UTC),
    )

    assert event.failure_type is FailureType.TEST_FAILURE
    assert event.failed_step == "Run pytest"
    assert event.job_name == "test (3.11)"
    assert event.timestamp == datetime(2026, 10, 9, 12, 4, 31, tzinfo=UTC)


def test_log_to_event_rejects_a_naive_timestamp() -> None:
    """A timezone-naive timestamp is rejected by the contract."""
    with pytest.raises(ContractError):
        log_to_event(
            "",
            repository=REPOSITORY,
            run_id="4242",
            workflow_name="CI",
            commit_sha="abc",
            failed_step="Run pytest",
            timestamp=datetime(2026, 10, 9, 12, 4, 31),
        )


def test_logs_stay_raw_for_quote_verification_but_can_be_redacted(load_log) -> None:
    """Ingestion keeps raw logs; redaction is available and separate."""
    bearer = "ghp_secretvaluesecretvalue1"
    log = f"{load_log('logs_test_failure.txt')}\nAuthorization: Bearer {bearer}\n"
    event = log_to_event(
        log,
        repository=REPOSITORY,
        run_id="4242",
        workflow_name="CI",
        commit_sha="abc",
        failed_step="Run pytest",
    )

    assert bearer in event.logs
    assert bearer not in event.redacted().logs
    assert "[REDACTED]" in event.redacted().logs


def test_classify_failure_returns_unknown_without_signals() -> None:
    """An unrecognised log is honestly classified as unknown."""
    assert classify_failure("") is FailureType.UNKNOWN
    assert classify_failure("Runner exited for no clear reason") is FailureType.UNKNOWN


def test_classify_failure_detects_build_and_config_errors() -> None:
    """A build failure is not silently reported as a test failure."""
    assert (
        classify_failure("make: *** [Makefile:4: build] Error 2")
        is FailureType.BUILD_OR_CONFIG_ERROR
    )
    assert (
        classify_failure("webpack 5.0.0 compiled with 2 errors")
        is FailureType.BUILD_OR_CONFIG_ERROR
    )


def _job_payload(
    job_id: int, name: str, conclusion: str, failed_steps: list[str]
) -> dict[str, object]:
    """Build a minimal GitHub job payload for the mock transport."""
    steps: list[dict[str, object]] = [
        {"number": 1, "name": "Set up job", "status": "completed", "conclusion": "success"}
    ]
    for step_name in failed_steps:
        steps.append(
            {
                "number": len(steps) + 1,
                "name": step_name,
                "status": "completed",
                "conclusion": "failure",
            }
        )
    return {
        "id": job_id,
        "run_id": 4242,
        "name": name,
        "status": "completed",
        "conclusion": conclusion,
        "steps": steps,
    }


def _run_payload(conclusion: str) -> dict[str, object]:
    """Build a minimal GitHub workflow-run payload for the mock transport."""
    return {
        "id": 4242,
        "name": "CI",
        "head_sha": "9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c",
        "conclusion": conclusion,
        "html_url": f"https://github.com/{REPOSITORY}/actions/runs/4242",
    }
