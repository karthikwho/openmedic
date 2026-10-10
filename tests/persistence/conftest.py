"""Shared fixtures for the persistence tests.

Every fixture is deterministic and every database lives under ``tmp_path``: the suite
never touches a real user store.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from openmedic.domain.contracts import (
    CheckResult,
    DiagnosisResult,
    Evidence,
    ExecutionMetadata,
    FailureEvent,
    IncidentRecord,
    RemediationAttempt,
    ValidationResult,
)
from openmedic.domain.enums import (
    CheckStatus,
    FailureType,
    RecommendedAction,
    RemediationStatus,
    RiskLevel,
)
from openmedic.persistence import IncidentRepository
from openmedic.persistence.database import connect

#: Fixed clock so ordering assertions are exact instead of timing-dependent.
BASE_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

#: A fake credential used to prove redaction happens before persistence. It matches the
#: Anthropic key shape on purpose and is not a real secret.
LEAKED_VALUE = "sk-ant-api03-A1b2C3d4E5f6G7h8I9j0K1"

#: A fake bearer token, used the same way.
LEAKED_BEARER = "abcdefghijklmnopqrstuvwxyz012345"

PATCH_HASH = "a" * 64
OTHER_PATCH_HASH = "b" * 64


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """Return a fresh database path inside the test's temporary directory."""
    return tmp_path / "incidents.sqlite3"


@pytest.fixture
def conn(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Return an unmigrated connection, for migration-level tests."""
    connection = connect(db_path)
    yield connection
    connection.close()


@pytest.fixture
def repo(db_path: Path) -> Iterator[IncidentRepository]:
    """Return an open repository on a freshly migrated database."""
    repository = IncidentRepository(db_path)
    yield repository
    repository.close()


@pytest.fixture
def make_event() -> Callable[..., FailureEvent]:
    """Return a factory for deterministic failure events."""

    def build(**overrides: object) -> FailureEvent:
        defaults: dict[str, object] = {
            "repository": "acme/widget",
            "commit_sha": "a" * 40,
            "workflow_name": "ci",
            "run_id": "1001",
            "job_name": "test",
            "failed_step": "pytest",
            "failure_type": FailureType.TEST_FAILURE,
            "logs": "Running pytest\nAssertionError: expected 2 got 1\n1 failed\n",
            "timestamp": BASE_TIME,
        }
        defaults.update(overrides)
        return FailureEvent(**defaults)  # type: ignore[arg-type]

    return build


#: Keys that belong on :class:`FailureEvent`, not on the incident record. Tests use them
#: directly (``make_incident(logs=..., run_id=...)``), so the factory routes them to the
#: derived event rather than letting Pydantic reject them as unknown record fields.
EVENT_KEYS: frozenset[str] = frozenset(
    {
        "repository",
        "commit_sha",
        "workflow_name",
        "run_id",
        "job_name",
        "failed_step",
        "failure_type",
        "logs",
        "timestamp",
        "source_path",
    }
)


@pytest.fixture
def make_incident(make_event: Callable[..., FailureEvent]) -> Callable[..., IncidentRecord]:
    """Return a factory for incident records derived from an event."""

    def build(**overrides: object) -> IncidentRecord:
        supplied_event = overrides.pop("event", None)
        event_overrides = {k: v for k, v in overrides.items() if k in EVENT_KEYS}
        for key in event_overrides:
            overrides.pop(key)
        if supplied_event is not None and event_overrides:
            msg = "pass either an explicit event= or event fields, not both"
            raise ValueError(msg)
        event = supplied_event or make_event(**event_overrides)  # type: ignore[arg-type]
        defaults: dict[str, object] = {
            "incident_id": event.resolved_incident_id,
            "event": event,
            "idempotency_key": event.idempotency_key,
            "created_at": BASE_TIME,
            "updated_at": BASE_TIME,
        }
        defaults.update(overrides)
        return IncidentRecord(**defaults)  # type: ignore[arg-type]

    return build


@pytest.fixture
def make_diagnosis() -> Callable[..., DiagnosisResult]:
    """Return a factory for diagnoses tied to a given incident."""

    def build(incident: IncidentRecord, **overrides: object) -> DiagnosisResult:
        defaults: dict[str, object] = {
            "incident_id": incident.incident_id,
            "failure_type": FailureType.TEST_FAILURE,
            "probable_cause": "the assertion no longer matches the expected total",
            "confidence": 0.8,
            "recommended_action": RecommendedAction.FIX_FAILING_TEST,
            "risk_level": RiskLevel.LOW,
            "evidence": [
                Evidence(
                    source="logs:2",
                    quote="AssertionError: expected 2 got 1",
                    explanation="the failing assertion names the mismatch",
                )
            ],
            "limitations": ["a single run was inspected"],
        }
        defaults.update(overrides)
        return DiagnosisResult(**defaults)  # type: ignore[arg-type]

    return build


@pytest.fixture
def make_attempt() -> Callable[..., RemediationAttempt]:
    """Return a factory for remediation attempts tied to a given incident."""

    def build(incident: IncidentRecord, **overrides: object) -> RemediationAttempt:
        defaults: dict[str, object] = {
            "attempt_id": "attempt-1",
            "incident_id": incident.incident_id,
            "status": RemediationStatus.PROPOSED,
            "rule_id": "tighten-assert",
            "summary": "update the expected total in the assertion",
            "rationale": "the fixture drifted and the assertion is now stale",
            "risk_level": RiskLevel.LOW,
            "files_changed": ["tests/test_total.py"],
            "patch_unified_diff": (
                "--- a/tests/test_total.py\n+++ b/tests/test_total.py\n"
                "@@ -1 +1 @@\n-assert total == 1\n+assert total == 2\n"
            ),
            "patch_hash": PATCH_HASH,
            "created_at": BASE_TIME + timedelta(minutes=2),
        }
        defaults.update(overrides)
        return RemediationAttempt(**defaults)  # type: ignore[arg-type]

    return build


@pytest.fixture
def make_validation() -> Callable[..., ValidationResult]:
    """Return a factory for validation results tied to a given incident."""

    def build(incident: IncidentRecord, **overrides: object) -> ValidationResult:
        defaults: dict[str, object] = {
            "incident_id": incident.incident_id,
            "candidate_patch_hash": PATCH_HASH,
            "passed": True,
            "checks_executed": [
                CheckResult(
                    name="pytest",
                    command=["pytest", "-q"],
                    status=CheckStatus.PASSED,
                    exit_code=0,
                    duration_seconds=3.5,
                    stdout_excerpt="12 passed",
                    stderr_excerpt="",
                )
            ],
            "failed_checks": [],
            "summary": "the allowlisted checks ran and passed",
            "started_at": BASE_TIME + timedelta(minutes=3),
            "completed_at": BASE_TIME + timedelta(minutes=3, seconds=5),
            "execution": ExecutionMetadata(
                isolation_kind="local-subprocess",
                sandbox_id="sandbox-1",
                timeout_seconds=120.0,
                limitations=["a subprocess is not a hardened sandbox"],
            ),
        }
        defaults.update(overrides)
        return ValidationResult(**defaults)  # type: ignore[arg-type]

    return build
