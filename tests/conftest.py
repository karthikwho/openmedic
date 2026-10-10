"""Shared pytest fixtures for the OpenMedic test suite.

Every test that needs a database, repository, or scratch directory receives a fresh
temporary one. No test ever touches a developer's real incident data.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from openmedic.domain import (
    FailureEvent,
    FailureType,
)

FIXED_TS = datetime(2026, 10, 9, 12, 0, 0, tzinfo=UTC)


def make_event(**overrides: object) -> FailureEvent:
    """Build a valid FailureEvent, overriding only what a test cares about."""
    defaults: dict[str, object] = {
        "failure_type": FailureType.UNKNOWN,
        "logs": "ERROR: something went wrong\n  at line 42",
        "timestamp": FIXED_TS,
        "repository": "example/application",
        "workflow_name": "CI",
        "run_id": "1001",
        "failed_step": "test",
        "commit_sha": "a" * 40,
    }
    defaults.update(overrides)
    return FailureEvent(**defaults)  # type: ignore[arg-type]


@pytest.fixture
def event() -> FailureEvent:
    return make_event()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "nested" / "incidents.db"


@pytest.fixture
def secret_log() -> str:
    """Return a log carrying fake-but-shaped secrets that must never be persisted."""
    return (
        "Run started\n"
        "OPENMEDIC_PROVIDER_API_KEY=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "Authorization: Bearer ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "DB password=Sup3rS3cr3tValue123\n"
        "ERROR: ModuleNotFoundError: No module named 'requests'\n"
    )


__all__ = ["FIXED_TS", "make_event"]
