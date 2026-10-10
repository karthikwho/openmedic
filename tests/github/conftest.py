"""Shared fixtures for the GitHub adapter tests.

Every test in this package talks to an ``httpx.MockTransport``, and no client is ever
constructed without an injected transport, so the suite cannot reach
api.github.com even by accident.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from openmedic.github.client import GitHubClient

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

#: Stand-in credential. The name deliberately avoids secret-ish words so it reads as
#: test data, and the value is rejected by GitHub on sight.
FAKE_CREDENTIAL = "ghp_0123456789abcdef0123456789abcdef0123"

Handler = Callable[[httpx.Request], httpx.Response]


def load_json_fixture(name: str) -> Any:
    """Load a JSON fixture by file name."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def load_log_fixture(name: str) -> str:
    """Load a plain-text log fixture by file name."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


def json_response(
    payload: Any,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Build a JSON ``httpx.Response`` for a mock transport."""
    return httpx.Response(status, json=payload, headers=headers)


def text_response(
    text: str,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Build a plain-text ``httpx.Response`` for a mock transport."""
    return httpx.Response(status, text=text, headers=headers)


def handler_for(routes: dict[str, httpx.Response]) -> Handler:
    """Return a handler that serves canned responses keyed by request path."""

    def handler(request: httpx.Request) -> httpx.Response:
        return routes.get(request.url.path, httpx.Response(404, json={"message": "Not Found"}))

    return handler


class RequestRecorder:
    """Record every request a client attempted to send."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def wrap(self, handler: Handler) -> Handler:
        """Return ``handler`` wrapped so each call is recorded before it runs."""

        def recording_handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return handler(request)

        return recording_handler

    @property
    def paths(self) -> list[str]:
        """Paths of every recorded request, in order."""
        return [request.url.path for request in self.requests]

    @property
    def hosts(self) -> list[str]:
        """Hosts of every recorded request, in order."""
        return [request.url.host for request in self.requests]


def build_client(
    handler: Handler,
    *,
    credential: str | None = FAKE_CREDENTIAL,
    max_pages: int = 10,
    timeout: float = 5.0,
) -> tuple[GitHubClient, RequestRecorder]:
    """Build a client bound to ``handler`` plus a recorder of its requests."""
    recorder = RequestRecorder()
    transport = httpx.MockTransport(recorder.wrap(handler))
    client = GitHubClient(credential, transport=transport, timeout=timeout, max_pages=max_pages)
    return client, recorder


@pytest.fixture
def make_client() -> Callable[..., tuple[GitHubClient, RequestRecorder]]:
    """Return a factory that builds a mocked GitHub client and its recorder."""
    return build_client


@pytest.fixture
def router() -> Callable[[dict[str, httpx.Response]], Handler]:
    """Return a factory mapping request paths to canned responses."""
    return handler_for


@pytest.fixture
def fake_credential() -> str:
    """Return the stand-in credential used to prove the token never leaks."""
    return FAKE_CREDENTIAL


@pytest.fixture
def make_json_response() -> Callable[..., httpx.Response]:
    """Return a factory for JSON responses."""
    return json_response


@pytest.fixture
def make_text_response() -> Callable[..., httpx.Response]:
    """Return a factory for plain-text responses."""
    return text_response


@pytest.fixture
def load_json() -> Callable[[str], Any]:
    """Return a loader for JSON fixtures."""
    return load_json_fixture


@pytest.fixture
def load_log() -> Callable[[str], str]:
    """Return a loader for log fixtures."""
    return load_log_fixture
