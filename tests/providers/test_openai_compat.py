"""Unit tests for the OpenAI-compatible adapter.

Every request goes through ``httpx.MockTransport``: no test opens a socket, and retry
backoff uses an injected sleep so no test blocks.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

import httpx
import pytest

from openmedic.domain.contracts import FailureEvent
from openmedic.domain.enums import FailureType
from openmedic.providers.base import (
    ProviderAuthError,
    ProviderConfig,
    ProviderContext,
    ProviderOutputError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    allowed_quote_lines,
)
from openmedic.providers.openai_compat import PROVIDER_NAME, OpenAICompatibleProvider

TIMESTAMP = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
ENDPOINT = "https://api.example.test/v1"
API_KEY_VALUE = "sk-not-a-real-key-1234567890"
GITHUB_PAT_VALUE = "ghp_abcdefghijklmnopqrstuvwxyz012345"

LOGS = (
    "Run: pytest -q\n"
    "collected 3 items\n"
    "tests/test_api.py::test_token FAILED\n"
    "ModuleNotFoundError: No module named 'requests'\n"
    "Authorization: Bearer " + API_KEY_VALUE + "\n"
    "Error: GITHUB_TOKEN=" + GITHUB_PAT_VALUE + "\n"
)

VERBATIM_QUOTE = "ModuleNotFoundError: No module named 'requests'"

DEFAULT_USAGE = {"prompt_tokens": 120, "completion_tokens": 24, "total_tokens": 144}


def _event() -> FailureEvent:
    return FailureEvent(
        repository="acme/widgets",
        commit_sha="a" * 40,
        workflow_name="ci",
        run_id="42",
        failed_step="pytest",
        failure_type=FailureType.DEPENDENCY_ERROR,
        logs=LOGS,
        timestamp=TIMESTAMP,
    )


def _context(event: FailureEvent, **kwargs: object) -> ProviderContext:
    values: dict[str, object] = {
        "event": event,
        "deterministic_diagnosis": None,
        "request_id": "req-0001",
        "allowed_quote_lines": allowed_quote_lines(event),
    }
    values.update(kwargs)
    return ProviderContext(**values)  # type: ignore[arg-type]


def _model_content(**overrides: object) -> str:
    payload: dict[str, object] = {
        "probable_cause": "The requests package is missing from the CI environment.",
        "confidence": 0.82,
        "recommended_action": "fix_dependency",
        "risk_level": "low",
        "requires_human_review": False,
        "raw_quotes": [VERBATIM_QUOTE],
        "limitations": ["the dependency manifest was not in the log excerpt"],
    }
    payload.update(overrides)
    return json.dumps(payload)


def _completion_body(content: object = None, *, usage: object = DEFAULT_USAGE) -> dict[str, object]:
    """Return the chat-completions body replayed by the mocked transport."""
    if content is None:
        content = _model_content()
    return {
        "id": "cmpl-test",
        "object": "chat.completion",
        "model": "gpt-test",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": usage,
    }


def _completion(content: object = None, *, usage: object = DEFAULT_USAGE) -> httpx.Response:
    return httpx.Response(200, json=_completion_body(content, usage=usage))


def _scripted(*responses: httpx.Response | Exception) -> tuple[object, list[dict[str, object]]]:
    """Return a transport handler that replays ``responses`` and records each request."""
    if not responses:
        message = "at least one scripted response is required"
        raise AssertionError(message)
    calls: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        index = min(len(calls), len(responses) - 1)
        calls.append(
            {
                "url": str(request.url),
                "headers": dict(request.headers),
                "raw": request.content,
                "body": json.loads(request.content),
            }
        )
        outcome = responses[index]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return handler, calls


def _build(
    client: httpx.Client,
    *,
    endpoint: str = ENDPOINT,
    model: str = "gpt-test",
    enabled: bool = True,
    timeout_seconds: float = 5.0,
    max_retries: int = 0,
    max_context_chars: int = 6000,
    api_key_env: str = "",
    credential: str | None = None,
    sleeps: list[float] | None = None,
) -> OpenAICompatibleProvider:
    """Build an adapter around ``client`` with an injected sleep and credential reader."""
    config = ProviderConfig(
        name=PROVIDER_NAME,
        endpoint=endpoint,
        model=model,
        api_key_env=api_key_env,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
        max_context_chars=max_context_chars,
        enabled=enabled,
        temperature=0.0,
    )
    reader = (lambda _name: credential) if api_key_env else (lambda _name: None)
    return OpenAICompatibleProvider(
        config,
        client=client,
        sleep=(sleeps.append if sleeps is not None else None),
        credential_reader=reader,
    )


@contextmanager
def _adapter(
    *responses: httpx.Response | Exception, **kwargs: object
) -> Iterator[tuple[OpenAICompatibleProvider, list[dict[str, object]], list[float]]]:
    """Yield ``(provider, calls, sleeps)`` backed by a mock transport."""
    handler, calls = _scripted(*responses)
    sleeps: list[float] = []
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        options: dict[str, object] = {
            "endpoint": ENDPOINT,
            "model": "gpt-test",
            "timeout_seconds": 5.0,
            "sleeps": sleeps,
        }
        options.update(kwargs)
        yield _build(client, **options), calls, sleeps  # type: ignore[arg-type]
    finally:
        client.close()


# ----------------------------------------------------------------- happy path


def test_fixed_response_produces_a_deterministic_result() -> None:
    event = _event()

    with _adapter(_completion()) as (provider, calls, _sleeps):
        first = provider.diagnose(event, context=_context(event))
        second = provider.diagnose(event, context=_context(event))

    assert first == second
    assert first.to_dict() == second.to_dict()
    assert first.provider == PROVIDER_NAME
    assert first.probable_cause == "The requests package is missing from the CI environment."
    assert first.confidence == 0.82
    assert first.recommended_action == "fix_dependency"
    assert first.risk_level == "low"
    assert first.requires_human_review is False
    assert first.limitations == ["the dependency manifest was not in the log excerpt"]
    assert first.raw_quotes == [VERBATIM_QUOTE]
    assert first.usage == DEFAULT_USAGE
    assert len(calls) == 2


def test_usage_is_none_when_the_provider_does_not_report_it() -> None:
    event = _event()

    with _adapter(_completion(usage=None)) as (provider, _calls, _sleeps):
        result = provider.diagnose(event, context=_context(event))

    assert result.usage is None


def test_content_returned_as_parts_is_joined() -> None:
    event = _event()
    parts = [{"type": "text", "text": _model_content()}]

    with _adapter(_completion(content=parts)) as (provider, _calls, _sleeps):
        result = provider.diagnose(event, context=_context(event))

    assert result.raw_quotes == [VERBATIM_QUOTE]


def test_request_payload_is_bounded_and_schema_constrained() -> None:
    event = _event()

    with _adapter(_completion()) as (provider, calls, _sleeps):
        provider.diagnose(event, context=_context(event))

    body = calls[0]["body"]
    assert calls[0]["url"] == ENDPOINT + "/chat/completions"
    assert body["model"] == "gpt-test"
    assert body["temperature"] == 0.0
    assert body["stream"] is False
    schema = body["response_format"]
    assert schema["type"] == "json_schema"
    assert schema["json_schema"]["strict"] is True
    assert set(schema["json_schema"]["schema"]["required"]) == {
        "probable_cause",
        "confidence",
        "recommended_action",
        "risk_level",
        "requires_human_review",
        "raw_quotes",
        "limitations",
    }
    assert body["messages"][0]["role"] == "system"

    prompt = json.loads(body["messages"][1]["content"])
    assert prompt["request_id"] == "req-0001"
    assert prompt["failure_type"] == "dependency_error"
    assert VERBATIM_QUOTE in prompt["log_excerpt"]
    assert prompt["deterministic_hint"] is None
    assert prompt["log_excerpt_truncated"] is False


def test_deterministic_hint_is_included_when_available() -> None:
    from openmedic.domain.contracts import DiagnosisResult, Evidence
    from openmedic.domain.enums import RecommendedAction, RiskLevel

    event = _event()
    diagnosis = DiagnosisResult(
        incident_id=event.resolved_incident_id,
        failure_type=FailureType.DEPENDENCY_ERROR,
        probable_cause="requests is not installed",
        evidence=[Evidence(source="logs:4", quote=VERBATIM_QUOTE, explanation="import failed")],
        confidence=0.9,
        recommended_action=RecommendedAction.FIX_DEPENDENCY,
        risk_level=RiskLevel.HIGH,
        requires_human_review=True,
        limitations=["manifest unavailable"],
    )

    with _adapter(_completion()) as (provider, calls, _sleeps):
        provider.diagnose(event, context=_context(event, deterministic_diagnosis=diagnosis))

    prompt = json.loads(calls[0]["body"]["messages"][1]["content"])
    assert prompt["deterministic_hint"]["risk_level"] == "high"
    assert prompt["deterministic_hint"]["evidence_quotes"] == [VERBATIM_QUOTE]


def test_log_excerpt_is_truncated_to_max_context_chars() -> None:
    event = _event()

    with _adapter(_completion(), max_context_chars=100) as (provider, calls, _sleeps):
        provider.diagnose(event, context=_context(event))

    prompt = json.loads(calls[0]["body"]["messages"][1]["content"])
    excerpt = prompt["log_excerpt"]
    assert len(excerpt) <= 100 + len("\n...[log excerpt truncated]")
    assert excerpt.endswith("...[log excerpt truncated]")
    assert prompt["log_excerpt_truncated"] is True


def test_an_explicit_timeout_object_is_sent_with_every_request() -> None:
    event = _event()
    seen: list[dict[str, object]] = []

    class _Recorder:
        def post(self, url: str, **kwargs: object) -> httpx.Response:
            seen.append(kwargs)
            request = httpx.Request("POST", url)
            return httpx.Response(200, json=_completion_body(), request=request)

    provider = _build(_Recorder(), timeout_seconds=7.5)  # type: ignore[arg-type]

    provider.diagnose(event, context=_context(event))

    timeout = seen[0]["timeout"]
    assert isinstance(timeout, httpx.Timeout)
    assert timeout.read == 7.5
    assert timeout.connect == 7.5


def test_fully_qualified_endpoint_is_not_doubled() -> None:
    event = _event()
    qualified = ENDPOINT + "/chat/completions"

    with _adapter(_completion(), endpoint=qualified) as (provider, calls, _sleeps):
        provider.diagnose(event, context=_context(event))

    assert calls[0]["url"] == qualified


# --------------------------------------------------------------- typed errors


def test_401_raises_an_auth_error() -> None:
    event = _event()

    with (
        _adapter(httpx.Response(401, json={"error": "unauthorized"})) as (
            provider,
            calls,
            sleeps,
        ),
        pytest.raises(ProviderAuthError) as excinfo,
    ):
        provider.diagnose(event, context=_context(event))

    assert calls[0]["url"].endswith("/chat/completions")
    assert "401" in str(excinfo.value)
    assert sleeps == []


def test_403_raises_an_auth_error() -> None:
    event = _event()

    with (
        _adapter(httpx.Response(403, json={"error": "forbidden"})) as (
            provider,
            _calls,
            _sleeps,
        ),
        pytest.raises(ProviderAuthError),
    ):
        provider.diagnose(event, context=_context(event))


def test_timeout_raises_a_timeout_error_without_retrying() -> None:
    event = _event()
    message = "simulated slow provider"

    def _timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(message, request=request)

    _handler, calls = _scripted(_completion())
    client = httpx.Client(transport=httpx.MockTransport(_timeout))
    provider = _build(client, max_retries=3, sleeps=[])
    try:
        with pytest.raises(ProviderTimeoutError) as excinfo:
            provider.diagnose(event, context=_context(event))
    finally:
        client.close()

    assert "5.0" in str(excinfo.value)
    assert calls == []


def test_connect_timeout_is_also_a_timeout_error() -> None:
    event = _event()
    message = "simulated connect timeout"

    def _timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout(message, request=request)

    client = httpx.Client(transport=httpx.MockTransport(_timeout))
    provider = _build(client)
    try:
        with pytest.raises(ProviderTimeoutError):
            provider.diagnose(event, context=_context(event))
    finally:
        client.close()


def test_non_2xx_raises_unavailable() -> None:
    event = _event()

    for status in (400, 404, 500, 502, 503):
        with (
            _adapter(httpx.Response(status, json={"error": "boom"})) as (
                provider,
                calls,
                _sleeps,
            ),
            pytest.raises(ProviderUnavailableError) as excinfo,
        ):
            provider.diagnose(event, context=_context(event))
        assert str(status) in str(excinfo.value)
        assert len(calls) == 1


def test_malformed_json_body_raises_an_output_error() -> None:
    event = _event()

    with (
        _adapter(httpx.Response(200, text="this is not json")) as (
            provider,
            _calls,
            _sleeps,
        ),
        pytest.raises(ProviderOutputError),
    ):
        provider.diagnose(event, context=_context(event))


def test_body_without_choices_raises_an_output_error() -> None:
    event = _event()

    with (
        _adapter(httpx.Response(200, json={"id": "cmpl"})) as (
            provider,
            _calls,
            _sleeps,
        ),
        pytest.raises(ProviderOutputError),
    ):
        provider.diagnose(event, context=_context(event))


def test_content_that_is_not_json_raises_an_output_error() -> None:
    event = _event()

    with (
        _adapter(_completion(content="I think it is a dependency problem.")) as (
            provider,
            _calls,
            _sleeps,
        ),
        pytest.raises(ProviderOutputError),
    ):
        provider.diagnose(event, context=_context(event))


def test_content_missing_probable_cause_raises_an_output_error() -> None:
    event = _event()
    broken = json.loads(_model_content())
    broken.pop("probable_cause")

    with (
        _adapter(_completion(content=json.dumps(broken))) as (
            provider,
            _calls,
            _sleeps,
        ),
        pytest.raises(ProviderOutputError),
    ):
        provider.diagnose(event, context=_context(event))


def test_non_numeric_confidence_raises_an_output_error() -> None:
    event = _event()

    with (
        _adapter(_completion(content=_model_content(confidence="high"))) as (
            provider,
            _calls,
            _sleeps,
        ),
        pytest.raises(ProviderOutputError),
    ):
        provider.diagnose(event, context=_context(event))


def test_refusal_raises_an_output_error() -> None:
    event = _event()
    response = httpx.Response(
        200,
        json={"choices": [{"message": {"role": "assistant", "content": None, "refusal": "no"}}]},
    )

    with _adapter(response) as (provider, _calls, _sleeps), pytest.raises(ProviderOutputError):
        provider.diagnose(event, context=_context(event))


# --------------------------------------------------------------------- retries


def test_429_then_200_retries_exactly_once_without_really_sleeping() -> None:
    event = _event()

    with _adapter(
        httpx.Response(429, json={"error": "slow down"}), _completion(), max_retries=2
    ) as (provider, calls, sleeps):
        started = time.monotonic()
        result = provider.diagnose(event, context=_context(event))
        elapsed = time.monotonic() - started

    assert result.raw_quotes == [VERBATIM_QUOTE]
    assert len(calls) == 2
    assert sleeps == [0.5]
    assert elapsed < 0.5  # the injected sleep never blocked


def test_5xx_then_200_retries() -> None:
    event = _event()

    with _adapter(httpx.Response(503, json={"error": "busy"}), _completion(), max_retries=1) as (
        provider,
        calls,
        sleeps,
    ):
        provider.diagnose(event, context=_context(event))

    assert len(calls) == 2
    assert sleeps == [0.5]


def test_retry_exhaustion_raises_the_typed_error() -> None:
    event = _event()
    busy = httpx.Response(429, json={"error": "slow down"})

    with (
        _adapter(busy, busy, max_retries=1) as (provider, calls, sleeps),
        pytest.raises(ProviderTimeoutError),
    ):
        provider.diagnose(event, context=_context(event))

    assert len(calls) == 2
    assert sleeps == [0.5]


def test_backoff_is_bounded_and_exponential() -> None:
    event = _event()
    busy = httpx.Response(429, json={"error": "slow down"})

    with (
        _adapter(busy, busy, busy, busy, max_retries=3) as (
            provider,
            calls,
            sleeps,
        ),
        pytest.raises(ProviderTimeoutError),
    ):
        provider.diagnose(event, context=_context(event))

    assert len(calls) == 4
    assert sleeps == [0.5, 1.0, 2.0]


def test_client_errors_are_not_retried() -> None:
    event = _event()

    with (
        _adapter(httpx.Response(400, json={"error": "bad request"}), max_retries=3) as (
            provider,
            calls,
            sleeps,
        ),
        pytest.raises(ProviderUnavailableError),
    ):
        provider.diagnose(event, context=_context(event))

    assert len(calls) == 1
    assert sleeps == []


def test_auth_failures_are_not_retried() -> None:
    event = _event()

    with (
        _adapter(httpx.Response(401, json={"error": "nope"}), max_retries=3) as (
            provider,
            calls,
            sleeps,
        ),
        pytest.raises(ProviderAuthError),
    ):
        provider.diagnose(event, context=_context(event))

    assert len(calls) == 1
    assert sleeps == []


# ------------------------------------------------------- configuration guards


def test_missing_model_makes_no_request_and_raises_unavailable() -> None:
    event = _event()

    with (
        _adapter(_completion(), model="") as (
            provider,
            calls,
            _sleeps,
        ),
        pytest.raises(ProviderUnavailableError) as excinfo,
    ):
        provider.diagnose(event, context=_context(event))

    assert calls == []
    assert "no model is configured" in (excinfo.value.detail or "")


def test_missing_credential_raises_auth_error_before_any_request() -> None:
    event = _event()

    with (
        _adapter(_completion(), api_key_env="OPENMEDIC_TEST_KEY", credential=None) as (
            provider,
            calls,
            _sleeps,
        ),
        pytest.raises(ProviderAuthError) as excinfo,
    ):
        provider.diagnose(event, context=_context(event))

    assert calls == []
    assert "OPENMEDIC_TEST_KEY" in str(excinfo.value)
    assert API_KEY_VALUE not in str(excinfo.value)


def test_healthcheck_reports_configuration_without_network() -> None:
    client = httpx.Client(transport=httpx.MockTransport(_scripted(_completion())[0]))

    usable = _build(client, api_key_env="KEY", credential=API_KEY_VALUE)
    missing_key = _build(client, api_key_env="KEY", credential=None)
    disabled = _build(client, enabled=False)
    no_model = _build(client, model="")

    assert usable.healthcheck() is True
    assert missing_key.healthcheck() is False
    assert disabled.healthcheck() is False
    assert no_model.healthcheck() is False


def test_owned_client_is_created_and_closed_without_network() -> None:
    provider = OpenAICompatibleProvider(
        ProviderConfig(name=PROVIDER_NAME, endpoint=ENDPOINT, model="gpt-test", enabled=True)
    )

    assert provider.healthcheck() is True
    provider.close()
    provider.close()  # idempotent
    assert provider.healthcheck() is True


def test_a_disabled_provider_never_touches_the_client() -> None:
    event = _event()
    touched: list[str] = []

    class _ExplodingClient:
        def post(self, url: str, **kwargs: object) -> httpx.Response:
            touched.append(url)
            message = "a disabled provider must not send a request"
            raise AssertionError(message)

    provider = _build(_ExplodingClient(), enabled=False)  # type: ignore[arg-type]

    with pytest.raises(ProviderUnavailableError):
        provider.diagnose(event, context=_context(event))

    assert touched == []
