"""Unit tests for the provider base contract, providerless mode, and the registry.

Nothing here performs network I/O. The providerless-mode and disabled-provider cases are
the point of this module: a missing provider is a typed error, never a fabricated answer.
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from openmedic.domain.contracts import DiagnosisResult, Evidence, FailureEvent
from openmedic.domain.enums import FailureType, RecommendedAction, RiskLevel
from openmedic.domain.errors import OpenMedicError, UsageError
from openmedic.providers.base import (
    TRUNCATION_MARKER,
    DiagnosisProvider,
    ProviderAuthError,
    ProviderConfig,
    ProviderContext,
    ProviderError,
    ProviderOutputError,
    ProviderResult,
    ProviderTimeoutError,
    ProviderUnavailableError,
    allowed_quote_lines,
)
from openmedic.providers.openai_compat import PROVIDER_NAME, OpenAICompatibleProvider
from openmedic.providers.registry import NoopProvider, ProviderRegistry

TIMESTAMP = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def _event() -> FailureEvent:
    return FailureEvent(
        repository="acme/widgets",
        commit_sha="a" * 40,
        workflow_name="ci",
        run_id="42",
        failed_step="pytest",
        failure_type=FailureType.DEPENDENCY_ERROR,
        logs="run tests\nModuleNotFoundError: No module named 'requests'\n",
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


def _deterministic(event: FailureEvent) -> DiagnosisResult:
    return DiagnosisResult(
        incident_id=event.resolved_incident_id,
        failure_type=FailureType.DEPENDENCY_ERROR,
        probable_cause="The requests package is not installed in the CI job.",
        evidence=[
            Evidence(
                source="logs:2",
                quote="ModuleNotFoundError: No module named 'requests'",
                explanation="The interpreter could not import the test dependency.",
            )
        ],
        confidence=0.9,
        recommended_action=RecommendedAction.FIX_DEPENDENCY,
        risk_level=RiskLevel.HIGH,
        requires_human_review=True,
        limitations=["dependency manifest was not available"],
    )


def _result(**kwargs: object) -> ProviderResult:
    values: dict[str, object] = {
        "provider": PROVIDER_NAME,
        "probable_cause": "missing dependency",
        "confidence": 0.5,
        "recommended_action": "fix_dependency",
        "risk_level": "low",
        "requires_human_review": False,
        "limitations": ["model was used"],
        "raw_quotes": ["ModuleNotFoundError: No module named 'requests'"],
    }
    values.update(kwargs)
    return ProviderResult(**values)  # type: ignore[arg-type]


# --------------------------------------------------------------------- config


def test_provider_config_defaults_to_disabled_providerless_mode() -> None:
    config = ProviderConfig()

    assert config.name == "none"
    assert config.endpoint == ""
    assert config.model == ""
    assert config.api_key_env == ""
    assert config.timeout_seconds == 30.0
    assert config.max_retries == 0
    assert config.temperature == 0.0
    assert config.max_context_chars == 6000
    assert config.enabled is False
    assert config.extra == {}
    assert isinstance(config.extra, dict)


def test_provider_config_is_frozen_and_serialisable() -> None:
    config = ProviderConfig(name=PROVIDER_NAME, endpoint="https://api.test/v1", extra={"a": "b"})

    with pytest.raises(FrozenInstanceError):
        config.endpoint = "https://elsewhere/v1"  # type: ignore[misc]

    payload = config.to_dict()
    assert payload["name"] == PROVIDER_NAME
    assert payload["extra"] == {"a": "b"}
    assert json.dumps(payload)  # JSON-serialisable


def test_provider_context_uses_the_redacted_quote_vocabulary() -> None:
    event = _event()

    context = _context(event)

    assert context.allowed_quote_lines == frozenset(
        {"run tests", "ModuleNotFoundError: No module named 'requests'"}
    )
    assert context.request_id == "req-0001"
    assert context.deterministic_diagnosis is None


# ------------------------------------------------------------- normalisation


def test_unrecognised_risk_level_is_escalated_never_downgraded() -> None:
    result = _result(risk_level="whatever", requires_human_review=False)

    assert result.risk_level == RiskLevel.HIGH.value
    assert result.requires_human_review is True
    assert any("unrecognised risk level" in item for item in result.limitations)


def test_published_risk_levels_pass_through_unchanged() -> None:
    for level in RiskLevel:
        assert _result(risk_level=level.value).risk_level == level.value


def test_unrecognised_recommended_action_becomes_investigate_manually() -> None:
    result = _result(recommended_action="delete_everything")

    assert result.recommended_action == RecommendedAction.INVESTIGATE_MANUALLY.value
    assert result.requires_human_review is True
    assert any("outside the published set" in item for item in result.limitations)


def test_confidence_is_clamped_into_the_unit_interval() -> None:
    assert _result(confidence=5.0).confidence == 1.0
    assert _result(confidence=-3.0).confidence == 0.0
    assert _result(confidence="not-a-number").confidence == 0.0  # type: ignore[arg-type]


def test_free_text_and_quotes_are_bounded() -> None:
    duplicate = "b" * 5000
    result = _result(
        probable_cause="x" * 9000,
        raw_quotes=["a" * 5000, duplicate, duplicate, "keep", *(f"q{i}" for i in range(40))],
    )

    assert len(result.probable_cause) == 4000 + len(TRUNCATION_MARKER)
    assert result.probable_cause.endswith(TRUNCATION_MARKER)
    assert len(result.raw_quotes) == 25  # MAX_PROVIDER_QUOTES
    assert result.raw_quotes[0] == "a" * 4000 + TRUNCATION_MARKER
    assert result.raw_quotes.count("b" * 4000 + TRUNCATION_MARKER) == 1  # de-duplicated
    assert result.raw_quotes[-1] == "q21"


def test_result_is_serialisable() -> None:
    payload = _result().to_dict()

    assert payload["risk_level"] == "low"
    assert payload["usage"] is None
    assert json.dumps(payload)


# -------------------------------------------------------------------- errors


def test_provider_error_hierarchy_and_exit_codes() -> None:
    assert issubclass(ProviderAuthError, ProviderError)
    assert issubclass(ProviderOutputError, ProviderError)
    assert issubclass(ProviderTimeoutError, ProviderError)
    assert issubclass(ProviderUnavailableError, ProviderError)
    assert issubclass(ProviderError, OpenMedicError)
    # A provider failure is an unavailable integration, not a user input error.
    assert ProviderError.exit_code == 5


def test_error_payload_never_carries_secret_material() -> None:
    error = ProviderUnavailableError(
        "provider is not usable", detail="credential environment variable MY_KEY is not set"
    )

    payload = error.to_dict()
    assert payload["error"] == "ProviderUnavailableError"
    assert "MY_KEY" in payload["detail"]


# ------------------------------------------------------------------ noop path


def test_noop_provider_raises_instead_of_answering() -> None:
    noop = NoopProvider()
    assert noop.name == "none"

    with pytest.raises(ProviderUnavailableError) as excinfo:
        noop.diagnose(_event(), context=_context(_event()))

    assert "no model provider is configured" in (excinfo.value.detail or "")


def test_adapter_satisfies_the_diagnosis_provider_protocol() -> None:
    config = ProviderConfig(name=PROVIDER_NAME, endpoint="https://api.test/v1", model="m")

    provider = OpenAICompatibleProvider(config)

    assert isinstance(provider, DiagnosisProvider)
    assert provider.name == PROVIDER_NAME


def test_disabled_provider_raises_unavailable_before_any_request(monkeypatch) -> None:
    provider = OpenAICompatibleProvider(ProviderConfig(name=PROVIDER_NAME, enabled=False))
    calls: list[tuple[object, ...]] = []

    def _record(*args: object, **kwargs: object) -> object:
        calls.append(args)
        msg = "a disabled provider must not issue a request"
        raise AssertionError(msg)

    # Patch the transport seam so an accidental request fails the test twice over:
    # once because it raises, and once because `calls` would no longer be empty.
    monkeypatch.setattr(provider, "_post", _record)

    with pytest.raises(ProviderUnavailableError):
        provider.diagnose(_event(), context=_context(_event()))

    assert calls == []


# ------------------------------------------------------------------ registry


def test_empty_environment_is_an_empty_registry_not_an_error() -> None:
    registry = ProviderRegistry().from_environment({})

    assert registry.available() == []
    assert registry.describe() == []
    assert registry.get(PROVIDER_NAME) is None
    with pytest.raises(ProviderUnavailableError):
        registry.require(PROVIDER_NAME)


def test_explicitly_disabled_provider_type_is_providerless() -> None:
    registry = ProviderRegistry().from_environment({"OPENMEDIC_PROVIDER_TYPE": "none"})

    assert registry.available() == []
    assert registry.describe() == []


def test_environment_variables_build_an_available_provider() -> None:
    registry = ProviderRegistry().from_environment(
        {
            "OPENMEDIC_PROVIDER_TYPE": "openai-compatible",
            "OPENMEDIC_PROVIDER_ENDPOINT": "  https://api.example.test/v1  ",
            "OPENMEDIC_PROVIDER_MODEL": "gpt-test",
            "OPENMEDIC_PROVIDER_API_KEY_ENV": "MY_KEY_VAR",
            "OPENMEDIC_PROVIDER_TIMEOUT": "12.5",
        }
    )

    assert registry.available() == [PROVIDER_NAME]
    assert registry.describe() == [
        {
            "name": PROVIDER_NAME,
            "available": True,
            "enabled": True,
            "endpoint": "https://api.example.test/v1",
            "model": "gpt-test",
            "credential_env": "MY_KEY_VAR",
            "timeout_seconds": 12.5,
            "max_retries": 0,
            "adapter": "OpenAICompatibleProvider",
            "reason": None,
        }
    ]


def test_unknown_provider_type_fails_loudly_instead_of_silently_no_op() -> None:
    registry = ProviderRegistry().from_environment(
        {
            "OPENMEDIC_PROVIDER_TYPE": "anthropic",
            "OPENMEDIC_PROVIDER_ENDPOINT": "https://api.anthropic.test",
            "OPENMEDIC_PROVIDER_MODEL": "claude-test",
        }
    )

    assert registry.available() == []
    provider = registry.get("anthropic")
    assert provider is not None
    with pytest.raises(ProviderUnavailableError) as excinfo:
        provider.diagnose(_event(), context=_context(_event()))

    assert "no adapter is implemented" in (excinfo.value.detail or "")


def test_incomplete_environment_config_is_registered_but_unavailable() -> None:
    registry = ProviderRegistry().from_environment(
        {"OPENMEDIC_PROVIDER_TYPE": "ollama", "OPENMEDIC_PROVIDER_API_KEY_ENV": "OLLAMA_KEY"}
    )

    assert registry.available() == []
    row = registry.describe()[0]
    assert row["enabled"] is False
    assert row["reason"] == "provider is disabled (enabled=false)"
    with pytest.raises(ProviderUnavailableError):
        registry.require("ollama")


def test_enabled_provider_without_a_model_is_unavailable() -> None:
    registry = ProviderRegistry().from_environment(
        {
            "OPENMEDIC_PROVIDER_TYPE": "ollama",
            "OPENMEDIC_PROVIDER_ENDPOINT": "http://localhost:11434/v1",
        }
    )

    assert registry.available() == []
    row = registry.describe()[0]
    assert row["enabled"] is True
    assert row["reason"] == "no model is configured"


def test_invalid_timeout_is_a_usage_error() -> None:
    for value in ("soon", "0", "-1", "nan", "inf"):
        with pytest.raises(UsageError):
            ProviderRegistry().from_environment({"OPENMEDIC_PROVIDER_TIMEOUT": value})


def test_describe_never_contains_the_credential_value() -> None:
    secret_value = "sk-not-a-real-key-1234567890"  # noqa: S105 - deliberately fake key
    registry = ProviderRegistry().from_environment(
        {
            "OPENMEDIC_PROVIDER_TYPE": "openai",
            "OPENMEDIC_PROVIDER_ENDPOINT": "https://api.example.test/v1",
            "OPENMEDIC_PROVIDER_MODEL": "gpt-test",
            "OPENMEDIC_PROVIDER_API_KEY_ENV": "MY_KEY_VAR",
            "MY_KEY_VAR": secret_value,
        }
    )

    blob = json.dumps(registry.describe())
    assert secret_value not in blob
    assert "MY_KEY_VAR" in blob  # the variable *name* is safe to show


def test_registry_accepts_an_explicit_provider_instance() -> None:
    class _Fake:
        name = "fake"

        def diagnose(self, event: FailureEvent, *, context: ProviderContext) -> ProviderResult:
            return _result(provider=self.name)

    registry = ProviderRegistry()
    registry.register(ProviderConfig(name="fake", enabled=True), _Fake())

    provider = registry.require("fake")
    assert isinstance(provider, _Fake)
    result = provider.diagnose(_event(), context=_context(_event()))
    assert result.provider == "fake"


def test_registry_disabled_config_is_not_available_even_with_a_provider() -> None:
    class _Fake:
        name = "fake"

        def diagnose(self, event: FailureEvent, *, context: ProviderContext) -> ProviderResult:
            msg = "a disabled provider must never be used"
            raise AssertionError(msg)

    registry = ProviderRegistry()
    registry.register(ProviderConfig(name="fake", enabled=False), _Fake())

    assert registry.available() == []
    with pytest.raises(ProviderUnavailableError):
        registry.require("fake")


def test_from_environment_keeps_explicitly_registered_providers() -> None:
    class _Fake:
        name = "fake"

        def diagnose(self, event: FailureEvent, *, context: ProviderContext) -> ProviderResult:
            return _result(provider=self.name)

    registry = ProviderRegistry()
    registry.register(ProviderConfig(name="fake", enabled=True), _Fake())
    combined = registry.from_environment(
        {
            "OPENMEDIC_PROVIDER_ENDPOINT": "https://api.example.test/v1",
            "OPENMEDIC_PROVIDER_MODEL": "gpt-test",
        }
    )

    assert combined.available() == ["fake", PROVIDER_NAME]
    assert registry.available() == ["fake"]


def test_deterministic_diagnosis_is_unaffected_by_providerless_mode() -> None:
    event = _event()
    deterministic = _deterministic(event)
    registry = ProviderRegistry().from_environment({})

    with pytest.raises(ProviderUnavailableError):
        registry.require(PROVIDER_NAME)

    assert registry.describe() == []
    assert deterministic.rule_id == "deterministic"
    assert deterministic.provider_used is False
    assert deterministic.risk_level is RiskLevel.HIGH
    assert deterministic == _deterministic(event)
    assert set(type(deterministic).model_fields) >= {
        "probable_cause",
        "risk_level",
        "requires_human_review",
        "limitations",
    }
