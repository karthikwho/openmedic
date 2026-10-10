"""Provider registry: construction, environment configuration, and honest reporting.

The registry is the only place that knows *which* adapters exist. Everything else depends
on :class:`~openmedic.providers.base.DiagnosisProvider`, so adding an adapter never
touches the deterministic core (D-007).

Environment configuration reads exactly five variables, and one of them is an indirection
rather than the credential itself:

* ``OPENMEDIC_PROVIDER_TYPE`` — adapter name, for example ``openai-compatible``.
* ``OPENMEDIC_PROVIDER_ENDPOINT`` — base URL, for example ``http://localhost:11434/v1``.
* ``OPENMEDIC_PROVIDER_MODEL`` — model identifier sent to the endpoint.
* ``OPENMEDIC_PROVIDER_API_KEY_ENV`` — **name** of the variable holding the credential.
* ``OPENMEDIC_PROVIDER_TIMEOUT`` — wall-clock seconds allowed per request.

The credential value is never read into configuration, never stored on the registry, and
never returned by :meth:`ProviderRegistry.describe`, so ``openmedic providers list`` and
a JSON report are both safe to paste into an issue. Missing or absent variables produce a
normal, empty registry: providerless mode is the default state, not an error (D-006).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from ..domain.contracts import FailureEvent
from ..domain.errors import UsageError
from .base import (
    DiagnosisProvider,
    ProviderConfig,
    ProviderContext,
    ProviderResult,
    ProviderUnavailableError,
)
from .openai_compat import PROVIDER_NAME, OpenAICompatibleProvider

#: Environment variables this layer reads. Nothing else is consulted, and in particular
#: the credential *value* is never read here, only the name of the variable holding it.
ENV_PROVIDER_TYPE: Final = "OPENMEDIC_PROVIDER_TYPE"
ENV_PROVIDER_ENDPOINT: Final = "OPENMEDIC_PROVIDER_ENDPOINT"
ENV_PROVIDER_MODEL: Final = "OPENMEDIC_PROVIDER_MODEL"
ENV_PROVIDER_API_KEY_ENV: Final = "OPENMEDIC_PROVIDER_API_KEY_ENV"
ENV_PROVIDER_TIMEOUT: Final = "OPENMEDIC_PROVIDER_TIMEOUT"

#: Type names that mean "run deterministic only".
_PROVIDERLESS_TYPES: Final[frozenset[str]] = frozenset(
    {"none", "no", "off", "disabled", "deterministic"}
)

#: Provider types served by the generic OpenAI-compatible adapter. These endpoints all
#: speak the same ``/chat/completions`` contract; they differ only in base URL and
#: credential. A type that is not listed here has **no adapter** and must fail loudly
#: rather than silently degrade to providerless mode.
_OPENAI_COMPATIBLE_TYPES: Final[frozenset[str]] = frozenset(
    {
        PROVIDER_NAME,
        "openai",
        "openrouter",
        "groq",
        "together",
        "mistral",
        "github-models",
        "vllm",
        "lmstudio",
        "ollama",
        "llamacpp",
    }
)

_DEFAULT_TIMEOUT_SECONDS: Final = 30.0


@dataclass(frozen=True, slots=True)
class _ProviderEntry:
    """One registered provider plus why it may be unusable."""

    config: ProviderConfig
    provider: DiagnosisProvider
    unavailable_reason: str | None = None

    @property
    def available(self) -> bool:
        """True only when the config is enabled and an adapter was constructed."""
        return self.config.enabled and self.unavailable_reason is None


class _UnavailableProvider:
    """A provider whose only job is to fail explicitly.

    Used for providerless mode and for types without an adapter, so the absence of a
    provider is a visible, typed error at the point of use rather than a ``None`` that
    some caller forgets to check.
    """

    def __init__(self, name: str, reason: str) -> None:
        self.name = name
        self.reason = reason

    def diagnose(self, event: FailureEvent, *, context: ProviderContext) -> ProviderResult:
        """Raise :class:`ProviderUnavailableError`; never produce an answer."""
        msg = (
            f"provider {self.name!r} cannot diagnose request {context.request_id!r} "
            f"for incident {event.resolved_incident_id!r}"
        )
        raise ProviderUnavailableError(msg, detail=self.reason)


class NoopProvider(_UnavailableProvider):
    """The providerless-mode provider (D-006, D-007).

    Application code should fall back to this, or to
    :meth:`ProviderRegistry.require` raising, rather than inventing an answer when no
    provider is configured. Its :meth:`diagnose` always raises.
    """

    def __init__(self, name: str = "none") -> None:
        super().__init__(
            name,
            "no model provider is configured; deterministic diagnosis is the only supported path",
        )


class ProviderRegistry:
    """Registry of configured providers, keyed by provider name."""

    def __init__(self, configs: Sequence[ProviderConfig] | None = None) -> None:
        self._entries: dict[str, _ProviderEntry] = {}
        for config in configs or ():
            self.register(config)

    def register(self, config: ProviderConfig, provider: DiagnosisProvider | None = None) -> None:
        """Register ``config``, building the matching adapter when ``provider`` is omitted.

        The registry key is the config name, falling back to the provider's own name and
        then to the adapter's canonical name. Registering an already-known name replaces
        it, so a configuration reload is a single call.
        """
        key = config.name.strip() or (provider.name.strip() if provider is not None else "")
        key = key or PROVIDER_NAME
        if provider is not None:
            self._entries[key] = _ProviderEntry(config=config, provider=provider)
            return
        built, reason = _build_provider(config)
        self._entries[key] = _ProviderEntry(
            config=config, provider=built, unavailable_reason=reason
        )

    def get(self, name: str) -> DiagnosisProvider | None:
        """Return the provider registered under ``name``, or ``None`` when unknown.

        A registered-but-unusable provider is returned as an explicit no-op provider that
        raises :class:`ProviderUnavailableError` from :meth:`diagnose`, so the caller
        never receives a silent stand-in answer.
        """
        entry = self._entries.get(name.strip())
        return entry.provider if entry is not None else None

    def require(self, name: str) -> DiagnosisProvider:
        """Return a usable provider or raise :class:`ProviderUnavailableError`.

        This is the honest resolution path: an unknown, disabled, or adapter-less provider
        is an error with a reason, never a fabricated answer.
        """
        entry = self._entries.get(name.strip())
        if entry is None:
            msg = f"no provider named {name!r} is configured"
            raise ProviderUnavailableError(
                msg, detail="configure a provider or run in deterministic-only mode"
            )
        if not entry.available:
            msg = f"provider {name!r} is not available"
            raise ProviderUnavailableError(
                msg, detail=entry.unavailable_reason or "provider is disabled"
            )
        return entry.provider

    def available(self) -> list[str]:
        """Return the sorted names of providers that are enabled and constructible."""
        return sorted(name for name, entry in self._entries.items() if entry.available)

    def from_environment(self, env: Mapping[str, str]) -> ProviderRegistry:
        """Return a new registry with this registry's providers plus the env-configured one.

        Only the five documented variables are read. When none is set the result is the
        seeded registry unchanged — an empty registry for a fresh instance — which is the
        normal providerless state rather than an error.
        """
        registry = self._clone()
        config = _config_from_environment(env)
        if config is not None:
            registry.register(config)
        return registry

    def _clone(self) -> ProviderRegistry:
        """Return an independent copy of this registry, including explicit providers."""
        clone = ProviderRegistry()
        clone._entries = dict(self._entries)
        return clone

    def describe(self) -> list[dict[str, object]]:
        """Return one row per registered provider for ``openmedic providers list``.

        Rows carry the credential *variable name* and never its value, so the output is
        safe in logs, terminal recordings, and bug reports.
        """
        rows: list[dict[str, object]] = []
        for name in sorted(self._entries):
            entry = self._entries[name]
            config = entry.config
            rows.append(
                {
                    "name": name,
                    "available": entry.available,
                    "enabled": config.enabled,
                    "endpoint": config.endpoint,
                    "model": config.model,
                    "credential_env": config.api_key_env,
                    "timeout_seconds": config.timeout_seconds,
                    "max_retries": config.max_retries,
                    "adapter": type(entry.provider).__name__,
                    "reason": entry.unavailable_reason,
                }
            )
        return rows


def _build_provider(config: ProviderConfig) -> tuple[DiagnosisProvider, str | None]:
    """Return the provider for ``config`` plus a reason when it is not usable."""
    if not config.enabled:
        return NoopProvider(config.name), "provider is disabled (enabled=false)"
    if not config.endpoint.strip():
        return NoopProvider(config.name), "no endpoint is configured"
    if not config.model.strip():
        return NoopProvider(config.name), "no model is configured"
    if config.name.strip().lower() not in _OPENAI_COMPATIBLE_TYPES:
        supported = ", ".join(sorted(_OPENAI_COMPATIBLE_TYPES))
        reason = (
            f"no adapter is implemented for provider type {config.name!r}; "
            f"supported types: {supported}"
        )
        return _UnavailableProvider(config.name, reason), reason
    return OpenAICompatibleProvider(config), None


def _config_from_environment(env: Mapping[str, str]) -> ProviderConfig | None:
    """Build a :class:`ProviderConfig` from the documented variables, or ``None``.

    ``None`` means "nothing is configured", which is the default providerless state.
    """
    provider_type = _clean(env.get(ENV_PROVIDER_TYPE))
    endpoint = _clean(env.get(ENV_PROVIDER_ENDPOINT))
    model = _clean(env.get(ENV_PROVIDER_MODEL))
    api_key_env = _clean(env.get(ENV_PROVIDER_API_KEY_ENV))
    timeout_raw = _clean(env.get(ENV_PROVIDER_TIMEOUT))

    if not any((provider_type, endpoint, model, api_key_env, timeout_raw)):
        return None
    if provider_type in _PROVIDERLESS_TYPES:
        return None

    timeout = _DEFAULT_TIMEOUT_SECONDS if not timeout_raw else _parse_timeout(timeout_raw)
    return ProviderConfig(
        name=provider_type or PROVIDER_NAME,
        endpoint=endpoint,
        model=model,
        api_key_env=api_key_env,
        timeout_seconds=timeout,
        enabled=bool(endpoint),
    )


def _clean(value: object) -> str:
    """Return a stripped string, treating anything else as absent."""
    return value.strip() if isinstance(value, str) else ""


def _parse_timeout(raw: str) -> float:
    """Parse a positive, finite timeout in seconds, or raise :class:`UsageError`."""
    try:
        seconds = float(raw)
    except ValueError as exc:
        msg = f"{ENV_PROVIDER_TIMEOUT} must be a number of seconds, got {raw!r}"
        raise UsageError(msg) from exc
    if not math.isfinite(seconds) or seconds <= 0:
        msg = f"{ENV_PROVIDER_TIMEOUT} must be a positive number of seconds, got {raw!r}"
        raise UsageError(msg)
    return seconds
