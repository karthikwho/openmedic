"""Provider adapters: optional model enrichment behind a stable protocol (FR-010).

The layer is optional by design. Importing this package never performs network I/O and
never requires credentials; :class:`ProviderRegistry` reports providerless mode as a
normal state, and the deterministic diagnosis path works without any of it (D-006).

Business logic lives in the application services; this package only translates between a
provider's HTTP/JSON contract and :class:`ProviderResult`.
"""

from __future__ import annotations

from .base import (
    MAX_PROVIDER_QUOTES,
    MAX_PROVIDER_TEXT_CHARS,
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
from .openai_compat import PROVIDER_NAME, OpenAICompatibleProvider
from .registry import NoopProvider, ProviderRegistry

__all__ = [
    "MAX_PROVIDER_QUOTES",
    "MAX_PROVIDER_TEXT_CHARS",
    "PROVIDER_NAME",
    "TRUNCATION_MARKER",
    "DiagnosisProvider",
    "NoopProvider",
    "OpenAICompatibleProvider",
    "ProviderAuthError",
    "ProviderConfig",
    "ProviderContext",
    "ProviderError",
    "ProviderOutputError",
    "ProviderRegistry",
    "ProviderResult",
    "ProviderTimeoutError",
    "ProviderUnavailableError",
    "allowed_quote_lines",
]
