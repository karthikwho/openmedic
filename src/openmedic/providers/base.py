"""Provider abstraction: configuration, advisory results, and the diagnosis protocol.

This module is the contract boundary between OpenMedic's deterministic core and any
optional model provider (TRD section 7, PRD FR-010). The deterministic diagnosis path
never imports a concrete adapter; it only ever sees :class:`DiagnosisProvider`,
:class:`ProviderConfig`, and :class:`ProviderResult`.

Three invariants are enforced structurally here rather than by convention:

1. A provider is *unavailable* unless it is explicitly enabled and configured. There is
   no fallback answer: :class:`ProviderUnavailableError` is raised instead.
2. :class:`ProviderResult` is advisory data only. It carries no lifecycle state, no
   validation result, no patch identity, and no approval flag, so no model output can
   change risk policy or validation state (ARCHITECTURE.md section 6, trust boundary 2).
3. Untrusted strings from a model are normalised at construction time: ``confidence`` is
   clamped into ``[0, 1]``, ``risk_level`` and ``recommended_action`` are constrained to
   the published enum values (an unrecognised risk label is treated as *high* and
   escalated, never silently downgraded), and free text is length-bounded.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final, Protocol, runtime_checkable

from ..domain.contracts import DiagnosisResult, FailureEvent
from ..domain.enums import RecommendedAction, RiskLevel
from ..domain.errors import OpenMedicError

#: Maximum characters of any free-text field kept from a provider. Model output is
#: unbounded by nature; persisted incident records and reports are not.
MAX_PROVIDER_TEXT_CHARS: Final = 4000

#: Maximum number of quotes kept from a provider response.
MAX_PROVIDER_QUOTES: Final = 25

#: Marker appended to truncated free text so a shortened value is never mistaken for a
#: complete one.
TRUNCATION_MARKER: Final = "...[truncated]"

#: Enum values a provider is allowed to report. Anything else is normalised to the
#: conservative fallback below instead of being passed through.
_RISK_LEVELS: Final[frozenset[str]] = frozenset(level.value for level in RiskLevel)
_RECOMMENDED_ACTIONS: Final[frozenset[str]] = frozenset(
    action.value for action in RecommendedAction
)

#: Conservative fallbacks. An unrecognised risk label must never lower the perceived
#: risk, and an unrecognised action must never become an automatic change.
_DEFAULT_RISK_LEVEL: Final = RiskLevel.HIGH.value
_DEFAULT_ACTION: Final = RecommendedAction.INVESTIGATE_MANUALLY.value


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """Everything needed to reach one model provider.

    ``api_key_env`` holds the *name* of an environment variable, never a credential
    value, so a config object is safe to log, serialise, and commit (SECURITY.md rule 2).
    ``extra`` carries adapter-specific strings; it is never interpreted by this layer.
    """

    name: str = "none"
    endpoint: str = ""
    model: str = ""
    api_key_env: str = ""
    timeout_seconds: float = 30.0
    max_retries: int = 0
    temperature: float = 0.0
    max_context_chars: int = 6000
    enabled: bool = False
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable view. Contains no credential material."""
        return {
            "name": self.name,
            "endpoint": self.endpoint,
            "model": self.model,
            "api_key_env": self.api_key_env,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "temperature": self.temperature,
            "max_context_chars": self.max_context_chars,
            "enabled": self.enabled,
            "extra": dict(self.extra),
        }


@dataclass(frozen=True, slots=True)
class ProviderResult:
    """Advisory output from a model provider.

    The field set is the whole story: there is nowhere to record a lifecycle state, a
    validation result, a patch hash, or an approval. A caller that wants to act on this
    data must build its own :class:`~openmedic.domain.contracts.DiagnosisResult`, keep
    ``requires_human_review`` and ``risk_level`` from the deterministic diagnosis unless
    a human raises them, and re-run validation for any candidate patch.

    ``raw_quotes`` holds the quotes the model returned, after the adapter dropped every
    quote that was not verbatim in the event's allowed log lines. They are still
    untrusted text: they are only useful as evidence because they were matched, not
    because a model produced them.
    """

    provider: str
    probable_cause: str
    confidence: float
    recommended_action: str
    risk_level: str
    requires_human_review: bool
    limitations: list[str]
    raw_quotes: list[str]
    usage: dict[str, int] | None = None

    def __post_init__(self) -> None:
        """Normalise untrusted model values into the published enum and range."""
        object.__setattr__(self, "provider", _bounded_text(self.provider))
        object.__setattr__(self, "probable_cause", _bounded_text(self.probable_cause))
        object.__setattr__(self, "confidence", _clamp_confidence(self.confidence))

        risk_level, risk_note = _normalize_risk_level(self.risk_level)
        action, action_note = _normalize_action(self.recommended_action)
        object.__setattr__(self, "risk_level", risk_level)
        object.__setattr__(self, "recommended_action", action)

        notes = [note for note in (risk_note, action_note) if note]
        object.__setattr__(self, "limitations", _bounded_list(self.limitations))
        if notes:
            object.__setattr__(self, "limitations", [*self.limitations, *notes])

        object.__setattr__(self, "raw_quotes", _bounded_quotes(self.raw_quotes))
        # Unrecognised policy fields mean the answer was not understood, which is an
        # escalation, never a permission.
        if notes and not self.requires_human_review:
            object.__setattr__(self, "requires_human_review", True)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable view for reports and CLI output."""
        return {
            "provider": self.provider,
            "probable_cause": self.probable_cause,
            "confidence": self.confidence,
            "recommended_action": self.recommended_action,
            "risk_level": self.risk_level,
            "requires_human_review": self.requires_human_review,
            "limitations": list(self.limitations),
            "raw_quotes": list(self.raw_quotes),
            "usage": dict(self.usage) if self.usage is not None else None,
        }


class ProviderError(OpenMedicError):
    """A configured provider could not produce a usable result.

    The deterministic diagnosis path is unaffected: callers catch this family and keep
    the deterministic result (API_CONTRACTS.md section 6, invariant 5). Messages must
    never contain credential material.
    """

    exit_code = 5


class ProviderUnavailableError(ProviderError):
    """The provider is disabled, misconfigured, unreachable, or returned a server error."""


class ProviderAuthError(ProviderError):
    """The credential was missing, rejected, or insufficient (HTTP 401/403)."""


class ProviderTimeoutError(ProviderError):
    """The provider timed out or rate-limited the request (HTTP 429).

    Rate limiting is reported with this shape so the caller's backoff and fallback
    handling stays uniform; :class:`ProviderUnavailableError` covers everything else.
    """


class ProviderOutputError(ProviderError):
    """The provider answered with output that could not be parsed or trusted."""


@runtime_checkable
class DiagnosisProvider(Protocol):
    """The protocol every adapter implements.

    ``diagnose`` receives the *original* event plus a :class:`ProviderContext`, and must
    return :class:`ProviderResult` or raise a :class:`ProviderError`. It must never
    raise for a provider-side failure condition other than through that family, and it
    must never fabricate evidence.
    """

    name: str

    def diagnose(self, event: FailureEvent, *, context: ProviderContext) -> ProviderResult:
        """Return an advisory diagnosis for ``event``."""


@dataclass(slots=True)
class ProviderContext:
    """Bounded context handed to a provider for one diagnosis request.

    ``allowed_quote_lines`` is the only quote vocabulary: verbatim, already-redacted log
    lines. ``deterministic_diagnosis`` is a hint for the model and never an instruction;
    it is also what keeps authority on the deterministic side, because the caller can
    always ignore :class:`ProviderResult` entirely. ``request_id`` exists for audit
    correlation and is never used as an authentication token.
    """

    event: FailureEvent
    deterministic_diagnosis: DiagnosisResult | None
    request_id: str
    allowed_quote_lines: frozenset[str]


def allowed_quote_lines(event: FailureEvent) -> frozenset[str]:
    """Return the verbatim, redacted log lines a provider may quote.

    Derived from ``event.redacted().logs`` so the quote vocabulary is exactly what the
    model was shown. Callers should use this to build :class:`ProviderContext` rather
    than splitting the raw log: a raw line can contain a secret, and a secret must never
    become a quotable line (SECURITY.md rule 2).
    """
    redacted_logs = event.redacted().logs
    return frozenset(line for line in redacted_logs.splitlines() if line.strip())


def _clamp_confidence(value: object) -> float:
    """Return ``value`` as a float inside ``[0, 1]``.

    A provider that reports ``5.0`` or ``"high"`` has produced a malformed number. It is
    clamped rather than rejected so one bad field cannot discard an otherwise usable
    enrichment, and the value can never leave ``[0, 1]`` on its own.
    """
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    if number != number:  # NaN
        return 0.0
    return min(max(number, 0.0), 1.0)


def _normalize_risk_level(value: object) -> tuple[str, str | None]:
    """Map a model-supplied risk label onto a published :class:`RiskLevel`."""
    candidate = value.strip().lower() if isinstance(value, str) else ""
    if candidate in _RISK_LEVELS:
        return candidate, None
    return _DEFAULT_RISK_LEVEL, (
        "provider reported an unrecognised risk level; treated as high and escalated "
        "for human review"
    )


def _normalize_action(value: object) -> tuple[str, str | None]:
    """Map a model-supplied action onto a published :class:`RecommendedAction`."""
    candidate = value.strip().lower().replace("-", "_").replace(" ", "_")
    if candidate in _RECOMMENDED_ACTIONS:
        return candidate, None
    return _DEFAULT_ACTION, (
        "provider recommended an action outside the published set; recorded as "
        "'investigate_manually'"
    )


def _bounded_text(value: object, limit: int = MAX_PROVIDER_TEXT_CHARS) -> str:
    """Return ``value`` as text no longer than ``limit`` characters."""
    text = value if isinstance(value, str) else ""
    if len(text) <= limit:
        return text
    return text[:limit] + TRUNCATION_MARKER


def _bounded_list(values: object, limit: int = MAX_PROVIDER_TEXT_CHARS) -> list[str]:
    """Return ``values`` as a bounded list of bounded strings."""
    if not isinstance(values, Sequence) or isinstance(values, str | bytes):
        return []
    return [_bounded_text(item, limit) for item in values if isinstance(item, str)]


def _bounded_quotes(values: object) -> list[str]:
    """Return at most :data:`MAX_PROVIDER_QUOTES` bounded, de-duplicated quotes."""
    if not isinstance(values, Sequence) or isinstance(values, str | bytes):
        return []
    quotes: list[str] = []
    for item in values:
        if not isinstance(item, str):
            continue
        bounded = _bounded_text(item)
        if bounded and bounded not in quotes:
            quotes.append(bounded)
        if len(quotes) >= MAX_PROVIDER_QUOTES:
            break
    return quotes
