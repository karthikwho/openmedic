"""Secret detection and redaction.

Untrusted logs routinely contain credentials. This module is the single gate that keeps
secret material out of prompts, persisted incident records, reports, fixtures, and test
output.

Design rules enforced here:

* Redaction is **deterministic** and **idempotent** — running it twice produces the same
  text, so a redacted string is stable across re-normalisation.
* Detections record the *kind* of secret and a short non-sensitive preview. The secret
  value itself is never stored, returned, or logged.
* Redaction is applied to text that may be attacker-controlled. Patterns are applied in
  a fixed order and never raise on pathological input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

PLACEHOLDER: Final = "[REDACTED]"

# Each entry is (kind, compiled pattern). Patterns are applied in list order.
# Group 1 is the secret-bearing portion and is replaced; group 2 (optional) is a
# prefix such as `"xoxb-..."` used only to build the label.
_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN[A-Z ]*PRIVATE KEY-----.*?(?:-----END[A-Z ]*PRIVATE KEY-----|\Z)",
            re.DOTALL | re.IGNORECASE,
        ),
    ),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b")),
    ("slack_token", re.compile(r"\bxox[a-z]-[A-Za-z0-9-]{10,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer_token", re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/-]{8,}=*")),
    ("basic_auth", re.compile(r"(?i)(\bbasic\s+)[A-Za-z0-9+/]{8,}={0,2}")),
    (
        "authorization_header",
        re.compile(r"(?i)(\bauthorization\s*[:=]\s*)(?:\"|')?[A-Za-z0-9._~+/-]{8,}=*(?:\"|')?"),
    ),
    (
        "password_field",
        re.compile(r"(?i)\b(password|passwd|pwd)\b(\s*[:=]\s*)(?:\"|')?[^\s\"']{4,}"),
    ),
    (
        "token_field",
        re.compile(
            r"(?i)\b(token|api[_-]?key|secret|client[_-]?secret|access[_-]?key)\b(\s*[:=]\s*)(?:\"|')?[^\s\"']{8,}"
        ),
    ),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{16,}\b")),
    (
        "docker_auth",
        re.compile(
            r"(?i)(\bDOCKER[A-Z_]*(?:PASSWORD|TOKEN|SECRET|AUTH)\b\s*[:=]\s*)(?:\"|')?[^\s\"']{6,}"
        ),
    ),
    ("db_conn_password", re.compile(r"://([^\s:/@]+):([^\s:/@]{3,})@")),
    # A long token-shaped userinfo with no password colon. Package mirrors routinely put
    # the token in the username slot (`https://<token>@packages.example/simple`), which
    # the rule above cannot see. Short userinfos (`git@`, `user@`) are left alone: they
    # are account names, not credentials, and mangling every URL would hide real ones.
    ("url_token_userinfo", re.compile(r"://([A-Za-z0-9_\-]{12,})@")),
    ("generic_high_entropy_hex", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
)


@dataclass(frozen=True, slots=True)
class SecretDetection:
    """A detected secret.

    ``preview`` holds only a non-sensitive label such as ``"bearer_token@12"``. It is
    constructed so that it cannot be reversed into the secret.
    """

    kind: str
    start: int
    end: int
    preview: str

    def to_dict(self) -> dict[str, str | int]:
        """Return a JSON-serialisable description of this detection."""
        return {
            "kind": self.kind,
            "start": self.start,
            "end": self.end,
            "preview": self.preview,
        }


@dataclass(slots=True)
class RedactionResult:
    """Outcome of a redaction pass."""

    text: str
    detections: list[SecretDetection] = field(default_factory=list)

    @property
    def had_secrets(self) -> bool:
        """Return whether any secret material was detected."""
        return bool(self.detections)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable description of the redaction."""
        return {
            "text": self.text,
            "detections": [d.to_dict() for d in self.detections],
            "redaction_count": len(self.detections),
        }


def _label(kind: str, index: int) -> str:
    return f"{kind}@{index}"


def redact(text: str, *, placeholder: str = PLACEHOLDER) -> RedactionResult:
    """Replace every detected secret in ``text`` with ``placeholder``.

    The scan is a single left-to-right pass so that overlapping matches are resolved
    deterministically and earlier (higher-severity) patterns win. Redaction is
    idempotent: applying the function to its own output yields no further detections,
    because the placeholder contains no pattern-matching material.
    """
    if not isinstance(text, str) or not text:
        return RedactionResult(text=text if isinstance(text, str) else "", detections=[])

    detections: list[SecretDetection] = []
    # Collect all candidate spans first, then resolve overlaps by earliest start and
    # longest match. Deterministic regardless of input ordering.
    candidates: list[tuple[int, int, str]] = []
    for kind, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            span = match.span()
            if span[0] == span[1]:
                continue
            candidates.append((span[0], span[1], kind))

    candidates.sort(key=lambda item: (item[0], -(item[1] - item[0])))

    out: list[str] = []
    cursor = 0
    for start, end, kind in candidates:
        if start < cursor:
            continue  # overlaps an already-redacted region
        out.append(text[cursor:start])
        out.append(placeholder)
        cursor = end
        detections.append(
            SecretDetection(kind=kind, start=start, end=end, preview=_label(kind, len(detections)))
        )
    out.append(text[cursor:])

    return RedactionResult(text="".join(out), detections=detections)


def redact_one_line(text: str) -> str:
    """Return only the redacted text, with detections discarded."""
    return redact(text).text
