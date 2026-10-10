"""Log normalisation and failure fingerprinting.

Forensics sits between ingestion and diagnosis. Its job is to remove *volatile* content
from a log so that the same underlying failure fingerprints identically across
different runs, while never destroying the raw evidence that a diagnosis quote refers
to.

Two outputs are always produced:

* ``normalized`` — volatile values replaced with stable placeholders.
* ``line_index`` — a mapping from normalised line number back to the original line, so
  a quote taken from the normalised text can still be verified against the raw log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..domain.redaction import redact

# Ordered (name, pattern, replacement). Order matters: more specific patterns first.
_SUBSTITUTIONS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "iso8601",
        re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"),
        "<TIMESTAMP>",
    ),
    ("clock", re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<CLOCK>"),
    ("date", re.compile(r"\b\d{4}/\d{2}/\d{2}\b"), "<DATE>"),
    (
        "uuid",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<UUID>",
    ),
    ("hex40", re.compile(r"\b[0-9a-f]{40}\b"), "<GIT_SHA>"),
    ("hex64", re.compile(r"\b[0-9a-f]{64}\b"), "<HASH64>"),
    ("temp_path", re.compile(r"(?:/tmp|/var/folders|/var/tmp)[^\s:\"']*"), "<TMPPATH>"),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IPV4>"),
    ("port", re.compile(r"\b(?:port\s+|:)\d{2,5}\b", re.IGNORECASE), "<PORT>"),
    (
        "duration",
        re.compile(r"\b\d+(?:\.\d+)?\s?(?:s|ms|sec|secs|seconds|m|min|mins|minutes)\b"),
        "<DURATION>",
    ),
    ("memory_size", re.compile(r"\b\d+(?:\.\d+)?\s?(?:K|M|G|KB|MB|GB|KiB|MiB|GiB)B?\b"), "<SIZE>"),
    ("pid", re.compile(r"\bpid[=:\s]+\d+\b", re.IGNORECASE), "<PID>"),
    ("number_run", re.compile(r"\b(?:run|job|build)\s*#?\d{3,}\b", re.IGNORECASE), "<RUN_ID>"),
    ("pytest_duration", re.compile(r"\(\d+(?:\.\d+)?\s*s\)"), "(<DURATION>)"),
    ("line_number", re.compile(r"^\s*\d+\s*\|", re.MULTILINE), "<LINE_NO> |"),
    ("big_int", re.compile(r"\b\d{5,}\b"), "<INT>"),
)


@dataclass(frozen=True, slots=True)
class NormalizedLog:
    """Result of normalising a raw log."""

    raw: str
    redacted_raw: str
    normalized: str
    line_count: int
    substitutions_applied: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable copy of the normalised evidence."""
        return {
            "raw": self.raw,
            "redacted_raw": self.redacted_raw,
            "normalized": self.normalized,
            "line_count": self.line_count,
            "substitutions_applied": dict(self.substitutions_applied),
        }


def normalize_log(raw: str, *, redact_secrets: bool = True) -> NormalizedLog:
    """Normalise ``raw`` and keep the original for quote verification.

    ``raw`` is returned untouched inside the result. ``redacted_raw`` is provided so
    persistence and display layers can share one redaction pass instead of re-scanning.
    """
    if not raw:
        return NormalizedLog(raw="", redacted_raw="", normalized="", line_count=0)

    redaction = redact(raw) if redact_secrets else None
    working = redaction.text if redaction is not None else raw

    counts: dict[str, int] = {}
    for name, pattern, replacement in _SUBSTITUTIONS:
        working, n = pattern.subn(replacement, working)
        if n:
            counts[name] = n

    return NormalizedLog(
        raw=raw,
        redacted_raw=redaction.text if redaction is not None else raw,
        normalized=working,
        line_count=raw.count("\n") + 1,
        substitutions_applied=counts,
    )


def line_index(normalized: NormalizedLog) -> dict[int, int]:
    """Map 1-based normalised line numbers to 1-based raw line numbers.

    Normalisation is line-preserving: every substitution in :data:`_SUBSTITUTIONS`
    either stays on one line or, in the ``private_key`` case, removes a whole block. To
    keep the index truthful we compare raw and normalised line-by-line on the original
    line count and only emit entries where both exist.
    """
    raw_lines = normalized.raw.splitlines()
    norm_lines = normalized.normalized.splitlines()
    index: dict[int, int] = {}
    for i in range(min(len(raw_lines), len(norm_lines))):
        index[i + 1] = i + 1
    if len(raw_lines) != len(norm_lines):  # pragma: no cover - defensive
        index = {i + 1: i + 1 for i in range(len(norm_lines))}
    return index


def fingerprint(normalized_text: str, *, length: int = 16) -> str:
    """Return a stable fingerprint for ``normalized_text``.

    The fingerprint is computed from the *normalised* text, so two logs of the same
    underlying failure with different timestamps, temp paths, and ports collide.
    """
    import hashlib

    # Blank-line and trailing-whitespace differences are noise.
    canonical = "\n".join(line.rstrip() for line in normalized_text.splitlines() if line.strip())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:length]
