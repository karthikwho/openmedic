"""Local log ingestion: pasted text, files on disk, and stdin.

Ingestion is the first layer that touches untrusted input, so it stays thin,
offline, and deterministic:

* It maps raw log text onto the locked :class:`~openmedic.domain.FailureEvent`
  contract. The contract is the source of truth; nothing here invents a parallel
  shape.
* It classifies the failure with documented, ordered heuristics. When no rule
  fires it returns ``FailureType.UNKNOWN`` instead of guessing, because a wrong
  guess sends the rest of the pipeline (diagnosis, remediation) down a wrong
  path. ``unknown`` is a valid, honest result.
* It never redacts. ``FailureEvent.logs`` is the evidence a diagnosis quote must
  be verifiable against, so redaction happens at display/persistence time via
  :meth:`~openmedic.domain.FailureEvent.redacted`.

No network access, credentials, or model calls are required for anything here.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final, TextIO

from ..domain import FailureEvent, FailureType, InvalidInputError, UsageError, utc_now

#: Metadata fields ``ingest_log_text`` accepts in addition to the log text itself.
_LOG_METADATA_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "repository",
        "commit_sha",
        "workflow_name",
        "run_id",
        "failed_step",
        "job_name",
        "source_path",
        "timestamp",
    }
)

#: How many distinct matching lines a single classification rule may contribute.
#: Without a cap, one very chatty pattern would swamp the other rules; three is
#: enough to say "this signature really is present" without letting log noise
#: decide the classification.
_MAX_SIGNAL_LINES: Final = 3


@dataclass(frozen=True, slots=True)
class _ClassificationRule:
    """One documented heuristic family used by :func:`classify_log_text`."""

    failure_type: FailureType
    description: str
    patterns: tuple[re.Pattern[str], ...]


# Ordered by precedence. The first rule wins a tie, because an earlier entry is
# the more specific, less guessable signal.
#
# Patterns are deliberately narrow. "Error" on its own is *not* a signature: it
# appears in every CI log, including the GitHub Actions trailer
# "Error: Process completed with exit code 1.", which says nothing about the
# cause. Rules must match the *shape* of a real failure report instead.
_RULES: Final[tuple[_ClassificationRule, ...]] = (
    _ClassificationRule(
        failure_type=FailureType.SYNTAX_OR_IMPORT_ERROR,
        description="Python syntax and import failures; the traceback names the bad symbol.",
        patterns=(
            re.compile(r"\bSyntaxError\b"),
            re.compile(r"\bIndentationError\b"),
            re.compile(r"\bTabError\b"),
            re.compile(r"\bImportError\b"),
            re.compile(r"cannot import name\b"),
        ),
    ),
    _ClassificationRule(
        failure_type=FailureType.DEPENDENCY_ERROR,
        description=(
            "Dependency resolution, installation, or registry-authentication failures, "
            "including a module the interpreter cannot find at all."
        ),
        patterns=(
            re.compile(r"\bModuleNotFoundError\b"),
            re.compile(r"No module named ['\"][^'\"]+['\"]"),
            re.compile(r"\bnpm (?:ERR|error)\b"),
            re.compile(r"\byarn error\b"),
            re.compile(r"\bERESOLVE\b"),
            re.compile(r"\bunable to resolve dependency tree\b", re.IGNORECASE),
            re.compile(r"\bCould not resolve dependenc(?:y|ies)\b", re.IGNORECASE),
            re.compile(r"\bConflicting peer dependenc(?:y|ies)\b", re.IGNORECASE),
            re.compile(r"\bNo matching distribution found for\b", re.IGNORECASE),
            re.compile(
                r"\bCould not find a version that satisfies the requirement\b", re.IGNORECASE
            ),
            re.compile(r"\bResolutionImpossible\b"),
            re.compile(r"\bBundler could not find compatible versions\b", re.IGNORECASE),
            re.compile(r"\bCould not find gem\b", re.IGNORECASE),
            re.compile(r"\bCould not find artifact\b", re.IGNORECASE),
            re.compile(r"\bsubprocess-exited-with-error\b"),
        ),
    ),
    _ClassificationRule(
        failure_type=FailureType.TEST_FAILURE,
        description="A test framework reported a failing test, assertion, or non-zero test exit.",
        patterns=(
            # pytest section banners and per-failure separators.
            re.compile(r"^\s*=+\s*FAILURES\s*=+"),
            re.compile(r"^\s*=+\s*short test summary info\s*=+"),
            re.compile(r"^\s*=+\s*ERRORS\s*=+"),
            re.compile(r"^\s*_{5,}\S.*\S\s*_{5,}\s*$"),
            # pytest failure summary rows and assertion reprs.
            re.compile(r"^FAILED\s+\S"),
            re.compile(r"^\s*E\s+assert\b"),
            re.compile(r"\bAssertionError\b"),
            re.compile(r"\b\d+\s+failed\b"),
            # jest / mocha / TAP forms.
            re.compile(r"^Tests:\s+.*\bfailed\b"),
            re.compile(r"\b\d+\s+failing\b"),
            re.compile(r"^\s*\u25cf\s+\S"),
            re.compile(r"^\s*(?:FAIL|\u2715|\u2717|\u00d7)\s+\S"),
            re.compile(r"^not ok \d+\b"),
        ),
    ),
    _ClassificationRule(
        failure_type=FailureType.BUILD_OR_CONFIG_ERROR,
        description="Build tooling, compilation, or a missing/invalid configuration input.",
        patterns=(
            re.compile(r"^\s*make(?:\[\d+\])?:\s*\*\*\*"),
            re.compile(r"ERROR:\s*failed to solve"),
            re.compile(r"\bCMake Error\b"),
            re.compile(r"\bModule build failed\b", re.IGNORECASE),
            re.compile(r"\berror CS\d+\b"),
            re.compile(r"fatal error:.*No such file"),
            re.compile(r"\bno such file or directory\b", re.IGNORECASE),
            re.compile(r"\bENOENT\b.*no such file", re.IGNORECASE),
            re.compile(
                r"\b(?:config|configuration)\b.*\b(?:error|invalid|not found|missing|failed)\b",
                re.IGNORECASE,
            ),
            re.compile(r"\b(?:error|failed|unable)\b.*\b(?:dockerfile|makefile)\b", re.IGNORECASE),
            re.compile(r"\bfailed to (?:load|parse|read)\b.*\bconfig\b", re.IGNORECASE),
            re.compile(r"\bcompilation (?:failed|error)\b", re.IGNORECASE),
            re.compile(r"\bbuild failed\b", re.IGNORECASE),
        ),
    ),
)

# Step-name markers, in the order they are preferred. The *last* match wins: the
# step that started most recently is the one that failed. Matches come from real
# GitHub Actions ("##[group]Run ...") and Azure Pipelines ("##[section]Starting: ...")
# command formats, plus the plain "Run <command>" form the Actions UI displays.
_STEP_MARKERS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^##\[group\](?P<value>.+?)\s*$", re.MULTILINE),
    re.compile(r"^##\[section\]Starting:\s*(?P<value>.+?)\s*$", re.MULTILINE),
    re.compile(r"^(?P<value>Run .+?)\s*$", re.MULTILINE),
)

# Job-name markers, in preference order. The *first* match wins, because a job
# header precedes the job's output. CI providers do not agree on one format, so
# the recognised forms are the explicit "##[job]" marker used by CI shims and the
# common plain-text headers ("Job name:", "Starting job:", "##[section]Starting: Job").
# When a log carries none of them the job stays None — the GitHub API supplies the
# real value, and guessing it would corrupt the idempotency key.
_JOB_MARKERS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^##\[job\](?P<value>.+?)\s*$", re.MULTILINE),
    re.compile(
        r"^\s*#?\s*job[_\s-]?name\s*[:=]\s*(?P<value>.+?)\s*$",
        re.MULTILINE | re.IGNORECASE,
    ),
    re.compile(r"^\s*starting\s+job\s*[:=]?\s*(?P<value>.+?)\s*$", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^##\[section\]Starting:\s*Job\s+(?P<value>.+?)\s*$", re.MULTILINE | re.IGNORECASE),
)


def classification_scores(text: str) -> dict[FailureType, int]:
    """Return how many signature lines matched each failure type.

    The mapping is empty for empty input and is ordered by rule precedence, so a
    caller can see both the chosen type and how close the runner-up was. The
    diagnosis layer uses this to state confidence and limitations honestly.
    """
    if not text or not text.strip():
        return {}
    lines = text.splitlines()
    scores = {rule.failure_type: _rule_score(lines, rule) for rule in _RULES}
    scores[FailureType.UNKNOWN] = 0  # never a signature; the honest "nothing matched" case
    return scores


def classify_log_text(text: str) -> FailureType:
    """Classify ``text`` into a coarse :class:`FailureType`.

    The heuristics are ordered and documented in :data:`_RULES`. Each rule
    contributes at most :data:`_MAX_SIGNAL_LINES` distinct matching lines, the
    highest score wins, and a tie goes to the earlier (more specific) rule. When
    no rule matches anything the result is ``FailureType.UNKNOWN`` — ambiguity is
    reported, never papered over with a guess.
    """
    selected = FailureType.UNKNOWN
    best = 0
    for failure_type, score in classification_scores(text).items():
        if score > best:  # strictly greater keeps the earlier rule on a tie
            selected = failure_type
            best = score
    return selected


def describe_classification(text: str) -> str:
    """Return a one-line, human-readable justification for :func:`classify_log_text`."""
    selected = classify_log_text(text)
    scores = classification_scores(text)
    if not any(scores.values()):
        return "unknown: no signature in the log matched a classification rule"
    rule = next(item for item in _RULES if item.failure_type is selected)
    return f"{selected.value}: {scores[selected]} signature line(s) - {rule.description}"


def _rule_score(lines: list[str], rule: _ClassificationRule) -> int:
    """Count distinct lines in ``lines`` matching any of ``rule``'s patterns."""
    score = 0
    for line in lines:
        if score >= _MAX_SIGNAL_LINES:
            break
        if any(pattern.search(line) for pattern in rule.patterns):
            score += 1
    return score


def detect_failed_step(text: str) -> str | None:
    """Return the most likely failing step name, or ``None`` when the log has no marker."""
    for marker in _STEP_MARKERS:
        matches = list(marker.finditer(text))
        if matches:
            return matches[-1].group("value")
    return None


def detect_job_name(text: str) -> str | None:
    """Return the job name printed in the log, or ``None`` when the log has no marker."""
    for marker in _JOB_MARKERS:
        match = marker.search(text)
        if match:
            return match.group("value")
    return None


def ingest_log_text(
    text: str,
    *,
    repository: str | None = None,
    commit_sha: str | None = None,
    workflow_name: str | None = None,
    run_id: str | None = None,
    failed_step: str | None = None,
    job_name: str | None = None,
    source_path: str | None = None,
    timestamp: datetime | None = None,
) -> FailureEvent:
    """Normalise raw log ``text`` into a :class:`FailureEvent`.

    ``text`` must contain at least one non-whitespace character; an empty body is
    a caller error rather than a failure event, so it raises
    :class:`InvalidInputError`. ``timestamp`` defaults to :func:`utc_now` and must
    be timezone-aware. ``failed_step`` and ``job_name`` are detected from
    CI-command markers only when they are not supplied explicitly. ``source_path``
    is transport context rather than contract data, so it is used only to make the
    "empty log" error actionable and is never stored on the event. The ``logs``
    field keeps ``text`` verbatim (modulo the contract's surrounding-whitespace
    strip) — call :meth:`FailureEvent.redacted` for a display copy.
    """
    if not isinstance(text, str):
        msg = (
            f"log text must be a str, got {type(text).__name__}; "
            "decode bytes with an explicit encoding before ingesting"
        )
        raise InvalidInputError(msg)
    if not text.strip():
        if source_path:
            msg = f"{source_path}: log text is empty; nothing to ingest"
        else:
            msg = "log text is empty; nothing to ingest"
        raise InvalidInputError(msg)

    return FailureEvent(
        repository=_optional_text(repository, "repository"),
        commit_sha=_optional_text(commit_sha, "commit_sha"),
        workflow_name=_optional_text(workflow_name, "workflow_name"),
        run_id=_optional_text(run_id, "run_id"),
        failed_step=_optional_text(failed_step, "failed_step") or detect_failed_step(text),
        job_name=_optional_text(job_name, "job_name") or detect_job_name(text),
        failure_type=classify_log_text(text),
        logs=text,
        timestamp=_timestamp_or_now(timestamp),
    )


def ingest_log_file(path: Path, **metadata: Any) -> FailureEvent:
    """Read the log at ``path`` and ingest it.

    The file is decoded as UTF-8; a missing file, an unreadable path, or invalid
    UTF-8 raises :class:`InvalidInputError` naming the path. ``metadata`` accepts
    the same keyword arguments as :func:`ingest_log_text`; anything else raises
    :class:`UsageError` instead of being silently dropped.
    """
    resolved = _coerce_path(path)
    try:
        text = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        msg = f"could not read log file {resolved}: {exc}"
        raise InvalidInputError(msg) from exc
    return _ingest_with_metadata(text, source_path=str(resolved), metadata=metadata)


def ingest_stdin(stream: TextIO | None = None) -> FailureEvent | None:
    """Ingest a log read from ``stream`` (``sys.stdin`` when omitted).

    Returns ``None`` when there is nothing to ingest — an interactive terminal,
    an empty stream, or a closed stream — so a caller can distinguish "no input"
    from "input failed to parse".
    """
    source = sys.stdin if stream is None else stream
    if _is_interactive(source):
        return None
    try:
        text = source.read()
    except OSError as exc:
        msg = f"could not read log input from stdin: {exc}"
        raise InvalidInputError(msg) from exc
    if not isinstance(text, str) or not text.strip():
        return None
    return ingest_log_text(text, source_path="<stdin>")


def _ingest_with_metadata(
    text: str, *, source_path: str | None, metadata: dict[str, Any]
) -> FailureEvent:
    """Validate caller-supplied metadata, then delegate to :func:`ingest_log_text`."""
    kwargs: dict[str, Any] = {}
    for key, value in metadata.items():
        if key not in _LOG_METADATA_FIELDS:
            msg = f"unknown metadata field {key!r}; expected one of {sorted(_LOG_METADATA_FIELDS)}"
            raise UsageError(msg)
        kwargs[key] = value
    if source_path is not None:
        kwargs.setdefault("source_path", source_path)
    try:
        return ingest_log_text(text, **kwargs)
    except InvalidInputError as exc:
        if source_path is None or exc.message.startswith(source_path):
            raise
        msg = f"{source_path}: {exc.message}"
        raise InvalidInputError(msg, detail=exc.detail) from exc


def _coerce_path(path: Path) -> Path:
    """Accept a ``Path`` or a path-like string, rejecting anything else."""
    if isinstance(path, Path):
        return path
    if isinstance(path, str):
        return Path(path)
    msg = f"log path must be a Path or str, got {type(path).__name__}"
    raise InvalidInputError(msg)


def _optional_text(value: str | None, field: str) -> str | None:
    """Return ``value`` as a trimmed string, or ``None``; reject other types."""
    if value is None:
        return None
    if not isinstance(value, str):
        msg = f"{field} must be a string or None, got {type(value).__name__}"
        raise InvalidInputError(msg)
    return value.strip()


def _timestamp_or_now(value: datetime | None) -> datetime:
    """Return ``value`` when it is timezone-aware, else raise with a doc pointer."""
    if value is None:
        return utc_now()
    if not isinstance(value, datetime):
        msg = f"timestamp must be a datetime instance or None, got {type(value).__name__}"
        raise InvalidInputError(msg)
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        msg = (
            "timestamp is timezone-naive; timestamps must be timezone-aware and "
            "UTC-normalised (docs/API_CONTRACTS.md section 1)"
        )
        raise InvalidInputError(msg)
    return value


def _is_interactive(stream: TextIO) -> bool:
    """Report whether ``stream`` is a terminal, tolerating objects without ``isatty``."""
    isatty = getattr(stream, "isatty", None)
    if isatty is None:
        return False
    try:
        return bool(isatty())
    except (OSError, ValueError):  # e.g. a detached or already-closed descriptor
        return False
