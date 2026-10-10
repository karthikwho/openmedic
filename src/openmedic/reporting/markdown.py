"""GitHub-commentable markdown report for one incident.

FR-013 asks for a diagnosis comment on the originating run. Three properties are
non-negotiable here, because a markdown report is the artefact a maintainer reads and
forwards:

* **It is built from the same payload as the JSON report.** ``render_markdown`` calls
  :func:`openmedic.reporting.json_report.report_dict` with redaction enabled, so the
  markdown can never disagree with the machine-readable report, and no secret reaches a
  public pull-request comment.
* **It is honest about isolation.** The validation's ``execution.isolation_kind`` and its
  ``execution.limitations`` are reproduced verbatim. A ``local-subprocess`` run is *not* a
  hardened sandbox and the report must not let a green check table imply otherwise.
* **It never implies a merge.** The report states explicitly that nothing was merged,
  pushed, or deployed. Branch and pull-request creation is a separate opt-in.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Final

from ..domain.enums import CheckStatus
from .json_report import check_status_label, report_dict

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..domain.contracts import IncidentRecord

#: Control characters that would break out of a markdown table cell or heading.
_CONTROL_RE: Final = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

#: Rendered instead of a value the contract leaves empty.
_EMPTY: Final = "_not recorded_"

#: Known check statuses, so an unknown status is reported as a non-success rather than
#: silently dropped from the vocabulary.
_KNOWN_CHECK_STATUSES: Final = frozenset(member.value for member in CheckStatus)

#: Wording of the no-auto-merge promise. Kept as a constant so the CLI help text, the
#: docs, and this report cannot drift apart.
_NO_MERGE_NOTE: Final = (
    "**Not automatically merged.** OpenMedic only writes a report. It does not merge, "
    "push, deploy, or comment on your behalf unless a human explicitly enables that "
    "separate, opt-in operation."
)

_ISOLATION_NOTES: Final[dict[str, str]] = {
    "local-subprocess": (
        "not a hardened sandbox: it shares the host filesystem and network namespace"
    ),
    "local-venv": "constrained to a virtual environment, not a hardened sandbox",
    "docker": "container isolation, still not a security boundary against a malicious patch",
}


def _check_label(status: Any) -> str:
    """Return the honest label for a check status carried in a payload dict."""
    if isinstance(status, str) and status in _KNOWN_CHECK_STATUSES:
        return check_status_label(CheckStatus(status))
    return f"{status} (not success)"


def _percent(value: Any) -> str:
    """Return ``value`` as a percentage, or a placeholder when it is missing."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{float(value):.0%}"
    return _EMPTY


def _cell(text: Any) -> str:
    """Return ``text`` as a single markdown table cell."""
    if text is None:
        return _EMPTY
    if isinstance(text, bool):
        return "yes" if text else "no"
    if isinstance(text, (int, float)):
        return str(text)
    if isinstance(text, list):
        return _cell(", ".join(str(item) for item in text))
    cleaned = _CONTROL_RE.sub(" ", str(text)).replace("\r\n", "\n").replace("\r", "\n")
    flattened = " ".join(part.strip() for part in cleaned.splitlines() if part.strip())
    return flattened.replace("|", "\\|") or _EMPTY


def _code(text: Any) -> str:
    """Return ``text`` wrapped in inline code, safe for a table cell."""
    value = _cell(text).replace("`", "'")
    return f"`{value}`"


def _quote(text: Any) -> list[str]:
    """Return ``text`` as a markdown blockquote, one line per input line."""
    raw = "" if text is None else str(text)
    lines = raw.splitlines() or [""]
    return [f"> {line}".rstrip() for line in lines]


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    """Return a markdown table, or an explicit note when there are no rows."""
    if not rows:
        return [f"_No {header[0].lower()} recorded._", ""]
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join("---" for _ in header) + " |",
    ]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    lines.append("")
    return lines


def _bullets(items: Any) -> list[str]:
    """Return ``items`` as a markdown bullet list, with an explicit empty marker."""
    values = list(items) if isinstance(items, list) else []
    if not values:
        return ["_None recorded._", ""]
    lines = [f"- {_cell(item)}" for item in values]
    lines.append("")
    return lines


def render_markdown(record: IncidentRecord, *, title: str | None = None) -> str:
    """Return a GitHub-commentable markdown report for ``record``.

    The report is redacted, states the honest outcome, and separates what was suggested
    from what was attempted, rejected, failed, or validated.
    """
    data = report_dict(record, redact=True)
    outcome = _mapping(data.get("outcome"))
    event = _mapping(data.get("event"))
    diagnosis = _mapping(data.get("diagnosis"))
    validation = _mapping(data.get("validation"))
    attempts = _sequence(data.get("remediation_attempts"))

    heading = title or f"OpenMedic incident report - {record.incident_id}"
    lines: list[str] = [f"## {heading}", ""]

    lines += _summary_section(data, event, outcome)
    lines += _diagnosis_section(diagnosis)
    lines += _attempts_section(attempts)
    lines += _validation_section(validation)
    lines += _history_section(_sequence(data.get("state_history")))
    lines += [_NO_MERGE_NOTE, ""]
    return "\n".join(lines).rstrip("\n") + "\n"


def _summary_section(
    data: dict[str, Any], event: dict[str, Any], outcome: dict[str, Any]
) -> list[str]:
    """Return the summary table, including the honest outcome line."""
    recovered = bool(outcome.get("recovered"))
    if recovered:
        outcome_text = "**RECOVERED** - validation passed for the exact current patch"
    else:
        reason = outcome.get("reason") or "no recovery is claimed"
        outcome_text = f"**NOT RECOVERED** - {_cell(reason)}"
    state = outcome.get("recorded_state") or data.get("state")
    state_text = _code(state)
    if outcome.get("state_claims_recovery") and not recovered:
        state_text += " (unverified)"
    lines = ["### Summary", ""]
    lines += _table(
        ["Field", "Value"],
        [
            ["Incident", _code(data.get("incident_id"))],
            ["Repository", _code(event.get("repository"))],
            ["Workflow", _code(event.get("workflow_name"))],
            ["Job", _code(event.get("job_name"))],
            ["Run", _code(event.get("run_id"))],
            ["Failed step", _cell(event.get("failed_step"))],
            ["Commit", _code(event.get("commit_sha"))],
            ["Failure type", _code(event.get("failure_type"))],
            ["Reported", _cell(event.get("timestamp"))],
            ["Recorded state", state_text],
            ["Outcome", outcome_text],
        ],
    )
    return lines


def _diagnosis_section(diagnosis: dict[str, Any]) -> list[str]:
    """Return the diagnosis section with evidence blockquotes and limitations."""
    if not diagnosis:
        return ["### Diagnosis", "", "_No deterministic diagnosis was recorded._", ""]

    lines = ["### Diagnosis", ""]
    lines += _table(
        ["Field", "Value"],
        [
            ["Probable cause", _cell(diagnosis.get("probable_cause"))],
            [
                "Confidence",
                f"{_percent(diagnosis.get('confidence'))} (not a fix probability)",
            ],
            ["Recommended action", _code(diagnosis.get("recommended_action"))],
            ["Risk level", _code(diagnosis.get("risk_level"))],
            [
                "Human review",
                "**required**" if diagnosis.get("requires_human_review") else "not required",
            ],
            ["Rule", _code(f"{diagnosis.get('rule_id')} v{diagnosis.get('rule_version')}")],
            ["Provider used", "yes" if diagnosis.get("provider_used") else "no (deterministic)"],
        ],
    )

    evidence = _sequence(diagnosis.get("evidence"))
    lines += ["#### Evidence", ""]
    if not evidence:
        lines += ["_No evidence was recorded._", ""]
    for index, item in enumerate(evidence, start=1):
        entry = _mapping(item)
        verified = bool(entry.get("verified_quote")) and not bool(entry.get("inferred"))
        marker = "verified quote" if verified else "**INFERRED - not a verified log quote**"
        lines += [
            f"{index}. **Source:** {_code(entry.get('source'))} — {marker}",
            "",
            *_quote(entry.get("quote")),
            "",
            f"   _Why:_ {_cell(entry.get('explanation'))}",
            "",
        ]

    lines += ["#### Limitations", ""]
    lines += _bullets(diagnosis.get("limitations"))
    return lines


def _attempts_section(attempts: list[Any]) -> list[str]:
    """Return the remediation attempts table with distinct, honest status labels."""
    lines = ["### Remediation attempts", ""]
    if not attempts:
        lines += ["_No remediation was proposed._", ""]
        return lines
    rows: list[list[str]] = []
    for attempt in attempts:
        entry = _mapping(attempt)
        status = entry.get("status_label") or _cell(entry.get("status"))
        if entry.get("validated"):
            status = f"**{status} / VALIDATED**"
        notes = _cell(entry.get("rejection_reason")) if entry.get("rejection_reason") else ""
        rows.append(
            [
                _code(entry.get("attempt_id")),
                status,
                _code(entry.get("risk_level")),
                _cell(entry.get("files_changed")),
                _code(entry.get("patch_hash")),
                _cell(notes),
            ]
        )
    lines += _table(["Attempt", "Status", "Risk", "Files", "Patch hash", "Notes"], rows)
    for attempt in attempts:
        entry = _mapping(attempt)
        lines += [
            f"- **{_code(entry.get('attempt_id'))}** — {_cell(entry.get('summary'))}",
            f"  - Rationale: {_cell(entry.get('rationale'))}",
            f"  - Rule: {_code(entry.get('rule_id'))}; human review: "
            f"{'required' if entry.get('requires_human_review') else 'not required'}",
        ]
    lines.append("")
    return lines


def _validation_section(validation: dict[str, Any]) -> list[str]:
    """Return the validation section, including isolation kind and its limitations."""
    lines = ["### Validation", ""]
    if not validation:
        lines += [
            "_No validation has run. No check was executed, so nothing about this "
            "incident is proven._",
            "",
        ]
        return lines

    outcome = "**PASSED**" if validation.get("passed") else "**NOT PASSED**"
    execution = _mapping(validation.get("execution"))
    isolation = _cell(execution.get("isolation_kind"))
    note = _ISOLATION_NOTES.get(isolation, "isolation strength is described by its limitations")
    lines += _table(
        ["Field", "Value"],
        [
            ["Outcome", outcome],
            ["Candidate patch", _code(validation.get("candidate_patch_hash"))],
            ["Isolation", f"{_code(isolation)} — {note}"],
            ["Docker available", "yes" if execution.get("docker_available") else "no"],
            ["Timeout", _cell(execution.get("timeout_seconds"))],
            ["Started", _cell(validation.get("started_at"))],
            ["Completed", _cell(validation.get("completed_at"))],
            ["Summary", _cell(validation.get("summary"))],
        ],
    )

    checks = _sequence(validation.get("checks_executed"))
    lines += ["#### Checks", ""]
    rows: list[list[str]] = []
    for check in checks:
        entry = _mapping(check)
        status = entry.get("status")
        rendered = _check_label(status)
        if not entry.get("passed"):
            rendered = f"**{rendered}**"
        rows.append(
            [
                _code(entry.get("name")),
                rendered,
                "yes" if entry.get("required") else "no",
                _cell(entry.get("exit_code")),
                _cell(entry.get("duration_seconds")),
            ]
        )
    lines += _table(["Check", "Status", "Required", "Exit", "Duration (s)"], rows)

    failed = _sequence(validation.get("failed_checks"))
    if failed:
        lines += [f"Failed checks: {_cell(failed)}", ""]

    lines += ["#### Isolation limitations", ""]
    lines += _bullets(execution.get("limitations"))
    return lines


def _history_section(history: list[Any]) -> list[str]:
    """Return the audited state-transition table."""
    lines = ["### State history (audit)", ""]
    rows: list[list[str]] = []
    for transition in history:
        entry = _mapping(transition)
        rows.append(
            [
                _cell(entry.get("at")),
                _cell(entry.get("from_state")),
                _cell(entry.get("to_state")),
                _cell(entry.get("reason")),
            ]
        )
    lines += _table(["At (UTC)", "From", "To", "Reason"], rows)
    return lines


def _mapping(value: Any) -> dict[str, Any]:
    """Return ``value`` as a plain mapping, or an empty mapping."""
    return value if isinstance(value, dict) else {}


def _sequence(value: Any) -> list[Any]:
    """Return ``value`` as a plain list."""
    if isinstance(value, list):
        return list(value)
    return []
