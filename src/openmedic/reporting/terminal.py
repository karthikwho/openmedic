"""Human-readable terminal report for one incident.

Two rules shape this module:

1. **Nothing here may claim a recovery it cannot prove.** The outcome line comes from
   :func:`openmedic.reporting.json_report.recovery_status`, which requires a passing
   validation bound to the exact patch currently recorded. When a record's state says
   ``recovered`` but its validation is stale, the state is printed with an ``UNVERIFIED``
   marker and the outcome line says so. FR-007: never mark an incident recovered unless
   required validation passed for the exact candidate patch.
2. **Log content is untrusted.** Every quote, summary, rationale and reason is stripped of
   ANSI escape sequences and other control characters before printing, so a hostile log
   cannot move the cursor, overwrite a heading, or fake a section. With ``color=False``
   the report is additionally forced to plain ASCII, which makes it safe to pipe to a file
   or a pager that is not a terminal.
"""

from __future__ import annotations

import re
import textwrap
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from ..domain.enums import CheckStatus, LifecycleState, RemediationStatus
from ..domain.redaction import redact
from .json_report import attempt_label, check_status_label, recovery_status

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..domain.contracts import (
        CheckResult,
        DiagnosisResult,
        Evidence,
        IncidentRecord,
        RemediationAttempt,
        ValidationResult,
    )
    from .json_report import RecoveryStatus

#: Escape sequences that could otherwise move the cursor or hide output. Stripped from
#: untrusted text before it reaches the terminal.
_ANSI_RE: Final = re.compile(
    r"\x1b\[[0-9;:?]*[ -/]*[@-~]"  # CSI, e.g. colours and cursor moves
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC, e.g. window-title changes
    r"|\x1b[@-Z_a-z]"  # two-character escapes such as ESC M
)
#: Remaining C0 controls, except tab and newline which are normalised instead.
_CONTROL_RE: Final = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_RESET: Final = "\x1b[0m"
_RED: Final = "\x1b[31m"
_GREEN: Final = "\x1b[32m"
_YELLOW: Final = "\x1b[33m"
_CYAN: Final = "\x1b[36m"
_BOLD: Final = "\x1b[1m"

#: Minimum usable width, so a tiny ``width`` cannot collapse the report into confetti.
_MIN_WIDTH: Final = 40

#: ASCII bullet, so the plain-text report stays portable.
_BULLET: Final = "-"


def _clean(text: str) -> str:
    """Strip escape sequences and control characters from untrusted ``text``."""
    without_ansi = _ANSI_RE.sub("", text)
    flattened = without_ansi.replace("\r\n", "\n").replace("\r", "\n").replace("\t", "    ")
    return _CONTROL_RE.sub(" ", flattened)


def _timestamp(value: datetime | None) -> str:
    """Return an ISO-8601 UTC rendering of a contract timestamp."""
    if value is None:
        return "(none)"
    return value.astimezone(UTC).isoformat()


def _validated_attempt_ids(record: IncidentRecord) -> set[str]:
    """Return the ids of attempts whose patch a passing validation is bound to."""
    validated: set[str] = set()
    for validation in record.validations:
        if not validation.passed:
            continue
        for attempt in record.attempts:
            if (
                validation.candidate_patch_hash is not None
                and attempt.patch_hash == validation.candidate_patch_hash
            ):
                validated.add(attempt.attempt_id)
    return validated


class TerminalReporter:
    """Render an incident as a human-readable terminal report."""

    def __init__(self, *, color: bool = True, width: int = 100) -> None:
        """Create a reporter. ``color=False`` yields plain ASCII with no ANSI escapes."""
        self._color = color
        self._width = max(_MIN_WIDTH, int(width))

    # -- public API ---------------------------------------------------------------

    def render(self, record: IncidentRecord) -> str:
        """Return the full report: header, diagnosis, attempts, validation, audit."""
        lines: list[str] = []
        lines += self._header(record)
        lines += self._diagnosis_section(record)
        lines += self._attempts_section(record)
        lines += self._validation_section(record)
        lines += self._history_section(record)
        return "\n".join(lines).rstrip("\n") + "\n"

    def render_diagnosis(self, diagnosis: DiagnosisResult) -> str:
        """Return only the diagnosis section for ``diagnosis``.

        Quote verification needs the originating log, which a bare diagnosis does not
        carry, so this view marks inferred evidence and nothing more. Use :meth:`render`
        when the event is available and quotes should be checked against it.
        """
        lines = [
            self._heading("DIAGNOSIS"),
            *self._diagnosis_body(diagnosis, unverified=set()),
        ]
        return "\n".join(lines).rstrip("\n") + "\n"

    def render_validation(self, validation: ValidationResult | None) -> str:
        """Return only the validation section, or an explicit "nothing ran" section."""
        lines = [self._heading("VALIDATION")]
        if validation is None:
            lines += self._no_validation_lines()
        else:
            lines += self._validation_body(validation)
        return "\n".join(lines).rstrip("\n") + "\n"

    # -- section builders ---------------------------------------------------------

    def _header(self, record: IncidentRecord) -> list[str]:
        """Return the incident header block, including the honest outcome line."""
        status = recovery_status(record)
        event = record.event
        workflow = event.workflow_name or "(unknown)"
        if event.job_name:
            workflow = f"{workflow} / job {event.job_name}"
        lines = [
            self._heading("OPENMEDIC INCIDENT REPORT"),
            self._label("Incident:", record.incident_id),
            self._label("Repository:", self._safe(event.repository or "") or "(unknown)"),
            self._label("Workflow:", self._safe(workflow)),
            self._label("Run:", self._safe(event.run_id or "") or "(unknown)"),
            self._label("Failed step:", self._safe(event.failed_step or "") or "(unknown)"),
            self._label("Commit:", event.commit_sha or "(unknown)"),
            self._label("Failure type:", event.failure_type.value),
            self._label("First reported:", _timestamp(record.created_at)),
            self._label("Last updated:", _timestamp(record.updated_at)),
            self._label("Recorded state:", self._state_display(record, status)),
            self._label("Outcome:", self._outcome_display(status)),
        ]
        if not status.verified:
            lines.append(self._label("Reason:", self._outcome_reason(record, status)))
        lines.append(self._label("Idempotency key:", self._safe(record.idempotency_key)))
        return lines

    def _diagnosis_section(self, record: IncidentRecord) -> list[str]:
        """Return the diagnosis section, or an explicit "no diagnosis" section."""
        diagnosis = record.latest_diagnosis
        if diagnosis is None:
            return [
                self._heading("DIAGNOSIS"),
                self._label(
                    "Status:",
                    self._warn("NONE - deterministic diagnosis did not run"),
                ),
                *self._wrap(
                    "Without a diagnosis there is no probable cause, no evidence and no "
                    "recommended action. Nothing below should be read as one."
                ),
            ]
        unverified = {id(item) for item in diagnosis.verify_evidence(record.event.logs)}
        return [
            self._heading("DIAGNOSIS"),
            *self._diagnosis_body(diagnosis, unverified=unverified),
        ]

    def _diagnosis_body(self, diagnosis: DiagnosisResult, *, unverified: set[int]) -> list[str]:
        """Return the shared diagnosis body used by both entry points."""
        review = self._bad("REQUIRED") if diagnosis.requires_human_review else "not required"
        lines = [
            self._label("Probable cause:", self._safe(diagnosis.probable_cause)),
            self._label(
                "Confidence:",
                f"{diagnosis.confidence:.0%} (not a probability that a fix will work)",
            ),
            self._label("Recommended action:", diagnosis.recommended_action.value),
            self._label("Risk level:", diagnosis.risk_level.value),
            self._label("Human review:", review),
            self._label(
                "Rule:",
                f"{diagnosis.rule_id} v{diagnosis.rule_version}"
                f" (provider used: {'yes' if diagnosis.provider_used else 'no'})",
            ),
            "",
            self._subheading("Evidence"),
        ]
        if not diagnosis.evidence:
            lines += self._wrap("No evidence was recorded.")
        for index, item in enumerate(diagnosis.evidence, start=1):
            lines += self._evidence_block(index, len(diagnosis.evidence), item, unverified)
        lines += ["", self._subheading("Limitations")]
        lines += self._bullet_list(diagnosis.limitations)
        return lines

    def _evidence_block(
        self, index: int, total: int, item: Evidence, unverified: set[int]
    ) -> list[str]:
        """Return one evidence item, marking inferred and unverifiable quotes."""
        if item.inferred:
            marker = self._warn("INFERRED - NOT A VERIFIED LOG QUOTE")
        elif id(item) in unverified:
            marker = self._bad("UNVERIFIED - QUOTE NOT FOUND IN THE SOURCE LOGS")
        else:
            marker = self._good("VERIFIED QUOTE")
        return [
            self._subheading(f"Evidence {index} of {total} - source: {item.source} - {marker}"),
            *self._wrap(self._safe(item.quote), indent="    "),
            self._label("Why:", self._safe(item.explanation), indent="    "),
        ]

    def _attempts_section(self, record: IncidentRecord) -> list[str]:
        """Return the remediation attempts section."""
        validated = _validated_attempt_ids(record)
        lines = [self._heading("REMEDIATION ATTEMPTS")]
        if not record.attempts:
            lines.append(self._label("Status:", self._warn("NONE - no fix has been proposed")))
            return lines
        for index, attempt in enumerate(record.attempts, start=1):
            lines += self._attempt_block(index, attempt, attempt.attempt_id in validated)
        return lines

    def _attempt_block(self, index: int, attempt: RemediationAttempt, validated: bool) -> list[str]:
        """Return one attempt with its distinct status label."""
        label = attempt_label(attempt, validated=validated)
        styled = self._good(label) if validated else self._accent(label)
        review = "required" if attempt.requires_human_review else "not required"
        lines = [
            self._subheading(f"{index}. {attempt.attempt_id} - {styled}"),
            self._label("Summary:", self._safe(attempt.summary), indent="   "),
            self._label("Rationale:", self._safe(attempt.rationale), indent="   "),
            self._label(
                "Risk:", f"{attempt.risk_level.value} (human review: {review})", indent="   "
            ),
            self._label("Rule:", attempt.rule_id, indent="   "),
        ]
        files = (
            ", ".join(self._safe(name) for name in attempt.files_changed)
            if attempt.files_changed
            else "(none recorded)"
        )
        lines.append(self._label("Files:", files, indent="   "))
        lines.append(
            self._label("Patch hash:", attempt.patch_hash or "(none recorded)", indent="   ")
        )
        if attempt.status is RemediationStatus.REJECTED and attempt.rejection_reason:
            lines.append(
                self._label("Rejected because:", self._safe(attempt.rejection_reason), indent="   ")
            )
        if attempt.status is RemediationStatus.FAILED:
            lines.append(self._label("Failed:", "this attempt did not complete", indent="   "))
        if attempt.status is RemediationStatus.SUPERSEDED and attempt.superseded_by:
            lines.append(self._label("Superseded by:", attempt.superseded_by, indent="   "))
        if attempt.validation_id:
            lines.append(self._label("Validation id:", attempt.validation_id, indent="   "))
        return lines

    def _validation_section(self, record: IncidentRecord) -> list[str]:
        """Return the validation section for the latest validation, if any."""
        validation = record.latest_validation
        lines = [self._heading("VALIDATION")]
        if validation is None:
            lines += self._no_validation_lines()
        else:
            lines += self._validation_body(validation)
        return lines

    def _no_validation_lines(self) -> list[str]:
        """Return the lines used when no validation has run at all."""
        return [
            self._label("Outcome:", self._warn("NONE - no validation has run")),
            *self._wrap("No check has been executed, so nothing about this incident is proven."),
        ]

    def _validation_body(self, validation: ValidationResult) -> list[str]:
        """Return the shared validation body used by both entry points."""
        if validation.passed:
            outcome = self._good("PASSED - every required check ran and succeeded")
        else:
            outcome = self._bad("NOT PASSED")
        execution = validation.execution
        isolation = execution.isolation_kind or "(not recorded)"
        if isolation == "local-subprocess":
            isolation += " (NOT a hardened sandbox)"
        lines = [
            self._label("Outcome:", outcome),
            self._label("Candidate patch:", validation.candidate_patch_hash or "(not bound)"),
            self._label("Isolation:", self._safe(isolation)),
            self._label("Docker available:", "yes" if execution.docker_available else "no"),
        ]
        if execution.timeout_seconds is not None:
            lines.append(self._label("Timeout:", f"{execution.timeout_seconds:g}s"))
        if validation.started_at is not None:
            lines.append(self._label("Started:", _timestamp(validation.started_at)))
        if validation.completed_at is not None:
            lines.append(self._label("Completed:", _timestamp(validation.completed_at)))
        lines += ["", self._subheading("Checks")]
        if not validation.checks_executed:
            lines += self._wrap("No checks were executed. An empty result is not a pass.")
        for check in validation.checks_executed:
            lines.append(self._check_line(check))
        if validation.failed_checks:
            lines.append(self._label("Failed checks:", ", ".join(validation.failed_checks)))
        lines.append(self._label("Summary:", self._safe(validation.summary) or "(none)"))
        if execution.limitations:
            lines += ["", self._subheading("Isolation limitations")]
            lines += self._bullet_list(execution.limitations)
        return lines

    def _check_line(self, check: CheckResult) -> str:
        """Return one check line. Every non-success is labelled as one, never as ok."""
        status = check_status_label(check.status)
        if check.status is CheckStatus.PASSED:
            label = self._good(f"[{status}]")
        else:
            label = self._bad(f"[{status}]")
        details = [f"required: {'yes' if check.required else 'no'}"]
        if check.exit_code is not None:
            details.append(f"exit={check.exit_code}")
        if check.duration_seconds is not None:
            details.append(f"{check.duration_seconds:g}s")
        if check.required and check.status is not CheckStatus.PASSED:
            details.append("blocks the result")
        return self._label(f"{label} {self._safe(check.name)}", "  ".join(details), indent="    ")

    def _history_section(self, record: IncidentRecord) -> list[str]:
        """Return the audited state-history section."""
        status = recovery_status(record)
        lines = [self._heading("STATE HISTORY (AUDIT)")]
        if not record.state_history:
            lines += self._wrap("No transitions have been recorded.")
            return lines
        for transition in record.state_history:
            origin = "start" if transition.from_state is None else transition.from_state.value
            target = transition.to_state.value
            note = ""
            if transition.to_state is LifecycleState.RECOVERED and not status.verified:
                note = self._warn(" (unverified - see outcome)")
            lines.append(
                self._label(
                    _timestamp(transition.at),
                    f"{origin} -> {target}{note}  reason: {self._safe(transition.reason)}",
                    indent="    ",
                )
            )
        return lines

    # -- formatting helpers -------------------------------------------------------

    def _state_display(self, record: IncidentRecord, status: RecoveryStatus) -> str:
        """Return the recorded state, marked UNVERIFIED when recovery is not proven."""
        state = record.state.value
        if status.verified:
            return self._good(f"{state} (verified)")
        if status.state_claims_recovery:
            return self._bad(f"{state} (UNVERIFIED - see outcome)")
        return state

    def _outcome_display(self, status: RecoveryStatus) -> str:
        """Return the outcome verdict. Only a proven recovery may say RECOVERED."""
        if status.verified:
            return self._good("RECOVERED - validated patch passed all required checks")
        return self._bad("NOT RECOVERED")

    def _outcome_reason(self, record: IncidentRecord, status: RecoveryStatus) -> str:
        """Return why the outcome is not a recovery."""
        if status.reason is not None:
            return status.reason
        return f"the incident is in state '{record.state.value}' and no recovery is claimed"

    def _heading(self, title: str) -> str:
        """Return a full-width section heading."""
        padded = f" {title} ".center(self._width, "=")[: self._width]
        return self._accent(padded)

    def _subheading(self, title: str) -> str:
        """Return a sub-heading, wrapped to the report width."""
        text = self._safe(title)
        if len(text) <= self._width:
            return self._bold(text)
        wrapped = textwrap.wrap(text, width=self._width, subsequent_indent="    ")
        return "\n".join(self._bold(line) for line in wrapped)

    def _label(self, name: str, value: str, *, indent: str = "") -> str:
        """Return one ``name: value`` row, wrapping the value under itself."""
        prefix = f"{indent}{name}"
        if not value:
            return prefix.rstrip()
        available = max(20, self._width - len(prefix) - 1)
        if len(value) <= available:
            return f"{prefix} {value}"
        wrapped = textwrap.wrap(value, width=available) or [""]
        first, *rest = wrapped
        padding = " " * (len(prefix) + 1)
        return "\n".join([f"{prefix} {first}", *(f"{padding}{line}" for line in rest)])

    def _wrap(self, text: str, *, indent: str = "") -> list[str]:
        """Return ``text`` wrapped to the report width, one line per entry."""
        available = max(20, self._width - len(indent))
        lines: list[str] = []
        for raw_line in self._safe(text).splitlines() or [""]:
            if not raw_line.strip():
                lines.append(indent.rstrip())
                continue
            wrapped = textwrap.wrap(
                raw_line, width=available, subsequent_indent=indent, initial_indent=indent
            )
            lines.extend(wrapped or [indent + raw_line])
        return lines

    def _bullet_list(self, items: list[str]) -> list[str]:
        """Return a bullet list. An empty list still prints an explicit marker."""
        if not items:
            return [self._wrap("(none recorded)", indent="    ")]
        lines: list[str] = []
        for item in items:
            lines += self._wrap(self._safe(item), indent=f"    {_BULLET} ")
        return lines

    def _safe(self, text: str) -> str:
        """Return ``text`` cleaned for display and, without colour, forced to ASCII.

        Secrets are redacted first (FR-002: redact before reporting), and verification
        still happens against the raw log, so a redacted quote is never confused with an
        unverifiable one. Identifiers and enum values are not passed through here.
        """
        cleaned = _clean(text)
        redacted = redact(cleaned).text
        if self._color:
            return redacted
        return redacted.encode("ascii", "replace").decode("ascii")

    def _accent(self, text: str) -> str:
        """Return ``text`` in the heading colour."""
        return self._style(text, _CYAN)

    def _bold(self, text: str) -> str:
        """Return ``text`` in bold."""
        return self._style(text, _BOLD)

    def _good(self, text: str) -> str:
        """Return ``text`` in the success colour."""
        return self._style(text, _GREEN)

    def _warn(self, text: str) -> str:
        """Return ``text`` in the warning colour."""
        return self._style(text, _YELLOW)

    def _bad(self, text: str) -> str:
        """Return ``text`` in the failure colour."""
        return self._style(text, _RED)

    def _style(self, text: str, code: str) -> str:
        """Wrap ``text`` in an ANSI ``code``, or return it unchanged without colour."""
        if not self._color:
            return text
        return f"{code}{text}{_RESET}"
