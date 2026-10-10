"""Terminal reporter tests.

The honest cases are the point of this module: a stale validation must never read as a
recovery, a skipped required check must never read as ok, and an inferred quote must never
read as a log quote.
"""

from __future__ import annotations

import re

from openmedic.domain.contracts import Evidence, IncidentRecord
from openmedic.domain.enums import LifecycleState, RemediationStatus
from openmedic.reporting.terminal import TerminalReporter

from . import (
    REDACTION_PROBE,
    VERIFIED_QUOTE,
    build_all_status_attempts,
    build_diagnosis,
    build_record,
    build_skipped_validation,
    build_stale_recovery_record,
)

_STATUS_LABEL_RE = re.compile(r"^\d+\. (att-[A-Za-z0-9_-]+) - (.*)$", re.MULTILINE)

_NEGATION_MARKERS = ("not recovered", "unverified", "stale", "no recovery is claimed")


def test_plain_text_mode_contains_no_ansi_escapes():
    """Plain mode is pure ASCII with no escape sequences, so it is pipe-safe."""
    output = TerminalReporter(color=False).render(build_record())

    assert "\x1b" not in output
    assert output.isascii()
    assert "\r" not in output


def test_plain_mode_narrow_width_stays_ascii():
    """Wrapping must not reintroduce escapes or run past the requested width."""
    reporter = TerminalReporter(color=False, width=60)
    output = reporter.render(build_record())

    assert "\x1b" not in output
    assert all(len(line) <= 60 for line in output.splitlines())


def test_sections_render_in_documented_order():
    """Header, diagnosis, attempts, validation, audit — in that order."""
    output = TerminalReporter(color=False).render(build_record())
    positions = [
        output.index("OPENMEDIC INCIDENT REPORT"),
        output.index("DIAGNOSIS"),
        output.index("REMEDIATION ATTEMPTS"),
        output.index("VALIDATION"),
        output.index("STATE HISTORY (AUDIT)"),
    ]

    assert positions == sorted(positions)


def attempt_labels(output: str) -> dict[str, str]:
    """Return the attempt id to status label mapping parsed from a rendered report."""
    return dict(_STATUS_LABEL_RE.findall(output))


def test_every_attempt_status_has_a_distinct_label():
    """Six statuses must never collapse into one ambiguous word (FR-007)."""
    statuses = build_all_status_attempts()
    record = build_record(
        state=LifecycleState.FAILED,
        attempts=statuses,
        validations=[],
        history=[],
    )
    output = TerminalReporter(color=False).render(record)

    labels = attempt_labels(output)
    assert len(labels) == len(statuses)
    assert set(labels.values()) == {
        "SUGGESTED",
        "AWAITING REVIEW",
        "REJECTED",
        "ATTEMPTED",
        "SUPERSEDED",
        "FAILED",
    }
    assert len(set(labels.values())) == 6


def test_validated_attempt_is_labelled_as_validated():
    """The validated attempt says VALIDATED and the rejected one says REJECTED."""
    output = TerminalReporter(color=False).render(build_record())
    labels = attempt_labels(output)

    assert "VALIDATED" in labels["att-2"]
    assert labels["att-1"] == "REJECTED"
    assert "Rejected because:" in output


def test_inferred_evidence_is_visibly_marked_as_inferred():
    """An inferred quote must never be presented as a log quote."""
    output = TerminalReporter(color=False).render(build_record())

    assert "INFERRED - NOT A VERIFIED LOG QUOTE" in output
    assert "VERIFIED QUOTE" in output
    assert VERIFIED_QUOTE in output
    assert output.index("VERIFIED QUOTE") < output.index("INFERRED")


def test_limitations_always_render():
    """Limitations are mandatory in the contract, so they are mandatory in the report."""
    output = TerminalReporter(color=False).render(build_record())

    assert "Limitations" in output
    assert "Only the failing step log was available." in output


def test_limitations_render_even_without_a_diagnosis():
    """A record with no diagnosis still states what is missing, not a blank section."""
    record = build_record(with_diagnosis=False)
    output = TerminalReporter(color=False).render(record)

    assert "NONE - deterministic diagnosis did not run" in output
    assert "DIAGNOSIS" in output


def test_skipped_required_check_is_rendered_as_non_success():
    """A skipped required check is not a pass, and never renders as ok."""
    record = build_record(
        state=LifecycleState.VALIDATING,
        validations=[build_skipped_validation()],
    )
    output = TerminalReporter(color=False).render(record)

    assert "NOT PASSED" in output
    assert "lint" in output
    assert "[SKIPPED (not success)]" in output
    assert "blocks the result" in output
    assert "[PASSED]" not in output
    assert "OK" not in output


def test_recorded_recovery_with_stale_validation_is_not_reported_as_recovered():
    """Honesty gate: state says recovered, but the patch changed after validation."""
    record = build_stale_recovery_record()
    assert record.state is LifecycleState.RECOVERED

    output = TerminalReporter(color=False).render(record)

    assert "NOT RECOVERED" in output
    assert "stale" in output.lower()
    assert "UNVERIFIED" in output
    for line in output.splitlines():
        if "recovered" in line.lower():
            assert any(marker in line.lower() for marker in _NEGATION_MARKERS), line


def test_proven_recovery_is_reported_as_recovered():
    """The control case for the honesty gate: a matching validation earns the word."""
    output = TerminalReporter(color=False).render(build_record())

    assert "Outcome:" in output
    assert "RECOVERED - validated patch passed all required checks" in output
    assert "recovered (verified)" in output


def test_no_validation_means_no_claim():
    """Without a validation the report says so instead of implying one."""
    record = build_record(state=LifecycleState.REMEDIATION_PENDING, validations=[], history=[])
    output = TerminalReporter(color=False).render(record)

    assert "NONE - no validation has run" in output
    assert "No check has been executed" in output


def test_color_mode_emits_ansi_and_plain_mode_does_not():
    """Colour is opt-in and never leaks into plain mode."""
    coloured = TerminalReporter(color=True).render(build_record())
    plain = TerminalReporter(color=False).render(build_record())

    assert "\x1b[" in coloured
    assert "\x1b" not in plain
    assert coloured.replace("\x1b", "") != plain


def test_escape_sequences_in_log_content_are_stripped():
    """Untrusted log text cannot move the cursor or fake a heading."""
    hostile = Evidence(
        source="logs:1",
        quote="\x1b[2J\x1b[H\x1b[1;31mFAKE SECTION\x1b[0m normal text",
        explanation="hostile content",
    )
    record = build_record()
    diagnosis = build_diagnosis()
    tampered = record.model_copy(
        update={
            "diagnoses": [
                diagnosis.model_copy(update={"evidence": [hostile]}),
            ]
        }
    )

    plain = TerminalReporter(color=False).render(tampered)
    coloured = TerminalReporter(color=True).render(tampered)

    assert "\x1b[2J" not in plain
    assert "\x1b" not in plain
    assert "\x1b[2J" not in coloured
    assert "\x1b[H" not in coloured
    assert "FAKE SECTION" in plain


def test_report_does_not_leak_the_planted_probe():
    """FR-002: secrets are redacted before reporting, in plain and coloured mode."""
    record = build_record()

    assert REDACTION_PROBE not in TerminalReporter(color=False).render(record)
    assert REDACTION_PROBE not in TerminalReporter(color=True).render(record)


def test_render_diagnosis_and_render_validation_are_usable_standalone():
    """The CLI renders partial views, so each section works without the others."""
    reporter = TerminalReporter(color=False)

    diagnosis_output = reporter.render_diagnosis(build_diagnosis())
    validation_output = reporter.render_validation(build_record().latest_validation)

    assert "DIAGNOSIS" in diagnosis_output
    assert "Probable cause:" in diagnosis_output
    assert "INFERRED - NOT A VERIFIED LOG QUOTE" in diagnosis_output
    assert "Limitations" in diagnosis_output
    assert "VALIDATION" in validation_output
    assert "PASSED - every required check ran and succeeded" in validation_output


def test_render_validation_with_none_states_that_nothing_ran():
    """``None`` is an explicit answer, not an empty report."""
    output = TerminalReporter(color=False).render_validation(None)

    assert "NONE - no validation has run" in output


def test_state_history_records_every_transition_with_reasons():
    """The audit trail is rendered, not summarised away."""
    output = TerminalReporter(color=False).render(build_record())

    assert "received -> diagnosing" in output
    assert "validating -> recovered" in output
    assert "ingested from a local log file" in output


def test_attempt_without_patch_hash_is_marked():
    """A missing patch identity is visible rather than silently blank."""
    record = build_record()
    attempt = record.attempts[1].model_copy(update={"patch_hash": None})
    tampered: IncidentRecord = record.model_copy(update={"attempts": [record.attempts[0], attempt]})

    output = TerminalReporter(color=False).render(tampered)

    assert "(none recorded)" in output


def test_rejected_only_record_does_not_claim_validation():
    """A record whose only attempt was rejected has nothing validated."""
    record = build_record(
        state=LifecycleState.REQUIRES_HUMAN_REVIEW,
        attempts=build_all_status_attempts(),
        validations=[],
        history=[],
    )
    output = TerminalReporter(color=False).render(record)

    assert "VALIDATED" not in " ".join(attempt_labels(output).values())
    assert "NONE - no validation has run" in output
    assert RemediationStatus.REJECTED.value in output
