"""JSON report tests: selective redaction and explicit outcome wording.

The machine-readable report is what a pipeline consumes, so two properties matter more
than its shape:

* identifiers survive redaction — a consumer has to be able to compare the patch the
  incident records with the patch a validation was bound to;
* the ``outcome`` block never upgrades a claim into a recovery, and never narrates a
  proven recovery as a problem.

These are the Milestone 9 requirements: selective redaction plus explicit outcome
wording, in the form a tool can assert on.
"""

from __future__ import annotations

import json

from openmedic.domain.enums import LifecycleState
from openmedic.reporting.json_report import recovery_status, report_dict, report_json

from . import (
    INCIDENT_ID,
    PATCH_HASH_NEWER,
    PATCH_HASH_REJECTED,
    PATCH_HASH_VALIDATED,
    REDACTION_PROBE,
    build_failed_validation,
    build_passing_validation,
    build_record,
    build_skipped_validation,
    build_stale_recovery_record,
)


def test_identifiers_survive_redaction() -> None:
    """Patch identities are content digests, not credentials, and must stay readable."""
    payload = report_dict(build_record())

    attempts = payload["remediation_attempts"]
    assert [attempt["patch_hash"] for attempt in attempts] == [
        PATCH_HASH_REJECTED,
        PATCH_HASH_VALIDATED,
    ]
    assert payload["incident_id"] == INCIDENT_ID
    assert payload["outcome"]["current_patch_hash"] == PATCH_HASH_VALIDATED
    assert payload["outcome"]["validated_patch_hash"] == PATCH_HASH_VALIDATED
    assert payload["validation"]["candidate_patch_hash"] == PATCH_HASH_VALIDATED

    # The point of keeping them verbatim: they are directly comparable.
    assert payload["outcome"]["current_patch_hash"] == attempts[-1]["patch_hash"]


def test_free_text_is_redacted_and_the_flag_says_so() -> None:
    """Every prose field carries the probe out; the flag tells a consumer which world."""
    payload = report_dict(build_record())

    assert payload["redacted"] is True
    assert REDACTION_PROBE not in payload["event"]["logs"]
    assert REDACTION_PROBE not in payload["diagnosis"]["probable_cause"]
    assert REDACTION_PROBE not in payload["remediation_attempts"][0]["summary"]
    assert json.dumps(payload).count(REDACTION_PROBE) == 0


def test_the_raw_payload_is_only_reachable_by_an_explicit_opt_out() -> None:
    """``redact=True`` is the default, and turning it off is a visible decision."""
    raw = report_dict(build_record(), redact=False)

    assert raw["redacted"] is False
    assert REDACTION_PROBE in raw["event"]["logs"]
    # Off means off everywhere, so a caller cannot end up with a half-raw report.
    assert json.dumps(raw).count(REDACTION_PROBE) > 0


def test_a_proven_recovery_reports_it_without_caveats() -> None:
    """A verified recovery must not also narrate a stale validation."""
    payload = report_dict(build_record())
    outcome = payload["outcome"]

    assert outcome["recovered"] is True
    assert outcome["state_claims_recovery"] is True
    assert outcome["stale_validation"] is False
    assert outcome["reason"] is None


def test_a_stale_validation_is_reported_not_hidden() -> None:
    """State says recovered, the patch moved: recovery must be revoked in the payload."""
    payload = report_dict(build_stale_recovery_record())
    outcome = payload["outcome"]

    assert outcome["state_claims_recovery"] is True
    assert outcome["recovered"] is False
    assert outcome["stale_validation"] is True
    assert outcome["reason"] is not None
    assert "stale validation" in outcome["reason"]
    # The hashes that prove it are reported verbatim rather than redacted away.
    assert outcome["current_patch_hash"] == PATCH_HASH_NEWER
    assert outcome["validated_patch_hash"] == PATCH_HASH_VALIDATED
    assert outcome["current_patch_hash"] != outcome["validated_patch_hash"]


def test_a_failed_validation_explains_a_claimed_recovery() -> None:
    """A claimed recovery resting on a failed validation says why it is not one."""
    payload = report_dict(build_record(validations=[build_failed_validation()]))
    outcome = payload["outcome"]

    assert outcome["state_claims_recovery"] is True
    assert outcome["recovered"] is False
    assert outcome["reason"] is not None
    assert "did not pass" in outcome["reason"]


def test_a_skipped_required_check_never_reads_as_recovered() -> None:
    """A skipped required check is an explicit non-success, so recovery is unproven."""
    validation = build_skipped_validation()
    assert validation.passed is False

    payload = report_dict(build_record(validations=[validation]))
    assert payload["outcome"]["recovered"] is False

    check = payload["validation"]["checks_executed"][0]
    assert check["status"] == "skipped"
    assert check["passed"] is False
    assert check["required"] is True
    assert check["blocking_failure"] is True
    assert check["exit_code"] is None


def test_an_incident_that_never_claimed_recovery_has_no_excuse_to_offer() -> None:
    """``reason`` only exists to explain a claim; it is not a status field."""
    payload = report_dict(build_record(state=LifecycleState.RECEIVED, validations=[]))
    outcome = payload["outcome"]

    assert outcome["recorded_state"] == "received"
    assert outcome["state_claims_recovery"] is False
    assert outcome["recovered"] is False
    assert outcome["reason"] is None


def test_the_payload_round_trips_through_json_text() -> None:
    """``report_json`` is ``report_dict`` serialised, not a second report."""
    record = build_record()

    assert json.loads(report_json(record)) == report_dict(record)
    assert json.loads(report_json(record, redact=False)) == report_dict(record, redact=False)


def test_recovery_status_and_the_payload_agree() -> None:
    """Both consumers of the same record must reach the same honest conclusion."""
    for record in (build_record(), build_stale_recovery_record()):
        status = recovery_status(record)
        outcome = report_dict(record)["outcome"]

        assert outcome["recovered"] is status.verified
        assert outcome["stale_validation"] is status.stale
        assert outcome["reason"] == status.reason


def test_a_passing_validation_alone_cannot_claim_recovery() -> None:
    """The validation is fine; the state never said recovered, so nothing is claimed."""
    record = build_record(
        state=LifecycleState.VALIDATING,
        validations=[build_passing_validation()],
    )
    status = recovery_status(record)

    assert status.validation is not None
    assert status.validation.passed is True
    assert status.verified is False
    assert status.state_claims_recovery is False
    assert report_dict(record)["outcome"]["recovered"] is False
