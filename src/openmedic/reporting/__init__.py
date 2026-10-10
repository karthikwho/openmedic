"""OpenMedic reporting layer: terminal, JSON, and GitHub-commentable markdown.

All three renderers answer the same two questions the same way, because they import them
from :mod:`openmedic.reporting.json_report`:

* :func:`recovery_status` — is the incident *actually* recovered? Recovery requires a
  passing validation bound to the exact patch currently recorded, so a stale validation
  can never be rendered as a recovery.
* :func:`attempt_status_label` — what is this attempt? Suggested, attempted, rejected,
  failed, awaiting review, and validated are distinct labels (FR-007).

Nothing in this package imports another OpenMedic layer above ``domain``, so the CLI, the
application services, and the later optional API can all render the same report.
"""

from __future__ import annotations

from .json_report import (
    ATTEMPT_STATUS_LABELS,
    REPORT_SCHEMA_VERSION,
    RecoveryStatus,
    attempt_label,
    attempt_status_label,
    check_status_label,
    diagnosis_dict,
    recovery_status,
    report_dict,
    report_json,
    validation_dict,
)
from .markdown import render_markdown
from .terminal import TerminalReporter

__all__ = [
    "ATTEMPT_STATUS_LABELS",
    "REPORT_SCHEMA_VERSION",
    "RecoveryStatus",
    "TerminalReporter",
    "attempt_label",
    "attempt_status_label",
    "check_status_label",
    "diagnosis_dict",
    "recovery_status",
    "render_markdown",
    "report_dict",
    "report_json",
    "validation_dict",
]
