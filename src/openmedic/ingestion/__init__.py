"""Ingestion layer: local logs, stdin, and ``FailureEvent`` JSON payloads.

This package is the only place that converts untrusted, format-specific input
into the domain contract. Everything above it (diagnosis, remediation, validation,
persistence, the CLI) consumes :class:`~openmedic.domain.FailureEvent` objects and
never has to know whether they came from a file, stdin, or a JSON payload.

Ingestion is offline by design: no network calls, no credentials, no model calls.
It also never redacts. ``FailureEvent.logs`` is the evidence a diagnosis quote is
verified against, so redaction happens at display/persistence time via
``FailureEvent.redacted()``.
"""

from __future__ import annotations

from .event_json import KNOWN_FIELDS, dump_event_json, ingest_event_json, parse_event_dict
from .logfile import (
    classification_scores,
    classify_log_text,
    describe_classification,
    detect_failed_step,
    detect_job_name,
    ingest_log_file,
    ingest_log_text,
    ingest_stdin,
)

__all__ = [
    "KNOWN_FIELDS",
    "classification_scores",
    "classify_log_text",
    "describe_classification",
    "detect_failed_step",
    "detect_job_name",
    "dump_event_json",
    "ingest_event_json",
    "ingest_log_file",
    "ingest_log_text",
    "ingest_stdin",
    "parse_event_dict",
]
