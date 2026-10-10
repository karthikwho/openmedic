"""Diagnosis layer: deterministic rules and the offline diagnosis engine.

This layer classifies a ``FailureEvent`` from its logs alone (PRD FR-004, FR-008). It
imports only the domain contracts and the forensics helpers, so it stays runnable with
no provider, no network access and no credentials. Optional provider enrichment lives in
``openmedic.providers`` and comes later; it can only add explanation, never change what is
reported here.
"""

from __future__ import annotations

from .engine import DiagnosisEngine
from .rules import (
    BuildOrConfigRule,
    DependencyResolutionRule,
    DiagnosisRule,
    MissingModuleRule,
    RuleMatch,
    SyntaxOrImportRule,
    TestFailureRule,
    UnknownRule,
    default_rules,
)

__all__ = [
    "BuildOrConfigRule",
    "DependencyResolutionRule",
    "DiagnosisEngine",
    "DiagnosisRule",
    "MissingModuleRule",
    "RuleMatch",
    "SyntaxOrImportRule",
    "TestFailureRule",
    "UnknownRule",
    "default_rules",
]
