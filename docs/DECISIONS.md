# OpenMedic — Architecture Decision Record

This file records locked project decisions. OpenCode may propose changes, but must document rationale, impact, migration, and tests before changing a locked decision.

## D-001 — Name
**Decision:** Product name is OpenMedic; suggested repository/package slug is `openmedic`.

## D-002 — Product focus
**Decision:** Focus on CI/CD failure analysis, diagnosis, safe remediation, validation, and reporting. Do not pivot into a generic coding agent.

## D-003 — Audience and mission
**Decision:** Build an open-source, self-hostable tool useful to students, independent developers, and maintainers who want provider choice and control over AI costs.

## D-004 — CLI-first
**Decision:** The CLI is the first interface. Core application services must be reusable without the CLI and without a running server.

## D-005 — Local-first
**Decision:** Local diagnosis and incident history should work on a developer machine. SQLite is the default durable store unless an existing sound implementation warrants retention.

## D-006 — Deterministic-first
**Decision:** Core diagnosis must work without model credentials or network access. AI is optional enrichment/advisory, never a mandatory dependency.

## D-007 — Provider agnosticism
**Decision:** Provider-specific code stays behind adapters. No provider is assumed to be free, unlimited, or always available.

## D-008 — Proof before success
**Decision:** `recovered` requires passing required checks for the exact candidate patch. Any subsequent patch change invalidates the prior validation.

## D-009 — Safe remediation
**Decision:** No blind model-generated shell execution, no production secrets in repair environments, no auto-merge, and no production deployment.

## D-010 — UI last
**Decision:** Complete and verify core workflows before spending significant effort on dashboard styling or visual polish.

## D-011 — Preserve existing work
**Decision:** Inspect repository status, contracts, tests, and team ownership before editing. Do not overwrite useful teammate work without an explicit, documented reason.

## D-012 — Honest claims
**Decision:** Never claim feature completion, test success, benchmark numbers, or market uniqueness without evidence.
