# OpenMedic — Implementation Roadmap

This roadmap is ordered by dependency, not by presentation polish. OpenCode should complete one milestone at a time, verify it, summarize evidence, and continue to the next milestone when safe and within the task's scope. It must not attempt an uncontrolled all-at-once rewrite.

## Milestone 0 — Repository audit and alignment

- Inspect `git status`, branch, tree, package metadata, contracts, team documents, tests, and recent changes.
- Identify existing implementation, duplicated modules, incomplete work, and ownership boundaries.
- Run baseline tests/lint without changing code; record failures separately from new failures.
- Reconcile current code with PRD/TRD/contracts.
- Update docs and `AGENTS.md`; do not delete or replace working teammate code.
- Produce `docs/IMPLEMENTATION_STATUS.md` with current facts and commands/results.

**Exit gate:** clear inventory, baseline test report, proposed file-level plan, no unapproved destructive edits.

## Milestone 1 — Packaging and CLI skeleton

- Establish package layout and installable `openmedic` command, adapting existing layout where appropriate.
- Add version, help, configuration loading, structured logging, documented exit codes.
- Add `openmedic init` for local project configuration/validation command discovery, not destructive scaffolding.
- Add smoke tests and installation instructions.

**Exit gate:** clean environment can install and run `openmedic --help` and `openmedic --version`.

## Milestone 2 — Contracts and local ingestion

- Preserve/reconcile `FailureEvent`, `DiagnosisResult`, `ValidationResult`, `IncidentRecord`.
- Add ingestion from file, stdin, and fixture.
- Add schema validation, timezone-aware timestamps, idempotency, and secret redaction.
- Add representative logs and malformed-input tests.

**Exit gate:** fixtures become validated incidents; invalid input returns useful errors; no secrets are emitted.

## Milestone 3 — Deterministic forensics and diagnosis

- Implement normalization without losing raw evidence.
- Implement stable failure fingerprints.
- Implement deterministic rules for dependency/import, syntax, test, build/config, and unknown failures.
- Attach verified quotes/line references and limitations.
- Add labelled fixture benchmark and negative/ambiguous tests.

**Exit gate:** diagnosis works offline with no API key; evidence is verifiable; unknown cases remain unknown.

## Milestone 4 — Persistence, lifecycle, and reporting

- SQLite repository, migrations, incident history, attempts, validations, transition audit.
- CLI commands to list/show incidents and emit JSON.
- Stable state transitions and duplicate ingestion handling.

**Exit gate:** incidents survive process restarts; history and state are consistent; lifecycle invariants have tests.

## Milestone 5 — Provider abstraction

- Define a narrow provider protocol.
- Add provider configuration and secret handling.
- Implement one provider adapter selected based on repository constraints.
- Add timeouts, retries only where safe, structured output validation, quote verification, and deterministic fallback.

**Exit gate:** tests prove provider errors never break deterministic diagnosis; no provider is advertised without a contract test.

## Milestone 6 — Validation runner

- Define project checks/configuration and safe command policy.
- Run checks in a disposable worktree/container when available.
- Enforce time/resource limits; capture outputs and exit codes.
- Handle timeout, missing runtime, partial checks, stale patch identity, and cleanup.
- Keep original working tree unchanged.

**Exit gate:** pass/fail is based on real execution; missing/skipped/failed checks cannot produce recovered status.

## Milestone 7 — Controlled remediation

- Implement narrow deterministic playbooks and patch proposals.
- Dry-run by default; show diffs.
- Add risk scoring and human approval for uncertain/high-risk actions.
- Reject test deletion, assertion weakening, and safety-check removal.
- Apply only to disposable candidate workspace.

**Exit gate:** at least one end-to-end repair class has a reproducible test proving both successful and unsuccessful validation outcomes.

## Milestone 8 — GitHub Actions integration

- Implement read-only run/job/log ingestion with least privilege.
- Handle pagination, rate limits, missing/expired logs, duplicates, and auth errors.
- Add workflow/action example and documented setup.
- Add reporting mode; write operations remain opt-in.

**Exit gate:** reproducible test against fixtures/mocks plus documented live integration test where credentials are available.

## Milestone 9 — Reporting and reviewable PRs

- Diagnosis reports/comments with evidence and validation.
- Optional branch/PR generation only after passing validation.
- No auto-merge/deployment.
- Permission checks and idempotency for repeated reports.

**Exit gate:** PR content accurately represents evidence and does not claim unverified success.

## Milestone 10 — Recurrence and cascade intelligence

- Track fingerprints, first/last seen, counts, and outcomes.
- Add conservative correlation/grouping with explanations.
- Separate correlation from proven causality.
- Add benchmark metrics.

**Exit gate:** repeat cases are reproducible; grouping tests include unrelated failures that must not be merged.

## Milestone 11 — Optional API and dashboard

- Add FastAPI only if needed, reusing application services.
- Add authentication and safe exposure defaults.
- Build a functional incident history/detail view after CLI workflows are stable.
- Ensure local CLI remains fully usable without the service.

**Exit gate:** API and CLI produce consistent outcomes and contracts; security tests cover write-enabled routes.

## Milestone 12 — Release quality

- Complete README, quick start, provider setup, GitHub setup, security notes, limitations, troubleshooting, architecture docs.
- Run full test/lint/type checks, package build, install-from-built-package smoke test.
- Validate benchmark results and publish only measured metrics.
- Add license and contribution guidelines after confirming the intended license with project owners.

**Exit gate:** clean checkout install works; tests and benchmark results are recorded; known limitations are explicit.

## Global completion rules

- Never report a milestone complete without commands run and outcomes recorded.
- Do not erase or rewrite teammate-owned work without inspection and a documented reason.
- If blocked by missing credentials, Docker, provider access, or external permissions, finish mock/fixture coverage and clearly list the unverified live step.
- Do not ask for permission repeatedly for routine reversible implementation decisions. Stop and ask only for destructive, security-sensitive, credential, billing, or genuinely ambiguous decisions.
- Keep changes scoped to the current milestone; do not start UI polish while core acceptance gates are failing.
