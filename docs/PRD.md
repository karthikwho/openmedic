# OpenMedic — Product Requirements Document (PRD)

**Version:** 2.0  
**Status:** Implementation baseline  
**Date:** 2026-10-09

## 1. Product summary

OpenMedic is an open-source CI/CD failure diagnosis and safe-recovery assistant. It ingests failed-run evidence, identifies likely causes with traceable evidence, proposes bounded remediations, validates changes in a controlled environment, and reports the result honestly.

OpenMedic is designed for developers who want useful debugging and recovery tooling without being forced to subscribe to a particular paid AI provider. The deterministic path must work without an LLM. Users may opt into compatible hosted APIs or local inference, subject to provider limits and hardware.

**One-line pitch:** Open-source CI recovery with evidence-backed diagnosis and proof-before-success, without mandatory paid AI.

## 2. Problem

CI failures interrupt development. Developers must inspect logs, identify the failing step, infer the root cause, edit code or configuration, rerun checks, and determine whether the change truly fixed the failure. AI-assisted products can help, but access, provider choice, hosted-service requirements, and inference cost can be barriers.

OpenMedic's hypothesis is that developers benefit from a transparent, self-hostable, provider-flexible tool that can perform deterministic analysis first and use AI only when configured.

This is not a claim that CI self-healing is new or that all alternatives are paid. Existing tools already cover parts of this problem. OpenMedic's intended distinction is openness, local control, provider flexibility, deterministic fallback, and visible validation evidence.

## 3. Target users

1. Students and independent developers.
2. Open-source maintainers.
3. Small teams seeking self-hostable debugging/recovery workflows.
4. Developers using local models or wanting to control API usage.

## 4. Product principles

- **Evidence before confidence:** diagnoses reference actual log evidence and communicate uncertainty.
- **Deterministic baseline:** known failures remain diagnosable without network access or model credentials.
- **Provider independence:** model integrations are adapters; core logic does not depend on one vendor.
- **Proof before success:** no recovery status without passing required validation for the exact candidate patch.
- **Safe by default:** untrusted logs, repository files, and model outputs cannot directly authorize arbitrary execution.
- **Local-first:** the core workflow runs on a developer machine and stores incident data locally by default.
- **Incremental and honest:** incomplete integrations and limitations are explicit; metrics are measured, never fabricated.
- **Useful CLI:** every essential operation must be scriptable and have predictable exit codes and machine-readable output where appropriate.

## 5. Goals

- Diagnose supported CI failures from local logs and structured events.
- Ingest real GitHub Actions failures and retrieve relevant run/job/log context.
- Normalize log output and produce stable failure fingerprints.
- Produce evidence-linked diagnosis with cause, confidence, limitations, and recommended action.
- Support optional provider adapters and local-model endpoints without coupling the core to them.
- Propose and apply narrowly scoped remediations under an explicit safety policy.
- Validate candidates in a disposable, resource-limited environment.
- Track incident state, attempts, validation evidence, and recurring failures.
- Offer local CLI workflows first, then GitHub Actions automation, with optional API/dashboard later.
- Benchmark results against seeded reproducible failure cases.

## 6. Non-goals

- Replacing GitHub Actions or other CI platforms.
- Guaranteeing every failure can be diagnosed or repaired.
- Unlimited free AI inference.
- Arbitrary autonomous shell execution from model output.
- Automatic production deployment or automatic merge to a protected branch.
- Managing fleets of self-hosted runners.
- Enterprise SSO or multi-tenant hosted SaaS in the initial implementation.
- Building a general-purpose coding agent unrelated to CI/CD recovery.

## 7. Functional requirements

### P0 — Core product

**FR-001: CLI foundation**
- Install/run OpenMedic as a Python CLI.
- Provide `--help`, version output, meaningful exit codes, readable errors, and `--json` or equivalent structured output for key commands.
- CLI calls reusable services; business logic must not live only in CLI command handlers.

**FR-002: Local ingestion**
- Accept a log file, stdin, or a versioned `FailureEvent` fixture.
- Validate input and produce a useful error for malformed data.
- Redact likely secrets before persistence/reporting.

**FR-003: Normalization and fingerprints**
- Normalize known volatile values (timestamps, temporary paths, hashes, ports) without destroying evidence.
- Preserve raw logs separately from normalized text where appropriate.
- Produce stable fingerprints for recurrence tracking.

**FR-004: Deterministic diagnosis**
- Support at minimum: dependency/import errors, syntax/import errors, test assertion failures, build/configuration errors, and unknown failures.
- Return probable cause, evidence quotes/line references, recommended next action, confidence, risk level, limitations, and human-review requirement.
- Unknown or ambiguous cases remain unknown; do not invent root causes.

**FR-005: Incident persistence**
- Record incidents, diagnosis results, remediation attempts, validation runs, timestamps, and state transitions.
- Use SQLite as the default durable local store. In-memory/fixture storage may exist for tests.
- Schema changes must be versioned/migrated safely.

**FR-006: Validation**
- Run configured project checks through a controlled runner.
- Capture command identity, exit code, stdout/stderr excerpts, duration, and which checks were executed.
- Missing, skipped, timed-out, errored, or non-zero checks do not count as success.

**FR-007: Honest reporting**
- Show diagnosis, supporting evidence, limitations, action proposal, safety decision, and validation outcome.
- Distinguish suggested, attempted, rejected, failed, and validated fixes.
- Never mark an incident recovered unless required validation passed for the exact candidate patch.

**FR-008: Offline deterministic path**
- Local ingestion, deterministic diagnosis, persistence, and reporting must work without a model API key and without network access after installation.

### P1 — Real integrations and controlled repair

**FR-009: GitHub Actions ingestion**
- Support a least-privilege GitHub token.
- Retrieve workflow run, job, failed step, commit SHA, and relevant logs.
- Support workflow-run event/webhook and/or polling; do not make both mandatory if one reliable approach is implemented first.
- Handle duplicate ingestion idempotently.

**FR-010: Provider abstraction**
- Define a stable provider protocol and configurable adapters.
- Start with a generic OpenAI-compatible endpoint and a local endpoint such as Ollama only if repository/dependency constraints support it.
- Provider outage, invalid output, rate limits, or missing credentials must fall back to deterministic results.
- Do not imply a free tier is unlimited or guaranteed.

**FR-011: Remediation proposals**
- Start with explicit playbooks for narrow, understood failure classes.
- Generate a diff/patch proposal and explain its rationale.
- Classify risk using documented rules.
- Require confirmation for risky or ambiguous operations.

**FR-012: Isolated patch validation**
- Apply candidate changes only in a disposable worktree/container or equivalently controlled workspace.
- Execute only configured/allowlisted checks with CPU, memory, process, network, and time controls appropriate to the runner.
- Preserve the original workspace.
- Record the exact patch identity and validation evidence.

**FR-013: GitHub reporting**
- Provide a diagnosis comment/report for the originating run.
- Later support a reviewable branch/PR only after validation. Never auto-merge.
- Clearly separate report-only behavior from write-enabled permissions.

### P2 — Intelligence and interface expansion

**FR-014: Recurrence intelligence**
- Track first seen, last seen, count, and prior outcomes for normalized fingerprints.

**FR-015: Cascade grouping**
- Group correlated failures using shared signatures, dependencies, workflow stages, and temporal evidence. Explain the evidence and uncertainty; do not claim causal proof from correlation alone.

**FR-016: Benchmarking**
- Maintain seeded failures and a repeatable benchmark for diagnosis accuracy, false-recovery count, validation correctness, time-to-report, deterministic coverage, and optional provider usage/cost.

**FR-017: Optional API/dashboard**
- Expose a versioned API and simple incident-history dashboard after the core workflow is stable.
- API/dashboard must call the same application services as the CLI.
- The API must not become a prerequisite for local CLI operation.

**FR-018: Additional CI adapters**
- Keep provider-specific logic behind interfaces so other CI providers can be added later. Build a second adapter only when the GitHub Actions path is stable.

## 8. Primary user journey

1. Developer runs OpenMedic against a local log/fixture or selects a failed CI run.
2. OpenMedic validates and normalizes the input.
3. It creates or deduplicates an incident.
4. Deterministic diagnosis runs first.
5. An optional configured model may enrich explanation or assist with an unknown failure, but cannot override evidence or safety rules.
6. OpenMedic prints a structured diagnosis and action proposal.
7. If repair is enabled and the action is allowed, OpenMedic creates a candidate patch in an isolated workspace.
8. Configured checks run against the exact candidate.
9. OpenMedic reports recovered only if all required checks pass; otherwise it reports failure or human review.
10. The incident and audit history remain inspectable.

## 9. Success metrics

Track measurements rather than pre-claiming targets:
- Diagnosis accuracy on labelled fixtures.
- Evidence quote correctness.
- False recovery count (required target: zero).
- Validation correctness and reproducibility.
- Percentage of cases handled without an LLM.
- Repair success rate by failure class.
- Human-review precision and recall where labels exist.
- Median time from ingestion to diagnosis.
- Model calls/tokens/cost per incident when a provider is used.
- Integration reliability and duplicate-event rate.

## 10. Product constraints

- The official hackathon focus is CI/CD failure analysis and recovery. Keep implementation and demo aligned to CI/CD; do not turn OpenMedic into an unrelated general coding agent.
- Build the CLI/core before a polished UI.
- Keep the repository's existing team contracts and useful code unless inspection proves they need a deliberate, documented change.
- Do not claim a feature exists until implemented and tested.
