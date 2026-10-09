# OpenMedic — Technical Requirements Document (TRD)

**Version:** 2.0  
**Status:** Implementation baseline  
**Date:** 2026-10-09

## 1. Technical objectives

Build a modular Python application that can run locally as a CLI, integrate with GitHub Actions, and later expose an optional API/UI without duplicating business logic. It must operate deterministically without an AI provider and enforce safe boundaries around repository changes and validation.

## 2. Technology baseline

Use these defaults unless repository inspection reveals a strong reason to retain an existing choice. Any deviation must be recorded in `docs/DECISIONS.md`.

- Python 3.11+ (prefer the version already standardized in the repo; otherwise Python 3.12).
- `pyproject.toml` for package metadata, dependency groups, tooling, and CLI entry point.
- Typer or Click for CLI, choosing one and avoiding redundant CLI frameworks.
- Pydantic for versioned input/output contracts if already used by the team.
- SQLite for durable local incident history; use the existing persistence layer if sound.
- pytest for tests.
- Ruff for linting and formatting.
- FastAPI only for the optional API/webhook service; it must not be required by CLI-only installs.
- GitHub API client or a small typed HTTP adapter, selected based on existing code and dependency footprint.
- Docker for stronger validation isolation when available; provide a clearly documented constrained local subprocess/venv mode only where safe and explicitly configured.
- Model providers are optional extras/adapters, not mandatory core dependencies.

Do not add a large framework or dependency without explaining why it is needed.

## 3. Architectural layers

1. **CLI/interface layer** — parse arguments, display output, map application outcomes to exit codes.
2. **Application services** — orchestrate use cases such as ingest, diagnose, repair, validate, inspect incidents.
3. **Domain/contracts** — schemas, enums, lifecycle rules, policies, domain errors.
4. **Ingestion adapters** — local log, stdin, fixture, GitHub Actions.
5. **Forensics** — normalization, line indexing, pattern detection, fingerprints.
6. **Diagnosis engine** — deterministic rules, evidence construction, optional AI enrichment.
7. **Provider adapters** — optional model provider protocol and concrete adapters.
8. **Remediation engine** — playbooks, patch generation, diff review, risk scoring.
9. **Execution/validation runner** — isolated candidate workspace and configured checks.
10. **Persistence** — SQLite repositories and schema migrations.
11. **Reporting** — terminal output, JSON, GitHub report/PR, optional API/UI.
12. **Observability/audit** — structured logs, timing, provider usage, state transitions.

No layer should reach around another layer to access its internals. Provider-specific and CI-specific logic must not leak into domain models.

## 4. Shared contracts: preserve and reconcile

The existing team contracts are the starting source of truth. Inspect actual implementation and member specs before changing names or fields. Do not create parallel schemas.

### `FailureEvent`
Existing agreed fields:
- `schema_version`
- `incident_id`
- `repository`
- `commit_sha`
- `workflow_name`
- `run_id`
- `failed_step`
- `failure_type`
- `logs`
- `timestamp`

Known failure types:
- `dependency_error`
- `syntax_or_import_error`
- `test_failure`
- `build_or_config_error`
- `unknown`

Timestamps must be timezone-aware. Keep logs sufficient to validate quoted evidence. Ingestion should be idempotent for duplicate run/step events.

### `DiagnosisResult`
Existing agreed fields:
- `schema_version`
- `incident_id`
- `failure_type`
- `probable_cause`
- `evidence[]` with `source`, `quote`, and `explanation`
- `confidence` in `[0, 1]`
- `recommended_action`
- `risk_level`
- `requires_human_review`
- `limitations`

Confidence is not proof of fix success. If source evidence cannot be quoted, explicitly mark inference and limitations. Validate quotes against the originating event where feasible.

### `ValidationResult`
Existing agreed fields:
- `incident_id`
- `passed`
- `checks_executed`
- `failed_checks`
- `summary`
- timestamp(s)
- optional execution metadata such as sandbox/run ID, exit code, and log excerpt.

Contract invariant: `passed=True` is invalid unless required checks actually ran and succeeded. Missing or incomplete validation is not success.

### `IncidentRecord`
Must connect the event, diagnosis, remediation attempts, validation results, lifecycle state, timestamps, and audit/transition history.

### Contract evolution
- Keep schema versioning explicit.
- Add backward-compatible optional fields where possible.
- For breaking changes, bump the version, provide migration/compatibility tests, and update all consumers in one coordinated change.
- Keep API and CLI serialization consistent.

## 5. CLI requirements

Proposed initial command surface; adapt names only when needed for consistency with existing code:

```text
openmedic --help
openmedic --version
openmedic init
openmedic diagnose <log-file>
openmedic ingest <event.json>
openmedic incidents list
openmedic incidents show <incident-id>
openmedic providers list
openmedic providers test <provider>
openmedic repair <incident-id> --dry-run
openmedic repair <incident-id> --apply
openmedic validate <incident-id>
openmedic github run <run-id>
openmedic benchmark
```

Not every command must be implemented in the first milestone. Never expose a command that silently does something unsafe. Repair should default to dry-run/proposal mode until the explicit safety gate is satisfied.

CLI conventions:
- `--help` at every command level.
- Human-readable default output and JSON output for automation.
- Non-zero exit code for invalid input, failed validation, unavailable integration, and unresolved repair; document exit-code meanings.
- No secrets printed in logs or command output.
- Destructive/write-enabled operations must be explicit and previewable.
- Commands should work from a project directory without a running OpenMedic server.

## 6. Diagnosis design

Run deterministic diagnosis first. Rule outputs must include rule ID/version, evidence spans, and limitations where useful. Initial patterns include:
- Python `ModuleNotFoundError` / `ImportError`.
- Python `SyntaxError`.
- test assertion failures and test framework summaries.
- dependency resolver/install errors.
- build/configuration errors.
- unknown signatures.

Avoid treating every occurrence of a keyword as definitive; inspect surrounding lines and prioritize the most relevant failure location. Keep unknown as a valid result. Add labelled fixtures for every rule and negative/ambiguous examples.

Optional model adapter:
- Accepts normalized event plus bounded context.
- Returns a structured candidate diagnosis or explanation.
- Must not fabricate evidence; validate quotes/line references against input.
- Cannot override risk policy or validation state.
- Timeout, rate limit, malformed output, missing key, or network error must not break the deterministic path.
- Avoid sending secrets and unnecessary repository contents to external providers.

## 7. Provider abstraction

Define a small protocol around structured diagnosis/enrichment. Do not tie application services to a particular SDK.

Configuration must identify provider type, endpoint, model, credential source, timeouts, and optional privacy controls. Credentials must come from environment variables or a local secret mechanism, never committed configuration.

Support a providerless mode by default. Add local/hosted adapters incrementally, based on actual demand and testability. Do not advertise a provider as supported until a contract test passes. Provider quotas, availability, licensing, and local hardware requirements must be documented honestly.

## 8. Remediation and execution

- Start with playbooks for narrow, understood cases; no arbitrary model-authored shell commands.
- Generate a patch/diff and explain the intended change before application.
- Apply patches in a disposable git worktree or isolated container.
- Keep the original working tree untouched.
- Do not mount credentials, SSH agent sockets, Docker socket, or other privileged host resources into untrusted execution by default.
- Use allowlisted validation commands and enforce timeouts/resource limits.
- Capture exact candidate commit/diff hash and check results.
- Reject patches that delete/skip tests, weaken assertions, disable lint/security checks, or broadly suppress failures without explicit reviewed policy.
- High-risk/uncertain fixes require human approval.
- No auto-merge and no production deployment.

## 9. Lifecycle and state machine

Recommended states:
`received → diagnosing → diagnosed → remediation_pending → remediating → validating → recovered`

Alternative states:
`failed`, `requires_human_review`.

Transitions must be explicit, persisted, and tested. Retries create new attempts rather than overwriting history.

**Invariant:** `recovered` requires passing required validation for the exact candidate patch currently recorded. If a patch changes after validation, validation is stale and recovery must be revoked until rerun.

## 10. Persistence

SQLite is the default local database. Requirements:
- Transactional writes for state changes and audit events.
- Stable incident IDs.
- Idempotency keys for incoming CI events.
- Versioned migrations.
- No credentials or raw secret values stored in incident records.
- Retention/cleanup controls can be added without compromising audit integrity.
- JSON export/import for portability where practical.

## 11. GitHub Actions integration

- Begin with read-only ingestion and diagnosis permissions.
- Use least-privilege scopes and document setup.
- Verify webhook signatures if webhooks are used.
- Fetch only the required workflow/job/log data.
- Handle rate limits, pagination, deleted/expired logs, retries, and duplicate events.
- Make report-only mode the default.
- Separate read-only diagnostics from write-enabled comments/branches/PRs.
- Never merge or deploy automatically.

## 12. Optional API and UI

FastAPI and a minimal dashboard are later interfaces, not the center of the architecture. Reuse the same application services and contracts. Local CLI use must remain available without the API server. Protect write-enabled endpoints with authentication, validate inputs, rate-limit where exposed, and do not provide arbitrary command execution endpoints.

## 13. Test strategy

- Unit tests: contracts, normalization, fingerprint stability, rule matching, evidence verification, risk decisions, lifecycle transitions, secret redaction, provider fallback, timeouts.
- Integration tests: log/fixture → incident → diagnosis → persistence → validation → report.
- Safety tests: malformed model output, prompt injection in logs, secret-bearing logs, malicious patch, deleted tests, timeout, nonzero exit, unavailable Docker, stale validation.
- GitHub tests: mocked API responses, pagination, rate limiting, duplicate delivery, missing logs, permission errors.
- End-to-end seeded repo: passing case, known failures, repair proposal, validation success and validation failure.
- Benchmark labels and expected outcomes must be committed with fixtures.
- Run tests, Ruff lint, and formatting checks before claiming a milestone complete.

## 14. Packaging and deployment

1. **Local CLI:** primary distribution; install in a virtual environment or package manager.
2. **GitHub Actions:** reusable action/workflow or CI adapter; secrets scoped by repository and permissions.
3. **Self-hosted service:** optional API/webhook/dashboard for teams that need centralized operation.
4. **Container:** optional for repeatable service deployment and sandboxed validation.

Do not require a hosted OpenMedic account. Local use should not depend on a public OpenMedic service.

## 15. Repository layout guidance

Adapt to existing code and team ownership. A possible target:

```text
OpenMedic/
├── AGENTS.md
├── README.md
├── pyproject.toml
├── .env.example
├── docs/
│   ├── PRD.md
│   ├── TRD.md
│   ├── ARCHITECTURE.md
│   ├── IMPLEMENTATION_ROADMAP.md
│   ├── API_CONTRACTS.md
│   ├── SECURITY.md
│   └── DECISIONS.md
├── src/openmedic/
│   ├── cli/
│   ├── application/
│   ├── domain/
│   ├── ingestion/
│   ├── forensics/
│   ├── diagnosis/
│   ├── providers/
│   ├── remediation/
│   ├── validation/
│   ├── persistence/
│   ├── reporting/
│   └── api/              # optional dependency group
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── safety/
│   └── fixtures/
├── examples/
├── integrations/
│   └── github-actions/
└── scripts/
```

This is a target shape, not permission to blindly move or overwrite files. Inspect first and preserve existing team modules when they fit.
