# OpenMedic — API and Domain Contracts

**Purpose:** shared source of truth for team modules, CLI serialization, optional API, and integrations. Before changing these definitions, inspect the existing implementation and member specifications. If code differs, document the discrepancy and reconcile deliberately rather than creating competing types.

## 1. Conventions

- Use explicit schema versions.
- All timestamps are timezone-aware; normalize to UTC for storage/serialization.
- Keep raw log evidence available for quote verification, while redacting secrets in persisted/displayed content where necessary.
- Treat external inputs and model outputs as untrusted.
- Errors must be structured and actionable.
- Idempotent ingestion must not create duplicate incidents for the same source event.

## 2. `FailureEvent`

Existing fields:
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

Failure type values:
- `dependency_error`
- `syntax_or_import_error`
- `test_failure`
- `build_or_config_error`
- `unknown`

Rules:
- `timestamp` must include timezone.
- `logs` must preserve enough original context to validate diagnosis evidence.
- If classification is uncertain, use `unknown`.
- Use a stable idempotency key based on source run/job/step or an explicit upstream event identifier.

## 3. `DiagnosisResult`

Existing fields:
- `schema_version`
- `incident_id`
- `failure_type`
- `probable_cause`
- `evidence[]`
- `confidence`
- `recommended_action`
- `risk_level`
- `requires_human_review`
- `limitations`

Each evidence item:
- `source`
- `quote`
- `explanation`

Rules:
- `confidence` is within `[0.0, 1.0]`; it is not the probability that a fix will work.
- Evidence quotes must be found in the source logs or clearly marked as inferred/no source.
- `limitations` must be populated, including when the model is unavailable or evidence is incomplete.
- Unknown or low-confidence cases must be escalated rather than guessed.
- A diagnosis cannot mark a fix as validated.

## 4. `ValidationResult`

Existing fields:
- `incident_id`
- `passed`
- `checks_executed`
- `failed_checks`
- `summary`
- timestamp(s)
- optional execution metadata: sandbox/run ID, exit code, duration, and bounded log excerpt.

Rules:
- `passed=true` only if all required checks actually ran and succeeded.
- Any required check skipped, missing, timed out, errored, or returned non-zero means validation has not passed.
- Record the candidate patch hash/identity. Validation for a different patch is stale.
- An empty `checks_executed` list cannot pass.

## 5. `IncidentRecord`

Must preserve:
- original event
- diagnosis result(s)
- remediation attempts and proposed/applied diffs
- validation result(s)
- lifecycle state
- created/updated timestamps
- transition/audit history
- source and idempotency metadata

Suggested states:
`received`, `diagnosing`, `diagnosed`, `remediation_pending`, `remediating`, `validating`, `recovered`, `failed`, `requires_human_review`.

## 6. Lifecycle invariants

1. Every state transition is validated and audited.
2. `recovered` requires a passing validation for the exact current patch.
3. A patch modification invalidates prior validation.
4. A retry adds an attempt; it does not erase prior evidence.
5. Provider failure cannot erase a valid deterministic diagnosis.
6. High-risk or uncertain remediation requires human review.
7. Duplicate events are idempotent.

## 7. Optional HTTP API

If/when FastAPI is added, keep it thin and versioned. Candidate endpoints:
- `GET /health`
- `POST /api/v1/incidents`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{incident_id}`
- `POST /api/v1/incidents/{incident_id}/diagnose`
- `POST /api/v1/incidents/{incident_id}/validate`

Do not expose a general-purpose endpoint that executes arbitrary request-supplied shell commands. Any write-enabled route must have authentication, explicit authorization, validation, audit logging, and safe defaults.

## 8. Compatibility

- Preserve existing field names and enum values unless a deliberate versioned change is approved.
- Update producer, consumer, fixtures, docs, and tests together.
- Keep example payloads valid against the actual schema.
- Avoid adding provider-specific fields to shared domain contracts unless they are truly domain-level.
