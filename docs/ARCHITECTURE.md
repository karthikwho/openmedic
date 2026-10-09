# OpenMedic — System Architecture

## 1. Architectural rule

**Collect evidence → normalize → diagnose → propose a bounded action → enforce policy → validate in isolation → report honestly.**

The CLI is the first interface, not the application core. OpenMedic must run locally without a server. GitHub Actions is the first live CI integration. API and dashboard are optional later interfaces.

## 2. Context diagram

```mermaid
flowchart LR
    Dev[Developer] --> CLI[OpenMedic CLI]
    Repo[Git repository / local logs] --> Ingest[Ingestion adapters]
    CI[GitHub Actions] --> GH[GitHub adapter]
    GH --> Ingest
    CLI --> App[Application services]
    Ingest --> App
    App --> Domain[Contracts and lifecycle]
    App --> Forensics[Normalization and fingerprints]
    Forensics --> Diagnosis[Deterministic diagnosis]
    Diagnosis --> Provider[Optional AI provider]
    Diagnosis --> Policy[Safety and risk policy]
    Provider --> Policy
    Policy --> Repair[Bounded remediation engine]
    Repair --> Sandbox[Disposable validation runner]
    Sandbox --> Validation[Validation result]
    App --> Store[(SQLite incident store)]
    Validation --> Store
    Store --> Report[CLI / JSON report]
    Report --> Dev
    App -. later .-> API[Optional API and dashboard]
```

## 3. Module boundaries

- **CLI:** user interaction, argument validation, output formatting, exit codes.
- **Application services:** use-case orchestration. Must be callable by CLI, API, and CI adapters.
- **Domain/contracts:** schemas, enums, lifecycle invariants, errors, safety policy interfaces.
- **Ingestion:** parse log files, stdin, fixtures, and CI run metadata into common events.
- **Forensics:** normalize volatile log content, preserve raw evidence, generate fingerprints.
- **Diagnosis:** deterministic rules and evidence selection; optional AI enrichment.
- **Provider adapters:** translate provider-specific request/response formats into the internal protocol.
- **Remediation:** playbook selection, diff generation, patch validation, risk evaluation.
- **Validation runner:** execute allowlisted checks against a disposable candidate.
- **Persistence:** SQLite repositories and migrations.
- **Reporting:** terminal and JSON reports; later GitHub comments/PRs and UI.
- **Optional API:** thin transport layer over application services.

## 4. Main sequence

```mermaid
sequenceDiagram
    participant U as Developer/CI
    participant I as Ingestion
    participant A as Application service
    participant F as Forensics
    participant D as Diagnosis
    participant P as Safety policy
    participant R as Repair engine
    participant V as Validation runner
    participant DB as SQLite
    participant O as Reporter

    U->>I: Log/event/run metadata
    I->>A: Validated FailureEvent
    A->>DB: Persist incident (idempotent)
    A->>F: Normalize and fingerprint
    F-->>A: Normalized evidence
    A->>D: Diagnose deterministically
    opt Provider configured and useful
        D->>D: Request optional enrichment
    end
    D-->>A: DiagnosisResult + evidence
    A->>DB: Persist diagnosis/audit
    A->>P: Evaluate proposed action
    P-->>A: Allow / dry-run / human review / reject
    opt Approved bounded repair
        A->>R: Prepare candidate patch
        R-->>A: Patch + candidate identity
        A->>V: Validate in disposable workspace
        V-->>A: Actual check results
        A->>DB: Persist attempt and validation
    end
    A->>O: Build evidence-based report
    O-->>U: Result + exit status
```

## 5. Deployment modes

### Mode A — Local CLI (first)
- Runs on the developer's machine.
- Local SQLite history.
- Log/fixture ingestion and deterministic diagnosis work offline.
- No public endpoint or OpenMedic account required.

### Mode B — GitHub Actions integration
- Runs as a workflow/action or connects to GitHub Actions using a scoped token.
- Read-only diagnosis is the initial integration mode.
- Optional report/comment/PR capabilities require separate explicit permissions.
- Can run per workflow or as a self-hosted process; choose the simplest reliable approach during implementation.

### Mode C — Self-hosted API/dashboard (later)
- Optional service for webhooks, team access, and UI.
- May run on a VPS, private server, or developer-owned machine.
- Webhooks require a reachable endpoint or a secure tunnel; polling/workflow-triggered operation may avoid inbound public webhooks.
- Service deployment must not become a dependency for the local CLI.

## 6. Trust boundaries

1. Logs, repository files, CI metadata, and issue/commit text are untrusted.
2. Model output is untrusted, even from a configured provider.
3. The remediation runner is a separate trust boundary with limited privileges and resources.
4. Secrets must not enter prompts, persistent incident records, reports, or test fixtures.
5. GitHub write permissions are separate from read permissions.
6. Human review is required for high-risk or ambiguous changes.

## 7. State machine

```mermaid
stateDiagram-v2
    [*] --> received
    received --> diagnosing
    diagnosing --> diagnosed
    diagnosing --> requires_human_review
    diagnosed --> remediation_pending
    diagnosed --> requires_human_review
    remediation_pending --> remediating
    remediation_pending --> requires_human_review
    remediating --> validating
    remediating --> failed
    validating --> recovered: all required checks pass
    validating --> failed: required check fails
    validating --> requires_human_review: incomplete or unsafe evidence
    failed --> diagnosing: explicit retry
```

Invariant: recovery is tied to a specific candidate patch and successful required checks. Any patch change invalidates prior validation.

## 8. Architectural decisions

- Keep CLI and optional API thin.
- Keep deterministic diagnosis independent of provider adapters.
- Keep CI-specific integrations behind adapter interfaces.
- Keep storage behind repositories/services.
- Keep repair execution separate from diagnosis and policy.
- Keep validation results immutable/auditable per attempt.
- Do not implement the dashboard before core end-to-end functionality is reliable.
