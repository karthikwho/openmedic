# OpenMedic — Agent Instructions

OpenMedic is an open-source, local-first, CLI-first CI/CD failure diagnosis and safe-recovery tool.
Core flow: collect evidence → normalize → diagnose deterministically → propose a bounded action → enforce safety policy → validate in isolation → report honestly. Python.

## Read these first — the specs, in this order
1. `docs/PRD.md` — scope and functional requirements (FR-001..FR-018)
2. `docs/TRD.md` — technical constraints, layer list, contract fields, CLI surface, test strategy
3. `docs/ARCHITECTURE.md` — module boundaries, sequence/state diagrams, trust boundaries
4. `docs/IMPLEMENTATION_ROADMAP.md` — milestone order and exit gates
5. `docs/API_CONTRACTS.md` — exact field names, enums, lifecycle invariants
6. `docs/SECURITY.md` — mandatory security rules
7. `docs/DECISIONS.md` — locked decisions D-001..D-012

If repository evidence conflicts with these, report the discrepancy and propose a minimal reconciliation. Do not silently ignore either source.

## Current repo state: implementation exists, uncommitted
- Milestones 1–11 are implemented: `pyproject.toml`, `README.md`, `.env.example`, `.github/workflows/ci.yml`, `uv.lock`, 15 source layers under `src/openmedic/`, and the layered `tests/` suite all exist in this tree. **None of it is committed** — `git status` shows the new work as untracked. Do not claim a command, test, or check passes unless you ran it in this working tree.
- `docs/IMPLEMENTATION_STATUS.md` is the source of truth for what is verified. §11 records the gate commands and their exact outcomes (822 tests, `ruff check` clean, `ruff format --check` clean, wheel build, clean-room install), the exit-code matrix, the end-to-end CLI evidence, the ten defects found and fixed during verification, the benchmark completion pass (§11.11: rules, labels, enforced targets, CI gate), and the findings recorded for an owner decision — the **license** question they raised is now closed (MIT, see below; §11.12). Read it before planning or implementing anything.
- All 18 PRD functional requirements (FR-001..FR-018) have an implementation. "Implemented" here means code exists and the suite passes — it does not mean the feature is correct under every input; §11.6 and §11.8 record where that is still open.
- `README_FIRST.md` and `OPENCODE_BOOTSTRAP.md` are seed/bootstrap files — setup history, not ongoing guidance. Their durable content is captured here.
- Root files: `AGENTS.md`, `README_FIRST.md`, `OPENCODE_BOOTSTRAP.md`, `.gitignore`, plus `LICENSE`, `README.md`, `pyproject.toml`, `uv.lock`, `.env.example`, `docs/`, `src/`, `tests/`, `.github/`.
- **License: MIT**, decided by the project owner. The root `LICENSE` file (MIT text, `Copyright (c) 2026 karthikwho`) is authoritative, and `pyproject.toml` declares it as a PEP 639 SPDX `License-Expression`. Earlier notes in `README.md`, `docs/IMPLEMENTATION_ROADMAP.md`, and `docs/IMPLEMENTATION_STATUS.md` that say the license was unresolved or that no `LICENSE` file exists are **superseded by this decision** — the historical wording is kept where erasing it would misrepresent what was true at the time. Contribution guidelines (the rest of Milestone 12) remain open.

## Toolchain
- Target Python 3.11+ (TRD prefers 3.12); the CI matrix is 3.11/3.12/3.13. The interpreter in this environment is **3.14**, and only 3.14 has actually been executed here — never claim a version that has not been run. `uv` is the package manager and is installed; `pytest` and `ruff` are installed through it, so use `uv run pytest` and `uv run ruff`, never bare `pytest`/`ruff`.
- `pyproject.toml` is the single source for metadata, dependency groups, tooling, and the `openmedic` entry point.
- CLI: Typer **or** Click — pick one and never add a second CLI framework.
- Data/contracts: Pydantic models, SQLite for durable local incident history, pytest for tests, Ruff for lint **and** format.
- FastAPI belongs in an **optional** dependency group (later API) and must not be importable-required by CLI-only installs.
- `data/`, `logs/`, and `*.sqlite*` are gitignored — the local incident store lives there and must never be committed.

## Workflow gates
- **Work one milestone at a time, in roadmap order.** Do not jump ahead, and never start UI polish (D-010) while a core acceptance gate is failing.
- Before editing: check `git status`, branch, tree, and recent changes (D-011). Preserve uncommitted and teammate-owned work; prefer the smallest coherent change over a rewrite.
- Before declaring a milestone complete: run tests, Ruff lint, and format checks, then record the exact commands and outcomes in `docs/IMPLEMENTATION_STATUS.md`.
- Stop and ask only for destructive actions, credentials/billing, permission expansion, or genuinely ambiguous requirements. Do not ask about routine reversible implementation choices.

## Package boundaries
Target layout `src/openmedic/`: `cli`, `application`, `domain`, `ingestion`, `forensics`, `diagnosis`, `providers`, `remediation`, `validation`, `persistence`, `reporting`, `api` (optional).
- The CLI is a thin transport layer. Business logic lives in application services that the CLI and the later API both call — never in command handlers.
- No layer reaches around another layer. CI-specific and provider-specific logic must not leak into domain models.
- CLI conventions: `--help` at every level, human-readable output by default plus JSON for automation, non-zero exit codes for invalid input / failed validation / unavailable integration / unresolved repair (document what each means), and repair defaulting to **dry-run/proposal** mode.

## Contracts are locked
- `FailureEvent`, `DiagnosisResult`, `ValidationResult`, `IncidentRecord` field names and enums in `docs/API_CONTRACTS.md` are the starting source of truth. Do not create parallel schemas; inspect the existing implementation before renaming anything.
- Timestamps are timezone-aware and normalized to UTC.
- Lifecycle states: `received`, `diagnosing`, `diagnosed`, `remediation_pending`, `remediating`, `validating`, `recovered`, `failed`, `requires_human_review`. Transitions are explicit, persisted, and tested; retries add attempts rather than erasing history.
- A breaking contract change requires a `schema_version` bump, versioned migration/compatibility tests, and updating every consumer, fixture, and doc in one coordinated change.

## Safety invariants — non-negotiable
- `recovered` requires that all required checks actually ran and passed for the **exact** candidate patch currently recorded. Skipped, missing, timed-out, errored, or non-zero checks are not success. Any patch change invalidates prior validation until it is rerun.
- Logs, repository contents, CI metadata, filenames, commit messages, and model output are untrusted. Never execute model-generated shell commands. Prompt injection in logs must not change tool permissions or safety policy.
- No secrets in prompts, logs, reports, fixtures, or persisted incident records — redact before persistence and never send them to a model provider.
- No auto-merge, no production deployment. GitHub access starts read-only; comments/branches/PRs are separate explicit opt-ins.
- Apply patches only in a disposable worktree or container, using allowlisted checks with timeouts and resource limits, and never mounting credentials, the Docker socket, or an SSH agent into untrusted execution.
- Reject patches that delete tests, weaken assertions, disable checks, or suppress failures, unless a human explicitly reviews a documented exception.
- High-risk or ambiguous changes require human review.

## Product constraints
- CI/CD failure analysis and recovery only — do not pivot into a general coding agent (D-002).
- Deterministic diagnosis must work with no model credentials and no network access; providers are optional adapters, never mandatory dependencies.
- Local CLI use requires no OpenMedic server or account.

## Testing
- `tests/` is organised by layer (`tests/diagnosis/`, `tests/persistence/`, ...) with top-level
  `tests/test_*.py` for domain, forensics, and CLI. Cross-cutting safety invariants live in
  `tests/safety/` and run as their own CI job (`safety-gate`) so a regression is unmistakable.
- Use `uv run pytest <path>` for a focused run, `uv run pytest` for the full offline suite.
  Never use the developer's real database: `tests/conftest.py` supplies an isolated
  `tmp_path`-backed store, and every test that needs a DB gets a fresh one.
- Fixtures stay deterministic and committed. Tests must not need paid APIs or network access.
  GitHub tests use mocked HTTP transports (`httpx.MockTransport`) — never api.github.com.
- Unit: contracts, normalization, fingerprint stability, rule matching, evidence-quote
  verification, lifecycle transitions, secret redaction, provider fallback and timeout.
- Integration: fixture → incident → diagnosis → persistence → validation → report.
- Safety (must not be skipped): malicious/malformed model output, prompt injection in logs,
  secret-bearing logs, patch deleting tests, timeout, non-zero exit, unavailable Docker, stale
  patch identity. These are the invariants in `docs/SECURITY.md` expressed as executable tests.
- The `safety` and `docker` pytest markers exist. Docker tests auto-skip when Docker is absent;
  never mark a test `docker` unless it genuinely needs the daemon.
- Benchmark labels and expected outcomes are committed with the fixtures.
- Verify commands: `uv run ruff check .` and `uv run ruff format --check .` (CI enforces both).
