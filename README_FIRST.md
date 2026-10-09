# OpenMedic — Start Here

This package is the implementation baseline for OpenMedic. Copy the contents into the root of your `OpenMedic/` project folder.

## Locked product direction

- Project name: **OpenMedic**; suggested repository/package name: `openmedic`.
- Product: open-source, local-first CI/CD failure diagnosis and safe recovery assistant.
- Interface strategy: **CLI first**. The engine must be reusable independently of the CLI.
- Primary integration: GitHub Actions, while keeping adapters possible for other CI providers later.
- AI policy: deterministic diagnosis must work without an AI provider. Model APIs and local models are optional adapters, not mandatory dependencies.
- Delivery strategy: implement complete working capabilities in dependency order; UI polish comes last.
- Hosting: usable locally without hosting; GitHub Actions integration next; optional self-hosted API/dashboard later.
- Safety: never report recovery without actual successful validation. No blind model-generated shell execution, auto-merge, or production deployment.

## Files

- `docs/PRD.md` — product requirements and scope.
- `docs/TRD.md` — technical requirements and implementation constraints.
- `docs/ARCHITECTURE.md` — component boundaries, data flow, trust boundaries.
- `docs/IMPLEMENTATION_ROADMAP.md` — milestone sequence and acceptance gates.
- `docs/API_CONTRACTS.md` — shared event, diagnosis, validation, and incident contracts.
- `docs/SECURITY.md` — security model and safety requirements.
- `docs/DECISIONS.md` — locked decisions and rationale.
- `OPENCODE_BOOTSTRAP.md` — exact initial instructions for OpenCode.
- `AGENTS.md` — durable repository-level instructions. Use OpenCode `/init` to inspect the repository and generate/update this file, then reconcile it with the product rules here.

## Important

These are specifications, not evidence that features already exist. OpenCode must inspect the current repository and team work before editing. It must not claim tests pass unless it actually runs them and records the results.
