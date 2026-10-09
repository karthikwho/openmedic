# OpenCode Bootstrap — Run This First

## Recommended workflow

1. Open the `OpenMedic/` directory as the OpenCode project root.
2. Ensure the specification files are present.
3. Run `/init` once. Let OpenCode inspect the repository and generate or update `AGENTS.md`.
4. Review the generated `AGENTS.md` against the locked product decisions. Keep repository-specific conventions discovered by `/init`, but retain all safety/product invariants from `docs/DECISIONS.md` and `docs/SECURITY.md`.
5. Then send the prompt below. Do not start implementation until the audit/alignment report is complete.

`/init` is useful for discovering repository conventions and creating persistent agent guidance. In a mostly empty folder it cannot infer much from code, so it should be used to inspect the actual existing project and then reconcile the generated instructions with these specifications. Do not let `/init` replace the PRD/TRD/architecture.

## Prompt to send after `/init`

You are the principal implementation agent for OpenMedic. Read `AGENTS.md` and every document under `docs/` before changing files.

Our goal is a working, open-source, CLI-first, local-first CI/CD failure diagnosis and safe-recovery tool. Deterministic diagnosis must work without an LLM; model providers are optional adapters. The CLI is the first interface. Optional API/dashboard comes later. Never claim recovery without actual successful validation for the exact candidate patch. Never execute arbitrary model-generated shell commands, expose secrets, auto-merge, or deploy to production.

### Phase 1 — Audit only; no destructive edits

1. Inspect `git status`, current branch, full repository tree, package metadata, tests, docs, contracts, team member briefs, and recent changes.
2. Identify what already works, what is incomplete, duplicated, inconsistent, or missing.
3. Run baseline tests/lint/type checks that are available. Record exact commands and results; distinguish pre-existing failures from anything caused by your work.
4. Compare current code and documents with the PRD, TRD, architecture, contracts, and roadmap.
5. Preserve all useful code and teammate-owned changes. Do not rewrite the repository from scratch.
6. Create/update `docs/IMPLEMENTATION_STATUS.md` containing:
   - repository inventory
   - current architecture
   - existing contract definitions and their source files
   - tests/checks run and results
   - feature status mapped to PRD/roadmap IDs
   - conflicts and risks
   - proposed minimal changes for Milestone 1
7. If any current docs contradict the locked specifications, propose exact changes and apply only documentation alignment that is safe and clearly supported. Do not silently discard information.
8. Stop after the audit report and present a concise summary before beginning code changes.

### Phase 2 — Implementation after audit

After the audit report is available, implement the roadmap one milestone at a time. Start with the earliest incomplete milestone. For each milestone:
- state its acceptance criteria
- inspect relevant files before editing
- implement the smallest coherent change
- add unit/integration/safety tests
- run tests, lint, formatting, and package checks relevant to the change
- inspect `git diff`
- update `docs/IMPLEMENTATION_STATUS.md`
- report exact evidence and blockers
- continue to the next milestone only when its exit gate passes

Do not pause for routine choices that are already decided in the documents. Ask only for genuinely blocking ambiguity, destructive actions, credentials, billing, or permission expansion. Never fabricate a test result or mark an incomplete feature as done.

### Initial task

Perform Phase 1 now. Audit the repository and report. Do not start broad implementation until the audit report is complete.
