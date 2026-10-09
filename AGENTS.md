# OpenMedic — Agent Instructions

## Source of truth
Before implementation, read:
1. `docs/PRD.md`
2. `docs/TRD.md`
3. `docs/ARCHITECTURE.md`
4. `docs/IMPLEMENTATION_ROADMAP.md`
5. `docs/API_CONTRACTS.md`
6. `docs/SECURITY.md`
7. `docs/DECISIONS.md`

These documents define product scope, architecture, safety invariants, and milestone order. If repository evidence conflicts with them, report the discrepancy and propose a minimal reconciliation; do not silently ignore either source.

## Working style
- Inspect `git status`, current branch, project tree, package metadata, tests, and recent changes before editing.
- Preserve uncommitted changes and teammate-owned work.
- Implement in roadmap order and keep changes scoped to the active milestone.
- Prefer small, coherent, tested changes over a wholesale rewrite.
- Do not ask for approval for routine reversible work. Stop for destructive changes, credential/billing decisions, permission expansion, or materially ambiguous requirements.
- Do not claim a command/test/lint/build passed unless you ran it and observed success.
- At milestone end, summarize files changed, behavior implemented, exact commands run, results, remaining issues, and next milestone.

## Product invariants
- OpenMedic is CI/CD-focused, open-source, CLI-first, and local-first.
- Deterministic diagnosis works without an LLM.
- AI providers are optional adapters; do not couple the core to one vendor.
- Logs, repository contents, and model output are untrusted.
- Never execute arbitrary model-generated shell commands.
- Never expose secrets in prompts, logs, output, fixtures, or persistent incident records.
- Never report `recovered` without actual successful required validation for the exact candidate patch.
- Missing, skipped, timed-out, or failed required checks are not success.
- No auto-merge or production deployment.
- Keep UI polish behind core end-to-end functionality.

## Code quality
- Follow existing repository conventions where sound.
- Add/update tests for behavior and safety invariants.
- Use type annotations and structured domain errors.
- Keep CLI, application services, domain contracts, adapters, and persistence separated.
- Avoid needless dependencies and duplicated contract definitions.
- Update documentation and examples when behavior changes.
- Keep fixtures deterministic and tests independent of paid APIs/network access.

## Security
- Use least privilege.
- Use disposable workspaces for patch execution.
- Use allowlisted checks, timeouts, and resource limits.
- Require human review for uncertain/high-risk changes.
- Record audit evidence without secrets.
