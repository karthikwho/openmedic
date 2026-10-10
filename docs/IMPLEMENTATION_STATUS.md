# OpenMedic — Implementation Status

**Document type:** Milestone 0 repository audit and alignment artifact
**Date of audit:** 2026-10-09
**Roadmap milestone covered:** Milestone 0 — Repository audit and alignment
**Status:** Milestone 0 complete (see acceptance checklist for the one caveat)

This file records verified facts only. It is not a claim that any feature exists. Where a
specification and the repository disagree, the disagreement is listed in
[section 4](#4-confirmed-gaps-between-specification-and-implementation).

---

## 1. Repository inventory

Tracked files, from `git ls-files`:

```
.gitignore
AGENTS.md
OPENCODE_BOOTSTRAP.md
README_FIRST.md
docs/API_CONTRACTS.md
docs/ARCHITECTURE.md
docs/DECISIONS.md
docs/IMPLEMENTATION_ROADMAP.md
docs/PRD.md
docs/SECURITY.md
docs/TRD.md
```

| Path | Kind | Role |
| --- | --- | --- |
| `docs/PRD.md` | Spec | Product requirements FR-001..FR-018 |
| `docs/TRD.md` | Spec | Technical constraints, layers, contracts, CLI surface |
| `docs/ARCHITECTURE.md` | Spec | Module boundaries, sequence/state diagrams, trust boundaries |
| `docs/IMPLEMENTATION_ROADMAP.md` | Spec | Milestone sequence and exit gates |
| `docs/API_CONTRACTS.md` | Spec | Locked contract fields, enums, lifecycle invariants |
| `docs/SECURITY.md` | Spec | Mandatory security rules |
| `docs/DECISIONS.md` | Spec | Locked decisions D-001..D-012 |
| `README_FIRST.md` | Seed | Copy-in baseline / locked product direction summary |
| `OPENCODE_BOOTSTRAP.md` | Seed | One-time setup + audit instructions |
| `AGENTS.md` | Instructions | Durable agent instructions (updated this milestone) |
| `docs/IMPLEMENTATION_STATUS.md` | Audit | This document (created this milestone) |

### No implementation exists

There is **no `pyproject.toml`, no `README.md`, no `src/`, no `tests/`, no `examples/`, no
`integrations/`, no `scripts/`, no `.github/`, and no `opencode.json`**. Every directory listed
in TRD §15 as a target shape is absent.

- Existing implementation modules: **none**
- Duplicated modules: **none**
- Incomplete work: **none** (nothing has been started)
- Ownership boundaries: **not yet established** — no code or team-member briefs exist to infer
  them from
- CI workflows: **none** (`.github/` does not exist)
- Pre-commit hooks, task runner (`Makefile`/`justfile`/`Taskfile`): **none**

The repository is a specification baseline. `README_FIRST.md` states this explicitly: "These are
specifications, not evidence that features already exist."

### Git state

- Branch: `main` (only branch), tracking `origin/main`
- Commits: 1 — `b402e35 docs: establish OpenMedic project foundation`
- Working tree at start of audit: clean
- Working tree at end of audit: `AGENTS.md` modified, `docs/IMPLEMENTATION_STATUS.md` added
  (this file). No files deleted or renamed.

---

## 2. Available tools and exact versions

Verified by running each command:

| Tool | Exact version | Status |
| --- | --- | --- |
| `python3` | Python 3.14.7 | Available |
| `uv` | 0.12.16 (761ff1379 2026-09-17 x86_64-unknown-linux) | Available |
| `git` | 2.55.0 | Available |
| `gh` (GitHub CLI) | 2.101.0 (2026-09-15) | Available |
| `make` | GNU Make 4.4.1 | Available |
| `pytest` | — | **Not installed** |
| `ruff` | — | **Not installed** |
| `pipx` | — | Not installed |
| `poetry` | — | Not installed |
| `docker` | — | Not installed |

Immediate consequences:

1. **No Python test or lint tooling exists.** Neither `pytest` nor `ruff` can run, so no baseline
   test/lint result can be produced until tooling is configured. `uv` is the available path to
   configure it.
2. **No Docker.** The validation runner's strongest isolation mode (Milestone 6) cannot be
   exercised here; the constrained local fallback mode described in TRD §2 is therefore likely
   to be the first implemented mode, not the last.
3. **Local Python is 3.14.7**, one minor above the TRD-preferred 3.12. A `pyproject.toml`
   created for Milestone 1 must pin a supported range rather than assume the ambient interpreter.
4. `gh` is present but has no configured credentials checked in this audit; no GitHub API call
   was attempted.

---

## 3. Baseline test and lint report

Required by the roadmap: "Run baseline tests/lint without changing code; record failures
separately from new failures."

| Command | Result | Interpretation |
| --- | --- | --- |
| `pytest` | `pytest: command not found`, exit 127 | Pre-existing: pytest is not installed |
| `ruff check .` | `ruff: command not found`, exit 127 | Pre-existing: ruff is not installed |
| `python3 -c "import openmedic; print(openmedic.__file__)"` | `ModuleNotFoundError`, exit 1 | Pre-existing: no package exists |

- Tests collected: **0** — no `tests/` directory and no test files exist.
- Lint findings: **0 files checked** — no source files exist.
- Pre-existing failures vs. new failures: **all three results are pre-existing**. None are
  attributable to this milestone, which changed no Python source (there is none).
- **No test or lint pass is claimed.** The honest statement is that there was nothing to run and
  no runner available.

---

## 4. Confirmed gaps between specification and implementation

All 18 PRD functional requirements are unimplemented. The table below is the gap list as it
stands after Milestone 0.

| Requirement | Spec source | State |
| --- | --- | --- |
| FR-001 CLI foundation | PRD §7 P0 | Not started |
| FR-002 Local ingestion | PRD §7 P0 | Not started |
| FR-003 Normalization and fingerprints | PRD §7 P0 | Not started |
| FR-004 Deterministic diagnosis | PRD §7 P0 | Not started |
| FR-005 Incident persistence | PRD §7 P0 | Not started |
| FR-006 Validation | PRD §7 P0 | Not started |
| FR-007 Honest reporting | PRD §7 P0 | Not started |
| FR-008 Offline deterministic path | PRD §7 P0 | Not started |
| FR-009 GitHub Actions ingestion | PRD §7 P1 | Not started |
| FR-010 Provider abstraction | PRD §7 P1 | Not started |
| FR-011 Remediation proposals | PRD §7 P1 | Not started |
| FR-012 Isolated patch validation | PRD §7 P1 | Not started |
| FR-013 GitHub reporting | PRD §7 P1 | Not started |
| FR-014 Recurrence intelligence | PRD §7 P2 | Not started |
| FR-015 Cascade grouping | PRD §7 P2 | Not started |
| FR-016 Benchmarking | PRD §7 P2 | Not started |
| FR-017 Optional API/dashboard | PRD §7 P2 | Not started |
| FR-018 Additional CI adapters | PRD §7 P2 | Not started |

Additional structural gaps:

- **Contract types are specified but not implemented.** `FailureEvent`, `DiagnosisResult`,
  `ValidationResult`, and `IncidentRecord` exist only as field lists in `docs/API_CONTRACTS.md`
  and TRD §4. No Pydantic models, no schema versions in code, no serialization.
- **Lifecycle state machine is specified but not implemented.** The nine states exist in prose and
  a Mermaid diagram only; there is no transition table, no persistence, no audit trail.
- **`docs/IMPLEMENTATION_STATUS.md`** did not exist before this milestone (created here).
- **`README.md`** is absent, so there are no install or usage instructions (Milestone 12 item,
  but worth noting as a gap now).
- **`.env.example`** is referenced by the TRD §15 target layout and implied by SECURITY.md's
  credential rules; it does not exist. `.gitignore` already anticipates it via `!.env.example`.
- **No license.** Milestone 12 requires one "after confirming the intended license with project
  owners." Unresolved.
  *Superseded:* the owner has since chosen **MIT**; the root `LICENSE` file exists and
  `pyproject.toml` declares it (§11.12).

---

## 5. Proposed technology choices that still require a decision

TRD §2 lists defaults and explicitly defers several choices. These are open and block Milestone 1
or shortly after.

| # | Decision | Options | Recommended | Blocks |
| --- | --- | --- | --- | --- |
| 1 | CLI framework | Typer / Click | **Typer** — typed options, automatic `--help` at every level, and `--json` output is easier to keep consistent. TRD permits either; the risk is adding both later. | Milestone 1 |
| 2 | Exact supported Python range | 3.11+ / 3.12 / 3.13 / 3.14 | **`>=3.11,<3.14`** with 3.12 as the tested baseline. Do not pin to the ambient 3.14 interpreter. | Milestone 1 |
| 3 | GitHub API client | PyGithub / `httpx` typed adapter / `requests` | **A small typed `httpx` adapter.** It is read-only usage, keeps dependency footprint low per TRD §2, and avoids a heavyweight SDK for a handful of endpoints. | Milestone 8 |
| 4 | Validation isolation mode order | Docker-first / local-subprocess-first | **Local constrained subprocess/venv mode first, Docker as an optional stronger mode.** Docker is not installed in the audit environment, so Docker-first would be unverifiable. | Milestone 6 |
| 5 | First provider adapter | Generic OpenAI-compatible / GitHub Models / Ollama | **Generic OpenAI-compatible HTTP endpoint.** PRD FR-010 names it first and it requires no new SDK. Ollama is local-only and not installed. | Milestone 5 |
| 6 | SQLite migration mechanism | Hand-rolled versioned migrations / Alembic | **Hand-rolled numbered migrations.** TRD requires versioned migrations but Alembic is a notable dependency for a single-file SQLite database. | Milestone 4 |
| 7 | Pydantic adoption | Adopt / avoid | **Adopt Pydantic v2.** TRD §2 nominates it and there is no existing code to conflict with. | Milestone 2 |
| 8 | Repository license | MIT / Apache-2.0 / other | **MIT** — decided by the project owner; the root `LICENSE` file is authoritative and `pyproject.toml` carries `license = "MIT"`. (At the time of the original audit: unresolved, awaiting owner input, blocking release only.) | Milestone 12 |

Decisions 1, 2, 6, and 7 are low-risk and reversible; they only need a pick so the scaffolding can
be created. Decisions 3, 4, and 5 are deferred to their milestones and can be revisited.
Decision 8 (license) has since been closed by the owner with MIT — see §11.12.

---

## 6. Risks and blockers

| Risk | Severity | Mitigation |
| --- | --- | --- |
| No Python tooling installed (no pytest/ruff), and no `pyproject.toml` to declare dev dependencies | High for velocity, low for correctness | Milestone 1 sets up the project and dev dependency group; `uv` is available to do it. Requires user approval before installing dependencies. |
| Docker absent, so the primary validation-isolation mode cannot be exercised | Medium | Implement the constrained local subprocess/venv mode first and gate Docker behind availability detection (Milestone 6 explicitly expects "unavailable Docker" to be handled). |
| Local interpreter 3.14 vs. target 3.11–3.12 | Low | Pin the supported range explicitly; run the test matrix on the minimum version. |
| Four contract schemas are only prose; two agents could implement them differently | Medium | Milestone 2 must implement `FailureEvent`, `DiagnosisResult`, `ValidationResult`, `IncidentRecord` from `docs/API_CONTRACTS.md` in a single coordinated change and lock them with round-trip tests before any consumer is built. |
| `recovered` is a safety-critical invariant that is easy to get subtly wrong (e.g. empty `checks_executed` passing) | High | Treat as an invariant from the first test, not a later hardening step. SECURITY.md's test list must be implemented as actual tests. |
| Roadmap pressure to build visible features (GitHub integration, UI) before the core loop works | Medium | Enforce roadmap order; D-010 keeps UI last. |
| No license, so the "open-source" claim is not yet actionable | Medium | **Resolved:** the owner chose MIT and the root `LICENSE` file exists (§11.12), so the claim is now actionable. |

**Current blockers requiring a user decision:** the technology choices in §5 (notably the
license), and approval to install development dependencies (`pytest`, `ruff`) before any test or
lint command can be run. No implementation work is blocked beyond that.
*Superseded:* the license is decided (MIT) and the development dependencies were approved and
installed; nothing in this paragraph is still outstanding (§11.12).

---

## 7. Milestone 0 acceptance checklist

| # | Roadmap item | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Inspect git status, branch, tree, package metadata, contracts, team documents, tests, recent changes | Complete | §1, §8 |
| 2 | Identify existing implementation, duplicated modules, incomplete work, ownership boundaries | Complete | §1 — none exist; ownership boundaries not yet established |
| 3 | Run baseline tests/lint without changing code; record failures separately from new failures | Complete (nothing to run) | §3 — `pytest` and `ruff` both exit 127, 0 tests collected; all results pre-existing |
| 4 | Reconcile current code with PRD/TRD/contracts | Complete | No code exists to reconcile. Specs are internally consistent — see §9. |
| 5 | Update docs and `AGENTS.md`; do not delete or replace working teammate code | Complete | `AGENTS.md` updated in place; no recursive files deleted or overwritten; no code existed to erase |
| 6 | Produce `docs/IMPLEMENTATION_STATUS.md` with current facts and commands/results | Complete | This file |

**Exit gate — "clear inventory, baseline test report, proposed file-level plan, no unapproved
destructive edits":**

- Clear inventory: **met** (§1)
- Baseline test report: **met with a caveat** — 0 tests collected because none exist and no runner
  is installed. This is a verified report of an empty test surface, not a passing run.
- Proposed file-level plan: **met** (§9)
- No unapproved destructive edits: **met** — one file added, one file modified, nothing deleted or
  renamed, no dependencies installed

**Overall: Milestone 0 is complete.** The caveat is recorded rather than glossed over: there was
no test or lint suite to execute, so "baseline tests pass" is not claimed anywhere in this
document.

---

## 8. Exact commands run during this audit

Run from `/home/atomic/Projects/OpenMedic` on 2026-10-09. Outputs are abbreviated where noted;
exit codes are as observed.

```bash
# Inventory
git ls-files
# → .gitignore AGENTS.md OPENCODE_BOOTSTRAP.md README_FIRST.md
#   docs/{API_CONTRACTS,ARCHITECTURE,DECISIONS,IMPLEMENTATION_ROADMAP,PRD,SECURITY,TRD}.md

git status --short      # → " M AGENTS.md"   exit 0
git branch -a           # → * main, remotes/origin/main
git log --oneline --all # → b402e35 docs: establish OpenMedic project foundation
find . -path ./.git -prune -o -type f -print | sort
# → the 11 tracked files only; no src/, tests/, .github/
ls -la                  # → AGENTS.md OPENCODE_BOOTSTRAP.md README_FIRST.md .gitignore docs/

# Toolchain
git --version             # → git version 2.55.0
python3 --version         # → Python 3.14.7
uv --version              # → uv 0.12.16 (761ff1379 2026-09-17 x86_64-unknown-linux)
gh --version              # → gh version 2.101.0 (2026-09-15)
make --version            # → GNU Make 4.4.1
command -v pytest pipx poetry docker ruff
# → not found for all five

# Baseline test/lint/import attempts
pytest                                   # → pytest: command not found, exit 127
ruff check .                             # → ruff: command not found, exit 127
python3 -c "import openmedic"            # → ModuleNotFoundError: openmedic, exit 1
```

No file was created, modified, or deleted by any command above except the explicit edit sessions
for `AGENTS.md` and this document. No dependency was installed. No network call was made.

---

## 9. Proposed file-level plan for the next milestone (Milestone 1)

Milestone 1 — Packaging and CLI skeleton. Exit gate: a clean environment can install and run
`openmedic --help` and `openmedic --version`.

Files to create (minimal, in dependency order):

1. `pyproject.toml` — project metadata, `requires-python` (decision #2), a single CLI framework
   (decision #1), a dev dependency group with `pytest` and `ruff`, tool config for Ruff, and the
   `openmedic = "openmedic.cli.app:main"` entry point.
2. `src/openmedic/__init__.py` — package docstring and `__version__` as the single source of the
   reported version.
3. `src/openmedic/cli/__init__.py`
4. `src/openmedic/cli/app.py` — the CLI skeleton. Must include `--help` at every level, redacted
   structured logging, documented exit codes, and JSON output support on key commands. No business
   logic in handlers.
5. `src/openmedic/cli/exit_codes.py` — the exit-code constants and their documented meanings
   (invalid input, failed validation, unavailable integration, unresolved repair).
6. `tests/unit/test_cli_help_and_version.py` — invokes `--help` and `--version` via the CLI
   runner and asserts exit code 0 plus a version string. Placed under `unit` to keep exactly the
   four directories `AGENTS.md` documents (`unit`, `integration`, `safety`, `fixtures`); a new
   top-level `tests/smoke/` would deviate from TRD §15 for no benefit.
7. `tests/conftest.py` — shared fixtures, including an isolated tmp-path-based config/DB location
   so tests never touch the developer's real `data/` directory.
8. `.env.example` — documents every credential the tool can read, with empty placeholder values.
   Must contain no real secret.
9. `README.md` — install, `--help`/`--version` smoke check, and a pointer to `docs/`.

Explicitly **not** in Milestone 1: contracts, ingestion, diagnosis, persistence, providers,
remediation, validation, GitHub integration, or API. `openmedic init` is a Milestone 1 item per
the roadmap and should be a config/validation command, not destructive scaffolding.

Consistency check for the plan: it imports nothing from `application`, `domain`, or any adapter
layer, so it cannot violate the TRD §3 layer rules or the thin-CLI rule. It also cannot create a
secret-handling path, so SECURITY.md's secret rules stay untouched at this stage.

---

## 10. Consistency verification performed

`AGENTS.md` and this document were checked against each spec. Findings:

| Check | Result |
| --- | --- |
| AGENTS.md doc reading order matches the seven spec files that exist | Consistent |
| TRD §15 target package subpackages vs. AGENTS.md package list | Consistent (12 subpackages) |
| AGENTS.md lifecycle state names vs. `API_CONTRACTS.md` §5 | Consistent (9 states, identical names) |
| AGENTS.md safety invariants vs. `SECURITY.md` and `DECISIONS.md` D-008/D-009 | Consistent |
| AGENTS.md toolchain claims vs. TRD §2 | Consistent |
| AGENTS.md test-layout and safety-case list vs. TRD §13 | Consistent |
| FR/decision ID ranges in AGENTS.md (FR-001..FR-018, D-001..D-012) vs. PRD and DECISIONS | Verified: both ranges exist in full |
| Specs internally consistent (no contradictions found between PRD, TRD, ARCHITECTURE, SECURITY, API_CONTRACTS) | No contradictions found |

Three corrections were made to `AGENTS.md` during this milestone so it does not contradict this
document:

1. Removed the claim that `docs/IMPLEMENTATION_STATUS.md` does not exist and that Milestone 0's
   exit gate is unmet — both are now false.
2. Replaced the "single commit / docs baseline" line, which would have gone stale as soon as work
   began, with a stable statement about repo state.
3. Added the concrete failure mode (`pytest`/`ruff` exit 127) and the requirement to get approval
   before installing dependencies, so the instruction is actionable rather than advisory.

No specification document was modified. The only changes in this milestone are `AGENTS.md`
(revised) and `docs/IMPLEMENTATION_STATUS.md` (created).

---

## 11. Implementation phase — verified evidence (Milestones 1–11)

Milestone 0 above recorded an empty repository. This section records what replaced it, with the
exact commands and their outcomes. Everything here was executed in this working tree; nothing is
inferred from the specifications.

### 11.1 What now exists

156 new files: `pyproject.toml`, `README.md`, `.env.example`, `.github/workflows/ci.yml`,
`uv.lock`, and 15 source layers under `src/openmedic/` (`cli`, `application`, `domain`,
`ingestion`, `forensics`, `diagnosis`, `providers`, `remediation`, `validation`, `persistence`,
`reporting`, `github`, `intelligence`, `api`, plus package inits). All 18 PRD functional
requirements have an implementation; the FR table in §4 of this document is superseded by the
evidence below.

The working tree is **not committed** — `git status` shows 8 untracked entries plus one modified
file (`AGENTS.md`). Per the standing instruction, nothing was committed, pushed, merged, or
deployed.

### 11.2 Gate commands and exact outcomes

Environment: Python 3.14.7, `uv` 0.12.16, pytest 9.1.1, ruff 0.16.10, Docker **not installed**.
Only Python 3.14 was executed here; 3.11–3.13 appear in the CI matrix but have not been run locally
and are not claimed.

Last re-run after the benchmark completion pass in §11.11. Every exit status below was
observed, not inferred:

```text
$ uv run pytest -q
822 passed in 6.43s
                                   exit 0

$ uv run ruff check .
All checks passed!
                                   exit 0

$ uv run ruff format --check .
114 files already formatted
                                   exit 0

$ uv build --out-dir /tmp/openmedic-final-dist
Successfully built openmedic-0.1.0.tar.gz
Successfully built openmedic-0.1.0-py3-none-any.whl
                                   exit 0

$ uv run pytest tests/safety -q
57 passed in 0.03s
                                   exit 0

$ uv run openmedic benchmark
OpenMedic diagnosis benchmark
  cases: 15
  type accuracy: 1.0000
  evidence verification rate: 1.0000
  rule id match rate: 1.0000
  false recovery count: 0
  mean confidence: 0.7420
  ...
  targets met
                                   exit 0
```

The test count moved 761 → 763 (defect J regression tests) → 822 (the rules, benchmark and
ingestion work in §11.11). Each number is what the command printed at the time; earlier
sections keep the count that applied to them.

### 11.3 Packaging and dependency isolation

Verified against a clean venv containing only the built wheel:

| Check | Outcome |
| --- | --- |
| `pip install openmedic-0.1.0-py3-none-any.whl` | exit 0 |
| `openmedic --version` → `0.1.0` | exit 0 |
| `import openmedic.cli.app` then assert no `fastapi` in `sys.modules` | `NONE` — CLI-only install is clean |
| `pip install '...[api]'` then re-check the CLI import path | still `NONE` — FastAPI stays optional |
| `from openmedic.api import create_app` with the `api` extra | builds, 11 routes |
| Installed wheel diagnosing a real log end-to-end | exit 0, `DEP-001 v1.0.0`, confidence 0.95 |

`git ls-files` shows no tracked `.db`, `.sqlite`, `data/`, `logs/`, or `.env` file. `.gitignore`
covers `*.db`, `*.sqlite`, `*.sqlite3`, `data/`, `logs/`, and `Thumbs.db`.

### 11.4 Documented exit codes — all reachable

Every code advertised by `openmedic --help` was exercised through the real entry point:

| Code | Meaning | Reproduced by |
| --- | --- | --- |
| 0 | success | `diagnose ci.log`, `ingest`, `repair` on an actionable incident |
| 2 | invalid command-line usage | `repair` with no `incident_id` |
| 3 | malformed or unknown input | `ingest bad.json`; `incidents show inc-doesnotexist` |
| 4 | required validation check did not pass | `validate` where `pytest` failed |
| 5 | integration unavailable | `github run` with no token; `providers test` unconfigured |
| 6 | unresolved repair | `validate` with no attempt; `repair` that cannot propose |
| 7 | requires human review | `repair` on an incident the diagnosis flagged for review |

`--help` exits 0 at every level: root, `init`, `diagnose`, `ingest`, `repair`, `validate`,
`benchmark`, `incidents`, `incidents list`, `incidents show`, `providers`, `providers list`,
`providers test`, `github`, `github run`.

### 11.5 End-to-end evidence

In a scratch directory containing `ci.log` (a `ModuleNotFoundError: requests` failure) and a
`requirements.txt`:

```text
openmedic init --json                 → created_database: true; Docker reported as
                                        "NOT a hardened sandbox"
openmedic ingest event.json           → state: diagnosing, exit 0
openmedic repair inc-9cd9de537af49f67 → proposal att-66be547e…, patch 45679c8b…,
                                        requirements.txt unchanged, exit 0,
                                        state now remediation_pending
openmedic validate inc-9cd9de537af49f67 → 2 checks executed under local-subprocess,
                                        pytest=failed → state failed, exit 4
```

The incident report for that run records `recovered: false`, `state_claims_recovery: false`,
`stale_validation: false`, `passed: false`, `required_not_success: ["pytest"]`,
`provider_used: false`, `redacted: true`, and `isolation_kind: local-subprocess` with the
"not a sandbox" limitation. The state history is append-only: three full
`failed → diagnosing → … → validating → failed` cycles are retained, none erased.

### 11.6 Defects found and fixed during verification

Verification was done by driving the real CLI, which surfaced ten defects that the unit suite
did not reach. Each is fixed and regression-tested.

| # | Defect | Effect before the fix |
| --- | --- | --- |
| A | `diagnose_stored` re-applied a state the record already held | `ContractError: diagnosed -> diagnosed` for every diagnosis not requiring review |
| B | `repair` requested `remediation_pending` after `record_attempt` had already walked to `remediating` | `ContractError` on every actionable repair |
| C | `record_attempt` landed at `remediating` for a patch that was only *proposed* | Dry runs claimed remediation had started |
| D | `_stage`/`validate` passed a pre-existing `TemporaryDirectory` to `disposable_worktree` | `openmedic validate` and `openmedic repair --apply` **always** crashed |
| E | `_proposal_for` built `FilePatch(path, before="", after="")` and never read the stored diff | Any patch that did get through would have written nothing |
| F | CLI `repair` passed `apply=dry_run` | **The default staged and ran checks; `--dry-run` did the opposite of its name** |
| G | `repair --apply` returned success when validation failed | A failed required check exited 0 |
| H | `repair`'s refusal branch returned success | Exit 7 was defined but unreachable; unresolved repairs read as success |
| I | `_default_cases_dir` used `parents[2]` | Bare `openmedic benchmark` failed with a wrong path |
| J | `Services._store` rebuilt a `RECEIVED` record and saved it over the stored incident | **Re-ingesting the same event erased the diagnosis, the attempts, the validations and every transition**, resetting a `failed` incident back to `diagnosing` |

D, F and J are the most serious: they made the entire post-proposal pipeline inoperable, inverted
the tool's core safety default, and destroyed the append-only history the product promises to keep.
None were caught because no test exercised `repair --apply`, `validate`, the CLI flag mapping, or a
duplicate arrival *after* progress end to end. Every row above now has at least one regression test
covering it, and the suite stands at 763 passed. Two of these were confirmed to fail when their fix
is reverted, so they pin the behaviour rather than the implementation:

* defect F: with `apply=dry_run` restored, the default `repair` exits 4, proving it staged a patch
  nobody asked for;
* defect J: with the old `_store` restored, both new tests fail — `remediation_pending` had become
  `diagnosing`, and `requires_human_review` had been put back into triage.

Defect E's fix is the largest: a unified diff is not self-contained (it carries changed regions
plus three context lines), so `parse_unified_diff(text, contents=...)` replays hunks onto the real
file content and then re-renders and compares — a diff that does not replay to itself is refused
rather than approximated, and the rebuild must reproduce the recorded `patch_hash`.

Defect J's fix sits in `Services._store`, not in `Repository.upsert_incident`. The repository method
is the write half of persistence — it must store whatever it is handed, which is how an in-memory
transition reaches the database — so it cannot also decide whether an incoming record is a duplicate
without breaking every state update. The ingestion boundary is the only place that knows whether an
event has already arrived, so it short-circuits there and returns the stored incident unchanged. A
`RECEIVED` record still gets its one missing transition, so an interrupted first ingest can finish
rather than strand a stuck row. `upsert_incident`'s docstring, which previously claimed an
idempotency it did not deliver for the same-ID case, was corrected to say what it actually does.

The pre-existing `test_duplicate_ingestion_is_idempotent` never caught this because it re-ingested
immediately, before there was any progress to lose; the two new tests ingest, diagnose, and propose
first. Their value is proven by reverting the fix, not by their passing.

### 11.7 Safety behaviour confirmed executable

Confirmed against the running CLI, not only in tests: prompt-injection text in logs is inert
(`benchmark` output and incident reports contain none of the injected strings, including under
secret-bearing logs); secrets in logs are redacted before persistence and before any report, with
the `redacted` flag set; a patch deleting tests or weakening assertions is refused by
`evaluate_patch_safety`; a failing required check blocks `recovered`; a patch changed after
validation is reported as stale rather than silently re-used; model output never reaches a shell;
`recovered` is only reachable through `apply_transition` with a passing `ValidationResult` bound to
the current patch hash.

### 11.8 Findings from the first verification pass — now resolved

The four benchmark findings recorded at the first verification pass are **closed**. Each is
documented with its evidence in §11.11; the original wording is summarised here so the
history stays readable.

1. **The benchmark corpus was calibrated for the wrong engine.** The production engine scored
   type accuracy `0.60` against a committed `type_accuracy_min` of `1.0`, and the corpus named
   rule IDs that did not exist in it (`py.module-not-found`, `ci.env-var-missing`, …).
   *Resolved:* the engine gained four signatures it genuinely lacked (§11.11.2), every expected
   label was audited by hand against `src/openmedic/diagnosis/rules.py`, and the rule-ID
   namespace was aligned to the production IDs. Type accuracy and rule-id match are now `1.0`.

2. **The committed benchmark targets were never applied.** `Services.benchmark()` ignored
   `expected.json`, so the command printed accuracy and exited `0` regardless.
   *Resolved:* targets are loaded, validated, cross-checked against the case labels, and
   enforced; a missed target exits `4` with the missed metric named.

3. **No CI benchmark step.** `.github/workflows/ci.yml` ran lint, format, the suite, the
   `api-optional` job and a build job — but not the benchmark.
   *Resolved:* a `benchmark` job runs the same command, and the build job installs the wheel
   into a clean venv and runs the packaged corpus from outside the checkout.

4. **The default corpus was not packaged.** `_default_cases_dir()` pointed into `tests/`.
   *Resolved:* the corpus is package data at `src/openmedic/intelligence/cases/`, so an
   installed wheel runs `openmedic benchmark` from any directory.

### 11.8.1 Still open — an owner decision

1. **License is still unresolved** (Milestone 12). No `LICENSE` file was created.
   *Superseded — closed.* The owner has chosen **MIT**. The root `LICENSE` file now exists
   and `pyproject.toml` declares `license = "MIT"`; the documentation that still said
   "unresolved" has been reconciled (§11.12).

### 11.9 Best next human action

Choose the license (Milestone 12) and commit the tree. The benchmark gate is now wired, so
the next milestone can be taken on with a failing diagnosis or safety regression caught by CI
rather than by inspection.

*Update:* the license has been chosen (MIT, §11.12); committing the tree is the human
action that remains.

---

### 11.10 Final verification pass

Re-run against the working tree as it stands, re-reading the files rather than trusting the
narrative above. Every exit status was observed.

**Gates.** `uv run pytest -q` → 763 passed, exit 0. `uv run ruff check .` → All checks passed!, exit
0. `uv run ruff format --check .` → 112 files already formatted, exit 0. `uv build --out-dir
/tmp/openmedic-final-dist` → wheel and sdist, exit 0. `uv run pytest tests/safety -q` → 57 passed,
exit 0.

**Tree and hygiene.** `git status --porcelain` shows 1 modified file (`AGENTS.md`) and 8 untracked
entries; HEAD is still `b402e35`, nothing committed. Of the 167 tracked-plus-would-be-added files,
none matches `*.db`, `*.sqlite`, `data/`, `logs/`, `.env`, `dist/`, `build/`, `*.egg-info`, `*.whl`
or `*.tar.gz`. No `dist/`, `build/` or `*.egg-info` directory exists inside the tree (build output
goes to `/tmp`). The only `.env`-shaped file is `.env.example`, which contains commented
placeholders only and is explicitly whitelisted in `.gitignore`. No `*.pem`, `*.key`, `id_rsa*`,
`id_ed25519*`, `*.p12` or `*.pfx` exists outside the ignored directories.

A secret-pattern sweep over all 167 files matched only **synthetic redaction-test probes**:
`ghp_bbbb…`, `ghp_16Z9…fsdfsdfsdf`, `ghp_0123456789abcdef…`, `sk-aaaa…`,
AWS's documented `AKIAIOSFODNN7EXAMPLE` placeholder, `github_pat_11ABCDEFG…` and `FAKEKEYBODY123`.
`src/` contains no token-shaped literal at all. These exist to prove redaction works; none is a real
credential.

**Recovery guard, checked independently.** A probe written fresh from `domain/contracts.py` and
`domain/lifecycle.py` (not from the repo's own test helpers) ran 12 assertions, 12 held, exit 0:

| Expectation | Result |
| --- | --- |
| Contract refuses `passed=True` with a failed required check | refused: `passed=True while required checks did not pass: ['pytest']` |
| Contract refuses `passed=True` with a skipped required check | refused |
| Failed validation cannot enter `recovered` | refused: `validation did not pass` |
| Empty check list cannot justify recovery | refused |
| Stale patch hash blocks recovery | refused: `validation is stale` |
| Patch changed after validation invalidates it | refused |
| Unbound validation cannot justify recovery | refused: `not bound to a candidate patch hash` |
| Empty `isolation_kind` cannot justify recovery | refused: `no recorded execution metadata` |
| Control: honest bound passing validation **is** accepted | entered `recovered` |
| Default policy has a required check | `pytest` required, `ruff` optional |
| Timeout is not success | `passed=False` |

The control case matters: the guard is not simply blocking every recovery. Note also that a
dishonest `passed=True` is made **unrepresentable** by a `model_validator` on the contract, so the
value is rejected at construction, before any lifecycle code sees it.

**Live CLI confirmation of the three invariants.** In a scratch directory with a
`ModuleNotFoundError` log and a `requirements.txt`:

* *Default repair is dry run* — `repair <id>` with no flag exited 0, the JSON payload contained **no
  `checks_executed` key**, `requirements.txt` was byte-identical before and after
  (`76f8bae4…af97`), and the state was `remediation_pending`, not `remediating`.
* *Failed validation cannot report recovery* — `repair <id> --apply` exited **4**, state `failed`,
  and `validate <id>` again exited 4. The incident report records `recovered: False`,
  `state_claims_recovery: False`, `validation.passed: False`, `required_not_success: ['pytest']`,
  `all_required_checks_passed: False`, `isolation_kind: local-subprocess`, and **no `recovered`
  transition anywhere in the history**. The source tree stayed byte-identical — only the disposable
  worktree was written.
* *Recovery is bound to the exact current patch hash* — `current_patch_hash ==
  validated_patch_hash` in the report, and the probe above refuses any mismatch.

**Defect J (duplicate-ingest erasure).** Reproduced before fixing: re-ingesting the identical
`event.json` took an incident from `failed` with 1 diagnosis, 1 attempt, 2 validations and 12
transitions down to `diagnosing` with 0/0/0 and **1** transition. After the fix, the same scenario
holds at `remediation_pending` with 1 diagnosis, 1 attempt and 3 transitions intact, incident count
still 1, and the re-ingest response now reports the true current state instead of a false
`diagnosing`. Both new regression tests were confirmed to **fail** when the fix is reverted.

**Packaging.** Clean venv, rebuilt wheel: install exit 0, `openmedic --version` → `0.1.0` exit 0,
`import openmedic.cli.app` loads **no** FastAPI module (asserted), and the installed entry point
diagnoses a real log end to end, exit 0, `DEP-001 v1.0.0`.

---

### 11.11 Benchmark completion pass

The four findings in §11.8 were closed in one pass. Nothing was made to pass by weakening a
target, lowering a threshold, or re-labeling a case to match the engine: the labels were audited,
the gaps they exposed in the engine were closed where the evidence supported it, and the target
mechanism was built so that this can never be true only by inspection again.

#### 11.11.1 Metrics, before and after

Measured by the same production command, `uv run openmedic benchmark`, over the same 15 committed
cases.

| Metric | Committed target | Before | After |
| --- | --- | --- | --- |
| `type_accuracy` | `≥ 1.0` | **0.6000** (9/15) | **1.0000** (15/15) |
| `evidence_verification_rate` | `≥ 1.0` | 1.0000 | 1.0000 |
| `rule_id_match_rate` | `≥ 1.0` (new) | not measured | **1.0000** (12/12 declared) |
| `false_recovery_count` | `≤ 0` | 0 | 0 |
| `mean_confidence` | `≥ 0.4` | 0.5660 | 0.7420 |
| Targets enforced | — | **no** (`exit 0` always) | **yes** (`exit 4` on a miss) |
| Default corpus from a wheel | — | no | yes |

Every one of the six misclassified cases was read and judged by hand before anything changed. All
six labels were already consistent with the committed `label_policy`; the engine was short of
capability, not the corpus short of accuracy. No label was altered to change a score.

#### 11.11.2 Engine changes, one per gap

| Case that failed | Root cause found in the engine | Change |
| --- | --- | --- |
| `docker-build-failure` | `_DOCKER_SOLVE_RE` required a bare `ERROR:`, but BuildKit prefixes its lines (`#3 ERROR:`, `3.412 ERROR:`) | Optional `_DOCKER_BUILDKIT_PREFIX`; a `_DOCKER_BUILDKIT_STEP_RE` match above the failure supplies step evidence |
| `npm-dependency-resolution` | Every npm regex required the legacy `npm ERR!`; npm v7+ prints `npm error` | Shared `_NPM_PREFIX` (`npm\s+(?:ERR!\|error)`) on all four npm regexes; `ERESOLVE could not resolve` added |
| `ci-env-var-missing` | `_CONFIG_ERROR_RE` did not cover "required environment variable X is not set" | New `_env_var_signal` in BUILD-001, capturing the variable name |
| `workflow-yaml-parse-error` | No rule matched `yaml: line N: …` or `Invalid workflow file: '…'` | New `_yaml_signal` in BUILD-001, quoting the parser's line and naming the file |
| `python-import-typo` | DEP-001 (0.95) beat SYN-001 for `cannot import name 'X' from 'Y'` even when `Y` is project source | `_CANNOT_IMPORT_NAME_RE` now captures the resolving path; a path outside `site-packages`/`dist-packages` means the module exists and the *code* is wrong, so DEP-001 declines and SYN-001 owns it |
| `pytest-collection-error` | DEP-001 (0.97) beat TEST-001 whenever pytest could not collect | `_pytest_collection_is_internal`: when the missing module's first dotted segment is the collecting file's own top-level package (`tests.helpers.fixtures` from `tests/test_smoke.py`), the suite never collected and TEST-001 owns it |

The two precedence changes are deliberately narrow, and both are decided by evidence in the log
rather than by guessing:

* A `cannot import name` error prints the resolving module's path **only when the module was
  found**. A path inside an installed environment is a version mismatch and stays a dependency
  problem (`python_import_no_symbol_installed.log`, DEP-001); a path in project source is a code
  defect (`python_import_no_symbol.log`, now SYN-001). No path, no claim — it stays DEP-001.
* A missing *third-party* package during collection is still DEP-001
  (`pytest_collection_import_error.log`, missing `requests`), because there the repair is an
  install. Only a project's own package landing at collection time moves to TEST-001.

Two guards keep the new rules from outvoting each other:

* BUILD-001's npm signal skips resolver-level codes (`ERESOLVE`, `E404`) and records a limitation
  saying why — an unsatisfiable dependency set is DEP-002's signature, and it must not be beaten by
  the build rule on the same line.
* Only `_DOCKER_SOLVE_RE` became BuildKit-tolerant. The pip regexes inside the same log stayed
  strict, so a pip resolver error *inside* a container build remains evidence for the build
  diagnosis rather than a competing dependency diagnosis.

**One characterization row changed, deliberately.** `python_import_no_symbol.log` moved from
`DEP-001` to `SYN-001` in `tests/diagnosis/test_engine.py`, with the reasoning recorded next to the
row. The fixture's module resolves at
`/home/runner/work/app/app/src/app/__init__.py` — project source — so the old reading implied the
repair was "declare `app` in `requirements.txt`", which is wrong. The SYN-001 playbook exists and
is reached either way; the playbooks cross-accept import failure types, so no remediation
capability was lost. The suite grew a fixture for the case that used to be conflated with it.

New fixtures and boundary tests: `docker_buildkit_failure`, `npm_eresolve_modern`,
`ci_environment_variable_missing`, `workflow_yaml_parse_error`, `python_import_no_symbol_installed`
and `pytest_collection_internal_package` in `tests/diagnosis/fixtures/`, plus
`tests/diagnosis/test_rule_boundaries.py`, which asserts the *negative* side of each boundary
against inline logs — a site-packages symbol error is still a dependency problem, a third-party
package missing at collection is still a dependency problem, a symbol error with no path claims
nothing, and a resolver code is never the build rule's.

#### 11.11.3 Ingestion hint aligned with the rules

`classify_log_text` filed `ModuleNotFoundError` / `No module named 'x'` under the syntax family, so
every missing-module diagnosis arrived with a limitation explaining that its own input disagreed
with it. The two patterns moved to the dependency family (an absent module is a manifest/environment
problem), one test row followed, and a new test asserts the hint and the diagnosis agree. The
engine's evidence-first override is unchanged; it is simply no longer needed for this common case.

#### 11.11.4 Targets are loaded, validated, cross-checked, and enforced

`src/openmedic/intelligence/benchmark.py` gained the enforcement half:

* `BenchmarkTargets` — the bar, read from `expected.json` beside the cases, never derived from the
  measured report.
* `check_targets` / `TargetCheck` / `TargetVerdict` — rates get a floor, counts get a ceiling, and
  every declared target appears in the verdict whether it passed or not.
* `load_targets` — rejects unknown target keys (a typo like `type_acuracy_min` cannot silently
  lower the bar), missing required targets, non-numeric values, negative values, and fractional
  counts.
* `validate_expected_matches_cases` — `expected.json` repeats each case's label, so divergence from
  the case files is now a hard error rather than a second, quieter source of truth: a case with no
  label, a label for a case that does not exist, and a mismatched type, rule id or confidence floor
  are all configuration errors.
* `BenchmarkRun` — one object carrying the report, the targets and the verdict. `Services.benchmark`
  returns it; the CLI prints it and exits **4** (`VALIDATION_FAILED`) naming the missed metrics when
  `passed` is false.

A new metric, `rule_id_match_rate`, is computed over the cases that *declare* an expected rule id
(honest unknowns declare none and are excluded rather than counted as matches), and the target
`rule_id_match_rate_min: 1.0` makes the hand-audited rule ids load-bearing instead of decorative.

Corpus integrity checks were not weakened: `evidence_verified` still verifies quotes against the
event log that was actually diagnosed, the false-recovery detector still scans for claim markers,
and the below-floor confidence limitation still fires per case.

#### 11.11.5 The corpus ships, and the labels were re-audited

`tests/intelligence/fixtures/cases/` moved to **`src/openmedic/intelligence/cases/`** as package
data — one copy, not two — and `_default_cases_dir()` now resolves it through
`openmedic.intelligence.default_cases_dir()`. Hatchling picks up the JSON automatically; the wheel
contains all 16 files and the sdist is the wheel's source, verified by building and installing it.

`expected.json` moved to schema `1.1.0` with a `label_policy` that states the two precedence rules
above explicitly, and every `expected_rule_id` was rewritten to the production rule that owns the
signature (`DEP-001`, `DEP-002`, `SYN-001`, `TEST-001`, `BUILD-001`, or `null` for an expected
unknown). Three case notes were extended with the evidence the decision rests on.

#### 11.11.6 CI

`ci.yml` gained a `benchmark` job (install, `uv run openmedic benchmark`) and a build step that
installs the wheel into a clean venv and runs the packaged corpus **from outside the checkout**. A
regression in the rules, the corpus, the targets, or the packaging now fails the workflow rather
than being a number in a report.

#### 11.11.7 Judge-facing demo

`scripts/demo.sh` runs six scenarios against the real CLI in a throwaway directory with its own
database: a supported failure diagnosed offline, an ambiguous log staying `unknown`, a dry-run
proposal leaving `git status` clean, `repair --apply` exiting `4` with `recovered: false`, the
benchmark meeting its targets, and the incident history. It exits non-zero if any scenario
misbehaves, so it is itself a check.

#### 11.11.8 Verification of this pass

Every command below was executed in the working tree; every exit status observed.

```text
$ uv run pytest -q                       → 822 passed, exit 0
$ uv run ruff check .                    → All checks passed!, exit 0
$ uv run ruff format --check .           → 114 files already formatted, exit 0
$ uv run pytest tests/safety -q          → 57 passed, exit 0
$ uv build --out-dir /tmp/openmedic-bench-dist
                                          → openmedic-0.1.0-py3-none-any.whl + sdist, exit 0
$ unzip -l <wheel> | grep cases          → 16 files (15 cases + expected.json)
$ (clean venv) pip install <wheel>
$ cd /tmp && openmedic benchmark         → 15 cases, accuracy 1.0000, evidence 1.0000,
                                            rule ids 1.0000, false recovery 0,
                                            mean confidence 0.7420, "targets met", exit 0
$ (clean venv) openmedic benchmark <corpus with a label the engine cannot meet>
                                          → [BAD] type_accuracy: 0 at least 1,
                                            TARGETS NOT MET, exit 4
$ ./scripts/demo.sh                      → all six scenarios OK, exit 0
```

The regression tests that pin this behaviour: `tests/intelligence/test_production_benchmark.py`
(25 tests — corpus location, both label sources agreeing, every target checked, honest unknowns
staying unknown, byte-identical repeat runs, plain-JSON payload, each configuration error, and a
corpus the engine *cannot* meet producing a failed verdict), four CLI tests in
`tests/test_cli_app.py` (exit `0` with targets met, JSON verdict payload, exit `4` on a miss, exit
`3` for a missing corpus), the six new fixtures in `tests/diagnosis/test_engine.py`, and twelve
boundary cases in `tests/diagnosis/test_rule_boundaries.py`.

#### 11.11.9 Files changed in this pass

| File | Change |
| --- | --- |
| `src/openmedic/diagnosis/rules.py` | npm prefix, BuildKit tolerance, env-var and YAML signals, project-source import rule, pytest-collection rule, docstrings |
| `src/openmedic/ingestion/logfile.py` | missing-module patterns moved to the dependency family |
| `src/openmedic/intelligence/benchmark.py` | targets, checks, verdict, run object, rule-id metric, corpus resolution, cross-check |
| `src/openmedic/intelligence/cases/` | **new** — the packaged corpus (moved, with re-audited labels) |
| `src/openmedic/intelligence/__init__.py` | new exports |
| `src/openmedic/application/services.py` | `benchmark()` loads and enforces targets; `_default_cases_dir()` reads the package |
| `src/openmedic/cli/app.py` | `benchmark` prints the verdict and exits `4` on a miss |
| `.github/workflows/ci.yml` | `benchmark` job; installed-wheel corpus check in `build` |
| `scripts/demo.sh` | **new** — the six-scenario judge demo |
| `pyproject.toml` | per-file lint ignore for embedded log literals in one test file |
| `README.md` | capability table, architecture, commands, exit codes, benchmark, demo, remediation model, troubleshooting |
| `tests/diagnosis/test_rule_boundaries.py`, `tests/intelligence/test_production_benchmark.py` | **new** |
| `tests/diagnosis/fixtures/*.log` (6 new), `tests/diagnosis/test_engine.py` | new signatures + the one documented row change |
| `tests/intelligence/test_benchmark.py`, `tests/test_application_services.py`, `tests/test_cli_app.py`, `tests/ingestion/test_logfile.py` | corpus path, run object, CLI exits, hint alignment |
| `docs/IMPLEMENTATION_STATUS.md`, `AGENTS.md` | this record, and the counts AGENTS.md quotes |

---

### 11.12 License decision (owner) and documentation reconciliation

The project owner has chosen **MIT**. The root `LICENSE` file holds the standard MIT text with
`Copyright (c) 2026 karthikwho`. This closes the last item flagged for an owner decision
(§5 row 8, §6, §11.8.1).

**Packaging metadata.** `pyproject.toml` now declares the licence the way the existing build
backend (hatchling, PEP 639) accepts it:

```toml
license = "MIT"
license-files = ["LICENSE"]
```

`requires-python = ">=3.11"` is unchanged. The deprecated `License :: OSI Approved :: MIT License`
classifier is deliberately **not** added: with a SPDX `License-Expression` it is redundant and
PEP 639 marks license classifiers as deprecated. Verified by building the artifacts:

```text
$ uv build --out-dir /tmp/openmedic-license-dist   → wheel + sdist, exit 0
wheel METADATA:  Metadata-Version: 2.5 / License-Expression: MIT / License-File: LICENSE
wheel contents:  openmedic-0.1.0.dist-info/licenses/LICENSE
sdist contents:  openmedic-0.1.0/LICENSE
```

**Documentation reconciled** (historical wording kept where erasing it would misrepresent the
record, and marked as superseded):

| File | Change |
| --- | --- |
| `AGENTS.md` | "no `LICENSE` file / license unresolved" replaced with the MIT decision and root-file list |
| `README.md` | the "no `LICENSE` file exists" bullet replaced; a `## License` section added |
| `docs/IMPLEMENTATION_ROADMAP.md` | Milestone 12 license line struck through and marked superseded; contribution guidelines remain open |
| `docs/IMPLEMENTATION_STATUS.md` §4, §5, §6, §11.8.1, §11.9 | original "unresolved / no license" text preserved with *Superseded* notes; §5 row 8 now records **MIT** |
| `pyproject.toml` | the "do not add a license" comment replaced by the declaration above |

No application code, test, fixture, or dependency constraint was touched.

**Third-party licence audit** (requirement: do not assume everything is MIT). Sources: the
installed `.venv` package `METADATA`, and PyPI metadata for the members of `uv.lock` that the
`api` extra does not install into this environment.

| Set | Licences observed |
| --- | --- |
| Runtime deps (`typer`, `pydantic`, `pydantic-core`, `httpx`, `httpcore`, `h11`, `idna`, `anyio`, `certifi`, `click`, `rich`, `shellingham`, `markdown-it-py`, `mdurl`, `typing-extensions`, `typing-inspection`, `annotated-doc`, `packaging`) | MIT, ISC, BSD-3-Clause, BSD-2-Clause, **MPL-2.0** (`certifi`), **PSF-2.0** (`typing-extensions`), **Apache-2.0 OR BSD-2-Clause** (`packaging`) |
| Dev deps (`pytest`, `ruff`, `pluggy`, `iniconfig`, `pygments`, `hatchling`) | MIT, BSD-2-Clause |
| `api` extra (`fastapi`, `starlette`, `uvicorn`, `opentelemetry-api`, `colorama`) | MIT, BSD-3-Clause, Apache-2.0, BSD (`colorama` classifier only) |
| Copied/vendored code or assets in this repository | **None found** — no `vendor/`/`node_modules/`, no images, fonts, minified JS/CSS, or other binary assets; no `copyright`/`all rights reserved` headers anywhere in `src/`, `tests/`, `scripts/`, `.github/`; fixture logs are synthetic and CI *references* `actions/checkout` and `astral-sh/setup-uv` rather than vendoring them |

No GPL/LGPL/AGPL or other strong-copyleft licence appears anywhere in the resolved dependency
closure, so nothing contradicts shipping this repository under MIT. `certifi` (MPL-2.0) and
`packaging` (Apache-2.0 OR BSD-2-Clause) are permissive/file-level terms that apply to
those dependencies as distributed; they are installed as separate distributions and are not
copied into this project.

**Not fully verified (reported, not assumed):** `colorama` has no SPDX licence expression on
PyPI — only a generic `BSD License` classifier — and it is not installed here (Windows-only
dependency of `click`), so its exact text was not read. `hatchling` is fetched at build time
and was verified as MIT only via PyPI metadata, not from a local copy. The contents of the
GitHub Actions referenced by `.github/workflows/ci.yml` are upstream code downloaded at CI
run time; they are not distributed with this repository. Fixture-log provenance rests on the
project's own documentation (they are synthetic), not on an independent source.

**Gates re-run after these changes.** Every exit status observed:

```text
$ uv run pytest -q                     → 822 passed, exit 0
$ uv run ruff check .                  → All checks passed!, exit 0
$ uv run ruff format --check .         → 114 files already formatted, exit 0
```

Nothing was committed, pushed, published, merged, or deployed.
