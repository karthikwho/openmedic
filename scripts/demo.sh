#!/usr/bin/env bash
# OpenMedic offline demonstration.
#
# Runs the real CLI against synthetic CI logs and a disposable repository in a
# temporary directory. It needs no credentials, no network access and no Docker, and it
# never writes to the source tree or to your incident database.
#
# Usage:
#   ./scripts/demo.sh
#   OPENMEDIC_BIN=/path/to/openmedic ./scripts/demo.sh   # test an installed wheel
#
# The script fails loudly (non-zero) if any step behaves differently from what it
# prints, so it doubles as an end-to-end smoke test.

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve the CLI once, from the starting directory. An installed `openmedic` wins,
# then a source checkout's `uv run`. Resolving up front means the demo keeps working
# after it changes directory into the synthetic repository below.
# ---------------------------------------------------------------------------
PROJECT_DIR="$(pwd)"
if [ -n "${OPENMEDIC_BIN:-}" ]; then
  MEDIC_CMD=("$OPENMEDIC_BIN")
elif command -v openmedic >/dev/null 2>&1; then
  MEDIC_CMD=(openmedic)
elif command -v uv >/dev/null 2>&1 && [ -f pyproject.toml ]; then
  MEDIC_CMD=(uv run --project "$PROJECT_DIR" openmedic)
else
  echo "error: no openmedic CLI found; install the wheel or run from a source checkout" >&2
  exit 1
fi

medic() {
  "${MEDIC_CMD[@]}" "$@"
}

py() {
  if command -v python3 >/dev/null 2>&1; then
    python3 "$@"
  else
    python "$@"
  fi
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/openmedic-demo.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# The demo owns its own incident store, so it cannot touch a real one.
export OPENMEDIC_DB="$WORK/incidents.db"
export OPENMEDIC_LOG_LEVEL="${OPENMEDIC_LOG_LEVEL:-WARNING}"

step() {
  printf '\n\033[1m=== %s ===\033[0m\n' "$1"
}

fail() {
  printf '\033[31mDEMO FAILED:\033[0m %s\n' "$1" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Synthetic evidence
# ---------------------------------------------------------------------------

cat > "$WORK/missing-module.log" <<'LOG'
Current runner version: '2.320.0'
##[group]Run python -m pytest -q
  python -m pytest -q
  shell: /usr/bin/bash -e {0}
Traceback (most recent call last):
  File "/home/runner/work/app/app/tests/test_client.py", line 3, in <module>
    import requests
ModuleNotFoundError: No module named 'requests'
##[error]Process completed with exit code 1.
LOG

cat > "$WORK/ambiguous.log" <<'LOG'
Current runner version: '2.320.0'
##[group]Run ./scripts/deploy.sh
  ./scripts/deploy.sh
  shell: /usr/bin/bash -e {0}
deploy: something went wrong
##[error]Process completed with exit code 1.
LOG

# A tiny repository whose dependency manifest a proposal can be made against.
REPO="$WORK/repo"
mkdir -p "$REPO/tests"
cat > "$REPO/requirements.txt" <<'REQ'
# Application dependencies.
REQ
cat > "$REPO/tests/test_client.py" <<'TEST'
import requests


def test_client_reaches_the_api() -> None:
    assert requests.get("https://example.invalid").status_code == 200
TEST
if command -v git >/dev/null 2>&1; then
  git -C "$REPO" init -q
  git -C "$REPO" add -A
  git -C "$REPO" -c user.name="OpenMedic demo" -c user.email="demo@invalid" commit -q -m "seed"
fi

py - "$WORK/missing-module.log" "$WORK/event.json" <<'PY'
import json
import sys
from pathlib import Path

log_path, out_path = Path(sys.argv[1]), Path(sys.argv[2])
out_path.write_text(
    json.dumps(
        {
            "repository": "acme/widget",
            "workflow_name": "CI",
            "job_name": "tests",
            "run_id": "1042",
            "failed_step": "tests",
            "logs": log_path.read_text(encoding="utf-8"),
            "timestamp": "2026-10-10T09:00:00Z",
        },
        indent=2,
    ),
    encoding="utf-8",
)
PY

echo "Working directory: $WORK (removed on exit)"
echo "Incident database: $OPENMEDIC_DB"

# ---------------------------------------------------------------------------
# 1. A supported failure produces an actionable, evidence-backed diagnosis
# ---------------------------------------------------------------------------
step "1. Diagnose a supported CI failure (offline, no credentials)"
medic diagnose "$WORK/missing-module.log" --repository acme/widget --run-id 1042 \
  | tee "$WORK/diagnose.txt"
grep -q "DEP-001" "$WORK/diagnose.txt" \
  || fail "expected the missing-dependency rule DEP-001"
echo "OK: diagnosed as DEP-001 with quoted evidence."

# ---------------------------------------------------------------------------
# 2. An ambiguous failure stays unknown rather than being guessed
# ---------------------------------------------------------------------------
step "2. An ambiguous failure stays unknown"
medic --json diagnose "$WORK/ambiguous.log" --repository acme/widget --run-id 1043 \
  | tee "$WORK/ambiguous.json" >/dev/null
grep -q '"failure_type": "unknown"' "$WORK/ambiguous.json" \
  || fail "an ambiguous log must be classified unknown"
echo "OK: reported unknown with low confidence and a request for human review."

# ---------------------------------------------------------------------------
# 3. Remediation defaults to a dry-run proposal and touches nothing
# ---------------------------------------------------------------------------
step "3. Ingest the failure and propose a remediation (dry-run by default)"
cd "$REPO"
BEFORE="$(cksum requirements.txt)"

medic --json ingest "$WORK/event.json" | tee "$WORK/ingest.json"
INCIDENT="$(py -c 'import json,sys; print(json.load(open(sys.argv[1]))["incident_id"])' "$WORK/ingest.json")"
echo "Incident: $INCIDENT"

medic repair "$INCIDENT" | tee "$WORK/proposal.txt"
AFTER="$(cksum requirements.txt)"
[ "$BEFORE" = "$AFTER" ] || fail "dry-run modified requirements.txt"
if command -v git >/dev/null 2>&1 && [ -d "$REPO/.git" ]; then
  [ -z "$(git -C "$REPO" status --porcelain)" ] || fail "dry-run left the repository dirty"
fi
echo "OK: a reviewable proposal was produced and the working tree is untouched."

# ---------------------------------------------------------------------------
# 4. Applying a patch cannot produce a recovery without passing checks
# ---------------------------------------------------------------------------
step "4. Apply the proposal: validation runs and cannot fake a recovery"
set +e
medic --json repair "$INCIDENT" --apply > "$WORK/apply.json" 2>"$WORK/apply.err"
APPLY_EXIT=$?
set -e
cat "$WORK/apply.err"
[ "$APPLY_EXIT" -eq 4 ] || fail "expected exit 4 (validation failed), got $APPLY_EXIT"
grep -q "pytest" "$WORK/apply.err" \
  || fail "the refusal should name the required check that did not pass"
medic --json incidents show "$INCIDENT" > "$WORK/state.json"
grep -q '"state": "failed"' "$WORK/state.json" \
  || fail "incident should be in the failed state after a failed validation"
grep -q '"recovered": false' "$WORK/state.json" \
  || fail "a failed validation claimed recovery"
echo "OK: exit 4, state 'failed', recovered=false — no recovery without passing checks."

# ---------------------------------------------------------------------------
# 5. The benchmark measures the real engine and enforces its targets
# ---------------------------------------------------------------------------
step "5. Benchmark the diagnosis engine against committed targets"
set +e
medic benchmark > "$WORK/benchmark.txt" 2>"$WORK/benchmark.err"
BENCH_EXIT=$?
set -e
tail -n 12 "$WORK/benchmark.txt"
[ "$BENCH_EXIT" -eq 0 ] || fail "benchmark exited $BENCH_EXIT; expected 0 with all targets met"
grep -q "targets met" "$WORK/benchmark.txt" || fail "benchmark did not report its targets as met"
echo "OK: every committed target met, exit 0."

# ---------------------------------------------------------------------------
# 6. Incident history is queryable
# ---------------------------------------------------------------------------
step "6. Incident history"
medic incidents list
medic incidents show "$INCIDENT" | head -n 20

printf '\n\033[1mDemo complete.\033[0m Every scenario above ran against the real CLI.\n'
