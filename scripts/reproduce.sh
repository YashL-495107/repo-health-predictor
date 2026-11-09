#!/usr/bin/env bash
# Reproduce the frozen-ruleset benchmark (benchmark/README.md section 9). Linux / macOS / Git Bash.
#
#   scripts/reproduce.sh --quick                       checks + selfcheck + a small --limit subset of the test split
#   scripts/reproduce.sh --datadog-dir ~/bench/dd      full sequence (needs the DataDog subset already fetched)
#   scripts/reproduce.sh --datadog-dir ~/bench/dd --fetch   also fetch the DataDog subset first (downloads ~229 MB)
#   scripts/reproduce.sh --dry-run [--quick]           print the commands only; nothing is run
#
# Checks before anything runs: the frozen tag exists, the ruleset version / freeze flag / README frozen row match it,
# GITHUB_TOKEN is set, the test set is not contaminated, and `run_benchmark.py --selfcheck` passes.
# Outputs go to benchmark/runs/repro/ and benchmark/repro/ so the committed results are never overwritten or resumed.
set -euo pipefail

TAG="ruleset-2026.11.08-12-frozen"
RULESET="2026.11.08-12"
SNAPSHOT="2026-11-08"          # the data snapshot of the committed RESULTS.md (reuses that cache when present)
QUICK=0; FETCH=0; DRY=0; LIMIT=5
DATADOG_DIR="${HOME}/bench/dd"; SAMPLES_DIR="${HOME}/bench/samples"
PY="${PYTHON:-python3}"
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) QUICK=1 ;;
    --fetch) FETCH=1 ;;
    --dry-run) DRY=1 ;;
    --limit) LIMIT="$2"; shift ;;
    --datadog-dir) DATADOG_DIR="$2"; shift ;;
    --samples-dir) SAMPLES_DIR="$2"; shift ;;
    --snapshot) SNAPSHOT="$2"; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
cd "$(dirname "$0")/.."
OUT=benchmark/runs/repro
fail() { echo "FAIL: $1" >&2; echo "  fix: $2" >&2; exit 1; }
run() { echo "+ $*"; if [ "$DRY" = 0 ]; then "$@"; fi; }

echo "== checks"
if [ "$DRY" = 0 ]; then
  git rev-parse --verify --quiet "${TAG}^{commit}" >/dev/null || fail "tag $TAG not found" "git fetch --tags origin"
  "$PY" - "$RULESET" <<'EOF' || fail "ruleset does not match the frozen version" "git checkout $TAG (or the trust-engine branch at that ruleset)"
import sys; sys.path[:0] = [".", "benchmark"]
from detectors.version import RULESET_FROZEN, RULESET_VERSION
import run_benchmark as RB
want = sys.argv[1]
ok = RULESET_VERSION == want and RULESET_FROZEN and RB.readme_frozen_version() == want
print(f"ruleset {RULESET_VERSION} frozen={RULESET_FROZEN} README={RB.readme_frozen_version()}")
sys.exit(0 if ok else 1)
EOF
  [ -n "${GITHUB_TOKEN:-}" ] || fail "GITHUB_TOKEN is not set" "export GITHUB_TOKEN=<token> (repo mode needs 5,000 requests/hour)"
  C=$("$PY" -c 'import sys; sys.path[:0]=[".","benchmark"]; import run_benchmark as RB; print(RB.contamination())')
  [ "$C" = "not contaminated" ] || fail "test set: $C" "see benchmark/CHANGELOG.md; a contaminated test set is not a held-out result"
  echo "test set: $C"
fi
run "$PY" benchmark/run_benchmark.py --selfcheck --samples-dir "$SAMPLES_DIR"

if [ "$QUICK" = 1 ]; then
  echo "== quick: a --limit $LIMIT subset of the test split (artifact mode, headline settings)"
  run "$PY" benchmark/run_benchmark.py --mode artifact --split test --limit "$LIMIT" --snapshot "$SNAPSHOT" \
      --samples-dir "$SAMPLES_DIR" --no-osv --no-fragility-escalation --out "$OUT/quick-artifact-test-noosv-nofrag.jsonl"
  exit 0
fi

echo "== DataDog subset"
if [ ! -f "$DATADOG_DIR/subset/mapping.csv" ]; then
  if [ "$FETCH" = 1 ]; then
    run "$PY" benchmark/fetch_datadog_subset.py --dir "$DATADOG_DIR" --dry-run
    run "$PY" benchmark/fetch_datadog_subset.py --dir "$DATADOG_DIR" --max-mb 2000
  elif [ "$DRY" = 0 ]; then
    fail "no DataDog subset in $DATADOG_DIR" "pass --fetch to download it (about 229 MB), or --datadog-dir <folder>"
  else
    echo "(dry run: the DataDog subset would be required at $DATADOG_DIR; --fetch downloads it)"
  fi
fi

echo "== README section 9 sequence"
run "$PY" benchmark/run_benchmark.py --mode artifact --split dev --snapshot "$SNAPSHOT" --samples-dir "$SAMPLES_DIR" --out "$OUT/artifact-dev.jsonl"
run "$PY" benchmark/run_benchmark.py --mode repo --split dev --snapshot "$SNAPSHOT" --out "$OUT/repo-dev.jsonl"
run "$PY" benchmark/prepare_known_bad.py --datadog-dir "$DATADOG_DIR" --samples-dir "$SAMPLES_DIR"
run "$PY" benchmark/run_benchmark.py --mode artifact --split test --snapshot "$SNAPSHOT" --samples-dir "$SAMPLES_DIR" --no-osv --no-fragility-escalation --out "$OUT/artifact-test-noosv-nofrag.jsonl"
run "$PY" benchmark/run_benchmark.py --mode artifact --split test --snapshot "$SNAPSHOT" --samples-dir "$SAMPLES_DIR" --no-osv --out "$OUT/artifact-test-noosv.jsonl"
run "$PY" benchmark/run_benchmark.py --mode artifact --split test --snapshot "$SNAPSHOT" --samples-dir "$SAMPLES_DIR" --no-fragility-escalation --out "$OUT/artifact-test-nofrag.jsonl"
run "$PY" benchmark/run_benchmark.py --mode artifact --split replay --snapshot "$SNAPSHOT" --out "$OUT/artifact-replay.jsonl"
run "$PY" benchmark/run_benchmark.py --mode repo --split test --category known_good --category dormant --category scary --snapshot "$SNAPSHOT" --no-osv --out "$OUT/repo-test-noosv.jsonl"
run "$PY" benchmark/run_benchmark.py --mode repo --split test --category known_good --category dormant --category scary --snapshot "$SNAPSHOT" --out "$OUT/repo-test.jsonl"
run mkdir -p benchmark/repro
run "$PY" benchmark/metrics.py --headline "$OUT/artifact-test-noosv-nofrag.jsonl" --frag-on "$OUT/artifact-test-noosv.jsonl" \
    --with-osv "$OUT/artifact-test-nofrag.jsonl" --repo-run "$OUT/repo-test-noosv.jsonl" --replay "$OUT/artifact-replay.jsonl" \
    --out benchmark/repro/RESULTS.md --csv-dir benchmark/repro/results
echo "done: compare benchmark/repro/RESULTS.md with benchmark/RESULTS.md (chat-AI step 7 is manual, see README section 9)"
