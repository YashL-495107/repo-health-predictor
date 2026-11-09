# Reproduce the frozen-ruleset benchmark (benchmark/README.md section 9). Windows PowerShell 5.1 or PowerShell 7.
#
#   .\scripts\reproduce.ps1 -Quick                          checks + selfcheck + a small -Limit subset of the test split
#   .\scripts\reproduce.ps1 -DatadogDir C:\bench\dd         full sequence (needs the DataDog subset already fetched)
#   .\scripts\reproduce.ps1 -DatadogDir C:\bench\dd -Fetch  also fetch the DataDog subset first (downloads ~229 MB)
#   .\scripts\reproduce.ps1 -DryRun [-Quick]                print the commands only; nothing is run
#
# Checks before anything runs: the frozen tag exists, the ruleset version / freeze flag / README frozen row match it,
# GITHUB_TOKEN is set, the test set is not contaminated, and `run_benchmark.py --selfcheck` passes.
# Outputs go to benchmark\runs\repro\ and benchmark\repro\ so the committed results are never overwritten or resumed.
param(
    [switch]$Quick,
    [switch]$Fetch,
    [switch]$DryRun,
    [int]$Limit = 5,
    [string]$DatadogDir = "C:\bench\dd",
    [string]$SamplesDir = "C:\bench\samples",
    [string]$Snapshot = "2026-11-08",
    [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
$Tag = "ruleset-2026.11.08-12-frozen"
$Ruleset = "2026.11.08-12"
Set-Location (Split-Path -Parent $PSScriptRoot)
$Out = "benchmark/runs/repro"

function Fail($what, $fix) { Write-Host "FAIL: $what"; Write-Host "  fix: $fix"; exit 1 }
function Run([string[]]$cmd) {
    Write-Host ("+ " + ($cmd -join " "))
    if (-not $DryRun) {
        & $cmd[0] $cmd[1..($cmd.Length - 1)]
        if ($LASTEXITCODE -ne 0) { Write-Host "command failed (exit $LASTEXITCODE)"; exit $LASTEXITCODE }
    }
}

Write-Host "== checks"
if (-not $DryRun) {
    git rev-parse --verify --quiet "$Tag^{commit}" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "tag $Tag not found" "git fetch --tags origin" }
    # only single quotes inside: Windows PowerShell 5.1 mangles double quotes in native-command arguments
    $check = 'import sys; sys.path[:0] = [''.'', ''benchmark'']; from detectors.version import RULESET_FROZEN, RULESET_VERSION; import run_benchmark as RB; w = sys.argv[1]; print(RULESET_VERSION, RULESET_FROZEN, RB.readme_frozen_version()); sys.exit(0 if (RULESET_VERSION == w and RULESET_FROZEN and RB.readme_frozen_version() == w) else 1)'
    & $Python -c $check $Ruleset
    if ($LASTEXITCODE -ne 0) { Fail "ruleset does not match the frozen version" "git checkout $Tag (or the trust-engine branch at that ruleset)" }
    if (-not $env:GITHUB_TOKEN) { Fail "GITHUB_TOKEN is not set" '$env:GITHUB_TOKEN = "<token>" (repo mode needs 5,000 requests/hour)' }
    $c = & $Python -c 'import sys; sys.path[:0] = [''.'', ''benchmark'']; import run_benchmark as RB; print(RB.contamination())'
    if ($c -ne "not contaminated") { Fail "test set: $c" "see benchmark/CHANGELOG.md; a contaminated test set is not a held-out result" }
    Write-Host "test set: $c"
}
Run @($Python, "benchmark/run_benchmark.py", "--selfcheck", "--samples-dir", $SamplesDir)

if ($Quick) {
    Write-Host "== quick: a -Limit $Limit subset of the test split (artifact mode, headline settings)"
    Run @($Python, "benchmark/run_benchmark.py", "--mode", "artifact", "--split", "test", "--limit", "$Limit", "--snapshot", $Snapshot,
          "--samples-dir", $SamplesDir, "--no-osv", "--no-fragility-escalation", "--out", "$Out/quick-artifact-test-noosv-nofrag.jsonl")
    exit 0
}

Write-Host "== DataDog subset"
if (-not (Test-Path (Join-Path $DatadogDir "subset/mapping.csv"))) {
    if ($Fetch) {
        Run @($Python, "benchmark/fetch_datadog_subset.py", "--dir", $DatadogDir, "--dry-run")
        Run @($Python, "benchmark/fetch_datadog_subset.py", "--dir", $DatadogDir, "--max-mb", "2000")
    } elseif (-not $DryRun) {
        Fail "no DataDog subset in $DatadogDir" "pass -Fetch to download it (about 229 MB), or -DatadogDir <folder>"
    } else {
        Write-Host "(dry run: the DataDog subset would be required at $DatadogDir; -Fetch downloads it)"
    }
}

Write-Host "== README section 9 sequence"
Run @($Python, "benchmark/run_benchmark.py", "--mode", "artifact", "--split", "dev", "--snapshot", $Snapshot, "--samples-dir", $SamplesDir, "--out", "$Out/artifact-dev.jsonl")
Run @($Python, "benchmark/run_benchmark.py", "--mode", "repo", "--split", "dev", "--snapshot", $Snapshot, "--out", "$Out/repo-dev.jsonl")
Run @($Python, "benchmark/prepare_known_bad.py", "--datadog-dir", $DatadogDir, "--samples-dir", $SamplesDir)
Run @($Python, "benchmark/run_benchmark.py", "--mode", "artifact", "--split", "test", "--snapshot", $Snapshot, "--samples-dir", $SamplesDir, "--no-osv", "--no-fragility-escalation", "--out", "$Out/artifact-test-noosv-nofrag.jsonl")
Run @($Python, "benchmark/run_benchmark.py", "--mode", "artifact", "--split", "test", "--snapshot", $Snapshot, "--samples-dir", $SamplesDir, "--no-osv", "--out", "$Out/artifact-test-noosv.jsonl")
Run @($Python, "benchmark/run_benchmark.py", "--mode", "artifact", "--split", "test", "--snapshot", $Snapshot, "--samples-dir", $SamplesDir, "--no-fragility-escalation", "--out", "$Out/artifact-test-nofrag.jsonl")
Run @($Python, "benchmark/run_benchmark.py", "--mode", "artifact", "--split", "replay", "--snapshot", $Snapshot, "--out", "$Out/artifact-replay.jsonl")
Run @($Python, "benchmark/run_benchmark.py", "--mode", "repo", "--split", "test", "--category", "known_good", "--category", "dormant", "--category", "scary", "--snapshot", $Snapshot, "--no-osv", "--out", "$Out/repo-test-noosv.jsonl")
Run @($Python, "benchmark/run_benchmark.py", "--mode", "repo", "--split", "test", "--category", "known_good", "--category", "dormant", "--category", "scary", "--snapshot", $Snapshot, "--out", "$Out/repo-test.jsonl")
if (-not $DryRun) { New-Item -ItemType Directory -Force -Path "benchmark/repro" | Out-Null }
Run @($Python, "benchmark/metrics.py", "--headline", "$Out/artifact-test-noosv-nofrag.jsonl", "--frag-on", "$Out/artifact-test-noosv.jsonl",
      "--with-osv", "$Out/artifact-test-nofrag.jsonl", "--repo-run", "$Out/repo-test-noosv.jsonl", "--replay", "$Out/artifact-replay.jsonl",
      "--out", "benchmark/repro/RESULTS.md", "--csv-dir", "benchmark/repro/results")
Write-Host "done: compare benchmark\repro\RESULTS.md with benchmark\RESULTS.md (chat-AI step 7 is manual, see README section 9)"
