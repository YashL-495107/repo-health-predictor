"""scripts/reproduce.sh and scripts/reproduce.ps1: checks first, section-9 sequence, never downloads without --fetch.
Only --dry-run and the failing checks are exercised: no scan is ever started by these tests."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SH, PS1 = ROOT / "scripts" / "reproduce.sh", ROOT / "scripts" / "reproduce.ps1"
STEPS = ["--selfcheck", "--mode artifact --split dev", "--mode repo --split dev", "prepare_known_bad.py",
         "--no-osv --no-fragility-escalation", "--split replay", "--category known_good --category dormant --category scary",
         "metrics.py --headline"]
bash = shutil.which("bash")


def _env(**kw):
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}
    env.update(kw)
    return env


@pytest.mark.skipif(bash is None or os.name == "nt", reason="bash script tested on POSIX")
def test_sh_syntax_and_dry_run_full_sequence(tmp_path):
    subprocess.run([bash, "-n", str(SH)], check=True)
    out = subprocess.run([bash, str(SH), "--dry-run", "--datadog-dir", str(tmp_path / "dd")], capture_output=True,
                         text=True, env=_env(PYTHON=sys.executable), check=True).stdout
    for step in STEPS:
        assert step in out, step
    assert "fetch_datadog_subset.py" not in out                     # never downloads without --fetch
    assert "--out benchmark/runs/repro/" in out and "--out benchmark/repro/RESULTS.md" in out
    fetch = subprocess.run([bash, str(SH), "--dry-run", "--fetch", "--datadog-dir", str(tmp_path / "dd")],
                           capture_output=True, text=True, env=_env(PYTHON=sys.executable), check=True).stdout
    assert "fetch_datadog_subset.py --dir" in fetch and "--max-mb 2000" in fetch


@pytest.mark.skipif(bash is None or os.name == "nt", reason="bash script tested on POSIX")
def test_sh_quick_dry_run_is_selfcheck_plus_limit():
    out = subprocess.run([bash, str(SH), "--dry-run", "--quick", "--limit", "3"], capture_output=True, text=True,
                         env=_env(PYTHON=sys.executable), check=True).stdout
    assert "--selfcheck" in out and "--limit 3" in out and "prepare_known_bad" not in out


@pytest.mark.skipif(bash is None or os.name == "nt", reason="bash script tested on POSIX")
def test_sh_checks_fail_fast_without_token():
    r = subprocess.run([bash, str(SH), "--quick"], capture_output=True, text=True, env=_env(PYTHON=sys.executable))
    assert r.returncode == 1 and "FAIL:" in r.stderr and "--selfcheck" not in r.stdout   # stops before any scan
    tag = subprocess.run(["git", "rev-parse", "--verify", "--quiet", "ruleset-2026.11.08-12-frozen^{commit}"], cwd=ROOT,
                         capture_output=True)
    sys.path.insert(0, str(ROOT))
    from detectors import version as V
    # The script stops at its FIRST failing check, in this order: the v1 tag exists, the code is ruleset v1, a token
    # is set. CI checkouts carry no tags, so there the first check fails; with the tag present, a v2 checkout (branch
    # ruleset-v2, merged into main) fails the ruleset check by design (the script reproduces v1), and only a v1
    # checkout gets as far as the token check.
    if tag.returncode != 0:
        assert "tag ruleset-2026.11.08-12-frozen not found" in r.stderr
    elif V.RULESET_VERSION != "2026.11.08-12":
        assert "ruleset does not match the frozen version" in r.stderr
    else:
        assert "GITHUB_TOKEN is not set" in r.stderr


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 not installed")
def test_ps1_dry_run(tmp_path):
    out = subprocess.run(["pwsh", "-NoProfile", "-File", str(PS1), "-DryRun", "-DatadogDir", str(tmp_path / "dd"),
                          "-Python", sys.executable], capture_output=True, text=True, env=_env(), check=True).stdout
    for step in STEPS:
        assert step in out, step
    assert "fetch_datadog_subset.py" not in out
    quick = subprocess.run(["pwsh", "-NoProfile", "-File", str(PS1), "-DryRun", "-Quick", "-Limit", "3", "-Python", sys.executable],
                           capture_output=True, text=True, env=_env(), check=True).stdout
    assert "--limit 3" in quick and "prepare_known_bad" not in quick


def test_scripts_follow_readme_section_9():
    readme = (ROOT / "benchmark" / "README.md").read_text(encoding="utf-8")
    sec9 = readme[readme.index("## 9."):]
    for flagset in ("--no-osv --no-fragility-escalation", "--split replay", "--selfcheck", "prepare_known_bad.py"):
        assert flagset in sec9
    for script in (SH, PS1):
        text = script.read_text(encoding="utf-8")
        assert "ruleset-2026.11.08-12-frozen" in text and "2026.11.08-12" in text and "GITHUB_TOKEN" in text
        assert "contamination()" in text and "--selfcheck" in text
    assert "scripts/reproduce" in sec9 or "scripts\\reproduce" in sec9
