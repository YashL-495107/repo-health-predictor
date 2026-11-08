"""Record real registry responses for the benchmark's artifact-path tests (run by hand, online; the tests replay them
offline). Packages are NOT benchmark items (none appears in any manifest), so recording them views no test result.

  npm   bufferutil 4.2.0  (install script "node-gyp-build"; ships prebuilt native binaries)
  npm   mitt 3.0.1        (code in dist/)
  npm   is-number 7.0.0   (plain, one file)
  PyPI  six 1.17.0, iniconfig 2.3.0

Usage: python tests/fixtures/record_benchmark_fixtures.py
Writes the http_cache files to tests/fixtures/benchmark_http/<SNAPSHOT>/ and the expected summaries to
tests/fixtures/benchmark_expected.json. Static analysis only: artifacts are read in memory, never executed.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SNAPSHOT = "fixtures-2026-11-08"
CACHE = HERE / "benchmark_http"
EXPECTED = HERE / "benchmark_expected.json"
PACKAGES = [("npm", "bufferutil", "4.2.0"), ("npm", "mitt", "3.0.1"), ("npm", "is-number", "7.0.0"),
            ("PyPI", "six", "1.17.0"), ("PyPI", "iniconfig", "2.3.0")]


def stable(rec: dict) -> dict:
    """The parts of a record that must not change between recording and offline replay."""
    return {"status": rec.get("status"), "label": rec.get("label"), "findings_by_tier": rec.get("findings_by_tier"),
            "detectors": {k: [v["status"], v["tier"]] for k, v in sorted((rec.get("detectors") or {}).items())},
            "artifact": {k: (rec.get("artifact") or {}).get(k) for k in ("filename", "sha256", "members", "version")},
            "limits_hit": rec.get("limits_hit")}


def scan_all(offline: bool) -> dict:
    sys.path[:0] = [str(ROOT), str(ROOT / "benchmark")]
    os.environ["REPOHEALTH_CACHE"] = str(CACHE)
    os.environ["REPOHEALTH_SNAPSHOT"] = SNAPSHOT
    if offline:
        os.environ["REPOHEALTH_OFFLINE"] = "1"
    import bench_items
    import repo_scan
    import run_benchmark as RB
    repo_scan.MAX_LINE_CHARS = RB.LINE_CAP_CHARS
    out = {}
    # replay: the offline guard blocks every request that does not go through http_cache (deps.dev and the
    # typosquat lookups use requests directly); they are not assessed in both passes when, as in the recording
    # sandbox, those hosts are unreachable
    with RB.Patches(offline=offline, osv=False, fragility_escalation=True, osv_index=RB.OsvIndex(True, HERE / "no_osv"),
                    artifact_mode=True):
        for eco, name, ver in PACKAGES:
            item = {**bench_items._item("dev", eco, name, ver), "split": "dev", "obtainable": "yes"}
            out[f"{eco}:{name}@{ver}"] = stable(RB.scan_artifact(item, osv=False))
    return out


def main() -> int:
    res = scan_all(offline=False)
    EXPECTED.write_text(json.dumps(res, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    size = sum(p.stat().st_size for p in CACHE.rglob("*") if p.is_file())
    print(f"recorded {len(res)} packages, {size} bytes in {CACHE}")
    for k, v in res.items():
        print(k, v["status"], v["label"], v["findings_by_tier"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
