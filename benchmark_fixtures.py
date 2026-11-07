"""Offline REGRESSION check over labelled, inert fixtures in benchmark_fixtures/.

The fixtures were written alongside the rules, so passing them shows the rules still do what they were written to
do; it is NOT an accuracy measure (see the Phase 5 benchmark for that).

Fixtures are stored as *.sample files so the repo reader (repo_scan.read_repo) never treats them as real code,
and they are never imported or executed. Each one is read as text and handed to the detectors in an in-memory
dict under a "virtual" path (the name minus .sample; setup fixtures become setup.py, README fixtures README.md),
because the detectors choose what to scan by file name.

Exit code 1 if recall on the malicious set is below 100% or any benign sample is flagged strong.
"""
from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from malware_proof import scan_ast_deobfuscation, scan_static_setup_py
from repo_behavior import scan_behavior

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_fixtures")


def virtual_path(fixture_name: str) -> str:
    name = fixture_name[:-len(".sample")] if fixture_name.endswith(".sample") else fixture_name
    if name.endswith("setup.py"):
        return "setup.py"
    if "readme" in name.lower():
        return "README.md"
    return name


def _url(f, ln):
    return f"fixture://{f}#L{ln}"


def scan_fixture(fixture_name: str, content: str) -> list[dict]:
    files = {virtual_path(fixture_name): content}
    findings = []
    findings += scan_ast_deobfuscation(files, _url)["findings"]
    findings += scan_static_setup_py(files, _url)["findings"]
    findings += scan_behavior({"text": files, "binaries": []}, "benchmark", _url)["findings"]
    return findings


def load_labels(fixture_dir: str = FIXTURE_DIR) -> list[dict]:
    with open(os.path.join(fixture_dir, "labels.csv"), newline="", encoding="utf-8") as fh:
        return [{"file": r["file"].strip(), "expected": r["expected"].strip().lower()} for r in csv.DictReader(fh)]


def evaluate(fixture_dir: str = FIXTURE_DIR) -> dict:
    rows = []
    for lab in load_labels(fixture_dir):
        with open(os.path.join(fixture_dir, lab["file"]), encoding="utf-8") as fh:
            content = fh.read()
        fs = scan_fixture(lab["file"], content)
        detected = any(f.get("strong") or f.get("sev") in ("High", "Medium") for f in fs)
        strong = any(f.get("strong") for f in fs)
        rules = sorted({f"{f.get('source')}: {f.get('rule')}" for f in fs if f.get("strong") or f.get("sev") in ("High", "Medium")})
        rows.append({**lab, "scanned_as": virtual_path(lab["file"]), "detected": detected, "strong": strong, "rules": rules})
    mal = [r for r in rows if r["expected"] == "malicious"]
    ben = [r for r in rows if r["expected"] == "benign"]
    recall = sum(r["detected"] for r in mal) / len(mal) if mal else 0.0
    return {
        "rows": rows,
        "recall": recall,
        "malicious": len(mal),
        "benign": len(ben),
        "benign_detected": sum(r["detected"] for r in ben),
        "benign_strong": sum(r["strong"] for r in ben),
        "passed": bool(mal) and recall == 1.0 and not any(r["strong"] for r in ben),
    }


def main() -> int:
    res = evaluate()
    w = max(len(r["file"]) for r in res["rows"])
    print(f"{'file':<{w}}  {'expected':<9}  {'detected':<8}  {'strong':<6}  rules")
    print("-" * (w + 40))
    for r in res["rows"]:
        print(f"{r['file']:<{w}}  {r['expected']:<9}  {str(r['detected']):<8}  {str(r['strong']):<6}  {'; '.join(r['rules']) or '-'}")
    print()
    hits = round(res['recall'] * res['malicious'])
    print(f"Regression fixtures: {hits}/{res['malicious']} detected (written alongside the rules; not an accuracy measure)")
    print(f"Benign look-alike fixtures: {res['benign_detected']}/{res['benign']} flagged, {res['benign_strong']} strong")
    print("PASS" if res["passed"] else "FAIL")
    return 0 if res["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
