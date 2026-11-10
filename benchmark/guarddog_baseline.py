"""GuardDog external baseline (DataDog's open-source package scanner, Apache-2.0) on the 461 run-2 items. Run locally;
the app never imports or runs GuardDog, and this changes no rule, score or benchmark number of ours.

  python benchmark\\guarddog_baseline.py --guarddog-python C:\\bench\\gdvenv\\Scripts\\python.exe ^
      --samples-dir C:\\bench\\samples --work-dir C:\\bench\\gdwork

Items: exactly the rows of benchmark/results/run2/features.csv (314 known-bad, 117 known-good, 18 scary, 12 dormant).

Inputs (decision, so both tools judge the same bytes): GuardDog scans the SAME text inputs our scanner read for each
item, written under their original file names into a temporary folder inside --work-dir (keep it inside the
Defender-excluded C:\\bench), then deleted:
  - DataDog known-bad samples: the restored inert .sample files under --samples-dir (".sample" removed from the name);
    the encrypted ZIPs are not decrypted again.
  - Registry items: the release artifact's text members from the benchmark HTTP cache (REPOHEALTH_OFFLINE=1: never
    downloaded again).
  Binary members and nested archives are not given to either tool's text rules in the same way (our extraction kept
  text only), so GuardDog's binary rules cannot fire here; that limit applies to both classes alike.
GuardDog's own temporary files go to --work-dir as well (TEMP/TMP/TMPDIR of its process). Nothing is executed,
imported or installed; GuardDog is static. It runs as `python -m guarddog <npm|pypi> scan <folder> --output-format
json --no-sandbox` (its kernel sandbox needs nono-py, which has no Windows packages; the sandbox only guards
GuardDog's own archive extraction, and here it reads plain folders we wrote).

Output benchmark/results/run2/guarddog.csv: id, set, label, ecosystem, status, risk_score (0-10), risk_label
(no_risks_detected / low / suspicious / high_risk), issues, findings_count, max_severity, rules_fired (rule names,
";"-separated), n_threat_rules, n_capability_rules, error_rules, guarddog_version, sandbox, input. No package
contents, no paths. Resumable: items already in the output are skipped (use --restart to start over).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
for p in (str(ROOT), str(BENCH)):
    if p not in sys.path:
        sys.path.insert(0, p)

FEATURES = BENCH / "results" / "run2" / "features.csv"
OUT = BENCH / "results" / "run2" / "guarddog.csv"
SNAPSHOT = "2026-11-08"                 # run 2's data snapshot (benchmark/RESULTS.md header)
TIMEOUT_S = 300                         # the benchmark's per-item budget
INPUT = "benchmark text inputs (same as our scanner)"
FIELDS = ["id", "set", "label", "ecosystem", "status", "risk_score", "risk_label", "issues", "findings_count",
          "max_severity", "rules_fired", "n_threat_rules", "n_capability_rules", "error_rules", "guarddog_version",
          "sandbox", "input"]
SEVERITY = {"low": 1, "medium": 2, "high": 3}
ITEM_DIR, TMP_DIR = "guarddog_item", "guarddog_tmp"   # inside --work-dir; nothing else in --work-dir is touched
NPM_ROOT = "package"


def read_items(path: Path = FEATURES) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return [{k: r[k] for k in ("id", "set", "label", "ecosystem")} for r in csv.DictReader(fh)]


def safe_rel(path: str) -> str | None:
    """A member path as a relative POSIX path inside the item folder, or None (absolute, '..', drive letters)."""
    p = PurePosixPath(path.replace("\\", "/"))
    if p.is_absolute() or not p.parts or any(x in ("..", "") or ":" in x for x in p.parts):
        return None
    return p.as_posix()


def write_inputs(text: dict, dest: Path) -> int:
    n = 0
    for path, body in text.items():
        rel = safe_rel(path)
        if rel is None:
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8", errors="ignore")
        n += 1
    return n


def parse(report: dict) -> dict:
    """GuardDog --output-format json -> CSV fields (rule names and numbers only)."""
    results = report.get("results") or {}
    fired = sorted(k for k, v in results.items() if v)
    rs = report.get("risk_score") or {}
    sev = [SEVERITY.get(str(r.get("severity")).lower(), 0) for r in report.get("risks") or []]
    return {"risk_score": rs.get("score", 0), "risk_label": rs.get("label", "no_risks_detected"),
            "issues": report.get("issues", 0), "findings_count": rs.get("findings_count", 0),
            "max_severity": max(sev) if sev else 0, "rules_fired": ";".join(fired),
            "n_threat_rules": sum(1 for f in fired if f.startswith("threat-")),
            "n_capability_rules": sum(1 for f in fired if f.startswith("capability-")),
            "error_rules": ";".join(sorted((report.get("errors") or {}).keys()))}


def run_guarddog(python: str, ecosystem: str, folder: Path, tmp: Path, timeout: int = TIMEOUT_S) -> dict:
    eco = {"PyPI": "pypi", "npm": "npm"}[ecosystem]
    env = {**os.environ, "TEMP": str(tmp), "TMP": str(tmp), "TMPDIR": str(tmp)}
    cmd = [python, "-m", "guarddog", eco, "scan", str(folder), "--output-format", "json", "--no-sandbox"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, encoding="utf-8", errors="replace")
    out = proc.stdout.strip()
    start = out.find("{")
    if start < 0:
        raise RuntimeError(f"no JSON output (exit {proc.returncode})")
    return json.loads(out[start:])


def guarddog_version(python: str) -> str:
    try:
        p = subprocess.run([python, "-m", "guarddog", "--version"], capture_output=True, text=True, timeout=120)
        return next((ln.strip() for ln in p.stdout.splitlines() if ln.strip()[:1].isdigit()), "unknown")
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def scan_item(item: dict, catalog: dict, samples_dir: Path | None, work: Path, python: str, version: str,
              timeout: int = TIMEOUT_S, runner=run_guarddog) -> dict:
    from extract_features import load_contents
    row = {"id": item["id"], "set": item["set"], "label": item["label"], "ecosystem": item["ecosystem"],
           "guarddog_version": version, "sandbox": "off", "input": INPUT,
           **{k: "" for k in FIELDS if k not in ("id", "set", "label", "ecosystem", "guarddog_version", "sandbox", "input")}}
    meta = catalog.get(item["id"])
    if not meta:
        row["status"] = "item not in the manifests"
        return row
    folder, tmp = work / ITEM_DIR, work / TMP_DIR       # only these two subfolders are ever created or deleted
    shutil.rmtree(folder, ignore_errors=True)
    tmp.mkdir(parents=True, exist_ok=True)
    try:
        contents, _release, status = load_contents(meta, samples_dir)
        if contents is None:
            row["status"] = f"contents: {status}"
            return row
        # npm: GuardDog's package-level rules (install hooks) look for package.json under package/, the npm tarball
        # layout; our readers strip that top folder, so it is restored. PyPI rules give the same result either way.
        dest = folder / "pkg" / NPM_ROOT if item["ecosystem"] == "npm" else folder / "pkg"
        if not write_inputs(contents.get("text") or {}, dest):
            row["status"] = "contents: no text member"
            return row
        report = runner(python, item["ecosystem"], folder / "pkg", tmp, timeout)
        row.update(parse(report))
        row["status"] = "scanned"
    except subprocess.TimeoutExpired:
        row["status"] = "timeout"
    except Exception as e:                     # one failing item must not stop the run; no message (it may hold paths)
        row["status"] = f"error ({type(e).__name__})"
    finally:
        shutil.rmtree(folder, ignore_errors=True)
        shutil.rmtree(tmp, ignore_errors=True)
    return row


def done_ids(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    with open(path, newline="", encoding="utf-8") as fh:
        return {r["id"] for r in csv.DictReader(fh)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="GuardDog baseline on the run-2 items (external reference; local only)")
    ap.add_argument("--guarddog-python", default=sys.executable, help="python.exe of the venv where GuardDog is installed")
    ap.add_argument("--samples-dir", required=True, help="restored DataDog samples (e.g. C:\\bench\\samples)")
    ap.add_argument("--work-dir", required=True, help="temporary folder INSIDE the Defender-excluded C:\\bench")
    ap.add_argument("--cache", default=None, help="benchmark HTTP cache (default benchmark/cache/http)")
    ap.add_argument("--snapshot", default=SNAPSHOT)
    ap.add_argument("--features", default=str(FEATURES))
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--timeout", type=int, default=TIMEOUT_S)
    ap.add_argument("--limit", type=int, default=None, help="scan at most N new items (trial run)")
    ap.add_argument("--restart", action="store_true", help="ignore an existing output file")
    a = ap.parse_args(argv)
    os.environ["REPOHEALTH_CACHE"] = str(Path(a.cache or BENCH / "cache" / "http").resolve())
    os.environ["REPOHEALTH_SNAPSHOT"] = a.snapshot
    os.environ["REPOHEALTH_OFFLINE"] = "1"
    version = guarddog_version(a.guarddog_python)
    if not version[:1].isdigit():
        print(f"GuardDog not found for {a.guarddog_python} (python -m guarddog --version failed)", file=sys.stderr)
        return 2
    import bench_items
    test, dev = bench_items.all_items()
    catalog = {i["id"]: i for i in test + dev}
    items = read_items(Path(a.features))
    out = Path(a.out)
    done = set() if a.restart else done_ids(out)
    todo = [i for i in items if i["id"] not in done][: a.limit]
    work = Path(a.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    mode = "w" if (a.restart or not out.is_file()) else "a"
    out.parent.mkdir(parents=True, exist_ok=True)
    print(f"GuardDog {version}: {len(todo)} item(s) to scan ({len(done)} already in {out.name})")
    with open(out, mode, newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS, lineterminator="\n")
        if mode == "w":
            w.writeheader()
        for n, item in enumerate(todo, 1):
            row = scan_item(item, catalog, Path(a.samples_dir).resolve(), work, a.guarddog_python, version, a.timeout)
            w.writerow(row)
            fh.flush()
            print(f"[{n}/{len(todo)}] {item['set']:10} {row['status']:22} {row['risk_label'] or '-'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
