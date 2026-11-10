"""Per-item feature table for the learned-combiner research (benchmark/ml_combiner.py). Run locally, on the machine that
holds the run-2 JSONL, the restored DataDog samples and the benchmark's HTTP cache:

  python benchmark\\extract_features.py --run benchmark\\runs\\run2\\artifact-test-noosv-nofrag.jsonl ^
      --samples-dir C:\\bench\\samples

Writes benchmark/results/run2/features.csv: one row per SCORED item of the run (known-bad, random known-good, scary,
dormant), with
  id, set, label (1 = known-bad, 0 = otherwise), ecosystem, artifact_kind (sdist / wheel / npm_tgz / datadog_sample),
  contents_status, file_count, total_bytes, install_hook, inflated_version,
  cap_network, cap_credential_env, cap_process_spawn, cap_decoding_obfuscation, cap_persistence,
  findings_list_truncated, and per detector: det_<detector>_known_malicious / _high_risk / _review (from the run's
  per-item finding list), det_<detector>_info (low-level notes) and det_<detector>_findings (all non-info findings).

Sources. Detector columns come from the JSONL only (what the frozen ruleset produced; nothing is re-scored). The
other columns re-read the SAME artifact the run scanned: DataDog samples from --samples-dir (inert .sample text);
registry artifacts from the benchmark HTTP cache with REPOHEALTH_OFFLINE=1 (never downloaded again: a cache miss
leaves the columns empty with contents_status "not in cache"). Capability counts use the existing static readers
(repo_behavior.scan_behavior categories, detectors.release_analysis.capabilities); nothing is executed, imported or
installed. No package contents, file names or paths are written.

The JSONL keeps at most 60 findings per item; findings_list_truncated = 1 marks items where the per-tier detector
counts may be undercounts (det_<detector>_findings and _info are exact).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
for p in (str(ROOT), str(BENCH)):
    if p not in sys.path:
        sys.path.insert(0, p)

OUT = BENCH / "results" / "run2" / "features.csv"
SETS = ("known_bad", "known_good", "scary", "dormant")
TIERS = ("known_malicious", "high_risk", "review")
CAPS = ("cap_network", "cap_credential_env", "cap_process_spawn", "cap_decoding_obfuscation", "cap_persistence")
BASE_FIELDS = ["id", "set", "label", "ecosystem", "artifact_kind", "contents_status", "file_count", "total_bytes",
               "install_hook", "inflated_version", *CAPS, "findings_list_truncated"]
COMPACT_LIMIT = 60


def read_run(path: Path) -> list[dict]:
    recs = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                r = json.loads(line)
                recs[r["id"]] = r                  # a later line for the same id (a retry) replaces the earlier one
    return [r for r in recs.values() if r.get("status") == "scored" and r.get("category") in SETS]


def detector_columns(records: list[dict]) -> list[str]:
    names = sorted({d for r in records for d in (r.get("detectors") or {})})
    return [f"det_{d}_{k}" for d in names for k in (*TIERS, "info", "findings")]


def detector_features(rec: dict, columns: list[str]) -> dict:
    out = {c: 0 for c in columns}
    for f in rec.get("findings") or []:
        c = f"det_{f.get('detector')}_{f.get('tier')}"
        if c in out:
            out[c] += 1
    for d, v in (rec.get("detectors") or {}).items():
        if f"det_{d}_info" in out:
            out[f"det_{d}_info"] = int(v.get("n_info") or 0)
            out[f"det_{d}_findings"] = int(v.get("n_findings") or 0)
    return out


def _npm_scripts(text: dict) -> dict:
    pj = next((t for p, t in text.items() if p == "package.json" or p.endswith("/package.json") and p.count("/") == 1), None)
    try:
        scripts = (json.loads(pj) or {}).get("scripts") or {} if pj else {}
    except (ValueError, AttributeError):
        scripts = {}
    return {k: v for k, v in scripts.items() if k in ("preinstall", "install", "postinstall") and isinstance(v, str)}


def load_contents(item: dict, samples_dir: Path | None) -> tuple[dict | None, dict, str]:
    """(contents, release dict for release_analysis, status). Never downloads (offline cache only)."""
    if item.get("source") == "datadog":
        from run_benchmark import load_sample_dir
        try:
            c = load_sample_dir(item["sample_dir"], samples_dir)
        except (OSError, ValueError) as e:
            return None, {}, f"sample not readable ({type(e).__name__})"
        if not c["text"]:
            return None, {}, "sample files missing"
        return c, {"version": item.get("version"), "contents": c, "install_scripts": _npm_scripts(c["text"])}, "read"
    import releases
    fetch = releases.fetch_pypi if item["ecosystem"] == "PyPI" else releases.fetch_npm if item["ecosystem"] == "npm" else None
    if fetch is None:
        return None, {}, "unsupported ecosystem"
    hist = fetch(item["package"], releases.DEFAULT_N, time.monotonic() + releases.FETCH_BUDGET_S, item.get("version") or None)
    if hist.get("status") != "ok" or not hist.get("releases"):
        return None, {}, "not in cache" if "offline" in str(hist.get("reason")) else f"registry: {hist.get('reason')}"
    rel = hist["releases"][0]
    if rel.get("contents") is None:
        st = str(rel.get("artifact_status"))
        return None, rel, "not in cache" if "offline" in st else f"artifact not read ({st})"
    return rel["contents"], rel, "read"


def content_features(contents: dict, release: dict, name: str) -> dict:
    from detectors.release_analysis import capabilities
    from repo_behavior import scan_behavior
    from run_benchmark import data_from_contents
    text = contents.get("text") or {}
    bins = contents.get("binaries") or []
    beh = Counter(f.get("cat") for f in scan_behavior(data_from_contents(contents), name, lambda f, ln: None)["findings"])
    caps = capabilities(release)
    return {"file_count": len(contents.get("members") or text),
            "total_bytes": sum(len(t.encode("utf-8", "ignore")) for t in text.values()) + sum(int(b.get("size") or 0) for b in bins),
            "install_hook": int(bool(caps["install_hook"]) or bool(release.get("install_scripts"))),
            "cap_network": beh["Network"] + len(caps["network"]) + len(caps["hook_network"]),
            "cap_credential_env": beh["Credential access"],
            "cap_process_spawn": len(caps["process"]),
            "cap_decoding_obfuscation": beh["Obfuscation"] + len(caps["decoded"]),
            "cap_persistence": beh["Persistence"]}


def artifact_kind(rec: dict, item: dict) -> str:
    if item.get("source") == "datadog":
        return "datadog_sample"
    k = str((rec.get("artifact") or {}).get("kind") or "")
    return {"bdist_wheel": "wheel", "npm_tgz": "npm_tgz", "sdist": "sdist", "wheel": "wheel"}.get(k, k or "unknown")


def build(records: list[dict], items: dict, samples_dir: Path | None, with_contents: bool = True) -> list[dict]:
    from error_analysis import inflated_version
    cols = detector_columns(records)
    rows = []
    for rec in sorted(records, key=lambda r: r["id"]):
        item = items.get(rec["id"]) or {}
        row = {"id": rec["id"], "set": rec["category"], "label": int(rec["category"] == "known_bad"),
               "ecosystem": item.get("ecosystem") or "",
               "artifact_kind": artifact_kind(rec, item),
               "inflated_version": int(bool(inflated_version(item.get("version") or ""))),
               "findings_list_truncated": int(len(rec.get("findings") or []) >= COMPACT_LIMIT)}
        row.update({k: "" for k in ("file_count", "total_bytes", "install_hook", *CAPS)})
        if with_contents and item:
            try:
                contents, release, status = load_contents(item, samples_dir)
                if contents is not None:
                    row.update(content_features(contents, release, item.get("package") or ""))
            except Exception as e:                     # one unreadable item must not stop the table
                status = f"error ({type(e).__name__})"
            row["contents_status"] = status
        else:
            row["contents_status"] = "not read (--no-contents)" if item else "item not in the manifests"
        row.update(detector_features(rec, cols))
        rows.append(row)
    return rows


def write(rows: list[dict], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = BASE_FIELDS + [c for c in rows[0] if c.startswith("det_")] if rows else BASE_FIELDS
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Per-item features for benchmark/ml_combiner.py (no contents, no paths)")
    ap.add_argument("--run", default=str(BENCH / "runs" / "run2" / "artifact-test-noosv-nofrag.jsonl"))
    ap.add_argument("--samples-dir", default=None, help="restored DataDog samples (e.g. C:\\bench\\samples)")
    ap.add_argument("--cache", default=None, help="benchmark HTTP cache (default benchmark/cache/http)")
    ap.add_argument("--snapshot", default=None, help="cache snapshot date (default: the run's snapshot)")
    ap.add_argument("--no-contents", action="store_true", help="detector columns only")
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args(argv)
    records = read_run(Path(a.run))
    if not records:
        print(f"no scored items in {a.run}", file=sys.stderr)
        return 2
    snap = a.snapshot or (records[0].get("run") or {}).get("snapshot")
    os.environ["REPOHEALTH_CACHE"] = str(Path(a.cache or BENCH / "cache" / "http").resolve())
    if snap:
        os.environ["REPOHEALTH_SNAPSHOT"] = snap
    os.environ["REPOHEALTH_OFFLINE"] = "1"                 # the same artifacts the run scanned; nothing downloaded
    import bench_items
    test, dev = bench_items.all_items()
    items = {i["id"]: i for i in test + dev}
    rows = build(records, items, Path(a.samples_dir).resolve() if a.samples_dir else None, not a.no_contents)
    path = write(rows, Path(a.out))
    st = Counter(r["contents_status"] for r in rows)
    print(f"wrote {path}: {len(rows)} items ({dict(Counter(r['set'] for r in rows))}); contents: {dict(st)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
