"""Read-only check of the extracted DataDog samples against the extraction manifests.

  python benchmark/verify_samples.py --samples-dir C:\\bench\\samples [--dataset-dir C:\\bench\\dd]

For every member that manifests/datadog_members.csv lists as "written", the .sample file must exist under
--samples-dir (path mapping: extract_datadog.written_paths, the same one extraction uses) and its sha256 must match the
manifest. Antivirus can remove or truncate these files after extraction (Windows Defender removed some in run 1).
With --dataset-dir, a mismatch is re-checked against the ZIP: a member whose bytes are not valid UTF-8 is stored
decoded, so its file hash differs from the member hash by construction ("normalised at extraction", not a problem).
Prints counts and writes ONLY item ids, relative member paths and the problem to results/samples_missing.csv. Nothing
is changed, extracted, executed or deleted.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
for p in (str(ROOT), str(BENCH)):
    if p not in sys.path:
        sys.path.insert(0, p)

import extract_datadog as XD  # noqa: E402

OUT = BENCH / "results" / "samples_missing.csv"


def read_rows(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(line for line in fh if not line.startswith("#")))


def _normalised_ok(dataset: Path, ext_row: dict, rel: str, file_sha: str, mapping: dict) -> bool:
    zpath = XD.sample_location(dataset, ext_row["sample_path"], mapping)
    if not zpath.is_file():
        return False
    blob = zpath.read_bytes()
    if hashlib.sha256(blob).hexdigest() != ext_row["zip_sha256"]:
        return False
    res = XD.read_sample(blob)
    strip = XD.strip_common_root(sorted(res["text"]))
    for key, text in res["text"].items():
        if "/".join(key.split("/")[strip:]) + ".sample" == rel:
            return hashlib.sha256(XD.written_bytes(text)).hexdigest() == file_sha
    return False


def check(samples_root: Path, extracted_csv: Path | None = None, members_csv: Path | None = None,
          dataset: Path | None = None) -> dict:
    ext = {r["id"]: r for r in read_rows(extracted_csv or XD.MANIFEST) if r.get("status") == "extracted"}
    members = defaultdict(list)
    for m in read_rows(members_csv or XD.MEMBERS):
        members[m["id"]].append(m)
    problems, counts = [], Counter()
    mapping = XD.load_mapping(dataset) if dataset is not None else {}
    for sid in sorted(ext):
        base = Path(samples_root) / ext[sid]["sample_dir"]
        for row, rel in XD.written_paths(members[sid]):
            counts["checked"] += 1
            f = base / rel
            if not f.is_file():
                problems.append({"id": sid, "member_path": rel, "problem": "missing"})
                counts["missing"] += 1
                continue
            sha = hashlib.sha256(f.read_bytes()).hexdigest()
            if sha == row["sha256"]:
                counts["ok"] += 1
            elif dataset is not None and _normalised_ok(dataset, ext[sid], rel, sha, mapping):
                counts["ok (normalised at extraction)"] += 1
            else:
                problems.append({"id": sid, "member_path": rel, "problem": "sha256 mismatch"})
                counts["sha256 mismatch"] += 1
    counts["items affected"] = len({p["id"] for p in problems})
    counts["items checked"] = len(ext)
    return {"problems": problems, "counts": counts}


def write_report(problems: list[dict], path: Path = OUT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["id", "member_path", "problem"], lineterminator="\n")
        w.writeheader()
        w.writerows(problems)
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check extracted .sample files against the extraction manifests (read-only)")
    ap.add_argument("--samples-dir", required=True)
    ap.add_argument("--dataset-dir", default=None, help="the DataDog subset folder, to recognise UTF-8-normalised members")
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--extracted", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--members", default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    res = check(Path(a.samples_dir), Path(a.extracted) if a.extracted else None, Path(a.members) if a.members else None,
                Path(a.dataset_dir) if a.dataset_dir else None)
    c = res["counts"]
    print(f"items checked {c['items checked']}; members checked {c['checked']}; ok {c['ok']}"
          + (f"; ok (normalised at extraction) {c['ok (normalised at extraction)']}" if c["ok (normalised at extraction)"] else "")
          + f"; missing {c['missing']}; sha256 mismatch {c['sha256 mismatch']}; items affected {c['items affected']}")
    path = write_report(res["problems"], Path(a.out))
    print(f"wrote {path} ({len(res['problems'])} row(s): ids and relative member paths only)")
    return 0 if not res["problems"] else 1


if __name__ == "__main__":
    sys.exit(main())
