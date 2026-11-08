"""Fetch ONLY the benchmark's DataDog samples from GitHub, without cloning the whole dataset (about 108 GB).

  python benchmark/fetch_datadog_subset.py --dir C:\\bench\\dd [--max-mb 2000] [--dry-run]

1. A partial, sparse clone: `git clone --filter=blob:none --no-checkout --depth 1 <url> <dir>`, then
   `git sparse-checkout init --no-cone`. The clone holds commit and tree objects only (names, no file contents).
   The sample paths are listed with `git ls-tree -r --name-only HEAD -- samples/pypi samples/npm` (tree objects only;
   `ls-tree -l` is NEVER used, because asking git for a size makes a partial clone download that file).
2. The two manifest.json files are checked out (small metadata), then the known-bad candidates
   (manifests/known_bad_candidates.csv) are matched to sample ZIPs at VERSION level, with the same package-name and
   version normalisation as the rest of the benchmark (bench_items.package_key / version_key). A candidate with no
   ZIP for its version is NOT matched to another version; the reason is recorded. The selection is
   extract_datadog.select_samples, so it is exactly what extract_datadog.py will extract: the version-level candidate
   matches plus the pre-declared random draw (150 per ecosystem, seed 20261107) over the FULL listing.
3. Before anything is downloaded, the number of files and bytes still to fetch is printed (sizes from HTTP HEAD
   requests to raw.githubusercontent.com at the cloned commit: Content-Length only, no body). The script refuses to
   continue above --max-mb (default 2000). Then the selected paths are written to .git/info/sparse-checkout and
   `git checkout` downloads only those ZIPs.
4. Resumable: an existing clone is reused, files already on disk are not fetched again (git only downloads missing
   objects), and the size check counts only what is still missing.

The ZIPs stay encrypted (ZipCrypto, password "infected") exactly as in the dataset. Nothing is extracted here: run
prepare_known_bad.py / extract_datadog.py with --datadog-dir / --dataset pointing at the same folder, which read the
ZIPs in memory and write text members only, as *.sample.

DataDog manifest rule (samples/<eco>/manifest.json): a package mapped to null is malicious in every version; a
package mapped to a list of versions is malicious ONLY in those versions. The match report records, for every
candidate, what the manifest says about its version.

Report: manifests/datadog_subset.csv (one row per candidate: matched path or the reason it is unmatched) and
manifests/datadog_subset_fetch.txt (dataset commit, counts, bytes). Both are committed; the ZIPs never are.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
for p in (str(ROOT), str(BENCH)):
    if p not in sys.path:
        sys.path.insert(0, p)

import bench_items  # noqa: E402
import extract_datadog as XD  # noqa: E402

DATASET_URL = "https://github.com/DataDog/malicious-software-packages-dataset"
RAW = "https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{path}"
MANIFEST_PATHS = ("samples/pypi/manifest.json", "samples/npm/manifest.json")
DEFAULT_MAX_MB = 2000
ASSUMED_MB_PER_FILE = 5.0      # used only when a size cannot be looked up (conservative: refuses earlier, never later)
REPORT = bench_items.MAN / "datadog_subset.csv"
SUMMARY = bench_items.MAN / "datadog_subset_fetch.txt"


class FetchError(SystemExit):
    def __init__(self, msg: str, code: int = 2):
        super().__init__(code)
        self.msg = msg

    def __str__(self):
        return self.msg


# ------------------------------------------------------------------ git

def git(clone: Path | None, *args: str, timeout: float = 3600) -> str:
    cmd = ["git"] + (["-C", str(clone)] if clone else []) + ["-c", "core.quotepath=off", *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
    except FileNotFoundError:
        raise FetchError("git is not installed or not on PATH (install Git for Windows)")
    if r.returncode != 0:
        raise FetchError(f"git {' '.join(args[:3])} failed: {r.stderr.strip()[:500]}")
    return r.stdout


def ensure_clone(clone: Path, url: str) -> str:
    """Partial sparse clone (reused when it exists). Returns the HEAD commit."""
    if not (clone / ".git").exists():
        if clone.exists() and any(clone.iterdir()):
            raise FetchError(f"{clone} exists, is not empty and is not a git clone; pick another folder")
        clone.parent.mkdir(parents=True, exist_ok=True)
        print(f"cloning (trees only, no file contents) {url} -> {clone}")
        git(None, "clone", "--filter=blob:none", "--no-checkout", "--depth", "1", url, str(clone))
        git(clone, "config", "core.longpaths", "true")       # Windows: deep sample paths
        git(clone, "sparse-checkout", "init", "--no-cone")
        write_sparse(clone, [])
    return git(clone, "rev-parse", "HEAD").strip()


def listing(clone: Path) -> list[str]:
    """All sample ZIP paths (tree objects only; never `ls-tree -l`)."""
    out = git(clone, "ls-tree", "-r", "--name-only", "HEAD", "--", "samples/pypi", "samples/npm")
    return [p for p in out.splitlines() if p.endswith(".zip")]


def _pattern(path: str) -> str:
    """Anchored non-cone sparse-checkout pattern for one exact path (gitignore syntax: escape special characters)."""
    out = []
    for ch in path:
        if ch in "\\*?[]!# ":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "/" + "".join(out)


def write_sparse(clone: Path, paths: list[str]) -> None:
    sp = clone / ".git" / "info" / "sparse-checkout"
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text("".join(_pattern(p) + "\n" for p in sorted(set(paths))), encoding="utf-8", newline="\n")


def checkout(clone: Path) -> None:
    branch = git(clone, "rev-parse", "--abbrev-ref", "HEAD").strip()
    git(clone, "checkout", branch if branch and branch != "HEAD" else "HEAD")
    git(clone, "sparse-checkout", "reapply")


# ------------------------------------------------------------------ matching

def read_manifests(clone: Path) -> dict[str, dict]:
    out = {}
    for rel, eco in zip(MANIFEST_PATHS, ("PyPI", "npm")):
        p = clone / rel
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = None
        out[eco] = {bench_items.package_key(eco, k): v for k, v in (raw or {}).items()} if isinstance(raw, dict) else None
    return out


def manifest_note(manifests: dict, eco: str, pkg_key: str, ver_key: str) -> str:
    m = manifests.get(eco)
    if m is None:
        return "manifest not available"
    if pkg_key not in m:
        return "package not in the DataDog manifest"
    versions = m[pkg_key]
    if versions is None:
        return "manifest: malicious in every version"
    listed = {bench_items.version_key(eco, v) for v in versions}
    return ("manifest: malicious in this version" if ver_key in listed else
            f"manifest: malicious ONLY in {', '.join(versions[:8])}{' ...' if len(versions) > 8 else ''} (not this version)")


def match_candidates(cands: list[dict], samples: list[dict], manifests: dict) -> list[dict]:
    """One row per candidate: matched sample path(s) at version level, or the reason there is none."""
    by_pkg: dict[tuple[str, str], list[dict]] = {}
    for s in samples:
        by_pkg.setdefault((s["ecosystem"], bench_items.package_key(s["ecosystem"], s["package"])), []).append(s)
    rows = []
    for c in cands:
        eco, ver = c["ecosystem"], (c.get("version") or "").strip()
        pk, vk = bench_items.package_key(eco, c["package"]), bench_items.version_key(eco, ver)
        pool = by_pkg.get((eco, pk), [])
        hits = [s for s in pool if bench_items.version_key(eco, s["version"]) == vk] if ver else []
        row = {"id": c["id"], "ecosystem": eco, "package": c["package"], "version": ver,
               "manifest": manifest_note(manifests, eco, pk, vk) if ver else "", "status": "matched" if hits else "unmatched",
               "category": ";".join(sorted({s["kind"] for s in hits})), "sample_paths": ";".join(s["sample_path"] for s in hits),
               "reason": "", "reason_kind": ""}
        if not hits:
            if not ver:
                row["reason"], row["reason_kind"] = "the OSV advisory lists no version: no version-level match possible", \
                    "no version in the advisory"
            elif not pool:
                row["reason"], row["reason_kind"] = "package not in the dataset listing", "package not in the dataset"
            else:
                row["reason_kind"] = "package in the dataset, but not this version"
                have = sorted({s["version"] for s in pool})
                row["reason"] = (f"no sample for version {ver}; the dataset has {', '.join(have[:8])}"
                                 f"{' ...' if len(have) > 8 else ''} (no other version is substituted)")
        rows.append(row)
    return rows


# ------------------------------------------------------------------ sizes

def head_sizes(paths: list[str], commit: str, url: str = DATASET_URL, workers: int = 8) -> dict[str, int | None]:
    """Content-Length of each file at the cloned commit via HTTP HEAD on raw.githubusercontent.com (no body)."""
    import requests
    owner, repo = url.rstrip("/").removesuffix(".git").split("/")[-2:]

    def one(p):
        try:
            r = requests.head(RAW.format(owner=owner, repo=repo, commit=commit, path=quote(p)), timeout=20,
                              allow_redirects=True, headers={"User-Agent": "repo-health-predictor benchmark"})
            n = r.headers.get("Content-Length")
            return p, int(n) if r.status_code == 200 and n and n.isdigit() else None
        except Exception:
            return p, None
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(pool.map(one, paths))


def size_check(to_fetch: list[str], sizes: dict[str, int | None], max_mb: float) -> dict:
    known = [sizes.get(p) for p in to_fetch if sizes.get(p) is not None]
    unknown = sum(1 for p in to_fetch if sizes.get(p) is None)
    total = sum(known) + int(unknown * ASSUMED_MB_PER_FILE * 1024 * 1024)
    return {"files": len(to_fetch), "bytes_known": sum(known), "unknown_sizes": unknown, "bytes_total": total,
            "mb_total": total / (1024 * 1024), "max_mb": max_mb, "ok": total <= max_mb * 1024 * 1024}


# ------------------------------------------------------------------ main

def run(clone: Path, url: str, max_mb: float, dry_run: bool, sizes_fn=head_sizes,
        report: Path = REPORT, summary: Path = SUMMARY, candidates_file: Path | None = None,
        n_random: int = XD.N_RANDOM_PER_ECO) -> int:
    commit = ensure_clone(clone, url)
    all_paths = listing(clone)
    samples = [s for s in (XD.parse_sample_path(p) for p in all_paths) if s]
    for s in samples:
        s["present"] = (clone / s["sample_path"]).is_file()
    samples.sort(key=lambda s: s["sample_path"])
    # manifests: small metadata files, fetched first (they are kept in the sparse set)
    current = [p for p in all_paths if (clone / p).is_file()]
    if not all((clone / m).is_file() for m in MANIFEST_PATHS):
        write_sparse(clone, current + list(MANIFEST_PATHS))
        checkout(clone)
    manifests = read_manifests(clone)

    cands = bench_items.read_manifest(candidates_file or bench_items.MAN / "known_bad_candidates.csv")
    rows = match_candidates(cands, samples, manifests)
    selected = XD.select_samples(samples, XD.candidate_keys(cands), n_random=n_random)
    sel_paths = [s["sample_path"] for s in selected]
    to_fetch = [p for p in sel_paths if not (clone / p).is_file()]

    pkg_keys = {(x["ecosystem"], bench_items.package_key(x["ecosystem"], x["package"])) for x in samples}
    st = Counter(r["status"] for r in rows)
    by_cat = Counter(c for r in rows if r["status"] == "matched" for c in r["category"].split(";"))
    by_eco = Counter((r["ecosystem"], r["status"]) for r in rows)
    sel_by = Counter(s["selected_by"] for s in selected)
    lines = [f"dataset {url} commit {commit}",
             f"listing: {len(samples)} sample ZIPs (pypi {sum(s['eco_dir'] == 'pypi' for s in samples)}, "
             f"npm {sum(s['eco_dir'] == 'npm' for s in samples)})",
             f"candidates: {len(rows)}; matched at version level {st.get('matched', 0)}, unmatched {st.get('unmatched', 0)}",
             "matched by category: " + (", ".join(f"{k} {v}" for k, v in sorted(by_cat.items())) or "none"),
             "by ecosystem: " + ", ".join(f"{e} {s} {n}" for (e, s), n in sorted(by_eco.items())),
             "unmatched reasons: " + ("; ".join(f"{k}: {v}" for k, v in Counter(
                 r["reason_kind"] for r in rows if r["status"] == "unmatched").most_common()) or "none"),
             "for information (not used, no substitution): of the candidates whose advisory lists no version, "
             f"{sum(1 for r in rows if r['reason_kind'] == 'no version in the advisory' and (r['ecosystem'], bench_items.package_key(r['ecosystem'], r['package'])) in pkg_keys)}"
             " have the package in the dataset",
             f"selection (= extract_datadog.py): {len(selected)} ZIPs ("
             + ", ".join(f"{k} {v}" for k, v in sorted(sel_by.items())) + ")",
             f"already on disk: {len(sel_paths) - len(to_fetch)}; to download: {len(to_fetch)}"]
    sizes = sizes_fn(to_fetch, commit) if to_fetch else {}
    chk = size_check(to_fetch, sizes, max_mb)
    lines.append(f"download size: {chk['files']} files, {chk['mb_total']:.1f} MB"
                 + (f" ({chk['unknown_sizes']} size(s) unknown, counted as {ASSUMED_MB_PER_FILE:.0f} MB each)"
                    if chk["unknown_sizes"] else "") + f"; limit --max-mb {max_mb:.0f}")
    for line in lines:
        print(line)
    report.parent.mkdir(parents=True, exist_ok=True)
    with open(report, "w", newline="", encoding="utf-8") as fh:
        fh.write(f"# DataDog subset match (version level, no substitute versions) | dataset commit {commit} | "
                 "generated by benchmark/fetch_datadog_subset.py\n")
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["empty"])
        w.writeheader()
        w.writerows(rows)
    summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if dry_run:
        print("dry run: nothing downloaded")
        return 0
    if not chk["ok"]:
        print(f"REFUSING TO DOWNLOAD: {chk['mb_total']:.1f} MB is above --max-mb {max_mb:.0f}. Free disk space and "
              "raise --max-mb deliberately if you want to continue.", file=sys.stderr)
        return 3
    if to_fetch:
        write_sparse(clone, list(MANIFEST_PATHS) + sel_paths)
        checkout(clone)
    missing = [p for p in sel_paths if not (clone / p).is_file()]
    print(f"done: {len(sel_paths) - len(missing)} of {len(sel_paths)} selected ZIPs on disk"
          + (f"; {len(missing)} missing (antivirus quarantine or download error), e.g. {missing[0]}" if missing else ""))
    print(f"next: python benchmark/prepare_known_bad.py --datadog-dir {clone} [--samples-dir <folder>]")
    return 0 if not missing else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fetch only the benchmark's DataDog samples (partial sparse clone)")
    ap.add_argument("--dir", required=True, help="folder for the sparse clone (new or an earlier one, e.g. C:\\bench\\dd)")
    ap.add_argument("--url", default=DATASET_URL)
    ap.add_argument("--max-mb", type=float, default=DEFAULT_MAX_MB, help="refuse to download more than this (MB)")
    ap.add_argument("--dry-run", action="store_true", help="clone trees, match, size check; download no sample")
    a = ap.parse_args(argv)
    print(XD.DEFENDER_WARNING, "\n", file=sys.stderr)
    try:
        return run(Path(a.dir).resolve(), a.url, a.max_mb, a.dry_run)
    except FetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
