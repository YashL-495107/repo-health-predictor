"""Fetch ONLY the benchmark's DataDog samples from GitHub, without cloning the whole dataset (about 108 GB) and without
ever creating a dataset path on disk (some cannot exist on Windows).

  python benchmark/fetch_datadog_subset.py --dir C:\\bench\\dd [--max-mb 2000] [--dry-run] [--method https|git]

1. A partial clone with no working tree: `git clone --filter=blob:none --no-checkout --depth 1 <url> <dir>`. It holds
   commit and tree objects only. NOTHING is ever checked out (no `git checkout`, no sparse-checkout): the dataset
   has paths Windows cannot hold (npm package names ending in "." such as `mad-1.0.0.2.2.8.`), and git refuses to
   check out a tree containing them on Windows, even for other paths.
2. The sample paths and their blob ids come from `git ls-tree -r -z HEAD -- samples/pypi samples/npm` (tree objects
   only; `ls-tree -l` is NEVER used: asking for a size makes a partial clone download the file). The two
   manifest.json files are read from git objects into memory (`git cat-file`), never written as dataset paths.
3. Candidates (manifests/known_bad_candidates.csv) are matched at VERSION level with the benchmark's shared name and
   version normalisation; a candidate without a sample of its own version is not matched to another version and the
   reason is recorded. The selection is extract_datadog.select_samples over the FULL listing (version-level candidate
   matches + the pre-declared random draw, seed 20261107), so extraction reads exactly what was fetched.
4. Before any download the number of files and bytes still missing is printed (HTTP HEAD on raw.githubusercontent.com
   at the cloned commit: Content-Length only) and the script refuses above --max-mb (default 2000). --dry-run stops
   here: it uses only ls-tree, the two manifests and HEAD requests.
5. Each selected ZIP is obtained WITHOUT creating its original path: by HTTPS from raw.githubusercontent.com at the
   cloned commit (default) or from git objects (`git cat-file --batch`, which fetches missing blobs on demand); the
   bytes are verified against the git blob id from the tree (sha1 of "blob <size>\\0" + content) before they are kept,
   and an HTTPS failure or mismatch falls back to git. The file is stored under a Windows-compatible flat name:
   <dir>/subset/<pypi|npm>/<category>/<sha1 of the original path>.zip, recorded in <dir>/subset/mapping.csv
   (original path, storage path, size, sha256, git blob, method, note). An original path that Windows cannot hold is
   never dropped: its note says "unsafe name, obtained via <method>" (the requested marker: it describes a
   file name on Windows, not a package).
6. Resumable: an existing clone is reused; a stored ZIP whose blob id still matches is not fetched again.

The ZIPs stay encrypted (ZipCrypto, password "infected"). Nothing is extracted here: prepare_known_bad.py /
extract_datadog.py (--datadog-dir / --dataset = the same folder) read the ZIPs through mapping.csv, in memory, and
write text members only, as *.sample.

DataDog manifest rule (samples/<eco>/manifest.json): a package mapped to null is malicious in every version; a
package mapped to a list of versions is malicious ONLY in those versions. Recorded per candidate in the report.

Reports (committed; the ZIPs never are): manifests/datadog_subset.csv (one row per candidate) and
manifests/datadog_subset_fetch.txt (dataset commit, counts, bytes, names Windows cannot hold).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
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
MANIFEST_PATHS = {"PyPI": "samples/pypi/manifest.json", "npm": "samples/npm/manifest.json"}
DEFAULT_MAX_MB = 2000
ASSUMED_MB_PER_FILE = 5.0      # used only when a size cannot be looked up (conservative: refuses earlier, never later)
MAX_ZIP_BYTES = XD.MAX_ZIP_BYTES
SUBSET = XD.SUBSET_DIR          # <dir>/subset/...
REPORT = bench_items.MAN / "datadog_subset.csv"
SUMMARY = bench_items.MAN / "datadog_subset_fetch.txt"
WIN_RESERVED = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.I)
WIN_BAD_CHARS = re.compile(r'[<>:"|?*\\\x00-\x1f]')


class FetchError(SystemExit):
    def __init__(self, msg: str, code: int = 2):
        super().__init__(code)
        self.msg = msg

    def __str__(self):
        return self.msg


def windows_unsafe(path: str) -> str | None:
    """Why a repository path cannot exist on Windows (NTFS / Win32), or None."""
    for part in path.split("/"):
        if part.endswith((".", " ")):
            return f"component {part!r} ends with a dot or a space"
        if WIN_RESERVED.match(part):
            return f"component {part!r} is a reserved Windows name"
        if WIN_BAD_CHARS.search(part):
            return f"component {part!r} has a character Windows does not allow"
    return None


# ------------------------------------------------------------------ git (never a checkout)

def git(clone: Path | None, *args: str, timeout: float = 3600, data: bytes | None = None) -> bytes:
    cmd = ["git"] + (["-C", str(clone)] if clone else []) + ["-c", "core.quotepath=off", *args]
    try:
        r = subprocess.run(cmd, capture_output=True, input=data, timeout=timeout)
    except FileNotFoundError:
        raise FetchError("git is not installed or not on PATH (install Git for Windows)")
    if r.returncode != 0:
        raise FetchError(f"git {' '.join(args[:3])} failed: {r.stderr.decode('utf-8', 'replace').strip()[:500]}")
    return r.stdout


def ensure_clone(clone: Path, url: str) -> str:
    """Partial clone without a working tree (reused when it exists). Returns the HEAD commit."""
    if not (clone / ".git").exists():
        if clone.exists() and any(clone.iterdir()):
            raise FetchError(f"{clone} exists, is not empty and is not a git clone; pick another folder (or delete it)")
        clone.parent.mkdir(parents=True, exist_ok=True)
        print(f"cloning (trees only, no file contents, no checkout) {url} -> {clone}")
        git(None, "clone", "--filter=blob:none", "--no-checkout", "--depth", "1", url, str(clone))
    return git(clone, "rev-parse", "HEAD").decode().strip()


def tree_blobs(clone: Path) -> dict[str, str]:
    """{path: blob id} for every file under samples/pypi and samples/npm (tree objects only, NUL-separated so any
    path survives unquoted)."""
    out = git(clone, "ls-tree", "-r", "-z", "HEAD", "--", "samples/pypi", "samples/npm")
    blobs = {}
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == b"blob":
            blobs[path.decode("utf-8", "surrogateescape")] = parts[2].decode()
    return blobs


def cat_blobs(clone: Path, shas: list[str]) -> dict[str, bytes]:
    """Blob contents by id with `git cat-file --batch` (missing blobs of the partial clone are fetched on demand).
    Read into memory only; the caller decides where (and whether) to store them."""
    if not shas:
        return {}
    out = git(clone, "cat-file", "--batch", data=("\n".join(shas) + "\n").encode())
    res, i = {}, 0
    while i < len(out):
        nl = out.index(b"\n", i)
        head = out[i:nl].split()
        i = nl + 1
        if len(head) == 2 and head[1] == b"missing":
            continue
        sha, size = head[0].decode(), int(head[2])
        res[sha] = out[i:i + size]
        i += size + 1
    return res


def blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


# ------------------------------------------------------------------ matching

def read_manifests(clone: Path, blobs: dict[str, str]) -> dict[str, dict | None]:
    shas = {eco: blobs.get(p) for eco, p in MANIFEST_PATHS.items()}
    got = cat_blobs(clone, [s for s in shas.values() if s])
    out = {}
    for eco, sha in shas.items():
        try:
            raw = json.loads(got[sha].decode("utf-8")) if sha and sha in got else None
        except ValueError:
            raw = None
        out[eco] = {bench_items.package_key(eco, k): v for k, v in raw.items()} if isinstance(raw, dict) else None
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
               "windows_unsafe": ";".join(filter(None, (windows_unsafe(s["sample_path"]) for s in hits))),
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


# ------------------------------------------------------------------ sizes and downloads

def _owner_repo(url: str) -> tuple[str, str]:
    owner, repo = url.rstrip("/").removesuffix(".git").split("/")[-2:]
    return owner, repo


def raw_url(url: str, commit: str, path: str) -> str:
    owner, repo = _owner_repo(url)
    return RAW.format(owner=owner, repo=repo, commit=commit, path=quote(path))


def head_sizes(paths: list[str], commit: str, url: str = DATASET_URL, workers: int = 8) -> dict[str, int | None]:
    """Content-Length of each file at the cloned commit via HTTP HEAD (no body)."""
    import requests

    def one(p):
        try:
            r = requests.head(raw_url(url, commit, p), timeout=20, allow_redirects=True,
                              headers={"User-Agent": "repo-health-predictor benchmark"})
            n = r.headers.get("Content-Length")
            return p, int(n) if r.status_code == 200 and n and n.isdigit() else None
        except Exception:
            return p, None
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(pool.map(one, paths))


def https_get(paths: list[str], commit: str, url: str = DATASET_URL, workers: int = 8) -> dict[str, bytes | None]:
    """File contents by HTTPS from raw.githubusercontent.com at the cloned commit (in memory)."""
    import requests

    def one(p):
        try:
            r = requests.get(raw_url(url, commit, p), timeout=120, headers={"User-Agent": "repo-health-predictor benchmark"})
            return p, r.content if r.status_code == 200 and len(r.content) <= MAX_ZIP_BYTES else None
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


def store(clone: Path, sample: dict, data: bytes) -> str:
    """Write the ZIP under its Windows-compatible flat name (atomic). Returns the storage path relative to the clone."""
    rel = XD.safe_sample_path(sample)
    dest = clone / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    tmp.write_bytes(data)
    os.replace(tmp, dest)
    return rel


def obtain(clone: Path, commit: str, url: str, todo: list[dict], blobs: dict[str, str], method: str,
           https_fn=https_get) -> dict[str, tuple[bytes, str]]:
    """{original path: (verified bytes, method)}. HTTPS first (when method == "https"), then git objects for
    anything HTTPS did not deliver or that failed the blob-id check."""
    got: dict[str, tuple[bytes, str]] = {}
    if method == "https" and todo:
        for p, data in https_fn([s["sample_path"] for s in todo], commit, url).items():
            if data is not None and blob_id(data) == blobs[p]:
                got[p] = (data, "https")
    rest = [s for s in todo if s["sample_path"] not in got]
    if rest:
        by_sha = cat_blobs(clone, [blobs[s["sample_path"]] for s in rest])
        for s in rest:
            data = by_sha.get(blobs[s["sample_path"]])
            if data is not None and blob_id(data) == blobs[s["sample_path"]]:
                got[s["sample_path"]] = (data, "git")
    return got


# ------------------------------------------------------------------ main

def run(clone: Path, url: str, max_mb: float, dry_run: bool, sizes_fn=head_sizes, https_fn=https_get,
        method: str = "https", report: Path = REPORT, summary: Path = SUMMARY, candidates_file: Path | None = None,
        n_random: int = XD.N_RANDOM_PER_ECO) -> int:
    commit = ensure_clone(clone, url)
    blobs = tree_blobs(clone)
    samples = sorted((s for s in (XD.parse_sample_path(p) for p in blobs if p.endswith(".zip")) if s),
                     key=lambda s: s["sample_path"])
    mapping = XD.load_mapping(clone)
    manifests = read_manifests(clone, blobs)

    cands = bench_items.read_manifest(candidates_file or bench_items.MAN / "known_bad_candidates.csv")
    rows = match_candidates(cands, samples, manifests)
    selected = XD.select_samples(samples, XD.candidate_keys(cands), n_random=n_random)

    def stored_ok(s):
        m = mapping.get(s["sample_path"])
        return bool(m) and (clone / m["safe_path"]).is_file() and m.get("git_blob") == blobs[s["sample_path"]]
    to_fetch = [s for s in selected if not stored_ok(s)]
    unsafe_all = sum(1 for s in samples if windows_unsafe(s["sample_path"]))
    unsafe_sel = [s for s in selected if windows_unsafe(s["sample_path"])]

    pkg_keys = {(x["ecosystem"], bench_items.package_key(x["ecosystem"], x["package"])) for x in samples}
    st = Counter(r["status"] for r in rows)
    by_cat = Counter(c for r in rows if r["status"] == "matched" for c in r["category"].split(";"))
    by_eco = Counter((r["ecosystem"], r["status"]) for r in rows)
    sel_by = Counter(s["selected_by"] for s in selected)
    lines = [f"dataset {url} commit {commit}",
             f"listing: {len(samples)} sample ZIPs (pypi {sum(s['eco_dir'] == 'pypi' for s in samples)}, "
             f"npm {sum(s['eco_dir'] == 'npm' for s in samples)}); {unsafe_all} with a path Windows cannot hold",
             f"candidates: {len(rows)}; matched at version level {st.get('matched', 0)}, unmatched {st.get('unmatched', 0)}",
             "matched by category: " + (", ".join(f"{k} {v}" for k, v in sorted(by_cat.items())) or "none"),
             "by ecosystem: " + ", ".join(f"{e} {s} {n}" for (e, s), n in sorted(by_eco.items())),
             "unmatched reasons: " + ("; ".join(f"{k}: {v}" for k, v in Counter(
                 r["reason_kind"] for r in rows if r["status"] == "unmatched").most_common()) or "none"),
             "for information (not used, no substitution): of the candidates whose advisory lists no version, "
             f"{sum(1 for r in rows if r['reason_kind'] == 'no version in the advisory' and (r['ecosystem'], bench_items.package_key(r['ecosystem'], r['package'])) in pkg_keys)}"
             " have the package in the dataset",
             f"selection (= extract_datadog.py): {len(selected)} ZIPs ("
             + ", ".join(f"{k} {v}" for k, v in sorted(sel_by.items())) + f"); {len(unsafe_sel)} with an original path "
             "Windows cannot hold (stored under a flat storage name, never dropped)",
             f"already stored: {len(selected) - len(to_fetch)}; to download: {len(to_fetch)}"]
    sizes = sizes_fn([s["sample_path"] for s in to_fetch], commit) if to_fetch else {}
    chk = size_check([s["sample_path"] for s in to_fetch], sizes, max_mb)
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
        print("dry run: nothing downloaded, nothing checked out")
        return 0
    if not chk["ok"]:
        print(f"REFUSING TO DOWNLOAD: {chk['mb_total']:.1f} MB is above --max-mb {max_mb:.0f}. Free disk space and "
              "raise --max-mb deliberately if you want to continue.", file=sys.stderr)
        return 3
    got = obtain(clone, commit, url, to_fetch, blobs, method, https_fn)
    for s in to_fetch:
        if s["sample_path"] not in got:
            continue
        data, how = got[s["sample_path"]]
        rel = store(clone, s, data)
        why = windows_unsafe(s["sample_path"])
        mapping[s["sample_path"]] = {"original_path": s["sample_path"], "safe_path": rel, "size": len(data),
                                     "sha256": hashlib.sha256(data).hexdigest(), "git_blob": blobs[s["sample_path"]],
                                     "method": how, "note": f"unsafe name, obtained via {how} ({why})" if why else ""}
    XD.write_mapping(clone, mapping)
    missing = [s["sample_path"] for s in selected if not stored_ok(s)]
    print(f"done: {len(selected) - len(missing)} of {len(selected)} selected ZIPs stored under {clone / SUBSET}"
          + (f"; {len(missing)} missing (download error or antivirus quarantine), e.g. {missing[0]}" if missing else ""))
    if unsafe_sel:
        print(f"{len(unsafe_sel)} selected ZIP(s) have a original path Windows cannot hold; see the note column of "
              f"{clone / SUBSET / 'mapping.csv'}")
    print(f"next: python benchmark/prepare_known_bad.py --datadog-dir {clone} [--samples-dir <folder>]")
    return 0 if not missing else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fetch only the benchmark's DataDog samples (partial clone, no checkout)")
    ap.add_argument("--dir", required=True, help="folder for the partial clone (new or an earlier one, e.g. C:\\bench\\dd)")
    ap.add_argument("--url", default=DATASET_URL)
    ap.add_argument("--max-mb", type=float, default=DEFAULT_MAX_MB, help="refuse to download more than this (MB)")
    ap.add_argument("--dry-run", action="store_true", help="ls-tree, the two manifests and HEAD requests only")
    ap.add_argument("--method", choices=("https", "git"), default="https",
                    help="how to obtain the ZIPs: HTTPS from raw.githubusercontent.com (git as fallback), or git only")
    a = ap.parse_args(argv)
    print(XD.DEFENDER_WARNING, "\n", file=sys.stderr)
    try:
        return run(Path(a.dir).resolve(), a.url, a.max_mb, a.dry_run, method=a.method)
    except FetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
