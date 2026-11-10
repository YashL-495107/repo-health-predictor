"""Fresh held-out set for ruleset v2 (pre-registered in benchmark/PREREG_v2.md). Selection, fetch, extraction and
pre-scan facts. Nothing is ever executed, imported or installed; samples are read as text in memory.

  python benchmark/fresh_set.py select-bad  --dataset C:\\bench\\dd        (done before the freeze; committed)
  python benchmark/fresh_set.py select-good                               (done before the freeze; committed)
  python benchmark/fresh_set.py dev-fingerprints --samples-dir <dev samples>  (the 76 dev items; committed)
  python benchmark/fresh_set.py fetch   --dir C:\\bench\\dd [--dry-run] [--max-mb 2000]
  python benchmark/fresh_set.py extract --dataset C:\\bench\\dd --samples-dir C:\\bench\\samples_fresh
  python benchmark/fresh_set.py facts   --samples-dir C:\\bench\\samples_fresh

Files (all under benchmark/manifests/fresh/, hashes and ids only, never sample contents):
  datadog_selection.csv   the drawn ZIPs: path, git blob id, ecosystem, category, package, version
  known_good.csv          the fresh random known-good sample (same columns as manifests/known_good.csv)
  dev76_fingerprints.csv  near-duplicate fingerprints of the 76 error-analysis items (normalised file hashes, hosts)
  datadog_extracted.csv / datadog_members.csv   written by `extract` (same format as the v1 manifests)
  fresh_facts.csv         written by `facts`: bucket and near-duplicate flag per fresh known-bad item

Selection rules (fixed in PREREG_v2.md before any fresh item is scanned):
  known-bad: every sample ZIP of the dataset at the pinned commit (samples/<pypi|npm>/<category>/<pkg>/<ver>/*.zip)
    that (1) is not a v1 sample path, (2) has a git blob id different from every v1 sample, and (3) whose
    (ecosystem, package key) is not a v1 DataDog sample package nor a v1 known-bad candidate package; then per
    ecosystem (pypi first) a fresh random.Random(FRESH_SEED) shuffles the path-sorted pool and the first
    N_PER_ECO samples are taken, skipping a sample whose blob or package was already taken (one sample per package).
  known-good: select_items.known_good with random.Random(FRESH_SEED), protocol date 2026-11-10, N_GOOD_PER_ECO per
    ecosystem, excluding every package and repository in the v1 known-good, dormant and scary manifests, the dev
    set and the viewed repositories.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
for p in (str(ROOT), str(BENCH)):
    if p not in sys.path:
        sys.path.insert(0, p)

import bench_items  # noqa: E402

FRESH_SEED = 20261110
N_PER_ECO = 150
N_GOOD_PER_ECO = 60
DATASET_COMMIT = "72c723be547033c558244520524b117c8d71663b"
FRESH = bench_items.MAN / "fresh"
SELECTION = FRESH / "datadog_selection.csv"
GOOD = FRESH / "known_good.csv"
FINGERPRINTS = FRESH / "dev76_fingerprints.csv"
EXTRACTED = FRESH / "datadog_extracted.csv"
MEMBERS = FRESH / "datadog_members.csv"
FACTS = FRESH / "fresh_facts.csv"
ERROR_ANALYSIS = BENCH / "ERROR_ANALYSIS.md"

# ------------------------------------------------------------------ near-duplicate rule (PREREG_v2.md section 4)
CODE_EXT = {".py", ".js", ".cjs", ".mjs", ".ts", ".sh", ".bat", ".cmd", ".ps1"}
MIN_FILE_CHARS = 200          # normalised characters; smaller files (stubs, one-liners) are not fingerprinted
HOST_RE = re.compile(r"\b(?:https?|wss?|ftp)://([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", re.I)
OAST_HOST_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:oast\.(?:fun|me|pro|live|site|online)|oastify\.com|"
                          r"burpcollaborator\.net|interact\.sh|dnslog\.cn|ceye\.io|requestrepo\.com|pipedream\.net|"
                          r"webhook\.site)|[a-z0-9.-]*oast-[a-z0-9.-]+\.[a-z]{2,})\b", re.I)
COMMON_HOSTS = {   # platform / documentation hosts shared by unrelated packages: never a campaign marker
    "github.com", "raw.githubusercontent.com", "api.github.com", "gist.github.com", "gist.githubusercontent.com",
    "objects.githubusercontent.com", "codeload.github.com", "registry.npmjs.org", "www.npmjs.com", "npmjs.com",
    "npmjs.org", "registry.yarnpkg.com", "pypi.org", "pypi.python.org", "files.pythonhosted.org", "upload.pypi.org",
    "test.pypi.org", "nodejs.org", "www.python.org", "python.org", "docs.python.org", "bun.sh", "deno.land",
    "google.com", "www.google.com", "googleapis.com", "www.googleapis.com", "example.com", "www.example.com",
    "localhost", "schema.org", "www.w3.org", "w3.org", "json-schema.org", "opensource.org", "mozilla.org",
    "developer.mozilla.org", "stackoverflow.com", "twitter.com", "x.com", "youtube.com", "www.youtube.com",
    "discord.com", "discordapp.com", "api.telegram.org", "t.me", "ifconfig.me", "api.ipify.org", "ipify.org",
    "ipinfo.io", "ip-api.com", "icanhazip.com", "checkip.amazonaws.com", "httpbin.org", "unpkg.com",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com", "creativecommons.org", "apache.org",
    "www.gnu.org", "gnu.org", "semver.org", "youtu.be", "mail.google.com", "login.microsoftonline.com",
    "www.imdb.com", "pixabay.com", "linuxmint.com", "iterm2.com", "www.iterm2.com", "publications.europa.eu",
    "pro.fontawesome.com", "ip-ranges.amazonaws.com", "telegra.ph", "te.legra.ph",
    "www.apache.org", "en.wikipedia.org", "readthedocs.io", "readthedocs.org", "shields.io", "img.shields.io",
    "badge.fury.io", "travis-ci.org", "codecov.io", "microsoft.com", "www.microsoft.com", "aka.ms",
}


def normalise_text(s: str) -> str:
    """Line endings to \\n, trailing whitespace per line removed, blank lines dropped (robust to how the text was
    written on Windows or Linux)."""
    lines = [ln.rstrip() for ln in s.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    return "\n".join(ln for ln in lines if ln)


def name_variants(package: str, version: str) -> list[str]:
    base = package.split("@")[-1] if package.startswith("@") else package
    names = {package, base, package.replace("@", "").replace("/", "-")}
    for n in list(names):
        names |= {n.replace("-", "_"), n.replace("_", "-"), n.replace("-", ""), n.replace(".", "-")}
    out = sorted((n for n in names if len(n) >= 3), key=len, reverse=True)
    if version and len(version) >= 3:
        out.append(version)
    return out


def name_normalised(text: str, package: str, version: str) -> str:
    for n in name_variants(package, version):
        text = re.sub(re.escape(n), "\u2400", text, flags=re.I)
    return text


def fingerprints(files: dict[str, str], package: str, version: str) -> set[tuple[str, str]]:
    """{(kind, value)}: kind "file" (sha256 of the normalised text of a code file), "named" (sha256 after replacing
    the item's package name variants and version), "host" (URL or OAST hostname not in COMMON_HOSTS)."""
    out = set()
    for path, body in files.items():
        if PurePosixPath(path).suffix.lower() not in CODE_EXT and PurePosixPath(path).name != "setup.py":
            continue
        norm = normalise_text(body)
        if len(norm) >= MIN_FILE_CHARS:
            out.add(("file", hashlib.sha256(norm.encode("utf-8")).hexdigest()))
            out.add(("named", hashlib.sha256(name_normalised(norm, package, version).encode("utf-8")).hexdigest()))
        for rx in (HOST_RE, OAST_HOST_RE):
            for m in rx.finditer(body):
                h = m.group(1).lower().rstrip(".")
                if h not in COMMON_HOSTS and not h.endswith((".github.io", ".githubusercontent.com")):
                    out.add(("host", h))
    return out


def bucket(files: dict[str, str], ecosystem: str) -> str:
    """'npm install hook' (the shallowest package.json declares preinstall/install/postinstall), 'PyPI setup.py'
    (a setup.py is present), else 'other'."""
    if ecosystem == "npm":
        pjs = sorted((p for p in files if PurePosixPath(p).name == "package.json"), key=lambda p: (p.count("/"), p))
        if pjs:
            try:
                scripts = (json.loads(files[pjs[0]]) or {}).get("scripts") or {}
            except (ValueError, AttributeError):
                scripts = {}
            if isinstance(scripts, dict) and any(isinstance(scripts.get(k), str) for k in ("preinstall", "install", "postinstall")):
                return "npm install hook"
        return "other"
    return "PyPI setup.py" if any(PurePosixPath(p).name == "setup.py" for p in files) else "other"


def read_sample_text(samples_root: Path, sample_dir: str) -> dict[str, str]:
    import run_benchmark as RB
    return RB.load_sample_dir(sample_dir, samples_root)["text"]


# ------------------------------------------------------------------ io
def write_csv(path: Path, rows: list[dict], note: str, cols: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = cols or (list(rows[0].keys()) if rows else ["empty"])
    with open(path, "w", newline="", encoding="utf-8") as fh:
        fh.write(f"# {note}\n")
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def dev76_ids(path: Path = ERROR_ANALYSIS) -> list[str]:
    """The 76 items developed against: the two error-analysis buckets 'setup.py present ... no hook pattern matched'
    and 'install hook declared ... no finding' (ERROR_ANALYSIS.md of run 2)."""
    text = path.read_text(encoding="utf-8")
    out = []
    for head in ("### setup.py present", "### install hook declared"):
        i = text.index(head)
        j = text.index("\n### ", i + 1)
        out += re.findall(r"^\| (DD-[^ |]+) \|", text[i:j], re.M)
    return out


# ------------------------------------------------------------------ select-bad
def select_bad(dataset: Path) -> list[dict]:
    import extract_datadog as XD
    import fetch_datadog_subset as FD
    commit = FD.git(dataset, "rev-parse", "HEAD").decode().strip()
    if commit != DATASET_COMMIT:
        raise SystemExit(f"dataset clone is at {commit}, the fresh selection is pinned to {DATASET_COMMIT}")
    blobs = FD.tree_blobs(dataset)
    listing = sorted((s for s in (XD.parse_sample_path(p) for p in blobs if p.endswith(".zip")) if s),
                     key=lambda s: s["sample_path"])
    v1 = bench_items.read_manifest(bench_items.MAN / "datadog_extracted.csv")
    v1_paths = {r["sample_path"] for r in v1}
    v1_blobs = {blobs[p] for p in v1_paths if p in blobs}
    v1_pkgs = {(r["ecosystem"], bench_items.package_key(r["ecosystem"], r["package"])) for r in v1}
    v1_pkgs |= {(r["ecosystem"], bench_items.package_key(r["ecosystem"], r["package"]))
                for r in bench_items.read_manifest(bench_items.MAN / "known_bad_candidates.csv")}
    chosen = []
    for eco_dir in ("pypi", "npm"):
        pool = [s for s in listing if s["eco_dir"] == eco_dir and s["sample_path"] not in v1_paths
                and blobs[s["sample_path"]] not in v1_blobs
                and (s["ecosystem"], bench_items.package_key(s["ecosystem"], s["package"])) not in v1_pkgs]
        order = list(pool)
        random.Random(FRESH_SEED).shuffle(order)
        taken_blobs, taken_pkgs, n = set(), set(), 0
        for s in order:
            if n >= N_PER_ECO:
                break
            pk = bench_items.package_key(s["ecosystem"], s["package"])
            if blobs[s["sample_path"]] in taken_blobs or pk in taken_pkgs:
                continue
            taken_blobs.add(blobs[s["sample_path"]])
            taken_pkgs.add(pk)
            chosen.append({"ecosystem": s["ecosystem"], "eco_dir": eco_dir, "kind": s["kind"], "package": s["package"],
                           "version": s["version"], "sample_path": s["sample_path"], "git_blob": blobs[s["sample_path"]],
                           "pool_size": len(pool)})
            n += 1
    return chosen


# ------------------------------------------------------------------ select-good
def select_good(snapshot: str = "2026-11-10") -> tuple[list[dict], list[str]]:
    os.environ.setdefault("REPOHEALTH_CACHE", str(BENCH / "cache" / "http"))
    os.environ["REPOHEALTH_SNAPSHOT"] = snapshot
    import select_items as SI
    SI.PROTOCOL_DATE = datetime(2026, 11, 10, tzinfo=timezone.utc)
    SI.N_GOOD_PER_ECO, SI.N_DORMANT_PER_ECO = N_GOOD_PER_ECO, 0
    ex_repos, ex_pkgs = SI.exclusions()
    dev = bench_items.dev_sets()
    ex_repos |= set(dev["repos"])
    ex_pkgs |= set(dev["packages"])
    for f in ("known_good.csv", "known_good_dormant.csv", "known_good_scary.csv", "known_bad_candidates.csv"):
        for r in bench_items.read_manifest(bench_items.MAN / f):
            ex_pkgs.add((r.get("package") or "").lower())
            if r.get("repo"):
                ex_repos.add(r["repo"].lower())
    ex_pkgs.discard("")
    ex_repos.discard("")
    lists = SI.popularity_lists()
    good, _dormant, notes = SI.known_good(random.Random(FRESH_SEED), lists, ex_repos, ex_pkgs)
    meta = lists["_meta"]
    notes.insert(0, f"popularity lists: hugovk last_update {meta.get('pypi_last_update')} ({meta.get('pypi_source')}); "
                    f"npm-high-impact top {SI.TOP_N}; exclusions {len(ex_pkgs)} packages, {len(ex_repos)} repositories")
    for r in good:
        r["category"] = "fresh_known_good"
    return good, notes


# ------------------------------------------------------------------ fetch / extract
def fetch(clone: Path, max_mb: float, dry_run: bool) -> int:
    import extract_datadog as XD
    import fetch_datadog_subset as FD
    sel = bench_items.read_manifest(SELECTION)
    commit = FD.ensure_clone(clone, FD.DATASET_URL)
    if commit != DATASET_COMMIT:
        print(f"REFUSING: the clone in {clone} is at {commit}, the fresh selection is pinned to {DATASET_COMMIT}. "
              "Use the existing C:\\bench\\dd clone (made for run 1/2) or a new folder.", file=sys.stderr)
        return 2
    blobs = FD.tree_blobs(clone)
    bad = [s for s in sel if blobs.get(s["sample_path"]) != s["git_blob"]]
    if bad:
        print(f"REFUSING: {len(bad)} selected path(s) have another blob id in the clone, e.g. {bad[0]['sample_path']}",
              file=sys.stderr)
        return 2
    mapping = XD.load_mapping(clone)

    def stored_ok(s):
        m = mapping.get(s["sample_path"])
        return bool(m) and (clone / m["safe_path"]).is_file() and m.get("git_blob") == s["git_blob"]
    todo = [s for s in sel if not stored_ok(s)]
    sizes = FD.head_sizes([s["sample_path"] for s in todo], commit) if todo else {}
    chk = FD.size_check([s["sample_path"] for s in todo], sizes, max_mb)
    print(f"fresh selection: {len(sel)} ZIPs; already stored {len(sel) - len(todo)}; to download {len(todo)} "
          f"({chk['mb_total']:.1f} MB; limit {max_mb:.0f} MB)")
    if dry_run:
        print("dry run: nothing downloaded")
        return 0
    if not chk["ok"]:
        print("REFUSING TO DOWNLOAD: above --max-mb", file=sys.stderr)
        return 3
    todo_s = [{**s, "eco_dir": s["eco_dir"]} for s in todo]
    got = FD.obtain(clone, commit, FD.DATASET_URL, todo_s, {s["sample_path"]: s["git_blob"] for s in sel}, "https")
    for s in todo_s:
        if s["sample_path"] not in got:
            continue
        data, how = got[s["sample_path"]]
        rel = FD.store(clone, s, data)
        why = FD.windows_unsafe(s["sample_path"])
        mapping[s["sample_path"]] = {"original_path": s["sample_path"], "safe_path": rel, "size": len(data),
                                     "sha256": hashlib.sha256(data).hexdigest(), "git_blob": s["git_blob"],
                                     "method": how, "note": f"unsafe name, obtained via {how} ({why})" if why else ""}
    XD.write_mapping(clone, mapping)
    missing = [s["sample_path"] for s in sel if not stored_ok(s)]
    print(f"done: {len(sel) - len(missing)} of {len(sel)} stored, each verified against its git blob id"
          + (f"; {len(missing)} missing (download error or antivirus), e.g. {missing[0]}" if missing else ""))
    return 0 if not missing else 1


def extract(dataset: Path, samples_root: Path) -> int:
    import extract_datadog as XD
    sel = bench_items.read_manifest(SELECTION)
    mapping = XD.load_mapping(dataset)
    rows, member_rows = [], []
    for k, s in enumerate(sel, 1):
        r = {**s, "file": PurePosixPath(s["sample_path"]).name}
        base = {"ecosystem": r["ecosystem"], "package": r["package"], "version": r["version"], "kind": r["kind"],
                "sample_path": r["sample_path"], "selected_by": "fresh_random", "dataset_commit": DATASET_COMMIT,
                "storage_note": (mapping.get(r["sample_path"]) or {}).get("note", "")}
        zpath = XD.sample_location(dataset, r["sample_path"], mapping)
        if not zpath.is_file():
            rows.append({**base, "id": f"DD-{r['ecosystem']}-{r['package']}-{r['version']}-notfetched", "zip_sha256": "",
                         "zip_bytes": "", "status": "not fetched", "reason": "selected but not on disk",
                         "sample_dir": "", "members_total": "", "text_written": 0, "bytes_written": 0, "skipped": "",
                         "limits_hit": ""})
            continue
        blob = zpath.read_bytes()
        import fetch_datadog_subset as FD
        if FD.blob_id(blob) != s["git_blob"]:
            rows.append({**base, "id": f"DD-{r['ecosystem']}-{r['package']}-{r['version']}-blobmismatch", "zip_sha256": "",
                         "zip_bytes": len(blob), "status": "skipped", "reason": "ZIP does not match its git blob id",
                         "sample_dir": "", "members_total": "", "text_written": 0, "bytes_written": 0, "skipped": "",
                         "limits_hit": ""})
            continue
        zsha = hashlib.sha256(blob).hexdigest()
        sid = XD.sample_id(r, zsha)
        res = XD.read_sample(blob)
        dest = XD.sample_dir_for(r, zsha, samples_root)
        n = nb = 0
        if not res.get("error") and res["text"]:
            n, nb = XD.write_sample(res["text"], dest)
        skipped = Counter(m["reason"].split(" (")[0] for m in res["members"] if m["action"] == "skipped")
        member_rows += [{"id": sid, **m} for m in res["members"]]
        rows.append({**base, "id": sid, "zip_sha256": zsha, "zip_bytes": len(blob),
                     "status": "extracted" if n else "skipped", "reason": res.get("error") or ("" if n else "no text members"),
                     "sample_dir": dest.relative_to(samples_root).as_posix() if n else "",
                     "members_total": len(res["members"]), "text_written": n, "bytes_written": nb,
                     "skipped": "; ".join(f"{a}: {b}" for a, b in sorted(skipped.items())), "limits_hit": "; ".join(res["limits"])})
        print(f"[{k}/{len(sel)}] {sid}: {rows[-1]['status']}, {n} text file(s)")
    cols = ["id", "ecosystem", "package", "version", "kind", "sample_path", "selected_by", "zip_sha256", "zip_bytes",
            "status", "reason", "sample_dir", "members_total", "text_written", "bytes_written", "skipped", "limits_hit",
            "dataset_commit", "storage_note"]
    note = (f"DataDog FRESH samples extracted as inert text (.sample) | dataset commit {DATASET_COMMIT} | seed {FRESH_SEED} | "
            "method: benchmark/PREREG_v2.md | samples themselves are NOT committed")
    write_csv(EXTRACTED, rows, note, cols)
    write_csv(MEMBERS, member_rows, note, ["id", "member", "size", "action", "reason", "sha256"])
    print(f"wrote {EXTRACTED} ({len(rows)} rows) and {MEMBERS} ({len(member_rows)} rows)")
    return 0


# ------------------------------------------------------------------ fingerprints and facts
def dev_fingerprints(samples_root: Path, extracted_csv: Path) -> list[dict]:
    ids = set(dev76_ids())
    rows, read = [], set()
    for r in bench_items.read_manifest(extracted_csv):
        if r["id"] not in ids:
            continue
        files = read_sample_text(samples_root, r["sample_dir"])
        if files:
            read.add(r["id"])
        for kind, value in sorted(fingerprints(files, r["package"], r["version"])):
            rows.append({"dev_id": r["id"], "kind": kind, "value": value})
    if ids - read:   # an item with files but no fingerprint (all files tiny, no host) is fine; an empty folder is not
        raise SystemExit(f"{len(ids - read)} dev item(s) have no sample files: {sorted(ids - read)[:3]}")
    return rows


def facts(samples_root: Path) -> list[dict]:
    fp = {}
    for r in bench_items.read_manifest(FINGERPRINTS):
        fp.setdefault((r["kind"], r["value"]), set()).add(r["dev_id"])
    out = []
    for r in bench_items.read_manifest(EXTRACTED):
        if r.get("status") != "extracted":
            continue
        files = read_sample_text(samples_root, r["sample_dir"])
        mine = fingerprints(files, r["package"], r["version"])
        hits = sorted({(k, v, d) for k, v in mine for d in fp.get((k, v), ())})
        reasons = sorted({k for k, _v, _d in hits})
        out.append({"id": r["id"], "ecosystem": r["ecosystem"], "kind": r["kind"], "bucket": bucket(files, r["ecosystem"]),
                    "near_duplicate": "yes" if hits else "no", "near_duplicate_rules": ";".join(reasons),
                    "near_duplicate_of": ";".join(sorted({d for *_x, d in hits}))[:500],
                    "files_read": len(files)})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fresh held-out set for ruleset v2 (PREREG_v2.md)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a1 = sub.add_parser("select-bad")
    a1.add_argument("--dataset", required=True, help="tree-only clone of the DataDog dataset at the pinned commit")
    sub.add_parser("select-good").add_argument("--snapshot", default="2026-11-10")
    a3 = sub.add_parser("dev-fingerprints")
    a3.add_argument("--samples-dir", required=True)
    a3.add_argument("--extracted", default=str(bench_items.MAN / "datadog_extracted.csv"))
    a4 = sub.add_parser("fetch")
    a4.add_argument("--dir", required=True)
    a4.add_argument("--max-mb", type=float, default=2000)
    a4.add_argument("--dry-run", action="store_true")
    a5 = sub.add_parser("extract")
    a5.add_argument("--dataset", required=True)
    a5.add_argument("--samples-dir", required=True)
    a6 = sub.add_parser("facts")
    a6.add_argument("--samples-dir", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "select-bad":
        rows = select_bad(Path(a.dataset))
        c = Counter(r["ecosystem"] for r in rows)
        pools = {r["ecosystem"]: r["pool_size"] for r in rows}
        write_csv(SELECTION, rows, f"Fresh known-bad selection | dataset commit {DATASET_COMMIT} | seed {FRESH_SEED} | "
                  f"{N_PER_ECO} per ecosystem, one per package | pool sizes {pools} | rules: benchmark/PREREG_v2.md")
        print(f"selected {len(rows)}: {dict(c)}; eligible pool {pools}")
    elif a.cmd == "select-good":
        rows, notes = select_good(a.snapshot)
        write_csv(GOOD, rows, f"Fresh known-good: select_items.known_good, seed {FRESH_SEED}, protocol date 2026-11-10, "
                  f"{N_GOOD_PER_ECO} per ecosystem, every v1 known-good/dormant/scary/dev package and repository excluded "
                  f"| snapshot {a.snapshot}")
        (FRESH / "known_good_notes.txt").write_text("\n".join(notes) + "\n", encoding="utf-8")
        print(f"selected {len(rows)}: {dict(Counter(r['ecosystem'] for r in rows))}")
    elif a.cmd == "dev-fingerprints":
        rows = dev_fingerprints(Path(a.samples_dir), Path(a.extracted))
        write_csv(FINGERPRINTS, rows, "Near-duplicate fingerprints of the 76 error-analysis (dev) items: sha256 of normalised "
                  "code files (file), the same after replacing package name/version (named), and non-common hosts (host)")
        print(f"{len(rows)} fingerprints for {len({r['dev_id'] for r in rows})} dev items")
    elif a.cmd == "fetch":
        return fetch(Path(a.dir).resolve(), a.max_mb, a.dry_run)
    elif a.cmd == "extract":
        return extract(Path(a.dataset).resolve(), Path(a.samples_dir).resolve())
    elif a.cmd == "facts":
        rows = facts(Path(a.samples_dir).resolve())
        write_csv(FACTS, rows, "Fresh known-bad pre-scan facts: bucket and near-duplicate flag vs the 76 dev items "
                  "(rules: benchmark/PREREG_v2.md section 4); computed from the extracted text, no scan")
        c = Counter((r["bucket"], r["near_duplicate"]) for r in rows)
        print(f"{len(rows)} items: " + ", ".join(f"{b} / near-dup {d}: {n}" for (b, d), n in sorted(c.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
