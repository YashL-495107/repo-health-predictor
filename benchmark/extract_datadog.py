"""Extract known-bad samples from a LOCAL clone of the DataDog malicious-software-packages dataset, as inert text.

Format (verified 2026-11-08 from the dataset README and the ZIP headers of one sample, nothing decrypted):
  samples/<pypi|npm>/<malicious_intent|compromised_lib>/<package>/<version>/<discovery-date>-<package>-v<version>.zip
  Each ZIP is encrypted with the legacy ZipCrypto scheme (general-purpose flag bit 0; deflate or stored members,
  no AES), password "infected" (README). Python's zipfile reads it in memory with that password.
  npm scoped packages use two directory levels for the package name (@scope/name).

Handling rules (static analysis only):
  - archives are read IN MEMORY; nothing is extracted by an archive tool and nothing is ever executed, imported,
    installed or compiled;
  - only TEXT members are written, each renamed with a ".sample" suffix (so x.py -> x.py.sample, run.ps1 ->
    run.ps1.sample): no file is ever written under an executable extension;
  - executables and other binaries are skipped by magic bytes (MZ, ELF, Mach-O, Java class) or NUL bytes;
  - path traversal (absolute paths, "..", drive letters, ":"), Windows reserved names and over-long paths are
    rejected or shortened; member count, per-member size, total decompressed size and compression ratio are capped,
    and the bytes actually read are bounded (declared sizes can lie);
  - nested archives (sdist .tar.gz, .tgz, .whl, .zip) are read in memory with releases.read_archive (same limits).
Output goes to the samples folder (--samples-dir; default benchmark/samples/, git-ignored); the manifest stores
sample paths relative to that folder, so run_benchmark.py must get the same --samples-dir. Committed: manifests/datadog_extracted.csv (one row per sample:
id, hashes, sizes, members skipped and why) and manifests/datadog_members.csv (per member: action and reason, hash).

Selection (pre-declared in benchmark/README.md section 6, before any result; amended 2026-11-08 before any test scan):
every sample whose (ecosystem, package, version) matches a candidate in known_bad_candidates.csv (shared name and
version normalisation, no substitute version), plus 150 sample files per ecosystem drawn with random.Random(20261107)
(a fresh generator per ecosystem, pypi first) from the path-sorted FULL listing (from git in a clone, so a sparse
clone gives the same draw). The union is extracted, without duplicates; selected files not on disk are recorded as
"not fetched".

Usage:  python benchmark/extract_datadog.py --dataset C:\\path\\to\\malicious-software-packages-dataset [--dry-run]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import os
import random
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
for p in (str(ROOT), str(BENCH)):
    if p not in sys.path:
        sys.path.insert(0, p)

import bench_items  # noqa: E402

SEED = 20261107
N_RANDOM_PER_ECO = 150
PASSWORD = b"infected"
ECOS = {"pypi": "PyPI", "npm": "npm"}
DEFAULT_SAMPLES = BENCH / "samples"   # git-ignored; --samples-dir points elsewhere (a dedicated folder)
MANIFEST = bench_items.MAN / "datadog_extracted.csv"
MEMBERS = bench_items.MAN / "datadog_members.csv"

MAX_ZIP_BYTES = 50 * 1024 * 1024
MAX_MEMBERS = 3000
MAX_MEMBER_BYTES = 1_000_000          # per text member (read at most this + 1 bytes)
MAX_TOTAL_BYTES = 50 * 1024 * 1024    # decompressed bytes read per sample
MAX_RATIO = 200                       # declared size / compressed size, for members above 1 MB declared
MAX_PATH_CHARS = 180                  # relative path length under the sample directory (Windows MAX_PATH margin)
NESTED_EXT = (".tar.gz", ".tgz", ".whl", ".zip", ".egg", ".tar")
EXEC_MAGIC = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
              b"\xca\xfe\xba\xbe")
WIN_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
DEFENDER_WARNING = """\
WARNING (Windows Defender / antivirus): this script reads REAL MALWARE samples. They stay inside the encrypted ZIPs
and are only read in memory; what is written to the samples folder is text renamed *.sample, never executable.
  - Do NOT disable your antivirus globally.
  - Your antivirus may quarantine the dataset clone or some .sample files (they can contain known malicious strings).
    A per-folder exclusion for the dataset folder and the samples folder is at your discretion; remove it when the
    benchmark is done. Quarantined files simply become "not obtainable" items.
  - Use a dedicated folder (--samples-dir, e.g. C:\\bench\\samples), not Downloads and not a cloud-synced folder.
  - Never open, run, install or double-click anything in these folders."""


# ------------------------------------------------------------------ listing and selection

def dataset_commit(dataset: Path) -> str:
    """HEAD commit of the clone, read from .git without running git."""
    g = dataset / ".git"
    try:
        head = (g / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref:"):
            return head
        ref = head.split(" ", 1)[1].strip()
        if (g / ref).exists():
            return (g / ref).read_text(encoding="utf-8").strip()
        packed = g / "packed-refs"
        if packed.exists():
            for line in packed.read_text(encoding="utf-8").splitlines():
                if line.endswith(" " + ref):
                    return line.split(" ", 1)[0]
    except OSError:
        pass
    return "unknown"


def parse_sample_path(rel: str) -> dict | None:
    """samples/<eco>/<kind>/<package...>/<version>/<file>.zip -> fields (None if it does not match)."""
    parts = rel.split("/")
    if len(parts) < 6 or parts[0] != "samples" or parts[1] not in ECOS or not parts[-1].endswith(".zip"):
        return None
    return {"eco_dir": parts[1], "ecosystem": ECOS[parts[1]], "kind": parts[2], "package": "/".join(parts[3:-2]),
            "version": parts[-2], "file": parts[-1], "sample_path": rel}


SUBSET_DIR = "subset"                 # <dataset>/subset/<eco>/<category>/<sha1 of original path>.zip
MAPPING_FIELDS = ["original_path", "safe_path", "size", "sha256", "git_blob", "method", "note"]


def safe_sample_path(r: dict) -> str:
    """Windows-compatible flat storage name of a sample ZIP (relative to the dataset folder). The original dataset path is
    never created on disk: some cannot exist on Windows (names ending in '.', reserved names)."""
    h = hashlib.sha1(r["sample_path"].encode("utf-8", "surrogateescape")).hexdigest()
    return f"{SUBSET_DIR}/{r['eco_dir']}/{safe_component(r['kind'], 40)}/{h}.zip"


def load_mapping(dataset: Path) -> dict[str, dict]:
    """{original path: row} from <dataset>/subset/mapping.csv (written by fetch_datadog_subset.py); {} without it."""
    p = Path(dataset) / SUBSET_DIR / "mapping.csv"
    if not p.is_file():
        return {}
    with open(p, newline="", encoding="utf-8") as fh:
        return {r["original_path"]: r for r in csv.DictReader(fh)}


def write_mapping(dataset: Path, mapping: dict[str, dict]) -> None:
    p = Path(dataset) / SUBSET_DIR / "mapping.csv"
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name("mapping.csv.part")
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=MAPPING_FIELDS)
        w.writeheader()
        w.writerows(sorted(mapping.values(), key=lambda r: r["original_path"]))
    os.replace(tmp, p)


def sample_location(dataset: Path, rel: str, mapping: dict[str, dict] | None = None) -> Path:
    """Where a sample ZIP is on disk: its storage name from the subset mapping when there is one, else its original path
    (a plain folder or a full clone)."""
    m = (mapping if mapping is not None else load_mapping(dataset)).get(rel)
    return Path(dataset) / (m["safe_path"] if m else rel)


def git_listing(dataset: Path) -> list[str] | None:
    """Every sample ZIP path in the clone's HEAD tree, from git (tree objects only: `ls-tree --name-only` never needs
    the file contents, so it works on a partial clone without downloading anything; -z keeps any path unquoted).
    None when the dataset folder is not a git repository or git is unavailable."""
    if not (dataset / ".git").exists():
        return None
    import subprocess
    try:
        out = subprocess.run(["git", "-C", str(dataset), "-c", "core.quotepath=off", "ls-tree", "-r", "-z", "--name-only",
                              "HEAD", "--", "samples/pypi", "samples/npm"],
                             capture_output=True, timeout=600, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    paths = [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]
    return [p for p in paths if p.endswith(".zip")]


def list_samples(dataset: Path) -> list[dict]:
    """All sample ZIPs of the dataset, path-sorted, each with present=True when the file is on disk (at its storage
    name from the subset mapping, or at its original path). In a git clone the listing comes from git, so a partial
    clone (fetch_datadog_subset.py) still sees the FULL dataset listing and the pre-declared random draw is the same
    as on a full clone; otherwise the folder is walked."""
    paths = git_listing(dataset)
    if paths is None:
        paths = []
        for eco_dir in ECOS:
            base = dataset / "samples" / eco_dir
            if base.is_dir():
                paths += [p.relative_to(dataset).as_posix() for p in base.rglob("*.zip")]
    mapping = load_mapping(dataset)
    out = []
    for rel in paths:
        info = parse_sample_path(rel)
        if info:
            out.append({**info, "present": sample_location(dataset, rel, mapping).is_file()})
    return sorted(out, key=lambda r: r["sample_path"])


def candidate_keys(rows: list[dict]) -> set[tuple[str, str, str]]:
    """(ecosystem, package key, version key) of the known-bad candidates; rows without a version cannot match a
    version-level sample (since the pre-run amendment of 2026-11-08: no other version is substituted)."""
    return {(r["ecosystem"], bench_items.package_key(r["ecosystem"], r["package"]),
             bench_items.version_key(r["ecosystem"], r["version"])) for r in rows if (r.get("version") or "").strip()}


def sample_key(r: dict) -> tuple[str, str, str]:
    return (r["ecosystem"], bench_items.package_key(r["ecosystem"], r["package"]),
            bench_items.version_key(r["ecosystem"], r["version"]))


def select_samples(listing: list[dict], candidates: set[tuple[str, str, str]], n_random: int = N_RANDOM_PER_ECO,
                   seed: int = SEED) -> list[dict]:
    """Pre-declared selection (README section 6, amended 2026-11-08 before any test scan): every sample whose
    (ecosystem, package, VERSION) matches a known-bad candidate (shared name/version keys), plus n_random sample
    files per ecosystem drawn with a fresh random.Random(seed) from the path-sorted FULL listing."""
    chosen: dict[str, dict] = {}
    for r in listing:
        if sample_key(r) in candidates:
            chosen[r["sample_path"]] = {**r, "selected_by": "candidate"}
    for eco_dir in ECOS:   # pypi first, then npm; a fresh generator per ecosystem
        pool = [r for r in listing if r["eco_dir"] == eco_dir]
        for r in random.Random(seed).sample(pool, min(n_random, len(pool))):
            prev = chosen.get(r["sample_path"])
            chosen[r["sample_path"]] = {**r, "selected_by": "candidate+random" if prev else "random"}
    return [chosen[k] for k in sorted(chosen)]


# ------------------------------------------------------------------ file names

def safe_component(name: str, limit: int = 60) -> str:
    s = re.sub(r"[^A-Za-z0-9._@+-]", "_", name).strip(" .") or "_"
    if s.split(".")[0].lower() in WIN_RESERVED:
        s = "_" + s
    if len(s) > limit:
        h = hashlib.sha256(name.encode()).hexdigest()[:8]
        s = s[: limit - 9] + "~" + h
    return s


def safe_member_path(name: str) -> tuple[str | None, str | None]:
    """Archive member name -> a sanitised relative POSIX path, or (None, reason) when it must be rejected."""
    n = name.replace("\\", "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return None, "absolute path"
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None, "path traversal (..)"
    if any(":" in p for p in parts):
        return None, "':' in name (drive letter or alternate data stream)"
    if not parts:
        return None, "empty name"
    cleaned_path = "/".join(safe_component(p) for p in parts)
    if len(cleaned_path) > MAX_PATH_CHARS:
        h = hashlib.sha256(n.encode()).hexdigest()[:10]
        cleaned_path = f"_long/{h}_{safe_component(parts[-1], 60)}"
    return cleaned_path, None


def strip_common_root(paths: list[str], max_levels: int = 3) -> int:
    """Number of leading components shared by every path (each path keeps at least its file name)."""
    k = 0
    while k < max_levels and paths:
        tops = {p.split("/")[k] if len(p.split("/")) > k + 1 else None for p in paths}
        if len(tops) != 1 or None in tops:
            break
        k += 1
    return k


def is_binary(head: bytes) -> str | None:
    if head.startswith(EXEC_MAGIC) or head[:4] == b"\xca\xfe\xd0\x0d":   # PE, ELF, Mach-O, Java class, pack200
        return "executable (magic bytes)"
    if b"\x00" in head[:2000]:
        return "binary (NUL bytes)"
    return None


# ------------------------------------------------------------------ extraction (in memory)

def read_sample(blob: bytes, password: bytes = PASSWORD) -> dict:
    """Read one encrypted sample ZIP in memory. Returns {"text": {safe_path: str}, "members": [rows], "limits": []}.
    Nothing is written here."""
    import releases
    out = {"text": {}, "members": [], "limits": []}
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as e:
        out["error"] = f"bad zip ({e})"
        return out
    infos = zf.infolist()
    if len(infos) > MAX_MEMBERS:
        out["limits"].append(f"member count {len(infos)} > {MAX_MEMBERS}")
        infos = infos[:MAX_MEMBERS]
    total = 0

    def rec(member, size, action, reason="", sha=""):
        out["members"].append({"member": member[:300], "size": size, "action": action, "reason": reason, "sha256": sha})

    for i in infos:
        if i.is_dir():
            continue
        path, why = safe_member_path(i.filename)
        if why:
            rec(i.filename, i.file_size, "skipped", why)
            continue
        if total + min(i.file_size, MAX_MEMBER_BYTES + 1) > MAX_TOTAL_BYTES:
            out["limits"].append(f"total decompressed bytes > {MAX_TOTAL_BYTES}")
            rec(i.filename, i.file_size, "skipped", "total size limit reached")
            break
        if i.file_size > (1 << 20) and i.compress_size and i.file_size / i.compress_size > MAX_RATIO:
            rec(i.filename, i.file_size, "skipped", f"compression ratio above {MAX_RATIO} (archive bomb guard)")
            continue
        nested = i.filename.lower().endswith(NESTED_EXT)
        limit = MAX_ZIP_BYTES if nested else MAX_MEMBER_BYTES
        try:
            with zf.open(i, pwd=password if i.flag_bits & 0x1 else None) as fh:
                data = fh.read(limit + 1)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError, EOFError) as e:
            rec(i.filename, i.file_size, "skipped", f"unreadable ({type(e).__name__})")
            continue
        total += len(data)
        sha = hashlib.sha256(data).hexdigest()
        if len(data) > limit:
            rec(i.filename, i.file_size, "skipped", f"larger than {limit} bytes", sha)
            continue
        if nested:
            kind = "sdist" if i.filename.lower().endswith((".tar.gz", ".tgz", ".tar")) else "wheel"
            inner = releases.read_archive(data, kind)
            if inner.get("error"):
                rec(i.filename, i.file_size, "skipped", f"nested archive unreadable ({inner['error']})", sha)
                continue
            rec(i.filename, i.file_size, "nested_archive", f"{len(inner['text'])} text members read in memory", sha)
            for b in inner.get("binaries") or []:
                rec(f"{i.filename}!{b['path']}", b.get("size"), "skipped", "executable (magic bytes)", b.get("sha256") or "")
            for m in inner.get("skipped") or []:
                rec(f"{i.filename}!{m}", None, "skipped", "nested archive size limit")
            if inner.get("limits_hit"):
                out["limits"].append(f"nested {i.filename}: {', '.join(inner['limits_hit'])}")
            stem = safe_component(re.sub(r"(\.tar\.gz|\.tgz|\.whl|\.zip|\.egg|\.tar)$", "", PurePosixPath(path).name, flags=re.I))
            for mpath, text in inner["text"].items():
                sp, why = safe_member_path(mpath)
                if why:
                    rec(f"{i.filename}!{mpath}", None, "skipped", why)
                    continue
                full = f"{path.rsplit('/', 1)[0] + '/' if '/' in path else ''}{stem}/{sp}"
                out["text"][full] = text
                rec(f"{i.filename}!{mpath}", len(text.encode("utf-8", "ignore")), "written", "text (from nested archive)",
                    hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest())
            continue
        kind = is_binary(data[:4096])
        if kind:
            rec(i.filename, i.file_size, "skipped", kind, sha)
            continue
        out["text"][path] = data.decode("utf-8", "ignore")
        rec(i.filename, len(data), "written", "text", sha)
    return out


def write_sample(text: dict[str, str], dest: Path) -> tuple[int, int]:
    """Write text members as <path>.sample under dest (common top-level directories stripped). Returns (files, bytes)."""
    paths = sorted(text)
    k = strip_common_root(paths)
    dest_r = dest.resolve()
    n = b = 0
    for p in paths:
        rel = "/".join(p.split("/")[k:])
        target = (dest / (rel + ".sample")).resolve()
        if dest_r not in target.parents:          # defence in depth: never outside the sample directory
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        data = text[p].encode("utf-8")
        target.write_bytes(data)
        n += 1
        b += len(data)
    return n, b


def sample_id(r: dict, zip_sha: str) -> str:
    return f"DD-{r['ecosystem']}-{r['package']}-{r['version']}-{zip_sha[:8]}"


def sample_dir_for(r: dict, zip_sha: str, samples_root: Path = DEFAULT_SAMPLES) -> Path:
    name = f"{safe_component(r['package'].replace('/', '__'), 50)}_{safe_component(r['version'], 30)}_{zip_sha[:8]}"
    return Path(samples_root) / "datadog" / r["eco_dir"] / name


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Extract DataDog samples as inert text (.sample)")
    ap.add_argument("--dataset", required=True, help="local clone of DataDog/malicious-software-packages-dataset")
    ap.add_argument("--dry-run", action="store_true", help="list and select only; read and write nothing")
    ap.add_argument("--limit", type=int, default=None, help="extract at most N samples (debugging)")
    ap.add_argument("--samples-dir", default=None, help="where the .sample text goes (default benchmark/samples, "
                    "git-ignored); use a dedicated folder outside Downloads; pass the same folder to run_benchmark.py")
    a = ap.parse_args(argv)
    print(DEFENDER_WARNING, "\n", file=sys.stderr)
    samples_root = Path(a.samples_dir or os.environ.get("REPOHEALTH_SAMPLES_DIR") or DEFAULT_SAMPLES).resolve()
    dataset = Path(a.dataset)
    if not ((dataset / "samples").is_dir() or (dataset / ".git").exists() or (dataset / SUBSET_DIR / "mapping.csv").is_file()):
        print(f"not a dataset folder (no samples/ folder, git clone or subset/mapping.csv): {dataset}", file=sys.stderr)
        return 2
    commit = dataset_commit(dataset)
    listing = list_samples(dataset)
    cands = candidate_keys(bench_items.read_manifest(bench_items.MAN / "known_bad_candidates.csv"))
    chosen = select_samples(listing, cands)
    missing = [r for r in chosen if not r.get("present", True)]
    if missing:
        print(f"{len(missing)} selected sample(s) are not on disk (sparse clone: run fetch_datadog_subset.py); they are "
              "recorded as 'not fetched'", file=sys.stderr)
    by = {}
    for r in chosen:
        by.setdefault((r["ecosystem"], r["selected_by"]), 0)
        by[(r["ecosystem"], r["selected_by"])] += 1
    print(f"dataset commit {commit}; {len(listing)} sample ZIPs listed; {len(chosen)} selected: "
          + ", ".join(f"{e} {s}: {n}" for (e, s), n in sorted(by.items())))
    if a.dry_run:
        for r in chosen[:20]:
            print(f"  {r['selected_by']:<16} {r['sample_path']}")
        print("dry run: nothing read or written")
        return 0
    if a.limit is not None:
        chosen = chosen[: a.limit]
    rows, member_rows = [], []
    mapping = load_mapping(dataset)
    for k, r in enumerate(chosen, 1):
        zpath = sample_location(dataset, r["sample_path"], mapping)   # storage name in a fetched subset
        if not zpath.is_file():
            rows.append({"ecosystem": r["ecosystem"], "package": r["package"], "version": r["version"], "kind": r["kind"],
                         "sample_path": r["sample_path"], "selected_by": r["selected_by"], "zip_bytes": "",
                         "dataset_commit": commit, "id": f"DD-{r['ecosystem']}-{r['package']}-{r['version']}-notfetched",
                         "zip_sha256": "", "status": "not fetched", "reason": "selected but not on disk (not in the fetched subset)",
                         "sample_dir": "", "members_total": "", "text_written": 0, "bytes_written": 0, "skipped": "",
                         "limits_hit": "", "storage_note": ""})
            continue
        size = zpath.stat().st_size
        base = {"ecosystem": r["ecosystem"], "package": r["package"], "version": r["version"], "kind": r["kind"],
                "sample_path": r["sample_path"], "selected_by": r["selected_by"], "zip_bytes": size,
                "dataset_commit": commit, "storage_note": (mapping.get(r["sample_path"]) or {}).get("note", "")}
        if size > MAX_ZIP_BYTES:
            rows.append({**base, "id": f"DD-{r['ecosystem']}-{r['package']}-{r['version']}-toolarge", "zip_sha256": "",
                         "status": "skipped", "reason": f"ZIP larger than {MAX_ZIP_BYTES} bytes", "sample_dir": "",
                         "members_total": "", "text_written": 0, "bytes_written": 0, "skipped": "", "limits_hit": ""})
            continue
        blob = zpath.read_bytes()
        zsha = hashlib.sha256(blob).hexdigest()
        sid = sample_id(r, zsha)
        res = read_sample(blob)
        dest = sample_dir_for(r, zsha, samples_root)
        n = nb = 0
        if not res.get("error") and res["text"]:
            n, nb = write_sample(res["text"], dest)
        skipped = {}
        for m in res["members"]:
            if m["action"] == "skipped":
                key = m["reason"].split(" (")[0]
                skipped[key] = skipped.get(key, 0) + 1
            member_rows.append({"id": sid, **m})
        status = "extracted" if n else "skipped"
        rows.append({**base, "id": sid, "zip_sha256": zsha, "status": status,
                     "reason": res.get("error") or ("" if n else "no text members"),
                     "sample_dir": dest.relative_to(samples_root).as_posix() if n else "", "members_total": len(res["members"]),
                     "text_written": n, "bytes_written": nb,
                     "skipped": "; ".join(f"{k2}: {v}" for k2, v in sorted(skipped.items())),
                     "limits_hit": "; ".join(res["limits"])})
        print(f"[{k}/{len(chosen)}] {sid}: {status}, {n} text file(s), skipped {sum(skipped.values())}")
    cols = ["id", "ecosystem", "package", "version", "kind", "sample_path", "selected_by", "zip_sha256", "zip_bytes",
            "status", "reason", "sample_dir", "members_total", "text_written", "bytes_written", "skipped", "limits_hit",
            "dataset_commit", "storage_note"]
    note = (f"# DataDog samples extracted as inert text (.sample) | dataset commit {commit} | seed {SEED} | "
            f"method: benchmark/README.md section 6 | samples themselves are NOT committed\n")
    with open(MANIFEST, "w", newline="", encoding="utf-8") as fh:
        fh.write(note)
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    with open(MEMBERS, "w", newline="", encoding="utf-8") as fh:
        fh.write(note)
        w = csv.DictWriter(fh, fieldnames=["id", "member", "size", "action", "reason", "sha256"])
        w.writeheader()
        w.writerows(member_rows)
    print(f"wrote {MANIFEST} ({len(rows)} rows) and {MEMBERS} ({len(member_rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
