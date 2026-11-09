"""fetch_datadog_subset.py against a tiny LOCAL git repository laid out like the DataDog dataset (no network: the clone
uses a file:// URL; sizes and HTTPS come from stubs). The repository is built with git plumbing (hash-object,
update-index --cacheinfo, write-tree, commit-tree), so it can hold paths Windows cannot (a name ending in ".", a
trailing space, a reserved name) on Linux AND on Windows: nothing in it is ever checked out. Sample ZIPs are synthetic,
encrypted like the dataset's, and inert."""
from __future__ import annotations

import csv
import gzip
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "benchmark"), str(ROOT / "tests")]

import bench_items  # noqa: E402
import extract_datadog as XD  # noqa: E402
import fetch_datadog_subset as F  # noqa: E402
from test_benchmark import _encrypted_zip  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "datadog"
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

SAMPLES = {   # path under samples/ -> package files inside the encrypted zip
    "pypi/malicious_intent/evil-pkg/1.0/2024-01-01-evil-pkg-v1.0.zip": {"setup.py": "x = 1\n"},
    "pypi/compromised_lib/goodlib/2.0/2024-02-01-goodlib-v2.0.zip": {"goodlib/__init__.py": "y = 2\n"},
    "pypi/compromised_lib/goodlib/2.1/2024-03-01-goodlib-v2.1.zip": {"goodlib/__init__.py": "y = 3\n"},
    "npm/malicious_intent/@sc/bad/0.0.1/2024-04-01-bad-v0.0.1.zip": {"package/index.js": "z()\n"},
    "npm/malicious_intent/lodash.merge/1.0.0/2024-05-01-lodash.merge-v1.0.0.zip": {"package/index.js": "w()\n"},
    "npm/malicious_intent/unrelated/9.9.9/2024-06-01-unrelated-v9.9.9.zip": {"package/index.js": "u()\n"},
    # Windows-unsafe original paths (the real dataset has npm names ending in "."):
    "npm/malicious_intent/mad-1.0.0.2.2.8./1.0.0/2025-09-27-mad-1.0.0.2.2.8.-v1.0.0.zip": {"package/index.js": "m()\n"},
    "pypi/malicious_intent/spacey /1.0/2024-07-01-spacey -v1.0.zip": {"setup.py": "s = 1\n"},
    "npm/malicious_intent/con/1.0.0/2024-08-01-con-v1.0.0.zip": {"package/index.js": "c()\n"},
}
UNSAFE = {p for p in SAMPLES if "mad-1.0.0.2.2.8." in p or "spacey " in p or "/con/" in p}
MANIFESTS = {"pypi": {"evil_pkg": None, "goodlib": ["2.0"], "spacey": None},
             "npm": {"@sc/bad": ["0.0.1"], "lodash.merge": None, "unrelated": None, "mad-1.0.0.2.2.8.": None, "con": None}}
CANDIDATES = [  # id, ecosystem, package, version
    ("MAL-1", "PyPI", "Evil_Pkg", "1.0.0"),        # name and PEP 440 version normalisation -> evil-pkg 1.0
    ("MAL-2", "PyPI", "goodlib", "2.0"),           # compromised_lib, listed version
    ("MAL-3", "PyPI", "goodlib", "3.0"),           # package present, version absent: no substitute
    ("MAL-4", "npm", "@sc/bad", "0.0.1"),          # scoped npm
    ("MAL-5", "npm", "lodash-merge", "1.0.0"),     # npm names are exact: lodash-merge is not lodash.merge
    ("MAL-6", "PyPI", "noversion", ""),            # advisory without a version
    ("MAL-7", "npm", "mad-1.0.0.2.2.8.", "1.0.0"), # Windows-unsafe: trailing dot
    ("MAL-8", "PyPI", "spacey", "1.0"),            # Windows-unsafe: trailing space in the dataset folder name
    ("MAL-9", "npm", "con", "1.0.0"),              # Windows-unsafe: reserved name
]
SELECTED = {p for p in SAMPLES if any(k in p for k in ("evil-pkg/1.0", "goodlib/2.0/", "@sc/bad", "mad-1.0.0.2.2.8.",
                                                        "spacey ", "/con/"))}


def _git(cwd, *args, data: bytes | None = None) -> str:
    return subprocess.run(["git", "-c", "core.protectNTFS=false", *args], cwd=cwd, check=True, capture_output=True,
                          input=data).stdout.decode().strip()


@pytest.fixture
def dataset(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _git(src, "init", "-q", "-b", "main")
    for k, v in (("uploadpack.allowFilter", "true"), ("uploadpack.allowAnySHA1InWant", "true"), ("core.protectNTFS", "false")):
        _git(src, "config", k, v)
    files = {f"samples/{rel}": _encrypted_zip({f"root/{k}": v.encode() for k, v in fs.items()}) for rel, fs in SAMPLES.items()}
    files.update({f"samples/{eco}/manifest.json": json.dumps(m).encode() for eco, m in MANIFESTS.items()})
    blob_of = {}
    for path, data in files.items():          # plumbing only: no file is created at the dataset path
        sha = _git(src, "hash-object", "-w", "--stdin", data=data)
        _git(src, "update-index", "--add", "--cacheinfo", f"100644,{sha},{path}")
        blob_of[path] = (sha, data)
    tree = _git(src, "write-tree")
    commit = _git(src, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit-tree", tree, "-m", "fake dataset")
    _git(src, "update-ref", "refs/heads/main", commit)
    cands = tmp_path / "cands.csv"
    with open(cands, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "ecosystem", "package", "version"])
        w.writerows(CANDIDATES)
    calls = {"sizes": [], "https": []}

    def sizes(paths, commit):
        calls["sizes"].append(list(paths))
        return {p: len(blob_of[p][1]) for p in paths}
    return {"src": src, "url": src.as_uri(), "cands": cands, "sizes": sizes, "calls": calls, "blobs": blob_of,
            "clone": tmp_path / "dd", "report": tmp_path / "subset.csv", "summary": tmp_path / "subset.txt"}


def _run(d, **kw):
    args = dict(max_mb=100, dry_run=False, sizes_fn=d["sizes"], method="git", report=d["report"], summary=d["summary"],
                candidates_file=d["cands"], n_random=0)
    args.update(kw)
    return F.run(d["clone"], d["url"], **args)


def _stored(clone):
    return sorted(p.relative_to(clone).as_posix() for p in (clone / "subset").rglob("*.zip")) if (clone / "subset").exists() else []


def _mapping(clone):
    return XD.load_mapping(clone)


# ------------------------------------------------------------------ pure helpers

@pytest.mark.parametrize("path, unsafe", [
    ("samples/npm/malicious_intent/mad-1.0.0.2.2.8./1.0.0/x.zip", True), ("samples/pypi/m/spacey /1.0/x.zip", True),
    ("samples/npm/m/con/1.0.0/x.zip", True), ("samples/npm/m/aux.js/1/x.zip", True), ("samples/npm/m/a:b/1/x.zip", True),
    ("samples/npm/m/console/1/x.zip", False), ("samples/npm/m/lodash.merge/1.0.0/x.zip", False),
    ("samples/npm/m/@sc/bad/0.0.1/x.zip", False)])
def test_windows_unsafe(path, unsafe):
    assert bool(F.windows_unsafe(path)) is unsafe


def test_safe_names_are_flat_and_hash_based():
    r = XD.parse_sample_path("samples/npm/malicious_intent/mad-1.0.0.2.2.8./1.0.0/2025-09-27-mad-1.0.0.2.2.8.-v1.0.0.zip")
    safe = XD.safe_sample_path(r)
    assert safe.startswith("subset/npm/malicious_intent/") and safe.endswith(".zip") and len(safe.split("/")[-1]) == 44
    assert F.windows_unsafe(safe) is None and "mad" not in safe


@needs_git
def test_blob_id_matches_git(tmp_path):
    data = b"PK\x03\x04 some bytes"
    _git(tmp_path, "init", "-q")
    assert F.blob_id(data) == _git(tmp_path, "hash-object", "--stdin", data=data)


# ------------------------------------------------------------------ the selection is unchanged (real dataset listing)

def test_selection_identical_to_before_the_storage_change():
    """The real DataDog listing (dataset commit 72c723be) and the 312 ZIPs the previous code (commit 54b7482) selected
    from it: the current selection must be byte-identical (same seed, same draw, same candidates)."""
    with gzip.open(FIX / "listing_72c723be.txt.gz", "rt", encoding="utf-8") as fh:
        paths = [line.rstrip("\n") for line in fh if line.strip()]
    expected = [tuple(line.rstrip("\n").split("\t")) for line in open(FIX / "selection_72c723be.txt", encoding="utf-8")
                if not line.startswith("#") and line.strip()]
    listing = sorted((s for s in (XD.parse_sample_path(p) for p in paths) if s), key=lambda r: r["sample_path"])
    cands = bench_items.read_manifest(bench_items.MAN / "known_bad_candidates.csv")
    got = [(r["selected_by"], r["sample_path"]) for r in XD.select_samples(listing, XD.candidate_keys(cands))]
    assert len(paths) == 29247 and len(listing) == 28988 and len(got) == 312     # 28,988 parse as dataset samples
    assert got == expected


# ------------------------------------------------------------------ fake dataset: fetch, mapping, extraction

@needs_git
def test_matching_is_version_level_with_shared_normalisation(dataset):
    assert _run(dataset, dry_run=True) == 0
    rows = {r["id"]: r for r in bench_items.read_manifest(dataset["report"])}
    assert rows["MAL-1"]["status"] == "matched" and rows["MAL-1"]["category"] == "malicious_intent"
    assert rows["MAL-2"]["status"] == "matched" and rows["MAL-2"]["category"] == "compromised_lib"
    assert rows["MAL-2"]["manifest"] == "manifest: malicious in this version"
    assert rows["MAL-3"]["status"] == "unmatched" and "no other version is substituted" in rows["MAL-3"]["reason"]
    assert rows["MAL-3"]["manifest"].startswith("manifest: malicious ONLY in 2.0")
    assert rows["MAL-4"]["status"] == "matched"
    assert rows["MAL-5"]["reason_kind"] == "package not in the dataset"
    assert rows["MAL-6"]["reason_kind"] == "no version in the advisory"
    for i in ("MAL-7", "MAL-8", "MAL-9"):
        assert rows[i]["status"] == "matched" and rows[i]["windows_unsafe"], i
    text = dataset["summary"].read_text(encoding="utf-8")
    assert "matched at version level 6, unmatched 3" in text and "3 with an original path Windows cannot hold" in text


@needs_git
def test_dry_run_checks_nothing_out_and_downloads_no_sample(dataset):
    assert _run(dataset, dry_run=True) == 0
    clone = dataset["clone"]
    assert sorted(p.name for p in clone.iterdir()) == [".git"]          # no working tree at all
    assert _stored(clone) == []


@needs_git
def test_size_guard_refuses_before_download(dataset):
    assert _run(dataset, max_mb=0.000001) == 3
    assert _stored(dataset["clone"]) == []


@needs_git
def test_fetch_via_git_stores_safe_names_and_keeps_unsafe_items(dataset):
    assert _run(dataset) == 0
    clone, m = dataset["clone"], _mapping(dataset["clone"])
    assert set(m) == {"samples/" + p for p in SELECTED}
    assert not (clone / "samples").exists()                              # no original path was ever created
    for orig, row in m.items():
        data = (clone / row["safe_path"]).read_bytes()
        assert data == dataset["blobs"][orig][1] and F.blob_id(data) == row["git_blob"] and row["method"] == "git"
        assert F.windows_unsafe(row["safe_path"]) is None
        if orig[len("samples/"):] in UNSAFE:
            assert row["note"].startswith("unsafe name, obtained via git (")
        else:
            assert row["note"] == ""


@needs_git
def test_fetch_via_https_verifies_blob_ids_and_falls_back_to_git(dataset):
    sel = sorted("samples/" + p for p in SELECTED)

    def https(paths, commit, url):
        dataset["calls"]["https"].append(list(paths))
        out = {}
        for i, p in enumerate(sorted(paths)):
            data = dataset["blobs"][p][1]
            out[p] = data if i % 3 == 0 else (b"tampered" + data if i % 3 == 1 else None)
        return out
    assert _run(dataset, method="https", https_fn=https) == 0
    m = _mapping(dataset["clone"])
    methods = {p: m[p]["method"] for p in sel}
    assert {methods[p] for i, p in enumerate(sel) if i % 3 == 0} == {"https"}
    assert {methods[p] for i, p in enumerate(sel) if i % 3 != 0} == {"git"}   # mismatch or failure -> git
    for p in sel:
        assert (dataset["clone"] / m[p]["safe_path"]).read_bytes() == dataset["blobs"][p][1]


@needs_git
def test_rerun_does_not_download_again(dataset):
    assert _run(dataset) == 0
    n = len(dataset["calls"]["sizes"])
    assert _run(dataset, method="https", https_fn=lambda *a: pytest.fail("nothing to download")) == 0
    assert len(dataset["calls"]["sizes"]) == n                          # nothing missing: no size lookup either
    assert "to download: 0" in dataset["summary"].read_text(encoding="utf-8")


@needs_git
def test_random_draw_is_over_the_full_listing(dataset):
    assert _run(dataset, n_random=1) == 0
    listing = sorted((s for s in (XD.parse_sample_path("samples/" + p) for p in SAMPLES) if s), key=lambda r: r["sample_path"])
    expected = {r["sample_path"] for r in XD.select_samples(
        listing, XD.candidate_keys([dict(zip(("id", "ecosystem", "package", "version"), c)) for c in CANDIDATES]), n_random=1)}
    assert set(_mapping(dataset["clone"])) == expected


@needs_git
def test_extraction_and_prepare_read_through_the_mapping(dataset, tmp_path, monkeypatch):
    assert _run(dataset) == 0
    monkeypatch.setattr(XD, "MANIFEST", tmp_path / "extracted.csv")
    monkeypatch.setattr(XD, "MEMBERS", tmp_path / "members.csv")
    monkeypatch.setattr(bench_items, "MAN", tmp_path)
    shutil.copy(dataset["cands"], tmp_path / "known_bad_candidates.csv")
    monkeypatch.setattr(XD.select_samples, "__defaults__", (0, XD.SEED))
    samples = tmp_path / "samples"
    assert XD.main(["--dataset", str(dataset["clone"]), "--samples-dir", str(samples)]) == 0
    rows = bench_items.read_manifest(tmp_path / "extracted.csv")
    assert len(rows) == len(SELECTED) and {r["status"] for r in rows} == {"extracted"}
    notes = {r["package"]: r["storage_note"] for r in rows}
    assert notes["mad-1.0.0.2.2.8."].startswith("unsafe name, obtained via git") and notes["con"].startswith("unsafe name, obtained via git")
    assert notes["evil-pkg"] == ""
    written = [p for p in samples.rglob("*") if p.is_file()]
    assert written and all(p.name.endswith(".sample") for p in written)
    assert all(F.windows_unsafe(p.relative_to(samples).as_posix()) is None for p in written)
    listed = XD.list_samples(dataset["clone"])
    assert len(listed) == len(SAMPLES) and sum(r["present"] for r in listed) == len(SELECTED)


def test_sparse_checkout_is_gone():
    src = (ROOT / "benchmark" / "fetch_datadog_subset.py").read_text(encoding="utf-8")
    assert '"checkout"' not in src and "sparse-checkout\"" not in src and "write_sparse" not in src


def test_size_check_counts_unknown_sizes_conservatively():
    chk = F.size_check(["a", "b"], {"a": 1024 * 1024, "b": None}, max_mb=5)
    assert chk["unknown_sizes"] == 1 and chk["mb_total"] == pytest.approx(1 + F.ASSUMED_MB_PER_FILE) and not chk["ok"]
