"""fetch_datadog_subset.py against a tiny LOCAL git repository laid out like the DataDog dataset (no network: the clone
uses a file:// URL; sizes come from a stub). Sample ZIPs are synthetic, encrypted like the dataset's, and inert."""
from __future__ import annotations

import csv
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

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

SAMPLES = {   # path under samples/ -> package files inside the encrypted zip
    "pypi/malicious_intent/evil-pkg/1.0/2024-01-01-evil-pkg-v1.0.zip": {"setup.py": "x = 1\n"},
    "pypi/compromised_lib/goodlib/2.0/2024-02-01-goodlib-v2.0.zip": {"goodlib/__init__.py": "y = 2\n"},
    "pypi/compromised_lib/goodlib/2.1/2024-03-01-goodlib-v2.1.zip": {"goodlib/__init__.py": "y = 3\n"},
    "npm/malicious_intent/@sc/bad/0.0.1/2024-04-01-bad-v0.0.1.zip": {"package/index.js": "z()\n"},
    "npm/malicious_intent/lodash.merge/1.0.0/2024-05-01-lodash.merge-v1.0.0.zip": {"package/index.js": "w()\n"},
    "npm/malicious_intent/unrelated/9.9.9/2024-06-01-unrelated-v9.9.9.zip": {"package/index.js": "u()\n"},
}
MANIFESTS = {"pypi": {"evil_pkg": None, "goodlib": ["2.0"]}, "npm": {"@sc/bad": ["0.0.1"], "lodash.merge": None, "unrelated": None}}
CANDIDATES = [  # id, ecosystem, package, version
    ("MAL-1", "PyPI", "Evil_Pkg", "1.0.0"),        # name and PEP 440 version normalisation -> evil-pkg 1.0
    ("MAL-2", "PyPI", "goodlib", "2.0"),           # compromised_lib, listed version
    ("MAL-3", "PyPI", "goodlib", "3.0"),           # package present, version absent: no substitute
    ("MAL-4", "npm", "@sc/bad", "0.0.1"),          # scoped npm
    ("MAL-5", "npm", "lodash-merge", "1.0.0"),     # npm names are exact: lodash-merge is not lodash.merge
    ("MAL-6", "PyPI", "noversion", ""),            # advisory without a version
]


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def dataset(tmp_path):
    src = tmp_path / "src"
    for rel, files in SAMPLES.items():
        p = src / "samples" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(_encrypted_zip({f"root/{k}": v.encode() for k, v in files.items()}))
    for eco, m in MANIFESTS.items():
        (src / "samples" / eco / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
    _git(src, "init", "-q", "-b", "main")
    _git(src, "config", "uploadpack.allowFilter", "true")
    _git(src, "config", "uploadpack.allowAnySHA1InWant", "true")
    _git(src, "add", "-A")
    _git(src, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "fake dataset")
    cands = tmp_path / "cands.csv"
    with open(cands, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "ecosystem", "package", "version"])
        w.writerows(CANDIDATES)
    sizes_seen = []

    def sizes(paths, commit):
        sizes_seen.append(list(paths))
        return {p: (src / p).stat().st_size for p in paths}
    return {"src": src, "url": src.as_uri(), "cands": cands, "sizes": sizes, "sizes_seen": sizes_seen,
            "clone": tmp_path / "dd", "report": tmp_path / "subset.csv", "summary": tmp_path / "subset.txt"}


def _run(d, **kw):
    args = dict(max_mb=100, dry_run=False, sizes_fn=d["sizes"], report=d["report"], summary=d["summary"],
                candidates_file=d["cands"], n_random=0)
    args.update(kw)
    return F.run(d["clone"], d["url"], **args)


def _zips_on_disk(clone):
    return sorted(p.relative_to(clone).as_posix() for p in (clone / "samples").rglob("*.zip"))


def test_matching_is_version_level_with_shared_normalisation(dataset):
    assert _run(dataset, dry_run=True) == 0
    rows = {r["id"]: r for r in bench_items.read_manifest(dataset["report"])}
    assert rows["MAL-1"]["status"] == "matched" and rows["MAL-1"]["category"] == "malicious_intent"
    assert rows["MAL-1"]["manifest"] == "manifest: malicious in every version"
    assert rows["MAL-2"]["status"] == "matched" and rows["MAL-2"]["category"] == "compromised_lib"
    assert rows["MAL-2"]["manifest"] == "manifest: malicious in this version"
    assert rows["MAL-3"]["status"] == "unmatched" and rows["MAL-3"]["reason_kind"] == "package in the dataset, but not this version"
    assert "2.0, 2.1" in rows["MAL-3"]["reason"] and "no other version is substituted" in rows["MAL-3"]["reason"]
    assert rows["MAL-3"]["manifest"].startswith("manifest: malicious ONLY in 2.0")
    assert rows["MAL-4"]["status"] == "matched"
    assert rows["MAL-5"]["status"] == "unmatched" and rows["MAL-5"]["reason_kind"] == "package not in the dataset"
    assert rows["MAL-6"]["reason_kind"] == "no version in the advisory"
    text = dataset["summary"].read_text(encoding="utf-8")
    assert "matched at version level 3, unmatched 3" in text
    assert "matched by category: compromised_lib 1, malicious_intent 2" in text


def test_dry_run_downloads_no_sample(dataset):
    assert _run(dataset, dry_run=True) == 0
    assert _zips_on_disk(dataset["clone"]) == []                        # trees and the two manifests only
    assert (dataset["clone"] / "samples" / "pypi" / "manifest.json").is_file()


def test_size_guard_refuses_before_download(dataset):
    assert _run(dataset, max_mb=0.000001) == 3
    assert _zips_on_disk(dataset["clone"]) == []


def test_fetch_downloads_only_the_selection_and_resumes(dataset):
    assert _run(dataset) == 0
    want = sorted("samples/" + p for p in SAMPLES if "evil-pkg/1.0" in p or "goodlib/2.0/" in p or "@sc/bad" in p)
    assert _zips_on_disk(dataset["clone"]) == want                       # goodlib 2.1, lodash.merge, unrelated: not fetched
    assert sorted(dataset["sizes_seen"][-1]) == want
    assert _run(dataset) == 0                                            # rerun: nothing left to fetch or size
    assert dataset["sizes_seen"][-1:] == [want] and len(dataset["sizes_seen"]) == 1
    assert "to download: 0" in dataset["summary"].read_text(encoding="utf-8")


def test_random_draw_is_over_the_full_listing(dataset):
    assert _run(dataset, n_random=1) == 0
    on_disk = _zips_on_disk(dataset["clone"])
    listing = [s for s in (XD.parse_sample_path("samples/" + p) for p in sorted(SAMPLES)) if s]
    expected = sorted(r["sample_path"] for r in XD.select_samples(
        sorted(listing, key=lambda r: r["sample_path"]),
        XD.candidate_keys([dict(zip(("id", "ecosystem", "package", "version"), c)) for c in CANDIDATES]), n_random=1))
    assert on_disk == expected


def test_extract_datadog_reads_the_sparse_clone(dataset, tmp_path, monkeypatch):
    assert _run(dataset) == 0
    monkeypatch.setattr(XD, "MANIFEST", tmp_path / "extracted.csv")
    monkeypatch.setattr(XD, "MEMBERS", tmp_path / "members.csv")
    monkeypatch.setattr(bench_items, "MAN", tmp_path)                    # read the test candidates
    shutil.copy(dataset["cands"], tmp_path / "known_bad_candidates.csv")
    monkeypatch.setattr(XD, "N_RANDOM_PER_ECO", 0)
    monkeypatch.setattr(XD.select_samples, "__defaults__", (0, XD.SEED))
    samples = tmp_path / "samples"
    assert XD.main(["--dataset", str(dataset["clone"]), "--samples-dir", str(samples)]) == 0
    rows = bench_items.read_manifest(tmp_path / "extracted.csv")
    assert sorted((r["package"], r["status"]) for r in rows) == [("@sc/bad", "extracted"), ("evil-pkg", "extracted"),
                                                                 ("goodlib", "extracted")]
    written = sorted(p.name for p in samples.rglob("*") if p.is_file())
    assert written and all(n.endswith(".sample") for n in written)
    # the git listing covers files that were never downloaded
    listed = XD.list_samples(dataset["clone"])
    assert len(listed) == len(SAMPLES) and sum(r["present"] for r in listed) == 3


def test_sparse_patterns_escape_special_characters(tmp_path):
    assert F._pattern("samples/npm/x/a b[1]/v!1/#z.zip") == "/samples/npm/x/a\\ b\\[1\\]/v\\!1/\\#z.zip"


def test_size_check_counts_unknown_sizes_conservatively():
    chk = F.size_check(["a", "b"], {"a": 1024 * 1024, "b": None}, max_mb=5)
    assert chk["unknown_sizes"] == 1 and chk["mb_total"] == pytest.approx(1 + F.ASSUMED_MB_PER_FILE) and not chk["ok"]
