"""verify_samples.py and extract_datadog.py --restore-missing. All inputs are synthetic and inert (encrypted ZipCrypto
fixtures built here); nothing is executed, imported or installed."""
from __future__ import annotations

import csv
import hashlib
import io
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmark"))
sys.path.insert(0, str(ROOT / "tests"))

import extract_datadog as XD  # noqa: E402
import verify_samples as V  # noqa: E402
from test_benchmark import _encrypted_zip  # noqa: E402

SID = "DD-npm-evil-1.0.0-abcd1234"
REL = "samples/npm/malicious_intent/evil/1.0.0/2025-01-01-evil-v1.0.0.zip"


def _tgz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for n, d in files.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            t.addfile(ti, io.BytesIO(d))
    return buf.getvalue()


def _setup(tmp_path):
    """A dataset with one sample ZIP (direct members under a common root + a nested tgz), extracted the normal way,
    with manifests written from read_sample's own rows."""
    blob = _encrypted_zip({
        "2025-01-01-evil-v1.0.0/package/index.js": b"require('child_process').exec('x')\n",
        "2025-01-01-evil-v1.0.0/package/package.json": b'{"name":"evil","scripts":{"postinstall":"node index.js"}}\n',
        "2025-01-01-evil-v1.0.0/package/lib/a.js": b"module.exports = 1\n",
        "2025-01-01-evil-v1.0.0/package/dist/evil-1.0.0.tgz": _tgz({"evil-1.0.0/setup.py": b"import os\n"}),
    })
    dd = tmp_path / "dd"
    (dd / REL).parent.mkdir(parents=True)
    (dd / REL).write_bytes(blob)
    samples = tmp_path / "samples"
    sample_dir = "datadog/npm/evil_1.0.0_abcd1234"
    res = XD.read_sample(blob)
    XD.write_sample(res["text"], samples / sample_dir)
    man = tmp_path / "man"
    man.mkdir()
    ext, mem = man / "extracted.csv", man / "members.csv"
    with open(ext, "w", newline="", encoding="utf-8") as fh:
        fh.write("# fixture\n")
        w = csv.DictWriter(fh, fieldnames=["id", "sample_path", "zip_sha256", "status", "sample_dir"])
        w.writeheader()
        w.writerow({"id": SID, "sample_path": REL, "zip_sha256": hashlib.sha256(blob).hexdigest(),
                    "status": "extracted", "sample_dir": sample_dir})
    with open(mem, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["id", "member", "size", "action", "reason", "sha256"])
        w.writeheader()
        w.writerows({"id": SID, **m} for m in res["members"])
    return dd, samples, samples / sample_dir, ext, mem


def _tree(root: Path) -> dict[str, tuple[bytes, int]]:
    return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mtime_ns) for p in root.rglob("*") if p.is_file()}


def test_mapping_equals_what_extraction_wrote(tmp_path):
    _dd, _s, sdir, _e, mem = _setup(tmp_path)
    rows = V.read_rows(mem)
    mapped = sorted(rel for _r, rel in XD.written_paths(rows))
    on_disk = sorted(str(p.relative_to(sdir)).replace("\\", "/") for p in sdir.rglob("*.sample"))
    assert mapped == on_disk == ["dist/evil-1.0.0/setup.py.sample", "index.js.sample",
                                 "lib/a.js.sample", "package.json.sample"]


def test_verify_all_present_is_clean(tmp_path):
    _dd, samples, _sd, ext, mem = _setup(tmp_path)
    res = V.check(samples, ext, mem)
    assert res["problems"] == [] and res["counts"]["ok"] == 4 and res["counts"]["items checked"] == 1


def test_verify_reports_missing_and_mismatch_ids_and_names_only(tmp_path):
    _dd, samples, sdir, ext, mem = _setup(tmp_path)
    (sdir / "index.js.sample").unlink()                      # what Defender did
    (sdir / "lib/a.js.sample").write_bytes(b"")              # truncated
    out = tmp_path / "samples_missing.csv"
    rc = V.main(["--samples-dir", str(samples), "--out", str(out), "--extracted", str(ext), "--members", str(mem)])
    assert rc == 1
    rows = list(csv.DictReader(open(out, encoding="utf-8")))
    assert rows == [{"id": SID, "member_path": "index.js.sample", "problem": "missing"},
                    {"id": SID, "member_path": "lib/a.js.sample", "problem": "sha256 mismatch"}]
    assert "require(" not in out.read_text(encoding="utf-8")   # no sample content in the report


def test_verify_never_writes_into_samples(tmp_path):
    _dd, samples, sdir, ext, mem = _setup(tmp_path)
    (sdir / "index.js.sample").unlink()
    before = _tree(samples)
    V.check(samples, ext, mem)
    assert _tree(samples) == before


def test_restore_rewrites_only_problem_files_and_verifies(tmp_path):
    dd, samples, sdir, ext, mem = _setup(tmp_path)
    good = (sdir / "index.js.sample").read_bytes()
    (sdir / "index.js.sample").unlink()
    (sdir / "dist/evil-1.0.0/setup.py.sample").unlink()
    (sdir / "lib/a.js.sample").write_bytes(b"tampered")
    untouched = {k: v for k, v in _tree(sdir).items() if k.endswith("package.json.sample")}
    man_before = (ext.read_bytes(), mem.read_bytes())
    r = XD.restore_missing(dd, samples, ext, mem)
    assert r["restored"] == 3 and r["failed"] == []
    assert (sdir / "index.js.sample").read_bytes() == good
    assert V.check(samples, ext, mem)["problems"] == []
    assert {k: v for k, v in _tree(sdir).items() if k in untouched} == untouched   # same bytes, same mtime
    assert (ext.read_bytes(), mem.read_bytes()) == man_before                   # manifests unchanged
    assert not list(samples.rglob("*.part"))


def test_restore_refuses_a_zip_that_differs_from_the_manifest(tmp_path):
    dd, samples, sdir, ext, mem = _setup(tmp_path)
    (sdir / "index.js.sample").unlink()
    (dd / REL).write_bytes(_encrypted_zip({"x/package/index.js": b"other\n"}))
    r = XD.restore_missing(dd, samples, ext, mem)
    assert r["restored"] == 0 and r["failed"][0][2] == "ZIP sha256 differs from the manifest"
    assert not (sdir / "index.js.sample").exists()


def test_restore_reads_through_the_subset_mapping(tmp_path):
    dd, samples, sdir, ext, mem = _setup(tmp_path)
    (sdir / "index.js.sample").unlink()
    safe = f"{XD.SUBSET_DIR}/npm/malicious_intent/{hashlib.sha1(REL.encode()).hexdigest()}.zip"
    (dd / safe).parent.mkdir(parents=True)
    (dd / REL).rename(dd / safe)
    XD.write_mapping(dd, {REL: {"original_path": REL, "safe_path": safe}})
    assert XD.restore_missing(dd, samples, ext, mem)["restored"] == 1


def test_restore_with_nothing_missing_writes_nothing(tmp_path):
    dd, samples, _sd, ext, mem = _setup(tmp_path)
    before = _tree(samples)
    assert XD.restore_missing(dd, samples, ext, mem) == {"restored": 0, "failed": [], "ids": 0}
    assert _tree(samples) == before


def test_verify_dataset_dir_recognises_utf8_normalised_members(tmp_path):
    """A member that is not valid UTF-8 is stored decoded, so its file hash differs from the raw member hash by
    construction; with --dataset-dir that is reported as ok, not as a mismatch."""
    blob = _encrypted_zip({"r/package/x.js": b"var a = '\xff\xfe';\n", "r/package/y.js": b"ok\n"})
    dd = tmp_path / "dd"
    (dd / REL).parent.mkdir(parents=True)
    (dd / REL).write_bytes(blob)
    res = XD.read_sample(blob)
    XD.write_sample(res["text"], tmp_path / "samples" / "d")
    ext, mem = tmp_path / "e.csv", tmp_path / "m.csv"
    ext.write_text(f"id,sample_path,zip_sha256,status,sample_dir\n{SID},{REL},{hashlib.sha256(blob).hexdigest()},extracted,d\n",
                   encoding="utf-8")
    with open(mem, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["id", "member", "size", "action", "reason", "sha256"])
        w.writeheader()
        w.writerows({"id": SID, **m} for m in res["members"])
    assert [p["member_path"] for p in V.check(tmp_path / "samples", ext, mem)["problems"]] == ["x.js.sample"]
    c = V.check(tmp_path / "samples", ext, mem, dd)
    assert c["problems"] == [] and c["counts"]["ok (normalised at extraction)"] == 1


def test_real_manifest_mapping_matches_text_written_counts():
    ext = {r["id"]: r for r in V.read_rows(XD.MANIFEST) if r["status"] == "extracted"}
    members: dict[str, list] = {}
    for m in V.read_rows(XD.MEMBERS):
        members.setdefault(m["id"], []).append(m)
    for sid, e in ext.items():
        rels = [rel for _r, rel in XD.written_paths(members.get(sid, []))]
        assert len(rels) == len(set(rels)) == int(e["text_written"]), sid
