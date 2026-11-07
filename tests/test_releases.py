"""releases.py parsing (recorded fixtures), in-memory archive reading, the HTTP cache, and the as_of wiring."""
import io
import json
import os
import tarfile

import pytest

import http_cache
import releases as R
from release_helpers import history, npm_release, tgz

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "releases")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return json.load(fh)


def test_parse_pypi_recorded_fixture_newest_first_with_upload_times():
    rels = R.parse_pypi(load("pypi_idna_project.json"), 5)
    assert [r["version"] for r in rels][:2] == ["3.20", "3.19"]
    assert all(r["upload_time"].endswith("Z") for r in rels)
    times = [r["upload_time"] for r in rels]
    assert times == sorted(times, reverse=True)


def test_dependency_names_exclude_optional_extras():
    req = load("pypi_requests_2.31.0_version.json")["info"]["requires_dist"]
    names = R.dependency_names(req)
    assert {"charset-normalizer", "idna", "urllib3", "certifi"} <= set(names)
    assert "pysocks" not in names and "chardet" not in names   # only under extras


def test_parse_npm_recorded_fixture_and_publisher():
    rels, unlisted = R.parse_npm(load("npm_left-pad_packument.json"), 3)
    assert [r["version"] for r in rels] == ["1.3.0", "1.2.0", "1.1.3"]
    assert rels[0]["publisher"] == "stevemao" and rels[0]["publisher_source"] == "npm _npmUser"
    assert rels[0]["artifact"]["url"].endswith("left-pad-1.3.0.tgz") and unlisted == []


def test_parse_npm_reports_unpublished_versions():
    p = load("npm_left-pad_packument.json")
    p["time"]["1.3.1"] = "2018-05-01T00:00:00.000Z"   # in time{} but removed from versions{}: unpublished
    _, unlisted = R.parse_npm(p, 3)
    assert unlisted == ["1.3.1"]


def test_provenance_publisher_parsing(monkeypatch):
    prov = load("pypi_idna_provenance.json")
    monkeypatch.setattr(http_cache, "get_json", lambda url, headers=None, timeout=None: (prov, 200, None))
    ident, src = R._pypi_publisher("idna", "3.20", "idna-3.20-py3-none-any.whl")
    assert ident.startswith("GitHub:kjd/idna/") and src == "PyPI provenance (Trusted Publisher)"
    monkeypatch.setattr(http_cache, "get_json", lambda url, headers=None, timeout=None: (None, 404, None))
    ident, src = R._pypi_publisher("requests", "2.31.0", "x.whl")
    assert ident is None and "Trusted Publishing" in src


def test_read_archive_strips_root_skips_links_and_traversal_and_flags_binaries():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        def add(name, data, **kw):
            info = tarfile.TarInfo(name)
            for k, v in kw.items():
                setattr(info, k, v)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        add("package/index.js", b"module.exports = 1;\n")
        add("package/bin/tool", b"MZ" + b"\x00" * 2000)
        add("package/../../etc/evil.js", b"x")
        link = tarfile.TarInfo("package/link.js"); link.type = tarfile.SYMTYPE; link.linkname = "/etc/passwd"
        tf.addfile(link)
    before = set(os.listdir("."))
    c = R.read_archive(buf.getvalue(), "npm_tgz")
    assert set(os.listdir(".")) == before          # nothing written to disk
    assert "index.js" in c["text"] and "link.js" not in c["members"]
    assert not any(".." in m for m in c["members"])
    assert [b["path"] for b in c["binaries"]] == ["bin/tool"]


def test_read_archive_records_skipped_large_files(monkeypatch):
    monkeypatch.setattr(R, "MAX_MEMBER_TEXT_BYTES", 10)
    c = R.read_archive(tgz({"big.js": "x" * 50, "small.js": "y"}), "npm_tgz")
    assert c["skipped"] == ["big.js"] and "small.js" in c["text"] and c["truncated"]


def test_fetch_npm_offline_with_recorded_packument(monkeypatch):
    pack = load("npm_left-pad_packument.json")
    monkeypatch.setattr(http_cache, "get_json", lambda url, headers=None, timeout=None: (pack, 200, None))
    monkeypatch.setattr(http_cache, "get_bytes", lambda url, max_bytes, timeout=60: (tgz({"index.js": "module.exports=1\n"}), None))
    h = R.fetch_npm("left-pad", 3)
    assert h["status"] == "ok" and h["releases"][0]["artifact_status"] == "read"
    assert h["releases"][2]["artifact_status"] == "not_fetched"   # only the 2 newest artifacts are downloaded


def test_oversize_artifact_is_not_downloaded(monkeypatch):
    called = []
    monkeypatch.setattr(http_cache, "get_bytes", lambda *a, **k: called.append(1) or (b"", None))
    contents, status = R._load_artifact({"url": "https://x", "size": R.MAX_ARTIFACT_BYTES + 1, "kind": "sdist"})
    assert contents is None and status == "too_large" and not called


def test_http_cache_roundtrip_and_offline_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("REPOHEALTH_CACHE", str(tmp_path))
    monkeypatch.setenv("REPOHEALTH_SNAPSHOT", "2026-11-07")
    calls = []

    class Resp:
        status_code = 200
        def json(self):
            return {"ok": 1}
    monkeypatch.setattr(http_cache.requests, "get", lambda url, headers=None, timeout=None: calls.append(headers) or Resp())
    assert http_cache.get_json("https://pypi.org/pypi/x/json") == ({"ok": 1}, 200, None)
    assert http_cache.get_json("https://pypi.org/pypi/x/json") == ({"ok": 1}, 200, None)
    assert len(calls) == 1                                  # second call served from the cache
    monkeypatch.setenv("REPOHEALTH_OFFLINE", "1")
    assert http_cache.get_json("https://pypi.org/pypi/other/json") == (None, None, "offline: not cached")


def test_github_token_only_sent_to_api_github(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    assert http_cache._headers("https://api.github.com/repos/o/r", None)["Authorization"] == "Bearer ghp_test"
    assert "Authorization" not in http_cache._headers("https://pypi.org/pypi/x/json", None)


def test_tag_candidates():
    c = R.tag_candidates("@scope/demo", "1.2.3")
    assert {"1.2.3", "v1.2.3", "demo-1.2.3", "@scope/demo@1.2.3", "demo@1.2.3"} <= set(c)


def test_apply_gate_uses_release_upload_time_as_as_of():
    from security import apply_gate
    rc = history([npm_release("1.0.1", "2021-10-22T12:00:00Z"), npm_release("1.0.0", "2021-01-01T00:00:00Z")])
    sec = {"level": "No unpatched issues found", "findings": [], "coverage": [], "package": rc["package"]}
    g = apply_gate({"score": 90.0, "label": "Healthy", "factors": [], "notes": []}, sec, [], None, releases=rc)
    assert g["as_of"].startswith("2021-10-22") and g["as_of_source"] == "upload time of 1.0.1"
    integ = [d for d in g["detectors"] if d["pillar"] == "Integrity"]
    assert {d["detector"]: d["status"] for d in integ}["release_delta"] == "ran"


@pytest.mark.parametrize("pkg_in_sec, expect", [(None, "not_applicable"), ({"ecosystem": "npm", "name": "x"}, "not_assessed")])
def test_integrity_pillar_status_without_release_data(pkg_in_sec, expect):
    from security import apply_gate
    sec = {"level": "No unpatched issues found", "findings": [], "coverage": [], "package": pkg_in_sec}
    g = apply_gate({"score": 90.0, "label": "Healthy", "factors": [], "notes": []}, sec, [],
                   {"ran": True, "malware_proof": {"findings": [], "layers": {"layer4": {"status": "not_applicable", "reason": "no published package"}}},
                    "findings": []})
    assert g["pillars"]["Integrity"]["status"] == expect
