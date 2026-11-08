"""Benchmark harness tests (Phase 5 Stage 2). All inputs are synthetic and inert; nothing is executed, imported or
installed, and no network is used (the end-to-end test runs offline from a synthetic cache)."""
from __future__ import annotations

import binascii
import io
import json
import os
import struct
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmark"))

import bench_items  # noqa: E402
import compare_chat_ai as CC  # noqa: E402
import extract_datadog as XD  # noqa: E402
import metrics as M  # noqa: E402
import run_benchmark as RB  # noqa: E402


@pytest.fixture
def ai_off(monkeypatch):
    """Other test modules import the app (and with it the AI module); the runner refuses to start when an AI module is
    loaded, so these tests run with it unloaded and with no key in the environment."""
    for k in RB.AI_KEY_VARS:
        monkeypatch.delenv(k, raising=False)
    for m in RB.AI_MODULES:
        monkeypatch.delitem(sys.modules, m, raising=False)
    for k in ("REPOHEALTH_OFFLINE", "REPOHEALTH_SNAPSHOT", "REPOHEALTH_CACHE", "VT_API_KEY", "GITHUB_TOKEN"):
        monkeypatch.setenv(k, "placeholder")   # setenv records the original state (even "absent") for restoring;
        monkeypatch.delenv(k)                  # the runner sets some of these directly in os.environ


# ------------------------------------------------------------------ statistics

def test_rule_of_three_known_values():
    assert M.rule_of_three(100) == pytest.approx(0.03)          # 0 of 100 -> at most 3.0%
    assert M.rule_of_three(300) == pytest.approx(0.01)
    assert M.rule_of_three(0) is None
    assert "rule of three: at most 3.0%" in M.rate_text(0, 100, zero_rule=True)


def test_wilson_known_values():
    lo, hi = M.wilson(0, 100)
    assert lo == 0.0 and hi == pytest.approx(0.0370, abs=1e-4)
    lo, hi = M.wilson(5, 100)
    assert lo == pytest.approx(0.0215, abs=1e-4) and hi == pytest.approx(0.1118, abs=1e-4)
    lo, hi = M.wilson(10, 10)
    assert lo == pytest.approx(0.7225, abs=1e-4) and hi == 1.0
    assert M.wilson(0, 0) is None
    assert M.rate_text(0, 0) == "n/a (n=0)"


def test_quantiles():
    assert M.quantile([1, 2, 3, 4], 0.5) == 2.5
    assert M.quantile(list(range(1, 101)), 0.95) == pytest.approx(95.05)


# ------------------------------------------------------------------ metrics: not_assessed is never "no findings"

def _rec(id_, cat, status="scored", tiers=None, label="No findings", split="test", detectors=None):
    fb = {"known_malicious": 0, "high_risk": 0, "review": 0, "info": 0, **(tiers or {})}
    return {"id": id_, "category": cat, "split": split, "status": status, "findings_by_tier": fb, "label": label,
            "detectors": detectors or {}, "findings": [], "elapsed_s": 1.0, "ruleset_version": "x",
            "not_assessed_reason": None if status == "scored" else "timeout"}


def test_not_assessed_item_is_never_counted_as_no_findings():
    run = {r["id"]: r for r in [
        _rec("b1", "known_bad", tiers={"high_risk": 1}),
        _rec("b2", "known_bad"),
        _rec("b3", "known_bad", status="not_assessed"),       # must not be a miss
        _rec("b4", "known_bad", status="unobtainable"),       # must not be a miss
        _rec("g1", "known_good"),
        _rec("g2", "known_good", status="not_assessed"),      # must not be a true negative
        _rec("g3", "known_good", label="Review recommended", tiers={"review": 1}),
    ]}
    rb = M.recall_block(M.class_rows(run, "known_bad"))
    assert rb["strict"] == {"hits": 1, "n": 2}
    fb = M.fp_block(M.class_rows(run, "known_good"))
    assert fb["strict"]["n"] == 2 and fb["strict"]["fp"] == 0
    assert fb["lenient"]["fp"] == 1 and fb["soft"]["fp"] == 1 and fb["hard"]["fp"] == 0
    md, tables = M.build_report(run, {}, {}, {}, {})
    listed = {r["id"] for r in tables["not_scored"]}
    assert {"b3", "b4", "g2"} <= listed
    assert [m["id"] for m in tables["misses"]] == ["b2"]
    assert "WITH OSV MAL- lookup (no-OSV run missing" in md


def test_hard_fp_by_label_and_headline_uses_noosv():
    main = {"b1": _rec("b1", "known_bad", tiers={"known_malicious": 1}),
            "g1": _rec("g1", "known_good", label="High-risk patterns: review before use")}
    noosv = {"b1": _rec("b1", "known_bad"), "g1": _rec("g1", "known_good")}
    assert M.hard_fp(main["g1"])
    md, tables = M.build_report(main, noosv, {}, {}, {})
    head = {(r["run"], r["operating_point"]): r["hits"] for r in tables["recall"]}
    assert head[("headline", "strict")] == 0 and head[("with_osv", "strict")] == 1


def test_per_detector_and_contribution():
    d1 = {"decoded_payload": {"tier": "high_risk", "status": "ran"}, "behavior_patterns": {"tier": "review", "status": "ran"}}
    d2 = {"decoded_payload": {"tier": "none_found", "status": "ran"}, "behavior_patterns": {"tier": "review", "status": "ran"}}
    bad = [_rec("b1", "known_bad", tiers={"high_risk": 1, "review": 1}, detectors=d1),
           _rec("b2", "known_bad", tiers={"review": 1}, detectors=d2)]
    good = [_rec("g1", "known_good", tiers={"review": 1}, detectors=d2)]
    rows = {r["detector"]: r for r in M.per_detector(bad, good)}
    assert rows["decoded_payload"]["strict_hits"] == 1 and rows["decoded_payload"]["strict_fp"] == 0
    assert rows["behavior_patterns"]["lenient_hits"] == 2 and rows["behavior_patterns"]["lenient_fp"] == 1
    c = M.contribution(bad, M.STRICT)
    assert c["only"]["decoded_payload"] == 1


# ------------------------------------------------------------------ guards

def test_loud_failure_when_gemini_key_present(monkeypatch, capsys, ai_off):
    monkeypatch.setenv("GEMINI_API_KEY", "dummy-not-a-real-key")
    with pytest.raises(RB.GuardError):
        RB.assert_ai_off()
    assert RB.main(["--split", "dev", "--limit", "0"]) == 2
    assert "REFUSING TO RUN: AI/Gemini key" in capsys.readouterr().err


def test_loud_failure_when_ai_module_imported(monkeypatch, ai_off):
    for k in RB.AI_KEY_VARS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setitem(sys.modules, "intelligence", object())
    with pytest.raises(RB.GuardError):
        RB.assert_ai_off()


def test_refuses_test_split_without_frozen_ruleset(tmp_path, monkeypatch):
    from detectors import version as V
    no_version = tmp_path / "README.md"
    no_version.write_text("# protocol without a frozen ruleset\n", encoding="utf-8")
    with pytest.raises(RB.GuardError):
        RB.check_frozen("test", no_version)
    wrong = tmp_path / "R2.md"
    wrong.write_text("| Frozen ruleset | **`1999.01.01-1`** |\n", encoding="utf-8")
    with pytest.raises(RB.GuardError):
        RB.check_frozen("test", wrong)
    right = tmp_path / "R3.md"
    right.write_text(f"| Frozen ruleset | **`{V.RULESET_VERSION}`** |\n", encoding="utf-8")
    assert RB.check_frozen("test", right) == V.RULESET_VERSION
    monkeypatch.setattr(V, "RULESET_FROZEN", False)
    with pytest.raises(RB.GuardError):
        RB.check_frozen("all", right)
    assert RB.check_frozen("dev", no_version) == ""      # the dev split is allowed (harness debugging)


def test_protocol_records_the_current_frozen_ruleset():
    from detectors import version as V
    assert RB.readme_frozen_version() == V.RULESET_VERSION and V.RULESET_FROZEN


def test_transient_reasons():
    assert RB.transient("registry: PyPI lookup failed (timeout)")
    assert RB.transient("artifact not read (download_failed (HTTP 503))")
    assert RB.transient("item time budget (300 s) exceeded")
    assert RB.transient("registry: npm lookup failed (offline: not cached)")
    assert not RB.transient("artifact not read (too_large)")
    assert not RB.transient("registry: 'x' is not on PyPI")


# ------------------------------------------------------------------ dev-set overlap

def test_overlap_moves_items_to_dev():
    dev = {"repos": {"fortra/impacket": "cred", "lodash/lodash": "cred"},
           "packages": {"impacket": "cred", "openai": "cred openai/openai-python"}}
    items = [bench_items._item("scary", "PyPI", "impacket", "1"), bench_items._item("known_good", "npm", "x", "1", repo="LoDash/lodash"),
             bench_items._item("known_good", "PyPI", "OpenAI", "1"), bench_items._item("known_good", "PyPI", "requests", "1")]
    items, moves = bench_items.assign_splits(items, dev)
    assert [i["split"] for i in items] == ["dev", "dev", "dev", "test"]
    assert len(moves) == 3
    assert bench_items.repo_aliases("openai/openai-python") == {"openai-python", "openai"}


def test_missing_credibility_manifest_refuses(monkeypatch, tmp_path):
    monkeypatch.setattr(bench_items, "CREDIBILITY", tmp_path / "missing.csv")
    with pytest.raises(SystemExit):
        bench_items.dev_sets()


def test_real_manifests_have_no_test_dev_overlap():
    items, moves = bench_items.all_items()
    dev = bench_items.dev_sets()
    for i in items:
        if i["split"] == "test":
            assert (i["repo"] or "").lower() not in dev["repos"]
            assert bench_items.norm(i["package"]) not in dev["packages"]
    assert {m["id"] for m in moves} >= {"scary:PyPI:impacket@0.13.1", "scary:PyPI:pwntools@4.15.0"}


# ------------------------------------------------------------------ artifact contents adapter

def test_data_from_contents_keeps_dist_skips_vendored_and_minified():
    contents = {"text": {"dist/index.js": "x()", "node_modules/a/index.js": "y()", "lib/app.min.js": "z()",
                         "pkg/__init__.py": "import os\n", "tests/test_a.py": "assert 1\n", "package-lock.json": "{}",
                         ".github/workflows/ci.yml": "on: push\n"},
                "binaries": [{"path": "bin/tool.exe", "size": 2048, "sha256": "ab" * 32}], "skipped": ["big.py"]}
    d = RB.data_from_contents(contents)
    assert "dist/index.js" in d["text"] and "node_modules/a/index.js" not in d["text"]
    assert "lib/app.min.js" not in d["text"] and "package-lock.json" not in d["text"]
    assert "pkg/__init__.py" in d["py"] and "tests/test_a.py" not in d["py"] and d["skipped"]["tests"] == 1
    assert ".github/workflows/ci.yml" in d["workflows"]
    assert d["counts"]["text_not_read"] == 1                   # the member the archive reader skipped
    assert d["binaries"][0]["path"] == "bin/tool.exe"


def test_osv_index_version_semantics(tmp_path):
    idx = [{"id": "MAL-1", "package": "Evil_Pkg", "versions": ["1.0"], "withdrawn": None},
           {"id": "MAL-2", "package": "evil-pkg", "versions": [], "withdrawn": None},
           {"id": "MAL-3", "package": "evil-pkg", "versions": ["2.0"], "withdrawn": "2025-01-01"}]
    (tmp_path / "osv_mal_PyPI.json").write_text(json.dumps(idx), encoding="utf-8")
    o = RB.OsvIndex(offline=True, cache_dir=tmp_path)
    assert o.mal_ids("PyPI", "evil.pkg", "1.0") == ["MAL-1", "MAL-2"]
    assert o.mal_ids("PyPI", "evil-pkg", "2.0") == ["MAL-2"]          # range-based record covers all; withdrawn ignored
    with pytest.raises(ConnectionError):
        o.mal_ids("npm", "x", "1")                                     # offline and not cached -> not assessed


def test_run_item_error_is_not_assessed(monkeypatch):
    def boom(item, osv):
        raise ValueError("parser bug")
    monkeypatch.setattr(RB, "scan_artifact", boom)
    rec = RB.run_item({"id": "x"}, "artifact", True, 5)
    assert rec["status"] == "not_assessed" and "ValueError" in rec["not_assessed_reason"]


def test_item_time_budget(monkeypatch):
    import time as _t
    monkeypatch.setattr(RB, "scan_artifact", lambda item, osv: _t.sleep(2) or {"status": "scored"})
    rec = RB.run_item({"id": "x"}, "artifact", True, 0.2)
    assert rec["status"] == "not_assessed" and RB.transient(rec["not_assessed_reason"])


# ------------------------------------------------------------------ resumability

def _synthetic_items(n=5):
    return [{**bench_items._item("dev", "PyPI", f"pkg{i}", "1.0", repo=f"o/pkg{i}"), "split": "dev", "obtainable": "yes"}
            for i in range(n)]


def test_kill_and_resume(monkeypatch, tmp_path, ai_off):
    for k in RB.AI_KEY_VARS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("REPOHEALTH_CACHE", str(tmp_path / "cache"))
    items = _synthetic_items(5)
    monkeypatch.setattr(bench_items, "all_items", lambda: (items, []))
    calls = []

    def fake_scan(item, osv):
        calls.append(item["id"])
        if item["package"] == "pkg4":
            return {"status": "not_assessed", "not_assessed_reason": "registry: PyPI lookup failed (timeout)"}
        return {"status": "scored", "findings_by_tier": {"high_risk": 0}, "label": "No findings"}

    monkeypatch.setattr(RB, "scan_artifact", fake_scan)
    out = tmp_path / "run.jsonl"
    args = ["--split", "dev", "--out", str(out), "--sleep", "0", "--offline", "--item-budget", "5"]
    # simulate the process being killed (Ctrl+C / window closed) while the 3rd record is being written
    real_append = RB.append
    n = {"k": 0}

    def killing_append(path, rec):
        n["k"] += 1
        if n["k"] == 3:
            raise KeyboardInterrupt
        real_append(path, rec)

    monkeypatch.setattr(RB, "append", killing_append)
    with pytest.raises(KeyboardInterrupt):
        RB.main(args)
    first = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines()]
    assert len(first) == 2
    monkeypatch.setattr(RB, "append", real_append)
    calls.clear()
    assert RB.main(args) == 0
    lines = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines()]
    ids = [r["id"] for r in lines]
    assert len(set(ids)) == 5 and len(ids) == 5                  # nothing scanned twice, nothing lost
    assert not set(calls) & {r["id"] for r in first}             # finished items were skipped on resume
    timeout_rec = next(r for r in lines if r["package"] == "pkg4")
    assert timeout_rec["retryable"] is True
    # a third run retries only the transient failure
    calls.clear()
    assert RB.main(args) == 0
    assert calls == [timeout_rec["id"]]


def test_resume_refuses_mixed_settings(monkeypatch, tmp_path, ai_off):
    for k in RB.AI_KEY_VARS:
        monkeypatch.delenv(k, raising=False)
    items = _synthetic_items(1)
    monkeypatch.setattr(bench_items, "all_items", lambda: (items, []))
    monkeypatch.setattr(RB, "scan_artifact", lambda item, osv: {"status": "not_assessed", "not_assessed_reason": "timeout"})
    out = tmp_path / "run.jsonl"
    assert RB.main(["--split", "dev", "--out", str(out), "--sleep", "0", "--offline"]) == 0
    assert RB.main(["--split", "dev", "--out", str(out), "--sleep", "0", "--offline", "--no-osv"]) == 2


# ------------------------------------------------------------------ end to end, offline, synthetic cache

def _write_cache(url, kind, payload):
    import http_cache
    p = Path(http_cache._path(url, kind))
    p.parent.mkdir(parents=True, exist_ok=True)
    if kind == "json":
        p.write_text(json.dumps({"url": url, "status": 200, "data": payload}), encoding="utf-8")
    else:
        p.write_bytes(payload)


def _sdist(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo(f"demo-pkg-1.0.0/{name}")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_end_to_end_artifact_mode_offline(monkeypatch, tmp_path, ai_off):
    for k in RB.AI_KEY_VARS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("REPOHEALTH_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("REPOHEALTH_SNAPSHOT", "2026-01-01")
    setup_text = (ROOT / "benchmark_fixtures" / "mal_base64_exec_setup.py.sample").read_text(encoding="utf-8")
    blob = _sdist({"setup.py": setup_text, "demo_pkg/__init__.py": "VERSION = '1.0.0'\n"})
    url = "https://files.example.invalid/demo-pkg-1.0.0.tar.gz"
    _write_cache("https://pypi.org/pypi/demo-pkg/json", "json", {
        "info": {"name": "demo-pkg", "version": "1.0.0", "project_urls": {}},
        "releases": {"1.0.0": [{"filename": "demo-pkg-1.0.0.tar.gz", "url": url, "size": len(blob),
                                "packagetype": "sdist", "upload_time_iso_8601": "2025-12-01T00:00:00Z", "yanked": False}]}})
    _write_cache(url, "bin", blob)
    item = {**bench_items._item("dev", "PyPI", "demo-pkg", "1.0.0", repo="o/demo-pkg"), "split": "dev", "obtainable": "yes"}
    monkeypatch.setattr(bench_items, "all_items", lambda: ([item], []))
    out = tmp_path / "e2e.jsonl"
    assert RB.main(["--split", "dev", "--out", str(out), "--sleep", "0", "--offline", "--snapshot", "2026-01-01"]) == 0
    rec = json.loads(out.read_text(encoding="utf-8").splitlines()[-1])
    assert rec["status"] == "scored" and rec["mode"] == "artifact" and rec["run"]["ai_layer"] == "off"
    assert rec["findings_by_tier"]["high_risk"] >= 1                 # the setup.py payload is found
    assert rec["label"].startswith("High-risk patterns")
    assert rec["detectors"]["release_vs_git"]["status"] == "not_assessed"
    assert rec["detectors"]["tagless_release"]["status"] == "not_assessed"
    assert rec["artifact"]["sha256"] and rec["artifact"]["members"] == 2
    assert "intelligence" not in sys.modules


# ------------------------------------------------------------------ DataDog extraction safety

def _crc_table():
    t = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        t.append(c)
    return t


_T = _crc_table()


def _zipcrypto(data: bytes, password: bytes, crc: int) -> bytes:
    """Legacy ZipCrypto (PKWARE APPNOTE 6.1), to build a synthetic encrypted archive like the dataset's."""
    k = [0x12345678, 0x23456789, 0x34567890]

    def upd(b):
        k[0] = _T[(k[0] ^ b) & 0xFF] ^ (k[0] >> 8)
        k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k[2] = _T[(k[2] ^ (k[1] >> 24)) & 0xFF] ^ (k[2] >> 8)

    for b in password:
        upd(b)
    out = bytearray()
    for b in bytes(11) + bytes([crc >> 24]) + data:
        t = (k[2] | 2) & 0xFFFF
        out.append(b ^ (((t * (t ^ 1)) >> 8) & 0xFF))
        upd(b)
    return bytes(out)


def _encrypted_zip(members: dict[str, bytes], password: bytes = b"infected") -> bytes:
    body, central = bytearray(), bytearray()
    for name, data in members.items():
        crc = binascii.crc32(data) & 0xFFFFFFFF
        enc = _zipcrypto(data, password, crc)
        nb = name.encode()
        off = len(body)
        body += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 1, 0, 0, 0x21, crc, len(enc), len(data), len(nb), 0) + nb + enc
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 1, 0, 0, 0x21, crc, len(enc), len(data),
                               len(nb), 0, 0, 0, 0, 0, off) + nb
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(members), len(members), len(central), len(body), 0)
    return bytes(body + central + end)


def test_extract_reads_zipcrypto_with_password():
    blob = _encrypted_zip({"2024-01-01-evil-v1.0/evil-1.0/setup.py": b"import os\n",
                           "2024-01-01-evil-v1.0/evil-1.0/evil/__init__.py": b"X = 1\n"})
    z = zipfile.ZipFile(io.BytesIO(blob))
    assert all(i.flag_bits & 1 for i in z.infolist())               # really encrypted
    res = XD.read_sample(blob)
    assert sorted(res["text"]) == ["2024-01-01-evil-v1.0/evil-1.0/evil/__init__.py", "2024-01-01-evil-v1.0/evil-1.0/setup.py"]
    assert XD.read_sample(blob, password=b"wrong")["text"] == {}     # wrong password -> nothing read


def test_extract_rejects_traversal_executables_and_bombs(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("../../evil.py", "print(1)\n")
        z.writestr("/etc/abs.py", "print(1)\n")
        z.writestr("C:/win/x.py", "print(1)\n")
        z.writestr("pkg/file.py:stream", "print(1)\n")
        z.writestr("pkg/payload.exe", b"MZ" + b"\x90" * 4000)
        z.writestr("pkg/lib.so", b"\x7fELF" + b"\x00" * 4000)
        z.writestr("pkg/blob.bin", b"\x01\x02\x00\x00" * 1000)
        z.writestr("pkg/bomb.txt", b"A" * (3 * 1024 * 1024))         # ratio far above 200
        z.writestr("pkg/run.ps1", "Write-Host hi\n")
        z.writestr("pkg/CON.py", "x = 1\n")
        z.writestr("pkg/setup.py", "from setuptools import setup\n")
    res = XD.read_sample(buf.getvalue())
    reasons = {m["member"]: m["reason"] for m in res["members"] if m["action"] == "skipped"}
    assert reasons["../../evil.py"].startswith("path traversal")
    assert reasons["/etc/abs.py"] == "absolute path"
    assert reasons["C:/win/x.py"] == "absolute path"
    assert reasons["pkg/file.py:stream"].startswith("':' in name")
    assert reasons["pkg/payload.exe"].startswith("executable")
    assert reasons["pkg/lib.so"].startswith("executable")
    assert reasons["pkg/blob.bin"].startswith("binary")
    assert "archive bomb" in reasons["pkg/bomb.txt"]
    assert set(res["text"]) == {"pkg/run.ps1", "pkg/_CON.py", "pkg/setup.py"}
    dest = tmp_path / "samples" / "x"
    n, _ = XD.write_sample(res["text"], dest)
    written = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
    assert n == 3 and written == ["_CON.py.sample", "run.ps1.sample", "setup.py.sample"]
    assert all(p.endswith(".sample") for p in written)              # never a real .ps1 / .py / .exe on disk
    assert not (tmp_path / "evil.py").exists() and not (tmp_path / "evil.py.sample").exists()


def test_extract_member_count_limit(monkeypatch):
    monkeypatch.setattr(XD, "MAX_MEMBERS", 5)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(20):
            z.writestr(f"p/f{i}.py", "x = 1\n")
    res = XD.read_sample(buf.getvalue())
    assert len(res["text"]) == 5 and any("member count" in x for x in res["limits"])


def test_extract_nested_sdist_read_in_memory():
    inner = _sdist({"setup.py": "from setuptools import setup\n", "demo/x.py": "Y = 2\n"})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("2024-01-01-demo-v1.0/demo-1.0.0.tar.gz", inner)
    res = XD.read_sample(buf.getvalue())
    assert set(res["text"]) == {"2024-01-01-demo-v1.0/demo-1.0.0/setup.py", "2024-01-01-demo-v1.0/demo-1.0.0/demo/x.py"}
    assert XD.strip_common_root(sorted(res["text"])) == 2


def test_extract_selection_is_seeded_and_parses_scoped_npm():
    listing = [XD.parse_sample_path(f"samples/npm/malicious_intent/@sc/pkg{i}/1.0.{i}/2024-01-01-pkg-v1.zip") for i in range(30)]
    listing += [XD.parse_sample_path(f"samples/pypi/compromised_lib/lib{i}/0.{i}/2024-01-01-lib-v0.zip") for i in range(30)]
    assert listing[0]["package"] == "@sc/pkg0" and listing[0]["ecosystem"] == "npm"
    a = XD.select_samples(sorted(listing, key=lambda r: r["sample_path"]), {("PyPI", "lib3")}, n_random=5)
    b = XD.select_samples(sorted(listing, key=lambda r: r["sample_path"]), {("PyPI", "lib3")}, n_random=5)
    assert a == b and any(r["package"] == "lib3" and "candidate" in r["selected_by"] for r in a)
    assert len([r for r in a if r["eco_dir"] == "npm"]) == 5
    assert XD.parse_sample_path("samples/pypi/x.zip") is None


def test_load_sample_dir_refuses_paths_outside_samples(tmp_path):
    with pytest.raises(ValueError):
        RB.load_sample_dir(str(tmp_path))


# ------------------------------------------------------------------ chat-AI comparison

def test_chat_prompt_states_truncation_and_never_says_safe():
    files = {"setup.py": "import os\n" * 10, "pkg/big.py": "x = 1\n" * 5000, "README.md": "hello"}
    prompt, info = CC.build_prompt({"ecosystem": "PyPI", "package": "demo", "version": "1.0"}, files)
    assert prompt.index("=== setup.py ===") < prompt.index("=== pkg/big.py ===")
    assert f"{CC.MAX_CODE_CHARS} characters in total" in prompt and info["truncated"] is True
    assert "README.md" not in prompt and "VERDICT: MALICIOUS or SUSPICIOUS or NO_CONCERNS" in prompt
    assert "safe" not in prompt.lower().replace("setup", "")


def test_chat_selection_is_seeded_and_stable():
    items = [{**bench_items._item("known_bad", "npm", f"b{i}", "1"), "obtainable": "yes"} for i in range(40)]
    items += [bench_items._item("known_good", "npm", f"g{i}", "1") for i in range(40)]
    items += [bench_items._item("scary", "npm", f"s{i}", "1") for i in range(10)]
    a, b = CC.select_items(items), CC.select_items(items)
    assert a == b and len(a) == 30
    fewer_bad = CC.select_items(items[5:])                           # a smaller known-bad pool
    assert [r for r in a if r["expected"] == "benign"] == [r for r in fewer_bad if r["expected"] == "benign"]


def test_chat_summary_counts():
    scoring = [{"item_id": "b1", "expected": "malicious", "chat_verdict": "MALICIOUS", "tool_strict_hit": "True", "tool_lenient_hit": "True"},
               {"item_id": "b2", "expected": "malicious", "chat_verdict": "suspicious", "tool_strict_hit": "False", "tool_lenient_hit": "True"},
               {"item_id": "g1", "expected": "benign", "chat_verdict": "NO_CONCERNS", "tool_strict_hit": "False", "tool_lenient_hit": "False"},
               {"item_id": "g2", "expected": "benign", "chat_verdict": "", "tool_strict_hit": "", "tool_lenient_hit": ""}]
    repeats = [{"item_id": "b1", "run_1": "MALICIOUS", "run_2": "SUSPICIOUS", "run_3": "MALICIOUS", "run_4": "", "run_5": ""},
               {"item_id": "g1", "run_1": "NO_CONCERNS", "run_2": "NO_CONCERNS", "run_3": "", "run_4": "", "run_5": ""}]
    md = CC.summarise(scoring, repeats)
    assert "| tool | 50.0% (1/2" in md and "| chat | 50.0% (1/2" in md        # strict
    assert "| chat | 100.0% (2/2" in md                                   # lenient
    assert "changed between runs: 50.0% (1/2" in md


def test_repo_mode_wiring_and_osv_ablation(monkeypatch):
    """Repo mode cannot reach GitHub in the test environment: the pipeline functions are replaced by stubs to check
    the wiring (features -> scan -> security -> releases -> apply_gate) and that --no-osv drops MAL- findings."""
    import github_client, releases, repo_scan, scoring, security
    seen = {}
    monkeypatch.setattr(github_client, "fetch_features", lambda c, o, r: {"full_name": f"{o}/{r}", "description": "", "topics": []})
    monkeypatch.setattr(repo_scan, "scan_repo", lambda c, o, r: {"ran": True, "scan_coverage": {}, "findings": []})
    monkeypatch.setattr(security, "assess_security", lambda c, o, r: {"level": "Low", "package": None, "checks": {}, "findings": [
        {"source": "OSV (Confirmed Malware)", "item": "dep"}, {"source": "OSV (dependency)", "item": "dep2"}]})
    monkeypatch.setattr(releases, "collect_release_context", lambda o, r, p: None)
    monkeypatch.setattr(scoring, "compute_health_score", lambda f: {"score": 80, "label": "Healthy"})

    def gate(health, sec, flags, scan, features=None, releases=None):
        seen["sources"] = [f["source"] for f in sec["findings"]]
        return {"trust_score": 90, "label": "No findings", "detectors": [], "pillars": {}}
    monkeypatch.setattr(security, "apply_gate", gate)
    rec = RB.scan_repository({"repo": "o/r"}, osv=False)
    assert rec["status"] == "scored" and seen["sources"] == ["OSV (dependency)"]
    RB.scan_repository({"repo": "o/r"}, osv=True)
    assert seen["sources"] == ["OSV (Confirmed Malware)", "OSV (dependency)"]
    assert RB.scan_repository({"repo": ""}, osv=True)["status"] == "not_applicable"
