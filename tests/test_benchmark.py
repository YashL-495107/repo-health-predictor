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

import re

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
    # Streamlit's AppTest (tests/test_app.py) leaves sys.modules["__main__"] pointing at app.py; a spawned item
    # process re-imports __main__, which would load the app (and its AI module). In real runs __main__ is the runner.
    import types
    monkeypatch.setitem(sys.modules, "__main__", types.ModuleType("__main__"))
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
    assert "WARNING: not the protocol's headline settings" in md      # these synthetic records carry no run config


def test_hard_fp_by_label_and_headline_uses_noosv():
    main = {"b1": _rec("b1", "known_bad", tiers={"known_malicious": 1}),
            "g1": _rec("g1", "known_good", label="High-risk patterns: review before use")}
    noosv = {"b1": _rec("b1", "known_bad"), "g1": _rec("g1", "known_good")}
    assert M.hard_fp(main["g1"])
    md, tables = M.build_report(noosv, {}, main, {}, {})
    head = {(r["run"], r["operating_point"]): r["hits"] for r in tables["recall"]}
    assert head[("headline", "strict")] == 0 and head[("with_osv", "strict")] == 1
    assert ("frag_on", "strict") not in head and "| strict | 0.0% (0/1" in md and "not run" in md


def test_headline_name_flags_wrong_settings():
    assert M.headline_name({"mode": "artifact", "osv": False, "fragility_escalation": False}) == \
        "WITHOUT OSV MAL- lookup, fragility escalation OFF"
    assert "WARNING" in M.headline_name({"mode": "artifact", "osv": False, "fragility_escalation": True})
    assert "WARNING" not in M.headline_name({"mode": "repo", "osv": False, "fragility_escalation": True})
    assert "WARNING" in M.headline_name({"mode": "artifact", "osv": True, "fragility_escalation": False})


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
    """v1's protocol records 2026.11.08-12; the code is either that ruleset or one pre-registered for the fresh
    split in PREREG_v2.md (branch ruleset-v2), and frozen either way."""
    from detectors import version as V
    assert RB.readme_frozen_version() == "2026.11.08-12" and V.RULESET_FROZEN
    assert V.RULESET_VERSION == RB.readme_frozen_version() or (
        V.RULESET_VERSION in RB.FRESH_RULESETS and f"`{V.RULESET_VERSION}`" in (RB.BENCH / "PREREG_v2.md").read_text(encoding="utf-8"))


def test_v1_test_split_refuses_with_v2_ruleset():
    from detectors import version as V
    if V.RULESET_VERSION != RB.readme_frozen_version():
        with pytest.raises(RB.GuardError):
            RB.check_frozen("test")


def test_transient_reasons():
    assert RB.transient("registry: PyPI lookup failed (timeout)")
    assert RB.transient("artifact not read (download_failed (HTTP 503))")
    assert RB.transient("item time budget (300 s) exceeded")
    assert RB.transient("registry: npm lookup failed (offline: not cached)")
    assert RB.transient("repository features: RateLimitError: GitHub API rate limit reached (resets in about 7 min)")
    assert not RB.transient("repository features: GitHubError: GitHub refused this request (403).")
    assert not RB.transient("artifact not read (too_large)")
    assert not RB.transient("killed: memory limit exceeded (RLIMIT_AS 3072 MB)")
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
    args = ["--split", "dev", "--out", str(out), "--sleep", "0", "--offline", "--item-budget", "5", "--no-isolate"]
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
    assert RB.main(["--split", "dev", "--out", str(out), "--sleep", "0", "--offline", "--no-isolate"]) == 0
    assert RB.main(["--split", "dev", "--out", str(out), "--sleep", "0", "--offline", "--no-isolate", "--no-osv"]) == 2


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
    cands = {("PyPI", "lib3", "0.3"), ("PyPI", "lib4", "9.9")}          # version-level; lib4 9.9 is not in the dataset
    a = XD.select_samples(sorted(listing, key=lambda r: r["sample_path"]), cands, n_random=5)
    b = XD.select_samples(sorted(listing, key=lambda r: r["sample_path"]), cands, n_random=5)
    assert a == b and any(r["package"] == "lib3" and "candidate" in r["selected_by"] for r in a)
    assert not any(r["package"] == "lib4" and "candidate" in r["selected_by"] for r in a)   # no substitute version
    assert len([r for r in a if r["eco_dir"] == "npm"]) == 5
    assert XD.parse_sample_path("samples/pypi/x.zip") is None


def test_load_sample_dir_refuses_paths_outside_samples(tmp_path):
    with pytest.raises(ValueError):
        RB.load_sample_dir("../../etc", root=tmp_path / "samples")
    (tmp_path / "samples" / "datadog" / "x").mkdir(parents=True)
    (tmp_path / "samples" / "datadog" / "x" / "setup.py.sample").write_text("x = 1\n", encoding="utf-8")
    assert RB.load_sample_dir("datadog/x", root=tmp_path / "samples")["text"] == {"setup.py": "x = 1\n"}


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


# ------------------------------------------------------------------ process isolation (spawned child processes)

def _iso_cfg(scan_fn, mem_mb=0):
    return {"mode": "artifact", "osv": False, "fragility_escalation": True, "offline": True, "mem_mb": mem_mb,
            "line_cap": RB.LINE_CAP_CHARS, "scan_fn": scan_fn, "osv_cache": None, "env": {"REPOHEALTH_OFFLINE": "1"}}


def test_isolated_item_that_sleeps_forever_is_killed(ai_off):
    rec = RB.run_item_isolated({"id": "x"}, _iso_cfg("bench_hooks:sleep_forever"), budget_s=8)
    assert rec["status"] == "not_assessed" and rec["not_assessed_reason"].startswith("timeout")
    assert rec["error"] == "timeout" and RB.transient(rec["not_assessed_reason"])
    assert rec["elapsed_s"] < 30


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS does not enforce RLIMIT_AS")
def test_isolated_item_that_allocates_too_much_is_killed(ai_off):
    rec = RB.run_item_isolated({"id": "x"}, _iso_cfg("bench_hooks:allocate_forever", mem_mb=1024), budget_s=60)
    assert rec["status"] == "not_assessed", rec
    assert rec["not_assessed_reason"].startswith("killed: memory limit exceeded"), rec   # Linux RLIMIT_AS / Windows job
    assert rec["error"] == "killed" and not RB.transient(rec["not_assessed_reason"])


def test_isolated_item_ok_and_crash(ai_off):
    ok = RB.run_item_isolated({"id": "x"}, _iso_cfg("bench_hooks:ok"), budget_s=60)
    assert ok["status"] == "scored" and ok["isolation"].startswith("process")
    dead = RB.run_item_isolated({"id": "x"}, _iso_cfg("bench_hooks:hard_exit"), budget_s=60)
    assert dead["status"] == "not_assessed" and dead["not_assessed_reason"].startswith("killed") and "exit code 3" in dead["not_assessed_reason"]


def test_run_continues_after_killed_items(monkeypatch, tmp_path, ai_off):
    items = [{**bench_items._item("dev", "PyPI", f"pkg{i}", "1.0", repo=f"o/pkg{i}"), "split": "dev", "obtainable": "yes"}
             for i in range(3)]
    monkeypatch.setattr(bench_items, "all_items", lambda: (items, []))
    out = tmp_path / "iso.jsonl"
    assert RB.main(["--split", "dev", "--out", str(out), "--sleep", "0", "--offline", "--item-budget", "6",
                    "--scan-fn", "bench_hooks:sleep_if_pkg1"]) == 0
    recs = {r["package"]: r for r in map(json.loads, out.read_text(encoding="utf-8").splitlines())}
    assert recs["pkg0"]["status"] == "scored" and recs["pkg2"]["status"] == "scored"
    assert recs["pkg1"]["status"] == "not_assessed" and recs["pkg1"]["retryable"] is True
    md, tables = M.build_report({k: {**v, "category": "known_good", "split": "test"} for k, v in recs.items()}, {}, {}, {}, {})
    assert "pkg1" in {r["id"].split(":")[2].split("@")[0] for r in tables["not_scored"]}


def test_line_cap_truncates_and_reports():
    import repo_scan
    data = {"text": {"a.js": "x" * 50 + "\nshort"}, "py": {"m.py": b"y = 1\n" + b"z" * 60}}
    changed = repo_scan.cap_long_lines(data, 20)
    assert sorted(changed) == ["a.js", "m.py"]
    assert data["text"]["a.js"] == "x" * 20 + "\nshort" and data["py"]["m.py"] == b"y = 1\n" + b"z" * 20


def test_eta_and_format():
    assert RB.eta_seconds([], 5) is None
    assert RB.eta_seconds([1, 3, 100], 10) == 30
    assert RB.fmt_hms(3725) == "1:02:05" and RB.fmt_hms(None) == "?"


def test_prepare_known_bad_end_to_end_synthetic(monkeypatch, tmp_path, ai_off):
    """Synthetic dataset (encrypted like the real one) -> extraction into a custom samples folder -> known-bad item
    manifest -> chat-AI item list. Every output goes to tmp_path; no scan is run."""
    import prepare_known_bad as PREP
    ds = tmp_path / "dd"
    zrel = "samples/pypi/malicious_intent/demo-evil/1.0.0/2024-01-01-demo-evil-v1.0.0.zip"
    (ds / zrel).parent.mkdir(parents=True)
    (ds / zrel).write_bytes(_encrypted_zip({"2024-01-01-demo-evil-v1.0.0/demo-evil-1.0.0/setup.py": b"x = 1\n",
                                            "2024-01-01-demo-evil-v1.0.0/demo-evil-1.0.0/run.exe": b"MZ" + bytes(3000)}))
    samples = tmp_path / "my samples"
    monkeypatch.setattr(XD, "MANIFEST", tmp_path / "datadog_extracted.csv")
    monkeypatch.setattr(XD, "MEMBERS", tmp_path / "datadog_members.csv")
    monkeypatch.setattr(bench_items, "DATADOG_EXTRACTED", tmp_path / "datadog_extracted.csv")
    monkeypatch.setattr(PREP, "OUT", tmp_path / "known_bad_items.csv")
    monkeypatch.setattr(CC, "OUT", tmp_path / "chat_ai")
    assert PREP.main(["--datadog-dir", str(ds), "--samples-dir", str(samples)]) == 0
    written = [p.relative_to(samples).as_posix() for p in samples.rglob("*") if p.is_file()]
    assert len(written) == 1 and written[0].startswith("datadog/pypi/demo-evil_1.0.0_") and written[0].endswith("setup.py.sample")
    rows = bench_items.read_manifest(tmp_path / "known_bad_items.csv")
    dd = [r for r in rows if r["source"] == "datadog"]
    assert len(dd) == 1 and dd[0]["has_code"] == "yes" and dd[0]["split"] == "test"
    assert sum(r["has_code"] == "yes" for r in rows) == 4          # 3 registry items + 1 sample
    chat = bench_items.read_manifest(tmp_path / "chat_ai" / "items.csv")
    assert sum(r["expected"] == "malicious" for r in chat) == 4
    # antivirus quarantine: an emptied sample folder is "no code" and the runner never scores it as "no findings"
    for p in samples.rglob("*.sample"):
        p.unlink()
    assert [r for r in PREP.build(samples) if r["source"] == "datadog"][0]["has_code"] == "no"
    monkeypatch.setenv("REPOHEALTH_SAMPLES_DIR", str(samples))
    item = next(i for i in bench_items.all_items()[0] if i["source"] == "datadog")
    rec = RB.scan_artifact(item, osv=False)
    assert rec["status"] == "not_assessed" and "missing" in rec["not_assessed_reason"]


def test_selfcheck_uses_dev_items_only_and_local_checks(tmp_path, ai_off):
    import selfcheck
    specs = selfcheck.dev_items()
    assert {m for _n, m, _i in specs} == {"repo", "artifact"} and len(specs) == 3
    assert all(i["split"] == "dev" for _n, _m, i in specs)
    assert {i["ecosystem"] for _n, m, i in specs if m == "artifact"} == {"PyPI", "npm"}
    res = {name: ok for name, ok, _d, _f in selfcheck.local_checks(tmp_path / "samples", tmp_path / "cache")}
    assert res["Samples folder writable"] and res["Dev manifest present, overlap check"]
    assert res["AI layer off (no Gemini key, no AI module)"] and res["Frozen ruleset recorded in the protocol"]


def test_contamination_reads_only_the_post_viewing_section(tmp_path):
    p = tmp_path / "CHANGELOG.md"
    p.write_text("## Post-viewing changes (x)\n\n(no entries)\n\n## Pre-run changes (y)\n\n- a wiring fix\n", encoding="utf-8")
    assert RB.contamination(p) == "not contaminated"
    p.write_text("## Post-viewing changes (x)\n\n- tuned a rule after viewing results\n\n## Pre-run changes (y)\n", encoding="utf-8")
    assert RB.contamination(p).startswith("CONTAMINATED")
    p.write_text("# old format\n\n- entry\n", encoding="utf-8")
    assert RB.contamination(p).startswith("CONTAMINATED")
    assert RB.contamination() == "not contaminated"          # the real changelog: only a pre-run change


def test_baseline_comparison_section():
    def rec(id_, cat, tiers=None, dets=None, findings=None):
        r = _rec(id_, cat, tiers=tiers, detectors=dets)
        r["findings"] = findings or []
        return r
    hist = {"publisher_change": {"tier": "review", "status": "ran"}, "dependency_injection": {"tier": "none_found", "status": "ran"}}
    head = {r["id"]: r for r in [
        rec("b1", "known_bad", {"high_risk": 1}, {"setup_py_hook": {"tier": "high_risk", "status": "ran"}}),
        rec("b2", "known_bad", {"review": 1}, {"behavior_patterns": {"tier": "review", "status": "ran"},
                                                "dependency_injection": {"tier": "none_found", "status": "ran"}}),
        rec("b3", "known_bad"),
        rec("g1", "known_good", {"review": 1}, hist),
        rec("g2", "known_good", {"review": 1}, {"setup_py_hook": {"tier": "review", "status": "ran"}}),
        rec("g3", "known_good")]}
    osv = {"osv_known_malicious": {"tier": "known_malicious", "status": "ran"}}
    with_osv = {k: dict(v) for k, v in head.items()}
    with_osv["b1"] = rec("b1", "known_bad", {"high_risk": 1, "known_malicious": 1}, osv)
    with_osv["b3"] = rec("b3", "known_bad", {"known_malicious": 1}, osv)
    lines, rows = M.baseline_block(head, head, with_osv)
    r = {x["row"]: x for x in rows}
    assert (r["OSV-only (MAL- lookup alone)"]["count"], r["OSV-only (MAL- lookup alone)"]["n"]) == (2, 3)
    assert r["detectors only, strict (headline)"]["count"] == 1 and r["detectors only, lenient (headline)"]["count"] == 2
    assert r["detectors + OSV, lenient"]["count"] == 3
    assert r["caught by the detectors (lenient) but not by OSV-only"]["count"] == 1          # b2
    assert r["caught by the detectors (strict) but not by OSV-only"]["count"] == 0
    assert r["caught by the detectors (lenient) but not by OSV-only"]["note"] == (
        "these are misses of the OSV lookup in this run (name/version matching), not gaps in OSV's coverage: "
        "every known-bad label comes from an OSV record")
    assert (r["history-detector lenient FPs"]["count"], r["history-detector lenient FPs"]["n"]) == (1, 2)
    assert r["dependency_injection ran"]["count"] == 1 and r["dependency_injection ran"]["note"] == "2 of 6 scored items"   # b2 and g1
    text = "\n".join(lines)
    assert "circular and biased upward" in text and "NOT a fair comparison" in text
    md, tables = M.build_report(head, head, with_osv, {}, {})
    assert "## Baseline comparison" in md and tables["baseline"] == rows


# ------------------------------------------------------------------ repo mode section (fixture run file)

REPO_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "repo_run_fixture.jsonl"


def test_repo_mode_section_from_fixture_run():
    repo = M.load_run(REPO_FIXTURE)
    lines, tables = M.repo_mode_block(repo)
    text = "\n".join(lines)
    rates = {(r["set"], r["kind"]): r for r in tables["repo_mode_false_positives"]}
    # known_good: 4 scored (1 review label, 1 high-risk label + finding, 1 none, 1 partial none), 1 not assessed
    assert (rates[("known_good", "strict")]["fp"], rates[("known_good", "strict")]["n"]) == (1, 4)
    assert rates[("known_good", "lenient")]["fp"] == 2 and rates[("known_good", "hard")]["fp"] == 1
    assert rates[("known_good", "soft")]["fp"] == 1
    lo, hi = M.wilson(2, 4)
    assert rates[("known_good", "lenient")]["ci_low"] == pytest.approx(lo) and rates[("known_good", "lenient")]["ci_high"] == pytest.approx(hi)
    assert rates[("scary", "lenient")]["fp"] == 1 and rates[("scary", "strict")]["rule_of_three"] == pytest.approx(1.5)
    assert rates[("dormant", "hard")]["fp"] == 0 and rates[("dormant", "hard")]["rule_of_three"] == pytest.approx(1.5)
    assert rates[("dormant", "soft")]["fp"] == 0                                  # Fragile is not a review label
    assert "| Random known-good (maintained) | lenient | 50.0% (2/4; 95% CI" in text
    assert "| Dormant / finished libraries | hard | 0.0% (0/2; 95% CI 0.0%-65.8%); rule of three: at most 150.0% |" in text
    assert [r["id"] for r in tables["repo_mode_not_scored"]] == ["known_good:PyPI:epsilon@5.0"]
    assert "Not scored in repo mode (listed, never imputed): 1 item(s)." in text and "RateLimitError" in text
    assert "Repo-mode known-bad recall is NOT measured" in text and "OSV MAL- lookup off" in text
    assert "known_bad:x" not in text


def test_repo_mode_section_in_report_and_absent_run():
    repo = M.load_run(REPO_FIXTURE)
    md, tables = M.build_report({"b1": _rec("b1", "known_bad")}, {}, {}, repo, {})
    assert "## Repo mode (what the app does)" in md and tables["repo_mode_not_scored"]
    md2, _ = M.build_report({"b1": _rec("b1", "known_bad")}, {}, {}, {}, {})
    assert "No repository-mode run given (--repo-run)" in md2 and "known-bad recall is not measured" in md2


def test_limits_and_readme_point_to_the_repo_mode_section_without_numbers():
    root = Path(__file__).resolve().parent.parent
    for name in ("LIMITS.md", "README.md"):
        text = (root / name).read_text(encoding="utf-8")
        assert 'section "Repo mode (what the app does)"' in text, name
        assert "repo-mode known-bad recall is not measured" in text.lower(), name
        i = text.index('section "Repo mode (what the app does)"')
        starts = [text.rfind(sep, 0, i) for sep in ("\n- ", "\n\n")]
        ends = [e for e in (text.find("\n- ", i), text.find("\n\n", i)) if e != -1]
        para = text[max(starts) + 1:min(ends) if ends else len(text)]
        para = para.replace("95%", "")                     # "95% intervals" names the interval, it is not a result
        assert not re.search(r"\d+(\.\d+)?%|\b\d+/\d+\b", para), f"{name}: no hand-typed repo-mode numbers: {para}"
