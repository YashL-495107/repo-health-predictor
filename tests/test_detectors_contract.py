"""Detector contract, registry, failure handling and equivalence with the existing malware engine."""
import io
import json
import os
import time
import zipfile

import pytest

import repo_scan
from benchmark_fixtures import FIXTURE_DIR, load_labels, virtual_path
from detectors import REGISTRY, RULESET_VERSION, run_detectors
from detectors.base import PILLARS, STATUSES, TIERS
from detectors.context import DetectorContext
from malware_proof import run_malware_proof_engine


def test_registry_entries_follow_the_contract():
    ids = [m.DETECTOR_ID for m in REGISTRY]
    assert len(ids) == len(set(ids))
    for m in REGISTRY:
        assert m.PILLAR in PILLARS and callable(m.detect)
        doc = (m.__doc__ or "").lower()
        assert "evasion" in doc and "false-positive" in doc, m.DETECTOR_ID


def test_every_detector_handles_an_empty_context():
    out = run_detectors(DetectorContext.build())
    assert len(out) == len(REGISTRY)
    for r in out:
        assert r["status"] in STATUSES and r["tier"] in TIERS and r["status"] != "ran"
        assert r["ruleset_version"] == RULESET_VERSION
    json.dumps(out)


def test_crashing_detector_is_not_assessed_with_exception_name():
    class Boom:
        DETECTOR_ID, PILLAR = "boom", "Behavior"
        @staticmethod
        def detect(ctx):
            raise KeyError("x")
    r = run_detectors(DetectorContext.build(), registry=[Boom])[0]
    assert r["status"] == "not_assessed" and r["not_assessed_reason"] == "crashed (KeyError)"


def test_slow_detector_times_out():
    class Slow:
        DETECTOR_ID, PILLAR = "slow", "Behavior"
        @staticmethod
        def detect(ctx):
            time.sleep(2)
    t0 = time.time()
    r = run_detectors(DetectorContext.build(), budget_s=0.2, registry=[Slow])[0]
    assert r["status"] == "not_assessed" and r["not_assessed_reason"] == "timeout" and time.time() - t0 < 1.5


def _fixture_scan(only=None):
    files = {}
    for lab in load_labels():
        if only and lab["expected"] != only:
            continue
        with open(os.path.join(FIXTURE_DIR, lab["file"]), encoding="utf-8") as fh:
            files[f"{lab['file']}/{virtual_path(lab['file'])}" if virtual_path(lab["file"]) == "setup.py" else virtual_path(lab["file"])] = fh.read()
    # setup.py must sit at the root to be checked; keep one setup fixture there
    setup = {k: v for k, v in files.items() if k.endswith("setup.py")}
    text = {k: v for k, v in files.items() if not k.endswith("setup.py")}
    if setup:
        text["setup.py"] = next(v for k, v in setup.items() if "mal_" in k or only == "benign")
    data = {"text": text, "py": {}, "binaries": [], "all_py_paths": set()}
    proof = run_malware_proof_engine(data, "o", "r", lambda f, ln: None)
    return {"ran": True, "malware_proof": proof, "findings": [], "known_malicious_count": proof["known_malicious_count"],
            "high_risk_pattern_count": proof["high_risk_pattern_count"]}, proof


def test_adapters_reproduce_the_existing_engine_on_fixtures():
    scan, proof = _fixture_scan()
    out = run_detectors(DetectorContext.build(scan=scan))
    hr = {(f["file"], f["line"]) for r in out for f in r["findings"] if f["tier"] == "high_risk"}
    strong = {(f["file"], f["line"]) for f in proof["findings"] if f.get("strong") and "VirusTotal" not in f["source"]}
    assert hr == strong and len(hr) == proof["high_risk_pattern_count"] > 0
    assert not any(f["tier"] == "known_malicious" for r in out for f in r["findings"])
    # every High/Medium engine finding is represented with a tier
    tiered = {(f["file"], f["line"], f["rule"]) for r in out for f in r["findings"]}
    expected = {(f["file"], f["line"], f["rule"]) for f in proof["findings"] if f.get("strong") or f["sev"] in ("High", "Medium")}
    assert expected <= tiered


def test_benign_fixtures_produce_no_high_risk():
    scan, _ = _fixture_scan(only="benign")
    out = run_detectors(DetectorContext.build(scan=scan))
    assert not any(f["tier"] in ("high_risk", "known_malicious") for r in out for f in r["findings"])


def test_scan_not_run_marks_content_detectors_not_assessed_with_reason():
    out = run_detectors(DetectorContext.build(scan={"ran": False, "skip_reason": "too large"}))
    content = [r for r in out if r["detector"] in ("decoded_payload", "behavior_patterns", "repo_secrets")]
    assert all(r["status"] == "not_assessed" and "too large" in r["not_assessed_reason"] for r in content)


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(f"o-r-abc123/{name}", data)
    buf.seek(0)
    return buf


def test_file_cap_gives_partial_coverage(monkeypatch):
    monkeypatch.setattr(repo_scan, "MAX_TEXT_FILES", 3)
    data = repo_scan.read_repo(_zip({f"f{i}.txt": "hello" for i in range(5)}))
    cov = repo_scan.scan_coverage(data)
    assert cov["partial"] and cov["text_read"] == 3 and cov["text_total"] == 5
    assert cov["detail"] == "partial scan: 3 of 5 text files"
    scan = {"ran": True, "malware_proof": {"findings": [], "layers": {"layer1": {"status": "ran"}, "behavior": {"status": "ran"}}},
            "scan_coverage": cov, "findings": []}
    r = next(x for x in run_detectors(DetectorContext.build(scan=scan)) if x["detector"] == "decoded_payload")
    assert r["status"] == "ran" and r["coverage"] == "partial" and r["coverage_detail"] == "partial scan: 3 of 5 text files"


@pytest.mark.parametrize("vt_key, n_bin, status", [("", 2, "not_assessed"), ("k", 0, "not_applicable"), ("", 0, "not_applicable")])
def test_virustotal_status(vt_key, n_bin, status):
    data = {"text": {}, "py": {}, "all_py_paths": set(), "binaries": [{"path": f"b{i}", "sha256": "00" * 32, "size": 2048} for i in range(n_bin)]}
    proof = run_malware_proof_engine(data, "o", "r", lambda f, ln: None, vt_api_key=vt_key)
    r = next(x for x in run_detectors(DetectorContext.build(scan={"ran": True, "malware_proof": proof, "findings": []}))
             if x["detector"] == "virustotal")
    assert r["status"] == status
