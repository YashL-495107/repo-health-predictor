"""Artifact path on REAL recorded registry data (3 npm + 2 PyPI packages, none of them a benchmark item), replayed
offline from tests/fixtures/benchmark_http. Re-record with tests/fixtures/record_benchmark_fixtures.py."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE.parent / "benchmark"), str(HERE / "fixtures")]

import record_benchmark_fixtures as REC  # noqa: E402


@pytest.fixture
def replay_env(monkeypatch):
    for k in ("REPOHEALTH_CACHE", "REPOHEALTH_SNAPSHOT", "REPOHEALTH_OFFLINE"):
        monkeypatch.setenv(k, "placeholder")   # recorded so they are restored after the test
    monkeypatch.setenv("REPOHEALTH_CACHE", str(REC.CACHE))
    monkeypatch.setenv("REPOHEALTH_SNAPSHOT", REC.SNAPSHOT)
    monkeypatch.setenv("REPOHEALTH_OFFLINE", "1")


def test_recorded_packages_replay_exactly(replay_env):
    expected = json.loads(REC.EXPECTED.read_text(encoding="utf-8"))
    got = json.loads(json.dumps(REC.scan_all(offline=True)))
    assert got == expected


def test_npm_specifics_install_script_dist_and_binaries(replay_env):
    import releases
    import run_benchmark as RB
    hist = releases.fetch_npm("bufferutil", releases.DEFAULT_N, None, "4.2.0")
    assert hist["status"] == "ok" and hist["releases"][0]["install_scripts"] == {"install": "node-gyp-build"}
    data = RB.data_from_contents(hist["releases"][0]["contents"])
    assert any(b["path"].endswith(".node") for b in data["binaries"])      # prebuilt native binaries seen, not run
    mitt = releases.fetch_npm("mitt", releases.DEFAULT_N, None, "3.0.1")["releases"][0]
    d = RB.data_from_contents(mitt["contents"])
    assert any(p.startswith("dist/") for p in d["text"])                    # dist/ is scanned in artifact mode
    isn = releases.fetch_npm("is-number", releases.DEFAULT_N, None, "7.0.0")["releases"][0]
    assert "index.js" in RB.data_from_contents(isn["contents"])["text"]


def test_recorded_results_are_plausible():
    exp = json.loads(REC.EXPECTED.read_text(encoding="utf-8"))
    assert all(v["status"] == "scored" for v in exp.values())
    for v in exp.values():
        assert v["detectors"]["tagless_release"][0] == "not_assessed"       # artifact mode: no repository
        assert v["detectors"]["release_vs_git"][0] == "not_assessed"
    # PyPI sdists and the npm tarballs were read
    assert exp["PyPI:six@1.17.0"]["artifact"]["members"] > 0 and exp["npm:mitt@3.0.1"]["artifact"]["members"] > 0
