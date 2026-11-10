"""benchmark/guarddog_baseline.py: inputs written under original names, then deleted; only rule names / numbers in the
output; nothing outside its two work subfolders is touched. GuardDog itself is not in CI: the integration test runs
only when GUARDDOG_PYTHON points to a python with guarddog installed."""
import csv
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "benchmark")]

import guarddog_baseline as G  # noqa: E402

REPORT = {"package": "pkg", "issues": 3, "errors": {"threat-x": "C:/secret/path/failed"},
          "results": {"capability-process-hooks": [{"location": "package.json:1", "code": "postinstall"}],
                      "threat-network-exfil-messenger": [{"location": "i.js:1", "code": "discord webhook"}],
                      "capability-filesystem-read": {}},
          "risk_score": {"score": 8.6, "label": "high_risk", "findings_count": 2},
          "risks": [{"severity": "high", "file_path": "i.js"}, {"severity": "medium", "file_path": "package.json"}]}


def _setup(tmp_path):
    sd = tmp_path / "samples" / "datadog" / "npm" / "evil_1_abcd"
    sd.mkdir(parents=True)
    (sd / "package.json.sample").write_text(json.dumps({"name": "evil", "scripts": {"postinstall": "node i.js"}}))
    (sd / "lib").mkdir()
    (sd / "lib" / "i.js.sample").write_text("require('https')\n")
    item = {"id": "DD-npm-evil-1-abcd", "set": "known_bad", "label": "1", "ecosystem": "npm"}
    catalog = {item["id"]: {"id": item["id"], "source": "datadog", "ecosystem": "npm", "package": "evil",
                            "version": "1", "sample_dir": "datadog/npm/evil_1_abcd"}}
    return item, catalog, tmp_path / "samples"


def test_scan_item_writes_original_names_and_cleans_up(tmp_path):
    item, catalog, samples = _setup(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    (work / "keep.txt").write_text("not ours")
    seen = {}

    def fake(python, eco, folder, tmp, timeout):
        seen["eco"] = eco
        seen["files"] = sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file())
        seen["tmp_inside_work"] = work in tmp.parents
        return REPORT
    row = G.scan_item(item, catalog, samples, work, "py", "3.2.0", runner=fake)
    assert seen == {"eco": "npm", "files": ["package/lib/i.js", "package/package.json"], "tmp_inside_work": True}
    assert (row["status"], row["risk_label"], row["risk_score"], row["max_severity"]) == ("scanned", "high_risk", 8.6, 3)
    assert row["rules_fired"] == "capability-process-hooks;threat-network-exfil-messenger"
    assert (row["n_threat_rules"], row["n_capability_rules"], row["error_rules"]) == (1, 1, "threat-x")
    assert sorted(p.name for p in work.iterdir()) == ["keep.txt"]                     # only our subfolders removed
    text = json.dumps(row)
    assert "secret" not in text and "discord" not in text and "i.js" not in text   # no contents, no paths


def test_failures_are_recorded_not_raised(tmp_path):
    item, catalog, samples = _setup(tmp_path)
    work = tmp_path / "w"

    def boom(*a, **k):
        raise RuntimeError("C:/private/path")
    row = G.scan_item(item, catalog, samples, work, "py", "3.2.0", runner=boom)
    assert row["status"] == "error (RuntimeError)" and "private" not in json.dumps(row)
    assert G.scan_item({**item, "id": "unknown"}, catalog, samples, work, "py", "3.2.0")["status"] == "item not in the manifests"


def test_safe_rel_rejects_escapes():
    assert G.safe_rel("pkg/a.py") == "pkg/a.py" and G.safe_rel("a\\b.js") == "a/b.js"
    for bad in ("../x", "/etc/x", "C:/x", "a/../../x", ""):
        assert G.safe_rel(bad) is None, bad


def test_items_are_the_461_feature_rows():
    items = G.read_items()
    assert len(items) == 461 and {i["set"] for i in items} == {"known_bad", "known_good", "scary", "dormant"}


@pytest.mark.skipif(not os.environ.get("GUARDDOG_PYTHON"), reason="GuardDog is not installed in CI (external baseline)")
def test_real_guarddog_on_a_fixture(tmp_path):
    item, catalog, samples = _setup(tmp_path)
    row = G.scan_item(item, catalog, samples, tmp_path / "work", os.environ["GUARDDOG_PYTHON"],
                      G.guarddog_version(os.environ["GUARDDOG_PYTHON"]))
    assert row["status"] == "scanned" and "capability-process-hooks" in row["rules_fired"]   # npm hook seen (package/)
    assert row["risk_label"] in ("no_risks_detected", "low", "suspicious", "high_risk")
