"""benchmark/error_analysis.py: explicit bucket rules over measurable facts, deterministic output, read-only."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "benchmark")]

import error_analysis as EA  # noqa: E402


def facts(code=2, setup=False, pkg=False):
    return {"code_files": code, "code_bytes": 100 * code, "text_files": code + 1, "setup_py": setup, "package_json": pkg,
            "skipped": {}}


def test_inflated_versions():
    assert EA.inflated_version("99.0.2") and EA.inflated_version("912.6") and EA.inflated_version("9.9.9")
    assert not EA.inflated_version("1.0.0") and not EA.inflated_version("0.9") and not EA.inflated_version("19.0.2")


def test_miss_bucket_rules_in_order():
    b = EA.miss_bucket
    assert b("review", facts(), "PyPI", "1.0", None, False) == "review-tier only"
    assert b("none", None, "PyPI", "1.0", None, False) == "facts not available (registry artifact)"
    assert b("none", facts(setup=True), "PyPI", "99.0", None, True) == "install-time script present but no detector fired"
    assert b("none", facts(pkg=True), "npm", "1.0.0", ["preinstall"], False) == "install-time script present but no detector fired"
    assert b("none", facts(pkg=True), "npm", "1.0.0", None, False) == "install-script fact not determinable here"
    assert b("none", facts(code=0, pkg=True), "npm", "1.0.0", [], False) == "no executable content"
    assert b("none", facts(pkg=True), "npm", "99.1.0", [], False) == "inflated version, no finding"
    assert b("none", facts(), "PyPI", "1.0", None, True) == "sample partial (read limits hit), no finding"
    assert b("none", facts(), "PyPI", "1.0", None, False) == "code present, no hook, no pattern matched"


def test_member_facts_from_names_and_sizes():
    m = [{"member": "x/pkg-1.0/setup.py", "size": "120", "action": "written", "reason": "text"},
         {"member": "x/pkg-1.0/pkg/__init__.py", "size": "30", "action": "written", "reason": "text"},
         {"member": "x/pkg-1.0/README.md", "size": "9", "action": "written", "reason": "text"},
         {"member": "x/pkg-1.0.tar.gz!pkg/run.sh", "size": "50", "action": "written", "reason": "text (from nested archive)"},
         {"member": "x/big.js", "size": "2000000", "action": "skipped", "reason": "larger than 1000000 bytes"}]
    f = EA.member_facts(m)
    assert f["code_files"] == 3 and f["code_bytes"] == 200 and f["setup_py"] and not f["package_json"]
    assert f["skipped"] == {"larger than 1000000 bytes": 1}


def test_npm_hooks_read_only_from_samples(tmp_path):
    d = tmp_path / "datadog" / "npm" / "x_1.0.0_abc"
    (d / "package").mkdir(parents=True)
    (d / "package.json.sample").write_text(json.dumps({"scripts": {"postinstall": "node i.js", "test": "x"}}), encoding="utf-8")
    (d / "package" / "package.json.sample").write_text(json.dumps({"scripts": {"preinstall": "y"}}), encoding="utf-8")
    assert EA.npm_hooks(tmp_path, "datadog/npm/x_1.0.0_abc") == ["postinstall"]       # the shallowest package.json
    assert EA.npm_hooks(None, "datadog/npm/x_1.0.0_abc") is None
    assert EA.npm_hooks(tmp_path, "datadog/npm/missing") is None


def test_fp_bucket_rules():
    p = EA.parse_fp
    assert EA.fp_bucket(p("setup_py_hook [review] Install-time execution (review) @ setup.py:84")).startswith(
        "setup.py build hook on a native-build package")
    assert EA.fp_bucket(p("publisher_change [review] New publisher for release 4.0.3: GitHub Actions @ -:-; "
                          "revival_takeover [review] Release 4.0.3 revives a silent project under new hands @ -:-")) == \
        "publisher change to GitHub Actions plus revival_takeover"
    assert EA.fp_bucket(p("publisher_change [review] New publisher for release 2.8.6: someone @ -:-; "
                          "revival_takeover [review] Release 2.8.6 revives a silent project under new hands @ -:-")) == "other"
    assert EA.fp_bucket(p("committed_binary [review] Binary: compiled executable committed to the repo @ a.node:1")) == "prebuilt binary"
    assert EA.fp_bucket(p("dependency_injection [review] New dependency x in 1.0.2: young package @ -:-")) == "young dependency"
    assert EA.fp_bucket(p("behavior_patterns [review] Network: exfil-style endpoint @ src/f.ts:41")) == "other"


def test_real_results_consistent_with_results_md_and_deterministic():
    res = EA.analyse(None)
    groups = [r["group"] for r in res["misses"]]
    assert len(res["misses"]) == 288 and groups.count("review-tier only") == 103 and groups.count("no finding at any tier") == 185
    assert len(res["fps"]) == 21 and sum(r["set"] == "known_good" for r in res["fps"]) == 17
    assert sum(r["history"] for r in res["fps"] if r["set"] == "known_good") == 7
    assert all(r["human_verified"] == "no" for r in res["misses"] + res["fps"])
    assert all(r["bucket"] in EA.MISS_BUCKETS for r in res["misses"]) and all(r["bucket"] in EA.FP_BUCKETS for r in res["fps"])
    assert EA.render(res) == EA.render(EA.analyse(None))
    committed = (ROOT / "benchmark" / "ERROR_ANALYSIS.md").read_text(encoding="utf-8")
    assert committed == EA.render(res)                                  # the committed document is current


def test_no_intent_claims_and_sqlmap_status():
    text = EA.render(EA.analyse(None))
    low = text.lower()
    for word in ("malicious intent", "is malware", "the author", "intended to", "designed to"):
        assert word not in low
    sq = EA.sqlmap_status()
    assert not sq["in_scary"] and sq["in_dev"] and sq["items"] == []
    assert "sqlmap is **not** in the benchmark scary set" in text
