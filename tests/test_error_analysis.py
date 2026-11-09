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


def test_committed_document_is_current_in_either_state():
    """CSV absent: the committed document equals the render without npm facts. CSV present (committed after a
    --samples-dir run): it equals the render from the CSV, and no "not determinable" rows remain."""
    committed = (ROOT / "benchmark" / "ERROR_ANALYSIS.md").read_text(encoding="utf-8")
    facts = EA.load_npm_facts()
    if facts is None:
        assert committed == EA.render(EA.analyse(None))
        assert "there is no `results/npm_install_facts.csv`" in committed
    else:
        res = EA.analyse(None, facts)
        assert committed == EA.render(res)
        assert not [r for r in res["misses"] if r["bucket"] == "install-script fact not determinable here"]
        assert "npm install-script facts come from `results/npm_install_facts.csv`" in committed


def test_no_intent_claims_and_sqlmap_status():
    text = EA.render(EA.analyse(None))
    low = text.lower()
    for word in ("malicious intent", "is malware", "the author", "intended to", "designed to"):
        assert word not in low
    sq = EA.sqlmap_status()
    assert not sq["in_scary"] and sq["in_dev"] and sq["items"] == []
    assert "sqlmap is **not** in the benchmark scary set" in text



def test_samples_run_writes_facts_csv_and_renders_identically_from_it(tmp_path, monkeypatch):
    """--samples-dir: facts are read from the samples, written to the CSV (no contents, no paths), and the document is
    rendered from the CSV, so a later run without samples gives the same bytes."""
    misses = EA.rows(EA.RESULTS / "misses.csv")
    ext = {r["id"]: r for r in EA.rows(EA.MAN / "datadog_extracted.csv")}
    npm = [m for m in sorted(misses, key=lambda r: r["id"]) if m["ecosystem"] == "npm" and m["id"] in ext]
    samples = tmp_path / "samples"
    for i, m in enumerate(npm):                    # synthetic package.json for every npm miss (inert JSON)
        d = samples / ext[m["id"]]["sample_dir"]
        d.mkdir(parents=True, exist_ok=True)
        scripts = {"preinstall": "node x.js"} if i % 3 == 0 else ({"postinstall": "y", "install": "z"} if i % 3 == 1 else {"test": "t"})
        (d / "package.json.sample").write_text(json.dumps({"name": m["package"], "scripts": scripts}), encoding="utf-8")
    facts_csv, out1, out2 = tmp_path / "npm_install_facts.csv", tmp_path / "a.md", tmp_path / "b.md"
    assert EA.main(["--samples-dir", str(samples), "--npm-facts", str(facts_csv), "--out", str(out1)]) == 0
    rows_ = EA.rows(facts_csv)
    assert list(rows_[0].keys()) == EA.NPM_FACT_FIELDS and len(rows_) == len(npm)
    text = facts_csv.read_text(encoding="utf-8")
    assert str(tmp_path) not in text and "node x.js" not in text and "datadog/" not in text   # no paths, no contents
    assert {r["has_install_script"] for r in rows_} == {"yes", "no"}
    assert {r["install_script_keys"] for r in rows_} >= {"preinstall", "install;postinstall", ""}
    assert EA.main(["--npm-facts", str(facts_csv), "--out", str(out2)]) == 0     # no samples: from the CSV
    assert out1.read_text(encoding="utf-8") == out2.read_text(encoding="utf-8")
    doc = out1.read_text(encoding="utf-8")
    assert "install-script fact not determinable here | 0 |" in doc
    assert "npm install-script facts come from `results/npm_install_facts.csv`" in doc
    res = EA.analyse(None, EA.load_npm_facts(facts_csv), facts_csv)
    gap = [r for r in res["misses"] if r["bucket"] == "install-time script present but no detector fired"]
    assert any(r["ecosystem"] == "npm" and "npm install hooks: preinstall" in r["facts"] for r in gap)


def test_unknown_when_the_sample_has_no_package_json(tmp_path):
    misses = EA.rows(EA.RESULTS / "misses.csv")
    ext = {r["id"]: r for r in EA.rows(EA.MAN / "datadog_extracted.csv")}
    facts = EA.collect_npm_facts(tmp_path, misses, ext)                    # empty samples folder
    assert facts and {f["has_install_script"] for f in facts} == {"unknown"}
    path = EA.write_npm_facts(facts, tmp_path / "f.csv")
    assert set(EA.load_npm_facts(path).values()) == {None}                 # unknown stays "not determinable"
