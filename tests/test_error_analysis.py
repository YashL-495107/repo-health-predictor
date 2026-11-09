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
    assert b("none", facts(setup=True), "PyPI", "99.0", None, True) == EA.BUCKET_SETUP_PY
    assert EA.BUCKET_SETUP_PY == "setup.py present (normal for source packages), no hook pattern matched"
    assert b("none", facts(pkg=True), "npm", "1.0.0", ["preinstall"], False) == EA.BUCKET_NPM_HOOK
    assert EA.BUCKET_NPM_HOOK == ("install hook declared (preinstall/postinstall), no finding: detector-gap candidate, "
                                  "cause not established")
    assert b("none", facts(setup=True, pkg=True), "npm", "1.0.0", None, False) == "install-script fact not determinable here"
    assert b("none", facts(setup=True, pkg=True), "npm", "1.0.0", [], False) == "code present, no hook, no pattern matched"
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


def test_committed_document_is_run2_and_current():
    """The committed document is rendered from run 2 (--results-dir benchmark/results/run2, npm facts from that
    folder): identical to a fresh render, no "not determinable" rows (the run-2 facts CSV has no unknowns) and every
    row human-verified: no."""
    committed = (ROOT / "benchmark" / "ERROR_ANALYSIS.md").read_text(encoding="utf-8")
    old = (EA.RESULTS, EA.NPM_FACTS)
    try:
        EA.set_results_dir(EA.BENCH / "results" / "run2")
        facts = EA.load_npm_facts()
        assert facts is not None and len(facts) == 98 and not [i for i, k in facts.items() if k is None]
        res = EA.analyse(None, facts, EA.NPM_FACTS)
        assert committed == EA.render(res)
    finally:
        EA.RESULTS, EA.NPM_FACTS = old
    assert "`results/run2/items.csv`" in committed
    assert "npm install-script facts come from `results/run2/npm_install_facts.csv`" in committed
    buckets = [r["bucket"] for r in res["misses"]]
    assert buckets.count(EA.BUCKET_NPM_HOOK) == 38 and buckets.count(EA.BUCKET_SETUP_PY) == 38
    assert buckets.count("install-script fact not determinable here") == 0
    assert all(r["human_verified"] == "no" for r in res["misses"] + res["fps"])


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
    npm_none = [m for m in npm if EA.parse_why(m["why"])[0] == "none"]      # facts only for no-finding npm items
    assert list(rows_[0].keys()) == EA.NPM_FACT_FIELDS and len(rows_) == len(npm_none)
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
    gap = [r for r in res["misses"] if r["bucket"] == EA.BUCKET_NPM_HOOK]
    assert any(r["ecosystem"] == "npm" and "npm install hooks: preinstall" in r["facts"] for r in gap)


def test_unknown_when_the_sample_has_no_package_json(tmp_path):
    misses = EA.rows(EA.RESULTS / "misses.csv")
    ext = {r["id"]: r for r in EA.rows(EA.MAN / "datadog_extracted.csv")}
    facts = EA.collect_npm_facts(tmp_path, misses, ext)                    # empty samples folder
    assert facts and {f["has_install_script"] for f in facts} == {"unknown"}
    path = EA.write_npm_facts(facts, tmp_path / "f.csv")
    assert set(EA.load_npm_facts(path).values()) == {None}                 # unknown stays "not determinable"



def test_unknown_items_are_listed_with_the_reason_when_facts_are_present(tmp_path):
    misses = EA.rows(EA.RESULTS / "misses.csv")
    ext = {r["id"]: r for r in EA.rows(EA.MAN / "datadog_extracted.csv")}
    facts = EA.collect_npm_facts(tmp_path / "empty", misses, ext)          # every no-finding npm item: unknown
    for f in facts[1:]:
        f["has_install_script"], f["install_script_keys"] = "no", ""
    path = EA.write_npm_facts(facts, tmp_path / "f.csv")
    res = EA.analyse(None, EA.load_npm_facts(path), path)
    nd = [r for r in res["misses"] if r["bucket"] == "install-script fact not determinable here"]
    assert [r["item"] for r in nd] == [facts[0]["id"]] and nd[0]["facts"].count("no package.json found in the extracted sample") == 1
    doc = EA.render(res)
    assert "1 item(s): no package.json found in the extracted sample" in doc and facts[0]["id"] in doc


def test_old_bucket_name_is_gone():
    for name in ("benchmark/error_analysis.py", "benchmark/ERROR_ANALYSIS.md", "LIMITS.md", "README.md"):
        assert "install-time script present but no detector fired" not in (ROOT / name).read_text(encoding="utf-8"), name


def test_results_dir_option_reads_another_run(tmp_path):
    """--results-dir (run 2) reads items/misses/false_positives from that folder and writes its npm facts CSV there by
    default; the default folder is left as it was."""
    import shutil
    run = EA.BENCH / "results" / "_test_run_copy"
    try:
        run.mkdir()
        for n in ("items.csv", "misses.csv", "false_positives.csv"):
            shutil.copy(EA.BENCH / "results" / n, run / n)
        if (EA.BENCH / "results" / "npm_install_facts.csv").is_file():
            shutil.copy(EA.BENCH / "results" / "npm_install_facts.csv", run / "npm_install_facts.csv")
        before = (ROOT / "benchmark" / "ERROR_ANALYSIS.md").read_bytes()
        out = tmp_path / "EA.md"
        old = (EA.RESULTS, EA.NPM_FACTS)
        try:
            assert EA.main(["--results-dir", str(run), "--out", str(out)]) == 0
        finally:
            EA.RESULTS, EA.NPM_FACTS = old
        doc = out.read_text(encoding="utf-8")
        assert "`results/_test_run_copy/items.csv`" in doc and "`results/items.csv`" not in doc
        assert (ROOT / "benchmark" / "ERROR_ANALYSIS.md").read_bytes() == before
    finally:
        shutil.rmtree(run, ignore_errors=True)
