"""METHOD.md / LIMITS.md / README.md / THREAT_MODEL.md quote only numbers that benchmark/RESULTS.md (run 2, the
headline) or its result files show; RESULTS.md is the current output of compare_runs.py."""
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmark"))
RESULTS = (ROOT / "benchmark" / "RESULTS.md").read_text(encoding="utf-8")
RUN2 = ROOT / "benchmark" / "results" / "run2"


def _csv(p):
    with open(p, encoding="utf-8") as fh:
        return list(csv.DictReader(l for l in fh if not l.startswith("#")))


def test_results_md_is_current_and_run2_is_the_headline():
    import compare_runs as CR
    assert RESULTS == CR.render()
    run2 = (ROOT / "benchmark" / "RESULTS_run2.md").read_text(encoding="utf-8")
    assert RESULTS.endswith(run2[run2.index("## Items per category"):])      # everything after "Runs" is run 2
    assert "| scored known-bad | 310 | 314 |" in RESULTS
    assert "| strict recall (no OSV) | 7.1% (22/310; 95% CI 4.7%-10.5%) | 12.4% (39/314; 95% CI 9.2%-16.5%) |" in RESULTS
    assert "| lenient recall (no OSV) | 40.3% (125/310; 95% CI 35.0%-45.9%) | 50.0% (157/314; 95% CI 44.5%-55.5%) |" in RESULTS
    assert "| OSV-only (circular) | not computed for run 1 | 72.3% (227/314; 95% CI 67.1%-77.0%) |" in RESULTS
    assert "identical in every set and kind" in RESULTS and "150 of 150 known-good" in RESULTS
    assert "136 files missing in 122 items" in RESULTS and "Strict hits gained 17, lost 0" in RESULTS
    assert (ROOT / "benchmark" / "RESULTS_run1.md").is_file()


def test_headline_numbers_are_in_results_md():
    for quote in ("12.4% (39/314; 95% CI 9.2%-16.5%)", "50.0% (157/314; 95% CI 44.5%-55.5%)",
                  "0.0% (0/117; 95% CI 0.0%-3.2%); rule of three: at most 2.6%", "14.5% (17/117; 95% CI 9.3%-22.0%)",
                  "22.2% (4/18; 95% CI 9.0%-45.2%)", "77.1% (242/314", "85.0% (267/314", "100.0% (39 hits, 0 FPs",
                  "90.2% (157 hits, 17 FPs", "release history not fetched (311)", "| dependency_injection | 461 | 132 |",
                  "| known_bad | 611 | 314 | 297 | 0 | 0 |", "Fragile / unmaintained 9.1% (1/11",
                  "72.3% (227/314; 95% CI 67.1%-77.0%)", "Not scored (listed, never imputed)", "300 item(s)."):
        assert quote in RESULTS, quote


def test_docs_only_use_those_numbers():
    method = (ROOT / "METHOD.md").read_text(encoding="utf-8")
    limits = (ROOT / "LIMITS.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    threat = (ROOT / "THREAT_MODEL.md").read_text(encoding="utf-8")
    for doc in (method, limits, readme, threat):
        assert "12.4% (39/314; 95% CI 9.2%-16.5%)" in doc
        assert "7.1% (22/310; 95% CI 4.7%-10.5%)" not in doc            # the superseded run is not the headline
    assert "314 : 117" in method and "not at real-world prevalence" in method
    assert "72.3% (227/314; 95% CI 67.1%-77.0%)" in method and "72.3%, 227/314" in limits
    assert "300 items were not scored" in method and "300 items were not scored" in readme
    for must in ("Indicators, not proof", "never means the package is harmless", "ARTIFACT mode only",
                 "known-bad recall is not measured", "311 scored items had no release",
                 "2 of the 3 obtainable replay incidents", "7 of the 17 lenient false positives", "Python only",
                 "compromised_lib", "@scope@name", "297 known-bad items have no obtainable code",
                 "circular", "triage aid", "Dual-use", "Threat model", "THREAT_MODEL.md",
                 # the Defender incident and its fix stay documented
                 "136 files missing in 122 items", "Run-1 known-bad recall was therefore biased downward",
                 "--restore-missing", "Both runs are reported", "not an antivirus artifact", "38 npm items",
                 "38 PyPI items"):
        assert must in limits, must
    for must in ("Indicators, not proof", "never means the package is harmless", "Repository-mode recall is not measured",
                 "History detectors are unproven", "OSV numbers are circular", "311 scored items had no release history",
                 "7 of the 17"):
        assert must in threat, must


def test_corrected_claims_match_the_committed_files():
    ext = _csv(ROOT / "benchmark/manifests/datadog_extracted.csv")
    items = {r["id"]: r for r in _csv(RUN2 / "items.csv")}
    cl = [r["id"] for r in ext if r["kind"] == "compromised_lib"]
    assert len(cl) == 11 and all(items[i]["status"] == "scored" for i in cl)
    assert sum(items[i]["strict_hit"] == "True" for i in cl) == 0 and sum(items[i]["lenient_hit"] == "True" for i in cl) == 1
    ns = _csv(RUN2 / "not_scored.csv")
    assert len(ns) == 300 and sum(r["category"] == "known_bad" for r in ns) == 297
    # run 1: the 4 samples missing at scan time are exactly the items that lost every file to the antivirus
    ns1 = _csv(ROOT / "benchmark/results/not_scored.csv")
    missing1 = {r["id"] for r in ns1 if r["category"] == "known_bad" and r["status"] == "not_assessed"}
    assert len(missing1) == 4 and len(ns1) == 304
    removed = _csv(ROOT / "benchmark/results/samples_missing.csv")
    assert len(removed) == 136 and len({r["id"] for r in removed}) == 122 and missing1 <= {r["id"] for r in removed}
    assert _csv(ROOT / "benchmark/results/samples_missing_after_restore.csv") == []
    assert _csv(ROOT / "benchmark/results/samples_missing_after_run2.csv") == []
    base = {r["row"]: r for r in _csv(RUN2 / "baseline.csv")}
    assert (base["OSV-only (MAL- lookup alone)"]["count"], base["OSV-only (MAL- lookup alone)"]["n"]) == ("227", "314")
    assert base["history-detector lenient FPs"]["count"] == "7"
