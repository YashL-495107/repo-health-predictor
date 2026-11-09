"""METHOD.md / LIMITS.md / README.md quote only numbers that benchmark/RESULTS.md (or its result files) shows."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = (ROOT / "benchmark" / "RESULTS.md").read_text(encoding="utf-8")


def test_headline_numbers_are_in_results_md():
    for quote in ("7.1% (22/310; 95% CI 4.7%-10.5%)", "40.3% (125/310; 95% CI 35.0%-45.9%)",
                  "0.0% (0/117; 95% CI 0.0%-3.2%); rule of three: at most 2.6%", "14.5% (17/117; 95% CI 9.3%-22.0%)",
                  "22.2% (4/18; 95% CI 9.0%-45.2%)", "74.5% (231/310", "80.6% (250/310", "100.0% (22 hits, 0 FPs",
                  "88.0% (125 hits, 17 FPs", "release history not fetched (307)", "| dependency_injection | 457 | 132 |",
                  "| known_bad | 611 | 310 | 297 | 4 | 0 |", "Fragile / unmaintained 9.1% (1/11"):
        assert quote in RESULTS, quote


def test_docs_only_use_those_numbers():
    method = (ROOT / "METHOD.md").read_text(encoding="utf-8")
    limits = (ROOT / "LIMITS.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for doc in (method, limits, readme):
        assert "7.1% (22/310; 95% CI 4.7%-10.5%)" in doc
    assert "310 : 117" in method and "not at real-world prevalence" in method
    for must in ("Indicators, not proof", "never means the package is harmless", "ARTIFACT mode only",
                 "known-bad recall is not measured", "307 scored items had no release",
                 "2 of the 3 obtainable replay incidents", "7 of the 17 lenient false positives", "Python only",
                 "compromised_lib", "@scope@name", "297 known-bad items have no obtainable code",
                 "4 known-bad samples were missing", "circular", "triage aid", "Dual-use", "Threat model"):
        assert must in limits, must


def test_corrected_claims_match_the_committed_files():
    import csv
    ext = [r for r in csv.DictReader(l for l in open(ROOT / "benchmark/manifests/datadog_extracted.csv", encoding="utf-8")
                                     if not l.startswith("#"))]
    items = {r["id"]: r for r in csv.DictReader(open(ROOT / "benchmark/results/items.csv", encoding="utf-8"))}
    cl = [r["id"] for r in ext if r["kind"] == "compromised_lib"]
    assert len(cl) == 11 and all(items[i]["status"] == "scored" for i in cl)
    assert sum(items[i]["strict_hit"] == "True" for i in cl) == 0 and sum(items[i]["lenient_hit"] == "True" for i in cl) == 1
    ns = list(csv.DictReader(open(ROOT / "benchmark/results/not_scored.csv", encoding="utf-8")))
    missing = [r for r in ns if r["category"] == "known_bad" and r["status"] == "not_assessed"]
    assert len(missing) == 4 and all("deleted or quarantined?" in r["reason"] for r in missing)
    assert len(ns) == 304
