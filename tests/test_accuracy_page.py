"""'How accurate is it?' page, compact verdict summary and README headline: every number equals the committed run-2
CSVs / RESULTS.md / ERROR_ANALYSIS.md; page order; the Trust check page shows the compact summary."""
import csv
import re
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import accuracy as A  # noqa: E402
from pillars import LABEL_HIGH_RISK, LABEL_NO_FINDINGS, LABEL_REVIEW  # noqa: E402

RUN2 = ROOT / "benchmark" / "results" / "run2"
RESULTS = (ROOT / "benchmark" / "RESULTS.md").read_text(encoding="utf-8")


def rows(name):
    with open(RUN2 / name, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def fmt(rate, k, n, lo, hi, r3=""):
    s = f"{100 * float(rate):.1f}% ({k}/{n}; 95% CI {100 * float(lo):.1f}%-{100 * float(hi):.1f}%)"
    return s + (f"; rule of three: at most {100 * float(r3):.1f}%" if r3 else "")


D = A.load()


def test_layered_table_equals_csvs_and_results_md():
    rec = {(r["operating_point"], r["run"]): r for r in rows("recall.csv")}
    base = {r["row"]: r for r in rows("baseline.csv")}
    lay = {r["Layer"]: r for r in D["layered"]}
    assert list(lay) == ["Known-malware database (OSV MAL- lookup) alone", "Behavior detectors only (never-seen malware)",
                         "Full system as the app runs (detectors + OSV)"]
    osv = base["OSV-only (MAL- lookup alone)"]
    assert lay["Known-malware database (OSV MAL- lookup) alone"]["Strict"] == \
        f"{100 * int(osv['count']) / int(osv['n']):.1f}% ({osv['count']}/{osv['n']})" == "72.3% (227/314)"
    for run, layer in (("headline", "Behavior detectors only (never-seen malware)"),
                       ("with_osv", "Full system as the app runs (detectors + OSV)")):
        for op, col in (("strict", "Strict"), ("lenient", "Lenient")):
            r = rec[(op, run)]
            assert lay[layer][col] == fmt(r["recall"], r["hits"], r["n"], r["ci_low"], r["ci_high"])
            assert lay[layer][col] in RESULTS
    assert "circular" in lay["Known-malware database (OSV MAL- lookup) alone"]["Meaning"]
    assert "fair measure" in lay["Behavior detectors only (never-seen malware)"]["Meaning"]
    assert "72.3% (227/314" in RESULTS


def test_false_positive_tables_equal_csvs():
    fp = {(r["set"], r["kind"]): r for r in rows("false_positives_rates.csv")}
    repo = {(r["set"], r["kind"]): r for r in rows("repo_mode_false_positives.csv")}
    for (s, _label), row in zip(A.SETS, D["fps"]):
        for kind, col in (("hard", "Strict / hard"), ("lenient", "Lenient")):
            r = fp[(s, kind)]
            assert row[col] == fmt(r["rate"], r["fp"], r["n"], r["ci_low"], r["ci_high"], r["rule_of_three"]) and row[col] in RESULTS
    for (s, _label), row in zip(A.SETS, D["repo_fps"]):
        for kind, col in (("hard", "Hard"), ("soft", "Soft")):
            r = repo[(s, kind)]
            assert row[col] == fmt(r["rate"], r["fp"], r["n"], r["ci_low"], r["ci_high"], r["rule_of_three"]) and row[col] in RESULTS
    assert D["fps"][0]["Strict / hard"].startswith("0.0% (0/117;") and "at most 2.6%" in D["fps"][0]["Strict / hard"]
    assert D["fps"][0]["Lenient"].startswith("14.5% (17/117;")


def test_precision_matches_results_md():
    p = {r["Operating point"]: r["Precision"] for r in D["precision"]}
    assert p == {"strict": "100.0% (39 hits, 0 false positives)", "lenient": "90.2% (157 hits, 17 false positives)"}
    assert "100.0% (39 hits, 0 FPs; 314 known-bad : 117 random known-good)" in RESULTS
    assert "90.2% (157 hits, 17 FPs; 314 known-bad : 117 random known-good)" in RESULTS


def test_per_detector_equals_csv():
    csv_rows = {r["detector"]: r for r in rows("per_detector.csv")}
    assert D["per_detector"]
    for r in D["per_detector"]:
        c = csv_rows[r["Detector"]]
        assert (r["Strict hits"], r["Strict FPs"], r["Lenient hits"], r["Lenient FPs"]) == \
            (int(c["strict_hits"]), int(c["strict_fp"]), int(c["lenient_hits"]), int(c["lenient_fp"]))
    listed = {r["Detector"] for r in D["per_detector"]}
    assert all(r["detector"] in listed for r in csv_rows.values()
               if any(int(r[k]) for k in ("strict_hits", "lenient_hits", "strict_fp", "lenient_fp")))


def test_why_it_misses_equals_error_analysis():
    md = (ROOT / "benchmark" / "ERROR_ANALYSIS.md").read_text(encoding="utf-8")
    for r in D["misses"]:
        assert f"| {r['Reason (bucket, run 2)']} | {r['Items']} |" in md
    misses = rows("misses.csv")
    assert sum(r["Items"] for r in D["misses"]) == len(misses) == 275
    got = {r["Reason (bucket, run 2)"]: r["Items"] for r in D["misses"]}
    assert got["review-tier only"] == 118 and got["code present, no hook, no pattern matched"] == 62
    assert got["setup.py present (normal for source packages), no hook pattern matched"] == 38


def test_measured_and_not_measured_lines():
    counts = {r["category"]: r for r in rows("counts.csv")}
    m = " ".join(D["measured"])
    assert f"{counts['known_bad']['selected']} known-bad items selected, {counts['known_bad']['scored']} scored" in m
    for k in ("seed 20261107", "data snapshot 2026-11-08", "ruleset-2026.11.08-12-frozen", "not contaminated", "Run 1 is superseded"):
        assert k in m, k
    base = {r["row"]: r for r in rows("baseline.csv")}
    nm = " ".join(D["not_measured"])
    for det in ("publisher_change", "revival_takeover", "dependency_injection", "release_delta"):
        assert f"{det} {base[det + ' ran']['count']}" in nm
    assert "Repository-mode known-bad recall" in nm and "Upgrade check" in nm and "AI section" in nm


def test_compact_verdict_numbers_equal_csvs():
    fp = {(r["set"], r["kind"]): r for r in rows("false_positives_rates.csv")}
    repo = {(r["set"], r["kind"]): r for r in rows("repo_mode_false_positives.csv")}
    rec = {(r["operating_point"], r["run"]): r for r in rows("recall.csv")}
    rv = A.compact_verdict(LABEL_REVIEW)
    assert f"({fp[('known_good', 'soft')]['fp']}/{fp[('known_good', 'soft')]['n']})" in rv and "14.5% (17/117)" in rv
    assert f"({repo[('known_good', 'soft')]['fp']}/{repo[('known_good', 'soft')]['n']})" in rv
    assert f"({rec[('lenient', 'headline')]['hits']}/314)" in rv and rv.endswith("Repository-mode known-bad recall is not measured.")
    hr = A.compact_verdict(LABEL_HIGH_RISK)
    assert "0.0% (0/117; rule of three: at most 2.6%)" in hr and "12.4% (39/314)" in hr
    nf = A.compact_verdict(LABEL_NO_FINDINGS)
    assert "157 of 314 known-bad samples (50.0%)" in nf and "no findings does not mean safe" in nf


def test_readme_headline_table():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert A.readme_layered_table(D) in readme
    assert "**Behavior detectors only (never-seen malware): headline**" in readme
    fp = {(r["set"], r["kind"]): r for r in rows("false_positives_rates.csv")}
    kg = fp[("known_good", "lenient")]
    assert f"| random known-good lenient false positives | {100 * float(kg['rate']):.1f}% ({kg['fp']}/{kg['n']}) |" in readme
    assert f"| random known-good strict / hard false positives | 0/{fp[('known_good', 'hard')]['n']} (rule of three: at most " \
           f"{100 * float(fp[('known_good', 'hard')]['rule_of_three']):.1f}%) |" in readme
    sc = fp[("scary", "lenient")]
    assert f"| scary-but-legitimate lenient false positives | {sc['fp']}/{sc['n']} |" in readme
    assert f"| dormant libraries flagged | {fp[('dormant', 'lenient')]['fp']}/{fp[('dormant', 'lenient')]['n']} |" in readme


# ------------------------------------------------------------------ app

def test_sidebar_page_order():
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    titles = re.findall(r'st\.Page\([^)]*title="([^"]+)"', src)
    assert titles == ["Trust check", "Dependency Audit", "Upgrade check", "How accurate is it?"]
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()
    at.switch_page("pages/2_How_accurate.py").run()
    assert not at.exception, at.exception
    assert at.title[0].value == "How accurate is it?"
    assert any(m.value == f"**{A.SUMMARY}**" for m in at.markdown)
    tables = [t.value for t in at.table]
    lay = next(t for t in tables if t.index.name == "Layer")
    assert list(lay["Strict"]) == [r["Strict"] for r in D["layered"]]
    assert list(lay.index) == [r["Layer"] for r in D["layered"]]
    heads = [m.value for m in at.markdown if m.value.startswith("#### ")]
    assert heads == ["#### Layered detection (known-bad samples, artifact mode)", "#### False positives",
                     "#### Precision (at the benchmark's class ratio)", "#### Per detector", "#### Why it misses",
                     "#### How it was measured", "#### What is NOT measured"] + (
        ["#### Version 2 (fresh test set)"] if A.load_v2() else [])
    if A.load_v2():
        v2t = next(t for t in tables if t.index.name == "Metric")
        assert list(v2t["v2 (2026.11.10-v2)"]) == [r["v2 (2026.11.10-v2)"] for r in A.load_v2()["recall"]]


def _md_escape(text):
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|<>~$])", r"\\\1", str(text))


def test_trust_check_shows_the_compact_summary_and_link():
    from streamlit.testing.v1 import AppTest
    import test_app as T
    from github_client import GitHubClient
    with patch("github_client.fetch_features", T.fake_fetch), patch.object(GitHubClient, "__init__", T._fake_init):
        at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()
        at.text_input(key="repo_input").set_value("o/r-accuracy")
        at.button[0].click().run()
        assert not at.exception, at.exception
        findings_tab = at.tabs[1]
        caps = [c.value for c in findings_tab.caption]
        labels = (LABEL_REVIEW, LABEL_HIGH_RISK, LABEL_NO_FINDINGS, "Fragile / unmaintained", "Not assessed")
        assert any(c in {_md_escape(A.compact_verdict(l)) for l in labels} for c in caps)
        assert not any(list(df.value.columns) == ["Mode", "Measure", "Measured"] for df in at.dataframe)
        assert "pages/2_How_accurate.py" in (ROOT / "trust_check.py").read_text(encoding="utf-8")


# ------------------------------------------------------------------ version 2 (fresh test set, branch ruleset-v2)
FRESH = ROOT / "benchmark" / "results" / "fresh"


def test_v2_rows_equal_fresh_csvs():
    import pytest
    v2 = A.load_v2()
    if v2 is None:
        pytest.skip("no fresh results on this branch")
    summ = {(r["ruleset"], r["subset"], r["metric"]): r for r in csv.DictReader(open(FRESH / "summary.csv", encoding="utf-8"))}
    head = next(csv.DictReader(open(FRESH / "headline.csv", encoding="utf-8")))["subset"]
    other = "a" if head == "b" else "b"
    want = []
    for sub in (head, other):
        for op in ("strict", "lenient"):
            want.append(tuple(fmt(r["rate"], r["k"], r["n"], r["ci_low"], r["ci_high"])
                              for r in (summ[("v1", sub, f"recall_{op}")], summ[("v2", sub, f"recall_{op}")])))
    for kind in ("hard", "soft"):
        want.append(tuple(fmt(r["rate"], r["k"], r["n"], r["ci_low"], r["ci_high"], r["rule_of_three"])
                          for r in (summ[("v1", "all", f"fp_{kind}")], summ[("v2", "all", f"fp_{kind}")])))
    got = [(r["v1 (official, 2026.11.08-12)"], r["v2 (2026.11.10-v2)"]) for r in v2["recall"]]
    assert got == want
    md = (ROOT / "benchmark" / "RESULTS_v2.md").read_text(encoding="utf-8")
    assert all(x in md for pair in got for x in pair)


def test_v2_readme_section():
    import pytest
    v2 = A.load_v2()
    if v2 is None:
        pytest.skip("no fresh results on this branch")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "### Version 2 (fresh test set)" in readme and A.readme_v2_table(v2) in readme
    assert "**v1 above stays the official result.**" in readme
    for line in v2["notes"][1:]:
        assert line in readme
    man = ROOT / "benchmark" / "manifests" / "fresh"

    def n(path, pred=lambda r: True):
        with open(path, newline="", encoding="utf-8") as fh:
            return sum(1 for r in csv.DictReader(x for x in fh if not x.startswith("#")) if pred(r))
    summ = {(r["ruleset"], r["subset"], r["metric"]): r for r in csv.DictReader(open(FRESH / "summary.csv", encoding="utf-8"))}
    assert f"{n(man / 'datadog_selection.csv')} new DataDog samples" in readme
    assert f"{summ[('v2', 'a', 'recall_strict')]['n']} scanned)" in readme
    assert f"{n(man / 'known_good.csv')} new random known-good packages ({summ[('v2', 'all', 'fp_hard')]['n']} scanned)" in readme
