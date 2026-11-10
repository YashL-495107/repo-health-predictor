"""Learned combiner (research only): committed ml_*.csv reproduce from features.csv; pages, README and ML_COMBINER.md
show exactly those numbers; leakage rule; shuffled-label and ceiling checks present; the app and its scoring do not
use the model (no scikit-learn in the app, Trust check / Upgrade check do not import it)."""
import csv
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "benchmark")]

import ml_results as M  # noqa: E402

RUN2 = ROOT / "benchmark" / "results" / "run2"
D = M.load()


def rows(name):
    with open(RUN2 / name, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_headline_is_a_strict_logistic_regression_and_reads_the_csv():
    s = rows("ml_summary.csv")
    head = [r for r in s if r["headline"] == "yes"]
    assert len(head) == 1 and (head[0]["feature_set"], head[0]["model"]) == ("A_strict", "logistic_regression")
    assert {(r["feature_set"], r["model"]) for r in s} == {(f, m) for f in ("A_strict", "A", "B", "C")
                                                         for m in ("logistic_regression", "random_forest")}
    assert all(r["trusted"] == ("no: dataset bias" if r["feature_set"] == "C" else "yes") for r in s)
    h = M.headline(D)
    assert h["auc"] == f"{float(head[0]['auc']):.3f} (95% CI {float(head[0]['auc_ci_low']):.3f}-{float(head[0]['auc_ci_high']):.3f})"
    r5 = next(r for r in rows("ml_recall_at_fp.csv") if (r["feature_set"], r["model"], r["target_fp"]) ==
              ("A_strict", "logistic_regression", "0.050000"))
    assert h["recall_5"].startswith(f"{100 * float(r5['recall']):.1f}% (95% CI {100 * float(r5['recall_ci_low']):.1f}%-")
    assert "12.4% (39/314) at 0/117" in h["line"] and "50.0% (157/314) at 17/117" in h["line"]
    lo = float(head[0]["auc_ci_low"])
    assert lo > 0.5, "stop condition: the headline AUC interval includes 0.5"


def test_results_table_matches_csv_for_every_row():
    table = M.results_table(D)
    for s, row in zip(rows("ml_summary.csv"), table):
        assert row["ROC AUC"] == M.auc_text(s) and row["Model"] == M.MODEL_LABEL[s["model"]]
        for t in (0.0, 0.05, 0.10, 0.15):
            r = M.recall_for(D, s["feature_set"], s["model"], t)
            assert row[f"Recall @ {int(t * 100)}% FP"] == f"{100 * float(r['recall']):.1f}% (FP {100 * float(r['realized_fp']):.1f}%)"
    assert table[-2]["Recall @ 0% FP"] == "12.4% (FP 0.0%)" and table[-1]["Recall @ 15% FP"] == "50.0% (FP 14.5%)"


def test_shuffled_label_and_ceiling_checks_present():
    san = rows("ml_sanity.csv")
    sh = [r for r in san if r["check"] == "shuffled labels: ROC AUC"]
    assert {r["feature_set"] for r in sh} == {"A_strict", "A"}
    for r in sh:
        assert abs(float(r["value"]) - 0.5) < 0.1 and float(r["ci_low"]) < 0.5 < float(r["ci_high"]), r
    ceil = {r["feature_set"]: r for r in san if r["check"].startswith("ceiling")}
    assert set(ceil) == {"A_strict", "A", "B", "C"} and int(ceil["A_strict"]["n"]) == 314
    assert any("Shuffled labels, feature set A_strict" in x for x in M.sanity_lines(D))


def test_leakage_rule():
    leak = rows("ml_leakage.csv")
    ind = {r["feature"] for r in leak if r["source_indicator"] == "yes"}
    for det in ("publisher_change", "revival_takeover", "release_delta", "dependency_injection"):
        assert any(f.startswith(f"det_{det}_") for f in ind), det
    for r in leak:
        reg = sum(int(r[f"nonzero_{g}"]) for g in ("registry_known_bad", "registry_known_good", "registry_scary_dormant"))
        if reg and not int(r["nonzero_datadog_known_bad"]):
            assert r["source_indicator"] == "yes", r["feature"]
    feats = rows("ml_features.csv")
    strict = {r["feature"] for r in feats if r["feature_set"] == "A_strict"}
    a = {r["feature"] for r in feats if r["feature_set"] == "A"}
    assert strict == a - ind and strict
    c = {r["feature"] for r in feats if r["feature_set"] == "C"}
    assert {"file_count", "total_bytes"} <= c and any(f.startswith("artifact_kind=") for f in c)


def test_committed_results_reproduce(tmp_path):
    """Re-run the headline (A_strict, logistic regression) from features.csv: same AUC and recall as committed."""
    pytest.importorskip("sklearn")
    import ml_combiner as MC
    MC.run(out_dir=tmp_path, models=("logistic_regression",), sets=("A_strict",), n_boot=200)
    new = next(r for r in csv.DictReader(open(tmp_path / "ml_summary.csv")) if r["feature_set"] == "A_strict")
    old = next(r for r in rows("ml_summary.csv") if r["feature_set"] == "A_strict" and r["model"] == "logistic_regression")
    assert new["auc"] == old["auc"] and new["auc_repeat_min"] == old["auc_repeat_min"]
    newr = {r["target_fp"]: r["recall"] for r in csv.DictReader(open(tmp_path / "ml_recall_at_fp.csv"))}
    oldr = {r["target_fp"]: r["recall"] for r in rows("ml_recall_at_fp.csv")
            if r["feature_set"] == "A_strict" and r["model"] == "logistic_regression"}
    assert newr == oldr


def test_threshold_never_exceeds_the_target_on_its_own_negatives():
    pytest.importorskip("sklearn")
    import numpy as np
    import ml_combiner as MC
    neg = np.array([0.1, 0.2, 0.2, 0.3, 0.9, 0.95, 0.5, 0.4, 0.6, 0.7])
    for t in MC.TARGET_FPS:
        thr = MC.threshold(neg, t)
        assert (neg >= thr).sum() <= int(t * len(neg) + 1e-9)


def test_docs_read_the_csvs():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert M.readme_block(D) in readme
    assert "**Behavior detectors only (never-seen malware): headline**" in readme      # v1 stays the headline
    assert (ROOT / "benchmark" / "ML_COMBINER.md").read_text(encoding="utf-8") == M.markdown(D)
    assert M.CAVEAT in readme and "not trusted" in M.markdown(D)


def test_app_does_not_use_the_model():
    req = (ROOT / "requirements.txt").read_text()
    assert "scikit-learn" not in req and "sklearn" not in req
    assert "scikit-learn==" in (ROOT / "requirements-dev.txt").read_text()
    for p in [ROOT / "app.py", ROOT / "trust_check.py", ROOT / "upgrade_check.py", ROOT / "ml_results.py",
              ROOT / "accuracy.py", *(ROOT / "app_pages").glob("*.py")]:
        t = p.read_text(encoding="utf-8")
        assert not re.search(r"^\s*(?:import|from)\s+(?:sklearn|ml_combiner)\b", t, re.M), p.name
    for p in (ROOT / "trust_check.py", ROOT / "upgrade_check.py", ROOT / "pillars.py", ROOT / "security.py"):
        assert "ml_results" not in p.read_text(encoding="utf-8"), p.name


def test_pages_render_and_show_the_csv_numbers():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()
    at.switch_page("app_pages/3_Learned_combiner.py").run()
    assert not at.exception, at.exception
    assert at.title[0].value == "Learned combiner (experimental)"
    assert any(w.value == M.CAVEAT for w in at.warning)
    text = " ".join(m.value for m in at.markdown)
    h = M.headline(D)
    cmp = next(t.value for t in at.table if "Recall @ 0% FP (95% CI)" in t.value.columns)
    assert list(cmp["Model"]) == [c["Model"] for c in M.comparison_table(D)]
    assert list(cmp["ROC AUC (95% CI)"]) == [c["ROC AUC (95% CI)"] for c in M.comparison_table(D)]
    assert M.COMPARE_NOTE in [c.value for c in at.caption]
    res = next(t.value for t in at.table if "Trusted" in t.value.columns)
    assert list(res["ROC AUC"])[:8] == [M.auc_text(s) for s in rows("ml_summary.csv")]
    assert "not trusted (dataset bias)" in text
    at.switch_page("app_pages/2_How_accurate.py").run()
    assert not at.exception, at.exception
    acc = next(t.value for t in at.table if "Recall @ 0% FP (95% CI)" in t.value.columns)
    assert list(acc["Recall @ 5% FP (95% CI)"]) == [c["Recall @ 5% FP (95% CI)"] for c in M.comparison_table(D)]
    assert any(c.value.startswith(M.COMPARE_NOTE) and "Frozen rules: strict: 12.4% (39/314)" in c.value for c in at.caption)
    assert any("Learned combiner (experimental): a post-freeze research model" in m.value for m in at.markdown)


def test_side_by_side_comparison_reads_the_csvs():
    cmp = M.comparison_table(D)
    assert [(c["Feature set"].split(":")[0], c["Model"]) for c in cmp] == [
        ("A-strict (headline)", "logistic regression (explainable weights)"),
        ("A-strict (headline)", "random forest (best performer)"),
        ("B", "logistic regression"), ("B", "random forest")]
    assert cmp[2]["Feature set"] == "B: adds install-hook and inflated-version metadata; more source-bias risk"
    summ = {(r["feature_set"], r["model"]): r for r in rows("ml_summary.csv")}
    rec = {(r["feature_set"], r["model"], r["target_fp"]): r for r in rows("ml_recall_at_fp.csv")}

    def pc(x):
        return f"{100 * float(x):.1f}%"
    for c, (fs, model) in zip(cmp, [("A_strict", "logistic_regression"), ("A_strict", "random_forest"),
                                    ("B", "logistic_regression"), ("B", "random_forest")]):
        s = summ[(fs, model)]
        assert c["ROC AUC (95% CI)"] == f"{float(s['auc']):.3f} ({float(s['auc_ci_low']):.3f}-{float(s['auc_ci_high']):.3f})"
        for t, col in (("0.000000", "Recall @ 0% FP (95% CI)"), ("0.050000", "Recall @ 5% FP (95% CI)"),
                       ("0.150000", "Recall @ 15% FP (95% CI)")):
            r = rec[(fs, model, t)]
            assert c[col] == (f"{pc(r['recall'])} ({pc(r['recall_ci_low'])}-{pc(r['recall_ci_high'])}); "
                              f"realized FP {pc(r['realized_fp'])}")
    assert not any(c["Feature set"].startswith("C") for c in cmp) and "not trusted (dataset bias)" in M.COMPARE_NOTE
    assert any(r["Trusted"] == "no: dataset bias" and r["Feature set"].startswith("C:") for r in M.results_table(D))
    md = M.markdown(D)
    assert "## Side by side: logistic regression and random forest (feature sets A-strict and B)" in md
    assert all("| " + " | ".join(c.values()) + " |" in md for c in cmp)
    assert md.index("## Side by side") < md.index("## Method")
