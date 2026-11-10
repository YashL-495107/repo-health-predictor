"""Display strings for the learned-combiner research result, READ from benchmark/results/run2/ml_*.csv (written by
benchmark/ml_combiner.py) and, for the frozen rules' operating points, recall.csv / false_positives_rates.csv.
Used by the "Learned combiner (experimental)" page, the "How accurate is it?" page, README.md and
benchmark/ML_COMBINER.md. No scikit-learn needed here. Research only: never used for the Trust score or any verdict.
"""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUN2 = ROOT / "benchmark" / "results" / "run2"
CAVEAT = ("Not used for the Trust score; post-freeze; cross-validated on the same data the rules were frozen against, "
          "not a fresh held-out test.")
TITLE = "Learned combiner (experimental)"
SET_LABEL = {"A_strict": "A-strict: detector/capability features without source indicators (headline)",
             "A": "A: detector/capability features",
             "B": "B: A + install hook + inflated version",
             "C": "C: B + size, file count, artifact kind, ecosystem (not trusted: dataset bias)"}
MODEL_LABEL = {"logistic_regression": "logistic regression", "random_forest": "random forest"}


def _rows(name: str, run_dir: Path = RUN2) -> list[dict]:
    with open(run_dir / name, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def p(x) -> str:
    return f"{100 * float(x):.1f}%"


def available(run_dir: Path = RUN2) -> bool:
    return (run_dir / "ml_summary.csv").is_file()


def load(run_dir: Path = RUN2) -> dict:
    summary = _rows("ml_summary.csv", run_dir)
    recall = _rows("ml_recall_at_fp.csv", run_dir)
    head = next(s for s in summary if s["headline"] == "yes")
    rules_rec = {(r["operating_point"], r["run"]): r for r in _rows("recall.csv", run_dir)}
    rules_fp = {(r["set"], r["kind"]): r for r in _rows("false_positives_rates.csv", run_dir)}
    return {"summary": summary, "recall": recall, "head": head,
            "extra": _rows("ml_extra_sets.csv", run_dir), "roc": _rows("ml_roc.csv", run_dir),
            "ecosystem": _rows("ml_ecosystem.csv", run_dir), "coef": _rows("ml_coefficients.csv", run_dir),
            "sanity": _rows("ml_sanity.csv", run_dir), "leakage": _rows("ml_leakage.csv", run_dir),
            "rules": {"strict": (rules_rec[("strict", "headline")], rules_fp[("known_good", "strict")]),
                      "lenient": (rules_rec[("lenient", "headline")], rules_fp[("known_good", "lenient")])}}


def auc_text(s: dict) -> str:
    return f"{float(s['auc']):.3f} (95% CI {float(s['auc_ci_low']):.3f}-{float(s['auc_ci_high']):.3f})"


def recall_text(r: dict) -> str:
    return (f"{p(r['recall'])} (95% CI {p(r['recall_ci_low'])}-{p(r['recall_ci_high'])}) at a realized "
            f"{p(r['realized_fp'])} false-positive rate")


def rules_text(d: dict) -> list[str]:
    out = []
    for op in ("strict", "lenient"):
        rec, fp = d["rules"][op]
        out.append(f"{op}: {p(rec['recall'])} ({rec['hits']}/{rec['n']}) at {fp['fp']}/{fp['n']} false positives "
                   f"({p(fp['rate'])})")
    return out


def recall_for(d: dict, feature_set: str, model: str, target: float) -> dict:
    return next(r for r in d["recall"] if r["feature_set"] == feature_set and r["model"] == model
                and abs(float(r["target_fp"]) - target) < 1e-9)


def headline(d: dict) -> dict:
    h = d["head"]
    r5 = recall_for(d, h["feature_set"], h["model"], 0.05)
    r15 = recall_for(d, h["feature_set"], h["model"], 0.15)
    r0 = recall_for(d, h["feature_set"], h["model"], 0.0)
    return {"set": h["feature_set"], "model": h["model"], "auc": auc_text(h), "recall_5": recall_text(r5),
            "recall_15": recall_text(r15), "recall_0": recall_text(r0), "rules": rules_text(d),
            "line": (f"{MODEL_LABEL[h['model']].capitalize()}, feature set {h['feature_set']}: "
                     f"ROC AUC {auc_text(h)}; recall {recall_text(r5)} (target 5%). Frozen rules: "
                     + "; ".join(rules_text(d)) + ".")}


COMPARE_MODEL_LABEL = {("A_strict", "logistic_regression"): "logistic regression (explainable weights)",
                       ("A_strict", "random_forest"): "random forest (best performer)",
                       ("B", "logistic_regression"): "logistic regression",
                       ("B", "random_forest"): "random forest"}
COMPARE_SET_LABEL = {"A_strict": "A-strict (headline): detector/capability features without source indicators",
                     "B": "B: adds install-hook and inflated-version metadata; more source-bias risk"}
COMPARE_NOTE = ("\"Best performer\" refers to ROC AUC; compare the recall columns at each false-positive target. "
                "Feature set C is not shown here: not trusted (dataset bias).")


def _cell(r: dict) -> str:
    return (f"{p(r['recall'])} ({p(r['recall_ci_low'])}-{p(r['recall_ci_high'])}); "
            f"realized FP {p(r['realized_fp'])}")


def comparison_table(d: dict) -> list[dict]:
    """Logistic regression and random forest side by side for feature sets A-strict and B: ROC AUC and recall at
    0 / 5 / 15 % target false positives with 95% CIs and the realized rate, read from ml_summary / ml_recall_at_fp."""
    out = []
    for fs in ("A_strict", "B"):
        for model in ("logistic_regression", "random_forest"):
            s = next(x for x in d["summary"] if x["feature_set"] == fs and x["model"] == model)
            out.append({"Feature set": COMPARE_SET_LABEL[fs], "Model": COMPARE_MODEL_LABEL[(fs, model)],
                        "ROC AUC (95% CI)": auc_text(s).replace(" (95% CI ", " ("),
                        **{f"Recall @ {int(t * 100)}% FP (95% CI)": _cell(recall_for(d, fs, model, t))
                           for t in (0.0, 0.05, 0.15)}})
    return out


def results_table(d: dict) -> list[dict]:
    rows = []
    for s in d["summary"]:
        r = {t: recall_for(d, s["feature_set"], s["model"], t) for t in (0.0, 0.05, 0.10, 0.15)}
        rows.append({"Feature set": SET_LABEL[s["feature_set"]], "Model": MODEL_LABEL[s["model"]],
                     "Trusted": s["trusted"], "ROC AUC": auc_text(s),
                     **{f"Recall @ {int(t * 100)}% FP": f"{p(v['recall'])} (FP {p(v['realized_fp'])})" for t, v in r.items()}})
    for op in ("strict", "lenient"):
        rec, fp = d["rules"][op]
        rows.append({"Feature set": f"Frozen rules, {op} (ruleset 2026.11.08-12)", "Model": "fixed rules", "Trusted": "yes",
                     "ROC AUC": "n/a (fixed points)", **{f"Recall @ {t}% FP": "" for t in (0, 5, 10, 15)},
                     "Recall @ 0% FP" if op == "strict" else "Recall @ 15% FP":
                         f"{p(rec['recall'])} (FP {p(fp['rate'])})"})
    return rows


def sanity_lines(d: dict) -> list[str]:
    out = []
    for s in d["sanity"]:
        if s["check"].startswith("shuffled"):
            out.append(f"Shuffled labels, feature set {s['feature_set']}: ROC AUC {float(s['value']):.3f} "
                       f"(95% CI {float(s['ci_low']):.3f}-{float(s['ci_high']):.3f}); should be near 0.5.")
        else:
            out.append(f"Ceiling, feature set {s['feature_set']}: {s['value']} of {s['n']} known-bad items have an "
                       f"all-zero feature vector; {s['note']}.")
    return out


def top_coefficients(d: dict, feature_set: str, k: int = 10) -> list[dict]:
    rows = [c for c in d["coef"] if c["feature_set"] == feature_set][:k]
    return [{"Feature": c["feature"], "Weight (per SD)": f"{float(c['coef_standardized']):+.3f}",
             "Odds ratio per SD": f"{float(c['odds_ratio_per_sd']):.2f}"} for c in rows]


def leakage_summary(d: dict) -> dict:
    ind = [l for l in d["leakage"] if l["source_indicator"] == "yes"]
    only_dd = [l for l in d["leakage"] if l["only_in_datadog"] == "yes"]
    return {"n_features": len(d["leakage"]), "indicators": ind, "only_datadog": only_dd,
            "detectors_excluded": sorted({l["feature"][4:].rsplit("_", 1)[0] for l in ind})}


def extra_lines(d: dict, feature_set: str, model: str) -> list[str]:
    out = []
    for t in (0.05, 0.15):
        rows = [e for e in d["extra"] if e["feature_set"] == feature_set and e["model"] == model
                and abs(float(e["target_fp"]) - t) < 1e-9]
        out.append(f"At the {int(t * 100)}% threshold: " + ", ".join(f"{e['set']} {e['flagged']}/{e['n']} flagged" for e in rows))
    return out


def readme_block(d: dict | None = None) -> str:
    d = d or load()
    h = headline(d)
    return (f"**{TITLE}** (research result, not the headline): {h['line']} {CAVEAT} "
            "Details: [benchmark/ML_COMBINER.md](benchmark/ML_COMBINER.md).\n")


def markdown(d: dict | None = None) -> str:
    """benchmark/ML_COMBINER.md, generated from the CSVs (benchmark/ml_combiner.py writes it after the run)."""
    d = d or load()
    h = headline(d)
    lk = leakage_summary(d)
    L = [f"# {TITLE}", "", f"**{CAVEAT}** Generated by `benchmark/ml_combiner.py` from `benchmark/results/run2/ml_*.csv`; "
         "no number in this file is typed by hand.", "",
         "## What it is", "",
         "A simple model that combines the frozen ruleset's own outputs for each item (finding counts per detector and "
         "tier, capability counts) into one score, to see whether a learned combination separates known-bad from random "
         "known-good packages better than the rules' fixed operating points. The rules, detectors, Trust score and "
         "verdicts are unchanged; the app never uses this model.", "",
         "## Headline (feature set " + h["set"] + ", " + MODEL_LABEL[h["model"]] + ")", "",
         f"- ROC AUC {h['auc']}.", f"- Recall {h['recall_0']} (target 0%).", f"- Recall {h['recall_5']} (target 5%).",
         f"- Recall {h['recall_15']} (target 15%).", "- Frozen rules: " + "; ".join(h["rules"]) + ".", "",
         "## Method", "",
         "- Data: benchmark run 2, `benchmark/results/run2/features.csv` (from `benchmark/extract_features.py`): "
         f"{d['head']['n_pos']} scored known-bad (positives) vs {d['head']['n_neg']} random known-good (negatives); "
         "scary and dormant items only scored, by models trained on all positives and negatives.",
         "- Models with fixed default hyperparameters (nothing tuned): logistic regression on standardized features (main, "
         "coefficients below) and a random forest (comparison).",
         f"- Stratified {d['head']['folds']}-fold cross-validation repeated {d['head']['repeats']} times with fixed seeds; "
         "every item is scored only by models that did not train on it. Thresholds for the fixed false-positive rates "
         "are chosen inside each training fold (inner cross-validation on its known-good items), never on the test "
         "fold; the realized false-positive rate is reported. 95% intervals: stratified bootstrap over items.",
         "- Feature sets: " + "; ".join(SET_LABEL.values()) + ".", "",
         "## Results", "", "| " + " | ".join(results_table(d)[0]) + " |", "|" + "---|" * len(results_table(d)[0])]
    L += ["| " + " | ".join(str(v) for v in r.values()) + " |" for r in results_table(d)]
    L += ["", "## Source leakage check", "",
          f"Nearly every scored known-bad item is a DataDog sample and every random known-good item is a registry archive, "
          f"so a feature that only one source can produce is a shortcut. Of {lk['n_features']} set-A features, "
          f"{len(lk['indicators'])} were excluded as source indicators (A-strict), from the detectors "
          f"{', '.join(lk['detectors_excluded'])}: they need release history (not applicable to DataDog samples) or are "
          f"non-zero only in registry archives. {len(lk['only_datadog'])} features are non-zero only in DataDog samples; "
          "because almost every positive is a DataDog sample, they cannot be told apart from real malware signals and "
          "were kept. Full table: `benchmark/results/run2/ml_leakage.csv`. Feature set C (size, file count, artifact "
          "kind, ecosystem) mostly encodes the source and is **not trusted**.", "",
          "## Sanity checks", ""] + ["- " + x for x in sanity_lines(d)]
    L += ["", f"## Logistic regression weights (feature set {h['set']}, standardized)", "",
          "| Feature | Weight (per SD) | Odds ratio per SD |", "|---|---|---|"]
    L += [f"| {c['Feature']} | {c['Weight (per SD)']} | {c['Odds ratio per SD']} |" for c in top_coefficients(d, h["set"], 15)]
    L += ["", "## Extra false-positive checks (models trained on all known-bad and known-good)", ""]
    L += ["- " + x for x in extra_lines(d, h["set"], h["model"])]
    L += ["", "## Per ecosystem", "", "| Feature set | Model | Ecosystem | ROC AUC | Recall @ 5% FP (realized FP) |", "|---|---|---|---|---|"]
    L += [f"| {e['feature_set']} | {MODEL_LABEL[e['model']]} | {e['ecosystem']} | {float(e['auc']):.3f} | "
          f"{p(e['recall_at_5pct_fp'])} ({p(e['realized_fp_at_5pct'])}) |" for e in d["ecosystem"]]
    L += ["", "## Caveats", "",
          "- Cross-validated on the same 431 items the rules were frozen against: not a fresh held-out test.",
          "- Class ratio 314 : 117, not real-world prevalence; precision is not reported for that reason.",
          "- Dataset bias: known-bad items are DataDog samples (inert text), known-good items registry archives; "
          "set C shows how a model exploits that. Even A-strict may keep source effects that this data cannot separate.",
          "- Post-freeze, unvalidated, never used for the Trust score or any verdict.", ""]
    cmp = comparison_table(d)
    side = ["## Side by side: logistic regression and random forest (feature sets A-strict and B)", "",
            "| " + " | ".join(cmp[0]) + " |", "|" + "---|" * len(cmp[0])]
    side += ["| " + " | ".join(r.values()) + " |" for r in cmp] + ["", COMPARE_NOTE, ""]
    return "\n".join(L).replace("\n## Method\n", "\n" + "\n".join(side) + "\n## Method\n", 1)
