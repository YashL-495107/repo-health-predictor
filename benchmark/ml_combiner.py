"""Learned combiner (experimental research result; post-freeze; never used for the Trust score or any verdict).

  python benchmark/ml_combiner.py            # reads benchmark/results/run2/features.csv, writes results/run2/ml_*.csv

Question: does a simple model over the frozen ruleset's own outputs (per-detector finding counts by tier, capability
counts) separate known-bad from random known-good better than the rules' fixed operating points?

Data: 314 scored known-bad (positives) vs 117 random known-good (negatives) of benchmark run 2; scary (18) and dormant
(12) are only scored, as extra false-positive checks, by models trained on all 431.

Models (FIXED default hyperparameters, nothing tuned): logistic regression on standardized features (main,
explainable: coefficients reported; max_iter raised only so it converges) and a random forest (comparison).

Validation: stratified 5-fold cross-validation repeated 5 times with fixed seeds (SEEDS). Every item is scored only by
models that did not train on it. Thresholds for the fixed false-positive rates (0 / 5 / 10 / 15 %) are chosen INSIDE
each training fold, from inner 5-fold out-of-fold scores of the training fold's known-good items, never on the test
fold; the realized false-positive rate on the test folds is reported next to each recall. Per item, scores are
averaged over the 5 repeats (AUC, ROC curve) and decisions are averaged (recall, realized FP rate). 95% intervals:
stratified bootstrap over items (N_BOOT resamples, fixed seed).

Feature sets (all reported):
  A         per-detector counts (known_malicious / high_risk / review / info / all findings) + capability counts
  A_strict  A without SOURCE INDICATORS (the headline when it differs from A), see leakage()
  B         A + install hook + inflated version
  C         B + file count, total bytes, artifact kind, ecosystem: NOT TRUSTED (dataset bias: nearly every known-bad
            item is a DataDog sample and every known-good item a registry archive, so these mostly encode the source)

Source indicators (rule fixed before any model was run): a set-A feature is a source indicator when (a) it belongs to
a detector that needs release history or a registry artifact (HISTORY_DETECTORS: not applicable to DataDog samples,
which have no release history), or (b) it is non-zero only in registry archives and never in a DataDog sample (it can
only say "registry"). A feature non-zero only in DataDog samples is NOT excluded: almost every positive is a DataDog
sample, so it cannot be told apart from a real malware signal; this is reported, not hidden.

Sanity checks: the same CV with shuffled labels (fixed seed; AUC should be near 0.5), and the ceiling (known-bad items
whose feature vector is all zero cannot be ranked above an all-zero known-good item).
"""
from __future__ import annotations

import argparse
import csv
import math
import sys
from pathlib import Path

import numpy as np

BENCH = Path(__file__).resolve().parent
RUN2 = BENCH / "results" / "run2"
FEATURES = RUN2 / "features.csv"
SEEDS = (20261107, 20261108, 20261109, 20261110, 20261111)
N_SPLITS = 5
TARGET_FPS = (0.0, 0.05, 0.10, 0.15)
N_BOOT = 2000
BOOT_SEED = 20261107
SHUFFLE_SEED = 20261107
HISTORY_DETECTORS = ("publisher_change", "revival_takeover", "release_delta", "dependency_injection", "tagless_release",
                     "release_vs_git")
MODELS = ("logistic_regression", "random_forest")
SET_ORDER = ("A_strict", "A", "B", "C")
SET_NOTES = {"A_strict": "detector/capability features without source indicators (headline)",
             "A": "detector/capability features",
             "B": "A + install hook + inflated version",
             "C": "B + size, file count, artifact kind, ecosystem: not trusted (dataset bias)"}
TRUSTED = {"A_strict": "yes", "A": "yes", "B": "yes", "C": "no: dataset bias"}


# ------------------------------------------------------------------ data

def read(path: Path = FEATURES) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _num(v) -> float:
    return float(v) if v not in ("", None) else 0.0


def is_datadog(r: dict) -> bool:
    return r["artifact_kind"] == "datadog_sample"


def set_a_columns(rows: list[dict]) -> list[str]:
    cols = [c for c in rows[0] if c.startswith("det_") or c.startswith("cap_")]
    return [c for c in cols if any(_num(r[c]) for r in rows)]          # all-zero columns carry nothing


def leakage(rows: list[dict], cols: list[str]) -> list[dict]:
    """Per set-A feature: share of items with a non-zero value by source and label, and the source-indicator rule."""
    groups = {"datadog_known_bad": [r for r in rows if is_datadog(r) and r["label"] == "1"],
              "registry_known_bad": [r for r in rows if not is_datadog(r) and r["label"] == "1"],
              "registry_known_good": [r for r in rows if not is_datadog(r) and r["set"] == "known_good"],
              "registry_scary_dormant": [r for r in rows if r["set"] in ("scary", "dormant")]}
    out = []
    for c in cols:
        nz = {g: sum(1 for r in rs if _num(r[c])) for g, rs in groups.items()}
        det = c[4:].rsplit("_", 1)[0] if c.startswith("det_") else None
        det = next((d for d in HISTORY_DETECTORS if c.startswith(f"det_{d}_")), None) if det else None
        reg = nz["registry_known_bad"] + nz["registry_known_good"] + nz["registry_scary_dormant"]
        if det:
            why = f"needs release history ({det}): not applicable to DataDog samples"
        elif reg and not nz["datadog_known_bad"]:
            why = "non-zero only in registry archives, never in a DataDog sample"
        else:
            why = ""
        row = {"feature": c, "source_indicator": "yes" if why else "no", "reason": why,
               "only_in_datadog": "yes" if nz["datadog_known_bad"] and not reg else "no"}
        for g, rs in groups.items():
            row[f"nonzero_{g}"] = nz[g]
            row[f"n_{g}"] = len(rs)
        out.append(row)
    return out


def feature_sets(rows: list[dict]) -> tuple[dict, list[dict]]:
    a = set_a_columns(rows)
    leak = leakage(rows, a)
    strict = [l["feature"] for l in leak if l["source_indicator"] == "no"]
    b = a + ["install_hook", "inflated_version"]
    kinds = sorted({r["artifact_kind"] for r in rows})
    ecos = sorted({r["ecosystem"] for r in rows})
    c = b + ["file_count", "total_bytes"] + [f"artifact_kind={k}" for k in kinds] + [f"ecosystem={e}" for e in ecos]
    return {"A_strict": strict, "A": a, "B": b, "C": c}, leak


def matrix(rows: list[dict], cols: list[str]) -> np.ndarray:
    def val(r, c):
        if c.startswith("artifact_kind="):
            return float(r["artifact_kind"] == c.split("=", 1)[1])
        if c.startswith("ecosystem="):
            return float(r["ecosystem"] == c.split("=", 1)[1])
        v = _num(r[c])
        return math.log1p(v) if c in ("total_bytes", "file_count") else v
    return np.array([[val(r, c) for c in cols] for r in rows], dtype=float)


# ------------------------------------------------------------------ models and CV

def make_model(name: str, seed: int):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    if name == "logistic_regression":
        return make_pipeline(StandardScaler(), LogisticRegression(max_iter=5000))
    return RandomForestClassifier(random_state=seed, n_jobs=1)


def threshold(neg_scores: np.ndarray, target: float) -> float:
    """Smallest threshold with at most floor(target * n) negatives scoring >= it (decision: score >= threshold)."""
    s = np.sort(neg_scores)[::-1]
    k = int(math.floor(target * len(s) + 1e-9))
    return float(np.nextafter(s[k], np.inf)) if k < len(s) else -np.inf


def _oof(X, y, name, seed):
    from sklearn.model_selection import StratifiedKFold
    out = np.zeros(len(y))
    for tr, te in StratifiedKFold(N_SPLITS, shuffle=True, random_state=seed).split(X, y):
        m = make_model(name, seed).fit(X[tr], y[tr])
        out[te] = m.predict_proba(X[te])[:, 1]
    return out


def cross_validate(X: np.ndarray, y: np.ndarray, name: str, seeds=SEEDS) -> dict:
    """{"scores": (repeats, n), "decisions": {target: (repeats, n) 0/1}} - every value from a model that did not
    train on that item; thresholds from inner out-of-fold scores of the training fold's negatives."""
    from sklearn.model_selection import StratifiedKFold
    scores = np.zeros((len(seeds), len(y)))
    dec = {t: np.zeros((len(seeds), len(y))) for t in TARGET_FPS}
    for i, seed in enumerate(seeds):
        for tr, te in StratifiedKFold(N_SPLITS, shuffle=True, random_state=seed).split(X, y):
            inner = _oof(X[tr], y[tr], name, seed + 1000)
            thr = {t: threshold(inner[y[tr] == 0], t) for t in TARGET_FPS}
            m = make_model(name, seed).fit(X[tr], y[tr])
            s = m.predict_proba(X[te])[:, 1]
            scores[i, te] = s
            for t in TARGET_FPS:
                dec[t][i, te] = (s >= thr[t]).astype(float)
    return {"scores": scores, "decisions": dec}


# ------------------------------------------------------------------ statistics

def auc(y, s) -> float:
    from sklearn.metrics import roc_auc_score
    return float(roc_auc_score(y, s))


def bootstrap(y: np.ndarray, fn, n_boot: int | None = None, seed: int = BOOT_SEED) -> tuple[float, float]:
    """95% percentile interval of fn(index array), resampling positives and negatives separately."""
    n_boot = n_boot or N_BOOT                           # read at call time, so run(n_boot=...) takes effect
    rng = np.random.default_rng(seed)
    pos, neg = np.where(y == 1)[0], np.where(y == 0)[0]
    vals = []
    for _ in range(n_boot):
        idx = np.concatenate([rng.choice(pos, len(pos)), rng.choice(neg, len(neg))])
        vals.append(fn(idx))
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))


def summarise(y, cv) -> dict:
    s = cv["scores"].mean(axis=0)
    out = {"auc": auc(y, s), "auc_ci": bootstrap(y, lambda i: auc(y[i], s[i])),
           "auc_per_repeat": [auc(y, r) for r in cv["scores"]], "recall": {}}
    for t in TARGET_FPS:
        d = cv["decisions"][t].mean(axis=0)
        pos, neg = y == 1, y == 0
        rec = float(d[pos].mean())
        fp = float(d[neg].mean())
        out["recall"][t] = {"recall": rec, "recall_ci": bootstrap(y, lambda i: float(d[i][y[i] == 1].mean())),
                            "fp": fp, "fp_ci": bootstrap(y, lambda i: float(d[i][y[i] == 0].mean()))}
    return out


# ------------------------------------------------------------------ run

def _w(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def _r(x) -> str:
    return f"{x:.6f}" if isinstance(x, float) else str(x)


def run(features: Path = FEATURES, out_dir: Path = RUN2, seeds=SEEDS, n_boot: int = N_BOOT, models=MODELS,
        sets=SET_ORDER) -> dict:
    global N_BOOT
    N_BOOT = n_boot
    rows = read(features)
    train = [r for r in rows if r["set"] in ("known_bad", "known_good")]
    extra = [r for r in rows if r["set"] in ("scary", "dormant")]
    y = np.array([int(r["label"]) for r in train])
    fsets, leak = feature_sets(rows)
    headline = "A_strict" if fsets["A_strict"] != fsets["A"] else "A"
    summary, recall_rows, extra_rows, roc_rows, eco_rows, coef_rows, sanity = [], [], [], [], [], [], []
    for fs in sets:
        cols = fsets[fs]
        X, Xe = matrix(train, cols), matrix(extra, cols)
        zero_pos = int(sum(1 for i in range(len(y)) if y[i] == 1 and not X[i].any()))
        zero_neg = int(sum(1 for i in range(len(y)) if y[i] == 0 and not X[i].any()))
        sanity.append({"check": "ceiling: known-bad with an all-zero feature vector", "feature_set": fs, "model": "-",
                       "value": zero_pos, "n": int(y.sum()), "ci_low": "", "ci_high": "",
                       "note": f"{zero_neg} of {int((y == 0).sum())} known-good are all-zero too; at 0% FP at most "
                               f"{int(y.sum()) - zero_pos} of {int(y.sum())} known-bad can be ranked above them"})
        for name in models:
            cv = cross_validate(X, y, name, seeds)
            sm = summarise(y, cv)
            summary.append({"feature_set": fs, "model": name, "headline": "yes" if (fs == headline and name == MODELS[0]) else "no",
                            "trusted": TRUSTED[fs], "note": SET_NOTES[fs], "n_features": len(cols),
                            "n_pos": int(y.sum()), "n_neg": int((y == 0).sum()), "auc": _r(sm["auc"]),
                            "auc_ci_low": _r(sm["auc_ci"][0]), "auc_ci_high": _r(sm["auc_ci"][1]),
                            "auc_repeat_min": _r(min(sm["auc_per_repeat"])), "auc_repeat_max": _r(max(sm["auc_per_repeat"])),
                            "repeats": len(seeds), "folds": N_SPLITS})
            for t, v in sm["recall"].items():
                recall_rows.append({"feature_set": fs, "model": name, "target_fp": _r(t), "recall": _r(v["recall"]),
                                    "recall_ci_low": _r(v["recall_ci"][0]), "recall_ci_high": _r(v["recall_ci"][1]),
                                    "realized_fp": _r(v["fp"]), "realized_fp_ci_low": _r(v["fp_ci"][0]),
                                    "realized_fp_ci_high": _r(v["fp_ci"][1]), "n_pos": int(y.sum()), "n_neg": int((y == 0).sum())})
            from sklearn.metrics import roc_curve
            s = cv["scores"].mean(axis=0)
            fpr, tpr, _ = roc_curve(y, s)
            roc_rows += [{"feature_set": fs, "model": name, "fpr": _r(float(a)), "tpr": _r(float(b))} for a, b in zip(fpr, tpr)]
            for eco in sorted({r["ecosystem"] for r in train}):
                m = np.array([r["ecosystem"] == eco for r in train])
                d5 = cv["decisions"][0.05].mean(axis=0)
                ok = len(set(y[m])) == 2
                eco_rows.append({"feature_set": fs, "model": name, "ecosystem": eco, "n_pos": int(y[m].sum()),
                                 "n_neg": int((y[m] == 0).sum()), "auc": _r(auc(y[m], s[m])) if ok else "",
                                 "recall_at_5pct_fp": _r(float(d5[m & (y == 1)].mean())) if y[m].sum() else "",
                                 "realized_fp_at_5pct": _r(float(d5[m & (y == 0)].mean())) if (y[m] == 0).sum() else ""})
            # extra false-positive checks: model on all 431, thresholds from the CV known-good scores
            full = make_model(name, seeds[0]).fit(X, y)
            se = full.predict_proba(Xe)[:, 1] if len(extra) else np.array([])
            for t in TARGET_FPS:
                thr = threshold(s[y == 0], t)
                for st in ("scary", "dormant"):
                    m = np.array([r["set"] == st for r in extra])
                    extra_rows.append({"feature_set": fs, "model": name, "target_fp": _r(t), "set": st,
                                       "flagged": int((se[m] >= thr).sum()), "n": int(m.sum())})
            if name == "logistic_regression":
                lr = full[-1]
                for c, w in sorted(zip(cols, lr.coef_[0]), key=lambda x: -abs(x[1])):
                    coef_rows.append({"feature_set": fs, "feature": c, "coef_standardized": _r(float(w)),
                                      "odds_ratio_per_sd": _r(float(math.exp(w)))})
    # shuffled labels: same CV, labels permuted with a fixed seed (logistic regression, headline set and A)
    rng = np.random.default_rng(SHUFFLE_SEED)
    ys = rng.permutation(y)
    for fs in dict.fromkeys((headline, "A")):
        cv = cross_validate(matrix(train, fsets[fs]), ys, "logistic_regression", seeds)
        s = cv["scores"].mean(axis=0)
        lo, hi = bootstrap(ys, lambda i: auc(ys[i], s[i]))
        sanity.append({"check": "shuffled labels: ROC AUC", "feature_set": fs, "model": "logistic_regression",
                       "value": _r(auc(ys, s)), "n": len(ys), "ci_low": _r(lo), "ci_high": _r(hi),
                       "note": f"labels permuted with seed {SHUFFLE_SEED}; should be near 0.5"})
    feat_rows = [{"feature_set": fs, "feature": c} for fs in sets for c in fsets[fs]]
    _w(out_dir / "ml_summary.csv", summary)
    _w(out_dir / "ml_recall_at_fp.csv", recall_rows)
    _w(out_dir / "ml_extra_sets.csv", extra_rows)
    _w(out_dir / "ml_roc.csv", roc_rows)
    _w(out_dir / "ml_ecosystem.csv", eco_rows)
    _w(out_dir / "ml_coefficients.csv", coef_rows)
    _w(out_dir / "ml_sanity.csv", sanity)
    _w(out_dir / "ml_leakage.csv", leak)
    _w(out_dir / "ml_features.csv", feat_rows)
    return {"headline": headline, "summary": summary}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Learned combiner over the frozen ruleset's outputs (research only)")
    ap.add_argument("--features", default=str(FEATURES))
    ap.add_argument("--out-dir", default=str(RUN2))
    a = ap.parse_args(argv)
    res = run(Path(a.features), Path(a.out_dir))
    if Path(a.out_dir).resolve() == RUN2.resolve():
        sys.path.insert(0, str(BENCH.parent))
        import ml_results
        (BENCH / "ML_COMBINER.md").write_text(ml_results.markdown(), encoding="utf-8", newline="\n")
        print(f"wrote {BENCH / 'ML_COMBINER.md'}")
    for s in res["summary"]:
        print(f"{s['feature_set']:9} {s['model']:20} AUC {float(s['auc']):.3f} "
              f"[{float(s['auc_ci_low']):.3f}, {float(s['auc_ci_high']):.3f}]")
    print(f"headline feature set: {res['headline']}; wrote {a.out_dir}/ml_*.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
