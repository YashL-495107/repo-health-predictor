"""Analyse data/backtest.csv: does the health score, computed a year ago, predict which repos went quiet?

    python backtest_analyze.py                   # needs: pip install scikit-learn matplotlib

Compares three predictors of y_dead (all using only information available at the snapshot date):
  1. baseline   : days since last commit
  2. formula    : the commit-only version of the live health score (no fitting)
  3. logistic   : logistic regression on the commit signals (5-fold cross-validated, repeated)
Reports AUC with bootstrap 95% intervals, death rate by score band, odds ratios, and robustness checks.
Sampling was case-control (kept-going vs went-quiet), so AUC is meaningful but rates/accuracy are not prevalence.
"""
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.linear_model import LogisticRegression
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import argparse
import os

import matplotlib
matplotlib.use("Agg")


def features(d):
    return pd.DataFrame({
        "days since last commit (log)": np.log1p(d["idle_days_T"]),
        "commits, last 12 weeks (log)": np.log1p(d["commits_12w_T"]),
        "earlier pace per 12 weeks (log)": np.log1p(d["prev_per_12w_T"]),
        "active authors, last 180 days": d["authors_180_T"],
        "active authors, previous 180 days": d["authors_prior_T"],
        "top author's share of commits": d["top_author_share_T"].fillna(1.0),
        "repo age (log days)": np.log1p(d["age_days_T"]),
    })


def model():
    return make_pipeline(StandardScaler(), LogisticRegression(C=1.0, max_iter=1000))


def oof_predict(X, y, repeats=5, seed=0):
    """Out-of-fold probabilities averaged over repeated stratified 5-fold CV (no row is scored by a model that saw it)."""
    cv = RepeatedStratifiedKFold(
        n_splits=5, n_repeats=repeats, random_state=seed)
    p, n = np.zeros(len(y)), np.zeros(len(y))
    for tr, te in cv.split(X, y):
        m = model().fit(X.iloc[tr], y[tr])
        p[te] += m.predict_proba(X.iloc[te])[:, 1]
        n[te] += 1
    return p / n


def boot(y, scores, base="baseline", n=2000, seed=1):
    """Bootstrap 95% CIs for each AUC and for the paired difference against the baseline."""
    rng, idx = np.random.default_rng(seed), np.arange(len(y))
    aucs = {k: [] for k in scores}
    diffs = {k: [] for k in scores if k != base}
    for _ in range(n):
        s = rng.choice(idx, len(idx))
        if y[s].min() == y[s].max():
            continue
        a = {k: roc_auc_score(y[s], v[s]) for k, v in scores.items()}
        for k in a:
            aucs[k].append(a[k])
        for k in diffs:
            diffs[k].append(a[k] - a[base])

    def ci(v): return tuple(np.percentile(v, [2.5, 97.5]))
    return {k: ci(v) for k, v in aucs.items()}, {k: ci(v) for k, v in diffs.items()}


def wilson(k, n, z=1.96):
    if n == 0:
        return (np.nan, np.nan)
    p = k / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (c - h, c + h)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/backtest.csv")
    ap.add_argument("--outdir", default="data")
    args = ap.parse_args()
    d = pd.read_csv(args.input)
    y = d["y_dead"].to_numpy().astype(int)
    if min(y.sum(), (1 - y).sum()) < 15:
        raise SystemExit(
            f"Need at least 15 repos in each class; got {y.sum()} dead / {(1 - y).sum()} alive.")
    X = features(d)
    print(
        f"{len(d)} repos | dead {y.sum()} ({y.mean():.0%}) | snapshot {d['snapshot'].iloc[0]}")
    print(f"truncated (very busy) repos: {int(d['truncated'].sum())}\n")

    scores = {"baseline": d["idle_days_T"].to_numpy(float),            # more idle days -> more likely dead
              # lower score -> more likely dead
              "formula": -d["score_commit_only_T"].to_numpy(float),
              "logistic": oof_predict(X, y)}
    auc = {k: roc_auc_score(y, v) for k, v in scores.items()}
    aci, dci = boot(y, scores)
    names = {"baseline": "Baseline: days since last commit", "formula": "Live formula (commit-only score)",
             "logistic": "Logistic regression (cross-validated)"}
    print("== AUC (0.5 = coin flip, 1.0 = perfect) ==")
    rows = []
    for k in scores:
        lo, hi = aci[k]
        extra = "" if k == "baseline" else f"   vs baseline: {auc[k] - auc['baseline']:+.3f} (95% CI {dci[k][0]:+.3f} to {dci[k][1]:+.3f})"
        print(f"{names[k]:40} {auc[k]:.3f}  (95% CI {lo:.3f}-{hi:.3f}){extra}")
        rows.append({"predictor": names[k], "auc": round(
            auc[k], 3), "ci_low": round(lo, 3), "ci_high": round(hi, 3)})
    print("A difference whose interval includes 0 is NOT evidence that one predictor is better.\n")

    # ---- score bands (the live thresholds 70 / 40) -------------------------------------------
    s = d["score_commit_only_T"]
    band = pd.cut(s, [-0.01, 39.99, 69.99, 100.01],
                  labels=["below 40", "40-69", "70+"])
    print("== Share of repos that went quiet, by commit-only score a year earlier ==")
    br = []
    for b in ["70+", "40-69", "below 40"]:
        m = band == b
        n, k = int(m.sum()), int(y[m].sum())
        lo, hi = wilson(k, n)
        print(
            f"score {b:9} n={n:3}  went quiet {k:3} ({k / max(n, 1):.0%}, 95% CI {lo:.0%}-{hi:.0%})")
        br.append((b, n, k, k / max(n, 1), lo, hi))
    print("(Shares reflect the case-control sample, not real-world rates; look at the ORDER across bands.)\n")

    # ---- odds ratios ----------------------------------------------------------------------------
    m = model().fit(X, y)
    coef = m[-1].coef_[0]
    rng, B = np.random.default_rng(2), []
    for _ in range(500):
        i = rng.choice(len(y), len(y))
        if y[i].min() != y[i].max():
            B.append(model().fit(X.iloc[i], y[i])[-1].coef_[0])
    B = np.array(B)
    orr = pd.DataFrame({"signal": X.columns, "odds_ratio": np.exp(coef), "lo": np.exp(np.percentile(B, 2.5, axis=0)),
                        "hi": np.exp(np.percentile(B, 97.5, axis=0))}).sort_values("odds_ratio")
    print("== Odds ratio of going quiet per +1 standard deviation (above 1 = more likely to go quiet) ==")
    for r in orr.itertuples():
        print(f"{r.signal:36} {r.odds_ratio:5.2f}  (95% CI {r.lo:.2f}-{r.hi:.2f})")
    print("Signals are correlated, so read single odds ratios cautiously.\n")

    # ---- robustness ---------------------------------------------------------------------------------
    print("== Robustness: AUC of baseline / formula ==")

    def pair(mask, label, yy=None):
        yy = y if yy is None else yy
        if yy[mask].min() == yy[mask].max() or min(yy[mask].sum(), (1 - yy[mask]).sum()) < 5:
            print(f"{label:34} too few of one class")
            return
        print(f"{label:34} n={int(mask.sum()):3}  {roc_auc_score(yy[mask], scores['baseline'][mask]):.3f} / "
              f"{roc_auc_score(yy[mask], scores['formula'][mask]):.3f}")
    allm = np.ones(len(y), bool)
    pair(allm, "all repos (main label)")
    pair(~d["truncated"].to_numpy(bool), "excluding truncated busy repos")
    pair(allm, "label: no commits only (ignore archive)",
         (d["commits_after"] == 0).astype(int).to_numpy())
    pair(allm, "label: <=2 commits or archived",
         ((d["commits_after"] <= 2) | d["archived_now"]).astype(int).to_numpy())
    for lang, g in d.groupby("language"):
        if len(g) >= 20:
            pair((d["language"] == lang).to_numpy(), f"language: {lang}")

    # ---- charts + summary -----------------------------------------------------------------------------
    os.makedirs(args.outdir, exist_ok=True)
    plt.figure(figsize=(5.5, 5))
    for k in scores:
        f, t, _ = roc_curve(y, scores[k])
        plt.plot(f, t, label=f"{names[k]} (AUC {auc[k]:.2f})")
    plt.plot([0, 1], [0, 1], "k--", lw=0.8)
    plt.xlabel("False positive rate")
    plt.ylabel("True positive rate")
    plt.title("Predicting which repos go quiet (snapshot 1 year ago)")
    plt.legend(fontsize=7, loc="lower right")
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, "backtest_roc.png"), dpi=200)
    plt.close()

    plt.figure(figsize=(5.5, 4))
    xs = [b[0] for b in br]
    ys = [b[3] * 100 for b in br]
    err = [[(b[3] - b[4]) * 100 for b in br],
           [(b[5] - b[3]) * 100 for b in br]]
    plt.bar(xs, ys, yerr=err, capsize=4, color=[
            "#1a9850", "#f4a300", "#d73027"])
    for i, b in enumerate(br):
        plt.text(i, 2, f"n={b[1]}", ha="center", fontsize=8)
    plt.ylabel("% that went quiet (sample share)")
    plt.xlabel("Commit-only health score a year earlier")
    plt.ylim(0, 100)
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, "backtest_bands.png"), dpi=200)
    plt.close()

    plt.figure(figsize=(7, 4))
    plt.errorbar(orr["odds_ratio"], range(len(orr)), xerr=[
                 orr["odds_ratio"] - orr["lo"], orr["hi"] - orr["odds_ratio"]], fmt="o", capsize=3)
    plt.axvline(1, color="k", lw=0.8)
    plt.xscale("log")
    plt.yticks(range(len(orr)), orr["signal"], fontsize=8)
    plt.xlabel("Odds ratio of going quiet per +1 SD (log scale)")
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, "backtest_odds.png"), dpi=200)
    plt.close()
    pd.DataFrame(rows).to_csv(os.path.join(
        args.outdir, "backtest_summary.csv"), index=False)
    print(
        f"\nSaved charts and summary in {args.outdir}/: backtest_roc.png, backtest_bands.png, backtest_odds.png, backtest_summary.csv")


if __name__ == "__main__":
    main()
