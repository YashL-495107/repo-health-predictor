"""Metrics for the GuardDog external baseline, with OUR definitions (benchmark/metrics.py: Wilson 95% intervals,
rule of three at 0 events), and the side-by-side with our detectors and the learned combiner.

  python benchmark/guarddog_metrics.py      # reads results/run2/guarddog.csv (+ our run-2 CSVs), writes guarddog_*.csv

Operating points for GuardDog 3.2.0 (its own risk labels; nothing tuned):
  default, high_risk        label high_risk (score >= 7)            ~ our strict
  default, suspicious+      label suspicious or high_risk (>= 5)    ~ our lenient
  matched FP                a threshold on GuardDog's 0-10 risk score with at most the target share of random
                            known-good items flagged (0, 5, 10, 15 % and our lenient rate 17/117); chosen on the same
                            117 known-good items (GuardDog is a fixed scorer, not trained here, so this is a point
                            on its ROC curve, slightly optimistic for any fixed threshold). Realized rates reported.
Items GuardDog could not scan are NOT scored for GuardDog (listed, never imputed); our rows keep their own n.
Hard false positive (GuardDog): a random known-good item labelled high_risk. Ours: as in RESULTS.md.
CAVEAT: GuardDog's rules were developed and evaluated by DataDog on the same malicious-packages dataset our known-bad
samples come from, so its recall here is likely inflated; a reference point, not a fair contest.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import numpy as np

BENCH = Path(__file__).resolve().parent
RUN2 = BENCH / "results" / "run2"
sys.path.insert(0, str(BENCH))

from metrics import rate_text, wilson  # noqa: E402

SETS = ("known_bad", "known_good", "scary", "dormant")
TARGETS = (0.0, 0.05, 0.10, 0.15)
N_BOOT, BOOT_SEED = 2000, 20261107
STRICT, LENIENT = {"high_risk"}, {"high_risk", "suspicious"}


def _rows(name: str, d: Path = RUN2) -> list[dict]:
    with open(d / name, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _w(path: Path, rows: list[dict]):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def auc(pos: np.ndarray, neg: np.ndarray) -> float:
    """Mann-Whitney AUC (ties count one half)."""
    if not len(pos) or not len(neg):
        return float("nan")
    allv = np.concatenate([pos, neg])
    order = allv.argsort(kind="mergesort")
    ranks = np.empty(len(allv))
    sv = allv[order]
    i = 0
    while i < len(sv):
        j = i
        while j + 1 < len(sv) and sv[j + 1] == sv[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    return float((ranks[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def threshold(neg: np.ndarray, target: float) -> float:
    """Smallest score threshold with at most floor(target * n) negatives scoring >= it."""
    s = np.sort(neg)[::-1]
    k = int(np.floor(target * len(s) + 1e-9))
    return float(np.nextafter(s[k], np.inf)) if k < len(s) else -np.inf


def run(d: Path = RUN2) -> dict:
    gd = _rows("guarddog.csv", d)
    ours = {r["id"]: r for r in _rows("items.csv", d)}
    scored = [r for r in gd if r["status"] == "scanned"]
    not_scored = [r for r in gd if r["status"] != "scanned"]
    by = {s: [r for r in scored if r["set"] == s] for s in SETS}
    score = {s: np.array([float(r["risk_score"] or 0) for r in by[s]]) for s in SETS}

    def point(name, flag, threshold_=""):
        row = {"tool": "GuardDog 3.2.0", "operating_point": name, "threshold": threshold_}
        for s in SETS:
            k = sum(1 for r, v in zip(by[s], score[s]) if flag(r, v))
            n = len(by[s])
            lo, hi = wilson(k, n)
            row.update({f"{s}_k": k, f"{s}_n": n, f"{s}_rate": f"{k / n:.6f}", f"{s}_ci_low": f"{lo:.6f}",
                        f"{s}_ci_high": f"{hi:.6f}", f"{s}_text": rate_text(k, n, zero_rule=(s != "known_bad"))})
        return row

    summary = [point("default: high_risk", lambda r, v: r["risk_label"] in STRICT),
               point("default: suspicious or high_risk", lambda r, v: r["risk_label"] in LENIENT)]
    kg = score["known_good"]
    fp_ours = next(r for r in _rows("false_positives_rates.csv", d) if r["set"] == "known_good" and r["kind"] == "lenient")
    targets = [(f"matched FP: {int(t * 100)}% target", t) for t in TARGETS]
    targets.append((f"matched FP: our lenient rate ({fp_ours['fp']}/{fp_ours['n']})", int(fp_ours["fp"]) / int(fp_ours["n"])))
    for name, t in targets:
        thr = threshold(kg, t)
        summary.append(point(name, lambda r, v, thr=thr: v >= thr, f"{thr:.6f}"))
    # ROC AUC of the risk score, known-bad vs random known-good, with a stratified bootstrap interval
    pos, neg = score["known_bad"], score["known_good"]
    rng = np.random.default_rng(BOOT_SEED)
    boots = [auc(rng.choice(pos, len(pos)), rng.choice(neg, len(neg))) for _ in range(N_BOOT)]
    stats = [{"key": "auc", "value": f"{auc(pos, neg):.6f}", "ci_low": f"{np.percentile(boots, 2.5):.6f}",
              "ci_high": f"{np.percentile(boots, 97.5):.6f}", "note": "risk score, known-bad vs random known-good"},
             {"key": "known_bad_scored", "value": len(by["known_bad"]), "ci_low": "", "ci_high": "",
              "note": f"of {len([r for r in gd if r['set'] == 'known_bad'])} known-bad items"},
             {"key": "not_scored", "value": len(not_scored), "ci_low": "", "ci_high": "",
              "note": "; ".join(f"{r['id']} ({r['status']})" for r in not_scored) or "-"}]
    # our detectors on exactly the items GuardDog scored (same n), for a like-for-like line
    bad_ids = [r["id"] for r in by["known_bad"]]
    for op in ("strict", "lenient"):
        k = sum(1 for i in bad_ids if ours[i][f"{op}_hit"] == "True")
        lo, hi = wilson(k, len(bad_ids))
        stats.append({"key": f"ours_{op}_on_guarddog_scored", "value": k, "ci_low": f"{lo:.6f}", "ci_high": f"{hi:.6f}",
                      "note": f"{rate_text(k, len(bad_ids))}: our detectors on the {len(bad_ids)} known-bad items GuardDog scored"})
    # overlap of catches (GuardDog high_risk vs our strict; suspicious+ vs our lenient)
    for g_set, op in ((STRICT, "strict"), (LENIENT, "lenient")):
        g = {r["id"] for r in by["known_bad"] if r["risk_label"] in g_set}
        o = {i for i in bad_ids if ours[i][f"{op}_hit"] == "True"}
        stats += [{"key": f"overlap_{op}_both", "value": len(g & o), "ci_low": "", "ci_high": "", "note": f"caught by both ({op} / GuardDog {'high_risk' if op == 'strict' else 'suspicious+'})"},
                  {"key": f"overlap_{op}_guarddog_only", "value": len(g - o), "ci_low": "", "ci_high": "", "note": "caught by GuardDog only"},
                  {"key": f"overlap_{op}_ours_only", "value": len(o - g), "ci_low": "", "ci_high": "", "note": "caught by our detectors only"}]
    # every random known-good / scary / dormant item GuardDog flagged, with our verdict for the same item
    flags = []
    for s in ("known_good", "scary", "dormant"):
        for r in by[s]:
            if r["risk_label"] in LENIENT:
                o = ours.get(r["id"], {})
                flags.append({"id": r["id"], "set": s, "guarddog_label": r["risk_label"], "guarddog_score": r["risk_score"],
                              "guarddog_rules": r["rules_fired"], "our_label": o.get("label", ""),
                              "our_strict_hit": o.get("strict_hit", ""), "our_lenient_hit": o.get("lenient_hit", ""),
                              "hard_fp_guarddog_only": "yes" if (s == "known_good" and r["risk_label"] in STRICT
                                                                 and o.get("strict_hit") != "True") else "no"})
    per_eco = []
    for eco in sorted({r["ecosystem"] for r in by["known_bad"]}):
        for name, g_set in (("default: high_risk", STRICT), ("default: suspicious or high_risk", LENIENT)):
            b = [r for r in by["known_bad"] if r["ecosystem"] == eco]
            g = [r for r in by["known_good"] if r["ecosystem"] == eco]
            kb, kg_ = sum(r["risk_label"] in g_set for r in b), sum(r["risk_label"] in g_set for r in g)
            per_eco.append({"ecosystem": eco, "operating_point": name, "recall_text": rate_text(kb, len(b)),
                            "fp_known_good_text": rate_text(kg_, len(g), zero_rule=True)})
    _w(d / "guarddog_summary.csv", summary)
    _w(d / "guarddog_stats.csv", stats)
    _w(d / "guarddog_flags.csv", flags or [{"id": "", "set": "", "guarddog_label": "", "guarddog_score": "",
                                             "guarddog_rules": "", "our_label": "", "our_strict_hit": "",
                                             "our_lenient_hit": "", "hard_fp_guarddog_only": ""}])
    _w(d / "guarddog_ecosystem.csv", per_eco)
    return {"summary": summary, "stats": stats, "flags": flags}


if __name__ == "__main__":
    res = run()
    for r in res["summary"]:
        print(f"{r['operating_point']:45} recall {r['known_bad_text']:40} FP kg {r['known_good_text']}")
    for s in res["stats"]:
        print(s["key"], s["value"], s["ci_low"], s["ci_high"], s["note"][:100])
