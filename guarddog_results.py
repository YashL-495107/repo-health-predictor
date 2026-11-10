"""Display strings for the GuardDog comparison, READ from benchmark/results/run2/guarddog_*.csv (written by
benchmark/guarddog_metrics.py from guarddog.csv) and our own run-2 CSVs (recall.csv, false_positives_rates.csv,
ml_*.csv). The app never imports or runs GuardDog; this module only formats committed numbers."""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUN2 = ROOT / "benchmark" / "results" / "run2"
TITLE = "Compared with GuardDog"
CAVEAT = ("GuardDog's rules were developed and evaluated by DataDog on the same malicious-packages dataset our known-bad "
          "samples come from, so its recall here is likely inflated; this is a reference point, not a fair contest.")
WHAT = ("GuardDog is DataDog's open-source scanner for malicious PyPI / npm (and other) packages (Apache-2.0). Version "
        "3.2.0 was run locally on the same 461 run-2 items, on the same text inputs our scanner read, with its default "
        "rules; it is an external reference only and is not part of the app.")
COVERAGE = [("Only in our tool", "repository mode (the app scans a GitHub repository), maintenance health, release "
             "provenance and publisher history, the upgrade check between two versions, and the Trust score with its "
             "evidence pillars."),
            ("Only in GuardDog", "a larger set of package-level rules (YARA rules for code and install scripts, plus "
             "registry-metadata rules such as typosquatting and maintainer e-mail domains, which need registry metadata "
             "and did not run on these local scans), and more ecosystems (Go, Rust, RubyGems).")]


def _rows(name: str, d: Path = RUN2) -> list[dict]:
    with open(d / name, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def available(d: Path = RUN2) -> bool:
    return (d / "guarddog_summary.csv").is_file()


def p(x) -> str:
    return f"{100 * float(x):.1f}%"


def _ci(k, n, lo, hi) -> str:
    return f"{p(int(k) / int(n))} ({k}/{n}; 95% CI {p(lo)}-{p(hi)})"


def load(d: Path = RUN2) -> dict:
    return {"summary": _rows("guarddog_summary.csv", d), "stats": {r["key"]: r for r in _rows("guarddog_stats.csv", d)},
            "flags": [r for r in _rows("guarddog_flags.csv", d) if r["id"]], "eco": _rows("guarddog_ecosystem.csv", d),
            "recall": {(r["operating_point"], r["run"]): r for r in _rows("recall.csv", d)},
            "fp": {(r["set"], r["kind"]): r for r in _rows("false_positives_rates.csv", d)},
            "ml_summary": _rows("ml_summary.csv", d), "ml_recall": _rows("ml_recall_at_fp.csv", d),
            "ml_extra": _rows("ml_extra_sets.csv", d)}


def _fp(r: dict) -> str:
    return _ci(r["fp"], r["n"], r["ci_low"], r["ci_high"]) + (f"; rule of three: at most {p(r['rule_of_three'])}"
                                                               if r.get("rule_of_three") else "")


def side_by_side(g: dict) -> list[dict]:
    rows = []
    for op, kind in (("strict", "strict"), ("lenient", "lenient")):
        rec = g["recall"][(op, "headline")]
        rows.append({"Tool": "Our detectors (frozen ruleset 2026.11.08-12)", "Operating point": op,
                     "ROC AUC": "n/a (fixed rules)",
                     "Known-bad recall": _ci(rec["hits"], rec["n"], rec["ci_low"], rec["ci_high"]),
                     "False positives: random known-good": _fp(g["fp"][("known_good", kind)]),
                     "Scary": f"{g['fp'][('scary', kind)]['fp']}/{g['fp'][('scary', kind)]['n']}",
                     "Dormant": f"{g['fp'][('dormant', kind)]['fp']}/{g['fp'][('dormant', kind)]['n']}"})
    names = {"logistic_regression": "logistic regression", "random_forest": "random forest"}
    for model in ("logistic_regression", "random_forest"):
        s = next(x for x in g["ml_summary"] if x["feature_set"] == "A_strict" and x["model"] == model)
        for t in ("0.050000", "0.150000"):
            r = next(x for x in g["ml_recall"] if x["feature_set"] == "A_strict" and x["model"] == model and x["target_fp"] == t)
            ex = {x["set"]: x for x in g["ml_extra"] if x["feature_set"] == "A_strict" and x["model"] == model and x["target_fp"] == t}
            rows.append({"Tool": f"Learned combiner, A-strict, {names[model]} (experimental)",
                         "Operating point": f"{int(round(float(t) * 100))}% FP target (cross-validated)",
                         "ROC AUC": f"{float(s['auc']):.3f} ({float(s['auc_ci_low']):.3f}-{float(s['auc_ci_high']):.3f})",
                         "Known-bad recall": f"{p(r['recall'])} (95% CI {p(r['recall_ci_low'])}-{p(r['recall_ci_high'])})",
                         "False positives: random known-good": f"{p(r['realized_fp'])} realized",
                         "Scary": f"{ex['scary']['flagged']}/{ex['scary']['n']}",
                         "Dormant": f"{ex['dormant']['flagged']}/{ex['dormant']['n']}"})
    a = g["stats"]["auc"]
    for r in g["summary"]:
        rows.append({"Tool": "GuardDog 3.2.0 (external reference)", "Operating point": r["operating_point"],
                     "ROC AUC": f"{float(a['value']):.3f} ({float(a['ci_low']):.3f}-{float(a['ci_high']):.3f})",
                     "Known-bad recall": r["known_bad_text"], "False positives: random known-good": r["known_good_text"],
                     "Scary": f"{r['scary_k']}/{r['scary_n']}", "Dormant": f"{r['dormant_k']}/{r['dormant_n']}"})
    return rows


def _pkg(item_id: str) -> str:
    """'known_good:PyPI:typer@0.28.0' -> 'typer 0.28.0 (PyPI)'."""
    _set, eco, rest = item_id.split(":", 2)
    name, _, ver = rest.rpartition("@")
    return f"{name} {ver} ({eco})"


def hard_fp_line(g: dict) -> str:
    only = [f for f in g["flags"] if f["hard_fp_guarddog_only"] == "yes"]
    kg = next(r for r in g["summary"] if r["operating_point"] == "default: high_risk")
    ours = g["fp"][("known_good", "strict")]
    return (f"Hard false positives on random known-good packages: GuardDog labelled {kg['known_good_k']} of "
            f"{kg['known_good_n']} high_risk; {len(only)} of them ({', '.join(_pkg(f['id']) for f in only)}) got no "
            f"high-risk finding from our detectors, whose strict false positives were {ours['fp']}/{ours['n']}.")


def flags_table(g: dict) -> list[dict]:
    return [{"Package": _pkg(f["id"]), "Set": f["set"].replace("_", " "), "GuardDog": f"{f['guarddog_label']} ({f['guarddog_score']})",
             "Our label (same item, artifact mode)": f["our_label"],
             "Our high-risk finding": "yes" if f["our_strict_hit"] == "True" else "no"} for f in g["flags"]]


def overlap_lines(g: dict) -> list[str]:
    s = g["stats"]
    return [f"Our strict vs GuardDog high_risk: both {s['overlap_strict_both']['value']}, GuardDog only "
            f"{s['overlap_strict_guarddog_only']['value']}, ours only {s['overlap_strict_ours_only']['value']}.",
            f"Our lenient vs GuardDog suspicious or high_risk: both {s['overlap_lenient_both']['value']}, GuardDog only "
            f"{s['overlap_lenient_guarddog_only']['value']}, ours only {s['overlap_lenient_ours_only']['value']}.",
            f"Our detectors on the same {s['known_bad_scored']['value']} known-bad items GuardDog scored: strict "
            f"{s['ours_strict_on_guarddog_scored']['note'].split(':')[0]}, lenient "
            f"{s['ours_lenient_on_guarddog_scored']['note'].split(':')[0]}."]


def not_scored_line(g: dict) -> str:
    s = g["stats"]
    return (f"Not scored for GuardDog (listed, never imputed): {s['not_scored']['value']} item(s): "
            f"{s['not_scored']['note']}. GuardDog's known-bad n is {s['known_bad_scored']['value']}.")


def headline(g: dict) -> str:
    hr = next(r for r in g["summary"] if r["operating_point"] == "default: high_risk")
    m0 = next(r for r in g["summary"] if r["operating_point"] == "matched FP: 0% target")
    strict = g["recall"][("strict", "headline")]
    return (f"GuardDog 3.2.0 at its default high_risk label: recall {hr['known_bad_text']} with "
            f"{hr['known_good_k']}/{hr['known_good_n']} random known-good packages flagged; at 0/{m0['known_good_n']} "
            f"false positives its recall is {m0['known_bad_text']}, against our strict rules' "
            f"{p(strict['recall'])} ({strict['hits']}/{strict['n']}).")


def readme_paragraph(g: dict | None = None) -> str:
    g = g or load()
    return (f"**{TITLE}** (external reference, not a fair contest): {headline(g)} {hard_fp_line(g)} {CAVEAT} "
            "Details: the app's \"Compared with GuardDog\" page and `benchmark/results/run2/guarddog_*.csv`.\n")
