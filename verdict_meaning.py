"""What a Trust verdict meant in the benchmark: measured numbers read from the committed run-2 result files
(benchmark/results/run2/*.csv, ruleset 2026.11.08-12). Nothing is typed by hand or recomputed except one count
(known-bad items without a review-tier or high-risk finding = n - lenient hits). Display only.

The app scans in REPOSITORY mode. Known-bad recall was measured in ARTIFACT mode only (release archives and DataDog
samples); repo-mode known-bad recall is not measured.
"""
from __future__ import annotations

import csv
from pathlib import Path

from pillars import (LABEL_FRAGILE, LABEL_HIGH_RISK, LABEL_KNOWN_MALICIOUS, LABEL_NO_FINDINGS, LABEL_NOT_ASSESSED,
                     LABEL_REVIEW)

RUN2 = Path(__file__).resolve().parent / "benchmark" / "results" / "run2"
SETS = (("known_good", "maintained (random known-good)"), ("scary", "scary-but-legitimate (hand-picked)"),
        ("dormant", "dormant / finished libraries"))
MODE_NOTE = ("Your scan ran in repository mode (the app's pipeline). Known-bad recall was measured in artifact mode "
             "only (release archives and DataDog samples); repository-mode known-bad recall is not measured.")
SOURCE_NOTE = "Benchmark run 2, ruleset 2026.11.08-12, from benchmark/results/run2/ (indicators, not proof)."

LABEL_MEANING = {
    LABEL_KNOWN_MALICIOUS: ("strict", "a known-malicious indicator (strict operating point). In the app the OSV MAL- "
                                      "lookup is on; the headline recall below is without it (OSV numbers are circular)."),
    LABEL_HIGH_RISK: ("strict", "at least one high-risk finding (strict operating point)."),
    LABEL_REVIEW: ("lenient", "at least one review-tier finding but no high-risk one (lenient, not strict)."),
    LABEL_NO_FINDINGS: ("none", "no review-tier or high-risk finding. This is not evidence that the package is harmless."),
    LABEL_FRAGILE: ("other", "a maintenance label: maintenance is not a threat signal and was not measured as one."),
    LABEL_NOT_ASSESSED: ("other", "no evidence pillar could run, so no benchmark number applies."),
}


def _rows(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _pct(x) -> str:
    return f"{100 * float(x):.1f}%"


def rate_from_row(r: dict, k_field: str) -> str:
    """'12.4% (39/314; 95% CI 9.2%-16.5%)' from a CSV row (rate, ci_low, ci_high, rule_of_three as written)."""
    rate = r.get("rate", r.get("recall"))
    s = f"{_pct(rate)} ({int(r[k_field])}/{int(r['n'])}; 95% CI {_pct(r['ci_low'])}-{_pct(r['ci_high'])})"
    if r.get("rule_of_three"):
        s += f"; rule of three: at most {_pct(r['rule_of_three'])}"
    return s


def measured(run_dir: Path = RUN2) -> dict | None:
    """{"artifact": {...}, "repo": {set: {"soft", "hard"}}, "no_finding_known_bad": (count, n)} or None when the
    result files are not available."""
    try:
        recall = {(r["operating_point"], r["run"]): r for r in _rows(run_dir / "recall.csv")}
        art = {(r["set"], r["kind"]): r for r in _rows(run_dir / "false_positives_rates.csv")}
        repo = {(r["set"], r["kind"]): r for r in _rows(run_dir / "repo_mode_false_positives.csv")}
    except (OSError, KeyError, csv.Error):
        return None
    strict, lenient = recall[("strict", "headline")], recall[("lenient", "headline")]
    return {
        "artifact": {"strict_recall": rate_from_row(strict, "hits"), "lenient_recall": rate_from_row(lenient, "hits"),
                     "soft_fp": rate_from_row(art[("known_good", "soft")], "fp"),
                     "hard_fp": rate_from_row(art[("known_good", "hard")], "fp")},
        "repo": {s: {"soft": rate_from_row(repo[(s, "soft")], "fp"), "hard": rate_from_row(repo[(s, "hard")], "fp")}
                 for s, _label in SETS if (s, "soft") in repo},
        "no_finding_known_bad": (int(lenient["n"]) - int(lenient["hits"]), int(lenient["n"])),
    }


def verdict_meaning(label_base: str | None, run_dir: Path = RUN2) -> dict:
    """{"available", "label", "meaning", "operating_point", "rows": [{"Mode", "Measure", "Measured"}], "mode_note",
    "source_note"}. Rows: artifact mode (known-bad strict / lenient recall, random known-good soft / hard
    false-positive rates), repository mode (soft and hard false-positive rates on the maintained, scary and dormant
    sets) and repository-mode known-bad recall: not measured."""
    point, meaning = LABEL_MEANING.get(label_base, ("other", "no benchmark operating point corresponds to this label."))
    out = {"available": False, "label": label_base, "meaning": meaning, "operating_point": point, "rows": [],
           "mode_note": MODE_NOTE, "source_note": SOURCE_NOTE, "extra": None}
    m = measured(run_dir)
    if m is None:
        out["meaning"] += " The benchmark result files are not available here, so no number is shown."
        return out
    a = m["artifact"]
    rows = [("Artifact", "Known-bad strict recall (high-risk or known-malicious finding)", a["strict_recall"]),
            ("Artifact", "Known-bad lenient recall (review-tier finding or above)", a["lenient_recall"]),
            ("Artifact", "Random known-good: soft false positives (Review recommended)", a["soft_fp"]),
            ("Artifact", "Random known-good: hard false positives (high-risk / DO NOT USE)", a["hard_fp"])]
    for s, label in SETS:
        if s in m["repo"]:
            rows.append(("Repository", f"{label}: soft false positives", m["repo"][s]["soft"]))
            rows.append(("Repository", f"{label}: hard false positives", m["repo"][s]["hard"]))
    rows.append(("Repository", "Known-bad recall", "not measured (known-bad items have no repository)"))
    out.update(available=True, rows=[{"Mode": md, "Measure": ms, "Measured": v} for md, ms, v in rows])
    if point == "none":
        k, n = m["no_finding_known_bad"]
        out["extra"] = (f"In artifact mode, {k} of {n} known-bad samples ({100 * k / n:.1f}%) also had no review-tier "
                        "or high-risk finding.")
    return out
