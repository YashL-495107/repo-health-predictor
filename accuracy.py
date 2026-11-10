"""Numbers for the "How accurate is it?" page, the compact verdict summary and the README headline table.

Every number is READ from committed files of benchmark run 2 (ruleset 2026.11.08-12): benchmark/results/run2/*.csv,
benchmark/RESULTS.md (header table) and benchmark/ERROR_ANALYSIS.md (bucket tables). Percentages are formatted from
the rates and Wilson intervals stored in the CSVs; the only arithmetic is count / n for rows the CSV stores as counts
(baseline.csv) and precision = hits / (hits + false positives), both checked against RESULTS.md by the tests.
Display only: nothing here changes a score, a detector or a benchmark file.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

from verdict_meaning import rate_from_row

ROOT = Path(__file__).resolve().parent
RUN2 = ROOT / "benchmark" / "results" / "run2"
RESULTS_MD = ROOT / "benchmark" / "RESULTS.md"
ERROR_MD = ROOT / "benchmark" / "ERROR_ANALYSIS.md"
REPO_URL = "https://github.com/YashL-495107/repo-health-predictor/blob/main/"
SUMMARY = "Measured on a frozen, pre-registered benchmark (ruleset 2026.11.08-12, run 2). Indicators, not proof."
SETS = (("known_good", "Random known-good (maintained)"), ("scary", "Scary-but-legitimate (hand-picked)"),
        ("dormant", "Dormant / finished libraries"))


def _rows(name: str, run_dir: Path = RUN2) -> list[dict]:
    with open(run_dir / name, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def pct_count(k: int, n: int) -> str:
    return f"{100 * k / n:.1f}% ({k}/{n})"


def short(r: dict, k_field: str) -> str:
    """'14.5% (17/117)', plus the rule-of-three bound when the CSV row has one: for one-line summaries."""
    k, n = int(r[k_field]), int(r["n"])
    r3 = f"; rule of three: at most {100 * float(r['rule_of_three']):.1f}%" if r.get("rule_of_three") else ""
    return f"{100 * k / n:.1f}% ({k}/{n}{r3})"


def _header(md: str) -> dict:
    """The key/value table at the top of RESULTS.md (Ruleset, Data snapshot, Seed, Test set, ...)."""
    out = {}
    for m in re.finditer(r"^\| ([^|]+?) \| \**([^|*]+?)\** \|$", md, re.M):
        out[m.group(1).strip()] = m.group(2).strip()
    return out


def _bucket_table(md: str, heading: str) -> list[tuple[str, int]]:
    i = md.index(heading)
    j = md.index("| bucket | count | examples |", i)
    out = []
    for line in md[j:].splitlines()[2:]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip("|").split("|")]
        out.append((cells[0], int(cells[1])))
    return out


def load(run_dir: Path = RUN2, results_md: Path = RESULTS_MD, error_md: Path = ERROR_MD) -> dict:
    recall = {(r["operating_point"], r["run"]): r for r in _rows("recall.csv", run_dir)}
    fp = {(r["set"], r["kind"]): r for r in _rows("false_positives_rates.csv", run_dir)}
    repo = {(r["set"], r["kind"]): r for r in _rows("repo_mode_false_positives.csv", run_dir)}
    base = {r["row"]: r for r in _rows("baseline.csv", run_dir)}
    counts = {r["category"]: r for r in _rows("counts.csv", run_dir)}
    md = results_md.read_text(encoding="utf-8")
    err = error_md.read_text(encoding="utf-8")
    osv = base["OSV-only (MAL- lookup alone)"]
    layered = [
        {"Layer": "Known-malware database (OSV MAL- lookup) alone",
         "Strict": pct_count(int(osv["count"]), int(osv["n"])), "Lenient": "n/a (no tiers)",
         "Meaning": "upper bound: the known-bad labels come from the same database (circular)"},
        {"Layer": "Behavior detectors only (never-seen malware)",
         "Strict": rate_from_row(recall[("strict", "headline")], "hits"),
         "Lenient": rate_from_row(recall[("lenient", "headline")], "hits"),
         "Meaning": "the fair measure of detecting new malware (headline)"},
        {"Layer": "Full system as the app runs (detectors + OSV)",
         "Strict": rate_from_row(recall[("strict", "with_osv")], "hits"),
         "Lenient": rate_from_row(recall[("lenient", "with_osv")], "hits"),
         "Meaning": "upper bound, same caveat (circular)"},
    ]
    fps = []
    for s, label in SETS:
        fps.append({"Set": label, "Strict / hard": rate_from_row(fp[(s, "hard")], "fp"),
                    "Lenient": rate_from_row(fp[(s, "lenient")], "fp")})
    repo_rows = [{"Set": label, "Hard": rate_from_row(repo[(s, "hard")], "fp"), "Soft": rate_from_row(repo[(s, "soft")], "fp")}
                 for s, label in SETS if (s, "soft") in repo]
    precision = []
    for op in ("strict", "lenient"):
        hits = int(recall[(op, "headline")]["hits"])
        f = int(fp[("known_good", op)]["fp"])
        precision.append({"Operating point": op,
                          "Precision": f"{100 * hits / (hits + f):.1f}% ({hits} hits, {f} false positives)",
                          "Class ratio": f"{recall[(op, 'headline')]['n']} known-bad : {fp[('known_good', op)]['n']} random known-good"})
    per_det = []
    for r in _rows("per_detector.csv", run_dir):
        if int(r["strict_hits"]) or int(r["lenient_hits"]) or int(r["strict_fp"]) or int(r["lenient_fp"]):
            per_det.append({"Detector": r["detector"], "Strict hits": int(r["strict_hits"]),
                            "Strict FPs": int(r["strict_fp"]), "Lenient hits": int(r["lenient_hits"]),
                            "Lenient FPs": int(r["lenient_fp"])})
    misses = _bucket_table(err, "## Known-bad items that are not a strict hit")
    fp_buckets = _bucket_table(err, "## Known-good and scary false positives (lenient)")
    hdr = _header(md)
    history = {k.split(" ran")[0]: int(v["count"]) for k, v in base.items() if k.endswith(" ran")}
    n_bad = int(recall[("strict", "headline")]["n"])
    return {"summary": SUMMARY, "layered": layered, "fps": fps, "repo_fps": repo_rows, "precision": precision,
            "per_detector": per_det, "misses": [{"Reason (bucket, run 2)": b, "Items": n} for b, n in misses if n],
            "fp_buckets": [{"Reason (bucket, run 2)": b, "Items": n} for b, n in fp_buckets if n],
            "header": hdr, "counts": counts, "history_ran": history, "n_known_bad": n_bad,
            "measured": [
                f"Test set: {counts['known_bad']['selected']} known-bad items selected, {counts['known_bad']['scored']} scored "
                f"({counts['known_bad']['unobtainable']} had no obtainable code); "
                f"{counts['known_good']['scored']} random known-good, {counts['scary']['scored']} scary-but-legitimate, "
                f"{counts['dormant']['scored']} dormant libraries scored.",
                f"Ruleset {hdr.get('Ruleset')} frozen before the test run (git tag ruleset-{hdr.get('Ruleset')}-frozen); "
                f"seed {hdr.get('Seed')}; data snapshot {hdr.get('Data snapshot (http_cache)')}; mode {hdr.get('Mode')}; "
                f"AI layer {hdr.get('AI layer')}.",
                f"No tuning on the test set (test set: {hdr.get('Test set')}); rule changes after viewing results go to "
                "benchmark/CHANGELOG.md and would mark it contaminated.",
                "Run 1 is superseded: Windows Defender had removed extracted sample files, which biased its recall "
                "downward; run 2 rescanned restored inputs with the same frozen ruleset.",
            ],
            "not_measured": [
                "Repository-mode known-bad recall (what the app runs): not measured; the known-bad items are package "
                "versions and samples without a repository. Repository mode was measured for false positives only.",
                "History-based detectors (publisher_change, revival_takeover, dependency_injection, release_delta) ran on "
                + ", ".join(f"{k} {v}" for k, v in history.items()) + f" of {n_bad} scored known-bad items: unproven.",
                "Upgrade check page and Additional signals: added after the freeze, unvalidated, no benchmark number.",
                "AI section: advisory, off in the benchmark, never changes a score.",
                "Learned combiner (experimental): a post-freeze research model, cross-validated on the same items the "
                "rules were frozen against (not a fresh held-out test); never used for the Trust score or a verdict.",
            ]}


def compact_verdict(label_base: str | None, run_dir: Path = RUN2) -> str:
    """One or two lines for the Trust check page, numbers read from the run-2 CSVs."""
    from pillars import (LABEL_FRAGILE, LABEL_HIGH_RISK, LABEL_KNOWN_MALICIOUS, LABEL_NO_FINDINGS, LABEL_NOT_ASSESSED,
                         LABEL_REVIEW)
    try:
        recall = {(r["operating_point"], r["run"]): r for r in _rows("recall.csv", run_dir)}
        fp = {(r["set"], r["kind"]): r for r in _rows("false_positives_rates.csv", run_dir)}
        repo = {(r["set"], r["kind"]): r for r in _rows("repo_mode_false_positives.csv", run_dir)}
    except (OSError, KeyError):
        return "Benchmark numbers are not available here."
    tail = " Repository-mode known-bad recall is not measured."
    if label_base == LABEL_REVIEW:
        return (f"In the benchmark, this verdict was given to {short(fp[('known_good', 'soft')], 'fp')} of random "
                f"known-good packages (artifact mode) and {short(repo[('known_good', 'soft')], 'fp')} in repository mode; "
                f"{short(recall[('lenient', 'headline')], 'hits')} of known-bad samples got at least a review-tier "
                "finding." + tail)
    if label_base in (LABEL_HIGH_RISK, LABEL_KNOWN_MALICIOUS):
        return (f"In the benchmark, a high-risk verdict was given to {short(fp[('known_good', 'hard')], 'fp')} of "
                f"random known-good packages; {short(recall[('strict', 'headline')], 'hits')} of known-bad samples got one "
                "without the OSV lookup." + tail)
    if label_base == LABEL_NO_FINDINGS:
        r = recall[("lenient", "headline")]
        k, n = int(r["n"]) - int(r["hits"]), int(r["n"])
        return (f"In the benchmark, {k} of {n} known-bad samples ({100 * k / n:.1f}%) also had no review-tier or "
                "high-risk finding: no findings does not mean safe." + tail)
    if label_base == LABEL_FRAGILE:
        return "This is a maintenance label; maintenance was not measured as a threat signal." + tail
    if label_base == LABEL_NOT_ASSESSED:
        return "No evidence pillar could run, so no benchmark number applies." + tail
    return "No benchmark operating point corresponds to this label." + tail


def readme_layered_table(d: dict | None = None) -> str:
    """The README headline table (markdown), from the same rows as the page; tests check the README contains it."""
    d = d or load()
    head = "| layer (known-bad samples, artifact mode) | strict | lenient | what it means |\n|---|---|---|---|\n"
    rows = []
    for r in d["layered"]:
        name = f"**{r['Layer']}: headline**" if "headline" in r["Meaning"] else r["Layer"]
        rows.append(f"| {name} | {r['Strict']} | {r['Lenient']} | {r['Meaning'].replace(' (headline)', '')} |")
    return head + "\n".join(rows) + "\n"


# ------------------------------------------------------------------ ruleset v2, fresh held-out set (branch ruleset-v2)
FRESH = ROOT / "benchmark" / "results" / "fresh"
FRESH_GOOD = ROOT / "benchmark" / "manifests" / "fresh" / "known_good.csv"
SUBSET_LABEL = {"a": "all fresh known-bad", "b": "excluding near-duplicates of the v2 development items"}


def load_v2(fresh_dir: Path = FRESH, good_manifest: Path = FRESH_GOOD) -> dict | None:
    """v1 vs v2 on the fresh held-out set, read from benchmark/results/fresh/*.csv (results_v2.py). None when the
    files are not there (main, or before the fresh runs)."""
    try:
        head = _rows("headline.csv", fresh_dir)[0]
        summ = {(r["ruleset"], r["subset"], r["metric"]): r for r in _rows("summary.csv", fresh_dir)}
        buck = {(r["ruleset"], r["subset"], r["bucket"], r["metric"]): r for r in _rows("per_bucket.csv", fresh_dir)}
        with open(good_manifest, newline="", encoding="utf-8") as fh:
            good = list(csv.DictReader(line for line in fh if not line.startswith("#")))
    except (OSError, IndexError, KeyError):
        return None
    h = head["subset"]
    other = "a" if h == "b" else "b"
    recall = []
    for s in (h, other):
        for op in ("strict", "lenient"):
            recall.append({"Metric": f"Recall, {op}: {SUBSET_LABEL[s]}" + (" (headline)" if s == h else ""),
                           "v1 (official, 2026.11.08-12)": rate_from_row(summ[("v1", s, f"recall_{op}")], "k"),
                           "v2 (2026.11.10-v2)": rate_from_row(summ[("v2", s, f"recall_{op}")], "k")})
    for kind, lab in (("hard", "Hard false positives, fresh random known-good"),
                      ("soft", "Soft false positives (Review recommended)")):
        recall.append({"Metric": lab, "v1 (official, 2026.11.08-12)": rate_from_row(summ[("v1", "all", f"fp_{kind}")], "k"),
                       "v2 (2026.11.10-v2)": rate_from_row(summ[("v2", "all", f"fp_{kind}")], "k")})
    buckets = []
    for b in ("npm install hook", "PyPI setup.py", "other"):
        g = {(k, m): buck[(k, h, b, m)] for k in ("v1", "v2") for m in ("recall_strict", "recall_lenient")}
        buckets.append({"Bucket": b, "v1 strict": rate_from_row(g[("v1", "recall_strict")], "k"),
                        "v2 strict": rate_from_row(g[("v2", "recall_strict")], "k"),
                        "v1 lenient": rate_from_row(g[("v1", "recall_lenient")], "k"),
                        "v2 lenient": rate_from_row(g[("v2", "recall_lenient")], "k")})
    hooks = sum(1 for r in good if (r.get("install_scripts") or "").strip())
    notes = [
        "v1 (ruleset 2026.11.08-12, run 2) remains the official headline above. Version 2 is a separate ruleset "
        "(branch ruleset-v2), developed after viewing run 2 and frozen (tag ruleset-2026.11.10-v2-frozen) before a "
        "fresh test set was scanned by both rulesets.",
        f"Headline subset: {SUBSET_LABEL[h]} ({head['near_duplicates']} near-duplicates removed; v2 strict recall "
        f"differs by {float(head['v2_strict_gap_pp']):.1f} points between the subsets, pre-registered threshold "
        f"{float(head['threshold_pp']):.0f}).",
        f"{hooks} of {len(good)} fresh known-good packages have an npm install script, so the fresh set gives no "
        "false-positive evidence for the new install-hook tracer; that evidence rests on the v1 install-hook packages "
        "checked before the freeze (development data).",
    ]
    return {"recall": recall, "buckets": buckets, "notes": notes, "headline_subset": h}


def readme_v2_table(v2: dict | None = None) -> str:
    """The README 'Version 2 (fresh test set)' table, from the same rows as the page; tests check the README has it."""
    v2 = v2 or load_v2()
    out = "| fresh test set | v1 (official) | v2 |\n|---|---|---|\n"
    return out + "\n".join(f"| {r['Metric']} | {r['v1 (official, 2026.11.08-12)']} | {r['v2 (2026.11.10-v2)']} |"
                           for r in v2["recall"]) + "\n"
