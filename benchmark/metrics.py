"""Benchmark metrics and the RESULTS.md / CSV generator (protocol: benchmark/README.md, sections 3-5).

Every number in RESULTS.md and the CSVs is computed here from the run files; nothing is typed by hand.

Definitions (fixed in the protocol):
  strict hit   at least one finding of tier high_risk or known_malicious
  lenient hit  at least one finding of tier review or above
  hard FP      a known-good item with a high_risk/known_malicious finding, or a label starting "DO NOT USE" or
               "High-risk patterns"
  soft FP      a known-good item labelled "Review recommended"
Only items with status "scored" count. Items whose code was not obtainable, or that could not be assessed, are
listed and excluded, never imputed. A not_assessed item is never counted as "no findings".

Headline numbers use the run WITHOUT the OSV MAL- lookup (--noosv); the with-OSV run is shown beside them and is
labelled circular for known-bad items (OSV MAL- advisories are how most known-bad items are labelled).

Usage:
  python benchmark/metrics.py --run benchmark/runs/artifact-test.jsonl --noosv benchmark/runs/artifact-test-noosv.jsonl
      [--nofrag benchmark/runs/artifact-test-nofrag.jsonl] [--repo-run benchmark/runs/repo-test.jsonl]
      [--replay benchmark/runs/artifact-replay.jsonl] [--out benchmark/RESULTS.md] [--csv-dir benchmark/results]
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
STRICT = ("known_malicious", "high_risk")
LENIENT = ("known_malicious", "high_risk", "review")
OPS = {"strict": STRICT, "lenient": LENIENT}
THREAT_LABELS = ("DO NOT USE", "High-risk patterns")
GOOD_SETS = ("known_good", "scary", "dormant")
SET_TITLES = {"known_good": "Random known-good (maintained)", "scary": "Hand-picked scary-but-legitimate",
              "dormant": "Dormant / finished libraries"}
Z = 1.959963984540054   # two-sided 95%


# ------------------------------------------------------------------ statistics

def wilson(k: int, n: int, z: float = Z) -> tuple[float, float] | None:
    """Wilson score interval for k successes in n trials (None when n == 0)."""
    if n <= 0:
        return None
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    lo, hi = max(0.0, centre - half), min(1.0, centre + half)
    return (0.0 if k == 0 else lo), (1.0 if k == n else hi)   # exact at the boundaries (no rounding residue)


def rule_of_three(n: int) -> float | None:
    """95% upper bound for a rate when 0 events were seen in n trials (3/n)."""
    return 3.0 / n if n > 0 else None


def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def rate_text(k: int, n: int, zero_rule: bool = False) -> str:
    """'12.3% (k/n; 95% CI 8.0-18.4%)', plus the rule-of-three bound when k == 0 and zero_rule."""
    if n == 0:
        return "n/a (n=0)"
    lo, hi = wilson(k, n)
    s = f"{pct(k / n)} ({k}/{n}; 95% CI {pct(lo)}-{pct(hi)})"
    if zero_rule and k == 0:
        s += f"; rule of three: at most {pct(rule_of_three(n))}"
    return s


def quantile(xs: list[float], q: float) -> float | None:
    if not xs:
        return None
    xs = sorted(xs)
    i = (len(xs) - 1) * q
    lo, hi = math.floor(i), math.ceil(i)
    return xs[lo] + (xs[hi] - xs[lo]) * (i - lo)


# ------------------------------------------------------------------ loading

def load_run(path: str | Path | None) -> dict[str, dict]:
    """{item_id: last record}. Missing file -> {}."""
    out = {}
    if not path or not Path(path).exists():
        return out
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            out[r["id"]] = r
    return out


def scored(r: dict) -> bool:
    return r.get("status") == "scored"


def tiers_hit(r: dict, tiers) -> bool:
    fb = r.get("findings_by_tier") or {}
    return any((fb.get(t) or 0) > 0 for t in tiers)


def detectors_fired(r: dict, tiers) -> list[str]:
    return sorted(d for d, v in (r.get("detectors") or {}).items() if v.get("tier") in tiers)


def label(r: dict) -> str:
    return str(r.get("label") or "")


def hard_fp(r: dict) -> bool:
    return tiers_hit(r, STRICT) or label(r).startswith(THREAT_LABELS)


def soft_fp(r: dict) -> bool:
    return label(r).startswith("Review recommended")


# ------------------------------------------------------------------ computations

def class_rows(run: dict, category: str, split: str = "test") -> list[dict]:
    return [r for r in run.values() if r.get("category") == category and r.get("split") == split]


def status_counts(rows: list[dict]) -> Counter:
    return Counter(r.get("status") for r in rows)


def recall_block(bad: list[dict]) -> dict:
    s = [r for r in bad if scored(r)]
    return {op: {"hits": sum(tiers_hit(r, t) for r in s), "n": len(s)} for op, t in OPS.items()}


def fp_block(good: list[dict]) -> dict:
    s = [r for r in good if scored(r)]
    out = {op: {"fp": sum(tiers_hit(r, t) for r in s), "n": len(s)} for op, t in OPS.items()}
    out["hard"] = {"fp": sum(hard_fp(r) for r in s), "n": len(s)}
    out["soft"] = {"fp": sum(soft_fp(r) and not hard_fp(r) for r in s), "n": len(s)}
    return out


def per_detector(bad: list[dict], good: list[dict]) -> list[dict]:
    """Per detector and operating point: hits on known-bad, FPs on the random known-good set, precision, recall."""
    bad_s, good_s = [r for r in bad if scored(r)], [r for r in good if scored(r)]
    names = sorted({d for r in bad_s + good_s for d in (r.get("detectors") or {})})
    rows = []
    for d in names:
        row = {"detector": d}
        for op, t in OPS.items():
            hits = sum(d in detectors_fired(r, t) for r in bad_s)
            fps = sum(d in detectors_fired(r, t) for r in good_s)
            row[f"{op}_hits"], row[f"{op}_misses"], row[f"{op}_fp"] = hits, len(bad_s) - hits, fps
            row[f"{op}_recall"] = hits / len(bad_s) if bad_s else None
            row[f"{op}_precision"] = hits / (hits + fps) if hits + fps else None
        row["n_bad"], row["n_good"] = len(bad_s), len(good_s)
        rows.append(row)
    return rows


def contribution(bad: list[dict], tiers) -> dict:
    """Which detectors fired on each known-bad hit; hits only one detector caught."""
    combos, only = Counter(), Counter()
    for r in bad:
        if not scored(r) or not tiers_hit(r, tiers):
            continue
        fired = detectors_fired(r, tiers)
        combos[" + ".join(fired) or "(evidence cap only)"] += 1
        if len(fired) == 1:
            only[fired[0]] += 1
    return {"combos": combos, "only": only}


def assessment(rows: list[dict]) -> list[dict]:
    """Per detector: share of scored items where it was not_assessed / not_applicable, with the top reasons."""
    s = [r for r in rows if scored(r)]
    names = sorted({d for r in s for d in (r.get("detectors") or {})})
    out = []
    for d in names:
        st = Counter((r["detectors"].get(d) or {}).get("status") for r in s)
        reasons = Counter(re.sub(r"\d+(?:\.[\w-]+)+", "<version>", r["detectors"][d].get("reason") or "")[:90] for r in s
                          if (r["detectors"].get(d) or {}).get("status") in ("not_assessed", "not_applicable"))
        out.append({"detector": d, "n": len(s), "ran": st.get("ran", 0), "not_assessed": st.get("not_assessed", 0),
                    "not_applicable": st.get("not_applicable", 0),
                    "top_reasons": "; ".join(f"{k} ({v})" for k, v in reasons.most_common(3))})
    return out


def times(rows: list[dict]) -> dict:
    xs = [float(r.get("elapsed_s") or 0) for r in rows if scored(r)]
    return {"n": len(xs), "median": quantile(xs, 0.5), "p95": quantile(xs, 0.95), "max": max(xs) if xs else None}


def why_miss(r: dict) -> str:
    parts = []
    rev = sorted({f"{f['detector']}: {f['rule'][:70]}" for f in r.get("findings") or [] if f.get("tier") == "review"})
    if rev:
        parts.append("review-tier only: " + "; ".join(rev[:3]))
    else:
        parts.append("no finding at review tier or above")
    na = sorted(d for d, v in (r.get("detectors") or {}).items() if v.get("status") == "not_assessed")
    if na:
        parts.append("not assessed: " + ", ".join(na))
    if (r.get("coverage") or {}).get("content_partial"):
        parts.append(str(r["coverage"].get("content_detail")))
    if r.get("limits_hit"):
        parts.append("limits hit: " + ", ".join(map(str, r["limits_hit"])))
    return " | ".join(parts)


def why_fp(r: dict, tiers) -> str:
    fs = [f for f in r.get("findings") or [] if f.get("tier") in tiers]
    items = [f"{f['detector']} [{f['tier']}] {f['rule'][:80]} @ {f.get('file') or '-'}:{f.get('line') or '-'}"
             + (" (fragility-escalated)" if f.get("fragility_amplified") else "") for f in fs[:4]]
    if not items and label(r).startswith(THREAT_LABELS + ("Review recommended",)):
        items = [f"label from evidence cap / security level: {r.get('limiting_reason')}"]
    return "; ".join(items)


# ------------------------------------------------------------------ report

def _cfg(run: dict) -> dict:
    for r in run.values():
        if r.get("run"):
            return r["run"]
    return {}


def _table(header: list[str], rows: list[list]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join("" if c is None else str(c).replace("|", "/") for c in row) + " |" for row in rows]
    return out


def build_report(main: dict, noosv: dict, nofrag: dict, repo: dict, replay: dict, split: str = "test") -> tuple[str, dict]:
    """Returns (markdown, csv_tables)."""
    cfg = _cfg(main) or _cfg(noosv)
    head = noosv if noosv else main
    head_name = "WITHOUT OSV MAL- lookup" if noosv else "WITH OSV MAL- lookup (no-OSV run missing: circular for known-bad)"
    L = ["# Benchmark results", "",
         "Generated by `benchmark/metrics.py` from the run files; no number in this file is typed by hand.", "",
         *_table(["", ""], [
             ["Ruleset", "**" + str(cfg.get("ruleset_version", "?")) + "**"],
             ["Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
             ["Data snapshot (http_cache)", cfg.get("snapshot", "?")],
             ["Seed", cfg.get("seed", "?")],
             ["Mode", cfg.get("mode", "?")],
             ["Test set", cfg.get("contamination", "?")],
             ["AI layer", cfg.get("ai_layer", "?")],
             ["Headline run", head_name]]), ""]
    tables: dict[str, list[dict]] = {}

    # counts per category
    L += ["## Items per category", ""]
    crow, ctab = [], []
    present = sorted({r.get("category") for r in head.values() if r.get("split") == split} - {"known_bad", *GOOD_SETS})
    for cat in ("known_bad",) + GOOD_SETS + tuple(present):
        rows = class_rows(head, cat, split)
        c = status_counts(rows)
        crow.append([cat, len(rows), c.get("scored", 0), c.get("unobtainable", 0), c.get("not_assessed", 0),
                     c.get("not_applicable", 0)])
        ctab.append(dict(zip(["category", "selected", "scored", "unobtainable", "not_assessed", "not_applicable"], crow[-1])))
    L += _table(["category", "in run", "scored", "code not obtainable", "not assessed", "not applicable"], crow)
    L += ["", "Only scored items enter the rates below. The others are listed at the end, never imputed.", ""]
    tables["counts"] = ctab

    # recall
    bad_h, bad_m = class_rows(head, "known_bad", split), class_rows(main, "known_bad", split)
    rb_h, rb_m = recall_block(bad_h), recall_block(bad_m)
    L += ["## Known-bad: recall", "",
          *_table(["operating point", f"headline ({'no OSV' if noosv else 'with OSV'})", "with OSV (circular)"],
                  [[op, rate_text(rb_h[op]["hits"], rb_h[op]["n"]), rate_text(rb_m[op]["hits"], rb_m[op]["n"])]
                   for op in OPS]), ""]
    tables["recall"] = [{"operating_point": op, "run": nm, "hits": b[op]["hits"], "n": b[op]["n"],
                         "recall": b[op]["hits"] / b[op]["n"] if b[op]["n"] else None,
                         "ci_low": (wilson(b[op]["hits"], b[op]["n"]) or (None, None))[0],
                         "ci_high": (wilson(b[op]["hits"], b[op]["n"]) or (None, None))[1]}
                        for nm, b in (("headline", rb_h), ("with_osv", rb_m)) for op in OPS]

    # false positives, per set
    L += ["## Known-good: false positives", "",
          "Each set is reported separately. The scary set is a hand-picked judgement sample, not random.", ""]
    fprows, fptab = [], []
    for cat in GOOD_SETS:
        fb = fp_block(class_rows(head, cat, split))
        for kind in ("strict", "lenient", "hard", "soft"):
            fprows.append([SET_TITLES[cat], kind, rate_text(fb[kind]["fp"], fb[kind]["n"], zero_rule=True)])
            fptab.append({"set": cat, "kind": kind, "fp": fb[kind]["fp"], "n": fb[kind]["n"],
                          "rate": fb[kind]["fp"] / fb[kind]["n"] if fb[kind]["n"] else None,
                          "ci_low": (wilson(fb[kind]["fp"], fb[kind]["n"]) or (None, None))[0],
                          "ci_high": (wilson(fb[kind]["fp"], fb[kind]["n"]) or (None, None))[1],
                          "rule_of_three": rule_of_three(fb[kind]["n"]) if fb[kind]["fp"] == 0 else None})
    L += _table(["set", "kind", "false-positive rate"], fprows)
    L += ["", "strict / lenient: an item with a finding at that operating point. hard: high_risk/known_malicious "
          "finding or a DO NOT USE / High-risk label. soft: labelled Review recommended (and not hard).", ""]
    tables["false_positives_rates"] = fptab

    # dormant labels (repo mode gives the maintenance pillar; artifact mode has none)
    for nm, run in (("artifact" if cfg.get("mode") == "artifact" else cfg.get("mode", "?"), head), ("repo", repo)):
        rows = [r for r in class_rows(run, "dormant", split) if scored(r)]
        if not rows:
            continue
        fr = sum(label(r).startswith("Fragile / unmaintained") for r in rows)
        th = sum(label(r).startswith(THREAT_LABELS) for r in rows)
        L += [f"Dormant libraries ({nm} mode): labelled Fragile / unmaintained {rate_text(fr, len(rows))}; "
              f"threat label {rate_text(th, len(rows), zero_rule=True)}.", ""]
    if not repo:
        L += ["Dormant libraries in repository mode: no repo-mode run given (the Fragile / unmaintained label needs "
              "the maintenance pillar, which artifact mode does not have).", ""]

    # precision
    good_rand = class_rows(head, "known_good", split)
    L += ["## Precision (at this benchmark's class ratio, not real-world prevalence)", ""]
    prow = []
    for op in OPS:
        tp = rb_h[op]["hits"]
        fp = fp_block(good_rand)[op]["fp"]
        prow.append([op, f"{pct(tp / (tp + fp)) if tp + fp else 'n/a'} ({tp} hits, {fp} FPs; "
                         f"{rb_h[op]['n']} known-bad : {fp_block(good_rand)[op]['n']} random known-good)"])
    L += _table(["operating point", "precision (headline run)"], prow) + [""]

    # per detector
    det = per_detector(bad_h, good_rand)
    L += ["## Per detector (headline run; FPs on the random known-good set)", ""]
    L += _table(["detector", "strict hits", "strict FP", "strict recall", "strict precision",
                 "lenient hits", "lenient FP", "lenient recall", "lenient precision"],
                [[d["detector"], d["strict_hits"], d["strict_fp"], pct(d["strict_recall"]), pct(d["strict_precision"]),
                  d["lenient_hits"], d["lenient_fp"], pct(d["lenient_recall"]), pct(d["lenient_precision"])]
                 for d in det])
    if det:
        L += ["", f"n = {det[0]['n_bad']} scored known-bad, {det[0]['n_good']} scored random known-good.", ""]
    tables["per_detector"] = det

    # contribution
    L += ["## Per-detector contribution (known-bad hits, headline run)", ""]
    for op, t in OPS.items():
        c = contribution(bad_h, t)
        L += [f"**{op}**: hits caught by one detector only: "
              + (", ".join(f"{k} {v}" for k, v in c["only"].most_common()) or "none"), ""]
        L += _table(["detectors that fired", "hits"], [[k, v] for k, v in c["combos"].most_common(15)]) + [""]
        tables[f"contribution_{op}"] = [{"detectors": k, "hits": v} for k, v in c["combos"].most_common()]

    # assessment
    all_rows = [r for r in head.values() if r.get("split") == split]
    ass = assessment(all_rows)
    L += ["## Detector coverage (share of scored items where a detector could not run)", ""]
    L += _table(["detector", "scored items", "ran", "not assessed", "not applicable", "top reasons"],
                [[a["detector"], a["n"], a["ran"], f"{a['not_assessed']} ({pct(a['not_assessed'] / a['n']) if a['n'] else 'n/a'})",
                  f"{a['not_applicable']} ({pct(a['not_applicable'] / a['n']) if a['n'] else 'n/a'})", a["top_reasons"]]
                 for a in ass]) + [""]
    tables["detector_coverage"] = ass

    # time
    L += ["## Scan time per item (seconds, scored items)", ""]
    trows = []
    for nm, run in (("headline", head), ("with OSV", main), ("repo", repo)):
        t = times([r for r in run.values() if r.get("split") == split])
        if t["n"]:
            trows.append([nm, t["n"], f"{t['median']:.1f}", f"{t['p95']:.1f}", f"{t['max']:.1f}"])
    L += _table(["run", "n", "median", "p95", "max"], trows) + [""]

    # ablations
    L += ["## Ablations", ""]
    abl = []
    for nm, run in (("with OSV MAL- lookup (circular)", main), ("without OSV MAL- lookup", noosv),
                    ("without fragility escalation", nofrag)):
        if not run:
            abl.append([nm, "not run", "", ""])
            continue
        rb = recall_block(class_rows(run, "known_bad", split))
        fb = fp_block(class_rows(run, "known_good", split))
        abl.append([nm, rate_text(rb["strict"]["hits"], rb["strict"]["n"]), rate_text(rb["lenient"]["hits"], rb["lenient"]["n"]),
                    rate_text(fb["hard"]["fp"], fb["hard"]["n"], zero_rule=True)])
    L += _table(["run", "strict recall", "lenient recall", "hard FP (random known-good)"], abl) + [""]

    # misses
    misses = []
    for r in sorted(bad_h, key=lambda r: r["id"]):
        if scored(r) and not tiers_hit(r, STRICT):
            misses.append({"id": r["id"], "ecosystem": r.get("ecosystem"), "package": r.get("package"),
                           "version": r.get("version"), "lenient_hit": tiers_hit(r, LENIENT), "label": label(r),
                           "why": why_miss(r)})
    L += ["## Misses and why", "", f"Known-bad items with no strict hit in the headline run: {len(misses)} "
          f"(of these, {sum(m['lenient_hit'] for m in misses)} have a review-tier finding, i.e. a lenient hit).", ""]
    L += _table(["item", "package", "version", "lenient hit", "why (automatic)"],
                [[m["id"], m["package"], m["version"], m["lenient_hit"], m["why"]] for m in misses]) + [""]
    tables["misses"] = misses

    # false positives
    fps = []
    for cat in GOOD_SETS:
        for r in sorted(class_rows(head, cat, split), key=lambda r: r["id"]):
            if not scored(r):
                continue
            kind = "hard" if hard_fp(r) else "soft" if soft_fp(r) else ("lenient-only" if tiers_hit(r, LENIENT) else None)
            if kind:
                fps.append({"id": r["id"], "set": cat, "kind": kind, "label": label(r),
                            "why": why_fp(r, STRICT if kind == "hard" else LENIENT)})
    L += ["## False positives and why", "", f"Known-good items with a finding or a non-neutral label: {len(fps)}.", ""]
    L += _table(["item", "set", "kind", "label", "findings (automatic)"],
                [[f["id"], f["set"], f["kind"], f["label"], f["why"]] for f in fps]) + [""]
    tables["false_positives"] = fps

    # replay
    if replay:
        L += ["## Replay / regression cases (NOT held-out evidence)", ""]
        L += _table(["case", "status", "label", "high_risk", "review", "detectors at review+"],
                    [[r["id"], r.get("status"), label(r), (r.get("findings_by_tier") or {}).get("high_risk"),
                      (r.get("findings_by_tier") or {}).get("review"), ", ".join(detectors_fired(r, LENIENT))]
                     for r in sorted(replay.values(), key=lambda r: r["id"])]) + [""]
        tables["replay"] = [{"id": r["id"], "status": r.get("status"), "label": label(r),
                             "detectors": " ".join(detectors_fired(r, LENIENT)),
                             "reason": r.get("not_assessed_reason") or ""} for r in replay.values()]

    # excluded
    excl = [r for r in head.values() if r.get("split") == split and not scored(r)]
    L += ["## Not scored (listed, never imputed)", "", f"{len(excl)} item(s).", ""]
    L += _table(["item", "category", "status", "reason"],
                [[r["id"], r.get("category"), r.get("status"), (r.get("not_assessed_reason") or "")[:140]]
                 for r in sorted(excl, key=lambda r: (r.get("category", ""), r["id"]))]) + [""]
    tables["not_scored"] = [{"id": r["id"], "category": r.get("category"), "status": r.get("status"),
                             "reason": r.get("not_assessed_reason") or ""} for r in excl]

    tables["items"] = [{"id": r["id"], "category": r.get("category"), "split": r.get("split"), "status": r.get("status"),
                        "label": label(r), "trust_score": r.get("trust_score"),
                        **{f"n_{k}": (r.get("findings_by_tier") or {}).get(k) for k in ("known_malicious", "high_risk", "review", "info")},
                        "strict_hit": tiers_hit(r, STRICT) if scored(r) else None,
                        "lenient_hit": tiers_hit(r, LENIENT) if scored(r) else None,
                        "elapsed_s": r.get("elapsed_s"), "ruleset_version": r.get("ruleset_version")}
                       for r in sorted(head.values(), key=lambda r: r["id"])]
    return "\n".join(L) + "\n", tables


def write_csvs(tables: dict, csv_dir: Path) -> list[Path]:
    csv_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for name, rows in tables.items():
        p = csv_dir / f"{name}.csv"
        cols = list(rows[0].keys()) if rows else ["empty"]
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        out.append(p)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Benchmark metrics and RESULTS.md")
    ap.add_argument("--run", required=True, help="main run (with OSV)")
    ap.add_argument("--noosv", default=None, help="ablation run without OSV MAL- (headline)")
    ap.add_argument("--nofrag", default=None, help="ablation run without fragility escalation")
    ap.add_argument("--repo-run", default=None, help="repository-mode run (dormant labels, soft FPs)")
    ap.add_argument("--replay", default=None, help="replay-case run (--split replay)")
    ap.add_argument("--split", default="test")
    ap.add_argument("--out", default=str(BENCH / "RESULTS.md"))
    ap.add_argument("--csv-dir", default=str(BENCH / "results"))
    a = ap.parse_args(argv)
    runs = [load_run(p) for p in (a.run, a.noosv, a.nofrag, a.repo_run, a.replay)]
    if not runs[0]:
        print(f"no records in {a.run}", file=sys.stderr)
        return 1
    versions = {r.get("ruleset_version") for run in runs for r in run.values()}
    if len(versions) > 1:
        print(f"REFUSING: run files mix ruleset versions {sorted(map(str, versions))}", file=sys.stderr)
        return 2
    md, tables = build_report(*runs, split=a.split)
    Path(a.out).write_text(md, encoding="utf-8")
    paths = write_csvs(tables, Path(a.csv_dir))
    print(f"wrote {a.out} and {len(paths)} CSV file(s) in {a.csv_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
