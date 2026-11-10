"""RESULTS_v2.md and benchmark/results/fresh/*.csv: v1 (2026.11.08-12) vs v2 (2026.11.10-v2) on the fresh held-out set.

Every number is computed here from the two run files and the pre-scan facts (manifests/fresh/fresh_facts.csv);
nothing is typed by hand. Definitions, subsets and the headline rule are those of benchmark/PREREG_v2.md:
  strict / lenient hit, hard / soft FP   as in metrics.py (protocol section 3)
  subset (a)  every scored fresh known-bad item
  subset (b)  (a) minus items flagged near-duplicate of the 76 dev items (fresh_facts.csv near_duplicate = yes)
  headline    (b) when v2's strict recall on (a) and (b) differ by at least HEADLINE_GAP_PP percentage points,
              otherwise (a); the other subset is always shown next to it
  buckets     npm install hook / PyPI setup.py / other (fresh_facts.csv, decided from the extracted text before scanning)

Usage:
  python benchmark/results_v2.py --v1 benchmark/runs/fresh/v1-artifact-fresh-noosv-nofrag.jsonl
      --v2 benchmark/runs/fresh/v2-artifact-fresh-noosv-nofrag.jsonl [--out benchmark/RESULTS_v2.md]
      [--csv-dir benchmark/results/fresh]
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BENCH = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH))

import bench_items  # noqa: E402
import metrics as M  # noqa: E402

HEADLINE_GAP_PP = 3.0
BUCKETS = ("npm install hook", "PyPI setup.py", "other")
FACTS = bench_items.MAN / "fresh" / "fresh_facts.csv"
EXPECTED = {"v1": "2026.11.08-12", "v2": "2026.11.10-v2"}


def fresh_rows(run: dict, category: str) -> list[dict]:
    return [r for r in run.values() if r.get("category") == category and r.get("split") == "fresh"]


def rate(k: int, n: int) -> dict:
    ci = M.wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 6) if n else None,
            "ci_low": round(ci[0], 6) if ci else None, "ci_high": round(ci[1], 6) if ci else None}


def recall(rows: list[dict], tiers) -> dict:
    s = [r for r in rows if M.scored(r)]
    return rate(sum(M.tiers_hit(r, tiers) for r in s), len(s))


def check_run(name: str, run: dict) -> dict:
    cfgs = {str(sorted((r.get("run") or {}).items())) for r in run.values()}
    cfg = next(iter(run.values())).get("run") or {} if run else {}
    problems = []
    if len(cfgs) > 1:
        problems.append("more than one run configuration in the file")
    if cfg.get("ruleset_version") != EXPECTED[name]:
        problems.append(f"ruleset {cfg.get('ruleset_version')} (expected {EXPECTED[name]})")
    if cfg.get("split") != "fresh" or cfg.get("osv") or cfg.get("fragility_escalation"):
        problems.append("not the headline configuration (--split fresh --no-osv --no-fragility-escalation)")
    if not (cfg.get("ruleset_check") or {}).get("verified"):
        problems.append("ruleset files not verified against the tag")
    if problems:
        raise SystemExit(f"{name} run refused: " + "; ".join(problems))
    return cfg


def build(v1: dict, v2: dict, facts: list[dict], extracted: list[dict] | None = None,
          good_manifest: list[dict] | None = None) -> tuple[list[str], dict]:
    c1, c2 = check_run("v1", v1), check_run("v2", v2)
    fx = {f["id"]: f for f in facts}
    runs = {"v1": v1, "v2": v2}
    bad = {k: fresh_rows(r, "known_bad") for k, r in runs.items()}
    good = {k: fresh_rows(r, "known_good") for k, r in runs.items()}
    no_facts = sorted({r["id"] for r in bad["v2"] if r["id"] not in fx})
    near = {i for i, f in fx.items() if f["near_duplicate"] == "yes"}

    def subset(rows, which):
        return rows if which == "a" else [r for r in rows if r["id"] not in near]

    summary = []
    for k in runs:
        for which in ("a", "b"):
            for op, t in M.OPS.items():
                summary.append({"ruleset": k, "set": "known_bad", "subset": which, "metric": f"recall_{op}",
                                **recall(subset(bad[k], which), t), "rule_of_three": None})
        fb = M.fp_block(good[k])
        for kind in ("hard", "soft", "lenient"):
            summary.append({"ruleset": k, "set": "known_good", "subset": "all", "metric": f"fp_{kind}",
                            **rate(fb[kind]["fp"], fb[kind]["n"]),
                            "rule_of_three": round(M.rule_of_three(fb[kind]["n"]), 6) if fb[kind]["fp"] == 0 and fb[kind]["n"] else None})
    get = {(s["ruleset"], s["subset"], s["metric"]): s for s in summary}
    a, b = get[("v2", "a", "recall_strict")], get[("v2", "b", "recall_strict")]
    gap = abs((a["rate"] or 0) - (b["rate"] or 0)) * 100
    head = "b" if gap >= HEADLINE_GAP_PP else "a"

    per_bucket = []
    for k in runs:
        for which in ("a", "b"):
            for bk in BUCKETS:
                rows = [r for r in subset(bad[k], which) if (fx.get(r["id"]) or {}).get("bucket") == bk]
                for op, t in M.OPS.items():
                    per_bucket.append({"ruleset": k, "subset": which, "bucket": bk, "metric": f"recall_{op}",
                                       **recall(rows, t)})
    per_det = M.per_detector([r for r in subset(bad["v2"], head)], good["v2"])
    only = {op: M.contribution(subset(bad["v2"], head), t)["only"] for op, t in M.OPS.items()}
    for row in per_det:
        row["strict_only_detector"] = only["strict"].get(row["detector"], 0)
        row["lenient_only_detector"] = only["lenient"].get(row["detector"], 0)
    ids = sorted({r["id"] for k in runs for r in bad[k] + good[k]})
    items = []
    for i in ids:
        r1, r2 = v1.get(i) or {}, v2.get(i) or {}
        f = fx.get(i) or {}
        items.append({"id": i, "category": (r2 or r1).get("category"), "ecosystem": (r2 or r1).get("ecosystem"),
                      "bucket": f.get("bucket", ""), "near_duplicate": f.get("near_duplicate", ""),
                      "near_duplicate_rules": f.get("near_duplicate_rules", ""),
                      "v1_status": r1.get("status"), "v2_status": r2.get("status"),
                      "v1_strict": M.scored(r1) and M.tiers_hit(r1, M.STRICT), "v1_lenient": M.scored(r1) and M.tiers_hit(r1, M.LENIENT),
                      "v2_strict": M.scored(r2) and M.tiers_hit(r2, M.STRICT), "v2_lenient": M.scored(r2) and M.tiers_hit(r2, M.LENIENT),
                      "v1_label": r1.get("label"), "v2_label": r2.get("label"),
                      "v2_detectors_strict": " + ".join(M.detectors_fired(r2, M.STRICT)) if M.scored(r2) else ""})
    both = [x for x in items if x["category"] == "known_bad" and x["v1_status"] == "scored" == x["v2_status"]
            and (head == "a" or x["near_duplicate"] != "yes")]
    paired = {op: Counter((x[f"v1_{op}"], x[f"v2_{op}"]) for x in both) for op in M.OPS}
    not_scored = [{"id": x["id"], "category": x["category"], "v1_status": x["v1_status"], "v2_status": x["v2_status"],
                   "v1_reason": (v1.get(x["id"]) or {}).get("not_assessed_reason"),
                   "v2_reason": (v2.get(x["id"]) or {}).get("not_assessed_reason")}
                  for x in items if x["v1_status"] != "scored" or x["v2_status"] != "scored"]

    def rt(s, zero=False):
        return M.rate_text(s["k"], s["n"], zero_rule=zero)
    L = ["# Results v2: fresh held-out set (v1 vs v2)", "",
         f"Generated by `benchmark/results_v2.py` on {datetime.now(timezone.utc):%Y-%m-%d} from the two run files and "
         "`manifests/fresh/fresh_facts.csv`; no number is typed by hand. Protocol: `benchmark/PREREG_v2.md` "
         "(committed and tagged before any fresh item was scanned). **v1 (`2026.11.08-12`) remains the official "
         "headline of the project**; this page compares both rulesets on data neither was developed on.", "",
         "| | v1 | v2 |", "|---|---|---|",
         f"| ruleset | `{c1['ruleset_version']}` | `{c2['ruleset_version']}` |",
         f"| ruleset files verified against tag | `{c1['ruleset_check']['tag']}` ({c1['ruleset_check']['files']} files, sha256 "
         f"`{c1['ruleset_check']['files_sha256'][:16]}`) | `{c2['ruleset_check']['tag']}` ({c2['ruleset_check']['files']} files, "
         f"sha256 `{c2['ruleset_check']['files_sha256'][:16]}`) |",
         f"| snapshot | {c1.get('snapshot')} | {c2.get('snapshot')} |",
         "| flags | artifact mode, `--no-osv --no-fragility-escalation` | same |", "",
         "## Items", ""]
    cnt = {k: Counter((r["category"], r["status"]) for r in bad[k] + good[k]) for k in runs}
    cats = sorted({c for k in cnt for c in cnt[k]})
    L += M._table(["class / status", "v1", "v2"], [[f"{c} / {s}", cnt["v1"].get((c, s), 0), cnt["v2"].get((c, s), 0)]
                                                  for c, s in cats])
    nd = Counter(f["near_duplicate"] for f in facts)
    if extracted is not None:
        st = Counter(r.get("status") for r in extracted)
        not_ext = [r for r in extracted if r.get("status") != "extracted"]
        L += ["", f"Fresh known-bad selection: {len(extracted)} ZIPs; {st.get('extracted', 0)} extracted and scanned; "
              f"{len(not_ext)} not extracted, so not run items and not scored: "
              + ("; ".join(f"{r['id']} ({r.get('reason') or r.get('status')})" for r in not_ext) or "none") + "."]
    if good_manifest is not None:
        hooks = [r["package"] for r in good_manifest if (r.get("install_scripts") or "").strip()]
        L += ["", f"**Fresh known-good install scripts: {len(hooks)} of {len(good_manifest)} packages declare an npm install "
              "script** (manifest column install_scripts" + (": " + ", ".join(hooks) if hooks else "") + "). "
              + ("So the fresh set gives no false-positive evidence for the install-hook tracer (`install_hook_target`): "
                 "its false-positive evidence rests on the v1 npm install-hook packages checked before the freeze "
                 "(\"v2 dev\", PREREG_v2.md section 2: esbuild, puppeteer, @swc/core, cypress traced with no finding; "
                 "core-js traced from its tarball, no finding), which are development data, not held-out evidence."
                 if not hooks else "")]
    L += ["", f"Near-duplicates of the 76 dev items (pre-scan, PREREG_v2.md section 4): {nd.get('yes', 0)} of {len(facts)} "
          "extracted fresh known-bad items. Rules that fired: " + (", ".join(f"{k} {v}" for k, v in Counter(
              r for f in facts for r in f["near_duplicate_rules"].split(";") if r).most_common()) or "none") + "."]
    if no_facts:
        L += ["", f"**{len(no_facts)} scored item(s) have no pre-scan facts row** (bucket / near-duplicate unknown): "
              + ", ".join(no_facts[:10])]
    L += ["", "## Headline: recall and false positives, side by side", "",
          f"Headline subset: **({head})** " + ("all scored fresh known-bad items" if head == "a" else
                                               "excluding near-duplicates of the 76 dev items")
          + f" (v2 strict recall differs by {gap:.1f} percentage points between (a) and (b); the pre-registered "
          f"threshold for switching to (b) is {HEADLINE_GAP_PP:.0f}).", ""]
    rows = []
    for which in (head, "b" if head == "a" else "a"):
        tag = "(a) all" if which == "a" else "(b) excl. near-duplicates"
        for op in ("strict", "lenient"):
            rows.append([f"recall {op}, {tag}" + (" **headline**" if which == head else ""),
                         rt(get[("v1", which, f"recall_{op}")]), rt(get[("v2", which, f"recall_{op}")])])
    for kind, lab in (("hard", "hard FP, fresh random known-good"), ("soft", "soft FP (Review recommended)"),
                      ("lenient", "any review-or-above finding, known-good")):
        rows.append([lab, rt(get[("v1", "all", f"fp_{kind}")], kind == "hard"), rt(get[("v2", "all", f"fp_{kind}")], kind == "hard")])
    L += M._table(["metric", "v1", "v2"], rows)
    g_both = [i for i in sorted({r["id"] for r in good["v2"]}) if M.scored(v1.get(i) or {}) and M.scored(v2.get(i) or {})]
    lab = [i for i in g_both if v1[i].get("label") != v2[i].get("label")]
    cnt_diff = [i for i in g_both if v1[i].get("findings_by_tier") != v2[i].get("findings_by_tier")]
    L += ["", f"Fresh known-good scored by both: {len(g_both)}; label different between v1 and v2: {len(lab)}"
          + (f" ({', '.join(lab)})" if lab else "") + f"; finding counts different: {len(cnt_diff)}"
          + (": " + "; ".join(f"{i} ({v1[i]['findings_by_tier']} -> {v2[i]['findings_by_tier']}, v2 detectors: "
                              f"{' + '.join(M.detectors_fired(v2[i], M.LENIENT))})" for i in cnt_diff) if cnt_diff else "") + "."]
    L += ["", "Paired on items scored by both rulesets (headline subset): "]
    for op in M.OPS:
        p = paired[op]
        L.append(f"- {op}: both hit {p.get((True, True), 0)}, v2 only {p.get((False, True), 0)}, v1 only "
                 f"{p.get((True, False), 0)}, neither {p.get((False, False), 0)}")
    L += ["", "## Recall per bucket", "", "Bucket from the extracted text before scanning (PREREG_v2.md section 5).", ""]
    for which in (head, "b" if head == "a" else "a"):
        L += [f"Subset ({which})" + (" (headline)" if which == head else ""), ""]
        trs = []
        for bk in BUCKETS:
            g = {(x["ruleset"], x["metric"]): x for x in per_bucket if x["subset"] == which and x["bucket"] == bk}
            trs.append([bk, rt(g[("v1", "recall_strict")]), rt(g[("v2", "recall_strict")]),
                        rt(g[("v1", "recall_lenient")]), rt(g[("v2", "recall_lenient")])])
        L += M._table(["bucket", "v1 strict", "v2 strict", "v1 lenient", "v2 lenient"], trs) + [""]
    L += ["## v2 per detector (headline subset; FP on the fresh random known-good set)", ""]
    L += M._table(["detector", "strict hits", "strict only-detector", "strict FP", "lenient hits", "lenient only-detector",
                   "lenient FP", "n bad", "n good"],
                  [[d["detector"], d["strict_hits"], d["strict_only_detector"], d["strict_fp"], d["lenient_hits"],
                    d["lenient_only_detector"], d["lenient_fp"], d["n_bad"], d["n_good"]] for d in per_det
                   if d["strict_hits"] or d["lenient_hits"] or d["strict_fp"] or d["lenient_fp"]])
    L += ["", "Detectors with no hit and no false positive are omitted; the full table is "
          "`results/fresh/per_detector_v2.csv`.", "", "## Not scored", ""]
    L += [f"{len(not_scored)} item(s) were not scored by at least one ruleset (listed in `results/fresh/not_scored.csv`); "
          "they are excluded, never imputed."]
    L += ["", "## What this does and does not show", "",
          "- Both rulesets were frozen and tagged before any fresh item was scanned; the runner checked every ruleset "
          "file against its tag and recorded the digest above.",
          "- v2 was developed on 76 items of run 2's error analysis (in-sample, optimistic); those items and every package "
          "of the v1 sets are excluded from the fresh set by construction, and campaign near-duplicates are reported "
          "separately as subset (b).",
          "- The fresh known-good set is a new random sample of popular packages; scary and dormant sets were not redrawn.",
          "- No AI layer, no OSV MAL- lookup, no fragility escalation (the headline configuration of v1)."]
    tables = {"headline": [{"subset": head, "v2_strict_gap_pp": round(gap, 2), "threshold_pp": HEADLINE_GAP_PP,
                            "near_duplicates": len(near & {r["id"] for r in bad["v2"]})}],
              "summary": summary, "per_bucket": per_bucket, "per_detector_v2": per_det, "items": items,
              "not_scored": not_scored}
    return L, tables


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--v1", required=True)
    ap.add_argument("--v2", required=True)
    ap.add_argument("--facts", default=str(FACTS))
    ap.add_argument("--out", default=str(BENCH / "RESULTS_v2.md"))
    ap.add_argument("--csv-dir", default=str(BENCH / "results" / "fresh"))
    a = ap.parse_args(argv)
    facts = bench_items.read_manifest(Path(a.facts))
    if not facts:
        raise SystemExit(f"no pre-scan facts in {a.facts}: run fresh_set.py facts first")
    lines, tables = build(M.load_run(a.v1), M.load_run(a.v2), facts,
                          bench_items.read_manifest(bench_items.MAN / "fresh" / "datadog_extracted.csv"),
                          bench_items.read_manifest(bench_items.MAN / "fresh" / "known_good.csv"))
    Path(a.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    for p in M.write_csvs(tables, Path(a.csv_dir)):
        print("wrote", p)
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
