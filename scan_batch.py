"""Calibration run: scan the repos from the backtest and measure how often the scanner raises STRONG findings.

    python scan_batch.py                       # reads data/backtest.csv, writes data/scan_results.csv

Why: a scanner that flags a large share of popular, well-run repos is too aggressive. This puts a number on it and
shows which rules cause it, so thresholds are tuned on evidence. Resumable: finished repos are skipped.
"""
import argparse
import os
import time
from collections import Counter

import pandas as pd
from dotenv import load_dotenv

from github_client import GitHubClient, parse_repo
from repo_scan import scan_repo


def summarise(df: pd.DataFrame) -> None:
    ran = df[df["ran"]]
    if "code_scan" in df:
        bad = int((df["code_scan"] == "unavailable").sum())
        if bad:
            print(f"\n*** WARNING: the Python code scan could NOT run for {bad} repos (Bandit unavailable: is the .venv active?). "
                  "Every code-finding number below is INVALID. ***")
    print(f"\n{len(df)} repos | scanned {len(ran)} | could not scan {len(df) - len(ran)} (too large, rate limit or error)")
    if ran.empty:
        return
    print(
        f"repos with >=1 STRONG finding: {(ran['strong'] > 0).sum()} ({(ran['strong'] > 0).mean():.0%})")
    print(
        f"repos with >=1 finding to review (medium/high, not strong): {(ran['review'] > 0).sum()} ({(ran['review'] > 0).mean():.0%})")
    if "code_high" in ran:
        print(
            f"repos with >=1 high-severity/high-confidence CODE finding: {(ran['code_high'] > 0).sum()} ({(ran['code_high'] > 0).mean():.0%})")
        print("distribution of code_high per repo:", ran["code_high"].describe(
            percentiles=[.5, .9, .95]).round(1).to_dict())
    for col, title in (("strong_rules", "Rules behind STRONG findings (repos affected)"),
                       ("review_rules", "Rules behind review findings (repos affected)")):
        c = Counter(r for cell in ran[col].dropna()
                    for r in set(str(cell).split(";")) if r)
        print(f"\n{title}:")
        for rule, n in c.most_common(10):
            print(f"  {n:3}  {rule}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/backtest.csv")
    ap.add_argument("--output", default="data/scan_results.csv")
    ap.add_argument("--sleep", type=float, default=1.0)
    args = ap.parse_args()
    load_dotenv()
    client = GitHubClient(os.getenv("GITHUB_TOKEN"))
    repos = pd.read_csv(args.input)["repo"].tolist()
    rows = pd.read_csv(args.output).to_dict(
        "records") if os.path.exists(args.output) else []
    done = {r["repo"] for r in rows}
    todo = [r for r in repos if r not in done]
    print(f"{len(done)} already scanned, {len(todo)} to go")
    for i, full in enumerate(todo, 1):
        owner, name = parse_repo(full)
        t0 = time.time()
        res = scan_repo(client, owner, name)
        fs = res["findings"]
        rows.append({"repo": full, "ran": res["ran"], "strong": res["strong"], "review": res["review"], "code_high": res["code_high"], "secrets_strong": res["secrets_strong"],
                     "ci_high": res["ci_high"], "code_scan": res["code_scan"], "n_findings": len(fs),
                     "strong_rules": ";".join(sorted({f["rule"].split(" (")[0] for f in fs if f["strong"]})),
                     "review_rules": ";".join(sorted({f["rule"].split(" (")[0] for f in fs if not f["strong"] and f["sev"] in ("High", "Medium")})),
                     "seconds": round(time.time() - t0, 1), "note": "" if res["ran"] else res["coverage"][0][:120]})
        pd.DataFrame(rows).to_csv(args.output, index=False)
        print(f"[{i}/{len(todo)}] {full}: ran={res['ran']} strong={res['strong']} code_high={res['code_high']} review={res['review']} bandit={res['code_scan']} ({rows[-1]['seconds']}s)")
        time.sleep(args.sleep)
    summarise(pd.DataFrame(rows))


if __name__ == "__main__":
    main()
