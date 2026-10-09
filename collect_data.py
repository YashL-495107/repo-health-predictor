"""Batch collector: scores every repo in repos.csv and writes data/dataset.csv.

    python collect_data.py                       # uses GITHUB_TOKEN from .env
    python collect_data.py --input repos.csv --output data/dataset.csv

Safe to stop and re-run: repos already present in the output file are skipped.
"""
import argparse
import os
import time

import pandas as pd
from dotenv import load_dotenv

from github_client import GitHubClient, GitHubError, RateLimitError, fetch_features, parse_repo
from scoring import compute_health_score


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="repos.csv")
    ap.add_argument("--output", default="data/dataset.csv")
    ap.add_argument("--sleep", type=float, default=2.0, help="seconds between repos (search API allows 30/min)")
    args = ap.parse_args()

    load_dotenv()
    client = GitHubClient(os.getenv("GITHUB_TOKEN"))
    if not client.authenticated:
        print("WARNING: no GITHUB_TOKEN set - you will hit the 60 requests/hour limit after ~7 repos.")

    repos = pd.read_csv(args.input)
    done = set()
    rows = []
    if os.path.exists(args.output):
        old = pd.read_csv(args.output)
        done = set(old["repo"])
        rows = old.to_dict("records")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    todo = [r for r in repos.to_dict("records") if r["repo"] not in done]
    print(f"{len(done)} already collected, {len(todo)} to go")

    for i, r in enumerate(todo, 1):
        try:
            owner, name = parse_repo(r["repo"])
            f = fetch_features(client, owner, name)
            res = compute_health_score(f)
        except RateLimitError as e:
            print(f"\nStopped: {e}\nRe-run later; finished repos are saved.")
            break
        except GitHubError as e:
            print(f"[{i}/{len(todo)}] {r['repo']}: SKIPPED - {e}")
            continue
        row = {k: v for k, v in f.items() if k not in ("weekly_commits", "description")}
        row.update(repo=r["repo"], category=r.get("category", ""), health_score=res["score"], label=res["label"])
        row.update({f"score_{x['key']}": x["score"] for x in res["factors"]})
        rows.append(row)
        pd.DataFrame(rows).to_csv(args.output, index=False)  # save after every repo
        print(f"[{i}/{len(todo)}] {r['repo']}: {res['score']:.0f} {res['label']}")
        time.sleep(args.sleep)

    print(f"Dataset has {len(rows)} repos -> {args.output}")


if __name__ == "__main__":
    main()
