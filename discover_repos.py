"""Pick repositories for the backtest and write data/backtest_repos.csv.

Design (case-control sampling, so the report must say so):
  snapshot date T = today - 365 days.
  stratum A  "kept going":  last push within the past 30 days
  stratum B  "went quiet":  last push between T and T+80 days
Every sampled repo therefore WAS active at T; the question is which of them stopped.
Because we sample on the outcome, AUC is meaningful but prevalence/accuracy are not.

    python discover_repos.py                 # uses GITHUB_TOKEN from .env
    python discover_repos.py --per-stratum 17
"""
import argparse
import os
import random
import time
from datetime import datetime, timedelta, timezone

import pandas as pd
from dotenv import load_dotenv

from github_client import GitHubClient, GitHubError

LANGS = ["python", "javascript", "typescript",
         "go", "rust", "java", "ruby", "php", "c++"]


def build_queries(today, lang):
    t = today - timedelta(days=365)
    def d(x): return x.strftime("%Y-%m-%d")
    base = f"language:{lang} stars:50..3000 fork:false created:<{d(t - timedelta(days=180))}"
    return {"A": f"{base} archived:false pushed:>{d(today - timedelta(days=30))}",
            "B": f"{base} pushed:{d(t)}..{d(t + timedelta(days=80))}"}


def search(client, q, pages=2, sleep=2.5):
    out = []
    for page in range(1, pages + 1):
        r = client.get("/search/repositories",
                       {"q": q, "sort": "stars", "per_page": 100, "page": page})
        items = r.json().get("items", [])
        out += [i["full_name"] for i in items]
        time.sleep(sleep)
        if len(items) < 100:
            break
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="data/backtest_repos.csv")
    ap.add_argument("--per-stratum", type=int, default=17,
                    help="repos per language per stratum")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    load_dotenv()
    client = GitHubClient(os.getenv("GITHUB_TOKEN"))
    rng = random.Random(args.seed)
    today = datetime.now(timezone.utc)
    rows, seen = [], set()
    for lang in LANGS:
        for stratum, q in build_queries(today, lang).items():
            try:
                pool = [r for r in search(client, q) if r not in seen]
            except GitHubError as e:
                print(f"{lang}/{stratum}: SKIPPED - {e}")
                continue
            pick = rng.sample(pool, min(args.per_stratum, len(pool)))
            for r in pick:
                seen.add(r)
                rows.append({"repo": r, "language": lang, "stratum": stratum})
            print(f"{lang:11} {stratum}: found {len(pool):3} -> kept {len(pick)}")
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    df = pd.DataFrame(rows)
    df.to_csv(args.output, index=False)
    print(
        f"\n{len(df)} repos -> {args.output}\n{df['stratum'].value_counts().to_string()}")


if __name__ == "__main__":
    main()
