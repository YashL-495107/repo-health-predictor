"""Backtest collector: rebuild each repo's commit signals AS THEY WERE a year ago, then record what happened.

    python backtest_collect.py                       # reads data/backtest_repos.csv, writes data/backtest.csv

Snapshot T = today - 365 days. Features use ONLY commits at or before T (no look-ahead).
Outcome: y_dead = 1 if the repo had NO commits in (T + 90 days, today] or is archived now.
(The 90-day grace gap means a repo that was still active just after T but went quiet soon after counts as dead.)
Safe to stop and re-run: finished repos are skipped. Repos that cannot be used are logged with a reason.
"""
import argparse
import csv
import os
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

import pandas as pd
from dotenv import load_dotenv

from github_client import GitHubClient, GitHubError, RateLimitError, _author_id, _dt, parse_repo
from scoring import FACTORS, score_activity, score_contributors, score_recency

SNAPSHOT_DAYS = 365
GRACE_DAYS = 90
PAGE_CAP = 6          # at most 600 pre-snapshot commits per repo
MAX_IDLE = 270        # must have committed within 270 days before T
MIN_AGE = 180         # must be at least 180 days old at T


class Skip(Exception):
    """Repo cannot be used for the backtest (reason is logged)."""


def snapshot_row(client, full_name: str, T: datetime, now: datetime) -> dict:
    owner, repo = parse_repo(full_name)
    meta = client.get(f"/repos/{owner}/{repo}").json()
    if meta.get("fork"):
        raise Skip("fork")
    if _dt(meta["created_at"]) > T - timedelta(days=MIN_AGE):
        raise Skip("too young at snapshot")

    # ---- features: commits at or before T ONLY -------------------------------------------
    pre = client.commits(owner, repo, since=T -
                         timedelta(days=360), until=T, pages=PAGE_CAP)
    items = [(_dt(c["commit"]["committer"]["date"]), _author_id(c))
             for c in pre]
    items = [(d, a) for d, a in items if d <= T]
    if items:
        last = max(d for d, _ in items)
    else:
        older = [_dt(c["commit"]["committer"]["date"])
                 for c in client.commits(owner, repo, until=T, pages=1)]
        older = [d for d in older if d <= T]
        if not older:
            raise Skip("no commits before snapshot")
        last = max(older)
    idle = (T - last).days
    if idle > MAX_IDLE:
        raise Skip("dormant at snapshot")

    t84, t180, t360, t364 = (T - timedelta(days=n)
                             for n in (84, 180, 360, 364))
    n12 = sum(1 for d, _ in items if d > t84)
    early = sum(1 for d, _ in items if t364 < d <= t84)
    # same convention as the live score
    prev_per_12w = early * 12 / 40
    recent = [a for d, a in items if d > t180 and a]
    prior = {a for d, a in items if t360 < d <= t180 and a}
    top_share = max(Counter(recent).values()) / len(recent) if recent else None
    truncated = len(pre) >= PAGE_CAP * 100 and min(d for d, _ in items) > t360

    # commit-only version of the live health score (issues/PRs cannot be rebuilt cheaply for a past date)
    r, a, c = score_recency(idle), score_activity(
        n12, prev_per_12w), score_contributors(len(set(recent)), len(prior))
    w = [FACTORS[k][1] for k in ("recency", "activity", "contributors")]
    score_t = (w[0] * r + w[1] * a + w[2] * c) / sum(w)

    # ---- outcome: what happened after T + grace -----------------------------------------
    start = T + timedelta(days=GRACE_DAYS)
    post = client.commits(owner, repo, since=start, pages=1)
    commits_after = sum(1 for x in post if _dt(
        x["commit"]["committer"]["date"]) > start)
    archived = bool(meta.get("archived"))

    return {"repo": full_name, "language": meta.get("language"), "snapshot": T.date().isoformat(),
            "idle_days_T": idle, "commits_12w_T": n12, "prev_per_12w_T": round(prev_per_12w, 2),
            "authors_180_T": len(set(recent)), "authors_prior_T": len(prior), "top_author_share_T": top_share,
            "age_days_T": (T - _dt(meta["created_at"])).days, "truncated": truncated,
            "score_commit_only_T": round(score_t, 2), "commits_after": commits_after,
            "archived_now": archived, "y_dead": int(archived or commits_after == 0)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/backtest_repos.csv")
    ap.add_argument("--output", default="data/backtest.csv")
    ap.add_argument("--skipped", default="data/backtest_skipped.csv")
    ap.add_argument("--sleep", type=float, default=0.7)
    args = ap.parse_args()
    load_dotenv()
    client = GitHubClient(os.getenv("GITHUB_TOKEN"))
    if not client.authenticated:
        print("WARNING: no GITHUB_TOKEN set; you will hit the 60 requests/hour limit almost immediately.")
    now = datetime.now(timezone.utc)
    T = now - timedelta(days=SNAPSHOT_DAYS)

    repos = pd.read_csv(args.input)
    rows, done = [], set()
    if os.path.exists(args.output):
        old = pd.read_csv(args.output)
        rows, done = old.to_dict("records"), set(old["repo"])
    if os.path.exists(args.skipped):
        done |= set(pd.read_csv(args.skipped)["repo"])
    todo = [r for r in repos.to_dict("records") if r["repo"] not in done]
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    print(
        f"snapshot date {T.date()} | {len(done)} already handled, {len(todo)} to go")

    for i, r in enumerate(todo, 1):
        try:
            row = snapshot_row(client, r["repo"], T, now)
        except Skip as e:
            with open(args.skipped, "a", newline="") as fh:
                w = csv.writer(fh)
                if fh.tell() == 0:
                    w.writerow(["repo", "reason"])
                w.writerow([r["repo"], str(e)])
            print(f"[{i}/{len(todo)}] {r['repo']}: skipped ({e})")
            continue
        except RateLimitError as e:
            print(f"\nStopped: {e}\nRe-run later; finished repos are saved.")
            break
        except GitHubError as e:
            print(
                f"[{i}/{len(todo)}] {r['repo']}: ERROR - {e} (will retry on next run)")
            continue
        row.update(stratum=r.get("stratum", ""))
        rows.append(row)
        pd.DataFrame(rows).to_csv(args.output, index=False)
        dead = sum(x["y_dead"] for x in rows)
        print(
            f"[{i}/{len(todo)}] {r['repo']}: y_dead={row['y_dead']} | usable {len(rows)}, dead {dead}")
        time.sleep(args.sleep)
    print(f"\n{len(rows)} usable repos -> {args.output}")


if __name__ == "__main__":
    main()
