"""Phase 1: Predictive Bus Factor, Contributor Monopoly & Maintainer Burnout Engine.

Integrates directly with github_client.py to analyze succession risk, knowledge
concentration (Gini & Shannon Entropy), silent lead-maintainer departures, and
issue response latency degradation.
"""
from __future__ import annotations

import math
import statistics
from collections import Counter
from datetime import datetime, timedelta, timezone

from github_client import GitHubClient, INSTANT_CLOSE_HOURS, _author_id, _dt


def _gini(counts: list[int]) -> float:
    """Compute Gini coefficient (0.0 = equal distribution, 1.0 = total monopoly)."""
    n = len(counts)
    if n <= 1 or sum(counts) == 0:
        return 1.0 if n == 1 else 0.0
    s = sorted(counts)
    total = sum(s)
    weighted_sum = sum((2 * i - n - 1) * val for i, val in enumerate(s, 1))
    return round(max(0.0, min(1.0, weighted_sum / (n * total))), 3)


def _normalized_entropy(counts: list[int]) -> float:
    """Normalized Shannon entropy (0.0 = monopoly, 1.0 = evenly spread across team)."""
    n = len(counts)
    total = sum(counts)
    if n <= 1 or total == 0:
        return 0.0
    entropy = -sum((c / total) * math.log(c / total) for c in counts if c > 0)
    return round(entropy / math.log(n), 3)


def _bus_factor(counts: list[int], threshold: float = 0.50) -> int:
    """Minimum number of authors whose combined commits exceed `threshold` (50%) of total work."""
    total = sum(counts)
    if total == 0:
        return 0
    acc = 0
    for idx, c in enumerate(sorted(counts, reverse=True), 1):
        acc += c
        if acc / total >= threshold:
            return idx
    return len(counts)


def fetch_succession_signals(client: GitHubClient, owner: str, repo: str) -> dict:
    """Fetch 365-day commit distributions and issue triage velocity using GitHubClient."""
    now = datetime.now(timezone.utc)
    d90 = now - timedelta(days=90)
    d180 = now - timedelta(days=180)
    d365 = now - timedelta(days=365)

    # Pull up to 300 commits over the last year for deep author distribution
    commits_1y = client.commits(owner, repo, since=d365, pages=3)
    if not commits_1y:
        commits_1y = client.commits(owner, repo, pages=1)

    author_commits_180d: Counter = Counter()
    author_commits_1y: Counter = Counter()
    author_last_seen: dict[str, datetime] = {}

    for c in commits_1y:
        aid = _author_id(c)
        if not aid:
            continue
        dt = _dt(c["commit"]["committer"]["date"])
        author_commits_1y[aid] += 1
        if dt >= d180:
            author_commits_180d[aid] += 1
        if aid not in author_last_seen or dt > author_last_seen[aid]:
            author_last_seen[aid] = dt

    # Analyze issue triage latency drift (recent 90d vs older 90-365d)
    closed_items = client.get(
        f"/repos/{owner}/{repo}/issues",
        {"state": "closed", "sort": "updated", "direction": "desc", "per_page": 100},
    ).json()

    recent_close_days: list[float] = []
    prior_close_days: list[float] = []
    for item in closed_items:
        if "pull_request" in item or not item.get("closed_at"):
            continue
        closed_at = _dt(item["closed_at"])
        created_at = _dt(item["created_at"])
        hours = (closed_at - created_at).total_seconds() / 3600
        if hours < INSTANT_CLOSE_HOURS:
            continue
        if closed_at >= d90:
            recent_close_days.append(hours / 24)
        elif closed_at >= d365:
            prior_close_days.append(hours / 24)

    # Check open issues for unanswered pile-up (0 comments)
    open_items = client.get(
        f"/repos/{owner}/{repo}/issues",
        {"state": "open", "sort": "created", "direction": "desc", "per_page": 50},
    ).json()
    real_open = [i for i in open_items if "pull_request" not in i]
    unanswered_open = sum(1 for i in real_open if i.get("comments", 0) == 0)

    return {
        "now": now,
        "author_commits_180d": author_commits_180d,
        "author_commits_1y": author_commits_1y,
        "author_last_seen": author_last_seen,
        "recent_close_days": recent_close_days,
        "prior_close_days": prior_close_days,
        "sampled_open_issues": len(real_open),
        "unanswered_open_issues": unanswered_open,
    }


def analyze_bus_factor(signals: dict) -> dict:
    """Turn raw succession signals into a Bus Factor report, Burnout Velocity, and Score."""
    now = signals["now"]
    active_counts = signals["author_commits_180d"] or signals["author_commits_1y"]
    counts_list = list(active_counts.values())
    total_commits = sum(counts_list)

    bf = _bus_factor(counts_list, threshold=0.50)
    gini = _gini(counts_list)
    entropy = _normalized_entropy(counts_list)

    # Identify top maintainer & check if they silently departed
    top_author, top_share, top_idle_days = "None", 1.0, 999
    silent_departure = False
    author_table = []

    if signals["author_commits_1y"]:
        top_author, top_1y_count = signals["author_commits_1y"].most_common(1)[0]
        total_1y = sum(signals["author_commits_1y"].values())
        top_share = round(top_1y_count / max(1, total_1y), 3)
        top_idle_days = max(0, (now - signals["author_last_seen"][top_author]).days)

        # If top author wrote >=40% of 1y commits, hasn't committed in 90+ days,
        # while others committed within the last 30 days -> Silent Departure!
        most_recent_any = min(
            (max(0, (now - dt).days) for dt in signals["author_last_seen"].values()),
            default=999,
        )
        if top_share >= 0.40 and top_idle_days >= 90 and most_recent_any <= 30:
            silent_departure = True

        for author, cnt in active_counts.most_common(10):
            last_dt = signals["author_last_seen"].get(author, now)
            author_table.append({
                "Contributor": author,
                "Commits": cnt,
                "Share (%)": round(100 * cnt / max(1, total_commits), 1),
                "Days Since Last Commit": max(0, (now - last_dt).days),
            })

    # Calculate Maintainer Burnout / Triage Latency Drift
    rec_d = signals["recent_close_days"]
    pri_d = signals["prior_close_days"]
    med_recent = round(statistics.median(rec_d), 1) if rec_d else None
    med_prior = round(statistics.median(pri_d), 1) if pri_d else None

    latency_drift_ratio = None
    if med_recent is not None and med_prior is not None and med_prior > 0:
        latency_drift_ratio = round(med_recent / max(1.0, med_prior), 2)

    unanswered_ratio = (
        round(signals["unanswered_open_issues"] / signals["sampled_open_issues"], 2)
        if signals["sampled_open_issues"] > 0
        else 0.0
    )

    # Determine Burnout Status
    if silent_departure:
        burnout_status = "Lead Maintainer Departed"
    elif latency_drift_ratio and latency_drift_ratio >= 2.5 and (med_recent or 0) > 14:
        burnout_status = "Severe Triage Slowdown (Burnout Risk)"
    elif unanswered_ratio >= 0.65 and signals["sampled_open_issues"] >= 10:
        burnout_status = "High Unanswered Issue Backlog"
    elif latency_drift_ratio and latency_drift_ratio >= 1.5 and (med_recent or 0) > 7:
        burnout_status = "Degrading Response Velocity"
    else:
        burnout_status = "Stable Triage Pace"

    # Compute 0-100 Succession & Continuity Score
    bf_score = {0: 0, 1: 25, 2: 55, 3: 80}.get(bf, 100 if bf >= 4 else 0)
    entropy_score = entropy * 100
    burnout_penalty = 0
    if silent_departure:
        burnout_penalty += 25
    if burnout_status == "Severe Triage Slowdown (Burnout Risk)":
        burnout_penalty += 20
    elif burnout_status in ("High Unanswered Issue Backlog", "Degrading Response Velocity"):
        burnout_penalty += 10

    raw_score = (0.65 * bf_score) + (0.35 * entropy_score) - burnout_penalty
    succession_score = round(max(0.0, min(100.0, raw_score)), 1)

    if succession_score < 35 or bf <= 1:
        risk_level = "Critical (Single Point of Failure)"
    elif succession_score < 60 or bf == 2:
        risk_level = "High (Concentrated Knowledge)"
    elif succession_score < 75:
        risk_level = "Moderate"
    else:
        risk_level = "Low (Healthy Governance)"

    findings = []
    if bf == 1:
        findings.append(
            f"Single point of failure: '{top_author}' accounts for {top_share * 100:.0f}% of commits "
            f"(Bus Factor = 1, Gini = {gini}). If this maintainer stops, development halts."
        )
    else:
        findings.append(
            f"Bus Factor is {bf} across {len(counts_list)} active contributor(s) "
            f"(Knowledge Entropy: {entropy:.2f}/1.00, Gini: {gini:.2f})."
        )

    if silent_departure:
        findings.append(
            f"Silent departure warning: Lead contributor '{top_author}' ({top_share * 100:.0f}% of 1yr work) "
            f"has not committed in {top_idle_days} days."
        )
    if latency_drift_ratio and latency_drift_ratio >= 1.8:
        findings.append(
            f"Triage slowdown: Median issue resolution slowed {latency_drift_ratio}x "
            f"(from {med_prior}d earlier in the year to {med_recent}d in the last 90 days)."
        )
    if unanswered_ratio >= 0.5 and signals["sampled_open_issues"] >= 10:
        findings.append(
            f"Maintainer bottleneck: {signals['unanswered_open_issues']} of the last "
            f"{signals['sampled_open_issues']} open issues have 0 responses."
        )

    return {
        "bus_factor": bf,
        "gini": gini,
        "entropy": entropy,
        "top_author": top_author,
        "top_author_share_pct": round(top_share * 100, 1),
        "top_author_idle_days": top_idle_days,
        "silent_departure": silent_departure,
        "median_close_recent_90d": med_recent,
        "median_close_prior": med_prior,
        "latency_drift_ratio": latency_drift_ratio,
        "unanswered_open_ratio": unanswered_ratio,
        "burnout_status": burnout_status,
        "succession_score": succession_score,
        "risk_level": risk_level,
        "author_table": author_table,
        "findings": findings,
    }


def run_bus_factor_analysis(client: GitHubClient, owner: str, repo: str) -> dict:
    """Single entry-point to call inside app.py."""
    signals = fetch_succession_signals(client, owner, repo)
    return analyze_bus_factor(signals)