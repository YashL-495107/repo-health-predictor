"""Health score: five explainable factors, each scored 0-100, combined with fixed weights.

If a factor does not apply (e.g. a repo with issues disabled) it is dropped and the
remaining weights are renormalised, so a repo is never punished for missing data.
Issue responsiveness is discounted when the repo has had no recent commits (see compute_health_score).
"""
from __future__ import annotations

import math

# name shown in the UI, weight (sums to 100)
FACTORS = {
    "recency": ("Commit recency", 25),
    "activity": ("Commit activity & trend", 20),
    "issues": ("Issue responsiveness", 20),
    "prs": ("Pull request activity", 15),
    "contributors": ("Contributor activity", 20),
}
HEALTHY, SLOWING = 70, 40  # label thresholds


def _clamp(x: float) -> float:
    return max(0.0, min(100.0, x))


def score_recency(days: int) -> float:
    """100 if committed within 14 days, falling linearly to 0 at 365 days."""
    if days <= 14:
        return 100.0
    return _clamp(100 * (365 - days) / (365 - 14))


def score_activity(recent_12w: int, prev_per_12w: float) -> float:
    """60% volume of commits in the last 12 weeks (log scale, 60+ = full marks),
    40% trend vs the earlier part of the year (a decline is penalised, growth is capped)."""
    level = _clamp(100 * math.log1p(recent_12w) / math.log1p(60))
    if prev_per_12w <= 0:
        trend = 100.0 if recent_12w > 0 else 0.0
    else:
        trend = _clamp(100 * recent_12w / prev_per_12w)
    return 0.6 * level + 0.4 * trend


def score_issues(f: dict) -> float | None:
    """60% how fast issues get closed (median days; <=3d full, >=365d zero),
    40% share of all issues that are closed. Issues closed within 1 hour of opening are
    ignored (bot/template/spam closes). None if the repo has no issues."""
    if not f["has_issues"] or (f["open_issues"] + f["closed_issues"]) == 0:
        return None
    d = f["median_days_to_close"]
    if d is None:
        responsiveness = 0.0  # issues exist but none were closed in the past year
    else:
        responsiveness = _clamp(
            100 * (1 - math.log(max(d, 3) / 3) / math.log(365 / 3)))
    return 0.6 * responsiveness + 0.4 * (f["issue_close_ratio"] or 0) * 100


def score_prs(f: dict) -> float | None:
    """Merged PRs in the last 180 days (log scale, 20+ = full marks). None if the repo
    has never used PRs (solo maintainers often push straight to main)."""
    if not f["has_pr_history"]:
        return None
    return _clamp(100 * math.log1p(f["merged_prs_180d"]) / math.log1p(20))


def score_contributors(recent: int, prior: int) -> float:
    """70% distinct human authors in the last 180 days (5+ = full marks),
    30% whether that number is holding up vs the previous 180 days."""
    if recent == 0:
        return 0.0
    level = min(recent, 5) / 5 * 100
    trend = 100.0 if prior == 0 else min(recent / prior, 1) * 100
    return 0.7 * level + 0.3 * trend


def label_for(score: float, archived: bool = False) -> str:
    if archived:
        return "Archived (read-only)"
    if score >= HEALTHY:
        return "Healthy"
    if score >= SLOWING:
        return "Slowing down"
    return "Likely abandoned"


def _details(f: dict) -> dict[str, str]:
    d = f["median_days_to_close"]
    return {
        "recency": f"Last commit {f['days_since_last_commit']} days ago",
        "activity": f"{f['commits_last_12w']} commits in the last 12 weeks "
        f"(earlier pace: {f['commits_prev_per_12w']:.0f} per 12 weeks)",
        "issues": (
            f"{f['closed_issues']} closed / {f['open_issues']} open; "
            + (f"median {d} days to close" if d is not None else "no real issue closes in the past year")
            + (f" ({f.get('instant_closes_ignored', 0)} instant closes ignored)" if f.get(
                "instant_closes_ignored") else "")
            if f["has_issues"]
            else "Issues are disabled"
        ),
        "prs": f"{f['merged_prs_180d']} PRs merged in the last 180 days" if f["has_pr_history"] else "No pull request history",
        "contributors": f"{f['authors_180d']} active authors in the last 180 days (previous 180 days: {f['authors_prev_180d']})",
    }


def compute_health_score(f: dict) -> dict:
    raw = {
        "recency": score_recency(f["days_since_last_commit"]),
        "activity": score_activity(f["commits_last_12w"], f["commits_prev_per_12w"]),
        "issues": score_issues(f),
        "prs": score_prs(f),
        "contributors": score_contributors(f["authors_180d"], f["authors_prev_180d"]),
    }
    details = _details(f)
    # A project nobody commits to cannot be "responsive": scale issue credit by how recently
    # code was committed (full credit if the last commit is within ~6 months, none at 1 year+).
    gate = min(1.0, raw["recency"] / 50)
    if raw["issues"] is not None and gate < 1:
        raw["issues"] *= gate
        details["issues"] += " - discounted: no recent commits"
    used = {k: v for k, v in raw.items() if v is not None}
    total_w = sum(FACTORS[k][1] for k in used)
    score = sum(v * FACTORS[k][1] for k, v in used.items()) / total_w

    notes = []
    if f["archived"]:
        score = min(score, 15.0)
        notes.append(
            "The owner has archived this repository (read-only), so the health score is capped.")
    for k in raw:
        if raw[k] is None:
            notes.append(
                f"{FACTORS[k][0]} was not scored ({details[k].lower()}); other weights were rescaled.")

    factors = [
        {
            "key": k,
            "name": FACTORS[k][0],
            "score": None if raw[k] is None else round(raw[k], 1),
            "weight": FACTORS[k][1],
            "effective_weight": round(100 * FACTORS[k][1] / total_w, 1) if k in used else 0,
            "detail": details[k],
        }
        for k in FACTORS
    ]
    score = round(score, 1)
    return {"score": score, "label": label_for(score, f["archived"]), "factors": factors, "notes": notes}


def explain(result: dict) -> str:
    """One plain-English sentence on what is driving the health score."""
    scored = [x for x in result["factors"] if x["score"] is not None]
    weak = [x for x in sorted(
        scored, key=lambda x: x["score"]) if x["score"] < 50][:2]
    strong = max(scored, key=lambda x: x["score"])
    if weak:
        weak_txt = " and ".join(
            f"{x['name'].lower()} ({x['detail'].lower()})" for x in weak)
        tail = f" Strongest signal: {strong['name'].lower()}." if strong["score"] >= 50 else ""
        return f"Health score is held back mainly by {weak_txt}.{tail}"
    return f"No weak spots: every scored factor is above 50. Strongest signal: {strong['name'].lower()} ({strong['detail'].lower()})."
