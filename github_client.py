"""GitHub REST API client + feature extraction for the Repository Health Predictor.

fetch_features() turns one public repo into a flat dict of raw health signals
(commits, issues, PRs, contributors). scoring.py turns those into a health score.
"""
from __future__ import annotations

import re
import statistics
import time
from datetime import datetime, timedelta, timezone

import requests

API = "https://api.github.com"
TIMEOUT = 20
# issues closed faster than this are ignored when measuring responsiveness
INSTANT_CLOSE_HOURS = 1


class GitHubError(Exception):
    """Error with a message that is safe to show directly to the user."""


class RateLimitError(GitHubError):
    """GitHub API rate limit reached."""


_REPO_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?(?:github\.com/)?"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?(?:[/#?].*)?$"
)


def parse_repo(text: str) -> tuple[str, str]:
    """Accept 'owner/repo' or any github.com URL and return (owner, repo)."""
    m = _REPO_RE.match((text or "").strip())
    if not m or m.group(1).lower() == "github.com":
        raise GitHubError(
            "Enter a GitHub URL like https://github.com/psf/requests, or just owner/repo.")
    return m.group(1), m.group(2)


def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class GitHubClient:
    def __init__(self, token: str | None = None):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "repo-health-predictor",
            }
        )
        token = (token or "").strip()
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        self.authenticated = bool(token)

    def get(self, path: str, params: dict | None = None, allow: tuple = (200,)) -> requests.Response:
        try:
            r = self.session.get(API + path, params=params, timeout=TIMEOUT)
        except requests.RequestException as e:
            raise GitHubError(
                f"Could not reach GitHub (network problem): {e}") from e

        if r.status_code in allow:
            return r

        if r.status_code in (403, 429):
            if r.headers.get("X-RateLimit-Remaining") == "0" or r.status_code == 429:
                reset = int(r.headers.get("X-RateLimit-Reset", "0") or 0)
                mins = max(1, int((reset - time.time()) / 60) +
                           1) if reset else 1
                raise RateLimitError(
                    f"GitHub API rate limit reached (resets in about {mins} min). "
                    "Add a personal access token to raise the limit from 60 to 5,000 requests/hour."
                )
            raise GitHubError(
                "GitHub refused this request (403). The repository may be restricted.")
        if r.status_code == 401:
            raise GitHubError(
                "The GitHub token was rejected. Check it or remove it to use anonymous access.")
        if r.status_code in (404, 451):
            raise GitHubError(
                "Repository not found (it may not exist, or it is private).")
        if r.status_code not in allow:
            raise GitHubError(
                f"Unexpected response from GitHub (HTTP {r.status_code}).")
        return r

    def weekly_commits(self, owner: str, repo: str) -> list[int] | None:
        """Commits per week for the last 52 weeks. GitHub computes this lazily and answers
        202 the first time, so we retry a few times."""
        for _ in range(5):
            r = self.get(
                f"/repos/{owner}/{repo}/stats/commit_activity", allow=(200, 202, 204))
            if r.status_code == 200:
                data = r.json()
                return [w["total"] for w in data] if data else None
            if r.status_code == 204:
                return None
            time.sleep(2)
        return None

    def commits(self, owner, repo, since=None, until=None, pages=1) -> list[dict]:
        out: list[dict] = []
        for page in range(1, pages + 1):
            params = {"per_page": 100, "page": page}
            if since:
                params["since"] = since.isoformat()
            if until:
                params["until"] = until.isoformat()
            r = self.get(f"/repos/{owner}/{repo}/commits",
                         params, allow=(200, 409))
            if r.status_code == 409:  # empty repository
                return out
            batch = r.json()
            out += batch
            if len(batch) < 100:
                break
        return out

    def search_count(self, query: str) -> int:
        r = self.get("/search/issues", {"q": query, "per_page": 1})
        return int(r.json().get("total_count", 0))


def _author_id(c: dict) -> str | None:
    login = (c.get("author") or {}).get("login")
    if login:
        # ignore bots (dependabot etc.)
        return None if login.endswith("[bot]") else login
    return ((c.get("commit") or {}).get("author") or {}).get("email")


def fetch_features(client: GitHubClient, owner: str, repo: str) -> dict:
    """Pull raw health signals for one repository (~8 API calls)."""
    now = datetime.now(timezone.utc)
    d90, d180, d365 = (now - timedelta(days=n) for n in (90, 180, 365))

    meta = client.get(f"/repos/{owner}/{repo}").json()
    full = meta["full_name"]

    # ---- commits: recency, weekly activity, contributors ------------------------------
    recent = client.commits(owner, repo, since=d180, pages=2)
    prior = client.commits(owner, repo, since=now -
                           timedelta(days=360), until=d180, pages=1)
    if recent:
        last_commit = _dt(recent[0]["commit"]["committer"]["date"])
    else:
        latest = client.commits(owner, repo, pages=1)
        if not latest:
            raise GitHubError(
                "This repository has no commits yet, so there is nothing to score.")
        last_commit = _dt(latest[0]["commit"]["committer"]["date"])
    days_since_last_commit = max(0, (now - last_commit).days)

    weekly = client.weekly_commits(owner, repo)
    if weekly is None:  # fall back to an approximation from the commit sample
        weekly = [0] * 52
    commits_last_12w = sum(weekly[-12:])
    prev_per_12w = sum(weekly[:-12]) * 12 / max(1, len(weekly) - 12)
    authors_recent = {a for a in map(_author_id, recent) if a}
    authors_prior = {a for a in map(_author_id, prior) if a}

    # ---- issues -----------------------------------------------------------------------
    has_issues = bool(meta.get("has_issues"))
    open_issues = closed_issues = 0
    median_days = None
    closed_90d = 0
    instant_closes = 0
    if has_issues:
        open_issues = client.search_count(f"repo:{full} is:issue is:open")
        closed_issues = client.search_count(f"repo:{full} is:issue is:closed")
        items = client.get(
            f"/repos/{owner}/{repo}/issues",
            {"state": "closed", "sort": "updated",
                "direction": "desc", "per_page": 100},
        ).json()
        durations = []
        for i in items:
            if "pull_request" in i or not i.get("closed_at"):
                continue
            closed_at = _dt(i["closed_at"])
            hours = (closed_at - _dt(i["created_at"])).total_seconds() / 3600
            if hours < INSTANT_CLOSE_HOURS:
                # closed almost immediately: bot / template / spam clean-up, not real maintenance
                if closed_at >= d365:
                    instant_closes += 1
                continue
            if closed_at >= d365:
                durations.append(hours / 24)
            if closed_at >= d90:
                closed_90d += 1
        median_days = round(statistics.median(
            durations), 1) if durations else None
    total_issues = open_issues + closed_issues

    # ---- pull requests ----------------------------------------------------------------
    pulls = client.get(
        f"/repos/{owner}/{repo}/pulls",
        {"state": "closed", "sort": "updated",
            "direction": "desc", "per_page": 100},
    ).json()
    merged_180d = sum(1 for p in pulls if p.get(
        "merged_at") and _dt(p["merged_at"]) >= d180)

    return {
        "full_name": full,
        "description": meta.get("description"),
        "language": meta.get("language"),
        "stars": meta.get("stargazers_count", 0),
        "forks": meta.get("forks_count", 0),
        "created_at": meta.get("created_at"),
        "topics": meta.get("topics") or [],
        "archived": bool(meta.get("archived")),
        "is_fork": bool(meta.get("fork")),
        "has_issues": has_issues,
        "days_since_last_commit": days_since_last_commit,
        "commits_last_12w": commits_last_12w,
        "commits_prev_per_12w": round(prev_per_12w, 1),
        "weekly_commits": weekly,
        "authors_180d": len(authors_recent),
        "authors_prev_180d": len(authors_prior),
        "open_issues": open_issues,
        "closed_issues": closed_issues,
        "issue_close_ratio": round(closed_issues / total_issues, 3) if total_issues else None,
        "median_days_to_close": median_days,
        "issues_closed_90d": closed_90d,
        "instant_closes_ignored": instant_closes,
        "merged_prs_180d": merged_180d,
        "has_pr_history": len(pulls) > 0,
        "fetched_at": now.isoformat(timespec="seconds"),
    }
