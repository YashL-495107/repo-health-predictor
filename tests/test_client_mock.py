"""Runs fetch_features end-to-end against a fake GitHub (no network needed)."""
import os, sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from github_client import GitHubClient, fetch_features
from scoring import compute_health_score

NOW = datetime.now(timezone.utc)
iso = lambda d: (NOW - timedelta(days=d)).isoformat().replace("+00:00", "Z")


def resp(data, status=200):
    r = MagicMock(); r.status_code = status; r.json.return_value = data; r.headers = {}; return r


def fake_get(url, params=None, timeout=None):
    p = url.replace("https://api.github.com", "")
    if p.endswith("/stats/commit_activity"):
        return resp([{"total": 5}] * 52)
    if p.endswith("/commits"):
        if params and params.get("until"):  # prior window
            return resp([{"author": {"login": f"u{i}"}, "commit": {"committer": {"date": iso(250)}}} for i in range(3)])
        return resp([{"author": {"login": f"u{i}"}, "commit": {"committer": {"date": iso(2 + i)}}} for i in range(6)]
                    + [{"author": {"login": "dependabot[bot]"}, "commit": {"committer": {"date": iso(9)}}}])
    if p == "/search/issues":
        return resp({"total_count": 40 if "is:open" in params["q"] else 160})
    if p.endswith("/issues"):
        return resp([{"created_at": iso(20), "closed_at": iso(10)}, {"created_at": iso(9), "closed_at": iso(8), "pull_request": {}}])
    if p.endswith("/pulls"):
        return resp([{"merged_at": iso(5)}, {"merged_at": None}, {"merged_at": iso(400)}])
    return resp({"full_name": "o/r", "has_issues": True, "stargazers_count": 10, "forks_count": 2, "archived": False,
                 "fork": False, "created_at": iso(900), "description": "d", "language": "Python"})


def test_fetch_features_end_to_end():
    c = GitHubClient(); c.session.get = fake_get
    f = fetch_features(c, "o", "r")
    assert f["days_since_last_commit"] == 2
    assert f["authors_180d"] == 6 and f["authors_prev_180d"] == 3  # bot excluded
    assert f["commits_last_12w"] == 60 and f["open_issues"] == 40 and f["closed_issues"] == 160
    assert f["median_days_to_close"] == 10.0 and f["merged_prs_180d"] == 1
    r = compute_health_score(f)
    assert 0 <= r["score"] <= 100
    print("score", r["score"], r["label"])


if __name__ == "__main__":
    test_fetch_features_end_to_end(); print("ok")
