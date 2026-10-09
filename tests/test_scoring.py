import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from github_client import GitHubError, parse_repo
from scoring import compute_health_score, explain, score_recency, FACTORS


def base(**kw):
    f = dict(
        days_since_last_commit=3, commits_last_12w=80, commits_prev_per_12w=70, authors_180d=12,
        authors_prev_180d=10, has_issues=True, open_issues=50, closed_issues=950,
        issue_close_ratio=0.95, median_days_to_close=2.0, merged_prs_180d=40, has_pr_history=True,
        archived=False,
    )
    f.update(kw)
    return f


def test_weights_sum_to_100():
    assert sum(w for _, w in FACTORS.values()) == 100


def test_active_repo_is_healthy():
    r = compute_health_score(base())
    assert r["score"] >= 85 and r["label"] == "Healthy"


def test_dead_repo_is_abandoned():
    r = compute_health_score(base(days_since_last_commit=900, commits_last_12w=0, commits_prev_per_12w=0,
                                  authors_180d=0, authors_prev_180d=0, closed_issues=10, open_issues=300,
                                  issue_close_ratio=0.03, median_days_to_close=None, merged_prs_180d=0))
    assert r["score"] < 15 and r["label"] == "Likely abandoned"


def test_archived_is_capped():
    r = compute_health_score(base(archived=True))
    assert r["score"] <= 15 and r["label"].startswith("Archived")


def test_missing_factors_rescale_instead_of_penalising():
    r = compute_health_score(base(has_issues=False, has_pr_history=False))
    assert r["score"] >= 85
    assert any(x["score"] is None for x in r["factors"]) and r["notes"]


def test_recency_monotonic():
    assert score_recency(5) == 100 and score_recency(400) == 0
    assert score_recency(100) > score_recency(200) > score_recency(300)


def test_explain_mentions_weakest():
    r = compute_health_score(base(days_since_last_commit=500))
    assert "commit recency" in explain(r)


def test_parse_repo():
    assert parse_repo("https://github.com/psf/requests") == ("psf", "requests")
    assert parse_repo("https://github.com/psf/requests/issues/12") == ("psf", "requests")
    assert parse_repo("github.com/psf/requests.git") == ("psf", "requests")
    assert parse_repo("psf/requests") == ("psf", "requests")
    for bad in ["", "hello", "https://github.com/psf"]:
        try:
            parse_repo(bad); assert False, bad
        except GitHubError:
            pass


if __name__ == "__main__":
    for n, fn in list(globals().items()):
        if n.startswith("test_"):
            fn(); print("ok", n)
