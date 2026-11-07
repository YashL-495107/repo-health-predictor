"""Consumers of apply_gate's score/label: the batch CSV columns and the analyzer summary."""
import contextlib
import io

import analyze_scan_results as A
import scan_batch as SB
from detectors import RULESET_VERSION


def features(**kw):
    f = dict(days_since_last_commit=3, commits_last_12w=80, commits_prev_per_12w=70, authors_180d=12,
             authors_prev_180d=10, has_issues=True, open_issues=50, closed_issues=950, issue_close_ratio=0.95,
             median_days_to_close=2.0, merged_prs_180d=40, has_pr_history=True, archived=False,
             full_name="acme/demo", description="", topics=[])
    f.update(kw)
    return f


def test_batch_row_has_trust_maintenance_and_ruleset_columns(monkeypatch):
    monkeypatch.setattr(SB, "fetch_features", lambda c, o, n: features())
    scan = {"ran": False, "skip_reason": "too large", "known_malicious_count": 0, "high_risk_pattern_count": 0, "strong": 0}
    sec = {"level": "No unpatched issues found", "findings": [], "coverage": [],
           "checks": {"github_advisories": "ran", "osv_dependencies": "not_applicable", "own_package": "not_applicable",
                      "scorecard": "not_available"}}
    cols = SB.trust_columns(None, "acme", "demo", scan, sec)
    assert cols["ruleset_version"] == RULESET_VERSION
    assert cols["maintenance_score"] >= 85 and cols["maintenance_label"] == "Healthy"
    assert cols["trust_score"] == 100 and cols["partial"] is True and "Partial assessment" in cols["trust_label"]


def test_batch_trust_columns_degrade_to_empty_not_zero(monkeypatch):
    def boom(*a):
        raise RuntimeError("down")
    monkeypatch.setattr(SB, "fetch_features", boom)
    cols = SB.trust_columns(None, "acme", "demo", {"ran": False}, None)
    assert cols["trust_score"] is None and cols["maintenance_score"] is None
    assert cols["trust_label"] == "not assessed (RuntimeError)"


def test_analyzer_reports_trust_median(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text("repo,ran,strong,trust_score,maintenance_score,seconds\nacme/a,True,0,100,90,1\nacme/b,True,0,50,20,1\n")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        A.main(["--input", str(p)])
    out = buf.getvalue()
    assert "Trust score (n=2):   median 75; maintenance median 55" in out
    assert "Scanned, no findings:" in out
