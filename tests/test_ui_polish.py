"""UI polish (presentation only): partial-assessment badge, findings filter, JSON download without secrets, example
buttons, tabs and chart tooltips. No score, detector or ruleset change."""
import json
import os
import sys
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui_text import PARTIAL_BADGE, filter_findings, partial_badge, result_json  # noqa: E402

APP = os.path.join(ROOT, "app.py")


def _pillars(**status):
    return {n: {"status": status.get(n, "ran"), "score": None if status.get(n, "ran") != "ran" else 90}
            for n in ("Integrity", "Behavior", "Exposure")}


# partial-assessment badge
def test_badge_absent_for_a_complete_assessment():
    assert partial_badge({"partial": False, "partial_reasons": [], "pillars": _pillars()}, []) is None


def test_badge_when_partial_with_reasons_deduplicated():
    res = {"partial": True, "partial_reasons": ["Integrity: not assessed (release lookup failed)"],
           "pillars": _pillars(Integrity="not_assessed")}
    b = partial_badge(res, ["Integrity not assessed", "Integrity not assessed"])
    assert b["label"] == PARTIAL_BADGE == "Partial assessment"
    assert b["reason"] == "Integrity: not assessed (release lookup failed); Integrity not assessed"


def test_badge_from_gaps_only_and_partial_without_reasons():
    js = "JavaScript code not code-scanned (the code scan covers Python only; pattern checks still ran)"
    assert partial_badge({"partial": False, "pillars": _pillars()}, [js])["reason"] == js
    assert partial_badge({"partial": True, "pillars": _pillars()}, [])["reason"] == "some checks did not run"


# findings filter
ROWS = [{"sev": "High", "rule": "B602 subprocess shell", "file": "setup.py", "source": "Bandit"},
        {"sev": "Medium", "rule": "Exposed token", "file": "config/app.yml", "source": "Secrets"},
        {"sev": "Low", "rule": "pull_request_target", "file": ".github/workflows/ci.yml", "source": "CI"}]


def test_filter_by_severity_and_search():
    assert filter_findings(ROWS, [], "") == ROWS                               # nothing selected: everything
    assert [r["sev"] for r in filter_findings(ROWS, ["High", "Low"], None)] == ["High", "Low"]
    assert filter_findings(ROWS, None, "SETUP.PY") == [ROWS[0]]                # file, case-insensitive
    assert filter_findings(ROWS, None, "secrets") == [ROWS[1]]                 # source
    assert filter_findings(ROWS, None, "pull_request") == [ROWS[2]]            # rule
    assert filter_findings(ROWS, ["Medium"], "bandit") == []
    assert ROWS[0]["rule"] == "B602 subprocess shell"                          # input unchanged


# JSON download
def test_result_json_drops_credentials_and_redacts_secret_values():
    data = {"features": {"full_name": "o/r", "token": "ghp_x", "nested": [{"api_key": "k"}]},
            "scan": {"findings": [{"detail": "header uses ghp_SECRET123 here"}]},
            "intelligence": {"ai_report": {"note": "key AIzaKEY456 echoed"}, "gemini_key": "AIzaKEY456"},
            "result": {"trust_score": 92.0, "ok": True, "missing": None, "when": object()}}
    out = result_json(data, ["ghp_SECRET123", "AIzaKEY456", "", None])
    assert "ghp_SECRET123" not in out and "AIzaKEY456" not in out and "ghp_x" not in out and '"k"' not in out
    j = json.loads(out)
    assert j["result"]["trust_score"] == 92.0 and j["result"]["ok"] is True and j["result"]["missing"] is None
    assert j["scan"]["findings"][0]["detail"] == "header uses [redacted] here"
    assert "token" not in j["features"] and j["features"]["nested"] == [{}]
    assert isinstance(j["result"]["when"], str)


# the app
def test_app_tabs_badge_filter_download_and_examples():
    import test_app as T
    from streamlit.testing.v1 import AppTest
    from github_client import GitHubClient
    with patch("github_client.fetch_features", T.fake_fetch), patch.object(GitHubClient, "__init__", T._fake_init):
        at = AppTest.from_file(APP, default_timeout=30).run()
        assert [b.label for b in at.button if b.key and b.key.startswith("s_")] == \
            ["psf/requests", "lodash/lodash", "sqlmapproject/sqlmap"]
        next(b for b in at.button if b.label == "psf/requests").click().run()       # fills the box and runs the scan
        assert not at.exception, at.exception
        assert at.text_input(key="repo_input").value == "psf/requests"
        assert [t.label for t in at.tabs] == ["Overview", "Findings", "Supply chain", "Maintenance", "What was checked"]
        text = " ".join(md.value for md in at.markdown)
        for keep in ("indicators, not proof", "not a safety guarantee", "#### Four pillars", "#### Verdict",
                     "#### What was and was not checked"):
            assert keep in text, keep
        assert any("No findings does not mean safe" in c.value for c in at.caption)
        assert any(c.value.startswith("Ruleset ") and "indicators, not proof" in c.value for c in at.caption)
        assert [e.label for e in at.expander].count("AI-generated, advisory, not part of the benchmark") == 1
        if any("rh-badge" in md.value for md in at.markdown):                     # partial result: reason visible too
            assert any(c.value.startswith("Partial") for c in at.caption)
        if at.multiselect:                                                         # findings present: filter widgets
            assert at.multiselect(key="find_sev").label == "Severity"
            at.text_input(key="find_q").set_value("zzz-no-match").run()
            assert any(c.value.startswith("Showing 0 of") for c in at.caption)


def test_download_button_and_tooltips_in_source():
    src = open(APP, encoding="utf-8").read()
    assert 'download_button("Download result (JSON)", data=result_json(export, [token, user_token, gemini_key, gemini_key_input])' in src
    assert 'export = {**data, "receipt": receipt, "additional_signals": sig}' in src
    assert 'hovertemplate="%{theta}: %{r:.0f} / 100<extra></extra>"' in src                 # radar: factor and value
    assert 'hovertemplate="%{x} weeks ago: %{y} commits<extra></extra>"' in src             # commits per week
    assert 'hover_bar(bar, "/ 100")' in src                                                 # pillar bar
    assert 'LinkColumn("Open", display_text="open on GitHub")' in src


def test_findings_filter_widgets_in_the_app():
    """With findings in the scan: severity multiselect, search box, row count, and the GitHub link column kept."""
    import repo_scan
    import test_app as T
    from streamlit.testing.v1 import AppTest
    from github_client import GitHubClient
    def scan_with_findings(client, owner, repo):
        out = {"ran": True, "coverage": ["Content scan: fixture"], "strong": 0, "review": 0, "code_high": 0,
               "secrets_strong": 0, "ci_high": 0, "code_scan": "ran", "malware_proof": None, "known_malicious_count": 0,
               "high_risk_pattern_count": 0}
        out["findings"] = [
            {"sev": "Low", "source": "CI", "rule": "unpinned action", "file": ".github/workflows/ci.yml", "line": 3,
             "detail": "uses a tag", "fix": "pin to a commit", "url": "https://github.com/o/r/blob/x/ci.yml#L3"},
            {"sev": "Info", "source": "Bandit", "rule": "B101 assert", "file": "pkg/a.py", "line": 9,
             "detail": "assert used", "fix": "-", "url": "https://github.com/o/r/blob/x/pkg/a.py#L9"}]
        return out

    with patch("github_client.fetch_features", T.fake_fetch), patch.object(GitHubClient, "__init__", T._fake_init), \
            patch.object(repo_scan, "scan_repo", scan_with_findings):
        at = AppTest.from_file(APP, default_timeout=30).run()
        at.text_input(key="repo_input").set_value("o/r-polish-findings")
        at.button[0].click().run()
        assert not at.exception, at.exception
        ms = at.multiselect(key="find_sev")
        assert ms.label == "Severity" and list(ms.value) == ["Low", "Info"]
        assert any(c.value == "Showing 2 of 2 finding(s)." for c in at.caption)
        at.text_input(key="find_q").set_value("bandit").run()
        assert any(c.value == "Showing 1 of 2 finding(s)." for c in at.caption)
        frame = next(df.value for df in at.dataframe if "Open" in df.value.columns)
        assert list(frame["Rule"]) == ["B101 assert"]
        at.text_input(key="find_q").set_value("").run()
        at.multiselect(key="find_sev").set_value(["Low"]).run()
        frame = next(df.value for df in at.dataframe if "Open" in df.value.columns)
        assert list(frame["Level"]) == ["Low"] and frame["Open"].iloc[0].startswith("https://github.com/")


def test_title_subtitle_and_guessed_package_message():
    import test_app as T
    from streamlit.testing.v1 import AppTest
    from github_client import GitHubClient
    src = open(APP, encoding="utf-8").read()
    assert 'st.title("Repository & Package Trust Check")' in src
    assert ('st.caption("Trust score from code, package and supply-chain evidence. Indicators, not proof. '
            'Maintenance shown separately.")') in src
    with patch("github_client.fetch_features", T.fake_fetch), patch.object(GitHubClient, "__init__", T._fake_init):
        at = AppTest.from_file(APP, default_timeout=30).run()
        assert at.title[0].value == "Repository & Package Trust Check"
        at.text_input(key="repo_input").set_value("o/r-guessed-name")
        at.button[0].click().run()
        assert not at.exception, at.exception
        guessed = any("package name guessed from the repository name" in c.value for c in at.caption)
        msg = ("Not checked: no package manifest in the repository root. The npm/PyPI name shown above is guessed "
               "from the repository name and is not used for these checks.")
        assert guessed == any(i.value == msg for i in at.info)       # shown exactly when blast radius guessed a name
        assert guessed, "fixture repository has no root manifest, so blast radius guesses the name"
