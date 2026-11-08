"""UI text rules (2026-11-08): headline label, Trust-score disclaimer, sourced blast-radius numbers, no secret parts in
the UI, Gemini sections in one collapsed expander. Display only: no score, detector or ruleset change."""
import os
import re
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pillars import LABEL_NO_FINDINGS, LABEL_REVIEW, PARTIAL_NOTE  # noqa: E402
from ui_text import TRUST_DISCLAIMER, blast_display, headline_label  # noqa: E402

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


# 1. headline
def test_no_findings_only_when_the_table_is_empty():
    assert headline_label(LABEL_NO_FINDINGS, LABEL_NO_FINDINGS, 0) == "No findings"
    assert headline_label(LABEL_NO_FINDINGS, LABEL_NO_FINDINGS, 3) == \
        "No review-tier or high-risk findings (3 lower-level notes listed below)"
    assert headline_label(LABEL_NO_FINDINGS, LABEL_NO_FINDINGS, 1).endswith("(1 lower-level note listed below)")
    partial = f"{LABEL_NO_FINDINGS} ({PARTIAL_NOTE})"
    assert headline_label(partial, LABEL_NO_FINDINGS, 2) == \
        f"No review-tier or high-risk findings (2 lower-level notes listed below) ({PARTIAL_NOTE})"


def test_other_labels_are_unchanged():
    assert headline_label(LABEL_REVIEW, LABEL_REVIEW, 5) == LABEL_REVIEW


def test_trust_score_disclaimer_next_to_the_score():
    src = open(APP, encoding="utf-8").read()
    assert TRUST_DISCLAIMER == "not a safety guarantee" and "{TRUST_DISCLAIMER}</span>" in src


# 2. no secret parts
def test_app_never_displays_key_diagnostics():
    src = open(APP, encoding="utf-8").read()
    assert "describe_gemini_key" not in src and "ends …" not in src


# 3. blast radius
BR = {"package_name": "demo", "ecosystem": "PyPI", "package_name_guessed": False, "fetched_at": "2026-11-08",
      "total_dependents": 1234, "direct_dependents": 34, "indirect_dependents": 1200, "pinned_deps": 2, "total_deps": 5,
      "typosquat_alerts": [], "blast_score": 87.3, "tier": "Tier-1 Critical Infrastructure", "estimated_downstream_repos": 99999}


def test_sourced_dependents_show_their_source_and_date():
    d = blast_display({**BR, "dependents_source": "deps.dev"}, "o/demo")
    assert ("Dependents (deps.dev)", "1,234") in d["metrics"]
    assert "estimate from deps.dev, 2026-11-08" in d["caption"] and "estimate from deps.dev, 2026-11-08" in d["simulator"]
    text = " ".join([d["caption"], d["simulator"]] + [v for _n, v in d["metrics"]])
    assert "87" not in text and "Tier-1" not in text and "99,999" not in text   # heuristic score/tier never shown
    assert "update cycle" not in d["simulator"]


def test_unsourced_figures_are_hidden():
    d = blast_display({**BR, "dependents_source": None, "total_dependents": 0}, "o/demo")
    assert ("Dependents (deps.dev)", "not available") in d["metrics"] and d["simulator"] is None
    text = " ".join([d["caption"]] + [v for _n, v in d["metrics"]])
    assert not re.search(r"99,?999|87|Tier-1", text) and "no data source" in d["caption"]


def test_blast_radius_records_whether_deps_dev_answered():
    import blast_radius as B
    feats = {"stars": 10, "forks": 1, "full_name": "o/demo", "language": "Python"}
    with patch.object(B, "_deps_dev_dependents", return_value={}), patch.object(B, "confirm_typosquat", return_value=None):
        assert B.compute_repo_blast_radius(feats, {"level": "Low"})["dependents_source"] is None
    with patch.object(B, "_deps_dev_dependents", return_value={"total_dependents": 0, "direct_dependents": 0,
                                                              "indirect_dependents": 0}), \
            patch.object(B, "confirm_typosquat", return_value=None):
        assert B.compute_repo_blast_radius(feats, {"level": "Low"})["dependents_source"] == "deps.dev"


# 4. one collapsed expander for everything Gemini produces
def test_gemini_sections_are_in_one_collapsed_expander():
    src = open(APP, encoding="utf-8").read()
    i = src.index('st.expander("AI-generated, advisory, not part of the benchmark", expanded=False)')
    body = src[i:src.index('    if scan.get("code_scan") == "unavailable"', i)]
    for part in ("AI explanation of findings", "AI Migration Engine", "Executive Memo", "Drop-in Replacements"):
        assert part in body and src.count(part) == 1, part


def test_app_renders_with_the_new_layout():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from streamlit.testing.v1 import AppTest
    import test_app as T
    from github_client import GitHubClient
    with patch("github_client.fetch_features", T.fake_fetch), patch.object(GitHubClient, "__init__", T._fake_init):
        at = AppTest.from_file(APP, default_timeout=30).run()
        at.text_input(key="repo_input").set_value("https://github.com/o/r")
        at.button[0].click().run()
        assert not at.exception, at.exception
        assert any(TRUST_DISCLAIMER in md.value for md in at.markdown)
        assert [e.label for e in at.expander].count("AI-generated, advisory, not part of the benchmark") == 1
        assert not any("Gemini key from" in c.value or "chars" in c.value for c in at.caption)
