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


# 5. "What drives the Trust score" (built only from values apply_gate / compute_trust already return)
def _res(results, maintenance=80.0, label="Healthy", caps=None, archived=False):
    from pillars import compute_trust
    t = compute_trust(results, {"score": maintenance, "label": label}, archived=archived, evidence_caps=caps)
    caps_out = [{"value": v, "rule": n, "tier": tr} for v, n, tr in caps or []]
    return {**t, "evidence_caps": caps_out, "maintenance_score": maintenance, "maintenance_label": label,
            "detectors": results}


def _det(detector, pillar, status="ran", findings=None, reason=None):
    from detectors.base import make_result
    return make_result(detector, pillar, status, findings or [], reason=reason)


def test_trust_drivers_pillar_table_and_limiting_marker():
    from ui_text import trust_drivers
    review = [{"tier": "review", "rule": "r", "file": "a.py", "line": 1, "detector": "behavior_patterns"}]
    res = _res([_det("release_delta", "Integrity"), _det("behavior_patterns", "Behavior", findings=review),
                _det("osv_advisories", "Exposure")])
    td = trust_drivers(res)
    rows = {r["Pillar"]: r for r in td["rows"]}
    assert [r["Pillar"] for r in td["rows"]] == ["Integrity", "Behavior", "Exposure"]
    assert rows["Behavior"]["Score"] == "92" and rows["Behavior"]["Limiting"] == "◀ limiting"
    assert rows["Integrity"]["Limiting"] == "" and rows["Integrity"]["Detectors ran"] == "1/1"
    assert td["caps_line"] == "No cap applied. Final score 92 = lowest pillar (Behavior 92)." and td["not_assessed"] == []


def test_trust_drivers_caps_and_not_assessed():
    from ui_text import trust_drivers
    res = _res([_det("release_delta", "Integrity", "not_assessed", reason="release lookup failed"),
                _det("tagless_release", "Integrity", "not_assessed", reason="repository refs not fetched"),
                _det("behavior_patterns", "Behavior"), _det("osv_advisories", "Exposure")],
               maintenance=30.0, label="Likely abandoned", caps=[(59, "offensive-security terms in name/description/topics", "review")])
    td = trust_drivers(res)
    rows = {r["Pillar"]: r for r in td["rows"]}
    assert rows["Integrity"]["Score"] == "not assessed" and rows["Integrity"]["Detectors ran"] == "0/2"
    assert "evidence cap 59: offensive-security terms in name/description/topics" in td["caps_line"]
    assert "maintenance ceiling 50: maintenance 30/100, below 40 (sets the final score, 50)" in td["caps_line"]
    assert td["caps_line"].endswith("Final score 50 set by maintenance ceiling 50: maintenance 30/100, below 40; lowest pillar: Behavior 100.")
    assert any(x.startswith("Integrity pillar:") for x in td["not_assessed"])
    assert "release_delta: release lookup failed" in td["not_assessed"]


def test_trust_drivers_binding_evidence_cap_and_archived():
    from ui_text import trust_drivers
    res = _res([_det("release_delta", "Integrity"), _det("behavior_patterns", "Behavior"), _det("osv_advisories", "Exposure")],
               maintenance=90.0, label="Archived (read-only)", archived=True,
               caps=[(49, "strong secret", "review")])
    td = trust_drivers(res)
    assert "evidence cap 49: strong secret (sets the final score, 49)" in td["caps_line"]
    assert "maintenance ceiling 50: repository archived;" in td["caps_line"] or "maintenance ceiling 50: repository archived." in td["caps_line"]
    assert "maintenance ceiling 50: repository archived (sets" not in td["caps_line"]


def test_trust_drivers_sqlmap_like_cap_sets_score_while_behavior_is_lowest_pillar():
    """Documented dev example (sqlmapproject/sqlmap, repo mode): Behavior limited by a credential-stealer pattern
    (one high-risk and one review finding: 100 - 35 - 8 = 57); evidence caps 59 (offensive terms) and 49 (high-risk
    pattern). The final 49 comes from the caps, not from the Behavior pillar score."""
    from ui_text import trust_drivers
    hr = [{"tier": "high_risk", "rule": "Credential-stealer pattern", "file": "lib/core/settings.py", "line": 1391,
           "detector": "behavior_patterns"},
          {"tier": "review", "rule": "Credential access: reads credential files", "file": "lib/core/common.py", "line": 7,
           "detector": "behavior_patterns"}]
    res = _res([_det("release_delta", "Integrity"), _det("behavior_patterns", "Behavior", findings=hr),
                _det("osv_advisories", "Exposure")],
               caps=[(59, "offensive-security terms in name/description/topics", "review"), (49, "high-risk pattern", "high_risk")])
    assert res["trust_score"] == 49 and res["pillars"]["Behavior"]["score"] == 57 and res["limiting_pillar"] == "Behavior"
    td = trust_drivers(res)
    assert {r["Pillar"]: r["Limiting"] for r in td["rows"]}["Behavior"] == "◀ limiting"
    line = td["caps_line"]
    assert "evidence cap 59: offensive-security terms in name/description/topics;" in line           # applies, not binding
    assert "evidence cap 49: high-risk pattern (sets the final score, 49)" in line
    assert "high-risk finding cap 49 (Behavior) (sets the final score, 49)" in line
    assert line.endswith("lowest pillar: Behavior 57.")


def test_assessment_gaps_next_to_the_score():
    from ui_text import assessment_gaps
    res = _res([_det("release_delta", "Integrity", "not_applicable", reason="no published package"),
                _det("behavior_patterns", "Behavior"), _det("osv_advisories", "Exposure")])
    gaps = assessment_gaps(res, "JavaScript", "no_python")
    assert gaps == ["Integrity not applicable",
                    "JavaScript code not code-scanned (the code scan covers Python only; pattern checks still ran)"]
    full = _res([_det("release_delta", "Integrity"), _det("behavior_patterns", "Behavior"), _det("osv_advisories", "Exposure")])
    assert assessment_gaps(full, "Python", "ran") == []


def test_trust_section_is_in_overview_and_maintenance_keeps_its_own_tab():
    """Tabbed layout (UI polish): "What drives the Trust score" closes the Overview tab; the renamed Maintenance section
    opens the Maintenance tab, so the two are still not mixed."""
    src = open(APP, encoding="utf-8").read()
    assert 'st.tabs(["Overview", "Findings", "Supply chain", "Maintenance", "What was checked"])' in src
    head = 'st.markdown("#### What drives the Trust score")'
    maint = 'st.markdown(f"#### Maintenance (separate from the Trust score; can cap it at {MAINTENANCE_CEILING} when fragile)")'
    i, f, m = src.index(head), src.index("    with t_find:"), src.index("    with t_maint:")
    assert src.index("    with t_over:") < i < f and "#### " not in src[i + len(head):f]   # last section of Overview
    assert src[m:].lstrip().split("\n", 1)[1].strip().startswith(maint)                    # first of Maintenance
    assert "What drives the maintenance score" not in src


def test_app_renders_the_trust_drivers_section():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from streamlit.testing.v1 import AppTest
    import test_app as T
    from github_client import GitHubClient
    with patch("github_client.fetch_features", T.fake_fetch), patch.object(GitHubClient, "__init__", T._fake_init):
        at = AppTest.from_file(APP, default_timeout=30).run()
        at.text_input(key="repo_input").set_value("https://github.com/o/r")
        at.button[0].click().run()
        assert not at.exception, at.exception
        assert [t.label for t in at.tabs] == ["Overview", "Findings", "Supply chain", "Maintenance", "What was checked"]
        over = [md.value for md in at.tabs[0].markdown if md.value.startswith("#### ")]
        maint = [md.value for md in at.tabs[3].markdown if md.value.startswith("#### ")]
        assert over[-1] == "#### What drives the Trust score"
        assert maint[0] == "#### Maintenance (separate from the Trust score; can cap it at 50 when fragile)"
        frames = [df.value for df in at.dataframe]
        assert any(list(f.columns) == ["Pillar", "Score", "Detectors ran", "Limiting"] and
                   list(f["Pillar"]) == ["Integrity", "Behavior", "Exposure"] for f in frames)
        assert any(md.value.startswith(("Caps applied:", "No cap applied")) for md in at.markdown)
        assert any(c.value.startswith("Not assessed:") for c in at.caption)


def test_forks_wording_and_partial_colour():
    src = open(APP, encoding="utf-8").read()
    assert "Forks with newer commits than upstream" in src and "akeover Forks" not in src
    intel = open(os.path.join(os.path.dirname(APP), "intelligence.py"), encoding="utf-8").read()
    assert "takeover forks" not in intel.lower()
    assert "trust_color = NEUTRAL_COLOR" in src and 'st.caption(_md_escape("Partial: "' in src
