"""Pillar scoring and the headline Trust score (pillars.py), plus the apply_gate wiring."""
from detectors.base import enrich, make_result
from pillars import (LABEL_FRAGILE, LABEL_HIGH_RISK, LABEL_KNOWN_MALICIOUS, LABEL_NO_FINDINGS, LABEL_NOT_ASSESSED,
                     LABEL_REVIEW, MAINTENANCE_CEILING, PARTIAL_NOTE, compute_trust, score_pillar)
from scoring import compute_health_score

ALL = [("release_vs_git", "Integrity"), ("decoded_payload", "Behavior"), ("behavior_patterns", "Behavior"),
       ("osv_known_malicious", "Exposure"), ("osv_advisories", "Exposure")]


def finding(tier, file="a.py", line=1, rule="rule"):
    return enrich({"sev": "High", "source": "test", "rule": rule, "file": file, "line": line, "detail": "",
                   "fix": "", "url": None, "strong": tier != "review"}, "test", tier)


def results(overrides=None, statuses=None):
    """All detectors ran with no findings, except the ones overridden."""
    overrides, statuses = overrides or {}, statuses or {}
    out = []
    for det, pillar in ALL:
        st = statuses.get(det, "ran")
        out.append(make_result(det, pillar, st, overrides.get(det, []), reason="no published package"
                               if st == "not_applicable" else "lookup failed"))
    return out


def healthy():
    return {"score": 95.0, "label": "Healthy"}


def dormant_features(**kw):
    f = dict(days_since_last_commit=730, commits_last_12w=0, commits_prev_per_12w=0, authors_180d=0,
             authors_prev_180d=0, has_issues=True, open_issues=3, closed_issues=40, issue_close_ratio=0.93,
             median_days_to_close=4.0, merged_prs_180d=0, has_pr_history=True, archived=False)
    f.update(kw)
    return f


def test_healthy_repo_with_confirmed_threat_is_not_trusted():
    t = compute_trust(results({"osv_known_malicious": [finding("known_malicious", file="", rule="OSV MAL-2026-1")]}),
                      healthy())
    assert t["trust_score"] <= 15
    assert t["label"] == LABEL_KNOWN_MALICIOUS
    assert t["limiting_pillar"] == "Exposure"


def test_finished_dormant_library_is_fragile_not_a_threat():
    m = compute_health_score(dormant_features())
    assert m["score"] < 40   # two years without commits lands in the "Likely abandoned" band
    t = compute_trust(results(), m)
    assert t["trust_score"] >= MAINTENANCE_CEILING
    assert t["label"] == LABEL_FRAGILE
    assert t["limiting_pillar"] == "Maintenance" and "not a threat signal" in t["limiting_reason"]


def test_dormant_library_with_high_risk_integrity_finding_is_capped_by_the_finding():
    m = compute_health_score(dormant_features())
    t = compute_trust(results({"release_vs_git": [finding("high_risk", file="pkg/__init__.py", line=3,
                                                           rule="Release artifact AST drift")]}), m)
    assert t["trust_score"] < MAINTENANCE_CEILING
    assert t["limiting_pillar"] == "Integrity" and t["limiting_kind"] == "pillar"
    assert "Release artifact AST drift" in t["limiting_reason"]
    assert t["label"] == LABEL_HIGH_RISK


def test_archived_repo_with_no_findings_is_capped_at_50_and_no_lower():
    m = compute_health_score(dormant_features(archived=True, days_since_last_commit=10, commits_last_12w=30,
                                              commits_prev_per_12w=30, authors_180d=5, authors_prev_180d=5))
    assert m["score"] <= 15   # scoring.py caps archived repos at 15
    t = compute_trust(results(), m, archived=True)
    assert t["trust_score"] == MAINTENANCE_CEILING
    assert t["label"] == LABEL_FRAGILE


def test_pillar_all_not_assessed_is_none_and_adds_partial_note():
    t = compute_trust(results(statuses={"decoded_payload": "not_assessed", "behavior_patterns": "not_assessed"}), healthy())
    assert t["pillars"]["Behavior"]["score"] is None and t["pillars"]["Behavior"]["status"] == "not_assessed"
    assert t["partial"] and t["label"] == f"{LABEL_NO_FINDINGS} ({PARTIAL_NOTE})"
    assert t["trust_score"] == 100   # headline from the assessed pillars, but never shown without the note


def test_pillar_all_not_applicable_is_none_without_implying_failure():
    t = compute_trust(results(statuses={"release_vs_git": "not_applicable"}), healthy())
    p = t["pillars"]["Integrity"]
    assert p["score"] is None and p["status"] == "not_applicable" and p["reason"] == "no published package"
    assert not t["partial"] and t["label"] == LABEL_NO_FINDINGS


def test_no_pillar_assessed_gives_not_assessed():
    t = compute_trust(results(statuses={d: "not_assessed" for d, _ in ALL}), healthy())
    assert t["trust_score"] is None and t["label"] == LABEL_NOT_ASSESSED


def test_partial_coverage_never_yields_a_bare_100():
    rs = results()
    rs[1] = make_result("decoded_payload", "Behavior", "ran", [], coverage="partial",
                        coverage_detail="partial scan: 1500 of 2300 text files")
    t = compute_trust(rs, healthy())
    assert t["trust_score"] == 100 and t["partial"] and PARTIAL_NOTE in t["label"]
    assert "partial scan: 1500 of 2300 text files" in t["pillars"]["Behavior"]["coverage"]["text"]


def test_evidence_cap_is_named_as_evidence_rule():
    t = compute_trust(results(), healthy(), evidence_caps=[(49, "strong secret", "review")])
    assert t["trust_score"] == 49 and t["limiting_kind"] == "evidence" and t["limiting_pillar"] is None
    assert t["limiting_reason"] == "capped by evidence rule: strong secret"
    assert t["label"] == LABEL_REVIEW


def test_known_malicious_evidence_cap_sets_the_label_even_without_a_detector_finding():
    t = compute_trust(results(), healthy(), evidence_caps=[(15, "known malicious indicator", "known_malicious")])
    assert t["trust_score"] == 15 and t["label"] == LABEL_KNOWN_MALICIOUS


def test_pillar_arithmetic():
    def score(*tiers, same_place=False):
        fs = [finding(t, line=1 if same_place else i) for i, t in enumerate(tiers)]
        return score_pillar("Behavior", [make_result("decoded_payload", "Behavior", "ran", fs)])["score"]
    assert score() == 100
    assert score("review") == 92
    assert score(*["review"] * 5) == 70                    # review penalty capped at -30
    assert score("high_risk") == 65
    assert score("high_risk", "high_risk") == 30
    assert score("high_risk", "high_risk", "high_risk") == 20   # floor 20 after 2 or more
    assert score("high_risk", "high_risk", same_place=True) == 65   # same location counts once
    assert score("known_malicious") == 10


def test_apply_gate_caps_abandoned_repo_with_known_malicious_finding():
    """Intended behavior change: caps used to be skipped for 'Likely abandoned' / archived repos."""
    from security import apply_gate
    m = compute_health_score(dormant_features())
    sec = {"level": "High", "coverage": [], "findings": [
        {"severity": "High", "source": "OSV (Confirmed Malware)", "item": "evil 1.0", "detail": "MAL-2026-1"}]}
    g = apply_gate(m, sec, [], {"ran": False, "skip_reason": "too large", "known_malicious_count": 0,
                                "high_risk_pattern_count": 0, "strong": 0})
    assert g["score"] <= 15 and g["trust_label_base"] == LABEL_KNOWN_MALICIOUS
    assert g["maintenance_label"] == "Likely abandoned" and g["maintenance_score"] == m["score"]
    assert g["partial"]   # content detectors were not assessed (download too large)
