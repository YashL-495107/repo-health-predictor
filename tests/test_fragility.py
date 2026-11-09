"""Fragility index (fragility.py) and the review -> high_risk escalation of Integrity signals."""
from detectors import run_detectors
from detectors.base import enrich, make_result
from detectors.context import DetectorContext
from fragility import ESCALATION_THRESHOLD, WEIGHTS, amplify, compute_fragility


def review_finding(capability=True):
    # release-vs-git code drift is code evidence; since 2026.11.07-5 only such findings can be escalated
    f = enrich({"sev": "Medium", "source": "Layer 4: Release-to-Git Diff", "rule": "Release drift (review)",
                "file": "pkg/x.py", "line": 4, "detail": "", "fix": "", "url": None, "strong": False},
               "release_vs_git", "review")
    return {**f, "capability_evidence": capability}


def fragile():
    return compute_fragility(10, {"bus_factor": 1, "silent_departure": True, "burnout_status": "Lead Maintainer Departed"},
                             {"days_since_last_commit": 800})


def test_formula_and_weights_are_documented_constants():
    # maintainers (10) added before Phase 3: registry maintainer count now feeds fragility
    assert WEIGHTS == {"maintenance": 45, "bus_factor": 25, "dormancy": 15, "silent_departure": 15, "maintainers": 10}
    assert ESCALATION_THRESHOLD == 60
    f = compute_fragility(20, {"bus_factor": 2, "silent_departure": False, "burnout_status": "Stable Triage Pace"},
                          {"days_since_last_commit": 365})
    # 0.45*80 + 0.25*60 + 0.15*50 + 0.15*0 = 58.5
    assert f["score"] == 58.5 and f["unvalidated"] is True
    assert any("maintainer count" in x for x in f["not_available"])   # no registry data passed here
    assert f["factors"] and all(isinstance(x, str) for x in f["factors"])


def test_missing_bus_factor_is_dropped_and_weights_rescaled():
    f = compute_fragility(20, {"bus_factor": 0, "burnout_status": "Unavailable (GitHubError)"}, {"days_since_last_commit": 0})
    # only maintenance (45) and dormancy (15): (45*80 + 15*0) / 60 = 60
    assert f["score"] == 60.0 and set(f["components"]) == {"maintenance", "dormancy"}


def test_fragility_escalates_review_integrity_signal_and_records_why():
    fr = fragile()
    assert fr["score"] >= ESCALATION_THRESHOLD
    r = amplify(make_result("release_vs_git", "Integrity", "ran", [review_finding()]), fr)
    assert r["tier"] == "high_risk" and r["fragility_amplified"] is True
    f = r["findings"][0]
    assert f["tier"] == "high_risk" and f["fragility_amplified"] is True
    assert "fragility index" in f["amplification_reason"] and "threshold 60" in f["amplification_reason"]


def test_no_escalation_below_threshold_or_outside_integrity_or_past_high_risk():
    low = compute_fragility(95, {"bus_factor": 6, "silent_departure": False, "burnout_status": "Stable"}, {"days_since_last_commit": 2})
    assert low["score"] < ESCALATION_THRESHOLD
    r = make_result("release_vs_git", "Integrity", "ran", [review_finding()])
    assert amplify(r, low)["tier"] == "review"
    b = make_result("decoded_payload", "Behavior", "ran", [review_finding()])
    assert amplify(b, fragile())["tier"] == "review"
    hr = make_result("release_vs_git", "Integrity", "ran", [{**review_finding(), "tier": "high_risk"}])
    assert amplify(hr, fragile())["tier"] == "high_risk"   # never escalated to known_malicious


def test_run_detectors_applies_fragility():
    class FakeIntegrity:
        DETECTOR_ID, PILLAR = "release_vs_git", "Integrity"
        @staticmethod
        def detect(ctx):
            return make_result("release_vs_git", "Integrity", "ran", [review_finding()])
    out = run_detectors(DetectorContext.build(fragility=fragile()), registry=[FakeIntegrity])
    assert out[0]["tier"] == "high_risk" and out[0]["fragility_amplified"]


def test_registry_maintainer_count_feeds_fragility():
    bf = {"bus_factor": 2, "silent_departure": False, "burnout_status": "Stable Triage Pace"}
    one = compute_fragility(20, bf, {"days_since_last_commit": 365}, maintainers={"count": 1, "source": "npm packument maintainers (current)"})
    many = compute_fragility(20, bf, {"days_since_last_commit": 365}, maintainers={"count": 4, "source": "npm packument maintainers (current)"})
    # (45*80 + 25*60 + 15*50 + 15*0 + 10*100) / 110 = 62.3 ; with 4 maintainers the last term is 0 -> 53.2
    assert one["score"] == 62.3 and many["score"] == 53.2
    assert one["components"]["maintainers"]["value"] == 100 and not one["not_available"]
    assert any("1 registry maintainer(s)" in x for x in one["factors"])


def test_missing_tag_alone_is_not_escalated_and_records_why():
    from detectors import tagless_release
    from release_helpers import history, npm_release, with_git
    rc = with_git(history([npm_release("2.0.0", "2026-03-01T00:00:00Z")]), default_tree={"index.js", "package.json"}, tags=["v1.0.0"])
    out = run_detectors(DetectorContext.build(releases=rc, fragility=fragile()), registry=[tagless_release])[0]
    f = out["findings"][0]
    assert fragile()["score"] >= ESCALATION_THRESHOLD
    assert out["tier"] == "review" and f["tier"] == "review" and not out["fragility_amplified"]
    assert "metadata-only" in f["no_escalation_reason"]   # was: per-detector no_fragility_escalation flag (-3)


def test_live_fragility_uses_scan_time_not_release_as_of():
    """The release detectors use as_of = latest release upload time; fragility (dormancy, maintainers) describes
    the project today and must use the scan-time features, not that as_of."""
    from security import apply_gate
    from release_helpers import history, npm_release
    rc = history([npm_release("1.0.1", "2019-05-01T00:00:00Z"), npm_release("1.0.0", "2019-01-01T00:00:00Z")])
    rc["history"]["maintainers"] = {"count": 3, "source": "npm packument maintainers (current)"}
    sec = {"level": "No unpatched issues found", "findings": [], "coverage": [], "package": rc["package"]}
    g = apply_gate({"score": 90.0, "label": "Healthy", "factors": [], "notes": []}, sec, [], None,
                   features={"days_since_last_commit": 3, "archived": False}, releases=rc)
    assert g["as_of"].startswith("2019-05-01")                     # release detectors: release time
    fr = g["fragility"]
    assert fr["measured_at"] == "scan time (today)"
    assert fr["components"]["dormancy"]["value"] == round(100 * 3 / 730, 1)   # 3 days (today), not ~7 years
    assert fr["components"]["maintainers"]["value"] == 0


def test_metadata_only_review_finding_is_not_escalated():
    r = amplify(make_result("release_vs_git", "Integrity", "ran", [review_finding(capability=False)]), fragile())
    assert r["tier"] == "review" and not r["fragility_amplified"]
    assert "metadata-only" in r["findings"][0]["no_escalation_reason"]
