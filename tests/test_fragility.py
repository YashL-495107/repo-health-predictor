"""Fragility index (fragility.py) and the review -> high_risk escalation of Integrity signals."""
from detectors import run_detectors
from detectors.base import enrich, make_result
from detectors.context import DetectorContext
from fragility import ESCALATION_THRESHOLD, WEIGHTS, amplify, compute_fragility


def review_finding():
    return enrich({"sev": "Medium", "source": "Layer 4: Release-to-Git Diff", "rule": "Release drift (review)",
                   "file": "pkg/x.py", "line": 4, "detail": "", "fix": "", "url": None, "strong": False},
                  "release_vs_git", "review")


def fragile():
    return compute_fragility(10, {"bus_factor": 1, "silent_departure": True, "burnout_status": "Lead Maintainer Departed"},
                             {"days_since_last_commit": 800})


def test_formula_and_weights_are_documented_constants():
    assert WEIGHTS == {"maintenance": 45, "bus_factor": 25, "dormancy": 15, "silent_departure": 15}
    assert ESCALATION_THRESHOLD == 60
    f = compute_fragility(20, {"bus_factor": 2, "silent_departure": False, "burnout_status": "Stable Triage Pace"},
                          {"days_since_last_commit": 365})
    # 0.45*80 + 0.25*60 + 0.15*50 + 0.15*0 = 58.5
    assert f["score"] == 58.5 and f["unvalidated"] is True
    assert any("publisher" in x for x in f["not_available"])
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
