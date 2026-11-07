"""Fragility index: how easy a project would be to take over or poison, from EXISTING maintenance outputs only.

Score 0-100, higher = more fragile. Transparent weighted average of the components that are available
(unavailable components are dropped and the remaining weights rescaled, like scoring.py):

  maintenance       45   100 - maintenance score (scoring.compute_health_score)
  bus_factor        25   bus factor 0 or 1 -> 100, 2 -> 60, 3 -> 30, 4+ -> 0   (bus_factor.py)
  dormancy          15   days since last commit / 730, capped at 100          (github_client features)
  silent_departure  15   100 if the top maintainer went silent, else 0       (bus_factor.py)
  publisher_count    -   NOT AVAILABLE in Phase 1 (needs registry release data, Phase 2)

UNVALIDATED DESIGN CHOICES: the weights above and the escalation threshold (60) were chosen by hand, not fitted or
measured. They are documented here so they can be challenged; do not read them as calibrated.

Use: fragility does NOT lower the headline trust score. It raises the severity of Integrity signals: when the
index is >= ESCALATION_THRESHOLD, a review-tier finding from an Integrity detector becomes high_risk, with
fragility_amplified=True and a plain-language reason. It never escalates past high_risk; only an external
authority can produce known_malicious.

Time: "days since last commit" is measured against the scan time in Phase 1 (no release dates yet).
"""
from __future__ import annotations

WEIGHTS = {"maintenance": 45, "bus_factor": 25, "dormancy": 15, "silent_departure": 15}   # unvalidated
ESCALATION_THRESHOLD = 60                                                                    # unvalidated
DORMANCY_FULL_DAYS = 730
BUS_FACTOR_MAP = {0: 100, 1: 100, 2: 60, 3: 30}   # 4+ -> 0


def _bus_available(bf) -> bool:
    return isinstance(bf, dict) and "bus_factor" in bf and not str(bf.get("burnout_status", "")).startswith("Unavailable")


def compute_fragility(maintenance_score=None, bus_factor: dict | None = None, features: dict | None = None,
                      archived: bool = False) -> dict:
    comps: dict[str, float] = {}
    if isinstance(maintenance_score, (int, float)):
        comps["maintenance"] = max(0.0, min(100.0, 100.0 - maintenance_score))
    if _bus_available(bus_factor):
        comps["bus_factor"] = float(BUS_FACTOR_MAP.get(int(bus_factor["bus_factor"]), 0))
        comps["silent_departure"] = 100.0 if bus_factor.get("silent_departure") else 0.0
    days = (features or {}).get("days_since_last_commit")
    if isinstance(days, (int, float)):
        comps["dormancy"] = min(100.0, 100.0 * days / DORMANCY_FULL_DAYS)

    not_available = ["publisher/maintainer count (needs registry release data; Phase 2)"]
    if "bus_factor" not in comps:
        not_available.append("bus factor and silent-departure flag (bus factor analysis unavailable)")
    if not comps:
        return {"score": None, "components": {}, "factors": [], "not_available": not_available,
                "threshold": ESCALATION_THRESHOLD, "unvalidated": True}

    total_w = sum(WEIGHTS[k] for k in comps)
    score = sum(WEIGHTS[k] * v for k, v in comps.items()) / total_w
    components = {k: {"value": round(v, 1), "weight": WEIGHTS[k], "contribution": round(WEIGHTS[k] * v / total_w, 1)}
                  for k, v in comps.items()}
    text = {
        "maintenance": lambda: f"maintenance score {maintenance_score:.0f}/100",
        "bus_factor": lambda: f"bus factor {bus_factor['bus_factor']}",
        "dormancy": lambda: f"{days} days since the last commit",
        "silent_departure": lambda: "the top maintainer went silent" if bus_factor.get("silent_departure")
                                    else "no silent maintainer departure",
    }
    factors = [f"{text[k]()} (adds {c['contribution']:.0f})" for k, c in
               sorted(components.items(), key=lambda kv: -kv[1]["contribution"])]
    if archived:
        factors.append("repository is archived (read-only)")
    return {"score": round(score, 1), "components": components, "factors": factors, "not_available": not_available,
            "threshold": ESCALATION_THRESHOLD, "unvalidated": True}


def amplify(result: dict, fragility: dict) -> dict:
    """Escalate review -> high_risk for an Integrity detector when fragility >= threshold. Returns a new dict."""
    score = (fragility or {}).get("score")
    if (result.get("pillar") != "Integrity" or result.get("status") != "ran" or not isinstance(score, (int, float))
            or score < ESCALATION_THRESHOLD or not any(f.get("tier") == "review" for f in result.get("findings", []))):
        return result
    top = ", ".join((fragility.get("factors") or [])[:2])
    reason = (f"Escalated from review to high-risk because the fragility index is {score:.0f} "
              f"(threshold {ESCALATION_THRESHOLD}): {top}. Fragile projects are takeover targets.")
    findings = []
    for f in result["findings"]:
        if f.get("tier") == "review":
            f = {**f, "tier": "high_risk", "fragility_amplified": True, "amplification_reason": reason}
        findings.append(f)
    from detectors.base import worst_tier
    return {**result, "findings": findings, "tier": worst_tier(x["tier"] for x in findings) or "none_found",
            "fragility_amplified": True, "amplification_reason": reason}
