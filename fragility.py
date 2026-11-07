"""Fragility index: how easy a project would be to take over or poison, from EXISTING maintenance outputs only.

Score 0-100, higher = more fragile. Transparent weighted average of the components that are available
(unavailable components are dropped and the remaining weights rescaled, like scoring.py):

  maintenance       45   100 - maintenance score (scoring.compute_health_score)
  bus_factor        25   bus factor 0 or 1 -> 100, 2 -> 60, 3 -> 30, 4+ -> 0   (bus_factor.py)
  dormancy          15   days since last commit / 730, capped at 100          (github_client features)
  silent_departure  15   100 if the top maintainer went silent, else 0       (bus_factor.py)
  maintainers       10   registry maintainer count: 1 -> 100, 2 -> 50, 3+ -> 0 (npm packument "maintainers",
                         PyPI "ownership.roles"; both are the CURRENT list, so they describe the project today)

CORRELATED INPUTS (partial double counting): the bus factor (from commit authorship) and the registry maintainer
count (who may publish) both measure "how few people hold the project". A single-maintainer project usually scores
high on both, so that risk is counted roughly twice (25 + 10 of the relative weight). Maintenance score and dormancy
overlap in the same way (both fall as commits stop). The weights do not correct for these correlations.

UNVALIDATED DESIGN CHOICES: the weights above (relative weights; available ones are rescaled to 100%) and the
escalation threshold (60) were chosen by hand, not fitted or
measured. They are documented here so they can be challenged; do not read them as calibrated.

Use: fragility does NOT lower the headline trust score. It raises the severity of Integrity signals: when the
index is >= ESCALATION_THRESHOLD, a review-tier finding from an Integrity detector becomes high_risk, with
fragility_amplified=True and a plain-language reason. It never escalates past high_risk; only an external
authority can produce known_malicious.

Time: fragility describes the project AS IT IS TODAY, so "days since last commit" and the maintainer count are
measured at scan time (today's date), on purpose, and are NOT measured against the release-based as_of used by
the release detectors. Replaying an old incident (Phase 5) must pass features recorded at that time.

Not escalated: findings marked no_fragility_escalation (a missing git tag on its own: many dormant projects never
tag, so escalating it would flag them for being dormant, not for any takeover evidence).
"""
from __future__ import annotations

WEIGHTS = {"maintenance": 45, "bus_factor": 25, "dormancy": 15, "silent_departure": 15, "maintainers": 10}   # unvalidated
MAINTAINER_MAP = {0: 100, 1: 100, 2: 50}   # 3+ -> 0
ESCALATION_THRESHOLD = 60                                                                    # unvalidated
DORMANCY_FULL_DAYS = 730
BUS_FACTOR_MAP = {0: 100, 1: 100, 2: 60, 3: 30}   # 4+ -> 0


def _bus_available(bf) -> bool:
    return isinstance(bf, dict) and "bus_factor" in bf and not str(bf.get("burnout_status", "")).startswith("Unavailable")


def compute_fragility(maintenance_score=None, bus_factor: dict | None = None, features: dict | None = None,
                      archived: bool = False, maintainers: dict | None = None) -> dict:
    comps: dict[str, float] = {}
    if isinstance(maintenance_score, (int, float)):
        comps["maintenance"] = max(0.0, min(100.0, 100.0 - maintenance_score))
    if _bus_available(bus_factor):
        comps["bus_factor"] = float(BUS_FACTOR_MAP.get(int(bus_factor["bus_factor"]), 0))
        comps["silent_departure"] = 100.0 if bus_factor.get("silent_departure") else 0.0
    days = (features or {}).get("days_since_last_commit")
    if isinstance(days, (int, float)):
        comps["dormancy"] = min(100.0, 100.0 * days / DORMANCY_FULL_DAYS)
    m_count = (maintainers or {}).get("count")
    if isinstance(m_count, int):
        comps["maintainers"] = float(MAINTAINER_MAP.get(m_count, 0))

    not_available = [] if "maintainers" in comps else ["registry maintainer count (no published package, or not exposed)"]
    if "bus_factor" not in comps:
        not_available.append("bus factor and silent-departure flag (bus factor analysis unavailable)")
    if not comps:
        return {"score": None, "components": {}, "factors": [], "not_available": not_available,
                "threshold": ESCALATION_THRESHOLD, "unvalidated": True, "measured_at": "scan time (today)"}

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
        "maintainers": lambda: f"{m_count} registry maintainer(s) ({maintainers.get('source')})",
    }
    factors = [f"{text[k]()} (adds {c['contribution']:.0f})" for k, c in
               sorted(components.items(), key=lambda kv: -kv[1]["contribution"])]
    if archived:
        factors.append("repository is archived (read-only)")
    return {"score": round(score, 1), "components": components, "factors": factors, "not_available": not_available,
            "threshold": ESCALATION_THRESHOLD, "unvalidated": True, "measured_at": "scan time (today)"}


def amplify(result: dict, fragility: dict) -> dict:
    """Escalate review -> high_risk for an Integrity detector when fragility >= threshold. Returns a new dict."""
    score = (fragility or {}).get("score")
    if (result.get("pillar") != "Integrity" or result.get("status") != "ran" or not isinstance(score, (int, float))
            or score < ESCALATION_THRESHOLD
            or not any(f.get("tier") == "review" and not f.get("no_fragility_escalation") for f in result.get("findings", []))):
        return result
    top = ", ".join((fragility.get("factors") or [])[:2])
    reason = (f"Escalated from review to high-risk because the fragility index is {score:.0f} "
              f"(threshold {ESCALATION_THRESHOLD}): {top}. Fragile projects are takeover targets.")
    findings = []
    for f in result["findings"]:
        if f.get("tier") == "review" and not f.get("no_fragility_escalation"):
            f = {**f, "tier": "high_risk", "fragility_amplified": True, "amplification_reason": reason}
        findings.append(f)
    from detectors.base import worst_tier
    return {**result, "findings": findings, "tier": worst_tier(x["tier"] for x in findings) or "none_found",
            "fragility_amplified": True, "amplification_reason": reason}
