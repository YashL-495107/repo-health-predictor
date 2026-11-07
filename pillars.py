"""Four-pillar model and the headline Trust score ("indicators, not proof").

Pillars
  Maintenance  the existing compute_health_score result (formula unchanged; the backtest still evaluates it).
  Integrity, Behavior, Exposure  0-100 from detector findings, or None.

Pillar rule (Integrity, Behavior, Exposure): start at 100.
  known_malicious -> pillar = min(pillar, 10)
  high_risk       -> -35 each; with 2 or more high_risk findings the pillar does not go below 20
  review          -> -8 each, at most -30 in total from review findings alone
  One location (file:line, or detector + rule when there is no file) counts once per tier inside a pillar, so the
  same evidence reported by two adapters is not double-counted.
  All feeding detectors not_assessed -> None ("not assessed"); all not_applicable -> None with the reason
  (for example "no published package"), which is not a failed check.

Headline = min over the ASSESSED Integrity/Behavior/Exposure pillars, then:
  - any high_risk finding caps the headline at 49 and any known_malicious at 15 (these mirror the existing
    security.py evidence caps, so a pillar finding is never weaker than them, and a high-risk finding on a
    dormant project limits the headline before the maintenance ceiling does);
  - maintenance ceiling: if the Maintenance pillar is below MAINTENANCE_ABANDONED (40) or the repository is
    archived, headline = min(headline, MAINTENANCE_CEILING (50)). Maintenance alone never lowers it below 50;
  - the existing security.py evidence caps (the lower value wins).
When values tie, a pillar finding is named before the maintenance ceiling, and both before an evidence rule.

Labels (precedence): DO NOT USE: known malicious indicator > High-risk patterns: review before use > Review
recommended > Fragile / unmaintained > No findings. "Partial assessment" is appended when a pillar was not
assessed or a detector only covered part of the repository; "Not assessed" when no pillar was assessed.
"""
from __future__ import annotations

from detectors.base import PILLARS, TIER_RANK

START = 100
KNOWN_MALICIOUS_PILLAR_CEILING = 10
HIGH_RISK_PENALTY, HIGH_RISK_FLOOR = 35, 20
REVIEW_PENALTY, REVIEW_PENALTY_CAP = 8, 30
TIER_HEADLINE_CAPS = {"known_malicious": 15, "high_risk": 49}
MAINTENANCE_ABANDONED = 40
MAINTENANCE_CEILING = 50

LABEL_KNOWN_MALICIOUS = "DO NOT USE: known malicious indicator"
LABEL_HIGH_RISK = "High-risk patterns: review before use"
LABEL_REVIEW = "Review recommended"
LABEL_FRAGILE = "Fragile / unmaintained"
LABEL_NO_FINDINGS = "No findings"
LABEL_NOT_ASSESSED = "Not assessed"
PARTIAL_NOTE = "Partial assessment"
_KIND_ORDER = {"pillar": 0, "maintenance": 1, "evidence": 2}


def _key(f: dict) -> tuple:
    if f.get("file"):
        return (f.get("file"), f.get("line"), f["tier"])
    return (f.get("detector"), f.get("rule"), f["tier"])


def _where(f: dict) -> str:
    return f" at {f['file']}:{f['line']}" if f.get("file") else ""


def score_pillar(pillar: str, results: list[dict]) -> dict:
    feeding = [r for r in results if r["pillar"] == pillar]
    ran = [r for r in feeding if r["status"] == "ran"]
    na = [r for r in feeding if r["status"] == "not_applicable"]
    partial = [r for r in ran if r.get("coverage") == "partial"]
    cov_text = f"{len(ran)} of {len(feeding)} detectors ran" + (f", {len(na)} not applicable" if na and ran else "")
    if partial:
        cov_text += "; " + "; ".join(sorted({r.get("coverage_detail") or f"{r['detector']}: partial" for r in partial}))
    coverage = {"ran": len(ran), "total": len(feeding), "not_applicable": len(na), "partial": bool(partial),
                "partial_details": [f"{r['detector']}: {r.get('coverage_detail') or 'partial'}" for r in partial],
                "text": cov_text}
    if not ran:
        if feeding and len(na) == len(feeding):
            reasons = sorted({r.get("not_assessed_reason") or "not applicable" for r in na})
            return {"pillar": pillar, "score": None, "status": "not_applicable", "reason": "; ".join(reasons),
                    "coverage": coverage, "findings": [], "worst": None}
        reasons = sorted({f"{r['detector']}: {r.get('not_assessed_reason')}" for r in feeding if r["status"] == "not_assessed"})
        return {"pillar": pillar, "score": None, "status": "not_assessed", "reason": "; ".join(reasons) or "no detectors",
                "coverage": coverage, "findings": [], "worst": None}

    uniq: dict[tuple, dict] = {}
    for r in ran:
        for f in r["findings"]:
            uniq.setdefault(_key(f), f)
    findings = sorted(uniq.values(), key=lambda f: -TIER_RANK[f["tier"]])
    n_hr = sum(1 for f in findings if f["tier"] == "high_risk")
    n_rv = sum(1 for f in findings if f["tier"] == "review")
    score = START - HIGH_RISK_PENALTY * n_hr - min(REVIEW_PENALTY * n_rv, REVIEW_PENALTY_CAP)
    if n_hr >= 2:
        score = max(score, HIGH_RISK_FLOOR)
    score = max(0, min(START, score))
    if any(f["tier"] == "known_malicious" for f in findings):
        score = min(score, KNOWN_MALICIOUS_PILLAR_CEILING)
    return {"pillar": pillar, "score": score, "status": "assessed", "reason": None, "coverage": coverage,
            "findings": findings, "worst": findings[0] if findings else None}


def _pillar_reason(p: dict) -> str:
    w = p["worst"]
    if w:
        amp = " (escalated by fragility)" if w.get("fragility_amplified") else ""
        return f"limited by {p['pillar']}: {w.get('rule')}{_where(w)}{amp}"
    return f"limited by {p['pillar']}: no findings ({p['coverage']['text']})"


def compute_trust(results: list[dict], maintenance: dict, *, archived: bool = False,
                  evidence_caps: list[tuple[float, str]] | None = None, security_level: str | None = None,
                  content_flags: list[str] | None = None) -> dict:
    """results: detector results; maintenance: {"score", "label"} from compute_health_score;
    evidence_caps: [(cap_value, short_name, tier_hint)] from security.apply_gate; tier_hint is the evidence tier the
    rule stands for (known_malicious / high_risk / review) so the label never contradicts a cap."""
    pillars = {p: score_pillar(p, results) for p in PILLARS}
    m_score = maintenance.get("score")
    weak_maintenance = archived or (isinstance(m_score, (int, float)) and m_score < MAINTENANCE_ABANDONED)
    pillars_out = {"Maintenance": {"pillar": "Maintenance", "score": m_score, "status": "assessed",
                                   "label": maintenance.get("label"),
                                   "note": f"Feeds the fragility index; on its own it can lower the headline to {MAINTENANCE_CEILING} at most."},
                   **pillars}

    all_findings = [f for p in pillars.values() for f in p["findings"]]
    tiers = {f["tier"] for f in all_findings}
    assessed = [p for p in PILLARS if pillars[p]["score"] is not None]
    partial_reasons = [f"{p}: not assessed ({pillars[p]['reason']})" for p in PILLARS if pillars[p]["status"] == "not_assessed"]
    partial_reasons += [d for p in PILLARS for d in pillars[p]["coverage"]["partial_details"]]

    if not assessed:
        return {"trust_score": None, "label": LABEL_NOT_ASSESSED, "label_base": LABEL_NOT_ASSESSED, "partial": True,
                "partial_reasons": partial_reasons, "pillars": pillars_out, "limiting_pillar": None,
                "limiting_kind": None, "limiting_reason": "no Integrity, Behavior or Exposure detector could run"}

    cands = [(pillars[p]["score"], "pillar", p, _pillar_reason(pillars[p])) for p in assessed]
    for tier, cap in TIER_HEADLINE_CAPS.items():
        holders = [p for p in assessed if any(f["tier"] == tier for f in pillars[p]["findings"])]
        if holders:
            p = holders[0]
            w = next(f for f in pillars[p]["findings"] if f["tier"] == tier)
            cands.append((cap, "pillar", p, f"limited by {p}: {w.get('rule')}{_where(w)}"))
    if weak_maintenance:
        why = "archived (read-only)" if archived else f"maintenance {m_score:.0f}/100, below {MAINTENANCE_ABANDONED}"
        cands.append((MAINTENANCE_CEILING, "maintenance", "Maintenance",
                      f"limited by Maintenance: {why}; maintenance alone caps the headline at {MAINTENANCE_CEILING}, it is not a threat signal"))
    for value, name, *_ in evidence_caps or []:
        cands.append((value, "evidence", None, f"capped by evidence rule: {name}"))
    tiers |= {c[2] for c in evidence_caps or [] if len(c) > 2 and c[2]}
    order = {p: i for i, p in enumerate(PILLARS)}
    value, kind, pillar, reason = min(cands, key=lambda c: (c[0], _KIND_ORDER[c[1]], order.get(c[2], 9)))

    if "known_malicious" in tiers:
        base = LABEL_KNOWN_MALICIOUS
    elif "high_risk" in tiers:
        base = LABEL_HIGH_RISK
    elif "review" in tiers or security_level in ("Elevated", "High") or content_flags:
        base = LABEL_REVIEW
    elif weak_maintenance:
        base = LABEL_FRAGILE
    else:
        base = LABEL_NO_FINDINGS
    partial = bool(partial_reasons)
    return {"trust_score": round(float(value), 1), "label": f"{base} ({PARTIAL_NOTE})" if partial else base,
            "label_base": base, "partial": partial, "partial_reasons": partial_reasons, "pillars": pillars_out,
            "limiting_pillar": pillar, "limiting_kind": kind, "limiting_reason": reason}
