"""scorecard (Exposure) - OpenSSF Scorecard overall score, from security.assess_security.

Detects: weak security practices as measured by Scorecard (overall score below 4/10 -> one review finding).
not_assessed when Scorecard has no data for the repository or the request failed.
Known evasions: Scorecard measures practices, not malicious code; a high score says nothing about payloads.
False-positive sources: small or personal projects without branch protection or CI scanning.
"""
from .base import enrich, make_result, not_assessed

DETECTOR_ID, PILLAR = "scorecard", "Exposure"
LOW_SCORE = 4


def detect(ctx) -> dict:
    sec = ctx.security
    if sec is None:
        return not_assessed(DETECTOR_ID, PILLAR, "security sources not checked")
    sc = sec.get("scorecard")
    if not sc or not isinstance(sc.get("score"), (int, float)):
        state = (sec.get("checks") or {}).get("scorecard")
        return not_assessed(DETECTOR_ID, PILLAR, "OpenSSF Scorecard has no data for this repository"
                            if state == "not_available" else "OpenSSF Scorecard lookup failed")
    out = []
    if sc["score"] < LOW_SCORE:
        f = {"sev": "Medium", "source": "Scorecard", "rule": f"OpenSSF Scorecard overall {sc['score']}/10",
             "file": "", "line": None, "detail": f"Overall Scorecard score below {LOW_SCORE}/10.", "fix": "", "url": None,
             "strong": False}
        out.append(enrich(f, DETECTOR_ID, "review", [{"type": "registry_field", "source": "OpenSSF Scorecard",
                                                       "field": "score", "value": sc["score"]}]))
    return make_result(DETECTOR_ID, PILLAR, "ran", out)
