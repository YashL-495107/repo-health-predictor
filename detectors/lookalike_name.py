"""lookalike_name (Exposure) - adapter for the behavior scan's "Name resembles a popular package" check.

Detects: a repository name that is one edit away from, or a letter swap / affix of, a popular package name.
Tier: review (name similarity alone is never proof).
Known evasions: names outside the built-in popular list, homoglyphs, scoped/namespaced squats.
False-positive sources: legitimate forks, plugins and short generic names that are close to many packages.
"""
from .base import content_gate, enrich, make_result, proof_findings

DETECTOR_ID, PILLAR = "lookalike_name", "Exposure"


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR, "behavior")
    if gate:
        return gate
    out = [enrich(f, DETECTOR_ID, "review") for f in proof_findings(ctx)
           if f.get("source") in ("Behavior", "Behavior pattern") and f.get("cat") == "Name"]
    return make_result(DETECTOR_ID, PILLAR, "ran", out)
