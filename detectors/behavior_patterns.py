"""behavior_patterns (Behavior) - adapter for the existing behavior scan (repo_behavior.scan_behavior), excluding
its name-similarity and committed-binary findings (those feed lookalike_name and committed_binary).

Detects: capability indicators (decode-then-execute, exfil-style endpoints, credential-file reads, environment
dumps, persistence, reverse shells, miners, npm install scripts) and same-file intent patterns built from them.
Tier (legacy mapping, Phase 1): intent patterns (strong) -> high_risk; single High/Medium indicators -> review.
These are regex/indicator matches, not data-flow analysis.
Known evasions: string building or encoding that hides the indicator text, splitting capabilities across files,
endpoints fetched at runtime, anything outside the scanned file types or in skipped test/docs folders.
False-positive sources: security tools and detection rulesets (downgraded when a file hits 5+ rules),
research code, deployment scripts that legitimately read credentials.
"""
from .base import content_gate, enrich, legacy_tier, make_result, proof_findings, text_coverage

DETECTOR_ID, PILLAR = "behavior_patterns", "Behavior"


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR, "behavior")
    if gate:
        return gate
    out = [enrich(f, DETECTOR_ID, t) for f in proof_findings(ctx)
           if f.get("source") in ("Behavior", "Behavior pattern") and f.get("cat") not in ("Name", "Binary")
           and (t := legacy_tier(f))]
    cov, detail = text_coverage(ctx, ("text",))
    return make_result(DETECTOR_ID, PILLAR, "ran", out, coverage=cov, coverage_detail=detail)
