"""release_vs_git (Integrity) - adapter for the existing Layer 4 release-to-git AST diff
(malware_proof.verify_release_integrity).

Detects: Python files in the latest PyPI wheel (under 5 MB) whose AST differs from the default branch, or that do
not exist in git ("phantom" files), with new execution/network capabilities.
Tier (legacy mapping, Phase 1): drift that adds capabilities (strong) -> high_risk; other drift -> no tier.
Fragility can escalate review-tier signals of this Integrity detector to high_risk (see fragility.py).
not_applicable without a published PyPI package; coverage is partial when only release metadata could be read
(no wheel under 5 MB) or when the Python file cap was hit.
Known evasions: sdist-only or large releases, non-Python payloads, changes that match git at a later commit,
npm packages (not compared in Phase 1).
False-positive sources: build-generated files, vendored code, releases cut from a branch other than default.
"""
from .base import content_gate, enrich, legacy_tier, make_result, proof_findings, text_coverage

DETECTOR_ID, PILLAR = "release_vs_git", "Integrity"


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR, "layer4")
    if gate:
        return gate
    out = [enrich(f, DETECTOR_ID, t) for f in proof_findings(ctx)
           if str(f.get("source", "")).startswith("Layer 4") and (t := legacy_tier(f))]
    st = (((ctx.scan or {}).get("malware_proof") or {}).get("layers") or {}).get("layer4") or {}
    cov, detail = text_coverage(ctx, ("py",))
    if st.get("partial"):
        cov, detail = "partial", "; ".join(x for x in (st.get("detail"), detail) if x)
    return make_result(DETECTOR_ID, PILLAR, "ran", out, coverage=cov, coverage_detail=detail)
