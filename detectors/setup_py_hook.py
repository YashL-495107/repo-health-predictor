"""setup_py_hook (Behavior) - adapter for the existing Layer 2 static setup.py check (malware_proof.scan_static_setup_py).

Detects: install-time code in a root setup.py (custom cmdclass / top-level calls) that combines process execution
with network access, read statically from the AST.
Tier (legacy mapping, Phase 1): exec + network in setup.py (strong) -> high_risk; single capability -> review.
not_applicable when the repository has no root setup.py.
Known evasions: logic moved to an imported helper module, build backends other than setuptools (pyproject-only
hooks), payloads fetched by a dependency, dynamic attribute access hiding the call names.
False-positive sources: legitimate native builds that download toolchains, version lookups via git.
"""
from .base import content_gate, enrich, legacy_tier, make_result, proof_findings, text_coverage

DETECTOR_ID, PILLAR = "setup_py_hook", "Behavior"


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR, "layer2")
    if gate:
        return gate
    out = [enrich(f, DETECTOR_ID, t) for f in proof_findings(ctx)
           if str(f.get("source", "")).startswith("Layer 2") and (t := legacy_tier(f))]
    cov, detail = text_coverage(ctx, ("text",))
    return make_result(DETECTOR_ID, PILLAR, "ran", out, coverage=cov, coverage_detail=detail)
