"""decoded_payload (Behavior) - adapter for the existing Layer 1 static decoder (malware_proof.scan_ast_deobfuscation).

Detects: encoded data (base64/hex/zlib/...) that is decoded and passed to exec/eval/compile, with the decoded text
inspected statically for execution/network/credential indicators. Nothing is ever executed.
Tier (legacy mapping, Phase 1): strong decoded-and-executed payload -> high_risk; "(review)" decodes -> review.
Known evasions: multi-stage loaders that fetch the payload at runtime, custom ciphers/XOR keys computed at runtime,
payloads split across files or built from non-literal values, languages other than Python/JS/TS/shell.
False-positive sources: code generators that exec locally built source, packed data tables, CTF/research samples.
"""
from .base import content_gate, enrich, legacy_tier, make_result, proof_findings, text_coverage

DETECTOR_ID, PILLAR = "decoded_payload", "Behavior"


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR, "layer1")
    if gate:
        return gate
    out = [enrich(f, DETECTOR_ID, t) for f in proof_findings(ctx)
           if str(f.get("source", "")).startswith("Layer 1") and (t := legacy_tier(f))]
    cov, detail = text_coverage(ctx, ("text",))
    return make_result(DETECTOR_ID, PILLAR, "ran", out, coverage=cov, coverage_detail=detail)
