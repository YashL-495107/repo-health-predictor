"""virustotal (Exposure) - adapter for the existing Layer 3 VirusTotal hash lookup.

Detects: committed executables whose SHA-256 is known to VirusTotal with antivirus detections.
Tier: >= 5 engines -> known_malicious (external authority); 1-4 engines -> review.
not_assessed without a VT_API_KEY or when rate-limited; not_applicable when no executables are committed.
At most 5 executables are looked up per scan, so coverage is partial when more are committed.
Known evasions: new or recompiled binaries with unknown hashes, payloads that are not committed executables.
False-positive sources: generic heuristic detections on packers/installers; a low engine count is weak evidence.
"""
from .base import content_gate, enrich, legacy_tier, make_result, proof_findings

DETECTOR_ID, PILLAR = "virustotal", "Exposure"


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR, "layer3")
    if gate:
        return gate
    out = [enrich(f, DETECTOR_ID, t) for f in proof_findings(ctx)
           if "VirusTotal" in str(f.get("source", "")) and (t := legacy_tier(f))]
    st = (((ctx.scan or {}).get("malware_proof") or {}).get("layers") or {}).get("layer3") or {}
    return make_result(DETECTOR_ID, PILLAR, "ran", out,
                       coverage="partial" if st.get("partial") else "full", coverage_detail=st.get("detail"))
