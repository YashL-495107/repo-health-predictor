"""committed_binary (Exposure) - adapter for the behavior scan's "compiled executable committed to the repo" check.

Detects: files of at least 1 KB that start with executable magic bytes (MZ / ELF / Mach-O) outside media types.
Tier: review (a committed binary cannot be read by the other static checks; VirusTotal covers known-bad hashes).
At most 20 binaries are recorded per repository (repo_scan.read_repo).
Known evasions: binaries inside archives, encrypted or base64-encoded binaries, files above 10 MB.
False-positive sources: test fixtures, vendored tools, game/firmware projects that ship binaries on purpose.
"""
from .base import content_gate, enrich, make_result, proof_findings

DETECTOR_ID, PILLAR = "committed_binary", "Exposure"


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR, "behavior")
    if gate:
        return gate
    out = [enrich(f, DETECTOR_ID, "review") for f in proof_findings(ctx)
           if f.get("source") in ("Behavior", "Behavior pattern") and f.get("cat") == "Binary"]
    return make_result(DETECTOR_ID, PILLAR, "ran", out)
