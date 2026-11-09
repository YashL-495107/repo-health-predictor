"""osv_advisories (Exposure) - known vulnerabilities, from security.assess_security.

Detects: unpatched GitHub security advisories for the repository and OSV vulnerabilities in its pinned
dependencies. Each is review tier; the existing security.py caps still apply (unpatched advisory or 3+ vulnerable
dependencies -> 49; some vulnerable dependencies -> 69).
Patched advisories (Info) carry no tier.
Known evasions: not applicable (this is a known-vulnerability lookup, not a malware detector).
False-positive sources: advisories that do not affect the way the dependency is used; only exact versions are checked.
"""
from .base import from_security_finding, make_result, security_gate

DETECTOR_ID, PILLAR = "osv_advisories", "Exposure"


def detect(ctx) -> dict:
    gate, checks = security_gate(ctx, DETECTOR_ID, ("github_advisories", "osv_dependencies"))
    if gate:
        return gate
    out = [from_security_finding(f, DETECTOR_ID, "review") for f in (ctx.security.get("findings") or [])
           if (f.get("source") == "GitHub advisory" and f.get("severity") == "High") or f.get("source") == "OSV (dependency)"]
    d = checks.get("osv_dependencies_detail") or {}
    notes = []
    if d.get("unpinned_not_scanned"):
        notes.append(f"{d['scanned']} of {d['scanned'] + d['unpinned_not_scanned']} dependencies looked up (others have no exact version)")
    if checks.get("github_advisories") != "ran":
        notes.append("GitHub advisories not checked")
    if checks.get("osv_dependencies") == "not_assessed":
        notes.append("dependency lookup failed")
    return make_result(DETECTOR_ID, PILLAR, "ran", out,
                       coverage="partial" if notes else "full", coverage_detail="; ".join(notes) or None)
