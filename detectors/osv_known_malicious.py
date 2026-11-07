"""osv_known_malicious (Exposure) - OSV MAL- (malicious package) advisories, from security.assess_security.

Detects: a pinned dependency, or the repository's own published package at its LATEST version, listed in an OSV
malicious-package advisory (id starting MAL-). This is an external authority -> known_malicious.
"Past malicious release" notices (older versions only) carry no tier, by design.
Coverage is partial when some dependencies have no exact version (they are not looked up) or the dependency list
was truncated.
Known evasions: malicious packages not yet reported to OSV, unpinned dependencies, ecosystems other than PyPI/npm.
False-positive sources: OSV data errors; a MAL- advisory always deserves manual confirmation.
"""
from .base import from_security_finding, make_result, security_gate

DETECTOR_ID, PILLAR = "osv_known_malicious", "Exposure"


def detect(ctx) -> dict:
    gate, checks = security_gate(ctx, DETECTOR_ID, ("osv_dependencies", "own_package"))
    if gate:
        return gate
    out = [from_security_finding(f, DETECTOR_ID, "known_malicious") for f in (ctx.security.get("findings") or [])
           if f.get("source") == "OSV (Confirmed Malware)"]
    d = checks.get("osv_dependencies_detail") or {}
    notes = []
    if d.get("unpinned_not_scanned"):
        notes.append(f"{d['scanned']} of {d['scanned'] + d['unpinned_not_scanned']} dependencies looked up (others have no exact version)")
    if d.get("truncated"):
        notes.append("dependency list truncated")
    if checks.get("own_package") == "not_assessed":
        notes.append("own-package check not run")
    return make_result(DETECTOR_ID, PILLAR, "ran", out,
                       coverage="partial" if notes else "full", coverage_detail="; ".join(notes) or None)
