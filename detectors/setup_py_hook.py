"""setup_py_hook (Behavior) - the Layer 2 static setup.py check (malware_proof.scan_static_setup_py) plus, since
ruleset v2 (2026.11.10-v2), the install-time trace of install_trace.trace_setup_py.

Detects: install-time code in the package-root setup.py (custom cmdclass / top-level calls) that combines process
execution with network access, read statically from the AST. v2 adds: the package-root setup.py of nested
artifacts (the shallowest setup.py when none is at depth <= 2), calls resolved through import aliases, string
constants that parse as Python, local modules followed up to two import levels, and per-file rules host
fingerprint + network, OAST / IP-lookup endpoint, socket + interactive shell (high_risk).
Tier: exec + network, or any v2 high-risk rule -> high_risk; single capability -> review.
not_applicable when the scanned files have no setup.py.
Known evasions: computed module names, build backends other than setuptools (pyproject-only hooks), payloads
fetched by a dependency, dynamic attribute access hiding the call names, code in compiled extensions.
False-positive sources: legitimate native builds that download toolchains, version lookups via git, setup.py
files that import a package whose own code reads the host name and uses the network.
"""
from .base import content_gate, enrich, legacy_tier, make_result, not_applicable, proof_findings, text_coverage

DETECTOR_ID, PILLAR = "setup_py_hook", "Behavior"
NEEDS_DATA = True


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR, "layer2")
    legacy_na = gate is not None and gate.get("status") == "not_applicable"
    if gate and not legacy_na:
        return gate
    out = [] if legacy_na else [enrich(f, DETECTOR_ID, t) for f in proof_findings(ctx)
                                if str(f.get("source", "")).startswith("Layer 2") and (t := legacy_tier(f))]
    traced = None
    if ctx.data is not None:
        from install_trace import trace_setup_py
        traced = trace_setup_py(dict(ctx.data.get("text") or {}))
    if legacy_na and not (traced and traced["setups"]):
        return gate
    seen = {(f.get("file"), f.get("line")) for f in out}
    for f in (traced or {}).get("findings") or []:
        if not f["strong"] and (f["file"], f["line"]) in seen:
            continue
        base = {"sev": "High" if f["strong"] else "Medium", "source": "Layer 2: Static setup.py Check (v2 trace)",
                "rule": f["rule"], "rule_id": f["rule_id"], "file": f["file"], "line": f["line"],
                "detail": f["detail"] + (" Followed from " + " -> ".join(f["trace"]) + "." if len(f["trace"]) > 1 else ""),
                "fix": "Do not install. Read the setup.py and the modules it runs by hand." if f["strong"] else "Review manually.",
                "url": None, "strong": f["strong"]}
        ev = [{"type": "file_line", "file": f["file"], "line": f["line"]}, {"type": "setup_trace", "trace": f["trace"]}]
        out.append({**enrich(base, DETECTOR_ID, "high_risk" if f["strong"] else "review", ev), "capability_evidence": True})
    cov, detail = text_coverage(ctx, ("text",))
    if traced and traced["parse_errors"]:
        cov, detail = "partial", ((detail + "; ") if detail else "") + "not parsed: " + ", ".join(traced["parse_errors"][:3])
    r = make_result(DETECTOR_ID, PILLAR, "ran", out, coverage=cov, coverage_detail=detail)
    if traced:
        r["setup_trace"] = {"setups": traced["setups"], "traced": traced["traced"]}
    return r
