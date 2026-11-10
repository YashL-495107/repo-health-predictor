"""install_hook_target (Behavior) - ruleset v2 (2026.11.10-v2): what an npm install hook actually runs.

Detects: for every preinstall / install / postinstall command, the local file it runs (or its inline `node -e`
code) and the local files that file references (require / import / spawned .js and .sh paths, up to 3 hops),
checked PER FILE with install-time rules (install_trace.py): host fingerprint + network, OAST / request-catcher /
IP-lookup endpoints, socket + interactive shell (high_risk); a detached background process (review).
not_applicable when no scanned package.json declares an install hook.
Known evasions: computed file names, payloads in files over the read limits or not shipped in the package,
fingerprints read through other APIs, network access through a dependency, hooks that only run a binary.
False-positive sources: install-time telemetry that reports the host name; reverse-shell or beacon demos.
"""
from .base import content_gate, enrich, make_result, not_applicable, text_coverage

DETECTOR_ID, PILLAR = "install_hook_target", "Behavior"
NEEDS_DATA = True
FIX = "Read the hook's target file. Install hooks are the main way npm malware runs; do not install until explained."


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR)
    if gate:
        return gate
    if ctx.data is None:
        return make_result(DETECTOR_ID, PILLAR, "not_assessed", reason="repository contents not available")
    from install_trace import trace_npm_hooks
    res = trace_npm_hooks(dict(ctx.data.get("text") or {}))
    if not res["hooks"]:
        return not_applicable(DETECTOR_ID, PILLAR, "no npm install hook in the scanned files")
    out = []
    for f in res["findings"]:
        base = {"sev": "High" if f["strong"] else "Medium", "source": "Install hook trace", "cat": "Install-time execution",
                "rule": f["rule"], "rule_id": f["rule_id"], "file": f["file"], "line": f["line"],
                "detail": f"{f['detail']} Reached from {f['hook']} via " + " -> ".join(f["trace"]) + ".",
                "fix": FIX, "url": None, "strong": f["strong"]}
        ev = [{"type": "file_line", "file": f["file"], "line": f["line"]},
              {"type": "install_hook", "hook": f["hook"], "trace": f["trace"]}]
        out.append({**enrich(base, DETECTOR_ID, "high_risk" if f["strong"] else "review", ev), "capability_evidence": True})
    missing = [h["missing"] for h in res["hooks"] if h["missing"]]
    cov, detail = text_coverage(ctx, ("text",))
    if missing:
        cov = "partial"
        detail = ((detail + "; ") if detail else "") + "hook target not in the scanned files: " + ", ".join(sorted(set(missing))[:5])
    r = make_result(DETECTOR_ID, PILLAR, "ran", out, coverage=cov, coverage_detail=detail)
    r["hooks_traced"] = [{k: h[k] for k in ("package_json", "script", "kind", "traced", "missing")} for h in res["hooks"]]
    return r
