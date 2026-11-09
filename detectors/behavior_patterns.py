"""behavior_patterns (Behavior) - adapter for the existing behavior scan (repo_behavior.scan_behavior), excluding
its name-similarity and committed-binary findings (those feed lookalike_name and committed_binary).

Detects: capability indicators (decode-then-execute, exfil-style endpoints, credential-file reads, environment
dumps, persistence, reverse shells, miners, npm install scripts) and same-file intent patterns built from them.
Tier (legacy mapping, Phase 1): intent patterns (strong) -> high_risk; single High/Medium indicators -> review.
Since 2026.11.07-7: the single-indicator rules "reads credential files" and "dumps all environment variables" are
dropped (kept as info_findings with the reason) for Python files that credential_exfiltration analysed with ast,
and become info in development-tooling paths (tasks.py, scripts/, tools/, .agents/, tests, docs, examples). They
are kept for JS/shell and unparseable files; multi-signal same-file intent patterns are always kept.
These are regex/indicator matches, not data-flow analysis.
Known evasions: string building or encoding that hides the indicator text, splitting capabilities across files,
endpoints fetched at runtime, anything outside the scanned file types or in skipped test/docs folders.
False-positive sources: security tools and detection rulesets (downgraded when a file hits 5+ rules),
research code, deployment scripts that legitimately read credentials.
"""
from pathlib import PurePosixPath

from .base import content_gate, enrich, legacy_tier, make_result, proof_findings, text_coverage

DETECTOR_ID, PILLAR = "behavior_patterns", "Behavior"
# single-indicator regex rules that credential_exfiltration owns for Python files it analysed with ast
DATAFLOW_OWNED = {"Credential access: reads credential files", "Credential access: dumps all environment variables"}
INFO_REASON = ("Downgraded to info: a single credential/environment indicator with no network sink, in a "
               "non-shipping path ({where}).")


def dev_tooling(path: str) -> str | None:
    """Kept for callers; delegates to the shared non-shipping classifier (detectors/paths.py)."""
    from .paths import non_shipping
    return non_shipping(path)


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR, "behavior")
    if gate:
        return gate
    ast_files = set((ctx.scan or {}).get("ast_analysed_py") or [])
    out, info = [], []
    for f in proof_findings(ctx):
        if f.get("source") not in ("Behavior", "Behavior pattern") or f.get("cat") in ("Name", "Binary"):
            continue
        t = legacy_tier(f)
        if not t:
            continue
        single_cred = f.get("source") == "Behavior" and f.get("rule") in DATAFLOW_OWNED
        if single_cred and f.get("file") in ast_files:
            # item 1: the data-flow detector analysed this Python file and owns credential/env evidence for it
            info.append({**f, "info_reason": "Suppressed: this Python file was analysed with data flow by "
                                             "credential_exfiltration, which owns single credential/env indicators."})
            continue
        if single_cred and (where := dev_tooling(f.get("file") or "")):
            info.append({**f, "info_reason": INFO_REASON.format(where=where)})          # item 2
            continue
        out.append(enrich(f, DETECTOR_ID, t))
    cov, detail = text_coverage(ctx, ("text",))
    res = make_result(DETECTOR_ID, PILLAR, "ran", out, coverage=cov, coverage_detail=detail)
    res["info_findings"] = info
    return res
