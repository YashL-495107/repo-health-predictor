"""Detector registry and runner.

Add a detector: create detectors/<id>.py with DETECTOR_ID, PILLAR and detect(ctx), then add one line to REGISTRY.
See detectors/base.py for the result contract and tier definitions.

Phase 1 note: the Phase 1 detectors ADAPT an existing check (the malware engine, behavior scan, secret/CI scans
and security.assess_security). Their high_risk tier is today's "strong" finding mapped by base.legacy_tier(),
not a new multi-signal detector. Phase 2 adds release_delta, tagless_release and publisher_change, which read
release history (releases.py) and are new detectors with their own tier logic.
"""
from __future__ import annotations

import concurrent.futures as cf

from . import (behavior_patterns, ci_workflow, committed_binary, credential_exfiltration, decoded_payload,
               dependency_injection, install_hook_target, lookalike_name, osv_advisories, osv_known_malicious, protestware_destructive,
               publisher_change, release_delta, release_vs_git, repo_secrets, revival_takeover, scorecard, setup_py_hook,
               tagless_release, virustotal)
from .base import (FINDING_TIERS, PILLARS, STATUSES, TIER_DISPLAY, TIERS, make_result, not_assessed,  # noqa: F401
                   worst_tier)
from .version import RULESET_VERSION  # noqa: F401

REGISTRY = [
    release_vs_git,        # Integrity
    release_delta,         # Integrity (Phase 2)
    tagless_release,       # Integrity (Phase 2)
    publisher_change,      # Integrity (Phase 2)
    dependency_injection,  # Integrity (Phase 3)
    revival_takeover,      # Integrity (Phase 3)
    decoded_payload,       # Behavior
    setup_py_hook,         # Behavior
    install_hook_target,   # Behavior (ruleset v2)
    behavior_patterns,     # Behavior
    credential_exfiltration,  # Behavior (Phase 4, data flow)
    protestware_destructive,  # Behavior (Phase 4, data flow)
    osv_known_malicious,   # Exposure
    osv_advisories,        # Exposure
    scorecard,             # Exposure
    lookalike_name,        # Exposure
    committed_binary,      # Exposure
    virustotal,            # Exposure
    repo_secrets,          # Exposure
    ci_workflow,           # Exposure
]

DEFAULT_BUDGET_S = 30.0   # overall wall-clock budget for all detectors together
# Detectors whose review-tier findings are single indicators located in a file: in non-shipping paths
# (detectors/paths.py) they become info. Release detectors work on artifact paths and handle this themselves
# (tagless_release: A2); ci_workflow is never non-shipping (.github).
NON_SHIPPING_APPLIES = {"behavior_patterns", "decoded_payload", "credential_exfiltration", "protestware_destructive",
                        "repo_secrets", "committed_binary"}


def downgrade_non_shipping(res: dict) -> dict:
    """review-tier findings of NON_SHIPPING_APPLIES detectors in non-shipping paths -> info_findings (with reason).
    high_risk and known_malicious findings are never touched. Returns a new dict."""
    from .paths import info_reason, non_shipping
    if res.get("detector") not in NON_SHIPPING_APPLIES or res.get("status") != "ran":
        return res
    keep, info = [], list(res.get("info_findings") or [])
    for f in res.get("findings") or []:
        if f.get("tier") == "review" and non_shipping(f.get("file")):
            info.append({**f, "tier": None, "info_reason": info_reason(f["file"])})
        else:
            keep.append(f)
    if len(keep) == len(res.get("findings") or []):
        return res
    return {**res, "findings": keep, "info_findings": info, "tier": worst_tier(f["tier"] for f in keep) or "none_found"}


def _valid(res, mod) -> bool:
    return (isinstance(res, dict) and res.get("detector") == mod.DETECTOR_ID and res.get("pillar") in PILLARS
            and res.get("status") in STATUSES and res.get("tier") in TIERS and isinstance(res.get("findings"), list))


def run_detectors(ctx, budget_s: float = DEFAULT_BUDGET_S, registry=None) -> list[dict]:
    """Run every registered detector in parallel within one overall time budget.

    A detector that raises -> not_assessed("crashed (<ExceptionType>)"); one still running when the budget
    expires -> not_assessed("timeout") (Python threads cannot be killed, so it may finish in the background and
    its result is discarded). Fragility amplification is applied afterwards (fragility.amplify).
    """
    registry = REGISTRY if registry is None else registry
    results: dict[str, dict] = {}
    # Detectors that need the repository contents (NEEDS_DATA) can only run inside scan_repo, where the contents are
    # in memory. When ctx has no data, reuse the result scan_repo already produced for them.
    if ctx.data is None and ctx.scan is not None:
        pre = {d.get("detector"): d for d in (ctx.scan.get("detectors") or []) if isinstance(d, dict)}
        for m in [m for m in registry if getattr(m, "NEEDS_DATA", False) and m.DETECTOR_ID in pre]:
            results[m.DETECTOR_ID] = pre[m.DETECTOR_ID]
        registry_run = [m for m in registry if m.DETECTOR_ID not in results]
    else:
        registry_run = list(registry)
    pool = cf.ThreadPoolExecutor(max_workers=min(8, max(1, len(registry))))
    try:
        futs = {pool.submit(m.detect, ctx): m for m in registry_run}
        done, _pending = cf.wait(futs, timeout=budget_s)
        for fut, mod in futs.items():
            if fut not in done:
                results[mod.DETECTOR_ID] = not_assessed(mod.DETECTOR_ID, mod.PILLAR, "timeout")
                continue
            try:
                res = fut.result()
                results[mod.DETECTOR_ID] = res if _valid(res, mod) else not_assessed(mod.DETECTOR_ID, mod.PILLAR, "invalid result")
            except Exception as e:
                results[mod.DETECTOR_ID] = not_assessed(mod.DETECTOR_ID, mod.PILLAR, f"crashed ({type(e).__name__})")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    ordered = [downgrade_non_shipping(results[m.DETECTOR_ID]) for m in registry]
    if ctx.fragility:
        from fragility import amplify
        ordered = [amplify(r, ctx.fragility) for r in ordered]
    return ordered
