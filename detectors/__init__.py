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

from . import (behavior_patterns, ci_workflow, committed_binary, decoded_payload, dependency_injection, lookalike_name,
               osv_advisories, osv_known_malicious, publisher_change, release_delta, release_vs_git, repo_secrets,
               revival_takeover, scorecard, setup_py_hook, tagless_release, virustotal)
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
    behavior_patterns,     # Behavior
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
    pool = cf.ThreadPoolExecutor(max_workers=min(8, max(1, len(registry))))
    try:
        futs = {pool.submit(m.detect, ctx): m for m in registry}
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
    ordered = [results[m.DETECTOR_ID] for m in registry]
    if ctx.fragility:
        from fragility import amplify
        ordered = [amplify(r, ctx.fragility) for r in ordered]
    return ordered
