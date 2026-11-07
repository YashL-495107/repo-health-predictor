"""Detector contract shared by every detector module.

A detector is `detect(ctx) -> DetectorResult`, where DetectorResult is a plain JSON-serialisable dict:

  detector, pillar ("Integrity" | "Behavior" | "Exposure"), status ("ran" | "not_assessed" | "not_applicable"),
  not_assessed_reason, tier ("known_malicious" | "high_risk" | "review" | "none_found" | "unknown"),
  findings (existing finding keys + detector, tier, evidence, ruleset_version), fragility_amplified,
  and these additive keys: coverage ("full" | "partial" | None), coverage_detail, ruleset_version.

Evidence tiers (never blur these):
  known_malicious  confirmed by an external authority (OSV MAL- advisory, >= 5 antivirus engines on a binary)
  high_risk        a multi-signal combination. IN PHASE 1 this comes from the existing engine's "strong"
                   findings (decoded payloads that reach exec, setup.py exec + network, same-file intent
                   patterns, release-vs-git drift with new capabilities), mapped by legacy_tier(); it is NOT yet
                   produced by the new attack-specific detectors planned for later phases.
  review           a single indicator worth a human look
  none_found       the detector ran and found nothing. This is not a guarantee of anything.
  unknown          the detector could not run

Findings may carry capability_evidence=True when they are backed by code (a hook, network/process code, a decoded
payload, a phantom file with a capability). Only those can be escalated by the fragility index (fragility.py).
"""
from __future__ import annotations

from .version import RULESET_VERSION

PILLARS = ("Integrity", "Behavior", "Exposure")
TIERS = ("known_malicious", "high_risk", "review", "none_found", "unknown")
FINDING_TIERS = ("known_malicious", "high_risk", "review")
TIER_RANK = {"known_malicious": 4, "high_risk": 3, "review": 2, "none_found": 1, "unknown": 0}
TIER_DISPLAY = {"known_malicious": "Known malicious", "high_risk": "High-risk pattern", "review": "Review",
                "none_found": "No findings", "unknown": "Unknown"}
STATUSES = ("ran", "not_assessed", "not_applicable")


def worst_tier(tiers) -> str | None:
    tiers = [t for t in tiers if t]
    return max(tiers, key=lambda t: TIER_RANK[t]) if tiers else None


def make_result(detector: str, pillar: str, status: str, findings: list[dict] | None = None,
                reason: str | None = None, coverage: str | None = None, coverage_detail: str | None = None) -> dict:
    assert pillar in PILLARS and status in STATUSES
    findings = findings or []
    if status == "ran":
        tier = worst_tier(f["tier"] for f in findings) or "none_found"
        coverage = coverage or "full"
    else:
        tier, findings, coverage, coverage_detail = "unknown", [], None, None
    # content_truncated: the repository content scan hit a file cap (read_repo limits; text_coverage() produces the
    # "partial scan: X of Y files" detail). Only this kind of partial coverage adds the headline "Partial assessment"
    # note; sub-signal limits (commit history read, dependency lookups, release metadata) stay in the detector detail.
    content_truncated = bool(status == "ran" and coverage_detail and "partial scan:" in coverage_detail)
    return {"detector": detector, "pillar": pillar, "status": status, "content_truncated": content_truncated,
            "not_assessed_reason": None if status == "ran" else (reason or status.replace("_", " ")),
            "tier": tier, "findings": findings, "fragility_amplified": False,
            "coverage": coverage, "coverage_detail": coverage_detail, "ruleset_version": RULESET_VERSION}


def not_assessed(detector: str, pillar: str, reason: str) -> dict:
    return make_result(detector, pillar, "not_assessed", reason=reason)


def not_applicable(detector: str, pillar: str, reason: str) -> dict:
    return make_result(detector, pillar, "not_applicable", reason=reason)


def legacy_tier(f: dict) -> str | None:
    """Tier for a finding produced by the existing (pre-detector) engine.

    VirusTotal: strong (>= 5 engines) -> known_malicious, else review.
    Other sources: strong -> high_risk (today's "high-risk pattern"); High/Medium -> review; Low/Info -> no tier.
    """
    src = str(f.get("source", ""))
    if "VirusTotal" in src:
        return "known_malicious" if f.get("strong") else "review"
    if f.get("strong"):
        return "high_risk"
    if f.get("sev") in ("High", "Medium"):
        return "review"
    return None


def enrich(f: dict, detector: str, tier: str, evidence: list[dict] | None = None) -> dict:
    """Copy an existing finding and add the detector keys. The original dict is never modified."""
    out = dict(f)
    if evidence is None:
        evidence = [{"type": "file_line", "file": f.get("file"), "line": f.get("line")}] if f.get("file") else []
    out.update({"detector": detector, "tier": tier, "evidence": evidence, "ruleset_version": RULESET_VERSION,
                "fragility_amplified": False})
    return out


def from_security_finding(f: dict, detector: str, tier: str) -> dict:
    """Map an assess_security finding (severity/source/item/detail) onto the existing finding keys."""
    base = {"sev": "High" if f.get("severity") == "High" else ("Medium" if f.get("severity") == "Elevated" else "Low"),
            "source": f.get("source", ""), "rule": f"{f.get('source', '')}: {f.get('item', '')}", "file": "", "line": None,
            "detail": f.get("detail", ""), "fix": "", "url": None, "strong": tier in ("known_malicious", "high_risk")}
    return enrich(base, detector, tier, [{"type": "registry_field", "source": f.get("source", ""), "item": f.get("item", "")}])


def content_gate(ctx, detector: str, pillar: str, layer: str | None = None) -> dict | None:
    """Common checks for detectors that read the repository contents. Returns a not_assessed / not_applicable
    result if the detector cannot run, else None."""
    scan = ctx.scan
    if scan is None:
        return not_assessed(detector, pillar, "content scan not run")
    if not scan.get("ran"):
        return not_assessed(detector, pillar, f"content scan did not run ({scan.get('skip_reason') or 'unknown reason'})")
    proof = scan.get("malware_proof") or {}
    if layer:
        if not proof:
            return not_assessed(detector, pillar, "malware engine did not run")
        st = (proof.get("layers") or {}).get(layer)
        if st is None:
            return None  # older result without layer status: assume it ran
        if st["status"] == "not_assessed":
            return not_assessed(detector, pillar, st.get("reason") or "not assessed")
        if st["status"] == "not_applicable":
            return not_applicable(detector, pillar, st.get("reason") or "not applicable")
    return None


def text_coverage(ctx, kinds=("text",)) -> tuple[str, str | None]:
    """('partial', 'partial scan: X of Y files') if read_repo hit a file cap for any of `kinds`."""
    cov = (ctx.scan or {}).get("scan_coverage") or {}
    partial = [k for k in kinds if cov.get(f"{k}_partial")]
    if not partial:
        return "full", None
    labels = {"text": "text", "py": "Python", "workflows": "workflow"}
    parts = [f"{cov.get(k + '_read')} of {cov.get(k + '_total')} {labels[k]} files" for k in partial]
    return "partial", "partial scan: " + ", ".join(parts)


def proof_findings(ctx) -> list[dict]:
    return list(((ctx.scan or {}).get("malware_proof") or {}).get("findings") or [])


def scan_findings(ctx) -> list[dict]:
    s = ctx.scan or {}
    return list(s.get("findings_all") or s.get("findings") or [])


def security_gate(ctx, detector: str, keys: tuple[str, ...]) -> tuple[dict | None, dict]:
    """Status of the security sources in `keys` (assess_security()['checks']). Returns (early_result, checks)."""
    sec = ctx.security
    if sec is None:
        return not_assessed(detector, "Exposure", "security sources not checked"), {}
    checks = dict(sec.get("checks") or {})
    if not checks:  # older result: infer from the overall level
        status = "not_assessed" if sec.get("level") == "Not assessed" else "ran"
        checks = {k: status for k in keys}
    states = [checks.get(k, "not_assessed") for k in keys]
    if "ran" in states:
        return None, checks
    if all(s in ("not_applicable",) for s in states):
        return not_applicable(detector, "Exposure", "no dependency manifest or published package"), checks
    return not_assessed(detector, "Exposure", "lookup failed or no data: " + ", ".join(f"{k}={s}" for k, s in zip(keys, states))), checks
