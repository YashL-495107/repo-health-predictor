"""Helpers shared by the release-based detectors (release_delta, tagless_release, publisher_change)."""
from __future__ import annotations

from .base import enrich, not_applicable, not_assessed

PILLAR = "Integrity"


def release_gate(ctx, detector: str, min_releases: int = 1) -> tuple[dict | None, dict | None]:
    """Returns (early_result, history). early_result is set when the detector cannot run."""
    rc = ctx.releases
    if rc is None:
        sec = ctx.security
        if sec is not None and "package" in sec and not sec.get("package"):
            return not_applicable(detector, PILLAR, "no published package"), None
        return not_assessed(detector, PILLAR, "release history not fetched"), None
    hist = rc.get("history") or {}
    if hist.get("status") == "not_found":
        return not_applicable(detector, PILLAR, hist.get("reason") or "package not published"), None
    if hist.get("status") != "ok":
        return not_assessed(detector, PILLAR, hist.get("reason") or "release lookup failed"), None
    rels = hist.get("releases") or []
    if len(rels) < min_releases:
        return not_applicable(detector, PILLAR, f"only {len(rels)} published release(s), nothing to compare"), None
    return None, hist


def release_finding(detector: str, tier: str, rule: str, detail: str, evidence: list[dict], file: str = "",
                    fix: str = "Compare the two releases by hand before installing.") -> dict:
    base = {"sev": "High" if tier == "high_risk" else "Medium", "source": f"Release history ({detector})",
            "rule": rule, "file": file, "line": None, "detail": detail, "fix": fix, "url": None,
            "strong": tier == "high_risk"}
    return enrich(base, detector, tier, evidence)


def version_pair(hist: dict, new: dict, old: dict | None) -> dict:
    return {"type": "version_pair", "ecosystem": hist.get("ecosystem"), "package": hist.get("name"),
            "new": new["version"], "new_upload_time": new.get("upload_time"),
            "old": old["version"] if old else None, "old_upload_time": old.get("upload_time") if old else None}
