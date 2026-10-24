"""Phase 3: Supply-Chain Blast Radius, Typosquatting Guard & Compromise Simulator.

Calculates downstream impact if a repository or dependency is compromised or abandoned:
  1. Queries Google Open Source Insights (deps.dev v3 API) & npm for reverse-dependents and downloads.
  2. Computes a 0-100 Supply-Chain Blast Radius Score & classifies infrastructure criticality tier.
  3. Detects zero-day typosquatting & combo-squatting across dependency manifests.
"""
from __future__ import annotations

import math
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import requests

from repo_behavior import POPULAR, _lev1

TIMEOUT = 6
SQUAT_AFFIXES = ("-dev", "-sdk", "-cli", "-official", "-core", "-utils", "-api", "py-", "python-", "node-", "js-")


def check_typosquat(pkg_name: str) -> str | None:
    """Return the popular package name if `pkg_name` is a 1-edit typosquat, transposition, or combo-squat."""
    clean = pkg_name.lower().strip()
    if clean in POPULAR:
        return None
    for pop in POPULAR:
        if _lev1(clean, pop):
            return pop
        if len(clean) == len(pop) and sorted(clean) == sorted(pop):
            diffs = [i for i in range(len(clean)) if clean[i] != pop[i]]
            if len(diffs) == 2 and diffs[1] - diffs[0] == 1:
                return pop
        for afx in SQUAT_AFFIXES:
            if clean == f"{pop}{afx}" or clean == f"{afx}{pop}":
                return pop
    return None


def _deps_dev_dependents(system: str, pkg_name: str, version: str = "") -> dict:
    """Query Google Open Source Insights (deps.dev v3 API) for reverse-dependency counts."""
    sys_key = "pypi" if system.lower() == "pypi" else "npm"
    try:
        if not version:
            r_pkg = requests.get(
                f"https://api.deps.dev/v3/systems/{sys_key}/packages/{quote(pkg_name, safe='')}",
                timeout=TIMEOUT,
            )
            if r_pkg.status_code == 200:
                versions = r_pkg.json().get("versions") or []
                default_v = next((v["versionKey"]["version"] for v in versions if v.get("isDefault")), None)
                version = default_v or (versions[-1]["versionKey"]["version"] if versions else "")
        if not version:
            return {}
        r_dep = requests.get(
            f"https://api.deps.dev/v3alpha/systems/{sys_key}/packages/{quote(pkg_name, safe='')}/versions/{quote(version, safe='')}:dependents",
            timeout=TIMEOUT,
        )
        if r_dep.status_code == 200:
            d = r_dep.json()
            return {
                "direct_dependents": int(d.get("directDependentCount", 0)),
                "indirect_dependents": int(d.get("indirectDependentCount", 0)),
                "total_dependents": int(d.get("dependentCount", 0)),
            }
    except Exception:
        pass
    return {}


def compute_repo_blast_radius(features: dict, security: dict, release_diff: dict | None = None) -> dict:
    """Compute the global blast radius if this repository is compromised or abandoned."""
    stars = features.get("stars", 0)
    forks = features.get("forks", 0)

    pkg_label = (release_diff or {}).get("package", "")
    repo_short = (features.get("full_name") or "").split("/")[-1]
    pkg_name = pkg_label.split("==")[0] if "==" in pkg_label else repo_short
    version = pkg_label.split("==")[1] if "==" in pkg_label else ""
    lang = (features.get("language") or "").lower()
    ecosystem = "PyPI" if lang == "python" or pkg_label else ("npm" if lang in ("javascript", "typescript") else "GitHub")

    deps_info = _deps_dev_dependents(ecosystem, pkg_name, version) if ecosystem in ("PyPI", "npm") else {}
    total_dependents = deps_info.get("total_dependents", 0)
    direct_dependents = deps_info.get("direct_dependents", 0)
    indirect_dependents = deps_info.get("indirect_dependents", 0)

    reach_signal = max(total_dependents, int(forks * 2.5 + stars * 0.4))
    reach_score = min(100.0, 100.0 * math.log1p(reach_signal) / math.log1p(50_000))

    sec_level = security.get("level", "Not assessed")
    sec_mult = 1.35 if sec_level == "High" else (1.15 if sec_level == "Elevated" else 1.0)
    blast_score = round(min(100.0, reach_score * sec_mult), 1)

    if blast_score >= 80 or total_dependents >= 10_000 or stars >= 25_000:
        tier = "Tier-1 Critical Infrastructure"
    elif blast_score >= 55 or total_dependents >= 500 or stars >= 3_000:
        tier = "High Ecosystem Blast Radius"
    elif blast_score >= 30 or total_dependents >= 25 or stars >= 200:
        tier = "Moderate Downstream Impact"
    else:
        tier = "Localized / Leaf Repository"

    twin = check_typosquat(pkg_name)

    return {
        "package_name": pkg_name,
        "ecosystem": ecosystem,
        "blast_score": blast_score,
        "tier": tier,
        "total_dependents": total_dependents,
        "direct_dependents": direct_dependents,
        "indirect_dependents": indirect_dependents,
        "estimated_downstream_repos": reach_signal,
        "typosquat_warning": f"'{pkg_name}' resembles popular package '{twin}' (typosquat/combo-squat check)" if twin else None,
        "compromise_simulation": (
            f"If `{features.get('full_name')}` were compromised today, an estimated "
            f"{total_dependents:,} downstream packages "
            f"({direct_dependents:,} direct, {indirect_dependents:,} transitive) "
            if total_dependents > 0
            else f"If `{features.get('full_name')}` were compromised today, ~{reach_signal:,} downstream forks/integrations "
        ) + "would inherit the poisoned release within 1 update cycle.",
    }


def detect_typosquatting(pkg_name: str, ecosystem: str | None = None) -> str | None:
    """Return the popular package name if pkg_name is a typosquat/combo-squat, or None."""
    return check_typosquat(pkg_name)


def analyze_blast_radius(
    features: dict,
    security: dict,
    release_diff: dict | None = None,
    deps: list[dict] | None = None,
) -> dict:
    """Entry point for Phase 3: Blast Radius, Compromise Simulator & Dependency Typosquats."""
    res = compute_repo_blast_radius(features, security, release_diff)
    typosquat_alerts = []
    pinned = 0
    unpinned = 0
    if deps:
        for d in deps:
            name = d.get("name", "")
            ver = d.get("version") or d.get("spec")
            if ver and ver != "unpinned":
                pinned += 1
            else:
                unpinned += 1
            twin = detect_typosquatting(name, d.get("ecosystem"))
            if twin:
                typosquat_alerts.append({
                    "package": name,
                    "resembles": twin,
                    "ecosystem": d.get("ecosystem", "PyPI"),
                })
    res["typosquat_alerts"] = typosquat_alerts
    res["pinned_deps"] = pinned
    res["unpinned_deps"] = unpinned
    res["total_deps"] = len(deps) if deps else 0
    return res


def enrich_audit_with_blast_radius(rows: list[dict]) -> list[dict]:
    """Enrich Dependency Audit rows with typosquatting checks and reverse-dependent counts."""
    def _enrich_row(r: dict) -> dict:
        row = dict(r)
        name = row.get("Package", "")
        ver = row.get("Version", "")
        twin = check_typosquat(name)
        if twin:
            row["Verdict"] = "Replace it"
            row["What to do"] = f"TYPOSQUATTING ALERT: '{name}' resembles popular package '{twin}'. Verify immediately!"
            row["Notes"] = (row.get("Notes", "") + f"; Typosquat lookalike of {twin}").lstrip("; ")
        dep_stats = _deps_dev_dependents("PyPI", name, "" if ver == "unpinned" else ver)
        row["Downstream Dependents"] = dep_stats.get("total_dependents", 0)
        return row

    with ThreadPoolExecutor(max_workers=6) as pool:
        return list(pool.map(_enrich_row, rows))