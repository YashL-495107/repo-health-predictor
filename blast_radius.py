"""Phase 3: Supply-Chain Blast Radius & Typosquatting Guard.

  1. Reverse-dependent counts from deps.dev (Google Open Source Insights) for PyPI and npm packages.
  2. A 0-100 blast-radius score and tier: how many projects would inherit a compromised release.
  3. A cautious lookalike (typosquat) check. A name match is only a prompt to review, and it is cleared when
     the matched package is itself a widely used project.

Limits (state these out loud):
  - The package name comes from the PyPI release when known, otherwise it is GUESSED from the repository name.
  - Dependents are only counted for PyPI and npm.
  - If deps.dev cannot be reached, a lookalike warning is kept, because it cannot be cleared.
  - Names shorter than 7 characters are never flagged (one-edit matches on short names are mostly real projects).
"""
from __future__ import annotations

import math
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import requests

from repo_behavior import POPULAR, _lev1

TIMEOUT = 8
MIN_SQUAT_LEN = 7             # shorter names are too ambiguous (reach/react, porch/torch, axiom/axios)
LEGIT_DEPENDENTS = 500        # a lookalike with more dependents than this is a real project, not a squat
SQUAT_AFFIXES = ("-official",)  # "-core", "-api", "-utils", "py-" ... are ordinary names, not squats

_DD_CACHE: dict[tuple, dict] = {}


# ------------------------------------------------------------------ deps.dev
def _system_key(system: str) -> str | None:
    s = (system or "").lower()
    return s if s in ("pypi", "npm") else None


def _deps_dev_dependents(system: str, pkg_name: str, version: str = "") -> dict:
    """Reverse-dependency counts from deps.dev. Returns {} if unknown, unsupported or unreachable.
    Successful lookups are cached for the life of the process."""
    sys_key = _system_key(system)
    if not sys_key or not pkg_name:
        return {}
    key = (sys_key, pkg_name.lower(), version)
    if key in _DD_CACHE:
        return dict(_DD_CACHE[key])
    out: dict = {}
    try:
        ver = version
        if not ver:
            r_pkg = requests.get(
                f"https://api.deps.dev/v3/systems/{sys_key}/packages/{quote(pkg_name, safe='')}",
                timeout=TIMEOUT,
            )
            if r_pkg.status_code == 200:
                versions = r_pkg.json().get("versions") or []
                default_v = next((v["versionKey"]["version"] for v in versions if v.get("isDefault")), None)
                ver = default_v or (versions[-1]["versionKey"]["version"] if versions else "")
        if ver:
            r_dep = requests.get(
                f"https://api.deps.dev/v3alpha/systems/{sys_key}/packages/{quote(pkg_name, safe='')}"
                f"/versions/{quote(ver, safe='')}:dependents",
                timeout=TIMEOUT,
            )
            if r_dep.status_code == 200:
                d = r_dep.json()
                out = {
                    "direct_dependents": int(d.get("directDependentCount", 0)),
                    "indirect_dependents": int(d.get("indirectDependentCount", 0)),
                    "total_dependents": int(d.get("dependentCount", 0)),
                }
    except Exception:
        out = {}
    if out:
        _DD_CACHE[key] = out
    return dict(out)


# ------------------------------------------------------------------ lookalike (typosquat) check
def check_typosquat(pkg_name: str) -> str | None:
    """Pure name check, no network. Returns the popular package a name resembles (one edit, adjacent
    transposition, or '<popular>-official'), or None. Names shorter than MIN_SQUAT_LEN are never flagged."""
    clean = (pkg_name or "").lower().strip()
    if len(clean) < MIN_SQUAT_LEN or clean in POPULAR:
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


def confirm_typosquat(pkg_name: str, ecosystem: str = "PyPI") -> str | None:
    """check_typosquat, then clear the match if the name itself is a widely used package (> LEGIT_DEPENDENTS
    dependents on deps.dev). The network lookup only happens when a name already matched. If the lookup
    fails, the warning is kept (it is only ever a 'review' signal)."""
    twin = check_typosquat(pkg_name)
    if not twin:
        return None
    if _deps_dev_dependents(ecosystem, pkg_name).get("total_dependents", 0) > LEGIT_DEPENDENTS:
        return None
    return twin


def detect_typosquatting(pkg_name: str, ecosystem: str | None = None) -> str | None:
    """Kept for audit.py: lookalike check with the deps.dev confirmation."""
    return confirm_typosquat(pkg_name, ecosystem or "PyPI")


# ------------------------------------------------------------------ blast radius
def compute_repo_blast_radius(features: dict, security: dict, release_diff: dict | None = None) -> dict:
    """Estimate how many projects would inherit a compromised or abandoned release of this repository."""
    stars = features.get("stars", 0)
    forks = features.get("forks", 0)

    pkg_label = (release_diff or {}).get("package", "")
    repo_short = (features.get("full_name") or "").split("/")[-1]
    guessed = "==" not in pkg_label
    pkg_name = pkg_label.split("==")[0] if not guessed else repo_short
    version = pkg_label.split("==")[1] if not guessed else ""
    lang = (features.get("language") or "").lower()
    ecosystem = "PyPI" if lang == "python" or pkg_label else ("npm" if lang in ("javascript", "typescript") else "GitHub")

    deps_info = _deps_dev_dependents(ecosystem, pkg_name, version)
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

    twin = confirm_typosquat(pkg_name, ecosystem) if ecosystem in ("PyPI", "npm") else None

    return {
        "package_name": pkg_name,
        "package_name_guessed": guessed,
        "ecosystem": ecosystem,
        "blast_score": blast_score,
        "tier": tier,
        "total_dependents": total_dependents,
        "direct_dependents": direct_dependents,
        "indirect_dependents": indirect_dependents,
        "estimated_downstream_repos": reach_signal,
        "typosquat_warning": (f"'{pkg_name}' may be a lookalike of popular package '{twin}'. "
                              "Verify the publisher and project before installing.") if twin else None,
        "compromise_simulation": (
            f"If `{features.get('full_name')}` were compromised today, an estimated "
            f"{total_dependents:,} downstream packages "
            f"({direct_dependents:,} direct, {indirect_dependents:,} transitive) "
            if total_dependents > 0
            else f"If `{features.get('full_name')}` were compromised today, ~{reach_signal:,} downstream forks/integrations "
        ) + "would inherit the poisoned release within 1 update cycle.",
    }


def analyze_blast_radius(
    features: dict,
    security: dict,
    release_diff: dict | None = None,
    deps: list[dict] | None = None,
) -> dict:
    """Entry point used by app.py: blast radius plus lookalike checks across the repo's dependencies."""
    res = compute_repo_blast_radius(features, security, release_diff)
    typosquat_alerts, pinned, unpinned = [], 0, 0
    for d in deps or []:
        name = d.get("name", "")
        ver = d.get("version") or d.get("spec")
        if ver and ver != "unpinned":
            pinned += 1
        else:
            unpinned += 1
        twin = confirm_typosquat(name, d.get("ecosystem") or "PyPI")
        if twin:
            typosquat_alerts.append({"package": name, "resembles": twin, "ecosystem": d.get("ecosystem", "PyPI")})
    res["typosquat_alerts"] = typosquat_alerts
    res["pinned_deps"] = pinned
    res["unpinned_deps"] = unpinned
    res["total_deps"] = len(deps) if deps else 0
    return res


def enrich_audit_with_blast_radius(rows: list[dict]) -> list[dict]:
    """Add lookalike notes and reverse-dependent counts to Dependency Audit rows (not currently called by the app)."""
    def _enrich_row(r: dict) -> dict:
        row = dict(r)
        name, ver = row.get("Package", ""), row.get("Version", "")
        eco = row.get("Ecosystem") or "PyPI"
        twin = confirm_typosquat(name, eco)
        if twin:
            if row.get("Verdict") != "Replace it":   # never weaken a stronger verdict
                row["Verdict"] = "Review urgently"
            row["What to do"] = (f"Possible lookalike of '{twin}'. Verify the publisher and project before installing. "
                                 + row.get("What to do", "")).strip()
            row["Notes"] = (row.get("Notes", "") + f"; possible lookalike of {twin}").lstrip("; ")
        stats = _deps_dev_dependents(eco, name, "" if ver in ("", "unpinned") else ver)
        row["Downstream Dependents"] = stats.get("total_dependents", 0)
        return row

    with ThreadPoolExecutor(max_workers=6) as pool:
        return list(pool.map(_enrich_row, rows))