"""Batch dependency audit: paste a manifest, get every dependency ranked by what to do about it.

Per dependency:
  * vulnerabilities: OSV.dev, EXACT versions only (pinned '==' or a lockfile)
  * maintenance: registry (PyPI / npm) -> GitHub repo -> last commit, archived, deprecated
The maintenance check is deliberately LIGHT (2 GitHub calls per package: last commit + archived flag),
not the full five-factor score. Findings are evidence for review, never a safety guarantee.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import quote

import requests

from github_client import GitHubClient, GitHubError, RateLimitError
from security import OSV_VULN, action_verdict, osv_scan, parse_package_lock

MAX_PACKAGES = 40
ACTIVE_DAYS, SLOW_DAYS = 180, 730
RANK = ["Replace it", "Review urgently", "Upgrade or review", "Plan to migrate", "Watch it",
        "Not enough data", "Maintenance looks fine, security not assessed",
        "Actively maintained, no unpatched issues found"]

EXAMPLE = "requests==2.19.0\nflask==2.0.0\nurllib3==1.25.0\nPyYAML==5.3\njinja2==2.10\nnumpy>=1.24\n"

GH_RE = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
_PIN = re.compile(
    r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==)\s*([A-Za-z0-9_.+!\-]+)$")
_NAME = re.compile(r"^([A-Za-z0-9_.\-]+)")
_EXACT_NPM = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?")


# ------------------------------------------------------------------ parsing
def parse_manifest(text: str) -> list[dict]:
    """requirements.txt / pip freeze, package.json or package-lock.json -> [{name, version|None, ecosystem}].
    version is None when the file does not pin an exact version. Raises ValueError on bad JSON."""
    t = (text or "").strip()
    if not t:
        return []
    deps: list[dict] = []
    if t.startswith("{"):
        data = json.loads(t)
        if "packages" in data and "lockfileVersion" in data:
            deps = parse_package_lock(t)
        else:
            for name, spec in (data.get("dependencies") or {}).items():
                ok = bool(_EXACT_NPM.fullmatch(str(spec).strip()))
                deps.append({"name": name, "version": str(
                    spec).strip() if ok else None, "ecosystem": "npm"})
    else:
        for line in t.splitlines():
            line = line.split("#")[0].split(";")[0].strip()
            if not line or line.startswith(("-", "git+", "http")):
                continue
            m = _PIN.match(line)
            if m and "*" not in m.group(3):
                deps.append(
                    {"name": m.group(1), "version": m.group(3), "ecosystem": "PyPI"})
            elif _NAME.match(line):
                deps.append({"name": _NAME.match(line).group(
                    1), "version": None, "ecosystem": "PyPI"})
    seen, out = set(), []
    for d in deps:
        k = (d["ecosystem"], d["name"].lower())
        if k not in seen:
            seen.add(k)
            out.append(d)
    return out


# ------------------------------------------------------------------ registry -> GitHub repo
def _gh_from(*urls) -> tuple[str, str] | None:
    for u in urls:
        m = GH_RE.search(str(u or ""))
        if m and m.group(1).lower() != "sponsors":
            return m.group(1), re.sub(r"\.git$", "", m.group(2))
    return None


def registry_info(dep: dict) -> dict:
    """Latest version, GitHub repo and deprecation flag from PyPI or npm."""
    name = dep["name"]
    try:
        if dep["ecosystem"] == "PyPI":
            r = requests.get(
                f"https://pypi.org/pypi/{quote(name)}/json", timeout=15)
            if r.status_code == 404:
                return {"found": False}
            r.raise_for_status()
            info = r.json()["info"]
            urls = info.get("project_urls") or {}
            first = [v for k, v in urls.items() if k.lower() in (
                "source", "source code", "repository", "code", "github", "homepage")]
            inactive = any(
                "Inactive" in c for c in info.get("classifiers") or [])
            return {"found": True, "latest": info.get("version"),
                    "repo": _gh_from(*first, *urls.values(), info.get("home_page")),
                    "deprecated": "Marked Inactive on PyPI" if inactive else None}
        r = requests.get(
            f"https://registry.npmjs.org/{quote(name, safe='@')}/latest", timeout=15)
        if r.status_code == 404:
            return {"found": False}
        r.raise_for_status()
        d = r.json()
        repo = d.get("repository")
        return {"found": True, "latest": d.get("version"),
                "repo": _gh_from(repo.get("url") if isinstance(repo, dict) else repo, d.get("homepage")),
                "deprecated": d.get("deprecated") or None}
    except (requests.RequestException, ValueError, KeyError):
        return {"found": None}


def github_light(owner: str, repo: str, token: str) -> dict:
    """Archived flag + days since last commit (2 API calls)."""
    c = GitHubClient(token)
    meta = c.get(f"/repos/{owner}/{repo}").json()
    r = c.get(f"/repos/{owner}/{repo}/commits",
              {"per_page": 1}, allow=(200, 409))
    commits = [] if r.status_code == 409 else r.json()
    days = None
    if commits:
        last = datetime.fromisoformat(
            commits[0]["commit"]["committer"]["date"].replace("Z", "+00:00"))
        days = max(0, (datetime.now(timezone.utc) - last).days)
    return {"archived": bool(meta.get("archived")), "days": days, "repo": meta.get("full_name", f"{owner}/{repo}")}


def light_label(days, archived: bool, deprecated: str | None) -> str | None:
    if archived:
        return "Archived (read-only)"
    if deprecated:
        return "Likely abandoned"
    if days is None:
        return None
    return "Healthy" if days <= ACTIVE_DAYS else "Slowing down" if days <= SLOW_DAYS else "Likely abandoned"


# ------------------------------------------------------------------ fix versions from OSV
def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def _norm(n: str) -> str:
    return re.sub(r"[-_.]+", "-", n.lower())


@lru_cache(maxsize=512)
def _osv_vuln(vid: str) -> dict | None:
    try:
        r = requests.get(OSV_VULN.format(id=vid), timeout=20)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError):
        return None


def min_safe_version(name: str, installed: str, ids: list[str]) -> str | None:
    """Smallest version above `installed` that fixes every advisory we could read (first 5).
    Approximation: versions are compared by their numeric parts only."""
    needed = []
    for vid in ids[:5]:
        v = _osv_vuln(vid)
        if not v:
            continue
        fixes = [e["fixed"] for a in v.get("affected", []) if _norm((a.get("package") or {}).get("name", "")) == _norm(name)
                 for rg in a.get("ranges", []) for e in rg.get("events", []) if "fixed" in e]
        later = [f for f in fixes if _vkey(f) > _vkey(installed)]
        if later:
            needed.append(min(later, key=_vkey))
    return max(needed, key=_vkey) if needed else None


# ------------------------------------------------------------------ the audit
def _check(dep: dict, token: str) -> dict:
    reg = registry_info(dep)
    out = {"reg": reg, "gh": None, "gh_error": None}
    if reg.get("repo"):
        try:
            out["gh"] = github_light(*reg["repo"], token)
        except RateLimitError:
            out["gh_error"] = "rate"
        except GitHubError:
            out["gh_error"] = "missing"
    return out


def audit(text: str, token: str = "", progress=None, max_packages: int = MAX_PACKAGES) -> dict:
    deps = parse_manifest(text)
    truncated = len(deps) > max_packages
    deps = deps[:max_packages]
    notes: list[str] = []

    exact = [d for d in deps if d["version"]]
    hits: dict[tuple, list[str]] = {}
    osv_ok = True
    if exact:
        try:
            for h in osv_scan(exact):
                hits[(h["ecosystem"], h["name"], h["version"])] = h["ids"]
        except requests.RequestException:
            osv_ok = False
            notes.append(
                "OSV could not be reached, so vulnerabilities were NOT checked.")

    checks: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(_check, d, token): i for i, d in enumerate(deps)}
        for n, f in enumerate(as_completed(futs), 1):
            checks[futs[f]] = f.result()
            if progress:
                progress(n, len(deps))

    rows = []
    for i, d in enumerate(deps):
        c = checks[i]
        reg = c["reg"]
        gh = c["gh"]
        ids = hits.get((d["ecosystem"], d["name"], d["version"]), [])
        if not d["version"] or not osv_ok:
            level = "Not assessed"
        else:
            level = "High" if len(
                ids) >= 3 else "Elevated" if ids else "No unpatched issues found"
        label = light_label(gh["days"] if gh else None,
                            gh["archived"] if gh else False, reg.get("deprecated"))
        fix = min_safe_version(d["name"], d["version"], ids) if ids else None
        if label is None:
            headline, why = ("Upgrade or review", "Known security problems; maintenance status could not be checked.") \
                if ids else ("Not enough data", "No GitHub repository could be found or read for this package, so maintenance was not checked.")
        else:
            headline, why = action_verdict(label, level)
        if fix:
            why += f" Upgrade to at least {fix}."
        notes_row = []
        if not d["version"]:
            notes_row.append("version not pinned: vulnerabilities not scanned")
        if reg.get("found") is False:
            notes_row.append("not found in registry")
        if reg.get("deprecated"):
            notes_row.append(f"deprecated: {reg['deprecated']}"[:90])
        if c["gh_error"] == "rate":
            notes_row.append("GitHub rate limit hit")
        rows.append({"Package": d["name"], "Version": d["version"] or "unpinned", "Verdict": headline, "What to do": why,
                     "Advisories": len(ids), "Maintenance": label or "unknown",
                     "Last commit (days)": gh["days"] if gh else None, "GitHub repo": (gh or {}).get("repo") or "-",
                     "Latest version": reg.get("latest") or "-", "Notes": "; ".join(notes_row)})
    if any(c["gh_error"] == "rate" for c in checks.values()):
        notes.append(
            "GitHub rate limit was reached: some maintenance checks are missing. Add a token and retry.")
    if truncated:
        notes.append(f"Only the first {max_packages} packages were checked.")
    rows.sort(key=lambda r: (RANK.index(
        r["Verdict"]) if r["Verdict"] in RANK else len(RANK), -r["Advisories"]))
    return {"rows": rows, "notes": notes, "unpinned": [r["Package"] for r in rows if r["Version"] == "unpinned"],
            "truncated": truncated}
