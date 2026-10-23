"""Security & risk layer. Deliberately SEPARATE from the maintenance score in scoring.py.

Maintenance health answers "is anyone looking after this?". This module answers "what known
problems does it have?" using three public sources:
  1. GitHub published security advisories for the repo itself
  2. OSV.dev: known vulnerabilities in the repo's *pinned* dependencies
  3. OpenSSF Scorecard: security-practice checks (if the repo has been scanned)

It does NOT detect malware or malicious intent, and "no findings" never means "safe".
Every source reports its own status so the UI can show what was and was not checked.
"""
from __future__ import annotations

import base64
import json
import re

import requests

from github_client import GitHubClient, GitHubError

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
SCORECARD = "https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}"
TIMEOUT = 20
MAX_DEPS = 500
MAX_DETAIL = 10  # fetch summaries/fixed versions for at most this many advisories

LEVELS = ["Not assessed", "No unpatched issues found", "Elevated", "High"]


# ------------------------------------------------------------------ manifest parsing
def parse_requirements(text: str) -> tuple[list[dict], int]:
    """Return (deps with exact '==' pins, count of deps whose version is NOT pinned)."""
    pinned, unpinned = [], 0
    for line in text.splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(
            r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==)\s*([A-Za-z0-9_.+!\-]+)$", line)
        if m and "*" not in m.group(3):
            pinned.append(
                {"name": m.group(1), "version": m.group(3), "ecosystem": "PyPI"})
        elif re.match(r"^[A-Za-z0-9_.\-]+", line):
            unpinned += 1
    return pinned, unpinned


def parse_package_json(text: str) -> tuple[list[dict], int]:
    """Only exact versions (e.g. "4.17.1") are scanned; ranges like ^1.2.0 are counted as unpinned."""
    data = json.loads(text)
    pinned, unpinned = [], 0
    for name, spec in (data.get("dependencies") or {}).items():
        if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?", str(spec).strip()):
            pinned.append(
                {"name": name, "version": spec.strip(), "ecosystem": "npm"})
        else:
            unpinned += 1
    return pinned, unpinned


def parse_package_lock(text: str) -> list[dict]:
    """Resolved versions from package-lock.json (lockfileVersion 2/3). Includes transitive deps."""
    data = json.loads(text)
    out = []
    for path, info in (data.get("packages") or {}).items():
        if not path or "node_modules/" not in path:
            continue  # "" is the root project
        name = path.split("node_modules/")[-1]
        if info.get("version") and not info.get("link"):
            out.append(
                {"name": name, "version": info["version"], "ecosystem": "npm"})
    return out


def _read_file(client: GitHubClient, owner: str, repo: str, path: str) -> str | None:
    """File text from the repo, or None if missing / too large for the contents API (>1 MB)."""
    r = client.get(f"/repos/{owner}/{repo}/contents/{path}", allow=(200, 404))
    if r.status_code == 404:
        return None
    data = r.json()
    if not isinstance(data, dict) or data.get("encoding") != "base64" or not data.get("content"):
        return None
    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")


def collect_dependencies(client: GitHubClient, owner: str, repo: str) -> dict:
    """Find manifests, return exact-version deps to scan plus honest coverage numbers."""
    deps, unpinned, files = [], 0, []
    txt = _read_file(client, owner, repo, "requirements.txt")
    if txt is not None:
        p, u = parse_requirements(txt)
        deps += p
        unpinned += u
        files.append("requirements.txt")
    lock = _read_file(client, owner, repo, "package-lock.json")
    if lock is not None:
        try:
            deps += parse_package_lock(lock)
            files.append("package-lock.json")
        except (ValueError, AttributeError):
            lock = None
    if lock is None:
        pj = _read_file(client, owner, repo, "package.json")
        if pj is not None:
            try:
                p, u = parse_package_json(pj)
                deps += p
                unpinned += u
                files.append("package.json")
            except ValueError:
                pass
    seen, uniq = set(), []
    for d in deps:
        k = (d["ecosystem"], d["name"].lower(), d["version"])
        if k not in seen:
            seen.add(k)
            uniq.append(d)
    return {"deps": uniq[:MAX_DEPS], "unpinned": unpinned, "files": files, "truncated": len(uniq) > MAX_DEPS}


# ------------------------------------------------------------------ sources
def osv_scan(deps: list[dict]) -> list[dict]:
    """Query OSV for exact name+version matches. Returns one dict per vulnerable dependency."""
    if not deps:
        return []
    body = {"queries": [{"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]}
                        for d in deps]}
    r = requests.post(OSV_BATCH, json=body, timeout=TIMEOUT)
    r.raise_for_status()
    results = r.json().get("results", [])
    hits = []
    for d, res in zip(deps, results):
        ids = [v["id"] for v in (res or {}).get("vulns", [])]
        if ids:
            hits.append({**d, "ids": ids})
    return hits


def osv_details(vuln_id: str) -> dict:
    """Summary + fixed versions for one advisory. Best-effort: returns {} on any failure."""
    try:
        r = requests.get(OSV_VULN.format(id=vuln_id), timeout=TIMEOUT)
        r.raise_for_status()
        v = r.json()
        fixed = sorted({e["fixed"] for a in v.get("affected", []) for rg in a.get("ranges", [])
                        for e in rg.get("events", []) if "fixed" in e})
        return {"summary": v.get("summary") or v.get("id"), "fixed": fixed}
    except (requests.RequestException, ValueError, KeyError):
        return {}


def repo_advisories(client: GitHubClient, owner: str, repo: str) -> list[dict]:
    """Published GitHub security advisories filed against this repository itself."""
    r = client.get(f"/repos/{owner}/{repo}/security-advisories",
                   {"state": "published", "per_page": 100}, allow=(200, 404))
    if r.status_code == 404 or not isinstance(r.json(), list):
        return []
    out = []
    for a in r.json():
        patched = [v.get("patched_versions") for v in a.get(
            "vulnerabilities", []) if v.get("patched_versions")]
        out.append({"id": a.get("ghsa_id"), "cve": a.get("cve_id"), "severity": a.get("severity"),
                    "summary": a.get("summary"), "published": (a.get("published_at") or "")[:10],
                    "patched": bool(patched)})
    return out


def scorecard(owner: str, repo: str) -> dict | None:
    """OpenSSF Scorecard result, or None if this repo has not been scanned."""
    r = requests.get(SCORECARD.format(owner=owner, repo=repo), timeout=TIMEOUT)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    d = r.json()
    checks = [{"name": c["name"], "score": c["score"], "reason": c.get("reason", "")}
              for c in d.get("checks", []) if isinstance(c.get("score"), (int, float)) and c["score"] >= 0]
    return {"score": d.get("score"), "checks": sorted(checks, key=lambda c: c["score"])}


# ------------------------------------------------------------------ assessment
def assess_security(client: GitHubClient, owner: str, repo: str) -> dict:
    """Run all three sources. A failing source never crashes the app; it is recorded in 'coverage'."""
    findings, coverage, level, checked = [], [], 1, 0

    # 1) the repo's own published advisories
    try:
        advs = repo_advisories(client, owner, repo)
        checked += 1
        coverage.append(f"GitHub security advisories: {len(advs)} published")
        unpatched = [a for a in advs if not a["patched"]]
        if unpatched:
            level = max(level, 3)
            for a in unpatched[:5]:
                findings.append({"severity": "High", "source": "GitHub advisory", "item": a["id"],
                                 "detail": f"{a['summary']} - published {a['published']}, no patched version listed"})
        for a in [x for x in advs if x["patched"]][:5]:
            findings.append({"severity": "Info", "source": "GitHub advisory", "item": a["id"],
                             "detail": f"{a['summary']} - published {a['published']}, patched version exists"})
    except GitHubError as e:
        coverage.append(f"GitHub security advisories: NOT checked ({e})")

    # 2) vulnerable dependencies (exact versions only)
    try:
        dep = collect_dependencies(client, owner, repo)
        if not dep["files"]:
            coverage.append(
                "Dependencies: no requirements.txt / package.json found, NOT checked")
        else:
            hits = osv_scan(dep["deps"])
            checked += 1
            note = f"Dependencies: scanned {len(dep['deps'])} exact versions from {', '.join(dep['files'])}"
            if dep["unpinned"]:
                note += f"; {dep['unpinned']} more have no exact version and were NOT scanned"
            coverage.append(note)
            if hits:
                level = max(level, 3 if len(hits) >= 3 else 2)
            for h in hits[:MAX_DETAIL]:
                info = osv_details(h["ids"][0])
                fix = f" Fixed in: {', '.join(info['fixed'])}." if info.get(
                    "fixed") else ""
                findings.append({"severity": "Elevated", "source": "OSV (dependency)",
                                 "item": f"{h['name']} {h['version']}",
                                 "detail": f"{len(h['ids'])} advisory(ies), e.g. {h['ids'][0]}: "
                                 f"{info.get('summary', '')}.{fix}"})
    except (requests.RequestException, ValueError, GitHubError) as e:
        coverage.append(f"Dependencies: NOT checked ({type(e).__name__})")

    # 3) OpenSSF Scorecard
    sc = None
    try:
        sc = scorecard(owner, repo)
        if sc is None:
            coverage.append(
                "OpenSSF Scorecard: this repo has not been scanned")
        else:
            checked += 1
            coverage.append(f"OpenSSF Scorecard: overall {sc['score']}/10")
            if isinstance(sc["score"], (int, float)) and sc["score"] < 4:
                level = max(level, 2)
            for c in sc["checks"][:3]:
                if c["score"] < 5:
                    findings.append({"severity": "Info", "source": "Scorecard", "item": c["name"],
                                     "detail": f"{c['score']}/10 - {c['reason']}"})
    except (requests.RequestException, ValueError) as e:
        coverage.append(f"OpenSSF Scorecard: NOT checked ({type(e).__name__})")

    if checked == 0:
        level = 0
    return {"level": LEVELS[level], "findings": findings, "coverage": coverage, "scorecard": sc}


def action_verdict(maintenance_label: str, risk_level: str, flagged: bool = False) -> tuple[str, str]:
    """Combine the two axes into one decision. Returns (headline, explanation).
    Wording never says 'safe'."""
    dead = maintenance_label in ("Likely abandoned", "Archived (read-only)")
    slow = maintenance_label == "Slowing down"
    risky = risk_level in ("Elevated", "High")
    if dead and risky:
        return ("Replace it", "Known security problems AND no active maintainers, so fixes are unlikely to arrive.")
    if dead:
        return ("Plan to migrate", "No unpatched issues found, but nobody is maintaining it, so future problems won't be fixed.")
    if flagged and not risky:
        return ("Use with caution", "Offensive-security or malware-related terms were found. Such repos can be legitimate "
                "research or defensive tools but are dual-use: review the code before running it.")
    if risky and slow:
        return ("Review urgently", "Known security problems and maintenance is slowing down. Check whether a fix exists.")
    if risky:
        return ("Upgrade or review", "Known security problems, but maintainers are active, so a fix may be available.")
    if risk_level == "Not assessed":
        return ("Maintenance looks fine, security not assessed", "The security sources could not be checked. This is not a safety guarantee.")
    if slow:
        return ("Watch it", "No unpatched issues found, but activity is slowing down.")
    return ("Actively maintained, no unpatched issues found",
            "This is NOT a safety guarantee: we do not detect malware or malicious intent.")


# ------------------------------------------------------------------ safety gate
# Whole-word terms (from name, description, topics) that suggest offensive-security or malware content.
OFFENSIVE_TERMS = {
    "malware", "ransomware", "trojan", "keylogger", "botnet", "backdoor", "rootkit", "spyware", "stealer",
    "infostealer", "virus", "exploit", "exploits", "payload", "payloads", "c2", "reverse-shell", "shellcode",
    "pentest", "pentesting", "penetration-testing", "red-team", "redteam", "hacking", "hacktool", "phishing",
    "ddos", "bruteforce", "brute-force", "credential-stuffing", "offensive-security",
}
CAP_HIGH, CAP_ELEVATED, CAP_CONTENT = 49, 69, 59


def content_flags(f: dict) -> list[str]:
    """Offensive/malware-related terms in the repo's name, description or topics. A heuristic, not malware
    detection: it can flag legitimate security tools and miss anything that does not use these words."""
    text = " ".join([f.get("full_name") or "",
                    f.get("description") or ""]).lower()
    words = set(re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", text))
    words |= {w for t in f.get("topics") or []
              for w in (t.lower(), *t.lower().split("-"))}
    return sorted(w for w in words if w in OFFENSIVE_TERMS)


def apply_gate(res: dict, sec: dict, flags: list[str], scan: dict | None = None) -> dict:
    """Make 'health' mean more than activity: known security problems or offensive/malware indicators
    cap the headline score and change the label to 'At risk'. The maintenance-only score is kept."""
    out = dict(res)
    out["maintenance_score"], out["maintenance_label"] = res["score"], res["label"]
    reasons, caps = [], []
    if sec["level"] == "High":
        caps.append(CAP_HIGH)
        reasons.append(
            f"Known security problems (unpatched advisory or 3+ vulnerable dependencies): score capped at {CAP_HIGH}.")
    elif sec["level"] == "Elevated":
        caps.append(CAP_ELEVATED)
        reasons.append(
            f"Known security problems found: score capped at {CAP_ELEVATED}.")
    if flags:
        caps.append(CAP_CONTENT)
        reasons.append(f"Offensive-security or malware-related terms in name/description/topics ({', '.join(flags)}): "
                       f"score capped at {CAP_CONTENT}. This is a dual-use warning, not proof of harm.")
    if scan and scan.get("strong"):
        caps.append(CAP_HIGH)
        reasons.append(f"Content scan found {scan['strong']} strong finding(s) (possible exposed secrets or high-risk CI patterns)"
                       f": score capped at {CAP_HIGH}. Static analysis can be wrong, so review each one.")
    out["gate_reasons"] = reasons
    dead = res["label"] in ("Likely abandoned", "Archived (read-only)")
    if caps and not dead:
        capped = min([res["score"], *caps])
        if capped < res["score"]:
            out["score"], out["label"] = capped, "At risk"
    return out
