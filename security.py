"""Security & risk layer. Deliberately SEPARATE from the maintenance score in scoring.py.

Maintenance health answers "is anyone looking after this?". This module answers "what known
problems does it have?" using three public sources:
  1. GitHub published security advisories for the repo itself
  2. OSV.dev: known vulnerabilities in the repo's *pinned* dependencies
  3. OpenSSF Scorecard: security-practice checks
"""
from __future__ import annotations
import base64
import json
import re
import requests
from urllib.parse import quote
from github_client import GitHubClient, GitHubError
from malware_proof import _detect_package_identity

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
SCORECARD = "https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}"
TIMEOUT = 20
MAX_DEPS = 500
MAX_DETAIL = 10 
LEVELS = ["Not assessed", "No unpatched issues found", "Elevated", "High"]

def parse_requirements(text: str) -> tuple[list[dict], int]:
    pinned, unpinned = [], 0
    for line in text.splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if not line or line.startswith(("-", "git+", "http")): continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==)\s*([A-Za-z0-9_.+!\-]+)$", line)
        if m and "*" not in m.group(3):
            pinned.append({"name": m.group(1), "version": m.group(3), "ecosystem": "PyPI", "scope": "runtime"})
        elif re.match(r"^[A-Za-z0-9_.\-]+", line):
            unpinned += 1
    return pinned, unpinned

def parse_package_json(text: str) -> tuple[list[dict], int]:
    data = json.loads(text)
    pinned, unpinned = [], 0
    for name, spec in (data.get("dependencies") or {}).items():
        if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?", str(spec).strip()):
            pinned.append({"name": name, "version": spec.strip(), "ecosystem": "npm", "scope": "runtime"})
        else:
            unpinned += 1
    return pinned, unpinned

DEV_REQ_FILE = re.compile(r"(?:^|[-_./])(?:dev|develop|development|test|tests|testing|doc|docs|lint|ci|typing)(?:[-_./]|$)", re.I)
DEV_EXTRAS = {"dev", "develop", "development", "test", "tests", "testing", "doc", "docs", "lint", "typing"}


def dependency_scope(source_file: str, *, npm_dev: bool = False, extra: str | None = None) -> str:
    """'runtime' or 'dev' (since 2026.11.08-11). dev: npm devDependencies or lockfile entries marked dev, requirements
    files named for dev/test/docs (requirements-dev.txt, docs/requirements.txt, test-requirements.txt, ...), and
    extras named dev/test/docs. Only runtime dependencies count toward Exposure review findings and the security caps;
    dev-scope advisories are reported as Info."""
    if npm_dev:
        return "dev"
    if extra and extra.strip().lower() in DEV_EXTRAS:
        return "dev"
    name = source_file.replace("\\", "/").lower()
    if name.endswith((".txt", ".in")) and DEV_REQ_FILE.search(name.rsplit(".", 1)[0]):
        return "dev"
    return "runtime"


def parse_package_lock(text: str) -> list[dict]:
    data = json.loads(text)
    out = []
    for path, info in (data.get("packages") or {}).items():
        if not path or "node_modules/" not in path: continue
        name = path.split("node_modules/")[-1]
        if info.get("version") and not info.get("link"):
            # lockfile v2/v3 marks packages needed only for development ("dev"; "devOptional" is also optional/peer)
            out.append({"name": name, "version": info["version"], "ecosystem": "npm",
                        "scope": dependency_scope("package-lock.json", npm_dev=bool(info.get("dev")))})
    return out

def _read_file(client: GitHubClient, owner: str, repo: str, path: str) -> str | None:
    r = client.get(f"/repos/{owner}/{repo}/contents/{path}", allow=(200, 404))
    if r.status_code == 404: return None
    data = r.json()
    if not isinstance(data, dict) or data.get("encoding") != "base64" or not data.get("content"): return None
    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")

def collect_dependencies(client: GitHubClient, owner: str, repo: str) -> dict:
    deps, unpinned, files = [], 0, []
    txt = _read_file(client, owner, repo, "requirements.txt")
    if txt is not None:
        p, u = parse_requirements(txt)
        deps += p; unpinned += u; files.append("requirements.txt")
    lock = _read_file(client, owner, repo, "package-lock.json")
    if lock is not None:
        try:
            deps += parse_package_lock(lock)
            files.append("package-lock.json")
        except (ValueError, AttributeError): lock = None
    if lock is None:
        pj = _read_file(client, owner, repo, "package.json")
        if pj is not None:
            try:
                p, u = parse_package_json(pj)
                deps += p; unpinned += u; files.append("package.json")
            except ValueError: pass
    seen, uniq = set(), []
    for d in sorted(deps, key=lambda d: d.get("scope") != "runtime"):   # runtime wins when both list a package
        k = (d["ecosystem"], d["name"].lower(), d["version"])
        if k not in seen:
            seen.add(k); uniq.append(d)
    return {"deps": uniq[:MAX_DEPS], "unpinned": unpinned, "files": files, "truncated": len(uniq) > MAX_DEPS}

def osv_scan(deps: list[dict]) -> list[dict]:
    if not deps: return []
    body = {"queries": [{"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]} for d in deps]}
    r = requests.post(OSV_BATCH, json=body, timeout=TIMEOUT)
    r.raise_for_status()
    results = r.json().get("results", [])
    hits = []
    for d, res in zip(deps, results):
        ids = [v["id"] for v in (res or {}).get("vulns", [])]
        if ids:
            is_mal = any(vid.startswith("MAL-") for vid in ids)
            hits.append({**d, "ids": ids, "is_mal": is_mal})
    return hits

def osv_details(vuln_id: str) -> dict:
    try:
        r = requests.get(OSV_VULN.format(id=vuln_id), timeout=TIMEOUT)
        r.raise_for_status()
        v = r.json()
        fixed = sorted({e["fixed"] for a in v.get("affected", []) for rg in a.get("ranges", []) for e in rg.get("events", []) if "fixed" in e})
        return {"summary": v.get("summary") or v.get("id"), "fixed": fixed}
    except (requests.RequestException, ValueError, KeyError): return {}

def repo_advisories(client: GitHubClient, owner: str, repo: str) -> list[dict]:
    r = client.get(f"/repos/{owner}/{repo}/security-advisories", {"state": "published", "per_page": 100}, allow=(200, 404))
    if r.status_code == 404 or not isinstance(r.json(), list): return []
    out = []
    for a in r.json():
        patched = [v.get("patched_versions") for v in a.get("vulnerabilities", []) if v.get("patched_versions")]
        out.append({"id": a.get("ghsa_id"), "cve": a.get("cve_id"), "severity": a.get("severity"),
                    "summary": a.get("summary"), "published": (a.get("published_at") or "")[:10], "patched": bool(patched)})
    return out

def scorecard(owner: str, repo: str) -> dict | None:
    r = requests.get(SCORECARD.format(owner=owner, repo=repo), timeout=TIMEOUT)
    if r.status_code == 404: return None
    r.raise_for_status()
    d = r.json()
    checks = [{"name": c["name"], "score": c["score"], "reason": c.get("reason", "")}
              for c in d.get("checks", []) if isinstance(c.get("score"), (int, float)) and c["score"] >= 0]
    return {"score": d.get("score"), "checks": sorted(checks, key=lambda c: c["score"])}

OSV_QUERY = "https://api.osv.dev/v1/query"


def latest_version(pkg: dict) -> str | None:
    """Latest published version on the registry, or None if it cannot be looked up."""
    name, eco = pkg["name"], pkg["ecosystem"]
    try:
        if eco == "npm":
            r = requests.get(f"https://registry.npmjs.org/{quote(name, safe='@/')}/latest", timeout=TIMEOUT)
            v = r.json().get("version") if r.status_code == 200 else None
        elif eco == "PyPI":
            r = requests.get(f"https://pypi.org/pypi/{quote(name, safe='')}/json", timeout=TIMEOUT)
            v = (r.json().get("info") or {}).get("version") if r.status_code == 200 else None
        else:
            return None
    except (requests.RequestException, ValueError, AttributeError):
        return None
    return str(v).strip() if v else None


def _osv_mal_ids(pkg: dict, version: str | None = None) -> list[str]:
    body = {"package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]}}
    if version:
        body["version"] = version
    r = requests.post(OSV_QUERY, json=body, timeout=TIMEOUT)
    r.raise_for_status()
    return [v["id"] for v in r.json().get("vulns", []) if str(v.get("id", "")).startswith("MAL-")]


def check_own_package_malware(pkg: dict) -> tuple[list[dict], str, bool]:
    """OSV malicious-package check for the repo's OWN published package, against its LATEST version only.
    Returns (findings, coverage_line, is_malicious). Only a MAL- advisory that affects the latest version creates
    the High 'OSV (Confirmed Malware)' finding; MAL- advisories for older versions only give an Info finding."""
    label = f"{pkg['ecosystem']} {pkg['name']}"
    version = latest_version(pkg)
    if not version:
        return [], f"Own package malware check ({label}): NOT run, could not look up the latest published version", False
    current = _osv_mal_ids(pkg, version)
    item = f"{pkg['name']} {version} ({pkg['ecosystem']})"
    if current:
        info = osv_details(current[0])
        return ([{"severity": "High", "source": "OSV (Confirmed Malware)", "item": item,
                  "detail": f"{len(current)} malicious-package advisory(ies) affect the latest release, e.g. {current[0]}: {info.get('summary', '')}."}],
                f"Own package ({label} {version}): latest release is listed in OSV malicious-package advisories", True)
    past = _osv_mal_ids(pkg)
    cov = f"Own package ({label} {version}): latest release checked against OSV malicious-package advisories, none listed"
    if past:
        ids = ", ".join(past[:3]) + ("..." if len(past) > 3 else "")
        return ([{"severity": "Info", "source": "OSV (past malicious release)", "item": f"{pkg['name']} ({pkg['ecosystem']})",
                  "detail": f"Past malicious release(s) of this package were reported ({ids}). The current release is not listed. "
                            "Make sure you install a fixed version."}], cov, False)
    return [], cov, False


def assess_security(client: GitHubClient, owner: str, repo: str) -> dict:
    findings, coverage, level, checked = [], [], 1, 0
    # Structured per-source status for the detector adapters (additive; coverage text is unchanged).
    # Values: "ran" | "not_applicable" | "not_assessed"; *_detail keys add counts.
    checks = {"github_advisories": "not_assessed", "osv_dependencies": "not_assessed",
              "own_package": "not_assessed", "scorecard": "not_assessed"}
    package = None   # {"ecosystem", "name"} of the repo's own published package, from its manifest
    try:
        advs = repo_advisories(client, owner, repo)
        checked += 1
        checks["github_advisories"] = "ran"
        coverage.append(f"GitHub security advisories: {len(advs)} published")
        unpatched = [a for a in advs if not a["patched"]]
        if unpatched:
            level = max(level, 3)
            for a in unpatched[:5]:
                findings.append({"severity": "High", "source": "GitHub advisory", "item": a["id"], "detail": f"{a['summary']} - published {a['published']}, no patched version listed"})
        for a in [x for x in advs if x["patched"]][:5]:
            findings.append({"severity": "Info", "source": "GitHub advisory", "item": a["id"], "detail": f"{a['summary']} - published {a['published']}, patched version exists"})
    except GitHubError as e: coverage.append(f"GitHub security advisories: NOT checked ({e})")

    try:
        dep = collect_dependencies(client, owner, repo)
        if not dep["files"]:
            coverage.append("Dependencies: no requirements.txt / package.json found, NOT checked")
            checks["osv_dependencies"] = "not_applicable"
        else:
            all_hits = osv_scan(dep["deps"])
            is_mal_hit = lambda h: h.get("is_mal") or any(vid.startswith("MAL-") for vid in h["ids"])
            # since 2026.11.08-11: dev/test/docs dependencies do not count toward the level (caps) or review findings;
            # MAL- (malicious package) hits are unchanged in every scope
            hits = [h for h in all_hits if h.get("scope", "runtime") == "runtime" or is_mal_hit(h)]
            dev_hits = [h for h in all_hits if h not in hits]
            checked += 1
            checks["osv_dependencies"] = "ran"
            checks["osv_dependencies_detail"] = {"scanned": len(dep["deps"]), "unpinned_not_scanned": dep["unpinned"],
                                                 "truncated": dep["truncated"], "vulnerable": len(hits),
                                                 "vulnerable_dev_only": len(dev_hits),
                                                 "detailed": min(len(hits), MAX_DETAIL)}
            note = f"Dependencies: scanned {len(dep['deps'])} exact versions from {', '.join(dep['files'])}"
            if dep["unpinned"]: note += f"; {dep['unpinned']} more have no exact version and were NOT scanned"
            coverage.append(note)
            if hits:
                has_mal = any(h.get("is_mal") or any(vid.startswith("MAL-") for vid in h["ids"]) for h in hits)
                level = max(level, 3) if has_mal else max(level, 3 if len(hits) >= 3 else 2)
            sorted_hits = sorted(hits, key=lambda h: (not (h.get("is_mal") or any(vid.startswith("MAL-") for vid in h["ids"]))))
            for h in sorted_hits[:MAX_DETAIL]:
                is_mal = h.get("is_mal") or any(vid.startswith("MAL-") for vid in h["ids"])
                mal_ids = [vid for vid in h["ids"] if vid.startswith("MAL-")]
                main_id = mal_ids[0] if mal_ids else h["ids"][0]
                info = osv_details(main_id)
                fix = f" Fixed in: {', '.join(info['fixed'])}." if info.get("fixed") else ""
                severity = "High" if is_mal else "Elevated"
                source = "OSV (Confirmed Malware)" if is_mal else "OSV (dependency)"
                findings.append({"severity": severity, "source": source, "item": f"{h['name']} {h['version']}", "detail": f"{len(h['ids'])} advisory(ies), e.g. {main_id}: {info.get('summary', '')}.{fix}"})
            for h in dev_hits[:MAX_DETAIL]:
                findings.append({"severity": "Info", "source": "OSV (dev dependency)", "item": f"{h['name']} {h['version']}",
                                 "detail": f"{len(h['ids'])} advisory(ies), e.g. {h['ids'][0]}. Development/test/docs "
                                           "dependency only: not installed for users, so it does not lower the score."})
            if dev_hits:
                coverage.append(f"Dependencies: {len(dev_hits)} vulnerable development-only dependency(ies) reported as Info")
    except (requests.RequestException, ValueError, GitHubError) as e: coverage.append(f"Dependencies: NOT checked ({type(e).__name__})")

    try:
        files = {}
        for fn in ("package.json", "pyproject.toml", "setup.py"):
            t = _read_file(client, owner, repo, fn)
            if t is not None: files[fn] = t
        pkg = _detect_package_identity(files)
        package = pkg
        if pkg:
            own_findings, own_cov, own_mal = check_own_package_malware(pkg)
            findings += own_findings
            coverage.append(own_cov)
            checks["own_package"] = "not_assessed" if "NOT run" in own_cov else "ran"
            if own_mal: level = max(level, 3)
        else:
            checks["own_package"] = "not_applicable"
    except (requests.RequestException, ValueError, GitHubError) as e: coverage.append(f"Own package OSV check: NOT checked ({type(e).__name__})")

    sc = None
    try:
        sc = scorecard(owner, repo)
        if sc is None:
            coverage.append("OpenSSF Scorecard: this repo has not been scanned")
            checks["scorecard"] = "not_available"
        else:
            checked += 1
            checks["scorecard"] = "ran"
            coverage.append(f"OpenSSF Scorecard: overall {sc['score']}/10")
            if isinstance(sc["score"], (int, float)) and sc["score"] < 4: level = max(level, 2)
            for c in sc["checks"][:3]:
                if c["score"] < 5:
                    findings.append({"severity": "Info", "source": "Scorecard", "item": c["name"], "detail": f"{c['score']}/10 - {c['reason']}"})
    except (requests.RequestException, ValueError) as e: coverage.append(f"OpenSSF Scorecard: NOT checked ({type(e).__name__})")
    
    if checked == 0: level = 0
    out = {"level": LEVELS[level], "findings": findings, "coverage": coverage, "scorecard": sc, "checks": checks}
    if checks["own_package"] != "not_assessed" or package:
        out["package"] = package   # only set when the manifest lookup ran (None = no published package)
    return out


def action_verdict(maintenance_label: str, risk_level: str, flagged: bool = False) -> tuple[str, str]:
    dead = maintenance_label in ("Likely abandoned", "Archived (read-only)")
    slow = maintenance_label == "Slowing down"
    risky = risk_level in ("Elevated", "High")
    if dead and risky: return ("Replace it", "Known security problems AND no active maintainers, so fixes are unlikely to arrive.")
    if dead: return ("Plan to migrate", "No unpatched issues found, but nobody is maintaining it, so future problems won't be fixed.")
    if flagged and not risky: return ("Use with caution", "Offensive-security or malware-related terms were found. Such repos can be legitimate research or defensive tools but are dual-use: review the code before running it.")
    if risky and slow: return ("Review urgently", "Known security problems and maintenance is slowing down. Check whether a fix exists.")
    if risky: return ("Upgrade or review", "Known security problems, but maintainers are active, so a fix may be available.")
    if risk_level == "Not assessed": return ("Maintenance looks fine, security not assessed", "The security sources could not be checked. Not assessed does not mean no problems exist.")
    if slow: return ("Watch it", "No unpatched issues found, but activity is slowing down.")
    return ("Actively maintained, no unpatched issues found", "No known vulnerabilities or malware indicators were found by our checks. No findings is not proof: static analysis can miss things.")

OFFENSIVE_TERMS = {"malware", "ransomware", "trojan", "keylogger", "botnet", "backdoor", "rootkit", "spyware", "stealer", "infostealer", "virus", "exploit", "exploits", "payload", "payloads", "c2", "reverse-shell", "shellcode", "pentest", "pentesting", "penetration-testing", "red-team", "redteam", "hacking", "hacktool", "phishing", "ddos", "bruteforce", "brute-force", "credential-stuffing", "offensive-security"}

def content_flags(f: dict) -> list[str]:
    text = " ".join([f.get("full_name") or "", f.get("description") or ""]).lower()
    words = set(re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", text))
    words |= {w for t in f.get("topics") or [] for w in (t.lower(), *t.lower().split("-"))}
    return sorted(w for w in words if w in OFFENSIVE_TERMS)

def apply_gate(res: dict, sec: dict, flags: list[str], scan: dict | None = None, *,
               bus_factor: dict | None = None, features: dict | None = None, as_of=None,
               releases: dict | None = None) -> dict:
    """Combine the maintenance result with security/content evidence into the headline Trust score.

    Keeps the existing evidence caps (known malicious 15; high-risk pattern 49; strong secret/CI 49; unpatched
    advisory or 3+ vulnerable deps 49; vulnerable deps 69; offensive terms 59) and applies them to EVERY repo:
    the earlier exception that skipped caps for "Likely abandoned" / archived repos was removed on purpose.
    On top of them, pillars.compute_trust() turns detector results into four pillars and the weakest-link
    headline. res["score"] / res["label"] now carry the trust score / label; res["maintenance_score"] /
    res["maintenance_label"] keep the maintenance values. New keys: trust_score, pillars, limiting_pillar,
    limiting_kind, limiting_reason, detectors, fragility, partial, partial_reasons, ruleset_version.
    """
    from detectors import RULESET_VERSION, run_detectors
    from detectors.context import DetectorContext
    from fragility import compute_fragility
    from pillars import compute_trust

    out = dict(res)
    out["maintenance_score"], out["maintenance_label"] = res["score"], res["label"]
    reasons, caps = [], []   # caps: (value, short name for "capped by evidence rule: <name>", tier it stands for)

    if sec["level"] == "High":
        caps.append((49, "unpatched advisory or 3+ vulnerable dependencies", "review"))
        reasons.append("Known security problems (unpatched advisory or 3+ vulnerable dependencies): score capped at 49.")
    elif sec["level"] == "Elevated":
        caps.append((69, "vulnerable dependencies", "review"))
        reasons.append("Known security problems found: score capped at 69.")

    if flags:
        caps.append((59, "offensive-security terms in name/description/topics", "review"))
        reasons.append(f"Offensive-security or malware-related terms in name/description/topics ({', '.join(flags)}): score capped at 59. This is a dual-use warning, not proof of harm.")

    scan = scan or {}
    mal_osv = any(f.get("source") == "OSV (Confirmed Malware)" for f in sec.get("findings", []))
    known_mal_count = scan.get("known_malicious_count", 0)
    high_risk_count = scan.get("high_risk_pattern_count", 0)

    if known_mal_count > 0 or mal_osv:
        caps.append((15, "known malicious indicator", "known_malicious"))
        reasons.append("Known-malicious indicator found (OSV malicious-package advisory and/or >=5 antivirus engines).")
    elif high_risk_count > 0:
        caps.append((49, "high-risk pattern", "high_risk"))
        reasons.append("High-risk code pattern(s) found. These are indicators, not proof of malware. Review manually before use.")
    elif scan.get("strong"):
        name = ("strong secret" if scan.get("secrets_strong") else
                "strong CI finding" if scan.get("ci_high") else "strong finding")
        caps.append((49, name, "review"))
        reasons.append(f"Content scan found {scan['strong']} strong finding(s) (possible exposed secrets or high-risk CI patterns): score capped at 49. Static analysis can be wrong, so review each one.")

    out["gate_reasons"] = reasons
    archived = res.get("label") == "Archived (read-only)" or bool((features or {}).get("archived"))
    # fragility describes the project today: dormancy and maintainer count are measured at scan time, not at as_of
    maintainers = ((releases or {}).get("history") or {}).get("maintainers")
    fragility = compute_fragility(res["score"], bus_factor, features, archived=archived, maintainers=maintainers)
    as_of_source = "scan time"
    latest = (((releases or {}).get("history") or {}).get("releases") or [None])[0]
    if as_of is None and latest and latest.get("upload_time"):
        from releases import _dt
        as_of, as_of_source = _dt(latest["upload_time"]), f"upload time of {latest['version']}"
    ctx = DetectorContext.build(as_of=as_of, as_of_source=as_of_source, scan=scan or None, security=sec,
                                features=features, bus_factor=bus_factor, health=res, fragility=fragility,
                                releases=releases)
    detector_results = run_detectors(ctx)
    trust = compute_trust(detector_results, {"score": res["score"], "label": res["label"]}, archived=archived,
                          evidence_caps=caps, security_level=sec.get("level"), content_flags=flags)

    out.update({
        "score": trust["trust_score"], "label": trust["label"], "trust_score": trust["trust_score"],
        "trust_label_base": trust["label_base"], "pillars": trust["pillars"],
        "limiting_pillar": trust["limiting_pillar"], "limiting_kind": trust["limiting_kind"],
        "limiting_reason": trust["limiting_reason"], "partial": trust["partial"],
        "partial_reasons": trust["partial_reasons"], "detectors": detector_results, "fragility": fragility,
        "evidence_caps": [{"value": v, "rule": n, "tier": t} for v, n, t in caps], "ruleset_version": RULESET_VERSION,
        "as_of": ctx.as_of.isoformat() if ctx.as_of else None, "as_of_source": as_of_source,
    })
    return out
