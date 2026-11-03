"""Phase 2: LLM-Assisted Semantic Triage, Migration Engine & Grounded Threat Validation.

Integrates Gemini 2.5 Flash to:
  1. Triage open issues and surface maintained community forks.
  2. Synthesize architectural migration recommendations.
  3. Ground static detection results in structured cybersecurity playbooks
     to provide transparent, step-by-step audit trails.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
import requests

from github_client import GitHubClient, GitHubError, _dt

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
TIMEOUT = 20

KNOWN_REPLACEMENTS = {
    "request/request": [
        {
            "name": "undici / native fetch",
            "ecosystem": "npm / Node.js",
            "effort": "Low (Drop-in API)",
            "why": "Built into modern Node.js (v18+); backed by the Node.js core team.",
            "snippet": "// Old (request)\nrequest('https://example.com', (err, res, body) => {});\n\n// New (Native fetch)\nconst res = await fetch('https://example.com');\nconst body = await res.text();",
        },
        {
            "name": "axios / got",
            "ecosystem": "npm",
            "effort": "Low",
            "why": "Actively maintained HTTP clients with automatic retries, interceptors, and TypeScript support.",
            "snippet": "import got from 'got';\nconst data = await got('https://example.com').json();",
        },
    ],
    "atom/atom": [
        {
            "name": "microsoft/vscode (Visual Studio Code)",
            "ecosystem": "Desktop / Electron",
            "effort": "Low",
            "why": "Huge extension ecosystem, monthly security patches, and native keymap importers for Atom.",
            "snippet": "# Install Atom Keymap in VS Code:\ncode --install-extension ms-vscode.atom-keybindings",
        },
    ],
    "psf/requests": [
        {
            "name": "encode/httpx",
            "ecosystem": "PyPI",
            "effort": "Low (95% API-compatible)",
            "why": "Supports both sync and async/await, HTTP/2, and strict timeouts while mirroring requests' API.",
            "snippet": "# Old\nimport requests\nr = requests.get('https://example.com')\n\n# New (httpx)\nimport httpx\nr = httpx.get('https://example.com')",
        }
    ],
}

ISSUE_CATEGORIES = {
    "Security / Vulnerability": re.compile(
        r"\b(?:cve-\d+|vuln|xss|sqli|rce|exploit|dos|denial of service|bypass|injection|secret|leak)\b", re.I
    ),
    "Crash / Memory / Hang": re.compile(
        r"\b(?:segfault|panic|crash|oom|memory leak|deadlock|hang|freeze|unhandled exception|traceback)\b", re.I
    ),
    "Breaking / Compatibility": re.compile(
        r"\b(?:breaking|deprecat|incompatible|python 3\.\d+|node \d+|regression|fails to build|importError)\b", re.I
    ),
}


def find_active_forks(client: GitHubClient, owner: str, repo: str, upstream_idle_days: int) -> list[dict]:
    try:
        r = client.get(f"/repos/{owner}/{repo}/forks", {"sort": "stargazers", "per_page": 20}, allow=(200, 404))
        if r.status_code != 200 or not isinstance(r.json(), list):
            return []
        forks = r.json()
    except GitHubError:
        return []

    now = datetime.now(timezone.utc)
    candidates = []
    for fk in forks:
        if fk.get("archived") or fk.get("disabled"):
            continue
        pushed = fk.get("pushed_at")
        if not pushed:
            continue
        fork_idle = max(0, (now - _dt(pushed)).days)
        if (upstream_idle_days > 45 and fork_idle < upstream_idle_days - 20) or (
            fk.get("stargazers_count", 0) >= 5 and fork_idle <= 90
        ):
            candidates.append({
                "Fork": fk["full_name"],
                "Stars": fk.get("stargazers_count", 0),
                "Days Since Push": fork_idle,
                "Days Fresher Than Upstream": max(0, upstream_idle_days - fork_idle),
                "URL": fk.get("html_url", f"https://github.com/{fk['full_name']}"),
                "Description": (fk.get("description") or "")[:100],
            })

    candidates.sort(key=lambda x: (-x["Stars"], x["Days Since Push"]))
    return candidates[:5]


def triage_open_issues(client: GitHubClient, owner: str, repo: str) -> dict:
    try:
        r = client.get(
            f"/repos/{owner}/{repo}/issues",
            {"state": "open", "sort": "comments", "direction": "desc", "per_page": 30},
            allow=(200, 404, 410),
        )
        if r.status_code != 200 or not isinstance(r.json(), list):
            return {"counts": {}, "critical_samples": []}
        raw_issues = [i for i in r.json() if "pull_request" not in i]
    except GitHubError:
        return {"counts": {}, "critical_samples": []}

    counts = {k: 0 for k in ISSUE_CATEGORIES}
    counts["General Bug / Feature"] = 0
    critical_samples = []

    for issue in raw_issues:
        title = issue.get("title") or ""
        body = (issue.get("body") or "")[:400]
        labels = " ".join(lbl.get("name", "") for lbl in (issue.get("labels") or []))
        blob = f"{title} {labels} {body}"

        matched_cat = "General Bug / Feature"
        for cat, rx in ISSUE_CATEGORIES.items():
            if rx.search(blob):
                matched_cat = cat
                break
        counts[matched_cat] += 1

        if len(critical_samples) < 8:
            critical_samples.append({
                "number": issue.get("number"),
                "title": title,
                "category": matched_cat,
                "comments": issue.get("comments", 0),
                "created_at": (issue.get("created_at") or "")[:10],
                "url": issue.get("html_url"),
            })

    return {"counts": counts, "critical_samples": critical_samples}


def _call_gemini(api_key: str, prompt: str) -> dict | None:
    if not api_key:
        return None
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }
    try:
        r = requests.post(f"{GEMINI_URL}?key={api_key}", json=payload, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
        return json.loads(text)
    except Exception:
        return None


def validate_threat_with_ai(api_key: str, finding: dict) -> dict | None:
    """
    NEW: Invokes the Gemini API using the `cybersecurity-threat-analysis` skill 
    to validate a static finding.
    """
    if not api_key or not (finding.get("strong") or finding.get("sev") == "High"):
        return None

    rule = finding.get("rule", "")
    detail = finding.get("detail", "")
    file_path = finding.get("file", "")

    prompt = f"""You are a Principal Application Security Auditor.
Your operational guidance is grounded in domain skills:
  - user:cybersecurity-offensive-appsec (Software supply-chain integrity, reverse-shell analysis)
  - user:cybersecurity-detection-response (Threat triage, evasion verification)
  - user:cybersecurity-forensics-intel (Payload decoding, IoC extraction)

Evaluate this static finding flagged in a repository scan:
File: {file_path}
Rule: {rule}
Extracted Evidence / Payload Details: {detail}

Validate whether this finding is a true malicious risk or a benign false positive.
Return ONLY valid JSON matching this exact schema:
{{
  "skill_reference": "user:cybersecurity-offensive-appsec / performing-supply-chain-attack-simulation",
  "attack_vector": "Categorize the threat (e.g., Multi-Stage Obfuscated Dropper, Credential Harvesting, Phantom Release Backdoor)",
  "mathematical_backing": "Explain the mechanics: why does the AST pattern, unhexing, or entropy confirm this is executable code rather than a benign string?",
  "execution_trace": "Step-by-step operational narrative of what this code does if executed in production.",
  "verdict": "Confirmed Malicious Risk | Benign False Positive | Review Required",
  "confidence": "High | Medium | Low"
}}"""

    res = _call_gemini(api_key, prompt)
    if res and isinstance(res, dict) and "verdict" in res:
        return res
    return None


def _fallback_intelligence(features: dict, health_res: dict, issue_triage: dict, forks: list[dict]) -> dict:
    full_name = features.get("full_name", "").lower()
    lang = features.get("language") or "Software"
    topics = ", ".join(features.get("topics") or []) or "general utility"

    alts = KNOWN_REPLACEMENTS.get(full_name)
    if not alts:
        alts = [
            {
                "name": f"Evaluate active {lang} alternatives ({topics})",
                "ecosystem": lang,
                "effort": "Medium (Evaluate API parity)",
                "why": f"Look for actively maintained {lang} packages with multiple core maintainers in '{topics}'.",
                "snippet": "# Add GEMINI_API_KEY to .env or Sidebar to generate migration code.",
            }
        ]

    sec_bugs = issue_triage["counts"].get("Security / Vulnerability", 0)
    crash_bugs = issue_triage["counts"].get("Crash / Memory / Hang", 0)
    compat_bugs = issue_triage["counts"].get("Breaking / Compatibility", 0)

    summary = (
        f"Out of sampled open issues, heuristic triage flagged {sec_bugs} security-related, "
        f"{crash_bugs} crash/memory, and {compat_bugs} compatibility/breaking threads. "
    )
    if forks:
        summary += f"Found {len(forks)} active community fork(s) led by {forks[0]['Fork']}."
    else:
        summary += "No active community takeover forks were detected."

    return {
        "source": "Heuristic Engine (Add GEMINI_API_KEY for AI Deep Synthesis)",
        "executive_memo": f"{features.get('full_name')} is currently rated '{health_res.get('label')}' (Score: {health_res.get('score')}/100). {summary}",
        "issue_triage_summary": summary,
        "alternatives": alts,
    }


def run_intelligence_engine(
    client: GitHubClient,
    owner: str,
    repo: str,
    features: dict,
    health_res: dict,
    malware_findings: list[dict] | None = None,
    gemini_api_key: str = "",
) -> dict:
    api_key = (gemini_api_key or os.getenv("GEMINI_API_KEY") or "").strip()
    idle_days = features.get("days_since_last_commit", 0)

    forks = find_active_forks(client, owner, repo, idle_days)
    triage = triage_open_issues(client, owner, repo)

    prompt = f"""You are a Principal Open-Source Supply Chain Architect.
Analyze this GitHub repository and return a strict JSON object:

Repository: {features.get('full_name')}
Description: {features.get('description')}
Language: {features.get('language')}
Topics: {features.get('topics')}
Health Score: {health_res.get('score')}/100 ({health_res.get('label')})
Days Since Last Commit: {idle_days}
Top Open Issues Sampled: {json.dumps(triage['critical_samples'][:6])}
Active Community Forks Found: {json.dumps(forks[:3])}

Return ONLY valid JSON with this exact structure:
{{
  "executive_memo": "2-sentence architectural risk assessment for an engineering lead deciding whether to depend on this repo.",
  "issue_triage_summary": "2-sentence synthesis of whether the open issues represent critical unpatched regressions/crashes or routine feature requests.",
  "alternatives": [
    {{
      "name": "owner/repo or package name of a modern, actively maintained alternative",
      "ecosystem": "e.g. PyPI / npm / Go / Rust",
      "effort": "Low (Drop-in) | Medium (Adapter needed) | High (Rewrite)",
      "why": "1-sentence explanation of why this alternative is safer and better maintained.",
      "snippet": "Short 4-6 line code example showing how to migrate or import the replacement."
    }}
  ]
}}"""

    llm_out = _call_gemini(api_key, prompt)
    if llm_out and isinstance(llm_out, dict) and "alternatives" in llm_out:
        llm_out["source"] = "Gemini 2.5 Flash AI Triage"
    else:
        llm_out = _fallback_intelligence(features, health_res, triage, forks)

    # Grounded AI Threat Validation for Strong & High-Severity Findings
    # AI Threat Validation (NEW)
    ai_audit_trails = {}
    if api_key:
        for finding in malware_findings:
            if finding.get("strong") or finding.get("sev") == "High":
                validation = validate_threat_with_ai(api_key, finding)
                if trail:
                    key = f"{f.get('file', '')}:{f.get('line', '')}:{f.get('rule', '')}"
                    ai_audit_trails[key] = trail

    return {
        "forks": forks,
        "issue_triage": triage,
        "ai_report": llm_out,
        "ai_audit_trails": ai_audit_trails,
    }