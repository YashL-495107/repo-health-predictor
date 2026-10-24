"""Behavior scan: malware-like INDICATORS grouped into capability categories and intent-shaped patterns.
Not a malware detector. It never executes anything and 'no findings' never means safe.
Design rules to limit false positives:
  - generic HTTP use is NOT an indicator; only exfil-style endpoints (webhooks, paste sites, raw IPs, .onion)
  - an intent pattern needs 2+ categories in the SAME file (or a hook that runs a suspicious file)
  - files that hit 5+ different rules are treated as detection rulesets/samples and downgraded
  - test/docs/examples folders are skipped
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import PurePosixPath

SKIP_PARTS = {"test", "tests", "testing", "__tests__", "spec", "fixtures", "docs", "doc", "examples", "example",
              "samples", "rules", "signatures"}
SKIP_EXT = {".md", ".json", ".lock", ".svg", ".xml"}
EXEC = re.compile(r"\b(?:exec|eval)\s*\(|\bFunction\s*\(")
LONG = re.compile(r"[A-Za-z0-9+/=_-]{300,}")
IPURL = re.compile(r"https?://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?")

# (category, rule, regex, severity, why)
RULES = [
    ("Obfuscation", "decode-then-execute",
     re.compile(r"\b(?:exec|eval)\s*\(\s*(?:[\w.]*\.)?(?:b64decode|decompress|fromhex|a85decode|b85decode)\b"
                r"|\b(?:exec|eval)\s*\(\s*marshal\.loads|\bFunction\s*\(\s*atob|\beval\s*\(\s*(?:atob|Buffer\.from\([^)]*base64)"),
     "High", "Decodes hidden data and runs it immediately, a common way to hide a payload."),
    ("Network", "exfil-style endpoint",
     re.compile(r"discord(?:app)?\.com/api/webhooks/\d+|api\.telegram\.org/bot\d+:|pastebin\.com/raw|transfer\.sh"
                r"|\.onion\b|ngrok(?:-free)?\.(?:io|app)|webhook\.site|requestbin|pipedream\.net"),
     "Medium", "Webhook, bot, paste or tunnel endpoint: a typical place to send stolen data or fetch a payload."),
    ("Credential access", "reads credential files",
     re.compile(r"\.ssh/(?:id_|authorized_keys)|\.aws/credentials|\.git-credentials|\.docker/config\.json|\.kube/config"
                r"|\.config/gcloud|wallet\.dat|Login Data|/etc/shadow|\.netrc\b"),
     "Medium", "References files that hold keys, tokens or browser/wallet secrets."),
    ("Credential access", "dumps all environment variables",
     re.compile(r"\bdict\(\s*os\.environ\s*\)|\bos\.environ\.copy\(\)|JSON\.stringify\(\s*process\.env\s*\)"
                r"|\bjson\.dumps\(\s*(?:dict\()?os\.environ"),
     "Medium", "Collects every environment variable (CI secrets and API keys live there)."),
    ("Persistence", "installs itself to run later",
     re.compile(r"crontab\s+-|/etc/cron\.|systemctl\s+enable|CurrentVersion\\+Run|schtasks\s+/create|LaunchAgents"
                r"|>>\s*~?/?\.?(?:bashrc|zshrc|profile)\b"),
     "Medium", "Registers something to survive reboots or new shells."),
    ("Remote shell", "reverse-shell pattern",
     re.compile(
         r"/dev/tcp/|\bbash\s+-i\s+>&|\bnc(?:at)?\s+[^\n]*\s-e\s|\bmkfifo\b[^\n]*\bnc\b"),
     "High", "Opens an interactive shell to a remote machine."),
    ("Mining", "cryptominer reference",
     re.compile(
         r"stratum\+(?:tcp|ssl)://|\bxmrig\b|\bminerd\b|cryptonight|coinhive|nicehash", re.I),
     "Medium", "Mining pool or miner software reference."),
]

# intent-shaped patterns: all listed categories must appear in the SAME file
PATTERNS = [
    ("Credential-stealer pattern", {"Credential access", "Network"}),
    ("Dropper / loader pattern", {"Obfuscation", "Network"}),
    ("Hidden persistence payload", {"Obfuscation", "Persistence"}),
    ("Hidden cryptominer", {"Mining", "Persistence"}),
    ("Backdoor / reverse shell", {"Remote shell"}),
]

RISKY_SCRIPT = re.compile(
    r"\b(?:curl|wget|powershell|Invoke-WebRequest|certutil)\b|base64|\beval\b|\bnode\s+-e\b|https?://")
RUNS_FILE = re.compile(
    r"\b(?:node|python3?)\s+(?:\./)?([\w./-]+\.(?:js|cjs|mjs|py))")
SUSPECT_CATS = {"Obfuscation", "Network", "Remote shell", "Credential access"}
POPULAR = {"requests", "urllib3", "numpy", "pandas", "flask", "django", "fastapi", "express", "react", "lodash", "axios",
           "colorama", "setuptools", "boto3", "pillow", "scipy", "pytest", "cryptography", "pyyaml", "jinja2",
           "tensorflow", "torch", "matplotlib", "selenium", "moment", "chalk", "webpack", "discord.py"}


def _scannable(path: str) -> bool:
    p = PurePosixPath(path)
    return (p.suffix.lower() not in SKIP_EXT and not any(x.lower() in SKIP_PARTS for x in p.parts[:-1]))


def _entropy(s: str) -> float:
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def _public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_unspecified or a.is_link_local)


def _lev1(a: str, b: str) -> bool:
    """True if edit distance is exactly 1."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    i = j = d = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        d += 1
        if d > 1:
            return False
        if len(a) > len(b):
            i += 1
        elif len(a) < len(b):
            j += 1
        else:
            i += 1
            j += 1
    return d + (len(a) - i) + (len(b) - j) == 1


def scan_behavior(data: dict, repo: str, url) -> dict:
    text = {p: c for p, c in data["text"].items() if _scannable(p)}
    first: dict = {}
    per_file: dict = defaultdict(dict)  # path -> {category: first line}

    def add(cat, rule, sev, why, path, n):
        k = (rule, path)
        if k in first:
            first[k]["count"] += 1
        else:
            first[k] = {"cat": cat, "rule": rule, "sev": sev,
                        "why": why, "file": path, "line": n, "count": 1}
        per_file[path].setdefault(cat, n)

    for path, content in text.items():
        has_exec = bool(EXEC.search(content))
        for n, raw in enumerate(content.splitlines(), 1):
            if len(raw) < 8:
                continue
            line = raw[:20000]
            for cat, rule, rx, sev, why in RULES:
                if rx.search(line):
                    add(cat, rule, sev, why, path, n)
            for m in IPURL.finditer(line):
                if _public_ip(m.group(1)):
                    add("Network", "URL with a raw IP address", "Medium",
                        "Talks to a bare IP instead of a domain name.", path, n)
            if has_exec and "data:" not in line:
                m = LONG.search(line)
                if m and _entropy(m.group(0)) > 5.0:
                    add("Obfuscation", "large encoded blob next to exec/eval", "Medium",
                        "A long encoded string in a file that also executes dynamic code.", path, n)

    rules_per_file = Counter(p for (_, p) in first)
    rulesets = {p for p, c in rules_per_file.items() if c >= 5}
    findings = []
    for h in first.values():
        note = " (file hits 5+ rules: may be a detection ruleset or sample)" if h["file"] in rulesets else ""
        findings.append({"sev": h["sev"], "source": "Behavior", "cat": h["cat"], "rule": f"{h['cat']}: {h['rule']}",
                         "file": h["file"], "line": h["line"], "detail": h["why"] + (f" ({h['count']} matches)" if h["count"] > 1 else "") + note,
                         "fix": "Open the line and confirm what it does and why it is there.",
                         "url": url(h["file"], h["line"]), "strong": False})

    # intent-shaped patterns (same file, not ruleset-like)
    for path, cats in per_file.items():
        if path in rulesets:
            continue
        for label, need in PATTERNS:
            if need <= cats.keys():
                ln = min(cats[c] for c in need)
                findings.append({"sev": "High", "source": "Behavior pattern", "cat": "Pattern", "rule": label, "file": path, "line": ln,
                                 "detail": "Same file combines: " + " + ".join(sorted(need)) + ". This combination is typical of malware, "
                                           "but security tools and research code can look the same.",
                                 "fix": "Read the file. If it is not what you expect, do not install or run this repository.",
                                 "url": url(path, ln), "strong": True})

    # install-time hooks (package.json scripts, setup.py cmdclass)
    for path, c in data["text"].items():
        name, base = PurePosixPath(path).name, str(PurePosixPath(path).parent)
        base = "" if base == "." else base + "/"
        if name == "package.json":
            try:
                scripts = (json.loads(c).get("scripts") or {})
            except (ValueError, AttributeError):
                continue
            for key in ("preinstall", "install", "postinstall", "prepare"):
                v = scripts.get(key)
                if not isinstance(v, str):
                    continue
                m = RUNS_FILE.search(v)
                target = (base + m.group(1)) if m else None
                runs_bad = bool(target and set(
                    per_file.get(target, {})) & SUSPECT_CATS)
                if runs_bad or RISKY_SCRIPT.search(v):
                    findings.append({"sev": "High" if runs_bad else "Medium", "source": "Behavior pattern" if runs_bad else "Behavior",
                                     "cat": "Install-time execution", "rule": f"Install-time execution: npm {key} script",
                                     "file": path, "line": 1,
                                     "detail": f"Runs automatically on install: {v[:120]}" + (f" and {target} has suspicious indicators" if runs_bad else ""),
                                     "fix": "Check what this script runs. Install hooks are the main way npm malware spreads.",
                                     "url": url(path, 1), "strong": runs_bad})
        elif name == "setup.py" and "cmdclass" in c and re.search(r"subprocess|os\.system|urlopen|requests\.|\bexec\(|\beval\(", c):
            findings.append({"sev": "Medium", "source": "Behavior", "cat": "Install-time execution",
                             "rule": "Install-time execution: custom setup.py command", "file": path, "line": 1,
                             "detail": "setup.py overrides install commands and runs processes or network code.",
                             "fix": "Read the cmdclass code; legitimate for native builds, abused by malicious packages.",
                             "url": url(path, 1), "strong": False})

    # committed executables
    for b in data.get("binaries", []):
        findings.append({"sev": "Medium", "source": "Behavior", "cat": "Binary", "rule": "Binary: compiled executable committed to the repo",
                         "file": b["path"], "line": 1,
                         "detail": f"{b['size'] // 1024} KB, SHA-256 {b['sha256']}. Cannot be reviewed as source; "
                         f"look the hash up at https://www.virustotal.com/gui/file/{b['sha256']}",
                         "fix": "Prefer building from source; verify the hash before trusting it.",
                         "url": url(b["path"], 1), "strong": False})

    # lookalike name
    r = repo.lower()
    twin = next((p for p in POPULAR if _lev1(r, p)), None)
    if twin:
        findings.append({"sev": "Low", "source": "Behavior", "cat": "Name", "rule": "Name resembles a popular package",
                         "file": "(repository name)", "line": 0, "detail": f"'{repo}' is one character away from '{twin}'.",
                         "fix": "Confirm you have the official project (typosquatting check).", "url": None, "strong": False})

    cats = Counter(f["cat"]
                   for f in findings if f["cat"] not in ("Pattern", "Name"))
    strong = [f["rule"] for f in findings if f["strong"]]
    cov = (f"Behavior scan: {len(text)} source/config files checked for malware-like indicators "
           f"({len(rulesets)} ruleset-like files downgraded); {len(strong)} intent-shaped pattern(s), "
           f"{sum(cats.values())} indicator(s), {len(data.get('binaries', []))} committed executable(s). Indicators only, not proof of intent.")
    return {"findings": findings, "profile": {"categories": dict(cats), "patterns": strong}, "coverage": cov}
