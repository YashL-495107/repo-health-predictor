"""Shared, pure analysis of release artifacts for the release-based detectors (no network, nothing executed).

capabilities(release) reads one release's archive contents (as text) and registry fields and returns, per kind,
the evidence for that capability:
  install_hook  npm preinstall/install/postinstall scripts that are not a known build step; a root setup.py whose
                static Layer 2 check reports install-time execution; a .pth file with an "import" line (runs at
                interpreter start-up)
  network       a code file that imports/uses a network API (socket, urllib, requests, httpx, http(s)/net modules,
                fetch) or a hook command that downloads (curl, wget, Invoke-WebRequest, a URL)
  process       a code file that starts processes (subprocess, os.system, os.popen, pty, child_process, spawn)
  decoded       Layer 1 decoder findings (encoded data decoded and executed) that are strong or High
  binary        executables inside the artifact (magic bytes)
Vendored, test and docs paths are ignored for network/process (vendored code bumps are a known benign source), and
so is the root setup.py, which the Layer 2 check judges call by call (git describe, version reads are benign).

delta(new, old) compares two releases and returns the capability kinds and items that are NEW in `new`.
"""
from __future__ import annotations

import re
import threading
from pathlib import PurePosixPath

from malware_proof import scan_ast_deobfuscation, scan_static_setup_py

CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".coffee"}
IGNORE_PARTS = {"vendor", "vendored", "_vendor", "third_party", "third-party", "node_modules", "extern", "test", "tests",
                "testing", "__tests__", "spec", "docs", "doc", "examples", "example", "fixtures", "benchmarks"}
NET = re.compile(r"^\s*(?:import|from)\s+(?:socket|urllib|urllib3|requests|httpx|http\.client|aiohttp|ftplib|smtplib)\b"
                 r"|require\(\s*['\"](?:https?|net|dgram|tls|node-fetch|axios|got|request)['\"]\s*\)"
                 r"|from\s+['\"](?:https?|net|dgram|node-fetch|axios|got)['\"]|\bfetch\(\s*['\"]https?://", re.M)
PROC = re.compile(r"^\s*(?:import|from)\s+(?:subprocess|pty)\b|\bos\.(?:system|popen|exec[lv]p?e?)\s*\("
                  r"|require\(\s*['\"]child_process['\"]\s*\)|from\s+['\"]child_process['\"]|\b(?:execSync|spawnSync|spawn|execFile)\s*\(", re.M)
HOOK_NET = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|iwr|certutil)\b|https?://", re.I)
# Hook commands that are ordinary build steps (no new capability on their own). Documented false-positive control.
BENIGN_HOOK = re.compile(r"^\s*(?:node-gyp(?:-build)?\s+rebuild|node-gyp-build|prebuild-install(?:\s|$)|husky(?:\s+install)?$|"
                         r"patch-package$|tsc(?:\s|$)|npm run build$|node-pre-gyp install(?:\s+--fallback-to-build)?$|cmake-js\s+compile)", re.I)
HOOK_FILE = re.compile(r"\b(?:node|sh|bash|python3?)\s+([\w./-]+\.(?:js|cjs|mjs|sh|py))")
_cache: dict[tuple, dict] = {}
_lock = threading.Lock()


def _code_files(text: dict[str, str]) -> dict[str, str]:
    out = {}
    for p, t in text.items():
        pp = PurePosixPath(p)
        if pp.suffix.lower() in CODE_EXT and not any(x.lower() in IGNORE_PARTS for x in pp.parts[:-1]):
            out[p] = t
    return out


def file_capabilities(path: str, text: str) -> set[str]:
    caps = set()
    if NET.search(text):
        caps.add("network")
    if PROC.search(text):
        caps.add("process")
    return caps


def capabilities(release: dict) -> dict:
    key = (release.get("version"), (release.get("artifact") or {}).get("url"), id(release.get("contents")))
    with _lock:
        if key in _cache:
            return _cache[key]
    contents = release.get("contents") or {}
    text = contents.get("text") or {}
    caps = {"install_hook": {}, "network": {}, "process": {}, "decoded": {}, "binary": {}, "hook_network": {}}

    for hook, cmd in (release.get("install_scripts") or {}).items():
        if BENIGN_HOOK.search(cmd or ""):
            continue
        # keyed by hook AND command, so a changed command counts as a new install-time capability
        caps["install_hook"][f"npm {hook}: {cmd}"] = cmd
        if HOOK_NET.search(cmd or ""):
            caps["hook_network"][f"npm {hook}: {cmd}"] = cmd
        for f in HOOK_FILE.findall(cmd or ""):
            body = text.get(f.lstrip("./"))
            if body and ("network" in file_capabilities(f, body) or HOOK_NET.search(body)):
                caps["hook_network"][f"npm {hook}: {cmd} -> {f}"] = "script makes network calls"
    if "setup.py" in text:
        for f in scan_static_setup_py({"setup.py": text["setup.py"]}, lambda *_: None)["findings"]:
            if f.get("sev") in ("High", "Medium") or f.get("strong"):
                caps["install_hook"]["setup.py " + str(f.get("func") or f.get("rule"))] = f"{f.get('rule')} (line {f.get('line')})"
                if f.get("strong"):
                    caps["hook_network"]["setup.py"] = f.get("rule")
    for p, t in text.items():
        if p.endswith(".pth") and re.search(r"^\s*import\s", t, re.M):
            caps["install_hook"][f"startup file {p}"] = ".pth file with an import line runs at interpreter start-up"

    for p, t in _code_files(text).items():
        if p == "setup.py":   # judged precisely by the Layer 2 check above; a regex hit here would undo its benign calls
            continue
        for c in file_capabilities(p, t):
            caps[c][p] = c
    for f in scan_ast_deobfuscation(text, lambda *_: None)["findings"]:
        if f.get("strong") or f.get("sev") == "High":
            caps["decoded"][f"{f['file']}:{f['line']}"] = f.get("rule")
    for b in contents.get("binaries") or []:
        caps["binary"][b["path"]] = b["sha256"]
    with _lock:
        _cache[key] = caps
    return caps


def unread_relevant(release: dict) -> list[str]:
    """Files skipped by the size limits that the analysis would have looked at (not in ignored folders)."""
    c = release.get("contents") or {}
    return [p for p in c.get("skipped") or []
            if not any(x.lower() in IGNORE_PARTS for x in PurePosixPath(p).parts[:-1])]


def delta(new: dict, old: dict) -> dict:
    """What is NEW in `new` compared with `old`.

    install_hook / decoded / binary / hook_network: new items (by hook name, file:line, path).
    network / process: package level - the capability is new only if `old` had none at all.
    """
    a, b = capabilities(new), capabilities(old)
    out = {}
    for k in ("install_hook", "decoded", "binary", "hook_network"):
        items = {i: v for i, v in a[k].items() if i not in b[k]}
        if items:
            out[k] = items
    for k in ("network", "process"):
        if a[k] and not b[k]:
            out[k] = a[k]
    return out


def assess_pair(new: dict, old: dict) -> dict:
    """Tier for release_delta: high_risk only if a NEW install-time execution capability appears together with
    network access (new at package level, or inside the new hook itself) or new decoded indicators; any single
    new capability on its own is review."""
    d = delta(new, old)
    hook = bool(d.get("install_hook"))
    net = bool(d.get("network")) or bool(d.get("hook_network"))
    dec = bool(d.get("decoded"))
    return {"delta": d, "high_risk": hook and (net or dec), "kinds": sorted(d)}
