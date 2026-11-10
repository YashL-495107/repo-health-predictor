"""Install-time code tracing (ruleset v2, 2026.11.10-v2). Static only: nothing is executed, imported or installed.

Two tracers, both read the scanned text files (data["text"]) and return findings in the existing finding shape:

npm (trace_npm_hooks, detector install_hook_target)
  For every package.json (outside node_modules / test / docs folders), the preinstall / install / postinstall
  commands are parsed. Each command that runs a local file (`node x.js`, `node ./lib/x.js`, `sh x.sh`,
  `python x.py`, `./x.sh`) or inline code (`node -e "..."`) starts a trace. From each reached JS / shell file the
  tracer follows local references up to MAX_HOPS hops: require('./x'), import ... from './x', import('./x'), and
  string literals naming a local .js/.cjs/.mjs/.sh file (spawn('node', ['index.js']), path.join(__dirname, 'x.js')).
  Rules, applied PER FILE of the traced set (high_risk unless stated):
    N1 host fingerprint + network: os.hostname()/userInfo()/networkInterfaces(), whoami, $(hostname), uname -a or
       JSON.stringify(process.env), together with a network module / fetch / curl-wget-ping-nslookup-dig in the
       same file
    N2 OAST, request-catcher or IP-lookup endpoint in a traced file (oastify, burpcollaborator, *.oast.*,
       interact.sh, dnslog.cn, ceye.io, requestrepo, canarytokens, pipedream, webhook.site, ifconfig.me, ipify,
       ip-api, ipinfo, icanhazip, checkip.amazonaws)
    N3 socket + interactive shell: net.Socket / net.connect / createConnection together with spawning sh / bash /
       cmd / powershell, or the reverse-shell text pattern of the behavior scan
    N4 (review) detached background process: detached: true together with .unref()
  os.platform / os.arch / os.homedir are deliberately NOT fingerprint signals (native-binary installers use them).

PyPI (trace_setup_py, detector setup_py_hook)
  Package-root setup.py: every setup.py at depth <= 2 (the v1 rule); if there is none, the shallowest setup.py
  file(s) outside test / docs / example folders (artifacts and dataset samples are often nested under a temp or
  name-version folder). Calls are resolved through import aliases (`from os import system as s` -> os.system,
  `import subprocess as sp` -> subprocess.*). String constants that parse as Python are analysed as code too (a
  payload written to a temp file and run). Local imports are followed up to two levels: from setup.py, a local
  module that is imported inside a function body or whose imported name is called; from a followed module, its
  local imports. Rules, applied PER FILE (high_risk unless stated):
    P1 host fingerprint (socket.gethostname, platform.node/uname, os.uname, getpass.getuser, os.getlogin,
       uuid.getnode, USER/USERNAME/COMPUTERNAME/HOSTNAME env reads, full environment dumps) + network call
    P2 OAST / request-catcher / IP-lookup endpoint string
    P3 socket + interactive shell (pty.spawn, a process running sh/bash/cmd/powershell, os.dup2)
    P4 process execution + network access (v1's setup.py rule, now alias-resolved and including code strings)
    P5 (review, setup.py only) a single alias-resolved execution or network call (v1 gives the same review for
       direct calls)
Known evasions: computed paths and module names, payloads in files over the read limits or not shipped, other
build backends, code in compiled extensions, network access through a dependency.
"""
from __future__ import annotations

import ast
import json
import re
import shlex
from pathlib import PurePosixPath

MAX_HOPS = 3            # npm: hook target + 3 hops of local references
MAX_FILES = 25          # npm: traced files per hook command
PY_MAX_LEVELS = 2       # PyPI: local-import levels followed from setup.py
PY_MAX_FILES = 15
MAX_CODE_STRINGS = 200  # PyPI: string constants per file tried as code
HOOK_KEYS = ("preinstall", "install", "postinstall")
SKIP_PARTS = {"node_modules", "test", "tests", "__tests__", "spec", "fixtures", "docs", "doc", "examples", "example"}
JS_EXT = (".js", ".cjs", ".mjs")

ENDPOINT = re.compile(
    r"oastify\.com|burpcollaborator\.net|\boast[-.][\w-]*\.?\w*|\.oast\.(?:fun|me|pro|live|site|online)\b|interact\.sh"
    r"|interactsh|dnslog\.cn|ceye\.io|requestrepo\.com|canarytokens\.(?:com|org)|pipedream\.net|webhook\.site"
    r"|ifconfig\.me|ipify\.org|ip-api\.com|ipinfo\.io|icanhazip\.com|checkip\.amazonaws\.com", re.I)

# ---------------------------------------------------------------- npm / JS / shell
JS_FINGERPRINT = re.compile(
    r"\.(?:hostname|userInfo|networkInterfaces)\s*\(\s*\)|\b(?:hostname|userInfo|networkInterfaces)\s*\(\s*\)"
    r"|\bwhoami\b|\$\(\s*hostname\s*\)|`hostname`|\buname\s+-a\b|JSON\.stringify\(\s*process\.env\s*\)")
JS_NETWORK = re.compile(
    r"\brequire\(\s*['\"](?:node:)?(?:https?|http2|net|dns|dgram|tls)['\"]\s*\)"
    r"|\bfrom\s+['\"](?:node:)?(?:https?|http2|net|dns|dgram|tls)['\"]"
    r"|\brequire\(\s*['\"](?:axios|node-fetch|request|got|needle|superagent|undici)['\"]\s*\)"
    r"|\bfetch\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\s*\("
    r"|\b(?:curl|wget|nslookup|dig|ping|Invoke-WebRequest|iwr)\s+[-\w$'\"`{(]")
JS_SOCKET = re.compile(r"\bnew\s+(?:net\.)?Socket\s*\(|\bnet\.(?:connect|createConnection)\s*\(")
JS_SHELL = re.compile(r"\b(?:spawn|spawnSync|exec|execSync|execFile|execFileSync|fork)\s*\(\s*['\"`]"
                      r"(?:/bin/|/usr/bin/)?(?:ba|z|da)?sh(?:\.exe)?['\"`]|['\"`](?:cmd(?:\.exe)?|powershell(?:\.exe)?)['\"`]")
JS_DETACHED = re.compile(r"\bdetached\s*:\s*true\b")
JS_UNREF = re.compile(r"\.unref\s*\(\s*\)")
REQ = re.compile(r"""\brequire\(\s*['"`](\.{1,2}/[^'"`]+)['"`]\s*\)"""
                 r"""|\b(?:import|export)\s[^;'"]*?\bfrom\s*['"](\.{1,2}/[^'"]+)['"]"""
                 r"""|\bimport\(\s*['"](\.{1,2}/[^'"]+)['"]\s*\)""")
FILE_LIT = re.compile(r"""['"`]((?:\.{1,2}/)?[\w@.\-/]*?[\w-]\.(?:c?js|mjs|sh))['"`]""")
SHELL_REF = re.compile(r"\b(?:node|nodejs)\s+(?:--?[\w-]+\s+)*['\"]?((?:\.{1,2}/)?[\w@.\-/]+\.(?:c?js|mjs))"
                       r"|\b(?:sh|bash)\s+['\"]?((?:\.{1,2}/)?[\w@.\-/]+\.sh)")


def _norm(path: str) -> str | None:
    out = []
    for p in path.replace("\\", "/").split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if not out:
                return None
            out.pop()
        else:
            out.append(p)
    return "/".join(out)


def _skipped(path: str) -> bool:
    return any(p.lower() in SKIP_PARTS for p in PurePosixPath(path).parts[:-1])


def _resolve(text: dict, base_dir: str, ref: str, exts=JS_EXT) -> str | None:
    p = _norm((base_dir + "/" if base_dir else "") + ref)
    if p is None:
        return None
    for cand in (p, *(p + e for e in exts), *(p + "/index" + e for e in exts)):
        if cand in text:
            return cand
    return None


def _line_of(content: str, m: re.Match) -> int:
    return content.count("\n", 0, m.start()) + 1


def parse_hook(cmd: str) -> list[tuple[str, str]]:
    """[(kind, value)] for one npm script command: ("file", relative path) or ("inline", code)."""
    out = []
    for seg in re.split(r"&&|\|\||;|\|", cmd or ""):
        try:
            toks = shlex.split(seg, posix=True)
        except ValueError:
            toks = seg.split()
        toks = [t for t in toks if not re.match(r"^[A-Za-z_][\w]*=", t)]          # VAR=value prefixes
        while toks and toks[0] in ("cross-env", "env", "exec", "nohup", "sudo"):
            toks = toks[1:]
        toks = [t for t in toks if t not in (">", ">>", "2>&1", "&") and not re.match(r"^\d?>", t)]
        if not toks:
            continue
        prog = PurePosixPath(toks[0]).name.lower()
        rest = toks[1:]
        if prog in ("node", "nodejs", "node.exe"):
            i = 0
            while i < len(rest):
                t = rest[i]
                if t in ("-e", "--eval", "-p", "--print") and i + 1 < len(rest):
                    out.append(("inline", rest[i + 1]))
                    break
                if t.startswith("-"):
                    i += 1 + (t in ("-r", "--require", "--import", "--loader"))
                    continue
                out.append(("file", t))
                break
        elif prog in ("sh", "bash", "zsh", "dash", "python", "python3", "py"):
            files = [t for t in rest if not t.startswith("-")]
            if "-c" in rest and rest.index("-c") + 1 < len(rest):
                out.append(("inline", rest[rest.index("-c") + 1]))
            elif files:
                out.append(("file", files[0]))
        elif toks[0].startswith(("./", "../")) or toks[0].endswith((".sh", ".js", ".cjs", ".mjs")):
            out.append(("file", toks[0]))
    return out


def _refs(text: dict, path: str, content: str, pkg_dir: str) -> list[str]:
    d = str(PurePosixPath(path).parent)
    d = "" if d == "." else d
    found = []
    for m in REQ.finditer(content):
        r = _resolve(text, d, next(g for g in m.groups() if g))
        if r:
            found.append(r)
    for m in list(FILE_LIT.finditer(content)) + list(SHELL_REF.finditer(content)):
        lit = next(g for g in m.groups() if g)
        r = _resolve(text, d, lit, ()) or _resolve(text, pkg_dir, lit, ())
        if r is None and "/" not in lit:      # bare file name used with a computed directory: unique match only
            hits = [p for p in text if p.startswith(pkg_dir + "/" if pkg_dir else "") and PurePosixPath(p).name == lit]
            r = hits[0] if len(hits) == 1 else None
        if r:
            found.append(r)
    return [r for r in found if r != path]


def js_rules(path: str, content: str) -> list[dict]:
    """Per-file rules N1-N4 (also used for inline `node -e` code, with path '<package.json>:<script>')."""
    out = []
    fp, net = JS_FINGERPRINT.search(content), JS_NETWORK.search(content)
    if fp and net:
        out.append(("N1", "Install hook sends a host fingerprint", True, _line_of(content, fp),
                    f"`{fp.group(0)[:40]}` and `{net.group(0)[:40]}` in the same install-time file."))
    ep = ENDPOINT.search(content)
    if ep:
        out.append(("N2", "Install hook contacts an OAST / IP-lookup endpoint", True, _line_of(content, ep),
                    f"`{ep.group(0)}` in install-time code: out-of-band callback or public-IP lookup services are "
                    "how install-time beacons report where they ran."))
    from repo_behavior import RULES
    rev = next((rx for cat, _r, rx, _s, _w in RULES if cat == "Remote shell"), None)
    sock, sh = JS_SOCKET.search(content), JS_SHELL.search(content)
    revm = rev.search(content) if rev else None
    if (sock and sh) or revm:
        m = revm or sock
        out.append(("N3", "Install hook opens a shell over a socket", True, _line_of(content, m),
                    "A network socket and an interactive shell in the same install-time file (reverse shell)."))
    det = JS_DETACHED.search(content)
    if det and JS_UNREF.search(content):
        out.append(("N4", "Install hook starts a detached background process", False, _line_of(content, det),
                    "`detached: true` with `.unref()`: the process keeps running after npm install returns."))
    return [{"rule_id": r, "rule": f"Install-time execution: {name}", "strong": strong, "file": path, "line": ln,
             "detail": detail} for r, name, strong, ln, detail in out]


def trace_npm_hooks(text: dict) -> dict:
    """{"hooks": [...], "findings": [...]} for every install hook in the scanned files."""
    hooks, findings = [], []
    for pj in sorted(p for p in text if PurePosixPath(p).name == "package.json" and not _skipped(p)):
        try:
            scripts = (json.loads(text[pj]) or {}).get("scripts") or {}
        except (ValueError, AttributeError):
            continue
        if not isinstance(scripts, dict):
            continue
        pkg_dir = str(PurePosixPath(pj).parent)
        pkg_dir = "" if pkg_dir == "." else pkg_dir
        for key in HOOK_KEYS:
            cmd = scripts.get(key)
            if not isinstance(cmd, str):
                continue
            for kind, val in parse_hook(cmd):
                rec = {"package_json": pj, "script": key, "command": cmd[:200], "kind": kind, "traced": [],
                       "missing": None}
                if kind == "inline":
                    src = f"{pj}:{key}"
                    for f in js_rules(src, val):
                        findings.append({**f, "file": pj, "line": 1, "hook": f"npm {key}: {cmd[:120]}",
                                         "trace": [src]})
                    # local files the inline code loads (node -e "require('./postinstall')") are traced like a target
                    starts = list(dict.fromkeys(_refs(text, pj, val, pkg_dir)))
                    if not starts:
                        hooks.append(rec)
                        continue
                else:
                    start = _resolve(text, pkg_dir, val, JS_EXT + (".sh",))
                    if not start:
                        rec["missing"] = val
                        hooks.append(rec)
                        continue
                    starts = [start]
                seen, frontier = list(starts), list(starts)
                for _hop in range(MAX_HOPS):
                    nxt = []
                    for p in frontier:
                        for r in _refs(text, p, text[p], pkg_dir):
                            if r not in seen and len(seen) < MAX_FILES:
                                seen.append(r)
                                nxt.append(r)
                    frontier = nxt
                rec["traced"] = seen
                hooks.append(rec)
                for p in seen:
                    for f in js_rules(p, text[p]):
                        findings.append({**f, "hook": f"npm {key}: {cmd[:120]}",
                                         "trace": seen[: seen.index(p) + 1]})
    # one finding per (rule, file)
    uniq = {}
    for f in findings:
        uniq.setdefault((f["rule_id"], f["file"]), f)
    return {"hooks": hooks, "findings": list(uniq.values())}


# ---------------------------------------------------------------- PyPI / setup.py
PY_EXEC = {"subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
           "subprocess.getoutput", "subprocess.getstatusoutput", "os.system", "os.popen", "os.startfile",
           "os.spawnl", "os.spawnlp", "os.spawnv", "os.spawnvp", "os.execl", "os.execlp", "os.execv", "os.execvp",
           "os.execve", "os.posix_spawn", "pty.spawn", "exec", "eval", "builtins.exec", "builtins.eval",
           "commands.getoutput"}
PY_NET = {"urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.request.Request", "urllib.urlopen",
          "urllib.urlretrieve", "urllib2.urlopen", "requests.get", "requests.post", "requests.put", "requests.patch",
          "requests.request", "requests.head", "requests.Session", "httpx.get", "httpx.post", "httpx.Client",
          "httpx.request", "http.client.HTTPConnection", "http.client.HTTPSConnection", "socket.socket",
          "socket.create_connection", "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex",
          "urllib3.PoolManager", "aiohttp.ClientSession", "dns.resolver.resolve", "dns.resolver.query",
          "smtplib.SMTP", "smtplib.SMTP_SSL", "ftplib.FTP", "telnetlib.Telnet"}
PY_FINGERPRINT = {"socket.gethostname", "socket.getfqdn", "platform.node", "platform.uname", "os.uname",
                  "getpass.getuser", "os.getlogin", "uuid.getnode"}
PY_ENV_NAMES = {"USER", "USERNAME", "LOGNAME", "COMPUTERNAME", "HOSTNAME", "USERDOMAIN"}
PY_SOCKET = {"socket.socket", "socket.create_connection"}
SHELL_ARG = re.compile(r"(?:^|/|\s)(?:ba|z|da)?sh(?:\.exe)?(?:\s+-i\b|$)|\bcmd(?:\.exe)?\b|\bpowershell\b", re.I)
DOWNLOAD = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|iwr|certutil|bitsadmin)\b|https?://", re.I)
BENIGN_TOOLS = ("git", "hg", "svn")


def _aliases(tree) -> dict:
    al = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                al[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
            for a in n.names:
                if a.name != "*":
                    al[a.asname or a.name] = f"{n.module}.{a.name}"
    return al


def _dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _canon(name: str, al: dict) -> str:
    if not name:
        return ""
    head, _, rest = name.partition(".")
    base = al.get(head, head)
    full = f"{base}.{rest}" if rest else base
    if full.startswith("builtins."):
        full = full[len("builtins."):]
    return full


def _strings(node) -> str:
    return " ".join(s.value for s in ast.walk(node) if isinstance(s, ast.Constant) and isinstance(s.value, str))


def _first_tool(node) -> str:
    a = node.args[0] if node.args else None
    if isinstance(a, (ast.List, ast.Tuple)) and a.elts and isinstance(a.elts[0], ast.Constant) \
            and isinstance(a.elts[0].value, str):
        return PurePosixPath(a.elts[0].value).name
    if isinstance(a, ast.Constant) and isinstance(a.value, str):
        parts = a.value.split()
        return PurePosixPath(parts[0]).name if parts else ""
    return ""


def py_caps(tree, depth: int = 0) -> dict:
    """Capability evidence in one parsed module: {"exec": [(line, name)], "net": [...], "fp": [...], "endpoint": [...],
    "shell": [...], "socket": [...]}; string constants that parse as Python are analysed too (one level)."""
    al = _aliases(tree)
    caps = {k: [] for k in ("exec", "net", "fp", "endpoint", "shell", "socket")}
    n_code = 0
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            name = _canon(_dotted(n.func), al)
            ln = getattr(n, "lineno", 1)
            if name in PY_EXEC:
                tool = _first_tool(n)
                if tool not in BENIGN_TOOLS:
                    caps["exec"].append((ln, name))
                    s = _strings(n)
                    if DOWNLOAD.search(s):
                        caps["net"].append((ln, name + " (downloads)"))
                    if name == "pty.spawn" or SHELL_ARG.search(s) or tool in ("sh", "bash", "cmd.exe", "cmd", "powershell"):
                        caps["shell"].append((ln, name))
            if name in PY_NET:
                caps["net"].append((ln, name))
            if name in PY_SOCKET:
                caps["socket"].append((ln, name))
            if name == "os.dup2":
                caps["shell"].append((ln, name))
            if name in PY_FINGERPRINT:
                caps["fp"].append((ln, name))
            if name in ("os.getenv", "os.environ.get") and n.args and isinstance(n.args[0], ast.Constant) \
                    and str(n.args[0].value).upper() in PY_ENV_NAMES:
                caps["fp"].append((ln, f"{name}({n.args[0].value!r})"))
            if name in ("dict", "json.dumps", "str") and n.args and _canon(_dotted(n.args[0]), al) == "os.environ":
                caps["fp"].append((ln, f"{name}(os.environ)"))
            if name == "os.environ.copy":
                caps["fp"].append((ln, name))
        elif isinstance(n, ast.Subscript) and _canon(_dotted(n.value), al) == "os.environ" \
                and isinstance(n.slice, ast.Constant) and str(n.slice.value).upper() in PY_ENV_NAMES:
            caps["fp"].append((getattr(n, "lineno", 1), f"os.environ[{n.slice.value!r}]"))
        elif isinstance(n, ast.Constant) and isinstance(n.value, (str, bytes)):
            s = n.value.decode("utf-8", "ignore") if isinstance(n.value, bytes) else n.value
            m = ENDPOINT.search(s)
            if m:
                caps["endpoint"].append((getattr(n, "lineno", 1), m.group(0)))
            if depth == 0 and n_code < MAX_CODE_STRINGS and 20 <= len(s) <= 20000 and "(" in s \
                    and re.search(r"\bimport\b|\bexec\s*\(|\beval\s*\(|urlopen|requests\.|socket\.", s):
                n_code += 1
                try:
                    sub = ast.parse(s, filename="<scanned-code>")
                except (SyntaxError, ValueError, RecursionError):
                    sub = None
                if sub is not None:
                    inner = py_caps(sub, depth + 1)
                    ln = getattr(n, "lineno", 1)
                    for k, v in inner.items():
                        caps[k].extend((ln, f"{x} (in a code string)") for _l, x in v)
    return caps


def root_setups(text: dict) -> list[str]:
    setups = [p for p in text if PurePosixPath(p).name == "setup.py" and not _skipped(p)]
    shallow = [p for p in setups if len(PurePosixPath(p).parts) <= 2]
    if shallow:
        return sorted(shallow)
    if not setups:
        return []
    d = min(len(PurePosixPath(p).parts) for p in setups)
    return sorted(p for p in setups if len(PurePosixPath(p).parts) == d)


def _local_module(text: dict, base: str, mod: str) -> str | None:
    rel = mod.replace(".", "/")
    for root in (base, (base + "/src") if base else "src"):
        for cand in (f"{rel}.py", f"{rel}/__init__.py"):
            p = _norm((root + "/" if root else "") + cand)
            if p and p in text:
                return p
    return None


def _followed_imports(tree, text: dict, base: str, from_setup: bool, mod_path: str | None = None) -> list[str]:
    """Local modules imported by this module. From setup.py only those imported inside a function body or whose
    imported name / module is called; from a followed module, every local import (absolute and relative)."""
    called = {_dotted(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    called_heads = {c.split(".")[0] for c in called if c}
    in_func = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(fn):
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    in_func.add(id(n))
    out = []
    for n in ast.walk(tree):
        mods = []
        if isinstance(n, ast.Import):
            for a in n.names:
                if not from_setup or id(n) in in_func or (a.asname or a.name.split(".")[0]) in called_heads:
                    mods.append((a.name, 0))
        elif isinstance(n, ast.ImportFrom):
            use = not from_setup or id(n) in in_func or any((a.asname or a.name) in called_heads for a in n.names)
            if use:
                if n.level and mod_path:
                    pkg = PurePosixPath(mod_path).parent
                    for _ in range(n.level - 1):
                        pkg = pkg.parent
                    pkg_s = "" if str(pkg) == "." else str(pkg)
                    for a in ([] if n.module else n.names):
                        mods.append(((pkg_s + "/" if pkg_s else "") + a.name, -1))
                    if n.module:
                        mods.append(((pkg_s + "/" if pkg_s else "") + n.module.replace(".", "/"), -1))
                elif n.module and not n.level:
                    mods.append((n.module, 0))
                    for a in n.names:
                        mods.append((f"{n.module}.{a.name}", 0))     # from pkg import submodule
        for m, kind in mods:
            if kind == -1:
                p = next((c for c in (m + ".py", m + "/__init__.py") if c in text), None)
            else:
                p = _local_module(text, base, m)
            if p:
                out.append(p)
    return out


def _py_rules(path: str, caps: dict, is_setup: bool) -> list[dict]:
    out = []
    f0 = lambda k: caps[k][0]   # noqa: E731
    if caps["fp"] and caps["net"]:
        out.append(("P1", "setup.py install-time code sends a host fingerprint", True, f0("fp")[0],
                    f"`{f0('fp')[1]}` and `{f0('net')[1]}` in the same install-time file."))
    if caps["endpoint"]:
        out.append(("P2", "setup.py install-time code contacts an OAST / IP-lookup endpoint", True, f0("endpoint")[0],
                    f"`{f0('endpoint')[1]}` in install-time code."))
    if caps["socket"] and caps["shell"]:
        out.append(("P3", "setup.py install-time code opens a shell over a socket", True, f0("shell")[0],
                    f"`{f0('socket')[1]}` and `{f0('shell')[1]}` in the same install-time file."))
    if caps["exec"] and caps["net"]:
        out.append(("P4", "process execution and network access in install-time code", True, f0("exec")[0],
                    f"`{f0('exec')[1]}` and `{f0('net')[1]}` in the same install-time file."))
    if is_setup and not out and (caps["exec"] or caps["net"]):
        k = "exec" if caps["exec"] else "net"
        out.append(("P5", "Install-time execution (review)", False, f0(k)[0],
                    f"`{f0(k)[1]}` call in setup.py (runs at build/install time; name resolved through imports)."))
    return [{"rule_id": r, "rule": ("High-Risk Pattern: " if s else "") + name, "strong": s, "file": path, "line": ln,
             "detail": d} for r, name, s, ln, d in out]


def trace_setup_py(text: dict) -> dict:
    """{"setups": [...], "traced": [...], "findings": [...], "parse_errors": [...]}."""
    setups = root_setups(text)
    findings, traced, errors = [], [], []
    for sp in setups:
        base = str(PurePosixPath(sp).parent)
        base = "" if base == "." else base
        level = {sp: 0}
        queue = [sp]
        while queue:
            p = queue.pop(0)
            try:
                tree = ast.parse(text[p], filename="<scanned-code>")
            except (SyntaxError, ValueError, RecursionError):
                errors.append(p)
                continue
            traced.append(p)
            for f in _py_rules(p, py_caps(tree), p == sp):
                findings.append({**f, "trace": [sp] if p == sp else [sp, p], "setup": sp})
            if level[p] < PY_MAX_LEVELS:
                for q in _followed_imports(tree, text, base, p == sp, p):
                    if q not in level and len(level) < PY_MAX_FILES:
                        level[q] = level[p] + 1
                        queue.append(q)
    uniq = {}
    for f in findings:
        uniq.setdefault((f["rule_id"], f["file"]), f)
    return {"setups": setups, "traced": traced, "findings": list(uniq.values()), "parse_errors": errors}
