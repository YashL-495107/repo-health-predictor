"""credential_exfiltration (Behavior) - credentials or the environment flowing to a network sink.

Python (data flow, ast only; see detectors/pyast.py for the taint model and parsing limits):
  BULK sources   the whole environment (dict(os.environ), os.environ.copy()/items()/keys()/values(), iterating it,
                 {**os.environ}, json.dumps(os.environ), os.environ passed whole to a call other than env=), and
                 foreign secret stores (SSH PRIVATE-KEY files only: id_*, *.pem, *_rsa, *_ed25519, *_ecdsa; not
                 ~/.ssh/config, known_hosts or authorized_keys; browser "Login Data"/Cookies/Local State, crypto
                 wallets, keystores, /etc/shadow, ~/.gnupg). For the SSH client libraries in the HAND-MAINTAINED
                 SSH_CLIENT_LIBS list (paramiko, asyncssh, fabric) SSH keys and SSH_AUTH_SOCK are not sources.
  NAMED sources  one credential-like environment variable read by name (name contains TOKEN, SECRET, PASSWORD, KEY,
                 CREDENTIAL, AUTH, SESSION, COOKIE ...) or a client's own credential file (~/.aws/credentials,
                 ~/.config/gcloud, ~/.netrc, ~/.pypirc, ~/.git-credentials, ~/.npmrc, ~/.docker/config.json,
                 ~/.kube/config). Configuration variables (HTTP_PROXY, HOME, PATH, LANG, ...) are not sources.
  sinks          requests/httpx/urllib/urllib3/aiohttp/http.client/socket calls, and .post/.put/.patch/.sendall/
                 .sendto/.urlopen on any object (plus .send/.request on objects created from those modules)
  destination    resolved from the sink's URL argument (literal, constant variable, f-string prefix):
                 exfil endpoint (Discord/Telegram/Slack-incoming webhooks, paste sites, tunnels, request bins),
                 raw public IP, .onion, unrelated host, known/related host (cloud/registry APIs, or a host sharing a
                 token with the package/repository name, or localhost/private), dynamic (not resolvable)
Tier:
  BULK -> exfil endpoint / raw IP / .onion / unrelated host                = high_risk
  BULK -> known/related host or dynamic destination                        = review
  NAMED -> exfil / raw IP / .onion / unrelated / dynamic destination      = review
  NAMED -> known/related host (a client calling its own API: boto3, gcloud, twine, git helpers) = not flagged
  foreign secret store read with no network sink                          = review ("source without sink")
  bulk environment or named variable with no network sink (copying env for a subprocess, logging) = not flagged
JS / shell: regex only, labelled "pattern match, no data-flow", review at most (never high_risk).
Evidence: source line, sink line, the variable chain, and the sink destination with its class.
capability_evidence is set (code-backed), per the escalation rule (fragility only escalates Integrity anyway).
Known evasions: data passed through function arguments/returns or other modules, obfuscated source names or
URLs (see decoded_payload), destinations built at runtime from non-literals (reported as "dynamic", review),
encrypting/compressing the data before sending (still tracked if done by assignment), exfiltration via DNS or
subprocess (curl) rather than a Python network call, a single named secret sent to a webhook (review, not high_risk).
False-positive sources: telemetry or CI tools that send environment details to their own service under an
unrelated-looking host, backup/sync tools for SSH keys, test code outside the skipped test folders.
"""
from __future__ import annotations

import ast
import ipaddress
import re
from urllib.parse import urlparse

from .base import content_gate, enrich, make_result, text_coverage
from . import pyast

DETECTOR_ID, PILLAR = "credential_exfiltration", "Behavior"
NEEDS_DATA = True

CRED_NAME = re.compile(r"TOKEN|SECRET|PASSW|PASSPHRASE|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH|SESSION|COOKIE|_KEY$", re.I)
NOT_CRED_NAME = re.compile(r"_PROXY$|^NO_PROXY$|CA_BUNDLE|_CERT|KEY_?(FILE|PATH|ID)$", re.I)
# SSH: only private-key files count (id_*, *.pem, *_rsa, *_ed25519, *_ecdsa, *_dsa under .ssh, or a bare id_* name);
# ~/.ssh/config, known_hosts and authorized_keys are not secrets.
SSH_KEY = re.compile(r"\.ssh/(?:id_[\w.-]+|[\w.-]+\.pem|[\w.-]+_(?:rsa|ed25519|ecdsa|dsa))\b|(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)\b", re.I)
FOREIGN_FILE = re.compile(r"\.ssh/(?:id_[\w.-]+|[\w.-]+\.pem|[\w.-]+_(?:rsa|ed25519|ecdsa|dsa))\b|(^|/)id_(rsa|dsa|ecdsa|ed25519)\b|Login Data|(^|/)Cookies$|Local State|wallet\.dat|\.electrum|Exodus|"
                          r"\.bitcoin|\.ethereum|keystore|/etc/shadow|\.gnupg|Local Storage/leveldb", re.I)
FOREIGN_PART = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "login data", "local state", "wallet.dat", ".gnupg", ".electrum"}
# HAND-MAINTAINED alias list: SSH client libraries whose OWN job is to use the user's SSH private keys and the SSH agent
# socket (SSH_AUTH_SOCK). For these packages neither is a source. Add a library here only after checking it is an SSH
# client; any other package reading an SSH private key keeps the foreign-secret-store rules.
SSH_CLIENT_LIBS = {"paramiko", "asyncssh", "fabric"}
CLIENT_FILE = re.compile(r"\.aws/credentials|\.config/gcloud|\.netrc|\.pypirc|\.git-credentials|\.npmrc|\.docker/config\.json|"
                         r"\.kube/config|kubeconfig|pip\.conf|pip\.ini", re.I)
# Which tools own which credential file: a client reading its OWN file (docker -> ~/.docker/config.json) is normal,
# whatever host it then talks to. Matched against the package/repository name tokens, like hosts.
CLIENT_FILE_OWNERS = [
    (re.compile(r"\.docker/config\.json", re.I), {"docker", "dockerpy", "moby", "podman"}),
    (re.compile(r"\.kube/config|kubeconfig", re.I), {"kube", "kubernetes", "k8s", "kubectl", "helm"}),
    (re.compile(r"\.pypirc", re.I), {"twine", "pypi", "flit", "poetry", "hatch", "setuptools", "pdm"}),
    (re.compile(r"pip\.conf|pip\.ini", re.I), {"pip", "pipenv", "pipx", "uv"}),
    (re.compile(r"\.aws/credentials", re.I), {"aws", "boto", "boto3", "botocore", "awscli", "s3", "s3fs", "moto"}),
    (re.compile(r"\.config/gcloud", re.I), {"gcloud", "google", "gcs", "bigquery", "gcsfs"}),
    (re.compile(r"\.git-credentials", re.I), {"git", "gitpython", "dulwich", "github", "gitlab"}),
    (re.compile(r"\.npmrc", re.I), {"npm", "pnpm", "yarn"}),
    (re.compile(r"\.netrc", re.I), {"netrc", "requests", "httpx", "urllib3", "curl", "pycurl"}),
]


def own_client_file(path_literal: str, names: set[str]) -> bool:
    if SSH_KEY.search(path_literal) and SSH_CLIENT_LIBS & names:
        return True
    return any(rx.search(path_literal) and owners & names for rx, owners in CLIENT_FILE_OWNERS)
NET_PREFIX = ("requests.", "httpx.", "urllib.", "urllib3.", "aiohttp.", "http.client.", "socket.", "smtplib.", "ftplib.")
NET_ANY_ATTR = {"post", "put", "patch", "sendall", "sendto", "urlopen", "sendmail", "storbinary"}
NET_OBJ_ATTR = {"send", "request", "get", "connect"}
EXFIL_HOST = re.compile(r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com|pastebin\.com|paste\.ee|"
                        r"hastebin|transfer\.sh|webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app)|"
                        r"\.trycloudflare\.com|interact\.sh|oast\.(?:fun|live|site|me)|burpcollaborator", re.I)
EXFIL_HOSTNAME = re.compile(r"\b(?:discord(?:app)?\.com|api\.telegram\.org|hooks\.slack\.com|pastebin\.com|webhook\.site|"
                            r"transfer\.sh|pipedream\.net|requestbin\.\w+|ngrok(?:-free)?\.(?:io|app))\b", re.I)
LOCAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                 "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]
KNOWN_API = ("amazonaws.com", "aws.amazon.com", "googleapis.com", "google.com", "azure.com", "windows.net",
             "microsoft.com", "pypi.org", "pythonhosted.org", "npmjs.org", "npmjs.com", "github.com",
             "githubusercontent.com", "gitlab.com", "bitbucket.org", "docker.io", "docker.com", "sentry.io",
             "cloudflare.com", "digitalocean.com", "heroku.com", "openai.com", "anthropic.com")
JS_EXT, SH_EXT = (".js", ".mjs", ".cjs", ".ts"), (".sh", ".bash")
FILE_ACCESS = ("open", "io.open", "Path", "pathlib.Path", "os.path.expanduser", "os.path.join", "shutil.copy",
               "shutil.copyfile", "shutil.copy2", "shutil.make_archive", "zipfile.ZipFile", "tarfile.open")
FILE_ACCESS_ATTR = {"read_text", "read_bytes", "open", "glob", "rglob", "iterdir"}
STOP_TOKENS = {"python", "client", "core", "lib", "libs", "tools", "utils", "util", "http", "https", "github", "main",
               "test", "tests", "plugin", "plugins", "official", "project", "package", "server", "service", "data"}
JS_BULK = re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)|\.\.\.process\.env|"
                     r"readFileSync\([^)]*(?:\.ssh|id_rsa|Login Data|wallet)")
JS_SINK = re.compile(r"https?\.request\(|\bfetch\(|axios\.|XMLHttpRequest|net\.connect\(|\.post\(")
SH_EXFIL = re.compile(r"\b(?:env|printenv)\b\s*\|\s*(?:curl|wget|nc)\b|cat\s+[^|\n]*(?:\.ssh|id_rsa)[^|\n]*\|\s*(?:curl|nc|wget)|"
                      r"curl[^\n]*-d\s*[\"']?\$\((?:env|printenv|cat [^)]*\.ssh)")


# ---------------------------------------------------------------- source classification

def _env_occurrence(node, par, al, owner_names: set[str] | None = None) -> dict | None:
    """Classify one use of os.environ: bulk, named credential, or None (not a source)."""
    p = par.get(id(node))
    if isinstance(p, ast.Subscript) and p.value is node:
        key = pyast.fold_str(p.slice)
        return _named(key, node.lineno, owner_names)
    if isinstance(p, ast.Attribute) and p.value is node:
        gp = par.get(id(p))
        if p.attr in ("get", "setdefault", "pop") and isinstance(gp, ast.Call) and gp.args:
            return _named(pyast.fold_str(gp.args[0]), node.lineno, owner_names)
        if p.attr in ("items", "keys", "values", "copy"):
            return {"kind": "bulk_env", "line": node.lineno, "what": f"os.environ.{p.attr}()"}
        return None
    if isinstance(p, ast.keyword) and p.arg == "env":
        return None                                # subprocess(..., env=os.environ): passing it on, not collecting
    if isinstance(p, (ast.For, ast.comprehension)) and p.iter is node:
        return {"kind": "bulk_env", "line": node.lineno, "what": "iterating os.environ"}
    if isinstance(p, (ast.Call, ast.Dict)):
        return {"kind": "bulk_env", "line": node.lineno, "what": "the whole os.environ"}
    return None


def _named(key, line, owner_names: set[str] | None = None) -> dict | None:
    if key == "SSH_AUTH_SOCK" and SSH_CLIENT_LIBS & (owner_names or set()):
        return None   # the SSH agent socket is an SSH client library's own credential channel
    if key and CRED_NAME.search(key) and not NOT_CRED_NAME.search(key):
        return {"kind": "named_env", "line": line, "what": f"environment variable {key}"}
    return None


def expr_sources(expr, par, al, taint, owner_names: set[str] | None = None) -> list[dict]:
    out = []
    for n in ast.walk(expr):
        if isinstance(n, (ast.Attribute, ast.Name)) and pyast.dotted(n, al) == "os.environ":
            if isinstance(n, ast.Name) or isinstance(n.value, ast.Name):
                s = _env_occurrence(n, par, al, owner_names)
                if s:
                    out.append(s)
        elif isinstance(n, ast.Call) and pyast.dotted(n.func, al) in ("os.getenv", "os.environ.get") and n.args:
            if pyast.dotted(n.func, al) == "os.getenv":
                s = _named(pyast.fold_str(n.args[0]), n.lineno, owner_names)
                if s:
                    out.append(s)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            v = n.value
            if (FOREIGN_FILE.search(v) or v.strip().lower() in FOREIGN_PART) and own_client_file(v, owner_names or set()):
                continue   # an SSH client library using the user's own keys (hand-maintained SSH_CLIENT_LIBS)
            if FOREIGN_FILE.search(v) or v.strip().lower() in FOREIGN_PART:
                out.append({"kind": "foreign_file", "line": n.lineno, "what": f"secret store path '{v[:60]}'"})
            elif CLIENT_FILE.search(v):
                if own_client_file(v, owner_names or set()):
                    continue   # the package's own credential file (docker reading ~/.docker/config.json): not a source
                out.append({"kind": "client_file", "line": n.lineno, "what": f"client credential file '{v[:60]}'"})
        if isinstance(n, (ast.Name, ast.Attribute)):
            key = n.id if isinstance(n, ast.Name) else pyast.dotted(n)
            for t in taint.get(key, []):
                out.append(t)
    return out


# ---------------------------------------------------------------- sinks and destinations

def _is_sink(call: ast.Call, al, net_objs: set[str]) -> bool:
    name = pyast.dotted(call.func, al)
    if not name:
        return False
    if name.startswith(NET_PREFIX) or name in ("urlopen", "post", "put", "patch"):
        return True
    attr = name.rsplit(".", 1)[-1]
    recv = name.rsplit(".", 1)[0] if "." in name else ""
    return attr in NET_ANY_ATTR or (attr in NET_OBJ_ATTR and recv in net_objs)


def _resolve(node, consts: dict[str, str]) -> str | None:
    v = pyast.fold_str(node)
    if v is not None:
        return v
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.Tuple) and node.elts:      # socket.connect((host, port))
        return _resolve(node.elts[0], consts)
    return None


def destination(call: ast.Call, consts, related_tokens: set[str]) -> dict:
    cand = list(call.args[:1]) + [k.value for k in call.keywords if k.arg in ("url", "address", "host")]
    raw = next((r for r in (_resolve(c, consts) for c in cand) if r), None)
    if not raw:
        return {"class": "dynamic", "value": None}
    host = urlparse(raw if "://" in raw else "//" + raw).hostname or raw
    if EXFIL_HOST.search(raw):
        return {"class": "exfil endpoint", "value": raw[:120], "host": host}
    if host.endswith(".onion"):
        return {"class": ".onion", "value": raw[:120], "host": host}
    try:
        ip = ipaddress.ip_address(host)
        # only RFC 1918 / loopback / link-local / unique-local count as local; Python's is_private also covers
        # documentation and other special ranges, which for this purpose are just raw IPs
        if any(ip in n for n in LOCAL_NETS):
            return {"class": "known/related host", "value": raw[:120], "host": host, "why": "local/private address"}
        return {"class": "raw IP", "value": raw[:120], "host": host}
    except ValueError:
        pass
    h = host.lower()
    if h in ("localhost",) or any(h == k or h.endswith("." + k) for k in KNOWN_API):
        return {"class": "known/related host", "value": raw[:120], "host": host, "why": "known API"}
    if any(t in h for t in related_tokens):
        return {"class": "known/related host", "value": raw[:120], "host": host, "why": "matches the package/repository name"}
    return {"class": "unrelated host", "value": raw[:120], "host": host}


def _tier(src_kind: str, dest_class: str) -> str | None:
    bulk = src_kind in ("bulk_env", "foreign_file")
    if bulk:
        return "high_risk" if dest_class in ("exfil endpoint", "raw IP", ".onion", "unrelated host") else "review"
    return None if dest_class == "known/related host" else "review"


# ---------------------------------------------------------------- per-file analysis

def analyse_python(path: str, text: str, related_tokens: set[str], owner_names: set[str] | None = None,
                   info: list | None = None) -> tuple[list[dict], str | None]:
    """info: optional list that receives info-level items (no tier), e.g. no-sink reads in development tooling."""
    owner_names = owner_names if owner_names is not None else set(related_tokens)
    tree, err = pyast.safe_parse(text)
    if tree is None:
        return [], err
    al, par = pyast.aliases(tree), pyast.parents(tree)
    consts = {}
    for st in tree.body:
        names, val = pyast.assigned_names(st)
        v = pyast.fold_str(val) if val is not None else None
        if v is not None:
            for n in names:
                consts[n] = v
    hits, foreign_reads, module_taint = [], [], {}
    for scope_name, body in pyast.scopes(tree):
        taint = {k: list(v) for k, v in module_taint.items()} if scope_name != "<module>" else {}
        net_objs, local_consts = set(), dict(consts)
        for st in pyast.ordered_statements(body):
            names, val = pyast.assigned_names(st)
            if val is not None and names:
                srcs = expr_sources(val, par, al, taint, owner_names)
                if isinstance(st, (ast.For, ast.AsyncFor)) and pyast.dotted(val, al) == "os.environ":
                    srcs.append({"kind": "bulk_env", "line": st.lineno, "what": "iterating os.environ"})
                for n in names:
                    if srcs:
                        taint[n] = [{**s, "chain": list(s.get("chain", [])) + [f"{n} (line {st.lineno})"]} for s in srcs]
                    if isinstance(val, ast.Call) and pyast.dotted(val.func, al).startswith(NET_PREFIX):
                        net_objs.add(n)
                    fv = pyast.fold_str(val)
                    if fv is not None:
                        local_consts[n] = fv
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            own = [st] if not hasattr(st, "body") else [x for x in ast.iter_child_nodes(st) if not isinstance(x, ast.stmt)]
            for node in own:
                for call in pyast.calls_in(node):
                    srcs = [s for a in list(call.args) + [k.value for k in call.keywords]
                            for s in expr_sources(a, par, al, taint, owner_names)]
                    cname = pyast.dotted(call.func, al)
                    file_call = cname in FILE_ACCESS or cname.rsplit(".", 1)[-1] in FILE_ACCESS_ATTR
                    fsrc = [s for s in expr_sources(call, par, al, taint, owner_names) if s["kind"] == "foreign_file"] if file_call else []
                    if fsrc and not _is_sink(call, al, net_objs):
                        foreign_reads += fsrc
                    if srcs and _is_sink(call, al, net_objs):
                        hits.append({"call": call, "sources": srcs, "dest": destination(call, local_consts, related_tokens)})
        if scope_name == "<module>":
            module_taint = taint
    findings, seen = [], set()
    for h in hits:
        for s in sorted(h["sources"], key=lambda s: s["kind"] not in ("bulk_env", "foreign_file")):
            tier = _tier(s["kind"], h["dest"]["class"])
            key = (h["call"].lineno, s["kind"], tier)
            if not tier or key in seen:
                continue
            seen.add(key)
            sink_name = pyast.dotted(h["call"].func, al)
            d = h["dest"]
            dest_txt = f"{d['class']}" + (f" ({d.get('host') or d.get('value')})" if d.get("value") else "")
            f = {"sev": "High" if tier == "high_risk" else "Medium", "source": "Behavior data flow",
                 "rule": ("Bulk credential/environment data sent to " if s["kind"] in ("bulk_env", "foreign_file")
                          else "Named credential sent to ") + d["class"],
                 "file": path, "line": h["call"].lineno,
                 "detail": f"{s['what']} (line {s['line']}) reaches `{sink_name}` (line {h['call'].lineno}); "
                           f"destination: {dest_txt}." + (f" Chain: {' -> '.join(s.get('chain', []))}." if s.get("chain") else ""),
                 "fix": "Read the code path by hand; do not install if the destination is not the project's own service.",
                 "url": None, "strong": tier == "high_risk"}
            ev = [{"type": "file_line", "file": path, "line": s["line"], "role": "source", "what": s["what"],
                   "code": pyast.snippet(text, s["line"])},
                  {"type": "file_line", "file": path, "line": h["call"].lineno, "role": "sink", "call": sink_name,
                   "code": pyast.snippet(text, h["call"].lineno)},
                  {"type": "destination", **d}, {"type": "chain", "steps": s.get("chain", [])}]
            findings.append({**enrich(f, DETECTOR_ID, tier, ev), "capability_evidence": True, "confidence": "data-flow"})
            break
    flowed = {(s["line"], s["what"]) for h in hits for s in h["sources"]}   # sources that already reached a sink
    from .behavior_patterns import INFO_REASON, dev_tooling
    where = dev_tooling(path)
    for s in {(x["line"], x["what"]): x for x in foreign_reads}.values():
        if (s["line"], s["what"]) in flowed:
            continue
        if where:   # single indicator, no sink, in development tooling -> info (reported separately, no tier)
            (info if info is not None else []).append({"file": path, "line": s["line"], "rule": "Reads a foreign secret store (no network sink found)",
                          "detail": s["what"], "info_reason": INFO_REASON.format(where=where)})
            continue
        f = {"sev": "Medium", "source": "Behavior data flow", "rule": "Reads a foreign secret store (no network sink found)",
             "file": path, "line": s["line"], "detail": f"{s['what']}; no network sink was found for the value in this file.",
             "fix": "Check why the package reads this file.", "url": None, "strong": False}
        findings.append({**enrich(f, DETECTOR_ID, "review"), "capability_evidence": True, "confidence": "data-flow"})
    return findings, None


def analyse_pattern(path: str, text: str) -> list[dict]:
    """JS / shell: regex only. Review at most."""
    if path.lower().endswith(SH_EXT):
        m = SH_EXFIL.search(text)
        hit = (m, m) if m else None
    else:
        b, s = JS_BULK.search(text), JS_SINK.search(text)
        dest = EXFIL_HOST.search(text) or EXFIL_HOSTNAME.search(text) or re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", text)
        hit = (b, s) if b and s and dest else None
    if not hit:
        return []
    line = text[:hit[0].start()].count("\n") + 1
    f = {"sev": "Medium", "source": "Behavior pattern match", "rule": "Environment/secret collection and sending (pattern match, no data-flow)",
         "file": path, "line": line, "detail": f"`{hit[0].group(0)[:80]}` and a network call to an exfil-style or raw-IP destination "
                                               "in the same file. Pattern match, no data-flow: lower confidence.",
         "fix": "Read the file by hand.", "url": None, "strong": False}
    return [{**enrich(f, DETECTOR_ID, "review"), "capability_evidence": True, "confidence": "pattern match, no data-flow"}]


def owner_tokens(ctx) -> set[str]:
    """All name tokens (length >= 2, no stop list) of the package and repository, for credential-file ownership."""
    names = [((ctx.features or {}).get("full_name") or ""), (((ctx.security or {}).get("package") or {}).get("name") or ""),
             (((ctx.releases or {}).get("package") or {}).get("name") or "")]
    toks = set()
    for n in names:
        low = n.lower()
        toks |= {t for t in re.split(r"[/_.\-@]+", low) if len(t) >= 2}
        toks |= {t.replace("-", "").replace("_", "") for t in low.split("/") if t}
    return toks


def related_tokens(ctx) -> set[str]:
    names = [((ctx.features or {}).get("full_name") or ""), (((ctx.security or {}).get("package") or {}).get("name") or "")]
    toks = set()
    for n in names:
        toks |= {t.lower() for t in re.split(r"[/_.\-@]+", n) if len(t) >= 4 and t.lower() not in STOP_TOKENS}
    return toks


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR)
    if gate:
        return gate
    data = ctx.data
    if data is None:
        from .base import not_assessed
        return not_assessed(DETECTOR_ID, PILLAR, "repository contents not available")
    toks, owners = related_tokens(ctx), owner_tokens(ctx)
    findings, skipped, seen, info = [], [], 0, []
    for path, text in (data.get("text") or {}).items():
        if pyast.analysable(path, (".py",)):
            seen += 1
            if seen > pyast.MAX_FILES:
                skipped.append(f"{path}: file limit")
                continue
            fs, err = analyse_python(path, text, toks, owners, info)
            if err:
                skipped.append(f"{path}: {err}")
            findings += fs
        elif pyast.analysable(path, JS_EXT + SH_EXT):
            findings += analyse_pattern(path, text)
    cov, detail = text_coverage(ctx, ("text",))
    if skipped:
        cov = "partial"
        detail = "; ".join(x for x in (detail, f"{len(skipped)} Python file(s) not analysed, e.g. {skipped[0]}") if x)
    res = make_result(DETECTOR_ID, PILLAR, "ran", findings, coverage=cov, coverage_detail=detail)
    res["info_findings"] = info
    return res
