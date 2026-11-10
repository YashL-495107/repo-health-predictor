"""Repo content scan: look INSIDE a public repository (code, secrets, CI workflows), not just at its activity."""
from __future__ import annotations
import concurrent.futures
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
import requests
from pathlib import PurePosixPath
from github_client import API, GitHubClient, GitHubError
from malware_proof import run_malware_proof_engine

MAX_ZIP_BYTES = 40 * 1024 * 1024
MAX_UNCOMPRESSED = 150 * 1024 * 1024
MAX_PY_FILES, MAX_PY_BYTES = 400, 400_000
MAX_TEXT_FILES, MAX_TEXT_BYTES = 1500, 200_000
MAX_WORKFLOWS = 30
MAX_BINARY_BYTES = 10 * 1024 * 1024
BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".scr", ".msi"}
SKIP_DIRS = {"node_modules", "venv", ".venv", "env", "site-packages", "vendor", "third_party", "third-party", "dist", "build", "__pycache__", ".git"}
TEST_DIRS = {"test", "tests", "testing", "__tests__", "spec", "fixtures"}
TEXT_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml", ".env", ".cfg", ".ini", ".toml", ".sh", ".txt", ".md", ".properties", ".xml", ".go", ".java", ".rb", ".php", ".rs", ".cs", ".conf", ".pem", ".key"}
SKIP_NAMES = {"package-lock.json", "yarn.lock", "poetry.lock", "pnpm-lock.yaml", "Cargo.lock", "composer.lock", "Pipfile.lock"}
SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
FIXTURE_DIRS = TEST_DIRS | {"testdata", "test_data", "test-data", "mock", "mocks", "example", "examples", "sample", "samples", "demo", "docs", "doc", "fixture", "itest", "itests", "e2e", "integration-test", "integration-tests", "unittest", "unittests"}
DOC_EXT = {".md", ".rst", ".txt"}
SOURCE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".go", ".rs", ".rb", ".php", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".scala", ".m"}
TEST_NAME = re.compile(r"(^test[_\-.]|[_\-.]tests?\.[a-z0-9]+$|\.(test|spec)\.[a-z0-9]+$)", re.I)
TEST_CLASS = re.compile(r"[a-z0-9]Tests?\.(java|kt|cs|scala)$")
NOISY_STRONG = {"B324"}
MACHO = {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}
MEDIA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".svg", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".webm", ".pdf", ".zip", ".gz", ".jar"}

def _is_executable(head: bytes) -> bool:
    return head[:2] == b"MZ" or head[:4] == b"\x7fELF" or head[:4] in MACHO

def _safe_proof(data, owner, repo, url):
    try:
        return run_malware_proof_engine(data, owner, repo, url)
    except Exception as e:
        return {"findings": [], "known_malicious_count": 0, "high_risk_pattern_count": 0, "review_count": 0,
                "encoded_blobs_not_code": 0, "setup_py_status": "error", "release_diff": {},
                "profile": {"categories": {}, "patterns": []},
                "coverage": [f"Malware engine: NOT run ({type(e).__name__})"]}

def _is_fixture(path: str) -> bool:
    parts = path.lower().split("/")
    name = parts[-1]
    return (any(p in FIXTURE_DIRS for p in parts[:-1]) or bool(TEST_NAME.search(name)) or bool(TEST_CLASS.search(path.split("/")[-1]))
            or name.endswith((".example", ".sample", ".template", ".dist")) or os.path.splitext(name)[1] in DOC_EXT)

class ScanTooLarge(Exception): pass

class DownloadError(GitHubError):
    """Download failure with a machine-readable kind: timeout, connection, server, not found, refused, http."""
    def __init__(self, message: str, kind: str):
        super().__init__(message)
        self.kind = kind

DOWNLOAD_TIMEOUT = (15, 120)          # (connect, read) seconds
DOWNLOAD_BACKOFF = (3, 8)             # seconds before attempt 2 and attempt 3
DOWNLOAD_RETRY_STATUS = {502, 503, 504}
_sleep = time.sleep                   # patched in tests

FIX = {"B102": "Avoid exec(); use a parser or a dispatch table instead.", "B307": "Avoid eval(); use ast.literal_eval for literals or a real parser.", "B602": "Pass an argument list with shell=False and never build commands from user input.", "B605": "Avoid shell commands built from strings; use subprocess with an argument list.", "B506": "Use yaml.safe_load().", "B301": "Do not unpickle untrusted data; use JSON or another data-only format.", "B501": "Do not disable TLS certificate verification (verify=False).", "B324": "Use SHA-256 or stronger for anything security related.", "B608": "Use parameterised queries instead of building SQL from strings.", "B201": "Never run Flask with debug=True outside local development.", "B104": "Bind to a specific interface unless public exposure is intended."}
SECRET_PATTERNS = {"AWS access key id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"), "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "Google API key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Stripe live secret key": re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")}
INJECT = re.compile(r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit)\.(?:title|body|message|label|ref)|github\.event\.pull_request\.head\.(?:ref|label)|github\.head_ref)\b")
RISKY_TRIGGERS = ("pull_request_target", "issue_comment", "issues", "workflow_run")

def _download_once(client: GitHubClient, owner: str, repo: str) -> io.BytesIO:
    r = client.session.get(f"{API}/repos/{owner}/{repo}/zipball", stream=True, timeout=DOWNLOAD_TIMEOUT)
    if r.status_code == 404: raise DownloadError("Repository not found (it may not exist, or it is private).", "not found")
    if r.status_code in (403, 429): raise DownloadError("GitHub refused or rate-limited the download; try again later or add a token.", "refused")
    if r.status_code in DOWNLOAD_RETRY_STATUS: raise DownloadError(f"Could not download the repository (HTTP {r.status_code}).", "server")
    if r.status_code != 200: raise DownloadError(f"Could not download the repository (HTTP {r.status_code}).", "http")
    if int(r.headers.get("Content-Length") or 0) > MAX_ZIP_BYTES: raise ScanTooLarge(f"larger than {MAX_ZIP_BYTES // 2**20} MB")
    buf, total = io.BytesIO(), 0
    for chunk in r.iter_content(1 << 20):
        total += len(chunk)
        if total > MAX_ZIP_BYTES: raise ScanTooLarge(f"larger than {MAX_ZIP_BYTES // 2**20} MB")
        buf.write(chunk)
    buf.seek(0)
    return buf

def download_zip(client: GitHubClient, owner: str, repo: str) -> io.BytesIO:
    """Download the repo zipball. Retries read/connect timeouts, dropped connections and HTTP 502/503/504
    up to 2 more times (3s, then 8s). 404/403/429 and the 40 MB limit are never retried."""
    attempts = len(DOWNLOAD_BACKOFF) + 1
    for attempt in range(1, attempts + 1):
        try:
            return _download_once(client, owner, repo)
        except requests.Timeout:
            kind, last = "timeout", "download timed out"
        except (requests.ConnectionError, requests.exceptions.ChunkedEncodingError):
            kind, last = "connection", "download failed: connection error"
        except DownloadError as e:
            if e.kind != "server":
                raise
            kind, last = "server", f"download failed ({str(e).split('(')[-1].rstrip(').')})"
        if attempt < attempts:
            _sleep(DOWNLOAD_BACKOFF[attempt - 1])
    raise DownloadError(f"{last} after {attempts} attempts", kind)

def skip_reason(e: Exception) -> str:
    """Normalised reason a download/scan did not run: timeout, too large, not found, refused, or other: <type>."""
    if isinstance(e, ScanTooLarge): return "too large"
    kind = getattr(e, "kind", None)
    if kind in ("timeout", "not found", "refused"): return kind
    if kind == "connection": return "other: ConnectionError"
    if kind in ("server", "http"):
        m = re.search(r"HTTP (\d{3})", str(e))
        return f"other: HTTP {m.group(1)}" if m else "other: HTTP error"
    return f"other: {type(e).__name__}"

def _is_test(parts: tuple[str, ...]) -> bool:
    name = parts[-1]
    return (any(p.lower() in TEST_DIRS for p in parts[:-1]) or name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py")

def read_repo(buf: io.BytesIO) -> dict:
    out = {"sha": "", "py": {}, "text": {}, "workflows": {}, "binaries": [], "all_py_paths": set(), "skipped": {"tests": 0, "too_big_or_limit": 0},
           # file counts for partial-scan reporting (additive): candidates seen vs read, per kind
           "counts": {"text_candidates": 0, "text_not_read": 0, "py_candidates": 0, "py_not_read": 0,
                      "workflow_candidates": 0, "workflows_not_read": 0}}
    cnt = out["counts"]
    with zipfile.ZipFile(buf) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED: raise ScanTooLarge(f"more than {MAX_UNCOMPRESSED // 2**20} MB uncompressed")
        for i in infos:
            parts = PurePosixPath(i.filename).parts
            if len(parts) < 2 or parts[0] == "/" or any(p in ("..", "") for p in parts): continue
            out["sha"] = out["sha"] or parts[0].rsplit("-", 1)[-1]
            rel = parts[1:]
            path, name = "/".join(rel), rel[-1]
            if name.endswith(".py"): out["all_py_paths"].add(path)
            if any(p in SKIP_DIRS for p in rel[:-1]) or name in SKIP_NAMES or name.endswith(".min.js"): continue
            is_wf = path.startswith(".github/workflows/") and name.lower().endswith((".yml", ".yaml"))
            if is_wf:
                cnt["workflow_candidates"] += 1
                if i.file_size <= MAX_TEXT_BYTES and len(out["workflows"]) < MAX_WORKFLOWS: out["workflows"][path] = z.read(i).decode("utf-8", "ignore")
                else: cnt["workflows_not_read"] += 1
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext == ".py":
                if _is_test(rel): out["skipped"]["tests"] += 1
                elif i.file_size > MAX_PY_BYTES or len(out["py"]) >= MAX_PY_FILES:
                    out["skipped"]["too_big_or_limit"] += 1
                    cnt["py_candidates"] += 1; cnt["py_not_read"] += 1
                else:
                    out["py"][path] = z.read(i)
                    cnt["py_candidates"] += 1
            is_text_cand = (ext in TEXT_EXT or name.lower().startswith(".env"))
            data = None
            if is_text_cand:
                cnt["text_candidates"] += 1
                if not (i.file_size <= MAX_TEXT_BYTES and len(out["text"]) < MAX_TEXT_FILES): cnt["text_not_read"] += 1
            if is_text_cand and i.file_size <= MAX_TEXT_BYTES and len(out["text"]) < MAX_TEXT_FILES:
                data = z.read(i)
                if b"\x00" not in data[:2000]:
                    out["text"][path] = data.decode("utf-8", "ignore")
                    continue
            if len(out["binaries"]) < 20 and 1024 <= i.file_size <= MAX_BINARY_BYTES and ext not in MEDIA_EXT:
                if data is None:
                    with z.open(i) as fh:
                        head = fh.read(4)
                else:
                    head = data[:4]
                if _is_executable(head):
                    blob = data if data is not None else z.read(i)
                    out["binaries"].append({"path": path, "size": i.file_size, "sha256": hashlib.sha256(blob).hexdigest()})
    return out

def run_bandit(py: dict[str, bytes]) -> list[dict] | None:
    if not py: return []
    with tempfile.TemporaryDirectory() as d:
        for rel, data in py.items():
            p = os.path.join(d, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh: fh.write(data)
        try:
            proc = subprocess.run([sys.executable, "-m", "bandit", "-r", d, "-f", "json", "-q"], capture_output=True, text=True, timeout=120)
            res = json.loads(proc.stdout)["results"]
        except (subprocess.SubprocessError, ValueError, KeyError, OSError): return None
    return [{"file": os.path.relpath(r["filename"], d).replace(os.sep, "/"), "line": r["line_number"], "id": r["test_id"], "name": r["test_name"], "sev": r["issue_severity"].title(), "conf": r["issue_confidence"].title(), "text": r["issue_text"], "cwe": (r.get("issue_cwe") or {}).get("id"), "more": r.get("more_info")} for r in res]

def _mask(s: str) -> str: return s[:4] + "…" + s[-2:] if len(s) > 8 else "…"

SECRET_REVIEW_TOKENS = {"test", "tests", "testdata", "testing", "fixture", "fixtures", "asset", "assets", "sample", "samples",
                        "example", "examples", "doc", "docs", "rules", "signatures", "yara", "sigma", "detections"}
SAMPLE_LOOKING = re.compile(r"example|sample|dummy|fake|test|xxxx|changeme|placeholder|not[_-]?a[_-]?real", re.I)


def secret_review_reason(path: str, kind: str, line: str) -> str | None:
    """Why a secret is info rather than strong: its path is non-shipping (detectors/paths.py: tests, fixtures,
    assets, samples, examples, docs, _static, _build, tools, scripts, .agents, tasks.py, noxfile.py, rule
    directories; matched on name tokens, so 'certbot_integration_tests' and 'sample-config' count). None means
    keep the normal rules. Applies to every secret kind since 2026.11.07-9."""
    from detectors.paths import non_shipping
    where = non_shipping(path)
    if not where:
        return None
    return (f"Downgraded from strong to info: the path is non-shipping ({where}), where test keys and sample "
            "credentials are normal. The same key in shipped code would be strong.")


def scan_secrets(text: dict[str, str], limit: int = 20) -> list[dict]:
    found = []
    for path, content in text.items():
        for n, line in enumerate(content.splitlines(), 1):
            if len(line) > 2000: continue
            for kind, rx in SECRET_PATTERNS.items():
                m = rx.search(line)
                if m and not m.group(0).upper().endswith("EXAMPLE"):
                    fixture = _is_fixture(path) or (kind == "Private key block" and os.path.splitext(path)[1].lower() in SOURCE_EXT)
                    found.append({"kind": kind, "file": path, "line": n, "masked": _mask(m.group(0)), "fixture": fixture,
                                  "review_reason": None if fixture else secret_review_reason(path, kind, line)})
                    if len(found) >= limit: return found
    return found

def _blocks(lines: list[str]):
    key = re.compile(r"^(\s*)(?:-\s*)?(run|script):\s*(.*)$")
    i = 0
    while i < len(lines):
        m = key.match(lines[i])
        if not m:
            i += 1; continue
        indent, rest = len(m.group(1)), m.group(3).strip()
        if rest and not rest.startswith(("|", ">")): yield i + 1, rest
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
            if lines[j].strip(): yield j + 1, lines[j]
            j += 1
        i = max(j, i + 1)

def scan_workflow(path: str, text: str) -> list[dict]:
    out, lines = [], text.splitlines()
    risky = any(re.search(rf"^\s*(?:on:\s*)?-?\s*{t}\b|^\s*{t}\s*:", text, re.M) or f"[{t}" in text or f", {t}" in text for t in RISKY_TRIGGERS)
    prt = re.search(r"pull_request_target", text) is not None
    if prt and re.search(r"ref:\s*\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)", text):
        out.append({"sev": "High", "rule": "pull_request_target checks out PR code", "file": path, "line": 1, "detail": "Runs untrusted pull-request code with a privileged token and access to secrets.", "fix": "Use pull_request, or do not check out the PR head in a pull_request_target workflow."})
    for n, line in _blocks(lines):
        if INJECT.search(line): out.append({"sev": "High" if risky else "Medium", "rule": "script injection via event data", "file": path, "line": n, "detail": "User-controlled text (title/body/branch name) is placed directly into a shell or script step.", "fix": "Pass it through an environment variable and quote it, instead of ${{ }} inside run:."})
        if re.search(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", line): out.append({"sev": "Medium", "rule": "pipes a download straight into a shell", "file": path, "line": n, "detail": "Runs remote code without checking it.", "fix": "Download, verify a checksum, then run."})
    for n, line in enumerate(lines, 1):
        if re.match(r"^\s*permissions:\s*write-all\s*$", line): out.append({"sev": "Medium", "rule": "permissions: write-all", "file": path, "line": n, "detail": "Gives the workflow token every write permission.", "fix": "Grant only the permissions the job needs."})
    unpinned = [u for u in re.findall(r"^\s*-?\s*uses:\s*([\w.\-]+/[\w.\-/]+)@([\w.\-]+)", text, re.M) if not u[0].startswith("actions/") and not re.fullmatch(r"[0-9a-f]{40}", u[1])]
    if unpinned: out.append({"sev": "Low", "rule": "third-party actions not pinned to a commit SHA", "file": path, "line": 1, "detail": f"{len(unpinned)} action(s), e.g. {unpinned[0][0]}@{unpinned[0][1]}.", "fix": "Pin third-party actions to a full commit SHA."})
    return out

def scan_repo(client: GitHubClient, owner: str, repo: str) -> dict:
    res = {"ran": False, "findings": [], "coverage": [], "strong": 0, "review": 0, "code_high": 0, "secrets_strong": 0, "ci_high": 0, "code_scan": "not_run", "malware_proof": None, "known_malicious_count": 0, "high_risk_pattern_count": 0}
    t0 = time.monotonic()
    res["timings"] = {}
    try:
        buf = download_zip(client, owner, repo)
        res["timings"]["zip_download"] = round(time.monotonic() - t0, 2)
        data = read_repo(buf)
        res["timings"]["read_zip"] = round(time.monotonic() - t0 - res["timings"]["zip_download"], 2)
    except ScanTooLarge as e:
        res["timings"].setdefault("zip_download", round(time.monotonic() - t0, 2))
        res["coverage"].append(f"Content scan: NOT run, repository is {e}")
        res["skip_reason"] = skip_reason(e)
        _attach_detectors(res)
        return res
    except (GitHubError, zipfile.BadZipFile, OSError) as e:
        res["timings"].setdefault("zip_download", round(time.monotonic() - t0, 2))
        res["coverage"].append(f"Content scan: NOT run ({e})")
        res["skip_reason"] = skip_reason(e)
        _attach_detectors(res)
        return res
    sha = data["sha"]
    res["commit_sha"] = sha      # commit named by the downloaded archive (evidence receipt only; no detector reads it)
    def url(f, ln): return f"https://github.com/{owner}/{repo}/blob/{sha}/{f}#L{ln}" if sha else None
    return scan_data(res, data, owner, repo, url, identity=repo_identity(owner, repo, data))


def repo_identity(owner: str, repo: str, data: dict) -> dict:
    """The names the content-time detectors may use: the repository and the package its root manifest declares
    (the same function assess_security uses, so repo mode sees the same package name at both stages)."""
    from malware_proof import _detect_package_identity
    try:
        pkg = _detect_package_identity(data.get("text") or {})
    except Exception:
        pkg = None
    return {"repo": f"{owner}/{repo}", "package": pkg, "source": "repository + root manifest"}


MAX_LINE_CHARS = None   # None (the app): lines are not capped. The benchmark harness sets a cap (resource limit).


def cap_long_lines(data: dict, max_chars: int) -> list[str]:
    """Truncate every line longer than max_chars in data["text"] and data["py"] (in place), so one huge minified
    line cannot stall the regex-based checks. Returns the paths that were changed (reported as a limit hit)."""
    changed = []
    for key, is_bytes in (("text", False), ("py", True)):
        for path, body in list((data.get(key) or {}).items()):
            s = body.decode("utf-8", "ignore") if is_bytes else body
            if not any(len(line) > max_chars for line in s.split("\n")):
                continue
            s = "\n".join(line[:max_chars] for line in s.split("\n"))
            data[key][path] = s.encode("utf-8") if is_bytes else s
            if path not in changed:
                changed.append(path)
    return changed


def scan_data(res: dict, data: dict, owner: str, repo: str, url, bandit_enabled: bool = True,
              identity: dict | None = None) -> dict:
    """The content scan on contents already in memory (data has read_repo's shape). scan_repo calls it after the
    download; the benchmark's artifact mode calls it on a release artifact. bandit_enabled=False skips Bandit (it is
    the only scanner that writes files to a temporary directory, and no detector reads its findings).
    MAX_LINE_CHARS (module setting, None in the app) caps line length first; capped files go to res["limits_hit"].
    identity ({"repo", "package"}) is handed to the content-time detectors for their name-relatedness checks."""
    res["ran"] = True
    res.setdefault("timings", {})
    if MAX_LINE_CHARS:
        capped = cap_long_lines(data, MAX_LINE_CHARS)
        if capped:
            res.setdefault("limits_hit", []).append(
                f"long lines truncated to {MAX_LINE_CHARS} characters in {len(capped)} file(s): {', '.join(capped[:5])}")
    t_scan = time.monotonic()
    findings = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f_bandit = executor.submit(run_bandit, data["py"]) if bandit_enabled else None
        f_proof = executor.submit(_safe_proof, data, owner, repo, url)
        bandit = f_bandit.result() if f_bandit else None
        proof = f_proof.result()

    if not bandit_enabled:
        res["code_scan"] = "not_run"
        res["coverage"].append("Python code scan: NOT run (Bandit disabled for this scan)")
    elif bandit is None:
        res["code_scan"] = "unavailable"
        res["coverage"].append("Python code scan: NOT run (Bandit unavailable)")
    else:
        res["code_scan"] = "ran" if data["py"] else "no_python"
        keep = [b for b in bandit if b["sev"] in ("High", "Medium") and b["conf"] in ("High", "Medium")]
        for b in keep:
            high = b["sev"] == "High" and b["conf"] == "High" and b["id"] not in NOISY_STRONG
            findings.append({"sev": b["sev"], "source": "Code (Bandit)", "rule": f"{b['id']} {b['name']}" + (f" (CWE-{b['cwe']})" if b["cwe"] else ""), "file": b["file"], "line": b["line"], "detail": f"{b['text']} [confidence {b['conf']}]", "fix": FIX.get(b["id"], "Review this finding."), "url": url(b["file"], b["line"]), "strong": False, "code_high": high})
        res["coverage"].append(f"Python code scan: {len(data['py'])} files scanned ({data['skipped']['tests']} test files and {data['skipped']['too_big_or_limit']} oversized/over-limit skipped); {len(keep)} medium/high findings, {len(bandit) - len(keep)} low-level findings hidden")
        if not data["py"]: res["coverage"][-1] = "Python code scan: no Python files found (other languages are not code-scanned)"

    secrets = scan_secrets(data["text"])
    for s in secrets:
        if s["fixture"]: findings.append({"sev": "Low", "source": "Secrets", "rule": f"Key-like text in a test/example/doc/source file ({s['kind']})", "file": s["file"], "line": s["line"], "detail": f"Matches a {s['kind']} pattern: {s['masked']}", "fix": "Usually intentional test data; confirm it is not a real credential.", "url": url(s["file"], s["line"]), "strong": False})
        elif s.get("review_reason"): findings.append({"sev": "Low", "source": "Secrets", "rule": f"Key-like text in a test/sample/asset path ({s['kind']})", "file": s["file"], "line": s["line"], "detail": f"Matches a {s['kind']} pattern: {s['masked']}. {s['review_reason']}", "fix": "Usually test or sample material; confirm it is not a real key.", "url": url(s["file"], s["line"]), "strong": False, "info_reason": s["review_reason"]})
        else: findings.append({"sev": "High", "source": "Secrets", "rule": f"Possible exposed {s['kind']}", "file": s["file"], "line": s["line"], "detail": f"Matches a {s['kind']} pattern: {s['masked']}", "fix": "Verify it is real; if so, revoke it and remove it from history.", "url": url(s["file"], s["line"]), "strong": True})
    res["coverage"].append(f"Secret scan: {len(data['text'])} text files checked for provider key patterns; {len(secrets)} matches ({sum(1 for s in secrets if s['fixture'])} in test/example/doc/source files, not counted as strong)")

    wf = [f for p, t in data["workflows"].items() for f in scan_workflow(p, t)]
    for w in wf: findings.append({**w, "source": "CI workflow", "url": url(w["file"], w["line"]), "strong": w["sev"] == "High"})
    res["coverage"].append(f"CI workflows: {len(data['workflows'])} checked; {len([w for w in wf if w['sev'] != 'Low'])} risky patterns")

    findings.extend(proof.get("findings", []))
    if isinstance(proof.get("coverage"), list): res["coverage"].extend(proof["coverage"])
    elif proof.get("coverage"): res["coverage"].append(proof["coverage"])
    
    res["malware_proof"] = proof
    res["known_malicious_count"] = proof.get("known_malicious_count", 0)
    res["high_risk_pattern_count"] = proof.get("high_risk_pattern_count", 0)

    findings.sort(key=lambda f: (SEV_ORDER.get(f["sev"], 9), f["file"], f["line"]))
    res["findings_all"] = list(findings)   # additive: untruncated, for the detector adapters
    res["findings"] = findings[:60]
    res["strong"] = sum(1 for f in findings if f.get("strong"))
    res["code_high"] = sum(1 for f in findings if f.get("code_high"))
    res["secrets_strong"] = sum(1 for f in findings if f.get("strong") and f["source"] == "Secrets")
    res["ci_high"] = sum(1 for f in findings if f.get("strong") and f["source"] == "CI workflow")
    res["review"] = sum(1 for f in findings if not f.get("strong") and f["sev"] in ("High", "Medium"))
    res["scan_coverage"] = scan_coverage(data)
    res["timings"]["scanners"] = round(time.monotonic() - t_scan, 2)
    t_det = time.monotonic()
    try:   # Python files the data-flow detectors analyse with ast (behavior_patterns defers to them for these)
        from detectors.pyast import parse_ok
        res["ast_analysed_py"] = sorted(p for p, t in data["text"].items() if parse_ok(p, t))
    except Exception:
        res["ast_analysed_py"] = []
    res["identity"] = identity
    _attach_detectors(res, data, identity)
    res["timings"]["content_detectors"] = round(time.monotonic() - t_det, 2)
    return res


def scan_coverage(data: dict) -> dict:
    """What share of the repository's files was actually read (file-count and size caps in read_repo)."""
    c = data.get("counts") or {}
    tc, tn = c.get("text_candidates", 0), c.get("text_not_read", 0)
    pc, pn = c.get("py_candidates", 0), c.get("py_not_read", 0)
    wc, wn = c.get("workflow_candidates", 0), c.get("workflows_not_read", 0)
    out = {"text_read": tc - tn, "text_total": tc, "py_read": pc - pn, "py_total": pc,
           "workflows_read": wc - wn, "workflows_total": wc,
           "text_partial": tn > 0, "py_partial": pn > 0, "workflows_partial": wn > 0}
    out["partial"] = out["text_partial"] or out["py_partial"] or out["workflows_partial"]
    parts = []
    if tn: parts.append(f"{tc - tn} of {tc} text files")
    if pn: parts.append(f"{pc - pn} of {pc} Python files")
    if wn: parts.append(f"{wc - wn} of {wc} workflow files")
    out["detail"] = ("partial scan: " + ", ".join(parts)) if parts else None
    return out


def _attach_detectors(res: dict, data: dict | None = None, identity: dict | None = None) -> None:
    """Content-only detector view (security sources are added later by apply_gate). The repository contents are only
    in memory here, so detectors that need them (NEEDS_DATA) run now; apply_gate reuses their results. Never raises."""
    try:
        from detectors import RULESET_VERSION, run_detectors
        from detectors.context import DetectorContext
        res["ruleset_version"] = RULESET_VERSION
        res["detectors"] = run_detectors(DetectorContext.build(scan=res, data=data, identity=identity))
    except Exception as e:  # the scan result must never be lost because of the detector layer
        res["detectors"] = []
        res["detectors_error"] = type(e).__name__