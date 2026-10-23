"""Repo content scan: look INSIDE a public repository (code, secrets, CI workflows), not just at its activity.

What it does (nothing from the repo is ever executed or imported):
  1. downloads the repo as a zip (size-capped) and extracts only the files it needs, safely
  2. Python code: runs Bandit (open-source static security analyser) and keeps medium+ severity/confidence findings
  3. secrets: high-confidence provider patterns only (AWS key id, GitHub token, Slack token, private key block ...)
  4. CI: GitHub Actions workflow patterns that are documented attack paths
What it does NOT do: scan languages other than Python for code flaws, detect malware or intent, or prove
anything is safe. Static analysers give false positives, so only secrets and high-risk CI patterns count as
STRONG; code findings are shown for review and never change a score.
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import PurePosixPath

from github_client import API, GitHubClient, GitHubError

MAX_ZIP_BYTES = 40 * 1024 * 1024
MAX_UNCOMPRESSED = 150 * 1024 * 1024
MAX_PY_FILES, MAX_PY_BYTES = 400, 400_000
MAX_TEXT_FILES, MAX_TEXT_BYTES = 1500, 200_000
MAX_WORKFLOWS = 30
SKIP_DIRS = {"node_modules", "venv", ".venv", "env", "site-packages", "vendor", "third_party", "third-party",
             "dist", "build", "__pycache__", ".git"}
TEST_DIRS = {"test", "tests", "testing", "__tests__", "spec", "fixtures"}
TEXT_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml", ".env", ".cfg", ".ini", ".toml", ".sh",
            ".txt", ".md", ".properties", ".xml", ".go", ".java", ".rb", ".php", ".rs", ".cs", ".conf", ".pem", ".key"}
SKIP_NAMES = {"package-lock.json", "yarn.lock", "poetry.lock",
              "pnpm-lock.yaml", "Cargo.lock", "composer.lock", "Pipfile.lock"}
SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
# Paths where key-like text is normally intentional test data, examples or documentation.
FIXTURE_DIRS = TEST_DIRS | {"testdata", "test_data", "test-data", "mock", "mocks", "example", "examples", "sample",
                            "samples", "demo", "docs", "doc", "fixture", "itest", "itests", "e2e", "integration-test",
                            "integration-tests", "unittest", "unittests"}
DOC_EXT = {".md", ".rst", ".txt"}
# Files that hold program text: a PEM *header string* inside one is nearly always a parser, test vector or example.
SOURCE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".go", ".rs", ".rb", ".php", ".cs", ".c", ".cc",
              ".cpp", ".h", ".hpp", ".swift", ".scala", ".m"}
TEST_NAME = re.compile(
    r"(^test[_\-.]|[_\-.]tests?\.[a-z0-9]+$|\.(test|spec)\.[a-z0-9]+$)", re.I)
TEST_CLASS = re.compile(r"[a-z0-9]Tests?\.(java|kt|cs|scala)$")
# Bandit rules that fire "high/high" on harmless uses (e.g. md5 for cache keys): shown for review, never counted as high.
NOISY_STRONG = {"B324"}


def _is_fixture(path: str) -> bool:
    parts = path.lower().split("/")
    name = parts[-1]
    return (any(p in FIXTURE_DIRS for p in parts[:-1]) or bool(TEST_NAME.search(name)) or bool(TEST_CLASS.search(path.split("/")[-1]))
            or name.endswith((".example", ".sample", ".template", ".dist"))
            or os.path.splitext(name)[1] in DOC_EXT)


class ScanTooLarge(Exception):
    """Repository is too large to scan within the app's limits."""


FIX = {
    "B102": "Avoid exec(); use a parser or a dispatch table instead.",
    "B307": "Avoid eval(); use ast.literal_eval for literals or a real parser.",
    "B602": "Pass an argument list with shell=False and never build commands from user input.",
    "B605": "Avoid shell commands built from strings; use subprocess with an argument list.",
    "B506": "Use yaml.safe_load().",
    "B301": "Do not unpickle untrusted data; use JSON or another safe format.",
    "B501": "Do not disable TLS certificate verification (verify=False).",
    "B324": "Use SHA-256 or stronger for anything security related.",
    "B608": "Use parameterised queries instead of building SQL from strings.",
    "B201": "Never run Flask with debug=True outside local development.",
    "B104": "Bind to a specific interface unless public exposure is intended.",
}

SECRET_PATTERNS = {
    "AWS access key id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Stripe live secret key": re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
}
INJECT = re.compile(r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit)\.(?:title|body|message|label|ref)"
                    r"|github\.event\.pull_request\.head\.(?:ref|label)|github\.head_ref)\b")
RISKY_TRIGGERS = ("pull_request_target", "issue_comment",
                  "issues", "workflow_run")


# ------------------------------------------------------------------ download + safe extraction
def download_zip(client: GitHubClient, owner: str, repo: str) -> io.BytesIO:
    r = client.session.get(
        f"{API}/repos/{owner}/{repo}/zipball", stream=True, timeout=60)
    if r.status_code == 404:
        raise GitHubError(
            "Repository not found (it may not exist, or it is private).")
    if r.status_code in (403, 429):
        raise GitHubError(
            "GitHub refused or rate-limited the download; try again later or add a token.")
    if r.status_code != 200:
        raise GitHubError(
            f"Could not download the repository (HTTP {r.status_code}).")
    if int(r.headers.get("Content-Length") or 0) > MAX_ZIP_BYTES:
        raise ScanTooLarge(f"larger than {MAX_ZIP_BYTES // 2**20} MB")
    buf, total = io.BytesIO(), 0
    for chunk in r.iter_content(1 << 20):
        total += len(chunk)
        if total > MAX_ZIP_BYTES:
            raise ScanTooLarge(f"larger than {MAX_ZIP_BYTES // 2**20} MB")
        buf.write(chunk)
    buf.seek(0)
    return buf


def _is_test(parts: tuple[str, ...]) -> bool:
    name = parts[-1]
    return (any(p.lower() in TEST_DIRS for p in parts[:-1]) or name.startswith("test_")
            or name.endswith("_test.py") or name == "conftest.py")


def read_repo(buf: io.BytesIO) -> dict:
    """Extract only what we scan, in memory. Skips unsafe paths, vendored/test code and oversized files."""
    out = {"sha": "", "py": {}, "text": {}, "workflows": {},
           "skipped": {"tests": 0, "too_big_or_limit": 0}}
    with zipfile.ZipFile(buf) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED:
            raise ScanTooLarge(
                f"more than {MAX_UNCOMPRESSED // 2**20} MB uncompressed")
        for i in infos:
            parts = PurePosixPath(i.filename).parts
            if len(parts) < 2 or parts[0] == "/" or any(p in ("..", "") for p in parts):
                continue  # unsafe or root-level junk (zip-slip guard)
            out["sha"] = out["sha"] or parts[0].rsplit("-", 1)[-1]
            rel = parts[1:]
            path, name = "/".join(rel), rel[-1]
            if any(p in SKIP_DIRS for p in rel[:-1]) or name in SKIP_NAMES or name.endswith(".min.js"):
                continue
            is_wf = path.startswith(
                ".github/workflows/") and name.lower().endswith((".yml", ".yaml"))
            if is_wf:
                if i.file_size <= MAX_TEXT_BYTES and len(out["workflows"]) < MAX_WORKFLOWS:
                    out["workflows"][path] = z.read(
                        i).decode("utf-8", "ignore")
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext == ".py":
                if _is_test(rel):
                    out["skipped"]["tests"] += 1
                elif i.file_size > MAX_PY_BYTES or len(out["py"]) >= MAX_PY_FILES:
                    out["skipped"]["too_big_or_limit"] += 1
                else:
                    out["py"][path] = z.read(i)
            if (ext in TEXT_EXT or name.lower().startswith(".env")) and i.file_size <= MAX_TEXT_BYTES and len(out["text"]) < MAX_TEXT_FILES:
                data = z.read(i)
                if b"\x00" not in data[:2000]:
                    out["text"][path] = data.decode("utf-8", "ignore")
    return out


# ------------------------------------------------------------------ scanners
def run_bandit(py: dict[str, bytes]) -> list[dict] | None:
    """Findings from Bandit, or None if Bandit could not run. Bandit parses code; it never executes it."""
    if not py:
        return []
    with tempfile.TemporaryDirectory() as d:
        for rel, data in py.items():
            p = os.path.join(d, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(data)
        try:
            proc = subprocess.run([sys.executable, "-m", "bandit", "-r", d, "-f", "json", "-q"],
                                  capture_output=True, text=True, timeout=120)
            res = json.loads(proc.stdout)["results"]
        except (subprocess.SubprocessError, ValueError, KeyError, OSError):
            return None
    return [{"file": os.path.relpath(r["filename"], d).replace(os.sep, "/"), "line": r["line_number"], "id": r["test_id"],
             "name": r["test_name"], "sev": r["issue_severity"].title(), "conf": r["issue_confidence"].title(),
             "text": r["issue_text"], "cwe": (r.get("issue_cwe") or {}).get("id"), "more": r.get("more_info")} for r in res]


def _mask(s: str) -> str:
    return s[:4] + "…" + s[-2:] if len(s) > 8 else "…"


def scan_secrets(text: dict[str, str], limit: int = 20) -> list[dict]:
    found = []
    for path, content in text.items():
        for n, line in enumerate(content.splitlines(), 1):
            if len(line) > 2000:
                continue
            for kind, rx in SECRET_PATTERNS.items():
                m = rx.search(line)
                if m and not m.group(0).upper().endswith("EXAMPLE"):
                    found.append({"kind": kind, "file": path, "line": n, "masked": _mask(m.group(0)), "fixture": _is_fixture(
                        path) or (kind == "Private key block" and os.path.splitext(path)[1].lower() in SOURCE_EXT)})
                    if len(found) >= limit:
                        return found
    return found


def _blocks(lines: list[str]):
    """Yield (line_number, text) for lines that belong to `run:` / `script:` blocks."""
    key = re.compile(r"^(\s*)(?:-\s*)?(run|script):\s*(.*)$")
    i = 0
    while i < len(lines):
        m = key.match(lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(3).strip()
        if rest and not rest.startswith(("|", ">")):
            yield i + 1, rest
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
            if lines[j].strip():
                yield j + 1, lines[j]
            j += 1
        i = max(j, i + 1)


def scan_workflow(path: str, text: str) -> list[dict]:
    out, lines = [], text.splitlines()
    risky = any(re.search(rf"^\s*(?:on:\s*)?-?\s*{t}\b|^\s*{t}\s*:", text, re.M) or f"[{t}" in text or f", {t}" in text
                for t in RISKY_TRIGGERS)
    prt = re.search(r"pull_request_target", text) is not None
    if prt and re.search(r"ref:\s*\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)", text):
        out.append({"sev": "High", "rule": "pull_request_target checks out PR code", "file": path, "line": 1,
                    "detail": "Runs untrusted pull-request code with a privileged token and access to secrets.",
                    "fix": "Use pull_request, or do not check out the PR head in a pull_request_target workflow."})
    for n, line in _blocks(lines):
        if INJECT.search(line):
            out.append({"sev": "High" if risky else "Medium", "rule": "script injection via event data", "file": path, "line": n,
                        "detail": "User-controlled text (title/body/branch name) is placed directly into a shell or script step.",
                        "fix": "Pass it through an environment variable and quote it, instead of ${{ }} inside run:."})
        if re.search(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", line):
            out.append({"sev": "Medium", "rule": "pipes a download straight into a shell", "file": path, "line": n,
                        "detail": "Runs remote code without checking it.", "fix": "Download, verify a checksum, then run."})
    for n, line in enumerate(lines, 1):
        if re.match(r"^\s*permissions:\s*write-all\s*$", line):
            out.append({"sev": "Medium", "rule": "permissions: write-all", "file": path, "line": n,
                        "detail": "Gives the workflow token every write permission.", "fix": "Grant only the permissions the job needs."})
    unpinned = [u for u in re.findall(r"^\s*-?\s*uses:\s*([\w.\-]+/[\w.\-/]+)@([\w.\-]+)", text, re.M)
                if not u[0].startswith("actions/") and not re.fullmatch(r"[0-9a-f]{40}", u[1])]
    if unpinned:
        out.append({"sev": "Low", "rule": "third-party actions not pinned to a commit SHA", "file": path, "line": 1,
                    "detail": f"{len(unpinned)} action(s), e.g. {unpinned[0][0]}@{unpinned[0][1]}.",
                    "fix": "Pin third-party actions to a full commit SHA."})
    return out


# ------------------------------------------------------------------ orchestration
def scan_repo(client: GitHubClient, owner: str, repo: str) -> dict:
    """Run every scanner. Never raises for scanner problems; says what ran in 'coverage'."""
    res = {"ran": False, "findings": [], "coverage": [], "strong": 0, "review": 0, "code_high": 0, "secrets_strong": 0, "ci_high": 0,
           "code_scan": "not_run"}
    try:
        data = read_repo(download_zip(client, owner, repo))
    except ScanTooLarge as e:
        res["coverage"].append(f"Content scan: NOT run, repository is {e}")
        return res
    except (GitHubError, zipfile.BadZipFile, OSError) as e:
        res["coverage"].append(f"Content scan: NOT run ({e})")
        return res
    res["ran"] = True
    sha, findings = data["sha"], []

    def url(
        f, ln): return f"https://github.com/{owner}/{repo}/blob/{sha}/{f}#L{ln}" if sha else None

    bandit = run_bandit(data["py"])
    if bandit is None:
        res["code_scan"] = "unavailable"
        res["coverage"].append(
            "Python code scan: NOT run (Bandit unavailable)")
    else:
        res["code_scan"] = "ran" if data["py"] else "no_python"
        keep = [b for b in bandit if b["sev"] in (
            "High", "Medium") and b["conf"] in ("High", "Medium")]
        for b in keep:
            high = b["sev"] == "High" and b["conf"] == "High" and b["id"] not in NOISY_STRONG
            findings.append({"sev": b["sev"], "source": "Code (Bandit)", "rule": f"{b['id']} {b['name']}"
                             + (f" (CWE-{b['cwe']})" if b["cwe"] else ""), "file": b["file"], "line": b["line"],
                             "detail": f"{b['text']} [confidence {b['conf']}]", "fix": FIX.get(b["id"], "Review this finding."),
                             "url": url(b["file"], b["line"]), "strong": False, "code_high": high})
        low = len(bandit) - len(keep)
        res["coverage"].append(f"Python code scan: {len(data['py'])} files scanned "
                               f"({data['skipped']['tests']} test files and {data['skipped']['too_big_or_limit']} oversized/over-limit skipped); "
                               f"{len(keep)} medium/high findings, {low} low-level findings hidden")
        if not data["py"]:
            res["coverage"][-1] = "Python code scan: no Python files found (other languages are not code-scanned)"

    secrets = scan_secrets(data["text"])
    for s in secrets:
        if s["fixture"]:
            findings.append({"sev": "Low", "source": "Secrets", "rule": f"Key-like text in a test/example/doc/source file ({s['kind']})",
                             "file": s["file"], "line": s["line"], "detail": f"Matches a {s['kind']} pattern: {s['masked']}",
                             "fix": "Usually intentional test data; confirm it is not a real credential.",
                             "url": url(s["file"], s["line"]), "strong": False})
        else:
            findings.append({"sev": "High", "source": "Secrets", "rule": f"Possible exposed {s['kind']}", "file": s["file"],
                             "line": s["line"], "detail": f"Matches a {s['kind']} pattern: {s['masked']}",
                             "fix": "Verify it is real; if so, revoke it and remove it from history.",
                             "url": url(s["file"], s["line"]), "strong": True})
    fixtures = sum(1 for s in secrets if s["fixture"])
    res["coverage"].append(f"Secret scan: {len(data['text'])} text files checked for provider key patterns; {len(secrets)} matches "
                           f"({fixtures} in test/example/doc/source files, not counted as strong)")

    wf = [f for p, t in data["workflows"].items() for f in scan_workflow(p, t)]
    for w in wf:
        findings.append({**w, "source": "CI workflow",
                        "url": url(w["file"], w["line"]), "strong": w["sev"] == "High"})
    res["coverage"].append(
        f"CI workflows: {len(data['workflows'])} checked; {len([w for w in wf if w['sev'] != 'Low'])} risky patterns")

    findings.sort(key=lambda f: (SEV_ORDER.get(
        f["sev"], 9), f["file"], f["line"]))
    res["findings"] = findings[:60]
    # secrets + high-risk CI only
    res["strong"] = sum(1 for f in findings if f["strong"])
    # high-severity, high-confidence code findings
    res["code_high"] = sum(1 for f in findings if f.get("code_high"))
    res["secrets_strong"] = sum(
        1 for f in findings if f["strong"] and f["source"] == "Secrets")
    res["ci_high"] = sum(1 for f in findings if f["strong"]
                         and f["source"] == "CI workflow")
    res["review"] = sum(1 for f in findings if not f["strong"]
                        and f["sev"] in ("High", "Medium"))
    return res
