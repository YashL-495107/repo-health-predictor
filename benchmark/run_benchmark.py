"""Benchmark runner (protocol: benchmark/README.md). Static analysis only: nothing scanned is executed, imported,
installed or compiled; release artifacts and dataset samples are read as text in memory.

One JSON line per item is APPENDED to the output file as soon as the item is done, so a run can be interrupted
(Ctrl+C, closed window, lost network) and resumed by running the same command again. On resume:
  - items with a final record are skipped;
  - items recorded as not_assessed for a transient reason (timeout, HTTP 5xx, connection error, offline cache miss,
    item time budget) are retried; --retry-errors also retries items whose scan raised.
The last record per item wins (metrics.py reads it that way).

Modes
  artifact (primary, protocol section 2): the release artifact of the pinned version (or the extracted DataDog
           sample) is given to the content detectors as the repository contents; the release detectors use the
           registry history up to that version. GitHub signals are not available (reported as not_assessed).
  repo     (secondary): the full app pipeline on the package's GitHub repository (known-good, dormant, scary, dev).

Ablations (separate output files): --no-osv (OSV MAL- lookups off: own-package check and the MAL- part of
dependency_injection; dependency MAL- findings from osv_scan are removed) and --no-fragility-escalation.

Isolation (default): every item runs in its own spawned process with a hard timeout (killed on overrun) and a memory
cap (RLIMIT_AS on Linux, a Job Object on Windows); --no-isolate runs in-process for debugging. Lines longer than
LINE_CAP_CHARS are truncated before the content checks (reported in limits_hit). --selfcheck checks the machine.

Guards: refuses to run when an AI/Gemini key is in the environment (the AI layer must be OFF), refuses --split test
or all unless benchmark/README.md records the frozen ruleset and it equals RULESET_VERSION with RULESET_FROZEN set,
and refuses to start without manifests/dev_credibility.csv.

Usage (see benchmark/README.md for Windows / PowerShell):
  python benchmark/run_benchmark.py --mode artifact --split test
  python benchmark/run_benchmark.py --mode artifact --split test --no-osv
  python benchmark/run_benchmark.py --mode repo --split test --category known_good
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
for p in (str(ROOT), str(BENCH)):
    if p not in sys.path:
        sys.path.insert(0, p)

import bench_items  # noqa: E402

SEED = 20261107
AI_KEY_VARS = ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY")
AI_MODULES = ("intelligence", "google.genai", "google.generativeai")
DEFAULT_ITEM_BUDGET_S = 300.0
DEFAULT_MEM_MB = 3072          # per item process (address space on Linux, committed memory on Windows)
LINE_CAP_CHARS = 100_000       # lines longer than this are truncated before the regex-based checks (limit hit)
RUNS = BENCH / "runs"
SAMPLES = BENCH / "samples"    # default; --samples-dir / REPOHEALTH_SAMPLES_DIR point elsewhere
REPO_CATEGORIES = {"known_good", "dormant", "scary", "dev"}
_TRANSIENT = re.compile(r"timeout|timed out|HTTP 5\d\d|HTTP 429|ConnectionError|ConnectTimeout|ReadTimeout|"
                        r"offline: not cached|item time budget|rate limit|rate-limited", re.I)


class GuardError(SystemExit):
    """A protocol guard refused to run (exit code 2, message printed)."""

    def __init__(self, msg: str):
        super().__init__(2)
        self.msg = msg

    def __str__(self):
        return self.msg


# ------------------------------------------------------------------ guards

def assert_ai_off(env=None) -> None:
    """Fail loudly if an AI/Gemini key is present or an AI module was imported. The AI layer is advisory and OFF for
    every benchmark run; a key in the environment means the run would not match the protocol."""
    env = os.environ if env is None else env
    present = [k for k in AI_KEY_VARS if str(env.get(k) or "").strip()]
    if present:
        raise GuardError("REFUSING TO RUN: AI/Gemini key present in the environment (" + ", ".join(present) + "). "
                         "The AI layer must be OFF for the benchmark. Unset it first, e.g. in PowerShell: "
                         + "; ".join(f"Remove-Item Env:{k}" for k in present))
    loaded = [m for m in AI_MODULES if m in sys.modules]
    if loaded:
        raise GuardError(f"REFUSING TO CONTINUE: AI module(s) imported during the benchmark: {', '.join(loaded)}")


def readme_frozen_version(readme: Path = BENCH / "README.md") -> str | None:
    if not readme.exists():
        return None
    m = re.search(r"Frozen ruleset\s*\|\s*\*\*`([^`]+)`\*\*", readme.read_text(encoding="utf-8"))
    return m.group(1) if m else None


def check_frozen(split: str, readme: Path = BENCH / "README.md") -> str:
    """The test split may only run with the frozen ruleset recorded in the protocol. Returns the recorded version."""
    from detectors import version as V
    recorded = readme_frozen_version(readme)
    if split in ("test", "all"):
        if not recorded:
            raise GuardError("REFUSING TO RUN the test split: benchmark/README.md does not record a frozen ruleset")
        if recorded != V.RULESET_VERSION:
            raise GuardError(f"REFUSING TO RUN the test split: README records ruleset {recorded}, code has "
                             f"{V.RULESET_VERSION}")
        if not getattr(V, "RULESET_FROZEN", False):
            raise GuardError("REFUSING TO RUN the test split: RULESET_FROZEN is not set in detectors/version.py")
    return recorded or ""


def contamination() -> str:
    p = BENCH / "CHANGELOG.md"
    text = p.read_text(encoding="utf-8") if p.exists() else ""
    return "not contaminated" if "(no entries)" in text else "CONTAMINATED (see benchmark/CHANGELOG.md)"


def transient(reason: str | None) -> bool:
    return bool(reason) and bool(_TRANSIENT.search(str(reason)))


# ------------------------------------------------------------------ environment and patches

def setup_env(args) -> dict:
    """Environment for the scan modules. Must run BEFORE they are imported (http_cache reads it at call time, but the
    VirusTotal key is read by the malware engine at call time too, so popping it here is enough)."""
    os.environ.setdefault("REPOHEALTH_CACHE", str(BENCH / "cache" / "http"))
    os.environ["REPOHEALTH_SNAPSHOT"] = args.snapshot or os.environ.get("REPOHEALTH_SNAPSHOT") or \
        datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if args.offline:
        os.environ["REPOHEALTH_OFFLINE"] = "1"
    if getattr(args, "samples_dir", None):
        os.environ["REPOHEALTH_SAMPLES_DIR"] = str(Path(args.samples_dir).resolve())
    token = os.environ.get("GITHUB_TOKEN")
    notes = []
    env_file = ROOT / ".env"
    if env_file.exists():
        try:
            from dotenv import dotenv_values
            vals = dotenv_values(env_file)
        except Exception:
            vals = {}
        if not token and vals.get("GITHUB_TOKEN"):
            os.environ["GITHUB_TOKEN"] = token = vals["GITHUB_TOKEN"]
        if args.virustotal and not os.environ.get("VT_API_KEY") and vals.get("VT_API_KEY"):
            os.environ["VT_API_KEY"] = vals["VT_API_KEY"]
        ignored = [k for k in AI_KEY_VARS if vals.get(k)]
        if ignored:
            notes.append(f".env contains {', '.join(ignored)}: NOT loaded (AI layer OFF; only GITHUB_TOKEN"
                         + (" and VT_API_KEY" if args.virustotal else "") + " are read from .env)")
    if not args.virustotal:
        os.environ.pop("VT_API_KEY", None)
    return {"github_token": bool(token), "notes": notes}


class OsvDisabled(Exception):
    pass


class OsvIndex:
    """MAL- advisories from the OSV bulk export (benchmark/cache/osv_mal_<eco>.json, built by select_items.py), so
    the lookup is pinned to a dated snapshot and works offline. A record with no listed versions is range-based in
    OSV (usually 'introduced: 0'), so it is treated as affecting every version.
    The JSON export is converted once into a small SQLite index (osv_mal.sqlite in the same folder) so each
    isolated item process can query it without loading the whole export into memory."""

    def __init__(self, offline: bool, cache_dir: Path | None = None):
        self.offline, self.status = offline, {}
        self.cache_dir = Path(cache_dir or BENCH / "cache")
        self.db_path = self.cache_dir / "osv_mal.sqlite"

    @staticmethod
    def key(eco: str, name: str) -> str:
        return bench_items.norm(name) if eco == "PyPI" else name

    def _have(self, con, eco: str) -> bool:
        return con.execute("SELECT n FROM meta WHERE eco = ?", (eco,)).fetchone() is not None

    def prepare(self, ecos=("PyPI", "npm")) -> dict:
        """Build the SQLite index for each ecosystem whose JSON export is available (or downloadable when online)."""
        import sqlite3
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(self.db_path)
        try:
            con.execute("CREATE TABLE IF NOT EXISTS mal (eco TEXT, key TEXT, id TEXT, versions TEXT)")
            con.execute("CREATE INDEX IF NOT EXISTS mal_key ON mal (eco, key)")
            con.execute("CREATE TABLE IF NOT EXISTS meta (eco TEXT PRIMARY KEY, n INTEGER, source TEXT)")
            for eco in ecos:
                if self._have(con, eco):
                    n, src = con.execute("SELECT n, source FROM meta WHERE eco = ?", (eco,)).fetchone()
                    self.status[eco] = f"{src} ({n} MAL- records)"
                    continue
                path = self.cache_dir / f"osv_mal_{eco}.json"
                if path.exists():
                    recs, src = json.loads(path.read_text(encoding="utf-8")), f"OSV bulk export index {path.name}"
                elif not self.offline:
                    import select_items
                    recs, src = select_items.osv_mal_index(eco), "OSV bulk export index built now"
                else:
                    self.status[eco] = "OSV index not cached (offline)"
                    continue
                rows = [(eco, self.key(eco, r["package"]), r["id"], json.dumps(r.get("versions") or []))
                        for r in recs if r.get("package") and not r.get("withdrawn")]
                con.executemany("INSERT INTO mal VALUES (?, ?, ?, ?)", rows)
                con.execute("INSERT INTO meta VALUES (?, ?, ?)", (eco, len(recs), src))
                con.commit()
                self.status[eco] = f"{src} ({len(recs)} MAL- records)"
        finally:
            con.close()
        return self.status

    def mal_ids(self, eco: str, name: str, version: str | None) -> list[str]:
        import sqlite3
        if not self.db_path.exists():
            self.prepare((eco,))
        con = sqlite3.connect(f"file:{self.db_path.as_posix()}?mode=ro", uri=True) if self.db_path.exists() else None
        if con is None:
            raise ConnectionError("offline: not cached (OSV MAL- index)")
        try:
            if not self._have(con, eco):
                con.close()
                self.prepare((eco,))
                con = sqlite3.connect(f"file:{self.db_path.as_posix()}?mode=ro", uri=True)
                if not self._have(con, eco):
                    raise ConnectionError("offline: not cached (OSV MAL- index)")
            rows = con.execute("SELECT id, versions FROM mal WHERE eco = ? AND key = ?", (eco, self.key(eco, name))).fetchall()
        finally:
            con.close()
        return sorted({i for i, v in rows if version is None or not json.loads(v) or version in json.loads(v)})


class Patches:
    """Runner-only module patches (never used by the app): offline network guard, OSV MAL- lookups from the pinned
    index (or disabled for --no-osv), fragility escalation off for --no-fragility-escalation, and in artifact mode
    the release-vs-git layer reported as not_assessed."""

    def __init__(self, *, offline: bool, osv: bool, fragility_escalation: bool, osv_index: OsvIndex,
                 artifact_mode: bool = False):
        self.offline, self.osv, self.frag, self.idx = offline, osv, fragility_escalation, osv_index
        self.artifact_mode = artifact_mode
        self._saved = []

    def _set(self, obj, name, value):
        self._saved.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def __enter__(self):
        import requests
        import fragility
        import security
        if self.offline:
            def no_network(*a, **k):
                raise requests.ConnectionError("offline mode: network disabled")
            self._set(requests.sessions.Session, "request", no_network)
        idx = self.idx

        class _Unavailable(requests.RequestException):
            pass

        if self.osv:
            def local_mal_ids(pkg: dict, version: str | None = None) -> list[str]:
                try:
                    return idx.mal_ids(pkg["ecosystem"], pkg["name"], version)
                except ConnectionError as e:
                    raise _Unavailable(str(e))
        else:
            def local_mal_ids(pkg: dict, version: str | None = None) -> list[str]:
                raise _Unavailable("ablation: OSV MAL- lookup disabled")
        self._set(security, "_osv_mal_ids", local_mal_ids)
        if not self.frag:
            self._set(fragility, "amplify", lambda result, frag: result)
        if self.artifact_mode:
            # Layer 4 compares the scanned files with the LATEST PyPI wheel, as a stand-in for "git vs release".
            # In artifact mode the scanned files ARE a release, so there is no git side: not_assessed (protocol: GitHub
            # signals are not available in artifact mode).
            import malware_proof
            self._set(malware_proof, "verify_release_integrity", lambda *a, **k: {
                "checked": False, "findings": [], "status": "artifact mode: no git repository to compare with"})
        return self

    def __exit__(self, *exc):
        for obj, name, value in reversed(self._saved):
            setattr(obj, name, value)
        self._saved.clear()
        return False


# ------------------------------------------------------------------ artifact contents -> read_repo shape

ARTIFACT_KEEP_DIRS = {"dist", "build"}   # in a release artifact these hold the shipped code, so they are scanned


def data_from_contents(contents: dict) -> dict:
    """read_archive / sample contents -> the dict shape repo_scan.read_repo returns, with read_repo's filters and
    limits (skipped directories, lock files, *.min.js, per-file and file-count caps), EXCEPT that dist/ and build/
    are kept: in a release artifact they are the shipped code, not build output next to the source."""
    from repo_scan import (MAX_PY_BYTES, MAX_PY_FILES, MAX_TEXT_BYTES, MAX_TEXT_FILES, MAX_WORKFLOWS, MEDIA_EXT,
                           SKIP_DIRS, SKIP_NAMES, TEXT_EXT, _is_test)
    skip_dirs = SKIP_DIRS - ARTIFACT_KEEP_DIRS
    out = {"sha": "", "py": {}, "text": {}, "workflows": {}, "binaries": [], "all_py_paths": set(),
           "skipped": {"tests": 0, "too_big_or_limit": 0},
           "counts": {"text_candidates": 0, "text_not_read": 0, "py_candidates": 0, "py_not_read": 0,
                      "workflow_candidates": 0, "workflows_not_read": 0}}
    cnt = out["counts"]
    for path in sorted(contents.get("text") or {}):
        body = contents["text"][path]
        rel = tuple(p for p in path.split("/") if p)
        if not rel or any(p == ".." for p in rel):
            continue
        name = rel[-1]
        size = len(body.encode("utf-8", "ignore"))
        if name.endswith(".py"):
            out["all_py_paths"].add(path)
        if any(p in skip_dirs for p in rel[:-1]) or name in SKIP_NAMES or name.endswith(".min.js"):
            continue
        if path.startswith(".github/workflows/") and name.lower().endswith((".yml", ".yaml")):
            cnt["workflow_candidates"] += 1
            if size <= MAX_TEXT_BYTES and len(out["workflows"]) < MAX_WORKFLOWS:
                out["workflows"][path] = body
            else:
                cnt["workflows_not_read"] += 1
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext == ".py":
            if _is_test(rel):
                out["skipped"]["tests"] += 1
            elif size > MAX_PY_BYTES or len(out["py"]) >= MAX_PY_FILES:
                out["skipped"]["too_big_or_limit"] += 1
                cnt["py_candidates"] += 1
                cnt["py_not_read"] += 1
            else:
                out["py"][path] = body.encode("utf-8", "ignore")
                cnt["py_candidates"] += 1
        if ext in TEXT_EXT or name.lower().startswith(".env"):
            cnt["text_candidates"] += 1
            if size <= MAX_TEXT_BYTES and len(out["text"]) < MAX_TEXT_FILES:
                out["text"][path] = body
            else:
                cnt["text_not_read"] += 1
    for path in contents.get("skipped") or []:   # members the archive reader did not read (its size limits)
        ext = os.path.splitext(path)[1].lower()
        if ext in TEXT_EXT:
            cnt["text_candidates"] += 1
            cnt["text_not_read"] += 1
    out["binaries"] = [b for b in contents.get("binaries") or []
                       if os.path.splitext(b["path"])[1].lower() not in MEDIA_EXT and b.get("sha256")][:20]
    return out


def samples_root() -> Path:
    return Path(os.environ.get("REPOHEALTH_SAMPLES_DIR") or SAMPLES).resolve()


def load_sample_dir(sample_dir: str, root: Path | None = None) -> dict:
    """Text members written by extract_datadog.py (name + '.sample'), read as text only, never executed.
    sample_dir is relative to the samples root (--samples-dir; default benchmark/samples)."""
    root = Path(root).resolve() if root else samples_root()
    rel = sample_dir[len("samples/"):] if sample_dir.startswith("samples/") else sample_dir
    base = (root / rel).resolve()
    if root not in base.parents and base != root:
        raise ValueError(f"sample directory outside the samples root {root}: {sample_dir}")
    text = {}
    for p in sorted(base.rglob("*.sample")):
        name = p.relative_to(base).as_posix()[: -len(".sample")]
        text[name] = p.read_text(encoding="utf-8", errors="ignore")
    return {"text": text, "binaries": [], "skipped": [], "limits_hit": [], "members": sorted(text)}


# ------------------------------------------------------------------ result summary

def _hash_check(item: dict, url: str | None) -> dict:
    if not url:
        return {"sha256": None, "hash_match": None}
    import http_cache
    blob, err = http_cache.get_bytes(url, 5 * 1024 * 1024)   # served from the cache written by the release fetch
    if err or blob is None:
        return {"sha256": None, "hash_match": None}
    sha = hashlib.sha256(blob).hexdigest()
    match = None
    if item.get("sha256"):
        match = sha == item["sha256"]
    elif str(item.get("npm_integrity", "")).startswith("sha512-"):
        match = "sha512-" + base64.b64encode(hashlib.sha512(blob).digest()).decode() == item["npm_integrity"]
    return {"sha256": sha, "hash_match": match}


def summarise(gate: dict, scan: dict) -> dict:
    dets, counts, compact = {}, {"known_malicious": 0, "high_risk": 0, "review": 0, "info": 0}, []
    for d in gate.get("detectors") or []:
        fs = d.get("findings") or []
        dets[d["detector"]] = {"pillar": d.get("pillar"), "status": d.get("status"), "tier": d.get("tier"),
                               "reason": d.get("not_assessed_reason"), "coverage": d.get("coverage"),
                               "coverage_detail": d.get("coverage_detail"), "content_truncated": d.get("content_truncated"),
                               "n_findings": len(fs), "n_info": len(d.get("info_findings") or []),
                               "fragility_amplified": bool(d.get("fragility_amplified"))}
        for f in fs:
            if f.get("tier") in counts:
                counts[f["tier"]] += 1
            if len(compact) < 60:
                compact.append({"detector": d["detector"], "tier": f.get("tier"), "rule": str(f.get("rule", ""))[:160],
                                "file": f.get("file"), "line": f.get("line"),
                                "fragility_amplified": bool(f.get("fragility_amplified"))})
        counts["info"] += len(d.get("info_findings") or [])
    pillars = {k: (v or {}).get("score") for k, v in (gate.get("pillars") or {}).items()}
    sc = scan.get("scan_coverage") or {}
    return {"trust_score": gate.get("trust_score"), "label": gate.get("label"), "label_base": gate.get("trust_label_base"),
            "pillars": pillars, "maintenance_score": gate.get("maintenance_score"),
            "limiting_reason": gate.get("limiting_reason"), "evidence_caps": gate.get("evidence_caps"),
            "fragility_score": (gate.get("fragility") or {}).get("score"),
            "detectors": dets, "findings_by_tier": counts, "findings": compact,
            "coverage": {"partial": gate.get("partial"), "partial_reasons": gate.get("partial_reasons"),
                         "content_partial": sc.get("partial"), "content_detail": sc.get("detail"),
                         "content_scan_ran": bool(scan.get("ran"))}}


def _empty_scan() -> dict:
    return {"ran": False, "findings": [], "coverage": [], "strong": 0, "review": 0, "code_high": 0,
            "secrets_strong": 0, "ci_high": 0, "code_scan": "not_run", "malware_proof": None,
            "known_malicious_count": 0, "high_risk_pattern_count": 0, "timings": {}}


# ------------------------------------------------------------------ modes

def artifact_security(eco: str, name: str, version: str | None, osv: bool) -> dict:
    """Security sources available without a repository: only the OSV MAL- check of this exact package version."""
    import security
    checks = {"github_advisories": "not_assessed", "osv_dependencies": "not_assessed", "own_package": "not_assessed",
              "scorecard": "not_assessed"}
    findings, coverage = [], ["Artifact mode: GitHub advisories, dependency advisories and Scorecard are not used"]
    if osv:
        try:
            ids = security._osv_mal_ids({"ecosystem": eco, "name": name}, version or None)
            checks["own_package"] = "ran"
            if ids:
                findings.append({"severity": "High", "source": "OSV (Confirmed Malware)", "item": f"{name} {version} ({eco})",
                                 "detail": f"{len(ids)} malicious-package advisory(ies) affect this version, e.g. {ids[0]}."})
            coverage.append(f"OSV MAL- check of {name} {version}: {len(ids)} advisory(ies)")
        except Exception as e:
            coverage.append(f"OSV MAL- check: NOT run ({e})")
    else:
        coverage.append("OSV MAL- check: disabled (ablation)")
    return {"level": "Not assessed", "findings": findings, "coverage": coverage, "checks": checks,
            "package": {"ecosystem": eco, "name": name}}


def scan_artifact(item: dict, osv: bool) -> dict:
    import releases
    import repo_scan
    from security import apply_gate
    eco, name, version = item["ecosystem"], item["package"], item.get("version") or None
    rec: dict = {"artifact": {}}
    rc, as_of = None, None
    if item.get("source") == "datadog":
        contents = load_sample_dir(item["sample_dir"])
        if not contents["text"]:   # deleted or quarantined by antivirus: never scan an empty folder as "no findings"
            return {**rec, "status": "not_assessed",
                    "not_assessed_reason": f"sample files missing in {item['sample_dir']} (deleted or quarantined?)"}
        rec["artifact"] = {"kind": "datadog_sample", "path": item["sample_dir"], "sha256": item.get("sha256"),
                           "hash_match": None, "members": len(contents["text"])}
    else:
        fetch = releases.fetch_pypi if eco == "PyPI" else releases.fetch_npm if eco == "npm" else None
        if fetch is None:
            return {**rec, "status": "not_applicable", "not_assessed_reason": f"unsupported ecosystem {eco}"}
        hist = fetch(name, releases.DEFAULT_N, time.monotonic() + releases.FETCH_BUDGET_S, version)
        if hist.get("status") != "ok" or not hist.get("releases"):
            return {**rec, "status": "not_assessed", "not_assessed_reason": f"registry: {hist.get('reason')}"}
        target = hist["releases"][0]
        art = target.get("artifact") or {}
        rec["artifact"] = {"kind": art.get("kind") or art.get("packagetype"), "filename": art.get("filename"),
                           "url": art.get("url"), "version": target["version"], "status": target.get("artifact_status")}
        if target.get("contents") is None:
            return {**rec, "status": "not_assessed",
                    "not_assessed_reason": f"artifact not read ({target.get('artifact_status')})"}
        contents = target["contents"]
        rec["artifact"].update(_hash_check(item, art.get("url")))
        rec["artifact"]["members"] = len(contents.get("members") or [])
        hist.update({"ecosystem": eco, "name": name})
        deps = releases.fetch_dependency_changes(hist, time.monotonic() + releases.FETCH_BUDGET_S) \
            if hist["status"] == "ok" else None
        na = {"status": "not_assessed", "reason": "artifact mode: the repository is not used", "commits": []}
        rc = {"package": {"ecosystem": eco, "name": name}, "history": hist, "git": dict(na), "dependencies": deps,
              "activity": dict(na), "requested_repo": None, "snapshot": os.environ.get("REPOHEALTH_SNAPSHOT"),
              "target_version": version, "timings": {}}
        version = version or target["version"]
        as_of = releases._dt(target.get("upload_time"))
    data = data_from_contents(contents)
    scan = repo_scan.scan_data(_empty_scan(), data, eco, name, lambda f, ln: None, bandit_enabled=False)
    rec["limits_hit"] = list(contents.get("limits_hit") or []) + list(scan.get("limits_hit") or [])
    sec = artifact_security(eco, name, version, osv)
    health = {"score": None, "label": "Not assessed (artifact mode)"}
    gate = apply_gate(health, sec, [], scan, features=None, releases=rc, as_of=as_of)
    rec.update(summarise(gate, scan))
    rec["status"] = "scored" if scan.get("ran") else "not_assessed"
    if not scan.get("ran"):
        rec["not_assessed_reason"] = "content scan did not run"
    return rec


def scan_repository(item: dict, osv: bool) -> dict:
    import repo_scan
    from github_client import GitHubClient, fetch_features
    from releases import collect_release_context
    from scoring import compute_health_score
    from security import apply_gate, assess_security, content_flags
    slug = (item.get("repo") or "").strip()
    if "/" not in slug:
        return {"status": "not_applicable", "not_assessed_reason": "no GitHub repository in the manifest"}
    owner, name = slug.split("/", 1)
    client = GitHubClient(os.environ.get("GITHUB_TOKEN"))
    try:
        feats = fetch_features(client, owner, name)
    except Exception as e:
        return {"status": "not_assessed", "not_assessed_reason": f"repository features: {type(e).__name__}: {str(e)[:160]}"}
    scan = repo_scan.scan_repo(client, owner, name)
    try:
        sec = assess_security(client, owner, name)
    except Exception as e:
        sec = {"level": "Not assessed", "findings": [], "coverage": [f"security sources crashed ({type(e).__name__})"],
               "checks": {k: "not_assessed" for k in ("github_advisories", "osv_dependencies", "own_package", "scorecard")}}
    if not osv:
        sec = {**sec, "findings": [f for f in sec.get("findings") or [] if f.get("source") != "OSV (Confirmed Malware)"]}
    try:
        rc = collect_release_context(owner, name, sec.get("package"))
    except Exception:
        rc = None
    health = compute_health_score(feats)
    gate = apply_gate(health, sec, content_flags(feats), scan, features=feats, releases=rc)
    rec = summarise(gate, scan)
    rec["limits_hit"] = ([scan["scan_coverage"]["detail"]] if (scan.get("scan_coverage") or {}).get("detail") else []) \
        + list(scan.get("limits_hit") or [])
    if scan.get("ran"):
        rec["status"] = "scored"
    else:
        rec["status"] = "not_assessed"
        rec["not_assessed_reason"] = f"content scan did not run ({scan.get('skip_reason') or 'unknown'})"
    return rec


# ------------------------------------------------------------------ run loop

def run_item(item: dict, mode: str, osv: bool, budget_s: float, scan_fn=None) -> dict:
    """In-process run (--no-isolate, for debugging): a worker thread with a time budget. Python threads cannot be
    killed, so a scan that overruns is abandoned (still running) and recorded as a timeout."""
    box: dict = {}
    fn = scan_fn or (scan_artifact if mode == "artifact" else scan_repository)

    def work():
        try:
            box["rec"] = fn(item, osv)
        except MemoryError:
            box["rec"] = {"status": "not_assessed", "not_assessed_reason": "killed: out of memory (MemoryError)",
                          "error": "killed"}
        except Exception as e:   # one bad item must not stop the run; it is recorded, never as "no findings"
            box["rec"] = {"status": "not_assessed", "not_assessed_reason": f"scan raised {type(e).__name__}: {str(e)[:200]}",
                          "error": type(e).__name__}

    t0 = time.monotonic()
    th = threading.Thread(target=work, daemon=True)
    th.start()
    th.join(budget_s)
    if th.is_alive():
        rec = {"status": "not_assessed", "not_assessed_reason": f"timeout: item time budget ({budget_s:.0f} s) exceeded",
               "error": "timeout"}
    else:
        rec = box.get("rec") or {"status": "not_assessed", "not_assessed_reason": "no result", "error": "unknown"}
    rec["elapsed_s"] = round(time.monotonic() - t0, 2)
    rec["isolation"] = "thread (--no-isolate)"
    return rec


# ------------------------------------------------------------------ process isolation

def _windows_job_memory_cap(mb: int) -> str:
    """Put the current process in a Windows Job Object with a per-process committed-memory limit. An allocation
    beyond it fails, which Python raises as MemoryError."""
    import ctypes
    from ctypes import wintypes

    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

    class IO(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOps", "WriteOps", "OtherOps", "ReadBytes", "WriteBytes", "OtherBytes")]

    class EXTENDED(ctypes.Structure):
        _fields_ = [("Basic", BASIC), ("Io", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return f"unavailable (CreateJobObject error {ctypes.get_last_error()})"
    info = EXTENDED()
    info.Basic.LimitFlags = 0x00000100            # JOB_OBJECT_LIMIT_PROCESS_MEMORY
    info.ProcessMemoryLimit = mb * 1024 * 1024
    if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):   # ExtendedLimitInformation
        return f"unavailable (SetInformationJobObject error {ctypes.get_last_error()})"
    if not k32.AssignProcessToJobObject(job, k32.GetCurrentProcess()):
        return f"unavailable (AssignProcessToJobObject error {ctypes.get_last_error()})"
    return f"Windows job object, {mb} MB per process"


def apply_memory_cap(mb: int | None) -> str:
    """Memory cap for the current (item) process, where the platform allows it. Returns a description."""
    if not mb:
        return "off"
    try:
        if os.name == "nt":
            return _windows_job_memory_cap(mb)
        import resource
        lim = mb * 1024 * 1024
        _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        if hard != resource.RLIM_INFINITY and hard < lim:
            lim = hard
        resource.setrlimit(resource.RLIMIT_AS, (lim, hard))
        return f"RLIMIT_AS {lim // (1024 * 1024)} MB"
    except Exception as e:   # never fail the item because the cap could not be set; say so in the record
        return f"unavailable ({type(e).__name__})"


def _resolve(spec: str):
    import importlib
    mod, fn = spec.split(":", 1)
    return getattr(importlib.import_module(mod), fn)


def _child_entry(conn, item: dict, cfg: dict) -> None:
    """Runs in a fresh (spawned) process: memory cap, environment, patches, one scan, result through the pipe."""
    cap = apply_memory_cap(cfg.get("mem_mb"))
    os.environ.update(cfg.get("env") or {})
    rec = None
    try:
        import repo_scan
        repo_scan.MAX_LINE_CHARS = cfg.get("line_cap")
        fn = _resolve(cfg["scan_fn"]) if cfg.get("scan_fn") else (scan_artifact if cfg["mode"] == "artifact" else scan_repository)
        with Patches(offline=cfg["offline"], osv=cfg["osv"], fragility_escalation=cfg["fragility_escalation"],
                     osv_index=OsvIndex(cfg["offline"], Path(cfg["osv_cache"]) if cfg.get("osv_cache") else None),
                     artifact_mode=cfg["mode"] == "artifact"):
            rec = fn(item, cfg["osv"])
    except MemoryError:
        rec = {"status": "not_assessed", "error": "killed",
               "not_assessed_reason": f"killed: memory limit exceeded ({cap})"}
    except Exception as e:
        rec = {"status": "not_assessed", "not_assessed_reason": f"scan raised {type(e).__name__}: {str(e)[:200]}",
               "error": type(e).__name__}
    rec["isolation"] = f"process (memory cap: {cap})"
    rec["ai_modules_loaded"] = [m for m in AI_MODULES if m in sys.modules]
    try:
        conn.send(rec)
    finally:
        conn.close()


def run_item_isolated(item: dict, cfg: dict, budget_s: float) -> dict:
    """One item in its own spawned process (spawn start method, also on Windows) with a hard timeout: on overrun the process is killed.
    Killed or crashed items are recorded as not_assessed ("timeout ..." / "killed ..."), never as "no findings"."""
    import multiprocessing as mp
    ctx = mp.get_context("spawn")
    rconn, wconn = ctx.Pipe(duplex=False)
    p = ctx.Process(target=_child_entry, args=(wconn, item, cfg), daemon=True)
    t0 = time.monotonic()
    p.start()
    wconn.close()
    rec = None
    try:
        if rconn.poll(budget_s):
            rec = rconn.recv()
    except (EOFError, OSError):
        rec = None
    if rec is None:
        if p.is_alive():
            p.kill()
            p.join(10)
            rec = {"status": "not_assessed", "error": "timeout",
                   "not_assessed_reason": f"timeout: no result within {budget_s:.0f} s (process killed)"}
        else:
            p.join(5)
            rec = {"status": "not_assessed", "error": "killed",
                   "not_assessed_reason": f"killed: the item process ended without a result (exit code {p.exitcode})"}
        rec["isolation"] = "process"
    else:
        p.join(30)
        if p.is_alive():
            p.kill()
            p.join(5)
    rconn.close()
    rec["elapsed_s"] = round(time.monotonic() - t0, 2)
    return rec


def fmt_hms(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    seconds = int(round(seconds))
    return f"{seconds // 3600:d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


def eta_seconds(durations: list[float], remaining: int) -> float | None:
    """Remaining items x the running median of the item durations so far (None before the first item)."""
    if not durations:
        return None
    import statistics
    return statistics.median(durations) * remaining


def applicable(item: dict, mode: str) -> bool:
    if mode == "artifact":
        return bool(item.get("package")) and item.get("ecosystem") in ("PyPI", "npm") or item.get("source") == "datadog"
    return item["category"] in REPO_CATEGORIES


def select(items: list[dict], args) -> list[dict]:
    out = [i for i in items if args.split == "all" or i["split"] == args.split]
    if args.category:
        out = [i for i in out if i["category"] in args.category]
    if args.debug_slice:
        allowed = {r["repo"].lower() for r in bench_items.read_manifest(bench_items.MAN / "debug_slice.csv")}
        out = [i for i in out if i["split"] == "dev" and (i.get("repo") or "").lower() in allowed]
    out = sorted(out, key=lambda i: i["id"])
    random.Random(args.seed).shuffle(out)
    return out


def default_out(args) -> Path:
    tag = f"{args.mode}-{args.split}"
    if args.debug_slice:
        tag += "-debugslice"
    if not args.osv:
        tag += "-noosv"
    if not args.fragility_escalation:
        tag += "-nofrag"
    return RUNS / f"{tag}.jsonl"


def load_done(path: Path, retry_errors: bool) -> tuple[dict, dict | None]:
    """{item_id: last record} and the run config of the existing file (None if empty)."""
    last, cfg = {}, None
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue   # a line cut off by an interruption
                last[r["id"]] = r
                cfg = cfg or r.get("run")
    done = {k: r for k, r in last.items() if not r.get("retryable") and not (retry_errors and r.get("error"))}
    return done, cfg


def append(path: Path, rec: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mode", choices=("artifact", "repo"), default="artifact")
    ap.add_argument("--split", choices=("dev", "test", "replay", "all"), default="dev")
    ap.add_argument("--category", action="append", choices=bench_items.CATEGORIES,
                    help="restrict to a category (repeatable)")
    ap.add_argument("--debug-slice", action="store_true", help="only the harness-debug slice (dev items)")
    ap.add_argument("--limit", type=int, default=None, help="scan at most N new items in this run")
    ap.add_argument("--seed", type=int, default=SEED, help="item order (and therefore the --limit subset)")
    ap.add_argument("--no-osv", dest="osv", action="store_false", help="ablation: OSV MAL- lookups off")
    ap.add_argument("--no-fragility-escalation", dest="fragility_escalation", action="store_false",
                    help="ablation: fragility escalation off")
    ap.add_argument("--virustotal", action="store_true", help="use VT_API_KEY if set (default: VirusTotal off)")
    ap.add_argument("--offline", action="store_true", help="serve HTTP only from the cache; no network at all")
    ap.add_argument("--snapshot", default=None, help="cache snapshot date YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--item-budget", type=float, default=DEFAULT_ITEM_BUDGET_S, help="seconds per item")
    ap.add_argument("--sleep", type=float, default=0.5, help="pause between items (seconds)")
    ap.add_argument("--retry-errors", action="store_true", help="also retry items whose scan raised")
    ap.add_argument("--out", default=None, help="output JSONL (default benchmark/runs/<mode>-<split>[...].jsonl)")
    ap.add_argument("--no-isolate", dest="isolate", action="store_false",
                    help="debugging: run items in this process (no hard kill, no memory cap)")
    ap.add_argument("--mem-mb", type=int, default=DEFAULT_MEM_MB, help="memory cap per item process (0 = off)")
    ap.add_argument("--samples-dir", default=None, help="extracted samples root (default benchmark/samples)")
    ap.add_argument("--selfcheck", action="store_true", help="check hosts, disk, samples dir and three dev items; "
                    "never touches the test split")
    ap.add_argument("--scan-fn", default=None, help=argparse.SUPPRESS)   # harness tests only: module:function
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.selfcheck:
        setup_env(args)
        import selfcheck
        return selfcheck.run(Path(args.samples_dir) if args.samples_dir else None)
    try:
        assert_ai_off()
        envinfo = setup_env(args)
        recorded = check_frozen(args.split)
        items, moves = bench_items.all_items()       # refuses without dev_credibility.csv
    except GuardError as e:
        print(str(e), file=sys.stderr)
        return 2
    from detectors import RULESET_VERSION
    out = Path(args.out) if args.out else default_out(args)
    run_cfg = {"mode": args.mode, "split": args.split, "osv": args.osv, "fragility_escalation": args.fragility_escalation,
               "virustotal": args.virustotal, "ruleset_version": RULESET_VERSION, "protocol_ruleset": recorded,
               "snapshot": os.environ["REPOHEALTH_SNAPSHOT"], "seed": args.seed, "offline": args.offline,
               "contamination": contamination(), "ai_layer": "off"}
    done, old_cfg = load_done(out, args.retry_errors)
    if old_cfg:
        keys = ("mode", "osv", "fragility_escalation", "ruleset_version", "virustotal")
        diff = [k for k in keys if old_cfg.get(k) != run_cfg.get(k)]
        if diff:
            print(f"REFUSING TO RESUME {out}: it was written with different settings ({', '.join(diff)}). "
                  "Use another --out.", file=sys.stderr)
            return 2
    todo_all = [i for i in select(items, args) if applicable(i, args.mode)]
    todo = [i for i in todo_all if i["id"] not in done]
    if args.limit is not None:
        todo = todo[: args.limit]
    for n in envinfo["notes"]:
        print("note:", n)
    print(f"ruleset {RULESET_VERSION} | snapshot {run_cfg['snapshot']} | seed {args.seed} | mode {args.mode} | "
          f"split {args.split} | OSV {'on' if args.osv else 'OFF (ablation)'} | fragility escalation "
          f"{'on' if args.fragility_escalation else 'OFF (ablation)'} | AI layer off | test set {run_cfg['contamination']}")
    print(f"dev-set overlap moves: {len(moves)} | output {out}")
    print(f"{len(done)} item(s) already done, {len(todo)} to scan now (of {len(todo_all)} selected)")
    osv_index = OsvIndex(args.offline)
    if args.mode == "artifact" or args.osv:
        osv_index.prepare()                          # once, before the items (each item process only reads it)
    cfg = {"mode": args.mode, "osv": args.osv, "fragility_escalation": args.fragility_escalation,
           "offline": args.offline, "mem_mb": args.mem_mb, "line_cap": LINE_CAP_CHARS, "scan_fn": args.scan_fn,
           "osv_cache": str(osv_index.cache_dir),
           "env": {k: v for k, v in os.environ.items() if k.startswith("REPOHEALTH_")}}
    print(f"isolation: {'one process per item, hard timeout ' + str(int(args.item_budget)) + ' s, memory cap ' + (str(args.mem_mb) + ' MB' if args.mem_mb else 'off') if args.isolate else 'OFF (--no-isolate, debugging)'}"
          f" | line cap {LINE_CAP_CHARS} characters")
    scannable = [i for i in todo if not (args.mode == "artifact" and i.get("obtainable") != "yes")]
    durations: list[float] = []
    t_start = time.monotonic()
    patches = None
    if not args.isolate:
        import repo_scan
        repo_scan.MAX_LINE_CHARS = LINE_CAP_CHARS
        patches = Patches(offline=args.offline, osv=args.osv, fragility_escalation=args.fragility_escalation,
                          osv_index=osv_index, artifact_mode=args.mode == "artifact").__enter__()
    try:
        scanned = 0
        for k, item in enumerate(todo, 1):
            started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if args.mode == "artifact" and item.get("obtainable") != "yes":
                rec = {"status": "unobtainable", "not_assessed_reason": item.get("obtainable_detail") or "code not obtainable",
                       "elapsed_s": 0.0}
            elif args.isolate:
                rec = run_item_isolated(item, cfg, args.item_budget)
                scanned += 1
            else:
                rec = run_item(item, args.mode, args.osv, args.item_budget,
                               scan_fn=_resolve(args.scan_fn) if args.scan_fn else None)
                scanned += 1
            if rec.get("ai_modules_loaded"):
                raise GuardError(f"REFUSING TO CONTINUE: AI module(s) loaded while scanning {item['id']}: "
                                 f"{', '.join(rec['ai_modules_loaded'])}")
            assert_ai_off()
            if rec["status"] != "unobtainable":
                durations.append(float(rec.get("elapsed_s") or 0))
            reason = rec.get("not_assessed_reason")
            rec.update({k2: item.get(k2) for k2 in ("id", "category", "split", "ecosystem", "package", "version", "repo",
                                                     "source", "move_reason")})
            rec.update({"mode": args.mode, "ruleset_version": RULESET_VERSION, "run": run_cfg, "started_at": started,
                        "retryable": rec.get("status") == "not_assessed" and transient(reason),
                        "error": rec.get("error") or ""})
            append(out, rec)
            fb = rec.get("findings_by_tier") or {}
            what = (f"{rec.get('label')} | KM={fb.get('known_malicious', 0)} HR={fb.get('high_risk', 0)} "
                    f"R={fb.get('review', 0)}") if rec["status"] == "scored" else f"{rec['status']}: {reason}"
            eta = eta_seconds(durations, len(scannable) - scanned)
            print(f"[{k}/{len(todo)}] {item['id']}: {what} ({rec.get('elapsed_s')}s) | elapsed "
                  f"{fmt_hms(time.monotonic() - t_start)} | ETA {fmt_hms(eta)}", flush=True)
            if args.sleep and rec["status"] != "unobtainable":
                time.sleep(args.sleep)
    finally:
        if patches is not None:
            patches.__exit__(None, None, None)
    print(f"done in {fmt_hms(time.monotonic() - t_start)}. OSV index: {osv_index.status or 'not used'}")
    return 0


def _entry() -> int:
    try:
        return main()
    except KeyboardInterrupt:
        print("\ninterrupted: finished items are saved; run the same command again to resume", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(_entry())
