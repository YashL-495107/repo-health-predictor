"""Batch scan for the detection benchmark: run the content scanner over a list of repos and write one CSV row per repo.

Resumable: repos already in --output are skipped, EXCEPT rows that were not scanned because of a transient download
problem (timeout, connection error, HTTP 5xx), which are re-scanned automatically on the next run. Rows skipped for
"too large", "not found" or "refused" stay done. Use --retry-errors to also rescan rows where the scan raised.
The CSV is rewritten (atomically) after every repo, so an interrupted run loses at most the repo in progress.
"""
import argparse, os, re, time
import pandas as pd
from dotenv import load_dotenv
from github_client import GitHubClient, fetch_features, parse_repo
from repo_scan import scan_repo
from scoring import compute_health_score
from security import apply_gate, assess_security, content_flags
from detectors import RULESET_VERSION
from releases import collect_release_context

FLAG_SOURCES = ("Layer ", "Behavior", "Secrets", "CI workflow")   # malware engine, behavior, secrets, CI
MAX_FLAGGED, FLAG_ITEM_CHARS = 5, 120


def _count(findings, prefix):
    return sum(1 for f in findings if str(f.get("source", "")).startswith(prefix))


def flagged_text(findings: list[dict], osv_items: list[str] | None = None) -> str:
    """'<rule> @ <file>:<line>' for strong or High findings from the malware engine, behavior, secrets and CI scans."""
    out, seen = [], set()
    for f in findings:
        if not (f.get("strong") or f.get("sev") == "High"):
            continue
        if not str(f.get("source", "")).startswith(FLAG_SOURCES):
            continue
        item = f"{f.get('rule', '')} @ {f.get('file', '')}:{f.get('line', '')}"
        if item not in seen:
            seen.add(item)
            out.append(item[:FLAG_ITEM_CHARS])
    out += [f"OSV MAL- advisory @ {i}"[:FLAG_ITEM_CHARS] for i in (osv_items or [])]
    return "; ".join(out[:MAX_FLAGGED])


def skipped_reason(res: dict) -> str:
    """One of: timeout, too large, not found, refused, other: <type>."""
    if res.get("skip_reason"):
        return res["skip_reason"]
    text = " ".join(c for c in res.get("coverage", []) if c.startswith("Content scan: NOT run")).lower()
    if "timed out" in text or "timeout" in text: return "timeout"
    if "larger than" in text or "uncompressed" in text: return "too large"
    if "not found" in text: return "not found"
    if "refused" in text or "rate-limited" in text: return "refused"
    return "other: unknown"


_TRANSIENT = re.compile(r"^(?:timeout|other: (?:ConnectionError|HTTP 5\d\d))$")


def needs_rescan(row: dict) -> bool:
    """True for rows that were not scanned because of a transient download problem (re-scanned on resume)."""
    if str(row.get("ran")).strip().lower() in ("true", "1"):
        return False
    reason = str(row.get("skipped_reason") or "").strip()
    if _TRANSIENT.match(reason):
        return True
    legacy = (reason + " " + str(row.get("note") or "")).lower()   # CSVs from older versions
    return "timed out" in legacy or "connection error" in legacy


STAGES = ("features", "security", "zip_download", "content_scan", "release_fetch", "artifacts", "git",
          "dependencies", "commit_history", "detectors", "bus_factor")
_UNSET = object()


def _client_like(client):
    """A fresh GitHubClient with the same token: requests.Session is not guaranteed to be shareable across threads."""
    if client is None:
        return None
    auth = (getattr(client, "session", None) and client.session.headers.get("Authorization")) or ""
    return GitHubClient(auth[len("Bearer "):] if auth.startswith("Bearer ") else None)


def _timed(timings: dict, key: str, fn):
    t0 = time.monotonic()
    try:
        return fn()
    finally:
        timings[key] = round(time.monotonic() - t0, 2)


def scan_one(client, full: str) -> dict:
    """One repository. Independent network stages run in parallel (content scan with its zip download, security
    lookups, repository features); the release fetch starts as soon as the security lookups found the package.
    REPOHEALTH_SEQUENTIAL=1 runs the stages in order (for timing comparisons). Per-stage seconds go to t_* columns."""
    import http_cache
    from concurrent.futures import ThreadPoolExecutor
    owner, name = parse_repo(full)
    t: dict[str, float] = {}

    def security_stage():
        try:
            return _timed(t, "security", lambda: assess_security(_client_like(client) or client, owner, name))
        except Exception:
            return None

    def features_stage():
        try:
            return _timed(t, "features", lambda: fetch_features(_client_like(client) or client, owner, name))
        except Exception as e:
            return e

    def release_stage(sec):
        try:
            return _timed(t, "release_fetch", lambda: collect_release_context(owner, name, (sec or {}).get("package")))
        except Exception:
            return None

    content = lambda: _timed(t, "content_scan", lambda: scan_repo(_client_like(client) or client, owner, name))
    if http_cache.sequential():
        res, sec, feats = content(), security_stage(), features_stage()
        rc = release_stage(sec)
    else:
        with ThreadPoolExecutor(max_workers=3) as pool:
            f_scan, f_feat = pool.submit(content), pool.submit(features_stage)
            sec = security_stage()
            rc = release_stage(sec)          # needs the package name found by the security lookups
            res, feats = f_scan.result(), f_feat.result()
    proof = res.get("malware_proof") or {}
    pf = proof.get("findings", [])
    # proof findings are complete; res["findings"] is capped at 60, so merge both for secrets/CI and dedupe
    all_f = pf + [f for f in res.get("findings", []) if f not in pf]
    osv_items = [f.get("item", "") for f in (sec or {}).get("findings", []) if f.get("source") == "OSV (Confirmed Malware)"]
    osv_mal = bool(osv_items) if sec is not None else None   # unknown, not False
    trust = _timed(t, "detectors", lambda: trust_columns(client, owner, name, res, sec, features=feats, rc=rc))
    st = res.get("timings") or {}
    t["zip_download"] = st.get("zip_download")
    t["detectors"] = round((t.get("detectors") or 0) + (st.get("content_detectors") or 0), 2)
    rt = (rc or {}).get("timings") or {}
    t.update({"artifacts": rt.get("artifacts"), "git": rt.get("git"), "dependencies": rt.get("dependencies"),
              "commit_history": rt.get("activity"), "bus_factor": None})   # bus factor is not run in batch mode
    return {
        "ran": bool(res["ran"]),
        "error": "",
        "skipped_reason": "" if res["ran"] else skipped_reason(res),
        "layer1_findings": _count(pf, "Layer 1"),
        "setup_py_findings": _count(pf, "Layer 2"),
        "release_diff_findings": _count(pf, "Layer 4"),
        "behavior_findings": _count(pf, "Behavior"),
        "vt_findings": _count(pf, "Layer 3"),
        "osv_mal": osv_mal,
        "known_malicious_count": res.get("known_malicious_count", 0),
        "high_risk_pattern_count": res.get("high_risk_pattern_count", 0),
        "strong": res.get("strong", 0),
        "review": res.get("review", 0),
        "code_high": res.get("code_high", 0),
        "secrets_strong": res.get("secrets_strong", 0),
        "ci_high": res.get("ci_high", 0),
        "flagged": flagged_text(all_f, osv_items),
        **trust,
        **{f"t_{k}": t.get(k) for k in STAGES},
    }


def trust_columns(client, owner: str, name: str, res: dict, sec: dict | None, features=_UNSET, rc=_UNSET) -> dict:
    """Trust score + maintenance score for the batch CSV. The bus factor is not fetched here (extra API calls),
    so the fragility index uses maintenance and dormancy only. Missing inputs give empty values, never 0."""
    out = {"trust_score": None, "trust_label": "", "maintenance_score": None, "maintenance_label": "",
           "limiting": "", "partial": None, "ruleset_version": RULESET_VERSION}
    try:
        if features is _UNSET:
            features = fetch_features(client, owner, name)
        if isinstance(features, Exception):
            raise features
        health = compute_health_score(features)
        sec = sec or {"level": "Not assessed", "findings": [], "coverage": [],
                      "checks": {k: "not_assessed" for k in ("github_advisories", "osv_dependencies", "own_package", "scorecard")}}
        if rc is _UNSET:
            try:
                rc = collect_release_context(owner, name, sec.get("package"))
            except Exception:
                rc = None
        g = apply_gate(health, sec, content_flags(features), res, features=features, releases=rc)
        out.update({"trust_score": g["trust_score"], "trust_label": g["label"], "maintenance_score": g["maintenance_score"],
                    "maintenance_label": g["maintenance_label"], "limiting": g["limiting_reason"] or "",
                    "partial": g["partial"]})
    except Exception as e:
        out["trust_label"] = f"not assessed ({type(e).__name__})"
    return out


def build_row(client, full: str, group: str | None = None) -> dict:
    """One CSV row. Never raises: a failing scan becomes ran=False with error=<ExceptionType>."""
    t0 = time.time()
    row = {"repo": full}
    if group is not None:
        row["group"] = group
    try:
        row.update(scan_one(client, full))
    except Exception as e:  # one bad repo must not stop the batch
        row.update({"ran": False, "error": type(e).__name__, "skipped_reason": f"other: {type(e).__name__}",
                    "ruleset_version": RULESET_VERSION})
    row["seconds"] = round(time.time() - t0, 1)
    return row


def _write(rows: list[dict], path: str):
    tmp = path + ".tmp"
    pd.DataFrame(rows).to_csv(tmp, index=False)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/backtest.csv")
    ap.add_argument("--output", default="data/scan_results.csv")
    ap.add_argument("--sleep", type=float, default=1.0)
    ap.add_argument("--limit", type=int, default=None, help="scan at most N new repos in this run")
    ap.add_argument("--group-column", default="group", help="input column copied to the output 'group' column, if present")
    ap.add_argument("--retry-errors", action="store_true", help="rescan rows that previously failed with an exception")
    ap.add_argument("--sequential", action="store_true", help="run each repo's stages in order (timing comparison)")
    ap.add_argument("--rescan", default="", help="comma-separated repos to re-scan even if already in --output (their rows are replaced)")
    args = ap.parse_args()
    if args.sequential:
        os.environ["REPOHEALTH_SEQUENTIAL"] = "1"
    load_dotenv()
    client = GitHubClient(os.getenv("GITHUB_TOKEN"))

    inp = pd.read_csv(args.input)
    groups = dict(zip(inp["repo"], inp[args.group_column].astype(str))) if args.group_column in inp.columns else {}
    rows = pd.read_csv(args.output).to_dict("records") if os.path.exists(args.output) else []
    forced = {x.strip() for x in args.rescan.split(",") if x.strip()}
    rescan = [r["repo"] for r in rows if needs_rescan(r) or r["repo"] in forced]
    rows = [r for r in rows if not (needs_rescan(r) or r["repo"] in forced)]
    if args.retry_errors:
        rows = [r for r in rows if not (isinstance(r.get("error"), str) and r["error"])]
    if rescan:
        print(f"re-scanning {len(rescan)} repo(s) (--rescan, or a previous timeout/connection error/5xx)")
    done = {r["repo"] for r in rows}
    todo = [r for r in inp["repo"].tolist() if r not in done]
    todo += [r for r in sorted(forced) if r not in done and r not in todo]   # --rescan may name repos not in --input
    for r in sorted(forced):
        if r in todo:   # forced repos go first so --limit does not skip them
            todo.remove(r); todo.insert(0, r)
    if args.limit is not None:
        todo = todo[:args.limit]
    print(f"{len(done)} already scanned, {len(todo)} to scan in this run")

    for i, full in enumerate(todo, 1):
        row = build_row(client, full, groups.get(full, "") if groups else None)
        rows.append(row)
        _write(rows, args.output)
        status = f"ERROR {row['error']}" if row.get("error") else (
            f"KM={row.get('known_malicious_count', 0)} HR={row.get('high_risk_pattern_count', 0)} strong={row.get('strong', 0)}"
            if row.get("ran") else f"not scanned: {row.get('skipped_reason')}")
        print(f"[{i}/{len(todo)}] {full}: {status} ({row['seconds']}s)")
        time.sleep(args.sleep)


if __name__ == "__main__":
    main()
