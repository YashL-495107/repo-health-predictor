"""Batch scan for the detection benchmark: run the content scanner over a list of repos and write one CSV row per repo.

Resumable: repos already in --output are skipped (use --retry-errors to rescan rows that failed with an exception).
The CSV is rewritten (atomically) after every repo, so an interrupted run loses at most the repo in progress.
"""
import argparse, os, re, time
import pandas as pd
from dotenv import load_dotenv
from github_client import GitHubClient, parse_repo
from repo_scan import scan_repo
from security import assess_security

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
    for c in res.get("coverage", []):
        if c.startswith("Content scan: NOT run"):
            return c[len("Content scan: NOT run"):].strip(" ,()").removeprefix("repository is ").strip() or "not run"
    return "not run"


def scan_one(client, full: str) -> dict:
    owner, name = parse_repo(full)
    res = scan_repo(client, owner, name)
    proof = res.get("malware_proof") or {}
    pf = proof.get("findings", [])
    # proof findings are complete; res["findings"] is capped at 60, so merge both for secrets/CI and dedupe
    all_f = pf + [f for f in res.get("findings", []) if f not in pf]
    try:
        sec = assess_security(client, owner, name)
        osv_items = [f.get("item", "") for f in sec.get("findings", []) if f.get("source") == "OSV (Confirmed Malware)"]
        osv_mal = bool(osv_items)
    except Exception:
        osv_items, osv_mal = [], None   # unknown, not False
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
    }


def build_row(client, full: str, group: str | None = None) -> dict:
    """One CSV row. Never raises: a failing scan becomes ran=False with error=<ExceptionType>."""
    t0 = time.time()
    row = {"repo": full}
    if group is not None:
        row["group"] = group
    try:
        row.update(scan_one(client, full))
    except Exception as e:  # one bad repo must not stop the batch
        row.update({"ran": False, "error": type(e).__name__, "skipped_reason": "scan raised an exception"})
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
    args = ap.parse_args()
    load_dotenv()
    client = GitHubClient(os.getenv("GITHUB_TOKEN"))

    inp = pd.read_csv(args.input)
    groups = dict(zip(inp["repo"], inp[args.group_column].astype(str))) if args.group_column in inp.columns else {}
    rows = pd.read_csv(args.output).to_dict("records") if os.path.exists(args.output) else []
    if args.retry_errors:
        rows = [r for r in rows if not (isinstance(r.get("error"), str) and r["error"])]
    done = {r["repo"] for r in rows}
    todo = [r for r in inp["repo"].tolist() if r not in done]
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
