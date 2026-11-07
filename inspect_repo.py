"""Review one repository by hand: python inspect_repo.py owner/repo

Runs the same content scan as the app and prints (a) every finding that is strong or High, with source, rule,
file:line and detail, and (b) the full coverage list (what was and was not checked).
"""
from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

from github_client import GitHubClient, GitHubError, parse_repo
from repo_scan import scan_repo


def important(findings: list[dict]) -> list[dict]:
    """Strong or High findings, de-duplicated (proof findings can also appear in the main list)."""
    out, seen = [], set()
    for f in findings:
        if not (f.get("strong") or f.get("sev") == "High"):
            continue
        k = (f.get("source"), f.get("rule"), f.get("file"), f.get("line"))
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def report(res: dict) -> str:
    proof = (res.get("malware_proof") or {}).get("findings", [])
    rows = important(proof + res.get("findings", []))
    lines = [f"Scan ran: {res.get('ran')}" + ("" if res.get("ran") else f" (reason: {res.get('skip_reason', 'unknown')})"),
             f"strong={res.get('strong', 0)} known_malicious={res.get('known_malicious_count', 0)} "
             f"high_risk={res.get('high_risk_pattern_count', 0)}",
             "", f"== Strong or High findings ({len(rows)}) =="]
    for i, f in enumerate(rows, 1):
        tag = "STRONG" if f.get("strong") else f.get("sev", "")
        lines.append(f"{i:3d}. [{tag}] {f.get('source')} | {f.get('rule')}")
        lines.append(f"     at   {f.get('file')}:{f.get('line')}")
        lines.append(f"     what {f.get('detail', '')}")
        if f.get("url"):
            lines.append(f"     open {f['url']}")
    if not rows:
        lines.append("none")
    dets = res.get("detectors") or []
    if dets:
        lines += ["", f"== Content detectors ({len(dets)}, ruleset {res.get('ruleset_version', '')}) =="]
        for d in dets:
            extra = d.get("not_assessed_reason") or d.get("coverage_detail") or ""
            lines.append(f"- {d['detector']:<20} {d['pillar']:<9} {d['status']:<14} {d['tier']:<15} {extra}")
        lines.append("  (security sources such as OSV and Scorecard are added by the app / scan_batch, not by this scan)")
    lines += ["", f"== Coverage ({len(res.get('coverage', []))}) =="] + [f"- {c}" for c in res.get("coverage", [])]
    return "\n".join(lines)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python inspect_repo.py owner/repo", file=sys.stderr)
        return 2
    load_dotenv()
    try:
        owner, repo = parse_repo(argv[0])
        res = scan_repo(GitHubClient(os.getenv("GITHUB_TOKEN")), owner, repo)
    except GitHubError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"# {owner}/{repo}")
    print(report(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
