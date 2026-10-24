"""Full-Stack Integration & Validity Verification Suite for Phases 1 through 4.

Runs live validation checks across:
  - Phase 1: Bus Factor, Gini entropy & Burnout velocity metrics.
  - Phase 2: Active fork discovery & open issue triage categorization.
  - Phase 3: Supply-Chain blast radius, reverse-dependents & typosquatting guard.
  - Phase 4: 4-Layer Malware Proof Engine (AST deobfuscation, sandbox, VT, release diff).
"""
from __future__ import annotations

import os
from dotenv import load_dotenv

from blast_radius import compute_repo_blast_radius, check_typosquat
from bus_factor import run_bus_factor_analysis
from github_client import GitHubClient, parse_repo
from intelligence import run_intelligence_engine
from repo_scan import scan_repo
from security import assess_security, content_flags, apply_gate
from scoring import compute_health_score


def main():
    load_dotenv()
    token = os.getenv("GITHUB_TOKEN", "")
    client = GitHubClient(token)

    print("=" * 78)
    print(" FULL-STACK OPEN-SOURCE INTELLIGENCE & SUPPLY-CHAIN VALIDATION SUITE")
    print("=" * 78)

    test_repos = ["psf/requests", "pallets/flask", "psf/cachecontrol"]
    passed = 0
    total = 0

    for repo_str in test_repos:
        total += 1
        print(f"\n[TEST {total}] Analyzing target: {repo_str} ...")
        try:
            owner, repo = parse_repo(repo_str)
            
            # 1. Base Health & Security Scan
            from github_client import fetch_features
            features = fetch_features(client, owner, repo)
            health = compute_health_score(features)
            security = assess_security(client, owner, repo)
            flags = content_flags(features)
            scan = scan_repo(client, owner, repo)
            result = apply_gate(health, security, flags, scan)

            print(f"  -> Health Score: {result['score']}/100 ({result['label']})")
            print(f"  -> Content Scan Ran: {scan['ran']} | Strong Findings: {scan['strong']} | Verified Malware: {scan.get('verified_malware', 0)}")

            # 2. Phase 1: Bus Factor & Burnout
            bus = run_bus_factor_analysis(client, owner, repo)
            print(f"  -> [Phase 1] Bus Factor: {bus['bus_factor']} | Gini: {bus['gini']} | Burnout: {bus['burnout_status']}")
            assert "bus_factor" in bus and "gini" in bus, "Phase 1 missing keys"

            # 3. Phase 2: Intelligence & Triage
            intel = run_intelligence_engine(client, owner, repo, features, result, "")
            print(f"  -> [Phase 2] AI Source: {intel['ai_report']['source']} | Forks Found: {len(intel['forks'])} | Issue Buckets: {list(intel['issue_triage']['counts'].keys())}")
            assert "ai_report" in intel and "forks" in intel, "Phase 2 missing keys"

            # 4. Phase 3: Blast Radius & Typosquatting
            blast = compute_repo_blast_radius(features, security, scan.get("malware_proof", {}).get("release_diff"))
            print(f"  -> [Phase 3] Tier: {blast['tier']} | Blast Score: {blast['blast_score']} | Downstream: {blast['estimated_downstream_repos']:,}")
            assert "blast_score" in blast and "tier" in blast, "Phase 3 missing keys"

            # 5. Phase 4: Malware Proof Engine
            proof = scan.get("malware_proof", {})
            print(f"  -> [Phase 4] Verified Proofs: {proof.get('verified_proof_count', 0)} | Benign Filtered: {proof.get('benign_blobs_filtered', 0)}")
            assert "verified_proof_count" in proof, "Phase 4 missing malware_proof dict"

            print(f"[PASS] {repo_str} successfully validated across all 4 phases.")
            passed += 1

        except Exception as e:
            print(f"[FAIL] {repo_str} encountered an error: {e}")
            import traceback
            traceback.print_exc()

    # Test Typosquatting Guard explicitly
    print("\n[TEST Typosquat Guard] Testing namespace typo detection...")
    fake_typo = "reqeusts"
    twin = check_typosquat(fake_typo)
    if twin == "requests":
        print(f"[PASS] Typosquat check successfully caught '{fake_typo}' as lookalike of '{twin}'.")
        passed += 1
        total += 1
    else:
        print(f"[FAIL] Typosquat check failed to catch '{fake_typo}'.")
        total += 1

    print("=" * 78)
    print(f" VALIDATION RESULT: {passed}/{total} checks passed ({passed / total:.0%})")
    print("=" * 78)
    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()