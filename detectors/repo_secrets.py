"""repo_secrets (Exposure) - adapter for the existing secret scan (repo_scan.scan_secrets).

Detects: provider key patterns (AWS, GitHub, Slack, Google, Stripe live keys, private key blocks) in text files.
Secrets are masked and NOT checked for validity.
Tier: a key-like string outside test/example/doc files -> review (strong). A private key block or sample-looking
key in a test / sample / asset / fixture / docs / rule-definition directory -> info (no tier, no cap), with the
reason recorded (repo_scan.secret_review_reason), consistent with the exact tests/ and docs/ fixture rule. The existing security.py rule still caps the
headline at 49 for a strong secret ("capped by evidence rule: strong secret").
Known evasions: split or encoded keys, providers without a distinctive prefix, files over the size/count caps.
False-positive sources: test fixtures not recognised as such, revoked or example keys, generated data.
"""
from .base import content_gate, enrich, make_result, scan_findings, text_coverage

DETECTOR_ID, PILLAR = "repo_secrets", "Exposure"


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR)
    if gate:
        return gate
    out = [enrich(f, DETECTOR_ID, "review") for f in scan_findings(ctx) if f.get("source") == "Secrets" and f.get("strong")]
    info = [f for f in scan_findings(ctx) if f.get("source") == "Secrets" and f.get("info_reason")]
    cov, detail = text_coverage(ctx, ("text",))
    res = make_result(DETECTOR_ID, PILLAR, "ran", out, coverage=cov, coverage_detail=detail)
    res["info_findings"] = info
    return res
