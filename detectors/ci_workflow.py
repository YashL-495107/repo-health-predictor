"""ci_workflow (Exposure) - adapter for the existing GitHub Actions checks (repo_scan.scan_workflow).

Detects: pull_request_target checking out PR code, script injection of event data into run steps, download piped
to a shell, permissions: write-all. (Unpinned third-party actions stay Low and get no tier.)
Tier: High and Medium workflow findings -> review. The existing security.py rule still caps the headline at 49
for a strong (High) CI finding ("capped by evidence rule: strong CI finding").
Known evasions: logic in composite actions or reusable workflows in other repos, scripts called from run steps.
False-positive sources: workflows that are only triggered by maintainers, injection into quoted env variables.
"""
from .base import content_gate, enrich, make_result, scan_findings, text_coverage

DETECTOR_ID, PILLAR = "ci_workflow", "Exposure"


def detect(ctx) -> dict:
    gate = content_gate(ctx, DETECTOR_ID, PILLAR)
    if gate:
        return gate
    out = [enrich(f, DETECTOR_ID, "review") for f in scan_findings(ctx)
           if f.get("source") == "CI workflow" and f.get("sev") in ("High", "Medium")]
    cov, detail = text_coverage(ctx, ("workflows",))
    return make_result(DETECTOR_ID, PILLAR, "ran", out, coverage=cov, coverage_detail=detail)
