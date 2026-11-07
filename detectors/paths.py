"""One shared classifier for NON-SHIPPING paths: files that are part of the repository but not of what users install
or run (tests, fixtures, docs, build output, developer tooling).

Used for ALL review-tier single-indicator findings (legacy behavior regexes, credential_exfiltration review flows,
secrets, committed binaries, decoded-payload review hits, JS/shell pattern matches) and for capability-free phantom
files: in these paths they become info (no tier) with the reason recorded. It is NEVER applied to high_risk or
known_malicious findings: a decoded payload that executes, or a phantom file with a network call, stays high_risk
wherever it is. `.github/` (CI workflows) is deliberately NOT non-shipping: workflows run with the project's secrets.

Known evasion (documented): an attacker who places a single-indicator payload under tests/, docs/, tools/, ... is
reported as info, not review. Multi-signal findings in those paths are still high_risk.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

NON_SHIPPING_DIRS = {"test", "tests", "testing", "testdata", "test_data", "fixture", "fixtures", "asset", "assets",
                     "sample", "samples", "example", "examples", "doc", "docs", "_static", "_build", "tool", "tools",
                     "script", "scripts", ".agents",
                     # rule-definition directories (detection rules contain indicator strings by design)
                     "rules", "signatures", "yara", "sigma", "detections"}
NON_SHIPPING_FILES = {"tasks.py", "noxfile.py"}
NEVER = {".github"}
# token match inside a directory name ("certbot_integration_tests", "sample-config"); underscore-led names
# (_static, _build) and .agents are matched as whole segments only
_TOKEN_DIRS = {d for d in NON_SHIPPING_DIRS if d[0].isalpha()}


def non_shipping(path: str | None) -> str | None:
    """The reason a path is non-shipping (e.g. "tests/ directory"), or None."""
    if not path:
        return None
    p = PurePosixPath(str(path))
    parts = [x.lower() for x in p.parts]
    if any(x in NEVER for x in parts[:-1]):
        return None
    if p.name.lower() in NON_SHIPPING_FILES:
        return f"{p.name} (developer task file)"
    for part in parts[:-1]:
        if part in NON_SHIPPING_DIRS:
            return f"{part}/ directory"
        hit = [t for t in re.split(r"[-_.]+", part) if t in _TOKEN_DIRS]
        if hit:
            return f"{part}/ directory ({hit[0]})"
    return None


def info_reason(path: str) -> str:
    return (f"Downgraded to info: a single indicator in a non-shipping path ({non_shipping(path)}). Test, fixture, "
            "docs, build-output and developer-tooling files are not what users install or run.")
