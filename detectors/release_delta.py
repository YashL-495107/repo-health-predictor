"""release_delta (Integrity) - "poisoned release": what the latest published release adds compared with the one
before it, read statically from both artifacts (sdist / wheel / npm tarball under 5 MB) and the registry fields.

Signals NEW in release N vs N-1 (see detectors/release_analysis.py): an install-time execution capability (npm
preinstall/install/postinstall that is not a known build step, setup.py install-time execution, a .pth start-up
file), a network or process capability the package did not have before, an encoded blob that the Layer 1 decoder
unwraps to indicators, a new executable.
Tier: high_risk only if a new install-time execution capability appears together with network access (new at
package level, or inside the new hook) or new decoded indicators. Any single new capability is review.
Evidence: the version pair (with upload times) and the files / hooks involved.
Time: compares two releases by their own upload times; nothing is measured against today's date.
Known evasions: payloads that only arrive at runtime (download after install), changes inside artifacts over 5 MB
(not read: coverage partial / not assessed), malicious code in a dependency rather than the package itself
(dependency_injection, Phase 3), capabilities hidden by string building that the regexes and the decoder miss,
poisoning spread over several releases so no single step adds a hook and network together.
False-positive sources: legitimate native-build hooks not in the BENIGN_HOOK list, a first-time telemetry or
update-check feature, vendored code that moved outside the ignored vendor folders, switching artifact type
between releases (sdist vs wheel), test files that are not in an ignored folder.
"""
from .base import make_result, not_assessed
from releases import MAX_MEMBERS

from .release_analysis import assess_pair, unread_relevant
from .release_common import PILLAR, release_finding, release_gate, version_pair

DETECTOR_ID = "release_delta"
LABELS = {"install_hook": "install-time execution", "network": "network access", "process": "process execution",
          "decoded": "decoded payload", "binary": "executable file", "hook_network": "network access inside an install hook"}


def _items(d: dict, k: str, limit: int = 5) -> list[str]:
    return list(d.get(k, {}))[:limit]


def _first_path(d: dict, kinds) -> str:
    """First evidence item that is a file path (hook entries such as "npm preinstall: node x.js" are not)."""
    for k in kinds:
        for i in d.get(k, {}):
            p = i.rsplit(":", 1)[0] if k == "decoded" else i
            if " " not in p:
                return p
    return ""


def detect(ctx) -> dict:
    gate, hist = release_gate(ctx, DETECTOR_ID, min_releases=2)
    if gate:
        return gate
    new, old = hist["releases"][0], hist["releases"][1]
    npm = hist.get("ecosystem") == "npm"
    if not npm and (new.get("contents") is None or old.get("contents") is None):
        st = new.get("artifact_status") if new.get("contents") is None else old.get("artifact_status")
        return not_assessed(DETECTOR_ID, PILLAR, f"release artifact not read ({st})")
    coverage, detail = "full", []
    for r in (new, old):
        if r.get("contents") is None:
            coverage = "partial"
            detail.append(f"{r['version']} artifact not read ({r.get('artifact_status')}): only registry scripts compared")
        elif unread_relevant(r) or len((r.get("contents") or {}).get("members") or []) >= MAX_MEMBERS:
            coverage = "partial"
            skipped = unread_relevant(r)
            detail.append(f"{r['version']} artifact only partly read" + (f" ({len(skipped)} large file(s) skipped, e.g. {skipped[0]})" if skipped else " (member limit)"))
    if (new.get("artifact") or {}).get("kind") != (old.get("artifact") or {}).get("kind"):
        coverage = "partial"
        detail.append("different artifact types compared")
    res = assess_pair(new, old)
    d = res["delta"]
    pair = version_pair(hist, new, old)
    findings = []
    if res["high_risk"]:
        parts = [LABELS[k] for k in ("install_hook", "hook_network", "network", "decoded") if k in d]
        ev = [pair] + [{"type": "file_line", "file": i, "line": None, "capability": k} for k in res["kinds"] for i in _items(d, k)]
        findings.append(release_finding(
            DETECTOR_ID, "high_risk",
            f"Release {new['version']} adds {' + '.join(parts)} absent from {old['version']}",
            "New in this release: " + "; ".join(f"{LABELS[k]}: {', '.join(_items(d, k, 3))}" for k in res["kinds"]),
            ev, file=_first_path(d, ("network", "decoded", "process", "binary"))))
        findings[-1]["capability_evidence"] = True
    else:
        for k in res["kinds"]:
            if k == "hook_network":
                continue
            findings.append(release_finding(
                DETECTOR_ID, "review", f"Release {new['version']} adds {LABELS[k]} absent from {old['version']}",
                ", ".join(_items(d, k, 5)), [pair] + [{"type": "file_line", "file": i, "line": None} for i in _items(d, k)],
                file=_first_path(d, (k,))))
            findings[-1]["capability_evidence"] = True   # every release_delta finding is backed by code
    return make_result(DETECTOR_ID, PILLAR, "ran", findings, coverage=coverage, coverage_detail="; ".join(detail) or None)
