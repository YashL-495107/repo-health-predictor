"""publisher_change (Integrity) - the latest release was published by an identity that published none of the
previous releases in the window (default: the 4 before it).

Publisher identity: npm per-version _npmUser.name; PyPI the PEP 740 provenance Trusted Publisher
(kind:repository/workflow), which only exists for releases uploaded with Trusted Publishing. PyPI does not expose
the uploading user per release, so without provenance the signal is not available (not_applicable, not a failed
check). A PyPI release WITHOUT provenance after earlier releases WITH it is reported as review too (publishing path
changed).
Tier: review. The explanation adds context a human needs: a long gap before the release (>= LONG_GAP_DAYS), a release
burst (>= BURST_COUNT releases within BURST_HOURS ending at this one), and whether release_delta finds a high-risk
change in the same release. Fragility can escalate it to high_risk (fragility.py).
Time: gap and burst use the releases' own upload times (as_of = the latest release), never today's date.
Known evasions: an attacker who steals the usual maintainer's token (same publisher), an attacker added as
maintainer long before using the access, publishing through the project's own CI.
False-positive sources: legitimate maintainer handovers, new co-maintainers, moving to Trusted Publishing or CI
publishing, organisation accounts rotating bots.
"""
from datetime import datetime

from .base import make_result, not_applicable
from .release_analysis import assess_pair
from .release_common import PILLAR, release_finding, release_gate, version_pair

DETECTOR_ID = "publisher_change"
LONG_GAP_DAYS = 180
BURST_COUNT, BURST_HOURS = 3, 72


def _t(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def _context(hist: dict, new: dict, old: dict) -> list[str]:
    out = []
    tn, to = _t(new.get("upload_time")), _t(old.get("upload_time"))
    if tn and to and (tn - to).days >= LONG_GAP_DAYS:
        out.append(f"published {(tn - to).days} days after the previous release")
    recent = [r for r in hist["releases"] if (t := _t(r.get("upload_time"))) and tn and 0 <= (tn - t).total_seconds() <= BURST_HOURS * 3600]
    if len(recent) >= BURST_COUNT:
        out.append(f"part of a burst of {len(recent)} releases within {BURST_HOURS} hours")
    if new.get("contents") is not None and old.get("contents") is not None or hist.get("ecosystem") == "npm":
        if assess_pair(new, old)["high_risk"]:
            out.append("release_delta also finds a high-risk change in this same release")
    return out


def detect(ctx) -> dict:
    gate, hist = release_gate(ctx, DETECTOR_ID, min_releases=2)
    if gate:
        return gate
    rels = hist["releases"]
    new, prior = rels[0], rels[1:]
    known_prior = [r["publisher"] for r in prior if r.get("publisher")]
    pair = version_pair(hist, new, prior[0])
    eco = hist.get("ecosystem")
    if not new.get("publisher"):
        if eco == "PyPI" and known_prior:
            f = release_finding(
                DETECTOR_ID, "review", f"Release {new['version']} has no Trusted Publisher provenance; earlier releases did",
                f"Earlier releases were published by {', '.join(sorted(set(known_prior)))}; this one was uploaded another way. "
                + "; ".join(_context(hist, new, prior[0])), [pair, {"type": "registry_field", "field": "provenance.publisher", "value": None}])
            return make_result(DETECTOR_ID, PILLAR, "ran", [f])
        return not_applicable(DETECTOR_ID, PILLAR, f"publisher identity not available for {new['version']} ({new.get('publisher_source')})")
    if not known_prior:
        return not_applicable(DETECTOR_ID, PILLAR, "publisher identity not available for earlier releases, nothing to compare")
    findings = []
    if new["publisher"] not in set(known_prior):
        ctxt = _context(hist, new, prior[0])
        findings.append(release_finding(
            DETECTOR_ID, "review", f"New publisher for release {new['version']}: {new['publisher']}",
            f"Earlier releases ({', '.join(r['version'] for r in prior)}) were published by {', '.join(sorted(set(known_prior)))}."
            + (" Context: " + "; ".join(ctxt) + "." if ctxt else ""),
            [pair, {"type": "registry_field", "field": "publisher", "new": new["publisher"], "prior": sorted(set(known_prior)),
                    "source": new.get("publisher_source")}],
            fix="Check whether the maintainers announced the new publisher."))
    cov = "partial" if len(known_prior) < len(prior) else "full"
    return make_result(DETECTOR_ID, PILLAR, "ran", findings, coverage=cov,
                       coverage_detail=f"publisher known for {len(known_prior)} of {len(prior)} earlier releases" if cov == "partial" else None)
