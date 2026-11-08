"""revival_takeover (Integrity) - a long-silent project that suddenly comes back under new hands: the takeover
pattern this tool's abandonment model is meant to anticipate.

Signals, all relative to as_of = the upload time of the latest release N:
  silence   no release for >= SILENCE_DAYS before N (registry), or a gap of >= SILENCE_DAYS between commits that
            ends within REVIVAL_WINDOW_DAYS before N (git)
  activity  after the silence: a new publisher (not among earlier releases), new commit author(s) (not seen before
            the gap), a release burst (>= BURST_COUNT releases within BURST_HOURS ending at N), or a rename/transfer
            indicator (the GitHub API returns another full_name; the registry's repository URL points elsewhere)
  capability in the revived release: a new install hook or decoded payload vs N-1 (release_delta logic), a decoded
            payload in N's artifact (Layer 1), or a strong Layer 2 setup.py pattern in N
Tier: silence + at least one activity signal = review ("revival alone"). Revival + capability = high_risk.
Silence without an activity signal (a quiet maintenance release by the usual publisher) is not flagged.
"Revival alone" is metadata-only, so fragility does not escalate it (dormancy is also its precondition). The fragility index is reported in the detail.
Legitimate cases that look the same: a genuine maintainer handover or adoption (often announced in the README or
issues), a maintainer returning after a break, moving to CI / Trusted Publishing (new publisher identity), an
organisation transfer. The evidence (dates, earlier and new publishers/authors) is listed so a human can judge.
Known evasions: a takeover without a long silence, an attacker who reuses the old maintainer's account or token,
payloads that arrive in a later release than the revival release, history that GitHub's commit list does not
show (force-pushed or rewritten history).
False-positive sources: the legitimate cases above, bots appearing as new commit authors, monorepo releases.
"""
import re
from datetime import datetime

from .base import make_result
from .release_analysis import assess_pair, capabilities
from .release_common import PILLAR, release_finding, release_gate, version_pair

DETECTOR_ID = "revival_takeover"
SILENCE_DAYS = 365
REVIVAL_WINDOW_DAYS = 180
BURST_COUNT, BURST_HOURS = 3, 72
BOT_ACCOUNTS = {"dependabot[bot]", "renovate[bot]", "github-actions[bot]", "dependabot-preview[bot]", "renovate-bot"}


def is_bot(author: str | None) -> bool:
    """Automation accounts are not "new commit authors": exact known names, or any GitHub App login ending [bot]."""
    a = (author or "").strip().lower()
    return a in BOT_ACCOUNTS or a.endswith("[bot]")


def _t(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def _repo_slug(url: str | None) -> str | None:
    m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", url or "")
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


def git_revival(commits: list[dict], as_of: datetime) -> dict | None:
    """Largest gap >= SILENCE_DAYS between consecutive commits whose later commit is within REVIVAL_WINDOW_DAYS
    before as_of. Bot commits (dependabot, renovate, github-actions, any *[bot]) are ignored: they neither break
    the silence nor count as new authors. Returns {gap_days, silent_since, revived_at, authors_before, authors_after}."""
    pts = sorted(((_t(c.get("date")), c.get("author")) for c in commits if _t(c.get("date")) and not is_bot(c.get("author"))),
                 key=lambda x: x[0])
    pts = [p for p in pts if p[0] <= as_of]
    best = None
    for (t1, _), (t2, _) in zip(pts, pts[1:]):
        gap = (t2 - t1).days
        if gap >= SILENCE_DAYS and 0 <= (as_of - t2).days <= REVIVAL_WINDOW_DAYS and (not best or gap > best["gap_days"]):
            best = {"gap_days": gap, "silent_since": t1.isoformat(), "revived_at": t2.isoformat(),
                    "authors_before": sorted({a for t, a in pts if t <= t1 and a}),
                    "authors_after": sorted({a for t, a in pts if t >= t2 and a})}
    return best


def detect(ctx) -> dict:
    gate, hist = release_gate(ctx, DETECTOR_ID, min_releases=2)
    if gate:
        return gate
    rc = ctx.releases or {}
    rels = hist["releases"]
    new = rels[0]
    # dormancy is about time: compare N with the CHRONOLOGICALLY previous release, not the version-order predecessor
    # that release_delta & co. use since 2026.11.08-11 (an old 0.x line release would look like a long silence)
    prev_v = (new.get("selection") or {}).get("chronological_previous")
    old = next((r for r in rels[1:] if r["version"] == prev_v), rels[1])
    tn, to = _t(new.get("upload_time")), _t(old.get("upload_time"))
    pair = version_pair(hist, new, old)
    notes, silence, activity, ev = [], [], [], [pair]

    if tn and to and (tn - to).days >= SILENCE_DAYS:
        silence.append(f"no release for {(tn - to).days} days before {new['version']} (previous: {old['version']})")
    act = rc.get("activity") or {}
    rev = None
    if act.get("status") == "ok" and tn:
        rev = git_revival(act.get("commits") or [], tn)
        if not act.get("complete"):   # a sub-signal limit: shown in the detector detail, not the headline
            notes.append(f"commit history read up to {len(act.get('commits') or [])} commits before the release")
        if rev:
            silence.append(f"no commits for {rev['gap_days']} days, then activity from {rev['revived_at'][:10]}")
            ev.append({"type": "registry_field", "source": "GitHub commits", **rev})
            new_authors = sorted(set(rev["authors_after"]) - set(rev["authors_before"]))
            if new_authors and rev["authors_before"]:
                activity.append(f"new commit author(s) after the silence: {', '.join(new_authors[:5])} "
                                f"(before: {', '.join(rev['authors_before'][:5])})")
    else:
        notes.append(f"git activity not assessed ({act.get('reason') or 'not fetched'}): registry signals only")

    prior_pubs = {r["publisher"] for r in rels[1:] if r.get("publisher")}
    if new.get("publisher") and prior_pubs and new["publisher"] not in prior_pubs:
        activity.append(f"new publisher {new['publisher']} (earlier: {', '.join(sorted(prior_pubs))})")
    burst = [r for r in rels if (t := _t(r.get("upload_time"))) and tn and 0 <= (tn - t).total_seconds() <= BURST_HOURS * 3600]
    if len(burst) >= BURST_COUNT:
        activity.append(f"burst of {len(burst)} releases within {BURST_HOURS} hours")
    git = rc.get("git") or {}
    req = (rc.get("requested_repo") or "").lower()
    if git.get("full_name") and req and git["full_name"].lower() != req:
        activity.append(f"repository now resolves to {git['full_name']} (renamed or transferred from {rc.get('requested_repo')})")
    reg_slug = _repo_slug(hist.get("repository_url"))
    if reg_slug and req and reg_slug != req and (not git.get("full_name") or reg_slug != git["full_name"].lower()):
        activity.append(f"registry repository URL points to {reg_slug}, not {req}")

    if not silence or not activity:
        return make_result(DETECTOR_ID, PILLAR, "ran", [], coverage="partial" if notes else "full",
                           coverage_detail="; ".join(notes) or None)

    caps = []
    if new.get("contents") is not None or hist.get("ecosystem") == "npm":
        a = assess_pair(new, old)["delta"]
        if a.get("install_hook"):
            caps.append("new install hook: " + ", ".join(list(a["install_hook"])[:2]))
        if a.get("decoded"):
            caps.append("new decoded payload: " + ", ".join(list(a["decoded"])[:2]))
    if new.get("contents") is not None:
        c = capabilities(new)
        if c["decoded"] and not any(x.startswith("new decoded") for x in caps):
            caps.append("decoded payload in the release: " + ", ".join(list(c["decoded"])[:2]))
        if c["hook_network"] and not any(x.startswith("new install hook") for x in caps):
            caps.append("install hook with network access in the release: " + ", ".join(list(c["hook_network"])[:2]))
    fr = (ctx.fragility or {}).get("score")
    detail = ("Silence: " + "; ".join(silence) + ". Then: " + "; ".join(activity) + "."
              + (f" In the revived release: {'; '.join(caps)}." if caps else " No new install-time capability or decoded payload in the revived release.")
              + (f" Fragility index {fr:.0f}/100." if isinstance(fr, (int, float)) else "")
              + " A genuine maintainer handover looks the same: check the project's announcements before concluding.")
    tier = "high_risk" if caps else "review"
    f = release_finding(DETECTOR_ID, tier,
                        f"Release {new['version']} revives a silent project" + (" with new install-time capability" if caps else " under new hands"),
                        detail, ev, fix="Confirm the handover with the previous maintainers before installing.")
    return make_result(DETECTOR_ID, PILLAR, "ran", [f], coverage="partial" if notes else "full",
                       coverage_detail="; ".join(notes) or None)
