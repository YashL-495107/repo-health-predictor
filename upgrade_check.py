"""Upgrade check: what changes, risk-wise, between two published versions of one PyPI / npm package.

Added after the freeze of ruleset 2026.11.08-12; not part of the benchmark; unvalidated. It never computes or shows a
Trust score and changes no detector, cap or score.

Both artifacts come from the public registry only (releases.fetch_pypi / fetch_npm: the same 5 MB artifact limit,
archive read limits and 60 s fetch budget as the benchmark), are read in memory and are never extracted, executed,
imported or installed. Building blocks reused unchanged:
  releases.fetch_*            version window, artifact contents, npm install scripts, dependencies, publisher, dates
  benchmark data_from_contents  artifact contents -> the content scan's input shape (same filters and caps)
  release_analysis.capabilities install hooks (npm scripts, setup.py Layer 2, .pth), network / process use, decoded
                                payloads, binaries - the evidence release_delta compares
  repo_behavior.scan_behavior   behavior categories (credential access, exfil-style network, persistence, obfuscation)
  releases.dependency_profile   first-release age of an added dependency; YOUNG_DAYS from dependency_injection
  blast_radius.confirm_typosquat lookalike names
  additional_signals            maintainer e-mail domains (RDAP) and provenance identity

Each row of the diff: {"area", "item", "change": "added" | "removed" | "unchanged", "evidence"}.
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from pathlib import PurePosixPath

import releases

AREAS = ("Install hooks", "Credential/env access", "Network activity (possible exfiltration)", "Network use", "Process spawn",
         "Decoding/obfuscation", "Filesystem persistence", "Dependencies", "Minified / obfuscated files")
RISK_AREAS = set(AREAS)            # an ADDED row in any of these areas is risk-relevant
PAGE_LABEL = "Added after the freeze; not part of the benchmark; unvalidated."
NO_CHANGES = "No risk-relevant changes found"
REVIEW = "Review before upgrading"
NOT_COMPARED = "Could not compare"
CAVEAT = "Indicators, not proof. No findings does not mean safe."
MINIFIED_LINE = 1000               # a code line this long marks a file as minified / packed
CODE_EXT = {".js", ".mjs", ".cjs", ".py", ".ts"}


def _bench_data_from_contents():
    bench = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark")
    if bench not in sys.path:
        sys.path.insert(0, bench)
    from run_benchmark import data_from_contents
    return data_from_contents


def load_version(ecosystem: str, name: str, version: str | None) -> dict:
    """The release (with artifact contents) and the release before it. version None = latest.
    {"status": "ok" | "not_found" | "error", "reason", "release", "previous", "repository_url", "maintainers"}."""
    fetch = releases.fetch_pypi if ecosystem == "PyPI" else releases.fetch_npm if ecosystem == "npm" else None
    if fetch is None:
        return {"status": "error", "reason": f"unsupported ecosystem {ecosystem}"}
    # 3 releases: the version, the one before (both downloaded: CONTENT_RELEASES = 2) and the one before that
    # (metadata only), so the release gap is known for both compared versions
    hist = fetch(name, 3, time.monotonic() + releases.FETCH_BUDGET_S, version or None)
    if hist.get("status") != "ok" or not hist.get("releases"):
        return {"status": hist.get("status") or "error", "reason": hist.get("reason") or "no release found"}
    rels = hist["releases"]
    return {"status": "ok", "reason": None, "release": rels[0], "previous": rels[1] if len(rels) > 1 else None,
            "earlier": rels[2] if len(rels) > 2 else None,
            "repository_url": hist.get("repository_url"), "maintainers": hist.get("maintainers"),
            "partial": hist.get("partial") or []}


def _days_between(a: str | None, b: str | None) -> int | None:
    da, db = releases._dt(a), releases._dt(b)
    return (da - db).days if da and db else None


def _minified(text: dict) -> dict:
    out = {}
    for p, t in text.items():
        ext = PurePosixPath(p).suffix.lower()
        if ext not in CODE_EXT:
            continue
        if p.endswith(".min.js"):
            out[p] = f"{p} (minified file name)"
            continue
        longest = max((len(line) for line in t.splitlines()), default=0)
        if longest >= MINIFIED_LINE:
            out[p] = f"{p} (a line of {longest:,} characters)"
    return out


def evidence(release: dict, name: str) -> dict:
    """Per-version evidence, keyed so that two versions can be compared: {area: {item key: evidence text}}, plus
    behavior findings (for the kill-chain strip) and facts (publisher, date, size)."""
    from detectors.release_analysis import capabilities
    from repo_behavior import scan_behavior
    contents = release.get("contents")
    out = {"version": release.get("version"), "read": contents is not None,
           "artifact_status": release.get("artifact_status"), "areas": {a: {} for a in AREAS},
           "behavior": [], "limits": list((contents or {}).get("limits_hit") or []),
           "publisher": release.get("publisher"), "publisher_source": release.get("publisher_source"),
           "uploaded": release.get("upload_time"), "dependencies": release.get("dependencies"),
           "size": None, "files": None}
    areas = out["areas"]
    for hook, cmd in (release.get("install_scripts") or {}).items():       # every npm install hook, benign or not
        areas["Install hooks"][f"npm {hook}"] = f"package.json scripts.{hook}: {cmd}"
    art = release.get("artifact") or {}
    out["size"] = art.get("unpacked_size") or art.get("size")
    if contents is None:
        return out
    text = contents.get("text") or {}
    out["files"] = len(contents.get("members") or text)
    caps = capabilities(release)
    for k, v in caps["install_hook"].items():
        if not k.startswith("npm "):
            areas["Install hooks"][k] = f"{k}: {v}"
    for p in caps["network"]:
        areas["Network use"][p] = f"{p}: imports or calls a network API"
    for k, v in caps["hook_network"].items():
        areas["Network activity (possible exfiltration)"][k] = f"{k}: {v}"
    for p in caps["process"]:
        areas["Process spawn"][p] = f"{p}: starts processes"
    for k, v in caps["decoded"].items():
        areas["Decoding/obfuscation"][k.rsplit(":", 1)[0]] = f"{k}: {v}"
    data = _bench_data_from_contents()(contents)
    beh = scan_behavior(data, name, lambda f, ln: None)["findings"]
    out["behavior"] = beh
    cat_area = {"Credential access": "Credential/env access", "Network": "Network activity (possible exfiltration)",
                "Remote shell": "Network activity (possible exfiltration)", "Persistence": "Filesystem persistence",
                "Obfuscation": "Decoding/obfuscation", "Install-time execution": "Install hooks"}
    for f in beh:
        a = cat_area.get(f.get("cat"))
        if a and str(f.get("sev")).lower() not in ("info", "low"):
            areas[a].setdefault(f"{f.get('file')}", f"{f.get('file')}:{f.get('line')} {f.get('rule')}")
    for p, ev in _minified(text).items():
        areas["Minified / obfuscated files"][p] = ev
    return out


def diff(old: dict, new: dict) -> list[dict]:
    rows = []
    for area in AREAS:
        if area == "Dependencies":
            continue
        a, b = old["areas"][area], new["areas"][area]
        for k in sorted(set(a) | set(b)):
            change = "added" if k in b and k not in a else "removed" if k in a and k not in b else "unchanged"
            rows.append({"area": area, "item": k, "change": change, "evidence": b.get(k) or a.get(k)})
    return rows


def dependency_rows(ecosystem: str, old: dict, new: dict, profile=None, lookalike=None) -> list[dict]:
    """Added / removed / unchanged declared dependencies; each added one with its registry age at the new release
    and a lookalike check. profile / lookalike are injectable (tests)."""
    from detectors.dependency_injection import YOUNG_DAYS
    if old.get("dependencies") is None or new.get("dependencies") is None:
        return [{"area": "Dependencies", "item": "(declared dependencies)", "change": "unchanged",
                 "evidence": "not available for both versions: could not compare", "not_compared": True}]
    profile = profile or (lambda n: releases.dependency_profile(ecosystem, n, releases._dt(new.get("uploaded")), download=False))
    if lookalike is None:
        from blast_radius import confirm_typosquat
        lookalike = lambda n: confirm_typosquat(n, ecosystem)          # noqa: E731
    a, b = set(old["dependencies"]), set(new["dependencies"])
    rows = []
    for d in sorted(b - a)[:releases.MAX_NEW_DEPS]:
        flags = []
        try:
            p = profile(d)
        except Exception as e:
            p = {"status": "error", "reason": type(e).__name__}
        if p.get("status") != "ok":
            flags.append(f"registry age: could not check ({p.get('reason')})")
        elif isinstance(p.get("age_days"), int):
            flags.append(f"first published {p['age_days']} days before this release"
                         + (f" (very new: under {YOUNG_DAYS} days)" if p["age_days"] < YOUNG_DAYS else ""))
        twin = None
        try:
            twin = lookalike(d)
        except Exception:
            flags.append("lookalike check: could not check")
        if twin:
            flags.append(f"lookalike of '{twin}'")
        rows.append({"area": "Dependencies", "item": d, "change": "added",
                     "evidence": "; ".join(flags) or "added in the new version",
                     "young": isinstance(p.get("age_days"), int) and p["age_days"] < YOUNG_DAYS, "lookalike": twin})
    for d in sorted(b - a)[releases.MAX_NEW_DEPS:]:
        rows.append({"area": "Dependencies", "item": d, "change": "added", "evidence": "added (not looked up: limit)"})
    for d in sorted(a - b):
        rows.append({"area": "Dependencies", "item": d, "change": "removed", "evidence": "removed in the new version"})
    for d in sorted(a & b):
        rows.append({"area": "Dependencies", "item": d, "change": "unchanged", "evidence": "declared in both versions"})
    return rows


def facts_rows(old: dict, new: dict, old_prev: dict | None, new_prev: dict | None) -> list[dict]:
    """Publisher per version, days since the release before each, size change (informational)."""
    def gap(ev, prev):
        d = _days_between(ev.get("uploaded"), (prev or {}).get("upload_time"))
        return f"{d} days after {prev.get('version')}" if d is not None and prev else "no earlier release found"
    from detectors.revival_takeover import SILENCE_DAYS
    pub_old, pub_new = old.get("publisher") or "not available", new.get("publisher") or "not available"
    if pub_old == pub_new:
        pchange = "unchanged"
    elif "not available" in (pub_old, pub_new):
        pchange = "info"            # one side has no publisher identity (e.g. moving to Trusted Publishing): not compared
    else:
        pchange = "changed"
    new_gap = _days_between(new.get("uploaded"), (new_prev or {}).get("upload_time"))
    rows = [{"area": "Publisher", "item": f"{old['version']} -> {new['version']}", "change": pchange,
             "evidence": f"{old['version']}: {pub_old} ({old.get('publisher_source')}); "
                         f"{new['version']}: {pub_new} ({new.get('publisher_source')})"},
            {"area": "Release gap (dormancy)", "item": new["version"], "change": "info",
             "evidence": f"{old['version']}: {gap(old, old_prev)}; {new['version']}: {gap(new, new_prev)}",
             "long_gap": isinstance(new_gap, int) and new_gap >= SILENCE_DAYS, "threshold": SILENCE_DAYS}]
    if old.get("size") and new.get("size"):
        pct = 100 * (new["size"] - old["size"]) / old["size"]
        rows.append({"area": "Size", "item": "artifact size", "change": "info",
                     "evidence": f"{old['size']:,} -> {new['size']:,} bytes ({pct:+.0f}%)"})
    return rows


def verdict(rows: list[dict], old: dict, new: dict) -> dict:
    if not old.get("read") or not new.get("read"):
        which = [e["version"] for e in (old, new) if not e.get("read")]
        return {"verdict": NOT_COMPARED, "items": [f"artifact of {v} not read" for v in which]}
    items = [f"{r['area']}: {r['item']}" + (f" ({r['evidence']})" if r["area"] == "Dependencies" else "")
             for r in rows if r.get("change") == "added" and r["area"] in RISK_AREAS]
    items += [f"Publisher changed: {r['evidence']}" for r in rows if r["area"] == "Publisher" and r["change"] == "changed"]
    items += [f"Long silence before the new version (at least {r['threshold']} days, revival_takeover's threshold): "
              f"{r['evidence']}" for r in rows if r["area"] == "Release gap (dormancy)" and r.get("long_gap")]
    items += [f"Provenance: {r['evidence']}" for r in rows if r["area"] == "Provenance" and r["change"] in ("removed", "mismatch")]
    items += [f"Maintainer email domain: {r['item']} ({r['evidence']})" for r in rows
              if r["area"] == "Maintainer email domain" and r.get("flag")]
    return {"verdict": REVIEW if items else NO_CHANGES, "items": items}


def provenance_rows(ecosystem: str, name: str, old: dict, new: dict, declared_repo: str | None, fetch,
                    npm_packument: dict | None = None) -> list[dict]:
    """Provenance present / absent and source repository per version (additional_signals.provenance_check), compared
    with the repository the registry declares. Signature not cryptographically verified here."""
    import additional_signals as AS
    slug = AS.normalise_repo(declared_repo) or ""
    res = {}
    for ev in (old, new):
        v = ev["version"]
        if ecosystem == "npm":
            dist = (((npm_packument or {}).get("versions") or {}).get(v) or {}).get("dist") or {}
            rec = {"status": "ok" if npm_packument else "could_not_check", "version": v,
                   "npm_attestations": dist.get("attestations"), "reason": "npm registry lookup failed"}
        else:
            rec = {"status": "ok", "version": v, "pypi_files": ev.get("filenames") or []}
        res[v] = AS.provenance_check(ecosystem, name, rec, slug, fetch)
    po, pn = res[old["version"]], res[new["version"]]
    has = lambda p: p["status"] in ("match", "mismatch")                       # noqa: E731
    if "could_not_check" in (po["status"], pn["status"]):
        change = "could not check"
    elif has(pn) and not has(po):
        change = "added"
    elif has(po) and not has(pn):
        change = "removed"
    else:
        change = "unchanged"
    if pn["status"] == "mismatch" and slug:
        change = "mismatch"
    def txt(v, p):
        if p["status"] in ("match", "mismatch"):
            return f"{v}: {p['source_repository']}" + (" (matches the declared repository)" if p["status"] == "match"
                                                        else " (not the declared repository)" if slug else "")
        return f"{v}: " + ("no attestation" if p["status"] == "none" else f"could not check ({p.get('detail')})")
    return [{"area": "Provenance", "item": "attestation and source repository", "change": change,
             "evidence": f"{txt(old['version'], po)}; {txt(new['version'], pn)}; {AS.SIGNATURE_NOTE}"}]


def domain_rows(sig: dict) -> list[dict]:
    """Current maintainers' e-mail domains (registry today, not per version) from additional_signals.collect."""
    reg = sig.get("registry") or {}
    if reg.get("status") != "ok":
        return [{"area": "Maintainer email domain", "item": "-", "change": "info",
                 "evidence": f"could not check ({reg.get('reason')})" if reg.get("status") == "could_not_check"
                 else f"not checked ({reg.get('reason')})"}]
    if not sig.get("domains"):
        return [{"area": "Maintainer email domain", "item": "-", "change": "info",
                 "evidence": "no non-free-mail contact domain listed: nothing to look up"}]
    return [{"area": "Maintainer email domain", "item": d["domain"], "change": "info", "flag": d.get("flag"),
             "evidence": (d.get("flag") or {"registered": "registered", "not_registered": "not registered"}.get(d["status"], "could not check"))
             + (f" ({d.get('reason')})" if d.get("reason") else "") + "; takeover-risk indicator, not proof"}
            for d in sig["domains"]]


def run(ecosystem: str, name: str, current: str | None, new: str | None, *, rdap_fetch=None, http_fetch=None,
        dep_profile=None, lookalike=None) -> dict:
    """The whole check. current None = the release just before `new`; new None = latest. Never raises for registry
    or network problems: they become "could not check" / NOT_COMPARED."""
    import additional_signals as AS
    import http_cache
    if http_fetch is None:
        def http_fetch(url, accept=None):
            data, status, err = http_cache.get_json(url, headers={"Accept": accept} if accept else None)
            return {"status": status, "data": data, "redirected": False, "error": err}
    out = {"ecosystem": ecosystem, "name": name, "label": PAGE_LABEL, "caveat": CAVEAT, "rows": [], "notes": []}
    nv = load_version(ecosystem, name, new)
    if nv["status"] != "ok":
        out.update(verdict={"verdict": NOT_COMPARED, "items": [f"new version: {nv['reason']}"]})
        return out
    if current:
        cv = load_version(ecosystem, name, current)
        if cv["status"] != "ok":
            out.update(verdict={"verdict": NOT_COMPARED, "items": [f"current version: {cv['reason']}"]})
            return out
        cur_rel, cur_prev = cv["release"], cv["previous"]
    else:
        if not nv["previous"]:
            out.update(verdict={"verdict": NOT_COMPARED, "items": ["no release before the new version"]})
            return out
        cur_rel, cur_prev = nv["previous"], nv.get("earlier")
    new_rel = nv["release"]
    if releases._dt(cur_rel.get("upload_time")) and releases._dt(new_rel.get("upload_time")) and \
            releases._dt(cur_rel["upload_time"]) > releases._dt(new_rel["upload_time"]):
        out["notes"].append("the 'current' version was published after the 'new' one: the comparison is a downgrade")
    old_ev, new_ev = evidence(cur_rel, name), evidence(new_rel, name)
    for ev, rel in ((old_ev, cur_rel), (new_ev, new_rel)):
        ev["filenames"] = [f.get("filename") for f in rel.get("files") or [] if f.get("filename")]
        if not ev["read"]:
            out["notes"].append(f"artifact of {ev['version']} not read ({ev['artifact_status']})")
        for lim in ev["limits"]:
            out["notes"].append(f"{ev['version']}: read limit hit ({lim}); unread files were not compared")
    for p in nv.get("partial") or []:
        out["notes"].append(p)
    out["versions"] = {"current": old_ev["version"], "new": new_ev["version"]}
    rows = diff(old_ev, new_ev)
    rows += dependency_rows(ecosystem, old_ev, new_ev, dep_profile, lookalike)
    rows += facts_rows(old_ev, new_ev, cur_prev, nv["previous"])
    packument = None
    if ecosystem == "npm":
        from urllib.parse import quote
        r = http_fetch(f"https://registry.npmjs.org/{quote(name, safe='@/')}")
        packument = r.get("data") if r.get("status") == 200 else None
    try:
        rows += provenance_rows(ecosystem, name, old_ev, new_ev, nv.get("repository_url"), http_fetch, packument)
    except Exception as e:
        rows.append({"area": "Provenance", "item": "-", "change": "could not check", "evidence": type(e).__name__})
    try:
        sig = AS.collect(ecosystem, name, AS.normalise_repo(nv.get("repository_url")) or "", rdap_fetch or AS.http_get_json)
        rows += domain_rows(sig)
    except Exception as e:
        rows.append({"area": "Maintainer email domain", "item": "-", "change": "info", "evidence": f"could not check ({type(e).__name__})"})
    out["rows"] = rows
    out["verdict"] = verdict(rows, old_ev, new_ev)
    out["killchain_findings"] = [r for r in rows if r.get("change") == "added"] + \
        [f for f in new_ev["behavior"] if f.get("file") in {r["item"] for r in rows if r.get("change") == "added"}]
    return out


def replay_cases(root: str | None = None) -> list[dict]:
    """Known incidents from the benchmark's committed replay data (benchmark/bench_items.REPLAY_TARGETS and
    manifests/replay_incidents.csv, results/run2/replay.csv). Only the incident list and the recorded benchmark result
    are offline; the two releases are downloaded from the registry when the check runs."""
    import csv
    root = root or os.path.dirname(os.path.abspath(__file__))
    bench = os.path.join(root, "benchmark")
    if bench not in sys.path:
        sys.path.insert(0, bench)
    try:
        from bench_items import REPLAY_TARGETS
        with open(os.path.join(bench, "manifests", "replay_incidents.csv"), encoding="utf-8") as fh:
            man = {r["incident"]: r for r in csv.DictReader(l for l in fh if not l.startswith("#"))}
        with open(os.path.join(bench, "results", "run2", "replay.csv"), encoding="utf-8") as fh:
            res = {r["id"]: r for r in csv.DictReader(fh)}
    except (OSError, ImportError):
        return []
    out = []
    for incident in ("event-stream / flatmap-stream", "node-ipc"):
        if incident not in REPLAY_TARGETS or incident not in man:
            continue
        eco, pkg, ver = REPLAY_TARGETS[incident]
        r = res.get(f"replay:{incident}") or {}
        out.append({"incident": incident, "ecosystem": eco, "package": pkg, "new": ver, "current": None,
                    "status": man[incident]["status"], "benchmark_label": r.get("label") or "-",
                    "benchmark_detectors": r.get("detectors") or "-", "note": man[incident]["reason"]})
    return out
