"""Repository & Package Trust Check - Streamlit app."""
import html
import os
import queue
import re
import threading
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv
from streamlit.runtime.scriptrunner import add_script_run_ctx, get_script_run_ctx

from github_client import GitHubClient, GitHubError, fetch_features, parse_repo
from scoring import HEALTHY, SLOWING, compute_health_score, explain
from security import action_verdict, apply_gate, assess_security, content_flags, collect_dependencies
from repo_scan import scan_repo
from bus_factor import run_bus_factor_analysis
import hashlib
from intelligence import build_ai_cards, SuccessCache, gather_repo_intel, run_ai_layer, _configured_model, resolve_gemini_key, _MISSING
from ui_text import (APP_CSS, NEUTRAL_COLOR, TRUST_DISCLAIMER, app_version, assessment_gaps, blast_display, evidence_receipt,
                     filter_findings, headline_label, partial_badge, result_json, trust_drivers)
import additional_signals as AS
import killchain
from verdict_meaning import verdict_meaning
from blast_radius import analyze_blast_radius
from detectors import RULESET_VERSION, TIER_DISPLAY
from releases import collect_release_context
from pillars import (LABEL_FRAGILE, LABEL_HIGH_RISK, LABEL_KNOWN_MALICIOUS, LABEL_NO_FINDINGS, LABEL_NOT_ASSESSED,
                     LABEL_REVIEW, MAINTENANCE_CEILING)

load_dotenv()
st.set_page_config(page_title="Repository & Package Trust Check", page_icon="🩺", layout="wide")
SAMPLES = ["psf/requests", "lodash/lodash", "sqlmapproject/sqlmap"]
COLORS = {"Healthy": "#1a9850", "Slowing down": "#f4a300", "At risk": "#e66101", "Likely abandoned": "#d73027", "Archived (read-only)": "#6c757d"}
TRUST_COLORS = {LABEL_KNOWN_MALICIOUS: "#b2182b", LABEL_HIGH_RISK: "#e66101", LABEL_REVIEW: "#f4a300",
                LABEL_FRAGILE: "#6c757d", LABEL_NO_FINDINGS: "#1a9850", LABEL_NOT_ASSESSED: "#6c757d"}
STATUS_TEXT = {"ran": "ran", "not_assessed": "not assessed", "not_applicable": "not applicable"}

def server_token() -> str:
    try:
        t = st.secrets.get("GITHUB_TOKEN", "")
        if t: return t
    except Exception: pass
    return os.getenv("GITHUB_TOKEN", "")

def _gemini_secret_raw():
    try:
        return st.secrets.get("GEMINI_API_KEY", _MISSING)
    except Exception:
        return _MISSING


def server_gemini_key() -> str:
    key, _, _ = resolve_gemini_key("", _gemini_secret_raw(), os.getenv("GEMINI_API_KEY", ""))
    return key

def _md_escape(text) -> str:
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|<>~$])", r"\\\1", str(text))


def _stage(progress, label, fn, timings: dict, key: str):
    """Run one analysis stage, report start/end through `progress` (a callable that may be called from worker threads, e.g. queue.put)."""
    if progress:
        progress(f"⏳ {label} ...")
    t0 = time.monotonic()
    try:
        return fn()
    finally:
        timings[key] = round(time.monotonic() - t0, 1)
        if progress:
            progress(f"✓ {label} ({timings[key]:.1f}s)")


@st.cache_data(ttl=3600, show_spinner=False)
def analyze(owner: str, repo: str, token: str, _progress=None) -> dict:
    """Full analysis. Independent network stages run in parallel (repository features, security lookups, content
    scan with its zip download, bus factor); the release fetch starts when the security lookups found the package.
    `_progress` (excluded from the cache key) receives stage messages; it must not call Streamlit itself."""
    timings: dict[str, float] = {}
    mk = lambda: GitHubClient(token)        # one client per thread: requests.Session is not shared across threads

    def scan_stage():
        try:
            return scan_repo(mk(), owner, repo)
        except Exception as e:
            return {"ran": False, "findings": [], "strong": 0, "review": 0, "malware_proof": None, "known_malicious_count": 0, "high_risk_pattern_count": 0, "coverage": [f"Content scan: NOT run ({type(e).__name__})"], "skip_reason": f"other: {type(e).__name__}"}

    def bus_stage():
        try: return run_bus_factor_analysis(mk(), owner, repo)
        except Exception as e: return {"bus_factor": 0, "gini": 0.0, "entropy": 0.0, "burnout_status": f"Unavailable ({type(e).__name__})", "findings": [], "author_table": [], "succession_score": 0.0, "risk_level": "Unknown"}

    def release_stage(security):
        try: return collect_release_context(owner, repo, security.get("package"))
        except Exception as e: return {"package": security.get("package"), "history": {"status": "error", "reason": f"release fetch crashed ({type(e).__name__})", "releases": []}, "git": None}

    def deps_stage():
        try: return collect_dependencies(mk(), owner, repo).get("deps", [])
        except Exception: return []

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_feat = pool.submit(_stage, _progress, "Repository metadata (GitHub)", lambda: fetch_features(mk(), owner, repo), timings, "features")
        f_scan = pool.submit(_stage, _progress, "Repository download and content scan", scan_stage, timings, "content_scan")
        f_bus = pool.submit(_stage, _progress, "Bus factor and maintainer activity", bus_stage, timings, "bus_factor")
        f_deps = pool.submit(deps_stage)
        security = _stage(_progress, "Security lookups (advisories, OSV, Scorecard)", lambda: assess_security(mk(), owner, repo), timings, "security")
        release_ctx = _stage(_progress, "Release history and artifacts", lambda: release_stage(security), timings, "release_fetch")
        features = f_feat.result()           # re-raises GitHubError (bad repo, rate limit) for the UI
        scan, bus_factor, deps_list = f_scan.result(), f_bus.result(), f_deps.result()
    flags = content_flags(features)
    result = _stage(_progress, "Detectors and Trust score", lambda: apply_gate(compute_health_score(features), security, flags, scan, bus_factor=bus_factor, features=features, releases=release_ctx), timings, "detectors")
    result["timings"] = {**timings, "zip_download": (scan.get("timings") or {}).get("zip_download")}

    try:
        release_diff = (scan.get("malware_proof") or {}).get("release_diff")
        blast = analyze_blast_radius(features, security, release_diff, deps=deps_list)
        blast["fetched_at"] = time.strftime("%Y-%m-%d", time.gmtime())     # when the deps.dev counts were read
    except Exception as e: blast = {"blast_score": 0.0, "tier": "Unknown", "pinned_deps": 0, "unpinned_deps": 0, "typosquat_alerts": [], "compromise_simulation": "", "total_dependents": 0}

    try: intel = _stage(_progress, "Forks and issue triage", lambda: gather_repo_intel(mk(), owner, repo, features), timings, "intel")
    except Exception: intel = {"forks": [], "issue_triage": {"counts": {}, "critical_samples": []}}
    return {"features": features, "result": result, "security": security, "flags": flags, "scan": scan, "bus_factor": bus_factor, "blast_radius": blast, "intelligence": intel, "releases": _release_summary(release_ctx)}


@st.cache_resource
def _ai_cache() -> SuccessCache:
    # Separate from analyze(): only successful Gemini results are kept (300s), so a failed call is retried on the next Analyze.
    return SuccessCache(ttl=300)


def ai_layer(owner: str, repo: str, gemini_key: str, data: dict) -> dict:
    intel = data["intelligence"]
    cache_key = (owner.lower(), repo.lower(), hashlib.sha256(gemini_key.encode()).hexdigest(), _configured_model())
    cached = _ai_cache().get(cache_key)
    if cached is not None:
        return cached
    try:
        ai = run_ai_layer(gemini_key, data["features"], data["result"], intel["issue_triage"], intel["forks"], data["scan"].get("findings", []))
    except Exception as e:
        err = f"AI layer did not run ({type(e).__name__})"
        ai = {"ai_report": {"executive_memo": "", "issue_triage_summary": "", "alternatives": [], "source": "Heuristic engine", "error": err}, "ai_audit_trails": {}, "ai_status": err}
    _ai_cache().put(cache_key, ai)
    return ai

@st.cache_data(ttl=900, show_spinner=False)
def additional_signals(ecosystem: str | None, name: str | None, scanned_repo: str) -> dict:
    """Informational signals (not part of the frozen ruleset or the benchmark). Each request has a timeout
    (AS.TIMEOUT); the whole result is cached for 15 minutes, failures included, and "Retry" clears it."""
    return AS.collect(ecosystem, name, scanned_repo, AS.http_get_json)


class _NotResolved(Exception):
    pass


@st.cache_data(ttl=3600, show_spinner=False)
def _full_commit_cached(owner: str, repo: str, short: str, token: str) -> str:
    try:
        sha = GitHubClient(token).get(f"/repos/{owner}/{repo}/commits/{short}").json().get("sha")
    except (GitHubError, ValueError) as e:
        raise _NotResolved(type(e).__name__) from e
    if not (isinstance(sha, str) and sha.startswith(short)):
        raise _NotResolved("unexpected answer")
    return sha


def full_commit(owner: str, repo: str, short: str | None, token: str) -> str | None:
    """Full SHA of the scanned archive's commit (cached on success only), or None when it cannot be resolved."""
    if not short:
        return None
    try:
        return _full_commit_cached(owner, repo, short, token)
    except _NotResolved:
        return None


def analyze_with_status(owner: str, repo: str, token: str) -> dict:
    """Run the cached analyze() in a worker thread (with the script context attached) and show stage progress in
    st.status from the main thread, so a long scan never looks frozen. A cache hit returns at once."""
    q: queue.Queue = queue.Queue()
    ctx = get_script_run_ctx()

    def work():
        add_script_run_ctx(threading.current_thread(), ctx)
        return analyze(owner, repo, token, _progress=q.put)

    with st.status(f"Analyzing {owner}/{repo} ...", expanded=True) as status:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(work)
            while True:
                try:
                    status.write(q.get(timeout=0.2))
                except queue.Empty:
                    if fut.done():
                        break
            while not q.empty():
                status.write(q.get_nowait())
            try:
                data = fut.result()
            except Exception:
                status.update(label=f"Analysis of {owner}/{repo} failed", state="error", expanded=False)
                raise
        t = (data.get("result") or {}).get("timings") or {}
        total = f" ({sum(v for v in t.values() if isinstance(v, (int, float))):.0f}s of stage time)" if t else ""
        status.update(label=f"Analysis of {owner}/{repo} complete{total}", state="complete", expanded=False)
    return data


def _release_summary(rc: dict | None) -> dict | None:
    """Small, display-only view of the release history (no archive contents, so the cached result stays small)."""
    if not rc:
        return None
    h = rc.get("history") or {}
    git = rc.get("git") or {}
    return {"package": rc.get("package"), "status": h.get("status"), "reason": h.get("reason"),
            "fields": h.get("fields"), "unlisted": h.get("unlisted_versions") or [], "matched_tag": git.get("matched_tag"),
            "n_tags": len(git.get("tags") or []) if git.get("tags") is not None else None,
            "rows": [{"Version": r["version"], "Uploaded": (r.get("upload_time") or "")[:19].replace("T", " "),
                      "Publisher": r.get("publisher") or f"not available ({r.get('publisher_source')})",
                      "Install scripts": ", ".join((r.get("install_scripts") or {}).keys()) or "-",
                      "Artifact": f"{(r.get('artifact') or {}).get('kind', '-')}: {r.get('artifact_status')}"}
                     for r in h.get("releases") or []]}


def _pillar_text(p: dict) -> tuple[str, str]:
    """Value and caption for one pillar card. Never a bare number: coverage is always shown."""
    if p["pillar"] == "Maintenance":
        return (f"{p['score']:.0f}", f"{p.get('label')}. {p.get('note')}")
    cov = p["coverage"]
    if p["score"] is None:
        if p["status"] == "not_applicable":
            return ("n/a", f"Not applicable: {p['reason']}")
        return ("not assessed", f"Could not run: {p['reason']}")
    return (f"{p['score']:.0f}", f"{p['score']:.0f} ({cov['text']})")


# Light styling only: spacing and chip/badge shapes. Colours come from the theme (text, borders) or the existing tier
# colours, so light and dark themes both work.
st.markdown(APP_CSS, unsafe_allow_html=True)


def hover_bar(fig: go.Figure, what: str):
    """Tooltips that show the factor name and its value (same data as the chart)."""
    fig.update_traces(hovertemplate="%{x}: %{y:.0f} " + what + "<extra></extra>")


def render_pillars(res: dict):
    pillars = res.get("pillars") or {}
    if not pillars:
        return
    st.markdown("#### Four pillars")
    st.caption("The Trust score is the lowest of Integrity, Behavior and Exposure, then the evidence caps. "
               "Maintenance is shown on its own: it feeds the fragility index and can lower the Trust score to "
               f"{MAINTENANCE_CEILING} at most.")
    cols = st.columns(4)
    order = ["Integrity", "Behavior", "Exposure", "Maintenance"]
    for c, name in zip(cols, order):
        p = pillars[name]
        val, cap = _pillar_text(p)
        limiting = " (limiting)" if res.get("limiting_pillar") == name else ""
        with c.container(border=True):
            st.metric(name + limiting, val)
            st.caption(_md_escape(cap))
    xs = [n for n in order if pillars[n]["score"] is not None]
    if xs:
        bar = go.Figure(go.Bar(x=xs, y=[pillars[n]["score"] for n in xs],
                               marker_color=["#888" if n == "Maintenance" else "#3778c2" for n in xs],
                               text=[f"{pillars[n]['score']:.0f}" for n in xs], textposition="outside"))
        bar.update_layout(yaxis=dict(range=[0, 110], title="0-100"), paper_bgcolor="rgba(0,0,0,0)",
                          plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=40, r=20, t=10, b=30), height=220)
        hover_bar(bar, "/ 100")
        st.plotly_chart(bar, width="stretch")
    if res.get("partial"):
        st.info("Partial assessment: " + _md_escape("; ".join(res.get("partial_reasons") or [])))
    fr = res.get("fragility") or {}
    if fr.get("score") is not None:
        with st.expander(f"Fragility index {fr['score']:.0f}/100", expanded=False):
            st.caption(_md_escape(f"Fragility index {fr['score']:.0f}/100 ({', '.join(fr.get('factors') or [])}). "
                                  f"At {fr['threshold']} or more, review-tier Integrity signals are escalated to high-risk. "
                                  "Weights and threshold are unvalidated design choices."))


def render_killchain(scan_findings: list[dict], res: dict):
    """Visual only: which attack stages the existing findings point at (killchain.MAP)."""
    det = [f for p in (res.get("pillars") or {}).values() for f in p.get("findings") or []]
    st.markdown(killchain.strip_html(killchain.killchain(list(scan_findings) + det)), unsafe_allow_html=True)
    st.caption(killchain.CAPTION)


def render_checks(res: dict):
    rs = st.session_state.get("_release_summary")
    with st.expander("Detectors (status and tier)", expanded=True):
        for d in res.get("detectors") or []:
            status = STATUS_TEXT.get(d["status"], d["status"])
            tier = TIER_DISPLAY.get(d["tier"], d["tier"]) if d["status"] == "ran" else ""
            extra = d.get("not_assessed_reason") or d.get("coverage_detail") or ""
            amp = " · escalated by fragility" if d.get("fragility_amplified") else ""
            st.markdown(f"`{d['detector']}` · {d['pillar']} · **{status}**" + (f" · {tier}" if tier else "")
                        + (f" · {_md_escape(extra)}" if extra else "") + amp)
        st.caption("Phase 1 detectors adapt the existing checks; their high-risk tier comes from the existing engine's "
                   "strong findings, not from new attack-specific detectors.")
    if rs:
        with st.expander("Release history used by the Integrity detectors", expanded=False):
            pkg = rs.get("package") or {}
            st.caption(_md_escape(f"{pkg.get('ecosystem')} package {pkg.get('name')}: " + (rs.get("reason") or rs.get("status") or "")))
            if rs.get("rows"):
                st.dataframe(pd.DataFrame(rs["rows"]), hide_index=True, width="stretch")
            if rs.get("fields"):
                st.caption(_md_escape("Publisher source: " + str(rs["fields"].get("publisher"))))
            if rs.get("unlisted"):
                st.caption(_md_escape("Versions no longer listed by the registry (unpublished): " + ", ".join(rs["unlisted"])))
            st.caption(_md_escape(f"Git tags: {rs['n_tags'] if rs.get('n_tags') is not None else 'not available'}; matching tag: {rs.get('matched_tag') or 'none'}"))


def render_verdict_meaning(label_base: str | None):
    """Measured benchmark numbers for this verdict, read from benchmark/results/run2 (verdict_meaning.py)."""
    vm = verdict_meaning(label_base)
    with st.container(border=True):
        st.markdown("##### What this verdict meant in the benchmark")
        st.caption(_md_escape(f"{label_base or 'This label'}: {vm['meaning']}"))
        if vm["available"]:
            st.dataframe(pd.DataFrame(vm["rows"]), hide_index=True, width="stretch", height=36 * (len(vm["rows"]) + 1) + 3)
            if vm["extra"]:
                st.caption(_md_escape(vm["extra"]))
        st.caption(_md_escape(vm["mode_note"]))
        st.caption(_md_escape(vm["source_note"]))


DOMAIN_STATUS = {"registered": "registered", "not_registered": "not registered", "could_not_check": AS.COULD_NOT_CHECK}


NO_MANIFEST_GUESSED = ("Not checked: no package manifest in the repository root. The npm/PyPI name shown above is guessed "
                       "from the repository name and is not used for these checks.")


def render_additional_signals(sig: dict, name_guessed: bool = False):
    """Informational panel. Never changes the Trust score or the verdict; a failed lookup says "could not check"."""
    with st.container(border=True):
        st.markdown(f"#### {AS.PANEL_TITLE}")
        st.caption("Informational only: these signals never change the Trust score, a cap or the verdict. "
                   f"Checked {sig.get('checked_at')} (UTC); results are kept for 15 minutes.")
        reg = sig.get("registry") or {}
        if reg.get("status") == "not_applicable":
            st.info(NO_MANIFEST_GUESSED if name_guessed else _md_escape(f"Not checked: {reg.get('reason')}."))
            return
        p = sig.get("package") or {}
        st.caption(_md_escape(f"Package: {p.get('name')} ({p.get('ecosystem')})"
                              + (f", latest release {reg.get('version')}" if reg.get("version") else "")))
        if reg.get("status") == "could_not_check":
            st.warning(_md_escape(f"Could not check the registry: {reg.get('reason')}. No additional signal is shown."))
        elif reg.get("status") == "not_found":
            st.info(_md_escape(f"Not checked: {reg.get('reason')}."))
        else:
            st.markdown(f"**Maintainer email domains** ({AS.TAKEOVER_NOTE})")
            c = reg.get("contacts") or {}
            skipped = []
            if c.get("free_mail"): skipped.append(f"{c['free_mail']} free-mail address(es)")
            if c.get("other_skipped"): skipped.append(f"{c['other_skipped']} GitHub no-reply address(es)")
            if c.get("more"): skipped.append(f"{c['more']} more domain(s) beyond the first {AS.MAX_DOMAINS}")
            src = f"Source: {reg.get('contact_source')}; only domains are shown, never the address."
            st.caption(_md_escape(src + (" Skipped: " + ", ".join(skipped) + "." if skipped else "")))
            if not sig.get("domains"):
                st.caption("No other contact domain is listed, so there was nothing to look up.")
            else:
                st.dataframe(pd.DataFrame([{"Domain checked": d["domain"],
                                            "RDAP": DOMAIN_STATUS.get(d["status"], d["status"]),
                                            "Flag": d.get("flag") or "-", "Detail": d.get("reason") or ""}
                                           for d in sig["domains"]]), hide_index=True, width="stretch")
                if any(d.get("flag") for d in sig["domains"]):
                    st.warning(f"Takeover-risk indicator, not proof: whoever controls a maintainer's email domain may "
                               "be able to reset that maintainer's registry account. Check the account before trusting "
                               "a new release.")
        pv = sig.get("provenance") or {}
        st.markdown(f"**Provenance identity** ({AS.SIGNATURE_NOTE})")
        detail = _md_escape(pv.get("detail") or "")
        if pv.get("status") == "match":
            st.info("Source repository in the provenance matches the scanned repository: " + detail + ".")
        elif pv.get("status") == "mismatch":
            st.warning("Source repository in the provenance does NOT match the scanned repository: " + detail + ".")
        elif pv.get("status") == "none":
            st.caption("No attestation found: " + detail + ". (Not a failure: many packages are published without one.)")
        else:
            st.warning("Could not check the provenance: " + detail + ".")
        if AS.has_failure(sig):
            st.button("Retry additional signals", key="retry_signals", on_click=additional_signals.clear)


with st.sidebar:
    st.header("About")
    st.write("Pulls **live data** from the GitHub REST API and public security sources and turns it into a **Trust score** (0-100, indicators, not proof): the weakest of three evidence pillars (Integrity, Behavior, Exposure). **Maintenance** (is anyone looking after it?) is shown separately; on its own it can lower the Trust score to 50 at most.")
    user_token = st.text_input("Your own GitHub token (optional)", type="password", placeholder="Leave empty to use the shared token", help="Only needed if the shared token hits GitHub's rate limit. Never stored.")
    token = user_token.strip() or server_token()
    gemini_key_input = st.text_input("Gemini API key (optional, for AI migration & triage)", type="password", placeholder="Leave empty for deterministic heuristics", help="Used for generative architecture migration code snippets and semantic issue triage.")
    gemini_key, key_source, key_notes = resolve_gemini_key(gemini_key_input, _gemini_secret_raw(), os.getenv("GEMINI_API_KEY", ""))
    # no key diagnostics in the UI: never display any part of a secret (source, length or characters)
    st.caption("Maintenance score bands")
    st.markdown(f"- **Healthy**: {HEALTHY}+\n- **Slowing down**: {SLOWING}-{HEALTHY - 1}\n- **Likely abandoned**: below {SLOWING}")

st.title("Repository & Package Trust Check")
st.caption("Trust score from code, package and supply-chain evidence. Indicators, not proof. Maintenance shown separately.")

if "repo_input" not in st.session_state: st.session_state.repo_input = ""
def _pick(sample: str):
    st.session_state.repo_input = sample
    st.session_state.analyzed = sample

col_in, col_btn = st.columns([5, 1], vertical_alignment="bottom")
col_in.text_input("Repository URL or owner/repo", key="repo_input", placeholder="https://github.com/psf/requests")
go_clicked = col_btn.button("Analyze", type="primary", width="stretch")

ex_cols = st.columns([1.2] + [2] * len(SAMPLES) + [3], vertical_alignment="center")
ex_cols[0].caption("Examples:")
for c, s in zip(ex_cols[1:], SAMPLES):
    c.button(s, key=f"s_{s}", on_click=_pick, args=(s,), width="stretch")

target = st.session_state.repo_input.strip()
if go_clicked or (target and st.session_state.get("analyzed") == target):
    try:
        owner, repo = parse_repo(target)
        data = analyze_with_status(owner, repo, token)
        with st.spinner("Asking Gemini (advisory only) ..." if gemini_key else "Preparing results ..."):
            data["intelligence"] = {**data["intelligence"], **ai_layer(owner, repo, gemini_key, data)}
        st.session_state.analyzed = target
    except GitHubError as e:
        st.error(str(e))
        st.stop()

    f, res = data["features"], data["result"]
    color = COLORS.get(res["maintenance_label"], "#444")
    gaps = assessment_gaps(res, f.get("language"), data["scan"].get("code_scan"))
    badge = partial_badge(res, gaps)
    trust_color = TRUST_COLORS.get(res.get("trust_label_base"), "#444")
    if (res.get("partial") or gaps) and trust_color == TRUST_COLORS[LABEL_NO_FINDINGS]:
        trust_color = NEUTRAL_COLOR      # a partial assessment is not shown in confident green
    trust_val = "n/a" if res.get("trust_score") is None else f"{res['trust_score']:.0f}"
    shown_label = headline_label(res["label"], res.get("trust_label_base"), len(data["scan"].get("findings") or []))

    sec, scan = data["security"], data["scan"]
    headline, why = action_verdict(res["maintenance_label"], sec["level"], bool(data["flags"]))
    dead = res["maintenance_label"] in ("Likely abandoned", "Archived (read-only)")
    mal_osv = any(x.get("source") == "OSV (Confirmed Malware)" for x in sec["findings"])
    if scan.get("known_malicious_count", 0) > 0 or mal_osv:
        headline, why = ("DO NOT USE: known malicious indicator", "Do not install or run it.")
        if scan.get("known_malicious_count", 0) == 0:
            mal_item = next(x.get("item") for x in sec["findings"] if x.get("source") == "OSV (Confirmed Malware)")
            why = f"Depends on a package that OSV lists as malicious: {mal_item}. Remove it before installing or running this repo."
    elif scan.get("high_risk_pattern_count", 0) > 0:
        headline, why = ("High-risk patterns found: review manually before use", "Indicators, not proof of malware.")
    elif scan["strong"] and sec["level"] not in ("Elevated", "High") and not dead:
        headline, why = ("Review the findings before using", f"The scan found {scan['strong']} strong finding(s) in this repository's secrets or CI configuration. Static analysis can be wrong, so check each one.")
    elif scan.get("code_high") and sec["level"] not in ("Elevated", "High") and not dead:
        headline, why = ("Review the code findings", f"The scan found {scan['code_high']} high-severity, high-confidence code finding(s). Static analysis is noisy, so this does not change the score on its own, but check each one before relying on this code.")

    pkg = sec.get("package") or {}
    with st.spinner("Checking additional signals (informational) ..."):
        sig = additional_signals(pkg.get("ecosystem"), pkg.get("name"), f["full_name"])
    receipt = evidence_receipt(data, res.get("ruleset_version", RULESET_VERSION), app_version(),
                               full_commit(owner, repo, scan.get("commit_sha"), token),
                               datetime.now(timezone.utc).isoformat(timespec="seconds"))
    export = {**data, "receipt": receipt, "additional_signals": sig}

    head_l, head_r = st.columns([4, 1], vertical_alignment="bottom")
    head_l.subheader(f["full_name"])
    if f["description"]: head_l.write(f["description"])
    head_r.download_button("Download result (JSON)", data=result_json(export, [token, user_token, gemini_key, gemini_key_input]),
                           file_name=f"{f['full_name'].replace('/', '_')}_result.json", mime="application/json",
                           width="stretch", help="The result shown on this page. No token or API key is included.")

    t_over, t_find, t_supply, t_maint, t_checked = st.tabs(["Overview", "Findings", "Supply chain", "Maintenance", "What was checked"])

    with t_over:
        left, right = st.columns([5, 7])
        with left:
            badge_html = (f"<span class='rh-badge' title='{html.escape(badge['reason'], quote=True)}'>⚠ {html.escape(badge['label'])}</span>"
                          if badge else "")
            st.markdown(f"<div class='rh-card' style='border-left:8px solid {trust_color}'><div class='rh-muted' style='font-size:14px'>Trust score <span style='font-size:12px'>(indicators, not proof)</span>{badge_html}</div><div style='font-size:60px;font-weight:700;line-height:1.1'>{trust_val}<span class='rh-muted' style='font-size:20px'> / 100</span></div><div><span class='rh-muted' style='font-size:13px;font-weight:400'>{TRUST_DISCLAIMER}</span></div><span class='rh-chip' style='background:{trust_color}'>{html.escape(shown_label)}</span></div>", unsafe_allow_html=True)
            if gaps: st.caption(_md_escape("Partial: " + "; ".join(gaps) + "."))
            elif badge: st.caption(_md_escape("Partial: " + badge["reason"] + "."))
            if res.get("limiting_reason"): st.caption(_md_escape(res["limiting_reason"]))
            m1, m2, m3 = st.columns(3)
            m1.metric("Stars", f"{f['stars']:,}")
            m2.metric("Forks", f"{f['forks']:,}")
            m3.metric("Language", f["language"] or "-")
            st.info(explain(res))
            for reason in res["gate_reasons"]: st.warning(reason)
            st.caption(f"Maintenance: {res['maintenance_score']:.0f} / 100 ({res['maintenance_label']}). It feeds the fragility index and can lower the Trust score to {MAINTENANCE_CEILING} at most.")

        with right:
            st.caption("Maintenance factors (0-100)")
            scored = [x for x in res["factors"] if x["score"] is not None]
            names = [x["name"] for x in scored]
            vals = [x["score"] for x in scored]
            fig = go.Figure(go.Scatterpolar(r=vals + vals[:1], theta=names + names[:1], fill="toself", line_color=color, fillcolor=color, opacity=0.55,
                                            hovertemplate="%{theta}: %{r:.0f} / 100<extra></extra>"))
            grid = "rgba(150,150,150,0.35)"
            fig.update_layout(polar=dict(bgcolor="rgba(0,0,0,0)", radialaxis=dict(range=[0, 100], tickvals=[0, 25, 50, 75, 100], gridcolor=grid, linecolor=grid), angularaxis=dict(gridcolor=grid, linecolor=grid)), paper_bgcolor="rgba(0,0,0,0)", showlegend=False, margin=dict(l=70, r=70, t=30, b=30), height=380)
            st.plotly_chart(fig, width="stretch")

        st.session_state["_release_summary"] = data.get("releases")
        render_killchain(scan.get("findings") or [], res)
        render_pillars(res)

        st.markdown("#### What drives the Trust score")
        td = trust_drivers(res)
        st.dataframe(pd.DataFrame(td["rows"]), hide_index=True, width="stretch")
        st.write(_md_escape(td["caps_line"]))
        if td["not_assessed"]:
            st.caption("Not assessed: " + _md_escape("; ".join(td["not_assessed"])))
        else:
            st.caption("Not assessed: nothing (every detector ran or was not applicable).")

    with t_find:
        st.markdown("#### Verdict")
        base = res.get("trust_label_base")
        if base in (LABEL_KNOWN_MALICIOUS, LABEL_HIGH_RISK, LABEL_REVIEW, LABEL_FRAGILE, LABEL_NO_FINDINGS, LABEL_NOT_ASSESSED):
            box = st.error if base == LABEL_KNOWN_MALICIOUS else (st.warning if base in (LABEL_HIGH_RISK, LABEL_REVIEW) else st.info)
            detail = why if "DO NOT USE" in headline else _md_escape(res.get("limiting_reason") or "")
            box(f"**{_md_escape(shown_label)}.** {detail}")
            st.caption(f"Maintenance advice: {headline}. {why}" if "DO NOT USE" not in headline else "")
        else:
            box = st.error if (headline in ("Replace it", "Review urgently") or "DO NOT USE" in headline) else (st.warning if headline in ("Upgrade or review", "Use with caution", "Review the findings before using", "Plan to migrate", "Review the code findings", "High-risk patterns found: review manually before use") else st.info)
            box(f"**{headline}.** {why}")
        render_verdict_meaning(res.get("trust_label_base"))
        if sec["findings"]: st.dataframe(pd.DataFrame(sec["findings"]).rename(columns={"severity": "Level", "source": "Source", "item": "Item", "detail": "Detail"}), hide_index=True, width="stretch")

        intel_data = data.get("intelligence") or {}
        audit_trails = intel_data.get("ai_audit_trails", {})
        ai_status = intel_data.get("ai_status", "no API key")
        intel = data.get("intelligence")

        # Everything Gemini produces, in ONE collapsed section: advisory text, never part of the score or the benchmark.
        with st.expander("AI-generated, advisory, not part of the benchmark", expanded=False):
            st.markdown("##### 🧠 AI explanation of findings")
            st.caption("Skills come from the local skills/ folder; the AI can be wrong and cannot change the score or the verdict.")
            cards = build_ai_cards(audit_trails)
            if not cards:
                st.info("AI explanation not shown: " + str(ai_status))
            else:
                if any(c["failed"] for c in cards): st.info("AI explanation status: " + str(ai_status))
                for card in cards:
                    # Titles are built from validated enums or fixed text; the location comes from the repo, so escape it.
                    st.markdown(f"**{'⚠️' if card['failed'] else '🔍'} {_md_escape(card['location'])}: {card['title']}**")
                    if card["failed"]:
                        st.text(card["reason"])
                        continue
                    trail = card["trail"]
                    st.text("Skill used: " + trail["skill_used"])
                    st.text("Issue addressed: " + trail.get("issue_addressed", ""))
                    st.text("How:\n" + "\n".join("  • " + h for h in trail.get("how", [])))
                    st.text(f"Verdict: {trail['verdict']} ({trail['confidence']} confidence)")
                    st.text("Location: " + card["location"])
            ai_rep = (intel or {}).get("ai_report", {})
            st.markdown("##### 🧠 AI Migration Engine")
            if str(ai_rep.get("source", "")).startswith("Gemini"):
                st.caption(f"Source: Gemini ({ai_rep.get('model') or 'unknown model'})")
            else:
                if gemini_key:
                    st.warning(f"Gemini was not used: {str(ai_rep.get('error') or 'unknown error').rstrip('. ')}. Showing heuristic results.")
                else:
                    st.info("No Gemini key set: showing heuristic results.")
                st.caption("Source: Heuristic engine")
            if ai_rep.get("executive_memo"): st.text("Executive Memo: " + str(ai_rep["executive_memo"]))
            alts = ai_rep.get("alternatives", [])
            if alts:
                st.markdown("##### 🔄 Recommended Drop-in Replacements & Migration")
                for alt in alts:
                    status = f" [{alt['registry_status']}]" if alt.get("registry_status") else ""
                    st.text(f"{alt.get('name')} ({alt.get('ecosystem')}) — Effort: {alt.get('effort')}{status}\n{alt.get('why')}")
                    if alt.get("snippet"): st.code(alt["snippet"], language="python" if "python" in str(alt.get("ecosystem")).lower() else "javascript")

        if scan.get("code_scan") == "unavailable": st.warning("The Python code scan could not run on this server, so code findings are missing from this result.")
        if scan["findings"]:
            st.markdown("#### Findings inside the repository")
            levels = list(dict.fromkeys(x["sev"] for x in scan["findings"]))
            fc1, fc2 = st.columns([2, 3])
            sel = fc1.multiselect("Severity", levels, default=levels, key="find_sev")
            query = fc2.text_input("Search rule, file or source", key="find_q", placeholder="e.g. setup.py, secret, Bandit")
            shown = filter_findings(scan["findings"], sel, query)
            st.caption(f"Showing {len(shown)} of {len(scan['findings'])} finding(s).")
            fd = pd.DataFrame([{"Level": x["sev"], "Source": x["source"], "Rule": x["rule"], "Where": f"{x['file']}:{x['line']}", "What": x["detail"], "Suggested fix": x["fix"], "Open": x.get("url")} for x in shown],
                              columns=["Level", "Source", "Rule", "Where", "What", "Suggested fix", "Open"])
            st.dataframe(fd, hide_index=True, width="stretch", column_config={"Open": st.column_config.LinkColumn("Open", display_text="open on GitHub")})
            st.caption("Static analysis can produce false positives, so treat each row as something to review, not a verdict. Code findings cover Python only. Secrets are masked and are not checked for validity.")

    with t_supply:
        proof = scan.get("malware_proof")
        shown_any = False
        if proof:
            shown_any = True
            st.markdown("#### 🛡️ Malware & Supply-Chain Indicators")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Known malicious indicators", proof.get("known_malicious_count", 0))
            c2.metric("High-risk patterns (review)", proof.get("high_risk_pattern_count", 0))
            c3.metric("setup.py static check", proof.get("setup_py_status", "No setup.py"))
            c4.metric("PyPI release checked", (proof.get("release_diff") or {}).get("package", "N/A"))
            diff_status = (proof.get("release_diff") or {}).get("status")
            if diff_status: st.info(diff_status)
            beh = proof.get("profile") or {}
            if beh.get("categories"):
                st.markdown("##### Behavior profile (indicator categories)")
                st.write(" · ".join(f"**{k}**: {v}" for k, v in beh["categories"].items()))
                if beh.get("patterns"):
                    st.warning("Malware-like combination(s): " + ", ".join(beh["patterns"]) + ". Indicators, not proof of intent.")

        bf_data = data.get("bus_factor")
        if bf_data and not str(bf_data.get("burnout_status", "")).startswith("Unavailable"):
            shown_any = True
            st.markdown("#### 🚌 Bus Factor, Knowledge Monopoly & Maintainer Burnout")
            b1, b2, b3, b4 = st.columns(4)
            b1.metric("Bus Factor", f"{bf_data.get('bus_factor', 0)} maintainer(s)")
            b2.metric("Gini Index", f"{bf_data.get('gini', 0.0):.2f}")
            b3.metric("Knowledge Entropy", f"{bf_data.get('entropy', 0.0):.2f} / 1.0")
            b4.metric("Triage Velocity", bf_data.get("burnout_status", "Stable Triage Pace"))
            for find in bf_data.get("findings", []): st.info("ℹ️ " + find)
            if bf_data.get("author_table"):
                with st.expander(f"View Contributor Commit Distribution (Top {len(bf_data['author_table'])})"): st.dataframe(pd.DataFrame(bf_data["author_table"]), hide_index=True, width="stretch")

        br_data = data.get("blast_radius")
        if br_data and br_data.get("tier") != "Unknown":
            shown_any = True
            st.markdown("#### 💥 Supply-Chain Blast Radius & Typosquatting Guard")
            bd = blast_display(br_data, f["full_name"])
            for col, (name, value) in zip(st.columns(4), bd["metrics"]): col.metric(name, value)
            st.caption(_md_escape(bd["caption"]))
            if br_data.get("typosquat_alerts"):
                for alert in br_data["typosquat_alerts"]: st.error(f"🚨 **TYPOSQUATTING ALERT:** Dependency `{alert['package']}` resembles popular package `{alert['resembles']}` ({alert.get('ecosystem', 'PyPI')}). Verify authenticity immediately!")
            elif br_data.get("typosquat_warning"): st.warning(f"⚠️ {br_data['typosquat_warning']}")
            if bd["simulator"]: st.info("⚡ **Compromise Simulator:** " + bd["simulator"])
        if not shown_any:
            st.info("No supply-chain data was available for this repository.")
        render_additional_signals(sig, name_guessed=not pkg and bool((data.get("blast_radius") or {}).get("package_name_guessed")))

    with t_maint:
        st.markdown(f"#### Maintenance (separate from the Trust score; can cap it at {MAINTENANCE_CEILING} when fragile)")
        table = pd.DataFrame([{"Factor": x["name"], "Score (0-100)": x["score"], "Weight %": x["effective_weight"], "Evidence": x["detail"]} for x in res["factors"]])
        st.dataframe(table, hide_index=True, width="stretch", column_config={"Score (0-100)": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f")})
        for n in res["notes"]: st.caption("ℹ️ " + n)

        st.markdown("#### Commits per week, last 52 weeks")
        weeks = f["weekly_commits"]
        bar = go.Figure(go.Bar(x=list(range(len(weeks) - 1, -1, -1)), y=weeks, marker_color=color,
                               hovertemplate="%{x} weeks ago: %{y} commits<extra></extra>"))
        bar.update_layout(xaxis=dict(title="Weeks ago (0 = this week)", autorange="reversed"), yaxis=dict(title="Commits", range=[0, max(5, max(weeks))]), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=40, r=20, t=10, b=40), height=280)
        st.plotly_chart(bar, width="stretch")

        if intel:
            triage = intel.get("issue_triage", {})
            counts = triage.get("counts", {})
            forks = intel.get("forks", [])
            if counts or forks:
                st.markdown("#### Issue triage & active forks")
            if counts:
                tc1, tc2, tc3, tc4 = st.columns(4)
                tc1.metric("Security / Vulnerability", counts.get("Security / Vulnerability", 0))
                tc2.metric("Crash / Memory / Hang", counts.get("Crash / Memory / Hang", 0))
                tc3.metric("Breaking / Compatibility", counts.get("Breaking / Compatibility", 0))
                tc4.metric("General Bug / Feature", counts.get("General Bug / Feature", 0))
            if forks:
                with st.expander(f"Forks with newer commits than upstream ({len(forks)} found)"): st.dataframe(pd.DataFrame(forks), hide_index=True, width="stretch")
        with st.expander("Raw metrics collected from the GitHub API"): st.json({k: v for k, v in f.items() if k != "weekly_commits"})
        with st.expander("Limitation of the maintenance score"):
            st.caption("Limitation: a *finished and stable* library can score low because it has little recent activity. The health score measures maintenance activity, not code quality.")

    with t_checked:
        st.markdown("#### What was and was not checked")
        for c in sec["coverage"] + scan["coverage"]: st.write("- " + c)
        st.caption("The Trust score combines detector findings (Integrity, Behavior, Exposure), the evidence caps and a maintenance ceiling. No findings does not mean safe: we look for malware indicators and known-bad packages, but static analysis can miss threats and cannot prove intent.")
        render_checks(res)

    st.divider()
    st.caption(f"Ruleset {res.get('ruleset_version', RULESET_VERSION)} · Trust score: indicators, not proof.")
