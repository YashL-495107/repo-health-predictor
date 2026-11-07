"""GitHub Repository Health & Abandonment Predictor - Streamlit app."""
import html
import os
import re
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

from github_client import GitHubClient, GitHubError, fetch_features, parse_repo
from scoring import HEALTHY, SLOWING, compute_health_score, explain
from security import action_verdict, apply_gate, assess_security, content_flags, collect_dependencies
from repo_scan import scan_repo
from bus_factor import run_bus_factor_analysis
import hashlib
from intelligence import build_ai_cards, SuccessCache, gather_repo_intel, run_ai_layer, _configured_model, resolve_gemini_key, describe_gemini_key, _MISSING
from blast_radius import analyze_blast_radius
from detectors import RULESET_VERSION, TIER_DISPLAY
from releases import collect_release_context
from pillars import (LABEL_FRAGILE, LABEL_HIGH_RISK, LABEL_KNOWN_MALICIOUS, LABEL_NO_FINDINGS, LABEL_NOT_ASSESSED,
                     LABEL_REVIEW, MAINTENANCE_CEILING)

load_dotenv()
st.set_page_config(page_title="Repo Health Predictor", page_icon="🩺", layout="wide")
SAMPLES = ["psf/requests", "pallets/flask", "fastapi/fastapi", "request/request", "atom/atom"]
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


@st.cache_data(ttl=3600, show_spinner=False)
def analyze(owner: str, repo: str, token: str) -> dict:
    client = GitHubClient(token)
    features = fetch_features(client, owner, repo)
    security = assess_security(client, owner, repo)
    flags = content_flags(features)
    try:
        scan = scan_repo(client, owner, repo)
    except Exception as e:
        scan = {"ran": False, "findings": [], "strong": 0, "review": 0, "malware_proof": None, "known_malicious_count": 0, "high_risk_pattern_count": 0, "coverage": [f"Content scan: NOT run ({type(e).__name__})"], "skip_reason": f"other: {type(e).__name__}"}
    # bus factor runs before the gate: it feeds the fragility index used by the trust score
    try: bus_factor = run_bus_factor_analysis(client, owner, repo)
    except Exception as e: bus_factor = {"bus_factor": 0, "gini": 0.0, "entropy": 0.0, "burnout_status": f"Unavailable ({type(e).__name__})", "findings": [], "author_table": [], "succession_score": 0.0, "risk_level": "Unknown"}
    try: release_ctx = collect_release_context(owner, repo, security.get("package"))
    except Exception as e: release_ctx = {"package": security.get("package"), "history": {"status": "error", "reason": f"release fetch crashed ({type(e).__name__})", "releases": []}, "git": None}
    result = apply_gate(compute_health_score(features), security, flags, scan, bus_factor=bus_factor, features=features, releases=release_ctx)

    try:
        deps_info = collect_dependencies(client, owner, repo)
        deps_list = deps_info.get("deps", [])
    except Exception: deps_list = []

    try:
        release_diff = (scan.get("malware_proof") or {}).get("release_diff")
        blast = analyze_blast_radius(features, security, release_diff, deps=deps_list)
    except Exception as e: blast = {"blast_score": 0.0, "tier": "Unknown", "pinned_deps": 0, "unpinned_deps": 0, "typosquat_alerts": [], "compromise_simulation": "", "total_dependents": 0}

    try: intel = gather_repo_intel(client, owner, repo, features)
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
        c.metric(name + limiting, val)
        c.caption(_md_escape(cap))
    xs = [n for n in order if pillars[n]["score"] is not None]
    if xs:
        bar = go.Figure(go.Bar(x=xs, y=[pillars[n]["score"] for n in xs],
                               marker_color=["#888" if n == "Maintenance" else "#3778c2" for n in xs],
                               text=[f"{pillars[n]['score']:.0f}" for n in xs], textposition="outside"))
        bar.update_layout(yaxis=dict(range=[0, 110], title="0-100"), paper_bgcolor="rgba(0,0,0,0)",
                          plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=40, r=20, t=10, b=30), height=220)
        st.plotly_chart(bar, width="stretch")
    if res.get("partial"):
        st.info("Partial assessment: " + _md_escape("; ".join(res.get("partial_reasons") or [])))
    fr = res.get("fragility") or {}
    if fr.get("score") is not None:
        st.caption(_md_escape(f"Fragility index {fr['score']:.0f}/100 ({', '.join(fr.get('factors') or [])}). "
                              f"At {fr['threshold']} or more, review-tier Integrity signals are escalated to high-risk. "
                              "Weights and threshold are unvalidated design choices."))
    rs = st.session_state.get("_release_summary")
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
    with st.expander("Detectors (status and tier)", expanded=False):
        for d in res.get("detectors") or []:
            status = STATUS_TEXT.get(d["status"], d["status"])
            tier = TIER_DISPLAY.get(d["tier"], d["tier"]) if d["status"] == "ran" else ""
            extra = d.get("not_assessed_reason") or d.get("coverage_detail") or ""
            amp = " · escalated by fragility" if d.get("fragility_amplified") else ""
            st.markdown(f"`{d['detector']}` · {d['pillar']} · **{status}**" + (f" · {tier}" if tier else "")
                        + (f" · {_md_escape(extra)}" if extra else "") + amp)
        st.caption("Phase 1 detectors adapt the existing checks; their high-risk tier comes from the existing engine's "
                   "strong findings, not from new attack-specific detectors.")


with st.sidebar:
    st.header("About")
    st.write("Pulls **live data** from the GitHub REST API and public security sources and turns it into a **Trust score** (0-100, indicators, not proof): the weakest of three evidence pillars (Integrity, Behavior, Exposure). **Maintenance** (is anyone looking after it?) is shown separately; on its own it can lower the Trust score to 50 at most.")
    user_token = st.text_input("Your own GitHub token (optional)", type="password", placeholder="Leave empty to use the shared token", help="Only needed if the shared token hits GitHub's rate limit. Never stored.")
    token = user_token.strip() or server_token()
    gemini_key_input = st.text_input("Gemini API key (optional, for AI migration & triage)", type="password", placeholder="Leave empty for deterministic heuristics", help="Used for generative architecture migration code snippets and semantic issue triage.")
    gemini_key, key_source, key_notes = resolve_gemini_key(gemini_key_input, _gemini_secret_raw(), os.getenv("GEMINI_API_KEY", ""))
    st.caption(describe_gemini_key(gemini_key, key_source, key_notes))
    st.caption("Maintenance score bands")
    st.markdown(f"- **Healthy**: {HEALTHY}+\n- **Slowing down**: {SLOWING}-{HEALTHY - 1}\n- **Likely abandoned**: below {SLOWING}")

st.title("GitHub Repository Health & Abandonment Predictor")
st.caption("Paste any public GitHub repository to get its Trust score (indicators, not proof) and its maintenance health.")

if "repo_input" not in st.session_state: st.session_state.repo_input = ""
def _pick(sample: str):
    st.session_state.repo_input = sample
    st.session_state.analyzed = sample

col_in, col_btn = st.columns([5, 1], vertical_alignment="bottom")
col_in.text_input("Repository URL or owner/repo", key="repo_input", placeholder="https://github.com/psf/requests")
go_clicked = col_btn.button("Analyze", type="primary", width="stretch")

st.write("Try one:")
for c, s in zip(st.columns(len(SAMPLES)), SAMPLES):
    c.button(s, key=f"s_{s}", on_click=_pick, args=(s,), width="stretch")

target = st.session_state.repo_input.strip()
if go_clicked or (target and st.session_state.get("analyzed") == target):
    try:
        owner, repo = parse_repo(target)
        with st.spinner(f"Fetching live data for {owner}/{repo} ..."):
            data = analyze(owner, repo, token)
        with st.spinner("Asking Gemini (advisory only) ..." if gemini_key else "Preparing results ..."):
            data["intelligence"] = {**data["intelligence"], **ai_layer(owner, repo, gemini_key, data)}
        st.session_state.analyzed = target
    except GitHubError as e:
        st.error(str(e))
        st.stop()

    f, res = data["features"], data["result"]
    color = COLORS.get(res["maintenance_label"], "#444")
    trust_color = TRUST_COLORS.get(res.get("trust_label_base"), "#444")
    trust_val = "n/a" if res.get("trust_score") is None else f"{res['trust_score']:.0f}"
    st.subheader(f["full_name"])
    if f["description"]: st.write(f["description"])

    left, right = st.columns([1, 2])
    with left:
        st.markdown(f"<div style='border-left:8px solid {trust_color};padding:6px 16px'><div style='font-size:14px;color:#888'>Trust score <span style='font-size:12px'>(indicators, not proof)</span></div><div style='font-size:56px;font-weight:700;line-height:1.1'>{trust_val}<span style='font-size:20px;color:#888'> / 100</span></div><div style='font-size:20px;font-weight:600;color:{trust_color}'>{html.escape(res['label'])}</div></div>", unsafe_allow_html=True)
        if res.get("limiting_reason"): st.caption(_md_escape(res["limiting_reason"]))
        st.write("")
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
        fig = go.Figure(go.Scatterpolar(r=vals + vals[:1], theta=names + names[:1], fill="toself", line_color=color, fillcolor=color, opacity=0.55))
        grid = "rgba(150,150,150,0.35)"
        fig.update_layout(polar=dict(bgcolor="rgba(0,0,0,0)", radialaxis=dict(range=[0, 100], tickvals=[0, 25, 50, 75, 100], gridcolor=grid, linecolor=grid), angularaxis=dict(gridcolor=grid, linecolor=grid)), paper_bgcolor="rgba(0,0,0,0)", showlegend=False, margin=dict(l=70, r=70, t=30, b=30), height=380)
        st.plotly_chart(fig, width="stretch")

    st.session_state["_release_summary"] = data.get("releases")
    render_pillars(res)

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
    
    st.markdown("#### Verdict")
    base = res.get("trust_label_base")
    if base in (LABEL_KNOWN_MALICIOUS, LABEL_HIGH_RISK, LABEL_REVIEW, LABEL_FRAGILE, LABEL_NO_FINDINGS, LABEL_NOT_ASSESSED):
        box = st.error if base == LABEL_KNOWN_MALICIOUS else (st.warning if base in (LABEL_HIGH_RISK, LABEL_REVIEW) else st.info)
        detail = why if "DO NOT USE" in headline else _md_escape(res.get("limiting_reason") or "")
        box(f"**{_md_escape(res['label'])}.** {detail}")
        st.caption(f"Maintenance advice: {headline}. {why}" if "DO NOT USE" not in headline else "")
    else:
        box = st.error if (headline in ("Replace it", "Review urgently") or "DO NOT USE" in headline) else (st.warning if headline in ("Upgrade or review", "Use with caution", "Review the findings before using", "Plan to migrate", "Review the code findings", "High-risk patterns found: review manually before use") else st.info)
        box(f"**{headline}.** {why}")
    if sec["findings"]: st.dataframe(pd.DataFrame(sec["findings"]).rename(columns={"severity": "Level", "source": "Source", "item": "Item", "detail": "Detail"}), hide_index=True, width="stretch")

    intel_data = data.get("intelligence") or {}
    audit_trails = intel_data.get("ai_audit_trails", {})
    ai_status = intel_data.get("ai_status", "no API key")
    proof = scan.get("malware_proof")
    if proof:
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

    st.markdown("#### 🧠 AI explanation of findings (advisory, never changes the score)")
    st.caption("Skills come from the local skills/ folder; the AI can be wrong and cannot change the verdict.")
    cards = build_ai_cards(audit_trails)
    if not cards:
        st.info("AI explanation not shown: " + str(ai_status))
    else:
        if any(c["failed"] for c in cards): st.info("AI explanation status: " + str(ai_status))
        for card in cards:
            # Titles are built from validated enums or fixed text; the location comes from the repo, so escape it.
            with st.expander(f"{'⚠️' if card['failed'] else '🔍'} {_md_escape(card['location'])}: {card['title']}"):
                if card["failed"]:
                    st.text(card["reason"])
                    continue
                trail = card["trail"]
                st.text("Skill used: " + trail["skill_used"])
                st.text("Issue addressed: " + trail.get("issue_addressed", ""))
                st.text("How:\n" + "\n".join("  • " + h for h in trail.get("how", [])))
                st.text(f"Verdict: {trail['verdict']} ({trail['confidence']} confidence)")
                st.text("Location: " + card["location"])

    bf_data = data.get("bus_factor")
    if bf_data and not str(bf_data.get("burnout_status", "")).startswith("Unavailable"):
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
        st.markdown("#### 💥 Supply-Chain Blast Radius & Typosquatting Guard")
        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Ecosystem Tier", br_data.get("tier", "Localized"))
        r2.metric("Blast Radius Score", f"{br_data.get('blast_score', 0):.0f} / 100")
        r3.metric("Pinned Deps", f"{br_data.get('pinned_deps', 0)} / {br_data.get('total_deps', 0)}")
        r4.metric("Typosquat Alerts", len(br_data.get("typosquat_alerts", [])))
        if br_data.get("typosquat_alerts"):
            for alert in br_data["typosquat_alerts"]: st.error(f"🚨 **TYPOSQUATTING ALERT:** Dependency `{alert['package']}` resembles popular package `{alert['resembles']}` ({alert.get('ecosystem', 'PyPI')}). Verify authenticity immediately!")
        elif br_data.get("typosquat_warning"): st.warning(f"⚠️ {br_data['typosquat_warning']}")
        sim = br_data.get("compromise_simulation")
        if sim: st.info("⚡ **Compromise Simulator:** " + sim)

    intel = data.get("intelligence")
    if intel:
        st.markdown("#### 🧠 AI Migration Engine, Semantic Issue Triage & Active Forks")
        ai_rep = intel.get("ai_report", {})
        if str(ai_rep.get("source", "")).startswith("Gemini"):
            st.caption(f"Source: Gemini ({ai_rep.get('model') or 'unknown model'})")
        else:
            if gemini_key:
                st.warning(f"Gemini was not used: {str(ai_rep.get('error') or 'unknown error').rstrip('. ')}. Showing heuristic results.")
            else:
                st.info("No Gemini key set: showing heuristic results.")
            st.caption("Source: Heuristic engine")
        if ai_rep.get("executive_memo"): st.text("Executive Memo: " + str(ai_rep["executive_memo"]))
        triage = intel.get("issue_triage", {})
        counts = triage.get("counts", {})
        if counts:
            tc1, tc2, tc3, tc4 = st.columns(4)
            tc1.metric("Security / Vulnerability", counts.get("Security / Vulnerability", 0))
            tc2.metric("Crash / Memory / Hang", counts.get("Crash / Memory / Hang", 0))
            tc3.metric("Breaking / Compatibility", counts.get("Breaking / Compatibility", 0))
            tc4.metric("General Bug / Feature", counts.get("General Bug / Feature", 0))
        forks = intel.get("forks", [])
        if forks:
            with st.expander(f"Active Community Takeover Forks Ahead of Upstream ({len(forks)} found)"): st.dataframe(pd.DataFrame(forks), hide_index=True, width="stretch")
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
        fd = pd.DataFrame([{"Level": f["sev"], "Source": f["source"], "Rule": f["rule"], "Where": f"{f['file']}:{f['line']}", "What": f["detail"], "Suggested fix": f["fix"], "Open": f.get("url")} for f in scan["findings"]])
        st.dataframe(fd, hide_index=True, width="stretch", column_config={"Open": st.column_config.LinkColumn("Open", display_text="open on GitHub")})
        st.caption("Static analysis can produce false positives, so treat each row as something to review, not a verdict. Code findings cover Python only. Secrets are masked and are not checked for validity.")

    with st.expander("What was and was not checked"):
        for c in sec["coverage"] + scan["coverage"]: st.write("- " + c)
        st.caption("The Trust score combines detector findings (Integrity, Behavior, Exposure), the evidence caps and a maintenance ceiling. No findings does not mean safe: we look for malware indicators and known-bad packages, but static analysis can miss threats and cannot prove intent.")

    st.markdown("#### What drives the maintenance score")
    table = pd.DataFrame([{"Factor": x["name"], "Score (0-100)": x["score"], "Weight %": x["effective_weight"], "Evidence": x["detail"]} for x in res["factors"]])
    st.dataframe(table, hide_index=True, width="stretch", column_config={"Score (0-100)": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f")})
    for n in res["notes"]: st.caption("ℹ️ " + n)

    st.markdown("#### Commits per week, last 52 weeks")
    weeks = f["weekly_commits"]
    bar = go.Figure(go.Bar(x=list(range(len(weeks) - 1, -1, -1)), y=weeks, marker_color=color))
    bar.update_layout(xaxis=dict(title="Weeks ago (0 = this week)", autorange="reversed"), yaxis=dict(title="Commits", range=[0, max(5, max(weeks))]), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=40, r=20, t=10, b=40), height=280)
    st.plotly_chart(bar, width="stretch")
    with st.expander("Raw metrics collected from the GitHub API"): st.json({k: v for k, v in f.items() if k != "weekly_commits"})
    st.caption(f"Ruleset {res.get('ruleset_version', RULESET_VERSION)} · Trust score: indicators, not proof.")
    st.caption("Limitation: a *finished and stable* library can score low because it has little recent activity. The health score measures maintenance activity, not code quality.")