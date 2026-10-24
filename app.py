"""GitHub Repository Health & Abandonment Predictor - Streamlit app."""
import os

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

from github_client import GitHubClient, GitHubError, fetch_features, parse_repo
from scoring import HEALTHY, SLOWING, compute_health_score, explain
from security import action_verdict, apply_gate, assess_security, content_flags, collect_dependencies
from repo_scan import scan_repo
from bus_factor import run_bus_factor_analysis
from intelligence import run_intelligence_engine
from blast_radius import analyze_blast_radius

load_dotenv()
st.set_page_config(page_title="Repo Health Predictor",
                   page_icon="🩺", layout="wide")

SAMPLES = ["psf/requests", "pallets/flask",
           "fastapi/fastapi", "request/request", "atom/atom"]
COLORS = {"Healthy": "#1a9850", "Slowing down": "#f4a300", "At risk": "#e66101",
          "Likely abandoned": "#d73027", "Archived (read-only)": "#6c757d"}


def server_token() -> str:
    """Shared token kept on the server (Streamlit secrets or .env). Never shown in the UI."""
    try:
        t = st.secrets.get("GITHUB_TOKEN", "")
        if t:
            return t
    except Exception:  # no secrets file
        pass
    return os.getenv("GITHUB_TOKEN", "")


@st.cache_data(ttl=3600, show_spinner=False)
def analyze(owner: str, repo: str, token: str, gemini_key: str = "") -> dict:
    client = GitHubClient(token)
    features = fetch_features(client, owner, repo)
    security = assess_security(client, owner, repo)
    flags = content_flags(features)
    try:
        scan = scan_repo(client, owner, repo)
    except Exception as e:  # the content scan must never break the main analysis
        scan = {"ran": False, "findings": [], "strong": 0, "review": 0,
                "malware_proof": None, "verified_malware": 0,
                "coverage": [f"Content scan: NOT run ({type(e).__name__})"]}
    result = apply_gate(compute_health_score(features), security, flags, scan)

    # Phase 1: Bus factor & succession analysis
    try:
        bus_factor = run_bus_factor_analysis(client, owner, repo)
    except Exception as e:
        bus_factor = {
            "bus_factor": 0, "gini": 0.0, "entropy": 0.0,
            "burnout_status": f"Unavailable ({type(e).__name__})",
            "findings": [], "author_table": [], "succession_score": 0.0, "risk_level": "Unknown",
        }

    # Phase 3: Dependencies & blast radius analysis
    try:
        deps_info = collect_dependencies(client, owner, repo)
        deps_list = deps_info.get("deps", [])
    except Exception:
        deps_list = []

    try:
        release_diff = (scan.get("malware_proof") or {}).get("release_diff")
        blast = analyze_blast_radius(features, security, release_diff, deps=deps_list)
    except Exception as e:
        blast = {
            "blast_score": 0.0, "tier": "Unknown", "pinned_deps": 0, "unpinned_deps": 0,
            "typosquat_alerts": [], "compromise_simulation": "", "total_dependents": 0,
        }

    # Phase 2: AI Migration & Issue Triage Engine
    try:
        intel = run_intelligence_engine(client, owner, repo, features, result, gemini_api_key=gemini_key)
    except Exception as e:
        intel = {
            "forks": [], "issue_triage": {"counts": {}, "critical_samples": []},
            "ai_report": {"executive_memo": "", "issue_triage_summary": "", "alternatives": []},
        }

    return {
        "features": features,
        "result": result,
        "security": security,
        "flags": flags,
        "scan": scan,
        "bus_factor": bus_factor,
        "blast_radius": blast,
        "intelligence": intel,
    }


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.header("About")
    st.write(
        "Pulls **live data** from the GitHub REST API and turns it into a **health score** "
        "(0-100) that shows whether a repository is actively maintained or drifting towards abandonment."
    )
    user_token = st.text_input(
        "Your own GitHub token (optional)", type="password", placeholder="Leave empty to use the shared token",
        help="Only needed if the shared token hits GitHub's rate limit. Never stored.",
    )
    token = user_token.strip() or server_token()
    gemini_key_input = st.text_input(
        "Gemini API key (optional, for AI migration & triage)",
        type="password",
        placeholder="Leave empty for deterministic heuristics",
        help="Used for generative architecture migration code snippets and semantic issue triage.",
    )
    gemini_key = gemini_key_input.strip() or os.getenv("GEMINI_API_KEY", "")
    st.caption("Health score bands")
    st.markdown(
        f"- **Healthy**: {HEALTHY}+\n- **Slowing down**: {SLOWING}-{HEALTHY - 1}\n- **Likely abandoned**: below {SLOWING}")

# ---------------------------------------------------------------- input
st.title("🩺 GitHub Repository Health & Abandonment Predictor")
st.caption("Paste any public GitHub repository to get its health score.")

if "repo_input" not in st.session_state:
    st.session_state.repo_input = ""


def _pick(sample: str):
    st.session_state.repo_input = sample
    st.session_state.analyzed = sample  # sample buttons analyze immediately


col_in, col_btn = st.columns([5, 1], vertical_alignment="bottom")
col_in.text_input("Repository URL or owner/repo", key="repo_input",
                  placeholder="https://github.com/psf/requests")
go_clicked = col_btn.button("Analyze", type="primary", width="stretch")

st.write("Try one:")
for c, s in zip(st.columns(len(SAMPLES)), SAMPLES):
    c.button(s, key=f"s_{s}", on_click=_pick, args=(s,), width="stretch")

# ---------------------------------------------------------------- results
target = st.session_state.repo_input.strip()
if go_clicked or (target and st.session_state.get("analyzed") == target):
    try:
        owner, repo = parse_repo(target)
        with st.spinner(f"Fetching live data for {owner}/{repo} ..."):
            data = analyze(owner, repo, token, gemini_key)
        st.session_state.analyzed = target
    except GitHubError as e:
        st.error(str(e))
        st.stop()

    f, res = data["features"], data["result"]
    color = COLORS.get(res["label"], "#444")

    st.subheader(f["full_name"])
    if f["description"]:
        st.write(f["description"])

    left, right = st.columns([1, 2])
    with left:
        st.markdown(
            f"<div style='border-left:8px solid {color};padding:6px 16px'>"
            f"<div style='font-size:14px;color:#888'>Health score</div>"
            f"<div style='font-size:56px;font-weight:700;line-height:1.1'>{res['score']:.0f}"
            f"<span style='font-size:20px;color:#888'> / 100</span></div>"
            f"<div style='font-size:20px;font-weight:600;color:{color}'>{res['label']}</div></div>",
            unsafe_allow_html=True,
        )
        st.write("")
        m1, m2, m3 = st.columns(3)
        m1.metric("Stars", f"{f['stars']:,}")
        m2.metric("Forks", f"{f['forks']:,}")
        m3.metric("Language", f["language"] or "-")
        st.info(explain(res))
        for reason in res["gate_reasons"]:
            st.warning(reason)
        if res["score"] != res["maintenance_score"]:
            st.caption(
                f"Maintenance activity alone: {res['maintenance_score']:.0f} / 100 ({res['maintenance_label']})")

    with right:
        scored = [x for x in res["factors"] if x["score"] is not None]
        names = [x["name"] for x in scored]
        vals = [x["score"] for x in scored]
        fig = go.Figure(go.Scatterpolar(
            r=vals + vals[:1], theta=names + names[:1], fill="toself", line_color=color,
            fillcolor=color, opacity=0.55,
        ))
        grid = "rgba(150,150,150,0.35)"
        fig.update_layout(
            polar=dict(
                bgcolor="rgba(0,0,0,0)",
                radialaxis=dict(range=[0, 100], tickvals=[
                                0, 25, 50, 75, 100], gridcolor=grid, linecolor=grid),
                angularaxis=dict(gridcolor=grid, linecolor=grid),
            ),
            paper_bgcolor="rgba(0,0,0,0)", showlegend=False, margin=dict(l=70, r=70, t=30, b=30), height=380,
        )
        st.plotly_chart(fig, width="stretch")

    # ---- verdict + what was checked -----------------------------------------------------
    sec, scan = data["security"], data["scan"]
    headline, why = action_verdict(
        res["maintenance_label"], sec["level"], bool(data["flags"]))
    dead = res["maintenance_label"] in (
        "Likely abandoned", "Archived (read-only)")
    if scan.get("verified_malware", 0) > 0:
        headline, why = ("DO NOT USE - Confirmed Malware / Supply-Chain Tampering",
                         f"Deterministic proof engine verified {scan['verified_malware']} active tampering/malware finding(s) "
                         "in the code, setup.py runtime sandbox, threat consensus, or PyPI release AST diff.")
    elif scan["strong"] and sec["level"] not in ("Elevated", "High") and not dead:
        headline, why = ("Review the findings before using",
                         f"The scan found {scan['strong']} strong finding(s) in this repository's secrets or CI configuration. "
                         "Static analysis can be wrong, so check each one.")
    elif scan.get("code_high") and sec["level"] not in ("Elevated", "High") and not dead:
        headline, why = ("Review the code findings",
                         f"The scan found {scan['code_high']} high-severity, high-confidence code finding(s). Static analysis is noisy, so this does "
                         "not change the score on its own, but check each one before relying on this code.")
    st.markdown("#### Verdict")
    box = st.error if (headline in ("Replace it", "Review urgently") or "DO NOT USE" in headline) else (
        st.warning if headline in ("Upgrade or review", "Use with caution", "Review the findings before using", "Plan to migrate", "Review the code findings") else st.info)
    box(f"**{headline}.** {why}")
    if sec["findings"]:
        st.dataframe(pd.DataFrame(sec["findings"]).rename(columns={
            "severity": "Level", "source": "Source", "item": "Item", "detail": "Detail"}),
            hide_index=True, width="stretch")

    proof = scan.get("malware_proof")
    if proof:
        st.markdown("#### 🛡️ 4-Layer Malware & Supply-Chain Proof Engine")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Verified Hidden Payloads / Tampering", proof.get("verified_proof_count", 0))
        c2.metric("Benign Encoded Blobs Filtered", proof.get("benign_blobs_filtered", 0))
        c3.metric(
            "PEP-578 Sandbox Syscalls Blocked",
            proof.get("sandbox_intercepted", 0) if proof.get("sandbox_ran") else "No setup.py",
        )
        c4.metric("PyPI Release AST Diff", proof.get("release_diff", {}).get("package", "N/A"))
        diff_status = proof.get("release_diff", {}).get("status")
        if diff_status:
            st.info(diff_status)

    # ---- Phase 1: Bus Factor, Knowledge Monopoly & Maintainer Burnout ------------
    bf_data = data.get("bus_factor")
    if bf_data and not str(bf_data.get("burnout_status", "")).startswith("Unavailable"):
        st.markdown("#### 🚌 Bus Factor, Knowledge Monopoly & Maintainer Burnout")
        b1, b2, b3, b4 = st.columns(4)
        b1.metric("Bus Factor", f"{bf_data.get('bus_factor', 0)} maintainer(s)")
        b2.metric("Gini Index", f"{bf_data.get('gini', 0.0):.2f}", help="0.0 = equal distribution, 1.0 = total monopoly")
        b3.metric("Knowledge Entropy", f"{bf_data.get('entropy', 0.0):.2f} / 1.0", help="Shannon entropy normalized across contributors")
        b4.metric("Triage Velocity", bf_data.get("burnout_status", "Stable Triage Pace"))

        for find in bf_data.get("findings", []):
            st.info("ℹ️ " + find)

        if bf_data.get("author_table"):
            with st.expander(f"View Contributor Commit Distribution (Top {len(bf_data['author_table'])})"):
                st.dataframe(pd.DataFrame(bf_data["author_table"]), hide_index=True, width="stretch")

    # ---- Phase 3: Supply-Chain Blast Radius & Typosquatting Guard ----------------
    br_data = data.get("blast_radius")
    if br_data and br_data.get("tier") != "Unknown":
        st.markdown("#### 💥 Supply-Chain Blast Radius & Typosquatting Guard")
        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Ecosystem Tier", br_data.get("tier", "Localized"))
        r2.metric("Blast Radius Score", f"{br_data.get('blast_score', 0):.0f} / 100")
        r3.metric("Pinned Deps", f"{br_data.get('pinned_deps', 0)} / {br_data.get('total_deps', 0)}")
        r4.metric("Typosquat Alerts", len(br_data.get("typosquat_alerts", [])))

        if br_data.get("typosquat_alerts"):
            for alert in br_data["typosquat_alerts"]:
                st.error(
                    f"🚨 **TYPOSQUATTING ALERT:** Dependency `{alert['package']}` resembles popular package "
                    f"`{alert['resembles']}` ({alert.get('ecosystem', 'PyPI')}). Verify authenticity immediately!"
                )
        elif br_data.get("typosquat_warning"):
            st.warning(f"⚠️ {br_data['typosquat_warning']}")

        sim = br_data.get("compromise_simulation")
        if sim:
            st.info("⚡ **Compromise Simulator:** " + sim)

    # ---- Phase 2: AI Migration Engine, Semantic Issue Triage & Active Forks -------
    intel = data.get("intelligence")
    if intel:
        st.markdown("#### 🧠 AI Migration Engine, Semantic Issue Triage & Active Forks")
        ai_rep = intel.get("ai_report", {})
        if ai_rep.get("executive_memo"):
            st.markdown(f"**Executive Memo:** {ai_rep['executive_memo']}")

        # Open issues risk breakdown
        triage = intel.get("issue_triage", {})
        counts = triage.get("counts", {})
        if counts:
            tc1, tc2, tc3, tc4 = st.columns(4)
            tc1.metric("Security / Vulnerability", counts.get("Security / Vulnerability", 0))
            tc2.metric("Crash / Memory / Hang", counts.get("Crash / Memory / Hang", 0))
            tc3.metric("Breaking / Compatibility", counts.get("Breaking / Compatibility", 0))
            tc4.metric("General Bug / Feature", counts.get("General Bug / Feature", 0))

        # Active Community Forks
        forks = intel.get("forks", [])
        if forks:
            with st.expander(f"Active Community Takeover Forks Ahead of Upstream ({len(forks)} found)"):
                st.dataframe(pd.DataFrame(forks), hide_index=True, width="stretch")

        # Drop-in Replacements
        alts = ai_rep.get("alternatives", [])
        if alts:
            st.markdown("##### 🔄 Recommended Drop-in Replacements & Migration")
            for alt in alts:
                st.markdown(
                    f"**{alt.get('name')}** (`{alt.get('ecosystem')}`) — *Effort: {alt.get('effort')}*\n\n"
                    f"{alt.get('why')}"
                )
                if alt.get("snippet"):
                    st.code(alt["snippet"], language="python" if "python" in str(alt.get("ecosystem")).lower() else "javascript")

    if scan.get("code_scan") == "unavailable":
        st.warning("The Python code scan could not run on this server, so code findings are missing from this result.")

    if scan["findings"]:
        st.markdown("#### Findings inside the repository")
        fd = pd.DataFrame([{"Level": f["sev"], "Source": f["source"], "Rule": f["rule"], "Where": f"{f['file']}:{f['line']}",
                            "What": f["detail"], "Suggested fix": f["fix"], "Open": f.get("url")} for f in scan["findings"]])
        st.dataframe(fd, hide_index=True, width="stretch",
                     column_config={"Open": st.column_config.LinkColumn("Open", display_text="open on GitHub")})
        st.caption("Static analysis can produce false positives, so treat each row as something to review, not a verdict. "
                   "Code findings cover Python only. Secrets are masked and are not checked for validity.")

    with st.expander("What was and was not checked"):
        for c in sec["coverage"] + scan["coverage"]:
            st.write("- " + c)
        st.caption("Health here = maintenance activity + known security problems + dual-use content flags. "
                   "No findings does not mean safe: this tool does not detect malware or malicious intent.")

    st.markdown("#### What drives the health score")
    table = pd.DataFrame(
        [{"Factor": x["name"], "Score (0-100)": x["score"], "Weight %": x["effective_weight"], "Evidence": x["detail"]}
         for x in res["factors"]]
    )
    st.dataframe(
        table, hide_index=True, width="stretch",
        column_config={"Score (0-100)": st.column_config.ProgressColumn(
            min_value=0, max_value=100, format="%.0f")},
    )
    for n in res["notes"]:
        st.caption("ℹ️ " + n)

    st.markdown("#### Commits per week, last 52 weeks")
    weeks = f["weekly_commits"]
    bar = go.Figure(
        go.Bar(x=list(range(len(weeks) - 1, -1, -1)), y=weeks, marker_color=color))
    bar.update_layout(
        xaxis=dict(title="Weeks ago (0 = this week)", autorange="reversed"),
        yaxis=dict(title="Commits", range=[0, max(5, max(weeks))]),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=40, r=20, t=10, b=40), height=280,
    )
    st.plotly_chart(bar, width="stretch")

    with st.expander("Raw metrics collected from the GitHub API"):
        raw = {k: v for k, v in f.items() if k != "weekly_commits"}
        st.json(raw)
    st.caption(
        "Limitation: a *finished and stable* library can score low because it has little recent activity. "
        "The health score measures maintenance activity, not code quality."
    )
