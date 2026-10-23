"""GitHub Repository Health & Abandonment Predictor - Streamlit app."""
import os

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

from github_client import GitHubClient, GitHubError, fetch_features, parse_repo
from scoring import HEALTHY, SLOWING, compute_health_score, explain
from security import action_verdict, apply_gate, assess_security, content_flags
from repo_scan import scan_repo

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
def analyze(owner: str, repo: str, token: str) -> dict:
    client = GitHubClient(token)
    features = fetch_features(client, owner, repo)
    security = assess_security(client, owner, repo)
    flags = content_flags(features)
    try:
        scan = scan_repo(client, owner, repo)
    except Exception as e:  # the content scan must never break the main analysis
        scan = {"ran": False, "findings": [], "strong": 0, "review": 0,
                "coverage": [f"Content scan: NOT run ({type(e).__name__})"]}
    result = apply_gate(compute_health_score(features), security, flags, scan)
    return {"features": features, "result": result, "security": security, "flags": flags, "scan": scan}


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
            data = analyze(owner, repo, token)
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
    if scan["strong"] and sec["level"] not in ("Elevated", "High") and not dead:
        headline, why = ("Review the findings before using",
                         f"The scan found {scan['strong']} strong finding(s) in this repository's secrets or CI configuration. "
                         "Static analysis can be wrong, so check each one.")
    elif scan.get("code_high") and sec["level"] not in ("Elevated", "High") and not dead:
        headline, why = ("Review the code findings",
                         f"The scan found {scan['code_high']} high-severity, high-confidence code finding(s). Static analysis is noisy, so this does "
                         "not change the score on its own, but check each one before relying on this code.")
    st.markdown("#### Verdict")
    box = st.error if headline in ("Replace it", "Review urgently") else (
        st.warning if headline in ("Upgrade or review", "Use with caution", "Review the findings before using", "Plan to migrate", "Review the code findings") else st.info)
    box(f"**{headline}.** {why}")
    if sec["findings"]:
        st.dataframe(pd.DataFrame(sec["findings"]).rename(columns={
            "severity": "Level", "source": "Source", "item": "Item", "detail": "Detail"}),
            hide_index=True, width="stretch")

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
