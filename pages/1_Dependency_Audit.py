"""Dependency audit page: paste a manifest, get every dependency ranked by what to do about it."""
import os

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from audit import EXAMPLE, MAX_PACKAGES, audit

load_dotenv()
st.set_page_config(page_title="Dependency Audit", page_icon="🩺", layout="wide")


def server_token() -> str:
    try:
        t = st.secrets.get("GITHUB_TOKEN", "")
        if t:
            return t
    except Exception:
        pass
    return os.getenv("GITHUB_TOKEN", "")


@st.cache_data(ttl=3600, show_spinner=False)
def run(text: str, token: str) -> dict:
    return audit(text, token)


with st.sidebar:
    st.header("About")
    st.write("Audits a whole dependency file at once: known vulnerabilities (OSV) plus a light "
             "maintenance check of each package's GitHub repository.")
    user_token = st.text_input("Your own GitHub token (optional)", type="password",
                               placeholder="Leave empty to use the shared token")
    token = user_token.strip() or server_token()

st.title("🩺 Dependency audit")
st.caption("Which of my dependencies should I worry about? Paste `pip freeze` output, a `requirements.txt`, "
           "a `package.json` or a `package-lock.json`. Exact versions give the best results.")

if "dep_text" not in st.session_state:
    st.session_state.dep_text = ""
st.text_area("Dependency file contents", key="dep_text", height=220,
             placeholder="requests==2.31.0\nflask==3.0.0\n...")
c1, c2, _ = st.columns([1, 1, 4])
c1.button("Load an example", on_click=lambda: st.session_state.update(
    dep_text=EXAMPLE), width="stretch")
go = c2.button("Audit", type="primary", width="stretch")

if go:
    text = st.session_state.dep_text
    if not text.strip():
        st.warning("Paste a dependency file first.")
        st.stop()
    try:
        with st.spinner("Checking vulnerabilities and maintenance for each package ..."):
            result = run(text, token)
    except ValueError:
        st.error(
            "That looks like JSON but could not be read. Paste the full package.json or package-lock.json.")
        st.stop()
    rows = result["rows"]
    if not rows:
        st.warning("No dependencies were found in that text.")
        st.stop()
    df = pd.DataFrame(rows)

    vulnerable = int((df["Advisories"] > 0).sum())
    inactive = int(df["Maintenance"].isin(
        ["Likely abandoned", "Archived (read-only)"]).sum())
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Packages checked", len(df))
    m2.metric("With known vulnerabilities", vulnerable)
    m3.metric("Inactive or deprecated", inactive)
    m4.metric("Not scanned (no exact version)", len(result["unpinned"]))

    for n in result["notes"]:
        st.warning(n)

    st.markdown("#### Ranked by what to do first")
    st.dataframe(df, hide_index=True, width="stretch")
    st.download_button("Download as CSV", df.to_csv(
        index=False), "dependency_audit.csv", "text/csv")

    if result["unpinned"]:
        st.info("No exact version, so vulnerabilities were NOT scanned for: " + ", ".join(result["unpinned"])
                + ". Pin versions (for example with `pip freeze`) to scan them.")
    with st.expander("How to read this, and what it cannot tell you"):
        st.markdown(
            "- **Vulnerabilities** come from OSV.dev and only for exact versions. *No advisories found does not mean safe.*\n"
            "- **Maintenance** is a light check: last commit within 180 days = active, within 730 (2 years) = slowing, older = inactive. "
            "Stable, finished libraries can look quiet without being abandoned. Archived or deprecated packages count as inactive. "
            "The full five-factor score is on the main page.\n"
            "- **Upgrade to at least** is approximate: it is the highest fixing version among the first five advisories, compared by "
            "its numeric parts. Always read the advisory.\n"
            f"- Up to {MAX_PACKAGES} packages are checked per run. We do not detect malware or malicious intent."
        )
