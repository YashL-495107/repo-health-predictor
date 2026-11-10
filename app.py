"""Repository & Package Trust Check - Streamlit entrypoint (Streamlit Cloud runs app.py).

Page router only: st.navigation names the pages in the sidebar. The main page's code is trust_check.py; with
st.navigation the pages/ folder is no longer discovered automatically, so every page is listed here. url_path keeps
the earlier addresses of the two pages in pages/.
"""
import streamlit as st

PAGES = [
    st.Page("trust_check.py", title="Trust check", icon="🩺", default=True),
    st.Page("pages/1_Dependency_Audit.py", title="Dependency Audit", url_path="Dependency_Audit"),
    st.Page("pages/1_Upgrade_check.py", title="Upgrade check", url_path="Upgrade_check"),
    st.Page("pages/2_How_accurate.py", title="How accurate is it?", url_path="How_accurate"),
    st.Page("pages/3_Learned_combiner.py", title="Learned combiner (experimental)", url_path="Learned_combiner"),
]

st.navigation(PAGES).run()
