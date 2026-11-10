"""Repository & Package Trust Check - Streamlit entrypoint (Streamlit Cloud runs app.py).

Page router only: st.navigation names the pages in the sidebar. The main page's code is trust_check.py; the other
pages live in app_pages/. That folder must NOT be called "pages": Streamlit auto-discovers a pages/ folder, and a
fresh session opened on a page URL would then bypass this router (sidebar showing file names such as "app").
url_path keeps the earlier page addresses.
"""
import streamlit as st

PAGES = [
    st.Page("trust_check.py", title="Trust check", icon="🩺", default=True),
    st.Page("app_pages/1_Dependency_Audit.py", title="Dependency Audit", url_path="Dependency_Audit"),
    st.Page("app_pages/1_Upgrade_check.py", title="Upgrade check", url_path="Upgrade_check"),
    st.Page("app_pages/2_How_accurate.py", title="How accurate is it?", url_path="How_accurate"),
    st.Page("app_pages/3_Learned_combiner.py", title="Learned combiner (experimental)", url_path="Learned_combiner"),
]

st.navigation(PAGES).run()
