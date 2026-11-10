"""How accurate is it? Measured numbers of benchmark run 2 (ruleset v1, 2026.11.08-12) and of the fresh test set
(v1 vs v2), all read from the committed result files by accuracy.py. Says which ruleset the app runs. Display only."""
import os
import sys

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import accuracy as A  # noqa: E402
from ui_text import APP_CSS  # noqa: E402

st.set_page_config(page_title="How accurate is it?", page_icon="🩺", layout="wide")
st.markdown(APP_CSS, unsafe_allow_html=True)

st.title("How accurate is it?")
d = A.load()
note = A.ruleset_note()
if note:
    st.info(note)
st.markdown(f"**{d['summary']}**")


def table(rows):
    """Static table: long text wraps (st.dataframe would cut it off); colours follow the theme."""
    df = pd.DataFrame(rows)
    st.table(df.set_index(df.columns[0]))


with st.container(border=True):
    st.markdown("#### Layered detection (known-bad samples, artifact mode)")
    table(d["layered"])
    st.caption("Strict: a high-risk or known-malicious finding. Lenient: a review-tier finding or above. The behavior "
               "detectors row is the headline: it is the only row that measures detecting malware the database does "
               "not already list. The other two rows are upper bounds, because the known-bad labels come from the same "
               "OSV MAL- records the lookup uses.")

with st.container(border=True):
    st.markdown("#### False positives")
    st.markdown("**Artifact mode** (release archives)")
    table(d["fps"])
    st.markdown("**Repository mode** (what the app runs)")
    table(d["repo_fps"])
    st.caption("Hard: a high-risk / known-malicious finding or a DO NOT USE / High-risk label. Soft: labelled Review "
               "recommended. Repository-mode known-bad recall is not measured. The scary set is a hand-picked judgement "
               "sample, not random.")

with st.container(border=True):
    st.markdown("#### Precision (at the benchmark's class ratio)")
    table(d["precision"])
    st.caption("Holds only at this benchmark's class ratio, not real-world prevalence: real registries have far fewer "
               "malicious packages, so real-world precision is lower and was not measured.")

c1, c2 = st.columns(2)
with c1, st.container(border=True):
    st.markdown("#### Per detector")
    table(d["per_detector"])
    st.caption("Known-bad hits and random known-good false positives per detector (headline run). Detectors with no "
               "hit and no false positive are not listed.")
with c2, st.container(border=True):
    st.markdown("#### Why it misses")
    table(d["misses"])
    st.caption("Known-bad items that are not a strict hit, by rule-based bucket over measurable facts (not verified by "
               "a human; buckets are explained in benchmark/ERROR_ANALYSIS.md).")

with st.container(border=True):
    import ml_results as M
    st.markdown("#### Learned combiner (experimental)")
    if M.available():
        _ml = M.load()
        _cmp = pd.DataFrame(M.comparison_table(_ml))
        st.table(_cmp.set_index(_cmp.columns[0]))
        st.caption(M.COMPARE_NOTE + " Frozen rules: " + "; ".join(M.headline(_ml)["rules"]) + ".")
    st.caption(M.CAVEAT + " The frozen rules above remain the official result.")
    st.page_link("app_pages/3_Learned_combiner.py", label="Learned combiner (experimental): details", icon="🧪")

with st.container(border=True):
    import guarddog_results as GD
    st.markdown("#### Compared with GuardDog")
    if GD.available():
        st.markdown(GD.headline(GD.load()))
    st.caption(GD.CAVEAT)
    st.page_link("app_pages/4_Compared_with_GuardDog.py", label="Compared with GuardDog: details", icon="🐕")

with st.container(border=True):
    st.markdown("#### How it was measured")
    for line in d["measured"]:
        st.markdown("- " + line)
    st.markdown(f"Details: [METHOD.md]({A.REPO_URL}METHOD.md) · [LIMITS.md]({A.REPO_URL}LIMITS.md) (including the run-1 "
                f"antivirus incident) · [benchmark/RESULTS.md]({A.REPO_URL}benchmark/RESULTS.md)")

with st.container(border=True):
    st.markdown("#### What is NOT measured")
    for line in d["not_measured"]:
        st.markdown("- " + line)

v2 = A.load_v2()
if v2:
    with st.container(border=True):
        st.markdown("#### Version 2 (fresh test set)")
        st.markdown(v2["notes"][0])
        table(v2["recall"])
        st.markdown("**Recall per bucket** (headline subset)")
        table(v2["buckets"])
        for line in v2["notes"][1:]:
            st.caption(line)
        st.caption("Artifact mode, no OSV lookup, no fragility escalation (v1's headline configuration). Details: "
                   f"[benchmark/RESULTS_v2.md]({A.REPO_URL}benchmark/RESULTS_v2.md) · "
                   f"[benchmark/PREREG_v2.md]({A.REPO_URL}benchmark/PREREG_v2.md)")

st.caption("Indicators, not proof. No findings does not mean safe. Numbers are read from benchmark/results/run2/, "
           "benchmark/RESULTS.md and benchmark/ERROR_ANALYSIS.md.")
