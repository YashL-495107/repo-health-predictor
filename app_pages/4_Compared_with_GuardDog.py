"""Compared with GuardDog: an external reference point. Every number is read from benchmark/results/run2/guarddog_*.csv
and our own run-2 CSVs by guarddog_results.py. The app never imports or runs GuardDog."""
import os
import sys

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import guarddog_results as G  # noqa: E402
from ui_text import APP_CSS  # noqa: E402

st.set_page_config(page_title="Compared with GuardDog", page_icon="🩺", layout="wide")
st.markdown(APP_CSS, unsafe_allow_html=True)
st.title(G.TITLE)
st.error("**Caveat:** " + G.CAVEAT)

if not G.available():
    st.info("The comparison files (benchmark/results/run2/guarddog_*.csv) are not available here.")
    st.stop()

g = G.load()


def table(rows):
    df = pd.DataFrame(rows)
    st.table(df.set_index(df.columns[0]))


with st.container(border=True):
    st.markdown("#### What GuardDog is")
    st.markdown(G.WHAT)

with st.container(border=True):
    st.markdown("#### Side by side (benchmark run 2)")
    table(G.side_by_side(g))
    st.caption("Same definitions as our benchmark: recall on known-bad items, false positives on random known-good "
               "items, 95% Wilson intervals and the rule of three at zero. GuardDog default points use its own labels "
               "(high_risk: score 7 or more; suspicious: 5 to 7). Matched-FP points use a threshold on its 0-10 risk "
               "score chosen on the same 117 known-good items (realized rate shown). The learned combiner is "
               "cross-validated and experimental.")
    st.caption(G.not_scored_line(g))

with st.container(border=True):
    st.markdown("#### Hard false positives on random known-good packages")
    st.warning(G.hard_fp_line(g))
    st.markdown("Every random known-good, scary or dormant package GuardDog labelled suspicious or high_risk, with "
                "our verdict for the same item:")
    table(G.flags_table(g))

c1, c2 = st.columns(2)
with c1, st.container(border=True):
    st.markdown("#### Which known-bad items each tool caught")
    for line in G.overlap_lines(g):
        st.markdown("- " + line)
with c2, st.container(border=True):
    st.markdown("#### Per ecosystem (GuardDog)")
    table([{"Ecosystem": e["ecosystem"], "Operating point": e["operating_point"], "Known-bad recall": e["recall_text"],
            "False positives: random known-good": e["fp_known_good_text"]} for e in g["eco"]])

with st.container(border=True):
    st.markdown("#### What each tool covers that the other does not")
    for who, what in G.COVERAGE:
        st.markdown(f"- **{who}:** {what}")

st.caption(G.CAVEAT + " Numbers are read from benchmark/results/run2/guarddog_*.csv (benchmark/guarddog_metrics.py).")
