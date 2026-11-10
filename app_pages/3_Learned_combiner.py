"""Learned combiner (experimental): a research result over the frozen ruleset's outputs. Every number is read from
benchmark/results/run2/ml_*.csv by ml_results.py. Never used for the Trust score or any verdict."""
import os
import sys

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ml_results as M  # noqa: E402
from ui_text import APP_CSS  # noqa: E402

st.set_page_config(page_title="Learned combiner (experimental)", page_icon="🩺", layout="wide")
st.markdown(APP_CSS, unsafe_allow_html=True)
st.title(M.TITLE)
st.warning(M.CAVEAT)

if not M.available():
    st.info("The result files (benchmark/results/run2/ml_*.csv) are not available here.")
    st.stop()

d = M.load()
h = M.headline(d)
lk = M.leakage_summary(d)


def table(rows):
    df = pd.DataFrame(rows)
    st.table(df.set_index(df.columns[0]))


with st.container(border=True):
    st.markdown("#### What it is")
    st.markdown("The rules give each package a fixed verdict. This experiment asks whether a simple model that weighs "
                "the same rule outputs (how many findings each detector raised, at which tier, and which capabilities "
                "the code has) separates known malware from ordinary packages better. It is trained and tested on the "
                "benchmark's own items. The app's Trust score and verdicts do not use it.")

with st.container(border=True):
    st.markdown("#### Headline: logistic regression and random forest side by side")
    table(M.comparison_table(d))
    st.caption(M.COMPARE_NOTE)
    st.markdown("**Frozen rules (official result):** " + "; ".join(h["rules"]))

with st.container(border=True):
    st.markdown("#### Method")
    s0 = d["head"]
    st.markdown(
        f"- **Data:** benchmark run 2: {s0['n_pos']} scored known-bad vs {s0['n_neg']} random known-good items; scary "
        "and dormant items are only scored, as extra false-positive checks.\n"
        "- **Features:** per-detector finding counts by tier (including low-level notes) and capability counts "
        "(network, credential / environment access, process spawn, decoding / obfuscation, persistence). Four sets: "
        + "; ".join(M.SET_LABEL.values()) + ".\n"
        "- **Models:** logistic regression on standardized features (main, explainable) and a random forest "
        "(comparison), with fixed default settings; nothing was tuned.\n"
        f"- **Validation:** stratified {s0['folds']}-fold cross-validation repeated {s0['repeats']} times with fixed "
        "seeds; each item is scored only by models that did not train on it; thresholds for each false-positive "
        "target are chosen inside the training folds, never on the test fold, and the realized rate is shown.")

with st.container(border=True):
    st.markdown("#### Results per feature set vs the frozen rules")
    table(M.results_table(d))
    st.caption("Recall @ X% FP: share of known-bad items flagged when the threshold targets X% false positives on "
               "random known-good items (realized rate in brackets). The frozen rules have two fixed operating points.")

with st.container(border=True):
    st.markdown("#### ROC curve (cross-validated scores)")
    fig = go.Figure()
    styles = [(h["set"], "logistic_regression", "solid"), (h["set"], "random_forest", "dot"), ("C", "logistic_regression", "dash")]
    for fs, model, dash in styles:
        pts = [r for r in d["roc"] if r["feature_set"] == fs and r["model"] == model]
        name = f"{fs}, {M.MODEL_LABEL[model]}" + (" (not trusted: dataset bias)" if fs == "C" else "")
        fig.add_trace(go.Scatter(x=[float(r["fpr"]) for r in pts], y=[float(r["tpr"]) for r in pts], mode="lines",
                                 name=name, line=dict(dash=dash, width=2),
                                 hovertemplate="FP rate %{x:.1%}, recall %{y:.1%}<extra>" + name + "</extra>"))
    for op, sym in (("strict", "diamond"), ("lenient", "square")):
        rec, fp = d["rules"][op]
        fig.add_trace(go.Scatter(x=[float(fp["rate"])], y=[float(rec["recall"])], mode="markers", name=f"frozen rules, {op}",
                                 marker=dict(size=12, symbol=sym),
                                 hovertemplate=f"frozen rules ({op}): FP %{{x:.1%}}, recall %{{y:.1%}}<extra></extra>"))
    fig.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines", name="chance", line=dict(color="rgba(150,150,150,0.6)", dash="dot")))
    fig.update_layout(xaxis=dict(title="False-positive rate (random known-good)", range=[0, 1], gridcolor="rgba(150,150,150,0.25)"),
                      yaxis=dict(title="Recall (known-bad)", range=[0, 1.02], gridcolor="rgba(150,150,150,0.25)"),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=460,
                      margin=dict(l=50, r=20, t=10, b=40), legend=dict(orientation="h", y=-0.2))
    st.plotly_chart(fig, width="stretch")

c1, c2 = st.columns(2)
with c1, st.container(border=True):
    st.markdown(f"#### Logistic regression weights (set {h['set']})")
    table(M.top_coefficients(d, h["set"]))
    st.caption("Weight per standard deviation of the feature; positive pushes toward known-bad. Weights of correlated "
               "features share the effect, so read them together, not one by one.")
with c2, st.container(border=True):
    st.markdown("#### Sanity checks")
    for line in M.sanity_lines(d):
        st.markdown("- " + line)
    st.markdown("**Extra false-positive checks** (models trained on all known-bad and known-good):")
    for line in M.extra_lines(d, h["set"], h["model"]):
        st.markdown("- " + line)

with st.container(border=True):
    st.markdown("#### Shortcut warning (feature set C) and source leakage")
    st.markdown(f"Nearly every known-bad item is a DataDog sample and every random known-good item a registry archive. "
                f"Feature set C (size, file count, artifact kind, ecosystem) lets a model recognise the **source**, "
                f"which is why its numbers are near perfect: **not trusted (dataset bias)**. In set A, "
                f"{len(lk['indicators'])} of {lk['n_features']} features were excluded as source indicators for the "
                f"headline (detectors: {', '.join(lk['detectors_excluded'])}). {len(lk['only_datadog'])} features fire "
                "only in DataDog samples; this data cannot tell whether they are malware signals or source effects.")

st.caption(M.CAVEAT + " Numbers are read from benchmark/results/run2/ml_*.csv (written by benchmark/ml_combiner.py).")
