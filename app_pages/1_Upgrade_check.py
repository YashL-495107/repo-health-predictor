"""Upgrade check page: what changes, risk-wise, between two published versions of one PyPI / npm package.
Added after the freeze; not part of the benchmark; unvalidated. No Trust score is computed or shown here."""
import os
import sys

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import additional_signals as AS  # noqa: E402
import killchain  # noqa: E402
import upgrade_check as U  # noqa: E402
from ui_text import APP_CSS  # noqa: E402

st.set_page_config(page_title="Upgrade check", page_icon="🩺", layout="wide")
st.markdown(APP_CSS, unsafe_allow_html=True)

st.title("Upgrade check (is this update safe?)")
st.caption(U.PAGE_LABEL + " " + U.CAVEAT + " Both versions are downloaded from the public registry and read as text "
           "in memory; nothing is installed or run. Same limits as the benchmark (5 MB per artifact, 60 s fetch budget).")


@st.cache_data(ttl=900, show_spinner=False)
def run_check(ecosystem: str, name: str, current: str | None, new: str | None) -> dict:
    return U.run(ecosystem, name, current or None, new or None, rdap_fetch=AS.http_get_json)


for k, v in (("uc_eco", "npm"), ("uc_name", ""), ("uc_cur", ""), ("uc_new", ""), ("uc_go", False)):
    st.session_state.setdefault(k, v)

cases = U.replay_cases()


def _pick_replay():
    c = next((x for x in cases if x["incident"] == st.session_state.uc_replay), None)
    if c:
        st.session_state.update(uc_eco=c["ecosystem"], uc_name=c["package"], uc_cur="", uc_new=c["new"], uc_go=True)


if cases:
    st.selectbox("Known incidents (replay)", ["(choose one)"] + [c["incident"] for c in cases], key="uc_replay",
                 on_change=_pick_replay)
    st.caption("Replay, not held-out evidence: the incident list and the benchmark's recorded result come from the "
               "repository (benchmark/manifests/replay_incidents.csv, results/run2/replay.csv); the two releases are "
               "downloaded from the registry when the check runs.")
else:
    st.caption("Known incidents (replay): the benchmark's replay data is not available here, so the selector is hidden.")

c1, c2, c3, c4 = st.columns([1, 2, 1.5, 1.5], vertical_alignment="bottom")
c1.selectbox("Ecosystem", ["npm", "PyPI"], key="uc_eco")
c2.text_input("Package name", key="uc_name", placeholder="e.g. requests or lodash")
c3.text_input("Current version", key="uc_cur", placeholder="empty = the release before the new one")
c4.text_input("New version", key="uc_new", placeholder="empty = latest")
if st.button("Check upgrade", type="primary"):
    st.session_state.uc_go = True

name = st.session_state.uc_name.strip()
if st.session_state.uc_go and name:
    with st.spinner("Downloading and comparing both versions (read only, nothing is run) ..."):
        res = run_check(st.session_state.uc_eco, name, st.session_state.uc_cur.strip(), st.session_state.uc_new.strip())
    case = next((c for c in cases if c["package"] == name and c["new"] == st.session_state.uc_new.strip()), None)
    if case:
        st.info(f"Replay, not held-out evidence: {case['incident']} ({case['status']}). Benchmark replay result for "
                f"{case['package']} {case['new']}: {case['benchmark_label']} (detectors: {case['benchmark_detectors']}). "
                f"{case['note']}")
    v = res.get("versions") or {}
    if v:
        st.subheader(f"{name} ({res['ecosystem']}): {v['current']} → {v['new']}")
    verdict = res["verdict"]
    if verdict["verdict"] == U.REVIEW:
        st.warning(f"**{U.REVIEW}.** Added or changed:\n" + "\n".join(f"- {i}" for i in verdict["items"]))
    elif verdict["verdict"] == U.NO_CHANGES:
        st.info(f"**{U.NO_CHANGES}.** {U.CAVEAT}")
    else:
        st.error(f"**{U.NOT_COMPARED}.** " + "; ".join(verdict["items"]))
    st.caption(U.CAVEAT + " " + U.PAGE_LABEL)
    if res.get("rows"):
        st.markdown(killchain.strip_html(killchain.killchain(res.get("killchain_findings") or [])), unsafe_allow_html=True)
        st.caption(killchain.CAPTION + " Here: only what the new version adds.")
        show_all = st.toggle("Show unchanged rows", value=False, key="uc_all")
        rows = [r for r in res["rows"] if show_all or r["change"] != "unchanged"]
        order = {"added": 0, "changed": 1, "mismatch": 1, "removed": 2, "could not check": 3, "info": 4, "unchanged": 5}
        rows.sort(key=lambda r: (order.get(r["change"], 9), U.AREAS.index(r["area"]) if r["area"] in U.AREAS else 99))
        st.dataframe(pd.DataFrame([{"Area": r["area"], "Item": r["item"], "Change": r["change"], "Evidence": r["evidence"]}
                                   for r in rows], columns=["Area", "Item", "Change", "Evidence"]),
                     hide_index=True, width="stretch")
        n_unch = sum(r["change"] == "unchanged" for r in res["rows"])
        st.caption(f"{n_unch} unchanged row(s) hidden." if not show_all and n_unch else " ")
    for n in res.get("notes") or []:
        st.caption("ℹ️ " + n)
    with st.expander("What this compares"):
        st.markdown(
            "- **Install hooks:** npm preinstall / install / postinstall scripts; setup.py install-time calls (static "
            "Layer 2 check); .pth start-up files.\n"
            "- **Capabilities:** credential / environment access, exfiltration-style network endpoints, network API use, "
            "process spawning, decoding / obfuscation, persistence (existing behavior scan and release analysis), "
            "per file.\n"
            "- **Dependencies:** added / removed; each added one with its age on the registry at the new release and a "
            "lookalike check.\n"
            "- **Publisher, release gap, maintainer email domains** (current registry contacts, RDAP; takeover-risk "
            "indicator, not proof), **provenance** per version (signature not cryptographically verified here), size, "
            "new minified files.\n"
            "- **Verdict:** \"Review before upgrading\" only when something risk-relevant is added or changed (install "
            "hook added, new capability category, very new or lookalike dependency, publisher changed, provenance "
            "removed or naming another repository, new minified file, maintainer-domain flag). A long release gap alone "
            "is shown as information; removed items never count.\n"
            "- Nothing is installed, imported or run. No Trust score is computed on this page.")
