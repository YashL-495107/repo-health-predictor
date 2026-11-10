"""Additional signals (informational, not part of the frozen ruleset or the benchmark): maintainer email-domain RDAP
check, provenance identity, verdict meaning from the run-2 CSVs, evidence receipt. No live network: registry answers
are recorded responses (tests/fixtures/signals, recorded 2026-11-10, trimmed, e-mail local parts redacted); RDAP
answers are SYNTHETIC, written in the RFC 9083 shape, because rdap.org could not be reached from the recording
environment."""
import csv
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import additional_signals as AS  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "signals"


def rec(name):
    return {"status": 200, "data": json.loads((FIX / name).read_text(encoding="utf-8")), "redirected": False, "error": None}


def rdap_registered(date):     # synthetic RFC 9083 domain object (only the fields used)
    return {"status": 200, "redirected": True, "error": None,
            "data": {"objectClassName": "domain", "ldhName": "x", "events": [
                {"eventAction": "registration", "eventDate": date}, {"eventAction": "last changed", "eventDate": date}]}}


NOT_FOUND_AT_REGISTRY = {"status": 404, "data": None, "redirected": True, "error": None}   # rdap.org redirected, then 404
NO_RDAP_SERVER = {"status": 404, "data": None, "redirected": False, "error": None}         # rdap.org itself: unknown TLD
NETWORK_DOWN = {"status": None, "data": None, "redirected": False, "error": "ConnectionError"}
NOT_FOUND = {"status": 404, "data": None, "redirected": False, "error": None}


def fetcher(table):
    calls = []

    def fetch(url, accept=None):
        calls.append(url)
        return table.get(url, NETWORK_DOWN)
    fetch.calls = calls
    return fetch


NPM_NODE_IPC = "https://registry.npmjs.org/node-ipc"
RDAP_DIGINOW = "https://rdap.org/domain/diginow.it"


# ------------------------------------------------------------------ e-mail domains

def test_free_mail_and_noreply_are_skipped_and_addresses_never_returned():
    c = AS.contact_domains(["a@gmail.com", "B <b@Example.co.uk>", "c@users.noreply.github.com", "d@mail.corp.io",
                            "e@outlook.com, f@corp.io", "", "not an address"])
    assert c == {"domains": ["example.co.uk", "corp.io"], "free_mail": 2, "other_skipped": 1, "more": 0}


def test_registrable_domain_approximation():
    assert AS.registrable_domain("mail.corp.io") == "corp.io"
    assert AS.registrable_domain("cs.example.ac.uk") == "example.ac.uk"
    assert AS.registrable_domain("Example.COM.") == "example.com"


def test_node_ipc_pattern_domain_not_registered():
    """node-ipc's recorded registry record: one maintainer on a custom e-mail domain (diginow.it). If the registry's
    RDAP server has no record of that domain, the takeover flag is raised. (Synthetic RDAP answer: whether diginow.it
    is registered today was not checked.)"""
    f = fetcher({NPM_NODE_IPC: rec("npm_node-ipc.json"), RDAP_DIGINOW: NOT_FOUND_AT_REGISTRY})
    sig = AS.collect("npm", "node-ipc", "RIAEvangelist/node-ipc", f)
    assert sig["registry"]["status"] == "ok" and sig["registry"]["version"] == "14.0.0"
    assert sig["domains"] == [{"domain": "diginow.it", "status": "not_registered", "registered_on": None,
                               "flag": AS.FLAG_NOT_REGISTERED,
                               "reason": "the registry's RDAP server has no record of this domain"}]
    assert AS.FLAG_NOT_REGISTERED == "domain not registered (could be bought and used to reset the maintainer account)"
    text = json.dumps(sig)
    assert "@" not in text and "redacted" not in text                     # never the address, only the domain
    assert sig["provenance"]["status"] == "none"                          # node-ipc 14.0.0 has no attestation


def test_node_ipc_pattern_domain_registered_after_latest_release():
    f = fetcher({NPM_NODE_IPC: rec("npm_node-ipc.json"), RDAP_DIGINOW: rdap_registered("2026-09-30T10:00:00Z")})
    d = AS.collect("npm", "node-ipc", "RIAEvangelist/node-ipc", f)["domains"][0]
    assert d["status"] == "registered" and d["flag"] == AS.FLAG_REGISTERED_AFTER
    assert d["reason"] == "registered 2026-09-30, latest release 2026-08-24"


def test_domain_registered_before_release_has_no_flag():
    f = fetcher({NPM_NODE_IPC: rec("npm_node-ipc.json"), RDAP_DIGINOW: rdap_registered("2009-03-02T00:00:00Z")})
    d = AS.collect("npm", "node-ipc", "RIAEvangelist/node-ipc", f)["domains"][0]
    assert d["flag"] is None and d["status"] == "registered" and "before the latest release" in d["reason"]


def test_failed_rdap_is_could_not_check_never_fine():
    for answer, reason in ((NETWORK_DOWN, "RDAP lookup failed (ConnectionError)"),
                           (NO_RDAP_SERVER, "no RDAP server known for .it"),
                           ({"status": 500, "data": None, "redirected": True, "error": None}, "RDAP lookup failed (HTTP 500)")):
        f = fetcher({NPM_NODE_IPC: rec("npm_node-ipc.json"), RDAP_DIGINOW: answer})
        sig = AS.collect("npm", "node-ipc", "RIAEvangelist/node-ipc", f)
        d = sig["domains"][0]
        assert d["status"] == "could_not_check" and d["flag"] is None and d["reason"] == reason
        assert AS.has_failure(sig)


def test_registry_failure_is_could_not_check():
    sig = AS.collect("npm", "node-ipc", "RIAEvangelist/node-ipc", fetcher({}))
    assert sig["registry"]["status"] == "could_not_check" and sig["domains"] == []
    assert sig["provenance"]["status"] == "could_not_check" and AS.has_failure(sig)
    assert AS.collect("npm", "nope", "o/r", fetcher({"https://registry.npmjs.org/nope": NOT_FOUND}))["registry"]["status"] == "not_found"


def test_no_package_means_not_checked():
    sig = AS.collect(None, None, "o/r", fetcher({}))
    assert sig["registry"]["status"] == "not_applicable" and not AS.has_failure(sig)


# ------------------------------------------------------------------ provenance

SIG_ATT = "https://registry.npmjs.org/-/npm/v1/attestations/sigstore@5.0.1"
SP_JSON = "https://pypi.org/pypi/sampleproject/json"
SP_SDIST = "https://pypi.org/integrity/sampleproject/4.0.0/sampleproject-4.0.0.tar.gz/provenance"
SP_WHEEL = "https://pypi.org/integrity/sampleproject/4.0.0/sampleproject-4.0.0-py3-none-any.whl/provenance"


def test_npm_provenance_match_and_mismatch():
    table = {"https://registry.npmjs.org/sigstore": rec("npm_sigstore.json"), SIG_ATT: rec("npm_sigstore_attestations.json"),
             "https://rdap.org/domain/dehamer.com": rdap_registered("2005-01-01T00:00:00Z")}
    pv = AS.collect("npm", "sigstore", "sigstore/sigstore-js", fetcher(table))["provenance"]
    assert pv["status"] == "match" and pv["source_repository"] == "https://github.com/sigstore/sigstore-js"
    assert pv["note"] == AS.SIGNATURE_NOTE == "signature not cryptographically verified here"
    pv = AS.collect("npm", "sigstore", "someone/fork-of-sigstore", fetcher(table))["provenance"]
    assert pv["status"] == "mismatch" and "not https://github.com/someone/fork-of-sigstore" in pv["detail"]


def test_npm_attestation_lookup_failure():
    table = {"https://registry.npmjs.org/sigstore": rec("npm_sigstore.json")}
    pv = AS.collect("npm", "sigstore", "sigstore/sigstore-js", fetcher(table))["provenance"]
    assert pv["status"] == "could_not_check" and pv["detail"] == "attestation lookup failed (ConnectionError)"


def test_pypi_provenance_from_the_integrity_api():
    table = {SP_JSON: rec("pypi_sampleproject.json"), SP_SDIST: rec("pypi_sampleproject_provenance.json"),
             "https://rdap.org/domain/example.com": rdap_registered("1995-08-14T04:00:00Z")}
    f = fetcher(table)
    sig = AS.collect("PyPI", "sampleproject", "pypa/sampleproject", f)
    assert sig["provenance"]["status"] == "match" and sig["provenance"]["publisher_kind"] == "GitHub"
    assert sig["provenance"]["source_repository"] == "https://github.com/pypa/sampleproject"
    assert SP_SDIST in f.calls and SP_WHEEL not in f.calls                       # sdist first, stops at the first hit
    assert [d["domain"] for d in sig["domains"]] == ["example.com"] and sig["domains"][0]["flag"] is None
    assert AS.collect("PyPI", "sampleproject", "o/r", fetcher(table))["provenance"]["status"] == "mismatch"


def test_pypi_without_attestation_is_none_and_failure_is_could_not_check():
    base = {SP_JSON: rec("pypi_sampleproject.json"), "https://rdap.org/domain/example.com": rdap_registered("1995-08-14T04:00:00Z")}
    pv = AS.collect("PyPI", "sampleproject", "pypa/sampleproject", fetcher({**base, SP_SDIST: NOT_FOUND, SP_WHEEL: NOT_FOUND}))["provenance"]
    assert pv["status"] == "none" and "no PEP 740 attestation" in pv["detail"]
    pv = AS.collect("PyPI", "sampleproject", "pypa/sampleproject", fetcher(base))["provenance"]
    assert pv["status"] == "could_not_check" and pv["detail"] == "provenance lookup failed (ConnectionError)"


def test_normalise_repo():
    assert AS.normalise_repo("https://github.com/Sigstore/Sigstore-JS.git") == "sigstore/sigstore-js"
    assert AS.normalise_repo("git+https://github.com/o/r@refs/heads/main") == "o/r"
    assert AS.normalise_repo("pypa/sampleproject") == "pypa/sampleproject"
    assert AS.normalise_repo("GitLab: group/project") is None and AS.normalise_repo(None) is None


def test_http_get_json_never_raises():
    import requests
    with patch.object(requests, "get", side_effect=requests.ConnectTimeout("x")):
        assert AS.http_get_json("https://rdap.org/domain/x.io") == {"status": None, "data": None, "redirected": False,
                                                                     "error": "ConnectTimeout"}


def test_signals_never_feed_the_score():
    """No scoring, cap, detector or verdict module imports the additional signals."""
    for p in list(ROOT.glob("*.py")) + list((ROOT / "detectors").glob("*.py")):
        if p.name in ("app.py", "additional_signals.py"):
            continue
        assert "additional_signals" not in p.read_text(encoding="utf-8"), p.name


# ------------------------------------------------------------------ verdict meaning (numbers = CSV values)

def _csv(name):
    with open(ROOT / "benchmark" / "results" / "run2" / name, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_verdict_meaning_numbers_equal_the_run2_csvs():
    from pillars import LABEL_NO_FINDINGS, LABEL_REVIEW
    from verdict_meaning import verdict_meaning
    vm = verdict_meaning(LABEL_REVIEW)
    rows = {r["Measure"]: r["Measured"] for r in vm["rows"]}

    def fmt(rate, k, n, lo, hi, r3=""):
        s = f"{100 * float(rate):.1f}% ({k}/{n}; 95% CI {100 * float(lo):.1f}%-{100 * float(hi):.1f}%)"
        return s + (f"; rule of three: at most {100 * float(r3):.1f}%" if r3 else "")

    rec_ = {(r["operating_point"], r["run"]): r for r in _csv("recall.csv")}
    for op, label in (("strict", "Known-bad strict recall (high-risk or known-malicious finding)"),
                      ("lenient", "Known-bad lenient recall (review-tier finding or above)")):
        r = rec_[(op, "headline")]
        assert rows[label] == fmt(r["recall"], r["hits"], r["n"], r["ci_low"], r["ci_high"])
    art = {(r["set"], r["kind"]): r for r in _csv("false_positives_rates.csv")}
    for kind, label in (("soft", "Random known-good: soft false positives (Review recommended)"),
                        ("hard", "Random known-good: hard false positives (high-risk / DO NOT USE)")):
        r = art[("known_good", kind)]
        assert rows[label] == fmt(r["rate"], r["fp"], r["n"], r["ci_low"], r["ci_high"], r["rule_of_three"])
    repo = {(r["set"], r["kind"]): r for r in _csv("repo_mode_false_positives.csv")}
    for s, name in (("known_good", "maintained (random known-good)"), ("scary", "scary-but-legitimate (hand-picked)"),
                    ("dormant", "dormant / finished libraries")):
        for kind in ("soft", "hard"):
            r = repo[(s, kind)]
            assert rows[f"{name}: {kind} false positives"] == fmt(r["rate"], r["fp"], r["n"], r["ci_low"], r["ci_high"], r["rule_of_three"])
    assert rows["Known-bad recall"].startswith("not measured")
    assert "repository mode" in vm["mode_note"] and "repository-mode known-bad recall is not measured" in vm["mode_note"]
    # the same strings appear in the committed RESULTS.md (generated from the same files)
    results = (ROOT / "benchmark" / "RESULTS.md").read_text(encoding="utf-8")
    for v in rows.values():
        assert v.startswith("not measured") or v in results, v
    nf = verdict_meaning(LABEL_NO_FINDINGS)
    r = rec_[("lenient", "headline")]
    k, n = int(r["n"]) - int(r["hits"]), int(r["n"])
    assert nf["extra"] == f"In artifact mode, {k} of {n} known-bad samples ({100 * k / n:.1f}%) also had no review-tier or high-risk finding."
    assert "not evidence that the package is harmless" in nf["meaning"]


def test_verdict_meaning_without_result_files(tmp_path):
    from verdict_meaning import verdict_meaning
    vm = verdict_meaning("Review recommended", tmp_path)
    assert vm["available"] is False and vm["rows"] == [] and "not available" in vm["meaning"]


# ------------------------------------------------------------------ evidence receipt

def test_app_version_from_git_folder(tmp_path):
    from ui_text import app_version
    sha = "a" * 40
    g = tmp_path / ".git"
    (g / "refs" / "heads").mkdir(parents=True)
    (g / "HEAD").write_text("ref: refs/heads/main\n")
    (g / "refs" / "heads" / "main").write_text(sha + "\n")
    assert app_version(str(tmp_path)) == {"git_sha": sha, "source": ".git (refs/heads/main)"}
    (g / "refs" / "heads" / "main").unlink()
    (g / "packed-refs").write_text(f"# pack-refs with: peeled\n{'b' * 40} refs/heads/main\n")
    assert app_version(str(tmp_path))["git_sha"] == "b" * 40
    (g / "HEAD").write_text("c" * 40)
    assert app_version(str(tmp_path)) == {"git_sha": "c" * 40, "source": ".git/HEAD (detached)"}
    assert app_version(str(tmp_path / "nowhere"))["git_sha"] is None


def test_evidence_receipt_and_download():
    from ui_text import evidence_receipt, result_json
    data = {"features": {"full_name": "o/r", "default_branch": "main", "fetched_at": "2026-11-10T00:00:00+00:00"},
            "scan": {"commit_sha": "0e322af"}}
    app_ver = {"git_sha": "d" * 40, "source": ".git (refs/heads/ui-polish)"}
    r = evidence_receipt(data, "2026.11.08-12", app_ver, "0e322af" + "1" * 33, "2026-11-10T04:00:00+00:00")
    assert r["scanned_commit"]["sha"] == "0e322af" + "1" * 33 and r["scanned_commit"]["full_sha_resolved"]
    assert (r["default_branch"], r["ruleset_version"], r["app_version"], r["receipt_generated_at_utc"]) == \
        ("main", "2026.11.08-12", app_ver, "2026-11-10T04:00:00+00:00")
    r2 = evidence_receipt(data, "2026.11.08-12", app_ver, None, "t")
    assert r2["scanned_commit"]["sha"] == "0e322af" and not r2["scanned_commit"]["full_sha_resolved"]
    r3 = evidence_receipt({"features": {}, "scan": {}}, "2026.11.08-12", app_ver, None, "t")
    assert r3["scanned_commit"]["sha"] is None and "did not download" in r3["scanned_commit"]["note"]
    out = json.loads(result_json({**data, "receipt": r}, ["ghp_tok"]))
    assert out["receipt"]["scanned_commit"]["short_sha_from_archive"] == "0e322af"


# ------------------------------------------------------------------ the app

def test_app_shows_the_panels_without_changing_the_score():
    import streamlit as st
    from streamlit.testing.v1 import AppTest
    import test_app as T
    from github_client import GitHubClient
    APP = str(ROOT / "app.py")
    table = {NPM_NODE_IPC: rec("npm_node-ipc.json"), RDAP_DIGINOW: NOT_FOUND_AT_REGISTRY}
    real_collect = AS.collect

    def collect_recorded(eco, name, scanned, fetch):
        return real_collect("npm", "node-ipc", scanned, fetcher(table))

    st.cache_data.clear()
    with patch("github_client.fetch_features", T.fake_fetch), patch.object(GitHubClient, "__init__", T._fake_init):
        at = AppTest.from_file(APP, default_timeout=30).run()
        at.text_input(key="repo_input").set_value("o/r-signals-base")
        at.button[0].click().run()
        base_md = [m.value for m in at.markdown]
        st.cache_data.clear()
        with patch.object(AS, "collect", collect_recorded):
            at2 = AppTest.from_file(APP, default_timeout=30).run()
            at2.text_input(key="repo_input").set_value("o/r-signals-base")
            at2.button[0].click().run()
        assert not at2.exception, at2.exception
        md = [m.value for m in at2.markdown]
        assert f"#### {AS.PANEL_TITLE}" in md
        assert "##### What this verdict meant in the benchmark" in md
        frames = [df.value for df in at2.dataframe]
        dom = next(f for f in frames if "Domain checked" in f.columns)
        assert list(dom["Domain checked"]) == ["diginow.it"] and list(dom["Flag"]) == [AS.FLAG_NOT_REGISTERED]
        assert any("Takeover-risk indicator, not proof" in w.value for w in at2.warning)
        assert any(list(f.columns) == ["Mode", "Measure", "Measured"] for f in frames)
        # the Trust score card and the verdict are identical with and without the signals
        card = lambda ms: [m for m in ms if "rh-card" in m]                           # noqa: E731
        assert card(md) == card(base_md) and card(md)
        assert [e.value for e in at2.error] == [e.value for e in at.error]
    st.cache_data.clear()
