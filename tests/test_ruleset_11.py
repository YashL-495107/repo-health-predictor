"""Ruleset 2026.11.08-11 (structural fixes from the dev repo-mode run). Every fix: a positive and a benign case.
All inputs are synthetic inert text; nothing is executed. Network addresses use documentation ranges."""
from __future__ import annotations

import sys
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "benchmark")]

import releases  # noqa: E402
import repo_behavior  # noqa: E402
import security  # noqa: E402
from detectors import downgrade_non_shipping, make_result, release_delta, revival_takeover, tagless_release  # noqa: E402
from detectors.context import DetectorContext  # noqa: E402
from detectors.paths import non_shipping  # noqa: E402
from release_helpers import history, npm_release, pypi_release, with_git  # noqa: E402

STEALER = "import os\ncreds = open(os.path.expanduser('~/.aws/credentials')).read()\nURL = 'https://discord.com/api/webhooks/1/x'\n"


def behavior(files: dict[str, str]) -> list[dict]:
    return repo_behavior.scan_behavior({"text": files, "binaries": []}, "demo", lambda f, l: None)["findings"]


# ------------------------------------------------------------------ 1. legacy regex rules: code/script files only

@pytest.mark.parametrize("path", ["pkg/collect.py", "bin/run.sh", "lib/x.js", "src/x.ts", "tools.ps1", "a.bat", "x.rb", "x.php", "main.go"])
def test_1_code_files_still_scanned(path):
    fs = behavior({path: STEALER})
    assert any(f["rule"] == "Credential-stealer pattern" for f in fs), path


def test_1_extensionless_script_with_shebang_is_code():
    assert any(f["rule"] == "Credential-stealer pattern" for f in behavior({"bin/tool": "#!/bin/sh\n" + STEALER}))
    assert behavior({"LICENSE": STEALER}) == []


@pytest.mark.parametrize("path", ["config/hosts.yml", "deploy.yaml", "wordlists/creds.txt", "NOTES.md", "data.json",
                                  "pyproject.toml", "setup.cfg", "app.ini", "lists/paths.lst", "x.yar", "fw.rules"])
def test_1_data_and_config_text_not_scanned(path):
    assert behavior({path: STEALER}) == [], path


def test_1_ci_workflows_keep_their_detector():
    import repo_scan
    import run_benchmark as RB
    data = RB.data_from_contents({"text": {".github/workflows/ci.yml": "on: push\npermissions: write-all\n"},
                                  "binaries": [], "skipped": []})
    res = repo_scan.scan_data(RB._empty_scan(), data, "o", "r", lambda f, l: None, bandit_enabled=False)
    ci = next(d for d in res["detectors"] if d["detector"] == "ci_workflow")
    assert ci["status"] == "ran" and any("write-all" in f["rule"] for f in ci["findings"])


# ------------------------------------------------------------------ 2. test files recognised by filename

@pytest.mark.parametrize("path", ["pkg/server_test.go", "src/util_test.py", "test_api.py", "pkg/test_api.py",
                                  "src/a.test.js", "src/a.test.ts", "web/b.spec.ts", "web/b.spec.js", "conftest.py",
                                  "src/c.spec.tsx", "lib/d.test.mjs"])
def test_2_test_files_by_name_are_non_shipping(path):
    assert non_shipping(path) and "test file" in non_shipping(path)


@pytest.mark.parametrize("path", ["src/latest.py", "src/contest.py", "src/testing_utils.py", "src/attest.js",
                                  "src/specs.js", "src/test.py", "src/protest_test_helper.py.bak", ".github/test_x.py"])
def test_2_ordinary_files_are_shipping(path):
    assert non_shipping(path) is None


def test_2_review_in_test_file_becomes_info_high_risk_does_not():
    f_rev = {"tier": "review", "file": "pkg/server_test.go", "rule": "r"}
    f_hr = {"tier": "high_risk", "file": "pkg/server_test.go", "rule": "h"}
    out = downgrade_non_shipping(make_result("behavior_patterns", "Behavior", "ran", [f_rev, f_hr]))
    assert [f["tier"] for f in out["findings"]] == ["high_risk"] and out["info_findings"][0]["file"] == "pkg/server_test.go"


# ------------------------------------------------------------------ 3. release selection

def _entries(pairs):
    return [(v, t) for v, t in pairs]


def test_3_axios_style_backport_compared_with_its_own_major_line():
    order, meta = releases.select_window(_entries([
        ("0.33.0", "2026-05-01T00:00:00Z"), ("1.20.0", "2026-08-01T00:00:00Z"), ("0.34.0", "2026-09-16T00:00:00Z"),
        ("1.21.0", "2026-10-20T00:00:00Z"), ("0.35.0", "2026-11-03T00:00:00Z")]), 5, None, "npm")
    assert order[:2] == ["0.35.0", "0.34.0"] and meta["chronological_previous"] == "1.21.0"
    assert meta["predecessor_rule"] == "version order, same major line"


def test_3_prereleases_skipped_when_a_stable_exists():
    order, _ = releases.select_window(_entries([("0.27.0", "2025-01-01T00:00:00Z"), ("0.28.1", "2025-06-01T00:00:00Z"),
                                                ("1.0.dev6", "2026-10-01T00:00:00Z")]), 5, None, "PyPI")
    assert order[:2] == ["0.28.1", "0.27.0"] and "1.0.dev6" not in order      # later pre-release outside the window
    order, _ = releases.select_window(_entries([("2.0.0", "2025-01-01T00:00:00Z"), ("2.1.0-beta.1", "2026-01-01T00:00:00Z")]),
                                      5, None, "npm")
    assert order[0] == "2.0.0"


def test_3_only_prereleases_and_fallbacks():
    order, meta = releases.select_window(_entries([("1.0.0-rc.1", "2025-01-01T00:00:00Z"), ("1.0.0-rc.2", "2025-02-01T00:00:00Z")]),
                                         5, None, "npm")
    assert order == ["1.0.0-rc.2", "1.0.0-rc.1"]
    order, meta = releases.select_window(_entries([("2.5.0", "2025-01-01T00:00:00Z"), ("3.0.0", "2025-02-01T00:00:00Z")]),
                                         5, None, "npm")
    assert order == ["3.0.0", "2.5.0"] and meta["predecessor_rule"].startswith("chronological")


def test_3_ordinary_linear_history_unchanged():
    pairs = [(f"1.{i}.0", f"2026-0{i + 1}-01T00:00:00Z") for i in range(6)]
    order, _ = releases.select_window(_entries(pairs), 5, None, "npm")
    assert order == ["1.5.0", "1.4.0", "1.3.0", "1.2.0", "1.1.0"]


def test_3_replay_mode_keeps_the_target_and_ignores_later_releases():
    order, _ = releases.select_window(_entries([("1.0.0", "2025-01-01T00:00:00Z"), ("1.1.0", "2025-02-01T00:00:00Z"),
                                                ("1.2.0", "2025-03-01T00:00:00Z")]), 5, "1.1.0", "npm")
    assert order == ["1.1.0", "1.0.0"]


def test_3_parse_npm_and_pypi_apply_the_selection():
    pk = {"time": {"0.34.0": "2026-09-16T00:00:00Z", "1.21.0": "2026-10-20T00:00:00Z", "0.35.0": "2026-11-03T00:00:00Z"},
          "versions": {v: {"dist": {"tarball": f"https://r.example/axios-{v}.tgz"}} for v in ("0.34.0", "1.21.0", "0.35.0")}}
    rels, _ = releases.parse_npm(pk, 5)
    assert [r["version"] for r in rels] == ["0.35.0", "0.34.0", "1.21.0"]
    proj = {"releases": {v: [{"filename": f"d-{v}.tar.gz", "url": "u", "packagetype": "sdist", "upload_time_iso_8601": t}]
                         for v, t in (("1.0", "2025-01-01T00:00:00Z"), ("1.1", "2025-02-01T00:00:00Z"), ("2.0b1", "2025-03-01T00:00:00Z"))}}
    assert [r["version"] for r in releases.parse_pypi(proj, 5)] == ["1.1", "1.0"]


PROC_JS = "const cp = require('child_process');\ncp.execSync('openssl version');\n"


def _axios_like(old_has_proc: bool):
    n = npm_release("0.35.0", "2026-11-03T00:00:00Z", files={"bin/ssl_hotfix.js": PROC_JS})
    pred = npm_release("0.34.0", "2026-09-16T00:00:00Z", files={"bin/ssl_hotfix.js": PROC_JS} if old_has_proc else {})
    other = npm_release("1.21.0", "2026-10-20T00:00:00Z")
    n["selection"] = {"n_version": "0.35.0", "predecessor": "0.34.0", "predecessor_rule": "version order, same major line",
                      "chronological_previous": "1.21.0"}
    return history([n, pred, other])


def test_3_release_delta_benign_capability_already_in_predecessor():
    r = release_delta.detect(DetectorContext.build(releases=_axios_like(old_has_proc=True)))
    assert r["findings"] == []                                   # before: "adds process execution absent from 1.21.0"


def test_3_release_delta_positive_capability_new_in_its_line():
    r = release_delta.detect(DetectorContext.build(releases=_axios_like(old_has_proc=False)))
    assert [f["tier"] for f in r["findings"]] == ["review"] and "0.34.0" in r["findings"][0]["rule"]


def test_3_revival_keeps_the_chronological_previous_release():
    rc = _axios_like(old_has_proc=True)
    r = revival_takeover.detect(DetectorContext.build(releases=rc))
    assert not any("no release for" in str(f.get("detail")) for f in r["findings"])   # 0.34.0 is 48 days back, 1.21.0 14


# ------------------------------------------------------------------ 4. tagless_release: new capabilities only

NET_JS = "const https = require('https');\nhttps.get('https://198.51.100.7/p', () => {});\n"


def _tagless(new_files, prev_files=None, prev=True, prev_read=True):
    n = npm_release("1.2.0", "2026-03-01T00:00:00Z", files=new_files)
    rels = [n]
    if prev:
        p = npm_release("1.1.0", "2026-01-01T00:00:00Z", files=prev_files or {})
        if not prev_read:
            p["contents"], p["artifact_status"] = None, "too_large"
        rels.append(p)
    rc = with_git(history(rels), default_tree={"index.js"}, tags=["v1.2.0"], matched="v1.2.0", tag_tree={"index.js"})
    return tagless_release.detect(DetectorContext.build(releases=rc))


def test_4_positive_new_network_phantom_is_high_risk():
    r = _tagless({"lib/update-check.js": NET_JS}, prev_files={})
    assert [f["tier"] for f in r["findings"]] == ["high_risk"]


def test_4_benign_same_capability_in_predecessor_is_review():
    r = _tagless({"lib/update-check.js": NET_JS}, prev_files={"lib/update-check.js": NET_JS})
    assert [f["tier"] for f in r["findings"]] == ["review"] and "not new" in r["findings"][0]["rule"]


def test_4_predecessor_unread_cannot_show_newness_review():
    r = _tagless({"lib/update-check.js": NET_JS}, prev_read=False)
    assert [f["tier"] for f in r["findings"]] == ["review"] and "not read" in (r["coverage_detail"] or "")


def test_4_no_predecessor_everything_is_new():
    assert [f["tier"] for f in _tagless({"lib/update-check.js": NET_JS}, prev=False)["findings"]] == ["high_risk"]


def test_4_install_time_phantom_stays_high_risk_even_if_present_before():
    files = {"scripts/post.js": NET_JS}
    n = npm_release("1.2.0", "2026-03-01T00:00:00Z", files=files, scripts={"postinstall": "node scripts/post.js"})
    p = npm_release("1.1.0", "2026-01-01T00:00:00Z", files=files, scripts={"postinstall": "node scripts/post.js"})
    rc = with_git(history([n, p]), default_tree={"index.js"}, tags=["v1.2.0"], matched="v1.2.0", tag_tree={"index.js"})
    r = tagless_release.detect(DetectorContext.build(releases=rc))
    assert "high_risk" in [f["tier"] for f in r["findings"]]


@pytest.mark.parametrize("vf", ["demo/_version.py", "demo/__version__.py", "demo/version.py", "demo/pkg_version.py"])
def test_4_generated_version_files_capability_free_are_info(vf):
    n = pypi_release("2.0", "2026-03-01T00:00:00Z", files={vf: "__version__ = '2.0'\n"})
    rc = with_git(history([n], "PyPI"), default_tree={"demo/__init__.py"}, tags=["2.0"], matched="2.0")
    r = tagless_release.detect(DetectorContext.build(releases=rc))
    assert r["findings"] == [] and r["info_findings"][0]["file"] == vf


def test_4_version_file_with_network_is_not_info():
    n = pypi_release("2.0", "2026-03-01T00:00:00Z", files={"demo/_version.py": "import urllib.request\n"})
    rc = with_git(history([n], "PyPI"), default_tree={"demo/__init__.py"}, tags=["2.0"], matched="2.0")
    assert [f["tier"] for f in tagless_release.detect(DetectorContext.build(releases=rc))["findings"]] == ["high_risk"]


# ------------------------------------------------------------------ 5. dependency advisories: runtime only

@pytest.mark.parametrize("src, kw, scope", [
    ("requirements.txt", {}, "runtime"), ("requirements-dev.txt", {}, "dev"), ("docs/requirements.txt", {}, "dev"),
    ("test-requirements.txt", {}, "dev"), ("requirements/test.txt", {}, "dev"), ("requirements/docs.in", {}, "dev"),
    ("requirements/prod.txt", {}, "runtime"), ("package-lock.json", {"npm_dev": True}, "dev"),
    ("package-lock.json", {}, "runtime"), ("pyproject.toml", {"extra": "docs"}, "dev"),
    ("pyproject.toml", {"extra": "socks"}, "runtime"), ("requirements-latest.txt", {}, "runtime")])
def test_5_dependency_scope(src, kw, scope):
    assert security.dependency_scope(src, **kw) == scope


def test_5_lockfile_dev_flag_is_read():
    lock = '{"packages": {"": {}, "node_modules/a": {"version": "1.0.0"}, "node_modules/b": {"version": "2.0.0", "dev": true}}}'
    assert {d["name"]: d["scope"] for d in security.parse_package_lock(lock)} == {"a": "runtime", "b": "dev"}


def _assess(monkeypatch, deps, hits):
    monkeypatch.setattr(security, "repo_advisories", lambda c, o, r: [])
    monkeypatch.setattr(security, "collect_dependencies", lambda c, o, r: {"deps": deps, "unpinned": 0,
                                                                          "files": ["package-lock.json"], "truncated": False})
    monkeypatch.setattr(security, "osv_scan", lambda ds: hits)
    monkeypatch.setattr(security, "osv_details", lambda i: {"summary": "s", "fixed": []})
    monkeypatch.setattr(security, "_read_file", lambda c, o, r, f: None)
    monkeypatch.setattr(security, "scorecard", lambda o, r: None)
    return security.assess_security(None, "o", "r")


def test_5_positive_runtime_vulnerability_counts(monkeypatch):
    d = {"name": "a", "version": "1.0.0", "ecosystem": "npm", "scope": "runtime"}
    sec = _assess(monkeypatch, [d], [{**d, "ids": ["GHSA-x"], "is_mal": False}])
    assert sec["level"] == "Elevated" and [f["source"] for f in sec["findings"]] == ["OSV (dependency)"]


def test_5_benign_dev_only_vulnerability_is_info(monkeypatch):
    d = {"name": "b", "version": "2.0.0", "ecosystem": "npm", "scope": "dev"}
    sec = _assess(monkeypatch, [d] * 1, [{**d, "ids": ["GHSA-y"], "is_mal": False}] * 3)
    assert sec["level"] == "No unpatched issues found"
    assert {f["source"] for f in sec["findings"]} == {"OSV (dev dependency)"} and all(f["severity"] == "Info" for f in sec["findings"])
    assert sec["checks"]["osv_dependencies_detail"]["vulnerable_dev_only"] == 3


def test_5_malicious_dev_dependency_unchanged(monkeypatch):
    d = {"name": "evil", "version": "1.0.0", "ecosystem": "npm", "scope": "dev"}
    sec = _assess(monkeypatch, [d], [{**d, "ids": ["MAL-2026-1"], "is_mal": True}])
    assert sec["level"] == "High" and sec["findings"][0]["source"] == "OSV (Confirmed Malware)"


# ------------------------------------------------------------------ 6. hygiene

def test_6_syntax_warning_from_scanned_code_is_silenced_ours_is_not():
    from detectors import pyast
    bad = 'x = "\\ "\n'
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("default")
        import importlib
        importlib.reload(pyast)                                  # re-installs the module-level filter after "default"
        pyast.parse_ok("a.py", bad)
        compile(bad, "own_module.py", "exec")
    # invalid escape sequences: SyntaxWarning since Python 3.12, DeprecationWarning before
    msgs = [str(x.filename) for x in w if issubclass(x.category, (SyntaxWarning, DeprecationWarning))]
    assert msgs == ["own_module.py"]


def test_6_dev_set_deduplicated_by_id():
    import bench_items
    items, _ = bench_items.all_items()
    ids = [i["id"].lower() for i in items]
    assert len(ids) == len(set(ids))
    pip = [i for i in items if i["id"].lower() == "dev:pypa/pip"]
    assert len(pip) == 1 and pip[0]["package"] == "pip" and pip[0].get("also_in") == ["dev_credibility.csv"]
