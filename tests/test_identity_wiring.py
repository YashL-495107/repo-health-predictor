"""Ruleset 2026.11.08-10: the package/repository name reaches credential_exfiltration's name-relatedness checks in the
REAL pipeline (repo_scan.scan_data -> content-time detectors), in artifact mode and in repo mode alike.

Before, only features/security carried names, and they are absent at content-scan time, so the related-host check,
the credential-file owner map and the SSH client aliases never saw a name outside unit tests. All code here is
synthetic, inert text; nothing is executed."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "benchmark")]

import repo_scan  # noqa: E402
import run_benchmark as RB  # noqa: E402
from detectors import credential_exfiltration as CE  # noqa: E402
from detectors.context import DetectorContext  # noqa: E402

PARAMIKO_AGENT = (
    "import os, socket\n"
    "class AgentClientProxy:\n"
    "    def connect(self):\n"
    "        path = os.environ['SSH_AUTH_SOCK']\n"
    "        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
    "        conn.connect(path)\n"
    "        return conn\n")
BOTO_SESSION = (
    "import os, requests\n"
    "def refresh(region):\n"
    "    creds = open(os.path.expanduser('~/.aws/credentials')).read()\n"
    "    url = f'https://sts.{region}.amazonaws.com/'\n"
    "    return requests.post(url, data=creds)\n")
ACME_CLIENT = (
    "import os, requests\n"
    "def ping():\n"
    "    return requests.post('https://api.acmecloud.io/v1/ping', headers={'X': os.environ['ACMECLOUD_TOKEN']})\n")


def ce_findings(files: dict[str, str], identity: dict | None) -> list[dict]:
    data = RB.data_from_contents({"text": files, "binaries": [], "skipped": []})
    res = repo_scan.scan_data(RB._empty_scan(), data, "o", "r", lambda f, ln: None, bandit_enabled=False,
                              identity=identity)
    ce = next(d for d in res["detectors"] if d["detector"] == "credential_exfiltration")
    assert ce["status"] == "ran"
    return ce["findings"]


def art(eco, name, repo=None):
    return RB.artifact_identity(eco, name, repo)


# (a) paramiko-like artifact: the SSH client alias applies
def test_a_paramiko_like_artifact_not_flagged():
    files = {"paramiko/agent.py": PARAMIKO_AGENT}
    assert ce_findings(files, art("PyPI", "paramiko", "paramiko/paramiko")) == []
    assert ce_findings(files, art("PyPI", "paramiko")) == []                 # package name alone is enough


# (b) boto3-like artifact: its own ~/.aws/credentials, sent to a dynamically built amazonaws host
def test_b_boto3_like_artifact_not_flagged():
    files = {"boto3/session.py": BOTO_SESSION}
    assert ce_findings(files, art("PyPI", "boto3", "boto/boto3")) == []


# (c) the same code under an unrelated package name is still review
@pytest.mark.parametrize("files", [{"paramiko/agent.py": PARAMIKO_AGENT}, {"boto3/session.py": BOTO_SESSION},
                                   {"acme/client.py": ACME_CLIENT}])
def test_c_same_code_unrelated_name_still_review(files):
    fs = ce_findings(files, art("PyPI", "stats-helper"))
    assert [f["tier"] for f in fs] == ["review"]
    assert ce_findings(files, None) == fs                                    # no identity: unchanged (review)


def test_related_host_uses_the_package_name():
    assert ce_findings({"acme/client.py": ACME_CLIENT}, art("PyPI", "acmecloud")) == []
    assert ce_findings({"acme/client.py": ACME_CLIENT}, art("npm", "@acmecloud/sdk")) == []
    assert ce_findings({"acme/client.py": ACME_CLIENT}, {"repo": "acme-inc/acmecloud-python", "package": None}) == []


# (d) PyPI / npm name normalisation: case and - _ .
@pytest.mark.parametrize("name", ["paramiko", "Paramiko", "PARAMIKO"])
def test_d_case_insensitive_names(name):
    assert ce_findings({"paramiko/agent.py": PARAMIKO_AGENT}, art("PyPI", name)) == []


@pytest.mark.parametrize("name", ["docker-py", "docker_py", "docker.py", "Docker-Py", "DOCKER_PY"])
def test_d_separators_normalise_to_the_same_tokens(name):
    toks = CE.owner_tokens(DetectorContext.build(identity=art("PyPI", name)))
    assert {"docker", "dockerpy", "py"} <= toks


@pytest.mark.parametrize("name", ["Boto3", "boto3", "BOTO3"])
def test_d_boto3_case(name):
    assert ce_findings({"boto3/session.py": BOTO_SESSION}, art("PyPI", name)) == []


def test_d_npm_scoped_name_tokens():
    toks = CE.related_tokens(DetectorContext.build(identity=art("npm", "@acmecloud/node-sdk")))
    assert "acmecloud" in toks


# repo mode sees the same names: repository + root manifest
def test_repo_mode_identity_from_root_manifest_matches_artifact_mode():
    files = {"setup.py": "from setuptools import setup\nsetup(name='paramiko')\n", "paramiko/agent.py": PARAMIKO_AGENT}
    data = RB.data_from_contents({"text": files, "binaries": [], "skipped": []})
    ident = repo_scan.repo_identity("paramiko", "paramiko", data)
    assert ident["repo"] == "paramiko/paramiko" and ident["package"] == {"ecosystem": "PyPI", "name": "paramiko"}
    assert ce_findings(files, ident) == ce_findings(files, art("PyPI", "paramiko", "paramiko/paramiko")) == []


def test_identity_is_recorded_on_the_scan_result():
    data = RB.data_from_contents({"text": {"a.py": "x = 1\n"}, "binaries": [], "skipped": []})
    res = repo_scan.scan_data(RB._empty_scan(), data, "o", "r", lambda f, ln: None, bandit_enabled=False,
                              identity=art("npm", "mitt", "developit/mitt"))
    assert res["identity"]["package"]["name"] == "mitt" and res["identity"]["repo"] == "developit/mitt"


def test_github_slug():
    assert RB.github_slug("git+https://github.com/paramiko/paramiko.git") == "paramiko/paramiko"
    assert RB.github_slug("https://github.com/boto/boto3/tree/develop") == "boto/boto3"
    assert RB.github_slug("https://gitlab.com/x/y") is None
