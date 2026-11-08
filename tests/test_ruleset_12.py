"""Ruleset 2026.11.08-12: Windows-robust http_cache, full exception text in benchmark records, and requirements*.txt as
development pins when the project declares its own Python package. Synthetic inputs only; no network."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "benchmark")]

import http_cache  # noqa: E402
import run_benchmark as RB  # noqa: E402
import security  # noqa: E402

FIXTURE_CACHE = ROOT / "tests" / "fixtures" / "benchmark_http"
HASH_NAME = re.compile(r"^[0-9a-f]{64}\.(?:json|bin)$")


# ------------------------------------------------------------------ 1. http_cache on Windows

def _longest_fixture_urls(n=5) -> list[str]:
    """Every URL in the recorded fixtures: request URLs and the artifact / tarball URLs inside the registry data."""
    urls = set()

    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif isinstance(x, str) and x.startswith(("https://", "http://")):
            urls.add(x)
    for p in FIXTURE_CACHE.rglob("*.json"):
        try:
            walk(json.loads(p.read_text(encoding="utf-8")))
        except ValueError:
            pass
    return sorted(urls, key=len, reverse=True)[:n]


class _Resp:
    def __init__(self, url, body=b"x" * 2048):
        self.status_code, self._url, self._body = 200, url, body
        self.headers = {"Content-Length": str(len(body))}

    def json(self):
        return {"url": self._url, "n": 1}

    def iter_content(self, n):
        yield self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def cache(monkeypatch, tmp_path):
    for k in ("REPOHEALTH_CACHE", "REPOHEALTH_SNAPSHOT", "REPOHEALTH_OFFLINE"):
        monkeypatch.setenv(k, "x")
        monkeypatch.delenv(k)
    monkeypatch.setenv("REPOHEALTH_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("REPOHEALTH_SNAPSHOT", "2026-11-08")
    monkeypatch.setattr(http_cache, "_polite", lambda url: None)
    calls = []
    monkeypatch.setattr(http_cache.requests, "get", lambda url, **kw: calls.append(url) or _Resp(url))
    http_cache.CACHE_ERRORS.clear()
    return tmp_path / "cache", calls


def test_longest_fixture_urls_roundtrip_with_hash_only_names(cache):
    root, calls = cache
    urls = _longest_fixture_urls()
    assert urls and len(urls[0]) > 130                      # the recorded fixtures have long artifact URLs (143 chars)
    for u in urls:
        assert http_cache.get_json(u)[1] == 200 and http_cache.get_bytes(u + "#bin", 10_000)[1] is None
    n = len(calls)
    for u in urls:                                         # second pass: all from the cache
        assert http_cache.get_json(u)[0] == {"url": u, "n": 1}
        assert http_cache.get_bytes(u + "#bin", 10_000)[0] == b"x" * 2048
    assert len(calls) == n
    files = [p for p in root.rglob("*") if p.is_file()]
    assert files and all(HASH_NAME.match(p.name) for p in files)          # no URL text, no leftover temp files
    assert all(len(p.relative_to(root).as_posix()) <= len("2026-11-08/") + 64 + 5 for p in files)
    assert http_cache.CACHE_ERRORS == []


def test_failed_cache_write_never_fails_the_request(cache, monkeypatch):
    root, _ = cache

    def blocked(src, dst):
        raise OSError(22, "Invalid argument", dst)          # what an antivirus block looks like through the C runtime
    monkeypatch.setattr(http_cache.os, "replace", blocked)
    data, err = http_cache.get_bytes("https://files.example/impacket-0.13.1.tar.gz", 10_000)
    assert err is None and data == b"x" * 2048
    assert len(http_cache.CACHE_ERRORS) == 1 and "Invalid argument" in http_cache.CACHE_ERRORS[0]
    assert "cache write failed" in http_cache.CACHE_ERRORS[0]
    assert [p for p in root.rglob("*") if p.is_file()] == []                # the temp file was removed


def test_unreadable_cache_entry_is_a_miss(cache):
    root, calls = cache
    u = "https://pypi.org/pypi/x/json"
    http_cache.get_json(u)
    p = Path(http_cache._path(u, "json"))
    p.write_text("{not json", encoding="utf-8")
    assert http_cache.get_json(u)[0] == {"url": u, "n": 1} and len(calls) == 2
    assert any("cache read failed" in e for e in http_cache.CACHE_ERRORS)


@pytest.mark.skipif(os.name != "nt", reason="MAX_PATH applies to Windows only")
def test_windows_paths_beyond_max_path(cache, monkeypatch, tmp_path):
    deep = tmp_path / ("d" * 60) / ("e" * 60) / ("f" * 60) / "cache"
    monkeypatch.setenv("REPOHEALTH_CACHE", str(deep))
    u = _longest_fixture_urls(1)[0]
    assert len(http_cache._path(u, "json")) > 260
    assert http_cache.get_json(u)[1] == 200 and http_cache.get_json(u)[0] == {"url": u, "n": 1}
    assert http_cache.CACHE_ERRORS == []


def test_exception_record_keeps_the_full_text_and_traceback():
    long_msg = "x" * 500 + " END"
    try:
        raise OSError(22, long_msg, r"C:\bench\cache\http\2026-11-08\abc.bin")
    except OSError as e:
        rec = RB.exception_record(e)
    assert rec["status"] == "not_assessed" and rec["error"].endswith("abc.bin'") and "END" in rec["error"]
    assert "Traceback" in rec["traceback"] and "OSError" in rec["traceback"]
    assert rec["not_assessed_reason"] == "scan raised " + rec["error"]


def test_cache_errors_are_attached_to_the_item_record():
    http_cache.CACHE_ERRORS[:] = ["cache write failed for p: OSError: [Errno 22] Invalid argument"]
    rec = RB.with_cache_errors({"status": "scored", "limits_hit": []})
    assert rec["cache_errors"] and "cache read/write failure" in rec["limits_hit"][0] and http_cache.CACHE_ERRORS == []


# ------------------------------------------------------------------ 2. requirements*.txt are dev pins in a package

HTTPX_PYPROJECT = '[build-system]\nrequires = ["hatchling"]\n\n[project]\nname = "httpx"\ndependencies = ["certifi", "httpcore==1.*"]\n'
HTTPX_REQS = "# Documentation\nmkdocs-material==9.5.0\n# Packaging\ncryptography==41.0.0\n# Tests\npytest==8.0.0\n"


@pytest.mark.parametrize("manifests, expected", [
    ({"pyproject.toml": HTTPX_PYPROJECT}, True),
    ({"pyproject.toml": "[tool.poetry]\nname = 'x'\n"}, True),
    ({"setup.py": "from setuptools import setup\nsetup(name='x')\n"}, True),
    ({"setup.cfg": "[metadata]\nname = x\n"}, True),
    ({"pyproject.toml": "[tool.black]\nline-length = 100\n"}, False),     # tool config only: an application
    ({"setup.cfg": "[flake8]\nmax-line-length = 100\n"}, False),
    ({}, False)])
def test_declares_python_package(manifests, expected):
    assert security.declares_python_package(manifests) is expected


@pytest.mark.parametrize("src", ["requirements.txt", "docs/requirements.txt", "requirements/test.txt", "requirements-dev.txt"])
def test_requirements_files_are_dev_pins_in_a_package(src):
    assert security.dependency_scope(src, package_manifest=True) == "dev"


def test_application_root_requirements_stay_runtime():
    assert security.dependency_scope("requirements.txt", package_manifest=False) == "runtime"
    assert security.dependency_scope("requirements-dev.txt", package_manifest=False) == "dev"


def _repo(monkeypatch, files: dict[str, str]):
    monkeypatch.setattr(security, "_read_file", lambda c, o, r, f: files.get(f))
    monkeypatch.setattr(security, "repo_advisories", lambda c, o, r: [])
    monkeypatch.setattr(security, "scorecard", lambda o, r: None)
    monkeypatch.setattr(security, "check_own_package_malware", lambda pkg: ([], "Own package: checked", False))
    monkeypatch.setattr(security, "osv_details", lambda i: {"summary": "s", "fixed": []})
    # cryptography 41.0.0 has known advisories: the stubbed OSV answers for it only
    monkeypatch.setattr(security, "osv_scan", lambda deps: [{**d, "ids": ["GHSA-crypto"], "is_mal": False}
                                                           for d in deps if d["name"] == "cryptography"])
    return security.assess_security(None, "o", "r")


def test_httpx_like_layout_requirements_are_info_and_no_cap(monkeypatch):
    sec = _repo(monkeypatch, {"requirements.txt": HTTPX_REQS, "pyproject.toml": HTTPX_PYPROJECT})
    assert sec["level"] == "No unpatched issues found"                       # no 69 / 49 cap
    dep = [f for f in sec["findings"] if "OSV" in f["source"]]
    assert [(f["source"], f["severity"], f["item"]) for f in dep] == [("OSV (dev dependency)", "Info", "cryptography 41.0.0")]
    assert any("development pins" in c for c in sec["coverage"])


def test_application_like_layout_unchanged(monkeypatch):
    sec = _repo(monkeypatch, {"requirements.txt": HTTPX_REQS})
    assert sec["level"] == "Elevated"                                       # vulnerable runtime dependency: cap 69
    dep = [f for f in sec["findings"] if "OSV" in f["source"]]
    assert [(f["source"], f["severity"]) for f in dep] == [("OSV (dependency)", "Elevated")]
