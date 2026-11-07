"""Small on-disk HTTP cache for registry and GitHub API responses, so benchmarks are reproducible and rate limits
are respected.

Key = sha256(method + URL + snapshot date). The snapshot date is today's UTC date, or REPOHEALTH_SNAPSHOT
(YYYY-MM-DD) to replay an earlier run. JSON responses (status 200 and 404) and binary downloads are cached under
REPOHEALTH_CACHE (default .cache/http). Other statuses and network errors are never cached.

REPOHEALTH_OFFLINE=1 serves only from the cache (a miss is an error "offline: not cached").
GITHUB_TOKEN is sent only to api.github.com and is never part of the cache key or the stored data.
A polite minimum interval is kept between requests to the same host.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

TIMEOUT = 20
MIN_INTERVAL_S = {"api.github.com": 0.25, "pypi.org": 0.1, "registry.npmjs.org": 0.1}
DEFAULT_INTERVAL_S = 0.1
_last: dict[str, float] = {}
_lock = threading.Lock()


def cache_dir() -> str:
    return os.getenv("REPOHEALTH_CACHE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache", "http")


def snapshot() -> str:
    return os.getenv("REPOHEALTH_SNAPSHOT") or datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _path(url: str, kind: str) -> str:
    key = hashlib.sha256(f"GET {url} {snapshot()}".encode()).hexdigest()
    return os.path.join(cache_dir(), snapshot(), f"{key}.{kind}")


def _polite(url: str):
    host = urlparse(url).hostname or ""
    gap = MIN_INTERVAL_S.get(host, DEFAULT_INTERVAL_S)
    with _lock:
        wait = _last.get(host, 0) + gap - time.monotonic()
        _last[host] = time.monotonic() + max(0.0, wait)
    if wait > 0:
        time.sleep(wait)


def _headers(url: str, extra: dict | None) -> dict:
    h = {"User-Agent": "repo-health-predictor (static analysis research tool)"}
    if (urlparse(url).hostname or "") == "api.github.com":
        h["Accept"] = "application/vnd.github+json"
        tok = os.getenv("GITHUB_TOKEN")
        if tok:
            h["Authorization"] = f"Bearer {tok}"
    h.update(extra or {})
    return h


def get_json(url: str, headers: dict | None = None, timeout: float = TIMEOUT) -> tuple[object | None, int | None, str | None]:
    """Returns (data, status, error). data is None unless status == 200."""
    p = _path(url, "json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            rec = json.load(fh)
        return rec["data"], rec["status"], None
    if os.getenv("REPOHEALTH_OFFLINE") == "1":
        return None, None, "offline: not cached"
    _polite(url)
    try:
        r = requests.get(url, headers=_headers(url, headers), timeout=timeout)
    except requests.Timeout:
        return None, None, "timeout"
    except requests.RequestException as e:
        return None, None, type(e).__name__
    if r.status_code not in (200, 404):
        return None, r.status_code, f"HTTP {r.status_code}"
    data = None
    if r.status_code == 200:
        try:
            data = r.json()
        except ValueError:
            return None, 200, "bad JSON"
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"url": url, "status": r.status_code, "data": data}, fh)
    os.replace(tmp, p)
    return data, r.status_code, None


def get_bytes(url: str, max_bytes: int, timeout: float = 60) -> tuple[bytes | None, str | None]:
    """Download at most max_bytes. Returns (content, error). Oversize downloads are aborted, not truncated."""
    p = _path(url, "bin")
    if os.path.exists(p):
        with open(p, "rb") as fh:
            return fh.read(), None
    if os.getenv("REPOHEALTH_OFFLINE") == "1":
        return None, "offline: not cached"
    _polite(url)
    try:
        with requests.get(url, headers=_headers(url, None), stream=True, timeout=(15, timeout)) as r:
            if r.status_code != 200:
                return None, f"HTTP {r.status_code}"
            if int(r.headers.get("Content-Length") or 0) > max_bytes:
                return None, "too large"
            buf, total = bytearray(), 0
            for chunk in r.iter_content(1 << 16):
                total += len(chunk)
                if total > max_bytes:
                    return None, "too large"
                buf += chunk
    except requests.Timeout:
        return None, "timeout"
    except requests.RequestException as e:
        return None, type(e).__name__
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p + ".tmp", "wb") as fh:
        fh.write(bytes(buf))
    os.replace(p + ".tmp", p)
    return bytes(buf), None
