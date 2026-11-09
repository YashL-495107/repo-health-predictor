"""Small on-disk HTTP cache for registry and GitHub API responses, so benchmarks are reproducible and rate limits
are respected.

Key = sha256(method + URL + snapshot date). The snapshot date is today's UTC date, or REPOHEALTH_SNAPSHOT
(YYYY-MM-DD) to replay an earlier run. JSON responses (status 200 and 404) and binary downloads are cached under
REPOHEALTH_CACHE (default .cache/http). Other statuses and network errors are never cached.

REPOHEALTH_OFFLINE=1 serves only from the cache (a miss is an error "offline: not cached").
GITHUB_TOKEN is sent only to api.github.com and is never part of the cache key or the stored data.
A polite minimum interval is kept between requests to the same host. Concurrency: the interval bookkeeping is
locked, and each write goes to its own short temp file before an atomic rename (parallel scan stages share the cache).
File names are hash-only; on Windows, paths near MAX_PATH use the long-path form. A cache read or write that fails
(antivirus block, permissions) never fails the request: the entry is a miss / is not stored, and the full error text
is appended to CACHE_ERRORS (the benchmark records it per item).

parallel(): helper used by the scan stages; REPOHEALTH_SEQUENTIAL=1 runs everything in order (for timing
comparisons and debugging).
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
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


def sequential() -> bool:
    return os.getenv("REPOHEALTH_SEQUENTIAL") == "1"


def parallel(fn, items, workers: int = 4) -> list:
    """[fn(x) for x in items], in parallel threads unless REPOHEALTH_SEQUENTIAL=1. Order is kept; exceptions are
    re-raised in the caller like the sequential version would."""
    items = list(items)
    if sequential() or len(items) <= 1:
        return [fn(x) for x in items]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool:
        return list(pool.map(fn, items))


def cache_dir() -> str:
    return os.getenv("REPOHEALTH_CACHE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache", "http")


def snapshot() -> str:
    return os.getenv("REPOHEALTH_SNAPSHOT") or datetime.now(timezone.utc).strftime("%Y-%m-%d")


CACHE_ERRORS: list[str] = []   # full text of cache read/write failures in this process (the benchmark records them)
WIN_LONG_PATH = 240             # below Windows' 260-character MAX_PATH, with room for the temp suffix


def _path(url: str, kind: str) -> str:
    """Hash-only file name (64 hex characters + .json/.bin): the URL never appears in a path, so no illegal
    characters, trailing dots or spaces, whatever the URL is."""
    key = hashlib.sha256(f"GET {url} {snapshot()}".encode()).hexdigest()
    return os.path.join(cache_dir(), snapshot(), f"{key}.{kind}")


def _fs(path: str) -> str:
    """Windows: long-path form (\\\\?\\...) for absolute paths near MAX_PATH, so a deep checkout still works."""
    if os.name == "nt":
        full = os.path.abspath(path)
        if len(full) >= WIN_LONG_PATH and not full.startswith("\\\\?\\"):
            return "\\\\?\\" + full
        return full
    return path


def _note(what: str, path: str, e: BaseException) -> None:
    msg = f"cache {what} failed for {path}: {type(e).__name__}: {e}"
    if getattr(e, "winerror", None) is not None:
        msg += f" (winerror {e.winerror})"
    with _lock:
        CACHE_ERRORS.append(msg)


def _read(p: str, binary: bool):
    """Cached content, or None (missing or unreadable: an unreadable entry is a cache miss, recorded)."""
    fp = _fs(p)
    if not os.path.exists(fp):
        return None
    try:
        if binary:
            with open(fp, "rb") as fh:
                return fh.read()
        with open(fp, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as e:
        _note("read", p, e)
        return None


def _write(p: str, payload: bytes) -> bool:
    """Atomic write through a short temp name in the same folder. A failure (antivirus block, permissions, path
    limits) never fails the request: the fetched data is still used, and the full error is recorded."""
    fp = _fs(p)
    tmp = os.path.join(os.path.dirname(fp), f".{os.path.basename(p)[:12]}{secrets.token_hex(4)}.tmp")
    try:
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(tmp, "wb") as fh:
            fh.write(payload)
        os.replace(tmp, fp)
        return True
    except OSError as e:
        _note("write", p, e)
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


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
    rec = _read(p, binary=False)
    if isinstance(rec, dict) and "status" in rec:
        return rec.get("data"), rec["status"], None
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
    _write(p, json.dumps({"url": url, "status": r.status_code, "data": data}).encode("utf-8"))
    return data, r.status_code, None


def get_bytes(url: str, max_bytes: int, timeout: float = 60) -> tuple[bytes | None, str | None]:
    """Download at most max_bytes. Returns (content, error). Oversize downloads are aborted, not truncated."""
    p = _path(url, "bin")
    cached = _read(p, binary=True)
    if cached is not None:
        return cached, None
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
    _write(p, bytes(buf))
    return bytes(buf), None
