"""`python benchmark/run_benchmark.py --selfcheck`: is this machine ready for the benchmark? Under 2 minutes, and it
never touches the test split (the three scan checks use DEV items only and a throw-away cache).

Prints PASS / FAIL per check with a one-line fix. Exit code 0 only when every check passed.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HOST_TIMEOUT_S = 15
ITEM_BUDGET_S = 90
MIN_FREE_GB = 2.0


def _http(method: str, url: str, **kw):
    import requests
    return requests.request(method, url, timeout=HOST_TIMEOUT_S,
                            headers={"User-Agent": "repo-health-predictor selfcheck", **kw.pop("headers", {})}, **kw)


def host_checks() -> list[tuple]:
    """(name, ok, detail, fix) per required host."""
    token = os.environ.get("GITHUB_TOKEN")
    checks = [
        ("PyPI JSON API (pypi.org)", "GET", "https://pypi.org/pypi/pip/json", {}, (200,),
         "allow https://pypi.org (proxy / firewall)"),
        ("PyPI files (files.pythonhosted.org)", "HEAD", "https://files.pythonhosted.org/", {}, (200, 301, 302, 403, 404),
         "allow https://files.pythonhosted.org (artifact downloads)"),
        ("npm registry (registry.npmjs.org)", "GET", "https://registry.npmjs.org/is-number", {}, (200,),
         "allow https://registry.npmjs.org"),
        ("GitHub API without token", "GET", "https://api.github.com/rate_limit", {}, (200,),
         "allow https://api.github.com"),
        ("GitHub repository download (codeload.github.com)", "HEAD",
         "https://codeload.github.com/pypa/twine/zip/refs/heads/main", {}, (200, 302),
         "allow https://codeload.github.com (repo-mode ZIP downloads)"),
        ("OSV bulk export (storage.googleapis.com)", "HEAD",
         "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip", {}, (200,),
         "allow https://osv-vulnerabilities.storage.googleapis.com (or copy benchmark/cache/osv_mal_*.json)"),
        ("OSV API (api.osv.dev)", "POST", "https://api.osv.dev/v1/query",
         {"json": {"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.4.1"}}, (200,),
         "allow https://api.osv.dev (repo-mode dependency advisories)"),
        ("deps.dev API (api.deps.dev)", "GET", "https://api.deps.dev/v3/systems/pypi/packages/requests", {}, (200,),
         "allow https://api.deps.dev (dependent counts; optional: without it those values are not assessed)"),
    ]

    def one(c):
        name, method, url, kw, ok_codes, fix = c
        try:
            r = _http(method, url, **kw)
            ok = r.status_code in ok_codes
            detail = f"HTTP {r.status_code}"
            if "rate_limit" in url and ok:
                rate = r.json()["rate"]
                detail += f", limit {rate['limit']}/hour, {rate['remaining']} left (60 = unauthenticated)"
            return (name, ok, detail, fix)
        except Exception as e:
            return (name, False, f"{type(e).__name__}: {str(e)[:120]}", fix)

    with ThreadPoolExecutor(max_workers=8) as pool:
        out = list(pool.map(one, checks))
    if token:
        try:
            r = _http("GET", "https://api.github.com/rate_limit", headers={"Authorization": f"Bearer {token}"})
            ok = r.status_code == 200 and r.json()["rate"]["limit"] >= 5000
            out.append(("GitHub API with GITHUB_TOKEN", ok,
                        f"HTTP {r.status_code}" + (f", limit {r.json()['rate']['limit']}, {r.json()['rate']['remaining']} left"
                                                   if r.status_code == 200 else ""),
                        "check the token (classic or fine-grained, public read access is enough) and that it is not expired"))
        except Exception as e:
            out.append(("GitHub API with GITHUB_TOKEN", False, f"{type(e).__name__}", "allow https://api.github.com"))
    else:
        out.append(("GitHub API with GITHUB_TOKEN", False, "GITHUB_TOKEN is not set",
                    'set it for repo mode: $env:GITHUB_TOKEN = "<token>" (60 requests/hour without it)'))
    return out


def local_checks(samples_dir: Path, cache_dir: Path) -> list[tuple]:
    import bench_items
    import run_benchmark as RB
    out = []
    try:
        RB.assert_ai_off()
        out.append(("AI layer off (no Gemini key, no AI module)", True, "ok", ""))
    except RB.GuardError as e:
        out.append(("AI layer off (no Gemini key, no AI module)", False, str(e)[:120], "Remove-Item Env:GEMINI_API_KEY"))
    try:
        v = RB.check_frozen("test")
        out.append(("Frozen ruleset recorded in the protocol", True, v, ""))
    except RB.GuardError as e:
        out.append(("Frozen ruleset recorded in the protocol", False, str(e)[:120], "do not run the test split; report it"))
    try:
        items, moves = bench_items.all_items()
        out.append(("Dev manifest present, overlap check", True, f"{len(items)} items, {len(moves)} moved to dev", ""))
    except SystemExit as e:
        out.append(("Dev manifest present, overlap check", False, str(e)[:120], "add benchmark/manifests/dev_credibility.csv"))
    for name, d in (("samples", samples_dir), ("cache", cache_dir)):
        try:
            d.mkdir(parents=True, exist_ok=True)
            free = shutil.disk_usage(d).free / 1e9
            out.append((f"Disk space ({name} folder)", free >= MIN_FREE_GB, f"{free:.1f} GB free at {d}",
                        f"free at least {MIN_FREE_GB:.0f} GB or point --samples-dir / REPOHEALTH_CACHE elsewhere"))
        except OSError as e:
            out.append((f"Disk space ({name} folder)", False, f"{type(e).__name__}", "create the folder or pick another"))
    try:
        probe = samples_dir / f".write-test-{uuid.uuid4().hex}.sample"
        probe.write_text("probe", encoding="utf-8")
        probe.unlink()
        out.append(("Samples folder writable", True, str(samples_dir), ""))
    except OSError as e:
        out.append(("Samples folder writable", False, f"{type(e).__name__}: {e}"[:120],
                    "use --samples-dir with a folder you own (not Downloads, not a synced folder)"))
    return out


def dev_items() -> list[tuple[str, str, dict]]:
    """(check name, mode, item): one dev repo-mode item, one dev npm artifact item, one dev PyPI artifact item."""
    import bench_items
    items, _ = bench_items.all_items()
    dev = sorted((i for i in items if i["split"] == "dev"), key=lambda i: i["id"])
    pypi = next(i for i in dev if i["ecosystem"] == "PyPI" and i["package"])
    npm = next((i for i in dev if i["ecosystem"] == "npm" and i["package"]), None)
    small = ("jaraco/keyring", "pypa/twine")            # small dev repositories first (a quick download)
    repo = next((i for s_ in small for i in dev if (i.get("repo") or "").lower() == s_), None) or \
        next(i for i in dev if i.get("repo") and i["category"] == "dev")
    out = [(f"Dev repo-mode item ({repo['repo']})", "repo", repo), (f"Dev PyPI artifact item ({pypi['package']})", "artifact", pypi)]
    if npm:
        out.insert(1, (f"Dev npm artifact item ({npm['package']})", "artifact", npm))
    for _n, _m, it in out:
        assert it["split"] == "dev", "selfcheck must never touch the test split"
    return out


def item_checks(osv_cache: Path) -> list[tuple]:
    import run_benchmark as RB
    env = {k: v for k, v in os.environ.items() if k.startswith("REPOHEALTH_")}

    def one(spec):
        name, mode, item = spec
        cfg = {"mode": mode, "osv": True, "fragility_escalation": True, "offline": False, "mem_mb": RB.DEFAULT_MEM_MB,
               "line_cap": RB.LINE_CAP_CHARS, "scan_fn": None, "osv_cache": str(osv_cache), "env": env}
        rec = RB.run_item_isolated(item, cfg, ITEM_BUDGET_S)
        ok = rec.get("status") == "scored"
        detail = (f"{rec.get('label')} in {rec.get('elapsed_s')} s" if ok else
                  f"{rec.get('status')}: {rec.get('not_assessed_reason')}"[:160])
        fix = ("needs api.github.com and codeload.github.com, and GITHUB_TOKEN" if mode == "repo"
               else "needs the registry and its file host (see the host checks above)")
        return (name, ok, detail, fix)

    with ThreadPoolExecutor(max_workers=3) as pool:
        return list(pool.map(one, dev_items()))


def run(samples_dir: Path | None = None) -> int:
    import run_benchmark as RB
    t0 = time.monotonic()
    samples_dir = Path(samples_dir or RB.samples_root())
    tmp_cache = Path(tempfile.mkdtemp(prefix="repohealth-selfcheck-"))
    saved = {k: os.environ.get(k) for k in ("REPOHEALTH_CACHE", "REPOHEALTH_SNAPSHOT", "REPOHEALTH_OFFLINE")}
    os.environ["REPOHEALTH_CACHE"] = str(tmp_cache)        # a fresh cache: every request really goes out
    os.environ["REPOHEALTH_SNAPSHOT"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    os.environ.pop("REPOHEALTH_OFFLINE", None)
    osv_index = RB.OsvIndex(offline=False)
    results = []
    try:
        results += local_checks(samples_dir, osv_index.cache_dir)
        results += host_checks()
        have_osv = any((osv_index.cache_dir / f"osv_mal_{e}.json").exists() for e in ("PyPI", "npm")) or osv_index.db_path.exists()
        results.append(("OSV MAL- index available locally", have_osv,
                        str(osv_index.db_path if osv_index.db_path.exists() else osv_index.cache_dir),
                        "run python benchmark/select_items.py once online (downloads the OSV export, ~400 MB for npm)"))
        if have_osv:
            osv_index.prepare()
        results += item_checks(osv_index.cache_dir)
    finally:
        shutil.rmtree(tmp_cache, ignore_errors=True)
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    width = max(len(r[0]) for r in results)
    for name, ok, detail, fix in results:
        line = f"{'PASS' if ok else 'FAIL'}  {name:<{width}}  {detail}"
        if not ok and fix:
            line += f"\n      fix: {fix}"
        print(line)
    failed = sum(not r[1] for r in results)
    print(f"\nselfcheck: {len(results) - failed} passed, {failed} failed in {time.monotonic() - t0:.0f} s "
          "(test split not touched)")
    return 0 if failed == 0 else 1
