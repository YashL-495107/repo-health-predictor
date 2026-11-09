"""Build the benchmark manifests (Stage 1: data selection only, nothing is scanned or scored).

Deterministic: every random choice uses random.Random(SEED) in a fixed order. Downloads only METADATA (OSV records,
registry JSON, popularity lists) into benchmark/cache/ (git-ignored). No package code is downloaded here; no artifact
is executed, imported or installed. Writes CSV manifests to benchmark/manifests/.

Usage:  python benchmark/select_items.py            (re-running gives the same manifests for the same snapshot)
"""
from __future__ import annotations

import csv
import io
import json
import os
import random
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("REPOHEALTH_CACHE", str(ROOT / "benchmark" / "cache" / "http"))
os.environ.setdefault("REPOHEALTH_SNAPSHOT", "2026-11-07")
import http_cache  # noqa: E402

SEED = 20261107
PROTOCOL_DATE = datetime(2026, 11, 7, tzinfo=timezone.utc)
N_BAD_PER_ECO = 150
N_GOOD_PER_ECO = 60
N_DORMANT_PER_ECO = 6
TOP_N = 1000
MAINTAINED_DAYS = 730          # "currently maintained": a release within 2 years of the protocol date
DORMANT_DAYS = 3 * 365         # "finished/dormant": no release for more than 3 years
MAN = ROOT / "benchmark" / "manifests"
CACHE = ROOT / "benchmark" / "cache"
OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
HUGOVK = "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json"
NPM_HIGH_IMPACT = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js"
DATADOG = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/{eco}/manifest.json"
EXEC_EXT = (".exe", ".dll", ".so", ".dylib", ".bin")

SCARY = [  # hand-picked judgement sample: legitimate packages that LOOK risky (documented as such)
    ("PyPI", "impacket", "security tool (network protocol attacks)"), ("PyPI", "scapy", "security tool (packet crafting)"),
    ("PyPI", "pwntools", "security tool (exploit development)"), ("PyPI", "mitmproxy", "security tool (intercepting proxy)"),
    ("PyPI", "yara-python", "security tool (malware signatures)"), ("PyPI", "bandit", "security tool (static analysis rules)"),
    ("PyPI", "volatility3", "security tool (memory forensics)"), ("PyPI", "frida", "security tool (instrumentation)"),
    ("npm", "esbuild", "build tool with an install script (downloads a native binary)"),
    ("npm", "puppeteer", "install script downloads a browser"), ("npm", "sharp", "install script (native build)"),
    ("npm", "bcrypt", "install script (node-pre-gyp native build)"), ("npm", "core-js", "postinstall script"),
    ("npm", "electron", "postinstall downloads a binary"), ("npm", "playwright", "install-time browser download"),
    ("npm", "@swc/core", "postinstall (native binary)"), ("npm", "protobufjs", "postinstall script"),
    ("npm", "cypress", "postinstall downloads a binary"), ("npm", "javascript-obfuscator", "obfuscation tool"),
    ("npm", "pdfjs-dist", "ships minified/vendored JS"), ("npm", "tinymce", "ships minified/vendored JS"),
]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dt(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def write_csv(name: str, rows: list[dict], header_note: str):
    MAN.mkdir(parents=True, exist_ok=True)
    path = MAN / name
    cols = list(rows[0].keys()) if rows else ["empty"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        fh.write(f"# {header_note} | seed={SEED} | generated={now_iso()} | snapshot={http_cache.snapshot()}\n")
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {path.relative_to(ROOT)} ({len(rows)} rows)")


# ------------------------------------------------------------------ exclusions (dev set + viewed)

def exclusions() -> tuple[set[str], set[str]]:
    repos, pkgs = set(), set()
    for f in ("dev_fp.csv", "dev_credibility.csv"):
        p = MAN / f
        if p.exists():
            for r in csv.DictReader(l for l in open(p, encoding="utf-8") if not l.startswith("#")):
                repos.add((r.get("repo") or "").lower()); pkgs.add((r.get("package") or "").lower())
    for f in ("scan_results.csv", "scan_holdout.csv", "backtest_repos.csv", "backtest_skipped.csv"):
        p = ROOT / "data" / f
        if p.exists():
            for r in csv.DictReader(open(p, encoding="utf-8")):
                repos.add((r.get("repo") or "").lower())
    repos.discard(""); pkgs.discard("")
    return repos, pkgs


# ------------------------------------------------------------------ known-bad

def osv_mal_index(eco: str) -> list[dict]:
    """MAL- records of one ecosystem from the OSV bulk export (metadata only)."""
    idx_path = CACHE / f"osv_mal_{eco}.json"
    if idx_path.exists():
        return json.loads(idx_path.read_text(encoding="utf-8"))
    blob, err = http_cache.get_bytes(OSV_BUCKET.format(eco=eco), 400 * 1024 * 1024, timeout=600)
    if err:
        raise SystemExit(f"OSV export {eco}: {err}")
    out = []
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for name in z.namelist():
            if not name.startswith("MAL-"):
                continue
            rec = json.loads(z.read(name))
            aff = (rec.get("affected") or [{}])[0]
            pkg = aff.get("package") or {}
            versions = sorted({v for a in rec.get("affected") or [] for v in a.get("versions") or []})
            out.append({"id": rec["id"], "ecosystem": pkg.get("ecosystem", eco), "package": pkg.get("name"),
                        "versions": versions, "published": rec.get("published"), "withdrawn": rec.get("withdrawn")})
    CACHE.mkdir(parents=True, exist_ok=True)
    idx_path.write_text(json.dumps(out), encoding="utf-8")
    return out


def registry_obtainable(eco: str, name: str, version: str | None) -> dict:
    """Is the code of this version still published? Metadata lookup only (no download)."""
    if eco == "PyPI":
        if not version:
            return {"obtainable": "no", "detail": "no version listed in the advisory"}
        data, status, err = http_cache.get_json(f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json")
        if status == 404:
            return {"obtainable": "no", "detail": "removed from PyPI"}
        if err:
            return {"obtainable": "unknown", "detail": err}
        files = [u for u in (data or {}).get("urls") or [] if not u["filename"].lower().endswith(EXEC_EXT)]
        if not files:
            return {"obtainable": "no", "detail": "no files"}
        f = sorted(files, key=lambda u: u.get("packagetype") != "sdist")[0]
        return {"obtainable": "yes", "detail": f"{f['packagetype']} {f['filename']} ({f.get('size')} bytes)",
                "sha256": (f.get("digests") or {}).get("sha256", ""), "artifact_url": f["url"]}
    data, status, err = http_cache.get_json(f"https://registry.npmjs.org/{quote(name, safe='@/')}")
    if status == 404:
        return {"obtainable": "no", "detail": "removed from npm"}
    if err:
        return {"obtainable": "unknown", "detail": err}
    vers = (data or {}).get("versions") or {}
    if version and version in vers:
        if version.endswith("-security") or "security holding" in str(vers[version].get("description", "")).lower():
            return {"obtainable": "no", "detail": "replaced by an npm security holding package"}
        dist = vers[version].get("dist") or {}
        return {"obtainable": "yes", "detail": f"tarball ({dist.get('unpackedSize')} bytes unpacked)",
                "sha256": "", "sha1": dist.get("shasum", ""), "integrity": dist.get("integrity", ""), "artifact_url": dist.get("tarball", "")}
    if any(v.endswith("-security") for v in vers):
        return {"obtainable": "no", "detail": "replaced by an npm security holding package"}
    return {"obtainable": "no", "detail": "version not listed (unpublished)"}


def known_bad(rng: random.Random) -> list[dict]:
    rows = []
    dd = {}
    for eco_dd, eco in (("pypi", "PyPI"), ("npm", "npm")):
        m, _, err = http_cache.get_json(DATADOG.format(eco=eco_dd))
        dd[eco] = m if isinstance(m, dict) else {}
    for eco in ("PyPI", "npm"):
        idx = [r for r in osv_mal_index(eco) if r["package"] and not r.get("withdrawn")]
        idx.sort(key=lambda r: r["id"])                       # fixed order before sampling
        sample = rng.sample(idx, min(N_BAD_PER_ECO, len(idx)))
        for r in sample:
            version = rng.choice(r["versions"]) if r["versions"] else None
            ob = registry_obtainable(eco, r["package"], version)
            rows.append({"id": r["id"], "ecosystem": eco, "package": r["package"], "version": version or "",
                         "source": "OSV MAL- (OpenSSF malicious-packages)", "source_url": f"https://osv.dev/vulnerability/{r['id']}",
                         "published": r["published"], "registry_obtainable": ob["obtainable"], "registry_detail": ob["detail"],
                         "sha256": ob.get("sha256", ""), "npm_integrity": ob.get("integrity", ""),
                         "in_datadog_manifest": "yes" if r["package"] in dd.get(eco, {}) else "no",
                         "osv_index_size": len(idx)})
    return rows


# ------------------------------------------------------------------ known-good

def popularity_lists() -> dict[str, list[str]]:
    top, _, err = http_cache.get_json(HUGOVK)
    pypi = [r["project"] for r in (top or {}).get("rows", [])][:TOP_N]
    js, err2 = http_cache.get_bytes(NPM_HIGH_IMPACT, 5 * 1024 * 1024)
    npm = re.findall(r"'([^']+)'", (js or b"").decode("utf-8", "ignore"))[:TOP_N]
    return {"PyPI": pypi, "npm": npm, "_meta": {"pypi_last_update": (top or {}).get("last_update"), "pypi_source": (top or {}).get("source")}}


def package_meta(eco: str, name: str) -> dict:
    if eco == "PyPI":
        d, status, err = http_cache.get_json(f"https://pypi.org/pypi/{quote(name, safe='')}/json")
        if err or not isinstance(d, dict):
            return {"ok": False, "detail": err or f"HTTP {status}"}
        info = d.get("info") or {}
        v = info.get("version")
        files = d.get("urls") or []
        up = max((f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")), default=None)
        urls = info.get("project_urls") or {}
        repo = next((u for u in list(urls.values()) + [info.get("home_page") or ""] if "github.com/" in (u or "")), "")
        f = sorted(files, key=lambda u: u.get("packagetype") != "sdist")[0] if files else {}
        return {"ok": True, "version": v, "latest_upload": up, "repo_url": repo, "deprecated": "",
                "sha256": (f.get("digests") or {}).get("sha256", ""), "install_scripts": ""}
    d, status, err = http_cache.get_json(f"https://registry.npmjs.org/{quote(name, safe='@/')}")
    if err or not isinstance(d, dict):
        return {"ok": False, "detail": err or f"HTTP {status}"}
    v = (d.get("dist-tags") or {}).get("latest")
    ver = (d.get("versions") or {}).get(v) or {}
    repo = (d.get("repository") or {}).get("url", "") if isinstance(d.get("repository"), dict) else str(d.get("repository") or "")
    scripts = ver.get("scripts") or {}
    return {"ok": True, "version": v, "latest_upload": (d.get("time") or {}).get(v), "repo_url": repo,
            "deprecated": str(ver.get("deprecated") or "")[:80], "sha256": "", "npm_integrity": (ver.get("dist") or {}).get("integrity", ""),
            "install_scripts": ",".join(k for k in ("preinstall", "install", "postinstall") if k in scripts)}


def repo_slug(url: str) -> str:
    m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$", url or "")
    return f"{m.group(1)}/{m.group(2)}".lower() if m else ""


def known_good(rng: random.Random, lists: dict, ex_repos: set, ex_pkgs: set):
    good, dormant, notes = [], [], []
    for eco in ("PyPI", "npm"):
        order = list(lists[eco])
        rng.shuffle(order)                                   # one seeded order per ecosystem
        n_good = n_dorm = 0
        for name in order:
            if n_good >= N_GOOD_PER_ECO and n_dorm >= N_DORMANT_PER_ECO:
                break
            if name.lower() in ex_pkgs:
                notes.append(f"{eco} {name}: excluded (dev set)")
                continue
            m = package_meta(eco, name)
            if not m["ok"]:
                notes.append(f"{eco} {name}: metadata not available ({m['detail']})")
                continue
            slug = repo_slug(m["repo_url"])
            if slug and slug in ex_repos:
                notes.append(f"{eco} {name}: excluded (repository {slug} viewed earlier)")
                continue
            if m["deprecated"]:
                continue
            age = (PROTOCOL_DATE - dt(m["latest_upload"])).days if dt(m["latest_upload"]) else None
            row = {"ecosystem": eco, "package": name, "version": m["version"], "latest_upload": m["latest_upload"],
                   "days_since_release": age, "repo": slug, "sha256": m.get("sha256", ""),
                   "npm_integrity": m.get("npm_integrity", ""), "install_scripts": m["install_scripts"],
                   "popularity_rank": lists[eco].index(name) + 1}
            if age is not None and age <= MAINTAINED_DAYS and n_good < N_GOOD_PER_ECO:
                good.append({**row, "category": "maintained"}); n_good += 1
            elif age is not None and age > DORMANT_DAYS and n_dorm < N_DORMANT_PER_ECO:
                dormant.append({**row, "category": "dormant"}); n_dorm += 1
    return good, dormant, notes


def scary(ex_pkgs: set) -> list[dict]:
    rows = []
    for eco, name, why in SCARY:
        if name.lower() in ex_pkgs:
            continue
        m = package_meta(eco, name)
        rows.append({"ecosystem": eco, "package": name, "why_scary": why, "exists": "yes" if m["ok"] else f"no ({m.get('detail')})",
                     "version": m.get("version", ""), "latest_upload": m.get("latest_upload", ""), "repo": repo_slug(m.get("repo_url", "")),
                     "install_scripts": m.get("install_scripts", ""), "sha256": m.get("sha256", ""), "npm_integrity": m.get("npm_integrity", "")})
    return rows


def main():
    rng = random.Random(SEED)
    ex_repos, ex_pkgs = exclusions()
    print(f"exclusions: {len(ex_repos)} repositories, {len(ex_pkgs)} packages"
          + ("" if (MAN / "dev_credibility.csv").exists() else "  (dev_credibility.csv MISSING: must be supplied before Stage 2)"))
    bad = known_bad(rng)
    write_csv("known_bad_candidates.csv", bad, "Known-bad candidates: seeded random sample of OSV MAL- advisories per ecosystem; "
              "registry_obtainable = code of that version still published (metadata lookup only)")
    lists = popularity_lists()
    good, dormant, notes = known_good(rng, lists, ex_repos, ex_pkgs)
    meta = lists["_meta"]
    write_csv("known_good.csv", good, f"Known-good maintained: seeded sample of the top {TOP_N} of hugovk/top-pypi-packages "
              f"({meta.get('pypi_source')}, last_update {meta.get('pypi_last_update')}) and wooorm/npm-high-impact; "
              f"latest release within {MAINTAINED_DAYS} days of 2026-11-07; dev set and viewed repositories excluded")
    write_csv("known_good_dormant.csv", dormant, f"Known-good dormant: same seeded order, latest release more than {DORMANT_DAYS} "
              "days before 2026-11-07, not deprecated")
    write_csv("known_good_scary.csv", scary(ex_pkgs), "Scary-but-legitimate: hand-picked judgement sample (not random)")
    (MAN / "selection_notes.txt").write_text("\n".join(notes) + "\n", encoding="utf-8")
    debug = [{"repo": r, "reason": "dev set (dev_fp)"} for r in sorted(ex_repos & {
        "boto/boto3", "pypa/twine", "getsentry/sentry-python", "docker/docker-py", "paramiko/paramiko",
        "jaraco/keyring", "certbot/certbot", "pypa/pip"})][:10]
    write_csv("debug_slice.csv", debug, "Harness-debug slice: DEV items only (at most 10)")


if __name__ == "__main__":
    main()
