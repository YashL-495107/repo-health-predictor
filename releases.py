"""Release history for a PyPI or npm package, plus the git refs needed to compare a release with its repository.

Only fields verified against live responses (2026-11-07) are used:
  PyPI  /pypi/<name>/json: releases{version: [file{filename, url, size, packagetype, upload_time_iso_8601,
        yanked}]}; /pypi/<name>/<version>/json: info.requires_dist.
        Per-release uploader: NOT exposed by the JSON API. The top-level "ownership" field lists the CURRENT
        owners only, so it cannot be replayed for an earlier as_of date and is not used as a per-release publisher.
        Per-release publisher: the PEP 740 integrity API /integrity/<name>/<version>/<filename>/provenance gives
        attestation_bundles[].publisher{kind, repository, workflow, environment} when the release was uploaded
        with Trusted Publishing; it returns 404 otherwise (then the publisher is "not available").
  npm   registry.npmjs.org/<name>: time{version: iso}, versions{v: {_npmUser{name}, scripts, dependencies,
        gitHead, dist{tarball, unpackedSize, fileCount}}}. Unpublished versions disappear from "versions" but stay
        in "time"; they are reported as unlisted_versions.
  GitHub /repos/{o}/{r}: default_branch; /repos/{o}/{r}/git/trees/{ref}?recursive=1: tree[{path, type}],
        truncated (verified here with a branch name and a commit SHA; the user verified a tag name works);
        /repos/{o}/{r}/tags: [{name, commit{sha}}] (verified by the user); only "name" is used.

Artifacts: at most MAX_ARTIFACT_BYTES (5 MB), read in memory. Archive members are never extracted to disk and
nothing is ever executed or imported; only regular files are read, as text (size-limited) or as binary magic bytes.
"""
from __future__ import annotations

import hashlib
import io
import re
import tarfile
import time
import zipfile
from datetime import datetime
from pathlib import PurePosixPath
from urllib.parse import quote

import http_cache

DEFAULT_N = 5
CONTENT_RELEASES = 2                 # artifacts are downloaded for the latest release and the one before
MAX_ARTIFACT_BYTES = 5 * 1024 * 1024
MAX_MEMBERS = 3000
MAX_MEMBER_TEXT_BYTES = 1_000_000
MAX_TOTAL_TEXT_BYTES = 25 * 1024 * 1024
MAX_TOTAL_DECOMPRESSED_BYTES = 50 * 1024 * 1024   # declared member sizes walked + bytes read, per artifact
MAX_BINARY_HASH_BYTES = 10 * 1024 * 1024
TEXT_EXT = {".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".ps1", ".bat", ".cmd",
            ".json", ".cfg", ".toml", ".txt", ".pth", ".in", ".yml", ".yaml", ".md", ".rst", ".coffee"}
MAGIC = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
FETCH_BUDGET_S = 60.0
MAX_TAG_PAGES = 10            # 1000 tags; beyond that the likely tag names are looked up directly


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------- archives

def _strip_root(paths: list[str]) -> str:
    roots = {p.split("/", 1)[0] for p in paths if "/" in p}
    return roots.pop() + "/" if len(roots) == 1 and all("/" in p for p in paths) else ""


def read_archive(blob: bytes, kind: str) -> dict:
    """Read an sdist/npm tarball (.tar.gz) or a wheel/zip in memory. Returns
    {"text": {path: str}, "binaries": [{path, size, sha256}], "members": [paths], "truncated": bool,
     "skipped": [paths not read because of the size limits], "limits_hit": [...], "error": None}.
    Paths have the single top-level directory (e.g. "pkg-1.0/" or npm's "package/") removed.

    Limits beyond the 5 MB download (a small download can decompress to far more):
      MAX_MEMBERS entries are looked at; members are listed lazily and listing stops once the DECLARED sizes of the
      members seen exceed MAX_TOTAL_DECOMPRESSED_BYTES (reaching a tar member means decompressing the ones before it);
      the bytes actually read (text, 4-byte magic checks, executables to hash) also stop at that total; one text
      member is read only up to MAX_MEMBER_TEXT_BYTES. Any limit hit sets truncated=True and is named in limits_hit.
    """
    out = {"text": {}, "binaries": [], "members": [], "truncated": False, "skipped": [], "limits_hit": [], "error": None}

    def hit(name):
        out["truncated"] = True
        if name not in out["limits_hit"]:
            out["limits_hit"].append(name)

    entries: list[tuple[str, int, callable, callable]] = []   # name, declared size, read_all, read_head
    declared = 0
    try:
        if kind in ("sdist", "npm_tgz") and not blob[:2] == b"PK":
            tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
            seen = 0
            while True:
                m = tf.next()                      # lazy: never lists the whole archive up front
                if m is None:
                    break
                seen += 1
                if seen > MAX_MEMBERS:
                    hit("member count")
                    break
                if not m.isreg():                  # never symlinks, devices or directories
                    continue
                declared += m.size
                if declared > MAX_TOTAL_DECOMPRESSED_BYTES:
                    hit("decompressed bytes")
                    break
                entries.append((m.name, m.size, (lambda m=m: tf.extractfile(m).read()),
                                (lambda m=m: tf.extractfile(m).read(4))))
        else:
            zf = zipfile.ZipFile(io.BytesIO(blob))
            infos = zf.infolist()
            if len(infos) > MAX_MEMBERS:
                hit("member count")
            for i in infos[:MAX_MEMBERS]:
                if i.is_dir():
                    continue
                declared += i.file_size
                if declared > MAX_TOTAL_DECOMPRESSED_BYTES:
                    hit("decompressed bytes")
                    break
                entries.append((i.filename, i.file_size, (lambda i=i: zf.read(i)),
                                (lambda i=i: zf.open(i).read(4))))
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as e:
        if not entries:
            out["error"] = type(e).__name__
            return out
        hit(f"archive error ({type(e).__name__})")
    root = _strip_root([n for n, *_ in entries]) if kind in ("sdist", "npm_tgz") else ""
    used = 0
    for n, size, read, head4 in entries:
        rel = n[len(root):] if root and n.startswith(root) else n
        rel = rel.lstrip("/")
        if not rel or ".." in PurePosixPath(rel).parts:
            continue
        out["members"].append(rel)
        ext = PurePosixPath(rel).suffix.lower()
        try:
            if ext in TEXT_EXT or PurePosixPath(rel).name in ("PKG-INFO", "setup.py", "Makefile"):
                if size > MAX_MEMBER_TEXT_BYTES or used + size > MAX_TOTAL_TEXT_BYTES:
                    hit("text size")
                    out["skipped"].append(rel)
                    continue
                if used + size > MAX_TOTAL_DECOMPRESSED_BYTES:
                    hit("decompressed bytes")
                    out["skipped"].append(rel)
                    continue
                data = read()[:MAX_MEMBER_TEXT_BYTES]
                used += len(data)
                if b"\x00" not in data[:2000]:
                    out["text"][rel] = data.decode("utf-8", "ignore")
                    continue
            if size >= 1024:
                used += 4
                if head4().startswith(MAGIC):
                    if size > MAX_BINARY_HASH_BYTES or used + size > MAX_TOTAL_DECOMPRESSED_BYTES:
                        hit("binary size")
                        out["binaries"].append({"path": rel, "size": size, "sha256": None})
                        continue
                    data = read()
                    used += len(data)
                    out["binaries"].append({"path": rel, "size": size, "sha256": hashlib.sha256(data).hexdigest()})
        except (tarfile.TarError, zipfile.BadZipFile, OSError, KeyError, EOFError):
            hit("unreadable member")
    out["bytes_read"] = used
    return out


def _load_artifact(art: dict | None) -> tuple[dict | None, str]:
    if not art:
        return None, "none"
    if (art.get("size") or 0) > MAX_ARTIFACT_BYTES:
        return None, "too_large"
    blob, err = http_cache.get_bytes(art["url"], MAX_ARTIFACT_BYTES)
    if err:
        return None, "too_large" if err == "too large" else f"download_failed ({err})"
    c = read_archive(blob, art["kind"])
    return (c, "read") if not c["error"] else (None, f"unreadable ({c['error']})")


# ---------------------------------------------------------------- PyPI

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def dependency_names(requires: list[str] | None) -> list[str]:
    """Names of declared dependencies, excluding optional extras ('; extra == ...')."""
    out = []
    for r in requires or []:
        if re.search(r"extra\s*==", r):
            continue
        m = _REQ_NAME.match(r)
        if m:
            out.append(m.group(1).lower().replace("_", "-"))
    return sorted(set(out))


def _pypi_artifact(files: list[dict], prefer: str | None = None) -> dict | None:
    def pick(kind):
        fs = [f for f in files if f.get("packagetype") == kind and not f.get("yanked")]
        if kind == "bdist_wheel":
            fs.sort(key=lambda f: (not f["filename"].endswith("-none-any.whl"), f.get("size") or 0))
        return fs[0] if fs else None
    order = [prefer] if prefer else []
    order += [k for k in ("sdist", "bdist_wheel") if k not in order]
    for k in order:
        f = pick(k)
        if f:
            return {"filename": f["filename"], "url": f["url"], "size": f.get("size"),
                    "kind": "sdist" if k == "sdist" else "wheel", "packagetype": k}
    return None


def parse_pypi(project: dict, n: int = DEFAULT_N) -> list[dict]:
    """Newest-first list of the last n releases (no network). Versions without files are skipped."""
    rels = []
    for v, files in (project.get("releases") or {}).items():
        times = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")]
        if not times:
            continue
        rels.append({"version": v, "upload_time": min(times), "yanked": all(f.get("yanked") for f in files),
                     "files": [{k: f.get(k) for k in ("filename", "url", "size", "packagetype")} for f in files],
                     "_files_raw": files})
    rels.sort(key=lambda r: _dt(r["upload_time"]) or datetime.min)
    return list(reversed(rels[-n:]))


def _pypi_publisher(name: str, version: str, filename: str) -> tuple[str | None, str]:
    data, status, err = http_cache.get_json(
        f"https://pypi.org/integrity/{quote(name, safe='')}/{quote(version, safe='')}/{quote(filename, safe='')}/provenance",
        headers={"Accept": "application/vnd.pypi.integrity.v1+json"})
    if status == 404:
        return None, "no provenance (not uploaded with Trusted Publishing)"
    if err or not isinstance(data, dict):
        return None, f"provenance lookup failed ({err})"
    pubs = [b.get("publisher") or {} for b in data.get("attestation_bundles") or []]
    if not pubs:
        return None, "no publisher in provenance"
    p = pubs[0]
    ident = f"{p.get('kind')}:{p.get('repository')}/{p.get('workflow')}"
    if p.get("environment"):
        ident += f" (environment {p['environment']})"
    return ident, "PyPI provenance (Trusted Publisher)"


def fetch_pypi(name: str, n: int = DEFAULT_N, deadline: float | None = None) -> dict:
    project, status, err = http_cache.get_json(f"https://pypi.org/pypi/{quote(name, safe='')}/json")
    if status == 404:
        return {"status": "not_found", "reason": f"'{name}' is not on PyPI", "releases": []}
    if err or not isinstance(project, dict):
        return {"status": "error", "reason": f"PyPI lookup failed ({err})", "releases": []}
    rels = parse_pypi(project, n)
    partial = []
    for r in rels:   # defaults, so releases skipped by the fetch budget still have every key
        r.update({"dependencies_raw": None, "dependencies": None, "install_scripts": None, "git_head": None,
                  "artifact": None, "publisher": None, "publisher_source": "not fetched (budget)",
                  "contents": None, "artifact_status": "not_fetched"})
    for i, r in enumerate(rels):
        if deadline and time.monotonic() > deadline:
            partial.append(f"fetch budget reached at {r['version']}")
            break
        vj, _, verr = http_cache.get_json(f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(r['version'], safe='')}/json")
        r["dependencies_raw"] = ((vj or {}).get("info") or {}).get("requires_dist") if not verr else None
        r["dependencies"] = dependency_names(r["dependencies_raw"]) if r["dependencies_raw"] is not None else None
        r["install_scripts"] = None          # npm-only concept; PyPI install hooks are read from setup.py
        r["git_head"] = None
        prefer = (rels[0].get("artifact") or {}).get("packagetype") if i else None
        r["artifact"] = _pypi_artifact(r.pop("_files_raw"), prefer)
        r["publisher"], r["publisher_source"] = _pypi_publisher(name, r["version"], r["artifact"]["filename"]) \
            if r["artifact"] else (None, "no files")
        if i < CONTENT_RELEASES:
            r["contents"], r["artifact_status"] = _load_artifact(r["artifact"])
        else:
            r["contents"], r["artifact_status"] = None, "not_fetched"
    for r in rels:
        r.pop("_files_raw", None)
    roles = ((project.get("ownership") or {}).get("roles") or [])
    users = sorted({r.get("user") for r in roles if r.get("user")})
    return {"status": "ok", "reason": None, "releases": rels, "unlisted_versions": [], "partial": partial,
            "maintainers": {"count": len(users) if roles else None, "names": users,
                            "source": "PyPI ownership.roles (current owners)" if roles else "not available",
                            "organization": (project.get("ownership") or {}).get("organization")},
            "fields": {"publisher": "PyPI provenance (PEP 740 Trusted Publisher) when present; per-release uploader not exposed",
                       "dependencies": "info.requires_dist per version", "install_scripts": "setup.py in the sdist"}}


# ---------------------------------------------------------------- npm

def parse_npm(packument: dict, n: int = DEFAULT_N) -> tuple[list[dict], list[str]]:
    times = {v: t for v, t in (packument.get("time") or {}).items() if v not in ("created", "modified")}
    versions = packument.get("versions") or {}
    listed = sorted((v for v in versions if v in times), key=lambda v: _dt(times[v]) or datetime.min)
    window = listed[-n:]
    first = _dt(times[window[0]]) if window else None
    unlisted = sorted((v for v in times if v not in versions and first and (_dt(times[v]) or datetime.min) >= first),
                      key=lambda v: _dt(times[v]) or datetime.min)
    rels = []
    for v in reversed(window):
        d = versions[v]
        dist = d.get("dist") or {}
        scripts = d.get("scripts") or {}
        rels.append({"version": v, "upload_time": times[v], "yanked": False,
                     "files": [{"filename": dist.get("tarball", "").rsplit("/", 1)[-1], "url": dist.get("tarball"),
                                "size": dist.get("unpackedSize"), "packagetype": "npm_tgz"}],
                     "artifact": {"filename": dist.get("tarball", "").rsplit("/", 1)[-1], "url": dist.get("tarball"),
                                  "size": None, "unpacked_size": dist.get("unpackedSize"), "kind": "npm_tgz"} if dist.get("tarball") else None,
                     "dependencies": sorted((d.get("dependencies") or {}).keys()),
                     "dependencies_raw": d.get("dependencies") or {},
                     "install_scripts": {k: scripts[k] for k in ("preinstall", "install", "postinstall") if k in scripts},
                     "publisher": ((d.get("_npmUser") or {}).get("name")),
                     "publisher_source": "npm _npmUser" if d.get("_npmUser") else "no _npmUser in packument",
                     "git_head": d.get("gitHead")})
    return rels, unlisted


def fetch_npm(name: str, n: int = DEFAULT_N, deadline: float | None = None) -> dict:
    data, status, err = http_cache.get_json(f"https://registry.npmjs.org/{quote(name, safe='@/')}")
    if status == 404:
        return {"status": "not_found", "reason": f"'{name}' is not on npm", "releases": []}
    if err or not isinstance(data, dict):
        return {"status": "error", "reason": f"npm lookup failed ({err})", "releases": []}
    rels, unlisted = parse_npm(data, n)
    for i, r in enumerate(rels):
        if i < CONTENT_RELEASES and not (deadline and time.monotonic() > deadline):
            r["contents"], r["artifact_status"] = _load_artifact(r["artifact"])
        else:
            r["contents"], r["artifact_status"] = None, "not_fetched"
    mnt = data.get("maintainers")
    names = sorted({m.get("name") for m in mnt if isinstance(m, dict) and m.get("name")}) if isinstance(mnt, list) else []
    return {"status": "ok", "reason": None, "releases": rels, "unlisted_versions": unlisted, "partial": [],
            "maintainers": {"count": len(names) if isinstance(mnt, list) else None, "names": names,
                            "source": "npm packument maintainers (current)" if isinstance(mnt, list) else "not available"},
            "fields": {"publisher": "npm per-version _npmUser.name", "dependencies": "versions[v].dependencies",
                       "install_scripts": "versions[v].scripts preinstall/install/postinstall"}}


# ---------------------------------------------------------------- git refs

def tag_candidates(name: str, version: str) -> list[str]:
    short = name.split("/")[-1]
    out = [version, f"v{version}", f"{short}-{version}", f"{short}-v{version}", f"{name}@{version}",
           f"{short}@{version}", f"release-{version}", f"release/{version}", f"version-{version}", f"{short}/v{version}"]
    return list(dict.fromkeys(out))


def tree_paths(owner: str, repo: str, ref: str) -> tuple[set[str] | None, bool, str | None]:
    data, status, err = http_cache.get_json(f"https://api.github.com/repos/{owner}/{repo}/git/trees/{quote(ref, safe='')}?recursive=1")
    if status == 404:
        return None, False, "ref not found"
    if err or not isinstance(data, dict):
        return None, False, err or "bad response"
    return {e["path"] for e in data.get("tree") or [] if e.get("type") == "blob"}, bool(data.get("truncated")), None


def find_tag(owner: str, repo: str, name: str, version: str, max_pages: int = MAX_TAG_PAGES) -> dict:
    """Find the git tag for `version`.

    Pages through /tags (100 per page) and stops at the first page with a matching name. If no tag matched and the
    list was not complete (page cap reached or a page failed), the likely names v{version} and {version} are
    looked up directly with /git/trees/<tag name> (a 200 means the ref exists). Returns
    {"matched_tag", "tags" (names seen, None if none could be listed), "tags_error", "complete", "method",
     "tag_tree" (paths if found by direct lookup), "tag_tree_truncated"}."""
    cands = [c.lower() for c in tag_candidates(name, version)]
    out = {"matched_tag": None, "tags": [], "tags_error": None, "complete": False, "method": None,
           "tag_tree": None, "tag_tree_truncated": False, "pages": 0}
    for page in range(1, max_pages + 1):
        data, _, terr = http_cache.get_json(f"https://api.github.com/repos/{owner}/{repo}/tags?per_page=100&page={page}")
        if terr or not isinstance(data, list):
            out["tags_error"] = terr or "bad response"
            break
        out["pages"] = page
        names = [t.get("name") for t in data if isinstance(t, dict) and t.get("name")]
        out["tags"] += names
        hit = next((t for t in names if t.lower() in cands), None)
        if hit:
            out.update(matched_tag=hit, method=f"tag list (page {page})")
            return out
        if len(data) < 100:
            out["complete"] = True
            return out
    for direct in (f"v{version}", version):          # list incomplete: ask for the likely names directly
        paths, trunc, terr = tree_paths(owner, repo, direct)
        if paths is not None:
            out.update(matched_tag=direct, method="direct lookup", tag_tree=sorted(paths), tag_tree_truncated=trunc)
            return out
    if out["tags_error"] and not out["tags"]:
        out["tags"] = None
    return out


def fetch_git(owner: str, repo: str, name: str, latest: dict | None) -> dict:
    out = {"status": "ok", "reason": None, "default_branch": None, "tags": None, "tags_error": None,
           "tags_complete": False, "tag_method": None, "matched_tag": None, "trees": {}, "tree_errors": {}, "truncated": []}
    meta, _, err = http_cache.get_json(f"https://api.github.com/repos/{owner}/{repo}")
    if err or not isinstance(meta, dict):
        return {**out, "status": "error", "reason": f"GitHub repository lookup failed ({err})"}
    out["default_branch"] = meta.get("default_branch")
    tag = find_tag(owner, repo, name, latest["version"]) if latest else {"tags": None, "tags_error": "no release"}
    out.update(tags=tag.get("tags"), tags_error=tag.get("tags_error"), tags_complete=tag.get("complete", False),
               tag_method=tag.get("method"), matched_tag=tag.get("matched_tag"))
    if tag.get("tag_tree") is not None:
        out["trees"]["tag"] = tag["tag_tree"]
        if tag.get("tag_tree_truncated"):
            out["truncated"].append("tag")
    refs = [("default", out["default_branch"])]
    if out["matched_tag"] and "tag" not in out["trees"]:
        refs.append(("tag", out["matched_tag"]))
    if latest and latest.get("git_head"):
        refs.append(("git_head", latest["git_head"]))
    for label, ref in refs:
        if not ref:
            continue
        paths, trunc, terr = tree_paths(owner, repo, ref)
        if paths is None:
            out["tree_errors"][label] = terr
        else:
            out["trees"][label] = sorted(paths)
            if trunc:
                out["truncated"].append(label)
    return out


def collect_release_context(owner: str, repo: str, package: dict | None, n: int = DEFAULT_N,
                            budget_s: float = FETCH_BUDGET_S) -> dict | None:
    """Everything the release detectors need. None when the repository publishes no package."""
    if not package:
        return None
    deadline = time.monotonic() + budget_s
    eco, name = package["ecosystem"], package["name"]
    try:
        hist = fetch_pypi(name, n, deadline) if eco == "PyPI" else fetch_npm(name, n, deadline) if eco == "npm" else \
            {"status": "error", "reason": f"unsupported ecosystem {eco}", "releases": []}
    except Exception as e:  # never let a parser bug break the scan
        hist = {"status": "error", "reason": f"release fetch crashed ({type(e).__name__})", "releases": []}
    hist.update({"ecosystem": eco, "name": name})
    git = None
    if hist["status"] == "ok":
        try:
            git = fetch_git(owner, repo, name, hist["releases"][0] if hist["releases"] else None)
        except Exception as e:
            git = {"status": "error", "reason": f"git lookup crashed ({type(e).__name__})"}
    return {"package": package, "history": hist, "git": git, "snapshot": http_cache.snapshot()}
