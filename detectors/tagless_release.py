"""tagless_release (Integrity) - the latest published artifact does not match the repository.

Signals: (a) no git tag matches the latest version (tried: 1.2.3, v1.2.3, name-1.2.3, name@1.2.3, release-1.2.3,
...); (b) "phantom" source files in the artifact that exist neither in the repository at the matching tag (or, for
npm, at the release's gitHead commit) nor on the default branch.
Tier: a missing tag alone is review (many projects do not tag); it is metadata-only, so fragility does not
escalate it. When GitHub truncates the recursive tree listing, the phantom-file check is skipped (coverage partial),
because missing paths would look like phantom files. Phantom files that carry a capability (network,
process, decoded payload, or an install hook that runs them) are high_risk; phantom files without one are review.
Since 2026.11.07-9: capability-free phantom files in docs/, _static/ or _build/ are info, not review.
Since 2026.11.08-11: a phantom file is high_risk only when its capability is install-time or concealed (install
hook, decoded payload), or a network/process capability that is NEW relative to the predecessor release's artifact
(the same file with the same capability there is not new; with no predecessor, every capability is new). Otherwise
it is review. Capability-free generated version files (_version.py, *_version.py, __version__.py, version.py) are
info.
Generated metadata (PKG-INFO, *.egg-info, *.dist-info, package.json, ...), build outputs (dist/,
build/, ...) and compiled .js whose .ts source is in the repository are not counted as phantom.
Time: compares the latest release's artifact with the repository state the API returns today; tags can be added
or moved later, so a replay of an old incident is only valid with a cached snapshot from that time.
Known evasions: a matching tag pushed with the malicious code, code hidden in build-output folders we skip,
payloads in non-source files, artifacts over 5 MB (not read), repositories whose tree listing is truncated.
False-positive sources: projects that never tag, monorepos with different tag schemes, releases built from a
branch other than the default, generated files we do not recognise.
"""
import re
from pathlib import PurePosixPath

from .base import make_result, not_assessed
from .release_analysis import CODE_EXT, capabilities, file_capabilities
from .release_common import PILLAR, release_finding, release_gate, version_pair

DETECTOR_ID = "tagless_release"
GENERATED = re.compile(r"(^|/)(PKG-INFO|setup\.cfg|MANIFEST\.in|package\.json|"
                       r"npm-shrinkwrap\.json|[^/]+\.egg-info/.*|[^/]+\.dist-info/.*|RECORD|WHEEL|METADATA)$")
BUILD_DIRS = {"dist", "build", "out", "es", "esm", "cjs", "umd", "bundles", "_build"}
DOC_BUILD_DIRS = {"docs", "doc", "_static", "_build"}   # generated documentation assets (Sphinx _static, ...)
# generated version files (setuptools_scm, versioneer, hatch-vcs write them at build time): info when capability-free
VERSION_FILE = re.compile(r"(^|/)(?:[\w-]*_version|__version__|version)\.py$")
INSTALL_TIME = {"install hook", "decoded"}   # install-time or concealed: high_risk without a predecessor comparison


def _in_repo(path: str, repo: set[str], suffixes: set[str]) -> bool:
    if path in repo or any(r.endswith("/" + path) for r in repo):
        return True
    pp = PurePosixPath(path)
    if pp.suffix in (".js", ".mjs", ".cjs", ".d.ts") or path.endswith(".d.ts"):
        stem = str(pp.with_suffix("")).removesuffix(".d")
        return any(f"{stem}{ext}" in suffixes or any(s.endswith(f"/{PurePosixPath(stem).name}{ext}") for s in suffixes)
                   for ext in (".ts", ".tsx", ".coffee", ".mts", ".cts"))
    return False


def detect(ctx) -> dict:
    gate, hist = release_gate(ctx, DETECTOR_ID, min_releases=1)
    if gate:
        return gate
    git = (ctx.releases or {}).get("git") or {}
    if git.get("status") != "ok":
        return not_assessed(DETECTOR_ID, PILLAR, git.get("reason") or "repository refs not fetched")
    new = hist["releases"][0]
    pair = version_pair(hist, new, None)
    findings, notes, coverage = [], [], "full"

    if git.get("tags") is None:
        coverage = "partial"
        notes.append(f"tag list not available ({git.get('tags_error')})")
    elif not git.get("matched_tag"):
        n_tags = len(git["tags"])
        findings.append(release_finding(
            DETECTOR_ID, "review", f"No git tag matches release {new['version']}",
            f"Checked {n_tags} tag(s); the repository has {'no tags at all' if not n_tags else 'tags, but none for this version'}. "
            "Many projects do not tag releases; this is a weak signal on its own.",
            [pair, {"type": "registry_field", "field": "tags", "count": n_tags}],
            fix="Check which commit the release was built from."))

    contents = new.get("contents")
    trees = git.get("trees") or {}
    if contents is None:
        coverage = "partial"
        notes.append(f"artifact not read ({new.get('artifact_status')}): phantom-file check skipped")
    elif "default" not in trees:
        coverage = "partial"
        notes.append(f"default-branch tree not available ({(git.get('tree_errors') or {}).get('default')})")
    elif git.get("truncated"):
        # a truncated listing would make real repository files look like phantom files: do not run the check
        coverage = "partial"
        notes.append(f"repository tree listing truncated by GitHub ({', '.join(git['truncated'])}): phantom-file check skipped")
    else:
        repo = set(trees["default"]) | set(trees.get("tag") or []) | set(trees.get("git_head") or [])
        caps = capabilities(new)
        rels = hist["releases"]
        prev = rels[1] if len(rels) > 1 else None
        prev_text = ((prev or {}).get("contents") or {}).get("text") if prev else None
        if prev is not None and prev_text is None:
            notes.append(f"predecessor {prev['version']} artifact not read: network/process in phantom files cannot be "
                         "shown to be new, so they are review")
        hook_files = {f for v in caps["install_hook"] for f in re.findall(r"[\w./-]+\.(?:js|cjs|mjs|sh|py)", v)}
        decoded_files = {k.rsplit(":", 1)[0] for k in caps["decoded"]}
        phantom, risky, info, known = [], [], [], []
        for p, t in (contents.get("text") or {}).items():
            pp = PurePosixPath(p)
            if pp.suffix.lower() not in CODE_EXT or GENERATED.search(p) or (pp.parts and pp.parts[0] in BUILD_DIRS):
                continue
            if p.endswith((".min.js", ".map")) or _in_repo(p, repo, repo):
                continue
            fc = file_capabilities(p, t) | ({"decoded"} if p in decoded_files else set()) | \
                 ({"install hook"} if any(p.endswith(h.lstrip("./")) for h in hook_files) else set())
            if fc:
                # high_risk only for install-time / concealed capabilities, or network/process that are NEW relative
                # to the predecessor's artifact (the same file with the same capability there is not new); no
                # predecessor at all = everything is new
                if prev is None:
                    new_caps = set(fc)
                elif prev_text is None:
                    new_caps = fc & INSTALL_TIME
                else:
                    old_caps = file_capabilities(p, prev_text[p]) if p in prev_text else set()
                    new_caps = (fc & INSTALL_TIME) | (fc - old_caps)
                (risky if new_caps else known).append((p, sorted(fc)))
            elif VERSION_FILE.search(p):
                info.append(p)                           # generated version file without a capability: info
            elif any(x.lower() in DOC_BUILD_DIRS for x in pp.parts[:-1]):
                info.append(p)                           # capability-free phantom in docs/_static/_build: info
            else:
                phantom.append(p)
        ref = f"tag {git['matched_tag']}" if git.get("matched_tag") else "the default branch" + (" or the release gitHead" if "git_head" in trees else "")
        if risky:
            findings.append(release_finding(
                DETECTOR_ID, "high_risk", f"Release {new['version']} contains {len(risky)} source file(s) not in the repository that add capabilities",
                "; ".join(f"{p} ({', '.join(c)})" for p, c in risky[:5]) + f". Compared with {ref}.",
                [pair] + [{"type": "file_line", "file": p, "line": None, "capabilities": c} for p, c in risky[:10]],
                file=risky[0][0], fix="Do not install until the extra files are explained by the maintainers."))
            findings[-1]["capability_evidence"] = True
        elif known:
            findings.append(release_finding(
                DETECTOR_ID, "review", f"Release {new['version']} contains {len(known)} source file(s) not in the repository "
                "with capabilities that are not new",
                "; ".join(f"{p} ({', '.join(c)})" for p, c in known[:5]) + f". Compared with {ref}. The same capability "
                f"was already in these files in {prev['version'] if prev else 'the previous release'}"
                + (" (predecessor artifact not read)" if prev is not None and prev_text is None else "") + ".",
                [pair] + [{"type": "file_line", "file": p, "line": None, "capabilities": c} for p, c in known[:10]],
                file=known[0][0]))
            findings[-1]["capability_evidence"] = True
        elif phantom:
            findings.append(release_finding(
                DETECTOR_ID, "review", f"Release {new['version']} contains {len(phantom)} source file(s) not in the repository",
                ", ".join(phantom[:8]) + f". Compared with {ref}. No network/process/decoded capability found in them.",
                [pair] + [{"type": "file_line", "file": p, "line": None} for p in phantom[:10]], file=phantom[0]))
    res = make_result(DETECTOR_ID, PILLAR, "ran", findings, coverage=coverage, coverage_detail="; ".join(notes) or None)
    if contents is not None and "default" in trees and not git.get("truncated") and info:
        res["info_findings"] = [{"file": p, "rule": "Source file not in the repository (generated version file or docs/build "
                                                    "asset, no capability)",
                                 "info_reason": ("Downgraded to info: a capability-free generated version file (written at "
                                                 "build time, usually not committed)." if VERSION_FILE.search(p) else
                                                 "Downgraded to info: a capability-free phantom file in a docs/_static/_build "
                                                 "directory (generated documentation assets are often not committed).")}
                                for p in info[:20]]
    return res
