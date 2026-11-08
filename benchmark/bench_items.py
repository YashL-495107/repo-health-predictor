"""Benchmark items: load the manifests, assign dev/test splits and move test items that overlap the dev set.

Pure metadata, no network. Used by run_benchmark.py, metrics.py and compare_chat_ai.py, so every script sees the same
item ids and splits.

Dev set (protocol section 1): manifests/dev_fp.csv (repo, ecosystem, package), manifests/dev_credibility.csv
(repo, group) and every repository in the earlier calibration / backtest files under data/.
An item overlaps the dev set when (deterministic, by name):
  - its repository slug (owner/name, case-insensitive) is a dev repository, or
  - its normalised package name equals a dev package: dev_fp's package column, or a name derived from a dev
    repository's name (the name itself, and the name without a "-python" / "-py" / "-js" / ".js" suffix or a
    "python-" prefix). Normalisation: lower case, runs of "-", "_", "." become "-" (PEP 503).
Overlapping items are moved to the dev set and the move is logged (reason per item). This can only shrink the test set.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAN = ROOT / "benchmark" / "manifests"
DATA = ROOT / "data"
CREDIBILITY = MAN / "dev_credibility.csv"
VIEWED_FILES = ("scan_results.csv", "scan_holdout.csv", "backtest_repos.csv", "backtest_skipped.csv")
CATEGORIES = ("known_bad", "known_good", "dormant", "scary", "replay", "dev")
DATADOG_EXTRACTED = MAN / "datadog_extracted.csv"   # written by extract_datadog.py (hashes only, no content)

# Replay cases that can be scanned (replay_incidents.csv status replayable / partially replayable).
# version = the release scanned; the release before it in the registry history is the benign comparison.
REPLAY_TARGETS = {
    "faker": ("npm", "faker", "6.6.6"),
    "event-stream / flatmap-stream": ("npm", "event-stream", "3.3.5"),
    "node-ipc": ("npm", "node-ipc", "11.0.0"),
}


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def package_key(eco: str, name: str) -> str:
    """The package-name key used everywhere in the benchmark: PyPI names are PEP 503-normalised (case, "-", "_" and
    "." are equivalent); npm names are compared exactly (npm forbids upper case, and "." / "_" are significant)."""
    return norm(name) if eco == "PyPI" else (name or "").strip()


def version_key(eco: str, version: str) -> str:
    """PyPI: the PEP 440 canonical form ("1.0" and "1.0.0" are the same release); npm: the string itself."""
    v = (version or "").strip()
    if eco == "PyPI" and v:
        try:
            from packaging.utils import canonicalize_version     # "1.0.0" and "1.0" -> "1" (PEP 440 equal)
            from packaging.version import InvalidVersion, Version
            try:
                Version(v)
            except InvalidVersion:
                return v
            return canonicalize_version(v)
        except ImportError:
            return v
    return v


def read_manifest(path: Path) -> list[dict]:
    """CSV rows, skipping '#' comment lines (the generator writes one header note)."""
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(line for line in fh if not line.startswith("#")))


def repo_aliases(slug: str) -> set[str]:
    name = norm(slug.split("/")[-1])
    out = {name}
    for suf in ("-python", "-py", "-js"):
        if name.endswith(suf) and len(name) > len(suf):
            out.add(name[: -len(suf)])
    if name.startswith("python-"):
        out.add(name[len("python-"):])
    return out


def dev_sets() -> dict:
    """{"repos": {slug: source}, "packages": {norm_name: source}, "credibility_rows": n}. Raises if the
    credibility manifest is missing (the protocol requires it before any scoring)."""
    if not CREDIBILITY.exists():
        raise SystemExit(f"{CREDIBILITY.name} is missing ({CREDIBILITY}): the dev set is incomplete, refusing to continue")
    repos, pkgs = {}, {}
    cred = read_manifest(CREDIBILITY)
    if not cred or "repo" not in cred[0]:
        raise SystemExit("dev_credibility.csv must have a 'repo' column")
    for r in cred:
        slug = r["repo"].strip().lower()
        if slug:
            repos.setdefault(slug, f"dev_credibility (group {r.get('group', '').strip() or '?'})")
            for a in repo_aliases(slug):
                pkgs.setdefault(a, f"dev_credibility {slug}")
    for r in read_manifest(MAN / "dev_fp.csv"):
        slug = r["repo"].strip().lower()
        repos.setdefault(slug, "dev_fp")
        if r.get("package"):
            pkgs.setdefault(norm(r["package"]), f"dev_fp {slug}")
        for a in repo_aliases(slug):
            pkgs.setdefault(a, f"dev_fp {slug}")
    for f in VIEWED_FILES:
        p = DATA / f
        if p.exists():
            with open(p, newline="", encoding="utf-8") as fh:
                for r in csv.DictReader(fh):
                    slug = (r.get("repo") or "").strip().lower()
                    if slug:
                        repos.setdefault(slug, f"viewed earlier (data/{f})")
    return {"repos": repos, "packages": pkgs, "credibility_rows": len(cred)}


def _item(category, eco, package, version, *, id_=None, repo="", source="", extra=None) -> dict:
    return {"id": id_ or f"{category}:{eco}:{package}@{version}", "category": category, "ecosystem": eco,
            "package": package, "version": version or "", "repo": (repo or "").strip(), "split": "test",
            "source": source, "move_reason": "", **(extra or {})}


def load_items() -> list[dict]:
    """Every item of every manifest, before the overlap check."""
    items = []
    for r in read_manifest(MAN / "known_bad_candidates.csv"):
        items.append(_item("known_bad", r["ecosystem"], r["package"], r["version"], id_=r["id"], source="osv_registry",
                           extra={"obtainable": r["registry_obtainable"], "obtainable_detail": r["registry_detail"],
                                  "sha256": r.get("sha256", ""), "npm_integrity": r.get("npm_integrity", "")}))
    for r in read_manifest(DATADOG_EXTRACTED):
        if r.get("status") != "extracted":
            continue
        items.append(_item("known_bad", r["ecosystem"], r["package"], r["version"], id_=r["id"], source="datadog",
                           extra={"obtainable": "yes", "obtainable_detail": f"DataDog sample {r['sample_path']}",
                                  "sample_dir": r["sample_dir"], "sha256": r.get("zip_sha256", "")}))
    for fname, cat in (("known_good.csv", "known_good"), ("known_good_dormant.csv", "dormant"),
                       ("known_good_scary.csv", "scary")):
        for r in read_manifest(MAN / fname):
            items.append(_item(cat, r["ecosystem"], r["package"], r["version"], repo=r.get("repo", ""), source=fname,
                               extra={"sha256": r.get("sha256", ""), "npm_integrity": r.get("npm_integrity", ""),
                                      "obtainable": "yes" if r.get("version") else "no"}))
    for r in read_manifest(MAN / "replay_incidents.csv"):
        tgt = REPLAY_TARGETS.get(r["incident"])
        eco, pkg, ver = tgt if tgt else (r["ecosystem"], r["incident"], "")
        items.append(_item("replay", eco, pkg, ver, id_=f"replay:{r['incident']}", source="replay_incidents.csv",
                           extra={"split": "replay", "obtainable": "yes" if tgt else "no",
                                  "obtainable_detail": r["status"] + ": " + r["reason"][:200]}))
    for r in read_manifest(MAN / "dev_fp.csv"):
        items.append(_item("dev", r["ecosystem"], r["package"], "", id_=f"dev:{r['repo']}", repo=r["repo"],
                           source="dev_fp.csv", extra={"split": "dev", "obtainable": "yes"}))
    if CREDIBILITY.exists():
        for r in read_manifest(CREDIBILITY):
            items.append(_item("dev", "", "", "", id_=f"dev:{r['repo']}", repo=r["repo"], source="dev_credibility.csv",
                               extra={"split": "dev", "obtainable": "yes", "group": r.get("group", "")}))
    return dedupe(items)


def dedupe(items: list[dict]) -> list[dict]:
    """One item per id (case-insensitive). A repository listed in two dev manifests (pypa/pip is in dev_fp.csv and
    dev_credibility.csv) is kept once: the first entry (dev_fp, which carries the package) wins; the other source is
    recorded in also_in."""
    out, by_id = [], {}
    for it in items:
        k = it["id"].lower()
        if k in by_id:
            by_id[k].setdefault("also_in", []).append(it["source"])
            continue
        by_id[k] = it
        out.append(it)
    return out


def assign_splits(items: list[dict], dev: dict | None = None) -> tuple[list[dict], list[dict]]:
    """Move test items that overlap the dev set to split=dev. Returns (items, moves)."""
    dev = dev or dev_sets()
    moves = []
    for it in items:
        if it["split"] != "test":
            continue
        why = None
        if it["repo"] and it["repo"].lower() in dev["repos"]:
            why = f"repository {it['repo'].lower()} is in the dev set ({dev['repos'][it['repo'].lower()]})"
        elif norm(it["package"]) in dev["packages"]:
            why = f"package {it['package']} matches {dev['packages'][norm(it['package'])]}"
        if why:
            it["split"], it["move_reason"] = "dev", why
            moves.append({"id": it["id"], "category": it["category"], "reason": why})
    return items, moves


def all_items() -> tuple[list[dict], list[dict]]:
    return assign_splits(load_items())


def main() -> int:
    items, moves = all_items()
    from collections import Counter
    c = Counter((i["category"], i["split"]) for i in items)
    print("items per category and split:")
    for (cat, split), n in sorted(c.items()):
        print(f"  {cat:<11} {split:<7} {n}")
    print(f"moved to dev (overlap with the dev set): {len(moves)}")
    for m in moves:
        print(f"  {m['id']}: {m['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
