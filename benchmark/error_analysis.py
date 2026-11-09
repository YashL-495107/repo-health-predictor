"""Error analysis of the frozen-ruleset benchmark -> benchmark/ERROR_ANALYSIS.md (deterministic, read-only).

  python benchmark/error_analysis.py [--samples-dir <folder>] [--out benchmark/ERROR_ANALYSIS.md]

Reads only existing files: results/items.csv, results/misses.csv, results/false_positives.csv,
manifests/datadog_extracted.csv, manifests/datadog_members.csv, manifests/known_good_scary.csv,
manifests/dev_credibility.csv, and the npm install-script facts: with --samples-dir (the extracted *.sample text
written by extract_datadog.py) it reads the package.json of each npm sample and records only the facts (item id,
ecosystem, has-install-script yes/no/unknown, script keys; no contents, no local paths) in results/npm_install_facts.csv,
then renders from that CSV; without --samples-dir it uses that CSV when it exists. It runs no scan and writes only its
outputs.

Rows: (a) every scored known-bad item that is not a strict hit, split into "review-tier only" and "no finding at any
tier"; (b) every known-good / scary false positive (lenient). Each row states MEASURABLE FACTS (files and bytes in the
sample, install-time script present or not, version shape, read limits) and a root-cause bucket chosen by the explicit
rules below. Nothing here claims what a package intends; "human-verified" is "no" for every row.

Bucket rules for misses (first rule that matches wins; each uses facts listed in the row):
  M1 "install-time script present but no detector fired": no finding at any tier, and an install-time script exists:
     a setup.py member (executed by pip when an sdist is installed) or an npm package.json with a preinstall, install
     or postinstall script. A real detector gap: every such item is listed.
  M2 "install-script fact not determinable here": no finding, npm package.json present, but its text is not on this
     machine (run with --samples-dir to read it). Listed so it is never silently counted as "no hook".
  M3 "no executable content": no finding and no code file in the sample (only metadata / text / data members).
  M4 "inflated version, no finding": no finding, code present, no install-time script, and the version is inflated
     (first number >= 90, or every number is 9, e.g. 9.9.9).
  M5 "sample partial (read limits hit), no finding": no finding, code present, no install-time script, and the
     extraction hit a read limit (member count, size, nested archive) or skipped members for size.
  M6 "code present, no hook, no pattern matched": no finding, code present, no install-time script, full read.
  M7 "facts not available (registry artifact)": the item came from the registry, not from a DataDog sample; its
     members are not in the extraction manifests.
  R1 "review-tier only": a finding at review tier (listed) but none at high-risk / known-malicious.
False-positive rules (first match wins):
  F1 "setup.py build hook on a native-build package (native sources not verified)": a finding located in setup.py from setup_py_hook or the
     custom-setup.py-command rule. ("native-build" is the package type this rule targets; whether the artifact
     carries native sources is not recorded in the result files and is not checked here.)
  F2 "publisher change to GitHub Actions plus revival_takeover": publisher_change names GitHub Actions as the new
     publisher and revival_takeover fired on the same release.
  F3 "prebuilt binary": release_delta added an executable file or committed_binary fired.
  F4 "young dependency": dependency_injection flagged a new dependency as a young package.
  F5 "other": none of the above.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
RESULTS, MAN = BENCH / "results", BENCH / "manifests"
OUT = BENCH / "ERROR_ANALYSIS.md"
NPM_FACTS = RESULTS / "npm_install_facts.csv"      # written by a --samples-dir run; read when no samples dir is given
NPM_FACT_FIELDS = ["id", "ecosystem", "has_install_script", "install_script_keys"]
CODE_EXT = {".py", ".pyw", ".pth", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".coffee", ".sh", ".bash",
            ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".rb", ".php", ".go", ".java", ".kt", ".cs", ".rs", ".pl",
            ".lua", ".c", ".cc", ".cpp", ".h", ".hpp"}
NPM_HOOKS = ("preinstall", "install", "postinstall")
HISTORY_DETECTORS = ("publisher_change", "revival_takeover", "dependency_injection", "release_delta")

MISS_BUCKETS = ["install-time script present but no detector fired", "install-script fact not determinable here",
                "no executable content", "inflated version, no finding", "sample partial (read limits hit), no finding",
                "code present, no hook, no pattern matched", "facts not available (registry artifact)", "review-tier only"]
FP_BUCKETS = ["setup.py build hook on a native-build package (native sources not verified)", "publisher change to GitHub Actions plus revival_takeover",
              "prebuilt binary", "young dependency", "other"]


def rows(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(line for line in fh if not line.startswith("#")))


def file_sha(path: Path) -> str:
    """sha256 of the file with line endings normalised to LF, so a Windows checkout (CRLF) gives the same value."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()[:12] if path.exists() else "missing"


# ------------------------------------------------------------------ facts

def inflated_version(version: str) -> bool:
    nums = [int(x) for x in re.findall(r"\d+", version or "")]
    return bool(nums) and (nums[0] >= 90 or (len(nums) >= 2 and all(set(str(n)) == {"9"} for n in nums)))


def member_facts(members: list[dict]) -> dict:
    """Facts from the extraction member list (names, sizes, actions); no file content needed."""
    written = [m for m in members if m["action"] == "written"]
    names = [PurePosixPath(m["member"].split("!")[-1]).name for m in written]
    code = [m for m in written if PurePosixPath(m["member"].split("!")[-1]).suffix.lower() in CODE_EXT]
    skipped = Counter(m["reason"].split(" (")[0] for m in members if m["action"] == "skipped")
    return {"code_files": len(code), "code_bytes": sum(int(m["size"] or 0) for m in code),
            "text_files": len(written), "setup_py": "setup.py" in names, "package_json": "package.json" in names,
            "skipped": dict(skipped)}


def npm_hooks(samples_dir: Path | None, sample_dir: str) -> list[str] | None:
    """Install hooks declared in the sample's shallowest package.json, or None when its text is not on this machine."""
    if not samples_dir or not sample_dir:
        return None
    base = samples_dir / sample_dir
    files = sorted(base.rglob("package.json.sample"), key=lambda p: (len(p.relative_to(base).parts), str(p))) if base.is_dir() else []
    if not files:
        return None
    try:
        scripts = json.loads(files[0].read_text(encoding="utf-8", errors="ignore")).get("scripts") or {}
    except (ValueError, AttributeError):
        return []
    return [k for k in NPM_HOOKS if isinstance(scripts, dict) and isinstance(scripts.get(k), str)]


def collect_npm_facts(samples_dir: Path, misses: list[dict], ext: dict) -> list[dict]:
    """npm install-script facts read from the extracted samples: item id, ecosystem, yes/no/unknown and the hook keys.
    No package contents and no local paths are recorded."""
    out = []
    for m in sorted(misses, key=lambda r: r["id"]):
        if m["ecosystem"] != "npm" or m["id"] not in ext:
            continue
        hooks = npm_hooks(samples_dir, ext[m["id"]].get("sample_dir", ""))
        out.append({"id": m["id"], "ecosystem": "npm",
                    "has_install_script": "unknown" if hooks is None else ("yes" if hooks else "no"),
                    "install_script_keys": ";".join(hooks or [])})
    return out


def write_npm_facts(facts: list[dict], path: Path = None) -> Path:
    path = Path(path or NPM_FACTS)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=NPM_FACT_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(facts)
    return path


def load_npm_facts(path: Path = None) -> dict[str, list[str] | None] | None:
    """{item id: hook keys ([] = none) or None (unknown)} from the facts CSV, or None when the CSV does not exist."""
    path = Path(path or NPM_FACTS)
    if not path.is_file():
        return None
    out = {}
    for r in rows(path):
        has = r.get("has_install_script")
        out[r["id"]] = None if has not in ("yes", "no") else [k for k in (r.get("install_script_keys") or "").split(";") if k]
    return out


def parse_why(why: str) -> tuple[str, list[str]]:
    """misses.csv 'why' -> ('review'|'none', ['detector: rule', ...])."""
    head = why.split(" | ")[0]
    if head.startswith("review-tier only:"):
        return "review", [x.strip() for x in head[len("review-tier only:"):].split(";") if x.strip()]
    return "none", []


FP_FINDING = re.compile(r"(?P<det>[a-z_]+) \[(?P<tier>[a-z_]+)\] (?P<rule>.*?) @ (?P<where>[^;]*)")


def parse_fp(why: str) -> list[dict]:
    return [m.groupdict() for m in FP_FINDING.finditer(why or "")]


# ------------------------------------------------------------------ buckets

def miss_bucket(kind: str, facts: dict | None, ecosystem: str, version: str, hooks: list[str] | None,
                partial: bool) -> str:
    if kind == "review":
        return "review-tier only"
    if facts is None:
        return "facts not available (registry artifact)"
    install = facts["setup_py"] or bool(hooks)
    if install:
        return "install-time script present but no detector fired"
    if ecosystem == "npm" and facts["package_json"] and hooks is None:
        return "install-script fact not determinable here"
    if facts["code_files"] == 0:
        return "no executable content"
    if inflated_version(version):
        return "inflated version, no finding"
    if partial:
        return "sample partial (read limits hit), no finding"
    return "code present, no hook, no pattern matched"


def fp_bucket(findings: list[dict]) -> str:
    dets = {f["det"] for f in findings}
    if any(f["where"].startswith("setup.py") and (f["det"] == "setup_py_hook" or "custom setup.py command" in f["rule"])
           for f in findings):
        return "setup.py build hook on a native-build package (native sources not verified)"
    if "revival_takeover" in dets and any(f["det"] == "publisher_change" and "GitHub Actions" in f["rule"] for f in findings):
        return "publisher change to GitHub Actions plus revival_takeover"
    if "committed_binary" in dets or any(f["det"] == "release_delta" and "executable file" in f["rule"] for f in findings):
        return "prebuilt binary"
    if any(f["det"] == "dependency_injection" and "young package" in f["rule"] for f in findings):
        return "young dependency"
    return "other"


# ------------------------------------------------------------------ analysis

def analyse(samples_dir: Path | None = None, npm_facts: dict | None = None, npm_facts_path: Path | None = None) -> dict:
    """samples_dir: read npm package.json scripts from the extracted samples. npm_facts: the same facts from the facts
    CSV (load_npm_facts). With neither, npm install-script facts are unknown."""
    items = {r["id"]: r for r in rows(RESULTS / "items.csv")}
    misses = rows(RESULTS / "misses.csv")
    fps = rows(RESULTS / "false_positives.csv")
    ext = {r["id"]: r for r in rows(MAN / "datadog_extracted.csv")}
    members = defaultdict(list)
    for m in rows(MAN / "datadog_members.csv"):
        members[m["id"]].append(m)

    miss_rows = []
    for m in sorted(misses, key=lambda r: r["id"]):
        kind, review = parse_why(m["why"])
        e = ext.get(m["id"])
        facts = member_facts(members[m["id"]]) if m["id"] in members else None
        if m["ecosystem"] != "npm":
            hooks = None
        elif samples_dir is not None:
            hooks = npm_hooks(samples_dir, (e or {}).get("sample_dir", ""))
        else:
            hooks = (npm_facts or {}).get(m["id"])
        partial = bool(e and (e.get("limits_hit") or (facts and facts["skipped"].get("larger than 1000000 bytes"))
                              or (facts and facts["skipped"].get("nested archive size limit"))))
        bucket = miss_bucket(kind, facts, m["ecosystem"], m["version"], hooks, partial)
        fact_bits = []
        if facts is not None:
            fact_bits.append(f"{facts['code_files']} code file(s), {facts['code_bytes']:,} bytes")
            fact_bits.append("setup.py present" if facts["setup_py"] else "no setup.py")
            if m["ecosystem"] == "npm":
                fact_bits.append(("npm install hooks: " + (", ".join(hooks) or "none")) if hooks is not None else
                                 ("package.json present, scripts not readable here" if facts["package_json"] else "no package.json"))
        else:
            fact_bits.append("registry artifact: member facts not in the extraction manifests")
        if inflated_version(m["version"]):
            fact_bits.append(f"inflated version {m['version']}")
        if partial:
            fact_bits.append("read limits hit: " + ((e or {}).get("limits_hit") or "members skipped for size"))
        if e:
            fact_bits.append(f"DataDog {e['kind']}")
        label = (items.get(m["id"]) or {}).get("label") or m["label"]
        what = label + (" | review-tier: " + "; ".join(review) if review else " | no finding at any tier")
        miss_rows.append({"item": m["id"], "ecosystem": m["ecosystem"], "group": "review-tier only" if kind == "review"
                          else "no finding at any tier", "what": what, "facts": "; ".join(fact_bits), "bucket": bucket,
                          "human_verified": "no"})

    fp_rows = []
    for r in sorted(fps, key=lambda r: r["id"]):
        found = parse_fp(r["why"])
        eco = r["id"].split(":")[1] if r["id"].count(":") >= 2 else ""
        dets = sorted({f["det"] for f in found})
        fp_rows.append({"item": r["id"], "ecosystem": eco, "set": r["set"],
                        "what": f"{r['label']} | detectors: {', '.join(dets) or '-'}",
                        "facts": "; ".join(f"{f['det']} [{f['tier']}] {f['rule']} @ {f['where'].strip()}" for f in found),
                        "bucket": fp_bucket(found), "history": bool(set(dets) & set(HISTORY_DETECTORS)),
                        "human_verified": "no"})
    source = "samples" if samples_dir is not None else ("csv" if npm_facts is not None else None)
    return {"misses": miss_rows, "fps": fp_rows, "npm_facts_source": source,
            "npm_facts_path": Path(npm_facts_path or NPM_FACTS) if source == "csv" else None}


def sqlmap_status() -> dict:
    scary = [r for r in rows(MAN / "known_good_scary.csv") if r["package"].lower() == "sqlmap"]
    cred = [r for r in rows(MAN / "dev_credibility.csv") if r["repo"].lower() == "sqlmapproject/sqlmap"]
    items = [r for r in rows(RESULTS / "items.csv") if "sqlmap" in r["id"].lower()]
    return {"in_scary": bool(scary), "in_dev": bool(cred), "items": items}


# ------------------------------------------------------------------ report

def _table(header, body):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c).replace("|", "/").replace("\n", " ") for c in row) + " |" for row in body]
    return out


def summary(rows_, buckets, key="bucket"):
    c = Counter(r[key] for r in rows_)
    body = []
    for b in buckets:
        ex = [r["item"] for r in rows_ if r[key] == b][:3]
        body.append([b, c.get(b, 0), ", ".join(ex) or "-"])
    return body


def render(res: dict) -> str:
    misses, fps = res["misses"], res["fps"]
    inputs = [RESULTS / "items.csv", RESULTS / "misses.csv", RESULTS / "false_positives.csv",
              MAN / "datadog_extracted.csv", MAN / "datadog_members.csv"]
    src = res.get("npm_facts_source")
    if src == "csv":
        fp = res["npm_facts_path"]
        npm_text = (f". npm install-script facts come from `results/{fp.name}` ({file_sha(fp)}), written by "
                    "`error_analysis.py --samples-dir` from the package.json of each extracted sample (item id, "
                    "has-install-script and the script keys only; no package contents, no local paths).")
    elif src == "samples":
        npm_text = (". npm install-script facts were read from the package.json of each extracted sample "
                    "(--samples-dir) and not recorded in a facts CSV.")
    else:
        npm_text = (". The extracted samples were NOT available and there is no `results/npm_install_facts.csv`, so npm "
                    "package.json scripts could not be read: those items are in the bucket \"install-script fact not "
                    "determinable here\" (re-run with --samples-dir on the machine that holds the samples).")
    L = ["# Error analysis (frozen ruleset 2026.11.08-12)", "",
         "Generated by `benchmark/error_analysis.py` from existing result and manifest files; no scan was run and no "
         "number is typed by hand. Every row states measurable facts and a bucket chosen by the explicit rules in the "
         "script's docstring. Nothing here says what a package intends. **Human-verified: no** for every row.", "",
         "Inputs (sha256, first 12 hex): " + ", ".join(f"`{p.relative_to(BENCH).as_posix()}` {file_sha(p)}" for p in inputs)
         + npm_text, ""]
    groups = Counter(r["group"] for r in misses)
    L += ["## Known-bad items that are not a strict hit", "",
          f"{len(misses)} scored known-bad items are not a strict hit: {groups.get('review-tier only', 0)} have a "
          f"review-tier finding only, {groups.get('no finding at any tier', 0)} have no finding at any tier.", ""]
    L += _table(["bucket", "count", "examples"], summary(misses, MISS_BUCKETS)) + [""]
    gap = [r for r in misses if r["bucket"] == "install-time script present but no detector fired"]
    L += ["### Detector gap: install-time script present but no detector fired (every item)", "",
          f"{len(gap)} item(s). Each has an install-time script (a setup.py, or an npm install hook) and no finding at "
          "any tier.", ""]
    L += _table(["item", "ecosystem", "facts"], [[r["item"], r["ecosystem"], r["facts"]] for r in gap]) + [""]
    L += ["## Known-good and scary false positives (lenient)", "",
          f"{len(fps)} items ({sum(r['set'] == 'known_good' for r in fps)} random known-good, "
          f"{sum(r['set'] == 'scary' for r in fps)} scary). Of the random known-good ones, "
          f"{sum(r['history'] for r in fps if r['set'] == 'known_good')} involve a history-based detector "
          f"({', '.join(HISTORY_DETECTORS)}).", ""]
    L += _table(["bucket", "count", "examples"], summary(fps, FP_BUCKETS)) + [""]
    L += _table(["item", "ecosystem", "set", "what happened", "facts", "root-cause bucket", "human-verified"],
                [[r["item"], r["ecosystem"], r["set"], r["what"], r["facts"], r["bucket"], r["human_verified"]] for r in fps]) + [""]
    sq = sqlmap_status()
    L += ["## sqlmap", ""]
    if sq["in_scary"]:
        L += ["sqlmap is in the benchmark scary set; its recorded labels: " +
              "; ".join(f"{r['id']}: {r['label']}" for r in sq["items"]), ""]
    else:
        L += ["sqlmap is **not** in the benchmark scary set (`manifests/known_good_scary.csv`) and has no benchmark "
              "record. `sqlmapproject/sqlmap` is a dev-set repository (`manifests/dev_credibility.csv`), so it is a "
              "documented repo-mode example, not benchmark evidence: in the app (repo mode) it shows 49/100 "
              "\"High-risk patterns\", with the Behavior pillar limited by a credential-stealer pattern at "
              "`lib/core/settings.py:1391` and evidence caps 59 (offensive-security terms) and 49 (high-risk pattern). "
              "These values were read from the app, not computed here. sqlmap is a security tool: its code contains the "
              "same patterns as the malware it tests for (dual-use).", ""]
    L += ["## All known-bad misses", ""]
    L += _table(["item", "ecosystem", "group", "what happened (label + detectors)", "facts", "root-cause bucket",
                 "human-verified"],
                [[r["item"], r["ecosystem"], r["group"], r["what"], r["facts"], r["bucket"], r["human_verified"]]
                 for r in misses]) + [""]
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Error analysis of the frozen-ruleset benchmark (read-only)")
    ap.add_argument("--samples-dir", default=None, help="extracted samples root (to read npm package.json scripts)")
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--npm-facts", default=str(NPM_FACTS), help="npm install-script facts CSV (written with --samples-dir)")
    a = ap.parse_args(argv)
    if a.samples_dir:
        # read the facts from the samples, record them (no contents, no paths), then render FROM the recorded CSV, so a
        # later run without the samples (CI) produces exactly the same document
        sd = Path(a.samples_dir).resolve()
        misses = rows(RESULTS / "misses.csv")
        ext = {r["id"]: r for r in rows(MAN / "datadog_extracted.csv")}
        facts = collect_npm_facts(sd, misses, ext)
        path = write_npm_facts(facts, Path(a.npm_facts))
        print(f"wrote {path} ({len(facts)} npm items; unknown: {sum(f['has_install_script'] == 'unknown' for f in facts)})")
    npm = load_npm_facts(Path(a.npm_facts))
    text = render(analyse(None, npm, Path(a.npm_facts)))
    Path(a.out).write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
