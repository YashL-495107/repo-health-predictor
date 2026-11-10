"""Tool vs a chat AI on a fixed set of about 30 items. No API is called: the prompts are pasted into a chat AI by hand
and its verdicts are typed into the scoring sheets. Every summary number is computed by this script.

Steps
  1. select   choose the items with random.Random(20261107), a fresh generator per pool, BEFORE any result is viewed (15 known-bad with
              obtainable code, 10 random known-good, 5 scary-but-legitimate; test split only) and write
              benchmark/chat_ai/items.csv. Re-running gives the same items (the pools are path/id-sorted first).
              Known-bad code is mostly obtainable only from the DataDog samples, so run it after extract_datadog.py.
  2. prompts  write the exact prompt per item to <samples folder>/chat_ai_prompts/ (git-ignored: known-bad prompts
              contain sample text), the scoring sheet benchmark/chat_ai/scoring.csv and the repeatability sheet
              benchmark/chat_ai/repeatability.csv (5 runs per item). The tool columns are filled from a benchmark
              run file (--tool-run, default the artifact-mode headline run: no OSV, no fragility escalation).
  3. summarise  read the filled sheets and write benchmark/chat_ai/SUMMARY.md (accuracy per side at both operating
              points, verdict drift across the 5 repeats).

Usage
  python benchmark/compare_chat_ai.py select
  python benchmark/compare_chat_ai.py prompts [--tool-run benchmark/runs/artifact-test-noosv.jsonl]
  python benchmark/compare_chat_ai.py summarise
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
for p in (str(ROOT), str(BENCH)):
    if p not in sys.path:
        sys.path.insert(0, p)

import bench_items  # noqa: E402

SEED = 20261107
N_BAD, N_GOOD, N_SCARY = 15, 10, 5
N_REPEATS = 5
MAX_CODE_CHARS = 60_000          # code included in one prompt (stated in the prompt)
MAX_FILE_CHARS = 15_000          # per file
CODE_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".pth", ".json", ".cfg",
            ".toml", ".txt", ".in", ".coffee")
PRIORITY = ("setup.py", "package.json", "pyproject.toml", "setup.cfg", "__init__.py", "index.js", "install.js",
            "preinstall.js", "postinstall.js", "main.py", "cli.py")
OUT = BENCH / "chat_ai"
PROMPTS_SUBDIR = "chat_ai_prompts"     # under the samples folder (git-ignored): known-bad prompts contain sample text
VERDICTS = ("MALICIOUS", "SUSPICIOUS", "NO_CONCERNS")

PROMPT_TEMPLATE = """You are reviewing a software package before installing it. Below are files from the {ecosystem} package \
"{package}" version {version}. Review the text only: do not run, install or import anything.

Answer in exactly this format:
VERDICT: MALICIOUS or SUSPICIOUS or NO_CONCERNS
CONFIDENCE: a number from 0 to 100
EVIDENCE: up to 3 bullet points, each citing file:line

Files ({shown} of {total} files shown; code truncated to {limit} characters in total and {per_file} per file):
{files}
"""


# ------------------------------------------------------------------ selection

def select_items(items: list[dict], seed: int = SEED) -> list[dict]:
    test = [i for i in items if i["split"] == "test"]
    bad = sorted((i for i in test if i["category"] == "known_bad" and i.get("obtainable") == "yes"), key=lambda i: i["id"])
    good = sorted((i for i in test if i["category"] == "known_good"), key=lambda i: i["id"])
    scary = sorted((i for i in test if i["category"] == "scary"), key=lambda i: i["id"])
    out = []
    for pool, n, expected in ((bad, N_BAD, "malicious"), (good, N_GOOD, "benign"), (scary, N_SCARY, "benign")):
        # a fresh generator per pool: the known-good choice does not change when the known-bad pool grows
        for i in random.Random(seed).sample(pool, min(n, len(pool))):
            out.append({"item_id": i["id"], "category": i["category"], "expected": expected, "ecosystem": i["ecosystem"],
                        "package": i["package"], "version": i["version"], "source": i.get("source", ""),
                        "sample_dir": i.get("sample_dir", "")})
    return out


def write_csv(path: Path, rows: list[dict], cols: list[str] | None = None, note: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = cols or (list(rows[0].keys()) if rows else ["empty"])
    with open(path, "w", newline="", encoding="utf-8") as fh:
        if note:
            fh.write(f"# {note}\n")
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


# ------------------------------------------------------------------ prompts

def item_files(item: dict) -> dict[str, str]:
    """Text files of the item's artifact (registry, via the benchmark cache) or of its extracted DataDog sample."""
    import run_benchmark as RB
    if item.get("source") == "datadog" or item.get("sample_dir"):
        return RB.load_sample_dir(item["sample_dir"])["text"]
    import releases
    fetch = releases.fetch_pypi if item["ecosystem"] == "PyPI" else releases.fetch_npm
    hist = fetch(item["package"], 1, None, item["version"] or None)
    if hist.get("status") != "ok" or not hist.get("releases") or hist["releases"][0].get("contents") is None:
        raise RuntimeError(f"artifact not available ({hist.get('reason') or hist['releases'][0].get('artifact_status')})")
    return hist["releases"][0]["contents"]["text"]


def build_prompt(item: dict, files: dict[str, str]) -> tuple[str, dict]:
    code = {p: t for p, t in files.items() if p.lower().endswith(CODE_EXT) or Path(p).name in PRIORITY}

    def rank(p):
        name = Path(p).name
        return (PRIORITY.index(name) if name in PRIORITY else len(PRIORITY), len(code[p]), p)

    parts, used, shown = [], 0, 0
    for p in sorted(code, key=rank):
        body = code[p][:MAX_FILE_CHARS]
        if used + len(body) > MAX_CODE_CHARS:
            body = body[: max(0, MAX_CODE_CHARS - used)]
        if not body:
            break
        numbered = "\n".join(f"{n:>5}: {line}" for n, line in enumerate(body.splitlines(), 1))
        parts.append(f"=== {p} ===\n{numbered}")
        used += len(body)
        shown += 1
    prompt = PROMPT_TEMPLATE.format(ecosystem=item["ecosystem"], package=item["package"], version=item["version"],
                                    shown=shown, total=len(code), limit=MAX_CODE_CHARS, per_file=MAX_FILE_CHARS,
                                    files="\n\n".join(parts))
    return prompt, {"files_shown": shown, "files_total": len(code), "code_chars": used,
                    "truncated": shown < len(code) or any(len(code[p]) > MAX_FILE_CHARS for p in code)}


def tool_side(rec: dict | None) -> dict:
    if not rec:
        return {"tool_status": "not in run", "tool_label": "", "tool_strict_hit": "", "tool_lenient_hit": ""}
    from metrics import LENIENT, STRICT, scored, tiers_hit
    ok = scored(rec)
    return {"tool_status": rec.get("status"), "tool_label": rec.get("label") or "",
            "tool_strict_hit": tiers_hit(rec, STRICT) if ok else "", "tool_lenient_hit": tiers_hit(rec, LENIENT) if ok else ""}


def safe_name(item_id: str) -> str:
    import re
    s = re.sub(r"[^A-Za-z0-9._-]", "_", item_id)[:80]
    return f"{s}_{hashlib.sha256(item_id.encode()).hexdigest()[:8]}"


# ------------------------------------------------------------------ summary

def chat_flag(verdict: str, op: str) -> bool | None:
    v = (verdict or "").strip().upper()
    if v not in VERDICTS:
        return None
    return v == "MALICIOUS" if op == "strict" else v in ("MALICIOUS", "SUSPICIOUS")


def summarise(scoring: list[dict], repeats: list[dict]) -> str:
    from metrics import rate_text
    L = ["# Tool vs chat AI (generated by benchmark/compare_chat_ai.py; no number typed by hand)", ""]
    for op in ("strict", "lenient"):
        L += [f"## Operating point: {op} (chat: {'MALICIOUS' if op == 'strict' else 'MALICIOUS or SUSPICIOUS'}; "
              f"tool: {'high_risk / known_malicious' if op == 'strict' else 'review or above'})", "",
              "| side | known-bad flagged | known-good flagged |", "|---|---|---|"]
        for side in ("tool", "chat"):
            bad_k = bad_n = good_k = good_n = 0
            for r in scoring:
                if side == "tool":
                    v = r.get(f"tool_{op}_hit")
                    flag = {"True": True, "False": False}.get(str(v))
                else:
                    flag = chat_flag(r.get("chat_verdict", ""), op)
                if flag is None:
                    continue
                if r["expected"] == "malicious":
                    bad_n += 1
                    bad_k += flag
                else:
                    good_n += 1
                    good_k += flag
            L.append(f"| {side} | {rate_text(bad_k, bad_n)} | {rate_text(good_k, good_n, zero_rule=True)} |")
        L.append("")
    drift, filled = [], 0
    for r in repeats:
        vs = [str(r.get(f"run_{k}", "")).strip().upper() for k in range(1, N_REPEATS + 1)]
        vs = [v for v in vs if v in VERDICTS]
        if len(vs) < 2:
            continue
        filled += 1
        c = Counter(vs)
        drift.append({"item_id": r["item_id"], "runs": len(vs), "distinct": len(c), "majority": c.most_common(1)[0][0],
                      "agreement": c.most_common(1)[0][1] / len(vs)})
    L += ["## Repeatability (same prompt, repeated runs)", ""]
    if drift:
        changed = sum(d["distinct"] > 1 for d in drift)
        L += [f"Items with a verdict that changed between runs: {rate_text(changed, filled)}.", "",
              "| item | runs | distinct verdicts | majority | agreement with majority |", "|---|---|---|---|---|"]
        L += [f"| {d['item_id']} | {d['runs']} | {d['distinct']} | {d['majority']} | {100 * d['agreement']:.0f}% |" for d in drift]
    else:
        L.append("No repeat runs filled in yet.")
    L += ["", "The tool is deterministic for a fixed ruleset and data snapshot (same input, same output); its "
          "repeatability is checked by re-running the benchmark offline from the cache."]
    return "\n".join(L) + "\n"


def read_sheet(path: Path) -> list[dict]:
    return bench_items.read_manifest(path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Tool vs chat AI comparison sheets (no API calls)")
    ap.add_argument("step", choices=("select", "prompts", "summarise"))
    ap.add_argument("--tool-run", default=str(BENCH / "runs" / "artifact-test-noosv-nofrag.jsonl"),
                    help="benchmark run for the tool columns (default: the artifact-mode headline run)")
    ap.add_argument("--samples-dir", default=None, help="samples folder (default benchmark/samples)")
    a = ap.parse_args(argv)
    os.environ.setdefault("REPOHEALTH_CACHE", str(BENCH / "cache" / "http"))
    if a.samples_dir:
        os.environ["REPOHEALTH_SAMPLES_DIR"] = str(Path(a.samples_dir).resolve())
    import run_benchmark as RB
    PROMPTS = RB.samples_root() / PROMPTS_SUBDIR
    if a.step == "select":
        items, _ = bench_items.v1_items()
        sel = select_items(items)
        write_csv(OUT / "items.csv", sel, note=f"Chat-AI comparison items, chosen by seed {SEED} before any result "
                                                f"was viewed ({N_BAD} known-bad with obtainable code, {N_GOOD} known-good, {N_SCARY} scary)")
        c = Counter(r["expected"] for r in sel)
        print(f"wrote {OUT / 'items.csv'}: {dict(c)}")
        if c.get("malicious", 0) < N_BAD:
            print(f"only {c.get('malicious', 0)} known-bad items have obtainable code; run extract_datadog.py first, "
                  "then select again (same seed, same procedure)")
        return 0
    if a.step == "prompts":
        from metrics import load_run
        sel = read_sheet(OUT / "items.csv")
        if not sel:
            print("run 'select' first", file=sys.stderr)
            return 1
        tool = load_run(a.tool_run)
        PROMPTS.mkdir(parents=True, exist_ok=True)
        scoring, repeats = [], []
        for it in sel:
            row = {"item_id": it["item_id"], "category": it["category"], "expected": it["expected"]}
            try:
                prompt, info = build_prompt(it, item_files(it))
                pfile = PROMPTS / f"{safe_name(it['item_id'])}.txt"
                pfile.write_text(prompt, encoding="utf-8")
                row.update({"prompt_file": pfile.relative_to(RB.samples_root()).as_posix(),
                            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(), **info})
            except Exception as e:
                row.update({"prompt_file": "", "prompt_sha256": "", "files_shown": 0, "files_total": 0, "code_chars": 0,
                            "truncated": "", "prompt_error": f"{type(e).__name__}: {e}"})
            row.update({"chat_ai": "", "date": "", "chat_verdict": "", "chat_confidence": "", "chat_notes": "",
                        **tool_side(tool.get(it["item_id"]))})
            scoring.append(row)
            repeats.append({"item_id": it["item_id"], **{f"run_{k}": "" for k in range(1, N_REPEATS + 1)}})
        cols = ["item_id", "category", "expected", "prompt_file", "prompt_sha256", "files_shown", "files_total",
                "code_chars", "truncated", "prompt_error", "chat_ai", "date", "chat_verdict", "chat_confidence",
                "chat_notes", "tool_status", "tool_label", "tool_strict_hit", "tool_lenient_hit"]
        for r in scoring:
            r.setdefault("prompt_error", "")
        write_csv(OUT / "scoring.csv", scoring, cols, note="Fill chat_ai, date, chat_verdict (MALICIOUS / SUSPICIOUS / "
                  "NO_CONCERNS), chat_confidence by hand; tool columns are filled from the benchmark run")
        write_csv(OUT / "repeatability.csv", repeats, note=f"Paste the SAME prompt {N_REPEATS} times (new chat each "
                  "time) and type each VERDICT")
        print(f"wrote {len(scoring)} prompts to {PROMPTS} (git-ignored) and the sheets in {OUT}")
        return 0
    text = summarise(read_sheet(OUT / "scoring.csv"), read_sheet(OUT / "repeatability.csv"))
    (OUT / "SUMMARY.md").write_text(text, encoding="utf-8")
    print(f"wrote {OUT / 'SUMMARY.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
