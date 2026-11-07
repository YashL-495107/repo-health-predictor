"""Summarise a scan_batch.py CSV: flag rates, every flagged repo with its reasons, not-scanned repos, timing and errors.

"Not scanned" (ran=False) is always reported separately from "scanned and clean".
Works with older CSVs that lack some columns (missing counts are treated as 0 / unknown).
"""
from __future__ import annotations

import argparse
import sys

import pandas as pd


def _bool(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


def load(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df.attrs["missing"] = [c for c in ("known_malicious_count", "high_risk_pattern_count", "osv_mal", "flagged") if c not in df.columns]
    for col in ("known_malicious_count", "high_risk_pattern_count", "strong", "seconds"):
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0) if col in df.columns else 0
    for col in ("flagged", "skipped_reason", "error", "group"):
        df[col] = df[col].fillna("").astype(str) if col in df.columns else ""
    df["ran"] = df["ran"].map(_bool) if "ran" in df.columns else False
    df["osv_mal"] = df["osv_mal"].map(_bool) if "osv_mal" in df.columns else False
    df["is_flagged"] = (df["known_malicious_count"] > 0) | (df["high_risk_pattern_count"] > 0) | df["osv_mal"]
    return df


CANONICAL = ("timeout", "too large", "not found", "refused")


def normalise_reason(reason: str, error: str = "") -> str:
    """Map old free-text reasons onto: timeout, too large, not found, refused, other: <type>."""
    r = str(reason or "").strip()
    if r in CANONICAL or r.startswith("other: "):
        return r
    low = r.lower()
    if "timed out" in low or "timeout" in low: return "timeout"
    if "larger than" in low or "uncompressed" in low: return "too large"
    if "not found" in low: return "not found"
    if "refused" in low or "rate-limited" in low: return "refused"
    if error: return f"other: {error}"
    return f"other: {r[:60]}" if r else "other: unknown"


def summary(df: pd.DataFrame) -> dict:
    ran = df[df["ran"]]
    secs = ran["seconds"] if len(ran) else df["seconds"]
    return {
        "repos": len(df),
        "scanned": len(ran),
        "not_scanned": int((~df["ran"]).sum()),
        "errors": int((df["error"] != "").sum()),
        "known_malicious": int((df["known_malicious_count"] > 0).sum()),
        "high_risk": int((df["high_risk_pattern_count"] > 0).sum()),
        "osv_mal": int(df["osv_mal"].sum()),
        "flagged": int(df["is_flagged"].sum()),
        "scanned_clean": int((df["ran"] & ~df["is_flagged"]).sum()),
        "median_s": float(secs.median()) if len(secs) else 0.0,
        "p95_s": float(secs.quantile(0.95)) if len(secs) else 0.0,
    }


def _print_summary(title: str, s: dict):
    pct = lambda n: f"{n / s['scanned']:.1%}" if s["scanned"] else "n/a"
    print(f"\n== {title} ==")
    print(f"Repos in file:            {s['repos']}")
    print(f"Scanned:                  {s['scanned']}")
    print(f"Not scanned (ran=False):  {s['not_scanned']}   (of which scan errors: {s['errors']})")
    print(f"known_malicious > 0:      {s['known_malicious']} ({pct(s['known_malicious'])} of scanned)")
    print(f"high_risk > 0:            {s['high_risk']} ({pct(s['high_risk'])} of scanned)")
    print(f"OSV MAL- match:           {s['osv_mal']}")
    print(f"Flagged (any of above):   {s['flagged']}")
    print(f"Scanned and clean:        {s['scanned_clean']}")
    print(f"Scan time (scanned repos): median {s['median_s']:.1f}s, p95 {s['p95_s']:.1f}s")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/scan_results.csv")
    args = ap.parse_args(argv)
    df = load(args.input)
    if df.attrs["missing"]:
        print(f"WARNING: {args.input} has no column(s) {', '.join(df.attrs['missing'])} (written by an older scan_batch.py). "
              "Flag counts below treat them as 0, so 'scanned and clean' is NOT measured for those repos. "
              "Rescan with the current scan_batch.py into a new --output file.")

    _print_summary(f"All repos ({args.input})", summary(df))
    groups = sorted(g for g in df["group"].unique() if g)
    for g in groups:
        _print_summary(f"Group {g}", summary(df[df["group"] == g]))

    pd.set_option("display.max_colwidth", None, "display.width", 250)
    flagged = df[df["is_flagged"]]
    print(f"\n== Flagged repos ({len(flagged)}): review each by hand ==")
    if len(flagged):
        cols = [c for c in ("repo", "group", "known_malicious_count", "high_risk_pattern_count", "osv_mal", "flagged") if c != "group" or groups]
        print(flagged[cols].to_string(index=False))
        if "flagged" in df.columns and (flagged["flagged"] == "").any():
            print("(empty 'flagged' text: this CSV was written by an older scan_batch.py; rescan to get reasons)")
    else:
        print("none")

    skipped = df[~df["ran"]]
    print(f"\n== Not scanned ({len(skipped)}): NOT the same as clean ==")
    if len(skipped):
        reason = skipped["skipped_reason"].where(skipped["skipped_reason"] != "", skipped.get("note", pd.Series("", index=skipped.index)).fillna("").astype(str))
        out = pd.DataFrame({"repo": skipped["repo"], "error": skipped["error"], "skipped_reason": [normalise_reason(r, e) for r, e in zip(reason, skipped["error"])]})
        counts = out["skipped_reason"].value_counts()
        print("Count per reason:")
        for r, n in counts.items():
            print(f"  {n:4d}  {r}")
        for r in counts.index:
            grp = out[out["skipped_reason"] == r]
            print(f"\n-- {r} ({len(grp)}) --")
            print(grp[["repo", "error"]].to_string(index=False))
    else:
        print("none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
