"""Display text for the Streamlit app (pure functions, unit-tested; no scoring logic lives here).

headline_label: the Trust label shown to the user. "No findings" is only shown when the findings table is empty;
  with lower-level rows in the table it says so ("No review-tier or high-risk findings (N lower-level notes listed
  below)"). The underlying label and score are unchanged.
blast_display: what the Supply-Chain Blast Radius section may show. Only sourced numbers are shown: deps.dev
  dependent counts, with "estimate from deps.dev, <date>". The heuristic blast score/tier (stars and forks with
  hand-picked weights) and the "~N downstream forks/integrations" figure have no source and are not shown.
"""
from __future__ import annotations

from pillars import LABEL_NO_FINDINGS, PARTIAL_NOTE

TRUST_DISCLAIMER = "not a safety guarantee"
NEUTRAL_COLOR = "#6c757d"   # partial assessments: never the confident green of a complete "No findings"


def headline_label(label: str, label_base: str | None, n_table_rows: int) -> str:
    if label_base != LABEL_NO_FINDINGS or n_table_rows <= 0:
        return label
    note = "note" if n_table_rows == 1 else "notes"
    text = f"No review-tier or high-risk findings ({n_table_rows} lower-level {note} listed below)"
    return f"{text} ({PARTIAL_NOTE})" if label.endswith(f"({PARTIAL_NOTE})") else text


def blast_display(br: dict, repo: str) -> dict:
    """{"sourced": bool, "metrics": [(name, value)], "caption": str, "simulator": str | None}."""
    sourced = br.get("dependents_source") == "deps.dev"
    pkg, eco, date = br.get("package_name") or "?", br.get("ecosystem") or "?", br.get("fetched_at") or "unknown date"
    name_note = ("package name guessed from the repository name" if br.get("package_name_guessed")
                 else "package name from the published release")
    metrics = [("Package", f"{pkg} ({eco})"),
               ("Dependents (deps.dev)", f"{int(br.get('total_dependents') or 0):,}" if sourced else "not available"),
               ("Pinned deps", f"{br.get('pinned_deps', 0)} / {br.get('total_deps', 0)}"),
               ("Typosquat alerts", str(len(br.get("typosquat_alerts") or [])))]
    if sourced:
        caption = (f"Dependents: estimate from deps.dev, {date} ({int(br.get('direct_dependents') or 0):,} direct, "
                   f"{int(br.get('indirect_dependents') or 0):,} transitive); {name_note}.")
        simulator = (f"deps.dev lists {int(br.get('total_dependents') or 0):,} packages that depend on {pkg} "
                     f"({int(br.get('direct_dependents') or 0):,} direct, {int(br.get('indirect_dependents') or 0):,} "
                     f"transitive), estimate from deps.dev, {date}. A compromised release of `{repo}` could reach "
                     "them through their normal dependency updates.")
    else:
        caption = ("deps.dev had no dependent count for this package, so no downstream estimate is shown "
                   f"({name_note}). A score from stars and forks is not shown because it has no data source.")
        simulator = None
    return {"sourced": sourced, "metrics": metrics, "caption": caption, "simulator": simulator}


def trust_drivers(res: dict) -> dict:
    """What drives the Trust score, built only from values apply_gate already returned (no new computation of the
    score): the three evidence pillars with detectors ran/total and the limiting marker, the caps that apply, and
    what was not assessed. {"rows": [...], "caps": [str], "caps_line": str, "not_assessed": [str]}."""
    from pillars import MAINTENANCE_ABANDONED, MAINTENANCE_CEILING
    pillars = res.get("pillars") or {}
    limiting_pillar, kind = res.get("limiting_pillar"), res.get("limiting_kind")
    rows = []
    for name in ("Integrity", "Behavior", "Exposure"):
        p = pillars.get(name) or {}
        cov = p.get("coverage") or {}
        score = p.get("score")
        rows.append({"Pillar": name,
                     "Score": f"{score:.0f}" if isinstance(score, (int, float)) else
                              ("not applicable" if p.get("status") == "not_applicable" else "not assessed"),
                     "Detectors ran": f"{cov.get('ran', 0)}/{cov.get('total', 0)}",
                     "Limiting": "◀ limiting" if kind == "pillar" and limiting_pillar == name else ""})
    final = res.get("trust_score")
    sets = lambda v: isinstance(final, (int, float)) and isinstance(v, (int, float)) and float(v) == float(final)
    caps = []   # (text, value)
    for c in res.get("evidence_caps") or []:
        caps.append((f"evidence cap {c.get('value')}: {c.get('rule')}", c.get("value")))
    from pillars import TIER_HEADLINE_CAPS
    for tier, value in TIER_HEADLINE_CAPS.items():
        holders = [n for n in ("Integrity", "Behavior", "Exposure")
                   if any(f.get("tier") == tier for f in (pillars.get(n) or {}).get("findings") or [])]
        if holders:
            caps.append((f"{tier.replace('_', '-')} finding cap {value} ({', '.join(holders)})", value))
    m = res.get("maintenance_score")
    archived = res.get("maintenance_label") == "Archived (read-only)"
    if archived or (isinstance(m, (int, float)) and m < MAINTENANCE_ABANDONED):
        why = "repository archived" if archived else f"maintenance {m:.0f}/100, below {MAINTENANCE_ABANDONED}"
        caps.append((f"maintenance ceiling {MAINTENANCE_CEILING}: {why}", MAINTENANCE_CEILING))
    scored = [(n, (pillars.get(n) or {}).get("score")) for n in ("Integrity", "Behavior", "Exposure")]
    scored = [(n, v) for n, v in scored if isinstance(v, (int, float))]
    lowest = min(scored, key=lambda x: x[1]) if scored else None
    setting = [t for t, v in caps if sets(v)]
    if isinstance(final, (int, float)):
        if setting:
            final_text = f"final score {final:.0f} set by " + " and ".join(setting)
        elif lowest and sets(lowest[1]):
            final_text = f"final score {final:.0f} = lowest pillar ({lowest[0]} {lowest[1]:.0f})"
        else:
            final_text = f"final score {final:.0f}"
        if lowest and (setting or not sets(lowest[1])):
            final_text += f"; lowest pillar: {lowest[0]} {lowest[1]:.0f}"
    else:
        final_text = "no final score (no pillar assessed)"
    marked = [t + (f" (sets the final score, {final:.0f})" if sets(v) else "") for t, v in caps]
    caps_line = ("Caps applied: " + "; ".join(marked) + ". " if caps else "No cap applied. ") + final_text[0].upper() + final_text[1:] + "."
    caps = marked
    not_assessed = [f"{name} pillar: {(pillars.get(name) or {}).get('reason') or 'not assessed'}"
                    for name in ("Integrity", "Behavior", "Exposure")
                    if (pillars.get(name) or {}).get("status") == "not_assessed"]
    not_assessed += [f"{d['detector']}: {d.get('not_assessed_reason') or 'not assessed'}"
                     for d in res.get("detectors") or [] if d.get("status") == "not_assessed"]
    return {"rows": rows, "caps": caps, "caps_line": caps_line, "not_assessed": not_assessed}


def assessment_gaps(res: dict, language: str | None, code_scan: str | None) -> list[str]:
    """What the Trust score does NOT cover for this repository, shown next to the score: pillars that were not
    assessed (with the reason) and code that was not code-scanned (the code scan, Bandit, and the data-flow analysis
    cover Python only; pattern checks run on other languages)."""
    out = []
    for name in ("Integrity", "Behavior", "Exposure"):
        p = (res.get("pillars") or {}).get(name) or {}
        if p.get("score") is None:
            out.append(f"{name} {'not applicable' if p.get('status') == 'not_applicable' else 'not assessed'}")
    lang = (language or "").strip()
    if lang and lang.lower() != "python":
        out.append(f"{lang} code not code-scanned (the code scan covers Python only; pattern checks still ran)")
    elif code_scan in ("unavailable", "not_run"):
        out.append("Python code scan did not run")
    return out
