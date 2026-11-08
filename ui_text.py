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
