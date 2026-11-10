"""Kill-chain strip (visual only): which attack stages EXISTING findings point at. No new detection, no scoring.

Stages, in order: Install-time execution -> Credential/env access -> Network exfiltration -> Persistence ->
Obfuscation. A stage is lit only when at least one finding maps to it through the fixed table MAP below; the
findings that lit it are listed on hover. Findings at info / Low level are ignored (they are notes, not indicators).

Finding shapes understood:
  content-scan findings  {"source", "rule", "sev", "file", "line", "cat"?}    (repo_scan / repo_behavior / malware_proof)
  detector findings      {"detector", "tier", "rule", "file", "line"}         (pillars of apply_gate)
  upgrade-check rows     {"area", "item", "change", "evidence"}               (upgrade_check; only "added" rows)
"""
from __future__ import annotations

import html

STAGES = ("Install-time execution", "Credential/env access", "Network exfiltration", "Persistence", "Obfuscation")

# (stage, field, value): a finding maps to the stage when finding[field] == value. "rule_prefix" matches the start of
# finding["rule"]. Fixed table, tested in tests/test_killchain.py.
MAP = (
    ("Install-time execution", "cat", "Install-time execution"),
    ("Install-time execution", "detector", "setup_py_hook"),
    ("Install-time execution", "source", "Layer 2: Static setup.py Check"),
    ("Install-time execution", "area", "Install hooks"),
    ("Credential/env access", "cat", "Credential access"),
    ("Credential/env access", "detector", "credential_exfiltration"),
    ("Credential/env access", "rule_prefix", "Credential-stealer pattern"),
    ("Credential/env access", "rule_prefix", "Credential access:"),
    ("Credential/env access", "area", "Credential/env access"),
    ("Network exfiltration", "cat", "Network"),
    ("Network exfiltration", "cat", "Remote shell"),
    ("Network exfiltration", "detector", "credential_exfiltration"),
    ("Network exfiltration", "rule_prefix", "Credential-stealer pattern"),
    ("Network exfiltration", "rule_prefix", "Network:"),
    ("Network exfiltration", "rule_prefix", "Backdoor / reverse shell"),
    ("Network exfiltration", "area", "Network exfiltration"),
    ("Persistence", "cat", "Persistence"),
    ("Persistence", "rule_prefix", "Persistence:"),
    ("Persistence", "rule_prefix", "Hidden persistence payload"),
    ("Persistence", "area", "Filesystem persistence"),
    ("Obfuscation", "cat", "Obfuscation"),
    ("Obfuscation", "detector", "decoded_payload"),
    ("Obfuscation", "source", "Layer 1: AST De-obfuscator"),
    ("Obfuscation", "rule_prefix", "Obfuscation:"),
    ("Obfuscation", "rule_prefix", "Dropper / loader pattern"),
    ("Obfuscation", "rule_prefix", "Hidden persistence payload"),
    ("Obfuscation", "area", "Decoding/obfuscation"),
)
IGNORED_LEVELS = {"info", "low"}


def stages_for(f: dict) -> list[str]:
    """Stages one finding maps to (possibly none), in STAGES order."""
    if str(f.get("sev") or f.get("tier") or "").lower() in IGNORED_LEVELS:
        return []
    if "change" in f and f.get("change") != "added":      # upgrade rows: only what the new version adds
        return []
    hit = set()
    for stage, field, value in MAP:
        if field == "rule_prefix":
            if str(f.get("rule") or "").startswith(value):
                hit.add(stage)
        elif f.get(field) == value:
            hit.add(stage)
    return [s for s in STAGES if s in hit]


def label(f: dict) -> str:
    where = f.get("file") or ""
    if where and f.get("line"):
        where = f"{where}:{f['line']}"
    text = f.get("rule") or f.get("item") or f.get("cat") or "finding"
    src = f.get("detector") or f.get("source") or f.get("area") or ""
    return " · ".join(x for x in (str(text), str(where or f.get("evidence") or ""), str(src)) if x)


def killchain(findings: list[dict]) -> list[dict]:
    """[{"stage", "lit", "findings": [labels]}] for every stage, in order."""
    by = {s: [] for s in STAGES}
    for f in findings or []:
        for s in stages_for(f):
            lab = label(f)
            if lab not in by[s]:
                by[s].append(lab)
    return [{"stage": s, "lit": bool(by[s]), "findings": by[s]} for s in STAGES]


def strip_html(chain: list[dict], max_listed: int = 8) -> str:
    """The strip as HTML (styles: .rh-kc* in the app's CSS). Hover (title attribute) lists the findings."""
    cells = []
    for i, c in enumerate(chain):
        if c["lit"]:
            listed = c["findings"][:max_listed]
            more = len(c["findings"]) - len(listed)
            tip = "\n".join(listed) + (f"\n… and {more} more" if more else "")
            cls, mark = "rh-kc rh-kc-on", f"● {len(c['findings'])}"
        else:
            tip, cls, mark = "No finding maps to this stage", "rh-kc", "○"
        cells.append(f"<div class='{cls}' title='{html.escape(tip, quote=True)}'><span class='rh-kc-mark'>{mark}</span> "
                     f"{html.escape(c['stage'])}</div>")
        if i < len(chain) - 1:
            cells.append("<div class='rh-kc-arrow'>→</div>")
    return "<div class='rh-kc-row'>" + "".join(cells) + "</div>"


CAPTION = ("Kill-chain strip (visual only): a stage is lit only when an existing finding maps to it (hover to see "
           "which). Indicators, not proof; an unlit stage does not mean that stage is absent.")
