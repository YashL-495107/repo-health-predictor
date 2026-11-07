# Project capabilities

Status as of ruleset `2026.11.07-1` (branch `trust-engine`, end of Phase 1). This file says what is built, what is
measured and what is not yet measured. Every number here comes from a script in this repository; anything without
a script behind it is marked "not yet measured".

The full plan is in [docs/PLAN.md](docs/PLAN.md).

## What the headline means

The headline is the **Trust score** ("indicators, not proof"), 0-100. It asks "how much evidence of a problem did
our checks find?", not "is anyone maintaining this?". No findings is the strongest statement the tool makes; it
does not mean the code has no problems.

Four pillars (`pillars.py`):

| Pillar | Source | In the headline? |
|---|---|---|
| Maintenance | `scoring.compute_health_score` (formula unchanged) | Only as a ceiling: below 40 or archived -> headline at most 50. It never lowers the headline below 50 on its own. |
| Integrity | detectors with pillar "Integrity" | yes (weakest link) |
| Behavior | detectors with pillar "Behavior" | yes (weakest link) |
| Exposure | detectors with pillar "Exposure" | yes (weakest link) |

Pillar rule (Integrity, Behavior, Exposure): start at 100; known_malicious -> at most 10; high_risk -> -35 each
(not below 20 once there are 2 or more); review -> -8 each, at most -30 in total. One location counts once per
tier inside a pillar. A pillar is `None` when none of its detectors ran: "not assessed" if they failed, "not
applicable" (for example "no published package") if they do not apply.

Headline = the lowest assessed pillar, then: any high_risk finding caps it at 49 and any known_malicious at 15
(mirroring the existing caps), the maintenance ceiling (50), and the existing evidence caps from `security.py`
(known malicious 15; high-risk pattern 49; strong secret / CI finding 49; unpatched advisory or 3+ vulnerable
dependencies 49; vulnerable dependencies 69; offensive-security terms 59). The lowest value wins and the result
names its cause: "limited by Integrity: ...", "limited by Maintenance: ..." or "capped by evidence rule: strong
secret".

Labels: DO NOT USE: known malicious indicator > High-risk patterns: review before use > Review recommended >
Fragile / unmaintained > No findings. "(Partial assessment)" is added when a pillar could not be assessed or a
detector only read part of the repository (for example "partial scan: 1500 of 2300 text files"). "Not assessed"
when no evidence pillar could be assessed.

**Intended behavior change in Phase 1:** `apply_gate` used to skip every evidence cap for repositories labelled
"Likely abandoned" or "Archived". That exception is removed: an abandoned repository with a known-malicious or
high-risk finding is now capped like any other.

## Detectors (Phase 1)

All twelve Phase 1 detectors are **adapters around checks that already existed**. They reuse the findings of the
existing engine and do not compute anything new, so results on the existing fixtures are unchanged.

**Honest note on tiers:** in Phase 1, the `high_risk` tier comes from the existing engine's "strong" findings
(decoded payloads that reach exec, setup.py exec + network, same-file intent patterns such as credential read +
exfil endpoint, release-vs-git drift with new capabilities), mapped by `detectors/base.py:legacy_tier`. It is
**not** produced by new multi-signal, attack-specific detectors; those are planned for Phases 2-4.

| Detector | Pillar | Wraps | Tier mapping |
|---|---|---|---|
| release_vs_git | Integrity | Layer 4 release-to-git AST diff (PyPI wheel < 5 MB) | strong -> high_risk |
| decoded_payload | Behavior | Layer 1 static decoder | strong -> high_risk, review decodes -> review |
| setup_py_hook | Behavior | Layer 2 static setup.py check | strong -> high_risk, Medium -> review |
| behavior_patterns | Behavior | behavior scan (indicators + same-file patterns) | pattern -> high_risk, indicator -> review |
| osv_known_malicious | Exposure | OSV MAL- for pinned deps and the own package's latest version | known_malicious |
| osv_advisories | Exposure | unpatched GitHub advisories, OSV dependency vulnerabilities | review |
| scorecard | Exposure | OpenSSF Scorecard overall score | below 4/10 -> review |
| lookalike_name | Exposure | behavior scan name-similarity check | review |
| committed_binary | Exposure | behavior scan committed-executable check | review |
| virustotal | Exposure | Layer 3 VirusTotal hash lookup (needs VT_API_KEY) | 5+ engines -> known_malicious, 1-4 -> review |
| repo_secrets | Exposure | secret scan | strong -> review (the 49 evidence cap still applies) |
| ci_workflow | Exposure | GitHub Actions checks | High/Medium -> review (the 49 cap still applies for High) |

Each detector's docstring lists what it detects, known evasions and false-positive sources. Every finding is
stamped with the ruleset version. Detectors run in parallel within a 30 s overall budget; a crash or timeout
gives `not_assessed` with the reason, never a crash of the scan and never "no findings".

Bandit code findings stay in the findings table but do not feed a pillar.

## Fragility index (`fragility.py`)

0-100, higher = more fragile: 45% (100 - maintenance score), 25% bus factor (1 -> 100, 2 -> 60, 3 -> 30, 4+ -> 0),
15% dormancy (days since last commit / 730), 15% silent departure of the top maintainer. Missing parts are
dropped and the weights rescaled. Publisher/maintainer count is **not available** until registry release data is
added (Phase 2).

**These weights and the escalation threshold (60) are unvalidated design choices**, set by hand and not fitted
or measured. At 60 or more, a review-tier finding from an Integrity detector is escalated to high_risk and marked
`fragility_amplified` with a plain-language reason. It never escalates to known_malicious.

In Phase 1, time-based signals use the scan time as `as_of`; release upload times arrive with Phase 2.

## What is measured

| Measurement | Script | Result | Caveat |
|---|---|---|---|
| Fixture benchmark: 5 inert malicious samples, 4 benign look-alikes | `python benchmark_fixtures.py` | 5/5 detected, 0/4 benign flagged | Hand-written fixtures, known when the rules were written. This is a regression check, not held-out evidence. |
| Maintenance score backtest | `backtest_collect.py`, `backtest_analyze.py` | see `data/backtest_summary.csv` | Measures the maintenance score only, not the Trust score. |

## Not yet measured

- Per-detector precision, recall and false-positive rate: **not yet measured** (Phase 5 benchmark).
- The Trust score on real packages, known-bad or known-good: **not yet measured**.
- The fragility weights and threshold: **not validated**.
- Release-based, dependency, takeover and data-flow detectors: **not built yet** (Phases 2-4).

## Tests

- `python -m pytest tests` (needs `pip install -r requirements-dev.txt`): contract, pillars, fragility,
  wording rule, consumers, app smoke test.
- `python verify_phase4_reality.py`: offline end-to-end checks of the detectors, AI layer and batch tools.
- `python benchmark_fixtures.py`: the fixture benchmark above.
