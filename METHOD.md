# Method

How the Trust score was measured. Every number below is quoted from `benchmark/RESULTS.md` (run 2, the headline; generated
by `benchmark/metrics.py` from the run files, with the run comparison from `benchmark/compare_runs.py`) or from the
run-2 result CSVs in `benchmark/results/run2/`; none is typed by hand. The full protocol,
fixed before any test-split scan, is `benchmark/README.md`. Limits are in [LIMITS.md](LIMITS.md).

## What was measured

- **Ruleset** `2026.11.08-12`, frozen (git tag `ruleset-2026.11.08-12-frozen`). Every change after the freeze and
  before the test run is logged in `benchmark/CHANGELOG.md` as a pre-run change; the test set is "not contaminated".
- **Seed** 20261107 for every random selection; data snapshot 2026-11-08; the AI / Gemini layer was off.
- **Unit:** one package version (known-bad) or one package (known-good, pinned at selection time).
- **Primary mode: artifact.** The release archive (sdist, wheel or npm tarball, or the extracted DataDog sample) is
  given to the content detectors as the repository contents; nothing is executed. Both classes are scanned the same
  way. **Secondary mode: repository** (the app's own pipeline) on the known-good, scary and dormant items.
- **Headline settings (artifact mode):** without the OSV MAL- lookup and without fragility escalation. The runs with
  OSV (circular, see below) and with fragility escalation are shown beside the headline.
- **Two runs, same ruleset and items.** Run 1 is superseded: Windows Defender had removed extracted sample files of
  known-bad items (136 files in 122 items, `benchmark/results/samples_missing.csv`), which biased its known-bad recall
  downward. Run 2 rescanned after the files were restored and checked against the manifests. No rule changed between
  the runs. Side by side: `benchmark/RESULTS.md`, section "Runs"; run 1 unchanged: `benchmark/RESULTS_run1.md`.

## Data

| set | how chosen | scored |
|---|---|---|
| known-bad | 300 OSV MAL- candidates (seeded) plus DataDog malicious-package samples (version-level candidate matches and a seeded random draw of 150 per ecosystem) | 314 of 611 |
| random known-good | seeded sample of the top 1000 PyPI / npm packages, released in the last 2 years | 117 of 119 |
| scary-but-legitimate | hand-picked (security tools, install scripts, minified JS) | 18 of 19 |
| dormant | popular packages without a release for 3+ years | 12 of 12 |

300 items were not scored and are listed in RESULTS.md, never imputed: 297 known-bad items whose code is not
obtainable and 3 known-good / scary artifacts over the 5 MB limit. (In run 1, 4 more known-bad samples were missing
from disk at scan time; in run 2 they were restored and scored.)

## Definitions (fixed in advance)

- **Strict hit:** at least one finding of tier high-risk or known-malicious.
- **Lenient hit:** at least one finding of tier review or above.
- **Hard false positive:** a known-good item with a high-risk / known-malicious finding or a "DO NOT USE" /
  "High-risk patterns" label. **Soft:** labelled "Review recommended".
- Rates carry a Wilson 95% interval; with 0 events, also the rule-of-three upper bound (3/n).

## Results (headline run)

| measure | result |
|---|---|
| known-bad strict recall | 12.4% (39/314; 95% CI 9.2%-16.5%) |
| known-bad lenient recall | 50.0% (157/314; 95% CI 44.5%-55.5%) |
| random known-good strict / hard false positives | 0/117 (95% CI 0.0%-3.2%; rule of three: at most 2.6%) |
| random known-good lenient (soft) false positives | 14.5% (17/117; 95% CI 9.3%-22.0%) |
| scary-but-legitimate lenient false positives | 4/18 (22.2%; 95% CI 9.0%-45.2%); strict 0/18 |
| dormant libraries with any finding or threat label | 0/12 |
| precision, strict / lenient | 100.0% (39 hits, 0 FPs) / 90.2% (157 hits, 17 FPs), **at this benchmark's class ratio 314 : 117 only**, not at real-world prevalence |

OSV-only (the MAL- lookup alone) flags 72.3% (227/314; 95% CI 67.1%-77.0%); with the detectors added, strict recall
is 77.1% (242/314) and lenient 85.0% (267/314). These numbers are circular: the known-bad labels come from OSV MAL- records, so the lookup finds what it was used to label. It is not a
fair comparison; the fair statement is how many known-bad items the detectors flag with no OSV knowledge (the headline).
Fragility escalation ON gives the same recall as OFF (12.4% / 50.0%) and one hard false positive (1/117).

Which detectors produced the hits, which detectors could not run, scan times, every miss and every false positive
with the automatic reason: `benchmark/RESULTS.md`. Root-cause buckets for every miss and false positive (rules over
measurable facts, not verified by a human): `benchmark/ERROR_ANALYSIS.md`.

## Replay cases (not held-out evidence)

The famous incidents were known when the rules were written, so they are regression checks only. Of the 5 replay rows,
3 had obtainable code: event-stream (review: publisher_change, revival_takeover), node-ipc (review:
dependency_injection) and faker (no findings); colors and ua-parser-js were not obtainable.

## Reproducing

`scripts/reproduce.ps1` / `scripts/reproduce.sh` (see `benchmark/README.md` section 9): checks the frozen tag, ruleset,
`GITHUB_TOKEN`, contamination and `--selfcheck`, then runs the sequence into `benchmark/repro/`.
