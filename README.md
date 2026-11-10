Link of the web/product: https://repo-health-predictor.streamlit.app/
# GitHub Repository Health & Abandonment Predictor

A Streamlit app that pulls **live data from the GitHub REST API** for any public repository and turns it into a
**health score (0-100)** showing whether the project is actively maintained or drifting towards abandonment.

Paste a repo URL -> get the health score, a radar chart of the contributing factors, the evidence behind each factor,
and a plain-English explanation.

## Trust score and benchmark (frozen ruleset 2026.11.08-12)

Next to the maintenance health score, the app shows a **Trust score (0-100, indicators, not proof;
not a safety guarantee)**: the weakest of three evidence pillars (Integrity, Behavior, Exposure) from static detectors, then evidence
caps. It was benchmarked once on a held-out test set with a frozen ruleset (git tag `ruleset-2026.11.08-12-frozen`).
Headline: the **behavior detectors only** row (artifact mode, no OSV lookup, run 2). The other two rows are upper bounds,
because the known-bad labels come from the same OSV MAL- records the lookup uses (circular). From `benchmark/RESULTS.md`
and `benchmark/results/run2/`:

| layer (known-bad samples, artifact mode) | strict | lenient | what it means |
|---|---|---|---|
| Known-malware database (OSV MAL- lookup) alone | 72.3% (227/314) | n/a (no tiers) | upper bound: the known-bad labels come from the same database (circular) |
| **Behavior detectors only (never-seen malware): headline** | 12.4% (39/314; 95% CI 9.2%-16.5%) | 50.0% (157/314; 95% CI 44.5%-55.5%) | the fair measure of detecting new malware |
| Full system as the app runs (detectors + OSV) | 77.1% (242/314; 95% CI 72.1%-81.4%) | 85.0% (267/314; 95% CI 80.7%-88.6%) | upper bound, same caveat (circular) |

| false positives | result |
|---|---|
| random known-good strict / hard false positives | 0/117 (rule of three: at most 2.6%) |
| random known-good lenient false positives | 14.5% (17/117) |
| scary-but-legitimate lenient false positives | 4/18 |
| dormant libraries flagged | 0/12 |

All numbers, with the repository-mode false-positive rates, are on the app's **How accurate is it?** page.

**Run 2 is the headline; run 1 is superseded.** In run 1, Windows Defender had removed extracted `.sample` files
of known-bad DataDog items (136 files in 122 items, measured by `benchmark/verify_samples.py`), so run-1 known-bad recall
was biased downward: 7.1% strict (22/310) and 40.3% lenient (125/310). Run 2 rescanned the same items with the same
frozen ruleset after `extract_datadog.py --restore-missing` restored the files (sha256 checked against the manifests)
and with a Defender exclusion for the samples folder only. False-positive rates are identical in both runs. Both runs
are reported: `benchmark/RESULTS.md`, section "Runs", and [LIMITS.md](LIMITS.md).

These are artifact-mode numbers. For what the app does (repository mode), see `benchmark/RESULTS.md`,
section "Repo mode (what the app does)": false-positive rates on the known-good, scary and dormant sets.
Repo-mode known-bad recall is not measured. 300 items were not scored (297 known-bad without obtainable code). Precision holds only at the benchmark's class
ratio (314 : 117), not real-world prevalence. Strict recall is low: use this as a triage aid beside OSV, not a
replacement. Read [METHOD.md](METHOD.md), [LIMITS.md](LIMITS.md), [THREAT_MODEL.md](THREAT_MODEL.md), `benchmark/RESULTS.md` and
`benchmark/ERROR_ANALYSIS.md` before quoting any number. Reproduce with `scripts/reproduce.ps1 -Quick` (PowerShell)
or `scripts/reproduce.sh --quick` (bash); see `benchmark/README.md` section 9.

### Version 2 (fresh test set)

Not the headline: **v1 above stays the official result.** Ruleset v2 (`2026.11.10-v2`, branch `ruleset-v2`) adds install-hook target tracing for npm and a deeper setup.py check. It was developed after viewing run 2, frozen (tag `ruleset-2026.11.10-v2-frozen`) and pre-registered (`benchmark/PREREG_v2.md`) before a fresh test set was scanned by both rulesets: 300 new DataDog samples (no package shared with the v1 sets; 298 scanned) and 120 new random known-good packages (116 scanned). Artifact mode, no OSV lookup, no fragility escalation. From `benchmark/RESULTS_v2.md` and `benchmark/results/fresh/`:

| fresh test set | v1 (official) | v2 |
|---|---|---|
| Recall, strict: excluding near-duplicates of the v2 development items (headline) | 15.0% (41/274; 95% CI 11.2%-19.7%) | 23.7% (65/274; 95% CI 19.1%-29.1%) |
| Recall, lenient: excluding near-duplicates of the v2 development items (headline) | 54.0% (148/274; 95% CI 48.1%-59.8%) | 60.6% (166/274; 95% CI 54.7%-66.2%) |
| Recall, strict: all fresh known-bad | 13.8% (41/298; 95% CI 10.3%-18.1%) | 27.9% (83/298; 95% CI 23.1%-33.2%) |
| Recall, lenient: all fresh known-bad | 51.3% (153/298; 95% CI 45.7%-57.0%) | 62.8% (187/298; 95% CI 57.1%-68.0%) |
| Hard false positives, fresh random known-good | 0.0% (0/116; 95% CI 0.0%-3.2%); rule of three: at most 2.6% | 0.0% (0/116; 95% CI 0.0%-3.2%); rule of three: at most 2.6% |
| Soft false positives (Review recommended) | 10.3% (12/116; 95% CI 6.0%-17.2%) | 10.3% (12/116; 95% CI 6.0%-17.2%) |

Headline subset: excluding near-duplicates of the v2 development items (24 near-duplicates removed; v2 strict recall differs by 4.1 points between the subsets, pre-registered threshold 3). 0 of 120 fresh known-good packages have an npm install script, so the fresh set gives no false-positive evidence for the new install-hook tracer; that evidence rests on the v1 install-hook packages checked before the freeze (development data).

## Run it

```bash
pip install -r requirements.txt
cp .env.example .env          # then paste your GitHub token into .env
streamlit run app.py
```

**GitHub token (recommended):** GitHub -> Settings -> Developer settings -> Personal access tokens -> generate
(no scopes needed for public repos). Without a token the API allows 60 requests/hour (~7 repos); with one, 5,000/hour.
You can also paste the token into the app's sidebar. Never commit `.env`.

## How the health score works

Five explainable factors, each scored 0-100, combined with fixed weights:

| Factor | Weight | Scored from |
|---|---|---|
| Commit recency | 25 | Days since last commit (100 within 14 days -> 0 at 365 days) |
| Commit activity & trend | 20 | Commits in last 12 weeks (log scale) + trend vs earlier in the year |
| Issue responsiveness | 20 | Median days to close issues + share of issues that are closed |
| Pull request activity | 15 | PRs merged in the last 180 days (log scale) |
| Contributor activity | 20 | Distinct human authors in the last 180 days + trend vs the previous 180 days |

- Bot accounts (e.g. dependabot) are ignored when counting contributors.
- If a factor does not apply (issues disabled, no PR history) it is dropped and the other weights are rescaled,
  so a repo is not punished for missing data.
- Archived repositories are capped at 15.
- Bands: **Healthy** 70+, **Slowing down** 40-69, **Likely abandoned** below 40.

Thresholds and weights live at the top of `scoring.py` and are easy to tune.

## Project structure

| File | Purpose |
|---|---|
| `app.py` | Streamlit UI (input, health score, radar chart, factor table, explanation) |
| `github_client.py` | GitHub API client: rate-limit handling, 202-retry for commit stats, feature extraction |
| `scoring.py` | Health score formula + plain-English explanation |
| `collect_data.py` | Batch-scores every repo in `repos.csv` -> `data/dataset.csv` (resumable) |
| `repos.csv` | Repos to collect, across web frameworks, CLI tools and ML libraries (mix of active and stale) |
| `tests/` | Unit tests for scoring, a mocked end-to-end test of data extraction, and a UI smoke test |

Run the tests: `python tests/test_scoring.py && python tests/test_client_mock.py && python tests/test_app.py`

## Limitations

- The health score measures **maintenance activity**, not code quality. A finished, stable library can score low
  simply because nothing needs changing.
- Issue and PR statistics use the 100 most recently updated items, so very large projects are sampled, not exhaustively counted.
- Weights and thresholds are expert-chosen; `collect_data.py` produces a dataset to validate and calibrate them.

## Team

| Role | Area |
|---|---|
| Data collection | `github_client.py`, `collect_data.py`, `repos.csv` |
| Analysis & modelling | `scoring.py`, validation on `data/dataset.csv` |
| App | `app.py`, visuals, demo |
