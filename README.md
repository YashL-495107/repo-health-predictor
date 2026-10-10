Link of the web/product: https://repo-health-predictor.streamlit.app/
# GitHub Repository Health & Abandonment Predictor

A Streamlit app that pulls **live data from the GitHub REST API** for any public repository and turns it into a
**health score (0-100)** showing whether the project is actively maintained or drifting towards abandonment.

Paste a repo URL -> get the health score, a radar chart of the contributing factors, the evidence behind each factor,
and a plain-English explanation.

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
