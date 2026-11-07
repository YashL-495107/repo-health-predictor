# Benchmark protocol (pre-registered)

Written and committed **before any benchmark scan**. Nothing in this file may be changed after test-set results have
been viewed, except by appending to `benchmark/CHANGELOG.md`, which marks the test set as **contaminated**.

| | |
|---|---|
| Frozen ruleset | **`2026.11.07-9`** (`detectors/version.py`, `RULESET_FROZEN = True`) |
| Protocol date | 2026-11-07 |
| Random seed | **20261107** (Python `random.Random(20261107)`), used for every random selection below |
| AI / Gemini layer | **OFF** for all benchmark runs (no key passed; the AI layer cannot change scores anyway) |

## 1. Dev set and test set

- **Dev set** (already viewed and used for tuning; never reported as held-out evidence):
  - the 8 `dev_fp` repositories of the dev sweeps: boto/boto3, pypa/twine, getsentry/sentry-python, docker/docker-py,
    paramiko/paramiko, jaraco/keyring, certbot/certbot, pypa/pip (`manifests/dev_fp.csv`);
  - the 21 "credibility" repositories. **Their list is not in this repository**; it must be supplied as
    `manifests/dev_credibility.csv` before Stage 2. The benchmark runner refuses to score the test set while that file is
    missing. Any test-set item that matches a credibility repository or package is moved to the dev set **before**
    scoring (by name, deterministic), and the move is logged in the run output.
  - Also treated as viewed, so excluded from the test set: every repository in `data/scan_results.csv`,
    `data/scan_holdout.csv`, `data/backtest_repos.csv` and `data/backtest_skipped.csv` (scanned or inspected in earlier
    sessions with earlier rulesets), and the benchmark regression fixtures (`benchmark_fixtures/`).
- **Test set** = every other item in the manifests below, chosen by the seed **before any result is viewed**.
- **Harness-debug slice**: at most 10 items, drawn from the DEV set only (`manifests/debug_slice.csv`). Scripts are
  debugged on this slice. Test items are never used to debug scripts.
- **Replay / regression cases**: the five famous incidents (section 6) were known when the rules were written. They are
  reported separately as replay / regression cases, never as held-out evidence.

## 2. Unit of evaluation and scan modes

- An item is one **package version** (ecosystem, name, version) for known-bad items, and one **package** (latest
  release at selection time, pinned in the manifest) for known-good items.
- **Primary mode: artifact.** For every item (known-bad and known-good alike) the release artifact (sdist / wheel /
  npm tarball, at most 5 MB, read in memory) is given to the content detectors as the repository contents; the release
  detectors use the registry history when it is still listed. GitHub-dependent signals are not available in this mode and
  are reported as not_assessed. Both classes are scanned the same way, so false-positive and recall numbers compare like
  with like.
- **Secondary mode: repository** (known-good and dormant items only): the full app pipeline on the package's GitHub
  repository (trust label, pillars, fragility). Used for the dormant-library check and the soft false-positive rate.
- Samples are inert text only (section 5). Nothing is ever executed, imported or installed.

## 3. Definitions (fixed in advance)

- **Hit, strict**: the item has at least one finding of tier `high_risk` or `known_malicious`.
- **Hit, lenient**: at least one finding of tier `review` or above.
- **Miss**: a known-bad item that is not a hit at that operating point (reported separately for strict and lenient).
- **Hard false positive**: a known-good item with a `high_risk` or `known_malicious` finding, or a trust label starting
  "DO NOT USE" or "High-risk patterns".
- **Soft false positive**: a known-good item labelled "Review recommended".
- **Dormant libraries** are expected to read "Fragile / unmaintained". They count as a (hard) false positive only if
  they reach a threat label (DO NOT USE / High-risk patterns); "Review recommended" on a dormant library is a soft false
  positive like any other.
- Items whose artifact could not be obtained are **not scored** (they are counted and listed, never padded or imputed).

## 4. Metrics (all with sample sizes next to every percentage)

- Per detector and overall: hits, misses, false positives, precision, recall, at both operating points.
- False-positive rate with a **Wilson 95% interval**; when there are 0 false positives, also the **rule-of-three** upper
  bound (3/n).
- Per-detector contribution: how many hits each detector produced alone and in combination.
- Scan-time distribution (median, p95, max) per mode.
- Fraction of items where each detector was `not_assessed`, with reasons.
- "Misses and why" and "False positives and why" sections listing every case.

## 5. Ablations

- **With and without the OSV MAL- lookup** (`osv_known_malicious` and the MAL- part of `dependency_injection`). OSV
  MAL- advisories are also how most known-bad items are labelled, so results WITH it are circular; the headline numbers
  are reported WITHOUT it, and the with-OSV numbers only next to them.
- **With and without fragility escalation** (Integrity review -> high_risk).

## 6. Data selection (manifests in `manifests/`, each with seed, method and date)

- **Known-bad** (`known_bad_candidates.csv`): MAL- advisories from the OSV bulk export (PyPI and npm; source: the
  OpenSSF malicious-packages project) and the DataDog malicious-software-packages dataset manifests. Seeded random
  sample. For each item record whether code is obtainable (registry file still published, or a dataset sample); report
  that number and do not pad. Samples are stored only under `benchmark/samples/` (git-ignored), as inert text renamed
  with a `.sample` extension; executable types (.exe, .dll, .so, .dylib, .bin) are skipped. Only manifests (id,
  ecosystem, source URL, hash) are committed.
- **Known-bad code from the DataDog dataset** (added in Stage 1, before any result was viewed). The registry check
  found that only 3 of the 300 sampled MAL- versions are still published, so code comes mainly from the DataDog
  dataset, whose sample paths can only be listed on a machine with GitHub access. Method, fixed now: list
  `samples/{pypi,npm}/**.zip` from a local clone of the dataset; take every sample whose (ecosystem, package) appears in
  `known_bad_candidates.csv`, plus a random sample of 150 sample files per ecosystem with `random.Random(20261107)` over
  the path-sorted listing; extract in memory with the dataset's password, keep text members only (renamed `.sample`,
  executables skipped), never write executables and never run anything. Record the dataset commit hash in the manifest.
- **Replay / regression cases** (`replay_incidents.csv`): event-stream/flatmap-stream, ua-parser-js, colors/faker,
  node-ipc, xz-utils. Each verified from a primary source (advisory) with its URL and the malicious change; marked
  "replayable" or "not replayable" with the reason. Never reconstructed or simulated.
- **Known-good** (`known_good.csv`): at least 100 widely used, maintained packages: a seeded random sample from the top
  1000 of hugovk/top-pypi-packages (PyPI download ranking) and the top 1000 of wooorm/npm-high-impact (npm high-impact
  list), excluding the dev set and viewed repositories. Plus `known_good_dormant.csv` (at least 10 finished/dormant
  libraries: popular packages whose latest release is more than 3 years before the protocol date, seeded scan of the same
  lists) and `known_good_scary.csv` (security tools, build tools with install scripts, projects that vendor or ship
  minified/obfuscated JS; a hand-picked judgement sample, documented as such).

## 7. Procedure

1. Commit this protocol (done before any scan).
2. Build manifests (`select_items.py`, seeded). Commit manifests and `SOURCES.md`.
3. Stage 2: write the runner and metrics; smoke-test on the dev debug slice only.
4. Full run on the test set, once, with the frozen ruleset, on a machine with network access. Results go to
   `RESULTS.md` and CSVs, with ruleset version, date, data snapshot (http_cache snapshot date) and seed.
5. Any rule change after step 4 -> `CHANGELOG.md`, and the test set is marked contaminated.
