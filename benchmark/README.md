# Benchmark protocol (pre-registered)

Written and committed **before any benchmark scan**. Nothing in this file may be changed after test-set results have
been viewed, except by appending to `benchmark/CHANGELOG.md`, which marks the test set as **contaminated**.

| | |
|---|---|
| Frozen ruleset | **`2026.11.08-11`** (`detectors/version.py`, `RULESET_FROZEN = True`; frozen at `2026.11.07-9`, then two pre-run changes, `2026.11.08-10` and `2026.11.08-11`, see `CHANGELOG.md`; no test-split item had been scanned) |
| Protocol date | 2026-11-07 |
| Random seed | **20261107** (Python `random.Random(20261107)`), used for every random selection below |
| AI / Gemini layer | **OFF** for all benchmark runs (no key passed; the AI layer cannot change scores anyway) |

## 1. Dev set and test set

- **Dev set** (already viewed and used for tuning; never reported as held-out evidence):
  - the 8 `dev_fp` repositories of the dev sweeps: boto/boto3, pypa/twine, getsentry/sentry-python, docker/docker-py,
    paramiko/paramiko, jaraco/keyring, certbot/certbot, pypa/pip (`manifests/dev_fp.csv`);
  - the 21 "credibility" repositories. **Their list is not in this repository**; it must be supplied as
    `manifests/dev_credibility.csv` before Stage 2. (Supplied in commit 6251337, columns `repo,group`; the overlap
    check in `bench_items.py` moved 3 test items to the dev set: lodash, impacket, pwntools.) The benchmark runner refuses to score the test set while that file is
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

## 8. Harness decisions (Stage 2; fixed before any test-set item was scanned)

The scripts implement sections 1-7. Where the protocol left a choice open, it is fixed here, before any test result:

1. **Dev-set overlap** (`bench_items.py`): a test item moves to dev when its repository slug is a dev repository, or
   its normalised package name equals a dev package (dev_fp's package column, or a dev repository's name with and
   without a `-python` / `-py` / `-js` suffix or `python-` prefix). Moves are logged per item.
2. **Artifact mode input**: the artifact is passed through `repo_scan.read_repo`'s filters and limits (skipped
   vendored directories, lock files, `*.min.js`, per-file and file-count caps), except that `dist/` and `build/` are
   kept: in a release artifact they hold the shipped code.
3. **Artifact mode, not available** (reported as not_assessed, never as "no findings"): git tags/tree and commit
   history (`tagless_release`, the git part of `revival_takeover`), the release-vs-git layer (`release_vs_git`:
   its comparison target would be another release, not git), GitHub advisories, dependency advisories and Scorecard.
   Bandit is not run in artifact mode (no detector reads its findings, and it is the only scanner that writes files
   to a temporary directory).
4. **Fragility in artifact mode**: the app's `apply_gate` is used unchanged. Without a repository, the only fragility
   input is the registry maintainer count, so a single-maintainer package reaches the escalation threshold. The
   `--no-fragility-escalation` ablation reports the effect.
5. **OSV MAL- lookups** come from the OSV bulk export (`benchmark/cache/osv_mal_<eco>.json`, the same export the
   known-bad sample was drawn from), so they are pinned to a snapshot and work offline. A MAL- record without listed
   versions is range-based and is treated as affecting every version. `--no-osv` disables them (own package and the
   MAL- part of `dependency_injection`; MAL- dependency findings from the live `osv_scan` are removed in repo mode).
6. **VirusTotal is off** unless `--virustotal` is passed (key-dependent and rate-limited); it is then reported as
   not_assessed where executables exist.
7. **Repo mode** runs the app pipeline (`scan_repo`, `assess_security`, `fetch_features`, `collect_release_context`,
   `apply_gate`) without the bus-factor analysis (as `scan_batch.py`). It needs the network (GitHub is not cached).
8. **Time budget**: 300 s per item. An item that exceeds it, or fails with a timeout, HTTP 5xx, a connection error
   or an offline cache miss, is recorded as not_assessed and retried on resume. An item whose scan raised is recorded
   as not_assessed with the error (retried only with `--retry-errors`).
9. **Precision** is computed with the random known-good set only and is stated as "at this benchmark's class
   ratio". The scary and dormant sets are reported separately.
10. **Replay targets** (`--split replay`): faker 6.6.6, event-stream 3.3.5 (the publisher handover), node-ipc 11.0.0
    (adds peacenotwar); the other cases are listed as not replayable with the reason.
11. **DataDog selection**: a fresh `random.Random(20261107)` per ecosystem (pypi first), union with the candidate
    matches, path-sorted. Nested archives inside a sample are read in memory with the release-artifact reader.
    Format verified from the dataset README and the ZIP headers of one sample (ZipCrypto, password `infected`, a
    real ZIP, not a Git LFS pointer); nothing was decrypted in this session.
12. **Chat-AI comparison**: 15 known-bad with obtainable code, 10 random known-good, 5 scary, test split only, a
    fresh seeded generator per pool. Code is truncated to 60,000 characters (15,000 per file), stated in the prompt.

Amendment (Stage 2 hardening, committed before any test-set item was scanned):

13. **Artifact-mode headline: fragility escalation OFF.** In artifact mode the only fragility input is the registry
    maintainer count (item 4), so a single-maintainer package reaches the threshold on that one input. The headline
    numbers in artifact mode therefore come from the run with `--no-osv --no-fragility-escalation`. Shown beside
    them: the same run with escalation ON, labelled "artifact mode, single-input fragility (maintainer count only)",
    and the with-OSV run, labelled circular. (Seen on recorded non-benchmark data: bufferutil 4.2.0, a legitimate
    npm package, gets a review-tier `release_delta` finding for a new prebuilt binary that single-input fragility
    escalates to high_risk.) Repository mode keeps escalation ON in its headline (all fragility inputs exist there).
14. **Process isolation** (default; `--no-isolate` only for debugging): each item runs in its own spawned process
    with a hard timeout (300 s; the process is killed) and a memory cap (3072 MB: `RLIMIT_AS` on Linux, a Job
    Object on Windows; not enforced on macOS). A killed item is recorded as not_assessed ("timeout ..." is retried
    on resume, "killed ..." is final), counted in "Not scored", never as "no findings".
15. **Line cap**: lines longer than 100,000 characters are truncated before the content checks and the file is
    named in `limits_hit`. Measured before setting it: 30 adversarial single-line files of 190,000 characters (the
    largest the 200 KB per-file read limit allows) took at most 0.36 s each, so the cap is a safeguard; the hard
    per-item timeout is the backstop.
16. **Missing samples**: a DataDog sample folder that is empty (deleted or quarantined by antivirus) is recorded as
    not_assessed ("sample files missing"), never scanned as an empty package.
17. **GitHub rate limits** in repository mode are recorded as not_assessed and retried on resume (like timeouts);
    a 403 for a restricted repository is final.
18. **Samples folder**: `--samples-dir` (default `benchmark/samples`, git-ignored); sample paths in the manifests
    are relative to it, so the same folder must be passed to every script.


## 9. Running it (Windows, PowerShell)

Everything runs from the repository folder, on branch `trust-engine`, with Python 3.11 or newer. Nothing scanned is
ever executed; still, use a normal user account (not an administrator shell).

**Antivirus (Windows Defender).** Do not disable it globally. The DataDog clone and the samples folder contain real
malware as encrypted ZIPs and inert `.sample` text; Defender may quarantine some files (they then become "not
obtainable" items, which is reported, not hidden). A per-folder exclusion for exactly those two folders is at your
discretion; remove it afterwards. Use a dedicated folder such as `C:\bench\samples`, not Downloads and not a
cloud-synced folder. Never open, run or double-click anything in those folders.

The exact sequence (one snapshot date for every run, so later runs reuse the cached downloads):

```powershell
cd C:\path\to\repo-health-predictor
git checkout trust-engine; git pull
py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Remove-Item Env:GEMINI_API_KEY, Env:GOOGLE_API_KEY, Env:GOOGLE_GENAI_API_KEY -ErrorAction SilentlyContinue
$env:GITHUB_TOKEN = "<your token>"          # repo mode (5,000 GitHub API requests per hour)
$snap = "2026-11-10"                        # pick today's date once and keep it for every run below
$samples = "C:\bench\samples"               # dedicated samples folder (outside Downloads)

# 1. Self-check (under 2 minutes; never touches the test split). Fix every FAIL before going on.
python benchmark\run_benchmark.py --selfcheck --samples-dir $samples

# 2. Dev split in both modes (harness check on already-viewed items)
python benchmark\run_benchmark.py --mode artifact --split dev --snapshot $snap --samples-dir $samples
python benchmark\run_benchmark.py --mode repo --split dev --snapshot $snap

# 3. Known-bad preparation: extraction (pre-declared), known-bad item manifest, chat-AI item list. No scan.
git clone --depth 1 https://github.com/DataDog/malicious-software-packages-dataset C:\bench\dd
python benchmark\prepare_known_bad.py --datadog-dir C:\bench\dd --samples-dir $samples

# 4. Test split, artifact mode: the headline run, then the runs shown beside it, then the replay cases
python benchmark\run_benchmark.py --mode artifact --split test --snapshot $snap --samples-dir $samples --no-osv --no-fragility-escalation
python benchmark\run_benchmark.py --mode artifact --split test --snapshot $snap --samples-dir $samples --no-osv
python benchmark\run_benchmark.py --mode artifact --split test --snapshot $snap --samples-dir $samples --no-fragility-escalation
python benchmark\run_benchmark.py --mode artifact --split replay --snapshot $snap

# 5. Test split, repository mode (known-good, dormant, scary): headline without OSV, then with OSV
python benchmark\run_benchmark.py --mode repo --split test --category known_good --category dormant --category scary --snapshot $snap --no-osv
python benchmark\run_benchmark.py --mode repo --split test --category known_good --category dormant --category scary --snapshot $snap

# 6. Results: benchmark\RESULTS.md and benchmark\results\*.csv
python benchmark\metrics.py --headline benchmark\runs\artifact-test-noosv-nofrag.jsonl `
  --frag-on benchmark\runs\artifact-test-noosv.jsonl --with-osv benchmark\runs\artifact-test-nofrag.jsonl `
  --repo-run benchmark\runs\repo-test-noosv.jsonl --replay benchmark\runs\artifact-replay.jsonl

# 7. Chat-AI comparison: prompts, then fill the sheets by hand, then the summary
python benchmark\compare_chat_ai.py prompts --samples-dir $samples
python benchmark\compare_chat_ai.py summarise
```

Commit `benchmark/manifests/datadog_extracted.csv`, `datadog_members.csv`, `known_bad_items.csv`,
`benchmark/chat_ai/items.csv`, `RESULTS.md` and `benchmark/results/` (hashes, ids and numbers only). Never commit
the samples folder or the prompts.

**Stopping and resuming.** Press Ctrl+C or close the window at any time: every finished item is already saved (one
line per item in `benchmark\runs\*.jsonl`). Run the same command again to continue; finished items are skipped and
items that failed for a transient reason (timeout, HTTP 5xx, network, GitHub rate limit) are retried. A run file
refuses to be resumed with different settings (mode, ablation flags, ruleset). Each line shows
`n/total`, the elapsed time and an ETA from the running median of the item durations.

**Duration (measured, 2026-11-08, Linux sandbox, artifact mode, process isolation, fresh cache, online).** 10 dev
items (8 PyPI dev_fp packages, lodash on npm, impacket on PyPI): median 2.4 s, p95 10.4 s, max 11.1 s per item
(`metrics.py` scan-time table); the 8-item debug slice took 35 s in total; `--selfcheck` took 3 s. Not measured:
repository mode (GitHub repository downloads are blocked in the sandbox that built the harness) and the DataDog
samples (no real sample was extracted there). Projection from the measured median, not a measurement: the
test-split artifact run has 153 items with a registry artifact listed (3 known-bad, 119 known-good, 19 scary, 12 dormant) plus the
DataDog samples, so a few minutes of scanning plus the 0.5 s pause per item; the live ETA replaces this projection.
