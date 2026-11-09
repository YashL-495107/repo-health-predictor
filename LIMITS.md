# Limits

What the Trust score and its benchmark do **not** show. Numbers are quoted from `benchmark/RESULTS.md` (run 2, the
headline) and its result files (`benchmark/results/run2/`, `benchmark/manifests/`); each limit names its source.
Threat model: [THREAT_MODEL.md](THREAT_MODEL.md). Method: [METHOD.md](METHOD.md).

## What a result means

- **Indicators, not proof.** A finding is a pattern worth a human look, not evidence of intent.
- **"No findings" never means the package is harmless.** It means none of these detectors fired on what they could
  read. The score is not a safety guarantee.
- **Strict recall is low: 12.4% (39/314; 95% CI 9.2%-16.5%)**, lenient 50.0% (157/314). Most known-bad samples are
  not flagged as high-risk. This is a triage aid to use beside OSV / registry malware feeds, not a replacement for them.
- **Precision (100.0% strict, 90.2% lenient) holds only at the benchmark's class ratio** of 314 known-bad to 117
  random known-good. Real registries have far fewer malicious packages, so real-world precision is lower and was not
  measured.
- **Dual-use code is flagged.** Security tools contain the same code as the malware they test for. In the app (repo
  mode), the dev-set repository sqlmapproject/sqlmap gets "High-risk patterns" (a credential-stealer pattern) and the
  offensive-terms cap; sqlmap is not in the benchmark (`benchmark/ERROR_ANALYSIS.md`).

## What was measured, and how

- **Recall was measured in ARTIFACT mode only** (release archives and DataDog samples given to the content detectors).
  **Repository mode, which is what the app runs, was measured on known-good, scary and dormant items only**: its
  false-positive rates (strict, lenient, hard, soft, with 95% intervals and rule-of-three bounds, same definitions as the
  artifact section) and its unscored items are in `benchmark/RESULTS.md`, section "Repo mode (what the app does)".
  **Repo-mode known-bad recall is not measured**: the known-bad items are package versions and samples without a
  repository.
- **OSV numbers are circular.** The known-bad labels come from OSV MAL- records, so OSV-only recall (72.3%, 227/314) and the with-OSV recall (77.1% strict)
  measures the label source, not the detectors. The headline excludes the OSV lookup.
- **300 items were not scored** and are never imputed: **297 known-bad items have no obtainable code** (removed from the
  registry, unpublished or replaced by a security holding package) and 3 known-good / scary artifacts were over the
  5 MB limit.
- **Antivirus removed sample files in run 1 (fixed in run 2).** After extraction, Windows Defender removed extracted
  `.sample` files of known-bad DataDog items: `benchmark/verify_samples.py` found **136 files missing in 122 items**
  (`benchmark/results/samples_missing.csv`; the Defender protection history showed 138, a count not produced by a
  repository script). 4 of those items had lost every file and were "missing from disk at scan time"; the other 118
  were scored on less code than was extracted. **Run-1 known-bad recall was therefore biased downward** (7.1% strict,
  40.3% lenient, n = 310). **Fix:** `extract_datadog.py --restore-missing` re-extracted only those files from the same
  ZIPs (ZIP and file sha256 checked against the manifests, which stayed unchanged); the samples folder got a Defender
  exclusion for exactly that folder; `verify_samples.py` then found 0 problems, before and after run 2
  (`samples_missing_after_restore.csv`, `samples_missing_after_run2.csv`). **Run 2** rescanned with the same frozen
  ruleset and no rule change (test set not contaminated): every hit it gained is in an item that had files removed, no
  hit was lost, and false-positive rates are identical. **Both runs are reported** (`benchmark/RESULTS.md`, section
  "Runs"; run 1 unchanged in `benchmark/RESULTS_run1.md` and `benchmark/results/`). Anyone re-running the benchmark on
  Windows should run `verify_samples.py` before scanning.
- **Dormant libraries:** 0/12 got a finding or a threat label in artifact mode.

## Detector coverage gaps

- **History-based detectors** (publisher_change, revival_takeover, dependency_injection, release_delta) need the
  previous release. DataDog samples have none, so they cannot be measured there: **311 scored items had no release
  history**, and dependency_injection ran on **132 of 461** scored items. They are validated only on replay incidents:
  **2 of the 3 obtainable replay incidents** were flagged (event-stream, node-ipc; faker was not). They also cause
  **7 of the 17 lenient false positives** on random known-good packages (new publisher plus revival, young new
  dependency, new prebuilt binary; `benchmark/ERROR_ANALYSIS.md`). This is a known issue for the next ruleset version;
  the frozen ruleset was not tuned on it.
- **Integrity in repo mode** is assessed only when the repository root declares a published package (PyPI `setup.py`
  / `pyproject.toml`, or an npm `package.json` not marked private); the release-vs-git comparison covers PyPI only.
  Repositories without such a root manifest (for example a private-marked monorepo root such as lodash) show
  Integrity as not assessed.
- **Code scanning covers Python only.** The code scan (Bandit) and the data-flow analysis read Python; JavaScript and
  other languages get pattern checks only. The app says so next to the score ("Partial: ... code not code-scanned").
- **DataDog coverage:** the 13 version-level candidate matches are all `malicious_intent`; the `compromised_lib`
  category (hijacked legitimate packages) is represented only by the 11 samples of the random draw
  (`benchmark/manifests/datadog_extracted.csv`), of which 0 are strict and 1 is a lenient hit
  (`benchmark/results/items.csv`). Compromised legitimate packages are therefore barely measured.
- **Scoped npm packages** are stored by DataDog as one folder `@scope@name`, while OSV and the candidates use
  `@scope/name`; they do not match, so a scoped candidate is never paired with its sample (at least one candidate,
  `@isv-occ-payment/occ-payment-service` 77.77.79, is in the dataset). Not fixed, to keep the pre-declared selection.
- **Install-time scripts without a finding:** `benchmark/ERROR_ANALYSIS.md` (run 2) lists every known-bad item with no
  finding at any tier that has a setup.py (bucket "setup.py present (normal for source packages), no hook pattern
  matched", **38 PyPI items**: pip runs setup.py for every source package, so this alone is not a sign of anything) and
  every npm item whose package.json declares an install hook (bucket "install hook declared (preinstall/postinstall),
  no finding: detector-gap candidate, cause not established", **38 npm items**). In run 1 the setup.py bucket had 42
  items; the run-1 npm count cannot be given from committed files (no run-1 npm facts file was committed, so all 122
  no-finding npm items were "not determinable"). The 38 npm items are **not an antivirus artifact**: every extracted
  file was verified present with the manifest sha256 before and after run 2, so the detectors saw the whole extracted
  sample. They are detector-gap candidates (an install hook ran code the content detectors did not match); the cause is
  not established per item and no row is human-verified.

## Threat model

See [THREAT_MODEL.md](THREAT_MODEL.md).
