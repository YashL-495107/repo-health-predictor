# Limits

What the Trust score and its benchmark do **not** show. Numbers are quoted from `benchmark/RESULTS.md` and the result
files next to it (`benchmark/results/`, `benchmark/manifests/`); each limit names its source. Method: [METHOD.md](METHOD.md).

## What a result means

- **Indicators, not proof.** A finding is a pattern worth a human look, not evidence of intent.
- **"No findings" never means the package is harmless.** It means none of these detectors fired on what they could
  read. The score is not a safety guarantee.
- **Strict recall is low: 7.1% (22/310; 95% CI 4.7%-10.5%)**, lenient 40.3% (125/310). Most known-bad samples are
  not flagged as high-risk. This is a triage aid to use beside OSV / registry malware feeds, not a replacement for them.
- **Precision (100.0% strict, 88.0% lenient) holds only at the benchmark's class ratio** of 310 known-bad to 117
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
- **OSV numbers are circular.** The known-bad labels come from OSV MAL- records, so the with-OSV recall (74.5% strict)
  measures the label source, not the detectors. The headline excludes the OSV lookup.
- **304 items were not scored** and are never imputed: **297 known-bad items have no obtainable code** (removed from the
  registry, unpublished or replaced by a security holding package), **4 known-bad samples were missing from disk at
  scan time** (recorded as "deleted or quarantined?"; the cause was not recorded, antivirus action is likely but
  unverified), and 3 known-good / scary artifacts were over the 5 MB limit.
- **Antivirus removed sample files in run 1.** After extraction, Windows Defender removed 138 extracted `.sample`
  files of known-bad DataDog items (count from the Defender protection history, not from a repository script;
  `benchmark/verify_samples.py` measures the exact number against `benchmark/manifests/datadog_members.csv` and writes
  the ids and file names to `benchmark/results/samples_missing.csv`). An item with removed files is still scored, on
  less code than was extracted, so **run-1 known-bad recall (strict and lenient) is biased downward**; false-positive
  rates on known-good items are not affected by this. **Run 2** uses restored inputs: `extract_datadog.py
  --restore-missing` re-extracts only the missing or mismatching files from the same ZIPs (ZIP and file sha256 checked
  against the manifests, which stay unchanged), and the scan runs with a Defender exclusion for the samples folder
  only. Run 2 uses the same frozen ruleset and changes no rule, so it does not contaminate the test set. **Both runs
  are reported**, run 1 is not overwritten. The 4 samples missing at scan time (above) may be the same cause.
- **Dormant libraries:** 0/12 got a finding or a threat label in artifact mode.

## Detector coverage gaps

- **History-based detectors** (publisher_change, revival_takeover, dependency_injection, release_delta) need the
  previous release. DataDog samples have none, so they cannot be measured there: **307 scored items had no release
  history**, and dependency_injection ran on **132 of 457** scored items. They are validated only on replay incidents:
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
- **Install-time scripts without a finding:** `benchmark/ERROR_ANALYSIS.md` lists every known-bad item with no finding
  at any tier that has a setup.py (bucket "setup.py present (normal for source packages), no hook pattern matched":
  pip runs setup.py for every source package, so this alone is not a sign of anything) and every npm item whose
  package.json declares an install hook (bucket "install hook declared (preinstall/postinstall), no finding:
  detector-gap candidate, cause not established"). Neither bucket is human-verified.

## Threat model (short)

- **In scope:** a package or repository whose published code contains install-time execution, decoded / obfuscated
  payloads, credential collection sent to a remote host, destructive or geo-gated code, committed executables, exposed
  secrets, risky CI workflows, or release metadata that changed in suspicious ways (new publisher, revival after
  silence, young new dependency, files not in the repository). Known-malicious packages listed by OSV.
- **Out of scope / not detected:** behaviour that appears only at run time (downloaded later, built from network
  input), payloads in binaries (only hashes are looked up, and only with a VirusTotal key), logic sabotage without a
  pattern (faker 6.6.6 had no finding), malicious code that matches a git tag, compromised maintainers who publish
  ordinary-looking code, and anything in archives over 5 MB.
- **Adversary assumption:** an attacker who knows these rules can avoid them (for example by keeping a single indicator
  in a test or docs path, which is downgraded to info). The score is a first filter for a human reviewer, not a gate.
- **Trust in the tool itself:** nothing scanned is executed, imported or installed; the AI layer is advisory, off in the
  benchmark, and cannot change a score.
