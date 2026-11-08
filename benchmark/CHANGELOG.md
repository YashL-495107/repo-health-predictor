# Benchmark changelog

Every ruleset change after the freeze is logged here, in one of two sections. Only the first one contaminates the
test set (`run_benchmark.contamination()` reads it).

## Post-viewing changes (after test-set results were viewed: test set CONTAMINATED)

(no entries)

## Pre-run changes (before any test-split item was scanned: test set NOT contaminated)

- **2026.11.07-9 -> 2026.11.08-10** (2026-11-08): wiring fix, no rule-logic change. credential_exfiltration's
  name-relatedness checks never received the package/repository name in the real pipeline (both modes); found on
  the dev artifact run (paramiko). Details: docs/RULESET_CHANGELOG.md. **No test-split item had been scanned**: only
  dev items, synthetic code and recorded non-benchmark packages. Protocol table updated to 2026.11.08-10.
- **2026.11.08-10 -> 2026.11.08-11** (2026-11-08): structural fixes from the dev repository-mode run (behavior regexes on
  code files only, test files by name, stable/same-major release selection, tagless_release new-capability rule
  and generated version files, runtime-only dependency advisories, parse-warning hygiene, dev-set de-duplication).
  Details: docs/RULESET_CHANGELOG.md. **No test-split item had been scanned**: only dev items, synthetic code and
  recorded non-benchmark packages. Protocol table updated to 2026.11.08-11.
- **2026.11.08-11 -> 2026.11.08-12** (2026-11-08): final pre-run dev round: Windows-robust download cache and full error text
  in run records (no detection change), requirements*.txt as development pins when the project declares its own
  Python package, documentation of two existing false-positive classes. Details: docs/RULESET_CHANGELOG.md.
  **No test-split item had been scanned**: only dev items, synthetic code and recorded non-benchmark packages.
  Protocol table updated to 2026.11.08-12.
- **DataDog subset fetch** (2026-11-08, ruleset unchanged at 2026.11.08-12, tag ruleset-2026.11.08-12-frozen):
  benchmark tooling and docs only, **no ruleset file changed** (no detector, rule, weight or threshold).
  `fetch_datadog_subset.py` (partial sparse clone of the ~108 GB dataset, version-level candidate matching with the
  shared name/version normalisation and no substitute versions, size guard before any download, resumable);
  `extract_datadog.py` lists samples from git in a clone (same random draw on a sparse clone) and matches candidates at
  version level; section 6 of the README amended accordingly, with the DataDog manifest rule. **No test-split item had
  been scanned**: only a metadata dry run against the dataset (trees and the two manifest files; no sample downloaded).
- **DataDog fetch on Windows** (2026-11-08, ruleset unchanged at 2026.11.08-12; **no ruleset or scanner file changed**):
  the previous fetch failed on Windows ("git checkout main failed: error: invalid path" for an npm package folder
  ending in "."). The partial clone is now never checked out; selected ZIPs are fetched by HTTPS (git objects as
  fallback), verified against their git blob ids and stored under flat hash names with `subset/mapping.csv`, which
  extract_datadog.py and prepare_known_bad.py read through. The selection is byte-identical (tested on the real
  listing: the same 312 ZIPs). **No test-split item had been scanned**: only a metadata dry run (trees, the two
  manifests, HEAD requests; no sample downloaded).
