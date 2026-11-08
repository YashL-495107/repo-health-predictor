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
