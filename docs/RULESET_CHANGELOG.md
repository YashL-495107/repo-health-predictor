# Ruleset changelog

Every change to detector logic, thresholds, tier mapping or fragility weights bumps `RULESET_VERSION`
(`detectors/version.py`). Results produced under different versions are not directly comparable.

## 2026.11.07-3

- **Fragility: a missing git tag on its own is no longer escalated** from review to high_risk (findings carry
  `no_fragility_escalation` and the reason).
- **Fragility: registry maintainer count added** (relative weight 10; npm `maintainers`, PyPI `ownership.roles`;
  1 -> 100, 2 -> 50, 3+ -> 0). Unvalidated, like the other weights. Changes every fragility score.
- **release_delta: the root setup.py is judged by Layer 2 only**, not also by the generic network/process regex
  (fixed a false positive on `git describe` version lookups).
- **Layer 2 (setup.py), two new strong rules**, which also apply to repository scans:
  - a process call whose command downloads (`curl`, `wget`, `Invoke-WebRequest`, a URL) counts as process execution
    AND network access (curl | sh in a cmdclass is now strong, was review);
  - `getattr` / `__import__` / `importlib.import_module` with a name assembled at runtime from literals that
    resolves to `exec`, `eval`, `system`, `subprocess`, `os`, ... is strong ("concealed call resolution").
  Both were added after writing the fixtures they are tested on, so those fixtures are regression cases, not
  held-out evidence.
- Archive reading: limits on member count and total decompressed bytes; a truncated tree skips the phantom-file
  check; tag lookup pages and falls back to a direct lookup (coverage changes, no tier changes).

## 2026.11.07-2

- New release-based Integrity detectors: release_delta, tagless_release, publisher_change.

## 2026.11.07-1

- Detector contract, 12 adapters around the existing checks (legacy tier mapping), pillars, Trust score,
  fragility index (weights 45/25/15/15, threshold 60, unvalidated).
