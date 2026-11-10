"""Single source of the ruleset version stamped on every detector finding and shown in the UI/report footer.

Format YYYY.MM.DD-n. Bump it whenever a detector's logic, thresholds or tier mapping changes, and add an
entry to docs/RULESET_CHANGELOG.md.
"""
RULESET_VERSION = "2026.11.10-v2"
# v1 (2026.11.08-12) was FROZEN for the Phase 5 benchmark (benchmark/README.md, tag ruleset-2026.11.08-12-frozen).
# v2 (2026.11.10-v2) is pre-registered in benchmark/PREREG_v2.md. Every change after the freeze is logged in
# benchmark/CHANGELOG.md: before any test-split scan as a pre-run change (test set not contaminated), after test
# results were viewed as a post-viewing change (test set contaminated).
RULESET_FROZEN = True    # frozen for the fresh held-out set (benchmark/PREREG_v2.md, tag ruleset-2026.11.10-v2-frozen)
