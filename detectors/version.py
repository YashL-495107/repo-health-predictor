"""Single source of the ruleset version stamped on every detector finding and shown in the UI/report footer.

Format YYYY.MM.DD-n. Bump it whenever a detector's logic, thresholds or tier mapping changes, and add an
entry to docs/RULESET_CHANGELOG.md.
"""
RULESET_VERSION = "2026.11.07-9"
# FROZEN for the Phase 5 benchmark (benchmark/README.md). Any change after this point must be logged in
# benchmark/CHANGELOG.md and marks the test set as contaminated.
RULESET_FROZEN = True
