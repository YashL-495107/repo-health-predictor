# Project capabilities

Status as of ruleset `2026.11.07-4` (branch `trust-engine`). Changes per ruleset version: [docs/RULESET_CHANGELOG.md](docs/RULESET_CHANGELOG.md). This file says what is built, what is
measured and what is not yet measured. Every number here comes from a script in this repository; anything without
a script behind it is marked "not yet measured".

The full plan is in [docs/PLAN.md](docs/PLAN.md).

## What the headline means

The headline is the **Trust score** ("indicators, not proof"), 0-100. It asks "how much evidence of a problem did
our checks find?", not "is anyone maintaining this?". No findings is the strongest statement the tool makes; it
does not mean the code has no problems.

Four pillars (`pillars.py`):

| Pillar | Source | In the headline? |
|---|---|---|
| Maintenance | `scoring.compute_health_score` (formula unchanged) | Only as a ceiling: below 40 or archived -> headline at most 50. It never lowers the headline below 50 on its own. |
| Integrity | detectors with pillar "Integrity" | yes (weakest link) |
| Behavior | detectors with pillar "Behavior" | yes (weakest link) |
| Exposure | detectors with pillar "Exposure" | yes (weakest link) |

Pillar rule (Integrity, Behavior, Exposure): start at 100; known_malicious -> at most 10; high_risk -> -35 each
(not below 20 once there are 2 or more); review -> -8 each, at most -30 in total. One location counts once per
tier inside a pillar. A pillar is `None` when none of its detectors ran: "not assessed" if they failed, "not
applicable" (for example "no published package") if they do not apply.

Headline = the lowest assessed pillar, then: any high_risk finding caps it at 49 and any known_malicious at 15
(mirroring the existing caps), the maintenance ceiling (50), and the existing evidence caps from `security.py`
(known malicious 15; high-risk pattern 49; strong secret / CI finding 49; unpatched advisory or 3+ vulnerable
dependencies 49; vulnerable dependencies 69; offensive-security terms 59). The lowest value wins and the result
names its cause: "limited by Integrity: ...", "limited by Maintenance: ..." or "capped by evidence rule: strong
secret".

Labels: DO NOT USE: known malicious indicator > High-risk patterns: review before use > Review recommended >
Fragile / unmaintained > No findings. "(Partial assessment)" is added when a pillar could not be assessed or a
detector only read part of the repository (for example "partial scan: 1500 of 2300 text files"). "Not assessed"
when no evidence pillar could be assessed.

**Intended behavior change in Phase 1:** `apply_gate` used to skip every evidence cap for repositories labelled
"Likely abandoned" or "Archived". That exception is removed: an abandoned repository with a known-malicious or
high-risk finding is now capped like any other.

## Release-based detectors (Phase 2)

New detectors with their own tier logic. They read the release history fetched by `releases.py` (last 5 releases;
artifacts of the 2 newest, at most 5 MB each, read in memory and never executed or installed) and git refs from the
GitHub API. Time signals use the releases' own upload times; `as_of` is the latest release's upload time.

| Detector | Pillar | Signals | Tier |
|---|---|---|---|
| release_delta | Integrity | what release N adds vs N-1: install hook (npm pre/install/postinstall, setup.py install-time execution, .pth start-up file), network or process capability, decoded payload, executable | high_risk only if a new install hook appears together with network access (new, or inside the hook) or decoded indicators; any single new capability is review |
| tagless_release | Integrity | no git tag for the latest version; source files in the artifact that are in neither the tag/gitHead tree nor the default branch | missing tag = review; extra files with capabilities = high_risk; extra files without = review |
| dependency_injection | Integrity | a dependency added in release N: young (first release < 30 days before N's upload), lookalike name, install hook (npm scripts; PyPI setup.py via Layer 2, max 3 sdists), removed from the registry, OSV MAL- | OSV MAL- = known_malicious; young + lookalike or young + install hook = high_risk; young, lookalike or removed alone = review |
| revival_takeover | Integrity | >= 365 days without a release or commits, then a new publisher, new commit author, release burst or rename/transfer indicator | revival alone = review (not escalated by fragility); revival + new install hook or decoded payload in the revived release = high_risk |
| publisher_change | Integrity | publisher of release N absent from the previous releases (npm `_npmUser`; PyPI Trusted Publisher provenance); context: long gap, release burst, release_delta high-risk in the same release | review (fragility can escalate it) |

Replay mode: `collect_release_context(owner, repo, package, target_version="3.3.5")` treats an older release as N;
the window, `as_of`, commit history and dependency ages end at its upload time. Registry data is still today's, so
unpublished releases cannot be replayed, and the git tag/tree comparison uses today's repository. Example (a replay /
regression case, not held-out evidence): event-stream at 3.3.5 gives review from publisher_change and
revival_takeover (779 days without a release, then publisher right9ctrl instead of dominictarr). The malicious
3.3.6 release and its flatmap-stream dependency are unpublished, so dependency_injection cannot be replayed on them
from live data.

What the APIs expose (checked live on 2026-11-07, see `releases.py`):
- **PyPI does not expose the uploading user per release.** The `ownership` field lists the current owners only and
  cannot be replayed. The per-release publisher comes from PEP 740 provenance (Trusted Publishing); for releases
  without it, publisher_change reports "publisher identity not available" (not applicable, not a failed check).
- npm exposes a per-version `_npmUser`, install scripts, dependencies and `gitHead`. Unpublished versions disappear
  from `versions` and are listed as "unlisted" (they cannot be compared).
- deps.dev (dependents count) and api.osv.dev could not be reached from this environment, so their response fields
  were not re-checked here; the dependents count is evidence only (never used for a tier) and shows "not
  available" when the lookup fails; a failed OSV lookup is reported as not assessed. GitHub commits
  (`commit.author.date/name`, `author.login`) and repository `full_name` were checked live.
- GitHub tags: only the tag `name` is used. The tag list response shape was not checked live from this environment
  (the test repository has no tags); the trees endpoint was checked with a branch name and a commit SHA.

Archive limits (beyond the 5 MB download): at most 3000 members; listing stops once the declared member sizes pass
50 MB of decompressed data; at most 1 MB per text file and 25 MB of text in total; executables over 10 MB are listed
but not hashed. Any limit hit makes the result partial and is named. Tags are matched by paging through the tag list
(up to 1000 tags, stopping at the first match) and, if the list is incomplete, by looking up `v{version}` and
`{version}` directly. A truncated recursive tree listing skips the phantom-file check (coverage partial).

Benign cases handled on purpose: known build hooks (`node-gyp rebuild`, `prebuild-install`, ...), native-build
`setup.py` changes without network (a cmake call is at most review), `git describe` version lookups in `setup.py`, vendored/test/docs folders, build-output folders and compiled `.js` with a `.ts`
source. Each detector's docstring lists its evasions and false-positive sources.

Responses are cached on disk (`http_cache.py`, keyed by URL and snapshot date; `REPOHEALTH_SNAPSHOT` replays a date,
`REPOHEALTH_OFFLINE=1` uses the cache only). Recorded, trimmed registry responses for offline tests are in
`tests/fixtures/releases/`.

## Detectors adapted from existing checks (Phase 1)

These twelve detectors are **adapters around checks that already existed**. They reuse the findings of the
existing engine and do not compute anything new, so results on the existing fixtures are unchanged.

**Honest note on tiers:** in Phase 1, the `high_risk` tier comes from the existing engine's "strong" findings
(decoded payloads that reach exec, setup.py exec + network, same-file intent patterns such as credential read +
exfil endpoint, release-vs-git drift with new capabilities), mapped by `detectors/base.py:legacy_tier`. It is
**not** produced by new multi-signal, attack-specific detectors; those are planned for Phases 2-4.

| Detector | Pillar | Wraps | Tier mapping |
|---|---|---|---|
| release_vs_git | Integrity | Layer 4 release-to-git AST diff (PyPI wheel < 5 MB) | strong -> high_risk |
| decoded_payload | Behavior | Layer 1 static decoder | strong -> high_risk, review decodes -> review |
| setup_py_hook | Behavior | Layer 2 static setup.py check | strong -> high_risk, Medium -> review |
| behavior_patterns | Behavior | behavior scan (indicators + same-file patterns) | pattern -> high_risk, indicator -> review |
| osv_known_malicious | Exposure | OSV MAL- for pinned deps and the own package's latest version | known_malicious |
| osv_advisories | Exposure | unpatched GitHub advisories, OSV dependency vulnerabilities | review |
| scorecard | Exposure | OpenSSF Scorecard overall score | below 4/10 -> review |
| lookalike_name | Exposure | behavior scan name-similarity check | review |
| committed_binary | Exposure | behavior scan committed-executable check | review |
| virustotal | Exposure | Layer 3 VirusTotal hash lookup (needs VT_API_KEY) | 5+ engines -> known_malicious, 1-4 -> review |
| repo_secrets | Exposure | secret scan | strong -> review (the 49 evidence cap still applies) |
| ci_workflow | Exposure | GitHub Actions checks | High/Medium -> review (the 49 cap still applies for High) |

Each detector's docstring lists what it detects, known evasions and false-positive sources. Every finding is
stamped with the ruleset version. Detectors run in parallel within a 30 s overall budget; a crash or timeout
gives `not_assessed` with the reason, never a crash of the scan and never "no findings".

Bandit code findings stay in the findings table but do not feed a pillar.

## Fragility index (`fragility.py`)

0-100, higher = more fragile. Relative weights: 45 (100 - maintenance score), 25 bus factor (1 -> 100, 2 -> 60,
3 -> 30, 4+ -> 0), 15 dormancy (days since last commit / 730), 15 silent departure of the top maintainer, 10 registry
maintainer count (1 -> 100, 2 -> 50, 3+ -> 0; npm packument `maintainers`, PyPI `ownership.roles`). Missing parts
are dropped and the rest rescaled to 100%. Bus factor and maintainer count are correlated (both measure how few
people hold the project), as are maintenance score and dormancy; the weights do not correct for this partial double
counting.

Fragility describes the project **today**: dormancy and the maintainer count are measured at scan time, not at the
release-based `as_of` used by the release detectors (tested).

**These weights and the escalation threshold (60) are unvalidated design choices**, set by hand and not fitted
or measured. At 60 or more, a review-tier finding from an Integrity detector is escalated to high_risk and marked
`fragility_amplified` with a plain-language reason. It never escalates to known_malicious. A missing git tag on its
own is **not** escalated (many dormant projects never tag; the finding records this reason).

In Phase 1, time-based signals use the scan time as `as_of`; release upload times arrive with Phase 2.

## What is measured

| Measurement | Script | Result | Caveat |
|---|---|---|---|
| Fixture benchmark: 8 inert malicious samples, 4 benign look-alikes | `python benchmark_fixtures.py` | 8/8 detected, 0/4 benign flagged | Hand-written fixtures, known when the rules were written. This is a regression check, not held-out evidence. |
| Maintenance score backtest | `backtest_collect.py`, `backtest_analyze.py` | see `data/backtest_summary.csv` | Measures the maintenance score only, not the Trust score. |

## Not yet measured

- Per-detector precision, recall and false-positive rate: **not yet measured** (Phase 5 benchmark).
- The Trust score on real packages, known-bad or known-good: **not yet measured**.
- The fragility weights and threshold: **not validated**.
- Release-based detectors (Phase 2): unit-tested on synthetic release pairs only; accuracy on real releases **not
  yet measured** (Phase 5). The real incidents (event-stream, ua-parser-js, ...) have not been replayed yet.
- Dependency and takeover detectors (Phase 3): tested on synthetic histories and one replay (event-stream 3.3.5);
  accuracy **not yet measured**.
- Data-flow detectors: **not built yet** (Phase 4).

## Tests

- `python -m pytest tests` (needs `pip install -r requirements-dev.txt`): contract, pillars, fragility,
  wording rule, consumers, release history parsing and the release detectors, app smoke test.
- `python verify_phase4_reality.py`: offline end-to-end checks of the detectors, AI layer and batch tools.
- `python benchmark_fixtures.py`: the fixture benchmark above.
