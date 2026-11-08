# Project capabilities

Status as of ruleset `2026.11.08-12` (**frozen** for the Phase 5 benchmark; `2026.11.07-9` plus three pre-run changes, see benchmark/CHANGELOG.md) (branch `trust-engine`). Changes per ruleset version: [docs/RULESET_CHANGELOG.md](docs/RULESET_CHANGELOG.md). This file says what is built, what is
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
tier inside a pillar, and review findings count once per (rule, top-level directory) group (the kept finding lists
all files of the group). A pillar is `None` when none of its detectors ran: "not assessed" if they failed, "not
applicable" (for example "no published package") if they do not apply.

Headline = the lowest assessed pillar, then: any high_risk finding caps it at 49 and any known_malicious at 15
(mirroring the existing caps), the maintenance ceiling (50), and the existing evidence caps from `security.py`
(known malicious 15; high-risk pattern 49; strong secret / CI finding 49; unpatched advisory or 3+ vulnerable
dependencies 49; vulnerable dependencies 69; offensive-security terms 59). The lowest value wins and the result
names its cause: "limited by Integrity: ...", "limited by Maintenance: ..." or "capped by evidence rule: strong
secret".

Labels: DO NOT USE: known malicious indicator > High-risk patterns: review before use > Review recommended >
Fragile / unmaintained > No findings. "(Partial assessment)" is added when a pillar could not be assessed or the
content scan only read part of the repository (for example "partial scan: 1500 of 2300 text files"). Limits of a
single sub-signal (for example the 300-commit history read) are shown in the detector detail, not in the headline.
"Not assessed" when no evidence pillar could be assessed. When nothing limits the score the reason reads "No limiting
pillar".

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
| revival_takeover | Integrity | >= 365 days without a release or commits, then a new publisher, new commit author (bot accounts ignored), release burst or rename/transfer indicator | revival alone = review (metadata-only: not escalated by fragility); revival + new install hook or decoded payload in the revived release = high_risk |
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

## Dev set

Rules were tuned (rulesets 2026.11.07-7 and -8) on 8 real clients: boto3, twine, sentry-python, docker-py, paramiko,
keyring, certbot and pip. They are a **dev set** and must not be reported as held-out evidence. The last tuning round
was 2026.11.07-9 (structural: one shared non-shipping-path classifier); the ruleset is frozen from there.

Non-shipping paths (`detectors/paths.py`: tests, fixtures, assets, samples, examples, docs, _static, _build, tools,
scripts, .agents, tasks.py, noxfile.py, rule directories; never .github): review-tier single indicators there are info.
**Known evasion:** a single-indicator payload placed in such a path is reported as info, not review. Multi-signal
findings (high_risk, known_malicious) in those paths are unchanged.

Hand-maintained lists that encode judgement (review them when adding rules): the known-API host list and stop
tokens, the client-credential-file owner map, and the SSH client library aliases (`SSH_CLIENT_LIBS`: paramiko,
asyncssh, fabric) in `detectors/credential_exfiltration.py`.

## Behavior data-flow detectors (Phase 4)

| Detector | Pillar | What it tracks | Tier |
|---|---|---|---|
| credential_exfiltration | Behavior | Python: a source (whole environment; ~/.ssh, browser, wallet stores; or one credential-like named variable / a client's own credential file) reaching a network sink in the same function or through module-level variables; the sink's destination is classified (exfil endpoint, raw IP, .onion, unrelated host, known/related host, dynamic) | bulk -> exfil/raw IP/.onion/unrelated = high_risk; bulk -> known/related/dynamic = review; named -> unrelated/exfil/dynamic = review; named -> known/related API = not flagged; foreign secret store read without a sink = review |
| protestware_destructive | Behavior | Python: delete / kill / mass overwrite / infinite loop inside an if/while (or after a guard clause) whose test uses locale, timezone, IP geolocation, country, hostname or a fixed date | gated destructive = high_risk; destructive alone or a gate alone = not flagged; OS checks (sys.platform, os.name) are not gates |

JavaScript and shell are checked by regex only ("pattern match, no data-flow") and are **review at most**. So the
node-ipc protestware (JavaScript) would be review here, not high_risk. colors.js / faker.js style sabotage (no gate)
is not flagged by design. The taint tracking is deliberately simple: values passed through function calls, returns
or other modules are not followed. Parsing uses `ast.parse` only, with size/node/file limits and per-file error
handling; nothing is compiled or executed (tested).

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
| repo_secrets | Exposure | secret scan | strong -> review (the 49 evidence cap still applies); private keys or sample-looking keys in test/sample/asset/fixture/docs/rule paths -> info (no tier, no cap) |
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
or measured. At 60 or more, a review-tier Integrity finding **with code/capability evidence** (a new install hook,
network/process code, a decoded payload, a phantom file with a capability, release-vs-git code drift) is escalated to
high_risk and marked `fragility_amplified` with a plain-language reason. Metadata-only findings (young dependency
alone, new publisher alone, missing tag, revival alone, lookalike name alone) stay review and record why. It never
escalates to known_malicious.

In Phase 1, time-based signals use the scan time as `as_of`; release upload times arrive with Phase 2.

## Phase 5 benchmark harness (built, full run not done)

Built and tested (`tests/test_benchmark.py`, synthetic inert inputs only); the protocol is `benchmark/README.md`.

- `benchmark/bench_items.py`: loads the manifests, assigns dev/test splits and moves test items that overlap the dev
  set (21 credibility repos, 8 dev_fp repos, earlier calibration/backtest repos). 3 items were moved
  (lodash, impacket, pwntools).
- `benchmark/run_benchmark.py`: artifact mode (primary) and repo mode (secondary), resumable JSONL output, ablations
  `--no-osv` and `--no-fragility-escalation`, `--offline` (cache only), refuses to run with an AI/Gemini key present
  and refuses the test split unless the frozen ruleset in the protocol matches the code.
- `benchmark/metrics.py`: recall, false-positive rates (Wilson 95% interval, rule of three), precision, per-detector
  table, contribution, detector coverage, scan time, "Misses and why", "False positives and why" -> `RESULTS.md` + CSVs.
- `benchmark/extract_datadog.py`: DataDog samples read in memory (ZipCrypto, password from the dataset README), text
  members written as `*.sample`, executables skipped; traversal, member-count, size and ratio guards.
- `benchmark/compare_chat_ai.py`: about 30 seeded items, exact prompts, hand-scoring and repeatability sheets, summary.

Hardening (before any real run): each item runs in its own process with a hard timeout and a memory cap (killed
items are recorded as not_assessed, never "no findings"); a 100,000-character line cap; `--selfcheck` (hosts, disk,
samples folder, one dev item per mode); `prepare_known_bad.py` (extraction + manifests, no scan); live progress and
ETA; artifact-mode headline with fragility escalation OFF (single-input fragility shown beside it); real recorded
registry data for 3 npm + 2 PyPI non-benchmark packages replayed offline in tests; CI on Ubuntu and Windows
(Python 3.11 and 3.13). Repository mode is still unverified on real repositories (GitHub downloads are blocked in
the sandbox that built it).

Smoke-tested on the 8-item dev debug slice only (artifact mode, PyPI recorded once, then replayed offline from the
cache with identical results, including after an interrupted run was resumed). **No test-set item has been scanned.**

## What is measured

| Measurement | Script | Result | Caveat |
|---|---|---|---|
| Regression fixtures: 10 inert malicious samples, 8 benign look-alikes | `python benchmark_fixtures.py` | regression fixtures: 10/10 detected (written alongside the rules; not an accuracy measure); 0/8 benign look-alikes flagged | Hand-written alongside the rules. |
| Maintenance score backtest | `backtest_collect.py`, `backtest_analyze.py` | see `data/backtest_summary.csv` | Measures the maintenance score only, not the Trust score. |

## Not yet measured

- Per-detector precision, recall and false-positive rate: **not yet measured**. The harness is built (above); the full
  run on the test set happens once, on a machine with network access (`benchmark/README.md` section 8).
- The Trust score on real packages, known-bad or known-good: **not yet measured**.
- Tool vs chat AI: sheets and prompts can be generated; **not yet measured**.
- The fragility weights and threshold: **not validated**.
- Release-based detectors (Phase 2): unit-tested on synthetic release pairs only; accuracy on real releases **not
  yet measured** (Phase 5). The real incidents (event-stream, ua-parser-js, ...) have not been replayed yet.
- Dependency and takeover detectors (Phase 3): tested on synthetic histories and one replay (event-stream 3.3.5);
  accuracy **not yet measured**.
- Data-flow detectors (Phase 4): tested on synthetic code (positive and benign); accuracy **not yet measured**.

## Tests

- `python -m pytest tests` (needs `pip install -r requirements-dev.txt`): contract, pillars, fragility,
  wording rule, consumers, release history parsing and the release detectors, app smoke test.
- `python verify_phase4_reality.py`: offline end-to-end checks of the detectors, AI layer and batch tools.
- `python benchmark_fixtures.py`: the fixture benchmark above.
- `python benchmark/run_benchmark.py --mode artifact --split dev --debug-slice`: harness smoke test on dev items.

## Known false-positive classes (dev evidence)

Seen on dev-set repositories (already viewed, never held-out evidence). They are documented, not tuned away; a
benchmark false positive of these kinds is expected and is reported under "False positives and why".

- **Committed test binaries** (pwntools, dev repository-mode run): compiled executables committed as test or
  exploit-development material. `committed_binary` reports them as review; inside a recognised test path they are
  info, elsewhere they stay review.
- **Vendored launcher executables** (pip, dev repository-mode run and dev artifact run): pip ships distlib's Windows
  launcher stubs (`src/pip/_vendor/distlib/t32.exe`, `t64.exe`, `w32.exe`, ...). `committed_binary` reports each as
  review ("Review recommended"); they are legitimate.
- **Publisher workflow migrations** (scikit-learn, dev repository-mode run): when a project moves its release
  upload to a different Trusted Publishing workflow or environment, `publisher_change` sees a new publisher identity
  for the latest release. This is also how a hijacked release would look, so it stays a finding.
- **Offensive security tools** (sqlmap, dev repository-mode run): security tools contain the same code as the
  malware they test for (reading credential stores, sending data to a remote host), so the behavior scan's
  credential-stealer pattern fires. Dual-use code cannot be told apart by static patterns alone.
- **Offensive-security terms cap (59)** (signature-base, pwntools, dev repository-mode run): an existing rule kept by
  design. Words such as malware, exploit, payload, pentest or red-team in the repository name, description or topics
  cap the headline at 59 ("Review recommended"). Defensive projects (detection-signature collections) and
  exploit-development libraries use the same words, so they are capped too. It is a dual-use warning, not evidence.
- **Scorecard below 4 plus the maintenance ceiling** (Yara-Rules, dev repository-mode run): existing rules kept by
  design. An OpenSSF Scorecard overall score below 4 raises the security level to "Elevated", which applies the 69
  cap (its reason text reads "vulnerable dependencies", even when the trigger is the Scorecard); a maintenance score
  below 40 (or an archived repository) adds the ceiling of 50. Dormant rule repositories score low on both, so they
  are limited without any finding in their content.
