# Pre-registration: ruleset v2 on a fresh held-out set

Written, committed and tagged (`ruleset-2026.11.10-v2-frozen`) **before any item of the fresh set was scanned** by
either ruleset. Nothing below may change after a fresh-set result has been viewed; any later change is logged in
`benchmark/CHANGELOG.md` and marks the fresh set as contaminated for the ruleset concerned.

**v1 (`2026.11.08-12`, run 2) stays the official headline of the project.** v2 lives on branch `ruleset-v2` only;
the app's scoring on main, the v1 tag and the run-1 / run-2 results are not changed.

| | |
|---|---|
| Rulesets scored on the fresh set | `2026.11.08-12` (v1, tag `ruleset-2026.11.08-12-frozen`, commit 82c754b) and `2026.11.10-v2` (v2, tag `ruleset-2026.11.10-v2-frozen`) |
| Date | 2026-11-10 |
| Seed | **20261110** (`random.Random(20261110)`), every fresh random selection |
| Data snapshot | `--snapshot 2026-11-10` for both runs (http_cache); DataDog dataset commit `72c723be547033c558244520524b117c8d71663b` |
| Mode and flags | artifact mode, `--no-osv --no-fragility-escalation` (v1's headline configuration), AI layer off |
| Run outputs | `benchmark/runs/fresh/v1-artifact-fresh-noosv-nofrag.jsonl`, `benchmark/runs/fresh/v2-artifact-fresh-noosv-nofrag.jsonl` |

## 1. What changed in v2 (frozen at the tag)

Details: `docs/RULESET_CHANGELOG.md` (2026.11.10-v2), `install_trace.py`, `detectors/install_hook_target.py`,
`detectors/setup_py_hook.py`. In short:

- **npm, new detector `install_hook_target`:** each preinstall / install / postinstall command is followed to the
  local file it runs (or the files its inline `node -e` code requires), then up to 3 hops of local require / import /
  spawned paths. Per traced file: N1 host fingerprint + network, N2 OAST / request-catcher / IP-lookup endpoint,
  N3 socket + interactive shell -> high_risk; N4 detached background process -> review.
- **PyPI, `setup_py_hook` extended:** package-root setup.py of nested artifacts, import-alias resolution, string
  constants parsed as code, local imports followed up to 2 levels. Per file: P1 fingerprint + network, P2 endpoint,
  P3 socket + shell, P4 exec + network -> high_risk; P5 single alias-resolved exec / network call in setup.py -> review.
- `.cjs` / `.mjs` are read as text.

No other detector, weight, threshold or tier mapping changed.

## 2. Development data (never reported as held-out evidence for v2)

- **The 76 development items:** the two run-2 error-analysis buckets "install hook declared, no finding" (38 npm) and
  "setup.py present, no hook pattern matched" (38 PyPI), listed in `ERROR_ANALYSIS.md` (`fresh_set.dev76_ids()`).
  Their ZIPs were downloaded at the dataset commit, sha256-checked against `manifests/datadog_extracted.csv` and
  read as text only.
- **False-positive check pool, labelled "v2 dev":** the v1 npm install-hook packages (scary: esbuild, puppeteer, sharp,
  bcrypt, core-js, electron, playwright, @swc/core, protobufjs, cypress; known-good with install scripts: core-js),
  and, as requested, all v1 random known-good (117), scary (18) and dormant (12) items.
- **Consequence:** for v2 the entire v1 test set is development data. Only the fresh set below measures v2.

### Pre-freeze checks (v2 at the frozen state, artifact mode, headline flags, snapshot 2026-11-10)

| check | result |
|---|---|
| v1 random known-good, hard false positives | **0 of 117** (v1 run 2: 0 of 117) |
| v1 random known-good, soft false positives (Review recommended) | 17 of 117, the same 17 items as v1 run 2 |
| v1 scary set | 0 hard, 4 soft of 18 (v1 run 2: 0 hard, 4 soft) |
| v1 dormant set | 0 hard, 0 soft of 12 (v1 run 2: same) |
| label changes versus v1 run 2 on these 147 items | **none** |
| install-hook packages traced | esbuild, puppeteer, @swc/core, cypress: traced, no finding; core-js: its package.json lies beyond the archive reader's 3,000-member limit in artifact mode (v1 and v2 alike), so its real hook was additionally traced directly from the tarball: inline `require('./postinstall')` followed, no finding; bcrypt (`node-gyp-build`), sharp / electron / playwright / protobufjs (no hook in the scanned version): nothing to trace |
| in-sample, the 76 development items | strict 41 / 76, lenient 44 / 76 (v1: 0 / 76 at both; these buckets had no finding at any tier). npm 20 / 38 strict, PyPI 21 / 38 strict. **In-sample and optimistic by construction** |

Notes: 4 of the 147 items were not assessed in artifact mode, as in run 2 except one: google-cloud-storage, lupa and
pdfjs-dist exceed the 5 MB artifact limit; pypdfium2 5.15.1 has been yanked on PyPI since run 2, so the registry
path no longer returns it; its exact artifact (sha256 `b4656a0efce2...` from the v1 manifest) was scanned directly
with v2: no findings, like v1. The 3 registry-obtainable v1 known-bad items were scanned once by accident during a
development run; their records were deleted without being read and were not used.

## 3. Fresh held-out set: selection (done and committed before the freeze)

**Known-bad** (`manifests/fresh/datadog_selection.csv`, `fresh_set.py select-bad`): from the full listing of the
DataDog dataset at the commit above (`samples/<pypi|npm>/<category>/<package>/<version>/*.zip`, git tree objects only),
eligible = not a v1 sample path, a git blob id different from every v1 sample, and an (ecosystem, package key) that is
neither a v1 DataDog sample package nor a v1 known-bad candidate package (so no other version of a v1 package).
Eligible pool: PyPI 1,892, npm 24,462 ZIPs. Per ecosystem (PyPI first) a fresh `random.Random(20261110)` shuffles the
path-sorted pool; the first **150** are taken, skipping a ZIP whose blob or package was already taken (one sample per
package). Selected: 300 ZIPs (PyPI 147 malicious_intent + 3 compromised_lib; npm 139 + 11), 315.7 MB, 1 with a path
Windows cannot hold (stored under a flat name, never dropped). Fetch verifies every ZIP against its git blob id;
extraction is v1's reader (`extract_datadog.read_sample`: text members only, renamed `.sample`, executables skipped).

**Known-good** (`manifests/fresh/known_good.csv`, `fresh_set.py select-good`): `select_items.known_good` (the v1
sampling code) with `random.Random(20261110)`, protocol date 2026-11-10, **60 per ecosystem** from the top 1000 of
hugovk/top-pypi-packages (last_update 2026-11-01) and wooorm/npm-high-impact, maintained (a release within 730 days),
not deprecated, excluding every package and repository of the v1 known-good, dormant and scary manifests, the v1
known-bad candidates, the dev set and the viewed repositories. Selected: 120 (none has an npm install script). Scary
and dormant sets are not redrawn.

Items whose code cannot be obtained or scanned are counted and listed as not scored, never imputed. The runner's
dev-overlap check (bench_items.py) also applies to the fresh split; a moved item is logged.

## 4. Near-duplicates of the 76 development items (fixed now, computed before scanning)

Malware comes in campaigns of near-identical packages. A fresh known-bad item is a **near-duplicate** when it shares
any fingerprint with one of the 76 development items (`fresh_set.fingerprints`, dev side committed in
`manifests/fresh/dev76_fingerprints.csv`, 960 fingerprints for 75 items; `embeds` has no file of 200+ characters):

1. **file:** the sha256 of a code file's normalised text (`\r\n` -> `\n`, trailing whitespace and blank lines removed)
   is equal; code file = `.py .js .cjs .mjs .ts .sh .bat .cmd .ps1` or `setup.py`, at least 200 normalised characters;
2. **named:** the same hash after replacing the item's own package-name variants and version with a placeholder
   (campaign templates that differ only in the package name);
3. **host:** a hostname from a URL literal or an OAST-style host name (`*.oast.*`, `*oast-*`, oastify,
   burpcollaborator, interact.sh, dnslog.cn, ceye.io, requestrepo, pipedream, webhook.site) is equal, excluding the
   fixed list `fresh_set.COMMON_HOSTS` (registries, code hosts, documentation hosts, chat platforms, IP-lookup
   services, paste/telegra.ph hosts) and `*.github.io`.

`fresh_set.py facts` writes `manifests/fresh/fresh_facts.csv` (bucket, near_duplicate yes/no, which rules) from the
extracted text, **before** either scan, and it is committed with the run outputs.

## 5. Metrics and operating points (as v1, protocol section 3)

- **Strict hit:** a high_risk or known_malicious finding. **Lenient hit:** review or above.
- **Hard FP:** a fresh known-good item with a strict finding or a DO NOT USE / High-risk label. **Soft FP:** labelled
  Review recommended (and not hard). Also reported: any review-or-above finding on known-good.
- Recall and FP rates with **Wilson 95% intervals**; zero FPs also with the rule-of-three bound.
- **Subsets:** (a) every scored fresh known-bad item; (b) (a) minus near-duplicates (section 4).
  **Headline: (b) if v2's strict recall on (a) and (b) differs by 3 percentage points or more, otherwise (a)**; the
  other subset is always shown beside it.
- **Buckets** (from the extracted text, before scanning): "npm install hook" (the shallowest package.json declares
  preinstall / install / postinstall), "PyPI setup.py" (a setup.py is present), "other". Recall of v1 and v2 per
  bucket, for (a) and (b).
- v2 per-detector table (hits, only-detector hits, FPs on the fresh known-good set) on the headline subset; paired
  counts (both / v2 only / v1 only / neither) on items scored by both.
- Computed only by `benchmark/results_v2.py`, which refuses run files that are not the headline configuration of the
  expected ruleset or whose ruleset files were not verified against the tag.

## 6. Procedure

1. Commit this note, the fresh manifests and the v2 code; tag `ruleset-2026.11.10-v2-frozen` (done before any fresh scan).
2. Fetch, extract and verify the fresh samples into a NEW folder (`C:\bench\samples_fresh`); write the pre-scan facts.
3. Scan the fresh split with v1: a git worktree at `ruleset-2026.11.08-12-frozen` with the v2 harness copied into its
   `benchmark/` folder. Scan it with v2 from a checkout of `ruleset-2026.11.10-v2-frozen`. For `--split fresh` the
   runner refuses unless the ruleset version is pre-registered here, `RULESET_FROZEN` is set, and every ruleset file
   (each tracked `.py` at the repository root and in `detectors/`) has the same git blob id as in that ruleset's tag,
   with no extra ruleset file; the tag, its commit, the file count and a digest are recorded in every run record.
4. `results_v2.py` writes `benchmark/RESULTS_v2.md` and `benchmark/results/fresh/*.csv`. No app page or README
   changes as part of this; a separate, optional diff is proposed for review.
5. No rule changes after step 1. Repository mode is not run on the fresh set.
