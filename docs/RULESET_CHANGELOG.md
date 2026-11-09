# Ruleset changelog

Every change to detector logic, thresholds, tier mapping or fragility weights bumps `RULESET_VERSION`
(`detectors/version.py`). Results produced under different versions are not directly comparable.

## 2026.11.08-12 (FROZEN; final pre-run dev round, no test-split item scanned)

Changes detection outcomes (item 2), so the version is bumped. **No test-split item had been scanned.**

1. **Windows: http_cache robustness** (no detection change). Reported: in artifact mode the dev item impacket 0.13.1
   failed on Windows with "OSError: [Errno 22] Invalid argument" on a cache path. Checked: -11 did not change
   impacket's release pair (0.13.1 vs 0.13.0 under -10 and -11), cache file names were already hash-only
   (64 hex characters, no URL text, no trailing dots or spaces), and the temp names were long but legal. Most likely
   cause (not reproducible here): the antivirus blocked writing or reading the cached impacket archive (impacket is
   an offensive-security toolkit that antivirus commonly flags); Windows reports such a block through the C runtime
   as errno 22 "Invalid argument". Changes: a failed cache read is a miss and a failed cache write no longer fails
   the request (the data is used from memory); both are recorded with the full error in the item's `cache_errors`;
   temp files get short names; paths near MAX_PATH use the Windows long-path form. A scan that raises now stores
   the FULL exception text (with the Windows error code) in `error` and the traceback in `traceback`.
2. **Dependency scope**: when the project declares its own Python package (pyproject.toml [project] /
   [tool.poetry], setup.py, setup.cfg [metadata] / [options]), requirements*.txt files are development pins:
   advisories there are Info "OSV (dev dependency)" and do not raise the security level or the caps (49 / 69,
   values unchanged). Without a package manifest (an application) the root requirements.txt stays runtime.
   requirements.txt is the only requirements file read (unchanged); the extra manifest reads happen only when it
   exists. MAL- hits are unchanged in every scope.
3. **Documentation only**: two existing rules kept by design added to the known false-positive classes in
   PROJECT_CAPABILITIES.md (the offensive-terms cap of 59; Scorecard below 4 plus the maintenance ceiling on
   dormant rule repositories).

## 2026.11.08-11 (pre-run structural fixes from the dev repository-mode run, no test-split item scanned; superseded by 2026.11.08-12)

Changes detection outcomes, so the version is bumped. **No test-split item had been scanned**; the evidence is the
dev set only (repository-mode run on the maintainer's machine; artifact mode on dev packages here).

1. **Legacy behavior regex rules on code/script files only** (`repo_behavior.scan_behavior`): py, js/mjs/cjs/jsx,
   ts/tsx, coffee, sh/bash/zsh, ps1/psm1, bat/cmd, vbs, rb, php, go, java, kt, scala, cs, rs, pl, lua, swift, c/cpp/h,
   .pth, and extension-less files with a "#!" line. Data/config text (yml, yaml, txt, md, json, toml, ini, cfg, xml,
   rule files, wordlists) is no longer scanned by these rules. Install-hook checks (package.json scripts, setup.py
   cmdclass) and CI workflows (ci_workflow) are unchanged.
2. **Test files by filename** in the shared non-shipping classifier (`detectors/paths.py`): `*_test.go`,
   `*_test.<ext>`, `test_*.py`, `*.test.js/ts` (also jsx/tsx/mjs/cjs), `*.spec.js/ts`, `conftest.py`. As before,
   this only turns review-tier single indicators into info; high_risk and known_malicious are never touched.
3. **Release selection** (`releases.select_window`, used by parse_pypi/parse_npm): N = the most recently published
   STABLE release (pre-releases skipped when any stable release exists; replay mode keeps its target); its
   predecessor = the highest lower version in the same major line published up to N (stable preferred), falling
   back to the chronologically previous release only if there is none. Releases published after N are outside the
   window. Applies to release_delta, tagless_release, publisher_change and dependency_injection (they read
   [N, predecessor, ...]); revival_takeover keeps the chronological previous release for its dormancy gap.
4. **tagless_release**: a phantom file is high_risk only with an install-time or concealed capability (install
   hook, decoded payload) or a network/process capability that is NEW relative to the predecessor's artifact (same
   file, same capability there = not new; no predecessor = new; predecessor unreadable = review). Otherwise review.
   Capability-free generated version files (`_version.py`, `*_version.py`, `__version__.py`, `version.py`) are info
   (before, `_version.py` and `version.py` were skipped entirely).
5. **Dependency advisories, runtime only** (`security.assess_security`). Exactly what changed: dependencies now carry
   a scope (`security.dependency_scope`); package-lock.json entries marked `"dev": true` are dev (the only dev source
   read today: root requirements.txt and package.json `dependencies` were already runtime-only, and dev/test/docs
   requirements files and extras are classified but not read). Dev-scope advisories (a) no longer raise the
   security level, so they no longer trigger the existing caps (49 for 3+ vulnerable dependencies, 69 for some),
   and (b) are reported as Info "OSV (dev dependency)" instead of an "OSV (dependency)" finding, so osv_advisories
   gives them no review tier. Cap values, GitHub advisories and MAL- (malicious package) hits in ANY scope are
   unchanged.
6. **Hygiene**: SyntaxWarnings raised while parsing scanned code (ast.parse only) are silenced via a module filter
   on the parse filename `<scanned-code>`; warnings from this project's own code still show. The benchmark dev set
   is de-duplicated by item id (pypa/pip was listed in dev_fp and dev_credibility).

Dev evidence (artifact mode, dev packages): axios 0.35.0 was compared with 1.21.0 ("adds process execution absent
from 1.21.0", review) and is now compared with 0.34.0 (same file and capability: no finding); httpx was analysed at
the pre-release 1.0.dev6 and is now analysed at 0.28.1. The other 21 dev packages are unchanged. One verification
check changed its fixture file type (Python code in a .txt file -> .py; the .txt case is now asserted unscanned).

## 2026.11.08-10 (pre-run wiring fix, no test-split item scanned; superseded by 2026.11.08-11)

Changes detection outcomes, so the version is bumped. **No test-split item had been scanned** when this was made
(only dev items, synthetic code and recorded non-benchmark packages); the test set is not contaminated.

- **Wiring bug (both scan modes):** credential_exfiltration's name-relatedness checks (related hosts, the
  credential-file owner map, the SSH client aliases) read the package/repository name only from `ctx.features`
  and `ctx.security`. The detector runs at content-scan time (it needs the file contents), where neither exists,
  so in the real pipeline it never saw a name; only unit tests (which passed the names directly) exercised the
  rules. Found on the dev artifact run: paramiko got "Named credential sent to dynamic" at paramiko/agent.py:229.
- **Fix:** `DetectorContext.identity` ({repo, package}). Repo mode (`repo_scan.scan_repo`) passes the repository
  and the package its root manifest declares (the same function `assess_security` uses); the benchmark's artifact
  mode passes the registry package name and the GitHub repository the registry lists. The rule logic is unchanged.
- **Normalisation:** the joined owner token now also removes "." (PyPI treats "-", "_" and "." alike):
  `docker.py` -> `dockerpy`, like `docker-py` and `docker_py`.
- Effect on the 8 dev items (artifact mode): paramiko Review recommended -> No findings; the other 7 unchanged.
- No other detector reads the package/repository name at content time (checked: protestware_destructive,
  behavior_patterns, decoded_payload, repo_secrets, committed_binary, setup_py_hook, ci_workflow use none; the
  typosquat check in the behavior scan already received the name in both modes; release, dependency and OSV
  detectors read it from the release context / security result, which both modes fill).
- **Known evasion (documented):** in repo mode the package name comes from the repository's own manifest, so a
  repository that declares `name="paramiko"` gets the SSH client alias. Artifact mode uses the registry name.

## 2026.11.07-9 (frozen for the Phase 5 benchmark; superseded by 2026.11.08-10)

Third and last dev-set round (structural). After this version the ruleset is frozen: any later change must be
logged in benchmark/CHANGELOG.md and marks the test set as contaminated.

- **One shared non-shipping-path classifier** (`detectors/paths.py`): tests, testdata, fixtures, assets, sample(s),
  example(s), docs, _static, _build, tools, scripts, .agents, tasks.py, noxfile.py and rule-definition directories
  (matched on whole segments and name tokens); `.github/` is never non-shipping. It replaces the separate
  dev-tooling and secret path lists of -7 / -8.
- Applied to ALL review-tier single-indicator findings of behavior_patterns, decoded_payload, credential_exfiltration,
  protestware_destructive, repo_secrets and committed_binary (in `run_detectors`): in non-shipping paths they become
  info with `info_reason`. Never applied to high_risk or known_malicious.
- Secrets of every kind (not only private keys) in non-shipping paths are info, and no longer count as strong
  (so no 49 cap).
- tagless_release: capability-free phantom files in docs/, _static/, _build/ are info; phantom files with a
  capability stay high_risk anywhere.
- Layer 1 (static decoder) now also scans test/docs/example folders but keeps only STRONG findings there, so a
  decoded-and-executed payload under tests/ is high_risk (it was not scanned at all before).
- **Known evasion (documented):** a single-indicator payload placed in a non-shipping path is info, not review.

## 2026.11.07-8

Second dev-set round on the same 8 repositories. **This is the last tuning on them**: after this version the dev set
is frozen for rule changes (they stay a dev set, never held-out evidence).

- **Pillar penalty grouping:** review-tier findings count once per distinct (rule, top-level directory) group, not
  once per file. The kept finding lists every file of the group in a "group" evidence entry. Root-level files form
  one group per rule; findings without a file group by (detector, rule). high_risk and known_malicious are never
  grouped. Changes pillar scores for repositories with one rule firing in many files.
- **Secrets in test / sample / asset / fixture / docs / rule paths are info** (no tier, no cap; `info_reason`
  recorded), consistent with the existing exact tests/ and docs/ fixture rule. In -7 these were review.
- **SSH:** only private-key files are secret sources (id_*, *.pem, *_rsa, *_ed25519, *_ecdsa, *_dsa under .ssh, or a
  bare id_* name). ~/.ssh/config, known_hosts and authorized_keys are not, in credential_exfiltration and in the
  legacy behavior regex (which no longer lists authorized_keys).
- **SSH client libraries:** for paramiko, asyncssh and fabric (a hand-maintained alias list, `SSH_CLIENT_LIBS` in
  detectors/credential_exfiltration.py) SSH private keys and the agent socket SSH_AUTH_SOCK are the client's own
  credentials, not sources. Any other package reading an SSH private key is unchanged (dynamic destination =
  review, exfil/raw IP/unrelated host = high_risk).

## 2026.11.07-7

Dev-set tuning from a sweep of 8 real clients (boto3, twine, sentry-python, docker-py, paramiko, keyring, certbot, pip)
and one false positive found on certbot. These repositories are now part of the **dev set** (used to tune rules), so
they cannot be used as held-out evidence later.

- **Secrets (certbot false positive):** a private key block, or a sample-looking key (example/sample/dummy/fake/test/
  xxxx/changeme in the line), in a path whose directory names contain test, tests, testdata, fixtures, assets, sample,
  samples, example, examples, docs or a rule-definition directory (rules, signatures, yara, sigma, detections) is now
  review, not strong (no 49 cap). Matched on name tokens, so `certbot_integration_tests` and `sample-config` count.
  The reason is recorded in `review_reason`. The same key at the repo root or in `src/` stays strong. certbot had 8
  strong private-key findings in test assets.
- **(1)** The legacy single-indicator regex rules "Credential access: reads credential files" and "dumps all
  environment variables" are no longer findings for Python files that credential_exfiltration analysed with ast
  (kept as `info_findings` with the reason). They are kept for JS, shell and unparseable files; multi-signal
  same-file intent patterns are always kept.
- **(2)** Single credential/environment indicators with no network sink in development-tooling paths (tasks.py,
  noxfile.py, scripts/, tools/, .agents/, tests, docs, examples, ...) become info (no tier) with the reason.
- **(3)** A client's OWN credential file is not a source (docker -> ~/.docker/config.json, kubernetes ->
  ~/.kube/config / kubeconfig, twine -> ~/.pypirc, pip -> pip.conf, aws/boto -> ~/.aws/credentials, ...), using the
  package/repository name tokens as for hosts. Someone else's client file stays a named source (review when sent to
  an unrelated or dynamic destination).
- **(4)** Only a truncated content scan (read_repo file caps: "partial scan: X of Y files") or an unassessed pillar
  adds the headline "Partial assessment" note. Sub-signal limits (the 300-commit read, dependency lookups, release
  metadata only, publisher known for some releases) stay in the detector detail.
- **(5)** When no pillar limits the score, the reason is "No limiting pillar: no findings in the assessed pillars"
  and no pillar is named (was "limited by Integrity: no findings").

## 2026.11.07-6

- New Behavior detectors with Python data flow (ast only; nothing compiled or executed):
  - **credential_exfiltration**: BULK sources (whole environment, foreign secret stores such as ~/.ssh, browser
    and wallet files) sent to an exfil endpoint / raw IP / .onion / unrelated host = high_risk; to a known or
    related host or a dynamic destination = review. NAMED credentials (one TOKEN/SECRET/KEY-like variable or a
    client's own credential file) = review only when sent to an unrelated/exfil/dynamic destination, not flagged
    when sent to a known/related API. A foreign secret store read with no sink = review. Configuration variables
    (proxies, HOME, PATH, ...) are not sources. The sink destination and its class are in the evidence.
  - **protestware_destructive**: destructive action gated on locale / timezone / IP geolocation / country /
    hostname / fixed date = high_risk; destructive alone or gate alone = not flagged; sys.platform / os.name /
    platform.system() checks are not gates.
  - JS / shell for both: regex only, "pattern match, no data-flow", review at most.
  - Parsing limits: 400 KB per file, 200,000 AST nodes, 2000 files; SyntaxError / RecursionError / MemoryError /
    ValueError caught per file (coverage partial).
- Both new detectors set capability_evidence on their findings.
- Detectors that need repository contents run inside scan_repo; apply_gate reuses their results.
- Raw-IP classification: only RFC 1918, loopback, link-local and unique-local addresses count as local (Python's
  is_private also covers documentation ranges).

## 2026.11.07-5

- **Fragility escalation only for findings with code/capability evidence** (`capability_evidence=True`: a new install
  hook, network/process code, a decoded payload, a phantom file with a capability, release-vs-git code drift).
  Metadata-only review findings (young dependency alone, new publisher alone, missing tag, revival alone, lookalike
  alone, phantom file without a capability) stay review and carry `no_escalation_reason`. This replaces the
  per-detector exemptions for missing tags and revival in -3 / -4, and changes publisher_change: on a fragile
  project a new publisher alone is now review (was escalated to high_risk).
- revival_takeover ignores bot accounts (dependabot[bot], renovate[bot], github-actions[bot], any *[bot]) as commit
  authors; their commits neither break a silence nor count as new authors.
- Bug fix: the per-release capability cache was keyed by `id()` of the archive contents, which Python reuses after
  garbage collection, and ignored npm install scripts; it could return another release's capabilities (seen as an
  order-dependent test failure). It is now keyed by content hashes and scripts.

## 2026.11.07-4

- New Integrity detectors: **dependency_injection** (new dependency in release N: young < 30 days at the release,
  lookalike, install hook, removed from the registry, OSV MAL-) and **revival_takeover** (>= 365 days of silence,
  then a new publisher / new commit author / release burst / rename indicator; high_risk only with a new install-time
  capability or decoded payload in the revived release). Revival alone is not escalated by fragility.
- release findings of tier known_malicious are now marked strong / High (were Medium).
- Replay mode: `collect_release_context(..., target_version=)` treats an older release as N.

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
