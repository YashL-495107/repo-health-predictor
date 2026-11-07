# Ruleset changelog

Every change to detector logic, thresholds, tier mapping or fragility weights bumps `RULESET_VERSION`
(`detectors/version.py`). Results produced under different versions are not directly comparable.

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
