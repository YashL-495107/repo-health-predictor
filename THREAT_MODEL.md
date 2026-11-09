# Threat model

What the Trust score is meant to catch, what it does not, and how far its evidence goes. Numbers are from
`benchmark/RESULTS.md` (run 2, the headline). Limits in detail: [LIMITS.md](LIMITS.md); method: [METHOD.md](METHOD.md).

## What a result is

- **Indicators, not proof.** A finding is a pattern worth a human look, not evidence of intent.
- **"No findings" never means the package is harmless.** It means none of the detectors fired on what they could read.
  The score is not a safety guarantee and not a gate: it is a first filter for a human reviewer, used beside OSV and
  registry malware feeds, not instead of them.

## In scope (what the detectors look for)

A package or repository whose published code or metadata contains:

- install-time execution (setup.py hooks, npm preinstall / install / postinstall);
- decoded or obfuscated payloads, credential collection sent to a remote host, destructive or geo-gated code;
- committed executables, exposed secrets, risky CI workflows;
- release metadata that changed in suspicious ways (new publisher, revival after silence, young new dependency, files
  in the release that are not in the repository);
- packages listed as malicious by OSV (MAL- records).

## Out of scope (not detected)

- Behaviour that appears only at run time: code downloaded later or built from network input.
- Payloads inside binaries (only hashes are looked up, and only with a VirusTotal key).
- Logic sabotage with no recognisable pattern (faker 6.6.6 had no finding).
- Malicious code that matches a git tag, and compromised maintainers who publish ordinary-looking code.
- Anything in archives over 5 MB. Code scanning (Bandit, data flow) covers Python only; other languages get pattern
  checks only.

## How far the evidence goes

- **Recall is low and measured in artifact mode only:** strict 12.4% (39/314; 95% CI 9.2%-16.5%), lenient 50.0%
  (157/314), on release archives and DataDog samples given to the content detectors.
- **Repository-mode recall is not measured.** Repo mode is what the app runs, but the known-bad items are package
  versions and samples without a repository; repo mode was measured for false positives only.
- **History detectors are unproven.** publisher_change, revival_takeover, dependency_injection and release_delta need
  the previous release, which DataDog samples lack: 311 scored items had no release history. They are supported only
  by replay incidents (2 of the 3 obtainable ones flagged), not by held-out recall, and they cause 7 of the 17 lenient
  false positives on random known-good packages.
- **OSV numbers are circular.** The known-bad labels come from OSV MAL- records, so OSV-only recall (72.3%, 227/314)
  measures the label source, not the detectors. The headline excludes the OSV lookup.
- **Precision holds only at the benchmark's class ratio** (314 known-bad : 117 random known-good); real registries
  have far fewer malicious packages, so real-world precision is lower and was not measured.
- **Dual-use code is flagged.** Security tools contain the same code as the malware they test for.

## Adversary assumption

An attacker who knows these rules can avoid them (for example by keeping a single indicator in a test or docs path,
which is downgraded to info). The rules are public; treat the score as one input to a review.

## Trust in the tool itself

Nothing scanned is executed, imported, installed or compiled. Benchmark samples are stored as inert `.sample` text
and never committed (only manifests and hashes). The AI layer is advisory, off in the benchmark, and cannot change a
score. Antivirus can remove extracted samples silently (it did in run 1); `benchmark/verify_samples.py` checks them
against the manifests before a scan.
