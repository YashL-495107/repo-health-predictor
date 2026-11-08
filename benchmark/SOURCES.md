# Data sources, licences and access terms

Checked on 2026-11-07 from this session. "Verified" means the licence or terms text was read from the source itself.
Nothing here grants more than the stated licence; samples are never redistributed by this repository (only manifests
with ids, source URLs and hashes are committed; `benchmark/samples/` is git-ignored).

| Source | Used for | Access | Licence / terms | Status |
|---|---|---|---|---|
| OSV.dev bulk export, `osv-vulnerabilities.storage.googleapis.com/{PyPI,npm}/all.zip` | known-bad labels (MAL- records) | reachable | the MAL- records originate from the OpenSSF malicious-packages repository (below); no separate licence file was found for the bucket itself | export downloaded (PyPI 35.9 MB, npm 209.9 MB, Last-Modified 2026-11-07) |
| OSV API `api.osv.dev` | advisory text for the replay cases | reachable | same as above | used for 6 advisories |
| OpenSSF malicious-packages (github.com/ossf/malicious-packages) | origin of OSV MAL- records | raw files reachable; the GitHub web page and API were refused by this session's proxy | repository `LICENSE`: **Apache License 2.0** (verified). The README contains no separate statement about the data licence | licence verified; directory listing not possible here |
| DataDog malicious-software-packages-dataset | known-bad samples (code) | raw files reachable; GitHub web/API refused | **Apache-2.0**, "You're welcome to use it with attribution" (README, verified); `LICENSE` file Apache 2.0 (verified). Samples are encrypted ZIPs, password `infected` (README) | manifests read (PyPI 1835 entries, npm 48600). Repository about 108 GB (GitHub API size 108565449 KB): never cloned in full. `benchmark/fetch_datadog_subset.py` uses a partial clone (`--filter=blob:none --no-checkout --depth 1`, tree objects only, never checked out) to list the sample paths and blob ids, then downloads only the selected ZIPs by HTTPS from raw.githubusercontent.com at the cloned commit (git objects as fallback), verifies each against its git blob id and stores it under a flat hash name (dry run here: 28,988 ZIPs listed, 312 selected, 229.4 MB). 26 dataset paths cannot exist on Windows (npm names ending in "."), which is why nothing is checked out. Manifest rule: a package mapped to `null` is malicious in every version, one mapped to a list of versions only in those versions |
| hugovk/top-pypi-packages | PyPI popularity ranking (known-good selection) | raw JSON reachable (the hugovk.dev site was refused) | **no licence file found** (LICENSE / LICENSE.txt 404; README has no licence text). Used only as a cited list of package names | `last_update` 2026-11-01, source ClickHouse |
| wooorm/npm-high-impact | npm popularity (known-good selection) | raw files reachable | **MIT** (verified `license` file). "High impact" = 1,000,000+ weekly downloads or 500+ dependents (README) | top.js read |
| PyPI JSON API, npm registry | versions, hashes, obtainability checks | reachable | public registry APIs (metadata only in Stage 1) | used |

Not reachable from this session (so not used, or to be run on a machine with network access): github.com web and API for
other repositories, docs.github.com, deps.dev, the npm downloads API, pypistats, libraries.io, osv.dev website.

Attribution: OpenSSF Malicious Packages (Apache-2.0); DataDog Security Labs, "Open-Source Dataset of Malicious Software
Packages" (Apache-2.0); Titus Wormer, npm-high-impact (MIT); Hugo van Kemenade, top-pypi-packages.
