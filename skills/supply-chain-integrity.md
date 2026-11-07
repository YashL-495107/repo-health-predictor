# Skill: Supply-Chain Integrity

## When this applies
- The published release (PyPI sdist/wheel, npm tarball) differs from the tagged source in git.
- A package or dependency name closely resembles a popular package (typosquat, combosquat).
- OSV lists the package or a dependency with a `MAL-` advisory (known malicious package).
- Antivirus consensus (e.g. VirusTotal) flags a committed binary or artifact.

## Indicators to check
1. Release drift: files or functions present in the published artifact but absent from git, especially in
   `__init__.py`, `setup.py`, or install hooks.
2. Nature of the drift: new imports of `subprocess`, `socket`, `urllib`, `base64`; new top-level code.
3. Name similarity: edit distance 1-2 from a popular package, swapped letters, extra hyphen/underscore, or a
   popular name plus a suffix like `-dev`, `-utils`, `-py`.
4. OSV `MAL-` id: which package and version range it covers, and whether the repo pins an affected version.
5. Publisher signals: very new package, single release, maintainer unrelated to the upstream project.
6. Detection count: number of engines flagging a binary and whether detections are generic heuristics.

## Step-by-step analysis
1. Identify which integrity signal fired (drift, name similarity, OSV MAL-, AV consensus).
2. For drift: list exactly what the artifact adds or changes versus git and what that code does.
3. For a name: name the popular package it resembles and the exact difference.
4. For OSV MAL-: confirm the advisory id format and which package/version it names.
5. For AV: note the detection ratio; a handful of generic heuristic names is weaker than many named families.
6. Check whether the signal affects code that runs automatically (import or install time).
7. Conclude: Likely Malicious for OSV MAL- matches or drift that adds execution/network code; Review Required for
   name similarity or low AV ratios alone; Likely Benign if a look-alike explains it.

## Benign look-alikes to rule out
- Build-generated files in releases (`_version.py`, compiled extensions, vendored licenses, `PKG-INFO`).
- Legitimate forks or scoped packages that intentionally share a name root.
- Short or generic names that are close to many packages by chance.
- AV false positives on packers, installers, or self-extracting archives from the project itself.

## Output notes
- Typosquat similarity alone is not proof of malice; OSV MAL- is an external confirmation and should be stated as such.
