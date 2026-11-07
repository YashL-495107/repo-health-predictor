# Skill: Install-Time Execution

## When this applies
- `setup.py` defines a custom `cmdclass` (install, develop, egg_info, build_py) or runs code at module top level.
- `package.json` has `preinstall`, `install`, `postinstall` or `prepare` scripts.
- Any build hook that runs automatically during `pip install` / `npm install` without the user calling it.

## Indicators to check
1. What the hook runs: an inline command, a local script file, or a remote download.
2. Process execution: `subprocess`, `os.system`, `os.popen`, `child_process.exec`, `sh -c`.
3. Network access during install: `urllib`, `requests`, `curl`, `wget`, `fetch`, raw IP URLs.
4. Reads of credentials or environment (`~/.ssh`, `~/.aws`, `.npmrc`, `process.env`, `os.environ`).
5. Writes outside the build directory (home directory, shell rc files, cron, startup folders).
6. Obfuscation inside the hook (encoded strings, `eval`, `exec`).

## Step-by-step analysis
1. Locate the hook: the `cmdclass` mapping and the `run()` method, or the npm script key and its command.
2. Resolve what actually executes: follow the command into any local script it calls.
3. List each side effect: process spawn, network request, file write, environment/credential read.
4. Decide whether each side effect is needed to build the package (compiling C extensions, generating files).
5. Check if output leaves the machine (network) or persists beyond install (files outside the project).
6. Compare with the benign look-alikes below.
7. Conclude: Likely Malicious if install-time code downloads/executes remote content, sends data out, or reads
   credentials; Review Required if it spawns processes for unclear reasons; Likely Benign if it is a standard build step.

## Benign look-alikes to rule out
- Compiling native extensions (`build_ext`, `node-gyp rebuild`, `cmake`, `cargo build`).
- Reading the version from git (`git describe`, `git rev-parse`) or from a local file.
- `prepare` scripts running a local bundler or TypeScript compiler (`tsc`, `rollup`, `husky install`).
- Downloading a prebuilt binary from the project's own release page with checksum verification (still worth noting).
- Generating protobuf or parser code from local grammar files.

## Output notes
- State which hook runs, when it runs, and the concrete side effects found in the evidence.
- Install-time code runs with the installing user's permissions, so treat network + execution as high risk.
