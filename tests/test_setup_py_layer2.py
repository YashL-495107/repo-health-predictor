"""Layer 2 setup.py rules: malicious install-time patterns stay high_risk; benign look-alikes do not."""
import os

import pytest

from detectors import release_delta
from detectors.context import DetectorContext
from malware_proof import scan_static_setup_py
from release_helpers import BENIGN_SETUP, history, pypi_release

FIX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "benchmark_fixtures")
MALICIOUS = ["mal_cmdclass_setup.py.sample", "mal_obfuscated_exec_setup.py.sample",
             "mal_curl_pipe_sh_setup.py.sample", "mal_base64_exec_setup.py.sample"]


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


def delta_tiers(new_setup):
    rc = history([pypi_release("1.1", "2026-03-01T00:00:00Z", files={"setup.py": new_setup}),
                  pypi_release("1.0", "2026-01-01T00:00:00Z", files={"setup.py": BENIGN_SETUP})], "PyPI")
    return [f["tier"] for f in release_delta.detect(DetectorContext.build(releases=rc))["findings"]]


@pytest.mark.parametrize("name", MALICIOUS)
def test_malicious_setup_py_added_in_a_release_is_high_risk(name):
    assert delta_tiers(fixture(name)) == ["high_risk"]


def test_concealed_exec_is_strong_in_layer2():
    fs = scan_static_setup_py({"setup.py": fixture("mal_obfuscated_exec_setup.py.sample")}, lambda *a: None)["findings"]
    assert any(f["strong"] and "concealed call resolution" in f["rule"] and "`exec`" in f["detail"] for f in fs)


def test_download_inside_a_process_command_is_strong_in_layer2():
    fs = scan_static_setup_py({"setup.py": fixture("mal_curl_pipe_sh_setup.py.sample")}, lambda *a: None)["findings"]
    assert any(f["strong"] and "downloads from the network" in f["detail"] for f in fs)


BENIGN = {
    "literal getattr": "import os\nfrom setuptools import setup\nv = getattr(os, 'sep')\nsetup(name='d', version='1')\n",
    "getattr with a variable": "from setuptools import setup\nimport demo\nfor k in ('a', 'b'):\n    getattr(demo, k)\nsetup(name='d')\n",
    "joined non-dangerous name": "from setuptools import setup\nimport demo\ngetattr(demo, '_'.join(['get', 'version']))\nsetup(name='d')\n",
    "cmake build, no download": "import subprocess\nfrom setuptools import setup\nsubprocess.check_call(['cmake', '--build', '.'])\nsetup(name='d')\n",
}


@pytest.mark.parametrize("label", list(BENIGN))
def test_benign_setup_py_look_alikes_are_not_strong(label):
    fs = scan_static_setup_py({"setup.py": BENIGN[label]}, lambda *a: None)["findings"]
    assert not any(f["strong"] for f in fs), (label, fs)
    assert "high_risk" not in delta_tiers(BENIGN[label])
