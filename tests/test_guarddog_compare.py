"""GuardDog comparison: guarddog_*.csv reproduce from guarddog.csv; the page, the accuracy-page section and README
show exactly those numbers; the failed item is not scored; the circularity caveat and the hard-FP statement are
present; the app never imports GuardDog."""
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "benchmark")]

import guarddog_metrics as GM  # noqa: E402
import guarddog_results as G  # noqa: E402

RUN2 = ROOT / "benchmark" / "results" / "run2"
D = G.load()


def rows(name, d=RUN2):
    with open(d / name, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_metrics_reproduce_from_guarddog_csv(tmp_path):
    import shutil
    for n in ("guarddog.csv", "items.csv", "false_positives_rates.csv"):
        shutil.copy(RUN2 / n, tmp_path / n)
    GM.run(tmp_path)
    for n in ("guarddog_summary.csv", "guarddog_stats.csv", "guarddog_flags.csv", "guarddog_ecosystem.csv"):
        assert (tmp_path / n).read_text(encoding="utf-8") == (RUN2 / n).read_text(encoding="utf-8").replace("\r\n", "\n"), n


def test_definitions_and_not_scored():
    gd = rows("guarddog.csv")
    scored = [r for r in gd if r["status"] == "scanned"]
    bad = [r for r in scored if r["set"] == "known_bad"]
    good = [r for r in scored if r["set"] == "known_good"]
    s = {r["operating_point"]: r for r in D["summary"]}
    hr = s["default: high_risk"]
    assert (int(hr["known_bad_k"]), int(hr["known_bad_n"])) == (sum(r["risk_label"] == "high_risk" for r in bad), len(bad))
    sus = s["default: suspicious or high_risk"]
    assert int(sus["known_bad_k"]) == sum(r["risk_label"] in ("high_risk", "suspicious") for r in bad)
    assert int(hr["known_good_k"]) == sum(r["risk_label"] == "high_risk" for r in good) and int(hr["known_good_n"]) == 117
    failed = [r["id"] for r in gd if r["status"] != "scanned"]
    assert len(bad) == 314 - len(failed) and all(f in D["stats"]["not_scored"]["note"] for f in failed)
    assert G.not_scored_line(D).startswith(f"Not scored for GuardDog (listed, never imputed): {len(failed)} item(s)")
    for name, r in s.items():                                   # matched-FP points never exceed their target
        if name.startswith("matched FP:") and "%" in name and "lenient" not in name:
            t = int(name.split(":")[1].strip().split("%")[0]) / 100
            assert int(r["known_good_k"]) <= int(t * int(r["known_good_n"]) + 1e-9), name
    assert 0.5 < float(D["stats"]["auc"]["value"]) <= 1


def test_auc_matches_a_direct_count():
    gd = [r for r in rows("guarddog.csv") if r["status"] == "scanned"]
    pos = [float(r["risk_score"]) for r in gd if r["set"] == "known_bad"]
    neg = [float(r["risk_score"]) for r in gd if r["set"] == "known_good"]
    direct = sum((a > b) + 0.5 * (a == b) for a in pos for b in neg) / (len(pos) * len(neg))
    assert abs(direct - float(D["stats"]["auc"]["value"])) < 1e-6


def test_side_by_side_reads_the_csvs():
    table = G.side_by_side(D)
    ours = [r for r in table if r["Tool"].startswith("Our detectors")]
    assert [r["Known-bad recall"] for r in ours] == ["12.4% (39/314; 95% CI 9.2%-16.5%)", "50.0% (157/314; 95% CI 44.5%-55.5%)"]
    gdr = [r for r in table if r["Tool"].startswith("GuardDog")]
    assert [r["Known-bad recall"] for r in gdr] == [r["known_bad_text"] for r in D["summary"]]
    assert [r["Operating point"] for r in gdr][:2] == ["default: high_risk", "default: suspicious or high_risk"]
    assert any(r["Operating point"].startswith("matched FP: 0%") for r in gdr)
    ml = [r for r in table if r["Tool"].startswith("Learned combiner")]
    assert len(ml) == 4 and {r["Tool"].split(", ")[2].split(" (")[0] for r in ml} == {"logistic regression", "random forest"}


def test_hard_false_positives_statement():
    only = [f for f in rows("guarddog_flags.csv") if f["hard_fp_guarddog_only"] == "yes"]
    ours = {r["id"]: r for r in rows("items.csv")}
    assert only and all(f["set"] == "known_good" and f["guarddog_label"] == "high_risk" for f in only)
    assert all(ours[f["id"]]["strict_hit"] == "False" for f in only)
    line = G.hard_fp_line(D)
    assert all(G._pkg(f["id"]) in line for f in only) and "our detectors" in line


def test_page_accuracy_section_and_readme():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()
    at.switch_page("app_pages/4_Compared_with_GuardDog.py").run()
    assert not at.exception, at.exception
    assert at.title[0].value == "Compared with GuardDog"
    assert any(G.CAVEAT in e.value for e in at.error)                       # caveat first and prominent
    assert any(w.value == G.hard_fp_line(D) for w in at.warning)
    side = next(t.value for t in at.table if "Known-bad recall" in t.value.columns and "ROC AUC" in t.value.columns)
    assert list(side["Known-bad recall"]) == [r["Known-bad recall"] for r in G.side_by_side(D)]
    at.switch_page("app_pages/2_How_accurate.py").run()
    assert not at.exception and any(m.value == G.headline(D) for m in at.markdown)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert G.readme_paragraph(D) in readme and G.CAVEAT in readme
    assert "**Behavior detectors only (never-seen malware): headline**" in readme      # our v1 headline unchanged


def test_app_never_imports_guarddog():
    for p in [ROOT / "app.py", ROOT / "trust_check.py", ROOT / "guarddog_results.py", *(ROOT / "app_pages").glob("*.py")]:
        assert not re.search(r"^\s*(?:import|from)\s+guarddog\b", p.read_text(encoding="utf-8"), re.M), p.name
    req = (ROOT / "requirements.txt").read_text() + (ROOT / "requirements-dev.txt").read_text()
    assert "guarddog" not in req.lower()
