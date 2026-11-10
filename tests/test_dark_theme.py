"""Dark by default: .streamlit/config.toml sets [theme] base = "dark" and keeps the existing settings; custom colours
stay readable (verdict chip text contrast, transparent chart backgrounds). Display only."""
import os
import re
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def test_config_sets_dark_base_and_keeps_existing_settings():
    with open(os.path.join(ROOT, ".streamlit", "config.toml"), "rb") as fh:
        cfg = tomllib.load(fh)
    assert cfg["theme"]["base"] == "dark"
    assert cfg["theme"]["primaryColor"] == "#1a9850" and cfg["browser"]["gatherUsageStats"] is False


def test_verdict_chip_text_contrast_on_every_tier_colour():
    from ui_text import NEUTRAL_COLOR, chip_text_color, contrast
    src = open(os.path.join(ROOT, "trust_check.py"), encoding="utf-8").read()
    tiers = re.findall(r"#[0-9a-fA-F]{6}", src[src.index("TRUST_COLORS = {"):src.index("STATUS_TEXT")])
    assert len(tiers) == 6
    for c in tiers + [NEUTRAL_COLOR, "#444444"]:
        assert contrast(chip_text_color(c), c) >= 4.5, c
    assert "color:{chip_text_color(trust_color)}" in src


def test_charts_have_transparent_backgrounds():
    src = open(os.path.join(ROOT, "trust_check.py"), encoding="utf-8").read()
    for layout in re.findall(r"update_layout\((.*)", src):
        assert 'paper_bgcolor="rgba(0,0,0,0)"' in layout, layout[:80]
    assert "background:#fff" not in src.replace(" ", "") and "background-color:white" not in src
