"""Smoke-tests the Streamlit UI with the GitHub layer mocked."""
import os, sys
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from streamlit.testing.v1 import AppTest
sys.path.insert(0, os.path.dirname(__file__))
import test_client_mock as m
from github_client import GitHubClient, fetch_features as real_fetch


def fake_fetch(client, owner, repo):
    client.session.get = m.fake_get
    return real_fetch(client, owner, repo)


def test_app_renders_result():
    with patch("github_client.fetch_features", fake_fetch):
        at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"), default_timeout=30).run()
        assert not at.exception
        at.text_input(key="repo_input").set_value("https://github.com/o/r")
        at.button[0].click().run()   # Analyze
        assert not at.exception, at.exception
        assert not at.error, [e.value for e in at.error]
        assert any("Health score" in md.value for md in at.markdown)
        print("rendered OK")


def test_app_bad_input():
    at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"), default_timeout=30).run()
    at.text_input(key="repo_input").set_value("not a repo")
    at.button[0].click().run()
    assert at.error and "owner/repo" in at.error[0].value
    print("bad input handled OK")



def test_sample_button_autoruns():
    with patch("github_client.fetch_features", fake_fetch):
        at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"), default_timeout=30).run()
        next(b for b in at.button if b.label == "pallets/flask").click().run()
        assert not at.exception and not at.error
        assert any("Health score" in md.value for md in at.markdown)
        print("sample button OK")


if __name__ == "__main__":
    test_app_renders_result(); test_app_bad_input(); test_sample_button_autoruns()
