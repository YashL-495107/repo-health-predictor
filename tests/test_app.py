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


# The app now gives each parallel stage its own GitHubClient (requests.Session is not shared across threads), so
# patching one client's session is not enough: every client must use the fake transport, keeping the test offline.
_orig_init = GitHubClient.__init__


def _fake_init(self, token=None):
    _orig_init(self, token)
    self.session.get = m.fake_get


def test_app_renders_result():
    with patch("github_client.fetch_features", fake_fetch), patch.object(GitHubClient, "__init__", _fake_init):
        at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"), default_timeout=30).run()
        assert not at.exception
        at.text_input(key="repo_input").set_value("https://github.com/o/r")
        at.button[0].click().run()   # Analyze
        assert not at.exception, at.exception
        assert not at.error, [e.value for e in at.error]
        assert any("Trust score" in md.value for md in at.markdown)  # headline relabelled in Phase 1 (trust engine)
        print("rendered OK")


def test_app_bad_input():
    at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"), default_timeout=30).run()
    at.text_input(key="repo_input").set_value("not a repo")
    at.button[0].click().run()
    assert at.error and "owner/repo" in at.error[0].value
    print("bad input handled OK")



def test_sample_button_autoruns():
    with patch("github_client.fetch_features", fake_fetch), patch.object(GitHubClient, "__init__", _fake_init):
        at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"), default_timeout=30).run()
        next(b for b in at.button if b.label == "psf/requests").click().run()
        assert not at.exception and not at.error
        assert any("Trust score" in md.value for md in at.markdown)  # headline relabelled in Phase 1 (trust engine)
        print("sample button OK")


if __name__ == "__main__":
    test_app_renders_result(); test_app_bad_input(); test_sample_button_autoruns()


def test_navigation_names_the_main_page_trust_check():
    """app.py stays the entrypoint (Streamlit Cloud) and only routes: the sidebar label of the main page is
    "Trust check"; the two pages in pages/ are listed explicitly and keep their addresses."""
    src = open(os.path.join(os.path.dirname(__file__), "..", "app.py"), encoding="utf-8").read()
    assert 'st.Page("trust_check.py", title="Trust check", icon="🩺", default=True)' in src
    assert 'st.Page("pages/1_Dependency_Audit.py", title="Dependency Audit", url_path="Dependency_Audit")' in src
    assert 'st.Page("pages/1_Upgrade_check.py", title="Upgrade check", url_path="Upgrade_check")' in src
    assert "st.navigation(PAGES).run()" in src
    for p in ("trust_check.py", "pages/1_Dependency_Audit.py", "pages/1_Upgrade_check.py"):
        assert os.path.isfile(os.path.join(os.path.dirname(__file__), "..", p)), p
    at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"), default_timeout=30).run()
    assert not at.exception and at.title[0].value == "Repository & Package Trust Check"   # default page = Trust check
    at.switch_page("pages/1_Upgrade_check.py").run()
    assert not at.exception and at.title[0].value == "Upgrade check (is this update safe?)"
    at.switch_page("pages/1_Dependency_Audit.py").run()
    assert not at.exception, at.exception
