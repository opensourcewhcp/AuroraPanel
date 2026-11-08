"""Basic Auth for whole domains and subdomains (Directory Privacy on a site's document root).

Apache, htpasswd and the site list are stubbed, so this checks the logic: which folders are allowed,
how a site resolves to its root, what the listings report, and that a subdomain is handled on its own.
"""
from __future__ import annotations

import pytest

from backend import webaccess


@pytest.fixture
def dp(tmp_path, monkeypatch):
    """A throwaway state file, two sites outside the usual web roots, and no real Apache or htpasswd."""
    ex, blog = tmp_path / "sites" / "example", tmp_path / "sites" / "blog"
    for d in (ex, blog, tmp_path / "sites" / "example-evil"):
        d.mkdir(parents=True)
    monkeypatch.setattr(webaccess, "DP_STATE", tmp_path / "dirprivacy.json")
    monkeypatch.setattr(webaccess, "DP_DIR", tmp_path / "privacy")
    monkeypatch.setattr(webaccess, "_need_apache", lambda: None)
    calls = {"htpasswd": [], "apply": 0}
    monkeypatch.setattr(webaccess, "_htpasswd_set", lambda f, u, p: calls["htpasswd"].append((f.name, u)))
    monkeypatch.setattr(webaccess, "_htpasswd_del", lambda f, u: None)
    monkeypatch.setattr(webaccess, "_dp_apply", lambda dirs: calls.__setitem__("apply", calls["apply"] + 1))
    monkeypatch.setattr(webaccess, "_site_docroots", lambda: {"example.com": str(ex.resolve()), "blog.example.com": str(blog.resolve())})
    return {"ex": ex, "blog": blog, "evil": tmp_path / "sites" / "example-evil", "calls": calls}


def test_folder_accepts_a_site_root_outside_the_usual_web_roots(dp):
    assert webaccess._folder(str(dp["ex"])) == dp["ex"].resolve()
    sub = dp["ex"] / "private"
    sub.mkdir()
    assert webaccess._folder(str(sub)) == sub.resolve()          # anything inside a site is fine


def test_folder_still_refuses_a_sibling_that_only_shares_a_prefix(dp):
    with pytest.raises(webaccess.WebAccessError, match="inside one of your sites"):
        webaccess._folder(str(dp["evil"]))                        # example-evil is not inside example


def test_protect_site_resolves_the_root_and_defaults_the_prompt_to_the_name(dp):
    r = webaccess.privacy_protect_site("Example.COM", "", "bob", "s3cret-pass")
    assert r["site"] == "example.com" and r["path"] == str(dp["ex"].resolve())
    sites = {s["server_name"]: s for s in webaccess.privacy_sites()["sites"]}
    assert sites["example.com"]["protected"] is True and sites["example.com"]["users"] == ["bob"]
    assert sites["example.com"]["label"] == "example.com"         # no label given: the domain name
    assert sites["blog.example.com"]["protected"] is False
    folder = webaccess.privacy_list()["folders"][0]
    assert folder["site"] == "example.com"                        # the listing tags it as a whole site
    assert dp["calls"]["htpasswd"] and dp["calls"]["apply"] == 1


def test_a_subdomain_is_protected_on_its_own(dp):
    webaccess.privacy_protect_site("blog.example.com", "Blog staging", "ann", "s3cret-pass")
    sites = {s["server_name"]: s for s in webaccess.privacy_sites()["sites"]}
    assert sites["blog.example.com"]["protected"] is True and sites["blog.example.com"]["label"] == "Blog staging"
    assert sites["example.com"]["protected"] is False             # the parent domain is untouched


def test_unknown_site_is_refused(dp):
    with pytest.raises(webaccess.WebAccessError, match="isn't a site"):
        webaccess.privacy_protect_site("nope.example.com", "", "bob", "s3cret-pass")


def test_turning_off_and_removing_are_reflected_for_the_site(dp):
    root = str(dp["ex"].resolve())
    webaccess.privacy_protect_site("example.com", "", "bob", "s3cret-pass")
    webaccess.privacy_toggle(root, False)
    s = {x["server_name"]: x for x in webaccess.privacy_sites()["sites"]}["example.com"]
    assert s["protected"] is False and s["enabled"] is False and s["users"] == ["bob"]
    webaccess.privacy_remove(root)
    s = {x["server_name"]: x for x in webaccess.privacy_sites()["sites"]}["example.com"]
    assert s["protected"] is False and s["users"] == []
