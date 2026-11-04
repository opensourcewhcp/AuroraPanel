"""Deleting a domain: which document roots may go with it."""
from pathlib import Path

import pytest

from backend import sites


def _sites(monkeypatch, *pairs):
    monkeypatch.setattr(sites, "list_sites", lambda: {"sites": [{"server_name": n, "docroot": d} for n, d in pairs]})


def test_own_folder_may_be_deleted(monkeypatch, tmp_path):
    root = tmp_path / "www" / "a.example.com"
    root.mkdir(parents=True)
    _sites(monkeypatch, ("a.example.com", str(root)), ("b.example.com", str(tmp_path / "www" / "b")))
    assert sites._docroot_deletable("a.example.com", str(root)) == root.resolve()


@pytest.mark.parametrize("docroot", ["", "relative/path", "/var/www", "/var/www/html", "/srv"])
def test_system_or_missing_folders_are_refused(monkeypatch, docroot):
    _sites(monkeypatch)
    with pytest.raises(sites.SiteError):
        sites._docroot_deletable("a.example.com", docroot)


def test_folder_shared_with_another_site_is_refused(monkeypatch, tmp_path):
    root = tmp_path / "www" / "shared"
    _sites(monkeypatch, ("a.example.com", str(root)), ("b.example.com", str(root)))
    with pytest.raises(sites.SiteError, match="b.example.com"):
        sites._docroot_deletable("a.example.com", str(root))


def test_folder_holding_another_site_is_refused(monkeypatch, tmp_path):
    root = tmp_path / "www" / "parent"
    _sites(monkeypatch, ("a.example.com", str(root)), ("sub.example.com", str(root / "sub")))
    with pytest.raises(sites.SiteError, match="sub.example.com"):
        sites._docroot_deletable("a.example.com", str(root))


def test_plain_remove_needs_no_job(monkeypatch, tmp_path):
    conf = tmp_path / "a.conf"
    conf.write_text("")
    monkeypatch.setattr(sites, "_require", lambda: None)
    monkeypatch.setattr(sites, "_conf_for", lambda n: conf)
    called = []
    monkeypatch.setattr(sites, "_remove_site_conf", lambda c, n: called.append(n) or {"ok": True})
    assert sites.remove_site("a.example.com") == {"ok": True}
    assert called == ["a.example.com"]
