"""Force HTTPS on Apache's built-in http site of a fresh server: nothing serves 443 yet, so the built-in
https site is turned on first (self-signed) instead of refusing."""
from __future__ import annotations

import subprocess

import pytest

from backend import sites

HTTP = "<VirtualHost *:80>\n    DocumentRoot /var/www/html\n</VirtualHost>\n"
SSL = "<VirtualHost *:443>\n    SSLEngine on\n    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem\n</VirtualHost>\n"


@pytest.fixture
def fresh(tmp_path, monkeypatch):
    avail = tmp_path / "sites-available"; avail.mkdir()
    (avail / "000-default.conf").write_text(HTTP)
    (avail / "default-ssl.conf").write_text(SSL)
    st = {"https_on": False, "calls": [], "enabled": []}
    monkeypatch.setattr(sites, "AVAIL", avail)
    monkeypatch.setattr(sites, "APACHE", tmp_path)
    monkeypatch.setattr(sites, "SITE_BAK", tmp_path / "bak")
    monkeypatch.setattr(sites, "SNAKEOIL", tmp_path / "snakeoil.pem")
    monkeypatch.setattr(sites, "_live_conf", lambda conf: conf)
    monkeypatch.setattr(sites.shutil, "which", lambda n: "/usr/sbin/" + n)

    def run(argv, *a, **k):
        st["calls"].append(argv)
        out = "*:80 default\n" + ("*:443 default-ssl\n" if st["https_on"] else "")
        return subprocess.CompletedProcess(argv, 0, out if argv[:2] == ["apache2ctl", "-S"] else "", "")
    monkeypatch.setattr(sites, "_run", run)

    def enable(conf, on):
        st["enabled"].append(conf.name); st["https_on"] = True
        return {"ok": True}
    monkeypatch.setattr(sites, "_set_system_enabled", enable)
    return st, avail


def test_force_https_turns_on_the_builtin_https_site_first(fresh):
    st, avail = fresh
    assert sites._set_system_force_https(avail / "000-default.conf", True) == {"ok": True}
    assert st["enabled"] == ["default-ssl.conf"]
    assert ["make-ssl-cert", "generate-default-snakeoil", "--force-overwrite"] in st["calls"]  # its certificate was missing
    text = (avail / "000-default.conf").read_text()
    assert sites._FH_BEGIN in text and "RewriteRule ^ https://" in text


def test_it_still_refuses_when_https_cannot_be_turned_on(fresh, monkeypatch):
    st, avail = fresh
    (avail / "default-ssl.conf").unlink()
    with pytest.raises(sites.SiteError, match="couldn't be turned on"):
        sites._set_system_force_https(avail / "000-default.conf", True)
    assert st["enabled"] == [] and sites._FH_BEGIN not in (avail / "000-default.conf").read_text()
