"""File list on/off for Apache's two built-in sites: the switch follows what visitors really get
(apache2.conf, the site's own <Directory> blocks and the document root's .htaccess) and changes the
place that decides it."""
from __future__ import annotations

import subprocess

import pytest

from backend import apache, sites


@pytest.fixture
def box(tmp_path, monkeypatch):
    www = tmp_path / "www"; root = www / "html"; root.mkdir(parents=True)
    avail = tmp_path / "sites-available"; avail.mkdir()
    st = {"calls": [], "ok": True, "root": root, "avail": avail, "www": www, "tmp": tmp_path}

    def write(apache2="", vdir="", ssl_dir=None):
        d = root.as_posix()
        (tmp_path / "apache2.conf").write_text(apache2.replace("WWW", www.as_posix()))
        (avail / "000-default.conf").write_text(f"<VirtualHost *:80>\n    DocumentRoot {d}\n{vdir.replace('ROOT', d)}</VirtualHost>\n")
        (avail / "default-ssl.conf").write_text(
            f"<VirtualHost *:443>\n    DocumentRoot {d}\n    SSLEngine on\n{(vdir if ssl_dir is None else ssl_dir).replace('ROOT', d)}</VirtualHost>\n")
    st["write"] = write
    monkeypatch.setattr(sites, "AVAIL", avail)
    monkeypatch.setattr(sites, "ENABLED", tmp_path / "sites-enabled")
    monkeypatch.setattr(sites, "APACHE", tmp_path)
    monkeypatch.setattr(sites, "SITE_BAK", tmp_path / "bak")
    monkeypatch.setattr(apache, "APACHE_ROOT", www.resolve())

    def run(argv, *a, **k):
        st["calls"].append(argv)
        bad = argv[:2] == ["apache2ctl", "configtest"] and not st["ok"]
        return subprocess.CompletedProcess(argv, 1 if bad else 0, "", "Syntax error" if bad else "")
    monkeypatch.setattr(sites, "_run", run)
    return st


STOCK = "<Directory WWW/>\n\tOptions Indexes FollowSymLinks\n\tAllowOverride None\n</Directory>\n"
OWN = "    <Directory ROOT>\n        Options FollowSymLinks\n        AllowOverride All\n    </Directory>\n"


def test_stock_apache_lists_files_and_the_switch_turns_it_off_and_back(box):
    box["write"](STOCK)
    http, ssl = box["avail"] / "000-default.conf", box["avail"] / "default-ssl.conf"
    before = http.read_text()
    assert sites._file_list_state(http)["on"] is True   # apache2.conf says so, the site itself says nothing

    assert sites._set_system_indexes(http, False) == {"ok": True}
    assert sites._FL_BEGIN in http.read_text() and "Options -Indexes" in http.read_text()
    assert sites._file_list_state(http)["on"] is False
    assert sites._file_list_state(ssl)["on"] is True    # https has its own switch
    assert not (box["root"] / ".htaccess").exists()     # overrides are off there: nothing to write
    assert ["systemctl", "reload", "apache2"] in box["calls"] and list((box["tmp"] / "bak").iterdir())

    sites._set_system_indexes(http, True)
    assert http.read_text() == before                   # back to the file as it was, no leftover block


def test_htaccess_that_turns_the_list_on_is_the_one_switched(box):
    box["write"](STOCK, OWN)
    ht = box["root"] / ".htaccess"
    ht.write_text("DirectoryIndex home.php\nOptions +Indexes +FollowSymLinks\n")
    http, ssl = box["avail"] / "000-default.conf", box["avail"] / "default-ssl.conf"
    before = ssl.read_text()
    st = sites._file_list_state(ssl)
    assert st["on"] is True and st["via"] == "htaccess" and st["conf"] is False

    sites._set_system_indexes(ssl, False)
    assert ssl.read_text() == before                    # the site config already said "off"
    lines = ht.read_text().splitlines()
    assert lines[-2:] == ["Options -Indexes", "DirectoryIndex home.php"] and "Options +Indexes +FollowSymLinks" in lines
    assert sites._file_list_state(ssl)["on"] is False
    assert sites._file_list_state(http)["on"] is False  # same folder, same .htaccess

    sites._set_system_indexes(http, True)
    assert sites._FL_BEGIN in http.read_text() and "Options +Indexes" in ht.read_text()
    assert sites._file_list_state(http)["on"] is True


def test_rejected_config_is_put_back(box):
    box["write"](STOCK)
    http = box["avail"] / "000-default.conf"
    before = http.read_text()
    box["ok"] = False
    with pytest.raises(sites.SiteError, match="nothing was changed"):
        sites._set_system_indexes(http, False)
    assert http.read_text() == before


def test_quick_toggle_and_listing_use_it(box, monkeypatch):
    box["write"](STOCK)
    monkeypatch.setattr(sites, "_require", lambda: None)
    monkeypatch.setattr(sites, "IS_LINUX", True)
    monkeypatch.setattr(sites, "_server_state", lambda: {})
    rows = {x["conf"]: x for x in sites.list_sites()["sites"]}
    assert rows["000-default.conf"]["indexes"] is True and rows["default-ssl.conf"]["indexes"] is True
    sites.quick_toggle("default-ssl.conf", "indexes", False)
    rows = {x["conf"]: x for x in sites.list_sites()["sites"]}
    assert rows["default-ssl.conf"]["indexes"] is False and rows["000-default.conf"]["indexes"] is True
    assert sites.get_site("default-ssl.conf")["settings"]["indexes"] is False


def test_walk_options_follows_apache_merging():
    w = sites._walk_options
    assert w(["Options FollowSymLinks"], True, False) == (False, False)        # a bare list replaces
    assert w(["Options +FollowSymLinks"], True, False) == (True, False)        # +/- only adjust
    assert w(["Options All", "AllowOverride AuthConfig Options=Indexes"], False, False) == (True, True)
    assert w(["AllowOverride All", "AllowOverride None"], False, False) == (False, False)
