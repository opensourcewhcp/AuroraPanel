"""File list on/off for Apache's two built-in sites: the switch follows what visitors really get
(apache2.conf, the site's own <Directory> blocks and the document root's .htaccess) and changes the
place that decides it."""
from __future__ import annotations

import subprocess

import pytest

from backend import apache, apacheport, sites, webaccess


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


def test_a_shared_htaccess_no_longer_ties_http_and_https_together(box):
    """The folder's .htaccess is read by both ports. Its Indexes setting moves into the two site files, so
    switching one port leaves the other showing exactly what it showed before."""
    box["write"](STOCK, OWN)
    ht = box["root"] / ".htaccess"
    ht.write_text("DirectoryIndex home.php\nOptions +Indexes +FollowSymLinks\nOptions +Indexes\n")
    http, ssl = box["avail"] / "000-default.conf", box["avail"] / "default-ssl.conf"
    before = ssl.read_text()
    st = sites._file_list_state(ssl)
    assert st["on"] is True and st["via"] == "htaccess" and st["conf"] is False

    assert sites._set_system_indexes(ssl, False) == {"ok": True}
    assert ssl.read_text() == before                    # the site config already said "off"
    assert ht.read_text().splitlines() == ["DirectoryIndex home.php", "Options +FollowSymLinks"]
    assert sites._file_list_state(ssl)["on"] is False
    assert sites._file_list_state(http)["on"] is True   # http kept its list: it is written into its own file now
    assert "Options +Indexes" in http.read_text()
    kept = [p for p in (box["tmp"] / "bak").iterdir() if ".htaccess." in p.name]
    assert kept and "Options +Indexes +FollowSymLinks" in kept[0].read_text()

    sites._set_system_indexes(http, False)
    assert sites._file_list_state(http)["on"] is False and sites._file_list_state(ssl)["on"] is False
    sites._set_system_indexes(ssl, True)
    assert sites._file_list_state(ssl)["on"] is True and sites._file_list_state(http)["on"] is False
    assert "Indexes" not in ht.read_text()


def test_a_complete_options_list_in_htaccess_still_decides_for_both(box):
    box["write"](STOCK, OWN)
    ht = box["root"] / ".htaccess"
    ht.write_text("Options FollowSymLinks\n")
    http, ssl = box["avail"] / "000-default.conf", box["avail"] / "default-ssl.conf"
    assert sites._file_list_state(http)["on"] is False
    assert sites._set_system_indexes(http, True) == {"ok": True, "both": True, "why": "htaccess"}
    assert ht.read_text().splitlines() == ["Options FollowSymLinks", "Options +Indexes"]
    assert sites._file_list_state(http)["on"] is True and sites._file_list_state(ssl)["on"] is True


def test_htaccess_lines_without_indexes():
    f = sites._htaccess_without_indexes
    assert f(["# x", "  Options +Indexes -MultiViews", "Options -Indexes", "RewriteEngine On"]) == ["# x", "  Options -MultiViews", "RewriteEngine On"]
    assert f(["options +INDEXES"]) == [] and f(["DirectoryIndex a.php"]) == ["DirectoryIndex a.php"]
    assert f(["Options Indexes FollowSymLinks"]) is None and f(["Options None"]) is None


def _force(box, on=True):
    """Force HTTPS on the http site, with the https site turned on."""
    http = box["avail"] / "000-default.conf"
    text = sites._FH_BLOCK.sub("", http.read_text())
    if on:
        text = text.replace("</VirtualHost>", f"    {sites._FH_BEGIN}\n    RewriteEngine On\n    RewriteRule ^ https://%{{HTTP_HOST}}%{{REQUEST_URI}} [R=301,L]\n    {sites._FH_END}\n</VirtualHost>")
    http.write_text(text)


def test_with_force_https_both_switches_are_one(box, monkeypatch):
    box["write"](STOCK)
    monkeypatch.setattr(sites, "_enabled", lambda name: True)
    http, ssl = box["avail"] / "000-default.conf", box["avail"] / "default-ssl.conf"
    _force(box)
    assert sites._fl_linked([http, ssl]) is True
    assert sites._set_system_indexes(http, False) == {"ok": True, "both": True, "why": "force_https"}
    assert sites._file_list_state(http)["on"] is False and sites._file_list_state(ssl)["on"] is False
    assert sites._set_system_indexes(ssl, True) == {"ok": True, "both": True, "why": "force_https"}
    assert sites._file_list_state(http)["on"] is True and sites._file_list_state(ssl)["on"] is True
    _force(box, False)                                   # Force HTTPS off: nothing about the lists changes
    assert sites._fl_linked([http, ssl]) is False
    assert sites._file_list_state(http)["on"] is True and sites._file_list_state(ssl)["on"] is True
    assert sites._set_system_indexes(http, False) == {"ok": True}
    assert sites._file_list_state(ssl)["on"] is True


def test_not_linked_while_https_is_off_or_unreadable(box, monkeypatch):
    box["write"](STOCK)
    http, ssl = box["avail"] / "000-default.conf", box["avail"] / "default-ssl.conf"
    _force(box)
    monkeypatch.setattr(sites, "_enabled", lambda name: False)
    assert sites._fl_linked([http, ssl]) is False
    monkeypatch.setattr(sites, "_enabled", lambda name: True)
    http.write_text("# nothing here\n")
    assert sites._fl_linked([http, ssl]) is False        # no http site to redirect from

    def boom(path):
        raise sites.SiteError("unreadable")
    monkeypatch.setattr(sites, "_has_http", lambda p: p.name == "000-default.conf")
    monkeypatch.setattr(sites, "_settings_from_conf", boom)
    assert sites._fl_linked([http, ssl]) is False


def test_turning_force_https_on_gives_http_the_https_list(box, monkeypatch):
    box["write"](STOCK)
    monkeypatch.setattr(sites, "_enabled", lambda name: True)
    http, ssl = box["avail"] / "000-default.conf", box["avail"] / "default-ssl.conf"
    sites._set_system_indexes(ssl, False)                # https: off, http: on
    assert sites._file_list_state(http)["on"] is True
    monkeypatch.setattr(sites, "_run", lambda argv, *a, **k: subprocess.CompletedProcess(argv, 0, "*:443 is here", ""))
    monkeypatch.setattr(apacheport, "get_port", lambda: 80)
    assert sites._set_system_force_https(http, True) == {"ok": True}
    assert sites._file_list_state(http)["on"] is False   # same as https from now on
    rows_linked = sites._fl_linked([http, ssl])
    assert rows_linked is True
    assert sites._set_system_force_https(http, False) == {"ok": True}
    assert sites._file_list_state(http)["on"] is False and sites._file_list_state(ssl)["on"] is False


def test_follow_https_is_quiet_when_there_is_nothing_to_follow(box, monkeypatch):
    box["write"](STOCK)
    http = box["avail"] / "000-default.conf"
    before = http.read_text()
    monkeypatch.setattr(sites, "_enabled", lambda name: False)
    sites._fl_follow_https(http)                         # https is off: nothing to copy
    assert http.read_text() == before
    (box["avail"] / "default-ssl.conf").write_text("<VirtualHost *:443>\n</VirtualHost>\n")
    http.write_text("<VirtualHost *:80>\n</VirtualHost>\n")
    sites._fl_follow_https(http)                         # no DocumentRoot at all: noted, not raised


def test_a_built_in_site_with_another_folder_is_not_a_peer(box):
    box["write"](STOCK)
    http, ssl = box["avail"] / "000-default.conf", box["avail"] / "default-ssl.conf"
    assert sites._fl_peers(http) == [http, ssl] and sites._fl_peers(ssl) == [ssl, http]
    ssl.write_text(f"<VirtualHost *:443>\n    DocumentRoot {box['www'].as_posix()}/other\n</VirtualHost>\n")
    assert sites._fl_peers(http) == [http]
    ssl.write_text("<VirtualHost *:443>\n</VirtualHost>\n")   # no DocumentRoot
    assert sites._fl_peers(http) == [http]
    ssl.unlink()
    assert sites._fl_peers(http) == [http]


def test_rejected_config_puts_the_htaccess_back_too(box):
    box["write"](STOCK, OWN)
    ht = box["root"] / ".htaccess"
    ht.write_text("Options +Indexes\n")
    http, ssl = box["avail"] / "000-default.conf", box["avail"] / "default-ssl.conf"
    before = (http.read_text(), ssl.read_text())
    box["ok"] = False
    with pytest.raises(sites.SiteError, match="nothing was changed"):
        sites._set_system_indexes(http, False)
    assert (http.read_text(), ssl.read_text()) == before and ht.read_text() == "Options +Indexes\n"


def test_an_htaccess_that_cannot_be_read_or_changed(box, monkeypatch):
    box["write"](STOCK, OWN)
    http = box["avail"] / "000-default.conf"
    real_read = apache._read_lines

    def read(rel):
        raise apache.ApacheError("is a symlink")
    # Unreadable: it is left alone, and the site file decides.
    monkeypatch.setattr(apache, "_read_lines", read)
    assert sites._set_system_indexes(http, True) == {"ok": True}
    monkeypatch.setattr(apache, "_read_lines", real_read)
    (box["root"] / ".htaccess").write_text("Options None\n")

    def no_write(rel, on, di):
        raise apache.ApacheError("read-only")
    monkeypatch.setattr(apache, "set_indexes", no_write)
    with pytest.raises(sites.SiteError, match="couldn't be changed"):
        sites._set_system_indexes(http, True)
    monkeypatch.setattr(apache, "set_indexes", lambda rel, on, di: {"ok": True})   # says yes, changes nothing
    with pytest.raises(sites.SiteError, match="still off"):
        sites._set_system_indexes(http, True)


def test_missing_autoindex_module_is_turned_on_and_a_failed_reload_restarts(box, monkeypatch):
    box["write"](STOCK)
    http = box["avail"] / "000-default.conf"
    sites._set_system_indexes(http, False)
    box["calls"].clear()
    real = sites._run

    def run(argv, *a, **k):
        r = real(argv, *a, **k)
        return subprocess.CompletedProcess(argv, 1, "", "") if argv[:2] == ["systemctl", "reload"] else r
    monkeypatch.setattr(sites, "_run", run)
    sites._set_system_indexes(http, True)
    assert ["a2enmod", "-q", "autoindex"] in box["calls"] and ["systemctl", "restart", "apache2"] in box["calls"]


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
    assert "indexes_linked" not in rows["000-default.conf"]
    # Force HTTPS on: the http row shows the https site's list, and both rows say they are one.
    monkeypatch.setattr(sites, "_enabled", lambda name: True)
    rows = {x["conf"]: x for x in sites.list_sites()["sites"]}
    assert rows["000-default.conf"]["https_via"] and "indexes_linked" not in rows["000-default.conf"]   # https on, not forced
    _force(box)
    rows = {x["conf"]: x for x in sites.list_sites()["sites"]}
    assert rows["000-default.conf"]["indexes"] is False and rows["000-default.conf"]["indexes_linked"] is True
    assert rows["default-ssl.conf"]["indexes_linked"] is True
    assert sites.quick_toggle("000-default.conf", "indexes", True)["both"] is True
    rows = {x["conf"]: x for x in sites.list_sites()["sites"]}
    assert rows["000-default.conf"]["indexes"] is True and rows["default-ssl.conf"]["indexes"] is True


def test_walk_options_follows_apache_merging():
    w = sites._walk_options
    assert w(["Options FollowSymLinks"], True, False) == (False, False)        # a bare list replaces
    assert w(["Options +FollowSymLinks"], True, False) == (True, False)        # +/- only adjust
    assert w(["Options All", "AllowOverride AuthConfig Options=Indexes"], False, False) == (True, True)
    assert w(["AllowOverride All", "AllowOverride None"], False, False) == (False, False)


def test_directory_privacy_offers_the_built_in_site_and_names_the_sites_inside_it(tmp_path, monkeypatch):
    """The lock on the built-in rows: http and https on the server's address are one entry (one folder),
    and protecting it says which other sites live inside that folder."""
    root = tmp_path / "html"; (root / "shop").mkdir(parents=True); (tmp_path / "blog").mkdir()
    monkeypatch.setattr(sites, "list_sites", lambda: {"sites": [
        {"server_name": "192.168.0.5", "docroot": str(root), "system": True},
        {"server_name": "192.168.0.5", "docroot": str(root), "system": True},
        {"server_name": "Shop.Example", "docroot": str(root / "shop"), "system": False},
        {"server_name": "blog.example", "docroot": str(tmp_path / "blog"), "system": False},
        {"server_name": "", "docroot": str(root), "system": True},
        {"server_name": "parked.example", "docroot": "", "system": False}]})
    roots = webaccess._site_docroots()
    assert roots == {"192.168.0.5": str(root.resolve()), "shop.example": str((root / "shop").resolve()), "blog.example": str((tmp_path / "blog").resolve())}
    monkeypatch.setattr(webaccess, "_load", lambda p: {})
    rows = {s["server_name"]: s for s in webaccess.privacy_sites()["sites"]}
    assert rows["192.168.0.5"]["inside"] == ["shop.example"] and rows["192.168.0.5"]["protected"] is False
    assert rows["shop.example"]["inside"] == [] and rows["blog.example"]["inside"] == []


def test_domains_page_has_the_lock_on_built_in_rows_and_says_when_both_changed():
    from pathlib import Path
    app_js = (Path(__file__).resolve().parent.parent / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
    assert "dmSlot(s.docroot, () => el(\"button\", { class: \"btn btn-sm btn-ghost dm-ico\", title: `Password protect" in app_js
    assert 'r && r.both ? " (http and https)"' in app_js and "s.indexes_linked ?" in app_js
    assert "(picked.inside || []).length" in app_js
