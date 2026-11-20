"""Server software another control panel (or a hand build) put on the machine: reported, and left alone.

Such a server has no package, so the panel used to call it "not installed" and offer to install its own copy
on top, which would have started a second server on the same ports."""
import os
import subprocess
from pathlib import Path

import pytest

from backend import databases, nginxsites as N, sysapps

FRONT = Path(__file__).resolve().parent.parent / "frontend"
AA_NGINX = "/www/server/nginx/sbin/nginx"
AA_MYSQL = "/www/server/mysql/bin/mysqld"


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(sysapps, "IS_LINUX", True)
    monkeypatch.setattr(sysapps, "_require_linux", lambda: None)
    monkeypatch.setattr(sysapps, "_dpkg_status", lambda pkgs: {p: None for p in pkgs})
    monkeypatch.setattr(sysapps, "_dpkg_broken", lambda pkgs: set())
    monkeypatch.setattr(sysapps, "_pg_server_pkgs", lambda: {})


def test_a_program_no_package_owns_is_external(linux, monkeypatch):
    monkeypatch.setattr(sysapps.shutil, "which", lambda name, path=None: "/usr/bin/nginx" if name == "nginx" else None)
    monkeypatch.setattr(sysapps, "_owned", lambda path: False)
    assert sysapps._unpackaged("nginx") == os.path.realpath("/usr/bin/nginx") == sysapps.external("nginx")
    assert sysapps._unpackaged("caddy") is None and sysapps.external("phpfpm") is None
    # A package's own program (nginx-core without the nginx metapackage, say) is the package manager's business.
    monkeypatch.setattr(sysapps, "_owned", lambda path: True)
    assert sysapps._unpackaged("nginx") is None


def test_the_usual_places_are_checked_when_it_is_not_on_the_path(linux, monkeypatch):
    monkeypatch.setattr(sysapps.shutil, "which", lambda name, path=None: None)
    monkeypatch.setattr(sysapps.os.path, "isfile", lambda p: p == AA_MYSQL)
    monkeypatch.setattr(sysapps, "_owned", lambda path: False)
    assert sysapps._unpackaged("mariadb") == os.path.realpath(AA_MYSQL)
    assert sysapps._unpackaged("nginx") is None


def test_our_own_package_is_never_external(linux, monkeypatch):
    monkeypatch.setattr(sysapps, "_unpackaged", lambda app_id: "/usr/sbin/nginx")
    assert sysapps.external("nginx") == "/usr/sbin/nginx"
    monkeypatch.setattr(sysapps, "_dpkg_status", lambda pkgs: {p: "1.26" for p in pkgs})
    assert sysapps.external("nginx") is None
    monkeypatch.setattr(sysapps, "_dpkg_status", lambda pkgs: {p: None for p in pkgs})
    monkeypatch.setattr(sysapps, "_dpkg_broken", lambda pkgs: set(pkgs))  # half-installed: Repair handles it
    assert sysapps.external("nginx") is None
    monkeypatch.setattr(sysapps, "IS_LINUX", False)
    assert sysapps.external("nginx") is None


def test_owned_asks_the_package_manager_about_the_link_and_its_target(monkeypatch):
    asked = []

    def run(argv, **kw):
        asked.append(argv)
        return subprocess.CompletedProcess(argv, 1, "", "no path found")
    monkeypatch.setattr(sysapps.subprocess, "run", run)
    monkeypatch.setattr(sysapps.distro, "is_dnf", lambda: False)
    monkeypatch.setattr(sysapps.os.path, "realpath", lambda p: AA_NGINX)
    assert sysapps._owned("/usr/bin/nginx") is False
    assert asked == [["dpkg-query", "-S", "/usr/bin/nginx"], ["dpkg-query", "-S", AA_NGINX]]
    def gone(argv, **kw):
        raise OSError("no such program")
    monkeypatch.setattr(sysapps.subprocess, "run", gone)
    assert sysapps._owned("/usr/bin/nginx") is False     # no package manager to ask: nobody owns it
    monkeypatch.setattr(sysapps.distro, "is_dnf", lambda: True)
    monkeypatch.setattr(sysapps.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "nginx-1.26", ""))
    assert sysapps._owned("/usr/sbin/nginx") is True


def test_install_start_and_uninstall_are_refused(linux, monkeypatch):
    launched = []
    monkeypatch.setattr(sysapps, "_unpackaged", lambda app_id: AA_NGINX if app_id == "nginx" else None)
    monkeypatch.setattr(sysapps.jobs, "launch", lambda *a, **k: launched.append(a))
    monkeypatch.setattr(sysapps.subprocess, "run", lambda *a, **k: launched.append(a))
    for call in (lambda: sysapps.install("nginx"), lambda: sysapps.install("nginx", True), lambda: sysapps.uninstall("nginx"),
                 lambda: sysapps.control("nginx", "stop"), lambda: sysapps.control("nginx", "restart", True)):
        with pytest.raises(sysapps.SysAppError, match="outside this panel") as e:
            call()
        assert AA_NGINX in str(e.value) and not isinstance(e.value, sysapps.ConflictError)
    assert launched == []


def test_another_panels_web_server_is_never_stopped_to_make_room(linux, monkeypatch):
    ran = []
    monkeypatch.setattr(sysapps, "_unpackaged", lambda app_id: AA_NGINX if app_id == "nginx" else None)
    monkeypatch.setattr(sysapps, "_running_web_server", lambda exclude: "nginx")
    monkeypatch.setattr(sysapps.subprocess, "run", lambda *a, **k: ran.append(a))
    monkeypatch.setattr(sysapps.jobs, "launch", lambda *a, **k: ran.append(a))
    for switch in (False, True):
        with pytest.raises(sysapps.SysAppError, match="won't stop it") as e:
            sysapps.install("apache", switch)
        assert not isinstance(e.value, sysapps.ConflictError)  # no "switch?" question: the answer is no
    assert ran == []


def test_databases_page_reports_it_and_offers_no_install(linux, monkeypatch):
    monkeypatch.setattr(databases, "IS_LINUX", True)
    monkeypatch.setattr(databases.shutil, "which", lambda name, path=None: f"/usr/bin/{name}")
    monkeypatch.setattr(databases.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", "no packages found"))
    monkeypatch.setattr(sysapps, "_unpackaged", lambda app_id: AA_MYSQL if app_id == "mariadb" else None)
    st = databases.mysql_status()
    assert st == {"installed": False, "running": False, "broken": False, "external": AA_MYSQL}
    assert databases.mysql_available() is False
    with pytest.raises(databases.DatabaseError, match="outside this panel"):
        databases.mysql_require()
    with pytest.raises(databases.DatabaseError, match="outside this panel"):
        databases.install_pkg("mariadb-server")
    # The package itself, installed: nothing external about it.
    monkeypatch.setattr(databases.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "ii \nactive\n", ""))
    assert databases.mysql_status()["external"] is None and databases.mysql_status()["installed"] is True


def test_postgres_status_carries_it_too(linux, monkeypatch):
    monkeypatch.setattr(databases, "IS_LINUX", True)
    monkeypatch.setattr(databases.shutil, "which", lambda name, path=None: None)
    monkeypatch.setattr(sysapps, "_unpackaged", lambda app_id: "/www/server/pgsql/bin/postgres")
    assert databases.pg_status() == {"installed": False, "running": False, "external": "/www/server/pgsql/bin/postgres"}
    with pytest.raises(databases.DatabaseError, match="outside this panel"):
        databases.pg_require()


def test_nginx_websites_stays_out_when_the_settings_live_elsewhere(linux, monkeypatch, tmp_path):
    monkeypatch.setattr(N.shutil, "which", lambda name, path=None: f"/usr/bin/{name}")
    monkeypatch.setattr(N, "_active", lambda unit: False)
    monkeypatch.setattr(sysapps, "_unpackaged", lambda app_id: AA_NGINX)
    monkeypatch.setattr(N, "CONF_DIR", tmp_path / "missing")
    assert N.external() == AA_NGINX and N.installed() is False
    st = N.status()
    assert st["installed"] is False and st["external"] == AA_NGINX and st["sites"] == []
    with pytest.raises(N.NginxError, match="isn't installed"):
        N.create({"server_name": "a.example"})
    # A hand build that does use /etc/nginx/conf.d keeps working as before.
    (tmp_path / "conf.d").mkdir()
    monkeypatch.setattr(N, "CONF_DIR", tmp_path / "conf.d")
    assert N.external() is None and N.installed() is True


def test_the_pages_show_it_without_an_install_button():
    app_js = (FRONT / "js" / "app.js").read_text(encoding="utf-8")
    card = app_js[app_js.index("function externalCard(a)"):app_js.index("function card(a)")]
    assert "Managed elsewhere" in card and "a.external" in card and "doInstall" not in card and "doCtl" not in card
    assert "if (a.external) return externalCard(a);" in app_js
    offer = app_js[app_js.index("function dbOffer("):app_js.index("const install = !d.installed;")]
    assert "if (d.external)" in offer and "is managed outside this panel" in offer and "sysappInstall" not in offer
    nginx_js = (FRONT / "js" / "nginx.js").read_text(encoding="utf-8")
    assert "if (d.external)" in nginx_js and "aren't managed here" in nginx_js


def test_nothing_is_external_off_linux(monkeypatch):
    monkeypatch.setattr(sysapps, "IS_LINUX", False)
    assert sysapps._unpackaged("nginx") is None and sysapps.external("mariadb") is None


def test_status_marks_it_and_keeps_it_not_installed(linux, monkeypatch):
    monkeypatch.setattr(sysapps, "_unpackaged", lambda app_id: AA_NGINX if app_id == "nginx" else None)
    monkeypatch.setattr(sysapps, "_dpkg_status", lambda pkgs: {p: ("2.4" if p == "apache2" else None) for p in pkgs})
    monkeypatch.setattr(sysapps, "_dpkg_broken", lambda pkgs: {"mariadb-server"} & set(pkgs))
    monkeypatch.setattr(sysapps, "_active", lambda units: {u: False for u in units})
    monkeypatch.setattr(sysapps, "_ram_mb", lambda: {})
    monkeypatch.setattr(sysapps, "_docroot", lambda k: None)
    monkeypatch.setattr(sysapps, "SERVER_APPS", {})
    monkeypatch.setattr(sysapps, "_docker_dbs", lambda: [])
    apps = {a["id"]: a for a in sysapps.status()["apps"]}
    assert apps["nginx"]["external"] == AA_NGINX and apps["nginx"]["installed"] is False
    assert apps["apache"]["external"] is None and apps["apache"]["installed"] is True
    assert apps["mariadb"]["external"] is None and apps["mariadb"]["broken"] is True   # half-installed: Repair, not "elsewhere"
    assert apps["caddy"]["external"] is None


def test_ordinary_installs_still_go_ahead(linux, monkeypatch):
    """Nothing external on the machine: the same apt jobs as before are started."""
    started = []
    monkeypatch.setattr(sysapps, "_unpackaged", lambda app_id: None)
    monkeypatch.setattr(sysapps, "_running_web_server", lambda exclude: None)
    monkeypatch.setattr(sysapps.jobs, "launch", lambda title, argv, **k: started.append((title, argv[-1])) or "job")
    assert sysapps.install("nginx") == "job" and databases.install_pkg("mariadb-server") == "job" and databases.install_pkg("phpmyadmin") == "job"
    assert started == [("install Nginx", "nginx"), ("install mariadb-server", "mariadb-server"), ("install phpmyadmin", "phpmyadmin")]
    with pytest.raises(databases.DatabaseError, match="Unsupported"):
        databases.install_pkg("rm -rf")
