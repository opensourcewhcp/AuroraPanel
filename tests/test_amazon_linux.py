"""Amazon Linux 2023 names MariaDB after its release line (mariadb1011-server); there is no plain mariadb-server."""
from types import SimpleNamespace

import pytest

from backend import fedora_compat as fc

OFFERED = "mariadb105-server\nmariadb1011-server\nmariadb114-server\nmariadb1011-gssapi-server\n"


def fake_run(installed="", offered=OFFERED):
    def run(*argv, **kw):
        if argv[0] == "rpm":
            return SimpleNamespace(stdout=installed, returncode=0)
        if argv[0] == "dnf":
            return SimpleNamespace(stdout=offered, returncode=0)
        raise AssertionError(argv)
    return run


@pytest.fixture
def amzn(monkeypatch):
    monkeypatch.setattr(fc, "os_release", lambda: {"ID": "amzn", "ID_LIKE": "fedora", "VERSION_ID": "2023"})


def test_newest_line_on_offer_is_installed(amzn, monkeypatch):
    monkeypatch.setattr(fc, "run", fake_run())
    assert fc.amzn_mariadb() == "114"                      # 11.4 is newer than 10.11, though 1011 is the bigger number
    assert fc.rpms_for("mariadb-server") == ["mariadb114-server"]
    assert fc.rpms_for("default-mysql-server") == ["mariadb114-server"]
    assert fc.rpms_for("mariadb-client") == ["mariadb114"]


def test_the_line_already_installed_wins(amzn, monkeypatch):
    monkeypatch.setattr(fc, "run", fake_run(installed="mariadb1011-server\n"))
    assert fc.rpms_for("mariadb-server") == ["mariadb1011-server"]
    assert fc.rpms_for("mariadb-client") == ["mariadb1011"]


def test_nothing_on_offer_falls_back_to_the_fedora_name(amzn, monkeypatch):
    monkeypatch.setattr(fc, "run", fake_run(offered=""))
    assert fc.amzn_mariadb() is None
    assert fc.rpms_for("mariadb-server") == ["mariadb-server"]
    assert fc.rpms_for("mariadb-client") == ["mariadb"]


def test_other_systems_are_not_asked(monkeypatch):
    monkeypatch.setattr(fc, "os_release", lambda: {"ID": "fedora"})
    monkeypatch.setattr(fc, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no lookup on Fedora")))
    assert fc.rpms_for("mariadb-server") == ["mariadb-server"]
    assert fc.rpms_for("mariadb-client") == ["mariadb"]


def test_apache2ctl_options_go_to_httpd():
    """apachectl here refuses options ("-S" is how the panel asks what answers on port 443, before Force HTTPS)."""
    assert fc.apache_argv(["-S"]) == ["httpd", "-S"]
    assert fc.apache_argv(["-t"]) == ["httpd", "-t"]
    assert fc.apache_argv(["configtest"]) == ["apachectl", "configtest"]
    assert fc.apache_argv([]) == ["apachectl"]


def test_status_sees_the_versioned_package(amzn, monkeypatch, capsys):
    monkeypatch.setattr(fc, "run", fake_run(installed="mariadb1011-server\n"))
    monkeypatch.setattr(fc, "rpm_versions", lambda names: {"mariadb1011-server": "10.11.19-1.amzn2023"} if "mariadb1011-server" in names else {})
    assert fc.dpkg_query(["-W", "-f=${Package}\\t${db:Status-Abbrev}\\n", "mariadb-server"]) == 0
    assert capsys.readouterr().out == "mariadb-server\tii \n"
