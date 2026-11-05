"""The Debian-named commands the panel uses on Fedora: package names, service names and the a2en* folders."""
import subprocess

import pytest

from backend import fedora_compat as fc


@pytest.mark.parametrize("deb,rpm", [
    ("apache2", ["httpd", "mod_ssl"]),
    ("php8.5-gd", ["php-gd"]),
    ("php8.5-fpm", ["php-fpm"]),
    ("php-zip", ["php-pecl-zip"]),
    ("dovecot-imapd", []),
    ("nmap", ["nmap"]),
])
def test_debian_packages_map_to_fedora_ones(deb, rpm):
    assert fc.rpms_for(deb) == rpm


@pytest.mark.parametrize("unit,real", [
    ("apache2", "httpd"), ("apache2.service", "httpd.service"), ("php8.5-fpm", "php-fpm"), ("cron", "crond"),
    ("certbot.timer", "certbot-renew.timer"), ("postgresql@18-main", "postgresql"), ("sshd", "sshd"), ("firewalld.service", "firewalld.service"),
])
def test_service_names(unit, real):
    assert fc.unit_name(unit) == real


def test_apt_install_translates_names_and_starts_what_debian_would(monkeypatch):
    calls, started = [], []
    monkeypatch.setattr(fc, "dnf", lambda *a: calls.append(a) or 0)
    monkeypatch.setattr(fc, "setup", lambda: None)
    monkeypatch.setattr(fc, "run", lambda *a, **k: started.append(a))
    assert fc.apt_get(["-o", "APT::Status-Fd=1", "-y", "install", "--no-install-recommends", "redis-server", "git"]) == 0
    assert calls == [("-y", "install", "git", "valkey", "valkey-compat-redis")]
    assert started == [("systemctl", "enable", "--now", "valkey")]


def test_a_failed_install_is_reported_and_nothing_is_set_up(monkeypatch):
    monkeypatch.setattr(fc, "dnf", lambda *a: 1)
    monkeypatch.setattr(fc, "setup", lambda: pytest.fail("setup ran"))
    assert fc.apt_get(["install", "nope"]) == 1


def test_dpkg_query_prints_debian_names_for_installed_packages(monkeypatch, capsys):
    monkeypatch.setattr(fc, "rpm_versions", lambda names: {"httpd": "2.4-1", "mod_ssl": "2.4-1"} if "httpd" in names else {})
    assert fc.dpkg_query(["-W", "-f=${Package}\\t${db:Status-Abbrev}\\t${Version}\\n", "apache2", "vsftpd"]) == 0
    assert capsys.readouterr().out == "apache2\tii \t2.4-1\n"


def test_apt_cache_says_when_fedora_has_no_package(monkeypatch, capsys):
    monkeypatch.setattr(fc, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "nmap 7.92-1\n", ""))
    monkeypatch.setattr(fc, "rpm_versions", lambda names: {})
    assert fc.apt_cache(["policy", "nmap", "rspamd", "dovecot-imapd"]) == 0
    out = capsys.readouterr().out
    assert "nmap:\n  Installed: (none)\n  Candidate: 7.92-1" in out
    assert "rspamd:\n  Installed: (none)\n  Candidate: (none)" in out
    assert "dovecot-imapd:\n  Installed: (none)\n  Candidate: included" in out


def test_stock_modules_are_switched_in_place(tmp_path, monkeypatch):
    mods = tmp_path / "mods"
    mods.mkdir()
    conf = mods / "00-base.conf"
    conf.write_text("LoadModule status_module modules/mod_status.so\n")
    monkeypatch.setattr(fc, "HTTPD_MODS", mods)
    assert fc.stock_module("status", False) is True
    assert conf.read_text() == "#LoadModule status_module modules/mod_status.so\n"
    assert fc.stock_module("status", True) is True
    assert conf.read_text() == "LoadModule status_module modules/mod_status.so\n"
    assert fc.stock_module("nothing", True) is False


def test_enabling_a_site_that_does_not_exist_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(fc, "AP", tmp_path)
    assert fc.a2_link("sites", "missing", True) == 1


def test_disabling_a_site_removes_only_its_enabled_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(fc, "AP", tmp_path)
    (tmp_path / "sites-available").mkdir()
    (tmp_path / "sites-enabled").mkdir()
    avail = tmp_path / "sites-available" / "a.conf"
    avail.write_text("x")
    on = tmp_path / "sites-enabled" / "a.conf"
    on.write_text("x")
    assert fc.a2_link("sites", "a", False) == 0
    assert avail.exists() and not on.exists()


@pytest.mark.parametrize("on,off,folder", [("a2ensite", "a2dissite", "sites"), ("a2enconf", "a2disconf", "conf")])
def test_the_commands_switch_a_site_or_conf_on_and_off(tmp_path, monkeypatch, on, off, folder):
    monkeypatch.setattr(fc, "AP", tmp_path)
    (tmp_path / f"{folder}-available").mkdir()
    (tmp_path / f"{folder}-available" / "a.conf").write_text("x")
    entry = tmp_path / f"{folder}-enabled" / "a.conf"
    monkeypatch.setattr(fc.Path, "symlink_to", lambda self, target: self.write_text(str(target)))
    assert fc.a2(on, ["-q", "a"]) == 0 and entry.exists()
    assert fc.a2(off, ["-q", "a"]) == 0 and not entry.exists()


def test_link_never_replaces_a_real_file(tmp_path):
    real = tmp_path / "real.conf"
    real.write_text("mine")
    fc.link(real, tmp_path / "other")
    assert real.read_text() == "mine" and not real.is_symlink()
