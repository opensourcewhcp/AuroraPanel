"""Apache's http port setting and the port conflict check that runs before an Apache tool is installed.

systemd, ss and the firewall are stubbed; the file rewriting runs against a throwaway copy of the
Apache config layout, so nothing on the machine running the tests is touched.
"""
from __future__ import annotations

import types

import pytest

from backend import apacheport, config

SS = ('LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("hiawatha",pid=612,fd=4))\n'
      'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("java",pid=700,fd=9))\n'
      'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n')


class _Run:
    """A fake subprocess.run: records argv; ss answers with SS; configtest/restart succeed unless told not to."""
    def __init__(self, ss_out=SS, fail=()):
        self.calls, self.ss_out, self.fail = [], ss_out, set(fail)

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        key = " ".join(argv[:2])
        rc = 1 if key in self.fail else 0
        return types.SimpleNamespace(returncode=rc, stdout=self.ss_out if argv[0] == "ss" else "", stderr="nope" if rc else "")


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(apacheport, "IS_LINUX", True)
    monkeypatch.setattr(apacheport.shutil, "which", lambda n: "/usr/bin/" + n)


@pytest.fixture
def etc(tmp_path, monkeypatch):
    """A copy of the Apache layout: ports.conf with 80 and 443, one site with both vhosts."""
    ports = tmp_path / "ports.conf"
    ports.write_text("Listen 80\n\n<IfModule ssl_module>\n\tListen 443\n</IfModule>\n")
    avail = tmp_path / "sites-available"
    avail.mkdir()
    (avail / "example.com.conf").write_text("<VirtualHost *:80>\n    ServerName example.com\n</VirtualHost>\n"
                                            "<IfModule mod_ssl.c>\n<VirtualHost *:443>\n    ServerName example.com\n</VirtualHost>\n</IfModule>\n")
    (avail / "000-default.conf").write_text("<VirtualHost *:80>\n\tDocumentRoot /var/www/html\n</VirtualHost>\n")
    monkeypatch.setattr(apacheport, "PORTS_CONF", ports)
    monkeypatch.setattr(apacheport, "SITES_AVAIL", avail)
    return {"ports": ports, "site": avail / "example.com.conf", "default": avail / "000-default.conf"}


def test_default_port_and_validation():
    assert apacheport.get_port() == 80
    for bad in (0, 70000, "abc", None, 443, 8088):
        with pytest.raises(apacheport.PortError):
            apacheport._validate(bad)
    assert apacheport._validate("8081") == 8081


def test_who_holds_and_suggest(linux, monkeypatch):
    monkeypatch.setattr(apacheport, "subprocess", types.SimpleNamespace(run=_Run(), SubprocessError=Exception))
    assert apacheport.who_holds(80) == "hiawatha"
    assert apacheport.who_holds(8080) == "java"
    assert apacheport.who_holds(8081) is None
    assert apacheport.suggest(80) == 8081          # first free candidate; 8080 is taken


def test_conflict_only_when_apache_is_down_and_someone_else_holds_the_port(linux, monkeypatch):
    run = _Run(fail={"systemctl is-active"})       # apache2 inactive
    monkeypatch.setattr(apacheport, "subprocess", types.SimpleNamespace(run=run, SubprocessError=Exception))
    assert apacheport.conflict() == {"other": "hiawatha", "port": 80, "suggested": 8081}
    with pytest.raises(apacheport.PortConflict) as e:
        apacheport.check_before_install("phpPgAdmin")
    assert e.value.payload() == {"other": "hiawatha", "port": 80, "suggested": 8081}
    assert "hiawatha is on port 80" in str(e.value) and "phpPgAdmin" in str(e.value)
    monkeypatch.setattr(apacheport, "subprocess", types.SimpleNamespace(run=_Run(), SubprocessError=Exception))  # apache active
    assert apacheport.conflict() is None
    apacheport.check_before_install("phpPgAdmin")   # no raise


def test_set_port_rewrites_listen_and_every_http_vhost_but_not_https(linux, etc, monkeypatch):
    run = _Run()
    monkeypatch.setattr(apacheport, "subprocess", types.SimpleNamespace(run=run, SubprocessError=Exception))
    monkeypatch.setattr(apacheport, "who_holds", lambda p: None)
    opened = []
    import backend.firewall as fw
    monkeypatch.setattr(fw, "open_ports", lambda *p: opened.extend(p))
    r = apacheport.set_port(8081)
    assert r["port"] == 8081 and len(r["changed"]) == 3
    assert etc["ports"].read_text() == "Listen 8081\n\n<IfModule ssl_module>\n\tListen 443\n</IfModule>\n"
    assert "<VirtualHost *:8081>" in etc["site"].read_text() and "<VirtualHost *:443>" in etc["site"].read_text()
    assert "*:80>" not in etc["default"].read_text()
    assert apacheport.get_port() == 8081 and config.load_config()["apache_http_port"] == 8081
    assert opened == ["8081/tcp"]
    assert ["apache2ctl", "configtest"] in run.calls and ["systemctl", "restart", "apache2"] in run.calls


def test_set_port_rolls_back_when_apache_rejects_it(linux, etc, monkeypatch):
    run = _Run(fail={"apache2ctl configtest"})
    monkeypatch.setattr(apacheport, "subprocess", types.SimpleNamespace(run=run, SubprocessError=Exception))
    monkeypatch.setattr(apacheport, "who_holds", lambda p: None)
    before = {k: v.read_text() for k, v in etc.items()}
    with pytest.raises(apacheport.PortError, match="rejected"):
        apacheport.set_port(8081)
    assert {k: v.read_text() for k, v in etc.items()} == before      # every file put back
    assert apacheport.get_port() == 80


def test_set_port_refuses_a_port_someone_else_uses(linux, etc, monkeypatch):
    monkeypatch.setattr(apacheport, "subprocess", types.SimpleNamespace(run=_Run(), SubprocessError=Exception))
    with pytest.raises(apacheport.PortError, match="already used by java"):
        apacheport.set_port(8080)


def test_same_port_is_a_no_op(linux, etc, monkeypatch):
    run = _Run()
    monkeypatch.setattr(apacheport, "subprocess", types.SimpleNamespace(run=run, SubprocessError=Exception))
    r = apacheport.set_port(80)
    assert r["changed"] == [] and ["systemctl", "restart", "apache2"] not in run.calls


def test_stop_other_uses_the_catalogue_unit_and_verifies(linux, monkeypatch):
    calls = []
    holds = {"n": 0}
    def who(port):
        holds["n"] += 1
        return "nginx" if holds["n"] == 1 else None   # held before, free after the stop
    monkeypatch.setattr(apacheport, "who_holds", who)
    monkeypatch.setattr(apacheport, "subprocess", types.SimpleNamespace(run=lambda argv, **kw: calls.append(list(argv)) or types.SimpleNamespace(returncode=0, stdout="", stderr=""), SubprocessError=Exception))
    r = apacheport.stop_other()
    assert r["stopped"] == "nginx" and ["systemctl", "disable", "--now", "nginx"] in calls


def test_sites_render_uses_the_configured_port(monkeypatch):
    from backend import sites
    monkeypatch.setattr(apacheport, "get_port", lambda: 8081)
    s = {**sites.DEFAULTS, "server_name": "example.com", "docroot": "/var/www/example.com", "ssl": "selfsigned",
         "cert": "/etc/ssl/c.pem", "key": "/etc/ssl/k.pem"}
    text = sites.render(s)
    assert "<VirtualHost *:8081>" in text and "<VirtualHost *:443>" in text and "*:80>" not in text
