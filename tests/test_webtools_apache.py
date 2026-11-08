"""phpMyAdmin / phpPgAdmin only count as ready when Apache really serves them.

Reported on 1.2.5: with hiawatha already on port 80, Apache couldn't start, the install still said
"ready" and the Open link answered 404 from hiawatha. These check the detection, the status and the
install's last line, with systemd, ss and the catalogue stubbed.
"""
from __future__ import annotations

import types

import pytest

from backend import databases, sysapps


class _Run:
    """A fake subprocess.run: records argv, returns canned ss output."""
    def __init__(self, ss_out=""):
        self.calls, self.ss_out = [], ss_out

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout=self.ss_out if argv[0] == "ss" else "", stderr="")


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(databases, "IS_LINUX", True)
    monkeypatch.setattr(databases.shutil, "which", lambda n: "/usr/bin/" + n)


def test_names_a_catalogued_server_holding_port_80(linux, monkeypatch):
    monkeypatch.setattr(sysapps, "_active", lambda units: {"apache2": False})
    monkeypatch.setattr(sysapps, "_running_web_server", lambda exclude: "nginx")
    monkeypatch.setattr(databases, "subprocess", types.SimpleNamespace(run=_Run(), SubprocessError=Exception))
    assert databases._apache_state() == {"apache": False, "other": "nginx"}


def test_falls_back_to_ss_for_a_server_outside_the_catalogue(linux, monkeypatch):
    monkeypatch.setattr(sysapps, "_active", lambda units: {"apache2": False})
    monkeypatch.setattr(sysapps, "_running_web_server", lambda exclude: None)
    ss = 'LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("hiawatha",pid=612,fd=4))\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
    monkeypatch.setattr(databases, "subprocess", types.SimpleNamespace(run=_Run(ss), SubprocessError=Exception))
    assert databases._apache_state() == {"apache": False, "other": "hiawatha"}


def test_apache_up_means_no_other(linux, monkeypatch):
    monkeypatch.setattr(sysapps, "_active", lambda units: {"apache2": True})
    monkeypatch.setattr(sysapps, "_running_web_server", lambda exclude: pytest.fail("not asked when Apache is up"))
    monkeypatch.setattr(databases, "subprocess", types.SimpleNamespace(run=_Run(), SubprocessError=Exception))
    assert databases._apache_state() == {"apache": True, "other": None}


def test_statuses_carry_the_other_server(linux, monkeypatch):
    monkeypatch.setattr(databases, "_apache_state", lambda: {"apache": False, "other": "hiawatha"})
    monkeypatch.setattr(databases, "phppgadmin_installed", lambda: True)
    monkeypatch.setattr(databases, "phpmyadmin_installed", lambda: True)
    pg, my = databases.phppgadmin_status(), databases.phpmyadmin_status()
    assert pg["installed"] and pg["apache"] is False and pg["other"] == "hiawatha"
    assert my["installed"] and my["apache"] is False and my["other"] == "hiawatha"


def test_install_last_line_is_a_warning_when_apache_cannot_serve(linux, monkeypatch):
    run = _Run()
    monkeypatch.setattr(databases, "subprocess", types.SimpleNamespace(run=run, SubprocessError=Exception))
    monkeypatch.setattr(databases, "_apache_state", lambda: {"apache": False, "other": "hiawatha"})
    lines = []
    r = databases._web_tool_done(lines.append, "phpPgAdmin", "/phppgadmin", "log in with a role that has a password.")
    assert r == {"ok": True, "reachable": False, "other": "hiawatha"}
    assert ["systemctl", "start", "apache2"] in run.calls          # it tried a plain start first
    assert lines[-1].startswith("⚠") and "hiawatha is on port 80" in lines[-1] and "/phppgadmin" in lines[-1]
    assert "ready" not in lines[-1]


def test_install_last_line_is_ready_when_apache_serves(linux, monkeypatch):
    monkeypatch.setattr(databases, "subprocess", types.SimpleNamespace(run=_Run(), SubprocessError=Exception))
    monkeypatch.setattr(databases, "_apache_state", lambda: {"apache": True, "other": None})
    lines = []
    r = databases._web_tool_done(lines.append, "phpMyAdmin", "/phpmyadmin", "log in with a user that has a password.")
    assert r["reachable"] is True and lines[-1].startswith("✔ phpMyAdmin is ready at /phpmyadmin")
