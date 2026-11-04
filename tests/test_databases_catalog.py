"""Databases on System Applications: native Redis/Memcached, Docker-only engines, "this server only" access."""
import subprocess

import pytest

from backend import dockerapps, requires, sysapps


def test_alnum_secret_is_oracle_safe():
    for _ in range(50):
        s = dockerapps._alnum_secret()
        assert len(s) == 20 and s.isalnum() and s[0].isalpha()
        assert any(c.isupper() for c in s) and any(c.islower() for c in s) and any(c.isdigit() for c in s)


def test_local_access_binds_loopback_and_has_no_url():
    inst = {"access": "local", "lan_ip": "192.168.0.5", "host_ports": {"5984/tcp": 5984}}
    assert dockerapps.port_bind(inst, "db") == "127.0.0.1"
    assert dockerapps.port_bind(inst, "web") == "127.0.0.1"
    assert dockerapps._url(inst, dockerapps.CATALOG["couchdb"]) == ""
    text = dockerapps.render_compose("mongo", dockerapps.CATALOG["mongodb"], {**inst, "app": "mongodb", "folders": {}, "host_ports": {"27017/tcp": 27017}, "env": {}})
    assert "127.0.0.1:27017:27017/tcp" in text
    assert "local" in dockerapps.ACCESS_MODES


def test_database_catalog_entries():
    for k in sysapps.DOCKER_DBS:
        app = dockerapps.CATALOG[k]
        assert app["cat"] == "Databases" and app["image"] and app["ports"]
    assert dockerapps.CATALOG["oracle"]["env"]["ORACLE_PWD"] == "{secret_alnum}"
    listed = {a["id"]: a for a in dockerapps.catalog()["catalog"]}
    assert listed["mongodb"]["local"] is True and not listed["couchdb"].get("local")


def test_sysapps_database_group():
    assert {k for k, v in sysapps.CATALOG.items() if v["group"] == "db"} == {"mariadb", "postgresql", "redis", "memcached"}
    assert sysapps.CATALOG["redis"]["pkg"] == "redis-server"


def test_docker_dbs_status(monkeypatch):
    monkeypatch.setattr(dockerapps, "_state", lambda: {"apps": {"mongo1": {"app": "mongodb"}, "web": {"app": "n8n"}}})
    monkeypatch.setattr(dockerapps, "_run", lambda argv, timeout=300, cwd=None: subprocess.CompletedProcess(argv, 0, "mongo1\nweb\n", ""))
    rows = {r["id"]: r for r in sysapps._docker_dbs()}
    assert list(rows) == list(sysapps.DOCKER_DBS)
    assert rows["mongodb"]["installed"] and rows["mongodb"]["active"] and rows["mongodb"]["containers"] == ["mongo1"]
    assert rows["oracle"]["installed"] is False and rows["oracle"]["docker"] is True
    assert rows["mongodb"]["ram_typical"].startswith("~")


def test_docker_dbs_status_without_state(monkeypatch):
    def boom():
        raise OSError("no state")
    monkeypatch.setattr(dockerapps, "_state", boom)
    rows = sysapps._docker_dbs()
    assert all(not r["installed"] and not r["active"] for r in rows)


def test_redis_uninstall_refused_while_mail_uses_it(monkeypatch):
    monkeypatch.setattr(sysapps, "_require_linux", lambda: None)
    monkeypatch.setattr(requires, "installed", lambda cid: cid == "mail")
    with pytest.raises(sysapps.SysAppError, match="Rspamd"):
        sysapps.uninstall("redis")
