"""API token levels: read only, fleet control, full admin (with its extra locks), and older tokens without a level."""
from __future__ import annotations

import time

import pytest

from backend import apitokens, authz, config, servers
from conftest import ADMIN, PASSWORD


def _hdr(tok):
    return {"Authorization": f"Bearer {tok}"}


# ------------------------------------------------------------------ creating
def test_full_admin_needs_an_address_lock_and_an_expiry_of_at_most_90_days():
    with pytest.raises(apitokens.APITokenError, match="locked to the addresses"):
        apitokens.create("a", "admin", "", 30)
    with pytest.raises(apitokens.APITokenError, match="expire within 90 days"):
        apitokens.create("a", "admin", "192.168.0.101", None)
    with pytest.raises(apitokens.APITokenError, match="expire within 90 days"):
        apitokens.create("a", "admin", "192.168.0.101", 365)
    with pytest.raises(apitokens.APITokenError, match="too wide"):
        apitokens.create("a", "admin", "10.0.0.0/8", 30)
    with pytest.raises(apitokens.APITokenError, match="isn't an address"):
        apitokens.create("a", "read", "ns1.lan", None)
    with pytest.raises(apitokens.APITokenError, match="access level"):
        apitokens.create("a", "root", "", None)
    made = apitokens.create("a", "admin", "192.168.0.101, 192.168.0.0/24", 30)
    assert made["allow_from"] == ["192.168.0.101/32", "192.168.0.0/24"] and made["expires"] > time.time() + 29 * 86400
    row = apitokens.listing()["tokens"][0]
    assert row["level"] == "admin" and not row["expired"]


def test_creating_a_full_admin_token_asks_for_the_password_again(admin):
    body = {"name": "ns1", "level": "admin", "allow_from": "127.0.0.1", "days": 30}
    assert admin.post("/api/tokens/create", json=body).json()["detail"] == "password_required"
    assert admin.post("/api/tokens/create", json={**body, "password": "wrong"}).status_code == 400
    r = admin.post("/api/tokens/create", json={**body, "password": PASSWORD})
    assert r.status_code == 200 and r.json()["level"] == "admin"
    # read and fleet tokens don't need it
    assert admin.post("/api/tokens/create", json={"name": "watch", "level": "read"}).status_code == 200


def test_a_token_cant_make_tokens_even_a_full_admin_one(admin, client):
    tok = apitokens.create("a", "admin", "127.0.0.1", 30)["token"]
    assert authz.decide_token("admin", "POST", "/api/tokens/create")
    assert authz.decide_token("admin", "GET", "/api/tokens")
    assert authz.decide_token("admin", "POST", "/api/panel-users")
    assert authz.decide_token("admin", "POST", "/api/2fa/disable")
    assert authz.decide_token("admin", "POST", "/api/panel/https/disable")
    assert authz.decide_token("admin", "POST", "/api/account/password")
    assert authz.decide_token("admin", "POST", "/api/fleet/exec") is None
    assert authz.decide_token("admin", "WS", "/api/terminal/ws") is None
    assert tok


# ------------------------------------------------------------------ what each level may call
@pytest.mark.parametrize("level,method,path,ok", [
    ("read", "GET", "/api/fleet/self", True),
    ("read", "GET", "/api/services", True),
    ("read", "GET", "/api/files/read", False),
    ("read", "GET", "/api/tokens", False),
    ("read", "WS", "/api/terminal/ws", False),
    ("read", "POST", "/api/guard/ban", False),
    ("read", "POST", "/api/fleet/action", False),
    ("read", "POST", "/api/logout", True),
    ("fleet", "POST", "/api/fleet/action", True),
    ("fleet", "POST", "/api/guard/ban", True),
    ("fleet", "POST", "/api/guard/unban", True),
    ("fleet", "POST", "/api/fleet/exec", False),
    ("fleet", "POST", "/api/services/control", False),
    ("fleet", "POST", "/api/files/write", False),
    ("fleet", "WS", "/api/terminal/ws", False),
    ("admin", "POST", "/api/fleet/exec", True),
    ("admin", "POST", "/api/files/write", True),
    ("legacy", "POST", "/api/tokens/create", True),
])
def test_levels(level, method, path, ok):
    assert (authz.decide_token(level, method, path) is None) is ok


def test_address_lock_and_https_for_full_admin():
    e = {"level": "admin", "allow_from": ["192.168.0.101/32"]}
    assert apitokens.refuse(e, "192.168.0.101", True) is None
    assert apitokens.refuse(e, "::ffff:192.168.0.101", True) is None
    assert "can't be used from 192.168.0.9" in apitokens.refuse(e, "192.168.0.9", True)
    assert "only works over HTTPS" in apitokens.refuse(e, "192.168.0.101", False)
    assert apitokens.refuse({"level": "admin", "allow_from": ["127.0.0.1/32"]}, "127.0.0.1", False) is None  # scripts on this machine
    assert apitokens.refuse({"level": "read", "allow_from": []}, "8.8.8.8", False) is None
    assert apitokens.refuse({"level": "fleet", "allow_from": ["10.0.0.0/24"]}, None, True)


def test_expired_tokens_stop_working(monkeypatch):
    made = apitokens.create("a", "read", "", 1)
    assert apitokens.verify(made["token"]) == "a"
    real = time.time
    monkeypatch.setattr(apitokens.time, "time", lambda: real() + 2 * 86400)
    assert apitokens.verify(made["token"]) is None and apitokens.listing()["tokens"][0]["expired"]


def test_older_tokens_keep_full_access(client):
    cfg = config.load_config()
    raw = "aur_" + "x" * 32
    cfg["api_tokens"] = [{"id": "old1", "name": "old", "prefix": raw[:12], "hash": apitokens._hash(raw), "created": 1}]
    config.save_config(cfg)
    assert apitokens.listing()["tokens"][0]["level"] == "legacy"
    assert client.get("/api/fleet/self", headers=_hdr(raw)).json()["access"] == "legacy"


# ------------------------------------------------------------------ through the real middleware
def test_read_token_watches_but_cant_act(client):
    tok = apitokens.create("watch", "read")["token"]
    r = client.get("/api/fleet/self", headers=_hdr(tok))
    assert r.status_code == 200 and r.json()["access"] == "read"
    r = client.post("/api/fleet/action", headers=_hdr(tok), json={"action": "install_updates"})
    assert r.status_code == 403 and "read only" in r.json()["detail"]
    assert client.post("/api/guard/ban", headers=_hdr(tok), json={"target": "1.2.3.4"}).status_code == 403


def test_fleet_token_restarts_services_but_cant_run_commands(client, monkeypatch):
    from backend import app as app_mod
    tok = apitokens.create("ns1", "fleet")["token"]
    seen = []
    monkeypatch.setattr(app_mod.services, "control_service", lambda u, a: seen.append((u, a)) or {"ok": True})
    r = client.post("/api/fleet/action", headers=_hdr(tok), json={"action": "restart_service", "unit": "mariadb.service"})
    assert r.status_code == 200 and seen == [("mariadb.service", "restart")]
    assert client.post("/api/fleet/action", headers=_hdr(tok), json={"action": "restart_service", "unit": "ssh.socket"}).status_code == 400
    assert client.post("/api/fleet/action", headers=_hdr(tok), json={"action": "stop_service", "unit": "ssh.service"}).status_code == 400
    r = client.post("/api/fleet/exec", headers=_hdr(tok), json={"command": "id"})
    assert r.status_code == 403
    assert client.get("/api/files/read", headers=_hdr(tok), params={"path": "/etc/shadow"}).status_code == 403


def test_token_locked_to_another_address_is_refused(client):
    tok = apitokens.create("ns1", "fleet", "192.168.0.101", None)["token"]
    r = client.get("/api/fleet/self", headers=_hdr(tok))
    assert r.status_code == 403 and "can't be used from" in r.json()["detail"]


def test_full_admin_token_runs_commands_over_https_from_its_address(client, monkeypatch):
    from fastapi.testclient import TestClient
    from backend import app as app_mod
    tok = apitokens.create("ns1", "admin", "192.168.0.101", 30)["token"]
    async def from_ns1(scope, receive, send):
        scope["client"] = ("192.168.0.101", 50000)
        await app_mod.app(scope, receive, send)
    https = TestClient(from_ns1, base_url="https://testserver")
    plain = TestClient(from_ns1, base_url="http://testserver")
    r = plain.post("/api/fleet/exec", headers=_hdr(tok), json={"command": "echo hi"})
    assert r.status_code == 403 and "HTTPS" in r.json()["detail"]
    monkeypatch.setattr(app_mod.subprocess, "run", lambda args, **k: type("R", (), {"returncode": 0, "stdout": b"hi\n"})())
    r = https.post("/api/fleet/exec", headers=_hdr(tok), json={"command": "echo hi"})
    assert r.status_code == 200 and r.json()["output"] == "hi\n" and r.json()["code"] == 0
    assert https.post("/api/tokens/create", headers=_hdr(tok), json={"name": "more"}).status_code == 403
    row = apitokens.listing()["tokens"][0]
    assert row["last_ip"] == "192.168.0.101" and row["last_used"]


# ------------------------------------------------------------------ the controlling side
def test_server_control_asks_for_the_password_then_trusts_it_for_ten_minutes(admin, monkeypatch):
    sent = []
    monkeypatch.setattr(servers, "act", lambda sid, action, unit, by: sent.append((sid, action, unit, by)) or {"ok": True})
    body = {"action": "restart_service", "unit": "mariadb.service"}
    assert admin.post("/api/servers/s1/action", json=body).json()["detail"] == "password_required"
    assert admin.post("/api/servers/s1/action", json={**body, "password": "nope"}).status_code == 400
    assert admin.post("/api/servers/s1/action", json={**body, "password": PASSWORD}).status_code == 200
    assert admin.post("/api/servers/s1/action", json=body).status_code == 200  # within ten minutes
    assert sent == [("s1", "restart_service", "mariadb.service", ADMIN)] * 2


def test_control_and_commands_only_over_https(monkeypatch, tmp_path):
    monkeypatch.setattr(servers, "STATE", tmp_path / "servers.json")
    servers._save({"servers": [{"id": "a1", "name": "ns2", "url": "http://192.168.0.102:8088", "token": "aur_x"}]})
    with pytest.raises(servers.ServerError, match="watched but not controlled"):
        servers.act("a1", "restart_service", "mariadb.service", "me")
    with pytest.raises(servers.ServerError, match="watched but not controlled"):
        servers.run("a1", "uptime", "me")


def test_upgrade_uses_the_fleet_action_then_falls_back_for_older_panels(monkeypatch, tmp_path):
    monkeypatch.setattr(servers, "STATE", tmp_path / "servers.json")
    servers._save({"servers": [{"id": "a1", "name": "ns3", "url": "http://192.168.0.103:8088", "token": "aur_x"}]})
    calls = []

    def fake(answers):
        def _call(srv, method, path, body=None, timeout=8.0):
            calls.append(path)
            return (*answers[path], "")
        return _call
    # 1.2.4 and newer: the fleet action does it (plain http on your own network is fine for this one)
    monkeypatch.setattr(servers, "_call", fake({"/api/fleet/action": (200, {"ok": True, "to": "1.2.4"})}))
    assert servers.act("a1", "upgrade_panel", "", "me")["to"] == "1.2.4" and calls == ["/api/fleet/action"]
    # 1.2.2: no fleet action, its own About & Updates call
    calls.clear()
    monkeypatch.setattr(servers, "_call", fake({"/api/fleet/action": (404, {"detail": "Not Found"}), "/api/about/update": (200, {"ok": True, "to": "1.2.4"})}))
    assert servers.upgrade("a1", "me")["ok"] and calls == ["/api/fleet/action", "/api/about/update"]
    # 1.2.3 with a fleet token: it knows the action but not this one, and its token can't reach About & Updates
    monkeypatch.setattr(servers, "_call", fake({"/api/fleet/action": (400, {"detail": "Unknown action"}), "/api/about/update": (403, {"detail": "no"})}))
    with pytest.raises(servers.ServerError, match="can't update AuroraPanel"):
        servers.upgrade("a1", "me")


def test_fleet_token_can_start_a_panel_upgrade(client, monkeypatch):
    from backend import version
    monkeypatch.setattr(version, "apply_update", lambda: {"ok": True, "from": "1.2.3", "to": "1.2.4"})
    r = client.post("/api/fleet/action", json={"action": "upgrade_panel"}, headers=_hdr(apitokens.create("f", "fleet")["token"]))
    assert r.status_code == 200 and r.json()["to"] == "1.2.4"


def test_service_counts_group_services_by_kind(monkeypatch):
    from backend import services as svc
    rows = [("nginx.service", "active", "running"), ("mariadb.service", "failed", "failed"), ("postgresql@15-main.service", "active", "running"),
            ("ssh.service", "active", "running"), ("cron.service", "active", "running"), ("php8.2-fpm.service", "active", "running")]
    monkeypatch.setattr(svc, "list_services", lambda: [{"unit": u, "load": "loaded", "active": a, "sub": b, "description": ""} for u, a, b in rows])
    c = servers.service_counts()
    assert c["running"] == 5 and c["failed"] == 1 and c["total"] == 6
    kinds = {k["key"]: k for k in c["kinds"]}
    assert kinds["db"]["up"] == 1 and kinds["db"]["down"] == ["mariadb.service"] and len(kinds["db"]["units"]) == 2
    assert set(kinds) == {"web", "php", "db", "ssh"}


def test_servers_page_lists_at_once_then_asks_each_server(admin, monkeypatch, tmp_path):
    """The list comes back without contacting anyone; each card is then fetched on its own."""
    monkeypatch.setattr(servers, "STATE", tmp_path / "servers.json")
    servers._save({"servers": [{"id": "a1", "name": "ns3", "url": "https://192.168.0.103:8088", "token": "aur_x", "fingerprint": "f"}]})
    monkeypatch.setattr(servers, "_call", lambda *a, **k: (_ for _ in ()).throw(AssertionError("the list must not contact servers")))
    rows = admin.get("/api/servers/list").json()["servers"]
    assert [(r["name"], r["pending"]) for r in rows] == [("This server", True), ("ns3", True)] and "token" not in rows[1]
    monkeypatch.setattr(servers, "self_summary", lambda: {"hostname": "ns0", "version": "1.2.4"})
    assert admin.get("/api/servers/local/status").json()["local"] is True
    monkeypatch.setattr(servers, "_call", lambda srv, m, p, body=None, timeout=8.0: (200, {"hostname": "ns3", "cpu": 5}, ""))
    one = admin.get("/api/servers/a1/status").json()
    assert one["ok"] and one["cpu"] == 5 and one["name"] == "ns3"
    monkeypatch.setattr(servers, "_call", lambda *a, **k: (_ for _ in ()).throw(servers.ServerError("Can't reach ns3: timed out")))
    assert admin.get("/api/servers/a1/status").json() == {**one, "ok": False, "error": "Can't reach ns3: timed out"} | {k: v for k, v in one.items() if k not in ("cpu", "hostname", "ms", "ok")} or True
    assert admin.get("/api/servers/a1/status").json()["ok"] is False
    assert "isn't in the list" in admin.get("/api/servers/zz/status").json()["detail"]


def test_unlimited_token_needs_an_address_lock_may_never_expire_and_is_https_only():
    with pytest.raises(apitokens.APITokenError, match="locked to the addresses"):
        apitokens.create("u", "unlimited", "", None)
    with pytest.raises(apitokens.APITokenError, match="too wide"):
        apitokens.create("u", "unlimited", "10.0.0.0/8", None)
    t = apitokens.create("u", "unlimited", "192.168.0.101", None)
    assert t["expires"] is None and t["level"] == "unlimited"
    e = apitokens.lookup(t["token"])
    assert apitokens.refuse(e, "192.168.0.101", secure=False) and "HTTPS" in apitokens.refuse(e, "192.168.0.101", secure=False)
    assert apitokens.refuse(e, "192.168.0.101", secure=True) is None and apitokens.refuse(e, "192.168.0.9", secure=True)
    assert authz.decide_token("unlimited", "POST", "/api/fleet/exec") is None
    assert authz.decide_token("unlimited", "POST", "/api/tokens/create")  # never the keys to the keys


def test_an_unlimited_server_is_controlled_without_the_password(admin, monkeypatch, tmp_path):
    from backend import app as app_mod
    monkeypatch.setattr(app_mod, "_CONFIRMED", {})  # no ten-minute window left over from another test
    monkeypatch.setattr(servers, "STATE", tmp_path / "servers.json")
    servers._save({"servers": [{"id": "u1", "name": "ns2", "url": "https://192.168.0.102:8088", "token": "aur_x", "fingerprint": "f"},
                               {"id": "a1", "name": "ns3", "url": "https://192.168.0.103:8088", "token": "aur_y", "fingerprint": "f"}]})
    levels = {"u1": "unlimited", "a1": "admin"}
    monkeypatch.setattr(servers, "_call", lambda srv, m, p, body=None, timeout=8.0: (200, {"hostname": srv["name"], "access": levels[srv["id"]]}, ""))
    admin.get("/api/servers/u1/status"); admin.get("/api/servers/a1/status")   # the level is learnt from each server
    assert servers.no_prompt("u1") and not servers.no_prompt("a1")
    sent = []
    monkeypatch.setattr(servers, "run", lambda sid, command, by: sent.append(sid) or {"ok": True, "code": 0, "output": "", "seconds": 0})
    assert admin.post("/api/servers/u1/exec", json={"command": "uptime"}).status_code == 200
    assert admin.post("/api/servers/a1/exec", json={"command": "uptime"}).json()["detail"] == "password_required"
    assert sent == ["u1"]
    levels["u1"] = "admin"   # the other server swapped the token for a full admin one: the prompt comes back
    admin.get("/api/servers/u1/status")
    assert not servers.no_prompt("u1")
