"""Servers: the list of other panels, certificate pinning, and acting on all of them at once.
http.client is replaced by a fake connection, so what goes over the wire (method, path, token header,
JSON body) and what comes back (status, payload, certificate) are both under the test's control."""
from __future__ import annotations

import hashlib
import json
import subprocess
import types

import pytest

from backend import problems, servers

DER_A = b"cert-of-server-a"
FP_A = hashlib.sha256(DER_A).hexdigest()


class FakeResponse:
    def __init__(self, status, raw):
        self.status = status
        self._raw = raw

    def read(self, n=None):
        return self._raw


class FakeConn:
    """One http(s) connection: records the request and answers from the `answers` table."""
    answers: dict = {}
    made: list = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.https = host, port, context is not None
        self.sock = types.SimpleNamespace(getpeercert=lambda binary_form=True: FakeConn.answers.get("der", DER_A))
        self.closed = False
        FakeConn.made.append(self)

    def connect(self):
        if FakeConn.answers.get("down"):
            raise OSError("connection refused")

    def request(self, method, path, body=None, headers=None):
        self.req = (method, path, body, headers)

    def getresponse(self):
        return FakeResponse(FakeConn.answers.get("status", 200), FakeConn.answers.get("raw", b'{"hostname": "pi-b"}'))

    def close(self):
        self.closed = True


@pytest.fixture
def wire(tmp_path, monkeypatch):
    FakeConn.answers = {}
    FakeConn.made = []
    monkeypatch.setattr(servers.http.client, "HTTPSConnection", FakeConn)
    monkeypatch.setattr(servers.http.client, "HTTPConnection", lambda host, port, timeout=None: FakeConn(host, port, timeout))
    monkeypatch.setattr(servers, "STATE", tmp_path / "servers.json")
    monkeypatch.setattr(servers.socket, "gethostbyname", lambda h: {"pi.lan": "192.168.0.50", "vps.example": "203.0.113.9"}[h])
    return FakeConn


# ------------------------------------------------------------------ addresses
def test_addresses_default_to_https_on_the_panel_port(wire):
    assert servers._parse(" 192.168.0.100 ") == ("https", "192.168.0.100", 8088)
    assert servers._parse("https://pi.lan:9443/") == ("https", "pi.lan", 9443)
    assert servers._parse("http://pi.lan") == ("http", "pi.lan", 8088)    # private: plain http is fine
    with pytest.raises(servers.ServerError, match="unencrypted"):
        servers._parse("http://vps.example")
    with pytest.raises(servers.ServerError, match="Can't find"):
        servers._parse("http://nowhere.invalid")
    for bad in ("", "ftp://pi.lan", "https://"):
        with pytest.raises(servers.ServerError, match="Enter the panel's address"):
            servers._parse(bad)


def test_requests_carry_the_token_and_check_the_pinned_certificate(wire):
    srv = {"name": "B", "url": "https://pi.lan:8088", "token": "aur_abc", "fingerprint": FP_A}
    status, payload, fp = servers._request(srv, "POST", "/api/guard/ban", {"target": "1.2.3.4"})
    assert (status, payload, fp) == (200, {"hostname": "pi-b"}, FP_A)
    conn = wire.made[-1]
    assert conn.https and conn.port == 8088 and conn.closed
    method, path, body, headers = conn.req
    assert method == "POST" and path == "/api/guard/ban" and json.loads(body) == {"target": "1.2.3.4"}
    assert headers["Authorization"] == "Bearer aur_abc" and headers["Content-Type"] == "application/json"
    status, payload, fp = servers._request(srv, "GET", "/api/fleet/self")
    assert "Content-Type" not in wire.made[-1].req[3] and wire.made[-1].req[2] is None
    wire.answers["der"] = b"someone else's certificate"
    with pytest.raises(servers.ServerError, match="certificate changed"):
        servers._request(srv, "GET", "/api/fleet/self")
    assert wire.made[-1].closed
    assert servers._request(srv, "GET", "/api/fleet/self", pin="")[2] == hashlib.sha256(b"someone else's certificate").hexdigest()


def test_unreachable_servers_and_non_json_answers_are_explained(wire):
    srv = {"name": "B", "url": "http://pi.lan", "token": "aur_abc"}
    wire.answers.update(status=502, raw=b"<html>Bad Gateway</html>")
    assert servers._request(srv, "GET", "/x") == (502, {"detail": "<html>Bad Gateway</html>"}, "")
    assert not wire.made[-1].https
    wire.answers["down"] = True
    with pytest.raises(servers.ServerError, match="Can't reach B: connection refused"):
        servers._request(srv, "GET", "/x")


# ------------------------------------------------------------------ the list
def test_adding_a_server_pins_its_certificate_and_stores_the_token_privately(wire, tmp_path):
    with pytest.raises(servers.ServerError, match="starts with aur_"):
        servers.add("B", "pi.lan", "not-a-token")
    wire.answers["status"] = 401
    with pytest.raises(servers.ServerError, match="didn't accept the token"):
        servers.add("B", "pi.lan", "aur_abc")
    wire.answers.update(status=404, raw=b'{"detail": "Not Found"}')
    with pytest.raises(servers.ServerError, match="answered 404: Not Found"):
        servers.add("B", "pi.lan", "aur_abc")
    wire.answers = {}
    shown = servers.add("", "pi.lan", " aur_abc ")
    assert shown["name"] == "pi.lan" and shown["url"] == "https://pi.lan:8088" and shown["hostname"] == "pi-b"
    assert shown["fingerprint"] == FP_A[:16] and "token" not in shown
    stored = json.loads((tmp_path / "servers.json").read_text())["servers"][0]
    assert stored["token"] == "aur_abc" and stored["fingerprint"] == FP_A
    with pytest.raises(servers.ServerError, match="already in the list"):
        servers.add("B again", "https://pi.lan:8088", "aur_other")
    assert servers.count() == 1
    assert servers.remove(shown["id"]) == {"ok": True} and servers.count() == 0
    assert servers._load() == {"servers": []}


def test_repin_accepts_a_renewed_certificate(wire):
    sid = servers.add("B", "pi.lan", "aur_abc")["id"]
    wire.answers["der"] = b"renewed"
    r = servers.repin(sid)
    assert r == {"ok": True, "fingerprint": hashlib.sha256(b"renewed").hexdigest()}
    assert servers._load()["servers"][0]["fingerprint"] == r["fingerprint"]
    with pytest.raises(servers.ServerError, match="Unknown server"):
        servers.repin("nope")
    wire.answers["status"] = 500
    with pytest.raises(servers.ServerError, match="answered 500"):
        servers.repin(sid)


# ------------------------------------------------------------------ this server's own summary
def test_self_summary_collects_health_from_every_subsystem(monkeypatch):
    import psutil
    from backend import alerts, guard, system_info, updates
    monkeypatch.setattr(psutil, "virtual_memory", lambda: types.SimpleNamespace(percent=41.5, total=8 * 2**30))
    monkeypatch.setattr(psutil, "disk_usage", lambda p: types.SimpleNamespace(percent=63.0, total=64 * 2**30))
    monkeypatch.setattr(psutil, "cpu_percent", lambda interval=None: 7.5)
    monkeypatch.setattr(psutil, "cpu_count", lambda: 4)
    monkeypatch.setattr(psutil, "boot_time", lambda: servers.time.time() - 3600)
    monkeypatch.setattr(psutil, "sensors_temperatures", lambda: {"cpu_thermal": [types.SimpleNamespace(current=51.6)]}, raising=False)
    monkeypatch.setattr(servers.os, "getloadavg", lambda: (0.42, 0.3, 0.1), raising=False)
    monkeypatch.setattr(system_info, "is_pi", lambda: True)
    monkeypatch.setattr(alerts, "load", lambda: {"active": {"a": {"level": "warning", "title": "Disk"}, "b": {"level": "critical", "title": "RAM"}}})
    monkeypatch.setattr(updates, "cached", lambda: {"total": 3, "security": 1})
    monkeypatch.setattr(servers.subprocess if hasattr(servers, "subprocess") else subprocess, "run",
                        lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "ssh.service loaded failed failed OpenSSH\n\n", ""))
    monkeypatch.setattr(guard, "listing", lambda: {"bans": [1, 2], "fail2ban": [3]})
    out = servers.self_summary()
    assert out["cpu"] == 7.5 and out["cpus"] == 4 and out["mem_pct"] == 41.5 and out["disk_pct"] == 63.0 and out["load"] == 0.42
    assert 3595 <= out["uptime"] <= 3605 and out["temp"] == 52 and out["pi"] is True
    assert out["alerts"] == [{"level": "critical", "title": "RAM"}, {"level": "warning", "title": "Disk"}]
    assert out["updates"]["total"] == 3 and out["updates"]["security"] == 1 and out["updates"]["reboot"] is False
    assert out["failed_units"] == ["ssh.service"] and out["bans"] == 3 and out["version"]


def test_self_summary_survives_broken_subsystems(monkeypatch):
    import psutil
    from backend import alerts, guard, updates
    boom = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    monkeypatch.setattr(psutil, "virtual_memory", boom)
    monkeypatch.setattr(alerts, "load", boom)
    monkeypatch.setattr(updates, "cached", boom)
    monkeypatch.setattr(guard, "listing", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    problems.clear()
    out = servers.self_summary()
    assert "cpu" not in out and out["alerts"] == [] and out["failed_units"] == [] and "bans" not in out and "updates" not in out
    assert out["hostname"] and len(problems.listing()["quiet"]) >= 3   # carried on, but counted
    problems.clear()


# ------------------------------------------------------------------ all servers at once
@pytest.fixture
def fleet(tmp_path, monkeypatch):
    monkeypatch.setattr(servers, "STATE", tmp_path / "servers.json")
    servers._save({"servers": [{"id": "a1", "name": "A", "url": "https://a:8088", "token": "aur_a", "added": 1, "hostname": "a"},
                               {"id": "b2", "name": "B", "url": "https://b:8088", "token": "aur_b", "added": 2},
                               {"id": "c3", "name": "C", "url": "https://c:8088", "token": "aur_c", "added": 3}]})
    calls = []

    def request(srv, method, path, body=None, timeout=8.0, pin=None):
        calls.append((srv["name"], method, path, body))
        if srv["name"] == "A":
            return 200, {"hostname": "a", "cpu": 3.0}, "fp"
        if srv["name"] == "B":
            return 401, {"detail": "Not authenticated"}, "fp"
        raise servers.ServerError("Can't reach C: timed out")
    monkeypatch.setattr(servers, "_request", request)
    monkeypatch.setattr(servers, "self_summary", lambda: {"hostname": "me", "cpu": 1.0})
    return calls


def test_overview_shows_this_server_first_then_every_other_with_its_state(fleet):
    ov = servers.overview()["servers"]
    assert ov[0] == {"id": "", "name": "This server", "hostname": "me", "cpu": 1.0, "ok": True, "local": True}
    a, b, c = ov[1:]
    assert a["ok"] and a["cpu"] == 3.0 and a["hostname"] == "a" and "token" not in a and a["ms"] >= 0
    assert b == {"id": "b2", "name": "B", "url": "https://b:8088", "added": 2, "fingerprint": "", "ok": False, "error": "answered 401 (token revoked?)"}
    assert c["ok"] is False and c["error"] == "Can't reach C: timed out"
    assert {(n, m, p) for n, m, p, _ in fleet} == {("A", "GET", "/api/fleet/self"), ("B", "GET", "/api/fleet/self"), ("C", "GET", "/api/fleet/self")}


def test_ban_and_unban_everywhere_report_per_server(fleet):
    r = servers.ban_everywhere("203.0.113.9", "scanner", 3600)
    assert r == {"A": {"ok": True, "error": ""}, "B": {"ok": False, "error": "Not authenticated"}, "C": {"ok": False, "error": "Can't reach C: timed out"}}
    body = next(b for n, m, p, b in fleet if n == "A" and p == "/api/guard/ban")
    assert body == {"target": "203.0.113.9", "reason": "scanner", "duration": 3600, "source": "Servers · ban everywhere"}
    r = servers.unban_everywhere("203.0.113.9")
    assert r["A"] == {"ok": True, "error": ""} and r["B"]["error"] == "Not authenticated"
    assert ("A", "POST", "/api/guard/unban", {"target": "203.0.113.9"}) in fleet
