"""Port Checker: every listening port on the machine, and one outside test for all of them."""
import json

import pytest

from backend import netmgr, portcheck


def _port(port, proto, process, scope, address="0.0.0.0"):
    return {"port": port, "proto": proto, "process": process, "scope": scope, "address": address}


@pytest.fixture
def box(monkeypatch):
    listening = [_port(22, "tcp", "sshd", "all interfaces"), _port(80, "tcp", "apache2", "all interfaces"), _port(445, "tcp", "smbd", "all interfaces"),
                 _port(3306, "tcp", "mariadbd", "this machine only", "127.0.0.1"), _port(5353, "udp", "?", "all interfaces"),
                 _port(8088, "tcp", "python", "this machine only", "127.0.0.1"), _port(8088, "tcp", "python", "all interfaces"),
                 _port("http-alt", "tcp", "odd", "all interfaces")]
    monkeypatch.setattr(netmgr, "ports", lambda: {"ports": listening})
    monkeypatch.setattr(portcheck, "default_route", lambda: {"ip": "192.168.0.100", "gateway": "192.168.0.1", "iface": "eth0"})
    monkeypatch.setattr(portcheck, "public_ip", lambda fresh=False: "203.0.113.9")
    monkeypatch.setattr(portcheck, "_firewall_rules", lambda: {"installed": True, "active": True, "kind": "ufw", "text": "Status: active\n22/tcp ALLOW Anywhere\n80 ALLOW Anywhere\n"})
    monkeypatch.setattr(portcheck, "_evidence", lambda port, proto: None)
    return listening


def test_every_listening_port_is_listed_with_what_it_is_and_who_can_reach_it(box):
    d = portcheck.listening()
    rows = {(r["port"], r["proto"]): r for r in d["ports"]}
    assert [r["port"] for r in d["ports"]] == [22, 80, 445, 3306, 5353, 8088]            # sorted, one row per port, odd names left out
    assert rows[(22, "tcp")]["service"] == "SSH" and rows[(22, "tcp")]["process"] == "sshd" and rows[(22, "tcp")]["firewall"] is True
    assert rows[(445, "tcp")]["firewall"] is False and rows[(445, "tcp")]["private"] is True   # not allowed by the firewall; belongs on the LAN
    assert rows[(3306, "tcp")]["local_only"] is True and rows[(3306, "tcp")]["outside"] is False and rows[(3306, "tcp")]["firewall"] is None
    assert rows[(8088, "tcp")]["local_only"] is False and rows[(8088, "tcp")]["address"] == "0.0.0.0"   # one socket on every interface is enough
    assert rows[(5353, "udp")]["process"] == "" and rows[(5353, "udp")]["service"].startswith("mDNS")
    assert d["public_ip"] == "203.0.113.9" and d["checked"] == 0 and d["firewall"] == {"installed": True, "active": True}
    assert all(r["outside"] is None for r in d["ports"] if not r["local_only"])            # nothing has left the machine yet


def test_one_outside_test_covers_all_tcp_ports_and_flags_what_should_be_private(box, monkeypatch):
    asked = []
    monkeypatch.setattr(portcheck, "_probe_many", lambda ip, ports: asked.append((ip, ports)) or {22: False, 80: True, 445: True})
    d = portcheck.scan()
    assert asked == [("203.0.113.9", [22, 80, 445, 8088])]                                 # local-only and UDP ports are never sent out
    rows = {(r["port"], r["proto"]): r for r in d["ports"]}
    assert rows[(80, "tcp")]["outside"] is True and "answered" in rows[(80, "tcp")]["why"]
    assert rows[(22, "tcp")]["outside"] is False and "router or a firewall" in rows[(22, "tcp")]["why"]
    assert rows[(8088, "tcp")]["outside"] is None and "didn't answer" in rows[(8088, "tcp")]["why"]
    assert rows[(5353, "udp")]["outside"] is None and "UDP" in rows[(5353, "udp")]["why"]
    assert d["summary"] == {"total": 6, "visible": 2, "hidden": 1, "local": 1, "unknown": 2, "exposed": [445]} and d["checked"] > 0


def test_udp_counts_as_proven_once_a_vpn_client_came_in_from_outside(box, monkeypatch):
    monkeypatch.setattr(portcheck, "_probe_many", lambda ip, ports: {})
    monkeypatch.setattr(portcheck, "_evidence", lambda port, proto: "phone connected from 198.51.100.7" if port == 5353 else None)
    row = next(r for r in portcheck.scan()["ports"] if r["proto"] == "udp")
    assert row["outside"] is True and row["why"].startswith("phone connected")


def test_without_a_public_address_nothing_is_sent_out(box, monkeypatch):
    monkeypatch.setattr(portcheck, "public_ip", lambda fresh=False: None)
    monkeypatch.setattr(portcheck, "_probe_many", lambda ip, ports: pytest.fail("no address to test"))
    d = portcheck.scan()
    assert all(r["outside"] is None for r in d["ports"] if r["proto"] == "tcp" and not r["local_only"])


def test_the_batch_test_asks_once_per_twenty_ports_and_falls_back_for_what_is_missing(monkeypatch):
    sent = []

    class Answer:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self.body

    def urlopen(req, timeout=0):
        ports = json.loads(req.data)["ports"]
        sent.append(ports)
        return Answer(json.dumps({"check": [{"port": p, "status": p % 2 == 0} for p in ports if p != 7]}).encode())
    monkeypatch.setattr(portcheck.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(portcheck, "_probe_tcp", lambda ip, port: True)
    out = portcheck._probe_many("203.0.113.9", list(range(1, 26)))
    assert [len(s) for s in sent] == [20, 5]
    assert out[2] is True and out[3] is False and out[7] is True and len(out) == 25       # port 7 was skipped by the service: asked on its own


def test_firewall_answer_per_port():
    ufw = {"installed": True, "active": True, "kind": "ufw", "text": "22/tcp ALLOW Anywhere\n443 (v6) ALLOW Anywhere (v6)\n"}
    assert portcheck._allowed(ufw, 22, "tcp") is True and portcheck._allowed(ufw, 443, "tcp") is True and portcheck._allowed(ufw, 3306, "tcp") is False
    assert portcheck._allowed({**ufw, "active": False}, 3306, "tcp") is True              # an inactive firewall blocks nothing
    assert portcheck._allowed({"installed": False, "active": False, "kind": "ufw", "text": ""}, 22, "tcp") is None


def test_routes(admin, box, monkeypatch):
    monkeypatch.setattr(portcheck, "_probe_many", lambda ip, ports: {80: True})
    assert len(admin.get("/api/portcheck/ports").json()["ports"]) == 6
    assert admin.post("/api/portcheck/scan").json()["summary"]["visible"] == 1
