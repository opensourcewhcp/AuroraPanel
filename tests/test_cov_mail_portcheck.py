"""Port Checker: listener / firewall / UPnP parsing, NAT classification and the verdict with its advice."""
import io
import json
import subprocess

import pytest

from backend import portcheck

SS_TCP = ('LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=700,fd=3))\n'
          'LISTEN 0 511 *:8443 *:* users:(("python3",pid=900,fd=6))\n')
UPNP_OUT = """upnpc : miniupnpc library test client, version 2.2.
 desc: http://192.168.0.1:5000/rootDesc.xml
Found valid IGD : http://192.168.0.1:5000/ctl/IPConn
Local LAN ip address : 192.168.0.100
ExternalIPAddress = 203.0.113.9
 i protocol exPort->inAddr:inPort description remoteHost leaseTime
 0 TCP  8443->192.168.0.100:8443 'AuroraPanel' '' 0
 1 UDP 51820->192.168.0.100:51820 'wireguard' '' 0
"""


@pytest.fixture
def tools(monkeypatch):
    """Pretend every tool exists and answer subprocess calls from a table keyed on argv[0]."""
    calls: list[list[str]] = []
    answers: dict[str, str] = {}

    def run(argv, capture_output=True, text=True, timeout=None, **kw):
        calls.append(list(argv))
        if answers.get(argv[0]) == "TIMEOUT":
            raise subprocess.TimeoutExpired(argv, timeout or 1)
        return subprocess.CompletedProcess(argv, 0, answers.get(argv[0], ""), "")
    monkeypatch.setattr(portcheck.subprocess, "run", run)
    monkeypatch.setattr(portcheck.shutil, "which", lambda name, path=None: f"/usr/sbin/{name}")
    run.calls, run.answers = calls, answers
    return run


def test_port_and_protocol_validation():
    assert portcheck._validate("443", "tcp") == (443, "tcp")
    for port, proto, msg in (("x", "tcp", "Invalid port"), (None, "tcp", "Invalid port"), (0, "tcp", "1"),
                             (70000, "udp", "65535"), (80, "icmp", "tcp or udp")):
        with pytest.raises(portcheck.PortError, match=msg):
            portcheck._validate(port, proto)


def test_listener_finds_the_process_on_the_port(tools):
    tools.answers["ss"] = SS_TCP
    assert portcheck._listener(8443, "tcp") == {"listening": True, "process": "python3", "address": "*:8443"}
    assert tools.calls[-1] == ["ss", "-Hlnpt"]
    assert portcheck._listener(80, "tcp") == {"listening": False}


def test_listener_knows_wireguard_kernel_sockets(tools, monkeypatch):
    tools.answers["ss"] = ""
    tools.answers["wg"] = "wg0\t51820\n"
    assert portcheck._listener(51820, "udp") == {"listening": True, "process": "wireguard (kernel)", "address": "*:51820"}
    assert tools.calls[-2:] == [["ss", "-Hlnpu"], ["wg", "show", "all", "listen-port"]]
    assert portcheck._listener(51821, "udp") == {"listening": False}
    monkeypatch.setattr(portcheck.shutil, "which", lambda name, path=None: None)
    assert portcheck._listener(22, "tcp") == {"listening": None}


def test_ufw_status_is_parsed(tools, monkeypatch):
    tools.answers["/usr/sbin/ufw"] = "Status: active\n\nTo  Action  From\n22/tcp  ALLOW  Anywhere\n8443  ALLOW  Anywhere\n22/tcp (v6)  ALLOW  Anywhere (v6)\n"
    assert portcheck._ufw(22, "tcp") == {"installed": True, "active": True, "allowed": True}
    assert portcheck._ufw(8443, "udp") == {"installed": True, "active": True, "allowed": True}
    assert portcheck._ufw(80, "tcp") == {"installed": True, "active": True, "allowed": False}
    assert tools.calls[-1] == ["/usr/sbin/ufw", "status"]
    tools.answers["/usr/sbin/ufw"] = "Status: inactive\n"
    assert portcheck._ufw(22, "tcp")["active"] is False
    monkeypatch.setattr(portcheck.shutil, "which", lambda name, path=None: None)
    assert portcheck._ufw(22, "tcp") == {"installed": False, "active": False, "allowed": None}


def test_upnp_listing_is_parsed(tools, monkeypatch):
    tools.answers["upnpc"] = UPNP_OUT
    u = portcheck._upnp()
    assert u["available"] and u["router_wan_ip"] == "203.0.113.9" and u["desc_url"] == "http://192.168.0.1:5000/rootDesc.xml"
    assert u["mappings"] == [{"proto": "tcp", "external": 8443, "internal_ip": "192.168.0.100", "internal": 8443, "desc": "AuroraPanel"},
                             {"proto": "udp", "external": 51820, "internal_ip": "192.168.0.100", "internal": 51820, "desc": "wireguard"}]
    tools.answers["upnpc"] = "No IGD UPnP Device found on the network !"
    assert portcheck._upnp() == {"available": False, "installed": True}
    tools.answers["upnpc"] = "TIMEOUT"
    assert portcheck._upnp() == {"available": False, "installed": True}
    monkeypatch.setattr(portcheck.shutil, "which", lambda name, path=None: None)
    assert portcheck._upnp() == {"available": False, "installed": False}


def test_nat_kind_classifies_the_router_wan_address():
    assert portcheck._nat_kind(None, "1.2.3.4") is None
    assert portcheck._nat_kind("1.2.3.4", "1.2.3.4") is None
    assert portcheck._nat_kind("100.64.5.5", "1.2.3.4") == "cgnat"
    assert portcheck._nat_kind("192.168.1.2", "1.2.3.4") == "double"
    assert portcheck._nat_kind("5.6.7.8", "1.2.3.4") == "cgnat"


class FakeResponse:
    def __init__(self, body):
        self.body = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.body


def test_outside_probe_uses_the_first_service_that_answers_for_our_ip(monkeypatch):
    seen = []

    def urlopen(req, timeout=0):
        seen.append(req.full_url)
        if "ifconfig.co" in req.full_url:
            return FakeResponse({"ip": "1.2.3.4", "reachable": True})
        raise AssertionError("second service must not be asked")
    monkeypatch.setattr(portcheck.urllib.request, "urlopen", urlopen)
    assert portcheck._probe_tcp("1.2.3.4", 443) is True
    assert seen == ["https://ifconfig.co/port/443"]


def test_outside_probe_falls_back_when_the_first_sees_another_ip(monkeypatch):
    def urlopen(req, timeout=0):
        if "ifconfig.co" in req.full_url:
            return FakeResponse({"ip": "9.9.9.9", "reachable": True})
        assert json.loads(req.data) == {"host": "1.2.3.4", "ports": [443]}
        return FakeResponse({"check": [{"port": 443, "status": False}]})
    monkeypatch.setattr(portcheck.urllib.request, "urlopen", urlopen)
    assert portcheck._probe_tcp("1.2.3.4", 443) is False

    def down(req, timeout=0):
        raise OSError("offline")
    monkeypatch.setattr(portcheck.urllib.request, "urlopen", down)
    assert portcheck._probe_tcp("1.2.3.4", 443) is None


def test_evidence_asks_each_vpn_module_and_ignores_failures(monkeypatch):
    from backend import ipsec, openvpn, wireguard

    def boom(port, proto):
        raise RuntimeError("no wg")
    monkeypatch.setattr(wireguard, "external_evidence", boom)
    monkeypatch.setattr(openvpn, "external_evidence", lambda p, pr: None)
    monkeypatch.setattr(ipsec, "external_evidence", lambda p, pr: f"client on {p}/{pr}")
    assert portcheck._evidence(500, "udp") == "client on 500/udp"
    monkeypatch.setattr(ipsec, "external_evidence", lambda p, pr: None)
    assert portcheck._evidence(500, "udp") is None


@pytest.fixture
def checked(tools, monkeypatch):
    """check() with network facts stubbed; returns a callable taking overrides."""
    monkeypatch.setattr(portcheck, "default_route", lambda: {"ip": "192.168.0.100", "gateway": "192.168.0.1", "iface": "eth0"})
    monkeypatch.setattr(portcheck, "public_ip", lambda fresh=False: "203.0.113.9")
    monkeypatch.setattr(portcheck, "_evidence", lambda port, proto: None)
    monkeypatch.setattr(portcheck, "_probe_tcp", lambda ip, port: None)
    monkeypatch.setattr(portcheck, "_TempListener", lambda port: (_ for _ in ()).throw(OSError("bind refused")))
    tools.answers["ss"] = SS_TCP
    tools.answers["/usr/sbin/ufw"] = "Status: active\n22/tcp ALLOW Anywhere\n"
    tools.answers["upnpc"] = UPNP_OUT
    return tools


def test_check_reports_an_open_port_with_a_mapping(checked, monkeypatch):
    monkeypatch.setattr(portcheck, "_probe_tcp", lambda ip, port: True)
    r = portcheck.check("8443", "tcp")
    assert r["verdict"] == "open" and r["external"] is True and r["method"].startswith("Outside TCP probe")
    assert r["listen"]["process"] == "python3" and r["firewall"]["allowed"] is False
    assert r["upnp_mapping"]["desc"] == "AuroraPanel" and r["nat"] is None
    assert r["router_url"] == "http://192.168.0.1/" and r["lan_ip"] == "192.168.0.100"
    assert r["temp_listener"] is False
    assert len(r["steps"]) == 1 and "firewall (ufw)" in r["steps"][0]


def test_check_closed_port_explains_the_forward(checked, monkeypatch):
    monkeypatch.setattr(portcheck, "_probe_tcp", lambda ip, port: False)
    r = portcheck.check(80, "tcp")
    assert r["verdict"] == "closed" and r["temp_listener"] is False and r["upnp_mapping"] is None
    assert r["steps"][0].startswith("Nothing on this Pi listens on TCP 80")
    assert any("forward TCP port 80 → 192.168.0.100 port 80" in s for s in r["steps"])
    assert any("DHCP reservation for 192.168.0.100" in s for s in r["steps"])


def test_check_uses_a_temporary_listener_when_nothing_listens(checked, monkeypatch):
    closed = []

    class TL:
        def __init__(self, port):
            self.port = port

        def close(self):
            closed.append(self.port)
    monkeypatch.setattr(portcheck, "_TempListener", TL)
    r = portcheck.check(80, "tcp")
    assert r["temp_listener"] is True and closed == [80]
    assert not any("Nothing on this Pi listens" in s for s in r["steps"])
    assert r["verdict"] == "unverified"


def test_check_udp_relies_on_vpn_evidence(checked, monkeypatch):
    checked.answers["ss"] = "UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\n"
    checked.answers["wg"] = "wg0\t51820\n"
    monkeypatch.setattr(portcheck, "_evidence", lambda port, proto: "peer handshake 2 min ago")
    r = portcheck.check(51820, "udp")
    assert r["verdict"] == "open" and r["method"] == "Live VPN client connected from the internet"
    assert r["listen"]["process"] == "wireguard (kernel)" and r["upnp_mapping"]["proto"] == "udp"
    assert ["wg", "show", "all", "listen-port"] in checked.calls


def test_check_explains_cgnat(checked, monkeypatch):
    checked.answers["upnpc"] = UPNP_OUT.replace("203.0.113.9", "100.72.1.9")
    r = portcheck.check(8443, "tcp")
    assert r["nat"] == "cgnat" and r["upstream_router"] is None
    assert any("carrier-grade NAT (router WAN 100.72.1.9)" in s for s in r["steps"])


def test_check_explains_double_nat_and_tests_the_inner_hop(checked, monkeypatch):
    checked.answers["upnpc"] = UPNP_OUT.replace("203.0.113.9", "10.1.1.7")
    monkeypatch.setattr(portcheck, "_probe_tcp", lambda ip, port: False)

    class Conn:
        def close(self):
            pass
    targets = []

    def create_connection(addr, timeout=0):
        targets.append(addr)
        return Conn()
    monkeypatch.setattr(portcheck.socket, "create_connection", create_connection)
    r = portcheck.check(8443, "tcp")
    assert r["nat"] == "double" and r["upstream_router"] == "10.1.1.1" and r["inner_hop"] is True
    assert targets == [("10.1.1.7", 8443)]
    assert any("Double NAT" in s for s in r["steps"])
    assert any(s.startswith("① On the upstream/ISP router (probably http://10.1.1.1/)") for s in r["steps"])
    assert any("② On your router (http://192.168.0.1/)" in s and "Verified working" in s for s in r["steps"])

    def refused(addr, timeout=0):
        raise OSError("refused")
    monkeypatch.setattr(portcheck.socket, "create_connection", refused)
    r = portcheck.check(8443, "tcp")
    assert r["inner_hop"] is False and any("Not working yet" in s for s in r["steps"])


def test_check_without_public_ip_skips_the_probe(checked, monkeypatch):
    monkeypatch.setattr(portcheck, "public_ip", lambda fresh=False: None)
    monkeypatch.setattr(portcheck, "_probe_tcp", lambda ip, port: (_ for _ in ()).throw(AssertionError("no probe")))
    r = portcheck.check(8443, "tcp")
    assert r["verdict"] == "unverified" and r["method"] is None and r["public_ip"] is None


def test_upnp_open_and_close_build_the_upnpc_commands(tools, monkeypatch):
    monkeypatch.setattr(portcheck, "default_route", lambda: {"ip": "192.168.0.100"})
    tools.answers["upnpc"] = "external 203.0.113.9:8443 TCP is redirected to internal 192.168.0.100:8443 (duration=0)"
    r = portcheck.upnp_open(8443, "tcp")
    assert r["ok"] and "redirected" in r["output"]
    assert tools.calls[-1] == ["upnpc", "-e", "AuroraPanel", "-a", "192.168.0.100", "8443", "8443", "TCP", "0"]
    tools.answers["upnpc"] = "AddPortMapping failed with code 718"
    with pytest.raises(portcheck.PortError, match="Router refused"):
        portcheck.upnp_open(8443, "tcp")
    assert portcheck.upnp_close(8443, "udp")["ok"]
    assert tools.calls[-1] == ["upnpc", "-d", "8443", "UDP"]
    monkeypatch.setattr(portcheck, "default_route", lambda: {})
    with pytest.raises(portcheck.PortError, match="No LAN address"):
        portcheck.upnp_open(8443, "tcp")
    monkeypatch.setattr(portcheck.shutil, "which", lambda name, path=None: None)
    with pytest.raises(portcheck.PortError, match="miniupnpc"):
        portcheck.upnp_close(8443, "tcp")


def test_install_upnp_launches_an_apt_job(monkeypatch):
    launched = {}

    def launch(title, argv, env=None, meta=None):
        launched.update(title=title, argv=list(argv), env=env)
        return "job"
    monkeypatch.setattr(portcheck.jobs, "launch", launch)
    assert portcheck.install_upnp() == "job"
    assert launched["title"] == "install miniupnpc" and launched["argv"][-2:] == ["install", "miniupnpc"]
    assert launched["env"]["DEBIAN_FRONTEND"] == "noninteractive"


def test_temp_listener_accepts_and_closes_connections():
    import socket
    tl = portcheck._TempListener(0)
    port = tl.sock.getsockname()[1]
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=3)
        c.close()
    finally:
        tl.close()
    assert tl.stop is True
    with pytest.raises(OSError):
        tl.sock.getsockname()
