"""vpncommon: the plumbing the VPN servers share (command runner, settings, forwarding, NAT, ufw,
namespace helpers), exercised with a recorded subprocess.run and temp paths only."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from backend import vpncommon
from test_cov_net_fakes import FakeRun, capture_launch, fake_which, redirect_paths


@pytest.fixture
def fake(monkeypatch):
    fr = FakeRun()
    monkeypatch.setattr(subprocess, "run", fr)
    return fr


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setattr(vpncommon, "STATE_DIR", tmp_path / "vpn")
    monkeypatch.setattr(vpncommon, "SETTINGS", tmp_path / "network.json")
    monkeypatch.setattr(vpncommon, "NAT_FILE", tmp_path / "vpn" / "nat.nft")
    monkeypatch.setattr(vpncommon, "NAT_UNIT", tmp_path / "aurora-vpn-nat.service")
    monkeypatch.setattr(vpncommon, "SYSCTL_FILE", tmp_path / "99-aurora-vpn.conf")
    return tmp_path


# ----------------------------------------------------------------------------- run
def test_run_turns_a_missing_tool_into_a_vpn_error(fake):
    fake.on("no-such-tool", exc=FileNotFoundError("no such file"))
    with pytest.raises(vpncommon.VPNError, match="no-such-tool: .*no such file"):
        vpncommon.run(["no-such-tool", "x"])


def test_run_reports_stderr_then_stdout_when_a_command_fails(fake):
    fake.on("wg", rc=1, err="  permission denied\n")
    with pytest.raises(vpncommon.VPNError, match="permission denied"):
        vpncommon.run(["wg", "show"])
    fake.on("wg", rc=2, out="only on stdout")
    with pytest.raises(vpncommon.VPNError, match="only on stdout"):
        vpncommon.run(["wg", "show"])
    fake.on("wg", rc=3)
    with pytest.raises(vpncommon.VPNError, match="wg failed"):
        vpncommon.run(["wg", "show"])
    assert vpncommon.run(["wg", "show"], check=False).returncode == 3


def test_run_passes_input_timeout_and_a_sbin_path(fake):
    vpncommon.run(["wg", "pubkey"], input="key\n", timeout=7, env={"EASYRSA_BATCH": "1"})
    kw = fake.kwargs[-1]
    assert kw["input"] == "key\n" and kw["timeout"] == 7
    assert kw["env"]["PATH"] == vpncommon.APT_ENV["PATH"] and kw["env"]["EASYRSA_BATCH"] == "1"


def test_require_linux_needs_linux_and_systemd(monkeypatch):
    monkeypatch.setattr(vpncommon, "IS_LINUX", False)
    with pytest.raises(vpncommon.VPNError, match="Linux with systemd"):
        vpncommon.require_linux()
    monkeypatch.setattr(vpncommon, "IS_LINUX", True)
    monkeypatch.setattr(shutil, "which", fake_which())
    with pytest.raises(vpncommon.VPNError):
        vpncommon.require_linux()
    monkeypatch.setattr(shutil, "which", fake_which("systemctl"))
    vpncommon.require_linux()


@pytest.mark.parametrize("name", ["laptop", "  phone.2  ", "a_b-c", "x" * 32])
def test_valid_name_accepts_simple_names(name):
    assert vpncommon.valid_name(name) == name.strip()


@pytest.mark.parametrize("bad", ["", "  ", "-lead", "has space", "x" * 33, "a/b", "é"])
def test_valid_name_rejects_odd_names(bad):
    with pytest.raises(vpncommon.VPNError, match="letters, digits"):
        vpncommon.valid_name(bad)


def test_which_needs_every_tool(monkeypatch):
    monkeypatch.setattr(shutil, "which", fake_which("wg", "wg-quick"))
    assert vpncommon.which("wg", "wg-quick") is True
    assert vpncommon.which("wg", "qrencode") is False


# ----------------------------------------------------------------------------- files
def test_write_secret_replaces_atomically_and_leaves_no_temp_file(tmp_path):
    p = tmp_path / "deep" / "secret.key"
    vpncommon.write_secret(p, "one")
    vpncommon.write_secret(p, "two")
    assert p.read_text(encoding="utf-8") == "two"
    assert sorted(x.name for x in p.parent.iterdir()) == ["secret.key"]


def test_load_json_merges_defaults_and_survives_bad_files(tmp_path):
    p = tmp_path / "s.json"
    assert vpncommon.load_json(p, {"port": 1}) == {"port": 1}
    p.write_text("not json", encoding="utf-8")
    d = vpncommon.load_json(p, {"port": 1})
    assert d == {"port": 1}
    d["port"] = 9   # a copy, never the default itself
    assert vpncommon.load_json(p, {"port": 1}) == {"port": 1}
    vpncommon.save_json(p, {"port": 5, "extra": True})
    assert vpncommon.load_json(p, {"port": 1, "dns": "x"}) == {"port": 5, "extra": True, "dns": "x"}


# ----------------------------------------------------------------------------- systemd
def test_unit_state_without_systemctl_is_inactive(monkeypatch, fake):
    monkeypatch.setattr(shutil, "which", fake_which())
    assert vpncommon.unit_state("wg-quick@wg0") == {"active": False, "enabled": False}
    assert fake.calls == []


def test_unit_state_reads_is_active_and_is_enabled(monkeypatch, fake):
    monkeypatch.setattr(shutil, "which", fake_which("systemctl"))
    fake.on("systemctl", "is-active", out="active\n").on("systemctl", "is-enabled", out="disabled\n")
    assert vpncommon.unit_state("u") == {"active": True, "state": "active", "enabled": False}
    fake.on("systemctl", "is-active", out="failed\n", rc=3).on("systemctl", "is-enabled", out="enabled\n")
    assert vpncommon.unit_state("u") == {"active": False, "state": "failed", "enabled": True}


def test_control_maps_actions_to_systemctl(monkeypatch, fake):
    monkeypatch.setattr(shutil, "which", fake_which("systemctl"))
    fake.on("systemctl", "is-active", out="active").on("systemctl", "is-enabled", out="enabled")
    with pytest.raises(vpncommon.VPNError, match="Invalid action"):
        vpncommon.control("u", "reload")
    r = vpncommon.control("u", "stop")
    assert fake.calls[0] == ["systemctl", "disable", "--now", "u"] and r["ok"] is True
    fake.calls.clear()
    vpncommon.control("u", "restart")
    assert fake.calls[:2] == [["systemctl", "enable", "u"], ["systemctl", "restart", "u"]]


def test_apt_install_and_remove_launch_noninteractive_apt_jobs(monkeypatch):
    monkeypatch.setattr(vpncommon, "require_linux", lambda: None)
    rec = capture_launch(monkeypatch, vpncommon.jobs)
    vpncommon.apt_install("install X", ["openvpn", "easy-rsa"], meta={"vpn": "openvpn"})
    vpncommon.apt_remove("remove X", ["openvpn"])
    assert rec.calls[0]["argv"] == [*vpncommon.APT, "install", "openvpn", "easy-rsa"]
    assert rec.calls[0]["env"] == vpncommon.APT_ENV and rec.calls[0]["meta"] == {"vpn": "openvpn"}
    assert rec.calls[1]["argv"] == [*vpncommon.APT, "remove", "openvpn"]


# ----------------------------------------------------------------------------- LAN facts
def test_default_route_without_ip_tool_or_route_is_empty(monkeypatch, fake):
    monkeypatch.setattr(shutil, "which", fake_which())
    assert vpncommon.default_route() == {"iface": None, "gateway": None, "ip": None, "lan": None}
    monkeypatch.setattr(shutil, "which", fake_which("ip"))
    fake.on("ip", "-4", "route", out="")
    assert vpncommon.default_route()["iface"] is None


def test_default_route_reads_gateway_interface_and_lan(monkeypatch, fake):
    monkeypatch.setattr(shutil, "which", fake_which("ip"))
    fake.on("ip", "-4", "route", out="default via 192.168.0.1 dev eth0 proto dhcp metric 100\n")
    fake.on("ip", "-4", "-o", "addr", out="2: eth0    inet 192.168.0.100/24 brd 192.168.0.255 scope global eth0\n")
    assert vpncommon.default_route() == {"iface": "eth0", "gateway": "192.168.0.1", "ip": "192.168.0.100", "lan": "192.168.0.0/24"}
    assert fake.calls[-1] == ["ip", "-4", "-o", "addr", "show", "dev", "eth0"]


def test_public_ip_fresh_drops_the_cache(monkeypatch):
    from backend import domains
    monkeypatch.setattr(domains, "public_ip", lambda: "203.0.113.9")
    monkeypatch.setattr(domains, "_public_ip_cache", {"ip": "old", "ts": 10 ** 12})
    assert vpncommon.public_ip() == "203.0.113.9" and domains._public_ip_cache["ip"] == "old"
    assert vpncommon.public_ip(fresh=True) == "203.0.113.9" and domains._public_ip_cache["ip"] is None


# ----------------------------------------------------------------------------- settings
@pytest.fixture
def no_ddns(monkeypatch):
    from backend import ddns
    monkeypatch.setattr(ddns, "hostname", lambda: None)
    monkeypatch.setattr(vpncommon, "public_ip", lambda fresh=False: None)


def test_settings_prefer_custom_endpoint_then_ddns_then_public_ip(state, monkeypatch, no_ddns):
    s = vpncommon.settings()
    assert s["endpoint"] == "" and s["effective_endpoint"] == "" and s["endpoint_source"] == "public_ip"
    with pytest.raises(vpncommon.VPNError, match="No public address known"):
        vpncommon.endpoint()
    monkeypatch.setattr(vpncommon, "public_ip", lambda fresh=False: "198.51.100.7")
    assert vpncommon.endpoint() == "198.51.100.7"
    from backend import ddns
    monkeypatch.setattr(ddns, "hostname", lambda: "home.duckdns.org")
    s = vpncommon.settings()
    assert s["effective_endpoint"] == "home.duckdns.org" and s["endpoint_source"] == "ddns"
    s = vpncommon.save_settings(endpoint="VPN.Example.COM")
    assert s["endpoint"] == "vpn.example.com" and s["endpoint_source"] == "custom"
    assert json.loads(vpncommon.SETTINGS.read_text(encoding="utf-8")) == {"endpoint": "vpn.example.com", "dns": "1.1.1.1, 1.0.0.1"}


def test_save_settings_validates_endpoint_and_dns(state, no_ddns):
    with pytest.raises(vpncommon.VPNError, match="hostname or IPv4"):
        vpncommon.save_settings(endpoint="bad host!")
    with pytest.raises(vpncommon.VPNError, match="Not an IPv4 address: 2001::1"):
        vpncommon.save_settings(dns="8.8.8.8, 2001::1")
    with pytest.raises(vpncommon.VPNError, match="At least one DNS"):
        vpncommon.save_settings(dns=" , ")
    s = vpncommon.save_settings(dns="9.9.9.9  149.112.112.112")
    assert s["dns"] == "9.9.9.9, 149.112.112.112"
    assert vpncommon.dns_servers() == ["9.9.9.9", "149.112.112.112"]
    assert vpncommon.dns_servers("1.1.1.1") == ["1.1.1.1"]


# ----------------------------------------------------------------------------- forwarding + NAT
def test_enable_forwarding_writes_sysctl_and_the_live_switch(state, monkeypatch):
    redirect_paths(monkeypatch, vpncommon, state)
    (state / "proc/sys/net/ipv4").mkdir(parents=True)
    assert vpncommon.forwarding_enabled() is False
    vpncommon.enable_forwarding()
    assert "net.ipv4.ip_forward = 1" in vpncommon.SYSCTL_FILE.read_text(encoding="utf-8")
    assert (state / "proc/sys/net/ipv4/ip_forward").read_text() == "1\n"
    assert vpncommon.forwarding_enabled() is True


def test_set_nat_renders_the_table_writes_the_unit_once_and_enables_it(state, monkeypatch, fake):
    monkeypatch.setattr(shutil, "which", fake_which("nft", "systemctl"))
    vpncommon.set_nat("10.8.0.5/24", True)
    nft = vpncommon.NAT_FILE.read_text(encoding="utf-8")
    assert "ip saddr 10.8.0.0/24 ip daddr != 10.8.0.0/24 masquerade" in nft
    assert "table ip aurora_vpn {" in nft and "type nat hook postrouting" in nft
    unit = vpncommon.NAT_UNIT.read_text(encoding="utf-8")
    assert f"ExecStart=/usr/bin/nft -f {vpncommon.NAT_FILE}" in unit and "ExecStop=/usr/bin/nft delete table ip aurora_vpn" in unit
    assert [c[1:] for c in fake.find("systemctl")] == [["daemon-reload"], ["enable", "aurora-vpn-nat.service"], ["restart", "aurora-vpn-nat.service"]]
    assert json.loads((vpncommon.STATE_DIR / "nat.json").read_text()) == ["10.8.0.0/24"]
    fake.calls.clear()
    vpncommon.set_nat("10.9.0.0/24", True)
    assert vpncommon._nat_subnets() == ["10.8.0.0/24", "10.9.0.0/24"]
    assert not fake.called("daemon-reload")   # unit already there
    assert "10.9.0.0/24 masquerade" in vpncommon.NAT_FILE.read_text(encoding="utf-8")
    fake.on("systemctl", "is-active", out="active").on("systemctl", "is-enabled", out="enabled")
    assert vpncommon.nat_active("10.9.0.1/24") is True and vpncommon.nat_active("10.7.0.0/24") is False


def test_set_nat_off_for_the_last_subnet_disables_the_unit(state, monkeypatch, fake):
    monkeypatch.setattr(shutil, "which", fake_which("nft", "systemctl"))
    vpncommon.set_nat("10.8.0.0/24", True)
    fake.calls.clear()
    fake.on("systemctl", "disable", rc=1, err="not loaded")   # tolerated: check=False
    vpncommon.set_nat("10.8.0.0/24", False)
    assert vpncommon._nat_subnets() == []
    assert fake.calls == [["systemctl", "disable", "--now", "aurora-vpn-nat.service"]]
    assert "masquerade" not in vpncommon.NAT_FILE.read_text(encoding="utf-8")


def test_set_nat_falls_back_to_the_usual_nft_path(state, monkeypatch, fake):
    monkeypatch.setattr(shutil, "which", fake_which("systemctl"))
    vpncommon.set_nat("10.8.0.0/24", True)
    assert "ExecStart=/usr/sbin/nft -f" in vpncommon.NAT_UNIT.read_text(encoding="utf-8")


# ----------------------------------------------------------------------------- ufw
def test_ufw_rules_only_when_ufw_is_installed(monkeypatch, fake):
    monkeypatch.setattr(shutil, "which", fake_which())
    vpncommon.ufw_open(51820, "udp", "10.8.0.0/24")
    vpncommon.ufw_close(51820, "udp", "10.8.0.0/24")
    assert fake.calls == []
    monkeypatch.setattr(shutil, "which", fake_which("ufw"))
    vpncommon.ufw_open(51820, "udp", "10.8.0.0/24")
    assert fake.calls == [
        ["/usr/bin/ufw", "allow", "51820/udp", "comment", "AuroraPanel VPN"],
        ["/usr/bin/ufw", "route", "allow", "from", "10.8.0.0/24"],
        ["/usr/bin/ufw", "route", "allow", "to", "10.8.0.0/24"],
        ["/usr/bin/ufw", "allow", "from", "10.8.0.0/24", "comment", "AuroraPanel VPN clients"],
    ]
    fake.calls.clear()
    vpncommon.ufw_close(4500, "udp")
    assert fake.calls == [["/usr/bin/ufw", "delete", "allow", "4500/udp"]]
    fake.calls.clear()
    vpncommon.ufw_close(500, "udp", "10.10.0.0/24")
    assert fake.calls[1:] == [["/usr/bin/ufw", "route", "delete", "allow", "from", "10.10.0.0/24"],
                              ["/usr/bin/ufw", "route", "delete", "allow", "to", "10.10.0.0/24"],
                              ["/usr/bin/ufw", "delete", "allow", "from", "10.10.0.0/24"]]


# ----------------------------------------------------------------------------- namespace helpers
def test_ns_helpers_wrap_ip_netns(fake):
    vpncommon.ns_cleanup()
    assert fake.calls[-1] == ["ip", "netns", "del", vpncommon.TEST_NS]
    fake.on("ping", rc=1, out="3 packets transmitted, 0 received, 100% packet loss")
    r = vpncommon.ns_exec(["ping", "-c", "1", "10.8.0.1"])
    assert fake.calls[-1][:4] == ["ip", "netns", "exec", vpncommon.TEST_NS] and r.returncode == 1


def test_ns_ping_logs_loss_and_outcome(monkeypatch, fake):
    monkeypatch.setattr(shutil, "which", fake_which("ping"))
    lines = []
    fake.on("ping", out="3 packets transmitted, 3 received, 0% packet loss")
    assert vpncommon.ns_ping(lines.append, "10.8.0.1", "Tunnel") is True
    assert lines[-1] == "✔ Tunnel (ping 10.8.0.1, 0% loss)"
    fake.on("ping", rc=1, out="")
    assert vpncommon.ns_ping(lines.append, "1.1.1.1", "Internet") is False
    assert lines[-1] == "✖ Internet (ping 1.1.1.1)"


def test_ns_ping_tries_to_install_ping_and_gives_up_cleanly(monkeypatch, fake):
    monkeypatch.setattr(shutil, "which", fake_which())
    lines = []
    assert vpncommon.ns_ping(lines.append, "10.8.0.1", "Tunnel") is False
    assert fake.calls[0][:1] == ["apt-get"] and "iputils-ping" in fake.calls[0]
    assert "ping tool isn't installed" in lines[-1]


def test_subnet_host_and_next_free_ip():
    assert vpncommon.subnet_host("10.8.0.0/24", 1) == "10.8.0.1"
    assert vpncommon.next_free_ip("10.8.0.0/24", set()) == "10.8.0.2"
    assert vpncommon.next_free_ip("10.8.0.0/24", {"10.8.0.2", "10.8.0.3"}) == "10.8.0.4"
    with pytest.raises(vpncommon.VPNError, match="subnet is full"):
        vpncommon.next_free_ip("10.8.0.0/30", {"10.8.0.2"})
