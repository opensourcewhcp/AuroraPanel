"""Security Report, network side: parsers, decisions and fixes, with every command and file faked."""
import json
import socket
import ssl
import subprocess
import threading

import pytest

from backend import secnet

SS = """tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=1,fd=4))
tcp   LISTEN 0 80  127.0.0.1:3306 0.0.0.0:* users:(("mariadbd",pid=2,fd=5))
tcp   LISTEN 0 50  0.0.0.0:445 0.0.0.0:* users:(("smbd",pid=3,fd=6))
tcp   LISTEN 0 10  192.168.0.100:53 0.0.0.0:* users:(("named",pid=4,fd=7))
tcp   LISTEN 0 10  172.17.0.1:53 0.0.0.0:* users:(("named",pid=4,fd=8))
tcp   LISTEN 0 10  [fe80::1%eth0]:53 [::]:*
tcp   LISTEN 0 10  *:80 *:* users:(("apache2",pid=5,fd=3))
tcp   LISTEN 0 10  0.0.0.0:* 0.0.0.0:*
udp   UNCONN 0 0   0.0.0.0:5353 0.0.0.0:* users:(("avahi-daemon",pid=6,fd=12))
udp   UNCONN 0 0   0.0.0.0:6379 0.0.0.0:*
udp   UNCONN 0 0   0.0.0.0:11211 0.0.0.0:*
udp   UNCONN 0 0   0.0.0.0:44845 0.0.0.0:* users:(("avahi-daemon",pid=6,fd=13))
tcp   LISTEN 0 10  0.0.0.0:8088 0.0.0.0:* users:(("python3",pid=9,fd=3))
raw   UNCONN 0 0   0.0.0.0:1 0.0.0.0:*
short line
tcp   LISTEN 0 10  weird 0.0.0.0:*
"""
IFACES = {"192.168.0.100": "eth0", "172.17.0.1": "docker0", "127.0.0.1": "lo"}


def cp(out="", rc=0, err=""):
    return subprocess.CompletedProcess([], rc, out, err)


def test_run_and_which(monkeypatch):
    assert secnet._run(["definitely-not-a-command-xyz"]).returncode == 1
    monkeypatch.setattr(secnet.shutil, "which", lambda n, path=None: "/usr/bin/" + n if n == "b" else None)
    assert secnet.which("a", "b") == "/usr/bin/b" and secnet.which("a") == ""
    t = {x["id"]: x for x in secnet.tools()}
    assert set(t) == {"nmap", "testssl", "sshaudit"} and not any(x["installed"] for x in t.values())


def test_parse_ss_and_exposure():
    rows = secnet.parse_ss(SS)
    assert {"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd"} in rows
    assert {"proto": "tcp", "addr": "fe80::1", "port": 53, "process": ""} in rows
    assert {"proto": "tcp", "addr": "*", "port": 80, "process": "apache2"} in rows
    assert not any(r["proto"] == "raw" for r in rows)
    ex = secnet.exposure
    assert ex("*", {}) == ex("::", {}) == "public"
    assert ex("127.0.0.1", {}) == ex("::1", {}) == "local"
    assert ex("fe80::1", {}) == "internal"
    assert ex("172.17.0.1", IFACES) == "internal" and ex("192.168.0.100", IFACES) == "public"
    assert ex("not-an-ip", {}) == "public"


def test_iface_of(monkeypatch):
    assert isinstance(secnet._iface_of(), dict)
    import psutil
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: (_ for _ in ()).throw(OSError("x")))
    assert secnet._iface_of() == {}


UFW = ["22/tcp ALLOW IN Anywhere", "22/tcp (v6) ALLOW IN Anywhere (v6)", "40000:40100/tcp ALLOW IN Anywhere", "80,443/tcp ALLOW IN Anywhere",
       "OpenSSH ALLOW IN Anywhere", "Samba ALLOW IN 192.168.0.0/16", "Apache Full on eth0 ALLOW IN Anywhere", "445/tcp DENY IN Anywhere",
       "5353 ALLOW IN 10.0.0.0/8", "53 ALLOW OUT Anywhere", "Anywhere DENY IN 1.2.3.4", "garbage line", "Unknown App ALLOW IN Anywhere  # note"]


def test_parse_ufw_and_state():
    p = secnet.parse_ufw(UFW)
    assert {"range": (40000, 40100), "proto": "tcp", "action": "ALLOW", "anywhere": True, "v6": False} in p
    assert {"range": (22, 22), "proto": "tcp", "action": "ALLOW", "anywhere": True, "v6": True} in p
    assert any(r["range"] == (443, 443) for r in p) and any(r["range"] == (1, 65535) and r["action"] == "DENY" for r in p)
    assert not any(r["range"] == (53, 53) and r["action"] == "ALLOW" and r["proto"] == "any" for r in p)  # OUT rule skipped
    fw = {"active": True}
    st = lambda port, proto: secnet.firewall_state(port, proto, fw, p)  # noqa: E731
    assert st(22, "tcp") == "open" and st(40050, "tcp") == "open" and st(139, "tcp") == "lan" and st(5353, "udp") == "lan"
    assert st(445, "tcp") == "lan"  # Samba's LAN-only allow comes before the deny: the internet hits the deny
    assert st(9999, "tcp") == "blocked"
    assert secnet.firewall_state(445, "tcp", fw, secnet.parse_ufw(["445/tcp DENY IN Anywhere", "445/tcp ALLOW IN Anywhere"])) == "blocked"
    assert secnet.firewall_state(445, "tcp", fw, secnet.parse_ufw(["445/tcp DENY IN 1.2.3.4", "445/tcp ALLOW IN Anywhere"])) == "open"
    assert secnet.firewall_state(22, "tcp", {"active": False}, p) == "none" and secnet.firewall_state(22, "tcp", {}, p) == "none"
    # an earlier allow wins over a later deny, as in ufw
    q = secnet.parse_ufw(["445/tcp ALLOW IN Anywhere", "445/tcp DENY IN Anywhere"])
    assert secnet.firewall_state(445, "tcp", fw, q) == "open"


def test_fw(monkeypatch):
    from backend import firewall
    monkeypatch.setattr(firewall, "status", lambda: {"active": True, "rules": []})
    assert secnet._fw()["active"]
    monkeypatch.setattr(firewall, "status", lambda: (_ for _ in ()).throw(OSError("no ufw")))
    assert secnet._fw() == {}
    monkeypatch.setattr(secnet, "_fw", lambda: {"active": True})
    assert secnet._ufw_active()


def test_open_ports_and_findings(monkeypatch):
    fw = {"active": True, "rules": [{"rule": r} for r in ["22/tcp ALLOW IN Anywhere", "445/tcp ALLOW IN Anywhere", "5353/udp ALLOW IN 192.168.0.0/16"]]}
    ports = secnet.open_ports(SS, fw, IFACES)
    by = {(p["port"], p["proto"]): p for p in ports}
    assert set(by) == {(22, "tcp"), (445, "tcp"), (53, "tcp"), (80, "tcp"), (8088, "tcp"), (5353, "udp"), (11211, "udp")}
    assert by[(8088, "tcp")]["service"] == "AuroraPanel" and by[(11211, "udp")]["service"] == "Memcached"
    assert by[(22, "tcp")]["addrs"] == ["all addresses"] and by[(53, "tcp")]["addrs"] == ["192.168.0.100"]
    assert by[(445, "tcp")]["firewall"] == "open" and by[(5353, "udp")]["firewall"] == "lan" and by[(80, "tcp")]["firewall"] == "blocked"
    extra = [{"port": 3306, "proto": "tcp", "service": "", "process": "", "firewall": "none"}, {"port": 111, "proto": "tcp", "service": "rpcbind", "process": "", "firewall": "blocked"}]
    f = {x["id"]: x for x in secnet.port_findings(ports + extra)}
    assert "port-111-tcp" not in f
    assert f["port-445-tcp"]["action"] == "port_lan:445/tcp" and f["port-445-tcp"]["severity"] == "medium"
    assert f["port-5353-udp"]["severity"] == "info" and f["port-5353-udp"]["action"] == ""
    assert f["port-3306-tcp"]["severity"] == "high" and "Turn on the firewall" in f["port-3306-tcp"]["fix"]
    assert "port-11211-udp" not in f and "port-22-tcp" not in f  # memcached is listening but blocked by the firewall
    # defaults: reads ss, the firewall and the interfaces itself
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp(SS))
    monkeypatch.setattr(secnet, "_fw", lambda: {})
    monkeypatch.setattr(secnet, "_iface_of", lambda: IFACES)
    assert all(p["firewall"] == "none" and p["reachable"] for p in secnet.open_ports())


NMAP = """<?xml version="1.0"?><nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="10.0p2" extrainfo="Debian 7"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="81"><state state="closed"/><service name="x"/></port>
<port protocol="tcp" portid="82"><state state="open"/></port>
</ports></host></nmaprun>"""


def test_nmap(monkeypatch):
    assert secnet.parse_nmap(NMAP) == {(22, "tcp"): "OpenSSH 10.0p2 Debian 7", (80, "tcp"): "http"}
    assert secnet.parse_nmap("<broken") == {}
    monkeypatch.setattr(secnet, "which", lambda *n: "")
    assert secnet.nmap_versions([{"port": 22, "proto": "tcp", "addrs": []}]) == {}
    monkeypatch.setattr(secnet, "which", lambda *n: "/usr/bin/nmap")
    assert secnet.nmap_versions([{"port": 53, "proto": "udp", "addrs": []}]) == {}
    calls = []

    def run(argv, timeout=60, input=None):
        calls.append(argv[-1])
        if argv[-1] == "127.0.0.1":
            return cp(NMAP)
        return cp(NMAP.replace('portid="22"', 'portid="53"'))
    monkeypatch.setattr(secnet, "_run", run)
    got = secnet.nmap_versions([{"port": 22, "proto": "tcp", "addrs": ["all addresses"]}, {"port": 53, "proto": "tcp", "addrs": ["192.168.0.100"]}])
    assert got[(53, "tcp")].startswith("OpenSSH") and calls == ["127.0.0.1", "192.168.0.100"]


def test_ftp_findings(monkeypatch):
    from backend import ftp
    on21 = [{"port": 21, "proto": "tcp"}]
    assert secnet.ftp_findings([]) == []
    monkeypatch.setattr(ftp, "installed", lambda: False)
    assert secnet.ftp_findings(on21) == []
    monkeypatch.setattr(ftp, "installed", lambda: True)
    monkeypatch.setattr(ftp, "_read_conf", lambda: {"ssl_enable": "NO"})
    assert secnet.ftp_findings(on21)[0]["action"] == "ftp_tls"
    monkeypatch.setattr(ftp, "_read_conf", lambda: {"ssl_enable": "YES", "force_local_logins_ssl": "YES"})
    assert secnet.ftp_findings(on21) == []
    monkeypatch.setattr(ftp, "_read_conf", lambda: (_ for _ in ()).throw(OSError("x")))
    assert secnet.ftp_findings(on21) == []
    saved = {}
    monkeypatch.setattr(ftp, "save_settings", lambda c: saved.update(c))
    assert secnet.ftp_tls_fix()["changed"] and saved["force_local_logins_ssl"] == "YES"


SSHD_T = """port 2222
ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes256-cbc
macs umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1
kexalgorithms curve25519-sha256,diffie-hellman-group14-sha1
"""
AUDIT = {"banner": {"raw": "SSH-2.0-OpenSSH_10.0"}, "kex": [{"algorithm": "ecdh-sha2-nistp256", "notes": {"fail": ["NSA curve"]}}, {"algorithm": "kex-strict-s-v00@openssh.com", "notes": {"warn": ["x"]}},
                 {"algorithm": "curve25519-sha256", "notes": {}}],
         "key": [{"algorithm": "ssh-rsa", "notes": {"warn": ["sha1"]}}], "mac": [{"algorithm": "umac-128@openssh.com", "notes": {"warn": ["tag"]}}],
         "enc": [], "cves": [{"name": "CVE-2023-48795", "cvssv2": 5.9, "description": "Terrapin"}, {"name": "CVE-2099-1", "cvssv2": 8.1, "description": "x"}]}


def test_ssh_parsers():
    a = secnet.parse_sshd_t(SSHD_T)
    w = secnet.weak_ssh(a)
    assert w == {"macs": ["umac-64-etm@openssh.com", "hmac-sha1"], "kexalgorithms": ["diffie-hellman-group14-sha1"], "ciphers": ["aes256-cbc"]}
    r = secnet.parse_ssh_audit(json.dumps(AUDIT))
    assert r["weak"]["kexalgorithms"] == ["ecdh-sha2-nistp256"] and r["weak"]["hostkeys"] == ["ssh-rsa"] and len(r["cves"]) == 2
    assert secnet.parse_ssh_audit("not json") == {}
    assert secnet.parse_ssh_audit(json.dumps({"banner": {"raw": ""}, "kex": []})) == {}  # refused: no verdict
    assert secnet.parse_ssh_audit("[]") == {}


def test_ssh_findings(monkeypatch):
    monkeypatch.setattr(secnet, "which", lambda *n: "")
    assert secnet.ssh_findings() == []
    monkeypatch.setattr(secnet, "which", lambda *n: "/usr/sbin/sshd" if n[0] == "sshd" else "")
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp("", 1))
    assert secnet.ssh_findings() == []
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp(SSHD_T))
    ids = {f["id"] for f in secnet.ssh_findings()}
    assert ids == {"ssh-weak-mac", "ssh-weak-kex", "ssh-weak-cipher"}
    seen = []

    def run(argv, timeout=60, input=None):
        seen.append(argv)
        return cp(json.dumps(AUDIT)) if "ssh-audit" in argv[0] else cp(SSHD_T)
    monkeypatch.setattr(secnet, "which", lambda *n: f"/usr/bin/{n[0]}")
    monkeypatch.setattr(secnet, "_run", run)
    f = {x["id"]: x for x in secnet.ssh_findings()}
    assert f["ssh-cves"]["severity"] == "high" and "ssh-hostkey" in f and "ecdh-sha2-nistp256" in f["ssh-weak-kex"]["detail"]
    assert ["-p", "2222"] == seen[1][2:4]
    clean = "ciphers chacha20-poly1305@openssh.com\nmacs hmac-sha2-256-etm@openssh.com\nkexalgorithms curve25519-sha256\n"
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp("garbage") if "ssh-audit" in argv[0] else cp(clean))
    assert secnet.ssh_findings() == []  # ssh-audit answered nonsense: sshd -T alone, nothing weak
    one = dict(AUDIT, cves=[AUDIT["cves"][0]], key=[])
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp(json.dumps(one)) if "ssh-audit" in argv[0] else cp(SSHD_T))
    f = {x["id"]: x for x in secnet.ssh_findings()}
    assert f["ssh-cves"]["severity"] == "medium" and f["ssh-cves"]["title"].endswith("weakness") and "ssh-hostkey" not in f


def test_ssh_crypto_fix(monkeypatch, tmp_path):
    main = tmp_path / "sshd_config"
    drop = tmp_path / "sshd_config.d" / "00-aurora-crypto.conf"
    monkeypatch.setattr(secnet, "SSHD_CONFIG", main)
    monkeypatch.setattr(secnet, "SSH_DROPIN", drop)
    monkeypatch.setattr(secnet, "which", lambda *n: "")
    with pytest.raises(secnet.SecNetError, match="not found"):
        secnet.ssh_crypto_fix()
    monkeypatch.setattr(secnet, "which", lambda *n: "/usr/sbin/sshd")
    main.write_text("Port 22\n")
    with pytest.raises(secnet.SecNetError, match="Include"):
        secnet.ssh_crypto_fix()
    main.write_text("Include /etc/ssh/sshd_config.d/*.conf\n")
    state = {"after": SSHD_T, "t": 0}
    reloads = []

    def run(argv, timeout=60, input=None):
        if argv[0] == "systemctl":
            reloads.append(argv[-1])
            return cp("", 1 if argv[-1] == "ssh" else 0)
        if argv[-1] == "-t":
            return cp("", state["t"], "bad line")
        out = state["after"] if drop.exists() else SSHD_T
        return cp(out)
    monkeypatch.setattr(secnet, "_run", run)
    # sshd -t fails → nothing kept
    state["t"] = 1
    with pytest.raises(secnet.SecNetError, match="bad line"):
        secnet.ssh_crypto_fix()
    assert not drop.exists()
    # the change doesn't take (an earlier file wins) → old file restored
    state["t"] = 0
    drop.parent.mkdir(exist_ok=True)
    drop.write_text("# old\n")
    with pytest.raises(secnet.SecNetError, match="earlier file"):
        secnet.ssh_crypto_fix()
    assert drop.read_text() == "# old\n"
    drop.unlink()
    state["after"] = "ciphers chacha20-poly1305@openssh.com,aes128-ctr\nmacs hmac-sha2-256-etm@openssh.com\nkexalgorithms curve25519-sha256\n"
    r = secnet.ssh_crypto_fix()
    assert r["changed"] and "MACs hmac-sha2-256-etm@openssh.com" in drop.read_text() and reloads == ["ssh", "sshd"]
    drop.unlink()
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp("", 1) if argv[0] == "systemctl" else run(argv))
    assert "next restart" in secnet.ssh_crypto_fix()["message"]
    monkeypatch.setattr(secnet, "_run", run)
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp(state["after"]))
    assert secnet.ssh_crypto_fix()["changed"] is False
    # only weak MACs offered: nothing strong to keep, so MACs are left alone
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp("macs hmac-sha1\nciphers aes128-ctr\n"))
    assert secnet.ssh_crypto_fix()["changed"] is False
    # sshd -T itself fails
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp("", 1))
    with pytest.raises(secnet.SecNetError, match="sshd -T failed"):
        secnet.ssh_crypto_fix()


def test_ssh_crypto_fix_follows_ssh_audit(monkeypatch, tmp_path):
    """What ssh-audit flags (NIST curves here) is removed too, so the report's issue really goes away."""
    main = tmp_path / "sshd_config"
    drop = tmp_path / "sshd_config.d" / "00-aurora-crypto.conf"
    main.write_text("Include /etc/ssh/sshd_config.d/*.conf\n")
    monkeypatch.setattr(secnet, "SSHD_CONFIG", main)
    monkeypatch.setattr(secnet, "SSH_DROPIN", drop)
    monkeypatch.setattr(secnet, "which", lambda *n: f"/usr/bin/{n[0]}")
    before = "port 22\nciphers aes128-ctr\nmacs hmac-sha2-256-etm@openssh.com\nkexalgorithms curve25519-sha256,ecdh-sha2-nistp256\n"
    after = "port 22\nciphers aes128-ctr\nmacs hmac-sha2-256-etm@openssh.com\nkexalgorithms curve25519-sha256\n"
    audit = {"kex": [{"algorithm": "ecdh-sha2-nistp256", "notes": {"warn": ["NIST curve"]}}]}

    def run(argv, timeout=60, input=None):
        if "ssh-audit" in argv[0]:
            return cp(json.dumps(audit))
        if argv[0] == "systemctl" or argv[-1] == "-t":
            return cp("")
        return cp(after if drop.exists() else before)
    monkeypatch.setattr(secnet, "_run", run)
    assert {f["id"] for f in secnet.ssh_findings()} == {"ssh-weak-kex"}
    assert secnet.ssh_crypto_fix()["changed"]
    assert "KexAlgorithms curve25519-sha256\n" in drop.read_text()


def test_timestamps(monkeypatch, tmp_path):
    ts, rules, sysctl = tmp_path / "ts", tmp_path / "before.rules", tmp_path / "90.conf"
    monkeypatch.setattr(secnet, "TCP_TS", ts)
    monkeypatch.setattr(secnet, "UFW_BEFORE", rules)
    monkeypatch.setattr(secnet, "SYSCTL_FILE", sysctl)
    monkeypatch.setattr(secnet, "_ufw_active", lambda: False)
    f = {x["id"]: x for x in secnet.timestamp_findings()}  # no files: ts treated as off, no ufw rule
    assert set(f) == {"icmp-timestamp"} and f["icmp-timestamp"]["action"] == ""
    ts.write_text("1\n")
    rules.write_text("*filter\n# ok icmp codes for INPUT\n-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT\nCOMMIT\n")
    monkeypatch.setattr(secnet, "_ufw_active", lambda: True)
    f = {x["id"]: x for x in secnet.timestamp_findings()}
    assert f["tcp-timestamps"]["action"] == "timestamps_off" and f["icmp-timestamp"]["action"] == "timestamps_off"
    reloads = []
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: reloads.append(argv) or cp())
    r = secnet.timestamps_fix()
    assert "ICMP" in r["message"] and ts.read_text() == "0\n" and "tcp_timestamps = 0" in sysctl.read_text()
    assert secnet.ICMP_RULE in rules.read_text() and (tmp_path / "before.rules.aurora-bak").exists() and reloads
    assert secnet.timestamp_findings() == []
    assert secnet.timestamps_fix()["message"] == "TCP timestamps off"  # rule already there
    monkeypatch.setattr(secnet, "_ufw_active", lambda: False)
    assert secnet.timestamps_fix()["message"] == "TCP timestamps off"  # no firewall: ICMP left alone
    monkeypatch.setattr(secnet, "_ufw_active", lambda: True)
    # ufw refuses → before.rules put back
    rules.write_text("# ok icmp codes for INPUT\n")
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp("", 1, "ERROR: bad rule"))
    with pytest.raises(secnet.SecNetError, match="bad rule"):
        secnet.timestamps_fix()
    assert rules.read_text() == "# ok icmp codes for INPUT\n"
    rules.write_text("*filter\n")
    with pytest.raises(secnet.SecNetError, match="unexpected layout"):
        secnet.timestamps_fix()
    monkeypatch.setattr(secnet, "TCP_TS", tmp_path / "missing" / "ts")
    with pytest.raises(secnet.SecNetError, match="TCP timestamps"):
        secnet.timestamps_fix()


def test_dns_findings(monkeypatch, tmp_path):
    opts = tmp_path / "named.conf.options"
    monkeypatch.setattr(secnet, "BIND_OPTIONS", opts)
    p53 = [{"port": 53, "reachable": True}]
    assert secnet.dns_findings([{"port": 53, "reachable": False}]) == []
    assert secnet.dns_findings(p53) == []  # no file
    opts.write_text("options { allow-recursion { localhost; localnets; }; };")
    assert secnet.dns_findings(p53) == []
    opts.write_text("options { recursion yes; };")
    assert secnet.dns_findings(p53) == []
    opts.write_text("options {\n // allow-recursion { localhost; };\n allow-recursion { any; };\n};")
    assert secnet.dns_findings(p53)[0]["id"] == "open-resolver"
    opts.write_text("options { recursion no; allow-recursion { any; }; };")
    assert secnet.dns_findings(p53) == []


class FakeSock:
    def __init__(self, lines):
        import io
        self.io = io.BytesIO(b"".join(lines))
        self.sent = []

    def makefile(self, mode):
        return self.io

    def sendall(self, b):
        self.sent.append(b)


def test_starttls_dialogues():
    s = FakeSock([b"220 hi\r\n", b"250-a\r\n", b"250 b\r\n", b"220 go\r\n"])
    assert secnet._starttls(s, "smtp") and s.sent[-1] == b"STARTTLS\r\n"
    assert not secnet._starttls(FakeSock([b"220 hi\r\n", b"250 b\r\n", b"454 no\r\n"]), "smtp")
    assert secnet._starttls(FakeSock([b"* OK\r\n", b"a OK go\r\n"]), "imap")
    assert secnet._starttls(FakeSock([b"+OK\r\n", b"+OK go\r\n"]), "pop3")
    assert secnet._starttls(FakeSock([]), "")


def _anon_server():
    """A local TLS server that offers only anonymous suites (no certificate)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers("aNULL:@SECLEVEL=0")
    except ssl.SSLError:
        pytest.skip("this OpenSSL has no anonymous suites")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        try:
            with ctx.wrap_socket(c, server_side=True) as t:
                t.recv(1)
        except (OSError, ssl.SSLError):
            pass
        srv.close()
    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


def test_anon_accepted_live():
    port = _anon_server()
    assert secnet.anon_accepted(port, "") is True
    s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = s.getsockname()[1]; s.close()
    assert secnet.anon_accepted(closed, "") is False


def test_anon_starttls_refused(monkeypatch):
    class C:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(secnet.socket, "create_connection", lambda *a, **k: C())
    monkeypatch.setattr(secnet, "_starttls", lambda s, k: False)
    assert secnet.anon_accepted(25, "smtp") is False


def test_mail_anon(monkeypatch):
    f = secnet.mail_anon_findings(lambda port, kind: port in (25, 587, 993))
    by = {x["id"]: x for x in f}
    assert "25, 587" in by["anon-ciphers-postfix"]["title"] and by["anon-ciphers-postfix"]["action"] == "mail_anon_off"
    assert "993" in by["anon-ciphers-dovecot"]["title"] and by["anon-ciphers-dovecot"]["action"] == ""
    assert secnet.mail_anon_findings(lambda p, k: False) == []
    monkeypatch.setattr(secnet, "which", lambda *n: "")
    with pytest.raises(secnet.SecNetError, match="Postfix"):
        secnet.mail_anon_fix()
    monkeypatch.setattr(secnet, "which", lambda *n: "/usr/sbin/postconf")
    calls = []

    def run(argv, timeout=60, input=None):
        calls.append(argv)
        return cp("old")
    monkeypatch.setattr(secnet, "_run", run)
    assert secnet.mail_anon_fix()["changed"] and any("smtpd_tls_exclude_ciphers=" + secnet.ANON_EXCLUDE in a for c in calls for a in c)
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp("", 1, "postconf: fatal") if "-e" in argv else cp("x"))
    with pytest.raises(secnet.SecNetError, match="fatal"):
        secnet.mail_anon_fix()
    back = []

    def run2(argv, timeout=60, input=None):
        back.append(argv)
        return cp("", 1, "reload failed") if argv[:2] == ["postfix", "reload"] else cp("v")
    monkeypatch.setattr(secnet, "_run", run2)
    with pytest.raises(secnet.SecNetError, match="put back"):
        secnet.mail_anon_fix()
    assert any("smtpd_tls_exclude_ciphers=v" in a for c in back for a in c)


def test_port_lan_fix(monkeypatch):
    from backend import firewall
    with pytest.raises(secnet.SecNetError, match="Bad port"):
        secnet.port_lan_fix("99999/tcp")
    monkeypatch.setattr(firewall, "guard_ports", lambda: ["22/tcp", "8088/tcp"])
    with pytest.raises(secnet.SecNetError, match="lock yourself out"):
        secnet.port_lan_fix("22/tcp")
    monkeypatch.setattr(secnet, "which", lambda *n: "")
    with pytest.raises(secnet.SecNetError, match="ufw"):
        secnet.port_lan_fix("445/tcp")
    monkeypatch.setattr(secnet, "which", lambda *n: "/usr/sbin/ufw")
    calls = []
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: calls.append(argv) or cp())
    assert "445/tcp" in secnet.port_lan_fix("445/tcp")["message"]
    assert ["/usr/sbin/ufw", "allow", "from", "192.168.0.0/16", "to", "any", "port", "445", "proto", "tcp"] in calls
    assert ["/usr/sbin/ufw", "delete", "allow", "445/tcp"] in calls
    monkeypatch.setattr(secnet, "_run", lambda argv, timeout=60, input=None: cp("", 1, "ERROR: x"))
    with pytest.raises(secnet.SecNetError, match="ERROR"):
        secnet.port_lan_fix("445/tcp")


TESTSSL = [{"id": "heartbleed", "severity": "OK", "finding": "not vulnerable"}, {"id": "SWEET32", "severity": "LOW", "finding": "uses 64 bit block ciphers", "cve": "CVE-2016-2183"},
           {"id": "SWEET32", "severity": "LOW", "finding": "dup"}, {"id": "cert_trust", "severity": "HIGH", "finding": "skip me"},
           {"id": "LUCKY13", "severity": "LOW", "finding": "potentially vulnerable"}, {"id": "some_new_check", "severity": "CRITICAL", "finding": "bad"}]


def test_testssl(monkeypatch):
    r = secnet.parse_testssl(json.dumps(TESTSSL))
    assert [x["id"] for x in r] == ["testssl-SWEET32", "testssl-LUCKY13", "testssl-some_new_check"]
    assert r[0]["title"] == "testssl.sh: SWEET32 (64-bit block ciphers)" and "CVE-2016-2183" in r[0]["detail"] and r[2]["severity"] == "critical"
    assert r[2]["title"] == "testssl.sh: some new check"
    wrapped = {"scanResult": [{"findings": TESTSSL}]}
    assert len(secnet.parse_testssl(json.dumps(wrapped))) == 3
    assert secnet.parse_testssl(json.dumps({"other": 1})) == [] and secnet.parse_testssl("nope") == []
    monkeypatch.setattr(secnet, "which", lambda *n: "")
    assert secnet.testssl("x.test", 443) == []
    monkeypatch.setattr(secnet, "which", lambda *n: "/usr/bin/testssl")
    seen = []

    def run(argv, timeout=60, input=None):
        seen.append(argv)
        jf = argv[argv.index("--jsonfile") + 1]
        if argv[-1].endswith(":443"):
            open(jf, "w").write(json.dumps(TESTSSL))
        return cp()
    monkeypatch.setattr(secnet, "_run", run)
    assert len(secnet.testssl("x.test", 443)) == 3
    assert secnet.testssl("mail.x.test", 25, "smtp") == [] and seen[-1][-3:] == ["-t", "smtp", "mail.x.test:25"]


def test_scan(monkeypatch):
    monkeypatch.setattr(secnet, "open_ports", lambda: [{"port": 22, "proto": "tcp", "service": "SSH", "process": "sshd", "addrs": [], "firewall": "open", "reachable": True}])
    monkeypatch.setattr(secnet, "nmap_versions", lambda ports: {(22, "tcp"): "OpenSSH 10"})
    monkeypatch.setattr(secnet, "ssh_findings", lambda: [secnet._f("low", "ssh", "d")])
    monkeypatch.setattr(secnet, "timestamp_findings", lambda: [secnet._f("low", "ts", "d")])
    monkeypatch.setattr(secnet, "which", lambda *n: "")
    logged = []
    f, facts = secnet.scan(logged.append)
    assert [x["id"] for x in f] == ["ssh", "ts"] and facts["ports"][0]["product"] == "OpenSSH 10" and logged == ["ports", "nmap", "ssh"]
    assert secnet.scan()[0]
