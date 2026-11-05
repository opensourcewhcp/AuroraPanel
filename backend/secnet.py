"""Security Report, network side: what an outside scanner (Nmap, OpenVAS, SSLyze, Nuclei) would see.

- Open ports: every listening socket, whether it is bound beyond this machine, and whether ufw lets
  the world reach it. Services that should never face the internet (databases, Samba, rpcbind …)
  become findings; with Nmap installed each port also gets the product and version it announces.
- FTP that accepts passwords in clear text, SSH offering weak algorithms (ssh-audit when installed,
  otherwise `sshd -T`), TCP and ICMP timestamps, an open DNS resolver, and anonymous TLS cipher
  suites on the mail ports (STARTTLS included).
- testssl.sh, when installed and a deep scan is asked for, adds its full TLS audit per endpoint.

Every probe targets this machine itself. Every fix backs up what it changes and checks the result
before it is kept.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import distro
from . import problems

PATH = distro.PATH
TIMEOUT = 5.0
SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSH_DROPIN = Path("/etc/ssh/sshd_config.d/00-aurora-crypto.conf")
SYSCTL_FILE = Path("/etc/sysctl.d/90-aurora-timestamps.conf")
TCP_TS = Path("/proc/sys/net/ipv4/tcp_timestamps")
UFW_BEFORE = Path("/etc/ufw/before.rules")
BIND_OPTIONS = Path("/etc/bind/named.conf.options")
ICMP_RULE = "-A ufw-before-input -p icmp --icmp-type timestamp-request -j DROP"
PRIVATE_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
_INTERNAL_IFACES = re.compile(r"^(lo|docker\d*|br-|veth|virbr|lxc|lxd|cni|flannel|podman|tailscale)")


class SecNetError(RuntimeError):
    pass


def _run(argv: list[str], timeout: int = 60, input: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input, env={"PATH": PATH, "LANG": "C.UTF-8"})
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def _f(sev: str, title: str, detail: str, fix: str = "", view: str = "", action: str = "", fid: str = "", cat: str = "network") -> dict:
    return {"severity": sev, "title": title, "detail": detail, "fix": fix, "view": view, "action": action,
            "id": fid or re.sub(r"\W+", "-", title.lower()).strip("-"), "cat": cat}


def which(*names: str) -> str:
    for n in names:
        p = shutil.which(n, path=PATH)
        if p:
            return p
    return ""


# ---------------------------------------------------------------- scanner tools
TOOLS = [
    {"id": "nmap", "bin": ("nmap",), "name": "Nmap", "for": "Open ports: the product and version every port announces, as an outside port scan shows them."},
    {"id": "testssl", "bin": ("testssl", "testssl.sh"), "name": "testssl.sh", "for": "Deep TLS scan: every protocol and cipher, and known TLS attacks (Heartbleed, ROBOT, LUCKY13 …) on each HTTPS and mail port."},
    {"id": "sshaudit", "bin": ("ssh-audit",), "name": "ssh-audit", "for": "SSH audit: every key exchange, host key, cipher and MAC rated, plus known OpenSSH weaknesses."},
]


def tools() -> list[dict]:
    return [{"id": t["id"], "name": t["name"], "for": t["for"], "installed": bool(which(*t["bin"]))} for t in TOOLS]


# ---------------------------------------------------------------- listening sockets
SERVICES = {
    (20, "tcp"): "FTP data", (21, "tcp"): "FTP", (22, "tcp"): "SSH", (23, "tcp"): "Telnet", (25, "tcp"): "SMTP", (53, "tcp"): "DNS", (53, "udp"): "DNS",
    (67, "udp"): "DHCP", (69, "udp"): "TFTP", (80, "tcp"): "HTTP", (110, "tcp"): "POP3", (111, "tcp"): "rpcbind", (111, "udp"): "rpcbind",
    (123, "udp"): "NTP", (137, "udp"): "NetBIOS name", (138, "udp"): "NetBIOS datagram", (139, "tcp"): "Samba (NetBIOS)", (143, "tcp"): "IMAP",
    (161, "udp"): "SNMP", (443, "tcp"): "HTTPS", (445, "tcp"): "Samba (SMB)", (465, "tcp"): "SMTP submission (TLS)", (500, "udp"): "IPsec IKE",
    (587, "tcp"): "SMTP submission", (631, "tcp"): "Printing (CUPS)", (631, "udp"): "Printing (CUPS)", (993, "tcp"): "IMAP (TLS)", (995, "tcp"): "POP3 (TLS)",
    (1194, "udp"): "OpenVPN", (1900, "udp"): "SSDP / UPnP", (2049, "tcp"): "NFS", (3306, "tcp"): "MySQL / MariaDB", (3389, "tcp"): "Remote Desktop",
    (4190, "tcp"): "ManageSieve", (4500, "udp"): "IPsec NAT-T", (5353, "udp"): "mDNS (Avahi)", (5432, "tcp"): "PostgreSQL", (5900, "tcp"): "VNC",
    (6379, "tcp"): "Redis", (8080, "tcp"): "HTTP (alt)", (9200, "tcp"): "Elasticsearch", (11211, "tcp"): "Memcached", (11211, "udp"): "Memcached",
    (27017, "tcp"): "MongoDB", (51820, "udp"): "WireGuard",
}
# Services that should not face the internet: (severity, why)
RISKY = {
    (23, "tcp"): ("high", "Telnet sends everything, passwords included, in clear text."),
    (69, "udp"): ("high", "TFTP has no passwords at all."),
    (3306, "tcp"): ("high", "Databases should only be reachable by the apps on this server."),
    (5432, "tcp"): ("high", "Databases should only be reachable by the apps on this server."),
    (6379, "tcp"): ("high", "Redis has no password by default; exposed instances are taken over within hours."),
    (27017, "tcp"): ("high", "Databases should only be reachable by the apps on this server."),
    (9200, "tcp"): ("high", "Elasticsearch has no login by default."),
    (11211, "tcp"): ("high", "Memcached has no login and is abused for DDoS amplification."),
    (11211, "udp"): ("high", "Memcached over UDP is the largest known DDoS amplifier."),
    (5900, "tcp"): ("high", "VNC is guessed and attacked constantly."),
    (3389, "tcp"): ("medium", "Remote Desktop is guessed and attacked constantly."),
    (111, "tcp"): ("medium", "rpcbind lists the RPC services of this machine and is used for DDoS amplification."),
    (111, "udp"): ("medium", "rpcbind lists the RPC services of this machine and is used for DDoS amplification."),
    (139, "tcp"): ("medium", "Windows file sharing belongs on your own network, never on the internet."),
    (445, "tcp"): ("medium", "Windows file sharing belongs on your own network, never on the internet (WannaCry spread this way)."),
    (137, "udp"): ("low", "NetBIOS names belong on your own network."),
    (138, "udp"): ("low", "NetBIOS belongs on your own network."),
    (2049, "tcp"): ("medium", "NFS shares belong on your own network."),
    (631, "tcp"): ("medium", "The printing service belongs on your own network."),
    (161, "udp"): ("medium", "SNMP leaks system details and is used for DDoS amplification."),
    (1900, "udp"): ("medium", "SSDP/UPnP is used for DDoS amplification."),
    (5353, "udp"): ("low", "mDNS announces the services of this machine (scanners report “mDNS enumeration”)."),
}


def parse_ss(text: str) -> list[dict]:
    """`ss -Htulnp` → [{proto, addr, port, process}] (proto tcp|udp)."""
    out = []
    for line in (text or "").splitlines():
        cols = line.split()
        if len(cols) < 5 or cols[0] not in ("tcp", "udp"):
            continue
        local = cols[4]
        m = re.match(r"^\[?(.*?)\]?(?:%\S+)?:(\d+|\*)$", local)
        if not m or m.group(2) == "*":
            continue
        addr = m.group(1)
        proc = ""
        pm = re.search(r'users:\(\("([^"]+)"', line)
        if pm:
            proc = pm.group(1)
        out.append({"proto": cols[0], "addr": addr or "*", "port": int(m.group(2)), "process": proc})
    return out


def _iface_of() -> dict[str, str]:
    try:
        import psutil
        return {a.address.split("%", 1)[0]: name for name, addrs in psutil.net_if_addrs().items() for a in addrs}
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return {}


def exposure(addr: str, ifaces: dict[str, str]) -> str:
    """public: reachable from other machines (any address, or one on a real network card);
    local: loopback only; internal: a container / VPN bridge only."""
    if addr in ("*", "0.0.0.0", "::", ""):
        return "public"
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "public"
    if ip.is_loopback:
        return "local"
    if ip.is_link_local:
        return "internal"
    name = ifaces.get(addr, "")
    return "internal" if name and _INTERNAL_IFACES.match(name) else "public"


UFW_APPS = {
    "openssh": [(22, "tcp")], "apache": [(80, "tcp")], "apache full": [(80, "tcp"), (443, "tcp")], "apache secure": [(443, "tcp")],
    "www": [(80, "tcp")], "www full": [(80, "tcp"), (443, "tcp")], "www secure": [(443, "tcp")], "postfix": [(25, "tcp")],
    "postfix smtps": [(465, "tcp")], "postfix submission": [(587, "tcp")], "dovecot imap": [(143, "tcp")], "dovecot secure imap": [(993, "tcp")],
    "dovecot pop3": [(110, "tcp")], "dovecot secure pop3": [(995, "tcp")], "bind9": [(53, "tcp"), (53, "udp")], "dns": [(53, "tcp"), (53, "udp")],
    "samba": [(137, "udp"), (138, "udp"), (139, "tcp"), (445, "tcp")], "cups": [(631, "tcp")],
}


def parse_ufw(rules: list[str]) -> list[dict]:
    """ufw status lines ("22/tcp ALLOW IN Anywhere") → [{ports: [(lo, hi)], proto, action, anywhere, v6}]."""
    out = []
    for r in rules or []:
        m = re.match(r"^(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s+(.+?)\s*(#.*)?$", r.strip())
        if not m or m.group(3) in ("OUT", "FWD"):
            continue
        to, action, frm = m.group(1).strip(), m.group(2), m.group(4).strip()
        v6 = "(v6)" in to or "(v6)" in frm
        to = to.replace("(v6)", "").strip()
        frm_clean = frm.replace("(v6)", "").strip()
        anywhere = frm_clean.lower().startswith("anywhere")
        entries = []
        pm = re.match(r"^([\d,:]+)(?:/(tcp|udp))?(?:\s+on\s+\S+)?$", to)
        if pm:
            for part in pm.group(1).split(","):
                lo, _, hi = part.partition(":")
                entries.append(((int(lo), int(hi or lo)), pm.group(2) or "any"))
        else:
            app = re.sub(r"\s+on\s+\S+$", "", to).strip().lower()
            if app.startswith("anywhere"):
                entries.append(((1, 65535), "any"))
            for port, proto in UFW_APPS.get(app, []):
                entries.append(((port, port), proto))
        for rng, proto in entries:
            out.append({"range": rng, "proto": proto, "action": action, "anywhere": anywhere, "v6": v6})
    return out


def firewall_state(port: int, proto: str, fw: dict, parsed: list[dict]) -> str:
    """open: the world can reach it; lan: only some sources (usually your network); blocked; none: no firewall."""
    if not fw or not fw.get("active"):
        return "none"
    allowed_any, allowed_some = False, False
    for r in parsed:
        if not (r["range"][0] <= port <= r["range"][1]) or r["proto"] not in (proto, "any"):
            continue
        if r["action"] in ("DENY", "REJECT"):
            if r["anywhere"] and not allowed_any and not allowed_some:
                return "blocked"
            continue
        if r["anywhere"]:
            allowed_any = True
        else:
            allowed_some = True
    return "open" if allowed_any else "lan" if allowed_some else "blocked"


def _fw() -> dict:
    try:
        from . import firewall
        return firewall.status()
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return {}


def open_ports(ss_text: str | None = None, fw: dict | None = None, ifaces: dict | None = None) -> list[dict]:
    """One row per (port, proto) bound beyond loopback, with who can reach it."""
    if ss_text is None:
        ss_text = _run(["ss", "-Htulnp"], 15).stdout
    fw = _fw() if fw is None else fw
    ifaces = _iface_of() if ifaces is None else ifaces
    parsed = parse_ufw([r["rule"] for r in fw.get("rules", [])]) if fw else []
    rows: dict[tuple, dict] = {}
    for s in parse_ss(ss_text):
        ex = exposure(s["addr"], ifaces)
        if ex != "public":
            continue
        key = (s["port"], s["proto"])
        # UDP sockets on random high ports are a program's own outgoing queries (Avahi, Rspamd, resolvers), not services
        if s["proto"] == "udp" and s["port"] >= 1024 and key not in SERVICES and key not in RISKY:
            continue
        service = SERVICES.get(key) or ("AuroraPanel" if s["process"].startswith(("python", "uvicorn")) and s["proto"] == "tcp" else "")
        row = rows.setdefault(key, {"port": s["port"], "proto": s["proto"], "service": service, "process": s["process"],
                                    "addrs": [], "product": ""})
        a = "all addresses" if s["addr"] in ("*", "0.0.0.0", "::") else s["addr"]
        if a not in row["addrs"]:
            row["addrs"].append(a)
        row["process"] = row["process"] or s["process"]
    out = sorted(rows.values(), key=lambda r: (r["proto"], r["port"]))
    for r in out:
        r["firewall"] = firewall_state(r["port"], r["proto"], fw, parsed)
        r["reachable"] = r["firewall"] in ("open", "none")
    return out


def port_findings(ports: list[dict]) -> list[dict]:
    out = []
    for p in ports:
        risk = RISKY.get((p["port"], p["proto"]))
        if not risk:
            continue
        sev, why = risk
        name = p["service"] or p["process"] or "service"
        where = "from anywhere" if p["firewall"] in ("open", "none") else "from part of the network"
        if p["firewall"] == "blocked":
            continue
        if p["firewall"] == "lan":
            sev = "info"
        action = f"port_lan:{p['port']}/{p['proto']}" if p["firewall"] == "open" else ""
        fix = ("One click: allow it only from your local network (10.x, 172.16-31.x, 192.168.x); the internet is blocked."
               if action else "Turn on the firewall (Security → Firewall), then allow it only from your own network."
               if p["firewall"] == "none" else "Already limited to some addresses.")
        out.append(_f(sev, f"{name} reachable on port {p['port']}/{p['proto']}", f"{why} It is reachable {where}.", fix, "firewall", action,
                      fid=f"port-{p['port']}-{p['proto']}"))
    return out


# ---------------------------------------------------------------- Nmap: product + version per port
def parse_nmap(xml_text: str) -> dict[tuple, str]:
    out = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for port in root.iter("port"):
        st = port.find("state")
        if st is None or st.get("state") != "open":
            continue
        svc = port.find("service")
        if svc is None:
            continue
        desc = " ".join(x for x in (svc.get("product", ""), svc.get("version", ""), svc.get("extrainfo", "")) if x).strip()
        out[(int(port.get("portid", "0")), port.get("protocol", "tcp"))] = desc or svc.get("name", "")
    return out


def nmap_versions(ports: list[dict]) -> dict[tuple, str]:
    nm = which("nmap")
    tcp = sorted({p["port"] for p in ports if p["proto"] == "tcp"})
    if not nm or not tcp:
        return {}
    r = _run([nm, "-Pn", "-n", "-sT", "-sV", "--version-light", "-T4", "-p", ",".join(map(str, tcp)), "-oX", "-", "127.0.0.1"], 240)
    found = parse_nmap(r.stdout)
    # services bound to one address only don't answer on 127.0.0.1: ask that address
    for p in ports:
        if p["proto"] == "tcp" and (p["port"], "tcp") not in found and p["addrs"] and p["addrs"][0] != "all addresses":
            r = _run([nm, "-Pn", "-n", "-sT", "-sV", "--version-light", "-T4", "-p", str(p["port"]), "-oX", "-", p["addrs"][0]], 120)
            found.update(parse_nmap(r.stdout))
    return found


# ---------------------------------------------------------------- FTP
def ftp_findings(ports: list[dict]) -> list[dict]:
    if not any(p["port"] == 21 and p["proto"] == "tcp" for p in ports):
        return []
    try:
        from . import ftp
        if not ftp.installed():
            return []
        conf = ftp._read_conf()
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return []
    if conf.get("ssl_enable", "NO").upper() == "YES" and conf.get("force_local_logins_ssl", "YES").upper() == "YES":
        return []
    return [_f("medium", "FTP accepts passwords in clear text", "vsftpd lets clients log in without encryption, so names and passwords "
               "can be read by anyone on the path (scanners: “FTP Unencrypted Cleartext Login”).",
               "One click: require FTPS (TLS) for logins and transfers. FTP clients must then connect with “explicit TLS”, FileZilla does by default.",
               "ftpaccounts", "ftp_tls", fid="ftp-cleartext")]


# ---------------------------------------------------------------- SSH
WEAK_MAC = re.compile(r"(md5|sha1|umac-64|-96)", re.I)
WEAK_KEX = re.compile(r"(sha1$|group1-|group14-sha1|group-exchange-sha1|gss-.*sha1|ecdh-sha2-nistp)", re.I)
WEAK_CIPHER = re.compile(r"(cbc|3des|arcfour|blowfish|cast128|rijndael)", re.I)


def parse_sshd_t(text: str) -> dict[str, list[str]]:
    out = {}
    for line in (text or "").splitlines():
        k, _, v = line.strip().partition(" ")
        if k in ("macs", "kexalgorithms", "ciphers"):
            out[k] = [x for x in v.split(",") if x]
    return out


def weak_ssh(algos: dict[str, list[str]]) -> dict[str, list[str]]:
    # Same verdicts as ssh-audit, so the report agrees with itself when ssh-audit can't connect
    # (OpenSSH 10 penalises repeated probes from one address): NIST curves and encrypt-and-MAC MACs go too.
    return {"macs": [a for a in algos.get("macs", []) if WEAK_MAC.search(a) or "-etm@" not in a],
            "kexalgorithms": [a for a in algos.get("kexalgorithms", []) if WEAK_KEX.search(a)],
            "ciphers": [a for a in algos.get("ciphers", []) if WEAK_CIPHER.search(a)]}


def parse_ssh_audit(text: str) -> dict:
    """ssh-audit -j → {"weak": {macs, kexalgorithms, ciphers, hostkeys}, "cves": [...]}."""
    try:
        d = json.loads(text)
    except ValueError:
        return {}
    if not isinstance(d, dict) or not ((d.get("banner") or {}).get("raw")):
        return {}  # never reached the server (refused or rate-limited): no verdict
    weak = {"macs": [], "kexalgorithms": [], "ciphers": [], "hostkeys": []}
    for sect, key in (("mac", "macs"), ("kex", "kexalgorithms"), ("enc", "ciphers"), ("key", "hostkeys")):
        for item in d.get(sect, []) or []:
            notes = item.get("notes") or {}
            if notes.get("fail") or notes.get("warn"):
                name = item.get("algorithm", "")
                if name and not name.startswith("kex-strict") and not name.startswith("ext-info"):
                    weak[key].append(name)
    cves = [{"name": c.get("name", ""), "cvss": c.get("cvssv2", 0), "description": c.get("description", "")} for c in d.get("cves", []) or []]
    return {"weak": weak, "cves": cves}


def _ssh_state(sshd: str) -> tuple[dict, dict, list[dict]] | None:
    """(offered, weak, cves): weak joins the built-in rules with ssh-audit's verdicts,
    so the report and the fix agree on what has to go."""
    r = _run([sshd, "-T"], 20)
    if r.returncode != 0:
        return None
    algos = parse_sshd_t(r.stdout)
    weak = weak_ssh(algos)
    cves: list[dict] = []
    port = next((ln.split()[1] for ln in r.stdout.splitlines() if ln.startswith("port ")), "22")
    sa = which("ssh-audit")
    if sa:
        a = parse_ssh_audit(_run([sa, "-j", "-p", port, "127.0.0.1"], 90).stdout)
        if a:
            for k in ("macs", "kexalgorithms", "ciphers"):
                weak[k] = sorted(set(weak[k]) | set(a["weak"].get(k, [])))
            cves = a["cves"]
            if a["weak"].get("hostkeys"):
                weak["hostkeys"] = a["weak"]["hostkeys"]
    return algos, weak, cves


def ssh_findings() -> list[dict]:
    if not which("sshd"):
        return []
    st = _ssh_state(which("sshd"))
    if st is None:
        return []
    _algos, weak, cves = st
    out = []
    fixable = "One click: offer only the strong ones (a separate file in sshd_config.d, tested with sshd -t before SSH reloads; open sessions stay connected)."
    if weak["macs"]:
        out.append(_f("low", "Weak SSH MAC algorithms offered", f"SSH still offers {', '.join(weak['macs'])} (scanners: “Weak MAC Algorithm(s) Supported (SSH)”).",
                      fixable, "sshaccess", "ssh_crypto", fid="ssh-weak-mac"))
    if weak["kexalgorithms"]:
        out.append(_f("medium", "Weak SSH key exchange offered", f"SSH still offers {', '.join(weak['kexalgorithms'])}, based on SHA-1 or small groups.",
                      fixable, "sshaccess", "ssh_crypto", fid="ssh-weak-kex"))
    if weak["ciphers"]:
        out.append(_f("medium", "Weak SSH ciphers offered", f"SSH still offers {', '.join(weak['ciphers'])} (CBC mode or retired ciphers).",
                      fixable, "sshaccess", "ssh_crypto", fid="ssh-weak-cipher"))
    if weak.get("hostkeys"):
        out.append(_f("low", "Weak SSH host key types", f"ssh-audit flags these host keys: {', '.join(weak['hostkeys'])}.",
                      "Remove the HostKey lines for them (ssh_host_rsa_key under 3072 bits, ssh_host_dsa_key) and restart SSH.", "sshaccess", fid="ssh-hostkey"))
    if cves:
        worst = max((c["cvss"] or 0) for c in cves)
        out.append(_f("high" if worst >= 7 else "medium", f"OpenSSH has {len(cves)} known weakness{'es' if len(cves) != 1 else ''}",
                      "; ".join(f"{c['name']} ({c['cvss']}): {c['description']}" for c in cves[:5]),
                      "Install the system updates (Updates page); Debian backports the security fixes.", "updates", fid="ssh-cves"))
    return out


def ssh_crypto_fix() -> dict:
    sshd = which("sshd")
    if not sshd:
        raise SecNetError("SSH server not found")
    main = SSHD_CONFIG
    if "sshd_config.d/" not in main.read_text(errors="replace"):
        raise SecNetError("sshd_config has no “Include /etc/ssh/sshd_config.d/*.conf” line, add it first")
    st = _ssh_state(sshd)
    if st is None:
        raise SecNetError("sshd -T failed, check /etc/ssh/sshd_config")
    algos, weak, _cves = st
    lines = ["# Written by AuroraPanel (Security Report): only strong SSH algorithms. Delete this file to undo."]
    for key, word in (("ciphers", "Ciphers"), ("macs", "MACs"), ("kexalgorithms", "KexAlgorithms")):
        keep = [a for a in algos.get(key, []) if a not in weak[key]]
        if weak[key] and keep:
            lines.append(f"{word} {','.join(keep)}")
    if len(lines) == 1:
        return {"changed": False, "message": "SSH already offers only strong algorithms"}
    old = SSH_DROPIN.read_text() if SSH_DROPIN.exists() else None
    SSH_DROPIN.parent.mkdir(parents=True, exist_ok=True)
    SSH_DROPIN.write_text("\n".join(lines) + "\n")
    t = _run([sshd, "-t"], 20)
    now = parse_sshd_t(_run([sshd, "-T"], 20).stdout)
    if t.returncode != 0 or any(set(now.get(k, [])) & set(weak[k]) for k in ("macs", "kexalgorithms", "ciphers")):
        if old is None:
            SSH_DROPIN.unlink(missing_ok=True)
        else:
            SSH_DROPIN.write_text(old)
        why = (t.stderr or t.stdout).strip()[-300:] if t.returncode != 0 else "an earlier file in sshd_config.d sets these first"
        raise SecNetError("SSH rejected the change, nothing was kept: " + (why or "sshd -t failed"))
    if any(_run(["systemctl", "reload", unit], 30).returncode == 0 for unit in ("ssh", "sshd")):
        return {"changed": True, "message": f"SSH now offers only strong algorithms ({SSH_DROPIN.name}); open sessions stayed connected"}
    return {"changed": True, "message": f"Saved {SSH_DROPIN.name}; SSH couldn't be reloaded, so it applies at its next restart"}


# ---------------------------------------------------------------- timestamps
def _ufw_active() -> bool:
    return bool(_fw().get("active"))


def timestamp_findings() -> list[dict]:
    out = []
    try:
        ts = TCP_TS.read_text().strip()
    except OSError:
        ts = "0"
    if ts != "0":
        out.append(_f("low", "TCP timestamps reveal the uptime", "Answers carry TCP timestamps, from which a scanner estimates how long the server "
                      "has been up and so which updates it missed (scanners: “TCP Timestamps Information Disclosure”).",
                      "One click: switch TCP timestamps off (net.ipv4.tcp_timestamps = 0, kept across reboots).", "", "timestamps_off", fid="tcp-timestamps"))
    active = _ufw_active()
    try:
        has_rule = "timestamp-request" in UFW_BEFORE.read_text(errors="replace")
    except OSError:
        has_rule = False
    if not has_rule:
        out.append(_f("low", "Answers ICMP timestamp requests", "The server tells anyone who asks its exact clock (scanners: “ICMP Timestamp Reply "
                      "Information Disclosure”, CVE-1999-0524).",
                      "One click: drop ICMP timestamp requests in the firewall." if active else "Turn on the firewall first, then drop ICMP timestamp requests here.",
                      "firewall", "timestamps_off" if active else "", fid="icmp-timestamp"))
    return out


def timestamps_fix() -> dict:
    done = []
    SYSCTL_FILE.write_text("# Written by AuroraPanel (Security Report): don't reveal uptime through TCP timestamps.\nnet.ipv4.tcp_timestamps = 0\n")
    try:
        TCP_TS.write_text("0\n")
        done.append("TCP timestamps off")
    except OSError as e:
        raise SecNetError(f"Couldn't switch TCP timestamps off: {e}")
    if _ufw_active() and UFW_BEFORE.exists():
        text = UFW_BEFORE.read_text(errors="replace")
        if "timestamp-request" not in text:
            marker = "# ok icmp codes for INPUT"
            if marker not in text:
                raise SecNetError("ufw's before.rules has an unexpected layout; TCP timestamps are off, ICMP was left alone")
            backup = UFW_BEFORE.with_name("before.rules.aurora-bak")
            backup.write_text(text)
            UFW_BEFORE.write_text(text.replace(marker, f"# AuroraPanel: don't answer ICMP timestamp requests\n{ICMP_RULE}\n\n{marker}", 1))
            r = _run(["ufw", "reload"], 60)
            if r.returncode != 0:
                UFW_BEFORE.write_text(text)
                _run(["ufw", "reload"], 60)
                raise SecNetError("ufw refused the rule, before.rules was put back: " + (r.stderr or r.stdout).strip()[-200:])
            done.append("ICMP timestamp requests dropped")
    return {"changed": True, "message": " and ".join(done)}


# ---------------------------------------------------------------- DNS
def _recursion_off(text: str) -> bool:
    return bool(re.search(r"(^|[\s;{])recursion\s+no\s*;", text))


def dns_findings(ports: list[dict]) -> list[dict]:
    if not any(p["port"] == 53 and p["reachable"] for p in ports):
        return []
    try:
        text = BIND_OPTIONS.read_text(errors="replace")
    except OSError:
        return []
    text = re.sub(r"//[^\n]*|#[^\n]*|/\*.*?\*/", "", text, flags=re.S)
    rec = re.search(r"allow-recursion\s*\{([^}]*)\}", text)
    if _recursion_off(text) or not (rec and re.search(r"(^|[\s;{])any\s*;", rec.group(1))):
        return []  # BIND's default allow-recursion is localhost + localnets: not open
    return [_f("high", "Open DNS resolver", "BIND answers recursive queries for anyone. Open resolvers are used to amplify DDoS attacks "
               "against others, and providers block servers that run one.",
               "Limit recursion to your network: allow-recursion { localhost; localnets; }; in named.conf.options.", "zones", fid="open-resolver")]


# ---------------------------------------------------------------- anonymous TLS on the mail ports
MAIL_PORTS = [(25, "smtp", "postfix"), (587, "smtp", "postfix"), (465, "", "postfix"), (143, "imap", "dovecot"), (993, "", "dovecot"),
              (110, "pop3", "dovecot"), (995, "", "dovecot")]
ANON_EXCLUDE = "aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, SRP, 3DES"


def _starttls(sock: socket.socket, kind: str) -> bool:
    f = sock.makefile("rb")
    try:
        if kind == "smtp":
            f.readline()
            sock.sendall(b"EHLO aurora.security.report\r\n")
            while True:
                line = f.readline()
                if not line or line[3:4] != b"-":
                    break
            sock.sendall(b"STARTTLS\r\n")
            return f.readline().startswith(b"220")
        if kind == "imap":
            f.readline()
            sock.sendall(b"a STARTTLS\r\n")
            return f.readline().startswith(b"a OK")
        if kind == "pop3":
            f.readline()
            sock.sendall(b"STLS\r\n")
            return f.readline().startswith(b"+OK")
        return True
    finally:
        f.close()


def anon_accepted(port: int, kind: str) -> bool:
    """Does the service agree to an anonymous (unauthenticated) TLS 1.2 suite?"""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as s:
            if not _starttls(s, kind):
                return False
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers("aNULL:@SECLEVEL=0")
            with ctx.wrap_socket(s) as t:
                return bool(t.cipher())
    except (OSError, ssl.SSLError, ValueError):
        return False


def mail_anon_findings(probe=anon_accepted) -> list[dict]:
    hits: dict[str, list[int]] = {"postfix": [], "dovecot": []}
    with ThreadPoolExecutor(max_workers=7) as ex:
        res = list(ex.map(lambda m: (m, probe(m[0], m[1])), MAIL_PORTS))
    for (port, _, who), ok in res:
        if ok:
            hits[who].append(port)
    out = []
    why = ("An anonymous suite (ADH / AECDH) encrypts without proving who the server is, so a machine in the middle can pose as it "
           "(scanners: “SSL/TLS: Report 'Anonymous' Cipher Suites”).")
    if hits["postfix"]:
        out.append(_f("medium", f"Anonymous TLS cipher suites accepted by Postfix (port {', '.join(map(str, hits['postfix']))})", why,
                      "One click: exclude aNULL and other weak suites in Postfix (smtpd_tls_exclude_ciphers), then reload it.",
                      "email", "mail_anon_off", fid="anon-ciphers-postfix", cat="tls"))
    if hits["dovecot"]:
        out.append(_f("medium", f"Anonymous TLS cipher suites accepted by Dovecot (port {', '.join(map(str, hits['dovecot']))})", why,
                      "Add !aNULL to ssl_cipher_list in Dovecot's 10-ssl.conf and restart it.", "email", fid="anon-ciphers-dovecot", cat="tls"))
    return out


def mail_anon_fix() -> dict:
    pc = which("postconf")
    if not pc:
        raise SecNetError("Postfix isn't installed")
    old = {k: _run([pc, "-h", k]).stdout.strip() for k in ("smtpd_tls_exclude_ciphers", "smtpd_tls_mandatory_exclude_ciphers")}
    r = _run([pc, "-e", f"smtpd_tls_exclude_ciphers={ANON_EXCLUDE}", f"smtpd_tls_mandatory_exclude_ciphers={ANON_EXCLUDE}"])
    if r.returncode != 0:
        raise SecNetError((r.stderr or r.stdout).strip()[-300:] or "postconf failed")
    rl = _run(["postfix", "reload"], 60)
    if rl.returncode != 0:
        _run([pc, "-e", *[f"{k}={v}" for k, v in old.items()]])
        _run(["postfix", "reload"], 60)
        raise SecNetError("Postfix didn't reload, the old settings were put back: " + (rl.stderr or rl.stdout).strip()[-300:])
    return {"changed": True, "message": "Postfix no longer offers anonymous or weak TLS suites"}


# ---------------------------------------------------------------- FTP + ports fixes
def ftp_tls_fix() -> dict:
    from . import ftp
    ftp.save_settings({"ssl_enable": "YES", "force_local_logins_ssl": "YES", "force_local_data_ssl": "YES"})
    return {"changed": True, "message": "FTP now requires TLS for logins and transfers. Connect with “explicit FTP over TLS”."}


def port_lan_fix(arg: str) -> dict:
    m = re.match(r"^(\d{1,5})/(tcp|udp)$", arg or "")
    if not m or not 1 <= int(m.group(1)) <= 65535:
        raise SecNetError("Bad port")
    port, proto = m.group(1), m.group(2)
    from . import firewall
    if port in [p.split("/")[0] for p in firewall.guard_ports()]:
        raise SecNetError("That's the port for SSH or this panel, it stays open so you can't lock yourself out")
    if firewall._firewalld():
        try:
            firewall.lan_only(port, proto, list(PRIVATE_NETS))
        except firewall.FirewallError as e:
            raise SecNetError(str(e)) from e
        return {"changed": True, "message": f"Port {port}/{proto} is now reachable only from your local network"}
    ufw = which("ufw")
    if not ufw:
        raise SecNetError("ufw isn't installed")
    for p in PRIVATE_NETS:
        r = _run([ufw, "allow", "from", p, "to", "any", "port", port, "proto", proto])
        if r.returncode != 0:
            raise SecNetError((r.stderr or r.stdout).strip()[-300:])
    for rule in (f"{port}/{proto}", port):
        _run([ufw, "delete", "allow", rule])
    return {"changed": True, "message": f"Port {port}/{proto} is now reachable only from your local network"}


# ---------------------------------------------------------------- testssl.sh (deep TLS)
TESTSSL_SKIP = re.compile(r"^(cert_|intermediate_|chain_of_trust|HSTS|security_headers|banner_|cookie_|DNS_CAArecord|OCSP_|engine_problem|scanProblem|"
                          r"service|pre_|optimal_proto|clientsimulation|TLS_session_ticket|PFS$|FS$|BREACH)", re.I)
TESTSSL_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
TESTSSL_NAMES = {
    "heartbleed": "Heartbleed", "CCS": "CCS injection", "ticketbleed": "Ticketbleed", "ROBOT": "ROBOT", "secure_renego": "Insecure renegotiation",
    "secure_client_renego": "Client-initiated renegotiation", "CRIME_TLS": "CRIME", "POODLE_SSL": "POODLE", "fallback_SCSV": "No TLS_FALLBACK_SCSV",
    "SWEET32": "SWEET32 (64-bit block ciphers)", "FREAK": "FREAK", "DROWN": "DROWN", "LOGJAM": "LOGJAM", "BEAST": "BEAST", "LUCKY13": "LUCKY13",
    "winshock": "Winshock", "RC4": "RC4 ciphers", "SSLv2": "SSLv2 offered", "SSLv3": "SSLv3 offered", "TLS1": "TLS 1.0 offered", "TLS1_1": "TLS 1.1 offered",
    "cipherlist_NULL": "NULL ciphers", "cipherlist_aNULL": "Anonymous ciphers", "cipherlist_EXPORT": "Export ciphers", "cipherlist_LOW": "Low-strength ciphers",
    "cipherlist_3DES_IDEA": "3DES / IDEA ciphers", "cipherlist_OBSOLETED": "Obsolete CBC ciphers", "DH_groups": "Weak Diffie-Hellman group",
}


def parse_testssl(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        data = data.get("scanResult", [{}])[0].get("findings", []) if "scanResult" in data else []
    out, seen = [], set()
    for it in data:
        sev = TESTSSL_SEV.get(str(it.get("severity", "")).upper())
        tid = str(it.get("id", ""))
        if not sev or TESTSSL_SKIP.match(tid) or tid in seen:
            continue
        seen.add(tid)
        name = TESTSSL_NAMES.get(tid, tid.replace("_", " "))
        cve = it.get("cve", "")
        out.append({"severity": sev, "title": f"testssl.sh: {name}", "detail": str(it.get("finding", "")) + (f" ({cve})" if cve else ""),
                    "fix": "Server-wide modern TLS (Harden web server) removes most of these; mail ports follow the mail TLS settings.",
                    "view": "sysapps", "action": "", "id": f"testssl-{tid}", "cat": "tls"})
    return out


def testssl(host: str, port: int, starttls: str = "") -> list[dict]:
    bin_ = which("testssl", "testssl.sh")
    if not bin_:
        return []
    with tempfile.TemporaryDirectory() as d:
        jf = Path(d) / "r.json"
        argv = [bin_, "--quiet", "--color", "0", "--warnings", "off", "--sneaky", "--ip", "127.0.0.1", "-p", "-U", "-s", "--jsonfile", str(jf)]
        if starttls:
            argv += ["-t", starttls]
        argv.append(f"{host}:{port}")
        _run(argv, 420)
        try:
            return parse_testssl(jf.read_text(errors="replace"))
        except OSError:
            return []


# ---------------------------------------------------------------- everything network
def scan(log=lambda *_: None) -> tuple[list[dict], dict]:
    t0 = time.time()
    ports = open_ports()
    log("ports")
    versions = nmap_versions(ports)
    for p in ports:
        p["product"] = versions.get((p["port"], p["proto"]), "")
    log("nmap")
    findings = port_findings(ports) + ftp_findings(ports) + dns_findings(ports)
    findings += ssh_findings()
    log("ssh")
    findings += timestamp_findings()
    facts = {"ports": ports, "nmap": bool(which("nmap")), "ssh_audit": bool(which("ssh-audit")), "took": round(time.time() - t0, 1)}
    return findings, facts


FIXES = {"ssh_crypto": ssh_crypto_fix, "timestamps_off": timestamps_fix, "mail_anon_off": mail_anon_fix, "ftp_tls": ftp_tls_fix}
