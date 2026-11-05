"""Network Monitor: who tried to connect to this Pi.

Two sources:
  * Connection log — an nftables table (inet aurora_mon) logs every NEW inbound
    unicast connection attempt to the kernel log, rate-limited, at a priority
    that runs before ufw so attempts on blocked/closed ports are seen too.
  * Auth events — parsed from the journal: SSH, panel logins, OpenVPN,
    strongSwan; plus WireGuard handshakes from `wg show`.

Everything here (usernames, CNs, hostnames) can be attacker-controlled, so
free text is length-capped and stripped of control characters, and the
frontend renders it with textContent only."""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from .vpncommon import VPNError, default_route, run, unit_state
from . import distro
from . import problems

MON_FILE = Path("/var/lib/aurora/netmon.nft")
MON_UNIT = Path("/etc/systemd/system/aurora-netmon.service")
PREFIX = "aurora-conn: "
SERVICES = {
    22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 500: "IPsec IKE", 4500: "IPsec NAT-T",
    1194: "OpenVPN", 51820: "WireGuard", 8088: "AuroraPanel", 3306: "MySQL", 5432: "PostgreSQL",
    21: "FTP", 25: "SMTP", 23: "Telnet", 3389: "RDP", 445: "SMB", 139: "NetBIOS", 5900: "VNC",
}
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean(s, limit: int = 120) -> str:
    """Untrusted text → short single-line plain string."""
    return _CTRL.sub("?", str(s or ""))[:limit]


def _service_names() -> dict[int, str]:
    names = dict(SERVICES)
    try:
        from . import openvpn, wireguard
        names[wireguard._state()["port"]] = "WireGuard"
        names[openvpn._state()["port"]] = "OpenVPN"
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    return names


# ---- enable / disable the connection log ----
def set_logging(on: bool) -> dict:
    nft = shutil.which("nft", path=distro.PATH)
    if not nft:
        raise VPNError("nftables is not installed (install any VPN, or `apt install nftables`)")
    if on:
        MON_FILE.parent.mkdir(parents=True, exist_ok=True)
        MON_FILE.write_text(f"""# Managed by AuroraPanel — log new inbound connection attempts.
table inet aurora_mon
delete table inet aurora_mon
table inet aurora_mon {{
  chain mon_input {{
    type filter hook input priority -10; policy accept;
    iifname "lo" return
    meta pkttype != host return
    ct state new limit rate 20/second burst 100 packets log prefix "{PREFIX}" level info
  }}
}}
""", encoding="utf-8")
        MON_UNIT.write_text(f"""[Unit]
Description=AuroraPanel Network Monitor (log inbound connection attempts)
After=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={nft} -f {MON_FILE}
ExecStop={nft} delete table inet aurora_mon

[Install]
WantedBy=multi-user.target
""", encoding="utf-8")
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "aurora-netmon.service"])
        run(["systemctl", "restart", "aurora-netmon.service"])
    else:
        run(["systemctl", "disable", "--now", "aurora-netmon.service"], check=False)
    return {"ok": True, "logging": unit_state("aurora-netmon.service")["active"]}


# ---- reading ----
def _journal(args: list[str], since_s: int, limit: int = 5000) -> list[dict]:
    if not shutil.which("journalctl"):
        return []
    r = subprocess.run(["journalctl", *args, "--since", f"-{since_s}s", "-o", "json", "-n", str(limit),
                        "--no-pager"], capture_output=True, text=True, timeout=30)
    out = []
    for line in r.stdout.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        msg = e.get("MESSAGE")
        if isinstance(msg, list):  # journald encodes non-UTF-8 messages as byte arrays
            msg = bytes(msg).decode("utf-8", "replace")
        try:
            ts = int(e.get("__REALTIME_TIMESTAMP", 0)) / 1e6
        except ValueError:
            ts = 0
        out.append({"ts": ts, "msg": msg or "", "id": e.get("SYSLOG_IDENTIFIER", "")})
    return out


def _scope(ip: str, lan: ipaddress.IPv4Network | None) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if lan and a.version == 4 and a in lan:
        return "lan"
    if a.is_loopback:
        return "local"
    if a.is_private or a.is_link_local:
        return "private"
    return "internet"


_KV = re.compile(r"\b(IN|SRC|DST|PROTO|SPT|DPT)=(\S*)")


def connections(since_s: int) -> list[dict]:
    names = _service_names()
    rows = []
    for e in _journal(["-k", "-g", PREFIX.strip()], since_s, 20000):
        kv = dict(_KV.findall(e["msg"]))
        if "SRC" not in kv:
            continue
        port = int(kv["DPT"]) if kv.get("DPT", "").isdigit() else None
        proto = kv.get("PROTO", "").lower()
        rows.append({"ts": e["ts"], "src": kv["SRC"], "dst": kv.get("DST"), "proto": proto,
                     "port": port, "iface": kv.get("IN"), "service": names.get(port) if port else None})
    return rows


# (source, regex, kind, outcome); named groups: ip, user
_AUTH_RULES = [
    ("SSH", re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F.:]+)"), "login", "fail"),
    ("SSH", re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\da-fA-F.:]+)"), "login", "fail"),
    ("SSH", re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\da-fA-F.:]+)"), "login", "ok"),
    ("SSH", re.compile(r"(?:Connection closed|Disconnected) by (?:invalid user \S+ |authenticating user \S+ )?(?P<ip>[\da-fA-F.:]+) port \d+ \[preauth\]"), "probe", "fail"),
    ("AuroraPanel", re.compile(r"aurora-auth: (?P<outcome>ok|fail) user=(?P<user>\"(?:[^\"\\]|\\.)*\") ip=(?P<ip>[\da-fA-F.:]+)"), "login", None),
    ("OpenVPN", re.compile(r"aurora-ovpn-auth: (?P<outcome>ok|fail) user=(?P<user>\"(?:[^\"\\]|\\.)*\") ip=(?P<ip>[\da-fA-F.:?]+)"), "login", None),
    ("OpenVPN", re.compile(r"(?P<user>[^/\s]+)/(?P<ip>[\d.]+):\d+ \[[^\]]*\] Peer Connection Initiated"), "vpn", "ok"),
    ("OpenVPN", re.compile(r"(?:\[AF_INET\])?(?P<ip>[\d.]+):\d+ (?:TLS Error|tls-crypt unwrapping failed|TLS handshake failed)"), "vpn", "fail"),
    ("OpenVPN", re.compile(r"(?:\[AF_INET\])?(?P<ip>[\d.]+):\d+ VERIFY ERROR"), "vpn", "fail"),
    ("IPsec", re.compile(r"(?P<ip>[\d.]+) is initiating an IKE_SA"), "vpn", "attempt"),
    ("IPsec", re.compile(r"EAP method \S+ failed for peer (?P<user>\S+)"), "vpn", "fail"),
    ("IPsec", re.compile(r"IKE_SA aurora\[\d+\] established between .*?\.\.\.(?P<ip>[\d.]+)\[(?P<user>[^\]]+)\]"), "vpn", "ok"),
]


def auth_events(since_s: int) -> list[dict]:
    lan = default_route().get("lan")
    lan_net = ipaddress.ip_network(lan) if lan else None
    sources = [
        (["-t", "sshd", "-t", "sshd-session"], {"SSH"}),
        (["-u", "aurorapanel", "-g", "aurora-auth"], {"AuroraPanel"}),
        (["-u", "openvpn-server@aurora"], {"OpenVPN"}),
        (["-u", "strongswan"], {"IPsec"}),
    ]
    events = []
    for args, wanted in sources:
        for e in _journal(args, since_s, 4000):
            for src, rx, kind, outcome in _AUTH_RULES:
                if src not in wanted:
                    continue
                m = rx.search(e["msg"])
                if not m:
                    continue
                g = m.groupdict()
                user = g.get("user")
                if user and user.startswith('"'):  # JSON-encoded by our own loggers
                    try:
                        user = json.loads(user)
                    except ValueError:
                        pass
                ip = g.get("ip") or ""
                events.append({"ts": e["ts"], "source": src, "kind": kind, "outcome": g.get("outcome") or outcome,
                               "ip": clean(ip, 45), "user": clean(user, 64) if user else None,
                               "scope": _scope(ip, lan_net) if ip else None, "detail": clean(e["msg"], 240)})
                break
    try:  # WireGuard: last handshake per peer (it logs nothing on its own)
        from . import wireguard
        st = wireguard.status()
        for p in st.get("peers", []):
            if p.get("latest_handshake") and time.time() - p["latest_handshake"] < since_s:
                ip = (p.get("endpoint") or "").rsplit(":", 1)[0].strip("[]")
                events.append({"ts": p["latest_handshake"], "source": "WireGuard", "kind": "vpn", "outcome": "ok",
                               "ip": clean(ip, 45), "user": p["name"], "scope": _scope(ip, lan_net),
                               "detail": "Latest handshake"})
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    events.sort(key=lambda x: x["ts"], reverse=True)
    return events[:500]


def blocked(since_s: int) -> list[dict]:
    """Packets dropped by a ban (logged by guard.py with prefix aurora-block:)."""
    rows = []
    for e in _journal(["-k", "-g", "aurora-block"], since_s, 20000):
        kv = dict(_KV.findall(e["msg"]))
        if "SRC" in kv:
            port = int(kv["DPT"]) if kv.get("DPT", "").isdigit() else None
            rows.append({"ts": e["ts"], "src": kv["SRC"], "proto": kv.get("PROTO", "").lower(), "port": port, "blocked": True})
    return rows


def summary(hours: int = 24, scope: str = "all") -> dict:
    hours = max(1, min(int(hours), 24 * 14))
    since = hours * 3600
    lan = default_route().get("lan")
    lan_net = ipaddress.ip_network(lan) if lan else None
    names = _service_names()
    blk = blocked(since)
    for b in blk:
        b["service"] = names.get(b["port"]) if b["port"] else None
    conns = connections(since) + blk
    by_ip: dict[str, dict] = {}
    by_port: dict[str, dict] = {}
    for c in conns:
        sc = _scope(c["src"], lan_net)
        if scope != "all" and sc != scope:
            continue
        d = by_ip.setdefault(c["src"], {"ip": c["src"], "scope": sc, "count": 0, "blocked": 0, "first": c["ts"],
                                        "last": c["ts"], "ports": {}})
        d["count"] += 1
        d["blocked"] += 1 if c.get("blocked") else 0
        d["first"], d["last"] = min(d["first"], c["ts"]), max(d["last"], c["ts"])
        key = f"{c['port']}/{c['proto']}"
        d["ports"][key] = d["ports"].get(key, 0) + 1
        p = by_port.setdefault(key, {"port": c["port"], "proto": c["proto"], "service": c["service"],
                                     "count": 0, "sources": set()})
        p["count"] += 1
        p["sources"].add(c["src"])
    sources = sorted(by_ip.values(), key=lambda d: d["last"], reverse=True)[:300]
    for d in sources:
        d["ports"] = [{"key": k, "count": n} for k, n in sorted(d["ports"].items(), key=lambda kv: -kv[1])][:12]
    ports = sorted(({**p, "sources": len(p["sources"])} for p in by_port.values()), key=lambda p: -p["count"])[:50]
    events = [e for e in auth_events(since) if scope == "all" or e["scope"] == scope]
    conns.sort(key=lambda c: c["ts"])
    recent = [c for c in conns if scope == "all" or _scope(c["src"], lan_net) == scope][-200:][::-1]
    try:
        from . import guard
        marks = guard.status_of(list({s["ip"] for s in sources} | {e["ip"] for e in events if e.get("ip")}))
    except Exception:
        marks = {}
    for s_ in sources:
        s_["status"] = marks.get(s_["ip"])
    for e in events:
        e["status"] = marks.get(e.get("ip"))
    return {
        "logging": unit_state("aurora-netmon.service")["active"],
        "nft": bool(shutil.which("nft", path=distro.PATH)),
        "hours": hours, "scope": scope, "lan": lan, "total": sum(d["count"] for d in by_ip.values()),
        "sources": sources, "ports": ports, "events": events, "recent": recent,
        "failed_logins": sum(1 for e in events if e["kind"] == "login" and e["outcome"] == "fail"),
        "blocked_total": sum(d["blocked"] for d in by_ip.values()),
    }
