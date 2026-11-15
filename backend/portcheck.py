"""Port Checker: is a port reachable from the internet, and if not, why?

Checks, in order: something listening here → host firewall (ufw) → router
(UPnP mapping, double-NAT / CGNAT) → an outside probe (TCP only; UDP can't be
probed statelessly, so live VPN clients connecting from outside count as
proof). Ends with concrete router port-forwarding instructions."""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.request

from . import jobs
from .vpncommon import APT, APT_ENV, default_route, public_ip
from . import problems

UA = {"User-Agent": "AuroraPanel-PortCheck/1.0", "Accept": "application/json"}


class PortError(RuntimeError):
    pass


def _validate(port, proto) -> tuple[int, str]:
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise PortError("Invalid port")
    if not 1 <= port <= 65535:
        raise PortError("Port must be 1–65535")
    if proto not in ("tcp", "udp"):
        raise PortError("Protocol must be tcp or udp")
    return port, proto


def _listener(port: int, proto: str) -> dict:
    if not shutil.which("ss"):
        return {"listening": None}
    out = subprocess.run(["ss", "-Hlnp" + ("u" if proto == "udp" else "t")], capture_output=True, text=True).stdout
    for line in out.splitlines():
        cols = line.split()
        local = next((c for c in cols if re.search(r":\d+$", c)), "")
        if local.rsplit(":", 1)[-1] == str(port):
            m = re.search(r'users:\(\("([^"]+)"', line)
            return {"listening": True, "process": m.group(1) if m else None, "address": local}
    # WireGuard is a kernel socket: ss shows it without a process; also check wg.
    if proto == "udp" and shutil.which("wg"):
        wg = subprocess.run(["wg", "show", "all", "listen-port"], capture_output=True, text=True).stdout
        if re.search(rf"\s{port}$", wg, re.M):
            return {"listening": True, "process": "wireguard (kernel)", "address": f"*:{port}"}
    return {"listening": False}


def _ufw(port: int, proto: str) -> dict:
    from . import firewall
    if firewall._firewalld():
        st = firewall.status()
        allowed = any(re.match(rf"(?:\S*,)?{port}(/{proto})?\b.*ALLOW", r["rule"]) for r in st["rules"])
        return {"installed": True, "active": st["active"], "allowed": allowed}
    ufw = shutil.which("ufw", path=APT_ENV["PATH"])
    if not ufw:
        return {"installed": False, "active": False, "allowed": None}
    out = subprocess.run([ufw, "status"], capture_output=True, text=True, timeout=10).stdout
    active = "Status: active" in out
    allowed = bool(re.search(rf"^{port}(/{proto})?\s+(\(v6\)\s+)?ALLOW", out, re.M))
    return {"installed": True, "active": active, "allowed": allowed}


def _upnp() -> dict:
    """Router facts over UPnP IGD (if the router has UPnP enabled)."""
    if not shutil.which("upnpc"):
        return {"available": False, "installed": False}
    try:
        out = subprocess.run(["upnpc", "-l"], capture_output=True, text=True, timeout=15).stdout
    except subprocess.TimeoutExpired:
        return {"available": False, "installed": True}
    ext = re.search(r"ExternalIPAddress\s*=\s*([\d.]+)", out)
    if not ext:
        return {"available": False, "installed": True}
    maps = []
    for m in re.finditer(r"^\s*\d+\s+(TCP|UDP)\s+(\d+)->([\d.]+):(\d+)\s+'([^']*)'", out, re.M):
        maps.append({"proto": m.group(1).lower(), "external": int(m.group(2)), "internal_ip": m.group(3),
                     "internal": int(m.group(4)), "desc": m.group(5)})
    name = re.search(r"desc:\s*(\S+)", out)
    return {"available": True, "installed": True, "router_wan_ip": ext.group(1), "mappings": maps,
            "desc_url": name.group(1) if name else None}


def _probe_tcp(ip: str, port: int) -> bool | None:
    try:
        with urllib.request.urlopen(urllib.request.Request(f"https://ifconfig.co/port/{port}", headers=UA), timeout=15) as r:
            d = json.loads(r.read().decode())
        if d.get("ip") == ip:
            return bool(d.get("reachable"))
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    try:
        body = json.dumps({"host": ip, "ports": [port]}).encode()
        req = urllib.request.Request("https://portchecker.io/api/v1/query", data=body,
                                     headers={**UA, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read().decode())
        return bool(d["check"][0]["status"])
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return None


class _TempListener:
    """Accept-and-close TCP listener so an outside probe has something to hit."""

    def __init__(self, port: int):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", port))
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self.stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
                c.close()
            except OSError:
                continue

    def close(self):
        self.stop = True
        time.sleep(0.6)
        self.sock.close()


# What usually sits on a port, so the list reads as services and not as numbers.
KNOWN = {20: "FTP data", 21: "FTP", 22: "SSH", 25: "Mail (SMTP)", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "Web (HTTP)", 110: "Mail (POP3)", 111: "rpcbind",
         123: "Time (NTP)", 137: "Windows names", 138: "Windows names", 139: "Windows file sharing", 143: "Mail (IMAP)", 443: "Web (HTTPS)", 445: "Windows file sharing",
         465: "Mail sending (SMTPS)", 500: "IPsec IKE", 587: "Mail sending", 631: "Printing", 993: "Mail (IMAPS)", 995: "Mail (POP3S)", 1194: "OpenVPN",
         3306: "MariaDB / MySQL", 4500: "IPsec NAT-T", 5353: "mDNS (.local names)", 5432: "PostgreSQL", 6379: "Redis", 11211: "Memcached", 27017: "MongoDB", 51820: "WireGuard"}
# Services that belong on your own network: seeing one of these from the internet is a finding, not a success.
PRIVATE = {111, 137, 138, 139, 445, 631, 3306, 5432, 6379, 11211, 27017}


def _firewall_rules() -> dict:
    """The host firewall, read once: is it on, and the text its rules are matched in."""
    from . import firewall
    if firewall._firewalld():
        st = firewall.status()
        return {"installed": True, "active": st["active"], "kind": "firewalld", "rules": [r["rule"] for r in st["rules"]]}
    ufw = shutil.which("ufw", path=APT_ENV["PATH"])
    if not ufw:
        return {"installed": False, "active": False, "kind": "ufw", "text": ""}
    out = subprocess.run([ufw, "status"], capture_output=True, text=True, timeout=10).stdout
    return {"installed": True, "active": "Status: active" in out, "kind": "ufw", "text": out}


def _allowed(fw: dict, port: int, proto: str) -> bool | None:
    """Does the host firewall let this port in? None when there is no firewall to ask."""
    if not fw["installed"]:
        return None
    if not fw["active"]:
        return True
    if fw["kind"] == "firewalld":
        return any(re.match(rf"(?:\S*,)?{port}(/{proto})?\b.*ALLOW", r) for r in fw["rules"])
    return bool(re.search(rf"^{port}(/{proto})?\s+(\(v6\)\s+)?ALLOW", fw["text"], re.M))


def listening() -> dict:
    """Every port something on this machine listens on: what it is, whether it answers other machines or only
    this one, and whether the host firewall lets it in. Nothing leaves the machine for this."""
    from . import netmgr
    net = default_route()
    fw = _firewall_rules()
    rows: dict[tuple, dict] = {}
    for p in netmgr.ports()["ports"]:
        if not isinstance(p["port"], int):
            continue
        local = p["scope"] == "this machine only"
        key = (p["port"], p["proto"])
        r = rows.get(key)
        if r is None:
            proc = "" if p["process"] == "?" else p["process"]
            rows[key] = {"port": p["port"], "proto": p["proto"], "process": proc, "service": KNOWN.get(p["port"], ""), "local_only": local,
                         "address": p["address"], "private": p["port"] in PRIVATE}
        else:
            r["local_only"] = r["local_only"] and local   # one socket on every interface is enough to be reachable
            if not local:
                r["address"] = p["address"]
    out = sorted(rows.values(), key=lambda r: (r["port"], r["proto"]))
    for r in out:
        r["firewall"] = None if r["local_only"] else _allowed(fw, r["port"], r["proto"])
        r["outside"], r["why"] = (False, "Only answers on this machine itself") if r["local_only"] else (None, "")
    return {"ports": out, "public_ip": public_ip(), "lan_ip": net.get("ip"), "gateway": net.get("gateway"),
            "firewall": {"installed": fw["installed"], "active": fw["active"]}, "checked": 0}


def _probe_many(ip: str, ports: list[int]) -> dict[int, bool]:
    """One outside test for a batch of TCP ports. Ports the service didn't answer for are left out."""
    out: dict[int, bool] = {}
    for i in range(0, len(ports), 20):
        chunk = ports[i:i + 20]
        try:
            req = urllib.request.Request("https://portchecker.io/api/v1/query", data=json.dumps({"host": ip, "ports": chunk}).encode(),
                                         headers={**UA, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=40) as r:
                d = json.loads(r.read().decode())
            for c in d.get("check") or []:
                out[int(c["port"])] = bool(c["status"])
        except Exception as quiet_exc:
            problems.quiet(quiet_exc)
    for port in [p for p in ports if p not in out][:6]:   # the batch service was down or skipped some: ask one by one, a few
        one = _probe_tcp(ip, port)
        if one is not None:
            out[port] = one
    return out


def scan() -> dict:
    """Test every listening port from the internet in one go. TCP is probed from outside; UDP has no handshake an
    outside prober can see, so it counts as proven only once a VPN client has connected from outside."""
    d = listening()
    pip = d["public_ip"]
    tcp = [r["port"] for r in d["ports"] if r["proto"] == "tcp" and not r["local_only"]]
    seen = _probe_many(pip, tcp) if pip and tcp else {}
    for r in d["ports"]:
        if r["local_only"]:
            continue
        if r["proto"] == "udp":
            ev = _evidence(r["port"], "udp")
            r["outside"], r["why"] = (True, ev) if ev else (None, "UDP can't be tested from outside. It counts as proven once a VPN client connects from the internet.")
        elif not pip:
            r["outside"], r["why"] = None, "This server's public address couldn't be found"
        else:
            o = seen.get(r["port"])
            r["outside"] = o
            r["why"] = (f"{pip}:{r['port']} answered a connection from the internet" if o else
                        "No answer from the internet: the router or a firewall keeps it in" if o is False else "The outside test service didn't answer for this port")
    d["checked"] = int(time.time())
    d["summary"] = {"total": len(d["ports"]), "visible": sum(1 for r in d["ports"] if r["outside"] is True),
                    "hidden": sum(1 for r in d["ports"] if r["outside"] is False and not r["local_only"]),
                    "local": sum(1 for r in d["ports"] if r["local_only"]), "unknown": sum(1 for r in d["ports"] if r["outside"] is None),
                    "exposed": [r["port"] for r in d["ports"] if r["outside"] is True and r["private"]]}
    return d


def _evidence(port: int, proto: str) -> str | None:
    from . import ipsec, openvpn, wireguard
    for mod in (wireguard, openvpn, ipsec):
        try:
            e = mod.external_evidence(port, proto)
        except Exception:
            e = None
        if e:
            return e
    return None


def _nat_kind(router_wan: str | None, pip: str | None) -> str | None:
    """None (router holds the public IP), 'cgnat' (ISP-level NAT, 100.64/10), or
    'double' (router sits behind another router on a private network)."""
    if not router_wan or not pip or router_wan == pip:
        return None
    a = ipaddress.ip_address(router_wan)
    if a in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat"
    return "double" if a.is_private else "cgnat"


def check(port, proto: str = "tcp") -> dict:
    port, proto = _validate(port, proto)
    net = default_route()
    pip = public_ip()
    listen = _listener(port, proto)
    fw = _ufw(port, proto)
    upnp = _upnp()
    mapped = None
    if upnp.get("available"):
        mapped = next((m for m in upnp["mappings"] if m["proto"] == proto and m["external"] == port), None)
    router_wan = upnp.get("router_wan_ip") if upnp.get("available") else None
    nat = _nat_kind(router_wan, pip)
    upstream = None
    if nat == "double":
        # Best guess at the upstream router's admin address: .1 of its /24.
        upstream = str(ipaddress.ip_network(f"{router_wan}/24", strict=False).network_address + 1)
    if listen.get("listening") and not listen.get("process") and proto == "udp" and shutil.which("wg"):
        wg = subprocess.run(["wg", "show", "all", "listen-port"], capture_output=True, text=True).stdout
        if re.search(rf"\s{port}$", wg, re.M):
            listen["process"] = "wireguard (kernel)"

    external, method, temp, inner_hop = None, None, False, None
    if proto == "tcp" and pip:
        tl = None
        if not listen.get("listening"):
            try:
                tl = _TempListener(port)
                temp = True
            except OSError:
                tl = None
        try:
            external = _probe_tcp(pip, port)
            method = "Outside TCP probe (ifconfig.co / portchecker.io)"
            if nat == "double" and not external:
                # Hit our router's WAN side from inside: proves whether the
                # forward on *our* router works, so only the upstream one is left.
                try:
                    socket.create_connection((router_wan, port), timeout=4).close()
                    inner_hop = True
                except OSError:
                    inner_hop = False
        finally:
            if tl:
                tl.close()
    evidence = _evidence(port, proto)
    if evidence:
        external, method = True, "Live VPN client connected from the internet"

    # Verdict + what to do next
    P = proto.upper()
    steps = []
    if not listen.get("listening") and not temp:
        steps.append(f"Nothing on this Pi listens on {P} {port}. Start the service first.")
    if fw["active"] and not fw["allowed"]:
        steps.append(f"The Pi's firewall (ufw) is active and doesn't allow {port}/{proto}. "
                     f"Allow it in System → Firewall.")
    if external is not True:
        if nat == "cgnat":
            steps.append(f"Your ISP puts you behind carrier-grade NAT (router WAN {router_wan}). Port "
                         f"forwarding can't work from here — ask your ISP for a public IPv4 address, or "
                         f"use a tunnel/relay service.")
        elif nat == "double":
            steps.append(f"Double NAT: your router's internet side is {router_wan}, i.e. it sits behind "
                         f"another router (usually the ISP modem/gateway). Forward the port on BOTH:")
            steps.append(f"① On the upstream/ISP router (probably http://{upstream}/): forward {P} {port} "
                         f"→ {router_wan} port {port}. (Or put that box in bridge mode and skip this.)")
            ok2 = " ✔ Verified working — only ① is left." if inner_hop else \
                " ✖ Not working yet." if inner_hop is False else ""
            steps.append(f"② On your router (http://{net.get('gateway')}/): forward {P} {port} "
                         f"→ {net.get('ip') or 'this Pi'} port {port}.{ok2}")
        else:
            steps.append(f"On your router (http://{net.get('gateway')}/), forward {P} port {port} "
                         f"→ {net.get('ip') or 'this Pi'} port {port}.")
        steps.append(f"Give this Pi a fixed LAN address (DHCP reservation for {net.get('ip')}) so the "
                     f"forward keeps pointing at it.")
    if external is True:
        verdict = "open"
    elif external is False:
        verdict = "closed"
    else:
        verdict = "unverified"
    return {
        "port": port, "proto": proto, "verdict": verdict, "external": external, "method": method,
        "evidence": evidence, "temp_listener": temp, "public_ip": pip, "lan_ip": net.get("ip"),
        "gateway": net.get("gateway"), "iface": net.get("iface"), "listen": listen, "firewall": fw,
        "upnp": upnp, "upnp_mapping": mapped, "nat": nat, "upstream_router": upstream, "inner_hop": inner_hop, "steps": steps,
        "router_url": f"http://{net['gateway']}/" if net.get("gateway") else None,
    }


def _upnpc(args: list[str]) -> str:
    if not shutil.which("upnpc"):
        raise PortError("UPnP client (miniupnpc) is not installed")
    r = subprocess.run(["upnpc", *args], capture_output=True, text=True, timeout=20)
    return (r.stdout + r.stderr).strip()


def upnp_open(port, proto) -> dict:
    port, proto = _validate(port, proto)
    ip = default_route().get("ip")
    if not ip:
        raise PortError("No LAN address found")
    out = _upnpc(["-e", "AuroraPanel", "-a", ip, str(port), str(port), proto.upper(), "0"])
    if "is redirected to internal" not in out:
        raise PortError("Router refused the UPnP mapping (UPnP may be disabled): " + out[-300:])
    return {"ok": True, "output": out[-600:]}


def upnp_close(port, proto) -> dict:
    port, proto = _validate(port, proto)
    out = _upnpc(["-d", str(port), proto.upper()])
    return {"ok": True, "output": out[-600:]}


def install_upnp() -> jobs.Job:
    return jobs.launch("install miniupnpc", [*APT, "install", "miniupnpc"], env=APT_ENV)
