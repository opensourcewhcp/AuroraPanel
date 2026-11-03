"""Network management via NetworkManager (nmcli) — what Pi owners ask for most:
static IP / DHCP, DNS servers, Wi-Fi scan & connect, hotspot, hostname,
devices on the LAN and listening ports.

Changing the IP of the connection you're using would cut you off, so risky
changes use *confirm-or-revert*: the change is applied, and unless the browser
confirms from the new address within the timeout the old settings come back.
"""
from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from . import problems

IS_LINUX = platform.system() == "Linux"
_pending: dict = {}          # the one change awaiting confirmation
_plock = threading.Lock()
REVERT_AFTER = 120


class NetError(RuntimeError):
    pass


def _nm() -> str:
    p = shutil.which("nmcli")
    if not (IS_LINUX and p):
        raise NetError("NetworkManager (nmcli) is not available on this host")
    return p


def _run(argv, timeout=30):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return r


def _split(line: str) -> list[str]:
    """nmcli -t escapes ':' as '\\:'."""
    out, cur, esc = [], "", False
    for ch in line:
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def _nmt(*args, timeout=30) -> list[list[str]]:
    r = _run([_nm(), "-t", *args], timeout)
    if r.returncode != 0:
        raise NetError(r.stderr.strip() or "nmcli failed")
    return [_split(l) for l in r.stdout.splitlines() if l.strip()]


def _iface_for_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            if any(a.address == ip for a in addrs):
                return name
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    return None


# --------------------------------------------------------------------------- #
# Overview
# --------------------------------------------------------------------------- #
def overview(panel_host: str | None = None) -> dict:
    nm_ok = bool(IS_LINUX and shutil.which("nmcli"))
    panel_if = _iface_for_ip(panel_host)
    res = {"nm": nm_ok, "hostname": socket.gethostname(), "panel_iface": panel_if, "panel_ip": panel_host,
           "devices": [], "connections": [], "pending": pending_status(), "gateway": None, "dns": []}
    r = _run(["ip", "-4", "route", "show", "default"])
    m = re.search(r"default via (\S+) dev (\S+)", r.stdout)
    if m:
        res["gateway"] = {"ip": m.group(1), "device": m.group(2)}
    # systemd-resolved (Ubuntu) puts its 127.0.0.53 stub in /etc/resolv.conf; the real servers are here.
    for f in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            res["dns"] = [l.split()[1] for l in Path(f).read_text().splitlines() if l.startswith("nameserver") and len(l.split()) > 1]
        except OSError:
            continue
        if res["dns"]:
            break
    if not nm_ok:
        # Servers configured with netplan / systemd-networkd: show the interfaces read-only.
        for line in _run(["ip", "-br", "-4", "addr"]).stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] != "lo":
                name = parts[0].split("@")[0]
                res["devices"].append({"device": name, "type": "wifi" if Path(f"/sys/class/net/{name}/wireless").exists() else "ethernet",
                                       "state": "connected" if parts[1] in ("UP", "UNKNOWN") else parts[1].lower(),
                                       "connection": None, "addresses": parts[2:]})
        return res
    for d in _nmt("-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"):
        if len(d) >= 4 and d[1] not in ("loopback", "wifi-p2p"):
            res["devices"].append({"device": d[0], "type": d[1], "state": d[2], "connection": d[3] or None})
    for c in _nmt("-f", "NAME,UUID,TYPE,DEVICE,ACTIVE,AUTOCONNECT", "connection", "show"):
        if len(c) >= 6 and c[2] != "loopback":
            info = connection(c[1])
            res["connections"].append({"name": c[0], "uuid": c[1], "type": _ctype(c[2]), "device": c[3] or None,
                                       "active": c[4] == "yes", "autoconnect": c[5] == "yes", **info})
    return res


def _ctype(t: str) -> str:
    return {"802-11-wireless": "wifi", "802-3-ethernet": "ethernet"}.get(t, t)


def connection(uuid: str) -> dict:
    rows = _nmt("-f", "ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,IP4.ADDRESS,IP4.GATEWAY,IP4.DNS,802-11-wireless.ssid,802-11-wireless.mode",
                "connection", "show", uuid)
    kv = {}
    for r in rows:
        # -t with -f on a single connection gives "key:value" lines (value may contain escaped colons)
        if len(r) >= 2:
            kv.setdefault(r[0], []).append(":".join(r[1:]))
    g = lambda k: (kv.get(k) or [""])[0]
    live_addr = [v for k, vs in kv.items() if k.startswith("IP4.ADDRESS") for v in vs]
    live_dns = [v for k, vs in kv.items() if k.startswith("IP4.DNS") for v in vs]
    return {
        "method": g("ipv4.method") or "auto",
        "addresses": [a for a in g("ipv4.addresses").split(",") if a],
        "gateway_cfg": g("ipv4.gateway") or "",
        "dns_cfg": [d for d in g("ipv4.dns").split(",") if d],
        "live_addresses": live_addr, "live_gateway": g("IP4.GATEWAY") or "", "live_dns": live_dns,
        "ssid": g("802-11-wireless.ssid") or None, "mode": g("802-11-wireless.mode") or None,
    }


# --------------------------------------------------------------------------- #
# Confirm-or-revert
# --------------------------------------------------------------------------- #
def pending_status() -> dict | None:
    with _plock:
        if not _pending:
            return None
        return {"id": _pending["id"], "label": _pending["label"], "new_url": _pending.get("new_url"),
                "seconds_left": max(0, int(_pending["deadline"] - time.time()))}


def _arm(label: str, undo, new_url: str | None) -> dict:
    import secrets
    pid = secrets.token_urlsafe(16)   # doubles as the one-time confirm code
    if new_url:
        new_url = f"{new_url}?netconfirm={pid}"
    with _plock:
        if _pending:
            raise NetError("Another network change is waiting for confirmation")
        _pending.update(id=pid, label=label, undo=undo, deadline=time.time() + REVERT_AFTER, new_url=new_url)

    def watchdog():
        while True:
            time.sleep(2)
            with _plock:
                if _pending.get("id") != pid:
                    return
                if time.time() < _pending["deadline"]:
                    continue
                undo_fn = _pending["undo"]
                _pending.clear()
            try:
                undo_fn()
            except Exception as quiet_exc:
                problems.quiet(quiet_exc)
            return
    threading.Thread(target=watchdog, daemon=True).start()
    return pending_status()


def confirm(pid: str) -> dict:
    import hmac
    with _plock:
        if not _pending or not hmac.compare_digest(str(_pending.get("id")), str(pid or "")):
            raise NetError("Nothing to confirm (it may already have been reverted)")
        _pending.clear()
    return {"ok": True}


def revert_now(pid: str) -> dict:
    with _plock:
        if _pending.get("id") != pid:
            raise NetError("Nothing to revert")
        undo = _pending["undo"]
        _pending.clear()
    undo()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# IPv4 settings
# --------------------------------------------------------------------------- #
def _snapshot(uuid: str) -> list[str]:
    c = connection(uuid)
    return ["ipv4.method", c["method"], "ipv4.addresses", ",".join(c["addresses"]),
            "ipv4.gateway", c["gateway_cfg"], "ipv4.dns", ",".join(c["dns_cfg"])]


def set_ipv4(uuid: str, method: str, address: str = "", gateway: str = "", dns: list[str] | None = None,
             panel_host: str | None = None, panel_port: int = 8088) -> dict:
    nm = _nm()
    if method not in ("auto", "manual"):
        raise NetError("Method must be DHCP (auto) or static (manual)")
    dns = [d.strip() for d in (dns or []) if d.strip()]
    for d in dns:
        try:
            ipaddress.IPv4Address(d)
        except ValueError:
            raise NetError(f"Invalid DNS server: {d}")
    args = ["ipv4.method", method]
    new_ip = None
    if method == "manual":
        try:
            iface = ipaddress.IPv4Interface(address if "/" in address else address + "/24")
        except ValueError:
            raise NetError("Enter the address like 192.168.0.50/24")
        try:
            gw = ipaddress.IPv4Address(gateway)
        except ValueError:
            raise NetError("Enter a valid gateway (your router, e.g. 192.168.0.1)")
        if gw not in iface.network:
            raise NetError(f"Gateway {gw} isn't inside {iface.network}")
        if iface.ip in (iface.network.network_address, iface.network.broadcast_address):
            raise NetError("That address is the network/broadcast address")
        new_ip = str(iface.ip)
        args += ["ipv4.addresses", str(iface), "ipv4.gateway", str(gw)]
    else:
        args += ["ipv4.addresses", "", "ipv4.gateway", ""]
    args += ["ipv4.dns", ",".join(dns), "ipv4.ignore-auto-dns", "yes" if (dns and method == "auto") else "no"]
    before = _snapshot(uuid)
    conns = {c[1]: c for c in _nmt("-f", "NAME,UUID,TYPE,DEVICE,ACTIVE", "connection", "show")}
    if uuid not in conns:
        raise NetError("Unknown connection")
    dev = conns[uuid][3]
    affects_panel = bool(dev) and dev == _iface_for_ip(panel_host)
    r = _run([nm, "connection", "modify", uuid, *args])
    if r.returncode != 0:
        raise NetError(r.stderr.strip() or "nmcli modify failed")

    def apply():
        time.sleep(1.5)  # let the HTTP response reach the browser first
        _run([nm, "connection", "up", uuid], 60)

    def undo():
        _run([nm, "connection", "modify", uuid, *before, "ipv4.ignore-auto-dns", "no"])
        _run([nm, "connection", "up", uuid], 60)

    threading.Thread(target=apply, daemon=True).start()
    if affects_panel:
        url = f"http://{new_ip}:{panel_port}/" if new_ip else None
        return {"ok": True, "pending": _arm(f"IPv4 settings for {conns[uuid][0]}", undo, url)}
    return {"ok": True, "pending": None}


# --------------------------------------------------------------------------- #
# Wi-Fi
# --------------------------------------------------------------------------- #
def wifi_scan(rescan: bool = True) -> dict:
    nm = _nm()
    rows = _nmt("-f", "IN-USE,SSID,BSSID,SIGNAL,SECURITY,CHAN,FREQ,RATE", "device", "wifi", "list",
                "--rescan", "yes" if rescan else "no", timeout=45)
    nets = {}
    for r in rows:
        if len(r) < 8:
            continue
        # BSSID contains colons which nmcli escapes; _split already unescaped them
        inuse, ssid, bssid, signal, sec, chan, freq, rate = r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]
        if not ssid:
            continue
        cur = nets.get(ssid)
        s = int(signal or 0)
        if cur and cur["signal"] >= s and inuse != "*":
            continue
        nets[ssid] = {"ssid": ssid, "bssid": bssid, "signal": s, "security": sec or "open", "channel": chan,
                      "band": "5 GHz" if (freq or "").startswith("5") else "6 GHz" if (freq or "").startswith("6") else "2.4 GHz",
                      "rate": rate, "in_use": inuse == "*" or (cur or {}).get("in_use", False)}
    saved = {c[0] for c in _nmt("-f", "NAME,TYPE", "connection", "show") if len(c) > 1 and c[1] == "802-11-wireless"}
    wifi_devs = [d[0] for d in _nmt("-f", "DEVICE,TYPE", "device", "status") if len(d) > 1 and d[1] == "wifi"]
    radio = _run([nm, "radio", "wifi"]).stdout.strip()
    out = sorted(nets.values(), key=lambda n: (-n["in_use"], -n["signal"]))
    for n in out:
        n["saved"] = n["ssid"] in saved
    return {"networks": out, "devices": wifi_devs, "radio": radio}


def wifi_connect(ssid: str, password: str = "", device: str = "", hidden: bool = False,
                 panel_host: str | None = None, panel_port: int = 8088) -> dict:
    nm = _nm()
    if not ssid or len(ssid) > 32:
        raise NetError("Enter the network name (SSID)")
    if password and not 8 <= len(password) <= 63:
        raise NetError("Wi-Fi passwords are 8–63 characters")
    dev = device or next(iter(wifi_scan(False)["devices"]), "wlan0")
    previous = None
    for d in _nmt("-f", "DEVICE,CONNECTION", "device", "status"):
        if d[0] == dev and len(d) > 1 and d[1]:
            previous = d[1]
    affects_panel = dev == _iface_for_ip(panel_host)
    argv = [nm, "device", "wifi", "connect", ssid, "ifname", dev]
    if password:
        argv += ["password", password]
    if hidden:
        argv += ["hidden", "yes"]

    def work():
        time.sleep(1.5)
        r = _run(argv, 60)
        if r.returncode != 0 and previous:
            _run([nm, "connection", "up", previous], 60)  # fall back straight away

    if not affects_panel:
        r = _run(argv, 60)
        if r.returncode != 0:
            raise NetError(r.stderr.strip() or r.stdout.strip() or "Connection failed")
        return {"ok": True, "pending": None, "message": r.stdout.strip()}
    threading.Thread(target=work, daemon=True).start()

    def undo():
        if previous:
            _run([nm, "connection", "up", previous], 60)
    return {"ok": True, "pending": _arm(f"Switch {dev} to “{ssid}”", undo, None)}


def wifi_forget(name: str) -> dict:
    nm = _nm()
    active = {c[0] for c in _nmt("-f", "NAME,ACTIVE", "connection", "show") if len(c) > 1 and c[1] == "yes"}
    if name in active:
        raise NetError("That network is in use — connect to another one first")
    r = _run([nm, "connection", "delete", "id", name])
    if r.returncode != 0:
        raise NetError(r.stderr.strip() or "Couldn't forget network")
    return {"ok": True}


def wifi_radio(on: bool, panel_host: str | None = None) -> dict:
    nm = _nm()
    if not on:
        pif = _iface_for_ip(panel_host)
        if pif and pif.startswith("wl"):
            raise NetError("You're connected to the panel over Wi-Fi — turning Wi-Fi off would cut you off")
    _run([nm, "radio", "wifi", "on" if on else "off"])
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Hotspot
# --------------------------------------------------------------------------- #
HOTSPOT_NAME = "Aurora-Hotspot"


def hotspot_status() -> dict:
    try:
        rows = _nmt("-f", "NAME,DEVICE,ACTIVE", "connection", "show")
    except NetError:
        return {"active": False, "exists": False}
    row = next((r for r in rows if r[0] == HOTSPOT_NAME), None)
    info = {}
    if row:
        c = _nmt("-s", "-f", "802-11-wireless.ssid,802-11-wireless.band,IP4.ADDRESS", "connection", "show", HOTSPOT_NAME)
        info = {r[0]: ":".join(r[1:]) for r in c if len(r) >= 2}
    return {"exists": bool(row), "active": bool(row and row[2] == "yes"), "device": row[1] if row else None,
            "ssid": info.get("802-11-wireless.ssid"), "band": info.get("802-11-wireless.band"),
            "address": next((v for k, v in info.items() if k.startswith("IP4.ADDRESS")), None)}


def hotspot_start(ssid: str, password: str, device: str = "wlan0", band: str = "bg", panel_host: str | None = None) -> dict:
    nm = _nm()
    if not 1 <= len(ssid or "") <= 32:
        raise NetError("Hotspot name must be 1–32 characters")
    if not 8 <= len(password or "") <= 63:
        raise NetError("Hotspot password must be 8–63 characters")
    if band not in ("bg", "a"):
        raise NetError("Band must be 2.4 GHz or 5 GHz")
    if device == _iface_for_ip(panel_host):
        raise NetError(f"You're reaching the panel through {device}. Turning it into a hotspot would disconnect you — "
                       "connect the Pi by Ethernet first (or use a second USB Wi-Fi adapter).")
    _run([nm, "connection", "delete", "id", HOTSPOT_NAME])
    r = _run([nm, "device", "wifi", "hotspot", "ifname", device, "con-name", HOTSPOT_NAME,
              "ssid", ssid, "password", password, "band", band], 60)
    if r.returncode != 0:
        raise NetError(r.stderr.strip() or "Couldn't start hotspot")
    _run([nm, "connection", "modify", HOTSPOT_NAME, "connection.autoconnect", "no"])
    return hotspot_status()


def hotspot_stop() -> dict:
    nm = _nm()
    _run([nm, "connection", "down", "id", HOTSPOT_NAME])
    return hotspot_status()


# --------------------------------------------------------------------------- #
# Hostname, neighbours, ports
# --------------------------------------------------------------------------- #
def set_hostname(name: str) -> dict:
    name = (name or "").strip().lower()
    if not re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", name):
        raise NetError("Hostname: letters, digits and hyphens (1–63), no dots")
    old = socket.gethostname()
    r = _run(["hostnamectl", "set-hostname", name])
    if r.returncode != 0:
        raise NetError(r.stderr.strip() or "hostnamectl failed")
    hosts = Path("/etc/hosts")
    try:
        text = hosts.read_text()
        if re.search(r"(?m)^127\.0\.1\.1\s", text):
            text = re.sub(r"(?m)^127\.0\.1\.1\s.*$", f"127.0.1.1\t{name}", text)
        else:
            text += f"\n127.0.1.1\t{name}\n"
        hosts.write_text(text)
    except OSError:
        pass
    _run(["systemctl", "restart", "avahi-daemon"])
    return {"ok": True, "old": old, "hostname": name, "mdns": f"{name}.local"}


_OUI = {  # a handful of very common vendors, enough to make the list friendlier
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi", "d8:3a:dd": "Raspberry Pi",
    "2c:cf:67": "Raspberry Pi", "28:cd:c1": "Raspberry Pi", "3c:22:fb": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple",
    "ac:bc:32": "Apple", "00:17:88": "Philips Hue", "18:b4:30": "Nest", "f4:f5:d8": "Google", "44:07:0b": "Google",
    "fc:65:de": "Amazon", "68:54:fd": "Amazon", "b4:e9:b8": "Dell", "00:1a:11": "Google", "50:c7:bf": "TP-Link",
}


def neighbours(resolve: bool = True) -> dict:
    r = _run(["ip", "neigh", "show"])
    out = []
    for line in r.stdout.splitlines():
        m = re.match(r"(\S+) dev (\S+)(?: lladdr (\S+))?.*?(\S+)$", line.strip())
        if not m or ":" in m.group(1) and not m.group(3):
            continue
        ip, dev, mac, st = m.group(1), m.group(2), m.group(3), m.group(4)
        if "." not in ip or st == "FAILED" or not mac:
            continue
        host = None
        if resolve:
            try:
                socket.setdefaulttimeout(0.4)
                host = socket.gethostbyaddr(ip)[0]
            except OSError:
                host = None
            finally:
                socket.setdefaulttimeout(None)
        local_admin = int(mac.split(":")[0], 16) & 2
        out.append({"ip": ip, "mac": mac, "device": dev, "state": st.lower(), "hostname": host,
                    "vendor": _OUI.get(mac[:8].lower()) or ("private / randomised MAC" if local_admin else None)})
    out.sort(key=lambda d: tuple(int(p) for p in d["ip"].split(".")))
    return {"devices": out}


def ports() -> dict:
    r = _run(["ss", "-tulpnH"])
    out, seen = [], set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, state, local = parts[0], parts[1], parts[4]
        if proto == "tcp" and state != "LISTEN":
            continue
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%")[0]
        m = re.search(r'users:\(\("([^"]+)"', line)
        proc = m.group(1) if m else "?"
        key = (proto, port, proc, addr in ("0.0.0.0", "*", "::"))
        if key in seen:
            continue
        seen.add(key)
        scope = "all interfaces" if addr in ("0.0.0.0", "*", "::") else "this machine only" if addr.startswith("127.") or addr == "::1" else addr
        out.append({"proto": proto, "port": int(port) if port.isdigit() else port, "process": proc, "address": addr, "scope": scope})
    out.sort(key=lambda p: (p["port"] if isinstance(p["port"], int) else 99999, p["proto"]))
    return {"ports": out}
