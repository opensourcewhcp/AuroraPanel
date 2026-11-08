"""Servers — every AuroraPanel you run, on one page.

Add another server with its address and an API token made there (Security → Manage API Tokens).
The panel then shows each server's health (CPU, memory, disk, alerts, updates, failed services) and
can act on all of them at once — e.g. ban an attacker on every server.

The other server's HTTPS certificate is pinned the first time it's added (its SHA-256 fingerprint):
self-signed certificates work, and a certificate that changes later is refused until you confirm it.
Plain http:// is only accepted for addresses on your own network.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import os
import secrets
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit
from . import problems

STATE = Path("/var/lib/aurora/servers.json")


class ServerError(RuntimeError):
    pass


class _PlainHttp(ServerError):
    """The other panel answered plain HTTP on a https:// connection: Panel HTTPS is off there."""


class _MovedToHttps(ServerError):
    """The other panel redirected a http:// request to https://: Panel HTTPS is on there now."""

    def __init__(self, url: str):
        super().__init__(url)
        self.url = url


def _speaks_plain_http(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            return s.recv(5) == b"HTTP/"
    except OSError:
        return False


def _load() -> dict:
    try:
        d = json.loads(STATE.read_text())
    except (OSError, ValueError):
        d = {}
    d.setdefault("servers", [])
    return d


def _save(d: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_name(f".{STATE.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(d, indent=1))
    os.chmod(tmp, 0o600)  # API tokens of the other servers
    tmp.replace(STATE)


def _parse(url: str) -> tuple[str, str, int]:
    u = urlsplit(url.strip() if "://" in url else "https://" + url.strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ServerError("Enter the panel's address, e.g. https://192.168.0.100:8088")
    port = u.port or (8088)
    if u.scheme == "http":
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
        except (OSError, ValueError):
            raise ServerError(f"Can't find {u.hostname}")
        if not (ip.is_private or ip.is_loopback):
            raise ServerError("Plain http:// would send the token unencrypted over the internet — use https://")
    return u.scheme, u.hostname, port


def _request(srv: dict, method: str, path: str, body: dict | None = None, timeout: float = 8.0, pin: str | None = None):
    """(status, json) from another panel; checks the pinned certificate fingerprint."""
    scheme, host, port = _parse(srv["url"])
    if scheme == "https":
        ctx = ssl._create_unverified_context()  # identity is checked by the pinned fingerprint below
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        try:
            conn.connect()
        except ssl.SSLError as e:
            if _speaks_plain_http(host, port, timeout):
                raise _PlainHttp(f"{srv.get('name', host)} answers plain HTTP, so Panel HTTPS is off there") from e
            raise
        fp = ""
        if scheme == "https":
            der = conn.sock.getpeercert(binary_form=True)
            fp = hashlib.sha256(der).hexdigest()
            want = pin if pin is not None else srv.get("fingerprint", "")
            if want and fp != want:
                raise ServerError(f"{srv.get('name', host)}'s certificate changed — if you renewed it, re-confirm the server; otherwise someone may be in between")
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": f"Bearer {srv['token']}", "User-Agent": "AuroraPanel-servers"}  # http.client adds Host
        if data is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        if scheme == "http" and r.status in (301, 302, 307, 308):
            loc = urlsplit(r.getheader("Location") or "")
            if loc.scheme == "https" and loc.hostname == host and (loc.port or 443) == port:
                raise _MovedToHttps(f"https://{host}:{port}")
        raw = r.read(4_000_000)
        try:
            payload = json.loads(raw or b"null")
        except ValueError:
            payload = {"detail": raw[:200].decode(errors="replace")}
        return r.status, payload, fp
    except (OSError, http.client.HTTPException, ssl.SSLError) as e:
        raise ServerError(f"Can't reach {srv.get('name', host)}: {e}")
    finally:
        conn.close()


def _call(srv: dict, method: str, path: str, body: dict | None = None, timeout: float = 8.0):
    """_request for a saved server. One that has turned Panel HTTPS on since is followed to https://
    (its certificate is remembered then, and srv["_moved"] tells the caller to save it). One that has
    turned it off is not followed back to plain http: that is what someone in between would do."""
    try:
        return _request(srv, method, path, body, timeout)
    except _MovedToHttps as m:
        srv["url"] = m.url
        status, payload, fp = _request(srv, method, path, body, timeout, pin="")
        srv["fingerprint"], srv["_moved"] = fp, True
        return status, payload, fp
    except _PlainHttp:
        raise ServerError(f"{srv.get('name', '')} answers plain HTTP now. Turn Panel HTTPS back on there (Security → Panel HTTPS), "
                          "or, on your own network, remove it here and add it again")


def _save_moved(servers: list[dict]) -> None:
    moved = {s["id"]: s for s in servers if s.pop("_moved", False)}
    if moved:
        d = _load()
        for s in d["servers"]:
            if s["id"] in moved:
                s["url"], s["fingerprint"] = moved[s["id"]]["url"], moved[s["id"]]["fingerprint"]
        _save(d)


def add(name: str, url: str, token: str) -> dict:
    token = (token or "").strip()
    if not token.startswith("aur_"):
        raise ServerError("Paste an API token made on that server (Security → Manage API Tokens) — it starts with aur_")
    scheme, host, port = _parse(url)
    srv = {"id": secrets.token_hex(4), "name": (name or host).strip()[:60], "url": f"{scheme}://{host}:{port}", "token": token, "added": int(time.time())}
    try:
        status, payload, fp = _request(srv, "GET", "/api/fleet/self", pin="")
    except _MovedToHttps as m:
        srv["url"] = m.url
        status, payload, fp = _request(srv, "GET", "/api/fleet/self", pin="")
    except _PlainHttp:
        # Panels installed before HTTPS was the default keep plain http after updates. On your own network that's allowed.
        try:
            _parse(f"http://{host}:{port}")
        except ServerError:
            raise ServerError(f"{host} answers plain HTTP. Turn on HTTPS there (Security → Panel HTTPS) and add it again: "
                              "the token mustn't cross the internet unencrypted")
        srv["url"] = f"http://{host}:{port}"
        status, payload, fp = _request(srv, "GET", "/api/fleet/self", pin="")
    if status == 401:
        raise ServerError("That server didn't accept the token")
    if status != 200:
        raise ServerError(f"{host} answered {status}: {payload.get('detail', '') if isinstance(payload, dict) else ''} — is it AuroraPanel 1.1.1 or newer?")
    srv["fingerprint"] = fp
    srv["hostname"] = payload.get("hostname", "")
    d = _load()
    if any(s["url"] == srv["url"] for s in d["servers"]):
        raise ServerError("That server is already in the list")
    d["servers"].append(srv)
    _save(d)
    return _public(srv)


def remove(sid: str) -> dict:
    d = _load()
    d["servers"] = [s for s in d["servers"] if s["id"] != sid]
    _save(d)
    return {"ok": True}


def repin(sid: str) -> dict:
    """Accept a server's new certificate (after a renewal)."""
    d = _load()
    srv = next((s for s in d["servers"] if s["id"] == sid), None)
    if not srv:
        raise ServerError("Unknown server")
    try:
        status, payload, fp = _request(srv, "GET", "/api/fleet/self", pin="")
    except _MovedToHttps as m:
        srv["url"] = m.url
        status, payload, fp = _request(srv, "GET", "/api/fleet/self", pin="")
    if status != 200:
        raise ServerError(f"It answered {status}")
    srv["fingerprint"] = fp
    _save(d)
    return {"ok": True, "fingerprint": fp}


def _public(s: dict) -> dict:
    return {k: s[k] for k in ("id", "name", "url", "added", "hostname") if k in s} | {"fingerprint": s.get("fingerprint", "")[:16],
                                                                                    "secure": s.get("url", "").startswith("https://")}


def self_summary() -> dict:
    """This server's health in one small JSON (what other panels show for it)."""
    import psutil
    from . import version
    out = {"hostname": socket.getfqdn() or socket.gethostname(), "version": version.VERSION, "time": int(time.time())}
    try:
        vm = psutil.virtual_memory()
        du = psutil.disk_usage("/")
        out.update(cpu=psutil.cpu_percent(interval=0.3), cpus=psutil.cpu_count(), mem_pct=vm.percent, mem_total=vm.total,
                   disk_pct=du.percent, disk_total=du.total, uptime=int(time.time() - psutil.boot_time()), load=os.getloadavg()[0])
        temps = psutil.sensors_temperatures() if hasattr(psutil, "sensors_temperatures") else {}
        for k in ("cpu_thermal", "coretemp", "k10temp"):
            if temps.get(k):
                out["temp"] = round(temps[k][0].current)
                break
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    try:
        from . import system_info
        out["pi"] = system_info.is_pi()
        out["model"] = Path("/proc/device-tree/model").read_text().strip("\x00").strip() if Path("/proc/device-tree/model").exists() else ""
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    try:
        from . import alerts
        a = alerts.load()["active"]
        out["alerts"] = sorted(({"level": x["level"], "title": x["title"]} for x in a.values()), key=lambda x: {"critical": 0, "warning": 1}.get(x["level"], 2))[:5]
    except Exception:
        out["alerts"] = []
    try:
        from . import updates
        u = updates.cached()
        out["updates"] = {"total": u.get("total", 0), "security": u.get("security", 0), "reboot": Path("/var/run/reboot-required").exists()}
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    try:
        import subprocess
        r = subprocess.run(["systemctl", "--failed", "--no-legend", "--plain"], capture_output=True, text=True, timeout=10)
        out["failed_units"] = [l.split()[0] for l in r.stdout.splitlines() if l.strip()][:8]
    except Exception:
        out["failed_units"] = []
    try:
        out["services"] = service_counts()
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    try:
        from . import guard
        g = guard.listing()
        out["bans"] = len(g["bans"]) + len(g["fail2ban"])
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    return out


# The services a server card shows by kind, with an icon each (frontend/js/ops.js).
_KINDS = [
    ("web", "Web", re.compile(r"^(apache2|httpd|nginx|caddy|lighttpd)\.service$")),
    ("php", "PHP", re.compile(r"^php[\d.]*-fpm\.service$")),
    ("db", "Database", re.compile(r"^(mariadb|mysql|mysqld|postgresql(@.+)?|redis(-server)?|mongod)\.service$")),
    ("mail", "Mail", re.compile(r"^(postfix|dovecot|exim4|opendkim|rspamd)\.service$")),
    ("dns", "DNS", re.compile(r"^(bind9|named|pdns|unbound|pihole-FTL|dnsmasq)\.service$")),
    ("ssh", "SSH", re.compile(r"^(ssh|sshd)\.service$")),
    ("docker", "Docker", re.compile(r"^(docker|containerd|podman)\.service$")),
    ("vpn", "VPN", re.compile(r"^(wg-quick@.+|openvpn(@.+)?|openvpn-server@.+)\.service$")),
    ("security", "Security", re.compile(r"^(fail2ban|crowdsec|clamav-daemon|ufw|firewalld)\.service$")),
]


def service_counts() -> dict:
    """How many services run and how many failed, plus the well-known ones grouped by kind."""
    from . import services as svc
    rows = [r for r in svc.list_services() if r.get("load") == "loaded"]
    kinds = []
    for key, label, rx in _KINDS:
        mine = [r for r in rows if rx.match(r["unit"])]
        if mine:
            kinds.append({"key": key, "label": label, "up": sum(r["active"] == "active" for r in mine),
                          "down": [r["unit"] for r in mine if r["active"] == "failed"][:5], "units": [r["unit"] for r in mine][:8]})
    return {"running": sum(r.get("sub") == "running" for r in rows), "failed": sum(r["active"] == "failed" for r in rows),
            "total": len(rows), "kinds": kinds}


def _controllable(sid: str) -> dict:
    d = _load()
    srv = next((x for x in d["servers"] if x["id"] == sid), None)
    if not srv:
        raise ServerError("That server isn't in the list")
    if not srv["url"].startswith("https://"):
        raise ServerError(f"{srv['name']} is reached over plain http, so it can be watched but not controlled. "
                          "Turn on Panel HTTPS there (Security → Panel HTTPS) first.")
    return srv


def _answer(srv: dict, status: int, payload) -> dict:
    if status == 200:
        return {"ok": True, **(payload or {})}
    if status in (404, 405):
        raise ServerError(f"{srv['name']} needs AuroraPanel 1.2.3 or newer for this. Update it first.")
    if status == 401:
        raise ServerError(f"{srv['name']} didn't accept the token (revoked or expired?)")
    detail = (payload or {}).get("detail") if isinstance(payload, dict) else ""
    raise ServerError(f"{srv['name']}: {detail or f'answered {status}'}")


def run(sid: str, command: str, by: str) -> dict:
    """Run one command on an added server (its token must be full admin) and bring back the output."""
    command = (command or "").strip()
    if not command or len(command) > 4000:
        raise ServerError("Type a command (at most 4000 characters)")
    srv = _controllable(sid)
    status, payload, _ = _call(srv, "POST", "/api/fleet/exec", {"command": command, "by": f"{by} on {socket.gethostname()}"}, timeout=140)
    _save_moved([srv])
    return _answer(srv, status, payload)


def act(sid: str, action: str, unit: str, by: str) -> dict:
    """Restart or start a service, or install updates, on an added server. Its token decides whether that's allowed;
    a server reached over plain http is only watched, never told what to do."""
    if action not in ("restart_service", "start_service", "install_updates"):
        raise ServerError("Unknown action")
    srv = _controllable(sid)
    status, payload, _ = _call(srv, "POST", "/api/fleet/action", {"action": action, "unit": unit, "by": f"{by} on {socket.gethostname()}"}, timeout=30)
    _save_moved([srv])
    return _answer(srv, status, payload)


def overview() -> dict:
    d = _load()
    me = {"id": "", "name": "This server", **self_summary(), "ok": True, "local": True}

    def one(srv):
        t0 = time.time()
        try:
            status, payload, _ = _call(srv, "GET", "/api/fleet/self", timeout=6)
            if status != 200:
                return {**_public(srv), "ok": False, "error": f"answered {status}" + (" (token revoked?)" if status == 401 else "")}
            return {**_public(srv), **payload, "ok": True, "ms": int((time.time() - t0) * 1000)}
        except ServerError as e:
            return {**_public(srv), "ok": False, "error": str(e)}

    with ThreadPoolExecutor(max_workers=8) as ex:
        others = list(ex.map(one, d["servers"]))
    _save_moved(d["servers"])
    return {"servers": [me] + others}


def ban_everywhere(ip: str, reason: str, duration: int | None) -> dict:
    """Ban on every added server (this one is done by the caller)."""
    res = {}

    def one(srv):
        try:
            status, payload, _ = _call(srv, "POST", "/api/guard/ban", {"target": ip, "reason": reason, "duration": duration, "source": "Servers · ban everywhere"})
            return srv["name"], {"ok": status == 200, "error": "" if status == 200 else (payload or {}).get("detail", f"HTTP {status}")}
        except ServerError as e:
            return srv["name"], {"ok": False, "error": str(e)}

    saved = _load()["servers"]
    with ThreadPoolExecutor(max_workers=8) as ex:
        for name, r in ex.map(one, saved):
            res[name] = r
    _save_moved(saved)
    return res


def unban_everywhere(ip: str) -> dict:
    res = {}

    def one(srv):
        try:
            status, payload, _ = _call(srv, "POST", "/api/guard/unban", {"target": ip})
            return srv["name"], {"ok": status == 200, "error": "" if status == 200 else (payload or {}).get("detail", f"HTTP {status}")}
        except ServerError as e:
            return srv["name"], {"ok": False, "error": str(e)}

    saved = _load()["servers"]
    with ThreadPoolExecutor(max_workers=8) as ex:
        for name, r in ex.map(one, saved):
            res[name] = r
    _save_moved(saved)
    return res


def count() -> int:
    return len(_load()["servers"])
