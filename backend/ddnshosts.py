"""Dynamic DNS hosts — cPanel-style: home.example.com follows a changing IP.

Each host is an A (or AAAA) record with a short TTL in a zone this server serves, plus a secret
update URL. Whatever calls the URL (a router, a cron job with curl, a Pi at home) moves the record
to the caller's IP, or to ?ip=. The answers are dyndns2-style ("good 1.2.3.4", "nochg 1.2.3.4",
"badauth") so routers with a "custom DynDNS" option understand them; /nic/update with
username = hostname and password = key works too.

The update URL is served by the panel and, when Apache runs, also at http(s)://<domain>/ddns/update
through a small Apache proxy, because routers usually can't use port 8088 or a self-signed cert.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path

from . import distro
from . import dnszones

STATE = Path("/var/lib/aurora/ddns-hosts.json")
APACHE = Path("/etc/apache2/conf-available/zz-aurora-ddns.conf")
TTL = 60
MIN_INTERVAL = 30  # seconds between record changes for one host (a router stuck in a loop)
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")
_lock = threading.Lock()


class DdnsError(RuntimeError):
    pass


def _load() -> dict:
    try:
        d = json.loads(STATE.read_text())
    except (OSError, ValueError):
        d = {}
    d.setdefault("hosts", [])
    return d


def _save(d: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_name(f".{STATE.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(d, indent=1))
    os.chmod(tmp, 0o600)  # holds the update keys
    tmp.replace(STATE)


def _public(h: dict) -> dict:
    return {k: v for k, v in h.items() if k != "key"} | {"key_hint": h["key"][:4] + "…"}


def _zones() -> list[str]:
    if not dnszones.ZONE_DIR.exists():
        return []
    return sorted(p.name[3:] for p in dnszones.ZONE_DIR.glob("db.*")
                  if p.is_file() and dnszones._DOMAIN.match(p.name[3:]))


_cert_cache: tuple[float, list[str]] = (0.0, [])


def _trusted_names() -> list[str]:
    """Names covered by a Let's Encrypt certificate on this server (routers reject self-signed ones)."""
    global _cert_cache
    if time.time() - _cert_cache[0] < 300:
        return _cert_cache[1]
    names: list[str] = []
    live = Path("/etc/letsencrypt/live")
    if live.is_dir():
        for d in live.iterdir():
            pem = d / "cert.pem"
            if not pem.exists():
                continue
            r = subprocess.run(["openssl", "x509", "-noout", "-checkend", "0", "-ext", "subjectAltName", "-in", str(pem)],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                names += [n.lower() for n in re.findall(r"DNS:([^,\s]+)", r.stdout)]
    _cert_cache = (time.time(), names)
    return names


def update_base(domain: str) -> str:
    """Where routers should send updates for names in domain: a host with a trusted certificate."""
    names = _trusted_names()
    if domain in names or f"*.{domain}" in names:
        return f"https://{domain}"
    same = sorted((n for n in names if n.endswith("." + domain) and not n.startswith("*")), key=len)
    if same:
        return f"https://{same[0]}"
    if names:
        return f"https://{sorted((n for n in names if not n.startswith('*')), key=len)[0]}"
    return f"http://{domain}"


def listing() -> dict:
    d = _load()
    doms = _zones()
    return {"hosts": [_public(h) for h in d["hosts"]], "domains": doms, "proxy": APACHE.exists(),
            "bases": {x: update_base(x) for x in doms}}


def _fam(ip: str) -> str:
    return "AAAA" if ipaddress.ip_address(ip).version == 6 else "A"


def _clean_ip(ip: str) -> str:
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise DdnsError(f"“{ip}” isn't an IP address")
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    if a.is_unspecified or a.is_multicast or a.is_loopback:
        raise DdnsError(f"{a} can't be used as a host address")
    return str(a)


def _set_record(h: dict, ip: str) -> None:
    """Point h's name at ip: replace its A/AAAA records of that family, keep the other family."""
    fam = _fam(ip)
    z = dnszones._load(h["domain"])
    name = h["host"] + "."
    clash = [r for r in z["records"] if r["name"] == name and r["type"] not in ("A", "AAAA", "TXT")]
    if clash:
        raise DdnsError(f"{h['host']} already has a {clash[0]['type']} record — remove it in the Zone Editor first")
    z["records"] = [r for r in z["records"] if not (r["name"] == name and r["type"] == fam)]
    z["records"].append(dnszones.clean_record({"type": fam, "name": name, "address": ip, "ttl": TTL}, h["domain"]))
    dnszones._write(h["domain"], z)


def create(domain: str, prefix: str, ip: str, description: str = "") -> dict:
    domain = dnszones._dom(domain)
    if domain not in _zones():
        raise DdnsError(f"{domain} has no zone on this server — create one in the Zone Editor first")
    prefix = (prefix or "").strip().lower().rstrip(".")
    if prefix.endswith("." + domain):
        prefix = prefix[: -len(domain) - 1]
    if not _LABEL.match(prefix):
        raise DdnsError("The subdomain may use letters, digits and hyphens (e.g. home or office.vpn)")
    host = f"{prefix}.{domain}"
    with _lock:
        d = _load()
        if any(h["host"] == host for h in d["hosts"]):
            raise DdnsError(f"{host} is already a Dynamic DNS host")
        h = {"id": secrets.token_hex(6), "host": host, "domain": domain, "description": (description or "").strip()[:200],
             "key": secrets.token_urlsafe(24), "created": int(time.time()), "ip": "", "ip6": "",
             "updated": 0, "updates": 0, "last_from": "", "last_result": ""}
        if ip:
            ip = _clean_ip(ip)
            _set_record(h, ip)
            h["ip6" if _fam(ip) == "AAAA" else "ip"] = ip
            h["updated"] = int(time.time())
            h["last_result"] = f"good {ip} (set when created)"
        d["hosts"].append(h)
        _save(d)
    ensure_proxy()
    return {**_public(h), "key": h["key"]}


def _find(d: dict, hid: str) -> dict:
    for h in d["hosts"]:
        if h["id"] == hid:
            return h
    raise DdnsError("No such Dynamic DNS host")


def reveal(hid: str) -> dict:
    h = _find(_load(), hid)
    return {"id": hid, "host": h["host"], "key": h["key"]}


def update_meta(hid: str, description: str | None = None) -> dict:
    with _lock:
        d = _load()
        h = _find(d, hid)
        if description is not None:
            h["description"] = description.strip()[:200]
        _save(d)
    return _public(h)


def regenerate(hid: str) -> dict:
    with _lock:
        d = _load()
        h = _find(d, hid)
        h["key"] = secrets.token_urlsafe(24)
        _save(d)
    return {"id": hid, "host": h["host"], "key": h["key"]}


def delete(hid: str, remove_record: bool = True) -> dict:
    with _lock:
        d = _load()
        h = _find(d, hid)
        if remove_record:
            try:
                z = dnszones._load(h["domain"])
                z["records"] = [r for r in z["records"] if not (r["name"] == h["host"] + "." and r["type"] in ("A", "AAAA"))]
                dnszones._write(h["domain"], z)
            except dnszones.ZoneError:
                pass
        d["hosts"] = [x for x in d["hosts"] if x["id"] != hid]
        _save(d)
    return {"ok": True}


def set_ip(hid: str, ip: str) -> dict:
    """Manual change from the panel."""
    with _lock:
        d = _load()
        h = _find(d, hid)
        ip = _clean_ip(ip)
        _set_record(h, ip)
        h["ip6" if _fam(ip) == "AAAA" else "ip"] = ip
        h.update(updated=int(time.time()), last_result=f"good {ip} (set in the panel)")
        _save(d)
    return _public(h)


def remote_update(key: str, ip: str, caller: str, hostname: str = "") -> str:
    """The public update call. Returns a dyndns2 answer line."""
    if not key:
        return "badauth"
    with _lock:
        d = _load()
        h = next((x for x in d["hosts"] if hmac.compare_digest(x["key"].encode(), key.encode())), None)
        if not h:
            return "badauth"
        if hostname and hostname.lower().rstrip(".") != h["host"]:
            return "nohost"
        try:
            ip = _clean_ip(ip or caller)
        except DdnsError:
            return "badip"
        field = "ip6" if _fam(ip) == "AAAA" else "ip"
        now = int(time.time())
        h["last_from"] = caller
        if h.get(field) == ip:
            h["last_result"] = f"nochg {ip}"
            h["checked"] = now
            _save(d)
            return f"nochg {ip}"
        if now - h.get("updated_" + field, 0) < MIN_INTERVAL:
            return "abuse"
        try:
            _set_record(h, ip)
        except (DdnsError, dnszones.ZoneError) as e:
            h["last_result"] = f"911 {e}"[:200]
            _save(d)
            return "911"
        h[field] = ip
        h["updated_" + field] = now
        h.update(updated=now, checked=now, updates=h.get("updates", 0) + 1, last_result=f"good {ip}")
        _save(d)
        return f"good {ip}"


# ---- Apache proxy: http(s)://<any site>/ddns/update → the panel ----
def _panel_target() -> str:
    from . import panelhttps
    https = panelhttps._dropin_paths() is not None
    return f"{'https' if https else 'http'}://127.0.0.1:{panelhttps._port()}"


def render_proxy(target: str) -> str:
    tls = target.startswith("https")
    lines = ["# Written by AuroraPanel (Domains → Dynamic DNS): the update URL on ports 80/443.",
             '<Location "/ddns/update">', f"    ProxyPass {target}/ddns/update retry=0", "</Location>",
             '<Location "/nic/update">', f"    ProxyPass {target}/nic/update retry=0", "</Location>"]
    if tls:
        # The panel's certificate is for its hostname (or self-signed); this hop never leaves the machine.
        lines += [f'<Proxy "{target}/">', "    SSLProxyEngine on", "    SSLProxyVerify none",
                  "    SSLProxyCheckPeerName off", "    SSLProxyCheckPeerExpire off", "</Proxy>"]
    return "\n".join(lines) + "\n"


def ensure_proxy() -> bool:
    if not Path("/etc/apache2/conf-available").exists() or not _load()["hosts"]:
        return False
    text = render_proxy(_panel_target())
    if APACHE.exists() and APACHE.read_text() == text:
        return True
    old = APACHE.read_text() if APACHE.exists() else None
    APACHE.write_text(text)
    env = {**os.environ, "PATH": distro.PATH}
    mods = ["proxy", "proxy_http"] + (["ssl"] if "SSLProxyEngine" in text else [])
    subprocess.run(["a2enmod", "-q", *mods], capture_output=True, env=env, timeout=30)
    subprocess.run(["a2enconf", "-q", "zz-aurora-ddns"], capture_output=True, env=env, timeout=30)
    t = subprocess.run(["apache2ctl", "configtest"], capture_output=True, text=True, env=env, timeout=30)
    if t.returncode != 0:
        if old is None:
            subprocess.run(["a2disconf", "-q", "zz-aurora-ddns"], capture_output=True, env=env, timeout=30)
            APACHE.unlink(missing_ok=True)
        else:
            APACHE.write_text(old)
        return False
    subprocess.run(["systemctl", "reload", "apache2"], capture_output=True, env=env, timeout=30)
    return True
