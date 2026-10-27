"""Reverse proxies: expose a local service (any host:port) at a domain over HTTPS.

A thin layer over sites.py. It writes an ordinary Apache vhost whose body is a ProxyPass block plus a
marker comment, so these show up as their own list, separate from document-root websites, and the WAF,
IP bans and AutoSSL all apply to them like any other site. New proxies start on a self-signed
certificate (always works); you upgrade to a real Let's Encrypt one from the site's HTTPS section once
the name points here, just like the Docker reverse-proxy apps do.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import sites

MARKER = "# aurora-reverse-proxy"
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


class ProxyError(RuntimeError):
    pass


def _target_url(target: str) -> str:
    """Normalise a user target into a scheme://host:port URL. Accepts '3000', 'localhost:3000', a host:port,
    or a full http(s):// URL. A bare port or host defaults to the loopback over http."""
    t = (target or "").strip()
    if not t:
        raise ProxyError("Enter where to forward to, for example 3000, localhost:3000 or http://127.0.0.1:3000")
    if t.isdigit():
        if not (1 <= int(t) <= 65535):
            raise ProxyError("That port is out of range")
        return f"http://127.0.0.1:{t}"
    if not re.match(r"^https?://", t):
        t = "http://" + t
    m = re.match(r"^(https?)://([^/:\s]+)(?::(\d+))?/?$", t)
    if not m:
        raise ProxyError("That target doesn't look right. Use a port, host:port, or a full http(s):// URL")
    scheme, host, port = m.group(1), m.group(2), m.group(3)
    if port and not (1 <= int(port) <= 65535):
        raise ProxyError("That port is out of range")
    return f"{scheme}://{host}" + (f":{port}" if port else "")


def _custom(target: str, websockets: bool) -> str:
    lines = ["ProxyPreserveHost On", "ProxyPass /.well-known/acme-challenge/ !"]
    if target.startswith("https://"):
        lines.append("SSLProxyEngine On")
    ws = " upgrade=websocket" if websockets else ""
    lines += [
        f"ProxyPass / {target}/{ws} timeout=3600",
        f"ProxyPassReverse / {target}/",
        'RequestHeader set X-Forwarded-Proto "expr=%{REQUEST_SCHEME}"',
        f"{MARKER} target={target} ws={'1' if websockets else '0'}",
    ]
    return "\n".join(lines)


def _parse(custom: str) -> dict:
    m = re.search(r"# aurora-reverse-proxy target=(\S+) ws=([01])", custom or "")
    return {"target": m.group(1), "websockets": m.group(2) == "1"} if m else {"target": "", "websockets": False}


def list_proxies() -> dict:
    out = []
    for s in sites.list_sites().get("sites", []):
        try:
            cur = sites.get_site(s["server_name"])["settings"]
        except sites.SiteError:
            continue
        if MARKER not in (cur.get("custom") or ""):
            continue
        info = _parse(cur.get("custom"))
        ssl = cur.get("ssl", "none")
        out.append({"domain": s["server_name"], "target": info["target"], "websockets": info["websockets"],
                    "ssl": ssl, "enabled": cur.get("enabled", True), "aliases": cur.get("aliases", []),
                    "url": f"http{'s' if ssl not in (None, 'none') else ''}://{s['server_name']}/"})
    out.sort(key=lambda p: p["domain"])
    return {"proxies": out}


def create_proxy(domain: str, target: str, websockets: bool = True, aliases: list | None = None) -> dict:
    domain = (domain or "").strip().lower().rstrip(".")
    if not _DOMAIN.match(domain):
        raise ProxyError("Enter a valid domain to expose it at, for example app.example.com")
    tgt = _target_url(target)
    try:
        sites.get_site(domain)
        raise ProxyError(f"{domain} is already a site here. Delete it first or pick another name.")
    except sites.SiteError:
        pass
    settings = {
        "server_name": domain,
        "aliases": [a.strip().lower() for a in (aliases or []) if a.strip()],
        "docroot": f"/var/www/proxy-{re.sub(r'[^a-z0-9.-]', '-', domain)}",
        "ssl": "selfsigned", "force_https": True,
        "custom": _custom(tgt, websockets), "security_headers": False, "gzip": False, "enabled": True,
    }
    Path(settings["docroot"]).mkdir(parents=True, exist_ok=True)
    sites._run(["a2enmod", "-q", "proxy", "proxy_http", "proxy_wstunnel", "headers"], 120)
    r = sites.create_site(settings)
    return {"ok": True, "domain": domain, "target": tgt, "url": f"https://{domain}/", **({} if isinstance(r, dict) else {})}


def delete_proxy(domain: str) -> dict:
    cur = sites.get_site(domain)["settings"]
    if MARKER not in (cur.get("custom") or ""):
        raise ProxyError("That is a website, not a reverse proxy created here. Manage it under Domains.")
    sites.remove_site(domain)
    return {"ok": True, "deleted": domain}
