"""Stage 4: who the visitor really is behind a proxy or CDN, and Cloudflare.

X-Forwarded-For and friends are only believed from addresses listed as trusted. Those lists also feed the web servers'
own real-IP modules, so the WAF rules and access logs see the visitor. Banning a trusted proxy at the firewall is refused
by the Safety Lock: behind a CDN, a ban belongs at the CDN.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
import urllib.error
import urllib.request
import uuid

APACHE_FILE, NGINX_FILE = "/etc/apache2/conf-available/zz-ella-proxies.conf", "/etc/nginx/conf.d/aurora-ella-realip.conf"
HEADERS = ("X-Forwarded-For", "CF-Connecting-IP", "X-Real-IP")
CF_URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
CF_API = "https://api.cloudflare.com/client/v4"
HEADER = "# Written by AuroraPanel (WAF Ella). Edit there: changes here are overwritten.\n"
MIN_PREFIX = {4: 8, 6: 28}


class ProxyError(ValueError):
    pass


def _nets(items) -> list:
    out = []
    for c in items or []:
        try:
            out.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            continue
    return out


def _in(ip, nets: list) -> bool:
    return any(ip.version == n.version and ip in n for n in nets)


def client_from(peer: str | None, headers: dict | None, trusted: list) -> tuple[str | None, str]:
    """(client address, where it came from). A header counts only when the connection came from a trusted proxy.
    In X-Forwarded-For the rightmost address that isn't a trusted proxy is the one a proxy of ours really saw: anything to
    its left was sent by the client and proves nothing."""
    if not peer:
        return None, "unknown"
    try:
        p = ipaddress.ip_address(peer)
    except ValueError:
        return peer, "peer"
    nets = _nets(trusted)
    h = headers or {}
    if not _in(p, nets):
        return peer, "peer"
    cf = str(h.get("cf-connecting-ip") or "").strip()
    if cf and _valid(cf):
        return cf, "cf-connecting-ip"
    chain = [x.strip() for x in str(h.get("x-forwarded-for") or "").split(",") if x.strip()]
    for hop in reversed(chain):
        if not _valid(hop):
            break
        if not _in(ipaddress.ip_address(hop), nets):
            return hop, "x-forwarded-for"
    real = str(h.get("x-real-ip") or "").strip()
    if real and _valid(real):
        return real, "x-real-ip"
    return peer, "peer"


def _valid(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def check_ranges(items) -> list[str]:
    out = []
    for raw in items or []:
        try:
            n = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError as exc:
            raise ProxyError(f"Not an IP address or range: {raw}") from exc
        if n.prefixlen < MIN_PREFIX[n.version]:
            raise ProxyError(f"{n} is too wide to trust: anyone in it could claim to be any visitor")
        out.append(str(n))
    return sorted(set(out))


def render_apache(trusted: list[str], header: str) -> str:
    if not trusted:
        return HEADER
    lines = [f"RemoteIPTrustedProxy {t}" for t in trusted]
    return HEADER + "<IfModule remoteip_module>\n    RemoteIPHeader " + header + "\n    " + "\n    ".join(lines) + "\n</IfModule>\n"


def render_nginx(trusted: list[str], header: str) -> str:
    if not trusted:
        return HEADER
    return HEADER + "".join(f"set_real_ip_from {t};\n" for t in trusted) + f"real_ip_header {header};\nreal_ip_recursive on;\n"


def parse_ranges(texts: list[str]) -> list[str]:
    """Cloudflare's published lists. A short or odd answer is refused: a bad list here would trust the wrong people."""
    out = []
    for text in texts:
        for line in text.splitlines():
            line = line.strip()
            if line:
                out.append(line)
    if not 5 <= len(out) <= 200:
        raise ProxyError(f"Cloudflare's list has {len(out)} ranges, which doesn't look right, so it wasn't used")
    ranges = check_ranges(out)
    for r in ranges:
        if ipaddress.ip_network(r).is_private:
            raise ProxyError(f"Cloudflare's list has a private range in it ({r}), so it wasn't used")
    return ranges


def _fetch(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "AuroraPanel"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310  fixed https addresses
        return r.read(200_000).decode("utf-8", "replace")


class Proxies:
    def __init__(self, store, configs, servers, fetch=_fetch, api=None):
        self.store, self.configs, self.servers, self.fetch = store, configs, servers, fetch
        self.api = api or _cf_call

    def state(self) -> dict:
        cf = self.store.setting("cdn_cloudflare") or {}
        return {"manual": self.store.setting("trusted_manual") or [], "header": self.store.setting("real_ip_header") or "X-Forwarded-For", "trusted": self.store.setting("trusted_proxies") or [],
                "cloudflare": {"enabled": bool(cf.get("enabled")), "ranges": len(cf.get("ranges") or []), "updated": cf.get("updated"), "error": cf.get("error", ""), "zone": cf.get("zone", ""), "has_token": bool(cf.get("token"))}}

    def _publish(self, actor: str) -> None:
        cf = self.store.setting("cdn_cloudflare") or {}
        manual = self.store.setting("trusted_manual") or []
        trusted = sorted(set(manual) | set(cf.get("ranges") or [] if cf.get("enabled") else []))
        header = "CF-Connecting-IP" if cf.get("enabled") and not manual else (self.store.setting("real_ip_header") or "X-Forwarded-For")
        self.store.set_setting("trusted_proxies", trusted)
        for sv in self.servers():
            path, text = (NGINX_FILE, render_nginx(trusted, header)) if sv["name"] == "nginx" else (APACHE_FILE, render_apache(trusted, header))
            self.configs.apply(path, text, actor, server=sv["name"], reload=sv["active"], watch_seconds=None)

    def set_manual(self, ranges: list, header: str, actor: str) -> dict:
        if header not in HEADERS:
            raise ProxyError("Header must be one of " + ", ".join(HEADERS))
        clean = check_ranges(ranges)
        old = (self.store.setting("trusted_manual"), self.store.setting("real_ip_header"))
        self.store.set_setting("trusted_manual", clean)
        self.store.set_setting("real_ip_header", header)
        self.store.audit(actor, "proxies.changed", "", {"ranges": clean, "header": header})
        try:
            self._publish(actor)
        except Exception:
            self.store.set_setting("trusted_manual", old[0] or [])
            self.store.set_setting("real_ip_header", old[1] or "X-Forwarded-For")
            raise
        return self.state()

    def set_cloudflare(self, enabled: bool, actor: str, token: str | None = None, zone: str | None = None) -> dict:
        cf = dict(self.store.setting("cdn_cloudflare") or {})
        if token is not None:
            cf["token"] = token.strip()
        if zone is not None:
            if zone and not re.fullmatch(r"[a-f0-9]{32}", zone):
                raise ProxyError("A Cloudflare zone ID is 32 hexadecimal characters")
            cf["zone"] = zone
        cf["enabled"] = bool(enabled)
        self.store.set_setting("cdn_cloudflare", cf)
        self.store.audit(actor, "proxies.cloudflare", "", {"enabled": bool(enabled), "zone": cf.get("zone", ""), "token_changed": token is not None})
        if enabled:
            self.refresh_cloudflare(actor)
        else:
            self._publish(actor)
        return self.state()

    def refresh_cloudflare(self, actor: str = "system") -> dict:
        """Keeps the last good list when a download fails, and says so."""
        cf = dict(self.store.setting("cdn_cloudflare") or {})
        try:
            ranges = parse_ranges([self.fetch(u) for u in CF_URLS])
        except (OSError, ValueError, urllib.error.URLError) as exc:
            cf["error"] = str(exc)[:200]
            self.store.set_setting("cdn_cloudflare", cf)
            if not cf.get("ranges"):
                raise ProxyError(f"Couldn't get Cloudflare's address list: {exc}") from exc
            return self.state()
        changed = ranges != cf.get("ranges")
        cf.update(ranges=ranges, updated=time.time(), error="")
        self.store.set_setting("cdn_cloudflare", cf)
        if changed:
            self.store.audit(actor, "proxies.cloudflare_ranges", "", {"count": len(ranges)})
            self._publish(actor)
        return self.state()

    def tick(self) -> None:
        cf = self.store.setting("cdn_cloudflare") or {}
        if cf.get("enabled") and time.time() - (cf.get("updated") or 0) > 86400:
            self.refresh_cloudflare()

    # ---- bans at the CDN: the only place a ban reaches a visitor who comes through it
    def cdn_ban(self, target: str, reason: str, actor: str) -> dict:
        cf = self.store.setting("cdn_cloudflare") or {}
        if not cf.get("token") or not cf.get("zone"):
            raise ProxyError("Add a Cloudflare API token and zone ID first.")
        n = ipaddress.ip_network(str(target).strip(), strict=False)
        mode = "ip" if n.num_addresses == 1 else ("ip_range" if n.version == 4 else "ip6")
        value = str(n.network_address) if n.num_addresses == 1 else str(n)
        res = self.api("POST", f"/zones/{cf['zone']}/firewall/access_rules/rules", cf["token"], {"mode": "block", "configuration": {"target": mode if mode != "ip6" else "ip_range", "value": value}, "notes": f"AuroraPanel: {reason}"[:100]})
        if not res.get("success"):
            raise ProxyError(f"Cloudflare refused it: {json.dumps(res.get('errors'))[:200]}")
        rule, block, now = res["result"]["id"], uuid.uuid4().hex, time.time()

        def add(c):
            c.execute("INSERT INTO blocks(id, source, owner, scope, backend, target, reason, created_at, desired_state, actual_state, last_verified_at, operation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                      (block, "cloudflare", actor, "server", "cdn-api", str(n), reason[:500], now, "active", "present", now, f"cf:{rule}"))
            self.store.audit_in(c, actor, "ban.cdn", str(n), {"rule": rule, "reason": reason})
        self.store.run(add)
        return {"ok": True, "id": block}

    def cdn_unban(self, block: dict, actor: str) -> dict:
        cf = self.store.setting("cdn_cloudflare") or {}
        rule = str(block.get("operation_id") or "")[3:]
        if not re.fullmatch(r"[A-Za-z0-9]{1,64}", rule):
            raise ProxyError("This ban has no Cloudflare rule on record")
        res = self.api("DELETE", f"/zones/{cf.get('zone')}/firewall/access_rules/rules/{rule}", cf.get("token", ""), None)
        if not res.get("success"):
            raise ProxyError(f"Cloudflare refused it: {json.dumps(res.get('errors'))[:200]}")

        def end(c):
            c.execute("UPDATE blocks SET desired_state='removed', actual_state='absent', last_verified_at=? WHERE id=?", (time.time(), block["id"]))
            self.store.audit_in(c, actor, "unban.cdn", block["target"], {"rule": rule})
        self.store.run(end)
        return {"ok": True, "state": "applied"}


def _cf_call(method: str, path: str, token: str, body: dict | None) -> dict:
    req = urllib.request.Request(CF_API + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "AuroraPanel"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310  fixed https address
            return json.loads(r.read(500_000))
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read(100_000))
        except ValueError:
            return {"success": False, "errors": [f"HTTP {exc.code}"]}
    except (OSError, ValueError) as exc:
        return {"success": False, "errors": [str(exc)[:200]]}


# What each web server can do here. "verified" means tests/integration ran it on the named system; nothing else earns the word.
MATRIX = [
    {"server": "Apache", "version": "2.4", "os": "Fedora 45", "connect": "ModSecurity 2 (mod_security) in the server", "inline": True, "logs": True, "ip_ban": True, "rate_limit": False, "tarpit": False, "status": "verified", "limits": "No rate limit or tarpit: nothing packaged does it without tying up workers."},
    {"server": "Nginx", "version": "1.2x", "os": "Fedora 45", "connect": "ModSecurity 3 (libmodsecurity) by connector", "inline": True, "logs": True, "ip_ban": True, "rate_limit": False, "tarpit": False, "status": "verified", "limits": "No inline rate limit or tarpit yet. A rate limit here is a ban read from logs, which acts on the next request. See the differences from ModSecurity 2 below."},
    {"server": "Apache / Nginx", "version": "distro", "os": "Debian, Ubuntu, Raspberry Pi OS", "connect": "the same packages", "inline": True, "logs": True, "ip_ban": True, "rate_limit": False, "tarpit": False, "status": "untested", "limits": "WAF Ella stages 3 to 8 haven't run on these yet."},
    {"server": "Caddy", "version": "2.x", "os": "Fedora 45", "connect": "behind an Nginx reverse proxy site", "inline": False, "logs": True, "ip_ban": True, "rate_limit": False, "tarpit": False, "status": "verified", "limits": "Logs and bans only unless it's behind Nginx. Coraza isn't packaged."},
    {"server": "LiteSpeed, HAProxy, Envoy", "version": "", "os": "", "connect": "behind an Nginx reverse proxy site", "inline": False, "logs": False, "ip_ban": True, "rate_limit": False, "tarpit": False, "status": "untested", "limits": "A custom log source can read their logs."},
]
ENGINE_DIFFERENCES = [
    {"what": "Audit log", "v2": "One JSON shape, parts per SecAuditLogParts", "v3": "A different JSON shape, read by its own parser"},
    {"what": "Blocking and logs", "v2": "'Access denied' line says it was blocked", "v3": "Worked out from the response code and engine mode"},
    {"what": "ctl:ruleRemoveTargetById", "v2": "Supported", "v3": "Supported"},
    {"what": "Rules behind Nginx's 'return'", "v2": "Not applicable", "v3": "A location using 'return' answers before the rules read the request, so it isn't inspected"},
    {"what": "Memory for the Core Rule Set", "v2": "Not measured here", "v3": "About 32 MB, at paranoia level 1 with one worker"},
    {"what": "<IfModule> in rule files", "v2": "Works", "v3": "Not understood, so WAF Ella writes separate files"},
    {"what": "HTTP/3 (QUIC)", "v2": "Apache doesn't serve it", "v3": "The panel doesn't turn it on. If you do, check that requests still reach the WAF"},
]
