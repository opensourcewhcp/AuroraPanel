"""Dynamic DNS: keep a hostname pointed at this network's public IP.

Providers are plain HTTPS update APIs. Updates run from a systemd timer
(aurora-ddns.timer → `python -m backend.ddns update`) so they keep working
even when the panel itself is stopped."""
from __future__ import annotations

import base64
import json
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from . import problems

CONFIG = Path("/var/lib/aurora/ddns.json")
UNIT_DIR = Path("/etc/systemd/system")
SERVICE, TIMER = "aurora-ddns.service", "aurora-ddns.timer"
APP_DIR = Path(__file__).resolve().parent.parent
UA = "AuroraPanel-DDNS/1.0 (https://github.com/)"
FORCE_EVERY = 24 * 3600  # re-send even when unchanged, so providers see the host is alive

PROVIDERS = {
    "duckdns": {"name": "DuckDNS", "signup": "https://www.duckdns.org", "suffix": ".duckdns.org",
                "fields": [["hostname", "Subdomain", "myhome  (→ myhome.duckdns.org)"], ["token", "Token", "", "secret"]],
                "note": "Free, no expiry. Sign in, add a subdomain, copy your token."},
    "noip": {"name": "No-IP", "signup": "https://www.noip.com/sign-up",
             "fields": [["hostname", "Hostname", "myhome.ddns.net"], ["username", "Username / DDNS key user", ""],
                        ["password", "Password / DDNS key", "", "secret"]],
             "note": "Free hostnames must be confirmed every 30 days by email."},
    "dynu": {"name": "Dynu", "signup": "https://www.dynu.com/en-US/ControlPanel/CreateAccount",
             "fields": [["hostname", "Hostname", "myhome.freeddns.org"], ["username", "Username", ""],
                        ["password", "Password (or IP update password)", "", "secret"]],
             "note": "Free, no expiry."},
    "desec": {"name": "deSEC (dedyn.io)", "signup": "https://desec.io/signup",
              "fields": [["hostname", "Hostname", "myhome.dedyn.io"], ["token", "Token", "", "secret"]],
              "note": "Free non-profit DNS; the dedyn.io name comes with a token."},
    "cloudflare": {"name": "Cloudflare (own domain)", "signup": "https://dash.cloudflare.com/profile/api-tokens",
                   "fields": [["hostname", "Record (full name)", "home.example.com"],
                              ["token", "API token (Zone.DNS edit)", "", "secret"]],
                   "note": "For a domain you own on Cloudflare. The A record is created if missing."},
    "freedns": {"name": "FreeDNS (afraid.org)", "signup": "https://freedns.afraid.org/signup/",
                "fields": [["hostname", "Hostname", "myhome.mooo.com"], ["token", "Update token (from the v2 update URL)", "", "secret"]],
                "note": "Use the token at the end of your 'sync.afraid.org/u/…' URL."},
    "custom": {"name": "Custom URL", "signup": "",
               "fields": [["hostname", "Hostname", "home.example.net"],
                          ["url", "Update URL — {ip} and {hostname} are replaced", "https://…?ip={ip}", "secret"]],
               "note": "Any provider with an HTTP(S) GET update URL."},
}


class DDNSError(RuntimeError):
    pass


def _load() -> dict:
    try:
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(cfg: dict):
    from .vpncommon import write_secret
    write_secret(CONFIG, json.dumps(cfg, indent=2))


def hostname() -> str | None:
    cfg = _load()
    return (cfg.get("hostname") or None) if cfg.get("enabled") else None


def _full_host(provider: str, host: str) -> str:
    host = host.strip().lower()
    if provider == "duckdns" and not host.endswith(".duckdns.org"):
        host += ".duckdns.org"
    return host


def _public_ip() -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=8) as r:
                ip = r.read().decode().strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return ip
        except Exception as quiet_exc:
            problems.quiet(quiet_exc)
            continue
    raise DDNSError("Could not determine the public IP (no internet?)")


def _http(url: str, headers: dict | None = None, data: bytes | None = None, method: str | None = None,
          auth: tuple[str, str] | None = None) -> tuple[int, str]:
    h = {"User-Agent": UA, **(headers or {})}
    if auth:
        h["Authorization"] = "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace").strip()
    except (urllib.error.URLError, OSError) as e:
        raise DDNSError(f"Provider unreachable: {e}")


def _dyndns2(url: str, cfg: dict, ip: str) -> str:
    q = urllib.parse.urlencode({"hostname": cfg["hostname"], "myip": ip})
    code, body = _http(f"{url}?{q}", auth=(cfg.get("username", ""), cfg.get("password", "")))
    if body.startswith(("good", "nochg")):
        return body
    raise DDNSError(f"Provider said: {body or code}")


def _cloudflare(cfg: dict, ip: str) -> str:
    tok = {"Authorization": f"Bearer {cfg['token']}", "Content-Type": "application/json"}
    host = cfg["hostname"]
    parts = host.split(".")
    zone = None
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        code, body = _http(f"https://api.cloudflare.com/client/v4/zones?name={cand}", tok)
        res = json.loads(body or "{}").get("result") or []
        if res:
            zone = res[0]["id"]
            break
    if not zone:
        raise DDNSError("No Cloudflare zone found for that name (check the token's zone access)")
    base = f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records"
    code, body = _http(f"{base}?type=A&name={host}", tok)
    recs = json.loads(body or "{}").get("result") or []
    payload = json.dumps({"type": "A", "name": host, "content": ip, "ttl": 120, "proxied": False}).encode()
    if recs:
        code, body = _http(f"{base}/{recs[0]['id']}", tok, payload, "PUT")
    else:
        code, body = _http(base, tok, payload, "POST")
    if not json.loads(body or "{}").get("success"):
        raise DDNSError(f"Cloudflare: {body[:300]}")
    return "updated"


def _send(cfg: dict, ip: str) -> str:
    p = cfg["provider"]
    if p == "duckdns":
        sub = cfg["hostname"].removesuffix(".duckdns.org")
        q = urllib.parse.urlencode({"domains": sub, "token": cfg["token"], "ip": ip})
        code, body = _http(f"https://www.duckdns.org/update?{q}")
        if body != "OK":
            raise DDNSError("DuckDNS rejected the update (check subdomain + token)")
        return "OK"
    if p == "noip":
        return _dyndns2("https://dynupdate.no-ip.com/nic/update", cfg, ip)
    if p == "dynu":
        return _dyndns2("https://api.dynu.com/nic/update", cfg, ip)
    if p == "desec":
        q = urllib.parse.urlencode({"hostname": cfg["hostname"], "myipv4": ip})
        code, body = _http(f"https://update.dedyn.io/?{q}", {"Authorization": f"Token {cfg['token']}"})
        if code == 200 and body.startswith(("good", "nochg")):
            return body
        raise DDNSError(f"deSEC said: {body or code}")
    if p == "cloudflare":
        return _cloudflare(cfg, ip)
    if p == "freedns":
        code, body = _http(f"https://sync.afraid.org/u/{urllib.parse.quote(cfg['token'])}/?address={ip}")
        if code == 200 and not body.lower().startswith("error"):
            return body[:200]
        raise DDNSError(f"FreeDNS said: {body or code}")
    if p == "custom":
        url = cfg["url"].replace("{ip}", ip).replace("{hostname}", cfg["hostname"])
        if not url.startswith(("http://", "https://")):
            raise DDNSError("Custom URL must start with http:// or https://")
        code, body = _http(url)
        if code >= 400:
            raise DDNSError(f"HTTP {code}: {body[:200]}")
        return body[:200] or f"HTTP {code}"
    raise DDNSError("Unknown provider")


def update(force: bool = False) -> dict:
    cfg = _load()
    if not cfg.get("provider"):
        raise DDNSError("Dynamic DNS is not configured")
    ip = _public_ip()
    last = cfg.get("last") or {}
    if (not force and last.get("ok") and last.get("ip") == ip
            and time.time() - last.get("ts", 0) < FORCE_EVERY):
        return {"changed": False, "ip": ip, "message": "unchanged"}
    try:
        msg = _send(cfg, ip)
        cfg["last"] = {"ok": True, "ip": ip, "ts": int(time.time()), "message": msg}
    except DDNSError as exc:
        cfg["last"] = {"ok": False, "ip": ip, "ts": int(time.time()), "message": str(exc)}
        _save(cfg)
        raise
    _save(cfg)
    return {"changed": True, "ip": ip, "message": msg}


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _unit_active(u: str) -> bool:
    try:
        return subprocess.run(["systemctl", "is-active", u], capture_output=True, text=True).stdout.strip() == "active"
    except OSError:  # no systemd (dev machine)
        return False


def status() -> dict:
    cfg = _load()
    safe = {k: v for k, v in cfg.items() if k not in ("token", "password", "url")}
    for k in ("token", "password", "url"):
        if cfg.get(k):
            safe[k + "_set"] = True
    host = cfg.get("hostname")
    last = cfg.get("last") or {}
    return {"config": safe, "providers": PROVIDERS, "timer_active": _unit_active(TIMER),
            "resolved_ip": _resolve(host) if host else None, "last": last,
            "ddclient_active": _unit_active("ddclient")}


def configure(provider: str, fields: dict, enabled: bool = True) -> dict:
    if provider not in PROVIDERS:
        raise DDNSError("Unknown provider")
    old = _load()
    cfg = {"provider": provider, "enabled": bool(enabled)}
    for f in PROVIDERS[provider]["fields"]:
        key, secret = f[0], len(f) > 3
        val = str(fields.get(key) or "").strip()
        if not val and secret and old.get("provider") == provider:
            val = old.get(key, "")  # blank secret on edit = keep the stored one
        if not val:
            raise DDNSError(f"{f[1]} is required")
        cfg[key] = val
    cfg["hostname"] = _full_host(provider, cfg["hostname"])
    if not re.match(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", cfg["hostname"]):
        raise DDNSError("Enter a valid hostname")
    if old.get("provider") == provider and old.get("hostname") == cfg["hostname"]:
        cfg["last"] = old.get("last")
    _save(cfg)
    result = update(force=True) if enabled else None
    _set_timer(enabled)
    return {"ok": True, "result": result, **status()}


def disable() -> dict:
    cfg = _load()
    cfg["enabled"] = False
    _save(cfg)
    _set_timer(False)
    return status()


def _set_timer(on: bool):
    if on:
        (UNIT_DIR / SERVICE).write_text(f"""[Unit]
Description=AuroraPanel Dynamic DNS update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory={APP_DIR}
ExecStart={sys.executable} -m backend.ddns update
""", encoding="utf-8")
        (UNIT_DIR / TIMER).write_text("""[Unit]
Description=AuroraPanel Dynamic DNS (every 5 minutes)

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
""", encoding="utf-8")
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", "--now", TIMER], capture_output=True)
    else:
        subprocess.run(["systemctl", "disable", "--now", TIMER], capture_output=True)


def stop_ddclient() -> dict:
    subprocess.run(["systemctl", "disable", "--now", "ddclient"], capture_output=True, text=True, timeout=30)
    return status()


if __name__ == "__main__":
    if sys.argv[1:2] == ["update"]:
        try:
            r = update(force="--force" in sys.argv)
            print(f"ddns: {r['message']} ({r['ip']})")
        except DDNSError as exc:
            print(f"ddns: {exc}", file=sys.stderr)
            sys.exit(1)
