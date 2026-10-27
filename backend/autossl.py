"""AutoSSL — a free trusted certificate for every site and the mail server, without asking.

Once a day (task runner) every website name, its aliases and the mail host name are checked: if a
name points to this server and isn't covered by a valid trusted certificate (≥ 20 days left), a
Let's Encrypt certificate is requested over HTTP (webroot) and the site is switched to it. Names that
point elsewhere are skipped and reported; a name that failed is retried the next day, never in a loop
(Let's Encrypt limits failed attempts).

Wildcards (*.example.com) need a DNS challenge: when this server answers DNS for the domain (Zone
Editor), the hooks below add the _acme-challenge TXT record themselves, wait for the nameservers to
show it, and remove it afterwards.

Requesting certificates means accepting the Let's Encrypt Subscriber Agreement: AutoSSL stays off
until the owner ticks that box in the panel.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

STATE = Path("/var/lib/aurora/autossl.json")
LE_LIVE = Path("/etc/letsencrypt/live")
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
RENEW_DAYS = 20
RETRY_HOURS = 23


class AutoSSLError(RuntimeError):
    pass


def _run(argv, timeout=300, env=None):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={**os.environ, "PATH": PATH, **(env or {})})
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def load() -> dict:
    try:
        s = json.loads(STATE.read_text())
    except (OSError, ValueError):
        s = {}
    s.setdefault("enabled", False)
    s.setdefault("agreed", False)
    s.setdefault("email", "")
    s.setdefault("results", {})
    s.setdefault("wildcards", [])
    s.setdefault("exclude", [])
    return s


def _save(s: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=1))


def settings(enabled: bool | None = None, email: str | None = None, agreed: bool | None = None, exclude: list[str] | None = None) -> dict:
    s = load()
    if email is not None:
        email = email.strip()
        from .sites import le_email_problem
        why = le_email_problem(email)
        if why:
            raise AutoSSLError(why)
        s["email"] = email
    if agreed is not None:
        s["agreed"] = bool(agreed)
    if enabled is not None:
        if enabled and not s["agreed"]:
            raise AutoSSLError("Tick “I agree to the Let's Encrypt Subscriber Agreement” first")
        if enabled and not shutil.which("certbot", path=PATH):
            raise AutoSSLError("Install Certbot first (one click on the SSL/TLS page)")
        s["enabled"] = bool(enabled)
    if exclude is not None:
        s["exclude"] = sorted({x.strip().lower() for x in exclude if x.strip()})
    _save(s)
    return status()


# ------------------------------------------------------------------ looking around
_my_ips_cache: tuple[float, set[str]] = (0, set())


def my_ips() -> set[str]:
    global _my_ips_cache
    if time.time() - _my_ips_cache[0] < 300:
        return _my_ips_cache[1]
    ips: set[str] = set()
    try:
        from . import dnszones
        ips |= set(dnszones._my_ips())
    except Exception:
        pass
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            import urllib.request
            ip = urllib.request.urlopen(url, timeout=6).read().decode().strip()
            ipaddress.ip_address(ip)
            ips.add(ip)
            break
        except Exception:
            continue
    _my_ips_cache = (time.time(), ips)
    return ips


def resolves_here(name: str) -> tuple[bool, list[str]]:
    try:
        addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(name, None)})
    except socket.gaierror:
        return False, []
    mine = my_ips()
    return any(a in mine for a in addrs), addrs


def _trusted_certs() -> list[dict]:
    """Every Let's Encrypt certificate here: names it covers and when it expires."""
    out = []
    if not LE_LIVE.is_dir():
        return out
    for d in LE_LIVE.iterdir():
        pem = d / "cert.pem"
        if not pem.exists():
            continue
        txt = _run(["openssl", "x509", "-noout", "-enddate", "-ext", "subjectAltName", "-in", str(pem)], 20).stdout
        m = re.search(r"notAfter=(.+)", txt)
        try:
            exp = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z").timestamp() if m else 0
        except ValueError:
            exp = 0
        out.append({"name": d.name, "names": [n.lower() for n in re.findall(r"DNS:([^,\s]+)", txt)], "expires": exp, "path": str(d)})
    return out


def covered(name: str, certs: list[dict]) -> dict | None:
    name = name.lower()
    best = None
    for c in certs:
        for n in c["names"]:
            if n == name or (n.startswith("*.") and name.count(".") == n.count(".") and name.endswith(n[1:])):
                if not best or c["expires"] > best["expires"]:
                    best = c
    return best


def _plan() -> list[dict]:
    """What AutoSSL would do for every site, name by name."""
    from . import sites
    s = load()
    certs = _trusted_certs()
    now = time.time()
    items = []
    try:
        listing = sites.list_sites()["sites"]
    except Exception:
        listing = []
    for site in listing:
        if site.get("system") or not site.get("managed") or not site.get("enabled"):
            continue
        if site["ssl"] == "custom":
            items.append({"site": site["server_name"], "names": [], "state": "own", "note": "Uses your own certificate — AutoSSL leaves it alone"})
            continue
        names = [site["server_name"]] + [a for a in site.get("aliases", []) if not a.startswith("*")]
        rows = []
        for n in names:
            n = n.lower()
            try:
                ipaddress.ip_address(n)
                continue
            except ValueError:
                pass
            if n in s["exclude"]:
                rows.append({"name": n, "state": "excluded"})
                continue
            here, addrs = resolves_here(n)
            c = covered(n, certs)
            days = (c["expires"] - now) / 86400 if c else None
            st = "ok" if c and days >= RENEW_DAYS else ("renew" if c else "missing")
            if not here:
                st = "elsewhere" if addrs else "nodns"
            rows.append({"name": n, "state": st, "addrs": addrs, "days": round(days) if days is not None else None, "cert": c["name"] if c else ""})
        items.append({"site": site["server_name"], "docroot": site["docroot"], "ssl": site["ssl"], "names": rows})
    # the mail server's own name
    try:
        from . import mail
        if mail.installed() and mail.configured():
            host = mail.hostname()
            here, addrs = resolves_here(host)
            c = covered(host, certs)
            days = (c["expires"] - now) / 86400 if c else None
            st = ("ok" if days >= RENEW_DAYS else "renew") if c else "missing"
            if not here:
                st = "elsewhere" if addrs else "nodns"
            items.append({"site": host, "mail": True, "names": [{"name": host, "state": st, "addrs": addrs,
                                                                 "days": round(days) if days is not None else None, "cert": c["name"] if c else ""}]})
    except Exception:
        pass
    return items


def status() -> dict:
    s = load()
    try:
        from . import config
        contact = config.get_prefs().get("contact_email", "")
    except Exception:
        contact = ""
    zones = []
    try:
        from . import dnszones
        zones = [z["domain"] for z in dnszones.list_zones([])["zones"]]
    except Exception:
        pass
    return {"enabled": s["enabled"], "agreed": s["agreed"], "email": s["email"] or contact, "exclude": s["exclude"],
            "certbot": bool(shutil.which("certbot", path=PATH)), "last_run": s.get("last_run"), "results": s["results"],
            "plan": _plan(), "wildcards": s["wildcards"], "zones": zones, "certs": _trusted_certs(), "port80": s.get("port80"),
            "running": _run(["systemctl", "is-active", "aurora-autossl"], 10).stdout.strip() in ("active", "activating")}


# ------------------------------------------------------------------ doing it
def _certbot_base(s: dict) -> list[str]:
    if not s["agreed"]:
        raise AutoSSLError("The Let's Encrypt Subscriber Agreement hasn't been accepted in the panel")
    email = s["email"]
    if not email:
        try:
            from . import config
            email = config.get_prefs().get("contact_email", "")
        except Exception:
            pass
    base = ["certbot", "certonly", "--non-interactive", "--agree-tos", "--keep-until-expiring", "--expand"]
    base += ["-m", email] if email else ["--register-unsafely-without-email"]
    return base


def _port80() -> dict:
    """Can the internet reach TCP 80 here? Let's Encrypt proves a name by fetching http://<name>/.well-known/…,
    so a shut port means every request would fail (and count against its limits). portcheck asks from outside
    and knows the router steps."""
    try:
        from . import portcheck
        r = portcheck.check(80, "tcp")
        return {"ts": int(time.time()), "verdict": r["verdict"], "steps": r.get("steps") or [], "router_url": r.get("router_url"),
                "public_ip": r.get("public_ip"), "lan_ip": r.get("lan_ip"), "evidence": r.get("evidence"),
                "upnp": bool((r.get("upnp") or {}).get("available"))}
    except Exception as e:
        return {"ts": int(time.time()), "verdict": "unverified", "steps": [], "error": str(e)[:200]}


def run(force: bool = False, only: str = "") -> dict:
    """One AutoSSL pass. Returns what happened per site."""
    from . import sites
    s = load()
    if not s["enabled"] and not force:
        return {"skipped": "AutoSSL is off"}
    now = time.time()
    out = {}
    gate = None  # the port-80 check, done once per pass and only when something needs a certificate
    for item in _plan():
        if only and item["site"] != only:
            continue
        need = [r["name"] for r in item["names"] if r["state"] in ("missing", "renew")]
        if not need:
            continue
        key = item["site"]
        prev = s["results"].get(key, {})
        if not force and prev.get("ok") is False and now - prev.get("ts", 0) < RETRY_HOURS * 3600:
            continue  # failed recently: Let's Encrypt limits failures, try again tomorrow
        if gate is None:
            gate = s["port80"] = _port80()
            _save(s)
        if gate["verdict"] == "closed":
            steps = " ".join(gate["steps"]) or "Forward TCP port 80 on your router to this Pi."
            out[key] = s["results"][key] = {"ts": int(now), "ok": False, "port80": True, "names": need,
                                           "error": f"Not requested: port 80 isn't reachable from the internet (checked from outside just now), so Let's Encrypt couldn't verify the name. {steps}"}
            _save(s)
            continue
        # everything of this site that points here goes on one certificate
        names = [r["name"] for r in item["names"] if r["state"] in ("ok", "missing", "renew")]
        if item.get("mail"):
            webroot = "/var/www/html"
            cert_name = key
        else:
            webroot = item["docroot"]
            cert_name = key
            if key not in names:
                out[key] = s["results"][key] = {"ts": int(now), "ok": False, "error": f"{key} itself doesn't point to this server — fix its DNS first"}
                continue
        argv = _certbot_base(s) + ["--webroot", "-w", webroot, "--cert-name", cert_name]
        for n in names:
            argv += ["-d", n]
        r = _run(argv, 600)
        res = {"ts": int(now), "names": names}
        if r.returncode == 0:
            res["ok"] = True
            try:
                if item.get("mail"):
                    from . import mail
                    mail.set_tls(cert_name)
                    res["note"] = "Mail server and webmail now use it"
                elif item.get("ssl") != "letsencrypt":
                    st = sites.get_site(key)["settings"]
                    st["ssl"] = "letsencrypt"
                    sites.save_site(key, st)
                    res["note"] = "Site switched to the new certificate"
            except Exception as e:
                res["note"] = f"Certificate issued, but switching the site failed: {e}"
        else:
            res["ok"] = False
            res["error"] = _why(r.stdout + r.stderr)
        out[key] = s["results"][key] = res
        _save(s)
    s = load()
    s["results"].update(out)
    s["last_run"] = int(now)
    _save(s)
    try:
        from . import audit
        for k, v in out.items():
            audit.record("system", "", f"AutoSSL {k}", ok=v.get("ok", False), status=200 if v.get("ok") else 500, detail={"names": v.get("names"), "error": v.get("error")})
    except Exception:
        pass
    return out


def _why(text: str) -> str:
    """The useful part of certbot's error, in plain words."""
    t = text
    if "too many" in t.lower() and "rate" in t.lower():
        return "Let's Encrypt rate limit hit — it'll be retried tomorrow"
    m = re.search(r"Detail: (.+)", t)
    detail = m.group(1).strip() if m else ""
    if "NXDOMAIN" in t or "DNS problem" in t:
        return f"DNS problem: {detail or 'the name does not resolve'}"
    if "Timeout" in t or "Connection refused" in t or "Fetching http" in t:
        return f"Let's Encrypt couldn't reach this server on port 80 ({detail[:160]}). Check the firewall and your router's port forwarding."
    if "unauthorized" in t.lower() or "404" in t:
        return f"The check file wasn't served — another site or redirect may be answering for that name ({detail[:160]})"
    return (detail or t.strip().splitlines()[-1] if t.strip() else "certbot failed")[:300]


def start(force: bool = True, only: str = "") -> dict:
    """Run now, as its own systemd unit (certbot can take a minute per site)."""
    from . import config
    if _run(["systemctl", "is-active", "aurora-autossl"], 10).stdout.strip() in ("active", "activating"):
        return {"ok": True, "already": True}
    argv = ["systemd-run", "--unit=aurora-autossl", "--collect", "--quiet", f"--working-directory={config.ROOT}",
            sys.executable, "-m", "backend.autossl", "run"] + (["--force"] if force else []) + ([only] if only else [])
    r = _run(argv, 30)
    if r.returncode != 0:
        raise AutoSSLError(r.stderr.strip()[-300:] or "couldn't start")
    return {"ok": True}


# ------------------------------------------------------------------ wildcards (DNS-01 through our own zones)
def _zone_for(domain: str) -> str:
    from . import dnszones
    zones = sorted((z["domain"] for z in dnszones.list_zones([])["zones"]), key=len, reverse=True)
    for z in zones:
        if domain == z or domain.endswith("." + z):
            return z
    raise AutoSSLError(f"This server doesn't host DNS for {domain} — create its zone in the Zone Editor first")


def hook(kind: str) -> int:
    """certbot --manual-auth-hook / --manual-cleanup-hook."""
    from . import dnszones
    domain = os.environ.get("CERTBOT_DOMAIN", "").lower().lstrip("*.")
    value = os.environ.get("CERTBOT_VALIDATION", "")
    zone = _zone_for(domain)
    name = f"_acme-challenge.{domain}."
    z = dnszones.get_zone(zone)
    if kind == "auth":
        dnszones.add_record(zone, {"type": "TXT", "name": name, "text": value, "ttl": 60})
        # wait until every nameserver of the zone serves it (secondaries get NOTIFY + transfer)
        ns = [r["target"].rstrip(".") for r in z["records"] if r["type"] == "NS" and r["name"] == zone + "."] or [zone]
        deadline = time.time() + 240
        while time.time() < deadline:
            ok = 0
            for n in ns:
                out = _run(["dig", "+short", "TXT", name, f"@{n}"], 15).stdout
                if value in out:
                    ok += 1
            if ok == len(ns):
                return 0
            time.sleep(10)
        return 0  # let Let's Encrypt try anyway; it reports precisely if it can't see the record
    for i, r in reversed(list(enumerate(z["records"]))):
        if r["type"] == "TXT" and r["name"] == name and (not value or r.get("text") == value):
            dnszones.delete_record(zone, i, {"name": r["name"], "type": "TXT"})
            z = dnszones.get_zone(zone)
    return 0


def issue_wildcard(domain: str) -> dict:
    """*.domain + domain on one certificate, via the DNS challenge (as its own unit)."""
    from . import dnszones, config
    domain = dnszones._dom(domain)
    _zone_for(domain)
    if not shutil.which("dig", path=PATH):
        raise AutoSSLError("The dig tool is missing — install bind9-dnsutils")
    s = load()
    _certbot_base(s)  # checks the agreement
    if domain not in s["wildcards"]:
        s["wildcards"].append(domain)
        _save(s)
    argv = ["systemd-run", f"--unit=aurora-wildcard-{re.sub(r'[^a-z0-9]', '-', domain)}", "--collect", "--quiet",
            f"--working-directory={config.ROOT}", sys.executable, "-m", "backend.autossl", "wildcard", domain]
    r = _run(argv, 30)
    if r.returncode != 0:
        raise AutoSSLError(r.stderr.strip()[-300:] or "couldn't start")
    return {"ok": True}


def _wildcard(domain: str) -> dict:
    s = load()
    py = f"{sys.executable} -m backend.autossl"
    argv = _certbot_base(s) + ["--manual", "--preferred-challenges", "dns", "--manual-auth-hook", f"{py} hook auth",
                               "--manual-cleanup-hook", f"{py} hook cleanup", "--cert-name", f"wildcard.{domain}", "-d", domain, "-d", f"*.{domain}"]
    from . import config
    r = _run(argv, 900, env={"PYTHONPATH": str(config.ROOT)})
    res = {"ts": int(time.time()), "names": [domain, f"*.{domain}"], "ok": r.returncode == 0, "wildcard": True}
    if r.returncode != 0:
        res["error"] = _why(r.stdout + r.stderr)
    s = load()
    s["results"][f"*.{domain}"] = res
    _save(s)
    return res


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "run":
        run(force="--force" in a, only=next((x for x in a[1:] if not x.startswith("--")), ""))
    elif a and a[0] == "hook" and len(a) > 1:
        sys.exit(hook(a[1]))
    elif a and a[0] == "wildcard" and len(a) > 1:
        sys.exit(0 if _wildcard(a[1]).get("ok") else 1)
