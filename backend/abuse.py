"""Report an attacking IP address to its network's abuse contact.

The contact comes from RDAP (the registries' official lookup service: ARIN, RIPE,
APNIC, LACNIC, AFRINIC), the evidence from the panel's own login log (netmon), and
the message goes out through this server's mail system from an address the admin
picked once (remembered). An address is reported at most once a week.
"""
from __future__ import annotations

import ipaddress
import json
import secrets
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CONF = Path("/var/lib/aurora/abuse.json")
RDAP = "https://rdap.org/ip/{ip}"
WEEK = 7 * 86400


class AbuseError(RuntimeError):
    pass


def _conf() -> dict:
    try:
        c = json.loads(CONF.read_text())
    except (OSError, ValueError):
        c = {}
    c.setdefault("from", "")
    c.setdefault("reported", {})
    return c


def _save(c: dict) -> None:
    CONF.parent.mkdir(parents=True, exist_ok=True)
    c["reported"] = {k: v for k, v in c["reported"].items() if time.time() - v.get("ts", 0) < 90 * 86400}
    CONF.write_text(json.dumps(c, indent=1))


def _public_ip(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise AbuseError(f"“{ip}” isn't an IP address")
    if not a.is_global:
        raise AbuseError(f"{ip} is a private/local address — there's no one to report it to")
    return str(a)


def _emails(entity: dict) -> list[str]:
    out = []
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == "email" and isinstance(item[3], str):
            out.append(item[3].strip().lower())
    return out


def _walk(entities: list, found: dict) -> None:
    for e in entities or []:
        roles = set(e.get("roles") or [])
        for m in _emails(e):
            if "abuse" in roles:
                found["abuse"].append(m)
            elif roles & {"technical", "administrative", "registrant", "noc"}:
                found["other"].append(m)
        _walk(e.get("entities"), found)


_cache: dict[str, tuple[float, dict]] = {}


def lookup(ip: str) -> dict:
    ip = _public_ip(ip)
    hit = _cache.get(ip)
    if hit and time.time() - hit[0] < 86400:
        return hit[1]
    req = urllib.request.Request(RDAP.format(ip=ip), headers={"Accept": "application/rdap+json", "User-Agent": "AuroraPanel"})
    try:
        data = json.loads(urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "replace"))
    except Exception as e:
        raise AbuseError(f"Couldn't look up who runs {ip} ({e})")
    found = {"abuse": [], "other": []}
    _walk(data.get("entities"), found)
    for r in data.get("remarks") or []:  # some registries only mention it in remarks
        for line in r.get("description") or []:
            for w in line.replace(",", " ").split():
                if "@" in w and "abuse" in w.lower():
                    found["abuse"].append(w.strip("<>.;:()").lower())
    contacts = list(dict.fromkeys(found["abuse"] or found["other"]))
    # Prefer a role address (abuse@…) over a named person, so the pre-filled default is the one
    # abuse desks actually read. RFC 2142 requires abuse@<domain>, so offer it as a suggestion too.
    contacts.sort(key=lambda a: (not a.startswith("abuse@"), a))
    suggestions = list(contacts)
    for dom in dict.fromkeys(a.split("@", 1)[1] for a in contacts if "@" in a):
        role = f"abuse@{dom}"
        if role not in suggestions:
            suggestions.append(role)
    out = {"ip": ip, "network": data.get("name") or "", "country": data.get("country") or "",
           "range": f"{data.get('startAddress', '')} – {data.get('endAddress', '')}".strip(" –"),
           "contacts": contacts, "suggestions": suggestions, "abuse_role": bool(found["abuse"]), "source": data.get("port43") or "RDAP"}
    _cache[ip] = (time.time(), out)
    return out


def evidence(ip: str, days: int = 7) -> list[dict]:
    """Failed logins (SSH, mail, panel, FTP), web attacks the WAF caught, and connection attempts
    the firewall logged (port scans — the Network Monitor's "Sources"), newest first."""
    from . import netmon
    ev = [e for e in netmon.auth_events(days * 86400) if e.get("ip") == ip and e.get("outcome") != "ok"]
    try:
        for c in netmon.connections(days * 86400) + netmon.blocked(days * 86400):
            if c.get("src") == ip:
                port = f"{c['port']}/{c.get('proto') or 'tcp'}" if c.get("port") else (c.get("proto") or "?")
                ev.append({"ts": c["ts"], "source": "firewall", "kind": "probe", "port": port,
                           "detail": f"connection attempt to port {port}" + (" — dropped (banned)" if c.get("blocked") else "")})
    except Exception:
        pass
    try:
        from . import waf
        for w in waf.events(hours=days * 24, limit=500, ip=ip):
            r = waf._primary(w["rules"])
            req = " ".join(w["request"].split(" ")[:2])[:160]
            ev.append({"ts": w["ts"], "source": "web firewall", "kind": "attack",
                       "detail": f"{r['category']} ({r['msg'][:80]}) — {req}" + (" — blocked" if w["blocked"] else "")})
    except Exception:
        pass
    return sorted(ev, key=lambda e: -e["ts"])


def _counts(ev: list[dict]) -> dict:
    attacks = sum(1 for e in ev if e.get("kind") == "attack")
    probes = [e for e in ev if e.get("kind") == "probe"]
    return {"logins": len(ev) - attacks - len(probes), "attacks": attacks, "probes": len(probes),
            "ports": len({e["port"] for e in probes})}


def _what(c: dict) -> str:
    parts = []
    if c.get("probes"):
        ports = c.get("ports", 0)
        parts.append(f"{c['probes']} connection attempt{'s' if c['probes'] != 1 else ''} to {ports} different port{'s' if ports != 1 else ''}"
                     + (" (a port scan)" if ports >= 5 else ""))
    if c["logins"]:
        parts.append(f"{c['logins']} unauthorized login attempt{'s' if c['logins'] != 1 else ''}")
    if c["attacks"]:
        parts.append(f"{c['attacks']} web attack{'s' if c['attacks'] != 1 else ''} (blocked by our web application firewall)")
    return " and ".join(parts) or "abusive traffic"


def _body(ip: str, info: dict, ev: list[dict], host: str, server_ip: str, note: str) -> str:
    fmt = lambda ts: datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    net = f" ({info['network']})" if info.get("network") else ""
    lines = [
        "Hello,",
        "",
        f"The address {ip}{net}, which belongs to your network, has been sending {_what(_counts(ev))} to our server.",
        "",
        f"Our server: {host} ({server_ip})",
        f"Period: {fmt(ev[-1]['ts'])} to {fmt(ev[0]['ts'])}." if ev else "Details: see below.",
        "",
        "Log excerpt (UTC):",
    ]
    for e in ev[:60]:
        if e.get("kind") in ("attack", "probe"):
            lines.append(f"  {fmt(e['ts'])}  {e['source']}: {e['detail']} from {ip}")
            continue
        who = f" as user '{e['user']}'" if e.get("user") else ""
        lines.append(f"  {fmt(e['ts'])}  {e['source']}: failed login{who} from {ip}")
    if len(ev) > 60:
        lines.append(f"  … and {len(ev) - 60} more")
    if note:
        lines += ["", note.strip()]
    lines += ["", "Please investigate and stop this activity — the machine may be compromised.",
              "This report was sent with AuroraPanel. Replies reach the sender.", "", "Thank you."]
    return "\n".join(lines)


def preview(ip: str) -> dict:
    ip = _public_ip(ip)
    from . import mail
    c = _conf()
    info = lookup(ip)
    ev = evidence(ip)
    # Abuse desks must be able to reply, so local-network (.local) addresses aren't offered.
    accounts = sorted(a for a in mail.load()["accounts"] if not mail.is_local(a.split("@")[1])) if mail.installed() else []
    rep = c["reported"].get(ip)
    return {"ip": ip, "info": info, "events": len(ev), "counts": _counts(ev), "from": c["from"] if c["from"] in accounts else "",
            "accounts": accounts, "mail_ready": mail.installed() and mail.configured(), "reported": rep,
            "summary": (_what(_counts(ev)) + " in the last 7 days") if ev else "Nothing logged from this address in the last 7 days",
            "body": _body(ip, info, ev, mail.hostname(), mail._public_ip(), "")}


def set_sender(addr: str) -> dict:
    from . import mail
    a = mail._addr(addr)
    if a not in mail.load()["accounts"]:
        raise AbuseError(f"{a} isn't an email account on this server")
    if mail.is_local(a.split("@")[1]):
        raise AbuseError("Pick an address on a real domain — nobody outside can reply to a .local address")
    c = _conf()
    c["from"] = a
    _save(c)
    return {"ok": True, "from": a}


def report(ip: str, sender: str = "", to: str = "", note: str = "", force: bool = False) -> dict:
    from . import mail
    ip = _public_ip(ip)
    if not (mail.installed() and mail.configured()):
        raise AbuseError("Reports are sent through this server's mail — set up Email first")
    c = _conf()
    if sender:
        set_sender(sender)
        c = _conf()
    frm = c["from"]
    if not frm or frm not in mail.load()["accounts"]:
        raise AbuseError("Choose the email account reports are sent from")
    prev = c["reported"].get(ip)
    if prev and time.time() - prev["ts"] < WEEK and not force:
        raise AbuseError(f"{ip} was already reported to {', '.join(prev['to'])} on "
                         f"{datetime.fromtimestamp(prev['ts']).strftime('%b %d')}")
    info = lookup(ip)
    rcpts = [mail._ext_addr(x) for x in ([to] if to else info["contacts"]) if x]
    if not rcpts:
        raise AbuseError(f"No abuse contact is published for {ip}")
    ev = evidence(ip)
    host = mail.hostname()
    subject = f"Abuse report: {ip} — {_what(_counts(ev))} against {host}"
    body = _body(ip, info, ev, host, mail._public_ip(), note)
    from email.message import EmailMessage
    from email.utils import formatdate
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = frm, ", ".join(rcpts), subject
    msg["Date"] = formatdate(usegmt=True)
    msg["Message-ID"] = f"<{secrets.token_hex(10)}@{frm.split('@')[1]}>"
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(body + "\n")  # headers are MIME-encoded, so any mail server accepts it
    r = subprocess.run(["/usr/sbin/sendmail", "-i", "-f", frm, "--", *rcpts], input=msg.as_bytes(),
                       capture_output=True, timeout=60)
    if r.returncode != 0:
        raise AbuseError(r.stderr.decode(errors="replace").strip()[-300:] or "sendmail failed")
    c["reported"][ip] = {"ts": int(time.time()), "to": rcpts, "from": frm, "events": len(ev)}
    _save(c)
    return {"ok": True, "to": rcpts, "from": frm, "events": len(ev)}


def reported() -> dict:
    return {ip: v for ip, v in _conf()["reported"].items()}
