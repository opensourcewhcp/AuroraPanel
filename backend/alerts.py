"""Alerts — tell the owner when something needs attention, by email, Telegram or a webhook.

check() is run every minute by the task runner (backend/tasks.py, a systemd timer — so it still
works when the panel itself is down). Each problem has a key; an alert is sent when it starts,
repeated as a reminder (daily by default) while it lasts, and a "resolved" note when it ends.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.request
from datetime import datetime
from pathlib import Path

STATE = Path("/var/lib/aurora/alerts.json")
SNOOZE = Path("/var/lib/aurora/alerts-snooze.json")  # own file: written from Slack buttons in the panel process
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
LEVELS = {"critical": 3, "warning": 2, "info": 1}
WATCH_DEFAULT = ["apache2", "nginx", "mariadb", "postgresql", "postfix", "dovecot", "rspamd", "named", "fail2ban", "vsftpd",
                 "wg-quick@wg0", "openvpn-server@server", "docker", "php*-fpm"]


class AlertError(RuntimeError):
    pass


def _default() -> dict:
    return {
        "channels": {"email": {"enabled": False, "to": "", "from": ""},
                     "telegram": {"enabled": False, "token": "", "chat_id": ""},
                     "webhook": {"enabled": False, "url": "", "kind": "generic"}},
        "rules": {"disk_pct": 90, "mem_pct": 95, "temp_c": 80, "cert_days": 14, "waf_burst": 50, "login_fails": 20,
                  "services": True, "backups": True, "updates": True, "reboot": True, "power": True},
        "min_level": "warning", "remind_hours": 24, "quiet": False,
        "active": {}, "history": [],
    }


def load() -> dict:
    try:
        s = json.loads(STATE.read_text())
    except (OSError, ValueError):
        s = {}
    d = _default()
    for k, v in s.items():
        if isinstance(v, dict) and isinstance(d.get(k), dict) and k not in ("active",):
            for kk, vv in v.items():
                if isinstance(vv, dict) and isinstance(d[k].get(kk), dict):
                    d[k][kk].update(vv)
                else:
                    d[k][kk] = vv
        else:
            d[k] = v
    return d


def _save(s: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_name(f".{STATE.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(s, indent=1))
    os.chmod(tmp, 0o600)  # holds a bot token / webhook secret
    tmp.replace(STATE)


def public(s: dict | None = None) -> dict:
    s = s or load()
    ch = json.loads(json.dumps(s["channels"]))
    if ch["telegram"].get("token"):
        ch["telegram"]["token_set"] = True
        ch["telegram"]["token"] = ""
    if ch["webhook"].get("url"):
        u = ch["webhook"]["url"]
        ch["webhook"]["url_hint"] = re.sub(r"(https?://[^/]+/).{0,}", r"\1…", u)
    accounts = []
    try:
        from . import mail
        if mail.installed():
            accounts = sorted(a for a in mail.load()["accounts"] if not mail.is_local(a.split("@")[1]))
    except Exception:
        pass
    return {"channels": ch, "rules": s["rules"], "min_level": s["min_level"], "remind_hours": s["remind_hours"], "quiet": s["quiet"],
            "active": sorted(s["active"].values(), key=lambda a: (-LEVELS.get(a["level"], 0), -a["since"])),
            "history": s["history"][-200:][::-1], "mail_accounts": accounts, "sendmail": bool(shutil.which("sendmail", path=PATH)),
            "host": socket.getfqdn() or socket.gethostname()}


def update(data: dict) -> dict:
    s = load()
    ch = data.get("channels") or {}
    if "email" in ch:
        e = ch["email"]
        to = str(e.get("to", "")).strip()
        if to and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", to):
            raise AlertError("That email address doesn't look right")
        s["channels"]["email"].update(enabled=bool(e.get("enabled")), to=to, **({"from": str(e.get("from", "")).strip()} if "from" in e else {}))
    if "telegram" in ch:
        t = ch["telegram"]
        if t.get("token"):
            if not re.match(r"^\d+:[\w-]{30,}$", t["token"].strip()):
                raise AlertError("A Telegram bot token looks like 123456789:AA… — copy it from @BotFather")
            s["channels"]["telegram"]["token"] = t["token"].strip()
        if "chat_id" in t:
            cid = str(t["chat_id"]).strip()
            if cid and not re.match(r"^(-?\d{3,20}|@[\w]{4,})$", cid):
                raise AlertError("The chat ID is a number (like 123456789 or -100…) or a @channel name")
            s["channels"]["telegram"]["chat_id"] = cid
        s["channels"]["telegram"]["enabled"] = bool(t.get("enabled"))
    if "webhook" in ch:
        w = ch["webhook"]
        if w.get("url"):
            u = w["url"].strip()
            if not re.match(r"^https?://[^\s]+$", u):
                raise AlertError("The webhook must be an http(s):// URL")
            s["channels"]["webhook"]["url"] = u
        if w.get("kind") in ("generic", "discord", "slack", "ntfy"):
            s["channels"]["webhook"]["kind"] = w["kind"]
        s["channels"]["webhook"]["enabled"] = bool(w.get("enabled"))
    if "rules" in data:
        r = data["rules"]
        nums = {"disk_pct": (50, 99), "mem_pct": (50, 100), "temp_c": (50, 100), "cert_days": (1, 60), "waf_burst": (5, 10000), "login_fails": (3, 1000)}
        for k, (lo, hi) in nums.items():
            if k in r:
                s["rules"][k] = max(lo, min(hi, int(r[k])))
        for k in ("services", "backups", "updates", "reboot", "power"):
            if k in r:
                s["rules"][k] = bool(r[k])
    if data.get("min_level") in LEVELS:
        s["min_level"] = data["min_level"]
    if "remind_hours" in data:
        s["remind_hours"] = max(0, min(24 * 14, int(data["remind_hours"])))
    if "quiet" in data:
        s["quiet"] = bool(data["quiet"])
    _save(s)
    return public(s)


# ------------------------------------------------------------------ snooze (Slack "Snooze 24 h")
def _snoozes() -> dict:
    try:
        d = json.loads(SNOOZE.read_text())
        return {k: v for k, v in d.items() if v > time.time()}
    except (OSError, ValueError):
        return {}


def snoozed(key: str) -> bool:
    return key in _snoozes()


def snooze(key: str, hours: float) -> None:
    """No reminders for this problem on any channel until then (0 = reminders back on)."""
    d = _snoozes()
    if hours > 0:
        d[key] = time.time() + hours * 3600
    else:
        d.pop(key, None)
    SNOOZE.parent.mkdir(parents=True, exist_ok=True)
    tmp = SNOOZE.with_name(f".{SNOOZE.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(d))
    tmp.replace(SNOOZE)


def _slack_on() -> bool:
    try:
        from . import slackbot
        return slackbot.enabled()
    except Exception:
        return False


# ------------------------------------------------------------------ sending
def _post(url: str, payload: bytes, ctype: str, headers: dict | None = None) -> None:
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": ctype, "User-Agent": "AuroraPanel", **(headers or {})})
    with urllib.request.urlopen(req, timeout=15) as r:
        r.read(1000)


def _default_from() -> str:
    """aurora@<hostname>.local when local mail is on — a real address that webmail can reply
    to and that passes the receiving server's checks; else the machine's full name."""
    try:
        from . import mail
        local = mail.local_domain_name()
        if local in mail.load().get("domains", {}):
            return f"aurora@{local}"
    except Exception:
        pass
    host = socket.getfqdn() or "localhost"
    return f"aurora@{host if '.' in host else host + '.local'}"


def _send_email(c: dict, subject: str, body: str) -> None:
    from email.message import EmailMessage
    from email.utils import formatdate
    to = c["to"]
    frm = c.get("from") or _default_from()
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = frm, to, subject
    msg["Date"] = formatdate(localtime=True)
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(body + "\n")
    r = subprocess.run(["sendmail", "-i", "-f", frm, "--", to], input=msg.as_bytes(), capture_output=True, timeout=60,
                       env={**os.environ, "PATH": PATH})
    if r.returncode != 0:
        raise AlertError(r.stderr.decode(errors="replace").strip()[-200:] or "sendmail failed")


def _send(s: dict, level: str, title: str, text: str, key: str = "", extra: dict | None = None) -> list[str]:
    host = socket.getfqdn() or socket.gethostname()
    icon = {"critical": "🔴", "warning": "🟠", "info": "🔵", "resolved": "✅"}.get(level, "•")
    subject = f"{icon} [{host}] {title}"
    body = f"{title}\n\n{text}\n\nServer: {host}\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M %Z')}\n— AuroraPanel"
    sent, errors = [], []
    c = s["channels"]
    if c["email"]["enabled"] and c["email"]["to"]:
        try:
            _send_email(c["email"], subject, body)
            sent.append("email")
        except Exception as e:
            errors.append(f"email: {e}")
    if c["telegram"]["enabled"] and c["telegram"]["token"] and c["telegram"]["chat_id"]:
        try:
            _post(f"https://api.telegram.org/bot{c['telegram']['token']}/sendMessage",
                  json.dumps({"chat_id": c["telegram"]["chat_id"], "text": f"{icon} {title}\n{text}\n\n{host}", "disable_web_page_preview": True}).encode(),
                  "application/json")
            sent.append("telegram")
        except Exception as e:
            errors.append(f"telegram: {re.sub(r'bot[^/]+/', 'bot…/', str(e))}")
    if _slack_on():
        try:
            from . import slackbot
            slackbot.notify_alert(level, title, text, key, extra)
            sent.append("slack")
        except Exception as e:
            errors.append(f"slack: {e}")
    w = c["webhook"]
    if w["enabled"] and w["url"]:
        try:
            if w["kind"] == "discord":
                _post(w["url"], json.dumps({"content": f"{icon} **{title}**\n{text}\n_{host}_"[:1900]}).encode(), "application/json")
            elif w["kind"] == "slack":
                _post(w["url"], json.dumps({"text": f"{icon} *{title}*\n{text}\n_{host}_"}).encode(), "application/json")
            elif w["kind"] == "ntfy":
                _post(w["url"], text.encode(), "text/plain", {"Title": f"[{host}] {title}"[:200].encode("ascii", "replace").decode(),
                                                          "Priority": {"critical": "urgent", "warning": "high"}.get(level, "default"),
                                                          "Tags": {"critical": "rotating_light", "warning": "warning", "resolved": "white_check_mark"}.get(level, "information_source")})
            else:
                _post(w["url"], json.dumps({"level": level, "title": title, "message": text, "server": host, "time": int(time.time())}).encode(), "application/json")
            sent.append("webhook")
        except Exception as e:
            errors.append(f"webhook: {e}")
    if errors and not sent:
        raise AlertError("; ".join(errors))
    return sent + [f"!{e}" for e in errors]


def test() -> dict:
    s = load()
    if not any(ch.get("enabled") for ch in s["channels"].values()) and not _slack_on():
        raise AlertError("Turn on at least one channel first")
    res = _send(s, "info", "Test alert", "If you can read this, AuroraPanel alerts reach you. 🎉")
    return {"sent": [x for x in res if not x.startswith("!")], "errors": [x[1:] for x in res if x.startswith("!")]}


# ------------------------------------------------------------------ checks
def _run(argv, timeout=20) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={**os.environ, "PATH": PATH}).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _units() -> list[str]:
    """Watched services that are installed (enabled) on this machine."""
    out = _run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--plain"])
    enabled = {l.split()[0].removesuffix(".service") for l in out.splitlines() if l.strip()}
    units = []
    for w in WATCH_DEFAULT:
        if "*" in w:
            rx = re.compile("^" + w.replace("*", ".*") + "$")
            units += sorted(u for u in enabled if rx.match(u))
        elif w in enabled:
            units.append(w)
    return units


def _cert_expiries() -> list[tuple[str, float]]:
    paths = []
    live = Path("/etc/letsencrypt/live")
    if live.is_dir():
        paths += [(d.name, d / "cert.pem") for d in live.iterdir() if (d / "cert.pem").exists()]
    out = []
    for name, p in paths:
        txt = _run(["openssl", "x509", "-noout", "-enddate", "-in", str(p)])
        m = re.search(r"notAfter=(.+)", txt)
        if m:
            try:
                out.append((name, datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z").timestamp()))
            except ValueError:
                pass
    return out


def collect(s: dict) -> dict[str, tuple]:
    """key -> (level, title, details[, extra]) for every problem present right now; extra carries
    what buttons need (e.g. the attacking IPs, for Ban/Trust in Slack)."""
    import psutil
    r = s["rules"]
    found: dict[str, tuple[str, str, str]] = {}
    seen_dev = set()
    for part in psutil.disk_partitions(all=False):
        if part.device in seen_dev or part.fstype in ("squashfs", "tmpfs", "devtmpfs", "overlay") or part.mountpoint.startswith(("/snap", "/boot/efi")):
            continue
        seen_dev.add(part.device)
        try:
            u = psutil.disk_usage(part.mountpoint)
        except OSError:
            continue
        if u.percent >= r["disk_pct"]:
            lvl = "critical" if u.percent >= 97 else "warning"
            found[f"disk:{part.mountpoint}"] = (lvl, f"Disk {part.mountpoint} is {u.percent:.0f}% full",
                                               f"{u.free / 1e9:.1f} GB free of {u.total / 1e9:.1f} GB. Disk Usage in the panel shows what's big; old backups and logs are the usual suspects.")
    vm = psutil.virtual_memory()
    if vm.percent >= r["mem_pct"]:
        found["mem"] = ("warning", f"Memory is {vm.percent:.0f}% used", f"{vm.available / 1e6:.0f} MB available. Resource Usage shows which software uses it.")
    try:
        temps = psutil.sensors_temperatures()
        for k in ("cpu_thermal", "coretemp", "k10temp", "soc_thermal"):
            if temps.get(k):
                t = temps[k][0].current
                if t >= r["temp_c"]:
                    found["temp"] = ("critical" if t >= r["temp_c"] + 5 else "warning", f"CPU is hot: {t:.0f}°C",
                                     "Check the fan/heatsink and airflow. A Raspberry Pi slows itself down above 80–85°C.")
                break
    except (AttributeError, OSError):
        pass
    if r["power"] and shutil.which("vcgencmd", path=PATH):
        m = re.search(r"throttled=0x([0-9a-f]+)", _run(["vcgencmd", "get_throttled"]))
        if m and int(m.group(1), 16) & 0x5:
            found["power"] = ("critical", "Raspberry Pi power problem: under-voltage or throttling right now",
                              "Use the official power supply and a short, thick USB-C cable. Under-voltage corrupts SD cards.")
    if r["services"]:
        units = _units()
        if units:
            out = _run(["systemctl", "is-active", *units])
            for u, st in zip(units, out.split()):
                if st in ("failed", "inactive"):
                    found[f"svc:{u}"] = ("critical", f"Service {u} is {'down (failed)' if st == 'failed' else 'stopped'}",
                                         f"It's enabled to run but isn't. Services → Status shows why; Restart usually brings it back.")
    now = time.time()
    for name, exp in _cert_expiries():
        days = (exp - now) / 86400
        if days < r["cert_days"]:
            found[f"cert:{name}"] = ("critical" if days < 3 else "warning",
                                     f"Certificate for {name} {'has expired' if days < 0 else f'expires in {days:.0f} days'}",
                                     "Certbot renews automatically 30 days ahead, so this means renewal is failing. SSL/TLS → Renew shows the error.")
    try:
        from . import waf
        if waf.installed():
            ev = [e for e in waf.events(hours=1, limit=5000) if e["ts"] >= now - 600 and e["blocked"]]
            if len(ev) >= r["waf_burst"]:
                ips = {}
                for e in ev:
                    ips[e["ip"]] = ips.get(e["ip"], 0) + 1
                top = ", ".join(f"{ip} ×{n}" for ip, n in sorted(ips.items(), key=lambda x: -x[1])[:5])
                found["waf"] = ("warning", f"Attack wave: the WAF blocked {len(ev)} requests in 10 minutes", f"Top sources: {top}. You can ban them from Security → WAF Firewall.",
                                {"ips": sorted(ips.items(), key=lambda x: -x[1])[:5]})
    except Exception:
        pass
    try:
        from . import audit
        fails = [e for e in audit.entries(days=1, q="login failed")["entries"] if e["ts"] >= now - 900]
        if len(fails) >= r["login_fails"]:
            per: dict[str, int] = {}
            for e in fails:
                per[e["ip"]] = per.get(e["ip"], 0) + 1
            found["logins"] = ("warning", f"{len(fails)} failed panel logins in 15 minutes",
                               f"From: {', '.join(sorted(per)[:6])}. Fail2ban bans repeat offenders; make sure 2FA is on.",
                               {"ips": sorted(per.items(), key=lambda x: -x[1])[:5]})
    except Exception:
        pass
    if r["backups"]:
        try:
            from . import schedules
            for p in schedules.load()["plans"]:
                last = p.get("last") or {}
                if p.get("enabled") and last.get("ok") is False:
                    found[f"backup:{p['id']}"] = ("critical", f"Backup “{p['name']}” failed", last.get("error", "")[:300] or "See Scheduled Backups for the log.")
                elif p.get("enabled") and p.get("last_ok_ts") and now - p["last_ok_ts"] > schedules.period(p) * 2 + 3600:
                    found[f"backup:{p['id']}:stale"] = ("warning", f"Backup “{p['name']}” hasn't succeeded since {datetime.fromtimestamp(p['last_ok_ts']):%b %d}",
                                                       "Scheduled Backups shows the last runs.")
        except Exception:
            pass
    if r["updates"]:
        try:
            from . import updates
            u = updates.cached()
            if u.get("security"):
                found["updates"] = ("warning", f"{u['security']} security update{'s' if u['security'] != 1 else ''} waiting",
                                    "System → Updates installs them in one click (or turn on automatic security updates).")
        except Exception:
            pass
    if r["reboot"] and Path("/var/run/reboot-required").exists():
        pk = ""
        try:
            pk = ", ".join(sorted(set(Path("/var/run/reboot-required.pkgs").read_text().split()))[:6])
        except OSError:
            pass
        found["reboot"] = ("info", "A restart is needed to finish updates", f"Updated: {pk or 'system packages'}. Restart from System → Updates when convenient.")
    return found


def check() -> dict:
    """Compare what's wrong now with what was wrong last time; notify about the differences."""
    s = load()
    try:
        found = collect(s)
    except Exception as e:  # never let a broken check stop the runner
        found = {"alerts:error": ("warning", "Alert checks failed", str(e)[:300])}
    now = time.time()
    min_lvl = LEVELS.get(s["min_level"], 2)
    active = s["active"]
    channels_on = any(c.get("enabled") for c in s["channels"].values()) or _slack_on()
    snoozes = _snoozes()
    sent_any = []
    for key, (level, title, text, *more) in found.items():
        extra = more[0] if more else None
        a = active.get(key)
        notify = LEVELS.get(level, 1) >= min_lvl and channels_on and not s["quiet"]
        if not a:
            active[key] = a = {"key": key, "level": level, "title": title, "text": text, "since": now, "last_sent": 0}
            s["history"].append({"ts": now, "key": key, "level": level, "title": title, "event": "started"})
        else:
            a.update(level=level, title=title, text=text)
        due = not a["last_sent"] or (s["remind_hours"] and now - a["last_sent"] >= s["remind_hours"] * 3600 and key not in snoozes)
        if notify and due:
            try:
                _send(s, level, title + (" (still)" if a["last_sent"] else ""), text, key, extra)
                a["last_sent"] = now
                sent_any.append(key)
            except Exception as e:
                a["send_error"] = str(e)[:200]
    for key in [k for k in active if k not in found]:
        a = active.pop(key)
        s["history"].append({"ts": now, "key": key, "level": a["level"], "title": a["title"], "event": "resolved"})
        if a.get("last_sent") and channels_on and not s["quiet"]:
            try:
                _send(s, "resolved", f"Resolved: {a['title']}", f"Back to normal after {_dur(now - a['since'])}.")
            except Exception:
                pass
    s["history"] = s["history"][-500:]
    s["checked"] = now
    _save(s)
    reports = []
    try:  # Slack: one message per new attacker, with Ban / Trust / Allow-rule buttons
        from . import slackbot
        reports = slackbot.security_scan()
    except Exception as e:
        print(f"alerts: Slack reports failed: {e}", flush=True)
    return {"active": len(active), "sent": sent_any, "reports": reports}


def _dur(sec: float) -> str:
    return f"{sec / 60:.0f} min" if sec < 3600 else f"{sec / 3600:.1f} h" if sec < 86400 else f"{sec / 86400:.1f} days"
