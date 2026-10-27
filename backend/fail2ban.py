"""fail2ban — automatic brute-force protection (cPanel's "Leech Protection").

The panel owns one file, /etc/fail2ban/jail.d/zz-aurora.local, holding the
global defaults and every jail it manages; stock jail.conf is never edited.
Bans are written into the shared ban list (guard.py, nft sets f2b4/f2b6) via
the "aurora-guard" action, so they show up next to manual bans and work
whether or not ufw is enabled. Trusted addresses become fail2ban's ignoreip.

Jails: SSH, AuroraPanel logins, OpenVPN, FTP, Apache, Nginx, MariaDB,
port-scan (from the Network Monitor log) and recidive (repeat offenders)."""
from __future__ import annotations

import ast
import platform
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import jobs

IS_LINUX = platform.system() == "Linux"
LOCAL = Path("/etc/fail2ban/jail.d/zz-aurora.local")
ACTION = Path("/etc/fail2ban/action.d/aurora-guard.conf")
FILTERS = Path("/etc/fail2ban/filter.d")
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}

_CUSTOM_FILTERS = {
    "aurora-panel": """[INCLUDES]
before = common.conf

[Definition]
# AuroraPanel login failures (logged by the panel as: aurora-auth: fail user="..." ip=1.2.3.4)
failregex = ^%(__prefix_line)saurora-auth: fail user=.* ip=<HOST>\\s*$
ignoreregex =
journalmatch = _SYSTEMD_UNIT=aurorapanel.service
""",
    "aurora-openvpn": """[INCLUDES]
before = common.conf

[Definition]
# Wrong OpenVPN passwords (per-user logins) and TLS garbage from scanners.
failregex = ^%(__prefix_line)saurora-ovpn-auth: fail user=.* ip=<HOST>(?:\\s|$)
            ^%(__prefix_line)s<HOST>:\\d+ (?:TLS Error: tls-crypt unwrapping failed|TLS Error: TLS handshake failed|VERIFY ERROR)
ignoreregex =
journalmatch = _SYSTEMD_UNIT=openvpn-server@aurora.service
""",
    "aurora-portscan": """[INCLUDES]
before = common.conf

[Definition]
# New inbound connections recorded by the Network Monitor (kernel log, prefix aurora-conn:).
failregex = ^%(__prefix_line)s.*aurora-conn: .* SRC=<HOST>(?:\\s|$)
ignoreregex =
journalmatch = _TRANSPORT=kernel
""",
}

_ACTION_TEXT = """# Managed by AuroraPanel — ban into the panel's shared ban list (nft set f2b4/f2b6).
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = /usr/local/sbin/aurora-guard-ban add <ip> <bantime>
actionunban = /usr/local/sbin/aurora-guard-ban del <ip>
"""

# id: (label, what it protects, section settings, requirement check, default maxretry, default on)
JAILS = {
    "sshd": ("SSH logins", "Wrong SSH passwords / keys", {"filter": "sshd", "backend": "systemd", "port": "ssh"},
             lambda: True, 5, True),
    "aurora-panel": ("AuroraPanel logins", "Wrong passwords on this control panel", {"filter": "aurora-panel", "backend": "systemd"},
                     lambda: True, 5, True),
    "aurora-openvpn": ("OpenVPN", "Wrong OpenVPN passwords and scanner handshakes", {"filter": "aurora-openvpn", "backend": "systemd"},
                       lambda: Path("/etc/openvpn/server/aurora.conf").exists(), 5, True),
    "vsftpd": ("FTP logins", "Wrong FTP passwords", {"filter": "vsftpd", "backend": "auto", "logpath": "/var/log/vsftpd.log"},
               lambda: Path("/etc/vsftpd.conf").exists(), 5, True),
    "apache-auth": ("Apache password pages", "Failed .htpasswd / Directory Privacy logins",
                    {"filter": "apache-auth", "backend": "auto", "logpath": "/var/log/apache2/*error.log"},
                    lambda: Path("/var/log/apache2").is_dir(), 5, True),
    "apache-badbots": ("Apache bad bots", "Known spam / e-mail harvesting robots",
                       {"filter": "apache-badbots", "backend": "auto", "logpath": "/var/log/apache2/*access.log"},
                       lambda: Path("/var/log/apache2").is_dir(), 1, False),
    "apache-noscript": ("Apache script probing", "Requests for scripts that don't exist (exploit scanners)",
                        {"filter": "apache-noscript", "backend": "auto", "logpath": "/var/log/apache2/*error.log"},
                        lambda: Path("/var/log/apache2").is_dir(), 6, False),
    "nginx-http-auth": ("Nginx password pages", "Failed Nginx basic-auth logins",
                        {"filter": "nginx-http-auth", "backend": "auto", "logpath": "/var/log/nginx/error.log"},
                        lambda: Path("/var/log/nginx").is_dir(), 5, True),
    "nginx-botsearch": ("Nginx exploit scanners", "Probing for admin pages / known exploits",
                        {"filter": "nginx-botsearch", "backend": "auto", "logpath": "/var/log/nginx/access.log"},
                        lambda: Path("/var/log/nginx").is_dir(), 5, False),
    "postfix-sasl": ("Email sending logins", "Wrong passwords when sending mail (SMTP AUTH on 465/587)",
                     {"filter": "postfix[mode=auth]", "backend": "systemd", "port": "smtp,465,submission", "journalmatch": "_SYSTEMD_UNIT=postfix@-.service"},
                     lambda: Path("/etc/postfix/aurora").is_dir(), 5, True),
    "dovecot": ("Email reading logins", "Wrong IMAP / POP3 passwords",
                {"filter": "dovecot", "backend": "systemd", "port": "pop3,pop3s,imap,imaps,submission,465,sieve"},
                lambda: Path("/etc/dovecot/aurora-users").exists(), 5, True),
    "mysqld-auth": ("MariaDB logins", "Wrong database passwords from the network",
                    {"filter": "mysqld-auth", "backend": "systemd", "journalmatch": "_SYSTEMD_UNIT=mariadb.service"},
                    lambda: Path("/etc/mysql").is_dir(), 5, False),
    "aurora-portscan": ("Port scans / connection floods", "Many new connections from one address (needs Network Monitor logging on)",
                        {"filter": "aurora-portscan", "backend": "systemd"}, lambda: True, 40, False),
    "recidive": ("Repeat offenders", "Addresses banned again and again get a long ban",
                 {"filter": "recidive", "backend": "auto", "logpath": "/var/log/fail2ban.log", "bantime": "1w", "findtime": "1d"},
                 lambda: True, 3, True),
}
_DEFAULTS = {"bantime": 60, "findtime": 10, "maxretry": 5, "increment": True, "maxtime_days": 7}


class Fail2banError(RuntimeError):
    pass


def _client() -> str | None:
    return shutil.which("fail2ban-client", path=APT_ENV["PATH"]) if IS_LINUX else None


def install() -> jobs.Job:
    return jobs.launch("install fail2ban", ["apt-get", "-o", "DPkg::Lock::Timeout=600", "-y", "install", "fail2ban", "nftables"], env=APT_ENV)


# ---------------------------------------------------------------- config file
def _parse_local() -> dict:
    """Our own simple INI -> {section: {key: value}}."""
    out: dict[str, dict] = {}
    cur = None
    for line in (LOCAL.read_text(errors="replace").splitlines() if LOCAL.exists() else []):
        m = re.match(r"^\[(.+)\]\s*$", line.strip())
        if m:
            cur = out.setdefault(m.group(1), {})
            continue
        m = re.match(r"^([\w.]+)\s*=\s*(.*)$", line.strip())
        if m and cur is not None:
            cur[m.group(1)] = m.group(2)
    return out


def _minutes(v: str | None, default: int) -> int:
    """fail2ban time ('10m', '1h', '600', '-1') -> minutes (-1 = forever)."""
    if v is None or v == "":
        return default
    v = v.strip()
    if v.startswith("-"):
        return -1
    m = re.match(r"^(\d+)\s*([smhdw]?)$", v)
    if not m:
        return default
    n, u = int(m.group(1)), m.group(2) or "s"
    secs = n * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[u]
    return max(1, secs // 60)


def _t(minutes: int) -> str:
    return "-1" if int(minutes) < 0 else f"{int(minutes)}m"


def config() -> dict:
    loc = _parse_local()
    d = loc.get("DEFAULT", {})
    glob_ = {"bantime": _minutes(d.get("bantime"), _DEFAULTS["bantime"]), "findtime": _minutes(d.get("findtime"), _DEFAULTS["findtime"]),
             "maxretry": int(d.get("maxretry", _DEFAULTS["maxretry"])),
             "increment": d.get("bantime.increment", "true" if _DEFAULTS["increment"] else "false") == "true",
             "maxtime_days": _minutes(d.get("bantime.maxtime"), _DEFAULTS["maxtime_days"] * 1440) // 1440 or 1,
             "extra_ignore": _extra_ignore()}
    jails = []
    for jid, (label, desc, sect, req, dmax, don) in JAILS.items():
        s = loc.get(jid, {})
        avail = req()
        jails.append({"id": jid, "label": label, "desc": desc, "available": avail,
                      "enabled": (s.get("enabled", "true" if don else "false") == "true") if LOCAL.exists() else (don and avail),
                      "maxretry": int(s.get("maxretry", dmax)), "findtime": _minutes(s.get("findtime", sect.get("findtime")), -2),
                      "bantime": _minutes(s.get("bantime", sect.get("bantime")), -2)})
    return {"global": glob_, "jails": jails, "configured": LOCAL.exists()}


def _extra_ignore() -> str:
    """Addresses the admin typed into fail2ban's own ignore box — kept on a
    marker line so they're never confused with the (changing) trusted list."""
    if LOCAL.exists():
        m = re.search(r"(?m)^# aurora-extra-ignore:(.*)$", LOCAL.read_text(errors="replace"))
        if m:
            return m.group(1).strip()
    return ""


def _auto_ignore() -> list[str]:
    try:
        from . import guard
        return guard.trusted_cidrs()
    except Exception:
        return []


def _write(glob_: dict, jails: list[dict]) -> str:
    ignore = ["127.0.0.1/8", "::1"] + _auto_ignore() + [x for x in (glob_.get("extra_ignore") or "").split() if x]
    lines = ["# Managed by AuroraPanel — fail2ban settings (Security → Fail2ban). Edits here are overwritten.",
             f"# aurora-extra-ignore: {' '.join((glob_.get('extra_ignore') or '').split())}",
             "[DEFAULT]", f"bantime = {_t(glob_['bantime'])}", f"findtime = {_t(glob_['findtime'])}",
             f"maxretry = {int(glob_['maxretry'])}", f"bantime.increment = {'true' if glob_['increment'] else 'false'}",
             f"bantime.maxtime = {int(glob_['maxtime_days'])}d", f"ignoreip = {' '.join(dict.fromkeys(ignore))}",
             "banaction = aurora-guard", "banaction_allports = aurora-guard", ""]
    for j in jails:
        jid = j["id"]
        label, desc, sect, req, dmax, don = JAILS[jid]
        on = bool(j["enabled"]) and req()
        lines.append(f"[{jid}]")
        lines.append(f"enabled = {'true' if on else 'false'}")
        for k, v in sect.items():
            if k in ("bantime", "findtime") and j.get(k, -2) != -2:
                continue
            lines.append(f"{k} = {v}")
        lines.append(f"maxretry = {int(j['maxretry'])}")
        if j.get("findtime", -2) != -2:
            lines.append(f"findtime = {_t(j['findtime'])}")
        if j.get("bantime", -2) != -2:
            lines.append(f"bantime = {_t(j['bantime'])}")
        lines.append("")
    return "\n".join(lines)


def _prepare_support_files():
    from . import guard
    guard.ensure()
    ACTION.write_text(_ACTION_TEXT, encoding="utf-8")
    for name, text in _CUSTOM_FILTERS.items():
        (FILTERS / f"{name}.conf").write_text("# Managed by AuroraPanel\n" + text, encoding="utf-8")
    # File-based jails need their log to exist or fail2ban refuses to start.
    for p in ("/var/log/vsftpd.log", "/var/log/fail2ban.log"):
        if not Path(p).exists() and Path(p).parent.is_dir():
            Path(p).touch(mode=0o640)


def _reload_or_rollback(old: str | None):
    t = subprocess.run(["fail2ban-client", "-t"], capture_output=True, text=True, timeout=60)
    if t.returncode != 0:
        _restore(old)
        raise Fail2banError("fail2ban rejected the configuration, nothing changed:\n" + (t.stderr or t.stdout).strip()[-600:])
    active = subprocess.run(["systemctl", "is-active", "--quiet", "fail2ban"]).returncode == 0
    r = subprocess.run(["systemctl", "reload" if active else "restart", "fail2ban"], capture_output=True, text=True, timeout=120)
    time.sleep(1.5)
    if r.returncode != 0 or subprocess.run(["systemctl", "is-active", "--quiet", "fail2ban"]).returncode != 0:
        tail = subprocess.run(["journalctl", "-u", "fail2ban", "-n", "10", "--no-pager", "-o", "cat"], capture_output=True, text=True).stdout
        _restore(old)
        subprocess.run(["systemctl", "restart", "fail2ban"], capture_output=True, timeout=120)
        raise Fail2banError("fail2ban didn't start with the new settings, so they were undone:\n" + tail.strip()[-600:])


def _restore(old: str | None):
    if old is None:
        LOCAL.unlink(missing_ok=True)
    else:
        LOCAL.write_text(old, encoding="utf-8")


def save(glob_changes: dict | None, jail_changes: dict | None) -> dict:
    if not _client():
        raise Fail2banError("fail2ban is not installed")
    cur = config()
    g = {**cur["global"], **(glob_changes or {})}
    for k in ("bantime", "findtime"):
        g[k] = int(g[k])
        if g[k] == 0 or g[k] < -1 or g[k] > 525600:
            raise Fail2banError(f"{k}: minutes between 1 and 525600, or -1 for permanent bans")
    g["maxretry"] = int(g["maxretry"])
    if not 1 <= g["maxretry"] <= 1000:
        raise Fail2banError("Max retries: 1–1000")
    g["maxtime_days"] = max(1, min(int(g["maxtime_days"]), 3650))
    g["increment"] = bool(g["increment"])
    for x in (g.get("extra_ignore") or "").split():
        if not re.match(r"^[0-9a-fA-F.:/]+$", x):
            raise Fail2banError(f"Ignore list: '{x}' isn't an IP or range")
    jails = cur["jails"]
    for jid, ch in (jail_changes or {}).items():
        j = next((x for x in jails if x["id"] == jid), None)
        if not j:
            raise Fail2banError(f"Unknown jail {jid}")
        for k, v in ch.items():
            if k == "enabled":
                j[k] = bool(v)
            elif k in ("maxretry", "findtime", "bantime"):
                v = int(v)
                if k == "maxretry" and not 1 <= v <= 1000:
                    raise Fail2banError("Max retries: 1–1000")
                if k != "maxretry" and not (v == -2 or v == -1 and k == "bantime" or 1 <= v <= 525600):
                    raise Fail2banError(f"{k}: minutes (1–525600)" + (", or -1 = permanent" if k == "bantime" else ""))
                j[k] = v
    _prepare_support_files()
    old = LOCAL.read_text() if LOCAL.exists() else None
    LOCAL.write_text(_write(g, jails), encoding="utf-8")
    _reload_or_rollback(old)
    return {"ok": True, **status()}


def sync_ignoreip():
    """Rewrite ignoreip after the trusted list changed (no-op if we don't manage fail2ban yet)."""
    if not _client() or not LOCAL.exists():
        return
    cur = config()
    old = LOCAL.read_text()
    LOCAL.write_text(_write(cur["global"], cur["jails"]), encoding="utf-8")
    try:
        _reload_or_rollback(old)
    except Fail2banError:
        pass


def enable_service(on: bool) -> dict:
    if not _client():
        raise Fail2banError("fail2ban is not installed")
    if on:
        if not LOCAL.exists():
            return save({}, {})  # first start: write the panel's config (sane defaults)
        subprocess.run(["systemctl", "enable", "--now", "fail2ban"], capture_output=True, timeout=120)
    else:
        subprocess.run(["systemctl", "disable", "--now", "fail2ban"], capture_output=True, timeout=120)
    return status()


# ---------------------------------------------------------------- status / actions
def status() -> dict:
    if not _client():
        return {"installed": False, "active": False, "jails": [], "config": None}
    active = subprocess.run(["systemctl", "is-active", "--quiet", "fail2ban"]).returncode == 0
    live = {}
    if active:
        out = subprocess.run(["fail2ban-client", "status"], capture_output=True, text=True, timeout=15).stdout
        m = re.search(r"Jail list:\s*(.*)", out)
        for j in [x.strip() for x in (m.group(1).split(",") if m else []) if x.strip()]:
            js = subprocess.run(["fail2ban-client", "status", j], capture_output=True, text=True, timeout=15).stdout
            g = lambda rx: (re.search(rx, js) or [None, "0"])[1]  # noqa: E731
            ips = re.search(r"Banned IP list:\s*(.*)", js)
            live[j] = {"failed_now": int(g(r"Currently failed:\s*(\d+)")), "failed_total": int(g(r"Total failed:\s*(\d+)")),
                       "banned_now": int(g(r"Currently banned:\s*(\d+)")), "banned_total": int(g(r"Total banned:\s*(\d+)")),
                       "banned_ips": ips.group(1).split() if ips and ips.group(1).strip() else []}
    cfg = config()
    for j in cfg["jails"]:
        j["live"] = live.get(j["id"])
    other = [{"id": k, **v} for k, v in live.items() if k not in JAILS]
    return {"installed": True, "active": active, "config": cfg, "jails": cfg["jails"], "other_jails": other}


def _valid(jail: str, ip: str):
    if not re.match(r"^[A-Za-z0-9._-]+$", jail or "") or not re.match(r"^[0-9a-fA-F:.]+$", ip or ""):
        raise Fail2banError("Invalid jail or IP")


def unban(jail: str, ip: str) -> dict:
    if not _client():
        raise Fail2banError("fail2ban is not installed")
    _valid(jail, ip)
    out = subprocess.run(["fail2ban-client", "set", jail, "unbanip", ip], capture_output=True, text=True, timeout=15)
    if out.returncode != 0:
        raise Fail2banError(out.stderr.strip() or out.stdout.strip() or "unban failed")
    return {"ok": True}


def ban(jail: str, ip: str, client_ip: str | None = None) -> dict:
    if not _client():
        raise Fail2banError("fail2ban is not installed")
    _valid(jail, ip)
    from . import guard
    for net, why in guard._protected_nets(client_ip):
        import ipaddress
        try:
            if ipaddress.ip_address(ip) in net:
                raise Fail2banError(f"Refusing to ban {ip}: it's {why}")
        except ValueError:
            raise Fail2banError("Invalid IP")
    if guard.is_trusted(ip):
        raise Fail2banError(f"{ip} is trusted — remove it from Trusted first")
    out = subprocess.run(["fail2ban-client", "set", jail, "banip", ip], capture_output=True, text=True, timeout=15)
    if out.returncode != 0:
        raise Fail2banError(out.stderr.strip() or out.stdout.strip() or "ban failed")
    return {"ok": True}


LOG_FILES = (Path("/var/log/fail2ban.log.1"), Path("/var/log/fail2ban.log"))
_EVENT = re.compile(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ fail2ban\.(filter|actions)\s+\[\d+\]: \w+\s+\[([\w.-]+)\] (Found|Ban|Unban|Restore Ban) (\S+)")


def parse_events(text: str) -> list[dict]:
    """fail2ban log lines → {ts, jail, kind: failure|ban|unban, ip, restored}. Observer duplicates of 'Found' are skipped."""
    import datetime
    out = []
    for ln in text.splitlines():
        m = _EVENT.search(ln)
        if not m:
            continue
        ts_s, src, jail, what, ip = m.groups()
        if what == "Found" and src != "filter":
            continue
        try:
            ts = int(datetime.datetime.strptime(ts_s, "%Y-%m-%d %H:%M:%S").timestamp())
        except ValueError:
            continue
        kind = "failure" if what == "Found" else "unban" if what == "Unban" else "ban"
        out.append({"ts": ts, "jail": jail, "kind": kind, "ip": ip.rstrip(","), "restored": what == "Restore Ban"})
    return out


def events(limit: int = 400) -> dict:
    """What fail2ban did lately, newest first: the failed attempts it noticed, every ban and unban — read from its
    log (current and previous file; the journal when there is no log file). `status` says which of those addresses
    are banned or trusted right now, so the page can colour them."""
    out: list[dict] = []
    source = ""
    for p in LOG_FILES:
        try:
            out += parse_events(p.read_text(errors="replace"))
            source = source or str(p.with_suffix("")) if p.suffix == ".1" else str(p)
        except OSError:
            continue
    if not source:
        out = parse_events(subprocess.run(["journalctl", "-u", "fail2ban", "-n", "4000", "--no-pager", "-o", "short-iso"],
                                          capture_output=True, text=True).stdout)
        source = "journal"
    out.sort(key=lambda e: -e["ts"])
    out = out[:limit]
    status: dict = {}
    try:
        from . import guard
        status = guard.status_of(sorted({e["ip"] for e in out}))
    except Exception:
        pass
    return {"events": out, "status": status, "source": source or "/var/log/fail2ban.log"}


def logs(lines: int = 200) -> str:
    p = Path("/var/log/fail2ban.log")
    if p.exists() and p.stat().st_size:
        return "\n".join(p.read_text(errors="replace").splitlines()[-lines:])
    return subprocess.run(["journalctl", "-u", "fail2ban", "-n", str(lines), "--no-pager", "-o", "short-iso"],
                          capture_output=True, text=True).stdout
