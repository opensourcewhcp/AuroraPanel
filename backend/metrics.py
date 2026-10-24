"""Metrics — Visitors, Errors, Bandwidth, Raw Access, Analytics and Resource Usage.

Everything is read from the logs the server already writes (Apache access/error logs, the
journal for mail/DNS/database, vsftpd's log) — no tracking code in the sites. A background
collector (start()) keeps the history that logs lose when they're rotated:
  * bandwidth per protocol (HTTP, IMAP, POP3, SMTP, FTP, network interfaces) in 5-minute,
    hourly and daily bins, plus per-site daily hits/pages/bytes/visitors;
  * resource usage (CPU, memory, swap, load, disk I/O, network, processes, temperature)
    every minute for a day, every 10 minutes for a month, hourly for a year.
It reads only what was appended since the last pass (by inode + offset), so it stays cheap on a Pi.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import subprocess
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

LOG_DIR = Path("/var/log/apache2")
SITES_DIR = Path("/etc/apache2/sites-enabled")
STATE_DIR = Path("/var/lib/aurora/metrics")
BW_FILE = STATE_DIR / "bandwidth.json"
RES_FILE = STATE_DIR / "resources.json"
LOGROTATE = Path("/etc/logrotate.d/apache2")
VSFTPD_LOG = Path("/var/log/vsftpd.log")
PROTOS = ("http", "imap", "pop3", "smtp", "ftp")
MAX_READ = 64 * 1024 * 1024  # never read more than this from one log in one go
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class MetricsError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
_Q = r'"((?:[^"\\]|\\.)*)"'
_COMBINED = re.compile(r'^(\S+) \S+ (\S+) \[([^\]]+)\] ' + _Q + r' (\d{3}) (\d+|-)(?: ' + _Q + ' ' + _Q + ')?')
_VHOST = re.compile(r'^(\S+?):(\d+) (\S+) \S+ (\S+) \[([^\]]+)\] ' + _Q + r' (\d{3}) (\d+|-)(?: ' + _Q + ' ' + _Q + ')?')
_MON = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_tz_cache: dict[str, int] = {}


def _clf_time(s: str) -> float:
    """'24/Oct/2026:09:35:38 +0300' → epoch seconds (fast; logs can have 100k lines)."""
    try:
        d, mon, rest = s[:2], s[3:6], s[7:]
        y, hh, mm, ss = int(rest[0:4]), int(rest[5:7]), int(rest[8:10]), int(rest[11:13])
        tz = rest[14:19]
        off = _tz_cache.get(tz)
        if off is None:
            sign = -1 if tz[0] == "-" else 1
            off = _tz_cache[tz] = sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
        return datetime(y, _MON[mon], int(d), hh, mm, ss, tzinfo=timezone.utc).timestamp() - off
    except (ValueError, KeyError, IndexError):
        return 0.0


def parse_access(line: str, vhost_fmt: bool = False) -> dict | None:
    if vhost_fmt:
        m = _VHOST.match(line)
        if not m:
            return None
        vh, port, ip, user, t, req, st, size, ref, ua = m.groups()
    else:
        m = _COMBINED.match(line)
        if not m:
            return None
        ip, user, t, req, st, size, ref, ua = m.groups()
        vh, port = "", ""
    parts = req.split(" ")
    method, url, proto = (parts + ["", "", ""])[:3] if len(parts) >= 2 else ("", req, "")
    return {"ts": _clf_time(t), "ip": ip, "user": "" if user == "-" else user, "method": method[:12], "url": url[:2000],
            "proto": proto[:12], "status": int(st), "size": 0 if size == "-" else int(size),
            "ref": "" if ref in (None, "-") else ref[:1000], "ua": "" if ua in (None, "-") else ua[:500],
            "vhost": vh, "port": port}


_BOT = re.compile(r"bot\b|bot/|crawl|spider|slurp|curl/|wget/|python|go-http|zgrab|masscan|nmap|scan|httpclient|java/|libwww|okhttp|"
                  r"headless|axios|node-fetch|facebookexternalhit|preview|monitor|uptime|checker|validator|fetcher|apache-httpclient|"
                  r"wordpress/|feedparser|ahrefs|semrush|mj12|dotbot|petalbot|bytespider|gptbot|ccbot|censys|expanse|"
                  r"internetmeasurement|^-?$", re.I)
_STATIC = re.compile(r"\.(css|js|mjs|png|jpe?g|gif|svg|ico|webp|avif|bmp|tiff?|heic|woff2?|ttf|otf|eot|map|mp4|webm|mp3|ogg|wav|pdf|zip|gz|"
                     r"txt|xml|json|webmanifest)$", re.I)


def _bot_name(u: str) -> str:
    """A readable name for a crawler/tool: the product token that isn't the generic Mozilla/5.0."""
    if not u:
        return "(empty user agent)"
    m = re.search(r"([A-Za-z][\w.-]*(?:bot|Bot|BOT|crawler|Crawler|spider|Spider|scan|Scan|Scanner))", u)
    if m:
        return m.group(1)
    m = re.search(r"compatible;\s*([^;/)]+)", u) or re.search(r"\(([A-Za-z][\w.-]+)/", u)
    if m:
        return m.group(1).strip()
    toks = [x.split("/")[0] for x in re.findall(r"[A-Za-z][\w.-]*/[\w.-]+", u) if not x.startswith("Mozilla/")]
    if toks:
        return toks[0]
    m = re.search(r"(zgrab|masscan|nmap|curl|wget)", u, re.I)
    return m.group(1) if m else u.split("/")[0][:40]


def classify_ua(ua: str) -> dict:
    u = ua or ""
    bot = bool(_BOT.search(u))
    if re.search(r"Edg(e|A|iOS)?/", u): br = "Edge"
    elif re.search(r"OPR/|Opera", u): br = "Opera"
    elif "SamsungBrowser" in u: br = "Samsung Internet"
    elif re.search(r"Firefox/|FxiOS", u): br = "Firefox"
    elif re.search(r"Chrome/|CriOS", u): br = "Chrome"
    elif "Safari/" in u and "Version/" in u: br = "Safari"
    elif re.search(r"MSIE|Trident/", u): br = "Internet Explorer"
    elif bot:
        br = _bot_name(u)
    else: br = "Other"
    if "Windows NT 10" in u: os_ = "Windows 10/11"
    elif "Windows" in u: os_ = "Windows"
    elif "Android" in u: os_ = "Android"
    elif re.search(r"iPhone|iPad|iPod", u): os_ = "iOS"
    elif "Mac OS X" in u or "Macintosh" in u: os_ = "macOS"
    elif "CrOS" in u: os_ = "ChromeOS"
    elif "Linux" in u: os_ = "Linux"
    else: os_ = "Unknown"
    dev = "bot" if bot else "tablet" if re.search(r"iPad|Tablet", u) else "phone" if re.search(r"Mobile|iPhone|Android", u) else "desktop"
    return {"bot": bot, "browser": br, "os": os_, "device": dev}


def is_page(url: str, status: int) -> bool:
    path = url.split("?", 1)[0]
    return status < 400 and status not in (301, 302, 304) and not _STATIC.search(path)


# --------------------------------------------------------------------------- #
# Sites and their logs
# --------------------------------------------------------------------------- #
def _apache_vars(s: str) -> str:
    return s.replace("${APACHE_LOG_DIR}", str(LOG_DIR)).strip('"')


def sites() -> list[dict]:
    """One entry per access log: which names (and http/https) write to it."""
    logs: dict[str, dict] = {}

    def add(log: str, fmt: str, names: list[str], port: str, err: str):
        e = logs.setdefault(log, {"log": log, "names": [], "ports": set(), "vhost_fmt": fmt == "vhost_combined", "error_logs": set()})
        for n in names:
            if n and n not in e["names"]:
                e["names"].append(n)
        if port:
            e["ports"].add(port)
        if err:
            e["error_logs"].add(err)

    if SITES_DIR.exists():
        for f in sorted(SITES_DIR.glob("*.conf")):
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            for block in re.findall(r"(?is)<VirtualHost\s+([^>]*)>(.*?)</VirtualHost>", text):
                addr, body = block
                port = (re.search(r":(\d+)", addr) or [None, ""])[1]
                names = re.findall(r"(?im)^\s*ServerName\s+(\S+)", body)
                for a in re.findall(r"(?im)^\s*ServerAlias\s+(.+)$", body):
                    names += a.split()
                cl = re.search(r"(?im)^\s*CustomLog\s+(\S+)\s+(\S+)", body)
                el = re.search(r"(?im)^\s*ErrorLog\s+(\S+)", body)
                err = _apache_vars(el.group(1)) if el else str(LOG_DIR / "error.log")
                if cl:
                    add(_apache_vars(cl.group(1)), cl.group(2), names, port, err)
                else:
                    add(str(LOG_DIR / "other_vhosts_access.log"), "vhost_combined", names, port, err)
    add(str(LOG_DIR / "access.log"), "combined", [], "", str(LOG_DIR / "error.log"))
    out = []
    for e in logs.values():
        p = Path(e["log"])
        base = p.name
        sid = re.sub(r"(-access)?\.log$", "", base) or base
        if base == "access.log":
            label, kind = "Default site (IP address & unknown names)", "default"
        elif base == "other_vhosts_access.log":
            label, kind = "Sites without their own log", "shared"
        else:
            label, kind = (e["names"][0] if e["names"] else sid), "site"
        files = rotated(p)
        out.append({"id": sid, "label": label, "kind": kind, "log": str(p), "names": e["names"], "vhost_fmt": e["vhost_fmt"],
                    "ssl": "443" in e["ports"], "http": bool(e["ports"] - {"443"}) or not e["ports"],
                    "error_logs": sorted(e["error_logs"]), "exists": p.exists(),
                    "size": sum(f["size"] for f in files), "updated": max((f["mtime"] for f in files), default=0)})
    order = {"site": 0, "shared": 1, "default": 2}
    from . import authz
    sc = authz.scope()
    if sc is not None:  # a website manager: only logs that belong to their sites
        mine = {n.lower() for n in sc["domains"]} | {"www." + n for n in sc["domains"]}
        out = [s for s in out if s["kind"] == "site" and mine & {n.lower() for n in s["names"]}]
    return sorted(out, key=lambda s: (order[s["kind"]], s["label"]))


def site(sid: str) -> dict:
    for s in sites():
        if s["id"] == sid:
            return s
    raise MetricsError("Unknown site")


def rotated(p: Path) -> list[dict]:
    """The log and its rotations, newest first: x.log, x.log.1, x.log.2.gz …"""
    out = []
    if p.exists():
        st = p.stat()
        out.append({"name": p.name, "path": str(p), "size": st.st_size, "mtime": int(st.st_mtime), "gz": False, "n": 0})
    for f in p.parent.glob(p.name + ".*"):
        m = re.fullmatch(re.escape(p.name) + r"\.(\d+)(\.gz)?", f.name)
        if m and f.is_file():
            st = f.stat()
            out.append({"name": f.name, "path": str(f), "size": st.st_size, "mtime": int(st.st_mtime), "gz": bool(m.group(2)), "n": int(m.group(1))})
    return sorted(out, key=lambda x: x["n"])


def _read_lines(path: str, max_bytes: int = MAX_READ) -> list[str]:
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rb") as f:
                data = f.read(max_bytes * 4)
        else:
            with open(path, "rb") as f:
                size = os.fstat(f.fileno()).st_size
                if size > max_bytes:
                    f.seek(size - max_bytes)
                    f.readline()
                data = f.read()
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()


def _entries(s: dict, since: float = 0, max_files: int = 30, names: list[str] | None = None):
    """Yield parsed entries from s's log (+ rotations), newest file first, each file oldest→newest."""
    for f in rotated(Path(s["log"]))[:max_files]:
        if since and f["mtime"] < since:
            break
        for line in _read_lines(f["path"]):
            e = parse_access(line, s["vhost_fmt"])
            if not e or (since and e["ts"] < since):
                continue
            if names and e["vhost"] and e["vhost"].lower() not in names:
                continue
            yield f["n"], e


# --------------------------------------------------------------------------- #
# Visitors
# --------------------------------------------------------------------------- #
def visitors(sid: str, limit: int = 1000, hours: int = 0, name: str = "") -> dict:
    s = site(sid)
    limit = max(1, min(int(limit), 20000))
    since = time.time() - hours * 3600 if hours else 0
    names = [name.lower()] if name else None
    by_file: dict[int, list] = defaultdict(list)
    total = 0
    for n, e in _entries(s, since, names=names):
        by_file[n].append(e)
        total += 1
        if not since and total > limit * 3 and n > 0:
            break
    rows = []
    for n in sorted(by_file):
        rows += reversed(by_file[n])
        if len(rows) >= limit:
            break
    rows = rows[:limit]
    uas: dict[str, dict] = {}
    for r in rows:
        c = uas.get(r["ua"])
        if c is None:
            c = uas[r["ua"]] = classify_ua(r["ua"])
        r.update(c)
        r["page"] = is_page(r["url"], r["status"])
    ips = Counter(r["ip"] for r in rows)
    try:
        from . import guard
        ipstat = guard.status_of(list(ips)[:2000])
    except Exception:
        ipstat = {}
    own = {n.lower() for n in s["names"]}
    try:
        from . import dnszones
        own |= dnszones._my_ips()
    except Exception:
        pass
    return {"site": s, "rows": rows, "total": len(rows), "own": sorted(own),
            "period": [rows[-1]["ts"], rows[0]["ts"]] if rows else None,
            "bytes": sum(r["size"] for r in rows), "unique_ips": len(ips),
            "bots": sum(1 for r in rows if r["bot"]), "errors": sum(1 for r in rows if r["status"] >= 400),
            "ip_status": {ip: st for ip, st in ipstat.items() if st}}


# --------------------------------------------------------------------------- #
# Errors — every source, sorted into categories with a plain-language hint
# --------------------------------------------------------------------------- #
_ERR = re.compile(r"^\[(?P<time>[^\]]+)\] \[(?:(?P<mod>[^:\]]+):)?(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)[^\]]*\]\s*(?P<rest>.*)$")
_CLIENT = re.compile(r"\[client ([^\]]+)\]\s*")
CATEGORIES = {
    "missing": ("Missing files", "Something asked for a file or script that doesn't exist. Mostly scanners probing for well-known paths — "
                "fix only the ones your own pages link to."),
    "permission": ("Permission denied", "Apache (user www-data) can't read a file or folder. Fix ownership/permissions — "
                   "Files → Fix Home Permissions does it for website folders."),
    "htaccess": ("Configuration / .htaccess", "A .htaccess or config line Apache doesn't understand — usually a module that isn't "
                 "enabled (e.g. rewrite, headers) or a typo."),
    "php_fatal": ("PHP fatal errors", "A PHP script crashed: the visitor got a blank page or 500 error. The message names the file and line."),
    "php_warn": ("PHP warnings & notices", "PHP kept running but something is off (deprecated calls, undefined variables). "
                 "Usually harmless; update the plugin/theme that causes them."),
    "security": ("Blocked attacks & bad requests", "Malformed or malicious requests that Apache or the WAF refused. Nothing to fix — "
                 "this is the protection working. Repeat offenders can be banned from Network Monitor."),
    "proxy": ("Proxy / backend", "Apache couldn't reach an app it forwards to (webmail, calendars, a Node/Python app)."),
    "ssl": ("SSL / TLS", "Certificate or handshake problems — expired certificates, clients with outdated TLS."),
    "timeout": ("Timeouts & limits", "A request took too long or hit a size/memory limit."),
    "server": ("Server start-up & runtime", "Apache itself starting, stopping or reloading, and worker/process messages."),
    "mail": ("Mail server", "Postfix (SMTP), Dovecot (IMAP/POP3) and Rspamd: delivery problems, failed logins, TLS issues."),
    "database": ("Database", "MariaDB/MySQL and PostgreSQL warnings and errors."),
    "dns": ("DNS server", "BIND9: zone loading problems, refused transfers, lame servers."),
    "php_fpm": ("PHP-FPM", "PHP's process manager: pools running out of workers, slow scripts."),
    "panel": ("AuroraPanel", "This control panel's own service."),
    "system": ("System", "Kernel and other system errors: out-of-memory kills, disk and hardware problems."),
    "other": ("Other", "Messages that don't fit another category."),
}


def _err_category(mod: str, level: str, msg: str) -> str:
    m, lo = (mod or "").lower(), msg.lower()
    if m == "security2" or "modsecurity" in lo or "ah10244" in lo or "invalid uri" in lo or "request failed" in lo \
            or "client sent malformed" in lo or "ah02429" in lo or "ah00126" in lo or "invalid method" in lo:
        return "security"
    if "permission denied" in lo or "ah00035" in lo or "ah01630" in lo or "client denied by server" in lo:
        return "permission"
    if "htaccess" in lo or "invalid command" in lo or "ah00526" in lo or "ah00529" in lo:
        return "htaccess"
    if "php fatal" in lo or "php parse error" in lo or "uncaught" in lo:
        return "php_fatal"
    if "php warning" in lo or "php notice" in lo or "php deprecated" in lo:
        return "php_warn"
    if "not found or unable to stat" in lo or "file does not exist" in lo or "ah01264" in lo or "ah00128" in lo or "ah01071" in lo and "primary script unknown" in lo:
        return "missing"
    if m.startswith("proxy") or "ah01114" in lo or "ah00957" in lo:
        return "proxy"
    if m == "ssl" or "ssl" in lo and "handshake" in lo:
        return "ssl"
    if "timeout" in lo or "timed out" in lo or "limit" in lo and "exceed" in lo:
        return "timeout"
    if m in ("mpm_prefork", "mpm_event", "mpm_worker", "core", "unique_id") and level in ("notice", "info", "warn"):
        return "server"
    if m == "php" or m.startswith("proxy_fcgi"):
        return "php_warn" if level.startswith("warn") or level == "notice" else "php_fatal"
    return "other"


def _err_time(s: str) -> float:
    for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return 0.0


def _pattern(msg: str) -> str:
    """Messages that differ only in numbers, IPs, paths or quoted values group together."""
    p = re.sub(r"\[client [^\]]+\]", "", msg)
    p = re.sub(r", referer: \S+", "", p)
    p = re.sub(r"(/[\w.@%+~-]+)+/?", "/…", p)
    p = re.sub(r"\b\d+(\.\d+)*\b", "#", p)
    p = re.sub(r"'[^']*'|\"[^\"]*\"", "'…'", p)
    return p.strip()[:240]


def _apache_errors(paths: list[str], since: float) -> list[dict]:
    out = []
    for path in paths:
        for f in rotated(Path(path))[:8]:
            if f["mtime"] < since:
                break
            for line in _read_lines(f["path"], 16 * 1024 * 1024):
                m = _ERR.match(line)
                if not m or '[id "920350"]' in line:  # site opened by IP address: WAF bookkeeping, not an error
                    continue
                ts = _err_time(m.group("time"))
                if ts < since:
                    continue
                rest = m.group("rest")
                c = _CLIENT.search(rest)
                client = c.group(1).rsplit(":", 1)[0] if c else ""
                msg = _CLIENT.sub("", rest)
                ref = ""
                if ", referer: " in msg:
                    msg, ref = msg.rsplit(", referer: ", 1)
                code = (re.search(r"\b(AH\d{5})\b", msg) or [None, ""])[1]
                mod, level = m.group("mod") or "", m.group("level")
                out.append({"ts": ts, "source": "web", "mod": mod, "level": level, "client": client, "code": code,
                            "msg": msg[:2000], "referer": ref[:500], "file": Path(path).name,
                            "cat": _err_category(mod, level, msg)})
    return out


_UNITS = {"mail": ["postfix@-.service", "postfix.service", "dovecot.service", "rspamd.service"],
          "database": ["mariadb.service", "mysql.service", "postgresql@*.service"],
          "dns": ["named.service", "bind9.service"], "panel": ["aurorapanel.service"], "php_fpm": ["php*-fpm.service"]}


def _journal_errors(cat: str, since: float, prio: str = "warning") -> list[dict]:
    args = ["journalctl", "-o", "json", "--no-pager", "-p", prio, "--since", f"@{int(since)}", "-n", "3000"]
    if cat == "system":
        args += ["-k"]
    else:
        for u in _UNITS[cat]:
            args += ["-u", u]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30, env={**os.environ, "PATH": PATH})
    except (OSError, subprocess.TimeoutExpired):
        return []
    out = []
    for line in r.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        msg = j.get("MESSAGE")
        if isinstance(msg, list):
            msg = bytes(msg).decode("utf-8", "replace")
        if not msg:
            continue
        p = int(j.get("PRIORITY", 6))
        unit = (j.get("_SYSTEMD_UNIT") or j.get("SYSLOG_IDENTIFIER") or "kernel").replace(".service", "")
        ip = (re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", msg) or [None, ""])[1]
        out.append({"ts": int(j.get("__REALTIME_TIMESTAMP", 0)) / 1e6, "source": cat, "mod": unit,
                    "level": ["emerg", "alert", "crit", "error", "warn", "notice", "info", "debug"][min(p, 7)],
                    "client": ip, "code": "", "msg": msg[:2000], "referer": "", "file": "journal", "cat": cat})
    return out


def errors(sid: str = "", hours: int = 24, sources: str = "web,mail,database,dns,php_fpm,panel,system",
           start: float = 0, end: float = 0) -> dict:
    """Errors of the last `hours`, or only those in [start, end) when a bar of the
    timeline was clicked (still within the period, so the logs read stay bounded)."""
    since = time.time() - max(1, min(hours, 24 * 31)) * 3600
    if start:
        since = max(since, start)
    want = set(sources.split(","))
    from . import authz
    if authz.scope() is not None:  # a website manager: their own sites' web errors only
        if not sid:
            mine = sites()
            if not mine:
                raise MetricsError("No websites")
            sid = mine[0]["id"]
        want = {"web"}
    items: list[dict] = []
    if "web" in want:
        if sid:
            paths = site(sid)["error_logs"]
        else:
            paths = sorted({p for s in sites() for p in s["error_logs"]})
        items += _apache_errors(paths, since)
    for cat in ("mail", "database", "dns", "php_fpm", "panel", "system"):
        if cat in want:
            items += _journal_errors(cat, since, "err" if cat == "system" else "warning")
    if end:
        items = [e for e in items if e["ts"] < end]
    items.sort(key=lambda e: -e["ts"])
    groups: dict[tuple, dict] = {}
    for e in items:
        k = (e["cat"], e["mod"], _pattern(e["msg"]))
        g = groups.get(k)
        if g is None:
            g = groups[k] = {"cat": e["cat"], "mod": e["mod"], "level": e["level"], "pattern": k[2], "example": e,
                             "count": 0, "first": e["ts"], "last": e["ts"], "clients": Counter()}
        g["count"] += 1
        g["first"] = min(g["first"], e["ts"])
        if e["client"]:
            g["clients"][e["client"]] += 1
    glist = []
    for g in groups.values():
        g["clients"] = g["clients"].most_common(5)
        glist.append(g)
    glist.sort(key=lambda g: (-g["last"]))
    counts = Counter(e["cat"] for e in items)
    levels = Counter(e["level"] for e in items)
    hist = Counter(int(e["ts"] // 3600) * 3600 for e in items)
    # Per hour and category, so the timeline shows what happened, not just how much.
    hist_cat: dict[int, Counter] = {}
    for e in items:
        hist_cat.setdefault(int(e["ts"] // 3600) * 3600, Counter())[e["cat"]] += 1
    return {"items": items[:3000], "groups": glist[:1000], "total": len(items), "counts": dict(counts), "levels": dict(levels),
            "categories": {k: {"label": v[0], "hint": v[1]} for k, v in CATEGORIES.items()},
            "hourly": sorted(hist.items()), "hourly_cats": sorted((h, dict(c)) for h, c in hist_cat.items()), "hours": hours}


# --------------------------------------------------------------------------- #
# Collector: bandwidth + per-site daily stats + resource usage
# --------------------------------------------------------------------------- #
_lock = threading.Lock()
_bw: dict | None = None
_res: dict | None = None
_last_collect = 0.0
_prev_res: dict = {}


def _load_json(p: Path, default: dict) -> dict:
    try:
        d = json.loads(p.read_text())
        return d if isinstance(d, dict) else default
    except (OSError, ValueError):
        return default


def _save_json(p: Path, d: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.{threading.get_ident()}.tmp")  # unique: two writers never share it
    tmp.write_text(json.dumps(d, separators=(",", ":")))
    tmp.replace(p)


def _bw_state() -> dict:
    global _bw
    if _bw is None:
        _bw = _load_json(BW_FILE, {})
        for k in ("files", "m5", "h", "d", "site_d", "site_ips", "journal"):
            _bw.setdefault(k, {})
    return _bw


def _day(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def _add(bw: dict, ts: float, proto: str, nbytes: int, now: float) -> None:
    if ts < now - 400 * 86400 or nbytes <= 0:
        return
    if ts >= now - 2 * 86400:
        k = str(int(ts // 300) * 300)
        b = bw["m5"].setdefault(k, {})
        b[proto] = b.get(proto, 0) + nbytes
    if ts >= now - 35 * 86400:
        k = str(int(ts // 3600) * 3600)
        b = bw["h"].setdefault(k, {})
        b[proto] = b.get(proto, 0) + nbytes
    b = bw["d"].setdefault(_day(ts), {})
    b[proto] = b.get(proto, 0) + nbytes


def _ingest_http(bw: dict, s: dict, e: dict, now: float, uas: dict) -> None:
    _add(bw, e["ts"], "http", e["size"], now)
    day = _day(e["ts"])
    key = s["id"]
    if s["kind"] == "shared" and e["vhost"]:
        key = "vh:" + e["vhost"].lower()
    d = bw["site_d"].setdefault(day, {}).setdefault(key, {"bytes": 0, "hits": 0, "pages": 0, "visitors": 0, "bots": 0, "errors": 0})
    d["bytes"] += e["size"]
    d["hits"] += 1
    c = uas.get(e["ua"])
    if c is None:
        c = uas[e["ua"]] = classify_ua(e["ua"])
    if c["bot"]:
        d["bots"] += 1
    elif is_page(e["url"], e["status"]):
        d["pages"] += 1
    if e["status"] >= 400:
        d["errors"] += 1
    if not c["bot"]:
        ips = bw["site_ips"].setdefault(day, {}).setdefault(key, {})
        if e["ip"] not in ips:
            ips[e["ip"]] = 1
            d["visitors"] += 1


def _tail_file(bw: dict, path: Path, first_run_backfill: bool):
    """New lines of path since the last pass (handles rotation: finishes the .1 file first)."""
    try:
        st = path.stat()
    except OSError:
        return []
    rec = bw["files"].get(str(path))
    lines: list[str] = []
    if rec is None:
        if first_run_backfill:
            for f in reversed(rotated(path)[1:15]):  # oldest rotation first
                lines += _read_lines(f["path"])
            start = 0
        else:
            start = st.st_size  # a new file appearing later: start at its end? no — read it all
            start = 0
    elif rec["ino"] != st.st_ino:
        old = path.with_name(path.name + ".1")
        try:
            if old.exists() and old.stat().st_ino == rec["ino"]:
                with open(old, "rb") as f:
                    f.seek(rec["off"])
                    lines += f.read(MAX_READ).decode("utf-8", "replace").splitlines()
        except OSError:
            pass
        start = 0
    else:
        start = rec["off"] if rec["off"] <= st.st_size else 0
    try:
        with open(path, "rb") as f:
            f.seek(start)
            data = f.read(MAX_READ)
            end = start + len(data)
            # Don't consume a half-written last line.
            cut = data.rfind(b"\n")
            if cut != len(data) - 1:
                end = start + cut + 1
                data = data[:cut + 1]
    except OSError:
        return lines
    bw["files"][str(path)] = {"ino": st.st_ino, "off": end}
    return lines + data.decode("utf-8", "replace").splitlines()


def _journal_bytes(bw: dict, now: float) -> None:
    cur = bw["journal"].get("cursor")
    args = ["journalctl", "-o", "json", "--no-pager", "-u", "dovecot.service", "-u", "postfix@-.service", "-u", "postfix.service",
            "--output-fields=MESSAGE,__REALTIME_TIMESTAMP,__CURSOR"]
    args += ["--after-cursor", cur] if cur else ["--since", f"@{int(now - 2 * 86400)}"]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=60, env={**os.environ, "PATH": PATH})
    except (OSError, subprocess.TimeoutExpired):
        return
    last = cur
    for line in r.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        last = j.get("__CURSOR", last)
        msg = j.get("MESSAGE")
        if not isinstance(msg, str):
            continue
        ts = int(j.get("__REALTIME_TIMESTAMP", 0)) / 1e6
        if msg.startswith("imap(") or "imap(" in msg[:40]:
            m = re.search(r"in=(\d+) out=(\d+)", msg)
            if m:
                _add(bw, ts, "imap", int(m.group(1)) + int(m.group(2)), now)
        elif msg.startswith("pop3(") or "pop3(" in msg[:40]:
            m = re.search(r"retr=\d+/(\d+)", msg)
            t = re.search(r"top=\d+/(\d+)", msg)
            n = (int(m.group(1)) if m else 0) + (int(t.group(1)) if t else 0)
            if n:
                _add(bw, ts, "pop3", n, now)
        elif ": from=<" in msg and "size=" in msg:
            m = re.search(r"size=(\d+), nrcpt=(\d+)", msg)
            if m:
                _add(bw, ts, "smtp", int(m.group(1)) * max(1, int(m.group(2))), now)
    if last:
        bw["journal"]["cursor"] = last


_FTP = re.compile(r"^\w{3} (\w{3}) +(\d+) (\d\d:\d\d:\d\d) (\d{4}) .*OK (?:UP|DOWN)LOAD: .*?, (\d+) bytes")


def _ftp_bytes(bw: dict, now: float, first: bool) -> None:
    if not VSFTPD_LOG.exists():
        return
    for line in _tail_file(bw, VSFTPD_LOG, first):
        m = _FTP.match(line)
        if m:
            try:
                ts = datetime.strptime(f"{m.group(2)} {m.group(1)} {m.group(4)} {m.group(3)}", "%d %b %Y %H:%M:%S").timestamp()
            except ValueError:
                continue
            _add(bw, ts, "ftp", int(m.group(5)), now)


def _prune(bw: dict, now: float) -> None:
    for k, keep in (("m5", 2 * 86400), ("h", 35 * 86400)):
        for t in [t for t in bw[k] if int(t) < now - keep]:
            del bw[k][t]
    old = _day(now - 400 * 86400)
    for k in ("d", "site_d"):
        for t in [t for t in bw[k] if t < old]:
            del bw[k][t]
    keep_ips = {_day(now), _day(now - 86400)}
    for t in [t for t in bw["site_ips"] if t not in keep_ips]:
        del bw["site_ips"][t]


def collect_bandwidth() -> None:
    now = time.time()
    with _lock:
        bw = _bw_state()
        first = not bw.get("initialized")
        uas: dict[str, dict] = {}
        for s in sites():
            p = Path(s["log"])
            for line in _tail_file(bw, p, first):
                e = parse_access(line, s["vhost_fmt"])
                if e and e["ts"]:
                    _ingest_http(bw, s, e, now, uas)
        _journal_bytes(bw, now)
        _ftp_bytes(bw, now, first)
        _prune(bw, now)
        bw["initialized"] = True
        bw["updated"] = now
        _save_json(BW_FILE, bw)


def _net_totals() -> tuple[int, int]:
    rx = tx = 0
    try:
        for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
            name, data = line.split(":", 1)
            name = name.strip()
            if name == "lo" or name.startswith(("veth", "docker", "br-")):
                continue
            f = data.split()
            rx += int(f[0])
            tx += int(f[8])
    except (OSError, ValueError, IndexError):
        pass
    return rx, tx


def _sample_resources() -> dict | None:
    try:
        import psutil
    except ImportError:
        return None
    now = time.time()
    vm, sm = psutil.virtual_memory(), psutil.swap_memory()
    io = psutil.disk_io_counters()
    rx, tx = _net_totals()
    cur = {"t": now, "rd": io.read_bytes if io else 0, "wr": io.write_bytes if io else 0,
           "ops": (io.read_count + io.write_count) if io else 0, "rx": rx, "tx": tx}
    prev = _prev_res.copy()
    _prev_res.update(cur)
    try:
        load1 = os.getloadavg()[0]
    except OSError:
        load1 = 0.0
    temp = None
    try:
        temps = psutil.sensors_temperatures()
        for key in ("cpu_thermal", "coretemp", "k10temp", "soc_thermal", "acpitz"):
            if temps.get(key):
                temp = round(temps[key][0].current, 1)
                break
    except (AttributeError, OSError):
        pass
    s = {"cpu": round(psutil.cpu_percent(interval=None), 1), "mem": round(vm.used / 1048576), "mem_pct": round(vm.percent, 1),
         "swap": round(sm.used / 1048576), "load": round(load1, 2), "procs": len(psutil.pids()), "temp": temp}
    if prev:
        dt = max(1.0, now - prev["t"])
        s.update(io_r=round(max(0, cur["rd"] - prev["rd"]) / dt), io_w=round(max(0, cur["wr"] - prev["wr"]) / dt),
                 iops=round(max(0, cur["ops"] - prev["ops"]) / dt, 1),
                 net_rx=round(max(0, cur["rx"] - prev["rx"]) / dt), net_tx=round(max(0, cur["tx"] - prev["tx"]) / dt))
        # Interface traffic also counts as bandwidth ("all traffic", including VPN and SSH).
        with _lock:
            bw = _bw_state()
            _add(bw, now, "net_rx", max(0, cur["rx"] - prev["rx"]), now)
            _add(bw, now, "net_tx", max(0, cur["tx"] - prev["tx"]), now)
    return s


_RES_KEYS = ("cpu", "mem", "mem_pct", "swap", "load", "procs", "temp", "io_r", "io_w", "iops", "net_rx", "net_tx")


def _res_state() -> dict:
    global _res
    if _res is None:
        _res = _load_json(RES_FILE, {})
        for k in ("m1", "m10", "h"):
            _res.setdefault(k, [])
        _res.setdefault("faults", [])
    return _res


def _roll(points: list, period: int, keep: int, sample: dict, now: float) -> None:
    """Average samples into bins of `period` seconds; each point is [t, {key: avg}, n]."""
    t = int(now // period) * period
    if points and points[-1][0] == t:
        avg, n = points[-1][1], points[-1][2]
        for k in _RES_KEYS:
            v = sample.get(k)
            if v is None:
                continue
            avg[k] = round((avg.get(k, v) * n + v) / (n + 1), 2)
            avg[k + "_max"] = max(avg.get(k + "_max", v), v)
        points[-1][2] = n + 1
    else:
        points.append([t, {k: v for k, v in sample.items() if v is not None} | {k + "_max": v for k, v in sample.items() if v is not None}, 1])
    cutoff = now - keep
    while points and points[0][0] < cutoff:
        points.pop(0)


def collect_resources() -> None:
    s = _sample_resources()
    if not s:
        return
    now = time.time()
    with _lock:
        r = _res_state()
        _roll(r["m1"], 60, 86400, s, now)
        _roll(r["m10"], 600, 31 * 86400, s, now)
        _roll(r["h"], 3600, 366 * 86400, s, now)


def _faults_scan() -> None:
    """Out-of-memory kills and Pi under-voltage/throttling, kept for the Resource Usage page."""
    now = time.time()
    with _lock:
        r = _res_state()
        since = r.get("faults_scanned", now - 7 * 86400)
    found = []
    try:
        out = subprocess.run(["journalctl", "-k", "-o", "short-unix", "--no-pager", "--since", f"@{int(since)}",
                              "-g", "Out of memory|oom-kill|Killed process|Under-voltage|throttl"],
                             capture_output=True, text=True, timeout=30, env={**os.environ, "PATH": PATH}).stdout
        for line in out.splitlines():
            parts = line.split(" ", 2)
            try:
                ts = float(parts[0])
            except (ValueError, IndexError):
                continue
            msg = parts[2] if len(parts) > 2 else line
            kind = "oom" if re.search(r"memory|oom|Killed process", msg, re.I) else "power"
            found.append({"ts": ts, "kind": kind, "msg": msg[:300]})
    except (OSError, subprocess.TimeoutExpired):
        pass
    with _lock:
        r = _res_state()
        r["faults"] = (r["faults"] + found)[-500:]
        r["faults_scanned"] = now


def start() -> None:
    """Background collector: resources every minute, logs every 5 minutes, saved to disk every 5."""
    if os.name != "posix" or not Path("/proc").exists() or getattr(start, "_started", False):
        return
    start._started = True

    def loop():
        n = 0
        try:
            import psutil
            psutil.cpu_percent(interval=None)
        except Exception:
            pass
        while True:
            try:
                collect_resources()
                if n % 5 == 0:
                    collect_bandwidth()
                    _faults_scan()
                    with _lock:
                        _save_json(RES_FILE, _res_state())
            except Exception:
                pass
            n += 1
            time.sleep(60)

    threading.Thread(target=loop, name="aurora-metrics", daemon=True).start()


def _fresh() -> None:
    global _last_collect
    if time.time() - _last_collect > 60:
        _last_collect = time.time()
        try:
            collect_bandwidth()
        except Exception:
            pass


def bandwidth() -> dict:
    _fresh()
    with _lock:
        bw = _bw_state()
        now = time.time()
        series = {
            "day": sorted((int(t), v) for t, v in bw["m5"].items() if int(t) >= now - 86400),
            "week": sorted((int(t), v) for t, v in bw["h"].items() if int(t) >= now - 7 * 86400),
            "month": sorted((int(t), v) for t, v in bw["h"].items() if int(t) >= now - 30 * 86400),
            "year": sorted(bw["d"].items()),
        }
        site_d = json.loads(json.dumps(bw["site_d"]))
    labels = {}
    for s in sites():
        labels[s["id"]] = s["label"]
    months: dict[str, dict] = defaultdict(lambda: defaultdict(lambda: {"bytes": 0, "hits": 0, "pages": 0, "visitors": 0}))
    for day, per in site_d.items():
        for sid, v in per.items():
            m = months[day[:7]][sid]
            for k in ("bytes", "hits", "pages", "visitors"):
                m[k] += v.get(k, 0)
    month_tot = {}
    for day, v in series["year"]:
        mt = month_tot.setdefault(day[:7], {})
        for p, n in v.items():
            mt[p] = mt.get(p, 0) + n
    return {"series": series, "months": {m: dict(v) for m, v in months.items()}, "month_totals": month_tot,
            "labels": {**labels, **{k: k[3:] for m in months.values() for k in m if k.startswith("vh:")}},
            "protos": ["http", "imap", "pop3", "smtp", "ftp"], "tz": time.strftime("%Z"), "updated": bw.get("updated")}


def resources(span: str = "day") -> dict:
    with _lock:
        r = _res_state()
        now = time.time()
        if span == "hour":
            pts = [p for p in r["m1"] if p[0] >= now - 3600]
        elif span == "day":
            pts = list(r["m1"]) if len(r["m1"]) > 30 else [p for p in r["m10"] if p[0] >= now - 86400]
        elif span == "week":
            pts = [p for p in r["m10"] if p[0] >= now - 7 * 86400]
        elif span == "month":
            pts = list(r["m10"])
        else:
            pts = list(r["h"])
        faults = [f for f in r["faults"] if f["ts"] >= now - 31 * 86400]
    try:
        import psutil
        vm = psutil.virtual_memory()
        info = {"cpus": psutil.cpu_count(), "mem_total": round(vm.total / 1048576), "swap_total": round(psutil.swap_memory().total / 1048576),
                "boot": psutil.boot_time()}
        procs = []
        for p in psutil.process_iter(["pid", "name", "username", "memory_info", "cpu_percent", "cmdline"]):
            mi = p.info.get("memory_info")
            procs.append({"pid": p.info["pid"], "name": p.info.get("name") or "", "user": p.info.get("username") or "",
                          "rss": mi.rss if mi else 0, "cpu": p.info.get("cpu_percent") or 0})
        apps: dict[str, dict] = {}
        for p in procs:
            a = apps.setdefault(_app_name(p["name"]), {"rss": 0, "cpu": 0.0, "n": 0})
            a["rss"] += p["rss"]
            a["cpu"] += p["cpu"]
            a["n"] += 1
        top = sorted(({"name": k, **v} for k, v in apps.items()), key=lambda a: -a["rss"])[:12]
    except Exception:
        info, top = {}, []
    return {"span": span, "points": [[p[0], p[1]] for p in pts], "faults": faults, "info": info, "apps": top}


_APPS = [("apache2", "Apache"), ("httpd", "Apache"), ("php-fpm", "PHP-FPM"), ("mariadbd", "MariaDB"), ("mysqld", "MariaDB"),
         ("postgres", "PostgreSQL"), ("named", "DNS (BIND)"), ("dovecot", "Mail (Dovecot)"), ("imap", "Mail (Dovecot)"),
         ("pop3", "Mail (Dovecot)"), ("rspamd", "Mail (Rspamd)"), ("redis", "Redis"), ("master", "Mail (Postfix)"),
         ("smtpd", "Mail (Postfix)"), ("qmgr", "Mail (Postfix)"), ("pickup", "Mail (Postfix)"), ("tlsmgr", "Mail (Postfix)"),
         ("python", "Python apps / AuroraPanel"), ("uvicorn", "AuroraPanel"), ("node", "Node.js apps"), ("fail2ban", "Fail2ban"),
         ("clam", "ClamAV"), ("freshclam", "ClamAV"), ("radicale", "Calendars (Radicale)"), ("sshd", "SSH"), ("systemd", "systemd"),
         ("vsftpd", "FTP"), ("wg", "WireGuard"), ("openvpn", "OpenVPN"), ("charon", "IPsec")]


def _app_name(proc: str) -> str:
    for pre, name in _APPS:
        if proc.startswith(pre):
            return name
    return proc or "?"


# --------------------------------------------------------------------------- #
# Raw access: files, download, retention
# --------------------------------------------------------------------------- #
def raw() -> dict:
    out = []
    for s in sites():
        files = rotated(Path(s["log"]))
        errs = []
        if s["kind"] == "site":
            for p in s["error_logs"]:
                if Path(p).name != "error.log":
                    errs += rotated(Path(p))
        out.append({**s, "files": files, "error_files": errs})
    rot = retention()
    total = sum(f["size"] for p in LOG_DIR.glob("*") if p.is_file() for f in [{"size": p.stat().st_size}]) if LOG_DIR.exists() else 0
    return {"sites": out, "retention": rot, "disk": total}


def log_file(name: str) -> Path:
    """A downloadable file: only names inside /var/log/apache2 that belong to an access/error log."""
    if not re.fullmatch(r"[\w.-]+\.log(\.\d+)?(\.gz)?", name or ""):
        raise MetricsError("Unknown log file")
    p = LOG_DIR / name
    if not p.is_file() or p.parent != LOG_DIR:
        raise MetricsError("Unknown log file")
    return p


def retention() -> dict:
    try:
        text = LOGROTATE.read_text()
    except OSError:
        return {"supported": False}
    rot = re.search(r"(?m)^\s*rotate\s+(\d+)", text)
    freq = re.search(r"(?m)^\s*(daily|weekly|monthly)\b", text)
    n = int(rot.group(1)) if rot else 14
    f = freq.group(1) if freq else "daily"
    days = n * {"daily": 1, "weekly": 7, "monthly": 30}[f]
    return {"supported": True, "rotate": n, "frequency": f, "days": days, "compress": bool(re.search(r"(?m)^\s*compress\b", text))}


def set_retention(days: int) -> dict:
    days = int(days)
    if days not in (7, 14, 30, 60, 90, 180, 365):
        raise MetricsError("Choose 7, 14, 30, 60, 90, 180 or 365 days")
    text = LOGROTATE.read_text()
    text = re.sub(r"(?m)^(\s*)(weekly|monthly)\b", r"\1daily", text)
    if re.search(r"(?m)^\s*rotate\s+\d+", text):
        text = re.sub(r"(?m)^(\s*)rotate\s+\d+", rf"\g<1>rotate {days}", text)
    else:
        text = text.replace("{", "{\n\trotate %d" % days, 1)
    LOGROTATE.write_text(text)
    return retention()


# --------------------------------------------------------------------------- #
# Analytics — an AWStats-style report, computed from the logs (+ the collector's history)
# --------------------------------------------------------------------------- #
_SEARCH = [("google.", "Google", "q"), ("bing.", "Bing", "q"), ("duckduckgo.", "DuckDuckGo", "q"), ("yandex.", "Yandex", "text"),
           ("baidu.", "Baidu", "wd"), ("yahoo.", "Yahoo", "p"), ("ecosia.", "Ecosia", "q"), ("search.brave", "Brave Search", "q"),
           ("qwant.", "Qwant", "q"), ("startpage.", "Startpage", "query")]
_SOCIAL = {"facebook.com": "Facebook", "m.facebook.com": "Facebook", "l.facebook.com": "Facebook", "t.co": "X (Twitter)",
           "x.com": "X (Twitter)", "twitter.com": "X (Twitter)", "instagram.com": "Instagram", "l.instagram.com": "Instagram",
           "linkedin.com": "LinkedIn", "lnkd.in": "LinkedIn", "reddit.com": "Reddit", "out.reddit.com": "Reddit", "pinterest.com": "Pinterest",
           "youtube.com": "YouTube", "t.me": "Telegram", "vk.com": "VK", "news.ycombinator.com": "Hacker News", "tiktok.com": "TikTok"}


def analytics(sid: str, days: int = 30, file: str = "", name: str = "") -> dict:
    s = site(sid)
    own = {n.lower() for n in s["names"]}
    names = [name.lower()] if name else None
    since = time.time() - max(1, min(days, 400)) * 86400
    if file:
        p = log_file(file)
        if not p.name.startswith(Path(s["log"]).name):
            raise MetricsError("That file doesn't belong to this site")
        src = ((0, e) for e in (parse_access(l, s["vhost_fmt"]) for l in _read_lines(str(p))) if e)
        since = 0
    else:
        src = _entries(s, since, names=names)
    uas: dict[str, dict] = {}
    hits = pages = nbytes = bot_hits = bot_bytes = 0
    first = last = None
    by_day: dict[str, dict] = defaultdict(lambda: {"hits": 0, "pages": 0, "bytes": 0, "visitors": set(), "visits": 0})
    by_hour = [{"hits": 0, "pages": 0, "bytes": 0} for _ in range(24)]
    by_wday = [{"hits": 0, "pages": 0, "bytes": 0} for _ in range(7)]
    hosts: dict[str, dict] = defaultdict(lambda: {"hits": 0, "pages": 0, "bytes": 0, "last": 0})
    robots: dict[str, dict] = defaultdict(lambda: {"hits": 0, "bytes": 0, "last": 0})
    urls: dict[str, dict] = defaultdict(lambda: {"hits": 0, "bytes": 0, "entry": 0, "exit": 0})
    ftypes: dict[str, dict] = defaultdict(lambda: {"hits": 0, "bytes": 0})
    oses, browsers, devices = Counter(), Counter(), Counter()
    status: Counter = Counter()
    e404: Counter = Counter()
    e404_ref: dict[str, str] = {}
    referrers, engines, phrases, social = Counter(), Counter(), Counter(), Counter()
    users: Counter = Counter()
    durations: list[float] = []
    sessions: dict[tuple, list] = {}  # (ip, ua) -> [start, last, last_url]
    visits = 0
    rows = sorted((e for _, e in src), key=lambda e: e["ts"])
    for e in rows:
        if since and e["ts"] < since:
            continue
        c = uas.get(e["ua"])
        if c is None:
            c = uas[e["ua"]] = classify_ua(e["ua"])
        ts = e["ts"]
        first = ts if first is None else first
        last = ts
        status[e["status"]] += 1
        if c["bot"]:
            bot_hits += 1
            bot_bytes += e["size"]
            r = robots[c["browser"]]
            r["hits"] += 1
            r["bytes"] += e["size"]
            r["last"] = ts
            continue
        hits += 1
        nbytes += e["size"]
        lt = time.localtime(ts)
        day = time.strftime("%Y-%m-%d", lt)
        pg = is_page(e["url"], e["status"])
        path = e["url"].split("?", 1)[0]
        d = by_day[day]
        d["hits"] += 1
        d["bytes"] += e["size"]
        by_hour[lt.tm_hour]["hits"] += 1
        by_hour[lt.tm_hour]["bytes"] += e["size"]
        by_wday[lt.tm_wday]["hits"] += 1
        by_wday[lt.tm_wday]["bytes"] += e["size"]
        h = hosts[e["ip"]]
        h["hits"] += 1
        h["bytes"] += e["size"]
        h["last"] = ts
        d["visitors"].add(e["ip"])
        if e["user"]:
            users[e["user"]] += 1
        ext = (re.search(r"\.([A-Za-z0-9]{1,6})$", path) or [None, ""])[1].lower() or "(page)"
        ftypes[ext]["hits"] += 1
        ftypes[ext]["bytes"] += e["size"]
        if e["status"] == 404:
            e404[path[:300]] += 1
            if e["ref"]:
                e404_ref[path[:300]] = e["ref"]
        key = (e["ip"], e["ua"])
        sess = sessions.get(key)
        if pg:
            pages += 1
            d["pages"] += 1
            by_hour[lt.tm_hour]["pages"] += 1
            by_wday[lt.tm_wday]["pages"] += 1
            h["pages"] += 1
            urls[path[:300]]["hits"] += 1
            urls[path[:300]]["bytes"] += e["size"]
            if sess is None or ts - sess[1] > 1800:
                if sess:
                    durations.append(sess[1] - sess[0])
                    urls[sess[2]]["exit"] += 1
                sessions[key] = [ts, ts, path[:300]]
                visits += 1
                d["visits"] += 1
                urls[path[:300]]["entry"] += 1
                oses[c["os"]] += 1
                browsers[c["browser"]] += 1
                devices[c["device"]] += 1
                ref = e["ref"]
                if ref:
                    try:
                        u = urlsplit(ref)
                        host = (u.hostname or "").lower()
                    except ValueError:
                        host = ""
                    if host and host not in own and not any(host == n or host.endswith("." + n) for n in own):
                        hit = next(((nm, q) for pat, nm, q in _SEARCH if pat in host), None)
                        if hit:
                            engines[hit[0]] += 1
                            kw = parse_qs(u.query).get(hit[1])
                            if kw and kw[0].strip():
                                phrases[unquote(kw[0]).strip().lower()[:120]] += 1
                        else:
                            bare = host[4:] if host.startswith("www.") else host
                            if bare in _SOCIAL:
                                social[_SOCIAL[bare]] += 1
                            referrers[ref.split("?")[0][:300]] += 1
            else:
                sess[1] = ts
                sess[2] = path[:300]
    for s0 in sessions.values():
        durations.append(s0[1] - s0[0])
        urls[s0[2]]["exit"] += 1
    buckets = [(0, 30, "0s–30s"), (30, 120, "30s–2min"), (120, 300, "2min–5min"), (300, 900, "5min–15min"),
               (900, 1800, "15min–30min"), (1800, 3600, "30min–1h"), (3600, 10 ** 9, "1h+")]
    dur = [{"label": lbl, "visits": sum(1 for x in durations if lo <= x < hi)} for lo, hi, lbl in buckets]
    uniq = set()
    for d in by_day.values():
        uniq |= d["visitors"]
    top = lambda c, n=25: [{"key": k, "n": v} for k, v in c.most_common(n)]
    # Monthly history (persisted by the collector, survives log rotation)
    history = []
    with _lock:
        sd = json.loads(json.dumps(_bw_state()["site_d"]))
    months: dict[str, dict] = defaultdict(lambda: {"hits": 0, "pages": 0, "bytes": 0, "visitors": 0, "days": 0})
    keys = {sid} | ({"vh:" + n for n in own} if s["kind"] == "shared" else set())
    for day, per in sd.items():
        for k in keys:
            v = per.get(k)
            if v:
                m = months[day[:7]]
                m["hits"] += v.get("hits", 0) - v.get("bots", 0)
                m["pages"] += v.get("pages", 0)
                m["bytes"] += v.get("bytes", 0)
                m["visitors"] += v.get("visitors", 0)
                m["days"] += 1
    for m in sorted(months)[-13:]:
        history.append({"month": m, **months[m]})
    return {
        "site": s, "first": first, "last": last, "days": days,
        "summary": {"visitors": len(uniq), "visits": visits, "pages": pages, "hits": hits, "bytes": nbytes,
                    "bot_hits": bot_hits, "bot_bytes": bot_bytes,
                    "avg_duration": round(sum(durations) / len(durations)) if durations else 0,
                    "pages_per_visit": round(pages / visits, 2) if visits else 0},
        "by_day": [{"day": k, "hits": v["hits"], "pages": v["pages"], "bytes": v["bytes"], "visitors": len(v["visitors"]),
                    "visits": v["visits"]} for k, v in sorted(by_day.items())],
        "by_hour": by_hour, "by_wday": by_wday, "history": history,
        "hosts": sorted(({"ip": k, **v} for k, v in hosts.items()), key=lambda x: -x["pages"] or -x["hits"])[:50],
        "robots": sorted(({"name": k, **v} for k, v in robots.items()), key=lambda x: -x["hits"])[:30],
        "pages_top": sorted(({"url": k, **v} for k, v in urls.items()), key=lambda x: -x["hits"])[:50],
        "entry": sorted(({"url": k, "n": v["entry"]} for k, v in urls.items() if v["entry"]), key=lambda x: -x["n"])[:15],
        "exit": sorted(({"url": k, "n": v["exit"]} for k, v in urls.items() if v["exit"]), key=lambda x: -x["n"])[:15],
        "filetypes": sorted(({"ext": k, **v} for k, v in ftypes.items()), key=lambda x: -x["hits"])[:20],
        "os": top(oses), "browsers": top(browsers), "devices": top(devices),
        "status": sorted(({"code": k, "n": v} for k, v in status.items()), key=lambda x: -x["n"]),
        "e404": [{"url": k, "n": v, "ref": e404_ref.get(k, "")} for k, v in e404.most_common(30)],
        "referrers": top(referrers), "engines": top(engines), "phrases": top(phrases), "social": top(social),
        "users": top(users), "durations": dur,
    }


# --------------------------------------------------------------------------- #
# One IP: who owns it, what it did here, and whether it's banned or trusted
# --------------------------------------------------------------------------- #
def _ptr(ip: str) -> str:
    import socket
    box: list[str] = []
    t = threading.Thread(target=lambda: box.append(socket.gethostbyaddr(ip)[0]), daemon=True)
    try:
        t.start()
        t.join(3)
    except OSError:
        pass
    return box[0] if box else ""


def ip_info(ip: str, days: int = 7) -> dict:
    import ipaddress
    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise MetricsError("That isn't an IP address")
    out: dict = {"ip": ip, "ptr": _ptr(ip), "days": days}
    a = ipaddress.ip_address(ip)
    out["private"] = a.is_private or a.is_loopback or a.is_link_local
    owner = {}
    if not out["private"]:
        try:
            from . import abuse
            owner = abuse.lookup(ip)
        except Exception as e:
            owner = {"error": str(e)}
    out["owner"] = owner
    # Ban / trust state, with the details the IP Blocker keeps
    state: dict = {"status": ""}
    try:
        from . import guard
        state["status"] = guard.status_of([ip]).get(ip, "")
        g = guard.listing()
        for b in g["bans"]:
            if a in ipaddress.ip_network(b["cidr"]):
                state.update(kind="manual", cidr=b["cidr"], reason=b.get("reason", ""), expires=b.get("expires"), created=b.get("created"),
                             source=b.get("source", ""))
        for f in g["fail2ban"]:
            if f["ip"] == ip:
                state.update(kind="fail2ban", jails=f["jails"], expires_in=f["expires_in"])
        for t in g["trusted"]:
            if a in ipaddress.ip_network(t["cidr"]):
                state.update(kind="trusted", cidr=t["cidr"], reason=t.get("note") or t.get("reason", ""))
        state["enabled"] = g["enabled"]
    except Exception as e:
        state["error"] = str(e)
    out["state"] = state
    # What it did on the websites
    since = time.time() - days * 86400
    hits = pages = nbytes = 0
    first = last = 0.0
    per_site: Counter = Counter()
    urls: Counter = Counter()
    uas: Counter = Counter()
    status: Counter = Counter()
    recent: list[dict] = []
    for s in sites():
        for _, e in _entries(s, since):
            if e["ip"] != ip:
                continue
            hits += 1
            nbytes += e["size"]
            pages += is_page(e["url"], e["status"])
            first = e["ts"] if not first or e["ts"] < first else first
            last = max(last, e["ts"])
            per_site[e["vhost"] or s["label"]] += 1
            urls[e["url"][:200]] += 1
            uas[e["ua"][:200]] += 1
            status[e["status"]] += 1
            recent.append({k: e[k] for k in ("ts", "method", "url", "status", "size", "ua", "ref")} | {"site": e["vhost"] or s["label"]})
    recent.sort(key=lambda r: -r["ts"])
    out["web"] = {"hits": hits, "pages": pages, "bytes": nbytes, "first": first, "last": last,
                  "sites": per_site.most_common(10), "urls": urls.most_common(12),
                  "agents": [{"ua": k, "n": n, **classify_ua(k)} for k, n in uas.most_common(5)],
                  "status": sorted(status.items()), "recent": recent[:40]}
    try:
        from . import waf
        ev = waf.events(hours=days * 24, limit=500, ip=ip)
        out["waf"] = {"events": len(ev), "blocked": sum(1 for e in ev if e["blocked"]),
                      "types": Counter(waf._primary(e["rules"])["category"] for e in ev).most_common(5)}
    except Exception:
        out["waf"] = {"events": 0, "blocked": 0, "types": []}
    try:
        from . import abuse
        out["logins_failed"] = sum(1 for e in abuse.evidence(ip, days) if e.get("kind") != "attack")
        out["reported"] = abuse.reported().get(ip)
    except Exception:
        out["logins_failed"], out["reported"] = 0, None
    try:
        from . import servers
        out["servers"] = servers.count()
    except Exception:
        out["servers"] = 0
    return out
