"""System Applications — one-click install/manage for a fixed catalog of server
software (web servers, PHP-FPM, MariaDB, FTP).

Only catalog ids are accepted from the client; package and service names come
from CATALOG, so nothing the user types reaches apt or systemctl. Only one web
server may own port 80: installing/starting a second one requires an explicit
"switch", which stops and disables the running one first.
"""
from __future__ import annotations

import glob
import platform
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import distro
from . import jobs

IS_LINUX = platform.system() == "Linux"
_APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "PATH": distro.PATH}
# Wait for a background apt/unattended-upgrades run instead of failing on the lock.
_APT = ["apt-get", "-o", "DPkg::Lock::Timeout=600", "-y"]

CATALOG: dict[str, dict] = {
    "apache": {
        "name": "Apache", "group": "web", "pkg": "apache2", "service": "apache2",
        "procs": ("apache2",), "ram": "~25–60 MB",
        "desc": "The classic web server. Needed for .htaccess, phpMyAdmin and the panel's Apache tools.",
    },
    "nginx": {
        "name": "Nginx", "group": "web", "pkg": "nginx", "service": "nginx",
        "procs": ("nginx",), "ram": "~5–15 MB",
        "desc": "Fast, event-driven web server and reverse proxy. Pair with PHP-FPM for PHP.",
    },
    "lighttpd": {
        "name": "Lighttpd", "group": "web", "pkg": "lighttpd", "service": "lighttpd",
        "procs": ("lighttpd",), "ram": "~2–5 MB",
        "desc": "Smallest footprint — a good fit for a Pi Zero or very low-memory boards.",
    },
    "caddy": {
        "name": "Caddy", "group": "web", "pkg": "caddy", "service": "caddy",
        "procs": ("caddy",), "ram": "~15–30 MB",
        "desc": "Modern web server that obtains and renews HTTPS certificates automatically.",
    },
    "phpfpm": {
        "name": "PHP-FPM", "group": "extra", "pkg": "php-fpm", "service": None,
        "procs": ("php-fpm",), "ram": "~20–40 MB",
        "desc": "PHP process manager used by Nginx, Lighttpd and Caddy to run PHP sites.",
    },
    "mariadb": {
        "name": "MariaDB", "group": "db", "pkg": "mariadb-server", "service": "mariadb",
        "procs": ("mariadbd", "mysqld"), "ram": "~80–150 MB",
        "desc": "MySQL-compatible database server (WordPress, most PHP apps).",
    },
    "postgresql": {
        "name": "PostgreSQL", "group": "db", "pkg": "postgresql", "service": "postgresql",
        "procs": ("postgres",), "ram": "~30–60 MB",
        "desc": "Advanced open-source SQL database (Django, Rails, Nextcloud, many Python apps).",
    },
    "redis": {
        "name": "Redis", "group": "db", "pkg": "redis-server", "service": "redis-server",
        "procs": ("redis-server",), "ram": "~5–30 MB",
        "desc": "In-memory key-value store for caches, sessions and queues (WordPress object cache, Laravel, Nextcloud). Listens on this server only.",
    },
    "memcached": {
        "name": "Memcached", "group": "db", "pkg": "memcached", "service": "memcached",
        "procs": ("memcached",), "ram": "~5–70 MB",
        "desc": "Simple in-memory cache that speeds up PHP and Python sites. Listens on this server only.",
    },
    "vsftpd": {
        "name": "vsftpd", "group": "extra", "pkg": "vsftpd", "service": "vsftpd",
        "procs": ("vsftpd",), "ram": "~1–3 MB",
        "desc": "Lightweight, secure FTP server for uploading site files.",
    },
}
WEB_SERVERS = [k for k, v in CATALOG.items() if v["group"] == "web"]

# Server software the panel installs on demand (requires.COMPONENTS) — listed here too so it can be
# started, stopped and configured in one place. "view" is the panel page that configures it.
SERVER_APPS: dict[str, dict] = {
    "mail": {"units": ["postfix", "dovecot", *(["opendkim", "spamassassin", "spamass-milter"] if distro.is_dnf() else ["rspamd", "redis-server"])], "procs": ("master", "smtpd", "qmgr", "pickup", "dovecot", "imap", "pop3", "lmtp", "auth", "rspamd", "opendkim", "spamd", "spamass-milter", "redis-server"),
             "view": "email", "ram": "~120–200 MB"},
    "webmail": {"units": [], "procs": (), "view": "mailaccounts", "ram": "runs inside Apache/PHP", "ext": "/webmail/", "name": "Webmail"},
    "dav": {"units": ["radicale"], "procs": ("radicale",), "view": "calendars", "ram": "~20–30 MB", "name": "Calendars & Contacts"},
    "bind9": {"units": ["named"], "procs": ("named",), "view": "zones", "ram": "~15–40 MB", "name": "DNS server"},
    "modsecurity": {"units": [], "procs": (), "view": "modsec", "ram": "runs inside Apache", "name": "WAF Firewall"},
    "fail2ban": {"units": ["fail2ban"], "procs": ("fail2ban-server",), "view": "leech", "ram": "~20–40 MB"},
    "clamav": {"units": ["clamav-freshclam"], "procs": ("freshclam", "clamd"), "view": "virus", "ram": "~10 MB (scans: ~1 GB)", "name": "Antivirus"},
    "ufw": {"units": [], "procs": (), "view": "firewall", "ram": "none (kernel rules)"},  # on/off lives on the Firewall page
    "docker": {"units": ["docker"], "procs": ("dockerd", "containerd"), "view": "dockerapps", "ram": "~60 MB + the apps", "name": "Docker"},
    "certbot": {"units": ["certbot.timer"], "procs": (), "view": "ssl", "ram": "none (runs twice a day)", "name": "Let's Encrypt"},
}
_ACTIONS = {"start", "stop", "restart"}


class SysAppError(RuntimeError):
    pass


class ConflictError(SysAppError):
    """Another web server already owns port 80; the client must confirm a switch."""

    def __init__(self, msg: str, other: str):
        super().__init__(msg)
        self.other = other


def _app(app_id: str) -> dict:
    if app_id not in CATALOG:
        raise SysAppError("Unknown application")
    return CATALOG[app_id]


def _require_linux():
    if not IS_LINUX or not shutil.which("apt-get") or not shutil.which("systemctl"):
        raise SysAppError("apt/systemd are not available on this host")


def _service(app_id: str) -> str | None:
    svc = CATALOG[app_id]["service"]
    if svc is None and app_id == "phpfpm":
        # Versioned unit, e.g. php8.4-fpm.service.
        units = sorted(glob.glob("/lib/systemd/system/php*-fpm.service") + glob.glob("/usr/lib/systemd/system/php*-fpm.service"))
        svc = Path(units[-1]).stem if units else None
    return svc


def _dpkg_status(pkgs: list[str]) -> dict[str, str | None]:
    """pkg -> installed version, or None when not installed."""
    result: dict[str, str | None] = {p: None for p in pkgs}
    if not IS_LINUX or not shutil.which("dpkg-query"):
        return result
    out = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\t${Version}\n", *pkgs],
                         capture_output=True, text=True, timeout=15)
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[1].startswith("ii"):
            result[parts[0]] = parts[2]
    return result


def _dpkg_broken(pkgs: list[str]) -> set[str]:
    """Packages whose install stopped part-way (dpkg "iF" half-configured, "iU" unpacked, …)."""
    if not IS_LINUX or not shutil.which("dpkg-query"):
        return set()
    out = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\n", *pkgs],
                         capture_output=True, text=True, timeout=15)
    broken = set()
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1][:1] == "i" and parts[1][1:2] not in ("i", "n"):
            broken.add(parts[0])
    return broken


def _pg_server_pkgs() -> dict[str, str]:
    """Installed versioned server packages (postgresql-17 …) -> version. The "postgresql"
    metapackage is optional, so these are what really say Postgres is installed."""
    if not IS_LINUX or not shutil.which("dpkg-query"):
        return {}
    out = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\t${Version}\n", "postgresql-[0-9]*"],
                         capture_output=True, text=True, timeout=15)
    return {p[0]: p[2] for p in (l.split("\t") for l in out.stdout.splitlines())
            if len(p) == 3 and p[1].startswith("ii") and re.fullmatch(r"postgresql-\d+", p[0])}


def _active(units: list[str]) -> dict[str, bool]:
    if not units or not shutil.which("systemctl"):
        return {u: False for u in units}
    out = subprocess.run(["systemctl", "is-active", *units], capture_output=True, text=True, timeout=10)
    states = out.stdout.split()
    return {u: (states[i] == "active" if i < len(states) else False) for i, u in enumerate(units)}


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _docroot(app_id: str) -> str | None:
    """The default site's web folder, read from the server's own config."""
    pats = {
        "apache": (["/etc/apache2/sites-enabled/000-default.conf", "/etc/apache2/sites-available/000-default.conf"],
                   r"^\s*DocumentRoot\s+\"?([^\"\s]+)", "/var/www/html"),
        "nginx": (["/etc/nginx/sites-enabled/default", "/etc/nginx/sites-available/default"],
                  r"^\s*root\s+([^;\s]+)\s*;", "/var/www/html"),
        "lighttpd": (["/etc/lighttpd/lighttpd.conf"],
                     r"^\s*server\.document-root\s*=\s*\"([^\"]+)\"", "/var/www/html"),
        "caddy": (["/etc/caddy/Caddyfile"], r"^\s*root\s+\*\s+(\S+)", "/usr/share/caddy"),
    }
    if app_id not in pats:
        return None
    files, rx, default = pats[app_id]
    for f in files:
        m = re.search(rx, _read(f), re.MULTILINE)
        if m:
            return m.group(1)
    return default


def _ram_mb() -> dict[str, float]:
    """Actual resident memory per catalog app (sum over its processes)."""
    try:
        import psutil
    except ImportError:
        return {}
    by_proc = {p: k for k, v in CATALOG.items() for p in v["procs"]}
    totals: dict[str, float] = {}
    for proc in psutil.process_iter(["name", "memory_info"]):
        name = proc.info.get("name") or ""
        mi = proc.info.get("memory_info")
        if not mi:
            continue
        key = by_proc.get(name) or ("phpfpm" if name.startswith("php-fpm") else None)
        if not key:
            key = next((k for k, v in SERVER_APPS.items() if name in v["procs"]), None)
        if key:
            totals[key] = totals.get(key, 0.0) + mi.rss / 1048576
    return {k: round(v, 1) for k, v in totals.items()}


def status() -> dict:
    if not IS_LINUX:
        return {"supported": False, "apps": []}
    versions = _dpkg_status([v["pkg"] for v in CATALOG.values()])
    broken = _dpkg_broken([v["pkg"] for v in CATALOG.values()])
    pg = _pg_server_pkgs()
    if pg:
        versions["postgresql"] = pg[max(pg, key=lambda p: int(p.split("-")[1]))]
    services = {k: _service(k) for k in CATALOG}
    active = _active([s for s in services.values() if s])
    ram = _ram_mb()
    apps = []
    for k, v in CATALOG.items():
        svc = services[k]
        installed = versions.get(v["pkg"]) is not None
        apps.append({
            "id": k, "name": v["name"], "group": v["group"], "desc": v["desc"], "ram_typical": v["ram"],
            "package": v["pkg"], "service": svc, "installed": installed, "version": versions.get(v["pkg"]),
            "broken": not installed and v["pkg"] in broken,
            "active": bool(svc and active.get(svc)), "ram_mb": ram.get(k),
            "docroot": _docroot(k) if installed else None,
        })
    from . import jobs as _jobs, requires
    units = [u for v in SERVER_APPS.values() for u in v["units"]]
    act = _active(units)
    for k, v in SERVER_APPS.items():
        c = requires.COMPONENTS[k]
        pk = c["pkgs"] if not callable(c["pkgs"]) else ["docker.io", "docker compose"]  # chosen per OS at install time
        installed = requires.installed(k)
        running = [j for j in _jobs.find(requires=k) if j.status == "running"]
        # ufw is "active" only when the firewall is on; the unit itself is just its boot loader.
        on = [u for u in v["units"] if act.get(u)]
        apps.append({
            "id": k, "name": v.get("name", c["name"]), "group": "server", "desc": c["desc"], "ram_typical": v["ram"],
            "package": ", ".join(pk[:3]) + ("…" if len(pk) > 3 else ""), "service": ", ".join(v["units"]) or None,
            "installed": installed, "version": None, "broken": False,
            "active": bool(v["units"]) and len(on) == len(v["units"]), "partial": bool(on) and len(on) < len(v["units"]),
            "units": [{"unit": u, "active": bool(act.get(u))} for u in v["units"]],
            "ram_mb": ram.get(k), "docroot": None, "view": v["view"], "ext": v.get("ext"),
            "needs": [n for n in c.get("needs", []) if not requires.installed(n)],
            "job": running[0].id if running else None,
        })
    apps += _docker_dbs()
    return {"supported": True, "apps": apps}


# Databases with no Debian package: installed from the Docker catalog, listed here next to the others.
DOCKER_DBS = ("mongodb", "cassandra", "oracle", "couchdb", "influxdb")


def _docker_dbs() -> list[dict]:
    from . import dockerapps
    insts = {}
    try:
        for name, inst in dockerapps._state().get("apps", {}).items():
            if inst.get("app") in DOCKER_DBS:
                insts.setdefault(inst["app"], []).append(name)
    except (OSError, ValueError, AttributeError):
        pass
    running = set()
    if insts:
        r = dockerapps._run(["docker", "ps", "--format", "{{.Names}}"], 20)
        running = set(r.stdout.split()) if r.returncode == 0 else set()
    out = []
    for k in DOCKER_DBS:
        v = dockerapps.CATALOG[k]
        names = insts.get(k, [])
        out.append({
            "id": k, "name": v["name"], "group": "db", "desc": v["desc"], "ram_typical": v["ram"].replace("≈ ", "~"),
            "package": v["image"], "service": None, "installed": bool(names), "version": None, "broken": False,
            "active": any(n in running for n in names), "ram_mb": None, "docroot": None,
            "docker": True, "containers": names,
        })
    return out


# Cached for the file manager, which asks on every directory listing.
_web_cache: tuple[float, str | None] = (0.0, None)


def web_root() -> str | None:
    """Web folder of the active (else installed) web server, or None if there is none."""
    global _web_cache
    if time.time() - _web_cache[0] < 10:
        return _web_cache[1]
    root = None
    if IS_LINUX:
        versions = _dpkg_status([CATALOG[k]["pkg"] for k in WEB_SERVERS])
        installed = [k for k in WEB_SERVERS if versions.get(CATALOG[k]["pkg"])]
        active = _active([CATALOG[k]["service"] for k in installed])
        # Apache first (the user's default stack), but a running server beats an idle one.
        ranked = sorted(installed, key=lambda k: (not active.get(CATALOG[k]["service"]), k != "apache"))
        for k in ranked:
            d = _docroot(k)
            if d and Path(d).is_dir():
                root = d
                break
    _web_cache = (time.time(), root)
    return root


def _running_web_server(exclude: str) -> str | None:
    others = [k for k in WEB_SERVERS if k != exclude]
    active = _active([CATALOG[k]["service"] for k in others])
    for k in others:
        if active.get(CATALOG[k]["service"]):
            return k
    return None


def _check_port80(app_id: str, switch: bool):
    """Raise ConflictError, or (when switching) stop+disable the running web server."""
    if CATALOG[app_id]["group"] != "web":
        return
    other = _running_web_server(app_id)
    if not other:
        return
    if not switch:
        raise ConflictError(
            f"{CATALOG[other]['name']} is running on port 80. Stop it and switch to {CATALOG[app_id]['name']}?", other)
    svc = CATALOG[other]["service"]
    subprocess.run(["systemctl", "disable", "--now", svc], capture_output=True, text=True, timeout=60)


def install(app_id: str, switch: bool = False) -> jobs.Job:
    _require_linux()
    if app_id in SERVER_APPS:
        from . import requires
        try:
            return requires.install(app_id)
        except requires.RequiresError as e:
            raise SysAppError(str(e))
    v = _app(app_id)
    _check_port80(app_id, switch)
    global _web_cache
    _web_cache = (0.0, None)
    if v["pkg"] in _dpkg_broken([v["pkg"]]):
        # A previous install stopped part-way: finish configuring it, then let apt fix up the rest.
        script = f"dpkg --force-confold --configure -a; {' '.join(_APT)} -f install && {' '.join(_APT)} install {v['pkg']}"
        return jobs.launch(f"repair {v['name']}", ["bash", "-c", script], env=_APT_ENV, meta={"app": app_id})
    return jobs.launch(f"install {v['name']}", [*_APT, "install", v["pkg"]], env=_APT_ENV, meta={"app": app_id})


def uninstall(app_id: str) -> jobs.Job:
    _require_linux()
    v = _app(app_id)
    if app_id == "redis" and not distro.is_dnf():  # Fedora's spam filter doesn't use Redis
        from . import requires
        if requires.installed("mail"):
            raise SysAppError("Email's spam filter (Rspamd) uses Redis, so it stays while Email is installed")
    global _web_cache
    _web_cache = (0.0, None)
    pkgs = [v["pkg"]]
    if app_id == "postgresql":
        # "postgresql" is a metapackage; the server itself is the versioned postgresql-NN.
        pkgs += list(_pg_server_pkgs())
    # "remove" (not purge): config files, site content and database files stay on disk.
    return jobs.launch(f"uninstall {v['name']}", [*_APT, "remove", *pkgs], env=_APT_ENV, meta={"app": app_id})


def control(app_id: str, action: str, switch: bool = False) -> dict:
    _require_linux()
    if action not in _ACTIONS:
        raise SysAppError("Invalid action")
    if app_id in SERVER_APPS:
        units = SERVER_APPS[app_id]["units"]
        if not units:
            raise SysAppError("This runs inside Apache — restart Apache instead")
        if action == "start":
            cmds = [["systemctl", "enable", "--now", *units]]
        else:
            cmds = [["systemctl", action, *units]]
        for cmd in cmds:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if out.returncode != 0:
                raise SysAppError(out.stderr.strip() or f"systemctl {action} failed")
        return {"ok": True, "service": " ".join(units), "action": action}
    _app(app_id)
    svc = _service(app_id)
    if not svc:
        raise SysAppError("This application has no service (is it installed?)")
    if action in ("start", "restart"):
        _check_port80(app_id, switch)
    cmds = [["systemctl", action, svc]]
    if action == "start":
        cmds.append(["systemctl", "enable", svc])  # a switched-to server should survive a reboot
    for cmd in cmds:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            raise SysAppError(out.stderr.strip() or f"systemctl {action} {svc} failed")
    global _web_cache
    _web_cache = (0.0, None)
    return {"ok": True, "service": svc, "action": action}
