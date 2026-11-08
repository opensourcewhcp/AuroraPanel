"""Domains section: Apache virtual hosts, Dynamic DNS (ddclient), Zone Editor
(BIND). Redirects are handled by the Apache .htaccess module (apache.py)."""
from __future__ import annotations

import platform
import re
import socket
import subprocess
from pathlib import Path

from . import distro
from . import jobs
from . import problems

IS_LINUX = platform.system() == "Linux"
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
SITES_AVAIL = Path("/etc/apache2/sites-available")
DEFAULT_DOCROOT_BASE = Path("/var/www")


class DomainError(RuntimeError):
    pass


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return socket.gethostbyname(socket.gethostname())


_public_ip_cache = {"ip": None, "ts": 0}


def public_ip() -> str | None:
    import time
    import urllib.request
    if _public_ip_cache["ip"] and time.time() - _public_ip_cache["ts"] < 300:
        return _public_ip_cache["ip"]
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=6) as r:
                ip = r.read().decode().strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    _public_ip_cache.update(ip=ip, ts=time.time())
                    return ip
        except Exception as quiet_exc:
            problems.quiet(quiet_exc)
            continue
    return None


def domain_info(server_name: str) -> dict:
    """Combined view for a domain: WHOIS + what to configure to run it."""
    name = (server_name or "").strip().lower()
    if not _HOSTNAME.match(name):
        raise DomainError("Enter a valid domain, e.g. example.com")
    lip, pip = _local_ip(), public_ip()
    try:
        resolved = socket.gethostbyname(name)
    except OSError:
        resolved = None
    who = {"registered": None, "expiry": None, "registrar": None, "created": None}
    try:
        who = whois_lookup(name)
    except DomainError:
        pass
    is_local_tld = name.endswith((".local", ".localhost", ".test"))
    registered = bool(who.get("registered"))
    return {
        "domain": name, "local_ip": lip, "public_ip": pip, "resolved_ip": resolved,
        "resolves_here_lan": resolved == lip, "resolves_here_wan": resolved == pip,
        "whois": who, "registered": registered, "is_local_tld": is_local_tld,
        "hosts_line": f"{lip}\t{name}",
        "dns_record": {"type": "A", "name": name, "value": pip} if pip else None,
        "mode": "local" if (is_local_tld or not registered) else "public",
    }


# ---- Domains (Apache virtual hosts) ----
import shutil


def list_vhosts() -> dict:
    if not (IS_LINUX and shutil.which("apache2ctl")):
        return {"supported": False, "vhosts": [], "local_ip": _local_ip()}
    try:
        out = subprocess.run(["apache2ctl", "-S"], capture_output=True, text=True, timeout=10)
    except (subprocess.SubprocessError, OSError) as exc:
        raise DomainError(str(exc))
    local_ip = _local_ip()
    vhosts, seen = [], set()
    text = out.stdout + "\n" + out.stderr
    for line in text.splitlines():
        m = re.search(r"port\s+(\d+)\s+namevhost\s+(\S+)\s+\(([^:]+):", line)
        if not m:
            continue
        server_name, port = m.group(2), m.group(1)
        if (server_name, port) in seen:
            continue
        seen.add((server_name, port))
        # Does the name resolve, and to us or elsewhere?
        resolved = None
        try:
            resolved = socket.gethostbyname(server_name)
        except OSError:
            resolved = None
        is_local = server_name.endswith((".local", ".localhost", ".test")) or server_name in ("localhost",)
        vhosts.append({
            "server_name": server_name, "port": port, "config": m.group(3),
            "resolved_ip": resolved,
            "resolves_here": resolved == local_ip,
            "needs_hosts": (resolved is None or is_local) and "." in server_name and not server_name.endswith(".local"),
        })
    return {"supported": True, "vhosts": vhosts, "local_ip": local_ip}


def create_vhost(server_name: str, docroot: str = "", port: int = 80) -> dict:
    if not (IS_LINUX and shutil.which("a2ensite")):
        raise DomainError("Apache (a2ensite) is not available")
    name = (server_name or "").strip().lower()
    if not _HOSTNAME.match(name):
        raise DomainError("Enter a valid domain, e.g. example.com")
    if not (1 <= int(port) <= 65535):
        raise DomainError("Invalid port")
    slug = name.replace("*", "wildcard")
    conf = SITES_AVAIL / f"{slug}.conf"
    if conf.exists():
        raise DomainError("A site with that name already exists")
    root = Path(docroot).expanduser() if docroot else (DEFAULT_DOCROOT_BASE / slug)
    if not root.is_absolute():
        raise DomainError("Doc root must be an absolute path")
    # The doc root is written verbatim into the vhost config below. A newline or quote would let extra
    # Apache directives be injected, and a bare system path (/ or /etc) would expose the whole machine.
    if any(c in str(root) for c in "\n\r\t\"'<>$`\\") or ".." in root.parts:
        raise DomainError("Doc root has characters that aren't allowed in a path")
    if len(root.parts) < 3:
        raise DomainError("Pick a dedicated folder for the site, e.g. /var/www/example.com")
    root.mkdir(parents=True, exist_ok=True)
    index = root / "index.html"
    if not index.exists():
        index.write_text(f"<!doctype html><meta charset=utf-8><title>{name}</title>"
                         f"<body style='font-family:system-ui;background:#0b1020;color:#eaf1fb;"
                         f"display:grid;place-items:center;height:100vh;margin:0'>"
                         f"<div><h1 style='background:linear-gradient(120deg,#22e3c3,#8a6bff);"
                         f"-webkit-background-clip:text;color:transparent'>{name}</h1>"
                         f"<p>New site created by AuroraPanel 🎉</p></div>", encoding="utf-8")
    conf.write_text(f"""<VirtualHost *:{int(port)}>
    ServerName {name}
    DocumentRoot {root}
    <Directory {root}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog ${{APACHE_LOG_DIR}}/{slug}-error.log
    CustomLog ${{APACHE_LOG_DIR}}/{slug}-access.log combined
</VirtualHost>
""", encoding="utf-8")
    r = subprocess.run(["a2ensite", f"{slug}.conf"], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        raise DomainError(r.stderr.strip() or "a2ensite failed")
    subprocess.run(["systemctl", "reload", "apache2"], capture_output=True, text=True, timeout=20)
    return {"ok": True, "server_name": name, "docroot": str(root), "local_ip": _local_ip(),
            "hosts_line": f"{_local_ip()}\t{name}"}


def remove_vhost(server_name: str) -> dict:
    if not (IS_LINUX and shutil.which("a2dissite")):
        raise DomainError("Apache (a2dissite) is not available")
    name = (server_name or "").strip().lower()
    if not _HOSTNAME.match(name):
        raise DomainError("Invalid domain")
    slug = name.replace("*", "wildcard")
    if name in ("localhost",) or slug in ("000-default", "default-ssl"):
        raise DomainError("Refusing to remove a default site")
    subprocess.run(["a2dissite", f"{slug}.conf"], capture_output=True, text=True, timeout=15)
    conf = SITES_AVAIL / f"{slug}.conf"
    if conf.exists():
        conf.unlink()
    subprocess.run(["systemctl", "reload", "apache2"], capture_output=True, text=True, timeout=20)
    return {"ok": True}


def whois_lookup(domain: str) -> dict:
    name = (domain or "").strip().lower()
    if not _HOSTNAME.match(name):
        raise DomainError("Invalid domain")
    # Registrable domain = last two labels (good enough for common TLDs).
    parts = name.split(".")
    registrable = ".".join(parts[-2:])
    tld = parts[-1]
    try:
        refer = _whois_query("whois.iana.org", tld)
        m = re.search(r"(?im)^(?:refer|whois):\s*(\S+)", refer)
        server = m.group(1) if m else f"{tld}.whois-servers.net"
        data = _whois_query(server, registrable)
    except OSError as exc:
        raise DomainError(f"WHOIS lookup failed: {exc}")
    expiry = _parse_field(data, [
        r"Registry Expiry Date:\s*(.+)", r"Registrar Registration Expiration Date:\s*(.+)",
        r"Expiration Date:\s*(.+)", r"Expiry Date:\s*(.+)", r"Expires On:\s*(.+)",
        r"paid-till:\s*(.+)", r"expire:\s*(.+)",
    ])
    registrar = _parse_field(data, [r"Registrar:\s*(.+)", r"registrar:\s*(.+)"])
    created = _parse_field(data, [r"Creation Date:\s*(.+)", r"Created On:\s*(.+)", r"created:\s*(.+)"])
    registered = bool(expiry or registrar or "Domain Name:" in data or "domain:" in data.lower())
    return {"domain": registrable, "registered": registered, "expiry": expiry,
            "registrar": registrar, "created": created}


def _whois_query(server: str, query: str, timeout: int = 8) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _parse_field(text: str, patterns: list[str]) -> str | None:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


# ---- Dynamic DNS (ddclient) ----
def dyndns_status() -> dict:
    installed = bool(IS_LINUX and shutil.which("ddclient"))
    cfg = Path("/etc/ddclient.conf")
    active = None
    if installed and shutil.which("systemctl"):
        active = subprocess.run(["systemctl", "is-active", "ddclient"], capture_output=True, text=True).stdout.strip()
    config_preview = ""
    if cfg.exists():
        try:
            # Redact passwords.
            lines = []
            for l in cfg.read_text(errors="replace").splitlines():
                lines.append(re.sub(r"(?i)(password\s*=\s*).*", r"\1********", l))
            config_preview = "\n".join(lines)
        except OSError:
            pass
    return {"installed": installed, "active": active, "config_path": str(cfg),
            "has_config": cfg.exists(), "config_preview": config_preview}


def dyndns_install() -> jobs.Job:
    env = {"DEBIAN_FRONTEND": "noninteractive", "PATH": distro.PATH}
    return jobs.launch("install ddclient", ["apt-get", "-y", "install", "ddclient"], env=env)


def dyndns_run() -> dict:
    if not (IS_LINUX and shutil.which("ddclient")):
        raise DomainError("ddclient is not installed")
    out = subprocess.run(["ddclient", "-force", "-verbose"], capture_output=True, text=True, timeout=60)
    return {"output": (out.stdout + "\n" + out.stderr).strip()[:4000]}


# ---- Zone Editor (BIND) ----
BIND_DIR = Path("/etc/bind")


def zones() -> dict:
    installed = bool(IS_LINUX and shutil.which("named"))
    if not BIND_DIR.exists():
        return {"installed": installed, "has_bind": False, "zones": []}
    zone_files = []
    for f in list(BIND_DIR.glob("db.*")) + list(BIND_DIR.glob("*.zone")) + list(BIND_DIR.glob("zones/*")):
        if f.is_file():
            zone_files.append({"name": f.name, "path": str(f), "size": f.stat().st_size})
    return {"installed": installed, "has_bind": True, "zones": zone_files}


def zone_content(name: str) -> dict:
    if not re.match(r"^[A-Za-z0-9._-]+$", name or ""):
        raise DomainError("Invalid zone file name")
    path = (BIND_DIR / name).resolve()
    if BIND_DIR not in path.parents and path.parent != BIND_DIR:
        raise DomainError("Invalid path")
    if not path.is_file():
        raise DomainError("Zone file not found")
    # Only files the Zone Editor actually lists are zone files: a plain name match would otherwise hand
    # back any file in /etc/bind (rndc.key, named.conf with its TSIG keys) to anyone who can read a zone.
    if str(path) not in {z["path"] for z in zones()["zones"]}:
        raise DomainError("Zone file not found")
    return {"name": name, "content": path.read_text(errors="replace")[:20000]}


def bind_install() -> jobs.Job:
    env = {"DEBIAN_FRONTEND": "noninteractive", "PATH": distro.PATH}
    return jobs.launch("install BIND9", ["apt-get", "-y", "install", "bind9"], env=env)
