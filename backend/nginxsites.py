"""Websites on Nginx: create, change, switch on and off, and remove them, the way the Domains page does for Apache.

Each site is one file, /etc/nginx/conf.d/aurora-site-<name>.conf, with its settings in a comment on the first lines.
Every change is written, checked with `nginx -t`, and only then reloaded; if the check fails the old files come back.
The Nginx package's own files are never edited.
"""
from __future__ import annotations

import glob
import http.client
import json
import os
import re
import shutil
import ssl
import subprocess
import threading
import time
from pathlib import Path

from . import distro

CONF_DIR = Path("/etc/nginx/conf.d")
DEFAULT_D = Path("/etc/nginx/default.d")
SSL_DIR = Path("/etc/nginx/aurora-ssl")
LOG_DIR = Path("/var/log/nginx")
WEB_BASE = Path("/var/www")
TRASH = Path("/var/lib/aurora/trash")
DEFAULT_CONF = CONF_DIR / "aurora-default.conf"
PREFIX = "aurora-site-"
HEADER = "# Written by AuroraPanel (Nginx Websites). Edit there: changes here are overwritten.\n"
META = re.compile(r"(?m)^# aurora-site: (\{.*\})$")
MODES = ("php", "static", "proxy")
HTTPS = ("none", "selfsigned")
_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DOCROOT = re.compile(r"^/var/www/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
_PROXY = re.compile(r"^https?://[A-Za-z0-9.\[\]:-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~/-]*)?$")
_SOCKETS = ("/run/php-fpm/www.sock", "/run/php/php*-fpm.sock", "/var/run/php/php*-fpm.sock")
RELOAD_SETTLE = 0.6  # `nginx -s reload` only signals: the new workers take over a moment after it returns
_lock = threading.RLock()


class NginxError(RuntimeError):
    pass


def _run(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={"PATH": distro.BASE_PATH, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(argv, 1, "", str(exc))


def installed() -> bool:
    return shutil.which("nginx", path=distro.BASE_PATH) is not None


def _active(unit: str) -> bool:
    return _run(["systemctl", "is-active", unit], 15).stdout.strip() == "active"


def _apache_unit() -> str:
    return "httpd" if shutil.which("httpd", path=distro.BASE_PATH) else "apache2"


def php_socket() -> str | None:
    for pattern in _SOCKETS:
        found = sorted(glob.glob(pattern))
        if found:
            return found[-1]
    return None


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "-", name.lower())[:120]


def _conf(name: str, enabled: bool = True) -> Path:
    return CONF_DIR / f"{PREFIX}{_slug(name)}.conf{'' if enabled else '.off'}"


# ----------------------------------------------------------------------------- settings
def clean(settings: dict) -> dict:
    """Everything here ends up in a config file: only exact, expected shapes get through."""
    s = dict(settings or {})
    name = str(s.get("server_name") or "").strip().lower()
    if not _HOST.match(name):
        raise NginxError("Enter a domain or subdomain such as blog.example.com")
    aliases = []
    for a in s.get("aliases") or []:
        a = str(a).strip().lower()
        if not a or a == name or a in aliases:
            continue
        if not _HOST.match(a):
            raise NginxError(f"Not a valid name: {a}")
        aliases.append(a)
    mode = s.get("mode") or "php"
    if mode not in MODES:
        raise NginxError("Type must be PHP, static or reverse proxy")
    docroot = str(s.get("docroot") or "").strip().rstrip("/") or f"{WEB_BASE.as_posix()}/{_slug(name)}"
    if not _DOCROOT.match(docroot) or ".." in docroot:
        raise NginxError("The web folder must be inside /var/www")
    proxy = str(s.get("proxy") or "").strip()
    if mode == "proxy" and not _PROXY.match(proxy):
        raise NginxError("Enter the address to forward to, such as http://127.0.0.1:3000")
    https = s.get("https") or "none"
    if https not in HTTPS:
        raise NginxError("HTTPS must be off or self-signed")
    try:
        body = int(s.get("max_body_mb") if s.get("max_body_mb") is not None else 64)
    except (TypeError, ValueError):
        raise NginxError("Upload limit must be a number") from None
    if not 1 <= body <= 10240:
        raise NginxError("Upload limit must be between 1 and 10240 MB")
    custom = str(s.get("custom") or "").strip()
    if len(custom) > 8000:
        raise NginxError("Extra settings are limited to 8000 characters")
    depth = 0
    for ch in custom:  # "} server {" balances, but would break out of this site's block
        depth += (ch == "{") - (ch == "}")
        if depth < 0:
            break
    if depth != 0:
        raise NginxError("Extra settings have unbalanced braces")
    return {"server_name": name, "aliases": aliases, "mode": mode, "docroot": docroot, "proxy": proxy if mode == "proxy" else "", "https": https,
            "force_https": bool(s.get("force_https")) and https != "none", "max_body_mb": body, "custom": custom}


def _site_body(s: dict, socket: str | None) -> list[str]:
    slug = _slug(s["server_name"])
    lines = [f"    access_log {LOG_DIR}/{slug}-access.log combined;", f"    error_log {LOG_DIR}/{slug}-error.log;", f"    client_max_body_size {s['max_body_mb']}m;",
             f"    root {s['docroot']};", "    location /.well-known/acme-challenge/ { allow all; }", "    location ~ /\\.(?!well-known) { deny all; }"]
    if s["mode"] == "proxy":
        lines += ["    location / {", f"        proxy_pass {s['proxy']};", "        proxy_set_header Host $host;", "        proxy_set_header X-Real-IP $remote_addr;",
                  "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;", "        proxy_set_header X-Forwarded-Proto $scheme;", "        proxy_http_version 1.1;",
                  "        proxy_set_header Upgrade $http_upgrade;", '        proxy_set_header Connection "upgrade";', "    }"]
    elif s["mode"] == "php":
        if not socket:
            raise NginxError("PHP isn't running here (no PHP-FPM socket). Install PHP-FPM, or choose a static site.")
        lines += ["    index index.php index.html index.htm;", "    location / { try_files $uri $uri/ /index.php?$query_string; }",
                  "    location ~ \\.php$ {", "        try_files $uri =404;", "        include fastcgi_params;", "        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;",
                  f"        fastcgi_pass unix:{socket};", "    }"]
    else:
        lines += ["    index index.html index.htm;", "    location / { try_files $uri $uri/ =404; }"]
    if s["custom"]:
        lines += ["    # Extra settings", *[f"    {x}" for x in s["custom"].splitlines()]]
    return lines


def render(s: dict, socket: str | None = None) -> str:
    names = " ".join([s["server_name"], *s["aliases"]])
    body = _site_body(s, socket)
    out = [HEADER.rstrip(), f"# aurora-site: {json.dumps(s, sort_keys=True)}"]
    if s["force_https"]:
        out += ["server {", "    listen 80;", "    listen [::]:80;", f"    server_name {names};", f"    root {s['docroot']};", "    location /.well-known/acme-challenge/ { allow all; }",
                "    location / { return 301 https://$host$request_uri; }", "}"]
    else:
        out += ["server {", "    listen 80;", "    listen [::]:80;", f"    server_name {names};", *body, "}"]
    if s["https"] != "none":
        crt, key = _cert_paths(s["server_name"])
        out += ["server {", "    listen 443 ssl;", "    listen [::]:443 ssl;", f"    server_name {names};", f"    ssl_certificate {crt.as_posix()};", f"    ssl_certificate_key {key.as_posix()};",
                "    ssl_protocols TLSv1.2 TLSv1.3;", *body, "}"]
    return "\n".join(out) + "\n"


def _cert_paths(name: str) -> tuple[Path, Path]:
    return SSL_DIR / f"{_slug(name)}.crt", SSL_DIR / f"{_slug(name)}.key"


def _ensure_cert(s: dict) -> None:
    if s["https"] != "selfsigned":
        return
    crt, key = _cert_paths(s["server_name"])
    if crt.exists() and key.exists():
        return
    from . import sslcerts
    SSL_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(SSL_DIR, 0o750)
    sslcerts.write_self_signed(crt, key, [s["server_name"], *s["aliases"]], 825)
    _run(["restorecon", "-R", str(SSL_DIR)])


def _ensure_docroot(s: dict) -> None:
    if s["mode"] == "proxy":
        return
    root = Path(s["docroot"])
    fresh = not root.exists()
    root.mkdir(parents=True, exist_ok=True)
    if fresh:
        page = f"<!doctype html><meta charset=utf-8><title>{s['server_name']}</title><body style='font-family:system-ui;text-align:center;margin-top:20vh'><h1>{s['server_name']}</h1><p>New site created by AuroraPanel.</p>"
        (root / "index.html").write_text(page, encoding="utf-8")
        _run(["chown", "-R", "www-data:www-data", str(root)])
    _run(["restorecon", "-R", str(root)])


# ----------------------------------------------------------------------------- applying
def test_config() -> dict:
    r = _run(["nginx", "-t"], 30)
    return {"ok": r.returncode == 0, "output": (r.stderr or r.stdout).strip()[-1500:]}


def _apply(changes: dict[Path, str | None]) -> None:
    """Write, check, reload. On any failure every file goes back to how it was."""
    with _lock:
        before = {p: (p.read_text(encoding="utf-8") if p.exists() else None) for p in changes}

        def put(items):
            for p, text in items.items():
                if text is None:
                    p.unlink(missing_ok=True)
                else:
                    tmp = p.with_name(p.name + ".aurora-tmp")
                    tmp.write_text(text, encoding="utf-8")
                    os.chmod(tmp, 0o644)
                    os.replace(tmp, p)
                    _run(["restorecon", str(p)])
        put(changes)
        check = test_config()
        if not check["ok"]:
            put(before)
            raise NginxError("Nginx rejected this, nothing changed:\n" + check["output"])
        if _active("nginx"):
            r = _run(["systemctl", "reload", "nginx"], 60)
            if r.returncode != 0:
                put(before)
                _run(["systemctl", "reload", "nginx"], 60)
                raise NginxError("Nginx wouldn't reload, nothing changed: " + (r.stderr or "")[-300:])
            time.sleep(RELOAD_SETTLE)


def _other_default_server() -> bool:
    """Does anything other than our own file already claim to be the default site?"""
    files = ["/etc/nginx/nginx.conf", *glob.glob("/etc/nginx/conf.d/*.conf"), *glob.glob("/etc/nginx/sites-enabled/*")]
    for f in files:
        if f == str(DEFAULT_CONF):
            continue
        try:
            if re.search(r"(?m)^\s*listen\s[^;#]*\bdefault_server\b", Path(f).read_text(errors="replace")):
                return True
        except OSError:
            pass
    return False


def render_default() -> str:
    """Requests for no particular site: the same /var/www/html folder Apache's built-in site uses, folder sites included."""
    shared = DEFAULT_D.is_dir() and (DEFAULT_D / "php.conf").exists()
    lines = [HEADER.rstrip(), "server {", "    listen 80 default_server;", "    listen [::]:80 default_server;", "    server_name _aurora_default;", f"    root {WEB_BASE / 'html'};",
             "    location ~ /\\.(?!well-known) { deny all; }"]
    if shared:
        lines.append(f"    include {DEFAULT_D}/*.conf;")
    else:
        lines.append("    index index.php index.html index.htm;")
        socket = php_socket()
        if socket:
            lines += ["    location ~ \\.php$ {", "        try_files $uri =404;", "        include fastcgi_params;", "        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;", f"        fastcgi_pass unix:{socket};", "    }"]
    return "\n".join([*lines, "}"]) + "\n"


def ensure_default() -> bool:
    """Make Nginx answer from /var/www/html instead of its own sample page. Leaves another default site alone."""
    if _other_default_server():
        return False
    (WEB_BASE / "html").mkdir(parents=True, exist_ok=True)
    text = render_default()
    if not DEFAULT_CONF.exists() or DEFAULT_CONF.read_text(encoding="utf-8") != text:
        _apply({DEFAULT_CONF: text})
    return True


# ----------------------------------------------------------------------------- reading
def _load(path: Path) -> dict | None:
    try:
        m = META.search(path.read_text(encoding="utf-8", errors="replace"))
        return json.loads(m.group(1)) if m else None
    except (OSError, ValueError):
        return None


def _probe(name: str, https: bool = False) -> str:
    """What this server answers for that name right now, asked locally. The real test of whether a site works."""
    try:
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            c = http.client.HTTPSConnection("127.0.0.1", 443, timeout=4, context=ctx)
        else:
            c = http.client.HTTPConnection("127.0.0.1", 80, timeout=4)
        c.request("GET", "/", headers={"Host": name, "User-Agent": "AuroraPanel check"})
        code = c.getresponse().status
        c.close()
        return str(code)
    except (OSError, http.client.HTTPException) as exc:
        return f"no answer ({str(exc)[:60]})"


def list_sites(probe: bool = True) -> list[dict]:
    out = []
    for path in sorted(list(CONF_DIR.glob(f"{PREFIX}*.conf")) + list(CONF_DIR.glob(f"{PREFIX}*.conf.off"))):
        s = _load(path)
        if not s:
            continue
        enabled = path.suffix == ".conf"
        out.append({**s, "enabled": enabled, "answer": _probe(s["server_name"]) if probe and enabled else None})
    return out


def _get(name: str) -> tuple[dict, bool]:
    name = str(name or "").strip().lower()
    if not _HOST.match(name):
        raise NginxError("Unknown site")
    for enabled in (True, False):
        s = _load(_conf(name, enabled))
        if s:
            return s, enabled
    raise NginxError("No such site")


def status() -> dict:
    if not installed():
        return {"installed": False, "active": False, "sites": [], "apache_active": _active(_apache_unit())}
    v = _run(["nginx", "-v"], 10)
    active = _active("nginx")
    other = [p.name for p in CONF_DIR.glob("*.conf") if not p.name.startswith(PREFIX) and p != DEFAULT_CONF]
    return {"installed": True, "active": active, "version": (v.stderr or v.stdout).strip().split("/")[-1][:30], "apache_active": _active(_apache_unit()), "config": test_config(),
            "php_socket": php_socket(), "default_site": DEFAULT_CONF.exists(), "other_default": _other_default_server(), "sites": list_sites(probe=active), "other_configs": sorted(other)}


# ----------------------------------------------------------------------------- changing
def _open_firewall(https: bool) -> None:
    from . import firewall
    firewall.open_ports("80/tcp", *(["443/tcp"] if https else []))


def create(settings: dict) -> dict:
    if not installed():
        raise NginxError("Nginx isn't installed")
    s = clean(settings)
    for enabled in (True, False):
        if _conf(s["server_name"], enabled).exists():
            raise NginxError("A site with that name already exists")
    taken = {n for x in list_sites(probe=False) for n in [x["server_name"], *x["aliases"]]}
    clash = taken & {s["server_name"], *s["aliases"]}
    if clash:
        raise NginxError(f"Another site already answers for {', '.join(sorted(clash))}")
    text = render(s, php_socket())  # refuses before anything is created when PHP is missing
    _ensure_docroot(s)
    _ensure_cert(s)
    ensure_default()
    _apply({_conf(s["server_name"]): text})
    _open_firewall(s["https"] != "none")
    return {"ok": True, "site": s, "answer": _probe(s["server_name"]) if _active("nginx") else None}


def update(name: str, settings: dict) -> dict:
    current, enabled = _get(name)
    s = clean({**current, **(settings or {}), "server_name": current["server_name"]})
    taken = {n for x in list_sites(probe=False) if x["server_name"] != current["server_name"] for n in [x["server_name"], *x["aliases"]]}
    clash = taken & set(s["aliases"])
    if clash:
        raise NginxError(f"Another site already answers for {', '.join(sorted(clash))}")
    text = render(s, php_socket())
    _ensure_docroot(s)
    _ensure_cert(s)
    _apply({_conf(s["server_name"], enabled): text})
    _open_firewall(s["https"] != "none")
    return {"ok": True, "site": s}


def set_enabled(name: str, on: bool) -> dict:
    s, enabled = _get(name)
    if enabled == bool(on):
        return {"ok": True, "enabled": enabled}
    src, dst = _conf(s["server_name"], enabled), _conf(s["server_name"], bool(on))
    _apply({src: None, dst: src.read_text(encoding="utf-8")})
    return {"ok": True, "enabled": bool(on)}


def delete(name: str, delete_files: bool = False) -> dict:
    s, enabled = _get(name)
    _apply({_conf(s["server_name"], enabled): None})
    moved = None
    root = Path(s["docroot"])
    if delete_files and s["mode"] != "proxy" and root.exists() and root != WEB_BASE / "html" and _DOCROOT.match(str(root)):
        TRASH.mkdir(parents=True, exist_ok=True)
        moved = str(TRASH / f"{root.name}-{int(time.time())}")
        shutil.move(str(root), moved)  # to the recycle bin: gone from the web, but not gone
    crt, key = _cert_paths(s["server_name"])
    crt.unlink(missing_ok=True)
    key.unlink(missing_ok=True)
    return {"ok": True, "moved_to": moved}


def control(action: str) -> dict:
    if action not in ("reload", "restart"):
        raise NginxError("Unknown action")
    check = test_config()
    if not check["ok"]:
        raise NginxError("The configuration has an error, so Nginx was left as it is:\n" + check["output"])
    r = _run(["systemctl", action, "nginx"], 60)
    if r.returncode != 0:
        raise NginxError((r.stderr or r.stdout).strip()[-400:] or f"{action} failed")
    time.sleep(RELOAD_SETTLE)
    return {"ok": True, "active": _active("nginx")}


def logs(name: str, kind: str = "error", lines: int = 200) -> dict:
    s, _ = _get(name)
    if kind not in ("error", "access"):
        raise NginxError("Unknown log")
    path = LOG_DIR / f"{_slug(s['server_name'])}-{kind}.log"
    lines = max(1, min(int(lines), 2000))
    try:
        with path.open("rb") as f:
            f.seek(max(0, path.stat().st_size - 512_000))
            text = f.read().decode("utf-8", "replace")
    except OSError:
        return {"path": str(path), "lines": []}
    return {"path": str(path), "lines": text.splitlines()[-lines:]}


def import_apache() -> dict:
    """Give every Apache site an Nginx twin using the same files. Apache's own settings aren't changed, and .htaccess rules don't carry over."""
    from . import sites as apache
    done, skipped = [], []
    for x in apache.list_sites().get("sites", []):
        if x.get("system"):
            continue
        name = x.get("server_name", "")
        try:
            st = apache.get_site(name)["settings"]
            root = st.get("docroot") or ""
            has_php = any(Path(root).glob("*.php")) if root else False
            mode = "php" if (has_php and php_socket()) else "static"
            create({"server_name": name, "aliases": st.get("aliases") or [], "docroot": root, "mode": mode, "https": "selfsigned" if st.get("ssl") == "selfsigned" else "none"})
            done.append(name)
        except (NginxError, apache.SiteError, OSError) as exc:
            skipped.append({"name": name, "why": str(exc)[:200]})
    return {"imported": done, "skipped": skipped}

