"""Per-application configuration for System Applications.

Every app exposes:
  * settings  — a schema of the options people change most, read from the
                live config and written back in the app's own format;
  * files     — the main config files, editable as text (advanced);
  * logs      — recent log output;
  * extras    — Apache/Lighttpd modules on/off.

Every write is validated with the app's own checker (apache2ctl configtest,
nginx -t, lighttpd -tt, caddy validate, php-fpm -t) and then reloaded. If the
check or the restart fails, the previous files are restored and the error is
shown — a bad setting can't leave a server down. vsftpd lives in ftp.py."""
from __future__ import annotations

import glob
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import ftp


class AppConfigError(RuntimeError):
    pass


def _run(argv, check=True, timeout=60, input=None) -> subprocess.CompletedProcess:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AppConfigError(str(exc))
    if check and r.returncode != 0:
        raise AppConfigError((r.stderr or r.stdout or f"{argv[0]} failed").strip()[-600:])
    return r


def _active(unit: str) -> bool:
    return subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0


def _read(p) -> str:
    try:
        return Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _apply(writes: dict[Path, str | None], validate: list[str] | None, unit: str | None, action: str = "reload",
           extra_rollback=None):
    """Write files, validate, reload/restart; on any failure restore everything."""
    backup = {p: (p.read_text(encoding="utf-8", errors="replace") if p.exists() else None) for p in writes}

    def restore():
        for p, old in backup.items():
            if old is None:
                p.unlink(missing_ok=True)
            else:
                p.write_text(old, encoding="utf-8")
        if extra_rollback:
            extra_rollback()

    for p, text in writes.items():
        if text is None:
            p.unlink(missing_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
    if validate:
        r = subprocess.run(validate, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            restore()
            raise AppConfigError("The configuration check failed, nothing was changed:\n" + (r.stderr or r.stdout).strip()[-800:])
    if unit and _active(unit):
        r = subprocess.run(["systemctl", action, unit], capture_output=True, text=True, timeout=90)
        time.sleep(0.8)
        if r.returncode != 0 or not _active(unit):
            tail = subprocess.run(["journalctl", "-u", unit, "-n", "10", "--no-pager", "-o", "cat"], capture_output=True, text=True).stdout
            restore()
            subprocess.run(["systemctl", "restart", unit], capture_output=True, timeout=90)
            raise AppConfigError(f"{unit} failed with the new settings, so they were undone:\n" + tail.strip()[-800:])


# ---------------------------------------------------------------- helpers
_SIZE = re.compile(r"^\d+[kKmMgG]?$")


def _num(v, label, lo=0, hi=1 << 40) -> str:
    v = str(v).strip()
    if not re.match(r"^-?\d+$", v) or not lo <= int(v) <= hi:
        raise AppConfigError(f"{label}: whole number between {lo} and {hi}")
    return str(int(v))


def _clean_line(v, label) -> str:
    v = str(v).strip()
    if any(c in v for c in "\n\r;{}#\"'`$\\"):
        raise AppConfigError(f"{label}: contains characters that aren't allowed")
    return v


# ================================================================ Apache
APACHE_TUNING = Path("/etc/apache2/conf-available/zz-aurora-tuning.conf")
APACHE_SCHEMA = [
    {"title": "Security", "fields": [
        {"key": "ServerTokens", "label": "Server header detail", "type": "select",
         "options": [["Prod", "Prod — just \"Apache\" (recommended)"], ["Major", "Major"], ["Minor", "Minor"], ["OS", "OS — version + OS"], ["Full", "Full — everything"]]},
        {"key": "ServerSignature", "label": "Signature on error pages", "type": "select", "options": [["Off", "Off (recommended)"], ["On", "On"], ["EMail", "On + admin e-mail"]]},
        {"key": "TraceEnable", "label": "Allow HTTP TRACE", "type": "bool", "help": "Off is safer."},
        {"key": "security_headers", "label": "Add security headers", "type": "bool",
         "help": "X-Content-Type-Options, X-Frame-Options (SAMEORIGIN), Referrer-Policy and a Content-Security-Policy that only stops framing "
                 "(frame-ancestors 'self', never overriding a policy a site sets itself) on every response (needs mod_headers)."},
        {"key": "tls_modern", "label": "Modern TLS only", "type": "bool",
         "help": "TLS 1.2 and 1.3 with strong cipher suites only (Mozilla's intermediate list): no CBC / SHA-1 suites that scanners call weak. "
                 "Works with every browser and phone from the last ten years."},
        {"key": "ServerAdmin", "label": "Admin e-mail", "type": "text", "placeholder": "webmaster@localhost"},
    ]},
    {"title": "Connections & limits", "fields": [
        {"key": "Timeout", "label": "Request timeout (s)", "type": "int", "min": 5, "max": 3600},
        {"key": "KeepAlive", "label": "Keep-alive", "type": "bool", "help": "Reuse connections — faster pages."},
        {"key": "MaxKeepAliveRequests", "label": "Requests per keep-alive connection", "type": "int", "min": 0, "max": 100000},
        {"key": "KeepAliveTimeout", "label": "Keep-alive timeout (s)", "type": "int", "min": 1, "max": 300},
        {"key": "LimitRequestBody_mb", "label": "Max request body (MB)", "type": "int", "min": 0, "max": 102400,
         "help": "Largest upload/POST Apache accepts. 0 = unlimited. PHP has its own limit (PHP Settings)."},
    ]},
]
# Mozilla "intermediate" TLS 1.2 suites (TLS 1.3 suites are always on)
TLS_CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
               "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
               "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305")
HARDENED = {"ServerTokens": "Prod", "ServerSignature": "Off", "TraceEnable": "Off", "security_headers": "On", "tls_modern": "On"}


def strip_vhost_tls(conf: str) -> dict:
    """Disable a site's own SSLCipherSuite / SSLProtocol / SSLHonorCipherOrder lines (commented out, marked) so the
    server-wide "Modern TLS only" block applies to it too — a VirtualHost's own lines always win over it.
    The file is backed up first and put back if Apache rejects the result; the server-wide block is made sure of."""
    name = Path(conf or "").name
    if not name.endswith(".conf") or name != conf:
        raise AppConfigError("Pick a site configuration file")
    live = Path("/etc/apache2/sites-enabled") / name
    if live.is_symlink():
        live = live.resolve()
    if not live.is_file():
        raise AppConfigError(f"{name} is not enabled")
    text = live.read_text(errors="replace")
    new, n = re.subn(r"(?im)^([ \t]*)(SSL(?:CipherSuite|Protocol|HonorCipherOrder)\s[^\n]*)$", r"\1# aurora-tls-modern: \2", text)
    if n:
        bak = Path("/var/lib/aurora/site-backups")
        bak.mkdir(parents=True, exist_ok=True)
        shutil.copy2(live, bak / f"{name}.{int(time.time())}")
        live.write_text(new, encoding="utf-8")
        test = subprocess.run(["apache2ctl", "configtest"], capture_output=True, text=True, timeout=60)
        if test.returncode != 0:
            live.write_text(text, encoding="utf-8")
            err = "\n".join(l for l in (test.stderr + test.stdout).splitlines() if "AH00558" not in l).strip()
            raise AppConfigError("Apache rejected the config, nothing was changed:\n" + err[:1500])
    h = apache_hardening()
    if h.get("available") and h["ok"] < h["total"]:
        apache_harden()  # writes the server-wide block and reloads
    elif n:
        if subprocess.run(["systemctl", "reload", "apache2"], capture_output=True, timeout=60).returncode != 0:
            subprocess.run(["systemctl", "restart", "apache2"], capture_output=True, timeout=120)
    return {"ok": True, "changed": n, "file": str(live)}


def apache_hardening() -> dict:
    """Which of the recommended web-server settings are on (for Global Security)."""
    if not Path("/etc/apache2/apache2.conf").exists():
        return {"available": False, "items": [], "ok": 0, "total": 0}
    v = apache_settings()["values"]
    labels = {"ServerTokens": "Server header hides the Apache version", "ServerSignature": "No server signature on error pages",
              "TraceEnable": "HTTP TRACE off", "security_headers": "Security headers on every site", "tls_modern": "Modern TLS only"}
    items = [{"key": k, "label": labels[k], "ok": v.get(k) == want, "value": v.get(k)} for k, want in HARDENED.items()]
    return {"available": True, "items": items, "ok": sum(1 for i in items if i["ok"]), "total": len(items)}


def apache_harden() -> dict:
    """Apply every recommended setting at once (validated and rolled back like any Apache save)."""
    return apache_save(dict(HARDENED))


_APACHE_DIRECTIVES = ["ServerTokens", "ServerSignature", "TraceEnable", "ServerAdmin", "Timeout", "KeepAlive",
                      "MaxKeepAliveRequests", "KeepAliveTimeout", "LimitRequestBody"]
APACHE_PROTECTED = {"authz_core", "authz_host", "dir", "mime", "alias", "env", "setenvif", "filter", "deflate",
                    "reqtimeout", "status", "autoindex", "negotiation", "access_compat", "authn_core", "authn_file",
                    "auth_basic", "authz_user"}
APACHE_POPULAR = {
    "rewrite": "URL rewriting (.htaccess, WordPress permalinks)", "ssl": "HTTPS", "headers": "Custom HTTP headers",
    "expires": "Browser caching headers", "http2": "HTTP/2 — faster HTTPS", "proxy": "Reverse proxy (base)",
    "proxy_http": "Proxy to HTTP backends (Node, Python apps)", "proxy_fcgi": "PHP-FPM via FastCGI",
    "proxy_wstunnel": "Proxy WebSockets", "remoteip": "Real client IP behind a proxy/Cloudflare",
    "security2": "ModSecurity web firewall", "dav": "WebDAV (Web Disk)", "dav_fs": "WebDAV file storage",
    "cgi": "CGI scripts", "userdir": "~user home pages", "ratelimit": "Bandwidth limiting", "brotli": "Brotli compression",
}


def _apache_scan() -> dict[str, str]:
    """Last top-level value of each directive, in Apache's load order."""
    files = ["/etc/apache2/apache2.conf"] + sorted(glob.glob("/etc/apache2/conf-enabled/*.conf"))
    vals: dict[str, str] = {}
    for f in files:
        depth = 0
        for line in _read(f).splitlines():
            s = line.strip()
            if s.startswith("</"):
                depth = max(0, depth - 1)
                continue
            if s.startswith("<"):
                depth += 1
                continue
            if depth or s.startswith("#"):
                continue
            m = re.match(r"^(\w+)\s+(.+?)\s*$", s)
            if m and m.group(1) in _APACHE_DIRECTIVES:
                vals[m.group(1)] = m.group(2).strip('"')
    return vals


def apache_settings() -> dict:
    v = _apache_scan()
    t = _read(APACHE_TUNING)
    values = {
        "ServerTokens": v.get("ServerTokens", "Full"), "ServerSignature": v.get("ServerSignature", "On"),
        "TraceEnable": v.get("TraceEnable", "On"), "ServerAdmin": v.get("ServerAdmin", ""),
        "Timeout": v.get("Timeout", "300"), "KeepAlive": v.get("KeepAlive", "On"),
        "MaxKeepAliveRequests": v.get("MaxKeepAliveRequests", "100"), "KeepAliveTimeout": v.get("KeepAliveTimeout", "5"),
        "LimitRequestBody_mb": str(int(v.get("LimitRequestBody", "0") or 0) // 1048576),
        "security_headers": "On" if "aurora-security-headers" in t else "Off",
        "tls_modern": "On" if "aurora-tls-modern" in t else "Off",
    }
    return {"schema": APACHE_SCHEMA, "values": values, "bool_values": ["On", "Off"]}


def apache_save(changes: dict) -> dict:
    cur = apache_settings()["values"]
    new = {**cur}
    for k, val in (changes or {}).items():
        f = next((f for s in APACHE_SCHEMA for f in s["fields"] if f["key"] == k), None)
        if not f:
            raise AppConfigError(f"Unknown setting {k}")
        if f["type"] == "bool":
            new[k] = "On" if str(val).lower() in ("on", "yes", "true", "1") else "Off"
        elif f["type"] == "select":
            if val not in [o[0] for o in f["options"]]:
                raise AppConfigError(f"{f['label']}: invalid choice")
            new[k] = val
        elif f["type"] == "int":
            new[k] = _num(val, f["label"], f.get("min", 0), f.get("max", 1 << 40))
        else:
            val = _clean_line(val, f["label"])
            if k == "ServerAdmin" and val and not re.match(r"^[^@\s]+@[^@\s]+$", val):
                raise AppConfigError("Admin e-mail looks invalid")
            new[k] = val
    lines = ["# Managed by AuroraPanel — Apache tuning (loaded last, so it wins).",
             f"ServerTokens {new['ServerTokens']}", f"ServerSignature {new['ServerSignature']}",
             f"TraceEnable {new['TraceEnable']}", f"Timeout {new['Timeout']}", f"KeepAlive {new['KeepAlive']}",
             f"MaxKeepAliveRequests {new['MaxKeepAliveRequests']}", f"KeepAliveTimeout {new['KeepAliveTimeout']}",
             f"LimitRequestBody {int(new['LimitRequestBody_mb']) * 1048576}"]
    if new.get("ServerAdmin"):
        lines.append(f"ServerAdmin {new['ServerAdmin']}")
    if new["security_headers"] == "On":
        if not Path("/etc/apache2/mods-enabled/headers.load").exists():
            _run(["a2enmod", "-q", "headers"])
        lines += ["# aurora-security-headers", "<IfModule mod_headers.c>",
                  '    Header always set X-Content-Type-Options "nosniff"',
                  '    Header always set X-Frame-Options "SAMEORIGIN"',
                  '    Header always set Referrer-Policy "strict-origin-when-cross-origin"',
                  "    Header always setifempty Content-Security-Policy \"frame-ancestors 'self'\"", "</IfModule>"]
    if new["tls_modern"] == "On":
        lines += ["# aurora-tls-modern", "<IfModule mod_ssl.c>",
                  "    SSLProtocol -all +TLSv1.2 +TLSv1.3",
                  f"    SSLCipherSuite {TLS_CIPHERS}",
                  "    SSLHonorCipherOrder off", "    SSLSessionTickets off", "</IfModule>"]
    enabled_link = Path("/etc/apache2/conf-enabled") / APACHE_TUNING.name

    def enable():
        if not enabled_link.exists():
            _run(["a2enconf", "-q", APACHE_TUNING.stem])
    was_enabled = enabled_link.exists()
    APACHE_TUNING.parent.mkdir(parents=True, exist_ok=True)
    old = _read(APACHE_TUNING) if APACHE_TUNING.exists() else None
    APACHE_TUNING.write_text("\n".join(lines) + "\n", encoding="utf-8")
    enable()

    def undo():
        if old is None:
            APACHE_TUNING.unlink(missing_ok=True)
        else:
            APACHE_TUNING.write_text(old, encoding="utf-8")
        if not was_enabled:
            _run(["a2disconf", "-q", APACHE_TUNING.stem], check=False)
    r = subprocess.run(["apache2ctl", "configtest"], capture_output=True, text=True)
    if r.returncode != 0:
        undo()
        raise AppConfigError("Apache rejected the settings, nothing was changed:\n" + r.stderr.strip()[-600:])
    if _active("apache2"):
        rr = subprocess.run(["systemctl", "reload", "apache2"], capture_output=True, text=True, timeout=60)
        if rr.returncode != 0:
            undo()
            subprocess.run(["systemctl", "restart", "apache2"], capture_output=True, timeout=60)
            raise AppConfigError("Apache failed to reload, settings undone: " + rr.stderr.strip()[-400:])
    return {"ok": True, **apache_settings()}


def apache_modules() -> list[dict]:
    avail = sorted(Path(p).stem for p in glob.glob("/etc/apache2/mods-available/*.load"))
    enabled = {Path(p).stem for p in glob.glob("/etc/apache2/mods-enabled/*.load")}
    return [{"name": m, "enabled": m in enabled, "desc": APACHE_POPULAR.get(m, ""), "popular": m in APACHE_POPULAR,
             "protected": m in APACHE_PROTECTED or m.startswith(("mpm_", "php"))} for m in avail]


def apache_module(name: str, on: bool) -> dict:
    mods = {m["name"]: m for m in apache_modules()}
    if name not in mods:
        raise AppConfigError("Unknown module")
    if mods[name]["protected"] and not on:
        raise AppConfigError(f"{name} is required by Apache or managed elsewhere (PHP version: PHP Settings)")
    _run(["a2enmod" if on else "a2dismod", "-q", "-f", name] if not on else ["a2enmod", "-q", name])
    r = subprocess.run(["apache2ctl", "configtest"], capture_output=True, text=True)
    if r.returncode != 0:
        _run(["a2dismod", "-q", "-f", name] if on else ["a2enmod", "-q", name], check=False)
        raise AppConfigError("Apache rejected that change, it was undone:\n" + r.stderr.strip()[-500:])
    if _active("apache2"):
        _run(["systemctl", "restart", "apache2"], timeout=90)
    return {"ok": True}


# ================================================================ Nginx
NGINX_CONF = Path("/etc/nginx/nginx.conf")
NGINX_FIELDS = [  # key, context, label, type, extra
    ("worker_processes", "main", "Worker processes", "text", {"help": "auto = one per CPU core (recommended)."}),
    ("worker_connections", "events", "Connections per worker", "int", {"min": 64, "max": 65535}),
    ("client_max_body_size", "http", "Max upload / request body", "size", {"help": "e.g. 64m. Default 1m — too small for most uploads. 0 = unlimited."}),
    ("keepalive_timeout", "http", "Keep-alive timeout (s)", "int", {"min": 0, "max": 600}),
    ("client_body_timeout", "http", "Request body timeout (s)", "int", {"min": 1, "max": 3600}),
    ("server_tokens", "http", "Show version in headers/errors", "bool", {"help": "Off hides the nginx version."}),
    ("gzip", "http", "Gzip compression", "bool", {}),
    ("gzip_comp_level", "http", "Gzip level (1–9)", "int", {"min": 1, "max": 9}),
    ("sendfile", "http", "sendfile (fast static files)", "bool", {}),
]


def _nginx_blocks(text: str):
    """Yield (context, line_index) for every line: main / events / http (top level of those blocks)."""
    ctx_stack = []
    for i, line in enumerate(text.splitlines()):
        s = re.sub(r"#.*", "", line).strip()
        ctx = ctx_stack[-1] if ctx_stack else "main"
        yield ctx, i, s
        for m in re.finditer(r"(\w+)?\s*\{|\}", s):
            if m.group(0) == "}":
                if ctx_stack:
                    ctx_stack.pop()
            else:
                name = m.group(1) or "block"
                ctx_stack.append(name if (not ctx_stack and name in ("events", "http")) else "nested")


def nginx_settings() -> dict:
    text = _read(NGINX_CONF)
    vals = {}
    for ctx, _i, s in _nginx_blocks(text):
        for key, c, *_ in NGINX_FIELDS:
            m = re.match(rf"^{key}\s+([^;]+);", s)
            if m and ctx == c:
                vals[key] = m.group(1).strip()
    defaults = {"worker_processes": "1", "worker_connections": "512", "client_max_body_size": "1m", "keepalive_timeout": "75",
                "client_body_timeout": "60", "server_tokens": "on", "gzip": "off", "gzip_comp_level": "1", "sendfile": "off"}
    values = {k: vals.get(k, defaults[k]) for k, *_ in NGINX_FIELDS}
    values["keepalive_timeout"] = values["keepalive_timeout"].split()[0].rstrip("s")
    values["client_body_timeout"] = values["client_body_timeout"].rstrip("s")
    schema = [{"title": "Performance & limits", "fields": [
        {"key": k, "label": l, "type": t, **e} for k, c, l, t, e in NGINX_FIELDS]}]
    return {"schema": schema, "values": values, "bool_values": ["on", "off"]}


def nginx_save(changes: dict) -> dict:
    fields = {k: (c, l, t, e) for k, c, l, t, e in NGINX_FIELDS}
    clean = {}
    for k, v in (changes or {}).items():
        if k not in fields:
            raise AppConfigError(f"Unknown setting {k}")
        c, l, t, e = fields[k]
        if t == "bool":
            v = "on" if str(v).lower() in ("on", "yes", "true", "1") else "off"
        elif t == "int":
            v = _num(v, l, e.get("min", 0), e.get("max", 1 << 30))
        elif t == "size":
            v = str(v).strip().lower()
            if not _SIZE.match(v):
                raise AppConfigError(f"{l}: e.g. 64m or 1g")
        else:
            v = _clean_line(v, l)
            if k == "worker_processes" and not re.match(r"^(auto|\d{1,3})$", v):
                raise AppConfigError("Worker processes: auto or a number")
        clean[k] = v
    lines = _read(NGINX_CONF).splitlines()
    placed = set()
    blocks = list(_nginx_blocks("\n".join(lines)))
    for ctx, i, s in blocks:
        for k, v in clean.items():
            c = fields[k][0]
            if ctx == c and re.match(rf"^(#\s*)?{k}\s+[^;]*;", lines[i].strip()) and k not in placed:
                indent = re.match(r"^\s*", lines[i]).group(0)
                lines[i] = f"{indent}{k} {v};"
                placed.add(k)
    for k, v in clean.items():
        if k in placed:
            continue
        c = fields[k][0]
        if c == "main":
            lines.insert(0, f"{k} {v};")
        else:
            idx = next((i for i, l in enumerate(lines) if re.match(rf"^\s*{c}\s*\{{", l)), None)
            if idx is None:
                raise AppConfigError(f"Couldn't find the {c} block in nginx.conf")
            lines.insert(idx + 1, f"\t{k} {v};")
    _apply({NGINX_CONF: "\n".join(lines) + "\n"}, ["nginx", "-t"], "nginx", "reload")
    return {"ok": True, **nginx_settings()}


# ================================================================ Lighttpd
LIGHTTPD_CONF = Path("/etc/lighttpd/lighttpd.conf")
LIGHTTPD_FIELDS = [
    ("server.port", "Port", "port", {}),
    ("server.document-root", "Web folder", "text", {"help": "Folder served for the default site."}),
    ("server.max-request-size", "Max request size (KB)", "int", {"min": 0, "max": 104857600, "help": "0 = unlimited."}),
    ("server.tag", "Server header", "text", {"help": "Empty hides the lighttpd version."}),
    ("server.max-keep-alive-requests", "Keep-alive requests", "int", {"min": 0, "max": 100000}),
    ("dir-listing.activate", "Directory listings", "bool", {}),
]


def lighttpd_settings() -> dict:
    text = _read(LIGHTTPD_CONF)
    vals = {}
    for k, *_ in LIGHTTPD_FIELDS:
        m = re.search(rf'(?m)^\s*{re.escape(k)}\s*=\s*"?([^"\n]*)"?\s*$', text)
        if m:
            vals[k] = m.group(1)
    defaults = {"server.port": "80", "server.document-root": "/var/www/html", "server.max-request-size": "0",
                "server.tag": "lighttpd", "server.max-keep-alive-requests": "100", "dir-listing.activate": "disable"}
    values = {k: vals.get(k, defaults[k]) for k, *_ in LIGHTTPD_FIELDS}
    schema = [{"title": "Server", "fields": [{"key": k, "label": l, "type": t, **e} for k, l, t, e in LIGHTTPD_FIELDS]}]
    return {"schema": schema, "values": values, "bool_values": ["enable", "disable"]}


def lighttpd_save(changes: dict) -> dict:
    fields = {k: (l, t, e) for k, l, t, e in LIGHTTPD_FIELDS}
    text = _read(LIGHTTPD_CONF)
    for k, v in (changes or {}).items():
        if k not in fields:
            raise AppConfigError(f"Unknown setting {k}")
        l, t, e = fields[k]
        if t == "bool":
            val = '"enable"' if str(v).lower() in ("enable", "on", "yes", "true", "1") else '"disable"'
        elif t in ("int", "port"):
            val = _num(v, l, 1 if t == "port" else e.get("min", 0), 65535 if t == "port" else e.get("max", 1 << 40))
        else:
            v = _clean_line(v, l)
            if k == "server.document-root" and not v.startswith("/"):
                raise AppConfigError("Web folder must be an absolute path")
            val = f'"{v}"'
        line = f"{k} = {val}"
        if re.search(rf"(?m)^\s*#?\s*{re.escape(k)}\s*=", text):
            text = re.sub(rf"(?m)^\s*#?\s*{re.escape(k)}\s*=.*$", line, text, count=1)
        else:
            text += f"\n{line}\n"
    _apply({LIGHTTPD_CONF: text}, ["lighttpd", "-tt", "-f", str(LIGHTTPD_CONF)], "lighttpd", "restart")
    return {"ok": True, **lighttpd_settings()}


def lighttpd_modules() -> list[dict]:
    avail = sorted(Path(p).stem.split("-", 1)[1] for p in glob.glob("/etc/lighttpd/conf-available/[0-9][0-9]-*.conf"))
    enabled = {Path(p).stem.split("-", 1)[1] for p in glob.glob("/etc/lighttpd/conf-enabled/[0-9][0-9]-*.conf")}
    return [{"name": m, "enabled": m in enabled, "desc": "", "popular": m in ("fastcgi-php", "rewrite", "ssl", "accesslog", "compress", "userdir"), "protected": False} for m in avail]


def lighttpd_module(name: str, on: bool) -> dict:
    if name not in {m["name"] for m in lighttpd_modules()}:
        raise AppConfigError("Unknown module")
    _run(["lighty-enable-mod" if on else "lighty-disable-mod", name], check=False)
    r = subprocess.run(["lighttpd", "-tt", "-f", str(LIGHTTPD_CONF)], capture_output=True, text=True)
    if r.returncode != 0:
        _run(["lighty-disable-mod" if on else "lighty-enable-mod", name], check=False)
        raise AppConfigError("lighttpd rejected that change, it was undone:\n" + (r.stderr or r.stdout)[-500:])
    if _active("lighttpd"):
        _run(["systemctl", "restart", "lighttpd"])
    return {"ok": True}


# ================================================================ MariaDB
MARIADB_OVERRIDE = Path("/etc/mysql/mariadb.conf.d/99-aurora.cnf")
MARIADB_SCHEMA = [
    {"title": "Network", "desc": "Remote access also needs a database user allowed from other hosts (Databases section) and the port open in the firewall.", "fields": [
        {"key": "remote_access", "label": "Allow connections from other computers", "type": "bool",
         "help": "Off = only apps on this Pi can connect (safest)."},
        {"key": "port", "label": "Port", "type": "port"},
        {"key": "skip_name_resolve", "label": "Skip DNS lookups for clients", "type": "bool", "help": "Faster connects; grant users by IP."},
        {"key": "max_connections", "label": "Max connections", "type": "int", "min": 10, "max": 10000},
        {"key": "wait_timeout", "label": "Idle connection timeout (s)", "type": "int", "min": 10, "max": 31536000},
    ]},
    {"title": "Memory & performance", "desc": "On a Pi keep the buffer pool well below total RAM (e.g. 256M on 4 GB).", "fields": [
        {"key": "innodb_buffer_pool_size", "label": "InnoDB buffer pool", "type": "size"},
        {"key": "max_allowed_packet", "label": "Max packet / row size", "type": "size", "help": "Raise for big imports (e.g. 64M)."},
        {"key": "tmp_table_size", "label": "In-memory temp table size", "type": "size"},
    ]},
    {"title": "Text & logging", "fields": [
        {"key": "character_set_server", "label": "Default character set", "type": "select",
         "options": [["utf8mb4", "utf8mb4 (full Unicode, emoji — recommended)"], ["utf8mb3", "utf8mb3"], ["latin1", "latin1"]]},
        {"key": "collation_server", "label": "Default collation", "type": "select",
         "options": [["utf8mb4_general_ci", "utf8mb4_general_ci"], ["utf8mb4_unicode_ci", "utf8mb4_unicode_ci"], ["utf8mb4_uca1400_ai_ci", "utf8mb4_uca1400_ai_ci"],
                     ["utf8mb3_general_ci", "utf8mb3_general_ci"], ["latin1_swedish_ci", "latin1_swedish_ci"]]},
        {"key": "slow_query_log", "label": "Log slow queries", "type": "bool"},
        {"key": "long_query_time", "label": "Slow query threshold (s)", "type": "int", "min": 0, "max": 3600},
    ]},
]


def _human(n) -> str:
    n = int(n)
    for unit, div in (("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10)):
        if n >= div and n % div == 0:
            return f"{n // div}{unit}"
    return str(n)


def mariadb_settings() -> dict:
    q = ("SELECT @@bind_address, @@port, @@skip_name_resolve, @@max_connections, @@wait_timeout, @@innodb_buffer_pool_size,"
         " @@max_allowed_packet, @@tmp_table_size, @@character_set_server, @@collation_server, @@slow_query_log, @@long_query_time")
    r = _run(["mysql", "-N", "-B", "-e", q], check=False, timeout=15)
    if r.returncode != 0:
        raise AppConfigError("MariaDB isn't running (start it first): " + r.stderr.strip()[-200:])
    f = r.stdout.strip().split("\t")
    values = {"remote_access": "On" if f[0] not in ("127.0.0.1", "localhost", "::1") else "Off", "port": f[1],
              "skip_name_resolve": "On" if f[2] == "1" else "Off", "max_connections": f[3], "wait_timeout": f[4],
              "innodb_buffer_pool_size": _human(f[5]), "max_allowed_packet": _human(f[6]), "tmp_table_size": _human(f[7]),
              "character_set_server": f[8], "collation_server": f[9], "slow_query_log": "On" if f[10] == "1" else "Off",
              "long_query_time": str(int(float(f[11])))}
    return {"schema": MARIADB_SCHEMA, "values": values, "bool_values": ["On", "Off"]}


def mariadb_save(changes: dict) -> dict:
    cur = mariadb_settings()["values"]
    new = {**cur}
    for k, v in (changes or {}).items():
        fdef = next((f for s in MARIADB_SCHEMA for f in s["fields"] if f["key"] == k), None)
        if not fdef:
            raise AppConfigError(f"Unknown setting {k}")
        if fdef["type"] == "bool":
            new[k] = "On" if str(v).lower() in ("on", "yes", "true", "1") else "Off"
        elif fdef["type"] in ("int", "port"):
            new[k] = _num(v, fdef["label"], 1 if fdef["type"] == "port" else fdef.get("min", 0), 65535 if fdef["type"] == "port" else fdef.get("max", 1 << 40))
        elif fdef["type"] == "size":
            v = str(v).strip().upper()
            if not _SIZE.match(v):
                raise AppConfigError(f"{fdef['label']}: e.g. 256M")
            new[k] = v
        else:
            if v not in [o[0] for o in fdef["options"]]:
                raise AppConfigError(f"{fdef['label']}: invalid choice")
            new[k] = v
    if not new["collation_server"].startswith(new["character_set_server"]):
        raise AppConfigError("Collation must match the character set (e.g. utf8mb4 → utf8mb4_general_ci)")
    lines = ["# Managed by AuroraPanel — loaded after 50-server.cnf, so these win.", "[mysqld]",
             f"bind-address = {'0.0.0.0' if new['remote_access'] == 'On' else '127.0.0.1'}", f"port = {new['port']}",
             f"max_connections = {new['max_connections']}", f"wait_timeout = {new['wait_timeout']}",
             f"innodb_buffer_pool_size = {new['innodb_buffer_pool_size']}", f"max_allowed_packet = {new['max_allowed_packet']}",
             f"tmp_table_size = {new['tmp_table_size']}", f"max_heap_table_size = {new['tmp_table_size']}",
             f"character-set-server = {new['character_set_server']}", f"collation-server = {new['collation_server']}",
             f"slow_query_log = {1 if new['slow_query_log'] == 'On' else 0}", f"long_query_time = {new['long_query_time']}"]
    if new["skip_name_resolve"] == "On":
        lines.append("skip-name-resolve")
    _apply({MARIADB_OVERRIDE: "\n".join(lines) + "\n"}, None, "mariadb", "restart")
    return {"ok": True, **mariadb_settings()}


# ================================================================ PostgreSQL
# Settings go in conf.d/99-aurora.conf (Debian's postgresql.conf has include_dir 'conf.d',
# read last, so these win); remote access adds a marked block to pg_hba.conf. Changes
# are checked with PostgreSQL's own pg_file_settings / pg_hba_file_rules views before
# the cluster unit (postgresql@VER-NAME — the plain "postgresql" unit is a dummy that
# stays "active" even when the database is down) is restarted.
PG_HBA_BEGIN = "# aurora-remote begin (managed by AuroraPanel — edit in System Applications → PostgreSQL)"
PG_HBA_END = "# aurora-remote end"
PG_SCHEMA = [
    {"title": "Network", "desc": "Remote access also needs a database role with a password (PostgreSQL Wizard) and port open in the firewall.", "fields": [
        {"key": "remote_access", "label": "Allow connections from other computers", "type": "bool",
         "help": "Off = only apps on this Pi can connect (safest)."},
        {"key": "remote_from", "label": "Allowed networks", "type": "text", "placeholder": "192.168.0.0/24",
         "help": "Comma-separated addresses or networks that may log in with a password, e.g. your LAN 192.168.0.0/24."},
        {"key": "port", "label": "Port", "type": "port"},
        {"key": "max_connections", "label": "Max connections", "type": "int", "min": 5, "max": 10000},
        {"key": "ssl", "label": "Encrypt connections (SSL)", "type": "bool", "help": "Uses the certificate set in postgresql.conf (a self-signed one on Debian)."},
    ]},
    {"title": "Memory & performance", "desc": "On a Pi: shared buffers ≈ 1/4 of RAM at most (e.g. 256MB on 2 GB, 1GB on 8 GB).", "fields": [
        {"key": "shared_buffers", "label": "Shared buffers", "type": "size", "help": "e.g. 256MB"},
        {"key": "work_mem", "label": "Memory per sort / hash", "type": "size", "help": "Per operation, per connection — keep small (4–16MB)."},
        {"key": "maintenance_work_mem", "label": "Maintenance memory", "type": "size", "help": "VACUUM, CREATE INDEX (e.g. 64MB)."},
        {"key": "effective_cache_size", "label": "Expected OS cache", "type": "size", "help": "A planner hint, not an allocation — about 1/2 of RAM."},
    ]},
    {"title": "Logging & maintenance", "fields": [
        {"key": "slow_query_ms", "label": "Log queries slower than (ms)", "type": "int", "min": 0, "max": 3600000, "help": "0 = off."},
        {"key": "log_connections", "label": "Log every connection", "type": "bool"},
        {"key": "autovacuum", "label": "Autovacuum", "type": "bool", "help": "Keep on — it reclaims space and keeps statistics fresh."},
    ]},
]
_PG_SETTINGS = ["listen_addresses", "port", "max_connections", "ssl", "shared_buffers", "work_mem",
                "maintenance_work_mem", "effective_cache_size", "log_min_duration_statement", "log_connections", "autovacuum"]
_PG_SIZE = re.compile(r"^(\d+)\s*(kB|KB|kb|k|K|MB|Mb|mb|M|m|GB|Gb|gb|G|g|TB|tb|T|t)?$")


def _pg_cluster() -> tuple[str, str, Path] | None:
    """(version, name, config dir) of the first cluster, from pg_lsclusters."""
    if not shutil.which("pg_lsclusters"):
        return None
    r = _run(["pg_lsclusters", "-h"], check=False, timeout=10)
    for line in r.stdout.splitlines():
        c = line.split()
        if len(c) >= 2 and Path(f"/etc/postgresql/{c[0]}/{c[1]}").is_dir():
            return c[0], c[1], Path(f"/etc/postgresql/{c[0]}/{c[1]}")
    return None


def _pg_psql(sql: str, check=True) -> subprocess.CompletedProcess:
    return _run(["runuser", "-u", "postgres", "--", "psql", "-X", "-tA", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-c", sql],
                check=check, timeout=30)


# Fails (non-zero exit, readable message) if the config files on disk contain an error.
# "setting could not be applied" only means "needs a restart" (e.g. max_connections) —
# the restart that follows applies it, so that one isn't an error.
_PG_VALIDATE_SQL = (
    "DO $$ DECLARE msg text; BEGIN "
    "SELECT string_agg(coalesce(sourcefile,'?') || ':' || coalesce(sourceline::text,'?') || ' ' || coalesce(name,'') || ': ' || error, E'\\n') "
    "INTO msg FROM pg_file_settings WHERE error IS NOT NULL AND error <> 'setting could not be applied'; "
    "IF msg IS NULL THEN SELECT string_agg('pg_hba.conf line ' || line_number || ': ' || error, E'\\n') INTO msg "
    "FROM pg_hba_file_rules WHERE error IS NOT NULL; END IF; "
    "IF msg IS NOT NULL THEN RAISE EXCEPTION '%', msg; END IF; END $$;")


def _pg_validate() -> list[str]:
    # Built before the new files are written, so it connects on the port the server is
    # running on now — after a port change psql would otherwise look for the new one.
    port = []
    r = _run(["pg_lsclusters", "-h"], check=False, timeout=10) if shutil.which("pg_lsclusters") else None
    for line in (r.stdout.splitlines() if r else []):
        c = line.split()
        if len(c) >= 3 and c[2].isdigit():
            port = ["-p", c[2]]
            break
    return ["runuser", "-u", "postgres", "--", "psql", "-X", "-q", *port, "-v", "ON_ERROR_STOP=1", "-c", _PG_VALIDATE_SQL]


def _pg_unit() -> str | None:
    c = _pg_cluster()
    return f"postgresql@{c[0]}-{c[1]}" if c else None


def _pg_hba_strip(text: str) -> str:
    return re.sub(rf"\n?{re.escape(PG_HBA_BEGIN)}.*?{re.escape(PG_HBA_END)}\n?", "\n", text, flags=re.S)


def _pg_hba_networks(text: str) -> list[str]:
    m = re.search(rf"{re.escape(PG_HBA_BEGIN)}(.*?){re.escape(PG_HBA_END)}", text, re.S)
    return re.findall(r"(?m)^host\s+all\s+all\s+(\S+)\s+scram-sha-256", m.group(1)) if m else []


def _pg_size(v, label) -> str:
    m = _PG_SIZE.match(str(v).strip())
    if not m:
        raise AppConfigError(f"{label}: e.g. 256MB")
    unit = {"k": "kB", "m": "MB", "g": "GB", "t": "TB"}[(m.group(2) or "MB")[0].lower()]
    return f"{int(m.group(1))}{unit}"


def _pg_bytes(size: str) -> int:
    m = re.match(r"^(\d+)(kB|MB|GB|TB)$", size)
    return int(m.group(1)) * {"kB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30, "TB": 1 << 40}[m.group(2)] if m else 0


def postgresql_settings() -> dict:
    c = _pg_cluster()
    if not c:
        raise AppConfigError("PostgreSQL isn't installed (no database cluster found)")
    names = ", ".join(f"'{n}'" for n in _PG_SETTINGS)
    r = _pg_psql(f"SELECT name, current_setting(name), setting FROM pg_settings WHERE name IN ({names})", check=False)
    if r.returncode != 0:
        raise AppConfigError("PostgreSQL isn't running (start it first): " + r.stderr.strip()[-200:])
    human, raw = {}, {}
    for line in r.stdout.splitlines():
        f = line.split("\t")
        if len(f) == 3:
            human[f[0]], raw[f[0]] = f[1], f[2]
    onoff = lambda n: "On" if human.get(n) == "on" else "Off"
    slow = int(raw.get("log_min_duration_statement", "-1") or -1)
    nets = _pg_hba_networks(_read(c[2] / "pg_hba.conf"))
    values = {"remote_access": "Off" if human.get("listen_addresses", "localhost") in ("localhost", "127.0.0.1", "::1", "") else "On",
              "remote_from": ", ".join(nets), "port": raw.get("port", "5432"), "max_connections": raw.get("max_connections", "100"),
              "ssl": onoff("ssl"), "shared_buffers": human.get("shared_buffers", ""), "work_mem": human.get("work_mem", ""),
              "maintenance_work_mem": human.get("maintenance_work_mem", ""), "effective_cache_size": human.get("effective_cache_size", ""),
              "slow_query_ms": str(max(slow, 0)), "log_connections": onoff("log_connections"), "autovacuum": onoff("autovacuum")}
    return {"schema": PG_SCHEMA, "values": values, "bool_values": ["On", "Off"], "version": c[0], "cluster": c[1]}


def postgresql_save(changes: dict) -> dict:
    import ipaddress
    import os
    ver, name, confdir = _pg_cluster() or (None, None, None)
    if not confdir:
        raise AppConfigError("PostgreSQL isn't installed (no database cluster found)")
    new = {**postgresql_settings()["values"]}
    for k, v in (changes or {}).items():
        fdef = next((f for s in PG_SCHEMA for f in s["fields"] if f["key"] == k), None)
        if not fdef:
            raise AppConfigError(f"Unknown setting {k}")
        if fdef["type"] == "bool":
            new[k] = "On" if str(v).lower() in ("on", "yes", "true", "1") else "Off"
        elif fdef["type"] in ("int", "port"):
            new[k] = _num(v, fdef["label"], 1 if fdef["type"] == "port" else fdef.get("min", 0), 65535 if fdef["type"] == "port" else fdef.get("max", 1 << 40))
        elif fdef["type"] == "size":
            new[k] = _pg_size(v, fdef["label"])
        else:
            new[k] = str(v).strip()
    for k in ("shared_buffers", "work_mem", "maintenance_work_mem", "effective_cache_size"):
        new[k] = _pg_size(new[k], k)
    try:
        ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        ram = 0
    if ram and _pg_bytes(new["shared_buffers"]) > ram // 2:
        raise AppConfigError(f"Shared buffers {new['shared_buffers']} is more than half of this Pi's RAM — PostgreSQL wouldn't start reliably")
    nets = []
    for part in [p.strip() for p in new["remote_from"].split(",") if p.strip()]:
        try:
            nets.append(str(ipaddress.ip_network(part, strict=False)))
        except ValueError:
            raise AppConfigError(f"Allowed networks: {part!r} isn't an address or network (e.g. 192.168.0.0/24)")
    if new["remote_access"] == "On" and not nets:
        raise AppConfigError("Remote access needs at least one allowed network, e.g. 192.168.0.0/24")

    slow = int(new["slow_query_ms"])
    conf = "\n".join([
        "# Managed by AuroraPanel — conf.d is read after postgresql.conf, so these win.",
        f"listen_addresses = '{'*' if new['remote_access'] == 'On' else 'localhost'}'",
        f"port = {new['port']}", f"max_connections = {new['max_connections']}",
        f"ssl = {'on' if new['ssl'] == 'On' else 'off'}",
        f"shared_buffers = '{new['shared_buffers']}'", f"work_mem = '{new['work_mem']}'",
        f"maintenance_work_mem = '{new['maintenance_work_mem']}'", f"effective_cache_size = '{new['effective_cache_size']}'",
        f"log_min_duration_statement = {slow if slow > 0 else -1}",
        f"log_connections = {'on' if new['log_connections'] == 'On' else 'off'}",
        f"autovacuum = {'on' if new['autovacuum'] == 'On' else 'off'}",
    ]) + "\n"
    hba_path = confdir / "pg_hba.conf"
    hba = _pg_hba_strip(_read(hba_path)).rstrip("\n") + "\n"
    if new["remote_access"] == "On":
        hba += "\n" + "\n".join([PG_HBA_BEGIN, *[f"host    all    all    {n}    scram-sha-256" for n in nets], PG_HBA_END]) + "\n"
    override = confdir / "conf.d" / "99-aurora.conf"
    _apply({override: conf, hba_path: hba}, _pg_validate(), _pg_unit(), "restart")
    for p in (override, hba_path):  # postgres must be able to read them
        shutil.chown(p, "postgres", "postgres")
    return {"ok": True, **postgresql_settings()}


def _pg_files():
    c = _pg_cluster()
    if not c:
        return []
    files = [str(c[2] / "postgresql.conf"), str(c[2] / "pg_hba.conf")]
    return files + ([str(c[2] / "conf.d" / "99-aurora.conf")] if (c[2] / "conf.d" / "99-aurora.conf").exists() else [])


def _pg_logs():
    c = _pg_cluster()
    return [f"/var/log/postgresql/postgresql-{c[0]}-{c[1]}.log"] if c else []


# ================================================================ PHP-FPM pool
def _fpm_pool() -> tuple[str, Path] | None:
    pools = sorted(glob.glob("/etc/php/*/fpm/pool.d/www.conf"))
    if not pools:
        return None
    p = Path(pools[-1])
    return p.parts[3], p


FPM_SCHEMA = [
    {"title": "Process manager", "desc": "How many PHP workers run. Each uses ~20–40 MB on a Pi — size max children to your RAM.", "fields": [
        {"key": "pm", "label": "Mode", "type": "select", "options": [["dynamic", "dynamic — keeps spare workers (balanced)"],
                                                                     ["ondemand", "ondemand — starts workers when needed (least RAM)"],
                                                                     ["static", "static — fixed number (fastest, most RAM)"]]},
        {"key": "pm.max_children", "label": "Max workers", "type": "int", "min": 1, "max": 1000},
        {"key": "pm.start_servers", "label": "Workers at start (dynamic)", "type": "int", "min": 1, "max": 1000},
        {"key": "pm.min_spare_servers", "label": "Min idle workers (dynamic)", "type": "int", "min": 1, "max": 1000},
        {"key": "pm.max_spare_servers", "label": "Max idle workers (dynamic)", "type": "int", "min": 1, "max": 1000},
        {"key": "pm.process_idle_timeout", "label": "Idle worker timeout (ondemand)", "type": "text", "help": "e.g. 10s"},
        {"key": "pm.max_requests", "label": "Recycle worker after N requests", "type": "int", "min": 0, "max": 1000000, "help": "0 = never. 500 guards against leaks."},
        {"key": "request_terminate_timeout", "label": "Kill request after (s)", "type": "int", "min": 0, "max": 86400, "help": "0 = off."},
    ]},
]
_FPM_DEFAULTS = {"pm": "dynamic", "pm.max_children": "5", "pm.start_servers": "2", "pm.min_spare_servers": "1",
                 "pm.max_spare_servers": "3", "pm.process_idle_timeout": "10s", "pm.max_requests": "0", "request_terminate_timeout": "0"}


def phpfpm_settings() -> dict:
    fp = _fpm_pool()
    if not fp:
        raise AppConfigError("PHP-FPM is not installed")
    ver, path = fp
    text = _read(path)
    vals = {}
    for k in _FPM_DEFAULTS:
        m = re.search(rf"(?m)^\s*{re.escape(k)}\s*=\s*(\S+)", text)
        if m:
            vals[k] = m.group(1)
    return {"schema": FPM_SCHEMA, "values": {k: vals.get(k, d) for k, d in _FPM_DEFAULTS.items()}, "version": ver, "pool_file": str(path)}


def phpfpm_save(changes: dict) -> dict:
    ver, path = _fpm_pool() or (None, None)
    if not path:
        raise AppConfigError("PHP-FPM is not installed")
    new = {**phpfpm_settings()["values"]}
    for k, v in (changes or {}).items():
        if k not in _FPM_DEFAULTS:
            raise AppConfigError(f"Unknown setting {k}")
        if k == "pm":
            if v not in ("dynamic", "ondemand", "static"):
                raise AppConfigError("Invalid mode")
        elif k == "pm.process_idle_timeout":
            if not re.match(r"^\d+[smhd]?$", str(v)):
                raise AppConfigError("Idle timeout: e.g. 10s")
        else:
            v = _num(v, k, 0, 1000000)
        new[k] = str(v)
    if new["pm"] == "dynamic":
        mc, st, mn, mx = (int(new[x]) for x in ("pm.max_children", "pm.start_servers", "pm.min_spare_servers", "pm.max_spare_servers"))
        if not (mn <= st <= mx <= mc):
            raise AppConfigError("Dynamic mode needs: min idle ≤ at start ≤ max idle ≤ max workers")
    text = _read(path)
    for k, v in new.items():
        if re.search(rf"(?m)^\s*;?\s*{re.escape(k)}\s*=", text):
            text = re.sub(rf"(?m)^\s*;?\s*{re.escape(k)}\s*=.*$", f"{k} = {v}", text, count=1)
        else:
            text += f"\n{k} = {v}\n"
    _apply({path: text}, [f"php-fpm{ver}", "-t"], f"php{ver}-fpm", "reload")
    return {"ok": True, **phpfpm_settings()}


# ================================================================ registry
def _fpm_files():
    fp = _fpm_pool()
    return [str(fp[1]), f"/etc/php/{fp[0]}/fpm/php-fpm.conf"] if fp else []


def _fpm_validate():
    fp = _fpm_pool()
    return [f"php-fpm{fp[0]}", "-t"] if fp else None


def _fpm_unit():
    fp = _fpm_pool()
    return f"php{fp[0]}-fpm" if fp else None


APPS = {
    "apache": {"settings": apache_settings, "save": apache_save, "modules": apache_modules, "module": apache_module,
               "files": lambda: ["/etc/apache2/apache2.conf", "/etc/apache2/ports.conf", "/etc/apache2/conf-available/security.conf"],
               "validate": lambda: ["apache2ctl", "configtest"], "unit": lambda: "apache2", "action": "reload",
               "logs": ["/var/log/apache2/error.log", "/var/log/apache2/access.log"]},
    "nginx": {"settings": nginx_settings, "save": nginx_save,
              "files": lambda: ["/etc/nginx/nginx.conf", "/etc/nginx/sites-available/default"],
              "validate": lambda: ["nginx", "-t"], "unit": lambda: "nginx", "action": "reload",
              "logs": ["/var/log/nginx/error.log", "/var/log/nginx/access.log"]},
    "lighttpd": {"settings": lighttpd_settings, "save": lighttpd_save, "modules": lighttpd_modules, "module": lighttpd_module,
                 "files": lambda: ["/etc/lighttpd/lighttpd.conf"],
                 "validate": lambda: ["lighttpd", "-tt", "-f", "/etc/lighttpd/lighttpd.conf"], "unit": lambda: "lighttpd", "action": "restart",
                 "logs": ["/var/log/lighttpd/error.log"]},
    "caddy": {"files": lambda: ["/etc/caddy/Caddyfile"],
              "validate": lambda: ["caddy", "validate", "--adapter", "caddyfile", "--config", "/etc/caddy/Caddyfile"],
              "unit": lambda: "caddy", "action": "reload", "logs": []},
    "mariadb": {"settings": mariadb_settings, "save": mariadb_save,
                "files": lambda: ["/etc/mysql/mariadb.conf.d/50-server.cnf"] + ([str(MARIADB_OVERRIDE)] if MARIADB_OVERRIDE.exists() else []),
                "validate": lambda: None, "unit": lambda: "mariadb", "action": "restart", "logs": []},
    "postgresql": {"settings": postgresql_settings, "save": postgresql_save, "files": _pg_files, "validate": _pg_validate,
                   "unit": _pg_unit, "action": "restart", "logs": _pg_logs},
    "phpfpm": {"settings": phpfpm_settings, "save": phpfpm_save, "files": _fpm_files, "validate": _fpm_validate,
               "unit": _fpm_unit, "action": "reload", "logs": []},
    "vsftpd": {"settings": ftp.settings, "save": ftp.save_settings, "files": lambda: ["/etc/vsftpd.conf"],
               "validate": lambda: None, "unit": lambda: "vsftpd", "action": "restart", "logs": ["/var/log/vsftpd.log"]},
}


def _app(app_id: str) -> dict:
    if app_id not in APPS:
        raise AppConfigError("Unknown application")
    return APPS[app_id]


def _logs(a: dict) -> list[str]:
    logs = a.get("logs", [])
    return [f for f in (logs() if callable(logs) else logs) if Path(f).exists()]


def _wrap(fn, *a):
    try:
        return fn(*a)
    except ftp.FTPError as exc:
        raise AppConfigError(str(exc))


def info(app_id: str) -> dict:
    a = _app(app_id)
    out = {"id": app_id, "has_settings": "settings" in a, "has_modules": "modules" in a,
           "files": [f for f in a["files"]() if Path(f).exists()], "logs": _logs(a),
           "unit": a["unit"](), "ftp_accounts": app_id == "vsftpd"}
    return out


def settings(app_id: str) -> dict:
    a = _app(app_id)
    if "settings" not in a:
        raise AppConfigError("This application is configured through its config file (Files tab)")
    return _wrap(a["settings"])


def save(app_id: str, changes: dict) -> dict:
    a = _app(app_id)
    if "save" not in a:
        raise AppConfigError("No settings form for this application")
    return _wrap(a["save"], changes)


def modules(app_id: str) -> list[dict]:
    a = _app(app_id)
    if "modules" not in a:
        raise AppConfigError("No modules for this application")
    return a["modules"]()


def set_module(app_id: str, name: str, on: bool) -> dict:
    a = _app(app_id)
    if "module" not in a:
        raise AppConfigError("No modules for this application")
    return a["module"](name, on)


def _check_file(app_id: str, path: str) -> Path:
    a = _app(app_id)
    if path not in a["files"]():
        raise AppConfigError("That file isn't editable here")
    return Path(path)


def read_file(app_id: str, path: str) -> dict:
    p = _check_file(app_id, path)
    return {"path": str(p), "content": _read(p)}


def write_file(app_id: str, path: str, content: str) -> dict:
    p = _check_file(app_id, path)
    if len(content) > 512 * 1024:
        raise AppConfigError("File too large")
    a = _app(app_id)
    _apply({p: content.replace("\r\n", "\n")}, a["validate"](), a["unit"](), a["action"])
    return {"ok": True}


def logs(app_id: str, which: str | None = None, lines: int = 200) -> dict:
    a = _app(app_id)
    lines = max(20, min(int(lines), 2000))
    files = _logs(a)
    if which and which in files:
        text = "\n".join(_read(which).splitlines()[-lines:])
        return {"source": which, "text": text}
    unit = a["unit"]()
    text = subprocess.run(["journalctl", "-u", unit or "", "-n", str(lines), "--no-pager", "-o", "short-iso"],
                          capture_output=True, text=True).stdout if unit else ""
    return {"source": f"journal ({unit})", "text": text}
