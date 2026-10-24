"""Domains → per-site settings (cPanel "Manage the Domain").

Each Aurora-managed site is one Apache conf in sites-available, regenerated from
a settings dict that is embedded in the file itself as a JSON comment:

    # aurora-settings: {"server_name": "...", ...}

Existing hand-written sites are *adopted*: their settings are inferred from the
conf, and on first save the original is kept as <conf>.aurora-bak.

Every write is checked with `apache2ctl configtest`; a failing config is rolled
back so a bad setting can never take Apache down.
"""
from __future__ import annotations

import ipaddress
import json
import platform
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import jobs, sslcerts

IS_LINUX = platform.system() == "Linux"
APACHE = Path("/etc/apache2")
AVAIL = APACHE / "sites-available"
ENABLED = APACHE / "sites-enabled"
SSL_DIR = APACHE / "ssl" / "aurora"
LE_LIVE = Path("/etc/letsencrypt/live")
DEFAULT_DOCROOT_BASE = Path("/var/www")
SYSTEM_CONFS = {"000-default.conf", "default-ssl.conf"}
MARK = "# aurora-settings:"
_SSL_MODE = re.compile(r"(?m)^# aurora-ssl-mode: (selfsigned|custom)\n?")
_CX_BEGIN, _CX_END = "# aurora-custom begin", "# aurora-custom end"
_CX_BLOCK = re.compile(rf"\n[ \t]*{re.escape(_CX_BEGIN)}.*?{re.escape(_CX_END)}[ \t]*", re.S)
_HOST = re.compile(r"^(?=.{1,253}$)(\*\.)?([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

DEFAULTS = {
    "server_name": "", "aliases": [], "docroot": "", "enabled": True,
    "www": "none",                       # none | force_www | force_bare
    "ssl": "none",                       # none | selfsigned | letsencrypt | custom
    "cert": "", "key": "", "chain": "",
    "force_https": False, "hsts": False,
    "redirect_url": "", "redirect_code": 301,
    "indexes": False, "allow_override": True,
    "gzip": True, "cache_static": False, "security_headers": True,
    "maintenance": False, "custom": "",
    "php_pool": "",                      # isolated: PHP runs in this PHP-FPM pool (Security → Site Isolation)
}


class SiteError(RuntimeError):
    pass


def _require():
    if not (IS_LINUX and shutil.which("apache2ctl")):
        raise SiteError("Apache is not available on this host")


def _run(argv, timeout=30):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


# --------------------------------------------------------------------------- #
# Reading existing confs
# --------------------------------------------------------------------------- #
def _blocks(text: str) -> list[dict]:
    """Split a conf into VirtualHost blocks with the directives we care about."""
    out = []
    for m in re.finditer(r"<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>", text, re.S | re.I):
        addr, body = m.group(1), m.group(2)
        port = (re.search(r":(\d+)", addr) or [None, "80"])[1]

        def d(name):
            mm = re.search(rf"(?im)^\s*{name}\s+(.+?)\s*$", body)
            return mm.group(1).strip().strip('"') if mm else None
        out.append({
            "port": int(port), "server_name": d("ServerName"),
            "aliases": " ".join(re.findall(r"(?im)^\s*ServerAlias\s+(.+?)\s*$", body)).split(),
            "docroot": d("DocumentRoot"), "ssl": bool(re.search(r"(?im)^\s*SSLEngine\s+on", body)),
            "cert": d("SSLCertificateFile"), "key": d("SSLCertificateKeyFile"), "chain": d("SSLCertificateChainFile"),
            "https_redirect": bool(re.search(r"(?im)^\s*(RewriteRule\s+\S+\s+https://|Redirect\s+(permanent|301)?\s*/\s+https://)", body)),
            "redirect": re.search(r"(?im)^\s*Redirect\s+(301|302|permanent|temp)?\s*/\s+(\S+)", body),
            "indexes": bool(re.search(r"(?im)^\s*Options\s+.*(?<![-\w])\+?Indexes", body)),
            "allow_override": bool(re.search(r"(?im)^\s*AllowOverride\s+All", body)),
            "hsts": "Strict-Transport-Security" in body,
        })
    return out


def _settings_from_conf(path: Path) -> dict:
    text = path.read_text(errors="replace")
    for line in text.splitlines()[:5]:
        if line.startswith(MARK):
            try:
                return {**DEFAULTS, **json.loads(line[len(MARK):]), "_managed": True}
            except ValueError:
                break
    blocks = _blocks(text)
    if not blocks:
        raise SiteError(f"No VirtualHost found in {path.name}")
    http = next((b for b in blocks if not b["ssl"]), None)
    https = next((b for b in blocks if b["ssl"]), None)
    main = https or http
    s = dict(DEFAULTS)
    s.update(server_name=(main["server_name"] or path.stem), aliases=main["aliases"],
             docroot=main["docroot"] or "", indexes=main["indexes"], allow_override=main["allow_override"],
             gzip=False, security_headers=False, hsts=bool(https and https["hsts"]))
    if https:
        le = str(LE_LIVE) in (https["cert"] or "")
        own = (https["cert"] or "") == str(SSL_DIR / f"{_slug(s['server_name'])}.crt")
        picked = _SSL_MODE.search(text)  # the choice made in the panel wins over guessing from the path
        s.update(ssl=picked.group(1) if picked else "letsencrypt" if le else "selfsigned" if own else "custom",
                 cert=https["cert"] or "", key=https["key"] or "", chain=https["chain"] or "")
    if http and http["https_redirect"]:
        s["force_https"] = True
    elif main["redirect"] and not main["redirect"].group(2).startswith("https://%{"):
        code = main["redirect"].group(1) or "302"
        s.update(redirect_url=main["redirect"].group(2), redirect_code=301 if code in ("301", "permanent") else 302)
    m = _CX_BLOCK.search(text)
    if m:  # built-in sites keep panel-added directives in a marked block
        s["custom"] = "\n".join(l[4:] if l.startswith("    ") else l.strip()
                                for l in m.group(0).strip().splitlines()[1:-1])
    s["_managed"] = False
    return s


def _conf_for(name: str) -> Path | None:
    # System sites are addressed by conf file: 000-default and default-ssl often share one ServerName.
    if name in SYSTEM_CONFS and (AVAIL / name).is_file():
        return AVAIL / name
    name = name.lower()
    for f in sorted(AVAIL.glob("*.conf")):
        try:
            for b in _blocks(f.read_text(errors="replace")):
                if (b["server_name"] or "").lower() == name:
                    return f
        except OSError:
            continue
    # Confs without a ServerName (stock default-ssl.conf) are listed under their file stem.
    for f in sorted(AVAIL.glob("*.conf")):
        try:
            if f.stem.lower() == name and _settings_from_conf(f)["server_name"].lower() == name:
                return f
        except (SiteError, OSError):
            continue
    return None


def _cert_info(s: dict) -> dict | None:
    path = s.get("cert")
    if s.get("ssl") == "selfsigned":
        path = str(SSL_DIR / f"{_slug(s['server_name'])}.crt")
    elif s.get("ssl") == "letsencrypt":
        path = str(LE_LIVE / s["server_name"] / "fullchain.pem")
    if not path or not Path(path).exists():
        return None
    return sslcerts._inspect(Path(path))


def _live_conf(conf: Path) -> Path:
    """The file Apache actually loads: a hand-copied regular file in sites-enabled wins over sites-available."""
    e = ENABLED / conf.name
    return e if e.exists() and not e.is_symlink() else conf


def _has_http(conf: Path) -> bool:
    try:
        return any(b["port"] == 80 for b in _blocks(_live_conf(conf).read_text(errors="replace")))
    except OSError:
        return False


def list_sites() -> dict:
    if not (IS_LINUX and AVAIL.exists()):
        return {"supported": False, "sites": []}
    sites = []
    for f in sorted(AVAIL.glob("*.conf")):
        system = f.name in SYSTEM_CONFS
        try:
            s = _settings_from_conf(_live_conf(f) if system else f)
        except (SiteError, OSError):
            continue
        cert = _cert_info(s) if s["ssl"] != "none" else None
        sites.append({
            "server_name": s["server_name"], "aliases": s["aliases"], "docroot": s["docroot"],
            "conf": f.name, "enabled": (ENABLED / f.name).exists(), "managed": s["_managed"],
            "system": system, "ssl": s["ssl"], "force_https": s["force_https"],
            "has_http": _has_http(f) if system else True,
            "redirect_url": s["redirect_url"], "maintenance": s["maintenance"],
            "cert_expires": cert.get("expires") if cert else None,
            "cert_self_signed": cert.get("self_signed") if cert else None,
        })
    # The http built-in site gets its https from default-ssl: show that on its row.
    https = next((x for x in sites if x["conf"] == "default-ssl.conf" and x["enabled"]), None)
    for x in sites:
        if x["system"] and x["has_http"] and https:
            x["https_via"] = {"ssl": https["ssl"], "cert_expires": https["cert_expires"]}
    return {"supported": True, "sites": sites, "certbot": bool(shutil.which("certbot"))}


def _builtin_https() -> dict | None:
    """The built-in https site (default-ssl) — it serves https for the http built-in site's address."""
    conf = AVAIL / "default-ssl.conf"
    if not conf.is_file():
        return None
    try:
        s = _settings_from_conf(_live_conf(conf))
    except (SiteError, OSError):
        return None
    enabled = (ENABLED / conf.name).exists()
    ssl = s["ssl"] if enabled else "none"
    return {"conf": conf.name, "enabled": enabled, "ssl": ssl, "cert": s["cert"], "key": s["key"], "chain": s["chain"],
            "cert_info": _cert_info(s) if ssl != "none" else None}


def get_site(name: str) -> dict:
    _require()
    conf = _conf_for(name)
    if not conf:
        raise SiteError("No site found with that name")
    system = conf.name in SYSTEM_CONFS
    src = _live_conf(conf) if system else conf
    s = _settings_from_conf(src)
    cert = _cert_info(s) if s["ssl"] != "none" else None
    has_http = _has_http(conf) if system else True
    return {"settings": {k: v for k, v in s.items() if not k.startswith("_")}, "managed": s["_managed"],
            "conf": conf.name, "system": system, "enabled": (ENABLED / conf.name).exists(),
            "has_http": has_http, "https": _builtin_https() if system and has_http else None,
            "cert": cert, "certbot": bool(shutil.which("certbot")),
            "le_available": (LE_LIVE / s["server_name"] / "fullchain.pem").exists(),
            "config_text": src.read_text(errors="replace")[:30000]}


# --------------------------------------------------------------------------- #
# Validation + rendering
# --------------------------------------------------------------------------- #
def _slug(name: str) -> str:
    return name.lower().replace("*", "wildcard")


def _is_ip(name: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(name), ipaddress.IPv4Address)
    except ValueError:
        return False


def _clean(settings: dict) -> dict:
    s = {**DEFAULTS, **{k: v for k, v in (settings or {}).items() if k in DEFAULTS}}
    s["server_name"] = (s["server_name"] or "").strip().lower()
    ip = _is_ip(s["server_name"])
    if not (ip or _HOST.match(s["server_name"])):
        raise SiteError("Enter a valid domain or IPv4 address, e.g. example.com or 192.168.0.100")
    if ip:
        if s["www"] != "none":
            raise SiteError("www handling doesn't apply to an IP address")
        if s["ssl"] == "letsencrypt":
            raise SiteError("Let's Encrypt can't issue certificates for an IP — use self-signed instead")
    aliases = []
    for a in s["aliases"] or []:
        a = str(a).strip().lower()
        if not a or a == s["server_name"] or a in aliases:
            continue
        if not (_HOST.match(a) or _is_ip(a)):
            raise SiteError(f"Invalid alias: {a}")
        aliases.append(a)
    bare = s["server_name"][4:] if s["server_name"].startswith("www.") else s["server_name"]
    if s["www"] in ("force_www", "force_bare"):
        other = bare if s["server_name"].startswith("www.") else "www." + bare
        if other not in aliases:
            aliases.append(other)
    s["aliases"] = aliases
    if s["www"] not in ("none", "force_www", "force_bare"):
        raise SiteError("Invalid www setting")
    root = (s["docroot"] or "").strip() or str(DEFAULT_DOCROOT_BASE / _slug(s["server_name"]))
    if not root.startswith("/") or ".." in root or any(c in root for c in "\n\"'<>"):
        raise SiteError("Document root must be an absolute path")
    s["docroot"] = root.rstrip("/") or "/"
    if s["ssl"] not in ("none", "selfsigned", "letsencrypt", "custom"):
        raise SiteError("Invalid SSL mode")
    if s["ssl"] == "none" and (s["force_https"] or s["hsts"]):
        raise SiteError("Force HTTPS / HSTS need an SSL certificate — pick one under HTTPS first")
    if s["ssl"] == "letsencrypt" and not (LE_LIVE / s["server_name"] / "fullchain.pem").exists():
        raise SiteError("No Let's Encrypt certificate yet — click “Issue / renew certificate” under HTTPS; "
                        "the site switches to it by itself once it's issued")
    if s["ssl"] == "custom":
        for k in ("cert", "key"):
            p = (s[k] or "").strip()
            if not p or not Path(p).is_file():
                raise SiteError(f"Custom SSL {k} file not found: {p or '(empty)'}")
        if s["chain"] and not Path(s["chain"]).is_file():
            raise SiteError(f"Chain file not found: {s['chain']}")
    url = (s["redirect_url"] or "").strip()
    if url and not re.match(r"^https?://[^\s\"'<>]+$", url):
        raise SiteError("Redirect must be a full http(s):// URL")
    s["redirect_url"] = url
    s["redirect_code"] = 302 if int(s["redirect_code"] or 301) == 302 else 301
    for k in ("enabled", "force_https", "hsts", "indexes", "allow_override", "gzip", "cache_static", "security_headers", "maintenance"):
        s[k] = bool(s[k])
    custom = s["custom"] or ""
    if re.search(r"(?i)</?\s*VirtualHost", custom):
        raise SiteError("Custom directives can't open or close a VirtualHost")
    s["custom"] = custom.strip()[:8000]
    pool = str(s.get("php_pool") or "")
    if pool and not re.fullmatch(r"aurora-[a-z0-9-]{1,48}", pool):
        raise SiteError("Invalid PHP pool")
    s["php_pool"] = pool
    return s


def _ssl_paths(s: dict) -> tuple[str, str, str]:
    if s["ssl"] == "selfsigned":
        return str(SSL_DIR / f"{_slug(s['server_name'])}.crt"), str(SSL_DIR / f"{_slug(s['server_name'])}.key"), ""
    if s["ssl"] == "letsencrypt":
        d = LE_LIVE / s["server_name"]
        return str(d / "fullchain.pem"), str(d / "privkey.pem"), ""
    return s["cert"], s["key"], s["chain"]


_MAINT = ('"<!doctype html><title>Maintenance</title><body style=\'font-family:system-ui;background:#0b0a0a;'
          'color:#f4efeb;display:grid;place-items:center;height:100vh;margin:0\'><div style=\'text-align:center\'>'
          '<h1>Be right back</h1><p>We are doing some maintenance. Please check again soon.</p></div>"')


def _content(s: dict, scheme: str) -> list[str]:
    name, root, esc = s["server_name"], s["docroot"], re.escape(s["server_name"])
    L = [f"    <Directory {root}>",
         f"        Options {'+' if s['indexes'] else '-'}Indexes +FollowSymLinks",
         f"        AllowOverride {'All' if s['allow_override'] else 'None'}",
         "        Require all granted",
         "    </Directory>"]
    rw = []
    bare = name[4:] if name.startswith("www.") else name
    if s["www"] == "force_www":
        rw += [f"    RewriteCond %{{HTTP_HOST}} ^{re.escape(bare)}$ [NC]",
               f"    RewriteRule ^ {scheme}://www.{bare}%{{REQUEST_URI}} [R=301,L]"]
    elif s["www"] == "force_bare":
        rw += [f"    RewriteCond %{{HTTP_HOST}} ^www\\.{re.escape(bare)}$ [NC]",
               f"    RewriteRule ^ {scheme}://{bare}%{{REQUEST_URI}} [R=301,L]"]
    if s["maintenance"]:
        rw += ["    RewriteCond %{REQUEST_URI} !^/\\.well-known/",
               "    RewriteRule ^ - [R=503,L]"]
        L.append(f"    ErrorDocument 503 {_MAINT}")
    if rw:
        L += ["    RewriteEngine On"] + rw
    if s["redirect_url"]:
        L.append(f"    Redirect {s['redirect_code']} / {s['redirect_url']}")
    if s["gzip"]:
        L += ["    <IfModule mod_deflate.c>",
              "        AddOutputFilterByType DEFLATE text/html text/plain text/css text/xml application/xml application/javascript application/json image/svg+xml",
              "    </IfModule>"]
    if s["cache_static"]:
        L += ["    <IfModule mod_expires.c>", "        ExpiresActive On",
              '        ExpiresByType image/* "access plus 1 month"',
              '        ExpiresByType font/* "access plus 1 month"',
              '        ExpiresByType text/css "access plus 1 week"',
              '        ExpiresByType application/javascript "access plus 1 week"',
              "    </IfModule>"]
    if s["security_headers"]:
        L += ["    <IfModule mod_headers.c>",
              '        Header always set X-Frame-Options "SAMEORIGIN"',
              '        Header always set X-Content-Type-Options "nosniff"',
              '        Header always set Referrer-Policy "strict-origin-when-cross-origin"',
              "    </IfModule>"]
    if scheme == "https" and s["hsts"]:
        L += ['    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"']
    slug = _slug(name)
    L += [f"    ErrorLog ${{APACHE_LOG_DIR}}/{slug}-error.log",
          f"    CustomLog ${{APACHE_LOG_DIR}}/{slug}-access.log combined"]
    if s.get("php_pool"):
        # Isolated: PHP runs as the site's own user in its PHP-FPM pool (overrides mod_php for this site).
        L += ['    <FilesMatch "\\.(php|phtml|phar)$">',
              f'        SetHandler "proxy:unix:/run/php/{s["php_pool"]}.sock|fcgi://localhost"',
              "    </FilesMatch>"]
    if s["custom"]:
        L += ["    # --- custom directives ---"] + ["    " + ln for ln in s["custom"].splitlines()]
    return L


def render(s: dict) -> str:
    head = [f"<VirtualHost *:80>", f"    ServerName {s['server_name']}"]
    if s["aliases"]:
        head.append(f"    ServerAlias {' '.join(s['aliases'])}")
    head.append(f"    DocumentRoot {s['docroot']}")
    out = ["# Managed by AuroraPanel — change it in Domains → Manage; manual edits get overwritten.",
           MARK + " " + json.dumps(s, separators=(",", ":")), ""]
    if s["force_https"] and s["ssl"] != "none":
        out += head + [f"    <Directory {s['docroot']}>", "        Require all granted", "    </Directory>",
                       "    RewriteEngine On",
                       "    RewriteCond %{REQUEST_URI} !^/\\.well-known/acme-challenge/",
                       "    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]",
                       "</VirtualHost>"]
    else:
        out += head + _content(s, "http") + ["</VirtualHost>"]
    if s["ssl"] != "none":
        cert, key, chain = _ssl_paths(s)
        out += ["", "<IfModule mod_ssl.c>", head[0].replace(":80", ":443")] + head[1:] + [
            "    SSLEngine on", f"    SSLCertificateFile {cert}", f"    SSLCertificateKeyFile {key}"]
        if chain:
            out.append(f"    SSLCertificateChainFile {chain}")
        out += _content(s, "https") + ["</VirtualHost>", "</IfModule>"]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #
def _ensure_selfsigned(s: dict, force: bool = False) -> None:
    crt, key, _ = _ssl_paths(s)
    if Path(crt).exists() and Path(key).exists() and not force:
        return
    SSL_DIR.mkdir(parents=True, exist_ok=True)
    san = ",".join(f"{'IP' if _is_ip(n) else 'DNS'}:{n}" for n in [s["server_name"], *s["aliases"]])
    r = _run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "825",
              "-keyout", key, "-out", crt, "-subj", f"/CN={s['server_name']}", "-addext", f"subjectAltName={san}",
              "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth"], 60)
    if r.returncode != 0:
        raise SiteError(r.stderr.strip() or "openssl failed")
    Path(key).chmod(0o600)


def regenerate_selfsigned(name: str) -> dict:
    """Make a fresh self-signed certificate (new key, new dates, current names) for a site that uses one.
    The old files are put back if Apache rejects the new ones."""
    _require()
    conf = _conf_for(name)
    if not conf:
        raise SiteError("No site found with that name")
    if conf.name in SYSTEM_CONFS:
        if _has_http(conf):
            conf = AVAIL / "default-ssl.conf"
        s = _settings_from_conf(_live_conf(conf))
        if s["server_name"] and not (_is_ip(s["server_name"]) or _HOST.match(s["server_name"])):
            s["server_name"] = _local_ip()
    else:
        s = _settings_from_conf(conf)
    s = {**s, "ssl": "selfsigned", "aliases": [a for a in s["aliases"] if _is_ip(a) or _HOST.match(a)]}
    crt, key, _ = _ssl_paths(s)
    if conf.name not in SYSTEM_CONFS and _settings_from_conf(conf)["ssl"] != "selfsigned":
        raise SiteError("This site doesn't use a self-signed certificate")
    if conf.name in SYSTEM_CONFS and (_settings_from_conf(_live_conf(conf))["cert"] or "") != crt:
        raise SiteError("Pick Self-signed and click Apply certificate first — this site uses other certificate files")
    old = {p: Path(p).read_bytes() for p in (crt, key) if Path(p).exists()}
    _ensure_selfsigned(s, force=True)
    test = _run(["apache2ctl", "configtest"])
    if test.returncode != 0:
        for pth, data in old.items():
            Path(pth).write_bytes(data)
        raise SiteError("Apache rejected the new certificate, the old one was kept:\n" + (test.stderr + test.stdout)[:1500])
    if _run(["systemctl", "reload", "apache2"]).returncode != 0:
        _run(["systemctl", "restart", "apache2"])
    return {"ok": True, "cert": crt}


def _needed_mods(s: dict) -> list[str]:
    mods = ["rewrite"]
    if s["ssl"] != "none":
        mods.append("ssl")
    if s["security_headers"] or s["hsts"]:
        mods.append("headers")
    if s["gzip"]:
        mods.append("deflate")
    if s["cache_static"]:
        mods.append("expires")
    if s.get("php_pool"):
        mods.append("proxy_fcgi")
    return mods


def _apply(conf: Path, text: str, enabled: bool, mods: list[str]) -> dict:
    """Write conf, configtest, enable/disable, reload — or roll back."""
    old = conf.read_text() if conf.exists() else None
    for m in mods:
        if not (APACHE / "mods-enabled" / f"{m}.load").exists():
            _run(["a2enmod", "-q", m])
    conf.write_text(text, encoding="utf-8")
    was_enabled = (ENABLED / conf.name).exists()
    if enabled and not was_enabled:
        _run(["a2ensite", "-q", conf.name])
    if not enabled and was_enabled:
        _run(["a2dissite", "-q", conf.name])
    test = _run(["apache2ctl", "configtest"])
    if test.returncode != 0:
        if old is None:
            _run(["a2dissite", "-q", conf.name])
            conf.unlink(missing_ok=True)
        else:
            conf.write_text(old, encoding="utf-8")
            if was_enabled and not (ENABLED / conf.name).exists():
                _run(["a2ensite", "-q", conf.name])
        err = "\n".join(l for l in (test.stderr + test.stdout).splitlines() if "AH00558" not in l).strip()
        raise SiteError("Apache rejected the config, nothing was changed:\n" + err[:1500])
    r = _run(["systemctl", "reload", "apache2"])
    if r.returncode != 0:
        _run(["systemctl", "restart", "apache2"])
    return {"ok": True}


def _ensure_docroot(s: dict) -> None:
    root = Path(s["docroot"])
    if root.exists():
        return
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text(
        f"<!doctype html><meta charset=utf-8><title>{s['server_name']}</title>"
        "<body style='font-family:system-ui;background:#0b0a0a;color:#f4efeb;display:grid;"
        "place-items:center;height:100vh;margin:0'><div style='text-align:center'>"
        f"<h1 style='color:#ff8a33'>{s['server_name']}</h1><p>New site created by AuroraPanel.</p></div>",
        encoding="utf-8")
    _run(["chown", "-R", "www-data:www-data", str(root)])


def create_site(settings: dict) -> dict:
    _require()
    s = _clean(settings)
    conf = _conf_for(s["server_name"])
    if conf and conf.name in SYSTEM_CONFS:
        # This address is Apache's built-in site, and Apache can't have two sites with one name. A folder
        # given with it means "serve this folder at http://<address>/<folder name>" — a folder site.
        sys_root = (_settings_from_conf(_live_conf(conf))["docroot"] or "").rstrip("/")
        raw = ((settings or {}).get("docroot") or "").strip().rstrip("/")
        if not raw or raw == sys_root:
            raise SiteError(f"{s['server_name']} is Apache's built-in site, which already serves {sys_root or '?'} at "
                            f"http://{s['server_name']}/ — open it with Manage to change it. To add a site at "
                            f"http://{s['server_name']}/<name>, enter a folder such as {sys_root or '/var/www/html'}/mysite.")
        r = create_folder_site(Path(raw).name, raw)
        return {**r, "folder_site": True, "server_name": s["server_name"], "docroot": r["path"],
                "url": f"http://{s['server_name']}/{r['name']}/"}
    if conf:
        raise SiteError("A site with that name already exists")
    conf = AVAIL / f"{_slug(s['server_name'])}.conf"
    if conf.exists():
        raise SiteError(f"{conf.name} already exists")
    _ensure_docroot(s)
    if s["ssl"] == "selfsigned":
        _ensure_selfsigned(s)
    _apply(conf, render(s), s["enabled"], _needed_mods(s))
    return {"ok": True, "server_name": s["server_name"], "docroot": s["docroot"]}


def save_site(original_name: str, settings: dict) -> dict:
    _require()
    conf = _conf_for(original_name)
    if not conf:
        raise SiteError("No site found with that name")
    if conf.name in SYSTEM_CONFS:
        raise SiteError("System default sites are read-only here")
    if "php_pool" not in (settings or {}):  # an older page that doesn't know isolation must not switch it off
        settings = {**settings, "php_pool": _settings_from_conf(conf).get("php_pool", "")}
    s = _clean(settings)
    if s["server_name"] != original_name.lower() and _conf_for(s["server_name"]):
        raise SiteError("Another site already uses that name")
    managed = _settings_from_conf(conf).get("_managed")
    if not managed:
        bak = conf.with_name(conf.name + ".aurora-bak")
        if not bak.exists():
            shutil.copy2(conf, bak)
    _ensure_docroot(s)
    if s["ssl"] == "selfsigned":
        _ensure_selfsigned(s)
    _apply(conf, render(s), s["enabled"], _needed_mods(s))
    return {"ok": True, "adopted": not managed}


def quick_toggle(name: str, key: str, value: bool) -> dict:
    """List-page switches (Force HTTPS, enabled, maintenance)."""
    if key not in ("force_https", "enabled", "maintenance"):
        raise SiteError("Unsupported toggle")
    cur = get_site(name)
    if cur["system"]:
        if key == "enabled":
            return _set_system_enabled(AVAIL / cur["conf"], bool(value))
        if key == "force_https":
            return _set_system_force_https(AVAIL / cur["conf"], bool(value))
        raise SiteError("System default sites can only be enabled/disabled or use Force HTTPS")
    s = cur["settings"]
    if key == "force_https" and value and s["ssl"] == "none":
        s["ssl"] = "selfsigned"   # needs *a* cert; upgrade to Let's Encrypt from Manage
    s[key] = bool(value)
    return save_site(name, s)


def _set_system_enabled(conf: Path, enabled: bool) -> dict:
    """a2ensite/a2dissite a stock conf without touching its contents."""
    link = ENABLED / conf.name
    was_enabled = link.exists()
    if enabled == was_enabled:
        return {"ok": True}
    if link.exists() and not link.is_symlink():
        raise SiteError(f"sites-enabled/{conf.name} is a regular file (edited by hand), not a link to sites-available, "
                        "so the panel won't remove it. Move it out of sites-enabled yourself to disable the site.")
    if enabled:
        if "SSLEngine" in conf.read_text(errors="replace") and not (APACHE / "mods-enabled" / "ssl.load").exists():
            _run(["a2enmod", "-q", "ssl"])
        r = _run(["a2ensite", "-q", conf.name])
    else:
        r = _run(["a2dissite", "-q", conf.name])
    if r.returncode != 0 or link.exists() != enabled:
        raise SiteError((r.stderr + r.stdout).strip() or f"Could not {'enable' if enabled else 'disable'} {conf.name}")
    test = _run(["apache2ctl", "configtest"])
    if test.returncode != 0:
        _run(["a2dissite" if enabled else "a2ensite", "-q", conf.name])
        err = "\n".join(l for l in (test.stderr + test.stdout).splitlines() if "AH00558" not in l).strip()
        raise SiteError("Apache rejected the config, nothing was changed:\n" + err[:1500])
    r = _run(["systemctl", "reload", "apache2"])
    if r.returncode != 0:
        _run(["systemctl", "restart", "apache2"])
    return {"ok": True}


_FH_BEGIN, _FH_END = "# aurora-force-https begin", "# aurora-force-https end"
_FH_BLOCK = re.compile(rf"\n[ \t]*{re.escape(_FH_BEGIN)}.*?{re.escape(_FH_END)}[ \t]*", re.S)
SITE_BAK = Path("/var/lib/aurora/site-backups")


def _set_system_force_https(conf: Path, on: bool) -> dict:
    """Add/remove a marked redirect inside a stock conf's :80 VirtualHost; the rest of the file is untouched."""
    live = _live_conf(conf)
    text = live.read_text(errors="replace")
    bare = _FH_BLOCK.sub("", text)
    if on:
        http = re.search(r"(?m)^[ \t]*<VirtualHost\s+[^>]*:80\s*>.*?(?=\n[ \t]*</VirtualHost>)", bare, re.S | re.I)
        if not http:
            raise SiteError(f"{conf.name} has no http (port 80) part — turn on Force HTTPS on the default (http) site instead")
        if ":443" not in (lambda r: r.stdout + r.stderr)(_run(["apache2ctl", "-S"])):
            raise SiteError("Nothing is serving HTTPS (port 443) yet — enable default-ssl or another HTTPS site first")
        new = bare[:http.end()] + "\n".join([
            "", f"    {_FH_BEGIN}", "    RewriteEngine On",
            "    RewriteCond %{REQUEST_URI} !^/\\.well-known/acme-challenge/",
            "    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]", f"    {_FH_END}"]) + bare[http.end():]
    else:
        if bare == text:
            if any(b["https_redirect"] for b in _blocks(text)):
                raise SiteError(f"The HTTPS redirect in {live} was written by hand — remove it there")
            return {"ok": True}
        new = bare
    if new == text:
        return {"ok": True}
    SITE_BAK.mkdir(parents=True, exist_ok=True)
    shutil.copy2(live, SITE_BAK / f"{conf.name}.{int(time.time())}")
    if on and not (APACHE / "mods-enabled" / "rewrite.load").exists():
        _run(["a2enmod", "-q", "rewrite"])
    live.write_text(new, encoding="utf-8")
    test = _run(["apache2ctl", "configtest"])
    if test.returncode != 0:
        live.write_text(text, encoding="utf-8")
        err = "\n".join(l for l in (test.stderr + test.stdout).splitlines() if "AH00558" not in l).strip()
        raise SiteError("Apache rejected the config, nothing was changed:\n" + err[:1500])
    r = _run(["systemctl", "reload", "apache2"])
    if r.returncode != 0:
        _run(["systemctl", "restart", "apache2"])
    return {"ok": True}


def set_system_ssl(conf_name: str, mode: str, cert: str = "", key: str = "", chain: str = "") -> dict:
    """Change the certificate of the built-in https site (default-ssl) — only its SSLCertificate* lines.
    "none" turns the site off instead; picking a certificate turns it back on."""
    _require()
    conf = AVAIL / conf_name
    if conf_name not in SYSTEM_CONFS or not conf.is_file():
        raise SiteError("Only Apache's built-in https site is changed here — use Manage → Save for other sites")
    if _has_http(conf):  # the http built-in site's https is served by default-ssl
        if not (AVAIL / "default-ssl.conf").is_file():
            raise SiteError("Apache's built-in https site (default-ssl.conf) is missing, so there's nothing to put a certificate on")
        conf_name, conf = "default-ssl.conf", AVAIL / "default-ssl.conf"
    if mode == "none":
        return _set_system_enabled(conf, False)
    live = _live_conf(conf)
    text = live.read_text(errors="replace")
    s = _settings_from_conf(live)
    if mode == "selfsigned":
        name = s["server_name"] if (_is_ip(s["server_name"]) or _HOST.match(s["server_name"])) else _local_ip()
        own = {**s, "ssl": "selfsigned", "server_name": name, "aliases": [a for a in s["aliases"] if _is_ip(a) or _HOST.match(a)]}
        _ensure_selfsigned(own)
        cert, key, chain = _ssl_paths(own)
    elif mode == "custom":
        cert, key, chain = (cert or "").strip(), (key or "").strip(), (chain or "").strip()
        for label, pth in (("certificate", cert), ("private key", key)):
            if not pth.startswith("/") or not Path(pth).is_file():
                raise SiteError(f"Custom SSL {label} file not found: {pth or '(empty)'}")
        if chain and (not chain.startswith("/") or not Path(chain).is_file()):
            raise SiteError(f"Chain file not found: {chain}")
    else:
        raise SiteError("Pick None, Self-signed or Custom")
    if any(c in cert + key + chain for c in "\n\"'<>"):
        raise SiteError("Invalid certificate path")
    # Remember which option was picked: a Custom certificate can be the same files as the self-signed one.
    new = _SSL_MODE.sub("", text)
    new = f"# aurora-ssl-mode: {mode}\n" + new
    for directive, val in (("SSLCertificateFile", cert), ("SSLCertificateKeyFile", key)):
        rx = re.compile(rf"(?im)^([ \t]*){directive}[ \t]+\S.*$")
        if not rx.search(new):
            raise SiteError(f"{live} has no {directive} line to change")
        new = rx.sub(lambda m: f"{m.group(1)}{directive} {val}", new, count=1)
    chain_rx = re.compile(r"(?im)^([ \t]*)SSLCertificateChainFile[ \t]+\S.*$")
    if chain:
        if chain_rx.search(new):
            new = chain_rx.sub(lambda m: f"{m.group(1)}SSLCertificateChainFile {chain}", new, count=1)
        else:
            new = re.sub(r"(?im)^([ \t]*)(SSLCertificateKeyFile[ \t]+\S.*)$",
                         lambda m: f"{m.group(1)}{m.group(2)}\n{m.group(1)}SSLCertificateChainFile {chain}", new, count=1)
    else:
        new = chain_rx.sub(lambda m: f"{m.group(1)}#SSLCertificateChainFile", new)
    if new != text:
        SITE_BAK.mkdir(parents=True, exist_ok=True)
        shutil.copy2(live, SITE_BAK / f"{conf.name}.{int(time.time())}")
        live.write_text(new, encoding="utf-8")
        test = _run(["apache2ctl", "configtest"])
        if test.returncode != 0:
            live.write_text(text, encoding="utf-8")
            err = "\n".join(l for l in (test.stderr + test.stdout).splitlines() if "AH00558" not in l).strip()
            raise SiteError("Apache rejected the certificate, nothing was changed:\n" + err[:1500])
    if not (ENABLED / conf.name).exists():
        try:
            return _set_system_enabled(conf, True)   # reloads Apache
        except SiteError:
            live.write_text(text, encoding="utf-8")
            raise
    r = _run(["systemctl", "reload", "apache2"])
    if r.returncode != 0:
        _run(["systemctl", "restart", "apache2"])
    return {"ok": True}


def _local_ip() -> str:
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as so:
            so.connect(("192.0.2.1", 80))
            return so.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def save_conf_text(name: str, text: str) -> dict:
    """Replace a site's whole config file (the one Apache loads) — backed up, checked, rolled back if rejected."""
    _require()
    conf = _conf_for(name)
    if not conf:
        raise SiteError("No site found with that name")
    text = (text or "").replace("\r\n", "\n")
    if len(text) > 200_000:
        raise SiteError("Config file too large (200 KB max)")
    if not re.search(r"(?i)<VirtualHost\s", text):
        raise SiteError("The file needs at least one <VirtualHost> block")
    live = _live_conf(conf) if conf.name in SYSTEM_CONFS else conf
    old = live.read_text(errors="replace")
    if text.rstrip("\n") == old.rstrip("\n"):
        return {"ok": True}
    SITE_BAK.mkdir(parents=True, exist_ok=True)
    shutil.copy2(live, SITE_BAK / f"{conf.name}.{int(time.time())}")
    live.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    test = _run(["apache2ctl", "configtest"])
    if test.returncode != 0:
        live.write_text(old, encoding="utf-8")
        err = "\n".join(l for l in (test.stderr + test.stdout).splitlines() if "AH00558" not in l).strip()
        raise SiteError("Apache rejected the file, nothing was changed:\n" + err[:1500])
    if (ENABLED / conf.name).exists():
        r = _run(["systemctl", "reload", "apache2"])
        if r.returncode != 0:
            _run(["systemctl", "restart", "apache2"])
    return {"ok": True, "backup": str(SITE_BAK)}


def set_system_custom(conf_name: str, custom: str) -> dict:
    """Extra directives for a built-in site, kept in a marked block at the end of its main
    VirtualHost (:80 for 000-default, :443 for default-ssl); the rest of the file is untouched."""
    _require()
    conf = AVAIL / conf_name
    if conf_name not in SYSTEM_CONFS or not conf.is_file():
        raise SiteError("Only Apache's built-in sites are changed here — use Manage → Save for other sites")
    custom = (custom or "").strip()[:8000]
    if re.search(r"(?i)</?\s*VirtualHost", custom):
        raise SiteError("Custom directives can't open or close a VirtualHost")
    if _CX_BEGIN in custom or _CX_END in custom:
        raise SiteError("Custom directives can't contain the panel's markers")
    live = _live_conf(conf)
    text = live.read_text(errors="replace")
    bare = _CX_BLOCK.sub("", text)
    if custom:
        port = "80" if _has_http(conf) else "443"
        vh = re.search(rf"(?m)^[ \t]*<VirtualHost\s+[^>]*:{port}\s*>.*?(?=\n[ \t]*</VirtualHost>)", bare, re.S | re.I)
        if not vh:
            raise SiteError(f"{conf.name} has no port {port} VirtualHost to add directives to")
        block = ["", f"    {_CX_BEGIN}"] + ["    " + ln for ln in custom.splitlines()] + [f"    {_CX_END}"]
        new = bare[:vh.end()] + "\n".join(block) + bare[vh.end():]
    else:
        new = bare
    if new == text:
        return {"ok": True}
    SITE_BAK.mkdir(parents=True, exist_ok=True)
    shutil.copy2(live, SITE_BAK / f"{conf.name}.{int(time.time())}")
    live.write_text(new, encoding="utf-8")
    test = _run(["apache2ctl", "configtest"])
    if test.returncode != 0:
        live.write_text(text, encoding="utf-8")
        err = "\n".join(l for l in (test.stderr + test.stdout).splitlines() if "AH00558" not in l).strip()
        raise SiteError("Apache rejected the directives, nothing was changed:\n" + err[:1500])
    r = _run(["systemctl", "reload", "apache2"])
    if r.returncode != 0:
        _run(["systemctl", "restart", "apache2"])
    return {"ok": True}


def remove_site(name: str) -> dict:
    _require()
    conf = _conf_for(name)
    if not conf:
        raise SiteError("No site found with that name")
    if conf.name in SYSTEM_CONFS:
        raise SiteError("Refusing to remove a system default site")
    _run(["a2dissite", "-q", conf.name])
    conf.unlink(missing_ok=True)
    # the panel's own self-signed certificate for it, and a2dissite's marker
    for leftover in (SSL_DIR / f"{_slug(name)}.crt", SSL_DIR / f"{_slug(name)}.key",
                     Path("/var/lib/apache2/site/disabled_by_admin") / conf.stem):
        leftover.unlink(missing_ok=True)
    _run(["systemctl", "reload", "apache2"])
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Let's Encrypt
# --------------------------------------------------------------------------- #
def certbot_install() -> jobs.Job:
    env = {"DEBIAN_FRONTEND": "noninteractive", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    return jobs.launch("install certbot", ["apt-get", "-y", "install", "certbot"], env=env)


# Mail domains that exist only on your own network: Let's Encrypt refuses them ("invalid email address").
_LOCAL_MAIL = re.compile(r"(\.(local|lan|home|internal|intranet|localdomain|localhost|test|example|invalid|home\.arpa)|^[0-9.]+|^\[.*\])$", re.I)


def le_email_problem(email: str) -> str:
    """Why Let's Encrypt would refuse this address ("" = fine). Empty is fine: no expiry emails."""
    email = (email or "").strip()
    if not email:
        return ""
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return "That email address doesn't look right"
    dom = email.rsplit("@", 1)[1]
    if _LOCAL_MAIL.search(dom) or "." not in dom:
        return (f"Let's Encrypt only accepts an email on a real internet domain — {dom} exists only on your network. "
                "Use your normal email address, or leave it empty (certificates still renew automatically; you just "
                "won't get Let's Encrypt's reminder emails).")
    return ""


def issue_letsencrypt(name: str, email: str, include_aliases: bool = True, force: bool = False) -> jobs.Job:
    _require()
    if not shutil.which("certbot"):
        raise SiteError("certbot is not installed")
    email = (email or "").strip()
    why = le_email_problem(email)
    if why:
        raise SiteError(why)
    s = get_site(name)["settings"]
    if _is_ip(s["server_name"]):
        raise SiteError("Let's Encrypt can't issue certificates for an IP address")
    names = [s["server_name"]] + ([a for a in s["aliases"] if not a.startswith("*") and not _is_ip(a)] if include_aliases else [])
    argv = ["certbot", "certonly", "--webroot", "-w", s["docroot"], "--non-interactive", "--agree-tos",
            *(["-m", email] if email else ["--register-unsafely-without-email"]),
            "--force-renewal" if force else "--keep-until-expiring", "--cert-name", s["server_name"]]
    for n in names:
        argv += ["-d", n]
    return jobs.launch(f"Let's Encrypt: {s['server_name']}", argv)


# --------------------------------------------------------------------------- #
# Folder sites: http(s)://<this Pi>/<name>
# --------------------------------------------------------------------------- #
# One panel-owned conf holds every folder site. A folder inside the default
# site's document root is served by that site already, so it only gets a
# <Directory> block (.htaccess on); a folder anywhere else also needs an Alias,
# which Apache applies on every site this Pi hosts.
FOLDER_CONF = APACHE / "conf-available" / "zz-aurora-folders.conf"
FOLDER_MARK = "# aurora-folders:"
_FOLDER_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_RESERVED = {"phpmyadmin", "phppgadmin", "webdisk", "icons", "server-status", "server-info", "cgi-bin", "javascript", "manual", ".well-known"}


def default_docroot() -> Path:
    """DocumentRoot of the stock :80 site (000-default), which answers on the Pi's IP."""
    conf = AVAIL / "000-default.conf"
    try:
        for b in _blocks(_live_conf(conf).read_text(errors="replace")):
            if b["docroot"]:
                return Path(b["docroot"])
    except OSError:
        pass
    return DEFAULT_DOCROOT_BASE / "html"


def _folder_state() -> list[dict]:
    try:
        first = FOLDER_CONF.read_text(errors="replace").splitlines()[0]
        if first.startswith(FOLDER_MARK):
            return json.loads(first[len(FOLDER_MARK):])
    except (OSError, IndexError, ValueError):
        pass
    return []


def _folder_render(items: list[dict]) -> str:
    out = [FOLDER_MARK + " " + json.dumps(items), "# Written by AuroraPanel (Domains → Folder sites). Edit them in the panel.", ""]
    for it in items:
        out.append(f"# /{it['name']}")
        if it["alias"]:
            out.append(f'Alias "/{it["name"]}" "{it["path"]}"')
        out += [f'<Directory "{it["path"]}">', f"    Options {'+' if it.get('indexes') else '-'}Indexes +FollowSymLinks", "    AllowOverride All",
                "    Require all granted", "</Directory>", ""]
    return "\n".join(out)


def _folder_apply(items: list[dict]) -> None:
    """Write the conf, keep it only if apache2ctl accepts it, then reload."""
    old = FOLDER_CONF.read_text(errors="replace") if FOLDER_CONF.exists() else None
    was_on = (APACHE / "conf-enabled" / FOLDER_CONF.name).exists()
    FOLDER_CONF.write_text(_folder_render(items), encoding="utf-8")
    if not was_on:
        _run(["a2enconf", "-q", FOLDER_CONF.stem])
    test = _run(["apache2ctl", "configtest"])
    if test.returncode != 0:
        if old is None:
            _run(["a2disconf", "-q", FOLDER_CONF.stem])
            FOLDER_CONF.unlink(missing_ok=True)
        else:
            FOLDER_CONF.write_text(old, encoding="utf-8")
            if not was_on:
                _run(["a2disconf", "-q", FOLDER_CONF.stem])
        err = "\n".join(l for l in (test.stderr + test.stdout).splitlines() if "AH00558" not in l).strip()
        raise SiteError("Apache rejected the config, nothing was changed:\n" + err[:1500])
    if _run(["systemctl", "reload", "apache2"]).returncode != 0:
        _run(["systemctl", "restart", "apache2"])


def list_folder_sites() -> dict:
    if not (IS_LINUX and AVAIL.exists()):
        return {"supported": False, "sites": [], "base": ""}
    items = _folder_state()
    for it in items:
        d = Path(it["path"])
        it["exists"] = d.is_dir()
        it["indexes"] = bool(it.get("indexes"))
        # Without an index page and with the file list off, Apache answers 403 Forbidden.
        it["has_index"] = it["exists"] and any((d / f).is_file() for f in _INDEX_FILES)
    return {"supported": True, "sites": items, "base": str(default_docroot())}


_INDEX_FILES = ("index.html", "index.htm", "index.php", "index.xhtml", "index.cgi", "index.pl")


def set_folder_site_indexes(name: str, on: bool) -> dict:
    """Turn Apache's automatic file list on or off for a folder site (used when it has no index page)."""
    _require()
    items = _folder_state()
    it = next((x for x in items if x["name"] == (name or "").strip().strip("/").lower()), None)
    if not it:
        raise SiteError("No folder site with that name")
    it["indexes"] = bool(on)
    _folder_apply(items)
    return {"ok": True}


def create_folder_site(name: str, path: str = "") -> dict:
    _require()
    name = (name or "").strip().strip("/").lower()
    if not _FOLDER_NAME.match(name) or name in _RESERVED:
        raise SiteError("Use a short name of letters, numbers, dots, dashes or underscores, e.g. mysite")
    base = default_docroot()
    path = (path or "").strip().rstrip("/") or str(base / name)
    if not path.startswith("/") or ".." in path.split("/") or any(c in path for c in "\n\"'<>$`\\"):
        raise SiteError("The folder must be an absolute path, e.g. /var/www/html/" + name)
    target = Path(path)
    if len(target.parts) < 3 or str(target) in ("/etc", "/usr", "/var", "/root", "/home", "/var/lib", "/var/log"):
        raise SiteError("Pick a folder of its own for the site, e.g. /var/www/" + name)
    items = _folder_state()
    if any(it["name"] == name for it in items):
        raise SiteError(f"/{name} is already a folder site")
    in_root = target.parent == base and target.name == name
    if not in_root and (base / name).exists():
        raise SiteError(f"{base / name} already exists, so /{name} is taken — pick another name")
    if not target.exists():
        target.mkdir(parents=True)
        (target / "index.html").write_text(
            f"<!doctype html><meta charset=utf-8><title>{name}</title>"
            "<body style='font-family:system-ui;background:#0b0a0a;color:#f4efeb;display:grid;"
            "place-items:center;height:100vh;margin:0'><div style='text-align:center'>"
            f"<h1 style='color:#ff8a33'>/{name}</h1><p>New site created by AuroraPanel.</p></div>",
            encoding="utf-8")
        _run(["chown", "-R", "www-data:www-data", str(target)])
    elif not target.is_dir():
        raise SiteError(f"{target} exists and isn't a folder")
    items.append({"name": name, "path": str(target), "alias": not in_root, "created": int(time.time())})
    _folder_apply(items)
    return {"ok": True, "name": name, "path": str(target), "alias": not in_root}


def remove_folder_site(name: str) -> dict:
    """Stops serving /<name> through the panel's conf; the folder and its files are kept."""
    _require()
    items = _folder_state()
    keep = [it for it in items if it["name"] != (name or "").strip().strip("/").lower()]
    if len(keep) == len(items):
        raise SiteError("No folder site with that name")
    if keep:
        _folder_apply(keep)
    else:
        _run(["a2disconf", "-q", FOLDER_CONF.stem])
        FOLDER_CONF.unlink(missing_ok=True)
        if _run(["systemctl", "reload", "apache2"]).returncode != 0:
            _run(["systemctl", "restart", "apache2"])
    return {"ok": True}
