"""Applications — a Softaculous-style installer for web apps (WordPress, Joomla, phpBB, Nextcloud…).

The catalog (appcatalog.py) says where each app's latest release comes from and how it's set up.
Every install runs as a background job with a progress bar:
  1. resolve the target: Local (http://<pi>/<name>), IP address, domain, subdomain, existing site
     (including Apache's built-in site and folder sites) or any folder
  2. make sure PHP (the version Apache runs) has the extensions the app needs
  3. download the latest release (checksum-verified when the project publishes one)
  4. unpack it (or create it with Composer, for frameworks)
  5. create a MariaDB database + user with a random password, when the app needs one
  6. run the app's own command-line installer (admin account included) — or, for apps that only
     have a web installer, hand over its setup page with the database details
  7. give the folder to www-data and let Apache read the app's .htaccess (security rules, pretty URLs)

Installs are remembered in /var/lib/aurora/apps.json; WordPress (and a few others) found under
/var/www are listed too.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

from . import appcatalog, databases, jobs, sites
from . import problems

REGISTRY = Path("/var/lib/aurora/apps.json")
APP_DATA = Path("/var/lib/aurora/app-data")
# Apps whose web root is a sub-folder (Laravel's public/, FreshRSS's p/…) live here, outside every site,
# and the site folder becomes a link to just that sub-folder — so .env files, configs and data aren't served.
APP_SRC = Path("/var/www/aurora-apps")
TRASH = Path("/var/lib/aurora/trash")
APACHE_CONF_DIR = Path("/etc/apache2/conf-available")
SCAN_ROOTS = [Path("/var/www")]
UA = {"User-Agent": "AuroraPanel (+https://aurora51.com)"}


class AppError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _run(argv, timeout=120, env=None, cwd=None, inp=None):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd, input=inp)


def _registry() -> list[dict]:
    try:
        return json.loads(REGISTRY.read_text())
    except (OSError, ValueError):
        return []


def _save_registry(items: list[dict]) -> None:
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY.write_text(json.dumps(items, indent=2))


def apache_php() -> str | None:
    """PHP version Apache actually runs (mods-enabled/phpX.Y.load)."""
    for f in sorted(Path("/etc/apache2/mods-enabled").glob("php*.load")):
        m = re.match(r"php(\d+\.\d+)\.load", f.name)
        if m:
            return m.group(1)
    return None


def _php_bin(ver: str | None) -> str | None:
    if ver and shutil.which(f"php{ver}"):
        return shutil.which(f"php{ver}")
    return shutil.which("php")


def _php_modules(php: str) -> set[str]:
    r = _run([php, "-m"], 30)
    return {l.strip().lower() for l in r.stdout.splitlines() if l.strip() and not l.startswith("[")}


def _slug(s: str, n: int = 20) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")[:n] or "site"


def _pw(n: int = 20) -> str:
    """A password every app's policy accepts: upper, lower, digit and a symbol."""
    alphabet = string.ascii_letters + string.digits
    while True:
        core = "".join(secrets.choice(alphabet) for _ in range(n - 2))
        p = core + secrets.choice("-_.!@#") + secrets.choice(string.digits)
        if re.search(r"[a-z]", p) and re.search(r"[A-Z]", p):
            return p


def _db_pw(n: int = 28) -> str:
    # databases._password forbids quotes/backslash/semicolon; keep it to safe characters.
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _pi_ip() -> str:
    try:
        return sites._local_ip()
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return ""


def _host(opts: dict) -> str:
    """The address the browser used to reach the panel (this Pi), else its LAN IP."""
    h = (opts.get("host") or "").strip().lower()
    if re.match(r"^[a-z0-9.-]{1,253}$", h) and h != "localhost" and not h.startswith("127."):
        return h
    return _pi_ip() or "localhost"


def _norm_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if url and not re.match(r"^https?://", url, re.I):
        url = "http://" + url  # people type 192.168.0.100/blog without the scheme
    return url


# --------------------------------------------------------------------------- #
# listing
# --------------------------------------------------------------------------- #
_status_cache: dict = {}


def _php_info() -> dict:
    ver = apache_php()
    php = _php_bin(ver)
    return {"php_version": ver, "php_bin": php, "mods": _php_modules(php) if php else set()}


def _detect(p: Path) -> str | None:
    for app in appcatalog.APPS:
        marks = app.get("detect")
        if marks and all((p / m).exists() for m in marks):
            return app["id"]
    return None


def installed() -> list[dict]:
    out, seen = [], set()
    for it in _registry():
        p = Path(it["path"])
        it = {**it, "app": it.get("app") or "wordpress", "exists": p.exists()}
        if it["exists"] and it["app"] == "wordpress":
            it["version"] = appcatalog.wp_version(p) or it.get("version")
        seen.add(str(p))
        out.append(it)
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for depth in ("*", "*/*", "*/*/*"):
            for p in root.glob(depth):
                if not p.is_dir() or str(p) in seen:
                    continue
                app = _detect(p)
                if not app:
                    continue
                seen.add(str(p))
                try:
                    url = url_for_folder(str(p), _pi_ip() or "localhost")
                except Exception:
                    url = None
                adm = (appcatalog.get(app) or {}).get("admin_path")
                out.append({"app": app, "path": str(p), "url": url, "detected": True, "exists": True,
                            "admin_url": url + adm if url and adm else None,
                            "db": appcatalog.wp_db(p) if app == "wordpress" else None,
                            "version": appcatalog.wp_version(p) if app == "wordpress" else None})
    return out


def status() -> dict:
    info = _php_info()
    mods = info["mods"]
    try:
        site_list = sites.list_sites().get("sites", [])
    except Exception:
        site_list = []
    try:
        fs = sites.list_folder_sites()
    except Exception:
        fs = {"sites": [], "base": ""}
    wp = next(a for a in appcatalog.APPS if a["id"] == "wordpress")
    return {
        "php_version": info["php_version"], "php_bin": info["php_bin"],
        "php_modules": sorted(mods),
        "php_missing": sorted(e for e in wp["exts"] if e not in mods),
        "mysql": databases.mysql_available(),
        "composer": bool(shutil.which("composer")),
        "installed": installed(),
        "sites": [{"server_name": s["server_name"], "docroot": s["docroot"], "ssl": s["ssl"], "system": s["system"],
                   "conf": s["conf"], "enabled": s["enabled"], "has_http": s.get("has_http", True)}
                  for s in site_list],
        "folder_sites": [{"name": f["name"], "path": f["path"]} for f in fs.get("sites", []) if f.get("exists")],
        "folder_base": fs.get("base") or "/var/www/html",
        "ip": _pi_ip(),
    }


def catalog() -> dict:
    """The app store: categories and apps (no network calls — versions come from latest())."""
    info = _php_info()
    mods = info["mods"]
    apps = []
    for a in appcatalog.APPS:
        item = {k: v for k, v in a.items() if k not in ("source", "install", "detect", "post", "composer")}
        item["missing_exts"] = sorted(e for e in a.get("exts", []) if e not in mods)
        why = _php_too_old(a, info["php_version"])
        if why and a["kind"] != "unavailable":
            item.update(kind="unavailable", why=why)
        apps.append(item)
    return {"categories": appcatalog.CATEGORIES, "apps": apps}


def _php_too_old(app: dict, ver: str | None) -> str | None:
    need = app.get("php_min")
    if need and ver and [int(x) for x in ver.split(".")] < [int(x) for x in need.split(".")]:
        return (f"The current {app['name']} needs PHP {need}; Apache here runs PHP {ver}. "
                "It becomes available once a newer PHP is installed (Software → PHP Settings).")
    return None


_latest_cache: dict[str, tuple[float, dict]] = {}


def latest(app_id: str) -> dict:
    """Version + download size of an app's current release (cached for an hour)."""
    app = appcatalog.get(app_id)
    if not app:
        raise AppError("Unknown app")
    hit = _latest_cache.get(app_id)
    if hit and time.time() - hit[0] < 3600:
        return hit[1]
    try:
        src = appcatalog.resolve(app)
    except Exception as exc:
        raise AppError(f"Couldn't look up the latest {app['name']}: {exc}")
    info = {"version": src.get("version"), "size": src.get("size"), "url": src.get("url")}
    _latest_cache[app_id] = (time.time(), info)
    return info


# --------------------------------------------------------------------------- #
# Where it goes
# --------------------------------------------------------------------------- #
def url_for_folder(path: str, host: str) -> str | None:
    """Where Apache already serves a folder: under a folder site, a site's document root, or the built-in site."""
    p = Path(path)
    best = None  # (depth of the match, url)
    for f in sites.list_folder_sites().get("sites", []):
        root = Path(f["path"])
        if p == root or root in p.parents:
            rel = p.relative_to(root).as_posix()
            cand = (len(root.parts), f"{_own_scheme()}://{host}/{f['name']}" + ("" if rel == "." else "/" + rel))
            best = max(best, cand) if best else cand
    for s in sites.list_sites().get("sites", []):
        if not s["enabled"] or not s["docroot"] or (s["system"] and not s.get("has_http", True)):
            continue
        root = Path(s["docroot"])
        if p == root or root in p.parents:
            rel = p.relative_to(root).as_posix()
            name = host if s["system"] else s["server_name"]
            scheme = ("https" if s["ssl"] != "none" else "http") if not s["system"] else _own_scheme()
            cand = (len(root.parts), f"{scheme}://{name}" + ("" if rel == "." else "/" + rel))
            best = max(best, cand) if best else cand
    return best[1] if best else None


def _own_scheme() -> str:
    """http or https for this Pi's own address: https when the built-in site forces it."""
    try:
        for x in sites.list_sites().get("sites", []):
            if x["system"] and x.get("has_http") and x["enabled"] and x.get("force_https") and x.get("https_via"):
                return "https"
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    return "http"


def _resolve_target(opts: dict, log, dry: bool = False) -> tuple[Path, str, bool | dict]:
    """Returns (install dir, public URL, what was created: False, True for an Apache site, or
    {"folder_site": name}). dry=True only checks, without creating anything."""
    mode = opts.get("mode")
    sub = (opts.get("subfolder") or "").strip().strip("/")
    if sub and not re.match(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$", sub) or ".." in sub:
        raise AppError("Sub-folder may only contain letters, digits, . _ - and /")
    if mode == "webroot":
        # A folder a web server other than Apache already serves: nothing to create, no Apache rules to add.
        base = Path(str(opts.get("path") or ""))
        url = _norm_url(opts.get("url") or "")
        if not str(base).startswith("/var/www/") or ".." in base.parts or not url:
            raise AppError("Choose a site's web folder inside /var/www")
        idx = base / "index.html"
        if not dry and idx.exists() and "New site created by AuroraPanel" in idx.read_text(errors="replace"):
            idx.unlink()
        return base, url, False
    host = _host(opts)
    if mode == "ip":
        ip = (opts.get("ip") or "").strip()
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            raise AppError("Enter an IP address, e.g. 192.168.0.50")
        if ip in (host, _pi_ip()):
            # This Pi's own address is Apache's built-in site: a site there is a folder at http://<ip>/<name>.
            opts = {**opts, "name": opts.get("name") or opts.get("app") or "app"}
            mode = "local"
        else:
            opts = {**opts, "domain": ip, "www": False}
            mode = "new_domain"
    if mode == "local":
        name = (opts.get("name") or "").strip().strip("/").lower()
        if not sites._FOLDER_NAME.match(name) or name in sites._RESERVED:
            raise AppError("Site name: letters, numbers, dots, dashes or underscores, e.g. blog")
        base = str(sites.default_docroot()).rstrip("/")
        path = (opts.get("path") or "").strip().rstrip("/") or f"{base}/{name}"
        url = f"{_own_scheme()}://{host}/{name}"
        existing = next((f for f in sites.list_folder_sites().get("sites", []) if f["name"] == name), None)
        if existing:
            if Path(existing["path"]) != Path(path):
                raise AppError(f"/{name} is already a folder site for {existing['path']} — pick another name")
            return Path(path), url, False
        if not existing and (Path(base) / name).exists() and Path(path) != Path(base) / name:
            raise AppError(f"{base}/{name} already exists, so /{name} is taken — pick another name")
        if dry:
            return Path(path), url, False
        log(f"• Creating local site {url}/ → {path}…")
        try:
            r = sites.create_folder_site(name, path)
        except sites.SiteError as exc:
            raise AppError(str(exc))
        idx = Path(r["path"]) / "index.html"
        if idx.exists() and "New site created by AuroraPanel" in idx.read_text(errors="replace"):
            idx.unlink()  # the starter page would shadow index.php
        return Path(r["path"]), url, {"folder_site": name}
    if mode in ("new_domain", "subdomain"):
        if mode == "subdomain":
            label = (opts.get("subdomain") or "").strip().lower()
            parent = (opts.get("parent") or "").strip().lower()
            if not re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", label):
                raise AppError("Enter a valid subdomain label, e.g. blog")
            if not parent:
                raise AppError("Pick the domain the subdomain belongs to")
            name = f"{label}.{parent}"
        else:
            name = (opts.get("domain") or "").strip().lower()
        if not re.match(r"^[a-z0-9.-]{1,253}$", name) or "." not in name:
            raise AppError("Enter a domain, e.g. myblog.com or blog.test")
        ssl = bool(opts.get("ssl"))
        if sites._conf_for(name):
            raise AppError(f"{name} already exists — pick “Existing site” to install into it")
        if dry:
            return Path("/var/www") / name / sub if sub else Path("/var/www") / name, \
                f"{'https' if ssl else 'http'}://{name}" + (f"/{sub}" if sub else ""), False
        settings = {"server_name": name, "ssl": "selfsigned" if ssl else "none", "force_https": ssl,
                    "aliases": ["www." + name] if mode == "new_domain" and opts.get("www", True) and not name.startswith("www.")
                    and not re.match(r"^\d", name) else []}
        log(f"• Creating Apache site {name}…")
        try:
            r = sites.create_site(settings)
        except sites.SiteError as exc:
            raise AppError(str(exc))
        base = Path(r["docroot"])
        idx = base / "index.html"
        if idx.exists() and "AuroraPanel" in idx.read_text(errors="replace"):
            idx.unlink()  # placeholder page would shadow index.php
        scheme = "https" if ssl else "http"
        return (base / sub if sub else base), f"{scheme}://{name}" + (f"/{sub}" if sub else ""), True
    if mode == "existing":
        name = (opts.get("site") or "").strip()
        if name.startswith("folder:"):
            fname = name[7:]
            f = next((x for x in sites.list_folder_sites().get("sites", []) if x["name"] == fname), None)
            if not f:
                raise AppError(f"No folder site /{fname}")
            base = Path(f["path"])
            return (base / sub if sub else base), f"{_own_scheme()}://{host}/{fname}" + (f"/{sub}" if sub else ""), False
        try:
            d = sites.get_site(name)
        except sites.SiteError as exc:
            raise AppError(str(exc))
        s = d["settings"]
        base = Path(s["docroot"])
        if d["system"]:
            scheme, server = (_own_scheme() if d["has_http"] else "https"), host  # the built-in site answers on this Pi's address
        else:
            scheme, server = ("https" if s["ssl"] != "none" else "http"), s["server_name"]
        idx = base / "index.html"
        if not dry and not sub and idx.exists() and "New site created by AuroraPanel" in idx.read_text(errors="replace"):
            idx.unlink()  # the starter page would shadow index.php; a page of the owner's own stays
        return (base / sub if sub else base), f"{scheme}://{server}" + (f"/{sub}" if sub else ""), False
    if mode == "folder":
        p = (opts.get("path") or "").strip().rstrip("/")
        if not p.startswith("/") or ".." in p.split("/") or len(Path(p).parts) < 3:
            raise AppError("Folder must be an absolute path of its own, e.g. /var/www/html/blog")
        url = _norm_url(opts.get("url") or "") or url_for_folder(p, host)
        if not url:
            # Nothing serves it yet: make it a local site at http://<pi>/<folder name>.
            return _resolve_target({**opts, "mode": "local", "name": Path(p).name.lower(), "path": p}, log, dry)
        if not re.match(r"^https?://[^\s\"'<>]+$", url):
            raise AppError("Enter the address this folder is served at, e.g. http://192.168.0.100/blog")
        return Path(p), url, False
    raise AppError("Choose where to install")


def preview(opts: dict) -> dict:
    """What the wizard shows before installing: the folder, the address, and anything that would stop it."""
    try:
        dest, url, _ = _resolve_target(opts, lambda *_: None, dry=True)
    except AppError as exc:
        return {"ok": False, "error": str(exc)}
    app = appcatalog.get(opts.get("app") or "wordpress") or {}
    web = url
    try:
        _check_empty(dest, bool(opts.get("overwrite")), app)
        problem = None
    except AppError as exc:
        problem = str(exc)
    return {"ok": problem is None, "error": problem, "path": str(dest), "url": web}


def _check_empty(path: Path, overwrite: bool, app: dict | None = None) -> None:
    if not path.exists():
        return
    if not path.is_dir():
        raise AppError(f"{path} is a file")
    items = [p for p in path.iterdir() if p.name not in ("index.html", ".well-known")]
    found = _detect(path)
    if found:
        name = (appcatalog.get(found) or {}).get("name", found)
        raise AppError(f"{name} is already installed in {path}")
    strict = (app or {}).get("kind") == "composer" or bool((app or {}).get("web_suffix"))
    if path.is_symlink():
        raise AppError(f"{path} is a link to another folder — pick another name")
    if items and (not overwrite or strict):
        raise AppError(f"{path} is not empty ({len(items)} items). Pick another folder"
                       + ("" if strict else " or tick “install anyway”") + ".")


# --------------------------------------------------------------------------- #
# Install steps
# --------------------------------------------------------------------------- #
EXT_PKG = {"mysqli": "mysql", "pdo_mysql": "mysql", "curl": "curl", "gd": "gd", "mbstring": "mbstring", "dom": "xml",
           "xml": "xml", "simplexml": "xml", "zip": "zip", "intl": "intl", "bcmath": "bcmath", "gmp": "gmp",
           "pdo_sqlite": "sqlite3", "sqlite3": "sqlite3", "soap": "soap", "imap": "imap", "ldap": "ldap", "apcu": "apcu",
           "exif": "common", "fileinfo": "common", "iconv": "common", "ctype": "common", "tokenizer": "common",
           "opcache": "opcache", "readline": "readline", "imagick": "imagick", "xsl": "xsl"}


def _ensure_php(app: dict, log) -> str:
    ver = apache_php()
    php = _php_bin(ver)
    if not php:
        raise AppError("PHP is not installed — install Apache + PHP first (Software → System Applications)")
    mods = _php_modules(php)
    missing = [e for e in app.get("exts", []) if e not in mods]
    if missing:
        pkgs = sorted({f"php{ver}-{EXT_PKG.get(e, e)}" if ver else f"php-{EXT_PKG.get(e, e)}" for e in missing})
        log(f"• Installing PHP extensions: {', '.join(pkgs)}…")
        rc = log.apt(["install", *pkgs], (1, 7)) if hasattr(log, "apt") else _run(
            ["apt-get", "-y", "-o", "DPkg::Lock::Timeout=600", "install", *pkgs], 900,
            {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}).returncode
        still = [e for e in app.get("exts_required", app.get("exts", [])) if e not in _php_modules(php)]
        if rc != 0 and still:
            raise AppError("Couldn't install required PHP extensions (see the log)")
        if still:
            raise AppError("Still missing PHP extensions: " + ", ".join(still))
        _run(["systemctl", "reload", "apache2"])
    else:
        log(f"• PHP {ver or ''} has everything {app['name']} needs")
    return php


def _download(src: dict, log, lo: float, hi: float) -> Path:
    url = src["url"]
    log(f"• Downloading {app_label(src)} from {url.split('/')[2]}…")
    tmp = Path(tempfile.mkdtemp(prefix="aurora-app-"))
    name = src.get("filename") or re.sub(r"[?#].*$", "", url.rsplit("/", 1)[-1]) or "download"
    zpath = tmp / name
    total = int(src.get("size") or 0)
    curl = shutil.which("curl")
    if curl:
        # The real curl: some project servers (phpBB's) only serve curl and wget.
        proc = subprocess.Popen([curl, "-fsSL", "--retry", "2", "--connect-timeout", "30", "-o", str(zpath), url],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        while proc.poll() is None:
            time.sleep(0.5)
            got = zpath.stat().st_size if zpath.exists() else 0
            log.progress(lo + (hi - lo) * (min(got / total, 1) if total else 0.5),
                         f"Downloading · {got // 1048576} of {total // 1048576 if total else '?'} MB")
        if proc.returncode != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            raise AppError(f"Download failed ({url.split('/')[2]}): {(proc.stderr.read() or '').strip()[-300:]}")
    else:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=60) as r, open(zpath, "wb") as fh:
            total = int(r.headers.get("Content-Length") or total)
            got, last = 0, 0.0
            while chunk := r.read(256 * 1024):
                fh.write(chunk)
                got += len(chunk)
                if time.monotonic() - last > 0.4:
                    last = time.monotonic()
                    log.progress(lo + (hi - lo) * (got / total if total else 0.5),
                                 f"Downloading · {got // 1048576} of {total // 1048576 if total else '?'} MB")
    log(f"  {zpath.stat().st_size / 1048576:.1f} MB downloaded")
    if src.get("checksum"):
        h = hashlib.new(src["algo"])
        with open(zpath, "rb") as fh:
            while chunk := fh.read(1 << 20):
                h.update(chunk)
        if h.hexdigest().lower() != src["checksum"].lower():
            shutil.rmtree(tmp, ignore_errors=True)
            raise AppError("The download failed its checksum check — try again")
        log(f"  {src['algo'].upper()} checksum OK")
    else:
        log("  (no published checksum — downloaded over HTTPS from the project's own server)")
    return zpath


def app_label(src: dict) -> str:
    return f"{src.get('name', 'app')} {src.get('version') or ''}".strip()


def _extract(archive: Path, dest: Path, sub: str | None, log) -> None:
    """Unpack into dest, dropping the archive's single top folder (and keeping only `sub` when given)."""
    log(f"• Unpacking into {dest}…")
    dest.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".aurora-unpack-", dir=dest.parent))
    try:
        name = archive.name.lower()
        if name.endswith(".zip") or zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as z:
                root = work.resolve()
                for info in z.infolist():
                    target = (work / info.filename).resolve()
                    if root not in target.parents and target != root:
                        continue  # zip-slip guard
                    if info.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(info) as s, open(target, "wb") as out:
                        shutil.copyfileobj(s, out)
                    mode = (info.external_attr >> 16) & 0o777
                    if mode & 0o100:
                        target.chmod(0o755)
        elif tarfile.is_tarfile(archive):
            with tarfile.open(archive) as tf:
                tf.extractall(work, filter="data")
        elif name.endswith(".php"):
            shutil.copy2(archive, work / "index.php")
        else:
            raise AppError(f"Don't know how to unpack {archive.name}")
        top = work
        entries = [p for p in top.iterdir() if p.name not in ("__MACOSX",)]
        while len(entries) == 1 and entries[0].is_dir():
            top = entries[0]
            entries = list(top.iterdir())
        if sub:
            cand = top / sub
            if not cand.is_dir():
                raise AppError(f"The download doesn't contain {sub}/ — the project may have changed its layout")
            top = cand
        for p in top.iterdir():
            target = dest / p.name
            if target.exists():
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            shutil.move(str(p), target)
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(archive.parent, ignore_errors=True)


def _create_db(prefix: str, base: str, log) -> tuple[str, str, str]:
    existing = {d["name"] for d in databases.mysql_databases()}
    name = f"{prefix}_{_slug(base, 40)}"[:60]
    i = 2
    while name in existing:
        name = f"{prefix}_{_slug(base, 36)}_{i}"[:60]
        i += 1
    user, pw = name[:32], _db_pw()
    log(f"• Creating database {name} and user {user}…")
    databases._mysql(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
    databases._mysql(f"DROP USER IF EXISTS '{user}'@'localhost';")
    databases._mysql(f"CREATE USER '{user}'@'localhost' IDENTIFIED BY '{pw}';")
    databases._mysql(f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{user}'@'localhost'; FLUSH PRIVILEGES;")
    return name, user, pw


def _apache_conf(dest: Path, slug: str, php_values: dict, log) -> str | None:
    """Let Apache read the app's .htaccess (and set its PHP limits) for this folder only."""
    if not APACHE_CONF_DIR.is_dir():
        return None
    name = f"zz-aurora-app-{slug}"
    conf = APACHE_CONF_DIR / f"{name}.conf"
    lines = [f"# Written by AuroraPanel for the app in {dest} — removed when the app is removed.",
             f'<Directory "{dest}">', "    AllowOverride All", "    Options -Indexes +FollowSymLinks", "    Require all granted"]
    if php_values:
        lines.append("    <IfModule php_module>")
        lines += [f"        php_value {k} {v}" for k, v in php_values.items()]
        lines.append("    </IfModule>")
    lines.append("</Directory>")
    conf.write_text("\n".join(lines) + "\n")
    _run(["a2enmod", "-q", "rewrite", "headers", "env", "dir", "mime"])
    _run(["a2enconf", "-q", name])
    t = _run(["apache2ctl", "configtest"])
    if t.returncode != 0:
        _run(["a2disconf", "-q", name])
        conf.unlink(missing_ok=True)
        log("  (Apache didn't accept the per-app rules — skipped them)")
        return None
    if _run(["systemctl", "reload", "apache2"]).returncode != 0:
        _run(["systemctl", "restart", "apache2"])
    log("• Apache: .htaccess rules and pretty URLs enabled for this folder")
    return name


def _remove_apache_conf(name: str | None) -> None:
    if not name or not re.match(r"^zz-aurora-app-[a-z0-9_]+$", name):
        return
    _run(["a2disconf", "-q", name])
    (APACHE_CONF_DIR / f"{name}.conf").unlink(missing_ok=True)
    if _run(["systemctl", "reload", "apache2"]).returncode != 0:
        _run(["systemctl", "restart", "apache2"])


def _composer(log) -> str:
    c = shutil.which("composer")
    if c:
        return c
    log("• Installing Composer (PHP's package manager)…")
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    r = _run(["apt-get", "-y", "-o", "DPkg::Lock::Timeout=600", "install", "composer"], 900, env)
    c = shutil.which("composer")
    if not c:
        raise AppError("Couldn't install Composer:\n" + (r.stderr or r.stdout)[-600:])
    return c


class Ctx:
    """What an app's installer gets: where, the database, the options, and helpers."""

    def __init__(self, app, dest, url, php, o, log, db=None):
        self.app, self.dest, self.url, self.php, self.o, self.log = app, dest, url, php, o, log
        self.db, self.db_user, self.db_pass = db or (None, None, None)
        self.data_dir: Path | None = None
        self.notes: list[str] = []
        self.creds: list[list[str]] = []

    @property
    def parts(self):
        return urllib.parse.urlsplit(self.url)

    def run(self, argv, timeout=900, cwd=None, env=None, as_www=False, inp=None, what=None):
        if as_www:
            argv = ["runuser", "-u", "www-data", "--", *argv]
        r = _run(argv, timeout, env={**os.environ, **(env or {})}, cwd=str(cwd or self.dest), inp=inp)
        if r.returncode != 0:
            out = ((r.stderr or "") + "\n" + (r.stdout or "")).strip()
            # Drop progress chatter and usage text; keep what explains the failure.
            lines = [l for l in out.splitlines() if l.strip() and not re.search(r"\.\.\. passed\.?$|^\s*\S+:\S+ \[--", l)]
            msg = "\n".join(lines)
            if len(msg) > 1300:
                msg = msg[:700] + "\n…\n" + msg[-500:]
            raise AppError(f"{what or self.app['name'] + ' installer'} failed:\n{msg}")
        return r

    def own(self):
        _run(["chown", "-R", "www-data:www-data", str(self.dest)], 600)

    def make_data_dir(self) -> Path:
        d = APP_DATA / f"{self.app['id']}-{_slug(self.url.split('://', 1)[1], 40)}"
        n = 2
        while d.exists():
            d = APP_DATA / f"{self.app['id']}-{_slug(self.url.split('://', 1)[1], 36)}-{n}"
            n += 1
        d.mkdir(parents=True)
        _run(["chown", "-R", "www-data:www-data", str(d)])
        d.chmod(0o770)
        self.data_dir = d
        return d


import urllib.parse  # noqa: E402  (used by Ctx.parts)


def _validate(app: dict, opts: dict) -> dict:
    o = dict(opts or {})
    o["app"] = app["id"]
    wants = bool(o.get("setup", True)) if app.get("optional_setup") else True
    o["setup"] = wants and app["kind"] == "cli" and app.get("admin", True)
    o["title"] = (o.get("title") or "").strip()[:80] or f"My {app['name']} site"
    if o["setup"]:
        if app.get("fixed_user"):
            o["admin_user"] = app["fixed_user"]  # the app names its first account itself
        else:
            o["admin_user"] = (o.get("admin_user") or "").strip()
            lo, hi = app.get("user_len", (3, 40))
            if not re.match(r"^[A-Za-z0-9_.@-]+$", o["admin_user"]) or not lo <= len(o["admin_user"]) <= hi:
                raise AppError(f"Admin username: {lo}–{hi} letters, digits, _ . @ -")
            if o["admin_user"].lower() == "admin":
                raise AppError("Please don't use “admin” as the username — it's the first thing bots try")
        o["admin_email"] = (o.get("admin_email") or "").strip()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", o["admin_email"]):
            raise AppError("Enter a valid admin email")
        o["admin_pass"] = o.get("admin_pass") or ""
        if len(o["admin_pass"]) < 12:
            raise AppError("Admin password must be at least 12 characters")
        if app.get("strong_pw") and not (re.search(r"[a-z]", o["admin_pass"]) and re.search(r"[A-Z]", o["admin_pass"])
                                          and re.search(r"\d", o["admin_pass"])):
            raise AppError(f"{app['name']} wants the password to mix upper- and lower-case letters and a number")
        if any(c in o["admin_pass"] for c in "\"'\\\n\r"):
            raise AppError("Admin password can't contain quotes, backslashes or line breaks")
    return o


_install_lock = threading.Lock()


def install(app_id: str, opts: dict) -> jobs.Job:
    app = appcatalog.get(app_id)
    if not app:
        raise AppError("Unknown app")
    if app["kind"] == "unavailable":
        raise AppError(app.get("why") or f"{app['name']} can't be installed here")
    too_old = _php_too_old(app, apache_php())
    if too_old:
        raise AppError(too_old)
    if opts.get("mode") != "webroot" and not shutil.which("apache2ctl"):
        raise AppError("Apache is not installed — install it in Software → System Applications")
    if app.get("db"):
        try:
            databases.mysql_require()
        except databases.DatabaseError as exc:
            raise AppError(str(exc))
    o = _validate(app, opts)
    # Check the target up-front so mistakes show at once instead of halfway through the job.
    dest0, _, _ = _resolve_target(o, lambda *_: None, dry=True)
    _check_empty(dest0, bool(o.get("overwrite")), app)
    with _install_lock:
        for j in jobs.find(area="apps"):
            if j.status == "running" and j.meta.get("path") == str(dest0):
                raise AppError(f"Something is already being installed in {dest0}")
        return jobs.launch_fn(f"Install {app['name']}", lambda log: _work(app, o, log),
                              meta={"area": "apps", "app": app["id"], "path": str(dest0)})


def _work(app: dict, o: dict, log) -> dict:
    t0 = time.time()
    log.progress(1, "Checking PHP")
    php = _ensure_php(app, log)
    log.progress(4, "Finding the latest release")
    src = {}
    if app["kind"] != "composer":
        src = {**appcatalog.resolve(app), "name": app["name"]}
        log(f"• Latest {app['name']}: {src.get('version') or 'current release'}")
    log.progress(6, "Preparing the site")
    dest, url, created = _resolve_target(o, log)
    _check_empty(dest, bool(o.get("overwrite")), app)
    # Only a folder that held nothing before may be emptied again if the install fails.
    fresh = not dest.exists() or not any(p for p in dest.iterdir() if p.name != "index.html")
    suffix = (app.get("web_suffix") or "").strip("/")
    site_dir = dest
    if suffix:
        # The project goes outside the web folders; the site folder will link to its public part only.
        APP_SRC.mkdir(parents=True, exist_ok=True)
        os.chmod(APP_SRC, 0o755)
        base = APP_SRC / _slug(f"{app['id']}_{url.split('://', 1)[1]}", 60)
        n = 2
        root_dir = base
        while root_dir.exists():
            root_dir = Path(f"{base}_{n}")
            n += 1
        dest = root_dir
    entry = {"app": app["id"], "path": str(site_dir), "url": url, "installed": int(time.time()),
             "created_site": created, "title": o["title"]}
    if suffix:
        entry["src"] = str(dest)
    try:
        if app["kind"] == "composer":
            log.progress(10, "Creating the project with Composer")
            comp = _composer(log)
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists() and not any(dest.iterdir()):
                dest.rmdir()
            env = {**os.environ, "COMPOSER_ALLOW_SUPERUSER": "1", "COMPOSER_HOME": "/var/lib/aurora/composer",
                   "COMPOSER_NO_INTERACTION": "1"}
            if app.get("composer_lib"):  # a library: required into the folder, not a project of its own
                dest.mkdir(parents=True, exist_ok=True)
                args = app["composer"] + [f"--working-dir={dest}"]
            else:
                args = app["composer"] + [str(dest)]
            log("• composer " + " ".join(args))
            r = _run([php, comp, *args], 1800, env, cwd=str(dest.parent))
            if r.returncode != 0:
                raise AppError("Composer failed:\n" + ((r.stderr or "") + (r.stdout or ""))[-1200:])
            log.progress(80, "Project created")
        else:
            zpath = _download(src, log, 8, 55)
            log.progress(56, "Unpacking")
            _extract(zpath, dest, app.get("sub"), log)
        log.progress(62, "Database")
        db = (None, None, None)
        if app.get("db"):
            db = _create_db(app.get("db_prefix", app["id"][:6]), url.split("://", 1)[1].replace("/", "_"), log)
            entry.update(db=db[0], db_user=db[1])
        ctx = Ctx(app, dest, url, php, o, log, db)
        if app.get("first_login"):
            ctx.notes.append(app["first_login"])
        log.progress(66, f"Setting up {app['name']}")
        installer = app.get("install")
        if installer:
            installer(ctx)
        log.progress(92, "Permissions")
        log("• Giving the files to the web server (www-data)…")
        ctx.own()
        _run(["find", str(dest), "-type", "d", "-exec", "chmod", "u+rwx,g+rx,o+rx", "{}", "+"], 600)
        post = app.get("post")
        if post:
            post(ctx)
        if suffix:
            pub = dest / suffix
            if not pub.is_dir():
                raise AppError(f"{app['name']} has no {suffix}/ folder — the project may have changed its layout")
            if site_dir.is_symlink() or site_dir.is_file():
                site_dir.unlink()
            elif site_dir.exists():
                shutil.rmtree(site_dir)  # empty (checked above), or just a placeholder page
            site_dir.parent.mkdir(parents=True, exist_ok=True)
            site_dir.symlink_to(pub, target_is_directory=True)
            _run(["chown", "-h", "www-data:www-data", str(site_dir)])
            log(f"• {site_dir} → {pub} (only the public folder is served)")
        if o.get("mode") != "webroot":
            entry["apache_conf"] = _apache_conf(dest / suffix if suffix else dest,
                                                _slug(f"{app['id']}_{url.split('://', 1)[1]}", 50), app.get("php_values") or {}, log)
        if ctx.data_dir:
            entry["data_dir"] = str(ctx.data_dir)
    except BaseException:
        # Leave nothing half-made behind: database, files we unpacked and the site we created.
        log("• Cleaning up after the failed install…")
        if entry.get("db"):
            try:
                databases._mysql(f"DROP DATABASE IF EXISTS `{entry['db']}`;")
                databases._mysql(f"DROP USER IF EXISTS '{entry['db_user']}'@'localhost';")
            except Exception as quiet_exc:
                problems.quiet(quiet_exc)
        if suffix:
            shutil.rmtree(dest, ignore_errors=True)  # the project folder is always ours
            if site_dir.is_symlink():
                site_dir.unlink()
        if fresh and site_dir.exists() and str(site_dir).startswith("/var/www/") and len(site_dir.parts) > 3:
            shutil.rmtree(site_dir, ignore_errors=True)
        if fresh and (created or o.get("mode") == "existing") and not site_dir.exists():
            site_dir.mkdir(parents=True, exist_ok=True)  # a site's document root must stay
            _run(["chown", "www-data:www-data", str(site_dir)])
        if isinstance(created, dict) and created.get("folder_site"):
            try:
                sites.remove_folder_site(created["folder_site"])
            except Exception as quiet_exc:
                problems.quiet(quiet_exc)
        raise
    web = url
    entry.update(url=web, version=src.get("version") or "", admin_user=o.get("admin_user") if o["setup"] else None,
                 admin_url=web + app["admin_path"] if app.get("admin_path") else None,
                 setup_url=web + app["setup_path"] if app.get("setup_path") else None)
    items = [i for i in _registry() if i.get("path") != str(site_dir)]
    _save_registry(items + [entry])
    log(f"✔ {app['name']} {entry['version']} installed in {int(time.time() - t0)}s")
    log(f"  Site:  {web}/")
    if entry.get("setup_url"):
        log(f"  Finish setup in your browser: {entry['setup_url']}")
    elif entry.get("admin_url"):
        log(f"  Admin: {entry['admin_url']}")
    return {**entry, "db_pass": db[2] if app.get("db") and app["kind"] != "cli" else None,
            "notes": ctx.notes, "creds": ctx.creds, "name": app["name"]}


def install_wordpress(opts: dict) -> jobs.Job:
    return install("wordpress", opts)


def uninstall(path: str, drop_db: bool = True, remove_site: bool = False) -> dict:
    p = Path(path)
    items = _registry()
    entry = next((i for i in items if i["path"] == path), None)
    if not entry and not _detect(p):
        raise AppError("No installed app found there")
    if str(p) in ("/", "/var/www", "/var/www/html", "/root", "/home") or not str(p).startswith("/var/www/"):
        raise AppError("For safety, only apps under /var/www/<site> can be removed here")
    app_id = (entry or {}).get("app") or _detect(p) or "wordpress"
    db = (entry or {}).get("db") or (appcatalog.wp_db(p) if app_id == "wordpress" else None)
    user = (entry or {}).get("db_user")
    TRASH.mkdir(parents=True, exist_ok=True)
    moved = None
    src = (entry or {}).get("src")
    if src and src.startswith(str(APP_SRC) + "/") and Path(src).exists():
        moved = TRASH / f"{Path(src).name}-{int(time.time())}"
        shutil.move(src, moved)
        if p.is_symlink():
            p.unlink()
            p.mkdir(parents=True, exist_ok=True)
            _run(["chown", "www-data:www-data", str(p)])
    elif p.is_symlink():
        p.unlink()
        p.mkdir(parents=True, exist_ok=True)
    elif p.exists():
        moved = TRASH / f"{p.name}-{int(time.time())}"
        shutil.move(str(p), moved)
        p.mkdir(parents=True, exist_ok=True)   # keep the docroot so Apache stays happy
        _run(["chown", "www-data:www-data", str(p)])
    data_dir = (entry or {}).get("data_dir")
    if data_dir and data_dir.startswith(str(APP_DATA) + "/") and Path(data_dir).exists():
        shutil.move(data_dir, TRASH / f"{Path(data_dir).name}-{int(time.time())}")
    if drop_db and db and re.match(r"^[A-Za-z0-9_]{1,64}$", db):
        databases._mysql(f"DROP DATABASE IF EXISTS `{db}`;")
        if user and re.match(r"^[A-Za-z0-9_]{1,32}$", user):
            databases._mysql(f"DROP USER IF EXISTS '{user}'@'localhost';")
    _remove_apache_conf((entry or {}).get("apache_conf"))
    created = (entry or {}).get("created_site")
    if remove_site and isinstance(created, dict) and created.get("folder_site"):
        try:
            sites.remove_folder_site(created["folder_site"])
        except sites.SiteError:
            pass
        try:
            p.rmdir()  # the site is gone, so its (now empty) folder can go too
        except OSError:
            pass
    elif remove_site and created is True:
        host = entry["url"].split("://", 1)[1].split("/")[0]
        try:
            sites.remove_site(host)
        except sites.SiteError:
            pass
    _save_registry([i for i in items if i["path"] != path])
    return {"ok": True, "files_moved_to": str(moved) if moved else None, "db_dropped": bool(drop_db and db)}


def suggest_password() -> dict:
    return {"password": _pw()}
