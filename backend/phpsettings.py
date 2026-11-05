"""PHP settings: php.ini basics, extensions and versions.

Changes never touch php.ini itself — they go into a panel-owned override
file, /etc/php/<ver>/<sapi>/conf.d/99-aurora.ini, which PHP reads last (so it
wins) and package upgrades leave alone. Removing a key there = back to the
php.ini default. The effective value is computed like PHP does: php.ini, then
conf.d/*.ini in order, last assignment wins."""
from __future__ import annotations

import glob
import platform
import re
import shutil
import subprocess
from pathlib import Path

from . import distro
from . import jobs
from . import problems

IS_LINUX = platform.system() == "Linux"
PHP_DIR = Path("/etc/php")
OVERRIDE = "99-aurora.ini"
SAPIS = {"apache2": "Apache (mod_php)", "fpm": "PHP-FPM (Nginx / Lighttpd / Caddy)", "cli": "Command line & cron"}
_VER = re.compile(r"^\d+\.\d+$")
_SIZE = re.compile(r"^(-1|\d+[KMG]?)$", re.I)
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "PATH": distro.PATH}
APT = ["apt-get", "-o", "DPkg::Lock::Timeout=600", "-y"]

# key, label, type, help, extra
SETTINGS = [
    ("Uploads & forms", [
        ("upload_max_filesize", "Max upload file size", "size", "Largest single uploaded file (e.g. 64M, 1G).", {}),
        ("post_max_size", "Max POST size", "size", "Whole form/request size — must be ≥ max upload size.", {}),
        ("max_file_uploads", "Max files per upload", "int", "How many files one request may upload.", {"min": 1, "max": 10000}),
        ("file_uploads", "Allow file uploads", "bool", "", {}),
        ("max_input_vars", "Max input variables", "int", "Form fields per request (raise for big WooCommerce/menus).", {"min": 100, "max": 1000000}),
    ]),
    ("Resources", [
        ("memory_limit", "Memory limit per script", "size", "e.g. 256M. -1 = unlimited (not recommended).", {}),
        ("max_execution_time", "Max execution time (s)", "int", "0 = unlimited.", {"min": 0, "max": 86400}),
        ("max_input_time", "Max input parsing time (s)", "int", "-1 = use max execution time.", {"min": -1, "max": 86400}),
        ("default_socket_timeout", "Socket timeout (s)", "int", "", {"min": 1, "max": 3600}),
    ]),
    ("Errors & logging", [
        ("display_errors", "Show errors in pages", "bool", "Turn OFF on live sites — it leaks paths and code details.", {}),
        ("display_startup_errors", "Show startup errors", "bool", "", {}),
        ("log_errors", "Log errors", "bool", "", {}),
        ("error_reporting", "Error reporting level", "select", "", {"options": [
            ["E_ALL", "Everything (development)"],
            ["E_ALL & ~E_DEPRECATED", "All except deprecations (production default)"],
            ["E_ALL & ~E_DEPRECATED & ~E_STRICT", "All except deprecations (older PHP default)"],
            ["E_ALL & ~E_NOTICE & ~E_DEPRECATED & ~E_STRICT", "Errors & warnings only"],
            ["E_ERROR | E_PARSE", "Fatal errors only"]]}),
    ]),
    ("General", [
        ("date.timezone", "Time zone", "timezone", "Used by date() when a script doesn't set one.", {}),
        ("short_open_tag", "Allow short tags <?", "bool", "", {}),
        ("allow_url_fopen", "Allow URL fopen", "bool", "Lets scripts open http:// URLs as files (needed by some apps).", {}),
        ("expose_php", "Expose PHP version header", "bool", "Adds X-Powered-By — off hides the PHP version.", {}),
        ("session.gc_maxlifetime", "Session lifetime (s)", "int", "Idle time before session data may be cleaned up.", {"min": 60, "max": 31536000}),
        ("session.cookie_httponly", "Session cookie HttpOnly", "bool", "Keeps session cookies away from JavaScript.", {}),
        ("disable_functions", "Disabled functions", "text", "Comma list, e.g. exec,shell_exec,system,passthru (hardening).", {}),
    ]),
    ("OPcache (speed)", [
        ("opcache.enable", "Enable OPcache", "bool", "Caches compiled scripts — big speed-up, keep on.", {}),
        ("opcache.memory_consumption", "OPcache memory (MB)", "int", "", {"min": 16, "max": 4096}),
        ("opcache.max_accelerated_files", "Max cached files", "int", "", {"min": 200, "max": 1000000}),
        ("opcache.validate_timestamps", "Check for changed files", "bool", "Off = faster, but code edits need a reload.", {}),
        ("opcache.revalidate_freq", "Re-check interval (s)", "int", "", {"min": 0, "max": 3600}),
    ]),
]
_FIELDS = {k: (label, typ, extra) for _, fs in SETTINGS for k, label, typ, _h, extra in fs}
_BOOL_TRUE = {"1", "on", "yes", "true"}

# Commonly needed extensions: package suffix -> what it's for
POPULAR_EXT = {
    "mysql": "MySQL/MariaDB (WordPress, most apps)", "pgsql": "PostgreSQL", "sqlite3": "SQLite",
    "curl": "HTTP requests / APIs", "gd": "Images: resize, thumbnails", "imagick": "Images: ImageMagick (advanced)",
    "mbstring": "Multibyte strings (UTF-8)", "intl": "Internationalisation", "xml": "XML / DOM",
    "zip": "ZIP archives", "bcmath": "Arbitrary precision math", "gmp": "Big-number math",
    "opcache": "Speed: bytecode cache", "apcu": "Speed: in-memory user cache", "redis": "Redis client",
    "memcached": "Memcached client", "soap": "SOAP web services", "ldap": "LDAP / Active Directory",
    "bz2": "bzip2 compression", "imap": "IMAP mail", "xdebug": "Debugger (dev only — slows PHP down)",
}


class PHPSettingsError(RuntimeError):
    pass


def _run(argv: list[str], timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={**APT_ENV})
    except (OSError, subprocess.SubprocessError) as exc:
        raise PHPSettingsError(str(exc))
    if check and r.returncode != 0:
        raise PHPSettingsError((r.stderr or r.stdout or "command failed").strip()[-500:])
    return r


def versions() -> list[str]:
    if not IS_LINUX or not PHP_DIR.is_dir():
        return []
    return sorted((p.name for p in PHP_DIR.iterdir() if _VER.match(p.name)), key=lambda v: tuple(map(int, v.split("."))))


def _sapis(ver: str) -> list[str]:
    return [s for s in SAPIS if (PHP_DIR / ver / s / "php.ini").exists()]


def _check_target(ver: str, sapi: str | None = None):
    if not _VER.match(ver or "") or ver not in versions():
        raise PHPSettingsError("Unknown PHP version")
    if sapi is not None and sapi not in _sapis(ver):
        raise PHPSettingsError("That PHP version has no such mode installed")


_LINE = re.compile(r"^\s*([A-Za-z0-9_.]+)\s*=\s*(.*?)\s*$")


def _parse_ini(path: Path) -> dict[str, str]:
    out = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        if line.lstrip().startswith((";", "#", "[")):
            continue
        m = _LINE.match(line)
        if m:
            v = m.group(2)
            if len(v) >= 2 and v[0] == v[-1] == '"':
                v = v[1:-1]
            else:
                v = re.split(r"\s;", v)[0].strip()
            out[m.group(1)] = v
    return out


def _effective(ver: str, sapi: str) -> tuple[dict, dict, dict]:
    """(effective, php.ini defaults, our overrides) for one SAPI."""
    base = _parse_ini(PHP_DIR / ver / sapi / "php.ini")
    eff = dict(base)
    for f in sorted(glob.glob(str(PHP_DIR / ver / sapi / "conf.d" / "*.ini"))):
        eff.update(_parse_ini(Path(f)))
    ours = _parse_ini(PHP_DIR / ver / sapi / "conf.d" / OVERRIDE)
    return eff, base, ours


def _norm(typ: str, v: str | None) -> str | None:
    if v is None:
        return None
    if typ == "bool":
        return "On" if str(v).strip().lower() in _BOOL_TRUE else "Off"
    return str(v)


# PHP's built-in values for settings php.ini leaves commented out.
_BUILTIN = {"max_input_vars": "1000", "max_file_uploads": "20", "default_socket_timeout": "60", "date.timezone": "",
            "disable_functions": "", "session.cookie_httponly": "Off", "opcache.enable": "On",
            "opcache.memory_consumption": "128", "opcache.max_accelerated_files": "10000",
            "opcache.validate_timestamps": "On", "opcache.revalidate_freq": "2", "display_startup_errors": "Off",
            "short_open_tag": "Off", "expose_php": "On", "allow_url_fopen": "On", "file_uploads": "On",
            "session.gc_maxlifetime": "1440"}


def get(ver: str, sapi: str) -> dict:
    _check_target(ver, sapi)
    eff, base, ours = _effective(ver, sapi)
    values = {k: _norm(t, eff.get(k, _BUILTIN.get(k))) for k, (_l, t, _e) in _FIELDS.items()}
    return {"version": ver, "sapi": sapi, "values": values, "overridden": sorted(k for k in ours if k in _FIELDS),
            "defaults": {k: _norm(_FIELDS[k][1], base.get(k)) for k in _FIELDS},
            "override_file": str(PHP_DIR / ver / sapi / "conf.d" / OVERRIDE)}


def _bytes(v: str) -> int:
    v = v.strip().upper()
    if v == "-1":
        return 1 << 62
    mult = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}.get(v[-1:], 1)
    return int(v.rstrip("KMG")) * mult


def _validate(key: str, value) -> str:
    if key not in _FIELDS:
        raise PHPSettingsError(f"Unknown setting {key}")
    label, typ, extra = _FIELDS[key]
    v = str(value).strip()
    if "\n" in v or '"' in v:
        raise PHPSettingsError(f"{label}: invalid characters")
    if typ == "size":
        if not _SIZE.match(v) or (v == "-1" and key != "memory_limit"):
            raise PHPSettingsError(f"{label}: use a number with K, M or G, e.g. 128M")
        return v.upper()
    if typ == "int":
        if not re.match(r"^-?\d+$", v):
            raise PHPSettingsError(f"{label}: must be a whole number")
        n = int(v)
        if not extra.get("min", -1 << 60) <= n <= extra.get("max", 1 << 60):
            raise PHPSettingsError(f"{label}: must be between {extra.get('min')} and {extra.get('max')}")
        return str(n)
    if typ == "bool":
        return "On" if v.lower() in _BOOL_TRUE else "Off"
    if typ == "select":
        if v not in [o[0] for o in extra["options"]]:
            raise PHPSettingsError(f"{label}: invalid choice")
        return v
    if typ == "timezone":
        import zoneinfo
        if v not in zoneinfo.available_timezones():
            raise PHPSettingsError(f"{label}: unknown time zone")
        return v
    if typ == "text":
        if key == "disable_functions" and v and not re.match(r"^[A-Za-z0-9_]+(\s*,\s*[A-Za-z0-9_]+)*$", v):
            raise PHPSettingsError(f"{label}: comma-separated function names only")
        return v
    raise PHPSettingsError("Unsupported setting type")


def _reload(ver: str, sapi: str) -> list[str]:
    done = []
    if sapi == "apache2" and shutil.which("apache2ctl"):
        if subprocess.run(["systemctl", "is-active", "--quiet", "apache2"]).returncode == 0:
            _run(["systemctl", "reload", "apache2"])
            done.append("apache2")
    if sapi == "fpm":
        unit = f"php{ver}-fpm"
        if subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0:
            _run([f"php-fpm{ver}", "-t"])
            _run(["systemctl", "reload", unit])
            done.append(unit)
    return done


def save(ver: str, sapis: list[str], changes: dict, reset: list[str] | None = None) -> dict:
    """Apply `changes` (key -> value) and `reset` keys (back to php.ini default)
    to every SAPI in `sapis`, then reload what uses them."""
    if not sapis:
        raise PHPSettingsError("Pick at least one place to apply the settings")
    for s in sapis:
        _check_target(ver, s)
    clean = {k: _validate(k, v) for k, v in (changes or {}).items()}
    reset = [k for k in (reset or []) if k in _FIELDS]
    reloaded = []
    for s in sapis:
        eff, _base, ours = _effective(ver, s)
        ours = {k: v for k, v in ours.items() if k in _FIELDS and k not in reset}
        ours.update(clean)
        merged = {**eff, **ours}
        up, post = merged.get("upload_max_filesize"), merged.get("post_max_size")
        if up and post and _SIZE.match(up) and _SIZE.match(post) and _bytes(post) != (1 << 62) and _bytes(post) < _bytes(up):
            raise PHPSettingsError(f"Max POST size ({post}) must be at least the max upload size ({up}) "
                                   f"— otherwise uploads that size fail.")
        path = PHP_DIR / ver / s / "conf.d" / OVERRIDE
        lines = ["; Managed by AuroraPanel — PHP settings overrides (read after php.ini).", ""]
        for k in _FIELDS:
            if k in ours:
                val = ours[k]
                lines.append(f'{k} = "{val}"' if _FIELDS[k][1] in ("text", "timezone", "select") else f"{k} = {val}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        reloaded += _reload(ver, s)
    return {"ok": True, "reloaded": reloaded, **get(ver, sapis[0])}


# ---- extensions ----
def _dpkg_installed(pkgs: list[str]) -> set[str]:
    if not pkgs or not shutil.which("dpkg-query"):
        return set()
    r = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\n", *pkgs], capture_output=True, text=True)
    return {l.split("\t")[0] for l in r.stdout.splitlines() if "\tii" in l}


def _apt_available(pkgs: list[str]) -> set[str]:
    if not pkgs or not shutil.which("apt-cache"):
        return set()
    r = subprocess.run(["apt-cache", "policy", *pkgs], capture_output=True, text=True, timeout=60)
    avail, cur = set(), None
    for line in r.stdout.splitlines():
        m = re.match(r"^(\S+):$", line)
        if m:
            cur = m.group(1)
        elif cur and "Candidate:" in line and "(none)" not in line:
            avail.add(cur)
    return avail


def extensions(ver: str) -> dict:
    _check_target(ver)
    sapis = _sapis(ver)
    mods = sorted(Path(p).stem for p in glob.glob(str(PHP_DIR / ver / "mods-available" / "*.ini")))
    enabled = {s: {Path(p).name.split("-", 1)[-1][:-4] for p in glob.glob(str(PHP_DIR / ver / s / "conf.d" / "*.ini"))}
               for s in sapis}
    pkgs = [f"php{ver}-{e}" for e in POPULAR_EXT]
    installed, available = _dpkg_installed(pkgs), _apt_available(pkgs)
    # mysql package provides mysqli/pdo_mysql, xml provides dom etc — show by package.
    popular = [{"ext": e, "package": f"php{ver}-{e}", "desc": d, "installed": f"php{ver}-{e}" in installed,
                "available": f"php{ver}-{e}" in available} for e, d in POPULAR_EXT.items()]
    return {"version": ver, "sapis": sapis, "modules": [{"name": m, "enabled": {s: m in enabled[s] for s in sapis}} for m in mods],
            "popular": popular}


def set_extension(ver: str, module: str, sapi: str, on: bool) -> dict:
    _check_target(ver, sapi)
    if not re.match(r"^[a-z0-9_]+$", module or "") or not (PHP_DIR / ver / "mods-available" / f"{module}.ini").exists():
        raise PHPSettingsError("Unknown extension")
    tool = "phpenmod" if on else "phpdismod"
    if not shutil.which(tool):
        raise PHPSettingsError(f"{tool} is not available")
    _run([tool, "-v", ver, "-s", sapi, module])
    if sapi == "cli":
        r = _run([f"/usr/bin/php{ver}", "-v"], check=False)
        if r.returncode != 0:  # a broken extension breaks PHP — undo
            _run(["phpdismod" if on else "phpenmod", "-v", ver, "-s", sapi, module], check=False)
            raise PHPSettingsError("PHP failed with that change, so it was undone: " + (r.stderr or r.stdout)[-300:])
    return {"ok": True, "reloaded": _reload(ver, sapi)}


def install_extension(ver: str, ext: str) -> jobs.Job:
    _check_target(ver)
    if ext not in POPULAR_EXT:
        raise PHPSettingsError("Unknown extension package")
    return jobs.launch(f"install php{ver}-{ext}", [*APT, "install", f"php{ver}-{ext}"], env=APT_ENV)


# ---- versions: which PHP Apache uses ----
def apache_version() -> str | None:
    for f in glob.glob("/etc/apache2/mods-enabled/php*.load"):
        m = re.search(r"php(\d+\.\d+)\.load$", f)
        if m:
            return m.group(1)
    return None


def apache_available() -> list[str]:
    return sorted(re.search(r"php(\d+\.\d+)\.load$", f).group(1) for f in glob.glob("/etc/apache2/mods-available/php*.load")
                  if re.search(r"php(\d+\.\d+)\.load$", f))


def set_apache_version(ver: str) -> dict:
    if ver not in apache_available():
        raise PHPSettingsError(f"No Apache module for PHP {ver} (install libapache2-mod-php{ver})")
    cur = apache_version()
    if cur == ver:
        return {"ok": True, "apache": ver}
    if cur:
        _run(["a2dismod", "-q", f"php{cur}"])
    _run(["a2enmod", "-q", f"php{ver}"])
    t = subprocess.run(["apache2ctl", "configtest"], capture_output=True, text=True)
    if t.returncode != 0:
        _run(["a2dismod", "-q", f"php{ver}"], check=False)
        if cur:
            _run(["a2enmod", "-q", f"php{cur}"], check=False)
        raise PHPSettingsError("Apache rejected the change, so it was undone: " + t.stderr[-300:])
    _run(["systemctl", "restart", "apache2"])
    return {"ok": True, "apache": ver}


def overview() -> dict:
    if not IS_LINUX:
        return {"supported": False, "versions": []}
    vs = versions()
    from . import phpmgr
    st = phpmgr.status()
    return {"supported": True, "versions": [{"version": v, "sapis": _sapis(v)} for v in vs], "sapi_labels": SAPIS,
            "schema": [{"title": t, "fields": [{"key": k, "label": l, "type": ty, "help": h, **e} for k, l, ty, h, e in fs]}
                       for t, fs in SETTINGS],
            "cli_default": st.get("current"), "apache": apache_version(), "apache_available": apache_available(),
            "timezones": _timezones()}


def _timezones() -> list[str]:
    try:
        import zoneinfo
        return sorted(z for z in zoneinfo.available_timezones() if "/" in z and not z.startswith(("Etc/", "SystemV/", "posix", "right")))
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return []
