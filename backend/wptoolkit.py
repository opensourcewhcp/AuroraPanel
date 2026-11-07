"""WordPress Toolkit — keep every WordPress on the server updated, checked, hardened and testable.

Uses WP-CLI (the official command-line tool), fetched once to /usr/local/lib/aurora/wp-cli.phar and
checked against its published SHA-512. Commands run as the site's file owner (the isolated site user,
or www-data), never as root inside the site.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from . import distro
from . import jobs

try:
    import pwd  # Linux only; tests also run on Windows
except ImportError:  # pragma: no cover
    pwd = None

PHAR = Path("/usr/local/lib/aurora/wp-cli.phar")
PHAR_URL = "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
PATH = distro.PATH
STAGING_STATE = Path("/var/lib/aurora/wp-staging")   # root's, out of the web's reach: a staging copy's key and database name
GATE = "aurora-staging-gate.php"
MU_HARDEN = "aurora-harden.php"
HARDEN_PHP = """<?php
// AuroraPanel WordPress Toolkit: xmlrpc.php is a password-guessing target. Done here so it holds on every web server.
if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
    http_response_code(403);
    exit;
}
add_filter('xmlrpc_enabled', '__return_false');
"""
UPDATE_WHAT = ("all", "core", "plugins", "themes", "translations")
# A plugin or theme slug. Never a leading dash: WP-CLI would read it as a flag, and --exec or --require run PHP.
_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,190}")
_DB_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_$-]{0,63}")


class WPError(RuntimeError):
    pass


def _run(argv, timeout=300, cwd=None, input=None):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd, input=input,
                              env={"PATH": PATH, "HOME": "/tmp", "WP_CLI_CACHE_DIR": "/tmp/.wp-cli-cache", "LANG": "C.UTF-8"})
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def cli_ready() -> bool:
    return PHAR.exists() and shutil.which("php", path=PATH) is not None


def install_cli() -> dict:
    """Download WP-CLI and check it against the SHA-512 the project publishes next to it."""
    if not shutil.which("php", path=PATH):
        raise WPError("PHP isn't installed")
    PHAR.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = urllib.request.urlopen(PHAR_URL, timeout=60).read()
        want = urllib.request.urlopen(PHAR_URL + ".sha512", timeout=30).read().decode().split()[0].strip()
    except Exception as e:
        raise WPError(f"Couldn't download WP-CLI: {e}")
    if hashlib.sha512(data).hexdigest() != want:
        raise WPError("The WP-CLI download didn't match its published checksum — not installed")
    tmp = PHAR.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o755)
    tmp.replace(PHAR)
    return {"ok": True}


def _owner(path: Path) -> str:
    try:
        return pwd.getpwuid((path / "wp-config.php").lstat().st_uid).pw_name
    except (OSError, KeyError):
        return "www-data"


def _site_user(path: Path) -> str:
    user = _owner(path)
    return "www-data" if user == "root" else user


def _as_owner(path: str, *argv: str, input: str | None = None) -> subprocess.CompletedProcess:
    """Anything that touches a site's files runs as the site. The site's folder is the site's to fill with symlinks,
    and root following one of them would hand a hacked WordPress the rest of the server."""
    return _run(["runuser", "-u", _site_user(Path(path)), "--", *argv], 60, input=input)


def _owner_write(path: str, target: Path, text: str, append: bool = False) -> None:
    r = _as_owner(path, "tee", *(["-a"] if append else []), str(target), input=text)
    if r.returncode != 0:
        raise WPError(f"Couldn't write {target.name}: {(r.stderr or '').strip()[-160:] or 'the site user has no access'}")


def _web_server(path: str) -> str:
    """Which web server has this site. .htaccess only means something to Apache."""
    p = Path(path).resolve()
    for name in ("nginxsites", "caddysites"):
        try:
            mod = __import__(f"{__package__}.{name}", fromlist=[name])
            for s in mod.list_sites(probe=False):
                root = s.get("docroot")
                if root and (p == Path(root).resolve() or Path(root).resolve() in p.parents):
                    return name.replace("sites", "")
        except Exception:  # noqa: BLE001  that server isn't set up here
            continue
    return "apache"


def _xmlrpc_blocked(path: str) -> bool:
    if (Path(path) / "wp-content" / "mu-plugins" / MU_HARDEN).exists():
        return True
    ht = Path(path) / ".htaccess"
    return ht.exists() and "aurora-block-xmlrpc" in ht.read_text(errors="replace") and _web_server(path) == "apache"


def wp(path: str, *args: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run `wp <args>` in the site, as the site's file owner."""
    p = Path(path)
    if not (p / "wp-config.php").exists() and not (p.parent / "wp-config.php").exists():
        raise WPError("Not a WordPress folder")
    if not cli_ready():
        install_cli()
    return _run(["runuser", "-u", _site_user(p), "--", _php(), "-d", "memory_limit=512M", str(PHAR), f"--path={p}", "--skip-themes", "--no-color", *args], timeout)


def _php() -> str:
    """The PHP the websites run on (Apache's), not whatever `php` points to — they can differ, and only
    the web one is sure to have the MySQL extension WordPress needs."""
    from . import isolate
    ver = isolate.php_version()
    return f"php{ver}" if ver and shutil.which(f"php{ver}", path=PATH) else "php"


def _json(r) -> list | dict:
    try:
        return json.loads(r.stdout or "[]")
    except ValueError:
        return []


def sites() -> list[dict]:
    from . import apps
    out = []
    for it in apps.installed():
        if it.get("app") == "wordpress" and it.get("exists"):
            out.append({"path": it["path"], "url": it.get("url"), "version": it.get("version"), "admin_url": it.get("admin_url")})
    return out


def _path_ok(path: str) -> str:
    p = str(Path(path).resolve())
    if not any(p == s["path"] or p == str(Path(s["path"]).resolve()) for s in sites()):
        raise WPError("That isn't a WordPress site on this server")
    return p


def details(path: str) -> dict:
    path = _path_ok(path)
    core = _json(wp(path, "core", "check-update", "--format=json"))
    pr = wp(path, "plugin", "list", "--fields=name,title,status,version,update,update_version,auto_update", "--format=json")
    plugins = _json(pr)
    db_error = _db_error(pr)
    themes = _json(wp(path, "theme", "list", "--fields=name,title,status,version,update,update_version,auto_update", "--format=json"))
    ver = wp(path, "core", "version").stdout.strip()
    url = wp(path, "option", "get", "siteurl").stdout.strip()
    cfg = Path(path) / "wp-config.php"
    txt = cfg.read_text(errors="replace") if cfg.exists() else ""
    hard = {
        "file_edit_off": bool(re.search(r"define\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true", txt)),
        "xmlrpc_blocked": _xmlrpc_blocked(path),
        "config_private": cfg.exists() and (cfg.stat().st_mode & 0o007) == 0,
        "debug_off": not re.search(r"define\(\s*['\"]WP_DEBUG['\"]\s*,\s*true", txt),
    }
    staging = _staging_public(path)
    return {"path": path, "url": url, "version": ver, "core_updates": core if isinstance(core, list) else [],
            "plugins": plugins, "themes": themes, "hardening": hard, "staging": staging,
            "maintenance": (Path(path) / ".maintenance").exists(), "db_error": db_error}


def _db_error(r) -> str:
    """WP-CLI's own words when the site can't reach its database ('' when fine)."""
    if r.returncode == 0:
        return ""
    err = (r.stderr or r.stdout or "").strip()
    if "database" in err.lower():
        return "This site can't reach its database (" + err.replace("Error: ", "").splitlines()[0][:160] + ")"
    return ""


def update(path: str, what: str = "all", names: list[str] | None = None) -> jobs.Job:
    path = _path_ok(path)
    if what not in UPDATE_WHAT:
        raise WPError("Unknown kind of update")
    for n in names or []:
        if not isinstance(n, str) or not _SLUG.fullmatch(n):
            raise WPError(f"“{str(n)[:60]}” isn't a plugin or theme name")

    def fn(log):
        steps = []
        if what in ("all", "core"):
            steps.append(("WordPress itself", ["core", "update"]))
            steps.append(("database", ["core", "update-db"]))
        if what in ("all", "plugins"):
            steps.append(("plugins", ["plugin", "update", *(names or ["--all"])]))
        if what in ("all", "themes"):
            steps.append(("themes", ["theme", "update", *(names or ["--all"])]))
        if what == "translations" or what == "all":
            steps.append(("translations", ["language", "core", "update"]))
        failed = []
        for i, (label, args) in enumerate(steps):
            log.progress(5 + 90 * i / len(steps), f"Updating {label}")
            r = wp(path, *args, timeout=900)
            for line in (r.stdout + r.stderr).strip().splitlines()[-15:]:
                log(line)
            if r.returncode != 0 and "already" not in (r.stdout + r.stderr).lower():
                if _db_error(r):
                    raise WPError(_db_error(r))
                failed.append(label)
        if failed:
            raise WPError("Couldn't update: " + ", ".join(failed) + " (see above)")
        log.progress(100, "Up to date")
        log("✓ Done")
        return {"ok": True}
    return jobs.launch_fn(f"WordPress updates ({Path(path).name})", fn, meta={"wp": path})


def auto_updates(path: str, on: bool) -> dict:
    path = _path_ok(path)
    act = "enable" if on else "disable"
    r1 = wp(path, "plugin", "auto-updates", act, "--all")
    r2 = wp(path, "theme", "auto-updates", act, "--all")
    for r in (r1, r2):
        if r.returncode != 0 and "already" not in (r.stdout + r.stderr).lower():
            raise WPError(_db_error(r) or (r.stderr or r.stdout).strip().replace("Error: ", "")[:200] or "WP-CLI failed")
    # minor + major core releases
    wp(path, "config", "set", "WP_AUTO_UPDATE_CORE", "true" if on else "minor", "--raw" if on else "--type=constant")
    return {"ok": True}


def scan(path: str) -> jobs.Job:
    """Changed WordPress/plugin files (against wordpress.org checksums) + ClamAV."""
    path = _path_ok(path)

    def fn(log):
        problems = 0
        log.progress(5, "Checking WordPress files against wordpress.org")
        r = wp(path, "core", "verify-checksums", timeout=600)
        out = (r.stdout + r.stderr).strip()
        for line in out.splitlines()[-40:]:
            log(line)
        if r.returncode != 0:
            problems += 1
        log.progress(40, "Checking plugin files")
        r = wp(path, "plugin", "verify-checksums", "--all", timeout=900)
        for line in (r.stdout + r.stderr).strip().splitlines()[-60:]:
            log(line)
        if r.returncode != 0:
            problems += 1
        # PHP files where they never belong
        up = Path(path) / "wp-content" / "uploads"
        if up.exists():
            php = [str(p) for p in up.rglob("*.php")][:30]
            if php:
                problems += 1
                log(f"! {len(php)} PHP file(s) inside uploads — a classic sign of a backdoor:")
                for p in php:
                    log(f"    {p}")
        if shutil.which("clamscan", path=PATH):
            log.progress(65, "Scanning for malware (ClamAV)")
            r = _run(["clamscan", "-r", "-i", "--no-summary", path], 3600)
            hits = [l for l in r.stdout.splitlines() if l.endswith("FOUND")]
            for l in hits[:50]:
                log(f"! {l}")
            problems += len(hits)
        log.progress(100, "Clean" if not problems else "Needs a look")
        log("✓ Nothing suspicious found" if not problems else f"! {problems} finding(s) above — reinstall changed core files with “Update”, delete unknown PHP files")
        return {"ok": True, "problems": problems}
    return jobs.launch_fn(f"WordPress scan ({Path(path).name})", fn, meta={"wp": path})


def harden(path: str) -> dict:
    path = _path_ok(path)
    done = []
    wp(path, "config", "set", "DISALLOW_FILE_EDIT", "true", "--raw", "--type=constant")
    done.append("Theme/plugin file editor in wp-admin switched off")
    wp(path, "config", "set", "WP_DEBUG", "false", "--raw", "--type=constant")
    mu = Path(path) / "wp-content" / "mu-plugins"
    _as_owner(path, "mkdir", "-p", str(mu))
    _owner_write(path, mu / MU_HARDEN, HARDEN_PHP)
    done.append("xmlrpc.php (password-guessing target) blocked")
    if _web_server(path) == "apache":
        ht = Path(path) / ".htaccess"
        if "aurora-block-xmlrpc" not in (ht.read_text(errors="replace") if ht.exists() else ""):
            block = ("\n# BEGIN aurora-block-xmlrpc (AuroraPanel WordPress Toolkit)\n<Files xmlrpc.php>\n    Require all denied\n</Files>\n"
                     "<FilesMatch \"^(wp-config\\.php|readme\\.html|license\\.txt)$\">\n    Require all denied\n</FilesMatch>\n# END aurora-block-xmlrpc\n")
            _owner_write(path, ht, block, append=True)
            done.append("readme.html and license.txt blocked")
    else:   # Nginx and Caddy don't read .htaccess. WordPress updates bring these two back, Harden again after one.
        _as_owner(path, "rm", "-f", str(Path(path) / "readme.html"), str(Path(path) / "license.txt"))
        done.append("readme.html and license.txt removed (a WordPress update brings them back, Harden again after one)")
    cfg = Path(path) / "wp-config.php"
    if cfg.exists() and _as_owner(path, "chmod", "640", str(cfg)).returncode == 0:
        done.append("wp-config.php readable only by the site")
    return {"ok": True, "done": done}


def maintenance(path: str, on: bool) -> dict:
    path = _path_ok(path)
    r = wp(path, "maintenance-mode", "activate" if on else "deactivate")
    return {"ok": r.returncode == 0 or "already" in r.stdout.lower()}


# ------------------------------------------------------------------ staging
def _db_config(path: str) -> dict:
    """DB_NAME etc. straight from wp-config.php (no PHP needed)."""
    txt = (Path(path) / "wp-config.php").read_text(errors="replace")
    out = {}
    for k in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"):
        m = re.search(rf"define\(\s*(['\"]){k}\1\s*,\s*(['\"])((?:(?!\2)[^\\]|\\.)*)\2\s*\)", txt)
        out[k] = re.sub(r"\\(.)", r"\1", m.group(3)) if m else ""
    m = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]*)['\"]", txt)
    out["table_prefix"] = m.group(1) if m else "wp_"
    return out


def _staging_dir(path: str) -> Path:
    return Path(path) / "aurora-staging"


def _state_file(path: str) -> Path:
    return STAGING_STATE / (hashlib.sha256(str(path).encode()).hexdigest()[:32] + ".json")


def _staging_info(path: str) -> dict | None:
    d = _staging_dir(path)
    if not d.is_dir():
        return None
    for f in (_state_file(path), d / ".aurora-staging.json"):   # the second is where copies made before the gate keep theirs
        try:
            return json.loads(f.read_text())
        except (OSError, ValueError):
            continue
    return None


def _staging_public(path: str) -> dict | None:
    info = _staging_info(path)
    if not info:
        return None
    key = info.get("key")
    out = {"url": info.get("url"), "created": info.get("created"), "protected": bool(key)}
    if key:
        out["access_url"] = f"{info['url']}?aurora_staging_key={key}"
    return out


def _save_state(path: str, info: dict) -> None:
    STAGING_STATE.mkdir(parents=True, exist_ok=True)
    os.chmod(STAGING_STATE, 0o700)
    f = _state_file(path)
    f.unlink(missing_ok=True)
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(json.dumps(info))


def _safe_write(target: Path, text: str, mode: int = 0o644) -> None:
    """A new file, as root, in a folder the site can write to: whatever stood at that name is gone first, link or not."""
    try:
        target.unlink()
    except FileNotFoundError:
        pass
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(fd, "w") as out:
        out.write(text)


def _php_str(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _gate_php(key: str, url: str) -> str:
    """Every page, login and API call of the copy loads wp-config.php, so this one check covers them all on any web
    server. The copy has the live site's admin accounts: without the key nobody gets as far as its login page."""
    sha = hashlib.sha256(key.encode()).hexdigest()
    cookie_path = urlparse(url).path.rstrip("/") + "/"
    return f"""<?php
// AuroraPanel WordPress Toolkit: this staging copy opens only with the link from the panel.
if (PHP_SAPI !== 'cli') {{
    $aurora_given = $_GET['aurora_staging_key'] ?? null;
    if (is_string($aurora_given) && hash_equals('{sha}', hash('sha256', $aurora_given))) {{
        setcookie('aurora_staging', $aurora_given, ['path' => {_php_str(cookie_path)}, 'httponly' => true, 'samesite' => 'Lax',
            'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off']);
        header('Cache-Control: no-store');
        header('Location: ' . {_php_str(cookie_path)});
        exit;
    }}
    $aurora_cookie = $_COOKIE['aurora_staging'] ?? null;
    if (!is_string($aurora_cookie) || !hash_equals('{sha}', hash('sha256', $aurora_cookie))) {{
        http_response_code(403);
        header('Cache-Control: no-store');
        header('X-Robots-Tag: noindex, nofollow');
        header('Content-Type: text/plain; charset=utf-8');
        echo "This is a private staging copy. Open it from the panel: WordPress Toolkit.\\n";
        exit;
    }}
    header('X-Robots-Tag: noindex, nofollow');
}}
"""


def _install_gate(dst: Path, key: str, url: str) -> None:
    cfg = dst / "wp-config.php"
    if cfg.is_symlink() or not cfg.is_file():
        raise WPError("The copy's wp-config.php isn't a plain file, so it can't be locked")
    _safe_write(dst / GATE, _gate_php(key, url))
    txt = cfg.read_text(errors="replace")
    if GATE not in txt:
        m = re.match(r"\s*<\?php\b", txt)
        if not m:
            raise WPError("The copy's wp-config.php doesn't start with <?php, so it can't be locked")
        txt = txt[:m.end()] + f"\nrequire __DIR__ . '/{GATE}';\n" + txt[m.end():]
        mode = cfg.lstat().st_mode & 0o777
        _safe_write(cfg, txt, mode)


def _point_rewrites_at_copy(dst: Path, url: str) -> None:
    """The copied .htaccess still sends pretty URLs to the live site's index.php: the copy's pages would be the live ones."""
    ht = dst / ".htaccess"
    if ht.is_symlink() or not ht.is_file():
        return
    copy = urlparse(url).path.rstrip("/") + "/"
    live = copy[: -len("aurora-staging/")]
    txt = ht.read_text(errors="replace")
    new = re.sub(rf"(?m)^(\s*RewriteBase\s+){re.escape(live)}\s*$", lambda m: m.group(1) + copy, txt)
    new = re.sub(rf"(?m)^(\s*RewriteRule\s+\.\s+){re.escape(live)}index\.php(.*)$", lambda m: m.group(1) + copy + "index.php" + m.group(2), new)
    if new != txt:
        _safe_write(ht, new)


def _chown_like(src: Path, dst: Path) -> None:
    try:
        st = (src / "wp-config.php").lstat()
        _run(["chown", "-R", f"{st.st_uid}:{st.st_gid}", str(dst)], 1800)
    except OSError:
        pass


def _mysql(sql: str) -> None:
    r = _run(["mysql"], 120, input=sql)   # on stdin: a command line with a password in it shows up in ps
    if r.returncode != 0:
        raise WPError(r.stderr.strip()[-300:] or "mysql failed")


def make_staging(path: str) -> jobs.Job:
    """A private copy at <site>/aurora-staging/ with its own database, locked by a key — try updates and changes there first."""
    path = _path_ok(path)
    if _staging_info(path):
        raise WPError("This site already has a staging copy — delete it first")

    def fn(log):
        try:
            return _make(log)
        except Exception:
            # never leave half a copy (or its database) behind
            shutil.rmtree(_staging_dir(path), ignore_errors=True)
            _state_file(path).unlink(missing_ok=True)
            for db in created:
                _run(["mysql"], 120, input=f"DROP DATABASE IF EXISTS `{db}`; DROP USER IF EXISTS '{db}'@'localhost'")
            raise

    created: list[str] = []

    def _make(log):
        src = Path(path)
        dst = _staging_dir(path)
        cfg = _db_config(path)
        url = wp(path, "option", "get", "siteurl").stdout.strip().rstrip("/")
        if not cfg["DB_NAME"]:
            raise WPError("Couldn't read the database settings from wp-config.php")
        if not _DB_NAME.fullmatch(cfg["DB_NAME"]):   # the site can write that file, and this goes on root's mysqldump command line
            raise WPError("The database name in wp-config.php has characters a staging copy can't use")
        sdb = re.sub(r"[^A-Za-z0-9_]", "_", cfg["DB_NAME"])[:56] + "_stg"
        spass = secrets.token_urlsafe(18)
        key = secrets.token_urlsafe(24)
        surl = f"{url}/aurora-staging"
        log.progress(5, "Copying files")
        dst.mkdir(exist_ok=False)
        if shutil.which("rsync", path=PATH):
            r = _run(["rsync", "-a", "--exclude=aurora-staging/", "--exclude=wp-content/cache/", f"{src}/", f"{dst}/"], 3600)
            if r.returncode != 0:
                raise WPError("Copying files failed: " + r.stderr[-300:])
        else:
            for item in src.iterdir():
                if item.name == "aurora-staging":
                    continue
                if item.is_dir():
                    shutil.copytree(item, dst / item.name, symlinks=True)
                else:
                    shutil.copy2(item, dst / item.name)
        # Locked before anything else happens: from here on the copy is reachable at its address.
        _install_gate(dst, key, surl + "/")
        _point_rewrites_at_copy(dst, surl + "/")
        _chown_like(src, dst)
        log.progress(45, "Copying the database")
        _mysql(f"CREATE DATABASE `{sdb}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        created.append(sdb)
        _mysql(f"CREATE USER '{sdb}'@'localhost' IDENTIFIED BY '{spass}'")
        _mysql(f"GRANT ALL PRIVILEGES ON `{sdb}`.* TO '{sdb}'@'localhost'")
        p1 = subprocess.Popen(["mysqldump", "--single-transaction", "--quick", "--", cfg["DB_NAME"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": PATH})
        r2 = subprocess.run(["mysql", sdb], stdin=p1.stdout, capture_output=True, env={"PATH": PATH})
        p1.stdout.close()
        err1 = p1.stderr.read().decode(errors="replace")
        if p1.wait() != 0 or r2.returncode != 0:
            raise WPError("Copying the database failed: " + (err1 or r2.stderr.decode(errors="replace"))[-300:])
        log.progress(70, "Pointing the copy at its own database and address")
        for k, v in (("DB_NAME", sdb), ("DB_USER", sdb), ("DB_PASSWORD", spass)):
            r = wp(str(dst), "config", "set", k, v, "--type=constant")
            if r.returncode != 0:
                raise WPError(f"Couldn't update the copy's wp-config.php: {r.stderr[-200:]}")
        wp(str(dst), "search-replace", url, surl, "--all-tables-with-prefix", "--skip-columns=guid", "--quiet", timeout=1800)
        wp(str(dst), "option", "update", "blog_public", "0")  # keep search engines off the copy
        wp(str(dst), "config", "shuffle-salts")               # a login cookie from the live site means nothing here
        _save_state(path, {"url": surl + "/", "db": sdb, "created": int(time.time()), "key": key})
        _chown_like(src, dst)
        log.progress(100, "Staging copy ready")
        log(f"✓ Staging copy: {surl}/ (locked: open it with the link in WordPress Toolkit, then log in with your usual admin account)")
        return {"ok": True, "url": surl + "/"}
    return jobs.launch_fn(f"WordPress staging ({Path(path).name})", fn, meta={"wp": path})


def protect_staging(path: str) -> dict:
    """Lock a copy made before staging copies came with a key."""
    path = _path_ok(path)
    info = _staging_info(path)
    if not info:
        raise WPError("No staging copy")
    if info.get("key"):
        return {"ok": True}
    key = secrets.token_urlsafe(24)
    dst = _staging_dir(path)
    _install_gate(dst, key, info["url"])
    _point_rewrites_at_copy(dst, info["url"])
    _chown_like(Path(path), dst)
    wp(str(dst), "config", "shuffle-salts")
    _save_state(path, {**info, "key": key})
    (dst / ".aurora-staging.json").unlink(missing_ok=True)
    return {"ok": True}


def delete_staging(path: str) -> dict:
    path = _path_ok(path)
    info = _staging_info(path)
    if not info:
        raise WPError("No staging copy")
    db = info["db"]
    if not re.fullmatch(r"[A-Za-z0-9_]+_stg", db):
        raise WPError("Unexpected staging database name — not deleting it")
    _mysql(f"DROP DATABASE IF EXISTS `{db}`")
    _mysql(f"DROP USER IF EXISTS '{db}'@'localhost'")
    shutil.rmtree(_staging_dir(path), ignore_errors=True)
    _state_file(path).unlink(missing_ok=True)
    return {"ok": True}
