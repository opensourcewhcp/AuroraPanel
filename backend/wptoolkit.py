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

from . import distro
from . import jobs

try:
    import pwd  # Linux only; tests also run on Windows
except ImportError:  # pragma: no cover
    pwd = None

PHAR = Path("/usr/local/lib/aurora/wp-cli.phar")
PHAR_URL = "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
PATH = distro.PATH


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
        return pwd.getpwuid((path / "wp-config.php").stat().st_uid).pw_name
    except (OSError, KeyError):
        return "www-data"


def wp(path: str, *args: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run `wp <args>` in the site, as the site's file owner."""
    p = Path(path)
    if not (p / "wp-config.php").exists() and not (p.parent / "wp-config.php").exists():
        raise WPError("Not a WordPress folder")
    if not cli_ready():
        install_cli()
    user = _owner(p)
    if user == "root":
        user = "www-data"
    return _run(["runuser", "-u", user, "--", _php(), "-d", "memory_limit=512M", str(PHAR), f"--path={p}", "--skip-themes", "--no-color", *args], timeout)


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
        "xmlrpc_blocked": "aurora-block-xmlrpc" in ((Path(path) / ".htaccess").read_text(errors="replace") if (Path(path) / ".htaccess").exists() else ""),
        "config_private": cfg.exists() and (cfg.stat().st_mode & 0o007) == 0,
        "debug_off": not re.search(r"define\(\s*['\"]WP_DEBUG['\"]\s*,\s*true", txt),
    }
    staging = _staging_info(path)
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
    ht = Path(path) / ".htaccess"
    txt = ht.read_text(errors="replace") if ht.exists() else ""
    if "aurora-block-xmlrpc" not in txt:
        block = ("\n# BEGIN aurora-block-xmlrpc (AuroraPanel WordPress Toolkit)\n<Files xmlrpc.php>\n    Require all denied\n</Files>\n"
                 "<FilesMatch \"^(wp-config\\.php|readme\\.html|license\\.txt)$\">\n    Require all denied\n</FilesMatch>\n# END aurora-block-xmlrpc\n")
        ht.write_text(txt + block)
        try:
            st = (Path(path) / "wp-config.php").stat()
            os.chown(ht, st.st_uid, st.st_gid)
        except OSError:
            pass
        done.append("xmlrpc.php (password-guessing target) and readme/license blocked")
    cfg = Path(path) / "wp-config.php"
    if cfg.exists():
        os.chmod(cfg, 0o640)
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


def _staging_info(path: str) -> dict | None:
    d = _staging_dir(path)
    meta = d / ".aurora-staging.json"
    if not meta.exists():
        return None
    try:
        return json.loads(meta.read_text())
    except ValueError:
        return None


def _mysql(sql: str) -> None:
    r = _run(["mysql", "-e", sql], 120)
    if r.returncode != 0:
        raise WPError(r.stderr.strip()[-300:] or "mysql failed")


def make_staging(path: str) -> jobs.Job:
    """A private copy at <site>/aurora-staging/ with its own database — try updates and changes there first."""
    path = _path_ok(path)
    if _staging_info(path):
        raise WPError("This site already has a staging copy — delete it first")

    def fn(log):
        try:
            return _make(log)
        except Exception:
            # never leave half a copy (or its database) behind
            shutil.rmtree(_staging_dir(path), ignore_errors=True)
            for db in created:
                _run(["mysql", "-e", f"DROP DATABASE IF EXISTS `{db}`; DROP USER IF EXISTS '{db}'@'localhost'"], 120)
            raise

    created: list[str] = []

    def _make(log):
        src = Path(path)
        dst = _staging_dir(path)
        cfg = _db_config(path)
        url = wp(path, "option", "get", "siteurl").stdout.strip().rstrip("/")
        if not cfg["DB_NAME"]:
            raise WPError("Couldn't read the database settings from wp-config.php")
        sdb = re.sub(r"[^A-Za-z0-9_]", "_", (cfg["DB_NAME"] + "_stg"))[:60]
        spass = secrets.token_urlsafe(18)
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
        log.progress(45, "Copying the database")
        _mysql(f"CREATE DATABASE `{sdb}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        created.append(sdb)
        _mysql(f"CREATE USER '{sdb}'@'localhost' IDENTIFIED BY '{spass}'")
        _mysql(f"GRANT ALL PRIVILEGES ON `{sdb}`.* TO '{sdb}'@'localhost'")
        p1 = subprocess.Popen(["mysqldump", "--single-transaction", "--quick", cfg["DB_NAME"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": PATH})
        r2 = subprocess.run(["mysql", sdb], stdin=p1.stdout, capture_output=True, env={"PATH": PATH})
        p1.stdout.close()
        err1 = p1.stderr.read().decode(errors="replace")
        if p1.wait() != 0 or r2.returncode != 0:
            raise WPError("Copying the database failed: " + (err1 or r2.stderr.decode(errors="replace"))[-300:])
        log.progress(70, "Pointing the copy at its own database and address")
        surl = f"{url}/aurora-staging"
        for k, v in (("DB_NAME", sdb), ("DB_USER", sdb), ("DB_PASSWORD", spass)):
            r = wp(str(dst), "config", "set", k, v, "--type=constant")
            if r.returncode != 0:
                raise WPError(f"Couldn't update the copy's wp-config.php: {r.stderr[-200:]}")
        wp(str(dst), "search-replace", url, surl, "--all-tables-with-prefix", "--skip-columns=guid", "--quiet", timeout=1800)
        wp(str(dst), "option", "update", "blog_public", "0")  # keep search engines off the copy
        (dst / ".aurora-staging.json").write_text(json.dumps({"url": surl + "/", "db": sdb, "created": int(time.time())}))
        os.chmod(dst / ".aurora-staging.json", 0o600)
        try:
            st = (src / "wp-config.php").stat()
            _run(["chown", "-R", f"{st.st_uid}:{st.st_gid}", str(dst)], 1800)
        except OSError:
            pass
        log.progress(100, "Staging copy ready")
        log(f"✓ Staging copy: {surl}/ (hidden from search engines; log in with your usual admin account)")
        return {"ok": True, "url": surl + "/"}
    return jobs.launch_fn(f"WordPress staging ({Path(path).name})", fn, meta={"wp": path})


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
    return {"ok": True}
