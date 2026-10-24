"""Per-site isolation — every website's PHP runs as its own Linux user, in its own PHP-FPM pool.

Without it all sites share Apache's PHP module as www-data: one hacked WordPress can read every other
site's files and database passwords. Isolated, site A's PHP runs as `site_a`, may only open files
inside its own folder (open_basedir), has its own temp/session folders, and its folder is closed to
every other site (mode 750, group site_a; Apache's www-data is in the group to serve static files).

Pools use pm = ondemand: a site that gets no visits uses no memory — right for a Raspberry Pi.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import jobs

try:
    import pwd  # Linux only (the panel runs on Linux; tests also run on Windows)
except ImportError:  # pragma: no cover
    pwd = None

STATE = Path("/var/lib/aurora/isolation.json")
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SESS_BASE = Path("/var/lib/php/aurora-sessions")
TMP_BASE = Path("/var/lib/php/aurora-tmp")


class IsolateError(RuntimeError):
    pass


# server_name -> True while hosting.py takes one of an account's sites down (only then may it be un-isolated)
_removing_account: dict[str, bool] = {}


def _run(argv, timeout=120):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={**os.environ, "PATH": PATH})
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def _load() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {"sites": {}}


def _save(d: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(d, indent=1))


def php_version() -> str:
    """The PHP version Apache uses today (mod_php), else the newest installed."""
    mods = sorted(glob.glob("/etc/apache2/mods-enabled/php*.load"))
    if mods:
        m = re.search(r"php(\d+\.\d+)", mods[-1])
        if m:
            return m.group(1)
    vers = sorted((Path(p).name for p in glob.glob("/etc/php/*") if re.fullmatch(r"\d+\.\d+", Path(p).name)), key=lambda v: tuple(map(int, v.split("."))))
    return vers[-1] if vers else ""


def fpm_ready(ver: str) -> bool:
    return bool(ver) and Path(f"/etc/php/{ver}/fpm/pool.d").is_dir() and shutil.which(f"php-fpm{ver}", path=PATH) is not None


def _names(server_name: str) -> tuple[str, str]:
    """(linux user, pool name) — user names max 32 chars."""
    slug = re.sub(r"[^a-z0-9]+", "-", server_name.lower()).strip("-")
    user = ("site_" + slug.replace("-", "_"))[:32].rstrip("_")
    return user, ("aurora-" + slug)[:48]


def _pool_conf(ver: str, pool: str, user: str, docroot: str, limits: dict | None = None, basedir: str = "") -> str:
    """limits (a hosting plan): php_workers = simultaneous PHP requests, php_memory_mb per request.
    basedir: what PHP may open — the site's folder, or a hosting account's whole home."""
    sess, tmp = SESS_BASE / pool, TMP_BASE / pool
    lim = limits or {}
    workers = int(lim.get("php_workers") or 8)
    mem = int(lim.get("php_memory_mb") or 0)
    return f"""; Written by AuroraPanel (Security → Site Isolation). Changes here are overwritten.
[{pool}]
user = {user}
group = {user}
listen = /run/php/{pool}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = {workers}
pm.process_idle_timeout = 30s
pm.max_requests = 500
request_terminate_timeout = 300
php_admin_value[open_basedir] = {(basedir or docroot).rstrip("/")}/:{tmp}/:{sess}/:/usr/share/php/:/usr/share/pear/:/dev/urandom
php_admin_value[upload_tmp_dir] = {tmp}
php_admin_value[sys_temp_dir] = {tmp}
php_admin_value[session.save_path] = {sess}
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec
php_admin_flag[allow_url_include] = off
php_admin_value[pcre.jit] = 0
catch_workers_output = yes
""" + (f"php_admin_value[memory_limit] = {mem}M\n" if mem else "")


def status() -> dict:
    from . import sites
    ver = php_version()
    st = _load()["sites"]
    out = []
    try:
        listing = sites.list_sites()["sites"]
    except Exception:
        listing = []
    for s in listing:
        if s.get("system") or not s.get("managed"):
            continue
        info = st.get(s["server_name"], {})
        user, pool = _names(s["server_name"])
        on = bool(info.get("on"))
        rss = 0
        if on:
            try:
                import psutil
                rss = sum(p.info["memory_info"].rss for p in psutil.process_iter(["username", "memory_info"]) if p.info.get("username") == info.get("user") and p.info.get("memory_info"))
            except Exception:
                pass
        out.append({"site": s["server_name"], "docroot": s["docroot"], "on": on, "user": info.get("user", user), "pool": info.get("pool", pool),
                    "socket": f"/run/php/{pool}.sock", "socket_ok": on and Path(f"/run/php/{info.get('pool', pool)}.sock").exists(),
                    "ram": rss, "since": info.get("since")})
    return {"php": ver, "fpm": fpm_ready(ver), "sites": out,
            "mod_php": any(Path(p).exists() for p in glob.glob("/etc/apache2/mods-enabled/php*.load"))}


def _prepare(ver: str, log=print) -> None:
    """php-fpm + Apache's FastCGI proxy, without touching mod_php (non-isolated sites keep using it)."""
    if not fpm_ready(ver):
        if not hasattr(log, "apt"):
            raise IsolateError(f"php{ver}-fpm isn't installed")
        rc = log.apt(["install", f"php{ver}-fpm"], (5, 60))
        if rc != 0 or not fpm_ready(ver):
            raise IsolateError(f"Couldn't install php{ver}-fpm")
    # fpm's own default pool (www) isn't needed; keep it but small
    _run(["a2enmod", "-q", "proxy_fcgi", "setenvif"])
    _run(["systemctl", "enable", "--now", f"php{ver}-fpm"])


def _owner_for(docroot: Path) -> str:
    """Who keeps owning the files: the home user for folders in /home, else the site user."""
    m = re.match(r"^/home/([^/]+)/", str(docroot) + "/")
    if m:
        try:
            pwd.getpwnam(m.group(1))
            return m.group(1)
        except KeyError:
            pass
    return ""


def enable(server_name: str, log=print, run_as: str = "", limits: dict | None = None, basedir: str = "") -> dict:
    """run_as: a hosting account's Linux user — its sites' PHP runs as the account itself (like
    cPanel's suEXEC), so the account owns its files and can't read anyone else's."""
    from . import sites
    ver = php_version()
    if not ver:
        raise IsolateError("PHP isn't installed")
    site = sites.get_site(server_name)["settings"]
    if not site.get("_managed", True):
        raise IsolateError("Let AuroraPanel manage this site first (open it in Domains and click Save)")
    docroot = Path(site["docroot"]).resolve()
    if not docroot.is_dir() or str(docroot) in ("/", "/var", "/var/www", "/home", "/root", "/etc", "/usr"):
        raise IsolateError(f"{docroot} can't be isolated — give the site its own folder first")
    _prepare(ver, log)
    user, pool = _names(server_name)
    if run_as:
        pwd.getpwnam(run_as)  # the account must exist
        user = run_as
    # 1. the site's own user (no login), Apache allowed to read its files through the group
    try:
        pwd.getpwnam(user)
    except KeyError:
        r = _run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", str(docroot), "--shell", "/usr/sbin/nologin",
                  "--comment", f"AuroraPanel site {server_name}", user])
        if r.returncode != 0:
            raise IsolateError(r.stderr.strip() or "useradd failed")
    _run(["usermod", "-aG", user, "www-data"])
    home_owner = run_as or _owner_for(docroot)
    if home_owner and home_owner != user:
        _run(["usermod", "-aG", user, home_owner])
    log(f"• PHP for {server_name} will run as “{user}”")
    # 2. ownership: owner can write, the site's group (its PHP + Apache) can read/write, nobody else gets in
    prev = {"uid": docroot.stat().st_uid, "gid": docroot.stat().st_gid, "mode": oct(docroot.stat().st_mode & 0o7777)}
    owner = home_owner or user
    _run(["chown", "-R", f"{owner}:{user}", str(docroot)], 1800)
    _run(["chmod", "-R", "u+rwX,g+rwX,o-rwx", str(docroot)], 1800)
    _run(["find", str(docroot), "-type", "d", "-exec", "chmod", "g+s", "{}", "+"], 1800)
    log("• Folder closed to other sites (750), Apache can still read it")
    for base in (SESS_BASE, TMP_BASE):
        base.mkdir(parents=True, exist_ok=True)
        os.chmod(base, 0o711)
        d = base / pool
        d.mkdir(exist_ok=True)
        shutil.chown(d, user, user)
        os.chmod(d, 0o700)
    # 3. the pool
    conf = Path(f"/etc/php/{ver}/fpm/pool.d/{pool}.conf")
    conf.write_text(_pool_conf(ver, pool, user, str(docroot), limits, basedir))
    t = _run([f"php-fpm{ver}", "-t"])
    if t.returncode != 0:
        conf.unlink(missing_ok=True)
        raise IsolateError("PHP-FPM rejected the pool: " + (t.stderr or t.stdout).strip()[-300:])
    _run(["systemctl", "reload-or-restart", f"php{ver}-fpm"])
    sock = Path(f"/run/php/{pool}.sock")
    for _ in range(20):
        if sock.exists():
            break
        import time
        time.sleep(0.25)
    log(f"• PHP-FPM pool “{pool}” running (starts workers only when visited)")
    # 4. the site's Apache config sends .php there
    s = sites.get_site(server_name)["settings"]
    s["php_pool"] = pool
    sites.save_site(server_name, {k: v for k, v in s.items() if not k.startswith("_")})
    d = _load()
    d["sites"][server_name] = {"on": True, "user": user, "pool": pool, "php": ver, "owner": owner, "prev": prev, "since": int(__import__("time").time()),
                               **({"account": run_as, "limits": limits or {}, "basedir": basedir} if run_as else {})}
    _save(d)
    log("✓ Isolated")
    return {"ok": True, "user": user, "pool": pool}


def disable(server_name: str) -> dict:
    from . import sites
    d = _load()
    info = d["sites"].get(server_name)
    if not info:
        raise IsolateError("This site isn't isolated")
    if info.get("account") and not _removing_account.get(server_name):
        # A hosting account's PHP must keep running as the account (its own user, its limits).
        raise IsolateError(f"{server_name} belongs to the hosting account “{info['account']}” — its PHP always runs as that account")
    s = sites.get_site(server_name)["settings"]
    s["php_pool"] = ""
    sites.save_site(server_name, {k: v for k, v in s.items() if not k.startswith("_")})
    conf = Path(f"/etc/php/{info.get('php', php_version())}/fpm/pool.d/{info['pool']}.conf")
    conf.unlink(missing_ok=True)
    _run(["systemctl", "reload-or-restart", f"php{info.get('php', php_version())}-fpm"])
    docroot = Path(s["docroot"])
    # files go back to Apache's user (or the home user who owned them) so mod_php can write uploads again
    owner = info.get("owner") or ""
    _run(["chown", "-R", f"{owner if owner and not owner.startswith('site_') else 'www-data'}:www-data", str(docroot)], 1800)
    _run(["find", str(docroot), "-type", "d", "-exec", "chmod", "g-s", "{}", "+"], 1800)
    _run(["chmod", "-R", "u+rwX,g-w,g+rX,o+rX", str(docroot)], 1800)
    prev = info.get("prev") or {}
    if prev.get("mode"):
        try:
            os.chmod(docroot, int(prev["mode"], 8) & 0o777)
        except (OSError, ValueError):
            pass
    # the site's own user and group are no longer needed (a hosting account's user is the account's to remove)
    if not info.get("account"):
        _run(["gpasswd", "-d", "www-data", info["user"]])
        _run(["userdel", info["user"]])
        _run(["groupdel", info["user"]])
    for base in (SESS_BASE, TMP_BASE):
        shutil.rmtree(base / info["pool"], ignore_errors=True)
    d["sites"].pop(server_name, None)
    _save(d)
    return {"ok": True}


def enable_job(server_name: str) -> jobs.Job:
    def fn(log):
        log.progress(2, f"Isolating {server_name}")
        r = enable(server_name, log)
        log.progress(100, "Done")
        return r
    return jobs.launch_fn(f"isolate {server_name}", fn, meta={"isolate": server_name})


def enable_all_job() -> jobs.Job:
    def fn(log):
        todo = [s["site"] for s in status()["sites"] if not s["on"]]
        if not todo:
            log("Every site is already isolated")
            return {"ok": True}
        for i, name in enumerate(todo):
            log.progress(5 + 90 * i / len(todo), f"Isolating {name}")
            try:
                enable(name, log)
            except Exception as e:
                log(f"! {name}: {e}")
        log.progress(100, "Done")
        return {"ok": True}
    return jobs.launch_fn("isolate every site", fn, meta={"isolate": "*"})


def apply_limits(server_name: str, limits: dict) -> None:
    """A hosting plan changed: rewrite the site's pool with the new PHP limits."""
    d = _load()
    info = d["sites"].get(server_name)
    if not info or not info.get("on"):
        return
    from . import sites
    docroot = sites.get_site(server_name)["settings"]["docroot"]
    conf = Path(f"/etc/php/{info['php']}/fpm/pool.d/{info['pool']}.conf")
    old = conf.read_text() if conf.exists() else ""
    conf.write_text(_pool_conf(info["php"], info["pool"], info["user"], docroot, limits, info.get("basedir", "")))
    if _run([f"php-fpm{info['php']}", "-t"]).returncode != 0:
        conf.write_text(old)
        raise IsolateError("PHP-FPM rejected the new limits")
    _run(["systemctl", "reload-or-restart", f"php{info['php']}-fpm"])
    info["limits"] = limits
    _save(d)


def fix_permissions(server_name: str) -> dict:
    """Re-apply ownership after files were added as root (File Manager, SFTP as root, restores)."""
    info = _load()["sites"].get(server_name)
    if not info:
        raise IsolateError("This site isn't isolated")
    from . import sites
    docroot = sites.get_site(server_name)["settings"]["docroot"]
    _run(["chown", "-R", f"{info['owner']}:{info['user']}", docroot], 1800)
    _run(["chmod", "-R", "u+rwX,g+rwX,o-rwx", docroot], 1800)
    _run(["find", docroot, "-type", "d", "-exec", "chmod", "g+s", "{}", "+"], 1800)
    return {"ok": True}


def owner_of(path: str) -> tuple[str, str] | None:
    """(owner, group) new files under path should get, when path is inside an isolated site."""
    p = str(Path(path).resolve())
    from . import sites
    for name, info in _load()["sites"].items():
        try:
            root = str(Path(sites.get_site(name)["settings"]["docroot"]).resolve())
        except Exception:
            continue
        if p == root or p.startswith(root + "/"):
            return info["owner"], info["user"]
    return None
