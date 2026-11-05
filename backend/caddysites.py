"""Websites on Caddy: one file each in /etc/caddy/Caddyfile.d, checked with `caddy validate` before Caddy reloads.

Caddy gets HTTPS certificates on its own for public domains. There is no WAF inside Caddy here: to put one in front of
it, make it listen on 127.0.0.1 and add a reverse proxy site on Nginx (see nginxwaf.py).
"""
from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import threading
import time
from pathlib import Path

from . import distro, nginxsites
from .nginxsites import NginxError as CaddyError

CADDYFILE = Path("/etc/caddy/Caddyfile")
SITES_DIR = Path("/etc/caddy/Caddyfile.d")
LOG_DIR = Path("/var/log/caddy")
PREFIX = "aurora-site-"
META = re.compile(r"(?m)^# aurora-site: (\{.*\})$")
HTTPS = ("none", "internal", "auto")
RELOAD_SETTLE = 0.6
PHP_POOL = Path("/etc/php-fpm.d/www.conf")
_lock = threading.RLock()
_run = nginxsites._run


def installed() -> bool:
    return shutil.which("caddy", path=distro.BASE_PATH) is not None


def _active(unit: str) -> bool:
    return _run(["systemctl", "is-active", unit], 15).stdout.strip() == "active"


def _conf(name: str, enabled: bool = True) -> Path:
    return SITES_DIR / f"{PREFIX}{nginxsites._slug(name)}.caddyfile{'' if enabled else '.off'}"


def clean(settings: dict) -> dict:
    """The same strict shapes as Nginx sites, plus Caddy's HTTPS choices."""
    wanted = (settings or {}).get("https") or "none"
    if wanted not in HTTPS:
        raise CaddyError("HTTPS must be off, Caddy's own certificate, or automatic")
    s = nginxsites.clean({**(settings or {}), "https": "none", "force_https": False})
    s["https"] = wanted
    if wanted == "auto" and not re.search(r"\.[a-z]{2,}$", s["server_name"]):
        raise CaddyError("Automatic HTTPS needs a public domain name")
    return s


def render(s: dict, socket: str | None) -> str:
    slug = nginxsites._slug(s["server_name"])
    names = [s["server_name"], *s["aliases"]]
    address = ", ".join(f"http://{n}" for n in names) if s["https"] == "none" else ", ".join(names)
    out = [nginxsites.HEADER.rstrip().replace("Nginx Websites", "Caddy Websites"), f"# aurora-site: {json.dumps(s, sort_keys=True)}", f"{address} {{"]
    if s["https"] == "internal":
        out.append("\ttls internal")
    out += ["\tencode gzip", f"\tlog {{\n\t\toutput file {LOG_DIR.as_posix()}/{slug}-access.log\n\t\tformat json\n\t}}"]
    if s["mode"] == "proxy":
        out.append(f"\treverse_proxy {s['proxy']}")
    else:
        out += ["\t@hidden {\n\t\tpath_regexp hidden /\\.\n\t\tnot path /.well-known/*\n\t}", "\trespond @hidden 403", f"\troot * {s['docroot']}"]
        if s["mode"] == "php":
            if not socket:
                raise CaddyError("PHP isn't running here (no PHP-FPM socket). Install PHP-FPM, or choose a static site.")
            out.append(f"\tphp_fastcgi unix/{socket}")
        out.append("\tfile_server")
    if s["custom"]:
        out += ["\t# Extra settings", *[f"\t{x}" for x in s["custom"].splitlines()]]
    out.append("}")
    return "\n".join(out) + "\n"


def validate() -> dict:
    r = _run(["caddy", "validate", "--config", str(CADDYFILE), "--adapter", "caddyfile"], 60)
    return {"ok": r.returncode == 0, "output": (r.stderr or r.stdout).strip()[-1500:]}


def _ensure_layout() -> None:
    """Caddy only reads the site folder if its main file says so. Debian's doesn't; Fedora's does."""
    SITES_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        shutil.chown(LOG_DIR, "caddy", "caddy")
    except (LookupError, OSError):
        pass
    _run(["restorecon", "-R", str(LOG_DIR)])
    text = CADDYFILE.read_text(encoding="utf-8") if CADDYFILE.exists() else ""
    new = text
    if not re.search(r"(?m)^\s*import\s+\S*Caddyfile\.d/\*", new):
        new = new.rstrip("\n") + f"\n\nimport {SITES_DIR.as_posix()}/*.caddyfile\n"
    if "skip_install_trust" not in new:
        # Caddy's own certificates would otherwise have it run sudo to add its root to this server's trust store.
        first = re.search(r"\A(\s*(?:#[^\n]*\n\s*)*)\{[ \t]*\n", new)
        new = f"{new[:first.end()]}\tskip_install_trust\n{new[first.end():]}" if first else "{\n\tskip_install_trust\n}\n\n" + new
    if new != text:
        CADDYFILE.parent.mkdir(parents=True, exist_ok=True)
        CADDYFILE.write_text(new, encoding="utf-8")


def _allow_php() -> None:
    """Let Caddy's user use the PHP socket. Fedora lists who may in its pool file; Debian uses the socket's group."""
    if PHP_POOL.exists():
        text = PHP_POOL.read_text(encoding="utf-8")
        m = re.search(r"(?m)^listen\.acl_users\s*=\s*(.*)$", text)
        if m and "caddy" not in m.group(1).split(","):
            PHP_POOL.write_text(text[:m.start(1)] + m.group(1).strip() + ",caddy" + text[m.end(1):], encoding="utf-8")
            _run(["systemctl", "restart", "php-fpm"], 60)
    else:
        _run(["usermod", "-aG", "www-data", "caddy"], 30)


def _apply(changes: dict[Path, str | None]) -> None:
    with _lock:
        before = {p: (p.read_text(encoding="utf-8") if p.exists() else None) for p in changes}

        def put(items):
            for p, text in items.items():
                if text is None:
                    p.unlink(missing_ok=True)
                else:
                    p.write_text(text, encoding="utf-8")
                    os.chmod(p, 0o644)
                    _run(["restorecon", str(p)])
        put(changes)
        check = validate()
        if not check["ok"]:
            put(before)
            raise CaddyError("Caddy rejected this, nothing changed:\n" + check["output"])
        # The check opens each site's log file, as root here: Caddy's own user has to be able to write to them after it.
        _run(["chown", "-R", "caddy:caddy", str(LOG_DIR)], 30)
        if _active("caddy"):
            r = _run(["systemctl", "reload", "caddy"], 60)
            if r.returncode != 0:
                put(before)
                _run(["systemctl", "reload", "caddy"], 60)
                raise CaddyError("Caddy wouldn't reload, nothing changed: " + (r.stderr or "")[-300:])
            time.sleep(RELOAD_SETTLE)


def _load(path: Path) -> dict | None:
    try:
        m = META.search(path.read_text(encoding="utf-8", errors="replace"))
        return json.loads(m.group(1)) if m else None
    except (OSError, ValueError):
        return None


def _probe(s: dict) -> str:
    try:
        c = http.client.HTTPConnection("127.0.0.1", 80, timeout=4)
        c.request("GET", "/", headers={"Host": s["server_name"], "User-Agent": "AuroraPanel check"})
        code = c.getresponse().status
        c.close()
        return str(code)
    except (OSError, http.client.HTTPException) as exc:
        return f"no answer ({str(exc)[:60]})"


def list_sites(probe: bool = True) -> list[dict]:
    out = []
    for p in sorted(list(SITES_DIR.glob(f"{PREFIX}*.caddyfile")) + list(SITES_DIR.glob(f"{PREFIX}*.caddyfile.off"))):
        s = _load(p)
        if s:
            on = p.suffix == ".caddyfile"
            out.append({**s, "enabled": on, "answer": _probe(s) if probe and on else None})
    return out


def _get(name: str) -> tuple[dict, bool]:
    for enabled in (True, False):
        s = _load(_conf(str(name or "").strip().lower(), enabled))
        if s:
            return s, enabled
    raise CaddyError("No such site")


def status() -> dict:
    if not installed():
        return {"installed": False, "active": False, "sites": []}
    active = _active("caddy")
    v = _run(["caddy", "version"], 10)
    return {"installed": True, "active": active, "version": v.stdout.split(" ")[0][:30], "config": validate(), "php_socket": nginxsites.php_socket(),
            "nginx_active": _active("nginx"), "apache_active": _active(nginxsites._apache_unit()), "sites": list_sites(probe=active)}


def create(settings: dict) -> dict:
    if not installed():
        raise CaddyError("Caddy isn't installed")
    s = clean(settings)
    if _conf(s["server_name"]).exists() or _conf(s["server_name"], False).exists():
        raise CaddyError("A site with that name already exists")
    clash = {n for x in list_sites(probe=False) for n in [x["server_name"], *x["aliases"]]} & {s["server_name"], *s["aliases"]}
    if clash:
        raise CaddyError(f"Another site already answers for {', '.join(sorted(clash))}")
    text = render(s, nginxsites.php_socket())
    _ensure_layout()
    nginxsites._ensure_docroot(s)
    if s["mode"] == "php":
        _allow_php()
    _apply({_conf(s["server_name"]): text})
    from . import firewall
    firewall.open_ports("80/tcp", "443/tcp")
    return {"ok": True, "site": s, "answer": _probe(s) if _active("caddy") else None}


def update(name: str, settings: dict) -> dict:
    current, enabled = _get(name)
    s = clean({**current, **(settings or {}), "server_name": current["server_name"]})
    text = render(s, nginxsites.php_socket())
    nginxsites._ensure_docroot(s)
    if s["mode"] == "php":
        _allow_php()
    _apply({_conf(s["server_name"], enabled): text})
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
    if delete_files and s["mode"] != "proxy" and root.exists() and root != nginxsites.WEB_BASE / "html" and nginxsites._DOCROOT.match(str(root)):
        nginxsites.TRASH.mkdir(parents=True, exist_ok=True)
        moved = str(nginxsites.TRASH / f"{root.name}-{int(time.time())}")
        shutil.move(str(root), moved)
    return {"ok": True, "moved_to": moved}


def control(action: str) -> dict:
    if action not in ("reload", "restart"):
        raise CaddyError("Unknown action")
    check = validate()
    if not check["ok"]:
        raise CaddyError("The configuration has an error, so Caddy was left as it is:\n" + check["output"])
    r = _run(["systemctl", action, "caddy"], 60)
    if r.returncode != 0:
        raise CaddyError((r.stderr or r.stdout).strip()[-400:] or f"{action} failed")
    time.sleep(RELOAD_SETTLE)
    return {"ok": True, "active": _active("caddy")}


def logs(name: str, lines: int = 200) -> dict:
    s, _ = _get(name)
    path = LOG_DIR / f"{nginxsites._slug(s['server_name'])}-access.log"
    try:
        with path.open("rb") as f:
            f.seek(max(0, path.stat().st_size - 512_000))
            text = f.read().decode("utf-8", "replace")
    except OSError:
        return {"path": str(path), "lines": []}
    return {"path": str(path), "lines": text.splitlines()[-max(1, min(int(lines), 2000)):]}
