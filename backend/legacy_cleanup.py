"""Takes a removed feature's leftovers on a server out of service, once. The names below are only what it must find.

Updates copy files over the old ones, so nothing else would stop its services or lift its firewall table.

Two things stay on purpose. Its real-IP settings (zz-ella-proxies.conf, aurora-ella-realip.conf) tell the web
server who the visitor is behind Cloudflare or another proxy: without them the logs show the proxy, and InstaBan
could ban it and cut off every visitor. And /var/lib/aurora/ella holds a server's event history, which isn't
this update's to destroy. Uninstalling the panel removes both.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from . import config, distro

DONE = Path("/var/lib/aurora/.ella-retired")
UNIT_DIR = Path("/etc/systemd/system")
UNITS = ("aurora-ella-agent.service", "aurora-ella.service")
CLI = Path("/usr/local/sbin/ella-cli")
APACHE_FILES = (Path("/etc/modsecurity/zz-ella-rules.conf"), Path("/etc/httpd/modsecurity.d/zz-ella-rules.conf"),
                Path("/etc/apache2/conf-enabled/zz-ella-tester.conf"), Path("/etc/apache2/conf-available/zz-ella-tester.conf"))
NGINX_MAIN = Path("/etc/nginx/aurora-waf/main.conf")
NGINX_RULES = Path("/etc/nginx/aurora-waf/ella.conf")
NGINX_TESTER = Path("/etc/nginx/conf.d/aurora-ella-tester.conf")
OLD_PROGRAM = ("backend/ella", "frontend/js/ella.js", "frontend/js/ella_soc.js", "docs/waf-ella.md")


def _run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=120, env={"PATH": distro.BASE_PATH, "LC_ALL": "C"})


def _remove(path: Path) -> bool:
    """A broken symlink counts as there: the web server's include would still find it."""
    if not os.path.lexists(path):
        return False
    path.unlink()
    return True


def _stop_services() -> None:
    present = [u for u in UNITS if (UNIT_DIR / u).exists()]
    for unit in present:
        _run("systemctl", "disable", "--now", unit)
        (UNIT_DIR / unit).unlink()
    if present:
        _run("systemctl", "daemon-reload")
    _remove(CLI)
    if shutil.which("nft", path=distro.BASE_PATH):
        _run("nft", "delete", "table", "inet", "aurora_ella")  # fails harmlessly when it isn't there


def _remove_apache_rules() -> bool:
    return any([_remove(p) for p in APACHE_FILES])


def _remove_nginx_rules() -> bool:
    """main.conf includes ella.conf and Nginx won't load with a missing include, so the line goes first."""
    changed = False
    if NGINX_MAIN.exists():
        text = NGINX_MAIN.read_text(encoding="utf-8")
        kept = [line for line in text.splitlines() if line.strip() != f"Include {NGINX_RULES.as_posix()}"]
        if len(kept) != len(text.splitlines()):
            NGINX_MAIN.write_text("\n".join(kept) + "\n", encoding="utf-8")
            changed = True
    return any([_remove(NGINX_RULES), _remove(NGINX_TESTER)]) or changed


def _reload(test: tuple[str, ...], unit: str, name: str) -> str:
    r = _run(*test)
    if r.returncode != 0:
        return f"{name} doesn't accept its settings: {(r.stderr or r.stdout).strip()[-300:]}"
    _run("systemctl", "reload", unit)
    return ""


def _reload_web_servers(apache: bool, nginx: bool) -> list[str]:
    problems = []
    if apache:
        if shutil.which("httpd", path=distro.BASE_PATH):
            problems.append(_reload(("httpd", "-t"), "httpd", "Apache"))
        elif shutil.which("apache2ctl", path=distro.BASE_PATH):
            problems.append(_reload(("apache2ctl", "-t"), "apache2", "Apache"))
    if nginx and shutil.which("nginx", path=distro.BASE_PATH):
        problems.append(_reload(("nginx", "-t"), "nginx", "Nginx"))
    return [p for p in problems if p]


def _remove_old_program() -> None:
    for rel in OLD_PROGRAM:
        p = config.ROOT / rel
        if p.is_dir():
            shutil.rmtree(p)
        elif p.exists():
            p.unlink()


def cleanup() -> None:
    """Safe to run at every start. Raises when a web server refuses its settings, so the panel can say so."""
    if os.name != "posix" or os.geteuid() != 0:
        return
    (config.ROOT / "backend" / "ella_retire.py").unlink(missing_ok=True)  # this file's old name; updates don't delete
    if DONE.exists():
        return
    _stop_services()
    apache, nginx = _remove_apache_rules(), _remove_nginx_rules()
    problems = _reload_web_servers(apache, nginx)
    _remove_old_program()
    DONE.parent.mkdir(parents=True, exist_ok=True)
    DONE.write_text("1.1.39\n", encoding="utf-8")
    if problems:
        raise RuntimeError("; ".join(problems))
