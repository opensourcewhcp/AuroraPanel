"""Apache's plain-http port, and the port check that runs before anything that needs Apache is installed.

Apache serves every site in this panel, so its http port is one setting (default 80), not a per-tool
option. Changing it rewrites `Listen` in ports.conf and the `*:80` of every site conf, opens the port
in the firewall and restarts Apache; if Apache rejects the result everything is put back.

The check exists because of a real report: another web server (hiawatha) already held port 80, Apache
was pulled in as a dependency of phpPgAdmin and could never start, and the panel still said "ready".
Now the install stops first and offers a choice: stop the other server, or run Apache on another port.
"""
from __future__ import annotations

import platform
import re
import shutil
import subprocess
from pathlib import Path

from . import config
from . import problems

IS_LINUX = platform.system() == "Linux"
DEFAULT = 80
PORTS_CONF = Path("/etc/apache2/ports.conf")
SITES_AVAIL = Path("/etc/apache2/sites-available")
CANDIDATES = (8081, 8080, 8000, 8880, 9080)


class PortError(RuntimeError):
    pass


class PortConflict(RuntimeError):
    """Another server holds Apache's http port; the client must choose what to do."""

    def __init__(self, msg: str, other: str, port: int, suggested: int):
        super().__init__(msg)
        self.other, self.port, self.suggested = other, port, suggested

    def payload(self) -> dict:
        return {"other": self.other, "port": self.port, "suggested": self.suggested}


def get_port() -> int:
    try:
        p = int(config.load_config().get("apache_http_port") or DEFAULT)
    except (TypeError, ValueError):
        return DEFAULT
    return p if 1 <= p <= 65535 else DEFAULT


def _validate(port) -> int:
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise PortError("Enter a port number")
    if not 1 <= p <= 65535:
        raise PortError("The port must be between 1 and 65535")
    if p == 443:
        raise PortError("443 is the HTTPS port; pick another one for plain http")
    if p == 8088:
        raise PortError("8088 is this panel's own port")
    return p


def who_holds(port: int) -> str | None:
    """The process listening on that port when it isn't Apache (asked from the kernel via ss), else None."""
    if not IS_LINUX or not shutil.which("ss"):
        return None
    try:
        out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError) as quiet_exc:
        problems.quiet(quiet_exc)
        return None
    for line in out.splitlines():
        if re.search(rf":{port}\s", line):
            m = re.search(r'users:\(\("([^"]+)"', line)
            if m and m.group(1) != "apache2":
                return m.group(1)
    return None


def apache_active() -> bool:
    if not IS_LINUX:
        return False
    return subprocess.run(["systemctl", "is-active", "--quiet", "apache2"], capture_output=True).returncode == 0


def suggest(port: int) -> int:
    for c in CANDIDATES:
        if c != port and not who_holds(c):
            return c
    return CANDIDATES[0]


def conflict() -> dict | None:
    """{"other", "port", "suggested"} when Apache isn't serving and another server holds its http port, else None."""
    port = get_port()
    if apache_active():
        return None
    other = who_holds(port)
    if not other:
        return None
    return {"other": other, "port": port, "suggested": suggest(port)}


def check_before_install(tool: str) -> None:
    """Raise PortConflict instead of letting an install land in a state where Apache can never start."""
    c = conflict()
    if c:
        raise PortConflict(f"{c['other']} is on port {c['port']}, and {tool} needs Apache there. Stop {c['other']} and give the "
                           f"port to Apache, or run Apache on another port (for example {c['suggested']}).",
                           c["other"], c["port"], c["suggested"])


def stop_other() -> dict:
    """Stop and disable the server holding Apache's port so Apache can take it. Catalogued servers are
    stopped by their unit; anything else by the process name, which is the unit name for the usual servers."""
    port = get_port()
    other = who_holds(port)
    if not other:
        return {"ok": True, "stopped": None}
    unit = other
    try:
        from . import sysapps
        for key, app in sysapps.CATALOG.items():
            if app.get("group") == "web" and (key == other or app.get("service") == other or other in app.get("procs", ())):
                unit = app["service"]
                break
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    subprocess.run(["systemctl", "disable", "--now", unit], capture_output=True, text=True, timeout=60)
    if who_holds(port):
        raise PortError(f"{other} is still on port {port}. Stop it by hand (systemctl stop {unit}) and try again.")
    return {"ok": True, "stopped": unit}


def _rewrite(text: str, path: Path, old: int, new: int) -> str:
    if path.name == "ports.conf":
        # Horizontal whitespace only: \s would swallow the newline and eat the blank line that follows.
        return re.sub(rf"(?m)^([ \t]*Listen[ \t]+(?:0\.0\.0\.0:|\[::\]:)?){old}[ \t]*$", rf"\g<1>{new}", text)
    return re.sub(rf"(?i)(<VirtualHost\s+[^>\s]*):{old}(\s*>)", rf"\g<1>:{new}\g<2>", text)


def _files() -> list[Path]:
    out = [PORTS_CONF] if PORTS_CONF.exists() else []
    if SITES_AVAIL.is_dir():
        out += sorted(SITES_AVAIL.glob("*.conf"))
    return out


def set_port(port, restart: bool = True) -> dict:
    """Move Apache's plain-http port. Rewrites ports.conf and every site conf, checks the config, opens
    the firewall, restarts Apache, and puts everything back if Apache rejects it."""
    new = _validate(port)
    old = get_port()
    if new != old:
        holder = who_holds(new)
        if holder:
            raise PortError(f"Port {new} is already used by {holder}")
    backups: dict[Path, str] = {}
    changed: list[str] = []
    try:
        if IS_LINUX:
            for f in _files():
                txt = f.read_text(errors="replace")
                backups[f] = txt
                t2 = _rewrite(txt, f, old, new) if new != old else txt
                if t2 != txt:
                    f.write_text(t2)
                    changed.append(str(f))
            if changed and shutil.which("apache2ctl"):
                t = subprocess.run(["apache2ctl", "configtest"], capture_output=True, text=True, timeout=60)
                if t.returncode != 0:
                    raise PortError("Apache rejected the new port: " + (t.stderr or t.stdout).strip()[-300:])
        cfg = config.load_config()
        cfg["apache_http_port"] = new
        config.save_config(cfg)
        if IS_LINUX and new != DEFAULT:
            try:
                from . import firewall
                firewall.open_ports(f"{new}/tcp")
            except Exception as quiet_exc:
                problems.quiet(quiet_exc)
        if IS_LINUX and restart and changed:
            r = subprocess.run(["systemctl", "restart", "apache2"], capture_output=True, text=True, timeout=90)
            if r.returncode != 0:
                raise PortError("Apache didn't start on the new port: " + (r.stderr or r.stdout).strip()[-300:])
        return {"ok": True, "port": new, "changed": changed}
    except Exception:
        for f, txt in backups.items():
            try:
                f.write_text(txt)
            except OSError:
                pass
        cfg = config.load_config()
        cfg["apache_http_port"] = old
        config.save_config(cfg)
        if IS_LINUX and changed:
            subprocess.run(["systemctl", "restart", "apache2"], capture_output=True, text=True, timeout=90)
        raise


def status() -> dict:
    return {"port": get_port(), "default": DEFAULT, "apache": apache_active(), "conflict": conflict()}
