"""ModSecurity — detect + enable/disable the Apache WAF module."""
from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

from . import distro
from . import jobs

IS_LINUX = platform.system() == "Linux"


class ModSecError(RuntimeError):
    pass


def _installed() -> bool:
    # module file shipped by libapache2-mod-security2
    return any(Path(p).exists() for p in
               ("/usr/lib/apache2/modules/mod_security2.so", "/etc/apache2/mods-available/security2.load"))


def status() -> dict:
    enabled = Path("/etc/apache2/mods-enabled/security2.load").exists()
    return {"supported": IS_LINUX and shutil.which("a2enmod") is not None,
            "installed": _installed(), "enabled": enabled}


def set_enabled(enabled: bool) -> dict:
    if not _installed():
        raise ModSecError("ModSecurity is not installed. Install 'libapache2-mod-security2' from Packages.")
    cmd = "a2enmod" if enabled else "a2dismod"
    if not shutil.which(cmd):
        raise ModSecError(f"{cmd} not available")
    out = subprocess.run([cmd, "security2"], capture_output=True, text=True, timeout=20)
    if out.returncode != 0:
        raise ModSecError(out.stderr.strip() or out.stdout.strip() or f"{cmd} failed")
    # Reload apache to apply.
    subprocess.run(["systemctl", "reload", "apache2"], capture_output=True, text=True, timeout=20)
    return {"ok": True, "enabled": enabled}


def install() -> jobs.Job:
    env = {"DEBIAN_FRONTEND": "noninteractive", "PATH": distro.PATH}
    return jobs.launch("install ModSecurity", ["apt-get", "-y", "install", "libapache2-mod-security2"], env=env)
