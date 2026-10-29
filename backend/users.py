"""Linux user account management.

Listing parses /etc/passwd. Mutations shell out to useradd/userdel/usermod/passwd
with validated arguments. All mutations require the panel to run as root.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess

from . import files

IS_LINUX = platform.system() == "Linux"
if IS_LINUX:
    import pwd  # Unix-only; not present on the Windows dev machine.
_NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class UserError(RuntimeError):
    pass


def _require_linux():
    if not IS_LINUX:
        raise UserError("User management is only available on Linux")


def _validate_name(name: str) -> str:
    if not _NAME_RE.match(name or ""):
        raise UserError("Invalid username")
    return name


def list_users(include_system: bool = False) -> list[dict]:
    if not IS_LINUX:
        return []
    users = []
    for p in pwd.getpwall():
        is_system = p.pw_uid < 1000 and p.pw_uid != 0
        if is_system and not include_system:
            continue
        users.append({
            "name": p.pw_name,
            "uid": p.pw_uid,
            "gid": p.pw_gid,
            "home": p.pw_dir,
            "shell": p.pw_shell,
            "gecos": p.pw_gecos,
            "is_system": is_system,
        })
    # A home inside (or equal to) another account's home belongs to that account: deleting it would
    # take the other account's files with it, so the page keeps it.
    homes = {p.pw_name: p.pw_dir for p in pwd.getpwall() if p.pw_dir and p.pw_dir not in ("/", "/nonexistent")}
    for u in users:
        h = u["home"]
        other = next((n for n, d in homes.items() if n != u["name"] and (h == d or h.startswith(d.rstrip("/") + "/"))), None)
        u["home_owner"] = other
    users.sort(key=lambda u: u["uid"])
    return users


def _home_owner(name: str, home: str) -> str | None:
    for p in pwd.getpwall():
        d = p.pw_dir
        if p.pw_name != name and d and d not in ("/", "/nonexistent") and (home == d or home.startswith(d.rstrip("/") + "/")):
            return p.pw_name
    return None


def backup_home(name: str) -> str | None:
    """The home folder as a tar.gz in the panel's backup folder, before the account goes."""
    import time
    from pathlib import Path
    from . import backups
    try:
        home = pwd.getpwnam(name).pw_dir
    except KeyError:
        raise UserError("No such user")
    if not home or not os.path.isdir(home) or home in ("/", "/nonexistent"):
        return None
    backups.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    out = backups.BACKUP_DIR / f"home-{name}-{time.strftime('%Y%m%d-%H%M%S')}.tar.gz"
    r = subprocess.run(["tar", "-czf", str(out), "-C", str(Path(home).parent), Path(home).name], capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        try:
            out.unlink()
        except OSError:
            pass
        raise UserError("Backup failed: " + (r.stderr.strip().splitlines() or ["tar failed"])[-1])
    return str(out)


def add_user(name: str, create_home: bool = True, shell: str = "/bin/bash") -> dict:
    _require_linux()
    name = _validate_name(name)
    if shell not in ("/bin/bash", "/bin/sh", "/usr/sbin/nologin", "/bin/false"):
        raise UserError("Unsupported shell")
    argv = ["useradd", "-s", shell]
    if create_home:
        argv.append("-m")
    argv.append(name)
    out = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    if out.returncode != 0:
        raise UserError(out.stderr.strip() or "useradd failed")
    return {"ok": True, "name": name}


def delete_user(name: str, remove_home: bool = False, backup: bool = False) -> dict:
    _require_linux()
    name = _validate_name(name)
    owner = files.default_user()
    if name == "root" or (owner and name == owner.pw_name):
        raise UserError(f"Refusing to delete protected account '{name}'")
    try:
        home = pwd.getpwnam(name).pw_dir
    except KeyError:
        raise UserError("No such user")
    shared = _home_owner(name, home) if remove_home else None
    if shared:
        raise UserError(f"{home} is inside {shared}'s home, so it stays; delete the files by hand if you want them gone")
    saved = backup_home(name) if backup else None
    argv = ["userdel"]
    if remove_home:
        argv.append("-r")
    argv.append(name)
    out = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise UserError(out.stderr.strip() or "userdel failed")
    return {"ok": True, "name": name, "backup": saved}


def set_lock(name: str, locked: bool) -> dict:
    _require_linux()
    name = _validate_name(name)
    flag = "-L" if locked else "-U"
    out = subprocess.run(["usermod", flag, name], capture_output=True, text=True, timeout=20)
    if out.returncode != 0:
        raise UserError(out.stderr.strip() or "usermod failed")
    return {"ok": True, "name": name, "locked": locked}


def set_password(name: str, password: str) -> dict:
    """Set a Linux account password on behalf of the panel admin.

    The password is piped to `chpasswd` and never logged or stored by the panel.
    """
    _require_linux()
    name = _validate_name(name)
    if not password or len(password) < 6 or "\n" in password:
        raise UserError("Password must be at least 6 characters and single-line")
    if not shutil.which("chpasswd"):
        raise UserError("chpasswd not available")
    proc = subprocess.run(["chpasswd"], input=f"{name}:{password}\n", text=True, capture_output=True, timeout=20)
    if proc.returncode != 0:
        raise UserError(proc.stderr.strip() or "chpasswd failed")
    return {"ok": True, "name": name}
