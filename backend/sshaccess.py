"""SSH Access: sshd status (read-only) + authorized_keys management.

We deliberately do NOT expose stop/disable of sshd here — cutting SSH on a
remote box is a lockout risk (the same class of mistake as the firewall). Key
management + status is what cPanel's SSH Access is really for.
"""
from __future__ import annotations

import base64
import hashlib
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from . import problems

IS_LINUX = platform.system() == "Linux"
_KEY_RE = re.compile(r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2-\S+|ssh-dss)\s+([A-Za-z0-9+/=]+)(\s+(.*))?$")


class SSHError(RuntimeError):
    pass


def _sshd_config() -> dict:
    cfg = {"port": "22", "permit_root_login": "default", "password_auth": "default"}
    p = Path("/etc/ssh/sshd_config")
    if not p.exists():
        return cfg
    try:
        for line in p.read_text(errors="replace").splitlines():
            s = line.strip()
            if s.startswith("#") or not s:
                continue
            low = s.lower()
            if low.startswith("port "):
                cfg["port"] = s.split(None, 1)[1].strip()
            elif low.startswith("permitrootlogin "):
                cfg["permit_root_login"] = s.split(None, 1)[1].strip()
            elif low.startswith("passwordauthentication "):
                cfg["password_auth"] = s.split(None, 1)[1].strip()
    except OSError:
        pass
    return cfg


def status() -> dict:
    active = enabled = None
    if IS_LINUX and shutil.which("systemctl"):
        for unit in ("ssh", "sshd"):
            r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
            if r.stdout.strip() in ("active", "inactive", "failed"):
                active = r.stdout.strip()
                en = subprocess.run(["systemctl", "is-enabled", unit], capture_output=True, text=True)
                enabled = en.stdout.strip()
                break
    return {"supported": IS_LINUX, "active": active, "enabled": enabled, "config": _sshd_config()}


def restart() -> dict:
    if not (IS_LINUX and shutil.which("systemctl")):
        raise SSHError("systemctl not available")
    unit = "ssh" if subprocess.run(["systemctl", "list-unit-files", "ssh.service"],
                                   capture_output=True, text=True).stdout.count("ssh.service") else "sshd"
    r = subprocess.run(["systemctl", "restart", unit], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise SSHError(r.stderr.strip() or "restart failed")
    return {"ok": True}


# ---- authorized_keys ----
def _authorized_keys_path(user: str) -> Path:
    import pwd
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", user or ""):
        raise SSHError("Invalid username")
    try:
        home = Path(pwd.getpwnam(user).pw_dir)
    except KeyError:
        raise SSHError("No such user")
    return home / ".ssh" / "authorized_keys"


def _fingerprint(b64key: str) -> str:
    try:
        raw = base64.b64decode(b64key)
        return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return "?"


def list_keys(user: str) -> dict:
    if not IS_LINUX:
        return {"supported": False, "keys": []}
    path = _authorized_keys_path(user)
    keys = []
    if path.exists():
        for idx, line in enumerate(path.read_text(errors="replace").splitlines()):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = _KEY_RE.match(s)
            if m:
                keys.append({"type": m.group(1), "comment": (m.group(4) or "").strip(),
                             "fingerprint": _fingerprint(m.group(2)), "raw": s})
    return {"supported": True, "user": user, "path": str(path), "keys": keys}


def add_key(user: str, public_key: str) -> dict:
    if not IS_LINUX:
        raise SSHError("Only available on Linux")
    pk = (public_key or "").strip()
    # A public key is one line and never large. Bounding it first keeps the \s+/.* parts of _KEY_RE from
    # backtracking on a crafted multi-megabyte input (polynomial ReDoS) and rejects multi-line payloads.
    if len(pk) > 16384 or "\n" in pk or "\r" in pk:
        raise SSHError("That doesn't look like a valid SSH public key")
    if not _KEY_RE.match(pk):
        raise SSHError("That doesn't look like a valid SSH public key")
    path = _authorized_keys_path(user)
    parent = path.parent
    # The panel runs as root. If ~/.ssh or authorized_keys is a symlink the user planted, following it
    # would let root write and chown an arbitrary file (e.g. /etc/shadow) as that user: a local privilege
    # escalation. Refuse symlinks and open the file with O_NOFOLLOW so the final component is never followed.
    if parent.is_symlink():
        raise SSHError(".ssh is a symlink; refusing to write through it")
    parent.mkdir(mode=0o700, exist_ok=True)
    if path.is_symlink():
        raise SSHError("authorized_keys is a symlink; refusing to write through it")
    existing = path.read_text(errors="replace").splitlines() if path.exists() else []
    if pk in [l.strip() for l in existing]:
        raise SSHError("Key already present")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, (pk + "\n").encode("utf-8"))
        os.fchmod(fd, 0o600)
        import pwd
        try:
            info = pwd.getpwnam(user)
            os.fchown(fd, info.pw_uid, info.pw_gid)
            os.chown(parent, info.pw_uid, info.pw_gid, follow_symlinks=False)
        except (KeyError, OSError):
            pass
    finally:
        os.close(fd)
    return {"ok": True}


def remove_key(user: str, raw: str) -> dict:
    if not IS_LINUX:
        raise SSHError("Only available on Linux")
    path = _authorized_keys_path(user)
    if not path.exists():
        raise SSHError("No authorized_keys file")
    target = (raw or "").strip()
    lines = path.read_text(errors="replace").splitlines()
    kept = [l for l in lines if l.strip() != target]
    if len(kept) == len(lines):
        raise SSHError("Key not found")
    path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    return {"ok": True}
