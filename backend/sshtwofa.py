"""SSH two-factor for Linux accounts: a one-time code from a phone app on top of the password,
through libpam-google-authenticator.

The panel writes each account's secret file, turns the PAM module on with ``nullok`` (accounts
without a secret sign in exactly as before) and lets sshd ask for the code. Logins with an SSH key
are untouched: ``AuthenticationMethods`` is left alone, so a key still signs in without a code and
the panel can never lock its own SSH access out."""
from __future__ import annotations

import glob
import os
import secrets
import shutil
import socket
import subprocess
from pathlib import Path
from urllib.parse import quote

from . import twofa

try:
    import pwd  # Unix only; the Windows dev machine has no accounts to read
except ImportError:  # pragma: no cover
    pwd = None


class SshTwofaError(Exception):
    pass


PAM_FILE = Path("/etc/pam.d/sshd")
PAM_LINE = "auth required pam_google_authenticator.so nullok"
SSHD_DROPIN = Path("/etc/ssh/sshd_config.d/aurora-2fa.conf")
SSHD_TEXT = ("# Written by AuroraPanel: lets sshd ask for the one-time code of accounts that set one up.\n"
             "# Accounts without a code, and logins with an SSH key, are unaffected.\n"
             "KbdInteractiveAuthentication yes\n"
             "ChallengeResponseAuthentication yes\n")
GA = ".google_authenticator"            # the file the PAM module reads
PENDING = ".google_authenticator.aurora-pending"   # written at setup, renamed once a code was confirmed
_MODULE_GLOBS = ("/lib/*/security/pam_google_authenticator.so", "/usr/lib/*/security/pam_google_authenticator.so",
                 "/lib/security/pam_google_authenticator.so", "/usr/lib/security/pam_google_authenticator.so")


def _module_installed() -> bool:
    return any(glob.glob(p) for p in _MODULE_GLOBS)


def _pam_on() -> bool:
    try:
        return "pam_google_authenticator.so" in PAM_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def status() -> dict:
    inst = _module_installed()
    return {"installed": inst, "pam": _pam_on(), "sshd": SSHD_DROPIN.is_file(), "ready": inst and _pam_on() and SSHD_DROPIN.is_file()}


def _account(name: str):
    if pwd is None:
        raise SshTwofaError("Only on Linux")
    try:
        return pwd.getpwnam(name)
    except KeyError:
        raise SshTwofaError("No such user")


def user_state(name: str) -> str:
    """'on' (code required), 'pending' (set up but not confirmed yet) or 'off'."""
    if pwd is None:
        return "off"
    try:
        home = Path(pwd.getpwnam(name).pw_dir)
    except KeyError:
        return "off"
    if (home / GA).is_file():
        return "on"
    if (home / PENDING).is_file():
        return "pending"
    return "off"


def states() -> dict:
    if pwd is None:
        return {}
    return {p.pw_name: user_state(p.pw_name) for p in pwd.getpwall() if p.pw_dir and os.path.isdir(p.pw_dir)}


def enroll(name: str) -> dict:
    """Make a secret for the account (not active yet) and return what the phone app needs."""
    p = _account(name)
    home = Path(p.pw_dir)
    if not home.is_dir():
        raise SshTwofaError(f"{name} has no home folder, so there is nowhere to keep the secret")
    secret = twofa._b32_secret()
    scratch = [f"{secrets.randbelow(10 ** 8):08d}" for _ in range(5)]
    text = "\n".join([secret, '" RATE_LIMIT 3 30', '" WINDOW_SIZE 3', '" DISALLOW_REUSE', '" TOTP_AUTH', *scratch]) + "\n"
    f = home / PENDING
    f.write_text(text, encoding="utf-8")
    os.chmod(f, 0o600)
    os.chown(f, p.pw_uid, p.pw_gid)
    issuer = f"SSH {socket.gethostname()}"
    uri = f"otpauth://totp/{quote(issuer)}:{quote(name)}?secret={secret}&issuer={quote(issuer)}&digits=6&period=30"
    return {"name": name, "secret": secret, "otpauth_uri": uri, "qr": twofa.qr_data_uri(uri), "scratch": scratch}


def confirm(name: str, code: str) -> dict:
    """The code from the app matched: switch the account on (and the server, the first time)."""
    p = _account(name)
    home = Path(p.pw_dir)
    f = home / PENDING
    if not f.is_file():
        raise SshTwofaError("Start the setup first")
    secret = f.read_text(encoding="utf-8").splitlines()[0].strip()
    if not twofa.verify(secret, (code or "").strip().replace(" ", "")):
        raise SshTwofaError("That code didn't match. Check the phone's clock and try the next one")
    setup_system()
    f.replace(home / GA)
    return {"ok": True, "name": name, "state": "on"}


def disable(name: str) -> dict:
    p = _account(name)
    home = Path(p.pw_dir)
    for n in (GA, PENDING):
        try:
            (home / n).unlink()
        except FileNotFoundError:
            pass
    return {"ok": True, "name": name, "state": "off"}


def setup_system() -> dict:
    """One-time: the PAM module, its line in /etc/pam.d/sshd and keyboard-interactive logins in sshd.
    sshd's own check (sshd -t) runs before the reload; if it objects, the setting is taken back."""
    changed = []
    if not _module_installed():
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        r = subprocess.run(["apt-get", "install", "-y", "-q", "libpam-google-authenticator"], capture_output=True, text=True, timeout=900, env=env)
        if r.returncode != 0 or not _module_installed():
            tail = (r.stderr.strip().splitlines() or ["apt-get failed"])[-1]
            raise SshTwofaError("Couldn't install libpam-google-authenticator: " + tail)
        changed.append("package")
    if not _pam_on():
        txt = PAM_FILE.read_text(encoding="utf-8")
        if "@include common-auth" in txt:   # the password is checked first, the code second
            txt = txt.replace("@include common-auth", "@include common-auth\n" + PAM_LINE, 1)
        else:
            txt = txt.rstrip("\n") + "\n" + PAM_LINE + "\n"
        PAM_FILE.write_text(txt, encoding="utf-8")
        changed.append("pam")
    if not SSHD_DROPIN.is_file():
        SSHD_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        SSHD_DROPIN.write_text(SSHD_TEXT, encoding="utf-8")
        sshd = shutil.which("sshd") or "/usr/sbin/sshd"
        t = subprocess.run([sshd, "-t"], capture_output=True, text=True, timeout=20)
        if t.returncode != 0:
            SSHD_DROPIN.unlink(missing_ok=True)
            raise SshTwofaError("sshd didn't accept the setting: " + (t.stderr.strip() or "sshd -t failed"))
        for unit in ("ssh", "sshd"):
            if subprocess.run(["systemctl", "reload", unit], capture_output=True, text=True, timeout=30).returncode == 0:
                break
        changed.append("sshd")
    return {"ok": True, "changed": changed}
