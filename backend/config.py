"""Configuration + credential storage for AuroraPanel.

The config lives in a JSON file next to the project root. The admin password is
never stored in plaintext: we keep a PBKDF2-HMAC-SHA256 hash + per-install salt.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path

# Project root = one level up from this backend/ package.
ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "aurora_config.json"

_PBKDF2_ITERATIONS = 200_000


def _hash_password(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    )
    return dk.hex()


def load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def _write_private(path: Path, text: str) -> None:
    """Write a file only its owner (root) can read: the config holds the session
    signing secret, 2FA secret and API token hashes — readable by a website's PHP
    user, it would let anyone on the server forge an admin login."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def save_config(cfg: dict) -> None:
    _write_private(CONFIG_PATH, json.dumps(cfg, indent=2))


def lock_down() -> None:
    """Make an existing config root-only (installs before 1.1.2 left it world-readable)."""
    for p in (CONFIG_PATH, initial_password_path()):
        try:
            if p.exists() and p.stat().st_mode & 0o077:
                os.chmod(p, 0o600)
        except OSError:
            pass


def is_initialized() -> bool:
    cfg = load_config()
    return bool(cfg.get("password_hash"))


def set_credentials(username: str, password: str, must_change: bool = False) -> None:
    """Create/overwrite the admin credentials + a fresh session secret."""
    salt = secrets.token_hex(16)
    cfg = load_config()
    cfg["username"] = username
    cfg["salt"] = salt
    cfg["password_hash"] = _hash_password(password, salt)
    # Rotate the signing secret whenever credentials change -> invalidates old sessions.
    cfg["session_secret"] = secrets.token_hex(32)
    if must_change:
        cfg["must_change_password"] = True
    else:
        cfg.pop("must_change_password", None)
    save_config(cfg)


# --------------------------------------------------------------------------- #
# First sign-in: a random password, made on the server, that must be replaced.
# There is no "create your account" page — whoever reached a fresh panel first
# (anyone on the internet, for a VPS) would have owned the server.
# --------------------------------------------------------------------------- #
# No look-alikes (0/O, 1/l/I), so it can be typed from the installer's output.
_PW_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def initial_password_path() -> Path:
    return CONFIG_PATH.with_name("aurora_initial_password")


def random_password() -> str:
    """Four groups of five (about 115 bits), e.g. "k7Qm2-Xp9aR-..."."""
    return "-".join("".join(secrets.choice(_PW_ALPHABET) for _ in range(5)) for _ in range(4))


def issue_temporary_password(username: str | None = None) -> tuple[str, str]:
    """Give the owner a new random password that has to be changed at sign-in, and
    save it root-only next to the config so the installer (or `sudo cat`) can show it.
    Also the way back in after a lost password (install.sh --reset-password)."""
    username = username or load_config().get("username") or "admin"
    password = random_password()
    set_credentials(username, password, must_change=True)
    _write_private(initial_password_path(), f"username: {username}\npassword: {password}\n")
    return username, password


def ensure_initial_credentials() -> tuple[str, str] | None:
    """On a panel nobody has signed in to yet, create "admin" with a random password."""
    if is_initialized():
        return None
    return issue_temporary_password("admin")


def must_change_password() -> bool:
    return bool(load_config().get("must_change_password"))


def verify_credentials(username: str, password: str) -> bool:
    cfg = load_config()
    if not cfg.get("password_hash"):
        return False
    # Always hash, and compare both fields in constant time, so a wrong
    # username takes as long as a wrong password (no username probing).
    candidate = _hash_password(password, cfg["salt"])
    name_ok = secrets.compare_digest(username.encode("utf-8"), str(cfg.get("username", "")).encode("utf-8"))
    return secrets.compare_digest(candidate, cfg["password_hash"]) and name_ok


def session_secret() -> str:
    cfg = load_config()
    secret = cfg.get("session_secret")
    if not secret:
        secret = secrets.token_hex(32)
        cfg["session_secret"] = secret
        save_config(cfg)
    return secret


def change_password(new_password: str) -> None:
    """Update the admin password and rotate the session secret, which signs out
    every existing session (the caller re-issues a cookie for the current one)."""
    cfg = load_config()
    salt = secrets.token_hex(16)
    cfg["salt"] = salt
    cfg["password_hash"] = _hash_password(new_password, salt)
    cfg["session_secret"] = secrets.token_hex(32)
    cfg.pop("must_change_password", None)
    save_config(cfg)
    initial_password_path().unlink(missing_ok=True)


def rotate_session_secret() -> None:
    """Invalidate every issued session cookie."""
    cfg = load_config()
    cfg["session_secret"] = secrets.token_hex(32)
    save_config(cfg)


def get_prefs() -> dict:
    cfg = load_config()
    return {
        "username": cfg.get("username", ""),
        "contact_email": cfg.get("contact_email", ""),
        "language": cfg.get("language", "en"),
        "default_theme": cfg.get("default_theme", "dark"),
    }


def set_prefs(**kwargs) -> dict:
    cfg = load_config()
    for k in ("contact_email", "language", "default_theme"):
        if k in kwargs and kwargs[k] is not None:
            cfg[k] = kwargs[k]
    save_config(cfg)
    return get_prefs()


def rename_user(new_username: str) -> None:
    cfg = load_config()
    cfg["username"] = new_username
    save_config(cfg)
