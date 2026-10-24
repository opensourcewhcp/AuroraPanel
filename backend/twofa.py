"""TOTP two-factor auth (RFC 6238), stdlib only.

Secret + enabled flag live in the panel config. Enrollment returns an
otpauth:// URI the user adds to Google Authenticator / Authy etc.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

from . import config

_DIGITS = 6
_PERIOD = 30


def _b32_secret() -> str:
    # 20 random bytes -> base32, no padding, as authenticator apps expect.
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _code_at(secret_b32: str, counter: int) -> str:
    # Restore base32 padding.
    pad = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    bincode = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(bincode % (10 ** _DIGITS)).zfill(_DIGITS)


def verify(secret_b32: str, code: str, window: int = 1) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != _DIGITS:
        return False
    counter = int(time.time() // _PERIOD)
    for delta in range(-window, window + 1):
        if hmac.compare_digest(_code_at(secret_b32, counter + delta), code):
            return True
    return False


def status() -> dict:
    cfg = config.load_config()
    return {"enabled": bool(cfg.get("totp_enabled")), "pending": bool(cfg.get("totp_secret") and not cfg.get("totp_enabled"))}


def begin_enroll(username: str) -> dict:
    """Generate (but don't yet enable) a secret; return provisioning details."""
    cfg = config.load_config()
    secret = _b32_secret()
    cfg["totp_secret"] = secret
    cfg["totp_enabled"] = False
    config.save_config(cfg)
    # The app shows "AuroraPanel <server>" — several panels stay apart in one authenticator.
    import socket
    from urllib.parse import quote
    issuer = f"AuroraPanel {socket.gethostname().split('.')[0]}"
    uri = (f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}&issuer={quote(issuer)}"
           f"&algorithm=SHA1&digits={_DIGITS}&period={_PERIOD}")
    return {"secret": secret, "otpauth_uri": uri, "issuer": issuer, "qr": qr_data_uri(uri)}


def qr_data_uri(text: str) -> str:
    """The otpauth link as a QR code (an SVG data: URI) to scan with Microsoft / Google Authenticator,
    Authy, 1Password… Made here, so the secret never goes to an outside QR service."""
    try:
        import segno
        return segno.make(text, error="m").svg_data_uri(scale=6, border=3, dark="#000", light="#fff")
    except Exception:
        return ""


def confirm_enable(code: str) -> bool:
    cfg = config.load_config()
    secret = cfg.get("totp_secret")
    if not secret:
        return False
    if not verify(secret, code):
        return False
    cfg["totp_enabled"] = True
    config.save_config(cfg)
    return True


def disable(code: str) -> bool:
    cfg = config.load_config()
    secret = cfg.get("totp_secret")
    if not cfg.get("totp_enabled") or not secret:
        return True
    if not verify(secret, code):
        return False
    cfg.pop("totp_secret", None)
    cfg["totp_enabled"] = False
    config.save_config(cfg)
    return True


def is_enabled() -> bool:
    return bool(config.load_config().get("totp_enabled"))


def verify_login(code: str) -> bool:
    cfg = config.load_config()
    secret = cfg.get("totp_secret")
    if not cfg.get("totp_enabled") or not secret:
        return True  # 2FA not enabled -> always passes
    return verify(secret, code)
