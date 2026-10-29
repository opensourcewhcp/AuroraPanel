"""Signed, expiring session tokens (stdlib only — no JWT dependency).

Token format:  base64url(payload).hex(hmac_sha256(secret, payload))
payload = "<username>:<expiry_epoch>"
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import time

from fastapi import Depends, HTTPException, Request, status

from . import config

SESSION_TTL_SECONDS = 60 * 60 * 8  # 8 hours
# Two cookie names, one per scheme. A browser refuses to overwrite a Secure cookie from a plain
# http:// page (RFC 6265bis "leave secure cookies alone"), so after Panel HTTPS is turned off a
# login over http would answer 200 yet the browser would keep the old https cookie, which it never
# sends over http: every next request 401, back to the login page. A separate name for http
# sessions never collides with the Secure one.
COOKIE_NAME = "aurora_session"  # issued over https, with the Secure flag
COOKIE_NAME_HTTP = "aurora_session_http"  # issued over plain http
COOKIE_NAMES = (COOKIE_NAME, COOKIE_NAME_HTTP)


def cookie_name(secure: bool) -> str:
    return COOKIE_NAME if secure else COOKIE_NAME_HTTP


def session_from_cookies(cookies) -> str | None:
    """The signed-in user from whichever session cookie the browser sent, or None."""
    for name in COOKIE_NAMES:
        token = cookies.get(name)
        if token:
            username = verify_token(token)
            if username:
                return username
    return None


def _sign(payload: str) -> str:
    secret = config.session_secret().encode("utf-8")
    return hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_token(username: str) -> str:
    expiry = int(time.time()) + SESSION_TTL_SECONDS
    payload = f"{username}:{expiry}"
    b64 = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")
    return f"{b64}.{_sign(payload)}"


def verify_token(token: str) -> str | None:
    """Return the username if the token is valid + unexpired, else None."""
    try:
        b64, signature = token.split(".", 1)
        payload = base64.urlsafe_b64decode(b64.encode("ascii")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if not hmac.compare_digest(signature, _sign(payload)):
        return None
    try:
        username, expiry_str = payload.rsplit(":", 1)
        expiry = int(expiry_str)
    except ValueError:
        return None
    if time.time() > expiry:
        return None
    return username


def require_auth(request: Request) -> str:
    """FastAPI dependency: accept a valid session cookie OR an API token."""
    username = session_from_cookies(request.cookies)
    if not username:
        # Fall back to an API token (Authorization: Bearer / X-Aurora-Token).
        from . import apitokens
        bearer = request.headers.get("authorization", "")
        api_tok = bearer[7:].strip() if bearer.lower().startswith("bearer ") else request.headers.get("x-aurora-token")
        name = apitokens.verify(api_tok) if api_tok else None
        if name:
            username = f"token:{name}"
    if username and not username.startswith("token:"):
        # A deleted or disabled panel user's session ends at once.
        from . import panelusers
        if not panelusers.get(username):
            username = None
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )
    return username


CurrentUser = Depends(require_auth)
