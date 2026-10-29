"""Who may do what — role checks for every API call (see panelusers.py for the roles).

AuthzMiddleware runs before the routes: it works out the caller, refuses what their role can't do
(deny by default for limited roles, so a new page is never accidentally open to them), and puts their
scope in a context variable that the File Manager, Email and Metrics read to show only what's theirs.
"""
from __future__ import annotations

import contextvars
import json
import re
from pathlib import Path

CURRENT: contextvars.ContextVar[dict | None] = contextvars.ContextVar("aurora_user", default=None)

# Website managers: only these calls, each further limited to their own sites inside the module.
SITE_ALLOW = [
    ("GET", r"/api/(me|status|requires)"),
    ("GET", r"/api/jobs/[\w-]+"),
    ("POST", r"/api/(logout|me/password)"),
    ("GET", r"/api/mysites"),
    ("GET", r"/api/files/(list|read|download)"),
    ("POST", r"/api/files/(write|delete|zip|unzip|mkdir|upload)"),
    ("GET", r"/api/mail/accounts(/device|/mobileconfig)?"),
    ("POST", r"/api/mail/accounts/(create|update|delete)"),
    ("GET", r"/api/metrics/(sites|visitors|analytics|errors)"),
]
# Viewers can read every page, but not these (secrets, file contents, downloads, a shell).
VIEWER_DENY_GET = re.compile(r"^/api/(files/(read|download)|backups/[^/]+/download|backups/download|metrics/download|"
                             r"schedules/plans/[^/]+/passphrase|docker/apps/[^/]+/secret|ddns-hosts/[^/]+/key|"
                             r"mail/accounts/mobileconfig|apitokens|terminal|sysapps/[^/]+/file)")
VIEWER_ALLOW_POST = re.compile(r"^/api/(logout|me/password)$")
# The owner on the installer's random password: only what it takes to replace it.
FIRST_LOGIN_ALLOW = re.compile(r"^/api/(me|status|logout|account/password)$")


def current() -> dict | None:
    return CURRENT.get()


def cross_origin(headers: dict, is_ws: bool, method: str) -> bool:
    """A browser request that changes something, or opens a WebSocket, must come from the panel's own
    pages. The session cookie is SameSite=strict, which stops other *sites*, but a website hosted on
    the same domain as the panel (blog.example.com against panel example.com:8088) counts as the same
    site: a page planted on a hacked website could open the root terminal or POST to any body-less
    endpoint with the owner's cookie. Browsers always send Origin on those requests, so it must name
    the host the request was sent to. Requests without Origin (curl, scripts, API tokens) pass."""
    if not is_ws and method in ("GET", "HEAD", "OPTIONS"):
        return False
    origin = (headers.get("origin") or "").strip().lower()
    if not origin:
        return False
    if origin == "null":
        return True
    host = origin.split("://", 1)[1] if "://" in origin else origin
    host = host.split("/", 1)[0]
    wanted = {h.strip().lower() for h in (headers.get("host", ""), headers.get("x-forwarded-host", "")) if h}
    # Origin leaves out a default port; Host may carry it (and the reverse).
    def variants(h: str) -> set[str]:
        out = {h}
        for p in (":80", ":443"):
            if h.endswith(p):
                out.add(h[: -len(p)])
            else:
                out.add(h + p)
        return out
    return not (variants(host) & {v for w in wanted for v in variants(w)})


def scope() -> dict | None:
    """For a website manager: {sites, roots, domains}; None for everyone else (no limits)."""
    u = CURRENT.get()
    if not u or u.get("role") != "site":
        return None
    if "_scope" not in u:
        from . import sites as S
        roots, domains = [], set()
        for name in u.get("sites", []):
            try:
                st = S.get_site(name)["settings"]
            except Exception:
                continue
            if st.get("docroot"):
                roots.append(Path(st["docroot"]).resolve())
            for n in [st["server_name"]] + list(st.get("aliases", [])):
                n = n.lower()
                domains.add(n[4:] if n.startswith("www.") else n)
        u["_scope"] = {"sites": list(u.get("sites", [])), "roots": roots, "domains": sorted(domains)}
    return u["_scope"]


def in_roots(p: Path) -> bool:
    sc = scope()
    if sc is None:
        return True
    return any(p == r or r in p.parents for r in sc["roots"])


def domain_ok(domain: str) -> bool:
    sc = scope()
    return sc is None or (domain or "").lower() in sc["domains"]


def _decide(user: dict | None, method: str, path: str) -> str | None:
    """None = allowed, else the reason it's refused."""
    if user and user.get("owner") and not FIRST_LOGIN_ALLOW.match(path):
        from . import config
        if config.must_change_password():
            return "password_change_required"
    if not user or user.get("role") == "admin":
        return None
    if user["role"] == "viewer":
        if method in ("GET", "HEAD"):
            return "This account can look but not open files, secrets or downloads" if VIEWER_DENY_GET.match(path) else None
        return None if VIEWER_ALLOW_POST.match(path) else "This account is read-only"
    if user["role"] == "site":
        for m, rx in SITE_ALLOW:
            if m == method and re.fullmatch(rx, path):
                return None
        return "This account manages only its own websites"
    return "Unknown role"


class AuthzMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope_, receive, send):
        if scope_["type"] not in ("http", "websocket"):
            return await self.app(scope_, receive, send)
        from . import audit, auth, panelusers
        name = audit._user_from_scope(scope_)
        user = panelusers.get(name) if name else None
        token = CURRENT.set(dict(user) if user else None)
        try:
            path = scope_.get("path", "")
            if path.startswith("/api/") and user:
                is_ws = scope_["type"] == "websocket"
                headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope_.get("headers", [])}
                why = _decide(user, "WS" if is_ws else scope_.get("method", "GET"), path)
                cookie_session = any(n + "=" in headers.get("cookie", "") for n in auth.COOKIE_NAMES)
                if not why and cookie_session and cross_origin(headers, is_ws, scope_.get("method", "GET")):
                    why = "Cross-origin request refused"
                if why:
                    if scope_["type"] == "websocket":
                        await send({"type": "websocket.close", "code": 1008})
                        return
                    body = json.dumps({"detail": why}).encode()
                    await send({"type": "http.response.start", "status": 403, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
                    await send({"type": "http.response.body", "body": body})
                    return
            await self.app(scope_, receive, send)
        finally:
            CURRENT.reset(token)
