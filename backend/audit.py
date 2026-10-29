"""Activity log — who changed what, from where, and whether it worked.

Every API call that changes something (POST/PUT/PATCH/DELETE) is recorded by AuditMiddleware,
plus logins (good and bad) and what the background task runner does on its own. Secrets in
request bodies (passwords, keys, tokens…) are never written. One JSON object per line in
/var/lib/aurora/audit.jsonl, rotated at 5 MB (four files kept, ~100k actions).
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

LOG = Path(os.environ.get("AURORA_AUDIT_LOG", "/var/lib/aurora/audit.jsonl"))
MAX_BYTES = 5 * 1024 * 1024
KEEP = 4
_lock = threading.Lock()
_SECRET = re.compile(r"pass|secret|token|key|otp|private|credential|cookie|auth|cert_pem|content", re.I)
# Fields worth showing in the summary, in this order.
_SHOW = ("address", "domain", "name", "target", "ip", "host", "id", "site", "path", "unit", "action", "mode", "enabled",
         "source", "dest", "db", "user", "username", "app", "engine", "kind", "days", "to", "prefix", "jail", "zone")
# Calls that change nothing worth logging (UI state, previews, tests that only read).
_SKIP = re.compile(r"^/api/(login|logout|jobs/[^/]+/cancel|terminal|mail/test|waf/test|files/(read|preview|list)|abuse/preview)")


def _redact(v, depth: int = 0):
    if depth > 3:
        return "…"
    if isinstance(v, dict):
        return {k: ("•••" if _SECRET.search(str(k)) else _redact(x, depth + 1)) for k, x in list(v.items())[:30]}
    if isinstance(v, list):
        return [_redact(x, depth + 1) for x in v[:15]]
    if isinstance(v, str):
        return v[:200]
    return v


def summary(path: str, body: dict | None, query: str = "") -> str:
    """'mail · accounts' + the identifying fields, e.g. 'address=bob@x.com'."""
    parts = [p for p in path.split("/")[2:] if p and not re.fullmatch(r"[0-9a-f]{8,}", p)]
    what = " · ".join(parts[:4]) or path
    bits = []
    src = dict(body or {})
    for kv in (query or "").split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            src.setdefault(k, v)
    for k in _SHOW:
        if k in src and src[k] not in (None, "", [], {}) and not _SECRET.search(k):
            v = src[k]
            v = ", ".join(map(str, v[:5])) if isinstance(v, list) else str(v)
            bits.append(f"{k}={v[:80]}")
        if len(bits) >= 4:
            break
    return what + (f" ({'; '.join(bits)})" if bits else "")


def record(user: str, ip: str, action: str, ok: bool = True, status: int = 200, detail=None, method: str = "", path: str = "") -> None:
    entry = {"ts": round(time.time(), 3), "user": user or "?", "ip": ip or "", "action": action[:300], "ok": bool(ok),
             "status": status, "method": method, "path": path[:200]}
    if detail is not None:
        entry["detail"] = _redact(detail)
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    with _lock:
        try:
            LOG.parent.mkdir(parents=True, exist_ok=True)
            if LOG.exists() and LOG.stat().st_size > MAX_BYTES:
                for i in range(KEEP - 1, 0, -1):
                    src = LOG.with_name(f"{LOG.name}.{i}")
                    if src.exists():
                        src.replace(LOG.with_name(f"{LOG.name}.{i + 1}"))
                LOG.replace(LOG.with_name(f"{LOG.name}.1"))
            with open(LOG, "a", encoding="utf-8") as f:
                f.write(line)
            os.chmod(LOG, 0o600)
        except OSError:
            pass


def entries(days: int = 30, q: str = "", user: str = "", only_failed: bool = False, limit: int = 2000) -> dict:
    since = time.time() - max(1, days) * 86400
    files = [LOG.with_name(f"{LOG.name}.{i}") for i in range(KEEP, 0, -1)] + [LOG]
    out = []
    ql = q.lower()
    users: set[str] = set()
    for f in files:
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("ts", 0) < since:
                continue
            users.add(e.get("user", "?"))
            if user and e.get("user") != user:
                continue
            if only_failed and e.get("ok"):
                continue
            if ql and ql not in json.dumps(e, ensure_ascii=False).lower():
                continue
            out.append(e)
    out.sort(key=lambda e: -e.get("ts", 0))
    return {"entries": out[:limit], "total": len(out), "users": sorted(users)}


def _user_from_scope(scope) -> str:
    """Who is calling — the same rules as auth.require_auth, without raising."""
    from . import auth, apitokens
    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
    from starlette.requests import cookie_parser  # same parsing as request.cookies (unquotes "…" values)
    u = auth.session_from_cookies(cookie_parser(headers.get("cookie", "")))
    if u:
        return u
    b = headers.get("authorization", "")
    tok = b[7:].strip() if b.lower().startswith("bearer ") else headers.get("x-aurora-token", "")
    if tok:
        name = apitokens.verify(tok)
        if name:
            return f"token:{name}"
    return ""


class AuditMiddleware:
    """Pure ASGI: sees the request body as it streams past (without consuming it) and the response status."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PUT", "PATCH", "DELETE"):
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if not path.startswith("/api/") or _SKIP.match(path):
            return await self.app(scope, receive, send)
        ctype = ""
        for k, v in scope.get("headers", []):
            if k == b"content-type":
                ctype = v.decode("latin-1").lower()
        buf = bytearray()
        status = {"code": 500}

        async def recv():
            msg = await receive()
            if msg.get("type") == "http.request" and len(buf) < 16384 and "json" in ctype:
                buf.extend(msg.get("body", b"")[:16384 - len(buf)])
            return msg

        async def snd(msg):
            if msg.get("type") == "http.response.start":
                status["code"] = msg.get("status", 500)
            await send(msg)

        try:
            await self.app(scope, recv, snd)
        finally:
            code = status["code"]
            if code != 401:  # unauthenticated noise isn't an action
                body = None
                if buf:
                    try:
                        body = json.loads(bytes(buf).decode("utf-8", "replace"))
                    except ValueError:
                        body = None
                if not isinstance(body, dict):
                    body = {"_": body} if body is not None else None
                if "multipart" in ctype:
                    body = {"upload": True}
                client = scope.get("client") or ("", 0)
                record(_user_from_scope(scope), client[0], summary(path, body, scope.get("query_string", b"").decode("latin-1")),
                       ok=code < 400, status=code, detail=body, method=scope.get("method", ""), path=path)
