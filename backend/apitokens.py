"""API Tokens — long-lived bearer tokens for programmatic access to the API.

Tokens are shown once at creation; only a SHA-256 hash is stored. Callers pass
`Authorization: Bearer <token>` (or `X-Aurora-Token: <token>`).

Every token has a level, enforced by authz.py before any route runs:
  read   sees what a Viewer sees (status, lists, health), changes nothing
  fleet  read, plus the fixed actions another panel's Servers page sends: ban and unban an
         address, start or restart a service, install updates
  admin  everything, with extra locks: only from the addresses it names, only over HTTPS
         (or from this machine), it expires within 90 days, and it can't manage tokens,
         panel users, the password, 2FA or Panel HTTPS
Tokens made before levels existed carry no level: they keep full access so nothing breaks,
and the page asks for them to be replaced.
"""
from __future__ import annotations

import hashlib
import ipaddress
import secrets
import threading
import time

from . import config

LEVELS = ("read", "fleet", "admin")
ADMIN_MAX_DAYS = 90
_TOUCH_EVERY = 300  # seconds between "last used" writes for the same token and address
_touch_lock = threading.Lock()


class APITokenError(RuntimeError):
    pass


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _load() -> list[dict]:
    return config.load_config().get("api_tokens", [])


def _save(tokens: list[dict]) -> None:
    cfg = config.load_config()
    cfg["api_tokens"] = tokens
    config.save_config(cfg)


def _nets(allow_from) -> list[str]:
    """'192.168.0.101, 10.0.0.0/24' (or a list) -> normalised networks; refuses a bad entry."""
    items = allow_from.replace("\n", ",").split(",") if isinstance(allow_from, str) else list(allow_from or [])
    out: list[str] = []
    for raw in items:
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise APITokenError(f"“{raw[:60]}” isn't an address or range (for example 192.168.0.101 or 192.168.0.0/24)")
        if str(net) not in out:
            out.append(str(net))
    if len(out) > 20:
        raise APITokenError("At most 20 addresses or ranges")
    return out


def create(name: str, level: str = "read", allow_from=None, days: int | None = None) -> dict:
    name = (name or "").strip()
    if not name or len(name) > 60:
        raise APITokenError("Name is required (max 60 chars)")
    if level not in LEVELS:
        raise APITokenError("Pick an access level: read only, fleet control or full admin")
    nets = _nets(allow_from)
    if days is not None and (days < 1 or days > 3650):
        raise APITokenError("Expiry must be between 1 and 3650 days")
    if level == "admin":
        if not nets:
            raise APITokenError("A full admin token must be locked to the addresses that will use it")
        for n in nets:
            net = ipaddress.ip_network(n)
            if net.prefixlen < (16 if net.version == 4 else 48):
                raise APITokenError(f"{n} is too wide for a full admin token: use single addresses or ranges of at most a /16")
        if not days or days > ADMIN_MAX_DAYS:
            raise APITokenError(f"A full admin token must expire within {ADMIN_MAX_DAYS} days")
    raw = "aur_" + secrets.token_urlsafe(24)
    now = time.time()
    entry = {"id": secrets.token_hex(6), "name": name, "prefix": raw[:12], "hash": _hash(raw), "created": now,
             "level": level, "allow_from": nets, "expires": now + days * 86400 if days else None}
    tokens = _load()
    tokens.append(entry)
    _save(tokens)
    # Return the raw token ONCE — it can never be recovered later.
    return {"id": entry["id"], "name": name, "token": raw, "level": level, "allow_from": nets, "expires": entry["expires"]}


def listing() -> dict:
    now = time.time()
    out = []
    for t in _load():
        row = {k: t.get(k) for k in ("id", "name", "prefix", "created", "allow_from", "expires", "last_used", "last_ip")}
        row["level"] = t.get("level") or "legacy"
        row["allow_from"] = row["allow_from"] or []
        row["expired"] = bool(t.get("expires") and t["expires"] < now)
        out.append(row)
    return {"tokens": out}


def revoke(token_id: str) -> dict:
    tokens = _load()
    kept = [t for t in tokens if t.get("id") != token_id]
    if len(kept) == len(tokens):
        raise APITokenError("Token not found")
    _save(kept)
    return {"ok": True}


def lookup(token: str) -> dict | None:
    """The stored entry for a valid, unexpired token, else None."""
    if not token:
        return None
    h = _hash(token)
    for t in _load():
        if secrets.compare_digest(t.get("hash", ""), h):
            if t.get("expires") and t["expires"] < time.time():
                return None
            return t
    return None


def verify(token: str) -> str | None:
    """Return the token's name if valid, else None."""
    t = lookup(token)
    return t.get("name", "api") if t else None


def level(entry: dict) -> str:
    return entry.get("level") or "legacy"


def _ip(ip: str | None):
    try:
        a = ipaddress.ip_address((ip or "").split("%", 1)[0])
    except ValueError:
        return None
    return a.ipv4_mapped or a if a.version == 6 else a


def refuse(entry: dict, ip: str | None, secure: bool) -> str | None:
    """Why this token can't be used from here (None = it can): its address lock, and HTTPS for full admin."""
    addr = _ip(ip)
    nets = entry.get("allow_from") or []
    if nets and not (addr and any(addr in ipaddress.ip_network(n) for n in nets)):
        return f"This API token can't be used from {ip or 'this address'}"
    if level(entry) == "admin" and not secure and not (addr and addr.is_loopback):
        return "A full admin API token only works over HTTPS. Turn on Panel HTTPS (Security → Panel HTTPS) on this server."
    return None


def touch(entry: dict, ip: str | None) -> None:
    """Remember when and from where a token was last used, at most every few minutes per token."""
    now = time.time()
    if entry.get("last_ip") == ip and now - (entry.get("last_used") or 0) < _TOUCH_EVERY:
        return
    with _touch_lock:
        tokens = _load()
        for t in tokens:
            if t.get("id") == entry.get("id"):
                t["last_used"], t["last_ip"] = now, ip
                _save(tokens)
                break
