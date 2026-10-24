"""Panel users — more people than the owner, each with the right amount of power.

Roles:
  admin   — everything (the owner set up at first run is always admin)
  viewer  — can look at every page, can't change anything or read secrets
  site    — "website manager": only their own websites — files, email accounts of those domains,
            visitors/analytics/errors — nothing else on the server. A hosting account's login is a
            website manager tied to the account (field "account"): files = the account's home,
            plus its own databases, within its plan's limits (hosting.py).
  reseller — creates and manages its own hosting accounts (WHM-style), with the plans and the
            number of accounts the admin allows; nothing else

Passwords are PBKDF2-hashed like the owner's. Sessions name the user; their role is looked up on every
request, so changing or deleting a user takes effect at once.
"""
from __future__ import annotations

import re
import secrets
import time

from . import config

ROLES = {"admin": "Administrator", "viewer": "Viewer (read-only)", "site": "Website manager", "reseller": "Reseller"}
_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._@-]{1,63}$")


class PanelUserError(RuntimeError):
    pass


def _all() -> list[dict]:
    return config.load_config().get("panel_users", [])


def _store(users: list[dict]) -> None:
    cfg = config.load_config()
    cfg["panel_users"] = users
    config.save_config(cfg)


def owner() -> str:
    return config.load_config().get("username", "")


def get(username: str) -> dict | None:
    """{username, role, sites} for an active user (the owner included), else None."""
    if not username:
        return None
    if username.startswith("token:"):
        return {"username": username, "role": "admin", "sites": []}  # API tokens are made by an admin
    if username == owner():
        return {"username": username, "role": "admin", "sites": [], "owner": True}
    for u in _all():
        if u["username"] == username and not u.get("disabled"):
            return {"username": username, "role": u["role"], "sites": u.get("sites", []),
                    **({"account": u["account"]} if u.get("account") else {})}
    return None


def verify(username: str, password: str) -> bool:
    for u in _all():
        if u["username"] == username:
            ok = secrets.compare_digest(config._hash_password(password, u["salt"]), u["hash"])
            return ok and not u.get("disabled")
    config._hash_password(password, "00" * 16)  # same time for unknown names
    return False


def listing() -> dict:
    out = [{"username": owner(), "role": "admin", "owner": True, "sites": [], "created": None}]
    for u in _all():
        out.append({k: u.get(k) for k in ("username", "role", "sites", "created", "disabled", "last_login", "account")})
    return {"users": out, "roles": ROLES}


def _sites_ok(sites: list[str]) -> list[str]:
    from . import sites as S
    known = {s["server_name"] for s in S.list_sites().get("sites", []) if not s.get("system")}
    bad = [x for x in sites if x not in known]
    if bad:
        raise PanelUserError(f"Unknown website: {', '.join(bad)}")
    return sorted(set(sites))


def create(username: str, password: str, role: str, sites: list[str] | None = None, account: str = "") -> dict:
    username = (username or "").strip()
    if not _NAME.match(username):
        raise PanelUserError("User name: 2–64 letters, digits, dot, dash, underscore or @")
    if username == owner() or any(u["username"] == username for u in _all()):
        raise PanelUserError("That user name is taken")
    if role not in ROLES:
        raise PanelUserError("Unknown role")
    if len(password or "") < 10:
        raise PanelUserError("Use a password of at least 10 characters")
    sites = _sites_ok(sites or []) if role == "site" else []
    if role == "site" and not sites:
        raise PanelUserError("Pick at least one website for a website manager")
    salt = secrets.token_hex(16)
    users = _all()
    users.append({"username": username, "role": role, "sites": sites, "salt": salt, "hash": config._hash_password(password, salt),
                  "created": int(time.time()), **({"account": account} if account else {})})
    _store(users)
    return {"ok": True}


def update(username: str, role: str | None = None, sites: list[str] | None = None, password: str | None = None, disabled: bool | None = None,
           _hosting: bool = False) -> dict:
    users = _all()
    u = next((x for x in users if x["username"] == username), None)
    if not u:
        raise PanelUserError("Unknown user" if username != owner() else "The owner is changed under Password & Security")
    if u.get("account") and not _hosting and (role is not None or sites is not None):
        raise PanelUserError("This is a hosting account's login — change its websites and plan under Hosting → Accounts")
    if role is not None:
        if role not in ROLES:
            raise PanelUserError("Unknown role")
        u["role"] = role
    if sites is not None:
        u["sites"] = _sites_ok(sites) if u["role"] == "site" else []
    if u["role"] == "site" and not u.get("sites"):
        raise PanelUserError("Pick at least one website for a website manager")
    if password:
        if len(password) < 10:
            raise PanelUserError("Use a password of at least 10 characters")
        u["salt"] = secrets.token_hex(16)
        u["hash"] = config._hash_password(password, u["salt"])
    if disabled is not None:
        u["disabled"] = bool(disabled)
    _store(users)
    return {"ok": True}


def delete(username: str, _hosting: bool = False) -> dict:
    users = _all()
    if username == owner():
        raise PanelUserError("The owner can't be deleted")
    if any(u["username"] == username and u.get("account") for u in users) and not _hosting:
        raise PanelUserError("This is a hosting account's login — terminate the account under Hosting → Accounts")
    if not any(u["username"] == username for u in users):
        raise PanelUserError("Unknown user")
    _store([u for u in users if u["username"] != username])
    return {"ok": True}


def touch(username: str) -> None:
    users = _all()
    for u in users:
        if u["username"] == username:
            u["last_login"] = int(time.time())
            _store(users)
            return


def change_own_password(username: str, current: str, new: str) -> dict:
    if not verify(username, current):
        raise PanelUserError("The current password is wrong")
    return update(username, password=new)
