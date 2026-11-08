"""Panel users — more people than the owner, each with the right amount of power.

Roles:
  admin   — everything (the owner set up at first run is always admin)
  viewer  — can look at every page, can't change anything or read secrets
  site    — "website manager": only their own websites — files, email accounts of those domains,
            visitors/analytics/errors — nothing else on the server.

Passwords are PBKDF2-hashed like the owner's. Sessions name the user; their role is looked up on every
request, so changing or deleting a user takes effect at once.
"""
from __future__ import annotations

import re
import secrets
import time

from . import config

ROLES = {"admin": "Administrator", "viewer": "Viewer (read-only)", "site": "Website manager"}
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


def name_taken(username: str) -> bool:
    """Any panel account (the owner, active or disabled users) already called that."""
    return username == owner() or any(u.get("username") == username for u in _all())


def get(username: str) -> dict | None:
    """{username, role, sites} for an active user (the owner included), else None.

    When the user is in a permission group, their effective role is the group's base role and their
    resolved capability toggles ride along as "_caps" for authz to read.
    """
    if not username:
        return None
    if username.startswith("token:"):
        return {"username": username, "role": "admin", "sites": []}  # API tokens are made by an admin
    if username == owner():
        return {"username": username, "role": "admin", "sites": [], "owner": True}
    for u in _all():
        if u["username"] == username and not u.get("disabled"):
            role, sites, grp = u["role"], u.get("sites", []), u.get("group") or None
            out = {"username": username, "role": role, "sites": sites}
            if grp:
                from . import permissions
                res = permissions.resolve_group(grp)
                if res:  # a live group: its base role and toggles win
                    out["role"] = res["role"]
                    out["group"] = grp
                    out["_caps"] = res["caps"]
                # a group that was deleted falls back to the user's stored role
            return out
    return None


def verify(username: str, password: str) -> bool:
    for u in _all():
        if u["username"] == username:
            ok = secrets.compare_digest(config._hash_password(password, u["salt"]), u["hash"])
            return ok and not u.get("disabled")
    config._hash_password(password, "00" * 16)  # same time for unknown names
    return False


def retired(username: str) -> bool:
    """Is this account on a role that no longer exists? It stays refused until an administrator picks a new one."""
    return any(u["username"] == username and u.get("role") not in ROLES for u in _all())


def listing() -> dict:
    out = [{"username": owner(), "role": "admin", "owner": True, "sites": [], "created": None}]
    for u in _all():
        out.append({k: u.get(k) for k in ("username", "role", "sites", "group", "created", "disabled", "last_login")})
    return {"users": out, "roles": ROLES}


def group_members(name: str) -> list[str]:
    """Usernames currently assigned to a permission group."""
    return [u["username"] for u in _all() if u.get("group") == name]


def rename_group(old: str, new: str) -> None:
    """Point every member of a renamed group at the new name (called by permissions.update_group)."""
    users = _all()
    changed = False
    for u in users:
        if u.get("group") == old:
            u["group"] = new
            changed = True
    if changed:
        _store(users)


def _resolve_group(role: str, group: str | None) -> tuple[str, str | None]:
    """A group pins the base role; without one, the given role stands."""
    if group:
        from . import permissions
        g = permissions.group(group)
        if not g:
            raise PanelUserError("Unknown permission group")
        return g["role"], group
    return role, None


def _sites_ok(sites: list[str]) -> list[str]:
    from . import sites as S
    known = {s["server_name"] for s in S.list_sites().get("sites", []) if not s.get("system")}
    bad = [x for x in sites if x not in known]
    if bad:
        raise PanelUserError(f"Unknown website: {', '.join(bad)}")
    return sorted(set(sites))


def create(username: str, password: str, role: str, sites: list[str] | None = None, group: str | None = None) -> dict:
    username = (username or "").strip()
    if not _NAME.match(username):
        raise PanelUserError("User name: 2–64 letters, digits, dot, dash, underscore or @")
    if username == owner() or any(u["username"] == username for u in _all()):
        raise PanelUserError("That user name is taken")
    role, group = _resolve_group(role, group)
    if role not in ROLES:
        raise PanelUserError("Unknown role")
    if len(password or "") < 10:
        raise PanelUserError("Use a password of at least 10 characters")
    sites = _sites_ok(sites or []) if role == "site" else []
    if role == "site" and not sites:
        raise PanelUserError("Pick at least one website for a website manager")
    salt = secrets.token_hex(16)
    entry = {"username": username, "role": role, "sites": sites, "salt": salt,
             "hash": config._hash_password(password, salt), "created": int(time.time())}
    if group:
        entry["group"] = group
    users = _all()
    users.append(entry)
    _store(users)
    return {"ok": True}


def update(username: str, role: str | None = None, sites: list[str] | None = None, password: str | None = None,
           disabled: bool | None = None, group: str | None = None) -> dict:
    users = _all()
    u = next((x for x in users if x["username"] == username), None)
    if not u:
        raise PanelUserError("Unknown user" if username != owner() else "The owner is changed under Password & Security")
    # group: None leaves it as-is, "" clears it, a name assigns it (and pins the base role).
    if group is not None:
        if group == "":
            u.pop("group", None)
        else:
            pinned_role, _ = _resolve_group(u["role"], group)
            u["group"] = group
            u["role"] = pinned_role
    if role is not None:
        if role not in ROLES:
            raise PanelUserError("Unknown role")
        u["role"] = role
        if u.get("group"):  # an explicit role must agree with the assigned group's base role
            from . import permissions
            g = permissions.group(u["group"])
            if g and g["role"] != role:
                raise PanelUserError("That role does not match the assigned group; clear the group first")
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


def delete(username: str) -> dict:
    users = _all()
    if username == owner():
        raise PanelUserError("The owner can't be deleted")
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
