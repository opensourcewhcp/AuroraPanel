"""Permissions — the one place that decides what a Viewer or Website manager may do.

Three layers, each the fallback for the one above:
  1. CAPABILITIES   the fixed catalogue: every toggle, the route group it gates, and its default.
  2. role defaults  an administrator's per-role overrides of those defaults (GET/POST /api/role-caps),
                    stored under "role_caps" in the config.
  3. groups         named presets an administrator builds (perm_groups) and assigns to a user. A group
                    refines one base role (viewer or site); its toggles win for members, and a member's
                    effective role is the group's base role.

A user with no group falls back to the role defaults. authz.py asks this module whether a request's
route is gated by a capability and reads the caller's effective toggles; it never decides policy itself.

site capabilities ALLOW their route group when on (a website manager is otherwise refused everything).
viewer capabilities DENY their route group when off (a viewer may otherwise read any page). So a site
toggle that names no route grants nothing, and a viewer toggle that names no route hides nothing.
"""
from __future__ import annotations

import re
import time

from . import config

# key -> {label, default, get?, post?}. get/post are full-match patterns for the routes the key gates.
CAPABILITIES: dict[str, dict[str, dict]] = {
    "site": {
        "files":         {"label": "File Manager", "default": True,
                          "get": r"/api/files/(list|read|download)", "post": r"/api/files/(write|delete|mkdir|upload)"},
        "files_archive": {"label": "Create and extract zip archives", "default": False,
                          "post": r"/api/files/(zip|unzip)"},
        "mail_accounts": {"label": "Manage mail accounts", "default": True,
                          "get": r"/api/mail/accounts(/device|/mobileconfig)?", "post": r"/api/mail/accounts/(create|update|delete)"},
        "metrics":       {"label": "Site metrics", "default": True,
                          "get": r"/api/metrics/(sites|visitors|analytics|errors)"},
    },
    "viewer": {
        "dns_zones":   {"label": "Read DNS zone files", "default": False, "get": r"/api/domains/zone"},
        "apache_conf": {"label": "Read Apache config (.htaccess, indexes, MIME, error pages, handlers)", "default": False,
                        "get": r"/api/apache/(htaccess|indexes|mime|errors|handlers)"},
        "disk_usage":  {"label": "See disk usage", "default": True, "get": r"/api/diskusage"},
    },
}

ROLE_LABELS = {"viewer": "Viewer (read-only)", "site": "Website manager"}
_GROUP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}$")


class PermissionError(RuntimeError):
    pass


def label(role: str, key: str) -> str:
    try:
        return CAPABILITIES[role][key]["label"]
    except KeyError:
        return key


def default(role: str, key: str) -> bool:
    return bool(CAPABILITIES[role][key]["default"])


# --------------------------------------------------------------------------- #
# Layer 2: per-role defaults (role_caps)
# --------------------------------------------------------------------------- #
def _role_overrides() -> dict:
    ov = config.load_config().get("role_caps", {})
    return ov if isinstance(ov, dict) else {}


def capabilities(role: str) -> dict[str, bool]:
    """Effective on/off for every capability of a role: defaults with the admin's role overrides on top."""
    reg = CAPABILITIES.get(role, {})
    ov = _role_overrides().get(role, {})
    ov = ov if isinstance(ov, dict) else {}
    return {k: bool(ov.get(k, spec["default"])) for k, spec in reg.items()}


def set_cap(role: str, key: str, enabled: bool) -> dict:
    """Turn one capability on or off for a whole role (the fallback for users with no group)."""
    if role not in CAPABILITIES:
        raise PermissionError("Unknown role")
    if key not in CAPABILITIES[role]:
        raise PermissionError("Unknown capability")
    cfg = config.load_config()
    rc = cfg.get("role_caps")
    rc = dict(rc) if isinstance(rc, dict) else {}
    role_map = dict(rc.get(role, {})) if isinstance(rc.get(role), dict) else {}
    role_map[key] = bool(enabled)
    rc[role] = role_map
    cfg["role_caps"] = rc
    config.save_config(cfg)
    return {"ok": True, "role": role, "key": key, "enabled": bool(enabled)}


def cap_for(role: str, method: str, path: str) -> str | None:
    """The capability key whose route group covers this request, or None."""
    want = "post" if method == "POST" else "get"
    for key, spec in CAPABILITIES.get(role, {}).items():
        rx = spec.get(want)
        if rx and re.fullmatch(rx, path):
            return key
    return None


# --------------------------------------------------------------------------- #
# Layer 3: named groups (perm_groups)
# --------------------------------------------------------------------------- #
def _groups() -> list[dict]:
    g = config.load_config().get("perm_groups", [])
    return g if isinstance(g, list) else []


def _store_groups(groups: list[dict]) -> None:
    cfg = config.load_config()
    cfg["perm_groups"] = groups
    config.save_config(cfg)


def _clean_caps(role: str, caps: dict | None) -> dict:
    reg = CAPABILITIES.get(role, {})
    return {k: bool(v) for k, v in (caps or {}).items() if k in reg}


def group(name: str) -> dict | None:
    return next((g for g in _groups() if g.get("name") == name), None)


def group_names() -> list[str]:
    return [g["name"] for g in _groups()]


def create_group(name: str, role: str, caps: dict | None = None) -> dict:
    name = (name or "").strip()
    if not _GROUP_NAME.match(name):
        raise PermissionError("Group name: 1 to 48 letters, digits, space, dot, dash or underscore")
    if role not in CAPABILITIES:
        raise PermissionError("Base role must be a viewer or a website manager")
    if group(name):
        raise PermissionError("That group name is taken")
    groups = _groups()
    groups.append({"name": name, "role": role, "caps": _clean_caps(role, caps), "created": int(time.time())})
    _store_groups(groups)
    return {"ok": True}


def update_group(name: str, role: str | None = None, caps: dict | None = None, new_name: str | None = None) -> dict:
    groups = _groups()
    g = next((x for x in groups if x.get("name") == name), None)
    if not g:
        raise PermissionError("Unknown group")
    if role is not None:
        if role not in CAPABILITIES:
            raise PermissionError("Base role must be a viewer or a website manager")
        g["role"] = role
        g["caps"] = _clean_caps(role, g.get("caps"))  # drop toggles that don't belong to the new base role
    if caps is not None:
        g["caps"] = _clean_caps(g["role"], caps)
    if new_name and new_name.strip() != name:
        nn = new_name.strip()
        if not _GROUP_NAME.match(nn):
            raise PermissionError("Group name: 1 to 48 letters, digits, space, dot, dash or underscore")
        if group(nn):
            raise PermissionError("That group name is taken")
        g["name"] = nn
        from . import panelusers
        panelusers.rename_group(name, nn)
    _store_groups(groups)
    return {"ok": True}


def delete_group(name: str) -> dict:
    groups = _groups()
    if not any(g.get("name") == name for g in groups):
        raise PermissionError("Unknown group")
    from . import panelusers
    members = panelusers.group_members(name)
    if members:
        raise PermissionError(f"That group is assigned to {len(members)} user(s); reassign them first")
    _store_groups([g for g in groups if g.get("name") != name])
    return {"ok": True}


def resolve_group(name: str) -> dict | None:
    """A group's base role and full effective toggles (role defaults with the group's overrides on top)."""
    g = group(name)
    if not g:
        return None
    role = g.get("role")
    if role not in CAPABILITIES:
        return None
    caps = capabilities(role)
    caps.update({k: bool(v) for k, v in (g.get("caps") or {}).items() if k in caps})
    return {"role": role, "caps": caps}


# --------------------------------------------------------------------------- #
# For the admin UI
# --------------------------------------------------------------------------- #
def catalogue() -> dict:
    """Every role's capabilities (label plus current role-level value) and the defined groups."""
    caps = {}
    for role, reg in CAPABILITIES.items():
        eff = capabilities(role)
        caps[role] = [{"key": k, "label": reg[k]["label"], "enabled": eff[k], "default": reg[k]["default"]} for k in reg]
    return {"roles": ROLE_LABELS, "capabilities": caps, "groups": _groups()}
