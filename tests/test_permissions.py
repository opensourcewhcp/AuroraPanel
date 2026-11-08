"""Permissions: the capability catalogue, per-role toggles, named groups, how they ride through
authz for sessions and API tokens, and how panelusers resolves a member's effective access.

Everything runs against the throwaway config from conftest, so no real setting is touched.
"""
from __future__ import annotations

import pytest

from backend import authz, config, panelusers, permissions


# --------------------------------------------------------------------------- capabilities + defaults
def test_defaults_match_the_catalogue():
    s = permissions.capabilities("site")
    assert s == {"files": True, "files_archive": False, "mail_accounts": True, "metrics": True}
    v = permissions.capabilities("viewer")
    assert v == {"dns_zones": False, "apache_conf": False, "disk_usage": True}
    # the security-relevant reads and archive extraction start OFF
    assert permissions.default("viewer", "dns_zones") is False
    assert permissions.default("site", "files_archive") is False


def test_set_cap_persists_and_validates():
    assert permissions.capabilities("site")["files_archive"] is False
    permissions.set_cap("site", "files_archive", True)
    assert permissions.capabilities("site")["files_archive"] is True
    permissions.set_cap("site", "files_archive", False)
    assert permissions.capabilities("site")["files_archive"] is False
    with pytest.raises(permissions.PermissionError, match="Unknown role"):
        permissions.set_cap("admin", "files", True)
    with pytest.raises(permissions.PermissionError, match="Unknown capability"):
        permissions.set_cap("site", "nope", True)


def test_cap_for_maps_routes_to_keys():
    assert permissions.cap_for("site", "POST", "/api/files/unzip") == "files_archive"
    assert permissions.cap_for("site", "POST", "/api/files/write") == "files"
    assert permissions.cap_for("site", "GET", "/api/metrics/visitors") == "metrics"
    assert permissions.cap_for("viewer", "GET", "/api/domains/zone") == "dns_zones"
    assert permissions.cap_for("viewer", "GET", "/api/apache/htaccess") == "apache_conf"
    assert permissions.cap_for("viewer", "GET", "/api/diskusage") == "disk_usage"
    assert permissions.cap_for("site", "GET", "/api/system/overview") is None
    assert permissions.cap_for("viewer", "GET", "/api/system/overview") is None


# --------------------------------------------------------------------------- groups
def test_group_crud_and_validation():
    with pytest.raises(permissions.PermissionError, match="Base role"):
        permissions.create_group("X", "admin")
    with pytest.raises(permissions.PermissionError, match="Group name"):
        permissions.create_group("bad/name", "site")
    permissions.create_group("Light reseller", "site", {"files_archive": False, "metrics": False, "nope": True})
    g = permissions.group("Light reseller")
    assert g["role"] == "site" and g["caps"] == {"files_archive": False, "metrics": False}  # unknown key dropped
    with pytest.raises(permissions.PermissionError, match="taken"):
        permissions.create_group("Light reseller", "site")
    # toggles merge over the role defaults
    res = permissions.resolve_group("Light reseller")
    assert res == {"role": "site", "caps": {"files": True, "files_archive": False, "mail_accounts": True, "metrics": False}}


def test_group_update_role_change_drops_foreign_caps():
    permissions.create_group("G", "site", {"files": False})
    permissions.update_group("G", role="viewer")
    g = permissions.group("G")
    assert g["role"] == "viewer" and g["caps"] == {}   # site's "files" doesn't belong to a viewer group
    permissions.update_group("G", caps={"dns_zones": True})
    assert permissions.group("G")["caps"] == {"dns_zones": True}


def test_resolve_missing_group_is_none():
    assert permissions.resolve_group("ghost") is None


# --------------------------------------------------------------------------- authz: sessions
def test_viewer_zone_and_apache_reads_are_off_until_enabled():
    v = {"role": "viewer"}
    assert authz._decide(v, "GET", "/api/domains/zone")            # denied by default
    assert authz._decide(v, "GET", "/api/apache/htaccess")         # denied by default
    assert authz._decide(v, "GET", "/api/diskusage") is None       # on by default
    assert authz._decide(v, "GET", "/api/system/overview") is None # not a gated route
    permissions.set_cap("viewer", "dns_zones", True)
    assert authz._decide(v, "GET", "/api/domains/zone") is None    # admin turned it on


def test_site_archive_is_off_until_enabled_and_files_can_be_revoked():
    s = {"role": "site"}
    assert authz._decide(s, "POST", "/api/files/unzip")            # archive off by default
    assert authz._decide(s, "POST", "/api/files/write") is None    # files on by default
    assert authz._decide(s, "GET", "/api/metrics/visitors") is None
    permissions.set_cap("site", "files_archive", True)
    assert authz._decide(s, "POST", "/api/files/unzip") is None
    permissions.set_cap("site", "files", False)
    assert authz._decide(s, "POST", "/api/files/write")            # revoked
    assert authz._decide(s, "GET", "/api/files/list")


def test_group_caps_on_the_user_dict_win_over_role_defaults():
    # files_archive default is OFF; a group that turns it ON rides along as _caps
    u = {"role": "site", "_caps": {"files": True, "files_archive": True, "mail_accounts": False, "metrics": True}}
    assert authz._decide(u, "POST", "/api/files/unzip") is None    # group enabled it
    assert authz._decide(u, "POST", "/api/mail/accounts/create")   # group disabled mail


def test_admin_management_routes_are_deny_by_default_for_limited_roles():
    for role in ({"role": "viewer"}, {"role": "site"}):
        for m, p in (("GET", "/api/role-caps"), ("POST", "/api/role-caps"),
                     ("GET", "/api/perm-groups"), ("POST", "/api/perm-groups/update")):
            assert authz._decide(role, m, p), (role, m, p)


# --------------------------------------------------------------------------- authz: API tokens
def test_read_tokens_follow_viewer_toggles_and_cant_manage_permissions():
    # read token is bound by the same viewer capability switches
    assert authz.decide_token("read", "GET", "/api/domains/zone")           # off by default
    permissions.set_cap("viewer", "dns_zones", True)
    assert authz.decide_token("read", "GET", "/api/domains/zone") is None
    # no token level may touch the permission policy
    for lvl in ("admin", "unlimited"):
        assert authz.decide_token(lvl, "POST", "/api/role-caps")
        assert authz.decide_token(lvl, "POST", "/api/perm-groups")
        assert authz.decide_token(lvl, "POST", "/api/perm-groups/delete")


# --------------------------------------------------------------------------- panelusers resolution
def test_member_takes_the_groups_role_and_caps():
    permissions.create_group("Viewers plus zones", "viewer", {"dns_zones": True})
    panelusers.create("vz", "correct-horse-1", "viewer", group="Viewers plus zones")
    u = panelusers.get("vz")
    assert u["role"] == "viewer" and u["group"] == "Viewers plus zones"
    assert u["_caps"]["dns_zones"] is True
    # a member with that group may read zones even though the viewer default is off
    assert authz._decide(u, "GET", "/api/domains/zone") is None


def test_deleting_a_group_is_blocked_while_it_has_members_then_renaming_follows_them():
    permissions.create_group("Team", "viewer", {})
    panelusers.create("m1", "correct-horse-1", "viewer", group="Team")
    assert panelusers.group_members("Team") == ["m1"]
    with pytest.raises(permissions.PermissionError, match="assigned to"):
        permissions.delete_group("Team")
    permissions.update_group("Team", new_name="Team B")
    assert panelusers.get("m1")["group"] == "Team B"
    assert panelusers.group_members("Team B") == ["m1"]


def test_member_of_a_deleted_group_falls_back_to_stored_role():
    permissions.create_group("Temp", "viewer", {"dns_zones": True})
    panelusers.create("fb", "correct-horse-1", "viewer", group="Temp")
    # remove the group directly from storage (bypassing the member guard) to simulate a dangling ref
    cfg = config.load_config()
    cfg["perm_groups"] = []
    config.save_config(cfg)
    u = panelusers.get("fb")
    assert u["role"] == "viewer" and "group" not in u and "_caps" not in u
    assert authz._decide(u, "GET", "/api/domains/zone")   # back to the viewer default (off)


def test_assigning_a_site_group_requires_its_sites(monkeypatch):
    monkeypatch.setattr(panelusers, "_sites_ok", lambda s: sorted(set(s)))  # pretend the sites exist
    permissions.create_group("Resellers", "site", {"files_archive": True})
    panelusers.create("bob", "correct-horse-1", "site", sites=["a.test"], group="Resellers")
    u = panelusers.get("bob")
    assert u["role"] == "site" and u["sites"] == ["a.test"] and u["_caps"]["files_archive"] is True
    # clearing the group keeps the user a site manager on the stored role
    panelusers.update("bob", group="")
    assert "group" not in panelusers.get("bob")


# --------------------------------------------------------------------------- routes (admin client)
def test_admin_routes_round_trip(admin):
    cat = admin.get("/api/role-caps")
    assert cat.status_code == 200 and "capabilities" in cat.json()
    assert admin.post("/api/role-caps", json={"role": "site", "key": "files_archive", "enabled": True}).status_code == 200
    assert permissions.capabilities("site")["files_archive"] is True
    assert admin.post("/api/role-caps", json={"role": "x", "key": "y", "enabled": True}).status_code == 400

    assert admin.post("/api/perm-groups", json={"name": "Grp", "role": "site", "caps": {"metrics": False}}).status_code == 200
    groups = admin.get("/api/perm-groups").json()["groups"]
    assert any(g["name"] == "Grp" for g in groups)
    assert admin.post("/api/perm-groups/update", json={"name": "Grp", "new_name": "Grp2"}).status_code == 200
    assert admin.post("/api/perm-groups/delete", json={"name": "Grp2"}).status_code == 200
    assert not admin.get("/api/perm-groups").json()["groups"]
