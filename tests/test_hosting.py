"""Hosting (WHM-style): plans, who sees which accounts, limits, safe names, and what each role may call."""
import pytest

from backend import authz, hosting, panelusers, sites


@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.setattr(hosting, "STATE", tmp_path / "hosting.json")
    monkeypatch.setattr(hosting, "HOME", tmp_path / "home")
    monkeypatch.setattr(hosting, "_audit", lambda *a: None)
    monkeypatch.setattr(sites, "list_sites", lambda: {"sites": [{"server_name": "taken.com", "aliases": ["www.taken.com"]}]})
    monkeypatch.setattr(hosting, "ready", lambda: {"apache": True, "php": True, "linux": True})
    monkeypatch.setattr(hosting, "pwd", None)
    return tmp_path


def as_user(u):
    authz.CURRENT.set(u)


@pytest.fixture(autouse=True)
def admin_by_default():
    tok = authz.CURRENT.set(None)
    yield
    authz.CURRENT.reset(tok)


def test_default_plans_and_plan_rules(host):
    d = hosting.listing()
    assert {"Starter", "Business", "Unlimited"} <= set(d["plans"])
    with pytest.raises(hosting.HostingError, match="Plan name"):
        hosting.save_plan("<b>", {})
    with pytest.raises(hosting.HostingError, match="PHP memory"):
        hosting.save_plan("Tiny", {"php_memory_mb": 8})
    hosting.save_plan("Tiny", {"disk_mb": 500, "sites": 1, "php_workers": 999})
    assert hosting.load()["plans"]["Tiny"]["php_workers"] == 64  # capped
    hosting.save_plan("Small", {"disk_mb": 600}, original="Tiny")  # rename
    assert "Tiny" not in hosting.load()["plans"] and "Small" in hosting.load()["plans"]


def test_plan_in_use_cant_be_deleted(host):
    d = hosting.load()
    d["accounts"]["alice"] = {"plan": "Starter", "domain": "a.com", "sites": ["a.com"], "owner": ""}
    hosting._save(d)
    with pytest.raises(hosting.HostingError, match="use this plan"):
        hosting.delete_plan("Starter")


def test_new_account_names_are_safe(host):
    for bad in ("root", "Admin", "a", "1abc", "site_x", "aurora1", "bob;rm", "x" * 17, "www"):
        with pytest.raises(hosting.HostingError):
            hosting.validate_new(bad, "new.com", "Starter", "long-enough-pw")
    with pytest.raises(hosting.HostingError, match="already has a website"):
        hosting.validate_new("bob", "www.taken.com", "Starter", "long-enough-pw")
    with pytest.raises(hosting.HostingError, match="Domain"):
        hosting.validate_new("bob", "not a domain", "Starter", "long-enough-pw")
    with pytest.raises(hosting.HostingError, match="10 characters"):
        hosting.validate_new("bob", "new.com", "Starter", "short")
    assert hosting.validate_new("bob", "WWW.New.com", "Starter", "long-enough-pw") == ("bob", "new.com")


def test_resellers_see_only_their_accounts_and_plans(host):
    panelusers.create("rita", "rita-password-1", "reseller")
    hosting.set_reseller("rita", ["Starter"], 1)
    d = hosting.load()
    d["accounts"]["alice"] = {"plan": "Starter", "domain": "a.com", "sites": ["a.com"], "owner": "rita"}
    d["accounts"]["bob"] = {"plan": "Business", "domain": "b.com", "sites": ["b.com"], "owner": ""}
    hosting._save(d)
    as_user(panelusers.get("rita"))
    ls = hosting.listing()
    assert [a["user"] for a in ls["accounts"]] == ["alice"] and list(ls["plans"]) == ["Starter"]
    assert "resellers" not in ls  # nothing about other resellers
    with pytest.raises(hosting.HostingError, match="No such account"):
        hosting.suspend("bob", True)
    with pytest.raises(hosting.HostingError, match="1 accounts"):
        hosting.validate_new("carl", "c.com", "Starter", "long-enough-pw")  # at her limit
    with pytest.raises(hosting.HostingError, match="your plans"):
        hosting.change_plan("alice", "Business")
    with pytest.raises(hosting.HostingError, match="administrator"):
        hosting.save_plan("Mine", {})


def test_account_login_cant_manage_hosting(host):
    panelusers.create("alice", "alice-password-1", "reseller")  # any panel user; role checked below
    as_user({"username": "alice", "role": "site", "account": "alice", "sites": ["a.com"]})
    with pytest.raises(hosting.HostingError):
        hosting.validate_new("zed", "z.com", "Starter", "long-enough-pw")
    with pytest.raises(hosting.HostingError):
        hosting.suspend("alice", True)


def test_mailbox_limit(host, monkeypatch):
    d = hosting.load()
    d["accounts"]["alice"] = {"plan": "Starter", "domain": "a.com", "sites": ["a.com"], "owner": ""}
    hosting._save(d)
    monkeypatch.setattr(hosting, "_mailboxes", lambda doms: [f"u{i}@a.com" for i in range(5)])
    with pytest.raises(hosting.HostingError, match="5 email"):
        hosting.check_mailbox_limit("new@a.com")
    hosting.check_mailbox_limit("new@other.com")  # not a hosting account's domain


def test_database_names_get_the_account_prefix(host):
    assert hosting._db_name("alice", "shop") == "alice_shop"
    assert hosting._db_name("alice", "alice_shop") == "alice_shop"
    for bad in ("", "shop;drop", "../x", "a" * 40):
        with pytest.raises(hosting.HostingError):
            hosting._db_name("alice", bad)


def test_over_limits_alerts(host):
    d = hosting.load()
    d["accounts"]["alice"] = {"plan": "Starter", "domain": "a.com", "sites": ["a.com"], "owner": ""}
    d["usage"]["alice"] = {"disk_bytes": 3000 * 1048576, "bandwidth_bytes": 1}
    hosting._save(d)
    out = hosting.over_limits()
    assert "quota:alice" in out and "bw:alice" not in out


def test_roles_reach_only_their_calls():
    rita = {"username": "rita", "role": "reseller"}
    assert authz._decide(rita, "GET", "/api/hosting") is None
    assert authz._decide(rita, "POST", "/api/hosting/accounts/create") is None
    assert authz._decide(rita, "POST", "/api/hosting/plans/save")  # plans are the admin's
    assert authz._decide(rita, "GET", "/api/files/list")
    assert authz._decide(rita, "GET", "/api/services")
    acct = {"username": "alice", "role": "site", "account": "alice", "sites": ["a.com"]}
    assert authz._decide(acct, "GET", "/api/hosting/me") is None
    assert authz._decide(acct, "POST", "/api/hosting/me/db/create") is None
    assert authz._decide(acct, "POST", "/api/hosting/accounts/create")
    assert authz._decide(acct, "GET", "/api/db/mysql")  # not the server's database page


def test_hosting_login_is_protected_in_panel_users(host):
    users = panelusers._all()
    users.append({"username": "alice", "role": "site", "sites": [], "salt": "00", "hash": "x", "account": "alice"})
    panelusers._store(users)
    with pytest.raises(panelusers.PanelUserError, match="Hosting"):
        panelusers.update("alice", role="admin")
    with pytest.raises(panelusers.PanelUserError, match="terminate"):
        panelusers.delete("alice")
    assert panelusers.get("alice")["account"] == "alice"
