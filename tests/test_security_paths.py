"""The security paths that never had tests: who may call what, API tokens, the ban/trust table,
the firewall's lock-out guards, SSH keys and service control. Every system tool is stubbed, so
these run anywhere, and the stubs record the exact commands so a wrong argument is a failure."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import subprocess
import sys
import time
import types

import pytest

from backend import apitokens, authz, config, firewall, guard, ipblocker, problems, services, sshaccess
from conftest import ADMIN, PASSWORD


# ------------------------------------------------------------------ authz: who may do what
def test_owner_on_the_installers_password_may_only_replace_it(monkeypatch):
    monkeypatch.setattr(config, "must_change_password", lambda: True)
    owner = {"owner": True, "role": "admin"}
    assert authz._decide(owner, "GET", "/api/system/overview") == "password_change_required"
    for p in ("/api/me", "/api/status", "/api/logout", "/api/account/password"):
        assert authz._decide(owner, "POST", p) is None
    monkeypatch.setattr(config, "must_change_password", lambda: False)
    assert authz._decide(owner, "GET", "/api/system/overview") is None


def test_admin_and_anonymous_pass_the_role_check():
    assert authz._decide({"role": "admin"}, "POST", "/api/anything") is None
    assert authz._decide(None, "POST", "/api/anything") is None   # the login dependency, not the role, decides


def test_viewer_reads_everything_but_secrets_and_changes_nothing():
    v = {"role": "viewer"}
    assert authz._decide(v, "GET", "/api/system/overview") is None
    for p in ("/api/files/read", "/api/backups/x/download", "/api/schedules/plans/p1/passphrase",
              "/api/docker/apps/a/secret", "/api/ddns-hosts/h/key", "/api/mail/accounts/mobileconfig",
              "/api/tokens", "/api/terminal", "/api/sysapps/x/file"):   # /api/tokens is the real route, not /api/apitokens
        assert authz._decide(v, "GET", p), p
    assert authz._decide(v, "POST", "/api/logout") is None
    assert authz._decide(v, "POST", "/api/me/password") is None
    assert authz._decide(v, "POST", "/api/firewall/enable") == "This account is read-only"
    assert authz._decide(v, "WS", "/api/terminal")


def test_site_manager_gets_only_its_own_tools():
    s = {"role": "site"}
    for m, p in (("GET", "/api/me"), ("GET", "/api/mysites"), ("GET", "/api/files/list"), ("POST", "/api/files/upload"),
                 ("GET", "/api/mail/accounts/device"), ("POST", "/api/mail/accounts/create"), ("GET", "/api/metrics/visitors"),
                 ("GET", "/api/jobs/abc-123")):
        assert authz._decide(s, m, p) is None, (m, p)
    for m, p in (("GET", "/api/system/overview"), ("POST", "/api/files/chmod"), ("GET", "/api/terminal"), ("POST", "/api/guard/ban"),
                 ("GET", "/api/files/listing")):   # the regex is anchored: no prefix tricks
        assert authz._decide(s, m, p) == "This account manages only its own websites", (m, p)
    assert authz._decide({"role": "weird"}, "GET", "/api/me") == "Unknown role"


def test_cross_origin_writes_must_come_from_the_panels_own_pages():
    co = authz.cross_origin
    assert co({"origin": "https://evil.example"}, False, "GET") is False          # reads are harmless
    assert co({"host": "pi:8088"}, False, "POST") is False                        # curl, tokens: no Origin
    assert co({"origin": "null", "host": "pi:8088"}, False, "POST") is True       # sandboxed or file: pages
    assert co({"origin": "https://pi:8088", "host": "pi:8088"}, False, "POST") is False
    assert co({"origin": "HTTPS://PI:8088/", "host": "pi:8088"}, False, "POST") is False
    assert co({"origin": "https://blog.pi", "host": "pi:8088"}, False, "POST") is True   # same site, other host: refused
    assert co({"origin": "https://pi", "host": "pi:443"}, False, "POST") is False         # default port left out
    assert co({"origin": "https://pi:443", "host": "pi"}, False, "POST") is False
    assert co({"origin": "https://pi.example", "host": "10.0.0.5:8088", "x-forwarded-host": "pi.example"}, False, "POST") is False
    assert co({"origin": "https://evil", "host": "pi:8088"}, True, "GET") is True          # a WebSocket is a write


def test_site_scope_limits_files_and_domains():
    from pathlib import Path
    token = authz.CURRENT.set({"role": "site", "sites": ["shop"],
                               "_scope": {"sites": ["shop"], "roots": [Path("/var/www/shop").resolve()], "domains": ["shop.example"]}})
    try:
        assert authz.scope()["domains"] == ["shop.example"]
        assert authz.in_roots(Path("/var/www/shop/index.php").resolve())
        assert not authz.in_roots(Path("/var/www/other").resolve())
        assert authz.domain_ok("Shop.example") and not authz.domain_ok("other.example")
    finally:
        authz.CURRENT.reset(token)
    assert authz.scope() is None and authz.in_roots(Path("/anything")) and authz.domain_ok("x")


# ------------------------------------------------------------------ API tokens
def test_api_tokens_are_shown_once_and_stored_hashed():
    with pytest.raises(apitokens.APITokenError):
        apitokens.create("  ")
    with pytest.raises(apitokens.APITokenError):
        apitokens.create("x" * 61)
    made = apitokens.create("backup script")
    assert made["token"].startswith("aur_") and len(made["token"]) > 20
    stored = config.load_config()["api_tokens"][0]
    assert made["token"] not in str(stored) and stored["hash"] == hashlib.sha256(made["token"].encode()).hexdigest()
    lst = apitokens.listing()["tokens"][0]
    assert set(lst) == {"id", "name", "prefix", "created"} and lst["prefix"] == made["token"][:12]
    assert apitokens.verify(made["token"]) == "backup script"
    assert apitokens.verify(made["token"][:-1] + "X") is None and apitokens.verify("") is None
    assert apitokens.revoke(made["id"]) == {"ok": True}
    assert apitokens.verify(made["token"]) is None
    with pytest.raises(apitokens.APITokenError):
        apitokens.revoke(made["id"])


def test_api_token_opens_the_api_until_revoked(admin, client):
    tok = admin.post("/api/tokens/create", json={"name": "ci"}).json()["token"]
    client.cookies.clear()
    assert client.get("/api/problems").status_code == 401
    assert client.get("/api/problems", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert client.get("/api/problems", headers={"X-Aurora-Token": tok}).status_code == 200
    assert client.get("/api/problems", headers={"Authorization": "Bearer aur_not-a-token"}).status_code == 401
    tid = apitokens.listing()["tokens"][0]["id"]
    apitokens.revoke(tid)
    assert client.get("/api/problems", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


# ------------------------------------------------------------------ guard: bans and trusted addresses (nft stubbed)
@pytest.fixture
def nft(tmp_path, monkeypatch):
    """guard with nftables, systemd and fail2ban replaced by recorders."""
    calls = []

    def run(args, check=True, input=None):
        calls.append(" ".join(args[1:]) if args and args[0] == "nft" else " ".join(args))
        return subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(guard, "_nft", lambda: "nft")
    monkeypatch.setattr(guard, "_run", run)
    monkeypatch.setattr(guard, "_table_exists", lambda: True)
    monkeypatch.setattr(guard, "_set_elements", lambda name: {})
    monkeypatch.setattr(guard, "_f2b_jails_by_ip", lambda: {})
    monkeypatch.setattr(guard, "_sync_fail2ban", lambda: None)
    monkeypatch.setattr(guard, "_sync_waf", lambda: None)
    monkeypatch.setattr(guard, "default_route", lambda: {"ip": "192.168.0.100", "gateway": "192.168.0.1"})
    monkeypatch.setattr(guard.shutil, "which", lambda *a, **k: None)   # no fail2ban-client
    monkeypatch.setattr(guard, "STATE", tmp_path / "guard.json")
    monkeypatch.setattr(guard, "NFT_FILE", tmp_path / "guard.nft")
    monkeypatch.setattr(guard, "UNIT", tmp_path / "aurora-guard.service")
    monkeypatch.setattr(guard, "BAN_HELPER", tmp_path / "aurora-guard-ban")
    return calls


def test_net_parsing_refuses_junk_and_oversized_ranges():
    assert str(guard._net(" 203.0.113.9 ")) == "203.0.113.9/32"
    assert str(guard._net("203.0.113.7/24")) == "203.0.113.0/24"   # host bits are forgiven
    for bad in ("", "pi", "203.0.113.0/7", "2001:db8::/8"):
        with pytest.raises(guard.GuardError):
            guard._net(bad)


def test_table_text_renders_sets_chain_and_timeouts():
    exp = int(time.time()) + 3600
    s = {"trusted": [{"cidr": "192.168.0.2/32"}, {"cidr": "2001:db8::/48"}],
         "bans": [{"cidr": "203.0.113.0/24", "expires": None}, {"cidr": "198.51.100.7/32", "expires": exp}]}
    t = guard._table_text(s)
    assert "elements = { 192.168.0.2 }" in t and "elements = { 2001:db8::/48 }" in t
    assert "203.0.113.0/24, 198.51.100.7 timeout 35" in t   # about 3600s left
    for line in ('iifname "lo" return', "ip saddr @trust4 return", "ip saddr @ban4 drop", "ip6 saddr @f2b6 drop",
                 "type filter hook input priority -20; policy accept;"):
        assert line in t
    assert t.index("@trust4 return") < t.index("@ban4 drop")   # trusted wins over banned


def test_ensure_writes_the_boot_unit_and_helper_once(nft):
    guard.ensure()
    assert guard.UNIT.exists() and "ExecStart=nft -f" in guard.UNIT.read_text() and guard.NFT_FILE.exists()
    helper = guard.BAN_HELPER.read_text()
    assert helper.startswith("#!/bin/sh") and "add element inet aurora_guard $set" in helper
    assert "systemctl enable aurora-guard.service" in nft
    n = len(nft)
    guard.ensure()
    assert len(nft) == n   # unit exists, table exists: nothing to do


def test_ban_refuses_what_would_lock_the_owner_out(nft):
    for target, why in (("127.0.0.1", "loopback"), ("192.168.0.100", "this Pi"), ("192.168.0.1", "your router"),
                        ("192.168.0.0/24", "this Pi"), ("10.0.0.9", "you")):
        with pytest.raises(guard.GuardError, match=why):
            guard.ban(target, client_ip="10.0.0.9")
    with pytest.raises(guard.GuardError, match="you"):
        guard.ban("10.0.0.9", client_ip="::ffff:10.0.0.9")   # IPv4 seen through an IPv6 socket
    assert guard.listing()["bans"] == []


def test_ban_records_and_programs_nft(nft):
    r = guard.ban("203.0.113.9", reason="  brute force  ", duration=3600, client_ip="10.0.0.9", source="InstaBan<script>")
    assert r["ban"]["reason"] == "brute force" and r["ban"]["source"] == "InstaBanscript" and r["replaced"] == []
    assert 3590 <= r["ban"]["expires"] - time.time() <= 3600
    assert "add element inet aurora_guard ban4 { 203.0.113.9 timeout 3600s }" in nft
    assert "ban4 { 203.0.113.9 timeout 3600s }" in guard.NFT_FILE.read_text().replace("\n", " ") or "203.0.113.9 timeout" in guard.NFT_FILE.read_text()
    with pytest.raises(guard.GuardError, match="Duration"):
        guard.ban("203.0.113.10", duration=30)
    with pytest.raises(guard.GuardError, match="Duration"):
        guard.ban("203.0.113.10", duration=11 * 365 * 86400)
    guard.ban("2001:db8::9", source="IP Blocker")
    assert "add element inet aurora_guard ban6 { 2001:db8::9 }" in nft
    lst = guard.listing()
    assert sorted(b["cidr"] for b in lst["bans"]) == ["2001:db8::9/128", "203.0.113.9/32"]
    assert lst["enabled"] is True and any("this Pi" in p for p in lst["protected"])


def test_wider_ban_replaces_narrower_and_already_covered_is_refused(nft):
    guard.ban("203.0.113.9")
    guard.ban("203.0.113.10")
    r = guard.ban("203.0.113.0/24")
    assert sorted(r["replaced"]) == ["203.0.113.10/32", "203.0.113.9/32"]
    assert "delete element inet aurora_guard ban4 { 203.0.113.9 }" in nft
    assert [b["cidr"] for b in guard.listing()["bans"]] == ["203.0.113.0/24"]
    with pytest.raises(guard.GuardError, match="Already covered"):
        guard.ban("203.0.113.77")
    assert guard.unban("203.0.113.0/24") == {"ok": True}
    assert "delete element inet aurora_guard ban4 { 203.0.113.0/24 }" in nft and guard.listing()["bans"] == []


def test_expired_bans_fall_out_of_the_state(nft):
    guard.ban("203.0.113.9", duration=60)
    s = guard._state()
    s["bans"][0]["expires"] = int(time.time()) - 1
    guard._save(s)
    assert guard.listing()["bans"] == []
    guard._save(guard._state())   # the next write of the boot file leaves it out too
    assert "203.0.113.9" not in guard.NFT_FILE.read_text()


def test_trust_lifts_bans_inside_it_and_bans_refuse_trusted(nft):
    guard.ban("203.0.113.9")
    r = guard.trust("203.0.113.0/24", note="office " + "x" * 200)
    assert r["unbanned"] == ["203.0.113.9/32"]
    assert "add element inet aurora_guard trust4 { 203.0.113.0/24 }" in nft
    t = guard.listing()["trusted"][0]
    assert t["cidr"] == "203.0.113.0/24" and len(t["note"]) == 120
    assert guard.is_trusted("203.0.113.200") and not guard.is_trusted("203.0.114.1") and not guard.is_trusted("junk")
    assert guard.trusted_cidrs() == ["203.0.113.0/24"]
    with pytest.raises(guard.GuardError, match="trusted"):
        guard.ban("203.0.113.9")
    with pytest.raises(guard.GuardError, match="Already trusted"):
        guard.trust("203.0.113.0/24")
    with pytest.raises(guard.GuardError, match="Overlaps"):
        guard.trust("203.0.113.5")
    assert guard.untrust("203.0.113.0/24") == {"ok": True}
    assert "delete element inet aurora_guard trust4 { 203.0.113.0/24 }" in nft and guard.trusted_cidrs() == []


def test_status_of_for_the_network_monitor(nft, monkeypatch):
    guard.ban("203.0.113.0/24")
    guard.trust("192.168.0.2")
    monkeypatch.setattr(guard, "_set_elements", lambda name: {"198.51.100.5": {"packets": 1, "expires_in": 10}} if name == "f2b4" else {})
    assert guard.status_of(["203.0.113.9", "192.168.0.2", "198.51.100.5", "8.8.8.8", "junk"]) == {
        "203.0.113.9": "banned", "192.168.0.2": "trusted", "198.51.100.5": "banned"}


def test_trust_changes_reach_fail2ban_and_the_waf(nft, monkeypatch):
    seen = []
    monkeypatch.setattr(guard, "_sync_fail2ban", lambda: seen.append("f2b"))
    monkeypatch.setattr(guard, "_sync_waf", lambda: seen.append("waf"))
    guard.trust("192.168.0.2")
    guard.untrust("192.168.0.2")
    assert seen == ["f2b", "waf", "f2b", "waf"]


def test_set_elements_reads_nft_json(monkeypatch):
    out = {"nftables": [{"metainfo": {}}, {"set": {"name": "ban4", "elem": [
        {"elem": {"val": "203.0.113.9", "counter": {"packets": 12}, "expires": 500}},
        {"elem": {"val": {"prefix": {"addr": "203.0.113.0", "len": 24}}, "counter": {"packets": 3}}},
        {"elem": {"val": {"range": ["10.0.0.1", "10.0.0.9"]}}},
        "198.51.100.1"]}}]}
    import json
    monkeypatch.setattr(guard, "_nft", lambda: "nft")
    monkeypatch.setattr(guard, "_run", lambda a, check=True, input=None: subprocess.CompletedProcess(a, 0, json.dumps(out), ""))
    got = guard._set_elements("ban4")
    assert got["203.0.113.9"] == {"packets": 12, "expires_in": 500}
    assert got["203.0.113.0/24"]["packets"] == 3 and "10.0.0.1-10.0.0.9" in got and got["198.51.100.1"]["packets"] == 0
    monkeypatch.setattr(guard, "_run", lambda a, check=True, input=None: subprocess.CompletedProcess(a, 1, "", "no table"))
    assert guard._set_elements("ban4") == {}


# ------------------------------------------------------------------ firewall: ufw with lock-out guards
UFW_ACTIVE = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8088/tcp                   ALLOW IN    Anywhere
[ 3] 80/tcp                     ALLOW IN    Anywhere
[ 4] Anywhere                   DENY IN     203.0.113.9
[ 5] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""


class _Calls(list):
    state: dict


@pytest.fixture
def ufw(monkeypatch):
    calls = _Calls()
    state = {"text": UFW_ACTIVE, "rc": 0, "err": ""}

    def run(argv, **kw):
        calls.append(" ".join(argv[1:]))
        if argv[1:3] == ["status", "numbered"]:
            return subprocess.CompletedProcess(argv, 0, state["text"], "")
        return subprocess.CompletedProcess(argv, state["rc"], "", state["err"])
    monkeypatch.setattr(firewall, "available", lambda: True)
    monkeypatch.setattr(firewall, "_ufw", lambda: "ufw")
    monkeypatch.setattr(firewall.subprocess, "run", run)
    monkeypatch.setattr(ipblocker.subprocess, "run", run)
    monkeypatch.setattr(firewall, "listening_ports", lambda: ["80/tcp", "22/tcp", "443/tcp"])
    monkeypatch.delenv("PORT", raising=False)
    calls.state = state
    return calls


def test_status_parses_numbered_rules(ufw):
    st = firewall.status()
    assert st["active"] and len(st["rules"]) == 5
    assert st["rules"][3] == {"num": 4, "rule": "Anywhere DENY IN 203.0.113.9"}
    ufw.state["text"] = "Status: inactive\n"
    assert firewall.status() == {"available": True, "active": False, "rules": []}


def test_enabling_allows_ssh_and_the_panel_before_the_switch(ufw):
    r = firewall.set_enabled(True)
    assert r == {"ok": True, "enabled": True, "preallowed": ["22/tcp", "8088/tcp", "80/tcp", "443/tcp"]}
    assert ufw[:4] == ["allow 22/tcp", "allow 8088/tcp", "allow 80/tcp", "allow 443/tcp"] and ufw[4] == "--force enable"
    assert firewall.set_enabled(False)["enabled"] is False and ufw[-1] == "disable"
    ufw.state.update(rc=1, err="ERROR: problem running ufw")
    with pytest.raises(firewall.FirewallError, match="problem running"):
        firewall.set_enabled(True)


def test_the_panel_port_follows_the_environment(ufw, monkeypatch):
    monkeypatch.setenv("PORT", "9443")
    assert firewall.guard_ports() == ["22", "9443"]


def test_deleting_the_rule_that_keeps_you_in_is_refused_while_active(ufw):
    for num in (1, 2, 5):
        with pytest.raises(firewall.FirewallError, match="lock you out"):
            firewall.delete_rule(num)
    assert firewall.delete_rule(3) == {"ok": True} and ufw[-1] == "--force delete 3"
    assert firewall.delete_rule(4) == {"ok": True}
    ufw.state["text"] = "Status: inactive\n[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
    assert firewall.delete_rule(1) == {"ok": True}   # inactive: nothing to lock out of
    for bad in (0, -1, "1", 1.5):
        with pytest.raises(firewall.FirewallError):
            firewall.delete_rule(bad)


def test_add_rule_validates_before_touching_ufw(ufw):
    for action, port, proto in (("drop", "80", "tcp"), ("allow", "0", "tcp"), ("allow", "65536", "tcp"), ("allow", "80;rm", "tcp"), ("allow", "80", "icmp")):
        with pytest.raises(firewall.FirewallError):
            firewall.add_rule(action, port, proto)
    assert ufw == []
    assert firewall.add_rule("limit", "2222", "tcp") == {"ok": True} and ufw[-1] == "limit 2222/tcp"
    ufw.state.update(rc=1, err="")
    with pytest.raises(firewall.FirewallError, match="ufw failed"):
        firewall.add_rule("allow", "53", "udp")


def test_ip_blocker_lists_denies_and_never_blocks_you(ufw):
    lst = ipblocker.list_blocked()
    assert lst["active"] and [b["source"] for b in lst["blocked"]] == ["203.0.113.9"]
    for bad in ("", "pi", "999.1.1.1"):
        with pytest.raises(ipblocker.IPBlockError, match="Invalid"):
            ipblocker.block(bad)
    for target in ("127.0.0.1", "10.0.0.0/8"):
        with pytest.raises(ipblocker.IPBlockError, match="lock yourself out"):
            ipblocker.block(target, client_ip="10.0.0.9")
    r = ipblocker.block("203.0.113.0/24", client_ip="10.0.0.9")
    assert r["ok"] and r["note"] is None and ufw[-2] == "deny from 203.0.113.0/24"
    ufw.state["text"] = "Status: inactive\n"
    assert "inactive" in ipblocker.block("198.51.100.1")["note"]
    assert ipblocker.unblock(4) == {"ok": True}


# ------------------------------------------------------------------ sshaccess: authorized_keys
ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxQk0QqE0b4oQ2y0p8bXHtq0n5m3Yd9o6t5Zr2y1wA9 me@laptop"


@pytest.fixture
def keys(tmp_path, monkeypatch):
    path = tmp_path / ".ssh" / "authorized_keys"
    monkeypatch.setattr(sshaccess, "IS_LINUX", True)
    monkeypatch.setattr(sshaccess, "_authorized_keys_path", lambda user: path)
    fake_pwd = types.SimpleNamespace(getpwnam=lambda u: (_ for _ in ()).throw(KeyError(u)))
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)   # no such account here: ownership step is skipped
    return path


def test_fingerprint_matches_openssh():
    b64 = ED25519.split()[1]
    want = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(b64)).digest()).decode().rstrip("=")
    assert sshaccess._fingerprint(b64) == want
    assert sshaccess._fingerprint("not base64!") == "?"


def test_keys_are_added_once_listed_and_removed(keys):
    with pytest.raises(sshaccess.SSHError, match="valid SSH public key"):
        sshaccess.add_key("a51", "ssh-rsa not*base64 x")
    assert sshaccess.add_key("a51", "  " + ED25519 + "\n") == {"ok": True}
    assert keys.read_text() == ED25519 + "\n"
    with pytest.raises(sshaccess.SSHError, match="already present"):
        sshaccess.add_key("a51", ED25519)
    keys.write_text(keys.read_text() + "# a comment\n\nssh-rsa AAAAB3NzaC1yc2E= old@box\n")
    lst = sshaccess.list_keys("a51")
    assert [k["type"] for k in lst["keys"]] == ["ssh-ed25519", "ssh-rsa"] and lst["keys"][0]["comment"] == "me@laptop"
    assert lst["keys"][0]["fingerprint"].startswith("SHA256:") and lst["keys"][0]["raw"] == ED25519
    with pytest.raises(sshaccess.SSHError, match="not found"):
        sshaccess.remove_key("a51", "ssh-rsa AAAA= nobody")
    assert sshaccess.remove_key("a51", ED25519) == {"ok": True}
    assert [k["type"] for k in sshaccess.list_keys("a51")["keys"]] == ["ssh-rsa"]
    assert sshaccess.remove_key("a51", "ssh-rsa AAAAB3NzaC1yc2E= old@box") == {"ok": True}
    assert keys.read_text() == "# a comment\n\n"
    keys.unlink()
    assert sshaccess.list_keys("a51")["keys"] == []
    with pytest.raises(sshaccess.SSHError, match="No authorized_keys"):
        sshaccess.remove_key("a51", ED25519)


def test_usernames_are_checked_before_any_lookup(monkeypatch):
    fake_pwd = types.SimpleNamespace(getpwnam=lambda u: (_ for _ in ()).throw(KeyError(u)))
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)
    for bad in ("", "Root", "a b", "../x", "x" * 33):
        with pytest.raises(sshaccess.SSHError, match="Invalid username"):
            sshaccess._authorized_keys_path(bad)
    with pytest.raises(sshaccess.SSHError, match="No such user"):
        sshaccess._authorized_keys_path("nobody-here")


def test_sshd_config_is_parsed_not_trusted_blindly(tmp_path, monkeypatch):
    cfg = tmp_path / "sshd_config"
    cfg.write_text("# Port 2222\nPort 2200\n\nPermitRootLogin prohibit-password\npasswordauthentication no\n")
    real = sshaccess.Path
    monkeypatch.setattr(sshaccess, "Path", lambda p: cfg if str(p) == "/etc/ssh/sshd_config" else real(p))
    assert sshaccess._sshd_config() == {"port": "2200", "permit_root_login": "prohibit-password", "password_auth": "no"}
    cfg.unlink()
    assert sshaccess._sshd_config()["port"] == "22"


# ------------------------------------------------------------------ services: systemctl
def test_unit_names_cannot_smuggle_arguments():
    for bad in ("", "-rf", "ssh --now", "a;b", "x/y", "nginx.service x"):
        with pytest.raises(services.ServiceError, match="Invalid service name"):
            services._validate_unit(bad)
    for ok in ("ssh", "nginx.service", "getty@tty1", "php8.2-fpm", "aurora-panel_x"):
        services._validate_unit(ok)


def test_control_and_status_go_through_systemctl(monkeypatch):
    calls = []
    out = {"rc": 0, "err": "", "stdout": ""}
    monkeypatch.setattr(services, "_systemctl_available", lambda: True)
    monkeypatch.setattr(services.subprocess, "run", lambda argv, **kw: (calls.append(argv), subprocess.CompletedProcess(argv, out["rc"], out["stdout"], out["err"]))[1])
    with pytest.raises(services.ServiceError, match="Unsupported action"):
        services.control_service("ssh", "mask")
    assert services.control_service("ssh", "restart") == {"unit": "ssh", "action": "restart", "ok": True}
    assert calls[-1] == ["systemctl", "restart", "ssh"]
    out.update(rc=1, err="Failed to restart ssh.service: Unit not found.")
    with pytest.raises(services.ServiceError, match="Unit not found"):
        services.control_service("ssh", "start")
    out.update(rc=0, stdout="● ssh.service - OpenBSD Secure Shell server\n   Active: active (running)\n")
    assert "active (running)" in services.service_status("ssh")["output"] and calls[-1][:3] == ["systemctl", "status", "ssh"]
    out["stdout"] = ("ssh.service loaded active running OpenBSD Secure Shell server\n"
                     "apache2.service loaded inactive dead The Apache HTTP Server\n"
                     "short line\n")
    lst = services.list_services()
    assert lst == [{"unit": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": "OpenBSD Secure Shell server"},
                   {"unit": "apache2.service", "load": "loaded", "active": "inactive", "sub": "dead", "description": "The Apache HTTP Server"}]
    monkeypatch.setattr(services.subprocess, "run", lambda argv, **kw: (_ for _ in ()).throw(OSError("boom")))
    with pytest.raises(services.ServiceError, match="boom"):
        services.list_services()


def test_without_systemctl_the_panel_degrades_clearly(monkeypatch):
    monkeypatch.setattr(services, "_systemctl_available", lambda: False)
    assert services.list_services() == []
    with pytest.raises(services.ServiceError, match="not available"):
        services.control_service("ssh", "start")
    with pytest.raises(services.ServiceError, match="not available"):
        services.service_status("ssh")


# ------------------------------------------------------------------ the swallowed-exception rewiring, end to end
def test_a_swallowed_exception_is_counted_not_lost():
    problems.clear()
    assert sshaccess._fingerprint("A") == "?"   # one character: not decodable
    q = problems.listing()["quiet"]
    assert len(q) == 1 and q[0]["where"].startswith("sshaccess._fingerprint:") and "Error" in q[0]["message"]
    problems.clear()
