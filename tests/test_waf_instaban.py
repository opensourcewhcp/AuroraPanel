"""InstaBan's list inside the WAF: what is on the list is refused before it is served, not after the log shows it."""
import re
import subprocess

import pytest

from backend import instaban, nginxsites, nginxwaf, waf

HAND_OVER = instaban._sync_waf   # the suite switches it off everywhere else (conftest), so no test reloads a real Apache
OWN_ADDRESSES = waf.server_ips   # likewise: the machine the suite runs on stays out of every other test

LIST = {"contains": ["/.env", "union select", "#fragment"], "starts": ["/old-admin/", '/a"b\\c'], "ua": ["sqlmap"],
        "ip": ["203.0.113.9/32", "198.51.100.0/24", "not an address"], "regex": [r'\.php\?.*=\.\./', r'a\\b"c%{tx.x}\"d\%']}


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setattr(waf, "STATE", tmp_path / "waf.json")
    monkeypatch.setattr(waf, "_panel_trusted", lambda: ["192.168.0.2"])
    monkeypatch.setattr(instaban, "STATE", tmp_path / "instaban.json")
    return waf.load()


def test_the_firewall_enforces_the_list_with_or_without_automatic_bans(state, monkeypatch):
    monkeypatch.setattr(instaban, "_sync_waf", lambda: None)
    assert instaban.load()["enabled"] is False                      # Auto-ban off: nobody is banned on their own
    assert "/.env" in waf.instaban_lists()["contains"] and "id:1000112" in waf.render_pre(state)   # the door is shut all the same
    instaban.set_settings(enabled=True)
    assert "id:1000112" in waf.render_pre(state)
    assert "InstaBan" not in waf.render_pre(state, {}) and "aurora-instaban" not in waf.render_pre(state, {})   # an empty list adds nothing


def test_the_list_becomes_rules_that_refuse_before_anything_is_served(state, monkeypatch):
    monkeypatch.setattr(instaban, "_sync_waf", lambda: None)
    instaban.set_settings(enabled=True)
    instaban.add_pattern("/Secret/", "starts")
    instaban.add_pattern("203.0.113.9", "ip")
    ib = waf.instaban_lists()
    assert "/.git/" in ib["contains"] and "sqlmap" in ib["ua"] and ib["starts"] == ["/secret/"] and ib["ip"] == ["203.0.113.9/32"]
    pre = waf.render_pre(state)
    rules = [line for line in pre.splitlines() if "InstaBan" in line]
    assert len(rules) == 5 and all("phase:1,deny,status:403,log,auditlog" in r for r in rules)   # phase 1: ahead of redirects and of the file
    # Trusted addresses are let through first; the list comes last.
    assert pre.index("id:1000101") < pre.index("id:1000110") < pre.index("id:1000113")
    paths = waf.IB_PATHS.as_posix()
    assert f'SecRule REQUEST_URI "@pmFromFile {paths}" "id:1000112,phase:1,deny,status:403,log,auditlog,t:none,t:lowercase,' in pre   # as sent ("wget+http")
    assert f'SecRule REQUEST_URI "@pmFromFile {paths}" "id:1000113,phase:1,deny,status:403,log,auditlog,t:none,t:urlDecodeUni,t:urlDecodeUni,t:lowercase,' in pre   # and decoded twice, like InstaBan
    assert f'SecRule REQUEST_HEADERS:User-Agent "@pmFromFile {waf.IB_UA.as_posix()}" "id:1000111,' in pre
    assert f'SecRule REMOTE_ADDR "@ipMatchFromFile {waf.IB_IPS.as_posix()}" "id:1000110,' in pre
    assert r'"@rx ^(?:/secret/)" "id:1001000,' in pre
    files = waf.instaban_files(ib)
    assert "/.git/\n" in files[waf.IB_PATHS] and "sqlmap\n" in files[waf.IB_UA] and files[waf.IB_IPS] == "203.0.113.9\n"   # a single address goes in bare
    # Detect only keeps the same rules: the engine's mode decides whether they refuse or just log.
    assert "SecRuleEngine DetectionOnly" in waf.render_pre({**state, "mode": "detect"}) and "id:1000112" in waf.render_pre({**state, "mode": "detect"})


def test_patterns_cannot_break_out_of_the_rule_they_are_written_into(state):
    pre = waf.render_pre(state, LIST)
    rules = [line for line in pre.splitlines() if "InstaBan" in line]
    for r in rules:   # every rule is one line with exactly its own quotes: operator and actions
        assert r.count('"') == 4 and "\\\\" not in r and "%{" not in r, r
    assert r'"@rx ^(?:/old-admin/|/a\x22b\x5cc)" "id:1001000,' in pre                    # plain text, as character codes
    assert r'"@rx (?i)\.php\?.*=\.\./" "id:1002000,' in pre                               # an ordinary expression is left as written
    assert r'"@rx (?i)a\x5cb\x22c\x25{tx.x}\x22d\x25" "id:1002001,' in pre                # backslash, quote and percent as codes
    for original, rule_id in ((LIST["regex"][0], 1002000), (LIST["regex"][1], 1002001)):   # and they still mean the same thing
        written = re.search(rf'"@rx \(\?i\)(.*)" "id:{rule_id},', pre).group(1)
        for probe in ("/index.php?page=../../etc/passwd", 'a\\b"c%{tx.x}"d%', "/blog/hello"):
            assert bool(re.search(original, probe, re.I)) == bool(re.search(written, probe, re.I))
    files = waf.instaban_files(LIST)
    assert files[waf.IB_PATHS] == "/.env\nunion select\n"                                 # "#..." would be a comment in the list file
    assert files[waf.IB_IPS] == "203.0.113.9\n198.51.100.0/24\n"
    assert "id:1002000" not in waf.render_pre(state, LIST, regex=False) and "id:1001000" in waf.render_pre(state, LIST, regex=False)


def test_a_long_list_is_split_over_several_rules(state, monkeypatch):
    monkeypatch.setattr(waf, "IB_RX_CHUNK", 20)
    rules = waf._instaban_rules({"starts": [f"/folder-number-{n}/" for n in range(5)]})
    assert [re.search(r"id:(\d+)", r).group(1) for r in rules] == ["1001000", "1001001", "1001002"]
    assert rules[0].count("/folder-number-") == 2 and rules[2].count("/folder-number-") == 1


@pytest.fixture
def apache(tmp_path, monkeypatch, state):
    etc = tmp_path / "modsecurity"
    etc.mkdir()
    for name, value in (("PRE", etc / "zz-aurora-waf.conf"), ("POST", tmp_path / "post.conf"), ("MAIN", etc / "modsecurity.conf"),
                        ("RECOMMENDED", etc / "missing"), ("IB_PATHS", etc / "paths.txt"), ("IB_UA", etc / "agents.txt"), ("IB_IPS", etc / "addresses.txt")):
        monkeypatch.setattr(waf, name, value)
    box = {"refuse": lambda: False, "calls": []}

    def run(argv, timeout=60, input=None):
        box["calls"].append(" ".join(argv))
        bad = argv[:2] == ["apache2ctl", "configtest"] and box["refuse"]()
        return subprocess.CompletedProcess(argv, 1 if bad else 0, "", "AH00526: Error creating rule: Error compiling pattern" if bad else "")
    monkeypatch.setattr(waf, "_run", run)
    monkeypatch.setattr(waf, "installed", lambda: True)
    monkeypatch.setattr(waf, "_refresh_nginx", lambda: None)
    monkeypatch.setattr(waf, "instaban_lists", lambda: LIST)
    real = waf.Path.write_text
    # apply() also writes the sites-off list to a fixed /etc path: that one stays inside the test folder.
    monkeypatch.setattr(waf.Path, "write_text", lambda self, text, *a, **k: real(etc / self.name if self.name == "aurora-sites-off.txt" else self, text, *a, **k))
    return box


def test_apply_writes_the_list_files_with_the_rules_and_reloads_once(apache):
    assert waf.apply() == {"ok": True}
    assert waf.IB_PATHS.read_text() == "/.env\nunion select\n" and waf.IB_UA.read_text() == "sqlmap\n"
    assert "id:1002001" in waf.PRE.read_text(encoding="utf-8")
    assert apache["calls"].count("apache2ctl configtest") == 1 and apache["calls"][-1] == "systemctl reload apache2"


def test_a_regular_expression_apache_refuses_is_left_out_not_the_whole_waf(apache):
    apache["refuse"] = lambda: "id:1002000" in waf.PRE.read_text(encoding="utf-8")
    assert waf.apply() == {"ok": True}
    pre = waf.PRE.read_text(encoding="utf-8")
    assert "id:1002000" not in pre and "id:1000112" in pre and "id:1001000" in pre   # the rest of the list is still enforced
    assert apache["calls"].count("apache2ctl configtest") == 2 and "systemctl reload apache2" in apache["calls"]


def test_a_refusal_for_any_other_reason_puts_everything_back(apache):
    waf.PRE.write_text("# before\n", encoding="utf-8")
    waf.IB_PATHS.write_text("/old\n", encoding="utf-8")
    apache["refuse"] = lambda: True
    with pytest.raises(waf.WafError, match="nothing changed"):
        waf.apply()
    assert waf.PRE.read_text(encoding="utf-8") == "# before\n" and waf.IB_PATHS.read_text(encoding="utf-8") == "/old\n"
    assert not waf.IB_UA.exists() and "systemctl reload apache2" not in apache["calls"]


def test_the_waf_page_names_these_hits_and_will_not_switch_the_list_off(state, monkeypatch):
    assert waf._category("1000112") == waf._category("1002003") == "Ban list" and waf._category("941100") == "XSS (cross-site scripting)"
    monkeypatch.setattr(waf, "apply", lambda s=None: pytest.fail("the list must not be switched off as a false alarm"))
    with pytest.raises(waf.WafError, match="InstaBan"):
        waf.allow_rule("1000112", "InstaBan: path or payload on the list")


def test_instaban_hands_the_list_over_when_it_or_the_switch_changes(state, monkeypatch):
    synced = []
    monkeypatch.setattr(instaban, "_sync_waf", lambda: synced.append(1))
    instaban.set_settings(enabled=True)
    assert len(synced) == 1
    instaban.set_settings(ttl="7d", report=True)
    instaban.set_settings(enabled=True)
    assert len(synced) == 1                      # nothing the WAF reads changed
    e = instaban.add_pattern("/backup.zip")
    assert len(synced) == 2
    assert instaban.import_patterns("/backup.zip\n")["added"] == 0 and len(synced) == 2   # already there
    assert instaban.import_patterns("/dump.sql\nstarts:/old-shop/\n")["added"] == 2 and len(synced) == 3   # one reload for the lot
    instaban.delete_pattern(e["id"])
    instaban.set_settings(enabled=False)
    assert len(synced) == 5


def test_handing_over_needs_a_waf_and_never_fails_the_change(state, monkeypatch):
    applied = []
    monkeypatch.setattr(waf, "installed", lambda: False)
    monkeypatch.setattr(waf, "module_on", lambda: True)
    monkeypatch.setattr(waf, "apply", lambda s=None: applied.append(1))
    monkeypatch.setattr(instaban, "_sync_waf", HAND_OVER)
    instaban._sync_waf()
    assert applied == []                          # no WAF on this server: InstaBan works from the log alone
    monkeypatch.setattr(waf, "installed", lambda: True)
    instaban._sync_waf()
    assert applied == [1]

    def refuse(s=None):
        raise waf.WafError("Apache rejected the WAF settings")
    monkeypatch.setattr(waf, "apply", refuse)
    assert instaban.add_pattern("/another.zip")["pattern"] == "/another.zip"   # saved, and the owner is told why the WAF lags behind


def test_nginx_gets_the_same_list_and_the_same_way_out(tmp_path, monkeypatch, state):
    etc = tmp_path / "modsecurity"
    for name, value in (("IB_PATHS", etc / "paths.txt"), ("IB_UA", etc / "agents.txt"), ("IB_IPS", etc / "addresses.txt")):
        monkeypatch.setattr(waf, name, value)
    for name in ("DIR", "MAIN", "PRE", "POST", "HOOK"):
        monkeypatch.setattr(nginxwaf, name, tmp_path / "nginx" / f"{name.lower()}.conf")
    (tmp_path / "nginx").mkdir()
    monkeypatch.setattr(nginxwaf, "module_installed", lambda: True)
    monkeypatch.setattr(nginxwaf, "find_crs", lambda: ("/etc/crs-setup.conf", ["/rules/REQUEST-901.conf"]))
    monkeypatch.setattr(waf, "instaban_lists", lambda: LIST)
    seen = []

    def apply(files):
        seen.append(files)
        if "id:1002000" in files[nginxwaf.PRE]:
            raise nginxsites.NginxError("Nginx rejected this, nothing changed")
    monkeypatch.setattr(nginxsites, "_apply", apply)
    nginxwaf._put("block")
    assert len(seen) == 2 and seen[0][waf.IB_PATHS] == "/.env\nunion select\n" and etc.is_dir()
    assert "id:1000112" in seen[1][nginxwaf.PRE] and "id:1002000" not in seen[1][nginxwaf.PRE] and "SecRuleEngine On" in seen[1][nginxwaf.PRE]
    monkeypatch.setattr(waf, "instaban_lists", lambda: {"contains": ["/.env"]})
    monkeypatch.setattr(nginxsites, "_apply", lambda files: (_ for _ in ()).throw(nginxsites.NginxError("refused")))
    with pytest.raises(nginxsites.NginxError):   # no expression to leave out: the refusal stands
        nginxwaf._put("block")


def test_this_servers_own_address_is_remembered_and_always_let_through(state, monkeypatch):
    from backend import guard
    monkeypatch.setattr(waf, "server_ips", OWN_ADDRESSES)
    monkeypatch.setattr(waf, "_OWN", {"at": 0.0, "ip": None})
    monkeypatch.setattr(guard, "default_route", lambda: {"ip": "192.0.2.10", "gateway": "192.0.2.1"})
    assert waf.server_ips(state) == ["192.0.2.10"]
    assert '@ipMatch 192.0.2.10,192.168.0.2"' in waf.render_pre(state)            # a site that calls itself is never refused
    monkeypatch.setattr(guard, "is_trusted", lambda ip: False)
    assert instaban._skip_ip("192.0.2.10") and not instaban._skip_ip("203.0.113.9")   # nor banned
    waf._save({**waf.load(), "trusted": ["203.0.113.0/24"]})
    assert instaban._skip_ip("203.0.113.9") and not instaban._skip_ip("198.51.100.1")   # the firewall's own trusted list counts for bans too
    waf._save({**waf.load(), "trusted": []})
    # The address can't be read for a moment (network restarting): the remembered one still counts.
    monkeypatch.setattr(waf, "_OWN", {"at": 0.0, "ip": None})
    monkeypatch.setattr(guard, "default_route", lambda: {"ip": None})
    assert waf.server_ips({"server_ips": ["192.0.2.10"]}) == ["192.0.2.10"] and waf.server_ips({}) == []
    # A new address replaces the old one, which may belong to someone else by now.
    monkeypatch.setattr(waf, "_OWN", {"at": 0.0, "ip": None})
    monkeypatch.setattr(guard, "default_route", lambda: {"ip": "192.0.2.77"})
    assert waf.server_ips({"server_ips": ["192.0.2.10"]}) == ["192.0.2.77"]


def test_the_page_can_ask_for_up_to_five_thousand_attacks_and_for_its_own_address(admin, monkeypatch):
    asked = []
    monkeypatch.setattr(waf, "events", lambda hours=24, limit=300, ip="": asked.append(limit) or [])
    for limit, got in ((None, 500), (5000, 5000), (999999, 5000), (0, 1)):
        assert admin.get("/api/waf/events" + (f"?limit={limit}" if limit is not None else "")).status_code == 200 and asked[-1] == got
    assert admin.get("/api/waf/you").json() == {"ip": "testclient"}
    assert instaban.MAX_HITS == 5000


def test_event_times_survive_the_doubled_sign_modsecurity_writes_west_of_greenwich():
    a = waf._ts("11/Nov/2026:11:17:14.400635 --0800")
    assert a and a == waf._ts("11/Nov/2026:11:17:14.400635 -0800") == waf._ts("11/Nov/2026:19:17:14.400635 +0000")
    assert waf._ts("11/Nov/2026:22:17:14 ++0300") == waf._ts("11/Nov/2026:19:17:14 +0000") and waf._ts("nonsense") == 0.0
