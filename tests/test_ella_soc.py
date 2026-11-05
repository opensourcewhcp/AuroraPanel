"""WAF Ella stages 3 to 8: everything that doesn't need a real web server or firewall.
The real thing runs in tests/integration/ella_soc.py on a test server."""
import json
import socket
import sys
import time

import pytest

from backend import authz
from backend.ella import collector, correlate, fleet, housekeeping as H, intel as I, notify, proxies as P, query as Q, rulebook as R, supply
from backend.ella.db import Store


class FakeConfigs:
    def __init__(self, refuse=False):
        self.files, self.refuse = {}, refuse
        self.calls = []

    def apply(self, path, text, actor, **kw):
        self.calls.append((path, kw))
        if self.refuse:
            raise R.RuleError("server refused it")
        self.files[path] = text
        return {"ok": True}


SERVERS = [{"name": "nginx", "engine": "v3", "file": R.NGINX_FILE, "active": True}, {"name": "apache", "engine": "v2", "file": R.APACHE_FILE, "active": False}]


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path)


@pytest.fixture
def book(store):
    return R.RuleBook(store, FakeConfigs(), sites=lambda: [], servers=lambda: SERVERS, policy_defaults=lambda: {"paranoia": 1, "threshold": 5, "mode": "block"})


def event(**kw):
    e = {"hash": kw.pop("hash", None) or f"{time.time_ns():064x}"[-64:], "ts_event": time.time(), "ts_received": time.time(), "source": "nginx_access", "client_ip": "203.0.113.9", "peer_ip": "203.0.113.9", "domain": "shop.example", "method": "GET", "url": "/admin/x",
         "status": 200, "user_agent": "curl/8", "headers": "{}", "tags": "[]", "historical": 0, "missing_fields": "[]", "query_keys": "[]", "evidence": []}
    e.update(kw)
    return e


TREE = {"all": [{"field": "path", "op": "prefix", "value": "/admin"}, {"any": [{"field": "method", "op": "equals", "value": "POST"}, {"not": {"field": "user_agent", "op": "contains", "value": "curl"}}]}]}


# ---- conditions and compiling
def test_tree_expands_to_one_chain_per_way():
    t = R.check_tree(TREE)
    assert len(R.ways(t)) == 2
    text = "\n".join(R.render_tree_rule(R.ID_RULES, "x", t, ["shop.example"], "", "block", "block", 403, "t"))
    assert text.count("id:") == 2 and text.count("deny,status:403") == 2
    assert '!@contains curl' in text and "chain" in text


def test_not_of_any_is_all_of_nots():
    t = R.check_tree({"not": {"any": [{"field": "method", "op": "equals", "value": "GET"}, {"field": "method", "op": "equals", "value": "HEAD"}]}})
    w = R.ways(t)
    assert len(w) == 1 and len(w[0]) == 2 and all(c["negate"] for c in w[0])


def test_detect_mode_never_denies():
    text = "\n".join(R.render_tree_rule(R.ID_RULES, "x", R.check_tree(TREE), [], "", "detect", "block", 403, "t"))
    assert "deny" not in text and "pass" in text


@pytest.mark.parametrize("bad", [
    {"field": "path", "op": "equals", "value": 'a"\n,exec:/bin/sh'},
    {"field": "path", "op": "equals", "value": "%{tx.x}"},
    {"field": "path", "op": "regex", "value": "(a+)+$"},
    {"field": "path", "op": "regex", "value": r"(a)\1"},
    {"field": "path", "op": "regex", "value": "(?=x)y"},
    {"field": "header", "name": "X\" bad", "op": "equals", "value": "1"},
    {"field": "ip", "op": "equals", "value": "1.2.3.4"},
    {"field": "ip", "op": "cidr", "value": "nonsense"},
    {"field": "rate", "op": "gt", "value": "5"},
    {"field": "size", "op": "gt", "value": "abc"},
])
def test_bad_conditions_are_refused(bad):
    with pytest.raises(R.RuleError):
        R.check_tree(bad)


def test_quote_in_value_stays_inside_the_operator():
    line = "\n".join(R.render_tree_rule(R.ID_RULES, "x", R.check_tree({"field": "user_agent", "op": "contains", "value": 'a"b\\c'}), [], "", "detect", "log", 403, "t"))
    assert '@contains a\\"b\\\\c"' in line


def test_too_many_ways_refused(book):
    many = {"all": [{"any": [{"field": "method", "op": "equals", "value": m} for m in "ABCDE"]} for _ in range(3)]}
    with pytest.raises(R.RuleError):
        book.create({"name": "big", "tree": many}, "t")


# ---- preview
def test_preview_counts_only_what_events_keep(store):
    store.add_events([event(), event(url="/other"), event(domain="b.example", user_agent="Mozilla")])
    r = R.preview(store, {"field": "path", "op": "prefix", "value": "/admin"}, ["shop.example"], "")
    assert r["matched"] == 1 and r["checked"] == 3 and r["domains"][0] == ("shop.example", 1)
    r2 = R.preview(store, {"field": "arg", "name": "q", "op": "contains", "value": "x"}, [], "")
    assert r2["matched"] == 0 and r2["cannot_check"] == ["arg:q"] and r2["note"]


def test_preview_respects_scope(store):
    store.add_events([event(domain="mine.example"), event(domain="theirs.example")])
    r = R.preview(store, {"field": "path", "op": "prefix", "value": "/"}, [], "", allowed=["mine.example"])
    assert r["matched"] == 1 and r["checked"] == 1


# ---- rule book
def test_block_needs_detect_first_and_everything_is_versioned(book, store):
    r = book.create({"name": "one", "tree": TREE}, "op")
    with pytest.raises(R.RuleError, match="detect mode first"):
        book.set_mode(r["id"], "block", "op")
    book.set_mode(r["id"], "detect", "op")
    assert book.set_mode(r["id"], "block", "op")["mode"] == "block"
    book.update(r["id"], {"reason": "tighter"}, "op")
    v = book.versions(r["id"])
    assert [x["version"] for x in v] == [2, 1]
    assert "deny,status:403" in book.configs.files[R.NGINX_FILE]
    actions = [a["action"] for a in store.audit_entries()]
    assert "rule.created" in actions and "rule.mode" in actions and store.audit_verify()["ok"]


def test_refused_publish_undoes_the_mode(store):
    configs = FakeConfigs(refuse=True)
    b = R.RuleBook(store, configs, sites=lambda: [], servers=lambda: SERVERS, policy_defaults=lambda: {})
    r = b.create({"name": "one", "tree": TREE}, "op")
    with pytest.raises(R.RuleError):
        b.set_mode(r["id"], "detect", "op")
    assert b.rule(r["id"])["mode"] == "off"


def test_exception_is_narrow_and_scoped(book, store):
    ex = book.add_exception({"rule_id": "942100", "var": "ARGS:comment", "domain": "shop.example", "path": "/blog"}, "op")
    text = book.configs.files[R.NGINX_FILE]
    assert "ctl:ruleRemoveTargetById=942100;ARGS:comment" in text and "shop\\.example" in text and "@beginsWith /blog" in text
    assert "SecRuleRemoveById" not in text
    with pytest.raises(PermissionError):
        book.add_exception({"rule_id": "1", "domain": "other.example", "path": "/"}, "site", allowed=["shop.example"])
    assert any(a["action"] == "exception.refused" for a in store.audit_entries())
    with pytest.raises(PermissionError):
        book.remove_exception(ex["id"], "site", allowed=["elsewhere.example"])
    book.remove_exception(ex["id"], "op")
    assert "ruleRemoveTargetById" not in book.configs.files[R.NGINX_FILE]


def test_exception_refuses_bad_input():
    for args in (("x", None, "a.example", "/"), ("1", None, "", "/"), ("1", None, "a.example", "nopath"), ("1", 'ARGS:a" "x', "a.example", "/"), ("1", "TX:foo", "a.example", "/")):
        with pytest.raises(R.RuleError):
            R.check_exception(*args)


def test_wizard_warns_when_wider_than_minimum():
    e = {"domain": "shop.example", "url": "/"}
    s = R.suggest_exception(e, {"rule_id": "942100", "matched_var_name": None})
    assert len(s["warnings"]) == 2 and "ctl:ruleRemoveById=942100" in s["preview"]
    s2 = R.suggest_exception({"domain": "shop.example", "url": "/blog"}, {"rule_id": "942100", "matched_var_name": "ARGS:comment"})
    assert not s2["warnings"] and "ARGS:comment" in s2["preview"]
    with pytest.raises(R.RuleError):
        R.suggest_exception({"domain": None, "url": "/"}, {"rule_id": "1"})


def test_honeypot_excludes_real_paths_and_protects_certificates(book, tmp_path):
    (tmp_path / "site").mkdir()
    (tmp_path / "site" / "backup.zip").write_text("x")
    assert R.domains_with_path(["/backup.zip"], [{"server_name": "real.example", "aliases": ["www.real.example"], "docroot": str(tmp_path / "site")}, {"server_name": "no.example", "aliases": [], "docroot": str(tmp_path / "none")}]) == ["real.example", "www.real.example"]
    lines = R.render_honeypot({"mode": "block", "paths": ["/.env", "/phpmyadmin/"]}, ["real.example"])
    assert "deny,status:404" in lines[0] and "!@rx" in lines[1] and r"/phpmyadmin/?" in lines[0]
    with pytest.raises(R.RuleError):
        book.set_honeypot({"mode": "detect", "paths": ["/.well-known/acme-challenge/x"]}, "op")


def test_cms_profile_on_and_off(book):
    book.set_cms("wp-xmlrpc", "block", ["shop.example"], "op")
    text = book.configs.files[R.NGINX_FILE]
    assert "@streq /xmlrpc.php" in text and f"id:{R.ID_CMS}" in text and "deny,status:403" in text
    book.set_cms("wp-xmlrpc", "off", [], "op")
    assert "xmlrpc" not in book.configs.files[R.NGINX_FILE]
    assert next(x for x in book.cms_status() if x["id"] == "wp-xmlrpc")["mode"] == "off"


def test_all_cms_profiles_compile():
    for key, p in R.CMS_PROFILES.items():
        lines = R.render_tree_rule(R.ID_CMS + p["n"], p["title"], R.check_tree(p["tree"]), [], "", "block", "block", 403, key)
        assert lines


GOOD_PATCH = 'SecRule REQUEST_URI "@contains /vuln" "id:1150001,phase:1,deny,status:403,log,msg:\'CVE\'"'


def test_patch_starts_in_detect_and_blocks_only_when_told(book):
    r = book.add_patch({"cve_id": "cve-2024-1234", "raw": GOOD_PATCH, "software": "App", "source_url": "https://example.org/a"}, "op")
    assert r["mode"] == "detect" and r["cve_id"] == "CVE-2024-1234"
    assert "deny" not in book.configs.files[R.NGINX_FILE].split("# Rule")[1]
    book.set_mode(r["id"], "block", "op")
    assert "deny,status:403" in book.configs.files[R.NGINX_FILE].split("# Rule")[1]


@pytest.mark.parametrize("raw", [
    'SecRule ARGS "@rx x" "id:1150001,phase:2,exec:/bin/sh"', 'Include /etc/passwd', 'SecRule ARGS "@rx x" "phase:2,deny"', 'SecRule ARGS "@rx x" "id:949110,phase:2,deny"',
    'SecRule ARGS "@inspectFile /x" "id:1150001,phase:2"', 'SecAuditLog /tmp/x', 'SecRule ARGS "x" "id:1150001,phase:2,chain"', 'SecRule ARGS "x" "id:1150001,phase:2,proxy:http://evil/"',
])
def test_bad_imports_refused(raw):
    with pytest.raises(R.RuleError):
        R.check_raw(raw)


def test_chain_and_continuation_lines_accepted():
    lines, ids = R.check_raw('SecRule ARGS "@rx x" \\\n   "id:1150002,phase:2,deny,chain"\nSecRule ARGS "@rx y" "t:none"')
    assert ids == [1150002] and len(lines) == 2


def test_switches_write_the_file_and_revert_on_refusal(book, store):
    book.set_switch("kill_switch", True, "op")
    assert "SecRuleEngine DetectionOnly" in book.configs.files[R.NGINX_FILE]
    book.set_switch("kill_switch", False, "op")
    assert "DetectionOnly" not in book.configs.files[R.NGINX_FILE]
    book.configs.refuse = True
    with pytest.raises(R.RuleError):
        book.set_switch("kill_switch", True, "op")
    assert store.setting("kill_switch") is False


def test_under_attack_turns_itself_off(book, store):
    book.under_attack(5, "op")
    assert "threshold=3" in book.configs.files[R.NGINX_FILE]
    store.set_setting("under_attack", {"on": True, "until": time.time() - 1})
    book.tick()
    assert store.setting("under_attack")["on"] is False and "threshold=3" not in book.configs.files[R.NGINX_FILE]


def test_rule_with_end_date_goes_off(book):
    r = book.create({"name": "t", "tree": TREE, "expires_at": time.time() + 3600}, "op")
    book.set_mode(r["id"], "detect", "op")
    book.store.run(lambda c: c.execute("UPDATE rules SET expires_at=? WHERE id=?", (time.time() - 1, r["id"])))
    book.tick()
    assert book.rule(r["id"])["mode"] == "off"


def test_policy_inheritance_and_lock(book):
    book.set_policy("global", "paranoia", 2, True, "op")
    with pytest.raises(R.RuleError, match="locked"):
        book.set_policy("domain:shop.example", "paranoia", 1, False, "op")
    eff = book.set_policy("domain:shop.example", "paranoia", 3, False, "op")
    assert eff["paranoia"]["value"] == 3 and eff["paranoia"]["from"] == "domain:shop.example"
    assert eff["threshold"]["from"] == "WAF Firewall page"
    text = book.configs.files[R.NGINX_FILE]
    assert "tx.blocking_paranoia_level=3" in text


def test_domain_mode_is_the_canary_switch(book):
    book.set_policy("domain:canary.example", "mode", "detect", False, "op")
    assert "ctl:ruleEngine=DetectionOnly" in book.configs.files[R.NGINX_FILE]


def test_engine_paranoia_setting_reaches_crs4():
    from backend import waf
    text = waf.render_pre({"mode": "block", "paranoia": 3, "threshold": 5, "apps": [], "trusted": [], "sites_off": []})
    assert "tx.blocking_paranoia_level=3" in text and "tx.paranoia_level=3" in text


# ---- query language
def test_query_compiles_with_bound_values():
    sql, args = Q.compile_query("client_ip:1.2.3.4 AND rule_id:942100 AND status>=500")
    assert "?" in sql and args == ["1.2.3.4", "942100", 500]
    assert "1.2.3.4" not in sql


@pytest.mark.parametrize("bad", ["nonsense:1", "status>=abc", "(a", "a)", "client_ip>1", "OR", "x" * 501, "AND a"])
def test_query_errors(bad):
    with pytest.raises(Q.QueryError):
        Q.compile_query(bad)


def test_query_cant_inject(store):
    store.add_events([event(url="/a"), event(url="/b", client_ip="198.51.100.1")])
    for text in ("client_ip:x' OR '1'='1", '"; DROP TABLE events; --', "url:%"):
        res = store.search_events(query=Q.compile_query(text))
        assert res["events"] == []
    assert len(store.search_events(query=Q.compile_query("NOT client_ip:198.51.100.1"))["events"]) == 1
    assert len(store.search_events(query=Q.compile_query("(url:/a OR url:/b) AND status=200"))["events"]) == 2


# ---- proxies
TRUST = ["10.0.0.0/8", "173.245.48.0/20"]


@pytest.mark.parametrize("peer,headers,want", [
    ("203.0.113.1", {"x-forwarded-for": "1.1.1.1"}, ("203.0.113.1", "peer")),  # an untrusted peer's header means nothing
    ("10.0.0.5", {"x-forwarded-for": "1.1.1.1"}, ("1.1.1.1", "x-forwarded-for")),
    ("10.0.0.5", {"x-forwarded-for": "6.6.6.6, 1.1.1.1, 10.0.0.9"}, ("1.1.1.1", "x-forwarded-for")),  # what the client sent itself stays on the left
    ("173.245.48.5", {"cf-connecting-ip": "2001:db8::1"}, ("2001:db8::1", "cf-connecting-ip")),
    ("10.0.0.5", {"x-forwarded-for": "not-an-ip"}, ("10.0.0.5", "peer")),
    ("10.0.0.5", {}, ("10.0.0.5", "peer")),
    ("2001:db8::9", {"x-forwarded-for": "1.1.1.1"}, ("2001:db8::9", "peer")),
])
def test_client_address(peer, headers, want):
    assert P.client_from(peer, headers, TRUST) == want


def test_trust_ranges_checked():
    assert P.check_ranges(["192.0.2.5", "192.0.2.5"]) == ["192.0.2.5/32"]
    for bad in (["0.0.0.0/0"], ["1.0.0.0/4"], ["::/0"], ["x"]):
        with pytest.raises(P.ProxyError):
            P.check_ranges(bad)


def test_realip_files():
    assert "set_real_ip_from 10.0.0.0/8;" in P.render_nginx(["10.0.0.0/8"], "X-Forwarded-For")
    assert "RemoteIPTrustedProxy 10.0.0.0/8" in P.render_apache(["10.0.0.0/8"], "X-Forwarded-For")
    assert "set_real_ip_from" not in P.render_nginx([], "X-Forwarded-For")


def test_cloudflare_ranges_validated_and_last_good_kept(store):
    cfg = FakeConfigs()
    good = "\n".join(f"173.245.{i}.0/24" for i in range(6))
    state = {"text": good}

    def fetch(_url):
        if state["text"] is None:
            raise OSError("down")
        return state["text"] if _url.endswith("v4") else ""
    p = P.Proxies(store, cfg, lambda: SERVERS, fetch=fetch)
    p.set_cloudflare(True, "op")
    assert p.state()["cloudflare"]["ranges"] == 6 and "173.245.0.0/24" in store.setting("trusted_proxies")
    state["text"] = None
    store.set_setting("cdn_cloudflare", {**store.setting("cdn_cloudflare"), "updated": 0})
    p.tick()
    assert p.state()["cloudflare"]["ranges"] == 6 and "down" in p.state()["cloudflare"]["error"]
    state["text"] = "10.0.0.0/24\n" * 6
    with pytest.raises(P.ProxyError):
        P.parse_ranges([state["text"]])


def test_cdn_ban_and_unban_recorded(store):
    calls = []

    def api(method, path, token, body):
        calls.append((method, path, token, body))
        return {"success": True, "result": {"id": "abc123"}}
    p = P.Proxies(store, FakeConfigs(), lambda: [], api=api)
    with pytest.raises(P.ProxyError):
        p.cdn_ban("203.0.113.1", "x", "op")
    store.set_setting("cdn_cloudflare", {"token": "t", "zone": "a" * 32})
    bid = p.cdn_ban("203.0.113.1", "bad", "op")["id"]
    row = store.read(lambda c: dict(c.execute("SELECT * FROM blocks WHERE id=?", (bid,)).fetchone()))
    assert row["backend"] == "cdn-api" and row["source"] == "cloudflare" and calls[0][3]["configuration"]["value"] == "203.0.113.1"
    p.cdn_unban(row, "op")
    assert calls[1][0] == "DELETE" and calls[1][1].endswith("/abc123")


# ---- possible breach
def _ev(status, score, rules=("942100",), action="detected"):
    return {"status": status, "anomaly_score": score, "action": action, "tags": "[]", "severity": "WARNING", "evidence": [{"rule_id": r} for r in rules], "peer_ip": "1.2.3.4", "client_ip": "1.2.3.4", "headers": "{}"}


@pytest.mark.parametrize("status,score,rules,breach", [(200, 5, ("942100",), True), (500, 10, ("942100",), True), (403, 10, ("942100",), False), (404, 10, ("942100",), False), (200, 2, ("920350",), False), (200, None, ("951100",), True), (403, None, ("951100",), False)])
def test_possible_breach(status, score, rules, breach):
    e = collector.classify(_ev(status, score, rules))
    assert ("possible-breach" in json.loads(e["tags"])) == breach
    if breach:
        assert e["severity"] == "CRITICAL"


def test_honeypot_rule_gets_high_confidence():
    e = collector.classify(_ev(200, None, (str(R.ID_HONEYPOT),)))
    assert "honeypot" in json.loads(e["tags"]) and e["confidence"] == "high"


def test_spoofed_forwarded_header_changes_nothing_unless_trusted():
    e = _ev(403, 5)
    e["headers"] = json.dumps({"x-forwarded-for": "9.9.9.9"})
    assert collector.classify(dict(e), ["10.0.0.0/8"])["client_ip"] == "1.2.3.4"
    assert collector.classify(dict(e), ["1.2.3.0/24"])["client_ip"] == "9.9.9.9"


# ---- alerts
def test_alert_dedupes_escalates_and_keeps_undelivered(store):
    a = notify.Alerts(store)
    first = a.raise_alert("k", "same", "WARNING", "t")
    second = a.raise_alert("k", "same", "WARNING", "t")
    assert first == second
    row = a.list()[0]
    assert row["count"] == 2 and row["delivered"] == 0  # nothing has told anyone yet, so it still has to go
    store.run(lambda c: c.execute("UPDATE alerts SET delivered=1"))
    for _ in range(notify.ESCALATE_COUNT - 2):
        a.raise_alert("k", "same", "WARNING", "t")
    row = a.list()[0]
    assert row["severity"] == "CRITICAL" and row["delivered"] == 0


def test_quiet_hours_hold_all_but_critical():
    ch = {"quiet_from": 22, "quiet_to": 7}
    assert notify._quiet(ch, "WARNING", 23) and notify._quiet(ch, "WARNING", 3) and not notify._quiet(ch, "WARNING", 12)
    assert not notify._quiet(ch, "CRITICAL", 23)


def test_delivery_failure_retries_and_success_marks(store, monkeypatch):
    sent = []
    state = {"fail": True}

    def fake(kind, cfg, alert, mailer=None):
        if state["fail"]:
            raise OSError("boom https://secret.example/hook")
        sent.append(alert["title"])
    monkeypatch.setattr(notify, "deliver", fake)
    a = notify.Alerts(store)
    a.add_channel({"kind": "webhook", "name": "w", "config": {"url": "https://x.example/h", "secret": "s"}}, "op")
    a.raise_alert("k", "d", "ERROR", "Something")
    assert a.tick(12) == 0 and a.list()[0]["delivered"] == 0
    assert "secret.example" not in a.channels()[0]["last_error"]
    state["fail"] = False
    assert a.tick(12) == 1 and a.list()[0]["delivered"] == 1 and sent == ["Something"]


def test_channel_validation_and_secrets_hidden(store):
    a = notify.Alerts(store)
    for bad in ({"kind": "webhook", "config": {"url": "http://8.8.8.8/x"}}, {"kind": "telegram", "config": {"token": "x", "chat": "1"}}, {"kind": "email", "config": {"to": "nope"}}, {"kind": "nope", "config": {}}):
        with pytest.raises(notify.AlertError):
            a.add_channel(bad, "op")
    ch = a.add_channel({"kind": "slack", "config": {"url": "https://hooks.example/SECRET"}}, "op")
    assert "SECRET" not in json.dumps(ch)


def test_webhook_signature():
    assert notify.sign("k", b"body") == notify.sign("k", b"body") != notify.sign("k2", b"body")


# ---- correlation
def _fail(ip, login, ago=10):
    return event(source="journal_sshd", action="login_failed", client_ip=ip, account=login, url=None, ts_event=time.time() - ago, domain=None)


def test_credential_stuffing_patterns(store):
    cor = correlate.Correlator(store, None, notify.Alerts(store))
    events = [_fail("203.0.113.1", f"user{i}") for i in range(12)] + [_fail(f"198.51.100.{i}", "admin") for i in range(12)] + [_fail("192.0.2.200", "x", ago=7200) for _ in range(55)]
    store.add_events(events)
    kinds = {f["kind"]: f for f in cor.stuffing()}
    assert kinds["ip_many_logins"]["target"] == "203.0.113.1"
    assert kinds["login_many_ips"]["target"] == "admin"
    assert kinds["slow_brute"]["target"] == "192.0.2.200"


def test_correlator_ban_off_by_default_and_historical_ignored(store):
    class Eng:
        banned = []

        def ban(self, t, *a, **k):
            self.banned.append(t)
    eng = Eng()
    cor = correlate.Correlator(store, eng, notify.Alerts(store))
    store.add_events([_fail("203.0.113.2", f"u{i}") for i in range(12)])
    cor.tick()
    assert eng.banned == []
    cor.set_settings({"auto_ban": True}, "op")
    cor.tick()
    assert "203.0.113.2" in eng.banned
    eng.banned.clear()
    store2 = Store(store.dir / "two")
    cor2 = correlate.Correlator(store2, eng, notify.Alerts(store2))
    cor2.set_settings({"auto_ban": True}, "op")
    store2.add_events([{**_fail("203.0.113.3", f"u{i}"), "historical": 1} for i in range(12)])
    cor2.tick()
    assert eng.banned == []


def test_breach_alert_raised(store):
    al = notify.Alerts(store)
    cor = correlate.Correlator(store, None, al)
    store.set_setting("correlator_ts", time.time() - 60)
    store.add_events([event(tags=json.dumps(["possible-breach"]), rule_id="942100", severity="CRITICAL")])
    cor.tick()
    assert any(a["kind"] == "possible_breach" and a["severity"] == "CRITICAL" for a in al.list())


def test_learning_lists_candidates(store):
    ev = [event(action="detected", url="/blog", evidence=[{"rule_id": "942100", "matched_var_name": "ARGS:comment", "matched_data": "x"}], client_ip=f"198.51.100.{i}") for i in range(4)]
    store.add_events(ev)
    got = correlate.Correlator(store, None, None).learning()
    assert got[0]["rule_id"] == "942100" and got[0]["hits"] == 4 and got[0]["clients"] == 4 and got[0]["var"] == "ARGS:comment"


# ---- reputation and bots
def test_lists_tag_with_source_and_skip_private(store):
    i = I.Intel(store, fetch=lambda u: "; comment\n45.33.32.0/24 ; SBL1\n10.0.0.0/8\n2a00:1450::/32\n")
    i.configure("spamhaus-drop", True, False, "op")
    hit = i.lookup("45.33.32.77")
    assert hit[0]["name"] == "spamhaus-drop" and hit[0]["fetched_at"]
    assert i.lookup("10.1.1.1") == [] and i.lookup("8.8.8.8") == [] and i.lookup("2a00:1450::1")
    assert i.lists()[0]["auto_ban"] == 0
    store.run(lambda c: c.execute("UPDATE ti_lists SET expires_at=1"))
    assert i.lookup("45.33.32.77") == []


def test_failed_download_keeps_the_list(store):
    state = {"ok": True}

    def f(_u):
        if not state["ok"]:
            raise OSError("nope")
        return "45.33.32.0/24\n"
    i = I.Intel(store, fetch=f)
    i.configure("tor-exits", True, False, "op")
    state["ok"] = False
    i.refresh("tor-exits")
    row = next(x for x in i.lists() if x["name"] == "tor-exits")
    assert row["count"] == 1 and "nope" in row["last_error"]


class Res:
    def __init__(self, host, addrs):
        self.host, self.addrs = host, addrs

    def reverse(self, _ip):
        if self.host is None:
            raise socket.herror("no")
        return self.host

    def forward(self, _h):
        return self.addrs


def test_bot_verification():
    assert I.claimed_bot("Mozilla/5.0 (compatible; Googlebot/2.1)") == "Googlebot" and I.claimed_bot("Mozilla") is None
    assert I.verify_bot("66.249.66.1", "Googlebot", Res("crawl-1.googlebot.com", ["66.249.66.1"])) is True
    assert I.verify_bot("6.6.6.6", "Googlebot", Res("evil.example", ["6.6.6.6"])) is False
    assert I.verify_bot("6.6.6.6", "Googlebot", Res("crawl.googlebot.com", ["66.249.66.1"])) is False  # a faked reverse record
    assert I.verify_bot("6.6.6.6", "Googlebot", Res(None, [])) is False


def test_country_from_csv(store, tmp_path):
    (tmp_path / "geo").mkdir()
    (tmp_path / "geo" / "dbip.csv").write_text("203.0.113.0,203.0.113.255,NZ\n2001:db8::,2001:db8::ffff,AU\n")
    i = I.Intel(store, geo_dir=tmp_path / "geo")
    assert i.country("203.0.113.5")["country"] == "NZ" and i.country("2001:db8::1")["country"] == "AU" and i.country("8.8.8.8") is None
    assert I.Intel(store, geo_dir=tmp_path / "none").geo_status()["available"] is False


# ---- retention and privacy
def test_pseudonymize_keeps_counts(store):
    old = time.time() - 200 * 86400
    store.add_events([event(ts_event=old, client_ip="203.0.113.77", peer_ip="203.0.113.77"), event(ts_event=old, client_ip="2001:db8:1:2::9", peer_ip=None), event(client_ip="203.0.113.77")])
    r = H.Retention(store)
    assert r.pseudonymize(time.time() - 90 * 86400) == 2
    rows = list(store.scan_events(old - 1))
    ips = sorted(e["client_ip"] for e in rows)
    assert "203.0.113.0" in ips and "2001:db8:1::" in ips and "203.0.113.77" in ips and len(rows) == 3
    assert r.pseudonymize(time.time() - 90 * 86400) == 0


def test_old_month_is_a_deleted_file(store):
    old = time.time() - 500 * 86400
    store.add_events([event(ts_event=old), event()])
    assert len(store.months()) == 2
    res = H.Retention(store).tick()
    assert len(res["removed"]) == 1 and len(store.months()) == 1
    assert store.audit_entries()[0]["action"] == "retention.ran"


def test_forget_and_audit_hides_value(store):
    store.add_events([event(client_ip="203.0.113.5"), event(client_ip="203.0.113.6")])
    r = H.Retention(store)
    assert r.forget("client_ip", "203.0.113.5", "op")["deleted"] == 1
    assert "203.0.113.5" not in json.dumps(store.audit_entries()[0])
    with pytest.raises(ValueError):
        r.forget("url", "/x", "op")


def test_anchor_once_a_day(store):
    store.audit("op", "x", "y")
    r = H.Retention(store)
    assert r.anchor()["seq"] == 1 and r.anchor() is None
    assert (store.dir / "audit-anchors.log").read_text().count("\n") == 1


# ---- export
def test_cef_escapes():
    line = H.to_cef({"source": "modsec_audit", "rule_id": "942100", "severity": "CRITICAL", "client_ip": "1.2.3.4", "url": "/a=b|c\nd", "ts_event": 1.5})
    assert line.startswith("CEF:0|AuroraPanel|WAF Ella|1|942100|modsec_audit|10|") and "\n" not in line and "a\\=b\\|c d" in line


def test_export_resumes_after_failure(store, monkeypatch):
    got = []
    state = {"fail": True}

    def post(url, body, headers):
        if state["fail"]:
            raise OSError("down")
        got.extend(json.loads(body))
    monkeypatch.setattr(notify, "_post", post)
    e = H.Exporter(store)
    e.set_targets([{"name": "siem", "kind": "http", "url": "https://x.example/in", "min_severity": "NOTICE"}], "op")
    t = store.setting("exports")
    t[0]["position"] = time.time() - 100
    store.set_setting("exports", t)
    store.add_events([event(severity="WARNING", ts_event=time.time() - 50), event(severity="NOTICE", ts_event=time.time() - 40)])
    assert e.tick() == 0 and e.targets()[0]["last_error"] == "down"
    state["fail"] = False
    assert e.tick() == 2 and len(got) == 2
    assert e.tick() == 0 and len(got) == 2


# ---- config as code
def test_config_round_trip_and_dry_run(book, store):
    r = book.create({"name": "keep", "tree": TREE}, "op")
    book.set_mode(r["id"], "detect", "op")
    book.add_exception({"rule_id": "942100", "var": "ARGS:a", "domain": "shop.example", "path": "/x"}, "op")
    book.set_policy("domain:shop.example", "threshold", 7, False, "op")
    text = H.to_yaml(H.export_config(book, store))
    doc = H.parse_yaml(text)
    assert H.diff_config(H.export_config(book, store), doc) == {"rules": {"add": [], "remove": [], "change": []}, "exceptions": {"add": [], "remove": [], "change": []}, "policies": {"add": [], "remove": [], "change": []}, "settings": {"change": []}}
    doc["rules"][0]["priority"] = 5
    doc["rules"].append({"name": "new", "kind": "custom", "tree": TREE, "mode": "off", "domains": [], "path": "", "action": "log", "status": 403, "priority": 1, "reason": ""})
    d = H.diff_config(H.export_config(book, store), doc)
    assert d["rules"]["add"] == ["custom:new"] and d["rules"]["change"] == ["custom:keep"]
    assert len(book.rules()) == 1  # the diff itself changed nothing
    H.import_config(book, store, doc, "op")
    assert {x["name"] for x in book.rules()} == {"keep", "new"} and book.effective("shop.example")["threshold"]["value"] == 7
    assert len(book.exceptions()) == 1


def test_import_refuses_bad_and_changes_nothing(book, store):
    book.create({"name": "keep", "tree": TREE}, "op")
    doc = H.export_config(book, store)
    doc["rules"].append({"name": "evil", "kind": "vpatch", "raw": 'SecRule ARGS "x" "id:1150001,exec:/bin/sh"'})
    with pytest.raises(R.RuleError):
        H.import_config(book, store, doc, "op")
    assert [r["name"] for r in book.rules()] == ["keep"]
    for bad in ("not: [valid", "just text", "schema: 99"):
        with pytest.raises(ValueError):
            H.parse_yaml(bad)
    with pytest.raises(ValueError):
        H.parse_yaml("!!python/object/apply:os.system ['true']")


def test_import_undone_when_the_server_refuses(book, store):
    r = book.create({"name": "keep", "tree": TREE}, "op")
    doc = H.export_config(book, store)
    doc["rules"][0]["priority"] = 9

    class Flaky(FakeConfigs):
        n = 0

        def apply(self, path, text, actor, **kw):
            Flaky.n += 1
            if Flaky.n == 1:
                raise R.RuleError("refused")
            return super().apply(path, text, actor, **kw)
    book.configs = Flaky()
    with pytest.raises(R.RuleError):
        H.import_config(book, store, doc, "op")
    assert book.rule(r["id"])["priority"] == 100


# ---- metrics and digest
def test_prometheus_output(store):
    store.run(lambda c: c.execute("INSERT INTO sources(path, kind, lines, unparsed) VALUES ('/x\"y', 'k', 5, 1)"))
    text = H.prometheus(store)
    assert 'ella_source_lines_total{source="/x\\"y"} 5' in text and "# TYPE ella_drift gauge" in text


def test_digest_scoped(store):
    store.add_events([event(action="blocked", rule_id="942100", domain="mine.example"), event(action="blocked", rule_id="941100", domain="theirs.example")])
    d = H.digest(store, 7, ["mine.example"])
    assert d["blocked"] == 1 and d["top_rules"] == [("942100", 1)]
    assert "theirs" not in H.digest_text(d)
    assert H.digest(store, 7, [])["events"] == 0


# ---- fleet protocol
def _cp(store, book):
    return fleet.ControlPlane(store, book)


def test_signed_request_replay_and_clock(book, store):
    cp = _cp(store, book)
    a = cp.enroll("web2", "op")
    body, ts = b"{}", int(time.time())
    sig = fleet.request_sig(a["secret"], "POST", "/p", ts, "n" * 20, body)
    assert cp.authenticate("POST", "/p", a["agent_id"], ts, "n" * 20, sig, body)["name"] == "web2"
    with pytest.raises(PermissionError, match="already"):
        cp.authenticate("POST", "/p", a["agent_id"], ts, "n" * 20, sig, body)
    with pytest.raises(PermissionError, match="signature"):
        cp.authenticate("POST", "/p", a["agent_id"], ts, "m" * 20, sig, body)
    old = ts - 300
    with pytest.raises(PermissionError, match="clocks"):
        cp.authenticate("POST", "/p", a["agent_id"], old, "o" * 20, fleet.request_sig(a["secret"], "POST", "/p", old, "o" * 20, body), body)
    cp.revoke(a["agent_id"], "op")
    with pytest.raises(PermissionError):
        cp.authenticate("POST", "/p", a["agent_id"], ts, "p" * 20, fleet.request_sig(a["secret"], "POST", "/p", ts, "p" * 20, body), body)


def test_policy_signature_and_version_only_rise():
    doc = {"protocol": 1, "version": 5, "config": {}}
    env = {"policy": doc, "signature": fleet.sign_doc("s", doc)}
    assert fleet.verify_policy("s", env, 4)["version"] == 5
    with pytest.raises(fleet.FleetError, match="already"):
        fleet.verify_policy("s", env, 5)
    with pytest.raises(fleet.FleetError, match="signature"):
        fleet.verify_policy("other", env, 0)
    tampered = {"policy": {**doc, "version": 6}, "signature": env["signature"]}
    with pytest.raises(fleet.FleetError, match="signature"):
        fleet.verify_policy("s", tampered, 0)


def test_member_applies_policy_keeps_it_offline_and_queues(tmp_path, store, book):
    """Two stores talking through the real signing code, without a network between them."""
    cp = _cp(store, book)
    r = book.create({"name": "from-the-centre", "tree": TREE}, "op")
    book.set_mode(r["id"], "detect", "op")
    joined = cp.enroll("web2", "op")
    other = Store(tmp_path / "member")
    obook = R.RuleBook(other, FakeConfigs(), sites=lambda: [], servers=lambda: SERVERS, policy_defaults=lambda: {})
    online = {"up": True}

    class Eng:
        bans = []

        def ban(self, t, ttl, reason, actor, **k):
            self.bans.append(t)

        def list_blocks(self):
            return []

    def sender(cfg, path, report):
        if not online["up"]:
            raise OSError("no route to host")
        body = json.dumps(report).encode()
        ts, nonce = int(time.time()), f"{time.time_ns():020d}"
        agent = cp.authenticate("POST", path, cfg["agent_id"], ts, nonce, fleet.request_sig(cfg["secret"], "POST", path, ts, nonce, body), body)
        return json.loads(json.dumps(cp.checkin(agent, json.loads(body))))
    m = fleet.Member(other, obook, Eng(), sender=sender)
    res = m.join("https://panel.example:8088", joined["agent_id"], joined["secret"], "op")
    assert res["ok"] and res["applied"] == 1 and obook.rules()[0]["name"] == "from-the-centre" and obook.rules()[0]["mode"] == "detect"
    assert cp.agents()[0]["online"] and cp.agents()[0]["policy_version"] == 0
    assert m.tick()["applied"] is None  # nothing new, so nothing applied again

    online["up"] = False
    other.add_events([event(severity="CRITICAL", hash="a" * 64, source="modsec_audit")])
    res = m.tick()
    assert res["ok"] is False and res["enforcing"] == 1 and m.spool.depth() > 0
    assert obook.rules()[0]["name"] == "from-the-centre"

    online["up"] = True
    cp.ban_everywhere("203.0.113.50", 3600, "bad", "op")
    res = m.tick()
    assert res["ok"] and res["applied"] == 2 and "203.0.113.50/32" in Eng.bans
    assert m.spool.depth() == 0 and len(store.search_events(source="modsec_audit")["events"]) == 1
    m.tick()
    assert len(store.search_events(source="modsec_audit")["events"]) == 1


def test_spool_bounded_and_counts_loss(tmp_path):
    s = fleet.Spool(tmp_path / "q.jsonl", max_bytes=2000)
    s.put([{"n": i, "pad": "x" * 50} for i in range(200)])
    assert s.depth() <= 2000 and s.lost() > 0
    got, size = s.peek(5)
    assert got[-1]["n"] == 199 or got[0]["n"] > 0
    s.drop(size)
    assert s.peek(1)[0][0]["n"] > got[0]["n"]


# ---- the agent socket
@pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets and SO_PEERCRED")
def test_socket_adapter_round_trip_and_refusal(tmp_path):
    import threading
    from backend.ella import agentd
    from backend.ella.adapter import AdapterError, AgentUnavailable, EllaSystemAdapter
    path = str(tmp_path / "a.sock")
    srv = agentd.serve(path, EllaSystemAdapter())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    a = agentd.SocketAdapter(path)
    assert a.ping()["ok"]
    with pytest.raises(AdapterError):
        a.call("nft_add", {"target": "not-an-ip"})
    with pytest.raises(AdapterError):
        a.call("os_system", {})
    srv.shutdown()
    srv.server_close()
    import os
    os.unlink(path)
    closed = agentd.SocketAdapter(path, fallback=None, fail_mode=lambda: "closed")
    with pytest.raises(AgentUnavailable):
        closed.call("nft_list", {"family": 4})

    class In:
        def call(self, op, args, oid):
            return {"ok": True, "inside": True}
    opened = agentd.SocketAdapter(path, fallback=In(), fail_mode=lambda: "open")
    assert opened.call("nft_list", {"family": 4})["inside"] and opened.last_transport == "fallback"


# ---- roles
def test_site_role_only_reaches_scoped_ella_routes():
    u = {"role": "site"}
    assert authz._decide(u, "GET", "/api/ella/events") is None
    assert authz._decide(u, "GET", "/api/ella/search") is None
    assert authz._decide(u, "GET", "/api/ella/investigate/1.2.3.4") is None
    assert authz._decide(u, "POST", "/api/ella/exceptions") is None
    assert authz._decide(u, "DELETE", "/api/ella/exceptions/4") is None
    for m, p in (("POST", "/api/ella/blocks"), ("GET", "/api/ella/blocks"), ("GET", "/api/ella/audit"), ("POST", "/api/ella/rules"), ("GET", "/api/ella/metrics"), ("GET", "/api/ella/config")):
        assert authz._decide(u, m, p), (m, p)


def test_soc_operator_role():
    u = {"role": "soc_operator"}
    assert authz._decide(u, "GET", "/api/ella/overview") is None
    assert authz._decide(u, "POST", "/api/ella/blocks") is None
    assert authz._decide(u, "POST", "/api/ella/rules") is None
    assert authz._decide(u, "GET", "/api/files/list")
    assert authz._decide(u, "POST", "/api/terminal")
    for p in ("/api/ella/fleet/enroll", "/api/ella/config/import", "/api/ella/proxies", "/api/ella/channels"):
        assert authz._decide(u, "POST", p)


def test_csv_cells_cant_become_formulas():
    from backend.ella.routes_soc import _csv_safe
    assert _csv_safe('=HYPERLINK("http://x")') == "'=HYPERLINK(\"http://x\")" and _csv_safe("+1") == "'+1" and _csv_safe("/ok") == "/ok" and _csv_safe(None) == ""


def test_sbom_and_crs_hashes(store, tmp_path):
    (tmp_path / "r.conf").write_text("a")
    g = (str(tmp_path / "*.conf"),)
    assert supply.check_crs(store, g)["baseline"] is True
    assert supply.check_crs(store, g)["changed"] == []
    (tmp_path / "r.conf").write_text("b")
    assert supply.check_crs(store, g)["changed"] == [str(tmp_path / "r.conf")]
    doc = supply.sbom("requirements.txt")
    assert doc["bomFormat"] == "CycloneDX" and "fastapi" in doc["direct_pinned"]


def test_fleet_checkin_needs_a_signature(client):
    r = client.post("/api/ella/fleet/checkin", json={"events": []})
    assert r.status_code == 403
    r = client.post("/api/ella/fleet/checkin", json={}, headers={"X-Ella-Agent": "x", "X-Ella-Time": "1", "X-Ella-Nonce": "n" * 20, "X-Ella-Signature": "bad"})
    assert r.status_code == 403


def test_system_commands_only_run_in_the_adapter():
    """The allowlist means nothing if another file can start a program."""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "backend" / "ella"
    for f in root.glob("*.py"):
        text = f.read_text(encoding="utf-8")
        if f.name in ("adapter.py", "cli.py"):
            continue
        assert "import subprocess" not in text and "os.system" not in text and "shell=True" not in text, f.name
    assert "shell=True" not in (root / "adapter.py").read_text(encoding="utf-8")


def test_no_page_puts_log_data_in_html():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "frontend" / "js"
    for name in ("ella.js", "ella_soc.js"):
        text = (root / name).read_text(encoding="utf-8")
        assert "innerHTML" not in text and "insertAdjacentHTML" not in text and "document.write" not in text, name
