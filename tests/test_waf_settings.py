"""WAF settings, allow-lists and the audit-log reader, with Apache stubbed."""
import json
import time

import pytest

from backend import waf


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setattr(waf, "STATE", tmp_path / "waf.json")
    applied = []
    monkeypatch.setattr(waf, "apply", lambda s=None: (applied.append(dict(s)), {"ok": True})[1])
    return applied


def test_update_validates_and_clamps(state):
    with pytest.raises(waf.WafError, match="Unknown mode"):
        waf.update({"mode": "yolo"})
    with pytest.raises(waf.WafError, match="isn't an IP"):
        waf.update({"trusted": ["192.168.0.2", "home"]})
    with pytest.raises(waf.WafError, match="isn't a host name"):
        waf.update({"sites_off": ["shop.example", "bad host"]})
    assert state == []   # nothing reached Apache
    waf.update({"mode": "detect", "paranoia": 9, "threshold": 1, "apps": ["wordpress", "nope", "roundcube"],
                "trusted": [" 10.0.0.5/32 ", "10.8.0.0/24", "10.0.0.5"], "sites_off": ["Shop.Example", "", "shop.example"]})
    s = state[-1]
    assert s["mode"] == "detect" and s["paranoia"] == 4 and s["threshold"] == 2
    assert s["apps"] == ["wordpress", "roundcube"] and s["trusted"] == ["10.0.0.5", "10.8.0.0/24"] and s["sites_off"] == ["shop.example"]
    waf.update({"paranoia": 0, "threshold": 500})
    assert state[-1]["paranoia"] == 1 and state[-1]["threshold"] == 100


def test_rendering_follows_the_settings(state, monkeypatch):
    monkeypatch.setattr(waf, "_panel_trusted", lambda: [])  # the machine's own IP Blocker trust list stays out of it
    s = waf.load()
    s.update(mode="detect", paranoia=2, threshold=7, apps=["wordpress", "drupal"], trusted=["10.0.0.5"], sites_off=["shop.example"])
    pre = waf.render_pre(s)
    assert "SecRuleEngine DetectionOnly" in pre and "tx.paranoia_level=2" in pre and "inbound_anomaly_score_threshold=7" in pre
    assert "setvar:tx.crs_exclusions_wordpress=1,setvar:tx.crs_exclusions_drupal=1" in pre
    assert '@ipMatch 10.0.0.5"' in pre and "aurora-sites-off.txt" in pre
    s["mode"] = "off"
    assert "SecRuleEngine Off" in waf.render_pre(s)


def test_allow_and_restore_rules(state):
    with pytest.raises(waf.WafError, match="Unknown rule"):
        waf.allow_rule("12; rm -rf")
    with pytest.raises(waf.WafError, match="score summary"):
        waf.allow_rule("949110")
    waf.allow_rule("920350", msg="Host header is a numeric IP\naddress\x00 " + "x" * 300)
    d = state[-1]["disabled_rules"]["920350"]
    assert "\n" not in d["msg"] and "\x00" not in d["msg"] and len(d["msg"]) <= 200 and d["since"] <= time.time()
    post = waf.render_post(state[-1])
    assert "<IfModule security2_module>" in post and "SecRuleRemoveById 920350   # Host header is a numeric IP address" in post
    waf.restore_rule("920350")
    assert state[-1]["disabled_rules"] == {} and "no rules switched off" in waf.render_post(state[-1])


def test_clean_ips_normalises_and_sorts():
    assert waf._clean_ips(["10.0.0.5/32", " 10.8.0.1/24", "", "2001:db8::1"]) == ["10.0.0.5", "10.8.0.0/24", "2001:db8::1"]
    with pytest.raises(waf.WafError):
        waf._clean_ips(["10.0.0.999"])


def _event(ts: str, ip: str, msgs: list[str], intercepted=True, status=403, line="GET /wordpress1/wp-login.php HTTP/1.1"):
    return json.dumps({"transaction": {"time": ts, "remote_address": ip, "transaction_id": "t-" + ip},
                       "request": {"request_line": line, "headers": {"Host": "192.168.0.100", "User-Agent": "Mozilla/5.0 test"}},
                       "response": {"status": status},
                       "audit_data": {"messages": msgs, "action": {"intercepted": intercepted}}})


def _msg(rule_id, msg, sev="CRITICAL"):
    return f'Warning. Pattern match "x" at ARGS. [file "rules.conf"] [line "1"] [id "{rule_id}"] [msg "{msg}"] [severity "{sev}"]'


def test_events_read_the_audit_log_newest_first(tmp_path, monkeypatch):
    log = tmp_path / "modsec_audit.log"
    monkeypatch.setattr(waf, "AUDIT", log)
    assert waf.events() == []   # no log yet
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    stamp = lambda minutes_ago: (now.replace(microsecond=0) - __import__("datetime").timedelta(minutes=minutes_ago)).strftime("%d/%b/%Y:%H:%M:%S.000000 +0000")
    log.write_text("\n".join([
        "not json",
        _event(stamp(26 * 60), "203.0.113.1", [_msg("942100", "SQLi")]),                                     # older than 24 h: cut off
        _event(stamp(30), "203.0.113.2", [_msg("920350", "numeric Host")], intercepted=False, status=200),      # noise only: dropped
        _event(stamp(20), "203.0.113.3", [_msg("920350", "numeric Host"), _msg("931100", "RFI"), _msg("949110", "score")]),
        _event(stamp(10), "203.0.113.4", [_msg("941100", "XSS")], intercepted=False, status=200),
        "{broken json",
    ]) + "\n")
    ev = waf.events()
    assert [e["ip"] for e in ev] == ["203.0.113.4", "203.0.113.3"]
    e3 = ev[1]
    assert e3["blocked"] is True and e3["status"] == 403 and e3["host"] == "192.168.0.100" and e3["ua"].startswith("Mozilla")
    assert [r["id"] for r in e3["rules"]] == ["931100"]    # the score summary and the pure-noise rule are filtered out
    assert e3["rules"][0]["category"] == "Remote file inclusion" and e3["rules"][0]["severity"] == "CRITICAL"
    assert ev[0]["blocked"] is False and ev[0]["rules"][0]["category"] == "XSS (cross-site scripting)"
    assert [e["ip"] for e in waf.events(ip="203.0.113.3")] == ["203.0.113.3"]
    assert len(waf.events(limit=1)) == 1
    assert waf.events(hours=15)[-1]["ip"] == "203.0.113.3"


def test_primary_rule_and_categories():
    rules = [{"id": "920350", "category": "Malformed request"}, {"id": "942100", "category": "SQL injection"}]
    assert waf._primary(rules)["id"] == "942100"
    assert waf._primary(rules[:1])["id"] == "920350"
    assert waf._category("933210") == "PHP injection" and waf._category("123456") == "Other"
    assert waf._ts("24/Oct/2026:12:34:56 +0300") > 0 and waf._ts("garbage") == 0.0


def test_status_sums_up_the_last_day(tmp_path, monkeypatch):
    monkeypatch.setattr(waf, "STATE", tmp_path / "waf.json")
    monkeypatch.setattr(waf, "installed", lambda: True)
    monkeypatch.setattr(waf, "module_on", lambda: True)
    monkeypatch.setattr(waf, "refresh_rules", lambda: False)
    monkeypatch.setattr(waf, "_run", lambda argv, **kw: type("R", (), {"returncode": 0, "stdout": "3.3.5-1\n"})())
    monkeypatch.setattr(waf, "events", lambda hours=24, limit=300, ip="": [
        {"ip": "203.0.113.3", "blocked": True, "rules": [{"id": "931100", "category": "Remote file inclusion"}]},
        {"ip": "203.0.113.3", "blocked": True, "rules": [{"id": "920350", "category": "Malformed request"}, {"id": "942100", "category": "SQL injection"}]},
        {"ip": "203.0.113.4", "blocked": False, "rules": [{"id": "941100", "category": "XSS (cross-site scripting)"}]}])
    st = waf.status()
    assert st["installed"] and st["crs_version"] == "3.3.5-1" and st["mode"] == "block" and "wordpress" in st["apps_all"]
    assert st["stats"]["events"] == 3 and st["stats"]["blocked"] == 2 and st["stats"]["detected"] == 1
    assert st["stats"]["ips"][0] == ["203.0.113.3", 2] or st["stats"]["ips"][0] == ("203.0.113.3", 2)
    assert dict(st["stats"]["types"])["SQL injection"] == 1   # the 920 noise never names the attack
