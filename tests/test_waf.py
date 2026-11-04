"""WAF rules: the built-in Roundcube exception under /webmail/."""
from backend import waf


def test_roundcube_exception_is_rendered_only_for_webmail(tmp_path, monkeypatch):
    monkeypatch.setattr(waf, "STATE", tmp_path / "waf.json")
    s = waf.load()
    assert "roundcube" in s["apps"] and "roundcube" in s["seen"]
    pre = waf.render_pre(s)
    assert waf.ROUNDCUBE_RULE in pre and "crs_exclusions_roundcube" not in pre and "crs_exclusions_wordpress" in pre
    assert '@beginsWith /webmail/' in waf.ROUNDCUBE_RULE and "ctl:ruleEngine=DetectionOnly" in waf.ROUNDCUBE_RULE   # watched, never blocked
    assert "ctl:requestBodyAccess=Off" in waf.ROUNDCUBE_RULE and "phase:1" in waf.ROUNDCUBE_RULE   # letters are never scanned
    s["apps"] = [a for a in s["apps"] if a != "roundcube"]
    off = waf.render_pre(s)
    assert "1000103" not in off and waf.WEBMAIL_BODY_RULE in off   # exception off: webmail checked, letters still never scanned
    assert "ctl:ruleEngine" not in waf.WEBMAIL_BODY_RULE and "ctl:requestBodyAccess=Off" in waf.WEBMAIL_BODY_RULE


def test_panel_trusted_addresses_are_exempt_from_the_waf_too(tmp_path, monkeypatch):
    # The owner's machine is Trusted (IP Blocker & Trust); opening WordPress by IP from there must never 403.
    from backend import guard
    monkeypatch.setattr(waf, "STATE", tmp_path / "waf.json")
    monkeypatch.setattr(guard, "trusted_cidrs", lambda: ["192.168.0.2/32", "10.8.0.0/24"])
    s = waf.load()
    # A single address goes in bare: ModSecurity refuses "192.168.0.2/32" in an @ipMatch list.
    assert 'SecRule REMOTE_ADDR "@ipMatch 10.8.0.0/24,192.168.0.2" "id:1000101,phase:1,pass,nolog,ctl:ruleEngine=Off"' in waf.render_pre(s)
    s["trusted"] = ["10.0.0.5"]
    assert '@ipMatch 10.0.0.5,10.8.0.0/24,192.168.0.2"' in waf.render_pre(s)   # the WAF page's own list is kept as well
    monkeypatch.setattr(guard, "trusted_cidrs", lambda: [])
    s["trusted"] = []
    assert "1000101" not in waf.render_pre(s)


def test_old_installs_get_the_exception_once(tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(waf, "STATE", tmp_path / "waf.json")
    (tmp_path / "waf.json").write_text(json.dumps({"mode": "block", "paranoia": 2, "apps": ["wordpress"]}), encoding="utf-8")
    s = waf.load()
    assert s["apps"] == ["wordpress", "roundcube"] and s["paranoia"] == 2
    # Switched off by the admin afterwards: it stays off.
    s["apps"] = ["wordpress"]
    waf._save(s)
    assert waf.load()["apps"] == ["wordpress"]


def test_rules_are_rewritten_once_per_revision(tmp_path, monkeypatch):
    monkeypatch.setattr(waf, "STATE", tmp_path / "waf.json")
    monkeypatch.setattr(waf, "installed", lambda: True)
    monkeypatch.setattr(waf, "module_on", lambda: True)
    calls = []
    monkeypatch.setattr(waf, "apply", lambda s=None: calls.append(1) or {"ok": True})
    assert waf.refresh_rules() is True and len(calls) == 1          # a fresh or older install: written once
    assert waf.refresh_rules() is False and len(calls) == 1         # same revision: nothing to do
    assert waf.load()["rules_rev"] == waf.RULES_REV
    monkeypatch.setattr(waf, "RULES_REV", waf.RULES_REV + 1)
    assert waf.refresh_rules() is True and len(calls) == 2          # a newer release: once more
