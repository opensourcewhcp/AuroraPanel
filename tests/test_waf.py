"""WAF rules: the built-in Roundcube exception under /webmail/."""
from backend import waf


def test_roundcube_exception_is_rendered_only_for_webmail(tmp_path, monkeypatch):
    monkeypatch.setattr(waf, "STATE", tmp_path / "waf.json")
    s = waf.load()
    assert "roundcube" in s["apps"] and "roundcube" in s["seen"]
    pre = waf.render_pre(s)
    assert waf.ROUNDCUBE_RULE in pre and "crs_exclusions_roundcube" not in pre and "crs_exclusions_wordpress" in pre
    assert '@beginsWith /webmail/' in waf.ROUNDCUBE_RULE and "931100-931199" in waf.ROUNDCUBE_RULE and "ruleRemoveById=920230" in waf.ROUNDCUBE_RULE
    s["apps"] = [a for a in s["apps"] if a != "roundcube"]
    assert "1000103" not in waf.render_pre(s)


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
