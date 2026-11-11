"""The WAF for Nginx: which files it writes, and that a refusal from Nginx changes nothing."""
import json
import subprocess

import pytest

from backend import nginxsites as S, nginxwaf as W, waf


@pytest.fixture
def box(tmp_path, monkeypatch):
    conf = tmp_path / "conf.d"
    conf.mkdir()
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "REQUEST-901.conf").write_text("# rules")
    setup = tmp_path / "crs-setup.conf"
    setup.write_text("# setup")
    state = {"refuse": False, "calls": []}

    def run(argv, timeout=60):
        state["calls"].append(" ".join(argv))
        if argv[:2] == ["nginx", "-t"] and state["refuse"]:
            return subprocess.CompletedProcess(argv, 1, "", "nginx: [emerg] rules failed")
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(S, "_run", run)
    monkeypatch.setattr(S, "_active", lambda u: u == "nginx")
    monkeypatch.setattr(S, "RELOAD_SETTLE", 0)
    monkeypatch.setattr(W, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(W, "DIR", tmp_path / "waf")
    monkeypatch.setattr(W, "MAIN", tmp_path / "waf" / "main.conf")
    monkeypatch.setattr(W, "PRE", tmp_path / "waf" / "pre.conf")
    monkeypatch.setattr(W, "POST", tmp_path / "waf" / "post.conf")
    monkeypatch.setattr(W, "HOOK", conf / "aurora-waf.conf")
    monkeypatch.setattr(W, "module_installed", lambda: True)
    monkeypatch.setattr(W, "find_crs", lambda: (str(setup), [str(tmp_path / "rules" / "REQUEST-901.conf")]))
    monkeypatch.setattr(waf, "load", lambda: {"mode": "block", "paranoia": 2, "threshold": 7, "apps": [], "trusted": [], "sites_off": [], "disabled_rules": {"942100": {"msg": "x"}}})
    monkeypatch.setattr(waf, "_panel_trusted", lambda: [])
    monkeypatch.setattr(waf, "instaban_lists", lambda: {})   # this machine's own InstaBan list stays out of it
    return state


def test_turning_it_on_writes_rules_in_the_right_order_and_checks_first(box):
    s = W.set_mode("block")
    assert s["mode"] == "block" and s["protecting"] and W.mode() == "block"
    main = W.MAIN.read_text()
    assert main.index(str(W.PRE.as_posix())) < main.index("crs-setup.conf") < main.index("REQUEST-901") < main.index(str(W.POST.as_posix()))
    assert "SecAuditLogFormat JSON" in main and "SecResponseBodyAccess Off" in main
    assert "SecRuleEngine On" in W.PRE.read_text() and "tx.paranoia_level=2" in W.PRE.read_text() and "inbound_anomaly_score_threshold=7" in W.PRE.read_text()
    assert W.POST.read_text().endswith("SecRuleRemoveById 942100\n") and "IfModule" not in W.POST.read_text()
    assert "modsecurity on;" in W.HOOK.read_text()
    assert box["calls"].index("nginx -t") < box["calls"].index("systemctl reload nginx")


def test_detect_mode_only_watches(box):
    assert W.set_mode("detect")["protecting"] is False
    assert "SecRuleEngine DetectionOnly" in W.PRE.read_text() and W.mode() == "detect"


def test_off_takes_it_out_of_nginx(box):
    W.set_mode("block")
    assert W.set_mode("off")["mode"] == "off" and not W.HOOK.exists()


def test_a_refusal_changes_nothing(box):
    W.set_mode("detect")
    before = W.PRE.read_text()
    box["refuse"] = True
    with pytest.raises(W.NginxWafError, match="rules failed"):
        W.set_mode("block")
    assert W.PRE.read_text() == before and W.mode() == "detect"


def test_never_claims_to_protect_without_the_module_or_rules(box, monkeypatch):
    monkeypatch.setattr(W, "module_installed", lambda: False)
    with pytest.raises(W.NginxWafError, match="isn't installed"):
        W.set_mode("block")
    assert W.status()["protecting"] is False and W.status()["installed"] is False
    assert not W.HOOK.exists()


def test_unknown_mode(box):
    with pytest.raises(W.NginxWafError):
        W.set_mode("sometimes")


def test_settings_changed_on_the_waf_page_are_passed_on_only_when_on(box):
    W.refresh()
    assert not W.PRE.exists()
    W.set_mode("block")
    waf.load = lambda: {"mode": "block", "paranoia": 3, "threshold": 7, "apps": [], "trusted": [], "sites_off": [], "disabled_rules": {}}
    W.refresh()
    assert "tx.paranoia_level=3" in W.PRE.read_text() and "SecRuleRemoveById" not in W.POST.read_text()


def test_mode_defaults_to_off_and_survives_a_bad_file(box):
    assert W.mode() == "off"
    W.STATE.write_text("{broken")
    assert W.mode() == "off"
    W.STATE.write_text(json.dumps({"mode": "everything"}))
    assert W.mode() == "off"


@pytest.mark.parametrize("url,local", [("http://127.0.0.1:3000", True), ("http://localhost:8080/", True), ("http://[::1]:80", True), ("http://192.168.0.5:80", False), ("http://example.com", False), ("http://127.0.0.1.evil.example/", False)])
def test_local_only_targets(url, local):
    assert W.is_local_only(url) is local


def test_routes(admin, box):
    assert admin.get("/api/nginx/waf").json()["installed"] is True
    assert admin.post("/api/nginx/waf", json={"mode": "detect"}).json()["mode"] == "detect"
    assert admin.post("/api/nginx/waf", json={"mode": "nope"}).status_code == 400


def test_routes_need_a_login(client):
    assert client.get("/api/nginx/waf").status_code == 401
    assert client.post("/api/nginx/waf", json={"mode": "off"}).status_code == 401
