"""Slack app: settings checks, who may press buttons, buttons that flip, escaping, attack reports."""
import json

import pytest

from backend import alerts, slackbot


@pytest.fixture
def slack(tmp_path, monkeypatch):
    monkeypatch.setattr(slackbot, "STATE", tmp_path / "slack.json")
    monkeypatch.setattr(slackbot, "SEEN", tmp_path / "seen.json")
    monkeypatch.setattr(alerts, "SNOOZE", tmp_path / "snooze.json")
    monkeypatch.setattr(slackbot, "restart", lambda: None)
    posted, responses = [], []
    monkeypatch.setattr(slackbot, "post", lambda text, blocks=None, s=None: posted.append((text, blocks)) or "1.0")
    monkeypatch.setattr(slackbot, "_respond", lambda url, body: responses.append(body))
    monkeypatch.setattr(slackbot, "_audit", lambda *a, **k: None)
    state = {}  # ip -> banned/trusted, standing in for the firewall
    monkeypatch.setattr(slackbot, "_ip_state", lambda ip: state.get(ip, ""))
    s = slackbot._default()
    s.update(enabled=True, bot_token="xoxb-" + "1" * 30, channel="#alerts")
    slackbot._save(s)
    return {"posted": posted, "responses": responses, "state": state}


def test_settings_are_checked(slack):
    with pytest.raises(slackbot.SlackError, match="xoxb-"):
        slackbot.update({"bot_token": "xapp-wrong-kind-of-token-123456"})
    with pytest.raises(slackbot.SlackError, match="member ID"):
        slackbot.update({"allowed": "bob"})
    with pytest.raises(slackbot.SlackError, match="Channel"):
        slackbot.update({"channel": "Not A Channel!"})
    r = slackbot.update({"enabled": False, "channel": "alerts", "allowed": "U0123ABCD, U0456EFGH U0123ABCD"})
    assert r["channel"] == "#alerts" and r["allowed"] == ["U0123ABCD", "U0456EFGH"]
    assert "bot_token" not in r and r["bot_token_set"] is True  # tokens never go back to the browser


def test_manifest_uses_socket_mode():
    m = slackbot.manifest()
    assert m["settings"]["socket_mode_enabled"] and m["settings"]["interactivity"]["is_enabled"]
    assert m["features"]["slash_commands"][0]["command"] == "/aurora"
    assert "url" not in json.dumps(m["features"])  # nothing for Slack to call back: works behind NAT


def test_attacker_text_is_escaped():
    assert slackbot.esc("<!channel> & <https://evil|bank>") == "&lt;!channel&gt; &amp; &lt;https://evil|bank&gt;"


def _press(action, value, uid="U0123ABCD", blocks=None):
    return {"type": "block_actions", "user": {"id": uid, "username": "ann"}, "response_url": "https://hooks.slack.com/x",
            "actions": [{"action_id": action, "value": json.dumps(value)}], "message": {"text": "t", "blocks": blocks or []}}


def test_only_allowed_members_act_and_first_can_claim(slack, monkeypatch):
    did = []
    monkeypatch.setattr(slackbot, "_do", lambda a, v, n: did.append(a) or "done")
    slackbot.handle_action(_press("ban", {"ip": "203.0.113.7"}))
    assert not did and "not allowed" in slack["responses"][-1]["text"]
    slackbot.handle_action(_press("claim", {}))  # nobody allowed yet: the first presser becomes allowed
    assert slackbot.load()["allowed"] == ["U0123ABCD"]
    slackbot.handle_action(_press("claim", {}, uid="U0999ZZZZ"))  # can't be taken over later
    assert slackbot.load()["allowed"] == ["U0123ABCD"]
    slackbot.handle_action(_press("ban", {"ip": "203.0.113.7"}))
    assert did == ["ban"]


def test_buttons_flip_and_history_grows(slack, monkeypatch):
    s = slackbot.load()
    s["allowed"] = ["U0123ABCD"]
    slackbot._save(s)

    def fake_do(action, v, name):
        slack["state"][v["ip"]] = {"ban": "banned", "unban": "", "trust": "trusted", "untrust": ""}[action]
        return f"{action} {v['ip']}"
    monkeypatch.setattr(slackbot, "_do", fake_do)
    blocks = slackbot.attack_blocks("203.0.113.7", "Attack", ["x"], None, s)
    acts = lambda bl: [e["action_id"] for b in bl if b.get("block_id") == "ip:203.0.113.7" for e in b["elements"] if "action_id" in e and not e["action_id"].startswith("open_")]
    assert acts(blocks) == ["ban", "trust"]
    slackbot.handle_action(_press("ban", {"ip": "203.0.113.7"}, blocks=blocks))
    b2 = slack["responses"][-1]["blocks"]
    assert acts(b2) == ["unban", "trust"] and "Banned now" in b2[0]["text"]["text"]
    slackbot.handle_action(_press("unban", {"ip": "203.0.113.7"}, blocks=b2))
    b3 = slack["responses"][-1]["blocks"]
    assert acts(b3) == ["ban", "trust"]
    hist = [b for b in b3 if b.get("block_id") == "hist"][0]["elements"]
    assert [h["text"].split(" —")[0] for h in hist] == ["ban 203.0.113.7", "unban 203.0.113.7"]


def test_bad_ip_in_button_is_refused(slack):
    with pytest.raises(ValueError):
        slackbot._do("ban", {"ip": "1.2.3.4; rm -rf /"}, "x")


def test_snooze_toggles(slack):
    assert not alerts.snoozed("disk:/")
    alerts.snooze("disk:/", 24)
    assert alerts.snoozed("disk:/")
    alerts.snooze("disk:/", 0)
    assert not alerts.snoozed("disk:/")


def test_attack_reported_once(slack, monkeypatch):
    import time
    from backend import waf
    now = time.time()
    ev = [{"ts": now - 30, "ip": "45.155.205.10", "blocked": True, "host": "site.test", "request": "GET /?q=<script>", "ua": "x",
           "rules": [{"id": "941100", "msg": "XSS", "category": "XSS", "severity": "CRITICAL"}]}] * 6
    ev += [{**ev[0], "ip": "192.168.1.5"}] * 9  # a private address is never reported
    monkeypatch.setattr(waf, "installed", lambda: True)
    monkeypatch.setattr(waf, "events", lambda **k: ev)
    s = slackbot.load()
    s["fail2ban"] = False
    slackbot._save(s)
    assert slackbot.security_scan() == ["waf:45.155.205.10"]
    text = json.dumps(slack["posted"][-1][1])
    assert "&lt;script&gt;" in text and "<script>" not in text and "allowrule" in text
    assert slackbot.security_scan() == []  # once a day per address
