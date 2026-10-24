"""Slack app — alerts with buttons, attack reports you answer in one click, and a /aurora command.

How it talks to Slack: Socket Mode. The panel opens the connection to Slack itself (outbound
HTTPS/WebSocket), so button clicks and /aurora reach a Raspberry Pi at home with no public address,
open port or certificate. Messages are posted with the bot token (chat.postMessage) — from the panel
and from the task runner, which checks for problems every minute even while the panel restarts.

What it sends:
  • every alert (disk, services, certificates, backups, updates…) with Snooze, and Restart for a stopped
    service;
  • an attack report per address — WAF blocks, failed panel logins, fail2ban bans — with
    Ban / Trust / Allow this WAF rule. Every button flips (Ban ⇄ Unban, Trust ⇄ Untrust, Allow ⇄ Undo),
    so a click is always reversible, and the message keeps a line per action: who, what, when.

Only the Slack members listed as allowed can press buttons or use /aurora (the first one is added by
pressing "Allow me" in the test message). Everything they do is in the Activity Log as slack:<name>.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

STATE = Path("/var/lib/aurora/slack.json")        # settings + tokens (written by the panel)
SEEN = Path("/var/lib/aurora/slack-seen.json")     # which attackers were reported (written by the task runner)
API = "https://slack.com/api/"


class SlackError(RuntimeError):
    pass


# ------------------------------------------------------------------ settings
def _default() -> dict:
    return {"enabled": False, "bot_token": "", "app_token": "", "channel": "", "allowed": [],
            "security": True, "waf_min": 5, "login_min": 5, "fail2ban": True, "panel_url": "", "team": "", "bot": ""}


def load() -> dict:
    d = _default()
    try:
        d.update(json.loads(STATE.read_text()))
    except (OSError, ValueError):
        pass
    return d


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # bot tokens
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=1)
    tmp.replace(path)


def _save(s: dict) -> None:
    _write(STATE, s)


def enabled(s: dict | None = None) -> bool:
    s = s or load()
    return bool(s["enabled"] and s["bot_token"] and s["channel"])


def public() -> dict:
    s = load()
    out = {k: v for k, v in s.items() if k not in ("bot_token", "app_token")}
    out["bot_token_set"], out["app_token_set"] = bool(s["bot_token"]), bool(s["app_token"])
    out["socket"] = dict(_status)
    out["manifest"] = json.dumps(manifest(), indent=2)
    return out


def update(data: dict, panel_url: str = "") -> dict:
    s = load()
    for k, prefix, label in (("bot_token", "xoxb-", "Bot token"), ("app_token", "xapp-", "App-level token")):
        v = str(data.get(k) or "").strip()
        if v:
            if not re.fullmatch(rf"{prefix}[\w-]{{20,}}", v):
                raise SlackError(f"The {label} starts with {prefix} — copy it from your Slack app's settings")
            s[k] = v
    if "channel" in data:
        ch = str(data["channel"]).strip()
        if ch and not re.fullmatch(r"#?[a-z0-9][a-z0-9._-]{0,79}|[CGD][A-Z0-9]{8,}", ch):
            raise SlackError("Channel: a name like #alerts (lowercase) or a channel ID like C0123ABCD")
        s["channel"] = ch if not ch or ch.startswith("#") or re.fullmatch(r"[CGD][A-Z0-9]{8,}", ch) else "#" + ch
    if "allowed" in data:
        ids = [x.strip() for x in re.split(r"[\s,]+", str(data["allowed"]) if not isinstance(data["allowed"], list) else " ".join(data["allowed"])) if x.strip()]
        for x in ids:
            if not re.fullmatch(r"[UW][A-Z0-9]{6,}", x):
                raise SlackError(f"“{x}” isn't a Slack member ID (like U0123ABCD — in Slack: your profile → ⋮ → Copy member ID)")
        s["allowed"] = sorted(set(ids))
    for k in ("enabled", "security", "fail2ban"):
        if k in data:
            s[k] = bool(data[k])
    for k, lo, hi in (("waf_min", 1, 1000), ("login_min", 1, 1000)):
        if k in data:
            s[k] = max(lo, min(hi, int(data[k])))
    if panel_url:
        s["panel_url"] = panel_url.rstrip("/")
    if s["enabled"] and s["bot_token"]:
        who = _api("auth.test", s["bot_token"])
        s["team"], s["bot"] = who.get("team", ""), who.get("user", "")
    _save(s)
    restart()
    return public()


def manifest() -> dict:
    """Paste into api.slack.com/apps → Create New App → From a manifest: everything is set up."""
    host = socket.gethostname().split(".")[0]
    return {
        "display_information": {"name": f"AuroraPanel {host}"[:35], "description": "Alerts and one-click actions from your AuroraPanel server",
                                "background_color": "#1b1817"},
        "features": {"bot_user": {"display_name": f"aurora-{host}"[:80], "always_online": True},
                     "slash_commands": [{"command": "/aurora", "description": "Server status, alerts, ban / unban / trust an IP",
                                         "usage_hint": "status | alerts | ip 1.2.3.4 | ban 1.2.3.4 | unban 1.2.3.4 | trust 1.2.3.4", "should_escape": False}]},
        "oauth_config": {"scopes": {"bot": ["chat:write", "chat:write.public", "commands"]}},
        "settings": {"interactivity": {"is_enabled": True}, "org_deploy_enabled": False, "socket_mode_enabled": True, "token_rotation_enabled": False},
    }


# ------------------------------------------------------------------ Slack Web API
def _api(method: str, token: str, payload: dict | None = None) -> dict:
    req = urllib.request.Request(API + method, data=json.dumps(payload or {}).encode(),
                                 headers={"Content-Type": "application/json; charset=utf-8", "Authorization": f"Bearer {token}", "User-Agent": "AuroraPanel"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read(2_000_000))
    except (OSError, ValueError) as e:
        raise SlackError(f"Can't reach Slack: {e}")
    if not d.get("ok"):
        err = d.get("error", "unknown error")
        hint = {"invalid_auth": "the token is wrong or was revoked", "not_in_channel": "invite the bot to the channel (/invite @bot)",
                "channel_not_found": "no such channel (for a private one, invite the bot and use its ID)", "not_allowed_token_type": "that's the wrong kind of token",
                "missing_scope": "reinstall the app with the manifest from the panel"}.get(err, "")
        raise SlackError(f"Slack: {err}{' — ' + hint if hint else ''}")
    return d


def _respond(url: str, body: dict) -> None:
    """Reply through a response_url (replaces the message the button was on, or answers /aurora)."""
    if not url.startswith("https://hooks.slack.com/"):
        return
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=15).read(1000)
    except OSError:
        pass


def esc(t) -> str:
    """Slack mrkdwn: & < > must be escaped, or text from an attacker (a request line, a user agent)
    could ping @channel or show a fake link."""
    return str(t if t is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def post(text: str, blocks: list | None = None, s: dict | None = None) -> str:
    s = s or load()
    d = _api("chat.postMessage", s["bot_token"], {"channel": s["channel"], "text": text[:3000], "blocks": blocks or [], "unfurl_links": False})
    return d.get("ts", "")


# ------------------------------------------------------------------ message building
LEVEL_ICON = {"critical": "🔴", "warning": "🟠", "info": "🔵", "resolved": "✅"}


def _btn(text: str, action: str, value: dict, style: str | None = None, confirm: str | None = None) -> dict:
    b = {"type": "button", "text": {"type": "plain_text", "text": text[:75], "emoji": True}, "action_id": action, "value": json.dumps(value, separators=(",", ":"))[:2000]}
    if style:
        b["style"] = style
    if confirm:
        b["confirm"] = {"title": {"type": "plain_text", "text": "Are you sure?"}, "text": {"type": "mrkdwn", "text": confirm},
                        "confirm": {"type": "plain_text", "text": "Yes"}, "deny": {"type": "plain_text", "text": "Cancel"}}
    return b


def _link(text: str, path: str, s: dict) -> dict | None:
    if not s.get("panel_url"):
        return None
    return {"type": "button", "text": {"type": "plain_text", "text": text}, "url": f"{s['panel_url']}/#/{path}", "action_id": f"open_{path}"}


def _ip_state(ip: str) -> str:
    try:
        from . import guard
        return guard.status_of([ip]).get(ip, "")
    except Exception:
        return ""


def _rule_allowed(rule: str) -> bool:
    try:
        from . import waf
        return str(rule) in waf.load().get("disabled_rules", {})
    except Exception:
        return False


def ip_actions(ip: str, rule: dict | None = None, s: dict | None = None) -> dict:
    """The buttons for one address, showing what a click would do *now* (so they flip)."""
    s = s or load()
    st = _ip_state(ip)
    els = [_btn("Unban" if st == "banned" else "🚫 Ban", "unban" if st == "banned" else "ban", {"ip": ip}, None if st == "banned" else "danger"),
           _btn("Untrust" if st == "trusted" else "✓ Trust", "untrust" if st == "trusted" else "trust", {"ip": ip},
                None if st == "trusted" else "primary",
                None if st == "trusted" else f"Trust *{esc(ip)}*? It will never be blocked by the WAF, fail2ban or bans.")]
    if rule and rule.get("id"):
        on = _rule_allowed(rule["id"])
        els.append(_btn(f"Undo allow rule {rule['id']}" if on else f"Allow rule {rule['id']} (false alarm)", "restorerule" if on else "allowrule",
                        {"rule": rule["id"], "msg": (rule.get("msg") or "")[:150]}, None,
                        None if on else f"Stop WAF rule {esc(rule['id'])} for *every* visitor? Only when it blocks real users by mistake."))
    lk = _link("Open IP Blocker", "ipblocker", s)
    if lk:
        els.append(lk)
    return {"type": "actions", "block_id": f"ip:{ip}", "elements": els}


def _state_line(ip: str) -> str:
    st = _ip_state(ip)
    return {"banned": "🚫 *Banned now*", "trusted": "✓ *Trusted now*"}.get(st, "Not banned")


def attack_blocks(ip: str, headline: str, lines: list[str], rule: dict | None = None, s: dict | None = None) -> list:
    host = socket.gethostname()
    return [
        {"type": "section", "block_id": "head", "text": {"type": "mrkdwn", "text": f"🛡️ *{esc(headline)}*\n`{esc(ip)}` · {_state_line(ip)}"}},
        {"type": "section", "block_id": "what", "text": {"type": "mrkdwn", "text": "\n".join(lines)[:2900] or " "}},
        ip_actions(ip, rule, s),
        {"type": "context", "block_id": "meta", "elements": [{"type": "mrkdwn", "text": f"{esc(host)} · {datetime.now():%b %d %H:%M}"}]},
    ]


def alert_blocks(level: str, title: str, text: str, key: str = "", extra: dict | None = None, s: dict | None = None) -> list:
    s = s or load()
    host = socket.gethostname()
    blocks = [{"type": "section", "block_id": "head", "text": {"type": "mrkdwn", "text": f"{LEVEL_ICON.get(level, '•')} *{esc(title)}*\n{esc(text)}"}}]
    for ip, n in ((extra or {}).get("ips") or [])[:5]:
        blocks.append({"type": "section", "block_id": f"ipl:{ip}", "text": {"type": "mrkdwn", "text": f"`{esc(ip)}` ×{n} · {_state_line(ip)}"}})
        blocks.append(ip_actions(ip, None, s))
    acts = []
    if key.startswith("svc:"):
        acts.append(_btn(f"↻ Restart {key[4:]}", "restart", {"unit": key[4:]}, "primary"))
    if key and level != "resolved":
        from . import alerts
        snoozed = alerts.snoozed(key)
        acts.append(_btn("Unsnooze" if snoozed else "🔕 Snooze 24 h", "unsnooze" if snoozed else "snooze", {"key": key}))
    path = {"svc": "services", "disk": "diskusage", "cert": "ssl", "backup": "schedules", "updates": "updates", "reboot": "updates", "waf": "modsec", "logins": "activity"}.get(key.split(":")[0])
    lk = _link("Open in AuroraPanel", path or "alerts", s)
    if lk:
        acts.append(lk)
    if acts:
        blocks.append({"type": "actions", "block_id": "alert", "elements": acts})
    blocks.append({"type": "context", "block_id": "meta", "elements": [{"type": "mrkdwn", "text": f"{esc(host)} · {datetime.now():%b %d %H:%M}"}]})
    return blocks


def notify_alert(level: str, title: str, text: str, key: str = "", extra: dict | None = None) -> None:
    s = load()
    post(f"{LEVEL_ICON.get(level, '•')} {title}", alert_blocks(level, title, text, key, extra, s), s)


def test() -> dict:
    s = load()
    if not (s["bot_token"] and s["channel"]):
        raise SlackError("Save the bot token and a channel first")
    blocks = [{"type": "section", "block_id": "head", "text": {"type": "mrkdwn", "text":
               f"👋 *AuroraPanel on {esc(socket.gethostname())} is connected.*\nAlerts and attack reports will appear here with buttons."}},
              {"type": "actions", "block_id": "test", "elements": [_btn("Test the buttons", "ping", {}, "primary"),
                                                                     *([] if s["allowed"] else [_btn("Allow me to use the buttons", "claim", {})])]}]
    post("AuroraPanel is connected", blocks, s)
    return {"ok": True, "socket": dict(_status)}


# ------------------------------------------------------------------ attack reports (task runner)
def _seen() -> dict:
    try:
        return json.loads(SEEN.read_text())
    except (OSError, ValueError):
        return {}


def security_scan() -> list[str]:
    """Report each new attacker once a day: WAF blocks, failed panel logins, fail2ban bans."""
    s = load()
    if not (enabled(s) and s["security"]):
        return []
    now = time.time()
    seen = {k: v for k, v in _seen().items() if now - v < 86400}
    sent = []

    def fresh(kind: str, ip: str) -> bool:
        if f"{kind}:{ip}" in seen:
            return False
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if kind == "f2b":  # already banned — worth knowing even (especially) for an address on your own network
            return not a.is_loopback
        return not (a.is_private or a.is_loopback) and _ip_state(ip) not in ("banned", "trusted")

    try:
        from . import waf
        if waf.installed():
            by_ip: dict[str, list] = {}
            for e in waf.events(hours=1, limit=5000):
                if e["ts"] >= now - 600 and e["blocked"]:
                    by_ip.setdefault(e["ip"], []).append(e)
            for ip, evs in sorted(by_ip.items(), key=lambda x: -len(x[1])):
                if len(evs) < s["waf_min"] or not fresh("waf", ip) or len(sent) >= 5:
                    continue
                rules: dict[str, dict] = {}
                for e in evs:
                    r = e["rules"][0]
                    rules.setdefault(r["id"], {**r, "n": 0})["n"] += 1
                top = sorted(rules.values(), key=lambda r: -r["n"])
                lines = [f"The WAF blocked *{len(evs)}* requests in 10 minutes."]
                lines += [f"• {esc(r['category'])}: _{esc(r['msg'])}_ (rule {esc(r['id'])}) ×{r['n']}" for r in top[:3]]
                ex = evs[0]
                lines.append(f"Example: `{esc(ex['request'][:180])}` on {esc(ex['host'] or 'this server')}")
                if ex.get("ua"):
                    lines.append(f"Client: {esc(ex['ua'][:120])}")
                post(f"Attack from {ip}", attack_blocks(ip, f"Someone at {ip} is attacking your sites", lines, top[0], s), s)
                seen[f"waf:{ip}"] = now
                sent.append(f"waf:{ip}")
    except Exception as e:
        print(f"slack: WAF report failed: {e}", flush=True)
    try:
        from . import audit
        fails: dict[str, list] = {}
        for e in audit.entries(days=1, q="login failed")["entries"]:
            if e["ts"] >= now - 900 and e.get("ip"):
                fails.setdefault(e["ip"], []).append(e)
        for ip, evs in fails.items():
            if len(evs) < s["login_min"] or not fresh("login", ip):
                continue
            users = sorted({e.get("user") or "?" for e in evs})
            lines = [f"*{len(evs)}* failed sign-ins to the panel in 15 minutes.", f"Usernames tried: {esc(', '.join(u for u in users if u)[:300]) or '—'}",
                     "If this is you (a forgotten password), press Trust; otherwise Ban."]
            post(f"Failed logins from {ip}", attack_blocks(ip, f"Someone at {ip} is guessing panel passwords", lines, None, s), s)
            seen[f"login:{ip}"] = now
            sent.append(f"login:{ip}")
    except Exception as e:
        print(f"slack: login report failed: {e}", flush=True)
    if s["fail2ban"]:
        try:
            from . import guard
            for ip, jails in guard._f2b_jails_by_ip().items():
                if f"f2b:{ip}" in seen or not fresh("f2b", ip) or len(sent) >= 10:
                    continue
                lines = [f"fail2ban banned it for repeated failures: *{esc(', '.join(jails))}*.",
                         "Locked yourself out? Unban (and Trust your own address)."]
                post(f"fail2ban banned {ip}", attack_blocks(ip, f"fail2ban banned {ip}", lines, None, s), s)
                seen[f"f2b:{ip}"] = now
                sent.append(f"f2b:{ip}")
        except Exception as e:
            print(f"slack: fail2ban report failed: {e}", flush=True)
    if sent or len(seen) != len(_seen()):
        _write(SEEN, seen)
    return sent


# ------------------------------------------------------------------ handling clicks and /aurora
def _allowed(s: dict, uid: str) -> bool:
    return uid in s["allowed"]


def _who(payload: dict) -> tuple[str, str]:
    u = payload.get("user") or {}
    uid = u.get("id") or payload.get("user_id", "")
    name = u.get("username") or u.get("name") or payload.get("user_name") or uid
    return uid, name


def _audit(name: str, action: str, ok: bool = True, detail=None) -> None:
    try:
        from . import audit
        audit.record(f"slack:{name}"[:64], "slack", action, ok=ok, status=200 if ok else 400, detail=detail, method="SLACK", path="/slack")
    except Exception:
        pass


def _do(action: str, v: dict, name: str) -> str:
    """Run one button's action; returns the line added to the message."""
    from . import guard
    ip = v.get("ip", "")
    if ip:
        ipaddress.ip_address(ip)  # only what we put in the button
    if action == "ban":
        guard.ban(ip, f"Slack: {name}", None, None, "Slack")
        return f"🚫 Banned {ip}"
    if action == "unban":
        guard.unban(ip)
        return f"↩ Unbanned {ip}"
    if action == "trust":
        guard.trust(ip, f"Slack: {name}")
        return f"✓ Trusted {ip}"
    if action == "untrust":
        guard.untrust(ip)
        return f"↩ No longer trusted: {ip}"
    if action in ("allowrule", "restorerule"):
        from . import waf
        rule = str(v.get("rule", ""))
        if not re.fullmatch(r"\d{3,7}", rule):
            raise SlackError("Unknown rule")
        if action == "allowrule":
            waf.allow_rule(rule, f"{v.get('msg', '')} (Slack: {name})")
            return f"✓ WAF rule {rule} allowed (no longer blocks anyone)"
        waf.restore_rule(rule)
        return f"↩ WAF rule {rule} is blocking again"
    if action == "restart":
        from . import services
        unit = str(v.get("unit", ""))
        services.control_service(unit, "restart")
        time.sleep(2)
        st = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=10).stdout.strip()
        return f"↻ Restarted {unit}: {st or 'unknown'}"
    if action in ("snooze", "unsnooze"):
        from . import alerts
        key = str(v.get("key", ""))[:200]
        alerts.snooze(key, 24 if action == "snooze" else 0)
        return "🔕 Snoozed for 24 hours (no reminders)" if action == "snooze" else "🔔 Reminders back on"
    raise SlackError("Unknown action")


def _rebuild(blocks: list, line: str, s: dict) -> list:
    """The same message with fresh buttons (so they show the reverse action) and one more history line."""
    out, hist = [], None
    for b in blocks:
        bid = b.get("block_id", "")
        if b.get("type") == "actions" and bid.startswith("ip:"):
            ip = bid[3:]
            rule = None
            for el in b.get("elements", []):
                if el.get("action_id") in ("allowrule", "restorerule"):
                    try:
                        v = json.loads(el.get("value") or "{}")
                        rule = {"id": v.get("rule"), "msg": v.get("msg", "")}
                    except ValueError:
                        pass
            out.append(ip_actions(ip, rule, s))
        elif b.get("type") == "actions" and bid == "alert":
            els = []
            for el in b.get("elements", []):
                if el.get("action_id") in ("snooze", "unsnooze"):
                    try:
                        key = json.loads(el.get("value") or "{}").get("key", "")
                    except ValueError:
                        key = ""
                    from . import alerts
                    sn = alerts.snoozed(key)
                    els.append(_btn("Unsnooze" if sn else "🔕 Snooze 24 h", "unsnooze" if sn else "snooze", {"key": key}))
                else:
                    els.append(el)
            out.append({**b, "elements": els})
        elif b.get("type") == "section" and (bid == "head" or bid.startswith("ipl:")) and "`" in json.dumps(b):
            txt = b["text"]["text"]
            ip = bid[4:] if bid.startswith("ipl:") else (re.search(r"`([0-9a-fA-F:.]+)`", txt) or [None, None])[1]
            if ip:
                txt = re.sub(r"(Not banned|🚫 \*Banned now\*|✓ \*Trusted now\*)$", _state_line(ip), txt, flags=re.M)
            out.append({**b, "text": {**b["text"], "text": txt}})
        elif bid == "hist":
            hist = b
        else:
            out.append(b)
    lines = [e["text"] for e in (hist or {}).get("elements", [])][-8:]
    lines.append(line)
    out.append({"type": "context", "block_id": "hist", "elements": [{"type": "mrkdwn", "text": t} for t in lines[-9:]]})
    return out


def handle_action(payload: dict) -> None:
    s = load()
    uid, name = _who(payload)
    url = payload.get("response_url", "")
    msg = payload.get("message") or {}
    for a in payload.get("actions", [])[:1]:
        action = a.get("action_id", "")
        if action.startswith("open_"):
            return  # a link button: Slack opens it
        try:
            v = json.loads(a.get("value") or "{}")
        except ValueError:
            v = {}
        stamp = datetime.now().strftime("%H:%M")
        if action == "claim":
            if s["allowed"]:
                line = f"Already set up — ask <@{s['allowed'][0]}> to add <@{uid}> in AuroraPanel → Alerts → Slack"
            else:
                s["allowed"] = [uid]
                _save(s)
                _audit(name, "Slack: allowed to use the buttons")
                line = f"✓ <@{uid}> can now use the buttons and /aurora (add more people in AuroraPanel → Alerts → Slack)"
        elif action == "ping":
            line = f"✓ Buttons work, <@{uid}> — your member ID is `{esc(uid)}`" + ("" if _allowed(s, uid) else " (not allowed to take actions yet)")
        elif not _allowed(s, uid):
            _audit(name, f"Slack: refused {action}", ok=False, detail=v)
            _respond(url, {"response_type": "ephemeral", "replace_original": False,
                           "text": f"⛔ You're not allowed to do this. Your member ID is {uid} — an admin can add it in AuroraPanel → Alerts → Slack."})
            return
        else:
            try:
                did = _do(action, v, name)
                _audit(name, f"Slack: {did}", detail=v)
                line = f"{esc(did)} — <@{uid}> · {stamp}"
            except Exception as e:
                _audit(name, f"Slack: {action} failed", ok=False, detail={"error": str(e)[:200], **v})
                line = f"⚠️ {esc(str(e)[:200])} — <@{uid}> · {stamp}"
        _respond(url, {"replace_original": True, "text": (msg.get("text") or "AuroraPanel")[:3000], "blocks": _rebuild(msg.get("blocks") or [], line, s)})


def handle_command(payload: dict) -> None:
    s = load()
    uid, name = _who(payload)
    url = payload.get("response_url", "")
    if not _allowed(s, uid):
        _respond(url, {"response_type": "ephemeral", "text": f"⛔ Not allowed. Your member ID is {uid} — add it in AuroraPanel → Alerts → Slack."})
        return
    args = (payload.get("text") or "").split()
    cmd = (args[0].lower() if args else "status")
    try:
        if cmd in ("ban", "unban", "trust", "untrust", "ip", "who") and len(args) == 2:
            ip = str(ipaddress.ip_address(args[1]))
            line = ""
            if cmd not in ("ip", "who"):
                did = _do(cmd, {"ip": ip}, name)
                _audit(name, f"Slack /aurora: {did}")
                line = f"{esc(did)} — <@{uid}> · {datetime.now():%H:%M}"
            blocks = attack_blocks(ip, f"Address {ip}", _ip_summary(ip), None, s)
            if line:
                blocks.append({"type": "context", "block_id": "hist", "elements": [{"type": "mrkdwn", "text": line}]})
            _respond(url, {"response_type": "ephemeral", "text": f"{ip}", "blocks": blocks})
        elif cmd == "alerts":
            from . import alerts
            act = alerts.load()["active"]
            txt = "\n".join(f"{LEVEL_ICON.get(a['level'], '•')} *{esc(a['title'])}* — since {datetime.fromtimestamp(a['since']):%b %d %H:%M}" for a in act.values()) or "✅ Nothing needs you right now."
            _respond(url, {"response_type": "ephemeral", "text": txt})
        elif cmd == "status":
            _respond(url, {"response_type": "ephemeral", "text": _status_text()})
        else:
            _respond(url, {"response_type": "ephemeral", "text": "*/aurora* `status` · `alerts` · `ip 1.2.3.4` · `ban 1.2.3.4` · `unban 1.2.3.4` · `trust 1.2.3.4` · `untrust 1.2.3.4`"})
    except Exception as e:
        _respond(url, {"response_type": "ephemeral", "text": f"⚠️ {esc(str(e)[:300])}"})


def _ip_summary(ip: str) -> list[str]:
    out = []
    try:
        from . import waf
        if waf.installed():
            ev = waf.events(hours=24, limit=2000, ip=ip)
            if ev:
                out.append(f"WAF: *{len(ev)}* blocked or flagged requests in 24 h, e.g. `{esc(ev[0]['request'][:150])}`")
    except Exception:
        pass
    try:
        from . import audit
        n = sum(1 for e in audit.entries(days=1, q="login failed")["entries"] if e.get("ip") == ip)
        if n:
            out.append(f"Failed panel logins in 24 h: *{n}*")
    except Exception:
        pass
    try:
        from . import guard
        j = guard._f2b_jails_by_ip().get(ip)
        if j:
            out.append(f"fail2ban: banned in {esc(', '.join(j))}")
    except Exception:
        pass
    return out or ["Nothing from this address in the last 24 hours."]


def _status_text() -> str:
    import psutil
    vm, du = psutil.virtual_memory(), psutil.disk_usage("/")
    up = time.time() - psutil.boot_time()
    from . import alerts
    act = alerts.load()["active"]
    return (f"*{esc(socket.gethostname())}* · up {up / 86400:.1f} days\n"
            f"CPU load {os.getloadavg()[0]:.2f} · memory {vm.percent:.0f}% · disk / {du.percent:.0f}% ({du.free / 1e9:.0f} GB free)\n"
            + (f"⚠️ {len(act)} problem(s): " + ", ".join(esc(a['title']) for a in list(act.values())[:5]) if act else "✅ No problems"))


# ------------------------------------------------------------------ Socket Mode (panel process)
_status: dict = {"connected": False, "since": 0, "error": ""}
_stop = threading.Event()
_thread: threading.Thread | None = None
_lock = threading.Lock()


def _socket_loop(stop: threading.Event) -> None:
    from websockets.sync.client import connect
    backoff = 2
    while not stop.is_set():
        s = load()
        if not (s["enabled"] and s["app_token"]):
            _status.update(connected=False, error="")
            return
        try:
            url = _api("apps.connections.open", s["app_token"])["url"]
            with connect(url, open_timeout=15, close_timeout=3, max_size=4_000_000) as ws:
                _status.update(connected=True, since=time.time(), error="")
                backoff = 2
                while not stop.is_set():
                    try:
                        raw = ws.recv(timeout=5)
                    except TimeoutError:
                        continue
                    env = json.loads(raw)
                    typ = env.get("type")
                    if env.get("envelope_id"):
                        ws.send(json.dumps({"envelope_id": env["envelope_id"]}))  # ack within 3 s, then work
                    if typ == "disconnect":
                        break
                    p = env.get("payload") or {}
                    if typ == "interactive" and p.get("type") == "block_actions":
                        threading.Thread(target=handle_action, args=(p,), daemon=True).start()
                    elif typ == "slash_commands":
                        threading.Thread(target=handle_command, args=(p,), daemon=True).start()
        except Exception as e:
            _status.update(connected=False, error=str(e)[:200])
            stop.wait(backoff)
            backoff = min(backoff * 2, 120)
    _status.update(connected=False)


def start() -> None:
    """Connect to Slack when the panel starts (or after the settings change)."""
    global _thread, _stop
    with _lock:
        if _thread and _thread.is_alive():
            return
        s = load()
        if not (s["enabled"] and s["app_token"]):
            return
        _stop = threading.Event()
        _thread = threading.Thread(target=_socket_loop, args=(_stop,), daemon=True, name="slack-socket")
        _thread.start()


def restart() -> None:
    global _thread
    with _lock:
        if _thread:
            _stop.set()
            _thread.join(timeout=8)
            _thread = None
    start()
