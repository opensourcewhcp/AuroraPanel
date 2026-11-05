"""Stage 6: alerts. One alert per thing per window, sent to whichever channels want that severity.

Quiet hours hold back everything below CRITICAL. An alert nobody could be told about stays undelivered and is retried.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import socket
import time
import urllib.error
import urllib.request

KINDS = ("email", "telegram", "slack", "discord", "webhook", "syslog")
RANK = {"NOTICE": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
DEDUPE_SECONDS = 900
ESCALATE_COUNT = 20
MAX_RETRY_AGE = 86400
SECRET_KEYS = {"token", "secret", "url"}


class AlertError(ValueError):
    pass


def check_channel(kind: str, cfg: dict) -> dict:
    cfg = dict(cfg or {})
    if kind not in KINDS:
        raise AlertError("Unknown channel kind")
    if kind == "email":
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", str(cfg.get("to") or "")):
            raise AlertError("That isn't an email address")
    elif kind == "telegram":
        if not re.fullmatch(r"\d+:[\w-]{20,}", str(cfg.get("token") or "")) or not re.fullmatch(r"-?\d{1,20}|@\w{3,64}", str(cfg.get("chat") or "")):
            raise AlertError("Telegram needs a bot token and a chat ID")
    elif kind in ("slack", "discord", "webhook"):
        if not re.match(r"^https://[^\s]+$|^http://(127\.|10\.|192\.168\.|localhost)[^\s]*$", str(cfg.get("url") or "")):
            raise AlertError("A web address must be https (plain http only on your own network)")
    elif kind == "syslog":
        if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", str(cfg.get("host") or "")) or not 1 <= int(cfg.get("port") or 514) <= 65535 or cfg.get("proto", "udp") not in ("udp", "tcp"):
            raise AlertError("Syslog needs a host, a port and udp or tcp")
    return cfg


def public_channel(row: dict) -> dict:
    """What the page may show: not the token or webhook address."""
    cfg = json.loads(row["config"]) if isinstance(row["config"], str) else row["config"]
    return {**row, "config": {k: ("set" if k in SECRET_KEYS and v else v) for k, v in cfg.items()}}


def sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _post(url: str, body: bytes, headers: dict) -> None:
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "AuroraPanel", **headers}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310  the operator's own address, checked in check_channel
        r.read(1000)


def send_syslog(host: str, port: int, proto: str, line: str) -> None:
    data = line.encode("utf-8", "replace")[:8000]
    if proto == "tcp":
        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(data + b"\n")
    else:
        with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(data, (host, port))


def deliver(kind: str, cfg: dict, alert: dict, mailer=None) -> None:
    text = f"[{alert['severity']}] {alert['title']}" + (f"\n{alert['detail']}" if alert.get("detail") else "") + (f"\n({alert['count']} times)" if alert.get("count", 1) > 1 else "")
    if kind == "email":
        (mailer or _mail)(cfg["to"], f"AuroraPanel: {alert['title']}"[:150], text)
    elif kind == "telegram":
        _post(f"https://api.telegram.org/bot{cfg['token']}/sendMessage", json.dumps({"chat_id": cfg["chat"], "text": text[:3900]}).encode(), {})
    elif kind == "slack":
        _post(cfg["url"], json.dumps({"text": text[:3900]}).encode(), {})
    elif kind == "discord":
        _post(cfg["url"], json.dumps({"content": text[:1900]}).encode(), {})
    elif kind == "webhook":
        body = json.dumps({"kind": alert["kind"], "severity": alert["severity"], "title": alert["title"], "detail": alert.get("detail", ""), "count": alert.get("count", 1), "ts": alert["last_ts"]}).encode()
        _post(cfg["url"], body, {"X-Aurora-Signature": "sha256=" + sign(cfg.get("secret", ""), body)} if cfg.get("secret") else {})
    elif kind == "syslog":
        send_syslog(cfg["host"], int(cfg.get("port") or 514), cfg.get("proto", "udp"), f"<{ {'CRITICAL': 10, 'ERROR': 11, 'WARNING': 12}.get(alert['severity'], 13) }>aurora-ella: {text}".replace("\n", " "))


def _mail(to: str, subject: str, text: str) -> None:
    import smtplib
    from email.message import EmailMessage
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "aurorapanel@localhost", to, subject
    m.set_content(text)
    with smtplib.SMTP("127.0.0.1", 25, timeout=10) as s:
        s.send_message(m)


def _quiet(ch: dict, severity: str, hour: int) -> bool:
    a, b = ch.get("quiet_from"), ch.get("quiet_to")
    if a is None or b is None or severity == "CRITICAL":
        return False
    return (a <= hour < b) if a <= b else (hour >= a or hour < b)


class Alerts:
    def __init__(self, store, mailer=None):
        self.store, self.mailer = store, mailer

    def raise_alert(self, kind: str, dedupe: str, severity: str, title: str, detail: str = "") -> int:
        """Same thing again within the window: count it on the open alert. Enough repeats raises its severity."""
        now = time.time()
        title, detail = re.sub(r"[\x00-\x1f\x7f]", " ", str(title))[:200], re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", str(detail))[:1000]

        def write(c):
            r = c.execute("SELECT id, count, severity FROM alerts WHERE dedupe = ? AND last_ts > ? ORDER BY id DESC LIMIT 1", (dedupe, now - DEDUPE_SECONDS)).fetchone()
            if r:
                count = r["count"] + 1
                up = count == ESCALATE_COUNT and RANK.get(r["severity"], 0) < RANK["CRITICAL"]
                # A repeat doesn't send again, unless it just got more serious. Whether the first copy went out is left alone.
                c.execute("UPDATE alerts SET count=?, last_ts=?, severity=?, delivered=CASE WHEN ? THEN 0 ELSE delivered END WHERE id=?", (count, now, "CRITICAL" if up else r["severity"], int(up), r["id"]))
                return r["id"]
            return c.execute("INSERT INTO alerts(kind, dedupe, severity, title, detail, first_ts, last_ts) VALUES (?,?,?,?,?,?,?)", (kind, dedupe, severity, title, detail, now, now)).lastrowid
        return self.store.run(write)

    def channels(self) -> list[dict]:
        return [dict(r) for r in self.store.read(lambda c: c.execute("SELECT * FROM alert_channels ORDER BY id").fetchall())]

    def add_channel(self, data: dict, actor: str) -> dict:
        kind = str(data.get("kind") or "")
        cfg = check_channel(kind, data.get("config"))
        sev = data.get("min_severity", "WARNING")
        if sev not in RANK:
            raise AlertError("Unknown severity")
        qf, qt = data.get("quiet_from"), data.get("quiet_to")
        for h in (qf, qt):
            if h is not None and not (isinstance(h, int) and 0 <= h <= 23):
                raise AlertError("Quiet hours are whole hours from 0 to 23")
        name = re.sub(r"[\x00-\x1f]", " ", str(data.get("name") or kind))[:60]

        def add(c):
            new = c.execute("INSERT INTO alert_channels(kind, name, config, min_severity, quiet_from, quiet_to) VALUES (?,?,?,?,?,?)", (kind, name, json.dumps(cfg), sev, qf, qt)).lastrowid
            self.store.audit_in(c, actor, "alert.channel_added", name, {"kind": kind, "min_severity": sev})
            return new
        new_id = self.store.run(add)
        return public_channel(next(x for x in self.channels() if x["id"] == new_id))

    def remove_channel(self, cid: int, actor: str) -> dict:
        def drop(c):
            c.execute("DELETE FROM alert_channels WHERE id = ?", (int(cid),))
            self.store.audit_in(c, actor, "alert.channel_removed", str(cid), {})
        self.store.run(drop)
        return {"ok": True}

    def test_channel(self, cid: int) -> dict:
        ch = next((x for x in self.channels() if x["id"] == int(cid)), None)
        if not ch:
            raise AlertError("No such channel")
        try:
            deliver(ch["kind"], json.loads(ch["config"]), {"kind": "test", "severity": "NOTICE", "title": "Test from WAF Ella", "detail": "This channel works.", "count": 1, "last_ts": time.time()}, self.mailer)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            self.store.run(lambda c: c.execute("UPDATE alert_channels SET last_error=? WHERE id=?", (_safe_error(exc), int(cid))))
            return {"ok": False, "error": _safe_error(exc)}
        self.store.run(lambda c: c.execute("UPDATE alert_channels SET last_error='', last_sent=? WHERE id=?", (time.time(), int(cid))))
        return {"ok": True}

    def list(self, limit: int = 200) -> list[dict]:
        return [dict(r) for r in self.store.read(lambda c: c.execute("SELECT * FROM alerts ORDER BY last_ts DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall())]

    def ack(self, aid: int, actor: str) -> dict:
        def write(c):
            c.execute("UPDATE alerts SET acked=1 WHERE id=?", (int(aid),))
            self.store.audit_in(c, actor, "alert.acked", str(aid), {})
        self.store.run(write)
        return {"ok": True}

    def tick(self, hour: int | None = None) -> int:
        """Send what hasn't gone out. Delivered means at least one channel took it, or there's no channel that wants it."""
        now = time.time()
        hour = time.localtime(now).tm_hour if hour is None else hour
        pending = [dict(r) for r in self.store.read(lambda c: c.execute("SELECT * FROM alerts WHERE delivered = 0 AND first_ts > ?", (now - MAX_RETRY_AGE,)).fetchall())]
        sent = 0
        channels = [c for c in self.channels() if c["enabled"]]
        for a in pending:
            wanted = [c for c in channels if RANK.get(a["severity"], 0) >= RANK.get(c["min_severity"], 2)]
            held = False
            ok = False
            for ch in wanted:
                if _quiet(ch, a["severity"], hour):
                    held = True
                    continue
                try:
                    deliver(ch["kind"], json.loads(ch["config"]), a, self.mailer)
                    ok = True
                    sent += 1
                    self.store.run(lambda c, ch=ch: c.execute("UPDATE alert_channels SET last_error='', last_sent=? WHERE id=?", (now, ch["id"])))
                except (OSError, ValueError, urllib.error.URLError) as exc:
                    self.store.run(lambda c, ch=ch, exc=exc: c.execute("UPDATE alert_channels SET last_error=? WHERE id=?", (_safe_error(exc), ch["id"])))
            if ok or (channels and not wanted) or (not channels and now - a["first_ts"] > 3600):
                if not held:
                    self.store.run(lambda c, a=a: c.execute("UPDATE alerts SET delivered=1 WHERE id=?", (a["id"],)))
        return sent


def _safe_error(exc: Exception) -> str:
    """A web address or bot token can be in an error's text, and it's a secret."""
    return re.sub(r"https?://\S+|bot\d+:[\w-]+", "[address]", str(exc))[:200]
