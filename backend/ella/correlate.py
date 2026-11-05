"""Correlator: looks across stored events for what no single event shows, then raises alerts or asks for a ban.

It acts after the fact, so it affects later requests, never the one that triggered it. Events marked historical are never
looked at. Bans are off unless the operator turned them on, and go through the normal ban path with its Safety Lock.
"""
from __future__ import annotations

import ipaddress
import json
import time

WINDOWS = (("short", 600), ("hour", 3600), ("day", 86400))
DEFAULTS = {"ip_many_logins": 10, "login_many_ips": 10, "net_many_ips": 20, "slow_fails_day": 50, "auto_ban": False, "ban_seconds": 3600, "rate_per_minute": 0}
HTTP_SOURCES = ("apache_access", "nginx_access", "caddy_access", "modsec_audit", "modsec3_audit")
PROTECTED_PREFIX = "/.well-known/acme-challenge/"


def _net24(ip: str) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 48}", strict=False))


class Correlator:
    def __init__(self, store, engine, alerts, intel=None):
        self.store, self.engine, self.alerts, self.intel = store, engine, alerts, intel

    def settings(self) -> dict:
        return {**DEFAULTS, **(self.store.setting("correlator") or {})}

    def set_settings(self, data: dict, actor: str) -> dict:
        clean = {}
        for k, default in DEFAULTS.items():
            v = data.get(k, self.settings()[k])
            if isinstance(default, bool):
                clean[k] = bool(v)
            else:
                if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 10 ** 7:
                    raise ValueError(f"{k} must be a whole number")
                clean[k] = v
        self.store.set_setting("correlator", clean)
        self.store.audit(actor, "correlator.settings", "", clean)
        return clean

    def _logins(self, since: float) -> list[dict]:
        return [e for e in self.store.scan_events(since, "action = 'login_failed' AND historical = 0")]

    def stuffing(self, now: float | None = None) -> list[dict]:
        """One address trying many logins, one login tried from many addresses, many addresses from one network, and slow guessing."""
        now = now or time.time()
        s = self.settings()
        found = []
        fails = self._logins(now - 86400)
        recent = [e for e in fails if e["ts_event"] >= now - 600]
        by_ip: dict[str, set] = {}
        by_login: dict[str, set] = {}
        by_net: dict[str, set] = {}
        for e in recent:
            ip, login = e["client_ip"], e["account"]
            if ip:
                by_ip.setdefault(ip, set()).add(login or "?")
                n = _net24(ip)
                if n:
                    by_net.setdefault(n, set()).add(ip)
            if login and ip:
                by_login.setdefault(login, set()).add(ip)
        for ip, names in by_ip.items():
            if len(names) >= s["ip_many_logins"]:
                found.append({"kind": "ip_many_logins", "target": ip, "count": len(names), "ban": ip, "title": f"{ip} tried {len(names)} different logins in 10 minutes"})
        for login, ips in by_login.items():
            if len(ips) >= s["login_many_ips"]:
                found.append({"kind": "login_many_ips", "target": login, "count": len(ips), "title": f"Login {login} was tried from {len(ips)} addresses in 10 minutes"})
        for net, ips in by_net.items():
            if len(ips) >= s["net_many_ips"]:
                found.append({"kind": "net_many_ips", "target": net, "count": len(ips), "title": f"{len(ips)} addresses in {net} failed logins in 10 minutes"})
        slow: dict[str, int] = {}
        for e in fails:
            if e["client_ip"]:
                slow[e["client_ip"]] = slow.get(e["client_ip"], 0) + 1
        for ip, n in slow.items():
            if n >= s["slow_fails_day"]:
                found.append({"kind": "slow_brute", "target": ip, "count": n, "ban": ip, "title": f"{ip} failed {n} logins in 24 hours"})
        return found

    def _check_new(self, since: float) -> dict:
        """Single events worth an alert of their own."""
        out = {"breach": 0, "honeypot": 0, "fake_bot": 0, "ti": 0}
        checked_bots: set = set()
        checked_ti: set = set()
        for e in self.store.scan_events(since, "historical = 0 AND client_ip IS NOT NULL", limit=20000):
            tags = json.loads(e["tags"] or "[]")
            where = f"{e['domain'] or 'unknown'}{e['url'] or ''}"
            if "possible-breach" in tags:
                out["breach"] += 1
                self.alerts.raise_alert("possible_breach", f"breach:{e['client_ip']}:{e['rule_id']}", "CRITICAL", f"Possible breach: {where}",
                                        f"{e['client_ip']} sent a request rule {e['rule_id']} flagged, and it was answered with {e['status']}. This is a suspicion, not proof.")
            if "honeypot" in tags:
                out["honeypot"] += 1
                self.alerts.raise_alert("honeypot", f"honeypot:{e['client_ip']}", "WARNING", f"{e['client_ip']} probed a honeypot path", where)
            if self.intel and e["source"] in HTTP_SOURCES:
                if e["user_agent"] and (e["client_ip"], e["user_agent"]) not in checked_bots:
                    checked_bots.add((e["client_ip"], e["user_agent"]))
                    bot = self.intel.bot_check(e["client_ip"], e["user_agent"])
                    if bot and bot["verified"] is False:
                        out["fake_bot"] += 1
                        self.alerts.raise_alert("fake_bot", f"fakebot:{e['client_ip']}", "WARNING", f"{e['client_ip']} claims to be {bot['bot']} and isn't", "Reverse and forward DNS don't match the search engine's own names.")
                if e["client_ip"] not in checked_ti:
                    checked_ti.add(e["client_ip"])
                    for hit in self.intel.lookup(e["client_ip"]):
                        out["ti"] += 1
                        self.alerts.raise_alert("reputation", f"ti:{e['client_ip']}:{hit['name']}", "NOTICE", f"{e['client_ip']} is on the {hit['name']} list", where)
                        if hit["auto_ban"]:
                            self._ban(e["client_ip"], f"On the {hit['name']} list")
        return out

    def _ban(self, target: str, why: str) -> None:
        from .blocks import BlockError
        s = self.settings()
        try:
            self.engine.ban(target, s["ban_seconds"] or None, why, "correlator", idempotency_key=None)
        except BlockError as exc:  # the Safety Lock said no: an alert, and no ban
            self.alerts.raise_alert("auto_ban_refused", f"refused:{target}", "WARNING", f"An automatic ban on {target} was refused", str(exc))

    def _rates(self, now: float) -> list[dict]:
        """Requests per client in the last minute. The Rate limit here is a ban on the next request, read from logs."""
        limit = self.settings()["rate_per_minute"]
        if not limit:
            return []
        counts: dict[str, int] = {}
        for e in self.store.scan_events(now - 60, "historical = 0 AND client_ip IS NOT NULL AND source IN ('apache_access','nginx_access','caddy_access')", limit=100000):
            if (e["url"] or "").startswith(PROTECTED_PREFIX):
                continue  # a certificate check must never count against anyone
            bot = self.intel.bot_check(e["client_ip"], e["user_agent"]) if self.intel else None
            if bot and bot["verified"]:
                continue  # a confirmed search engine isn't rate limited without a decision to do so
            counts[e["client_ip"]] = counts.get(e["client_ip"], 0) + 1
        return [{"kind": "rate", "target": ip, "count": n, "ban": ip, "title": f"{ip} made {n} requests in a minute"} for ip, n in counts.items() if n >= limit]

    def tick(self, now: float | None = None) -> dict:
        now = now or time.time()
        since = self.store.setting("correlator_ts") or now - 60
        result = self._check_new(since)
        self.store.set_setting("correlator_ts", now)
        found = self.stuffing(now) + self._rates(now)
        auto = self.settings()["auto_ban"]
        for f in found:
            self.alerts.raise_alert(f["kind"], f"{f['kind']}:{f['target']}", "WARNING", f["title"], "Seen in logs, so anything done about it affects the next request.")
            if auto and f.get("ban"):
                self._ban(f["ban"], f["title"])
        return {**result, "found": len(found)}

    def learning(self, days: int = 7, min_hits: int = 3, allowed: list[str] | None = None) -> list[dict]:
        """From a detect period: which rule keeps hitting which parameter on which page, as candidate exceptions, most hits first."""
        import sqlite3
        since = time.time() - max(1, min(days, 90)) * 86400
        counts: dict[tuple, dict] = {}
        for path in self.store.months():
            c = sqlite3.connect(path, timeout=5)
            c.row_factory = sqlite3.Row
            try:
                rows = c.execute("SELECT e.domain, e.url, e.client_ip, x.rule_id, x.matched_var_name, x.matched_data FROM events e JOIN event_evidence x ON x.event_id = e.id WHERE e.ts_event >= ? AND e.action = 'detected' AND e.historical = 0 AND x.rule_id IS NOT NULL AND e.domain IS NOT NULL", (since,)).fetchall()
            finally:
                c.close()
            for r in rows:
                if allowed is not None and r["domain"] not in allowed:
                    continue
                key = (r["rule_id"], r["domain"], r["url"], r["matched_var_name"])
                item = counts.setdefault(key, {"rule_id": r["rule_id"], "domain": r["domain"], "path": r["url"], "var": r["matched_var_name"], "hits": 0, "clients": set(), "example": r["matched_data"]})
                item["hits"] += 1
                item["clients"].add(r["client_ip"])
        out = [{**v, "clients": len(v["clients"])} for v in counts.values() if v["hits"] >= min_hits]
        # One client making every hit looks like an attack. Many clients look like a page that trips the rule.
        out.sort(key=lambda v: (-v["clients"], -v["hits"]))
        return out[:200]
