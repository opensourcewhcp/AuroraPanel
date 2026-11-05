"""Stage 6: how long things are kept, SIEM export, config as code, digests, Prometheus metrics.

IP addresses are personal data: after a set time they're cut to /24 or /48, and the counts stay useful.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shutil
import sqlite3
import time
import urllib.error
from pathlib import Path

from . import notify, rulebook

RETENTION_DEFAULT = {"keep_months": 12, "pseudonymize_days": 90, "max_mb": 2048}
SCHEMA_VERSION = 1


# ----------------------------------------------------------------------------- retention
def truncate_ip(ip: str | None) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return ip
    return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 48}", strict=False).network_address)


class Retention:
    def __init__(self, store):
        self.store = store

    def settings(self) -> dict:
        return {**RETENTION_DEFAULT, **(self.store.setting("retention") or {})}

    def set_settings(self, data: dict, actor: str) -> dict:
        clean = {}
        for k, (lo, hi) in {"keep_months": (1, 120), "pseudonymize_days": (1, 3650), "max_mb": (50, 10 ** 7)}.items():
            v = data.get(k, self.settings()[k])
            if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
                raise ValueError(f"{k} must be between {lo} and {hi}")
            clean[k] = v
        self.store.set_setting("retention", clean)
        self.store.audit(actor, "retention.settings", "", clean)
        return clean

    def usage(self) -> dict:
        files = [{"file": p.name, "mb": round(p.stat().st_size / 1e6, 2)} for p in self.store.months()]
        return {"files": files, "total_mb": round(sum(f["mb"] for f in files), 2), "free_mb": round(shutil.disk_usage(self.store.dir).free / 1e6)}

    def tick(self, now: float | None = None) -> dict:
        now = now or time.time()
        s = self.settings()
        removed = []
        months = self.store.months()
        keep_from = time.strftime("%Y%m", time.gmtime(now - s["keep_months"] * 31 * 86400))
        for p in months:
            if p.stem[7:] < keep_from:
                removed.append(self._drop(p))
        # Over quota: the oldest month goes, never the current one.
        months = self.store.months()
        while len(months) > 1 and sum(p.stat().st_size for p in months) / 1e6 > s["max_mb"]:
            removed.append(self._drop(months[-1]))
            months = self.store.months()
        changed = self.pseudonymize(now - s["pseudonymize_days"] * 86400)
        if removed or changed:
            self.store.audit("system", "retention.ran", "", {"removed": removed, "pseudonymized": changed})
        return {"removed": removed, "pseudonymized": changed}

    def _drop(self, path: Path) -> str:
        def work(_c):
            month = path.stem[7:]
            conn = self.store._months.pop(month, None)
            if conn is not None:
                conn.close()
            for suffix in ("", "-wal", "-shm"):
                Path(str(path) + suffix).unlink(missing_ok=True)
        self.store.run(work)
        return path.name

    def pseudonymize(self, before: float, batch: int = 5000) -> int:
        cut = time.strftime("%Y%m", time.gmtime(before))

        def work(_c):
            total = 0
            for path in self.store.months():
                month = path.stem[7:]
                if month > cut:
                    continue
                c = self.store._month(month)
                rows = c.execute("SELECT id, client_ip, peer_ip FROM events WHERE ts_event < ? AND (client_ip IS NOT NULL OR peer_ip IS NOT NULL) AND (tags NOT LIKE '%pseudonymized%' OR tags IS NULL) LIMIT ?", (before, batch)).fetchall()
                if not rows:
                    continue
                c.execute("BEGIN IMMEDIATE")
                for r in rows:
                    c.execute("UPDATE events SET client_ip=?, peer_ip=?, tags=json_insert(COALESCE(tags,'[]'), '$[#]', 'pseudonymized') WHERE id=?", (truncate_ip(r["client_ip"]), truncate_ip(r["peer_ip"]), r["id"]))
                c.execute("COMMIT")
                total += len(rows)
            return total
        return self.store.run(work)

    def forget(self, field: str, value: str, actor: str) -> dict:
        """A request to delete someone's data: every event with this address, account or domain."""
        if field not in ("client_ip", "account", "domain") or not value:
            raise ValueError("Delete by client_ip, account or domain")

        def work(_c):
            total = 0
            for path in self.store.months():
                c = self.store._month(path.stem[7:])
                c.execute("BEGIN IMMEDIATE")
                total += c.execute(f"DELETE FROM events WHERE {field} = ?", (value,)).rowcount  # noqa: S608  field is from the fixed list above
                c.execute("COMMIT")
            return total
        n = self.store.run(work)
        self.store.audit(actor, "data.deleted", field, {"events": n, "value_hash": hashlib.sha256(value.encode()).hexdigest()[:16]})
        return {"deleted": n}

    def anchor(self, now: float | None = None) -> dict | None:
        """Once a day, the audit chain's newest hash goes to a separate file: rewriting history would then also need that file."""
        now = now or time.time()
        path = self.store.dir / "audit-anchors.log"
        day = time.strftime("%Y-%m-%d", time.gmtime(now))
        if path.exists() and path.read_text(encoding="utf-8").rstrip().rsplit("\n", 1)[-1].startswith(day):
            return None
        r = self.store.read(lambda c: c.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone())
        if not r:
            return None
        with path.open("a", encoding="utf-8") as f:
            f.write(f"{day} {r['seq']} {r['hash']}\n")
        return {"day": day, "seq": r["seq"], "hash": r["hash"]}


# ----------------------------------------------------------------------------- SIEM export
CEF_SEV = {"CRITICAL": 10, "ERROR": 8, "WARNING": 6, "NOTICE": 3}
_CEF_ESC = re.compile(r"([\\|=])")


def _cef(v) -> str:
    return _CEF_ESC.sub(r"\\\1", str(v if v is not None else "")).replace("\n", " ").replace("\r", " ")


def to_cef(e: dict) -> str:
    ext = {"src": e.get("client_ip"), "dhost": e.get("domain"), "requestMethod": e.get("method"), "request": e.get("url"), "cs1": e.get("rule_id"), "cs1Label": "rule", "act": e.get("action"), "rt": int(float(e.get("ts_event") or 0) * 1000), "cn1": e.get("status"), "cn1Label": "status"}
    head = "|".join(_cef(x) for x in ("AuroraPanel", "WAF Ella", "1", e.get("rule_id") or e.get("source"), e.get("source"), CEF_SEV.get(e.get("severity") or "", 3)))
    return f"CEF:0|{head}|" + " ".join(f"{k}={_cef(v)}" for k, v in ext.items() if v not in (None, ""))


EXPORT_FIELDS = ("ts_event", "server", "domain", "source", "client_ip", "peer_ip", "method", "url", "status", "user_agent", "rule_id", "severity", "anomaly_score", "action", "tags")


class Exporter:
    """Each destination has its own position, so when one is down it picks up from there: nothing is held in memory or lost."""

    def __init__(self, store):
        self.store = store

    def targets(self) -> list[dict]:
        return self.store.setting("exports") or []

    def public(self) -> list[dict]:
        return [{k: ("set" if k == "secret" and v else v) for k, v in t.items()} for t in self.targets()]

    def set_targets(self, items: list[dict], actor: str) -> list[dict]:
        old = {t["name"]: t for t in self.targets()}
        out = []
        for t in items or []:
            name = str(t.get("name") or "")
            if not re.fullmatch(r"[A-Za-z0-9 _-]{1,40}", name):
                raise ValueError("Bad destination name")
            kind = t.get("kind")
            if kind == "syslog":
                notify.check_channel("syslog", t)
            elif kind == "http":
                notify.check_channel("webhook", t)
            else:
                raise ValueError("A destination is syslog (CEF) or http (JSON)")
            if t.get("min_severity", "NOTICE") not in notify.RANK:
                raise ValueError("Unknown severity")
            secret = t.get("secret")
            out.append({"name": name, "kind": kind, "host": t.get("host"), "port": t.get("port"), "proto": t.get("proto"), "url": t.get("url"), "min_severity": t.get("min_severity", "NOTICE"),
                        "domains": [str(d) for d in t.get("domains") or []], "secret": old.get(name, {}).get("secret") if secret in (None, "set") else secret, "position": old.get(name, {}).get("position") or time.time(), "last_error": ""})
        self.store.set_setting("exports", out)
        self.store.audit(actor, "export.changed", "", {"names": [t["name"] for t in out]})
        return self.public()

    def tick(self, batch: int = 500) -> int:
        targets = self.targets()
        total = 0
        for t in targets:
            total += self._one(t, batch)
        if targets:
            self.store.set_setting("exports", targets)
        return total

    def _one(self, t: dict, batch: int) -> int:
        since = float(t.get("position") or time.time())
        rows = [e for e in reversed(list(self.store.scan_events(since + 0.000001, "historical = 0 AND severity IS NOT NULL", limit=batch * 4)))]
        rows = rows[:batch]
        pick = [e for e in rows if notify.RANK.get(e["severity"], 0) >= notify.RANK[t.get("min_severity", "NOTICE")] and (not t.get("domains") or e["domain"] in t["domains"])]
        try:
            if pick:
                self._send(t, pick)
            t["last_error"] = ""
        except (OSError, ValueError, urllib.error.URLError) as exc:
            t["last_error"] = notify._safe_error(exc)
            return 0  # the position stays where it was: all of this goes again next time
        if rows:
            t["position"] = rows[-1]["ts_event"]
        return len(pick)

    def _send(self, t: dict, events: list[dict]) -> None:
        if t["kind"] == "syslog":
            for e in events:
                notify.send_syslog(t["host"], int(t.get("port") or 514), t.get("proto") or "udp", f"<{14 if e['severity'] == 'NOTICE' else 12}>aurora-ella: {to_cef(e)}")
        else:
            body = json.dumps([{k: e.get(k) for k in EXPORT_FIELDS} for e in events]).encode()
            notify._post(t["url"], body, {"X-Aurora-Signature": "sha256=" + notify.sign(t["secret"], body)} if t.get("secret") else {})


# ----------------------------------------------------------------------------- config as code
def export_config(book, store, proxies_state: dict | None = None) -> dict:
    def rule(r):
        return {k: r[k] for k in ("name", "kind", "domains", "path", "tree", "raw", "action", "status", "mode", "priority", "reason", "locked", "expires_at", "cve_id", "software", "versions", "source_url")}
    settings = {k: store.setting(k) for k in ("honeypot", "kill_switch", "response_inspection", "body_limit_action", "management_cidrs", "trusted_manual", "real_ip_header", "protected_paths", "correlator", "retention")}
    return {"schema": SCHEMA_VERSION, "exported": int(time.time()), "rules": [rule(r) for r in book.rules()],
            "exceptions": [{k: e[k] for k in ("rule_id", "var", "domain", "path", "reason", "expires_at")} for e in book.exceptions()],
            "policies": [{"scope": p["scope"], "key": p["key"], "value": json.loads(p["value"]), "locked": bool(p["locked"])} for p in store.read(lambda c: [dict(x) for x in c.execute("SELECT * FROM policies ORDER BY scope, key").fetchall()])],
            "settings": settings}


def to_yaml(doc: dict) -> str:
    import yaml
    return yaml.safe_dump(doc, sort_keys=True, allow_unicode=True, default_flow_style=False)


def parse_yaml(text: str) -> dict:
    import yaml
    if len(text or "") > 5_000_000:
        raise ValueError("That file is too big")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Not valid YAML: {str(exc)[:200]}") from exc
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA_VERSION:
        raise ValueError(f"This isn't a WAF Ella export of schema version {SCHEMA_VERSION}")
    return doc


def _key_rule(r: dict) -> str:
    return f"{r.get('kind', 'custom')}:{r.get('name')}"


def diff_config(current: dict, incoming: dict) -> dict:
    """What an import would change, without changing it."""
    out = {}
    for section, key in (("rules", _key_rule), ("exceptions", lambda e: f"{e.get('rule_id')}|{e.get('var')}|{e.get('domain')}|{e.get('path')}"), ("policies", lambda p: f"{p.get('scope')}|{p.get('key')}")):
        a = {key(x): x for x in current.get(section) or []}
        b = {key(x): x for x in incoming.get(section) or []}
        out[section] = {"add": sorted(set(b) - set(a)), "remove": sorted(set(a) - set(b)), "change": sorted(k for k in set(a) & set(b) if a[k] != b[k])}
    out["settings"] = {"change": sorted(k for k in incoming.get("settings") or {} if (current.get("settings") or {}).get(k) != incoming["settings"][k])}
    return out


def import_config(book, store, doc: dict, actor: str, publish: bool = True) -> dict:
    """Everything is validated before anything is written. Imported block-mode rules stay in the mode the export had."""
    cur = export_config(book, store)
    changes = diff_config(cur, doc)
    existing = {_key_rule(r): r for r in book.rules()}
    rules, exs, pols = [], [], []
    for r in doc.get("rules") or []:
        kind = r.get("kind", "custom")
        clean = book._clean_rule(r)
        if kind == "vpatch":
            rulebook.check_raw(r.get("raw"))
            tree = None
        elif kind == "cms":
            if r.get("reason") not in rulebook.CMS_PROFILES:
                raise rulebook.RuleError(f"Unknown profile in an import: {r.get('reason')}")
            tree = rulebook.CMS_PROFILES[r["reason"]]["tree"]
        elif kind == "custom":
            tree = rulebook.check_tree(r.get("tree") or {})
        else:
            raise rulebook.RuleError(f"Unknown rule kind: {kind}")
        if r.get("mode", "off") not in rulebook.MODES:
            raise rulebook.RuleError("Bad rule mode in the import")
        rules.append((r, clean, kind, tree))
    for e in doc.get("exceptions") or []:
        exs.append(rulebook.check_exception(e.get("rule_id"), e.get("var"), e.get("domain"), e.get("path")))
    for p in doc.get("policies") or []:
        rulebook.check_policy(p.get("key"), p.get("value"))
        pols.append(p)
    settings = {k: v for k, v in (doc.get("settings") or {}).items() if k in ("honeypot", "kill_switch", "response_inspection", "body_limit_action", "management_cidrs", "protected_paths", "correlator", "retention")}
    now = time.time()

    def write(c):
        wanted = {_key_rule(r) for r, *_ in rules}
        for k, r in existing.items():
            if k not in wanted and not r["locked"]:
                c.execute("DELETE FROM rules WHERE id = ?", (r["id"],))
        for r, clean, kind, tree in rules:
            old = existing.get(_key_rule(r))
            tree_text = json.dumps(tree) if tree else None
            mode = r.get("mode", "off")
            if old:
                c.execute("UPDATE rules SET domains=?, path=?, tree=?, raw=?, action=?, status=?, mode=?, priority=?, reason=?, expires_at=?, version=version+1, detect_since=COALESCE(detect_since, ?), updated_at=? WHERE id=?",
                          (json.dumps(clean["domains"]), clean["path"], tree_text, r.get("raw"), clean["action"], clean["status"], mode, clean["priority"], r.get("reason") or "", clean["expires_at"], now if mode != "off" else None, now, old["id"]))
                rid = old["id"]
            else:
                rid = c.execute("INSERT INTO rules(name, kind, domains, path, tree, raw, action, status, mode, priority, author, reason, expires_at, detect_since, cve_id, software, versions, source_url, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                (clean["name"], kind, json.dumps(clean["domains"]), clean["path"], tree_text, r.get("raw"), clean["action"], clean["status"], mode, clean["priority"], actor, r.get("reason") or "", clean["expires_at"], now if mode != "off" else None,
                                 r.get("cve_id"), r.get("software"), r.get("versions"), r.get("source_url"), now, now)).lastrowid
            book._version(c, rid, actor)
        c.execute("UPDATE exceptions SET enabled = 0 WHERE enabled = 1")
        for e in exs:
            c.execute("INSERT INTO exceptions(rule_id, var, domain, path, author, reason, created_at) VALUES (?,?,?,?,?,?,?)", (e["rule_id"], e["var"], e["domain"], e["path"], actor, "imported", now))
        c.execute("DELETE FROM policies")
        for p in pols:
            c.execute("INSERT INTO policies(scope, key, value, locked) VALUES (?,?,?,?)", (p["scope"], p["key"], json.dumps(p["value"]), int(bool(p.get("locked")))))
        for k, v in settings.items():
            c.execute("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (k, json.dumps(v)))
        store.audit_in(c, actor, "config.imported", "", changes)
    before = cur
    store.run(write)
    if publish:
        try:
            book.publish(actor)
        except rulebook.RuleError:
            # The web server refused the result, so the import is undone too.
            import_config(book, store, before, f"{actor} (undoing a refused import)", publish=False)
            book.publish(actor)
            raise
    return changes


# ----------------------------------------------------------------------------- digests, reports, metrics
def digest(store, days: int = 7, allowed: list[str] | None = None, now: float | None = None) -> dict:
    now = now or time.time()
    since = now - days * 86400
    top_rules: dict[str, int] = {}
    top_ips: dict[str, int] = {}
    top_domains: dict[str, int] = {}
    totals = {"events": 0, "blocked": 0, "detected": 0, "breaches": 0, "login_failed": 0}
    for path in store.months():
        if path.stem[7:] < time.strftime("%Y%m", time.gmtime(since)):
            break
        c = sqlite3.connect(path, timeout=5)
        c.row_factory = sqlite3.Row
        try:
            where, args = "ts_event >= ?", [since]
            if allowed is not None:
                if not allowed:
                    continue
                where += f" AND domain IN ({','.join('?' for _ in allowed)})"
                args += allowed
            r = c.execute(f"SELECT COUNT(*) n, SUM(action='blocked') b, SUM(action='detected') d, SUM(tags LIKE '%possible-breach%') p, SUM(action='login_failed') l FROM events WHERE {where}", args).fetchone()  # noqa: S608  bound values, fixed text
            totals["events"] += r["n"] or 0
            totals["blocked"] += r["b"] or 0
            totals["detected"] += r["d"] or 0
            totals["breaches"] += r["p"] or 0
            totals["login_failed"] += r["l"] or 0
            for col, bucket in (("rule_id", top_rules), ("client_ip", top_ips), ("domain", top_domains)):
                for x in c.execute(f"SELECT {col} k, COUNT(*) n FROM events WHERE {where} AND action IN ('blocked','detected') AND {col} IS NOT NULL GROUP BY {col} ORDER BY n DESC LIMIT 10", args):  # noqa: S608
                    bucket[x["k"]] = bucket.get(x["k"], 0) + x["n"]
        finally:
            c.close()
    top = lambda d: sorted(d.items(), key=lambda kv: -kv[1])[:10]  # noqa: E731
    return {"days": days, **totals, "top_rules": top(top_rules), "top_clients": top(top_ips), "top_domains": top(top_domains)}


def digest_text(d: dict) -> str:
    lines = [f"WAF Ella: the last {d['days']} days", f"{d['events']} events, {d['blocked']} blocked, {d['detected']} detected, {d['breaches']} possible breaches, {d['login_failed']} failed logins."]
    for title, key in (("Rules that fired most", "top_rules"), ("Busiest attackers", "top_clients"), ("Most targeted sites", "top_domains")):
        if d[key]:
            lines += ["", title + ":"] + [f"  {k}: {n}" for k, n in d[key]]
    return "\n".join(lines)


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * p))]


def slo(store, now: float | None = None) -> dict:
    """The system's promises, from what it actually recorded in the last day. None means nothing to measure yet."""
    now = now or time.time()
    since = now - 86400
    lag = [e["ts_received"] - e["ts_event"] for e in store.scan_events(since, "historical = 0 AND source IN ('modsec_audit','modsec3_audit')", limit=5000)]
    ops = store.read(lambda c: c.execute("SELECT applied_at - created_at AS d FROM operations WHERE kind='ban' AND state IN ('applied','expired') AND applied_at IS NOT NULL AND created_at >= ?", (since,)).fetchall())
    ban = [r["d"] for r in ops if r["d"] is not None]
    lost = store.read(lambda c: c.execute("SELECT SUM(lines) l, SUM(unparsed) u FROM sources").fetchone())
    return {"event_to_store_p95": percentile(lag, 0.95), "ban_applied_p95": percentile(ban, 0.95), "unreadable_share": (lost["u"] or 0) / lost["l"] if lost["l"] else None,
            "targets": {"event_to_store_p95": 5, "ban_applied_p95": 3, "unreadable_share": 0.001}}


def _label(v) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def prometheus(store, parts: dict | None = None) -> str:
    """The text format Prometheus reads. Reads only what WAF Ella already keeps."""
    out = []

    def add(name: str, help_text: str, kind: str, samples: list[tuple[dict, float]]):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            lab = "{" + ",".join(f'{k}="{_label(v)}"' for k, v in labels.items()) + "}" if labels else ""
            out.append(f"{name}{lab} {value}")
    sources = [dict(r) for r in store.read(lambda c: c.execute("SELECT path, kind, offset, lines, unparsed, last_event_ts, status FROM sources").fetchall())]
    add("ella_source_lines_total", "Lines read from a log", "counter", [({"source": s["path"]}, s["lines"]) for s in sources])
    add("ella_source_unparsed_total", "Lines that could not be read", "counter", [({"source": s["path"]}, s["unparsed"]) for s in sources])
    add("ella_source_last_event_timestamp_seconds", "Newest event from a log", "gauge", [({"source": s["path"]}, s["last_event_ts"]) for s in sources if s["last_event_ts"]])
    lag = []
    for s in sources:
        if s["path"].startswith("/"):
            try:
                lag.append(({"source": s["path"]}, max(0, Path(s["path"]).stat().st_size - (s["offset"] or 0))))
            except OSError:
                pass
    add("ella_source_lag_bytes", "Bytes between the read position and the end of a log", "gauge", lag)
    blocks = store.read(lambda c: c.execute("SELECT backend, COUNT(*) n FROM blocks WHERE desired_state='active' GROUP BY backend").fetchall())
    add("ella_active_bans", "Active bans by backend", "gauge", [({"backend": r["backend"]}, r["n"]) for r in blocks])
    ops = store.read(lambda c: c.execute("SELECT state, COUNT(*) n FROM operations GROUP BY state").fetchall())
    add("ella_operations", "Ban operations by state", "gauge", [({"state": r["state"]}, r["n"]) for r in ops])
    add("ella_drift", "Differences between records and firewalls", "gauge", [({}, len(store.setting("drift") or []))])
    alerts = store.read(lambda c: c.execute("SELECT COUNT(*) n FROM alerts WHERE acked = 0").fetchone())
    add("ella_alerts_open", "Alerts nobody has acknowledged", "gauge", [({}, alerts["n"])])
    size = sum(p.stat().st_size for p in store.dir.glob("*.db"))
    add("ella_database_bytes", "Size of WAF Ella's databases", "gauge", [({}, size)])
    s = slo(store)
    add("ella_event_to_store_p95_seconds", "95th percentile from log time to stored", "gauge", [({}, s["event_to_store_p95"])] if s["event_to_store_p95"] is not None else [])
    add("ella_ban_applied_p95_seconds", "95th percentile from ban request to confirmed", "gauge", [({}, s["ban_applied_p95"])] if s["ban_applied_p95"] is not None else [])
    return "\n".join(out) + "\n"
