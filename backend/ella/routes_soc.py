"""/api/ella, stages 3 to 8. Every button in the SOC pages is one of these calls, so an API token can do the same work.

A website manager's scope is passed down into each query or rule check here, never filtered afterwards.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import time
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel

from .. import auth, authz
from . import housekeeping, proxies as prx, query as Q, rulebook, service, supply
from .blocks import BlockError, SafetyLocked

router = APIRouter(prefix="/api/ella", dependencies=[Depends(auth.require_auth)])
public = APIRouter(prefix="/api/ella")  # signed per server instead of a login


class Body(BaseModel):
    model_config = {"extra": "allow"}


def _d(body: BaseModel) -> dict:
    return body.model_dump()


def _p() -> dict:
    return service.parts()


def _scope() -> list[str] | None:
    sc = authz.scope()
    return sc["domains"] if sc is not None else None


def _guard(fn):
    """The errors these modules raise for bad input become 400s with their own message."""
    try:
        return fn()
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except SafetyLocked as exc:
        raise HTTPException(status_code=409, detail={"message": str(exc), "safety_lock": exc.reasons, "forceable": exc.forceable}) from exc
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("")
def index():
    return {"service": "WAF Ella", "docs": "/docs", "search_fields": Q.FIELDS}


# ------------------------------------------------------------------ overview
@router.get("/overview")
def overview():
    p = _p()
    store = p["store"]
    now = time.time()
    blocks = store.read(lambda c: c.execute("SELECT source, COUNT(*) n FROM blocks WHERE desired_state='active' GROUP BY source").fetchall())
    srcs = store.read(lambda c: c.execute("SELECT path, status, last_read_ts, last_event_ts FROM sources").fetchall())
    breaches = store.search_events(limit=10, query=Q.compile_query("tags:possible-breach"))["events"]
    transport = p["adapter"].ping() if hasattr(p["adapter"], "ping") else {"ok": False, "error": "running inside the panel"}
    servers = [{"name": s["name"], "engine": s["engine"], "active": s["active"], "mode": _server_mode(s)} for s in rulebook._waf_servers()]
    open_alerts = store.read(lambda c: c.execute("SELECT COUNT(*) n FROM alerts WHERE acked=0").fetchone()["n"])
    return {"digest": housekeeping.digest(store, 1), "blocks": {r["source"]: r["n"] for r in blocks}, "breaches": breaches, "waf": servers, "under_attack": store.setting("under_attack"), "kill_switch": store.setting("kill_switch"),
            "sources": {"total": len(srcs), "stale": len([s for s in srcs if s["status"] not in ("not_found",) and (not s["last_read_ts"] or now - s["last_read_ts"] > 60)]), "error": len([s for s in srcs if s["status"] in ("error", "unavailable")])},
            "agent": {"ok": bool(transport.get("ok")), "transport": getattr(p["adapter"], "last_transport", "in-process"), "error": transport.get("error", ""), "fail_mode": store.setting("fail_mode") or "open"},
            "fleet": {"member": p["member"].status(), "agents": p["control"].agents()}, "slo": housekeeping.slo(store), "open_alerts": open_alerts, "drift": len(store.setting("drift") or [])}


def _server_mode(s: dict) -> str:
    try:
        if s["name"] == "nginx":
            from .. import nginxwaf
            return nginxwaf.status()["mode"]
        from .. import waf
        return waf.load()["mode"]
    except Exception:  # noqa: BLE001  one page's field isn't worth failing the whole overview
        return "unknown"


# ------------------------------------------------------------------ search
@router.get("/search/fields")
def search_fields():
    return {"fields": Q.FIELDS}


@router.get("/search")
def search(q: str = "", limit: int = 100, cursor_ts: float | None = None, cursor_id: int | None = None):
    cursor = (cursor_ts, cursor_id) if cursor_ts is not None and cursor_id is not None else None
    return _guard(lambda: _p()["store"].search_events(limit, cursor, _scope(), query=Q.compile_query(q)))


CSV_FIELDS = ("ts_event", "server", "domain", "source", "client_ip", "client_ip_source", "peer_ip", "method", "url", "status", "user_agent", "rule_id", "severity", "anomaly_score", "action", "tags")


def _csv_safe(v):
    """A spreadsheet runs a cell starting with these as a formula, and these values came from strangers."""
    text = "" if v is None else str(v)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@router.get("/export")
def export(q: str = "", format: str = "json", limit: int = 5000):
    rows = _guard(lambda: _p()["store"].search_events(min(limit, 1000), None, _scope(), query=Q.compile_query(q)))["events"]
    while len(rows) >= 1000 and len(rows) < min(limit, 50000):
        more = _guard(lambda: _p()["store"].search_events(1000, (rows[-1]["ts_event"], rows[-1]["id"]), _scope(), query=Q.compile_query(q)))["events"]
        if not more:
            break
        rows += more
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(CSV_FIELDS)
        for e in rows:
            w.writerow([_csv_safe(e.get(k)) for k in CSV_FIELDS])
        return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="ella-events.csv"'})
    return Response(json.dumps(rows), media_type="application/json", headers={"Content-Disposition": 'attachment; filename="ella-events.json"'})


@router.get("/queries")
def queries(user: str = auth.CurrentUser):
    return {"queries": [dict(r) for r in _p()["store"].read(lambda c: c.execute("SELECT id, name, query FROM saved_queries WHERE owner = ? ORDER BY name", (user,)).fetchall())]}


@router.post("/queries")
def query_save(body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    name, text = re.sub(r"[\x00-\x1f]", " ", str(d.get("name") or ""))[:60], str(d.get("query") or "")
    _guard(lambda: Q.compile_query(text))
    if not name:
        raise HTTPException(status_code=400, detail="Give the search a name")
    _p()["store"].run(lambda c: c.execute("INSERT INTO saved_queries(owner, name, query) VALUES (?,?,?)", (user, name, text)))
    return {"ok": True}


@router.delete("/queries/{qid}")
def query_delete(qid: int, user: str = auth.CurrentUser):
    _p()["store"].run(lambda c: c.execute("DELETE FROM saved_queries WHERE id = ? AND owner = ?", (qid, user)))
    return {"ok": True}


@router.get("/investigate/{ip}")
def investigate(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="That isn't an IP address") from exc
    p = _p()
    allowed = _scope()
    events = p["store"].search_events(200, None, allowed, client_ip=ip)["events"]
    rules: dict[str, int] = {}
    domains: dict[str, int] = {}
    for e in events:
        if e.get("rule_id"):
            rules[e["rule_id"]] = rules.get(e["rule_id"], 0) + 1
        if e.get("domain"):
            domains[e["domain"]] = domains.get(e["domain"], 0) + 1
    out = {"ip": ip, "events": events, "rules": sorted(rules.items(), key=lambda kv: -kv[1]), "domains": sorted(domains.items(), key=lambda kv: -kv[1])}
    if allowed is None:  # bans are the whole server's, and enrichment shows what other sites saw
        addr = ipaddress.ip_address(ip)
        allb = p["engine"].list_blocks(active_only=False)
        mine = [b for b in allb if _covers(b["target"], addr)]
        ua = next((e["user_agent"] for e in events if e.get("user_agent")), None)
        out.update(blocks=mine, active_blocks=[b for b in mine if b["desired_state"] == "active"], lists=p["intel"].lookup(ip), country=p["intel"].country(ip), geo=p["intel"].geo_status(), bot=p["intel"].bot_check(ip, ua),
                   audit=p["store"].audit_entries(50, ip), safety=_safety(ip))
    return out


def _covers(target: str, addr) -> bool:
    try:
        n = ipaddress.ip_network(target, strict=False)
        return n.version == addr.version and addr in n
    except ValueError:
        return False


def _safety(target: str) -> dict:
    n = ipaddress.ip_network(target, strict=False)
    reasons, forceable = _p()["engine"].safety_reasons(n, None)
    return {"reasons": reasons, "forceable": forceable}


@router.post("/blast")
def blast(body: Body):
    """What a wide ban would hit, shown before it's done."""
    d = _d(body)
    try:
        n = ipaddress.ip_network(str(d.get("target") or "").strip(), strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Not an IP address or range") from exc
    minutes = max(1, min(int(d.get("minutes") or 60), 1440))
    since = time.time() - minutes * 60
    p = _p()
    clients, domains, verified = set(), {}, set()
    for e in p["store"].scan_events(since, "client_ip IS NOT NULL", limit=100000):
        if _covers(str(n), _addr(e["client_ip"])):
            clients.add(e["client_ip"])
            if e["domain"]:
                domains[e["domain"]] = domains.get(e["domain"], 0) + 1
            bot = p["intel"].bot_check(e["client_ip"], e["user_agent"]) if e["user_agent"] else None
            if bot and bot["verified"]:
                verified.add(f"{bot['bot']} at {e['client_ip']}")
    return {"target": str(n), "addresses": n.num_addresses, "minutes": minutes, "active_clients": len(clients), "domains": sorted(domains.items(), key=lambda kv: -kv[1])[:20], "verified_bots": sorted(verified), "safety": _safety(str(n))}


def _addr(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return ipaddress.ip_address("0.0.0.0")  # never inside a range anyone may ban: 0.0.0.0/8 is refused


@router.post("/blocks/bulk")
def bulk_ban(body: Body, request: Request, user: str = auth.CurrentUser):
    d = _d(body)
    targets = d.get("targets") or []
    if not isinstance(targets, list) or not 1 <= len(targets) <= 200:
        raise HTTPException(status_code=400, detail="Give between 1 and 200 addresses")
    out = []
    for t in targets:
        try:
            r = _p()["engine"].ban(str(t), d.get("ttl"), str(d.get("reason") or ""), user, request.client.host if request.client else None, bool(d.get("force")))
            out.append({"target": t, "state": r["state"]})
        except BlockError as exc:
            out.append({"target": t, "error": str(exc)[:300]})
    return {"results": out}


# ------------------------------------------------------------------ rules
@router.get("/rules")
def rules():
    b = _p()["book"]
    return {"rules": b.rules(), "fields": sorted(rulebook.FIELDS) + sorted(rulebook.PREFIXED), "operators": sorted(rulebook.OPERATORS) + list(rulebook.PRESENCE), "cms": b.cms_status(), "honeypot": _p()["store"].setting("honeypot"), "matrix": prx.MATRIX, "differences": prx.ENGINE_DIFFERENCES,
            "switches": {k: _p()["store"].setting(k) for k in ("kill_switch", "under_attack", "response_inspection", "body_limit_action")}, "servers": [{k: s[k] for k in ("name", "active", "engine")} for s in rulebook._waf_servers()]}


@router.post("/rules")
def rule_add(body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["book"].create(_d(body), user))


@router.put("/rules/{rid}")
def rule_edit(rid: int, body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["book"].update(rid, _d(body), user))


@router.post("/rules/{rid}/mode")
def rule_mode(rid: int, body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["book"].set_mode(rid, _d(body).get("mode"), user))


@router.delete("/rules/{rid}")
def rule_delete(rid: int, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["book"].delete(rid, user))


@router.get("/rules/{rid}/versions")
def rule_versions(rid: int):
    return {"versions": _p()["book"].versions(rid)}


@router.post("/rules/preview")
def rule_preview(body: Body):
    d = _d(body)
    return _guard(lambda: rulebook.preview(_p()["store"], d.get("tree") or {}, d.get("domains") or [], d.get("path") or "", int(d.get("days") or 7), _scope()))


@router.post("/rules/compile")
def rule_compile(body: Body):
    """The ModSecurity text a rule would become."""
    d = _d(body)

    def work():
        tree = rulebook.check_tree(d.get("tree") or {})
        clean = _p()["book"]._clean_rule({**d, "name": d.get("name") or "preview"})
        return {"text": "\n".join(rulebook.render_tree_rule(rulebook.ID_RULES, clean["name"], tree, clean["domains"], clean["path"], d.get("mode") or "detect", clean["action"], clean["status"], "ella-rule-preview"))}
    return _guard(work)


@router.get("/exceptions")
def exceptions():
    return {"exceptions": _p()["book"].exceptions(_scope())}


@router.post("/exceptions/suggest")
def exception_suggest(body: Body):
    """False Positive Wizard: from one rule hit on one stored event, the narrowest exception."""
    d = _d(body)

    def work():
        e = _p()["store"].get_event(float(d.get("ts")), int(d.get("id")), _scope())
        if not e:
            raise PermissionError("No such event")
        hit = next((x for x in e["evidence"] if x["rule_id"] == str(d.get("rule_id"))), None)
        if not hit:
            raise ValueError("That rule isn't on this event")
        return rulebook.suggest_exception(e, hit)
    return _guard(work)


@router.post("/exceptions")
def exception_add(body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["book"].add_exception(_d(body), user, _scope()))


@router.delete("/exceptions/{eid}")
def exception_remove(eid: int, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["book"].remove_exception(eid, user, _scope()))


@router.post("/honeypot")
def honeypot(body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["book"].set_honeypot(_d(body), user))


@router.post("/cms/{profile}")
def cms(profile: str, body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    return _guard(lambda: _p()["book"].set_cms(profile, d.get("mode"), [str(x).strip().lower() for x in d.get("domains") or []], user))


@router.post("/patches")
def patch_add(body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["book"].add_patch(_d(body), user))


@router.post("/under-attack")
def under_attack(body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["book"].under_attack(_d(body).get("minutes"), user))


@router.post("/switch/{key}")
def switch(key: str, body: Body, user: str = auth.CurrentUser):
    _guard(lambda: _p()["book"].set_switch(key, _d(body).get("value"), user))
    return {"ok": True}


@router.get("/policies")
def policies(domain: str = ""):
    p = _p()
    rows = p["store"].read(lambda c: [dict(r) for r in c.execute("SELECT scope, key, value, locked FROM policies ORDER BY scope, key").fetchall()])
    return {"policies": rows, "effective": p["book"].effective(domain.lower()) if domain else None}


@router.post("/policies")
def policy_set(body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    return _guard(lambda: _p()["book"].set_policy(str(d.get("scope") or ""), str(d.get("key") or ""), d.get("value"), bool(d.get("locked")), user))


@router.delete("/policies")
def policy_remove(scope: str, key: str, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["book"].remove_policy(scope, key, user))


@router.get("/learning")
def learning(days: int = 7):
    return {"suggestions": _p()["correlator"].learning(days, allowed=_scope())}


# ------------------------------------------------------------------ Rule Tester
@router.get("/tester")
def tester_status():
    return _p()["tester"].status()


@router.post("/tester/setup")
def tester_setup(user: str = auth.CurrentUser):
    return _guard(lambda: _p()["tester"].setup(user))


@router.post("/tester/run")
def tester_run(body: Body):
    d = _d(body)
    return _guard(lambda: _p()["tester"].run(str(d.get("method") or "GET"), str(d.get("url") or "/"), d.get("headers") or {}, str(d.get("body") or ""), str(d.get("host") or "localhost")))


# ------------------------------------------------------------------ incidents
@router.get("/incidents")
def incidents():
    return {"incidents": [dict(r) for r in _p()["store"].read(lambda c: c.execute("SELECT i.*, (SELECT COUNT(*) FROM incident_items x WHERE x.incident_id = i.id) AS items FROM incidents i ORDER BY i.updated_at DESC LIMIT 500").fetchall())]}


@router.post("/incidents")
def incident_add(body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    title = re.sub(r"[\x00-\x1f]", " ", str(d.get("title") or "")).strip()[:200]
    if not title:
        raise HTTPException(status_code=400, detail="An incident needs a title")
    sev = d.get("severity", "WARNING")
    if sev not in ("NOTICE", "WARNING", "ERROR", "CRITICAL"):
        raise HTTPException(status_code=400, detail="Unknown severity")
    now = time.time()

    def add(c):
        new = c.execute("INSERT INTO incidents(title, severity, owner, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?)", (title, sev, str(d.get("owner") or user)[:64], user, now, now)).lastrowid
        if d.get("kind") and d.get("ref"):
            c.execute("INSERT INTO incident_items(incident_id, kind, ref, actor, ts) VALUES (?,?,?,?,?)", (new, str(d["kind"])[:20], str(d["ref"])[:200], user, now))
        p = _p()
        p["store"].audit_in(c, user, "incident.created", str(new), {"title": title})
        return new
    return {"id": _p()["store"].run(add)}


@router.get("/incidents/{iid}")
def incident_get(iid: int):
    store = _p()["store"]
    r = store.read(lambda c: c.execute("SELECT * FROM incidents WHERE id = ?", (iid,)).fetchone())
    if not r:
        raise HTTPException(status_code=404, detail="No such incident")
    items = store.read(lambda c: [dict(x) for x in c.execute("SELECT * FROM incident_items WHERE incident_id = ? ORDER BY ts", (iid,)).fetchall()])
    return {**dict(r), "items": items, "audit": store.audit_entries(100, str(iid))}


@router.post("/incidents/{iid}/items")
def incident_item(iid: int, body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    kind = str(d.get("kind") or "note")
    if kind not in ("note", "event", "block", "client"):
        raise HTTPException(status_code=400, detail="Unknown item kind")
    now = time.time()

    def add(c):
        if not c.execute("SELECT 1 FROM incidents WHERE id=?", (iid,)).fetchone():
            raise ValueError("No such incident")
        c.execute("INSERT INTO incident_items(incident_id, kind, ref, note, actor, ts) VALUES (?,?,?,?,?,?)", (iid, kind, str(d.get("ref") or "")[:200], str(d.get("note") or "")[:4000], user, now))
        c.execute("UPDATE incidents SET updated_at=? WHERE id=?", (now, iid))
    _guard(lambda: _p()["store"].run(add))
    return {"ok": True}


@router.post("/incidents/{iid}/status")
def incident_status(iid: int, body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    if d.get("status") not in ("open", "investigating", "resolved", "false_alarm"):
        raise HTTPException(status_code=400, detail="Unknown status")
    store = _p()["store"]

    def save(c):
        c.execute("UPDATE incidents SET status=?, owner=COALESCE(?, owner), updated_at=? WHERE id=?", (d["status"], d.get("owner"), time.time(), iid))
        store.audit_in(c, user, "incident.status", str(iid), {"status": d["status"], "owner": d.get("owner")})
    store.run(save)
    return {"ok": True}


# ------------------------------------------------------------------ alerts, export, correlation
@router.get("/alerts")
def alerts(limit: int = 200):
    from .notify import public_channel
    a = _p()["alerts"]
    return {"alerts": a.list(limit), "channels": [public_channel(c) for c in a.channels()]}


@router.post("/alerts/{aid}/ack")
def alert_ack(aid: int, user: str = auth.CurrentUser):
    return _p()["alerts"].ack(aid, user)


@router.post("/channels")
def channel_add(body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["alerts"].add_channel(_d(body), user))


@router.post("/channels/{cid}/test")
def channel_test(cid: int):
    return _guard(lambda: _p()["alerts"].test_channel(cid))


@router.delete("/channels/{cid}")
def channel_remove(cid: int, user: str = auth.CurrentUser):
    return _p()["alerts"].remove_channel(cid, user)


@router.get("/exports")
def exports():
    return {"exports": _p()["exporter"].public()}


@router.post("/exports")
def exports_set(body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: {"exports": _p()["exporter"].set_targets(_d(body).get("exports") or [], user)})


@router.get("/correlator")
def correlator():
    c = _p()["correlator"]
    return {"settings": c.settings(), "now": c.stuffing()}


@router.post("/correlator")
def correlator_set(body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["correlator"].set_settings(_d(body), user))


# ------------------------------------------------------------------ retention, config as code, reports
@router.get("/retention")
def retention():
    r = _p()["retention"]
    return {"settings": r.settings(), "usage": r.usage()}


@router.post("/retention")
def retention_set(body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["retention"].set_settings(_d(body), user))


@router.post("/retention/forget")
def retention_forget(body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    return _guard(lambda: _p()["retention"].forget(str(d.get("field")), str(d.get("value") or ""), user))


@router.get("/config")
def config_export():
    p = _p()
    return Response(housekeeping.to_yaml(housekeeping.export_config(p["book"], p["store"])), media_type="application/yaml", headers={"Content-Disposition": 'attachment; filename="waf-ella.yaml"'})


@router.post("/config/diff")
def config_diff(body: Body):
    p = _p()
    return _guard(lambda: housekeeping.diff_config(housekeeping.export_config(p["book"], p["store"]), housekeeping.parse_yaml(str(_d(body).get("text") or ""))))


@router.post("/config/import")
def config_import(body: Body, user: str = auth.CurrentUser):
    p = _p()
    return _guard(lambda: housekeeping.import_config(p["book"], p["store"], housekeeping.parse_yaml(str(_d(body).get("text") or "")), user))


@router.get("/digest")
def digest(days: int = 7):
    d = housekeeping.digest(_p()["store"], max(1, min(days, 90)), _scope())
    return {**d, "text": housekeeping.digest_text(d)}


@router.get("/metrics")
def metrics():
    return Response(housekeeping.prometheus(_p()["store"]), media_type="text/plain; version=0.0.4")


@router.get("/slo")
def slo():
    return housekeeping.slo(_p()["store"])


@router.get("/sbom")
def sbom():
    return supply.sbom()


@router.get("/supply")
def supply_state():
    return supply.check_crs(_p()["store"])


# ------------------------------------------------------------------ proxies and CDN
@router.get("/proxies")
def proxies():
    return _p()["proxies"].state()


@router.post("/proxies")
def proxies_set(body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    return _guard(lambda: _p()["proxies"].set_manual(d.get("ranges") or [], str(d.get("header") or "X-Forwarded-For"), user))


@router.post("/proxies/cloudflare")
def proxies_cf(body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    return _guard(lambda: _p()["proxies"].set_cloudflare(bool(d.get("enabled")), user, d.get("token"), d.get("zone")))


@router.post("/proxies/cdn-ban")
def proxies_cdn_ban(body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    return _guard(lambda: _p()["proxies"].cdn_ban(str(d.get("target") or ""), str(d.get("reason") or ""), user))


@router.post("/proxies/cdn-unban/{block_id}")
def proxies_cdn_unban(block_id: str, user: str = auth.CurrentUser):
    b = _p()["engine"].get_block(block_id)
    if not b or b["source"] != "cloudflare":
        raise HTTPException(status_code=404, detail="No such Cloudflare ban")
    return _guard(lambda: _p()["proxies"].cdn_unban(b, user))


# ------------------------------------------------------------------ reputation
@router.get("/intel")
def intel():
    i = _p()["intel"]
    return {"lists": i.lists(), "geo": i.geo_status()}


@router.post("/intel/{name}")
def intel_set(name: str, body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    return _guard(lambda: _p()["intel"].configure(name, bool(d.get("enabled")), bool(d.get("auto_ban")), user))


@router.post("/intel-own")
def intel_own(body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    return _guard(lambda: _p()["intel"].add_own(str(d.get("name") or ""), str(d.get("text") or ""), user))


# ------------------------------------------------------------------ agent and fleet
@router.get("/agent")
def agent():
    a = _p()["adapter"]
    ping = a.ping() if hasattr(a, "ping") else {"ok": False, "error": "This install has no socket folder yet"}
    return {"ping": ping, "transport": getattr(a, "last_transport", "in-process"), "fail_mode": _p()["store"].setting("fail_mode") or "open"}


@router.post("/fail-mode")
def fail_mode(body: Body, user: str = auth.CurrentUser):
    m = _d(body).get("mode")
    if m not in ("open", "closed"):
        raise HTTPException(status_code=400, detail="Open or closed")
    s = _p()["store"]
    s.set_setting("fail_mode", m)
    s.audit(user, "agent.fail_mode", "", {"mode": m})
    return {"mode": m}


@router.get("/fleet")
def fleet_state():
    p = _p()
    return {"agents": p["control"].agents(), "member": p["member"].status(), "bans": p["store"].setting("fleet_bans") or [], "version": p["store"].setting("fleet_version") or 0}


@router.post("/fleet/enroll")
def fleet_enroll(body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["control"].enroll(_d(body).get("name"), user))


@router.post("/fleet/agents/{aid}/rotate")
def fleet_rotate(aid: str, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["control"].rotate(aid, user))


@router.delete("/fleet/agents/{aid}")
def fleet_revoke(aid: str, user: str = auth.CurrentUser):
    return _p()["control"].revoke(aid, user)


@router.post("/fleet/ban-everywhere")
def fleet_ban(body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    return _guard(lambda: _p()["control"].ban_everywhere(str(d.get("target") or ""), d.get("ttl"), str(d.get("reason") or ""), user))


@router.post("/fleet/lift-everywhere")
def fleet_lift(body: Body, user: str = auth.CurrentUser):
    return _guard(lambda: _p()["control"].lift_everywhere(str(_d(body).get("target") or ""), user))


@router.post("/fleet/join")
def fleet_join(body: Body, user: str = auth.CurrentUser):
    d = _d(body)
    return _guard(lambda: _p()["member"].join(str(d.get("url") or ""), str(d.get("agent_id") or ""), str(d.get("secret") or ""), user, d.get("pin")))


@router.post("/fleet/leave")
def fleet_leave(user: str = auth.CurrentUser):
    return _p()["member"].leave(user)


@public.post("/fleet/checkin")
async def fleet_checkin(request: Request, x_ella_agent: str = Header(default=""), x_ella_time: str = Header(default=""), x_ella_nonce: str = Header(default=""), x_ella_signature: str = Header(default="")) -> Any:
    """No login: each managed server signs with its own secret."""
    body = await request.body()
    if len(body) > 20_000_000:
        raise HTTPException(status_code=413, detail="Too big")
    p = _p()
    try:
        agent_row = p["control"].authenticate("POST", "/api/ella/fleet/checkin", x_ella_agent, x_ella_time, x_ella_nonce, x_ella_signature, body)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    try:
        report = json.loads(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Bad body") from exc
    return p["control"].checkin(agent_row, report if isinstance(report, dict) else {})

