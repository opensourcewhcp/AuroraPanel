"""/api/ella: every action the interface offers is one of these calls. authz.py applies the roles before they run."""
from __future__ import annotations

import os
import re

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

from .. import auth, authz
from . import collector, leaks, service
from .blocks import BlockError, SafetyLocked

router = APIRouter(prefix="/api/ella", dependencies=[Depends(auth.require_auth)])


class BanBody(BaseModel):
    target: str
    ttl: int | None = None
    reason: str = ""
    force: bool = False
    scope: str = "server"


class UnbanBody(BaseModel):
    reason: str = ""


class DriftBody(BaseModel):
    backend: str
    target: str
    action: str


class JailBan(BaseModel):
    ip: str
    force: bool = False


class CustomBody(BaseModel):
    path: str
    format: str
    pattern: str | None = None
    fields: dict | None = None


class ImportBody(BaseModel):
    path: str
    kind: str


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/events")
def events(limit: int = 100, cursor_ts: float | None = None, cursor_id: int | None = None, client_ip: str = "", domain: str = "", rule_id: str = "", source: str = "", action: str = ""):
    sc = authz.scope()  # a website manager's query only ever covers their own domains
    cursor = (cursor_ts, cursor_id) if cursor_ts is not None and cursor_id is not None else None
    return service.parts()["store"].search_events(limit, cursor, sc["domains"] if sc else None, client_ip=client_ip, domain=domain, rule_id=rule_id, source=source, action=action)


@router.get("/sources")
def sources():
    rows = service.parts()["store"].read(lambda c: c.execute("SELECT path, kind, status, last_error, last_event_ts, last_read_ts, lines, unparsed, samples, offset FROM sources ORDER BY path").fetchall())
    out, seen = [], set()
    for r in rows:
        d = dict(r)
        seen.add(d["path"])
        info = collector.SOURCE_INFO.get(d["path"] if d["path"].startswith("journal:") else d["kind"], ("", ""))
        lag = None
        if d["path"].startswith("/"):
            try:
                lag = max(0, os.stat(d["path"]).st_size - d["offset"])
            except OSError:
                d["status"] = "not_found"
        out.append({**d, "format": info[0], "fields": info[1], "lag_bytes": lag})
    # Logs this server could have but doesn't are shown, so an empty source can't be mistaken for a quiet one.
    for path, kind in collector.SYSTEM_FILES:
        if path not in seen:
            info = collector.SOURCE_INFO[kind]
            out.append({"path": path, "kind": kind, "status": "not_found", "format": info[0], "fields": info[1], "lines": 0, "unparsed": 0, "samples": "[]", "lag_bytes": None, "last_event_ts": None, "last_read_ts": None, "last_error": ""})
    return {"sources": out}


@router.post("/sources/custom")
def add_custom(body: CustomBody, user: str = auth.CurrentUser):
    p = service.parts()
    try:
        spec = collector.check_custom(body.model_dump())
    except (ValueError, re.error) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    cur = [s for s in (p["store"].setting("custom_sources") or []) if s["path"] != spec["path"]]
    p["store"].set_setting("custom_sources", [*cur, spec])
    p["store"].audit(user, "source.custom_added", spec["path"], {"format": spec["format"]})
    return {"ok": True, "source": spec}


@router.delete("/sources/custom")
def del_custom(path: str, user: str = auth.CurrentUser):
    p = service.parts()
    p["store"].set_setting("custom_sources", [s for s in (p["store"].setting("custom_sources") or []) if s["path"] != path])
    p["store"].audit(user, "source.custom_removed", path, {})
    return {"ok": True}


@router.post("/sources/import")
def import_history(body: ImportBody, user: str = auth.CurrentUser):
    """Old logs, as history: marked historical, and nothing ever bans because of them."""
    if not re.fullmatch(r"/var/log/[\w./-]{1,200}", body.path) or ".." in body.path:
        raise HTTPException(status_code=400, detail="Only files under /var/log can be imported")
    try:
        r = service.parts()["collector"].import_file(body.path, body.kind)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    service.parts()["store"].audit(user, "source.imported", body.path, r)
    return r


@router.get("/leaks")
def leak_report():
    return leaks.report(service.parts()["store"])


@router.get("/blocks")
def blocks(active: bool = True):
    return {"blocks": service.parts()["engine"].list_blocks(active)}


@router.post("/blocks")
def ban(body: BanBody, request: Request, user: str = auth.CurrentUser, idempotency_key: str | None = Header(default=None)):
    try:
        return service.parts()["engine"].ban(body.target, body.ttl, body.reason, user, _ip(request), body.force, idempotency_key, body.scope)
    except SafetyLocked as exc:
        raise HTTPException(status_code=409, detail={"message": str(exc), "safety_lock": exc.reasons, "forceable": exc.forceable}) from exc
    except BlockError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/blocks/{block_id}/unban")
def unban(block_id: str, body: UnbanBody, user: str = auth.CurrentUser):
    try:
        return service.parts()["registry"].unban(block_id, user, body.reason)
    except BlockError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/drift")
def drift():
    store = service.parts()["store"]
    return {"drift": store.setting("drift") or [], "checked": store.setting("drift_checked")}


@router.post("/drift/check")
def drift_check():
    return service.parts()["registry"].sync()


@router.post("/drift/resolve")
def drift_resolve(body: DriftBody, request: Request, user: str = auth.CurrentUser):
    try:
        return service.parts()["registry"].resolve(body.backend, body.target, body.action, user, _ip(request))
    except (BlockError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/fail2ban")
def f2b():
    p = service.parts()
    history = p["store"].search_events(limit=100, source="fail2ban_log")["events"]
    return {**p["registry"].fail2ban_overview(), "history": history}


@router.post("/fail2ban/init")
def f2b_init(user: str = auth.CurrentUser):
    try:
        return service.parts()["registry"].fail2ban_init(user)
    except (BlockError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/fail2ban/{jail}/ban")
def f2b_ban(jail: str, body: JailBan, request: Request, user: str = auth.CurrentUser):
    try:
        return service.parts()["registry"].fail2ban_ban(jail, body.ip, user, _ip(request), body.force)
    except SafetyLocked as exc:
        raise HTTPException(status_code=409, detail={"message": str(exc), "safety_lock": exc.reasons, "forceable": exc.forceable}) from exc
    except (BlockError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/operations/{op_id}")
def operation(op_id: str):
    op = service.parts()["engine"].get_operation(op_id)
    if not op:
        raise HTTPException(status_code=404, detail="No such operation")
    return op


@router.get("/audit")
def audit(limit: int = 200, target: str = ""):
    store = service.parts()["store"]
    return {"entries": store.audit_entries(limit, target), "chain": store.audit_verify()}
