"""/api/ella: every action the interface offers is one of these calls. authz.py applies the roles before they run."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

from .. import auth, authz
from . import leaks, service
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


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/events")
def events(limit: int = 100, cursor_ts: float | None = None, cursor_id: int | None = None, client_ip: str = "", domain: str = "", rule_id: str = "", source: str = "", action: str = ""):
    sc = authz.scope()  # a website manager's query only ever covers their own domains
    cursor = (cursor_ts, cursor_id) if cursor_ts is not None and cursor_id is not None else None
    return service.parts()["store"].search_events(limit, cursor, sc["domains"] if sc else None, client_ip=client_ip, domain=domain, rule_id=rule_id, source=source, action=action)


@router.get("/sources")
def sources():
    rows = service.parts()["store"].read(lambda c: c.execute("SELECT path, kind, status, last_error, last_event_ts, last_read_ts, lines, unparsed, samples FROM sources ORDER BY path").fetchall())
    return {"sources": [dict(r) for r in rows]}


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
        return service.parts()["engine"].unban(block_id, user, body.reason)
    except BlockError as exc:
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
