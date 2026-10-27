"""AuroraPanel — a cPanel-style control panel for Raspberry Pi.

FastAPI backend: auth, system metrics, systemd services, processes, and a
sandboxed file manager. Serves the static frontend from ../frontend.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

from fastapi import (
    Depends, FastAPI, File, Form, HTTPException, Request, UploadFile,
    WebSocket, WebSocketDisconnect,
)
from fastapi.responses import (
    FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware
from pydantic import BaseModel

from . import (
    abuse, alerts, slackbot, antivirus, audit, authz, autossl, dockerapps, isolate, migrate, panelusers, servers, wptoolkit, schedules, tasks, updates, apache, apitokens, appmanager, auth, backups, config, cron,
    apps, databases, diskusage, dnszones, domains, fail2ban, netmgr, sites, files, firewall, ipblocker, jobs,
    metrics, modsecurity, netdiag, waf, packages, perms, phpmgr, services, sslcerts, sshaccess,
    secreport, shadow, sysapps, system_info, terminal, twofa, users,
    appconfig, ddns, ddnshosts, ftp, gitvc, guard, images, ipsec, webaccess, netmon, openvpn, mail, panelhttps, phpsettings, portcheck, requires, version, vpncommon, wireguard,
)

# The API schema is a full map of every endpoint, so it's off unless asked for.
_OPENAPI_URL = "/openapi.json" if os.environ.get("AURORA_ENABLE_OPENAPI") == "1" else None
app = FastAPI(title="AuroraPanel", version=version.VERSION,
              docs_url=None, redoc_url=None, openapi_url=_OPENAPI_URL)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
# Changes every process start (i.e. every deploy/restart). Injected into the
# frontend's asset URLs so browsers always fetch the current JS/CSS — a stale
# cached copy can never be reused because its URL no longer matches.
APP_VERSION = str(int(time.time()))


def _frontend_build() -> str:
    """Changes only when the panel's code does (unlike APP_VERSION, which changes on every
    restart): open tabs compare it to spot an update and offer a reload."""
    import hashlib
    h = hashlib.sha256(version.VERSION.encode())
    front = Path(__file__).resolve().parent.parent / "frontend"
    for f in sorted(front.rglob("*")):
        if f.suffix in (".js", ".css", ".html") and f.is_file():
            h.update(f"{f.relative_to(front)}:{f.stat().st_size}:{int(f.stat().st_mtime)}".encode())
    return h.hexdigest()[:12]


FRONTEND_BUILD = _frontend_build()


class _GZipFrontend(GZipMiddleware):
    """Compress the panel's own HTML/JS/CSS (app.js shrinks about 5×, which matters when
    the server is across the internet), but never API streams, downloads or uploads."""

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "") if scope["type"] == "http" else ""
        if path == "/" or (not path.startswith("/api/") and path.endswith((".js", ".css", ".html", ".svg"))):
            return await super().__call__(scope, receive, send)
        return await self.app(scope, receive, send)


app.add_middleware(_GZipFrontend, minimum_size=1024)
app.add_middleware(authz.AuthzMiddleware)
app.add_middleware(audit.AuditMiddleware)  # outermost: also records refused calls


@app.middleware("http")
async def _no_stale_frontend(request, call_next):
    """Force browsers to revalidate HTML/JS/CSS so a redeploy is never masked by
    a stale cached script. StaticFiles answers the conditional GET with 304 when
    unchanged, so this stays cheap."""
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.endswith((".html", ".js", ".css")):
        response.headers["Cache-Control"] = "no-cache"
    if path.startswith("/api/"):
        response.headers["X-Aurora-Build"] = FRONTEND_BUILD
    # Defence in depth against XSS: even if untrusted text (log lines, usernames
    # from the Network Monitor…) ever reached innerHTML, no script could run —
    # only our own same-origin files are executable; no inline/eval, no plugins.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ws: wss:; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def _render_index() -> HTMLResponse:
    html = (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")
    html = html.replace("__V__", APP_VERSION).replace("__BUILD__", FRONTEND_BUILD)
    return HTMLResponse(html, headers={"Cache-Control": "no-cache"})


@app.get("/")
def index_root():
    return _render_index()


@app.get("/index.html")
def index_html():
    return _render_index()


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #
class LoginBody(BaseModel):
    username: str
    password: str
    otp: str | None = None


class ServiceBody(BaseModel):
    unit: str
    action: str


class WriteBody(BaseModel):
    path: str
    content: str


class PathBody(BaseModel):
    path: str


class MkdirBody(BaseModel):
    path: str
    name: str


# --------------------------------------------------------------------------- #
# Auth / setup
# --------------------------------------------------------------------------- #
@app.get("/api/status")
def api_status():
    """Public: whether the owner still has the installer's random password (the sign-in
    page then says where to find it), and whether this is a Raspberry Pi (the interface
    says "server" instead of "Pi" on other machines).

    There is deliberately no "create your admin account" call: the installer makes the
    account with a random password, so nobody who finds a fresh panel can claim it."""
    return {"initialized": config.is_initialized(), "first_login": config.must_change_password(),
            "pi": system_info.is_pi()}


def _auth_log(ok: bool, username: str, request: Request):
    """One journal line per login attempt, read back by the Network Monitor.
    The username is JSON-encoded so it can't inject fake log lines."""
    ip = request.client.host if request.client else "?"
    print(f"aurora-auth: {'ok' if ok else 'fail'} user={json.dumps(username[:64])} ip={ip}", flush=True)
    audit.record(username[:64], ip, "login" if ok else "login failed", ok=ok, status=200 if ok else 401, method="POST", path="/api/login")


# Per-IP login throttle (fail2ban still bans at the firewall; this works without it).
# Each attempt is counted when it STARTS, so a burst of parallel requests can't
# all slip past the check while the (slow) password hash runs.
_LOGIN_WINDOW = 15 * 60
_LOGIN_MAX_FAILS = 10
_LOGIN_MAX_IPS = 10000
_login_fails: dict[str, list[float]] = {}
_login_lock = threading.Lock()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _login_begin(ip: str) -> int:
    """Count one attempt for this IP. Returns seconds to wait if it's over the
    limit (the attempt is then not counted), else 0."""
    now = time.time()
    with _login_lock:
        recent = [t for t in _login_fails.pop(ip, []) if now - t < _LOGIN_WINDOW]
        if len(recent) >= _LOGIN_MAX_FAILS:
            _login_fails[ip] = recent
            return int(_LOGIN_WINDOW - (now - recent[0])) + 1
        recent.append(now)
        _login_fails[ip] = recent  # re-inserted = most recently used
        # Bound memory by dropping the least recently used IPs, never the whole table.
        while len(_login_fails) > _LOGIN_MAX_IPS:
            _login_fails.pop(next(iter(_login_fails)))
    return 0


def _login_forgive(ip: str, everything: bool = False):
    """Take back the attempt counted by _login_begin (right password), or clear
    the IP entirely (successful login)."""
    with _login_lock:
        recent = _login_fails.get(ip)
        if not recent:
            return
        if everything:
            _login_fails.pop(ip, None)
        else:
            recent.pop()


def _is_https(request: Request) -> bool:
    if os.environ.get("AURORA_SECURE_COOKIES") == "1":
        return True
    proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return request.url.scheme == "https" or proto == "https"


def _set_session(resp: JSONResponse, request: Request, username: str):
    resp.set_cookie(
        auth.COOKIE_NAME, auth.issue_token(username),
        httponly=True, samesite="strict", max_age=auth.SESSION_TTL_SECONDS, path="/",
        secure=_is_https(request),
    )


@app.post("/api/login")
def api_login(body: LoginBody, request: Request):
    ip = _client_ip(request)
    wait = _login_begin(ip)
    if wait:
        raise HTTPException(status_code=429, detail=f"Too many failed logins. Try again in {(wait + 59) // 60} min.")
    is_owner = config.verify_credentials(body.username, body.password)
    if not is_owner and not panelusers.verify(body.username, body.password):
        _auth_log(False, body.username, request)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not is_owner:
        panelusers.touch(body.username)
    if is_owner and twofa.is_enabled():
        if not body.otp:
            # Right password, code still to come: don't count this one.
            _login_forgive(ip)
            # Signal the frontend to prompt for a 2FA code.
            raise HTTPException(status_code=401, detail="otp_required")
        if not twofa.verify_login(body.otp):
            _auth_log(False, body.username, request)
            raise HTTPException(status_code=401, detail="Invalid 2FA code")
    _login_forgive(ip, everything=True)
    _auth_log(True, body.username, request)
    resp = JSONResponse({"ok": True, "username": body.username})
    _set_session(resp, request, body.username)
    return resp


@app.post("/api/logout")
def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE_NAME, path="/")
    return resp


@app.get("/api/audit")
def api_audit(days: int = 30, q: str = "", user: str = "", failed: bool = False, limit: int = 2000, _u: str = auth.CurrentUser):
    return audit.entries(max(1, min(days, 400)), q, user, failed, max(1, min(limit, 20000)))


@app.get("/api/me")
def api_me(user: str = auth.CurrentUser):
    owner = files.default_user()
    me = panelusers.get(user) or {"role": "admin", "sites": []}
    full = me["role"] == "admin"  # limited users don't need to know the server's Linux account
    return {"username": user, "role": me["role"], "sites": me.get("sites", []), "owner": bool(me.get("owner")),
            "must_change_password": bool(me.get("owner")) and config.must_change_password(),
            "system_user": owner.pw_name if owner and full else None,
            "home": owner.pw_dir if owner and full else None}


class OwnPasswordBody(BaseModel):
    current: str
    new: str


@app.post("/api/me/password")
def api_me_password(body: OwnPasswordBody, user: str = auth.CurrentUser):
    """A panel user changes their own password (the owner uses Password & Security)."""
    try:
        return panelusers.change_own_password(user, body.current, body.new)
    except panelusers.PanelUserError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/mysites")
def api_mysites(user: str = auth.CurrentUser):
    """A website manager's home page: their sites with links to what they may use."""
    me = panelusers.get(user) or {"sites": []}
    out = []
    for name in me.get("sites", []):
        try:
            st = sites.get_site(name)["settings"]
            out.append({"name": name, "docroot": st["docroot"], "ssl": st["ssl"], "aliases": st.get("aliases", [])})
        except Exception:
            continue
    return {"sites": out, "webmail": mail.webmail_url() if mail.installed() else ""}


# --------------------------------------------------------------------------- #
# Panel users (roles)
# --------------------------------------------------------------------------- #
def _pu_call(fn):
    try:
        return fn()
    except panelusers.PanelUserError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/panel-users")
def api_pu(user: str = auth.CurrentUser):
    return {**panelusers.listing(), "sites": [s["server_name"] for s in sites.list_sites().get("sites", []) if not s.get("system")]}


class PanelUserBody(BaseModel):
    username: str
    password: str | None = None
    role: str | None = None
    sites: list[str] | None = None
    disabled: bool | None = None


@app.post("/api/panel-users")
def api_pu_create(body: PanelUserBody, user: str = auth.CurrentUser):
    return _pu_call(lambda: panelusers.create(body.username, body.password or "", body.role or "viewer", body.sites))


@app.post("/api/panel-users/update")
def api_pu_update(body: PanelUserBody, user: str = auth.CurrentUser):
    return _pu_call(lambda: panelusers.update(body.username, body.role, body.sites, body.password, body.disabled))


@app.post("/api/panel-users/delete")
def api_pu_delete(body: PanelUserBody, user: str = auth.CurrentUser):
    return _pu_call(lambda: panelusers.delete(body.username))


# --------------------------------------------------------------------------- #
# System metrics
# --------------------------------------------------------------------------- #
@app.get("/api/system/overview")
def api_overview(user: str = auth.CurrentUser):
    return system_info.overview()


@app.get("/api/system/disks")
def api_disks(user: str = auth.CurrentUser):
    return {"disks": system_info.disks()}


@app.get("/api/system/network")
def api_network(user: str = auth.CurrentUser):
    return system_info.networks()


# ---- Network manager (static IP, Wi-Fi, hotspot, hostname, LAN devices, ports) ----
def _panel(request: Request) -> tuple[str | None, int]:
    return request.url.hostname, request.url.port or (443 if request.url.scheme == "https" else 80)


def _net_call(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except netmgr.NetError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class NetIPv4Body(BaseModel):
    uuid: str
    method: str
    address: str = ""
    gateway: str = ""
    dns: list[str] = []


class WifiConnectBody(BaseModel):
    ssid: str
    password: str = ""
    device: str = ""
    hidden: bool = False


class NameBody(BaseModel):
    name: str


class HotspotBody(BaseModel):
    ssid: str
    password: str
    device: str = "wlan0"
    band: str = "bg"


class PendingBody(BaseModel):
    id: str


class RadioBody(BaseModel):
    on: bool


@app.get("/api/net/overview")
def api_net_overview(request: Request, user: str = auth.CurrentUser):
    return _net_call(netmgr.overview, _panel(request)[0])


@app.post("/api/net/ipv4")
def api_net_ipv4(body: NetIPv4Body, request: Request, user: str = auth.CurrentUser):
    host, port = _panel(request)
    return _net_call(netmgr.set_ipv4, body.uuid, body.method, body.address, body.gateway, body.dns, host, port)


@app.get("/api/net/wifi")
def api_net_wifi(rescan: bool = True, user: str = auth.CurrentUser):
    return _net_call(netmgr.wifi_scan, rescan)


@app.post("/api/net/wifi/connect")
def api_net_wifi_connect(body: WifiConnectBody, request: Request, user: str = auth.CurrentUser):
    host, port = _panel(request)
    return _net_call(netmgr.wifi_connect, body.ssid, body.password, body.device, body.hidden, host, port)


@app.post("/api/net/wifi/forget")
def api_net_wifi_forget(body: NameBody, user: str = auth.CurrentUser):
    return _net_call(netmgr.wifi_forget, body.name)


@app.post("/api/net/wifi/radio")
def api_net_wifi_radio(body: RadioBody, request: Request, user: str = auth.CurrentUser):
    return _net_call(netmgr.wifi_radio, body.on, _panel(request)[0])


@app.get("/api/net/hotspot")
def api_net_hotspot(user: str = auth.CurrentUser):
    return netmgr.hotspot_status()


@app.post("/api/net/hotspot/start")
def api_net_hotspot_start(body: HotspotBody, request: Request, user: str = auth.CurrentUser):
    return _net_call(netmgr.hotspot_start, body.ssid, body.password, body.device, body.band, _panel(request)[0])


@app.post("/api/net/hotspot/stop")
def api_net_hotspot_stop(user: str = auth.CurrentUser):
    return _net_call(netmgr.hotspot_stop)


@app.post("/api/net/hostname")
def api_net_hostname(body: NameBody, user: str = auth.CurrentUser):
    return _net_call(netmgr.set_hostname, body.name)


@app.get("/api/net/neighbours")
def api_net_neighbours(user: str = auth.CurrentUser):
    return netmgr.neighbours()


@app.get("/api/net/ports")
def api_net_ports(user: str = auth.CurrentUser):
    return netmgr.ports()


@app.get("/api/net/pending")
def api_net_pending(user: str = auth.CurrentUser):
    return {"pending": netmgr.pending_status()}


@app.post("/api/net/confirm")
def api_net_confirm(body: PendingBody):
    # Deliberately unauthenticated: after an IP change the login cookie belongs to the
    # old address. The one-time id (only shown to a logged-in user) is the credential,
    # and all it can do is *keep* a change the admin already made.
    return _net_call(netmgr.confirm, body.id)


@app.post("/api/net/revert")
def api_net_revert(body: PendingBody, user: str = auth.CurrentUser):
    return _net_call(netmgr.revert_now, body.id)


# ---- Applications ----
class WPInstallBody(BaseModel):
    options: dict


class AppRemoveBody(BaseModel):
    path: str
    drop_db: bool = True
    remove_site: bool = False


def _app_call(fn, *a):
    try:
        return fn(*a)
    except apps.AppError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/apps2/status")
def api_apps2_status(user: str = auth.CurrentUser):
    return apps.status()


@app.post("/api/apps2/wordpress")
def api_apps2_wordpress(body: WPInstallBody, user: str = auth.CurrentUser):
    return {"job": _app_call(apps.install_wordpress, body.options).id}


@app.post("/api/apps2/remove")
def api_apps2_remove(body: AppRemoveBody, user: str = auth.CurrentUser):
    return _app_call(apps.uninstall, body.path, body.drop_db, body.remove_site)


class AppInstallBody(BaseModel):
    app: str
    options: dict


@app.get("/api/apps2/catalog")
def api_apps2_catalog(user: str = auth.CurrentUser):
    return apps.catalog()


@app.get("/api/apps2/latest")
def api_apps2_latest(app_id: str, user: str = auth.CurrentUser):
    return _app_call(apps.latest, app_id)


@app.post("/api/apps2/preview")
def api_apps2_preview(body: AppInstallBody, user: str = auth.CurrentUser):
    return _app_call(apps.preview, {**body.options, "app": body.app})


@app.post("/api/apps2/install")
def api_apps2_install(body: AppInstallBody, user: str = auth.CurrentUser):
    return {"job": _app_call(apps.install, body.app, body.options).id}


@app.get("/api/apps2/password")
def api_apps2_password(user: str = auth.CurrentUser):
    return apps.suggest_password()


@app.get("/api/system/processes")
def api_processes(sort_by: str = "cpu", limit: int = 40, user: str = auth.CurrentUser):
    import psutil
    procs, counts = system_info.processes_full(limit=max(1, min(2000, limit)), sort_by=sort_by)
    return {"processes": procs, "counts": counts, "cpus": psutil.cpu_count() or 1, "mem_total": psutil.virtual_memory().total}


@app.post("/api/system/processes/{pid}/kill")
def api_kill(pid: int, user: str = auth.CurrentUser):
    import psutil
    try:
        system_info.kill_process(pid)
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail="No such process")
    except psutil.AccessDenied:
        raise HTTPException(status_code=403, detail="Access denied (try running as root)")
    return {"ok": True, "pid": pid}


# --------------------------------------------------------------------------- #
# Services
# --------------------------------------------------------------------------- #
@app.get("/api/services")
def api_services(user: str = auth.CurrentUser):
    try:
        return {"services": services.list_services(), "supported": services.IS_LINUX}
    except services.ServiceError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/services/control")
def api_service_control(body: ServiceBody, user: str = auth.CurrentUser):
    try:
        return services.control_service(body.unit, body.action)
    except services.ServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/services/status")
def api_service_status(unit: str, user: str = auth.CurrentUser):
    try:
        return services.service_status(unit)
    except services.ServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# File manager
# --------------------------------------------------------------------------- #
@app.get("/api/files/list")
def api_files_list(path: str = "", user: str = auth.CurrentUser):
    try:
        return files.list_dir(path)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/files/read")
def api_files_read(path: str, user: str = auth.CurrentUser):
    try:
        return files.read_text(path)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/files/write")
def api_files_write(body: WriteBody, user: str = auth.CurrentUser):
    try:
        return files.write_text(body.path, body.content)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class DeleteBody(BaseModel):
    path: str
    permanent: bool = False


class ZipBody(BaseModel):
    path: str = ""
    names: list[str]
    archive_name: str = "archive.zip"
    overwrite: bool = False


class UnzipBody(BaseModel):
    path: str
    overwrite: bool = False


class TrashActionBody(BaseModel):
    id: str
    overwrite: bool = False


class TransferBody(BaseModel):
    path: str = ""
    names: list[str]
    dest: str
    overwrite: bool = False


@app.post("/api/files/move")
def api_files_move(body: TransferBody, user: str = auth.CurrentUser):
    try:
        return files.transfer(body.path, body.names, body.dest, "move", body.overwrite)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/files/copy")
def api_files_copy(body: TransferBody, user: str = auth.CurrentUser):
    try:
        return files.transfer(body.path, body.names, body.dest, "copy", body.overwrite)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/files/delete")
def api_files_delete(body: DeleteBody, user: str = auth.CurrentUser):
    try:
        return files.delete(body.path, body.permanent)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/files/zip")
def api_files_zip(body: ZipBody, user: str = auth.CurrentUser):
    try:
        return files.zip_entries(body.path, body.names, body.archive_name, body.overwrite)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/files/unzip")
def api_files_unzip(body: UnzipBody, user: str = auth.CurrentUser):
    try:
        return files.unzip(body.path, body.overwrite)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/files/trash")
def api_files_trash(user: str = auth.CurrentUser):
    return files.list_trash()


@app.post("/api/files/trash/restore")
def api_files_trash_restore(body: TrashActionBody, user: str = auth.CurrentUser):
    try:
        return files.restore_trash(body.id, body.overwrite)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/files/trash/delete")
def api_files_trash_delete(body: TrashActionBody, user: str = auth.CurrentUser):
    try:
        return files.delete_trash(body.id)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/files/trash/empty")
def api_files_trash_empty(user: str = auth.CurrentUser):
    return files.empty_trash()


@app.post("/api/files/mkdir")
def api_files_mkdir(body: MkdirBody, user: str = auth.CurrentUser):
    try:
        return files.make_dir(body.path, body.name)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (FileExistsError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/files/upload")
async def api_files_upload(
    path: str = Form(""), file: UploadFile = File(...), user: str = auth.CurrentUser
):
    data = await file.read()
    try:
        return files.save_upload(path, file.filename or "upload.bin", data)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/files/download")
def api_files_download(path: str, user: str = auth.CurrentUser):
    try:
        target = files.resolve_for_download(path)
    except files.FileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return FileResponse(target, filename=target.name)


# --------------------------------------------------------------------------- #
# Background jobs (shared by packages + backups)
# --------------------------------------------------------------------------- #
@app.get("/api/jobs")
def api_jobs(user: str = auth.CurrentUser):
    return {"jobs": jobs.listing()}


@app.get("/api/jobs/{job_id}")
def api_job(job_id: str, tail: int = 400, user: str = auth.CurrentUser):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="No such job")
    return job.to_dict(tail=tail)


# --------------------------------------------------------------------------- #
# Packages (apt)
# --------------------------------------------------------------------------- #
class PkgNamesBody(BaseModel):
    packages: list[str]


@app.get("/api/packages/installed")
def api_pkg_installed(user: str = auth.CurrentUser):
    return {"packages": packages.installed(), "supported": packages.IS_LINUX}


@app.get("/api/packages/upgradable")
def api_pkg_upgradable(user: str = auth.CurrentUser):
    try:
        return {"packages": packages.upgradable()}
    except packages.PackageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/packages/search")
def api_pkg_search(q: str, user: str = auth.CurrentUser):
    try:
        return {"results": packages.search(q)}
    except packages.PackageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/packages/update")
def api_pkg_update(user: str = auth.CurrentUser):
    try:
        return {"job": packages.job_update().id}
    except packages.PackageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/packages/upgrade")
def api_pkg_upgrade(user: str = auth.CurrentUser):
    try:
        return {"job": packages.job_upgrade().id}
    except packages.PackageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/packages/install")
def api_pkg_install(body: PkgNamesBody, user: str = auth.CurrentUser):
    try:
        return {"job": packages.job_install(body.packages).id}
    except packages.PackageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/packages/remove")
def api_pkg_remove(body: PkgNamesBody, user: str = auth.CurrentUser):
    try:
        return {"job": packages.job_remove(body.packages).id}
    except packages.PackageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Cron
# --------------------------------------------------------------------------- #
class CronAddBody(BaseModel):
    schedule: str
    command: str
    label: str | None = None


class CronDelBody(BaseModel):
    raw: str


class CronUpdateBody(BaseModel):
    raw: str
    schedule: str
    command: str
    label: str | None = None
    paused: bool = False


class CronPauseBody(BaseModel):
    raw: str
    paused: bool


@app.get("/api/cron")
def api_cron(user: str = auth.CurrentUser):
    try:
        return {**cron.list_jobs(), "supported": cron.IS_LINUX}
    except cron.CronError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/cron/add")
def api_cron_add(body: CronAddBody, user: str = auth.CurrentUser):
    try:
        return cron.add_job(body.schedule, body.command, body.label)
    except cron.CronError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/cron/update")
def api_cron_update(body: CronUpdateBody, user: str = auth.CurrentUser):
    try:
        return cron.update_job(body.raw, body.schedule, body.command, body.label, body.paused)
    except cron.CronError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/cron/pause")
def api_cron_pause(body: CronPauseBody, user: str = auth.CurrentUser):
    try:
        return cron.set_paused(body.raw, body.paused)
    except cron.CronError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/cron/run")
def api_cron_run(body: CronDelBody, user: str = auth.CurrentUser):
    try:
        return cron.run_now(body.raw)
    except cron.CronError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/cron/delete")
def api_cron_delete(body: CronDelBody, user: str = auth.CurrentUser):
    try:
        return cron.delete_job(body.raw)
    except cron.CronError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
class UserAddBody(BaseModel):
    name: str
    create_home: bool = True
    shell: str = "/bin/bash"


class UserDelBody(BaseModel):
    name: str
    remove_home: bool = False


class UserLockBody(BaseModel):
    name: str
    locked: bool


class UserPwBody(BaseModel):
    name: str
    password: str


@app.get("/api/users")
def api_users(include_system: bool = False, user: str = auth.CurrentUser):
    return {"users": users.list_users(include_system=include_system), "supported": users.IS_LINUX}


@app.post("/api/users/add")
def api_users_add(body: UserAddBody, user: str = auth.CurrentUser):
    try:
        return users.add_user(body.name, body.create_home, body.shell)
    except users.UserError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/users/delete")
def api_users_delete(body: UserDelBody, user: str = auth.CurrentUser):
    try:
        return users.delete_user(body.name, body.remove_home)
    except users.UserError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/users/lock")
def api_users_lock(body: UserLockBody, user: str = auth.CurrentUser):
    try:
        return users.set_lock(body.name, body.locked)
    except users.UserError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/users/password")
def api_users_password(body: UserPwBody, user: str = auth.CurrentUser):
    try:
        return users.set_password(body.name, body.password)
    except users.UserError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Firewall (ufw)
# --------------------------------------------------------------------------- #
class FwToggleBody(BaseModel):
    enabled: bool


class FwRuleBody(BaseModel):
    action: str
    port: str
    proto: str = "tcp"


class FwDelBody(BaseModel):
    num: int


@app.get("/api/firewall")
def api_firewall(user: str = auth.CurrentUser):
    return firewall.status()


@app.post("/api/firewall/toggle")
def api_firewall_toggle(body: FwToggleBody, user: str = auth.CurrentUser):
    try:
        return firewall.set_enabled(body.enabled)
    except firewall.FirewallError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/firewall/rule")
def api_firewall_rule(body: FwRuleBody, user: str = auth.CurrentUser):
    try:
        return firewall.add_rule(body.action, body.port, body.proto)
    except firewall.FirewallError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/firewall/delete")
def api_firewall_delete(body: FwDelBody, user: str = auth.CurrentUser):
    try:
        return firewall.delete_rule(body.num)
    except firewall.FirewallError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Disk usage
# --------------------------------------------------------------------------- #
@app.get("/api/diskusage")
def api_diskusage(path: str = "/", user: str = auth.CurrentUser):
    try:
        return diskusage.children_sizes(path)
    except diskusage.DiskUsageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Backups
# --------------------------------------------------------------------------- #
class BackupCreateBody(BaseModel):
    source: str
    label: str = ""


class BackupRestoreBody(BaseModel):
    name: str
    dest: str | None = None


class BackupDbBody(BaseModel):
    engine: str
    db: str
    label: str = ""


class BackupDbRestoreBody(BaseModel):
    name: str
    target: str = ""
    engine: str = ""
    wipe: bool = True


class BackupNameBody(BaseModel):
    name: str


@app.get("/api/backups")
def api_backups(user: str = auth.CurrentUser):
    return backups.list_backups()


@app.post("/api/backups/create")
def api_backups_create(body: BackupCreateBody, user: str = auth.CurrentUser):
    try:
        return {"job": backups.create_backup(body.source, body.label).id}
    except backups.BackupError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/backups/restore")
def api_backups_restore(body: BackupRestoreBody, user: str = auth.CurrentUser):
    try:
        return {"job": backups.restore_backup(body.name, body.dest).id}
    except backups.BackupError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/backups/database")
def api_backups_database(body: BackupDbBody, user: str = auth.CurrentUser):
    try:
        return {"job": backups.backup_database(body.engine, body.db, body.label).id}
    except backups.BackupError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/backups/restore-db")
def api_backups_restore_db(body: BackupDbRestoreBody, user: str = auth.CurrentUser):
    try:
        return {"job": backups.restore_database(body.name, body.target, body.engine, body.wipe).id}
    except backups.BackupError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/backups/jobs")
def api_backups_jobs(user: str = auth.CurrentUser):
    return backups.backup_jobs()


@app.post("/api/backups/upload")
async def api_backups_upload(file: UploadFile = File(...), user: str = auth.CurrentUser):
    tmp = None
    try:
        tmp, final = backups.upload_target(file.filename or "")
        with open(tmp, "wb") as fh:
            while chunk := await file.read(1 << 20):
                fh.write(chunk)
        return backups.finish_upload(tmp, final)
    except backups.BackupError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Upload failed: {exc}")
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


@app.post("/api/backups/delete")
def api_backups_delete(body: BackupNameBody, user: str = auth.CurrentUser):
    try:
        return backups.delete_backup(body.name)
    except backups.BackupError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/backups/download")
def api_backups_download(name: str, user: str = auth.CurrentUser):
    try:
        target = backups.resolve_for_download(name)
    except backups.BackupError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return FileResponse(target, filename=target.name)


# --------------------------------------------------------------------------- #
# Two-factor auth
# --------------------------------------------------------------------------- #
class OtpBody(BaseModel):
    code: str


@app.get("/api/2fa/status")
def api_2fa_status(user: str = auth.CurrentUser):
    return twofa.status()


@app.post("/api/2fa/enroll")
def api_2fa_enroll(user: str = auth.CurrentUser):
    return twofa.begin_enroll(user)


@app.post("/api/2fa/enable")
def api_2fa_enable(body: OtpBody, request: Request, user: str = auth.CurrentUser):
    if not twofa.confirm_enable(body.code):
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    # Sessions opened without 2FA shouldn't outlive turning it on: sign them
    # all out and give this browser a fresh cookie.
    config.rotate_session_secret()
    resp = JSONResponse({"ok": True, "enabled": True})
    _set_session(resp, request, config.get_prefs()["username"])
    return resp


@app.post("/api/2fa/disable")
def api_2fa_disable(body: OtpBody, user: str = auth.CurrentUser):
    if not twofa.disable(body.code):
        raise HTTPException(status_code=400, detail="Invalid code")
    return {"ok": True, "enabled": False}


class PanelHttpsBody(BaseModel):
    source: str = "self"
    regenerate: bool = False
    host: str = ""  # what the browser's address bar shows: goes into a regenerated self-signed certificate


@app.get("/api/panel/https")
def api_panel_https(request: Request, user: str = auth.CurrentUser):
    return panelhttps.status(request.url.scheme, request.url.hostname or "")


@app.post("/api/panel/https/enable")
def api_panel_https_enable(body: PanelHttpsBody, request: Request, user: str = auth.CurrentUser):
    try:
        return panelhttps.enable(body.source, body.regenerate, body.host or request.url.hostname or "")
    except panelhttps.PanelHttpsError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/panel/https/confirm")
def api_panel_https_confirm(request: Request, user: str = auth.CurrentUser):
    try:
        return panelhttps.confirm(request.url.scheme)
    except panelhttps.PanelHttpsError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/panel/https/disable")
def api_panel_https_disable(user: str = auth.CurrentUser):
    return panelhttps.disable()


@app.post("/api/panel/https/harden")
def api_panel_https_harden(user: str = auth.CurrentUser):
    try:
        return panelhttps.harden()
    except panelhttps.PanelHttpsError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/panel/https/redirect")
def api_panel_https_redirect(user: str = auth.CurrentUser):
    try:
        return panelhttps.harden()
    except panelhttps.PanelHttpsError as e:
        raise HTTPException(status_code=400, detail=str(e))


# Web server hardening (Apache: version hidden, security headers, modern TLS) — see appconfig.py
@app.get("/api/apache/hardening")
def api_apache_hardening(user: str = auth.CurrentUser):
    return appconfig.apache_hardening()


@app.post("/api/apache/harden")
def api_apache_harden(user: str = auth.CurrentUser):
    try:
        return appconfig.apache_harden()
    except appconfig.AppConfigError as e:
        raise HTTPException(status_code=400, detail=str(e))


# Shadow Copies: version history of a site's files (see shadow.py)
class ShadowBody(BaseModel):
    id: str
    on: bool | None = None
    path: str = ""
    ts: int | None = None
    keep_days: int | None = None
    max_versions: int | None = None
    max_mb: int | None = None
    max_file_mb: int | None = None


def _shadow_call(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except shadow.ShadowError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/shadow")
def api_shadow(user: str = auth.CurrentUser):
    return shadow.overview()


@app.get("/api/shadow/files")
def api_shadow_files(id: str, q: str = "", only: str = "", user: str = auth.CurrentUser):
    return _shadow_call(shadow.files, id, q, only)


@app.post("/api/shadow/enable")
def api_shadow_enable(body: ShadowBody, user: str = auth.CurrentUser):
    return _shadow_call(shadow.set_enabled, body.id, bool(body.on))


@app.post("/api/shadow/settings")
def api_shadow_settings(body: ShadowBody, user: str = auth.CurrentUser):
    return _shadow_call(shadow.set_settings, body.id, body.keep_days, body.max_versions, body.max_mb, body.max_file_mb)


@app.post("/api/shadow/snapshot")
def api_shadow_snapshot(body: ShadowBody, user: str = auth.CurrentUser):
    if body.id == "*":
        return {"ok": True, "sites": shadow.snapshot_all()}
    return _shadow_call(shadow.snapshot, body.id)


@app.post("/api/shadow/restore")
def api_shadow_restore(body: ShadowBody, user: str = auth.CurrentUser):
    return _shadow_call(shadow.restore, body.id, body.path, int(body.ts or 0))


@app.post("/api/shadow/forget")
def api_shadow_forget(body: ShadowBody, user: str = auth.CurrentUser):
    return _shadow_call(shadow.forget, body.id, body.path, body.ts)


@app.get("/api/shadow/download")
def api_shadow_download(id: str, path: str, ts: int, user: str = auth.CurrentUser):
    p = _shadow_call(shadow.version_path, id, path, ts)
    return FileResponse(str(p), filename=Path(path).name, media_type="application/octet-stream")


# Security Report: scan what this server owns, score it (see secreport.py)
class SecReportBody(BaseModel):
    targets: list[str] = []


@app.get("/api/secreport")
def api_secreport(user: str = auth.CurrentUser):
    return secreport.overview()


@app.post("/api/secreport/run")
def api_secreport_run(body: SecReportBody, user: str = auth.CurrentUser):
    try:
        return secreport.run(body.targets or None)
    except secreport.SecReportError as e:
        raise HTTPException(status_code=400, detail=str(e))


class SecFixBody(BaseModel):
    action: str


@app.post("/api/secreport/fix")
def api_secreport_fix(body: SecFixBody, user: str = auth.CurrentUser):
    """One-click fix offered next to a finding (see secreport.fix)."""
    try:
        return secreport.fix(body.action)
    except secreport.SecReportError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/secreport/html")
def api_secreport_html(user: str = auth.CurrentUser):
    rep = secreport.last()
    if not rep:
        raise HTTPException(status_code=404, detail="Run a report first")
    name = f"security-report-{rep['hostname']}-{time.strftime('%Y-%m-%d', time.localtime(rep['ts']))}.html"
    return HTMLResponse(secreport.report_html(rep), headers={"Content-Disposition": f'attachment; filename="{name}"'})


# --------------------------------------------------------------------------- #
# Advanced: Apache .htaccess (Indexes, MIME, Error pages, Handlers)
# --------------------------------------------------------------------------- #
class IndexesBody(BaseModel):
    dir: str = ""
    listing: bool
    directory_index: str | None = None


class MimeAddBody(BaseModel):
    dir: str = ""
    mime: str
    extensions: str


class ErrorSetBody(BaseModel):
    create: str = ""  # file name to write a starter page to, if missing
    dir: str = ""
    code: str
    document: str


class HandlerAddBody(BaseModel):
    dir: str = ""
    handler: str
    extensions: str


class ApacheRemoveBody(BaseModel):
    dir: str = ""
    raw: str


@app.get("/api/apache/htaccess")
def api_apache_raw(dir: str = "", user: str = auth.CurrentUser):
    try:
        return apache.raw(dir)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/apache/indexes")
def api_apache_indexes(dir: str = "", user: str = auth.CurrentUser):
    try:
        return {**apache.get_indexes(dir), "root": str(apache.APACHE_ROOT)}
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/apache/indexes")
def api_apache_set_indexes(body: IndexesBody, user: str = auth.CurrentUser):
    try:
        return apache.set_indexes(body.dir, body.listing, body.directory_index)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/apache/mime")
def api_apache_mime(dir: str = "", user: str = auth.CurrentUser):
    try:
        return {**apache.list_mime(dir), "system": apache.system_mime()}
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/apache/mime")
def api_apache_add_mime(body: MimeAddBody, user: str = auth.CurrentUser):
    try:
        return apache.add_mime(body.dir, body.mime, body.extensions)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/apache/errors")
def api_apache_errors(dir: str = "", user: str = auth.CurrentUser):
    try:
        return apache.list_errors(dir)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/apache/errors")
def api_apache_set_error(body: ErrorSetBody, user: str = auth.CurrentUser):
    try:
        return apache.set_error(body.dir, body.code, body.document, body.create)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/apache/handlers")
def api_apache_handlers(dir: str = "", user: str = auth.CurrentUser):
    try:
        return apache.list_handlers(dir)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/apache/handlers")
def api_apache_add_handler(body: HandlerAddBody, user: str = auth.CurrentUser):
    try:
        return apache.add_handler(body.dir, body.handler, body.extensions)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/apache/options")
def api_apache_options(dir: str = "", user: str = auth.CurrentUser):
    try:
        return apache.list_options(dir)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class ApacheOptionBody(BaseModel):
    dir: str = ""
    name: str
    on: bool


@app.post("/api/apache/options")
def api_apache_set_option(body: ApacheOptionBody, user: str = auth.CurrentUser):
    try:
        return apache.set_option(body.dir, body.name, body.on)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/apache/remove")
def api_apache_remove(body: ApacheRemoveBody, user: str = auth.CurrentUser):
    try:
        return apache.remove_directive(body.dir, body.raw)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Advanced: Track DNS
# --------------------------------------------------------------------------- #
@app.get("/api/dns/records")
def api_dns_records(host: str, types: str = "", server: str = "", user: str = auth.CurrentUser):
    try:
        return netdiag.dns_records(host, [t for t in types.upper().split(",") if t], server)
    except netdiag.NetDiagError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/dns/propagation")
def api_dns_propagation(host: str, type: str = "A", user: str = auth.CurrentUser):
    try:
        return netdiag.propagation(host, type.upper())
    except netdiag.NetDiagError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/dns/mailcheck")
def api_dns_mailcheck(domain: str, user: str = auth.CurrentUser):
    try:
        return netdiag.mail_check(domain)
    except netdiag.NetDiagError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/dns/nscheck")
def api_dns_nscheck(domain: str, user: str = auth.CurrentUser):
    try:
        return netdiag.ns_check(domain)
    except netdiag.NetDiagError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/dns/whois")
def api_dns_whois(host: str, user: str = auth.CurrentUser):
    try:
        return netdiag.whois(host)
    except netdiag.NetDiagError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/dns/reverse")
def api_dns_reverse(ip: str, user: str = auth.CurrentUser):
    try:
        return netdiag.reverse_lookup(ip)
    except netdiag.NetDiagError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/dns/traceroute")
def api_dns_traceroute(host: str, user: str = auth.CurrentUser):
    try:
        return netdiag.traceroute(host)
    except netdiag.NetDiagError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/net/ping")
def api_net_ping(host: str, count: int = 4, user: str = auth.CurrentUser):
    try:
        return netdiag.ping(host, count)
    except netdiag.NetDiagError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Advanced: Virus scanner (ClamAV)
# --------------------------------------------------------------------------- #
class ScanBody(BaseModel):
    path: str
    recursive: bool = True


@app.get("/api/antivirus/status")
def api_av_status(user: str = auth.CurrentUser):
    return antivirus.status()


@app.post("/api/antivirus/scan")
def api_av_scan(body: ScanBody, user: str = auth.CurrentUser):
    try:
        return {"job": antivirus.scan(body.path, body.recursive).id}
    except antivirus.AntivirusError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/antivirus/update")
def api_av_update(user: str = auth.CurrentUser):
    try:
        return {"job": antivirus.update_db().id}
    except antivirus.AntivirusError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Security: SSH Access
# --------------------------------------------------------------------------- #
class SSHKeyBody(BaseModel):
    user: str
    public_key: str


class SSHKeyRemoveBody(BaseModel):
    user: str
    raw: str


@app.get("/api/ssh/status")
def api_ssh_status(user: str = auth.CurrentUser):
    return sshaccess.status()


@app.post("/api/ssh/restart")
def api_ssh_restart(user: str = auth.CurrentUser):
    try:
        return sshaccess.restart()
    except sshaccess.SSHError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/ssh/keys")
def api_ssh_keys(target: str, user: str = auth.CurrentUser):
    try:
        return sshaccess.list_keys(target)
    except sshaccess.SSHError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/ssh/keys/add")
def api_ssh_keys_add(body: SSHKeyBody, user: str = auth.CurrentUser):
    try:
        return sshaccess.add_key(body.user, body.public_key)
    except sshaccess.SSHError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/ssh/keys/remove")
def api_ssh_keys_remove(body: SSHKeyRemoveBody, user: str = auth.CurrentUser):
    try:
        return sshaccess.remove_key(body.user, body.raw)
    except sshaccess.SSHError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Security: IP Blocker
# --------------------------------------------------------------------------- #
class IPBody(BaseModel):
    ip: str


class NumBody(BaseModel):
    num: int


@app.get("/api/ipblocker")
def api_ipblocker(user: str = auth.CurrentUser):
    return ipblocker.list_blocked()


@app.post("/api/ipblocker/block")
def api_ipblocker_block(body: IPBody, request: Request, user: str = auth.CurrentUser):
    try:
        return ipblocker.block(body.ip, request.client.host if request.client else None)
    except ipblocker.IPBlockError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/ipblocker/unblock")
def api_ipblocker_unblock(body: NumBody, user: str = auth.CurrentUser):
    try:
        return ipblocker.unblock(body.num)
    except (ipblocker.IPBlockError, firewall.FirewallError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Security: SSL/TLS Certificates
# --------------------------------------------------------------------------- #
class SelfSignedBody(BaseModel):
    common_name: str
    days: int = 365


@app.get("/api/ssl/certs")
def api_ssl_certs(user: str = auth.CurrentUser):
    try:
        return sslcerts.list_certs()
    except sslcerts.SSLCertError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/ssl/selfsigned")
def api_ssl_selfsigned(body: SelfSignedBody, user: str = auth.CurrentUser):
    try:
        return sslcerts.generate_self_signed(body.common_name, body.days)
    except sslcerts.SSLCertError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Security: API Tokens
# --------------------------------------------------------------------------- #
class TokenNameBody(BaseModel):
    name: str


class TokenIdBody(BaseModel):
    id: str


@app.get("/api/tokens")
def api_tokens(user: str = auth.CurrentUser):
    return apitokens.listing()


@app.post("/api/tokens/create")
def api_tokens_create(body: TokenNameBody, user: str = auth.CurrentUser):
    try:
        return apitokens.create(body.name)
    except apitokens.APITokenError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/tokens/revoke")
def api_tokens_revoke(body: TokenIdBody, user: str = auth.CurrentUser):
    try:
        return apitokens.revoke(body.id)
    except apitokens.APITokenError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Security: Hotlink Protection + Redirects (Apache)
# --------------------------------------------------------------------------- #
class HotlinkBody(BaseModel):
    dir: str = ""
    enabled: bool
    allowed_hosts: str = ""
    extensions: str = ""


class RedirectBody(BaseModel):
    dir: str = ""
    code: str
    source: str
    target: str


@app.get("/api/apache/hotlink")
def api_hotlink(dir: str = "", user: str = auth.CurrentUser):
    try:
        return {**apache.get_hotlink(dir), "root": str(apache.APACHE_ROOT)}
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/apache/hotlink")
def api_hotlink_set(body: HotlinkBody, user: str = auth.CurrentUser):
    try:
        return apache.set_hotlink(body.dir, body.enabled, body.allowed_hosts, body.extensions)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/apache/redirects")
def api_redirects(dir: str = "", user: str = auth.CurrentUser):
    try:
        return apache.list_redirects(dir)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/apache/redirects")
def api_redirects_add(body: RedirectBody, user: str = auth.CurrentUser):
    try:
        return apache.add_redirect(body.dir, body.code, body.source, body.target)
    except apache.ApacheError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Security: ModSecurity
# --------------------------------------------------------------------------- #
class EnableBody(BaseModel):
    enabled: bool


@app.get("/api/modsecurity")
def api_modsec(user: str = auth.CurrentUser):
    return modsecurity.status()


@app.post("/api/modsecurity/toggle")
def api_modsec_toggle(body: EnableBody, user: str = auth.CurrentUser):
    try:
        return modsecurity.set_enabled(body.enabled)
    except modsecurity.ModSecError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/modsecurity/install")
def api_modsec_install(user: str = auth.CurrentUser):
    return {"job": modsecurity.install().id}


# --------------------------------------------------------------------------- #
# Security: WAF Firewall (ModSecurity + OWASP CRS)
# --------------------------------------------------------------------------- #
def _waf_call(fn):
    try:
        return fn()
    except waf.WafError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class WafBody(BaseModel):
    mode: str | None = None
    paranoia: int | None = None
    threshold: int | None = None
    apps: list[str] | None = None
    trusted: list[str] | None = None
    sites_off: list[str] | None = None


class WafRuleBody(BaseModel):
    id: str
    msg: str = ""


@app.get("/api/waf")
def api_waf(user: str = auth.CurrentUser):
    return waf.status()


@app.post("/api/waf")
def api_waf_update(body: WafBody, user: str = auth.CurrentUser):
    return _waf_call(lambda: waf.update(body.model_dump(exclude_none=True)))


@app.get("/api/waf/events")
def api_waf_events(hours: int = 24, ip: str = "", user: str = auth.CurrentUser):
    ev = waf.events(hours=max(1, min(hours, 24 * 30)), limit=500, ip=ip)
    try:
        st = guard.status_of(sorted({e["ip"] for e in ev}))
    except Exception:
        st = {}
    return {"events": ev, "ip_status": st}


@app.post("/api/waf/allow-rule")
def api_waf_allow(body: WafRuleBody, user: str = auth.CurrentUser):
    return _waf_call(lambda: waf.allow_rule(body.id, body.msg))


@app.post("/api/waf/restore-rule")
def api_waf_restore(body: WafRuleBody, user: str = auth.CurrentUser):
    return _waf_call(lambda: waf.restore_rule(body.id))


@app.post("/api/waf/test")
def api_waf_test(user: str = auth.CurrentUser):
    return _waf_call(waf.test)


# --------------------------------------------------------------------------- #
# Security: Leech Protection (fail2ban)
# --------------------------------------------------------------------------- #
class UnbanBody(BaseModel):
    jail: str
    ip: str


@app.get("/api/fail2ban")
def api_fail2ban(user: str = auth.CurrentUser):
    return fail2ban.status()


@app.post("/api/fail2ban/unban")
def api_fail2ban_unban(body: UnbanBody, user: str = auth.CurrentUser):
    try:
        return fail2ban.unban(body.jail, body.ip)
    except fail2ban.Fail2banError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/fail2ban/install")
def api_fail2ban_install(user: str = auth.CurrentUser):
    return {"job": fail2ban.install().id}


# --------------------------------------------------------------------------- #
# Security: Fix Home Permissions
# --------------------------------------------------------------------------- #
class NameBody(BaseModel):
    name: str


@app.post("/api/fixperms")
def api_fixperms(body: NameBody, user: str = auth.CurrentUser):
    try:
        return perms.fix_home(body.name)
    except perms.PermError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Domains
# --------------------------------------------------------------------------- #
class VhostBody(BaseModel):
    server_name: str
    docroot: str = ""
    port: int = 80


class DomainNameBody(BaseModel):
    server_name: str


class SiteSaveBody(BaseModel):
    original: str = ""
    settings: dict


class SiteToggleBody(BaseModel):
    server_name: str
    key: str
    value: bool


class LEBody(BaseModel):
    server_name: str
    email: str
    include_aliases: bool = True
    force: bool = False


def _site_call(fn, *a):
    try:
        return fn(*a)
    except sites.SiteError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/sites")
def api_sites(user: str = auth.CurrentUser):
    return sites.list_sites()


@app.get("/api/sites/get")
def api_site_get(name: str, user: str = auth.CurrentUser):
    return _site_call(sites.get_site, name)


@app.post("/api/sites/create")
def api_site_create(body: SiteSaveBody, user: str = auth.CurrentUser):
    return _site_call(sites.create_site, body.settings)


@app.post("/api/sites/save")
def api_site_save(body: SiteSaveBody, user: str = auth.CurrentUser):
    return _site_call(sites.save_site, body.original, body.settings)


@app.post("/api/sites/toggle")
def api_site_toggle(body: SiteToggleBody, user: str = auth.CurrentUser):
    return _site_call(sites.quick_toggle, body.server_name, body.key, body.value)


class SystemSslBody(BaseModel):
    conf: str
    ssl: str
    cert: str = ""
    key: str = ""
    chain: str = ""


@app.post("/api/sites/system-ssl")
def api_site_system_ssl(body: SystemSslBody, user: str = auth.CurrentUser):
    return _site_call(sites.set_system_ssl, body.conf, body.ssl, body.cert, body.key, body.chain)


class SystemAdoptBody(BaseModel):
    conf: str


@app.post("/api/sites/system-adopt")
def api_site_system_adopt(body: SystemAdoptBody, user: str = auth.CurrentUser):
    """A hand-copied sites-enabled/<conf> becomes the normal sites-available file + link (contents kept, both backed up)."""
    return _site_call(sites.adopt_system_conf, body.conf)


class FolderIndexesBody(BaseModel):
    name: str
    on: bool


@app.post("/api/sites/folders/indexes")
def api_folder_site_indexes(body: FolderIndexesBody, user: str = auth.CurrentUser):
    return _site_call(sites.set_folder_site_indexes, body.name, body.on)


class SiteConfBody(BaseModel):
    name: str
    text: str


@app.post("/api/sites/conf")
def api_site_conf(body: SiteConfBody, user: str = auth.CurrentUser):
    return _site_call(sites.save_conf_text, body.name, body.text)


class SystemCustomBody(BaseModel):
    conf: str
    custom: str = ""


@app.post("/api/sites/system-custom")
def api_site_system_custom(body: SystemCustomBody, user: str = auth.CurrentUser):
    return _site_call(sites.set_system_custom, body.conf, body.custom)


@app.post("/api/sites/remove")
def api_site_remove(body: DomainNameBody, user: str = auth.CurrentUser):
    return _site_call(sites.remove_site, body.server_name)


class FolderSiteBody(BaseModel):
    name: str
    path: str = ""
    delete_files: bool = False  # remove: also delete the folder
    backup: bool = False        # remove: back the folder up (Backups) before deleting it


@app.get("/api/sites/folders")
def api_folder_sites(user: str = auth.CurrentUser):
    return sites.list_folder_sites()


@app.post("/api/sites/folders/create")
def api_folder_site_create(body: FolderSiteBody, user: str = auth.CurrentUser):
    return _site_call(sites.create_folder_site, body.name, body.path)


@app.post("/api/sites/folders/remove")
def api_folder_site_remove(body: FolderSiteBody, user: str = auth.CurrentUser):
    return _site_call(sites.remove_folder_site, body.name, body.delete_files, body.backup)


@app.post("/api/sites/certbot/install")
def api_certbot_install(user: str = auth.CurrentUser):
    return {"job": sites.certbot_install().id}


@app.post("/api/sites/letsencrypt")
def api_site_le(body: LEBody, user: str = auth.CurrentUser):
    return {"job": _site_call(sites.issue_letsencrypt, body.server_name, body.email, body.include_aliases, body.force).id}


class RegenBody(BaseModel):
    name: str


@app.post("/api/sites/selfsigned/regenerate")
def api_site_regen(body: RegenBody, user: str = auth.CurrentUser):
    return _site_call(sites.regenerate_selfsigned, body.name)


# ---- Zone Editor (structured) ----
class ZoneCreateBody(BaseModel):
    domain: str
    ip: str = ""
    mode: str = "default"


class ZoneRecordBody(BaseModel):
    domain: str
    record: dict = {}
    index: int = -1
    fingerprint: dict | None = None


class ZoneDomainBody(BaseModel):
    domain: str


def _zone_call(fn, *a):
    try:
        return fn(*a)
    except dnszones.ZoneError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/dns/zones")
def api_dns_zones(user: str = auth.CurrentUser):
    names = []
    try:
        for s in sites.list_sites().get("sites", []):
            names += [s["server_name"], *s["aliases"]]
    except Exception:
        pass
    return dnszones.list_zones(names)


@app.get("/api/dns/zone")
def api_dns_zone(domain: str, user: str = auth.CurrentUser):
    return _zone_call(dnszones.get_zone, domain)


@app.post("/api/dns/zone/create")
def api_dns_zone_create(body: ZoneCreateBody, user: str = auth.CurrentUser):
    return _zone_call(dnszones.create_zone, body.domain, body.ip, body.mode)


@app.post("/api/dns/zone/delete")
def api_dns_zone_delete(body: ZoneDomainBody, user: str = auth.CurrentUser):
    return _zone_call(dnszones.delete_zone, body.domain)


@app.post("/api/dns/record/add")
def api_dns_record_add(body: ZoneRecordBody, user: str = auth.CurrentUser):
    return _zone_call(dnszones.add_record, body.domain, body.record)


@app.post("/api/dns/record/update")
def api_dns_record_update(body: ZoneRecordBody, user: str = auth.CurrentUser):
    return _zone_call(dnszones.update_record, body.domain, body.index, body.record, body.fingerprint)


@app.post("/api/dns/record/delete")
def api_dns_record_delete(body: ZoneRecordBody, user: str = auth.CurrentUser):
    return _zone_call(dnszones.delete_record, body.domain, body.index, body.fingerprint)


@app.get("/api/domains/vhosts")
def api_vhosts(user: str = auth.CurrentUser):
    try:
        return domains.list_vhosts()
    except domains.DomainError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/domains/vhosts/create")
def api_vhost_create(body: VhostBody, user: str = auth.CurrentUser):
    try:
        return domains.create_vhost(body.server_name, body.docroot, body.port)
    except domains.DomainError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/domains/vhosts/remove")
def api_vhost_remove(body: DomainNameBody, user: str = auth.CurrentUser):
    try:
        return domains.remove_vhost(body.server_name)
    except domains.DomainError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/domains/info")
def api_domain_info(name: str, user: str = auth.CurrentUser):
    try:
        return domains.domain_info(name)
    except domains.DomainError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/domains/dyndns")
def api_dyndns(user: str = auth.CurrentUser):
    return domains.dyndns_status()


@app.post("/api/domains/dyndns/run")
def api_dyndns_run(user: str = auth.CurrentUser):
    try:
        return domains.dyndns_run()
    except domains.DomainError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/domains/dyndns/install")
def api_dyndns_install(user: str = auth.CurrentUser):
    return {"job": domains.dyndns_install().id}


@app.get("/api/domains/zones")
def api_zones(user: str = auth.CurrentUser):
    return domains.zones()


class SecondariesBody(BaseModel):
    auto: bool = True
    extra: list[str] = []


@app.get("/api/dns/secondaries")
def api_dns_secondaries(user: str = auth.CurrentUser):
    return dnszones.secondary_settings()


@app.post("/api/dns/secondaries")
def api_dns_secondaries_set(body: SecondariesBody, user: str = auth.CurrentUser):
    try:
        return dnszones.set_secondaries(body.auto, body.extra)
    except dnszones.ZoneError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/domains/zone")
def api_zone(name: str, user: str = auth.CurrentUser):
    try:
        return domains.zone_content(name)
    except domains.DomainError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/domains/bind/install")
def api_bind_install(user: str = auth.CurrentUser):
    return {"job": domains.bind_install().id}


# --------------------------------------------------------------------------- #
# Databases
# --------------------------------------------------------------------------- #
class DBNameBody(BaseModel):
    name: str


class DBUserBody(BaseModel):
    user: str
    host: str = "localhost"
    password: str


class DBWizardBody(BaseModel):
    db: str
    user: str
    password: str
    host: str = "localhost"


class PGWizardBody(BaseModel):
    db: str
    role: str
    password: str


class PkgBody(BaseModel):
    pkg: str


@app.get("/api/db/overview")
def api_db_overview(user: str = auth.CurrentUser):
    return databases.overview()


@app.get("/api/db/mysql")
def api_db_mysql(user: str = auth.CurrentUser):
    st = databases.mysql_status()
    if not (st["installed"] and st["running"]):
        return {**st, "databases": [], "users": [], "phpmyadmin": databases.phpmyadmin_status()}
    try:
        return {**st, **databases.mysql_overview(), "phpmyadmin": databases.phpmyadmin_status()}
    except databases.DatabaseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/db/mysql/create")
def api_db_mysql_create(body: DBNameBody, user: str = auth.CurrentUser):
    try:
        return databases.mysql_create_db(body.name)
    except databases.DatabaseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/db/mysql/drop")
def api_db_mysql_drop(body: DBNameBody, user: str = auth.CurrentUser):
    try:
        return databases.mysql_drop_db(body.name)
    except databases.DatabaseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/db/mysql/wizard")
def api_db_mysql_wizard(body: DBWizardBody, user: str = auth.CurrentUser):
    try:
        return databases.mysql_wizard(body.db, body.user, body.password, body.host)
    except databases.DatabaseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _db_call(fn):
    try:
        return fn()
    except databases.DatabaseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class MyUserBody(BaseModel):
    user: str
    host: str = "localhost"
    password: str = ""
    db: str = ""
    admin: bool = False


class MyGrantBody(BaseModel):
    db: str
    user: str
    host: str = "localhost"
    on: bool = True


@app.post("/api/db/mysql/user/create")
def api_db_mysql_user_create(body: MyUserBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.mysql_create_user(body.user, body.host, body.password, body.db, body.admin))


@app.post("/api/db/mysql/user/password")
def api_db_mysql_user_password(body: MyUserBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.mysql_set_password(body.user, body.host, body.password))


@app.post("/api/db/mysql/user/admin")
def api_db_mysql_user_admin(body: MyUserBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.mysql_set_admin(body.user, body.host, body.admin))


@app.post("/api/db/mysql/user/drop")
def api_db_mysql_user_drop(body: MyUserBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.mysql_drop_user(body.user, body.host))


@app.post("/api/db/mysql/grant")
def api_db_mysql_grant(body: MyGrantBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.mysql_grant(body.db, body.user, body.host, body.on))


@app.post("/api/db/phpmyadmin/install")
def api_db_phpmyadmin_install(user: str = auth.CurrentUser):
    return _db_call(lambda: {"job": databases.phpmyadmin_install().id})


class PGCreateBody(BaseModel):
    name: str
    owner: str = ""


class PGRoleBody(BaseModel):
    name: str
    password: str = ""
    login: bool = True
    createdb: bool = False
    createrole: bool = False
    superuser: bool = False
    conn_limit: int = -1


class PGGrantBody(BaseModel):
    db: str
    role: str
    grant: bool = True


class PGOwnerBody(BaseModel):
    db: str
    role: str


class OnBody(BaseModel):
    on: bool


@app.get("/api/db/pg")
def api_db_pg(user: str = auth.CurrentUser):
    st = databases.pg_status()
    pga = databases.phppgadmin_status()
    if not (st["installed"] and st["running"]):
        return {**st, "databases": [], "roles": [], "phppgadmin": pga}
    return _db_call(lambda: {**st, **databases.pg_overview(), "phppgadmin": pga})


@app.post("/api/db/pg/role/create")
def api_db_pg_role_create(body: PGRoleBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.pg_create_role(body.name, body.password, body.login, body.createdb,
                                                      body.createrole, body.superuser))


@app.post("/api/db/pg/role/update")
def api_db_pg_role_update(body: PGRoleBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.pg_update_role(body.name, body.login, body.createdb, body.createrole,
                                                      body.superuser, body.conn_limit))


@app.post("/api/db/pg/role/password")
def api_db_pg_role_password(body: PGRoleBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.pg_set_password(body.name, body.password))


@app.post("/api/db/pg/role/drop")
def api_db_pg_role_drop(body: DBNameBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.pg_drop_role(body.name))


@app.post("/api/db/pg/grant")
def api_db_pg_grant(body: PGGrantBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.pg_grant(body.db, body.role, body.grant))


@app.post("/api/db/pg/owner")
def api_db_pg_owner(body: PGOwnerBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.pg_set_owner(body.db, body.role))


@app.post("/api/db/phppgadmin/lan")
def api_db_phppgadmin_lan(body: OnBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.phppgadmin_set_lan(body.on))


@app.post("/api/db/phppgadmin/install")
def api_db_phppgadmin_install(user: str = auth.CurrentUser):
    return _db_call(lambda: {"job": databases.phppgadmin_install().id})


@app.post("/api/db/pg/repair")
def api_db_pg_repair(user: str = auth.CurrentUser):
    try:
        return databases.pg_repair()
    except databases.DatabaseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/db/pg/create")
def api_db_pg_create(body: PGCreateBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.pg_create_db_owned(body.name, body.owner))


@app.post("/api/db/pg/drop")
def api_db_pg_drop(body: DBNameBody, user: str = auth.CurrentUser):
    return _db_call(lambda: databases.pg_drop_db_force(body.name))


@app.post("/api/db/pg/wizard")
def api_db_pg_wizard(body: PGWizardBody, user: str = auth.CurrentUser):
    try:
        return databases.pg_wizard(body.db, body.role, body.password)
    except databases.DatabaseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/db/install")
def api_db_install(body: PkgBody, user: str = auth.CurrentUser):
    try:
        return {"job": databases.install_pkg(body.pkg).id}
    except databases.DatabaseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Software: Application Manager
# --------------------------------------------------------------------------- #
class AppCreateBody(BaseModel):
    name: str
    workdir: str
    command: str
    autostart: bool = True


class AppActionBody(BaseModel):
    name: str
    action: str


@app.get("/api/apps")
def api_apps(user: str = auth.CurrentUser):
    return appmanager.list_apps()


@app.post("/api/apps/create")
def api_apps_create(body: AppCreateBody, user: str = auth.CurrentUser):
    try:
        return appmanager.create_app(body.name, body.workdir, body.command, body.autostart)
    except appmanager.AppError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/apps/control")
def api_apps_control(body: AppActionBody, user: str = auth.CurrentUser):
    try:
        return appmanager.control_app(body.name, body.action)
    except appmanager.AppError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/apps/remove")
def api_apps_remove(body: NameBody, user: str = auth.CurrentUser):
    try:
        return appmanager.remove_app(body.name)
    except appmanager.AppError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/apps/logs")
def api_apps_logs(name: str, user: str = auth.CurrentUser):
    try:
        return appmanager.logs(name)
    except appmanager.AppError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# --------------------------------------------------------------------------- #
# Software: Select PHP Version
# --------------------------------------------------------------------------- #
class PHPBody(BaseModel):
    version: str


@app.get("/api/php")
def api_php(user: str = auth.CurrentUser):
    return phpmgr.status()


@app.post("/api/php/set")
def api_php_set(body: PHPBody, user: str = auth.CurrentUser):
    try:
        return phpmgr.set_cli_version(body.version)
    except phpmgr.PHPError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _php_call(fn):
    try:
        return fn()
    except (phpsettings.PHPSettingsError, phpmgr.PHPError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class PHPSettingsBody(BaseModel):
    version: str
    sapis: list[str]
    changes: dict = {}
    reset: list[str] = []


class PHPExtBody(BaseModel):
    version: str
    module: str
    sapi: str | None = None
    on: bool = True


@app.get("/api/php/settings/overview")
def api_php_overview(user: str = auth.CurrentUser):
    return _php_call(phpsettings.overview)


@app.get("/api/php/settings")
def api_php_settings(version: str, sapi: str, user: str = auth.CurrentUser):
    return _php_call(lambda: phpsettings.get(version, sapi))


@app.post("/api/php/settings")
def api_php_settings_save(body: PHPSettingsBody, user: str = auth.CurrentUser):
    return _php_call(lambda: phpsettings.save(body.version, body.sapis, body.changes, body.reset))


@app.get("/api/php/extensions")
def api_php_extensions(version: str, user: str = auth.CurrentUser):
    return _php_call(lambda: phpsettings.extensions(version))


@app.post("/api/php/extensions/toggle")
def api_php_ext_toggle(body: PHPExtBody, user: str = auth.CurrentUser):
    return _php_call(lambda: phpsettings.set_extension(body.version, body.module, body.sapi or "", body.on))


@app.post("/api/php/extensions/install")
def api_php_ext_install(body: PHPExtBody, user: str = auth.CurrentUser):
    return _php_call(lambda: {"job": phpsettings.install_extension(body.version, body.module).id})


@app.post("/api/php/apache-version")
def api_php_apache_version(body: PHPBody, user: str = auth.CurrentUser):
    return _php_call(lambda: phpsettings.set_apache_version(body.version))


# --------------------------------------------------------------------------- #
# Email
# --------------------------------------------------------------------------- #
def _mail(fn, *a, **k):
    try:
        return fn(*a, **k)
    except mail.MailError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class MailDomainBody(BaseModel):
    domain: str
    routing: str | None = None
    mode: str | None = None
    target: str = ""
    message: str = ""


class MailAccountBody(BaseModel):
    address: str
    password: str | None = None
    quota_mb: int | None = None
    name: str | None = None
    suspend: dict | None = None
    delete_mail: bool = False


class MailForwarderBody(BaseModel):
    source: str
    kind: str = "forward"
    dest: str = ""
    message: str = ""


class MailOwnerBody(BaseModel):
    owner: str
    data: dict = {}
    filters: list = []


class MailListBody(BaseModel):
    address: str
    data: dict = {}
    create: bool = False


class MailQueueBody(BaseModel):
    action: str
    ids: list[str] = []


class MailImportBody(BaseModel):
    kind: str
    text: str
    dry_run: bool = True
    default_domain: str = ""
    quota_mb: int = 1024


class MailExpungeBody(BaseModel):
    address: str
    mailbox: str
    older_days: int = 0


class MailValueBody(BaseModel):
    value: str = ""
    to: str = ""
    sender: str = ""


@app.get("/api/mail/status")
def api_mail_status(user: str = auth.CurrentUser):
    ok, why = mail.dovecot_ok() if mail.IS_LINUX else (True, "")
    return {**mail.status(), "dovecot_supported": ok, "dovecot_why": why}


@app.get("/api/mail/domains")
def api_mail_domains(user: str = auth.CurrentUser):
    s = mail.load()
    return {"domains": [{"domain": d, "routing": v.get("routing", "local"), "catchall": v.get("catchall", {}),
                         "forward_to": s["domain_forwarders"].get(d),
                         "accounts": sum(1 for a in s["accounts"] if a.endswith("@" + d))} for d, v in sorted(s["domains"].items())],
            "candidates": mail.candidate_domains(), "hostname": mail.hostname(s)}


@app.post("/api/mail/domains/add")
def api_mail_domain_add(body: MailDomainBody, user: str = auth.CurrentUser):
    return _mail(mail.add_domain, body.domain)


@app.post("/api/mail/domains/remove")
def api_mail_domain_remove(body: MailDomainBody, user: str = auth.CurrentUser):
    return _mail(mail.remove_domain, body.domain)


@app.post("/api/mail/domains/routing")
def api_mail_routing(body: MailDomainBody, user: str = auth.CurrentUser):
    return _mail(mail.set_routing, body.domain, body.routing or "local")


@app.get("/api/mail/domains/routing")
def api_mail_routing_get(domain: str, user: str = auth.CurrentUser):
    def get():
        d = mail._domain(domain)
        dom = mail.load()["domains"].get(d, {"routing": "local"})
        return {"domain": d, "routing": dom.get("routing", "local"), "effective": mail._effective_routing(d, dom),
                "mx": mail._mx(d), "hostname": mail.hostname()}
    return _mail(get)


@app.post("/api/mail/domains/catchall")
def api_mail_catchall(body: MailDomainBody, user: str = auth.CurrentUser):
    return _mail(mail.set_catchall, body.domain, body.mode or "fail", body.target, body.message)


@app.get("/api/mail/accounts")
def api_mail_accounts(user: str = auth.CurrentUser):
    return mail.list_accounts()


@app.post("/api/mail/accounts/create")
def api_mail_account_create(body: MailAccountBody, user: str = auth.CurrentUser):
    return _mail(mail.create_account, body.address, body.password or "", body.quota_mb if body.quota_mb is not None else 1024, body.name or "")


@app.post("/api/mail/accounts/update")
def api_mail_account_update(body: MailAccountBody, user: str = auth.CurrentUser):
    return _mail(mail.update_account, body.address, body.password, body.quota_mb, body.suspend, body.name)


@app.post("/api/mail/accounts/delete")
def api_mail_account_delete(body: MailAccountBody, user: str = auth.CurrentUser):
    return _mail(mail.delete_account, body.address, body.delete_mail)


@app.get("/api/mail/accounts/device")
def api_mail_device(address: str, user: str = auth.CurrentUser):
    return _mail(mail.device_settings, address)


@app.get("/api/mail/accounts/mobileconfig")
def api_mail_mobileconfig(address: str, user: str = auth.CurrentUser):
    text = _mail(mail.mobileconfig, address)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", address)
    return Response(text, media_type="application/x-apple-aspen-config",
                    headers={"Content-Disposition": f'attachment; filename="{name}.mobileconfig"'})


@app.get("/api/mail/password")
def api_mail_password(user: str = auth.CurrentUser):
    return {"password": mail.gen_password()}


@app.get("/api/mail/forwarders")
def api_mail_forwarders(user: str = auth.CurrentUser):
    return mail.list_forwarders()


@app.post("/api/mail/forwarders/add")
def api_mail_forwarder_add(body: MailForwarderBody, user: str = auth.CurrentUser):
    return _mail(mail.add_forwarder, body.source, body.kind, body.dest, body.message)


@app.post("/api/mail/forwarders/delete")
def api_mail_forwarder_delete(body: MailForwarderBody, user: str = auth.CurrentUser):
    return _mail(mail.delete_forwarder, body.source, body.dest or None)


@app.post("/api/mail/forwarders/domain")
def api_mail_domain_forwarder(body: MailForwarderBody, user: str = auth.CurrentUser):
    if body.kind == "delete":
        return _mail(mail.delete_domain_forwarder, body.source)
    return _mail(mail.add_domain_forwarder, body.source, body.dest)


@app.get("/api/mail/trace")
def api_mail_trace(address: str, user: str = auth.CurrentUser):
    return _mail(mail.trace, address)


@app.get("/api/mail/autoresponders")
def api_mail_autoresponders(user: str = auth.CurrentUser):
    return mail.list_autoresponders()


@app.post("/api/mail/autoresponders/save")
def api_mail_autoresponder_save(body: MailOwnerBody, user: str = auth.CurrentUser):
    return _mail(mail.set_autoresponder, body.owner, body.data)


@app.post("/api/mail/autoresponders/delete")
def api_mail_autoresponder_delete(body: MailOwnerBody, user: str = auth.CurrentUser):
    return _mail(mail.delete_autoresponder, body.owner)


@app.get("/api/mail/filters")
def api_mail_filters(owner: str = "global", user: str = auth.CurrentUser):
    return _mail(mail.get_filters, owner)


@app.post("/api/mail/filters")
def api_mail_filters_save(body: MailOwnerBody, user: str = auth.CurrentUser):
    return _mail(mail.save_filters, body.owner, body.filters)


@app.get("/api/mail/spam")
def api_mail_spam(owner: str = "global", user: str = auth.CurrentUser):
    return _mail(mail.get_spam, owner)


@app.post("/api/mail/spam")
def api_mail_spam_save(body: MailOwnerBody, user: str = auth.CurrentUser):
    return _mail(mail.set_spam, body.owner, body.data)


@app.get("/api/mail/lists")
def api_mail_lists(user: str = auth.CurrentUser):
    return mail.list_lists()


@app.post("/api/mail/lists/save")
def api_mail_list_save(body: MailListBody, user: str = auth.CurrentUser):
    return _mail(mail.save_list, body.address, body.data, body.create)


@app.post("/api/mail/lists/delete")
def api_mail_list_delete(body: MailListBody, user: str = auth.CurrentUser):
    return _mail(mail.delete_list, body.address)


@app.get("/api/mail/track")
def api_mail_track(q: str = "", status: str = "", hours: int = 168, user: str = auth.CurrentUser):
    return _mail(mail.track, q, status, hours)


@app.get("/api/mail/queue")
def api_mail_queue(user: str = auth.CurrentUser):
    return mail.queue()


@app.post("/api/mail/queue")
def api_mail_queue_action(body: MailQueueBody, user: str = auth.CurrentUser):
    return _mail(mail.queue_action, body.action, body.ids)


@app.get("/api/mail/deliverability")
def api_mail_deliverability(domain: str = "", user: str = auth.CurrentUser):
    return _mail(mail.deliverability, domain) if domain else _mail(mail.deliverability_all)


@app.post("/api/mail/deliverability/install")
def api_mail_deliverability_install(body: MailDomainBody, user: str = auth.CurrentUser):
    try:
        return _mail(mail.install_record, body.domain, body.mode or "")
    except Exception as exc:  # zone errors come from dnszones
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/mail/disk")
def api_mail_disk(address: str = "", user: str = auth.CurrentUser):
    return _mail(mail.disk_usage, address) if address else mail.disk_overview()


@app.post("/api/mail/disk/expunge")
def api_mail_expunge(body: MailExpungeBody, user: str = auth.CurrentUser):
    return _mail(mail.expunge, body.address, body.mailbox, body.older_days)


@app.post("/api/mail/import")
def api_mail_import(body: MailImportBody, user: str = auth.CurrentUser):
    return _mail(mail.import_csv, body.kind, body.text, body.dry_run, body.default_domain, body.quota_mb)


@app.get("/api/mail/export")
def api_mail_export(kind: str = "accounts", user: str = auth.CurrentUser):
    return Response(mail.export_csv("forwarders" if kind == "forwarders" else "accounts"), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="email-{kind}.csv"'})


@app.get("/api/mail/tls")
def api_mail_tls(user: str = auth.CurrentUser):
    return mail.get_tls()


@app.post("/api/mail/tls")
def api_mail_tls_set(body: MailValueBody, user: str = auth.CurrentUser):
    return _mail(mail.set_tls, body.value or "self")


@app.post("/api/mail/tls/issue")
def api_mail_tls_issue(user: str = auth.CurrentUser):
    return {"job": _mail(mail.issue_cert).id}


@app.post("/api/mail/hostname")
def api_mail_hostname(body: MailValueBody, user: str = auth.CurrentUser):
    return _mail(mail.set_hostname, body.value)


class DavBody(BaseModel):
    owner: str
    id: str = ""
    kind: str = "calendar"
    name: str = ""
    color: str = ""
    description: str = ""
    with_: str = ""
    write: bool = False


@app.get("/api/mail/dav")
def api_mail_dav(user: str = auth.CurrentUser):
    return mail.list_collections()


@app.post("/api/mail/dav/create")
def api_mail_dav_create(body: DavBody, user: str = auth.CurrentUser):
    return _mail(mail.create_collection, body.owner, body.kind, body.name, body.color, body.description)


@app.post("/api/mail/dav/update")
def api_mail_dav_update(body: DavBody, user: str = auth.CurrentUser):
    return _mail(mail.update_collection, body.owner, body.id, body.name, body.color, body.description)


@app.post("/api/mail/dav/delete")
def api_mail_dav_delete(body: DavBody, user: str = auth.CurrentUser):
    return _mail(mail.delete_collection, body.owner, body.id)


@app.post("/api/mail/dav/share")
def api_mail_dav_share(body: DavBody, user: str = auth.CurrentUser):
    return _mail(mail.share_collection, body.owner, body.id, body.with_, body.write)


@app.post("/api/mail/dav/unshare")
def api_mail_dav_unshare(body: DavBody, user: str = auth.CurrentUser):
    return _mail(mail.unshare_collection, body.owner, body.id, body.with_)


class MailLocalBody(BaseModel):
    enabled: bool = True


@app.post("/api/mail/local")
def api_mail_local(body: MailLocalBody, user: str = auth.CurrentUser):
    return _mail(mail.enable_local, body.enabled)


class TrackSettingsBody(BaseModel):
    days: int | None = None
    clear: bool = False


@app.post("/api/mail/track/settings")
def api_mail_track_settings(body: TrackSettingsBody, user: str = auth.CurrentUser):
    return _mail(mail.set_track_settings, body.days, body.clear)


class AbuseBody(BaseModel):
    ip: str
    sender: str = ""
    to: str = ""
    note: str = ""
    force: bool = False


def _abuse(fn, *a):
    try:
        return fn(*a)
    except (abuse.AbuseError, mail.MailError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/abuse/preview")
def api_abuse_preview(ip: str, user: str = auth.CurrentUser):
    return _abuse(abuse.preview, ip)


@app.get("/api/abuse/reported")
def api_abuse_reported(user: str = auth.CurrentUser):
    return abuse.reported()


@app.post("/api/abuse/report")
def api_abuse_report(body: AbuseBody, user: str = auth.CurrentUser):
    return _abuse(abuse.report, body.ip, body.sender, body.to, body.note, body.force)


@app.post("/api/mail/test")
def api_mail_test(body: MailValueBody, user: str = auth.CurrentUser):
    return _mail(mail.send_test, body.to, body.sender)


# --------------------------------------------------------------------------- #
# Requirements: software a page needs, with a one-click install
# --------------------------------------------------------------------------- #
class RequireBody(BaseModel):
    id: str


@app.get("/api/requires")
def api_requires(ids: str = "", user: str = auth.CurrentUser):
    return requires.status([i for i in ids.split(",") if i])


@app.post("/api/requires/install")
def api_requires_install(body: RequireBody, user: str = auth.CurrentUser):
    try:
        return {"job": requires.install(body.id).id}
    except requires.RequiresError as e:
        raise HTTPException(status_code=400, detail=str(e))


# --------------------------------------------------------------------------- #
# Software: System Applications (web servers, PHP-FPM, MariaDB, FTP)
# --------------------------------------------------------------------------- #
class SysAppBody(BaseModel):
    id: str
    action: str | None = None
    switch: bool = False


def _sysapp_call(fn):
    try:
        return fn()
    except sysapps.ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except sysapps.SysAppError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/sysapps")
def api_sysapps(user: str = auth.CurrentUser):
    return sysapps.status()


@app.post("/api/sysapps/install")
def api_sysapps_install(body: SysAppBody, user: str = auth.CurrentUser):
    return _sysapp_call(lambda: {"job": sysapps.install(body.id, body.switch).id})


@app.post("/api/sysapps/uninstall")
def api_sysapps_uninstall(body: SysAppBody, user: str = auth.CurrentUser):
    return _sysapp_call(lambda: {"job": sysapps.uninstall(body.id).id})


@app.post("/api/sysapps/control")
def api_sysapps_control(body: SysAppBody, user: str = auth.CurrentUser):
    return _sysapp_call(lambda: sysapps.control(body.id, body.action or "", body.switch))


# --------------------------------------------------------------------------- #
# Network: VPN servers, Dynamic DNS, Port Checker
# --------------------------------------------------------------------------- #
def _vpn_call(fn):
    try:
        return fn()
    except (vpncommon.VPNError, ddns.DDNSError, portcheck.PortError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class VPNSettingsBody(BaseModel):
    endpoint: str | None = None
    dns: str | None = None


class VPNSetupBody(BaseModel):
    port: int | None = None
    proto: str | None = None
    subnet: str | None = None
    redirect: bool = True


class VPNActionBody(BaseModel):
    action: str


class VPNClientBody(BaseModel):
    name: str
    tunnel: str | None = None
    password: str | None = None
    disabled: bool | None = None
    mode: str | None = None


class DDNSBody(BaseModel):
    provider: str
    fields: dict
    enabled: bool = True


class PortBody(BaseModel):
    port: int
    proto: str = "tcp"


_VPNS = {"wireguard": wireguard, "openvpn": openvpn, "ipsec": ipsec}


def _vpn(kind: str):
    if kind not in _VPNS:
        raise HTTPException(status_code=404, detail="Unknown VPN type")
    return _VPNS[kind]


@app.get("/api/vpn/overview")
def api_vpn_overview(user: str = auth.CurrentUser):
    out = {"settings": _vpn_call(vpncommon.settings)}
    for k, mod in _VPNS.items():
        try:
            out[k] = mod.status()
        except Exception as exc:  # one broken VPN must not hide the others
            out[k] = {"error": str(exc)}
    return out


@app.post("/api/vpn/settings")
def api_vpn_settings(body: VPNSettingsBody, user: str = auth.CurrentUser):
    return _vpn_call(lambda: vpncommon.save_settings(body.endpoint, body.dns))


@app.get("/api/vpn/{kind}")
def api_vpn_status(kind: str, user: str = auth.CurrentUser):
    return _vpn_call(_vpn(kind).status)


@app.post("/api/vpn/{kind}/install")
def api_vpn_install(kind: str, user: str = auth.CurrentUser):
    return _vpn_call(lambda: {"job": _vpn(kind).install().id})


@app.post("/api/vpn/{kind}/setup")
def api_vpn_setup(kind: str, body: VPNSetupBody, user: str = auth.CurrentUser):
    def go():
        if kind == "wireguard":
            return wireguard.setup(body.port or 51820, body.subnet or "10.8.0.0/24")
        if kind == "openvpn":
            return {"job": openvpn.setup(body.port or 1194, body.proto or "udp", body.subnet or "10.9.0.0/24",
                                         body.redirect).id}
        return {"job": ipsec.setup(body.subnet or "10.10.0.0/24").id}
    _vpn(kind)
    return _vpn_call(go)


@app.post("/api/vpn/{kind}/control")
def api_vpn_control(kind: str, body: VPNActionBody, user: str = auth.CurrentUser):
    return _vpn_call(lambda: _vpn(kind).control(body.action))


@app.post("/api/vpn/{kind}/selftest")
def api_vpn_selftest(kind: str, user: str = auth.CurrentUser):
    if kind not in ("wireguard", "openvpn"):
        raise HTTPException(status_code=400, detail="Self-test is available for WireGuard and OpenVPN")
    return _vpn_call(lambda: {"job": _vpn(kind).selftest().id})


@app.post("/api/vpn/{kind}/clients")
def api_vpn_client_add(kind: str, body: VPNClientBody, user: str = auth.CurrentUser):
    def go():
        if kind == "wireguard":
            return wireguard.add_peer(body.name, body.tunnel or "full")
        if kind == "openvpn":
            return openvpn.add_user(body.name, body.mode or "cert+password", body.password)
        return ipsec.add_user(body.name, body.password)
    _vpn(kind)
    return _vpn_call(go)


@app.post("/api/vpn/{kind}/clients/remove")
def api_vpn_client_remove(kind: str, body: VPNClientBody, user: str = auth.CurrentUser):
    fn = {"wireguard": wireguard.remove_peer, "openvpn": openvpn.revoke_client, "ipsec": ipsec.remove_user}
    _vpn(kind)
    return _vpn_call(lambda: fn[kind](body.name))


@app.post("/api/vpn/openvpn/users/password")
def api_ovpn_user_password(body: VPNClientBody, user: str = auth.CurrentUser):
    return _vpn_call(lambda: openvpn.set_password(body.name, body.password))


@app.post("/api/vpn/openvpn/users/mode")
def api_ovpn_user_mode(body: VPNClientBody, user: str = auth.CurrentUser):
    return _vpn_call(lambda: openvpn.set_mode(body.name, body.mode or "", body.password))


@app.post("/api/vpn/openvpn/users/toggle")
def api_ovpn_user_toggle(body: VPNClientBody, user: str = auth.CurrentUser):
    return _vpn_call(lambda: openvpn.set_disabled(body.name, bool(body.disabled)))


@app.post("/api/vpn/wireguard/clients/toggle")
def api_wg_client_toggle(body: VPNClientBody, user: str = auth.CurrentUser):
    return _vpn_call(lambda: wireguard.set_peer_disabled(body.name, bool(body.disabled)))


@app.get("/api/vpn/{kind}/clients/{name}/config")
def api_vpn_client_config(kind: str, name: str, user: str = auth.CurrentUser):
    fn = {"wireguard": wireguard.client_config, "openvpn": openvpn.client_config, "ipsec": ipsec.client_profiles}
    _vpn(kind)
    return _vpn_call(lambda: fn[kind](name))


@app.get("/api/ddns")
def api_ddns(user: str = auth.CurrentUser):
    return _vpn_call(ddns.status)


@app.post("/api/ddns")
def api_ddns_configure(body: DDNSBody, user: str = auth.CurrentUser):
    return _vpn_call(lambda: ddns.configure(body.provider, body.fields, body.enabled))


@app.post("/api/ddns/update")
def api_ddns_update(user: str = auth.CurrentUser):
    return _vpn_call(lambda: ddns.update(force=True))


@app.post("/api/ddns/disable")
def api_ddns_disable(user: str = auth.CurrentUser):
    return _vpn_call(ddns.disable)


@app.post("/api/ddns/stop-ddclient")
def api_ddns_stop_ddclient(user: str = auth.CurrentUser):
    return _vpn_call(ddns.stop_ddclient)


@app.post("/api/portcheck")
def api_portcheck(body: PortBody, user: str = auth.CurrentUser):
    return _vpn_call(lambda: portcheck.check(body.port, body.proto))


@app.post("/api/portcheck/upnp/open")
def api_portcheck_upnp_open(body: PortBody, user: str = auth.CurrentUser):
    return _vpn_call(lambda: portcheck.upnp_open(body.port, body.proto))


@app.post("/api/portcheck/upnp/close")
def api_portcheck_upnp_close(body: PortBody, user: str = auth.CurrentUser):
    return _vpn_call(lambda: portcheck.upnp_close(body.port, body.proto))


class NetmonLoggingBody(BaseModel):
    on: bool


@app.get("/api/netmon")
def api_netmon(hours: int = 24, scope: str = "all", user: str = auth.CurrentUser):
    if scope not in ("all", "internet", "lan", "private"):
        raise HTTPException(status_code=400, detail="Invalid scope")
    return _vpn_call(lambda: netmon.summary(hours, scope))


@app.post("/api/netmon/logging")
def api_netmon_logging(body: NetmonLoggingBody, user: str = auth.CurrentUser):
    return _vpn_call(lambda: netmon.set_logging(body.on))


@app.post("/api/portcheck/upnp/install")
def api_portcheck_upnp_install(user: str = auth.CurrentUser):
    return _vpn_call(lambda: {"job": portcheck.install_upnp().id})


# --------------------------------------------------------------------------- #
# Bans & trusted addresses (guard) + fail2ban settings
# --------------------------------------------------------------------------- #
def _guard_call(fn):
    try:
        return fn()
    except (guard.GuardError, fail2ban.Fail2banError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class GuardBody(BaseModel):
    target: str
    reason: str | None = None
    duration: int | None = None
    source: str | None = None


class F2BBody(BaseModel):
    jail: str | None = None
    ip: str | None = None
    on: bool | None = None


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@app.get("/api/guard")
def api_guard(user: str = auth.CurrentUser):
    return _guard_call(guard.listing)


@app.post("/api/guard/ban")
def api_guard_ban(body: GuardBody, request: Request, user: str = auth.CurrentUser):
    return _guard_call(lambda: guard.ban(body.target, body.reason or "", body.duration, _client_ip(request), body.source or ""))


@app.post("/api/guard/unban")
def api_guard_unban(body: GuardBody, user: str = auth.CurrentUser):
    return _guard_call(lambda: guard.unban(body.target))


@app.post("/api/guard/trust")
def api_guard_trust(body: GuardBody, user: str = auth.CurrentUser):
    return _guard_call(lambda: guard.trust(body.target, body.reason or ""))


@app.post("/api/guard/untrust")
def api_guard_untrust(body: GuardBody, user: str = auth.CurrentUser):
    return _guard_call(lambda: guard.untrust(body.target))


@app.post("/api/fail2ban/save")
async def api_fail2ban_save(request: Request, user: str = auth.CurrentUser):
    body = await request.json()
    return _guard_call(lambda: fail2ban.save(body.get("global"), body.get("jails")))


@app.post("/api/fail2ban/service")
def api_fail2ban_service(body: F2BBody, user: str = auth.CurrentUser):
    return _guard_call(lambda: fail2ban.enable_service(bool(body.on)))


@app.post("/api/fail2ban/ban")
def api_fail2ban_ban(body: F2BBody, request: Request, user: str = auth.CurrentUser):
    return _guard_call(lambda: fail2ban.ban(body.jail or "", body.ip or "", _client_ip(request)))


@app.get("/api/fail2ban/logs")
def api_fail2ban_logs(lines: int = 200, user: str = auth.CurrentUser):
    return {"text": fail2ban.logs(max(20, min(lines, 2000)))}


@app.get("/api/fail2ban/events")
def api_fail2ban_events(limit: int = 400, user: str = auth.CurrentUser):
    """Recent failed attempts, bans and unbans from fail2ban's log."""
    return fail2ban.events(max(20, min(limit, 2000)))


# --------------------------------------------------------------------------- #
# Files section: Images, Web Disk, Directory Privacy, Git, Backup Wizard, Inodes
# --------------------------------------------------------------------------- #
def _files_call(fn):
    try:
        return fn()
    except (images.ImageError, webaccess.WebAccessError, gitvc.GitError, backups.BackupError,
            diskusage.DiskUsageError, files.FileError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class ImageOpBody(BaseModel):
    path: str
    width: int | None = None
    height: int | None = None
    percent: int | None = None
    max_px: int | None = None
    keep_aspect: bool = True
    keep_original: bool = True
    quality: int = 85
    to: str | None = None
    recursive: bool = False
    delete_original: bool = False


class WebAccessBody(BaseModel):
    name: str | None = None
    path: str | None = None
    password: str | None = None
    readonly: bool | None = None
    disabled: bool | None = None
    label: str | None = None
    remove: bool = False
    enabled: bool | None = None


class GitBody(BaseModel):
    name: str
    path: str | None = None
    owner: str | None = None
    clone_url: str | None = None
    branch: str | None = None
    use_key: bool = False
    deploy_path: str | None = None
    deploy_cmd: str | None = None
    delete_files: bool = False


class WizardBody(BaseModel):
    kind: str = "custom"
    name: str | None = None
    paths: list[str] = []
    mysql: list[str] = []
    pgsql: list[str] = []
    label: str = ""
    dest: str | None = None
    rename: dict[str, str] = {}
    wipe: bool = True


@app.get("/api/images/info")
def api_images_info(path: str = "", user: str = auth.CurrentUser):
    return _files_call(lambda: {"available": images.available(), **(images.info(path) if images.available() else {})})


@app.post("/api/images/scale")
def api_images_scale(body: ImageOpBody, user: str = auth.CurrentUser):
    return _files_call(lambda: images.scale(body.path, body.width, body.height, body.percent, body.keep_aspect, body.keep_original, body.quality))


@app.post("/api/images/thumbnails")
def api_images_thumbs(body: ImageOpBody, user: str = auth.CurrentUser):
    return _files_call(lambda: {"job": images.thumbnails(body.path, body.percent, body.max_px, body.recursive).id})


@app.post("/api/images/convert")
def api_images_convert(body: ImageOpBody, user: str = auth.CurrentUser):
    return _files_call(lambda: {"job": images.convert(body.path, body.to or "", body.quality, body.delete_original).id})


@app.get("/api/webdisk")
def api_webdisk(user: str = auth.CurrentUser):
    return webaccess.webdisk_list()


@app.post("/api/webdisk")
def api_webdisk_create(body: WebAccessBody, user: str = auth.CurrentUser):
    return _files_call(lambda: webaccess.webdisk_create(body.name or "", body.password or "", body.path or "", bool(body.readonly)))


@app.post("/api/webdisk/update")
def api_webdisk_update(body: WebAccessBody, user: str = auth.CurrentUser):
    return _files_call(lambda: webaccess.webdisk_update(body.name or "", body.path, body.readonly, body.disabled, body.password))


@app.post("/api/webdisk/delete")
def api_webdisk_delete(body: WebAccessBody, user: str = auth.CurrentUser):
    return _files_call(lambda: webaccess.webdisk_delete(body.name or ""))


class WebdiskCertBody(BaseModel):
    host: str = ""


@app.get("/api/webdisk/certificate")
def api_webdisk_certificate(host: str = "", user: str = auth.CurrentUser):
    return _files_call(lambda: webaccess.webdisk_certificate(host))


@app.post("/api/webdisk/certificate")
def api_webdisk_certificate_create(body: WebdiskCertBody, user: str = auth.CurrentUser):
    return _files_call(lambda: webaccess.webdisk_certificate_ensure(body.host))


@app.get("/api/dirprivacy")
def api_dirprivacy(user: str = auth.CurrentUser):
    return webaccess.privacy_list()


@app.post("/api/dirprivacy/protect")
def api_dirprivacy_protect(body: WebAccessBody, user: str = auth.CurrentUser):
    return _files_call(lambda: webaccess.privacy_protect(body.path or "", body.label or "", body.name or "", body.password or ""))


@app.post("/api/dirprivacy/user")
def api_dirprivacy_user(body: WebAccessBody, user: str = auth.CurrentUser):
    return _files_call(lambda: webaccess.privacy_user(body.path or "", body.name or "", body.password, body.remove))


@app.post("/api/dirprivacy/toggle")
def api_dirprivacy_toggle(body: WebAccessBody, user: str = auth.CurrentUser):
    return _files_call(lambda: webaccess.privacy_toggle(body.path or "", bool(body.enabled)))


@app.post("/api/dirprivacy/remove")
def api_dirprivacy_remove(body: WebAccessBody, user: str = auth.CurrentUser):
    return _files_call(lambda: webaccess.privacy_remove(body.path or ""))


@app.get("/api/git")
def api_git(user: str = auth.CurrentUser):
    return _files_call(gitvc.listing)


@app.get("/api/git/{name}")
def api_git_details(name: str, user: str = auth.CurrentUser):
    return _files_call(lambda: gitvc.details(name))


@app.post("/api/git/key")
def api_git_key(body: GitBody, user: str = auth.CurrentUser):
    return _files_call(lambda: gitvc.make_key(body.name, body.owner or ""))


@app.post("/api/git/create")
def api_git_create(body: GitBody, user: str = auth.CurrentUser):
    return _files_call(lambda: {"job": gitvc.create(body.name, body.path or "", body.owner or "", body.clone_url, body.branch, body.use_key).id})


@app.post("/api/git/pull")
def api_git_pull(body: GitBody, user: str = auth.CurrentUser):
    return _files_call(lambda: {"job": gitvc.pull(body.name).id})


@app.post("/api/git/checkout")
def api_git_checkout(body: GitBody, user: str = auth.CurrentUser):
    return _files_call(lambda: gitvc.checkout(body.name, body.branch or ""))


@app.post("/api/git/deploy-settings")
def api_git_deploy_settings(body: GitBody, user: str = auth.CurrentUser):
    return _files_call(lambda: gitvc.set_deploy(body.name, body.deploy_path or "", body.deploy_cmd or ""))


@app.post("/api/git/deploy")
def api_git_deploy(body: GitBody, user: str = auth.CurrentUser):
    return _files_call(lambda: {"job": gitvc.deploy(body.name).id})


@app.post("/api/git/remove")
def api_git_remove(body: GitBody, user: str = auth.CurrentUser):
    return _files_call(lambda: gitvc.remove(body.name, body.delete_files))


@app.get("/api/backups/wizard")
def api_backup_wizard(user: str = auth.CurrentUser):
    return _files_call(backups.wizard_options)


@app.post("/api/backups/wizard")
def api_backup_wizard_create(body: WizardBody, user: str = auth.CurrentUser):
    return _files_call(lambda: {"job": backups.wizard_create(body.kind, body.paths, body.mysql, body.pgsql, body.label).id})


@app.get("/api/backups/manifest")
def api_backup_manifest(name: str, user: str = auth.CurrentUser):
    return _files_call(lambda: backups.manifest(name))


@app.post("/api/backups/wizard/restore")
def api_backup_wizard_restore(body: WizardBody, user: str = auth.CurrentUser):
    return _files_call(lambda: {"job": backups.wizard_restore(body.name or "", body.paths, body.mysql, body.pgsql,
                                                              body.dest or "/", body.rename, body.wipe).id})


@app.get("/api/inodes")
def api_inodes(path: str = "/", user: str = auth.CurrentUser):
    return _files_call(lambda: diskusage.inodes(path))


# --------------------------------------------------------------------------- #
# System Applications: per-app configuration + FTP accounts
# --------------------------------------------------------------------------- #
def _cfg_call(fn):
    try:
        return fn()
    except (appconfig.AppConfigError, ftp.FTPError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class AppSettingsBody(BaseModel):
    changes: dict


class AppModuleBody(BaseModel):
    name: str
    on: bool


class AppFileBody(BaseModel):
    path: str
    content: str


class FTPAccountBody(BaseModel):
    name: str
    password: str | None = None
    folder: str | None = None
    access: str | None = None
    create_folder: bool = True
    enabled: bool | None = None


@app.get("/api/sysapps/{app_id}/config")
def api_appcfg_info(app_id: str, user: str = auth.CurrentUser):
    return _cfg_call(lambda: appconfig.info(app_id))


@app.get("/api/sysapps/{app_id}/settings")
def api_appcfg_settings(app_id: str, user: str = auth.CurrentUser):
    return _cfg_call(lambda: appconfig.settings(app_id))


@app.post("/api/sysapps/{app_id}/settings")
def api_appcfg_save(app_id: str, body: AppSettingsBody, user: str = auth.CurrentUser):
    return _cfg_call(lambda: appconfig.save(app_id, body.changes))


@app.get("/api/sysapps/{app_id}/modules")
def api_appcfg_modules(app_id: str, user: str = auth.CurrentUser):
    return _cfg_call(lambda: {"modules": appconfig.modules(app_id)})


@app.post("/api/sysapps/{app_id}/modules")
def api_appcfg_module(app_id: str, body: AppModuleBody, user: str = auth.CurrentUser):
    return _cfg_call(lambda: appconfig.set_module(app_id, body.name, body.on))


@app.get("/api/sysapps/{app_id}/file")
def api_appcfg_file(app_id: str, path: str, user: str = auth.CurrentUser):
    return _cfg_call(lambda: appconfig.read_file(app_id, path))


@app.post("/api/sysapps/{app_id}/file")
def api_appcfg_file_save(app_id: str, body: AppFileBody, user: str = auth.CurrentUser):
    return _cfg_call(lambda: appconfig.write_file(app_id, body.path, body.content))


@app.get("/api/sysapps/{app_id}/logs")
def api_appcfg_logs(app_id: str, source: str | None = None, lines: int = 200, user: str = auth.CurrentUser):
    return _cfg_call(lambda: appconfig.logs(app_id, source, lines))


@app.get("/api/ftp/accounts")
def api_ftp_accounts(user: str = auth.CurrentUser):
    if not ftp.installed():
        return {"installed": False, "accounts": []}
    return _cfg_call(lambda: {"installed": True, **ftp.accounts()})


@app.post("/api/ftp/accounts")
def api_ftp_create(body: FTPAccountBody, user: str = auth.CurrentUser):
    return _cfg_call(lambda: ftp.create(body.name, body.password or "", body.folder or "", body.access or "full", body.create_folder))


@app.post("/api/ftp/accounts/password")
def api_ftp_password(body: FTPAccountBody, user: str = auth.CurrentUser):
    return _cfg_call(lambda: ftp.set_password(body.name, body.password or ""))


@app.post("/api/ftp/accounts/modify")
def api_ftp_modify(body: FTPAccountBody, user: str = auth.CurrentUser):
    return _cfg_call(lambda: ftp.modify(body.name, body.folder, body.access, body.create_folder))


@app.post("/api/ftp/accounts/toggle")
def api_ftp_toggle(body: FTPAccountBody, user: str = auth.CurrentUser):
    return _cfg_call(lambda: ftp.set_enabled(body.name, bool(body.enabled)))


@app.post("/api/ftp/accounts/delete")
def api_ftp_delete(body: FTPAccountBody, user: str = auth.CurrentUser):
    return _cfg_call(lambda: ftp.delete(body.name))


# --------------------------------------------------------------------------- #
# About & updates (the update check only runs when the admin asks for it)
# --------------------------------------------------------------------------- #
@app.get("/api/about")
def api_about(user: str = auth.CurrentUser):
    return version.info()


@app.post("/api/about/check")
def api_about_check(user: str = auth.CurrentUser):
    try:
        return version.check()
    except version.UpdateError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/api/about/changelog")
def api_about_changelog(user: str = auth.CurrentUser):
    try:
        return version.changelog()
    except version.UpdateError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/api/about/update")
def api_about_update(user: str = auth.CurrentUser):
    try:
        return version.apply_update()
    except version.UpdateError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/about/update")
def api_about_update_status(user: str = auth.CurrentUser):
    return version.update_status()


# --------------------------------------------------------------------------- #
# Preferences: account
# --------------------------------------------------------------------------- #
class PasswordChangeBody(BaseModel):
    current: str
    new_password: str


class PrefsBody(BaseModel):
    contact_email: str | None = None
    language: str | None = None
    default_theme: str | None = None


class RenameBody(BaseModel):
    username: str


@app.get("/api/account/prefs")
def api_prefs(user: str = auth.CurrentUser):
    return config.get_prefs()


@app.post("/api/account/prefs")
def api_prefs_set(body: PrefsBody, user: str = auth.CurrentUser):
    return config.set_prefs(contact_email=body.contact_email, language=body.language, default_theme=body.default_theme)


@app.post("/api/account/password")
def api_account_password(body: PasswordChangeBody, request: Request, user: str = auth.CurrentUser):
    prefs = config.get_prefs()
    if not config.verify_credentials(prefs["username"], body.current):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    if body.new_password == body.current:
        raise HTTPException(status_code=400, detail="Choose a password different from the current one")
    config.change_password(body.new_password)
    # change_password rotated the signing secret, which signs out every other
    # session; hand this browser a fresh cookie so it stays logged in.
    resp = JSONResponse({"ok": True})
    _set_session(resp, request, prefs["username"])
    return resp


@app.post("/api/account/rename")
def api_account_rename(body: RenameBody, user: str = auth.CurrentUser):
    if not body.username.strip():
        raise HTTPException(status_code=400, detail="Username required")
    config.rename_user(body.username.strip())
    return {"ok": True, "username": body.username.strip()}


# --------------------------------------------------------------------------- #
# Metrics: Visitors, Errors, Bandwidth, Raw Access, Analytics, Resource Usage
# --------------------------------------------------------------------------- #
def _met_call(fn):
    try:
        return fn()
    except metrics.MetricsError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.on_event("startup")
def _metrics_start():
    config.lock_down()
    # install.sh normally makes the account before the first start; this covers
    # run.sh / run.bat and an update of a panel nobody had signed in to yet.
    made = config.ensure_initial_credentials()
    if made:
        where = config.initial_password_path()
        # The password itself only goes to a terminal, never into the journal.
        shown = f"password {made[1]}" if sys.stdout.isatty() else f"password in {where} (sudo cat {where})"
        print(f"aurora: first sign-in: user {made[0]}, {shown} — you'll be asked to change it", flush=True)
    metrics.start()
    try:
        slackbot.start()  # Socket Mode: receives button clicks and /aurora
    except Exception as exc:
        print(f"aurora: Slack not started: {exc}", flush=True)
    try:
        tasks.ensure_timer()
    except Exception as exc:  # never block the panel from starting
        print(f"aurora: task timer not installed: {exc}", flush=True)


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #
def _alert_call(fn):
    try:
        return fn()
    except alerts.AlertError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/alerts")
def api_alerts(user: str = auth.CurrentUser):
    return {**alerts.public(), "tasks": tasks.status()}


@app.post("/api/alerts")
def api_alerts_save(body: dict, user: str = auth.CurrentUser):
    return _alert_call(lambda: alerts.update(body))


@app.post("/api/alerts/test")
def api_alerts_test(user: str = auth.CurrentUser):
    return _alert_call(alerts.test)


# Slack app: alerts with buttons, attack reports, /aurora (see slackbot.py)
def _slack_call(fn):
    try:
        return fn()
    except (slackbot.SlackError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/slack")
def api_slack(user: str = auth.CurrentUser):
    return slackbot.public()


@app.post("/api/slack")
async def api_slack_save(request: Request, user: str = auth.CurrentUser):
    body = await request.json()
    # Links in Slack messages open the panel at the address it's being used from.
    host = request.headers.get("host", "")
    url = f"{request.url.scheme}://{host}" if re.fullmatch(r"[\w.\-\[\]:]{1,255}", host) else ""
    return _slack_call(lambda: slackbot.update(body if isinstance(body, dict) else {}, url))


@app.post("/api/slack/test")
def api_slack_test(user: str = auth.CurrentUser):
    return _slack_call(slackbot.test)


@app.post("/api/alerts/check")
def api_alerts_check(user: str = auth.CurrentUser):
    return _alert_call(lambda: {**alerts.check(), **alerts.public()})


# --------------------------------------------------------------------------- #
# Scheduled (off-site) backups
# --------------------------------------------------------------------------- #
def _sch_call(fn):
    try:
        return fn()
    except (schedules.ScheduleError, backups.BackupError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/schedules")
def api_sch(user: str = auth.CurrentUser):
    return schedules.listing()


@app.post("/api/schedules/plans")
def api_sch_plan(body: dict, user: str = auth.CurrentUser):
    return _sch_call(lambda: schedules.save_plan(body))


@app.delete("/api/schedules/plans/{pid}")
def api_sch_plan_del(pid: str, user: str = auth.CurrentUser):
    return _sch_call(lambda: schedules.delete_plan(pid))


@app.post("/api/schedules/plans/{pid}/run")
def api_sch_run(pid: str, user: str = auth.CurrentUser):
    return _sch_call(lambda: schedules.start(pid))


@app.get("/api/schedules/plans/{pid}/log")
def api_sch_log(pid: str, name: str = "", user: str = auth.CurrentUser):
    return _sch_call(lambda: schedules.run_log(pid, name))


@app.get("/api/schedules/plans/{pid}/snapshots")
def api_sch_snaps(pid: str, user: str = auth.CurrentUser):
    return _sch_call(lambda: schedules.snapshots(pid))


class FetchBody(BaseModel):
    dest: str = ""
    name: str


@app.post("/api/schedules/plans/{pid}/fetch")
def api_sch_fetch(pid: str, body: FetchBody, user: str = auth.CurrentUser):
    return _sch_call(lambda: schedules.fetch(pid, body.dest, body.name))


@app.get("/api/schedules/plans/{pid}/passphrase")
def api_sch_pass(pid: str, user: str = auth.CurrentUser):
    return _sch_call(lambda: {"passphrase": schedules.passphrase(pid)})


@app.post("/api/schedules/destinations")
def api_sch_dest(body: dict, user: str = auth.CurrentUser):
    return _sch_call(lambda: schedules.save_destination(body))


@app.delete("/api/schedules/destinations/{did}")
def api_sch_dest_del(did: str, user: str = auth.CurrentUser):
    return _sch_call(lambda: schedules.delete_destination(did))


@app.post("/api/schedules/destinations/{did}/test")
def api_sch_dest_test(did: str, user: str = auth.CurrentUser):
    return _sch_call(lambda: schedules.test_destination(did))


# --------------------------------------------------------------------------- #
# System updates
# --------------------------------------------------------------------------- #
def _upd_call(fn):
    try:
        r = fn()
        return {"job": r.id} if hasattr(r, "id") else r
    except updates.UpdateError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/updates")
def api_upd(user: str = auth.CurrentUser):
    return updates.status()


@app.post("/api/updates/refresh")
def api_upd_refresh(user: str = auth.CurrentUser):
    return _upd_call(lambda: {**updates.refresh(), **updates.status()})


class UpdInstallBody(BaseModel):
    packages: list[str] = []


@app.post("/api/updates/install")
def api_upd_install(body: UpdInstallBody, user: str = auth.CurrentUser):
    return _upd_call(lambda: updates.install(body.packages))


class UpdAutoBody(BaseModel):
    enabled: bool
    mode: str = "security"
    reboot: bool = False
    reboot_time: str = "04:00"


@app.post("/api/updates/auto")
def api_upd_auto(body: UpdAutoBody, user: str = auth.CurrentUser):
    return _upd_call(lambda: updates.set_auto(body.enabled, body.mode, body.reboot, body.reboot_time))


class RebootBody(BaseModel):
    minutes: int = 1
    cancel: bool = False


@app.post("/api/updates/reboot")
def api_upd_reboot(body: RebootBody, user: str = auth.CurrentUser):
    return _upd_call(lambda: updates.cancel_reboot() if body.cancel else updates.reboot(body.minutes))


# --------------------------------------------------------------------------- #
# WordPress Toolkit
# --------------------------------------------------------------------------- #
def _wp_call(fn):
    try:
        r = fn()
        return {"job": r.id} if hasattr(r, "id") else r
    except wptoolkit.WPError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/wptoolkit")
def api_wpt(user: str = auth.CurrentUser):
    return {"sites": wptoolkit.sites(), "cli": wptoolkit.cli_ready()}


@app.get("/api/wptoolkit/site")
def api_wpt_site(path: str, user: str = auth.CurrentUser):
    return _wp_call(lambda: wptoolkit.details(path))


class WPActBody(BaseModel):
    path: str
    what: str = "all"
    names: list[str] = []
    on: bool = True


@app.post("/api/wptoolkit/update")
def api_wpt_update(body: WPActBody, user: str = auth.CurrentUser):
    return _wp_call(lambda: wptoolkit.update(body.path, body.what, body.names))


@app.post("/api/wptoolkit/scan")
def api_wpt_scan(body: WPActBody, user: str = auth.CurrentUser):
    return _wp_call(lambda: wptoolkit.scan(body.path))


@app.post("/api/wptoolkit/harden")
def api_wpt_harden(body: WPActBody, user: str = auth.CurrentUser):
    return _wp_call(lambda: wptoolkit.harden(body.path))


@app.post("/api/wptoolkit/autoupdates")
def api_wpt_auto(body: WPActBody, user: str = auth.CurrentUser):
    return _wp_call(lambda: wptoolkit.auto_updates(body.path, body.on))


@app.post("/api/wptoolkit/maintenance")
def api_wpt_maint(body: WPActBody, user: str = auth.CurrentUser):
    return _wp_call(lambda: wptoolkit.maintenance(body.path, body.on))


@app.post("/api/wptoolkit/staging")
def api_wpt_staging(body: WPActBody, user: str = auth.CurrentUser):
    return _wp_call(lambda: wptoolkit.make_staging(body.path) if body.on else wptoolkit.delete_staging(body.path))


# --------------------------------------------------------------------------- #
# Move from cPanel
# --------------------------------------------------------------------------- #
def _mig_call(fn):
    try:
        r = fn()
        return {"job": r.id} if hasattr(r, "id") else r
    except (migrate.MigrateError, OSError, __import__("tarfile").TarError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/migrate")
def api_mig(user: str = auth.CurrentUser):
    return {"backups": migrate.candidates(), "folder": str(migrate._dir())}


@app.get("/api/migrate/analyze")
def api_mig_analyze(path: str, user: str = auth.CurrentUser):
    return _mig_call(lambda: migrate.analyze(path))


class MigFetchBody(BaseModel):
    url: str


@app.post("/api/migrate/fetch")
def api_mig_fetch(body: MigFetchBody, user: str = auth.CurrentUser):
    return _mig_call(lambda: migrate.fetch(body.url))


class MigRunBody(BaseModel):
    path: str
    sites: list[str] = []
    databases: list[str] = []
    mail: bool = True
    zones: bool = False


@app.post("/api/migrate/run")
def api_mig_run(body: MigRunBody, user: str = auth.CurrentUser):
    return _mig_call(lambda: migrate.run(body.path, body.model_dump()))


# --------------------------------------------------------------------------- #
# Servers (other AuroraPanels)
# --------------------------------------------------------------------------- #
def _srv_call(fn):
    try:
        return fn()
    except (servers.ServerError, guard.GuardError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/fleet/self")
def api_fleet_self(user: str = auth.CurrentUser):
    return servers.self_summary()


@app.get("/api/servers")
def api_servers(user: str = auth.CurrentUser):
    return servers.overview()


class ServerAddBody(BaseModel):
    name: str = ""
    url: str
    token: str


@app.post("/api/servers")
def api_servers_add(body: ServerAddBody, user: str = auth.CurrentUser):
    return _srv_call(lambda: servers.add(body.name, body.url, body.token))


@app.delete("/api/servers/{sid}")
def api_servers_del(sid: str, user: str = auth.CurrentUser):
    return _srv_call(lambda: servers.remove(sid))


@app.post("/api/servers/{sid}/repin")
def api_servers_repin(sid: str, user: str = auth.CurrentUser):
    return _srv_call(lambda: servers.repin(sid))


class FleetBanBody(BaseModel):
    ip: str
    reason: str = ""
    duration: int | None = None
    unban: bool = False


@app.post("/api/servers/ban")
def api_servers_ban(body: FleetBanBody, request: Request, user: str = auth.CurrentUser):
    """Ban (or unban) on this server and every added server."""
    def go():
        try:  # already banned/unbanned here must not stop the others
            local = guard.unban(body.ip) if body.unban else guard.ban(body.ip, body.reason, body.duration, _client_ip(request), "Servers · ban everywhere")
            local = {"ok": True}
        except guard.GuardError as exc:
            local = {"ok": False, "error": str(exc)}
        others = servers.unban_everywhere(body.ip) if body.unban else servers.ban_everywhere(body.ip, body.reason, body.duration)
        return {"local": local, "servers": others}
    return _srv_call(go)


# --------------------------------------------------------------------------- #
# Docker apps
# --------------------------------------------------------------------------- #
def _dk_call(fn):
    try:
        r = fn()
        return {"job": r.id} if hasattr(r, "id") else r
    except (dockerapps.DockerError, sites.SiteError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/docker")
def api_dk(user: str = auth.CurrentUser):
    return {**dockerapps.catalog(), **dockerapps.listing()}


class DockerInstallBody(BaseModel):
    app: str
    name: str = ""
    access: str = "proxy"
    domain: str = ""
    folders: dict = {}


@app.post("/api/docker/install")
def api_dk_install(body: DockerInstallBody, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.install(body.app, body.name, body.access, body.domain, body.folders))


@app.post("/api/docker/prune")
def api_dk_prune(user: str = auth.CurrentUser):
    return _dk_call(dockerapps.prune)


@app.post("/api/docker/apps/{name}/{action}")
def api_dk_ctl(name: str, action: str, user: str = auth.CurrentUser):
    if action == "update":
        return _dk_call(lambda: dockerapps.update(name))
    return _dk_call(lambda: dockerapps.control(name, action))


@app.get("/api/docker/apps/{name}/logs")
def api_dk_logs(name: str, lines: int = 300, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.logs(name, lines))


@app.get("/api/docker/apps/{name}/secret")
def api_dk_secret(name: str, key: str, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.secret(name, key))


@app.delete("/api/docker/apps/{name}")
def api_dk_remove(name: str, data: bool = False, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.remove(name, data))


# ---- every container (panel apps, custom containers, ones made elsewhere) ----
class DockerSettingsBody(BaseModel):
    ports: list | None = None
    path: str | None = None
    keep_alive: bool | None = None
    env: list | None = None
    restart: str = ""
    mem_limit: str = ""
    cpus: str = ""
    access: str = ""
    domain: str = ""


class DockerCustomBody(BaseModel):
    name: str
    image: str
    title: str = ""
    uid: str = ""
    access: str = "lan"
    domain: str = ""
    restart: str = "unless-stopped"
    ports: list = []
    volumes: list = []
    env: list = []
    devices: list = []
    command: str = ""
    mem_limit: str = ""
    cpus: str = ""
    host_network: bool = False
    privileged: bool = False
    https_only: bool = False
    note: str = ""
    path: str = ""
    keep_alive: bool = False


class DockerExecBody(BaseModel):
    cmd: str
    user: str = ""
    workdir: str = ""


class DockerImageBody(BaseModel):
    image: str


def _dk_admin(user: str) -> None:
    me = panelusers.get(user) if not user.startswith("token:") else None
    if not me or me.get("role") != "admin":
        raise HTTPException(status_code=403, detail="A shell inside a container is for administrators")


@app.get("/api/docker/catalog")
def api_dk_catalog(user: str = auth.CurrentUser):
    return dockerapps.catalog()


@app.get("/api/docker/overview")
def api_dk_overview(user: str = auth.CurrentUser):
    me = panelusers.get(user) if not user.startswith("token:") else None
    return {**dockerapps.overview(), "lan_ip": dockerapps._lan_ip(), "arch": dockerapps.arch(), "admin": bool(me and me.get("role") == "admin")}


@app.post("/api/docker/memcgroup")
def api_dk_memcgroup(user: str = auth.CurrentUser):
    return _dk_call(dockerapps.enable_mem_cgroup)


@app.get("/api/docker/containers")
def api_dk_containers(user: str = auth.CurrentUser):
    return dockerapps.containers()


@app.post("/api/docker/custom")
def api_dk_custom(body: DockerCustomBody, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.create_custom(body.model_dump()))


@app.get("/api/docker/containers/{ref}")
def api_dk_inspect(ref: str, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.inspect(ref))


@app.post("/api/docker/containers/{ref}/action/{action}")
def api_dk_container_action(ref: str, action: str, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.container_action(ref, action))


@app.get("/api/docker/containers/{ref}/logs")
def api_dk_container_logs(ref: str, lines: int = 400, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.container_logs(ref, lines))


@app.get("/api/docker/containers/{ref}/top")
def api_dk_container_top(ref: str, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.container_top(ref))


@app.post("/api/docker/containers/{ref}/exec")
def api_dk_container_exec(ref: str, body: DockerExecBody, user: str = auth.CurrentUser):
    _dk_admin(user)
    return _dk_call(lambda: dockerapps.exec_cmd(ref, body.cmd, body.user, body.workdir))


@app.put("/api/docker/containers/{ref}/settings")
def api_dk_container_settings(ref: str, body: DockerSettingsBody, user: str = auth.CurrentUser):
    data = body.model_dump()
    if ref in dockerapps._state()["apps"]:
        return _dk_call(lambda: dockerapps.update_settings(ref, data))
    return _dk_call(lambda: dockerapps.recreate_external(ref, data))


@app.delete("/api/docker/containers/{ref}")
def api_dk_container_remove(ref: str, data: bool = False, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.container_remove(ref, data))


@app.get("/api/docker/images")
def api_dk_images(user: str = auth.CurrentUser):
    return dockerapps.images()


@app.post("/api/docker/images/pull")
def api_dk_image_pull(body: DockerImageBody, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.image_pull(body.image))


@app.get("/api/docker/images/{ref:path}")
def api_dk_image_inspect(ref: str, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.image_inspect(ref))


@app.delete("/api/docker/images/{ref:path}")
def api_dk_image_remove(ref: str, user: str = auth.CurrentUser):
    return _dk_call(lambda: dockerapps.image_remove(ref))


# --------------------------------------------------------------------------- #
# Site isolation (PHP-FPM pool + Linux user per site)
# --------------------------------------------------------------------------- #
def _iso_call(fn):
    try:
        r = fn()
        return {"job": r.id} if hasattr(r, "id") else r
    except (isolate.IsolateError, sites.SiteError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class IsoBody(BaseModel):
    site: str = ""


@app.get("/api/isolation")
def api_iso(user: str = auth.CurrentUser):
    return isolate.status()


@app.post("/api/isolation/enable")
def api_iso_on(body: IsoBody, user: str = auth.CurrentUser):
    return _iso_call(lambda: isolate.enable_all_job() if not body.site else isolate.enable_job(body.site))


@app.post("/api/isolation/disable")
def api_iso_off(body: IsoBody, user: str = auth.CurrentUser):
    return _iso_call(lambda: isolate.disable(body.site))


@app.post("/api/isolation/fix")
def api_iso_fix(body: IsoBody, user: str = auth.CurrentUser):
    return _iso_call(lambda: isolate.fix_permissions(body.site))


# --------------------------------------------------------------------------- #
# AutoSSL
# --------------------------------------------------------------------------- #
def _assl_call(fn):
    try:
        return fn()
    except (autossl.AutoSSLError, dnszones.ZoneError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/autossl")
def api_assl(user: str = auth.CurrentUser):
    return autossl.status()


class AutoSSLBody(BaseModel):
    enabled: bool | None = None
    email: str | None = None
    agreed: bool | None = None
    exclude: list[str] | None = None


@app.post("/api/autossl")
def api_assl_save(body: AutoSSLBody, user: str = auth.CurrentUser):
    return _assl_call(lambda: autossl.settings(body.enabled, body.email, body.agreed, body.exclude))


class AutoSSLRunBody(BaseModel):
    only: str = ""


@app.post("/api/autossl/run")
def api_assl_run(body: AutoSSLRunBody, user: str = auth.CurrentUser):
    return _assl_call(lambda: autossl.start(True, body.only))


class WildcardBody(BaseModel):
    domain: str


@app.post("/api/autossl/wildcard")
def api_assl_wild(body: WildcardBody, user: str = auth.CurrentUser):
    return _assl_call(lambda: autossl.issue_wildcard(body.domain))


@app.get("/api/metrics/sites")
def api_met_sites(user: str = auth.CurrentUser):
    return {"sites": metrics.sites()}


@app.get("/api/metrics/visitors")
def api_met_visitors(site: str, limit: int = 1000, hours: int = 0, name: str = "", user: str = auth.CurrentUser):
    return _met_call(lambda: metrics.visitors(site, limit, hours, name))


@app.get("/api/metrics/errors")
def api_met_errors(site: str = "", hours: int = 24, sources: str = "web,mail,database,dns,php_fpm,panel,system",
                   start: float = 0, end: float = 0, user: str = auth.CurrentUser):
    return _met_call(lambda: metrics.errors(site, hours, sources, start, end))


@app.get("/api/metrics/bandwidth")
def api_met_bw(user: str = auth.CurrentUser):
    return metrics.bandwidth()


@app.get("/api/metrics/resources")
def api_met_res(span: str = "day", user: str = auth.CurrentUser):
    return metrics.resources(span)


@app.get("/api/metrics/analytics")
def api_met_analytics(site: str, days: int = 30, file: str = "", name: str = "", user: str = auth.CurrentUser):
    return _met_call(lambda: metrics.analytics(site, days, file, name))


@app.get("/api/metrics/ip")
def api_met_ip(ip: str, days: int = 7, user: str = auth.CurrentUser):
    return _met_call(lambda: metrics.ip_info(ip, max(1, min(days, 90))))


@app.get("/api/metrics/raw")
def api_met_raw(user: str = auth.CurrentUser):
    return metrics.raw()


class RetentionBody(BaseModel):
    days: int


@app.post("/api/metrics/retention")
def api_met_retention(body: RetentionBody, user: str = auth.CurrentUser):
    return _met_call(lambda: metrics.set_retention(body.days))


@app.get("/api/metrics/download")
def api_met_download(file: str, gz: bool = False, user: str = auth.CurrentUser):
    p = _met_call(lambda: metrics.log_file(file))
    if gz and not p.name.endswith(".gz"):
        import gzip as _gz
        def stream():
            with open(p, "rb") as f:
                buf = io.BytesIO()
                z = _gz.GzipFile(fileobj=buf, mode="wb")
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    z.write(chunk)
                    yield buf.getvalue(); buf.seek(0); buf.truncate()
                z.close()
                yield buf.getvalue()
        return StreamingResponse(stream(), media_type="application/gzip",
                                 headers={"Content-Disposition": f'attachment; filename="{p.name}.gz"'})
    media = "application/gzip" if p.name.endswith(".gz") else "text/plain"
    return FileResponse(str(p), media_type=media, filename=p.name)


# --------------------------------------------------------------------------- #
# Domains: Dynamic DNS hosts (and their public update URL)
# --------------------------------------------------------------------------- #
def _ddh_call(fn):
    try:
        return fn()
    except (ddnshosts.DdnsError, dnszones.ZoneError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class DdnsHostBody(BaseModel):
    domain: str
    prefix: str
    ip: str = ""
    description: str = ""


class DdnsHostEdit(BaseModel):
    description: str | None = None
    ip: str | None = None


@app.get("/api/ddns-hosts")
def api_ddh(request: Request, user: str = auth.CurrentUser):
    return {**ddnshosts.listing(), "your_ip": _caller_ip(request)}


@app.post("/api/ddns-hosts")
def api_ddh_create(body: DdnsHostBody, user: str = auth.CurrentUser):
    return _ddh_call(lambda: ddnshosts.create(body.domain, body.prefix, body.ip, body.description))


@app.post("/api/ddns-hosts/{hid}")
def api_ddh_edit(hid: str, body: DdnsHostEdit, user: str = auth.CurrentUser):
    def go():
        if body.ip:
            ddnshosts.set_ip(hid, body.ip)
        return ddnshosts.update_meta(hid, body.description)
    return _ddh_call(go)


@app.get("/api/ddns-hosts/{hid}/key")
def api_ddh_key(hid: str, user: str = auth.CurrentUser):
    return _ddh_call(lambda: ddnshosts.reveal(hid))


@app.post("/api/ddns-hosts/{hid}/regenerate")
def api_ddh_regen(hid: str, user: str = auth.CurrentUser):
    return _ddh_call(lambda: ddnshosts.regenerate(hid))


@app.delete("/api/ddns-hosts/{hid}")
def api_ddh_delete(hid: str, user: str = auth.CurrentUser):
    return _ddh_call(lambda: ddnshosts.delete(hid))


def _caller_ip(request: Request) -> str:
    """The client's address; behind our own Apache proxy, the address Apache saw."""
    ip = request.client.host if request.client else ""
    if ip in ("127.0.0.1", "::1"):
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            ip = fwd.split(",")[-1].strip()
    return ip


def _ddns_answer(text: str) -> Response:
    return Response(text + "\n", media_type="text/plain", headers={"Cache-Control": "no-store"})


@app.api_route("/ddns/update", methods=["GET", "POST"])
def ddns_public_update(request: Request, key: str = "", ip: str = "", myip: str = ""):
    """Public, no login: the secret key is the credential (?key=…, optional &ip=…)."""
    return _ddns_answer(ddnshosts.remote_update(key, ip or myip, _caller_ip(request)))


@app.get("/nic/update")
def ddns_public_nic(request: Request, hostname: str = "", myip: str = ""):
    """dyndns2 protocol for routers: Basic auth with user = hostname, password = key."""
    import base64
    key, user = "", ""
    h = request.headers.get("authorization", "")
    if h.lower().startswith("basic "):
        try:
            user, _, key = base64.b64decode(h[6:]).decode("utf-8", "replace").partition(":")
        except ValueError:
            pass
    if not key:
        return Response("badauth\n", status_code=401, media_type="text/plain",
                        headers={"WWW-Authenticate": 'Basic realm="AuroraPanel Dynamic DNS"'})
    return _ddns_answer(ddnshosts.remote_update(key, myip.split(",")[0], _caller_ip(request), hostname or user))


# --------------------------------------------------------------------------- #
# Terminal (WebSocket PTY)
# --------------------------------------------------------------------------- #
@app.websocket("/api/terminal/ws")
async def api_terminal(websocket: WebSocket):
    # Authenticate via the same session cookie before accepting.
    token = websocket.cookies.get(auth.COOKIE_NAME)
    name = auth.verify_token(token) if token else None
    me = panelusers.get(name) if name else None
    if not me or me["role"] != "admin":  # a root shell is for administrators only
        await websocket.close(code=1008)
        return
    await websocket.accept()
    try:
        await terminal.run(websocket)
    except WebSocketDisconnect:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.websocket("/api/docker/containers/{ref}/shell")
async def api_docker_shell(websocket: WebSocket, ref: str, user: str = ""):
    """A shell inside a container (docker exec), as root unless ?user= says otherwise. Administrators only."""
    token = websocket.cookies.get(auth.COOKIE_NAME)
    name = auth.verify_token(token) if token else None
    me = panelusers.get(name) if name else None
    if not me or me["role"] != "admin":
        await websocket.close(code=1008)
        return
    try:
        argv = dockerapps.shell_argv(ref, user)
    except dockerapps.DockerError:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    try:
        await terminal.run(websocket, argv)
    except WebSocketDisconnect:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Static frontend (mounted last so /api takes precedence)
# --------------------------------------------------------------------------- #
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
