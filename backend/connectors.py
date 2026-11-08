"""Cloud Apps, Google Drive: connect a Drive, then copy files both ways.

Transfers run through rclone, which the panel installs on request. Signing in uses rclone's own
OAuth flow in its "remote machine" form, because Google only sends a sign-in back to a public
address or to 127.0.0.1 on the computer with the browser, never to a home server's LAN address:

  1. start(): the panel runs `rclone authorize` here, which listens on 127.0.0.1:53682 on this
     server, and hands the browser the Google sign-in page that listener points to.
  2. The owner signs in and allows access. Google then sends the browser to
     http://127.0.0.1:53682/?state=…&code=…, which fails to load on their own computer.
     They copy that address from the address bar and paste it into the panel.
  3. finish(): the panel delivers the pasted address to the waiting listener here, rclone trades
     the one-time code for a token and prints it, and the panel saves it as an rclone remote.

Google Drive works with rclone's built-in Google app or the owner's own OAuth client (client ID + secret,
type "Desktop app"). Google Photos was removed in 1.2.4: since 31 March 2025 Google lets apps see only
the photos they uploaded themselves, so a library could never be shown. Connections made before are
removed the next time the page loads.

Copies never delete anything: a push or pull adds new and changed files and leaves the rest.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import distro
from . import jobs
from . import problems

BASE = Path("/var/lib/aurora/connectors")
PATH = distro.PATH + ":/usr/local/bin"
AUTH_PORT = 53682
AUTH_TIMEOUT = 600  # a sign-in left open longer than this is dropped

SERVICES = {
    "drive": {"name": "Google Drive", "backend": "drive", "icon": "t_cloud",
              "about": "Files and folders in your Drive, both ways.",
              "roots": []},
}


class ConnectError(RuntimeError):
    pass


# --------------------------------------------------------------------------- state
def _state_path() -> Path:
    return BASE / "accounts.json"


def _conf() -> Path:
    return BASE / "rclone.conf"


def _private_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except OSError as quiet_exc:
        problems.quiet(quiet_exc)


def _write_private(p: Path, text: str) -> None:
    _private_dir(p.parent)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    tmp.replace(p)


def load() -> dict:
    try:
        d = json.loads(_state_path().read_text())
    except (OSError, ValueError):
        d = {}
    if not isinstance(d, dict):
        d = {}
    d.setdefault("accounts", [])
    return d


def _save(d: dict) -> None:
    _write_private(_state_path(), json.dumps(d, indent=1))


def rclone_ok() -> bool:
    return shutil.which("rclone", path=PATH) is not None


def rclone_version() -> tuple[int, ...]:
    from . import requires
    return requires.rclone_version()


def _env() -> dict:
    return {"PATH": PATH, "HOME": str(BASE), "LANG": "C.UTF-8", "RCLONE_CONFIG": str(_conf())}


def _rclone(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    if not rclone_ok():
        raise ConnectError("Install rclone first (one click on this page)")
    try:
        return subprocess.run(["rclone", "--config", str(_conf()), *args], capture_output=True, text=True, timeout=timeout, env=_env())
    except subprocess.TimeoutExpired:
        raise ConnectError(f"Google took longer than {timeout} seconds to answer")
    except OSError as exc:
        raise ConnectError(str(exc))


def _err(r: subprocess.CompletedProcess) -> str:
    lines = [re.sub(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d (ERROR|NOTICE|INFO|CRITICAL)\s*:?\s*", "", ln).strip()
             for ln in ((r.stderr or "") + "\n" + (r.stdout or "")).splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith("Config file")]
    return (" ".join(lines[-2:]) or "rclone failed")[-400:]


def _remote(acct_id: str) -> str:
    return f"c_{acct_id}"


def _public(a: dict) -> dict:
    return {k: a.get(k) for k in ("id", "service", "label", "email", "created", "own_client")} | {"name": SERVICES[a["service"]]["name"]}


def _forget_retired(d: dict) -> dict:
    """Drop connections to services that are gone (Google Photos, removed in 1.2.4), rclone remote included."""
    gone = [a for a in d["accounts"] if a.get("service") not in SERVICES]
    if gone:
        for a in gone:
            try:
                _drop_remote(_remote(a["id"]))
            except Exception:  # rclone missing or the remote already gone: the account goes anyway
                pass
        d["accounts"] = [a for a in d["accounts"] if a.get("service") in SERVICES]
        _save(d)
    return d


def listing() -> dict:
    d = _forget_retired(load())
    with _LOCK:
        pending = {s["service"]: True for s in _SESSIONS.values()}
    ver = rclone_version() if rclone_ok() else ()
    return {"rclone": rclone_ok(), "rclone_version": ".".join(map(str, ver)),
            "services": [{"id": k, "name": v["name"], "icon": v["icon"], "about": v["about"], "roots": v["roots"],
                          "signing_in": pending.get(k, False)} for k, v in SERVICES.items()],
            "accounts": [_public(a) for a in d["accounts"]]}


def _account(acct_id: str) -> dict:
    for a in load()["accounts"]:
        if a["id"] == acct_id:
            return a
    raise ConnectError("That connection doesn't exist (any more)")


# --------------------------------------------------------------------------- remotes in rclone.conf
def _read_conf() -> dict[str, list[str]]:
    """Sections of our private rclone.conf: name -> its body lines."""
    try:
        text = _conf().read_text()
    except OSError:
        return {}
    out: dict[str, list[str]] = {}
    cur = None
    for ln in text.splitlines():
        m = re.fullmatch(r"\[([^\]]+)\]\s*", ln)
        if m:
            cur = m.group(1)
            out[cur] = []
        elif cur is not None and ln.strip():
            out[cur].append(ln)
    return out


def _write_conf(sections: dict[str, list[str]]) -> None:
    _write_private(_conf(), "".join(f"[{k}]\n" + "".join(f"{x}\n" for x in v) + "\n" for k, v in sections.items()))


def _set_remote(name: str, kv: dict) -> None:
    secs = _read_conf()
    secs[name] = [f"{k} = {v}" for k, v in kv.items() if v not in (None, "")]
    _write_conf(secs)


def _drop_remote(name: str) -> None:
    secs = _read_conf()
    if secs.pop(name, None) is not None:
        _write_conf(secs)


# --------------------------------------------------------------------------- sign-in
_LOCK = threading.Lock()
_SESSIONS: dict[str, dict] = {}   # sid -> {"proc", "service", "lines", "started", "client_id", "client_secret", "label"}
_CLIENT_ID = re.compile(r"^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$")


def _reader(sess: dict) -> None:
    proc = sess["proc"]
    for line in proc.stdout:
        sess["lines"].append(line.rstrip("\n"))


def _stop(sid: str) -> None:
    sess = _SESSIONS.pop(sid, None)
    if sess and sess["proc"].poll() is None:
        try:
            sess["proc"].kill()
            sess["proc"].wait(5)
        except (OSError, subprocess.SubprocessError) as quiet_exc:
            problems.quiet(quiet_exc)


def _reap() -> None:
    for sid, s in list(_SESSIONS.items()):
        if time.time() - s["started"] > AUTH_TIMEOUT or s["proc"].poll() is not None:
            _stop(sid)


def _local_get(url: str, timeout: int = 20) -> urllib.request.addinfourl | None:
    """GET a URL on the waiting rclone listener without following redirects."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        return opener.open(url, timeout=timeout)
    except urllib.error.HTTPError as e:
        return e


def start(service: str, client_id: str = "", client_secret: str = "", label: str = "") -> dict:
    """Begin a Google sign-in. Returns the Google page to open and a session id for finish()."""
    if service not in SERVICES:
        raise ConnectError("Unknown service")
    if not rclone_ok():
        raise ConnectError("Install rclone first (one click on this page)")
    client_id, client_secret = (client_id or "").strip(), (client_secret or "").strip()
    if client_id or client_secret:
        if not _CLIENT_ID.fullmatch(client_id):
            raise ConnectError("The client ID ends in .apps.googleusercontent.com")
        if len(client_secret) < 10:
            raise ConnectError("Paste the client secret as well")
    label = re.sub(r"[\x00-\x1f]", "", label or "").strip()[:60]
    with _LOCK:
        _reap()
        for sid in list(_SESSIONS):  # one listener on the port at a time; a new sign-in replaces an old one
            _stop(sid)
        _private_dir(BASE)
        argv = ["rclone", "--config", str(_conf()), "authorize", SERVICES[service]["backend"]]
        if client_id:
            argv += [client_id, client_secret]
        argv += ["--auth-no-open-browser"]
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=_env())
        except OSError as exc:
            raise ConnectError(str(exc))
        sid = secrets.token_urlsafe(12)
        sess = {"proc": proc, "service": service, "lines": [], "started": time.time(), "label": label,
                "client_id": client_id, "client_secret": client_secret}
        _SESSIONS[sid] = sess
    threading.Thread(target=_reader, args=(sess,), daemon=True).start()
    local = None
    for _ in range(100):
        for ln in list(sess["lines"]):
            m = re.search(rf"http://127\.0\.0\.1:{AUTH_PORT}/auth\?state=[A-Za-z0-9_-]+", ln)
            if m:
                local = m.group(0)
                break
        if local or proc.poll() is not None:
            break
        time.sleep(0.15)
    if not local:
        with _LOCK:
            _stop(sid)
        tail = " ".join(sess["lines"][-2:])
        if "address already in use" in tail:
            raise ConnectError(f"Port {AUTH_PORT} on this server is busy, another rclone sign-in is open. Close it and try again")
        raise ConnectError("rclone didn't start the sign-in: " + (tail[-300:] or "no answer"))
    r = _local_get(local)
    google = r.headers.get("Location", "") if r is not None else ""
    if not google.startswith("https://accounts.google.com/"):
        with _LOCK:
            _stop(sid)
        raise ConnectError("rclone didn't give a Google sign-in page")
    return {"session": sid, "url": google, "expires": AUTH_TIMEOUT}


def _parse_token(lines: list[str]) -> str | None:
    """The token rclone prints between its paste markers (JSON, or base64 JSON in newer versions)."""
    text = "\n".join(lines)
    m = re.search(r"--->\s*(.+?)\s*<---", text, re.S)
    if not m:
        return None
    blob = m.group(1).strip()
    try:
        tok = json.loads(blob)
    except ValueError:
        import base64
        try:
            tok = json.loads(base64.b64decode(blob + "=" * (-len(blob) % 4)).decode())
        except (ValueError, UnicodeDecodeError):
            return None
        if isinstance(tok, dict) and "token" in tok and isinstance(tok["token"], (str, dict)):
            tok = tok["token"] if isinstance(tok["token"], dict) else json.loads(tok["token"])
    if not isinstance(tok, dict) or not tok.get("access_token"):
        return None
    return json.dumps(tok, separators=(",", ":"))


def finish(sid: str, auth_response: str) -> dict:
    """Complete a sign-in with the address Google sent the browser to."""
    with _LOCK:
        _reap()
        sess = _SESSIONS.get(sid or "")
    if not sess:
        raise ConnectError("That sign-in expired or was replaced. Press Connect to start again")
    raw = (auth_response or "").strip()
    try:
        u = urllib.parse.urlsplit(raw if "://" in raw else "http://127.0.0.1/?" + raw.lstrip("?"))
    except ValueError:
        raise ConnectError("Paste the whole address from the browser's address bar")
    q = urllib.parse.parse_qs(u.query)
    if q.get("error"):
        raise ConnectError(f"Google said: {q['error'][0]}")
    code, state = (q.get("code") or [""])[0], (q.get("state") or [""])[0]
    if not code or not state:
        raise ConnectError("That address has no code in it. After you allow access, copy the address of the page that fails to load")
    local = f"http://127.0.0.1:{AUTH_PORT}/?" + urllib.parse.urlencode({k: v[0] for k, v in q.items()})
    r = _local_get(local, 60)
    token = None
    for _ in range(200):
        token = _parse_token(sess["lines"])
        if token or sess["proc"].poll() is not None:
            break
        time.sleep(0.15)
    if not token:
        token = _parse_token(sess["lines"])
    with _LOCK:
        _stop(sid)
    if not token:
        detail = " ".join(ln for ln in sess["lines"][-3:] if "token" not in ln.lower())
        if r is not None and getattr(r, "status", 200) >= 400:
            detail = detail or f"HTTP {r.status}"
        raise ConnectError("Google didn't accept that code. Codes work once and for a few minutes, so start again. " + detail[-200:])
    return _create(sess["service"], token, sess["client_id"], sess["client_secret"], sess["label"])


def _create(service: str, token: str, client_id: str, client_secret: str, label: str) -> dict:
    acct_id = secrets.token_hex(4)
    kv = {"type": "drive", "client_id": client_id, "client_secret": client_secret, "token": token, "scope": "drive"}
    _set_remote(_remote(acct_id), kv)
    email = ""
    r = _rclone(["config", "userinfo", f"{_remote(acct_id)}:", "--json"], 60)
    if r.returncode == 0:
        try:
            email = json.loads(r.stdout or "{}").get("Email", "")
        except ValueError:
            email = ""
    d = load()
    acct = {"id": acct_id, "service": service, "label": label or SERVICES[service]["name"], "email": email,
            "created": time.time(), "own_client": bool(client_id)}
    d["accounts"].append(acct)
    _save(d)
    return _public(acct)


def cancel(sid: str) -> dict:
    with _LOCK:
        _stop(sid or "")
    return {"ok": True}


def rename(acct_id: str, label: str) -> dict:
    label = re.sub(r"[\x00-\x1f]", "", label or "").strip()[:60]
    if not label:
        raise ConnectError("Give it a name")
    d = load()
    for a in d["accounts"]:
        if a["id"] == acct_id:
            a["label"] = label
            _save(d)
            return _public(a)
    raise ConnectError("That connection doesn't exist (any more)")


def disconnect(acct_id: str) -> dict:
    _account(acct_id)
    d = load()
    d["accounts"] = [a for a in d["accounts"] if a["id"] != acct_id]
    _save(d)
    _drop_remote(_remote(acct_id))
    return {"ok": True, "revoke": "https://myaccount.google.com/connections"}


# --------------------------------------------------------------------------- files
def _clean_remote_path(path: str) -> str:
    p = (path or "").strip().strip("/")
    if re.search(r"[\x00-\x1f]", p) or ".." in p.split("/"):
        raise ConnectError("That path isn't allowed")
    return p


def browse(acct_id: str, path: str = "") -> dict:
    a = _account(acct_id)
    p = _clean_remote_path(path)
    r = _rclone(["lsjson", f"{_remote(acct_id)}:{p}", "--max-depth", "1", "--no-mimetype", "--fast-list"], 120)
    if r.returncode != 0:
        msg = _err(r)
        if "directory not found" in msg.lower():
            return {"path": p, "entries": []}
        raise ConnectError(msg)
    try:
        items = json.loads(r.stdout or "[]")
    except ValueError:
        items = []
    ents = [{"name": x.get("Name", ""), "dir": bool(x.get("IsDir")), "size": None if x.get("IsDir") else x.get("Size"),
             "modified": x.get("ModTime", "")} for x in items]
    ents.sort(key=lambda e: (not e["dir"], e["name"].lower()))
    return {"path": p, "entries": ents[:5000], "more": len(ents) > 5000}


def _local(path: str) -> Path:
    from . import files
    try:
        return files._resolve(path)
    except files.FileError as exc:
        raise ConnectError(str(exc))


_PROGRESS = re.compile(r"(\d{1,3})%")


def transfer(acct_id: str, direction: str, local: str, remote: str) -> dict:
    """Copy between this server and Google. Adds new and changed files, never deletes any."""
    a = _account(acct_id)
    if direction not in ("push", "pull"):
        raise ConnectError("Push (to Google) or pull (to this server)")
    if not (local or "").strip():
        raise ConnectError("Pick a file or folder on this server")
    lp = _local(local)
    rp = _clean_remote_path(remote)
    svc = SERVICES[a["service"]]["name"]
    if direction == "push":
        if not lp.exists():
            raise ConnectError("That file or folder doesn't exist on this server")
        if lp.is_dir():
            dst = "/".join(x for x in (rp, lp.name) if x)
        else:
            dst = rp
        src, target = str(lp), f"{_remote(acct_id)}:{dst}"
        title = f"Push {lp.name} to {svc} /{dst}"
    else:
        if not lp.is_dir():
            raise ConnectError("Pull into a folder on this server")
        src = f"{_remote(acct_id)}:{rp}"
        leaf = rp.rsplit("/", 1)[-1] if rp else "Google Drive"
        target = str(lp / leaf)
        title = f"Pull {svc} /{rp} to {target}"
    argv = ["rclone", "--config", str(_conf()), "copy", src, target, "--stats", "2s", "--stats-one-line", "--stats-log-level", "NOTICE",
            "--retries", "3", "--low-level-retries", "10"]

    def fn(log):
        log(f"• {title}")
        log("• New and changed files are copied, nothing is deleted on either side")
        log.progress(1, "Starting")
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=_env())
        except OSError as exc:
            raise ConnectError(str(exc))
        last = ""
        for line in proc.stdout:
            line = line.rstrip("\n")
            clean = re.sub(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \w+\s*:?\s*", "", line).strip()
            if not clean:
                continue
            m = _PROGRESS.search(clean)
            if m and ("ETA" in clean or "/s" in clean):
                log.progress(max(1, min(99, int(m.group(1)))), clean[:120])
                last = clean
            else:
                log(clean)
        rc = proc.wait()
        if last:
            log(last)
        if rc != 0:
            raise ConnectError(f"rclone stopped with exit code {rc}, see the lines above")
        log.progress(100, "Done")
        log("✓ Done")
        return {"ok": True}

    job = jobs.launch_fn(title, fn, meta={"connector": acct_id})
    return {"job": job.id}
