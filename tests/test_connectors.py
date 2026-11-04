"""Third-party Apps (backend/connectors.py): Google Drive and Google Photos through rclone.

No Google account and no real rclone are involved. `rclone authorize` is a fake process whose
output the tests write line by line, the local listener it would run is a fake GET, and other
rclone calls are answered from a rule table."""
from __future__ import annotations

import base64
import io
import json
import subprocess
import threading

import pytest

from backend import connectors, jobs

GOOGLE = "https://accounts.google.com/o/oauth2/auth?client_id=x&redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2F&state=ST"
CID, SEC = "123-abc.apps.googleusercontent.com", "GOCSPX-abcdefghij"
TOKEN = {"access_token": "ya29.secret", "token_type": "Bearer", "refresh_token": "1//refresh", "expiry": "2026-11-03T12:00:00Z"}


class FakeProc:
    """Stands in for the running `rclone authorize`: tests push output lines into it."""

    def __init__(self, argv, lines=None, ends=False):
        self.argv = argv
        self._lines = list(lines or [])
        self._cv = threading.Condition()
        self._ended = ends
        self.killed = False
        self.stdout = self

    def feed(self, *lines):
        with self._cv:
            self._lines += lines
            self._cv.notify_all()

    def end(self):
        with self._cv:
            self._ended = True
            self._cv.notify_all()

    def __iter__(self):
        return self

    def __next__(self):
        with self._cv:
            while not self._lines and not self._ended:
                self._cv.wait(0.05)
            if self._lines:
                return self._lines.pop(0) + "\n"
            raise StopIteration

    def poll(self):
        return 0 if self._ended and not self._lines else None

    def kill(self):
        self.killed = True
        self.end()

    def wait(self, timeout=None):
        return 0


class Resp:
    def __init__(self, status=307, location=GOOGLE):
        self.status = status
        self.headers = {"Location": location}


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(connectors, "BASE", tmp_path / "connectors")
    monkeypatch.setattr(connectors.shutil, "which", lambda name, path=None: "/usr/bin/rclone" if name == "rclone" else None)
    monkeypatch.setattr(connectors, "rclone_version", lambda: (1, 75, 2))
    real_sleep = connectors.time.sleep
    monkeypatch.setattr(connectors.time, "sleep", lambda s: real_sleep(0.005))
    state = {"procs": [], "gets": [], "rules": [], "calls": []}

    def popen(argv, **kw):
        if "authorize" in argv:
            p = FakeProc(argv, ["2026/11/03 11:16:56 NOTICE: Please go to the following link: http://127.0.0.1:53682/auth?state=ST"])
        else:
            p = FakeProc(argv, state.get("copy_lines", []), ends=True)
            p.wait = lambda timeout=None: state.get("copy_rc", 0)
        state["procs"].append(p)
        return p

    def run(argv, **kw):
        state["calls"].append(list(argv))
        joined = " ".join(argv)
        for words, rc, out, err in state["rules"]:
            if all(w in joined for w in words):
                return subprocess.CompletedProcess(argv, rc, out, err)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def local_get(url, timeout=20):
        state["gets"].append(url)
        if "/auth?" in url:
            return state.get("auth_resp", Resp())
        if state.get("on_code"):
            state["on_code"]()
        return Resp(200, "")

    monkeypatch.setattr(connectors.subprocess, "Popen", popen)
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(connectors, "_local_get", local_get)
    state["on"] = lambda *words, rc=0, out="", err="": state["rules"].insert(0, (words, rc, out if isinstance(out, str) else json.dumps(out), err))
    yield state
    with connectors._LOCK:
        for sid in list(connectors._SESSIONS):
            connectors._stop(sid)


def _sign_in(conn, service="drive", token_line=None, **kw):
    if service == "photos":
        kw.setdefault("client_id", CID)
        kw.setdefault("client_secret", SEC)
    r = connectors.start(service, **kw)
    proc = conn["procs"][-1]
    conn["on_code"] = lambda: proc.feed("Paste the following into your remote machine --->", token_line or json.dumps(TOKEN), "<---End paste")
    return r, proc


# ------------------------------------------------------------------ token parsing and config file
def test_token_is_read_from_json_or_base64_between_the_markers():
    lines = ["noise", "Paste the following into your remote machine --->", json.dumps(TOKEN), "<---End paste"]
    assert json.loads(connectors._parse_token(lines))["refresh_token"] == "1//refresh"
    b64 = base64.b64encode(json.dumps({"token": json.dumps(TOKEN)}).encode()).decode().rstrip("=")
    assert json.loads(connectors._parse_token(["--->", b64, "<---End paste"]))["access_token"] == "ya29.secret"
    assert connectors._parse_token(["no markers here"]) is None
    assert connectors._parse_token(["--->", "garbage!!", "<---"]) is None
    assert connectors._parse_token(["--->", json.dumps({"no": "token"}), "<---"]) is None


def test_remotes_are_kept_in_a_private_rclone_conf(conn):
    connectors._set_remote("c_a", {"type": "drive", "token": "{}", "client_id": ""})
    connectors._set_remote("c_b", {"type": "google photos"})
    text = connectors._conf().read_text()
    assert "[c_a]\ntype = drive\ntoken = {}\n" in text and "client_id" not in text and "[c_b]" in text
    connectors._drop_remote("c_a")
    assert list(connectors._read_conf()) == ["c_b"]
    connectors._drop_remote("missing")


# ------------------------------------------------------------------ sign-in
def test_start_runs_rclone_authorize_and_returns_the_google_page(conn):
    r = connectors.start("photos", label="Family", client_id=CID, client_secret=SEC)
    assert r["url"] == GOOGLE and r["session"] and r["expires"] == connectors.AUTH_TIMEOUT
    argv = conn["procs"][-1].argv
    assert argv[argv.index("authorize") + 1] == "google photos" and argv[-1] == "--auth-no-open-browser"
    assert conn["gets"][-1] == "http://127.0.0.1:53682/auth?state=ST"
    d = connectors.listing()
    assert d["services"][1]["signing_in"] is True and d["photos_ok"] and d["rclone_version"] == "1.75.2"


def test_photos_needs_a_current_rclone_and_an_own_google_app(conn, monkeypatch):
    with pytest.raises(connectors.ConnectError, match="your own Google app"):
        connectors.start("photos")
    monkeypatch.setattr(connectors, "rclone_version", lambda: (1, 60, 1))
    with pytest.raises(connectors.ConnectError, match="1.70 or newer"):
        connectors.start("photos", client_id=CID, client_secret=SEC)
    d = connectors.listing()
    assert not d["photos_ok"] and d["rclone_version"] == "1.60.1"
    assert connectors.start("drive")["url"] == GOOGLE  # Drive still works with the shared app


def test_a_new_sign_in_replaces_the_old_one(conn):
    connectors.start("drive")
    first = conn["procs"][-1]
    connectors.start("drive")
    assert first.killed and len(connectors._SESSIONS) == 1


def test_start_with_an_own_google_app_passes_its_id_and_secret(conn):
    with pytest.raises(connectors.ConnectError, match="apps.googleusercontent.com"):
        connectors.start("drive", client_id="nope", client_secret="x" * 20)
    with pytest.raises(connectors.ConnectError, match="secret"):
        connectors.start("drive", client_id="123-abc.apps.googleusercontent.com", client_secret="x")
    connectors.start("drive", client_id="123-abc.apps.googleusercontent.com", client_secret="GOCSPX-abcdefghij")
    argv = conn["procs"][-1].argv
    assert argv[-3:] == ["123-abc.apps.googleusercontent.com", "GOCSPX-abcdefghij", "--auth-no-open-browser"]


def test_start_fails_clearly(conn, monkeypatch):
    with pytest.raises(connectors.ConnectError, match="Unknown service"):
        connectors.start("dropbox")
    conn["auth_resp"] = Resp(200, "")
    with pytest.raises(connectors.ConnectError, match="Google sign-in page"):
        connectors.start("drive")
    assert not connectors._SESSIONS

    def popen(argv, **kw):
        return FakeProc(argv, ["2026/11/03 NOTICE: Failed to start auth webserver: listen tcp 127.0.0.1:53682: bind: address already in use"], ends=True)
    monkeypatch.setattr(connectors.subprocess, "Popen", popen)
    with pytest.raises(connectors.ConnectError, match="busy"):
        connectors.start("drive")

    def popen2(argv, **kw):
        return FakeProc(argv, ["something else"], ends=True)
    monkeypatch.setattr(connectors.subprocess, "Popen", popen2)
    with pytest.raises(connectors.ConnectError, match="didn't start"):
        connectors.start("drive")
    monkeypatch.setattr(connectors.shutil, "which", lambda name, path=None: None)
    with pytest.raises(connectors.ConnectError, match="Install rclone"):
        connectors.start("drive")


def test_finish_trades_the_pasted_address_for_a_saved_connection(conn):
    conn["on"]("config", "userinfo", out={"Email": "me@example.com"})
    r, proc = _sign_in(conn, label="Work drive")
    a = connectors.finish(r["session"], "http://127.0.0.1:53682/?state=ST&code=4%2F0Abc&scope=https://www.googleapis.com/auth/drive")
    assert a["label"] == "Work drive" and a["email"] == "me@example.com" and a["service"] == "drive" and not a["own_client"]
    assert "code=4%2F0Abc" in conn["gets"][-1] and "state=ST" in conn["gets"][-1]
    conf = connectors._conf().read_text()
    assert f"[c_{a['id']}]" in conf and "type = drive" in conf and "scope = drive" in conf and "ya29.secret" in conf
    assert proc.killed and not connectors._SESSIONS
    listing = connectors.listing()
    assert listing["accounts"][0]["email"] == "me@example.com" and "ya29" not in json.dumps(listing)


def test_finish_accepts_just_the_query_part(conn):
    r, _ = _sign_in(conn)
    a = connectors.finish(r["session"], "state=ST&code=abc")
    assert a["label"] == "Google Drive" and a["email"] == ""


def test_finish_explains_what_went_wrong(conn):
    with pytest.raises(connectors.ConnectError, match="expired"):
        connectors.finish("nope", "x")
    r, proc = _sign_in(conn)
    with pytest.raises(connectors.ConnectError, match="no code"):
        connectors.finish(r["session"], "http://127.0.0.1:53682/")
    with pytest.raises(connectors.ConnectError, match="access_denied"):
        connectors.finish(r["session"], "http://127.0.0.1:53682/?error=access_denied")
    conn["on_code"] = lambda: proc.feed("2026 ERROR: Failed to get token: oauth2: cannot fetch token: 400 Bad Request")
    with pytest.raises(connectors.ConnectError, match="didn't accept"):
        connectors.finish(r["session"], "http://127.0.0.1:53682/?state=ST&code=old")
    assert not connectors._SESSIONS


def test_photos_connection_is_checked_and_dropped_when_refused(conn):
    conn["on"]("lsjson", "album", rc=1, err="2026/11/03 ERROR : couldn't list albums: Error 403: insufficient scopes")
    r, _ = _sign_in(conn, "photos")
    with pytest.raises(connectors.ConnectError, match="refused access"):
        connectors.finish(r["session"], "state=ST&code=abc")
    assert connectors._read_conf() == {} and connectors.load()["accounts"] == []
    conn["rules"].clear()
    r, _ = _sign_in(conn, "photos", client_id="123-abc.apps.googleusercontent.com", client_secret="GOCSPX-abcdefghij")
    a = connectors.finish(r["session"], "state=ST&code=abc")
    conf = connectors._conf().read_text()
    assert a["own_client"] and "type = google photos" in conf and "read_only = false" in conf and "client_id = 123-abc" in conf


def test_cancel_stops_the_listener(conn):
    r = connectors.start("drive")
    assert connectors.cancel(r["session"]) == {"ok": True}
    assert conn["procs"][-1].killed and not connectors._SESSIONS


def test_old_sign_ins_expire(conn, monkeypatch):
    r = connectors.start("drive")
    connectors._SESSIONS[r["session"]]["started"] -= connectors.AUTH_TIMEOUT + 1
    with pytest.raises(connectors.ConnectError, match="expired"):
        connectors.finish(r["session"], "state=ST&code=abc")


# ------------------------------------------------------------------ managing connections
def _account(conn, service="drive"):
    r, _ = _sign_in(conn, service)
    return connectors.finish(r["session"], "state=ST&code=abc")


def test_rename_and_disconnect(conn):
    a = _account(conn)
    assert connectors.rename(a["id"], "  Backups\n ")["label"] == "Backups"
    with pytest.raises(connectors.ConnectError, match="name"):
        connectors.rename(a["id"], "   ")
    with pytest.raises(connectors.ConnectError, match="doesn't exist"):
        connectors.rename("zz", "x")
    r = connectors.disconnect(a["id"])
    assert r["revoke"].startswith("https://myaccount.google.com/") and connectors._read_conf() == {}
    with pytest.raises(connectors.ConnectError, match="doesn't exist"):
        connectors.disconnect(a["id"])


def test_browse_drive_and_the_photos_root(conn):
    d = _account(conn)
    conn["on"]("lsjson", out=[{"Name": "b.txt", "IsDir": False, "Size": 3, "ModTime": "t"}, {"Name": "Docs", "IsDir": True, "Size": -1}])
    r = connectors.browse(d["id"], "/Work/")
    assert r["path"] == "Work" and [e["name"] for e in r["entries"]] == ["Docs", "b.txt"] and r["entries"][0]["size"] is None
    assert f"c_{d['id']}:Work" in conn["calls"][-1]
    conn["on"]("lsjson", rc=3, err="ERROR : error listing: directory not found")
    assert connectors.browse(d["id"], "Gone")["entries"] == []
    conn["on"]("lsjson", rc=1, err="ERROR : couldn't connect: 401")
    with pytest.raises(connectors.ConnectError, match="401"):
        connectors.browse(d["id"], "")
    with pytest.raises(connectors.ConnectError, match="isn't allowed"):
        connectors.browse(d["id"], "a/../b")
    conn["rules"].clear()
    p = _account(conn, "photos")
    root = connectors.browse(p["id"], "")
    assert [e["name"] for e in root["entries"]] == ["album", "upload", "media"]


@pytest.fixture
def run_jobs(monkeypatch):
    done = []

    class Log:
        def __init__(self):
            self.lines, self.pct = [], []

        def __call__(self, line):
            self.lines.append(line)

        def progress(self, pct, stage=None):
            self.pct.append((pct, stage))

    def launch_fn(title, fn, meta=None):
        log = Log()
        try:
            res = fn(log)
            err = None
        except Exception as exc:  # noqa: BLE001
            res, err = None, exc
        done.append({"title": title, "log": log, "result": res, "error": err, "meta": meta})

        class J:
            id = "job1"
        return J()

    monkeypatch.setattr(jobs, "launch_fn", launch_fn)
    return done


def test_drive_push_and_pull_copy_without_deleting(conn, run_jobs, files_root):
    d = _account(conn)
    (files_root / "site").mkdir()
    (files_root / "site" / "a.html").write_text("x")
    conn["copy_lines"] = ["2026/11/03 11:00:00 NOTICE: Transferred:   1 KiB / 2 KiB, 50%, 1 KiB/s, ETA 1s", "2026/11/03 11:00:01 INFO  : a.html: Copied (new)"]
    assert connectors.transfer(d["id"], "push", str(files_root / "site"), "Backups") == {"job": "job1"}
    j = run_jobs[-1]
    argv = conn["procs"][-1].argv
    assert argv[argv.index("copy") + 1:argv.index("copy") + 3] == [str(files_root / "site"), f"c_{d['id']}:Backups/site"]
    assert "sync" not in argv and "--delete" not in " ".join(argv)
    assert j["error"] is None and (50, j["log"].pct[1][1]) == j["log"].pct[1] and j["log"].lines[-1] == "✓ Done"
    assert "a.html: Copied (new)" in j["log"].lines
    connectors.transfer(d["id"], "pull", str(files_root), "Backups/site")
    argv = conn["procs"][-1].argv
    assert argv[argv.index("copy") + 1:argv.index("copy") + 3] == [f"c_{d['id']}:Backups/site", str(files_root / "site")]
    connectors.transfer(d["id"], "pull", str(files_root), "")
    assert conn["procs"][-1].argv[conn["procs"][-1].argv.index("copy") + 2] == str(files_root / "Google Drive")
    conn["copy_rc"] = 1
    connectors.transfer(d["id"], "push", str(files_root / "site" / "a.html"), "")
    assert "exit code 1" in str(run_jobs[-1]["error"])


def test_transfer_checks(conn, run_jobs, files_root):
    d = _account(conn)
    with pytest.raises(connectors.ConnectError, match="Push"):
        connectors.transfer(d["id"], "mirror", str(files_root), "")
    with pytest.raises(connectors.ConnectError, match="Pick a file"):
        connectors.transfer(d["id"], "push", " ", "")
    with pytest.raises(connectors.ConnectError, match="doesn't exist"):
        connectors.transfer(d["id"], "push", str(files_root / "missing"), "")
    (files_root / "f.txt").write_text("x")
    with pytest.raises(connectors.ConnectError, match="into a folder"):
        connectors.transfer(d["id"], "pull", str(files_root / "f.txt"), "x")
    with pytest.raises(connectors.ConnectError, match="limited"):
        connectors.transfer(d["id"], "push", "/etc/shadow", "")
    with pytest.raises(connectors.ConnectError, match="doesn't exist"):
        connectors.transfer("nope", "push", str(files_root), "")


def test_photos_push_goes_into_upload_or_an_album_and_only_media(conn, run_jobs, files_root):
    p = _account(conn, "photos")
    (files_root / "pics").mkdir()
    with pytest.raises(connectors.ConnectError, match="album/<name>"):
        connectors.transfer(p["id"], "push", str(files_root / "pics"), "media/all")
    with pytest.raises(connectors.ConnectError, match="pull from an album"):
        connectors.transfer(p["id"], "pull", str(files_root), "upload")
    connectors.transfer(p["id"], "push", str(files_root / "pics"), "album/Summer 2026")
    argv = conn["procs"][-1].argv
    assert argv[argv.index("copy") + 2] == f"c_{p['id']}:album/Summer 2026" and "--include" in argv
    connectors.transfer(p["id"], "pull", str(files_root), "album/Summer 2026")
    argv = conn["procs"][-1].argv
    assert "--ignore-existing" in argv and argv[argv.index("copy") + 2] == str(files_root / "Summer 2026")


# ------------------------------------------------------------------ API
def test_api(admin, conn):
    r = admin.get("/api/connect")
    assert r.status_code == 200 and r.json()["rclone"] is True and [s["id"] for s in r.json()["services"]] == ["drive", "photos"]
    assert admin.post("/api/connect/start", json={"service": "dropbox"}).status_code == 400
    s = admin.post("/api/connect/start", json={"service": "drive"}).json()
    assert s["url"] == GOOGLE
    proc = conn["procs"][-1]
    conn["on_code"] = lambda: proc.feed("--->", json.dumps(TOKEN), "<---End paste")
    a = admin.post("/api/connect/finish", json={"session": s["session"], "auth_response": "state=ST&code=abc"}).json()
    assert a["service"] == "drive" and "ya29" not in json.dumps(a)
    assert admin.post(f"/api/connect/{a['id']}/rename", json={"label": "Mine"}).json()["label"] == "Mine"
    conn["on"]("lsjson", out=[])
    assert admin.get(f"/api/connect/{a['id']}/browse?path=").json()["entries"] == []
    assert admin.post(f"/api/connect/{a['id']}/transfer", json={"direction": "push", "local": "/etc/shadow", "remote": ""}).status_code == 400
    assert admin.post("/api/connect/cancel", json={"session": "x"}).json() == {"ok": True}
    assert admin.post("/api/connect/finish", json={"session": "x", "auth_response": "y"}).status_code == 400
    assert admin.delete(f"/api/connect/{a['id']}").json()["ok"] is True
