"""Servers: http or https, whichever the other panel speaks, without ever sending a token over plain http to the internet.
The plain-HTTP cases use a real server on this machine, so the TLS failure is the real one."""
from __future__ import annotations

import json
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from backend import servers


class _Panel(BaseHTTPRequestHandler):
    """An AuroraPanel without Panel HTTPS: plain HTTP only."""

    def do_GET(self):
        ok = self.path == "/api/fleet/self" and self.headers.get("Authorization") == "Bearer aur_good"
        body = json.dumps({"hostname": "ns2"} if ok else {"detail": "Authentication required"}).encode()
        self.send_response(200 if ok else 401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def plain_panel(tmp_path, monkeypatch):
    monkeypatch.setattr(servers, "STATE", tmp_path / "servers.json")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Panel)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_a_panel_without_https_on_your_network_is_added_over_http(plain_panel):
    shown = servers.add("ns2", f"127.0.0.1:{plain_panel}", "aur_good")
    assert shown["url"] == f"http://127.0.0.1:{plain_panel}" and shown["hostname"] == "ns2"
    assert servers.overview()["servers"][1]["ok"] is True


def test_typing_https_for_it_works_too_and_a_wrong_token_is_still_refused(plain_panel):
    with pytest.raises(servers.ServerError, match="didn't accept the token"):
        servers.add("ns2", f"https://127.0.0.1:{plain_panel}", "aur_wrong")
    assert servers.add("ns2", f"https://127.0.0.1:{plain_panel}", "aur_good")["url"].startswith("http://")


def test_a_panel_without_https_on_the_internet_is_refused(plain_panel, monkeypatch):
    real = servers._parse

    def as_if_public(url):
        if url.startswith("http://"):
            raise servers.ServerError("Plain http:// would send the token unencrypted over the internet — use https://")
        return real(url)
    monkeypatch.setattr(servers, "_parse", as_if_public)
    with pytest.raises(servers.ServerError, match=r"answers plain HTTP\. Turn on HTTPS there"):
        servers.add("vps", f"127.0.0.1:{plain_panel}", "aur_good")
    assert servers.count() == 0


def test_a_saved_https_server_is_never_moved_back_to_plain_http(plain_panel):
    servers._save({"servers": [{"id": "a1", "name": "ns2", "url": f"https://127.0.0.1:{plain_panel}", "token": "aur_good",
                                "fingerprint": "ab" * 32}]})
    row = servers.overview()["servers"][1]
    assert row["ok"] is False and "answers plain HTTP now" in row["error"]
    assert servers._load()["servers"][0]["url"].startswith("https://")


# A panel that turned Panel HTTPS on: plain http gets a 307 to https on the same port (backend/serve.py).
class _Resp:
    def __init__(self, status, raw=b"", location=""):
        self.status, self._raw, self._loc = status, raw, location

    def read(self, n=None):
        return self._raw

    def getheader(self, name, default=None):
        return self._loc if name == "Location" else default


@pytest.fixture
def moved(tmp_path, monkeypatch):
    monkeypatch.setattr(servers, "STATE", tmp_path / "servers.json")
    monkeypatch.setattr(servers.socket, "gethostbyname", lambda h: "192.168.0.102")
    made = []

    class Conn:
        def __init__(self, host, port, timeout=None, context=None):
            self.https = context is not None
            self.sock = types.SimpleNamespace(getpeercert=lambda binary_form=True: b"ns2-cert")
            made.append(self)

        def connect(self):
            pass

        def request(self, *a, **k):
            pass

        def getresponse(self):
            if self.https:
                return _Resp(200, b'{"hostname": "ns2"}')
            return _Resp(307, location="https://ns2.lan:8088/api/fleet/self")

        def close(self):
            pass
    monkeypatch.setattr(servers.http.client, "HTTPSConnection", Conn)
    monkeypatch.setattr(servers.http.client, "HTTPConnection", Conn)
    return made


def test_adding_with_http_follows_a_panel_that_has_https(moved):
    shown = servers.add("ns2", "http://ns2.lan:8088", "aur_good")
    assert shown["url"] == "https://ns2.lan:8088" and shown["fingerprint"]


def test_a_saved_http_server_that_turns_https_on_moves_to_https_and_is_remembered(moved):
    servers._save({"servers": [{"id": "a1", "name": "ns2", "url": "http://ns2.lan:8088", "token": "aur_good"}]})
    assert servers.overview()["servers"][1]["ok"] is True
    saved = servers._load()["servers"][0]
    assert saved["url"] == "https://ns2.lan:8088" and saved["fingerprint"] and "_moved" not in saved
    assert servers.ban_everywhere("1.2.3.4", "test", None)["ns2"]["ok"] is True


def test_a_redirect_somewhere_else_is_not_followed(moved, monkeypatch):
    monkeypatch.setattr(_Resp, "getheader", lambda self, n, d=None: "https://elsewhere.example:8088/")
    with pytest.raises(servers.ServerError, match="answered 307"):
        servers.add("ns2", "http://ns2.lan:8088", "aur_good")
