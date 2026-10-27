"""backend.serve: uvicorn plus an http → https redirect on the same port."""
import http.client
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time

import pytest

from backend import serve


def test_redirect_keeps_host_and_path():
    r = serve.redirect_response(b"GET /a/b?c=1#x HTTP/1.1\r\nHost: pi.local:8088\r\nAccept: */*\r\n\r\n", "1.2.3.4:8088")
    head, body = r.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    assert lines[0] == b"HTTP/1.1 307 Temporary Redirect"
    assert b"Location: https://pi.local:8088/a/b?c=1#x" in lines
    assert b"Connection: close" in lines and b"Cache-Control: no-store" in lines
    assert int(dict(l.split(b": ", 1) for l in lines[1:])[b"Content-Length"]) == len(body)


def test_redirect_falls_back_without_a_clean_host():
    assert b"Location: https://10.0.0.5:8088/\r\n" in serve.redirect_response(b"GET / HTTP/1.0\r\n\r\n", "10.0.0.5:8088")
    # header injection in Host or an odd target never reaches the Location line
    r = serve.redirect_response(b"GET /x HTTP/1.1\r\nHost: evil\r\nX: y\r\n\r\n", "10.0.0.5:8088")
    assert b"Location: https://evil/x" in r
    r = serve.redirect_response(b"GET /x HTTP/1.1\r\nHost: a b\r\n\r\n", "10.0.0.5:8088")
    assert b"Location: https://10.0.0.5:8088/x" in r
    r = serve.redirect_response(b"GET http://proxy/x HTTP/1.1\r\nHost: pi:8088\r\n\r\n", "f")
    assert b"Location: https://pi:8088/\r\n" in r


def test_garbage_gets_no_answer():
    assert serve.redirect_response(b"\x00\x01\x02", "h") is None
    assert serve.redirect_response(b"SSH-2.0-OpenSSH\r\n", "h") is None
    assert serve.redirect_response(b"BREW / HTCPCP/1.0\r\n\r\n", "h") is None


def _openssl():
    return shutil.which("openssl") or next((p for p in (r"C:\Program Files\Git\usr\bin\openssl.exe",) if os.path.isfile(p)), None)


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    exe = _openssl()
    if not exe:
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("tls")
    crt, key = d / "c.pem", d / "k.pem"
    subprocess.run([exe, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", str(key), "-out", str(crt), "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)
    return str(crt), str(key)


async def _app(scope, receive, send):
    assert scope["type"] == "http"
    body = f"hello {scope['client'][0]} {scope['path']}".encode()
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


@pytest.fixture
def front(cert):
    import uvicorn
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    cfg = uvicorn.Config(_app, host="127.0.0.1", port=port, ssl_certfile=cert[0], ssl_keyfile=cert[1], log_level="warning", lifespan="off")
    srv = serve.Front(cfg)
    t = threading.Thread(target=srv.run, daemon=True); t.start()
    for _ in range(100):
        if srv.started: break
        time.sleep(0.05)
    assert srv.started
    yield port
    srv.should_exit = True
    t.join(5)
    assert not t.is_alive()


def test_plain_http_is_redirected_and_tls_is_served(front):
    c = http.client.HTTPConnection("127.0.0.1", front, timeout=5)
    c.request("GET", "/panel?x=1", headers={"Host": f"pi.lan:{front}"})
    r = c.getresponse()
    assert r.status == 307 and r.getheader("Location") == f"https://pi.lan:{front}/panel?x=1"
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    c2 = http.client.HTTPSConnection("127.0.0.1", front, timeout=5, context=ctx)
    c2.request("GET", "/hi")
    r2 = c2.getresponse()
    assert r2.status == 200 and r2.read() == b"hello 127.0.0.1 /hi"  # uvicorn saw the real client address
    # garbage is dropped without an answer
    with socket.create_connection(("127.0.0.1", front), timeout=5) as s:
        s.sendall(b"\x00\x00\x00junk\r\n\r\n")
        assert s.recv(100) == b""
