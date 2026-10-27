"""Reverse proxy target parsing and config building (pure logic).

create/list/delete go through sites.py + Apache, so they are integration-tested on the Pi, not here.
"""
import pytest

from backend import proxysites


@pytest.mark.parametrize("inp,out", [
    ("3000", "http://127.0.0.1:3000"),
    ("localhost:3000", "http://localhost:3000"),
    ("127.0.0.1:8080", "http://127.0.0.1:8080"),
    ("http://10.0.0.5:9000", "http://10.0.0.5:9000"),
    ("https://backend:8443", "https://backend:8443"),
    ("example.internal", "http://example.internal"),
    ("  localhost:5000/  ", "http://localhost:5000"),
])
def test_target_url_ok(inp, out):
    assert proxysites._target_url(inp) == out


@pytest.mark.parametrize("bad", ["", "   ", "99999", "0", "http://", "ht!tp://x", "host:0", "host:70000"])
def test_target_url_bad(bad):
    with pytest.raises(proxysites.ProxyError):
        proxysites._target_url(bad)


def test_custom_and_parse_roundtrip():
    c = proxysites._custom("http://127.0.0.1:3000", True)
    assert "ProxyPass / http://127.0.0.1:3000/ upgrade=websocket" in c
    assert "ProxyPass /.well-known/acme-challenge/ !" in c
    assert proxysites.MARKER in c
    assert proxysites._parse(c) == {"target": "http://127.0.0.1:3000", "websockets": True}


def test_custom_https_and_no_ws():
    c = proxysites._custom("https://api:8443", False)
    assert "SSLProxyEngine On" in c
    assert "upgrade=websocket" not in c
    assert proxysites._parse(c) == {"target": "https://api:8443", "websockets": False}


def test_parse_handles_non_proxy():
    assert proxysites._parse("just a normal vhost") == {"target": "", "websockets": False}
