"""Every API route: locked without a session, and no crash (HTTP 500) when called.

On a Pi this calls the real read-only pages (services, Apache sites, databases…),
so it shows which ones break on that system. Routes that only start work
(POST/PUT/DELETE) are checked for the login lock but never run.
"""
import sys

import pytest

from backend.app import app

PUBLIC = {"/", "/index.html", "/api/status", "/api/login", "/api/logout", "/api/net/confirm"}
# Slow (scans the whole disk), or reaches out to the internet.
SKIP_CALL = {"/api/diskusage", "/api/inodes", "/api/about/update", "/api/files/download", "/api/backups/download"}

ROUTES = sorted({(m, r.path) for r in app.routes if getattr(r, "methods", None) and r.path.startswith("/api/")
                 for m in r.methods if m in ("GET", "POST", "PUT", "DELETE")})
CALLABLE_GETS = [p for m, p in ROUTES if m == "GET" and "{" not in p and p not in SKIP_CALL]


@pytest.mark.parametrize("method,path", [r for r in ROUTES if r[1] not in PUBLIC])
def test_requires_login(client, method, path):
    url = path.replace("{", "").replace("}", "")  # any value for path parameters
    r = client.request(method, url, json={})
    assert r.status_code == 401, f"{method} {path} answered {r.status_code} without a session"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the panel's pages read a Linux system")
@pytest.mark.parametrize("path", CALLABLE_GETS)
def test_get_does_not_crash(admin, path):
    r = admin.get(path)
    assert r.status_code < 500, f"GET {path} → {r.status_code}: {r.text[:400]}"


def test_security_headers(client):
    r = client.get("/api/status")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"


def test_openapi_hidden(client):
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(p).status_code == 404
