"""First sign-in (installer's random password), login, sessions, throttle."""
import os
import sys

import pytest

from conftest import ADMIN, PASSWORD
from backend import auth, config
from fastapi.testclient import TestClient


def test_no_way_to_claim_a_fresh_panel(client):
    # A panel nobody has signed in to can't be taken over by whoever finds it first.
    assert client.get("/api/status").json()["initialized"] is False
    assert client.post("/api/setup", json={"username": "evil", "password": PASSWORD}).status_code in (404, 405)
    assert config.is_initialized() is False


def test_initial_password_made_once():
    user, pw = config.ensure_initial_credentials()
    assert user == "admin" and len(pw) == 23 and pw.count("-") == 3
    assert config.verify_credentials("admin", pw) and config.must_change_password()
    saved = config.initial_password_path().read_text(encoding="utf-8")
    assert f"password: {pw}" in saved
    if not sys.platform.startswith("win"):
        assert os.stat(config.initial_password_path()).st_mode & 0o077 == 0
        assert os.stat(config.CONFIG_PATH).st_mode & 0o077 == 0
    assert config.ensure_initial_credentials() is None  # never overwrites an account
    assert config.random_password() != pw


def test_first_login_must_change_password(client):
    _, pw = config.ensure_initial_credentials()
    assert client.get("/api/status").json()["first_login"] is True
    assert client.post("/api/login", json={"username": "admin", "password": pw}).status_code == 200
    me = client.get("/api/me").json()
    assert me["must_change_password"] is True
    # Nothing else opens until it's replaced — pages, actions, API tokens, the terminal.
    for method, path in [("GET", "/api/overview"), ("GET", "/api/apitokens"), ("POST", "/api/apitokens"),
                         ("GET", "/api/panel-users"), ("POST", "/api/account/rename")]:
        r = client.request(method, path, json={"name": "x", "username": "x"})
        assert r.status_code == 403 and r.json()["detail"] == "password_change_required", (method, path)
    # The same password again, or too short, is refused.
    assert client.post("/api/account/password", json={"current": pw, "new_password": pw}).status_code == 400
    assert client.post("/api/account/password", json={"current": pw, "new_password": "short"}).status_code == 400
    r = client.post("/api/account/password", json={"current": pw, "new_password": PASSWORD})
    assert r.status_code == 200
    assert client.get("/api/me").json()["must_change_password"] is False
    assert client.get("/api/status").json()["first_login"] is False
    assert not config.initial_password_path().exists()
    assert client.get("/api/panel-users").status_code == 200
    assert not config.verify_credentials("admin", pw)


def test_reset_password_keeps_username_and_signs_out(admin):
    tok = admin.cookies.get(auth.COOKIE_NAME_HTTP)  # the test client speaks plain http
    user, pw = config.issue_temporary_password()
    assert user == ADMIN and config.must_change_password()
    assert auth.verify_token(tok) is None  # every old session is gone
    assert config.verify_credentials(ADMIN, pw)


@pytest.mark.skipif(sys.platform.startswith("win"), reason="file modes")
def test_lock_down_old_world_readable_config():
    config.CONFIG_PATH.write_text("{}", encoding="utf-8")
    os.chmod(config.CONFIG_PATH, 0o644)
    config.lock_down()
    assert os.stat(config.CONFIG_PATH).st_mode & 0o777 == 0o600


def test_login_wrong_and_right(client):
    config.set_credentials(ADMIN, PASSWORD)
    assert client.post("/api/login", json={"username": ADMIN, "password": "nope-nope"}).status_code == 401
    assert client.post("/api/login", json={"username": "other", "password": PASSWORD}).status_code == 401
    r = client.post("/api/login", json={"username": ADMIN, "password": PASSWORD})
    assert r.status_code == 200
    assert auth.COOKIE_NAME_HTTP in r.cookies  # plain http gets the http cookie name
    assert auth.COOKIE_NAME not in r.cookies
    assert client.get("/api/me").json()["username"] == ADMIN


def test_https_cookie_still_accepted_over_http(client):
    """A session issued over https (the Secure cookie name) keeps working, and so does a plain http
    session: both names are read, so turning Panel HTTPS off never leaves the browser locked out."""
    config.set_credentials(ADMIN, PASSWORD)
    client.cookies.set(auth.COOKIE_NAME, auth.issue_token(ADMIN))
    assert client.get("/api/me").json()["username"] == ADMIN
    client.cookies.clear()
    client.cookies.set(auth.COOKIE_NAME_HTTP, auth.issue_token(ADMIN))
    assert client.get("/api/me").json()["username"] == ADMIN
    r = client.post("/api/logout")
    assert all(n in r.headers.get("set-cookie", "") for n in auth.COOKIE_NAMES)  # both names cleared


def test_logout_and_bad_tokens(admin):
    assert admin.get("/api/me").status_code == 200
    admin.post("/api/logout")
    admin.cookies.clear()
    assert admin.get("/api/me").status_code == 401
    for name in auth.COOKIE_NAMES:
        admin.cookies.clear()
        admin.cookies.set(name, "garbage")
        assert admin.get("/api/me").status_code == 401


def test_token_signature_and_rotation():
    config.set_credentials(ADMIN, PASSWORD)
    tok = auth.issue_token(ADMIN)
    assert auth.verify_token(tok) == ADMIN
    payload, sig = tok.rsplit(".", 1)
    assert auth.verify_token(payload + "." + ("0" * len(sig))) is None
    # Changing the password rotates the secret: old sessions stop working.
    config.change_password("another-long-password")
    assert auth.verify_token(tok) is None


def test_login_throttle(client, app_module):
    config.set_credentials(ADMIN, PASSWORD)
    for _ in range(app_module._LOGIN_MAX_FAILS):
        assert client.post("/api/login", json={"username": ADMIN, "password": "wrong-pass"}).status_code == 401
    r = client.post("/api/login", json={"username": ADMIN, "password": PASSWORD})
    assert r.status_code == 429  # even the right password waits once the limit is hit


def test_2fa_enrol_has_a_qr_code_named_after_the_server():
    config.set_credentials(ADMIN, PASSWORD)
    from backend import twofa
    d = twofa.begin_enroll(ADMIN)
    assert d["qr"].startswith("data:image/svg+xml") and d["issuer"].startswith("AuroraPanel ")
    assert d["otpauth_uri"].startswith("otpauth://totp/AuroraPanel%20") and f"secret={d['secret']}" in d["otpauth_uri"]


def _otp(step_offset=0):
    """The current authenticator code for the test panel's secret."""
    import time
    from backend import twofa
    secret = config.load_config()["totp_secret"]
    return twofa._code_at(secret, int(time.time() // 30) + step_offset)


def test_2fa_on_asks_for_code_right_away_and_off_is_plain_login(admin):
    from backend import twofa
    twofa.begin_enroll(ADMIN)
    r = admin.post("/api/2fa/enable", json={"code": _otp(-1)})  # the three steps in the window, used in order
    assert r.status_code == 200 and r.json()["relogin"]
    assert admin.get("/api/me").status_code == 401  # this browser too: every session is gone
    admin.cookies.clear()
    r = admin.post("/api/login", json={"username": ADMIN, "password": PASSWORD})
    assert r.status_code == 401 and r.json()["detail"] == "otp_required"
    code = _otp(0)  # a fresh step: the enable call used up the previous one
    assert admin.post("/api/login", json={"username": ADMIN, "password": PASSWORD, "otp": code}).status_code == 200
    assert admin.get("/api/me").status_code == 200
    # A code is single use: the same one again is refused.
    other = TestClient(admin.app)
    assert other.post("/api/login", json={"username": ADMIN, "password": PASSWORD, "otp": code}).status_code == 401
    # Off again: password alone signs in.
    assert admin.post("/api/2fa/disable", json={"code": _otp(1)}).status_code == 200
    other.cookies.clear()
    assert other.post("/api/login", json={"username": ADMIN, "password": PASSWORD}).status_code == 200
    assert other.get("/api/me").json()["username"] == ADMIN


def test_cookie_sessions_refuse_cross_origin_writes(admin):
    """A page on another origin (a hacked website on the same domain, say) can't use the cookie."""
    assert admin.post("/api/logout", headers={"origin": "https://evil.example"}).status_code == 403
    assert admin.post("/api/logout", headers={"origin": "null"}).status_code == 403
    assert admin.get("/api/me", headers={"origin": "https://evil.example"}).status_code == 200  # reads are harmless (CORS)
    assert admin.get("/api/me", headers={"origin": "http://testserver"}).status_code == 200
    assert admin.post("/api/logout", headers={"origin": "http://testserver"}).status_code == 200
    assert admin.get("/api/me").status_code == 401


def test_api_tokens_ignore_origin(admin):
    from backend import apitokens
    tok = apitokens.create("ci")["token"]
    c = TestClient(admin.app)
    assert c.post("/api/logout", headers={"authorization": f"Bearer {tok}", "origin": "https://evil.example"}).status_code == 200
