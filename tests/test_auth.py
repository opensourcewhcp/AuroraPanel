"""First sign-in (installer's random password), login, sessions, throttle."""
import os
import sys

import pytest

from conftest import ADMIN, PASSWORD
from backend import auth, config


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
    tok = admin.cookies.get(auth.COOKIE_NAME)
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
    assert auth.COOKIE_NAME in r.cookies
    assert client.get("/api/me").json()["username"] == ADMIN


def test_logout_and_bad_tokens(admin):
    assert admin.get("/api/me").status_code == 200
    admin.post("/api/logout")
    admin.cookies.clear()
    assert admin.get("/api/me").status_code == 401
    admin.cookies.set(auth.COOKIE_NAME, "garbage")
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
