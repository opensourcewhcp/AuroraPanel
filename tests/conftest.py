"""Shared test setup.

Every test runs against a throwaway panel config (admin account, session
secret, 2FA) in a temp folder, and a File Manager confined to a temp folder,
so running the suite — even as root on a real Pi — never touches the real
install's login, settings or files.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Must be set before backend.files is imported (it reads it at import time).
_FILES_TMP = Path(os.environ.setdefault("AURORA_TEST_TMP", str(ROOT / ".pytest-tmp"))) / "files-root"
_FILES_TMP.mkdir(parents=True, exist_ok=True)
os.environ["AURORA_FILE_ROOT"] = str(_FILES_TMP)

from backend import config  # noqa: E402

ADMIN, PASSWORD = "tester", "correct-horse-battery"


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "aurora_config.json")
    from backend import audit
    monkeypatch.setattr(audit, "LOG", tmp_path / "audit.jsonl")  # the suite's requests never land in the real Activity Log
    yield


@pytest.fixture
def files_root():
    for p in sorted(_FILES_TMP.rglob("*"), reverse=True):
        p.unlink() if p.is_file() or p.is_symlink() else p.rmdir()
    return _FILES_TMP


@pytest.fixture
def app_module():
    from backend import app as app_mod
    app_mod._login_fails.clear()
    return app_mod


@pytest.fixture
def client(app_module):
    from fastapi.testclient import TestClient
    return TestClient(app_module.app)


@pytest.fixture
def admin(client):
    """A client signed in as the owner (with a password of their own, not the installer's)."""
    config.set_credentials(ADMIN, PASSWORD)
    r = client.post("/api/login", json={"username": ADMIN, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return client
