"""Update check: version ordering (a wrong order means Pis never get offered an update)."""
from backend import version


def test_numeric_order():
    k = version._key
    assert k("1.0.10-beta") > k("1.0.9-beta")
    assert k("1.1.0-beta") > k("1.0.10-beta")
    assert k("1.0.0") > k("1.0.0-beta")  # a final release beats its beta


def test_current_version_is_valid():
    assert version._key(version.VERSION)


# ---- going back to a kept version (Preferences → About & Updates → Go back) ----
import subprocess

import pytest


def test_rollbacks_lists_saved_copies_newest_first(tmp_path, monkeypatch):
    monkeypatch.setattr(version, "UPDATE_DIR", str(tmp_path))
    for name in ("backup-1.0.9-beta.tgz", "backup-1.1.2.tgz", "backup-1.1.10.tgz", f"backup-{version.VERSION}.tgz",
                 "backup-junk.tgz", "pre-fresh-20261021.tgz", "aurorapanel-1.1.2.zip"):
        (tmp_path / name).write_bytes(b"x")
    got = version.rollbacks()
    assert [r["version"] for r in got] == ["1.1.10", "1.1.2", "1.0.9-beta"]  # semver order, the running one left out
    assert all(r["label"] == "v" + r["version"] and r["size"] == 1 and r["saved"] > 0 for r in got)
    assert version.info()["rollbacks"] == got


def test_rollbacks_is_empty_without_an_updates_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(version, "UPDATE_DIR", str(tmp_path / "nope"))
    assert version.rollbacks() == []


def test_rollback_refuses_unknown_version_and_a_running_update(tmp_path, monkeypatch):
    monkeypatch.setattr(version, "UPDATE_DIR", str(tmp_path))
    with pytest.raises(version.UpdateError, match="No saved copy"):
        version.apply_rollback("1.0.0")
    (tmp_path / "backup-1.0.0.tgz").write_bytes(b"x")
    monkeypatch.setattr(version, "_unit_active", lambda: True)
    with pytest.raises(version.UpdateError, match="already running"):
        version.apply_rollback("1.0.0")


def test_rollback_hands_off_to_the_background_unit(tmp_path, monkeypatch):
    monkeypatch.setattr(version, "UPDATE_DIR", str(tmp_path))
    (tmp_path / "backup-1.0.0.tgz").write_bytes(b"x")
    monkeypatch.setattr(version, "_unit_active", lambda: False)
    monkeypatch.setenv("AURORA_USER", "pi")
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert version.apply_rollback(" 1.0.0 ") == {"ok": True, "from": version.VERSION, "to": "1.0.0"}
    argv = seen["argv"]
    assert argv[:3] == ["systemd-run", "--quiet", "--collect"] and f"--unit={version.UPDATE_UNIT}" in argv
    assert "--setenv=SUDO_USER=pi" in argv
    assert argv[-4:] == [str(tmp_path / "backup-1.0.0.tgz"), version._install_dir(), version.VERSION, "1.0.0"]
    runner = (tmp_path / "run-rollback.sh").read_text(encoding="utf-8")
    assert "--exclude=./aurora_config.json" in runner  # today's password, 2FA and sessions survive
    assert "install.sh" in runner and "backup-$CUR.tgz" in runner  # installer re-run, the version left is kept

    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", "boom"))
    with pytest.raises(version.UpdateError, match="boom"):
        version.apply_rollback("1.0.0")


def test_update_status_shows_only_the_latest_run(tmp_path, monkeypatch):
    monkeypatch.setattr(version, "UPDATE_DIR", str(tmp_path))
    monkeypatch.setattr(version, "_unit_active", lambda: False)
    (tmp_path / "update.log").write_text(
        "== 2026-10-28T11:55 updating AuroraPanel 1.1.17 -> 1.1.18 in /x\n✔ updated to 1.1.18\n"
        "== 2026-10-28T11:56 rolling back AuroraPanel 1.1.18 -> 1.1.17 in /x\n• Restoring the files of 1.1.17\n✔ rolled back to 1.1.17\n",
        encoding="utf-8")
    s = version.update_status()
    assert s["running"] is False and s["version"] == version.VERSION
    assert s["log"][0].startswith("== ") and "rolling back" in s["log"][0] and s["log"][-1] == "✔ rolled back to 1.1.17"
    assert not any("updated to" in line for line in s["log"])


def test_rollback_routes(admin, tmp_path, monkeypatch):
    monkeypatch.setattr(version, "UPDATE_DIR", str(tmp_path))
    assert admin.get("/api/about").json()["rollbacks"] == []
    r = admin.post("/api/about/rollback", json={"version": "9.9.9"})
    assert r.status_code == 400 and "No saved copy" in r.json()["detail"]
    (tmp_path / "backup-1.0.0.tgz").write_bytes(b"x")
    assert [x["version"] for x in admin.get("/api/about").json()["rollbacks"]] == ["1.0.0"]
