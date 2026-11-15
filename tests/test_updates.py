"""System updates: apt's list parsed security-first, the cached status the About page and the
Updates page read, the automatic-updates config, and the routes behind them."""
import json
import subprocess

import pytest

from backend import updates

APT = """Listing... Done
openssl/trixie-security 3.5.1-1+deb13u2 arm64 [upgradable from: 3.5.1-1+deb13u1]
libssl3t64/trixie-security 3.5.1-1+deb13u2 arm64 [upgradable from: 3.5.1-1+deb13u1]
vim/trixie 2:9.1.1230-1 arm64 [upgradable from: 2:9.1.0-1]
N: There is 1 additional version. Please use the '-a' switch to see it
"""
NO_REBOOT = {"required": False, "packages": [], "kernel": "6.12", "boot": 0}
AUTO_OFF = {"installed": False, "enabled": False, "mode": "security", "reboot": False, "reboot_time": "04:00", "last": ""}


def _apt_present(monkeypatch, present=True):
    monkeypatch.setattr(updates.shutil, "which", lambda *a, **k: "/usr/bin/apt-get" if present else None)


def test_parse_upgradable_puts_security_fixes_first(monkeypatch):
    monkeypatch.setattr(updates, "_run", lambda argv, timeout=600: subprocess.CompletedProcess(argv, 0, APT, ""))
    pk = updates._parse_upgradable()
    assert [p["name"] for p in pk] == ["libssl3t64", "openssl", "vim"]
    assert [p["security"] for p in pk] == [True, True, False]
    assert pk[0] == {"name": "libssl3t64", "origin": "trixie-security", "to": "3.5.1-1+deb13u2", "from": "3.5.1-1+deb13u1",
                     "arch": "arm64", "security": True}


def test_refresh_caches_and_status_reads_the_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(updates, "CACHE", tmp_path / "updates.json")
    _apt_present(monkeypatch)
    calls = []

    def run(argv, timeout=600):
        calls.append(argv[0])
        return subprocess.CompletedProcess(argv, 0, APT if argv[0] == "apt" else "", "")
    monkeypatch.setattr(updates, "_run", run)
    d = updates.refresh()
    assert calls == ["apt-get", "apt"]  # lists refreshed, then listed
    assert d["total"] == 3 and d["security"] == 2 and d["checked"] > 0 and d["error"] == ""
    assert json.loads((tmp_path / "updates.json").read_text())["security"] == 2
    assert updates.refresh(update_lists=False)["total"] == 3 and calls[-1] == "apt"

    monkeypatch.setattr(updates, "reboot_info", lambda: NO_REBOOT)
    monkeypatch.setattr(updates, "auto_status", lambda: AUTO_OFF)
    s = updates.status()
    assert s["supported"] and s["total"] == 3 and s["security"] == 2 and s["running"] is None
    assert s["packages"][0]["security"] and s["auto"]["enabled"] is False and s["reboot"]["required"] is False


def test_refresh_without_apt_says_so(monkeypatch):
    _apt_present(monkeypatch, False)
    assert updates.refresh() == {"supported": False}


def test_cached_is_empty_until_the_first_check(tmp_path, monkeypatch):
    monkeypatch.setattr(updates, "CACHE", tmp_path / "missing.json")
    assert updates.cached() == {"checked": 0, "packages": [], "total": 0, "security": 0}
    (tmp_path / "missing.json").write_text("{not json")
    assert updates.cached()["total"] == 0


def test_a_busy_apt_lock_is_not_reported_as_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(updates, "CACHE", tmp_path / "updates.json")
    _apt_present(monkeypatch)

    def run(argv, timeout=600):
        if argv[0] == "apt-get":
            return subprocess.CompletedProcess(argv, 100, "", "E: Could not get lock /var/lib/apt/lists/lock")
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(updates, "_run", run)
    assert updates.refresh()["error"] == ""

    monkeypatch.setattr(updates, "_run", lambda argv, timeout=600: subprocess.CompletedProcess(argv, 100, "", "E: no network"))
    assert "no network" in updates.refresh()["error"]


def test_set_auto_checks_its_inputs():
    with pytest.raises(updates.UpdateError, match="security or all"):
        updates.set_auto(True, "weird")
    with pytest.raises(updates.UpdateError, match="04:00"):
        updates.set_auto(True, "security", True, "4am")


def test_set_auto_writes_debians_unattended_upgrades_config(tmp_path, monkeypatch):
    monkeypatch.setattr(updates, "AUTO_CONF", tmp_path / "20auto-upgrades")
    monkeypatch.setattr(updates, "UU_CONF", tmp_path / "52aurora-unattended")
    monkeypatch.setattr(updates.shutil, "which", lambda *a, **k: "/usr/bin/unattended-upgrade")
    r = updates.set_auto(True, "security", True, "03:30")
    assert r["ok"] and r["enabled"] and r["mode"] == "security" and r["reboot"] and r["reboot_time"] == "03:30"
    t = (tmp_path / "52aurora-unattended").read_text()
    assert "AURORA-MODE security" in t and 'Automatic-Reboot "true"' in t and 'Automatic-Reboot-Time "03:30"' in t
    assert "-updates" not in t  # security pockets only
    assert 'Unattended-Upgrade "1"' in (tmp_path / "20auto-upgrades").read_text()

    r = updates.set_auto(False, "all")
    assert r["enabled"] is False and r["mode"] == "all"
    assert 'Unattended-Upgrade "0"' in (tmp_path / "20auto-upgrades").read_text()
    assert "-updates" in (tmp_path / "52aurora-unattended").read_text()


def test_install_only_accepts_package_names(monkeypatch):
    launched = {}

    class Job:
        id = "j1"

    monkeypatch.setattr(updates.jobs, "find", lambda **kw: [])
    monkeypatch.setattr(updates.jobs, "launch_fn", lambda title, fn, meta=None: launched.update(title=title, meta=meta) or Job())
    j = updates.install(["openssl", "../evil", "a b"])
    assert j.id == "j1" and launched["meta"] == {"updates": "install"}


def test_updates_routes(admin, tmp_path, monkeypatch):
    monkeypatch.setattr(updates, "CACHE", tmp_path / "updates.json")
    (tmp_path / "updates.json").write_text(json.dumps({"checked": 1, "total": 1, "security": 1, "packages": [
        {"name": "openssl", "origin": "trixie-security", "to": "2", "from": "1", "arch": "arm64", "security": True}]}))
    _apt_present(monkeypatch)
    monkeypatch.setattr(updates, "reboot_info", lambda: {**NO_REBOOT, "required": True, "packages": ["linux-image"]})
    monkeypatch.setattr(updates, "auto_status", lambda: {**AUTO_OFF, "installed": True, "enabled": True})
    d = admin.get("/api/updates").json()
    assert d["security"] == 1 and d["packages"][0]["security"] and d["reboot"]["required"] and d["auto"]["enabled"]
    assert admin.post("/api/updates/auto", json={"enabled": True, "mode": "weird"}).status_code == 400


class _Log:
    """What a job hands to its function: a log, a progress bar and apt."""
    def __init__(self, answers):
        self.lines, self.calls, self.answers = [], [], list(answers)

    def __call__(self, text):
        self.lines.append(text)

    def progress(self, pct, stage=None):
        pass

    def apt(self, args, span=(0, 100), timeout=1800, env=None):
        self.calls.append(" ".join(args))
        return self.answers.pop(0) if self.answers else 0


def _install_fn(monkeypatch, names=None):
    got = {}
    monkeypatch.setattr(updates.jobs, "find", lambda **kw: [])
    monkeypatch.setattr(updates.jobs, "launch_fn", lambda title, fn, meta=None: got.update(fn=fn) or object())
    monkeypatch.setattr(updates.distro, "is_dnf", lambda: False)
    monkeypatch.setattr(updates, "refresh", lambda update_lists=True: {"total": 0})
    monkeypatch.setattr(updates, "reboot_info", lambda: {"required": False})
    updates.install(names)
    return got["fn"]


def test_half_installed_packages_are_read_from_dpkg(monkeypatch):
    out = "ii \tbash\t5.2\nrc \told-thing\t1\niF \tgoogle-cloud-cli\t593.0.0-0\niU \tfoo\t2\niH \tbar\t3\nun \tgone\t\nii \tzsh\t5.9\n"
    monkeypatch.setattr(updates, "_run", lambda argv, timeout=600: subprocess.CompletedProcess(argv, 0, out, ""))
    assert [(p["name"], p["state"]) for p in updates.unfinished()] == [("google-cloud-cli", "set-up failed"), ("foo", "unpacked, not set up"), ("bar", "half installed")]


def test_an_interrupted_install_is_finished_before_upgrading(monkeypatch):
    stuck = [[{"name": "google-cloud-cli", "version": "593", "state": "set-up failed"}]]
    ran = []
    monkeypatch.setattr(updates, "unfinished", lambda: stuck[0])

    def run(argv, timeout=600):
        ran.append(" ".join(argv))
        if argv[:2] == ["dpkg", "--configure"]:
            stuck[0] = []                       # setting it up again worked
        return subprocess.CompletedProcess(argv, 0, "Setting up google-cloud-cli (593) ...", "")
    monkeypatch.setattr(updates, "_run", run)
    log = _Log([0, 0])
    assert _install_fn(monkeypatch)(log)["ok"] is True
    assert ran[0] == "dpkg --configure -a --force-confdef --force-confold"
    assert log.calls[0] == "update" and log.calls[1].endswith("full-upgrade") and len(log.calls) == 2     # no second try needed
    assert any("left half-installed: google-cloud-cli (set-up failed)" in l for l in log.lines) and any("Repaired" in l for l in log.lines)


def test_a_failed_upgrade_is_repaired_and_tried_once_more(monkeypatch):
    stuck = [[]]
    monkeypatch.setattr(updates, "unfinished", lambda: stuck[0])

    def run(argv, timeout=600):
        if argv[:2] == ["dpkg", "--configure"]:
            stuck[0] = []
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(updates, "_run", run)
    log = _Log([0, 100, 0])                      # update fine, upgrade fails, second try fine

    def apt(args, span=(0, 100), timeout=1800, env=None, real=log.apt):
        rc = real(args, span, timeout, env)
        if rc == 100:
            stuck[0] = [{"name": "google-cloud-cli", "version": "593", "state": "set-up failed"}]   # what the failed run left behind
        return rc
    log.apt = apt
    assert _install_fn(monkeypatch)(log)["ok"] is True
    assert [c.split()[-1] for c in log.calls] == ["update", "full-upgrade", "full-upgrade"]
    assert any("Repairing and trying once more" in l for l in log.lines) and any("second try went through" in l for l in log.lines)


def test_when_the_repair_cannot_help_the_error_names_the_package(monkeypatch):
    stuck = [[]]
    monkeypatch.setattr(updates, "unfinished", lambda: stuck[0])
    monkeypatch.setattr(updates, "_run", lambda argv, timeout=600: subprocess.CompletedProcess(argv, 1, "", "post-installation script subprocess returned error exit status 1"))
    log = _Log([0, 100, 100, 100])

    def apt(args, span=(0, 100), timeout=1800, env=None, real=log.apt):
        rc = real(args, span, timeout, env)
        if rc == 100:
            stuck[0] = [{"name": "google-cloud-cli", "version": "593", "state": "set-up failed"}]
        return rc
    log.apt = apt
    with pytest.raises(updates.UpdateError, match="google-cloud-cli could not be set up, even after a repair and a second try"):
        _install_fn(monkeypatch, ["google-cloud-cli"])(log)
    assert any(c.endswith("-f install") for c in log.calls)                                               # apt was asked to repair too
    assert sum(1 for c in log.calls if "--only-upgrade" in c) == 2                                        # exactly one retry, no loop
