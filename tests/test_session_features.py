"""Previous-build pruning, account rename, user deletion with a backup, SSH two-factor plumbing, remote mail
accounts, the inbox feed, the exported security report and the contact suggestions."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from backend import mail, secreport, sshtwofa, users, version


# ----------------------------------------------------------------------------- previous build
def test_prune_keeps_only_the_build_you_came_from(tmp_path, monkeypatch):
    monkeypatch.setattr(version, "UPDATE_DIR", str(tmp_path))
    old = tmp_path / "backup-1.1.2.tgz"; old.write_bytes(b"x"); os.utime(old, (1000, 1000))
    newest = tmp_path / "backup-1.1.10.tgz"; newest.write_bytes(b"x"); os.utime(newest, (5000, 5000))
    mid = tmp_path / "backup-1.1.16.tgz"; mid.write_bytes(b"x"); os.utime(mid, (3000, 3000))   # higher number, older save
    (tmp_path / f"backup-{version.VERSION}.tgz").write_bytes(b"x")   # the running build's own snapshot stays
    (tmp_path / "aurorapanel-1.1.10.zip").write_bytes(b"x")
    (tmp_path / "staging-abc").mkdir(); (tmp_path / "staging-abc" / "f").write_bytes(b"x")
    (tmp_path / "update.log").write_text("log", encoding="utf-8")
    r = version.prune_updates()
    assert r["kept"] == ["backup-1.1.10.tgz"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["backup-1.1.10.tgz", f"backup-{version.VERSION}.tgz", "update.log"]
    assert [x["version"] for x in version.rollbacks()] == ["1.1.10"]


def test_snapshot_of_the_running_build_is_taken_once(tmp_path, monkeypatch):
    monkeypatch.setattr(version, "UPDATE_DIR", str(tmp_path / "updates"))
    src = tmp_path / "install"; (src / "backend").mkdir(parents=True); (src / "backend" / "x.py").write_text("1", encoding="utf-8")
    (src / ".venv").mkdir(); (src / ".venv" / "big").write_bytes(b"0" * 10)
    monkeypatch.setattr(version, "_install_dir", lambda: str(src))
    import shutil
    if not shutil.which("tar"):
        pytest.skip("tar")
    out = version.snapshot_current()
    assert out and out.endswith(f"backup-{version.VERSION}.tgz") and version.snapshot_current() is None
    import tarfile
    names = tarfile.open(out).getnames()
    assert any(n.endswith("backend/x.py") for n in names) and not any(".venv" in n for n in names)
    assert version.rollbacks() == []   # the running build is never offered as a step back


def test_prune_without_an_updates_folder_is_a_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(version, "UPDATE_DIR", str(tmp_path / "nope"))
    assert version.prune_updates() == {"kept": [], "removed": []}


# ----------------------------------------------------------------------------- rename
def test_rename_keeps_the_owner_signed_in(admin):
    me = admin.get("/api/me").json()["username"]
    r = admin.post("/api/account/rename", json={"username": "Renamed.Owner"})
    assert r.status_code == 200 and r.json()["username"] == "renamed.owner"
    assert "set-cookie" in {k.lower() for k in r.headers}   # a fresh session for the new name
    assert admin.get("/api/me").json()["username"] == "renamed.owner"
    assert admin.get("/api/account/prefs").json()["username"] == "renamed.owner"
    for bad in ("", "x", "has space", "a" * 40, "-dash"):
        assert admin.post("/api/account/rename", json={"username": bad}).status_code == 400, bad
    assert admin.post("/api/account/rename", json={"username": me}).status_code == 200


def test_language_must_be_one_the_panel_ships(admin):
    assert admin.post("/api/account/prefs", json={"language": "xx"}).status_code == 400
    assert admin.post("/api/account/prefs", json={"language": "uk"}).json()["language"] == "uk"
    assert admin.post("/api/account/prefs", json={"language": "en"}).status_code == 200


def test_contact_suggestions_and_users_2fa_answer(admin):
    r = admin.get("/api/account/contact-suggestions")
    assert r.status_code == 200 and isinstance(r.json()["suggestions"], list)
    r = admin.get("/api/users/2fa")
    assert r.status_code == 200 and set(r.json()) >= {"supported", "status", "users", "panel"}


# ----------------------------------------------------------------------------- users
@pytest.mark.skipif(not users.IS_LINUX, reason="Linux accounts")
def test_a_home_inside_another_account_is_flagged():
    import pwd
    me = pwd.getpwuid(os.getuid())
    assert users._home_owner("someone-else", me.pw_dir + "/incoming") == me.pw_name
    assert users._home_owner(me.pw_name, me.pw_dir) is None


def test_shell_names_in_the_users_page():
    js = (Path(__file__).resolve().parent.parent / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
    for s in ("/bin/bash", "/bin/sh", "/usr/sbin/nologin", "/bin/false", "What the shells mean", "Two-factor over SSH", "Set up 2FA", "Save a backup of the home folder first"):
        assert s in js, s


def test_ssh_twofa_status_is_a_plain_report(monkeypatch, tmp_path):
    monkeypatch.setattr(sshtwofa, "PAM_FILE", tmp_path / "sshd")
    monkeypatch.setattr(sshtwofa, "SSHD_DROPIN", tmp_path / "aurora-2fa.conf")
    monkeypatch.setattr(sshtwofa, "_module_installed", lambda: False)
    assert sshtwofa.status() == {"installed": False, "pam": False, "sshd": False, "ready": False}
    (tmp_path / "sshd").write_text("@include common-auth\n" + sshtwofa.PAM_LINE + "\n", encoding="utf-8")
    (tmp_path / "aurora-2fa.conf").write_text(sshtwofa.SSHD_TEXT, encoding="utf-8")
    monkeypatch.setattr(sshtwofa, "_module_installed", lambda: True)
    assert sshtwofa.status()["ready"] is True
    assert "nullok" in sshtwofa.PAM_LINE and "KbdInteractiveAuthentication yes" in sshtwofa.SSHD_TEXT


# ----------------------------------------------------------------------------- remote mail accounts
@pytest.fixture
def mail_state(tmp_path, monkeypatch):
    monkeypatch.setattr(mail, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(mail, "RC_CONF", tmp_path / "rc.inc.php")  # not there: webmail untouched
    monkeypatch.setattr(mail, "webmail_installed", lambda: False)
    return tmp_path


def test_remote_account_keeps_settings_never_the_password(mail_state):
    with pytest.raises(mail.MailError):
        mail.remote_add({"preset": "gmail", "email": "nope"})
    with pytest.raises(mail.MailError):
        mail.remote_add({"preset": "custom", "email": "a@b.c", "imap_host": "bad host!"})
    a = mail.remote_add({"preset": "gmail", "email": "Me@Gmail.com", "label": "Gmail"})
    assert a["imap"] == "ssl://imap.gmail.com:993" and a["smtp"] == "ssl://smtp.gmail.com:465" and a["username"] == "me@gmail.com"
    assert "_host" not in a["webmail"] and "imap.gmail.com" not in a["webmail"]   # the server's name never travels in a link
    raw = json.loads((mail_state / "state.json").read_text(encoding="utf-8"))
    assert "password" not in json.dumps(raw)
    with pytest.raises(mail.MailError):
        mail.remote_add({"preset": "gmail", "email": "me@gmail.com"})   # twice
    imap, smtp = mail._rc_hosts()
    assert "'ssl://imap.gmail.com:993' => 'Gmail'" in imap and "'ssl://imap.gmail.com:993' => 'ssl://smtp.gmail.com:465'" in smtp
    assert "localhost:143" in imap
    mail.remote_remove(a["id"])
    assert mail.remote_accounts() == [] and mail._rc_hosts() == ("['localhost:143']", "'tls://localhost:587'")
    with pytest.raises(mail.MailError):
        mail.remote_remove("gone")


def test_remote_presets_cover_the_big_providers():
    assert {"gmail", "outlook", "yahoo", "icloud", "custom"} <= set(mail.REMOTE_PRESETS)
    assert "app password" in mail.REMOTE_PRESETS["gmail"]["hint"].lower()


# ----------------------------------------------------------------------------- inbox feed
@pytest.mark.skipif(os.name == "nt", reason="Maildir flags use a colon in the file name")
def test_inbox_feed_reads_the_newest_mail_first(tmp_path, monkeypatch):
    monkeypatch.setattr(mail, "VMAIL", tmp_path)
    box = tmp_path / "ns0.local" / "a51" / "Maildir"
    (box / "new").mkdir(parents=True); (box / "cur").mkdir()
    old = box / "cur" / "1.mail:2,S"
    old.write_bytes(b"From: Alice <alice@example.com>\r\nSubject: =?utf-8?q?Caf=C3=A9_hours?=\r\nDate: Mon, 01 Jan 2024 10:00:00 +0000\r\n\r\nbody")
    new = box / "new" / "2.mail"
    new.write_bytes(b"From: bob@example.com\r\nSubject: Hello\r\nDate: Tue, 02 Jan 2024 10:00:00 +0000\r\n\r\nbody")
    items = mail.inbox_feed(["a51@ns0.local", "nobody@ns0.local"], 10)
    assert [i["subject"] for i in items] == ["Hello", "Café hours"]
    assert items[0]["unread"] is True and items[1]["unread"] is False
    assert items[0]["from"] == "bob@example.com" and items[1]["from"] == "Alice" and items[1]["from_addr"] == "alice@example.com"
    assert items[0]["account"] == "a51@ns0.local"
    assert mail.inbox_feed([], 10) == []


def test_inbox_addresses_are_the_owners_own_mailboxes(tmp_path, monkeypatch):
    monkeypatch.setattr(mail, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(mail, "local_domain_name", lambda: "ns0.local")
    s = mail.load()
    s["accounts"] = {"a51@example.com": {}, "info@example.com": {}, "x@ns0.local": {}, "me@other.org": {}}
    mail.save(s)
    assert mail.inbox_addresses("a51", "me@other.org") == ["a51@example.com", "me@other.org", "x@ns0.local"]


# ----------------------------------------------------------------------------- the exported report
def test_report_html_folds_identical_targets_and_leads_with_the_fixes():
    f = {"severity": "low", "title": "Self-signed certificate", "detail": "Browsers warn.", "fix": "Get a Let's Encrypt certificate."}
    rep = {"hostname": "ns0", "ts": int(time.time()), "took": 1.0, "score": 95, "grade": "A", "counts": {"low": 2},
           "targets": [{"kind": "panel", "label": "ns0:8088", "score": 97, "grade": "A+", "findings": [f], "facts": {"version": "TLSv1.3", "cipher": "x", "cert": {"days": 10}}},
                       {"kind": "panel", "label": "ns0.local:8088", "score": 97, "grade": "A+", "findings": [f], "facts": {}},
                       {"kind": "site", "label": "example.com", "score": 100, "grade": "A+", "findings": [], "facts": {}}]}
    html = secreport.report_html(rep)
    assert "What to do first" in html and html.count("Self-signed certificate") == 2   # once in the to-do list, once in the folded card
    assert "2 addresses, same result" in html and "ns0.local:8088" in html
    assert "3 targets checked" in html and "shown as 2 cards" in html
    assert "flex-direction:column" in html   # the score ring's grade and number no longer overlap
    assert "Seen on ns0:8088, ns0.local:8088" in html
