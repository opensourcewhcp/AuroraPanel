import pytest

from backend import fail2ban

LOG = """2026-10-29 10:52:00,000 fail2ban.filter         [100]: INFO    [sshd] Found 66.175.214.102
2026-10-29 10:52:01,000 fail2ban.actions        [100]: NOTICE  [sshd] Ban 66.175.214.102
2026-10-29 10:55:00,000 fail2ban.filter         [100]: INFO    [sshd] Found 177.104.140.2
2026-10-29 11:05:00,000 fail2ban.actions        [100]: NOTICE  [sshd] Unban 66.175.214.102
"""


def _setup(monkeypatch, tmp_path):
    log = tmp_path / "fail2ban.log"
    log.write_text(LOG, encoding="utf-8")
    monkeypatch.setattr(fail2ban, "LOG_FILES", [log])
    monkeypatch.setattr(fail2ban, "DISMISSED", tmp_path / "dismissed.json")
    monkeypatch.setattr(fail2ban, "_add_users", lambda ev: None)


def test_events_have_keys_and_total(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    r = fail2ban.events(limit=2)
    assert r["total"] == 4 and len(r["events"]) == 2
    assert r["events"][0]["kind"] == "unban" and r["events"][0]["key"] == fail2ban.event_key(r["events"][0])
    assert all("|" in e["key"] for e in r["events"])


def test_dismiss_hides_entries_and_forgets_stale_keys(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    r = fail2ban.events()
    ban = next(e for e in r["events"] if e["kind"] == "ban")
    assert fail2ban.dismiss([ban["key"], "not a key", 42])["removed"] == 1
    r2 = fail2ban.events()
    assert r2["total"] == 3 and all(e["key"] != ban["key"] for e in r2["events"])
    # a key older than anything still in the log is dropped on the next read
    fail2ban._save_dismissed(fail2ban._dismissed() | {"1000000000|sshd|ban|1.2.3.4|"})
    fail2ban.events()
    assert fail2ban._dismissed() == {ban["key"]}


def test_dismiss_rejects_empty_selection(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    with pytest.raises(fail2ban.Fail2banError):
        fail2ban.dismiss([])
