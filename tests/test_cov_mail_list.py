"""Mailing-list delivery script: who may post, which headers it adds, what it hands to sendmail."""
import io
import json
import subprocess
import sys
from email import message_from_bytes

import pytest

from backend import mail_list


class FakeStdin:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


MSG = (b"From: Carol <carol@gmail.com>\r\nTo: team@ex.com\r\nSubject: Hello\r\n"
       b"DKIM-Signature: v=1; a=rsa-sha256; d=gmail.com\r\nReply-To: carol@gmail.com\r\n\r\nbody\r\n")


@pytest.fixture
def run_list(tmp_path, monkeypatch):
    """Call main() with a lists.json in tmp_path, a captured stdin and a recorded sendmail."""
    calls: list[dict] = []
    conf = tmp_path / "lists.json"
    monkeypatch.setattr(mail_list, "CONF", str(conf))

    def fake_run(argv, input=None, **kw):
        calls.append({"argv": argv, "input": input})
        return subprocess.CompletedProcess(argv, fake_run.rc, b"", fake_run.stderr)
    fake_run.rc, fake_run.stderr = 0, b""
    monkeypatch.setattr(mail_list.subprocess, "run", fake_run)

    def go(lists, listaddr="team@ex.com", sender="carol@gmail.com", raw=MSG):
        conf.write_text(json.dumps(lists), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["list.py", listaddr, sender])
        monkeypatch.setattr(sys, "stdin", FakeStdin(raw))
        return mail_list.main()
    go.calls, go.run = calls, fake_run
    return go


def test_missing_arguments_is_a_data_error(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["list.py", "team@ex.com"])
    assert mail_list.main() == mail_list.EX_DATAERR


def test_unreadable_config_is_a_tempfail(tmp_path, monkeypatch):
    monkeypatch.setattr(mail_list, "CONF", str(tmp_path / "missing.json"))
    monkeypatch.setattr(sys, "argv", ["list.py", "team@ex.com", "a@b.com"])
    assert mail_list.main() == mail_list.EX_TEMPFAIL
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(mail_list, "CONF", str(tmp_path / "bad.json"))
    assert mail_list.main() == mail_list.EX_TEMPFAIL


def test_unknown_list_is_refused(run_list, capsys):
    assert run_list({}) == mail_list.EX_NOPERM
    assert "not a mailing list" in capsys.readouterr().err
    assert run_list.calls == []


def test_bounces_and_own_posts_are_dropped_silently(run_list):
    lists = {"team@ex.com": {"members": ["alice@ex.com"]}}
    assert run_list(lists, sender="MAILER-DAEMON@ex.com") == 0
    assert run_list(lists, sender="") == 0
    looped = b"X-Aurora-List: team@ex.com\r\n" + MSG
    assert run_list(lists, raw=looped) == 0
    assert run_list.calls == []


def test_members_only_list_refuses_outsiders(run_list, capsys):
    lists = {"team@ex.com": {"members": ["alice@ex.com"], "access": "members"}}
    assert run_list(lists, sender="stranger@else.com") == mail_list.EX_NOPERM
    assert "Only members" in capsys.readouterr().err


def test_announce_list_only_owners_post(run_list, capsys):
    lists = {"team@ex.com": {"members": ["alice@ex.com"], "owners": ["boss@ex.com"], "access": "announce"}}
    assert run_list(lists, sender="alice@ex.com") == mail_list.EX_NOPERM
    assert "announcement list" in capsys.readouterr().err
    assert run_list(lists, sender="boss@ex.com") == 0
    assert len(run_list.calls) == 1


def test_open_list_rewrites_headers_and_sends_to_members(run_list):
    lists = {"team@ex.com": {"members": ["alice@ex.com", "Bob@ex.com", "team@ex.com"], "owners": ["boss@ex.com"],
                             "access": "open", "description": 'The "Team"'}}
    assert run_list(lists) == 0
    call = run_list.calls[0]
    assert call["argv"] == ["/usr/sbin/sendmail", "-i", "-f", "team@ex.com", "--", "alice@ex.com", "bob@ex.com"]
    sent = message_from_bytes(call["input"])
    assert sent["X-Aurora-List"] == "team@ex.com"
    assert sent["List-Id"] == "\"The 'Team'\" <team.ex.com>"
    assert sent["List-Post"] == "<mailto:team@ex.com>"
    assert sent["List-Owner"] == "<mailto:boss@ex.com>"
    assert sent["List-Unsubscribe"] == "<mailto:boss@ex.com?subject=unsubscribe%20team@ex.com>"
    assert sent["Precedence"] == "list"
    assert sent["Subject"] == "[team] Hello"
    assert sent["From"] == "Carol via team <team@ex.com>"   # outside domain, so From is rewritten for DMARC
    assert sent["Reply-To"] == "team@ex.com"
    assert sent["DKIM-Signature"] is None


def test_subject_prefix_is_not_doubled_and_can_be_disabled(run_list):
    lists = {"team@ex.com": {"members": ["alice@ex.com"], "access": "open"}}
    raw = MSG.replace(b"Subject: Hello", b"Subject: Re: [TEAM] Hello")
    assert run_list(lists, raw=raw) == 0
    assert message_from_bytes(run_list.calls[-1]["input"])["Subject"] == "Re: [TEAM] Hello"
    lists["team@ex.com"]["prefix"] = False
    assert run_list(lists) == 0
    assert message_from_bytes(run_list.calls[-1]["input"])["Subject"] == "Hello"


def test_from_munging_keeps_reply_to_sender_when_not_replying_to_list(run_list):
    lists = {"team@ex.com": {"members": ["alice@ex.com"], "access": "open", "reply_to_list": False}}
    assert run_list(lists) == 0
    sent = message_from_bytes(run_list.calls[-1]["input"])
    assert sent["From"] == "Carol via team <team@ex.com>"
    assert sent["Reply-To"] == "Carol <carol@gmail.com>"
    assert sent["List-Owner"] == "<mailto:postmaster@ex.com>"   # no owners configured


def test_local_sender_keeps_its_from_and_munging_can_be_disabled(run_list):
    lists = {"team@ex.com": {"members": ["alice@ex.com"], "access": "open"}}
    raw = MSG.replace(b"carol@gmail.com", b"alice@ex.com")
    assert run_list(lists, sender="alice@ex.com", raw=raw) == 0
    assert message_from_bytes(run_list.calls[-1]["input"])["From"] == "Carol <alice@ex.com>"
    lists["team@ex.com"]["munge_from"] = False
    assert run_list(lists) == 0
    assert message_from_bytes(run_list.calls[-1]["input"])["From"] == "Carol <carol@gmail.com>"


def test_no_members_means_nothing_is_sent(run_list):
    assert run_list({"team@ex.com": {"members": ["team@ex.com"], "access": "open"}}) == 0
    assert run_list.calls == []


def test_members_are_sent_in_batches_of_fifty(run_list):
    members = [f"m{i}@ex.com" for i in range(120)]
    assert run_list({"team@ex.com": {"members": members, "access": "open"}}) == 0
    sizes = [len(c["argv"]) - 5 for c in run_list.calls]
    assert sizes == [50, 50, 20]
    assert all(c["input"] == run_list.calls[0]["input"] for c in run_list.calls)


def test_sendmail_failure_is_a_tempfail_with_its_stderr(run_list, capsys):
    run_list.run.rc, run_list.run.stderr = 1, b"postdrop: queue full"
    assert run_list({"team@ex.com": {"members": ["alice@ex.com"], "access": "open"}}) == mail_list.EX_TEMPFAIL
    assert "queue full" in capsys.readouterr().err
