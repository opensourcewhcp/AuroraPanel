"""Cron jobs: schedule validation, the crontab text the panel writes, labels and pausing.
The crontab command is replaced by a recorder, so the exact text handed to `crontab -` is checked."""
from __future__ import annotations

import subprocess

import pytest

from backend import cron


@pytest.fixture
def crontab(monkeypatch):
    """cron on a Linux host whose crontab command is an in-memory file."""
    state = {"text": "", "rc": 0, "err": "", "writes": [], "wrc": 0, "werr": ""}

    def run(argv, **kw):
        if argv == ["crontab", "-l"]:
            return subprocess.CompletedProcess(argv, state["rc"], state["text"], state["err"])
        if argv == ["crontab", "-"]:
            state["writes"].append(kw["input"])
            if state["wrc"] == 0:
                state["text"] = kw["input"]
            return subprocess.CompletedProcess(argv, state["wrc"], "", state["werr"])
        raise AssertionError(f"unexpected command {argv}")
    monkeypatch.setattr(cron, "IS_LINUX", True)
    monkeypatch.setattr(cron.shutil, "which", lambda name, *a, **k: "/usr/bin/crontab" if name == "crontab" else None)
    monkeypatch.setattr(cron.subprocess, "run", run)
    return state


# ------------------------------------------------------------------ schedules
def test_macros_and_five_field_schedules_are_normalised():
    assert cron.validate_schedule("  @daily ") == "@daily"
    assert cron.validate_schedule("*/5  1-3   *  JAN,jul  mon-FRI") == "*/5 1-3 * JAN,jul mon-FRI"
    assert cron.validate_schedule("0 0 1 1 7") == "0 0 1 1 7"   # 7 is Sunday too


@pytest.mark.parametrize("bad, why", [
    ("", "required"), ("@fortnightly", "Unknown macro"), ("* * * *", "5 fields"), ("* * * * * *", "5 fields"),
    ("a! * * * *", "Invalid field"), ("60 * * * *", "between 0 and 59"), ("* 24 * * *", "between 0 and 23"),
    ("* * 0 * *", "between 1 and 31"), ("* * * 13 *", "between 1 and 12"), ("* * * * 8", "between 0 and 7"),
    ("10-5 * * * *", "goes backwards"), ("*/0 * * * *", "Bad step"), ("*/a * * * *", "Bad step"), ("1/2/3 * * * *", "Bad step"),
    ("* * * FOO *", "valid month"), ("* * * * x", "valid day-of-week"),
])
def test_bad_schedules_are_refused_with_a_reason(bad, why):
    with pytest.raises(cron.CronError, match=why):
        cron.validate_schedule(bad)


def test_entries_split_into_schedule_and_command():
    assert cron._parse_entry("@reboot /usr/bin/backup --all") == ("@reboot", "/usr/bin/backup --all")
    assert cron._parse_entry("@reboot") == ("@reboot", "")
    assert cron._parse_entry("*/5 * * * * echo hi there") == ("*/5 * * * *", "echo hi there")
    assert cron._parse_entry("* * * echo") is None
    with pytest.raises(cron.CronError, match="Newlines"):
        cron._clean("echo a\necho b", "command")
    assert cron._clean("  echo a  ", "command") == "echo a"
    tz = cron._tz()
    assert isinstance(tz["utc_offset_min"], int) and -900 <= tz["utc_offset_min"] <= 900


# ------------------------------------------------------------------ reading
def test_without_crontab_the_page_says_so(monkeypatch):
    monkeypatch.setattr(cron, "IS_LINUX", False)
    lst = cron.list_jobs()
    assert lst["jobs"] == [] and lst["supported"] is False and "tz" in lst
    with pytest.raises(cron.CronError, match="not available"):
        cron.add_job("@daily", "echo")


def test_listing_understands_labels_pauses_env_lines_and_comments(crontab):
    crontab["text"] = ("SHELL=/bin/sh\n"
                       "# aurora: Nightly backup\n"
                       "0 2 * * * /usr/local/bin/backup.sh\n"
                       "# a plain comment breaks the label chain\n"
                       "# aurora: orphan label\n"
                       "# another comment\n"
                       "#paused: @weekly /opt/report.sh\n"
                       "not a job at all\n"
                       "\n"
                       "*/10 * * * * curl -s http://localhost/ping\n")
    jobs = cron.list_jobs()["jobs"]
    assert [(j["schedule"], j["command"], j["label"], j["paused"]) for j in jobs] == [
        ("0 2 * * *", "/usr/local/bin/backup.sh", "Nightly backup", False),
        ("@weekly", "/opt/report.sh", None, True),
        ("*/10 * * * *", "curl -s http://localhost/ping", None, False)]
    assert jobs[0]["line"] == 2 and jobs[1]["raw"] == "#paused: @weekly /opt/report.sh"


def test_an_empty_crontab_is_not_an_error_but_a_broken_one_is(crontab):
    crontab.update(rc=1, err="no crontab for root")
    assert cron.list_jobs()["jobs"] == []
    crontab.update(rc=1, err="crontab: permission denied", text="something")
    with pytest.raises(cron.CronError, match="permission denied"):
        cron.list_jobs()


# ------------------------------------------------------------------ writing
def test_add_job_appends_the_label_and_entry(crontab):
    crontab["text"] = "MAILTO=me@example.com\n0 1 * * * old.sh\n"
    assert cron.add_job(" @daily ", " /opt/new.sh --quiet ", " New thing ") == {"ok": True}
    assert crontab["writes"][-1] == "MAILTO=me@example.com\n0 1 * * * old.sh\n# aurora: New thing\n@daily /opt/new.sh --quiet\n"
    assert cron.add_job("5 4 * * *", "echo hi") == {"ok": True}
    assert crontab["writes"][-1].endswith("@daily /opt/new.sh --quiet\n5 4 * * * echo hi\n")
    with pytest.raises(cron.CronError, match="Command is required"):
        cron.add_job("@daily", "   ")
    crontab["text"] = ""
    cron.add_job("@reboot", "/opt/boot.sh")
    assert crontab["writes"][-1] == "@reboot /opt/boot.sh\n"   # a first job gets no leading blank line
    crontab.update(wrc=1, werr='"-":0: bad minute')
    with pytest.raises(cron.CronError, match="bad minute"):
        cron.add_job("@daily", "x")


def test_update_replaces_the_job_and_its_label_in_place(crontab):
    crontab["text"] = "# aurora: Old\n0 1 * * * old.sh\n0 2 * * * other.sh\n"
    assert cron.update_job("0 1 * * * old.sh", "0 3 * * *", "new.sh", "Renamed") == {"ok": True}
    assert crontab["text"] == "# aurora: Renamed\n0 3 * * * new.sh\n0 2 * * * other.sh\n"
    cron.update_job("0 2 * * * other.sh", "@hourly", "other.sh", None, paused=True)
    assert crontab["text"].splitlines()[-1] == "#paused: @hourly other.sh"
    with pytest.raises(cron.CronError, match="not found"):
        cron.update_job("0 9 * * * gone.sh", "@daily", "x")
    with pytest.raises(cron.CronError, match="No line"):
        cron.delete_job("   ")
    with pytest.raises(cron.CronError, match="Command is required"):
        cron.update_job("0 3 * * * new.sh", "@daily", "")


def test_delete_removes_the_job_with_its_label_only(crontab):
    crontab["text"] = "# a comment that stays\n# aurora: Gone\n0 1 * * * gone.sh\n0 2 * * * keep.sh\n"
    assert cron.delete_job("0 1 * * * gone.sh") == {"ok": True, "removed": "0 1 * * * gone.sh"}
    assert crontab["text"] == "# a comment that stays\n0 2 * * * keep.sh\n"
    cron.delete_job("0 2 * * * keep.sh")
    assert crontab["text"] == "# a comment that stays\n"


def test_pausing_keeps_the_label_and_cron_ignores_the_line(crontab):
    crontab["text"] = "# aurora: Report\n@weekly /opt/report.sh\n"
    assert cron.set_paused("@weekly /opt/report.sh", True) == {"ok": True}
    assert crontab["text"] == "# aurora: Report\n#paused: @weekly /opt/report.sh\n"
    job = cron.list_jobs()["jobs"][0]
    assert job["paused"] and job["label"] == "Report"
    cron.set_paused(job["raw"], False)
    assert crontab["text"] == "# aurora: Report\n@weekly /opt/report.sh\n"
    with pytest.raises(cron.CronError, match="not found"):
        cron.set_paused("@daily nothing", True)


def test_run_now_launches_the_command_through_a_shell(crontab, monkeypatch):
    crontab["text"] = "# aurora: Report\n@weekly /opt/report.sh --full\n0 1 * * * /opt/plain.sh\n"
    launched = []

    class J:
        id = "job-1"
    monkeypatch.setattr(cron.jobrunner, "launch", lambda title, argv, **kw: launched.append((title, argv)) or J())
    assert cron.run_now("@weekly /opt/report.sh --full") == {"job_id": "job-1"}
    assert launched[-1] == ("Run: Report", ["/bin/sh", "-c", "/opt/report.sh --full"])
    cron.run_now("0 1 * * * /opt/plain.sh")
    assert launched[-1][0] == "Run: /opt/plain.sh"
    with pytest.raises(cron.CronError, match="not found"):
        cron.run_now("0 9 * * * gone.sh")
