"""Problems: background failures are counted, shown and never silent."""
import logging

import pytest

from backend import problems


@pytest.fixture(autouse=True)
def fresh():
    problems.clear()
    yield
    problems.clear()


def test_record_dedupes_and_counts():
    a = problems.record("WAF rules", RuntimeError("Apache said no"), hint="Press Apply")
    b = problems.record("WAF rules", RuntimeError("Apache said no"))
    assert a["id"] == b["id"] and b["count"] == 2 and b["hint"] == "Press Apply"
    assert b["message"] == "RuntimeError: Apache said no"
    lst = problems.listing()["problems"]
    assert len(lst) == 1 and lst[0]["where"] == "WAF rules"


def test_dismiss_one_then_all():
    problems.record("one", "first")
    problems.record("two", "second")
    ids = [e["id"] for e in problems.listing()["problems"]]
    assert len(ids) == 2
    assert problems.dismiss(ids[0]) == {"ok": True, "left": 1}
    assert [e["id"] for e in problems.listing()["problems"]] == [ids[1]]
    assert problems.dismiss() == {"ok": True, "left": 0}


def test_dismissed_problem_comes_back_when_it_happens_again():
    e = problems.record("x", "boom")
    problems.dismiss(e["id"])
    assert problems.listing()["problems"] == []
    again = problems.record("x", "boom")
    assert again["count"] == 1 and problems.listing()["problems"][0]["id"] != e["id"]


def test_capped_oldest_out(monkeypatch):
    monkeypatch.setattr(problems, "MAX_PROBLEMS", 3)
    for i in range(5):
        problems.record("w", f"m{i}")
    assert sorted(e["message"] for e in problems.listing()["problems"]) == ["m2", "m3", "m4"]


def test_quiet_knows_where_it_was_called_from_and_never_raises(caplog):
    def helper():
        try:
            raise ValueError("nope")
        except Exception as exc:
            problems.quiet(exc)
    with caplog.at_level(logging.INFO, logger="aurora"):
        for _ in range(3):
            helper()
    q = problems.listing()["quiet"]
    assert len(q) == 1 and q[0]["count"] == 3 and q[0]["message"] == "ValueError: nope"
    assert q[0]["where"].startswith("test_problems.helper:")
    assert sum("carried on after ValueError: nope" in r.message for r in caplog.records) == 1   # logged once, counted thrice
    problems.quiet(ValueError("x"), where=None)   # still fine
    assert problems.listing()["problems"] == []   # quiet never alarms the dashboard


def test_message_is_one_line_and_bounded():
    e = problems.record("w", "a\nb   c" + "x" * 1000)
    assert "\n" not in e["message"] and len(e["message"]) <= 400 and e["message"].startswith("a b cxxx")


def test_background_task_failure_lands_on_the_dashboard(caplog):
    def bad():
        raise OSError("disk gone")
    with caplog.at_level(logging.WARNING, logger="aurora"):
        problems.background("Snapshot", bad, hint="No copy was saved").join(5)
        problems.background("Fine", lambda: None).join(5)
    lst = problems.listing()["problems"]
    assert len(lst) == 1 and lst[0]["where"] == "Snapshot" and lst[0]["hint"] == "No copy was saved"
    assert any("Snapshot: OSError: disk gone" in r.message for r in caplog.records)


def test_waf_rewrite_refused_by_apache_is_reported(tmp_path, monkeypatch):
    from backend import waf
    monkeypatch.setattr(waf, "STATE", tmp_path / "waf.json")
    monkeypatch.setattr(waf, "installed", lambda: True)
    monkeypatch.setattr(waf, "module_on", lambda: True)
    def refuse(s=None):
        raise waf.WafError("Apache rejected the WAF settings, nothing changed:\nSyntax error on line 7")
    monkeypatch.setattr(waf, "apply", refuse)
    assert waf.refresh_rules() is False
    p = problems.listing()["problems"]
    assert len(p) == 1 and p[0]["where"] == "WAF rules" and "Syntax error on line 7" in p[0]["message"] and "Apply" in p[0]["hint"]


def test_trusted_list_syncs_report_instead_of_hiding(monkeypatch):
    from backend import guard, waf
    monkeypatch.setattr(waf, "installed", lambda: True)
    monkeypatch.setattr(waf, "module_on", lambda: True)
    def refuse(s=None):
        raise waf.WafError("no")
    monkeypatch.setattr(waf, "apply", refuse)
    guard._sync_waf()
    assert problems.listing()["problems"][0]["where"] == "Trusted addresses → WAF"


def test_problems_api(admin):
    problems.record("WAF rules", "x", hint="h")
    r = admin.get("/api/problems")
    assert r.status_code == 200
    body = r.json()
    assert body["problems"][0]["where"] == "WAF rules" and "quiet" in body
    pid = body["problems"][0]["id"]
    assert admin.post("/api/problems/dismiss", json={"id": pid}).json() == {"ok": True, "left": 0}
    problems.record("a", "b")
    assert admin.post("/api/problems/dismiss", json={}).json()["left"] == 0


def test_problems_api_needs_a_login(client):
    assert client.get("/api/problems").status_code == 401
