"""One-click fixes: a button only appears when it can work, and success means it worked."""
import subprocess

import pytest

from backend import autossl, secreport


@pytest.mark.parametrize("here,addrs,action,says", [
    (True, ["71.197.107.133"], "autossl_run:a.example", ""),
    (False, ["104.21.69.101"], None, "points to 104.21.69.101"),
    (False, [], None, "no DNS record"),
])
def test_certificate_is_only_offered_for_a_name_that_points_here(monkeypatch, here, addrs, action, says):
    monkeypatch.setattr(autossl, "resolves_here", lambda n: (here, addrs))
    f = {"fix": "old"}
    secreport._offer_certificate(f, "a.example")
    assert f.get("action") == action and says in f["fix"]


@pytest.fixture
def job(monkeypatch):
    """A fake AutoSSL unit: active for `busy` checks, and writes `result` when it starts."""
    st = {"busy": 0, "started": [], "result": None, "results": {}}

    def run(argv, timeout=0):
        out = "inactive"
        if st["busy"] > 0:
            st["busy"] -= 1
            out = "active"
        return subprocess.CompletedProcess(argv, 0, out, "")

    def start(force, site):
        st["started"].append(site)
        if st["result"] is not None:
            st["results"][site] = {"ts": 4102444800, **st["result"]}
        return {"ok": True}

    monkeypatch.setattr(autossl, "_run", run)
    monkeypatch.setattr(autossl, "start", start)
    monkeypatch.setattr(autossl, "load", lambda: {"results": st["results"]})
    monkeypatch.setattr(autossl, "_plan", lambda: [])
    monkeypatch.setattr(autossl.time, "sleep", lambda s: None)
    return st


def test_request_returns_the_real_success(job):
    job["result"] = {"ok": True, "note": "Site switched to the new certificate"}
    assert autossl.request("a.example")["note"] == "Site switched to the new certificate"


def test_request_reports_the_real_failure(job):
    job["result"] = {"ok": False, "error": "port 80 isn't reachable"}
    with pytest.raises(autossl.AutoSSLError, match="port 80"):
        autossl.request("a.example")


def test_request_waits_its_turn_instead_of_being_dropped(job):
    job["busy"] = 3
    job["result"] = {"ok": True}
    assert autossl.request("b.example")["ok"] and job["started"] == ["b.example"]


def test_a_job_that_did_nothing_is_not_a_success(job):
    with pytest.raises(autossl.AutoSSLError, match="doesn't point"):
        autossl.request("a.example")


def test_an_old_result_is_not_mistaken_for_this_one(job):
    job["results"]["a.example"] = {"ts": 1, "ok": True}
    with pytest.raises(autossl.AutoSSLError):
        autossl.request("a.example")


def test_fix_passes_the_failure_on(monkeypatch):
    def refuse(site):
        raise autossl.AutoSSLError("port 80 isn't reachable")
    monkeypatch.setattr(autossl, "request", refuse)
    with pytest.raises(secreport.SecReportError, match="port 80"):
        secreport.fix("autossl_run:a.example")
