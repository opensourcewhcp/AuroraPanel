"""Network diagnostics (netdiag): input validation, the dig/whois/ping command lines and how their output is read."""
import subprocess

import pytest

from backend import netdiag


@pytest.fixture
def fake_run(monkeypatch):
    """Record every argv netdiag runs and answer from a table keyed on (name, type) or argv[0]."""
    calls: list[list[str]] = []
    answers: dict = {}

    def run(argv, capture_output=True, text=True, timeout=0):
        calls.append(list(argv))
        if argv[0] == "dig":
            key = tuple(argv[-2:])
            out = answers.get(key, answers.get(argv[0], ""))
        else:
            out = answers.get(argv[0], "")
        err = answers.get("stderr", "")
        return subprocess.CompletedProcess(argv, 0, out, err)
    monkeypatch.setattr(netdiag.subprocess, "run", run)
    monkeypatch.setattr(netdiag.shutil, "which", lambda name, path=None: f"/usr/bin/{name}")
    run.calls, run.answers = calls, answers
    return run


def test_host_validation_accepts_names_and_ips_only():
    assert netdiag._valid_host("  Example.com ") == "Example.com"
    assert netdiag._valid_host("2001:db8::1") == "2001:db8::1"
    for bad in ("", "a b", "x;rm", "-" * 300, None):
        with pytest.raises(netdiag.NetDiagError, match="Invalid hostname"):
            netdiag._valid_host(bad)


def test_run_reports_missing_tools_and_failures(monkeypatch):
    def missing(argv, **kw):
        raise FileNotFoundError
    monkeypatch.setattr(netdiag.subprocess, "run", missing)
    with pytest.raises(netdiag.NetDiagError, match="dig is not installed"):
        netdiag._run(["dig", "x"])

    def slow(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 5)
    monkeypatch.setattr(netdiag.subprocess, "run", slow)
    with pytest.raises(netdiag.NetDiagError, match="timed out"):
        netdiag._run(["dig", "x"])


def test_run_joins_stdout_and_stderr(fake_run):
    fake_run.answers["whois"] = "out\n"
    fake_run.answers["stderr"] = "warn\n"
    assert netdiag._run(["whois", "x"]) == "out\n\nwarn"


def test_dig_needs_the_tool(monkeypatch):
    monkeypatch.setattr(netdiag.shutil, "which", lambda name, path=None: None)
    with pytest.raises(netdiag.NetDiagError, match="dnsutils"):
        netdiag.dns_records("example.com")


def test_resolver_keys_map_to_addresses_or_a_typed_host():
    assert netdiag._server("") is None and netdiag._server("system") is None
    assert netdiag._server("cloudflare") == "1.1.1.1"
    assert netdiag._server("10.0.0.53") == "10.0.0.53"
    with pytest.raises(netdiag.NetDiagError):
        netdiag._server("bad host")


def test_dns_records_runs_dig_per_type_and_drops_comments(fake_run):
    fake_run.answers[("example.com", "A")] = "93.184.216.34\n; comment\n\n"
    fake_run.answers[("example.com", "MX")] = "10 mail.example.com."
    r = netdiag.dns_records("example.com", ["A", "MX", "BOGUS"], server="google")
    assert r["server"] == "8.8.8.8"
    assert r["records"] == {"A": ["93.184.216.34"], "MX": ["10 mail.example.com."]}
    assert ["dig", "+short", "+time=3", "+tries=1", "@8.8.8.8", "example.com", "A"] in fake_run.calls
    r = netdiag.dns_records("example.com", ["BOGUS"])
    assert list(r["records"]) == list(netdiag.DEFAULT_TYPES) and r["server"] == "this Pi"


def test_propagation_flags_disagreeing_resolvers(fake_run, monkeypatch):
    fake_run.answers[("example.com", "A")] = "1.2.3.4"
    r = netdiag.propagation("example.com", "NOPE")
    assert r["type"] == "A" and r["agree"] is True
    assert [row["name"] for row in r["resolvers"]] == [n for n, _ in netdiag.RESOLVERS]
    assert ["dig", "+short", "+time=3", "+tries=1", "@9.9.9.9", "example.com", "A"] in fake_run.calls

    def run(argv, **kw):
        out = "5.6.7.8" if "@1.1.1.1" in argv else "1.2.3.4"
        return subprocess.CompletedProcess(argv, 0, out, "")
    monkeypatch.setattr(netdiag.subprocess, "run", run)
    assert netdiag.propagation("example.com")["agree"] is False


def test_mail_check_finds_spf_dmarc_and_dkim(fake_run):
    fake_run.answers[("ex.com", "MX")] = "10 mail.ex.com."
    fake_run.answers[("ex.com", "TXT")] = '"v=spf1 +mx -all"\n"other"'
    fake_run.answers[("_dmarc.ex.com", "TXT")] = '"v=DMARC1; p=reject"'
    fake_run.answers[("mail._domainkey.ex.com", "TXT")] = '"v=DKIM1; k=rsa; p=AAA"'
    r = netdiag.mail_check("ex.com")
    assert r["spf"] == ['"v=spf1 +mx -all"'] and r["dmarc"] == ['"v=DMARC1; p=reject"']
    assert list(r["dkim"]) == ["mail"]
    assert r["ok"] == {"mx": True, "spf": True, "dmarc": True, "dkim": True}
    r = netdiag.mail_check("empty.com")
    assert r["ok"] == {"mx": False, "spf": False, "dmarc": False, "dkim": False} and r["dkim"] == {}


def test_ns_check_compares_soa_serials(fake_run):
    fake_run.answers[("ex.com", "NS")] = "ns2.ex.com.\nns1.ex.com."
    fake_run.answers[("ns1.ex.com", "A")] = "10.0.0.1"
    fake_run.answers[("ns2.ex.com", "A")] = ""
    fake_run.answers[("ex.com", "SOA")] = "ns1.ex.com. hostmaster.ex.com. 2026110201 3600 600 86400 300"
    r = netdiag.ns_check("ex.com")
    assert r["ns"] == ["ns1.ex.com", "ns2.ex.com"]
    assert r["servers"][0] == {"ns": "ns1.ex.com", "ip": "10.0.0.1", "serial": "2026110201", "ok": True}
    assert r["servers"][1]["ip"] == "" and r["servers"][1]["ok"] is True
    assert r["agree"] is True
    assert any("@10.0.0.1" in c for c in fake_run.calls) and any("@ns2.ex.com" in c for c in fake_run.calls)
    assert netdiag.ns_check("none.com")["servers"] == []


def test_whois_strips_notices_and_needs_the_tool(fake_run, monkeypatch):
    fake_run.answers["whois"] = "% RIPE notice\nNOTICE: terms\n>>> last update\nnetname: TEST-NET\ncountry: DE\n"
    r = netdiag.whois("203.0.113.5")
    assert r["text"] == "netname: TEST-NET\ncountry: DE"
    assert r["summary"] == {"Network": "TEST-NET", "Country": "DE"}
    assert fake_run.calls[-1] == ["whois", "203.0.113.5"]
    monkeypatch.setattr(netdiag.shutil, "which", lambda name, path=None: None)
    with pytest.raises(netdiag.NetDiagError, match="whois is not installed"):
        netdiag.whois("example.com")


def test_reverse_lookup_prefers_dig_then_host(fake_run, monkeypatch):
    fake_run.answers["dig"] = "host.example.com."
    assert netdiag.reverse_lookup("1.2.3.4") == {"ip": "1.2.3.4", "result": "host.example.com."}
    assert fake_run.calls[-1] == ["dig", "+short", "-x", "1.2.3.4"]
    monkeypatch.setattr(netdiag.shutil, "which", lambda name, path=None: "/usr/bin/host" if name == "host" else None)
    assert netdiag.reverse_lookup("1.2.3.4")["result"] == "(no PTR record)"
    assert fake_run.calls[-1] == ["host", "1.2.3.4"]
    monkeypatch.setattr(netdiag.shutil, "which", lambda name, path=None: None)
    with pytest.raises(netdiag.NetDiagError, match="dig/host"):
        netdiag.reverse_lookup("1.2.3.4")


def test_ping_parses_average_and_loss(fake_run, monkeypatch):
    fake_run.answers["ping"] = ("PING x (1.2.3.4)\n4 packets transmitted, 3 received, 25% packet loss\n"
                                "rtt min/avg/max/mdev = 1.2/3.45/5.6/0.7 ms")
    r = netdiag.ping("example.com", count=99)
    assert fake_run.calls[-1] == ["ping", "-c", "10", "-w", "15", "example.com"]
    assert r["avg_ms"] == 3.45 and r["loss_pct"] == 25.0
    fake_run.answers["ping"] = "ping: unknown host"
    r = netdiag.ping("example.com", count=0)
    assert fake_run.calls[-1][2] == "1" and r["avg_ms"] is None and r["loss_pct"] is None
    monkeypatch.setattr(netdiag.shutil, "which", lambda name, path=None: None)
    with pytest.raises(netdiag.NetDiagError, match="ping is not installed"):
        netdiag.ping("example.com")


def test_traceroute_falls_back_to_tracepath(fake_run, monkeypatch):
    fake_run.answers["traceroute"] = " 1  gw  1 ms"
    assert netdiag.traceroute("example.com")["output"] == "1  gw  1 ms"
    assert fake_run.calls[-1] == ["traceroute", "-w", "2", "-q", "1", "-m", "20", "example.com"]
    monkeypatch.setattr(netdiag.shutil, "which", lambda name, path=None: "/bin/tracepath" if name == "tracepath" else None)
    fake_run.answers["tracepath"] = "1: gw"
    assert netdiag.traceroute("example.com")["output"] == "1: gw"
    assert fake_run.calls[-1] == ["tracepath", "example.com"]
    monkeypatch.setattr(netdiag.shutil, "which", lambda name, path=None: None)
    with pytest.raises(netdiag.NetDiagError, match="traceroute"):
        netdiag.traceroute("example.com")
