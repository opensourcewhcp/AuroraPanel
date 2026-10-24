"""Abuse reports (RDAP contact lookup, guards) and local-network mail (.local)."""
import pytest

from backend import abuse, mail


def test_only_public_addresses_can_be_reported():
    for ip in ("192.168.0.5", "10.0.0.1", "127.0.0.1", "not-an-ip"):
        with pytest.raises(abuse.AbuseError):
            abuse._public_ip(ip)
    assert abuse._public_ip(" 92.118.39.49 ") == "92.118.39.49"


def test_rdap_abuse_contact_is_found_in_nested_entities():
    found = {"abuse": [], "other": []}
    abuse._walk([{"roles": ["registrant"], "vcardArray": ["vcard", [["email", {}, "text", "noc@isp.net"]]],
                  "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "Abuse@ISP.net"]]]}]}],
                found)
    assert found == {"abuse": ["abuse@isp.net"], "other": ["noc@isp.net"]}


def test_report_body_lists_the_evidence():
    ev = [{"ts": 1792800000 + i, "source": "SSH", "user": "admin" if i % 2 else None} for i in range(3)][::-1]
    body = abuse._body("92.118.39.49", {"network": "DMZHOST"}, ev, "mail.example.com", "203.0.113.7", "")
    assert "92.118.39.49 (DMZHOST)" in body and "3 unauthorized login attempts" in body and "as user 'admin'" in body
    assert "mail.example.com (203.0.113.7)" in body


def test_local_domains(monkeypatch):
    monkeypatch.setattr(mail.socket, "gethostname", lambda: "NS1.lan")
    assert mail.local_domain_name() == "ns1.local"
    assert mail.is_local("ns1.local") and not mail.is_local("shop.com")
    s = mail._default_state()
    s["domains"] = {"ns1.local": {"routing": "local", "routing_set": True, "local": True, "catchall": {"mode": "fail"}}}
    s["accounts"] = {"admin@ns1.local": {"hash": "{SHA512-CRYPT}x", "quota_mb": 0, "suspend": {}}}
    m = mail.render_postfix(s)
    assert "ns1.local OK" in m["domains"] and "admin@ns1.local ns1.local/admin/" in m["mailboxes"]
    assert "ns1.local lmtp:unix:private/dovecot-lmtp" in m["transport"]   # ours: deliver here, not to [ns1.local]
    assert mail._effective_routing("ns1.local", {"routing": "auto"}) == "local"
    assert mail.ensure_dkim("ns1.local") is None
    assert "smtp_host_lookup" in mail.postfix_settings("h", "c", "k") and "pcre:" in mail.postfix_settings("h", "c", "k")["transport_maps"]


def test_report_body_includes_web_attacks():
    ev = [{"ts": 1792800100, "source": "web firewall", "kind": "attack", "detail": "SQL injection (libinjection) — GET /?id=1 — blocked"},
          {"ts": 1792800000, "source": "SSH", "user": "root"}]
    body = abuse._body("192.0.2.9", {}, ev, "mail.example.com", "203.0.113.7", "")
    assert "1 unauthorized login attempt and 1 web attack" in body
    assert "web firewall: SQL injection" in body and "failed login as user 'root'" in body


def test_port_scan_is_evidence(monkeypatch):
    # The Network Monitor's "Sources" (firewall-logged connection attempts) count, not only failed logins.
    from backend import netmon
    ip = "85.217.140.39"
    scan = [{"ts": 1000 + i, "src": ip, "proto": "tcp", "port": 1000 + i} for i in range(12)]
    monkeypatch.setattr(netmon, "auth_events", lambda s: [])
    monkeypatch.setattr(netmon, "connections", lambda s: scan + [{"ts": 5, "src": "9.9.9.9", "proto": "tcp", "port": 22}])
    monkeypatch.setattr(netmon, "blocked", lambda s: [{"ts": 2000, "src": ip, "proto": "tcp", "port": 22, "blocked": True}])
    ev = abuse.evidence(ip)
    c = abuse._counts(ev)
    assert c == {"logins": 0, "attacks": 0, "probes": 13, "ports": 13}
    assert "13 connection attempts to 13 different ports (a port scan)" in abuse._what(c)
    body = abuse._body(ip, {"network": "NET"}, ev, "host", "1.2.3.4", "")
    assert "firewall: connection attempt to port 1011/tcp from 85.217.140.39" in body
    assert "dropped (banned)" in body and "9.9.9.9" not in body


def test_abuse_suggestions_prefer_role_address():
    # A registry that lists a person: keep it as the parsed default, but offer abuse@<domain> too,
    # and let a role address sort first when the registry does publish one.
    import json as _j
    from backend import abuse

    def fake_rdap(url, timeout=0):
        class R:
            def read(s):
                return _j.dumps({"name": "NET-1", "country": "US", "entities": [
                    {"roles": ["administrative"], "vcardArray": ["vcard", [["email", {}, "text", "andrew.clarke@hostus.us"]]]}]}).encode()
        return R()
    import urllib.request
    abuse._cache.clear()
    import pytest as _p
    monkeypatch = _p.MonkeyPatch()
    monkeypatch.setattr(urllib.request, "urlopen", fake_rdap)
    try:
        out = abuse.lookup("160.119.66.206")
    finally:
        monkeypatch.undo()
    assert out["contacts"] == ["andrew.clarke@hostus.us"]            # parsed default unchanged
    assert "abuse@hostus.us" in out["suggestions"]                   # role address offered


def test_counts_handles_probes_without_a_port():
    # Regression: SSH pre-auth probes (kind "probe") have no 'port'; _counts must not crash,
    # and firewall probes with ports are still summarised as a scan.
    from backend import abuse
    ev = [{"kind": "probe", "source": "SSH", "detail": "Connection closed [preauth]", "ts": 1},  # no port
          {"kind": "probe", "source": "firewall", "port": "22/tcp", "ts": 2},
          {"kind": "probe", "source": "firewall", "port": "80/tcp", "ts": 3},
          {"kind": "login", "source": "SSH", "ts": 4}]
    c = abuse._counts(ev)
    assert c == {"logins": 1, "attacks": 0, "probes": 3, "ports": 2}
    assert "3 connection attempts to 2 different ports" in abuse._what(c)
    # pure SSH probes, no ports -> "rejected connection attempts", no crash
    c2 = abuse._counts([{"kind": "probe", "source": "SSH", "ts": 1}])
    assert c2["ports"] == 0 and "1 rejected connection attempt" in abuse._what(c2)
