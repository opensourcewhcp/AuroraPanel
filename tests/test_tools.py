"""Small parsers behind the Advanced tools: fail2ban activity, WHOIS summary, .htaccess options."""
from backend import fail2ban, netdiag


LOG = """2026-10-22 11:20:18,453 fail2ban.filter         [1029]: INFO    [aurora-panel] Found 192.168.0.2 - 2026-10-22 11:20:18
2026-10-22 11:20:18,453 fail2ban.observer       [1029]: INFO    [aurora-panel] Found 192.168.0.2, bad - 2026-10-22 11:20:18, 1 # -> 2.0
2026-10-22 11:54:21,779 fail2ban.actions        [1045]: NOTICE  [aurora-panel] Restore Ban 192.168.0.2
2026-10-22 12:01:35,234 fail2ban.actions        [1046]: NOTICE  [aurora-panel] Unban 192.168.0.2
2026-10-22 12:02:00,000 fail2ban.actions        [1046]: NOTICE  [sshd] Ban 203.0.113.9
2026-10-25 16:36:00,804 fail2ban.filter         [1046]: INFO    [apache-auth] Ignore 192.168.0.2 by ip
"""


def test_fail2ban_events_parse():
    ev = fail2ban.parse_events(LOG)
    kinds = [(e["jail"], e["kind"], e["ip"], e["restored"]) for e in ev]
    assert kinds == [("aurora-panel", "failure", "192.168.0.2", False), ("aurora-panel", "ban", "192.168.0.2", True),
                     ("aurora-panel", "unban", "192.168.0.2", False), ("sshd", "ban", "203.0.113.9", False)]
    assert ev[0]["ts"] < ev[-1]["ts"]


def test_fail2ban_events_reads_files(tmp_path, monkeypatch):
    p = tmp_path / "fail2ban.log"; p.write_text(LOG, encoding="utf-8")
    monkeypatch.setattr(fail2ban, "LOG_FILES", (tmp_path / "missing.log.1", p))
    r = fail2ban.events(limit=2)
    assert len(r["events"]) == 2 and r["events"][0]["ip"] == "203.0.113.9"  # newest first, limited


def test_whois_summary_picks_the_useful_lines():
    text = """Domain Name: EXAMPLE.COM
   Registrar: Example Registrar, Inc.
   Updated Date: 2025-08-14T07:01:31Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2026-08-13T04:00:00Z
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
"""
    s = netdiag.whois_summary(text)
    assert s["Registrar"] == "Example Registrar, Inc."
    assert s["Created"].startswith("1995") and s["Expires"].startswith("2026")
    assert s["Name servers"] == "A.IANA-SERVERS.NET, B.IANA-SERVERS.NET"
    assert s["Status"] == "clientDeleteProhibited"
    ip = netdiag.whois_summary("NetRange: 203.0.113.0 - 203.0.113.255\nCIDR: 203.0.113.0/24\nNetName: TEST-NET-3\nOrgName: Example Org\nCountry: US\n")
    assert ip["Network"] == "TEST-NET-3" and ip["Range"] == "203.0.113.0/24" and ip["Country"] == "US"


def test_htaccess_options_and_handlers(tmp_path, monkeypatch):
    from backend import apache
    root = tmp_path / "www"; (root / "html").mkdir(parents=True)
    monkeypatch.setattr(apache, "APACHE_ROOT", root.resolve())
    assert apache.list_options("html")["options"]["ExecCGI"] is None
    apache.set_option("html", "ExecCGI", True)
    apache.set_option("html", "includes", True)
    assert (root / "html" / ".htaccess").read_text().splitlines() == ["Options +ExecCGI", "Options +Includes"]
    assert apache.list_options("html")["options"]["Includes"] is True
    apache.set_option("html", "ExecCGI", False)
    assert apache.list_options("html")["options"]["ExecCGI"] is None
    apache.add_handler("html", "cgi-script", "cgi .pl")
    apache.add_handler("html", "server-parsed", "")   # whole folder → SetHandler
    apache.add_handler("html", "default-handler", "")  # replaces the previous SetHandler
    text = (root / "html" / ".htaccess").read_text()
    assert "AddHandler cgi-script cgi pl" in text and text.count("SetHandler") == 1 and "SetHandler default-handler" in text
    r = apache.create_error_page("html", "404", "/404.html")
    assert r["created"] and "Page not found" in (root / "html" / "404.html").read_text()
    assert apache.create_error_page("html", "404", "404.html")["created"] is False
    apache.set_error("html", "503", "/oops/503.html", create="oops/503.html")
    assert (root / "html" / "oops" / "503.html").exists() and "ErrorDocument 503 /oops/503.html" in (root / "html" / ".htaccess").read_text()
