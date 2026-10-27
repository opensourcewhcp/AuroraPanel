"""Security Report + Panel HTTPS name coverage: the pure parts (no network, no systemd)."""
from backend import panelhttps, secreport


def test_clean_name_and_covers():
    assert panelhttps.clean_name(" NS0.Local ") == "ns0.local"
    assert panelhttps.clean_name("[2001:db8::1]") == "2001:db8::1"
    assert panelhttps.clean_name("localhost") == ""
    assert panelhttps.clean_name("not a host") == ""
    names = ["ns0", "ns0.local", "*.example.com", "192.168.0.100"]
    assert panelhttps.covers(names, "ns0")
    assert panelhttps.covers(names, "NS0.LOCAL")
    assert panelhttps.covers(names, "192.168.0.100")
    assert panelhttps.covers(names, "panel.example.com")
    assert not panelhttps.covers(names, "a.b.example.com")  # wildcards match one label only
    assert not panelhttps.covers(names, "71.197.107.133")
    assert not panelhttps.covers(names, "")


def test_grade_and_deductions():
    assert secreport.grade(100) == "A+" and secreport.grade(90) == "A" and secreport.grade(80) == "B"
    assert secreport.grade(65) == "C" and secreport.grade(50) == "D" and secreport.grade(10) == "F"
    assert secreport.DEDUCT["critical"] > secreport.DEDUCT["high"] > secreport.DEDUCT["medium"] > secreport.DEDUCT["low"] > secreport.DEDUCT["info"] == 0


def test_header_findings_match_the_scanner_wording():
    bare = {"status": 200, "headers": {"server": "Apache/2.4.69 (Debian)", "x-powered-by": "PHP/8.4"}, "cookies": ["PHPSESSID=abc; path=/"]}
    ids = {f["id"] for f in secreport._header_findings(bare, "site", "vhosts", "apache_harden", True)}
    assert {"server-header", "x-powered-by", "x-frame-options", "csp", "nosniff", "referrer-policy", "hsts", "cookie-PHPSESSID"} <= ids
    hardened = {"status": 200, "headers": {"server": "Apache", "x-frame-options": "SAMEORIGIN", "content-security-policy": "frame-ancestors 'self'",
                "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin", "strict-transport-security": "max-age=31536000"},
                "cookies": ["sid=1; Secure; HttpOnly; SameSite=Lax"]}
    assert secreport._header_findings(hardened, "site", "vhosts", "apache_harden", True) == []
    # a CSP with frame-ancestors is as good as X-Frame-Options
    csp_only = {"status": 200, "headers": {"content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"}, "cookies": []}
    assert "x-frame-options" not in {f["id"] for f in secreport._header_findings(csp_only, "panel", "panelhttps", "", True)}


def test_report_html_is_self_contained():
    rep = {"ts": 1_800_000_000, "took": 2.5, "hostname": "ns0", "score": 72, "grade": "C",
           "counts": {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 1},
           "targets": [{"id": "site:x.test", "kind": "site", "label": "Website · x.test", "score": 72, "grade": "C", "facts": {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "cert": {"days": 40}},
                        "findings": [{"severity": "high", "title": "Weak <cipher>", "detail": "d & e", "fix": "Harden"}]}],
           "weakest": "site:x.test", "fixes": ["apache_harden"]}
    h = secreport.report_html(rep)
    assert "<!doctype html>" in h and "Weak &lt;cipher&gt;" in h and "d &amp; e" in h and "72" in h and "ns0" in h
    assert "http://" not in h and "https://" not in h  # no external assets


def test_targets_only_own_things(monkeypatch):
    """Whatever modules say, the list is built from this server's names and sites — never a free-text target."""
    monkeypatch.setattr(panelhttps, "status", lambda scheme, host="": {"enabled": True, "port": 8088})
    monkeypatch.setattr(panelhttps, "_known_names", lambda: ["ns0", "192.168.0.100", "localhost"])
    import backend.sites as sites
    monkeypatch.setattr(sites, "list_sites", lambda: {"sites": [{"server_name": "a.test", "aliases": ["www.a.test"], "enabled": True, "ssl": "selfsigned", "force_https": False, "has_http": True, "conf": "a.test.conf"},
                                                                 {"server_name": "off.test", "aliases": [], "enabled": False, "ssl": "none"}]})
    import backend.mail as mail
    monkeypatch.setattr(mail, "load", lambda: {"domains": {}, "accounts": {}})
    ids = [t["id"] for t in secreport.targets()]
    assert "panel:ns0" in ids and "panel:192.168.0.100" in ids and "panel:localhost" not in ids
    assert "site:a.test" in ids and "site:www.a.test" in ids and "site:off.test" not in ids
    assert "ip:192.168.0.100" in ids and not any(i.startswith("mail:") for i in ids) and "server" in ids
