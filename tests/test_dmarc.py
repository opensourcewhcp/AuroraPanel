"""DMARC: parse / build / validate, the wizard, grading, DNS lookups and publishing (DNS and zones faked)."""
import pytest

from backend import dmarc, dnszones


@pytest.fixture(autouse=True)
def _no_local_dns(monkeypatch, request):
    """No BIND on a test box: this server's own DNS reads as down unless a test fakes it."""
    if "real_local_txt" in request.keywords:
        return
    def down(name):
        raise dmarc._LocalDown("no server")
    monkeypatch.setattr(dmarc, "_local_txt", down)
    monkeypatch.setattr(dmarc.time, "sleep", lambda s: None)
    monkeypatch.setattr(dmarc, "_authoritative", lambda z: True)  # a zone here is the public one unless a test says otherwise


def test_names():
    assert dmarc.clean_domain(" WWW.Example.COM. ") == "example.com"
    with pytest.raises(dmarc.DmarcError):
        dmarc.clean_domain("not a domain")
    assert dmarc.is_public("example.com") and not dmarc.is_public("ns0.local") and not dmarc.is_public("192.168.0.1") and not dmarc.is_public("")
    assert dmarc.org_domain("a.b.example.com") == "example.com"
    assert dmarc.org_domain("shop.example.co.uk") == "example.co.uk"
    assert dmarc.org_domain("example.com") == "example.com"


def test_parse_and_settings():
    t = dmarc.parse("v=DMARC1; p=Reject; sp=none; pct=50; rua=mailto:a@x.com!10m, mailto:b@x.com; ruf=mailto:f@x.com; adkim=s; aspf=r; ri=3600; junk")
    s = dmarc.settings_from(t)
    assert s == {"enabled": True, "p": "reject", "sp": "none", "pct": 50, "rua": ["a@x.com", "b@x.com"], "ruf": ["f@x.com"],
                 "adkim": "s", "aspf": "r", "fo": "0", "ri": 3600}
    assert dmarc.parse("v=spf1 -all") == {} and dmarc.parse("") == {}
    assert dmarc.settings_from({}) == {**dmarc.DEFAULTS, "enabled": False}
    odd = dmarc.settings_from({"v": "DMARC1", "p": "bogus", "sp": "bogus", "pct": "x", "ri": "y"})
    assert odd["p"] == "none" and odd["sp"] == "" and odd["pct"] == 100 and odd["ri"] == dmarc.DEFAULT_RI


@pytest.mark.parametrize("bad, msg", [
    ({"p": "maybe"}, "Policy"), ({"sp": "x"}, "Subdomain"), ({"pct": "x"}, "Percentage"), ({"pct": 0}, "Percentage"),
    ({"rua": ["nope"]}, "valid report"), ({"ruf": "bad@"}, "failure report"), ({"rua": [f"a{i}@x.com" for i in range(6)]}, "At most"),
    ({"adkim": "q"}, "Alignment"), ({"fo": "7"}, "Failure reporting"), ({"ri": "x"}, "seconds"), ({"ri": 60}, "between"),
])
def test_validate_rejects(bad, msg):
    with pytest.raises(dmarc.DmarcError, match=msg):
        dmarc.validate(bad)


def test_build_and_explain():
    assert dmarc.build({"p": "none"}) == "v=DMARC1; p=none; adkim=r; aspf=r"
    assert "fo=" not in dmarc.build({"p": "none", "ruf": ["f@x.com"]})
    full = {"p": "quarantine", "sp": "reject", "pct": 25, "rua": "mailto:a@x.com, b@x.com a@x.com", "ruf": ["f@x.com"], "fo": "1:d:1", "adkim": "s", "aspf": "s", "ri": 3600}
    rec = dmarc.build(full)
    assert rec == "v=DMARC1; p=quarantine; sp=reject; pct=25; rua=mailto:a@x.com,mailto:b@x.com; ruf=mailto:f@x.com; fo=1:d; adkim=s; aspf=s; ri=3600"
    tags = [x["tag"] for x in dmarc.explain(full, "x.com")]
    assert "sp=reject" in tags and "pct=25" in tags and "ruf=…" in tags and "adkim=s" in tags
    plain = [x["tag"] for x in dmarc.explain({"p": "none"})]
    assert "(no sp)" in plain and "(no rua)" in plain
    assert "x.com" in dmarc.explain(full, "x.com")[2]["text"]


def test_recommend_paths():
    r = dmarc.recommend("example.com", {"sends": "none", "reports": ""})
    assert r["settings"]["p"] == "reject" and r["settings"]["sp"] == "" and r["external"] == []
    r = dmarc.recommend("example.com", {"sends": "here", "stage": "new", "reports": ""})
    assert r["settings"]["p"] == "none" and any("Without reports" in w for w in r["why"])
    r = dmarc.recommend("example.com", {"sends": "both", "stage": "monitored", "reports": "dmarc@example.com", "subdomains": "reject", "alignment": "strict"})
    assert r["record"] == "v=DMARC1; p=quarantine; sp=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s"
    assert any("Other services" in w for w in r["why"])
    r = dmarc.recommend("example.com", {"sends": "elsewhere", "stage": "confident", "reports": "me@reports.net"})
    assert r["settings"]["p"] == "reject" and r["external"] == [{"address": "me@reports.net", "name": "example.com._report._dmarc.reports.net", "value": "v=DMARC1"}]
    assert dmarc.recommend("example.com", None)["settings"]["p"] == "none"


def test_external_auth_same_org():
    assert dmarc.external_auth("shop.example.com", ["a@example.com", "b@shop.example.com", "c@x.example.com"]) == []


def _ids(a):
    return {f["id"] for f in a["findings"]}


def test_assess_levels():
    a = dmarc.assess("x.com", {}, "", False, True)
    assert a["level"] == "missing" and a["grade"] == "F" and {"dmarc-missing", "spf-missing", "dkim-missing"} <= _ids(a)
    assert next(f for f in a["findings"] if f["id"] == "dmarc-missing")["severity"] == "high"
    a = dmarc.assess("x.com", {}, "v=spf1 -all", False, False, inherited="v=DMARC1; p=reject")
    assert a["level"] == "inherited" and _ids(a) == {"dmarc-inherited"}
    a = dmarc.assess("x.com", dmarc.parse("v=DMARC1; p=none"), "v=spf1 mx ?all", True, True)
    assert a["level"] == "monitor" and {"dmarc-none", "dmarc-no-rua", "spf-neutral"} <= _ids(a)
    a = dmarc.assess("x.com", dmarc.parse("v=DMARC1; p=reject; pct=50; rua=mailto:a@x.com; sp=none"), "v=spf1 +all", True, True)
    assert a["level"] == "partial" and {"dmarc-pct", "dmarc-sp-none", "spf-all"} <= _ids(a) and a["grade"] == "C"
    a = dmarc.assess("x.com", dmarc.parse("v=DMARC1; p=quarantine; rua=mailto:a@x.com"), "v=spf1 mx -all", True, True)
    assert a["level"] == "partial" and not a["findings"] and a["grade"] == "B"
    a = dmarc.assess("x.com", dmarc.parse("v=DMARC1; p=reject; rua=mailto:a@x.com"), "v=spf1 mx -all", True, True)
    assert a["level"] == "enforced" and a["grade"] == "A" and all(n["tone"] == "good" for n in a["notes"])


class _RR:
    def __init__(self, *parts):
        self.strings = [p.encode() for p in parts]


def test_txt_and_lookup(monkeypatch):
    class Res:
        def resolve(self, name, kind):
            if name == "boom":
                raise RuntimeError("nxdomain")
            return [_RR("v=spf1 ", "-all")]
    assert dmarc._resolver().lifetime == 5
    monkeypatch.setattr(dmarc, "_resolver", lambda: Res())
    assert dmarc._txt("x.com") == ["v=spf1 -all"]
    assert dmarc._txt("boom") == []
    db = {"_dmarc.a.example.com": [], "_dmarc.example.com": ["v=DMARC1; p=reject"], "a.example.com": ["google-site", "v=spf1 mx -all"],
          "google._domainkey.a.example.com": ["v=DKIM1; k=rsa; p=MIIB"]}
    monkeypatch.setattr(dmarc, "_txt", lambda n: db.get(n, []))
    r = dmarc.lookup("a.example.com")
    assert r == {"record": "", "parent": "v=DMARC1; p=reject", "org": "example.com", "spf": "v=spf1 mx -all", "dkim": True}
    db["_dmarc.a.example.com"] = ["v=DMARC1;p=none"]
    db.pop("google._domainkey.a.example.com")
    r = dmarc.lookup("a.example.com")
    assert r["record"] == "v=DMARC1;p=none" and r["parent"] == "" and r["dkim"] is False


def test_sends_here(monkeypatch):
    import backend.mail as mail
    monkeypatch.setattr(mail, "load", lambda: {"domains": {"x.com": {}}})
    assert dmarc._sends_here("x.com") and not dmarc._sends_here("y.com")
    monkeypatch.setattr(mail, "load", lambda: (_ for _ in ()).throw(OSError("no mail")))
    assert dmarc._sends_here("x.com") is False


class FakeZones:
    def __init__(self, zones):
        self.zones = zones  # name -> records

    def install(self, monkeypatch):
        class P:
            def __init__(s, d):
                s.d = d

            def exists(s):
                if s.d == "explode.com":
                    raise OSError("bad")
                return s.d in self.zones
        monkeypatch.setattr(dnszones, "_path", lambda d: P(d))
        monkeypatch.setattr(dnszones, "get_zone", lambda d: {"records": list(self.zones[d])})
        monkeypatch.setattr(dnszones, "delete_record", lambda d, i: self.zones[d].pop(i))
        monkeypatch.setattr(dnszones, "add_record", lambda d, r: self.zones[d].append(r))


def test_zone_helpers(monkeypatch):
    z = FakeZones({"example.com": [{"type": "TXT", "name": "_dmarc.shop.example.com.", "text": "v=DMARC1; p=none"},
                                   {"type": "TXT", "name": "_dmarc.shop.example.com.", "text": "hello"},
                                   {"type": "A", "name": "example.com.", "address": "1.2.3.4"},
                                   {"type": "TXT", "name": "_dmarc.shop.example.com.", "text": "v=DMARC1; p=reject"}]})
    z.install(monkeypatch)
    assert dmarc._zone_for("shop.example.com") == "example.com"
    assert dmarc._zone_for("other.org") == ""
    assert dmarc._zone_for("a.explode.com") == ""
    text, idx = dmarc._zone_record("example.com", "shop.example.com")
    assert text == "v=DMARC1; p=none" and idx == [0, 3]
    r = dmarc.save("shop.example.com", {"p": "reject", "rua": ["dmarc@elsewhere.net"]})
    assert r["published"] and r["zone"] == "example.com" and r["external"][0]["name"] == "shop.example.com._report._dmarc.elsewhere.net"
    recs = [x for x in z.zones["example.com"] if x["type"] == "TXT" and "DMARC1" in x.get("text", "")]
    assert len(recs) == 1 and recs[0]["text"].startswith("v=DMARC1; p=reject") and recs[0]["name"] == "_dmarc.shop.example.com."
    assert dmarc.remove("shop.example.com") == {"removed": 1}
    r = dmarc.save("other.org", {"p": "none"})
    assert not r["published"] and r["value"] == "v=DMARC1; p=none; adkim=r; aspf=r" and r["name"] == "_dmarc.other.org"
    with pytest.raises(dmarc.DmarcError, match="isn't served"):
        dmarc.remove("other.org")


def test_status(monkeypatch):
    assert dmarc.status("ns0.local")["public"] is False
    z = FakeZones({"example.com": [{"type": "TXT", "name": "_dmarc.example.com.", "text": "v=DMARC1; p=quarantine; rua=mailto:d@example.com"}]})
    z.install(monkeypatch)
    monkeypatch.setattr(dmarc, "lookup", lambda d: {"record": "v=DMARC1; p=none", "parent": "", "org": "example.com", "spf": "v=spf1 mx -all", "dkim": True})
    monkeypatch.setattr(dmarc, "_sends_here", lambda d: True)
    st = dmarc.status("example.com")
    assert st["public"] and st["zone"] == "example.com" and st["pending"] is True
    assert st["settings"]["p"] == "quarantine" and st["assess"]["level"] == "monitor" and st["default_reports"] == "dmarc@example.com"
    monkeypatch.setattr(dnszones, "get_zone", lambda d: (_ for _ in ()).throw(dnszones.ZoneError("broken")))
    st = dmarc.status("example.com")
    assert st["zone_record"] == "" and st["settings"]["p"] == "none" and st["pending"] is False
    monkeypatch.setattr(dmarc, "_sends_here", lambda d: False)
    z.zones.clear()
    st = dmarc.status("example.com")
    assert st["zone"] == "" and st["default_reports"] == "postmaster@example.com"


def test_domains_lists_mail_and_site_main_domains(monkeypatch):
    import backend.mail as mail
    import backend.sites as sites
    monkeypatch.setattr(mail, "load", lambda: {"domains": {"shop.com": {}, "ns0.local": {}}})
    monkeypatch.setattr(sites, "list_sites", lambda: {"sites": [{"server_name": "www.blog.example.org"}, {"server_name": "shop.com"},
                                                                {"server_name": "192.168.0.5", "system": True}, {"server_name": "x.test"}]})
    assert dmarc.domains() == [{"domain": "shop.com", "mail": True, "sites": ["shop.com"]},
                               {"domain": "example.org", "mail": False, "sites": ["www.blog.example.org"]}]
    monkeypatch.setattr(mail, "load", lambda: (_ for _ in ()).throw(OSError("x")))
    monkeypatch.setattr(sites, "list_sites", lambda: (_ for _ in ()).throw(OSError("x")))
    assert dmarc.domains() == []


@pytest.mark.real_local_txt
def test_local_txt(monkeypatch):
    import dns.resolver
    seen = {}

    class R:
        def __init__(self, configure=True):
            seen["configure"] = configure

        def resolve(self, name, kind):
            seen["ns"] = self.nameservers
            if name == "nx":
                raise dns.resolver.NXDOMAIN()
            if name == "none":
                raise dns.resolver.NoAnswer()
            if name == "down":
                raise dns.resolver.NoNameservers()
            return [_RR("v=DMARC1; ", "p=none")]
    monkeypatch.setattr(dns.resolver, "Resolver", R)
    assert dmarc._local_txt("_dmarc.x.com") == ["v=DMARC1; p=none"] and seen == {"configure": False, "ns": ["127.0.0.1"]}
    assert dmarc._local_txt("nx") == [] and dmarc._local_txt("none") == []
    with pytest.raises(dmarc._LocalDown):
        dmarc._local_txt("down")


def test_live_records_prefers_this_servers_dns(monkeypatch):
    pub = {"_dmarc.x.com": ["v=DMARC1; p=none"], "x.com": ["v=spf1 mx ~all"]}
    loc = {"_dmarc.x.com": ["v=DMARC1; p=quarantine"], "x.com": ["v=spf1 mx ~all"], "aurora._domainkey.x.com": ["v=DKIM1; p=AB"]}
    monkeypatch.setattr(dmarc, "_txt", lambda n: pub.get(n, []))
    monkeypatch.setattr(dmarc, "_zone_for", lambda d: "")
    r = dmarc.live_records("x.com")
    assert r["record"] == "v=DMARC1; p=none" and not r["here"] and not r["propagating"]
    monkeypatch.setattr(dmarc, "_zone_for", lambda d: "x.com")
    r = dmarc.live_records("x.com")  # this server's DNS is down: the public answer stands
    assert r["record"] == "v=DMARC1; p=none" and not r["here"]
    monkeypatch.setattr(dmarc, "_local_txt", lambda n: loc.get(n, []))
    r = dmarc.live_records("x.com")
    assert r["record"] == "v=DMARC1; p=quarantine" and r["public"] == "v=DMARC1; p=none" and r["here"] and r["propagating"] and r["dkim"]
    pub["_dmarc.x.com"] = loc["_dmarc.x.com"]
    assert dmarc.live_records("x.com")["propagating"] is False


def test_verify(monkeypatch):
    assert dmarc.verify("x.com", "v=DMARC1; p=none") is False  # server down, every try
    answers = iter([[], ["v=DMARC1;  p=none;"]])
    monkeypatch.setattr(dmarc, "_local_txt", lambda n: next(answers))
    assert dmarc.verify("x.com", "v=DMARC1; p=none") is True
    monkeypatch.setattr(dmarc, "_local_txt", lambda n: ["v=DMARC1; p=reject"])
    assert dmarc.verify("x.com", "v=DMARC1; p=none", tries=2) is False


def test_next_step():
    ns = lambda rec, sends=True: dmarc.next_step(dmarc.parse(rec), "x.com", sends)
    s = ns("")
    assert s["p"] == "none" and s["rua"] == ["dmarc@x.com"]
    assert ns("", sends=False)["rua"] == ["postmaster@x.com"]
    s = ns("v=DMARC1; p=none; rua=mailto:a@x.com")
    assert s["p"] == "quarantine" and s["rua"] == ["a@x.com"]
    s = ns("v=DMARC1; p=quarantine; pct=40")
    assert s["p"] == "quarantine" and s["pct"] == 100
    s = ns("v=DMARC1; p=quarantine; sp=none")
    assert s["p"] == "reject" and s["sp"] == ""
    assert ns("v=DMARC1; p=reject")["p"] == "reject"


def test_step(monkeypatch):
    z = FakeZones({"x.com": []})
    z.install(monkeypatch)
    monkeypatch.setattr(dmarc, "_sends_here", lambda d: True)
    state = {"rec": "", "spf": "", "dkim": False}
    monkeypatch.setattr(dmarc, "live_records", lambda d: {"record": state["rec"], "spf": state["spf"], "dkim": state["dkim"]})
    served = []
    monkeypatch.setattr(dmarc, "_local_txt", lambda n: served)
    r = dmarc.step("x.com")  # nothing yet, own mail not authenticated: start by monitoring
    assert "p=none" in r["value"] and "monitoring" in r["message"] and r["verified"] is False
    state.update(spf="v=spf1 mx ~all", dkim=True)
    served.append("v=DMARC1; p=quarantine; rua=mailto:dmarc@x.com; adkim=r; aspf=r")
    r = dmarc.step("x.com")  # SPF and DKIM already pass: straight to quarantine
    assert "p=quarantine" in r["value"] and r["verified"] and "checked" in r["message"]
    assert len([x for x in z.zones["x.com"] if "DMARC1" in x["text"]]) == 1
    state["rec"] = "v=DMARC1; p=quarantine; rua=mailto:dmarc@x.com"
    assert "reject" in dmarc.step("x.com")["message"]
    with pytest.raises(dmarc.DmarcError, match="isn't served"):
        dmarc.step("other.org")


@pytest.mark.real_local_txt
def test_authoritative(monkeypatch):
    import backend.mail as mail
    monkeypatch.setattr(mail, "_my_names", lambda: {"vps.example.net", "203.0.113.5"})
    monkeypatch.setattr(mail, "_public_ip", lambda: "203.0.113.5")
    monkeypatch.setattr(mail, "_a", lambda n: {"ns1.x.com": ["203.0.113.5"]}.get(n, ["198.51.100.1"]))
    monkeypatch.setattr(mail, "_ns", lambda z: {"x.com": ["ns1.x.com", "ns2.other.net"], "y.com": ["vps.example.net"]}.get(z, ["ns.cloudflare.com"]))
    assert dmarc._authoritative("x.com") and dmarc._authoritative("y.com") and not dmarc._authoritative("z.com")
    monkeypatch.setattr(mail, "_ns", lambda z: (_ for _ in ()).throw(OSError("no dns")))
    assert dmarc._authoritative("x.com") is False


def test_zone_here_but_public_dns_elsewhere(monkeypatch):
    z = FakeZones({"x.com": []})
    z.install(monkeypatch)
    monkeypatch.setattr(dmarc, "_authoritative", lambda zone: False)
    monkeypatch.setattr(dmarc, "_txt", lambda n: [])
    monkeypatch.setattr(dmarc, "_local_txt", lambda n: ["v=DMARC1; p=reject"])
    r = dmarc.live_records("x.com")
    assert r["record"] == "" and not r["here"]  # the local zone is not what the world sees
    assert "DNS provider too" in dmarc.save("x.com", {"p": "none"})["message"]
    with pytest.raises(dmarc.DmarcError, match="isn't served"):
        dmarc.step("x.com")
    assert dmarc.status("x.com")["served"] is False
