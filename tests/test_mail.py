"""Email: the state → Postfix / Dovecot / Sieve / Rspamd rendering and input validation."""
import pytest

from backend import mail

H = "{SHA512-CRYPT}$6$salt$hash"


def state(**kw):
    s = mail._default_state()
    s["domains"] = {"ex.com": {"routing": "local", "catchall": {"mode": "fail", "message": "Nobody here"}}}
    s["accounts"] = {"alice@ex.com": {"hash": H, "quota_mb": 100, "suspend": {}},
                     "bob@ex.com": {"hash": H, "quota_mb": 0, "suspend": {"incoming": True, "outgoing": True, "login": True}}}
    s.update(kw)
    return s


def test_addresses_are_validated():
    assert mail._addr(" Alice@Ex.COM ") == "alice@ex.com"
    for bad in ("alice", "a@b", "a b@ex.com", "-a@ex.com", "a..b@ex.com", "a@ex..com", "a@ex.com\nX"):
        with pytest.raises(mail.MailError):
            mail._addr(bad)
    assert mail._ext_addr("Some.One+tag@Gmail.com") == "Some.One+tag@gmail.com"


def test_postfix_maps():
    s = state(forwarders={"sales@ex.com": {"type": "forward", "dest": ["alice@ex.com", "x@gmail.com"]},
                          "alice@ex.com": {"type": "forward", "dest": ["me@gmail.com"]},
                          "old@ex.com": {"type": "fail", "message": "Gone"},
                          "junk@ex.com": {"type": "discard", "dest": []}},
              lists={"team@ex.com": {"members": ["alice@ex.com"]}})
    m = mail.render_postfix(s)
    assert "ex.com OK" in m["domains"]
    assert "alice@ex.com ex.com/alice/" in m["mailboxes"] and "team@ex.com lists/team@ex.com/" in m["mailboxes"]
    al = m["aliases"].splitlines()
    assert "sales@ex.com alice@ex.com, x@gmail.com" in al
    assert "alice@ex.com alice@ex.com, me@gmail.com" in al   # a mailbox with a forwarder keeps a copy
    assert "bob@ex.com bob@ex.com" in al                    # identity entry so a catch-all can't swallow it
    assert "junk@ex.com discard@discard.aurora.invalid" in al
    ra = m["recipient_access"].splitlines()
    assert "old@ex.com REJECT Gone" in ra and "bob@ex.com REJECT This mailbox is not accepting mail right now" in ra
    assert "alice@ex.com DUNNO" in ra and "ex.com REJECT Nobody here" in ra   # access maps key on the bare domain
    assert ra.index("alice@ex.com DUNNO") < ra.index("ex.com REJECT Nobody here")
    assert "bob@ex.com REJECT" in m["sasl_access"]
    assert "team@ex.com auroralist:" in m["transport"] and "discard.aurora.invalid discard:" in m["transport"]
    assert "sales@ex.com alice@ex.com" in m["sender_login"]   # alice may send as sales@


def test_catchall_and_domain_forwarders():
    s = state()
    s["domains"]["ex.com"]["catchall"] = {"mode": "forward", "target": "alice@ex.com"}
    m = mail.render_postfix(s)
    assert "@ex.com alice@ex.com" in m["aliases"] and "REJECT Nobody" not in m["recipient_access"]
    s["domain_forwarders"] = {"ex.com": "new.com"}
    assert "@ex.com @new.com" in mail.render_postfix(s)["aliases"]


def test_routing_backup_and_remote():
    s = state()
    s["domains"]["ex.com"]["routing"] = "backup"
    m = mail.render_postfix(s)
    assert m["domains"] == "" and "ex.com OK" in m["relay_domains"] and "alice@ex.com" not in m["mailboxes"]
    s["domains"]["ex.com"]["routing"] = "remote"
    m = mail.render_postfix(s)
    assert m["domains"] == "" and m["relay_domains"] == ""


def test_dovecot_users():
    t = mail.render_dovecot_users(state())
    assert f"alice@ex.com:{H}::::::userdb_quota_storage_size=100M" in t
    assert "bob@ex.com:" in t and "nologin=y" in t.split("bob@ex.com:")[1]


def test_user_sieve_spam_filters_and_vacation():
    s = state()
    s["filters"]["alice@ex.com"] = [mail._clean_filter({"name": "News", "rules": [{"part": "from", "op": "contains", "value": 'news"letter'}],
                                                         "actions": [{"type": "fileinto", "value": "News/Weekly"}]})]
    s["autoresponders"]["alice@ex.com"] = {"enabled": True, "subject": "Away: %subject%", "body": "Hi %from%\n.dot\nbye",
                                           "interval_hours": 6, "start": 1790000000, "stop": None, "from_name": ""}
    s["spam"]["per_user"]["alice@ex.com"] = {"enabled": True, "threshold": 4, "junk": True, "autodelete": True,
                                             "delete_threshold": 9, "allow": ["boss@corp.com", "friends.org"], "block": ["spam.biz"]}
    t = mail.render_user_sieve(s, "alice@ex.com")
    assert t.startswith(mail.HEADER) and 'require [' in t
    for ext in ("vacation", "vacation-seconds", "variables", "date", "relational", "fileinto", "mailbox"):
        assert f'"{ext}"' in t
    assert 'address :domain :is "from" ["spam.biz"]' in t and "discard;" in t
    assert 'header :contains "X-Spam-Level" "*********"' in t and 'header :contains "X-Spam-Level" "****"' in t
    assert 'address :is "from" ["boss@corp.com"]' in t and 'address :domain :is "from" ["friends.org"]' in t
    assert ':seconds 21600' in t and "${subject}" in t and "${from}" in t
    assert "\n..dot\n" in t                         # dot-stuffed multi-line string
    assert 'header :contains "from" "news\\"letter"' in t and 'fileinto :create "News/Weekly";' in t


def test_filter_validation():
    ok = {"name": "x", "rules": [{"part": "size", "op": "over", "value": "5M"}], "actions": [{"type": "redirect", "value": "a@b.co"}]}
    assert mail._clean_filter(ok)["rules"][0]["value"] == "5M"
    for bad in ({**ok, "name": ""}, {**ok, "rules": []}, {**ok, "actions": []},
                {**ok, "rules": [{"part": "size", "op": "over", "value": "lots"}]},
                {**ok, "rules": [{"part": "subject", "op": "regex", "value": "("}]},
                {**ok, "actions": [{"type": "fileinto", "value": "../etc"}]},
                {**ok, "actions": [{"type": "pipe", "value": "/bin/sh"}]},
                {**ok, "rules": [{"part": "header", "op": "is", "value": "x", "header": "Bad Header:"}]}):
        with pytest.raises(mail.MailError):
            mail._clean_filter(bad)


def test_global_sieve_empty_and_rspamd():
    s = state()
    assert "require" not in mail.render_global_sieve(s)
    s["spam"].update(threshold=6, greylist=True, allow=["ok.com", "a@b.com"], block=["bad.biz"])
    r = mail.render_rspamd(s)
    assert "add_header = 6;" in r["local.d/actions.conf"] and "greylist = 5;" in r["local.d/actions.conf"]
    assert r["aurora/allow_domain.map"].strip() == "ok.com" and r["aurora/allow_addr.map"].strip() == "a@b.com"
    assert "try_fallback = true;" in r["local.d/dkim_signing.conf"]


def test_spf_suggestion_keeps_existing_terms():
    assert mail._suggest_spf("ex.com", "", "1.2.3.4") == "v=spf1 +a +mx +ip4:1.2.3.4 ~all"
    assert mail._suggest_spf("ex.com", "v=spf1 include:_spf.google.com -all", "1.2.3.4") == "v=spf1 include:_spf.google.com +ip4:1.2.3.4 -all"
    assert mail._suggest_spf("ex.com", "v=spf1 ip4:1.2.3.4 ~all", "1.2.3.4") == "v=spf1 ip4:1.2.3.4 ~all"


def test_import_preview(monkeypatch):
    monkeypatch.setattr(mail, "load", lambda: state())
    r = mail.import_csv("accounts", "email,password\nnew@ex.com,\njohn,Secret-pass-1\nalice@ex.com,\nbad@@x,", True, "ex.com")
    rows = {x["line"]: x for x in r["rows"]}
    assert rows[1]["ok"] and rows[1]["generated"] and rows[2]["address"] == "john@ex.com"
    assert not rows[3]["ok"] and "exists" in rows[3]["error"] and not rows[4]["ok"]
    f = mail.import_csv("forwarders", "source,destination\nsales,a@x.com;b@y.com", True, "ex.com")
    assert f["rows"][0]["dest"] == "a@x.com,b@y.com"


def test_mobileconfig_is_xml(monkeypatch):
    monkeypatch.setattr(mail, "hostname", lambda s=None: "mail.ex.com")
    import xml.dom.minidom
    xml.dom.minidom.parseString(mail.mobileconfig("alice@ex.com"))


def test_autoresponder_save_cleans_from_name(monkeypatch):
    s = state()
    monkeypatch.setattr(mail, "load", lambda: s)
    monkeypatch.setattr(mail, "save", lambda x: None)
    monkeypatch.setattr(mail, "apply", lambda x=None: {"ok": True})
    mail.set_autoresponder("alice@ex.com", {"subject": "Away", "body": "Back soon", "from_name": 'Carol "CJ" <x>\\'})
    assert s["autoresponders"]["alice@ex.com"]["from_name"] == "Carol CJ x"
    with pytest.raises(mail.MailError):
        mail.set_autoresponder("nobody@ex.com", {"subject": "a", "body": "b"})
    with pytest.raises(mail.MailError):
        mail.set_autoresponder("alice@ex.com", {"subject": "a", "body": "b", "start": "2026-02-01T00:00:00Z", "stop": "2026-01-01T00:00:00Z"})


def test_ip_address_is_not_a_mail_domain():
    # name@192.168.0.100 is refused by webmail and mail apps: point to local mail instead.
    assert mail.is_ip_name("192.168.0.100") and not mail.is_ip_name("ns0.local") and not mail.is_ip_name("1.example.com")
    with pytest.raises(mail.MailError, match="Local mail"):
        mail._ensure_domain({"domains": {}}, "192.168.0.100")
    s = {"domains": {"192.168.0.100": {"routing": "auto"}}}
    assert mail._ensure_domain(s, "192.168.0.100") is s["domains"]["192.168.0.100"]  # an existing one keeps working
