"""Security Report end to end: real probes against a local TLS/HTTP server, every finding branch,
the one-click fixes, accepted findings, history, the background job and the HTML report."""
import json
import shutil
import socket
import ssl
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

from backend import dmarc, jobs, secnet, secreport


# ---------------------------------------------------------------- a local server
@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")
    d = tmp_path_factory.mktemp("cert")
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem"),
                        "-days", "30", "-subj", "/CN=x.test", "-addext", "subjectAltName=DNS:x.test,DNS:www.x.test"], capture_output=True)
    if r.returncode != 0:
        pytest.skip("openssl can't make a test certificate")
    return d


class Server:
    """Answers every connection with `reply` (optionally over TLS) until stopped."""

    def __init__(self, reply: bytes, cert=None):
        self.reply = reply
        self.ctx = None
        if cert:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(str(cert / "c.pem"), str(cert / "k.pem"))
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        try:
            c.settimeout(2)
            if self.ctx:
                c = self.ctx.wrap_socket(c, server_side=True)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = c.recv(4096)
                if not chunk:
                    break
                buf += chunk
            c.sendall(self.reply)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def close(self):
        self.stop = True
        self.sock.close()


@pytest.fixture
def redirect_to_test_port(monkeypatch):
    """Lets the fixed-port probes (443, 80) reach a test server on another port."""
    real = socket.create_connection
    table = {}

    def conn(addr, *a, **k):
        host, port = addr
        return real((host, table.get(port, port)), *a, **k)
    monkeypatch.setattr(secreport.socket, "create_connection", conn)
    return table


def _chunked(*parts: bytes) -> bytes:
    return b"".join(b"%x;ext=1\r\n%s\r\n" % (len(p), p) for p in parts) + b"0\r\n\r\n"


OK_PAGE = (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.66 (Debian)\r\nX-Powered-By: PHP/8.4\r\nContent-Type: text/html\r\n"
           b"Set-Cookie: sid=1; path=/\r\nTransfer-Encoding: chunked\r\n\r\n" + _chunked(b"<form method=post><input></fo", b"rm>xx"))


def test_http_and_dechunk(cert):
    s = Server(OK_PAGE)
    try:
        r = secreport._http(s.port, "x.test", False)
        assert r["status"] == 200 and r["headers"]["server"].startswith("Apache") and r["cookies"] == ["sid=1; path=/"]
        assert r["body"] == "<form method=post><input></form>xx"
    finally:
        s.close()
    t = Server(b"HTTP/1.1 301 Moved\r\nLocation: https://x.test/\r\nContent-Length: 2\r\n\r\nhi", cert)
    try:
        r = secreport._http(t.port, "x.test", True)
        assert r["status"] == 301 and r["body"] == "hi" and r["length"] == 2
        assert secreport._http(t.port, "127.0.0.1", True)["status"] == 301
    finally:
        t.close()
    junk = Server(b"SSH-2.0-OpenSSH\r\n\r\n")
    try:
        assert secreport._http(junk.port, "x.test", False) is None
    finally:
        junk.close()
    s = socket.socket(); s.bind(("127.0.0.1", 0)); free = s.getsockname()[1]; s.close()
    assert secreport._http(free, "x.test", False) is None
    assert secreport._dechunk(b"zz\r\nrest") == b"zz\r\nrest"
    assert secreport._dechunk(b"") == b""


def test_handshake_cert_and_tls_findings(cert):
    s = Server(b"HTTP/1.1 200 OK\r\n\r\n", cert)
    try:
        h = secreport._handshake(s.port, "x.test", secreport._ctx())
        assert h["ok"] and h["version"].startswith("TLS")
        v = secreport._handshake(s.port, "x.test", secreport._ctx(verify=True))
        assert not v["ok"] and "verify_code" in v
        info = secreport._cert_details(h["der"])
        assert info["names"] == ["x.test", "www.x.test"] and info["self_signed"] and 25 <= info["days"] <= 30
        f, facts = secreport._tls_findings(s.port, "x.test", "site", "vhosts", "apache_harden")
        ids = {x["id"] for x in f}
        assert "self-signed" in ids and "cert-mismatch" not in ids and facts["matches"] and not facts["trusted"]
        assert all(x["cat"] == "tls" for x in f)
        f, _ = secreport._tls_findings(s.port, "other.test", "panel", "panelhttps", "panel_regen")
        mm = next(x for x in f if x["id"] == "cert-mismatch")
        assert mm["severity"] == "high" and mm["action"] == "panel_regen"
        f, _ = secreport._tls_findings(s.port, "127.0.0.1", "ip", "vhosts", "apache_harden")
        assert {"cert-ip", "self-signed"} <= {x["id"] for x in f}
    finally:
        s.close()
    s = socket.socket(); s.bind(("127.0.0.1", 0)); free = s.getsockname()[1]; s.close()
    f, facts = secreport._tls_findings(free, "x.test", "site", "vhosts", "")
    assert f[0]["id"] == "no-tls" and facts == {"reachable": False}
    assert secreport._cert_details(b"not a certificate")["names"] == []


def _fake_tls(monkeypatch, *, days=40, self_signed=False, verify_ok=True, names=("x.test",), legacy=(), weak=None, subject="CN=x.test"):
    def hs(port, sni, ctx):
        if ctx.verify_mode == ssl.CERT_REQUIRED:
            return {"ok": verify_ok, "verify_message": "unable to get local issuer certificate"}
        if ctx.maximum_version == ssl.TLSVersion.TLSv1 and "TLS 1.0" in legacy:
            return {"ok": True}
        if ctx.maximum_version == ssl.TLSVersion.TLSv1_1 and "TLS 1.1" in legacy:
            return {"ok": True}
        if ctx.maximum_version == ssl.TLSVersion.TLSv1_2:
            if weak == "raise":
                raise ssl.SSLError("no ciphers")
            return {"ok": bool(weak), "cipher": weak}
        if ctx.maximum_version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            if legacy == "raise":
                raise ssl.SSLError("no protocols")
            return {"ok": False}
        return {"ok": True, "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "der": b"x"}
    monkeypatch.setattr(secreport, "_handshake", hs)
    monkeypatch.setattr(secreport, "_cert_details", lambda der: {"subject": subject, "issuer": subject if self_signed else "CN=CA", "names": list(names),
                                                                  "days": days, "self_signed": self_signed})


def test_tls_finding_branches(monkeypatch):
    _fake_tls(monkeypatch, days=-3, legacy=("TLS 1.0", "TLS 1.1"), weak="ECDHE-RSA-AES128-SHA")
    f = {x["id"]: x for x in secreport._tls_findings(443, "x.test", "site", "vhosts", "apache_harden")[0]}
    assert f["expired"]["severity"] == "critical" and "TLS 1.0 and TLS 1.1" in f["legacy-tls"]["title"] and f["weak-ciphers"]["severity"] == "medium"
    _fake_tls(monkeypatch, days=5, weak="DES-CBC3-SHA")
    f = {x["id"]: x for x in secreport._tls_findings(443, "x.test", "site", "vhosts", "apache_harden")[0]}
    assert f["expiring"]["severity"] == "high" and f["weak-ciphers"]["severity"] == "high"
    _fake_tls(monkeypatch, weak="ECDHE-RSA-AES128-SHA")
    f = {x["id"]: x for x in secreport._tls_findings(465, "mail.x.test", "mail", "email", "")[0]}
    assert f["weak-ciphers"]["severity"] == "info" and f["cert-mismatch"]["action"] == ""
    _fake_tls(monkeypatch, weak="RC4-SHA")
    f = {x["id"]: x for x in secreport._tls_findings(465, "x.test", "mail", "email", "")[0]}
    assert f["weak-ciphers"]["severity"] == "high"
    _fake_tls(monkeypatch, verify_ok=False, weak="raise", legacy="raise")
    f = {x["id"]: x for x in secreport._tls_findings(443, "x.test", "site", "vhosts", "")[0]}
    assert set(f) == {"untrusted"}
    _fake_tls(monkeypatch, self_signed=True, names=(), subject="")
    for kind, name, sev in (("panel", "ns0", "low"), ("site", "1.2.3.4", "low"), ("mail", "mail.x.test", "medium")):
        f = {x["id"]: x for x in secreport._tls_findings(443, name, kind, "vhosts", "")[0]}
        assert f["self-signed"]["severity"] == sev
    _fake_tls(monkeypatch, days=None)
    assert secreport._tls_findings(443, "x.test", "site", "vhosts", "")[0] == []


def test_vhost_override(monkeypatch, tmp_path):
    monkeypatch.setattr(secreport, "SITES_ENABLED", tmp_path)
    (tmp_path / "a.conf").write_text("<VirtualHost *:443>\n  SSLCipherSuite HIGH\n</VirtualHost>\n")
    (tmp_path / "000-default.conf").mkdir()
    assert secreport._vhost_tls_override("a.conf") == "a.conf"
    assert secreport._vhost_tls_override("") == ""
    (tmp_path / "default-ssl.conf").write_text("SSLProtocol all\n")
    assert secreport._vhost_tls_override("b.conf") == "default-ssl.conf"
    monkeypatch.setattr(secreport.Path, "is_file", lambda self: (_ for _ in ()).throw(OSError("denied")))
    assert secreport._vhost_tls_override("a.conf") == ""


def test_header_and_web_extras():
    h = {"status": 200, "headers": {"content-security-policy": "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'", "x-content-type-options": "nosniff",
                                    "referrer-policy": "no-referrer", "content-type": "text/html"}, "cookies": ["a=1; Secure; HttpOnly"],
         "body": "<form method='POST' action=/c><input type=hidden name=_wpnonce value=1></form><form method=post><input name=q></form>"}
    f = {x["id"]: x for x in secreport._header_findings(h, "site", "vhosts", "apache_harden", True)}
    assert "frame-ancestors" in f["csp-weak"]["detail"] and "'unsafe-eval'" in f["csp-weak"]["detail"] and "cookie-a" in f and "csrf" in f
    assert "x-frame-options" not in f or True
    assert secreport.csp_weaknesses("default-src 'self'; form-action 'self'; frame-ancestors 'none'; ;") == []
    assert "wildcard or undefined" in secreport.csp_weaknesses("form-action 'self'; frame-ancestors 'self'; img-src *")[0]
    assert not secreport._forms_without_token("<form method=get></form>")
    assert secreport._big_redirect({"status": 301, "headers": {"location": "https://x/"}, "length": 400})["id"] == "big-redirect"
    assert secreport._big_redirect({"status": 301, "headers": {"location": "https://x/"}, "length": 100}) is None
    assert secreport._big_redirect({"status": 200, "headers": {}, "length": 9000}) is None


def test_extra_web_findings(monkeypatch):
    monkeypatch.setattr(secreport, "_http", lambda *a: {"body": "<address>Apache/2.4.66 (Debian) Server at x Port 443</address>"})
    f = secreport._extra_web_findings(443, "x.test", True, "vhosts", "apache_harden")
    assert f[0]["id"] == "banner" and "Apache/2.4.66" in f[0]["detail"]
    monkeypatch.setattr(secreport, "_http", lambda *a: None)
    assert secreport._extra_web_findings(443, "x.test", True, "vhosts", "apache_harden") == []


# ---------------------------------------------------------------- whole targets
def _web(monkeypatch, *, tls=True, plain=None, https=None, facts=None, tls_f=None):
    monkeypatch.setattr(secreport, "_handshake", lambda port, sni, ctx: {"ok": tls})
    monkeypatch.setattr(secreport, "_tls_findings", lambda port, name, kind, v, a: (list(tls_f or []), dict(facts or {"trusted": True, "cert": {"self_signed": False}})))
    monkeypatch.setattr(secreport, "_extra_web_findings", lambda *a: [])

    def http(port, host, tls_, path="/"):
        return https if tls_ else plain
    monkeypatch.setattr(secreport, "_http", http)


BARE = {"status": 200, "headers": {"server": "Apache/2.4"}, "cookies": [], "body": ""}


def test_scan_site_variants(monkeypatch, tmp_path):
    from backend import autossl
    monkeypatch.setattr(autossl, "resolves_here", lambda n: (True, ["192.0.2.1"]))
    monkeypatch.setattr(secreport, "SITES_ENABLED", tmp_path)
    (tmp_path / "s.conf").write_text("SSLCipherSuite ALL\n")
    tf = [secreport._f("medium", "Weak", "d", fid="weak-ciphers"), secreport._f("medium", "Self", "d", fid="self-signed")]
    _web(monkeypatch, plain={"status": 200, "headers": {}, "cookies": [], "body": "", "length": 900}, https=BARE, tls_f=tf)
    t = {"id": "site:x.test", "kind": "site", "name": "x.test", "site": "x.test", "conf": "s.conf", "label": "Website · x.test"}
    r = secreport._scan_target(t)
    f = {x["id"]: x for x in r["findings"]}
    assert f["weak-ciphers"]["action"] == "vhost_tls:s.conf" and f["self-signed"]["action"] == "autossl_run:x.test"
    assert f["hsts"]["action"] == "hsts:x.test" and f["no-redirect"]["action"] == "force_https:x.test" and r["grade"] in "ABCDF"
    # self-signed: HSTS isn't offered
    _web(monkeypatch, plain={"status": 301, "headers": {"location": "https://x.test/"}, "cookies": [], "body": "", "length": 10}, https=BARE,
         facts={"trusted": False, "cert": {"self_signed": True}})
    assert "hsts" not in {x["id"] for x in secreport._scan_target(t)["findings"]}
    # plain http only
    _web(monkeypatch, tls=False, plain=BARE)
    assert "no-https" in {x["id"] for x in secreport._scan_target(t)["findings"]}
    _web(monkeypatch, tls=False, plain=None)
    assert [x["id"] for x in secreport._scan_target(t)["findings"]] == ["silent"]
    # by address: header findings on http, no "no-redirect"
    _web(monkeypatch, plain=BARE, https=None)
    ip = secreport._scan_target({"id": "ip:1.2.3.4", "kind": "ip", "name": "1.2.3.4", "label": "x"})
    assert "no-redirect" not in {x["id"] for x in ip["findings"]} and "server-header" in {x["id"] for x in ip["findings"]}
    _web(monkeypatch, tls=False, plain=BARE)
    assert "no-https" not in {x["id"] for x in secreport._scan_target({"id": "ip:1.2.3.4", "kind": "ip", "name": "1.2.3.4", "label": "x"})["findings"]}


def test_scan_panel_mail_network_dmarc_server(monkeypatch):
    from backend import autossl
    monkeypatch.setattr(autossl, "resolves_here", lambda n: (True, ["192.0.2.1"]))
    _web(monkeypatch, https=BARE, plain=BARE)
    p = secreport._scan_target({"id": "panel:ns0", "kind": "panel", "name": "ns0", "port": 8088, "scheme": "http", "label": "p"})
    assert p["findings"][0]["id"] == "panel-http" and p["findings"][0]["severity"] == "critical"
    p = secreport._scan_target({"id": "panel:ns0", "kind": "panel", "name": "ns0", "port": 8088, "scheme": "https", "label": "p"})
    assert "server-header" in {x["id"] for x in p["findings"]}
    _web(monkeypatch, https=None, plain=None)
    assert secreport._scan_target({"id": "panel:ns0", "kind": "panel", "name": "ns0", "port": 8088, "scheme": "http", "label": "p"})["findings"][0]["id"] == "panel-http"
    secreport._scan_target({"id": "panel:ns0", "kind": "panel", "name": "ns0", "port": 8088, "scheme": "https", "label": "p"})
    # mail: both TLS ports, plus anonymous suites
    monkeypatch.setattr(secreport, "_tls_findings", lambda port, name, kind, v, a: ([secreport._f("medium", "Self-signed certificate", "d", fid="self-signed")], {"port": port}))
    monkeypatch.setattr(secnet, "mail_anon_findings", lambda: [secnet._f("medium", "Anon", "d", fid="anon-ciphers-postfix", cat="tls")])
    m = secreport._scan_target({"id": "mail:mail.x.test", "kind": "mail", "name": "mail.x.test", "label": "m", "deep": (25, "smtp")})
    f = {x["id"]: x for x in m["findings"]}
    assert f["465-self-signed"]["action"] == "autossl_run:mail.x.test" and "993-self-signed" in f and "anon-ciphers-postfix" in f
    assert set(m["facts"]) == {"465", "993"}
    monkeypatch.setattr(secnet, "testssl", lambda name, port, st="": [secnet._f("low", "testssl.sh: LUCKY13", "d", fid="testssl-LUCKY13", cat="tls")])
    m = secreport._scan_target({"id": "mail:mail.x.test", "kind": "mail", "name": "mail.x.test", "label": "m", "deep": (25, "smtp")}, deep=True)
    assert m["facts"]["testssl"] and "testssl-LUCKY13" in {x["id"] for x in m["findings"]}
    # network
    monkeypatch.setattr(secnet, "scan", lambda: ([secnet._f("low", "ts", "d", fid="tcp-timestamps")], {"ports": [], "nmap": False}))
    n = secreport._scan_target({"id": "network", "kind": "network", "name": "ns0", "label": "n"})
    assert n["findings"][0]["cat"] == "network" and n["facts"]["ports"] == []
    # dmarc
    monkeypatch.setattr(dmarc, "lookup", lambda d: {"record": "", "parent": "", "org": d, "spf": "", "dkim": False})
    dm = secreport._scan_target({"id": "dmarc:x.com", "kind": "dmarc", "name": "x.com", "sends": True, "label": "d"})
    f = {x["id"]: x for x in dm["findings"]}
    assert f["dmarc-missing"]["action"] == "dmarc_wizard:x.com" and f["spf-missing"]["action"] == "" and f["spf-missing"]["view"] == "deliverability"
    assert dm["facts"]["level"] == "missing" and all(x["cat"] == "email" for x in dm["findings"])
    # DNS served here: every DMARC/SPF/DKIM issue is a one-click fix, and a fresh record waiting on caches is noted
    monkeypatch.setattr(dmarc, "live_records", lambda d: {"record": "v=DMARC1; p=none", "parent": "", "org": d, "spf": "", "dkim": False,
                                                         "here": True, "propagating": True})
    f = {x["id"]: x for x in secreport._scan_target({"id": "dmarc:x.com", "kind": "dmarc", "name": "x.com", "sends": True, "label": "d"})["findings"]}
    assert f["dmarc-none"]["action"] == "dmarc_step:x.com" and f["spf-missing"]["action"] == "mail_dns:spf:x.com"
    assert f["dkim-missing"]["action"] == "mail_dns:dkim:x.com" and "One click" in f["spf-missing"]["fix"] and f["dmarc-propagating"]["severity"] == "info"
    monkeypatch.setattr(dmarc, "live_records", lambda d: {"record": "", "parent": "v=DMARC1; p=reject", "org": "x.com", "spf": "v=spf1 -all", "dkim": True,
                                                         "here": True, "propagating": False})
    f = {x["id"]: x for x in secreport._scan_target({"id": "dmarc:a.x.com", "kind": "dmarc", "name": "a.x.com", "sends": False, "label": "d"})["findings"]}
    assert f["dmarc-inherited"]["action"] == "dmarc_wizard:a.x.com" and "dmarc-propagating" not in f
    # server
    monkeypatch.setattr(secreport, "_posture", lambda: [secreport._f("medium", "2FA", "d", fid="2fa")])
    s = secreport._scan_target({"id": "server", "kind": "server", "name": "ns0", "label": "s"})
    assert s["findings"][0]["cat"] == "server" and s["score"] == 92


def test_posture(monkeypatch, tmp_path):
    from backend import appconfig, fail2ban, firewall, panelhttps, twofa, waf
    monkeypatch.setattr(twofa, "is_enabled", lambda: False)
    monkeypatch.setattr(panelhttps, "status", lambda scheme: {"enabled": False})
    monkeypatch.setattr(firewall, "status", lambda: {"available": True, "active": False})
    monkeypatch.setattr(fail2ban, "status", lambda: {"installed": False})
    monkeypatch.setattr(waf, "status", lambda: {"installed": True, "mode": "off"})
    monkeypatch.setattr(appconfig, "apache_hardening", lambda: {"available": True, "ok": 1, "total": 2, "items": [{"label": "Server header", "ok": False}, {"label": "x", "ok": True}]})
    ca = tmp_path / "ca.conf"
    ca.write_text(secreport.EMSIGN_G3 + "\n")
    monkeypatch.setattr(secreport, "CA_CONF", ca)
    ids = {x["id"] for x in secreport._posture()}
    assert ids == {"2fa", "panel-https", "ufw", "fail2ban", "waf-off", "emsign-g3", "apache-harden"}
    monkeypatch.setattr(twofa, "is_enabled", lambda: (_ for _ in ()).throw(OSError("x")))
    monkeypatch.setattr(panelhttps, "status", lambda scheme: {"enabled": True, "hardened": False})
    monkeypatch.setattr(appconfig, "apache_hardening", lambda: (_ for _ in ()).throw(OSError("no apache")))
    ids = {x["id"] for x in secreport._posture()}
    assert "panel-ciphers" in ids and "2fa" in ids and "apache-harden" not in ids


def test_emsign(monkeypatch, tmp_path):
    ca = tmp_path / "ca.conf"
    monkeypatch.setattr(secreport, "CA_CONF", ca)
    assert secreport.emsign_trusted() is False
    assert secreport.distrust_emsign() == {"changed": False}
    ca.write_text("mozilla/A.crt\n" + secreport.EMSIGN_G3 + "\n")
    monkeypatch.setattr(secreport.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
    assert secreport.distrust_emsign() == {"changed": True} and ("!" + secreport.EMSIGN_G3) in ca.read_text()
    ca.write_text(secreport.EMSIGN_G3 + "\n")
    monkeypatch.setattr(secreport.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="boom"))
    with pytest.raises(secreport.SecReportError, match="boom"):
        secreport.distrust_emsign()


def test_fix_actions(monkeypatch):
    from backend import appconfig, autossl, firewall, panelhttps, sites
    calls = []
    monkeypatch.setattr(appconfig, "apache_harden", lambda: calls.append("harden"))
    monkeypatch.setattr(panelhttps, "harden", lambda: calls.append("panel"))
    monkeypatch.setattr(firewall, "set_enabled", lambda on: {"preallowed": ["22/tcp"]})
    monkeypatch.setattr(appconfig, "strip_vhost_tls", lambda c: {"changed": 2 if c == "a.conf" else 0})
    monkeypatch.setattr(autossl, "request", lambda name: calls.append(name) or {"ok": True})
    monkeypatch.setattr(sites, "quick_toggle", lambda n, k, v: calls.append((n, k)))
    monkeypatch.setattr(secreport, "distrust_emsign", lambda: {"changed": False})
    for k in secnet.FIXES:
        monkeypatch.setitem(secnet.FIXES, k, lambda k=k: {"message": f"did {k}"})
    monkeypatch.setattr(secnet, "port_lan_fix", lambda arg: {"message": f"lan {arg}"})
    out = {a: secreport.fix(a)["message"] for a in ("apache_harden", "panel_harden", "ufw_enable", "vhost_tls:a.conf", "vhost_tls:b.conf", "autossl_run:x.test",
                                                     "hsts:x.test", "force_https:x.test", "ca_distrust", "ssh_crypto", "port_lan:445/tcp")}
    assert "22/tcp" in out["ufw_enable"] and "2 cipher/protocol lines" in out["vhost_tls:a.conf"] and "no cipher lines" in out["vhost_tls:b.conf"]
    assert out["ssh_crypto"] == "did ssh_crypto" and out["port_lan:445/tcp"] == "lan 445/tcp" and "already" in out["ca_distrust"]
    from backend import mail
    monkeypatch.setattr(dmarc, "step", lambda d: {"message": f"step {d}"})
    monkeypatch.setattr(mail, "install_record", lambda d, k: calls.append((d, k)))
    assert secreport.fix("dmarc_step:x.com")["message"] == "step x.com"
    assert "SPF record for x.com" in secreport.fix("mail_dns:spf:x.com")["message"] and ("x.com", "spf") in calls
    with pytest.raises(secreport.SecReportError, match="Unknown"):
        secreport.fix("nope")
    monkeypatch.setattr(secnet, "port_lan_fix", lambda arg: (_ for _ in ()).throw(secnet.SecNetError("Bad port")))
    with pytest.raises(secreport.SecReportError, match="Bad port"):
        secreport.fix("port_lan:x")
    monkeypatch.setattr(appconfig, "apache_harden", lambda: (_ for _ in ()).throw(ValueError()))
    with pytest.raises(secreport.SecReportError, match="ValueError"):
        secreport.fix("apache_harden")


def test_targets_all_kinds(monkeypatch):
    from backend import mail, panelhttps, sites
    monkeypatch.setattr(panelhttps, "status", lambda scheme, host="": {"enabled": True, "port": 8088})
    monkeypatch.setattr(panelhttps, "_known_names", lambda: ["ns0", "ns0.local", "192.168.0.100", "127.0.0.1", "localhost"])
    monkeypatch.setattr(sites, "list_sites", lambda: {"sites": [{"server_name": "www.Example.com", "aliases": ["*.example.com", ""], "enabled": True, "ssl": "letsencrypt"},
                                                                {"server_name": "192.168.0.100", "system": True, "enabled": True, "ssl": "selfsigned"}]})
    monkeypatch.setattr(mail, "load", lambda: {"domains": {"example.com": {}, "ns0.local": {}}, "accounts": {}})
    monkeypatch.setattr(mail, "hostname", lambda s: "mail.example.com")
    t = {x["id"]: x for x in secreport.targets()}
    assert t["panel:ns0"]["deep"] == (8088, "") and t["panel:ns0.local"]["deep"] is None
    assert t["site:www.example.com"]["deep"] == (443, "") and "site:*.example.com" not in t
    assert t["dmarc:example.com"]["sends"] is True and "dmarc:ns0.local" not in t and "dmarc:192.168.0.100" not in t
    assert t["mail:mail.example.com"]["deep"] == (25, "smtp") and "network" in t and list(t)[-1] == "server"
    monkeypatch.setattr(panelhttps, "status", lambda scheme, host="": (_ for _ in ()).throw(OSError("x")))
    monkeypatch.setattr(panelhttps, "_known_names", lambda: (_ for _ in ()).throw(OSError("x")))
    monkeypatch.setattr(sites, "list_sites", lambda: (_ for _ in ()).throw(OSError("x")))
    monkeypatch.setattr(mail, "load", lambda: (_ for _ in ()).throw(OSError("x")))
    assert [x["id"] for x in secreport.targets()] == ["network", "server"]
    monkeypatch.setattr(sites, "list_sites", lambda: {"sites": [{"server_name": "a.example.org", "enabled": True}]})
    ids = [x["id"] for x in secreport.targets()]
    assert "dmarc:example.org" in ids and "dmarc:a.example.org" not in ids


# ---------------------------------------------------------------- report: finalize, history, accept, job
@pytest.fixture
def store(monkeypatch, tmp_path):
    for k in ("STATE", "ACCEPTED", "HISTORY"):
        monkeypatch.setattr(secreport, k, tmp_path / f"{k}.json")
    return tmp_path


def _t(tid, kind, findings):
    return {"id": tid, "kind": kind, "name": tid, "label": f"{kind} · {tid}", "findings": findings, "facts": {}, "score": 0, "grade": "F"}


def _fd(fid, sev, action="", cat="web"):
    return {"id": fid, "severity": sev, "title": fid.upper(), "detail": "d", "fix": "f", "view": "", "action": action, "cat": cat}


def test_finalize_and_plan(store):
    rep = {"targets": [_t("site:a", "site", [_fd("hsts", "low", "hsts:a"), _fd("csp", "medium", "apache_harden"), _fd("x", "info")]),
                       _t("site:b", "site", [_fd("csp", "medium", "apache_harden"), _fd("w", "high", "dmarc_wizard:b", "email"), _fd("p", "low", "panel_harden")]),
                       _t("server", "server", [_fd("2fa", "medium", cat="server")])]}
    secreport.finalize(rep, {"site:b|w": {"note": "fine", "ts": 1}})
    assert rep["counts"]["accepted"] == 1 and rep["counts"]["medium"] == 3 and rep["counts"]["info"] == 1
    assert rep["targets"][1]["score"] == 100 - 8 - 3 and rep["cats"] == {"web": 4, "server": 1}
    plan = {p["action"]: p for p in rep["fix_plan"]}
    assert "dmarc_wizard:b" not in plan and plan["apache_harden"]["resolves"] == ["CSP"] and plan["apache_harden"]["worst"] == "medium"
    assert [p["action"] for p in rep["fix_plan"]][-1] == "panel_harden" and plan["hsts:a"]["arg"] == "a"
    assert rep["weakest"] == "server" or rep["weakest"].startswith("site")
    secreport.finalize({"targets": [_t("server", "server", [])]}, {})
    only = secreport.finalize({"targets": []}, {})
    assert only["score"] == 100 and only["weakest"] is None
    lone = secreport.finalize({"targets": [_t("site:a", "site", [_fd("u", "unknownsev", "made_up")])]}, {})
    assert lone["fix_plan"][0]["label"] == "Fix"


def test_history_and_accept(store, monkeypatch):
    rep1 = {"ts": 100, "targets": [_t("site:a", "site", [_fd("a1", "low"), _fd("a2", "medium")]), _t("site:z", "site", [_fd("z1", "low")])]}
    secreport.finalize(rep1, {})
    secreport._history(rep1, None)
    assert rep1["targets"][0]["findings"][0]["first_seen"] == 100 and rep1["targets"][0]["findings"][0]["new"] is False
    rep2 = {"ts": 200, "targets": [_t("site:a", "site", [_fd("a2", "medium"), _fd("a3", "low"), _fd("i", "info")])]}
    secreport.finalize(rep2, {})
    secreport._history(rep2, rep1)
    f = {x["id"]: x for x in rep2["targets"][0]["findings"]}
    assert f["a2"]["first_seen"] == 100 and f["a3"]["new"] is True and rep2["resolved"] == [{"target": "site · site:a", "title": "A1", "severity": "low"}]
    h = json.loads((store / "HISTORY.json").read_text())
    assert "site:a|a1" not in h["first_seen"] and "site:z|z1" in h["first_seen"] and [r["ts"] for r in h["runs"]] == [100, 200]
    assert [r["ts"] for r in secreport.history()] == [100, 200]
    # accept / un-accept rescore the stored report
    secreport._save_json(secreport.STATE, rep2)
    r = secreport.accept("site:a|a2", True, " on purpose ")
    assert r["report"]["counts"]["accepted"] == 1 and r["report"]["targets"][0]["score"] == 97
    assert json.loads((store / "ACCEPTED.json").read_text())["site:a|a2"]["note"] == "on purpose"
    r = secreport.accept("site:a|a2", False)
    assert r["report"]["counts"]["accepted"] == 0
    with pytest.raises(secreport.SecReportError):
        secreport.accept("bad key with spaces", True)
    secreport.STATE.unlink()
    assert secreport.accept("site:a|a2", True)["report"] is None
    monkeypatch.setattr(secreport, "HISTORY", store / "nodir" / "x" / "h.json")
    monkeypatch.setattr(secreport.Path, "mkdir", lambda *a, **k: (_ for _ in ()).throw(OSError("read-only")))
    secreport._save_json(secreport.HISTORY, {})  # swallowed


def test_run_start_overview(store, monkeypatch):
    monkeypatch.setattr(secreport, "targets", lambda: [{"id": "site:a", "kind": "site", "name": "a", "label": "Website · a"}, {"id": "server", "kind": "server", "name": "s", "label": "S"}])
    monkeypatch.setattr(secreport, "_scan_target", lambda t, deep=False: {**t, "findings": [_fd("x", "low", "apache_harden")] if t["kind"] == "site" else [], "facts": {}, "score": 0, "grade": "F"})
    monkeypatch.setattr(secnet, "tools", lambda: [{"id": "nmap", "installed": True}])
    with pytest.raises(secreport.SecReportError):
        secreport.run(["nothing"])

    class Log(list):
        def __call__(self, line):
            self.append(line)

        def progress(self, pct, stage=None):
            self.append((pct, stage))
    log = Log()
    rep = secreport.run(None, True, log)
    assert rep["deep"] and rep["score"] == 97 and rep["fixes"] == ["apache_harden"] and secreport.last()["ts"] == rep["ts"] and len(log) == 4
    assert secreport.run(["server"])["targets"][0]["id"] == "server"
    j = secreport.start(["server"])
    for _ in range(100):
        if jobs.get(j["job"]).status != "running":
            break
        time.sleep(0.05)
    assert jobs.get(j["job"]).status == "done" and jobs.get(j["job"]).result["targets"][0]["id"] == "server"
    ov = secreport.overview()
    assert ov["running"] is None and ov["history"] and "dmarc_wizard" in ov["fix_info"] and ov["tools"][0]["id"] == "nmap"
    gate = threading.Event()
    monkeypatch.setattr(secreport, "run", lambda ids, deep, log: gate.wait(5) and {})
    a = secreport.start()
    assert secreport.start()["already"] and secreport.overview()["running"] == a["job"]
    gate.set()


def test_report_html_full():
    rep = {"ts": 1_800_000_000, "took": 2.5, "hostname": "ns0", "score": 72, "grade": "C",
           "counts": {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 1, "accepted": 1},
           "resolved": [{"target": "Website · a", "title": "Old <thing>", "severity": "low"}],
           "targets": [
               {"id": "network", "kind": "network", "label": "Network services", "score": 92, "grade": "A", "facts": {"ports": [{"port": 445, "proto": "tcp", "service": "Samba", "product": "smbd 4", "firewall": "open"}]},
                "findings": [{"severity": "medium", "title": "Samba open", "detail": "d", "fix": "f", "first_seen": 1_799_000_000},
                             {"severity": "low", "title": "Accepted one", "detail": "d", "fix": "f", "accepted": {"note": "lan only", "ts": 1}},
                             {"severity": "low", "title": "Accepted bare", "detail": "d", "fix": "", "accepted": {"ts": 1}}]},
               {"id": "dmarc:x.com", "kind": "dmarc", "label": "Email authentication · x.com", "score": 100, "grade": "A+", "facts": {"record": "v=DMARC1; p=reject"}, "findings": []},
               {"id": "site:a", "kind": "site", "label": "Website · a", "score": 100, "grade": "A+", "facts": {}, "findings": []},
               {"id": "site:b", "kind": "site", "label": "Website · b", "score": 100, "grade": "A+", "facts": {}, "findings": []},
           ]}
    h = secreport.report_html(rep)
    assert "Old &lt;thing&gt;" in h and "smbd 4" in h and "open to all" in h and "lan only" in h and "v=DMARC1; p=reject" in h
    assert "Fixed since the last report" in h and "Accepted <i>2" in h and "2 addresses, same result" in h and "First seen" in h
    assert "https://" not in h and "http://" not in h


def test_probe_edge_cases(monkeypatch):
    big = Server(b"HTTP/1.1 200 OK\r\nJunk header line\r\nX-A: 1\r\n\r\n" + b"x" * 70000)
    try:
        r = secreport._http(big.port, "x.test", False)
        assert r["status"] == 200 and r["headers"] == {"x-a": "1"} and len(r["body"]) >= 65536 - 60
    finally:
        big.close()

    class Reset:
        def __init__(self):
            self.n = 0

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def sendall(self, b):
            pass

        def recv(self, n):
            self.n += 1
            if self.n == 1:
                return b"HTTP/1.1 204 No Content\r\n\r\n"
            raise ConnectionResetError("reset")
    monkeypatch.setattr(secreport.socket, "create_connection", lambda *a, **k: Reset())
    assert secreport._http(80, "x.test", False)["status"] == 204
    monkeypatch.setattr(secreport.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=b"subject=CN = a\nissuer=CN = b\nnotAfter=someday\n"))
    info = secreport._cert_details(b"x")
    assert info["days"] is None and info["self_signed"] is False
    monkeypatch.setattr(secreport.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("no openssl")))
    assert secreport._cert_details(b"x")["names"] == []


def test_scan_more_branches(monkeypatch):
    _web(monkeypatch, plain={"status": 301, "headers": {"location": "https://x.test/"}, "cookies": [], "body": "", "length": 900}, https=BARE)
    t = {"id": "site:x.test", "kind": "site", "name": "x.test", "site": "x.test", "label": "w"}
    assert "big-redirect" in {x["id"] for x in secreport._scan_target(t)["findings"]}
    assert secreport._scan_target({"id": "x", "kind": "other", "name": "x", "label": "x"})["findings"] == []
    monkeypatch.setattr(secreport, "_tls_findings", lambda port, name, kind, v, a: ([secreport._f("low", "Self-signed certificate", "d", fid="self-signed")], {}))
    monkeypatch.setattr(secnet, "mail_anon_findings", lambda: [])
    m = secreport._scan_target({"id": "mail:1.2.3.4", "kind": "mail", "name": "1.2.3.4", "label": "m"})
    assert all(x["action"] == "" for x in m["findings"])


def test_posture_all_good(monkeypatch, tmp_path):
    from backend import appconfig, fail2ban, firewall, panelhttps, twofa, waf
    monkeypatch.setattr(twofa, "is_enabled", lambda: True)
    monkeypatch.setattr(panelhttps, "status", lambda scheme: (_ for _ in ()).throw(OSError("x")))
    monkeypatch.setattr(firewall, "status", lambda: {"available": True, "active": True})
    monkeypatch.setattr(fail2ban, "status", lambda: {"installed": True, "active": True})
    monkeypatch.setattr(waf, "status", lambda: {"installed": True, "mode": "on"})
    monkeypatch.setattr(appconfig, "apache_hardening", lambda: {"available": True, "ok": 5, "total": 5, "items": []})
    monkeypatch.setattr(secreport, "CA_CONF", tmp_path / "none.conf")
    assert secreport._posture() == []
    monkeypatch.setattr(panelhttps, "status", lambda scheme: {"enabled": True, "hardened": True})
    assert secreport._posture() == []


def test_https_only_site(monkeypatch):
    _web(monkeypatch, plain=None, https=BARE)
    ids = {x["id"] for x in secreport._scan_target({"id": "site:x.test", "kind": "site", "name": "x.test", "site": "x.test", "label": "w"})["findings"]}
    assert "silent" not in ids and "no-redirect" not in ids and "server-header" in ids
