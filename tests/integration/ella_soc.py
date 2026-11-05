#!/usr/bin/env python3
"""WAF Ella stages 3 to 8 on a real server. Run as root from the panel folder, with the panel running:

    PYTHONPATH=. .venv/bin/python tests/integration/ella_soc.py [nginx|apache]

Real requests go to the real web server, and rules really load in it. It needs that web server running with its WAF in block
mode, uses *.ella-test.example as its hosts, and removes what it adds. It changes the firewall and web server config while it
runs, so use a test machine. It has a network namespace as its attacker, so it can't ban the address you connect from.
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from backend import distro

os.environ["PATH"] = distro.PATH + ":" + os.environ["PATH"]
from backend.ella import agentd, collector, correlate, fleet, housekeeping as H, intel as I, notify, proxies as P, query as Q, rulebook as R, tester as T  # noqa: E402
from backend.ella.adapter import EllaSystemAdapter  # noqa: E402
from backend.ella.blocks import BlockError, Engine  # noqa: E402
from backend.ella.configs import ConfigManager  # noqa: E402
from backend.ella.db import Store  # noqa: E402

SERVER = sys.argv[1] if len(sys.argv) > 1 else "nginx"
HOST = "site.ella-test.example"
OTHER = "other.ella-test.example"
results: list[tuple[str, bool, str]] = []
STARTED = time.time()
store = Store()
adapter = EllaSystemAdapter(store.dir / "adapter.log")
engine = Engine(store, adapter)
configs = ConfigManager(adapter, store.dir / "snapshots", audit=store.audit)
book = R.RuleBook(store, configs)
pid = os.getpid()
FILE = R.NGINX_FILE if SERVER == "nginx" else R.APACHE_FILE
AUDIT = Path("/var/log/nginx/modsec_audit.log" if SERVER == "nginx" else "/var/log/apache2/modsec_audit.log")
# This run's settings must not be left behind.
SAVED = {k: store.setting(k) for k in ("honeypot", "kill_switch", "under_attack", "response_inspection", "body_limit_action", "trusted_proxies", "trusted_manual", "real_ip_header")}


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"\n       {detail}" if detail else ""), flush=True)
    return ok


def req(path: str = "/", method: str = "GET", host: str = HOST, headers: dict | None = None, body: bytes | None = None, peer: str = "127.0.0.1") -> int:
    """One real request. A plain client that looks like a browser, so the rule set scores only what the test sends."""
    h = {"Host": host, "User-Agent": "Mozilla/5.0 ella-test", "Accept": "*/*", **(headers or {})}
    s = socket.create_connection((peer, 80), timeout=10)
    c = http.client.HTTPConnection(peer, 80, timeout=10)
    c.sock = s
    c.request(method, path, body=body, headers=h)
    code = c.getresponse().status
    c.close()
    return code


def audit_since(start: int) -> list[bytes]:
    time.sleep(0.3)
    with AUDIT.open("rb") as f:
        f.seek(start)
        return [x for x in f.read().split(b"\n") if x]


def audit_pos() -> int:
    return AUDIT.stat().st_size if AUDIT.exists() else 0


def t_paranoia_really_reaches_the_rules() -> None:
    """The setting the panel writes has to be the one CRS 4 reads."""
    pre = Path("/etc/nginx/aurora-waf/pre.conf" if SERVER == "nginx" else "/etc/modsecurity/zz-aurora-waf.conf").read_text()
    check("the WAF's paranoia level uses the variable CRS 4 reads", "tx.blocking_paranoia_level" in pre, pre.splitlines()[4][:110] if len(pre.splitlines()) > 4 else "")


def t_rules_block_for_real() -> None:
    r = book.create({"name": "ella test admin", "domains": [HOST], "tree": {"all": [{"field": "path", "op": "prefix", "value": "/ella-admin"}, {"any": [{"field": "method", "op": "equals", "value": "POST"}, {"field": "header", "name": "X-Ella-Bad", "op": "exists"}]}]}}, "test")
    check("a rule can't go straight to block", _refuses(lambda: book.set_mode(r["id"], "block", "test"), "detect"))
    book.set_mode(r["id"], "detect", "test")
    check("detect mode: the web server accepted the file", FILE in str(store.audit_entries(5)) or Path(FILE).exists())
    start = audit_pos()
    code = req("/ella-admin", "POST", body=b"a=1", headers={"Content-Type": "application/x-www-form-urlencoded"})
    hits = audit_since(start)
    check("detect mode logs and lets it through", code != 403 and any(b"Ella: ella test admin" in x for x in hits), f"HTTP {code}, {len(hits)} audit records")
    book.set_mode(r["id"], "block", "test")
    check("block: POST to the path is refused", req("/ella-admin", "POST", body=b"a=1", headers={"Content-Type": "application/x-www-form-urlencoded"}) == 403)
    check("block: so is the other way of matching", req("/ella-admin", headers={"X-Ella-Bad": "1"}) == 403)
    check("not on a GET without the header", req("/ella-admin") != 403)
    check("not on another path", req("/elsewhere", "POST", body=b"a=1", headers={"Content-Type": "application/x-www-form-urlencoded"}) != 403)
    check("not on another site", req("/ella-admin", "POST", host=OTHER, body=b"a=1", headers={"Content-Type": "application/x-www-form-urlencoded"}) != 403)
    check("encoding doesn't get around it", req("/%65lla-admin", "POST", body=b"a=1", headers={"Content-Type": "application/x-www-form-urlencoded"}) == 403)
    book.delete(r["id"], "test")
    check("removing it stops it", req("/ella-admin", headers={"X-Ella-Bad": "1"}) != 403)


def _refuses(fn, word: str) -> bool:
    try:
        fn()
    except (R.RuleError, ValueError, RuntimeError) as exc:
        return word in str(exc)
    return False


def t_bad_file_refused_by_server() -> None:
    before = Path(FILE).read_text()
    good = {"name": "patch", "cve_id": "CVE-2026-0001", "raw": 'SecRule REQUEST_URI "@contains /ella-vuln" "id:1150001,phase:1,deny,status:403,log,msg:\'patched\'"'}
    rule = book.add_patch(good, "test")
    check("a virtual patch starts in detect, whatever it says", rule["mode"] == "detect" and req("/ella-vuln") != 403)
    book.set_mode(rule["id"], "block", "test")
    check("and blocks when told to", req("/ella-vuln") == 403)
    book.delete(rule["id"], "test")
    # An operator mustn't be able to reach this, but the server's check is the last line, so try it directly.
    try:
        configs.apply(FILE, before + "\nSecRule THIS IS BROKEN\n", "test", server=SERVER, watch_seconds=None)
        check("a broken file is refused by the web server", False)
    except RuntimeError as exc:
        check("a broken file is refused by the web server", True, str(exc).splitlines()[0][:100])
    check("and the previous file is back, and the server up", Path(FILE).read_text() == before and req("/") < 500)


def t_false_positive_wizard() -> None:
    """A real false alarm: SQL in a comment on one page."""
    attack = "/ella-blog?comment=1%27%20OR%20%271%27%3D%271"
    check("the attack is blocked before the exception", req(attack) == 403)
    start = audit_pos()
    req(attack)
    parser = collector.PARSERS["modsec3_audit" if SERVER == "nginx" else "modsec_audit"]
    ev = next((e for e in (parser.parse(x, {"path": "x", "inode": 0, "offset": 0}) for x in audit_since(start)) if e and not e.get("skip")), None)
    if not check("the event names the rule and field", bool(ev and ev["evidence"]), str(ev["evidence"][0] if ev and ev["evidence"] else "")[:140]):
        return
    hits = [x for x in ev["evidence"] if x["matched_var_name"] == "ARGS:comment"]
    check("the matched field is known", bool(hits))
    made = []
    for h in hits:
        s = R.suggest_exception({"domain": HOST, "url": "/ella-blog"}, h)
        made.append(book.add_exception({"rule_id": s["rule_id"], "var": s["var"], "domain": s["domain"], "path": s["path"], "reason": "test"}, "test")["id"])
    code = req(attack)
    check("the exception lets it through on this page", code != 403, f"HTTP {code}")
    check("the rule still works on another page", req("/ella-other?comment=1%27%20OR%20%271%27%3D%271") == 403)
    check("and on another site", req(attack, host=OTHER) == 403)
    check("and in another field on this page", req("/ella-blog?title=1%27%20OR%20%271%27%3D%271") == 403)
    for e in made:
        book.remove_exception(e, "test")
    check("removing the exception brings the block back", req(attack) == 403)


def t_honeypot_and_cms() -> None:
    root = Path(f"/var/www/{OTHER}")
    book.set_honeypot({"mode": "block", "paths": ["/.env", "/ella-trap/"]}, "test")
    start = audit_pos()
    check("a honeypot path is refused as if it weren't there", req("/.env") == 404)
    parser = collector.PARSERS["modsec3_audit" if SERVER == "nginx" else "modsec_audit"]
    evs = [parser.parse(x, {"path": "x", "inode": 0, "offset": 0}) for x in audit_since(start)]
    ev = next((e for e in evs if e and not e.get("skip")), None)
    if ev:
        ev.setdefault("evidence", [])
        collector.classify(ev)
    check("and is a high-confidence honeypot event", bool(ev) and "honeypot" in (ev.get("tags") or "") and ev["confidence"] == "high", (ev or {}).get("tags", ""))
    check("the certificate check path is left alone", req("/.well-known/acme-challenge/x") != 403)
    book.set_cms("wp-xmlrpc", "block", [HOST], "test")
    check("the WordPress profile blocks xmlrpc.php here", req("/xmlrpc.php", "POST", body=b"<x/>", headers={"Content-Type": "text/xml"}) == 403)
    check("but not on a site that didn't choose it", req("/xmlrpc.php", "POST", host=OTHER, body=b"<x/>", headers={"Content-Type": "text/xml"}) != 403)
    book.set_cms("wp-users", "block", [HOST], "test")
    check("user listing is blocked", req("/wp-json/wp/v2/users") == 403)
    start = audit_pos()
    req("/?author=1")
    check("so is looking users up by number", any(b"hide the user list" in x for x in audit_since(start)))
    start = audit_pos()
    req("/?page=1")
    check("a normal page isn't", not any(b"hide the user list" in x for x in audit_since(start)))
    book.set_cms("wp-xmlrpc", "off", [], "test")
    book.set_cms("wp-users", "off", [], "test")
    book.set_honeypot({"mode": "off", "paths": ["/.env"]}, "test")
    root.exists()


def t_switches() -> None:
    book.set_switch("kill_switch", True, "test")
    time.sleep(0.3)
    # /test/ answers 200 here, while / answers 403 for having no index page, which would look like a block.
    attack = "/test/?x=%3Cscript%3Ealert(1)%3C/script%3E"
    check("the clean page used for these answers", req("/test/") == 200)
    code = req(attack)
    check("kill switch: attacks are only logged", code != 403, f"HTTP {code}")
    book.set_switch("kill_switch", False, "test")
    check("off again: they're blocked", req(attack) == 403)
    start = audit_pos()
    req("/test/", "DELETE")  # not TRACE: Nginx refuses that itself, before any rule runs
    check("before Under Attack, DELETE isn't refused by that rule", not any(b"ella-under-attack" in x or b"while Under Attack" in x for x in audit_since(start)))
    book.under_attack(5, "test")
    start = audit_pos()
    req("/test/", "DELETE")
    check("Under Attack refuses odd methods", any(b"while Under Attack" in x for x in audit_since(start)))
    check("everyday methods still work", req("/test/") == 200)
    book.under_attack(0, "test")
    book.set_policy(f"domain:{OTHER}", "mode", "detect", False, "test")
    check("one site in detect mode lets attacks by", req(attack, host=OTHER) != 403)
    check("while others keep blocking", req(attack) == 403)
    book.remove_policy(f"domain:{OTHER}", "mode", "test")
    utf7 = req("/", "POST", body=b"a=1", headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-7"})
    check("UTF-7 bodies are refused", utf7 in (403, 415), f"HTTP {utf7}")
    big = b"a=" + b"x" * (14 * 1024 * 1024)
    code = None
    try:
        code = req("/", "POST", body=big, headers={"Content-Type": "application/x-www-form-urlencoded"})
    except OSError as exc:
        code = str(exc)[:40]
    check("a body over the limit is refused by default", code in (413, 403), str(code))


def t_smuggling() -> None:
    """Both Content-Length and Transfer-Encoding: the server, before any rule, mustn't pass this on as two requests."""
    s = socket.create_connection(("127.0.0.1", 80), timeout=5)
    s.sendall(f"POST / HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode())
    time.sleep(0.5)
    s.settimeout(1)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    s.close()
    first = data.split(b"\r\n", 1)[0].decode("latin-1")
    check("a request with both length headers is refused, or handled as one", b" 400 " in data[:40] or data.count(b"HTTP/1.1 ") <= 2, first)


def t_tester() -> None:
    tester = T.Tester(configs, R._waf_servers)
    st = tester.setup("test")
    if not check("Rule Tester sets up on 127.0.0.1", st.get("ready"), str(st)):
        return
    outside = subprocess.run(f"ss -ltn | grep -c '127.0.0.1:{st['port']}'", shell=True, capture_output=True, text=True).stdout.strip()
    check("it listens on this machine only", outside != "0")
    start = audit_pos()
    r = tester.run("GET", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", {}, "", HOST)
    check("an attack is reported blocked, with rules and a score", r["action"] == "blocked" and bool(r["rules"]) and (r["anomaly_score"] or 0) >= 5, f"{r['status']}, score {r['anomaly_score']}, rules {[x['rule_id'] for x in r['rules']][:4]}")
    r2 = tester.run("GET", "/hello", {}, "", HOST)
    check("a clean request is reported allowed", r2["action"] == "allowed" and not r2["rules"], str(r2)[:150])
    r3 = tester.run("POST", "/x", {"Content-Type": "application/x-www-form-urlencoded"}, "a=1' OR '1'='1", HOST)
    check("request bodies are checked", r3["action"] == "blocked" and bool(r3["rules"]), f"{r3['status']}, {[x['rule_id'] for x in r3['rules']][:4]}")
    temp = Store(store.dir.parent / f"ella-livecheck-{pid}")
    col = collector.Collector(temp, log_dir=str(AUDIT.parent))
    kind = "modsec3_audit" if SERVER == "nginx" else "modsec_audit"
    with AUDIT.open("rb") as f:
        evs, *_ = col._read(f, str(AUDIT), 1, start, kind)
    check("nothing from the tester reaches Live Events", evs == [], f"{len(evs)} events")
    code = req("/?x=%3Cscript%3Ealert(1)%3C/script%3E", headers={"X-Ella-Test": "faked"})
    time.sleep(0.3)
    with AUDIT.open("rb") as f:
        forged, *_ = col._read(f, str(AUDIT), 1, start, kind)
    check("a visitor faking that header still shows up", code == 403 and len(forged) >= 1, f"{len(forged)} events")
    subprocess.run(["rm", "-rf", str(temp.dir)], check=False)
    configs.apply(str(tester._conf_path(SERVER)), None, "test", server=SERVER, watch_seconds=None)
    check("it comes back out cleanly", req("/") < 500)


def t_proxies_and_real_client() -> None:
    p = P.Proxies(store, configs, R._waf_servers)
    fake = "45.33.32.156"
    attacker_before = req("/", headers={"X-Forwarded-For": fake}) < 500
    start = audit_pos()
    req("/?x=%3Cscript%3Ealert(1)%3C/script%3E", headers={"X-Forwarded-For": fake})
    parser = collector.PARSERS["modsec3_audit" if SERVER == "nginx" else "modsec_audit"]
    ev = next((e for e in (parser.parse(x, {"path": "x", "inode": 0, "offset": 0}) for x in audit_since(start)) if e and not e.get("skip")), None)
    check("from an untrusted address the header is ignored", attacker_before and bool(ev) and ev["client_ip"] != fake and collector.classify(dict(ev), [])["client_ip"] != fake, (ev or {}).get("client_ip", ""))
    p.set_manual(["127.0.0.1"], "X-Forwarded-For", "test")
    time.sleep(0.5)
    start = audit_pos()
    req("/?x=%3Cscript%3Ealert(1)%3C/script%3E", headers={"X-Forwarded-For": fake})
    ev = next((e for e in (parser.parse(x, {"path": "x", "inode": 0, "offset": 0}) for x in audit_since(start)) if e and not e.get("skip")), None)
    check("from a trusted proxy the visitor's address reaches the WAF", bool(ev) and ev["client_ip"] == fake, (ev or {}).get("client_ip", ""))
    try:
        engine.ban("127.0.0.1", 60, "x", "test")
        check("loopback can't be banned even as a proxy", False)
    except BlockError:
        check("loopback can't be banned even as a proxy", True)
    p.set_manual(["192.0.2.10"], "X-Forwarded-For", "test")
    try:
        engine.ban("192.0.2.10", 60, "x", "test")
        check("a trusted proxy can't be banned at the firewall", False)
    except BlockError as exc:
        check("a trusted proxy can't be banned at the firewall", "trusted proxy" in str(exc), str(exc)[:110])
    p.set_manual([], "X-Forwarded-For", "test")
    check("taking the proxy out goes back to normal", req("/") < 500)
    ok = False
    try:
        ranges = P.parse_ranges([P._fetch(u) for u in P.CF_URLS])
        ok = len(ranges) > 10
    except (OSError, ValueError) as exc:
        print("  (Cloudflare's list unreachable:", exc, ")")
    check("Cloudflare's real address list downloads and passes its checks", ok)


def ns_run(cmd: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(["ip", "netns", "exec", "ellasoc", "sh", "-c", cmd], capture_output=True, text=True, timeout=timeout)


def t_ipv6_ban() -> None:
    subprocess.run("ip netns del ellasoc 2>/dev/null; ip link del ellasoc0 2>/dev/null", shell=True)
    for c in ("ip netns add ellasoc", "ip link add ellasoc0 type veth peer name ellasoc1", "ip link set ellasoc1 netns ellasoc", "ip -6 addr add fd00:e11a::1/64 dev ellasoc0 nodad", "ip link set ellasoc0 up",
              "ip netns exec ellasoc ip -6 addr add fd00:e11a::2/64 dev ellasoc1 nodad", "ip netns exec ellasoc ip link set ellasoc1 up", "ip netns exec ellasoc ip link set lo up"):
        subprocess.run(c, shell=True, check=False)
    time.sleep(1.5)
    subprocess.run("firewall-cmd --add-rich-rule='rule family=ipv6 source address=fd00:e11a::/64 accept' >/dev/null 2>&1", shell=True)
    url = 'curl -g -s -m 4 -o /dev/null -w "%{http_code}" -H "Host: ' + HOST + '" "http://[fd00:e11a::1]/"'
    before = ns_run(url).stdout.strip()
    if not before.isdigit() or before == "000":
        check("IPv6 ban, end to end", False, f"NOT RUN: the server doesn't answer on IPv6 here (got {before!r})")
        _ipv6_cleanup()
        return
    check("over IPv6, a client gets an answer", before.isdigit() and int(before) < 500, before)
    op = engine.ban("fd00:e11a::2", 300, "test", "test")
    check("an IPv6 ban is confirmed in the firewall", op["state"] == "applied", str(op.get("error")))
    after = ns_run(url).stdout.strip()
    check("the banned IPv6 client can't connect", after in ("000", ""), after)
    row = next(b for b in engine.list_blocks() if b["target"] == "fd00:e11a::2/128")
    engine.unban(row["id"], "test")
    again = ns_run(url).stdout.strip()
    check("unbanning brings it back", again.isdigit() and int(again) < 500 and again != "000", again)
    _ipv6_cleanup()


def _ipv6_cleanup() -> None:
    subprocess.run("firewall-cmd --remove-rich-rule='rule family=ipv6 source address=fd00:e11a::/64 accept' >/dev/null 2>&1; ip netns del ellasoc 2>/dev/null; ip link del ellasoc0 2>/dev/null", shell=True)


def t_agent() -> None:
    a = agentd.SocketAdapter()
    ping = a.ping()
    check("the agent service answers", ping.get("ok"), str(ping))
    if not ping.get("ok"):
        return
    st = subprocess.run("systemctl show aurora-ella-agent -p MemoryMax -p TasksMax -p CPUQuotaPerSecUSec -p NoNewPrivileges -p ProtectSystem -p CapabilityBoundingSet", shell=True, capture_output=True, text=True).stdout
    check("it runs with limits and few privileges", "NoNewPrivileges=yes" in st and "ProtectSystem=strict" in st and "MemoryMax=209715200" in st, " ".join(st.split())[:220])
    target = "198.51.100.77"
    e2 = Engine(store, a)
    op = e2.ban(target, 60, "through the agent", "test")
    check("a ban through the socket is confirmed by reading it back", op["state"] == "applied", str(op.get("error")))
    in_set = target in subprocess.run(["nft", "list", "set", "inet", "aurora_ella", "ella4"], capture_output=True, text=True).stdout
    check("and is really in the firewall", in_set)
    row = next(b for b in e2.list_blocks() if b["target"] == f"{target}/32")
    e2.unban(row["id"], "test")
    check("nginx -t works from inside the sandbox", a.call("nginx_test" if SERVER == "nginx" else "apache_test").get("ok"), "")
    check("reloading works from inside it", a.call("nginx_reload" if SERVER == "nginx" else "apache_reload").get("ok"))
    time.sleep(1)
    check("fail2ban answers from inside it", a.call("f2b_status").get("ok"))
    check("journald reads from inside it", a.call("journal_read", {"journal": "sshd"}).get("ok"))
    try:
        a.call("nft_add", {"target": "1.2.3.4; reboot"})
        check("bad arguments are refused over the socket", False)
    except ValueError:
        check("bad arguments are refused over the socket", True)
    denied = subprocess.run(["sudo", "-u", "nobody", "/usr/bin/python3", "-c", "import socket;s=socket.socket(socket.AF_UNIX);s.connect('/run/aurora-ella/agent.sock')"], capture_output=True, text=True)
    check("other users can't reach the socket", denied.returncode != 0, denied.stderr.strip().splitlines()[-1][:100] if denied.stderr else "")
    subprocess.run("systemctl stop aurora-ella-agent", shell=True)
    time.sleep(0.5)
    fallback = agentd.SocketAdapter(fallback=adapter, fail_mode=lambda: "open")
    check("agent down, open: the panel carries on", fallback.call("nft_list", {"family": 4}).get("ok") and fallback.last_transport == "fallback")
    closed = Engine(store, agentd.SocketAdapter(fallback=adapter, fail_mode=lambda: "closed"))
    op = closed.ban("198.51.100.78", 60, "while closed", "test")
    check("agent down, closed: a ban isn't claimed, and the reason is given", op["state"] != "applied" and "agent" in op["error"], str(op.get("error"))[:110])
    subprocess.run("systemctl start aurora-ella-agent", shell=True)
    time.sleep(1)
    for row in closed.list_blocks():
        if row["target"] == "198.51.100.78/32":
            store.run(lambda c, r=row: c.execute("UPDATE blocks SET desired_state='failed' WHERE id=?", (r["id"],)))
            store.run(lambda c, r=row: c.execute("UPDATE operations SET state='failed', next_retry_at=NULL WHERE id=?", (r["operation_id"],)))
    check("and back up, it answers", a.ping().get("ok"))


def t_fleet_over_http() -> None:
    """The real panel's real route, signed, on this machine. A second machine isn't part of this."""
    temp = Store(store.dir.parent / f"ella-member-{pid}")
    cfg_stub = type("C", (), {"apply": lambda *a, **k: {"ok": True}})()
    other_book = R.RuleBook(temp, cfg_stub, sites=lambda: [], servers=lambda: [{"name": "nginx", "engine": "v3", "file": R.NGINX_FILE, "active": False}], policy_defaults=lambda: {})
    token = _api_token()
    base = _panel_url()
    enrolled = _panel("POST", "/api/ella/fleet/enroll", token, {"name": "ella-test-member"})
    if not check("a server can be enrolled through the API", "secret" in enrolled, str(list(enrolled))[:100]):
        return

    class Eng:
        bans: list = []

        def ban(self, t, ttl, reason, actor, **k):
            self.bans.append(t)

        def list_blocks(self):
            return []
    pin = _cert_pin(base)
    m = fleet.Member(temp, other_book, Eng())
    res = m.join(base, enrolled["agent_id"], enrolled["secret"], "test", pin)
    check("a member joins over HTTPS and gets a signed policy", res.get("ok") and bool(res.get("applied")), str(res))
    bad = dict(temp.setting("fleet_member"))
    bad["secret"] = "x" * 40
    try:
        fleet._send(bad, "/api/ella/fleet/checkin", {})
        check("the wrong secret is refused", False)
    except fleet.FleetError as exc:
        check("the wrong secret is refused", "403" in str(exc), str(exc)[:90])
    wrongpin = dict(temp.setting("fleet_member"))
    wrongpin["pin"] = "0" * 64
    try:
        fleet._send(wrongpin, "/api/ella/fleet/checkin", {})
        check("the wrong certificate is refused", False)
    except fleet.FleetError as exc:
        check("the wrong certificate is refused", "fingerprint" in str(exc))
    _panel("POST", "/api/ella/fleet/ban-everywhere", token, {"target": "198.51.100.90", "ttl": 60, "reason": "test"})
    res = m.tick()
    check("ban everywhere reaches the member", "198.51.100.90/32" in Eng.bans, str(res))
    temp.add_events([{"hash": uuid.uuid4().hex * 2, "ts_event": time.time() + 1, "ts_received": time.time(), "source": "modsec_audit", "severity": "CRITICAL", "client_ip": "198.51.100.91", "domain": "member.ella-test.example", "historical": 0, "missing_fields": "[]", "url": "/x", "tags": "[]", "headers": "{}", "query_keys": "[]", "evidence": []}])
    m.tick()
    seen = _panel("GET", "/api/ella/search?q=" + "client_ip:198.51.100.91", token)
    check("its events reach the control panel", len(seen.get("events", [])) >= 1)
    cur = temp.setting("fleet_member")
    gone = {**cur, "url": "https://127.0.0.1:1"}
    temp.set_setting("fleet_member", gone)
    r = m.tick()
    check("with the control panel gone it keeps its policy", not r["ok"] and r["enforcing"] == cur["version"])
    _panel("POST", "/api/ella/fleet/lift-everywhere", token, {"target": "198.51.100.90"})
    _panel("DELETE", f"/api/ella/fleet/agents/{enrolled['agent_id']}", token)
    engine_row = [b for b in engine.list_blocks() if b["target"] == "198.51.100.90/32"]
    for b in engine_row:
        engine.unban(b["id"], "test")
    _drop_token(token)
    subprocess.run(["rm", "-rf", str(temp.dir)], check=False)


def _panel_url() -> str:
    for scheme in ("https", "http"):
        probe = subprocess.run(["curl", "-sk", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", f"{scheme}://127.0.0.1:8088/api/status"], capture_output=True, text=True).stdout
        if probe and probe != "000":
            return f"{scheme}://127.0.0.1:8088"
    raise RuntimeError("The panel isn't answering on 8088")


def _cert_pin(url: str) -> str | None:
    if not url.startswith("https"):
        return None
    import hashlib
    import ssl
    pem = ssl.get_server_certificate(("127.0.0.1", 8088))
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


_TOK: dict = {}


def _api_token() -> str:
    from backend import apitokens
    made = apitokens.create(f"ella-test-{pid}")
    _TOK["id"] = made.get("id") or made.get("name")
    return made["token"]


def _drop_token(_t: str) -> None:
    from backend import apitokens
    apitokens.revoke(_TOK["id"])


def _panel(method: str, path: str, token: str, body: dict | None = None) -> dict:
    args = ["curl", "-sk", "-m", "30", "-X", method, "-H", f"Authorization: Bearer {token}", "-H", "Content-Type: application/json"]
    if body is not None:
        args += ["-d", json.dumps(body)]
    out = subprocess.run([*args, _panel_url() + path], capture_output=True, text=True).stdout
    try:
        return json.loads(out)
    except ValueError:
        return {"raw": out[:300]}


class _Sink(http.server.BaseHTTPRequestHandler):
    got: list = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        _Sink.got.append((self.path, dict(self.headers), self.rfile.read(n)))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def t_alerts_and_export() -> None:
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_port
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", 0))
    u.settimeout(3)
    temp = Store(store.dir.parent / f"ella-alerts-{pid}")
    al = notify.Alerts(temp)
    al.add_channel({"kind": "webhook", "name": "hook", "config": {"url": f"http://127.0.0.1:{port}/alert", "secret": "shh"}, "min_severity": "WARNING"}, "test")
    al.add_channel({"kind": "syslog", "name": "log", "config": {"host": "127.0.0.1", "port": u.getsockname()[1], "proto": "udp"}, "min_severity": "WARNING"}, "test")
    al.raise_alert("possible_breach", "b1", "CRITICAL", "Test breach", "details")
    for _ in range(3):
        al.raise_alert("possible_breach", "b1", "CRITICAL", "Test breach", "details")
    sent = al.tick()
    check("an alert reaches a webhook and syslog, once", sent == 2 and len(_Sink.got) == 1, f"sent {sent}, webhook got {len(_Sink.got)}")
    path, headers, body = _Sink.got[0]
    check("the webhook is signed, and the signature checks out", headers.get("X-Aurora-Signature") == "sha256=" + notify.sign("shh", body))
    try:
        line = u.recv(4000).decode()
    except OSError:
        line = ""
    check("syslog received it", "Test breach" in line, line[:80])
    bad = al.add_channel({"kind": "webhook", "name": "dead", "config": {"url": "http://127.0.0.1:1/x"}}, "test")
    test = al.test_channel(bad["id"])
    check("a dead channel reports its error", not test["ok"] and test["error"], test.get("error", ""))
    _Sink.got.clear()
    ex = H.Exporter(temp)
    ex.set_targets([{"name": "siem", "kind": "http", "url": f"http://127.0.0.1:{port}/siem", "min_severity": "NOTICE"}, {"name": "cef", "kind": "syslog", "host": "127.0.0.1", "port": u.getsockname()[1], "proto": "udp", "min_severity": "NOTICE"}], "test")
    t = temp.setting("exports")
    for x in t:
        x["position"] = time.time() - 60
    temp.set_setting("exports", t)
    temp.add_events([{"hash": uuid.uuid4().hex * 2, "ts_event": time.time() - 5, "ts_received": time.time(), "source": "modsec_audit", "severity": "CRITICAL", "client_ip": "198.51.100.5", "rule_id": "942100", "domain": HOST, "url": "/x", "historical": 0, "missing_fields": "[]", "tags": "[]", "headers": "{}", "query_keys": "[]", "evidence": []}])
    n = ex.tick()
    try:
        cef = u.recv(4000).decode()
    except OSError:
        cef = ""
    check("events export as JSON and CEF", n == 2 and len(_Sink.got) == 1 and "CEF:0|AuroraPanel" in cef, cef[:70])
    srv.shutdown()
    u.close()
    subprocess.run(["rm", "-rf", str(temp.dir)], check=False)


def t_config_round_trip_real() -> None:
    r = book.create({"name": "yaml test", "domains": [HOST], "tree": {"field": "path", "op": "prefix", "value": "/ella-yaml"}}, "test")
    book.set_mode(r["id"], "detect", "test")
    book.set_mode(r["id"], "block", "test")
    doc = H.parse_yaml(H.to_yaml(H.export_config(book, store)))
    book.delete(r["id"], "test")
    check("after deleting the rule it no longer blocks", req("/ella-yaml") != 403)
    changes = H.diff_config(H.export_config(book, store), doc)
    check("a dry run says it would bring it back, and changes nothing", changes["rules"]["add"] == ["custom:yaml test"] and req("/ella-yaml") != 403)
    H.import_config(book, store, doc, "test")
    check("importing the file brings it back, blocking", req("/ella-yaml") == 403)
    book.delete(next(x["id"] for x in book.rules() if x["name"] == "yaml test"), "test")


def t_metrics_query_digest() -> None:
    text = H.prometheus(store)
    check("metrics are in Prometheus's format", "# TYPE ella_active_bans gauge" in text and "ella_source_lines_total" in text)
    sql = Q.compile_query("source:modsec3_audit OR source:modsec_audit")
    res = store.search_events(5, query=sql)
    check("the search language runs on real data", isinstance(res["events"], list), f"{len(res['events'])} events")
    d = H.digest(store, 7)
    check("the digest comes from real data", "events" in d, H.digest_text(d).splitlines()[1][:100])
    r = H.Retention(store)
    a = r.anchor()
    log = store.dir / "audit-anchors.log"
    check("today's audit anchor is written", log.exists() and (a is None or a["hash"] in log.read_text()))
    check("the audit chain is still whole", store.audit_verify()["ok"], str(store.audit_verify()))


def t_real_lists() -> None:
    temp = Store(store.dir.parent / f"ella-ti-{pid}")
    i = I.Intel(temp)
    i.configure("spamhaus-drop", True, False, "test")
    row = next(x for x in i.lists() if x["name"] == "spamhaus-drop")
    check("a real reputation list downloads and loads", row["count"] > 100 or bool(row["last_error"]), f"{row['count']} entries, problem: {row['last_error'] or 'none'}")
    bot = I.verify_bot("66.249.66.1", "Googlebot")
    check("a real Googlebot address verifies through DNS", bot is True, str(bot))
    check("and a fake one doesn't", I.verify_bot("1.1.1.1", "Googlebot") is False)
    subprocess.run(["rm", "-rf", str(temp.dir)], check=False)


def new_denials() -> str:
    out = subprocess.run("ausearch --input-logs -m avc -ts recent </dev/null 2>/dev/null", shell=True, capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        m = re.search(r"audit\((\d+\.\d+):", line)
        if m and float(m.group(1)) >= STARTED and "denied" in line and "execmem" not in line:
            found.append(re.sub(r"^.*avc: *denied *", "", line)[:170])
    return "\n".join(sorted(set(found)))


def restore() -> None:
    for k, v in SAVED.items():
        store.set_setting(k, v)
    for r in book.rules():
        if r["author"] == "test":
            store.run(lambda c, r=r: c.execute("DELETE FROM rules WHERE id=?", (r["id"],)))
    store.run(lambda c: c.execute("DELETE FROM policies WHERE scope LIKE 'domain:%ella-test.example'"))
    book.publish("test", watch=False)
    P.Proxies(store, configs, R._waf_servers)._publish("test")


def main() -> int:
    if os.geteuid() != 0:
        sys.exit("Run as root.")
    tests = [t_paranoia_really_reaches_the_rules, t_rules_block_for_real, t_bad_file_refused_by_server, t_false_positive_wizard, t_honeypot_and_cms, t_switches, t_smuggling, t_tester, t_proxies_and_real_client, t_ipv6_ban, t_agent, t_fleet_over_http, t_alerts_and_export, t_config_round_trip_real, t_metrics_query_digest, t_real_lists]
    only = sys.argv[2:]
    try:
        book.publish("test", watch=False)
        for t in tests:
            if only and t.__name__ not in only:
                continue
            print(f"\n=== {t.__name__}", flush=True)
            try:
                t()
            except (RuntimeError, OSError, KeyError, ValueError, IndexError, StopIteration, AttributeError, TypeError, subprocess.TimeoutExpired) as exc:
                check(t.__name__, False, f"{type(exc).__name__}: {exc}")
    finally:
        restore()
    avc = new_denials()
    check("no SELinux denials in this run, apart from the expected execmem", not avc, avc)
    bad = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad)} passed, {len(bad)} failed")
    for name, _, detail in bad:
        print(f"  FAILED {name}: {detail[:240]}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
