#!/usr/bin/env python3
"""WAF Ella, stage 1, end to end on a real server. Run as root from the panel folder, with the panel running:

    PYTHONPATH=. .venv/bin/python tests/integration/ella_stage1.py

The attacker is a network namespace (10.199.0.2, fd99:199::2) on a veth pair, so nothing here can ban the
address you are connected from. Everything it makes is removed at the end. Prints real command output.
"""
from __future__ import annotations

import json
import os
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from backend import fail2ban, guard, waf
from backend.ella import leaks
from backend.ella.adapter import EllaSystemAdapter
from backend.ella.blocks import BlockError, Engine, SafetyLocked
from backend.ella.configs import ConfigError, ConfigManager, health
from backend.ella.db import Store

NS, HOST_IF, NS_IF = "ellatest", "ella0", "ella1"
HOST4, ATTACKER4, HOST6, ATTACKER6 = "10.199.0.1", "10.199.0.2", "fd99:199::1", "fd99:199::2"
CONF = "/etc/apache2/conf-available/zz-ella.conf"
PAGE = Path("/var/www/html/ella-test.html")
PAGE_URL = f"http://{HOST4}/ella-test.html"
results: list[tuple[str, bool, str]] = []
store = Store()
adapter = EllaSystemAdapter(store.dir / "adapter.log")
engine = Engine(store, adapter)
configs = ConfigManager(adapter, store.dir / "snapshots", audit=store.audit)


def sh(cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)  # test code, fixed strings only


def in_ns(cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return sh(f"ip netns exec {NS} {cmd}", timeout)


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"\n       {detail}" if detail else ""), flush=True)
    return ok


def setup_net() -> None:
    teardown_net()
    PAGE.write_text("ok\n")
    os.chmod(PAGE, 0o644)
    sh(f"restorecon {PAGE}")
    for c in (f"ip netns add {NS}", f"ip link add {HOST_IF} type veth peer name {NS_IF}", f"ip link set {NS_IF} netns {NS}",
              f"ip addr add {HOST4}/24 dev {HOST_IF}", f"ip -6 addr add {HOST6}/64 dev {HOST_IF} nodad", f"ip link set {HOST_IF} up",
              f"ip netns exec {NS} ip addr add {ATTACKER4}/24 dev {NS_IF}", f"ip netns exec {NS} ip -6 addr add {ATTACKER6}/64 dev {NS_IF} nodad",
              f"ip netns exec {NS} ip link set {NS_IF} up", f"ip netns exec {NS} ip link set lo up"):
        r = sh(c)
        if r.returncode:
            sys.exit(f"Test network failed: {c}: {r.stderr}")
    # udev gives a new veth another MAC moments after it appears, leaving a stale neighbour entry for about 10 s.
    sh("udevadm settle")
    time.sleep(1)
    in_ns("ip neigh flush all")
    streak = 0
    for _ in range(60):
        streak = streak + 1 if curl(extra="-H 'Host: ella-test.example'", timeout=1) not in ("000", "") else 0
        if streak >= 5:
            return
        time.sleep(0.5)
    sys.exit("The test network never settled")


def teardown_net() -> None:
    PAGE.unlink(missing_ok=True)
    sh(f"ip netns del {NS}")
    sh(f"ip link del {HOST_IF}")


def curl(url: str = PAGE_URL, extra: str = "", timeout: int = 4) -> str:
    return in_ns(f"curl -s -o /dev/null -m {timeout} -w '%{{http_code}}' {extra} {shlex.quote(url)}", timeout + 5).stdout.strip()


def rows(sql: str, args: tuple = ()) -> list[dict]:
    out = []
    for p in store.months():
        c = sqlite3.connect(p, timeout=5)
        c.row_factory = sqlite3.Row
        out += [dict(r) for r in c.execute(sql, args)]
        c.close()
    return out


def wait_for(fn, secs: float = 15, every: float = 0.25):
    end = time.time() + secs
    while time.time() < end:
        r = fn()
        if r:
            return r
        time.sleep(every)
    return fn()


def nft_set(family: int = 4) -> str:
    return sh(f"nft list set inet aurora_ella ella{family}").stdout


def clear_ban(target: str) -> None:
    for b in engine.list_blocks():
        if b["target"].split("/")[0] == target:
            engine.unban(b["id"], "test", "cleanup")


# ----------------------------------------------------------------------------- 1. event
def t_event_reaches_storage_and_search() -> None:
    marker = uuid.uuid4().hex[:10]
    normal = curl(extra="-H 'Host: ella-test.example'")
    check("the same page answers normally without an attack", normal == "200", f"HTTP {normal}")
    code = curl(f"http://{HOST4}/{marker}?password=hunter2&q=<script>alert(1)</script>",
                "-H 'Host: ella-test.example' -H 'Authorization: Bearer SECRETTOKEN123' -H 'Cookie: sid=COOKIESECRET' -A 'ella-test-agent'")
    check("attack from the namespace is blocked inline", code == "403", f"HTTP {code}")
    mine = lambda: [e for e in store.search_events(limit=50, client_ip=ATTACKER4, source="modsec_audit", domain="ella-test.example")["events"] if e["url"] == f"/{marker}"]
    t0 = time.time()
    found = wait_for(mine)
    if not check("audit log event is in the database and in the Live Events query", bool(found), f"visible after {time.time() - t0:.1f}s (target p95 5s)"):
        return
    check("the event says the WAF blocked it", found[0]["action"] == "blocked" and found[0]["status"] == 403)
    e = found[0]
    print(json.dumps({k: e[k] for k in ("ts_event", "domain", "client_ip", "client_ip_source", "method", "url", "query_keys", "status", "rule_id", "severity", "anomaly_score", "action", "raw_ref", "missing_fields")}, indent=1))
    print("evidence:", json.dumps(e["evidence"][:2], indent=1))
    check("evidence has rule, variable name and matched data", any(x["rule_id"] and x["matched_var_name"] for x in e["evidence"]))
    dump = json.dumps(found)
    check("password, token and cookie are not stored", not any(s in dump for s in ("hunter2", "SECRETTOKEN123", "COOKIESECRET")))
    print("--- grep over the raw database files for the secrets:")
    print(sh(f"grep -c -a -E 'hunter2|SECRETTOKEN123|COOKIESECRET' {store.dir}/events-*.db* || true").stdout)


# ----------------------------------------------------------------------------- 2-4. ban
def t_ban_applied_keepalive_and_traffic() -> None:
    client = subprocess.Popen(["ip", "netns", "exec", NS, sys.executable, "-c", KEEPALIVE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    first = client.stdout.readline().strip()
    check("keep-alive session is open before the ban", first.startswith("first "), first)
    t0 = time.time()
    op = engine.ban(ATTACKER4, 600, "stage 1 test", "test", operator_ip=None)
    secs = time.time() - t0
    listing = nft_set()
    print(listing)
    check("ban reaches applied and is in the nft set", op["state"] == "applied" and ATTACKER4 in listing, f"state={op['state']} in {secs:.2f}s (target p95 3s) capabilities={op['capabilities']}")
    b = engine.get_block(op["block_id"])
    check("record says present, verified by reading", b["actual_state"] == "present" and b["last_verified_at"] is not None)
    client.stdin.write("go\n")
    client.stdin.flush()
    second = client.stdout.readline().strip()
    client.wait(timeout=20)
    check("keep-alive session of the banned address is cut", second.startswith(("reset", "timeout", "closed")), second)
    code = curl()
    check("new requests from the banned address don't get through", code in ("000", ""), f"curl http_code={code!r}")
    check("other addresses still work", health("localhost")[0], health("localhost")[1])


KEEPALIVE = f"""
import http.client, socket, sys
c = http.client.HTTPConnection("{HOST4}", 80, timeout=8)
c.request("GET", "/ella-test.html", headers={{"Host": "ella-test.example", "Connection": "keep-alive"}})
r = c.getresponse(); r.read(); print("first", r.status, flush=True)
sys.stdin.readline()
try:
    c.sock.sendall(b"GET /ella-test.html HTTP/1.1\\r\\nHost: ella-test.example\\r\\n\\r\\n")
    c.sock.settimeout(8)
    data = c.sock.recv(100)
    print("closed by server" if not data else "STILL ANSWERED " + repr(data[:20]), flush=True)
except socket.timeout:
    print("timeout", flush=True)
except OSError as e:
    print("reset", e, flush=True)
"""


def t_unban_leaves_fail2ban_alone() -> None:
    guard.ensure()
    sh(f"/usr/local/sbin/aurora-guard-ban add {ATTACKER4} 600")
    f2b = sh("nft list set inet aurora_guard f2b4").stdout
    check("the same address is also in fail2ban's f2b4", ATTACKER4 in f2b)
    block = next(b for b in engine.list_blocks() if b["target"].startswith(ATTACKER4))
    u = engine.unban(block["id"], "test", "stage 1 test")
    check("unban reaches applied and leaves Ella's set", u["state"] == "applied" and ATTACKER4 not in nft_set(), f"state={u['state']}")
    still = sh("nft list set inet aurora_guard f2b4").stdout
    print(still)
    check("fail2ban's entry is untouched", ATTACKER4 in still)
    check("the address is still kept out, by fail2ban's entry", curl() in ("000", ""), f"http_code={curl()!r}")
    sh(f"/usr/local/sbin/aurora-guard-ban del {ATTACKER4}")
    code = curl(extra="-H 'Host: ella-test.example'")
    check("reachable again once both are gone", code not in ("000", ""), f"HTTP {code}")


def t_real_fail2ban_uses_guard_sets() -> None:
    """Real fail2ban, real jail, this panel's profile: does banaction land in f2b4 on Fedora?"""
    ip = "198.51.100.77"
    sh("systemctl start fail2ban")
    before = sh("fail2ban-client status").stdout
    print(before)
    if "Number of jail:\t0" in before:
        print("0 jails: initializing the panel's profile")
        fail2ban.save(None, None)
        sh("systemctl restart fail2ban")
        wait_for(lambda: "sshd" in sh("fail2ban-client status").stdout, 15, 1)
    print(sh("fail2ban-client status").stdout)
    print(sh("grep -h banaction /etc/fail2ban/jail.d/*.local /etc/fail2ban/jail.d/*.conf").stdout)
    r = sh(f"fail2ban-client set sshd banip {ip}")
    print("banip:", r.stdout.strip(), r.stderr.strip())
    time.sleep(2)
    listing = sh("nft list set inet aurora_guard f2b4").stdout
    print(listing)
    check("fail2ban's ban lands in the panel's f2b4 set", ip in listing, sh("journalctl -u fail2ban -n 3 --no-pager | cut -c1-150").stdout)
    sh(f"fail2ban-client set sshd unbanip {ip}")
    time.sleep(1)
    check("fail2ban's unban removes it from f2b4", ip not in sh("nft list set inet aurora_guard f2b4").stdout)


# ----------------------------------------------------------------------------- safety, ipv6, expiry
def t_safety_lock() -> None:
    for target, kw, forceable in (("127.0.0.1", {}, False), ("127.0.0.1", {"force": True}, False), ("::1", {"force": True}, False), ("203.0.113.5", {"operator_ip": "203.0.113.5"}, True)):
        try:
            engine.ban(target, 60, "test", "test", **kw)
            check(f"Safety Lock refuses {target} {kw}", False, "IT WAS BANNED")
            clear_ban(target)
        except SafetyLocked as exc:
            check(f"Safety Lock refuses {target} {kw}", exc.forceable == forceable, str(exc))
    check("nothing got into the set", "127.0.0.1" not in nft_set() and "203.0.113.5" not in nft_set())
    print("--- ", [e["action"] for e in store.audit_entries(3)])


def t_ipv6() -> None:
    url = f"http://[{HOST6}]/"
    before = curl(url, "-g -H 'Host: ella-test.example'")
    op = engine.ban(ATTACKER6, 60, "ipv6 test", "test")
    print(nft_set(6))
    check("IPv6 ban applied", op["state"] == "applied" and ATTACKER6 in nft_set(6), f"before ban: HTTP {before}")
    check("IPv6 traffic is dropped", before not in ("000", "") and curl(url, "-g") in ("000", ""))
    engine.unban(op["block_id"], "test", "done")
    check("IPv6 back after unban", curl(url, "-g -H 'Host: ella-test.example'") not in ("000", ""))


def t_ttl_expiry() -> None:
    op = engine.ban(ATTACKER4, 4, "ttl test", "test")
    check("short ban applied", op["state"] == "applied" and curl(timeout=2) in ("000", ""))
    time.sleep(5)
    print(nft_set())
    check("the kernel took it out of the set when its time ran out", ATTACKER4 not in nft_set())
    # the panel's own worker notices
    done = wait_for(lambda: engine.get_block(op["block_id"])["desired_state"] == "expired", 20, 1)
    check("the worker marked it expired from the set's real state", bool(done), f"op state={engine.get_operation(op['id'])['state']}")
    check("traffic passes again", curl(extra="-H 'Host: ella-test.example'") not in ("000", ""))


def t_backend_failure() -> None:
    class Broken(EllaSystemAdapter):
        def call(self, op, args=None, operation_id=""):
            if op == "nft_add":
                return {"ok": False, "error": "simulated: nft unavailable"}
            return super().call(op, args, operation_id)
    e = Engine(store, Broken())
    op = e.ban("203.0.113.200", 60, "failure test", "test")
    check("a failing backend isn't reported applied", op["state"] == "pending" and "nft unavailable" in op["error"], f"state={op['state']} attempts={op['attempts']} retry in {op['next_retry_at'] - time.time():.1f}s")
    # finish it here, in the broken engine, so the panel's healthy worker doesn't retry and succeed
    for _ in range(3):
        store.run(lambda c: c.execute("UPDATE operations SET next_retry_at=NULL WHERE id=?", (op["id"],)))
        e._attempt(op["id"])
    final = e.get_operation(op["id"])
    check("after the retries it is failed, with the reason", final["state"] == "failed" and final["attempts"] == 4, f"{final['state']}: {final['error']}")


# ----------------------------------------------------------------------------- config + Watchdog
def t_broken_config_rolls_back() -> None:
    good = "# Managed by WAF Ella\n"
    configs.apply(CONF, good, "test", watch_seconds=None)
    try:
        configs.apply(CONF, "ThisIsNotADirective at all\n", "test", watch_seconds=None)
        check("broken config is refused", False, "it was accepted")
    except ConfigError as exc:
        check("broken config is refused", True, str(exc).splitlines()[-1][:150])
    check("the previous file is back", Path(CONF).read_text() == good)
    active = sh("systemctl is-active httpd").stdout.strip()
    check("httpd stayed active", active == "active" and health()[0], f"{active}, {health()[1]}")


def t_watchdog_rolls_back_degradation() -> None:
    good = Path(CONF).read_text()
    try:
        configs.apply(CONF, "Redirect 503 /\n", "test", watch_seconds=None)
        check("a valid config that breaks the site is rolled back right after the reload", False, "it stayed")
    except ConfigError as exc:
        check("a valid config that breaks the site is rolled back right after the reload", Path(CONF).read_text() == good and health()[0], str(exc))
    # This one passes the health check (Host: localhost still works) and fails real visitors: only the Watchdog can see it.
    harmful = """<If "%{HTTP_HOST} != 'localhost'">\n    Redirect 503 /\n</If>\n"""
    configs.apply(CONF, harmful, "test", watch_seconds=None)
    code = curl(extra="-H 'Host: ella-test.example'")
    check("the harmful config passed the checks and visitors get 503", health()[0] and code == "503", f"local {health()[1]}, visitor HTTP {code}")
    snap = next(s for s in configs.snapshots(CONF) if s["content"] == good)
    out: dict = {}
    w = threading.Thread(target=lambda: out.update(configs.watch(CONF, snap, seconds=30, interval=1)))
    w.start()
    time.sleep(0.5)
    for _ in range(30):
        curl(extra="-H 'Host: ella-test.example'", timeout=2)
    w.join(timeout=40)
    check("Watchdog saw the 5xx share and rolled it back", out.get("rolled_back") is True, out.get("why", str(out)))
    time.sleep(1)
    code = curl(extra="-H 'Host: ella-test.example'")
    check("visitors served again, file restored, httpd active", code == "200" and Path(CONF).read_text() == good and sh("systemctl is-active httpd").stdout.strip() == "active", f"HTTP {code}")
    check("snapshots are capped at 5", len(configs.snapshots(CONF)) <= 5, str(len(configs.snapshots(CONF))))
    check("the rollback is in the audit log", any(e["action"] == "config.rolled_back" and e["actor"] == "watchdog" for e in store.audit_entries(5)))


# ----------------------------------------------------------------------------- reading logs
SENDER = f"""
import http.client, sys, time
tag, n = sys.argv[1], int(sys.argv[2])
gave_up = 0
for i in range(n):
    for attempt in range(40):
        try:
            c = http.client.HTTPConnection("{HOST4}", 80, timeout=5)
            c.request("GET", f"/{{tag}}/{{i}}", headers={{"Host": "ella-test.example"}})
            c.getresponse().read(); c.close()
            break
        except (OSError, http.client.HTTPException):
            time.sleep(0.25)
    else:
        gave_up += 1
    time.sleep(0.01)
sys.exit(1 if gave_up else 0)
"""


def _count_tag(tag: str) -> tuple[int, int]:
    got = rows("SELECT url FROM events WHERE source='apache_access' AND url LIKE ?", (f"/{tag}/%",))
    return len(got), len({g["url"] for g in got})


def _send(tag: str, n: int) -> subprocess.Popen:
    return subprocess.Popen(["ip", "netns", "exec", NS, sys.executable, "-c", SENDER, tag, str(n)])


def t_rotation_loses_nothing() -> None:
    """Twice: keeping the old file, as logrotate normally does, and "rotate 0", which deletes it at once."""
    for keep in (4, 0):
        tag, n = f"rot{keep}" + uuid.uuid4().hex[:8], 400
        conf = store.dir / "test-logrotate.conf"
        conf.write_text(f"/var/log/httpd/access.log {{\n  rotate {keep}\n  dateext\n  dateformat -%Y%m%d-%s\n  missingok\n  sharedscripts\n  postrotate\n    /bin/systemctl reload httpd.service >/dev/null 2>&1 || true\n  endscript\n}}\n")
        before = os.stat("/var/log/httpd/access.log").st_ino
        p = _send(tag, n)
        time.sleep(1.5)
        r = sh(f"logrotate -f -s {store.dir}/test-logrotate.state {conf}")
        wait_for(lambda: os.path.exists("/var/log/httpd/access.log"), 20)  # the reload that recreates it is asynchronous
        after = os.stat("/var/log/httpd/access.log").st_ino
        check(f"rotate {keep}: logrotate replaced the log", before != after and r.returncode == 0, f"inode {before} -> {after} {r.stderr[:150]}")
        rc = p.wait(timeout=120)
        check(f"rotate {keep}: every request was answered", rc == 0, f"sender exit {rc}")
        wait_for(lambda: _count_tag(tag) == (n, n), 30, 1)
        total, distinct = _count_tag(tag)
        check(f"rotate {keep}: every line arrived once", (total, distinct) == (n, n), f"sent {n}, stored {total}, distinct {distinct}")
        conf.unlink(missing_ok=True)


def t_restart_no_duplicates() -> None:
    tag, n = "rst" + uuid.uuid4().hex[:8], 400
    p = _send(tag, n)
    time.sleep(1.5)
    r = sh("systemctl restart aurorapanel")
    check("the panel restarted mid-traffic", r.returncode == 0)
    rc = p.wait(timeout=120)
    check("the sender finished", rc == 0, f"exit {rc}")
    wait_for(lambda: _count_tag(tag) == (n, n), 40, 1)
    total, distinct = _count_tag(tag)
    check("no duplicates and no loss across the restart", (total, distinct) == (n, n), f"sent {n}, stored {total}, distinct {distinct}")
    src = store.read(lambda c: c.execute("SELECT path, kind, status, lines, unparsed FROM sources").fetchall())
    print("sources:", json.dumps([dict(s) for s in src], indent=1))


# ----------------------------------------------------------------------------- ella-cli and audit
def t_cli() -> None:
    env = "PATH=/usr/local/sbin:/usr/sbin:/usr/bin"
    print(sh(f"{env} ella-cli status").stdout)
    op = engine.ban(ATTACKER4, 120, "cli test", "test")
    r = sh(f"{env} ella-cli bypass --minutes 1 --cidr {ATTACKER4}/32")
    print(r.stdout, r.stderr)
    check("ella-cli bypass lets the address past its ban", curl(extra="-H 'Host: ella-test.example'") not in ("000", ""), r.stdout.strip())
    sh(f"nft delete element inet aurora_ella bypass4 {{ {ATTACKER4} }}")
    sh(f"nft delete element inet aurora_guard trust4 {{ {ATTACKER4} }}")
    check("after bypass ends the ban holds again", curl(timeout=2) in ("000", ""))
    r = sh(f"{env} ella-cli unban {ATTACKER4}")
    print(r.stdout, r.stderr)
    check("ella-cli unban opens the address", curl(extra="-H 'Host: ella-test.example'") not in ("000", ""))
    done = wait_for(lambda: engine.get_block(op["block_id"])["desired_state"] == "removed", 15, 1)
    time.sleep(6)
    check("the panel recorded it and didn't put the ban back", bool(done) and ATTACKER4 not in nft_set())
    check("and it is in the audit chain", any(e["action"] == "cli.unban" for e in store.audit_entries(10)))
    # the CLI with the database out of reach
    r = sh(f"{env} AURORA_ELLA_DIR=/nonexistent/ella ella-cli status")
    check("ella-cli status works without the database", r.returncode == 0 and "database: not available" in r.stdout, (r.stdout + r.stderr).strip()[-120:])
    attack = f"{PAGE_URL}?q=<script>alert(1)</script>"
    before = curl(attack, "-H 'Host: ella-test.example'")
    r = sh(f"{env} ella-cli waf detect-only")
    print(r.stdout, r.stderr)
    detect = curl(attack, "-H 'Host: ella-test.example'")
    check("ella-cli waf detect-only stops the blocking", before == "403" and detect == "200", f"before {before}, after {detect}")
    r = sh(f"{env} ella-cli rollback")
    print(r.stdout, r.stderr)
    check("ella-cli rollback brings the blocking back", curl(attack, "-H 'Host: ella-test.example'") == "403")
    check("and the panel's own WAF setting agrees with the file", waf.load()["mode"] == "block", f"mode={waf.load()['mode']}")


def t_audit_chain() -> None:
    v = store.audit_verify()
    check("audit hash chain verifies", v["ok"], str(v))
    for sql in ("UPDATE audit SET actor='x'", "DELETE FROM audit"):
        try:
            store.run(lambda c, sql=sql: c.execute(sql))
            check(f"audit refuses: {sql}", False)
        except sqlite3.IntegrityError as exc:
            check(f"audit refuses: {sql}", True, str(exc))
    acts = [f"{e['seq']} {e['actor']} {e['action']} {e['target']}" for e in store.audit_entries(8)]
    print("\n".join(acts))


def t_leak_scan() -> None:
    r = leaks.scan(store)
    print(json.dumps({k: r[k] for k in ("scanned", "total", "counts")}))
    check("the secrets check ran over real stored events and found nothing", r["total"] == 0, str(r["findings"][:3]))


def t_avc() -> None:
    r = sh("ausearch --input-logs -m avc -ts recent -i </dev/null 2>/dev/null | grep denied | sed -E 's/.*avc: *denied *//;s/pid=[0-9]+ //;s/ino=[0-9]+ //' | cut -c1-170 | sort | uniq -c | sort -nr | head")
    check("no SELinux denials during the run", not r.stdout.strip(), r.stdout.strip())


TESTS = [t_event_reaches_storage_and_search, t_ban_applied_keepalive_and_traffic, t_unban_leaves_fail2ban_alone, t_real_fail2ban_uses_guard_sets, t_safety_lock, t_ipv6, t_ttl_expiry,
         t_backend_failure, t_broken_config_rolls_back, t_watchdog_rolls_back_degradation, t_rotation_loses_nothing, t_restart_no_duplicates, t_cli, t_audit_chain, t_leak_scan, t_avc]


def main() -> int:
    if os.geteuid() != 0:
        sys.exit("Run as root.")
    setup_net()
    only = sys.argv[1:]
    try:
        for t in TESTS:
            if only and t.__name__ not in only:
                continue
            print(f"\n=== {t.__name__}", flush=True)
            try:
                t()
            except (RuntimeError, OSError, KeyError, ValueError, StopIteration, subprocess.TimeoutExpired, sqlite3.Error) as exc:
                check(t.__name__, False, f"{type(exc).__name__}: {exc}")
    finally:
        for b in engine.list_blocks():
            if b["reason"].endswith(("test", "done")) or b["owner"] == "test":
                try:
                    engine.unban(b["id"], "test", "end of test")
                except BlockError:
                    pass
        sh(f"/usr/local/sbin/aurora-guard-ban del {ATTACKER4}")
        teardown_net()
    bad = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad)} passed, {len(bad)} failed")
    for name, _, detail in bad:
        print(f"  FAILED {name}: {detail[:200]}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
