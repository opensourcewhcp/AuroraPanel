#!/usr/bin/env python3
"""WAF Ella, stage 2, on a real server. Run as root from the panel folder, with the panel running:

    PYTHONPATH=. .venv/bin/python tests/integration/ella_stage2.py

It uses documentation addresses (198.51.100.x), which nobody really connects from, and removes what it adds.
It needs nothing from Apache or the WAF, so it runs whichever web server is on port 80.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path

from backend import guard
from backend.ella.adapter import EllaSystemAdapter
from backend.ella.blocks import BlockError, Engine
from backend.ella.collector import Collector, check_custom
from backend.ella.db import Store
from backend.ella.registry import Registry

# A new address each run: fail2ban's recidive jail would otherwise start banning the test's own address too.
_base = 100 + int(uuid.uuid4().hex[:4], 16) % 150
THREE, EXTERNAL, GUARD_EXT, F2B_EXT = (f"198.51.100.{_base + i}" for i in range(4))
LOG = Path("/var/log/ella-custom-test.log")
results: list[tuple[str, bool, str]] = []
store = Store()
adapter = EllaSystemAdapter(store.dir / "adapter.log")
engine = Engine(store, adapter)
registry = Registry(engine)


def sh(cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)  # test code, fixed strings only


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"\n       {detail}" if detail else ""), flush=True)
    return ok


def wait_for(fn, secs: float = 20, every: float = 0.5):
    end = time.time() + secs
    while time.time() < end:
        r = fn()
        if r:
            return r
        time.sleep(every)
    return fn()


def rows(sql: str, args: tuple = ()) -> list[dict]:
    out = []
    for p in store.months():
        c = sqlite3.connect(p, timeout=5)
        c.row_factory = sqlite3.Row
        out += [dict(r) for r in c.execute(sql, args)]
        c.close()
    return out


def mirrored(target: str) -> dict:
    return {b["source"]: b for b in engine.list_blocks() if b["target"] == f"{target}/32"}


def t_three_sources_one_address() -> None:
    guard.unban(THREE)  # in case an earlier run was cut short
    op = engine.ban(THREE, 600, "stage 2 test", "test")
    guard.ban(THREE, "stage 2 test", 600, None, "stage 2 test")
    print(sh(f"fail2ban-client set sshd banip {THREE}").stdout.strip())
    time.sleep(1)
    registry.sync()
    m = mirrored(THREE)
    print(json.dumps({k: {x: v[x] for x in ("backend", "owner", "actual_state", "desired_state")} for k, v in m.items()}, indent=1))
    check("one address, three independent entries", set(m) == {"ella", "guard", "fail2ban:sshd"}, str(sorted(m)))
    check("each one confirmed present", all(v["actual_state"] == "present" for v in m.values()))
    ella_set = lambda: THREE in sh("nft list set inet aurora_ella ella4").stdout  # noqa: E731
    guard_set = lambda: THREE in sh("nft list set inet aurora_guard ban4").stdout  # noqa: E731
    f2b_set = lambda: THREE in sh("nft list set inet aurora_guard f2b4").stdout  # noqa: E731
    check("all three really are in the firewall", ella_set() and guard_set() and f2b_set())

    registry.unban(m["guard"]["id"], "test", "stage 2 test")
    registry.sync()
    check("lifting the IP Blocker's leaves the other two", ella_set() and f2b_set() and not guard_set(), str(sorted(mirrored(THREE))))
    r = registry.unban(m["fail2ban:sshd"]["id"], "test", "stage 2 test")
    time.sleep(1)
    registry.sync()
    check("lifting fail2ban's leaves WAF Ella's", r["state"] == "applied" and ella_set() and not f2b_set(), str(sorted(mirrored(THREE))))
    check("after that, only WAF Ella's is listed", set(mirrored(THREE)) == {"ella"})
    engine.unban(op["block_id"], "test", "stage 2 test")
    registry.sync()
    check("and now none", not mirrored(THREE) and not ella_set())
    check("every step is in the audit chain", store.audit_verify()["ok"], str(store.audit_verify()))


def _drift(kind: str, backend: str, target: str) -> bool:
    return any(d["kind"] == kind and d["backend"] == backend and d["target"] == f"{target}/32" for d in registry.drift())


def t_drift() -> None:
    adapter.call("nft_ensure")
    guard.ensure()
    sh(f"nft add element inet aurora_ella ella4 {{ {EXTERNAL} }}")
    sh(f"nft add element inet aurora_guard ban4 {{ {GUARD_EXT} }}")
    sh(f"nft add element inet aurora_guard f2b4 {{ {F2B_EXT} }}")
    d = registry.drift()
    print(json.dumps(d, indent=1)[:800])
    check("an address added by hand to WAF Ella's set is noticed", _drift("external", "ella", EXTERNAL))
    check("one added by hand to the IP Blocker's set is noticed", _drift("external", "guard", GUARD_EXT))
    check("one added by hand to fail2ban's set is noticed", _drift("external", "fail2ban", F2B_EXT))
    registry.resolve("ella", EXTERNAL, "accept", "test")
    check("accepting it makes it a normal record", "ella" in mirrored(EXTERNAL) and not _drift("external", "ella", EXTERNAL))
    registry.unban(mirrored(EXTERNAL)["ella"]["id"], "test", "stage 2 test")
    registry.resolve("guard", GUARD_EXT, "remove", "test")
    registry.resolve("fail2ban", F2B_EXT, "remove", "test")
    check("removing takes it out of the firewall", GUARD_EXT not in sh("nft list set inet aurora_guard ban4").stdout and F2B_EXT not in sh("nft list set inet aurora_guard f2b4").stdout)
    op = engine.ban(EXTERNAL, 600, "stage 2 test", "test")
    sh(f"nft delete element inet aurora_ella ella4 {{ {EXTERNAL} }}")
    engine.reconcile()
    check("a ban deleted behind the record's back is put back", EXTERNAL in sh("nft list set inet aurora_ella ella4").stdout)
    engine.unban(op["block_id"], "test", "stage 2 test")
    try:
        registry.resolve("guard", "198.51.100.99", "remove", "test")
        check("a difference that isn't there is refused", False)
    except BlockError as exc:
        check("a difference that isn't there is refused", True, str(exc))


def t_read_only_ufw() -> None:
    r = adapter.call("ufw_status")
    if r["installed"]:
        check("ufw status is read", r["ok"], "ufw is installed here")
    else:
        check("no ufw here means not installed, not an error", r["ok"] and not r["active"], str({k: r[k] for k in ("ok", "installed", "active")}))


def t_fail2ban_page() -> None:
    o = registry.fail2ban_overview()
    print(json.dumps([{k: j[k] for k in ("name", "bantime", "findtime", "maxretry", "uses_panel_sets", "journal", "logpath", "actions")} for j in o["jails"]][:2], indent=1))
    check("real jails with their real settings", o["state"] == "ok" and all(j["bantime"] and j["findtime"] and j["maxretry"] for j in o["jails"]), f"{len(o['jails'])} jails")
    check("jails send bans to the panel's sets", all(j["uses_panel_sets"] for j in o["jails"]))
    try:
        registry.fail2ban_init("test")
        check("set-up refuses a server that has jails", False)
    except BlockError as exc:
        check("set-up refuses a server that has jails", True, str(exc))


def _events(source: str, needle: str) -> list[dict]:
    return rows("SELECT e.*, (SELECT group_concat(msg) FROM event_evidence x WHERE x.event_id = e.id) AS msg FROM events e WHERE source = ? AND (url LIKE ? OR msg LIKE ? OR account = ?)",
                (source, f"%{needle}%", f"%{needle}%", needle))


def t_sources_reach_events() -> None:
    marker = "ella" + uuid.uuid4().hex[:8]
    sh(f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 {marker}@127.0.0.1 true")
    got = wait_for(lambda: _events("journal_sshd", marker))
    check("journald: a bad SSH login becomes an event", bool(got) and got[0]["action"] == "login_failed" and got[0]["client_ip"] == "127.0.0.1", str({k: got[0][k] for k in ("action", "client_ip", "account", "raw_ref")}) if got else "none")
    sh(f"""curl -sk -o /dev/null -m 5 -H 'Content-Type: application/json' -H 'Origin: https://127.0.0.1:8088' -d '{{"username":"{marker}","password":"wrong"}}' https://127.0.0.1:8088/api/login""")
    got = wait_for(lambda: _events("panel_audit", marker))
    check("panel log: a failed panel login becomes an event", bool(got) and got[0]["action"] == "login_failed", str({k: got[0][k] for k in ("action", "client_ip", "account", "url", "status")}) if got else "none")
    print(sh(f"fail2ban-client set sshd banip {THREE}").stdout.strip())
    got = wait_for(lambda: [e for e in rows("SELECT * FROM events WHERE source='fail2ban_log' AND client_ip=? AND action='ban' AND rule_id='sshd' ORDER BY ts_event DESC LIMIT 1", (THREE,))])
    check("fail2ban log: a ban becomes an event with its jail", bool(got) and got[0]["rule_id"] == "sshd", str({k: got[0][k] for k in ("action", "client_ip", "rule_id")}) if got else "none")
    sh(f"fail2ban-client set sshd unbanip {THREE}")
    if shutil.which("nginx") and sh("systemctl is-active nginx").stdout.strip() == "active":
        sh(f"curl -s -o /dev/null -m 5 http://127.0.0.1/{marker}")
        got = wait_for(lambda: _events("nginx_access", marker))
        check("Nginx access log becomes events", bool(got), str({k: got[0][k] for k in ("url", "status", "client_ip")}) if got else "none")
    else:
        print("NOT RUN: Nginx access log (Nginx isn't the running server)")
    src = store.read(lambda c: c.execute("SELECT path, kind, status, lines, unparsed FROM sources ORDER BY path").fetchall())
    print("\n".join(f"  {s['path']:<52} {s['status']:<11} lines={s['lines']:<6} unreadable={s['unparsed']}" for s in src))


def t_real_history_imports_as_history() -> None:
    target = next((p for p in ("/var/log/httpd/error_log", "/var/log/apache2/error.log") if os.path.exists(p) and os.path.getsize(p)), None)
    if not target:
        print("NOT RUN: no Apache error log to import")
        return
    c = Collector(store, adapter=adapter)
    a = c.import_file(target, "apache_error")
    b = c.import_file(target, "apache_error")
    check("a real error log imports, readable", a["lines"] > 0 and a["unparsed"] / max(a["lines"], 1) < 0.05, str(a))
    check("importing it again adds nothing", b["stored"] == 0, str(b))
    check("imported events are marked as history", rows("SELECT count(*) AS n FROM events WHERE source = 'apache_error' AND historical = 0 AND raw_ref LIKE ?", (f"{target}@%",)) is not None)


def t_custom_source_and_copytruncate() -> None:
    tag = "cus" + uuid.uuid4().hex[:8]
    LOG.write_text("")
    spec = check_custom({"path": str(LOG), "format": "regex", "pattern": r"^(?P<client_ip>\S+) (?P<method>\w+) (?P<url>\S+) (?P<status>\d+)$"})
    store.set_setting("custom_sources", [s for s in (store.setting("custom_sources") or []) if s["path"] != str(LOG)] + [spec])
    known = lambda: store.read(lambda c: c.execute("SELECT 1 FROM sources WHERE path = ?", (str(LOG),)).fetchone())  # noqa: E731
    check("the worker picks up a new custom source", bool(wait_for(known, 15)))
    with LOG.open("a") as f:
        for i in range(50):
            f.write(f"198.51.100.5 GET /{tag}/{i}?token=SECRET 200\n")
        f.write("this line is not in the format\n")
    count = lambda: rows("SELECT count(*) AS n, count(distinct url) AS d FROM events WHERE source='custom' AND url LIKE ?", (f"/{tag}/%",))[0]  # noqa: E731
    wait_for(lambda: count()["n"] == 50)
    check("custom lines become events", count()["n"] == 50, str(count()))
    check("query values stay out", not rows("SELECT 1 FROM events WHERE source='custom' AND raw_ref LIKE '%SECRET%' OR url LIKE '%SECRET%'"))
    row = store.read(lambda c: c.execute("SELECT unparsed, samples FROM sources WHERE path = ?", (str(LOG),)).fetchone())
    check("an unreadable line is counted, with a sample", row["unparsed"] >= 1 and "not in the format" in row["samples"], f"unreadable={row['unparsed']}")
    # copytruncate: the file is copied and emptied in place, same inode
    shutil.copy(LOG, str(LOG) + ".1")
    os.truncate(LOG, 0)
    time.sleep(1.5)
    with LOG.open("a") as f:
        for i in range(50, 100):
            f.write(f"198.51.100.5 GET /{tag}/{i} 200\n")
    wait_for(lambda: count()["n"] == 100)
    c = count()
    check("copytruncate: new lines arrive once", (c["n"], c["d"]) == (100, 100), str(c))
    try:
        check_custom({"path": str(LOG), "format": "regex", "pattern": r"^(?P<url>(a+)+)$"})
        check("a pattern that could hang is refused", False)
    except ValueError as exc:
        check("a pattern that could hang is refused", True, str(exc))
    store.set_setting("custom_sources", [s for s in (store.setting("custom_sources") or []) if s["path"] != str(LOG)])


def t_restart_no_duplicate_journal_events() -> None:
    marker = "ella" + uuid.uuid4().hex[:8]
    for _ in range(3):
        sh(f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 {marker}@127.0.0.1 true")
    wait_for(lambda: len(_events("journal_sshd", marker)) >= 3)
    before = len(_events("journal_sshd", marker))
    sh(f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 {marker}@127.0.0.1 true")
    r = sh("systemctl restart aurorapanel")
    sh(f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 {marker}@127.0.0.1 true")
    # OpenSSH can refuse repeat failures before they log anything (PerSourcePenalties), so the journal is the count.
    logged = lambda: int(sh(f"journalctl -t sshd -t sshd-session --no-pager -o cat | grep -c 'Invalid user {marker} '").stdout.strip() or 0)  # noqa: E731
    wait_for(lambda: len(_events("journal_sshd", marker)) >= logged(), 30)
    time.sleep(6)
    got, want = _events("journal_sshd", marker), logged()
    check("journal events across a panel restart: none lost, none repeated", r.returncode == 0 and want > 0 and len(got) == want and len({e["raw_ref"] for e in got}) == len(got), f"the journal has {want}, stored {len(got)}")


def t_leak_scan_and_avc() -> None:
    from backend.ella import leaks
    r = leaks.scan(store)
    check("secrets check finds nothing in the new sources' events", r["total"] == 0, json.dumps({k: r[k] for k in ("scanned", "total", "counts")}) + " " + str(r["findings"][:3]))
    a = sh("ausearch --input-logs -m avc -ts recent -i </dev/null 2>/dev/null | grep denied | sed -E 's/.*avc: *denied *//;s/pid=[0-9]+ //;s/ino=[0-9]+ //' | cut -c1-170 | sort | uniq -c | head")
    check("no SELinux denials during the run", not a.stdout.strip(), a.stdout.strip())


TESTS = [t_three_sources_one_address, t_drift, t_read_only_ufw, t_fail2ban_page, t_sources_reach_events, t_real_history_imports_as_history, t_custom_source_and_copytruncate, t_restart_no_duplicate_journal_events, t_leak_scan_and_avc]


def main() -> int:
    if os.geteuid() != 0:
        sys.exit("Run as root.")
    try:
        for t in TESTS:
            print(f"\n=== {t.__name__}", flush=True)
            try:
                t()
            except (RuntimeError, OSError, KeyError, ValueError, IndexError, subprocess.TimeoutExpired, sqlite3.Error) as exc:
                check(t.__name__, False, f"{type(exc).__name__}: {exc}")
    finally:
        for ip in (THREE, EXTERNAL):
            for src, b in mirrored(ip).items():
                try:
                    registry.unban(b["id"], "test", "end of test")
                except BlockError:
                    pass
            sh(f"fail2ban-client set sshd unbanip {ip}")
        for name, ip in (("ban4", GUARD_EXT), ("f2b4", F2B_EXT)):
            sh(f"nft delete element inet aurora_guard {name} {{ {ip} }}")
        LOG.unlink(missing_ok=True)
        Path(str(LOG) + ".1").unlink(missing_ok=True)
        registry.sync()
    bad = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad)} passed, {len(bad)} failed")
    for name, _, detail in bad:
        print(f"  FAILED {name}: {detail[:200]}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
