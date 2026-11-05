#!/usr/bin/env python3
"""WAF Ella stage 8: the numbers from the spec, measured on this machine. Run as root from the panel folder:

    PYTHONPATH=. .venv/bin/python tests/integration/ella_load.py [events]

It leaves the running web server's mode alone: "without WAF" is a test host with the WAF switched off by a domain policy, on
the same server. That still loads the module, so it slightly flatters the WAF's added cost. It needs `ab` (httpd-tools).
Its database is a temporary folder, and bans use documentation addresses and are lifted again.
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from backend import distro

os.environ["PATH"] = distro.PATH + ":" + os.environ["PATH"]
from backend.ella import agentd, collector, housekeeping as H, query as Q, rulebook as R  # noqa: E402
from backend.ella.adapter import EllaSystemAdapter  # noqa: E402
from backend.ella.blocks import Engine  # noqa: E402
from backend.ella.configs import ConfigManager  # noqa: E402
from backend.ella.db import Store  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000
ON, OFF = "on.ella-load.example", "off.ella-load.example"
rows = []


def row(name, target, value, ok, how):
    rows.append((name, target, value, ok))
    print(f"{'MET ' if ok else 'MISS' if ok is False else '    '} {name}: {value} (target {target}). {how}", flush=True)


def ab(host: str, n: int = 2000, c: int = 8) -> dict:
    out = subprocess.run(["ab", "-q", "-n", str(n), "-c", str(c), "-H", f"Host: {host}", "-H", "Accept: */*", "-H", "User-Agent: Mozilla/5.0 load", "http://127.0.0.1/test/"], capture_output=True, text=True, timeout=300).stdout
    rps = float(re.search(r"Requests per second:\s+([\d.]+)", out).group(1))
    p99 = float(re.search(r"\s99%\s+(\d+)", out).group(1))
    p50 = float(re.search(r"\s50%\s+(\d+)", out).group(1))
    bad = int((re.search(r"Non-2xx responses:\s+(\d+)", out) or [0, 0])[1])
    return {"rps": rps, "p50": p50, "p99": p99, "non2xx": bad}


def t_waf_cost() -> None:
    store = Store()
    adapter = EllaSystemAdapter(store.dir / "adapter.log")
    book = R.RuleBook(store, ConfigManager(adapter, store.dir / "snapshots", audit=store.audit))
    book.set_policy(f"domain:{OFF}", "mode", "off", False, "load-test")
    time.sleep(1)
    try:
        ab(ON, 300)
        ab(OFF, 300)
        runs_on, runs_off = [], []
        for _ in range(3):
            runs_off.append(ab(OFF))
            runs_on.append(ab(ON))
        off, on = max(runs_off, key=lambda r: r["rps"]), max(runs_on, key=lambda r: r["rps"])
        print("  rules off:", runs_off, "\n  rules on: ", runs_on)
        added = on["p99"] - off["p99"]
        row("Added latency, p99, paranoia 1", "5 ms", f"{added:.0f} ms ({off['p99']:.0f} to {on['p99']:.0f}, ab reports whole ms)", added <= 5, "ab, 2000 requests, 8 at a time, best of 3")
        share = on["rps"] / off["rps"]
        row("Throughput with the WAF", "70 % of without", f"{share * 100:.0f} % ({off['rps']:.0f} to {on['rps']:.0f} requests/s)", share >= 0.7, "same runs")
    finally:
        book.remove_policy(f"domain:{OFF}", "mode", "load-test")


def make_event(i: int, t: float) -> dict:
    ip = f"203.0.{i % 200}.{i % 250 + 1}"
    return {"hash": f"{uuid.uuid4().hex}{uuid.uuid4().hex}", "ts_event": t, "ts_received": t + 0.2, "server": "load", "domain": f"site{i % 50}.example", "source": "modsec_audit" if i % 10 == 0 else "nginx_access", "peer_ip": ip, "client_ip": ip, "client_ip_source": "peer", "method": "GET", "url": f"/page/{i % 1000}",
            "query_keys": "[]", "status": 200, "response_size": 1234, "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0", "headers": '{"host":"x"}', "rule_id": "942100" if i % 10 == 0 else None, "severity": "WARNING" if i % 10 == 0 else None, "confidence": "n/a", "action": "logged", "tags": "[]", "raw_ref": f"/var/log/x@1:{i}", "historical": 0, "missing_fields": "[]", "evidence": []}


def t_storage() -> None:
    d = Path(tempfile.mkdtemp(prefix="ella-load-", dir="/var/lib/aurora"))
    try:
        store = Store(d)
        now = time.time()
        t0, done = time.time(), 0
        while done < N:
            batch = [make_event(done + i, now - random.random() * 86400) for i in range(5000)]
            store.add_events(batch)
            done += len(batch)
        secs = time.time() - t0
        rate = done / secs
        row("Writing events", "2 000/s sustained", f"{rate:.0f}/s over {done} events", rate >= 2000, "batches of 5000, the database write alone")
        size = sum(p.stat().st_size for p in d.glob("events-*.db*"))
        per = size / done
        row("Storage per event", "1 KB", f"{per:.0f} bytes", per <= 1024, f"{size / 1e6:.0f} MB for {done} events, no evidence rows")
        times = []
        for q in ("client_ip:203.0.7.8", "rule_id:942100 AND domain:site10.example", "domain:site3.example AND status>=200"):
            t1 = time.time()
            got = store.search_events(100, query=Q.compile_query(q))
            times.append(time.time() - t1)
            print(f"  {q}: {times[-1] * 1000:.0f} ms, {len(got['events'])} rows")
        row(f"Search over {done} events", "2 s over 10 million", f"worst {max(times) * 1000:.0f} ms", max(times) <= 2, "filters on indexed fields. 10 million wasn't built: this is the number at this size" if done < 10_000_000 else "")
        t1 = time.time()
        d2 = H.digest(store, 1)
        print(f"  digest over the day: {time.time() - t1:.1f} s, {d2['events']} events")
        t1 = time.time()
        col_dir = d / "logs"
        col_dir.mkdir()
        log = col_dir / "x-access.log"
        c = collector.Collector(store, log_dir=str(col_dir))
        log.write_text("")
        c.tick()
        lines = 20000
        stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
        with log.open("a") as f:
            for i in range(lines):
                f.write(f'203.0.113.{i % 250} - - [{stamp}] "GET /p/{i}?a=1 HTTP/1.1" 200 12 "-" "Mozilla/5.0"\n')
        t1 = time.time()
        got = 0
        while got < lines and time.time() - t1 < 120:
            got += c.tick()
        rate = got / (time.time() - t1)
        row("Reading and parsing a log, all the way to stored", "2 000/s sustained", f"{rate:.0f}/s over {got} lines", rate >= 2000, "real access log lines")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def t_bans() -> None:
    store = Store()
    a = agentd.SocketAdapter(fallback=EllaSystemAdapter(store.dir / "adapter.log"))
    via = "agent service" if a.ping().get("ok") else "in-process"
    eng = Engine(store, a)
    took = []
    ids = []
    for i in range(30):
        t = f"198.51.100.{i + 100}"
        t1 = time.time()
        op = eng.ban(t, 120, "load test", "load-test")
        took.append(time.time() - t1)
        if op["state"] != "applied":
            print("  not applied:", op["error"])
        ids.append(op["block_id"])
    for b in ids:
        eng.unban(b, "load-test")
    took.sort()
    p95 = took[int(len(took) * 0.95)]
    row("Ban to confirmed, p95", "3 s", f"{p95 * 1000:.0f} ms", p95 <= 3, f"30 bans through the {via}, including read-back and cutting connections")


def t_drift() -> None:
    table = "ella_load_test"
    els = ", ".join(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}" for i in range(10000))
    script = f"table inet {table} {{\n set s {{\n type ipv4_addr\n flags timeout\n elements = {{ {els} }}\n }}\n}}\n"
    subprocess.run(["nft", "-f", "-"], input=script, text=True, check=True)
    try:
        ad = EllaSystemAdapter()
        t1 = time.time()
        r = ad._list("load", "", ("inet", table), "s")
        known = {f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}" for i in range(5000)}
        diff = {e["element"] for e in r["elements"]} - known
        secs = time.time() - t1
        row("Comparing a set of 10 000 entries", "1 s", f"{secs * 1000:.0f} ms", secs <= 1 and len(diff) == 5000, "nft's JSON, parsed and compared with a list")
    finally:
        subprocess.run(["nft", "delete", "table", "inet", table], check=False)


def t_memory() -> None:
    def rss(unit: str):
        pid = subprocess.run(["systemctl", "show", unit, "-p", "MainPID", "--value"], capture_output=True, text=True).stdout.strip()
        try:
            return int(re.search(r"VmRSS:\s+(\d+)", Path(f"/proc/{pid}/status").read_text()).group(1)) // 1024
        except (OSError, AttributeError):
            return None
    agent = rss("aurora-ella-agent")
    row("Agent service memory", "200 MB", f"{agent} MB" if agent is not None else "not running", agent is not None and agent <= 200, "resident, after this run")
    panel = rss("aurorapanel")
    row("The whole panel, with WAF Ella inside", "for information", f"{panel} MB" if panel else "?", None, "resident. WAF Ella isn't separable from the panel here")


def main() -> int:
    if os.geteuid() != 0:
        sys.exit("Run as root.")
    print(json.dumps({"cpus": os.cpu_count(), "mem_mb": int(re.search(r"MemTotal:\s+(\d+)", Path("/proc/meminfo").read_text()).group(1)) // 1024, "date": time.strftime("%Y-%m-%d"), "kernel": os.uname().release}))
    for t in (t_waf_cost, t_storage, t_bans, t_drift, t_memory):
        print(f"\n=== {t.__name__}", flush=True)
        try:
            t()
        except (RuntimeError, OSError, ValueError, KeyError, AttributeError, subprocess.SubprocessError) as exc:
            row(t.__name__, "", f"{type(exc).__name__}: {exc}", False, "")
    misses = [r for r in rows if r[3] is False]
    print(f"\n{len([r for r in rows if r[3]])} targets met, {len(misses)} missed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
