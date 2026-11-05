#!/usr/bin/env python3
"""The WAF on Nginx and a server behind it, for real. Run as root from the panel folder with Nginx running:

    PYTHONPATH=. .venv/bin/python tests/integration/nginx_waf.py

Attacks come from this machine (127.0.0.1) to test sites by Host header. A real Caddy runs on 127.0.0.1 behind Nginx.
It leaves the WAF in the mode it found, and removes its test sites.
"""
from __future__ import annotations

import json
import os
import shutil
import re
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from backend import distro

os.environ["PATH"] = distro.PATH + ":" + os.environ["PATH"]
from backend import nginxsites as N, nginxwaf as W  # noqa: E402
from backend.ella.db import Store  # noqa: E402

SITE, BEHIND = "waf.nginx-test.example", "caddy.nginx-test.example"
CADDY_PORT = 18082
results: list[tuple[str, bool, str]] = []
store = Store()


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"\n       {detail}" if detail else ""), flush=True)
    return ok


def curl(host: str, path: str = "/", *extra: str) -> str:
    return subprocess.run(["curl", "-s", "-o", "/dev/null", "-m", "8", "-w", "%{http_code}", "-H", f"Host: {host}", *extra, f"http://127.0.0.1{path}"], capture_output=True, text=True, timeout=20).stdout


def body(host: str, path: str = "/") -> str:
    return subprocess.run(["curl", "-s", "-m", "8", "-H", f"Host: {host}", f"http://127.0.0.1{path}"], capture_output=True, text=True, timeout=20).stdout


XSS = "/?q=<script>alert(1)</script>"
SQLI = "/?id=1%27%20OR%20%271%27=%271"
TRAVERSAL = "/?file=../../../../etc/passwd"
CMD = "/?c=;cat%20/etc/passwd"


STARTED = time.time()


def new_denials() -> str:
    """SELinux refusals since this run began, apart from execmem (see docs/waf-ella.md). Older ones aren't this run's."""
    out = subprocess.run("ausearch --input-logs -m avc -ts recent </dev/null 2>/dev/null", shell=True, capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        m = re.search(r"audit\((\d+\.\d+):", line)
        if m and float(m.group(1)) >= STARTED and "denied" in line and "execmem" not in line:
            found.append(re.sub(r"^.*avc: *denied *", "", line)[:170])
    return "\n".join(sorted(set(found)))


def wait_for(fn, secs=15):
    end = time.time() + secs
    while time.time() < end:
        r = fn()
        if r:
            return r
        time.sleep(0.4)
    return fn()


def main() -> int:
    before = W.mode()
    st = W.status()
    print(st)
    if not check("the module and rules are installed", st["installed"], str(st)):
        return 1
    caddy = None
    tmp = Path(tempfile.mkdtemp(prefix="caddy-test-"))
    os.chmod(tmp, 0o755)
    try:
        r = N.create({"server_name": SITE, "mode": "static"})
        Path(r["site"]["docroot"], "index.html").write_text("site page\n")
        W.set_mode("off")
        check("WAF off: an attack reaches the site", curl(SITE, XSS) == "200")

        # --- detection only
        W.set_mode("detect")
        check("watching only: an attack still reaches the site", curl(SITE, XSS) == "200", "HTTP 200 expected")
        got = wait_for(lambda: store.search_events(limit=20, source="modsec3_audit", domain=SITE, action="detected")["events"])
        check("and it is recorded as detected", bool(got), str({k: got[0][k] for k in ("rule_id", "action", "status", "anomaly_score")}) if got else "no event")

        # --- blocking
        t0 = time.time()
        W.set_mode("block")
        print(f"switching on took {time.time() - t0:.1f}s with {st['rule_files']} rule files")
        check("the page itself still loads", curl(SITE) == "200" and "site page" in body(SITE))
        for name, path in (("XSS", XSS), ("SQL injection", SQLI), ("path traversal", TRAVERSAL), ("command injection", CMD)):
            code = curl(SITE, path)
            check(f"{name} is blocked", code == "403", f"HTTP {code}")
        code = curl(SITE, "/", "-A", "sqlmap/1.8")
        check("a known attack tool's User-Agent is blocked", code == "403", f"HTTP {code}")
        code = curl(SITE, "/", "-X", "POST", "--data-urlencode", "comment=<script>alert(1)</script>")
        check("an attack in a form body is blocked", code == "403", f"HTTP {code}")
        code = curl(SITE, "/?q=hello+world&page=2")
        check("an ordinary query isn't", code == "200", f"HTTP {code}")

        marker = "wafmark" + uuid.uuid4().hex[:8]
        curl(SITE, f"/{marker}?password=hunter2&q=<script>alert(1)</script>", "-H", "Authorization: Bearer SECRETTOKEN123", "-H", "Cookie: sid=COOKIESECRET")
        mine = lambda: [e for e in store.search_events(limit=50, source="modsec3_audit", domain=SITE)["events"] if e["url"] == f"/{marker}"]  # noqa: E731
        got = wait_for(mine)
        if check("the block shows in WAF Ella's events", bool(got)):
            e = got[0]
            print(json.dumps({k: e[k] for k in ("client_ip", "domain", "url", "query_keys", "status", "rule_id", "severity", "anomaly_score", "action")}))
            print(json.dumps(e["evidence"][:1]))
            check("with its rule and matched variable", e["action"] == "blocked" and all(x["rule_id"] and x["matched_var_name"] for x in e["evidence"]), str([x["matched_var_name"] for x in e["evidence"]]))
            check("and without the password, token or cookie", not any(s in json.dumps(got) for s in ("hunter2", "SECRETTOKEN123", "COOKIESECRET")))

        # --- settings from the WAF page
        from backend import waf
        s = waf.load()
        check("Nginx uses the WAF page's settings", f"tx.paranoia_level={s['paranoia']}" in W.PRE.read_text() and f"threshold={s['threshold']}" in W.PRE.read_text())

        # --- a real Caddy behind Nginx
        (tmp / "index.html").write_text("caddy page\n")
        os.chmod(tmp / "index.html", 0o644)
        (tmp / "Caddyfile").write_text(f"{{\n\tadmin off\n\tauto_https off\n}}\n:{CADDY_PORT} {{\n\tbind 127.0.0.1\n\troot * {tmp}\n\tfile_server\n}}\n")
        caddy = subprocess.Popen(["caddy", "run", "--config", str(tmp / "Caddyfile"), "--adapter", "caddyfile"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        direct = subprocess.run(["curl", "-s", "-m", "4", f"http://127.0.0.1:{CADDY_PORT}/"], capture_output=True, text=True).stdout
        check("Caddy is running on 127.0.0.1", "caddy page" in direct, direct[:40])
        listening = subprocess.run(["ss", "-Hltn", f"sport = :{CADDY_PORT}"], capture_output=True, text=True).stdout
        local_addrs = [ln.split()[3] for ln in listening.splitlines() if ln.split()]
        check("and only there, so it can't be reached around the WAF", bool(local_addrs) and all(a.startswith("127.0.0.1:") for a in local_addrs), str(local_addrs))
        target = f"http://127.0.0.1:{CADDY_PORT}"
        N.create({"server_name": BEHIND, "mode": "proxy", "proxy": target})
        check("that target counts as local", W.is_local_only(target))
        check("visitors get Caddy's page through Nginx", "caddy page" in body(BEHIND))
        check("attacks on it are blocked before reaching Caddy", curl(BEHIND, XSS) == "403" and curl(BEHIND, SQLI) == "403")

        # --- refusal leaves things working
        keep = W.PRE.read_text()
        bad = W.HOOK.read_text()
        try:
            N._apply({W.HOOK: bad + "modsecurity_rules_file /nonexistent/file.conf;\n"})
            check("Nginx refuses a broken WAF file", False)
        except N.NginxError as exc:
            check("Nginx refuses a broken WAF file", True, str(exc).splitlines()[-1][:110])
        check("and blocking carries on", W.PRE.read_text() == keep and W.HOOK.read_text() == bad and curl(SITE, XSS) == "403" and curl(SITE) == "200")

        # --- speed, rough
        def timed(n: int = 200) -> float:
            t = time.time()
            for _ in range(n):
                curl(SITE)
            return (time.time() - t) / n * 1000
        with_waf = timed()
        W.set_mode("off")
        without = timed()
        print(f"rough time per request through curl: with WAF {with_waf:.1f} ms, without {without:.1f} ms")
        W.set_mode("block")
        rss = subprocess.run("ps -C nginx -o rss= | awk '{s+=$1} END {print int(s/1024)}'", shell=True, capture_output=True, text=True).stdout.strip()
        print(f"nginx memory with the rules loaded: {rss} MB")

        # The WAF's regex engine asks for executable memory (most likely PCRE's JIT) and is refused, and rules still
        # work. Allowing it would mean httpd_execmem for every web process, so this refusal is expected and stays.
        avc = new_denials()
        check("no SELinux denials in this run, apart from the expected execmem", not avc, avc)
    finally:
        if caddy:
            caddy.terminate()
        for name in (SITE, BEHIND):
            try:
                N.delete(name, True)
            except N.NginxError:
                pass
            shutil.rmtree(f"/var/www/{name}", ignore_errors=True)
        subprocess.run(f"rm -rf {N.TRASH}/*.nginx-test.example-*; rm -f {N.LOG_DIR}/*.nginx-test.example-*.log", shell=True, check=False)
        shutil.rmtree(tmp, ignore_errors=True)
        W.set_mode(before)
    bad_ = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad_)} passed, {len(bad_)} failed")
    for name, _, detail in bad_:
        print(f"  FAILED {name}: {detail[:200]}")
    return 1 if bad_ else 0


if __name__ == "__main__":
    sys.exit(main())
