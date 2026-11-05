#!/usr/bin/env python3
"""WordPress and certificate paths on Nginx, and websites on Caddy, for real. Run as root from the panel folder:

    PYTHONPATH=. .venv/bin/python tests/integration/more_web.py

It needs Nginx running, MariaDB and PHP-FPM, and internet access for WordPress. For the Caddy part it switches port 80 to
Caddy for a moment and back to Nginx. Issuing a real Let's Encrypt certificate needs a public domain, so that isn't run here.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

from backend import distro

os.environ["PATH"] = distro.PATH + ":" + os.environ["PATH"]
from backend import apps, caddysites as C, nginxsites as N, nginxwaf as W, sysapps  # noqa: E402

WP, ACME, CP, CS, CX, CT = "wp.nginx-test.example", "acme.nginx-test.example", "php.caddy-test.example", "static.caddy-test.example", "proxy.caddy-test.example", "tls.caddy-test.example"
results: list[tuple[str, bool, str]] = []
STARTED = time.time()


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"\n       {detail}" if detail else ""), flush=True)
    return ok


def fetch(host: str, path: str = "/", scheme: str = "http", extra: tuple = ()) -> tuple[str, str]:
    r = subprocess.run(["curl", "-sk", "-m", "10", "-H", f"Host: {host}", "--resolve", f"{host}:443:127.0.0.1", "-w", "\n%{http_code}", *extra,
                        f"https://{host}{path}" if scheme == "https" else f"http://127.0.0.1{path}"], capture_output=True, text=True, timeout=25)
    body, _, code = r.stdout.rpartition("\n")
    return code, body


def new_denials() -> str:
    out = subprocess.run("ausearch --input-logs -m avc -ts recent </dev/null 2>/dev/null", shell=True, capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        m = re.search(r"audit\((\d+\.\d+):", line)
        if m and float(m.group(1)) >= STARTED and "denied" in line and "execmem" not in line:
            found.append(re.sub(r"^.*avc: *denied *", "", line)[:170])
    return "\n".join(sorted(set(found)))


def wait_job(j, secs=240):
    end = time.time() + secs
    while j.status == "running" and time.time() < end:
        time.sleep(1)
    return j


def t_wordpress_on_nginx() -> None:
    N.create({"server_name": WP})
    pw = "Aa1" + secrets.token_urlsafe(15).replace("-", "x").replace("_", "y")
    j = wait_job(N.wordpress(WP, {"title": "Nginx test", "admin_user": "wpowner", "admin_email": "owner@example.org", "admin_pass": pw}))
    print("\n".join(str(x)[:130] for x in list(j.lines)[-5:]))
    if not check("WordPress installs on a Nginx site, through the WAF's server", j.status == "done", j.status):
        return
    root = Path(f"/var/www/{WP}")
    code, body = fetch(WP)
    check("its home page is WordPress", code == "200" and "Nginx test" in body, f"HTTP {code}")
    check("no Apache files were added for it", not list(Path("/etc/apache2/conf-enabled").glob("zz-aurora-app-*nginx_test*")))
    code, body = fetch(WP, "/wp-login.php")
    check("its login page loads", code == "200" and "user_login" in body, f"HTTP {code}")
    cookie = "wordpress_test_cookie=WP%20Cookie%20check"
    login = subprocess.run(["curl", "-s", "-o", "/dev/null", "-m", "15", "-w", "%{http_code} %{redirect_url}", "-H", f"Host: {WP}", "-b", cookie, "--data-urlencode", "log=wpowner", "--data-urlencode", f"pwd={pw}", "--data-urlencode", "wp-submit=Log In", "http://127.0.0.1/wp-login.php"], capture_output=True, text=True, timeout=30).stdout
    check("the admin can log in", login.startswith("302") and "wp-admin" in login, login[:80])
    wp = shutil.which("wp") or str(Path("/var/lib/aurora/wp-cli.phar"))
    print("wp-cli:", wp if os.path.exists(wp) else "not found")
    code, body = fetch(WP, "/hello-world/")
    print("pretty URL /hello-world/: HTTP", code)
    code, _ = fetch(WP, "/?s=<script>alert(1)</script>")
    if W.mode() == "block":
        check("the WAF guards it", code == "403", f"HTTP {code}")
    r = apps.uninstall(str(root), drop_db=True)
    check("it uninstalls, with its database", r["ok"] and r["db_dropped"], str(r)[:120])
    N.delete(WP, True)


def t_certificate_path_on_nginx() -> None:
    N.create({"server_name": ACME, "mode": "static", "https": "selfsigned", "force_https": True})
    root = Path(f"/var/www/{ACME}")
    challenge = root / ".well-known/acme-challenge"
    challenge.mkdir(parents=True)
    (challenge / "token123").write_text("proof")
    subprocess.run(["restorecon", "-R", str(root)], check=False)
    code, body = fetch(ACME, "/.well-known/acme-challenge/token123")
    check("Let's Encrypt's check gets through a site that forces HTTPS", code == "200" and body == "proof", f"HTTP {code}")
    check("while everything else is redirected", fetch(ACME)[0] == "301")
    N.delete(ACME, True)
    N.create({"server_name": ACME, "mode": "proxy", "proxy": "http://127.0.0.1:9"})
    challenge.mkdir(parents=True, exist_ok=True)
    (challenge / "token123").write_text("proof")
    subprocess.run(["restorecon", "-R", str(root)], check=False)
    code, body = fetch(ACME, "/.well-known/acme-challenge/token123")
    check("and through a reverse proxy site", code == "200" and body == "proof", f"HTTP {code}")
    N.delete(ACME)
    shutil.rmtree(root, ignore_errors=True)
    try:
        N.create({"server_name": "printer.local", "mode": "static"})
        N.letsencrypt("printer.local", "me@example.org")
        check("a private name is refused a certificate", False)
    except N.NginxError as exc:
        check("a private name is refused a certificate", True, str(exc))
    N.delete("printer.local", True)


def t_caddy_sites() -> None:
    if not C.installed():
        r = subprocess.run(["apt-get", "-y", "install", "caddy"], capture_output=True, text=True, timeout=300)
        print(r.stdout[-200:], r.stderr[-200:])
    was_nginx = N._active("nginx")
    print(sysapps.control("caddy", "start", True))
    time.sleep(2)
    check("switching port 80 to Caddy", C._active("caddy") and not N._active("nginx"))
    try:
        r = C.create({"server_name": CP})
        root = Path(f"/var/www/{CP}")
        check("create a PHP site on Caddy", r["ok"], str(r.get("answer")))
        check("it shows its starter page", "created by AuroraPanel" in fetch(CP)[1])
        (root / "index.html").unlink()
        (root / "index.php").write_text('<?php echo "php ".PHP_VERSION; file_put_contents(__DIR__."/w.txt","written"); echo " ".file_get_contents(__DIR__."/w.txt");')
        subprocess.run(["chown", "-R", "www-data:www-data", str(root)], check=False)
        code, body = fetch(CP)
        check("PHP runs on Caddy and can write", code == "200" and body.startswith("php ") and body.endswith("written"), f"HTTP {code}: {body[:70]}")
        (root / ".env").write_text("SECRET=1")
        code, body = fetch(CP, "/.env")
        check("dotfiles aren't served", code == "403" and "SECRET" not in body, f"HTTP {code}")

        C.create({"server_name": CS, "mode": "static"})
        check("a static site works", fetch(CS)[0] == "200" and CS in fetch(CS)[1])

        backend = subprocess.Popen([sys.executable, "-m", "http.server", "18766", "--bind", "127.0.0.1", "-d", str(root)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        C.create({"server_name": CX, "mode": "proxy", "proxy": "http://127.0.0.1:18766"})
        code, body = fetch(CX, "/w.txt")
        check("a reverse proxy site reaches its app", code == "200" and body == "written", f"HTTP {code}")
        backend.terminate()

        C.create({"server_name": CT, "mode": "static", "https": "internal"})
        time.sleep(1)
        code, body = fetch(CT, "/", "https")
        check("Caddy's own certificate serves HTTPS", code == "200" and CT in body, f"HTTP {code}")

        keep = C._conf(CS).read_text()
        try:
            C.update(CS, {"custom": "this_is_not_a_directive on"})
            check("a bad setting is refused", False)
        except C.CaddyError as exc:
            check("a bad setting is refused", True, str(exc).splitlines()[1][:110] if len(str(exc).splitlines()) > 1 else str(exc)[:110])
        check("and the site is unchanged and up", C._conf(CS).read_text() == keep and fetch(CS)[0] == "200" and C.validate()["ok"])

        C.set_enabled(CS, False)
        check("turning a site off stops it answering as itself", CS not in fetch(CS)[1])
        C.set_enabled(CS, True)
        check("turning it on brings it back", CS in fetch(CS)[1])

        log = C.logs(CP)
        check("each site has its own log", any('"status"' in x for x in log["lines"]), log["path"])
        listed = {s["server_name"]: s for s in C.status()["sites"]}
        check("the list shows real answers", listed[CS]["answer"] == "200", str({k: v["answer"] for k, v in listed.items()}))
        st = sysapps.status()
        check("System Applications shows Caddy running", any(a["id"] == "caddy" and a["active"] for a in st["apps"]))
    finally:
        for name in (CP, CS, CX, CT):
            try:
                C.delete(name, True)
            except C.CaddyError:
                pass
            shutil.rmtree(f"/var/www/{name}", ignore_errors=True)
        subprocess.run(f"rm -rf {N.TRASH}/*.caddy-test.example-*; rm -f /var/log/caddy/*.caddy-test.example-*.log", shell=True, check=False)
        if was_nginx:
            print(sysapps.control("nginx", "start", True))
            time.sleep(2)
    check("Nginx is back on port 80, and Caddy is stopped", N._active("nginx") and not C._active("caddy"))
    check("visitors reach Nginx sites again", fetch("x.example", "/test/")[0] == "200")


def main() -> int:
    if os.geteuid() != 0:
        sys.exit("Run as root.")
    for t in (t_certificate_path_on_nginx, t_wordpress_on_nginx, t_caddy_sites):
        print(f"\n=== {t.__name__}", flush=True)
        try:
            t()
        except (RuntimeError, OSError, KeyError, ValueError, IndexError, subprocess.TimeoutExpired) as exc:
            check(t.__name__, False, f"{type(exc).__name__}: {exc}")
    for name in (WP, ACME):
        try:
            N.delete(name, True)
        except N.NginxError:
            pass
        shutil.rmtree(f"/var/www/{name}", ignore_errors=True)
    avc = new_denials()
    check("no SELinux denials in this run, apart from the expected execmem", not avc, avc)
    bad = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad)} passed, {len(bad)} failed")
    for name, _, detail in bad:
        print(f"  FAILED {name}: {detail[:220]}")
    return 1 if bad else 0


if __name__ == "__main__":
    print(json.dumps({"mode": W.mode()}))
    sys.exit(main())
