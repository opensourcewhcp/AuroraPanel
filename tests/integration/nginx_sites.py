#!/usr/bin/env python3
"""Nginx websites on a real server with Nginx running. Run as root from the panel folder:

    PYTHONPATH=. .venv/bin/python tests/integration/nginx_sites.py

Creates test sites under nginx-test.example and removes them, and asks the local server for them by Host header.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from backend import distro

os.environ["PATH"] = distro.PATH + ":" + os.environ["PATH"]
from backend import nginxsites as N  # noqa: E402

PHP, STATIC, PROXY, TLS = (f"{x}.nginx-test.example" for x in ("php", "static", "proxy", "tls"))
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"\n       {detail}" if detail else ""), flush=True)
    return ok


def curl(host: str, path: str = "/", scheme: str = "http") -> tuple[str, str]:
    r = subprocess.run(["curl", "-sk", "-m", "6", "-H", f"Host: {host}", "-w", "\n%{http_code}", f"{scheme}://127.0.0.1{path}"], capture_output=True, text=True, timeout=15)
    body, _, code = r.stdout.rpartition("\n")
    return code, body


def main() -> int:
    st = N.status()
    print({k: st.get(k) for k in ("installed", "active", "version", "php_socket", "default_site", "other_default", "apache_active")})
    if not st["active"]:
        sys.exit("Nginx isn't running.")
    backend = None
    try:
        # --- a PHP site, and PHP actually running
        r = N.create({"server_name": PHP, "aliases": [f"www.{PHP}"]})
        check("create a PHP site", r["ok"], str(r.get("answer")))
        root = Path(r["site"]["docroot"])
        check("the new site shows its starter page", "created by AuroraPanel" in curl(PHP)[1])
        (root / "index.html").unlink()
        (root / "index.php").write_text('<?php echo "php ".PHP_VERSION." route=".$_SERVER["REQUEST_URI"]; file_put_contents(__DIR__."/w.txt","written"); echo " ".file_get_contents(__DIR__."/w.txt");')
        subprocess.run(["chown", "-R", "www-data:www-data", str(root)], check=False)
        code, body = curl(PHP)
        check("PHP runs, and can write to its folder", code == "200" and body.startswith("php ") and body.endswith("written"), f"HTTP {code}: {body[:80]}")
        code, body = curl(PHP, "/pretty/url?x=1")
        check("pretty URLs reach index.php", code == "200" and "route=/pretty/url" in body, body[:80])
        check("the other name answers too", curl(f"www.{PHP}")[0] == "200")
        (root / ".env").write_text("SECRET=1")
        check("dotfiles aren't served", curl(PHP, "/.env")[0] == "403")
        (root / "up.jpg").write_text('<?php echo "RAN";')
        code, body = curl(PHP, "/up.jpg/x.php")
        check("a picture can't be run as PHP by a crafted address", "RAN" not in body, f"HTTP {code}")

        # --- static
        r = N.create({"server_name": STATIC, "mode": "static"})
        Path(r["site"]["docroot"], "note.php").write_text("<?php echo 1;")
        check("a static site works", curl(STATIC)[0] == "200")
        code, body = curl(STATIC, "/note.php")
        check("a static site doesn't run PHP", "<?php" in body or code in ("200", "404"), f"HTTP {code}")

        # --- reverse proxy to a real local server
        backend = subprocess.Popen([sys.executable, "-m", "http.server", "18765", "--bind", "127.0.0.1", "-d", str(root)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import time
        time.sleep(1)
        out = subprocess.run(["semanage", "port", "-l"], capture_output=True, text=True).stdout
        print("SELinux httpd_can_network_connect:", subprocess.run(["getsebool", "httpd_can_network_connect"], capture_output=True, text=True).stdout.strip(), "| ports known:", "http_port_t" in out)
        N.create({"server_name": PROXY, "mode": "proxy", "proxy": "http://127.0.0.1:18765"})
        code, body = curl(PROXY, "/up.jpg")
        check("a reverse proxy site reaches its app", code == "200" and "RAN" in body, f"HTTP {code}")

        # --- HTTPS
        N.create({"server_name": TLS, "mode": "static", "https": "selfsigned", "force_https": True})
        code, _ = curl(TLS)
        check("HTTP redirects to HTTPS", code == "301", f"HTTP {code}")
        code, body = curl(TLS, "/", "https")
        check("HTTPS answers with the self-signed certificate", code == "200" and "created by AuroraPanel" in body, f"HTTP {code}")

        # --- rejected change
        before = N._conf(STATIC).read_text()
        try:
            N.update(STATIC, {"custom": "this_is_not_a_directive on;"})
            check("a bad setting is refused", False)
        except N.NginxError as exc:
            check("a bad setting is refused", True, str(exc).splitlines()[-2][:120] if len(str(exc).splitlines()) > 1 else str(exc)[:120])
        check("and the site is unchanged and still up", N._conf(STATIC).read_text() == before and curl(STATIC)[0] == "200" and N.test_config()["ok"])

        # --- on and off
        N.set_enabled(STATIC, False)
        code, body = curl(STATIC)
        check("turning a site off stops it answering as itself", STATIC not in body, f"HTTP {code}")
        N.set_enabled(STATIC, True)
        check("turning it on brings it back", STATIC in curl(STATIC)[1])

        # --- default site: the folder site from /var/www/html
        N.ensure_default()
        probe = Path("/var/www/html/nginx-test-folder")
        probe.mkdir(exist_ok=True)
        (probe / "index.html").write_text("folder works")
        subprocess.run(["restorecon", "-R", str(probe)], check=False)
        code, body = curl("192.168.58.132", "/nginx-test-folder/")
        check("folders in /var/www/html show by IP address", code == "200" and "folder works" in body, f"HTTP {code}")
        shutil.rmtree(probe, ignore_errors=True)
        test_page = Path("/var/www/html/test/index.html")
        if test_page.exists():
            check("your own /test folder site shows again", curl("192.168.58.132", "/test/")[0] == "200")

        # --- logs and control
        got = N.logs(PHP, "access")
        check("each site has its own access log", any("/pretty/url" in x for x in got["lines"]), got["path"])
        check("reload works", N.control("reload")["active"])
        listed = {s["server_name"]: s for s in N.status()["sites"]}
        check("the list shows real answers", listed[STATIC]["answer"] == "200" and set(listed) >= {PHP, STATIC, PROXY, TLS}, str({k: v["answer"] for k, v in listed.items()}))
        check("no config errors at the end", N.test_config()["ok"])
        avc = subprocess.run("ausearch --input-logs -m avc -ts recent -i </dev/null 2>/dev/null | grep denied | grep -E 'nginx|httpd' | sed -E 's/.*avc: *denied *//;s/pid=[0-9]+ //;s/ino=[0-9]+ //' | cut -c1-170 | sort | uniq -c | head -5", shell=True, capture_output=True, text=True).stdout
        check("no SELinux denials for the web server", not avc.strip(), avc.strip())
    finally:
        if backend:
            backend.terminate()
        for name in (PHP, STATIC, PROXY, TLS):
            try:
                N.delete(name, True)
            except N.NginxError:
                pass
        for s in ("php", "static", "proxy", "tls"):
            shutil.rmtree(f"/var/www/{s}.nginx-test.example", ignore_errors=True)
        subprocess.run(f"rm -rf {N.TRASH}/*.nginx-test.example-*; rm -f {N.LOG_DIR}/*.nginx-test.example-*.log", shell=True, check=False)
        N.control("reload")
    bad = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad)} passed, {len(bad)} failed")
    for name, _, detail in bad:
        print(f"  FAILED {name}: {detail[:200]}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
