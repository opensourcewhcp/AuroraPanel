"""Rule Tester: a made-up request against the real rules, answered by an empty stand-in instead of any website.

A small listener on 127.0.0.1 has the same rules as the running web server and nothing behind it, so nothing reaches an
application. Its hits go to the audit log like any other (ModSecurity 3 can't give one server its own log). Each test request
carries a secret only this panel knows, which is how the collector leaves them out of Live Events: a visitor can't hide their
attack from Live Events by sending the same header.
"""
from __future__ import annotations

import http.client
import json
import re
import socket
import time
import uuid
from pathlib import Path

from . import collector
from .adapter import TESTER_ROOT
from .rulebook import RuleError

PORTS = (8009, 8008)  # already web ports in SELinux's policy, so no policy change is needed
NGINX_CONF = "/etc/nginx/conf.d/aurora-ella-tester.conf"
APACHE_CONF = "/etc/apache2/conf-available/zz-ella-tester.conf"
NGINX_LOG, APACHE_LOG = "/var/log/nginx/modsec_audit.log", "/var/log/apache2/modsec_audit.log"
STUB = Path(TESTER_ROOT)
MAX_BODY = 131072


def _free(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) != 0


def render(server: str, port: int) -> str:
    if server == "nginx":
        return (f"# Written by AuroraPanel (WAF Ella's Rule Tester). Only answers on this machine, and has nothing behind it.\n"
                f"server {{\n    listen 127.0.0.1:{port};\n    server_name _;\n    root {STUB.as_posix()};\n    access_log off;\n"
                f"    error_page 405 =200 /ok.txt;\n    location / {{ try_files /ok.txt =404; }}\n}}\n")
    return (f"# Written by AuroraPanel (WAF Ella's Rule Tester). Only answers on this machine, and has nothing behind it.\nListen 127.0.0.1:{port}\n"
            f"<VirtualHost 127.0.0.1:{port}>\n    ServerName ella-tester.invalid\n    DocumentRoot {STUB.as_posix()}\n    CustomLog /dev/null common\n"
            f"    FallbackResource /ok.txt\n    <Directory {STUB.as_posix()}>\n        Require local\n    </Directory>\n</VirtualHost>\n")


class Tester:
    def __init__(self, configs, servers):
        self.configs, self.servers = configs, servers

    def _server(self) -> dict | None:
        running = [s for s in self.servers() if s["active"]]
        return running[0] if running else None

    def _conf_path(self, name: str) -> Path:
        return Path(NGINX_CONF if name == "nginx" else APACHE_CONF)

    def status(self) -> dict:
        sv = self._server()
        if not sv:
            return {"available": False, "why": "No web server with a WAF is running here, so there are no live rules to test against."}
        path = self._conf_path(sv["name"])
        port = None
        if path.exists():
            m = re.search(r"127\.0\.0\.1:(\d+)", path.read_text(encoding="utf-8"))
            port = int(m.group(1)) if m else None
        return {"available": True, "server": sv["name"], "ready": port is not None, "port": port}

    def setup(self, actor: str) -> dict:
        sv = self._server()
        if not sv:
            raise RuleError("No web server with a WAF is running here, so there are no live rules to test against.")
        st = self.status()
        if st["ready"]:
            return st
        port = next((p for p in PORTS if _free(p)), None)
        if port is None:
            raise RuleError(f"Ports {PORTS[0]} and {PORTS[1]} are taken on this machine, so the tester can't run here.")
        STUB.mkdir(parents=True, exist_ok=True)
        (STUB / "ok.txt").write_text("ok\n", encoding="utf-8")
        STUB.parent.chmod(0o711)
        STUB.chmod(0o755)
        collector_file = STUB / "ok.txt"
        collector_file.chmod(0o644)
        self.configs.adapter.call("label_web_folder", {"path": STUB.as_posix()})
        self.configs.apply(str(self._conf_path(sv["name"])), render(sv["name"], port), actor, server=sv["name"], watch_seconds=None)
        return self.status()

    def run(self, method: str, url: str, headers: dict | None, body: str, host: str) -> dict:
        st = self.status()
        if not st["available"]:
            return st
        if not st["ready"]:
            raise RuleError("Set the tester up first.")
        if not re.fullmatch(r"[A-Z]{3,10}", method or ""):
            raise RuleError("Bad method")
        if not (url or "").startswith("/") or len(url) > 4000 or re.search(r"[\x00-\x20\x7f]", url):
            raise RuleError("URL must start with / and have no spaces (encode them as %20)")
        if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", host or ""):
            raise RuleError("Bad host name")
        if len(body or "") > MAX_BODY:
            raise RuleError("The body is too long for the tester")
        send = {}
        for k, v in (headers or {}).items():
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", str(k)) or re.search(r"[\r\n]", str(v)) or len(str(v)) > 4000:
                raise RuleError(f"Bad header: {str(k)[:40]}")
            send[str(k)] = str(v)
        marker = f"{collector.tester_key().decode()}-{uuid.uuid4().hex}"
        send.update({"Host": host, "X-Ella-Test": marker})
        send.setdefault("User-Agent", "WAF Ella Rule Tester")
        send.setdefault("Accept", "*/*")  # the rule set itself scores a request without one
        log = Path(NGINX_LOG if st["server"] == "nginx" else APACHE_LOG)
        start = log.stat().st_size if log.exists() else 0
        try:
            c = http.client.HTTPConnection("127.0.0.1", st["port"], timeout=15)
            c.request(method, url, body=(body or "").encode("utf-8") or None, headers=send)
            status = c.getresponse().status
            c.close()
        except OSError as exc:
            raise RuleError(f"The tester didn't answer: {exc}") from exc
        # Apache writes its audit record after the answer has gone out, so a blocked request's record may take a moment.
        hits = _read_hits(log, start, marker, st["server"])
        deadline = time.time() + (2 if status >= 400 else 0.4)
        while not hits["logged"] and time.time() < deadline:
            time.sleep(0.1)
            hits = _read_hits(log, start, marker, st["server"])
        return {"available": True, "server": st["server"], "status": status, "action": "blocked" if status in (403, 404, 405, 415, 429, 503) and hits["rules"] else "allowed", **hits}


def _read_hits(log: Path, start: int, marker: str, server: str) -> dict:
    """The audit record with our marker. ModSecurity writes it as the request ends, which is just before the answer here."""
    if not log.exists():
        return {"rules": [], "anomaly_score": None, "logged": False}
    with log.open("rb") as f:
        f.seek(start if start <= log.stat().st_size else 0)
        data = f.read(4_000_000)
    parser = collector.PARSERS["modsec3_audit" if server == "nginx" else "modsec_audit"]
    for raw in data.split(b"\n"):
        if marker.encode() not in raw:
            continue
        ev = parser.parse(raw, {"path": str(log), "inode": 0, "offset": 0})
        if ev and not ev.get("skip"):
            return {"rules": [{k: x.get(k) for k in ("rule_id", "msg", "severity", "matched_var_name", "matched_data")} for x in ev["evidence"]], "anomaly_score": ev["anomaly_score"], "logged": True}
        # The rule set's own summary lines are all that matched, or the rule hit carried no details.
        try:
            json.loads(raw)
        except ValueError:
            continue
        return {"rules": [], "anomaly_score": None, "logged": True}
    return {"rules": [], "anomaly_score": None, "logged": False}
