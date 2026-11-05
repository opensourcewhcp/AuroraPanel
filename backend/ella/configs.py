"""Changing Apache's config safely: snapshot, atomic replace, syntax check, reload, health check, Watchdog.

Apache only reads its config when told to, so the candidate is put in place and checked with `httpd -t` before any
reload: a bad file is back out again before the running server ever sees it. The check has to happen in place
because it follows the same Include lines Apache does.

Standard library only: ella-cli uses this when the panel is down.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path

KEEP_SNAPSHOTS = 5
ABSENT = "ABSENT"
CONF_AVAILABLE = "/etc/apache2/conf-available"
MANAGED = re.compile(r"^(/etc/modsecurity/zz-(aurora-waf|ella[a-z0-9-]*)\.conf|/etc/apache2/conf-available/zz-(aurora-waf|ella[a-z0-9-]*)\.conf|/etc/nginx/aurora-waf/ella[a-z0-9-]*\.conf|/etc/nginx/conf\.d/aurora-ella-[a-z0-9-]+\.conf)$")
# What differs between the two web servers. Everything else about a change is the same.
SERVERS = {"apache": {"test": "apache_test", "reload": "apache_reload", "unit": "", "log": "/var/log/apache2/access.log"},
           "nginx": {"test": "nginx_test", "reload": "nginx_reload", "unit": "nginx", "log": "/var/log/nginx/access.log"}}
# Watchdog defaults: 5xx > 5 % over at least 20 requests, or three failed health checks in a row.
WATCH_SECONDS, WATCH_INTERVAL, MAX_5XX, MIN_REQUESTS, MAX_HEALTH_FAILS = 90, 5, 0.05, 20, 3
RELOAD_SETTLE = 0.6  # nginx -s reload returns before the new workers answer


class ConfigError(RuntimeError):
    pass


def health(host: str = "localhost", timeout: int = 5) -> tuple[bool, str]:
    """Is Apache answering on this machine? Any answer below 500 means yes (a WAF 403 is a working server)."""
    try:
        c = http.client.HTTPConnection("127.0.0.1", 80, timeout=timeout)
        c.request("GET", "/", headers={"Host": host, "User-Agent": "WAF Ella healthcheck"})
        status = c.getresponse().status
        c.close()
        return status < 500, f"HTTP {status}"
    except OSError as exc:
        return False, str(exc)


class ConfigManager:
    def __init__(self, adapter, snapshot_dir: Path | str, audit=None, access_log: str = "/var/log/apache2/access.log", on_critical=None):
        self.adapter = adapter
        self.dir = Path(snapshot_dir)
        self.audit = audit or (lambda *a, **k: None)
        self.access_log = access_log
        self.on_critical = on_critical or (lambda title, detail: None)
        self.lock = threading.Lock()

    @staticmethod
    def _check_target(path: str) -> Path:
        if not MANAGED.match(path or ""):
            raise ConfigError(f"WAF Ella doesn't manage {path!r}")
        return Path(path)

    # ------------------------------------------------------------- snapshots
    def _snap_dir(self, target: Path) -> Path:
        return self.dir / target.name

    def snapshots(self, path: str) -> list[dict]:
        target = self._check_target(path)
        out = []
        for f in sorted(self._snap_dir(target).glob("*.json"), reverse=True):
            try:
                out.append(json.loads(f.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return out

    def _snapshot(self, target: Path) -> dict:
        text = target.read_text(encoding="utf-8") if target.exists() else None
        digest = hashlib.sha256((text if text is not None else ABSENT).encode()).hexdigest()
        snap = {"path": str(target), "ts": time.time(), "sha256": digest, "content": text}
        d = self._snap_dir(target)
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{time.time_ns()}-{digest[:12]}.json").write_text(json.dumps(snap), encoding="utf-8")
        for old in sorted(d.glob("*.json"), reverse=True)[KEEP_SNAPSHOTS:]:
            old.unlink(missing_ok=True)
        return snap

    @staticmethod
    def _write_atomic(target: Path, text: str | None) -> None:
        if text is None:
            target.unlink(missing_ok=True)
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".ella-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            os.chmod(tmp, 0o644)
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def _enable(self, target: Path) -> None:
        """A zz-ella file must also be linked into conf-enabled, or Apache would never read it."""
        if str(target.parent) == CONF_AVAILABLE and target.name.startswith("zz-ella"):
            link = Path("/etc/apache2/conf-enabled") / target.name
            if not link.is_symlink():
                link.symlink_to(f"../conf-available/{target.name}")

    # ------------------------------------------------------------- the change itself
    def apply(self, path: str, text: str | None, actor: str, host: str = "localhost", watch_seconds: int | None = WATCH_SECONDS, watch_interval: int = WATCH_INTERVAL, server: str = "apache", reload: bool = True) -> dict:
        """Returns once the server runs the new file. The Watchdog then keeps an eye on it in the background.
        reload=False is for a server that isn't running: the file is still checked, and it reads it when it starts."""
        target = self._check_target(path)
        sv = SERVERS[server]
        with self.lock:
            snap = self._snapshot(target)
            self._write_atomic(target, text)
            self._enable(target)
            test = self.adapter.call(sv["test"])
            if not test["ok"]:
                self._write_atomic(target, snap["content"])
                self.audit(actor, "config.rejected", path, {"output": test["output"][-500:]})
                raise ConfigError(f"{'Apache' if server == 'apache' else 'Nginx'} rejected the file, the previous one is back:\n" + test["output"])
            if reload:
                reloaded = self.adapter.call(sv["reload"])
                if server == "nginx":
                    time.sleep(RELOAD_SETTLE)
                ok, detail = (reloaded["ok"], reloaded.get("error", "")) if reloaded["ok"] is False else self._alive(host, server)
                if not ok:
                    self._restore(target, snap, server)
                    self.audit(actor, "config.rolled_back", path, {"why": detail, "stage": "reload"})
                    raise ConfigError(f"{'Apache' if server == 'apache' else 'Nginx'} didn't come back after the reload ({detail}), the previous file is back")
        self.audit(actor, "config.applied", path, {"sha256": hashlib.sha256((text if text is not None else ABSENT).encode()).hexdigest(), "previous": snap["sha256"], "server": server, "reloaded": reload})
        if watch_seconds and reload:
            threading.Thread(target=self.watch, args=(path, snap, host, watch_seconds, watch_interval, server), daemon=True, name="ella-watchdog").start()
        return {"ok": True, "previous": snap["sha256"]}

    def _alive(self, host: str, server: str = "apache") -> tuple[bool, str]:
        unit = SERVERS[server]["unit"]
        st = self.adapter.call("service_active", {"unit": unit}) if unit else self.adapter.call("service_active")
        if not st.get("active"):
            return False, "the service isn't active"
        return health(host)

    def _restore(self, target: Path, snap: dict, server: str = "apache") -> None:
        self._write_atomic(target, snap["content"])
        self.adapter.call(SERVERS[server]["reload"])

    # ------------------------------------------------------------- Watchdog (Dead Man's Switch)
    def _log_size(self, log: str | None = None) -> int:
        try:
            return os.stat(log or self.access_log).st_size
        except OSError:
            return 0

    def _rate_5xx(self, start: int, log: str | None = None) -> tuple[int, int]:
        try:
            with open(log or self.access_log, "rb") as f:
                f.seek(start if start <= os.fstat(f.fileno()).st_size else 0)
                lines = f.read(8_000_000).split(b"\n")
        except OSError:
            return 0, 0
        total = bad = 0
        for ln in lines:
            m = re.search(rb'" (\d{3}) ', ln)
            if m and b"WAF Ella healthcheck" not in ln:
                total += 1
                bad += m.group(1).startswith(b"5")
        return total, bad

    def watch(self, path: str, snap: dict, host: str = "localhost", seconds: int = WATCH_SECONDS, interval: int = WATCH_INTERVAL, server: str = "apache") -> dict:
        """Watch the server after a change. On degradation put the previous file back and raise the alarm."""
        target = self._check_target(path)
        log = self.access_log if server == "apache" else SERVERS[server]["log"]
        start, fails, deadline = self._log_size(log), 0, time.time() + seconds
        why = ""
        while time.time() < deadline:
            time.sleep(interval)
            ok, detail = self._alive(host, server)
            fails = 0 if ok else fails + 1
            total, bad = self._rate_5xx(start, log)
            if fails >= MAX_HEALTH_FAILS:
                why = f"health check failed {fails} times ({detail})"
            elif total >= MIN_REQUESTS and bad / total > MAX_5XX:
                why = f"{bad} of {total} requests answered 5xx"
            if why:
                break
        if not why:
            return {"rolled_back": False}
        with self.lock:
            self._restore(target, snap, server)
        self.audit("watchdog", "config.rolled_back", path, {"why": why, "restored": snap["sha256"]})
        self.on_critical("WAF Ella rolled a config back", f"{path}: {why}")
        return {"rolled_back": True, "why": why}

    def rollback(self, path: str, actor: str) -> dict:
        """Back to the newest snapshot that differs from the current file."""
        target = self._check_target(path)
        current = target.read_text(encoding="utf-8") if target.exists() else None
        for snap in self.snapshots(path):
            if snap["content"] != current:
                with self.lock:
                    self._write_atomic(target, snap["content"])
                    test = self.adapter.call("apache_test")
                    if not test["ok"]:
                        self._write_atomic(target, current)
                        raise ConfigError("That snapshot doesn't pass Apache's check any more:\n" + test["output"])
                    self.adapter.call("apache_reload")
                self.audit(actor, "config.rollback", path, {"restored": snap["sha256"]})
                return {"ok": True, "restored": snap["sha256"], "from": snap["ts"]}
        raise ConfigError("There is no earlier version to go back to")
