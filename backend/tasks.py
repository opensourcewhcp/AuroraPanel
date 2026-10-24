"""The background task runner: `python -m backend.tasks run`, started every minute by a systemd timer.

It's separate from the panel process on purpose: alerts must still go out when the panel is down,
and a long backup or certificate request must not die when the panel restarts.

Every minute:  alerts check, due backup plans (each in its own transient unit)
Every 6 hours: refresh the list of available updates (apt-get update)
Once a day:    AutoSSL (03:10–04:10, so certificates renew while it's quiet)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

STATE = Path("/var/lib/aurora/tasks.json")
LOCK = Path("/run/aurora-tasks.lock")
UNIT = Path("/etc/systemd/system/aurora-tasks.service")
TIMER = Path("/etc/systemd/system/aurora-tasks.timer")


def _load() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def _save(s: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=1))


def _every(s: dict, key: str, seconds: int) -> bool:
    now = time.time()
    if now - s.get(key, 0) >= seconds:
        s[key] = now
        return True
    return False


def run() -> dict:
    import fcntl  # Linux only; imported here so the module loads anywhere
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCK, "w") as lk:
        try:
            fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return {"skipped": "already running"}
        s = _load()
        done = {}
        try:
            from . import schedules
            for pid in schedules.due():
                try:
                    schedules.start(pid)
                    done[f"backup:{pid}"] = "started"
                except Exception as e:
                    done[f"backup:{pid}"] = str(e)
        except Exception as e:
            done["backups"] = f"error: {e}"
        if _every(s, "updates", 6 * 3600):
            try:
                from . import updates
                updates.refresh()
                done["updates"] = "refreshed"
            except Exception as e:
                done["updates"] = f"error: {e}"
        if _every(s, "hosting", 3600):
            try:  # hosting accounts' disk and bandwidth, for their usage bars and over-limit alerts
                from . import hosting
                if hosting.load()["accounts"]:
                    hosting.measure()
                    done["hosting"] = "measured"
            except Exception as e:
                done["hosting"] = f"error: {e}"
        hour = datetime.now().hour
        if hour == 3 and _every(s, "autossl", 20 * 3600):
            try:
                from . import autossl
                if autossl.load()["enabled"]:
                    autossl.start(force=False)
                    done["autossl"] = "started"
            except Exception as e:
                done["autossl"] = f"error: {e}"
        try:
            from . import alerts
            done["alerts"] = alerts.check()
        except Exception as e:
            done["alerts"] = f"error: {e}"
        s["last_run"] = time.time()
        s["last"] = {k: v if isinstance(v, (str, int, float)) else json.dumps(v)[:200] for k, v in done.items()}
        _save(s)
        return done


def ensure_timer() -> bool:
    """Install/refresh the systemd units that start the runner. Called when the panel starts."""
    if not Path("/etc/systemd/system").is_dir() or os.geteuid() != 0:
        return False
    from . import config
    service = ("# Written by AuroraPanel: background tasks (alerts, scheduled backups, AutoSSL, update checks)\n"
               "[Unit]\nDescription=AuroraPanel background tasks\nAfter=network-online.target\n\n"
               f"[Service]\nType=oneshot\nWorkingDirectory={config.ROOT}\nExecStart={sys.executable} -m backend.tasks run\n"
               "Nice=5\nTimeoutStartSec=15min\n")
    timer = ("# Written by AuroraPanel\n[Unit]\nDescription=AuroraPanel background tasks, every minute\n\n"
             "[Timer]\nOnBootSec=90s\nOnUnitActiveSec=60s\nAccuracySec=10s\n\n[Install]\nWantedBy=timers.target\n")
    changed = False
    for p, text in ((UNIT, service), (TIMER, timer)):
        try:
            if p.read_text() == text:
                continue
        except OSError:
            pass
        p.write_text(text)
        changed = True
    env = {**os.environ, "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    if changed:
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, env=env, timeout=60)
    active = subprocess.run(["systemctl", "is-active", "aurora-tasks.timer"], capture_output=True, text=True, env=env, timeout=30).stdout.strip()
    if changed or active != "active":
        subprocess.run(["systemctl", "enable", "--now", "aurora-tasks.timer"], capture_output=True, env=env, timeout=60)
    return True


def status() -> dict:
    s = _load()
    env = {**os.environ, "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    active = subprocess.run(["systemctl", "is-active", "aurora-tasks.timer"], capture_output=True, text=True, env=env, timeout=30).stdout.strip()
    return {"timer": active, "last_run": s.get("last_run"), "last": s.get("last", {})}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        print(json.dumps(run(), default=str))
