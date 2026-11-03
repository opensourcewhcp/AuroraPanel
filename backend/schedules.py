"""Scheduled backups — automatic, encrypted, kept off this machine.

A plan says what to back up (websites, databases, mail, the panel's settings, extra folders),
when (hourly/daily/weekly/monthly at a set time), how many copies to keep, and where to send
them: another disk on this machine, or off-site through rclone (S3 and S3-compatible storage such
as Cloudflare R2/Wasabi/MinIO, Backblaze B2, SFTP, WebDAV/Nextcloud, or any rclone remote you
paste — e.g. Google Drive). Archives use the same format as the Backup Wizard, so any copy can be
brought back and restored there. Optional AES-256 encryption happens before anything leaves.

Runs are started by the task runner (systemd timer) as their own transient systemd unit, so a
long backup never blocks alerts and survives a panel restart.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

from . import backups
from . import problems

STATE = Path("/var/lib/aurora/backup-plans.json")
RCLONE_CONF = Path("/var/lib/aurora/rclone.conf")
KEYS = Path("/var/lib/aurora/backup-keys")
RUN_LOGS = Path("/var/lib/aurora/backup-runs")
LOCAL_BASE = backups.BACKUP_DIR / "scheduled"
PATH = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin"
FREQS = {"hourly": 3600, "daily": 86400, "weekly": 7 * 86400, "monthly": 30 * 86400}
DEST_TYPES = ("local", "s3", "b2", "sftp", "webdav", "rclone")
S3_PROVIDERS = {"AWS": "Amazon S3", "Cloudflare": "Cloudflare R2", "Wasabi": "Wasabi", "DigitalOcean": "DigitalOcean Spaces",
                "Minio": "MinIO", "Other": "Other S3-compatible"}


class ScheduleError(RuntimeError):
    pass


def _env() -> dict:
    return {**os.environ, "PATH": PATH}


def _run(argv, timeout=120, input=None):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input, env=_env())
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def load() -> dict:
    try:
        d = json.loads(STATE.read_text())
    except (OSError, ValueError):
        d = {}
    d.setdefault("plans", [])
    d.setdefault("destinations", [])
    return d


def _save(d: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_name(f".{STATE.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(d, indent=1))
    os.chmod(tmp, 0o600)
    tmp.replace(STATE)


def period(p: dict) -> int:
    return FREQS.get(p.get("freq", "daily"), 86400)


def next_run(p: dict, after: float | None = None) -> float:
    """Next start time after `after` (default: the last run, or now)."""
    now = datetime.fromtimestamp(after or time.time())
    hh, mm = (int(x) for x in (p.get("time") or "03:30").split(":"))
    f = p.get("freq", "daily")
    if f == "hourly":
        t = now.replace(minute=mm, second=0, microsecond=0)
        if t <= now:
            t += timedelta(hours=1)
    elif f == "weekly":
        t = now.replace(hour=hh, minute=mm, second=0, microsecond=0) + timedelta(days=(int(p.get("weekday", 0)) - now.weekday()) % 7)
        if t <= now:
            t += timedelta(days=7)
    elif f == "monthly":
        day = max(1, min(28, int(p.get("monthday", 1))))
        t = now.replace(day=day, hour=hh, minute=mm, second=0, microsecond=0)
        if t <= now:
            t = (t.replace(day=1) + timedelta(days=32)).replace(day=day)
    else:
        t = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if t <= now:
            t += timedelta(days=1)
    return t.timestamp()


# ------------------------------------------------------------------ destinations
def rclone_ok() -> bool:
    return shutil.which("rclone", path=PATH) is not None


def _remote(dest: dict) -> str:
    """'aur_<id>:bucket/prefix' for rclone, or a local folder."""
    if dest["type"] == "local":
        return dest["path"]
    base = dest.get("bucket", "").strip("/")
    pre = dest.get("prefix", "").strip("/")
    return f"aur_{dest['id']}:" + "/".join(x for x in (base, pre) if x)


def _rclone(*args, timeout=3600) -> subprocess.CompletedProcess:
    return _run(["rclone", "--config", str(RCLONE_CONF), "--retries", "3", "--low-level-retries", "5", *args], timeout)


def _write_remote(dest: dict, secret: dict) -> None:
    """Create/replace the [aur_<id>] section of our private rclone.conf."""
    name = f"aur_{dest['id']}"
    t = dest["type"]
    if t == "rclone":
        body = secret.get("conf", "")
        lines = [l for l in body.splitlines() if l.strip() and not l.strip().startswith(("[", "#", ";"))]
        if not any(l.split("=", 1)[0].strip() == "type" for l in lines):
            raise ScheduleError("Paste a whole rclone remote: the lines under [name], including “type = …”")
        section = "\n".join(lines)
    else:
        kv: dict[str, str] = {}
        if t == "s3":
            kv = {"type": "s3", "provider": dest.get("provider") or "Other", "access_key_id": secret.get("access_key", ""),
                  "secret_access_key": secret.get("secret_key", ""), "region": dest.get("region", ""), "endpoint": dest.get("endpoint", ""),
                  "acl": "private", "no_check_bucket": "true"}
        elif t == "b2":
            kv = {"type": "b2", "account": secret.get("access_key", ""), "key": secret.get("secret_key", ""), "hard_delete": "true"}
        elif t == "sftp":
            kv = {"type": "sftp", "host": dest.get("host", ""), "user": dest.get("user", ""), "port": str(dest.get("port") or 22),
                  "key_file": str(KEYS / "id_ed25519"), "shell_type": "unix", "md5sum_command": "none", "sha1sum_command": "none"}
            if secret.get("password"):
                r = _run(["rclone", "obscure", secret["password"]], 30)
                kv["pass"] = r.stdout.strip()
        elif t == "webdav":
            kv = {"type": "webdav", "url": dest.get("url", ""), "vendor": dest.get("vendor") or "other", "user": dest.get("user", "")}
            if secret.get("password"):
                kv["pass"] = _run(["rclone", "obscure", secret["password"]], 30).stdout.strip()
        section = "\n".join(f"{k} = {v}" for k, v in kv.items() if v != "")
    text = RCLONE_CONF.read_text() if RCLONE_CONF.exists() else ""
    text = re.sub(rf"(?ms)^\[{re.escape(name)}\]\n.*?(?=^\[|\Z)", "", text).rstrip("\n")
    RCLONE_CONF.parent.mkdir(parents=True, exist_ok=True)
    RCLONE_CONF.write_text((text + "\n\n" if text else "") + f"[{name}]\n{section}\n")
    os.chmod(RCLONE_CONF, 0o600)


def ssh_key() -> str:
    """The public key SFTP destinations log in with (made on first use)."""
    KEYS.mkdir(parents=True, exist_ok=True)
    os.chmod(KEYS, 0o700)
    k = KEYS / "id_ed25519"
    if not k.exists():
        _run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"aurorapanel-backup@{socket.gethostname()}", "-f", str(k)], 30)
    try:
        return (KEYS / "id_ed25519.pub").read_text().strip()
    except OSError:
        return ""


def save_destination(data: dict) -> dict:
    d = load()
    t = data.get("type")
    if t not in DEST_TYPES:
        raise ScheduleError("Unknown destination type")
    did = data.get("id") or secrets.token_hex(4)
    old = next((x for x in d["destinations"] if x["id"] == did), None)
    name = (data.get("name") or "").strip()[:60] or {"local": "Local disk", "s3": "S3", "b2": "Backblaze B2", "sftp": "SFTP server",
                                                      "webdav": "WebDAV", "rclone": "rclone remote"}[t]
    dest = {"id": did, "type": t, "name": name, "created": (old or {}).get("created", int(time.time()))}
    if t == "local":
        p = Path(str(data.get("path", "")).strip() or "/")
        if not p.is_absolute() or str(p) in ("/", "/etc", "/usr", "/var", "/root", "/home", "/proc", "/sys", "/dev", "/boot"):
            raise ScheduleError("Choose a folder for the backups, e.g. /mnt/usb/backups")
        dest["path"] = str(p)
    else:
        if not rclone_ok():
            raise ScheduleError("Off-site backups need rclone — install it first (one click on this page)")
        for k in ("bucket", "prefix", "region", "endpoint", "provider", "host", "user", "port", "url", "vendor"):
            if data.get(k) not in (None, ""):
                dest[k] = str(data[k]).strip()[:300]
        if t in ("s3", "b2") and not dest.get("bucket"):
            raise ScheduleError("Enter the bucket name")
        if t == "s3" and dest.get("provider", "Other") not in S3_PROVIDERS:
            dest["provider"] = "Other"
        if t == "sftp" and not (dest.get("host") and dest.get("user")):
            raise ScheduleError("SFTP needs a host and a user name")
        if t == "webdav" and not re.match(r"^https?://", dest.get("url", "")):
            raise ScheduleError("WebDAV needs the server URL (https://…)")
        if t in ("sftp", "webdav", "rclone") and data.get("path"):
            dest["prefix"] = str(data["path"]).strip().strip("/")[:300]
        secret = {k: str(data.get(k) or "") for k in ("access_key", "secret_key", "password", "conf")}
        if old and not any(secret.values()):
            pass  # editing names/paths only: keep the stored credentials
        else:
            if t in ("s3", "b2") and not (secret["access_key"] and secret["secret_key"]):
                raise ScheduleError("Enter the access key and the secret key")
            if t == "sftp":
                ssh_key()
            _write_remote(dest, secret)
    d["destinations"] = [x for x in d["destinations"] if x["id"] != did] + [dest]
    _save(d)
    return dest


def delete_destination(did: str) -> dict:
    d = load()
    if any(did in p.get("dests", []) for p in d["plans"]):
        raise ScheduleError("A backup plan still sends to this destination — change the plan first")
    d["destinations"] = [x for x in d["destinations"] if x["id"] != did]
    _save(d)
    if RCLONE_CONF.exists():
        RCLONE_CONF.write_text(re.sub(rf"(?ms)^\[aur_{re.escape(did)}\]\n.*?(?=^\[|\Z)", "", RCLONE_CONF.read_text()))
    return {"ok": True}


def test_destination(did: str) -> dict:
    dest = _dest(did)
    probe = f".aurora-test-{secrets.token_hex(3)}"
    t0 = time.time()
    if dest["type"] == "local":
        p = Path(dest["path"])
        try:
            p.mkdir(parents=True, exist_ok=True)
            (p / probe).write_text("ok")
            (p / probe).unlink()
        except OSError as e:
            raise ScheduleError(f"Can't write to {p}: {e}")
        free = shutil.disk_usage(p).free
        return {"ok": True, "message": f"Writable — {free / 1e9:.1f} GB free", "ms": int((time.time() - t0) * 1000)}
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("AuroraPanel connection test\n")
    try:
        r = _rclone("copyto", f.name, f"{_remote(dest)}/{probe}", timeout=120)
        if r.returncode != 0:
            raise ScheduleError(_clean_err(r.stderr))
        _rclone("deletefile", f"{_remote(dest)}/{probe}", timeout=60)
    finally:
        os.unlink(f.name)
    return {"ok": True, "message": "Connected — a test file was written and removed", "ms": int((time.time() - t0) * 1000)}


def _clean_err(s: str) -> str:
    lines = [re.sub(r"^\S+ \S+ (ERROR|NOTICE|Failed to \w+)\s*:?\s*", "", l) for l in s.splitlines() if "ERROR" in l or "Failed" in l or "error" in l.lower()]
    return ("; ".join(dict.fromkeys(lines)) or s.strip())[-400:] or "rclone failed"


def _dest(did: str) -> dict:
    for x in load()["destinations"]:
        if x["id"] == did:
            return x
    raise ScheduleError("Unknown destination")


# ------------------------------------------------------------------ plans
def save_plan(data: dict) -> dict:
    d = load()
    pid = data.get("id") or secrets.token_hex(4)
    old = next((x for x in d["plans"] if x["id"] == pid), {})
    name = (data.get("name") or "").strip()[:60] or "Server backup"
    what = data.get("what") or {}
    clean_what = {k: bool(what.get(k)) for k in ("sites", "databases", "mail", "panel", "home")}
    extra = []
    for p in what.get("paths") or []:
        p = str(p).strip()
        if not p:
            continue
        rp = Path(p)
        if not rp.is_absolute() or str(rp) == "/" or str(rp).startswith(("/proc", "/sys", "/dev", "/run")):
            raise ScheduleError(f"Can't back up {p}")
        extra.append(str(rp))
    clean_what["paths"] = extra[:30]
    if not any(clean_what[k] for k in ("sites", "databases", "mail", "panel", "home")) and not extra:
        raise ScheduleError("Choose at least one thing to back up")
    freq = data.get("freq", "daily")
    if freq not in FREQS:
        raise ScheduleError("Unknown schedule")
    tm = str(data.get("time") or "03:30")
    if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", tm):
        raise ScheduleError("Time must look like 03:30")
    dests = [x for x in data.get("dests") or [] if any(y["id"] == x for y in d["destinations"])]
    keep = max(1, min(365, int(data.get("keep", 7))))
    keep_local = max(0, min(30, int(data.get("keep_local", 1))))
    if not dests and not keep_local:
        raise ScheduleError("Send the backups somewhere: pick a destination or keep copies on this machine")
    plan = {**old, "id": pid, "name": name, "what": clean_what, "freq": freq, "time": tm, "weekday": int(data.get("weekday", 0)) % 7,
            "monthday": max(1, min(28, int(data.get("monthday", 1)))), "keep": keep, "keep_local": keep_local, "dests": dests,
            "enabled": bool(data.get("enabled", True)), "encrypt": bool(data.get("encrypt"))}
    if plan["encrypt"]:
        KEYS.mkdir(parents=True, exist_ok=True)
        os.chmod(KEYS, 0o700)
        kf = KEYS / f"plan-{pid}.pass"
        if data.get("passphrase"):
            if len(data["passphrase"]) < 12:
                raise ScheduleError("Use a passphrase of at least 12 characters")
            kf.write_text(data["passphrase"])
        elif not kf.exists():
            kf.write_text(secrets.token_urlsafe(24))
        os.chmod(kf, 0o600)
    plan.setdefault("history", [])
    plan["next"] = next_run(plan)
    d["plans"] = [x for x in d["plans"] if x["id"] != pid] + [plan]
    _save(d)
    return plan


def passphrase(pid: str) -> str:
    try:
        return (KEYS / f"plan-{pid}.pass").read_text().strip()
    except OSError:
        raise ScheduleError("This plan doesn't encrypt its backups")


def delete_plan(pid: str) -> dict:
    d = load()
    d["plans"] = [x for x in d["plans"] if x["id"] != pid]
    _save(d)
    return {"ok": True}


def _what_paths(what: dict) -> tuple[list[str], list[str], list[str]]:
    """(folders, mysql dbs, postgres dbs) for a plan."""
    paths: list[str] = []
    if what.get("sites"):
        try:
            from . import sites, sysapps
            roots = {s["docroot"] for s in sites.list_sites()["sites"] if s.get("docroot")}
            web = sysapps.web_root()
            if web:
                roots.add(web)
            paths += sorted(r for r in roots if Path(r).exists())
        except Exception:
            web = "/var/www"
            if Path(web).exists():
                paths.append(web)
    if what.get("home"):
        from . import files
        paths.append(str(files._default_user_home()))
    if what.get("mail"):
        paths += [p for p in ("/var/vmail", "/var/lib/aurora/mail", "/var/lib/rspamd/dkim", "/var/lib/radicale") if Path(p).exists()]
    if what.get("panel"):
        from . import config
        paths += [p for p in (str(config.CONFIG_PATH), "/var/lib/aurora", "/etc/apache2", "/etc/postfix", "/etc/dovecot", "/etc/bind",
                              "/var/lib/bind", "/etc/letsencrypt", "/etc/wireguard", "/etc/openvpn", "/etc/fail2ban", "/etc/modsecurity") if Path(p).exists()]
    paths += [p for p in what.get("paths", []) if Path(p).exists()]
    # drop folders inside others, and never the backups folder itself
    paths = sorted(set(paths))
    paths = [p for p in paths if not any(p != q and p.startswith(q.rstrip("/") + "/") for q in paths)]
    mysql = pgsql = []
    if what.get("databases"):
        mysql = backups._mysql_dbs() if backups._my_ok() else []
        pgsql = backups._pg_dbs() if backups._pg_ready() else []
    return paths, mysql, pgsql


def _log_line(f, text: str) -> None:
    f.write(f"{datetime.now():%H:%M:%S} {text}\n")
    f.flush()


def run(pid: str) -> dict:
    """Do one backup now (called inside its own systemd unit)."""
    d = load()
    plan = next((x for x in d["plans"] if x["id"] == pid), None)
    if not plan:
        raise ScheduleError("Unknown plan")
    RUN_LOGS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    logp = RUN_LOGS / f"{pid}-{stamp}.log"
    t0 = time.time()
    result = {"ts": int(t0), "ok": False, "log": logp.name, "dests": {}}
    work = None
    with open(logp, "w") as log:
        try:
            _log_line(log, f"Backup “{plan['name']}” started on {socket.gethostname()}")
            paths, mysql, pgsql = _what_paths(plan["what"])
            _log_line(log, f"Folders: {', '.join(paths) or '—'}")
            _log_line(log, f"Databases: {', '.join(['mysql:' + x for x in mysql] + ['pgsql:' + x for x in pgsql]) or '—'}")
            local_dir = LOCAL_BASE / pid
            local_dir.mkdir(parents=True, exist_ok=True)
            work = Path(tempfile.mkdtemp(prefix=".sched-", dir=backups.BACKUP_DIR))
            for engine, dbs in (("mysql", mysql), ("pgsql", pgsql)):
                for db in dbs:
                    (work / "databases" / engine).mkdir(parents=True, exist_ok=True)
                    with open(work / "databases" / engine / f"{db}.sql", "wb") as out, tempfile.TemporaryFile() as err:
                        rc = subprocess.run(backups._dump_argv(engine, db), stdout=out, stderr=err, env=_env()).returncode
                        if rc != 0:
                            err.seek(0)
                            raise ScheduleError(f"Couldn't dump {db}: {err.read().decode(errors='replace').strip()[-300:]}")
                    _log_line(log, f"Dumped {engine} database {db} ({(work / 'databases' / engine / f'{db}.sql').stat().st_size / 1e6:.1f} MB)")
            manifest = {"created": int(t0), "kind": "scheduled", "plan": plan["name"], "paths": paths, "mysql": mysql, "pgsql": pgsql,
                        "host": socket.gethostname(), "format": 1}
            (work / "manifest.json").write_text(json.dumps(manifest, indent=2))
            safe = re.sub(r"[^A-Za-z0-9._-]+", "-", plan["name"]).strip("-")[:40] or "backup"
            fname = f"{safe}-{socket.gethostname()}-{stamp}.tar.gz" + (".enc" if plan.get("encrypt") else "")
            out = local_dir / fname
            tar = ["tar", "-czf", "-", f"--exclude={str(backups.BACKUP_DIR).lstrip('/')}", "--exclude=var/lib/aurora/backup-runs",
                   "--warning=no-file-changed", "--ignore-failed-read", "-C", str(work), "manifest.json"]
            if mysql or pgsql:
                tar.append("databases")
            if paths:
                tar += ["-C", "/", *[p.lstrip("/") for p in paths]]
            _log_line(log, "Packing" + (" and encrypting (AES-256)…" if plan.get("encrypt") else "…"))
            with open(out, "wb") as fh, tempfile.TemporaryFile() as err:
                p1 = subprocess.Popen(tar, stdout=subprocess.PIPE, stderr=err, env=_env())
                if plan.get("encrypt"):
                    p2 = subprocess.Popen(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt",
                                           "-pass", f"file:{KEYS / f'plan-{pid}.pass'}"], stdin=p1.stdout, stdout=fh, stderr=err, env=_env())
                    p1.stdout.close()
                    rc2 = p2.wait()
                    rc1 = p1.wait()
                    if rc2 != 0:
                        err.seek(0)
                        raise ScheduleError("Encryption failed: " + err.read().decode(errors="replace")[-300:])
                else:
                    shutil.copyfileobj(p1.stdout, fh, 1 << 20)
                    rc1 = p1.wait()
                if rc1 not in (0, 1):
                    err.seek(0)
                    raise ScheduleError("tar failed: " + err.read().decode(errors="replace")[-400:])
            os.chmod(out, 0o600)  # holds configs and databases: owner-only, even when encrypted
            size = out.stat().st_size
            result["size"] = size
            result["file"] = fname
            _log_line(log, f"Archive ready: {fname} ({size / 1e6:.1f} MB)")
            failures = []
            for did in plan.get("dests", []):
                try:
                    dest = _dest(did)
                except ScheduleError:
                    continue
                td = time.time()
                try:
                    if dest["type"] == "local":
                        target = Path(dest["path"]) / pid
                        target.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(out, target / fname)
                    else:
                        r = _rclone("copyto", str(out), f"{_remote(dest)}/{pid}/{fname}", timeout=6 * 3600)
                        if r.returncode != 0:
                            raise ScheduleError(_clean_err(r.stderr))
                    pruned = _prune(dest, pid, plan["keep"])
                    result["dests"][did] = {"ok": True, "secs": int(time.time() - td), "pruned": pruned}
                    _log_line(log, f"✓ Sent to {dest['name']} in {time.time() - td:.0f}s" + (f", removed {pruned} old copies" if pruned else ""))
                except Exception as e:
                    result["dests"][did] = {"ok": False, "error": str(e)[:300]}
                    failures.append(f"{dest['name']}: {e}")
                    _log_line(log, f"✗ {dest['name']}: {e}")
            # keep only the newest keep_local archives on this machine
            locals_ = sorted(local_dir.glob("*.tar.gz*"), key=lambda p: p.stat().st_mtime, reverse=True)
            for old in locals_[plan.get("keep_local", 1):]:
                old.unlink(missing_ok=True)
            if failures:
                raise ScheduleError("Upload failed — " + "; ".join(failures))
            result["ok"] = True
            _log_line(log, f"Done in {time.time() - t0:.0f}s")
        except Exception as e:
            result["error"] = str(e)[:500]
            _log_line(log, f"FAILED: {e}")
        finally:
            if work:
                shutil.rmtree(work, ignore_errors=True)
    result["secs"] = int(time.time() - t0)
    d = load()
    for p in d["plans"]:
        if p["id"] == pid:
            p["last"] = result
            if result["ok"]:
                p["last_ok_ts"] = result["ts"]
            p["history"] = ([result] + p.get("history", []))[:30]
            p["next"] = next_run(p)
    _save(d)
    for old in sorted(RUN_LOGS.glob(f"{pid}-*.log"))[:-30]:
        old.unlink(missing_ok=True)
    try:
        from . import audit
        audit.record("system", "", f"scheduled backup ({plan['name']})", ok=result["ok"], status=200 if result["ok"] else 500,
                     detail={"size": result.get("size"), "error": result.get("error")})
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    return result


def _prune(dest: dict, pid: str, keep: int) -> int:
    names = [x["name"] for x in snapshots_at(dest, pid)]
    gone = 0
    for n in names[keep:]:
        if dest["type"] == "local":
            (Path(dest["path"]) / pid / n).unlink(missing_ok=True)
        else:
            _rclone("deletefile", f"{_remote(dest)}/{pid}/{n}", timeout=120)
        gone += 1
    return gone


def snapshots_at(dest: dict, pid: str) -> list[dict]:
    """Archives for plan pid at dest, newest first."""
    if dest["type"] == "local":
        p = Path(dest["path"]) / pid
        items = [{"name": f.name, "size": f.stat().st_size, "time": f.stat().st_mtime} for f in p.glob("*.tar.gz*")] if p.exists() else []
    else:
        r = _rclone("lsjson", f"{_remote(dest)}/{pid}", timeout=120)
        if r.returncode != 0:
            if "directory not found" in r.stderr.lower() or "not found" in r.stderr.lower():
                return []
            raise ScheduleError(_clean_err(r.stderr))
        items = []
        for x in json.loads(r.stdout or "[]"):
            if not x.get("IsDir") and re.search(r"\.tar\.gz(\.enc)?$", x["Name"]):
                try:
                    ts = datetime.fromisoformat(x["ModTime"].replace("Z", "+00:00")).timestamp()
                except (ValueError, KeyError):
                    ts = 0
                items.append({"name": x["Name"], "size": x.get("Size", 0), "time": ts})
    return sorted(items, key=lambda x: x["name"], reverse=True)


def snapshots(pid: str) -> dict:
    d = load()
    plan = next((x for x in d["plans"] if x["id"] == pid), None)
    if not plan:
        raise ScheduleError("Unknown plan")
    out = []
    local_dir = LOCAL_BASE / pid
    if local_dir.exists():
        for f in sorted(local_dir.glob("*.tar.gz*"), reverse=True):
            out.append({"where": "this machine", "dest": "", "name": f.name, "size": f.stat().st_size, "time": f.stat().st_mtime})
    errors = {}
    for did in plan.get("dests", []):
        try:
            dest = _dest(did)
            for s in snapshots_at(dest, pid):
                out.append({"where": dest["name"], "dest": did, **s})
        except Exception as e:
            errors[did] = str(e)[:200]
    return {"snapshots": out, "errors": errors}


def fetch(pid: str, dest: str, name: str) -> dict:
    """Bring one archive back into the Backups list (decrypted), ready for the restore wizard."""
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.tar\.gz(\.enc)?", name or ""):
        raise ScheduleError("Unknown archive")
    backups._ensure_dir()
    tmp = backups.BACKUP_DIR / f".fetch-{secrets.token_hex(4)}-{name}"
    try:
        if not dest:
            src = LOCAL_BASE / pid / name
            if not src.exists():
                raise ScheduleError("That copy is gone")
            shutil.copy2(src, tmp)
        else:
            dd = _dest(dest)
            if dd["type"] == "local":
                shutil.copy2(Path(dd["path"]) / pid / name, tmp)
            else:
                r = _rclone("copyto", f"{_remote(dd)}/{pid}/{name}", str(tmp), timeout=6 * 3600)
                if r.returncode != 0:
                    raise ScheduleError(_clean_err(r.stderr))
        final_name = name[:-4] if name.endswith(".enc") else name
        final = backups._unique(final_name)
        if name.endswith(".enc"):
            r = _run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-in", str(tmp), "-out", str(final),
                      "-pass", f"file:{KEYS / f'plan-{pid}.pass'}"], 3600)
            if r.returncode != 0:
                final.unlink(missing_ok=True)
                raise ScheduleError("Couldn't decrypt — wrong passphrase or damaged file")
        else:
            tmp.replace(final)
        os.chmod(final, 0o600)
        try:
            with __import__("tarfile").open(final) as tf:
                m = json.loads(tf.extractfile("manifest.json").read())
            backups._remember(final.name, {"kind": "wizard", "category": "full", "paths": m.get("paths", []), "mysql": m.get("mysql", []),
                                           "pgsql": m.get("pgsql", []), "created": m.get("created"), "host": m.get("host"), "wkind": "scheduled"})
        except Exception as quiet_exc:
            problems.quiet(quiet_exc)
        return {"ok": True, "name": final.name}
    finally:
        tmp.unlink(missing_ok=True)


def run_log(pid: str, name: str = "") -> dict:
    logs = sorted(RUN_LOGS.glob(f"{pid}-*.log"))
    if name:
        if not re.fullmatch(rf"{re.escape(pid)}-\d{{8}}-\d{{6}}\.log", name):
            raise ScheduleError("Unknown log")
        p = RUN_LOGS / name
    elif logs:
        p = logs[-1]
    else:
        return {"name": "", "text": "", "running": running(pid)}
    try:
        txt = p.read_text(errors="replace")[-20000:]
    except OSError:
        txt = ""
    return {"name": p.name, "text": txt, "running": running(pid)}


def running(pid: str) -> bool:
    return _run(["systemctl", "is-active", f"aurora-backup-{pid}"], 10).stdout.strip() in ("active", "activating")


def start(pid: str) -> dict:
    """Run a plan now in its own transient systemd unit."""
    if not any(p["id"] == pid for p in load()["plans"]):
        raise ScheduleError("Unknown plan")
    if running(pid):
        return {"ok": True, "already": True}
    from . import config
    r = _run(["systemd-run", f"--unit=aurora-backup-{pid}", "--collect", "--quiet", "--property=Nice=10",
              "--property=IOSchedulingClass=idle", f"--working-directory={config.ROOT}", sys.executable, "-m", "backend.schedules", "run", pid], 30)
    if r.returncode != 0:
        raise ScheduleError(r.stderr.strip()[-300:] or "couldn't start the backup")
    return {"ok": True}


def due() -> list[str]:
    """Plans whose time has come (called by the task runner every minute)."""
    now = time.time()
    out = []
    d = load()
    changed = False
    for p in d["plans"]:
        if not p.get("enabled"):
            continue
        if not p.get("next"):
            p["next"] = next_run(p)
            changed = True
        if p["next"] <= now:
            out.append(p["id"])
            p["next"] = next_run(p, now + 60)
            changed = True
    if changed:
        _save(d)
    return out


def listing() -> dict:
    d = load()
    plans = []
    for p in d["plans"]:
        q = {k: v for k, v in p.items() if k != "history"}
        q["history"] = p.get("history", [])[:10]
        q["running"] = running(p["id"])
        plans.append(q)
    return {"plans": plans, "destinations": d["destinations"], "rclone": rclone_ok(), "s3_providers": S3_PROVIDERS,
            "ssh_key": ssh_key() if any(x["type"] == "sftp" for x in d["destinations"]) else "",
            "local_dir": str(LOCAL_BASE), "free": shutil.disk_usage(str(backups.BACKUP_DIR if backups.BACKUP_DIR.exists() else "/")).free}


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "run":
        res = run(sys.argv[2])
        sys.exit(0 if res.get("ok") else 1)
