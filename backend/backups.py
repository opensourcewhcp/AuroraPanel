"""Backups: folder archives, single-database dumps and Backup Wizard archives.

Everything lives in BACKUP_DIR. Three kinds of file:
  * folder archive  <label>-<stamp>.tar.gz   (tar -C <parent> <folder>; restores into <parent>)
  * database dump   mysql-<db>-<stamp>.sql.gz / pgsql-<db>-<stamp>.sql.gz (also uploaded .sql/.sql.gz)
  * wizard archive  manifest.json + databases/ + folders stored with absolute paths

What we know about each file (category, original folder, databases inside) is kept in
BACKUP_DIR/.aurora-index.json so the list doesn't have to open big archives every time.
Create/restore/import run as background jobs that report a percentage, and any number can
run at once; one archive can't be restored twice at the same time or deleted while busy.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
from pathlib import Path

from . import jobs
from . import problems

BACKUP_DIR = Path(os.environ.get("AURORA_BACKUP_DIR", str(Path.home() / "aurora-backups"))).resolve()
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_DB = re.compile(r"^[A-Za-z0-9_$-]{1,64}$")
_SYSTEM_DBS = {"information_schema", "performance_schema", "mysql", "sys", "postgres", "template0", "template1"}
_EXTS = (".tar.gz", ".tgz", ".sql.gz", ".sql")
_CHUNK = 1 << 20
_lock = threading.Lock()


class BackupError(RuntimeError):
    pass


def _ensure_dir() -> None:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _safe_label(text: str, fallback: str = "backup") -> str:
    """Folder names can have spaces and brackets; archive names can't."""
    s = re.sub(r"-{2,}", "-", re.sub(r"[^A-Za-z0-9._-]+", "-", text or "")).strip("-.")
    return s[:80] or fallback


def _is_sql(name: str) -> bool:
    return name.endswith((".sql", ".sql.gz"))


# --------------------------------------------------------------------------- #
#  Index (what's inside each file)
# --------------------------------------------------------------------------- #
def _index_path() -> Path:
    return BACKUP_DIR / ".aurora-index.json"


def _load_index() -> dict:
    try:
        return json.loads(_index_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_index(idx: dict) -> None:
    tmp = _index_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(idx, indent=1), encoding="utf-8")
    os.replace(tmp, _index_path())


def _remember(name: str, info: dict) -> None:
    with _lock:
        idx = _load_index()
        idx[name] = {**idx.get(name, {}), **info}
        _save_index(idx)


def _guess_parent(top: str) -> str | None:
    """Where a folder archive made elsewhere (or before we kept notes) most likely came from."""
    from . import files
    for c in (str(files._default_user_home()), "/home", "/var/www", "/var/www/html", "/srv", "/opt", "/root", "/etc", "/usr/local"):
        try:
            if top and Path(c, top).exists():
                return c
        except OSError:  # e.g. /root when not running as root
            continue
    return None


def _sql_head(p: Path) -> str:
    try:
        opener = gzip.open if p.name.endswith(".gz") else open
        with opener(p, "rb") as fh:
            return fh.read(8192).decode("utf-8", errors="replace")
    except (OSError, EOFError):
        return ""


def _inspect(p: Path) -> dict:
    name = p.name
    if _is_sql(name):
        head = _sql_head(p)
        m = re.match(r"^(mysql|pgsql)-(.+)-\d{8}-\d{6}\.sql(\.gz)?$", name)
        engine = m.group(1) if m else ("pgsql" if "PostgreSQL database dump" in head else
                                       "mysql" if re.search(r"(MariaDB|MySQL) dump", head) else None)
        db, guessed = (m.group(2) if m else None), False
        if not db:
            h = re.search(r"Database:\s*([A-Za-z0-9_$-]+)", head)
            if h:
                db = h.group(1)
            else:  # an uploaded dump that doesn't say: suggest a name from the file
                db = re.sub(r"_+", "_", re.sub(r"[^a-z0-9_]", "_", re.sub(r"\.sql(\.gz)?$", "", name).lower())).strip("_")[:64] or "imported"
                guessed = True
        return {"kind": "sql", "category": "databases", "engine": engine, "db": db, "db_guessed": guessed}
    try:
        with tarfile.open(p, "r|gz") as tf:
            first = tf.next()
            if first is not None and first.name == "manifest.json" and first.isfile():
                man = json.loads(tf.extractfile(first).read().decode("utf-8"))
                paths, my, pg = man.get("paths", []), man.get("mysql", []), man.get("pgsql", [])
                cat = "full" if man.get("kind") == "full" else ("mixed" if paths and (my or pg) else "databases" if (my or pg) else "files")
                return {"kind": "wizard", "category": cat, "paths": paths, "mysql": my, "pgsql": pg,
                        "created": man.get("created"), "host": man.get("host"), "wkind": man.get("kind")}
            top = first.name.lstrip("./").split("/")[0] if first is not None else ""
    except (OSError, tarfile.TarError, ValueError, EOFError) as exc:
        return {"kind": "unknown", "category": "files", "error": f"Can't read this archive: {exc}"}
    parent = _guess_parent(top)
    return {"kind": "plain", "category": "files", "top": top, "parent": parent, "guessed": True}


def _info(p: Path, idx: dict) -> dict:
    st = p.stat()
    key = f"{st.st_size}:{int(st.st_mtime)}"
    entry = idx.get(p.name) or {}
    if entry.get("key") != key or "kind" not in entry:
        known = {k: v for k, v in entry.items() if k in ("parent", "source", "engine", "db") and v}
        entry = {**_inspect(p), **known, "key": key}
        if known.get("parent"):
            entry["guessed"] = False
        idx[p.name] = entry
    return entry


def _files() -> list[Path]:
    _ensure_dir()
    return [f for f in BACKUP_DIR.iterdir() if f.is_file() and not f.name.startswith(".") and f.name.endswith(_EXTS)]


def _mysql_dbs() -> list[str]:
    if not shutil.which("mysql"):
        return []
    r = subprocess.run(["mysql", "-N", "-B", "-e", "SHOW DATABASES"], capture_output=True, text=True, timeout=30)
    return [d for d in r.stdout.split() if d not in _SYSTEM_DBS] if r.returncode == 0 else []


def _pg_ready() -> bool:
    from . import databases
    return databases.pg_available()


def _pg_dbs() -> list[str]:
    if not _pg_ready():
        return []
    r = subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-At", "-c",
                        "SELECT datname FROM pg_database WHERE NOT datistemplate"], capture_output=True, text=True, timeout=30)
    return [d for d in r.stdout.split() if d not in _SYSTEM_DBS] if r.returncode == 0 else []


def _my_ok() -> bool:
    from . import databases
    try:
        return databases.mysql_available()
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return False


def list_backups() -> dict:
    items = []
    with _lock:
        idx = _load_index()
        files = sorted(_files(), key=lambda p: p.stat().st_mtime, reverse=True)
        for f in files:
            st = f.stat()
            info = {k: v for k, v in _info(f, idx).items() if k != "key"}
            items.append({"name": f.name, "size": st.st_size, "modified": st.st_mtime, **info})
        names = {f.name for f in files}
        for gone in [n for n in idx if n not in names]:
            del idx[gone]
        try:
            _save_index(idx)
        except OSError:
            pass
    my_ok, pg_ok = _my_ok(), _pg_ready()
    from . import files as fm
    return {"dir": str(BACKUP_DIR), "backups": items, "home": str(fm._default_user_home()),
            "databases": {"mysql": _mysql_dbs() if my_ok else [], "pgsql": _pg_dbs() if pg_ok else [],
                          "mysql_ok": my_ok, "pgsql_ok": pg_ok}}


# --------------------------------------------------------------------------- #
#  Busy tracking
# --------------------------------------------------------------------------- #
def _busy(name: str) -> jobs.Job | None:
    for j in jobs.find(area="backups", archive=name):
        if j.status == "running":
            return j
    return None


def _launch(title: str, op: str, name: str, fn, extra: dict | None = None) -> jobs.Job:
    """Start a job for one archive, refusing while another job is using it."""
    with _lock:
        j = _busy(name)
        if j:
            what = {"restore": "being restored", "create": "being created", "import": "being imported"}.get(j.meta.get("op"), "busy")
            raise BackupError(f"{name} is already {what} — wait for that to finish")
        return jobs.launch_fn(title, fn, meta={"area": "backups", "op": op, "archive": name, **(extra or {})})


def backup_jobs() -> dict:
    """Running jobs plus the ones that finished in the last hour, for the progress bars."""
    now = time.time()
    out = []
    for j in jobs.find(area="backups"):
        if j.status == "running" or (j.finished and now - j.finished < 3600):
            d = j.to_dict(tail=6)
            d.pop("result", None)
            out.append(d)
    return {"jobs": out, "now": now}


# --------------------------------------------------------------------------- #
#  Streaming helpers (they are what moves the progress bar)
# --------------------------------------------------------------------------- #
def _feed(argv: list[str], src: Path, log, lo: float, hi: float, stage: str, gunzip: bool = False) -> tuple[int, str]:
    """Pipe a file into a command's stdin; the bar follows the bytes read from disk."""
    total = max(1, src.stat().st_size)
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=err)
        try:
            with open(src, "rb") as raw:
                reader = gzip.GzipFile(fileobj=raw) if gunzip else raw
                last = 0.0
                while True:
                    chunk = reader.read(_CHUNK)
                    if not chunk:
                        break
                    proc.stdin.write(chunk)
                    now = time.monotonic()
                    if now - last > 0.3:
                        log.progress(lo + (hi - lo) * raw.tell() / total, stage)
                        last = now
            proc.stdin.close()
        except BrokenPipeError:
            pass
        except (OSError, EOFError) as exc:
            proc.kill()
            proc.wait()
            raise BackupError(f"Reading {src.name} failed: {exc}")
        rc = proc.wait()
        err.seek(0)
        msg = err.read().decode("utf-8", errors="replace").strip()
    log.progress(hi, stage)
    return rc, msg


def _drain(argv: list[str], out: Path, log, lo: float, hi: float, stage: str, estimate: int) -> tuple[int, str]:
    """Run a command and gzip its stdout into `out`; the bar follows bytes against an estimate."""
    total = max(1, estimate)
    done = 0
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=err)
        try:
            with gzip.open(out, "wb", compresslevel=6) as gz:
                last = 0.0
                while True:
                    chunk = proc.stdout.read(_CHUNK)
                    if not chunk:
                        break
                    gz.write(chunk)
                    done += len(chunk)
                    now = time.monotonic()
                    if now - last > 0.3:
                        # Estimates are rough: never claim to be finished before the end.
                        log.progress(lo + (hi - lo) * min(done / total, 0.97), stage)
                        last = now
        except OSError as exc:
            proc.kill()
            proc.wait()
            raise BackupError(f"Writing {out.name} failed: {exc}")
        rc = proc.wait()
        err.seek(0)
        msg = err.read().decode("utf-8", errors="replace").strip()
    log.progress(hi, stage)
    return rc, msg


def _du(paths: list[str]) -> int:
    try:
        r = subprocess.run(["du", "-sbc", *paths], capture_output=True, text=True, timeout=900)
        last = r.stdout.strip().splitlines()[-1]
        return int(last.split()[0])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return 0


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def _finish(tmp: Path, final: Path, info: dict, log) -> dict:
    os.replace(tmp, final)
    _remember(final.name, info)
    log(f"✔ {final.name} ({_human(final.stat().st_size)})")
    return {"name": final.name}


def _unique(name: str) -> Path:
    p = BACKUP_DIR / name
    n = 2
    while p.exists():
        stem, ext = (name[:-7], ".tar.gz") if name.endswith(".tar.gz") else (name[:-7], ".sql.gz") if name.endswith(".sql.gz") else os.path.splitext(name)
        p = BACKUP_DIR / f"{stem}-{n}{ext}"
        n += 1
    return p


# --------------------------------------------------------------------------- #
#  Folder backups
# --------------------------------------------------------------------------- #
def create_backup(source: str, label: str = "") -> jobs.Job:
    src = Path(source or "").expanduser()
    if not src.is_absolute():
        raise BackupError("Source path must be absolute")
    src = src.resolve()
    if not src.exists():
        raise BackupError("Source path does not exist")
    if str(src) == "/" or str(src).startswith(("/proc", "/sys", "/dev", "/run")):
        raise BackupError(f"Can't back up {src}")
    if src == BACKUP_DIR or BACKUP_DIR in src.parents:
        raise BackupError("That's the backups folder itself")
    if label and not _NAME_RE.match(label):
        raise BackupError("Label may only contain letters, digits, dot, dash, underscore")
    _ensure_dir()
    final = _unique(f"{label or _safe_label(src.name, 'root')}-{_stamp()}.tar.gz")
    tmp = BACKUP_DIR / f".partial-{final.name}"
    parent, base = str(src.parent), src.name
    # Backing up a folder that holds the backups: leave the archives out.
    excludes = [f"--exclude={BACKUP_DIR.relative_to(src.parent)}"] if src in BACKUP_DIR.parents else []

    def fn(log):
        log.progress(None, "Measuring the folder…")
        log(f"• Measuring {src}…")
        total = _du([str(src)])
        if total:
            log(f"• {_human(total)} to pack")
        log.progress(0, "Packing")
        try:
            rc, err = _drain(["tar", "-cf", "-", "--warning=no-file-changed", *excludes, "-C", parent, base],
                             tmp, log, 0, 100, "Packing", total)
            if rc not in (0, 1):  # 1 = some files changed while being read
                raise BackupError("tar: " + err[-400:])
            return _finish(tmp, final, {"kind": "plain", "category": "files", "top": base, "parent": parent,
                                        "source": str(src), "guessed": False}, log)
        finally:
            tmp.unlink(missing_ok=True)
    return _launch(f"Back up {src}", "create", final.name, fn, {"source": str(src)})


def _archive_path(name: str) -> Path:
    if not name or "/" in name or "\\" in name or "\0" in name or name.startswith(".") or not name.endswith(_EXTS):
        raise BackupError("Invalid backup name")
    p = (BACKUP_DIR / name).resolve()
    if p.parent != BACKUP_DIR:
        raise BackupError("Invalid backup path")
    if not p.is_file():
        raise BackupError("Backup not found")
    return p


def _info_for(name: str) -> dict:
    p = _archive_path(name)
    with _lock:
        idx = _load_index()
        info = _info(p, idx)
        try:
            _save_index(idx)
        except OSError:
            pass
    return info


def restore_backup(name: str, dest: str | None = None) -> jobs.Job:
    archive = _archive_path(name)
    info = _info_for(name)
    if info["kind"] == "wizard":
        raise BackupError("This archive was made by the Backup Wizard — pick what to restore from it instead")
    if info["kind"] == "sql":
        raise BackupError("This is a database dump — restore it into a database instead")
    dest = (dest or info.get("parent") or "").strip()
    if not dest:
        raise BackupError("Pick the folder to restore into")
    destp = Path(dest).resolve()
    if not destp.is_dir():
        raise BackupError(f"{destp} is not a folder")
    where = destp / info["top"] if info.get("top") else destp

    def fn(log):
        log(f"• Restoring into {where} (files in the backup replace the ones there)…")
        rc, err = _feed(["tar", "-xzf", "-", "-C", str(destp)], archive, log, 0, 100, "Unpacking")
        if rc != 0:
            raise BackupError("tar: " + err[-400:])
        log(f"✔ Restored to {where}")
        return {"ok": True, "where": str(where)}
    return _launch(f"Restore {name}", "restore", name, fn, {"dest": str(where)})


def delete_backup(name: str) -> dict:
    archive = _archive_path(name)
    if _busy(name):
        raise BackupError("That backup is in use right now — wait for the job to finish")
    archive.unlink()
    with _lock:
        idx = _load_index()
        if idx.pop(name, None) is not None:
            _save_index(idx)
    return {"ok": True, "deleted": name}


def resolve_for_download(name: str) -> Path:
    return _archive_path(name)


# --------------------------------------------------------------------------- #
#  Databases: one-database dumps, restore / import into any database
# --------------------------------------------------------------------------- #
def _pg_check():
    from . import databases
    try:
        databases.pg_require()
    except databases.DatabaseError as exc:
        raise BackupError(str(exc))


def _my_check():
    from . import databases
    try:
        databases.mysql_require()
    except databases.DatabaseError as exc:
        raise BackupError(str(exc))


def _check_engine(engine: str):
    if engine == "mysql":
        _my_check()
    elif engine == "pgsql":
        _pg_check()
    else:
        raise BackupError("Pick MariaDB/MySQL or PostgreSQL")


def _db_size(engine: str, db: str) -> int:
    try:
        if engine == "mysql":
            r = subprocess.run(["mysql", "-N", "-B", "-e",
                                f"SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = '{db}'"],
                               capture_output=True, text=True, timeout=60)
        else:
            r = subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-At", "-c", f"SELECT pg_database_size('{db}')"],
                               capture_output=True, text=True, timeout=60)
        return int(float(r.stdout.strip() or 0))
    except (OSError, subprocess.SubprocessError, ValueError):
        return 0


def _dump_argv(engine: str, db: str) -> list[str]:
    if engine == "mysql":
        return ["mysqldump", "--single-transaction", "--routines", "--events", "--triggers", db]
    return ["runuser", "-u", "postgres", "--", "pg_dump", "--no-owner", db]


def backup_database(engine: str, db: str, label: str = "") -> jobs.Job:
    if not _DB.match(db or "") or db in _SYSTEM_DBS:
        raise BackupError("Pick a database")
    _check_engine(engine)
    if db not in (_mysql_dbs() if engine == "mysql" else _pg_dbs()):
        raise BackupError(f"No database called {db}")
    if label and not _NAME_RE.match(label):
        raise BackupError("Label may only contain letters, digits, dot, dash, underscore")
    _ensure_dir()
    final = _unique(f"{engine}-{db}-{_stamp()}.sql.gz" if not label else f"{engine}-{db}-{label}-{_stamp()}.sql.gz")
    tmp = BACKUP_DIR / f".partial-{final.name}"
    pretty = "MariaDB" if engine == "mysql" else "PostgreSQL"

    def fn(log):
        log(f"• Dumping {pretty} database {db}…")
        est = _db_size(engine, db)
        try:
            rc, err = _drain(_dump_argv(engine, db), tmp, log, 0, 100, "Dumping", est)
            if rc != 0:
                raise BackupError(f"{'mysqldump' if engine == 'mysql' else 'pg_dump'} {db}: {err[-300:]}")
            return _finish(tmp, final, {"kind": "sql", "category": "databases", "engine": engine, "db": db}, log)
        finally:
            tmp.unlink(missing_ok=True)
    return _launch(f"Back up {pretty} database {db}", "create", final.name, fn, {"engine": engine, "db": db})


def _pg_owner(db: str) -> str:
    r = subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-At", "-c",
                        f"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '{db}'"],
                       capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def _prepare_db(engine: str, db: str, wipe: bool, log) -> None:
    """Make sure the target database exists (emptied first when wipe is set)."""
    if engine == "mysql":
        sql = (f"DROP DATABASE IF EXISTS `{db}`; " if wipe else "") + f"CREATE DATABASE IF NOT EXISTS `{db}`"
        if wipe:
            log(f"• Emptying {db} (user permissions on it are kept)…")
        r = subprocess.run(["mysql", "-e", sql], capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            raise BackupError(f"mysql: {r.stderr.strip()[-300:]}")
        return
    owner = _pg_owner(db)
    if owner and wipe:
        log(f"• Emptying {db} (owner {owner} is kept)…")
        r = subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-q", "-c", f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)'],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            raise BackupError(f"psql: {r.stderr.strip()[-300:]}")
    if not owner or wipe:
        r = subprocess.run(["runuser", "-u", "postgres", "--", "createdb", *(["-O", owner] if owner else []), db],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise BackupError(f"createdb {db}: {r.stderr.strip()[-300:]}")


def _import(engine: str, db: str, src: Path, gunzip: bool, log, lo: float, hi: float) -> None:
    pretty = "MariaDB" if engine == "mysql" else "PostgreSQL"
    log(f"• Importing into {pretty} database {db}…")
    if engine == "mysql":
        rc, err = _feed(["mysql", db], src, log, lo, hi, f"Importing into {db}", gunzip=gunzip)
        if rc != 0:
            raise BackupError(f"mysql {db}: {err[-300:]}")
        return
    rc, err = _feed(["runuser", "-u", "postgres", "--", "psql", "-q", "-v", "ON_ERROR_STOP=0", "-d", db],
                    src, log, lo, hi, f"Importing into {db}", gunzip=gunzip)
    if rc != 0:
        raise BackupError(f"psql {db}: {err[-300:]}")
    errors = [line for line in err.splitlines() if "ERROR:" in line]
    if errors:
        log(f"⚠ PostgreSQL reported {len(errors)} error(s), e.g. {errors[0][-200:]}")


def _target(db: str) -> str:
    db = (db or "").strip()
    if not _DB.match(db):
        raise BackupError("Database names may use letters, digits, _ $ - (up to 64)")
    if db in _SYSTEM_DBS:
        raise BackupError(f"{db} is a system database")
    return db


def restore_database(name: str, target: str = "", engine: str = "", wipe: bool = True) -> jobs.Job:
    """Restore a .sql / .sql.gz dump into `target` (its own database when empty, created if missing)."""
    src = _archive_path(name)
    info = _info_for(name)
    if info["kind"] != "sql":
        raise BackupError("That isn't a database dump")
    engine = engine or info.get("engine") or ""
    _check_engine(engine)
    db = _target(target or info.get("db") or "")

    def fn(log):
        _prepare_db(engine, db, wipe, log)
        _import(engine, db, src, name.endswith(".gz"), log, 0, 100)
        log(f"✔ {db} restored from {name}")
        return {"ok": True, "db": db}
    if engine == "mysql":
        _remember(name, {"engine": engine})
    return _launch(f"Restore {name} → {db}", "restore", name, fn, {"db": db, "engine": engine, "dest": db})


# --------------------------------------------------------------------------- #
#  Uploads (.sql, .sql.gz, .tar.gz made elsewhere)
# --------------------------------------------------------------------------- #
def upload_target(filename: str) -> tuple[Path, Path]:
    base = os.path.basename((filename or "").replace("\\", "/"))
    low = base.lower()
    ext = next((e for e in (".tar.gz", ".tgz", ".sql.gz", ".sql") if low.endswith(e)), None)
    if not ext:
        raise BackupError("Upload a .sql, .sql.gz or .tar.gz file")
    _ensure_dir()
    final = _unique(_safe_label(base[: -len(ext)], "upload") + ext)
    return BACKUP_DIR / f".partial-{final.name}", final


def finish_upload(tmp: Path, final: Path) -> dict:
    try:
        with open(tmp, "rb") as fh:
            magic = fh.read(2)
        if final.name.endswith((".gz", ".tgz")) and magic != b"\x1f\x8b":
            raise BackupError("That file isn't gzip-compressed — is the extension right?")
        os.replace(tmp, final)
    finally:
        tmp.unlink(missing_ok=True)
    info = _info_for(final.name)
    return {"name": final.name, "size": final.stat().st_size, **{k: v for k, v in info.items() if k != "key"}}


# ======================================================================
#  Backup Wizard: one archive = files (stored with absolute paths) +
#  database dumps + manifest.json, so a restore can pick what to bring back.
# ======================================================================
def wizard_options() -> dict:
    from . import files, sysapps
    home = str(files._default_user_home())
    web = sysapps.web_root()
    return {"home": home, "web_root": web, "mysql": _mysql_dbs(), "pgsql": _pg_dbs(), "dir": str(BACKUP_DIR),
            "configs": [p for p in ("/etc/apache2", "/etc/nginx", "/etc/php", "/etc/mysql", "/etc/openvpn", "/etc/wireguard",
                                    "/etc/swanctl", "/etc/vsftpd.conf", "/etc/fail2ban", "/var/lib/aurora") if Path(p).exists()]}


def wizard_create(kind: str, paths: list[str] | None = None, mysql: list[str] | None = None, pgsql: list[str] | None = None,
                  label: str = "") -> jobs.Job:
    """kind: full | files | databases | custom."""
    opts = wizard_options()
    if kind == "full":
        paths = [p for p in (opts["home"], opts["web_root"]) if p] + opts["configs"]
        mysql, pgsql = opts["mysql"], opts["pgsql"]
    paths = [str(Path(p).resolve()) for p in (paths or []) if p]
    for p in paths:
        if not Path(p).is_absolute() or not Path(p).exists():
            raise BackupError(f"Not found: {p}")
        if p == "/" or p.startswith(("/proc", "/sys", "/dev", "/run")):
            raise BackupError(f"Can't back up {p}")
    mysql = [d for d in (mysql or []) if _DB.match(d)]
    pgsql = [d for d in (pgsql or []) if _DB.match(d)]
    if not paths and not mysql and not pgsql:
        raise BackupError("Pick at least one folder or database")
    if mysql:
        _my_check()
    if pgsql:
        _pg_check()
    if label and not _NAME_RE.match(label):
        raise BackupError("Label may only contain letters, digits, dot, dash, underscore")
    _ensure_dir()
    final = _unique(f"{label or 'aurora-' + kind}-{_stamp()}.tar.gz")
    tmp = BACKUP_DIR / f".partial-{final.name}"
    # Never back the backups folder up into itself.
    excludes = [f"--exclude={str(BACKUP_DIR).lstrip('/')}"]
    cat = "full" if kind == "full" else ("mixed" if paths and (mysql or pgsql) else "databases" if (mysql or pgsql) else "files")

    def fn(log):
        work = Path(tempfile.mkdtemp(prefix=".wiz-", dir=BACKUP_DIR))
        try:
            dbs = [("mysql", d) for d in mysql] + [("pgsql", d) for d in pgsql]
            db_share = 30.0 if dbs and paths else 100.0 if dbs else 0.0
            for i, (engine, db) in enumerate(dbs):
                lo, hi = db_share * i / len(dbs), db_share * (i + 1) / len(dbs)
                (work / "databases" / engine).mkdir(parents=True, exist_ok=True)
                log(f"• Dumping {'MariaDB' if engine == 'mysql' else 'PostgreSQL'} database {db}…")
                out = work / "databases" / engine / f"{db}.sql"
                est = _db_size(engine, db)
                with tempfile.TemporaryFile() as err:
                    proc = subprocess.Popen(_dump_argv(engine, db), stdout=subprocess.PIPE, stderr=err)
                    done, last = 0, 0.0
                    with open(out, "wb") as fh:
                        for chunk in iter(lambda: proc.stdout.read(_CHUNK), b""):
                            fh.write(chunk)
                            done += len(chunk)
                            if time.monotonic() - last > 0.3:
                                log.progress(lo + (hi - lo) * min(done / max(1, est), 0.97), f"Dumping {db}")
                                last = time.monotonic()
                    if proc.wait() != 0:
                        err.seek(0)
                        raise BackupError(f"dump {db}: {err.read().decode(errors='replace').strip()[-300:]}")
            manifest = {"created": int(time.time()), "kind": kind, "paths": paths, "mysql": mysql, "pgsql": pgsql,
                        "host": socket.gethostname(), "format": 1}
            (work / "manifest.json").write_text(json.dumps(manifest, indent=2))
            argv = ["tar", "-cf", "-", *excludes, "--warning=no-file-changed", "-C", str(work), "manifest.json"]
            if dbs:
                argv.append("databases")
            total = _du([str(work)])
            if paths:
                log.progress(db_share, "Measuring folders…")
                log(f"• Packing {len(paths)} folder(s)/file(s)…")
                total += _du(paths)
                argv += ["-C", "/", *[p.lstrip("/") for p in paths]]
            rc, err = _drain(argv, tmp, log, db_share if paths else 97, 100, "Packing", total)
            if rc not in (0, 1):  # 1 = some files changed while reading
                raise BackupError("tar: " + err[-400:])
            return _finish(tmp, final, {"kind": "wizard", "category": cat, "paths": paths, "mysql": mysql, "pgsql": pgsql,
                                        "created": manifest["created"], "host": manifest["host"], "wkind": kind}, log)
        finally:
            shutil.rmtree(work, ignore_errors=True)
            tmp.unlink(missing_ok=True)
    return _launch(f"Backup wizard: {kind}", "create", final.name, fn, {"kind": kind})


def manifest(name: str) -> dict:
    info = _info_for(name)
    if info["kind"] != "wizard":
        return {"wizard": False, "top": [info["top"]] if info.get("top") else []}
    return {"wizard": True, "kind": info.get("wkind"), "paths": info.get("paths", []), "mysql": info.get("mysql", []),
            "pgsql": info.get("pgsql", []), "created": info.get("created"), "host": info.get("host")}


def wizard_restore(name: str, paths: list[str] | None = None, mysql: list[str] | None = None,
                   pgsql: list[str] | None = None, dest: str = "/", rename: dict | None = None,
                   wipe: bool = True) -> jobs.Job:
    """Bring back the picked folders (to their own place, or under `dest`) and databases
    (into their own name, or the one `rename` gives)."""
    archive = _archive_path(name)
    man = manifest(name)
    if not man.get("wizard"):
        raise BackupError("That archive wasn't made by the Backup Wizard — use Restore on the Backups page")
    paths = [p for p in (paths or []) if p in man["paths"]]
    mysql = [d for d in (mysql or []) if d in man["mysql"]]
    pgsql = [d for d in (pgsql or []) if d in man["pgsql"]]
    if not paths and not mysql and not pgsql:
        raise BackupError("Pick what to restore")
    if mysql:
        _my_check()
    if pgsql:
        _pg_check()
    rename = rename or {}
    targets = {(e, d): _target(rename.get(f"{e}:{d}") or rename.get(d) or d) for e, ds in (("mysql", mysql), ("pgsql", pgsql)) for d in ds}
    destp = Path(dest or "/").resolve()
    if not destp.is_dir():
        raise BackupError(f"{destp} is not a folder")

    def fn(log):
        dbs = list(targets.items())
        steps = (1 if paths else 0) + (1 if dbs else 0) + len(dbs)
        step = 100.0 / max(1, steps)
        pos = 0.0
        if paths:
            where = "their original location" if str(destp) == "/" else str(destp)
            log(f"• Restoring {len(paths)} folder(s) to {where} (existing files are overwritten)…")
            rc, err = _feed(["tar", "-xzf", "-", "-C", str(destp), *[p.lstrip("/") for p in paths]],
                            archive, log, pos, pos + step, "Unpacking files")
            if rc != 0:
                raise BackupError("tar: " + err[-400:])
            pos += step
        if not dbs:
            log("✔ Restore finished")
            return {"ok": True}
        work = Path(tempfile.mkdtemp(prefix=".rst-", dir=BACKUP_DIR))
        try:
            members = [f"databases/{e}/{d}.sql" for (e, d), _ in dbs]
            rc, err = _feed(["tar", "-xzf", "-", "-C", str(work), *members], archive, log, pos, pos + step, "Reading database dumps")
            if rc != 0:
                raise BackupError("tar: " + err[-400:])
            pos += step
            for (engine, d), target in dbs:
                _prepare_db(engine, target, wipe, log)
                _import(engine, target, work / "databases" / engine / f"{d}.sql", False, log, pos, pos + step)
                pos += step
            log("✔ Restore finished")
            return {"ok": True}
        finally:
            shutil.rmtree(work, ignore_errors=True)
    shown = [("original locations" if str(destp) == "/" else str(destp))] if paths else []
    shown += sorted(set(targets.values()))
    return _launch(f"Restore {name}", "restore", name, fn, {"dest": ", ".join(shown)})
