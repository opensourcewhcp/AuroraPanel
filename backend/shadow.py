"""Shadow Copies — a version history for a website's files, so anything the owner changed, overwrote
or deleted can be brought back.

Per site (a domain or a folder site) that has it turned on:
  • the panel keeps a copy of every file under the site's folder the first time it sees it, and a new
    copy each time the file changes — found by a snapshot every 10 minutes (task runner) and, for
    changes made through the File Manager, saved the moment before the file is overwritten or deleted;
  • copies live in /var/lib/aurora/shadow/<site>/v/<path in the site>/<unix time>, never inside the
    site itself, so nothing can reach them through the web server;
  • limits keep the space in check: versions per file, days to keep, a cap on the total size and a cap
    per file (big videos and archives are skipped) — oldest versions go first, the newest of each file
    is always kept.

Restoring writes the chosen version back (the current file is saved as a version first, so a restore
can itself be undone). Deleting a site deletes its shadow copies too.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
from pathlib import Path

ROOT = Path("/var/lib/aurora/shadow")
CONF = ROOT / "config.json"
DEFAULTS = {"keep_days": 30, "max_versions": 10, "max_mb": 500, "max_file_mb": 25}
# folders no one wants versioned: caches, build output, VCS internals, the panel's own leftovers
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "cache", ".cache", "caches", "tmp", "temp", "sessions", "logs", "log",
             ".aurora-trash", "__pycache__", ".next", ".nuxt", "upgrade", "wflogs", "w3tc-config", "et-cache", "litespeed"}
SKIP_SUFFIX = {".log", ".tmp", ".swp", ".part", ".lock", ".pid", ".sock"}
_lock = threading.Lock()
_roots_cache: tuple[float, list[tuple[Path, str, dict]]] = (0.0, [])


class ShadowError(RuntimeError):
    pass


# ---------------------------------------------------------------- config
def _load() -> dict:
    try:
        d = json.loads(CONF.read_text(encoding="utf-8"))
        d.setdefault("sites", {})
        return d
    except (OSError, ValueError):
        return {"sites": {}}


def _save(d: dict) -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(ROOT, 0o700)
    tmp = CONF.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=1), encoding="utf-8")
    tmp.replace(CONF)


def _store(sid: str) -> Path:
    return ROOT / re.sub(r"[^A-Za-z0-9._-]+", "-", sid)


def _cfg(sid: str) -> dict:
    return {**DEFAULTS, "enabled": False, **_load()["sites"].get(sid, {})}


# ---------------------------------------------------------------- what can have shadow copies
def targets() -> list[dict]:
    """Every website and folder site on this server with a real folder."""
    out, seen = [], set()
    try:
        from . import sites as S
        for s in S.list_sites()["sites"]:
            root = s.get("docroot")
            if root and s.get("server_name") and root not in seen and Path(root).is_dir():
                seen.add(root)
                out.append({"id": f"site:{s['server_name']}", "kind": "site", "name": s["server_name"], "path": root, "enabled_site": bool(s.get("enabled"))})
        for f in S.list_folder_sites().get("sites", []):
            root = f.get("path")
            if root and root not in seen and Path(root).is_dir():
                seen.add(root)
                out.append({"id": f"folder:{f['name']}", "kind": "folder", "name": f"/{f['name']}", "path": root, "enabled_site": True})
    except Exception:
        pass
    return out


def _target(sid: str) -> dict:
    t = next((x for x in targets() if x["id"] == sid), None)
    if not t:
        raise ShadowError("No such website or folder site")
    return t


# ---------------------------------------------------------------- the store
def _ver_dir(store: Path, rel: str) -> Path:
    return store / "v" / rel


def _versions(vd: Path) -> list[tuple[int, int]]:
    """[(ts, size)] oldest first."""
    out = []
    try:
        for p in vd.iterdir():
            if p.is_file() and p.name.isdigit():
                out.append((int(p.name), p.stat().st_size))
    except OSError:
        pass
    return sorted(out)


def _manifest(store: Path) -> dict:
    try:
        return json.loads((store / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_manifest(store: Path, m: dict) -> None:
    store.mkdir(parents=True, exist_ok=True)
    tmp = store / "manifest.tmp"
    tmp.write_text(json.dumps(m, separators=(",", ":")), encoding="utf-8")
    tmp.replace(store / "manifest.json")


def _wanted(rel_parts: tuple[str, ...], name: str, size: int, max_file: int) -> bool:
    if any(p in SKIP_DIRS for p in rel_parts[:-1]):
        return False
    if name.startswith(".") and name not in (".htaccess", ".env", ".htpasswd"):
        return False
    if Path(name).suffix.lower() in SKIP_SUFFIX:
        return False
    return size <= max_file


def _copy_version(store: Path, root: Path, f: Path, ts: int) -> int:
    rel = f.relative_to(root).as_posix()
    vd = _ver_dir(store, rel)
    vd.mkdir(parents=True, exist_ok=True)
    dst = vd / str(ts)
    n = 0
    while dst.exists():  # two changes in the same second
        n += 1
        dst = vd / str(ts + n)
    shutil.copy2(f, dst)  # keeps the file's mode, so a restore gives it back exactly; the store itself is 0700
    return dst.stat().st_size


def _prune(store: Path, cfg: dict) -> int:
    """Apply the limits; returns bytes freed."""
    freed = 0
    cutoff = time.time() - cfg["keep_days"] * 86400
    all_versions: list[tuple[int, int, Path]] = []  # (ts, size, path) across the store, newest-of-file excluded
    for vd, _, files in os.walk(store / "v"):
        vers = sorted((int(n) for n in files if n.isdigit()))
        if not vers:
            continue
        keep = vers[-1]
        old = vers[:-1]
        # too many versions of one file, or too old
        for ts in old[:max(0, len(vers) - cfg["max_versions"])]:
            p = Path(vd) / str(ts); freed += p.stat().st_size; p.unlink(missing_ok=True)
        for ts in old[max(0, len(vers) - cfg["max_versions"]):]:
            p = Path(vd) / str(ts)
            if ts < cutoff:
                freed += p.stat().st_size; p.unlink(missing_ok=True)
            elif p.exists():
                all_versions.append((ts, p.stat().st_size, p))
        _ = keep
    # total cap: oldest non-newest versions go first
    total = usage(store)["bytes"]
    cap = cfg["max_mb"] * 1048576
    for ts, size, p in sorted(all_versions):
        if total <= cap:
            break
        p.unlink(missing_ok=True); total -= size; freed += size
    # drop empty dirs
    for d, subdirs, files in os.walk(store / "v", topdown=False):
        if not subdirs and not files and Path(d) != store / "v":
            try:
                Path(d).rmdir()
            except OSError:
                pass
    return freed


def usage(store: Path) -> dict:
    files = versions = size = 0
    for d, _, names in os.walk(store / "v"):
        vs = [n for n in names if n.isdigit()]
        if vs:
            files += 1; versions += len(vs)
            for n in vs:
                try:
                    size += (Path(d) / n).stat().st_size
                except OSError:
                    pass
    return {"files": files, "versions": versions, "bytes": size}


# ---------------------------------------------------------------- snapshots
def snapshot(sid: str, log=None, initial: bool = False) -> dict:
    """Copy every new or changed file under the site into the store, then apply the limits."""
    t = _target(sid)
    cfg = _cfg(sid)
    if not cfg["enabled"] and not initial:
        return {"ok": True, "changes": 0, "skipped": "off"}
    root = Path(t["path"]).resolve()
    store = _store(sid)
    say = log or (lambda *_: None)
    with _lock:
        m = _manifest(store)
        now = int(time.time())
        changes = skipped = seen_n = 0
        max_file = cfg["max_file_mb"] * 1048576
        seen: set[str] = set()
        for d, subdirs, files in os.walk(root):
            subdirs[:] = [x for x in subdirs if x not in SKIP_DIRS and not (Path(d) / x).is_symlink()]
            for name in files:
                f = Path(d) / name
                try:
                    st = f.lstat()
                except OSError:
                    continue
                if not os.path.isfile(f) or os.path.islink(f):
                    continue
                rel = f.relative_to(root).as_posix()
                if not _wanted(tuple(rel.split("/")), name, st.st_size, max_file):
                    skipped += 1
                    continue
                seen.add(rel); seen_n += 1
                prev = m.get(rel)
                if prev and prev[0] == st.st_mtime_ns and prev[1] == st.st_size:
                    continue
                try:
                    _copy_version(store, root, f, now)
                except OSError as e:
                    say(f"! {rel}: {e}")
                    continue
                m[rel] = [st.st_mtime_ns, st.st_size]
                changes += 1
                if log and changes % 200 == 0:
                    say(f"• {changes} files copied so far…")
        # files that vanished: keep their versions, forget their current state
        gone = [rel for rel in list(m) if rel not in seen]
        for rel in gone:
            m.pop(rel, None)
        _save_manifest(store, m)
        freed = _prune(store, cfg)
        d = _load()
        d["sites"].setdefault(sid, {})
        d["sites"][sid].update({"last_run": now, "last_changes": changes, "last_gone": len(gone)})
        _save(d)
    u = usage(store)
    say(f"✓ {changes} file{'s' if changes != 1 else ''} copied, {len(gone)} vanished since last time, {skipped} skipped (caches, logs, files over {cfg['max_file_mb']} MB)"
        + (f", {freed / 1048576:.1f} MB pruned" if freed else "") + f" — {u['versions']} versions, {u['bytes'] / 1048576:.1f} MB in the store")
    return {"ok": True, "changes": changes, "gone": len(gone), "skipped": skipped, "freed": freed, **u}


def snapshot_all(log=None) -> dict:
    out = {}
    for sid, c in _load()["sites"].items():
        if c.get("enabled"):
            try:
                out[sid] = snapshot(sid, log)["changes"]
            except Exception as e:  # a site gone missing shouldn't stop the others
                out[sid] = f"error: {e}"
    return out


def before_change(path) -> None:
    """File Manager hook: about to overwrite or delete `path` — save what's there now (cheap, best effort)."""
    global _roots_cache
    try:
        p = Path(path)
        if time.time() - _roots_cache[0] > 15:
            roots = []
            conf = _load()["sites"]
            for t in targets():
                c = conf.get(t["id"], {})
                if c.get("enabled"):
                    roots.append((Path(t["path"]).resolve(), t["id"], {**DEFAULTS, **c}))
            _roots_cache = (time.time(), roots)
        for root, sid, cfg in _roots_cache[1]:
            rp = p.resolve()
            if rp == root or root not in rp.parents:
                continue
            files = [rp] if rp.is_file() else [x for x in rp.rglob("*") if x.is_file()] if rp.is_dir() else []
            store = _store(sid)
            max_file = cfg["max_file_mb"] * 1048576
            with _lock:
                m = _manifest(store)
                now = int(time.time())
                n = 0
                for f in files[:5000]:
                    if f.is_symlink():
                        continue
                    rel = f.relative_to(root).as_posix()
                    st = f.stat()
                    if not _wanted(tuple(rel.split("/")), f.name, st.st_size, max_file):
                        continue
                    prev = m.get(rel)
                    if prev and prev[0] == st.st_mtime_ns and prev[1] == st.st_size:
                        continue  # the current content is already the newest version
                    _copy_version(store, root, f, now)
                    m[rel] = [st.st_mtime_ns, st.st_size]
                    n += 1
                if n:
                    _save_manifest(store, m)
            return
    except Exception:
        return


# ---------------------------------------------------------------- management
def overview() -> dict:
    conf = _load()["sites"]
    out = []
    for t in targets():
        c = {**DEFAULTS, "enabled": False, **conf.get(t["id"], {})}
        u = usage(_store(t["id"])) if (_store(t["id"]) / "v").exists() else {"files": 0, "versions": 0, "bytes": 0}
        out.append({**t, **{k: c.get(k) for k in ("enabled", "keep_days", "max_versions", "max_mb", "max_file_mb", "last_run", "last_changes", "since")}, "usage": u})
    free = None
    try:
        free = shutil.disk_usage(str(ROOT if ROOT.exists() else Path("/var/lib"))).free
    except OSError:
        pass
    return {"sites": out, "defaults": DEFAULTS, "free": free, "store": str(ROOT)}


def set_enabled(sid: str, on: bool):
    """Turn Shadow on (returns a job that makes the first snapshot) or off (versions are kept until you delete them)."""
    t = _target(sid)
    d = _load()
    c = d["sites"].setdefault(sid, {})
    c["enabled"] = bool(on)
    if on and not c.get("since"):
        c["since"] = int(time.time())
    _save(d)
    global _roots_cache
    _roots_cache = (0.0, [])
    if not on:
        return {"ok": True}
    from . import jobs

    def fn(log):
        log(f"• First snapshot of {t['path']} — every file under the limits gets an initial copy")
        log.progress(None, "Copying")
        r = snapshot(sid, log, initial=True)
        return r
    return {"ok": True, "job": jobs.launch_fn(f"Shadow: first snapshot of {t['name']}", fn, meta={"shadow": sid}).id}


def set_settings(sid: str, keep_days=None, max_versions=None, max_mb=None, max_file_mb=None) -> dict:
    _target(sid)
    d = _load()
    c = d["sites"].setdefault(sid, {})
    for k, v, lo, hi in (("keep_days", keep_days, 1, 3650), ("max_versions", max_versions, 1, 500), ("max_mb", max_mb, 10, 1_000_000), ("max_file_mb", max_file_mb, 1, 10_000)):
        if v is None:
            continue
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise ShadowError(f"{k}: enter a whole number")
        if not lo <= v <= hi:
            raise ShadowError(f"{k}: between {lo} and {hi}")
        c[k] = v
    _save(d)
    store = _store(sid)
    freed = _prune(store, {**DEFAULTS, **c}) if (store / "v").exists() else 0
    return {"ok": True, "freed": freed}


def files(sid: str, q: str = "", only: str = "") -> dict:
    """Every file that has versions: its current state (current / modified / deleted) and the versions."""
    t = _target(sid)
    root = Path(t["path"]).resolve()
    store = _store(sid)
    m = _manifest(store)
    q = (q or "").lower()
    out = []
    base = store / "v"
    if base.exists():
        for d, _, names in os.walk(base):
            vs = sorted(int(n) for n in names if n.isdigit())
            if not vs:
                continue
            rel = Path(d).relative_to(base).as_posix()
            if q and q not in rel.lower():
                continue
            cur = root / rel
            if cur.is_file():
                st = cur.stat()
                known = m.get(rel)
                status = "current" if known and known[0] == st.st_mtime_ns and known[1] == st.st_size else "modified"
                cur_info = {"size": st.st_size, "mtime": int(st.st_mtime)}
            else:
                status, cur_info = "deleted", None
            if only and only != status:
                continue
            out.append({"path": rel, "status": status, "current": cur_info,
                        "versions": [{"ts": ts, "size": (Path(d) / str(ts)).stat().st_size} for ts in reversed(vs)]})
    out.sort(key=lambda x: -x["versions"][0]["ts"])
    counts = {"current": 0, "modified": 0, "deleted": 0}
    for x in out:
        counts[x["status"]] += 1
    return {"files": out[:2000], "total": len(out), "counts": counts, "root": str(root)}


def version_path(sid: str, rel: str, ts: int) -> Path:
    _target(sid)
    rel = rel.strip("/")
    if not rel or ".." in rel.split("/"):
        raise ShadowError("Bad path")
    p = _ver_dir(_store(sid), rel) / str(int(ts))
    if not p.is_file():
        raise ShadowError("That version no longer exists")
    return p


def restore(sid: str, rel: str, ts: int) -> dict:
    """Write a version back into the site. The current file (if any) is saved as a version first."""
    t = _target(sid)
    src = version_path(sid, rel, ts)
    root = Path(t["path"]).resolve()
    dst = (root / rel).resolve()
    if root not in dst.parents:
        raise ShadowError("Bad path")
    if dst.exists():
        before_change(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    try:  # the web server (and the owner) must be able to read what came back
        mode = dst.stat().st_mode & 0o777
        if mode & 0o044 != 0o044:
            os.chmod(dst, mode | 0o644)
    except OSError:
        pass
    try:  # same owner as the site's folder (folders created on the way too), so uploads and PHP keep working
        rs = root.stat()
        cur = dst
        while cur != root:
            if os.name != "nt":
                os.chown(cur, rs.st_uid, rs.st_gid)
            cur = cur.parent
    except OSError:
        pass
    try:
        from . import files as F
        F._give_to_site(dst)
    except Exception:
        pass
    st = dst.stat()
    with _lock:
        store = _store(sid)
        m = _manifest(store)
        m[rel] = [st.st_mtime_ns, st.st_size]
        _save_manifest(store, m)
    return {"ok": True, "path": str(dst), "size": st.st_size}


def forget(sid: str, rel: str = "", ts: int | None = None) -> dict:
    """Delete one version, every version of one file, or the whole store of a site."""
    _target(sid)
    store = _store(sid)
    if rel:
        rel = rel.strip("/")
        if ".." in rel.split("/"):
            raise ShadowError("Bad path")
        vd = _ver_dir(store, rel)
        if ts is not None:
            (vd / str(int(ts))).unlink(missing_ok=True)
        else:
            shutil.rmtree(vd, ignore_errors=True)
            with _lock:
                m = _manifest(store); m.pop(rel, None); _save_manifest(store, m)
        return {"ok": True}
    shutil.rmtree(store / "v", ignore_errors=True)
    _save_manifest(store, {})
    return {"ok": True}


def drop(sid: str) -> None:
    """A site was deleted: its shadow copies go too."""
    shutil.rmtree(_store(sid), ignore_errors=True)
    d = _load()
    if sid in d["sites"]:
        d["sites"].pop(sid, None)
        _save(d)
    global _roots_cache
    _roots_cache = (0.0, [])
