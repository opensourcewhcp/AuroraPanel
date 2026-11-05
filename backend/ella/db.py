"""WAF Ella's storage: SQLite from the standard library.

ella.db holds state (sources, blocks, operations, audit, settings). Events live in one file per month,
events-YYYYMM.db, so retention is deleting a file rather than DELETE over millions of rows. Each process has
one writing connection per file, all used from a single worker thread; readers open their own connections.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import sqlite3
import threading
import time
from concurrent.futures import Future
from pathlib import Path

MAIN_DDL = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources (
  path TEXT PRIMARY KEY, kind TEXT NOT NULL, inode INTEGER, offset INTEGER NOT NULL DEFAULT 0,
  prev_inode INTEGER, prev_offset INTEGER, prev_until REAL,
  last_event_ts REAL, last_read_ts REAL, lines INTEGER NOT NULL DEFAULT 0, unparsed INTEGER NOT NULL DEFAULT 0,
  samples TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'ok', last_error TEXT NOT NULL DEFAULT '', cursor TEXT, head TEXT);
CREATE TABLE IF NOT EXISTS blocks (
  id TEXT PRIMARY KEY, source TEXT NOT NULL, owner TEXT NOT NULL, scope TEXT NOT NULL, backend TEXT NOT NULL, target TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '', ttl INTEGER, created_at REAL NOT NULL, expires_at REAL,
  desired_state TEXT NOT NULL, actual_state TEXT NOT NULL, last_verified_at REAL, operation_id TEXT, forced INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS blocks_one_active ON blocks(source, target) WHERE desired_state = 'active';
CREATE INDEX IF NOT EXISTS blocks_target ON blocks(target);
CREATE TABLE IF NOT EXISTS operations (
  id TEXT PRIMARY KEY, block_id TEXT NOT NULL REFERENCES blocks(id), kind TEXT NOT NULL, idempotency_key TEXT UNIQUE,
  state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_retry_at REAL, error TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL,
  capabilities TEXT NOT NULL DEFAULT '{}', created_at REAL NOT NULL, updated_at REAL NOT NULL, applied_at REAL);
CREATE INDEX IF NOT EXISTS operations_due ON operations(state, next_retry_at);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
  detail TEXT NOT NULL, operation_id TEXT NOT NULL DEFAULT '', prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'custom', domains TEXT NOT NULL DEFAULT '[]', path TEXT NOT NULL DEFAULT '', tree TEXT, raw TEXT,
  action TEXT NOT NULL DEFAULT 'block', status INTEGER NOT NULL DEFAULT 403, mode TEXT NOT NULL DEFAULT 'off', priority INTEGER NOT NULL DEFAULT 100, author TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL DEFAULT 1, locked INTEGER NOT NULL DEFAULT 0, expires_at REAL, detect_since REAL, cve_id TEXT, software TEXT, versions TEXT, source_url TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS rule_versions (rule_id INTEGER NOT NULL, version INTEGER NOT NULL, snapshot TEXT NOT NULL, actor TEXT NOT NULL, ts REAL NOT NULL, PRIMARY KEY (rule_id, version));
CREATE TABLE IF NOT EXISTS exceptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, var TEXT, domain TEXT NOT NULL, path TEXT NOT NULL, author TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, expires_at REAL, enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS policies (scope TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, locked INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (scope, key));
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', severity TEXT NOT NULL DEFAULT 'WARNING', owner TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS incident_items (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE, kind TEXT NOT NULL, ref TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL, ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS inc_items ON incident_items(incident_id);
CREATE TABLE IF NOT EXISTS alert_channels (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, name TEXT NOT NULL, config TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, min_severity TEXT NOT NULL DEFAULT 'WARNING', quiet_from INTEGER, quiet_to INTEGER, last_error TEXT NOT NULL DEFAULT '', last_sent REAL);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, dedupe TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', count INTEGER NOT NULL DEFAULT 1, first_ts REAL NOT NULL, last_ts REAL NOT NULL, delivered INTEGER NOT NULL DEFAULT 0, acked INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS alerts_dedupe ON alerts(dedupe, last_ts);
CREATE TABLE IF NOT EXISTS ti_lists (name TEXT PRIMARY KEY, url TEXT, enabled INTEGER NOT NULL DEFAULT 0, auto_ban INTEGER NOT NULL DEFAULT 0, count INTEGER NOT NULL DEFAULT 0, fetched_at REAL, expires_at REAL, last_error TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS ti_entries (list TEXT NOT NULL REFERENCES ti_lists(name) ON DELETE CASCADE, family INTEGER NOT NULL, start BLOB NOT NULL, stop BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS ti_range ON ti_entries(family, start, stop);
CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, name TEXT NOT NULL, secret TEXT NOT NULL, created_at REAL NOT NULL, last_seen REAL, policy_version INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT '{}', revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS saved_queries (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, name TEXT NOT NULL, query TEXT NOT NULL);
"""

EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, ts_event REAL NOT NULL, ts_received REAL NOT NULL, server TEXT, account TEXT, domain TEXT,
  source TEXT NOT NULL, peer_ip TEXT, client_ip TEXT, client_ip_source TEXT, method TEXT, url TEXT, query_keys TEXT, status INTEGER, response_size INTEGER,
  user_agent TEXT, headers TEXT, rule_id TEXT, severity TEXT, confidence TEXT, anomaly_score INTEGER, action TEXT, tags TEXT, raw_ref TEXT,
  historical INTEGER NOT NULL DEFAULT 0, missing_fields TEXT NOT NULL DEFAULT '[]');
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts_event);
CREATE INDEX IF NOT EXISTS ev_ip ON events(client_ip, ts_event);
CREATE INDEX IF NOT EXISTS ev_domain ON events(domain, ts_event);
CREATE INDEX IF NOT EXISTS ev_rule ON events(rule_id, ts_event);
CREATE INDEX IF NOT EXISTS ev_source ON events(source, ts_event);
CREATE TABLE IF NOT EXISTS event_evidence (
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, rule_id TEXT, matched_var_name TEXT, operator TEXT, severity TEXT, msg TEXT, matched_data TEXT);
CREATE INDEX IF NOT EXISTS evi_event ON event_evidence(event_id);
"""

EVENT_COLUMNS = ("hash", "ts_event", "ts_received", "server", "account", "domain", "source", "peer_ip", "client_ip", "client_ip_source", "method", "url",
                 "query_keys", "status", "response_size", "user_agent", "headers", "rule_id", "severity", "confidence", "anomaly_score", "action", "tags",
                 "raw_ref", "historical", "missing_fields")

DEFAULT_SETTINGS = {
    "management_cidrs": [],
    "trusted_proxies": [],
    "protected_paths": ["/.well-known/acme-challenge/"],
    "capabilities": {},
    "custom_sources": [],
    "drift": [],
    "honeypot": {"mode": "detect", "paths": ["/.env", "/.git/config", "/wp-config.php.bak", "/backup.zip", "/phpmyadmin/"]},
    "under_attack": {"on": False, "until": None},
    "kill_switch": False,
    "response_inspection": False,
    "body_limit_action": "Reject",
}
GENESIS = "0" * 64


def ella_dir() -> Path:
    return Path(os.environ.get("AURORA_ELLA_DIR", "/var/lib/aurora/ella"))


def _pragmas(c: sqlite3.Connection) -> None:
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA busy_timeout=5000")
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA wal_autocheckpoint=1000")


def month_of(ts: float) -> str:
    return time.strftime("%Y%m", time.gmtime(ts))


class Store:
    def __init__(self, directory: Path | str | None = None):
        self.dir = Path(directory) if directory else ella_dir()
        self.dir.mkdir(parents=True, exist_ok=True)
        self._q: queue.Queue = queue.Queue(maxsize=10000)
        self._months: dict[str, sqlite3.Connection] = {}
        self._main: sqlite3.Connection | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.run(lambda c: None)  # creates the schema, and reports a bad folder straight away

    # ------------------------------------------------------------- the writer
    def _connect(self, path: Path, ddl: str) -> sqlite3.Connection:
        c = sqlite3.connect(path, timeout=5, isolation_level=None)
        c.row_factory = sqlite3.Row
        _pragmas(c)
        c.executescript(ddl)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return c

    def _month(self, month: str) -> sqlite3.Connection:
        if month not in self._months:
            self._months[month] = self._connect(self.dir / f"events-{month}.db", EVENTS_DDL)
        return self._months[month]

    def _worker(self) -> None:
        self._main = self._connect(self.dir / "ella.db", MAIN_DDL)
        have = {r["name"] for r in self._main.execute("PRAGMA table_info(sources)")}
        for column in ("cursor", "head"):  # databases made by stage 1
            if column not in have:
                self._main.execute(f"ALTER TABLE sources ADD COLUMN {column} TEXT")
        for k, v in DEFAULT_SETTINGS.items():
            self._main.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (k, json.dumps(v)))
        while True:
            fn, fut = self._q.get()
            try:
                self._main.execute("BEGIN IMMEDIATE")
                res = fn(self._main)
                self._main.execute("COMMIT")
                fut.set_result(res)
            except BaseException as exc:  # the caller gets it; this thread must outlive it
                if self._main.in_transaction:
                    self._main.execute("ROLLBACK")
                fut.set_exception(exc)

    def run(self, fn):
        """Run fn(connection) in one transaction on the writer thread and return its result."""
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._worker, name="ella-db-writer", daemon=True)
                self._thread.start()
        fut: Future = Future()
        self._q.put((fn, fut))
        return fut.result(timeout=60)

    def add_events(self, events: list[dict]) -> int:
        """Write one batch. A record already stored (same hash) is skipped, so re-reading after a restart adds nothing."""
        def write(_main):
            added = 0
            by_month: dict[str, list[dict]] = {}
            for e in events:
                by_month.setdefault(month_of(e["ts_event"]), []).append(e)
            for month, rows in by_month.items():
                c = self._month(month)
                c.execute("BEGIN IMMEDIATE")
                try:
                    cols = ",".join(EVENT_COLUMNS)
                    marks = ",".join("?" for _ in EVENT_COLUMNS)
                    for e in rows:
                        cur = c.execute(f"INSERT OR IGNORE INTO events({cols}) VALUES ({marks})", [e.get(k) for k in EVENT_COLUMNS])
                        if cur.rowcount:
                            added += 1
                            for ev in e.get("evidence", []):
                                c.execute("INSERT INTO event_evidence VALUES (?,?,?,?,?,?,?)",
                                          (cur.lastrowid, ev.get("rule_id"), ev.get("matched_var_name"), ev.get("operator"), ev.get("severity"),
                                           ev.get("msg"), ev.get("matched_data")))
                    c.execute("COMMIT")
                except BaseException:
                    c.execute("ROLLBACK")
                    raise
            return added
        return self.run(write)

    # ------------------------------------------------------------- readers
    def read(self, fn):
        c = sqlite3.connect(self.dir / "ella.db", timeout=5)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=5000")
        try:
            return fn(c)
        finally:
            c.close()

    def months(self) -> list[Path]:
        return sorted(self.dir.glob("events-[0-9][0-9][0-9][0-9][0-9][0-9].db"), reverse=True)

    def search_events(self, limit: int = 100, cursor: tuple[float, int] | None = None, allowed_domains: list[str] | None = None, query: tuple[str, list] | None = None, **filters) -> dict:
        """Newest first, paged by cursor. allowed_domains is the caller's scope and is applied in the query itself.
        query is the (SQL, values) from query.compile_query."""
        limit = max(1, min(int(limit), 1000))
        where, args = [], []
        if query and query[0]:
            where.append(query[0])
            args += list(query[1])
        for col in ("client_ip", "domain", "rule_id", "source", "action"):
            if filters.get(col):
                where.append(f"{col} = ?")
                args.append(str(filters[col]))
        if allowed_domains is not None:
            if not allowed_domains:
                return {"events": [], "next_cursor": None}
            where.append(f"domain IN ({','.join('?' for _ in allowed_domains)})")
            args += list(allowed_domains)
        if cursor:
            where.append("(ts_event, id) < (?, ?)")
            args += [cursor[0], cursor[1]]
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        out: list[dict] = []
        for path in self.months():
            if len(out) >= limit:
                break
            c = sqlite3.connect(path, timeout=5)
            c.row_factory = sqlite3.Row
            try:
                rows = c.execute(f"SELECT * FROM events {clause} ORDER BY ts_event DESC, id DESC LIMIT ?", [*args, limit - len(out)]).fetchall()
                for r in rows:
                    e = dict(r)
                    e.pop("hash", None)
                    for k in ("query_keys", "headers", "tags", "missing_fields"):
                        e[k] = json.loads(e[k]) if e[k] else None
                    e["evidence"] = [dict(x) for x in c.execute("SELECT rule_id, matched_var_name, operator, severity, msg, matched_data FROM event_evidence WHERE event_id = ?", (r["id"],))]
                    out.append(e)
            finally:
                c.close()
        nxt = [out[-1]["ts_event"], out[-1]["id"]] if len(out) == limit else None
        return {"events": out, "next_cursor": nxt}

    def get_event(self, ts: float, event_id: int, allowed_domains: list[str] | None = None) -> dict | None:
        """One event, by the two values every listed event carries. The caller's scope applies here too."""
        path = self.dir / f"events-{month_of(float(ts))}.db"
        if not path.exists():
            return None
        c = sqlite3.connect(path, timeout=5)
        c.row_factory = sqlite3.Row
        try:
            r = c.execute("SELECT * FROM events WHERE id = ?", (int(event_id),)).fetchone()
            if not r or (allowed_domains is not None and r["domain"] not in allowed_domains):
                return None
            e = dict(r)
            e.pop("hash", None)
            for k in ("query_keys", "headers", "tags", "missing_fields"):
                e[k] = json.loads(e[k]) if e[k] else None
            e["evidence"] = [dict(x) for x in c.execute("SELECT rule_id, matched_var_name, operator, severity, msg, matched_data FROM event_evidence WHERE event_id = ?", (r["id"],))]
            return e
        finally:
            c.close()

    def scan_events(self, since: float, where: str = "", args: tuple = (), limit: int = 200000):
        """Events newer than since, across the month files, newest first. For previews and reports."""
        n = 0
        for path in self.months():
            if path.stem[7:] < month_of(since):
                break
            c = sqlite3.connect(path, timeout=5)
            c.row_factory = sqlite3.Row
            try:
                sql = f"SELECT * FROM events WHERE ts_event >= ? {('AND ' + where) if where else ''} ORDER BY ts_event DESC LIMIT ?"
                for r in c.execute(sql, (since, *args, limit - n)):
                    n += 1
                    yield dict(r)
            finally:
                c.close()
            if n >= limit:
                return

    # ------------------------------------------------------------- settings
    def setting(self, key: str):
        row = self.read(lambda c: c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone())
        return json.loads(row["value"]) if row else DEFAULT_SETTINGS.get(key)

    def set_setting(self, key: str, value) -> None:
        self.run(lambda c: c.execute("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, json.dumps(value))))

    # ------------------------------------------------------------- audit: append-only hash chain
    @staticmethod
    def _audit_hash(prev: str, ts: float, actor: str, action: str, target: str, detail: str, op: str) -> str:
        return hashlib.sha256(json.dumps([prev, ts, actor, action, target, detail, op], ensure_ascii=False).encode()).hexdigest()

    def audit_in(self, c: sqlite3.Connection, actor: str, action: str, target: str, detail: dict | None = None, operation_id: str = "") -> None:
        """Append inside the caller's transaction, so the record and the change it describes commit together."""
        row = c.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        ts, text = round(time.time(), 3), json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)
        h = self._audit_hash(prev, ts, actor, action, target, text, operation_id)
        c.execute("INSERT INTO audit(ts, actor, action, target, detail, operation_id, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)",
                  (ts, actor, action, target, text, operation_id, prev, h))

    def audit(self, actor: str, action: str, target: str, detail: dict | None = None, operation_id: str = "") -> None:
        self.run(lambda c: self.audit_in(c, actor, action, target, detail, operation_id))

    def audit_entries(self, limit: int = 200, target: str = "") -> list[dict]:
        sql = "SELECT * FROM audit " + ("WHERE target = ? " if target else "") + "ORDER BY seq DESC LIMIT ?"
        args = ([target] if target else []) + [max(1, min(int(limit), 2000))]
        rows = self.read(lambda c: c.execute(sql, args).fetchall())
        return [{**dict(r), "detail": json.loads(r["detail"])} for r in rows]

    def audit_verify(self) -> dict:
        """Walk the whole chain. Returns the first record that doesn't match."""
        prev, n = GENESIS, 0
        for r in self.read(lambda c: c.execute("SELECT * FROM audit ORDER BY seq").fetchall()):
            want = self._audit_hash(prev, r["ts"], r["actor"], r["action"], r["target"], r["detail"], r["operation_id"])
            if r["prev_hash"] != prev or r["hash"] != want:
                return {"ok": False, "records": n, "broken_at": r["seq"]}
            prev, n = r["hash"], n + 1
        return {"ok": True, "records": n, "broken_at": None}
