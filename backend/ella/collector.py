"""Collector: reads log files and turns each record into one normalized event.

Sources share one small interface (kind, parse), so adding a format never touches the reader. The position is
inode + offset in the sources table, written after the events commit: a crash in between re-reads the same lines
and the record hash drops the repeats. Log contents are attacker-controlled: lengths are capped, secrets masked,
and only the query parameter names of a URL are kept, never the values.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import socket
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

MAX_LINE = {"modsec_audit": 512_000, "apache_access": 16_000}
READ_CHUNK = 4_000_000
DRAIN_SECONDS = 60  # Apache children keep writing to a rotated file until a graceful reload reaches them
HEADER_ALLOW = {"host", "user-agent", "referer", "origin", "content-type", "x-forwarded-for"}
SECRET_NAME = re.compile(r"pass(word|wd)?|token|secret|api[_-]?key|cvv|card|authorization|cookie", re.I)
SECRET_VALUE = [(re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), "[jwt]"),
                (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}"), "Bearer [masked]"),
                (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "[hex]"),
                (re.compile(r"(?i)\b(pass(?:word|wd)?|token|secret|api[_-]?key|cvv|card)=[^&\s\"']+"), r"\1=[masked]")]
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
SEVERITY_RANK = {"CRITICAL": 4, "ERROR": 3, "WARNING": 2, "NOTICE": 1}
SUMMARY_RULES = {"949110", "959100", "980170", "980130", "980140", "980145", "980150", "980155"}


def clean(text, limit: int = 512) -> str | None:
    if text is None:
        return None
    return CONTROL.sub(" ", str(text))[:limit]


def mask(text: str | None, limit: int = 256) -> str | None:
    if text is None:
        return None
    out = CONTROL.sub(" ", str(text))
    for rx, repl in SECRET_VALUE:
        out = rx.sub(repl, out)
    return out[:limit]


def split_url(raw: str) -> tuple[str | None, list[str]]:
    """(path, parameter names). Values can hold anything, so they are never kept."""
    if not raw:
        return None, []
    try:
        u = urlsplit(raw)
        keys = [k for k, _ in parse_qsl(u.query, keep_blank_values=True)]
    except ValueError:
        return mask(raw.split("?", 1)[0], 1024), []
    seen: list[str] = []
    for k in keys:
        k = clean(k, 64) or ""
        if k and k not in seen:
            seen.append(k)
    return mask(u.path, 1024), seen[:30]


def _record_hash(kind: str, inode: int, offset: int, line: bytes) -> str:
    return hashlib.sha256(f"{kind}|{inode}|{offset}|".encode() + line).hexdigest()


def _finish(e: dict, wanted: tuple[str, ...]) -> dict:
    """Say which fields this source couldn't fill: null with a reason, not an empty string."""
    e["missing_fields"] = json.dumps([k for k in wanted if e.get(k) in (None, "")])
    return e


# ----------------------------------------------------------------------------- ModSecurity JSON audit log
_MS_TIME = re.compile(r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})(\.\d+)?\s+-*([+-]?\d{4})")
_M_ID = re.compile(r'\[id "(\d+)"\]')
_M_MSG = re.compile(r'\[msg "((?:[^"\\]|\\.)*)"\]')
_M_DATA = re.compile(r'\[data "((?:[^"\\]|\\.)*)"\]')
_M_SEV = re.compile(r'\[severity "(\w+)"\]')
_M_AT = re.compile(r'\bat ([A-Z_]+(?::[^\s\[\]]+?)?)\.?\s+\[file')
_M_WITHIN = re.compile(r'found within ([A-Z_]+(?::[^\s:]+)?):')
_M_SCORE = re.compile(r"Total Score: (\d+)|blocking=(\d+)")


def _ms_time(text: str) -> float | None:
    m = _MS_TIME.search(text or "")
    if not m:
        return None
    sign = m.group(3) if m.group(3)[0] in "+-" else "-" + m.group(3)
    try:
        return datetime.strptime(f"{m.group(1)} {sign}", "%d/%b/%Y:%H:%M:%S %z").timestamp() + float(m.group(2) or 0)
    except ValueError:
        return None


def _evidence(message: str) -> dict | None:
    rid = _M_ID.search(message)
    if not rid:
        return None
    data = _M_DATA.search(message)
    var = _M_AT.search(message) or (_M_WITHIN.search(data.group(1)) if data else None)
    var_name = clean(var.group(1), 128) if var else None
    head = re.sub(r"^(Warning\.|Access denied[^.]*\.)\s*", "", message)
    operator = clean(re.split(r'\s+"|\s+at\s|\s+\[', head, maxsplit=1)[0], 64)
    # Only the name of a matched secret field is worth keeping, never what was in it.
    matched = "[masked]" if var_name and SECRET_NAME.search(var_name) else mask(data.group(1)) if data else None
    msg = _M_MSG.search(message)
    sev = _M_SEV.search(message)
    return {"rule_id": rid.group(1), "matched_var_name": var_name, "operator": operator, "severity": sev.group(1) if sev else None,
            "msg": clean(msg.group(1), 256) if msg else None, "matched_data": matched}


class ModsecAudit:
    kind = "modsec_audit"
    wanted = ("domain", "peer_ip", "client_ip", "method", "url", "status", "user_agent", "rule_id", "severity", "anomaly_score", "action")

    def parse(self, line: bytes, ctx: dict) -> dict | None:
        """An event, None for a line this format can't read; a record with no real rule hit is dropped as "skip"."""
        try:
            d = json.loads(line)
            tr, rq, rs, ad = d["transaction"], d.get("request") or {}, d.get("response") or {}, d.get("audit_data") or {}
            ts = _ms_time(tr.get("time", ""))
            if ts is None:
                return None
        except (ValueError, KeyError, TypeError, AttributeError):
            return None
        messages = [m for m in (ad.get("messages") or []) if isinstance(m, str)]
        rules, score = [], None
        for m in messages:
            for a, b in _M_SCORE.findall(m):
                score = max(score or 0, int(a or b))
            ev = _evidence(m)
            if ev and ev["rule_id"] not in SUMMARY_RULES:
                rules.append(ev)
        if not rules:
            return {"skip": True}
        parts = str(rq.get("request_line") or "").split(" ")
        path, keys = split_url(parts[1] if len(parts) > 1 else "")
        heads = {str(k).lower(): clean(mask(str(v), 512), 512) for k, v in (rq.get("headers") or {}).items() if str(k).lower() in HEADER_ALLOW}
        if "referer" in heads and heads["referer"]:
            heads["referer"] = heads["referer"].split("?", 1)[0]
        host = (heads.get("host") or "").split(":")[0].lower() or None
        top = max(rules, key=lambda r: SEVERITY_RANK.get(r["severity"] or "", 0))
        denied = any(m.startswith("Access denied") for m in messages)
        ip = clean(tr.get("remote_address"), 64)
        return _finish({
            "ts_event": ts, "domain": host, "peer_ip": ip, "client_ip": ip, "client_ip_source": "peer", "method": clean(parts[0], 16) or None, "url": path,
            "query_keys": json.dumps(keys), "status": rs.get("status") if isinstance(rs.get("status"), int) else None, "user_agent": heads.get("user-agent"),
            "headers": json.dumps(heads), "rule_id": top["rule_id"], "severity": top["severity"], "confidence": "medium", "anomaly_score": score,
            "action": "blocked" if denied else "detected", "tags": json.dumps(sorted({r["rule_id"][:3] for r in rules})),
            "raw_ref": f"{ctx['path']}#{clean(tr.get('transaction_id'), 64)}", "evidence": rules}, self.wanted)


# ----------------------------------------------------------------------------- Apache combined access log
_COMBINED = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?')


class ApacheAccess:
    kind = "apache_access"
    wanted = ("peer_ip", "client_ip", "method", "url", "status", "response_size", "user_agent")

    def parse(self, line: bytes, ctx: dict) -> dict | None:
        m = _COMBINED.match(line.decode("utf-8", "replace"))
        if not m:
            return None
        try:
            ts = datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z").timestamp()
        except ValueError:
            return None
        parts = m.group(3).split(" ")
        path, keys = split_url(parts[1] if len(parts) > 1 else "")
        size = m.group(5)
        ua = clean(mask(m.group(7), 512), 512) if m.group(7) not in (None, "-") else None
        ref = mask((m.group(6) or "").split("?", 1)[0], 512) if m.group(6) not in (None, "-") else None
        return _finish({
            "ts_event": ts, "domain": ctx.get("domain"), "peer_ip": clean(m.group(1), 64), "client_ip": clean(m.group(1), 64), "client_ip_source": "peer",
            "method": clean(parts[0], 16) or None, "url": path, "query_keys": json.dumps(keys), "status": int(m.group(4)),
            "response_size": int(size) if size.isdigit() else None, "user_agent": ua, "headers": json.dumps({"referer": ref} if ref else {}),
            "confidence": "n/a", "action": "logged", "tags": "[]", "raw_ref": f"{ctx['path']}@{ctx['inode']}:{ctx['offset']}", "evidence": []}, self.wanted)


PARSERS = {"modsec_audit": ModsecAudit(), "apache_access": ApacheAccess()}
_ROTATED = re.compile(r"(\.\d+|-\d{8}|\.gz|\.xz|\.old)$")


def discover(log_dir: str = "/var/log/apache2") -> list[tuple[str, str]]:
    """(path, kind) of every live log. Rotated copies are only read to finish them."""
    found = []
    audit = Path(log_dir) / "modsec_audit.log"
    if audit.exists():
        found.append((str(audit), "modsec_audit"))
    for p in sorted(set(glob.glob(f"{log_dir}/*access.log") + glob.glob(f"{log_dir}/*access_log"))):
        if not _ROTATED.search(p):
            found.append((p, "apache_access"))
    return found


def _domain_from(path: str) -> str | None:
    m = re.match(r"(.+)-access\.log$", Path(path).name)
    return m.group(1).lower() if m and "." in m.group(1) else None


def _find_rotated(path: str, inode: int) -> str | None:
    p = Path(path)
    for cand in p.parent.glob(p.name + "*"):
        try:
            if str(cand) != path and cand.stat().st_ino == inode:
                return str(cand)
        except OSError:
            continue
    return None


class Collector:
    def __init__(self, store, log_dir: str = "/var/log/apache2", server: str | None = None):
        self.store = store
        self.log_dir = log_dir
        self.server = server or socket.gethostname()
        # Files are kept open: an open file can still be read after logrotate renames or even deletes it.
        self._current: dict = {}
        self._previous: dict = {}

    def _handle(self, table: dict, path: str, inode: int, open_path: str | None):
        """The open file with this inode, opening open_path if needed. None if it's gone for good."""
        f = table.get(path)
        if f is not None and os.fstat(f.fileno()).st_ino == inode:
            return f
        if f is not None:
            f.close()
            table.pop(path, None)
        if open_path is None:
            return None
        f = open(open_path, "rb")
        if os.fstat(f.fileno()).st_ino != inode:
            f.close()
            return None
        table[path] = f
        return f

    def _read(self, f, path: str, inode: int, offset: int, kind: str) -> tuple[list[dict], int, int, int, list[str]]:
        """Parse whole lines from offset. (events, new offset, lines, unparsed, samples)"""
        parser, limit = PARSERS[kind], MAX_LINE[kind]
        events, unparsed, lines, samples = [], 0, 0, []
        f.seek(offset)
        data = f.read(READ_CHUNK)
        end = data.rfind(b"\n") + 1
        if not end:
            if len(data) > limit:  # one endless line: count it and step over what was read
                return [], offset + len(data), 0, 1, []
            return [], offset, 0, 0, []
        pos, now = 0, time.time()
        for raw in data[:end].split(b"\n")[:-1]:
            at = offset + pos
            pos += len(raw) + 1
            lines += 1
            ctx = {"path": path, "inode": inode, "offset": at, "domain": _domain_from(path)}
            ev = parser.parse(raw[:limit], ctx) if len(raw) <= limit else None
            if ev is None:
                unparsed += 1
                if len(samples) < 5:
                    samples.append(mask(raw[:200].decode("utf-8", "replace"), 200) or "")
                continue
            if ev.get("skip"):
                continue
            ev.update(hash=_record_hash(kind, inode, at, raw), ts_received=now, server=self.server, source=kind, historical=0)
            events.append(ev)
        return events, offset + end, lines, unparsed, samples

    def tick(self) -> int:
        """Read what is new in every source. Returns the events stored by this pass."""
        rows = {r["path"]: dict(r) for r in self.store.read(lambda c: c.execute("SELECT * FROM sources").fetchall())}
        total = 0
        for path, kind in discover(self.log_dir):
            total += self._tick_one(path, kind, rows.get(path))
        return total

    def _tick_one(self, path: str, kind: str, row: dict | None) -> int:
        now = time.time()
        try:
            st = os.stat(path)
        except OSError as exc:
            if row:
                self.store.run(lambda c: c.execute("UPDATE sources SET status='unavailable', last_error=?, last_read_ts=? WHERE path=?", (str(exc), now, path)))
            return 0
        if row is None:
            # A newly found log starts at its end: history is a separate, explicit import that never bans.
            self.store.run(lambda c: c.execute("INSERT INTO sources(path, kind, inode, offset, last_read_ts) VALUES (?,?,?,?,?)", (path, kind, st.st_ino, st.st_size, now)))
            return 0
        s = dict(row)
        events, lines, unparsed, samples = [], 0, 0, []

        def take(f, p, inode, off):
            nonlocal lines, unparsed
            ev, new_off, n, bad, smp = self._read(f, p, inode, off, kind)
            events.extend(ev)
            lines += n
            unparsed += bad
            samples.extend(smp)
            return new_off

        try:
            if s["inode"] != st.st_ino:
                # Rotated: the old file has another name, or none, and may still be growing for a moment.
                s.update(prev_inode=s["inode"], prev_offset=s["offset"], prev_until=now + DRAIN_SECONDS, inode=st.st_ino, offset=0)
                old_handle = self._current.pop(path, None)
                if old_handle is not None:
                    if path in self._previous:
                        self._previous.pop(path).close()
                    self._previous[path] = old_handle
            elif st.st_size < s["offset"]:
                s["offset"] = 0  # truncated in place (copytruncate)
            if s.get("prev_inode"):
                # After a panel restart there is no open file left: look for it under its new name.
                old = self._handle(self._previous, path, s["prev_inode"], None if path in self._previous else _find_rotated(path, s["prev_inode"]))
                if old:
                    s["prev_offset"] = take(old, path, s["prev_inode"], s["prev_offset"])
                if not old or now > (s.get("prev_until") or 0):
                    s.update(prev_inode=None, prev_offset=None, prev_until=None)
                    if path in self._previous:
                        self._previous.pop(path).close()
            cur = self._handle(self._current, path, s["inode"], path)
            if cur:
                s["offset"] = take(cur, path, s["inode"], s["offset"])
            s["status"], s["last_error"] = "ok", ""
        except OSError as exc:
            s["status"], s["last_error"] = "error", str(exc)
        added = self.store.add_events(events) if events else 0
        last = max((e["ts_event"] for e in events), default=s.get("last_event_ts"))
        keep = (json.loads(s.get("samples") or "[]") + samples)[-5:]

        def save(c):
            c.execute("UPDATE sources SET inode=?, offset=?, prev_inode=?, prev_offset=?, prev_until=?, last_event_ts=?, last_read_ts=?, lines=lines+?, unparsed=unparsed+?, samples=?, status=?, last_error=? WHERE path=?",
                      (s["inode"], s["offset"], s.get("prev_inode"), s.get("prev_offset"), s.get("prev_until"), last, now, lines, unparsed, json.dumps(keep), s["status"], s["last_error"], path))
        self.store.run(save)
        return added
