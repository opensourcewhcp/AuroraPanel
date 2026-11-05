"""The daily check that masking did its job: looks through stored events for secrets that got past it.

A finding names where and what kind, never the value, so the report itself can't become a leak.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time

SCAN_EVERY = 86400
MAX_FINDINGS = 50
PATTERNS = {
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"),
    "bearer": re.compile(r"(?i)\bbearer\s+(?!\[masked\])[A-Za-z0-9._~+/=-]{6,}"),
    "hex_key": re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    "secret_value": re.compile(r"(?i)\b(?:pass(?:word|wd)?|token|secret|api[_-]?key|cvv|card)=(?!\[masked\])[^&\s\"']+"),
}
EVENT_COLUMNS = ("domain", "url", "user_agent", "headers")
EVIDENCE_COLUMNS = ("msg", "matched_data")


def _check(text, where: dict, findings: list[dict], counts: dict) -> None:
    if not text:
        return
    for kind, rx in PATTERNS.items():
        if rx.search(str(text)):
            counts[kind] = counts.get(kind, 0) + 1
            if len(findings) < MAX_FINDINGS:
                findings.append({**where, "kind": kind})


def scan(store) -> dict:
    """Look at everything stored since the last scan, month file by month file, and save the result."""
    previous = store.setting("leak_scan") or {}
    seen: dict = dict(previous.get("last_ids") or {})
    findings: list[dict] = list(previous.get("findings") or [])
    counts: dict = dict(previous.get("counts") or {})
    scanned = 0
    for path in store.months():
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        c.row_factory = sqlite3.Row
        try:
            start = int(seen.get(path.name, 0))
            top = start
            for r in c.execute(f"SELECT id, {','.join(EVENT_COLUMNS)} FROM events WHERE id > ? ORDER BY id", (start,)):
                scanned += 1
                top = r["id"]
                for col in EVENT_COLUMNS:
                    _check(r[col], {"file": path.name, "event_id": r["id"], "column": col}, findings, counts)
            for r in c.execute(f"SELECT event_id, {','.join(EVIDENCE_COLUMNS)} FROM event_evidence WHERE event_id > ? AND event_id <= ?", (start, top)):
                for col in EVIDENCE_COLUMNS:
                    _check(r[col], {"file": path.name, "event_id": r["event_id"], "column": col}, findings, counts)
            seen[path.name] = top
        finally:
            c.close()
    result = {"ts": time.time(), "scanned": scanned, "total": sum(counts.values()), "counts": counts, "findings": findings[:MAX_FINDINGS], "last_ids": seen}
    store.set_setting("leak_scan", result)
    return result


def due(store) -> bool:
    last = (store.setting("leak_scan") or {}).get("ts") or 0
    return time.time() - last >= SCAN_EVERY


def report(store) -> dict:
    r = store.setting("leak_scan") or {}
    return json.loads(json.dumps({k: r.get(k) for k in ("ts", "scanned", "total", "counts", "findings")}))
