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
import secrets
import socket
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from .proxies import client_from

MAX_LINE = {"modsec_audit": 512_000, "modsec3_audit": 512_000}
DEFAULT_MAX_LINE = 16_000
READ_CHUNK = 4_000_000
JOURNAL_SECONDS = 2
DRAIN_SECONDS = 60  # Apache children keep writing to a rotated file until a graceful reload reaches them
HEADER_ALLOW = {"host", "user-agent", "referer", "origin", "content-type", "x-forwarded-for", "cf-connecting-ip", "x-real-ip"}
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


# ----------------------------------------------------------------------------- ModSecurity 3 (Nginx) JSON audit log
_V3_VAR = re.compile(r"against variable `([^`']*)")
_V3_OP = re.compile(r"Operator `(\w+)'")
_V3_SCORE = re.compile(r"Total Score: (\d+)|blocking=(\d+)")
_V3_SEVERITY = {"0": "CRITICAL", "1": "CRITICAL", "2": "CRITICAL", "3": "ERROR", "4": "WARNING", "5": "NOTICE"}


class Modsec3Audit:
    """A different shape from ModSecurity 2's log, with the same fields worth keeping. The match text, which holds the
    raw value that matched, is never stored: only the variable's name and the masked data."""
    kind = "modsec3_audit"
    wanted = ModsecAudit.wanted

    def parse(self, line: bytes, ctx: dict) -> dict | None:
        try:
            tr = json.loads(line)["transaction"]
            rq, rs = tr.get("request") or {}, tr.get("response") or {}
            ts = datetime.strptime(re.sub(r"\s+", " ", str(tr["time_stamp"])).strip(), "%a %b %d %H:%M:%S %Y").timestamp()
        except (ValueError, KeyError, TypeError, AttributeError):
            return None
        rules, score = [], None
        for msg in tr.get("messages") or []:
            if not isinstance(msg, dict):
                continue
            d = msg.get("details") or {}
            for a, b in _V3_SCORE.findall(str(msg.get("message", "")) + " " + str(d.get("data", ""))):
                score = max(score or 0, int(a or b))
            rid = str(d.get("ruleId") or "")
            if not rid or rid in SUMMARY_RULES:
                continue
            match = str(d.get("match") or "")
            v = _V3_VAR.search(match)
            o = _V3_OP.search(match)
            # libinjection's matches don't name a variable in "match", but the rule's data does.
            within = _M_WITHIN.search(str(d.get("data") or "")) if not v else None
            var = clean(v.group(1), 128) if v else clean(within.group(1), 128) if within else None
            rules.append({"rule_id": rid, "matched_var_name": var, "operator": clean(o.group(1), 64) if o else None, "severity": _V3_SEVERITY.get(str(d.get("severity"))),
                          "msg": clean(msg.get("message"), 256), "matched_data": "[masked]" if var and SECRET_NAME.search(var) else mask(d.get("data"))})
        if not rules:
            return {"skip": True}
        path, keys = split_url(str(rq.get("uri") or ""))
        heads = {str(k).lower(): clean(mask(str(v), 512), 512) for k, v in (rq.get("headers") or {}).items() if str(k).lower() in HEADER_ALLOW}
        if heads.get("referer"):
            heads["referer"] = heads["referer"].split("?", 1)[0]
        host = (heads.get("host") or "").split(":")[0].lower() or None
        top = max(rules, key=lambda r: SEVERITY_RANK.get(r["severity"] or "", 0))
        code = rs.get("http_code") if isinstance(rs.get("http_code"), int) else None
        detection = "detection" in str((tr.get("producer") or {}).get("secrules_engine", "")).lower()
        ip = clean(tr.get("client_ip"), 64)
        return _finish({
            "ts_event": ts, "domain": host, "peer_ip": ip, "client_ip": ip, "client_ip_source": "peer", "method": clean(rq.get("method"), 16), "url": path, "query_keys": json.dumps(keys),
            "status": code, "user_agent": heads.get("user-agent"), "headers": json.dumps(heads), "rule_id": top["rule_id"], "severity": top["severity"], "confidence": "medium", "anomaly_score": score,
            "action": "blocked" if code == 403 and not detection else "detected", "tags": json.dumps(sorted({r["rule_id"][:3] for r in rules})),
            "raw_ref": f"{ctx['path']}#{clean(tr.get('unique_id'), 64)}", "evidence": rules}, self.wanted)


class CaddyAccess:
    kind = "caddy_access"
    wanted = ("client_ip", "domain", "method", "url", "status", "response_size", "user_agent")

    def parse(self, line: bytes, ctx: dict) -> dict | None:
        try:
            d = json.loads(line)
            rq = d["request"]
            ts = float(d["ts"])
        except (ValueError, KeyError, TypeError):
            return None
        path, keys = split_url(str(rq.get("uri") or ""))
        ua = (rq.get("headers") or {}).get("User-Agent") or [None]
        ip = clean(rq.get("client_ip") or rq.get("remote_ip"), 64)
        return _finish({"ts_event": ts, "domain": clean(str(rq.get("host") or "").split(":")[0].lower(), 200) or None, "peer_ip": clean(rq.get("remote_ip"), 64), "client_ip": ip, "client_ip_source": "peer", "method": clean(rq.get("method"), 16),
                        "url": path, "query_keys": json.dumps(keys), "status": d.get("status") if isinstance(d.get("status"), int) else None, "response_size": d.get("size") if isinstance(d.get("size"), int) else None,
                        "user_agent": clean(mask(ua[0], 512), 512), "headers": "{}", "confidence": "n/a", "action": "logged", "tags": "[]", "raw_ref": f"{ctx['path']}@{ctx['inode']}:{ctx['offset']}", "evidence": []}, self.wanted)


class NginxAccess(ApacheAccess):
    kind = "nginx_access"


# ----------------------------------------------------------------------------- error logs and the like
def _message_event(ts, ip, severity, action, msg, ctx, wanted, rule=None, tags=(), account=None, domain=None) -> dict:
    """An event whose main content is one line of text. The text is untrusted and goes through masking."""
    return _finish({"ts_event": ts, "domain": domain or ctx.get("domain"), "peer_ip": clean(ip, 64), "client_ip": clean(ip, 64), "client_ip_source": "peer" if ip else None, "query_keys": "[]",
                    "headers": "{}", "rule_id": clean(rule, 64), "severity": severity, "confidence": "n/a", "action": action, "tags": json.dumps(list(tags)), "account": clean(account, 64),
                    "raw_ref": ctx.get("ref") or f"{ctx['path']}@{ctx['inode']}:{ctx['offset']}", "evidence": [{"msg": mask(msg, 512)}] if msg else []}, wanted)


_APACHE_ERROR = re.compile(r"^\[(?P<t>[^\]]+)\] \[(?:[^:\]]*:)?(?P<lvl>\w+)\](?: \[pid [^\]]*\])?(?: \([^)]*\)[^:]*:)?(?: \[client (?P<ip>[^\]]+)\])?\s*(?P<msg>.*)$")
_LEVELS = {"emerg": "CRITICAL", "alert": "CRITICAL", "crit": "CRITICAL", "error": "ERROR", "warn": "WARNING", "warning": "WARNING", "notice": "NOTICE", "info": "NOTICE", "debug": "NOTICE"}


class ApacheError:
    kind = "apache_error"
    wanted = ("peer_ip", "client_ip", "severity")
    continuation = re.compile(rb"^\s|^PHP Stack trace|^Stack trace|^#\d+ ")

    def parse(self, line: bytes, ctx: dict) -> dict | None:
        m = _APACHE_ERROR.match(line.decode("utf-8", "replace"))
        if not m:
            # Apache's startup notes come before logging is set up: no timestamp, and nothing about a visitor.
            return {"skip": True} if re.match(rb"AH\d+: ", line) else None
        try:
            ts = datetime.strptime(re.sub(r"\.\d+", "", m.group("t")), "%a %b %d %H:%M:%S %Y").timestamp()
        except ValueError:
            return None
        ip = m.group("ip")
        if ip:
            ip = ip.rsplit(":", 1)[0].strip("[]")
        return _message_event(ts, ip, _LEVELS.get(m.group("lvl").lower(), "NOTICE"), "logged", m.group("msg"), ctx, self.wanted)


_NGINX_ERROR = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(\w+)\] [^:]*: (.*?)(?:, client: ([^,]+))?(?:, server: ([^,]*))?(?:, request: .*)?$")


class NginxError:
    kind = "nginx_error"
    wanted = ("peer_ip", "client_ip", "severity")

    def parse(self, line: bytes, ctx: dict) -> dict | None:
        m = _NGINX_ERROR.match(line.decode("utf-8", "replace"))
        if not m:
            return None
        ts = time.mktime(time.strptime(m.group(1), "%Y/%m/%d %H:%M:%S"))
        return _message_event(ts, m.group(4), _LEVELS.get(m.group(2).lower(), "NOTICE"), "logged", m.group(3), ctx, self.wanted, domain=clean(m.group(5), 200))


_F2B = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ fail2ban\.\S+\s+\[\d+\]: (\w+)\s+(?:\[([\w.-]+)\] )?(.*)$")
_F2B_WHAT = re.compile(r"^(Found|Ban|Unban|Restore Ban) (\S+)")


class Fail2banLog:
    kind = "fail2ban_log"
    wanted = ("client_ip", "rule_id")

    def parse(self, line: bytes, ctx: dict) -> dict | None:
        m = _F2B.match(line.decode("utf-8", "replace"))
        if not m:
            return None
        ts = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
        level, jail, rest = m.group(2), m.group(3), m.group(4)
        what = _F2B_WHAT.match(rest)
        if what:
            action = {"Found": "detected", "Ban": "ban", "Restore Ban": "ban", "Unban": "unban"}[what.group(1)]
            return _message_event(ts, what.group(2), "WARNING" if action == "ban" else "NOTICE", action, rest, ctx, self.wanted, rule=jail)
        if level in ("ERROR", "CRITICAL"):
            return _message_event(ts, None, "ERROR", "error", rest, ctx, ("rule_id",), rule=jail)
        return {"skip": True}


class PanelAudit:
    """The panel's own log of logins and changes: JSON lines from audit.py."""
    kind = "panel_audit"
    wanted = ("client_ip", "account", "url", "status")

    def parse(self, line: bytes, ctx: dict) -> dict | None:
        try:
            d = json.loads(line)
            ts, what = float(d["ts"]), str(d["action"])
        except (ValueError, KeyError, TypeError):
            return None
        failed = what == "login failed"
        e = _message_event(ts, d.get("ip"), "WARNING" if failed else "NOTICE", "login_failed" if failed else "login" if what == "login" else "admin_action", what, ctx, self.wanted, account=d.get("user"))
        e.update(method=clean(d.get("method"), 16), url=mask(d.get("path"), 512), status=d.get("status") if isinstance(d.get("status"), int) else None)
        return _finish(e, self.wanted)


_PHP = re.compile(r"^\[(\d\d-\w{3}-\d{4} \d\d:\d\d:\d\d)[^\]]*\] (?:PHP )?(\w+)[: ]+(.*)$")


class PhpError:
    kind = "php_error"
    wanted = ("severity",)
    continuation = re.compile(rb"^\s|^PHP Stack trace|^Stack trace|^#\d+ |^thrown in ")

    def parse(self, line: bytes, ctx: dict) -> dict | None:
        m = _PHP.match(line.decode("utf-8", "replace"))
        if not m:
            return None
        ts = time.mktime(time.strptime(m.group(1), "%d-%b-%Y %H:%M:%S"))
        lvl = m.group(2).upper()
        sev = "CRITICAL" if lvl in ("ALERT", "EMERGENCY", "FATAL") else "ERROR" if lvl.startswith("ERR") else "WARNING" if lvl.startswith("WARN") else "NOTICE"
        return _message_event(ts, None, sev, "logged", m.group(3), ctx, self.wanted)


_VSFTPD = re.compile(r'^\w{3} (\w{3}\s+\d+ \d\d:\d\d:\d\d \d{4}) \[pid \d+\] (?:\[([^\]]*)\] )?(FAIL LOGIN|OK LOGIN): Client "([^"]+)"')


class VsftpdLog:
    kind = "vsftpd_log"
    wanted = ("client_ip", "account")

    def parse(self, line: bytes, ctx: dict) -> dict | None:
        m = _VSFTPD.match(line.decode("utf-8", "replace"))
        if not m:
            return {"skip": True}  # transfers and connects: not security events on their own
        ts = time.mktime(time.strptime(re.sub(r"\s+", " ", m.group(1)), "%b %d %H:%M:%S %Y"))
        failed = m.group(3).startswith("FAIL")
        return _message_event(ts, m.group(4).replace("::ffff:", ""), "WARNING" if failed else "NOTICE", "login_failed" if failed else "login", m.group(3), ctx, self.wanted, account=m.group(2))


# ----------------------------------------------------------------------------- operator-defined formats
CUSTOM_FIELDS = {"client_ip", "domain", "method", "url", "status", "user_agent", "rule_id", "severity", "ts"}
_NESTED = re.compile(r"\([^()]*[+*][^()]*\)[+*{]|\(\?[^)]*\)[+*]{2}")


def check_custom(spec: dict) -> dict:
    """Refuse a custom source before it can run: an absolute log path, and no pattern prone to catastrophic backtracking."""
    path = str(spec.get("path") or "")
    if not re.fullmatch(r"/[\w./-]{1,200}", path) or ".." in path or path.startswith(("/proc", "/sys", "/dev")):
        raise ValueError("Path must be an absolute path to a log file")
    fmt = spec.get("format")
    if fmt == "regex":
        pattern = str(spec.get("pattern") or "")
        if not pattern or len(pattern) > 500:
            raise ValueError("A pattern is needed, 500 characters at most")
        if _NESTED.search(pattern):
            raise ValueError("That pattern has a repeat inside a repeat, which can hang on hostile input")
        groups = set(re.compile(pattern).groupindex)
        if not groups or groups - CUSTOM_FIELDS:
            raise ValueError(f"Name groups after these fields only: {', '.join(sorted(CUSTOM_FIELDS))}")
    elif fmt == "json":
        fields = spec.get("fields")
        if not isinstance(fields, dict) or not fields or set(fields) - CUSTOM_FIELDS:
            raise ValueError(f"Map these fields only: {', '.join(sorted(CUSTOM_FIELDS))}")
    else:
        raise ValueError("Format must be regex or json")
    return {"path": path, "format": fmt, "pattern": spec.get("pattern"), "fields": spec.get("fields")}


class CustomSource:
    wanted = ("client_ip", "url", "status")

    def __init__(self, spec: dict):
        self.spec = spec
        self.kind = "custom"
        self.rx = re.compile(spec["pattern"]) if spec["format"] == "regex" else None

    def parse(self, line: bytes, ctx: dict) -> dict | None:
        text = line[:4000].decode("utf-8", "replace").rstrip(chr(13))  # a log written on Windows
        if self.rx:
            m = self.rx.search(text)
            if not m:
                return None
            got = m.groupdict()
        else:
            try:
                d = json.loads(text)
            except ValueError:
                return None
            if not isinstance(d, dict):
                return None
            got = {k: d.get(v) for k, v in self.spec["fields"].items()}
        try:
            ts = float(got.get("ts"))
        except (TypeError, ValueError):
            ts = time.time()
        path, keys = split_url(str(got.get("url") or ""))
        e = _message_event(ts, got.get("client_ip"), clean(got.get("severity"), 16), "logged", None, ctx, self.wanted, rule=got.get("rule_id"), domain=clean(got.get("domain"), 200))
        st = str(got.get("status") or "")
        e.update(method=clean(got.get("method"), 16), url=path, query_keys=json.dumps(keys), status=int(st) if st.isdigit() else None, user_agent=clean(mask(got.get("user_agent"), 512), 512))
        return _finish(e, self.wanted)


PARSERS = {"caddy_access": CaddyAccess(), "modsec3_audit": Modsec3Audit(), "modsec_audit": ModsecAudit(), "apache_access": ApacheAccess(), "nginx_access": NginxAccess(), "apache_error": ApacheError(), "nginx_error": NginxError(),
           "fail2ban_log": Fail2banLog(), "panel_audit": PanelAudit(), "php_error": PhpError(), "vsftpd_log": VsftpdLog()}
_ROTATED = re.compile(r"(\.\d+|-\d{8}(-\d+)?|\.gz|\.xz|\.old)$")
# Logs outside Apache's folder that this server may have. Absent ones are listed as not found, not hidden.
SYSTEM_FILES = [("/var/log/nginx/modsec_audit.log", "modsec3_audit"), ("/var/log/nginx/access.log", "nginx_access"), ("/var/log/nginx/error.log", "nginx_error"), ("/var/log/fail2ban.log", "fail2ban_log"), ("/var/lib/aurora/audit.jsonl", "panel_audit"),
                ("/var/log/php-fpm/error.log", "php_error"), ("/var/log/vsftpd.log", "vsftpd_log")]


# ----------------------------------------------------------------------------- journald
_IP = r"([0-9a-fA-F:.]+)"
_SSH = [(re.compile(rf"Failed \S+ for (?:invalid user )?(\S*) from {_IP}"), "login_failed", "WARNING"), (re.compile(rf"Invalid user (\S*) from {_IP}"), "login_failed", "WARNING"),
        (re.compile(rf"Accepted \S+ for (\S+) from {_IP}"), "login", "NOTICE")]


def _journal_sshd(msg: str) -> tuple | None:
    for rx, action, sev in _SSH:
        m = rx.search(msg)
        if m:
            return m.group(2), m.group(1), action, sev, ()
    return None


def _journal_postfix(msg: str) -> tuple | None:
    m = re.search(rf"\[{_IP}\]: SASL \S+ authentication failed", msg)
    if m:
        return m.group(1), None, "login_failed", "WARNING", ()
    m = re.search(rf"NOQUEUE: reject: \S+ from [^\[]*\[{_IP}\]", msg)
    if m:
        return m.group(1), None, "rejected", "NOTICE", ()
    return None


def _journal_dovecot(msg: str) -> tuple | None:
    if "auth failed" in msg or "Authentication failure" in msg or "authentication failure" in msg:
        m = re.search(rf"rip={_IP}", msg)
        u = re.search(r"user=<([^>]*)>", msg)
        if m:
            return m.group(1), u.group(1) if u else None, "login_failed", "WARNING", ()
    return None


def _journal_firewall(msg: str) -> tuple | None:
    m = re.search(rf"\bSRC={_IP}", msg)
    if not m:
        return None
    port = re.search(r"\bDPT=(\d+)", msg)
    proto = re.search(r"\bPROTO=(\w+)", msg)
    return m.group(1), None, "dropped", "NOTICE", tuple(x for x in (proto.group(1).lower() if proto else "", f"dpt:{port.group(1)}" if port else "") if x)


def _journal_cron(msg: str) -> tuple | None:
    return (None, None, "logged", "NOTICE", ()) if msg else None


JOURNAL_SOURCES = {"sshd": _journal_sshd, "postfix": _journal_postfix, "dovecot": _journal_dovecot, "firewall": _journal_firewall, "cron": _journal_cron}
SOURCE_INFO = {
    "caddy_access": ("JSON", "client, domain, request, status, size, User-Agent"), "modsec3_audit": ("JSON", "client, request, status, rules, matched data"), "modsec_audit": ("JSON", "client, request, status, rules, matched data"), "apache_access": ("combined", "client, request, status, size, User-Agent"),
    "nginx_access": ("combined", "client, request, status, size, User-Agent"), "apache_error": ("text", "client, severity, message"), "nginx_error": ("text", "client, domain, severity, message"),
    "fail2ban_log": ("text", "client, jail, ban and unban"), "panel_audit": ("JSON", "client, panel user, action, status"), "php_error": ("text", "severity, message"),
    "vsftpd_log": ("text", "client, user, login result"), "custom": ("set by you", "the fields you mapped"), "journal:sshd": ("journald", "client, user, login result"),
    "journal:postfix": ("journald", "client, login failures, rejections"), "journal:dovecot": ("journald", "client, user, login failures"), "journal:firewall": ("journald", "client, protocol, port"),
    "journal:cron": ("journald", "message"), "instaban": ("JSON", "client, request, matched pattern"),
}


def discover(log_dir: str = "/var/log/apache2") -> list[tuple[str, str]]:
    """(path, kind) of every live log. Rotated copies are only read to finish them."""
    found = []
    audit = Path(log_dir) / "modsec_audit.log"
    if audit.exists():
        found.append((str(audit), "modsec_audit"))
    for pattern, kind in (("*access.log", "apache_access"), ("*access_log", "apache_access"), ("*error.log", "apache_error"), ("*error_log", "apache_error")):
        for p in sorted(glob.glob(f"{log_dir}/{pattern}")):
            if not _ROTATED.search(p):
                found.append((p, kind))
    return found


def _domain_from(path: str) -> str | None:
    m = re.match(r"(.+)-(?:access|error)\.log$", Path(path).name)
    return m.group(1).lower() if m and "." in m.group(1) else None


HEAD_BYTES = 256


def _head_mark(path: str, length: int | None = None) -> str | None:
    """A file's identity beyond its inode, which a filesystem can hand straight to a new file: "length:hash" of its start."""
    try:
        with open(path, "rb") as f:
            data = f.read(HEAD_BYTES if length is None else length)
    except OSError:
        return None
    return f"{len(data)}:{hashlib.sha256(data).hexdigest()}" if data else None


def _find_rotated(path: str, inode: int) -> str | None:
    p = Path(path)
    for cand in p.parent.glob(p.name + "*"):
        try:
            if str(cand) != path and cand.stat().st_ino == inode:
                return str(cand)
        except OSError:
            continue
    return None


_tester_key: bytes | None = None


def tester_key() -> bytes:
    """The Rule Tester's secret. Made once, readable by root alone."""
    global _tester_key
    if _tester_key is None:
        from .db import ella_dir
        path = ella_dir() / "tester.key"
        try:
            _tester_key = path.read_bytes().strip()
        except OSError:
            _tester_key = b""
        if not _tester_key:
            _tester_key = secrets.token_hex(24).encode()
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(_tester_key)
    return _tester_key


def classify(ev: dict, trusted: list | None = None, threshold: int = 5) -> dict:
    """What can be said about one event on its own: who the client really is, and whether this looks like a breach.

    Inbound score at the blocking level, and yet the request got a 2xx or 5xx: nothing stopped it. Or a response rule fired
    on an answer that went out. These are suspicions, and the tag says so."""
    heads = ev.get("headers")
    if trusted and ev.get("peer_ip"):
        try:
            parsed = json.loads(heads) if isinstance(heads, str) else heads or {}
        except ValueError:
            parsed = {}
        ev["client_ip"], ev["client_ip_source"] = client_from(ev["peer_ip"], parsed, trusted)
    rules = [r.get("rule_id") or "" for r in ev.get("evidence") or []]
    tags = json.loads(ev.get("tags") or "[]")
    if any(r.startswith("1190") for r in rules):
        tags.append("honeypot")
        ev["confidence"] = "high"
    if any(r.startswith("11") and len(r) == 7 for r in rules):
        tags.append("ella-rule")
    if rules:
        status, score = ev.get("status"), ev.get("anomaly_score")
        answered = isinstance(status, int) and (200 <= status < 300 or status >= 500)
        leak = any(r.startswith("95") for r in rules) and isinstance(status, int) and status != 403
        if (answered and isinstance(score, int) and score >= threshold) or leak:
            tags.append("possible-breach")
            ev["severity"], ev["confidence"] = "CRITICAL", "medium"
    ev["tags"] = json.dumps(sorted(set(tags)))
    return ev


class Collector:
    def __init__(self, store, log_dir: str = "/var/log/apache2", server: str | None = None, adapter=None, system: bool = False, instaban_state: str = "/var/lib/aurora/instaban.json"):
        self.store = store
        self.log_dir = log_dir
        self.server = server or socket.gethostname()
        self.adapter = adapter
        self.system = system  # read the logs and journals outside Apache's folder too
        self.instaban_state = Path(instaban_state)
        self._next_journal = 0.0
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
        parser, limit = self._parser(path, kind), MAX_LINE.get(kind, DEFAULT_MAX_LINE)
        following = getattr(parser, "continuation", None)
        events, unparsed, lines, samples = [], 0, 0, []
        f.seek(offset)
        data = f.read(READ_CHUNK)
        end = data.rfind(b"\n") + 1
        if not end:
            if len(data) > limit:  # one endless line: count it and step over what was read
                return [], offset + len(data), 0, 1, []
            return [], offset, 0, 0, []
        pos, now = 0, time.time()
        trusted = self.store.setting("trusted_proxies") or []
        skip_key = tester_key() if kind in ("modsec_audit", "modsec3_audit") else None
        for raw in data[:end].split(b"\n")[:-1]:
            at = offset + pos
            pos += len(raw) + 1
            lines += 1
            if skip_key and skip_key in raw:
                continue  # the Rule Tester's own request
            if following is not None and events and following.match(raw):
                # One event over several lines (a stack trace): it belongs to the event before it.
                tags = json.loads(events[-1].get("tags") or "[]")
                if "multiline" not in tags:
                    events[-1]["tags"] = json.dumps([*tags, "multiline"])
                continue
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
            classify(ev, trusted)
            events.append(ev)
        return events, offset + end, lines, unparsed, samples

    def _parser(self, path: str, kind: str):
        if kind == "custom":
            spec = next(s for s in (self.store.setting("custom_sources") or []) if s["path"] == path)
            return CustomSource(spec)
        return PARSERS[kind]

    def _all_files(self) -> list[tuple[str, str]]:
        found = discover(self.log_dir)
        if self.system:
            found += [(p, k) for p, k in SYSTEM_FILES if os.path.exists(p)]
            # Each Nginx website keeps its own logs.
            for pattern, kind in (("/var/log/nginx/*-access.log", "nginx_access"), ("/var/log/nginx/*-error.log", "nginx_error"), ("/var/log/caddy/*-access.log", "caddy_access")):
                found += [(p, kind) for p in sorted(glob.glob(pattern))]
        found += [(s["path"], "custom") for s in (self.store.setting("custom_sources") or []) if os.path.exists(s["path"])]
        return found

    def tick(self) -> int:
        """Read what is new in every source. Returns the events stored by this pass."""
        rows = {r["path"]: dict(r) for r in self.store.read(lambda c: c.execute("SELECT * FROM sources").fetchall())}
        total = 0
        for path, kind in self._all_files():
            total += self._tick_one(path, kind, rows.get(path))
        if self.system and self.adapter and time.time() >= self._next_journal:
            self._next_journal = time.time() + JOURNAL_SECONDS
            for name in JOURNAL_SOURCES:
                total += self._tick_journal(name, rows.get(f"journal:{name}"))
            total += self._tick_instaban(rows.get("instaban"))
        return total

    def _save_row(self, path: str, kind: str, cursor, status: str, error: str, events: list[dict], lines: int, unparsed: int, last) -> None:
        now = time.time()

        def save(c):
            c.execute("INSERT INTO sources(path, kind) VALUES (?, ?) ON CONFLICT(path) DO NOTHING", (path, kind))
            c.execute("UPDATE sources SET cursor=?, status=?, last_error=?, last_read_ts=?, last_event_ts=?, lines=lines+?, unparsed=unparsed+? WHERE path=?", (cursor, status, error, now, last, lines, unparsed, path))
        self.store.run(save)

    def _tick_journal(self, name: str, row: dict | None) -> int:
        """Position is journald's own cursor; the cursor also makes each record's identity, so repeats are dropped."""
        path, kind, parse = f"journal:{name}", f"journal_{name}", JOURNAL_SOURCES[name]
        cursor = row["cursor"] if row else None
        r = self.adapter.call("journal_read", {"journal": name, "cursor": cursor})
        if not r["ok"] and not r["records"]:
            self._save_row(path, kind, cursor, "unavailable", r.get("error", "")[:200], [], 0, 0, row["last_event_ts"] if row else None)
            return 0
        if cursor is None:  # first look: note where the journal ends, and read from there on
            self._save_row(path, kind, r["records"][-1]["cursor"] if r["records"] else None, "ok", "", [], 0, 0, None)
            return 0
        events, now = [], time.time()
        for rec in r["records"]:
            got = parse(rec["message"])
            if got is None:
                continue
            ip, account, action, severity, tags = got
            ctx = {"path": path, "ref": f"{path}#{rec['cursor']}", "domain": None}
            e = _message_event(rec["ts"], ip, severity, action, rec["message"], ctx, ("client_ip",), tags=tags, account=account)
            e.update(hash=hashlib.sha256(f"{path}|{rec['cursor']}".encode()).hexdigest(), ts_received=now, server=self.server, source=kind, historical=0)
            events.append(e)
        added = self.store.add_events(events) if events else 0
        last = max((e["ts_event"] for e in events), default=row["last_event_ts"] if row else None)
        new_cursor = r["records"][-1]["cursor"] if r["records"] else cursor
        self._save_row(path, kind, new_cursor, "ok", "", events, len(r["records"]), 0, last)
        return added

    def _tick_instaban(self, row: dict | None) -> int:
        """InstaBan keeps its hits in its state file, so this source polls them. Its patterns stay where they are."""
        path = "instaban"
        if not self.instaban_state.exists():
            if row:
                self._save_row(path, "instaban", row["cursor"], "not_found", "", [], 0, 0, row["last_event_ts"])
            return 0
        try:
            hits = json.loads(self.instaban_state.read_text(encoding="utf-8")).get("hits") or []
        except (OSError, ValueError) as exc:
            self._save_row(path, "instaban", row["cursor"] if row else None, "error", str(exc)[:200], [], 0, 1, row["last_event_ts"] if row else None)
            return 0
        since = float(row["cursor"]) if row and row["cursor"] else None
        if since is None:  # start from now, as every other source does
            self._save_row(path, "instaban", str(max((h.get("ts", 0) for h in hits), default=0)), "ok", "", [], 0, 0, None)
            return 0
        events, now = [], time.time()
        for h in hits:
            if float(h.get("ts", 0)) <= since:
                continue
            url, keys = split_url(str(h.get("request") or h.get("path") or ""))
            ctx = {"path": path, "ref": f"instaban#{h.get('ts')}", "domain": h.get("site")}
            e = _message_event(float(h["ts"]), h.get("ip"), "WARNING", "ban" if h.get("banned") else "detected", f"Matched: {h.get('pattern')}", ctx, ("client_ip", "url"), rule=h.get("pattern_id"), domain=clean(h.get("site"), 200))
            e.update(url=url, query_keys=json.dumps(keys), user_agent=clean(mask(h.get("ua"), 512), 512), confidence="high", hash=hashlib.sha256(f"instaban|{json.dumps(h, sort_keys=True)}".encode()).hexdigest(),
                     ts_received=now, server=self.server, source="instaban", historical=0)
            events.append(e)
        added = self.store.add_events(events) if events else 0
        newest = max((e["ts_event"] for e in events), default=since)
        self._save_row(path, "instaban", str(newest), "ok", "", events, len(events), 0, newest if events else (row["last_event_ts"] if row else None))
        return added

    def import_file(self, path: str, kind: str) -> dict:
        """Read a whole log as history. Marked historical, so nothing can ever ban because of it, and repeats are dropped."""
        if kind not in PARSERS:
            raise ValueError("Unknown format")
        inode, offset, stored, lines, unparsed = os.stat(path).st_ino, 0, 0, 0, 0
        with open(path, "rb") as f:
            while True:
                events, new_offset, n, bad, _ = self._read(f, path, inode, offset, kind)
                for e in events:
                    e["historical"] = 1
                if events:
                    stored += self.store.add_events(events)
                lines += n
                unparsed += bad
                if new_offset == offset:
                    break
                offset = new_offset
        return {"lines": lines, "unparsed": unparsed, "stored": stored}

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
            elif s.get("head") and st.st_size != s["offset"]:
                # Same inode and big enough, but does it start the same? If not, it's a new file in the old one's place.
                seen_len = int(s["head"].split(":", 1)[0])
                if _head_mark(path, seen_len) != s["head"]:
                    s["offset"] = 0
                    old = self._current.pop(path, None)
                    if old is not None:
                        old.close()
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
        head = _head_mark(path)

        def save(c):
            c.execute("UPDATE sources SET inode=?, offset=?, prev_inode=?, prev_offset=?, prev_until=?, last_event_ts=?, last_read_ts=?, lines=lines+?, unparsed=unparsed+?, samples=?, status=?, last_error=?, head=? WHERE path=?",
                      (s["inode"], s["offset"], s.get("prev_inode"), s.get("prev_offset"), s.get("prev_until"), last, now, lines, unparsed, json.dumps(keep), s["status"], s["last_error"], head, path))
        self.store.run(save)
        return added
