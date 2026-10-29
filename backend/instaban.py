"""InstaBan: a list of payloads, paths and pages that only attackers ask for. The first request that
matches one gets its address banned at the firewall for a time you choose, the hit is kept as evidence
(what was tried, from where, against which site), and the address can be reported to its abuse desk.

Sources: every Apache access log on this server, read incrementally every few seconds by a small
thread inside the panel. Trusted addresses (IP Blocker & Trust) are never banned, nor is loopback.

Everything stored here is attacker-controlled text (payloads, request lines, user agents). The API
hands it to the panel as plain JSON and the page shows it with textContent only, so a payload can be
looked at, listed and exported without ever being rendered or run."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import unquote

from . import guard

STATE = Path("/var/lib/aurora/instaban.json")
LOG_DIR = Path("/var/log/apache2")
MAX_READ = 4 * 1024 * 1024
MAX_HITS = 500
TTL_CHOICES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "forever": 0}
KINDS = ("contains", "starts", "regex", "ua", "ip")   # path contains / starts with / regex, user agent contains, address or range
# Behaviour watched per address, on top of the pattern list (counts within a sliding window, in seconds).
DEFAULT_BEHAVIOR = {
    "errors": {"on": True, "count": 30, "window": 60},    # 4xx answers: someone guessing paths
    "flood": {"on": False, "count": 600, "window": 60},   # requests of any kind: a hammering client
    "ports": {"on": True, "count": 8, "window": 60},      # distinct ports knocked on (needs the Network Monitor's connection log)
}
_LOCK = threading.Lock()


class InstaBanError(Exception):
    pass


# Paths and payloads no visitor of a normal website ever asks for. Each line is a plain substring
# of the URL-decoded, lower-cased request target (path + query).
DEFAULT_PATTERNS = [
    ("/.git/", "Source control folder: git"), ("/.svn/", "Source control folder: subversion"), ("/.hg/", "Source control folder: mercurial"),
    ("/.env", "Environment file with secrets"), ("/.aws/credentials", "Cloud keys"), ("/.ssh/id_rsa", "SSH private key"),
    ("/etc/passwd", "System account file"), ("/../", "Path traversal"), ("/wp-config.php.", "WordPress config backups (.bak, .old, ~)"),
    ("/vendor/phpunit/", "PHPUnit remote code execution probe"), ("eval-stdin.php", "PHPUnit remote code execution probe"),
    ("/cgi-bin/.%2e/", "Apache path traversal (CVE-2021-41773)"), ("/boaform/", "Router exploit"), ("/hnap1", "Router exploit (HNAP)"),
    ("/shell?", "Command injection probe"), ("/actuator/env", "Spring Boot secrets endpoint"), ("/_ignition/execute-solution", "Laravel debug RCE"),
    ("/php-cgi/php-cgi.exe", "PHP CGI on Windows exploit"), ("allow_url_include=", "PHP CGI argument injection"), ("auto_prepend_file=", "PHP CGI argument injection"),
    ("<script", "Cross-site scripting payload"), ("union select", "SQL injection payload"), ("wget+http", "Download-and-run payload"), ("chmod+777", "Download-and-run payload"),
    ("/xmlrpc.php?rsd", "WordPress XML-RPC scanner"), ("/wp-content/plugins/wp-file-manager/", "wp-file-manager exploit"),
]
# User agents that only vulnerability scanners send.
DEFAULT_UA = [("sqlmap", "SQL injection tool"), ("nikto", "Web vulnerability scanner"), ("masscan", "Port scanner"), ("zgrab", "Internet-wide scanner"),
              ("nmap scripting engine", "Nmap scripts"), ("acunetix", "Vulnerability scanner"), ("nessus", "Vulnerability scanner"), ("wpscan", "WordPress scanner")]

_LINE = re.compile(r'^(?:(?P<vhost>\S+):\d+ )?(?P<ip>[0-9a-fA-F:.]+) \S+ \S+ \[(?P<time>[^\]]*)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')


def _default() -> dict:
    return {"version": 1, "enabled": False, "ttl": "24h", "report": False, "patterns": [], "hits": [], "files": {},
            "stats": {"hits": 0, "bans": 0, "reports": 0}, "last_scan": 0, "behavior": json.loads(json.dumps(DEFAULT_BEHAVIOR))}


def load() -> dict:
    s = _default()
    try:
        s.update(json.loads(STATE.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    if not s["patterns"] and not s.get("seeded"):
        now = int(time.time())
        s["patterns"] = [{"id": _pid(), "pattern": p, "kind": "contains", "note": n, "added": now, "hits": 0} for p, n in DEFAULT_PATTERNS]
        s["seeded"] = True
    if not s.get("seeded_ua"):   # the scanner user agents arrived in a later release: added once
        now = int(time.time())
        s["patterns"] += [{"id": _pid(), "pattern": p, "kind": "ua", "note": n, "added": now, "hits": 0} for p, n in DEFAULT_UA]
        s["seeded_ua"] = True
    b = json.loads(json.dumps(DEFAULT_BEHAVIOR))
    for k, v in (s.get("behavior") or {}).items():
        if k in b and isinstance(v, dict):
            b[k].update({kk: vv for kk, vv in v.items() if kk in b[k]})
    s["behavior"] = b
    return s


def save(s: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(s, indent=1), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(STATE)


def _pid() -> str:
    return secrets.token_hex(4)


# ---------------------------------------------------------------- patterns
def _check_pattern(pattern: str, kind: str) -> tuple[str, str]:
    p = (pattern or "").strip()
    if kind not in KINDS:
        raise InstaBanError("Kind must be contains, starts, regex, ua or ip")
    if not p:
        raise InstaBanError("Enter the payload, path, user agent or address")
    if len(p) > 200 or "\n" in p:
        raise InstaBanError("One pattern per line, up to 200 characters")
    if kind == "ip":
        try:
            return str(ipaddress.ip_network(p, strict=False)), kind
        except ValueError:
            raise InstaBanError("Enter an address or a range, e.g. 203.0.113.9 or 203.0.113.0/24")
    if kind == "ua":
        p = p.lower()
        if len(p) < 4 or p in ("mozilla", "chrome", "safari", "firefox", "windows", "linux", "android", "iphone", "curl", "wget", "bot"):
            raise InstaBanError("That matches ordinary browsers or tools; pick something only a scanner sends")
        return p, kind
    if kind == "regex":
        try:
            re.compile(p, re.I)
        except re.error as exc:
            raise InstaBanError(f"Not a valid regular expression: {exc}")
        if len(p) < 4:
            raise InstaBanError("A regular expression that short would match nearly everything")
    else:
        p = p.lower()
        if len(p) < 4:
            raise InstaBanError("Too short: that would match ordinary pages too")
        if p in ("/", "/index", "/index.php", "/index.html", "http", "https", ".php", ".html", "/wp-", "/wp-admin", "/wp-login.php", "/admin"):
            raise InstaBanError("That matches normal traffic; real visitors would be banned")
    return p, kind


def add_pattern(pattern: str, kind: str = "contains", note: str = "") -> dict:
    p, kind = _check_pattern(pattern, kind)
    with _LOCK:
        s = load()
        if any(x["pattern"] == p and x["kind"] == kind for x in s["patterns"]):
            raise InstaBanError("Already on the list")
        entry = {"id": _pid(), "pattern": p, "kind": kind, "note": (note or "").strip()[:120], "added": int(time.time()), "hits": 0}
        s["patterns"].append(entry)
        save(s)
    return entry


def import_patterns(text: str, kind: str = "contains") -> dict:
    """One pattern per line; '#' starts a comment, a trailing '  # note' becomes the note. Duplicates and bad lines are skipped."""
    added, skipped = 0, []
    with _LOCK:
        s = load()
        have = {(x["pattern"], x["kind"]) for x in s["patterns"]}
        for raw in (text or "").splitlines()[:2000]:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            note = ""
            if "  #" in line:
                line, note = line.split("  #", 1)
                line, note = line.strip(), note.strip()
            k = kind
            for prefix in ("regex:", "starts:", "contains:", "ua:", "ip:"):   # the export's own prefixes round-trip
                if line.lower().startswith(prefix):
                    k, line = prefix[:-1], line[len(prefix):].strip()
                    break
            try:
                p, k = _check_pattern(line, k)
            except InstaBanError as exc:
                skipped.append(f"{line[:60]}: {exc}")
                continue
            if (p, k) in have:
                continue
            have.add((p, k))
            s["patterns"].append({"id": _pid(), "pattern": p, "kind": k, "note": note[:120], "added": int(time.time()), "hits": 0})
            added += 1
        save(s)
    return {"added": added, "skipped": skipped[:20], "total": len(s["patterns"])}


def delete_pattern(pid: str) -> dict:
    with _LOCK:
        s = load()
        before = len(s["patterns"])
        s["patterns"] = [x for x in s["patterns"] if x["id"] != pid]
        if len(s["patterns"]) == before:
            raise InstaBanError("No such pattern")
        save(s)
    return {"ok": True, "total": len(s["patterns"])}


def export_text() -> str:
    s = load()
    lines = ["# InstaBan patterns, one per line. Everything after two spaces and # is the note.", "# kind=contains unless the line starts with regex: or starts:"]
    for x in s["patterns"]:
        prefix = "" if x["kind"] == "contains" else f"{x['kind']}:"
        lines.append(f"{prefix}{x['pattern']}" + (f"  # {x['note']}" if x.get("note") else ""))
    return "\n".join(lines) + "\n"


def set_settings(enabled: bool | None = None, ttl: str | None = None, report: bool | None = None) -> dict:
    with _LOCK:
        s = load()
        if enabled is not None:
            s["enabled"] = bool(enabled)
        if ttl is not None:
            if ttl not in TTL_CHOICES:
                raise InstaBanError("Pick one of the ban lengths")
            s["ttl"] = ttl
        if report is not None:
            s["report"] = bool(report)
        if enabled and not s["files"]:
            _mark_log_ends(s)   # switching on: only requests from now on count, not months of old logs
        save(s)
    return settings()


def settings() -> dict:
    s = load()
    return {"enabled": s["enabled"], "ttl": s["ttl"], "ttl_seconds": TTL_CHOICES.get(s["ttl"], 86400), "report": s["report"],
            "ttl_choices": list(TTL_CHOICES), "stats": s["stats"], "last_scan": s["last_scan"], "pattern_count": len(s["patterns"]),
            "behavior": s["behavior"], "ports_source": _ports_source()}


def _ports_source() -> bool:
    """Port knocks come from the Network Monitor's connection log (Network -> Network Monitor -> logging)."""
    try:
        from . import netmon
        return bool(netmon.unit_state("aurora-netmon.service")["active"])
    except Exception:
        return False


def set_behavior(data: dict) -> dict:
    with _LOCK:
        s = load()
        for k in DEFAULT_BEHAVIOR:
            v = (data or {}).get(k)
            if not isinstance(v, dict):
                continue
            if "on" in v:
                s["behavior"][k]["on"] = bool(v["on"])
            for f, lo, hi in (("count", 3, 100000), ("window", 10, 3600)):
                if f in v:
                    try:
                        n = int(v[f])
                    except (TypeError, ValueError):
                        raise InstaBanError(f"{k}: {f} must be a number")
                    if not lo <= n <= hi:
                        raise InstaBanError(f"{k}: {f} must be between {lo} and {hi}")
                    s["behavior"][k][f] = n
        save(s)
    return settings()


def overview() -> dict:
    s = load()
    hits = list(reversed(s["hits"][-200:]))
    try:
        from . import abuse
        reported = set(abuse.reported().get("reported", {}).keys()) if hasattr(abuse, "reported") else set()
    except Exception:
        reported = set()
    for h in hits:
        h["reported"] = h.get("reported") or h["ip"] in reported
    day = int(time.time()) - 86400
    return {**settings(), "patterns": sorted(s["patterns"], key=lambda x: (-x.get("hits", 0), x["pattern"])), "hits": hits,
            "hits_24h": sum(1 for h in s["hits"] if h["ts"] >= day), "trusted": len(guard.trusted_cidrs()), "kinds": list(KINDS)}


def clear_hits() -> dict:
    with _LOCK:
        s = load()
        s["hits"] = []
        save(s)
    return {"ok": True}


# ---------------------------------------------------------------- matching
def _compiled(patterns: list[dict]) -> list[tuple[dict, object]]:
    out = []
    for p in patterns:
        if p["kind"] == "regex":
            try:
                out.append((p, re.compile(p["pattern"], re.I)))
            except re.error:
                continue
        else:
            out.append((p, None))
    return out


def match(target: str, compiled: list[tuple[dict, object]], ua: str = "", ip: str = "") -> dict | None:
    """The first pattern the request trips: its target (URL-decoded, lower-cased), its user agent or its address."""
    try:
        t = unquote(unquote(target))
    except Exception:
        t = target
    low = t.lower()
    ua_low = (ua or "").lower()
    addr = None
    for p, rx in compiled:
        k = p["kind"]
        if k == "ua":
            if ua_low and p["pattern"] in ua_low:
                return p
        elif k == "ip":
            if addr is None:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    addr = False
            if addr and addr in ipaddress.ip_network(p["pattern"]):
                return p
        elif rx is not None:
            if rx.search(t):
                return p
        elif k == "starts":
            if low.startswith(p["pattern"]):
                return p
        elif p["pattern"] in low:
            return p
    return None


# ---------------------------------------------------------------- behaviour: per-address counters in memory
_SEEN: dict[str, dict[str, list]] = {}   # ip -> {"errors": [(ts, None)...], "flood": [...], "ports": [(ts, port)...]}


def _note(kind: str, ip: str, now: float, window: int, value=None) -> int:
    """Record one event and return how many are inside the window (distinct values when a value is given)."""
    d = _SEEN.setdefault(ip, {})
    lst = d.setdefault(kind, [])
    lst.append((now, value))
    cutoff = now - window
    d[kind] = [x for x in lst if x[0] >= cutoff]
    if value is not None:
        return len({x[1] for x in d[kind]})
    return len(d[kind])


def _forget(now: float) -> None:
    for ip in list(_SEEN):
        if all(not v or v[-1][0] < now - 3600 for v in _SEEN[ip].values()):
            del _SEEN[ip]


def parse_line(line: str) -> dict | None:
    m = _LINE.match(line)
    if not m:
        return None
    req = m.group("req")
    parts = req.split(" ")
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else req
    return {"ip": m.group("ip"), "host": m.group("vhost") or "", "method": method[:10], "target": target[:600], "status": int(m.group("status")),
            "ua": (m.group("ua") or "")[:200]}


def _skip_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if a.is_loopback or a.is_unspecified:
        return True
    return guard.is_trusted(ip)


# ---------------------------------------------------------------- logs
def _logs() -> list[Path]:
    if not LOG_DIR.is_dir():
        return []
    return sorted(p for p in LOG_DIR.glob("*access*.log") if p.is_file())


def _mark_log_ends(s: dict) -> None:
    for p in _logs():
        try:
            st = p.stat()
            s["files"][str(p)] = {"ino": st.st_ino, "off": st.st_size}
        except OSError:
            pass


def _new_lines(s: dict, path: Path) -> list[str]:
    try:
        st = path.stat()
    except OSError:
        return []
    rec = s["files"].get(str(path))
    lines: list[str] = []
    if rec is None:
        start = st.st_size          # a log that appeared later: from now on
    elif rec["ino"] != st.st_ino:   # rotated: finish the old file first
        old = path.with_name(path.name + ".1")
        try:
            if old.exists() and old.stat().st_ino == rec["ino"]:
                with open(old, "rb") as f:
                    f.seek(rec["off"])
                    lines += f.read(MAX_READ).decode("utf-8", "replace").splitlines()
        except OSError:
            pass
        start = 0
    else:
        start = rec["off"] if rec["off"] <= st.st_size else 0
    try:
        with open(path, "rb") as f:
            f.seek(start)
            data = f.read(MAX_READ)
            end = start + len(data)
            cut = data.rfind(b"\n")
            if cut != len(data) - 1:
                end = start + cut + 1
                data = data[:cut + 1]
    except OSError:
        return lines
    s["files"][str(path)] = {"ino": st.st_ino, "off": end}
    return lines + data.decode("utf-8", "replace").splitlines()


def scan(now: int | None = None) -> dict:
    """Read what the access logs gained since the last pass and act on every match."""
    now = now or int(time.time())
    with _LOCK:
        s = load()
        if not s["enabled"]:
            s["last_scan"] = now
            save(s)
            return {"scanned": 0, "hits": 0, "bans": 0}
        compiled = _compiled(s["patterns"])
        scanned = hits = bans = 0
        banned_now: set[str] = set()
        for path in _logs():
            for line in _new_lines(s, path):
                scanned += 1
                rec = parse_line(line)
                if not rec:
                    continue
                p = match(rec["target"], compiled, rec["ua"], rec["ip"])
                why = ""
                if not p:
                    b = s["behavior"]
                    if rec["ip"] in banned_now:
                        continue
                    if b["flood"]["on"] and _note("flood", rec["ip"], now, b["flood"]["window"]) >= b["flood"]["count"]:
                        why = f"{b['flood']['count']} requests within {b['flood']['window']} s"
                    elif b["errors"]["on"] and 400 <= rec["status"] < 500 and _note("errors", rec["ip"], now, b["errors"]["window"]) >= b["errors"]["count"]:
                        why = f"{b['errors']['count']} error answers within {b['errors']['window']} s"
                    if not why:
                        continue
                hit = {"ts": now, "ip": rec["ip"], "host": rec["host"], "method": rec["method"], "target": rec["target"], "status": rec["status"],
                       "ua": rec["ua"], "pattern": p["pattern"] if p else why, "pattern_id": p["id"] if p else "", "kind": p["kind"] if p else "behavior",
                       "log": path.name, "banned": False, "reported": False, "error": ""}
                if p:
                    p["hits"] = p.get("hits", 0) + 1
                s["stats"]["hits"] += 1
                hits += 1
                if _skip_ip(rec["ip"]):
                    hit["error"] = "trusted or local address, not banned"
                elif rec["ip"] in banned_now:
                    hit["banned"] = True
                else:
                    try:
                        ttl = TTL_CHOICES.get(s["ttl"], 86400) or None
                        guard.ban(rec["ip"], f"InstaBan: {hit['pattern'][:60]}", duration=ttl, source="InstaBan")
                        hit["banned"] = True
                        bans += 1
                        s["stats"]["bans"] += 1
                    except guard.GuardError as exc:
                        hit["banned"] = "Already covered" in str(exc)
                        hit["error"] = "" if hit["banned"] else str(exc)[:160]
                    except Exception as exc:  # nft missing, helper broken: keep the evidence, say why
                        hit["error"] = str(exc)[:160]
                    banned_now.add(rec["ip"])
                    if s["report"] and hit["banned"]:
                        try:
                            from . import abuse
                            abuse.report(rec["ip"], note=f"InstaBan: requested {rec['target'][:120]} ({p['pattern'][:60]})")
                            hit["reported"] = True
                            s["stats"]["reports"] += 1
                        except Exception as exc:
                            hit["error"] = (hit["error"] + " · " if hit["error"] else "") + f"report: {str(exc)[:120]}"
                s["hits"].append(hit)
        # Port knocks: distinct ports one address touched, from the Network Monitor's connection log.
        pb = s["behavior"]["ports"]
        if pb["on"]:
            for ev in _port_events(now, s):
                if ev["src"] in banned_now or _note("ports", ev["src"], ev["ts"], pb["window"], ev["port"]) < pb["count"]:
                    continue
                ports = sorted({x[1] for x in _SEEN.get(ev["src"], {}).get("ports", [])})
                shown = ", ".join(str(x) for x in ports[:12]) + ("..." if len(ports) > 12 else "")
                hit = {"ts": now, "ip": ev["src"], "host": "", "method": "", "target": f"ports {shown}", "status": 0, "ua": "",
                       "pattern": f"{pb['count']} ports within {pb['window']} s", "pattern_id": "", "kind": "ports",
                       "log": "connections", "banned": False, "reported": False, "error": ""}
                s["stats"]["hits"] += 1
                hits += 1
                if _skip_ip(ev["src"]):
                    hit["error"] = "trusted or local address, not banned"
                else:
                    try:
                        ttl = TTL_CHOICES.get(s["ttl"], 86400) or None
                        guard.ban(ev["src"], f"InstaBan: {hit['pattern']}", duration=ttl, source="InstaBan")
                        hit["banned"] = True
                        bans += 1
                        s["stats"]["bans"] += 1
                    except guard.GuardError as exc:
                        hit["banned"] = "Already covered" in str(exc)
                        hit["error"] = "" if hit["banned"] else str(exc)[:160]
                    except Exception as exc:
                        hit["error"] = str(exc)[:160]
                    banned_now.add(ev["src"])
                s["hits"].append(hit)
        _forget(now)
        s["hits"] = s["hits"][-MAX_HITS:]
        s["last_scan"] = now
        save(s)
    return {"scanned": scanned, "hits": hits, "bans": bans}


def _port_events(now: float, s: dict) -> list[dict]:
    """New inbound connections since the last pass, from the kernel log the Network Monitor keeps."""
    try:
        from . import netmon
    except Exception:
        return []
    last_scan = s.get("last_scan") or (now - 30)
    try:
        rows = netmon.connections(max(15, min(3600, int(now - last_scan) + 5)))
    except Exception:
        return []
    last = s.get("ports_seen_ts", 0)
    out = [{"ts": r["ts"], "src": r["src"], "port": r["port"]} for r in rows if r.get("port") and r["ts"] > last]
    if rows:
        s["ports_seen_ts"] = max(r["ts"] for r in rows)
    return out


# ---------------------------------------------------------------- the background pass
_thread: threading.Thread | None = None


def start(interval: int = 10) -> None:
    global _thread
    if _thread and _thread.is_alive():
        return

    def loop():
        while True:
            time.sleep(interval)
            try:
                if load()["enabled"]:
                    scan()
            except Exception:
                pass

    _thread = threading.Thread(target=loop, name="instaban", daemon=True)
    _thread.start()
