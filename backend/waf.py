"""WAF firewall — ModSecurity 2 + the OWASP Core Rule Set (CRS) in front of Apache.

The panel owns two small files and leaves the packages' own files alone:
  /etc/modsecurity/zz-aurora-waf.conf   (read before the CRS) — engine mode, paranoia level,
        anomaly threshold, app exclusions, trusted IPs and sites with the WAF off;
  /etc/apache2/conf-available/zz-aurora-waf.conf   (read after the CRS) — rules switched off
        because they were false alarms ("Allow this rule").
/etc/modsecurity/modsecurity.conf is created from the package's recommended file once, with
JSON audit logging so the panel can show what was blocked and why.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

STATE = Path("/var/lib/aurora/waf.json")
MAIN = Path("/etc/modsecurity/modsecurity.conf")
RECOMMENDED = Path("/etc/modsecurity/modsecurity.conf-recommended")
PRE = Path("/etc/modsecurity/zz-aurora-waf.conf")
POST = Path("/etc/apache2/conf-available/zz-aurora-waf.conf")
AUDIT = Path("/var/log/apache2/modsec_audit.log")
CRS_LOAD = Path("/usr/share/modsecurity-crs/owasp-crs.load")
HEADER = "# Written by AuroraPanel (Security → WAF Firewall). Edit there — changes here are overwritten.\n"
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
APPS = {"wordpress": "WordPress", "nextcloud": "Nextcloud", "drupal": "Drupal", "dokuwiki": "DokuWiki",
        "phpmyadmin": "phpMyAdmin", "phpbb": "phpBB", "xenforo": "XenForo", "roundcube": "Webmail (Roundcube)"}
# Roundcube has no CRS exclusion package. Under /webmail/ its own login and CSRF tokens guard it, so the
# rule groups it trips by design are lifted there: remote-file-inclusion (a mail host like ssl://imap.gmail.com
# in the sign-in link looks like one), XSS and SQL injection (HTML mail being written and read).
ROUNDCUBE_RULE = ('SecRule REQUEST_URI "@beginsWith /webmail/" "id:1000103,phase:1,pass,nolog,t:none,'
                  'ctl:ruleRemoveById=931100-931199,ctl:ruleRemoveById=941100-941999,ctl:ruleRemoveById=942100-942999"')
# CRS bookkeeping rules: the score summary, not an attack type of their own.
_SUMMARY = {"949110", "959100", "980130", "980140", "980145", "959180"}
# Noise, not attacks: someone opened a site by its IP address (920350), which on its own never blocks.
_NOISE = {"920350"}


class WafError(RuntimeError):
    pass


def _run(argv, timeout=60, input=None):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input,
                              env={**os.environ, "PATH": PATH})
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def _default() -> dict:
    return {"mode": "block", "paranoia": 1, "threshold": 5, "apps": ["wordpress", "nextcloud", "drupal", "dokuwiki", "phpmyadmin", "roundcube"],
            "trusted": [], "sites_off": [], "disabled_rules": {}, "seen": []}


def load() -> dict:
    try:
        s = json.loads(STATE.read_text())
    except (OSError, ValueError):
        s = {}
    d = _default()
    d.update({k: v for k, v in s.items() if k in d})
    # An exception added in a later release is switched on once for installs that predate it.
    global _PENDING_APPLY
    if "roundcube" not in d.get("seen", []):
        d["seen"] = list(d.get("seen", [])) + ["roundcube"]
        if "roundcube" not in d["apps"]:
            d["apps"] = d["apps"] + ["roundcube"]
        _save(d)
        _PENDING_APPLY = True   # written into Apache's rules the next time the WAF page looks at its status
    return d


_PENDING_APPLY = False


def _save(s: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=1))


def installed() -> bool:
    return Path("/etc/apache2/mods-available/security2.load").exists() and CRS_LOAD.exists()


def module_on() -> bool:
    return Path("/etc/apache2/mods-enabled/security2.load").exists()


def render_pre(s: dict) -> str:
    engine = {"block": "On", "detect": "DetectionOnly", "off": "Off"}[s["mode"]]
    out = [HEADER, f"SecRuleEngine {engine}", ""]
    # CRS settings (ids 900000–900999 are reserved for the admin's setup).
    out.append(f'SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level={int(s["paranoia"])}"')
    out.append(f'SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold={int(s["threshold"])},'
               f'setvar:tx.outbound_anomaly_score_threshold=4"')
    apps = [a for a in s["apps"] if a in APPS and a != "roundcube"]
    if apps:
        out.append('SecAction "id:900130,phase:1,nolog,pass,t:none,' + ",".join(f"setvar:tx.crs_exclusions_{a}=1" for a in apps) + '"')
    if "roundcube" in s["apps"]:
        out.append(ROUNDCUBE_RULE)
    if s["trusted"]:
        out.append(f'SecRule REMOTE_ADDR "@ipMatch {",".join(s["trusted"])}" "id:1000101,phase:1,pass,nolog,ctl:ruleEngine=Off"')
    if s["sites_off"]:
        out.append(f'SecRule REQUEST_HEADERS:Host "@pmFromFile /etc/modsecurity/aurora-sites-off.txt" '
                   f'"id:1000102,phase:1,pass,nolog,t:lowercase,ctl:ruleEngine=Off"')
    return "\n".join(out) + "\n"


def render_post(s: dict) -> str:
    ids = sorted(s["disabled_rules"], key=lambda x: int(x))
    note = lambda i: re.sub(r"[^\x20-\x7e]", " ", str(s["disabled_rules"][i].get("msg", "")))[:80]
    body = "\n".join(f"    SecRuleRemoveById {int(i)}   # {note(i)}" for i in ids)
    return HEADER + "<IfModule security2_module>\n" + (body + "\n" if body else "    # no rules switched off\n") + "</IfModule>\n"


def _ensure_main() -> None:
    """modsecurity.conf from the package's recommendation, with JSON audit logs of what matched."""
    if not RECOMMENDED.exists():
        return
    text = MAIN.read_text() if MAIN.exists() else RECOMMENDED.read_text()
    text = re.sub(r"(?m)^SecRuleEngine .*$", "# SecRuleEngine is set by the panel in zz-aurora-waf.conf", text)
    text = re.sub(r"(?m)^SecAuditLogParts .*$", "SecAuditLogParts ABFHZ", text)
    if "SecAuditLogFormat" not in text:
        text += "\n# AuroraPanel: one JSON line per event, read by Security → WAF Firewall\nSecAuditLogFormat JSON\n"
    text = re.sub(r"(?m)^SecAuditEngine .*$", "SecAuditEngine RelevantOnly", text)
    # Requests are what attacks arrive in. Scanning every page the server sends back costs CPU on a Pi and would
    # copy response bodies (someone's webmail, say) into the audit log.
    text = re.sub(r"(?m)^SecResponseBodyAccess .*$", "SecResponseBodyAccess Off", text)
    MAIN.write_text(text)


def apply(s: dict | None = None) -> dict:
    s = s or load()
    if not installed():
        raise WafError("The WAF isn't installed yet")
    _ensure_main()
    Path("/etc/modsecurity/aurora-sites-off.txt").write_text("\n".join(s["sites_off"]) + "\n")
    old = {p: p.read_text() if p.exists() else None for p in (PRE, POST)}
    PRE.write_text(render_pre(s))
    POST.write_text(render_post(s))
    _run(["a2enmod", "-q", "security2"])
    _run(["a2enmod", "-q", "unique_id"])
    _run(["a2enconf", "-q", "zz-aurora-waf"])
    t = _run(["apache2ctl", "configtest"])
    if t.returncode != 0:
        for p, txt in old.items():
            if txt is None:
                p.unlink(missing_ok=True)
            else:
                p.write_text(txt)
        raise WafError("Apache rejected the WAF settings, nothing changed:\n" + t.stderr.strip()[-500:])
    _run(["systemctl", "reload", "apache2"])
    _save(s)
    return {"ok": True}


def setup() -> list[str]:
    """After the packages are installed: blocking mode, paranoia 1, the usual app exclusions."""
    s = load()
    apply(s)
    return ["• WAF on: OWASP Core Rule Set, blocking mode, paranoia level 1 (fewest false alarms)",
            f"• Exclusions for {', '.join(APPS[a] for a in s['apps'])} so their admin pages keep working"]


def status() -> dict:
    global _PENDING_APPLY
    if _PENDING_APPLY:
        _PENDING_APPLY = False
        if installed():
            try:
                apply()
            except Exception:
                pass
    s = load()
    crs_ver = ""
    r = _run(["dpkg-query", "-W", "-f=${Version}", "modsecurity-crs"])
    if r.returncode == 0:
        crs_ver = r.stdout.strip()
    ev = events(hours=24, limit=5000)
    blocked = sum(1 for e in ev if e["blocked"])
    by_type: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    for e in ev:
        m = _primary(e["rules"])
        by_type[m["category"]] = by_type.get(m["category"], 0) + 1
        by_ip[e["ip"]] = by_ip.get(e["ip"], 0) + 1
    return {"installed": installed(), "module_on": module_on(), "crs_version": crs_ver, **s, "apps_all": APPS,
            "stats": {"events": len(ev), "blocked": blocked, "detected": len(ev) - blocked,
                      "types": sorted(by_type.items(), key=lambda x: -x[1])[:6],
                      "ips": sorted(by_ip.items(), key=lambda x: -x[1])[:6]}}


def _primary(rules: list[dict]) -> dict:
    """The rule that says what the attack was — protocol checks (920xxx) only when nothing else matched."""
    return next((r for r in rules if not r["id"].startswith("920")), rules[0])


def _clean_ips(vals) -> list[str]:
    out = []
    for v in vals or []:
        v = str(v).strip()
        if not v:
            continue
        try:
            n = ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise WafError(f"“{v}” isn't an IP address or range")
        out.append(str(n.network_address) if n.num_addresses == 1 else str(n))
    return sorted(set(out))


def update(data: dict) -> dict:
    s = load()
    if "mode" in data:
        if data["mode"] not in ("block", "detect", "off"):
            raise WafError("Unknown mode")
        s["mode"] = data["mode"]
    if "paranoia" in data:
        s["paranoia"] = max(1, min(4, int(data["paranoia"])))
    if "threshold" in data:
        s["threshold"] = max(2, min(100, int(data["threshold"])))
    if "apps" in data:
        s["apps"] = [a for a in data["apps"] if a in APPS]
    if "trusted" in data:
        s["trusted"] = _clean_ips(data["trusted"])
    if "sites_off" in data:
        hosts = []
        for h in data["sites_off"] or []:
            h = str(h).strip().lower()
            if h and not re.match(r"^[a-z0-9.-]{1,253}(:\d+)?$", h):
                raise WafError(f"“{h}” isn't a host name")
            if h:
                hosts.append(h)
        s["sites_off"] = sorted(set(hosts))
    return apply(s)


def allow_rule(rule_id: str, msg: str = "") -> dict:
    s = load()
    if not re.match(r"^\d{3,7}$", str(rule_id)):
        raise WafError("Unknown rule")
    if str(rule_id) in _SUMMARY:
        raise WafError("That's the score summary, not a single rule — allow the rule that added the points")
    clean = re.sub(r"[^\x20-\x7e]", " ", msg or "")[:200]  # one printable line: it ends up in an Apache config comment
    s["disabled_rules"][str(rule_id)] = {"msg": clean, "since": int(time.time())}
    return apply(s)


def restore_rule(rule_id: str) -> dict:
    s = load()
    s["disabled_rules"].pop(str(rule_id), None)
    return apply(s)


_MSG = re.compile(r'\[id "(\d+)"\].*?\[msg "([^"]*)"\](?:.*?\[severity "([A-Z]+)"\])?')
_CATS = [("941", "XSS (cross-site scripting)"), ("942", "SQL injection"), ("930", "Path traversal / file access"),
         ("931", "Remote file inclusion"), ("932", "Command injection"), ("933", "PHP injection"), ("934", "Code injection"),
         ("944", "Java attack"), ("943", "Session fixation"), ("920", "Malformed request"), ("921", "HTTP smuggling"),
         ("913", "Scanner / bot"), ("911", "Disallowed method"), ("950", "Data leak"), ("951", "SQL error leak"),
         ("952", "Source code leak"), ("953", "PHP leak"), ("954", "Server error leak")]


def _category(rule_id: str) -> str:
    for p, name in _CATS:
        if rule_id.startswith(p):
            return name
    return "Other"


def events(hours: int = 24, limit: int = 300, ip: str = "") -> list[dict]:
    """Recent WAF events (newest first) from ModSecurity's JSON audit log."""
    if not AUDIT.exists():
        return []
    since = time.time() - hours * 3600
    try:
        with AUDIT.open("rb") as f:
            f.seek(max(0, AUDIT.stat().st_size - 20_000_000))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        tr, rq = d.get("transaction") or {}, d.get("request") or {}
        ts = _ts(tr.get("time", ""))
        if ts and ts < since:
            break
        rip = tr.get("remote_address", "")
        if ip and rip != ip:
            continue
        ad = d.get("audit_data") or {}
        rules = []
        for m in ad.get("messages") or []:
            mm = _MSG.search(m)
            if mm and mm.group(1) not in _SUMMARY and mm.group(1) not in _NOISE:
                rules.append({"id": mm.group(1), "msg": mm.group(2), "severity": mm.group(3) or "", "category": _category(mm.group(1))})
        if not rules:
            continue
        hdr = {k.lower(): v for k, v in (rq.get("headers") or {}).items()}
        rules.sort(key=lambda r: r["id"].startswith("920"))
        out.append({"ts": ts, "ip": rip, "host": hdr.get("host", ""), "request": (rq.get("request_line") or "")[:300],
                    "status": (d.get("response") or {}).get("status"), "blocked": bool((ad.get("action") or {}).get("intercepted")),
                    "rules": rules, "ua": hdr.get("user-agent", "")[:160], "id": tr.get("transaction_id", "")})
        if len(out) >= limit:
            break
    return out


def _ts(s: str) -> float:
    # "24/Oct/2026:12:34:56.123456 +0300"
    from datetime import datetime
    for fmt in ("%d/%b/%Y:%H:%M:%S.%f %z", "%d/%b/%Y:%H:%M:%S %z"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return 0.0


def test() -> dict:
    """Send a harmless fake attack to this server's own Apache and report what the WAF did."""
    import http.client
    import ssl
    path = "/?aurora_waf_test=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    code, err = None, ""
    # HTTPS first (sites usually redirect HTTP there, and a redirect happens before the WAF looks at the request).
    # It's this server talking to itself, so the certificate isn't checked.
    for conn in (lambda: http.client.HTTPSConnection("127.0.0.1", 443, timeout=10, context=ssl._create_unverified_context()),
                 lambda: http.client.HTTPConnection("127.0.0.1", 80, timeout=10)):
        try:
            c = conn()
            c.request("GET", path, headers={"User-Agent": "AuroraPanel WAF test", "Host": "localhost"})
            code = c.getresponse().status
            c.close()
            if code not in (301, 302, 307, 308):
                break
        except (OSError, http.client.HTTPException) as e:
            err = str(e)
    if code is None:
        raise WafError(f"Couldn't reach Apache on this server ({err})")
    mode = load()["mode"]
    blocked = code == 403
    if mode == "block":
        verdict = "Blocked — the WAF stopped the fake XSS attack." if blocked else f"Not blocked (HTTP {code}) — check that the WAF module is on."
    elif mode == "detect":
        verdict = f"Logged but let through (detect-only mode, HTTP {code}) — see the event below."
    else:
        verdict = f"The WAF is off (HTTP {code})."
    return {"status": code, "blocked": blocked, "mode": mode, "verdict": verdict}
