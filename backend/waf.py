"""WAF firewall — ModSecurity 2 + the OWASP Core Rule Set (CRS) in front of Apache.

The panel owns two small files and leaves the packages' own files alone:
  /etc/modsecurity/zz-aurora-waf.conf   (read before the CRS) — engine mode, paranoia level,
        anomaly threshold, app exclusions, trusted IPs and sites with the WAF off. The panel's
        Trusted addresses (IP Blocker & Trust) are exempt as well, so "trusted" means trusted everywhere;
  /etc/apache2/conf-available/zz-aurora-waf.conf   (read after the CRS) — rules switched off
        because they were false alarms ("Allow this rule").
/etc/modsecurity/modsecurity.conf is created from the package's recommended file once, with
JSON audit logging so the panel can show what was blocked and why.

InstaBan's list is enforced here as well. InstaBan itself reads the access log, which Apache writes after
it has answered, so on its own the first request for a listed path is served before the ban lands. The same
list is part of the WAF's rules, so a firewall that is Blocking refuses the request before anything is
served, whether or not the address is banned afterwards (that is the Auto-ban switch).
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

from . import distro
from . import problems

STATE = Path("/var/lib/aurora/waf.json")
MAIN = Path("/etc/modsecurity/modsecurity.conf")
RECOMMENDED = Path("/etc/modsecurity/modsecurity.conf-recommended")
PRE = Path("/etc/modsecurity/zz-aurora-waf.conf")
POST = Path("/etc/apache2/conf-available/zz-aurora-waf.conf")
AUDIT = Path("/var/log/apache2/modsec_audit.log")
CRS_LOAD = Path("/usr/share/modsecurity-crs/owasp-crs.load")
HEADER = "# Written by AuroraPanel (Security → InstaWAFF). Edit there — changes here are overwritten.\n"
PATH = distro.PATH
APPS = {"wordpress": "WordPress", "nextcloud": "Nextcloud", "drupal": "Drupal", "dokuwiki": "DokuWiki",
        "phpmyadmin": "phpMyAdmin", "phpbb": "phpBB", "xenforo": "XenForo", "roundcube": "Webmail (Roundcube)"}
# Webmail is never blocked by the WAF. Roundcube has its own sign-in, CSRF tokens and HTML sanitiser, and
# the Core Rule Set reads its ordinary traffic as attacks (a mail host in the sign-in link, its pre-encoded
# _url field, HTML mail being written). Under /webmail/ the engine only watches: attempts still show up
# on the WAF page, nobody is refused. Switch the "Webmail (Roundcube)" exception off to block there too.
# Webmail is watched, never blocked, and the WAF doesn't read what is posted there: a letter that quotes an abuse
# report (".env", ".git", URL-encoded links) is text, not an attack, and scanning a long message body could
# cost a send (a false alarm, or an Apache child lost on a huge regex match, which Roundcube shows as
# "Connection Error (Failed to reach the server)"). The address, query and headers are still checked.
ROUNDCUBE_RULE = ('SecRule REQUEST_URI "@beginsWith /webmail/" '
                  '"id:1000103,phase:1,pass,nolog,t:none,ctl:ruleEngine=DetectionOnly,ctl:requestBodyAccess=Off"')
# Without the Roundcube exception the WAF still checks webmail, but never the letters themselves.
WEBMAIL_BODY_RULE = ('SecRule REQUEST_URI "@beginsWith /webmail/" '
                     '"id:1000104,phase:1,pass,nolog,t:none,ctl:requestBodyAccess=Off"')
# Bump when the rules the panel renders change: an install that still has older rules in Apache rewrites
# them once (at start, and when the WAF page is opened), so a shipped exception never stays on paper.
RULES_REV = 10
# InstaBan's list as the WAF reads it: one entry per line (paths and payloads, user agents, addresses).
IB_PATHS = PRE.with_name("aurora-instaban-paths.txt")
IB_UA = PRE.with_name("aurora-instaban-agents.txt")
IB_IPS = PRE.with_name("aurora-instaban-addresses.txt")
IB_RX_CHUNK = 1500   # characters of pattern per "starts with" rule, so no config line grows without end
IB_CATEGORY = "Ban list"
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
            "trusted": [], "sites_off": [], "disabled_rules": {}, "seen": [], "rules_rev": 0, "server_ips": []}


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
        try:
            _save(d)
        except OSError:   # no state folder or read-only (a test runner without root): still answer
            pass
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


def _panel_trusted() -> list[str]:
    """The panel's Trusted addresses (IP Blocker & Trust): never blocked by anything, the WAF included.
    The owner's own machine is usually among them, and opening a site by its IP address from there
    (numeric Host header, an IP in WordPress's redirect_to) must not end in a 403."""
    try:
        from . import guard
        return _clean_ips(guard.trusted_cidrs())
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return []


def instaban_lists() -> dict:
    """InstaBan's list by kind: the firewall enforces it whenever it is on, with or without automatic bans.
    Read once per apply, so the rules and the list files they point at always describe the same list."""
    try:
        from . import instaban
        ib = instaban.load()
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return {}
    out: dict[str, list[str]] = {}
    for p in ib.get("patterns", []):
        text = str(p.get("pattern", ""))
        if text and not any(ord(c) < 32 for c in text):
            out.setdefault(str(p.get("kind")), []).append(text)
    return out


def instaban_files(ib: dict) -> dict:
    """The list files the rules read. A line that starts with # would be a comment there, so such a pattern is
    left to InstaBan's own log reading."""
    addresses = []
    for v in ib.get("ip", []):
        try:
            addresses += _clean_ips([v])
        except WafError:
            continue
    lines = lambda vals: "".join(f"{v}\n" for v in vals if not v.startswith("#"))
    return {IB_PATHS: lines(ib.get("contains", [])), IB_UA: lines(ib.get("ua", [])), IB_IPS: lines(addresses)}


_BACKSLASH = chr(92)
_RX_CODES = {_BACKSLASH: r"\x5c", '"': r"\x22", "%": r"\x25"}


def _rx_literal(text: str) -> str:
    """Plain text as a regular expression with nothing in it that a config file could misread."""
    return "".join(c if c.isascii() and (c.isalnum() or c in "/_-") else "".join(rf"\x{b:02x}" for b in c.encode()) for c in text)


def _rx_portable(rx: str) -> str:
    """Someone's own regular expression, safe inside a quoted rule. Apache and Nginx each read an escaped
    backslash and an escaped quote their own way, and ModSecurity expands %{...}, so a literal backslash, a
    quote and a percent sign are written as character codes."""
    out, i = [], 0
    while i < len(rx):
        c = rx[i]
        if c == _BACKSLASH and i + 1 < len(rx):
            out.append(_RX_CODES.get(rx[i + 1], c + rx[i + 1]))
            i += 2
            continue
        out.append(c if c == _BACKSLASH else _RX_CODES.get(c, c))
        i += 1
    return "".join(out)


def _instaban_rules(ib: dict, regex: bool = True) -> list[str]:
    """Refuse what is on InstaBan's list before it is served. Phase 1, so it comes ahead of redirects and of
    the file itself; Detect only logs it, like every other rule. Matching follows InstaBan: the address as
    sent and URL-decoded twice, lower-cased."""
    files = instaban_files(ib)
    act = lambda rid, what, t: (f'"id:{rid},phase:1,deny,status:403,log,auditlog,{t},'
                                f"msg:'InstaBan: {what}',severity:'CRITICAL',tag:'aurora-instaban'\"")
    decoded = "t:none,t:urlDecodeUni,t:urlDecodeUni"
    out = []
    if files[IB_IPS]:
        out.append(f'SecRule REMOTE_ADDR "@ipMatchFromFile {IB_IPS.as_posix()}" ' + act(1000110, "address on the list", "t:none"))
    if files[IB_UA]:
        out.append(f'SecRule REQUEST_HEADERS:User-Agent "@pmFromFile {IB_UA.as_posix()}" ' + act(1000111, "scanner user agent", "t:none,t:lowercase"))
    if files[IB_PATHS]:
        out.append(f'SecRule REQUEST_URI "@pmFromFile {IB_PATHS.as_posix()}" ' + act(1000112, "path or payload on the list", "t:none,t:lowercase"))
        out.append(f'SecRule REQUEST_URI "@pmFromFile {IB_PATHS.as_posix()}" ' + act(1000113, "path or payload on the list", decoded + ",t:lowercase"))
    starts = [_rx_literal(v) for v in ib.get("starts", [])]
    chunk, size, rid = [], 0, 1001000
    for n, v in enumerate(starts):
        chunk.append(v)
        size += len(v)
        if size >= IB_RX_CHUNK or n == len(starts) - 1:
            out.append(f'SecRule REQUEST_URI "@rx ^(?:{"|".join(chunk)})" ' + act(rid, "path on the list", decoded + ",t:lowercase"))
            chunk, size, rid = [], 0, rid + 1
    if regex:
        for n, v in enumerate(ib.get("regex", [])):
            out.append(f'SecRule REQUEST_URI "@rx (?i){_rx_portable(v)}" ' + act(1002000 + n, "pattern on the list", decoded))
    return out


_OWN = {"at": 0.0, "ip": None}


def server_ips(s: dict | None = None) -> list[str]:
    """This server's own addresses: a site that calls itself (WordPress cron, a health check, a webhook to its
    own name) must never be refused or banned. Remembered in the settings, so the exception holds when the
    address can't be read for a moment (network restarting); replaced when the server gets another address."""
    known = list((s or {}).get("server_ips") or [])
    if time.monotonic() - _OWN["at"] > 60 or not _OWN["at"]:   # asked for every hit InstaBan looks at: look it up once a minute
        try:
            from . import guard
            _OWN.update(at=time.monotonic(), ip=guard.default_route().get("ip"))
        except Exception as quiet_exc:
            problems.quiet(quiet_exc)
            _OWN.update(at=time.monotonic(), ip=None)
    now = _OWN["ip"]
    try:
        return _clean_ips([now]) if now else _clean_ips(known)
    except WafError:
        return []


def render_pre(s: dict, ib: dict | None = None, regex: bool = True) -> str:
    engine = {"block": "On", "detect": "DetectionOnly", "off": "Off"}[s["mode"]]
    out = [HEADER, f"SecRuleEngine {engine}", ""]
    # CRS settings (ids 900000–900999 are reserved for the admin's setup).
    out.append(f'SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level={int(s["paranoia"])},setvar:tx.blocking_paranoia_level={int(s["paranoia"])}"')  # CRS 3 reads the first, CRS 4 only the second
    out.append(f'SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold={int(s["threshold"])},'
               f'setvar:tx.outbound_anomaly_score_threshold=4"')
    apps = [a for a in s["apps"] if a in APPS and a != "roundcube"]
    if apps:
        out.append('SecAction "id:900130,phase:1,nolog,pass,t:none,' + ",".join(f"setvar:tx.crs_exclusions_{a}=1" for a in apps) + '"')
    out.append(ROUNDCUBE_RULE if "roundcube" in s["apps"] else WEBMAIL_BODY_RULE)
    # Single addresses go in bare: ModSecurity refuses "a.b.c.d/32" in an @ipMatch list.
    trusted = sorted(set(s["trusted"]) | set(_clean_ips(_panel_trusted())) | set(server_ips(s)))
    if trusted:
        out.append(f'SecRule REMOTE_ADDR "@ipMatch {",".join(trusted)}" "id:1000101,phase:1,pass,nolog,ctl:ruleEngine=Off"')
    if s["sites_off"]:
        out.append(f'SecRule REQUEST_HEADERS:Host "@pmFromFile /etc/modsecurity/aurora-sites-off.txt" '
                   f'"id:1000102,phase:1,pass,nolog,t:lowercase,ctl:ruleEngine=Off"')
    # Last, so trusted addresses, sites with the WAF off and webmail's watch-only rule have had their say.
    out += _instaban_rules(instaban_lists() if ib is None else ib, regex)
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
        text += "\n# AuroraPanel: one JSON line per event, read by Security → InstaWAFF\nSecAuditLogFormat JSON\n"
    text = re.sub(r"(?m)^SecAuditEngine .*$", "SecAuditEngine RelevantOnly", text)
    # Requests are what attacks arrive in. Scanning every page the server sends back costs CPU on a Pi and would
    # copy response bodies (someone's webmail, say) into the audit log.
    text = re.sub(r"(?m)^SecResponseBodyAccess .*$", "SecResponseBodyAccess Off", text)
    MAIN.write_text(text)


def _refresh_nginx() -> None:
    """Nginx's WAF uses these same settings. A problem there mustn't undo what Apache just accepted."""
    try:
        from . import nginxwaf
        nginxwaf.refresh()
    except Exception as exc:  # noqa: BLE001
        problems.record("WAF for Nginx", exc, hint="Nginx kept its previous WAF settings. Open Nginx Websites to see why.")


def apply(s: dict | None = None) -> dict:
    s = s or load()
    if not installed():
        raise WafError("The WAF isn't installed yet")
    s["server_ips"] = server_ips(s)   # remembered with the settings
    _ensure_main()
    Path("/etc/modsecurity/aurora-sites-off.txt").write_text("\n".join(s["sites_off"]) + "\n")
    ib = instaban_lists()
    lists = instaban_files(ib)
    old = {p: p.read_text(encoding="utf-8") if p.exists() else None for p in (PRE, POST, *lists)}
    for p, text in lists.items():
        p.write_text(text, encoding="utf-8")
    PRE.write_text(render_pre(s, ib), encoding="utf-8")
    POST.write_text(render_post(s), encoding="utf-8")
    _run(["a2enmod", "-q", "security2"])
    _run(["a2enmod", "-q", "unique_id"])
    _run(["a2enconf", "-q", "zz-aurora-waf"])
    t = _run(["apache2ctl", "configtest"])
    if t.returncode != 0 and ib.get("regex"):
        # A regular expression Python accepts and Apache doesn't must not take the rest of the WAF down with it.
        refused = t.stderr.strip()[-300:]
        PRE.write_text(render_pre(s, ib, regex=False), encoding="utf-8")
        t = _run(["apache2ctl", "configtest"])
        if t.returncode == 0:
            problems.record("WAF and InstaBan", "Apache refused one of InstaBan's regular expressions:\n" + refused,
                            hint="The rest of the list is enforced by the WAF. InstaBan still bans on these patterns from the access log.")
    if t.returncode != 0:
        for p, txt in old.items():
            if txt is None:
                p.unlink(missing_ok=True)
            else:
                p.write_text(txt, encoding="utf-8")
        raise WafError("Apache rejected the WAF settings, nothing changed:\n" + t.stderr.strip()[-500:])
    _run(["systemctl", "reload", "apache2"])
    _save(s)
    _refresh_nginx()
    return {"ok": True}


def setup() -> list[str]:
    """After the packages are installed: blocking mode, paranoia 1, the usual app exclusions."""
    s = load()
    apply(s)
    return ["• WAF on: OWASP Core Rule Set, blocking mode, paranoia level 1 (fewest false alarms)",
            f"• Exclusions for {', '.join(APPS[a] for a in s['apps'])} so their admin pages keep working"]


def refresh_rules() -> bool:
    """Rewrite Apache's rules when the panel's rendering moved on (RULES_REV) or an exception was added
    (load() flags it). True when a rewrite happened. Nothing is done without ModSecurity installed."""
    global _PENDING_APPLY
    s = load()   # may flag an exception that still has to reach Apache
    due = _PENDING_APPLY or int(s.get("rules_rev", 0)) != RULES_REV
    _PENDING_APPLY = False
    if not due or not installed() or not module_on():
        return False
    try:
        apply(s)
    except Exception as exc:
        # Apache kept the old rules: say so where the owner looks, instead of pretending it worked.
        problems.record("WAF rules", exc, hint="Open Security → InstaWAFF and press Apply to see Apache's answer.")
        return False
    s["rules_rev"] = RULES_REV
    try:
        _save(s)
    except OSError:
        pass
    return True


def status() -> dict:
    refresh_rules()
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
            "server_ips": server_ips(s), "panel_trusted": _panel_trusted(),
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


def _arm_instaban() -> None:
    """Blocking means bans too. Reporting stays as its switch says, and the ban list can still be turned off."""
    try:
        from . import instaban
        instaban.set_settings(enabled=True)
    except Exception as exc:  # noqa: BLE001
        problems.record("WAF Blocking → InstaBan", exc, hint="The WAF is blocking, but InstaBan didn't switch on. Open Security → InstaWAFF and turn the ban list on.")


def update(data: dict) -> dict:
    s = load()
    was = s["mode"]
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
    out = apply(s)
    if s["mode"] == "block" and was != "block":
        _arm_instaban()
    return out


def allow_rule(rule_id: str, msg: str = "") -> dict:
    s = load()
    if not re.match(r"^\d{3,7}$", str(rule_id)):
        raise WafError("Unknown rule")
    if _category(str(rule_id)) == IB_CATEGORY:
        raise WafError("That's InstaBan's list. Remove the pattern under Security → InstaWAFF, Detection, instead")
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
         ("952", "Source code leak"), ("953", "PHP leak"), ("954", "Server error leak"), ("100", IB_CATEGORY)]


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
    # "24/Oct/2026:12:34:56.123456 +0300". West of Greenwich ModSecurity 2 writes the sign twice ("--0800"),
    # which no parser accepts: without this every event lost its time, and with it the 1 h / 24 h / 7 day periods.
    from datetime import datetime
    s = re.sub(r" ([+-])[+-](\d{4})$", r" \g<1>\g<2>", s or "")
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
    s = load()
    mode = s["mode"]
    blocked = code == 403
    # The test comes from this server itself. If loopback was made a trusted address, the firewall lets it through.
    exempt = False
    for net in list(s["trusted"]) + _panel_trusted():
        try:
            exempt = exempt or ipaddress.ip_address("127.0.0.1") in ipaddress.ip_network(net, strict=False)
        except ValueError:
            continue
    if mode == "block":
        verdict = ("Blocked: the firewall stopped the fake XSS attack." if blocked
                   else f"Let through (HTTP {code}) because 127.0.0.1 is a trusted address, and this test comes from the server itself. Remove 127.0.0.1 under IP Blocker & Trust, then test again." if exempt
                   else f"Not blocked (HTTP {code}): check that the firewall module is on.")
    elif mode == "detect":
        verdict = f"Logged but let through (Detect only, HTTP {code}): see it under Attacks."
    else:
        verdict = f"The firewall is off (HTTP {code})."
    return {"status": code, "blocked": blocked, "mode": mode, "verdict": verdict}
