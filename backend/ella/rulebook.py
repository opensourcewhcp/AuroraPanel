"""Stage 3: WAF Ella's own rules. A rule is a tree of conditions, compiled to ModSecurity for Apache (v2) and Nginx (v3).

The file is loaded after the panel's settings and before the Core Rule Set, so an exception is in force before the rules it
touches run, and a block here ends the request before the rule set spends time on it. Rules start in detect mode, and
every change is versioned. ModSecurity has no OR across a chain, so a tree is expanded into one chain per way it can match.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from pathlib import Path

ID_RULES, ID_EXCEPTIONS, ID_POLICY, ID_ATTACK, ID_HONEYPOT, ID_CMS = 1100000, 1180000, 1170000, 1175000, 1190000, 1191000
ID_PATCH_MIN, ID_PATCH_MAX = 1150000, 1169999
APACHE_FILE, NGINX_FILE = "/etc/modsecurity/zz-ella-rules.conf", "/etc/nginx/aurora-waf/ella.conf"
HEADER = "# Written by AuroraPanel (WAF Ella). Edit there: changes here are overwritten.\n"
MODES = ("off", "detect", "block")
ACTIONS = ("log", "block")
STATUSES = (403, 404, 429, 503)
MAX_WAYS, MAX_CONDITIONS, MAX_VALUE = 16, 8, 400

HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
ARG_NAME = re.compile(r"^[\w.\[\]-]{1,64}$")
DOMAIN = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
_NESTED = re.compile(r"\([^()]*[+*][^()]*\)[+*{]|\(\?[^)]*\)[+*]{2}|\(([^()|]+)\|\1\)[+*]")
_PATH_T = "t:none,t:urlDecodeUni,t:normalizePath"
# field: (ModSecurity variable, transformations, what stored events keep for the preview)
FIELDS = {
    "ip": ("REMOTE_ADDR", "t:none", "client_ip"), "host": ("REQUEST_HEADERS:Host", "t:none,t:lowercase", "domain"), "path": ("REQUEST_FILENAME", _PATH_T, "url"),
    "method": ("REQUEST_METHOD", "t:none", "method"), "user_agent": ("REQUEST_HEADERS:User-Agent", "t:none", "user_agent"), "referer": ("REQUEST_HEADERS:Referer", "t:none", "header:referer"),
    "origin": ("REQUEST_HEADERS:Origin", "t:none", "header:origin"), "content_type": ("REQUEST_HEADERS:Content-Type", "t:none,t:lowercase", "header:content-type"),
    "size": ("REQUEST_HEADERS:Content-Length", "t:none", None), "query": ("QUERY_STRING", "t:none,t:urlDecodeUni", None),
}
PREFIXED = {"header": "REQUEST_HEADERS", "arg": "ARGS", "query_arg": "ARGS_GET", "body_arg": "ARGS_POST"}
OPERATORS = {"equals": "@streq", "contains": "@contains", "prefix": "@beginsWith", "suffix": "@endsWith", "regex": "@rx", "in_list": "@pm", "cidr": "@ipMatch", "gt": "@gt", "ge": "@ge", "lt": "@lt", "le": "@le", "eq": "@eq"}
PRESENCE = ("exists", "missing")
NUMERIC = ("gt", "ge", "lt", "le", "eq")


class RuleError(ValueError):
    pass


# ----------------------------------------------------------------------------- checking what an operator typed
def safe_value(value, what: str = "Value") -> str:
    text = str(value if value is not None else "")
    if len(text) > MAX_VALUE:
        raise RuleError(f"{what} is too long ({MAX_VALUE} characters at most)")
    if re.search(r"[\x00-\x1f\x7f]", text):
        raise RuleError(f"{what} has control characters in it")
    if "%{" in text:
        raise RuleError(f"{what} can't contain %{{, which ModSecurity would expand")
    return text


def _quote(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _rx_quote(text: str) -> str:
    return text.replace('"', '\\"')  # backslashes stay: they are the pattern's own


def check_regex(pattern: str) -> str:
    pattern = safe_value(pattern, "Pattern")
    if not pattern:
        raise RuleError("The pattern is empty")
    if _NESTED.search(pattern):
        raise RuleError("That pattern has a repeat inside a repeat, which can hang on hostile input")
    if re.search(r"\\[1-9]|\(\?<?[=!]", pattern):
        raise RuleError("Backreferences and lookaround aren't allowed in patterns: their run time can't be limited")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise RuleError(f"That pattern doesn't parse: {exc}") from exc
    return pattern


def _ip_list(value) -> list[str]:
    items = value if isinstance(value, list) else re.split(r"[\s,]+", str(value or "").strip())
    out = []
    for raw in items:
        if not raw:
            continue
        try:
            n = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError as exc:
            raise RuleError(f"Not an IP address or range: {raw}") from exc
        out.append(str(n.network_address) if n.num_addresses == 1 else str(n))
    if not out or len(out) > 500:
        raise RuleError("Give between 1 and 500 addresses")
    return out


def check_condition(cond: dict) -> dict:
    field, op = str(cond.get("field") or ""), str(cond.get("op") or "")
    name = cond.get("name")
    if field in PREFIXED:
        rule = HEADER_NAME if field == "header" else ARG_NAME
        if not rule.match(str(name or "")):
            raise RuleError(f"Bad {'header' if field == 'header' else 'parameter'} name: {name!r}")
    elif field not in FIELDS:
        raise RuleError(f"Unknown field: {field!r}. {'Rates and country checks act on logs, as Automatic bans, not inside a rule.' if field in ('rate', 'geo', 'asn') else ''}".strip())
    if op not in OPERATORS and op not in PRESENCE:
        raise RuleError(f"Unknown check: {op!r}")
    out = {"field": field, "op": op}
    if name:
        out["name"] = str(name)
    if op in PRESENCE:
        if field in FIELDS and field not in ("referer", "origin", "content_type", "user_agent", "size", "query"):
            raise RuleError(f"{field} is always there, so exists and missing mean nothing for it")
        return out
    value = cond.get("value")
    if op == "cidr":
        if field != "ip":
            raise RuleError("Only the client address can be checked against a range")
        out["value"] = _ip_list(value)
    elif field == "ip":
        raise RuleError("Check the client address with the range check")
    elif op in NUMERIC:
        if not re.fullmatch(r"\d{1,12}", str(value or "")):
            raise RuleError("That check needs a whole number")
        out["value"] = str(value)
    elif op == "regex":
        out["value"] = check_regex(value)
    elif op == "in_list":
        words = value if isinstance(value, list) else re.split(r"[\s,]+", str(value or "").strip())
        words = [safe_value(w) for w in words if w]
        if not words or len(words) > 200 or any('"' in w or " " in w for w in words):
            raise RuleError("A list takes 1 to 200 words without spaces or quotes")
        out["value"] = words
    else:
        text = safe_value(value)
        if not text:
            raise RuleError("A value is needed")
        out["value"] = text
    return out


def check_tree(node: dict, depth: int = 0) -> dict:
    """{"all": [...]}, {"any": [...]}, {"not": node}, or one condition."""
    if not isinstance(node, dict) or depth > 6:
        raise RuleError("Conditions are nested too deeply")
    for key in ("all", "any"):
        if key in node:
            kids = node[key]
            if not isinstance(kids, list) or not kids:
                raise RuleError("A group needs at least one condition")
            return {key: [check_tree(k, depth + 1) for k in kids]}
    if "not" in node:
        return {"not": check_tree(node["not"], depth + 1)}
    return check_condition(node)


def ways(node: dict, negate: bool = False) -> list[list[dict]]:
    """Every way the tree can match: a list of AND-ed conditions, each possibly negated."""
    if "not" in node:
        return ways(node["not"], not negate)
    key = "all" if "all" in node else "any" if "any" in node else None
    if key is None:
        return [[{**node, "negate": negate}]]
    kids = [ways(k, negate) for k in node[key]]
    if (key == "any") != negate:
        return [w for k in kids for w in k][:MAX_WAYS + 1]
    out: list[list[dict]] = [[]]
    for k in kids:
        out = [a + b for a in out for b in k]
        if len(out) > MAX_WAYS:
            raise RuleError(f"These conditions expand to more than {MAX_WAYS} rules. Simplify them.")
    return out


# ----------------------------------------------------------------------------- compiling
def _var(cond: dict) -> tuple[str, str]:
    if cond["field"] in PREFIXED:
        return f"{PREFIXED[cond['field']]}:{cond['name']}", "t:none"
    return FIELDS[cond["field"]][0], FIELDS[cond["field"]][1]


def _secrule(cond: dict) -> tuple[str, str, str]:
    """(variable, quoted operator, transformations)"""
    var, t = _var(cond)
    bang = "!" if cond.get("negate") else ""
    if cond["op"] in PRESENCE:
        want = (cond["op"] == "exists") != bool(cond.get("negate"))
        return f"&{var}", f'"@{"gt" if want else "eq"} 0"', "t:none"
    value = cond["value"]
    if cond["op"] == "cidr":
        text = ",".join(value)
    elif cond["op"] == "in_list":
        text = " ".join(value)
    elif cond["op"] == "regex":
        return var, f'"{bang}@rx {_rx_quote(value)}"', t
    else:
        text = _quote(str(value))
    return var, f'"{bang}{OPERATORS[cond["op"]]} {text}"', t


def host_rx(domains: list[str]) -> str:
    parts = [(r"(?:[^.]+\.)*" + re.escape(d[2:])) if d.startswith("*.") else re.escape(d) for d in domains]
    return "^(?:" + "|".join(parts) + r")(?::\d+)?$"


def _chain(first_id: int, head: str, conds: list[tuple[str, str, str]]) -> list[str]:
    lines = []
    for i, (var, op, t) in enumerate(conds):
        more = i < len(conds) - 1
        if i == 0:
            lines.append(f'SecRule {var} {op} "id:{first_id},{head},{t}{",chain" if more else ""}"')
        else:
            lines.append(f'    SecRule {var} {op} "{t}{",chain" if more else ""}"')
    return lines


def _scope_conds(domains: list[str], path: str) -> list[tuple[str, str, str]]:
    out = []
    if domains:
        out.append(("REQUEST_HEADERS:Host", f'"@rx {host_rx(domains)}"', "t:none,t:lowercase"))
    if path:
        out.append(("REQUEST_FILENAME", f'"@beginsWith {_quote(path)}"', _PATH_T))
    return out


def _disruptive(mode: str, action: str, status: int) -> str:
    return f"deny,status:{int(status)}" if mode == "block" and action == "block" else "pass"


def _msg(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9 ._:/-]", " ", name)[:80]


def render_tree_rule(base_id: int, name: str, tree: dict, domains: list[str], path: str, mode: str, action: str, status: int, tag: str) -> list[str]:
    all_ways = ways(tree)
    if len(all_ways) > MAX_WAYS:
        raise RuleError(f"These conditions expand to more than {MAX_WAYS} rules. Simplify them.")
    head = f"phase:2,{_disruptive(mode, action, status)},log,msg:'Ella: {_msg(name)}',tag:'{tag}',severity:'WARNING'"
    lines = []
    for n, way in enumerate(all_ways):
        if len(way) > MAX_CONDITIONS:
            raise RuleError(f"One way of matching has more than {MAX_CONDITIONS} conditions. Simplify it.")
        lines += _chain(base_id + n, head, [*_scope_conds(domains, path), *[_secrule(c) for c in way]])
    return lines


def render_exception(ex: dict) -> list[str]:
    """The narrowest thing that works: this rule, this variable, this path, this site. Runs in phase 1, before the rule set."""
    rid = int(ex["rule_id"])
    ctl = f"ctl:ruleRemoveTargetById={rid};{ex['var']}" if ex.get("var") else f"ctl:ruleRemoveById={rid}"
    conds = _scope_conds([ex["domain"]], ex["path"])
    lines = _chain(ID_EXCEPTIONS + int(ex["id"]), "phase:1,pass,nolog", conds)
    lines[-1] = lines[-1][:-1] + f',{ctl}"'
    return lines


def check_exception(rule_id, var, domain, path) -> dict:
    rule_id = str(rule_id or "")
    if not re.fullmatch(r"\d{1,8}", rule_id):
        raise RuleError("Rule ID must be a number")
    domain = str(domain or "").strip().lower()
    if not DOMAIN.match(domain):
        raise RuleError("An exception needs one domain. A whole-server exception isn't offered here.")
    path = safe_value(path or "", "Path")
    if not path.startswith("/") or '"' in path or " " in path:
        raise RuleError("Path must start with / and have no spaces or quotes")
    var = str(var or "") or None
    if var and not re.fullmatch(r"(ARGS|ARGS_GET|ARGS_POST|REQUEST_COOKIES|REQUEST_HEADERS)(:[\w.\[\]-]{1,128})|REQUEST_URI|REQUEST_FILENAME|QUERY_STRING|REQUEST_BODY|ARGS_NAMES|REQUEST_COOKIES_NAMES", var):
        raise RuleError(f"Can't make an exception for this variable: {var}")
    return {"rule_id": rule_id, "var": var, "domain": domain, "path": path}


def suggest_exception(event: dict, evidence: dict) -> dict:
    """False Positive Wizard: from one rule hit on one event, the narrowest exception, with the file text it would add."""
    var = evidence.get("matched_var_name") or None
    if var and not re.fullmatch(r"(ARGS|ARGS_GET|ARGS_POST|REQUEST_COOKIES|REQUEST_HEADERS)(:[\w.\[\]-]{1,128})|REQUEST_URI|REQUEST_FILENAME|QUERY_STRING|REQUEST_BODY|ARGS_NAMES|REQUEST_COOKIES_NAMES", var):
        var = None
    if not event.get("domain"):
        raise RuleError("This event has no domain, so it can't get a one-site exception.")
    ex = check_exception(evidence.get("rule_id"), var, event["domain"], event.get("url") or "/")
    warnings = []
    if not var:
        warnings.append("This event doesn't say what the rule matched, so the exception switches the whole rule off for this path. That's wider than the minimum.")
    if ex["path"] == "/":
        warnings.append("The path is /, which covers the whole site. Narrow it if you can.")
    return {**ex, "warnings": warnings, "preview": "\n".join(render_exception({**ex, "id": 0}))}


# ----------------------------------------------------------------------------- matching stored events: the preview
def _event_value(event: dict, field: str, name: str | None):
    """(known, value). known is False when events don't keep this, so a match can't be claimed either way."""
    if field in PREFIXED:
        if field == "header":
            return (name.lower() in ("host", "user-agent", "referer", "origin", "content-type", "x-forwarded-for")), _headers(event).get(name.lower())
        return False, None
    src = FIELDS[field][2]
    if src is None:
        return False, None
    if src.startswith("header:"):
        return True, _headers(event).get(src[7:])
    return True, event.get(src)


def _headers(event: dict) -> dict:
    h = event.get("headers")
    if isinstance(h, str):
        try:
            return json.loads(h) or {}
        except ValueError:
            return {}
    return h or {}


def _test(cond: dict, value) -> bool:
    op = cond["op"]
    if op in PRESENCE:
        return (value not in (None, "")) == (op == "exists")
    if value is None:
        return False
    text = str(value)
    want = cond.get("value")
    if op == "equals":
        return text == want
    if op == "contains":
        return want in text
    if op == "prefix":
        return text.startswith(want)
    if op == "suffix":
        return text.endswith(want)
    if op == "regex":
        return re.search(want, text[:2000]) is not None
    if op == "in_list":
        return any(w in text for w in want)
    if op == "cidr":
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return False
        return any(ip.version == n.version and ip in n for n in map(ipaddress.ip_network, want))
    try:
        a, b = float(text), float(want)
    except ValueError:
        return False
    return {"gt": a > b, "ge": a >= b, "lt": a < b, "le": a <= b, "eq": a == b}[op]


def matches(event: dict, tree: dict, unknown: set | None = None) -> bool:
    """Three-valued underneath: a condition events can't answer makes that way of matching not count, and is reported."""
    for way in ways(tree):
        ok = True
        for c in way:
            known, value = _event_value(event, c["field"], c.get("name"))
            if not known:
                if unknown is not None:
                    unknown.add(c["field"] + (f":{c['name']}" if c.get("name") else ""))
                ok = False
                break
            hit = _test(c, value)
            if hit == bool(c.get("negate")):
                ok = False
                break
        if ok:
            return True
    return False


def preview(store, tree: dict, domains: list[str], path: str, days: int = 7, allowed: list[str] | None = None) -> dict:
    tree = check_tree(tree)
    since = time.time() - max(1, min(int(days), 90)) * 86400
    checked = hit = 0
    unknown: set = set()
    by_domain: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    samples = []
    for e in store.scan_events(since, "url IS NOT NULL"):
        if allowed is not None and e["domain"] not in allowed:
            continue
        checked += 1
        if domains and not any((e["domain"] or "") == d or (d.startswith("*.") and (e["domain"] or "").endswith(d[1:])) for d in domains):
            continue
        if path and not (e["url"] or "").startswith(path):
            continue
        if matches(e, tree, unknown):
            hit += 1
            by_domain[e["domain"] or "unknown"] = by_domain.get(e["domain"] or "unknown", 0) + 1
            by_ip[e["client_ip"] or "unknown"] = by_ip.get(e["client_ip"] or "unknown", 0) + 1
            if len(samples) < 20:
                samples.append({k: e[k] for k in ("ts_event", "client_ip", "domain", "method", "url", "status", "user_agent", "source")})
    top = lambda d: sorted(d.items(), key=lambda kv: -kv[1])[:10]  # noqa: E731
    return {"checked": checked, "matched": hit, "days": days, "domains": top(by_domain), "clients": top(by_ip), "samples": samples, "cannot_check": sorted(unknown),
            "note": "This only looks at what events keep. Parameter values and request bodies are never stored, so conditions on them can't be previewed." if unknown else ""}


# ----------------------------------------------------------------------------- imported rules (virtual patches)
_RAW_LINE = re.compile(r'^(SecRule|SecAction)\s')
_RAW_FORBIDDEN = re.compile(r"\bexec:|@inspectFile|@fuzzyHash|\bSecAuditLog|\bSecRemote|\bInclude\b|\bSecDataDir|\bSecTmpDir|\bSecUploadDir|\bSecGeoLookupDb|\bappend:|\bprepend:|\bproxy:|\.lua\b", re.I)


def check_raw(text: str) -> tuple[list[str], list[int]]:
    """Refuse anything but plain rules with IDs in the range kept for patches, and anything that runs programs or reads files."""
    joined = re.sub(r"\\\r?\n[ \t]*", " ", str(text or "")).strip()
    lines = [ln.strip() for ln in joined.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines or len(lines) > 50:
        raise RuleError("Paste between 1 and 50 rules")
    ids: list[int] = []
    chained = False
    for ln in lines:
        if not _RAW_LINE.match(ln):
            raise RuleError(f"Only SecRule and SecAction lines are accepted: {ln[:60]}")
        if _RAW_FORBIDDEN.search(ln):
            raise RuleError(f"This line uses something that isn't allowed in an imported rule: {ln[:60]}")
        if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", ln):
            raise RuleError("Control characters aren't allowed")
        m = re.search(r"\bid:'?(\d+)'?", ln)
        if not chained:
            if not m:
                raise RuleError(f"Every rule needs an id: {ln[:60]}")
            rid = int(m.group(1))
            if not ID_PATCH_MIN <= rid <= ID_PATCH_MAX or rid in ids:
                raise RuleError(f"Rule IDs must be unique and between {ID_PATCH_MIN} and {ID_PATCH_MAX}: {rid}")
            ids.append(rid)
        elif m:
            raise RuleError("A rule inside a chain can't have its own id")
        chained = bool(re.search(r"\bchain\b", ln))
    if chained:
        raise RuleError("The last rule ends in chain, with nothing after it")
    return lines, ids


def detect_only(line: str) -> str:
    """The same rule with nothing disruptive in it: it logs, and lets the request through."""
    return re.sub(r"\b(deny|drop|block)\b(?:,status:\d+)?|\bredirect:[^,\"']+|\bstatus:\d+,?", lambda m: "pass" if m.group(1) or m.group(0).startswith("redirect") else "", line)


# ----------------------------------------------------------------------------- honeypots and CMS profiles
HONEYPOT_SITES_BASE = ("/var/www",)


def honeypot_rx(paths: list[str]) -> str:
    return "^(?:" + "|".join(re.escape(p.rstrip("/")) + ("/?" if p.endswith("/") else "") for p in paths) + ")$"


def domains_with_path(paths: list[str], sites: list[dict]) -> list[str]:
    """Sites where a honeypot path really exists: a request for it there is a visitor, not a probe."""
    out = []
    for s in sites:
        root = s.get("docroot")
        if root and any(Path(root, p.lstrip("/")).exists() for p in paths):
            out += [s["server_name"], *s.get("aliases", [])]
    return sorted(set(out))


def render_honeypot(cfg: dict, excluded: list[str]) -> list[str]:
    mode = cfg.get("mode", "detect")
    paths = cfg.get("paths") or []
    if mode == "off" or not paths:
        return []
    act = "deny,status:404" if mode == "block" else "pass"
    conds = [("REQUEST_FILENAME", f'"@rx {honeypot_rx(paths)}"', _PATH_T)]
    if excluded:
        conds.append(("REQUEST_HEADERS:Host", f'"!@rx {host_rx(excluded)}"', "t:none,t:lowercase"))
    return _chain(ID_HONEYPOT, f"phase:1,{act},log,msg:'Ella: honeypot path',tag:'ella-honeypot',severity:'WARNING'", conds)


def _p(value: str, op: str = "equals") -> dict:
    return {"field": "path", "op": op, "value": value}


CMS_PROFILES = {
    "wp-xmlrpc": {"title": "WordPress: block xmlrpc.php", "effect": "Jetpack and the WordPress mobile app stop working on these sites.", "tree": _p("/xmlrpc.php"), "n": 0},
    "wp-users": {"title": "WordPress: hide the user list", "effect": "Apps that read /wp-json/wp/v2/users without logging in stop working.",
                 "tree": {"any": [_p("/wp-json/wp/v2/users", "prefix"), {"all": [_p("/"), {"field": "arg", "name": "author", "op": "regex", "value": r"^\d+$"}]}]}, "n": 1},
    "wp-login-referer": {"title": "WordPress: login needs a Referer", "effect": "Stops simple login bots. A browser with Referer turned off can't log in.",
                         "tree": {"all": [_p("/wp-login.php"), {"field": "method", "op": "equals", "value": "POST"}, {"field": "referer", "op": "missing"}]}, "n": 4},
    "wp-backups": {"title": "WordPress: block config backups", "effect": "None for normal use.", "tree": {"field": "path", "op": "regex", "value": r"/wp-config\.php(?:\.bak|\.old|\.save|\.swp|~)$"}, "n": 6},
    "joomla": {"title": "Joomla: block config and installer files", "effect": "None for normal use.", "tree": {"field": "path", "op": "regex", "value": r"/(?:configuration\.php(?:\.bak|~)|administrator/manifests/files/joomla\.xml|installation/)"}, "n": 8},
    "drupal": {"title": "Drupal: block version and install files", "effect": "None for normal use. Update tools read these locally, not over the web.", "tree": {"field": "path", "op": "regex", "value": r"/(?:CHANGELOG\.txt|core/install\.php|sites/default/settings\.php)$"}, "n": 10},
    "phpmyadmin": {"title": "phpMyAdmin: block its setup pages", "effect": "The web setup page stops working. It isn't needed once phpMyAdmin is configured.", "tree": {"field": "path", "op": "regex", "value": r"/(?:phpmyadmin|pma)/(?:setup|scripts/setup\.php)"}, "n": 12},
    "backups": {"title": "Backup files left in web folders", "effect": "Blocks downloads of .sql, .tar.gz, .zip.bak and similar from these sites. Don't use it where visitors download such files.", "tree": {"field": "path", "op": "regex", "value": r"\.(?:sql|sql\.gz|bak|old|tar\.gz|tgz)$"}, "n": 14},
}


# ----------------------------------------------------------------------------- settings per domain, with inheritance
POLICY_KEYS = {"paranoia": (1, 4), "threshold": (1, 100), "mode": MODES}
ORDER = ("global", "server", "account", "domain", "path")


def scope_level(scope: str) -> int:
    return ORDER.index(scope.split(":", 1)[0])


def effective(rows: list[dict], domain: str, defaults: dict) -> dict:
    """Each setting, and where it came from. A locked setting can only be tightened lower down, never loosened."""
    out = {k: {"value": v, "from": "WAF Firewall page", "locked": False} for k, v in defaults.items()}
    for r in sorted(rows, key=lambda x: scope_level(x["scope"])):
        kind, _, name = r["scope"].partition(":")
        if kind == "domain" and name != domain:
            continue
        if kind not in ("global", "domain"):
            continue
        k, value = r["key"], json.loads(r["value"]) if isinstance(r["value"], str) else r["value"]
        cur = out.get(k, {"value": None, "locked": False, "from": ""})
        if cur["locked"] and not _tighter(k, value, cur["value"]):
            continue
        out[k] = {"value": value, "from": r["scope"], "locked": bool(r["locked"]) or cur["locked"]}
    return out


def _tighter(key: str, new, old) -> bool:
    if key == "paranoia":
        return new >= old
    if key == "threshold":
        return new <= old
    return MODES.index(new) >= MODES.index(old)


def check_policy(key: str, value):
    if key == "mode":
        if value not in MODES:
            raise RuleError("Mode must be off, detect or block")
        return value
    if key not in POLICY_KEYS or isinstance(value, bool) or not isinstance(value, int):
        raise RuleError(f"Unknown setting or bad value: {key}")
    lo, hi = POLICY_KEYS[key]
    if not lo <= value <= hi:
        raise RuleError(f"{key} must be between {lo} and {hi}")
    return value


def render_policies(rows: list[dict], defaults: dict) -> list[str]:
    lines = []
    domains = sorted({r["scope"].split(":", 1)[1] for r in rows if r["scope"].startswith("domain:")})
    for n, d in enumerate(domains):
        eff = effective(rows, d, defaults)
        acts = []
        for key in ("paranoia", "threshold", "mode"):
            item = eff.get(key)
            if not item or item["from"] != f"domain:{d}":
                continue
            if key == "paranoia":
                acts.append(f"setvar:tx.paranoia_level={int(item['value'])},setvar:tx.blocking_paranoia_level={int(item['value'])}")
            elif key == "threshold":
                acts.append(f"setvar:tx.inbound_anomaly_score_threshold={int(item['value'])}")
            elif item["value"] != "block":
                acts.append("ctl:ruleEngine=" + ("DetectionOnly" if item["value"] == "detect" else "Off"))
        if acts:
            lines.append(f'SecRule REQUEST_HEADERS:Host "@rx {host_rx([d])}" "id:{ID_POLICY + n},phase:1,pass,nolog,t:none,t:lowercase,{",".join(acts)}"')
    return lines


def render_under_attack() -> list[str]:
    return ["# Under Attack: lower threshold, and only the everyday methods.",
            f'SecAction "id:{ID_ATTACK},phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=3"',
            f'SecRule REQUEST_METHOD "!@rx ^(?:GET|HEAD|POST|OPTIONS)$" "id:{ID_ATTACK + 1},phase:1,deny,status:405,log,msg:\'Ella: method refused while Under Attack\',tag:\'ella-under-attack\',t:none"']


# ----------------------------------------------------------------------------- the whole file
def render(state: dict, engine: str) -> str:
    """state: rules, exceptions, honeypot, honeypot_excluded, policies, policy_defaults, under_attack, kill_switch, response_inspection, body_limit_action."""
    out = [HEADER.rstrip()]
    if state.get("kill_switch"):
        out += ["# Kill switch: every rule only logs.", "SecRuleEngine DetectionOnly"]
    if state.get("response_inspection"):
        out += ["# Response checks: bodies are read by the rules, and audit logs still don't copy them.", "SecResponseBodyAccess On", "SecResponseBodyMimeType text/plain text/html application/json"]
    if state.get("body_limit_action") == "ProcessPartial":
        out += ["SecRequestBodyLimitAction ProcessPartial", f'SecRule REQBODY_ERROR "!@eq 0" "id:{ID_POLICY + 900},phase:2,pass,log,msg:\'Ella: request body cut at the limit\',tag:\'body-partial\',severity:\'CRITICAL\'"']
    out += [f'SecRule REQUEST_HEADERS:Content-Type "@rx (?i)charset\\s*=\\s*[\\"\']?\\s*utf-?7" "id:{ID_POLICY + 901},phase:1,deny,status:415,log,msg:\'Ella: UTF-7 content type\',tag:\'ella-encoding\',t:none"']
    if state.get("under_attack"):
        out += render_under_attack()
    out += render_policies(state.get("policies") or [], state.get("policy_defaults") or {})
    exs = [e for e in state.get("exceptions") or [] if e.get("enabled", 1)]
    if exs:
        out.append("# Exceptions")
        for e in exs:
            out += render_exception(e)
    out += render_honeypot(state.get("honeypot") or {}, state.get("honeypot_excluded") or [])
    now = time.time()
    rules = [r for r in state.get("rules") or [] if r["mode"] != "off" and not (r.get("expires_at") and r["expires_at"] <= now)]
    for r in sorted(rules, key=lambda x: (-int(x.get("priority") or 100), x["id"])):
        out.append(f"# Rule {r['id']} v{r['version']}: {_msg(r['name'])}")
        if r["kind"] == "vpatch":
            lines, _ = check_raw(r["raw"])
            out += [detect_only(ln) if r["mode"] != "block" else ln for ln in lines]
        else:
            base = ID_CMS + CMS_PROFILES[r["profile"]]["n"] if r["kind"] == "cms" else ID_RULES + int(r["id"]) * 100
            tag = f"ella-cms-{r['profile']}" if r["kind"] == "cms" else f"ella-rule-{r['id']}"
            out += render_tree_rule(base, r["name"], json.loads(r["tree"]) if isinstance(r["tree"], str) else r["tree"], json.loads(r["domains"]) if isinstance(r["domains"], str) else r["domains"], r["path"], r["mode"], r["action"], r["status"], tag)
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------- the rule book: storage and publishing
class RuleBook:
    def __init__(self, store, configs, sites=None, servers=None, policy_defaults=None):
        self.store, self.configs = store, configs
        self._sites = sites or _panel_sites
        self._servers = servers or _waf_servers
        self._defaults = policy_defaults or _waf_defaults

    # ---- reading
    def _rows(self, sql: str, args: tuple = ()) -> list[dict]:
        return [dict(r) for r in self.store.read(lambda c: c.execute(sql, args).fetchall())]

    def rules(self, kind: str | None = None) -> list[dict]:
        rows = self._rows("SELECT * FROM rules " + ("WHERE kind = ? " if kind else "") + "ORDER BY id", (kind,) if kind else ())
        for r in rows:
            r["domains"] = json.loads(r["domains"])
            r["tree"] = json.loads(r["tree"]) if r["tree"] else None
        return rows

    def rule(self, rule_id: int) -> dict:
        got = [r for r in self.rules() if r["id"] == int(rule_id)]
        if not got:
            raise RuleError("No such rule")
        return got[0]

    def versions(self, rule_id: int) -> list[dict]:
        return [{**r, "snapshot": json.loads(r["snapshot"])} for r in self._rows("SELECT * FROM rule_versions WHERE rule_id = ? ORDER BY version DESC", (int(rule_id),))]

    def exceptions(self, domains: list[str] | None = None) -> list[dict]:
        rows = self._rows("SELECT * FROM exceptions WHERE enabled = 1 ORDER BY id DESC")
        return [e for e in rows if domains is None or e["domain"] in domains]

    def state(self) -> dict:
        s = self.store.setting
        honey = s("honeypot") or {}
        rules = self.rules()
        for r in rules:
            if r["kind"] == "cms":
                r["profile"] = r["reason"]
        ua = s("under_attack") or {}
        return {"rules": rules, "exceptions": self.exceptions(), "honeypot": honey, "honeypot_excluded": domains_with_path(honey.get("paths") or [], self._sites()),
                "policies": self._rows("SELECT * FROM policies"), "policy_defaults": self._defaults(), "under_attack": bool(ua.get("on")), "kill_switch": bool(s("kill_switch")),
                "response_inspection": bool(s("response_inspection")), "body_limit_action": s("body_limit_action")}

    # ---- publishing
    def publish(self, actor: str, watch: bool = True) -> dict:
        """Write the rules to every web server with a WAF. A server that refuses keeps its previous file, and says so."""
        state = self.state()
        results = {}
        for sv in self._servers():
            text = render(state, sv["engine"])
            try:
                self.configs.apply(sv["file"], text, actor, server=sv["name"], reload=sv["active"], watch_seconds=90 if watch and sv["active"] else None)
                results[sv["name"]] = {"ok": True, "active": sv["active"]}
            except Exception as exc:  # noqa: BLE001  ConfigError, or an OSError writing the file: report it per server
                results[sv["name"]] = {"ok": False, "error": str(exc)[:1500]}
        bad = [v["error"] for v in results.values() if not v["ok"]]
        if bad:
            raise RuleError(bad[0])
        if not results:
            raise RuleError("Neither Apache nor Nginx has a WAF installed, so there's nothing to put rules in.")
        return results

    def _version(self, c, rule_id: int, actor: str) -> None:
        r = dict(c.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone())
        c.execute("INSERT OR REPLACE INTO rule_versions(rule_id, version, snapshot, actor, ts) VALUES (?,?,?,?,?)", (rule_id, r["version"], json.dumps(r), actor, time.time()))

    def _clean_rule(self, d: dict) -> dict:
        name = safe_value(d.get("name"), "Name").strip()
        if not name:
            raise RuleError("A rule needs a name")
        domains = [str(x).strip().lower() for x in d.get("domains") or [] if str(x).strip()]
        for x in domains:
            if not DOMAIN.match(x):
                raise RuleError(f"Not a domain: {x}")
        path = safe_value(d.get("path") or "", "Path")
        if path and (not path.startswith("/") or '"' in path or " " in path):
            raise RuleError("Path must start with / and have no spaces or quotes")
        action, status = d.get("action", "block"), d.get("status", 403)
        if action not in ACTIONS or status not in STATUSES:
            raise RuleError("Action must be log or block, and status one of " + ", ".join(map(str, STATUSES)))
        prio = d.get("priority", 100)
        if isinstance(prio, bool) or not isinstance(prio, int) or not 0 <= prio <= 1000:
            raise RuleError("Priority must be between 0 and 1000")
        exp = d.get("expires_at")
        if exp is not None and not isinstance(exp, (int, float)):
            raise RuleError("Bad expiry time")
        return {"name": name, "domains": domains, "path": path, "action": action, "status": status, "priority": prio, "reason": safe_value(d.get("reason") or "", "Reason")[:300], "expires_at": exp}

    def _create(self, clean: dict, kind: str, tree, raw, actor: str, extra: dict | None = None) -> int:
        now = time.time()

        def add(c):
            cur = c.execute("INSERT INTO rules(name, kind, domains, path, tree, raw, action, status, mode, priority, author, reason, expires_at, cve_id, software, versions, source_url, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,'off',?,?,?,?,?,?,?,?,?,?)",
                            (clean["name"], kind, json.dumps(clean["domains"]), clean["path"], json.dumps(tree) if tree else None, raw, clean["action"], clean["status"], clean["priority"], actor, clean["reason"], clean["expires_at"],
                             *[(extra or {}).get(k) for k in ("cve_id", "software", "versions", "source_url")], now, now))
            self._version(c, cur.lastrowid, actor)
            self.store.audit_in(c, actor, "rule.created", str(cur.lastrowid), {"name": clean["name"], "kind": kind})
            return cur.lastrowid
        return self.store.run(add)

    def create(self, data: dict, actor: str) -> dict:
        clean = self._clean_rule(data)
        tree = check_tree(data.get("tree") or {})
        if len(ways(tree)) > MAX_WAYS:
            raise RuleError(f"These conditions expand to more than {MAX_WAYS} rules. Simplify them.")
        return self.rule(self._create(clean, "custom", tree, None, actor))

    def update(self, rule_id: int, data: dict, actor: str) -> dict:
        cur = self.rule(rule_id)
        clean = self._clean_rule({**cur, **data})
        tree = check_tree(data["tree"]) if data.get("tree") else cur["tree"]
        raw = cur["raw"]
        if cur["kind"] == "vpatch" and data.get("raw"):
            check_raw(data["raw"])
            raw = data["raw"]

        def save(c):
            c.execute("UPDATE rules SET name=?, domains=?, path=?, tree=?, raw=?, action=?, status=?, priority=?, reason=?, expires_at=?, version=version+1, updated_at=? WHERE id=?",
                      (clean["name"], json.dumps(clean["domains"]), clean["path"], json.dumps(tree) if tree else None, raw, clean["action"], clean["status"], clean["priority"], clean["reason"], clean["expires_at"], time.time(), rule_id))
            self._version(c, rule_id, actor)
            self.store.audit_in(c, actor, "rule.updated", str(rule_id), {"from_version": cur["version"]})
        self.store.run(save)
        if cur["mode"] != "off":
            self.publish(actor)
        return self.rule(rule_id)

    def set_mode(self, rule_id: int, mode: str, actor: str) -> dict:
        """off, detect or block. Block needs a detect period first: you see what a rule would do before it does it."""
        if mode not in MODES:
            raise RuleError("Mode must be off, detect or block")
        cur = self.rule(rule_id)
        if mode == "block" and not cur["detect_since"]:
            raise RuleError("Run this rule in detect mode first, so you can see what it would block.")
        now = time.time()

        def save(c):
            c.execute("UPDATE rules SET mode=?, detect_since=COALESCE(detect_since, ?), updated_at=? WHERE id=?", (mode, now if mode == "detect" else None, now, rule_id))
            self.store.audit_in(c, actor, "rule.mode", str(rule_id), {"from": cur["mode"], "to": mode})
        self.store.run(save)
        try:
            self.publish(actor)
        except RuleError:
            self.store.run(lambda c: c.execute("UPDATE rules SET mode=? WHERE id=?", (cur["mode"], rule_id)))
            raise
        return self.rule(rule_id)

    def delete(self, rule_id: int, actor: str) -> dict:
        cur = self.rule(rule_id)
        if cur["locked"]:
            raise RuleError("This rule is locked")

        def drop(c):
            c.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
            self.store.audit_in(c, actor, "rule.deleted", str(rule_id), {"name": cur["name"], "version": cur["version"]})
        self.store.run(drop)
        if cur["mode"] != "off":
            self.publish(actor)
        return {"ok": True}

    # ---- exceptions
    def add_exception(self, data: dict, actor: str, allowed: list[str] | None = None) -> dict:
        ex = check_exception(data.get("rule_id"), data.get("var"), data.get("domain"), data.get("path"))
        if allowed is not None and ex["domain"] not in allowed:
            self.store.audit(actor, "exception.refused", ex["domain"], {"why": "outside this account's sites"})
            raise PermissionError("That domain isn't yours")
        for r in self.rules():
            if r["locked"] and any(str(x) == ex["rule_id"] for x in [r["id"]]):
                raise RuleError("This rule is locked: it can't be excepted")
        now = time.time()

        def add(c):
            cur = c.execute("INSERT INTO exceptions(rule_id, var, domain, path, author, reason, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)", (ex["rule_id"], ex["var"], ex["domain"], ex["path"], actor, str(data.get("reason") or "")[:300], now, data.get("expires_at")))
            self.store.audit_in(c, actor, "exception.created", ex["domain"], {**ex, "id": cur.lastrowid})
            return cur.lastrowid
        new_id = self.store.run(add)
        try:
            self.publish(actor)
        except RuleError:
            self.store.run(lambda c: c.execute("DELETE FROM exceptions WHERE id = ?", (new_id,)))
            raise
        return {"id": new_id, **ex}

    def remove_exception(self, ex_id: int, actor: str, allowed: list[str] | None = None) -> dict:
        got = self._rows("SELECT * FROM exceptions WHERE id = ?", (int(ex_id),))
        if not got:
            raise RuleError("No such exception")
        if allowed is not None and got[0]["domain"] not in allowed:
            raise PermissionError("That domain isn't yours")

        def drop(c):
            c.execute("UPDATE exceptions SET enabled = 0 WHERE id = ?", (int(ex_id),))
            self.store.audit_in(c, actor, "exception.removed", got[0]["domain"], {"id": int(ex_id), "rule_id": got[0]["rule_id"]})
        self.store.run(drop)
        self.publish(actor)
        return {"ok": True}

    # ---- honeypots, CMS profiles
    def set_honeypot(self, data: dict, actor: str) -> dict:
        mode = data.get("mode", "detect")
        if mode not in MODES:
            raise RuleError("Mode must be off, detect or block")
        paths = [safe_value(p, "Path").strip() for p in data.get("paths") or [] if str(p).strip()]
        if len(paths) > 100 or any(not p.startswith("/") or " " in p or '"' in p for p in paths):
            raise RuleError("Up to 100 paths, each starting with / and with no spaces or quotes")
        if "/.well-known/acme-challenge/" in paths or any(p.startswith("/.well-known/acme-challenge") for p in paths):
            raise RuleError("Certificate checks use that path, so it can't be a honeypot")
        old = self.store.setting("honeypot")
        self.store.set_setting("honeypot", {"mode": mode, "paths": paths})
        self.store.audit(actor, "honeypot.changed", "", {"mode": mode, "paths": len(paths)})
        try:
            self.publish(actor)
        except RuleError:
            self.store.set_setting("honeypot", old)
            raise
        return {"mode": mode, "paths": paths, "excluded": domains_with_path(paths, self._sites())}

    def cms_status(self) -> list[dict]:
        have = {r["reason"]: r for r in self.rules("cms")}
        return [{"id": k, "title": p["title"], "effect": p["effect"], "mode": have[k]["mode"] if k in have else "off", "domains": have[k]["domains"] if k in have else [], "rule_id": have[k]["id"] if k in have else None} for k, p in CMS_PROFILES.items()]

    def set_cms(self, profile: str, mode: str, domains: list[str], actor: str) -> dict:
        if profile not in CMS_PROFILES:
            raise RuleError("Unknown profile")
        have = {r["reason"]: r for r in self.rules("cms")}
        if profile in have:
            rid = have[profile]["id"]
            self.store.run(lambda c: c.execute("UPDATE rules SET domains=?, updated_at=? WHERE id=?", (json.dumps(domains), time.time(), rid)))
        else:
            p = CMS_PROFILES[profile]
            rid = self._create({**self._clean_rule({"name": p["title"], "domains": domains}), "reason": profile}, "cms", p["tree"], None, actor)
        if mode == "block" and not self.rule(rid)["detect_since"]:
            self.store.run(lambda c: c.execute("UPDATE rules SET detect_since=? WHERE id=?", (time.time(), rid)))  # a profile's effects are written on it, and the operator chose it
        return self.set_mode(rid, mode, actor)

    # ---- virtual patches
    def add_patch(self, data: dict, actor: str) -> dict:
        check_raw(data.get("raw"))
        cve = str(data.get("cve_id") or "").strip().upper()
        if cve and not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
            raise RuleError("That isn't a CVE number")
        url = safe_value(data.get("source_url") or "", "Source")
        if url and not re.match(r"^https?://", url):
            raise RuleError("Source must be a web address")
        clean = self._clean_rule({"name": data.get("name") or cve or "Virtual patch", "reason": data.get("reason") or ""})
        rid = self._create(clean, "vpatch", None, str(data["raw"]), actor, {"cve_id": cve or None, "software": safe_value(data.get("software") or "")[:100], "versions": safe_value(data.get("versions") or "")[:100], "source_url": url})
        try:
            return self.set_mode(rid, "detect", actor)  # checked by the web server, and in detect before it can do anything
        except RuleError:
            self.store.run(lambda c: c.execute("DELETE FROM rules WHERE id = ?", (rid,)))
            raise

    # ---- switches
    def set_switch(self, key: str, value, actor: str) -> None:
        if key not in ("kill_switch", "response_inspection", "body_limit_action"):
            raise RuleError("Unknown setting")
        if key == "body_limit_action" and value not in ("Reject", "ProcessPartial"):
            raise RuleError("Reject or ProcessPartial")
        old = self.store.setting(key)
        self.store.set_setting(key, value)
        self.store.audit(actor, f"waf.{key}", "", {"from": old, "to": value})
        try:
            self.publish(actor, watch=False)
        except RuleError:
            self.store.set_setting(key, old)
            raise

    def under_attack(self, minutes: int, actor: str) -> dict:
        """On for a set time, off by itself. 0 turns it off."""
        if isinstance(minutes, bool) or not isinstance(minutes, int) or not 0 <= minutes <= 1440:
            raise RuleError("Minutes must be between 0 and 1440")
        state = {"on": minutes > 0, "until": time.time() + minutes * 60 if minutes else None}
        old = self.store.setting("under_attack")
        self.store.set_setting("under_attack", state)
        self.store.audit(actor, "waf.under_attack", "", state)
        try:
            self.publish(actor, watch=False)
        except RuleError:
            self.store.set_setting("under_attack", old)
            raise
        return state

    def set_policy(self, scope: str, key: str, value, locked: bool, actor: str) -> dict:
        kind, _, name = scope.partition(":")
        if kind not in ("global", "domain") or (kind == "domain" and not DOMAIN.match(name)):
            raise RuleError("A setting applies to global or domain:<name>")
        value = check_policy(key, value)
        rows = self._rows("SELECT * FROM policies")
        if kind == "domain":
            eff = effective([r for r in rows if r["scope"] == "global"], name, self._defaults()).get(key)
            if eff and eff["locked"] and not _tighter(key, value, eff["value"]):
                raise RuleError(f"{key} is locked at {eff['value']} by {eff['from']}. A domain can only tighten it.")

        def save(c):
            c.execute("INSERT INTO policies(scope, key, value, locked) VALUES (?,?,?,?) ON CONFLICT(scope, key) DO UPDATE SET value=excluded.value, locked=excluded.locked", (scope, key, json.dumps(value), int(bool(locked))))
            self.store.audit_in(c, actor, "policy.set", scope, {"key": key, "value": value, "locked": bool(locked)})
        self.store.run(save)
        self.publish(actor)
        return self.effective(name) if kind == "domain" else {"ok": True}

    def remove_policy(self, scope: str, key: str, actor: str) -> dict:
        def drop(c):
            c.execute("DELETE FROM policies WHERE scope = ? AND key = ?", (scope, key))
            self.store.audit_in(c, actor, "policy.removed", scope, {"key": key})
        self.store.run(drop)
        self.publish(actor)
        return {"ok": True}

    def effective(self, domain: str) -> dict:
        return effective(self._rows("SELECT * FROM policies"), domain, self._defaults())

    def tick(self) -> None:
        """Whatever has run out of time: Under Attack, and rules and exceptions with an end date."""
        now = time.time()
        ua = self.store.setting("under_attack") or {}
        changed = False
        if ua.get("on") and ua.get("until") and ua["until"] <= now:
            self.store.set_setting("under_attack", {"on": False, "until": None})
            self.store.audit("system", "waf.under_attack", "", {"on": False, "why": "time ran out"})
            changed = True
        for r in self.rules():
            if r["mode"] != "off" and r["expires_at"] and r["expires_at"] <= now:
                self.store.run(lambda c, r=r: (c.execute("UPDATE rules SET mode='off' WHERE id=?", (r["id"],)), self.store.audit_in(c, "system", "rule.expired", str(r["id"]), {"name": r["name"]})))
                changed = True
        for e in self._rows("SELECT * FROM exceptions WHERE enabled = 1 AND expires_at IS NOT NULL AND expires_at <= ?", (now,)):
            self.store.run(lambda c, e=e: (c.execute("UPDATE exceptions SET enabled = 0 WHERE id = ?", (e["id"],)), self.store.audit_in(c, "system", "exception.expired", e["domain"], {"id": e["id"]})))
            changed = True
        if changed:
            self.publish("system", watch=False)


# ----------------------------------------------------------------------------- facts from the panel
def _panel_sites() -> list[dict]:
    out = []
    try:
        from .. import sites
        for s in sites.list_sites():
            st = s.get("settings") or s
            if st.get("server_name"):
                out.append({"server_name": st["server_name"], "aliases": st.get("aliases") or [], "docroot": st.get("docroot")})
    except Exception:  # noqa: BLE001  a honeypot list isn't worth failing over
        pass
    for mod in ("nginxsites", "caddysites"):
        try:
            import importlib
            m = importlib.import_module(f"..{mod}", __package__)
            for s in m.list_sites(probe=False):
                out.append({"server_name": s["server_name"], "aliases": s.get("aliases") or [], "docroot": s.get("docroot")})
        except Exception:  # noqa: BLE001
            pass
    return out


def _waf_servers() -> list[dict]:
    """Which web servers have a WAF to put rules in."""
    out = []
    try:
        from .. import nginxwaf, nginxsites
        if nginxwaf.module_installed() and nginxwaf.find_crs():
            out.append({"name": "nginx", "engine": "v3", "file": NGINX_FILE, "active": nginxsites._active("nginx") and nginxwaf.HOOK.exists()})
    except Exception:  # noqa: BLE001
        pass
    try:
        from .. import nginxsites, waf
        if waf.installed():
            out.append({"name": "apache", "engine": "v2", "file": APACHE_FILE, "active": nginxsites._active(nginxsites._apache_unit())})
    except Exception:  # noqa: BLE001
        pass
    return out


def _waf_defaults() -> dict:
    try:
        from .. import waf
        s = waf.load()
        return {"paranoia": s["paranoia"], "threshold": s["threshold"], "mode": s["mode"]}
    except Exception:  # noqa: BLE001
        return {"paranoia": 1, "threshold": 5, "mode": "detect"}
