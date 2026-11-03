"""Zone Editor — structured DNS records stored as BIND zone files.

Zones live in /var/lib/bind/db.<domain> (a path BIND's AppArmor profile allows).
Every write is validated with `named-checkzone` before it replaces the file; the
SOA serial is bumped automatically. When BIND9 is installed the zone is also
registered in named.conf.local and reloaded, otherwise the records are kept
ready to serve (and can be exported for a registrar's DNS panel).
"""
from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from . import problems

IS_LINUX = platform.system() == "Linux"
ZONE_DIR = Path("/var/lib/bind")
NAMED_LOCAL = Path("/etc/bind/named.conf.local")
HEADER = "; Managed by AuroraPanel Zone Editor"
TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"]
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_LABEL = re.compile(r"^(\*|@|[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)(\.([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?))*$")


class ZoneError(RuntimeError):
    pass


def _dom(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    if not _DOMAIN.match(d):
        raise ZoneError("Invalid domain")
    return d


def _path(domain: str) -> Path:
    return ZONE_DIR / f"db.{_dom(domain)}"


def bind_installed() -> bool:
    return bool(IS_LINUX and shutil.which("named"))


# --------------------------------------------------------------------------- #
# Server options: safe defaults + secondary DNS (zone transfers)
# --------------------------------------------------------------------------- #
OPTIONS = Path("/etc/bind/named.conf.options")
SECONDARIES = Path("/var/lib/aurora/dns-secondaries.json")
OPT_HEADER = "// Written by AuroraPanel (Zone Editor → Secondary DNS). Edit there — changes here are overwritten."
# Recursive lookups only for this machine, its own networks (a Pi's LAN) and VPN clients — never an open resolver.
_RECURSION = "localhost; localnets; 10.0.0.0/8; 100.64.0.0/10;"


def _ips(host: str) -> list[str]:
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None) if a[0] in (socket.AF_INET, socket.AF_INET6)})
    except OSError:
        return []


def _my_ips() -> set[str]:
    out = {"127.0.0.1", "::1"}
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            out.update(a.address.split("%")[0] for a in addrs if a.family in (socket.AF_INET, socket.AF_INET6))
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    try:
        from . import mail
        ip = mail._public_ip()
        if ip:
            out.add(ip)
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    return out


def _sec_conf() -> dict:
    try:
        import json
        c = json.loads(SECONDARIES.read_text())
    except (OSError, ValueError):
        c = {}
    return {"auto": c.get("auto", True), "extra": [x for x in c.get("extra", []) if _valid_ip(x)]}


def _valid_ip(x: str) -> bool:
    try:
        ipaddress.ip_address(str(x))
        return True
    except ValueError:
        return False


def detected_secondaries() -> dict[str, list[str]]:
    """Nameservers named in our zones' NS records that aren't this server — the secondaries
    that copy the zones (e.g. a hosting provider's ns1/ns2)."""
    mine, out = _my_ips(), {}
    if not ZONE_DIR.exists():
        return out
    for f in ZONE_DIR.glob("db.*"):
        d = f.name[3:]
        try:
            z = parse(f.read_text(errors="replace"), d)
        except Exception as quiet_exc:
            problems.quiet(quiet_exc)
            continue
        for r in z["records"]:
            if r["type"] != "NS":
                continue
            host = r["target"].rstrip(".")
            if host in out:
                continue
            ips = [i for i in _ips(host) if i not in mine]
            if ips:
                out[host] = ips
    return out


def refused_transfers(days: int = 7) -> list[dict]:
    """Recent zone-transfer requests BIND refused — usually a provider's secondary DNS
    (its fetching address isn't always one of its nameservers, like ipserver's dnsmgr)."""
    try:
        r = subprocess.run(["journalctl", "-u", "named", "-u", "bind9", "--since", f"-{days}d", "-o", "cat", "--no-pager", "-q"],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return []
    seen: dict[str, dict] = {}
    for line in r.stdout.splitlines():
        m = re.search(r"client @\S+ ([0-9a-fA-F.:]+)#\d+.*zone transfer '([^/]+)/[A-Z]+/IN' denied", line)
        if m and _valid_ip(m.group(1)):
            seen.setdefault(m.group(1), {"ip": m.group(1), "zones": set()})["zones"].add(m.group(2))
    allowed = set(allowed_transfer_ips()) | _my_ips()
    return [{"ip": k, "zones": sorted(v["zones"])} for k, v in seen.items() if k not in allowed]


def allowed_transfer_ips() -> list[str]:
    c = _sec_conf()
    ips = list(c["extra"])
    if c["auto"]:
        for v in detected_secondaries().values():
            ips += v
    return sorted(dict.fromkeys(ips))


def render_options(ips: list[str]) -> str:
    acl = "".join(f" {i};" for i in ips)
    lines = [OPT_HEADER, "options {", '\tdirectory "/var/cache/bind";', "\tdnssec-validation auto;", "\tlisten-on-v6 { any; };",
             f"\tallow-recursion {{ {_RECURSION} }};", f"\tallow-query-cache {{ {_RECURSION} }};",
             f"\tallow-transfer {{ localhost;{acl} }};", "\tnotify yes;"]
    if ips:
        lines.append(f"\talso-notify {{{acl} }};")
    lines += ['\tversion "not disclosed";', "};", ""]
    return "\n".join(lines)


def apply_options() -> dict:
    """Write BIND's options (safe defaults + allowed secondaries) and reload if they changed."""
    if not (bind_installed() and OPTIONS.parent.is_dir()):
        return {"ok": False}
    old = OPTIONS.read_text() if OPTIONS.exists() else None
    if old is not None and not old.startswith(OPT_HEADER) and not SECONDARIES.exists():
        # Taking over a hand-written file: keep whatever it already allowed to transfer.
        m = re.search(r"allow-transfer\s*\{([^}]*)\}", old)
        kept = [x.strip() for x in (m.group(1).split(";") if m else []) if _valid_ip(x.strip()) and x.strip() not in ("127.0.0.1", "::1")]
        if kept:
            import json
            SECONDARIES.parent.mkdir(parents=True, exist_ok=True)
            SECONDARIES.write_text(json.dumps({"auto": True, "extra": sorted(set(kept))}))
    ips = allowed_transfer_ips()
    text = render_options(ips)
    if old == text:
        return {"ok": True, "changed": False, "allowed": ips}
    if old is not None and not old.startswith(OPT_HEADER):
        dist = OPTIONS.with_name("named.conf.options.dist")
        if not dist.exists():
            dist.write_text(old)
    OPTIONS.write_text(text)
    chk = subprocess.run(["named-checkconf"], capture_output=True, text=True, timeout=30)
    if chk.returncode != 0:
        if old is not None:
            OPTIONS.write_text(old)
        raise ZoneError("BIND rejected the options, nothing changed:\n" + (chk.stderr or chk.stdout).strip()[-400:])
    subprocess.run(["rndc", "reconfig"], capture_output=True, timeout=20)
    for f in ZONE_DIR.glob("db.*") if ZONE_DIR.exists() else []:
        subprocess.run(["rndc", "notify", f.name[3:]], capture_output=True, timeout=10)
    return {"ok": True, "changed": True, "allowed": ips}


def secondary_settings() -> dict:
    c = _sec_conf()
    return {**c, "detected": detected_secondaries(), "refused": refused_transfers(), "allowed": allowed_transfer_ips(),
            "bind_installed": bind_installed()}


def set_secondaries(auto: bool, extra: list[str]) -> dict:
    import json
    bad = [x for x in extra if not _valid_ip(str(x).strip())]
    if bad:
        raise ZoneError(f"Not an IP address: {', '.join(map(str, bad))}")
    SECONDARIES.parent.mkdir(parents=True, exist_ok=True)
    SECONDARIES.write_text(json.dumps({"auto": bool(auto), "extra": sorted({str(x).strip() for x in extra})}))
    return {**apply_options(), **secondary_settings()}


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _strip_comment(line: str) -> str:
    out, q = [], False
    for i, ch in enumerate(line):
        if ch == '"' and (i == 0 or line[i - 1] != "\\"):
            q = not q
        if ch == ";" and not q:
            break
        out.append(ch)
    return "".join(out)


def _tokens(s: str) -> list[str]:
    return re.findall(r'"(?:[^"\\]|\\.)*"|\S+', s)


def _fqdn(name: str, origin: str) -> str:
    if name == "@":
        return origin
    return name if name.endswith(".") else f"{name}.{origin}"


def parse(text: str, domain: str) -> dict:
    origin, ttl_default, last = f"{domain}.", 14400, None
    soa, records = None, []
    # Join parenthesised continuations.
    lines, buf, depth = [], "", 0
    for raw in text.splitlines():
        ln = _strip_comment(raw)
        if not ln.strip() and depth == 0:
            continue
        depth += ln.count("(") - ln.count(")")
        buf += (" " if buf else "") + (ln if not buf else ln.strip())
        if depth <= 0:
            lines.append(buf.replace("(", " ").replace(")", " "))
            buf, depth = "", 0
    for ln in lines:
        if ln.startswith("$TTL"):
            ttl_default = int(re.sub(r"\D", "", ln.split()[1]) or 14400)
            continue
        if ln.startswith("$ORIGIN"):
            origin = ln.split()[1]
            continue
        toks = _tokens(ln)
        if not toks:
            continue
        if ln[0] in " \t":
            name = last or origin
        else:
            name = _fqdn(toks.pop(0), origin)
        last = name
        ttl = ttl_default
        while toks and (toks[0].isdigit() or toks[0].upper() in ("IN", "CH", "HS")):
            t = toks.pop(0)
            if t.isdigit():
                ttl = int(t)
        if not toks:
            continue
        rtype, data = toks[0].upper(), toks[1:]
        if rtype == "SOA":
            soa = {"mname": data[0], "rname": data[1], "serial": int(data[2]), "refresh": int(data[3]),
                   "retry": int(data[4]), "expire": int(data[5]), "minimum": int(data[6]), "ttl": ttl}
            continue
        rec = {"name": name, "ttl": ttl, "type": rtype}
        try:
            if rtype in ("A", "AAAA"):
                rec["address"] = data[0]
            elif rtype in ("CNAME", "NS"):
                rec["target"] = data[0]
            elif rtype == "MX":
                rec.update(priority=int(data[0]), target=data[1])
            elif rtype == "SRV":
                rec.update(priority=int(data[0]), weight=int(data[1]), port=int(data[2]), target=data[3])
            elif rtype == "TXT":
                rec["text"] = "".join(re.sub(r"\\(.)", r"\1", t[1:-1] if t.startswith('"') else t) for t in data)
            elif rtype == "CAA":
                rec.update(flags=int(data[0]), tag=data[1], value=data[2].strip('"'))
            else:
                rec["raw"] = " ".join(data)
        except (IndexError, ValueError):
            rec["raw"] = " ".join(data)
        records.append(rec)
    return {"origin": origin, "ttl": ttl_default, "soa": soa, "records": records}


# --------------------------------------------------------------------------- #
# Validation + rendering
# --------------------------------------------------------------------------- #
def _norm_name(name: str, domain: str) -> str:
    n = (name or "").strip().lower()
    if n in ("", "@", domain, domain + "."):
        return domain + "."
    if n.endswith("."):
        base = n[:-1]
        if base != domain and not base.endswith("." + domain):
            raise ZoneError(f"{name} is outside the {domain} zone")
        rel = base[: -len(domain) - 1] if base != domain else "@"
    elif n.endswith("." + domain):
        rel = n[: -len(domain) - 1]
    else:
        rel = n
    if not _LABEL.match(rel):
        raise ZoneError(f"Invalid record name: {name}")
    return f"{rel}.{domain}." if rel != "@" else domain + "."


def _norm_target(t: str, domain: str) -> str:
    t = (t or "").strip().lower()
    if not t:
        raise ZoneError("Target is required")
    if t == "@":
        return domain + "."
    if not t.endswith("."):
        t = t + "." if "." in t else f"{t}.{domain}."
    if not re.match(r"^([a-z0-9_*](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+$", t):
        raise ZoneError(f"Invalid hostname: {t}")
    return t


def _int(v, lo, hi, what):
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ZoneError(f"{what} must be a number")
    if not lo <= n <= hi:
        raise ZoneError(f"{what} must be between {lo} and {hi}")
    return n


def clean_record(r: dict, domain: str) -> dict:
    t = str(r.get("type", "")).upper()
    if t not in TYPES:
        raise ZoneError(f"Unsupported record type {t}")
    out = {"type": t, "name": _norm_name(r.get("name", "@"), domain), "ttl": _int(r.get("ttl", 14400), 60, 604800, "TTL")}
    if t == "A":
        try:
            out["address"] = str(ipaddress.IPv4Address(str(r.get("address", "")).strip()))
        except ValueError:
            raise ZoneError("A record needs a valid IPv4 address")
    elif t == "AAAA":
        try:
            out["address"] = str(ipaddress.IPv6Address(str(r.get("address", "")).strip()))
        except ValueError:
            raise ZoneError("AAAA record needs a valid IPv6 address")
    elif t in ("CNAME", "NS"):
        out["target"] = _norm_target(r.get("target", ""), domain)
        if t == "CNAME" and out["name"] == domain + ".":
            raise ZoneError("A CNAME can't be placed on the domain itself (@) — use an A record")
    elif t == "MX":
        out.update(priority=_int(r.get("priority", 10), 0, 65535, "Priority"), target=_norm_target(r.get("target", ""), domain))
    elif t == "SRV":
        if not re.match(r"^_[a-z0-9-]+\._(tcp|udp|tls)\.", out["name"]):
            raise ZoneError("SRV name must look like _service._tcp (e.g. _sip._tcp)")
        out.update(priority=_int(r.get("priority", 0), 0, 65535, "Priority"), weight=_int(r.get("weight", 0), 0, 65535, "Weight"),
                   port=_int(r.get("port", 0), 0, 65535, "Port"), target=_norm_target(r.get("target", ""), domain))
    elif t == "TXT":
        text = str(r.get("text", ""))
        if not text or len(text) > 4000 or "\n" in text:
            raise ZoneError("TXT value must be 1–4000 characters on one line")
        out["text"] = text
    elif t == "CAA":
        tag = str(r.get("tag", "issue"))
        if tag not in ("issue", "issuewild", "iodef"):
            raise ZoneError("CAA tag must be issue, issuewild or iodef")
        val = str(r.get("value", "")).strip()
        if not val or '"' in val:
            raise ZoneError("CAA value is required (e.g. letsencrypt.org)")
        out.update(flags=_int(r.get("flags", 0), 0, 255, "Flags"), tag=tag, value=val)
    return out


def _check_conflicts(records: list[dict]) -> None:
    by_name: dict[str, set] = {}
    for r in records:
        by_name.setdefault(r["name"], set()).add(r["type"])
    for name, types in by_name.items():
        if "CNAME" in types and len(types) > 1:
            raise ZoneError(f"{name} has a CNAME plus other records — a CNAME must be the only record for a name")


def _rdata(r: dict) -> str:
    t = r["type"]
    if t in ("A", "AAAA"):
        return r["address"]
    if t in ("CNAME", "NS"):
        return r["target"]
    if t == "MX":
        return f"{r['priority']} {r['target']}"
    if t == "SRV":
        return f"{r['priority']} {r['weight']} {r['port']} {r['target']}"
    if t == "TXT":
        s = r["text"].replace("\\", "\\\\").replace('"', '\\"')
        return " ".join(f'"{s[i:i + 255]}"' for i in range(0, len(s), 255))
    if t == "CAA":
        return f'{r["flags"]} {r["tag"]} "{r["value"]}"'
    return r.get("raw", "")


def render(domain: str, soa: dict, records: list[dict], ttl: int = 14400) -> str:
    order = {t: i for i, t in enumerate(["NS", "A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"])}
    recs = sorted(records, key=lambda r: (r["name"] != domain + ".", order.get(r["type"], 99)))
    L = [HEADER, f"$TTL {ttl}", f"$ORIGIN {domain}.",
         f"@\t{soa['ttl']}\tIN\tSOA\t{soa['mname']} {soa['rname']} ( {soa['serial']} {soa['refresh']} {soa['retry']} {soa['expire']} {soa['minimum']} )"]
    for r in recs:
        L.append(f"{r['name']}\t{r['ttl']}\tIN\t{r['type']}\t{_rdata(r)}")
    return "\n".join(L) + "\n"


def _next_serial(old: int) -> int:
    today = int(time.strftime("%Y%m%d")) * 100
    return max(today, old + 1)


# --------------------------------------------------------------------------- #
# Zone operations
# --------------------------------------------------------------------------- #
def _load(domain: str) -> dict:
    p = _path(domain)
    if not p.exists():
        raise ZoneError(f"No zone for {domain} yet")
    z = parse(p.read_text(errors="replace"), _dom(domain))
    if not z["soa"]:
        raise ZoneError("Zone file has no SOA record")
    return z


def _write(domain: str, z: dict) -> dict:
    domain = _dom(domain)
    _check_conflicts(z["records"])
    z["soa"]["serial"] = _next_serial(z["soa"]["serial"])
    text = render(domain, z["soa"], z["records"], z.get("ttl", 14400))
    checker = shutil.which("named-checkzone")
    if checker:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".zone") as tmp:
            tmp.write(text)
        try:
            r = subprocess.run([checker, domain, tmp.name], capture_output=True, text=True, timeout=20)
        finally:
            Path(tmp.name).unlink(missing_ok=True)
        if r.returncode != 0:
            raise ZoneError("Zone check failed:\n" + (r.stdout + r.stderr).replace(tmp.name, "zone").strip()[:1500])
    ZONE_DIR.mkdir(parents=True, exist_ok=True)
    _path(domain).write_text(text, encoding="utf-8")
    served = _publish(domain)
    if served:
        try:
            apply_options()  # NS records may name new secondaries
        except ZoneError:
            pass
    return {"ok": True, "serial": z["soa"]["serial"], "served": served}


def _publish(domain: str) -> bool:
    if not (bind_installed() and NAMED_LOCAL.exists()):
        return False
    conf = NAMED_LOCAL.read_text()
    if f'zone "{domain}"' not in conf:
        conf = conf.rstrip("\n") + f'\n\n// aurora-zone {domain}\nzone "{domain}" {{ type master; file "{_path(domain)}"; }};\n'
        NAMED_LOCAL.write_text(conf)
        subprocess.run(["rndc", "reconfig"], capture_output=True, timeout=20)
    r = subprocess.run(["rndc", "reload", domain], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        subprocess.run(["systemctl", "reload", "named"], capture_output=True, timeout=30)
    return True


def _unpublish(domain: str) -> None:
    if not NAMED_LOCAL.exists():
        return
    conf = NAMED_LOCAL.read_text()
    new = re.sub(rf'\n*// aurora-zone {re.escape(domain)}\nzone "{re.escape(domain)}" \{{[^\n]*\}};\n?', "\n", conf)
    if new != conf:
        NAMED_LOCAL.write_text(new)
        if bind_installed():
            subprocess.run(["rndc", "reconfig"], capture_output=True, timeout=20)


def _live_ns(domain: str) -> list[str]:
    if not shutil.which("dig"):
        return []
    try:
        r = subprocess.run(["dig", "+short", "+time=3", "+tries=1", "NS", domain], capture_output=True, text=True, timeout=10)
        return sorted(l.strip().rstrip(".") for l in r.stdout.splitlines() if l.strip() and not l.startswith(";"))
    except (subprocess.SubprocessError, OSError):
        return []


def list_zones(site_names: list[str]) -> dict:
    zones, seen = [], set()
    if ZONE_DIR.exists():
        for f in sorted(ZONE_DIR.glob("db.*")):
            d = f.name[3:]
            if not _DOMAIN.match(d):
                continue
            try:
                z = parse(f.read_text(errors="replace"), d)
            except Exception as quiet_exc:
                problems.quiet(quiet_exc)
                continue
            seen.add(d)
            zones.append({"domain": d, "records": len(z["records"]), "serial": z["soa"]["serial"] if z["soa"] else None,
                          "managed": f.read_text(errors="replace").startswith(HEADER)})
    missing = sorted({n for n in site_names if _DOMAIN.match(n) and n not in seen and not n.startswith("www.")})
    return {"zones": zones, "without_zone": missing, "bind_installed": bind_installed(),
            "checker": bool(shutil.which("named-checkzone"))}


def get_zone(domain: str) -> dict:
    domain = _dom(domain)
    z = _load(domain)
    ns_zone = sorted(r["target"].rstrip(".") for r in z["records"] if r["type"] == "NS" and r["name"] == domain + ".")
    return {"domain": domain, "soa": z["soa"], "ttl": z["ttl"], "records": z["records"], "ns_zone": ns_zone,
            "ns_live": _live_ns(domain), "bind_installed": bind_installed(), "zone_text": _path(domain).read_text(errors="replace")}


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def _dig_import(domain: str) -> list[dict]:
    recs = []
    if not shutil.which("dig"):
        return recs
    for host in ["", "www.", "mail.", "ftp.", "_dmarc.", "autodiscover."]:
        for t in ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA"]:
            if host and t in ("NS", "MX", "CAA") or (not host and t == "CNAME"):
                continue
            try:
                r = subprocess.run(["dig", "+noall", "+answer", "+time=3", "+tries=1", t, host + domain],
                                   capture_output=True, text=True, timeout=8)
            except (subprocess.SubprocessError, OSError):
                continue
            z = parse(r.stdout, domain)
            for rec in z["records"]:
                if rec["type"] == t and rec["name"].rstrip(".") == (host + domain).rstrip("."):
                    if rec not in recs:
                        recs.append(rec)
    return recs


def create_zone(domain: str, ip: str = "", mode: str = "default") -> dict:
    domain = _dom(domain)
    if _path(domain).exists():
        raise ZoneError("A zone already exists for that domain")
    ip = (ip or "").strip() or _local_ip()
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise ZoneError("Enter a valid IPv4 address for the zone")
    soa = {"mname": f"ns1.{domain}.", "rname": f"hostmaster.{domain}.", "serial": 0,
           "refresh": 3600, "retry": 1800, "expire": 1209600, "minimum": 86400, "ttl": 86400}
    if mode == "import":
        recs = _dig_import(domain)
        if not recs:
            raise ZoneError("No public DNS records found to import — create with defaults instead")
        live_ns = [r for r in recs if r["type"] == "NS"]
        if live_ns:
            soa["mname"] = live_ns[0]["target"]
    else:
        d = domain + "."
        recs = [
            {"name": d, "ttl": 86400, "type": "NS", "target": f"ns1.{d}"},
            {"name": d, "ttl": 86400, "type": "NS", "target": f"ns2.{d}"},
            {"name": d, "ttl": 14400, "type": "A", "address": ip},
            {"name": f"ns1.{d}", "ttl": 14400, "type": "A", "address": ip},
            {"name": f"ns2.{d}", "ttl": 14400, "type": "A", "address": ip},
            {"name": f"mail.{d}", "ttl": 14400, "type": "A", "address": ip},
            {"name": f"www.{d}", "ttl": 14400, "type": "CNAME", "target": d},
            {"name": f"ftp.{d}", "ttl": 14400, "type": "CNAME", "target": d},
            {"name": d, "ttl": 14400, "type": "MX", "priority": 10, "target": f"mail.{d}"},
            {"name": d, "ttl": 14400, "type": "TXT", "text": f"v=spf1 a mx ip4:{ip} ~all"},
        ]
    cleaned = []
    for r in recs:
        try:
            cleaned.append(clean_record(r, domain))
        except ZoneError:
            if mode != "import":
                raise  # imported records we can't represent (e.g. null MX ".") are skipped
    recs = cleaned
    return _write(domain, {"soa": soa, "records": recs, "ttl": 14400})


def _find(z: dict, index: int, fingerprint: dict | None) -> int:
    if not 0 <= index < len(z["records"]):
        raise ZoneError("Record not found — the zone changed, reload and try again")
    if fingerprint:
        cur = z["records"][index]
        if cur.get("name") != fingerprint.get("name") or cur.get("type") != fingerprint.get("type"):
            raise ZoneError("Record changed since you loaded it — reload and try again")
    return index


def add_record(domain: str, record: dict) -> dict:
    domain = _dom(domain)
    z = _load(domain)
    z["records"].append(clean_record(record, domain))
    return _write(domain, z)


def update_record(domain: str, index: int, record: dict, fingerprint: dict | None = None) -> dict:
    domain = _dom(domain)
    z = _load(domain)
    z["records"][_find(z, index, fingerprint)] = clean_record(record, domain)
    return _write(domain, z)


def delete_record(domain: str, index: int, fingerprint: dict | None = None) -> dict:
    domain = _dom(domain)
    z = _load(domain)
    z["records"].pop(_find(z, index, fingerprint))
    return _write(domain, z)


def delete_zone(domain: str) -> dict:
    domain = _dom(domain)
    p = _path(domain)
    if not p.exists():
        raise ZoneError("No zone for that domain")
    _unpublish(domain)
    p.rename(p.with_name(p.name + f".deleted-{int(time.time())}"))
    return {"ok": True}
