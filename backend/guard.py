"""Bans & trusted addresses (one nftables table: inet aurora_guard).

  trusted  (trust4/trust6)  never blocked by anything here, and exempt from
                            fail2ban (written to its ignoreip)
  bans     (ban4/ban6)      manual bans: single IPs or ranges (CIDR), optional
                            expiry, with a reason
  fail2ban (f2b4/f2b6)      filled by fail2ban's "aurora-guard" action, with
                            per-ban timeouts

Works whether or not ufw is enabled (its own hook runs first, priority -20).
State lives in /var/lib/aurora/guard.json; changes are applied live with
`nft add/delete element` (so fail2ban's entries survive), and the full table
is rebuilt from the JSON at boot by aurora-guard.service.

Safety: refuses to ban loopback, this Pi's own addresses, the LAN gateway,
the address of the admin doing the banning, or anything trusted."""
from __future__ import annotations

import ipaddress
import re
import json
import shutil
import subprocess
import time
from pathlib import Path

from . import distro
from . import problems
from .vpncommon import default_route, load_json, save_json, write_secret

STATE = Path("/var/lib/aurora/guard.json")
NFT_FILE = Path("/var/lib/aurora/guard.nft")
UNIT = Path("/etc/systemd/system/aurora-guard.service")
BAN_HELPER = Path("/usr/local/sbin/aurora-guard-ban")
TABLE = "inet aurora_guard"
LOG_PREFIX = "aurora-block: "


class GuardError(RuntimeError):
    pass


def _nft() -> str:
    n = shutil.which("nft", path=distro.PATH)
    if not n:
        raise GuardError("nftables is not installed (apt install nftables)")
    return n


def _run(args: list[str], check=True, input=None) -> subprocess.CompletedProcess:
    r = subprocess.run(args, capture_output=True, text=True, timeout=30, input=input)
    if check and r.returncode != 0:
        raise GuardError((r.stderr or r.stdout).strip()[-400:] or "nft failed")
    return r


def _state() -> dict:
    s = load_json(STATE, {"bans": [], "trusted": []})
    now = time.time()
    s["bans"] = [b for b in s["bans"] if not b.get("expires") or b["expires"] > now]
    return s


def _save(s: dict):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    save_json(STATE, s)
    _write_boot_file(s)


def _net(text: str) -> ipaddress._BaseNetwork:
    try:
        n = ipaddress.ip_network((text or "").strip(), strict=False)
    except ValueError:
        raise GuardError("Enter an IP address or a range like 203.0.113.0/24")
    if n.version == 4 and n.prefixlen < 8 or n.version == 6 and n.prefixlen < 16:
        raise GuardError("That range is too large to ban")
    return n


def _fam(n) -> str:
    return "4" if n.version == 4 else "6"


def _elem(n) -> str:
    return str(n.network_address) if n.num_addresses == 1 else str(n)


# ---------------------------------------------------------------- table
def _table_text(s: dict) -> str:
    now = time.time()

    def elems(items, with_timeout):
        out = []
        for it in items:
            e = _elem(ipaddress.ip_network(it["cidr"]))
            if with_timeout and it.get("expires"):
                out.append(f"{e} timeout {max(1, int(it['expires'] - now))}s")
            else:
                out.append(e)
        return out

    def setdef(name, typ, flags, items, with_timeout=False):
        body = f"    type {typ}; flags {flags}; counter;"
        e = elems(items, with_timeout)
        if e:
            body += f"\n    elements = {{ {', '.join(e)} }}"
        return f"  set {name} {{\n{body}\n  }}"

    t4 = [t for t in s["trusted"] if ipaddress.ip_network(t["cidr"]).version == 4]
    t6 = [t for t in s["trusted"] if ipaddress.ip_network(t["cidr"]).version == 6]
    b4 = [b for b in s["bans"] if ipaddress.ip_network(b["cidr"]).version == 4]
    b6 = [b for b in s["bans"] if ipaddress.ip_network(b["cidr"]).version == 6]
    return "\n".join([
        "# Managed by AuroraPanel — bans & trusted addresses.",
        f"table {TABLE}", f"delete table {TABLE}", f"table {TABLE} {{",
        setdef("trust4", "ipv4_addr", "interval", t4), setdef("trust6", "ipv6_addr", "interval", t6),
        setdef("ban4", "ipv4_addr", "interval, timeout", b4, True), setdef("ban6", "ipv6_addr", "interval, timeout", b6, True),
        "  set f2b4 {\n    type ipv4_addr; flags timeout; counter;\n  }",
        "  set f2b6 {\n    type ipv6_addr; flags timeout; counter;\n  }",
        "  chain guard_input {",
        "    type filter hook input priority -20; policy accept;",
        '    iifname "lo" return',
        "    ip saddr @trust4 return",
        "    ip6 saddr @trust6 return",
        f'    ip saddr @ban4 limit rate 10/second log prefix "{LOG_PREFIX}" level info',
        "    ip saddr @ban4 drop",
        f'    ip6 saddr @ban6 limit rate 10/second log prefix "{LOG_PREFIX}" level info',
        "    ip6 saddr @ban6 drop",
        f'    ip saddr @f2b4 limit rate 10/second log prefix "{LOG_PREFIX}" level info',
        "    ip saddr @f2b4 drop",
        f'    ip6 saddr @f2b6 limit rate 10/second log prefix "{LOG_PREFIX}" level info',
        "    ip6 saddr @f2b6 drop",
        "  }",
        "}", ""])


def _write_boot_file(s: dict):
    NFT_FILE.parent.mkdir(parents=True, exist_ok=True)
    NFT_FILE.write_text(_table_text(s), encoding="utf-8")


def _table_exists() -> bool:
    return _run([_nft(), "list", "table", "inet", "aurora_guard"], check=False).returncode == 0


def ensure() -> None:
    """Create the table + boot unit + fail2ban helper if missing (idempotent)."""
    nft = _nft()
    s = _state()
    _write_boot_file(s)
    if not UNIT.exists():
        UNIT.write_text(f"""[Unit]
Description=AuroraPanel bans & trusted addresses (nftables table aurora_guard)
After=network-pre.target
Before=network-online.target fail2ban.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={nft} -f {NFT_FILE}
ExecStop={nft} delete table inet aurora_guard

[Install]
WantedBy=multi-user.target
""", encoding="utf-8")
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", "aurora-guard.service"])
    if not _table_exists():
        _run([nft, "-f", str(NFT_FILE)])
    _write_helper(nft)


def _write_helper(nft: str):
    """Tiny root helper fail2ban's action calls: aurora-guard-ban add|del <ip> [seconds]."""
    BAN_HELPER.write_text(f"""#!/bin/sh
# Managed by AuroraPanel — used by fail2ban action aurora-guard.
set -e
op="$1"; ip="$2"; secs="$3"
case "$ip" in *[!0-9a-fA-F.:]*|"") echo "bad ip" >&2; exit 2;; esac
case "$ip" in *:*) set=f2b6;; *) set=f2b4;; esac
{nft} list table inet aurora_guard >/dev/null 2>&1 || {nft} -f {NFT_FILE}
if [ "$op" = add ]; then
  case "$secs" in ''|-*|*[!0-9]*) {nft} add element inet aurora_guard $set "{{ $ip }}";;
    *) {nft} add element inet aurora_guard $set "{{ $ip timeout ${{secs}}s }}";; esac
else
  {nft} delete element inet aurora_guard $set "{{ $ip }}" 2>/dev/null || true
fi
""", encoding="utf-8")
    BAN_HELPER.chmod(0o755)


# ---------------------------------------------------------------- live data
def _set_elements(name: str) -> dict[str, dict]:
    """element -> {packets, expires_in} from `nft -j list set`."""
    r = _run([_nft(), "-j", "list", "set", "inet", "aurora_guard", name], check=False)
    out = {}
    if r.returncode != 0:
        return out
    try:
        data = json.loads(r.stdout)["nftables"]
    except (ValueError, KeyError):
        return out
    for item in data:
        st = item.get("set")
        if not st:
            continue
        for e in st.get("elem", []):
            val, packets, expires = e, 0, None
            if isinstance(e, dict) and "elem" in e:
                inner = e["elem"]
                val = inner.get("val")
                packets = (inner.get("counter") or {}).get("packets", 0)
                expires = inner.get("expires")
            if isinstance(val, dict) and "prefix" in val:
                val = f"{val['prefix']['addr']}/{val['prefix']['len']}"
            elif isinstance(val, dict) and "range" in val:
                val = f"{val['range'][0]}-{val['range'][1]}"
            out[str(val)] = {"packets": packets, "expires_in": expires}
    return out


def _f2b_jails_by_ip() -> dict[str, list[str]]:
    if not shutil.which("fail2ban-client"):
        return {}
    r = subprocess.run(["fail2ban-client", "banned"], capture_output=True, text=True, timeout=15)
    out: dict[str, list[str]] = {}
    try:
        import ast
        for d in ast.literal_eval(r.stdout.strip() or "[]"):
            for jail, ips in d.items():
                for ip in ips:
                    out.setdefault(ip, []).append(jail)
    except (ValueError, SyntaxError):
        pass
    return out


def listing() -> dict:
    s = _state()
    live = {} if not _table_exists() else {**_set_elements("ban4"), **_set_elements("ban6")}
    f2b = {} if not _table_exists() else {**_set_elements("f2b4"), **_set_elements("f2b6")}
    tl = {} if not _table_exists() else {**_set_elements("trust4"), **_set_elements("trust6")}
    jails = _f2b_jails_by_ip()
    bans = []
    for b in s["bans"]:
        e = _elem(ipaddress.ip_network(b["cidr"]))
        bans.append({**b, "packets": live.get(e, {}).get("packets", 0), "active": e in live})
    auto = [{"ip": ip, "packets": v["packets"], "expires_in": v["expires_in"], "jails": jails.get(ip, [])}
            for ip, v in f2b.items()]
    trusted = [{**t, "packets": tl.get(_elem(ipaddress.ip_network(t["cidr"])), {}).get("packets", 0)} for t in s["trusted"]]
    return {"enabled": _table_exists(), "bans": sorted(bans, key=lambda b: -b["created"]),
            "fail2ban": sorted(auto, key=lambda a: a["ip"]), "trusted": trusted,
            "protected": _protected_desc()}


# ---------------------------------------------------------------- checks
def _protected_nets(client_ip: str | None) -> list[tuple[ipaddress._BaseNetwork, str]]:
    nets = [(ipaddress.ip_network("127.0.0.0/8"), "loopback"), (ipaddress.ip_network("::1/128"), "loopback")]
    r = default_route()
    if r.get("ip"):
        nets.append((ipaddress.ip_network(r["ip"]), "this Pi"))
    if r.get("gateway"):
        nets.append((ipaddress.ip_network(r["gateway"]), "your router"))
    if client_ip:
        try:
            ip = ipaddress.ip_address(client_ip)
            if ip.version == 6 and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            nets.append((ipaddress.ip_network(ip), "you (the address you're using the panel from)"))
        except ValueError:
            pass
    return nets


def _protected_desc() -> list[str]:
    return [f"{n} ({why})" for n, why in _protected_nets(None)]


def _covers(a, b) -> bool:
    return a.version == b.version and (b.subnet_of(a) if a.num_addresses >= b.num_addresses else a.subnet_of(b))


# ---------------------------------------------------------------- actions
def ban(target: str, reason: str = "", duration: int | None = None, client_ip: str | None = None, source: str = "") -> dict:
    ensure()
    n = _net(target)
    for p, why in _protected_nets(client_ip):
        if n.version == p.version and (p.subnet_of(n) or n.subnet_of(p)):
            raise GuardError(f"Refusing to ban {n}: it includes {why}")
    s = _state()
    for t in s["trusted"]:
        if _covers(n, ipaddress.ip_network(t["cidr"])):
            raise GuardError(f"{n} overlaps the trusted {t['cidr']} — remove it from Trusted first")
    for b in s["bans"]:
        bn = ipaddress.ip_network(b["cidr"])
        if bn.version == n.version and n.subnet_of(bn) and not (b.get("expires") and duration is None):
            raise GuardError(f"Already covered by the ban on {b['cidr']}")
    # A wider ban replaces narrower ones inside it (nft interval sets can't overlap).
    inside = [b for b in s["bans"] if ipaddress.ip_network(b["cidr"]).version == n.version and ipaddress.ip_network(b["cidr"]).subnet_of(n)]
    for b in inside:
        _del_elem("ban", ipaddress.ip_network(b["cidr"]))
    s["bans"] = [b for b in s["bans"] if b not in inside]
    duration = int(duration) if duration else None
    if duration is not None and not 60 <= duration <= 10 * 365 * 86400:
        raise GuardError("Duration must be between 1 minute and 10 years")
    entry = {"cidr": str(n), "reason": (reason or "").strip()[:120], "created": int(time.time()),
             "expires": int(time.time()) + duration if duration else None,
             "source": re.sub(r"[^\w &·/().,-]", "", source or "")[:60] or "IP Blocker"}  # the panel page it was banned from
    el = _elem(n) + (f" timeout {duration}s" if duration else "")
    _run([_nft(), "add", "element", "inet", "aurora_guard", f"ban{_fam(n)}", "{ " + el + " }"])
    s["bans"].append(entry)
    _save(s)
    # fail2ban may also hold single IPs inside the range — clear those entries.
    if n.num_addresses > 1:
        for ip in list({**_set_elements("f2b4"), **_set_elements("f2b6")}):
            try:
                if ipaddress.ip_address(ip) in n:
                    _unban_f2b(ip)
            except ValueError:
                pass
    return {"ok": True, "ban": entry, "replaced": [b["cidr"] for b in inside]}


def _del_elem(kind: str, n):
    _run([_nft(), "delete", "element", "inet", "aurora_guard", f"{kind}{_fam(n)}", "{ " + _elem(n) + " }"], check=False)


def _unban_f2b(ip: str):
    if shutil.which("fail2ban-client"):
        subprocess.run(["fail2ban-client", "unban", ip], capture_output=True, text=True, timeout=15)
    n = ipaddress.ip_network(ip)
    _del_elem("f2b", n)


def unban(target: str, include_fail2ban: bool = True) -> dict:
    """include_fail2ban=False lifts only this list's own entry."""
    n = _net(target)
    s = _state()
    before = len(s["bans"])
    s["bans"] = [b for b in s["bans"] if ipaddress.ip_network(b["cidr"]) != n]
    if _table_exists():
        _del_elem("ban", n)
    if len(s["bans"]) != before:
        _save(s)
    if include_fail2ban and n.num_addresses == 1:
        _unban_f2b(str(n.network_address))
    return {"ok": True}


def trust(target: str, note: str = "") -> dict:
    ensure()
    n = _net(target)
    s = _state()
    if any(ipaddress.ip_network(t["cidr"]) == n for t in s["trusted"]):
        raise GuardError("Already trusted")
    for t in s["trusted"]:
        if _covers(n, ipaddress.ip_network(t["cidr"])):
            raise GuardError(f"Overlaps the trusted {t['cidr']} — edit that entry instead")
    removed = []
    for b in list(s["bans"]):
        if _covers(n, ipaddress.ip_network(b["cidr"])):
            _del_elem("ban", ipaddress.ip_network(b["cidr"]))
            s["bans"].remove(b)
            removed.append(b["cidr"])
    for ip in list({**_set_elements("f2b4"), **_set_elements("f2b6")}):
        try:
            if ipaddress.ip_address(ip) in n:
                _unban_f2b(ip)
                removed.append(ip)
        except ValueError:
            pass
    _run([_nft(), "add", "element", "inet", "aurora_guard", f"trust{_fam(n)}", "{ " + _elem(n) + " }"])
    s["trusted"].append({"cidr": str(n), "note": (note or "").strip()[:120], "created": int(time.time())})
    _save(s)
    _sync_fail2ban()
    _sync_waf()
    return {"ok": True, "unbanned": removed}


def untrust(target: str) -> dict:
    n = _net(target)
    s = _state()
    s["trusted"] = [t for t in s["trusted"] if ipaddress.ip_network(t["cidr"]) != n]
    if _table_exists():
        _del_elem("trust", n)
    _save(s)
    _sync_fail2ban()
    _sync_waf()
    return {"ok": True}


def trusted_cidrs() -> list[str]:
    return [t["cidr"] for t in _state()["trusted"]]


def is_trusted(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(c) for c in trusted_cidrs())


def status_of(ips: list[str]) -> dict[str, str]:
    """ip -> 'trusted' | 'banned' for the Network Monitor."""
    s = _state()
    tr = [ipaddress.ip_network(t["cidr"]) for t in s["trusted"]]
    bn = [ipaddress.ip_network(b["cidr"]) for b in s["bans"]]
    f2b = set({**_set_elements("f2b4"), **_set_elements("f2b6")}) if _table_exists() else set()
    out = {}
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(a in n for n in tr):
            out[ip] = "trusted"
        elif ip in f2b or any(a in n for n in bn):
            out[ip] = "banned"
    return out


def ban_times(ips: list[str]) -> dict[str, int]:
    """ip -> when the panel's ban on it began. Fail2Ban's own bans carry no start time here, so they're left out."""
    bans = [(ipaddress.ip_network(b["cidr"]), int(b.get("created") or 0)) for b in _state()["bans"]]
    out = {}
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        since = [c for n, c in bans if c and a in n]
        if since:
            out[ip] = min(since)
    return out


def _sync_waf():
    """The WAF (ModSecurity) exempts trusted addresses too: rewrite its rules when the list changes."""
    try:
        from . import waf
        if waf.installed() and waf.module_on():
            waf.apply()
    except Exception as exc:
        problems.record("Trusted addresses → WAF", exc, hint="The WAF may still block a trusted address. Open Security → WAF Firewall and press Apply.")


def _sync_fail2ban():
    try:
        from . import fail2ban
        fail2ban.sync_ignoreip()
    except Exception as exc:
        problems.record("Trusted addresses → fail2ban", exc, hint="fail2ban may still ban a trusted address. Open Security → Fail2ban and save its settings once.")
