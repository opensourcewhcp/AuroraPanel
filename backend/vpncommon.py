"""Shared plumbing for the Network section's VPN servers (WireGuard, OpenVPN,
strongSwan): network settings (public endpoint, client DNS), IPv4 forwarding,
NAT for VPN subnets (one nftables table owned by a oneshot unit), ufw rules
and apt installs."""
from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import distro
from . import jobs

IS_LINUX = platform.system() == "Linux"
STATE_DIR = Path("/var/lib/aurora/vpn")
SETTINGS = Path("/var/lib/aurora/network.json")
NAT_FILE = STATE_DIR / "nat.nft"
NAT_UNIT = Path("/etc/systemd/system/aurora-vpn-nat.service")
SYSCTL_FILE = Path("/etc/sysctl.d/99-aurora-vpn.conf")
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "PATH": distro.PATH}
APT = ["apt-get", "-o", "DPkg::Lock::Timeout=600", "-y"]
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")


class VPNError(RuntimeError):
    pass


def run(argv: list[str], input: str | None = None, timeout: int = 60, check: bool = True,
        env: dict | None = None) -> subprocess.CompletedProcess:
    try:
        r = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "PATH": APT_ENV["PATH"], **(env or {})})
    except (OSError, subprocess.SubprocessError) as exc:
        raise VPNError(f"{argv[0]}: {exc}")
    if check and r.returncode != 0:
        raise VPNError((r.stderr or r.stdout or f"{argv[0]} failed").strip()[-600:])
    return r


def require_linux():
    if not IS_LINUX or not shutil.which("systemctl"):
        raise VPNError("VPN servers need Linux with systemd")


def valid_name(name: str) -> str:
    name = (name or "").strip()
    if not _NAME.match(name):
        raise VPNError("Name: letters, digits, dot, dash or underscore (max 32)")
    return name


def which(*names: str) -> bool:
    return all(shutil.which(n, path=APT_ENV["PATH"] + ":" + os.environ.get("PATH", "")) for n in names)


def write_secret(path: Path, text: str, mode: int = 0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def load_json(path: Path, default: dict) -> dict:
    try:
        return {**default, **json.loads(path.read_text(encoding="utf-8"))}
    except (OSError, ValueError):
        return dict(default)


def save_json(path: Path, data: dict):
    write_secret(path, json.dumps(data, indent=2))


# ---- systemd ----
def unit_state(unit: str) -> dict:
    if not shutil.which("systemctl"):
        return {"active": False, "enabled": False}
    a = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True).stdout.strip()
    e = subprocess.run(["systemctl", "is-enabled", unit], capture_output=True, text=True).stdout.strip()
    return {"active": a == "active", "state": a, "enabled": e == "enabled"}


def control(unit: str, action: str) -> dict:
    if action not in ("start", "stop", "restart"):
        raise VPNError("Invalid action")
    if action == "stop":
        run(["systemctl", "disable", "--now", unit], timeout=60)
    else:
        run(["systemctl", "enable", unit], timeout=30)
        run(["systemctl", action, unit], timeout=60)
    return {"ok": True, **unit_state(unit)}


def apt_install(title: str, pkgs: list[str], meta: dict | None = None) -> jobs.Job:
    require_linux()
    return jobs.launch(title, [*APT, "install", *pkgs], env=APT_ENV, meta=meta or {})


def apt_remove(title: str, pkgs: list[str]) -> jobs.Job:
    require_linux()
    return jobs.launch(title, [*APT, "remove", *pkgs], env=APT_ENV)


# ---- LAN / WAN facts ----
def default_route() -> dict:
    """{'iface', 'gateway', 'ip', 'lan'} of the default IPv4 route."""
    out = {"iface": None, "gateway": None, "ip": None, "lan": None}
    if not shutil.which("ip"):
        return out
    r = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True).stdout
    m = re.search(r"default via (\S+) dev (\S+)", r)
    if not m:
        return out
    out["gateway"], out["iface"] = m.group(1), m.group(2)
    a = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", out["iface"]], capture_output=True, text=True).stdout
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", a)
    if m:
        itf = ipaddress.ip_interface(m.group(1))
        out["ip"], out["lan"] = str(itf.ip), str(itf.network)
    return out


def public_ip(fresh: bool = False) -> str | None:
    from . import domains
    if fresh:
        domains._public_ip_cache.update(ip=None, ts=0)
    return domains.public_ip()


# ---- Network settings (endpoint clients connect to, DNS pushed to clients) ----
_DEFAULTS = {"endpoint": "", "dns": "1.1.1.1, 1.0.0.1"}


def settings() -> dict:
    s = load_json(SETTINGS, _DEFAULTS)
    from . import ddns
    host = ddns.hostname()
    s["ddns_hostname"] = host
    s["public_ip"] = public_ip()
    s["effective_endpoint"] = s["endpoint"] or host or s["public_ip"] or ""
    s["endpoint_source"] = "custom" if s["endpoint"] else "ddns" if host else "public_ip"
    return s


def save_settings(endpoint: str | None = None, dns: str | None = None) -> dict:
    s = load_json(SETTINGS, _DEFAULTS)
    if endpoint is not None:
        endpoint = endpoint.strip().lower()
        if endpoint and not re.match(r"^[a-z0-9.-]{1,253}$", endpoint):
            raise VPNError("Endpoint must be a hostname or IPv4 address")
        s["endpoint"] = endpoint
    if dns is not None:
        dns_list = dns_servers(dns)
        s["dns"] = ", ".join(dns_list)
    SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    save_json(SETTINGS, {k: s[k] for k in _DEFAULTS})
    return settings()


def dns_servers(text: str | None = None) -> list[str]:
    text = load_json(SETTINGS, _DEFAULTS)["dns"] if text is None else text
    out = []
    for part in re.split(r"[,\s]+", text or ""):
        if not part:
            continue
        try:
            out.append(str(ipaddress.IPv4Address(part)))
        except ValueError:
            raise VPNError(f"Not an IPv4 address: {part}")
    if not out:
        raise VPNError("At least one DNS server is required")
    return out


def endpoint() -> str:
    ep = settings()["effective_endpoint"]
    if not ep:
        raise VPNError("No public address known — set the VPN endpoint (or Dynamic DNS) first")
    return ep


# ---- Forwarding + NAT ----
def enable_forwarding():
    SYSCTL_FILE.write_text("# AuroraPanel VPN: route client traffic\nnet.ipv4.ip_forward = 1\n", encoding="utf-8")
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")


def forwarding_enabled() -> bool:
    try:
        return Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    except OSError:
        return False


def _nat_subnets() -> list[str]:
    try:
        return json.loads((STATE_DIR / "nat.json").read_text())
    except (OSError, ValueError):
        return []


def set_nat(subnet: str, on: bool):
    """Masquerade (or stop masquerading) a VPN subnet; rewrites + reloads the table."""
    subnet = str(ipaddress.ip_network(subnet, strict=False))
    nets = [n for n in _nat_subnets() if n != subnet] + ([subnet] if on else [])
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    save_json(STATE_DIR / "nat.json", nets)  # type: ignore[arg-type]
    rules = "\n".join(f"    ip saddr {n} ip daddr != {n} masquerade" for n in nets)
    NAT_FILE.write_text(f"""# Managed by AuroraPanel — NAT for VPN clients.
table ip aurora_vpn
delete table ip aurora_vpn
table ip aurora_vpn {{
  chain vpn_postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
{rules}
  }}
  chain vpn_forward {{
    type filter hook forward priority mangle; policy accept;
    tcp flags syn tcp option maxseg size set rt mtu
  }}
}}
""", encoding="utf-8")
    if not NAT_UNIT.exists():
        nft = shutil.which("nft", path=APT_ENV["PATH"]) or "/usr/sbin/nft"
        NAT_UNIT.write_text(f"""[Unit]
Description=AuroraPanel VPN NAT (nftables table aurora_vpn)
After=network-pre.target
Before=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={nft} -f {NAT_FILE}
ExecStop={nft} delete table ip aurora_vpn

[Install]
WantedBy=multi-user.target
""", encoding="utf-8")
        run(["systemctl", "daemon-reload"])
    if nets:
        run(["systemctl", "enable", "aurora-vpn-nat.service"])
        run(["systemctl", "restart", "aurora-vpn-nat.service"])
    else:
        run(["systemctl", "disable", "--now", "aurora-vpn-nat.service"], check=False)


def nat_active(subnet: str) -> bool:
    return str(ipaddress.ip_network(subnet, strict=False)) in _nat_subnets() and \
        unit_state("aurora-vpn-nat.service")["active"]


# ---- ufw (only touched when installed) ----
def ufw_open(port: int, proto: str, subnet: str | None = None):
    from . import firewall
    if firewall._firewalld():
        firewall.open_ports(f"{port}/{proto}")
        if subnet:
            firewall.trust_subnet(subnet)
        return
    ufw = shutil.which("ufw", path=APT_ENV["PATH"])
    if not ufw:
        return
    subprocess.run([ufw, "allow", f"{port}/{proto}", "comment", "AuroraPanel VPN"], capture_output=True, text=True, timeout=20)
    if subnet:
        # ufw's default FORWARD policy is DROP; let VPN clients be routed.
        subprocess.run([ufw, "route", "allow", "from", subnet], capture_output=True, text=True, timeout=20)
        subprocess.run([ufw, "route", "allow", "to", subnet], capture_output=True, text=True, timeout=20)
        # …and reach this server itself (the panel, DNS, file shares) — that's what a home VPN is for.
        subprocess.run([ufw, "allow", "from", subnet, "comment", "AuroraPanel VPN clients"], capture_output=True, text=True, timeout=20)


def ufw_close(port: int, proto: str, subnet: str | None = None):
    from . import firewall
    if firewall._firewalld():
        firewall.close_ports(f"{port}/{proto}")
        if subnet:
            firewall.trust_subnet(subnet, False)
        return
    ufw = shutil.which("ufw", path=APT_ENV["PATH"])
    if not ufw:
        return
    subprocess.run([ufw, "delete", "allow", f"{port}/{proto}"], capture_output=True, text=True, timeout=20)
    if subnet:
        subprocess.run([ufw, "route", "delete", "allow", "from", subnet], capture_output=True, text=True, timeout=20)
        subprocess.run([ufw, "route", "delete", "allow", "to", subnet], capture_output=True, text=True, timeout=20)
        subprocess.run([ufw, "delete", "allow", "from", subnet], capture_output=True, text=True, timeout=20)


# ---- Self-test helpers (network namespace playing the part of a client) ----
TEST_NS = "aurora-vpntest"


def ns_cleanup():
    subprocess.run(["ip", "netns", "del", TEST_NS], capture_output=True)


def ns_exec(argv: list[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return run(["ip", "netns", "exec", TEST_NS, *argv], timeout=timeout, check=False)


PING_ATTEMPTS, PING_RETRY_SECONDS = 5, 3


def ns_ping(log, target: str, what: str) -> bool:
    if not shutil.which("ping", path=APT_ENV["PATH"]):
        # Minimal cloud images ship without ping; without it the test can't tell anything.
        subprocess.run(["apt-get", "-o", "DPkg::Lock::Timeout=120", "-y", "install", "iputils-ping"],
                       capture_output=True, text=True, timeout=300, env={**os.environ, **APT_ENV})
        if not shutil.which("ping", path=APT_ENV["PATH"]):
            log(f"✖ {what}: the ping tool isn't installed (apt install iputils-ping)")
            return False
    # A tunnel device that has just appeared can drop packets for a few seconds, so give it several chances.
    for attempt in range(PING_ATTEMPTS):
        if attempt:
            time.sleep(PING_RETRY_SECONDS)
        r = ns_exec(["ping", "-c", "3", "-W", "2", target], timeout=15)
        ok = r.returncode == 0 and " 0% packet loss" in r.stdout
        if ok:
            break
    m = re.search(r"([\d.]+)% packet loss", r.stdout)
    log(f"{'✔' if ok else '✖'} {what} (ping {target}{', ' + m.group(1) + '% loss' if m else ''})")
    return ok


def subnet_host(subnet: str, index: int) -> str:
    net = ipaddress.ip_network(subnet, strict=False)
    return str(net.network_address + index)


def next_free_ip(subnet: str, used: set[str]) -> str:
    net = ipaddress.ip_network(subnet, strict=False)
    for h in list(net.hosts())[1:]:  # .1 is the server
        if str(h) not in used:
            return str(h)
    raise VPNError("The VPN subnet is full")
