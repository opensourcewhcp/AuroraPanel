"""Firewall management via ufw (Uncomplicated Firewall)."""
from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess

IS_LINUX = platform.system() == "Linux"

# Ports that must never be firewalled off, or the admin loses access to the box.
def _safe_ports() -> list[str]:
    panel_port = os.environ.get("PORT", "8088")
    return ["22", str(panel_port)]


class FirewallError(RuntimeError):
    pass


def _ufw() -> str:
    path = shutil.which("ufw") if IS_LINUX else None
    if not path:
        raise FirewallError("ufw is not installed (try installing it from Packages)")
    return path


def available() -> bool:
    return bool(IS_LINUX and shutil.which("ufw"))


def status() -> dict:
    if not available():
        return {"available": False, "active": False, "rules": []}
    out = subprocess.run([_ufw(), "status", "numbered"], capture_output=True, text=True, timeout=10)
    text = out.stdout
    active = "Status: active" in text
    rules = []
    for line in text.splitlines():
        m = re.match(r"^\[\s*(\d+)\]\s+(.*)", line.strip())
        if m:
            rules.append({"num": int(m.group(1)), "rule": re.sub(r"\s+", " ", m.group(2)).strip()})
    return {"available": True, "active": active, "rules": rules}


# UDP services worth keeping reachable when the firewall goes up (DNS, IPsec, OpenVPN, WireGuard).
_UDP_KNOWN = {53, 500, 4500, 1194, 51820}


def listening_ports() -> list[str]:
    """What this server offers to the network right now: TCP ports listening on every address, plus the
    well-known UDP services. Allowing these before `ufw enable` means switching the firewall on blocks
    nothing that works today — only what nobody opened on purpose — and the list can be trimmed afterwards."""
    try:
        import psutil
    except ImportError:
        return []
    out: set[str] = set()
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError):
        return []
    for c in conns:
        if not c.laddr or c.laddr.ip not in ("0.0.0.0", "::", ""):
            continue  # bound to one address (loopback, a VPN, docker's bridge): not public
        if c.type == 1 and c.status == "LISTEN":  # SOCK_STREAM
            out.add(f"{c.laddr.port}/tcp")
        elif c.type == 2 and c.laddr.port in _UDP_KNOWN:  # SOCK_DGRAM
            out.add(f"{c.laddr.port}/udp")
    return sorted(out, key=lambda x: (int(x.split("/")[0]), x))


def set_enabled(enabled: bool) -> dict:
    ufw = _ufw()
    preallowed = []
    if enabled:
        # CRITICAL: allow SSH + the panel port BEFORE enabling, so a one-click
        # enable can never lock the admin out of the box (or the panel) — and
        # everything that already serves the network, so no site, mail or VPN
        # goes dark the moment the firewall comes up. Trim the rules afterwards.
        wanted = [f"{port}/tcp" for port in _safe_ports()]
        wanted += [p for p in listening_ports() if p not in wanted]
        for rule in wanted:
            subprocess.run([ufw, "allow", rule], capture_output=True, text=True, timeout=15)
            preallowed.append(rule)
    # --force avoids the interactive y/n prompt on enable.
    argv = [ufw, "--force", "enable"] if enabled else [ufw, "disable"]
    out = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    if out.returncode != 0:
        raise FirewallError(out.stderr.strip() or out.stdout.strip() or "ufw failed")
    return {"ok": True, "enabled": enabled, "preallowed": preallowed}


def guard_ports() -> list[str]:
    """The ports the panel protects from being firewalled off."""
    return _safe_ports()


def add_rule(action: str, port: str, proto: str = "tcp") -> dict:
    if action not in ("allow", "deny", "reject", "limit"):
        raise FirewallError("Invalid action")
    if not re.match(r"^\d{1,5}$", str(port)) or not (0 < int(port) < 65536):
        raise FirewallError("Invalid port")
    if proto not in ("tcp", "udp"):
        raise FirewallError("Invalid protocol")
    out = subprocess.run([_ufw(), action, f"{port}/{proto}"], capture_output=True, text=True, timeout=15)
    if out.returncode != 0:
        raise FirewallError(out.stderr.strip() or out.stdout.strip() or "ufw failed")
    return {"ok": True}


def delete_rule(num: int) -> dict:
    if not isinstance(num, int) or num < 1:
        raise FirewallError("Invalid rule number")
    # Refuse to delete a rule that keeps SSH / the panel reachable while ufw is
    # active — that is exactly the change that locks the admin out of the box.
    st = status()
    if st["active"]:
        rule = next((r["rule"] for r in st["rules"] if r["num"] == num), "")
        for port in _safe_ports():
            if re.search(rf"(^|\D){port}(/tcp)?(\s|$|\b)", rule) and "ALLOW" in rule.upper():
                raise FirewallError(
                    f"Refusing to delete the rule allowing port {port} while the "
                    f"firewall is active — it would lock you out. Disable the "
                    f"firewall first if you really mean to remove it.")
    # `ufw --force delete N` skips the confirmation prompt.
    out = subprocess.run([_ufw(), "--force", "delete", str(num)], capture_output=True, text=True, timeout=15)
    if out.returncode != 0:
        raise FirewallError(out.stderr.strip() or out.stdout.strip() or "ufw failed")
    return {"ok": True}
