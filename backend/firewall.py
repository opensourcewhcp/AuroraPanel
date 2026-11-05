"""Firewall management: ufw (Debian family), or firewalld where ufw is absent (Fedora)."""
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


def _firewalld() -> bool:
    return bool(IS_LINUX and not shutil.which("ufw") and shutil.which("firewall-cmd"))


def _fwd_running() -> bool:
    return subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=15).returncode == 0


def _fwd(*args: str, check: bool = True) -> str:
    """One permanent firewalld change or query. Works while firewalld is stopped, too."""
    argv = ["firewall-cmd", "--permanent", *args] if _fwd_running() else ["firewall-offline-cmd", *args]
    out = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if check and out.returncode != 0:
        raise FirewallError(out.stderr.strip() or out.stdout.strip() or "firewalld failed")
    return out.stdout


def _fwd_apply() -> None:
    if _fwd_running():
        out = subprocess.run(["firewall-cmd", "--reload"], capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            raise FirewallError(out.stderr.strip() or "firewall-cmd --reload failed")


_RICH_PORT = re.compile(r'port="?(\d+)"?\s+protocol="?(tcp|udp)"?')
_RICH_SRC = re.compile(r'source address="?([^"\s]+)"?')


def _rich_text(rich: str) -> str:
    """A rich rule in the ufw wording that the rest of the panel reads."""
    action = "DENY" if re.search(r"\b(drop|reject)\b", rich) else "LIMIT" if "limit value" in rich else "ALLOW"
    port, src = _RICH_PORT.search(rich), _RICH_SRC.search(rich)
    target = f"{port.group(1)}/{port.group(2)}" if port else "Anywhere"
    return f"{target} {action} IN {src.group(1) if src else 'Anywhere'}"


def _fwd_rules() -> list[dict]:
    """Numbered rules of the default zone. "del" holds the firewalld option that removes the rule."""
    rules: list[dict] = []
    for svc in _fwd("--list-services").split():
        ports = _fwd(f"--service={svc}", "--get-ports", check=False).split() or ["any"]
        rules.append({"rule": f"{','.join(ports)} ALLOW IN Anywhere ({svc})", "del": f"--remove-service={svc}"})
    for port in _fwd("--list-ports").split():
        rules.append({"rule": f"{port} ALLOW IN Anywhere", "del": f"--remove-port={port}"})
    for rich in _fwd("--list-rich-rules").splitlines():
        if rich.strip():
            rules.append({"rule": _rich_text(rich), "del": f"--remove-rich-rule={rich.strip()}"})
    return [{"num": i, **r} for i, r in enumerate(rules, 1)]


def _fwd_status() -> dict:
    rules = [{"num": r["num"], "rule": r["rule"]} for r in _fwd_rules()]
    return {"available": True, "backend": "firewalld", "active": _fwd_running(), "rules": rules}


def _fwd_set_enabled(enabled: bool) -> dict:
    preallowed = []
    if enabled:
        # Same promise as ufw: SSH, the panel and whatever serves the network are allowed first.
        wanted = [f"{port}/tcp" for port in _safe_ports()]
        wanted += [p for p in listening_ports() if p not in wanted]
        for rule in wanted:
            _fwd(f"--add-port={rule}", check=False)
            preallowed.append(rule)
    out = subprocess.run(["systemctl", "enable" if enabled else "disable", "--now", "firewalld"],
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise FirewallError(out.stderr.strip() or "Could not change firewalld")
    return {"ok": True, "enabled": enabled, "preallowed": preallowed}


def open_ports(*ports: str) -> list[str]:
    """Open ports ("80/tcp", "53", "40000:40100/tcp") in firewalld when it is running. Returns what was opened."""
    if not _firewalld() or not _fwd_running():
        return []
    done = []
    for p in ports:
        p = p.replace(":", "-")
        for one in ([p] if "/" in p else [f"{p}/tcp", f"{p}/udp"]):
            _fwd(f"--add-port={one}", check=False)
            done.append(one)
    _fwd_apply()
    return done


def close_ports(*ports: str) -> None:
    if not _firewalld() or not _fwd_running():
        return
    for p in ports:
        _fwd(f"--remove-port={p.replace(':', '-')}", check=False)
    _fwd_apply()


def trust_subnet(subnet: str, trusted: bool = True) -> None:
    """VPN clients: let this subnet reach the server and be routed (firewalld's version of `ufw route allow`)."""
    if _firewalld() and _fwd_running():
        _fwd("--zone=trusted", f"--{'add' if trusted else 'remove'}-source={subnet}", check=False)
        _fwd_apply()


def lan_only(port: str, proto: str, nets: list[str]) -> None:
    """Replace an open port with rules allowing only these networks."""
    for net in nets:
        family = "ipv6" if ":" in net else "ipv4"
        _fwd(f'--add-rich-rule=rule family="{family}" source address="{net}" port port="{port}" protocol="{proto}" accept')
    _fwd(f"--remove-port={port}/{proto}", check=False)
    _fwd_apply()


def deny_source(ip: str) -> None:
    """firewalld's version of `ufw deny from <ip>`."""
    family = "ipv6" if ":" in ip else "ipv4"
    _fwd(f'--add-rich-rule=rule family="{family}" source address="{ip}" drop')
    _fwd_apply()


def _ufw() -> str:
    path = shutil.which("ufw") if IS_LINUX else None
    if not path:
        raise FirewallError("ufw is not installed (try installing it from Packages)")
    return path


def available() -> bool:
    return bool(IS_LINUX and (shutil.which("ufw") or shutil.which("firewall-cmd")))


def status() -> dict:
    if not available():
        return {"available": False, "active": False, "rules": []}
    if _firewalld():
        return _fwd_status()
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
    if _firewalld():
        return _fwd_set_enabled(enabled)
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
    if _firewalld():
        target = f'port port="{port}" protocol="{proto}"'
        if action == "allow":
            _fwd(f"--add-port={port}/{proto}")
        elif action == "limit":
            _fwd(f'--add-rich-rule=rule {target} accept limit value="6/m"')
        else:
            _fwd(f'--add-rich-rule=rule {target} {"drop" if action == "deny" else "reject"}')
        _fwd_apply()
        return {"ok": True}
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
    if _firewalld():
        entry = next((r for r in _fwd_rules() if r["num"] == num), None)
        if not entry:
            raise FirewallError("That rule no longer exists")
        _fwd(entry["del"])
        _fwd_apply()
        return {"ok": True}
    # `ufw --force delete N` skips the confirmation prompt.
    out = subprocess.run([_ufw(), "--force", "delete", str(num)], capture_output=True, text=True, timeout=15)
    if out.returncode != 0:
        raise FirewallError(out.stderr.strip() or out.stdout.strip() or "ufw failed")
    return {"ok": True}
