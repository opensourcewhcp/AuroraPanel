"""IP Blocker — block/unblock source IPs via ufw deny rules."""
from __future__ import annotations

import ipaddress
import re
import subprocess

from . import firewall

# Never let the admin block themselves off the box (their own IP is checked in block()).
_PROTECTED = {"127.0.0.1", "::1"}


class IPBlockError(RuntimeError):
    pass


def _valid_ip(ip: str) -> str:
    ip = (ip or "").strip()
    try:
        ipaddress.ip_network(ip, strict=False)  # allow single IPs and CIDR
    except ValueError:
        raise IPBlockError("Invalid IP address or CIDR")
    return ip


def available() -> bool:
    return firewall.available()


def list_blocked() -> dict:
    st = firewall.status()
    blocked = []
    for r in st.get("rules", []):
        rule = r["rule"]
        m = re.search(r"DENY\s+IN\s+(\S+)", rule) or re.search(r"(\S+)\s+DENY", rule)
        if "DENY" in rule.upper():
            # Extract the source (last token is usually the source for "deny from").
            src = rule.split()[-1]
            blocked.append({"num": r["num"], "rule": rule, "source": src})
    return {"available": st.get("available", False), "active": st.get("active", False), "blocked": blocked}


def block(ip: str, client_ip: str | None = None) -> dict:
    ip = _valid_ip(ip)
    net = ipaddress.ip_network(ip, strict=False)
    for p in _PROTECTED | ({client_ip} if client_ip else set()):
        try:
            if ipaddress.ip_address(p) in net:
                raise IPBlockError(f"Refusing to block {ip} — it covers {p} and you'd lock yourself out")
        except ValueError:
            pass
    if firewall._firewalld():
        firewall.deny_source(ip)
        return {"ok": True, "blocked": ip, "note": None if st_active() else "Firewall is inactive, so the block takes effect once you enable it."}
    ufw = firewall._ufw()  # raises if ufw missing
    out = subprocess.run([ufw, "deny", "from", ip], capture_output=True, text=True, timeout=15)
    if out.returncode != 0:
        raise IPBlockError(out.stderr.strip() or out.stdout.strip() or "ufw failed")
    return {"ok": True, "blocked": ip, "note": None if st_active() else "Firewall is inactive — block takes effect once you enable it."}


def unblock(num: int) -> dict:
    return firewall.delete_rule(num)


def st_active() -> bool:
    return firewall.status().get("active", False)
