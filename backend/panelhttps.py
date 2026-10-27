"""HTTPS for the panel itself (the uvicorn port, 8088 by default).

uvicorn reads UVICORN_SSL_CERTFILE / UVICORN_SSL_KEYFILE from its environment,
so turning HTTPS on is just a systemd drop-in next to aurorapanel.service — the
unit that install.sh writes (and rewrites on every update) stays untouched.

Switching is lockout-safe: before the restart a transient timer is armed that
deletes the drop-in and restarts the panel on plain HTTP again, unless the
browser confirms within REVERT_SECONDS that it reached the panel over HTTPS.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
from pathlib import Path

import psutil

SERVICE = "aurorapanel"
DROPIN = Path(f"/etc/systemd/system/{SERVICE}.service.d/aurora-https.conf")
UNIT = Path(f"/etc/systemd/system/{SERVICE}.service")
TLS_DIR = Path("/var/lib/aurora/panel-tls")
SELF_CRT = TLS_DIR / "panel.crt"
SELF_KEY = TLS_DIR / "panel.key"
PENDING = TLS_DIR / "pending"
NAMES = TLS_DIR / "names"  # extra host names / IPs the owner opened the panel with (kept across regenerations)
# TLS 1.2 cipher suites for the panel (Mozilla "intermediate"); TLS 1.3 suites are always on. Nothing with
# CBC or SHA-1, which scanners flag as weak. TLS 1.0/1.1 can't use any of these, so they are off too.
CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")
_HOST = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
LE_LIVE = Path("/etc/letsencrypt/live")
LE_HOOK = Path(f"/etc/letsencrypt/renewal-hooks/deploy/{SERVICE}-restart")
REVERT_UNIT = f"{SERVICE}-https-revert"
REVERT_SECONDS = 180


class PanelHttpsError(RuntimeError):
    pass


def _run(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def _port() -> int:
    try:
        return int(os.environ.get("PORT", "8088"))
    except ValueError:
        return 8088


def _local_ips() -> list[str]:
    """IPv4 addresses people reach this machine by — not Docker / bridge / VPN-tunnel internals."""
    ips = []
    for name, addrs in psutil.net_if_addrs().items():
        if name.startswith(("docker", "br-", "veth", "virbr", "lo", "wg", "tun", "tap", "ipsec")):
            continue
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254.")):
                ips.append(a.address)
    return sorted(set(ips))


def clean_name(name: str) -> str:
    """A host name or IP address as it may appear in a certificate, else ''."""
    n = (name or "").strip().lower().strip("[]")
    if not n or n == "localhost":
        return ""
    try:
        return str(ipaddress.ip_address(n))
    except ValueError:
        return n if _HOST.match(n) else ""


def covers(names: list[str], host: str) -> bool:
    """Does a certificate valid for `names` (DNS and IP entries) cover `host`? Wildcards match one label."""
    h = clean_name(host)
    if not h:
        return False
    for n in names:
        n = (n or "").strip().lower()
        if n == h:
            return True
        if n.startswith("*.") and "." in h and h.split(".", 1)[1] == n[2:]:
            return True
    return False


def _saved_names() -> list[str]:
    try:
        return [x for x in (clean_name(l) for l in NAMES.read_text(encoding="utf-8").splitlines()) if x]
    except OSError:
        return []


def remember_name(host: str) -> None:
    """Keep a name the owner reaches the panel by, so every regenerated certificate includes it."""
    h = clean_name(host)
    if not h or h in _local_ips() or h in ("127.0.0.1", socket.gethostname().lower()):
        return
    names = _saved_names()
    if h not in names:
        TLS_DIR.mkdir(parents=True, exist_ok=True)
        NAMES.write_text("\n".join(names + [h]) + "\n", encoding="utf-8")


def _known_names() -> list[str]:
    """Everything this server is likely to be opened as: host name, .local, FQDN, mail host, Dynamic DNS
    names, the public IP, every local IP, and names the owner used before."""
    host = socket.gethostname().lower()
    out = [host, f"{host}.local", "localhost", "127.0.0.1"] + _local_ips()
    for fn in (lambda: socket.getfqdn(),
               lambda: __import__("backend.mail", fromlist=["hostname"]).hostname(),
               lambda: __import__("backend.mail", fromlist=["_public_ip"])._public_ip(),
               lambda: __import__("backend.ddns", fromlist=["hostname"]).hostname()):
        try:
            v = fn()
            if v:
                out.append(str(v))
        except Exception:
            pass
    try:
        from . import ddnshosts
        out += [f"{h['host']}.{h['domain']}" for h in ddnshosts._load().get("hosts", []) if h.get("host") and h.get("domain")]
    except Exception:
        pass
    out += _saved_names()
    seen, names = set(), []
    for n in out:
        c = clean_name(n) or ("localhost" if n == "localhost" else "")
        if c and c not in seen:
            seen.add(c); names.append(c)
    return names


def _dropin_paths() -> tuple[str, str] | None:
    """(certfile, keyfile) from the drop-in, or None when HTTPS is off."""
    if not DROPIN.is_file():
        return None
    env = {}
    for line in DROPIN.read_text(encoding="utf-8").splitlines():
        if line.startswith("Environment=") and "=" in line[12:]:
            k, v = line[12:].split("=", 1)
            env[k.strip()] = v.strip().strip('"')
    if env.get("UVICORN_SSL_CERTFILE") and env.get("UVICORN_SSL_KEYFILE"):
        return env["UVICORN_SSL_CERTFILE"], env["UVICORN_SSL_KEYFILE"]
    return None


def _cert_info(crt: str) -> dict:
    r = _run(["openssl", "x509", "-in", crt, "-noout", "-subject", "-enddate", "-ext", "subjectAltName"])
    info = {"subject": "", "expires": "", "names": []}
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            info["subject"] = line[8:].strip()
        elif line.startswith("notAfter="):
            info["expires"] = line[9:].strip()
        elif "DNS:" in line or "IP Address:" in line:
            info["names"] = [n.split(":", 1)[1].strip() for n in line.split(",") if ":" in n]
    return info


def _le_certs() -> list[str]:
    if not LE_LIVE.is_dir():
        return []
    return sorted(d.name for d in LE_LIVE.iterdir()
                  if (d / "fullchain.pem").is_file() and (d / "privkey.pem").is_file())


def _pending_deadline() -> float | None:
    try:
        deadline = float(PENDING.read_text().strip())
    except (OSError, ValueError):
        return None
    return deadline if deadline > time.time() else None


def status(scheme: str, host: str = "") -> dict:
    paths = _dropin_paths()
    deadline = _pending_deadline()
    source = None
    if paths:
        source = "self" if paths[0] == str(SELF_CRT) else Path(paths[0]).parent.name
    cert = _cert_info(paths[0]) if paths else None
    return {
        "enabled": bool(paths),
        "active": scheme == "https",
        "source": source,
        "cert": cert,
        "pending": bool(deadline),
        "revert_in": int(deadline - time.time()) if deadline else 0,
        "letsencrypt": _le_certs(),
        "port": _port(),
        "hostname": socket.gethostname(),
        "ips": _local_ips(),
        # the name in the browser's address bar, and whether the certificate is valid for it
        "host": clean_name(host),
        "covers": covers(cert["names"], host) if cert else None,
        "hardened": bool(paths) and "UVICORN_SSL_CIPHERS" in (DROPIN.read_text(encoding="utf-8") if DROPIN.is_file() else ""),
        # plain http://…:port answers with a redirect to https (backend.serve is the entry point)
        "redirect": bool(paths) and os.environ.get("AURORA_FRONT") == "1",
    }


def _make_self_signed():
    """A self-signed cert valid for every name this server is opened as (see _known_names):
    825 days, the longest Apple devices accept."""
    host = socket.gethostname()
    names = []
    for n in _known_names():
        try:
            ipaddress.ip_address(n)
            names.append(f"IP:{n}")
        except ValueError:
            names.append(f"DNS:{n}")
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(TLS_DIR, 0o700)
    tmp_key, tmp_crt = TLS_DIR / "panel.key.new", TLS_DIR / "panel.crt.new"
    r = _run(["openssl", "req", "-x509", "-nodes",
              "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
              "-keyout", str(tmp_key), "-out", str(tmp_crt), "-days", "825",
              "-subj", f"/CN={host}/O=AuroraPanel",
              "-addext", "subjectAltName=" + ",".join(names),
              "-addext", "basicConstraints=critical,CA:FALSE",
              "-addext", "keyUsage=critical,digitalSignature",
              "-addext", "extendedKeyUsage=serverAuth"], timeout=60)
    if r.returncode != 0:
        raise PanelHttpsError(r.stderr.strip() or "openssl failed")
    os.chmod(tmp_key, 0o600)
    tmp_key.replace(SELF_KEY)
    tmp_crt.replace(SELF_CRT)


def _check_pair(crt: str, key: str):
    """Load the pair exactly as uvicorn will, so a bad cert can't stop the panel from starting."""
    try:
        ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(crt, key)
    except (ssl.SSLError, OSError) as e:
        raise PanelHttpsError(f"That certificate can't be used: {e}")


def _set_le_hook(on: bool):
    """certbot renews the files in place; uvicorn only reads them at start."""
    if on:
        LE_HOOK.parent.mkdir(parents=True, exist_ok=True)
        LE_HOOK.write_text(f"#!/bin/sh\n# Written by AuroraPanel: reload the panel's renewed certificate.\n"
                           f"systemctl try-restart {SERVICE}\n", encoding="utf-8")
        os.chmod(LE_HOOK, 0o755)
    else:
        LE_HOOK.unlink(missing_ok=True)


def _stop_revert():
    _run(["systemctl", "stop", f"{REVERT_UNIT}.timer", f"{REVERT_UNIT}.service"])
    _run(["systemctl", "reset-failed", f"{REVERT_UNIT}.timer", f"{REVERT_UNIT}.service"])
    PENDING.unlink(missing_ok=True)


def _restart_soon():
    """Restart from outside the service's cgroup, after this response has gone out."""
    unit = f"{SERVICE}-restart-{int(time.time())}"
    # Transient timers default to AccuracySec=1min, which would delay this by up to a minute.
    r = _run(["systemd-run", "--quiet", "--collect", f"--unit={unit}", "--on-active=2",
              "--timer-property=AccuracySec=100ms", "systemctl", "restart", SERVICE])
    if r.returncode != 0:
        raise PanelHttpsError(r.stderr.strip() or "Couldn't schedule the panel restart")


def _exec_override() -> str:
    """Drop-in lines that swap `-m uvicorn` for `-m backend.serve` (uvicorn plus the http → https
    redirect on the same port) on units written before that entry point existed. New units from
    install.sh already use it, so nothing is added for them."""
    try:
        for line in UNIT.read_text(encoding="utf-8").splitlines():
            if line.startswith("ExecStart=") and " -m uvicorn " in line:
                return "ExecStart=\n" + line.replace(" -m uvicorn ", " -m backend.serve ", 1) + "\n"
    except OSError:
        pass
    return ""


def _write_dropin(crt: str, key: str):
    DROPIN.parent.mkdir(parents=True, exist_ok=True)
    DROPIN.write_text(
        "# Written by AuroraPanel (Security → Panel HTTPS). Delete this file and run\n"
        f"# 'systemctl daemon-reload && systemctl restart {SERVICE}' to go back to HTTP.\n"
        "[Service]\n"
        f"Environment=UVICORN_SSL_CERTFILE={crt}\n"
        f"Environment=UVICORN_SSL_KEYFILE={key}\n"
        # modern ciphers only (no CBC / SHA-1 suites), and no "server: uvicorn" header
        f"Environment=UVICORN_SSL_CIPHERS={CIPHERS}\n"
        "Environment=UVICORN_SERVER_HEADER=false\n"
        + _exec_override(), encoding="utf-8")


def install_default():
    """New installs start on HTTPS with a self-signed certificate (install.sh calls this
    before it starts the service, so there's no browser to confirm and no revert timer)."""
    if not (SELF_CRT.is_file() and SELF_KEY.is_file()):
        _make_self_signed()
    _check_pair(str(SELF_CRT), str(SELF_KEY))
    _write_dropin(str(SELF_CRT), str(SELF_KEY))


def enable(source: str, regenerate: bool = False, host: str = "") -> dict:
    """host: the name in the browser's address bar — a regenerated self-signed certificate includes it."""
    if not shutil.which("systemd-run"):
        raise PanelHttpsError("systemd is required")
    if source == "self":
        if host:
            remember_name(host)
        if regenerate or not (SELF_CRT.is_file() and SELF_KEY.is_file()):
            _make_self_signed()
        crt, key = str(SELF_CRT), str(SELF_KEY)
    elif source in _le_certs():
        crt, key = str(LE_LIVE / source / "fullchain.pem"), str(LE_LIVE / source / "privkey.pem")
    else:
        raise PanelHttpsError("Unknown certificate")
    _check_pair(crt, key)

    # Arm the safety net first: back to HTTP unless the browser confirms over HTTPS.
    _stop_revert()
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    PENDING.write_text(str(time.time() + REVERT_SECONDS))
    revert = (f"rm -f '{DROPIN}' '{PENDING}' '{LE_HOOK}'; systemctl daemon-reload; "
              f"systemctl restart {SERVICE}")
    r = _run(["systemd-run", "--quiet", "--collect", f"--unit={REVERT_UNIT}",
              f"--on-active={REVERT_SECONDS}", "--timer-property=AccuracySec=1s",
              "/bin/sh", "-c", revert])
    if r.returncode != 0:
        PENDING.unlink(missing_ok=True)
        raise PanelHttpsError(r.stderr.strip() or "Couldn't arm the automatic revert")

    _write_dropin(crt, key)
    _set_le_hook(source != "self")
    _run(["systemctl", "daemon-reload"])
    _restart_soon()
    return {"ok": True, "revert_in": REVERT_SECONDS,
            "host": source if source != "self" else None, "port": _port()}


def harden() -> dict:
    """Rewrite the drop-in for the certificate in use with strong ciphers only, no Server header and
    the http → https redirect, then restart. No revert timer: this can't lock anyone out (every browser since 2014 speaks TLS 1.2
    with these suites)."""
    paths = _dropin_paths()
    if not paths:
        raise PanelHttpsError("Turn on Panel HTTPS first")
    _write_dropin(*paths)
    _run(["systemctl", "daemon-reload"])
    _restart_soon()
    return {"ok": True}


def confirm(scheme: str) -> dict:
    """Called by the browser once it has loaded the panel over HTTPS."""
    if scheme != "https":
        raise PanelHttpsError("Open the panel over https:// to confirm")
    _stop_revert()
    return {"ok": True}


def disable() -> dict:
    _stop_revert()
    if DROPIN.is_file():
        DROPIN.unlink()
        _set_le_hook(False)
        _run(["systemctl", "daemon-reload"])
        _restart_soon()
    return {"ok": True, "port": _port()}
