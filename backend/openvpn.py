"""OpenVPN server (openvpn-server@aurora): EC PKI via easy-rsa, tls-crypt,
inline .ovpn client profiles, revocation (CRL), live clients from the status
file, and an end-to-end self-test from a network namespace.

Users: every user has a login type —
  cert           certificate only (their own profile)
  cert+password  their own profile AND their password (username == cert CN)
  password       password only (generic profile without a client cert)
OpenVPN checks each connection with AUTH_SCRIPT against USERS_DB (salted
PBKDF2 hashes). The server drops to nobody:nogroup, so the DB is root:nogroup
0640 and only the panel (root) writes it. Changes are live: the script runs on
every (re)connect and the management socket kicks affected sessions."""
from __future__ import annotations

try:
    import grp
except ImportError:  # Windows dev box
    grp = None
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from . import distro
from . import jobs, problems
from .vpncommon import (
    STATE_DIR, VPNError, control as _control, default_route, dns_servers, enable_forwarding,
    endpoint, load_json, ns_cleanup, ns_exec, ns_ping, run, save_json, set_nat, TEST_NS,
    ufw_close, ufw_open, unit_state, valid_name, which, write_secret, apt_install, nat_active,
    forwarding_enabled,
)

NAME = "aurora"
SRV_DIR = Path("/etc/openvpn/server")
CONF = SRV_DIR / f"{NAME}.conf"
PKI = SRV_DIR / f"{NAME}-pki"
TC_KEY = SRV_DIR / f"{NAME}-tc.key"
CRL = SRV_DIR / f"{NAME}-crl.pem"
STATUS_FILE = Path(f"/run/openvpn-server/status-{NAME}.log")
UNIT = f"openvpn-server@{NAME}"
EASYRSA = Path("/usr/share/easy-rsa/easyrsa")
# Whom the server drops to. Fedora's /etc/openvpn/server only lets its own "openvpn" group in, and has no "nogroup".
RUN_USER, RUN_GROUP = ("openvpn", "openvpn") if distro.is_dnf() else ("nobody", "nogroup")
STATE = STATE_DIR / "openvpn.json"
PKGS = ["openvpn", "easy-rsa", "nftables", "iproute2", "iputils-ping"]
SELFTEST_PREFIX = "aurora-selftest-"
CIPHERS = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
_DEFAULT = {"port": 1194, "proto": "udp", "subnet": "10.9.0.0/24", "redirect": True}
AUTH_SCRIPT = SRV_DIR / f"{NAME}-auth.py"
USERS_DB = SRV_DIR / f"{NAME}-users.json"
MGMT_SOCK = Path(f"/run/openvpn-server/{NAME}-mgmt.sock")
MODES = {"cert+password": "Certificate + password", "password": "Password only", "cert": "Certificate only"}
PBKDF2_ITERS = 200_000

# Runs inside OpenVPN (as nobody) for every connection; stdlib only.
_AUTH_SCRIPT_SRC = r'''#!/usr/bin/python3
# Managed by AuroraPanel — OpenVPN per-user login check. Exit 0 = allow.
import hashlib, hmac, json, os, sys
DB = "%(db)s"

def log(ok, user, why):
    ip = os.environ.get("untrusted_ip", "?")
    print("aurora-ovpn-auth: %%s user=%%s ip=%%s %%s" %% ("ok" if ok else "fail", json.dumps(user[:64]), ip, why),
          file=sys.stderr, flush=True)
    return 0 if ok else 1

def check(stored, pw):
    try:
        algo, iters, salt, digest = stored.split("$")
        got = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(iters)).hex()
        return algo == "pbkdf2_sha256" and hmac.compare_digest(got, digest)
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return False

def main():
    user, pw = "", ""
    try:
        with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
            lines = f.read().split("\n")
        user, pw = lines[0].strip(), (lines[1] if len(lines) > 1 else "")
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    cn = os.environ.get("common_name") or os.environ.get("X509_0_CN") or ""
    if cn == "UNDEF":
        cn = ""
    try:
        with open(DB, encoding="utf-8") as f:
            users = json.load(f).get("users", {})
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return log(False, user, "user database unreadable")
    c = users.get(cn) if cn else None
    if c and c.get("mode") == "cert":
        if c.get("disabled"):
            return log(False, cn, "disabled")
        return log(True, cn, "certificate")
    if not user:
        return log(False, cn, "no username sent")
    u = users.get(user)
    if not u:
        return log(False, user, "unknown user")
    if u.get("disabled"):
        return log(False, user, "disabled")
    if u.get("mode") == "cert":
        return log(False, user, "certificate-only user")
    if u.get("mode") == "cert+password" and cn != user:
        return log(False, user, "certificate does not belong to this user")
    if not check(u.get("hash", ""), pw):
        return log(False, user, "wrong password")
    return log(True, user, u.get("mode"))

sys.exit(main())
'''


def _state() -> dict:
    return load_json(STATE, _DEFAULT)


# ---- user database ----
def _hash(pw: str) -> str:
    salt = secrets.token_bytes(16)
    d = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERS).hex()
    return f"pbkdf2_sha256${PBKDF2_ITERS}${salt.hex()}${d}"


def _db() -> dict:
    try:
        return json.loads(USERS_DB.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"users": {}}


def _save_db(db: dict):
    tmp = USERS_DB.with_name(USERS_DB.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    try:
        os.chown(tmp, 0, grp.getgrnam(RUN_GROUP).gr_gid)
    except (AttributeError, KeyError, PermissionError):
        pass
    os.chmod(tmp, 0o640)
    os.replace(tmp, USERS_DB)


def _ensure_auth():
    """Install the login check + user DB; adopt pre-existing cert profiles as
    'certificate only' users so nothing that worked before breaks."""
    AUTH_SCRIPT.write_text(_AUTH_SCRIPT_SRC % {"db": USERS_DB}, encoding="utf-8")
    os.chmod(AUTH_SCRIPT, 0o755)
    db = _db()
    changed = not USERS_DB.exists()
    for c in _index():
        if not c["revoked"] and not c["name"].startswith(SELFTEST_PREFIX) and c["name"] not in db["users"]:
            db["users"][c["name"]] = {"mode": "cert", "created": int(time.time())}
            changed = True
    if changed:
        _save_db(db)


def _password(pw: str | None) -> tuple[str, bool]:
    """(password, generated?) — validates a given one or makes a new one."""
    pw = (pw or "").strip()
    if not pw:
        return secrets.token_urlsafe(12), True
    if len(pw) < 8 or len(pw) > 128:
        raise VPNError("Password must be 8–128 characters")
    if "\n" in pw or "\r" in pw:
        raise VPNError("Password can't contain line breaks")
    return pw, False


def _easyrsa(*args: str, timeout: int = 120) -> str:
    env = {"EASYRSA_BATCH": "1", "EASYRSA_PKI": str(PKI), "EASYRSA_ALGO": "ec",
           "EASYRSA_CURVE": "prime256v1", "EASYRSA_CA_EXPIRE": "3650", "EASYRSA_CERT_EXPIRE": "3650",
           "EASYRSA_CRL_DAYS": "3650"}
    if args[0] == "build-ca":
        # Only the CA: in batch mode REQ_CN would override every later cert's CN too.
        env["EASYRSA_REQ_CN"] = "AuroraPanel OpenVPN CA"
    return run([str(EASYRSA), *args], timeout=timeout, env=env).stdout


def _publish_crl():
    _easyrsa("gen-crl")
    shutil.copyfile(PKI / "crl.pem", CRL)
    os.chmod(CRL, 0o644)  # re-read per connection after dropping to nobody


def _render(s: dict):
    net = ipaddress.ip_network(s["subnet"])
    lines = [
        "# Managed by AuroraPanel — edits here are overwritten.",
        f"port {s['port']}",
        f"proto {s['proto']}",
        "dev tun",
        f"ca {PKI}/ca.crt",
        f"cert {PKI}/issued/server.crt",
        f"key {PKI}/private/server.key",
        "dh none",
        f"tls-crypt {TC_KEY}",
        f"crl-verify {CRL}",
        # Per-user logins: a client cert is optional (password-only users have
        # none); the script decides per user what is required.
        "verify-client-cert optional",
        "script-security 2",
        f"auth-user-pass-verify {AUTH_SCRIPT} via-file",
        f"management {MGMT_SOCK} unix",
        "topology subnet",
        f"server {net.network_address} {net.netmask}",
    ]
    if s["redirect"]:
        lines.append('push "redirect-gateway def1 bypass-dhcp"')
    else:
        lan = default_route().get("lan")
        if lan:
            n = ipaddress.ip_network(lan)
            lines.append(f'push "route {n.network_address} {n.netmask}"')
    lines += [f'push "dhcp-option DNS {d}"' for d in dns_servers()]
    lines += [
        "keepalive 10 120",
        f"data-ciphers {CIPHERS}",
        f"user {RUN_USER}",
        f"group {RUN_GROUP}",
        "persist-key",
        "persist-tun",
        f"status {STATUS_FILE} 10",
        "status-version 2",
        "verb 3",
    ]
    if s["proto"] == "udp":
        lines.append("explicit-exit-notify 1")
    write_secret(CONF, "\n".join(lines) + "\n", 0o644)


def install() -> jobs.Job:
    return apt_install("install OpenVPN", PKGS, meta={"vpn": "openvpn"})


def _pki_ready() -> bool:
    return (PKI / "ca.crt").exists() and (PKI / "issued/server.crt").exists() and TC_KEY.exists()


def setup(port: int = 1194, proto: str = "udp", subnet: str = "10.9.0.0/24", redirect: bool = True) -> jobs.Job:
    if not which("openvpn") or not EASYRSA.exists():
        raise VPNError("OpenVPN / easy-rsa are not installed")
    if CONF.exists() and "AuroraPanel" not in CONF.read_text(errors="replace"):
        raise VPNError(f"{CONF} exists and was not created by AuroraPanel")
    port = int(port)
    if not 1 <= port <= 65535:
        raise VPNError("Invalid port")
    if proto not in ("udp", "tcp"):
        raise VPNError("Protocol must be udp or tcp")
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        raise VPNError("Invalid subnet")
    if not net.is_private or net.prefixlen > 29:
        raise VPNError("Use a private subnet of /29 or larger, e.g. 10.9.0.0/24")
    lan = default_route().get("lan")
    if lan and net.overlaps(ipaddress.ip_network(lan)):
        raise VPNError(f"The VPN subnet overlaps your LAN ({lan})")
    old = _state() if CONF.exists() else None

    def fn(log):
        if not _pki_ready():
            log("• Creating the certificate authority (EC P-256)…")
            if PKI.exists():
                shutil.rmtree(PKI)
            _easyrsa("init-pki")
            _easyrsa("build-ca", "nopass")
            log("• Issuing the server certificate…")
            _easyrsa("build-server-full", "server", "nopass")
            log("• Generating the tls-crypt key…")
            run(["openvpn", "--genkey", "secret", str(TC_KEY)])
            os.chmod(TC_KEY, 0o600)
            _publish_crl()
        s = {"port": port, "proto": proto, "subnet": str(net), "redirect": bool(redirect)}
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        save_json(STATE, s)
        log("• Installing the per-user login check…")
        _ensure_auth()
        log(f"• Writing {CONF} ({proto.upper()} {port}, clients in {net})")
        _render(s)
        enable_forwarding()
        if old:
            set_nat(old["subnet"], False)
            ufw_close(old["port"], old["proto"], old["subnet"])
        set_nat(s["subnet"], True)
        ufw_open(port, proto, s["subnet"])
        log("• Starting openvpn-server@aurora…")
        run(["systemctl", "enable", UNIT])
        run(["systemctl", "restart", UNIT], timeout=60)
        for _ in range(20):
            time.sleep(0.5)
            if unit_state(UNIT)["active"] and _listening(s):
                break
        if not unit_state(UNIT)["active"]:
            tail = run(["journalctl", "-u", UNIT, "-n", "15", "--no-pager"], check=False).stdout
            raise VPNError("OpenVPN failed to start:\n" + tail)
        log(f"✔ OpenVPN is running and listening on {proto.upper()} {port}")
        return {"ok": True}
    return jobs.launch_fn("OpenVPN setup", fn, meta={"vpn": "openvpn"})


def _listening(s: dict) -> bool:
    flag = "-Hlnu" if s["proto"] == "udp" else "-Hlnt"
    out = run(["ss", flag], check=False).stdout
    return bool(re.search(rf"[:\]]{s['port']}\s", out))


def _index() -> list[dict]:
    """Client certificates from easy-rsa's index.txt (latest entry per CN)."""
    certs: dict[str, dict] = {}
    try:
        lines = (PKI / "index.txt").read_text().splitlines()
    except OSError:
        return []
    for line in lines:
        f = line.split("\t")
        if len(f) < 6:
            continue
        m = re.search(r"CN=([^/]+)", f[5])
        if not m or m.group(1) == "server":
            continue
        cn = m.group(1)
        certs[cn] = {"name": cn, "revoked": f[0] == "R", "expires": f[1], "serial": f[3]}
    return list(certs.values())


def _status_clients() -> dict:
    """user name -> live session. Cert users are keyed by certificate CN,
    password-only users (CN 'UNDEF') by the username they logged in with."""
    clients = {}
    try:
        text = STATUS_FILE.read_text(errors="replace")
    except OSError:
        return clients
    users = _db()["users"]
    header = None
    for line in text.splitlines():
        f = line.split(",")
        if f[0] == "HEADER" and len(f) > 1 and f[1] == "CLIENT_LIST":
            header = f[2:]
        elif f[0] == "CLIENT_LIST" and header:
            row = dict(zip(header, f[1:]))
            cn, un = row.get("Common Name", ""), row.get("Username", "")
            key = cn if cn in users else un if un in users else (cn if cn != "UNDEF" else un)
            clients.setdefault(key, []).append({
                "real_address": row.get("Real Address"), "virtual_address": row.get("Virtual Address"),
                "rx": int(row.get("Bytes Received") or 0), "tx": int(row.get("Bytes Sent") or 0),
                "since": int(row.get("Connected Since (time_t)") or 0) or None,
                "cipher": row.get("Data Channel Cipher"),
            })
    return clients


def _active_certs() -> set[str]:
    return {c["name"] for c in _index() if not c["revoked"]}


def status() -> dict:
    installed = which("openvpn") and EASYRSA.exists()
    s = _state()
    configured = CONF.exists() and _pki_ready()
    u = unit_state(UNIT) if installed else {"active": False, "enabled": False}
    live = _status_clients() if u.get("active") else {}
    certs = _active_certs()
    db = _db()["users"]
    clients = []
    for name in sorted(db, key=str.lower):
        rec = db[name]
        sessions = live.get(name, [])
        first = sessions[0] if sessions else {}
        clients.append({
            "name": name, "mode": rec.get("mode"), "mode_label": MODES.get(rec.get("mode"), "?"),
            "disabled": bool(rec.get("disabled")), "has_cert": name in certs, "created": rec.get("created"),
            "password_changed": rec.get("password_changed"), "online": bool(sessions), "sessions": len(sessions),
            **first, "rx": sum(x["rx"] for x in sessions), "tx": sum(x["tx"] for x in sessions),
        })
    conf = CONF.read_text(errors="replace") if CONF.exists() else ""
    return {"installed": bool(installed), "configured": configured, **u, "port": s["port"],
            "proto": s["proto"], "subnet": s["subnet"], "redirect": s["redirect"], "clients": clients,
            "modes": MODES, "logins_enabled": "auth-user-pass-verify" in conf,
            "listening": bool(u.get("active") and _listening(s)),
            "forwarding": forwarding_enabled(), "nat": configured and nat_active(s["subnet"])}


def control(action: str) -> dict:
    if not CONF.exists():
        raise VPNError("Set up the OpenVPN server first")
    return _control(UNIT, action)


# ---- user management (panel admin only — every API route requires the admin session) ----
def _mgmt(cmd: str) -> str:
    """One command on the management socket (root-only, created by openvpn at start)."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(str(MGMT_SOCK))
            s.recv(4096)  # >INFO banner
            s.sendall((cmd + "\n").encode())
            time.sleep(0.2)
            return s.recv(4096).decode(errors="replace")
    except OSError:
        return ""


def _kick(name: str):
    """Disconnect a user's live sessions now (by real address, which works for
    password-only users too). Falls back to a restart if the socket isn't there."""
    sessions = _status_clients().get(name, [])
    for sess in sessions:
        addr = sess.get("real_address")
        if addr and "SUCCESS" not in _mgmt(f"kill {addr}"):
            run(["systemctl", "restart", UNIT], timeout=60, check=False)
            return


def _need_server():
    if not _pki_ready() or not CONF.exists():
        raise VPNError("Set up the OpenVPN server first")
    if "auth-user-pass-verify" not in CONF.read_text(errors="replace"):
        raise VPNError("Enable user logins first (OpenVPN → Server settings → Apply & restart)")
    _ensure_auth()


def _user(db: dict, name: str) -> dict:
    rec = db["users"].get(name)
    if rec is None:
        raise VPNError("No such user")
    return rec


def _check_mode(mode: str) -> str:
    if mode not in MODES:
        raise VPNError("Login type must be one of: " + ", ".join(MODES))
    return mode


def _issue_cert(name: str):
    if name in _active_certs():
        return
    # A revoked cert with the same name may leave files behind; clear them so
    # easy-rsa can issue a fresh one.
    for p in (PKI / "issued" / f"{name}.crt", PKI / "private" / f"{name}.key", PKI / "reqs" / f"{name}.req"):
        p.unlink(missing_ok=True)
    _easyrsa("build-client-full", name, "nopass")


def _revoke_cert(name: str):
    if name not in _active_certs():
        return
    _easyrsa("revoke", name)
    _publish_crl()


def add_user(name: str, mode: str = "cert+password", password: str | None = None) -> dict:
    _need_server()
    name = valid_name(name)
    mode = _check_mode(mode)
    if name == "server" or name.startswith(SELFTEST_PREFIX):
        raise VPNError("That name is reserved")
    db = _db()
    if name in db["users"]:
        raise VPNError("A user with that name already exists")
    rec = {"mode": mode, "created": int(time.time())}
    out = {"ok": True, "name": name, "mode": mode}
    if mode != "cert":
        pw, generated = _password(password)
        rec["hash"], rec["password_changed"] = _hash(pw), int(time.time())
        out.update(password=pw, generated=generated)
    if mode != "password":
        _issue_cert(name)
    db["users"][name] = rec
    _save_db(db)
    return out


def set_password(name: str, password: str | None) -> dict:
    _need_server()
    db = _db()
    rec = _user(db, name)
    if rec.get("mode") == "cert":
        raise VPNError("This user logs in with a certificate only — change the login type to use a password")
    pw, generated = _password(password)
    rec["hash"], rec["password_changed"] = _hash(pw), int(time.time())
    _save_db(db)
    _kick(name)  # sessions using the old password end now
    return {"ok": True, "name": name, "password": pw, "generated": generated}


def set_mode(name: str, mode: str, password: str | None = None) -> dict:
    _need_server()
    mode = _check_mode(mode)
    db = _db()
    rec = _user(db, name)
    out = {"ok": True, "name": name, "mode": mode, "new_profile": True}
    if mode != "cert" and not rec.get("hash"):
        pw, generated = _password(password)
        rec["hash"], rec["password_changed"] = _hash(pw), int(time.time())
        out.update(password=pw, generated=generated)
    if mode == "cert":
        rec.pop("hash", None)
    if mode == "password":
        _revoke_cert(name)  # the old profile's certificate is no longer needed
    else:
        _issue_cert(name)
    rec["mode"] = mode
    _save_db(db)
    _kick(name)
    return out


def set_disabled(name: str, disabled: bool) -> dict:
    _need_server()
    db = _db()
    _user(db, name)["disabled"] = bool(disabled)
    _save_db(db)
    if disabled:
        _kick(name)
    return {"ok": True}


def delete_user(name: str) -> dict:
    _need_server()
    db = _db()
    _user(db, name)
    _kick(name)
    _revoke_cert(name)
    del db["users"][name]
    _save_db(db)
    return {"ok": True}


# Kept for the generic /clients API routes.
def add_client(name: str) -> dict:
    return add_user(name, "cert")


def revoke_client(name: str) -> dict:
    return delete_user(name)


def _pem(path: Path, kind: str) -> str:
    text = path.read_text()
    m = re.search(rf"-----BEGIN {kind}-----.*?-----END {kind}-----", text, re.S)
    if not m:
        raise VPNError(f"Could not read {path.name}")
    return m.group(0)


def _profile(name: str, host: str, port: int | None = None, mode: str = "cert") -> str:
    """Inline .ovpn. mode: 'cert' (cert only), 'cert+password' (cert + login
    prompt) or 'password' (no client cert, login prompt only)."""
    s = _state()
    tc = TC_KEY.read_text().strip()
    cert_block = []
    if mode != "password":
        crt, key = PKI / "issued" / f"{name}.crt", PKI / "private" / f"{name}.key"
        if not crt.exists() or not key.exists():
            raise VPNError("Client certificate not found (was it revoked?)")
        key_pem = re.search(r"-----BEGIN (?:EC |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:EC |ENCRYPTED )?PRIVATE KEY-----",
                            key.read_text(), re.S)
        if not key_pem:
            raise VPNError("Could not read the client key")
        cert_block = ["<cert>", _pem(crt, "CERTIFICATE"), "</cert>", "<key>", key_pem.group(0), "</key>"]
    login = ["auth-user-pass", "auth-retry interact"] if mode != "cert" else []
    return "\n".join([
        f"# AuroraPanel OpenVPN profile — {name} ({MODES.get(mode, mode)})",
        "client",
        "dev tun",
        f"proto {s['proto']}",
        f"remote {host} {port or s['port']}",
        "resolv-retry infinite",
        "nobind",
        "persist-key",
        "persist-tun",
        "remote-cert-tls server",
        f"data-ciphers {CIPHERS}",
        *login,
        "verb 3",
        "<ca>", _pem(PKI / "ca.crt", "CERTIFICATE"), "</ca>",
        *cert_block,
        "<tls-crypt>", tc, "</tls-crypt>",
    ]) + "\n"


def client_config(name: str) -> dict:
    name = valid_name(name)
    rec = _db()["users"].get(name)
    if rec is None:
        raise VPNError("No such user")
    mode = rec.get("mode", "cert")
    return {"name": name, "mode": mode, "filename": f"{name}.ovpn", "config": _profile(name, endpoint(), mode=mode),
            "needs_password": mode != "cert"}


def selftest() -> jobs.Job:
    """Issue a throwaway cert, connect a real OpenVPN client from a network
    namespace (via a veth pair) to the running server, ping the server's tunnel
    IP and the internet through the tunnel, then revoke + clean up."""
    def fn(log):
        st = status()
        if not st["configured"] or not st["active"]:
            raise VPNError("OpenVPN must be set up and running")
        s = _state()
        cn = f"{SELFTEST_PREFIX}{int(time.time())}"
        logins = st.get("logins_enabled")
        log(f"• Issuing temporary client certificate {cn}")
        _easyrsa("build-client-full", cn, "nopass")
        test_pw = secrets.token_urlsafe(16)
        if logins:
            # Log in as a temporary certificate + password user: exercises the
            # per-user login check exactly like a real device.
            db = _db()
            db["users"][cn] = {"mode": "cert+password", "hash": _hash(test_pw), "created": int(time.time())}
            _save_db(db)
        ns_cleanup()
        subprocess.run(["ip", "link", "del", "aurvt-h"], capture_output=True)
        tmpdir = Path(tempfile.mkdtemp(prefix="aurora-ovpn-"))
        proc = None
        ok = False
        try:
            run(["ip", "netns", "add", TEST_NS])
            run(["ip", "link", "add", "aurvt-h", "type", "veth", "peer", "name", "aurvt-n"])
            run(["ip", "link", "set", "aurvt-n", "netns", TEST_NS])
            run(["ip", "addr", "add", "10.253.77.1/30", "dev", "aurvt-h"])
            run(["ip", "link", "set", "aurvt-h", "up"])
            for argv in (["ip", "link", "set", "lo", "up"], ["ip", "addr", "add", "10.253.77.2/30", "dev", "aurvt-n"],
                         ["ip", "link", "set", "aurvt-n", "up"], ["ip", "route", "add", "default", "via", "10.253.77.1"]):
                r = ns_exec(argv)
                if r.returncode != 0:
                    raise VPNError(f"{' '.join(argv)}: {r.stderr.strip()}")
            prof = tmpdir / "test.ovpn"
            text = _profile(cn, "10.253.77.1", mode="cert+password" if logins else "cert")
            if logins:
                creds = tmpdir / "creds.txt"
                write_secret(creds, f"{cn}\n{test_pw}\n")
                text = text.replace("auth-user-pass\n", f"auth-user-pass {creds}\n").replace("auth-retry interact", "auth-retry none")
            write_secret(prof, text + "pull-filter ignore \"dhcp-option\"\n")
            log(f"• Connecting a real OpenVPN client to 10.253.77.1:{s['port']}/{s['proto']}…")
            proc = subprocess.Popen(["ip", "netns", "exec", TEST_NS, "openvpn", "--config", str(prof)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            connected, deadline, tail = False, time.time() + 40, []
            os.set_blocking(proc.stdout.fileno(), False)
            while time.time() < deadline and proc.poll() is None:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                tail.append(line.rstrip())
                if "Initialization Sequence Completed" in line:
                    connected = True
                    break
                if re.search(r"AUTH_FAILED|TLS Error|VERIFY ERROR|Exiting due to fatal error", line):
                    break
            if not connected:
                log("✖ Client did not connect. Last client log lines:")
                for t in tail[-12:]:
                    log("    " + t)
                raise VPNError("OpenVPN handshake failed")
            log("✔ TLS handshake + certificate check" + (" + username/password login" if logins else "")
                + " (Initialization Sequence Completed)")
            server_ip = str(ipaddress.ip_network(s["subnet"]).network_address + 1)
            tunnel = ns_ping(log, server_ip, "Tunnel to the server")
            route = ns_exec(["ip", "route", "get", "1.1.1.1"]).stdout
            via_tun = "dev tun" in route
            if s["redirect"]:
                log(f"{'✔' if via_tun else '✖'} Internet traffic is routed into the tunnel")
                internet = ns_ping(log, "1.1.1.1", "Internet through the VPN (forwarding + NAT)")
            else:
                log("• Split tunnel: internet stays local (not tested)")
                via_tun = internet = True
            ok = tunnel and via_tun and internet
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            ns_cleanup()
            subprocess.run(["ip", "link", "del", "aurvt-h"], capture_output=True)
            shutil.rmtree(tmpdir, ignore_errors=True)
            db = _db()
            if db["users"].pop(cn, None) is not None:
                _save_db(db)
            try:
                _easyrsa("revoke", cn)
                _publish_crl()
            except VPNError as exc:
                log(f"! could not revoke {cn}: {exc}")
            log("• Revoked the temporary certificate and removed the namespace")
        if not ok:
            raise VPNError("Self-test failed — see the steps above")
        log("✔ OpenVPN works end to end. Remote devices additionally need "
            f"{s['proto'].upper()} {s['port']} forwarded on your router.")
        return {"ok": True}
    return jobs.launch_fn("OpenVPN self-test", fn, meta={"vpn": "openvpn"})


def external_evidence(port: int, proto: str) -> str | None:
    st = status() if which("openvpn") else None
    if not st or not st["active"] or proto != st["proto"] or int(port) != st["port"]:
        return None
    lan = default_route().get("lan")
    for c in st["clients"]:
        ra = (c.get("real_address") or "").rsplit(":", 1)[0]
        try:
            a = ipaddress.ip_address(ra)
        except ValueError:
            continue
        if not a.is_private and not (lan and a in ipaddress.ip_network(lan)):
            return f"OpenVPN client '{c['name']}' is connected from {ra}"
    return None
