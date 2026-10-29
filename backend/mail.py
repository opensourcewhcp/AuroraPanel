"""Email: accounts, forwarders, catch-alls, routing, autoresponders, filters, spam,
mailing lists, delivery tracking, deliverability (SPF/DKIM/DMARC/PTR) and more.

The stack: Postfix (SMTP, virtual domains) → Rspamd milter (spam score, DKIM
signing) → Dovecot 2.4 over LMTP (IMAP/POP3, quota, Sieve). Everything the
panel manages lives in one state file (STATE); apply() renders it into the
Postfix lookup tables, the Dovecot users file, one Sieve script per mailbox
and Rspamd's maps, then reloads only what changed. Hand edits to those
generated files are overwritten; the distro's own settings are left alone
except the handful set by setup().
"""
from __future__ import annotations

import csv
import io
import json
import os
import platform
try:
    import pwd
except ImportError:  # Windows (tests)
    pwd = None
import re
import secrets
import shutil
import socket
import string
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from . import jobs

IS_LINUX = platform.system() == "Linux"
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

STATE = Path("/var/lib/aurora/mail/state.json")
PF_DIR = Path("/etc/postfix/aurora")
DC_CONF = Path("/etc/dovecot/dovecot.conf")
DC_USERS = Path("/etc/dovecot/aurora-users")
SIEVE_DIR = Path("/etc/dovecot/sieve")
SIEVE_GLOBAL = SIEVE_DIR / "aurora-before.sieve"
VMAIL = Path("/var/vmail")
RSPAMD_LOCAL = Path("/etc/rspamd/local.d")
RSPAMD_MAPS = Path("/etc/rspamd/aurora")
DKIM_DIR = Path("/var/lib/rspamd/dkim")
LIB_DIR = Path("/usr/local/lib/aurora-mail")
AUTOCONFIG_DIR = Path("/usr/local/share/aurora-mail/autoconfig")
LIST_CONF = Path("/etc/aurora-mail/lists.json")
TLS_DIR = Path("/etc/aurora-mail/tls")
TRASH = Path("/var/lib/aurora/trash")
SELECTOR = "aurora"
HEADER = "# Written by AuroraPanel (Email). Edit in the panel — changes here are overwritten.\n"

PACKAGES = ["postfix", "postfix-pcre", "dovecot-core", "dovecot-imapd", "dovecot-pop3d", "dovecot-lmtpd",
            "dovecot-sieve", "dovecot-managesieved", "rspamd", "redis-server"]
MAIL_PORTS = ["25/tcp", "465/tcp", "587/tcp", "993/tcp", "995/tcp", "143/tcp", "110/tcp"]

_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_LOCAL = re.compile(r"^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?$")
_EMAIL = re.compile(r"^[^@\s\"'\\<>,;:]{1,64}@[a-z0-9.-]{1,253}$", re.I)
_FOLDER = re.compile(r"^[\w .&()-]{1,60}(?:/[\w .&()-]{1,60}){0,3}$", re.U)


class MailError(RuntimeError):
    pass


# ----------------------------------------------------------------------------- helpers
def _run(argv: list[str], timeout: int = 60, input: str | None = None, env: dict | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input,
                              env={**os.environ, "PATH": PATH, "LANG": "C.UTF-8", **(env or {})})
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def _write(path: Path, text: str, mode: int = 0o644, owner: str | None = None, group: str | None = None) -> bool:
    """Atomic write; True when the content changed."""
    try:
        if path.read_text(encoding="utf-8") == text:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    if owner or group:
        shutil.chown(tmp, owner, group)
    tmp.replace(path)
    return True


def _domain(d: str) -> str:
    d = (d or "").strip().lower().rstrip(".")
    if not _DOMAIN.match(d):
        raise MailError(f"“{d}” isn't a valid domain name")
    return d


def _local(u: str) -> str:
    u = (u or "").strip().lower()
    if not _LOCAL.match(u) or ".." in u:
        raise MailError("Use letters, digits, dots, dashes, underscores or + (start and end with a letter or digit)")
    return u


def _addr(a: str) -> str:
    a = (a or "").strip().lower()
    if a.count("@") != 1:
        raise MailError(f"“{a}” isn't an email address")
    u, d = a.split("@")
    return f"{_local(u)}@{_domain(d)}"


def _ext_addr(a: str) -> str:
    """Any deliverable address (forward targets may be anywhere)."""
    a = (a or "").strip()
    if not _EMAIL.match(a) or not _DOMAIN.match(a.split("@")[1].lower()):
        raise MailError(f"“{a}” isn't an email address")
    return a.split("@")[0] + "@" + a.split("@")[1].lower()


def _line(s: str, n: int = 300) -> str:
    return re.sub(r"[\r\n\t]+", " ", str(s or "")).strip()[:n]


def _pw_hash(password: str) -> str:
    if len(password or "") < 8:
        raise MailError("The password needs at least 8 characters")
    if any(c in password for c in "\r\n:"):
        raise MailError("The password can't contain line breaks or “:”")
    r = _run(["openssl", "passwd", "-6", "-stdin"], input=password + "\n")
    h = r.stdout.strip()
    if r.returncode != 0 or not h.startswith("$6$"):
        raise MailError("Couldn't hash the password (openssl missing?)")
    return "{SHA512-CRYPT}" + h


def gen_password(n: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits
    while True:
        p = "".join(secrets.choice(alphabet) for _ in range(n - 2)) + secrets.choice("-_.!@#%") + secrets.choice(string.digits)
        if re.search(r"[a-z]", p) and re.search(r"[A-Z]", p):
            return p


def _vmail_ids() -> tuple[int, int]:
    p = pwd.getpwnam("vmail")
    return p.pw_uid, p.pw_gid


# ----------------------------------------------------------------------------- state
def _default_state() -> dict:
    return {"version": 1, "hostname": "", "hostname_mode": "auto", "domains": {}, "accounts": {}, "forwarders": {}, "domain_forwarders": {},
            "autoresponders": {}, "filters": {"global": []}, "lists": {},
            "spam": {"enabled": True, "threshold": 5, "junk": True, "autodelete": False, "delete_threshold": 12,
                     "allow": [], "block": [], "greylist": False, "per_user": {}},
            "tls": {"source": "self"}, "dav_shares": [], "track": {"days": 30, "cleared": 0}}


def load() -> dict:
    try:
        s = json.loads(STATE.read_text())
    except (OSError, ValueError):
        s = {}
    base = _default_state()
    for k, v in base.items():
        s.setdefault(k, v)
    for k, v in base["spam"].items():
        s["spam"].setdefault(k, v)
    s["filters"].setdefault("global", [])
    for dom in s["domains"].values():
        # Domains from before routing was auto-detected: follow DNS unless routing was chosen on purpose.
        if dom.get("routing") == "local" and not dom.get("routing_set"):
            dom["routing"] = "auto"
    return s


def save(s: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE.parent, 0o700)
    _write(STATE, json.dumps(s, indent=1, sort_keys=True), 0o600)


def installed() -> bool:
    return IS_LINUX and shutil.which("postfix", path=PATH) is not None and shutil.which("doveadm", path=PATH) is not None \
        and Path("/etc/rspamd").is_dir()


def configured() -> bool:
    return DC_CONF.exists() and DC_CONF.read_text(errors="replace").startswith(HEADER) and PF_DIR.is_dir()


def _require():
    if not (installed() and configured()):
        raise MailError("The mail server isn't set up yet — open Email to install it")


def hostname(s: dict | None = None) -> str:
    s = s or load()
    return s.get("hostname") or socket.getfqdn() or socket.gethostname()


# ----------------------------------------------------------------------------- domains
def is_ip_name(d: str) -> bool:
    """192.168.0.100 passes the domain pattern, but name@192.168.0.100 isn't a valid email
    address: Roundcube, phones and most mail programs refuse to send to it."""
    return bool(re.fullmatch(r"[0-9.]+", d or ""))


IP_DOMAIN_HINT = ("An IP address can't be a mail domain — webmail and mail apps refuse addresses like name@192.168.0.100. "
                  "Without a domain, turn on Local mail on the Email page: addresses like you@{local} work on this server "
                  "(alerts, apps, webmail) with no DNS or internet.")


def _ensure_domain(s: dict, d: str) -> dict:
    d = _domain(d)
    if d not in s["domains"]:
        if is_ip_name(d):
            raise MailError(IP_DOMAIN_HINT.format(local=local_domain_name()))
        s["domains"][d] = {"routing": "auto", "catchall": {"mode": "fail", "message": "No such user here"},
                           "created": int(time.time())}
    return s["domains"][d]


def candidate_domains() -> list[str]:
    """Domains the user probably wants mail for: mail domains, websites and DNS zones."""
    out = set(load()["domains"])
    try:
        from . import sites
        for x in sites.list_sites().get("sites", []):
            for n in [x["server_name"], *x.get("aliases", [])]:
                n = (n or "").lower()
                if _DOMAIN.match(n) and not n.startswith("www.") and "." in n and not is_ip_name(n):
                    out.add(n)
    except Exception:
        pass
    try:
        from . import dnszones
        for z in dnszones.list_zones([]).get("zones", []):
            out.add(z["domain"])
    except Exception:
        pass
    return sorted(out)


LOCAL_PCRE = PF_DIR / "transport_local.pcre"
# Bump when postfix_settings()/postfix_services() change, so existing servers pick them up on the next apply().
CONFIG_REV = 5


def _write_local_pcre() -> None:
    _write(LOCAL_PCRE, HEADER + "# Mail for another device on the local network goes straight to it (found by mDNS).\n"
                       # Domains only: in the full-address lookup Postfix forbids $1 and logs a warning.
                       "/^([^@]+\\.local)$/ smtp:[$1]\n", 0o644)


def _upgrade_config(s: dict) -> None:
    _write_local_pcre()
    cert, key = _tls_paths(s)
    for k, v in postfix_settings(hostname(s), cert, key).items():
        _run(["postconf", "-e", f"{k}={v}"])
    for name, entry, params in postfix_services():
        _run(["postconf", "-M", f"{name}={entry}"])
        for p in params:
            _run(["postconf", "-P", f"{name}/{p}"])
    if s.get("tls", {}).get("source", "self") != "self":
        _apache_mailhost(hostname(s), cert, key)
    from . import requires
    requires.php_no_jit()
    s["config_rev"] = CONFIG_REV
    save(s)


def is_local(d: str) -> bool:
    return d.endswith(".local")


def local_domain_name() -> str:
    """This device's own name on the local network (what avahi/mDNS answers): <hostname>.local."""
    short = re.sub(r"[^a-z0-9-]", "-", socket.gethostname().split(".")[0].lower()).strip("-") or "server"
    return f"{short}.local"


def local_status() -> dict:
    s = load()
    name = local_domain_name()
    mdns = _run(["systemctl", "is-active", "--quiet", "avahi-daemon"]).returncode == 0
    return {"domain": name, "enabled": name in s["domains"], "mdns": mdns,
            "accounts": sorted(a for a in s["accounts"] if a.endswith("@" + name))}


def enable_local(on: bool = True) -> dict:
    """Mail without the internet: <hostname>.local for apps on this machine (admin@ns1.local),
    and for other AuroraPanel servers on the same network (they're found by their .local name)."""
    _require()
    s = load()
    name = local_domain_name()
    if on:
        dom = _ensure_domain(s, name)
        dom.update(routing="local", routing_set=True, local=True)
        s.pop("local_off", None)
    else:
        if any(a.endswith("@" + name) for a in s["accounts"]):
            raise MailError(f"Delete the accounts on {name} first")
        s["domains"].pop(name, None)
        s["local_off"] = True  # a re-run of the mail setup won't turn it back on
    save(s)
    apply(s)
    return local_status()


def add_domain(d: str) -> dict:
    _require()
    s = load()
    _ensure_domain(s, d)
    save(s)
    apply(s)
    ensure_dkim(_domain(d))
    return {"ok": True}


def remove_domain(d: str) -> dict:
    """Stop handling mail for a domain. Mailboxes must be deleted first (so no mail is lost by
    accident); its mailing lists, forwarders and settings go with it. The DKIM key is kept, so
    re-adding the domain doesn't break the published DNS record."""
    s = load()
    d = _domain(d)
    if d not in s["domains"]:
        raise MailError(f"{d} isn't a mail domain")
    accounts = [a for a in s["accounts"] if a.endswith("@" + d)]
    if accounts:
        raise MailError(f"Delete the {len(accounts)} email account(s) on {d} first")
    lists = [a for a in s["lists"] if a.endswith("@" + d)]
    fwd = [k for k in s["forwarders"] if k.endswith("@" + d)]
    s["domains"].pop(d, None)
    s["lists"] = {k: v for k, v in s["lists"].items() if k not in lists}
    s["forwarders"] = {k: v for k, v in s["forwarders"].items() if k not in fwd}
    s["domain_forwarders"].pop(d, None)
    save(s)
    apply(s)
    return {"ok": True, "removed_lists": len(lists), "removed_forwarders": len(fwd)}


def set_routing(d: str, routing: str) -> dict:
    s = load()
    if routing not in ("local", "backup", "remote", "auto"):
        raise MailError("Unknown routing")
    dom = _ensure_domain(s, d)
    dom["routing"] = routing
    dom["routing_set"] = routing != "auto"
    save(s)
    apply(s)
    return {"ok": True, "effective": _effective_routing(_domain(d), dom)}


def _is_me(host: str) -> bool:
    ip = _public_ip()
    return host in _my_names() or bool(ip and ip in _a(host))


def _effective_routing(d: str, dom: dict) -> str:
    """auto: this server receives the domain's mail when its best MX points here (or there's
    no MX yet), keeps a backup copy when a lower-priority MX does, and otherwise sends it on."""
    r = dom.get("routing", "auto")
    if r != "auto" or is_local(d):
        return "local" if is_local(d) else r
    mx = _mx(d)
    if not mx:
        return "local"
    best = min(p for p, _ in mx)
    if any(_is_me(h) for p, h in mx if p == best):
        return "local"
    return "backup" if any(_is_me(h) for _, h in mx) else "remote"


def set_catchall(d: str, mode: str, target: str = "", message: str = "") -> dict:
    s = load()
    dom = _ensure_domain(s, d)
    if mode == "forward":
        targets = [_ext_addr(t) for t in re.split(r"[,\s]+", target) if t.strip()]
        if not targets:
            raise MailError("Enter the address to send it to")
        dom["catchall"] = {"mode": "forward", "target": ",".join(targets)}
    elif mode == "fail":
        dom["catchall"] = {"mode": "fail", "message": _line(message or "No such user here", 200)}
    elif mode == "discard":
        dom["catchall"] = {"mode": "discard"}
    else:
        raise MailError("Unknown option")
    save(s)
    apply(s)
    return {"ok": True}


# ----------------------------------------------------------------------------- accounts
def list_accounts() -> dict:
    from . import authz
    s = load()
    usage = _quota_usage()
    out = []
    for a, acc in sorted(s["accounts"].items()):
        if not authz.domain_ok(a.split("@")[1]):
            continue
        used = usage.get(a, 0)
        q = acc.get("quota_mb", 0)
        out.append({"address": a, "domain": a.split("@")[1], "name": acc.get("name", ""), "quota_mb": q,
                    "used_bytes": used, "percent": round(used / (q * 1048576) * 100, 2) if q else None,
                    "suspend": acc.get("suspend", {}), "created": acc.get("created"),
                    "autoresponder": bool(s["autoresponders"].get(a, {}).get("enabled")),
                    "filters": len(s["filters"].get(a, [])),
                    "forwards": [k for k, v in s["forwarders"].items() if a in v.get("dest", [])]})
    doms = sorted(d for d in s["domains"] if authz.domain_ok(d))
    return {"accounts": out, "domains": doms, "candidates": candidate_domains() if authz.scope() is None else [],
            "hostname": hostname(s), "webmail": webmail_url(),
            # Offered on the page when off: mail on this server without owning a domain.
            "local_domain": local_domain_name() if authz.scope() is None else "",
            "ip_domains": [d for d in doms if is_ip_name(d)]}


def _quota_usage() -> dict[str, int]:
    """address -> bytes used. Exact message sizes from every mailbox (one call for everyone), so the
    figure matches the per-mailbox table; Dovecot's quota counter (rounded up to whole KiB) is the fallback."""
    if not shutil.which("doveadm", path=PATH):
        return {}
    r = _run(["doveadm", "-f", "flow", "mailbox", "status", "-A", "vsize", "*"], 120)
    exact: dict[str, int] = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if not parts or "@" not in parts[0]:
            continue
        kv = dict(re.findall(r"(\w+)=(\S*)", line))
        try:
            exact[parts[0]] = exact.get(parts[0], 0) + int(kv.get("vsize") or 0)
        except ValueError:
            pass
    if exact:
        return exact
    r = _run(["doveadm", "-f", "flow", "quota", "get", "-A"], 60)
    out: dict[str, int] = {}
    for line in r.stdout.splitlines():
        # "user@dom Quota name=User quota Type=STORAGE Value=11 Limit=51200 %=0" (Value in KiB)
        kv = dict(re.findall(r"(\w+)=(\S*)", line))
        user = kv.get("Username") or (line.split()[0] if line.strip() else "")
        if kv.get("Type") == "STORAGE" and "@" in user:
            try:
                out[user] = int(kv.get("Value") or 0) * 1024
            except ValueError:
                pass
    return out


def create_account(address: str, password: str, quota_mb: int = 1024, name: str = "") -> dict:
    from . import authz
    if authz.scope() is not None and not authz.domain_ok(str(address).rsplit('@', 1)[-1].strip().lower()):
        raise MailError("That address isn't on one of your websites' domains")
    _require()
    s = load()
    a = _addr(address)
    if a in s["accounts"]:
        raise MailError(f"{a} already exists")
    if a in s["lists"]:
        raise MailError(f"{a} is a mailing list")
    _ensure_domain(s, a.split("@")[1])
    s["accounts"][a] = {"hash": _pw_hash(password), "quota_mb": max(0, int(quota_mb or 0)), "name": _line(name, 80),
                        "created": int(time.time()), "suspend": {"login": False, "incoming": False, "outgoing": False}}
    save(s)
    apply(s)
    ensure_dkim(a.split("@")[1])
    try:
        _dav_defaults(a)
    except (MailError, OSError):
        pass
    return {"ok": True, "address": a}


def import_account(address: str, crypt_hash: str, quota_mb: int = 0) -> dict:
    """A mailbox moved from another server, keeping its password: crypt_hash is the old server's
    crypt(3) hash ($6$… / $5$… / $1$…), which Dovecot checks as-is."""
    _require()
    if not re.fullmatch(r"\$(1|5|6|2[aby]?|y)\$[./A-Za-z0-9$,=+-]{8,200}", crypt_hash or ""):
        raise MailError("unsupported password hash")
    s = load()
    a = _addr(address)
    if a in s["accounts"]:
        raise MailError("already exists here")
    _ensure_domain(s, a.split("@")[1])
    s["accounts"][a] = {"hash": "{CRYPT}" + crypt_hash, "quota_mb": max(0, int(quota_mb or 0)), "name": "", "created": int(time.time()),
                        "suspend": {"login": False, "incoming": False, "outgoing": False}, "imported": True}
    save(s)
    apply(s)
    ensure_dkim(a.split("@")[1])
    return {"ok": True, "address": a}


def update_account(address: str, password: str | None = None, quota_mb: int | None = None,
                   suspend: dict | None = None, name: str | None = None) -> dict:
    from . import authz
    if authz.scope() is not None and not authz.domain_ok(str(address).rsplit('@', 1)[-1].strip().lower()):
        raise MailError("That address isn't on one of your websites' domains")
    s = load()
    a = _addr(address)
    acc = s["accounts"].get(a)
    if not acc:
        raise MailError(f"No account {a}")
    if password:
        acc["hash"] = _pw_hash(password)
    if quota_mb is not None:
        acc["quota_mb"] = max(0, int(quota_mb))
    if name is not None:
        acc["name"] = _line(name, 80)
    if suspend:
        acc.setdefault("suspend", {})
        for k in ("login", "incoming", "outgoing"):
            if k in suspend:
                acc["suspend"][k] = bool(suspend[k])
    save(s)
    apply(s)
    if password:
        _run(["doveadm", "auth", "cache", "flush"])
    return {"ok": True}


def delete_account(address: str, delete_mail: bool = False) -> dict:
    from . import authz
    if authz.scope() is not None and not authz.domain_ok(str(address).rsplit('@', 1)[-1].strip().lower()):
        raise MailError("That address isn't on one of your websites' domains")
    s = load()
    a = _addr(address)
    if a not in s["accounts"]:
        raise MailError(f"No account {a}")
    del s["accounts"][a]
    s["autoresponders"].pop(a, None)
    s["filters"].pop(a, None)
    s["spam"]["per_user"].pop(a, None)
    s["dav_shares"] = [x for x in s.get("dav_shares", []) if a not in (x["owner"], x["with"])]
    save(s)
    apply(s)
    home = _home(a)
    moved = None
    if delete_mail and home.exists():
        TRASH.mkdir(parents=True, exist_ok=True)
        moved = TRASH / f"mail-{a.replace('@', '_at_')}-{int(time.time())}"
        shutil.move(str(home), moved)
    return {"ok": True, "moved_to": str(moved) if moved else None}


def _home(a: str) -> Path:
    u, d = a.split("@")
    return VMAIL / d / u


def device_settings(address: str) -> dict:
    from . import authz
    if authz.scope() is not None and not authz.domain_ok(str(address).rsplit('@', 1)[-1].strip().lower()):
        raise MailError("That address isn't on one of your websites' domains")
    a = _addr(address)
    h = hostname()
    return {"address": a, "username": a, "incoming": {"imap": {"host": h, "port": 993, "security": "SSL/TLS"},
                                                       "pop3": {"host": h, "port": 995, "security": "SSL/TLS"}},
            "outgoing": {"host": h, "port": 465, "security": "SSL/TLS", "alt_port": 587, "alt_security": "STARTTLS"},
            "webmail": webmail_url(), "dav": dav_urls(a)}


def mobileconfig(address: str) -> str:
    from . import authz
    if authz.scope() is not None and not authz.domain_ok(str(address).rsplit('@', 1)[-1].strip().lower()):
        raise MailError("That address isn't on one of your websites' domains")
    """Apple configuration profile (iPhone, iPad, Mac): one tap sets up the account."""
    a = _addr(address)
    h = hostname()
    uid = lambda: "".join(secrets.choice("0123456789ABCDEF") for _ in range(32))
    def u():
        x = uid()
        return f"{x[:8]}-{x[8:12]}-{x[12:16]}-{x[16:20]}-{x[20:]}"
    esc = lambda t: t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
 <key>PayloadContent</key><array><dict>
  <key>EmailAccountDescription</key><string>{esc(a)}</string>
  <key>EmailAccountType</key><string>EmailTypeIMAP</string>
  <key>EmailAddress</key><string>{esc(a)}</string>
  <key>IncomingMailServerAuthentication</key><string>EmailAuthPassword</string>
  <key>IncomingMailServerHostName</key><string>{esc(h)}</string>
  <key>IncomingMailServerPortNumber</key><integer>993</integer>
  <key>IncomingMailServerUseSSL</key><true/>
  <key>IncomingMailServerUsername</key><string>{esc(a)}</string>
  <key>OutgoingMailServerAuthentication</key><string>EmailAuthPassword</string>
  <key>OutgoingMailServerHostName</key><string>{esc(h)}</string>
  <key>OutgoingMailServerPortNumber</key><integer>465</integer>
  <key>OutgoingMailServerUseSSL</key><true/>
  <key>OutgoingMailServerUsername</key><string>{esc(a)}</string>
  <key>OutgoingPasswordSameAsIncomingPassword</key><true/>
  <key>PayloadDisplayName</key><string>{esc(a)}</string>
  <key>PayloadIdentifier</key><string>com.aurorapanel.mail.{u()}</string>
  <key>PayloadType</key><string>com.apple.mail.managed</string>
  <key>PayloadUUID</key><string>{u()}</string>
  <key>PayloadVersion</key><integer>1</integer>
 </dict></array>
 <key>PayloadDisplayName</key><string>Email — {esc(a)}</string>
 <key>PayloadIdentifier</key><string>com.aurorapanel.mail.profile.{u()}</string>
 <key>PayloadType</key><string>Configuration</string>
 <key>PayloadUUID</key><string>{u()}</string>
 <key>PayloadVersion</key><integer>1</integer>
</dict></plist>
"""


AUTOCONFIG_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!-- Written by AuroraPanel (Email): Thunderbird / Evolution / K-9 automatic setup. -->
<clientConfig version="1.1">
 <emailProvider id="{host}">
  <domain>%EMAILDOMAIN%</domain>
  <displayName>%EMAILADDRESS%</displayName>
  <incomingServer type="imap"><hostname>{host}</hostname><port>993</port><socketType>SSL</socketType>
   <authentication>password-cleartext</authentication><username>%EMAILADDRESS%</username></incomingServer>
  <incomingServer type="pop3"><hostname>{host}</hostname><port>995</port><socketType>SSL</socketType>
   <authentication>password-cleartext</authentication><username>%EMAILADDRESS%</username></incomingServer>
  <outgoingServer type="smtp"><hostname>{host}</hostname><port>465</port><socketType>SSL</socketType>
   <authentication>password-cleartext</authentication><username>%EMAILADDRESS%</username></outgoingServer>
 </emailProvider>
</clientConfig>
"""


# ----------------------------------------------------------------------------- forwarders
def list_forwarders() -> dict:
    s = load()
    rows = [{"source": k, **v} for k, v in sorted(s["forwarders"].items())]
    doms = [{"domain": k, "target": v} for k, v in sorted(s["domain_forwarders"].items())]
    return {"forwarders": rows, "domain_forwarders": doms, "domains": sorted(s["domains"]), "candidates": candidate_domains()}


def add_forwarder(source: str, kind: str, dest: str = "", message: str = "") -> dict:
    _require()
    s = load()
    src = _addr(source)
    if src in s["lists"]:
        raise MailError(f"{src} is a mailing list")
    _ensure_domain(s, src.split("@")[1])
    cur = s["forwarders"].get(src, {"type": "forward", "dest": []})
    if kind == "forward":
        targets = [_ext_addr(t) for t in re.split(r"[,\s]+", dest) if t.strip()]
        if not targets:
            raise MailError("Enter the address to forward to")
        if src in [t.lower() for t in targets]:
            raise MailError("An address can't forward to itself")
        merged = cur["dest"] if cur.get("type") == "forward" else []
        cur = {"type": "forward", "dest": merged + [t for t in targets if t not in merged]}
    elif kind == "fail":
        cur = {"type": "fail", "message": _line(message or "No such person at this address", 200), "dest": []}
    elif kind == "discard":
        cur = {"type": "discard", "dest": []}
    else:
        raise MailError("Unknown destination")
    s["forwarders"][src] = cur
    save(s)
    apply(s)
    return {"ok": True}


def delete_forwarder(source: str, dest: str | None = None) -> dict:
    s = load()
    src = _addr(source)
    f = s["forwarders"].get(src)
    if not f:
        raise MailError("No such forwarder")
    if dest and f.get("type") == "forward":
        f["dest"] = [t for t in f["dest"] if t.lower() != dest.lower()]
        if not f["dest"]:
            del s["forwarders"][src]
    else:
        del s["forwarders"][src]
    save(s)
    apply(s)
    return {"ok": True}


def add_domain_forwarder(domain: str, target: str) -> dict:
    s = load()
    d, t = _domain(domain), _domain(target)
    if d == t:
        raise MailError("A domain can't forward to itself")
    _ensure_domain(s, d)
    s["domain_forwarders"][d] = t
    save(s)
    apply(s)
    return {"ok": True}


def delete_domain_forwarder(domain: str) -> dict:
    s = load()
    s["domain_forwarders"].pop(_domain(domain), None)
    save(s)
    apply(s)
    return {"ok": True}


def trace(address: str) -> dict:
    """Where would mail to this address end up? Follows aliases the way Postfix does."""
    s = load()
    a = _ext_addr(address).lower()
    steps, seen, out = [], set(), []

    def walk(x: str, depth: int):
        if depth > 8 or x in seen:
            steps.append({"address": x, "result": "loop"})
            return
        seen.add(x)
        u, d = x.split("@")
        if d not in s["domains"] and d not in s["domain_forwarders"]:
            out.append({"address": x, "result": "remote"})
            return
        f = s["forwarders"].get(x)
        if x in s["lists"]:
            out.append({"address": x, "result": "list", "members": len(s["lists"][x].get("members", []))})
        elif f and f["type"] == "fail":
            out.append({"address": x, "result": "rejected", "message": f.get("message")})
            return
        elif f and f["type"] == "discard":
            out.append({"address": x, "result": "discarded"})
            return
        if x in s["accounts"]:
            out.append({"address": x, "result": "mailbox"})
        if f and f["type"] == "forward":
            for t in f["dest"]:
                steps.append({"from": x, "to": t})
                walk(t.lower(), depth + 1)
            return
        if x in s["accounts"] or x in s["lists"]:
            return
        if d in s["domain_forwarders"]:
            t = f"{u}@{s['domain_forwarders'][d]}"
            steps.append({"from": x, "to": t})
            walk(t, depth + 1)
            return
        ca = s["domains"].get(d, {}).get("catchall", {})
        if ca.get("mode") == "forward":
            for t in ca["target"].split(","):
                steps.append({"from": x, "to": t, "via": "default address"})
                walk(t.lower(), depth + 1)
        elif ca.get("mode") == "discard":
            out.append({"address": x, "result": "discarded", "via": "default address"})
        else:
            out.append({"address": x, "result": "rejected", "message": ca.get("message", "No such user here"), "via": "default address"})

    walk(a, 0)
    return {"address": a, "hops": steps, "ends": out}


# ----------------------------------------------------------------------------- autoresponders
def list_autoresponders() -> dict:
    s = load()
    return {"autoresponders": [{"address": k, **v} for k, v in sorted(s["autoresponders"].items())],
            "accounts": sorted(s["accounts"])}


def set_autoresponder(address: str, data: dict) -> dict:
    s = load()
    a = _addr(address)
    if a not in s["accounts"]:
        raise MailError("Autoresponders run on a mailbox — create the email account first")
    subject = _line(data.get("subject"), 200)
    body = str(data.get("body") or "").replace("\r\n", "\n")[:20000]
    if not subject or not body.strip():
        raise MailError("Enter a subject and a message")
    def ts(v):
        if not v:
            return None
        try:
            return int(datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp())
        except ValueError:
            raise MailError(f"“{v}” isn't a date")
    start, stop = ts(data.get("start")), ts(data.get("stop"))
    if start and stop and stop <= start:
        raise MailError("The stop time must be after the start time")
    s["autoresponders"][a] = {"enabled": bool(data.get("enabled", True)), "from_name": re.sub(r'["<>\\]', "", _line(data.get("from_name"), 100)),
                              "subject": subject, "body": body, "html": bool(data.get("html")),
                              "interval_hours": max(0, min(24 * 365, int(data.get("interval_hours") or 0))),
                              "start": start, "stop": stop, "updated": int(time.time())}
    save(s)
    apply(s)
    return {"ok": True}


def delete_autoresponder(address: str) -> dict:
    s = load()
    s["autoresponders"].pop(_addr(address), None)
    save(s)
    apply(s)
    return {"ok": True}


# ----------------------------------------------------------------------------- filters (Sieve)
RULE_PARTS = {"from", "to", "cc", "any_recipient", "subject", "header", "body", "spam_score", "size"}
RULE_OPS = {"contains", "not_contains", "is", "not_is", "begins", "ends", "matches", "regex", "not_regex", "over", "under"}
ACTIONS = {"fileinto", "copyinto", "redirect", "redirect_copy", "discard", "reject", "stop", "flag", "markread"}


def _clean_filter(f: dict) -> dict:
    name = _line(f.get("name"), 80)
    if not name:
        raise MailError("Give the filter a name")
    rules, actions = [], []
    for r in (f.get("rules") or [])[:20]:
        part, op = r.get("part"), r.get("op", "contains")
        if part not in RULE_PARTS or op not in RULE_OPS:
            raise MailError("Unknown rule")
        val = _line(r.get("value"), 300)
        rule = {"part": part, "op": op, "value": val}
        if part == "header":
            h = _line(r.get("header"), 80)
            if not re.match(r"^[A-Za-z0-9-]{1,80}$", h):
                raise MailError("Header names use letters, digits and dashes")
            rule["header"] = h
        if part in ("spam_score", "size"):
            if not re.match(r"^\d+(?:[KMG])?$", val, re.I):
                raise MailError("Enter a number" + (" (K/M/G allowed)" if part == "size" else ""))
            if part == "spam_score":
                rule["op"] = "over"
        elif op in ("regex", "not_regex"):
            try:
                re.compile(val)
            except re.error:
                raise MailError(f"“{val}” isn't a valid regular expression")
        elif not val:
            raise MailError("Every rule needs a value")
        rules.append(rule)
    if not rules:
        raise MailError("Add at least one rule")
    for a in (f.get("actions") or [])[:10]:
        t = a.get("type")
        if t not in ACTIONS:
            raise MailError("Unknown action")
        v = _line(a.get("value"), 300)
        if t in ("fileinto", "copyinto") and (not _FOLDER.match(v) or ".." in v or v.startswith((".", "/")) or "/." in v):
            raise MailError("Folder names use letters, digits, spaces and /")
        if t in ("redirect", "redirect_copy"):
            v = _ext_addr(v)
        if t == "reject" and not v:
            v = "This message was rejected."
        actions.append({"type": t, "value": v})
    if not actions:
        raise MailError("Add at least one action")
    return {"name": name, "match": "any" if f.get("match") == "any" else "all", "rules": rules, "actions": actions,
            "enabled": bool(f.get("enabled", True))}


def get_filters(owner: str) -> dict:
    s = load()
    key = "global" if owner == "global" else _addr(owner)
    return {"owner": key, "filters": s["filters"].get(key, []), "accounts": sorted(s["accounts"])}


def save_filters(owner: str, filters: list[dict]) -> dict:
    s = load()
    key = "global" if owner == "global" else _addr(owner)
    if key != "global" and key not in s["accounts"]:
        raise MailError("Filters run on a mailbox — create the email account first")
    clean = [_clean_filter(f) for f in filters[:100]]
    names = [f["name"].lower() for f in clean]
    if len(names) != len(set(names)):
        raise MailError("Filter names must be unique")
    s["filters"][key] = clean
    save(s)
    apply(s)
    return {"ok": True, "count": len(clean)}


def _q(v: str) -> str:
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _qlist(vs: list[str]) -> str:
    return "[" + ", ".join(_q(v) for v in vs) + "]"


def _glob_escape(v: str) -> str:
    return v.replace("\\", "\\\\\\\\").replace("*", "\\\\*").replace("?", "\\\\?")


def _sieve_test(r: dict, req: set) -> str:
    part, op, v = r["part"], r["op"], r["value"]
    if part == "spam_score":
        return f'header :contains "X-Spam-Level" {_q("*" * max(1, min(50, int(v))))}'
    if part == "size":
        return f"size :{'under' if op == 'under' else 'over'} {v.upper()}"
    neg = op.startswith("not_")
    base = op[4:] if neg else op
    cmp_ = {"contains": ":contains", "is": ":is", "begins": ":matches", "ends": ":matches", "matches": ":matches",
            "regex": ":regex"}[base]
    if base == "regex":
        req.add("regex")
    val = v
    if base == "begins":
        val = _glob_escape(v) + "*"
    elif base == "ends":
        val = "*" + _glob_escape(v)
    if part == "body":
        req.add("body")
        t = f"body :text {cmp_} {_q(val)}"
    elif part == "header":
        t = f"header {cmp_} {_q(r['header'])} {_q(val)}"
    elif part == "any_recipient":
        t = f'header {cmp_} ["to", "cc"] {_q(val)}'
    else:
        t = f"header {cmp_} {_q(part)} {_q(val)}"
    return f"not {t}" if neg else t


def _sieve_actions(actions: list[dict], req: set) -> list[str]:
    out = []
    for a in actions:
        t, v = a["type"], a["value"]
        if t == "fileinto":
            req.update({"fileinto", "mailbox"})
            out.append(f"fileinto :create {_q(v)};")
        elif t == "copyinto":
            req.update({"fileinto", "mailbox", "copy"})
            out.append(f"fileinto :copy :create {_q(v)};")
        elif t == "redirect":
            out.append(f"redirect {_q(v)};")
        elif t == "redirect_copy":
            req.add("copy")
            out.append(f"redirect :copy {_q(v)};")
        elif t == "discard":
            out.append("discard;")
        elif t == "reject":
            req.add("reject")
            out.append(f"reject {_q(v)};")
        elif t == "stop":
            out.append("stop;")
        elif t == "flag":
            req.add("imap4flags")
            out.append('addflag "\\\\Flagged";')
        elif t == "markread":
            req.add("imap4flags")
            out.append('addflag "\\\\Seen";')
    return out


def _sieve_filters(filters: list[dict], req: set) -> list[str]:
    lines = []
    for f in filters:
        if not f.get("enabled", True):
            continue
        tests = [_sieve_test(r, req) for r in f["rules"]]
        cond = tests[0] if len(tests) == 1 else f"{'anyof' if f['match'] == 'any' else 'allof'} ({', '.join(tests)})"
        lines.append(f"# {_line(f['name'], 80)}")
        lines.append(f"if {cond} {{")
        lines += ["  " + x for x in _sieve_actions(f["actions"], req)]
        lines.append("}")
    return lines


def _sieve_text_literal(body: str) -> str:
    """A Sieve multi-line string: text: … . (lines starting with "." are dot-stuffed)."""
    lines = [("." + l if l.startswith(".") else l) for l in body.replace("\r", "").split("\n")]
    return "text:\n" + "\n".join(lines) + "\n.\n"


def _when(prefix: str, epoch: int, req: set) -> str:
    """currentdate test for "now ≥ epoch" (prefix ge) or "now < epoch" (prefix lt), in UTC."""
    req.update({"date", "relational"})
    d = datetime.fromtimestamp(epoch, timezone.utc)
    day, tm = d.strftime("%Y-%m-%d"), d.strftime("%H:%M:%S")
    z = ':zone "+0000"'
    if prefix == "ge":
        return (f'anyof (currentdate {z} :value "gt" "date" {_q(day)}, '
                f'allof (currentdate {z} :is "date" {_q(day)}, currentdate {z} :value "ge" "time" {_q(tm)}))')
    return (f'anyof (currentdate {z} :value "lt" "date" {_q(day)}, '
            f'allof (currentdate {z} :is "date" {_q(day)}, currentdate {z} :value "lt" "time" {_q(tm)}))')


def _sieve_vacation(a: str, ar: dict, aliases: list[str], req: set) -> list[str]:
    req.update({"vacation", "variables"})
    body = ar["body"]
    for tag, var in (("%subject%", "${subject}"), ("%from%", "${from}"), ("%email%", "${email}")):
        body = body.replace(tag, var)
    subject = ar["subject"]
    for tag, var in (("%subject%", "${subject}"), ("%from%", "${from}"), ("%email%", "${email}")):
        subject = subject.replace(tag, var)
    conds = []
    if ar.get("start"):
        conds.append(_when("ge", ar["start"], req))
    if ar.get("stop"):
        conds.append(_when("lt", ar["stop"], req))
    secs = int(ar.get("interval_hours") or 0) * 3600
    if secs:
        req.add("vacation-seconds")
    frm = f"{ar['from_name']} <{a}>" if ar.get("from_name") else a
    lines = ['set "subject" "";', 'set "from" "";', 'set "email" "";',
             'if header :matches "subject" "*" { set "subject" "${1}"; }',
             'if header :matches "from" "*" { set "from" "${1}"; }',
             'if address :matches "from" "*" { set "email" "${1}"; }']
    opts = f":subject {_q(subject)} :from {_q(frm)} :addresses {_qlist([a, *aliases])}"
    opts += f" :seconds {secs}" if secs else " :days 1"
    if ar.get("html"):
        payload = "Content-Type: text/html; charset=utf-8\n\n" + body
        vac = f"vacation {opts} :mime {_sieve_text_literal(payload)}"
    else:
        vac = f"vacation {opts} {_sieve_text_literal(body)}"
    vac += ";"  # after the text: literal's closing "." line
    if conds:
        lines += [f"if allof ({', '.join(conds)}) {{", vac, "}"]
    else:
        lines.append(vac)
    return lines


def _spam_for(s: dict, a: str) -> dict:
    base = {k: s["spam"][k] for k in ("enabled", "threshold", "junk", "autodelete", "delete_threshold")}
    base.update({"allow": [], "block": []})
    base.update(s["spam"]["per_user"].get(a, {}))
    return base


def render_user_sieve(s: dict, a: str) -> str:
    req: set = {"fileinto", "mailbox"}
    body: list[str] = []
    sp = _spam_for(s, a)
    addrs = [x for x in sp.get("block", []) if "@" in x]
    doms = [x for x in sp.get("block", []) if "@" not in x]
    block = [t for t in ([f"address :is \"from\" {_qlist(addrs)}"] if addrs else []) +
             ([f"address :domain :is \"from\" {_qlist(doms)}"] if doms else [])]
    if block:
        body += ["# Blocked senders", f"if anyof ({', '.join(block)}) {{", "  discard;", "  stop;", "}"]
    if sp.get("enabled"):
        allow_a = [x for x in sp.get("allow", []) if "@" in x]
        allow_d = [x for x in sp.get("allow", []) if "@" not in x]
        allow = [t for t in ([f"address :is \"from\" {_qlist(allow_a)}"] if allow_a else []) +
                 ([f"address :domain :is \"from\" {_qlist(allow_d)}"] if allow_d else [])]
        spam = []
        if sp.get("autodelete"):
            spam += [f'if header :contains "X-Spam-Level" {_q("*" * int(sp["delete_threshold"]))} {{', "  discard;", "  stop;", "}"]
        if sp.get("junk"):
            spam += [f'if header :contains "X-Spam-Level" {_q("*" * int(sp["threshold"]))} {{', '  fileinto :create "Junk";', "  stop;", "}"]
        if spam:
            body.append("# Spam")
            if allow:
                body.append(f"if not anyof ({', '.join(allow)}) {{")
                body += ["  " + x for x in spam]
                body.append("}")
            else:
                body += spam
    ar = s["autoresponders"].get(a)
    if ar and ar.get("enabled"):
        aliases = [k for k, v in s["forwarders"].items() if a in v.get("dest", [])]
        body += ["# Autoresponder", *_sieve_vacation(a, ar, aliases, req)]
    fl = _sieve_filters(s["filters"].get(a, []), req)
    if fl:
        body += ["# Filters", *fl]
    return HEADER + f"require {_qlist(sorted(req))};\n" + "\n".join(body) + "\n"


def render_global_sieve(s: dict) -> str:
    req: set = set()
    fl = _sieve_filters(s["filters"].get("global", []), req)
    head = HEADER + "# Global filters: run for every mailbox before its own filters.\n"
    return head + (f"require {_qlist(sorted(req))};\n" if req else "") + "\n".join(fl) + "\n"


# ----------------------------------------------------------------------------- spam
def get_spam(owner: str = "global") -> dict:
    s = load()
    if owner == "global":
        return {"owner": "global", **s["spam"], "per_user": sorted(s["spam"]["per_user"]), "accounts": sorted(s["accounts"]),
                "rspamd": _active("rspamd"), "stats": _rspamd_stats()}
    a = _addr(owner)
    return {"owner": a, **_spam_for(s, a), "custom": a in s["spam"]["per_user"]}


def _clean_senders(vals) -> list[str]:
    out = []
    for v in vals or []:
        v = str(v).strip().lower().lstrip("*@.")
        if not v:
            continue
        if "@" in v:
            v = _ext_addr(v).lower()
        else:
            v = _domain(v)
        if v not in out:
            out.append(v)
    return out[:1000]


def set_spam(owner: str, data: dict) -> dict:
    s = load()
    def num(k, lo, hi, d):
        try:
            return max(lo, min(hi, int(float(data.get(k, d)))))
        except (TypeError, ValueError):
            return d
    vals = {"enabled": bool(data.get("enabled", True)), "threshold": num("threshold", 1, 30, 5), "junk": bool(data.get("junk", True)),
            "autodelete": bool(data.get("autodelete")), "delete_threshold": num("delete_threshold", 1, 50, 12),
            "allow": _clean_senders(data.get("allow")), "block": _clean_senders(data.get("block"))}
    if vals["autodelete"] and vals["delete_threshold"] <= vals["threshold"]:
        raise MailError("Auto-delete must start above the spam threshold, so borderline mail still reaches Junk")
    if owner == "global":
        s["spam"].update(vals)
        s["spam"]["greylist"] = bool(data.get("greylist"))
    else:
        a = _addr(owner)
        if data.get("reset"):
            s["spam"]["per_user"].pop(a, None)
        else:
            s["spam"]["per_user"][a] = vals
    save(s)
    apply(s)
    return {"ok": True}


def _rspamd_stats() -> dict:
    r = _run(["rspamc", "stat"], 10)
    out = {}
    for k, rx in (("scanned", r"Messages scanned: (\d+)"), ("spam", r"Messages with action add header: (\d+)"),
                  ("rejected", r"Messages with action reject: (\d+)"), ("ham", r"Messages with action no action: (\d+)"),
                  ("learned", r"Messages learned: (\d+)")):
        m = re.search(rx, r.stdout)
        out[k] = int(m.group(1)) if m else 0
    return out


# ----------------------------------------------------------------------------- mailing lists
def list_lists() -> dict:
    s = load()
    return {"lists": [{"address": k, **{x: y for x, y in v.items() if x != "members"}, "member_count": len(v.get("members", [])),
                       "members": v.get("members", [])} for k, v in sorted(s["lists"].items())],
            "domains": sorted(s["domains"]), "candidates": candidate_domains()}


def save_list(address: str, data: dict, create: bool = False) -> dict:
    _require()
    s = load()
    a = _addr(address)
    if create and (a in s["lists"] or a in s["accounts"] or a in s["forwarders"]):
        raise MailError(f"{a} is already in use")
    if not create and a not in s["lists"]:
        raise MailError("No such list")
    _ensure_domain(s, a.split("@")[1])
    members = []
    for m in data.get("members") or []:
        m = str(m).strip()
        if m:
            m = _ext_addr(m)
            if m.lower() == a:
                raise MailError("A list can't be a member of itself")
            if m.lower() not in [x.lower() for x in members]:
                members.append(m)
    owners = [_ext_addr(o) for o in (data.get("owners") or []) if str(o).strip()]
    access = data.get("access", "members")
    if access not in ("public", "members", "announce"):
        raise MailError("Unknown access type")
    if access == "announce" and not owners:
        raise MailError("An announcement list needs at least one owner who may post")
    s["lists"][a] = {"description": _line(data.get("description"), 200), "access": access, "members": members[:5000],
                     "owners": owners[:50], "prefix": bool(data.get("prefix", True)), "reply_to_list": bool(data.get("reply_to_list", True)),
                     "munge_from": bool(data.get("munge_from", True)), "created": s["lists"].get(a, {}).get("created", int(time.time()))}
    save(s)
    apply(s)
    return {"ok": True}


def delete_list(address: str) -> dict:
    s = load()
    s["lists"].pop(_addr(address), None)
    save(s)
    apply(s)
    return {"ok": True}


# ----------------------------------------------------------------------------- rendering
def render_postfix(s: dict) -> dict[str, str]:
    """name -> table text, for the hash: maps in PF_DIR."""
    local, relay = [], []
    for d, dom in sorted(s["domains"].items()):
        r = _effective_routing(d, dom) if dom.get("routing") == "auto" else dom.get("routing", "local")
        (relay if r == "backup" else local if r == "local" else []).append(d)
    mailboxes, aliases, recip, sasl, transport, login = [], [], [], [], [], {}
    for a, acc in sorted(s["accounts"].items()):
        if a.split("@")[1] not in local:
            continue
        u, d = a.split("@")
        mailboxes.append(f"{a} {d}/{u}/")
        login.setdefault(a, set()).add(a)
        if acc.get("suspend", {}).get("incoming"):
            recip.append(f"{a} REJECT This mailbox is not accepting mail right now")
        if acc.get("suspend", {}).get("outgoing"):
            sasl.append(f"{a} REJECT Sending is suspended for this account")
    for a in sorted(s["lists"]):
        if a.split("@")[1] in local:
            mailboxes.append(f"{a} lists/{a}/")
            transport.append(f"{a} auroralist:")
    for src, f in sorted(s["forwarders"].items()):
        d = src.split("@")[1]
        if d not in local:
            continue
        if f["type"] == "forward":
            dest = list(f["dest"])
            if src in s["accounts"]:
                dest = [src, *dest]  # keep a copy in the mailbox
            aliases.append(f"{src} {', '.join(dest)}")
            for t in f["dest"]:
                if t.lower() in s["accounts"]:
                    login.setdefault(src, set()).add(t.lower())
        elif f["type"] == "fail":
            recip.append(f"{src} REJECT {f.get('message') or 'No such person at this address'}")
        elif f["type"] == "discard":
            aliases.append(f"{src} discard@discard.aurora.invalid")
    # Every real address maps to itself, so a catch-all never swallows it.
    fw = {k for k, v in s["forwarders"].items() if v["type"] == "forward"}
    for a in sorted(set(s["accounts"]) | set(s["lists"])):
        if a.split("@")[1] in local and a not in fw:
            aliases.append(f"{a} {a}")
    for d in local:
        if d in s["domain_forwarders"]:
            aliases.append(f"@{d} @{s['domain_forwarders'][d]}")
            continue
        ca = s["domains"][d].get("catchall", {})
        if ca.get("mode") == "forward":
            aliases.append(f"@{d} {', '.join(ca['target'].split(','))}")
        elif ca.get("mode") == "discard":
            aliases.append(f"@{d} discard@discard.aurora.invalid")
        else:
            msg = _line(ca.get("message") or "No such user here", 200)
            # Known addresses pass; anything else on the domain gets this answer at SMTP time.
            known = {m.split()[0] for m in mailboxes} | {x.split()[0] for x in aliases if not x.startswith("@")} | \
                    {r.split()[0] for r in recip}
            recip += [f"{k} DUNNO" for k in sorted(known) if k.endswith("@" + d) and not any(r.startswith(k + " ") for r in recip)]
            recip.append(f"{d} REJECT {msg}")
    transport += [f"{d} lmtp:unix:private/dovecot-lmtp" for d in local if is_local(d)]
    transport.append("discard.aurora.invalid discard:")
    logins = [f"{k} {', '.join(sorted(v))}" for k, v in sorted(login.items())]
    return {"domains": "\n".join(f"{d} OK" for d in local), "relay_domains": "\n".join(f"{d} OK" for d in relay),
            "mailboxes": "\n".join(mailboxes), "aliases": "\n".join(aliases), "recipient_access": "\n".join(recip),
            "sasl_access": "\n".join(sasl), "transport": "\n".join(transport), "sender_login": "\n".join(logins)}


def render_dovecot_users(s: dict) -> str:
    lines = []
    for a, acc in sorted(s["accounts"].items()):
        extra = []
        if acc.get("quota_mb"):
            extra.append(f"userdb_quota_storage_size={int(acc['quota_mb'])}M")
        if acc.get("suspend", {}).get("login"):
            extra.append("nologin=y")
            extra.append("reason=This account is suspended")
        lines.append(f"{a}:{acc['hash']}::::::{' '.join(extra)}")
    return "\n".join(lines) + ("\n" if lines else "")


def render_rspamd(s: dict) -> dict[str, str]:
    sp = s["spam"]
    allow = [x for x in sp.get("allow", [])]
    block = [x for x in sp.get("block", [])]
    return {
        "local.d/milter_headers.conf": HEADER + """use = ["x-spamd-bar", "x-spam-level", "x-spam-status", "authentication-results", "x-spamd-result"];
extended_spam_headers = true;
skip_local = false;
skip_authenticated = true;
routines {
  x-spam-level { header = "X-Spam-Level"; char = "*"; remove = 1; }
  x-spam-status { header = "X-Spam-Status"; remove = 1; }
}
""",
        "local.d/actions.conf": HEADER + f"""reject = 15;
add_header = {max(1, int(sp['threshold']))};
greylist = {max(1, int(sp['threshold']) - 1) if sp.get('greylist') else 'null'};
""",
        "local.d/greylist.conf": HEADER + f"enabled = {'true' if sp.get('greylist') else 'false'};\n",
        "local.d/redis.conf": HEADER + 'servers = "127.0.0.1";\n',
        "local.d/dkim_signing.conf": HEADER + f"""enabled = true;
path = "{DKIM_DIR}/$domain.$selector.key";
selector = "{SELECTOR}";
sign_authenticated = true;
sign_local = true;
use_esld = false;
allow_username_mismatch = true;
try_fallback = true;
""",
        "local.d/multimap.conf": HEADER + f"""AURORA_ALLOW_ADDR {{ type = "from"; filter = "email:addr"; map = "{RSPAMD_MAPS}/allow_addr.map"; score = -20.0; description = "Sender on the panel's allow list"; }}
AURORA_ALLOW_DOMAIN {{ type = "from"; filter = "email:domain"; map = "{RSPAMD_MAPS}/allow_domain.map"; score = -15.0; description = "Domain on the panel's allow list"; }}
AURORA_BLOCK_ADDR {{ type = "from"; filter = "email:addr"; map = "{RSPAMD_MAPS}/block_addr.map"; score = 30.0; description = "Sender on the panel's block list"; }}
AURORA_BLOCK_DOMAIN {{ type = "from"; filter = "email:domain"; map = "{RSPAMD_MAPS}/block_domain.map"; score = 30.0; description = "Domain on the panel's block list"; }}
""",
        "aurora/allow_addr.map": "\n".join(x for x in allow if "@" in x) + "\n",
        "aurora/allow_domain.map": "\n".join(x for x in allow if "@" not in x) + "\n",
        "aurora/block_addr.map": "\n".join(x for x in block if "@" in x) + "\n",
        "aurora/block_domain.map": "\n".join(x for x in block if "@" not in x) + "\n",
    }


def render_lists(s: dict) -> str:
    return json.dumps({k: v for k, v in s["lists"].items()}, indent=1)


def apply(s: dict | None = None) -> dict:
    """Render the state into every generated file and reload what changed."""
    s = s or load()
    if not configured():
        return {"ok": False}
    changed = set()
    if s.get("config_rev") != CONFIG_REV:
        _upgrade_config(s)
        changed.add("postfix-maps")
    # Mail to postmaster@<this host name> (bounce notices, cron) is delivered here, not looped back out —
    # unless the host name is itself one of the mail domains (Postfix forbids listing it in both places).
    want = "localhost" if hostname(s) in s["domains"] else "$myhostname, localhost"
    if _run(["postconf", "-h", "mydestination"]).stdout.strip() != want:
        _run(["postconf", "-e", f"mydestination={want}"])
        changed.add("postfix-maps")
    for name, text in render_postfix(s).items():
        p = PF_DIR / name
        if _write(p, HEADER + text + "\n", 0o640, "root", "postfix") or not Path(str(p) + ".db").exists():
            r = _run(["postmap", f"hash:{p}"])
            if r.returncode != 0:
                raise MailError(f"postmap {name}: {r.stderr.strip()[-300:]}")
            changed.add("postfix-maps")
    if _write(DC_USERS, render_dovecot_users(s), 0o640, "root", "dovecot"):
        changed.add("dovecot-users")
    uid, gid = _vmail_ids()
    if _write(SIEVE_GLOBAL, render_global_sieve(s), 0o644):
        _run(["sievec", str(SIEVE_GLOBAL)])
    for a in s["accounts"]:
        home = _home(a)
        if not home.exists():
            home.mkdir(parents=True)
            for p in (home, home.parent):
                os.chown(p, uid, gid)
        sdir = home / "sieve"
        sdir.mkdir(exist_ok=True)
        os.chown(sdir, uid, gid)
        script = sdir / "aurora.sieve"
        if _write(script, render_user_sieve(s, a), 0o600):
            os.chown(script, uid, gid)
            r = _run(["sievec", str(script)])
            svbin = script.with_suffix(".svbin")
            if svbin.exists():
                os.chown(svbin, uid, gid)
            if r.returncode != 0:
                raise MailError(f"Sieve script for {a} didn't compile: {(r.stderr or r.stdout).strip()[-400:]}")
        active = home / ".dovecot.sieve"
        if not active.is_symlink():
            active.unlink(missing_ok=True)
            active.symlink_to("sieve/aurora.sieve")
            os.lchown(active, uid, gid)
    for name, text in render_rspamd(s).items():
        if _write(Path("/etc/rspamd") / name, text, 0o644):
            changed.add("rspamd-conf" if name.startswith("local.d") else "rspamd-maps")
    _write(LIST_CONF, render_lists(s), 0o640, "root", "vmail")
    sync_dav(s)
    if "postfix-maps" in changed:
        # Postfix notices changed tables only after one more request; reload so the change applies at once.
        _run(["postfix", "reload"], 30)
    if "dovecot-users" in changed:
        # passwd-file is re-read when its mtime changes; two edits in one second would look unchanged.
        _run(["doveadm", "reload"], 30)
    if "rspamd-conf" in changed:
        _run(["systemctl", "reload-or-restart", "rspamd"], 60)
    return {"ok": True, "changed": sorted(changed)}


# ----------------------------------------------------------------------------- setup / status
def _active(unit: str) -> bool:
    return _run(["systemctl", "is-active", "--quiet", unit], 10).returncode == 0


_routing_seen: dict[str, str] = {}


def _follow_dns() -> None:
    """Re-render when automatic settings would now come out differently (cheap: DNS is cached)."""
    try:
        maybe_autohost()
        s = load()
        now = {d: _effective_routing(d, v) for d, v in s["domains"].items() if v.get("routing", "auto") == "auto"}
        if _routing_seen and now != _routing_seen:
            apply(s)
        _routing_seen.clear()
        _routing_seen.update(now)
    except Exception:
        pass


def status() -> dict:
    inst = installed()
    if inst and configured():
        _follow_dns()
    s = load()
    st = {"supported": IS_LINUX, "installed": inst, "configured": inst and configured(), "hostname": hostname(s),
          "hostname_mode": s.get("hostname_mode", "auto"),
          "ip": _public_ip(), "domains": len(s["domains"]), "accounts": len(s["accounts"]),
          "forwarders": len(s["forwarders"]), "lists": len(s["lists"]),
          "services": {u: _active(u) for u in ("postfix", "dovecot", "rspamd", "redis-server")} if inst else {},
          "webmail": webmail_url(), "webmail_installed": webmail_installed(), "dav_installed": dav_installed()}
    if inst and configured():
        st["queue"] = len(_queue())
        st["detected"] = detect_hostname(s)
        st["local"] = local_status()
        st["tls"] = _tls_info(s)
        st["dovecot_version"] = _run(["dovecot", "--version"]).stdout.strip()
    return st


def dovecot_ok() -> tuple[bool, str]:
    """The generated configuration is Dovecot 2.4 syntax."""
    if shutil.which("dovecot", path=PATH):
        m = re.match(r"(\d+)\.(\d+)", _run(["dovecot", "--version"]).stdout.strip())
    else:
        m = re.search(r"Candidate:\s*(?:\d+:)?(\d+)\.(\d+)", _run(["apt-cache", "policy", "dovecot-core"]).stdout)
    if m and (int(m.group(1)), int(m.group(2))) < (2, 4):
        return False, (f"This system offers Dovecot {m.group(0)}; the panel's mail server needs Dovecot 2.4 or newer "
                       "(Debian 13 / Raspberry Pi OS trixie, Ubuntu 25.04 or newer).")
    return True, ""


def setup(log, host: str | None = None) -> dict:
    """One-time configuration after the packages are installed (also safe to re-run)."""
    s = load()
    if host:
        s["hostname_mode"] = "manual"
    elif s.get("hostname_mode", "auto") == "auto":
        det = detect_hostname(s)
        host = det["hostname"]
        log(f"• {det['reason']}")
    host = (host or s.get("hostname") or socket.getfqdn() or socket.gethostname()).lower()
    s["hostname"] = host
    save(s)
    log(f"• Mail server name: {host}")
    if _run(["id", "vmail"]).returncode != 0:
        _run(["useradd", "-r", "-u", "5000", "-U", "-d", str(VMAIL), "-s", "/usr/sbin/nologin", "vmail"])
        if _run(["id", "vmail"]).returncode != 0:
            _run(["useradd", "-r", "-U", "-d", str(VMAIL), "-s", "/usr/sbin/nologin", "vmail"])
    uid, gid = _vmail_ids()
    VMAIL.mkdir(parents=True, exist_ok=True)
    os.chown(VMAIL, uid, gid)
    os.chmod(VMAIL, 0o750)
    for d in (PF_DIR, SIEVE_DIR, RSPAMD_MAPS, LIB_DIR, LIST_CONF.parent, TLS_DIR):
        d.mkdir(parents=True, exist_ok=True)
    shutil.chown(LIST_CONF.parent, "root", "vmail")
    os.chmod(LIST_CONF.parent, 0o750)
    # TLS: a self-signed certificate until a real one is chosen under Encryption.
    crt, key = TLS_DIR / "mail.crt", TLS_DIR / "mail.key"
    if not crt.exists():
        from . import sslcerts
        sslcerts.write_self_signed(crt, key, [host], 3650)
        log("• Created a self-signed TLS certificate (replace it under Email → Encryption)")
    cert, keyf = _tls_paths(s)
    # Dovecot: our own complete configuration (the distro's conf.d is left in place, unused).
    if DC_CONF.exists() and not DC_CONF.read_text(errors="replace").startswith(HEADER):
        shutil.copy2(DC_CONF, DC_CONF.with_name("dovecot.conf.dist"))
    _write(DC_CONF, render_dovecot_conf(uid, cert, keyf), 0o644)
    DC_USERS.touch()
    shutil.chown(DC_USERS, "root", "dovecot")
    os.chmod(DC_USERS, 0o640)
    # Postfix
    log("• Configuring Postfix")
    for k, v in postfix_settings(host, cert, keyf).items():
        r = _run(["postconf", "-e", f"{k}={v}"])
        if r.returncode != 0:
            raise MailError(f"postconf {k}: {r.stderr.strip()}")
    for name, entry, params in postfix_services():
        _run(["postconf", "-M", f"{name}={entry}"])
        for p in params:
            _run(["postconf", "-P", f"{name}/{p}"])
    _write(Path("/etc/mailname"), host + "\n")
    _write_local_pcre()
    s["config_rev"] = CONFIG_REV
    save(s)
    # Mailing lists run as vmail through this script.
    _write(LIB_DIR / "list.py", (Path(__file__).parent / "mail_list.py").read_text(), 0o755)
    # Autoconfig for Thunderbird & co.
    _write(AUTOCONFIG_DIR / "config-v1.1.xml", AUTOCONFIG_XML.format(host=host), 0o644)
    _apache_autoconfig()
    # Rspamd: allow/block maps must exist before rspamd reads multimap.
    for n in ("allow_addr", "allow_domain", "block_addr", "block_domain"):
        (RSPAMD_MAPS / f"{n}.map").touch()
    DKIM_DIR.mkdir(parents=True, exist_ok=True)
    shutil.chown(DKIM_DIR, "_rspamd" if _user_exists("_rspamd") else "root", None)
    # Mail works from the first minute, domain or not: you@<hostname>.local for alerts,
    # apps and webmail on this server (unless it was turned off on purpose).
    if not s.get("local_off"):
        _ensure_domain(s, local_domain_name()).update(routing="local", routing_set=True, local=True)
        save(s)
        log(f"• Local mail is on: addresses like info@{local_domain_name()} work on this server")
    apply(s)
    log("• Starting services")
    for u in ("redis-server", "rspamd", "dovecot", "postfix"):
        _run(["systemctl", "enable", u], 60)
        r = _run(["systemctl", "restart", u], 120)
        log(f"  {u}: {'running' if r.returncode == 0 and _active(u) else 'FAILED — ' + _run(['systemctl', 'status', u, '--no-pager', '-n', '8']).stdout[-600:]}")
    _ufw_allow()
    try:
        from . import fail2ban
        if fail2ban._client() and fail2ban.LOCAL.exists():
            fail2ban.save(None, None)
            log("• Fail2ban now also guards SMTP and IMAP/POP3 logins")
    except Exception:
        pass
    for d in s["domains"]:
        ensure_dkim(d)
    return {"hostname": host}


def _user_exists(u: str) -> bool:
    try:
        pwd.getpwnam(u)
        return True
    except KeyError:
        return False


def _ufw_allow() -> None:
    if "Status: active" in _run(["ufw", "status"]).stdout:
        for p in MAIL_PORTS:
            _run(["ufw", "allow", p])


def _apache_autoconfig() -> None:
    conf = Path("/etc/apache2/conf-available/zz-aurora-mail.conf")
    if not Path("/etc/apache2").is_dir():
        return
    text = HEADER + f"""# Thunderbird, K-9 and Evolution find the server settings here by themselves.
Alias /.well-known/autoconfig/mail {AUTOCONFIG_DIR}
Alias /mail/config-v1.1.xml {AUTOCONFIG_DIR}/config-v1.1.xml
<Directory {AUTOCONFIG_DIR}>
    Require all granted
    Options None
</Directory>
"""
    if _write(conf, text):
        _run(["a2enconf", "-q", "zz-aurora-mail"])
        if _run(["apache2ctl", "configtest"]).returncode == 0:
            _run(["systemctl", "reload", "apache2"])


def render_dovecot_conf(uid: int, cert: str, key: str) -> str:
    return HEADER + f"""dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0

protocols = imap pop3 lmtp sieve
listen = *, ::
log_path = syslog
syslog_facility = mail
auth_mechanisms = plain login
auth_allow_cleartext = no
auth_failure_delay = 2 secs

mail_driver = maildir
mail_home = {VMAIL}/%{{user | domain}}/%{{user | username}}
mail_path = ~/Maildir
mail_uid = vmail
mail_gid = vmail
first_valid_uid = {uid}
last_valid_uid = {uid}
mail_privileged_group = mail

passdb passwd-file {{
  passwd_file_path = {DC_USERS}
  default_password_scheme = SHA512-CRYPT
}}
userdb passwd-file {{
  passwd_file_path = {DC_USERS}
}}

namespace inbox {{
  inbox = yes
  separator = /
  mailbox Drafts {{
    special_use = \\Drafts
    auto = subscribe
  }}
  mailbox Junk {{
    special_use = \\Junk
    auto = subscribe
  }}
  mailbox Trash {{
    special_use = \\Trash
    auto = subscribe
  }}
  mailbox Sent {{
    special_use = \\Sent
    auto = subscribe
  }}
  mailbox Archive {{
    special_use = \\Archive
    auto = subscribe
  }}
}}

ssl = yes
ssl_server_cert_file = {cert}
ssl_server_key_file = {key}
ssl_min_protocol = TLSv1.2

mail_plugins {{
  quota = yes
}}
quota "User quota" {{
  driver = count
}}
quota_exceeded_message = This mailbox is full.

protocol imap {{
  mail_plugins {{
    imap_quota = yes
  }}
}}
protocol lmtp {{
  mail_plugins {{
    sieve = yes
  }}
  auth_username_format = %{{user | lower}}
}}

sieve_script personal {{
  driver = file
  path = ~/sieve
  active_path = ~/.dovecot.sieve
}}
sieve_script aurora-global {{
  type = before
  driver = file
  path = {SIEVE_GLOBAL}
}}
sieve_extensions {{
  vacation-seconds = yes
  editheader = yes
}}

service lmtp {{
  unix_listener /var/spool/postfix/private/dovecot-lmtp {{
    mode = 0600
    user = postfix
    group = postfix
  }}
}}
service auth {{
  unix_listener /var/spool/postfix/private/auth {{
    mode = 0660
    user = postfix
    group = postfix
  }}
  unix_listener auth-userdb {{
    mode = 0660
    user = vmail
  }}
}}
service imap-login {{
  inet_listener imap {{
    port = 143
  }}
  inet_listener imaps {{
    port = 993
    ssl = yes
  }}
}}
service pop3-login {{
  inet_listener pop3 {{
    port = 110
  }}
  inet_listener pop3s {{
    port = 995
    ssl = yes
  }}
}}
service managesieve-login {{
  inet_listener sieve {{
    port = 4190
    listen = 127.0.0.1
  }}
}}
"""


def postfix_settings(host: str, cert: str, key: str) -> dict:
    m = f"hash:{PF_DIR}"
    return {
        "myhostname": host, "myorigin": "$myhostname", "mydestination": "localhost",
        "inet_interfaces": "all", "inet_protocols": "all", "recipient_delimiter": "+",
        "virtual_mailbox_domains": f"{m}/domains", "virtual_mailbox_maps": f"{m}/mailboxes",
        "virtual_alias_maps": f"{m}/aliases", "virtual_transport": "lmtp:unix:private/dovecot-lmtp",
        "transport_maps": f"{m}/transport, pcre:{LOCAL_PCRE}", "relay_domains": f"{m}/relay_domains",
        # [name.local] is looked up with the system resolver too, so other devices are found by mDNS.
        "smtp_host_lookup": "dns, native",
        "smtpd_sender_login_maps": f"{m}/sender_login",
        "smtpd_sasl_type": "dovecot", "smtpd_sasl_path": "private/auth", "smtpd_sasl_auth_enable": "no",
        "smtpd_tls_cert_file": cert, "smtpd_tls_key_file": key, "smtpd_tls_security_level": "may",
        "smtpd_tls_auth_only": "yes", "smtp_tls_security_level": "may", "smtpd_tls_loglevel": "1",
        "smtpd_tls_mandatory_protocols": "!SSLv2,!SSLv3,!TLSv1,!TLSv1.1", "smtpd_tls_protocols": "!SSLv2,!SSLv3,!TLSv1,!TLSv1.1",
        "smtpd_helo_required": "yes", "disable_vrfy_command": "yes", "strict_rfc821_envelopes": "yes",
        "smtpd_relay_restrictions": "permit_mynetworks,permit_sasl_authenticated,defer_unauth_destination",
        # Unknown/suspended local addresses get their own answer even from local programs, so it comes first.
        "smtpd_recipient_restrictions": f"check_recipient_access {m}/recipient_access,permit_mynetworks,"
                                        f"permit_sasl_authenticated,reject_unauth_destination,reject_unlisted_recipient",
        # master.cf -o values can't contain spaces, so the submission ports reference this.
        "aurora_submission_sender": f"reject_sender_login_mismatch,check_sasl_access {m}/sasl_access",
        "smtp_address_preference": "ipv4",
        "smtpd_milters": "inet:127.0.0.1:11332", "non_smtpd_milters": "inet:127.0.0.1:11332",
        "milter_default_action": "accept", "milter_protocol": "6",
        "milter_mail_macros": "i {mail_addr} {client_addr} {client_name} {auth_authen}",
        "message_size_limit": "52428800", "mailbox_size_limit": "0", "biff": "no",
        "append_dot_mydomain": "no", "smtputf8_enable": "yes",
        # Local programs (sendmail) often write UTF-8 headers; don't demand SMTPUTF8 for those — Dovecot's LMTP doesn't offer it.
        "smtputf8_autodetect_classes": "bounce",
        "auroralist_destination_recipient_limit": "1",
    }


def postfix_services() -> list[tuple[str, str, list[str]]]:
    m = f"hash:{PF_DIR}"
    sub = ["smtpd_tls_security_level=encrypt", "smtpd_sasl_auth_enable=yes", "smtpd_tls_auth_only=yes",
           "smtpd_client_restrictions=permit_sasl_authenticated,reject",
           "smtpd_sender_restrictions=$aurora_submission_sender",
           "smtpd_recipient_restrictions=permit_sasl_authenticated,reject",
           "smtpd_relay_restrictions=permit_sasl_authenticated,reject", "milter_macro_daemon_name=ORIGINATING"]
    return [
        ("submission/inet", "submission inet n - y - - smtpd", ["syslog_name=postfix/submission", *sub]),
        ("submissions/inet", "submissions inet n - y - - smtpd",
         ["syslog_name=postfix/submissions", "smtpd_tls_wrappermode=yes", *sub]),
        ("auroralist/unix", f"auroralist unix - n n - - pipe flags=Rq user=vmail argv=/usr/bin/python3 {LIB_DIR}/list.py ${{recipient}} ${{sender}}", []),
    ]


# ----------------------------------------------------------------------------- TLS
def _tls_paths(s: dict) -> tuple[str, str]:
    src = s.get("tls", {}).get("source", "self")
    if src != "self":
        live = Path("/etc/letsencrypt/live") / src
        if (live / "fullchain.pem").exists():
            return str(live / "fullchain.pem"), str(live / "privkey.pem")
    return str(TLS_DIR / "mail.crt"), str(TLS_DIR / "mail.key")


def _tls_info(s: dict) -> dict:
    from . import sslcerts
    cert, _ = _tls_paths(s)
    info = sslcerts.describe_cert(Path(cert)) or {}
    le = sorted(p.name for p in Path("/etc/letsencrypt/live").glob("*") if (p / "fullchain.pem").exists()) \
        if Path("/etc/letsencrypt/live").is_dir() else []
    return {"source": s.get("tls", {}).get("source", "self"), "cert": info, "letsencrypt": le,
            "covers_host": sslcerts.covers_host(Path(cert), hostname(s)) if Path(cert).exists() else False}


def get_tls() -> dict:
    s = load()
    return {**_tls_info(s), "hostname": hostname(s), "certbot": bool(shutil.which("certbot", path=PATH)),
            "ports": _port_report()}


def set_tls(source: str) -> dict:
    s = load()
    if source != "self" and not (Path("/etc/letsencrypt/live") / source / "fullchain.pem").exists():
        raise MailError("Unknown certificate")
    s["tls"] = {"source": source}
    save(s)
    cert, key = _tls_paths(s)
    _run(["postconf", "-e", f"smtpd_tls_cert_file={cert}", f"smtpd_tls_key_file={key}"])
    _write(DC_CONF, render_dovecot_conf(_vmail_ids()[0], cert, key), 0o644)
    hook = Path("/etc/letsencrypt/renewal-hooks/deploy/aurora-mail")
    if source != "self":
        _write(hook, "#!/bin/sh\n# Written by AuroraPanel (Email): reload mail with renewed certificates.\n"
                     "systemctl reload postfix dovecot\nsystemctl reload apache2 2>/dev/null || true\n", 0o755)
    _apache_mailhost(hostname(s), cert, key if source != "self" else "")
    _run(["systemctl", "reload", "postfix"])
    _run(["systemctl", "restart", "dovecot"])
    return {"ok": True}


MAILHOST_SITE = Path("/etc/apache2/sites-available/aurora-mailhost.conf")


def _apache_mailhost(host: str, cert: str, key: str) -> None:
    """HTTPS for the mail host name in Apache, with the mail server's trusted certificate, so webmail,
    calendars, autoconfig and Dynamic DNS updates at https://<mail host>/ don't show a certificate warning.
    Without a real certificate (key == "") the site is removed and Apache's default answers instead."""
    if not Path("/etc/apache2/sites-available").is_dir():
        return
    if not key:
        if MAILHOST_SITE.exists():
            _run(["a2dissite", "-q", "aurora-mailhost"])
            MAILHOST_SITE.unlink()
            if _run(["apache2ctl", "configtest"]).returncode == 0:
                _run(["systemctl", "reload", "apache2"])
        return
    text = HEADER + f"""# The mail host name over HTTPS: webmail (/webmail), calendars (/dav), autoconfig.
<VirtualHost *:443>
    ServerName {host}
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile {cert}
    SSLCertificateKeyFile {key}
    ErrorLog ${{APACHE_LOG_DIR}}/{host}-error.log
    CustomLog ${{APACHE_LOG_DIR}}/{host}-access.log combined
</VirtualHost>
"""
    old = MAILHOST_SITE.read_text() if MAILHOST_SITE.exists() else None
    if old == text:
        return
    _write(MAILHOST_SITE, text, 0o644)
    _run(["a2enmod", "-q", "ssl"])
    _run(["a2ensite", "-q", "aurora-mailhost"])
    if _run(["apache2ctl", "configtest"]).returncode != 0:
        if old is None:
            _run(["a2dissite", "-q", "aurora-mailhost"])
            MAILHOST_SITE.unlink()
        else:
            _write(MAILHOST_SITE, old, 0o644)
        return
    _run(["systemctl", "reload", "apache2"])


def issue_cert() -> jobs.Job:
    """Let's Encrypt for the mail host name (via Apache, which must answer for it on port 80)."""
    s = load()
    host = hostname(s)
    if not shutil.which("certbot", path=PATH):
        raise MailError("Certbot isn't installed")

    def fn(log):
        log.progress(10, f"Requesting a certificate for {host}")
        args = ["certbot", "certonly", "--non-interactive", "--agree-tos", "--register-unsafely-without-email",
                "--keep-until-expiring", "-d", host]
        args += ["--apache"] if shutil.which("apache2ctl", path=PATH) else ["--standalone"]
        r = _run(args, 300)
        for line in (r.stdout + r.stderr).splitlines()[-20:]:
            log(line)
        if r.returncode != 0:
            raise MailError(f"Let's Encrypt refused: make sure {host} points to this server and port 80 is open")
        log.progress(85, "Switching the mail server to it")
        set_tls(host)
        return {"ok": True}

    return jobs.launch_fn(f"certificate for {host}", fn, meta={"mail": "tls"})


def detect_hostname(s: dict | None = None) -> dict:
    """The best name for this mail server, from what DNS says right now:
    1. the IP's reverse name (PTR), when it's a name on one of our domains and points back here;
    2. mail.<domain> (or <domain>) of a mail domain whose DNS points here — MX-target domains first;
    3. the IP's reverse name, if it points back here (a provider default, still consistent);
    4. the machine's own name."""
    s = s or load()
    ip = _public_ip()
    ptr = _ptr(ip)
    here = lambda h: bool(ip and ip in _a(h))
    doms = sorted((d for d in s["domains"] if not is_local(d)), key=lambda d: (not any(_is_me(h) for _, h in _mx(d)), d))
    if ptr and here(ptr) and any(ptr == d or ptr.endswith("." + d) for d in doms):
        return {"hostname": ptr, "reason": "It's the reverse DNS name of this server's IP and points back here — ideal.", "ptr": ptr, "ip": ip, "ptr_ok": True}
    for d in doms:
        for h in (f"mail.{d}", d):
            if here(h):
                return {"hostname": h, "reason": f"{h} points to this server." + (
                    "" if ptr == h else f" Ask your provider to set the IP's reverse DNS (PTR) to {h} — it's “{ptr or 'missing'}” now."),
                    "ptr": ptr, "ip": ip, "ptr_ok": ptr == h}
    if ptr and here(ptr):
        return {"hostname": ptr, "reason": "The reverse DNS name of this server's IP (none of your domains points here yet).", "ptr": ptr, "ip": ip, "ptr_ok": True}
    fq = (socket.getfqdn() or socket.gethostname()).lower()
    return {"hostname": fq, "reason": "This machine's own name — no DNS name points to it yet.", "ptr": ptr, "ip": ip, "ptr_ok": ptr == fq}


_auto_checked = [0.0]


def maybe_autohost(force: bool = False) -> str | None:
    """In automatic mode, follow DNS: switch the server name when a better one appears."""
    s = load()
    if s.get("hostname_mode", "auto") != "auto" or not configured():
        return None
    if not force and time.time() - _auto_checked[0] < 600:
        return None
    _auto_checked[0] = time.time()
    best = detect_hostname(s)["hostname"]
    if best and best != hostname(s) and _DOMAIN.match(best):
        _apply_hostname(best)
        return best
    return None


def set_hostname(host: str) -> dict:
    """A name, or "auto" to let the panel pick (and keep following) the best one."""
    s = load()
    if (host or "").strip().lower() == "auto":
        s["hostname_mode"] = "auto"
        save(s)
        _apply_hostname(detect_hostname(s)["hostname"])
        return {"ok": True, "hostname": hostname(), "mode": "auto"}
    host = _domain(host)
    s["hostname_mode"] = "manual"
    save(s)
    _apply_hostname(host)
    return {"ok": True, "hostname": host, "mode": "manual"}


def _apply_hostname(host: str) -> dict:
    s = load()
    s["hostname"] = host
    save(s)
    _run(["postconf", "-e", f"myhostname={host}"])
    _write(Path("/etc/mailname"), host + "\n")
    _write(AUTOCONFIG_DIR / "config-v1.1.xml", AUTOCONFIG_XML.format(host=host), 0o644)
    if (Path("/etc/letsencrypt/live") / host / "fullchain.pem").exists():
        set_tls(host)  # a real certificate for the new name already exists: use it
    elif s.get("tls", {}).get("source", "self") == "self":
        from . import sslcerts
        sslcerts.write_self_signed(TLS_DIR / "mail.crt", TLS_DIR / "mail.key", [host], 3650)
        _run(["systemctl", "restart", "dovecot"])
    _run(["systemctl", "reload", "postfix"])
    return {"ok": True}


def _port_report() -> list[dict]:
    want = [(25, "SMTP (incoming mail)"), (465, "SMTPS (sending, TLS)"), (587, "Submission (sending, STARTTLS)"),
            (993, "IMAPS"), (995, "POP3S"), (143, "IMAP (STARTTLS)"), (110, "POP3 (STARTTLS)")]
    out = _run(["ss", "-Hltn"]).stdout
    listening = {int(m) for m in re.findall(r":(\d+)\s", out)}
    return [{"port": p, "label": l, "listening": p in listening} for p, l in want]


# ----------------------------------------------------------------------------- DKIM & deliverability
def _dkim_key(d: str) -> Path:
    return DKIM_DIR / f"{d}.{SELECTOR}.key"


def ensure_dkim(d: str) -> str | None:
    """Create the domain's DKIM key once; return the DNS TXT value."""
    if not IS_LINUX or not shutil.which("openssl", path=PATH) or is_local(d):
        return None
    key = _dkim_key(d)
    if not key.exists():
        DKIM_DIR.mkdir(parents=True, exist_ok=True)
        r = _run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)])
        if r.returncode != 0:
            return None
        os.chmod(key, 0o640)
        shutil.chown(key, "root", "_rspamd" if _user_exists("_rspamd") else None)
    return dkim_record(d)


def dkim_record(d: str) -> str | None:
    key = _dkim_key(d)
    if not key.exists():
        return None
    import base64
    try:
        r = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"], capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or not r.stdout:
        return None
    return f"v=DKIM1; k=rsa; p={base64.b64encode(r.stdout).decode()}"


def _resolver():
    import dns.resolver
    r = dns.resolver.Resolver()
    r.lifetime = 6
    return r


def _txt(name: str) -> list[str]:
    try:
        return ["".join(p.decode(errors="replace") for p in rr.strings) for rr in _resolver().resolve(name, "TXT")]
    except Exception:
        return []


_dns_cache: dict[tuple, tuple[float, list]] = {}


def _cached(key: tuple, fn, ttl: int = 300) -> list:
    hit = _dns_cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    val = fn()
    _dns_cache[key] = (time.time(), val)
    return val


def _mx(d: str) -> list[tuple[int, str]]:
    def look():
        try:
            return sorted((rr.preference, str(rr.exchange).rstrip(".").lower()) for rr in _resolver().resolve(d, "MX"))
        except Exception:
            return []
    return _cached(("mx", d), look)


def _a(name: str) -> list[str]:
    def look():
        out = []
        for t in ("A", "AAAA"):
            try:
                out += [str(rr) for rr in _resolver().resolve(name, t)]
            except Exception:
                pass
        return out
    return _cached(("a", name), look, 120)


def _ptr(ip: str) -> str:
    def look():
        try:
            import dns.reversename
            return [str(_resolver().resolve(dns.reversename.from_address(ip), "PTR")[0]).rstrip(".").lower()]
        except Exception:
            return [""]
    return _cached(("ptr", ip), look, 600)[0] if ip else ""


def _ns(d: str) -> list[str]:
    try:
        return sorted(str(rr).rstrip(".").lower() for rr in _resolver().resolve(d, "NS"))
    except Exception:
        return []


_ip_cache: tuple[float, str] = (0.0, "")


def _public_ip() -> str:
    global _ip_cache
    if time.time() - _ip_cache[0] < 600 and _ip_cache[1]:
        return _ip_cache[1]
    ip = ""
    r = _run(["ip", "-4", "route", "get", "1.1.1.1"])
    m = re.search(r"src (\S+)", r.stdout)
    if m:
        ip = m.group(1)
    if not ip or ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "127.")):
        try:
            import urllib.request
            ip = urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode().strip() or ip
        except Exception:
            pass
    _ip_cache = (time.time(), ip)
    return ip


def _my_names() -> set[str]:
    s = load()
    names = {hostname(s), socket.gethostname().lower()}
    ip = _public_ip()
    return {n for n in names if n} | ({ip} if ip else set())


def _spf_allows(d: str, ip: str, depth: int = 0) -> tuple[bool | None, str]:
    """(True/False/None, record): does the domain's SPF allow this IP? None = no SPF."""
    recs = [t for t in _txt(d) if t.lower().startswith("v=spf1")]
    if not recs:
        return None, ""
    rec = recs[0]
    if depth > 5:
        return False, rec
    import ipaddress
    try:
        me = ipaddress.ip_address(ip)
    except ValueError:
        return False, rec
    for term in rec.split()[1:]:
        q = term[0] if term[0] in "+-~?" else "+"
        t = term.lstrip("+-~?").lower()
        hit = False
        if t.startswith(("ip4:", "ip6:")):
            try:
                hit = me in ipaddress.ip_network(t[4:], strict=False)
            except ValueError:
                pass
        elif t == "a" or t.startswith("a:"):
            hit = ip in _a(t[2:] if t.startswith("a:") else d)
        elif t == "mx" or t.startswith("mx:"):
            hit = any(ip in _a(h) for _, h in _mx(t[3:] if t.startswith("mx:") else d))
        elif t.startswith("include:"):
            ok, _ = _spf_allows(t[8:], ip, depth + 1)
            hit = bool(ok)
        elif t == "all":
            return q == "+", rec
        if hit:
            return q == "+", rec
    return False, rec


def _suggest_spf(d: str, current: str, ip: str) -> str:
    v = "ip6" if ":" in ip else "ip4"
    if not current:
        return f"v=spf1 +a +mx +{v}:{ip} ~all"
    parts = current.split()
    if f"{v}:{ip}" in current or f"+{v}:{ip}" in current:
        return current
    tail = parts[-1] if parts[-1].lstrip("+-~?").lower() == "all" else "~all"
    body = [p for p in parts[1:] if p.lstrip("+-~?").lower() != "all"]
    return " ".join(["v=spf1", *body, f"+{v}:{ip}", tail])


def deliverability(d: str) -> dict:
    d = _domain(d)
    s = load()
    if is_local(d):
        return {"domain": d, "local": True, "checks": {}, "nameservers": [], "zone_here": False, "authoritative": False,
                "score": 0, "total": 0, "hostname": hostname(s), "ip": _public_ip()}
    ip = _public_ip()
    host = hostname(s)
    mx = _mx(d)
    ns = _ns(d)
    mine = _my_names()
    checks = {}
    # MX
    ours = [h for _, h in mx if h in mine or ip in _a(h)]
    checks["mx"] = {"ok": bool(ours) or s["domains"].get(d, {}).get("routing") == "remote", "records": mx,
                    "suggest": {"type": "MX", "name": d + ".", "value": f"10 {host}."},
                    "note": "" if ours else f"Mail for {d} doesn't come to this server yet."}
    # SPF
    ok, rec = _spf_allows(d, ip) if ip else (None, "")
    checks["spf"] = {"ok": bool(ok), "current": rec, "suggest": {"type": "TXT", "name": d + ".", "value": _suggest_spf(d, rec, ip)},
                     "note": "No SPF record." if ok is None else "" if ok else f"SPF doesn't allow this server ({ip})."}
    # DKIM
    want = ensure_dkim(d) if s["domains"].get(d) is not None else dkim_record(d)
    cur = _txt(f"{SELECTOR}._domainkey.{d}")
    norm = lambda t: re.sub(r"\s+", "", t or "")
    dk_ok = bool(want) and any(norm(want).split("p=")[-1] == norm(c).split("p=")[-1] for c in cur)
    checks["dkim"] = {"ok": dk_ok, "current": cur[0] if cur else "", "suggest": {"type": "TXT", "name": f"{SELECTOR}._domainkey.{d}.", "value": want or ""},
                      "note": "" if dk_ok else ("No DKIM record for this server's key." if not cur else "The DKIM record doesn't match this server's key.")}
    # DMARC
    dm = [t for t in _txt(f"_dmarc.{d}") if t.lower().startswith("v=dmarc1")]
    checks["dmarc"] = {"ok": bool(dm), "current": dm[0] if dm else "",
                       "suggest": {"type": "TXT", "name": f"_dmarc.{d}.", "value": f"v=DMARC1; p=quarantine; adkim=r; aspf=r; rua=mailto:postmaster@{d}"},
                       "note": "" if dm else "No DMARC policy — big providers increasingly require one."}
    # PTR / HELO
    ptr = ""
    try:
        import dns.reversename
        ptr = str(_resolver().resolve(dns.reversename.from_address(ip), "PTR")[0]).rstrip(".").lower() if ip else ""
    except Exception:
        pass
    fwd = ip in _a(ptr) if ptr else False
    checks["ptr"] = {"ok": bool(ptr) and fwd and ptr == host, "current": ptr, "hostname": host, "ip": ip,
                     "note": ("" if ptr == host and fwd else
                              f"The reverse DNS of {ip} is “{ptr or 'missing'}”; it should be {host} (set it at your hosting provider), "
                              f"and {host} must point back to {ip}.")}
    # Who serves DNS for the domain: can we install the records ourselves?
    zone = False
    try:
        from . import dnszones
        zone = dnszones._path(d).exists()
    except Exception:
        pass
    authoritative = any(n in mine or ip in _a(n) for n in ns)
    return {"domain": d, "checks": checks, "nameservers": ns, "zone_here": zone, "authoritative": authoritative,
            "score": sum(1 for c in checks.values() if c["ok"]), "total": len(checks), "hostname": host, "ip": ip}


def deliverability_all() -> dict:
    s = load()
    out = []
    for d in sorted(s["domains"]):
        if is_ip_name(d):  # made before this was refused: say why its addresses don't work
            out.append({"domain": d, "error": IP_DOMAIN_HINT.format(local=local_domain_name())})
            continue
        try:
            r = deliverability(d)
            out.append({"domain": d, "score": r["score"], "total": r["total"], "local": r.get("local", False),
                        "problems": [k.upper() for k, v in r["checks"].items() if not v["ok"]]})
        except Exception as e:
            out.append({"domain": d, "error": str(e)})
    return {"domains": out}


def install_record(d: str, kind: str) -> dict:
    """Write the suggested record into this server's DNS zone for the domain."""
    from . import dnszones
    d = _domain(d)
    rep = deliverability(d)
    c = rep["checks"].get(kind)
    if not c or kind == "ptr":
        raise MailError("That record can't be installed here")
    if not rep["zone_here"]:
        raise MailError(f"There's no DNS zone for {d} on this server — add the record at your DNS provider instead")
    sug = c["suggest"]
    name = sug["name"].rstrip(".")
    recs = dnszones.get_zone(d).get("records", [])
    # Replace the old record of the same kind instead of adding a second one.
    marker = {"spf": "v=spf1", "dmarc": "v=dmarc1", "dkim": "v=dkim1"}.get(kind)
    for i in reversed(range(len(recs))):
        r = recs[i]
        if r.get("name", "").rstrip(".") != name or r.get("type") != sug["type"]:
            continue
        if kind == "mx" or (marker and marker in str(r.get("text", "")).lower()):
            dnszones.delete_record(d, i)
    if sug["type"] == "MX":
        pr, host = sug["value"].split()
        dnszones.add_record(d, {"name": name + ".", "type": "MX", "priority": int(pr), "target": host})
    else:
        dnszones.add_record(d, {"name": name + ".", "type": "TXT", "text": sug["value"]})
    return {"ok": True}


# ----------------------------------------------------------------------------- queue & tracking
def _queue() -> list[dict]:
    r = _run(["postqueue", "-j"], 30)
    out = []
    for line in r.stdout.splitlines():
        try:
            q = json.loads(line)
        except ValueError:
            continue
        out.append({"id": q.get("queue_id"), "queue": q.get("queue_name"), "arrival": q.get("arrival_time"),
                    "size": q.get("message_size"), "sender": q.get("sender"),
                    "recipients": [{"address": r.get("address"), "reason": r.get("delay_reason", "")} for r in q.get("recipients", [])]})
    return out


def queue() -> dict:
    return {"messages": _queue()}


def queue_action(action: str, ids: list[str] | None = None) -> dict:
    ids = [i for i in (ids or []) if re.match(r"^[0-9A-Za-z]{6,20}$", i)]
    if action == "flush":
        _run(["postqueue", "-f"])
    elif action == "delete" and ids:
        _run(["postsuper", "-d", "-"], input="\n".join(ids) + "\n")
    elif action == "delete_deferred":
        _run(["postsuper", "-d", "ALL", "deferred"])
    elif action == "requeue" and ids:
        _run(["postsuper", "-r", "-"], input="\n".join(ids) + "\n")
    else:
        raise MailError("Unknown queue action")
    return {"ok": True}


_LOG_RX = re.compile(r"^(\S+)\s+\S+\s+(postfix/[\w-]+)\[\d+\]:\s+(.*)$")


def track_settings() -> dict:
    t = load().get("track") or {}
    return {"days": int(t.get("days", 30)), "cleared": int(t.get("cleared", 0))}


def set_track_settings(days: int | None = None, clear: bool = False) -> dict:
    s = load()
    t = s.setdefault("track", {"days": 30, "cleared": 0})
    if days is not None:
        t["days"] = max(1, min(365, int(days)))
    if clear:
        t["cleared"] = int(time.time())
    save(s)
    return track_settings()


def track(recipient: str = "", status: str = "", hours: int = 168, limit: int = 500) -> dict:
    """Delivery events from the mail log: one row per recipient per message (or SMTP rejection).
    Only the last `days` (30 by default) are shown, and nothing from before “Clear history”."""
    cfg = track_settings()
    hours = min(int(hours), cfg["days"] * 24)
    since = f"-{max(1, min(24 * 365, hours))}h"
    r = _run(["journalctl", "SYSLOG_FACILITY=2", "--since", since, "-o", "short-iso", "--no-pager", "-q"], 60)
    text = r.stdout
    if not text.strip() and Path("/var/log/mail.log").exists():
        text = Path("/var/log/mail.log").read_text(errors="replace")[-8_000_000:]
    msgs: dict[str, dict] = {}
    rows = []
    for line in text.splitlines():
        m = _LOG_RX.match(line)
        if not m:
            continue
        ts, prog, rest = m.groups()
        if rest.startswith("NOQUEUE: reject:"):
            mm = re.search(r"RCPT from (\S+): (\d{3} [\d.]+ .*?); from=<([^>]*)> to=<([^>]*)>", rest)
            if mm:
                rows.append({"time": ts, "status": "rejected", "from": mm.group(3), "to": mm.group(4),
                             "result": mm.group(2)[:200], "client": mm.group(1), "id": ""})
            continue
        qm = re.match(r"([0-9A-F]{6,20}|[0-9A-Za-z]{10,20}): (.*)$", rest)
        if not qm:
            continue
        qid, info = qm.groups()
        mg = msgs.setdefault(qid, {"id": qid})
        if prog.endswith("smtpd") and "client=" in info:
            mg["client"] = re.sub(r"^client=", "", info.split(",")[0])
            mg.setdefault("first", ts)
            if "sasl_username=" in info:
                mg["user"] = info.split("sasl_username=")[1].split(",")[0]
        elif prog.endswith("cleanup") and "message-id=" in info:
            mg["message_id"] = info.split("message-id=", 1)[1].strip()
        elif prog.endswith("qmgr") and info.startswith("from=<"):
            mg["from"] = info[6:].split(">", 1)[0]
            mg.setdefault("first", ts)
        elif "to=<" in info and "status=" in info:
            to = info.split("to=<", 1)[1].split(">", 1)[0]
            st = re.search(r"status=(\w+)(?: \((.*)\))?", info)
            relay = re.search(r"relay=([^,]+)", info)
            delay = re.search(r"delay=([\d.]+)", info)
            rows.append({"time": ts, "id": qid, "status": st.group(1) if st else "?", "to": to,
                         "from": mg.get("from", ""), "result": (st.group(2) or "")[:300] if st else "",
                         "relay": relay.group(1) if relay else "", "delay": float(delay.group(1)) if delay else None,
                         "client": mg.get("client", ""), "user": mg.get("user", "")})
        elif prog.endswith("cleanup") and "milter-reject" in info:
            rows.append({"time": ts, "id": qid, "status": "rejected", "to": (re.search(r"to=<([^>]*)>", info) or [None, ""])[1],
                         "from": (re.search(r"from=<([^>]*)>", info) or [None, ""])[1], "result": info.split(":", 1)[-1][:200],
                         "client": mg.get("client", "")})
    if cfg["cleared"]:
        def after(r_):
            try:
                return datetime.fromisoformat(r_["time"]).timestamp() > cfg["cleared"]
            except (ValueError, TypeError):
                return True
        rows = [r_ for r_ in rows if after(r_)]
    scores = _spam_scores()
    for r_ in rows:
        if r_.get("id") in scores:
            r_["spam"] = scores[r_["id"]]
    want = recipient.strip().lower()
    if want:
        rows = [x for x in rows if want in (x.get("to") or "").lower() or want in (x.get("from") or "").lower()]
    if status:
        sts = set(status.split(","))
        rows = [x for x in rows if x["status"] in sts or ("failed" in sts and x["status"] in ("bounced", "rejected"))]
    rows.reverse()
    counts: dict[str, int] = {}
    for x in rows:
        counts[x["status"]] = counts.get(x["status"], 0) + 1
    return {"events": rows[:limit], "total": len(rows), "counts": counts, "settings": cfg}


def _spam_scores() -> dict[str, float]:
    p = Path("/var/log/rspamd/rspamd.log")
    if not p.exists():
        return {}
    out = {}
    try:
        with p.open("rb") as f:
            f.seek(max(0, p.stat().st_size - 4_000_000))
            data = f.read().decode(errors="replace")
    except OSError:
        return {}
    for m in re.finditer(r"qid: <([0-9A-Za-z]+)>.*?\[(-?[\d.]+)/[\d.]+\]", data):
        try:
            out[m.group(1)] = float(m.group(2))
        except ValueError:
            pass
    return out


# ----------------------------------------------------------------------------- disk usage
def disk_usage(address: str) -> dict:
    a = _addr(address)
    r = _run(["doveadm", "-f", "json", "mailbox", "status", "-u", a, "messages vsize", "*"], 60)
    try:
        boxes = json.loads(r.stdout or "[]")
    except ValueError:
        boxes = []
    out = [{"mailbox": b.get("mailbox"), "messages": int(b.get("messages") or 0), "size": int(b.get("vsize") or 0)} for b in boxes]
    return {"address": a, "mailboxes": sorted(out, key=lambda x: -x["size"]),
            "total": sum(x["size"] for x in out), "quota_mb": load()["accounts"].get(a, {}).get("quota_mb", 0)}


def disk_overview() -> dict:
    s = load()
    usage = _quota_usage()
    return {"accounts": [{"address": a, "used_bytes": usage.get(a, 0), "quota_mb": acc.get("quota_mb", 0)}
                         for a, acc in sorted(s["accounts"].items(), key=lambda kv: -usage.get(kv[0], 0))]}


def expunge(address: str, mailbox: str, older_days: int = 0) -> dict:
    a = _addr(address)
    if not _FOLDER.match(mailbox or "") and mailbox != "INBOX":
        raise MailError("Unknown mailbox")
    q = ["mailbox", mailbox] + (["savedbefore", f"{int(older_days)}d"] if int(older_days or 0) > 0 else ["all"])
    r = _run(["doveadm", "expunge", "-u", a, *q], 300)
    if r.returncode != 0:
        raise MailError(r.stderr.strip()[-300:] or "doveadm expunge failed")
    _run(["doveadm", "quota", "recalc", "-u", a], 120)
    return {"ok": True}


# ----------------------------------------------------------------------------- import / export
def import_csv(kind: str, text: str, dry_run: bool = True, default_domain: str = "", quota_mb: int = 1024) -> dict:
    """CSV rows → accounts (email[,password][,quota_mb]) or forwarders (source,destination)."""
    if kind not in ("accounts", "forwarders"):
        raise MailError("Choose accounts or forwarders")
    rows = list(csv.reader(io.StringIO(text.strip())))
    if rows and rows[0] and rows[0][0].strip().lower() in ("email", "address", "source", "account", "user", "username"):
        rows = rows[1:]
    s = load()
    out = []
    for i, row in enumerate(rows[:2000], 1):
        row = [c.strip() for c in row]
        if not row or not any(row):
            continue
        item = {"line": i, "ok": True, "error": ""}
        try:
            if kind == "accounts":
                addr = row[0] if "@" in row[0] else (f"{row[0]}@{default_domain}" if default_domain else row[0])
                a = _addr(addr)
                pw = row[1] if len(row) > 1 and row[1] else gen_password()
                q = int(row[2]) if len(row) > 2 and row[2].isdigit() else quota_mb
                if a in s["accounts"]:
                    raise MailError("already exists")
                item.update({"address": a, "password": pw, "quota_mb": q, "generated": not (len(row) > 1 and row[1])})
                if len(pw) < 8:
                    raise MailError("password shorter than 8 characters")
            else:
                if len(row) < 2:
                    raise MailError("needs source and destination")
                src = row[0] if "@" in row[0] else f"{row[0]}@{default_domain}"
                item.update({"source": _addr(src), "dest": ",".join(_ext_addr(x) for x in re.split(r"[;|\s]+", row[1]) if x)})
        except (MailError, ValueError) as e:
            item.update({"ok": False, "error": str(e)})
        out.append(item)
    if not dry_run:
        for it in out:
            if not it["ok"]:
                continue
            try:
                if kind == "accounts":
                    create_account(it["address"], it["password"], it["quota_mb"])
                else:
                    add_forwarder(it["source"], "forward", it["dest"])
                it["done"] = True
            except MailError as e:
                it.update({"ok": False, "error": str(e)})
    return {"rows": out, "valid": sum(1 for x in out if x["ok"]), "invalid": sum(1 for x in out if not x["ok"]), "dry_run": dry_run}


def export_csv(kind: str) -> str:
    s = load()
    buf = io.StringIO()
    w = csv.writer(buf)
    if kind == "accounts":
        w.writerow(["email", "quota_mb", "name", "suspended_login", "suspended_incoming", "suspended_outgoing"])
        for a, acc in sorted(s["accounts"].items()):
            sp = acc.get("suspend", {})
            w.writerow([a, acc.get("quota_mb", 0), acc.get("name", ""), sp.get("login", False), sp.get("incoming", False), sp.get("outgoing", False)])
    else:
        w.writerow(["source", "destination"])
        for k, v in sorted(s["forwarders"].items()):
            w.writerow([k, ";".join(v.get("dest", [])) or f":{v['type']}:"])
    return buf.getvalue()


# ----------------------------------------------------------------------------- webmail (Roundcube)
WEBMAIL_CONF = Path("/etc/apache2/conf-available/zz-aurora-webmail.conf")
RC_CONF = Path("/etc/roundcube/config.inc.php")


def webmail_installed() -> bool:
    return RC_CONF.exists() and WEBMAIL_CONF.exists()


def webmail_url() -> str:
    return "/webmail/" if webmail_installed() else ""


RC_BOOTSTRAP = Path("/usr/share/roundcube/program/lib/Roundcube/bootstrap.php")


def _patch_roundcube() -> str | None:
    """Roundcube 1.6.11 declares array_first(), which PHP 8.5 now has built in — a fatal error.
    Guard it the way newer Roundcube releases do (a fixed package update simply replaces the file)."""
    try:
        t = RC_BOOTSTRAP.read_text(encoding="utf-8")
    except OSError:
        return None
    changed = False
    for fn in ("array_first", "array_last"):
        m = re.search(rf"(?m)^function {fn}\(\$array\)\n\{{\n.*?^\}}\n", t, re.S)
        if m and f"function_exists('{fn}')" not in t:
            t = t[:m.start()] + f"if (!function_exists('{fn}')) {{\n{m.group(0)}}}\n" + t[m.end():]
            changed = True
    if changed:
        RC_BOOTSTRAP.write_text(t, encoding="utf-8")
        return "• Patched Roundcube for PHP 8.5 (array_first is now built into PHP)"
    return None


def setup_webmail() -> list[str]:
    """Point Roundcube at this server's IMAP/SMTP and publish it at /webmail on every site."""
    if not RC_CONF.exists():
        raise MailError("Roundcube isn't installed")
    fix = _patch_roundcube()
    cur = RC_CONF.read_text(errors="replace")
    m = re.search(r"\$config\['des_key'\]\s*=\s*'([^']+)'", cur)
    des = m.group(1) if m else "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))
    db = '\ninclude("/etc/roundcube/debian-db-roundcube.php");' if Path("/etc/roundcube/debian-db-roundcube.php").exists() else ""
    rc_imap, rc_smtp = _rc_hosts()  # this server, plus the remote accounts (Gmail and friends) read here
    _write(RC_CONF, f"""<?php
// Written by AuroraPanel (Email → Webmail). Edit in the panel — changes here are overwritten.
$config = [];{db}
$config['imap_host'] = {rc_imap};
$config['smtp_host'] = {rc_smtp};
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
$config['smtp_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true]];
$config['support_url'] = '';
$config['product_name'] = 'Webmail';
$config['des_key'] = '{des}';
$config['plugins'] = ['archive', 'zipdownload', 'newmail_notifier'];
$config['skin'] = 'elastic';
$config['enable_spellcheck'] = false;
$config['login_autocomplete'] = 2;
$config['session_lifetime'] = 60;
$config['ip_check'] = true;
$config['x_frame_options'] = 'sameorigin';
$config['draft_autosave'] = 60;
$config['mime_param_folding'] = 0;
$config['create_default_folders'] = true;
$config['archive_mbox'] = 'Archive';
$config['junk_mbox'] = 'Junk';
""", 0o640, "root", "www-data")
    _write(WEBMAIL_CONF, HEADER + """Alias /webmail /var/lib/roundcube/public_html
<Directory /var/lib/roundcube/public_html/>
    Options +FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
<Directory /var/lib/roundcube/config>
    Options -FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>
<Directory /var/lib/roundcube/temp>
    Require all denied
</Directory>
<Directory /var/lib/roundcube/logs>
    Require all denied
</Directory>
""")
    out = []
    _run(["a2enconf", "-q", "zz-aurora-webmail"])
    t = _run(["apache2ctl", "configtest"])
    if t.returncode != 0:
        _run(["a2disconf", "-q", "zz-aurora-webmail"])
        raise MailError("Apache rejected the webmail settings:\n" + t.stderr.strip()[-400:])
    _run(["systemctl", "reload", "apache2"])
    if fix:
        out.append(fix)
    out.append("• Webmail is at /webmail on every site of this server")
    return out


# ----------------------------------------------------------------------------- calendars & contacts (Radicale)
DAV_CONF = Path("/etc/radicale/config")
DAV_USERS = Path("/etc/radicale/aurora-users")
DAV_RIGHTS = Path("/etc/radicale/aurora-rights")
DAV_ROOT = Path("/var/lib/radicale/collections/collection-root")
DAV_APACHE = Path("/etc/apache2/conf-available/zz-aurora-dav.conf")


def dav_installed() -> bool:
    return DAV_CONF.exists() and DAV_CONF.read_text(errors="replace").startswith(HEADER)


def dav_urls(a: str) -> dict:
    h = hostname()
    return {"server": f"https://{h}/dav/", "principal": f"https://{h}/dav/{a}/"} if dav_installed() else {}


def setup_dav() -> list[str]:
    if not shutil.which("radicale", path=PATH):
        raise MailError("Radicale isn't installed")
    _write(DAV_CONF, HEADER + f"""[server]
hosts = 127.0.0.1:5232
max_content_length = 100000000

[auth]
type = htpasswd
htpasswd_filename = {DAV_USERS}
htpasswd_encryption = autodetect
realm = Calendars and contacts
delay = 2

[rights]
type = from_file
file = {DAV_RIGHTS}

[storage]
filesystem_folder = /var/lib/radicale/collections

[web]
type = internal
""", 0o644)
    _write(DAV_APACHE, HEADER + """# Calendars & contacts (CalDAV / CardDAV) — Radicale behind Apache.
RedirectMatch 301 ^/\\.well-known/(caldav|carddav)$ /dav/
<Location /dav/>
    ProxyPass http://127.0.0.1:5232/ retry=0
    ProxyPassReverse http://127.0.0.1:5232/
    ProxyPreserveHost On
    RequestHeader set X-Script-Name /dav
</Location>
""")
    out = []
    _run(["a2enmod", "-q", "proxy", "proxy_http", "headers"])
    _run(["a2enconf", "-q", "zz-aurora-dav"])
    t = _run(["apache2ctl", "configtest"])
    if t.returncode != 0:
        _run(["a2disconf", "-q", "zz-aurora-dav"])
        raise MailError("Apache rejected the calendar proxy:\n" + t.stderr.strip()[-400:])
    _run(["systemctl", "restart", "apache2"])
    DAV_ROOT.mkdir(parents=True, exist_ok=True)
    _run(["chown", "-R", "radicale:radicale", str(DAV_ROOT.parent)])
    sync_dav(load())
    _run(["systemctl", "enable", "radicale"])
    _run(["systemctl", "restart", "radicale"], 60)
    out.append("• Calendars & contacts are at /dav on every site of this server")
    s = load()
    for a in s["accounts"]:
        _dav_defaults(a)
    return out


def _dav_rights(s: dict) -> str:
    esc = lambda t: re.escape(t)
    lines = [HEADER, "[root]\nuser: .+\ncollection:\npermissions: R\n",
             "[principal]\nuser: .+\ncollection: {user}\npermissions: RW\n",
             "[own]\nuser: .+\ncollection: {user}/[^/]+\npermissions: rw\n"]
    for i, sh in enumerate(s.get("dav_shares", [])):
        lines.append(f"[share-{i}]\nuser: {esc(sh['with'])}\ncollection: {esc(sh['owner'])}/{esc(sh['collection'])}\n"
                     f"permissions: {'rw' if sh.get('write') else 'r'}\n")
        lines.append(f"[share-{i}-principal]\nuser: {esc(sh['with'])}\ncollection: {esc(sh['owner'])}\npermissions: R\n")
    return "\n".join(lines)


def sync_dav(s: dict) -> None:
    if not dav_installed():
        return
    users = "".join(f"{a}:{acc['hash'].split('}', 1)[-1]}\n" for a, acc in sorted(s["accounts"].items())
                    if not acc.get("suspend", {}).get("login"))
    _write(DAV_USERS, users, 0o640, "root", "radicale")
    if _write(DAV_RIGHTS, _dav_rights(s), 0o644):
        _run(["systemctl", "try-restart", "radicale"], 60)


def _dav_dir(owner: str, coll: str = "") -> Path:
    p = DAV_ROOT / owner
    if coll:
        if not re.match(r"^[A-Za-z0-9_.-]{1,80}$", coll) or coll in (".", ".."):
            raise MailError("Unknown collection")
        p = p / coll
    return p


def _chown_dav(p: Path) -> None:
    try:
        shutil.chown(p, "radicale", "radicale")
    except (LookupError, OSError):
        pass


def _dav_defaults(a: str) -> None:
    if not dav_installed() or _dav_dir(a).exists():
        return
    create_collection(a, "calendar", "Calendar", "#ff7a1a", "")
    create_collection(a, "addressbook", "Contacts", "", "")


def list_collections() -> dict:
    s = load()
    out = []
    if DAV_ROOT.is_dir():
        for owner in sorted(DAV_ROOT.iterdir()):
            if not owner.is_dir() or owner.name.startswith("."):
                continue
            for c in sorted(owner.iterdir()):
                pf = c / ".Radicale.props"
                if not c.is_dir() or not pf.exists():
                    continue
                try:
                    props = json.loads(pf.read_text())
                except ValueError:
                    props = {}
                tag = props.get("tag", "")
                items = sum(1 for f in c.iterdir() if f.is_file() and not f.name.startswith("."))
                out.append({"owner": owner.name, "id": c.name, "type": "calendar" if tag == "VCALENDAR" else "addressbook" if tag == "VADDRESSBOOK" else "other",
                            "name": props.get("D:displayname") or c.name, "color": props.get("ICAL:calendar-color", ""),
                            "description": props.get("C:calendar-description") or props.get("CR:addressbook-description", ""),
                            "items": items, "url": f"https://{hostname(s)}/dav/{owner.name}/{c.name}/"})
    return {"collections": out, "shares": s.get("dav_shares", []), "accounts": sorted(s["accounts"]),
            "installed": dav_installed(), "server": f"https://{hostname(s)}/dav/"}


def create_collection(owner: str, kind: str, name: str, color: str = "", description: str = "") -> dict:
    s = load()
    a = _addr(owner)
    if a not in s["accounts"]:
        raise MailError("Calendars belong to an email account — create it first")
    name = _line(name, 80) or ("Calendar" if kind == "calendar" else "Contacts")
    cid = secrets.token_hex(8)
    d = _dav_dir(a, cid)
    for p in (DAV_ROOT.parent, DAV_ROOT):
        if not p.exists():
            p.mkdir()
            _chown_dav(p)
    d.mkdir(parents=True)
    props = {"D:displayname": name}
    if kind == "calendar":
        props.update({"tag": "VCALENDAR", "C:supported-calendar-component-set": "VEVENT,VTODO,VJOURNAL"})
        if re.match(r"^#[0-9a-fA-F]{6}$", color or ""):
            props["ICAL:calendar-color"] = color
        if description:
            props["C:calendar-description"] = _line(description, 200)
    elif kind == "addressbook":
        props["tag"] = "VADDRESSBOOK"
        if description:
            props["CR:addressbook-description"] = _line(description, 200)
    else:
        raise MailError("Choose calendar or address book")
    (d / ".Radicale.props").write_text(json.dumps(props))
    for p in (d.parent, d, d / ".Radicale.props"):
        _chown_dav(p)
    return {"ok": True, "id": cid}


def update_collection(owner: str, cid: str, name: str, color: str = "", description: str = "") -> dict:
    d = _dav_dir(_addr(owner), cid)
    pf = d / ".Radicale.props"
    if not pf.exists():
        raise MailError("Unknown collection")
    props = json.loads(pf.read_text())
    props["D:displayname"] = _line(name, 80) or props.get("D:displayname", "")
    if props.get("tag") == "VCALENDAR":
        if re.match(r"^#[0-9a-fA-F]{6}$", color or ""):
            props["ICAL:calendar-color"] = color
        props["C:calendar-description"] = _line(description, 200)
    else:
        props["CR:addressbook-description"] = _line(description, 200)
    pf.write_text(json.dumps(props))
    _chown_dav(pf)
    return {"ok": True}


def delete_collection(owner: str, cid: str) -> dict:
    a = _addr(owner)
    d = _dav_dir(a, cid)
    if not (d / ".Radicale.props").exists():
        raise MailError("Unknown collection")
    TRASH.mkdir(parents=True, exist_ok=True)
    shutil.move(str(d), TRASH / f"dav-{a}-{cid}-{int(time.time())}")
    s = load()
    s["dav_shares"] = [x for x in s.get("dav_shares", []) if not (x["owner"] == a and x["collection"] == cid)]
    save(s)
    sync_dav(s)
    return {"ok": True}


def share_collection(owner: str, cid: str, with_: str, write: bool) -> dict:
    s = load()
    a, w = _addr(owner), _addr(with_)
    if w not in s["accounts"]:
        raise MailError(f"{w} isn't an email account on this server")
    if a == w:
        raise MailError("It's already theirs")
    if not (_dav_dir(a, cid) / ".Radicale.props").exists():
        raise MailError("Unknown collection")
    shares = [x for x in s.get("dav_shares", []) if not (x["owner"] == a and x["collection"] == cid and x["with"] == w)]
    shares.append({"owner": a, "collection": cid, "with": w, "write": bool(write)})
    s["dav_shares"] = shares
    save(s)
    sync_dav(s)
    return {"ok": True}


def unshare_collection(owner: str, cid: str, with_: str) -> dict:
    s = load()
    a, w = _addr(owner), _addr(with_)
    s["dav_shares"] = [x for x in s.get("dav_shares", []) if not (x["owner"] == a and x["collection"] == cid and x["with"] == w)]
    save(s)
    sync_dav(s)
    return {"ok": True}


def send_test(to: str, sender: str = "") -> dict:
    """Send a short test message through the local Postfix (shows up in Track Delivery)."""
    to = _ext_addr(to)
    s = load()
    frm = _addr(sender) if sender else f"postmaster@{hostname(s)}"
    msg = (f"From: {frm}\nTo: {to}\nSubject: AuroraPanel test message\nMessage-ID: <{secrets.token_hex(8)}@{hostname(s)}>\n"
           f"Date: {datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')}\nMIME-Version: 1.0\n"
           "Content-Type: text/plain; charset=utf-8\n\nThis is a test message from your AuroraPanel mail server.\n")
    r = _run(["sendmail", "-i", "-f", frm, to], 30, input=msg)
    if r.returncode != 0:
        raise MailError(r.stderr.strip()[-300:] or "sendmail failed")
    return {"ok": True, "from": frm, "to": to}


# --------------------------------------------------------------------------- #
# Remote accounts: Gmail, Outlook or any IMAP server, read in this server's webmail
# --------------------------------------------------------------------------- #
# The panel keeps the server settings (never the password): Roundcube gets them as extra
# hosts, and "Check Email" opens webmail with the account pre-selected. The password is
# typed in webmail, as with any mail app.
REMOTE_PRESETS = {
    "gmail": {"name": "Gmail / Google Workspace", "imap_host": "imap.gmail.com", "imap_port": 993, "imap_enc": "ssl",
              "smtp_host": "smtp.gmail.com", "smtp_port": 465, "smtp_enc": "ssl",
              "hint": "Google needs an app password: Google Account → Security → 2-Step Verification → App passwords. The normal password doesn't work for mail apps."},
    "outlook": {"name": "Outlook / Hotmail / Microsoft 365", "imap_host": "outlook.office365.com", "imap_port": 993, "imap_enc": "ssl",
                "smtp_host": "smtp.office365.com", "smtp_port": 587, "smtp_enc": "tls",
                "hint": "Personal Microsoft accounts need an app password when two-step verification is on."},
    "yahoo": {"name": "Yahoo Mail", "imap_host": "imap.mail.yahoo.com", "imap_port": 993, "imap_enc": "ssl",
              "smtp_host": "smtp.mail.yahoo.com", "smtp_port": 465, "smtp_enc": "ssl",
              "hint": "Yahoo needs an app password: Account Security → Generate app password."},
    "icloud": {"name": "iCloud Mail", "imap_host": "imap.mail.me.com", "imap_port": 993, "imap_enc": "ssl",
               "smtp_host": "smtp.mail.me.com", "smtp_port": 587, "smtp_enc": "tls",
               "hint": "iCloud needs an app-specific password from appleid.apple.com → Sign-In and Security."},
    "custom": {"name": "Other IMAP server", "imap_host": "", "imap_port": 993, "imap_enc": "ssl", "smtp_host": "", "smtp_port": 587, "smtp_enc": "tls", "hint": ""},
}
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


def _remote_spec(a: dict, kind: str) -> str:
    enc = a.get(f"{kind}_enc", "ssl")
    return f"{'ssl://' if enc == 'ssl' else 'tls://' if enc == 'tls' else ''}{a[f'{kind}_host']}:{a[f'{kind}_port']}"


def remote_accounts() -> list[dict]:
    out = []
    for a in load().get("remote", []):
        x = dict(a)
        x["imap"] = _remote_spec(a, "imap")
        x["smtp"] = _remote_spec(a, "smtp")
        # Only the user name goes into the link: the mail server's name stays out of URLs, status bars and browser
        # history (the account is picked from webmail's own dropdown).
        x["webmail"] = f"{webmail_url()}?_user={quote(a['username'])}" if webmail_url() else ""
        out.append(x)
    return out


def remote_test(a: dict, password: str) -> None:
    """Sign in to the IMAP server once with the given password, so a typo shows up now, not in webmail."""
    import imaplib
    try:
        if a["imap_enc"] == "ssl":
            c = imaplib.IMAP4_SSL(a["imap_host"], int(a["imap_port"]), timeout=20)
        else:
            c = imaplib.IMAP4(a["imap_host"], int(a["imap_port"]), timeout=20)
            if a["imap_enc"] == "tls":
                c.starttls()
        try:
            c.login(a["username"], password)
        finally:
            try:
                c.logout()
            except Exception:
                pass
    except imaplib.IMAP4.error as exc:
        hint = REMOTE_PRESETS.get(a.get("preset", ""), {}).get("hint", "")
        raise MailError(f"The server refused the sign-in ({str(exc)[:120]}). {hint}".strip())
    except (OSError, socket.timeout) as exc:
        raise MailError(f"Couldn't reach {a['imap_host']}:{a['imap_port']} ({exc})")


def remote_add(data: dict) -> dict:
    preset = REMOTE_PRESETS.get(str(data.get("preset") or "custom")) or REMOTE_PRESETS["custom"]
    email_addr = str(data.get("email") or "").strip().lower()
    if "@" not in email_addr or " " in email_addr:
        raise MailError("Enter the address, e.g. you@gmail.com")
    a = {"id": "", "preset": str(data.get("preset") or "custom"), "label": str(data.get("label") or "").strip() or email_addr,
         "email": email_addr, "username": str(data.get("username") or "").strip() or email_addr}
    for kind in ("imap", "smtp"):
        host = str(data.get(f"{kind}_host") or preset[f"{kind}_host"] or "").strip().lower()
        if not _HOST_RE.match(host):
            raise MailError(f"Enter the {kind.upper()} server name, e.g. {kind}.example.com")
        try:
            port = int(data.get(f"{kind}_port") or preset[f"{kind}_port"])
        except (TypeError, ValueError):
            raise MailError(f"The {kind.upper()} port must be a number")
        if not 1 <= port <= 65535:
            raise MailError(f"The {kind.upper()} port must be between 1 and 65535")
        enc = str(data.get(f"{kind}_enc") or preset[f"{kind}_enc"])
        if enc not in ("ssl", "tls", "none"):
            raise MailError("Encryption must be ssl, tls or none")
        a[f"{kind}_host"], a[f"{kind}_port"], a[f"{kind}_enc"] = host, port, enc
    s = load()
    s.setdefault("remote", [])
    if any(x["username"] == a["username"] and x["imap_host"] == a["imap_host"] for x in s["remote"]):
        raise MailError("That account is already on the list")
    if data.get("password"):
        remote_test(a, str(data["password"]))
    a["id"] = re.sub(r"[^a-z0-9]+", "-", email_addr).strip("-")[:40] + "-" + secrets.token_hex(3)
    a["created"] = int(time.time())
    s["remote"].append(a)
    save(s)
    _refresh_webmail_hosts()
    return next(x for x in remote_accounts() if x["id"] == a["id"])


def remote_remove(rid: str) -> dict:
    s = load()
    before = len(s.get("remote", []))
    s["remote"] = [x for x in s.get("remote", []) if x["id"] != rid]
    if len(s["remote"]) == before:
        raise MailError("No such remote account")
    save(s)
    _refresh_webmail_hosts()
    return {"ok": True}


def _refresh_webmail_hosts() -> None:
    """Roundcube's host list follows the remote accounts; a webmail that isn't installed is left alone."""
    if RC_CONF.exists() and webmail_installed():
        try:
            setup_webmail()
        except Exception:
            pass


def _rc_hosts() -> tuple[str, str]:
    """PHP for Roundcube's imap_host and smtp_host: this server, plus every remote account."""
    remote = load().get("remote", [])
    if not remote:
        return "['localhost:143']", "'tls://localhost:587'"
    esc = lambda v: str(v).replace("\\", "\\\\").replace("'", "\\'")  # noqa: E731
    hosts = [("localhost:143", f"This server ({hostname()})")] + [(_remote_spec(a, "imap"), a["label"]) for a in remote]
    smtp = [("localhost:143", "tls://localhost:587")] + [(_remote_spec(a, "imap"), _remote_spec(a, "smtp")) for a in remote]
    return ("[" + ", ".join(f"'{esc(k)}' => '{esc(v)}'" for k, v in hosts) + "]",
            "[" + ", ".join(f"'{esc(k)}' => '{esc(v)}'" for k, v in smtp) + "]")


# --------------------------------------------------------------------------- #
# Inbox feed: the newest messages of this server's own mailboxes, for the panel's menu
# --------------------------------------------------------------------------- #
def _hdr(msg, name: str) -> str:
    from email.header import decode_header, make_header
    raw = msg.get(name, "") or ""
    try:
        return str(make_header(decode_header(raw))).strip()
    except Exception:
        return str(raw).strip()


def inbox_feed(addresses: list[str], limit: int = 10) -> list[dict]:
    """The newest messages in the INBOX of each address (Maildir new/ and cur/), newest first."""
    from email.parser import BytesHeaderParser
    from email.utils import parseaddr, parsedate_to_datetime
    items: list[dict] = []
    parser = BytesHeaderParser()
    for addr in addresses:
        if "@" not in addr:
            continue
        user, dom = addr.split("@", 1)
        for sub in ("new", "cur"):
            d = VMAIL / dom / user / "Maildir" / sub
            if not d.is_dir():
                continue
            try:
                files = sorted((p for p in d.iterdir() if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True)[:limit * 2]
            except OSError:
                continue
            for f in files:
                flags = f.name.split(":2,", 1)[1] if ":2," in f.name else ""
                try:
                    with f.open("rb") as fh:
                        msg = parser.parse(fh)
                    mtime = f.stat().st_mtime
                except OSError:
                    continue
                name, from_addr = parseaddr(_hdr(msg, "From"))
                try:
                    ts = parsedate_to_datetime(msg.get("Date", "")).timestamp()
                except Exception:
                    ts = mtime
                items.append({"account": addr, "from": name or from_addr or "unknown sender", "from_addr": from_addr,
                              "subject": _hdr(msg, "Subject") or "(no subject)", "ts": int(ts), "unread": sub == "new" or "S" not in flags,
                              "id": f"{addr}:{f.name}"})
    items.sort(key=lambda x: x["ts"], reverse=True)
    return items[:limit]


def inbox_addresses(owner: str, contact: str) -> list[str]:
    """Whose mail the menu shows: the contact address if it's a mailbox here, mailboxes named after
    the panel owner, and the ones on this server's own local domain."""
    s = load()
    local = local_domain_name()
    out = []
    for a in sorted(s["accounts"]):
        if a == (contact or "").lower() or a.split("@")[0] == (owner or "").lower() or (local and a.endswith("@" + local)):
            out.append(a)
    return out
