"""Apache-based access tools for the Files section:

  Web Disk          WebDAV accounts: map a folder as a network drive
                    (Windows / macOS / Linux / phones) at /webdisk/<user>/
  Directory Privacy password-protect folders of your websites

Both write panel-owned Apache config (conf-available/zz-aurora-*.conf) with
bcrypt password files outside the web root, run `apache2ctl configtest`
before reloading, and restore the previous state if Apache rejects it.
Web Disk never executes scripts: PHP is switched off inside /webdisk/, so
files are always transferred as files."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

from . import sslcerts

WD_CONF = Path("/etc/apache2/conf-available/zz-aurora-webdisk.conf")
WD_HTPASSWD = Path("/etc/apache2/aurora-webdisk.htpasswd")
WD_STATE = Path("/var/lib/aurora/webdisk.json")
WD_SSL_CONF = Path("/etc/apache2/sites-available/zz-aurora-webdisk-ssl.conf")
WD_CERT = Path("/etc/apache2/ssl/aurora/webdisk.crt")
WD_KEY = Path("/etc/apache2/ssl/aurora/webdisk.key")
WD_DOCROOT = Path("/var/lib/aurora/webdisk-root")
_SKIP_IFACE = re.compile(r"^(lo|docker\d*|br-|veth|virbr)")
_VHOST = re.compile(r"<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>", re.S | re.I)
DP_CONF = Path("/etc/apache2/conf-available/zz-aurora-privacy.conf")
DP_DIR = Path("/etc/apache2/aurora-privacy")
DP_STATE = Path("/var/lib/aurora/dirprivacy.json")
_USER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
_ALLOWED = ("/var/www/", "/srv/", "/home/")


class WebAccessError(RuntimeError):
    pass


def _need_apache():
    if not shutil.which("apache2ctl"):
        raise WebAccessError("Apache is not installed (System Applications → Apache)")
    if not shutil.which("htpasswd"):
        raise WebAccessError("htpasswd is missing (apt install apache2-utils)")


def _load(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


def _store(p: Path, d: dict):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(d, indent=2))
    p.chmod(0o600)


def _site_docroots() -> dict[str, str]:
    """server_name -> resolved document root of every site Apache serves. A subdomain is a site of
    its own here, so protecting it means protecting its root."""
    try:
        from . import sites
        out = {}
        for s in sites.list_sites().get("sites", []):
            root = s.get("docroot") or (s.get("settings") or {}).get("docroot")
            if s.get("system") or not root:
                continue
            out[str(s["server_name"]).lower()] = str(Path(root).resolve())
        return out
    except Exception as quiet_exc:
        from . import problems
        problems.quiet(quiet_exc)
        return {}


def _folder(path: str, create: bool = False) -> Path:
    p = Path((path or "").strip())
    if not p.is_absolute() or ".." in p.parts:
        raise WebAccessError("Folder must be an absolute path, e.g. /var/www/html/private")
    # Inside one of the usual web roots, or anywhere inside a site's own document root (a site may live
    # elsewhere, e.g. /opt/sites). The site check is per path component, so /srv/a never matches /srv/ab.
    inside_site = any(p == Path(r) or Path(r) in p.parents for r in _site_docroots().values())
    if not inside_site and (not str(p).rstrip("/").startswith(tuple(a.rstrip("/") for a in _ALLOWED)) or str(p).rstrip("/") in ("/home", "/srv", "/var/www")):
        raise WebAccessError("Pick a folder inside one of your sites, /var/www, /srv or /home/<user>")
    if not p.exists():
        if not create:
            raise WebAccessError("Folder does not exist")
        p.mkdir(parents=True)
    if not p.is_dir():
        raise WebAccessError("Not a folder")
    if any(c in str(p) for c in '"\n\r<>'):
        raise WebAccessError("Folder name contains characters Apache can't use")
    return p.resolve()


def _password(pw: str) -> str:
    if not pw or len(pw) < 8 or len(pw) > 128 or "\n" in pw:
        raise WebAccessError("Password: 8–128 characters")
    return pw


def _htpasswd_set(file: Path, user: str, pw: str):
    file.parent.mkdir(parents=True, exist_ok=True)
    args = ["htpasswd", "-iB"] + ([] if file.exists() else ["-c"]) + [str(file), user]
    r = subprocess.run(args, input=pw + "\n", capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise WebAccessError(r.stderr.strip() or "htpasswd failed")
    shutil.chown(file, "root", "www-data")
    file.chmod(0o640)


def _htpasswd_del(file: Path, user: str):
    if file.exists():
        subprocess.run(["htpasswd", "-D", str(file), user], capture_output=True, text=True, timeout=30)


def _apply_conf(conf: Path, text: str | None, mods: list[str]):
    """Write/enable a conf, configtest, reload; restore on any failure."""
    old = conf.read_text() if conf.exists() else None
    enabled_link = Path("/etc/apache2/conf-enabled") / conf.name
    was_enabled = enabled_link.exists()
    newly = []
    for m in mods:
        if not Path(f"/etc/apache2/mods-enabled/{m}.load").exists():
            subprocess.run(["a2enmod", "-q", m], capture_output=True, timeout=30)
            newly.append(m)
    if text is None:
        conf.unlink(missing_ok=True)
        if was_enabled:
            subprocess.run(["a2disconf", "-q", conf.stem], capture_output=True, timeout=30)
    else:
        conf.write_text(text, encoding="utf-8")
        if not was_enabled:
            subprocess.run(["a2enconf", "-q", conf.stem], capture_output=True, timeout=30)
    t = subprocess.run(["apache2ctl", "configtest"], capture_output=True, text=True, timeout=30)
    if t.returncode != 0:
        if old is None:
            conf.unlink(missing_ok=True)
            subprocess.run(["a2disconf", "-q", conf.stem], capture_output=True, timeout=30)
        else:
            conf.write_text(old, encoding="utf-8")
            if was_enabled and not enabled_link.exists():
                subprocess.run(["a2enconf", "-q", conf.stem], capture_output=True, timeout=30)
        raise WebAccessError("Apache rejected the change, nothing was applied:\n" + t.stderr.strip()[-500:])
    _reload_apache(restart=bool(newly))


def _reload_apache(restart: bool = False):
    """Graceful reload (no dropped requests); a full restart only when a module
    was newly enabled. Always leaves Apache running if it was running."""
    if subprocess.run(["systemctl", "is-active", "--quiet", "apache2"]).returncode != 0:
        return
    subprocess.run(["systemctl", "restart" if restart else "reload", "apache2"], capture_output=True, timeout=90)
    time.sleep(0.5)
    if subprocess.run(["systemctl", "is-active", "--quiet", "apache2"]).returncode != 0:
        subprocess.run(["systemctl", "reset-failed", "apache2"], capture_output=True, timeout=30)
        subprocess.run(["systemctl", "start", "apache2"], capture_output=True, timeout=90)


def _acl(user: str, folder: Path, rw: bool, remove: bool = False):
    if not shutil.which("setfacl"):
        return
    if remove:
        subprocess.run(["setfacl", "-R", "-x", f"u:{user},d:u:{user}", str(folder)], capture_output=True, timeout=300)
        return
    perm = "rwX" if rw else "rX"
    subprocess.run(["setfacl", "-R", "-m", f"u:{user}:{perm},d:u:{user}:{perm}", str(folder)], capture_output=True, timeout=300)


# ================================================================ Web Disk
def _wd_render(accts: dict) -> str:
    out = ["# Managed by AuroraPanel — Web Disk (WebDAV). Edits here are overwritten.",
           "DavLockDB /var/lib/apache2/aurora-davlock/DavLock", ""]
    for user, a in sorted(accts.items()):
        if a.get("disabled"):
            continue
        folder = a["path"]
        verbs = "GET HEAD OPTIONS PROPFIND"
        acc = [f"    Require user {user}"] if not a.get("readonly") else [
            f"    <Limit {verbs}>", f"        Require user {user}", "    </Limit>",
            f"    <LimitExcept {verbs}>", "        Require all denied", "    </LimitExcept>"]
        # No <Directory> block on purpose: the folder may be a live site root, and
        # changing its settings would affect the website too.
        out += [f'Alias /webdisk/{user} "{folder}"',
                f"<Location /webdisk/{user}>", "    DAV On", "    AuthType Basic",
                '    AuthName "AuroraPanel Web Disk"', f"    AuthUserFile {WD_HTPASSWD}", *acc,
                "    Options +Indexes", "    DirectoryIndex disabled",
                "    # Never execute scripts from the Web Disk — always transfer them as files.",
                "    <IfModule php_module>", "        php_admin_flag engine off", "    </IfModule>",
                "    RemoveHandler .php .phtml .phar .cgi .pl .py", "    RemoveType .php .phtml .phar",
                "    SetHandler none", "</Location>", ""]
    return "\n".join(out)


def webdisk_list() -> dict:
    accts = _load(WD_STATE)
    return {"apache": bool(shutil.which("apache2ctl")),
            "accounts": [{"name": u, "path": a["path"], "readonly": bool(a.get("readonly")), "disabled": bool(a.get("disabled")),
                          "created": a.get("created"), "exists": Path(a["path"]).is_dir()} for u, a in sorted(accts.items())]}


def _wd_apply(accts: dict, removed_paths: list[str] | None = None):
    Path("/var/lib/apache2/aurora-davlock").mkdir(parents=True, exist_ok=True)
    shutil.chown("/var/lib/apache2/aurora-davlock", "www-data", "www-data")
    _apply_conf(WD_CONF, _wd_render(accts) if accts else None, ["dav", "dav_fs", "auth_basic", "authn_file", "alias"])
    _wd_sync_acls(accts, removed_paths or [])


def _wd_sync_acls(accts: dict, removed_paths: list[str]):
    """Make sure Apache (www-data) can serve each Web Disk folder: write access
    where an active account may write, read access otherwise. Only ever ADDS
    permissions — a folder may be a live site whose apps rely on existing
    www-data rights, so nothing is reduced or removed (read-only is enforced
    by Apache itself, not by file permissions)."""
    need: dict[str, bool] = {}
    for a in accts.values():
        if a.get("disabled"):
            continue
        need[a["path"]] = need.get(a["path"], False) or not a.get("readonly")
    for path, rw in need.items():
        p = Path(path)
        if not p.is_dir() or not shutil.which("setfacl"):
            continue
        if rw:
            _acl("www-data", p, True)
        elif (p.stat().st_mode & 0o005) != 0o005 and "user:www-data:" not in subprocess.run(
                ["getfacl", "-cp", str(p)], capture_output=True, text=True).stdout:
            _acl("www-data", p, False)


def webdisk_create(user: str, password: str, path: str, readonly: bool = False) -> dict:
    _need_apache()
    user = (user or "").strip()
    if not _USER.match(user):
        raise WebAccessError("Username: letters, digits, . _ - (max 32)")
    accts = _load(WD_STATE)
    if user in accts:
        raise WebAccessError("That Web Disk account already exists")
    folder = _folder(path, create=True)
    _htpasswd_set(WD_HTPASSWD, user, _password(password))
    accts[user] = {"path": str(folder), "readonly": bool(readonly), "created": int(time.time())}
    try:
        _wd_apply(accts)
    except WebAccessError:
        _htpasswd_del(WD_HTPASSWD, user)
        raise
    _store(WD_STATE, accts)
    return {"ok": True, "name": user, "path": str(folder)}


def webdisk_update(user: str, path: str | None = None, readonly: bool | None = None, disabled: bool | None = None,
                   password: str | None = None) -> dict:
    _need_apache()
    accts = _load(WD_STATE)
    if user not in accts:
        raise WebAccessError("No such Web Disk account")
    a = dict(accts[user])
    if password:
        _htpasswd_set(WD_HTPASSWD, user, _password(password))
    if path:
        a["path"] = str(_folder(path, create=True))
    if readonly is not None:
        a["readonly"] = bool(readonly)
    if disabled is not None:
        a["disabled"] = bool(disabled)
    new = {**accts, user: a}
    if new != accts:
        _wd_apply(new)
        _store(WD_STATE, new)
    return {"ok": True}


def webdisk_delete(user: str) -> dict:
    _need_apache()
    accts = _load(WD_STATE)
    if user not in accts:
        raise WebAccessError("No such Web Disk account")
    del accts[user]
    _wd_apply(accts)
    _htpasswd_del(WD_HTPASSWD, user)
    _store(WD_STATE, accts)
    return {"ok": True, "note": "Files in the folder were kept."}


# ---------------------------------------------------- Web Disk certificate
def webdisk_certificate(host: str) -> dict:
    """The certificate Apache presents for `host`, if that name is on it.

    Windows will not map the drive until this file is a trusted root. This
    only reports what is already in use — it does not create one."""
    host = _clean_host(host)
    try:
        presented = _presented_vhost(host)
        path = Path(presented["cert"]) if presented and presented.get("cert") else None
        ready = bool(path and sslcerts.covers_host(path, host))
    except sslcerts.SSLCertError as exc:
        raise WebAccessError(str(exc)) from exc
    return _cert_payload(path if ready else None, host, generated=False, ready=ready)


def webdisk_certificate_ensure(host: str) -> dict:
    """Make sure Apache presents a certificate that includes `host`.

    An existing certificate that already covers the address is kept, so a
    computer that trusted it does not have to trust a new one. Otherwise a
    self-signed certificate is written for this Pi's names and Apache is
    pointed at it."""
    host = _clean_host(host)
    current = webdisk_certificate(host)
    if current["ready"] and current.get("pem"):
        return current
    _need_apache()
    if not shutil.which("openssl"):
        raise WebAccessError("openssl is not installed")
    vhosts = _ssl_vhosts()
    owner = next((v for v in vhosts if _has_name(v, host)), None)
    names = _cert_names(host, owner["names"] if owner else [])
    if owner and owner.get("cert") and Path(owner["cert"]).is_file() and not _is_self_signed(owner["cert"]):
        raise WebAccessError(
            f"Apache already serves {host} with a certificate AuroraPanel can't replace. "
            "Include this address in that certificate, then download it here.")
    backups = _begin_cert(names)
    try:
        if owner:
            _retarget_vhost(owner)
        else:
            _install_dedicated_vhost(host, names, vhosts)
    except Exception:
        _restore_cert(backups)
        raise
    _drop_cert_backups(backups)
    payload = _cert_payload(WD_CERT, host, generated=True, ready=True)
    if not payload.get("pem") or not sslcerts.covers_host(WD_CERT, host):
        raise WebAccessError("The certificate was written but does not cover " + host)
    return payload


def _clean_host(host: str) -> str:
    host = (host or "").strip().strip("[]").rstrip(".")
    if not host:
        ips = _lan_ips()
        host = ips[0] if ips else socket.gethostname()
    if not sslcerts.valid_cert_name(host):
        raise WebAccessError("That address can't be put on a certificate")
    return host


def _lan_ips() -> list[str]:
    try:
        import psutil
    except ImportError:
        return []
    out = []
    for name, addrs in psutil.net_if_addrs().items():
        if _SKIP_IFACE.match(name):
            continue
        for addr in addrs:
            ip = (addr.address or "").split("%")[0]
            if addr.family == socket.AF_INET and ip.startswith("127."):
                continue
            if addr.family == socket.AF_INET6 and (ip == "::1" or ip.lower().startswith("fe80")):
                continue
            if addr.family in (socket.AF_INET, socket.AF_INET6) and sslcerts.valid_cert_name(ip) and ip not in out:
                out.append(ip)
    return out


def _cert_names(host: str, extra: list[str]) -> list[str]:
    names = []
    for candidate in [host, socket.gethostname(), socket.getfqdn(), "localhost", *_lan_ips(), *extra]:
        candidate = (candidate or "").strip().strip("[]").rstrip(".")
        if candidate and candidate not in names and sslcerts.valid_cert_name(candidate):
            names.append(candidate)
    return names[:32]


def _cert_payload(path: Path | None, host: str, generated: bool, ready: bool) -> dict:
    info = None
    if path and path.is_file():
        try:
            info = sslcerts.describe_cert(path)
        except sslcerts.SSLCertError as exc:
            raise WebAccessError(str(exc)) from exc
    self_signed = bool(info and info.get("self_signed"))
    if not ready:
        message = (f"Apache has no certificate for {host} yet. Create one and Apache will use it "
                   "for the Web Disk — then download it and trust it on Windows.")
    elif self_signed:
        message = ("Windows reports error 1244 until this certificate is a trusted root on that computer. "
                   "Download it and import it there. Accepting the warning in the browser does not let Windows map the drive.")
    else:
        message = "This address already uses a certificate Windows trusts."
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", host).strip("-") or "webdisk"
    return {
        "ready": ready, "generated": generated,
        "self_signed": self_signed if info else True,
        "needs_trust": (not ready) or self_signed,
        "subject": (info or {}).get("subject") or "",
        "names": (info or {}).get("names") or [],
        "host": host, "filename": f"aurora-{safe}.crt",
        "pem": (info or {}).get("pem"), "message": message,
    }


def _ssl_vhosts() -> list[dict]:
    enabled = Path("/etc/apache2/sites-enabled")
    if not enabled.is_dir():
        return []
    found = []
    for conf in sorted(enabled.iterdir(), key=lambda p: p.name):
        if not conf.name.endswith(".conf"):
            continue
        try:
            text = conf.resolve().read_text(encoding="utf-8", errors="replace")
            real = str(conf.resolve())
        except OSError:
            continue
        for match in _VHOST.finditer(text):
            addr, body = match.group(1), match.group(2)
            port_m = re.search(r":(\d+)", addr)
            port = int(port_m.group(1)) if port_m else 80
            if port != 443 or not re.search(r"(?im)^\s*SSLEngine\s+on", body):
                continue
            server = _directive(body, "ServerName") or ""
            aliases = []
            for line in re.findall(r"(?im)^\s*ServerAlias\s+(.+)$", body):
                aliases.extend(line.split())
            names = []
            for raw in [server, *aliases]:
                bare = raw.strip().strip("[]")
                if bare and bare not in names:
                    names.append(bare)
            cert = _directive(body, "SSLCertificateFile")
            found.append({"conf": real, "server_name": server.strip("[]"), "names": names, "cert": cert})
    return found


def _directive(body: str, name: str) -> str | None:
    match = re.search(rf'(?im)^\s*{name}\s+("[^"]*"|\S+)', body)
    return match.group(1).strip().strip('"') if match else None


def _has_name(vhost: dict, host: str) -> bool:
    want = host.lower()
    return any(name.lower() == want for name in vhost["names"])


def _presented_vhost(host: str) -> dict | None:
    """The TLS vhost Apache actually picks for this address."""
    vhosts = _ssl_vhosts()
    owner = next((v for v in vhosts if _has_name(v, host)), None)
    if owner:
        return owner
    return vhosts[0] if vhosts else None


def _is_self_signed(path: str | None) -> bool:
    if not path or not Path(path).is_file():
        return False
    try:
        info = sslcerts.describe_cert(Path(path))
    except sslcerts.SSLCertError:
        return False
    return bool(info and info.get("self_signed"))


def _apache_name(name: str) -> str:
    try:
        if ipaddress.ip_address(name).version == 6:
            return f"[{name}]"
    except ValueError:
        pass
    return name


def _begin_cert(names: list[str]) -> list[tuple[Path, Path]]:
    backups = []
    for path in (WD_CERT, WD_KEY):
        if path.exists():
            backup = Path(str(path) + ".bak")
            shutil.copy2(path, backup)
            backups.append((path, backup))
    try:
        sslcerts.write_self_signed(WD_CERT, WD_KEY, names)
    except sslcerts.SSLCertError as exc:
        _restore_cert(backups)
        raise WebAccessError(str(exc)) from exc
    except Exception:
        _restore_cert(backups)
        raise
    return backups


def _restore_cert(backups: list[tuple[Path, Path]]):
    for path, backup in backups:
        if backup.exists():
            shutil.copy2(backup, path)
            backup.unlink(missing_ok=True)


def _drop_cert_backups(backups: list[tuple[Path, Path]]):
    for _, backup in backups:
        backup.unlink(missing_ok=True)


def _retarget_vhost(vhost: dict):
    """Point an existing self-signed vhost at the Web Disk certificate."""
    path = Path(vhost["conf"]).resolve()
    _guard_apache_path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    matched = False

    def repl(match: re.Match) -> str:
        nonlocal matched
        addr, body = match.group(1), match.group(2)
        port_m = re.search(r":(\d+)", addr)
        port = int(port_m.group(1)) if port_m else 80
        server = (_directive(body, "ServerName") or "").strip("[]")
        if port != 443 or server.lower() != (vhost.get("server_name") or "").lower():
            return match.group(0)
        matched = True
        body = re.sub(r'(?im)^(\s*SSLCertificateFile\s+)(?:"[^"]*"|\S+)', rf"\g<1>{WD_CERT}", body, count=1)
        if not re.search(r"(?im)^\s*SSLCertificateKeyFile\s+", body):
            body = body.rstrip() + f"\n    SSLCertificateKeyFile {WD_KEY}\n"
        else:
            body = re.sub(r'(?im)^(\s*SSLCertificateKeyFile\s+)(?:"[^"]*"|\S+)', rf"\g<1>{WD_KEY}", body, count=1)
        body = re.sub(r'(?im)^\s*SSLCertificateChainFile\s+\S+\s*\n', "", body)
        if not re.search(rf"(?im)^\s*SSLCertificateFile\s+{re.escape(str(WD_CERT))}\s*$", body):
            raise WebAccessError(f"Couldn't point {path.name} at the new certificate")
        return f"<VirtualHost {addr}>{body}</VirtualHost>"

    updated = _VHOST.sub(repl, text)
    if not matched:
        raise WebAccessError(f"Couldn't find the HTTPS site for this address in {path.name}")
    if updated == text:
        _reload_apache()
        return
    _commit_apache_file(path, updated, enable_site=False)


def _install_dedicated_vhost(host: str, names: list[str], vhosts: list[dict]):
    taken = {name.lower() for vhost in vhosts for name in vhost["names"]}
    aliases = [name for name in names if name.lower() != host.lower() and name.lower() not in taken]
    WD_DOCROOT.mkdir(parents=True, exist_ok=True)
    lines = ["# Managed by AuroraPanel — Web Disk certificate. Edits here are overwritten.",
             "<IfModule mod_ssl.c>", "<VirtualHost *:443>", f"    ServerName {_apache_name(host)}"]
    if aliases:
        lines.append("    ServerAlias " + " ".join(_apache_name(name) for name in aliases))
    lines += ["    SSLEngine on", f"    SSLCertificateFile {WD_CERT}", f"    SSLCertificateKeyFile {WD_KEY}",
              f'    DocumentRoot "{WD_DOCROOT}"', f'    <Directory "{WD_DOCROOT}">',
              "        Require all granted", "        Options -Indexes", "        DirectoryIndex disabled",
              "    </Directory>", "</VirtualHost>", "</IfModule>", ""]
    _commit_apache_file(WD_SSL_CONF, "\n".join(lines), enable_site=True)


def _guard_apache_path(path: Path):
    root = Path("/etc/apache2").resolve()
    resolved = path.resolve()
    if root != resolved and root not in resolved.parents:
        raise WebAccessError("Refusing to edit a file outside Apache's configuration")


def _commit_apache_file(conf: Path, text: str, enable_site: bool):
    """Write a site file, configtest, reload. Restore the previous file on failure."""
    _guard_apache_path(conf)
    old = conf.read_text(encoding="utf-8") if conf.exists() else None
    enabled_link = Path("/etc/apache2/sites-enabled") / conf.name
    was_enabled = enabled_link.exists()
    newly = []
    if not Path("/etc/apache2/mods-enabled/ssl.load").exists():
        enabled_mod = subprocess.run(["a2enmod", "-q", "ssl"], capture_output=True, text=True, timeout=30)
        if enabled_mod.returncode != 0:
            raise WebAccessError(enabled_mod.stderr.strip() or "Couldn't enable Apache's SSL module")
        newly.append("ssl")
    def rollback():
        if old is None:
            conf.unlink(missing_ok=True)
        else:
            conf.write_text(old, encoding="utf-8")
        if not was_enabled:
            subprocess.run(["a2dissite", "-q", conf.stem], capture_output=True, timeout=30)
        if newly:
            subprocess.run(["a2dismod", "-q", "ssl"], capture_output=True, timeout=30)

    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text(text, encoding="utf-8")
    if enable_site and not enabled_link.exists():
        enabled_site = subprocess.run(["a2ensite", "-q", conf.stem], capture_output=True, text=True, timeout=30)
        if enabled_site.returncode != 0 or not enabled_link.exists():
            rollback()
            raise WebAccessError(enabled_site.stderr.strip() or "Couldn't enable the certificate site")
    test = subprocess.run(["apache2ctl", "configtest"], capture_output=True, text=True, timeout=30)
    if test.returncode != 0:
        rollback()
        detail = "\n".join(line for line in (test.stderr + test.stdout).splitlines() if "AH00558" not in line).strip()
        raise WebAccessError("Apache rejected the certificate, nothing was changed:\n" + detail[-500:])
    _reload_apache(restart=bool(newly))


# ================================================================ Directory Privacy
def _dp_key(path: str) -> str:
    return hashlib.sha1(path.encode()).hexdigest()[:12]


def _dp_render(dirs: dict) -> str:
    out = ["# Managed by AuroraPanel — Directory Privacy. Edits here are overwritten.", ""]
    for path, d in sorted(dirs.items()):
        if not d.get("enabled", True) or not d.get("users"):
            continue
        label = re.sub(r'["\\\n\r]', "", d.get("label") or "Restricted area")[:60]
        out += [f'<Directory "{path}">', "    AuthType Basic", f'    AuthName "{label}"',
                f"    AuthUserFile {DP_DIR / (_dp_key(path) + '.htpasswd')}", "    Require valid-user", "</Directory>", ""]
    return "\n".join(out)


def privacy_list() -> dict:
    dirs = _load(DP_STATE)
    by_root = {root: name for name, root in _site_docroots().items()}  # a protected docroot is a whole site
    return {"apache": bool(shutil.which("apache2ctl")),
            "folders": [{"path": p, "label": d.get("label"), "enabled": d.get("enabled", True), "users": sorted(d.get("users", [])),
                         "exists": Path(p).is_dir(), "site": by_root.get(p)} for p, d in sorted(dirs.items())]}


def privacy_sites() -> dict:
    """Every site (domains and subdomains alike) and whether its whole document root is behind a login."""
    dirs = _load(DP_STATE)
    out = []
    for name, root in sorted(_site_docroots().items()):
        d = dirs.get(root) or {}
        out.append({"server_name": name, "docroot": root, "protected": bool(d and d.get("enabled", True) and d.get("users")),
                    "enabled": bool(d) and d.get("enabled", True), "label": d.get("label"), "users": sorted(d.get("users", []))})
    return {"apache": bool(shutil.which("apache2ctl")), "sites": out}


def privacy_protect_site(site: str, label: str, user: str, password: str) -> dict:
    """Basic Auth in front of a whole domain or subdomain: protect its document root."""
    site = (site or "").strip().lower().rstrip(".")
    roots = _site_docroots()
    if site not in roots:
        raise WebAccessError("That domain isn't a site on this server (create it under Domains first)")
    r = privacy_protect(roots[site], label or site, user, password)
    return {**r, "site": site}


def _dp_apply(dirs: dict):
    active = {p: d for p, d in dirs.items() if d.get("enabled", True) and d.get("users")}
    _apply_conf(DP_CONF, _dp_render(dirs) if active else None, ["auth_basic", "authn_file", "authz_user"])


def privacy_protect(path: str, label: str, user: str, password: str) -> dict:
    _need_apache()
    folder = str(_folder(path))
    user = (user or "").strip()
    if not _USER.match(user):
        raise WebAccessError("Username: letters, digits, . _ - (max 32)")
    dirs = _load(DP_STATE)
    d = dirs.get(folder, {"label": label or "Restricted area", "users": [], "enabled": True})
    if label:
        d["label"] = label[:60]
    htp = DP_DIR / f"{_dp_key(folder)}.htpasswd"
    _htpasswd_set(htp, user, _password(password))
    if user not in d["users"]:
        d["users"].append(user)
    d["enabled"] = True
    dirs[folder] = d
    _dp_apply(dirs)
    _store(DP_STATE, dirs)
    return {"ok": True, "path": folder}


def privacy_user(path: str, user: str, password: str | None = None, remove: bool = False) -> dict:
    _need_apache()
    dirs = _load(DP_STATE)
    folder = str(Path(path))
    if folder not in dirs:
        raise WebAccessError("That folder isn't protected")
    d = dirs[folder]
    htp = DP_DIR / f"{_dp_key(folder)}.htpasswd"
    if remove:
        _htpasswd_del(htp, user)
        d["users"] = [u for u in d["users"] if u != user]
    else:
        if not _USER.match(user or ""):
            raise WebAccessError("Username: letters, digits, . _ - (max 32)")
        _htpasswd_set(htp, user, _password(password or ""))
        if user not in d["users"]:
            d["users"].append(user)
    _dp_apply(dirs)
    _store(DP_STATE, dirs)
    return {"ok": True}


def privacy_toggle(path: str, enabled: bool) -> dict:
    _need_apache()
    dirs = _load(DP_STATE)
    if path not in dirs:
        raise WebAccessError("That folder isn't protected")
    dirs[path]["enabled"] = bool(enabled)
    _dp_apply(dirs)
    _store(DP_STATE, dirs)
    return {"ok": True}


def privacy_remove(path: str) -> dict:
    _need_apache()
    dirs = _load(DP_STATE)
    if path not in dirs:
        raise WebAccessError("That folder isn't protected")
    del dirs[path]
    _dp_apply(dirs)
    (DP_DIR / f"{_dp_key(path)}.htpasswd").unlink(missing_ok=True)
    _store(DP_STATE, dirs)
    return {"ok": True}
