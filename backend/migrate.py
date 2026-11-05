"""Move from cPanel — import a cPanel full backup (cpmove-USER.tar.gz / backup-…_USER.tar.gz).

What comes across:
  * websites — the main domain, addon domains and subdomains, each as its own site with its files;
  * databases — every MySQL database, and its users with their existing passwords (cPanel keeps the
    MySQL password hashes, so wp-config.php and friends keep working unchanged);
  * email — every mailbox with its existing password (cPanel's crypt hashes work as-is) and all mail,
    plus forwarders;
  * DNS zones — optional, when this server is going to answer DNS for the domains.
Nothing that already exists here is overwritten; it's reported and skipped.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

from . import distro
from . import jobs
from . import problems

PATH = distro.PATH


class MigrateError(RuntimeError):
    pass


def _dir() -> Path:
    from . import backups
    d = backups.BACKUP_DIR / "import"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _run(argv, timeout=3600, input=None, stdin=None):
    try:
        return subprocess.run(argv, capture_output=True, text=input is not None, timeout=timeout, input=input, stdin=stdin,
                              env={**os.environ, "PATH": PATH})
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def candidates() -> list[dict]:
    """cPanel backups found on this server (the import folder, the backups folder, home folders)."""
    from . import backups
    seen, out = set(), []
    for base in (_dir(), backups.BACKUP_DIR, Path("/root"), *Path("/home").glob("*")):
        try:
            files = list(base.glob("*.tar.gz")) + list(base.glob("*.tgz"))
        except OSError:
            continue
        for f in files:
            if f in seen or not re.search(r"(cpmove-|backup-.*_)", f.name):
                continue
            seen.add(f)
            st = f.stat()
            out.append({"path": str(f), "name": f.name, "size": st.st_size, "mtime": int(st.st_mtime)})
    return sorted(out, key=lambda x: -x["mtime"])


def fetch(url: str) -> jobs.Job:
    """Download a backup from a link (e.g. one the old host gives you) into the import folder."""
    if not re.match(r"^https?://[^\s]+$", url or ""):
        raise MigrateError("Paste an http(s):// link to the backup file")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", url.rstrip("/").split("/")[-1].split("?")[0]) or "cpanel-backup.tar.gz"
    if not name.endswith((".tar.gz", ".tgz")):
        name += ".tar.gz"
    dest = _dir() / name

    def fn(log):
        log.progress(1, "Downloading")
        req = urllib.request.Request(url, headers={"User-Agent": "AuroraPanel"})
        tmp = dest.with_suffix(".part")
        with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
            total = int(r.headers.get("Content-Length") or 0)
            got = 0
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                got += len(chunk)
                if total:
                    log.progress(min(99, got * 100 / total), f"Downloading {got / 1e6:.0f} of {total / 1e6:.0f} MB")
        tmp.replace(dest)
        os.chmod(dest, 0o600)
        log.progress(100, "Downloaded")
        log(f"✓ Saved as {dest}")
        return {"path": str(dest)}
    return jobs.launch_fn("download cPanel backup", fn, meta={"migrate": "fetch"})


def _check_path(path: str) -> Path:
    p = Path(path).resolve()
    if not any(str(p) == c["path"] for c in candidates()):
        raise MigrateError("Pick a cPanel backup from the list (put it in the import folder first)")
    return p


_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")  # a mailbox name / domain safe to use as a folder name


def _inside(base: Path, p: Path) -> bool:
    try:
        return p.resolve().is_relative_to(base.resolve())
    except (OSError, ValueError):
        return False


def _yaml_value(text: str, key: str) -> str:
    m = re.search(rf"(?m)^{re.escape(key)}:\s*['\"]?([^'\"\n]*)['\"]?\s*$", text)
    return m.group(1).strip() if m else ""


def _yaml_block(text: str, key: str) -> list[str]:
    """The indented lines under `key:` (a simple YAML list or map)."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(key)}:\s*$", line):
            out = []
            for nxt in lines[i + 1:]:
                if not nxt.strip():
                    continue
                if not nxt[0].isspace() and not nxt.startswith("-"):
                    break
                out.append(nxt)
            return out
    return []


def _yaml_list(text: str, key: str) -> list[str]:
    inline = re.search(rf"(?m)^{re.escape(key)}:\s*\[(.*)\]", text)
    if inline:
        return [x.strip(" '\"") for x in inline.group(1).split(",") if x.strip()]
    return [m.group(1).strip(" '\"") for l in _yaml_block(text, key) if (m := re.match(r"^\s*-\s*(.+)$", l))]


def _yaml_map_keys(text: str, key: str) -> dict[str, str]:
    out = {}
    for line in _yaml_block(text, key):
        mm = re.match(r"\s+['\"]?([^:'\"]+)['\"]?:\s*['\"]?([^'\"\n]*)", line)
        if mm:
            out[mm.group(1).strip()] = mm.group(2).strip()
    return out


_DOMAIN = re.compile(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}")


def analyze(path: str) -> dict:
    """Read the backup's table of contents and small metadata files (no full extraction)."""
    p = _check_path(path)
    small: dict[str, str] = {}
    dbs, mailboxes, zones, sizes = [], [], [], {}
    top = ""
    with tarfile.open(p, "r:gz") as tf:
        for m in tf:
            name = m.name
            if not top:
                top = name.split("/")[0]
            rel = name[len(top) + 1:] if name.startswith(top + "/") else name
            if m.isfile() and (rel.startswith(("userdata/", "etc/", "va/")) or rel in ("mysql.sql", "cp/" + top)) and m.size < 2_000_000:
                try:
                    small[rel] = tf.extractfile(m).read().decode("utf-8", "replace")
                except Exception as quiet_exc:
                    problems.quiet(quiet_exc)
            if m.isfile() and rel.startswith("mysql/") and rel.endswith(".sql"):
                dbs.append({"name": Path(rel).stem, "size": m.size})
            if m.isfile() and rel.startswith("dnszones/") and rel.endswith(".db"):
                zones.append(Path(rel).stem)
            mm = re.match(r"homedir/mail/([^/]+\.[^/]+)/([^/]+)/", rel)
            if mm:
                key = f"{mm.group(2)}@{mm.group(1)}"
                sizes[key] = sizes.get(key, 0) + (m.size if m.isfile() else 0)
    main = small.get("userdata/main", "")
    user = _yaml_value(main, "user") or (top.split("-", 1)[-1] if top.startswith("cpmove-") else top)
    main_domain = _yaml_value(main, "main_domain")
    addons = _yaml_map_keys(main, "addon_domains")
    subs = _yaml_list(main, "sub_domains")
    parked = _yaml_list(main, "parked_domains")
    sites = []
    # addon_domains maps the addon domain to cPanel's internal subdomain, whose userdata holds its settings
    inner = {v.lower(): k.lower() for k, v in addons.items()}
    entries = [(main_domain, main_domain, "main")] + [(d, d, "subdomain") for d in subs if d and d.lower() not in inner] \
        + [(k, v, "addon") for k, v in addons.items()]
    for dom, ud_name, kind in entries:
        dom = (dom or "").lower()
        if not _DOMAIN.fullmatch(dom) or any(s["domain"] == dom for s in sites):
            continue
        ud = small.get(f"userdata/{ud_name}", "") or small.get(f"userdata/{dom}", "")
        docroot = _yaml_value(ud, "documentroot")
        rel = re.sub(r"^/home\d*/[^/]+/", "", docroot) if docroot else ("public_html" if kind == "main" else dom)
        if rel.startswith("/") or ".." in Path(rel).parts:
            rel = "public_html" if kind == "main" else dom
        aliases = [a.lower() for a in (_yaml_value(ud, "serveralias").split() if ud else [])
                   if a.lower() != dom and (ud_name.lower() == dom or a.lower() not in (ud_name.lower(), "www." + ud_name.lower()))]
        sites.append({"domain": dom, "docroot_rel": rel, "aliases": aliases + (parked if kind == "main" else []), "kind": kind})
    for key, text in small.items():
        mm = re.match(r"etc/([^/]+\.[^/]+)/shadow$", key)
        if mm:
            for line in text.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and _SAFE.fullmatch(parts[0]) and _SAFE.fullmatch(mm.group(1)) and parts[1].startswith("$"):
                    a = f"{parts[0]}@{mm.group(1)}"
                    mailboxes.append({"address": a, "size": sizes.get(a, 0)})
    fwd = 0
    for key, text in small.items():
        if key.startswith("va/"):
            fwd += sum(1 for l in text.splitlines() if ":" in l and not l.startswith("*"))
    return {"path": str(p), "top": top, "user": user, "main_domain": main_domain, "sites": sites, "databases": dbs,
            "db_users": sorted(set(re.findall(r"TO '([^']+)'@", small.get("mysql.sql", "")))), "mailboxes": sorted(mailboxes, key=lambda x: x["address"]),
            "forwarders": fwd, "zones": zones}


def run(path: str, opts: dict) -> jobs.Job:
    info = analyze(path)
    want_sites = set(opts.get("sites") or [s["domain"] for s in info["sites"]])
    want_dbs = set(opts.get("databases") or [d["name"] for d in info["databases"]])
    want_mail = bool(opts.get("mail", True))
    want_zones = bool(opts.get("zones", False))

    def fn(log):
        p = Path(info["path"])
        need = p.stat().st_size * 3
        free = shutil.disk_usage(_dir()).free
        if free < need:
            raise MigrateError(f"Not enough free disk space: need about {need / 1e9:.1f} GB, have {free / 1e9:.1f} GB")
        work = _dir() / f"work-{secrets.token_hex(3)}"
        work.mkdir()
        report = {"sites": [], "databases": [], "mail": [], "skipped": []}
        try:
            log.progress(2, "Unpacking the backup")
            r = _run(["tar", "-xzf", str(p), "-C", str(work), "--no-same-owner"], 7200)
            if r.returncode != 0:
                raise MigrateError("Couldn't unpack: " + (r.stderr or "")[-300:])
            root = work / info["top"]
            # ---- websites
            from . import sites
            todo = [s for s in info["sites"] if s["domain"] in want_sites]
            for i, s in enumerate(todo):
                log.progress(10 + 30 * i / max(1, len(todo)), f"Website {s['domain']}")
                src = root / "homedir" / s["docroot_rel"]
                if not _inside(root / "homedir", src):
                    report["skipped"].append(f"site {s['domain']} (its folder points outside the backup)")
                    continue
                dst = Path("/var/www") / s["domain"]
                try:
                    sites.get_site(s["domain"])
                    report["skipped"].append(f"site {s['domain']} (already exists)")
                    log(f"• {s['domain']}: a site with that name exists here — skipped")
                    continue
                except sites.SiteError:
                    pass
                if dst.exists() and any(dst.iterdir()):
                    report["skipped"].append(f"site {s['domain']} ({dst} isn't empty)")
                    continue
                aliases = [a for a in s["aliases"] if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", a)]
                sites.create_site({"server_name": s["domain"], "aliases": aliases, "docroot": str(dst), "ssl": "selfsigned"})
                if src.is_dir():
                    for item in dst.iterdir():  # the placeholder index.html
                        item.unlink() if item.is_file() else shutil.rmtree(item)
                    rr = _run(["cp", "-a", f"{src}/.", str(dst)], 7200)
                    if rr.returncode != 0:
                        log(f"! copying {s['domain']}: {rr.stderr[-200:]}")
                    _run(["chown", "-R", "www-data:www-data", str(dst)], 3600)
                report["sites"].append(s["domain"])
                log(f"✓ Website {s['domain']} → {dst}")
            # ---- databases (+ users with their existing password hashes)
            grants = (root / "mysql.sql").read_text(errors="replace") if (root / "mysql.sql").exists() else ""
            dbs = [d for d in info["databases"] if d["name"] in want_dbs]
            for i, d in enumerate(dbs):
                log.progress(40 + 25 * i / max(1, len(dbs)), f"Database {d['name']}")
                name = d["name"]
                if not re.fullmatch(r"[A-Za-z0-9_$-]{1,64}", name):
                    report["skipped"].append(f"database {name} (odd name)")
                    continue
                exists = _run(["mysql", "-N", "-e", f"SHOW DATABASES LIKE '{name}'"], 60, input="")
                if exists.stdout.strip():
                    report["skipped"].append(f"database {name} (already exists)")
                    log(f"• {name}: already exists here — skipped")
                    continue
                _run(["mysql", "-e", f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"], 60, input="")
                with open(root / "mysql" / f"{name}.sql", "rb") as fh:
                    rr = _run(["mysql", name], 7200, stdin=fh)
                if rr.returncode != 0:
                    log(f"! {name}: {rr.stderr.decode(errors='replace')[-300:] if isinstance(rr.stderr, bytes) else rr.stderr[-300:]}")
                report["databases"].append(name)
                log(f"✓ Database {name}")
            made_users = set()
            for line in grants.splitlines():
                m = re.match(r"GRANT USAGE ON \*\.\* TO '([^']+)'@'([^']+)' IDENTIFIED BY PASSWORD '(\*[0-9A-F]{40})'", line)
                if m and m.group(2) in ("localhost", "%") and m.group(1) not in made_users:
                    u, h = m.group(1), m.group(3)
                    if not re.fullmatch(r"[A-Za-z0-9_.$-]{1,80}", u):
                        continue
                    rr = _run(["mysql", "-e", f"CREATE USER IF NOT EXISTS '{u}'@'localhost' IDENTIFIED BY PASSWORD '{h}'"], 60, input="")
                    if rr.returncode != 0:  # MySQL 8 spelling
                        _run(["mysql", "-e", f"CREATE USER IF NOT EXISTS '{u}'@'localhost' IDENTIFIED WITH mysql_native_password AS '{h}'"], 60, input="")
                    made_users.add(u)
            for line in grants.splitlines():
                m = re.match(r"GRANT (.+?) ON `([^`]+)`\.\* TO '([^']+)'@'(localhost|%)'", line)
                if m and m.group(3) in made_users:
                    db = m.group(2).replace("\\_", "_")
                    if db in report["databases"]:
                        _run(["mysql", "-e", f"GRANT ALL PRIVILEGES ON `{db}`.* TO '{m.group(3)}'@'localhost'"], 60, input="")
            if made_users:
                log(f"✓ Database users kept with their passwords: {', '.join(sorted(made_users))}")
            # ---- email
            if want_mail and info["mailboxes"]:
                from . import mail
                if not (mail.installed() and mail.configured()):
                    report["skipped"].append("email (set up the mail server first, then import again with only email ticked)")
                    log("• Email skipped — the mail server isn't set up here yet")
                else:
                    for i, mb in enumerate(info["mailboxes"]):
                        log.progress(65 + 25 * i / max(1, len(info["mailboxes"])), f"Mailbox {mb['address']}")
                        user, dom = mb["address"].split("@")
                        shadow = (root / "etc" / dom / "shadow").read_text(errors="replace")
                        h = next((l.split(":")[1] for l in shadow.splitlines() if l.split(":")[0] == user), "")
                        try:
                            mail.import_account(mb["address"], h)
                        except mail.MailError as e:
                            report["skipped"].append(f"mailbox {mb['address']} ({e})")
                            log(f"• {mb['address']}: {e}")
                            continue
                        src = root / "homedir" / "mail" / dom / user
                        if src.is_dir() and _inside(root / "homedir" / "mail", src):
                            dst = mail.VMAIL / dom / user / "Maildir"
                            dst.mkdir(parents=True, exist_ok=True)
                            _run(["cp", "-a", f"{src}/.", str(dst)], 7200)
                            for idx in dst.rglob("dovecot.index*"):
                                idx.unlink(missing_ok=True)
                            _run(["chown", "-R", "vmail:vmail", str(mail.VMAIL / dom / user)], 3600)
                        report["mail"].append(mb["address"])
                    for va in (root / "va").glob("*") if (root / "va").exists() else []:
                        for line in va.read_text(errors="replace").splitlines():
                            if ":" not in line or line.startswith("*"):
                                continue
                            src_a, dest = (x.strip() for x in line.split(":", 1))
                            if "@" not in src_a:
                                continue
                            if dest.startswith(":fail:"):
                                kind, args = "fail", {"message": dest[6:].strip()}
                            elif dest.startswith(":blackhole:"):
                                kind, args = "discard", {}
                            else:
                                targets = [x.strip() for x in dest.split(",") if re.match(r"^[^@\s|/]+@[^@\s]+$", x.strip())]
                                if not targets:
                                    log(f"• forwarder {src_a} → {dest[:60]}: not something this server can do (pipes/scripts) — skipped")
                                    continue
                                kind, args = "forward", {"dest": ", ".join(targets)}
                            try:
                                mail.add_forwarder(src_a, kind, **args)
                                report["forwarders"] = report.get("forwarders", 0) + 1
                            except mail.MailError as e:
                                report["skipped"].append(f"forwarder {src_a} ({e})")
                                log(f"• forwarder {src_a}: {e}")
                    log(f"✓ {len(report['mail'])} mailbox(es) with their mail and passwords, {report.get('forwarders', 0)} forwarder(s)")
            # ---- DNS
            if want_zones:
                from . import dnszones
                for zf in sorted((root / "dnszones").glob("*.db")) if (root / "dnszones").exists() else []:
                    dom = zf.stem
                    try:
                        z = dnszones.parse(zf.read_text(errors="replace"), dom)
                        if dnszones._path(dom).exists():
                            report["skipped"].append(f"zone {dom} (exists)")
                            continue
                        recs = []
                        for r_ in z["records"]:
                            try:
                                recs.append(dnszones.clean_record(r_, dom))
                            except dnszones.ZoneError:
                                pass
                        dnszones._write(dom, {"soa": z["soa"], "records": recs, "ttl": 14400})
                        log(f"✓ DNS zone {dom} ({len(recs)} records) — update the A records to this server's IP before switching nameservers")
                    except Exception as e:
                        report["skipped"].append(f"zone {dom} ({e})")
            log.progress(100, "Imported")
            log("✓ Import finished. Next: point the domains' DNS here; AutoSSL then gets real certificates.")
            try:
                from . import audit
                audit.record("system", "", f"cPanel import ({info['user']})", detail={k: (len(v) if isinstance(v, list) else v) for k, v in report.items()})
            except Exception as quiet_exc:
                problems.quiet(quiet_exc)
            return report
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return jobs.launch_fn(f"import cPanel account {info['user']}", fn, meta={"migrate": "run"})
