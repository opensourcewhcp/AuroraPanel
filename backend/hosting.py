"""Hosting — WHM-style plans, accounts and resellers.

  Plan      limits for an account: disk, monthly bandwidth, websites, databases, email accounts,
            PHP workers (simultaneous PHP requests) and PHP memory. 0 = unlimited.
  Account   a separate Linux user with its own home (/home/<user>, public_html for the main domain,
            /home/<user>/<domain> for more), its own panel login (a website manager tied to the
            account: files = its home, its sites' mail, stats and its own databases <user>_*),
            and its sites' PHP running as the account itself (Site Isolation), within the plan.
  Reseller  a panel user who creates and manages their own accounts, with the plans and the
            number of accounts the admin gives them.

Suspending turns the account's websites off, its panel login and its mailboxes' sign-in off;
unsuspending restores exactly that. Usage (disk incl. mail and databases, bandwidth this month) is
measured by the task runner every hour; going over a limit raises an alert.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

try:
    import pwd
except ImportError:  # pragma: no cover — the panel runs on Linux
    pwd = None

from . import jobs

STATE = Path("/var/lib/aurora/hosting.json")
HOME = Path("/home")
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

LIMITS = [  # key, label, unit
    ("disk_mb", "Disk space", "MB"), ("bandwidth_gb", "Bandwidth per month", "GB"), ("sites", "Websites", ""),
    ("databases", "Databases", ""), ("mailboxes", "Email accounts", ""),
    ("php_workers", "PHP workers", "at once"), ("php_memory_mb", "PHP memory", "MB per request"),
]
DEFAULT_PLANS = {
    "Starter": {"disk_mb": 2048, "bandwidth_gb": 20, "sites": 1, "databases": 2, "mailboxes": 5, "php_workers": 3, "php_memory_mb": 128},
    "Business": {"disk_mb": 10240, "bandwidth_gb": 100, "sites": 10, "databases": 20, "mailboxes": 50, "php_workers": 6, "php_memory_mb": 256},
    "Unlimited": {"disk_mb": 0, "bandwidth_gb": 0, "sites": 0, "databases": 0, "mailboxes": 0, "php_workers": 10, "php_memory_mb": 512},
}
_USER = re.compile(r"^[a-z][a-z0-9]{1,15}$")
_PLAN = re.compile(r"^[\w][\w .+-]{0,39}$")
# Names a hosting account must never take (system accounts, services, confusing ones).
RESERVED = {"root", "admin", "administrator", "www", "wwwdata", "mail", "ftp", "mysql", "mariadb", "postgres", "nobody", "daemon",
            "bin", "sys", "sync", "games", "man", "lp", "news", "uucp", "proxy", "backup", "list", "irc", "gnats", "vmail", "sshd",
            "systemd", "aurora", "aurorapanel", "pi", "ubuntu", "debian", "test", "user", "guest", "postmaster", "abuse", "webmaster",
            "hostmaster", "info", "support", "redis", "docker", "dovecot", "postfix", "rspamd", "bind", "named", "apache", "nginx",
            "phpmyadmin", "roundcube", "operator", "staff", "users", "sudo", "wheel", "adm", "shadow", "utmp", "tty", "disk", "kmem"}


class HostingError(RuntimeError):
    pass


def _run(argv, timeout=120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env={**os.environ, "PATH": PATH})
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


# ------------------------------------------------------------------ state
def load() -> dict:
    try:
        d = json.loads(STATE.read_text())
    except (OSError, ValueError):
        d = {}
    d.setdefault("plans", json.loads(json.dumps(DEFAULT_PLANS)))
    d.setdefault("accounts", {})
    d.setdefault("resellers", {})
    d.setdefault("usage", {})
    return d


def _save(d: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_name(f".{STATE.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(d, fh, indent=1)
    tmp.replace(STATE)


# ------------------------------------------------------------------ who may see what
def _caller() -> dict:
    """The panel user making this call ({} = admin, the owner or an API token)."""
    from . import authz
    u = authz.current() or {}
    return u if u.get("role") in ("reseller", "site") else {}


def _visible(d: dict, acct: str) -> dict:
    a = d["accounts"].get(acct)
    c = _caller()
    if not a or (c.get("role") == "reseller" and a.get("owner") != c["username"]) or c.get("role") == "site":
        raise HostingError("No such account")
    return a


def _plans_for(d: dict) -> list[str]:
    c = _caller()
    if c.get("role") == "reseller":
        return [p for p in d["resellers"].get(c["username"], {}).get("plans", []) if p in d["plans"]]
    return sorted(d["plans"])


# ------------------------------------------------------------------ plans
def _limits(data: dict) -> dict:
    out = {}
    for k, label, _ in LIMITS:
        try:
            v = int(data.get(k) or 0)
        except (TypeError, ValueError):
            raise HostingError(f"{label}: a whole number (0 = unlimited)")
        if v < 0 or v > 10_000_000:
            raise HostingError(f"{label}: 0 (unlimited) or more")
        out[k] = v
    if not out["php_workers"]:
        out["php_workers"] = 5  # PHP-FPM needs a number
    out["php_workers"] = min(out["php_workers"], 64)
    if out["php_memory_mb"] and out["php_memory_mb"] < 32:
        raise HostingError("PHP memory: at least 32 MB (or 0 for PHP's default)")
    return out


def save_plan(name: str, data: dict, original: str = "") -> dict:
    if _caller():
        raise HostingError("Only an administrator manages plans")
    name = (name or "").strip()
    if not _PLAN.match(name):
        raise HostingError("Plan name: up to 40 letters, digits, spaces, dot, dash, plus")
    d = load()
    lim = _limits(data)
    if original and original != name:
        if original not in d["plans"]:
            raise HostingError("Unknown plan")
        if name in d["plans"]:
            raise HostingError("A plan with that name exists")
        d["plans"].pop(original)
        for a in d["accounts"].values():
            if a["plan"] == original:
                a["plan"] = name
        for r in d["resellers"].values():
            r["plans"] = [name if p == original else p for p in r.get("plans", [])]
    d["plans"][name] = lim
    _save(d)
    # Accounts on this plan get the new PHP limits now.
    for user, a in d["accounts"].items():
        if a["plan"] == name:
            _apply_php(a, lim)
    return listing()


def delete_plan(name: str) -> dict:
    if _caller():
        raise HostingError("Only an administrator manages plans")
    d = load()
    if name not in d["plans"]:
        raise HostingError("Unknown plan")
    users = [u for u, a in d["accounts"].items() if a["plan"] == name]
    if users:
        raise HostingError(f"{len(users)} account(s) use this plan ({', '.join(users[:5])}) — move them to another plan first")
    d["plans"].pop(name)
    for r in d["resellers"].values():
        r["plans"] = [p for p in r.get("plans", []) if p != name]
    _save(d)
    return listing()


# ------------------------------------------------------------------ listing
def _month_bytes(domains: list[str]) -> int:
    """Web traffic of these sites this month (Metrics keeps it per site and day)."""
    try:
        from . import metrics
        ids = {s["id"] for s in metrics.sites() if set(n.lower() for n in s["names"]) & set(domains)}
        month = time.strftime("%Y-%m")
        sd = metrics._bw_state()["site_d"]
        return sum(v.get("bytes", 0) for day, per in sd.items() if day.startswith(month) for k, v in per.items()
                   if k in ids or (k.startswith("vh:") and k[3:] in domains))
    except Exception:
        return 0


def listing() -> dict:
    d = load()
    c = _caller()
    accts = []
    for user, a in sorted(d["accounts"].items()):
        if c.get("role") == "reseller" and a.get("owner") != c["username"]:
            continue
        accts.append({"user": user, **a, "usage": d["usage"].get(user, {}), "limits": d["plans"].get(a["plan"], {})})
    out = {"accounts": accts, "plans": {p: d["plans"][p] for p in _plans_for(d)}, "limits": LIMITS}
    if c.get("role") == "reseller":
        r = d["resellers"].get(c["username"], {})
        out["reseller"] = {"max_accounts": r.get("max_accounts", 0), "used": len(accts)}
    else:
        from . import panelusers
        out["resellers"] = [{"username": u["username"], **d["resellers"].get(u["username"], {"plans": [], "max_accounts": 0}),
                             "accounts": sum(1 for a in d["accounts"].values() if a.get("owner") == u["username"])}
                            for u in panelusers.listing()["users"] if u.get("role") == "reseller"]
        out["ready"] = ready()
    return out


def ready() -> dict:
    """What creating an account needs: Apache (websites) and PHP-FPM (per-account PHP)."""
    from . import isolate
    return {"apache": bool(shutil.which("apache2ctl", path=PATH)), "php": bool(isolate.php_version()), "linux": pwd is not None}


def set_reseller(username: str, plans: list[str], max_accounts: int) -> dict:
    if _caller():
        raise HostingError("Only an administrator manages resellers")
    from . import panelusers
    u = panelusers.get(username)
    if not u or u.get("role") != "reseller":
        raise HostingError("Make this person a panel user with the Reseller role first (System → Panel Users)")
    d = load()
    bad = [p for p in plans if p not in d["plans"]]
    if bad:
        raise HostingError(f"Unknown plan: {', '.join(bad)}")
    d["resellers"][username] = {"plans": sorted(set(plans)), "max_accounts": max(0, min(int(max_accounts or 0), 100000))}
    _save(d)
    return listing()


# ------------------------------------------------------------------ accounts
def _check_new_user(user: str) -> None:
    if not _USER.match(user or ""):
        raise HostingError("User name: 2–16 lowercase letters and digits, starting with a letter (it becomes a Linux user)")
    if user in RESERVED or user.startswith(("site", "aurora")):
        raise HostingError(f"“{user}” is reserved — pick another user name")
    if pwd is not None:
        try:
            pwd.getpwnam(user)
            raise HostingError(f"A Linux user “{user}” already exists on this server")
        except KeyError:
            pass
    if (HOME / user).exists():
        raise HostingError(f"/home/{user} already exists")
    from . import panelusers
    if panelusers.get(user) or any(u["username"] == user for u in panelusers.listing()["users"]):
        raise HostingError(f"A panel user “{user}” already exists")


def _check_domain(domain: str) -> str:
    domain = (domain or "").strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}", domain):
        raise HostingError("Domain: a name like example.com")
    from . import sites
    known = {s["server_name"] for s in sites.list_sites().get("sites", [])}
    known |= {a for s in sites.list_sites().get("sites", []) for a in s.get("aliases", [])}
    if domain in known or "www." + domain in known:
        raise HostingError(f"{domain} already has a website on this server")
    return domain


def _docroot(user: str, domain: str, main: bool) -> Path:
    return HOME / user / ("public_html" if main else domain)


def _apply_php(a: dict, lim: dict) -> None:
    from . import isolate
    for dom in a.get("sites", []):
        try:
            isolate.apply_limits(dom, lim)
        except Exception as e:
            print(f"hosting: PHP limits for {dom}: {e}", flush=True)


def _add_site(user: str, domain: str, main: bool, lim: dict, log) -> None:
    from . import isolate, sites
    root = _docroot(user, domain, main)
    root.mkdir(parents=True, exist_ok=True)
    idx = root / "index.html"
    if not any(root.iterdir()):
        idx.write_text(f"<!doctype html><meta charset=utf-8><title>{domain}</title>"
                       f"<p style=\"font:16px system-ui;margin:3em\">{domain} is ready. Upload your site to "
                       f"{'public_html' if main else domain}.</p>\n")
    _run(["chown", "-R", f"{user}:{user}", str(root)])
    sites.create_site({"server_name": domain, "docroot": str(root), "www": "none", "aliases": ["www." + domain], "ssl": "none"})
    log(f"• Website {domain} → {root}")
    isolate.enable(domain, log, run_as=user, limits=lim, basedir=str(HOME / user))


def validate_new(user: str, domain: str, plan: str, password: str, email: str = "") -> tuple[str, str]:
    """Every check a new account must pass — run before the job starts, so mistakes show at once."""
    c = _caller()
    if c.get("role") == "site":
        raise HostingError("Not allowed")
    d = load()
    if plan not in _plans_for(d):
        raise HostingError("Pick one of your plans")
    if c.get("role") == "reseller":
        r = d["resellers"].get(c["username"], {})
        mine = sum(1 for a in d["accounts"].values() if a.get("owner") == c["username"])
        if r.get("max_accounts") and mine >= r["max_accounts"]:
            raise HostingError(f"You can have {r['max_accounts']} accounts — ask the administrator for more")
    user = (user or "").strip().lower()
    _check_new_user(user)
    domain = _check_domain(domain)
    if len(password or "") < 10:
        raise HostingError("Use a password of at least 10 characters")
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HostingError("Contact email doesn't look right")
    rd = ready()
    if not (rd["apache"] and rd["php"]):
        raise HostingError("Hosting needs Apache and PHP (Software → install them) first")
    return user, domain


def create_account(user: str, domain: str, plan: str, password: str, email: str = "", log=print) -> dict:
    user, domain = validate_new(user, domain, plan, password, email)
    c = _caller()
    d = load()
    lim = d["plans"][plan]
    # 1. the Linux user: home only reachable by the user (and Apache through the group, set by isolation)
    r = _run(["useradd", "--create-home", "--home-dir", str(HOME / user), "--shell", "/usr/sbin/nologin", "--user-group",
              "--comment", f"AuroraPanel hosting {domain}", user])
    if r.returncode != 0:
        raise HostingError(r.stderr.strip() or "useradd failed")
    log(f"• Linux user “{user}” with home /home/{user}")
    try:
        os.chmod(HOME / user, 0o750)
        _run(["usermod", "-aG", user, "www-data"])
        # 2. the website, its PHP as the account
        _add_site(user, domain, True, lim, log)
        # 3. the panel login: a website manager tied to the account
        from . import panelusers
        panelusers.create(user, password, "site", [domain], account=user)
        log(f"• Panel login “{user}” (sees only this account)")
    except Exception:
        log("! Something failed — undoing")
        _teardown(user, [domain], keep_files=False, log=log)
        raise
    d = load()
    d["accounts"][user] = {"plan": plan, "domain": domain, "sites": [domain], "email": email.strip(), "owner": c.get("username", ""),
                           "created": int(time.time()), "suspended": False}
    _save(d)
    _audit(f"Hosting: created account {user} ({domain}, {plan})")
    log(f"✓ Account {user} is ready: http://{domain}/ — sign in to the panel as {user}")
    return {"ok": True, "user": user}


def create_account_job(user: str, domain: str, plan: str, password: str, email: str = "") -> jobs.Job:
    from . import authz
    who = authz.current()  # the job runs in another thread: keep the caller's rights

    def fn(log):
        tok = authz.CURRENT.set(who)
        try:
            log.progress(3, f"Creating {user}")
            res = create_account(user, domain, plan, password, email, log)
            log.progress(100, "Done")
            return res
        finally:
            authz.CURRENT.reset(tok)
    return jobs.launch_fn(f"hosting account {user}", fn, meta={"hosting": user})


def add_domain(user: str, domain: str) -> dict:
    d = load()
    a = _visible(d, user)
    lim = d["plans"].get(a["plan"], {})
    if lim.get("sites") and len(a["sites"]) >= lim["sites"]:
        raise HostingError(f"The {a['plan']} plan allows {lim['sites']} website(s) — upgrade the plan for more")
    domain = _check_domain(domain)
    _add_site(user, domain, False, lim, print)
    from . import panelusers
    a["sites"].append(domain)
    panelusers.update(user, sites=a["sites"], _hosting=True)
    _save(d)
    _audit(f"Hosting: {user} + website {domain}")
    return {"ok": True}


def change_plan(user: str, plan: str) -> dict:
    d = load()
    a = _visible(d, user)
    if plan not in _plans_for(d):
        raise HostingError("Pick one of your plans")
    lim = d["plans"][plan]
    if lim.get("sites") and len(a["sites"]) > lim["sites"]:
        raise HostingError(f"The account has {len(a['sites'])} websites; {plan} allows {lim['sites']}")
    a["plan"] = plan
    _save(d)
    _apply_php(a, lim)
    _audit(f"Hosting: {user} → plan {plan}")
    return {"ok": True}


def set_password(user: str, password: str) -> dict:
    d = load()
    _visible(d, user)
    from . import panelusers
    panelusers.update(user, password=password, _hosting=True)
    _audit(f"Hosting: new panel password for {user}")
    return {"ok": True}


def _mailboxes(domains: list[str]) -> list[str]:
    try:
        from . import mail
        return sorted(x for x in mail.load()["accounts"] if x.split("@")[1] in domains)
    except Exception:
        return []


def suspend(user: str, on: bool, reason: str = "") -> dict:
    """Websites off, panel login off, mailbox sign-in off — and back exactly as it was."""
    d = load()
    a = _visible(d, user)
    if bool(a.get("suspended")) == bool(on):
        return {"ok": True}
    from . import panelusers, sites
    if on:
        a["sites_disabled"] = []
        for dom in a["sites"]:
            try:
                if sites.get_site(dom)["settings"].get("enabled", True):
                    sites.quick_toggle(dom, "enabled", False)
                    a["sites_disabled"].append(dom)
            except Exception as e:
                print(f"hosting: {dom}: {e}", flush=True)
    else:
        for dom in a.pop("sites_disabled", a["sites"]):
            try:
                sites.quick_toggle(dom, "enabled", True)
            except Exception as e:
                print(f"hosting: {dom}: {e}", flush=True)
    panelusers.update(user, disabled=on, _hosting=True)
    try:
        from . import mail
        accs = mail.load()["accounts"]
        if on:
            # Remember which mailboxes this switched off, so unsuspending leaves ones an admin
            # had suspended on purpose as they were.
            mine = [x for x in _mailboxes(a["sites"]) if not (accs.get(x, {}).get("suspend") or {}).get("login")]
            for addr in mine:
                mail.update_account(addr, suspend={"login": True})
            a["mail_suspended"] = mine
        else:
            for addr in a.pop("mail_suspended", []):
                if addr in accs:
                    mail.update_account(addr, suspend={"login": False})
    except Exception as e:
        print(f"hosting: mail suspend: {e}", flush=True)
    a["suspended"] = bool(on)
    a["suspend_reason"] = (reason or "").strip()[:200] if on else ""
    a["suspended_at"] = int(time.time()) if on else 0
    _save(d)
    _audit(f"Hosting: {'suspended' if on else 'unsuspended'} {user}")
    return {"ok": True}


def _teardown(user: str, domains: list[str], keep_files: bool, log=print) -> None:
    from . import isolate, panelusers, sites
    for dom in domains:
        isolate._removing_account[dom] = True
        try:
            try:
                isolate.disable(dom)
            except Exception as e:
                log(f"  {dom}: {e}")
            try:
                sites.remove_site(dom)
            except Exception as e:
                log(f"  {dom}: {e}")
        finally:
            isolate._removing_account.pop(dom, None)
    try:
        panelusers.delete(user, _hosting=True)
    except Exception:
        pass
    _run(["pkill", "-u", user])
    _run(["gpasswd", "-d", "www-data", user])
    if keep_files:
        _run(["userdel", user])
    else:
        _run(["userdel", "--remove", user])
    _run(["groupdel", user])


def terminate(user: str, keep_files: bool = False, delete_mail: bool = True, delete_databases: bool = True) -> dict:
    d = load()
    a = _visible(d, user)
    if delete_mail:
        try:
            from . import mail
            for addr in _mailboxes(a["sites"]):
                mail.delete_account(addr, delete_mail=True)
        except Exception as e:
            print(f"hosting: mail: {e}", flush=True)
    if delete_databases:
        for db in my_databases(user, _d=d)["databases"]:
            try:
                db_drop(user, db["name"], _d=d)
            except Exception as e:
                print(f"hosting: {db['name']}: {e}", flush=True)
        for u in my_databases(user, _d=d)["users"]:
            try:
                from . import databases
                databases.mysql_drop_user(u, "localhost")
            except Exception:
                pass
    _teardown(user, a["sites"], keep_files)
    d = load()
    d["accounts"].pop(user, None)
    d["usage"].pop(user, None)
    _save(d)
    _audit(f"Hosting: terminated {user}{' (files kept)' if keep_files else ''}")
    return {"ok": True}


# ------------------------------------------------------------------ the account's own databases
def _me() -> str:
    c = _caller()
    if c.get("role") != "site" or not c.get("account"):
        raise HostingError("This is for hosting accounts")
    return c["account"]


def _db_name(user: str, name: str) -> str:
    name = (name or "").strip().lower()
    full = name if name.startswith(user + "_") else f"{user}_{name}"
    if not re.fullmatch(r"[a-z0-9_]{1,64}", full) or full == user + "_":
        raise HostingError(f"Name: letters, digits and _ (it becomes {user}_<name>)")
    if len(full) > 32:
        raise HostingError("Keep it under 32 characters including the prefix")
    return full


def my_databases(user: str = "", _d: dict | None = None) -> dict:
    user = user or _me()
    from . import databases
    if not databases.mysql_available():
        return {"available": False, "databases": [], "users": [], "prefix": user + "_"}
    ov = databases.mysql_overview()
    dbs = [x for x in ov["databases"] if x["name"].startswith(user + "_")]
    users = [u["user"] for u in ov["users"] if u["user"].startswith(user + "_") and u["host"] == "localhost"]
    d = _d or load()
    lim = d["plans"].get(d["accounts"].get(user, {}).get("plan", ""), {})
    return {"available": True, "databases": dbs, "users": users, "prefix": user + "_", "limit": lim.get("databases", 0)}


def db_create(name: str, password: str, user: str = "") -> dict:
    """One database plus a user of the same name with full access to it (the common case)."""
    user = user or _me()
    d = load()
    lim = d["plans"].get(d["accounts"].get(user, {}).get("plan", ""), {})
    have = my_databases(user, _d=d)
    if lim.get("databases") and len(have["databases"]) >= lim["databases"]:
        raise HostingError(f"Your plan allows {lim['databases']} database(s)")
    full = _db_name(user, name)
    from . import databases
    databases.mysql_wizard(full, full, password, "localhost")
    _audit(f"Hosting: {user} created database {full}")
    return {"ok": True, "database": full, "user": full, "host": "localhost"}


def db_drop(user: str, name: str, _d: dict | None = None) -> dict:
    full = _db_name(user, name)
    from . import databases
    databases.mysql_drop_db(full)
    try:
        databases.mysql_drop_user(full, "localhost")
    except Exception:
        pass
    _audit(f"Hosting: dropped database {full}")
    return {"ok": True}


def db_password(name: str, password: str) -> dict:
    user = _me()
    full = _db_name(user, name)
    from . import databases
    databases.mysql_set_password(full, "localhost", password)
    return {"ok": True}


def me() -> dict:
    """A hosting account's own page: plan, usage and limits."""
    user = _me()
    d = load()
    a = d["accounts"].get(user)
    if not a:
        raise HostingError("This account no longer exists")
    return {"user": user, "plan": a["plan"], "limits": d["plans"].get(a["plan"], {}), "usage": d["usage"].get(user, {}),
            "sites": a["sites"], "home": str(HOME / user), "labels": LIMITS}


# ------------------------------------------------------------------ limits enforced elsewhere
def account_of_domain(domain: str) -> str:
    domain = (domain or "").lower()
    for user, a in load()["accounts"].items():
        if domain in a["sites"]:
            return user
    return ""


def check_mailbox_limit(address: str) -> None:
    """Called before a mailbox is created: an account's plan caps its email accounts."""
    dom = address.split("@")[-1].lower()
    user = account_of_domain(dom)
    if not user:
        return
    d = load()
    a = d["accounts"][user]
    lim = d["plans"].get(a["plan"], {}).get("mailboxes", 0)
    if lim and len(_mailboxes(a["sites"])) >= lim:
        raise HostingError(f"The {a['plan']} plan allows {lim} email account(s) for {user}")


# ------------------------------------------------------------------ usage (task runner, hourly)
def _du(path: Path) -> int:
    r = _run(["du", "-sb", str(path)], 600)
    try:
        return int(r.stdout.split()[0])
    except (IndexError, ValueError):
        return 0


def measure() -> dict:
    """Disk (home + mail + databases) and this month's bandwidth for every account; alerts if over."""
    d = load()
    if not d["accounts"]:
        return {}
    db_sizes = {}
    try:
        from . import databases
        if databases.mysql_available():
            for name, size in databases._my_rows("SELECT table_schema, COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables GROUP BY table_schema;"):
                db_sizes[name] = int(float(size or 0))
    except Exception:
        pass
    vmail = Path("/var/vmail")
    for user, a in d["accounts"].items():
        disk = _du(HOME / user)
        mail_b = sum(_du(vmail / dom) for dom in a["sites"] if (vmail / dom).exists())
        dbs = sum(v for k, v in db_sizes.items() if k.startswith(user + "_"))
        d["usage"][user] = {"disk_bytes": disk + mail_b + dbs, "files_bytes": disk, "mail_bytes": mail_b, "db_bytes": dbs,
                            "bandwidth_bytes": _month_bytes(a["sites"]), "mailboxes": len(_mailboxes(a["sites"])),
                            "measured": int(time.time())}
    _save(d)
    return d["usage"]


def over_limits() -> dict[str, tuple]:
    """For alerts: key -> (level, title, text) for accounts over their disk or bandwidth."""
    d = load()
    out = {}
    for user, a in d["accounts"].items():
        u, lim = d["usage"].get(user, {}), d["plans"].get(a["plan"], {})
        if lim.get("disk_mb") and u.get("disk_bytes", 0) > lim["disk_mb"] * 1048576:
            out[f"quota:{user}"] = ("warning", f"Hosting account {user} is over its disk space",
                                    f"{u['disk_bytes'] / 1048576:.0f} MB used of {lim['disk_mb']} MB ({a['plan']}). Upgrade the plan or ask them to clean up.")
        if lim.get("bandwidth_gb") and u.get("bandwidth_bytes", 0) > lim["bandwidth_gb"] * 1e9:
            out[f"bw:{user}"] = ("warning", f"Hosting account {user} is over its monthly bandwidth",
                                 f"{u['bandwidth_bytes'] / 1e9:.1f} GB this month of {lim['bandwidth_gb']} GB ({a['plan']}).")
    return out


def _audit(action: str) -> None:
    try:
        from . import audit, authz
        c = authz.current() or {}
        audit.record(c.get("username") or "admin", "", action, method="HOSTING", path="/hosting")
    except Exception:
        pass
