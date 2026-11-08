"""Databases: MariaDB/MySQL + PostgreSQL management, plus phpMyAdmin/phpPgAdmin
detection. The panel runs as root, so it reaches MariaDB via unix-socket auth
and PostgreSQL by running psql as the postgres role.
"""
from __future__ import annotations

import glob
import platform
import re
import shutil
import subprocess
from pathlib import Path

from . import distro
from . import jobs

IS_LINUX = platform.system() == "Linux"
_IDENT = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_HOST = re.compile(r"^[A-Za-z0-9_%.:-]{1,60}$")
_MYSQL_SYS = {"mysql", "information_schema", "performance_schema", "sys"}
_PG_SYS = {"postgres", "template0", "template1"}


class DatabaseError(RuntimeError):
    pass


def _ident(name: str, what: str = "name") -> str:
    if not _IDENT.match(name or ""):
        raise DatabaseError(f"Invalid {what} (letters, digits, underscore; max 64)")
    return name


def _password(pw: str) -> str:
    if not pw or len(pw) < 6 or len(pw) > 128:
        raise DatabaseError("Password must be 6–128 characters")
    if any(c in pw for c in "'\"\\`;\n\r"):
        raise DatabaseError("Password may not contain quotes, backslash, backtick, semicolon or newlines")
    return pw


# =========================== MariaDB / MySQL ===============================
_MY_SERVER_PKGS = ("mariadb-server", "mysql-server", "default-mysql-server")
_MY_UNITS = ("mariadb", "mysql")


def mysql_status() -> dict:
    """Is a MariaDB/MySQL *server* installed and running? The mysql client alone (pulled in
    by phpMyAdmin, PHP, …) isn't enough: without the server every query fails with
    "Can't connect to local server through socket '/run/mysqld/mysqld.sock'"."""
    st = {"installed": False, "running": False, "broken": False}
    if not IS_LINUX:
        return st
    if shutil.which("dpkg-query"):
        out = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\n", *_MY_SERVER_PKGS],
                             capture_output=True, text=True, timeout=15)
        flags = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        st["installed"] = any(f.startswith("ii") for f in flags)
        # e.g. "iF" (half-configured) / "iU" (unpacked): an install that failed part-way.
        st["broken"] = not st["installed"] and any(f[:1] == "i" and f[1:2] not in ("i", "n") for f in flags)
    else:
        st["installed"] = bool(shutil.which("mariadbd") or shutil.which("mysqld") or Path("/usr/sbin/mariadbd").exists())
    if st["installed"] or st["broken"]:
        r = subprocess.run(["systemctl", "is-active", *_MY_UNITS], capture_output=True, text=True, timeout=10)
        st["running"] = "active" in r.stdout.split()
    return st


def mysql_require():
    if not IS_LINUX:
        raise DatabaseError("MariaDB/MySQL management is only available on Linux")
    st = mysql_status()
    if st["broken"]:
        raise DatabaseError("MariaDB's installation didn't finish. Click Repair in System Applications → Extras "
                            "(or the Repair button on the Databases page).")
    if not st["installed"]:
        raise DatabaseError("MariaDB isn't installed on this Pi. Install it from System Applications → Extras "
                            "(or the Install button on the Databases page).")
    if not st["running"]:
        raise DatabaseError("MariaDB is installed but not running. Start it from System Applications → Extras.")
    if not shutil.which("mysql"):
        raise DatabaseError("The MariaDB client (mysql) is missing — reinstall MariaDB from System Applications.")


def mysql_available() -> bool:
    st = mysql_status()
    return bool(st["installed"] and st["running"] and shutil.which("mysql"))


def _mysql(sql: str) -> str:
    mysql_require()
    out = subprocess.run(["mysql", "-N", "-B", "-e", sql], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise DatabaseError(out.stderr.strip() or "MySQL command failed")
    return out.stdout


_MY_BUILTIN_USERS = {"root", "mysql", "mariadb.sys", "debian-sys-maint", "mysql.sys", "mysql.session", "mysql.infoschema"}
# Created by the phpmyadmin package (its own settings storage) — managing them here would break phpMyAdmin.
_MY_APP_OWNED = {"phpmyadmin"}


def _my_rows(sql: str) -> list[list[str]]:
    return [line.split("\t") for line in _mysql(sql).splitlines() if line]


def _my_unescape(s: str) -> str:
    # mysql -B escapes backslashes; mysql.db stores `a_b` grants as a\_b (phpMyAdmin style).
    return s.replace("\\\\", "\\").replace("\\_", "_").replace("\\%", "%")


def _my_account(user: str, host: str) -> str:
    if not re.match(r"^[A-Za-z0-9_.-]{1,80}$", user or ""):
        raise DatabaseError("Invalid username (letters, digits, underscore, dot, dash)")
    if not _HOST.match(host or ""):
        raise DatabaseError("Invalid host")
    return f"`{user}`@`{host}`"


def _my_user_exists(user: str, host: str) -> bool:
    return bool(_my_rows(f"SELECT 1 FROM mysql.user WHERE User='{user}' AND Host='{host}';"))


def _my_protected(user: str) -> bool:
    return user in _MY_BUILTIN_USERS or user in _MY_APP_OWNED


def mysql_databases() -> list[dict]:
    return [{"name": n, "system": n in _MYSQL_SYS} for (n, *_) in _my_rows("SHOW DATABASES;")]


def mysql_users() -> list[dict]:
    return [{"user": u, "host": h} for u, h in _my_rows("SELECT User, Host FROM mysql.user;")]


def mysql_overview() -> dict:
    """Databases (size, tables, charset, who has access) and users (password, admin, databases)."""
    sizes = {r[0]: (int(float(r[1] or 0)), int(r[2] or 0)) for r in _my_rows(
        "SELECT table_schema, COALESCE(SUM(data_length + index_length), 0), COUNT(*) "
        "FROM information_schema.tables GROUP BY table_schema;")}
    access: dict[str, list[str]] = {}
    for db, u, h in _my_rows("SELECT Db, User, Host FROM mysql.db;"):
        access.setdefault(_my_unescape(db), []).append(f"{u}@{h}")
    dbs = []
    for name, charset in _my_rows("SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME;"):
        size, tables = sizes.get(name, (0, 0))
        dbs.append({"name": name, "system": name in _MYSQL_SYS, "app": "phpMyAdmin" if name in _MY_APP_OWNED else "",
                    "size": _human(size), "tables": tables, "charset": charset,
                    "access": sorted(access.get(name, []))})
    users = []
    for u, h, auth, priv_super, priv_grant in _my_rows(
            "SELECT User, Host, authentication_string, Super_priv, Grant_priv FROM mysql.user ORDER BY User, Host;"):
        acct = f"{u}@{h}"
        users.append({"user": u, "host": h, "account": acct,
                      "has_password": auth not in ("", "invalid") and not auth.startswith("*THISISNOTAVALIDPASSWORD"),
                      "admin": priv_super == "Y", "can_grant": priv_grant == "Y",
                      "databases": sorted(d for d, accts in access.items() if acct in accts),
                      "system": u in _MY_BUILTIN_USERS, "app": "phpMyAdmin" if u in _MY_APP_OWNED else ""})
    return {"databases": dbs, "users": users}


def _human(n: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def mysql_create_db(name: str) -> dict:
    _ident(name, "database name")
    if _my_rows(f"SHOW DATABASES LIKE '{name.replace('_', chr(92) + '_')}';"):
        raise DatabaseError(f"A database named {name} already exists")
    _mysql(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4;")
    return {"ok": True}


def mysql_drop_db(name: str) -> dict:
    _ident(name, "database name")
    if name in _MYSQL_SYS:
        raise DatabaseError("Refusing to drop a system database")
    if name in _MY_APP_OWNED:
        raise DatabaseError("This database stores phpMyAdmin's own settings — remove phpMyAdmin instead")
    _mysql(f"DROP DATABASE `{name}`;")
    # Database-level grants outlive the database in mysql.db; clear them so a new database
    # with the same name doesn't silently inherit the old users.
    for u, h in _my_rows(f"SELECT User, Host FROM mysql.db WHERE Db IN ('{name}', '{name.replace('_', chr(92) * 2 + '_')}');"):
        _mysql(f"REVOKE ALL PRIVILEGES ON `{name}`.* FROM {_my_account(u, h)};")
    return {"ok": True}


def mysql_create_user(user: str, host: str, password: str, db: str = "", admin: bool = False) -> dict:
    acct = _my_account(user, host)
    _password(password)
    if db:
        _ident(db, "database name")
    if _my_user_exists(user, host):
        raise DatabaseError(f"The user {user}@{host} already exists")
    _mysql(f"CREATE USER {acct} IDENTIFIED BY '{password}';")
    if db:
        _mysql(f"GRANT ALL PRIVILEGES ON `{db}`.* TO {acct};")
    if admin:
        _mysql(f"GRANT ALL PRIVILEGES ON *.* TO {acct} WITH GRANT OPTION;")
    return {"ok": True, "user": f"{user}@{host}"}


def _my_manageable(user: str, host: str) -> str:
    acct = _my_account(user, host)
    if user in _MY_APP_OWNED:
        raise DatabaseError(f"{user} is phpMyAdmin's own account — changing it would break phpMyAdmin")
    if _my_protected(user):
        raise DatabaseError(f"{user} is a built-in account — it can't be changed here")
    if not _my_user_exists(user, host):
        raise DatabaseError(f"No such user {user}@{host}")
    return acct


def mysql_set_password(user: str, host: str, password: str) -> dict:
    acct = _my_manageable(user, host)
    _password(password)
    _mysql(f"ALTER USER {acct} IDENTIFIED BY '{password}';")
    return {"ok": True}


def mysql_drop_user(user: str, host: str) -> dict:
    _mysql(f"DROP USER {_my_manageable(user, host)};")
    return {"ok": True}


def mysql_grant(db: str, user: str, host: str, on: bool) -> dict:
    """Full access (all privileges) to one database — or take it away."""
    _ident(db, "database name")
    acct = _my_manageable(user, host)
    if on:
        _mysql(f"GRANT ALL PRIVILEGES ON `{db}`.* TO {acct};")
    elif _my_rows(f"SELECT 1 FROM mysql.db WHERE User='{user}' AND Host='{host}' AND Db IN ('{db}', '{db.replace('_', chr(92) * 2 + '_')}');"):
        _mysql(f"REVOKE ALL PRIVILEGES ON `{db}`.* FROM {acct};")
    return {"ok": True}


def mysql_set_admin(user: str, host: str, on: bool) -> dict:
    """Admin = every privilege on every database (what phpMyAdmin needs for full control).
    Revoking only touches the global level, so per-database access stays."""
    acct = _my_manageable(user, host)
    if on:
        _mysql(f"GRANT ALL PRIVILEGES ON *.* TO {acct} WITH GRANT OPTION;")
    else:
        _mysql(f"REVOKE ALL PRIVILEGES ON *.* FROM {acct}; REVOKE GRANT OPTION ON *.* FROM {acct};")
    return {"ok": True}


def mysql_wizard(db: str, user: str, password: str, host: str = "localhost") -> dict:
    """Create a database + user and grant the user full access to it."""
    _ident(db, "database name")
    acct = _my_account(user, host)
    _password(password)
    if _my_rows(f"SHOW DATABASES LIKE '{db.replace('_', chr(92) + '_')}';"):
        raise DatabaseError(f"A database named {db} already exists — pick another name, or give a user access to it in Manage Databases")
    if _my_user_exists(user, host):
        raise DatabaseError(f"The user {user}@{host} already exists — pick another name, or give it access in Manage Databases")
    _mysql(f"CREATE DATABASE `{db}` CHARACTER SET utf8mb4;")
    _mysql(f"CREATE USER {acct} IDENTIFIED BY '{password}';")
    _mysql(f"GRANT ALL PRIVILEGES ON `{db}`.* TO {acct};")
    return {"ok": True, "database": db, "user": f"{user}@{host}"}


def _apache_state() -> dict:
    """Is Apache serving, and if not, which other web server holds port 80 (nginx, Caddy, hiawatha, ...)?

    phpMyAdmin and phpPgAdmin are Apache aliases: when another server owns port 80, Apache can't start
    and their /phpmyadmin or /phppgadmin link answers 404 from that other server instead."""
    if not IS_LINUX:
        return {"apache": False, "other": None}
    import re
    from . import problems, sysapps
    apache, other = False, None
    try:
        apache = bool(sysapps._active(["apache2"]).get("apache2"))
        other = None if apache else sysapps._running_web_server("apache")
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    if not apache and not other and shutil.which("ss"):
        try:  # not one of the catalogued servers: ask the kernel who listens on port 80
            out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                if re.search(r":80\s", line):
                    m = re.search(r'users:\(\("([^"]+)"', line)
                    if m and m.group(1) != "apache2":
                        other = m.group(1)
                        break
        except (OSError, subprocess.SubprocessError) as quiet_exc:
            problems.quiet(quiet_exc)
    return {"apache": apache, "other": other}


def _web_tool_done(log, tool: str, path: str, ready_hint: str) -> dict:
    """The last line of a phpMyAdmin / phpPgAdmin install: 'ready' only if Apache really serves it.
    Otherwise say who holds port 80 and what to do, instead of a green tick that leads to a 404."""
    st = _apache_state()
    if not st["apache"] and IS_LINUX:
        subprocess.run(["systemctl", "start", "apache2"], capture_output=True, timeout=60)  # a plain restart may be all it needs
        st = _apache_state()
    if st["apache"]:
        log(f"✔ {tool} is ready at {path} — {ready_hint}")
        return {"ok": True, "reachable": True}
    who = f"{st['other']} is on port 80 instead of Apache" if st["other"] else "Apache isn't running"
    log(f"⚠ {tool} is installed, but {who}, so {path} can't be opened yet. Stop that server or move it off port 80, "
        f"start Apache under System Applications, then open {path}.")
    return {"ok": True, "reachable": False, "other": st["other"]}


def phpmyadmin_status() -> dict:
    st = _apache_state()
    return {"installed": phpmyadmin_installed(), "path": "/phpmyadmin",
            "enabled": Path("/etc/apache2/conf-enabled/phpmyadmin.conf").exists(),
            "apache": st["apache"], "other": st["other"]}


def phpmyadmin_install() -> jobs.Job:
    """apt-get install phpmyadmin, answering its setup questions: configure Apache and
    let dbconfig-common create phpMyAdmin's settings database over the root socket."""
    mysql_require()
    if not shutil.which("apache2ctl"):
        raise DatabaseError("phpMyAdmin needs Apache — install it in System Applications first")

    def fn(log):
        seed = ("phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2\n"
                "phpmyadmin phpmyadmin/dbconfig-install boolean true\n")
        subprocess.run(["debconf-set-selections"], input=seed, text=True, capture_output=True, timeout=30)
        log("• Installing phpMyAdmin (apt-get install phpmyadmin)…")
        log("• Refreshing package lists (apt-get update)…")
        if log.apt(["update"], (1, 10)) != 0:
            log("  Some package lists couldn't be refreshed; trying the install anyway.")
        if log.apt(["install", "phpmyadmin"], (10, 95)) != 0:
            raise DatabaseError("apt-get install phpmyadmin failed")
        if not Path("/etc/apache2/conf-enabled/phpmyadmin.conf").exists() and Path("/etc/apache2/conf-available/phpmyadmin.conf").exists():
            subprocess.run(["a2enconf", "phpmyadmin"], capture_output=True, text=True, timeout=30)
        from . import webaccess
        webaccess._reload_apache()
        _web_tool_done(log, "phpMyAdmin", "/phpmyadmin", "log in with a user that has a password.")
        return phpmyadmin_status()

    return jobs.launch_fn("install phpMyAdmin", fn)


# =============================== PostgreSQL =================================
PG_USER = "postgres"


def _pg_user_exists() -> bool:
    try:
        import pwd
        pwd.getpwnam(PG_USER)
        return True
    except (ImportError, KeyError):
        return False


def pg_status() -> dict:
    """Is the server installed (Debian layout: /usr/lib/postgresql/NN) and is a cluster online?"""
    installed = (IS_LINUX and bool(shutil.which("psql")) and bool(glob.glob("/usr/lib/postgresql/*/bin/postgres"))
                 and _pg_user_exists())
    running = False
    if installed and shutil.which("pg_lsclusters"):
        out = subprocess.run(["pg_lsclusters", "-h"], capture_output=True, text=True, timeout=10)
        # columns: ver cluster port status owner datadir log
        running = any(len(c) > 3 and c[3].startswith("online") for c in (l.split() for l in out.stdout.splitlines()))
    return {"installed": installed, "running": running}


def pg_repair() -> dict:
    """Give every cluster's data directory back to the postgres role (fixes 'could not
    open file "global/pg_filenode.map": Permission denied' after a stray chown), then restart."""
    if not pg_status()["installed"] or not shutil.which("pg_lsclusters"):
        raise DatabaseError("PostgreSQL is not installed")
    out = subprocess.run(["pg_lsclusters", "-h"], capture_output=True, text=True, timeout=10)
    datadirs = [c[5] for c in (l.split() for l in out.stdout.splitlines()) if len(c) > 5]
    paths = [p for p in ["/var/lib/postgresql", *datadirs] if Path(p).exists()]
    logs = [p for p in ["/var/log/postgresql"] if Path(p).exists()]
    subprocess.run(["systemctl", "stop", "postgresql"], capture_output=True, text=True, timeout=60)
    for p in paths:
        subprocess.run(["chown", "-R", "postgres:postgres", p], capture_output=True, text=True, timeout=120)
    for p in datadirs:
        subprocess.run(["chmod", "700", p], capture_output=True, text=True, timeout=10)
    for p in logs:
        subprocess.run(["chown", "-R", "postgres:adm", p], capture_output=True, text=True, timeout=60)
    r = subprocess.run(["systemctl", "start", "postgresql"], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise DatabaseError(r.stderr.strip() or "PostgreSQL failed to start after repair")
    return {"ok": True, "fixed": paths + logs, **pg_status()}


def pg_require():
    """Raise a readable error unless the PostgreSQL server is installed and running —
    instead of letting runuser fail with 'user postgres does not exist'."""
    if not IS_LINUX:
        raise DatabaseError("PostgreSQL management is only available on Linux")
    st = pg_status()
    if not st["installed"]:
        raise DatabaseError("PostgreSQL isn't installed on this Pi. Install it from System Applications → Extras "
                            "(or the Install button on the PostgreSQL Databases page).")
    if not st["running"]:
        raise DatabaseError("PostgreSQL is installed but not running. Start it from System Applications → Extras.")


def pg_available() -> bool:
    st = pg_status()
    return st["installed"] and st["running"] and _pg_runner() is not None


def _pg_runner() -> list[str] | None:
    if shutil.which("runuser"):
        return ["runuser", "-u", PG_USER, "--"]
    if shutil.which("su"):
        return ["su", "-s", "/bin/sh", PG_USER, "-c"]
    return None


def _psql(sql: str) -> str:
    pg_require()
    runner = _pg_runner()
    if not runner:
        raise DatabaseError("Cannot run psql as the postgres role")
    if runner[0] == "runuser":
        argv = runner + ["psql", "-tAc", sql]
        out = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    else:  # su -c takes a single shell string
        out = subprocess.run(runner + [f"psql -tAc \"{sql}\""], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise DatabaseError(out.stderr.strip() or "psql command failed")
    return out.stdout


def pg_databases() -> list[dict]:
    dbs = []
    for line in _psql("SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname;").splitlines():
        name = line.strip()
        if name:
            dbs.append({"name": name, "system": name in _PG_SYS})
    return dbs


def pg_roles() -> list[dict]:
    roles = []
    for line in _psql("SELECT rolname FROM pg_roles ORDER BY rolname;").splitlines():
        name = line.strip()
        if name:
            roles.append({"name": name, "system": name.startswith("pg_") or name == "postgres"})
    return roles


def pg_create_db(name: str) -> dict:
    _ident(name, "database name")
    _run_pg_sql(f'CREATE DATABASE "{name}";')
    return {"ok": True}


def pg_drop_db(name: str) -> dict:
    _ident(name, "database name")
    if name in _PG_SYS:
        raise DatabaseError("Refusing to drop a system database")
    _run_pg_sql(f'DROP DATABASE "{name}";')
    return {"ok": True}


def _run_pg_sql(sql_with_dquotes: str) -> str:
    """Run a statement whose identifiers are wrapped in real double quotes,
    handling the su-vs-runuser quoting difference."""
    pg_require()
    runner = _pg_runner()
    if not runner:
        raise DatabaseError("Cannot run psql as the postgres role")
    if runner[0] == "runuser":
        out = subprocess.run(runner + ["psql", "-tAc", sql_with_dquotes], capture_output=True, text=True, timeout=30)
    else:
        esc = sql_with_dquotes.replace('"', '\\"')
        out = subprocess.run(runner + [f'psql -tAc "{esc}"'], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise DatabaseError(out.stderr.strip() or "psql command failed")
    return out.stdout


# ---------------------------------------------------- PostgreSQL management
# Identifiers are restricted to [A-Za-z0-9_] by _ident() and passwords may not contain
# quotes (_password), so interpolating them into SQL below is safe.
_PG_PROTECTED = {"postgres"}


def _pg(sql: str, db: str | None = None) -> list[list[str]]:
    """Run one statement as the postgres superuser; rows as lists of columns."""
    pg_require()
    if not shutil.which("runuser"):
        raise DatabaseError("runuser is required to manage PostgreSQL")
    argv = ["runuser", "-u", PG_USER, "--", "psql", "-X", "-q", "-tA", "-F", "\t", "-v", "ON_ERROR_STOP=1"]
    if db:
        argv += ["-d", db]
    out = subprocess.run(argv + ["-c", sql], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        msg = out.stderr.strip()
        raise DatabaseError(re.sub(r"^(psql:[^:]*:\d+: )?ERROR:\s*", "", msg.splitlines()[0] if msg else "psql command failed"))
    return [line.split("\t") for line in out.stdout.splitlines() if line]


def _pg_role_name(name: str) -> str:
    _ident(name, "role name")
    if name.lower().startswith("pg_"):
        raise DatabaseError("Role names starting with pg_ are reserved by PostgreSQL")
    return name


def _pg_role_exists(name: str) -> bool:
    return bool(_pg(f"SELECT 1 FROM pg_roles WHERE rolname = '{name}'"))


def _pg_db_exists(name: str) -> bool:
    return bool(_pg(f"SELECT 1 FROM pg_database WHERE datname = '{name}'"))


def pg_overview() -> dict:
    """Databases (owner, size, encoding, who has access) and roles (attributes)."""
    dbs = []
    for r in _pg("SELECT d.datname, pg_get_userbyid(d.datdba), pg_size_pretty(pg_database_size(d.oid)), "
                 "pg_encoding_to_char(d.encoding), d.datistemplate, "
                 "(SELECT count(*) FROM pg_stat_activity a WHERE a.datname = d.datname), "
                 "coalesce((SELECT string_agg(DISTINCT g.rolname, ',') FROM aclexplode(d.datacl) x "
                 "  JOIN pg_roles g ON g.oid = x.grantee WHERE x.privilege_type = 'CREATE' AND g.oid <> d.datdba), '') "
                 "FROM pg_database d ORDER BY d.datistemplate, d.datname"):
        if len(r) < 7 or r[4] == "t":
            continue  # templates aren't user databases
        dbs.append({"name": r[0], "owner": r[1], "size": r[2], "encoding": r[3], "connections": int(r[5] or 0),
                    "access": [a for a in r[6].split(",") if a], "system": r[0] in _PG_SYS})
    roles = []
    for r in _pg("SELECT a.rolname, a.rolcanlogin, a.rolsuper, a.rolcreatedb, a.rolcreaterole, a.rolpassword IS NOT NULL, "
                 "a.rolconnlimit, coalesce((SELECT string_agg(d.datname, ',') FROM pg_database d WHERE d.datdba = a.oid "
                 "  AND NOT d.datistemplate), '') "
                 "FROM pg_authid a WHERE a.rolname NOT LIKE 'pg\\_%' ORDER BY a.rolname"):
        if len(r) < 8:
            continue
        roles.append({"name": r[0], "login": r[1] == "t", "superuser": r[2] == "t", "createdb": r[3] == "t",
                      "createrole": r[4] == "t", "has_password": r[5] == "t", "conn_limit": int(r[6]),
                      "owns": [d for d in r[7].split(",") if d], "system": r[0] in _PG_PROTECTED})
    return {"databases": dbs, "roles": roles}


def pg_create_db_owned(name: str, owner: str = "") -> dict:
    _ident(name, "database name")
    if _pg_db_exists(name):
        raise DatabaseError(f"Database {name} already exists")
    if owner:
        _ident(owner, "owner")
        if not _pg_role_exists(owner):
            raise DatabaseError(f"No role named {owner}")
    _pg(f'CREATE DATABASE "{name}"' + (f' OWNER "{owner}"' if owner else "") + " ENCODING 'UTF8' TEMPLATE template0")
    return {"ok": True}


def pg_drop_db_force(name: str) -> dict:
    _ident(name, "database name")
    if name in _PG_SYS:
        raise DatabaseError("Refusing to drop a system database")
    # WITH (FORCE) disconnects open sessions instead of failing (PostgreSQL 13+).
    _pg(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    return {"ok": True}


def pg_set_owner(db: str, role: str) -> dict:
    _ident(db, "database name")
    _ident(role, "role name")
    if db in _PG_SYS:
        raise DatabaseError("System databases stay owned by postgres")
    if not _pg_role_exists(role):
        raise DatabaseError(f"No role named {role}")
    _pg(f'ALTER DATABASE "{db}" OWNER TO "{role}"')
    # PostgreSQL 15+: the public schema belongs to pg_database_owner, so the new owner can
    # create tables; tables that already exist (e.g. made by postgres) still need a grant.
    if role not in _PG_PROTECTED:
        pg_grant(db, role, True)
    return {"ok": True}


def pg_grant(db: str, role: str, grant: bool = True) -> dict:
    """Full read/write access to a database for a role (or take it away)."""
    _ident(db, "database name")
    _pg_role_name(role)
    if db in _PG_SYS:
        raise DatabaseError("Grant access to your own databases, not the system ones")
    if not _pg_role_exists(role):
        raise DatabaseError(f"No role named {role}")
    # Default privileges apply to objects created by a given role, so cover the database
    # owner (who normally creates the tables) and postgres — not just whoever runs this.
    owner = (_pg(f"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '{db}'") or [[""]])[0][0]
    if not owner:
        raise DatabaseError(f"No database named {db}")
    creators = sorted({owner, "postgres"} - {role})
    if grant:
        _pg(f'GRANT ALL PRIVILEGES ON DATABASE "{db}" TO "{role}"')
        stmts = [f'GRANT ALL ON SCHEMA public TO "{role}"',
                 f'GRANT ALL ON ALL TABLES IN SCHEMA public TO "{role}"',
                 f'GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO "{role}"',
                 f'GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO "{role}"']
        for c in creators:  # tables/sequences created later are covered too
            stmts += [f'ALTER DEFAULT PRIVILEGES FOR ROLE "{c}" IN SCHEMA public GRANT ALL ON TABLES TO "{role}"',
                      f'ALTER DEFAULT PRIVILEGES FOR ROLE "{c}" IN SCHEMA public GRANT ALL ON SEQUENCES TO "{role}"']
        for stmt in stmts:
            _pg(stmt, db)
    else:
        for c in creators:
            _pg(f'ALTER DEFAULT PRIVILEGES FOR ROLE "{c}" IN SCHEMA public REVOKE ALL ON TABLES FROM "{role}"', db)
            _pg(f'ALTER DEFAULT PRIVILEGES FOR ROLE "{c}" IN SCHEMA public REVOKE ALL ON SEQUENCES FROM "{role}"', db)
        for stmt in (f'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM "{role}"',
                     f'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "{role}"',
                     f'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "{role}"',
                     f'REVOKE ALL ON SCHEMA public FROM "{role}"'):
            _pg(stmt, db)
        _pg(f'REVOKE ALL PRIVILEGES ON DATABASE "{db}" FROM "{role}"')
    return {"ok": True}


def pg_create_role(name: str, password: str, login: bool = True, createdb: bool = False,
                   createrole: bool = False, superuser: bool = False) -> dict:
    _pg_role_name(name)
    if _pg_role_exists(name):
        raise DatabaseError(f"Role {name} already exists")
    opts = ["LOGIN" if login else "NOLOGIN", "CREATEDB" if createdb else "NOCREATEDB",
            "CREATEROLE" if createrole else "NOCREATEROLE", "SUPERUSER" if superuser else "NOSUPERUSER"]
    if login:
        _password(password)
        opts.append(f"PASSWORD '{password}'")
    _pg(f'CREATE ROLE "{name}" ' + " ".join(opts))
    return {"ok": True, "role": name}


def pg_update_role(name: str, login: bool, createdb: bool, createrole: bool, superuser: bool,
                   conn_limit: int = -1) -> dict:
    _pg_role_name(name)
    if name in _PG_PROTECTED:
        raise DatabaseError("The postgres role can't be changed here")
    if not _pg_role_exists(name):
        raise DatabaseError(f"No role named {name}")
    if not -1 <= int(conn_limit) <= 10000:
        raise DatabaseError("Connection limit: -1 (unlimited) to 10000")
    opts = ["LOGIN" if login else "NOLOGIN", "CREATEDB" if createdb else "NOCREATEDB",
            "CREATEROLE" if createrole else "NOCREATEROLE", "SUPERUSER" if superuser else "NOSUPERUSER",
            f"CONNECTION LIMIT {int(conn_limit)}"]
    _pg(f'ALTER ROLE "{name}" ' + " ".join(opts))
    return {"ok": True}


def pg_set_password(name: str, password: str) -> dict:
    _ident(name, "role name")
    _password(password)
    if not _pg_role_exists(name):
        raise DatabaseError(f"No role named {name}")
    _pg(f"ALTER ROLE \"{name}\" PASSWORD '{password}'")
    return {"ok": True}


def pg_drop_role(name: str) -> dict:
    """Drop a role; whatever it owns (databases, tables) is handed to postgres first."""
    _pg_role_name(name)
    if name in _PG_PROTECTED:
        raise DatabaseError("The postgres role can't be removed")
    if not _pg_role_exists(name):
        raise DatabaseError(f"No role named {name}")
    for (db,) in _pg(f"SELECT datname FROM pg_database WHERE datdba = (SELECT oid FROM pg_roles WHERE rolname = '{name}')"):
        _pg(f'ALTER DATABASE "{db}" OWNER TO postgres')
    # Objects and grants live per database: clean them up in every one we can connect to.
    for (db,) in _pg("SELECT datname FROM pg_database WHERE datallowconn"):
        _pg(f'REASSIGN OWNED BY "{name}" TO postgres', db)
        _pg(f'DROP OWNED BY "{name}"', db)
    _pg(f'DROP ROLE "{name}"')
    return {"ok": True}


# ------------------------------------------------------------- phpPgAdmin
# Debian's phppgadmin.conf says "Require local", so it only works from the Pi itself.
# This override (loaded after it) also lets in private networks: your LAN and VPN clients.
PGA_ACCESS_CONF = Path("/etc/apache2/conf-available/zz-aurora-phppgadmin.conf")
_PGA_ACCESS = """# Managed by AuroraPanel — lets phpPgAdmin be used from your local network / VPN
# (Debian's phppgadmin.conf only allows the Pi itself). Delete via the panel to undo.
<Directory /usr/share/phppgadmin>
    Require local
    Require ip 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7 fe80::/10
</Directory>
"""


def phppgadmin_status() -> dict:
    installed = phppgadmin_installed()
    enabled = Path("/etc/apache2/conf-enabled/phppgadmin.conf").exists()
    lan = (Path("/etc/apache2/conf-enabled") / PGA_ACCESS_CONF.name).exists()
    if installed and not lan:
        txt = ""
        try:
            txt = Path("/etc/apache2/conf-available/phppgadmin.conf").read_text(errors="replace")
        except OSError:
            pass
        lan = "Require local" not in txt  # someone opened it up by hand
    st = _apache_state()
    return {"installed": installed, "enabled": enabled, "lan": lan, "path": "/phppgadmin", "apache": st["apache"], "other": st["other"]}


def phppgadmin_set_lan(on: bool) -> dict:
    from .webaccess import _reload_apache
    if not IS_LINUX or not shutil.which("a2enconf"):
        raise DatabaseError("Apache is not installed")
    if on:
        PGA_ACCESS_CONF.write_text(_PGA_ACCESS)
        subprocess.run(["a2enconf", "-q", PGA_ACCESS_CONF.stem], capture_output=True, timeout=30)
    else:
        subprocess.run(["a2disconf", "-q", PGA_ACCESS_CONF.stem], capture_output=True, timeout=30)
        PGA_ACCESS_CONF.unlink(missing_ok=True)
    t = subprocess.run(["apache2ctl", "configtest"], capture_output=True, text=True, timeout=30)
    if t.returncode != 0:
        subprocess.run(["a2disconf", "-q", PGA_ACCESS_CONF.stem], capture_output=True, timeout=30)
        PGA_ACCESS_CONF.unlink(missing_ok=True)
        raise DatabaseError("Apache rejected the change, nothing was applied:\n" + t.stderr.strip()[-400:])
    _reload_apache()
    return {"ok": True, **phppgadmin_status()}


def phppgadmin_install() -> jobs.Job:
    """apt install phppgadmin, then open it to the local network."""
    def fn(log):
        # Refresh the package lists first: a stale index asks for a package build the mirror has
        # already replaced and the install dies with a 404 (seen with php-pgsql from packages.sury.org).
        log("• Refreshing package lists (apt-get update)…")
        if log.apt(["update"], (1, 10)) != 0:
            log("  Some package lists couldn't be refreshed; trying the install anyway.")
        log("• Installing phpPgAdmin (apt-get install phppgadmin php-pgsql)…")
        if log.apt(["install", "phppgadmin", "php-pgsql"], (10, 95)) != 0:
            raise DatabaseError("apt-get install failed. If it reported a 404, the package mirror is behind; try again in a few minutes.")
        log("• Allowing access from your local network…")
        phppgadmin_set_lan(True)
        return _web_tool_done(log, "phpPgAdmin", "/phppgadmin", "log in with a PostgreSQL role that has a password.")
    return jobs.launch_fn("Install phpPgAdmin", fn)


def pg_wizard(db: str, role: str, password: str) -> dict:
    _ident(db, "database name")
    _ident(role, "role name")
    _password(password)
    _run_pg_sql(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}';")
    _run_pg_sql(f"CREATE DATABASE \"{db}\" OWNER \"{role}\";")
    return {"ok": True, "database": db, "role": role}


# ============================= web admin tools =============================
def phpmyadmin_installed() -> bool:
    return any(Path(p).exists() for p in ("/usr/share/phpmyadmin", "/etc/phpmyadmin"))


def phppgadmin_installed() -> bool:
    return any(Path(p).exists() for p in ("/usr/share/phppgadmin", "/etc/phppgadmin"))


def overview() -> dict:
    return {
        "mysql": {"available": mysql_available()},
        "postgres": {"available": pg_available()},
        "phpmyadmin": phpmyadmin_status(),
        "phppgadmin": {"installed": phppgadmin_installed(), "path": "/phppgadmin"},
    }


def install_pkg(pkg: str) -> jobs.Job:
    if pkg not in ("phppgadmin", "phpmyadmin", "postgresql", "mariadb-server"):
        raise DatabaseError("Unsupported package")
    env = {"DEBIAN_FRONTEND": "noninteractive", "PATH": distro.PATH}
    return jobs.launch(f"install {pkg}", ["apt-get", "-y", "install", pkg], env=env)
