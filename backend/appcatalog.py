"""The app catalog for Applications: what each app is, where its latest release comes from, and
how it gets set up. apps.py does the common work (download, unpack, database, Apache, permissions).

kind:
  cli         fully set up here, admin account included (the app has a command-line installer)
  web         unpacked + database made; you finish in the app's own setup page (details are shown)
  static      nothing to set up (single-file tools, front-end kits)
  composer    created with Composer (PHP frameworks and libraries)
  unavailable listed so people know why it isn't offered
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import string
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from . import problems

UA = {"User-Agent": "AuroraPanel (+https://aurora51.com)"}

CATEGORIES = [
    {"id": "blogs", "name": "Blogs", "icon": "wand"},
    {"id": "cms", "name": "Portals / CMS", "icon": "globe"},
    {"id": "forums", "name": "Forums", "icon": "users"},
    {"id": "galleries", "name": "Image Galleries", "icon": "image"},
    {"id": "wikis", "name": "Wikis", "icon": "indexes"},
    {"id": "social", "name": "Social Networking", "icon": "users"},
    {"id": "ecommerce", "name": "E-Commerce", "icon": "token"},
    {"id": "erp", "name": "ERP", "icon": "dashboard"},
    {"id": "mail", "name": "Mails", "icon": "bell"},
    {"id": "analytics", "name": "Polls & Analytics", "icon": "radar"},
    {"id": "projects", "name": "Project Management", "icon": "calendar"},
    {"id": "education", "name": "Educational", "icon": "info"},
    {"id": "dbtools", "name": "DB Tools", "icon": "database"},
    {"id": "music", "name": "Music", "icon": "flame"},
    {"id": "rss", "name": "RSS", "icon": "link"},
    {"id": "files", "name": "File Management", "icon": "folder"},
    {"id": "frameworks", "name": "Frameworks", "icon": "terminal"},
    {"id": "other", "name": "Others", "icon": "apps"},
]


# --------------------------------------------------------------------------- #
# Release lookups
# --------------------------------------------------------------------------- #
def _get(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(url, headers={**UA, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _head(url: str) -> tuple[int, str]:
    """(size, final url) — follows redirects."""
    req = urllib.request.Request(url, method="HEAD", headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return int(r.headers.get("Content-Length") or 0), r.url
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return 0, url


def _vkey(v: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", v)]


def _gh(repo: str, asset: str | None) -> dict:
    d = json.loads(_get(f"https://api.github.com/repos/{repo}/releases/latest"))
    ver = (d.get("tag_name") or "").lstrip("v")
    if asset:
        rx = re.compile(asset)
        a = next((a for a in d.get("assets", []) if rx.search(a["name"])), None)
        if not a:
            raise RuntimeError(f"no release file matching {asset} in {repo} {ver}")
        out = {"version": ver, "url": a["browser_download_url"], "size": a.get("size"), "filename": a["name"]}
        sha = next((x for x in d.get("assets", []) if x["name"] == a["name"] + ".sha256"), None)
        if sha:
            try:
                out.update(checksum=_get(sha["browser_download_url"]).split()[0], algo="sha256")
            except Exception as quiet_exc:
                problems.quiet(quiet_exc)
        return out
    return {"version": ver, "url": d["zipball_url"], "filename": f"{repo.split('/')[1]}-{ver}.zip"}


def _src_wordpress(_):
    try:
        ver = json.loads(_get("https://api.wordpress.org/core/version-check/1.7/"))["offers"][0]["version"]
    except Exception:
        ver = None
    url = "https://wordpress.org/latest.zip"
    out = {"version": ver, "url": url, "filename": "wordpress.zip"}
    try:
        out.update(checksum=_get(url + ".sha1").split()[0], algo="sha1")
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    return out


def _src_phpbb(_):
    d = json.loads(_get("https://version.phpbb.com/phpbb/versions.json"))["stable"]
    branch = max(d, key=_vkey)
    v = d[branch]["current"]
    url = f"https://download.phpbb.com/pub/release/{branch}/{v}/phpBB-{v}.zip"
    out = {"version": v, "url": url}
    try:
        out.update(checksum=_get(url + ".sha256").split()[0], algo="sha256")
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    return out


def _src_joomla(_):
    d = json.loads(_get("https://downloads.joomla.org/api/v1/latest/cms"))
    v = max((b["version"] for b in d["branches"]), key=_vkey)
    return {"version": v, "url": f"https://github.com/joomla/joomla-cms/releases/download/{v}/Joomla_{v}-Stable-Full_Package.zip"}


def _src_mediawiki(_):
    idx = _get("https://releases.wikimedia.org/mediawiki/")
    for branch in sorted(set(re.findall(r'href="(1\.\d+)/"', idx)), key=_vkey, reverse=True):
        page = _get(f"https://releases.wikimedia.org/mediawiki/{branch}/")
        files = re.findall(rf"mediawiki-({re.escape(branch)}\.\d+)\.tar\.gz\"", page)
        if files:
            v = max(files, key=_vkey)
            return {"version": v, "url": f"https://releases.wikimedia.org/mediawiki/{branch}/mediawiki-{v}.tar.gz"}
    raise RuntimeError("no MediaWiki release found")


def _src_nextcloud(_):
    url = "https://download.nextcloud.com/server/releases/latest.zip"
    out = {"version": "latest", "url": url, "filename": "nextcloud.zip"}
    try:
        out.update(checksum=_get(url + ".sha256").split()[0], algo="sha256")
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
    return out


def resolve(app: dict) -> dict:
    s = app["source"]
    t = s["t"]
    if t == "fn":
        out = s["fn"](app)
    elif t == "gh":
        out = _gh(s["repo"], s.get("asset"))
    elif t == "url":
        size, final = _head(s["url"])
        m = re.search(s["ver"], final) if s.get("ver") else None
        out = {"version": m.group(1) if m else s.get("version", "latest"), "url": s["url"], "size": size,
               "filename": s.get("filename")}
    else:
        raise RuntimeError("unknown source")
    if not out.get("size") and t != "url":
        out["size"] = _head(out["url"])[0] or None
    return out


# --------------------------------------------------------------------------- #
# Helpers for installers
# --------------------------------------------------------------------------- #
def _php_str(v: str) -> str:
    return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _rand(n: int, chars: str = string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(chars) for _ in range(n))


def _host_port(ctx) -> tuple[str, int, str, str]:
    u = ctx.parts
    port = u.port or (443 if u.scheme == "https" else 80)
    return u.hostname, port, u.scheme, (u.path or "/")


def wp_version(path: Path) -> str | None:
    try:
        m = re.search(r"\$wp_version\s*=\s*'([^']+)'", (path / "wp-includes" / "version.php").read_text(errors="replace"))
        return m.group(1) if m else None
    except OSError:
        return None


def wp_db(path: Path) -> str | None:
    try:
        m = re.search(r"define\(\s*'DB_NAME'\s*,\s*'([^']+)'", (path / "wp-config.php").read_text(errors="replace"))
        return m.group(1) if m else None
    except OSError:
        return None


def _rmtree(ctx, name: str) -> None:
    p = ctx.dest / name
    if p.is_dir():
        shutil.rmtree(p, ignore_errors=True)
    elif p.exists():
        p.unlink()


# --------------------------------------------------------------------------- #
# Installers (ctx: see apps.Ctx)
# --------------------------------------------------------------------------- #
_WP_INSTALL_PHP = r"""<?php
define('WP_INSTALLING', true);
$u = parse_url(getenv('AP_URL'));
$_SERVER['HTTP_HOST'] = $u['host'] . (isset($u['port']) ? ':' . $u['port'] : '');
$_SERVER['REQUEST_URI'] = isset($u['path']) ? $u['path'] : '/';
$_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
if ($u['scheme'] === 'https') { $_SERVER['HTTPS'] = 'on'; }
require getenv('AP_DIR') . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
if (is_blog_installed()) { fwrite(STDERR, "already installed\n"); exit(2); }
$r = wp_install(getenv('AP_TITLE'), getenv('AP_USER'), getenv('AP_EMAIL'), (int) getenv('AP_PUBLIC'), '', wp_slash(getenv('AP_PASS')), getenv('AP_LANG') ?: '');
update_option('siteurl', getenv('AP_URL'));
update_option('home', getenv('AP_URL'));
echo "user_id=" . $r['user_id'] . "\n";
"""


def i_wordpress(ctx):
    ctx.log("• Writing wp-config.php (fresh security keys)…")
    sample = (ctx.dest / "wp-config-sample.php").read_text()
    for k, v in {"database_name_here": ctx.db, "username_here": ctx.db_user, "password_here": ctx.db_pass}.items():
        sample = sample.replace(f"'{k}'", _php_str(v))
    salt = string.ascii_letters + string.digits + "!@#$%^&*()-_[]{}<>~+=,.;:/?|"
    sample = re.sub(r"'put your unique phrase here'", lambda _: _php_str(_rand(64, salt)), sample)
    extra = ("\n/* Added by AuroraPanel */\n"
             "define( 'FS_METHOD', 'direct' );\n"
             "if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https' ) { $_SERVER['HTTPS'] = 'on'; }\n")
    sample = sample.replace("/* That's all, stop editing!", extra + "\n/* That's all, stop editing!")
    (ctx.dest / "wp-config.php").write_text(sample)
    os.chmod(ctx.dest / "wp-config.php", 0o640)
    if not ctx.o["setup"]:
        ctx.notes.append("Finish WordPress's “5-minute install” in your browser.")
        return
    ctx.log(f"• Running the WordPress installer (admin user “{ctx.o['admin_user']}”)…")
    with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as fh:
        fh.write(_WP_INSTALL_PHP)
    try:
        ctx.run([ctx.php, fh.name], 300, env={"AP_DIR": str(ctx.dest), "AP_URL": ctx.url, "AP_TITLE": ctx.o["title"],
                                             "AP_USER": ctx.o["admin_user"], "AP_EMAIL": ctx.o["admin_email"],
                                             "AP_PASS": ctx.o["admin_pass"], "AP_PUBLIC": "0" if ctx.o.get("hide_search") else "1",
                                             "AP_LANG": ""})
    finally:
        os.unlink(fh.name)


def i_phpbb(ctx):
    host, port, scheme, path = _host_port(ctx)
    o = ctx.o
    yml = f"""installer:
    admin:
        name: {json.dumps(o['admin_user'])}
        password: {json.dumps(o['admin_pass'])}
        email: {json.dumps(o['admin_email'])}
    board:
        lang: en
        name: {json.dumps(o['title'])}
        description: {json.dumps(o.get('tagline') or 'A phpBB forum on a Raspberry Pi')}
    database:
        dbms: mysqli
        dbhost: localhost
        dbport: ~
        dbuser: {json.dumps(ctx.db_user)}
        dbpasswd: {json.dumps(ctx.db_pass)}
        dbname: {json.dumps(ctx.db)}
        table_prefix: phpbb_
    email:
        enabled: false
        smtp_delivery: ~
        smtp_host: ~
        smtp_port: ~
        smtp_auth: ~
        smtp_user: ~
        smtp_pass: ~
    server:
        cookie_secure: {'true' if scheme == 'https' else 'false'}
        server_protocol: {scheme}://
        force_server_vars: false
        server_name: {json.dumps(host)}
        server_port: {port}
        script_path: {json.dumps(path)}
    extensions: []
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
        fh.write(yml)
    try:
        os.chmod(fh.name, 0o600)
        ctx.log("• Running the phpBB installer…")
        r = ctx.run([ctx.php, "install/phpbbcli.php", "install", fh.name], 900)
        if "error" in (r.stdout or "").lower() and "successfully" not in (r.stdout or "").lower():
            raise RuntimeError("phpBB installer: " + r.stdout[-800:])
    finally:
        os.unlink(fh.name)
    _rmtree(ctx, "install")


def i_joomla(ctx):
    o = ctx.o
    ctx.log("• Running the Joomla installer…")
    ctx.run([ctx.php, "installation/joomla.php", "install", "-n", f"--site-name={o['title']}", f"--admin-user={o['admin_user']}",
             f"--admin-username={o['admin_user']}", f"--admin-password={o['admin_pass']}", f"--admin-email={o['admin_email']}",
             "--db-type=mysqli", "--db-host=localhost", f"--db-user={ctx.db_user}", f"--db-pass={ctx.db_pass}",
             f"--db-name={ctx.db}", f"--db-prefix={_rand(4).lower()}_", "--db-encryption=0"], 900)
    _rmtree(ctx, "installation")


def i_mediawiki(ctx):
    host, port, scheme, path = _host_port(ctx)
    o = ctx.o
    server = f"{scheme}://{host}" + ("" if port in (80, 443) else f":{port}")
    user = o["admin_user"][:1].upper() + o["admin_user"][1:]  # MediaWiki user names start with a capital
    ctx.log("• Running the MediaWiki installer (takes a minute)…")
    ctx.run([ctx.php, "maintenance/run.php", "install", "--dbtype=mysql", "--dbserver=localhost", f"--dbname={ctx.db}",
             f"--dbuser={ctx.db_user}", f"--dbpass={ctx.db_pass}", f"--server={server}",
             f"--scriptpath={'' if path == '/' else path.rstrip('/')}", f"--pass={o['admin_pass']}", "--lang=en",
             o["title"], user], 1800)
    if user != o["admin_user"]:
        ctx.notes.append(f"MediaWiki capitalises user names: log in as “{user}”.")


def i_nextcloud(ctx):
    o = ctx.o
    data = ctx.make_data_dir()
    ctx.own()
    ctx.log("• Running the Nextcloud installer (a few minutes on a Pi)…")
    occ = [ctx.php, "-d", "memory_limit=1G", "occ"]
    ctx.run([*occ, "maintenance:install", "--database=mysql", "--database-host=localhost", f"--database-name={ctx.db}",
             f"--database-user={ctx.db_user}", f"--database-pass={ctx.db_pass}", f"--admin-user={o['admin_user']}",
             f"--admin-pass={o['admin_pass']}", f"--admin-email={o['admin_email']}", f"--data-dir={data}"], 1800, as_www=True)
    host = ctx.parts.hostname
    ctx.run([*occ, "config:system:set", "trusted_domains", "1", f"--value={host}"], 120, as_www=True)
    ctx.run([*occ, "config:system:set", "overwrite.cli.url", f"--value={ctx.url}"], 120, as_www=True)
    path = ctx.parts.path or "/"
    ctx.run([*occ, "config:system:set", "htaccess.RewriteBase", f"--value={path if path.endswith('/') else path + '/'}"], 120, as_www=True)
    ctx.run([*occ, "maintenance:update:htaccess"], 300, as_www=True)
    ctx.run([*occ, "background:cron"], 120, as_www=True)
    ctx.notes.append(f"Files are stored in {data} (outside the web folder).")


def i_dokuwiki(ctx):
    o = ctx.o
    ctx.log("• Writing DokuWiki's settings, admin account and permissions…")
    r = ctx.run([ctx.php, "-r", "echo password_hash(getenv('AP_PASS'), PASSWORD_BCRYPT);"], 60, env={"AP_PASS": o["admin_pass"]})
    conf = ctx.dest / "conf"
    (conf / "local.php").write_text(
        "<?php\n/* Written by AuroraPanel */\n"
        f"$conf['title'] = {_php_str(o['title'])};\n$conf['lang'] = 'en';\n$conf['license'] = 'cc-by-sa';\n"
        "$conf['useacl'] = 1;\n$conf['superuser'] = '@admin';\n$conf['disableactions'] = 'register';\n")
    name = re.sub(r"[:\n]", "", o["admin_user"])
    (conf / "users.auth.php").write_text(
        "# users.auth.php\n# <?php exit()?>\n# Don't modify the lines above\n#\n# login:passwordhash:Real Name:email:groups,comma,separated\n\n"
        f"{name.lower()}:{r.stdout.strip()}:{name}:{o['admin_email']}:admin,user\n")
    (conf / "acl.auth.php").write_text(
        "# acl.auth.php\n# <?php exit()?>\n# Don't modify the lines above\n#\n# Access Control Lists\n#\n"
        "*               @ALL          1\n*               @user         8\n")
    for f in ("users.auth.php", "acl.auth.php", "local.php"):
        os.chmod(conf / f, 0o640)
    _rmtree(ctx, "install.php")
    if name.lower() != name:
        ctx.notes.append(f"DokuWiki log-ins are lower case: “{name.lower()}”.")


def i_grav(ctx):
    o = ctx.o
    ctx.log("• Creating the Grav admin account…")
    ctx.run([ctx.php, "bin/plugin", "login", "newuser", "-n", "-u", o["admin_user"].lower(), "-p", o["admin_pass"],
             "-e", o["admin_email"], "-P", "b", "-N", o["admin_user"], "-t", "Administrator"], 300)
    site = ctx.dest / "user" / "config" / "site.yaml"
    try:
        t = site.read_text()
        site.write_text(re.sub(r"(?m)^title:.*$", "title: " + json.dumps(o["title"]), t, count=1))
    except OSError:
        pass


def i_freshrss(ctx):
    o = ctx.o
    ctx.log("• Running the FreshRSS installer…")
    ctx.run([ctx.php, "cli/do-install.php", f"--default-user={o['admin_user']}", f"--base-url={ctx.url}",
             f"--title={o['title']}", "--db-type=mysql", "--db-host=localhost", f"--db-user={ctx.db_user}",
             f"--db-password={ctx.db_pass}", f"--db-base={ctx.db}", "--db-prefix=freshrss_", "--auth-type=form",
             "--disable-update"], 600)
    ctx.run([ctx.php, "cli/create-user.php", f"--user={o['admin_user']}", f"--password={o['admin_pass']}",
             f"--email={o['admin_email']}"], 600)


def i_opencart(ctx):
    o = ctx.o
    for rel in ("config-dist.php", "admin/config-dist.php"):
        p = ctx.dest / rel
        if p.exists():
            p.rename(p.with_name("config.php"))
    ctx.log("• Running the OpenCart installer…")
    ctx.run([ctx.php, "install/cli_install.php", "install", "--username", o["admin_user"], "--email", o["admin_email"],
             "--password", o["admin_pass"], "--http_server", ctx.url + "/", "--db_driver", "mysqli",
             "--db_hostname", "localhost", "--db_username", ctx.db_user, "--db_password", ctx.db_pass,
             "--db_database", ctx.db, "--db_port", "3306", "--db_prefix", "oc_"], 900)
    _rmtree(ctx, "install")


def i_concrete(ctx):
    o = ctx.o
    ctx.log("• Running the Concrete CMS installer (a few minutes)…")
    ctx.run([ctx.php, "-d", "memory_limit=1G", "concrete/bin/concrete", "c5:install", "-n", "--allow-as-root",
             "--db-server=localhost", f"--db-username={ctx.db_user}", f"--db-password={ctx.db_pass}",
             f"--db-database={ctx.db}", f"--site={o['title']}", "--starting-point=atomik_full",
             f"--admin-email={o['admin_email']}", f"--admin-password={o['admin_pass']}",
             f"--canonical-url={ctx.url}/", f"--timezone={_timezone()}"], 1800)
    ctx.notes.append("Concrete CMS names the first account “admin” — log in with that and your password.")


def _timezone() -> str:
    try:
        tz = subprocess.run(["timedatectl", "show", "-p", "Timezone", "--value"], capture_output=True, text=True, timeout=10).stdout.strip()
        return tz if re.match(r"^[A-Za-z_]+(/[A-Za-z0-9_+-]+)*$", tz) else "UTC"
    except Exception as quiet_exc:
        problems.quiet(quiet_exc)
        return "UTC"


def i_moodle(ctx):
    o = ctx.o
    data = ctx.make_data_dir()
    short = re.sub(r"[^A-Za-z0-9]", "", o["title"])[:20] or "Moodle"
    ctx.log("• Running the Moodle installer (this one takes 5–15 minutes on a Pi)…")
    ctx.run([ctx.php, "-d", "max_input_vars=5000", "-d", "memory_limit=1G", "admin/cli/install.php",
             "--non-interactive", "--agree-license", "--lang=en", f"--wwwroot={ctx.url}", f"--dataroot={data}",
             "--dbtype=mariadb", "--dbhost=localhost", f"--dbname={ctx.db}", f"--dbuser={ctx.db_user}",
             f"--dbpass={ctx.db_pass}", "--prefix=mdl_", f"--fullname={o['title']}", f"--shortname={short}",
             f"--adminuser={o['admin_user'].lower()}", f"--adminpass={o['admin_pass']}",
             f"--adminemail={o['admin_email']}"], 3600)
    _run_quiet(["chown", "-R", "www-data:www-data", str(data)])
    ctx.notes.append(f"Course files are stored in {data} (outside the web folder).")


def _run_quiet(argv):
    subprocess.run(argv, capture_output=True, timeout=600)


def i_roundcube(ctx):
    ctx.log("• Writing Roundcube's settings and creating its tables…")
    cfg = (
        "<?php\n/* Written by AuroraPanel */\n$config = [];\n"
        f"$config['db_dsnw'] = {_php_str(f'mysql://{ctx.db_user}:{ctx.db_pass}@localhost/{ctx.db}')};\n"
        "$config['imap_host'] = 'localhost:143';\n$config['smtp_host'] = 'localhost:587';\n"
        "$config['smtp_user'] = '%u';\n$config['smtp_pass'] = '%p';\n"
        f"$config['support_url'] = '';\n$config['product_name'] = {_php_str(ctx.o['title'])};\n"
        f"$config['des_key'] = {_php_str(_rand(24))};\n"
        "$config['plugins'] = ['archive', 'zipdownload'];\n$config['skin'] = 'elastic';\n")
    (ctx.dest / "config" / "config.inc.php").write_text(cfg)
    os.chmod(ctx.dest / "config" / "config.inc.php", 0o640)
    sql = ctx.dest / "SQL" / "mysql.initial.sql"
    with open(sql) as fh:
        r = subprocess.run(["mysql", ctx.db], stdin=fh, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError("Roundcube tables: " + r.stderr[-400:])
    _rmtree(ctx, "installer")
    ctx.notes.append("Roundcube is a webmail client: it logs in to a mail server (IMAP on localhost:143, SMTP on 587). "
                     "Without a mail server on this Pi, point imap_host/smtp_host in config/config.inc.php at yours.")


def i_phplist(ctx):
    cfg = ctx.dest / "config" / "config.php"
    t = cfg.read_text(errors="replace")
    for var, val in (("database_host", "localhost"), ("database_name", ctx.db), ("database_user", ctx.db_user),
                     ("database_password", ctx.db_pass)):
        t, n = re.subn(rf"(?m)^\${var}\s*=\s*'[^']*';", lambda _m, v=var, x=val: f"${v} = {_php_str(x)};", t)
        if not n:
            t += f"\n${var} = {_php_str(val)};\n"
    cfg.write_text(t)
    os.chmod(cfg, 0o640)
    ctx.notes.append("Open the admin page and click “Initialise database” to create phpList's tables and admin account.")


def i_smf(ctx):
    # GitHub's source keeps the installer files in other/; the release package moves them to the top.
    other = ctx.dest / "other"
    for f in ("install.php", "Settings.php", "Settings_bak.php", "install_2-1_mysql.sql", "db_last_error.php"):
        if (other / f).exists():
            shutil.copy2(other / f, ctx.dest / f)
    if not (ctx.dest / "install.php").exists():
        raise RuntimeError("SMF's installer (other/install.php) isn't in this release")


def i_seeddms(ctx):
    cfg = ctx.dest / "conf" / "settings.xml"
    path = (ctx.parts.path or "/").rstrip("/") + "/"
    t = cfg.read_text(errors="replace")
    t = re.sub(r'httpRoot = "[^"]*"', f'httpRoot = "{path}"', t, count=1)
    cfg.write_text(t)


def i_omeka(ctx):
    ini = ctx.dest / "db.ini"
    ini.write_text(f'[database]\nhost     = "localhost"\nusername = "{ctx.db_user}"\npassword = "{ctx.db_pass}"\n'
                   f'dbname   = "{ctx.db}"\nprefix   = "omeka_"\ncharset  = "utf8"\n')
    os.chmod(ini, 0o640)


def i_postfixadmin(ctx):
    (ctx.dest / "templates_c").mkdir(exist_ok=True)
    local = ctx.dest / "config.local.php"
    local.write_text(
        "<?php\n/* Written by AuroraPanel */\n$CONF['configured'] = true;\n$CONF['database_type'] = 'mysqli';\n"
        f"$CONF['database_host'] = 'localhost';\n$CONF['database_user'] = {_php_str(ctx.db_user)};\n"
        f"$CONF['database_password'] = {_php_str(ctx.db_pass)};\n$CONF['database_name'] = {_php_str(ctx.db)};\n")
    os.chmod(local, 0o640)
    ctx.notes.append("Open setup.php to set the setup password, create the tables and the first admin.")


def i_starter_bootstrap(ctx):
    (ctx.dest / "index.html").write_text(_STARTER.format(title=ctx.o["title"], css="css/bootstrap.min.css",
                                                         js="js/bootstrap.bundle.min.js", lib="Bootstrap",
                                                         body=_BS_BODY.format(title=ctx.o["title"])))


def i_starter_uikit(ctx):
    (ctx.dest / "index.html").write_text(_STARTER.format(title=ctx.o["title"], css="css/uikit.min.css",
                                                         js="js/uikit.min.js", lib="UIkit",
                                                         body=_UK_BODY.format(title=ctx.o["title"])))


_STARTER = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="{css}">
</head>
<body>
{body}
<script src="{js}"></script>
</body>
</html>
"""
_BS_BODY = """<main class="container py-5">
  <div class="p-5 mb-4 bg-body-tertiary rounded-3">
    <h1 class="display-5 fw-bold">{title}</h1>
    <p class="col-md-8 fs-5">Bootstrap is ready. Edit <code>index.html</code> in the File Manager to start building.</p>
    <a class="btn btn-primary btn-lg" href="https://getbootstrap.com/docs/">Bootstrap docs</a>
  </div>
</main>"""
_UK_BODY = """<div class="uk-section uk-section-muted"><div class="uk-container">
  <h1 class="uk-heading-medium">{title}</h1>
  <p class="uk-text-lead">UIkit is ready. Edit <code>index.html</code> in the File Manager to start building.</p>
  <a class="uk-button uk-button-primary" href="https://getuikit.com/docs/introduction">UIkit docs</a>
</div></div>"""


def i_composer_demo(lib: str, code: str):
    def f(ctx):
        (ctx.dest / "index.php").write_text(
            "<?php\nrequire __DIR__ . '/vendor/autoload.php';\n" + code +
            f"\n// {lib} is installed with Composer in vendor/. Edit this file to start.\n")
    return f


# --------------------------------------------------------------------------- #
# The catalog
# --------------------------------------------------------------------------- #
DB_EXTS = ["mysqli", "pdo_mysql"]
COMMON = ["curl", "gd", "mbstring", "dom", "zip", "intl"]

APPS: list[dict] = [
    # Blogs
    {"id": "wordpress", "name": "WordPress", "cat": "blogs", "kind": "cli", "db": True, "db_prefix": "wp",
     "tagline": "The publishing platform behind 40% of the web: blogs, shops and business sites.",
     "site": "https://wordpress.org", "exts": DB_EXTS + COMMON, "exts_required": ["mysqli"], "user_len": (3, 60),
     "source": {"t": "fn", "fn": _src_wordpress}, "install": i_wordpress, "admin_path": "/wp-admin/",
     "detect": ["wp-config.php", "wp-includes/version.php"], "color": "#21759b", "popular": True,
     "optional_setup": True},
    {"id": "grav", "name": "Grav", "cat": "blogs", "kind": "cli", "db": False,
     "tagline": "Fast flat-file CMS with an admin panel — no database needed.", "site": "https://getgrav.org",
     "exts": ["curl", "gd", "mbstring", "dom", "zip"], "strong_pw": True,
     "source": {"t": "url", "url": "https://getgrav.org/download/core/grav-admin/latest", "filename": "grav-admin.zip"},
     "install": i_grav, "admin_path": "/admin", "detect": ["system/defines.php", "bin/grav"], "color": "#221e1f"},
    # CMS
    {"id": "joomla", "name": "Joomla", "cat": "cms", "kind": "cli", "db": True, "db_prefix": "jml",
     "tagline": "Award-winning CMS for websites and powerful online applications.", "site": "https://www.joomla.org",
     "exts": DB_EXTS + COMMON, "user_len": (3, 40), "source": {"t": "fn", "fn": _src_joomla}, "install": i_joomla,
     "admin_path": "/administrator/", "detect": ["configuration.php", "administrator/index.php"], "color": "#5091cd", "popular": True},
    {"id": "drupal", "popular": True, "name": "Drupal", "cat": "cms", "kind": "web", "db": True, "db_prefix": "drp",
     "tagline": "Flexible, enterprise-grade CMS for ambitious sites.", "site": "https://www.drupal.org",
     "exts": DB_EXTS + COMMON, "source": {"t": "url", "url": "https://www.drupal.org/download-latest/tar.gz",
                                          "ver": r"drupal-([\d.]+)\.tar", "filename": "drupal.tar.gz"},
     "setup_path": "/core/install.php", "detect": ["core/lib/Drupal.php"], "color": "#0678be"},
    {"id": "concrete", "name": "Concrete CMS", "cat": "cms", "kind": "cli", "db": True, "db_prefix": "c5",
     "tagline": "Edit any page in place: point and click, no manuals.", "site": "https://www.concretecms.org",
     "exts": DB_EXTS + COMMON, "fixed_user": "admin", "php_values": {"memory_limit": "512M"},
     "source": {"t": "gh", "repo": "concretecms/concretecms", "asset": r"^concrete-cms-[\d.]+\.zip$"},
     "install": i_concrete, "admin_path": "/index.php/login", "detect": ["concrete/bin/concrete"], "color": "#17171a"},
    {"id": "e107", "name": "e107", "cat": "cms", "kind": "web", "db": True, "db_prefix": "e107",
     "tagline": "Content management system with a plugin-rich core.", "site": "https://e107.org",
     "exts": DB_EXTS + COMMON, "source": {"t": "gh", "repo": "e107inc/e107", "asset": r"_full\.zip$"},
     "setup_path": "/install.php", "detect": ["e107_admin/admin.php"], "color": "#2a4b7c"},
    # Forums
    {"id": "phpbb", "name": "phpBB", "cat": "forums", "kind": "cli", "db": True, "db_prefix": "phpbb",
     "tagline": "The most widely used open-source forum software.", "site": "https://www.phpbb.com",
     "exts": DB_EXTS + ["curl", "gd", "mbstring", "dom", "zip"], "user_len": (3, 20),
     "source": {"t": "fn", "fn": _src_phpbb}, "install": i_phpbb, "admin_path": "/adm/",
     "detect": ["includes/constants.php", "viewforum.php"], "color": "#0f4a8a", "popular": True},
    {"id": "smf", "name": "SMF", "cat": "forums", "kind": "web", "db": True, "db_prefix": "smf",
     "tagline": "Simple Machines Forum: a professional-grade community package.", "site": "https://www.simplemachines.org",
     "exts": DB_EXTS + COMMON, "source": {"t": "gh", "repo": "SimpleMachines/SMF"}, "install": i_smf,
     "setup_path": "/install.php", "detect": ["SSI.php", "Sources/Subs.php"], "color": "#3b6496"},
    {"id": "mybb", "name": "MyBB", "cat": "forums", "kind": "web", "db": True, "db_prefix": "mybb",
     "tagline": "Easy, multilingual, feature-packed free forum software.", "site": "https://mybb.com",
     "exts": DB_EXTS + COMMON, "source": {"t": "gh", "repo": "mybb/mybb", "asset": r"^mybb_\d+\.zip$"}, "sub": "Upload",
     "setup_path": "/install/", "detect": ["inc/class_core.php"], "color": "#007fd0"},
    # Galleries
    {"id": "piwigo", "name": "Piwigo", "cat": "galleries", "kind": "web", "db": True, "db_prefix": "pwg",
     "tagline": "Photo gallery software for the web, with albums and tags.", "site": "https://piwigo.org",
     "exts": DB_EXTS + COMMON + ["exif"], "source": {"t": "url", "url": "https://piwigo.org/download/dlcounter.php?code=latest",
                                                     "filename": "piwigo.zip"},
     "setup_path": "/install.php", "detect": ["include/constants.php", "picture.php"], "color": "#ff7700"},
    # Wikis
    {"id": "mediawiki", "popular": True, "name": "MediaWiki", "cat": "wikis", "kind": "cli", "db": True, "db_prefix": "mw",
     "tagline": "The wiki engine that runs Wikipedia.", "site": "https://www.mediawiki.org",
     "exts": DB_EXTS + COMMON, "source": {"t": "fn", "fn": _src_mediawiki}, "install": i_mediawiki,
     "admin_path": "/index.php/Special:UserLogin", "detect": ["LocalSettings.php", "includes/Setup.php"], "color": "#36c"},
    {"id": "dokuwiki", "name": "DokuWiki", "cat": "wikis", "kind": "cli", "db": False,
     "tagline": "Simple wiki that keeps pages in plain text files — no database.", "site": "https://www.dokuwiki.org",
     "exts": ["mbstring", "dom", "gd"], "source": {"t": "url", "url": "https://download.dokuwiki.org/src/dokuwiki/dokuwiki-stable.tgz",
                                                  "filename": "dokuwiki.tgz"},
     "install": i_dokuwiki, "admin_path": "/doku.php?do=login", "detect": ["doku.php", "inc/init.php"], "color": "#5b7c99"},
    # Social
    {"id": "ph7builder", "name": "pH7Builder", "cat": "social", "kind": "web", "db": True, "db_prefix": "ph7",
     "tagline": "Social dating and community site builder.", "site": "https://ph7builder.com",
     "exts": DB_EXTS + COMMON, "source": {"t": "gh", "repo": "pH7Software/pH7-Social-Dating-CMS", "asset": r"^pH7Builder-v[\d.]+\.zip$"},
     "setup_path": "/_install/", "detect": ["_protected/app/configs/constants.php"], "color": "#e0457b"},
    # E-commerce
    {"id": "opencart", "popular": True, "name": "OpenCart", "cat": "ecommerce", "kind": "cli", "db": True, "db_prefix": "oc",
     "tagline": "Online store with products, checkout and extensions.", "site": "https://www.opencart.com",
     "exts": DB_EXTS + COMMON, "user_len": (3, 20), "source": {"t": "gh", "repo": "opencart/opencart", "asset": r"^opencart-[\d.]+\.zip$"},
     "sub": "upload", "install": i_opencart, "admin_path": "/admin/", "detect": ["system/startup.php", "catalog/controller"],
     "color": "#23a1d1"},
    {"id": "abantecart", "name": "AbanteCart", "cat": "ecommerce", "kind": "web", "db": True, "db_prefix": "abc",
     "tagline": "Free eCommerce platform for merchants.", "site": "https://www.abantecart.com",
     "exts": DB_EXTS + COMMON, "source": {"t": "gh", "repo": "abantecart/abantecart-src"}, "sub": "public_html",
     "setup_path": "/install/", "detect": ["core/engine/registry.php"], "color": "#0e8acb"},
    # ERP
    {"id": "dolibarr", "name": "Dolibarr", "cat": "erp", "kind": "web", "db": True, "db_prefix": "dol",
     "tagline": "ERP & CRM for small companies, freelancers and foundations.", "site": "https://www.dolibarr.org",
     "exts": DB_EXTS + COMMON, "source": {"t": "gh", "repo": "Dolibarr/dolibarr"}, "web_suffix": "/htdocs",
     "setup_path": "/install/", "detect": ["htdocs/main.inc.php"], "color": "#263c5c"},
    # Mail
    {"id": "roundcube", "name": "Roundcube", "cat": "mail", "kind": "cli", "db": True, "db_prefix": "rc", "admin": False,
     "tagline": "Free webmail client with an app-like interface (needs an IMAP mail server).", "site": "https://roundcube.net",
     "exts": DB_EXTS + COMMON, "source": {"t": "gh", "repo": "roundcube/roundcubemail", "asset": r"-complete\.tar\.gz$"},
     "install": i_roundcube, "web_suffix": "/public_html", "detect": ["program/include/rcmail.php"], "color": "#37beff"},
    {"id": "phplist", "name": "phpList", "cat": "mail", "kind": "web", "db": True, "db_prefix": "phpl",
     "tagline": "Newsletter and mailing-list manager.", "site": "https://www.phplist.org",
     "exts": DB_EXTS + COMMON + ["imap"], "exts_required": ["mysqli"],
     "source": {"t": "url", "url": "https://sourceforge.net/projects/phplist/files/latest/download",
                "ver": r"phplist-([\d.]+)\.tgz", "filename": "phplist.tgz"},
     "sub": "public_html/lists", "install": i_phplist, "setup_path": "/admin/", "detect": ["admin/init.php", "config/config.php"], "color": "#2493d1"},
    {"id": "postfixadmin", "name": "Postfix Admin", "cat": "mail", "kind": "web", "db": True, "db_prefix": "pfa",
     "tagline": "Web admin for Postfix mailboxes, domains and aliases.", "site": "https://postfixadmin.github.io/postfixadmin/",
     "exts": DB_EXTS + ["mbstring", "imap"], "exts_required": ["mysqli"],
     "source": {"t": "gh", "repo": "postfixadmin/postfixadmin", "asset": r"php84\.tar\.gz$"}, "install": i_postfixadmin,
     "web_suffix": "/public", "setup_path": "/setup.php", "detect": ["model/PFAHandler.php"], "color": "#555"},
    # Analytics
    {"id": "matomo", "name": "Matomo", "cat": "analytics", "kind": "web", "db": True, "db_prefix": "mtm",
     "tagline": "Privacy-friendly web analytics you host yourself.", "site": "https://matomo.org",
     "exts": DB_EXTS + COMMON, "source": {"t": "url", "url": "https://builds.matomo.org/matomo.zip", "filename": "matomo.zip"},
     "sub": "matomo", "setup_path": "/", "php_values": {"memory_limit": "512M"}, "detect": ["core/Version.php", "matomo.js"], "color": "#3152a0"},
    # Projects
    {"id": "kanboard", "name": "Kanboard", "cat": "projects", "kind": "web", "db": False,
     "tagline": "Minimalist Kanban project board (SQLite, no setup).", "site": "https://kanboard.org",
     "exts": ["pdo_sqlite", "gd", "mbstring", "dom", "zip"], "source": {"t": "gh", "repo": "kanboard/kanboard"},
     "setup_path": "/", "detect": ["app/Core/Base.php", "kanboard"], "color": "#2d2d2d",
     "first_login": "Log in with admin / admin, then change the password straight away (Users → admin → Change password)."},
    # Education
    {"id": "moodle", "popular": True, "name": "Moodle", "cat": "education", "kind": "cli", "db": True, "db_prefix": "mdl",
     "tagline": "The world's open-source learning platform for courses and classes.", "site": "https://moodle.org",
     "exts": DB_EXTS + COMMON + ["soap", "exif"], "exts_required": ["mysqli", "intl", "zip", "gd", "mbstring"],
     "php_values": {"max_input_vars": "5000"},
     "source": {"t": "url", "url": "https://download.moodle.org/download.php/direct/stable500/moodle-latest-500.tgz",
                "version": "5.0", "filename": "moodle.tgz"},
     "install": i_moodle, "admin_path": "/login/", "detect": ["version.php", "lib/moodlelib.php"], "color": "#f98012"},
    {"id": "omeka", "name": "Omeka", "cat": "education", "kind": "web", "db": True, "db_prefix": "omk",
     "tagline": "Publish digital collections and online exhibits.", "site": "https://omeka.org/classic/",
     "exts": DB_EXTS + COMMON + ["exif"], "source": {"t": "gh", "repo": "omeka/Omeka", "asset": r"^omeka-[\d.]+\.zip$"},
     "install": i_omeka, "setup_path": "/install/", "detect": ["bootstrap.php", "application/libraries/Omeka"], "color": "#71a7cb"},
    # DB tools
    {"id": "adminer", "name": "Adminer", "cat": "dbtools", "kind": "static", "db": False,
     "tagline": "Full database manager in a single PHP file (MariaDB, PostgreSQL, SQLite…).", "site": "https://www.adminer.org",
     "exts": DB_EXTS, "source": {"t": "gh", "repo": "vrana/adminer", "asset": r"^adminer-[\d.]+\.php$"},
     "detect": [], "color": "#4d76b5",
     "first_login": "Log in with a database user from Databases (server: localhost)."},
    # Music
    {"id": "ampache", "name": "Ampache", "cat": "music", "kind": "web", "db": True, "db_prefix": "amp",
     "tagline": "Stream your music collection from anywhere.", "site": "https://ampache.org",
     "exts": DB_EXTS + COMMON, "source": {"t": "gh", "repo": "ampache/ampache", "asset": r"^ampache-[\d.]+_all_php8\.5\.zip$"},
     "web_suffix": "/public", "setup_path": "/install.php", "php_min": "8.5", "detect": ["src/Config/Init/InitializationHandlerConfig.php"],
     "color": "#d9531e"},
    # RSS
    {"id": "freshrss", "name": "FreshRSS", "cat": "rss", "kind": "cli", "db": True, "db_prefix": "frss",
     "tagline": "Self-hosted RSS & Atom feed reader, fast and light.", "site": "https://freshrss.org",
     "exts": DB_EXTS + ["curl", "mbstring", "dom", "zip", "intl"], "user_len": (3, 38),
     "source": {"t": "gh", "repo": "FreshRSS/FreshRSS"}, "install": i_freshrss, "web_suffix": "/p", "admin_path": "/",
     "detect": ["constants.php", "p/api"], "color": "#0062be"},
    # Files
    {"id": "nextcloud", "name": "Nextcloud", "cat": "files", "kind": "cli", "db": True, "db_prefix": "nc",
     "tagline": "Your own cloud: files, calendar, contacts and photos.", "site": "https://nextcloud.com",
     "exts": DB_EXTS + COMMON + ["bcmath", "gmp", "exif"], "exts_required": ["mysqli", "pdo_mysql", "gd", "zip", "mbstring", "dom", "curl"],
     "php_values": {"memory_limit": "512M", "upload_max_filesize": "2G", "post_max_size": "2G"},
     "source": {"t": "fn", "fn": _src_nextcloud}, "install": i_nextcloud, "admin_path": "/",
     "detect": ["occ", "lib/versioncheck.php"], "color": "#0082c9", "popular": True},
    {"id": "owncloud", "name": "ownCloud", "cat": "files", "kind": "unavailable",
     "tagline": "File sync and share through a web interface or WebDAV.", "site": "https://owncloud.com",
     "why": "ownCloud 10 only runs on PHP 7.4, which current Raspberry Pi OS doesn't have. Nextcloud (same roots) works great.",
     "color": "#041e42"},
    {"id": "projectsend", "name": "ProjectSend", "cat": "files", "kind": "unavailable",
     "tagline": "Share files privately with clients.", "site": "https://www.projectsend.org",
     "why": "ProjectSend 2 needs a background worker, scheduled tasks and its own command-line setup (nginx recommended), so it can't be dropped into a folder. Nextcloud covers file sharing well.",
     "color": "#2a7fb8"},
    {"id": "extplorer", "name": "eXtplorer", "cat": "files", "kind": "web", "db": False,
     "tagline": "File manager for your web space (browse, upload, edit, zip).", "site": "https://extplorer.net",
     "exts": ["mbstring", "zip"], "source": {"t": "gh", "repo": "soerennb/extplorer", "asset": r"-release\.zip$"},
     "setup_path": "/", "detect": ["libraries/standalone.php"], "color": "#f26b21",
     "first_login": "Log in with admin / admin and change the password right away (Admin → Users). Anyone who logs in can edit the files in this folder."},
    {"id": "seeddms", "name": "SeedDMS", "cat": "files", "kind": "web", "db": False,
     "tagline": "Document management with versions, workflows and full-text search.", "site": "https://www.seeddms.org",
     "exts": ["pdo_sqlite", "gd", "mbstring", "dom", "zip"],
     "source": {"t": "url", "url": "https://sourceforge.net/projects/seeddms/files/latest/download",
                "ver": r"seeddms-quickstart-([\d.]+)\.tar", "filename": "seeddms.tar.gz"},
     "web_suffix": "/www", "install": i_seeddms, "setup_path": "/", "detect": ["seeddms/inc/inc.Settings.php"], "color": "#333",
     "first_login": "SeedDMS quickstart comes ready with SQLite: log in with admin / admin and change the password."},
    # Frameworks
    {"id": "laravel", "name": "Laravel", "cat": "frameworks", "kind": "composer", "db": False,
     "tagline": "The PHP framework for web artisans — elegant and expressive.", "site": "https://laravel.com",
     "exts": ["mbstring", "dom", "curl", "zip", "pdo_sqlite", "intl"], "composer": ["create-project", "--prefer-dist", "laravel/laravel"],
     "web_suffix": "/public", "detect": ["artisan", "bootstrap/app.php"], "color": "#ff2d20"},
    {"id": "codeigniter", "name": "CodeIgniter", "cat": "frameworks", "kind": "composer", "db": False,
     "tagline": "Powerful PHP framework with a very small footprint.", "site": "https://codeigniter.com",
     "exts": ["mbstring", "intl", "curl", "dom"], "composer": ["create-project", "codeigniter4/appstarter"],
     "web_suffix": "/public", "detect": ["spark", "app/Config/App.php"], "color": "#dd4814"},
    {"id": "symfony", "name": "Symfony", "cat": "frameworks", "kind": "composer", "db": False,
     "tagline": "Reusable components and a full-stack framework.", "site": "https://symfony.com",
     "exts": ["mbstring", "dom", "intl", "curl"], "composer": ["create-project", "symfony/skeleton"],
     "web_suffix": "/public", "detect": ["bin/console", "config/bundles.php"], "color": "#1a171b"},
    {"id": "cakephp", "name": "CakePHP", "cat": "frameworks", "kind": "composer", "db": False,
     "tagline": "Rapid development framework with conventions over configuration.", "site": "https://cakephp.org",
     "exts": ["mbstring", "intl", "dom", "pdo_sqlite"], "composer": ["create-project", "--prefer-dist", "cakephp/app"],
     "detect": ["bin/cake", "config/app.php"], "color": "#d33c43"},
    {"id": "yii", "name": "Yii", "cat": "frameworks", "kind": "composer", "db": False,
     "tagline": "Fast, secure, high-performance PHP framework.", "site": "https://www.yiiframework.com",
     "exts": ["mbstring", "intl", "dom", "curl"], "composer": ["create-project", "--prefer-dist", "yiisoft/yii2-app-basic"],
     "web_suffix": "/web", "detect": ["yii", "config/web.php"], "color": "#40b3d8"},
    {"id": "smarty", "name": "Smarty", "cat": "frameworks", "kind": "composer", "db": False,
     "tagline": "Template engine that separates presentation from logic.", "site": "https://www.smarty.net",
     "exts": ["mbstring"], "composer": ["require", "smarty/smarty"], "composer_lib": True,
     "install": i_composer_demo("Smarty", "$smarty = new \\Smarty\\Smarty();\n$smarty->setCompileDir(sys_get_temp_dir());\n"
                                          "echo $smarty->fetch('string:<h1>Hello from {$name}!</h1>', ['name' => 'Smarty']);\n"),
     "detect": [], "color": "#f0c040"},
    {"id": "htmlpurifier", "name": "HTML Purifier", "cat": "frameworks", "kind": "composer", "db": False,
     "tagline": "Standards-compliant HTML filter that removes XSS.", "site": "http://htmlpurifier.org",
     "exts": ["mbstring", "dom"], "composer": ["require", "ezyang/htmlpurifier"], "composer_lib": True,
     "install": i_composer_demo("HTML Purifier", "$p = new HTMLPurifier(HTMLPurifier_Config::createDefault());\n"
                                                "echo $p->purify('<h1 onclick=\"alert(1)\">Clean HTML</h1><script>bad()</script>');\n"),
     "detect": [], "color": "#6a8caf"},
    {"id": "bootstrap", "name": "Bootstrap", "cat": "frameworks", "kind": "static", "db": False,
     "tagline": "Sleek, responsive front-end toolkit — a starter page included.", "site": "https://getbootstrap.com",
     "exts": [], "source": {"t": "gh", "repo": "twbs/bootstrap", "asset": r"^bootstrap-[\d.]+-dist\.zip$"},
     "install": i_starter_bootstrap, "detect": [], "color": "#7952b3"},
    {"id": "uikit", "name": "UIkit", "cat": "frameworks", "kind": "static", "db": False,
     "tagline": "Lightweight, modular front-end framework — a starter page included.", "site": "https://getuikit.com",
     "exts": [], "source": {"t": "gh", "repo": "uikit/uikit", "asset": r"^uikit-[\d.]+\.zip$"},
     "install": i_starter_uikit, "detect": [], "color": "#1e87f0"},
    # Others
    {"id": "whmcs", "name": "WHMCS", "cat": "other", "kind": "unavailable",
     "tagline": "Client management, billing and support for hosting businesses.", "site": "https://www.whmcs.com",
     "why": "WHMCS is commercial: it needs a paid licence and is downloaded from your WHMCS account, so it can't be fetched here.",
     "color": "#1a5a96"},
    {"id": "openrealestate", "name": "Open Real Estate", "cat": "other", "kind": "unavailable",
     "tagline": "Websites for real-estate agencies and realtors.", "site": "https://monoray.net",
     "why": "There's no public download of Open Real Estate to fetch automatically any more.", "color": "#2f7d32"},
]


def get(app_id: str) -> dict | None:
    return next((a for a in APPS if a["id"] == app_id), None)
