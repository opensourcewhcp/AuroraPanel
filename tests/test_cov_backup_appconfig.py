"""App configuration editors: rendered config text, validation, and rollback when the checker or the service says no.

Every system command goes through a recording stub, and every /etc or /var path is redirected into tmp_path,
so these run on any machine without touching a real server."""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from backend import appconfig, ftp


class Runner:
    """A subprocess.run stand-in: records every call, answers from prefix rules (longest match wins)."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.rules: list[tuple[tuple, object]] = []

    def on(self, *prefix, rc=0, out="", err="", fn=None):
        self.rules.append((tuple(prefix), fn or (lambda argv: (rc, out, err))))
        return self

    def __call__(self, argv, **kw):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        best = None
        for prefix, fn in self.rules:
            if tuple(argv[:len(prefix)]) == prefix and (best is None or len(prefix) >= len(best[0])):
                best = (prefix, fn)
        rc, out, err = best[1](argv) if best else (0, "", "")
        return subprocess.CompletedProcess(argv, rc, out, err)

    def argv(self, *prefix) -> list[list[str]]:
        return [c for c in self.calls if tuple(c[:len(prefix)]) == prefix]


@pytest.fixture
def run(monkeypatch):
    r = Runner()
    monkeypatch.setattr(appconfig.subprocess, "run", r)

    def enconf(argv):  # the real a2enconf links the file into conf-enabled, which the scan then reads
        src = appconfig.APACHE_TUNING
        dst = src.parent.parent / "conf-enabled" / src.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        return 0, "", ""
    r.on("a2enconf", fn=enconf)
    monkeypatch.setattr(appconfig, "time", SimpleNamespace(sleep=lambda s: None, time=lambda: 1700000000))
    return r


@pytest.fixture
def etc(tmp_path, monkeypatch):
    """Redirect every absolute /etc, /var or /usr path the module builds into tmp_path."""
    real = pathlib.Path

    def redirect(*parts):
        p = real(*parts)
        s = p.as_posix()
        for pre in ("/etc/", "/var/", "/usr/"):
            if s.startswith(pre):
                return tmp_path / s.lstrip("/")
        return p

    import glob as glob_mod
    monkeypatch.setattr(appconfig, "Path", redirect)
    monkeypatch.setattr(appconfig, "glob", SimpleNamespace(glob=lambda pat: sorted(glob_mod.glob(str(redirect(pat))))))
    monkeypatch.setattr(appconfig, "APACHE_TUNING", redirect("/etc/apache2/conf-available/zz-aurora-tuning.conf"))
    monkeypatch.setattr(appconfig, "NGINX_CONF", redirect("/etc/nginx/nginx.conf"))
    monkeypatch.setattr(appconfig, "LIGHTTPD_CONF", redirect("/etc/lighttpd/lighttpd.conf"))
    monkeypatch.setattr(appconfig, "MARIADB_OVERRIDE", redirect("/etc/mysql/mariadb.conf.d/99-aurora.cnf"))
    return redirect


def _write(p, text=""):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ---------------------------------------------------------------- helpers
def test_run_wraps_missing_binary_and_nonzero_exit(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("no such tool")
    monkeypatch.setattr(appconfig.subprocess, "run", boom)
    with pytest.raises(appconfig.AppConfigError, match="no such tool"):
        appconfig._run(["tool"])
    r = Runner().on("tool", rc=2, err="bad things")
    monkeypatch.setattr(appconfig.subprocess, "run", r)
    with pytest.raises(appconfig.AppConfigError, match="bad things"):
        appconfig._run(["tool"])
    assert appconfig._run(["tool"], check=False).returncode == 2


def test_num_and_clean_line_validate():
    assert appconfig._num(" 42 ", "x", 0, 100) == "42"
    with pytest.raises(appconfig.AppConfigError, match="between 0 and 100"):
        appconfig._num("101", "x", 0, 100)
    with pytest.raises(appconfig.AppConfigError):
        appconfig._num("abc", "x")
    assert appconfig._clean_line("  hello world ", "x") == "hello world"
    for bad in ("a;b", "a#b", 'a"b', "a$b", "a\\b", "a\nb"):
        with pytest.raises(appconfig.AppConfigError, match="aren't allowed"):
            appconfig._clean_line(bad, "x")


def test_read_returns_empty_for_missing_file(tmp_path):
    assert appconfig._read(tmp_path / "nope") == ""
    assert appconfig._read(_write(tmp_path / "a", "text")) == "text"


def test_human_sizes():
    assert appconfig._human(256 * 1024 * 1024) == "256M"
    assert appconfig._human(2 << 30) == "2G"
    assert appconfig._human(16 * 1024) == "16K"
    assert appconfig._human(1000) == "1000"


# ---------------------------------------------------------------- _apply
def test_apply_writes_validates_and_reloads_active_unit(tmp_path, run):
    run.on("systemctl", "is-active", rc=0)
    p = _write(tmp_path / "a.conf", "old")
    appconfig._apply({p: "new"}, ["checker", "-t"], "svc", "reload")
    assert p.read_text() == "new"
    assert run.argv("checker") == [["checker", "-t"]]
    assert run.argv("systemctl", "reload") == [["systemctl", "reload", "svc"]]


def test_apply_skips_restart_when_unit_inactive(tmp_path, run):
    run.on("systemctl", "is-active", rc=3)
    p = tmp_path / "sub" / "new.conf"
    appconfig._apply({p: "x"}, None, "svc")
    assert p.read_text() == "x"
    assert not run.argv("systemctl", "reload")


def test_apply_validation_failure_restores_files_and_runs_extra_rollback(tmp_path, run):
    run.on("checker", rc=1, err="syntax error line 3")
    kept = _write(tmp_path / "kept.conf", "before")
    fresh = tmp_path / "fresh.conf"
    gone = _write(tmp_path / "gone.conf", "doomed")
    undone = []
    with pytest.raises(appconfig.AppConfigError, match="syntax error line 3"):
        appconfig._apply({kept: "after", fresh: "created", gone: None}, ["checker"], "svc", extra_rollback=lambda: undone.append(1))
    assert kept.read_text() == "before"
    assert not fresh.exists()           # a file that did not exist before is removed again
    assert gone.read_text() == "doomed"  # a deletion is undone
    assert undone == [1]
    assert not run.argv("systemctl")


def test_apply_service_failure_restores_and_restarts(tmp_path, run):
    states = iter([0, 1])  # active before, dead after the reload
    run.on("systemctl", "is-active", fn=lambda a: (next(states), "", ""))
    run.on("journalctl", out="svc: cannot bind\n")
    p = _write(tmp_path / "a.conf", "old")
    with pytest.raises(appconfig.AppConfigError, match="undone:\nsvc: cannot bind"):
        appconfig._apply({p: "new"}, None, "svc", "reload")
    assert p.read_text() == "old"
    assert run.argv("systemctl", "reload") == [["systemctl", "reload", "svc"]]
    assert run.argv("systemctl", "restart") == [["systemctl", "restart", "svc"]]   # the rollback restart


# ---------------------------------------------------------------- Apache
APACHE_MAIN = """# comment ServerTokens Full
ServerTokens Major
Timeout 120
<Directory />
    ServerSignature On
    <IfModule x>
        KeepAlive Off
    </IfModule>
</Directory>
ServerAdmin "root@pi.local"
LimitRequestBody 2097152
"""


def test_apache_scan_takes_last_top_level_value_in_load_order(tmp_path, etc):
    _write(etc("/etc/apache2/apache2.conf"), APACHE_MAIN)
    _write(etc("/etc/apache2/conf-enabled/10-x.conf"), "Timeout 60\n")
    v = appconfig._apache_scan()
    assert v["ServerTokens"] == "Major"      # the comment is ignored
    assert v["Timeout"] == "60"              # conf-enabled loads after apache2.conf
    assert "ServerSignature" not in v        # nested in a block
    assert "KeepAlive" not in v
    assert v["ServerAdmin"] == "root@pi.local"


def test_apache_settings_defaults_and_tuning_markers(tmp_path, etc):
    _write(etc("/etc/apache2/apache2.conf"), APACHE_MAIN)
    _write(appconfig.APACHE_TUNING, "# aurora-security-headers\n")
    s = appconfig.apache_settings()
    v = s["values"]
    assert v["LimitRequestBody_mb"] == "2" and v["KeepAlive"] == "On" and v["TraceEnable"] == "On"
    assert v["security_headers"] == "On" and v["tls_modern"] == "Off"
    assert s["bool_values"] == ["On", "Off"]


@pytest.mark.parametrize("changes,msg", [
    ({"Bogus": 1}, "Unknown setting"),
    ({"ServerTokens": "Everything"}, "invalid choice"),
    ({"Timeout": "2"}, "between 5 and 3600"),
    ({"ServerAdmin": "not-an-email"}, "looks invalid"),
    ({"ServerAdmin": "a;b@c"}, "aren't allowed"),
])
def test_apache_save_rejects_bad_values_before_touching_disk(tmp_path, etc, run, changes, msg):
    with pytest.raises(appconfig.AppConfigError, match=msg):
        appconfig.apache_save(changes)
    assert not appconfig.APACHE_TUNING.exists() and not run.calls


def test_apache_save_renders_tuning_file_and_enables_it(tmp_path, etc, run):
    run.on("systemctl", "is-active", rc=0)
    out = appconfig.apache_save({"ServerTokens": "Prod", "TraceEnable": "no", "LimitRequestBody_mb": "64",
                                 "ServerAdmin": "admin@example.com", "security_headers": "true", "tls_modern": "1"})
    text = appconfig.APACHE_TUNING.read_text()
    assert "ServerTokens Prod\n" in text and "TraceEnable Off\n" in text
    assert "LimitRequestBody 67108864\n" in text and "ServerAdmin admin@example.com\n" in text
    assert 'Header always set X-Frame-Options "SAMEORIGIN"' in text
    assert "SSLProtocol -all +TLSv1.2 +TLSv1.3" in text and appconfig.TLS_CIPHERS in text
    assert ["a2enmod", "-q", "headers"] in run.calls      # headers.load was missing
    assert ["a2enconf", "-q", "zz-aurora-tuning"] in run.calls
    assert ["apache2ctl", "configtest"] in run.calls
    assert run.argv("systemctl", "reload") == [["systemctl", "reload", "apache2"]]
    assert out["ok"] is True and out["values"]["ServerTokens"] == "Prod" and out["values"]["LimitRequestBody_mb"] == "64"


def test_apache_save_configtest_failure_removes_new_file_and_disables_conf(tmp_path, etc, run):
    run.on("apache2ctl", "configtest", rc=1, err="AH00526: Syntax error")
    with pytest.raises(appconfig.AppConfigError, match="AH00526"):
        appconfig.apache_save({"Timeout": "30"})
    assert not appconfig.APACHE_TUNING.exists()
    assert ["a2disconf", "-q", "zz-aurora-tuning"] in run.calls


def test_apache_save_reload_failure_restores_previous_file(tmp_path, etc, run):
    _write(appconfig.APACHE_TUNING, "# previous\n")
    _write(etc("/etc/apache2/conf-enabled/zz-aurora-tuning.conf"), "")
    run.on("systemctl", "is-active", rc=0)
    run.on("systemctl", "reload", rc=1, err="Job for apache2 failed")
    with pytest.raises(appconfig.AppConfigError, match="failed to reload"):
        appconfig.apache_save({"Timeout": "30"})
    assert appconfig.APACHE_TUNING.read_text() == "# previous\n"
    assert not run.argv("a2disconf")   # it was enabled before, so it stays enabled
    assert run.argv("systemctl", "restart") == [["systemctl", "restart", "apache2"]]


def test_apache_hardening_counts_recommended_settings(tmp_path, etc, run):
    assert appconfig.apache_hardening() == {"available": False, "items": [], "ok": 0, "total": 0}
    _write(etc("/etc/apache2/apache2.conf"), "ServerTokens Prod\nTraceEnable Off\n")
    h = appconfig.apache_hardening()
    assert h["available"] and h["total"] == 5 and h["ok"] == 2
    assert {i["key"]: i["ok"] for i in h["items"]}["ServerSignature"] is False
    appconfig.apache_harden()
    assert appconfig.apache_hardening()["ok"] == 5


def test_apache_modules_marks_protected_and_popular(tmp_path, etc):
    for m in ("rewrite", "mpm_event", "php8.2", "dir", "ssl"):
        _write(etc(f"/etc/apache2/mods-available/{m}.load"))
    _write(etc("/etc/apache2/mods-enabled/dir.load"))
    mods = {m["name"]: m for m in appconfig.apache_modules()}
    assert mods["dir"]["enabled"] and mods["dir"]["protected"]
    assert mods["mpm_event"]["protected"] and mods["php8.2"]["protected"]
    assert mods["rewrite"]["popular"] and not mods["rewrite"]["enabled"] and "WordPress" in mods["rewrite"]["desc"]
    assert not mods["ssl"]["protected"]


def test_apache_module_toggle_and_rollback(tmp_path, etc, run):
    for m in ("rewrite", "dir"):
        _write(etc(f"/etc/apache2/mods-available/{m}.load"))
    with pytest.raises(appconfig.AppConfigError, match="Unknown module"):
        appconfig.apache_module("nope", True)
    with pytest.raises(appconfig.AppConfigError, match="required by Apache"):
        appconfig.apache_module("dir", False)
    run.on("systemctl", "is-active", rc=0)
    assert appconfig.apache_module("rewrite", True) == {"ok": True}
    assert run.calls[0] == ["a2enmod", "-q", "rewrite"]
    assert run.argv("systemctl", "restart") == [["systemctl", "restart", "apache2"]]
    run.calls.clear()
    appconfig.apache_module("rewrite", False)
    assert run.calls[0] == ["a2dismod", "-q", "-f", "rewrite"]
    run.calls.clear()
    run.on("apache2ctl", "configtest", rc=1, err="needs mod_x")
    with pytest.raises(appconfig.AppConfigError, match="undone"):
        appconfig.apache_module("rewrite", True)
    assert ["a2dismod", "-q", "-f", "rewrite"] in run.calls


def test_strip_vhost_tls_comments_site_lines_and_restores_on_rejection(tmp_path, etc, run):
    with pytest.raises(appconfig.AppConfigError, match="Pick a site"):
        appconfig.strip_vhost_tls("../x.conf")
    with pytest.raises(appconfig.AppConfigError, match="not enabled"):
        appconfig.strip_vhost_tls("site.conf")
    site = _write(etc("/etc/apache2/sites-enabled/site.conf"),
                  "<VirtualHost *:443>\n  SSLProtocol all\n  SSLCipherSuite HIGH\n  DocumentRoot /var/www\n</VirtualHost>\n")
    _write(etc("/etc/apache2/apache2.conf"), "ServerTokens Prod\n")
    run.on("apache2ctl", "configtest", rc=1, err="AH00558: hostname\nAH00526: bad")
    with pytest.raises(appconfig.AppConfigError) as ei:
        appconfig.strip_vhost_tls("site.conf")
    assert "AH00526" in str(ei.value) and "AH00558" not in str(ei.value)
    assert "  SSLProtocol all\n" in site.read_text()  # put back
    assert list(etc("/var/lib/aurora/site-backups").iterdir())
    run.rules.clear()
    r = appconfig.strip_vhost_tls("site.conf")
    assert r["changed"] == 2
    text = site.read_text()
    assert "# aurora-tls-modern: SSLProtocol all" in text and "DocumentRoot /var/www" in text
    assert appconfig.APACHE_TUNING.exists()   # hardening was applied as a side effect


def test_strip_vhost_tls_only_reloads_when_already_hardened(tmp_path, etc, run):
    site = _write(etc("/etc/apache2/sites-enabled/site.conf"), "SSLHonorCipherOrder on\n")
    _write(etc("/etc/apache2/apache2.conf"), "ServerTokens Prod\nServerSignature Off\nTraceEnable Off\n")
    _write(appconfig.APACHE_TUNING, "# aurora-security-headers\n# aurora-tls-modern\n")
    run.on("systemctl", "reload", rc=1)
    appconfig.strip_vhost_tls("site.conf")
    assert site.read_text().startswith("# aurora-tls-modern: SSLHonorCipherOrder on")
    assert ["systemctl", "restart", "apache2"] in run.calls


# ---------------------------------------------------------------- Nginx
NGINX = """user www-data;
worker_processes auto; # one per core
events {
    worker_connections 768;
}
http {
    sendfile on;
    # server_tokens off;
    keepalive_timeout 65s;
    server {
        client_max_body_size 10m;
    }
}
"""


def test_nginx_blocks_tracks_context():
    ctx = {i: c for c, i, _ in appconfig._nginx_blocks(NGINX)}
    assert ctx[1] == "main" and ctx[3] == "events" and ctx[6] == "http"
    assert ctx[10] == "nested"   # inside server { } the directive does not count


def test_nginx_settings_reads_contexts_and_defaults(tmp_path, etc):
    _write(appconfig.NGINX_CONF, NGINX)
    v = appconfig.nginx_settings()["values"]
    assert v["worker_processes"] == "auto" and v["worker_connections"] == "768"
    assert v["keepalive_timeout"] == "65" and v["sendfile"] == "on"
    assert v["client_max_body_size"] == "1m"   # the one inside server {} is not the http default
    assert v["server_tokens"] == "on"           # commented out means the default


@pytest.mark.parametrize("changes,msg", [
    ({"nope": "1"}, "Unknown setting"),
    ({"worker_connections": "10"}, "between 64 and 65535"),
    ({"client_max_body_size": "lots"}, "64m or 1g"),
    ({"worker_processes": "many"}, "auto or a number"),
])
def test_nginx_save_rejects_bad_values(tmp_path, etc, run, changes, msg):
    _write(appconfig.NGINX_CONF, NGINX)
    with pytest.raises(appconfig.AppConfigError, match=msg):
        appconfig.nginx_save(changes)


def test_nginx_save_replaces_in_place_uncomments_and_inserts(tmp_path, etc, run):
    _write(appconfig.NGINX_CONF, NGINX)
    run.on("systemctl", "is-active", rc=0)
    out = appconfig.nginx_save({"worker_connections": "1024", "server_tokens": "off", "client_max_body_size": "64M",
                                "gzip": "yes", "worker_processes": "4"})
    text = appconfig.NGINX_CONF.read_text()
    assert "    worker_connections 1024;\n" in text        # indentation kept
    assert "    server_tokens off;\n" in text and "# server_tokens" not in text
    # inserted at the top of http (before its first directive), not into the nested server block
    assert text.index("http {") < text.index("\tclient_max_body_size 64m;\n") < text.index("    sendfile on;")
    assert "\tgzip on;" in text
    assert text.startswith("user www-data;\nworker_processes 4;")
    assert "client_max_body_size 10m;" in text              # the server-level one is untouched
    assert run.argv("nginx") == [["nginx", "-t"]] and ["systemctl", "reload", "nginx"] in run.calls
    assert out["values"]["worker_connections"] == "1024"


def test_nginx_save_without_http_block_fails_before_writing(tmp_path, etc, run):
    _write(appconfig.NGINX_CONF, "events {\n}\n")
    with pytest.raises(appconfig.AppConfigError, match="Couldn't find the http block"):
        appconfig.nginx_save({"gzip": "on"})
    assert appconfig.NGINX_CONF.read_text() == "events {\n}\n"
    assert not run.calls


def test_nginx_save_rolls_back_when_nginx_t_fails(tmp_path, etc, run):
    _write(appconfig.NGINX_CONF, NGINX)
    run.on("nginx", "-t", rc=1, err="unknown directive")
    with pytest.raises(appconfig.AppConfigError, match="unknown directive"):
        appconfig.nginx_save({"worker_connections": "2048"})
    assert appconfig.NGINX_CONF.read_text() == NGINX


# ---------------------------------------------------------------- Lighttpd
def test_lighttpd_settings_and_save(tmp_path, etc, run):
    _write(appconfig.LIGHTTPD_CONF, 'server.port = 8080\n#server.tag = "x"\nserver.document-root = "/srv/www"\n')
    v = appconfig.lighttpd_settings()["values"]
    assert v["server.port"] == "8080" and v["server.document-root"] == "/srv/www" and v["dir-listing.activate"] == "disable"
    with pytest.raises(appconfig.AppConfigError, match="Unknown setting"):
        appconfig.lighttpd_save({"x": 1})
    with pytest.raises(appconfig.AppConfigError, match="absolute path"):
        appconfig.lighttpd_save({"server.document-root": "www"})
    with pytest.raises(appconfig.AppConfigError, match="between 1 and 65535"):
        appconfig.lighttpd_save({"server.port": "0"})
    run.on("systemctl", "is-active", rc=0)
    out = appconfig.lighttpd_save({"server.port": "81", "server.tag": "", "dir-listing.activate": "on", "server.max-request-size": "2048"})
    text = appconfig.LIGHTTPD_CONF.read_text()
    assert "server.port = 81\n" in text
    assert 'server.tag = ""\n' in text and "#server.tag" not in text    # the commented line is replaced
    assert text.endswith('dir-listing.activate = "enable"\n\nserver.max-request-size = 2048\n')
    assert run.argv("lighttpd") == [["lighttpd", "-tt", "-f", str(appconfig.LIGHTTPD_CONF)]]
    assert ["systemctl", "restart", "lighttpd"] in run.calls
    assert out["values"]["server.port"] == "81" and out["values"]["server.tag"] == ""


def test_lighttpd_modules_and_toggle(tmp_path, etc, run):
    for n in ("10-fastcgi-php", "05-auth"):
        _write(etc(f"/etc/lighttpd/conf-available/{n}.conf"))
    _write(etc("/etc/lighttpd/conf-enabled/05-auth.conf"))
    mods = {m["name"]: m for m in appconfig.lighttpd_modules()}
    assert mods["auth"]["enabled"] and not mods["fastcgi-php"]["enabled"] and mods["fastcgi-php"]["popular"]
    with pytest.raises(appconfig.AppConfigError, match="Unknown module"):
        appconfig.lighttpd_module("zzz", True)
    run.on("systemctl", "is-active", rc=0)
    appconfig.lighttpd_module("fastcgi-php", True)
    assert run.calls[0] == ["lighty-enable-mod", "fastcgi-php"] and ["systemctl", "restart", "lighttpd"] in run.calls
    run.calls.clear()
    run.on("lighttpd", "-tt", rc=1, out="config broken")
    with pytest.raises(appconfig.AppConfigError, match="config broken"):
        appconfig.lighttpd_module("auth", False)
    assert run.calls[0] == ["lighty-disable-mod", "auth"] and ["lighty-enable-mod", "auth"] in run.calls


# ---------------------------------------------------------------- MariaDB
MY_ROW = "\t".join(["127.0.0.1", "3306", "0", "151", "28800", str(256 << 20), str(16 << 20), str(16 << 20),
                    "utf8mb4", "utf8mb4_general_ci", "0", "10.000000"])


def test_mariadb_settings_reads_live_values(tmp_path, etc, run):
    run.on("mysql", out=MY_ROW + "\n")
    v = appconfig.mariadb_settings()["values"]
    assert v["remote_access"] == "Off" and v["port"] == "3306" and v["innodb_buffer_pool_size"] == "256M"
    assert v["slow_query_log"] == "Off" and v["long_query_time"] == "10"
    run.on("mysql", rc=1, err="Can't connect to local server")
    with pytest.raises(appconfig.AppConfigError, match="isn't running"):
        appconfig.mariadb_settings()


def test_mariadb_save_renders_override_and_restarts(tmp_path, etc, run):
    run.on("mysql", out=MY_ROW + "\n")
    run.on("systemctl", "is-active", rc=0)
    with pytest.raises(appconfig.AppConfigError, match="Unknown setting"):
        appconfig.mariadb_save({"x": 1})
    with pytest.raises(appconfig.AppConfigError, match="e.g. 256M"):
        appconfig.mariadb_save({"innodb_buffer_pool_size": "big"})
    with pytest.raises(appconfig.AppConfigError, match="invalid choice"):
        appconfig.mariadb_save({"character_set_server": "ebcdic"})
    with pytest.raises(appconfig.AppConfigError, match="Collation must match"):
        appconfig.mariadb_save({"character_set_server": "latin1"})
    assert not appconfig.MARIADB_OVERRIDE.exists()
    out = appconfig.mariadb_save({"remote_access": "on", "skip_name_resolve": "yes", "max_allowed_packet": "64m",
                                  "slow_query_log": "1", "port": "3307"})
    text = appconfig.MARIADB_OVERRIDE.read_text()
    assert "[mysqld]\nbind-address = 0.0.0.0\nport = 3307\n" in text
    assert "max_allowed_packet = 64M\n" in text and "slow_query_log = 1\n" in text
    assert "max_heap_table_size = 16M\n" in text and text.endswith("skip-name-resolve\n")
    assert ["systemctl", "restart", "mariadb"] in run.calls
    assert out["ok"] is True


# ---------------------------------------------------------------- PostgreSQL
@pytest.fixture
def pg(tmp_path, etc, run, monkeypatch):
    which = {"pg_lsclusters": "/usr/bin/pg_lsclusters"}
    chowned = []
    monkeypatch.setattr(appconfig, "shutil", SimpleNamespace(which=lambda n, **k: which.get(n), copy2=shutil.copy2,
                                                             chown=lambda p, u, g: chowned.append((str(p), u, g))))
    confdir = etc("/etc/postgresql/16/main")
    _write(confdir / "pg_hba.conf", "local all all peer\n")
    run.on("pg_lsclusters", out="16 main 5433 online postgres /var/lib/postgresql/16/main /var/log/x.log\n")
    rows = {"listen_addresses": ("localhost", "localhost"), "port": ("5433", "5433"), "max_connections": ("100", "100"),
            "ssl": ("on", "on"), "shared_buffers": ("128MB", "16384"), "work_mem": ("4MB", "4096"),
            "maintenance_work_mem": ("64MB", "65536"), "effective_cache_size": ("4GB", "524288"),
            "log_min_duration_statement": ("-1", "-1"), "log_connections": ("off", "off"), "autovacuum": ("on", "on")}
    run.on("runuser", "-u", "postgres", "--", "psql", "-X", "-tA", out="".join(f"{k}\t{h}\t{r}\n" for k, (h, r) in rows.items()))
    return SimpleNamespace(confdir=confdir, which=which, chowned=chowned)


def test_pg_helpers(tmp_path, etc, pg):
    assert appconfig._pg_cluster()[:2] == ("16", "main")
    assert appconfig._pg_unit() == "postgresql@16-main"
    assert appconfig._pg_validate()[7:9] == ["-p", "5433"]   # validates on the port the server listens on now
    assert appconfig._pg_size("256", "x") == "256MB" and appconfig._pg_size("1g", "x") == "1GB" and appconfig._pg_size("512 kB", "x") == "512kB"
    with pytest.raises(appconfig.AppConfigError, match="e.g. 256MB"):
        appconfig._pg_size("lots", "x")
    assert appconfig._pg_bytes("2GB") == 2 << 30 and appconfig._pg_bytes("weird") == 0
    block = f"{appconfig.PG_HBA_BEGIN}\nhost    all    all    10.0.0.0/8    scram-sha-256\n{appconfig.PG_HBA_END}\n"
    assert appconfig._pg_hba_networks("x\n" + block) == ["10.0.0.0/8"]
    assert appconfig._pg_hba_strip("local all all peer\n" + block) == "local all all peer\n"
    assert str(pg.confdir / "postgresql.conf") in appconfig._pg_files()
    assert appconfig._pg_logs() == ["/var/log/postgresql/postgresql-16-main.log"]
    pg.which.clear()
    assert appconfig._pg_cluster() is None and appconfig._pg_files() == [] and appconfig._pg_logs() == []
    assert "-p" not in appconfig._pg_validate()


def test_postgresql_settings_without_cluster_or_server(tmp_path, etc, run, pg):
    run.on("runuser", "-u", "postgres", "--", "psql", "-X", "-tA", rc=1, err="connection refused")
    with pytest.raises(appconfig.AppConfigError, match="isn't running"):
        appconfig.postgresql_settings()
    pg.which.clear()
    with pytest.raises(appconfig.AppConfigError, match="no database cluster"):
        appconfig.postgresql_settings()
    with pytest.raises(appconfig.AppConfigError, match="no database cluster"):
        appconfig.postgresql_save({})


def test_postgresql_settings_reads_values(pg):
    s = appconfig.postgresql_settings()
    v = s["values"]
    assert s["version"] == "16" and s["cluster"] == "main"
    assert v["remote_access"] == "Off" and v["remote_from"] == "" and v["port"] == "5433"
    assert v["ssl"] == "On" and v["slow_query_ms"] == "0" and v["shared_buffers"] == "128MB" and v["autovacuum"] == "On"


@pytest.mark.parametrize("changes,msg", [
    ({"zzz": 1}, "Unknown setting"),
    ({"remote_from": "not-a-network"}, "isn't an address"),
    ({"remote_access": "on"}, "at least one allowed network"),
    ({"max_connections": "1"}, "between 5 and 10000"),
])
def test_postgresql_save_rejects_bad_values(pg, changes, msg):
    with pytest.raises(appconfig.AppConfigError, match=msg):
        appconfig.postgresql_save(changes)
    assert not (pg.confdir / "conf.d" / "99-aurora.conf").exists()


def test_postgresql_save_refuses_shared_buffers_over_half_ram(pg, monkeypatch):
    monkeypatch.setattr(os, "sysconf", lambda name: 4096 if name == "SC_PAGE_SIZE" else 1024, raising=False)  # 4 MB box
    with pytest.raises(appconfig.AppConfigError, match="more than half"):
        appconfig.postgresql_save({"shared_buffers": "128MB"})


def test_postgresql_save_writes_conf_and_hba_block(pg, run, monkeypatch):
    monkeypatch.setattr(os, "sysconf", lambda name: 0, raising=False)
    run.on("systemctl", "is-active", rc=0)
    out = appconfig.postgresql_save({"remote_access": "yes", "remote_from": "192.168.0.5, 10.0.0.0/8", "slow_query_ms": "250",
                                     "work_mem": "8", "log_connections": "on"})
    conf = (pg.confdir / "conf.d" / "99-aurora.conf").read_text()
    assert "listen_addresses = '*'\nport = 5433\n" in conf
    assert "work_mem = '8MB'\n" in conf and "log_min_duration_statement = 250\n" in conf and "log_connections = on\n" in conf
    hba = (pg.confdir / "pg_hba.conf").read_text(encoding="utf-8")
    assert hba.startswith("local all all peer\n\n" + appconfig.PG_HBA_BEGIN)
    assert "host    all    all    192.168.0.5/32    scram-sha-256\nhost    all    all    10.0.0.0/8    scram-sha-256\n" in hba
    validate = [c for c in run.calls if c[:4] == ["runuser", "-u", "postgres", "--"] and "-q" in c]
    assert validate and validate[0][-1] == appconfig._PG_VALIDATE_SQL
    assert ["systemctl", "restart", "postgresql@16-main"] in run.calls
    assert {u for _, u, _ in pg.chowned} == {"postgres"} and len(pg.chowned) == 2
    assert out["ok"] is True
    # turning remote access off again strips the block
    appconfig.postgresql_save({"remote_access": "off", "remote_from": ""})
    assert appconfig.PG_HBA_BEGIN not in (pg.confdir / "pg_hba.conf").read_text(encoding="utf-8")


def test_postgresql_save_rollback_when_validation_fails(pg, run, monkeypatch):
    monkeypatch.setattr(os, "sysconf", lambda name: 0, raising=False)
    run.on("runuser", "-u", "postgres", "--", "psql", "-X", "-q", rc=1, err="pg_hba.conf line 3: invalid")
    with pytest.raises(appconfig.AppConfigError, match="invalid"):
        appconfig.postgresql_save({"ssl": "off"})
    assert not (pg.confdir / "conf.d" / "99-aurora.conf").exists()
    assert (pg.confdir / "pg_hba.conf").read_text() == "local all all peer\n"
    assert not pg.chowned


# ---------------------------------------------------------------- PHP-FPM
POOL = "[www]\nuser = www-data\npm = dynamic\npm.max_children = 5\n;pm.max_requests = 500\n"


@pytest.fixture
def fpm(tmp_path, etc, monkeypatch):
    pool = _write(tmp_path / "www.conf", POOL)
    monkeypatch.setattr(appconfig, "_fpm_pool", lambda: ("8.2", pool))
    return pool


def test_fpm_pool_absent(etc, monkeypatch):
    assert appconfig._fpm_pool() is None
    with pytest.raises(appconfig.AppConfigError, match="not installed"):
        appconfig.phpfpm_settings()
    with pytest.raises(appconfig.AppConfigError, match="not installed"):
        appconfig.phpfpm_save({})
    assert appconfig._fpm_files() == [] and appconfig._fpm_validate() is None and appconfig._fpm_unit() is None


def test_phpfpm_settings_defaults_and_registry_helpers(fpm):
    s = appconfig.phpfpm_settings()
    assert s["version"] == "8.2" and s["values"]["pm.max_children"] == "5" and s["values"]["pm.max_requests"] == "0"
    assert appconfig._fpm_files() == [str(fpm), "/etc/php/8.2/fpm/php-fpm.conf"]
    assert appconfig._fpm_validate() == ["php-fpm8.2", "-t"] and appconfig._fpm_unit() == "php8.2-fpm"


@pytest.mark.parametrize("changes,msg", [
    ({"nope": "1"}, "Unknown setting"),
    ({"pm": "magic"}, "Invalid mode"),
    ({"pm.process_idle_timeout": "soon"}, "e.g. 10s"),
    ({"pm.max_children": "x"}, "whole number"),
    ({"pm.start_servers": "9"}, "Dynamic mode needs"),
])
def test_phpfpm_save_rejects(fpm, run, changes, msg):
    with pytest.raises(appconfig.AppConfigError, match=msg):
        appconfig.phpfpm_save(changes)
    assert fpm.read_text() == POOL


def test_phpfpm_save_rewrites_pool_and_reloads(fpm, run):
    run.on("systemctl", "is-active", rc=0)
    out = appconfig.phpfpm_save({"pm.max_children": "8", "pm.max_spare_servers": "4", "pm.max_requests": "500"})
    text = fpm.read_text()
    assert "pm.max_children = 8\n" in text and "pm.max_requests = 500\n" in text and ";pm.max_requests" not in text
    assert "\npm.max_spare_servers = 4\n" in text        # appended since the pool did not have it
    assert run.argv("php-fpm8.2") == [["php-fpm8.2", "-t"]] and ["systemctl", "reload", "php8.2-fpm"] in run.calls
    assert out["values"]["pm.max_children"] == "8"
    # ondemand mode skips the dynamic sanity rule
    appconfig.phpfpm_save({"pm": "ondemand", "pm.start_servers": "50"})
    assert "pm = ondemand\n" in fpm.read_text()


# ---------------------------------------------------------------- registry
def test_registry_lookup_and_info(tmp_path, etc, run):
    with pytest.raises(appconfig.AppConfigError, match="Unknown application"):
        appconfig.info("exim")
    conf = _write(etc("/etc/caddy/Caddyfile"), "localhost\n")
    i = appconfig.info("caddy")
    assert conf.exists()
    assert i == {"id": "caddy", "has_settings": False, "has_modules": False, "files": ["/etc/caddy/Caddyfile"], "logs": [],
                 "unit": "caddy", "ftp_accounts": False}
    with pytest.raises(appconfig.AppConfigError, match="Files tab"):
        appconfig.settings("caddy")
    with pytest.raises(appconfig.AppConfigError, match="No settings form"):
        appconfig.save("caddy", {})
    with pytest.raises(appconfig.AppConfigError, match="No modules"):
        appconfig.modules("nginx")
    with pytest.raises(appconfig.AppConfigError, match="No modules"):
        appconfig.set_module("nginx", "x", True)
    assert appconfig.info("vsftpd")["ftp_accounts"] is True


def test_registry_dispatches_to_app_functions(tmp_path, etc, run, monkeypatch):
    _write(appconfig.NGINX_CONF, NGINX)
    assert appconfig.settings("nginx")["values"]["worker_connections"] == "768"
    assert appconfig.save("nginx", {"gzip": "on"})["values"]["gzip"] == "on"
    for m in ("rewrite",):
        _write(etc(f"/etc/apache2/mods-available/{m}.load"))
    assert appconfig.modules("apache")[0]["name"] == "rewrite"
    assert appconfig.set_module("apache", "rewrite", True) == {"ok": True}
    def broken():
        raise ftp.FTPError("vsftpd missing")
    monkeypatch.setitem(appconfig.APPS["vsftpd"], "settings", broken)
    with pytest.raises(appconfig.AppConfigError, match="vsftpd missing"):
        appconfig.settings("vsftpd")


def test_read_and_write_file_are_limited_to_the_apps_files(tmp_path, etc, run):
    conf = _write(etc("/etc/caddy/Caddyfile"), "localhost\n")
    with pytest.raises(appconfig.AppConfigError, match="isn't editable"):
        appconfig.read_file("caddy", str(tmp_path / "other"))
    assert appconfig.read_file("caddy", "/etc/caddy/Caddyfile") == {"path": "/etc/caddy/Caddyfile", "content": "localhost\n"}
    with pytest.raises(appconfig.AppConfigError, match="too large"):
        appconfig.write_file("caddy", "/etc/caddy/Caddyfile", "x" * (512 * 1024 + 1))
    run.on("systemctl", "is-active", rc=0)
    assert appconfig.write_file("caddy", "/etc/caddy/Caddyfile", "a\r\nb\r\n") == {"ok": True}
    assert conf.read_text() == "a\nb\n"
    assert run.argv("caddy") == [["caddy", "validate", "--adapter", "caddyfile", "--config", "/etc/caddy/Caddyfile"]]
    assert ["systemctl", "reload", "caddy"] in run.calls
    run.on("caddy", rc=1, err="Caddyfile:1: unrecognized")
    with pytest.raises(appconfig.AppConfigError, match="unrecognized"):
        appconfig.write_file("caddy", "/etc/caddy/Caddyfile", "garbage")
    assert conf.read_text() == "a\nb\n"


def test_logs_from_file_or_journal(tmp_path, etc, run):
    log = _write(etc("/var/log/nginx/error.log"), "\n".join(str(i) for i in range(50)) + "\n")
    out = appconfig.logs("nginx", "/var/log/nginx/error.log", lines=5)
    assert out["source"] == "/var/log/nginx/error.log"
    assert out["text"] == "30\n31\n32\n33\n34\n35\n36\n37\n38\n39\n40\n41\n42\n43\n44\n45\n46\n47\n48\n49"  # floor of 20 lines
    assert log.exists()
    run.on("journalctl", out="nginx started\n")
    out = appconfig.logs("nginx", lines=5000)
    assert out == {"source": "journal (nginx)", "text": "nginx started\n"}
    assert run.calls[-1][:5] == ["journalctl", "-u", "nginx", "-n", "2000"]
