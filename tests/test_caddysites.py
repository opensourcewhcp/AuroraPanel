"""Caddy websites and the Nginx additions (Let's Encrypt, WordPress): what they write and what they refuse."""
import json
import subprocess

import pytest

from backend import apps, caddysites as C, jobs, nginxsites as N
from backend.ella import collector


def _posix_ok(monkeypatch):
    monkeypatch.setattr(N, "_DOCROOT", __import__("re").compile(r"^.+$"))


def test_caddy_php_site():
    t = C.render(C.clean({"server_name": "a.example", "aliases": ["www.a.example"]}), "/run/php-fpm/www.sock")
    assert "http://a.example, http://www.a.example {" in t and "root * /var/www/a.example" in t
    assert "php_fastcgi unix//run/php-fpm/www.sock" in t and "file_server" in t and "respond @hidden 403" in t and "format json" in t


def test_caddy_needs_php_for_a_php_site():
    with pytest.raises(C.CaddyError, match="PHP-FPM"):
        C.render(C.clean({"server_name": "a.example"}), None)


def test_caddy_proxy_and_https_choices():
    t = C.render(C.clean({"server_name": "a.example", "mode": "proxy", "proxy": "http://127.0.0.1:3000", "https": "internal"}), None)
    assert "reverse_proxy http://127.0.0.1:3000" in t and "tls internal" in t and "\na.example {" in t and "file_server" not in t
    t = C.render(C.clean({"server_name": "a.example", "mode": "static", "https": "auto"}), None)
    assert "\na.example {" in t and "tls internal" not in t and "http://" not in t.split("\n", 2)[2]


@pytest.mark.parametrize("settings", [{"server_name": "a.example; x"}, {"server_name": "a.example", "https": "letsencrypt"}, {"server_name": "myhost", "https": "auto"}, {"server_name": "a.example", "docroot": "/etc"},
                                      {"server_name": "a.example", "custom": "} evil {"}, {"server_name": "a.example", "mode": "proxy", "proxy": "file:///etc/passwd"}])
def test_caddy_refuses_bad_settings(settings):
    with pytest.raises(C.CaddyError):
        C.clean(settings)


@pytest.fixture
def caddy(tmp_path, monkeypatch):
    _posix_ok(monkeypatch)
    state = {"calls": []}
    sites = tmp_path / "Caddyfile.d"
    main = tmp_path / "Caddyfile"
    main.write_text(":80 {\n}\n")
    pool = tmp_path / "www.conf"
    pool.write_text("listen.acl_users = apache,nginx\n")

    def run(argv, timeout=60):
        state["calls"].append(" ".join(argv))
        if argv[:2] == ["caddy", "validate"] and any("BROKEN" in p.read_text() for p in sites.glob("*")):
            return subprocess.CompletedProcess(argv, 1, "", "Error: unrecognized directive: BROKEN")
        return subprocess.CompletedProcess(argv, 0, "v2.11 x", "")
    for mod, names in ((C, ("CADDYFILE", main)), (C, ("SITES_DIR", sites)), (C, ("LOG_DIR", tmp_path / "log")), (C, ("PHP_POOL", pool)), (C, ("RELOAD_SETTLE", 0))):
        monkeypatch.setattr(mod, names[0], names[1])
    monkeypatch.setattr(C, "_run", run)
    monkeypatch.setattr(N, "_run", run)
    monkeypatch.setattr(C, "installed", lambda: True)
    monkeypatch.setattr(C, "_active", lambda u: u == "caddy")
    monkeypatch.setattr(C, "_probe", lambda s: "200")
    monkeypatch.setattr(N, "php_socket", lambda: "/run/php.sock")
    monkeypatch.setattr(C.shutil, "chown", lambda *a, **k: None)
    return {**state, "sites": sites, "main": main, "pool": pool, "www": tmp_path / "www"}


def _site(c, name="a.example", **kw):
    return {"server_name": name, "docroot": str(c["www"] / name).replace("\\", "/"), **kw}


def test_caddy_create_checks_then_reloads_and_lets_it_use_php(caddy):
    r = C.create(_site(caddy))
    assert r["ok"] and r["answer"] == "200" and (caddy["sites"] / "aurora-site-a.example.caddyfile").exists()
    assert caddy["calls"].index(f"caddy validate --config {C.CADDYFILE} --adapter caddyfile") < caddy["calls"].index("systemctl reload caddy")
    assert "import" in caddy["main"].read_text() and caddy["pool"].read_text().strip() == "listen.acl_users = apache,nginx,caddy" and "systemctl restart php-fpm" in caddy["calls"]
    caddy["calls"].clear()
    C.create(_site(caddy, "b.example"))
    assert "systemctl restart php-fpm" not in caddy["calls"]  # already allowed
    assert caddy["main"].read_text().count("import") == 1


def test_caddy_import_line_is_not_added_twice(caddy):
    caddy["main"].write_text("import Caddyfile.d/*.caddyfile\n")
    C.create(_site(caddy, mode="static"))
    assert caddy["main"].read_text().count("import ") == 1


def test_caddy_never_tries_to_change_the_systems_trust_store(caddy):
    C.create(_site(caddy, mode="static"))
    text = caddy["main"].read_text()
    assert text.startswith("{\n\tskip_install_trust\n}\n") and text.count("skip_install_trust") == 1
    C.create(_site(caddy, "b.example", mode="static"))
    assert caddy["main"].read_text().count("skip_install_trust") == 1


def test_caddy_trust_option_joins_an_existing_global_block(caddy):
    caddy["main"].write_text("# my settings\n{\n\temail me@example.org\n}\n:80 {\n}\n")
    C.create(_site(caddy, mode="static"))
    assert caddy["main"].read_text().startswith("# my settings\n{\n\tskip_install_trust\n\temail me@example.org\n}")


def test_caddy_rejected_config_changes_nothing(caddy):
    C.create(_site(caddy, mode="static"))
    before = (caddy["sites"] / "aurora-site-a.example.caddyfile").read_text()
    with pytest.raises(C.CaddyError, match="BROKEN"):
        C.update("a.example", {"custom": "BROKEN"})
    assert (caddy["sites"] / "aurora-site-a.example.caddyfile").read_text() == before
    with pytest.raises(C.CaddyError, match="rejected"):
        C.create(_site(caddy, "b.example", mode="static", custom="BROKEN"))
    assert not (caddy["sites"] / "aurora-site-b.example.caddyfile").exists()


def test_caddy_on_off_and_remove(caddy):
    C.create(_site(caddy, mode="static", aliases=["www.a.example"]))
    with pytest.raises(C.CaddyError, match="already"):
        C.create(_site(caddy, "www.a.example", mode="static"))
    assert C.set_enabled("a.example", False)["enabled"] is False and C.list_sites()[0]["answer"] is None
    C.set_enabled("a.example", True)
    assert C.delete("a.example")["moved_to"] is None and (caddy["www"] / "a.example").exists() and not C.list_sites()
    with pytest.raises(C.CaddyError, match="No such"):
        C.delete("a.example")


def test_caddy_routes(admin, caddy):
    assert admin.get("/api/caddy").json()["installed"] is True
    assert admin.post("/api/caddy/sites", json=_site(caddy, mode="static")).status_code == 200
    assert admin.post("/api/caddy/sites", json={"server_name": "bad name"}).status_code == 400
    assert admin.delete("/api/caddy/sites/a.example").json()["ok"]


def test_caddy_routes_need_a_login(client):
    assert client.get("/api/caddy").status_code == 401


def test_caddy_access_log_becomes_an_event():
    line = json.dumps({"ts": 1793848000.5, "status": 404, "size": 12, "request": {"remote_ip": "203.0.113.9", "client_ip": "203.0.113.9", "method": "GET", "host": "A.example:443", "uri": "/x?token=SECRET&y=1", "headers": {"User-Agent": ["ua/1"], "Cookie": ["sid=SECRET"]}}}).encode()
    e = collector.PARSERS["caddy_access"].parse(line, {"path": "/l", "inode": 1, "offset": 0})
    assert (e["client_ip"], e["domain"], e["url"], e["status"], e["user_agent"]) == ("203.0.113.9", "a.example", "/x", 404, "ua/1")
    assert "SECRET" not in json.dumps(e) and json.loads(e["query_keys"]) == ["token", "y"]
    assert collector.PARSERS["caddy_access"].parse(b"not json", {"path": "/l", "inode": 1, "offset": 0}) is None


# ----------------------------------------------------------------------------- Let's Encrypt on Nginx
@pytest.fixture
def ngx(tmp_path, monkeypatch):
    _posix_ok(monkeypatch)
    conf = tmp_path / "conf.d"
    conf.mkdir()
    live = tmp_path / "live"
    state = {"calls": [], "certbot_rc": 0}

    def run(argv, timeout=60):
        state["calls"].append(argv)
        if argv[0] == "certbot":
            if state["certbot_rc"] == 0:
                for n in argv[argv.index("-d") + 1:argv.index("-d") + 2]:
                    (live / n).mkdir(parents=True, exist_ok=True)
                    (live / n / "fullchain.pem").write_text("x")
            return subprocess.CompletedProcess(argv, state["certbot_rc"], "out", "Challenge failed")
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(N, "CONF_DIR", conf)
    monkeypatch.setattr(N, "DEFAULT_CONF", conf / "aurora-default.conf")
    monkeypatch.setattr(N, "DEFAULT_D", tmp_path / "none")
    monkeypatch.setattr(N, "LE_LIVE", live)
    monkeypatch.setattr(N, "RELOAD_SETTLE", 0)
    monkeypatch.setattr(N, "_run", run)
    monkeypatch.setattr(N, "installed", lambda: True)
    monkeypatch.setattr(N, "_active", lambda u: u == "nginx")
    monkeypatch.setattr(N, "php_socket", lambda: "/run/php.sock")
    monkeypatch.setattr(N, "_probe", lambda name, https=False: "200")
    monkeypatch.setattr(N, "_other_default_server", lambda: True)
    monkeypatch.setattr(N, "_open_firewall", lambda https: None)
    monkeypatch.setattr(N.shutil, "which", lambda name, path=None: f"/usr/bin/{name}")
    state["www"] = tmp_path / "www"
    return state


def _ng(s, name="shop.example.com", **kw):
    return {"server_name": name, "docroot": str(s["www"] / name).replace("\\", "/"), **kw}


def _finish(job):
    import time
    while job.status == "running":
        time.sleep(0.02)
    return job


def test_a_certificate_switches_the_site_to_https(ngx):
    N.create(_ng(ngx, mode="static", aliases=["www.shop.example.com"]))
    j = _finish(N.letsencrypt("shop.example.com", "me@example.org"))
    assert j.status == "done"
    argv = next(a for a in ngx["calls"] if a[0] == "certbot")
    assert argv[1:3] == ["certonly", "--webroot"] and "www.shop.example.com" in argv and "me@example.org" in argv and "systemctl reload nginx" in argv
    t = N._conf("shop.example.com").read_text()
    assert "listen 443 ssl;" in t and "live/shop.example.com/fullchain.pem" in t.replace("\\", "/") and "return 301 https" in t and "acme-challenge" in t
    assert N.list_sites()[0]["https"] == "letsencrypt" and N.list_sites()[0]["le_ready"] is True


def test_a_refused_certificate_leaves_the_site_as_it_was(ngx):
    N.create(_ng(ngx, mode="static"))
    before = N._conf("shop.example.com").read_text()
    ngx["certbot_rc"] = 1
    j = _finish(N.letsencrypt("shop.example.com", "me@example.org"))
    assert j.status == "failed" and any("Challenge failed" in str(x) for x in j.lines)
    assert N._conf("shop.example.com").read_text() == before


@pytest.mark.parametrize("name", ["printer.local", "a.test", "x.example", "intranet.lan"])
def test_private_names_cannot_ask_for_a_certificate(ngx, name):
    N.create(_ng(ngx, name, mode="static"))
    with pytest.raises(N.NginxError, match="public domain"):
        N.letsencrypt(name, "me@example.org")


def test_a_bad_email_is_refused(ngx):
    N.create(_ng(ngx, mode="static"))
    with pytest.raises(N.NginxError, match="email"):
        N.letsencrypt("shop.example.com", "me; rm -rf /")


def test_https_cannot_be_chosen_without_the_certificate():
    with pytest.raises(N.NginxError, match="no Let's Encrypt certificate"):
        N.clean({"server_name": "shop.example.com", "https": "letsencrypt"})


# ----------------------------------------------------------------------------- WordPress on Nginx
def test_wordpress_goes_to_the_site_folder_without_apache(ngx, monkeypatch):
    N.create(_ng(ngx))
    seen = {}

    class J:
        id = "j1"
    monkeypatch.setattr(apps, "install_wordpress", lambda o: seen.update(o) or J())
    assert N.wordpress("shop.example.com", {"admin_user": "boss", "admin_email": "a@b.co", "admin_pass": "x" * 12}).id == "j1"
    assert seen["mode"] == "webroot" and seen["url"] == "http://shop.example.com" and seen["path"].endswith("shop.example.com")


def test_wordpress_needs_php(ngx):
    N.create(_ng(ngx, mode="static"))
    with pytest.raises(N.NginxError, match="PHP"):
        N.wordpress("shop.example.com", {})


def test_webroot_mode_stays_inside_var_www():
    for path in ("/etc", "/var/www/../../etc", ""):
        with pytest.raises(apps.AppError):
            apps._resolve_target({"mode": "webroot", "path": path, "url": "http://a.example"}, lambda *_: None, dry=True)


def test_jobs_module_is_importable():
    assert jobs.launch_fn
