"""Nginx websites: what reaches the config files, and that a rejected change leaves everything as it was."""
import subprocess

import pytest

from backend import nginxsites as N


@pytest.mark.parametrize("settings", [
    {"server_name": "a.example; include /etc/shadow"}, {"server_name": "a.example\nlisten 1"}, {"server_name": ""}, {"server_name": "../x"},
    {"server_name": "a.example", "aliases": ["b.example; deny all"]},
    {"server_name": "a.example", "docroot": "/etc"}, {"server_name": "a.example", "docroot": "/var/www/../../etc"}, {"server_name": "a.example", "docroot": "/var/www/a b"},
    {"server_name": "a.example", "docroot": "/var/www/a;x"},
    {"server_name": "a.example", "mode": "cgi"}, {"server_name": "a.example", "mode": "proxy", "proxy": "file:///etc/passwd"}, {"server_name": "a.example", "mode": "proxy", "proxy": "http://x; deny all"},
    {"server_name": "a.example", "https": "letsencrypt"}, {"server_name": "a.example", "max_body_mb": 0}, {"server_name": "a.example", "max_body_mb": "x"},
    {"server_name": "a.example", "custom": "} server {"},
])
def test_anything_unexpected_is_refused(settings):
    with pytest.raises(N.NginxError):
        N.clean(settings)


def test_clean_fills_in_sensible_values():
    s = N.clean({"server_name": "Blog.Example.COM", "aliases": ["www.blog.example.com", "www.blog.example.com", "blog.example.com"]})
    assert s["server_name"] == "blog.example.com" and s["aliases"] == ["www.blog.example.com"]
    assert s["docroot"] == "/var/www/blog.example.com" and s["mode"] == "php" and s["https"] == "none" and s["max_body_mb"] == 64


def test_php_site_config():
    t = N.render(N.clean({"server_name": "a.example", "aliases": ["www.a.example"]}), "/run/php-fpm/www.sock")
    assert "server_name a.example www.a.example;" in t and "root /var/www/a.example;" in t
    assert "fastcgi_pass unix:/run/php-fpm/www.sock;" in t and "try_files $uri =404;" in t  # no running uploaded files by a crafted path
    assert "location ~ /\\.(?!well-known) { deny all; }" in t and "client_max_body_size 64m;" in t and "443" not in t


def test_php_site_needs_php():
    with pytest.raises(N.NginxError, match="PHP-FPM"):
        N.render(N.clean({"server_name": "a.example"}), None)


def test_static_and_proxy_sites():
    assert "fastcgi" not in N.render(N.clean({"server_name": "a.example", "mode": "static"}))
    t = N.render(N.clean({"server_name": "a.example", "mode": "proxy", "proxy": "http://127.0.0.1:3000"}))
    assert "proxy_pass http://127.0.0.1:3000;" in t and "proxy_set_header X-Forwarded-Proto $scheme;" in t and "fastcgi" not in t


def test_https_and_forcing_it():
    t = N.render(N.clean({"server_name": "a.example", "mode": "static", "https": "selfsigned", "force_https": True}))
    assert "listen 443 ssl;" in t and "ssl_certificate /etc/nginx/aurora-ssl/a.example.crt;" in t
    assert "return 301 https://$host$request_uri;" in t and "acme-challenge" in t
    assert N.clean({"server_name": "a.example", "force_https": True})["force_https"] is False  # nothing to force it to


def test_settings_survive_in_the_file(tmp_path, monkeypatch):
    monkeypatch.setattr(N, "CONF_DIR", tmp_path)
    s = N.clean({"server_name": "a.example", "mode": "static", "custom": "add_header X-Test 1;"})
    (tmp_path / "aurora-site-a.example.conf").write_text(N.render(s))
    assert "add_header X-Test 1;" in N.render(s) and N.list_sites(probe=False)[0]["custom"] == "add_header X-Test 1;"


@pytest.fixture
def box(tmp_path, monkeypatch):
    """A pretend server: nginx -t passes unless a config contains BROKEN."""
    conf = tmp_path / "conf.d"
    conf.mkdir()
    calls = []
    monkeypatch.setattr(N, "CONF_DIR", conf)
    monkeypatch.setattr(N, "DEFAULT_CONF", conf / "aurora-default.conf")
    monkeypatch.setattr(N, "DEFAULT_D", tmp_path / "none")
    monkeypatch.setattr(N, "WEB_BASE", tmp_path / "www")
    monkeypatch.setattr(N, "_DOCROOT", __import__("re").compile(r"^.+$"))
    monkeypatch.setattr(N, "TRASH", tmp_path / "trash")
    monkeypatch.setattr(N, "SSL_DIR", tmp_path / "ssl")
    monkeypatch.setattr(N, "RELOAD_SETTLE", 0)
    monkeypatch.setattr(N, "installed", lambda: True)
    monkeypatch.setattr(N, "_active", lambda u: u == "nginx")
    monkeypatch.setattr(N, "php_socket", lambda: "/run/php.sock")
    monkeypatch.setattr(N, "_probe", lambda name, https=False: "200")
    monkeypatch.setattr(N, "_other_default_server", lambda: False)
    monkeypatch.setattr(N, "_open_firewall", lambda https: calls.append("firewall"))

    def run(argv, timeout=60):
        calls.append(" ".join(argv))
        if argv[:2] == ["nginx", "-t"] and any("BROKEN" in p.read_text() for p in conf.glob("*")):
            return subprocess.CompletedProcess(argv, 1, "", "nginx: [emerg] unknown directive BROKEN")
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(N, "_run", run)
    return {"conf": conf, "calls": calls, "www": tmp_path / "www"}


def _site(box, name="a.example", **kw):
    return {"server_name": name, "docroot": str(box["www"] / name), **kw}


def test_create_checks_then_reloads_and_makes_a_starter_page(box):
    r = N.create(_site(box))
    assert r["ok"] and r["answer"] == "200"
    assert (box["conf"] / "aurora-site-a.example.conf").exists() and (box["www"] / "a.example" / "index.html").exists()
    assert (box["conf"] / "aurora-default.conf").exists()
    assert box["calls"].index("nginx -t") < box["calls"].index("systemctl reload nginx") and "firewall" in box["calls"]


def test_a_rejected_config_changes_nothing(box):
    N.create(_site(box))
    before = (box["conf"] / "aurora-site-a.example.conf").read_text()
    with pytest.raises(N.NginxError, match="BROKEN"):
        N.update("a.example", {"custom": "BROKEN;"})
    assert (box["conf"] / "aurora-site-a.example.conf").read_text() == before
    with pytest.raises(N.NginxError, match="rejected"):
        N.create(_site(box, "b.example", custom="BROKEN;"))
    assert not (box["conf"] / "aurora-site-b.example.conf").exists()


def test_names_cannot_be_taken_twice(box):
    N.create(_site(box, aliases=["www.a.example"]))
    with pytest.raises(N.NginxError, match="already exists"):
        N.create(_site(box))
    with pytest.raises(N.NginxError, match="already answers"):
        N.create(_site(box, "www.a.example"))
    N.create(_site(box, "b.example"))
    with pytest.raises(N.NginxError, match="already answers"):
        N.update("b.example", {"aliases": ["www.a.example"]})


def test_a_proxy_site_gets_selinux_permission_and_others_do_not(box, monkeypatch):
    real = N._run
    state = {"bool": "off"}

    def run(argv, timeout=60):
        if argv[0] == "getsebool":
            return subprocess.CompletedProcess(argv, 0, f"httpd_can_network_connect --> {state['bool']}", "")
        if argv[0] == "setsebool":
            state["bool"] = "on"
        return real(argv, timeout)
    monkeypatch.setattr(N, "_run", run)
    monkeypatch.setattr(N.shutil, "which", lambda name, path=None: f"/usr/sbin/{name}")
    assert N.proxy_blocked() is True
    N.create(_site(box, mode="static"))
    assert state["bool"] == "off"
    N.create(_site(box, "b.example", mode="proxy", proxy="http://127.0.0.1:3000"))
    assert state["bool"] == "on" and N.proxy_blocked() is False


def test_no_selinux_means_nothing_to_allow(box, monkeypatch):
    monkeypatch.setattr(N.shutil, "which", lambda name, path=None: None)
    assert N.proxy_blocked() is False and N.allow_proxy() == {"ok": True, "blocked": False}


def test_turning_a_site_off_and_on(box):
    N.create(_site(box))
    assert N.set_enabled("a.example", False)["enabled"] is False
    assert not (box["conf"] / "aurora-site-a.example.conf").exists() and (box["conf"] / "aurora-site-a.example.conf.off").exists()
    assert N.list_sites()[0]["enabled"] is False and N.list_sites()[0]["answer"] is None
    N.set_enabled("a.example", True)
    assert (box["conf"] / "aurora-site-a.example.conf").exists()


def test_removing_keeps_files_unless_asked_and_then_only_binned(box):
    N.create(_site(box))
    N.create(_site(box, "b.example"))
    assert N.delete("a.example")["moved_to"] is None and (box["www"] / "a.example").exists()
    moved = N.delete("b.example", True)["moved_to"]
    assert moved and not (box["www"] / "b.example").exists() and (__import__("pathlib").Path(moved) / "index.html").exists()
    with pytest.raises(N.NginxError, match="No such"):
        N.delete("b.example")


def test_control_refuses_a_broken_config(box):
    (box["conf"] / "x.conf").write_text("BROKEN")
    with pytest.raises(N.NginxError, match="left as it is"):
        N.control("restart")
    assert "systemctl restart nginx" not in box["calls"]
    with pytest.raises(N.NginxError, match="Unknown"):
        N.control("stop; rm -rf /")


def test_routes(admin, box):
    assert admin.get("/api/nginx").json()["installed"] is True
    r = admin.post("/api/nginx/sites", json=_site(box, mode="static"))
    assert r.status_code == 200 and admin.get("/api/nginx").json()["sites"][0]["server_name"] == "a.example"
    assert admin.post("/api/nginx/sites", json={"server_name": "bad name"}).status_code == 400
    assert admin.post("/api/nginx/sites/a.example/enabled", json={"on": False}).json()["enabled"] is False
    assert admin.delete("/api/nginx/sites/a.example").json()["ok"]


def test_routes_need_a_login(client):
    assert client.get("/api/nginx").status_code == 401
    assert client.post("/api/nginx/sites", json={"server_name": "a.example"}).status_code == 401
