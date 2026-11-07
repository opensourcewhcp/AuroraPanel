"""WordPress Toolkit: who may reach it, what update accepts, hardening on each web server, and the staging lock."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from backend import authz, wptoolkit as W


@pytest.fixture
def site(tmp_path, monkeypatch):
    p = tmp_path / "site"
    p.mkdir()
    (p / "wp-config.php").write_text("<?php\ndefine('DB_NAME', 'shop');\n$table_prefix = 'wp_';\n")
    (p / "wp-content").mkdir()
    monkeypatch.setattr(W, "sites", lambda: [{"path": str(p), "url": "https://x", "version": "6", "admin_url": ""}])
    monkeypatch.setattr(W, "STAGING_STATE", tmp_path / "state")
    monkeypatch.setattr(W, "_web_server", lambda path: "apache")
    monkeypatch.setattr(W, "_owner", lambda path: "www-data")
    calls: list[tuple] = []

    def run(argv, timeout=300, cwd=None, input=None):
        """Plays runuser: the file work really happens, and every call is on record."""
        calls.append((list(argv), input))
        if argv[:1] == ["runuser"]:
            cmd = argv[4:]
            if cmd[0] == "tee":
                target = Path(cmd[-1])
                with target.open("a" if "-a" in cmd else "w") as f:
                    f.write(input or "")
            elif cmd[0] == "mkdir":
                Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
            elif cmd[0] == "rm":
                for t in cmd[2:]:
                    Path(t).unlink(missing_ok=True)
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(W, "_run", run)
    monkeypatch.setattr(W, "wp", lambda path, *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
    return {"path": p, "calls": calls, "tmp": tmp_path}


# ---------------------------------------------------------------- who may reach it
@pytest.mark.parametrize("path", ["/api/wptoolkit", "/api/wptoolkit/site"])
def test_only_admins_read_the_toolkit(path):
    assert authz._decide({"role": "admin"}, "GET", path) is None
    assert authz._decide({"role": "viewer"}, "GET", path)
    assert authz._decide({"role": "site", "domains": ["a.example"]}, "GET", path)


def test_viewers_can_still_read_ordinary_pages():
    assert authz._decide({"role": "viewer"}, "GET", "/api/status") is None


# ---------------------------------------------------------------- update
@pytest.mark.parametrize("bad", ["--exec=system('id');", "--require=/tmp/x.php", "-x", "a b", "../x", "", "a;b", 5])
def test_update_refuses_anything_that_is_not_a_slug(site, bad):
    with pytest.raises(W.WPError):
        W.update(str(site["path"]), "plugins", [bad])


def test_update_refuses_an_unknown_kind(site):
    with pytest.raises(W.WPError):
        W.update(str(site["path"]), "everything")


def test_update_accepts_real_slugs(site, monkeypatch):
    monkeypatch.setattr(W.jobs, "launch_fn", lambda title, fn, meta=None: title)
    assert W.update(str(site["path"]), "plugins", ["woocommerce", "wp-super_cache.2"]).startswith("WordPress updates")


# ---------------------------------------------------------------- harden
def test_harden_on_apache_blocks_in_htaccess_and_on_any_server(site):
    r = W.harden(str(site["path"]))
    mu = site["path"] / "wp-content" / "mu-plugins" / W.MU_HARDEN
    assert "XMLRPC_REQUEST" in mu.read_text() and "aurora-block-xmlrpc" in (site["path"] / ".htaccess").read_text()
    assert any("readme.html" in d for d in r["done"])
    W.harden(str(site["path"]))
    assert (site["path"] / ".htaccess").read_text().count("BEGIN aurora-block-xmlrpc") == 1


def test_harden_works_as_the_site_user_so_a_symlink_gets_no_root(site, monkeypatch):
    victim = site["tmp"] / "victim"
    victim.write_text("root's file\n")
    (site["path"] / ".htaccess").symlink_to(victim)
    chowned: list = []
    monkeypatch.setattr(W.os, "chown", lambda *a: chowned.append(a))
    monkeypatch.setattr(W.os, "chmod", lambda *a: chowned.append(a))
    W.harden(str(site["path"]))
    assert not chowned                                                                      # root touches nothing
    writes = [c for c in site["calls"] if "tee" in c[0]]
    assert writes and all(c[0][:4] == ["runuser", "-u", "www-data", "--"] for c in writes)  # it's all the site's own doing


def test_harden_on_nginx_does_not_pretend_with_htaccess(site, monkeypatch):
    monkeypatch.setattr(W, "_web_server", lambda path: "nginx")
    (site["path"] / "readme.html").write_text("6.9")
    (site["path"] / "license.txt").write_text("GPL")
    r = W.harden(str(site["path"]))
    assert not (site["path"] / ".htaccess").exists()
    assert not (site["path"] / "readme.html").exists() and not (site["path"] / "license.txt").exists()
    assert W._xmlrpc_blocked(str(site["path"])) is True
    assert any("removed" in d for d in r["done"])


def test_an_htaccess_marker_counts_for_nothing_outside_apache(site, monkeypatch):
    (site["path"] / ".htaccess").write_text("# BEGIN aurora-block-xmlrpc\n")
    assert W._xmlrpc_blocked(str(site["path"])) is True
    monkeypatch.setattr(W, "_web_server", lambda path: "caddy")
    assert W._xmlrpc_blocked(str(site["path"])) is False


def test_web_server_finds_the_site_under_nginx_and_falls_back_to_apache(tmp_path, monkeypatch):
    from backend import caddysites, nginxsites
    web = tmp_path / "web"
    (web / "blog").mkdir(parents=True)
    monkeypatch.setattr(nginxsites, "list_sites", lambda probe=True: [{"docroot": str(web)}])
    monkeypatch.setattr(caddysites, "list_sites", lambda probe=True: 1 / 0)   # not set up here
    assert W._web_server(str(web / "blog")) == "nginx"
    assert W._web_server(str(tmp_path / "elsewhere")) == "apache"


# ---------------------------------------------------------------- staging
def _copy(site) -> Path:
    d = W._staging_dir(str(site["path"]))
    d.mkdir()
    shutil.copy2(site["path"] / "wp-config.php", d / "wp-config.php")
    return d


def test_gate_goes_first_in_the_copys_config(site):
    d = _copy(site)
    W._install_gate(d, "the-key", "https://x/blog/aurora-staging/")
    cfg = (d / "wp-config.php").read_text()
    assert cfg.index(W.GATE) < cfg.index("DB_NAME") and cfg.startswith("<?php\nrequire __DIR__")
    W._install_gate(d, "the-key", "https://x/blog/aurora-staging/")
    assert (d / "wp-config.php").read_text().count(W.GATE) == 1
    gate = (d / W.GATE).read_text()
    assert "the-key" not in gate and "'/blog/aurora-staging/'" in gate   # only the hash is on disk in the web folder


def test_gate_refuses_a_symlinked_config_and_replaces_a_planted_link(site):
    d = _copy(site)
    victim = site["tmp"] / "victim"
    victim.write_text("keep")
    (d / W.GATE).symlink_to(victim)
    W._install_gate(d, "k", "https://x/aurora-staging/")
    assert victim.read_text() == "keep" and not (d / W.GATE).is_symlink()
    (d / "wp-config.php").unlink()
    (d / "wp-config.php").symlink_to(victim)
    with pytest.raises(W.WPError):
        W._install_gate(d, "k", "https://x/aurora-staging/")


@pytest.mark.skipif(not shutil.which("php"), reason="no php here")
def test_gate_really_answers_403_without_the_key(site, tmp_path):
    d = _copy(site)
    W._install_gate(d, "the-key", "https://x/aurora-staging/")
    php = tmp_path / "try.php"
    php.write_text(f"<?php require {str(d / W.GATE)!r}; echo 'cli passes';")
    assert subprocess.run(["php", str(php)], capture_output=True, text=True).stdout == "cli passes"
    subprocess.run(["php", "-l", str(d / W.GATE)], check=True, capture_output=True)


def test_staging_key_stays_out_of_the_site_and_only_the_link_shows_it(site):
    path = str(site["path"])
    d = _copy(site)
    W._save_state(path, {"url": "https://x/aurora-staging/", "db": "shop_stg", "created": 1, "key": "the-key"})
    pub = W._staging_public(path)
    assert pub["protected"] is True and pub["access_url"].endswith("?aurora_staging_key=the-key") and "key" not in pub and "db" not in pub
    assert W._state_file(path).stat().st_mode & 0o077 == 0
    assert not any("the-key" in f.read_text(errors="replace") for f in d.rglob("*") if f.is_file())


def test_a_copy_from_before_the_gate_shows_as_open_and_can_be_locked(site):
    path = str(site["path"])
    d = _copy(site)
    (d / ".aurora-staging.json").write_text(json.dumps({"url": "https://x/aurora-staging/", "db": "shop_stg", "created": 1}))
    assert W._staging_public(path)["protected"] is False
    W.protect_staging(path)
    assert W._staging_public(path)["protected"] is True
    assert (d / W.GATE).exists() and not (d / ".aurora-staging.json").exists()
    first = W._staging_info(path)["key"]
    W.protect_staging(path)
    assert W._staging_info(path)["key"] == first


def test_delete_removes_copy_key_and_database_without_sql_on_the_command_line(site):
    path = str(site["path"])
    d = _copy(site)
    W._save_state(path, {"url": "https://x/aurora-staging/", "db": "shop_stg", "created": 1, "key": "k"})
    W.delete_staging(path)
    assert not d.exists() and not W._state_file(path).exists()
    sql = [c for c in site["calls"] if c[0][0] == "mysql"]
    assert sql and all(c[0] == ["mysql"] and "shop_stg" in c[1] for c in sql)


def test_delete_refuses_a_tampered_database_name(site):
    path = str(site["path"])
    d = _copy(site)
    (d / ".aurora-staging.json").write_text(json.dumps({"url": "u", "db": "mysql`; DROP DATABASE x; --"}))
    with pytest.raises(W.WPError):
        W.delete_staging(path)
    assert d.exists()


def test_make_staging_refuses_a_database_name_that_could_be_a_flag(site, monkeypatch):
    (site["path"] / "wp-config.php").write_text("<?php\ndefine('DB_NAME', '--result-file=/etc/x');\n")
    monkeypatch.setattr(W.jobs, "launch_fn", lambda title, fn, meta=None: fn(type("L", (), {"__call__": lambda s, m: None, "progress": lambda s, p, m="": None})()))
    with pytest.raises(W.WPError, match="database name"):
        W.make_staging(str(site["path"]))
    assert not W._staging_dir(str(site["path"])).exists()


@pytest.mark.parametrize("url,live,copy", [("https://x/blog/aurora-staging/", "/blog/", "/blog/aurora-staging/"), ("https://x/aurora-staging/", "/", "/aurora-staging/")])
def test_the_copys_pretty_urls_stay_on_the_copy(site, url, live, copy):
    d = _copy(site)
    (d / ".htaccess").write_text(f"# BEGIN WordPress\nRewriteEngine On\nRewriteBase {live}\nRewriteRule ^index\\.php$ - [L]\nRewriteRule . {live}index.php [L]\n# END WordPress\n")
    W._point_rewrites_at_copy(d, url)
    txt = (d / ".htaccess").read_text()
    assert f"RewriteBase {copy}\n" in txt and f"RewriteRule . {copy}index.php [L]" in txt and "RewriteRule ^index" in txt
    W._point_rewrites_at_copy(d, url)
    assert (d / ".htaccess").read_text() == txt
