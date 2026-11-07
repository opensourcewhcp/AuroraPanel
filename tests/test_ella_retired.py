"""WAF Ella is gone: what it left on a server comes out safely, and its accounts don't gain access."""
import os
import subprocess

import pytest

from backend import authz, ella_retire as R, nginxwaf, panelusers


@pytest.fixture
def server(tmp_path, monkeypatch):
    calls = []

    def run(*argv):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(R, "_run", run)
    monkeypatch.setattr(R.shutil, "which", lambda name, path=None: f"/usr/sbin/{name}" if name in ("nft", "apache2ctl", "nginx") else None)
    monkeypatch.setattr(R.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(R.os, "name", "posix")
    monkeypatch.setattr(R, "DONE", tmp_path / "state" / ".ella-retired")
    monkeypatch.setattr(R, "UNIT_DIR", tmp_path / "systemd")
    monkeypatch.setattr(R, "CLI", tmp_path / "ella-cli")
    monkeypatch.setattr(R, "APACHE_FILES", (tmp_path / "zz-ella-rules.conf", tmp_path / "zz-ella-tester.conf"))
    waf = tmp_path / "aurora-waf"
    waf.mkdir()
    monkeypatch.setattr(R, "NGINX_MAIN", waf / "main.conf")
    monkeypatch.setattr(R, "NGINX_RULES", waf / "ella.conf")
    monkeypatch.setattr(R, "NGINX_TESTER", tmp_path / "aurora-ella-tester.conf")
    root = tmp_path / "app"
    (root / "backend" / "ella").mkdir(parents=True)
    (root / "backend" / "ella" / "service.py").write_text("old")
    (root / "backend" / "app.py").write_text("keep")
    monkeypatch.setattr(R.config, "ROOT", root)
    return tmp_path, calls


def _ella_installed(tmp_path):
    (tmp_path / "systemd").mkdir()
    for u in R.UNITS:
        (tmp_path / "systemd" / u).write_text("[Unit]")
    (tmp_path / "ella-cli").write_text("#!/bin/sh")
    (tmp_path / "zz-ella-rules.conf").write_text("rules")
    (tmp_path / "aurora-waf" / "ella.conf").write_text("rules")
    (tmp_path / "aurora-waf" / "main.conf").write_text(
        f"SecRuleEngine On\nInclude /x/pre.conf\nInclude {(tmp_path / 'aurora-waf' / 'ella.conf').as_posix()}\nInclude /x/post.conf\n")


def test_everything_comes_out_and_the_web_servers_reload(server):
    tmp_path, calls = server
    _ella_installed(tmp_path)
    R.cleanup()
    assert not (tmp_path / "systemd" / "aurora-ella-agent.service").exists() and not (tmp_path / "ella-cli").exists()
    assert ("systemctl", "disable", "--now", "aurora-ella-agent.service") in calls and ("systemctl", "daemon-reload") in calls
    assert ("nft", "delete", "table", "inet", "aurora_ella") in calls
    assert not (tmp_path / "zz-ella-rules.conf").exists() and not (tmp_path / "aurora-waf" / "ella.conf").exists()
    assert ("systemctl", "reload", "apache2") in calls and ("systemctl", "reload", "nginx") in calls
    assert not (tmp_path / "app" / "backend" / "ella").exists() and (tmp_path / "app" / "backend" / "app.py").exists()


def test_nginx_loses_the_include_with_the_file(server):
    """Otherwise Nginx can't load its settings and every site goes down."""
    tmp_path, _ = server
    _ella_installed(tmp_path)
    R.cleanup()
    assert (tmp_path / "aurora-waf" / "main.conf").read_text() == "SecRuleEngine On\nInclude /x/pre.conf\nInclude /x/post.conf\n"


def test_real_ip_settings_are_never_on_the_list():
    """Behind Cloudflare they are what stops InstaBan from banning the proxy."""
    listed = [p.as_posix() for p in (*R.APACHE_FILES, R.NGINX_RULES, R.NGINX_TESTER)]
    assert not any("proxies" in p or "realip" in p for p in listed)


def test_a_broken_symlink_is_removed(server):
    tmp_path, _ = server
    target = tmp_path / "zz-ella-rules.conf"
    try:
        os.symlink(tmp_path / "missing", target)
    except OSError:
        pytest.skip("no symlinks here")
    assert R._remove(target) and not os.path.lexists(target)


def test_nothing_to_do_reloads_nothing_and_runs_only_once(server):
    tmp_path, calls = server
    R.cleanup()
    assert not any(c[:2] == ("systemctl", "reload") for c in calls)
    calls.clear()
    R.cleanup()
    assert calls == []


def test_a_refused_config_isn_t_reloaded_and_is_reported(server, monkeypatch):
    tmp_path, calls = server
    _ella_installed(tmp_path)
    monkeypatch.setattr(R, "_run", lambda *a: calls.append(a) or subprocess.CompletedProcess(a, 1 if a[-1] == "-t" else 0, "", "bad line"))
    with pytest.raises(RuntimeError, match="bad line"):
        R.cleanup()
    assert not any(c[:2] == ("systemctl", "reload") for c in calls)


def test_nginx_settings_no_longer_mention_ella():
    assert "ella" not in nginxwaf.render_main("/s.conf", ["/r.conf"]).lower()


def test_retired_role_is_gone_and_gains_nothing():
    assert "soc_operator" not in panelusers.ROLES
    user = {"name": "old", "role": "soc_operator"}
    for method, path in (("GET", "/api/sites"), ("POST", "/api/firewall/rules"), ("GET", "/api/ella/events"), ("GET", "/api/files/read")):
        assert authz._decide(user, method, path), path
    assert authz._decide(user, "POST", "/api/logout") is None


def test_retired_role_can_t_sign_in(monkeypatch):
    monkeypatch.setattr(panelusers, "_all", lambda: [{"username": "old", "role": "soc_operator"}, {"username": "v", "role": "viewer"}])
    assert panelusers.retired("old") and not panelusers.retired("v") and not panelusers.retired("nobody")
