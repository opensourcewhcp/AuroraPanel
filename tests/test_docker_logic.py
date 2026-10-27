"""Unit coverage for the pure-logic and docker-mockable parts of backend.dockerapps.

The install/create/update job closures shell out to docker, compose and apache and are exercised
end-to-end on the Pi; here we cover the decision logic, parsers, URL/port building, and the
one-shot container actions with docker mocked, so regressions in that logic fail the suite."""
import json
import types

import pytest

from backend import dockerapps as dk


@pytest.fixture(autouse=True)
def quiet_host(monkeypatch, tmp_path):
    monkeypatch.setattr(dk, "_lan_ip", lambda: "192.168.0.100")
    monkeypatch.setattr(dk, "STATE", tmp_path / "docker-apps.json")
    monkeypatch.setattr(dk, "BASE", tmp_path / "apps")


def _ok(stdout="", returncode=0, stderr=""):
    return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


# ---- tiny pure helpers -------------------------------------------------------------------------
def test_cid_and_inst_and_parse_uid():
    assert dk._cid(" nginx ") == "nginx"
    for bad in ("", "-bad", "a/b", "x" * 200):
        with pytest.raises(dk.DockerError):
            dk._cid(bad)
    assert dk.parse_uid("1000") == (1000, 1000)
    assert dk.parse_uid("1000:2000") == (1000, 2000)
    assert dk.parse_uid("root") is None and dk.parse_uid("") is None and dk.parse_uid("1:x") is None
    with pytest.raises(dk.DockerError):
        dk._inst("nope")


def test_parse_ps_ports_dedupes_v4_and_v6():
    ports = dk._parse_ps_ports("192.168.0.100:10081->80/tcp, 0.0.0.0:53->53/udp, :::53->53/udp")
    assert {"host": 10081, "container": 80, "proto": "tcp", "bind": "192.168.0.100"} in ports
    assert sum(1 for p in ports if p["container"] == 53) == 1  # v4 + v6 collapsed
    assert dk._parse_ps_ports("") == [] and dk._parse_ps_ports(None) == []


def test_yaml_str_quotes_specials():
    for v in ("plain", "a: b", "yes", "123", "*ref", "@x", "has space", ""):
        q = dk._yaml_str(v)
        assert q.startswith('"') and q.endswith('"')  # json.dumps quotes every scalar


@pytest.mark.parametrize("inst,app,expected", [
    ({"access": "proxy", "domain": "app.example.com", "host_ports": {}}, {"ports": [], "path": "/ui/"}, "https://app.example.com/ui/"),
    ({"access": "lan", "lan_ip": "10.0.0.5", "domain": "", "host_ports": {"80/tcp": 8080}}, {"ports": [(80, "tcp", "web")]}, "http://10.0.0.5:8080/"),
    ({"access": "lan", "lan_ip": "10.0.0.5", "domain": "", "host_ports": {"80/tcp": 8080}, "tls_port": 8443}, {"ports": [(80, "tcp", "web")]}, "https://10.0.0.5:8443/"),
    ({"access": "public", "domain": "", "host_ports": {"80/tcp": 8080}}, {"ports": [(80, "tcp", "web")]}, "http://{host}:8080/"),
    ({"access": "lan", "lan_ip": "10.0.0.5", "domain": "", "host_ports": {}}, {"no_web": True, "ports": []}, ""),
    ({"access": "lan", "lan_ip": "10.0.0.5", "domain": "", "host_ports": {}}, {"ports": [(80, "tcp", "web")]}, ""),
    ({"access": "lan", "lan_ip": "10.0.0.5", "domain": "", "host_ports": {}, "host_network": None}, {"host_network": True, "ports": [(3000, "tcp", "web")]}, "http://10.0.0.5:3000/"),
])
def test_url_covers_every_access_shape(inst, app, expected):
    assert dk._url(inst, app) == expected


def test_port_bind_branches():
    assert dk.port_bind({"access": "proxy"}, "web") == "127.0.0.1"
    assert dk.port_bind({"access": "proxy", "lan_ip": "10.0.0.5"}, "dns") == "10.0.0.5"
    assert dk.port_bind({"access": "lan", "lan_ip": "10.0.0.5", "tls_port": 8443}, "web") == "127.0.0.1"  # TLS front proxies to loopback
    assert dk.port_bind({"access": "lan", "lan_ip": "10.0.0.5"}, "tcp") == "10.0.0.5"
    assert dk.port_bind({"access": "public"}, "tcp") == "0.0.0.0"


def test_needs_tls_front_rules():
    app = {"https_only": True, "ports": [(80, "tcp", "web")]}
    assert dk.needs_tls_front(app, {"access": "lan"}) is True
    assert dk.needs_tls_front(app, {"access": "public"}) is True
    assert dk.needs_tls_front(app, {"access": "proxy"}) is False  # proxy already gets HTTPS from the vhost
    assert dk.needs_tls_front({"https_only": False, "ports": [(80, "tcp", "web")]}, {"access": "lan"}) is False
    assert dk.needs_tls_front({"https_only": True, "ports": [(53, "udp", "dns")]}, {"access": "lan"}) is False


def test_shell_argv():
    a = dk.shell_argv("box")
    assert a[:3] == ["docker", "exec", "-it"] and "box" in a and a[-2] == "-c" and "bash" in a[-1]
    assert "-u" in dk.shell_argv("box", "www-data")
    with pytest.raises(dk.DockerError):
        dk.shell_argv("box", "bad user!")


# ---- one-shot actions with docker mocked -------------------------------------------------------
def test_exec_cmd(monkeypatch):
    seen = {}
    monkeypatch.setattr(dk, "_run", lambda argv, timeout=300, cwd=None: seen.update(argv=argv) or _ok(stdout="hi", returncode=0))
    out = dk.exec_cmd("box", "ls -la", user="root", workdir="/tmp")
    assert out["output"] == "hi" and out["code"] == 0
    assert "-u" in seen["argv"] and "-w" in seen["argv"]
    with pytest.raises(dk.DockerError):
        dk.exec_cmd("box", "   ")
    with pytest.raises(dk.DockerError):
        dk.exec_cmd("box", "ls", user="bad user!")


def test_container_action(monkeypatch):
    calls = []
    monkeypatch.setattr(dk, "_docker", lambda argv, timeout=120: calls.append(argv) or _ok())
    monkeypatch.setattr(dk, "_state", lambda: {"apps": {}})
    dk.container_action("box", "kill")
    assert calls[-1][0] == "kill"
    with pytest.raises(dk.DockerError):
        dk.container_action("box", "melt")


def test_container_action_managed_uses_compose(monkeypatch, tmp_path):
    (tmp_path / "apps" / "web").mkdir(parents=True)
    (tmp_path / "apps" / "web" / "docker-compose.yml").write_text("services: {}")
    monkeypatch.setattr(dk, "_state", lambda: {"apps": {"web": {"app": "custom"}}})
    monkeypatch.setattr(dk, "control", lambda name, action: {"ok": True, "via": "compose"})
    assert dk.container_action("web", "restart") == {"ok": True, "via": "compose"}


def test_container_remove_external(monkeypatch):
    calls = []
    monkeypatch.setattr(dk, "_state", lambda: {"apps": {}})
    monkeypatch.setattr(dk, "_docker", lambda argv, timeout=120: calls.append(argv) or _ok())
    assert dk.container_remove("box", delete_data=True)["ok"] is True
    assert "-v" in calls[0]


def test_container_logs_and_top(monkeypatch):
    monkeypatch.setattr(dk, "_run", lambda argv, timeout=300, cwd=None: _ok(stdout="line1\n"))
    assert "line1" in dk.container_logs("box", lines=99999)["text"]
    assert "line1" in dk.container_top("box")["text"]
    monkeypatch.setattr(dk, "_run", lambda argv, timeout=300, cwd=None: _ok(stderr="boom", returncode=1))
    for fn in (dk.container_logs, dk.container_top):
        with pytest.raises(dk.DockerError):
            fn("box")


def test_prune_and_image_remove(monkeypatch):
    monkeypatch.setattr(dk, "_run", lambda argv, timeout=300, cwd=None: _ok(stdout="Total reclaimed space: 1.2GB"))
    assert dk.prune() == {"ok": True, "reclaimed": "1.2GB"}
    monkeypatch.setattr(dk, "_docker", lambda argv, timeout=120: _ok())
    assert dk.image_remove("nginx:latest")["ok"] is True
    with pytest.raises(dk.DockerError):
        dk.image_remove("bad name!")


def test_images_merges_usage(monkeypatch):
    def run(argv, timeout=300, cwd=None):
        if "ps" in argv:
            return _ok(stdout="nginx:latest\tweb\nredis:7\tcache\n")
        return _ok(stdout=json.dumps({"ID": "abc", "Repository": "nginx", "Tag": "latest", "Size": "140MB", "CreatedSince": "2 days ago"}))
    monkeypatch.setattr(dk, "installed", lambda: True)
    monkeypatch.setattr(dk, "daemon_ok", lambda: True)
    monkeypatch.setattr(dk, "_run", run)
    imgs = dk.images()["images"]
    assert imgs[0]["repo"] == "nginx" and imgs[0]["used_by"] == ["web"]


def test_overview_states(monkeypatch):
    monkeypatch.setattr(dk, "installed", lambda: False)
    assert dk.overview() == {"installed": False, "running": False}
    monkeypatch.setattr(dk, "installed", lambda: True)
    monkeypatch.setattr(dk, "daemon_ok", lambda: False)
    assert dk.overview() == {"installed": True, "running": False}


def test_inspect_builds_panel_view(monkeypatch):
    raw = [{"Id": "f" * 64, "Name": "/web", "Config": {"Image": "nginx:latest", "Env": ["TZ=UTC"], "Cmd": ["nginx"]},
            "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}, "Memory": 0, "NanoCpus": 0, "Binds": [], "PortBindings": {}},
            "NetworkSettings": {"Ports": {}}, "State": {"Status": "running"}, "Mounts": []}]
    monkeypatch.setattr(dk, "_docker", lambda argv, timeout=120: _ok(stdout=json.dumps(raw)))
    monkeypatch.setattr(dk, "_state", lambda: {"apps": {}})
    info = dk.inspect("web")
    assert info["name"] == "web" and info["managed"] is False and info["custom"] is False
    monkeypatch.setattr(dk, "_docker", lambda argv, timeout=120: _ok(stdout="[]"))
    with pytest.raises(dk.DockerError):
        dk.inspect("gone")


def test_recreate_external_refuses_managed(monkeypatch):
    monkeypatch.setattr(dk, "inspect", lambda ref: {"managed": True, "name": "web"})
    with pytest.raises(dk.DockerError):
        dk.recreate_external("web", {})


def test_catalog_shape():
    c = dk.catalog()
    ids = {x["id"] for x in c["catalog"]}
    assert {"pihole", "mosquitto", "vaultwarden"} <= ids
    ph = next(x for x in c["catalog"] if x["id"] == "pihole")
    assert any(p["kind"] == "web" for p in ph["ports"])
