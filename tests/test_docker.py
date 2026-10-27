"""Docker: compose rendering for catalog and custom containers, the settings parsers, and the container listing."""
import pytest

from backend import dockerapps as dk


@pytest.fixture(autouse=True)
def quiet_host(monkeypatch, tmp_path):
    monkeypatch.setattr(dk, "_lan_ip", lambda: "192.168.0.100")
    monkeypatch.setattr(dk, "_port_free", lambda port, proto="tcp", host="0.0.0.0": port != 8080)  # 8080 is "busy"
    monkeypatch.setattr(dk, "STATE", tmp_path / "docker-apps.json")
    monkeypatch.setattr(dk, "BASE", tmp_path / "apps")


def _custom(**over):
    data = {"name": "myapp", "image": "nginx:latest", "access": "lan", "ports": [{"container": 80, "proto": "tcp", "host": 0, "kind": "web"}],
            "volumes": [{"host": "", "container": "/usr/share/nginx/html"}], "env": [{"key": "TZ", "value": "UTC"}]}
    data.update(over)
    return data


def test_custom_spec_renders_compose_with_lan_bind_and_free_port():
    name, spec, inst = dk.custom_spec(_custom(restart="always", mem_limit="512m", cpus="1.5", command="nginx -g 'daemon off;'", uid="101"))
    assert name == "myapp" and inst["host_ports"] == {"80/tcp": 10080}  # auto-picked (below 1024 → 10000+port)
    yml = dk.render_compose(name, spec, inst)
    assert '"192.168.0.100:10080:80/tcp"' in yml  # local network only
    assert "restart: always" in yml and 'mem_limit: "512m"' in yml and 'cpus: "1.5"' in yml
    assert "command: \"nginx -g 'daemon off;'\"" in yml
    assert '/apps/myapp/usr-share-nginx-html:/usr/share/nginx/html' in yml.replace("\\", "/")
    assert 'TZ: "UTC"' in yml and 'aurora.app: "custom"' in yml and 'aurora.managed: "myapp"' in yml
    assert spec["uid"] == "101" and dk.parse_uid("101") == (101, 101) and dk.parse_uid("1000:1000") == (1000, 1000)


def test_custom_public_and_proxy_binds():
    _, spec, inst = dk.custom_spec(_custom(access="public", ports=[{"container": 80, "proto": "tcp", "host": 8443, "kind": "web"}, {"container": 53, "proto": "udp", "host": 5353}]))
    yml = dk.render_compose("myapp", spec, inst)
    assert '"0.0.0.0:8443:80/tcp"' in yml and '"0.0.0.0:5353:53/udp"' in yml
    _, spec, inst = dk.custom_spec(_custom(access="proxy", domain="App.Example.com."))
    assert inst["domain"] == "app.example.com"
    assert '"127.0.0.1:10080:80/tcp"' in dk.render_compose("myapp", spec, inst)  # web port stays behind Apache


@pytest.mark.parametrize("bad,msg", [
    ({"name": "My App"}, "Name"),
    ({"image": "not an image!"}, "Image"),
    ({"access": "proxy", "domain": "nope"}, "web address"),
    ({"access": "proxy", "domain": "a.example.com", "ports": [{"container": 80, "host": 0, "kind": "tcp"}]}, "web page"),
    ({"volumes": [{"host": "/etc", "container": "/x"}]}, "server itself"),
    ({"volumes": [{"host": "", "container": "relative"}]}, "start with /"),
    ({"ports": [{"container": 80, "host": 8080, "kind": "web"}]}, "already in use"),
    ({"ports": [{"container": 70000, "host": 0}]}, "1–65535"),
    ({"env": [{"key": "9bad", "value": "x"}]}, "variable name"),
    ({"mem_limit": "lots"}, "512m"),
    ({"cpus": "99"}, "CPUs"),
    ({"uid": "root"}, "User ID"),
    ({"devices": ["/etc/passwd"]}, "/dev/"),
    ({"restart": "sometimes"}, "restart"),
])
def test_custom_spec_rejects_bad_input(bad, msg):
    with pytest.raises(dk.DockerError, match=msg):
        dk.custom_spec(_custom(**bad))


def test_host_network_publishes_nothing():
    _, spec, inst = dk.custom_spec(_custom(host_network=True, privileged=True, devices=["/dev/ttyUSB0"], ports=[{"container": 80, "host": 80}]))
    yml = dk.render_compose("myapp", spec, inst)
    assert "network_mode: host" in yml and "privileged: true" in yml and '"/dev/ttyUSB0"' in yml and "ports:" not in yml


def test_catalog_compose_still_binds_by_access():
    app = dk.CATALOG["uptimekuma"]
    inst = {"app": "uptimekuma", "access": "proxy", "lan_ip": "192.168.0.100", "host_ports": {"3001/tcp": 10001}, "env": {}, "image": app["image"], "restart": "on-failure"}
    yml = dk.render_compose("kuma", app, inst)
    assert '"127.0.0.1:10001:3001/tcp"' in yml and "restart: on-failure" in yml
    inst["access"] = "lan"
    assert '"192.168.0.100:10001:3001/tcp"' in dk.render_compose("kuma", app, inst)
    assert dk.app_def(inst) is app
    assert dk.app_def({"app": "custom", "spec": {"name": "X"}})["name"] == "X"


def test_parsers():
    assert dk._parse_env(["A=1", {"key": "B", "value": "two"}, "  ", "=x"]) == {"A": "1", "B": "two"}
    assert dk._parse_limits("1G", "0.5") == ("1g", "0.5") and dk._parse_limits("", "") == ("", "")
    ps = dk._parse_ps_ports("0.0.0.0:10000->5678/tcp, :::10000->5678/tcp, 127.0.0.1:53->53/udp")
    assert ps == [{"host": 10000, "container": 5678, "proto": "tcp", "bind": "0.0.0.0"}, {"host": 53, "container": 53, "proto": "udp", "bind": "127.0.0.1"}]
    with pytest.raises(dk.DockerError, match="twice"):
        dk._parse_ports([{"container": 1, "host": 5}, {"container": 2, "host": 5}])
    with pytest.raises(dk.DockerError, match="listen address"):
        dk._parse_ports([{"container": 1, "host": 5, "bind": "lan"}])
    assert dk.shell_argv("n8n", "node")[:5] == ["docker", "exec", "-it", "-u", "node"]
    with pytest.raises(dk.DockerError):
        dk.shell_argv("n8n; rm -rf /")
    with pytest.raises(dk.DockerError):
        dk._cid("../x")


def test_own_data_hands_folders_to_the_image_user(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(dk.os, "chown", lambda p, u, g, **kw: calls.append((str(p), u, g)))
    d = tmp_path / "data"; d.mkdir(); (d / "f").write_text("x")
    dk.own_data({"uid": "1000:1000"}, [d])
    assert (str(d), 1000, 1000) in calls and (str(d / "f"), 1000, 1000) in calls
    calls.clear()
    dk.own_data({}, [d])
    assert not calls
    assert dk.CATALOG["n8n"]["uid"] == "1000:1000"  # n8n runs as node — a root-owned folder crash-loops it (EACCES)


def test_containers_listing_merges_panel_state(monkeypatch):
    monkeypatch.setattr(dk, "installed", lambda: True)
    monkeypatch.setattr(dk, "daemon_ok", lambda: True)
    monkeypatch.setattr(dk, "_state", lambda: {"apps": {"n8n": {"app": "n8n", "access": "lan", "lan_ip": "192.168.0.100", "host_ports": {"5678/tcp": 10000}, "env": {}, "secret_keys": []}}})
    ps = ('{"ID":"abc123456789ff","Names":"n8n","Image":"n8nio/n8n:latest","State":"restarting","Status":"Restarting (1) 5 seconds ago","Ports":"192.168.0.100:10000->5678/tcp","Labels":"aurora.app=n8n","CreatedAt":"x","Command":"tini"}\n'
          '{"ID":"def","Names":"redis","Image":"redis:7","State":"running","Status":"Up 2 days","Ports":"","Labels":"com.docker.compose.project=stack","CreatedAt":"x","Command":"redis"}\n'
          '{"ID":"ghi","Names":"hand","Image":"alpine","State":"exited","Status":"Exited (0)","Ports":"","Labels":"","CreatedAt":"x","Command":"sh"}\n')
    stats = '{"Name":"redis","CPUPerc":"0.30%","MemUsage":"8MiB / 8GiB","MemPerc":"0.10%","NetIO":"1kB / 2kB"}\n'

    def run(argv, timeout=300, cwd=None):
        out = ps if argv[1] == "ps" else stats if argv[1] == "stats" else ""
        return type("R", (), {"returncode": 0, "stdout": out, "stderr": ""})()
    monkeypatch.setattr(dk, "_run", run)
    cs = dk.containers()["containers"]
    assert [c["name"] for c in cs] == ["redis", "n8n", "hand"]  # running first, then by state
    n8n = next(c for c in cs if c["name"] == "n8n")
    assert n8n["origin"] == "app" and n8n["managed"] and n8n["title"] == "n8n" and n8n["url"] == "http://192.168.0.100:10000/"
    assert n8n["ports"] == [{"host": 10000, "container": 5678, "proto": "tcp", "bind": "192.168.0.100"}] and n8n["id"] == "abc123456789"
    redis = next(c for c in cs if c["name"] == "redis")
    assert redis["origin"] == "compose" and redis["project"] == "stack" and redis["cpu"] == "0.30%"
    assert next(c for c in cs if c["name"] == "hand")["origin"] == "external"


def test_page_path_in_urls_and_spec():
    _, spec, inst = dk.custom_spec(_custom(path="/admin/"))
    assert spec["path"] == "/admin/"
    assert dk._url(inst, spec) == f"http://192.168.0.100:{inst['host_ports']['80/tcp']}/admin/"
    _, spec, inst = dk.custom_spec(_custom(path="/"))
    assert spec["path"] == "" and dk._url(inst, spec).endswith("/")
    with pytest.raises(dk.DockerError):
        dk.custom_spec(_custom(path="admin"))
    with pytest.raises(dk.DockerError):
        dk.custom_spec(_custom(path="/../etc"))
    # Pi-hole's page is /admin, so its Open link must say so
    app = dk.CATALOG["pihole"]
    inst = {"app": "pihole", "access": "lan", "lan_ip": "192.168.0.100", "domain": "", "host_ports": {"80/tcp": 10081, "53/tcp": 53, "53/udp": 53}, "env": {}, "folders": {}}
    assert dk._url(inst, app) == "http://192.168.0.100:10081/admin/"
    assert "NET_ADMIN" in dk.render_compose("pihole", app, inst)


def test_host_port_check_uses_the_bind_address(monkeypatch):
    seen = []
    monkeypatch.setattr(dk, "_port_free", lambda port, proto="tcp", host="0.0.0.0": seen.append((port, proto, host)) or True)
    dk._check_host_ports([{"container": 53, "host": 53, "proto": "udp", "kind": "dns", "bind": ""}], set(), {"access": "lan", "lan_ip": "192.168.0.100"})
    dk._check_host_ports([{"container": 80, "host": 8081, "proto": "tcp", "kind": "web", "bind": ""}], set(), {"access": "proxy", "lan_ip": "192.168.0.100"})
    dk._check_host_ports([{"container": 80, "host": 8082, "proto": "tcp", "kind": "web", "bind": "10.0.0.5"}], set(), {"access": "public", "lan_ip": ""})
    assert seen == [(53, "udp", "192.168.0.100"), (8081, "tcp", "127.0.0.1"), (8082, "tcp", "10.0.0.5")]


def test_find_page_falls_back_to_common_paths(monkeypatch):
    monkeypatch.setattr(dk, "_http_status", lambda host, port, path="/": 302 if path == "/admin/" else 404)
    assert dk.find_page("127.0.0.1", 10081) == "/admin/"
    monkeypatch.setattr(dk, "_http_status", lambda host, port, path="/": 404)
    assert dk.find_page("127.0.0.1", 10081) == ""


def test_settle_page_remembers_where_the_page_is(monkeypatch):
    monkeypatch.setattr(dk, "find_page", lambda host, port: "/admin/")
    lines = []
    inst = {"app": "uptimekuma", "access": "lan", "lan_ip": "192.168.0.100", "domain": "", "host_ports": {"3001/tcp": 10001}, "env": {}, "folders": {}}
    dk._state()  # fresh state file
    dk._save({"apps": {"kuma": inst}})
    dk._settle_page("kuma", inst, dk.CATALOG["uptimekuma"], 404, 10001, lines.append)
    assert inst["path"] == "/admin/" and dk._state()["apps"]["kuma"]["path"] == "/admin/"
    assert dk._url(inst, dk.CATALOG["uptimekuma"]) == "http://192.168.0.100:10001/admin/"
    # a 200 at the root, or a catalog entry that already names the page, changes nothing
    inst2 = dict(inst, path="")
    dk._settle_page("kuma", inst2, dk.CATALOG["uptimekuma"], 200, 10001, lines.append)
    assert not inst2["path"]
    dk._settle_page("ph", inst2, dk.CATALOG["pihole"], 404, 10001, lines.append)
    assert not inst2["path"]


def test_keep_alive_renders_a_tty():
    _, spec, inst = dk.custom_spec(_custom(keep_alive=True, ports=[]))
    assert spec["tty"] is True
    out = dk.render_compose("myapp", spec, inst)
    assert "    tty: true\n    stdin_open: true\n" in out
    _, spec, _ = dk.custom_spec(_custom())
    assert spec["tty"] is False


def test_image_inspect_reads_ports_env_and_shell(monkeypatch):
    import json, types
    cfg = {"ExposedPorts": {"80/tcp": {}, "53/udp": {}, "9000/tcp": {}}, "Env": ["PATH=/usr/bin", "TZ=UTC"], "Cmd": ["nginx", "-g", "daemon off;"],
           "Entrypoint": None, "Volumes": {"/data": {}}, "WorkingDir": "/app", "User": "", "Labels": {"org.opencontainers.image.title": "x"}}
    img = [{"Id": "sha256:" + "ab" * 32, "RepoTags": ["x:latest"], "RepoDigests": [], "Created": "2026-10-20T10:00:00Z", "Size": 1234, "Architecture": "arm64", "Os": "linux", "Config": cfg}]
    monkeypatch.setattr(dk, "_docker", lambda argv, timeout=120: types.SimpleNamespace(stdout=json.dumps(img)))
    monkeypatch.setattr(dk, "_run", lambda argv, timeout=120, **kw: types.SimpleNamespace(stdout='{"CreatedBy":"/bin/sh -c #(nop) CMD [\\"nginx\\"]","Size":"0B","CreatedSince":"3 days ago"}\n' if "history" in argv else "web1\n", returncode=0, stderr=""))
    info = dk.image_inspect("x:latest")
    assert info["id"] == "ab" * 6 and info["web_port"] == 80
    assert [(p["port"], p["proto"], p["kind"]) for p in info["ports"]] == [(53, "udp", "dns"), (80, "tcp", "web"), (9000, "tcp", "tcp")]
    assert info["env"] == [{"key": "TZ", "value": "UTC"}] and info["volumes"] == ["/data"] and info["shell"] is False
    assert info["history"][0]["by"].startswith("CMD") and info["used_by"] == ["web1"]
    # a bare shell image (kali) is flagged so the dialog keeps it alive
    cfg.update(ExposedPorts=None, Cmd=["/bin/bash"], Volumes=None)
    assert dk.image_inspect("kali:latest")["shell"] is True
    with pytest.raises(dk.DockerError):
        dk.image_inspect("bad name!")


def test_mosquitto_setup_writes_a_passwd_and_a_secret(monkeypatch, tmp_path):
    import types
    calls = []
    def fake_run(argv, timeout=300, cwd=None):
        calls.append(argv)
        (tmp_path / "config" / "passwd").write_text("aurora:$7$hash\n")  # mimic mosquitto_passwd -c
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(dk, "_run", fake_run)
    monkeypatch.setattr(dk, "own_data", lambda app, paths: None)
    inst = {"app": "mosquitto", "env": {}, "secret_keys": ["MQTT_PASSWORD"]}
    (tmp_path / "config").mkdir()
    dk.setup_mosquitto(tmp_path, inst, dk.CATALOG["mosquitto"], lambda *a: None)
    assert (tmp_path / "config" / "passwd").exists()
    assert inst["env"]["MQTT_USERNAME"] == "aurora" and len(inst["env"]["MQTT_PASSWORD"]) > 10
    assert any("mosquitto_passwd" in a for a in calls[0])
    # mosquitto is wired to run the hook
    assert dk.CATALOG["mosquitto"].get("setup") == "mosquitto"
    assert dk.SETUP_HOOKS["mosquitto"] is dk.setup_mosquitto


def test_mosquitto_setup_falls_back_to_open_when_passwd_fails(monkeypatch, tmp_path):
    import types
    monkeypatch.setattr(dk, "_run", lambda argv, timeout=300, cwd=None: types.SimpleNamespace(returncode=1, stdout="", stderr="boom"))
    monkeypatch.setattr(dk, "own_data", lambda app, paths: None)
    (tmp_path / "config").mkdir()
    inst = {"app": "mosquitto", "env": {}, "secret_keys": ["MQTT_PASSWORD"]}
    dk.setup_mosquitto(tmp_path, inst, dk.CATALOG["mosquitto"], lambda *a: None)
    assert "allow_anonymous true" in (tmp_path / "config" / "mosquitto.conf").read_text()
    assert "MQTT_PASSWORD" not in inst["env"]  # nothing to show, it's open
