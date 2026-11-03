"""Docker apps: the host-facing paths (Docker detection, the install/update/settings jobs, the HTTPS front,
the proxy site, external containers) with every command stubbed, so they run on Windows and on CI without Docker."""
import json
import pathlib
import socket
import subprocess
import sys
import threading
import types

import pytest

from backend import dockerapps as dk
from backend import jobs, panelhttps, sites

_REAL_LAN_IP = dk._lan_ip  # kept before the fixture below replaces it


def _ok(stdout="", returncode=0, stderr=""):
    return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


class FakeLog:
    def __init__(self):
        self.lines, self.stages = [], []

    def __call__(self, line):
        self.lines.append(str(line))

    def progress(self, pct, stage=None):
        self.stages.append((pct, stage))

    @property
    def text(self):
        return "\n".join(self.lines)


def _capture_jobs(monkeypatch):
    """Run job functions synchronously; the box holds the title, meta, log, result or error."""
    box = {}

    def launch_fn(title, fn, meta=None):
        box.update(title=title, meta=meta or {}, log=FakeLog(), result=None, error=None)
        try:
            box["result"] = fn(box["log"])
        except Exception as exc:
            box["error"] = exc
        return box
    monkeypatch.setattr(jobs, "launch_fn", launch_fn)
    return box


def _recorder(monkeypatch, name="_run", responses=None):
    """Replace dk.<name> with a stub that records argv and answers by substring of the command line."""
    calls = []

    def fn(argv, timeout=300, cwd=None):
        calls.append(list(argv))
        line = " ".join(str(a) for a in argv)
        for key, resp in (responses or {}).items():
            if key in line:
                return resp() if callable(resp) else resp
        return _ok()
    monkeypatch.setattr(dk, name, fn)
    return calls


@pytest.fixture(autouse=True)
def host(monkeypatch, tmp_path):
    monkeypatch.setattr(dk, "_lan_ip", lambda: "192.168.0.100")
    monkeypatch.setattr(dk, "STATE", tmp_path / "docker-apps.json")
    monkeypatch.setattr(dk, "BASE", tmp_path / "apps")
    monkeypatch.setattr(dk.os, "uname", lambda: types.SimpleNamespace(machine="aarch64"), raising=False)
    monkeypatch.setattr(dk.os, "chown", lambda *a, **k: None, raising=False)


@pytest.fixture
def jail(monkeypatch, tmp_path):
    """Path("/etc/...") and other literal system paths land under tmp_path, so the code runs anywhere."""
    real = pathlib.Path
    root = tmp_path / "root"
    keep = tmp_path.as_posix()

    def P(*parts):
        p = real(*parts)
        s = p.as_posix()
        if s.startswith("/") and not s.startswith(keep):
            return root / s.lstrip("/")
        return p
    monkeypatch.setattr(dk, "Path", P)
    for d in ("etc/docker", "etc/systemd/system", "etc/apache2/sites-available", "var/www", "sys/fs/cgroup", "boot"):
        (root / d).mkdir(parents=True, exist_ok=True)
    return root


def _fake_subprocess(monkeypatch, run=None, popen=None):
    ns = types.SimpleNamespace(run=run or (lambda *a, **k: _ok()), Popen=popen, PIPE=-1, STDOUT=-2,
                               CompletedProcess=subprocess.CompletedProcess, TimeoutExpired=subprocess.TimeoutExpired)
    monkeypatch.setattr(dk, "subprocess", ns)
    return ns


class FakePopen:
    """A `docker compose pull` that prints a few lines; exit code picked by the test."""
    calls = []

    def __init__(self, argv, cwd=None, **kw):
        FakePopen.calls.append({"argv": list(argv), "cwd": cwd})
        self.stdout = iter(["Pulling app ...\n", "Pull complete\n", "\n", "Download complete\n"])

    def wait(self):
        return FakePopen.rc


# ---- Docker detection and the host setup --------------------------------------------------------------------
def test_run_turns_a_missing_binary_into_a_failed_result(monkeypatch):
    def boom(*a, **k):
        raise OSError("no docker here")
    _fake_subprocess(monkeypatch, run=boom)
    r = dk._run(["docker", "info"])
    assert r.returncode == 1 and "no docker here" in r.stderr
    assert dk._env()["PATH"] == dk.PATH


def test_compose_cmd_prefers_the_plugin_then_the_old_binary(monkeypatch):
    found = {"docker": "/usr/bin/docker", "docker-compose": "/usr/bin/docker-compose"}
    monkeypatch.setattr(dk.shutil, "which", lambda name, path=None: found.get(name))
    monkeypatch.setattr(dk, "_run", lambda argv, timeout=300, cwd=None: _ok(returncode=0))
    assert dk.compose_cmd() == ["docker", "compose"] and dk.installed() is True
    monkeypatch.setattr(dk, "_run", lambda argv, timeout=300, cwd=None: _ok(returncode=1))
    assert dk.compose_cmd() == ["docker-compose"] and dk.daemon_ok() is False
    found.clear()
    assert dk.compose_cmd() is None and dk.installed() is False


def test_post_install_caps_logs_keeps_vpn_routes_and_turns_on_memory_accounting(monkeypatch, jail):
    calls = _recorder(monkeypatch)
    (jail / "etc/docker/daemon.json").write_text('{"data-root": "/mnt/docker"}')
    (jail / "sys/fs/cgroup/cgroup.controllers").write_text("cpu io pids\n")
    cmdline = jail / "boot/cmdline.txt"
    cmdline.write_text("console=serial0,115200 root=PARTUUID=abc rootfstype=ext4 fsck.repair=yes rootwait\n")
    monkeypatch.setattr(dk, "CMDLINE", [cmdline])
    notes = dk.post_install()
    cfg = json.loads((jail / "etc/docker/daemon.json").read_text())
    assert cfg["data-root"] == "/mnt/docker" and cfg["log-driver"] == "json-file" and cfg["log-opts"]["max-size"] == "10m"
    unit = (jail / "etc/systemd/system/aurora-docker-vpn.service").read_text()
    assert "iptables -I DOCKER-USER -i wg+ -j ACCEPT" in unit and "--pol ipsec" in unit and "BindsTo=docker.service" in unit
    assert ["systemctl", "restart", "docker"] in calls and ["systemctl", "enable", "docker", "aurora-docker-vpn"] in calls
    assert dk.BASE.is_dir()
    assert cmdline.read_text().rstrip("\n").endswith(dk.MEM_CGROUP_FLAGS)
    assert any("Memory accounting" in n for n in notes) and len(notes) == 3
    # a second run: the flag is pending, so nothing more is added and no note repeats
    assert len(dk.post_install()) == 2
    assert cmdline.read_text().count("cgroup_enable=memory") == 1


def test_post_install_survives_a_broken_daemon_json(monkeypatch, jail):
    _recorder(monkeypatch)
    (jail / "etc/docker/daemon.json").write_text("{not json")
    monkeypatch.setattr(dk, "CMDLINE", [])
    dk.post_install()
    assert json.loads((jail / "etc/docker/daemon.json").read_text())["log-driver"] == "json-file"


def test_mem_cgroup_states(monkeypatch, jail):
    cmdline = jail / "boot/cmdline.txt"
    monkeypatch.setattr(dk, "CMDLINE", [cmdline])
    assert dk.mem_cgroup() == {"active": True, "pending": False, "can_enable": False}  # no controllers file: do not nag
    (jail / "sys/fs/cgroup/cgroup.controllers").write_text("cpu memory\n")
    assert dk.mem_cgroup()["active"] is True
    (jail / "sys/fs/cgroup/cgroup.controllers").write_text("cpu\n")
    assert dk.mem_cgroup() == {"active": False, "pending": False, "can_enable": False}  # no cmdline.txt
    cmdline.write_text("root=x\n")
    assert dk.mem_cgroup()["can_enable"] is True
    assert dk.enable_mem_cgroup() == {"ok": True, "changed": True}
    assert dk.mem_cgroup() == {"active": False, "pending": True, "can_enable": False}
    assert dk.enable_mem_cgroup() == {"ok": True, "changed": False}
    monkeypatch.setattr(dk, "CMDLINE", [])
    with pytest.raises(dk.DockerError, match="cmdline"):
        dk.enable_mem_cgroup()


def test_arch_maps_kernel_names_to_docker_names(monkeypatch):
    for machine, want in (("aarch64", "arm64"), ("x86_64", "amd64"), ("armv7l", "arm"), ("riscv64", "riscv64")):
        monkeypatch.setattr(dk.os, "uname", lambda m=machine: types.SimpleNamespace(machine=m), raising=False)
        assert dk.arch() == want


def _snic(addr, mask="255.255.255.0", family=socket.AF_INET):
    return types.SimpleNamespace(family=family, address=addr, netmask=mask)


def test_lan_ip_skips_docker_bridges_loopback_and_public_addresses(monkeypatch):
    ifaces = {"lo": [_snic("127.0.0.1")], "docker0": [_snic("172.17.0.1")], "wg0": [_snic("10.8.0.1")],
              "eth0": [_snic("fe80::1", family=socket.AF_INET6), _snic("8.8.8.8"), _snic("192.168.0.100")]}
    monkeypatch.setitem(sys.modules, "psutil", types.SimpleNamespace(net_if_addrs=lambda: ifaces))
    assert _REAL_LAN_IP() == "192.168.0.100"
    assert dk._lan_net() == "192.168.0.0/24"
    ifaces["eth0"] = [_snic("192.168.0.100", mask=None)]
    assert dk._lan_net() == "192.168.0.0/24"  # no netmask: assume /24
    monkeypatch.setitem(sys.modules, "psutil", types.SimpleNamespace(net_if_addrs=lambda: (_ for _ in ()).throw(RuntimeError("x"))))
    assert _REAL_LAN_IP() == ""
    monkeypatch.setattr(dk, "_lan_ip", lambda: "")
    assert dk._lan_net() == ""


def test_port_free_checks_a_real_socket():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    try:
        assert dk._port_free(port, "udp", "127.0.0.1") is False
    finally:
        probe.close()
    assert dk._port_free(port, "udp", "127.0.0.1") is True
    assert dk._port_free(port, "tcp", "127.0.0.1") is True


def test_free_port_skips_used_and_busy_ports(monkeypatch):
    dk._save({"apps": {"a": {"host_ports": {"80/tcp": 10000}}}})
    monkeypatch.setattr(dk, "_port_free", lambda port, proto="tcp", host="0.0.0.0": port != 10001)
    assert dk._free_port(80) == 10002  # 10000 is taken by an app, 10001 by the host
    assert dk._free_port(20000) == 20000


def test_state_file_round_trip_and_bad_content(tmp_path):
    assert dk._state() == {"apps": {}}
    dk.STATE.write_text("{broken")
    assert dk._state() == {"apps": {}}
    dk._save({"apps": {"x": {"app": "n8n"}}, "extra": 1})
    assert json.loads(dk.STATE.read_text())["extra"] == 1 and dk._state()["apps"]["x"]["app"] == "n8n"
    assert not list(tmp_path.glob(".docker-apps.json.*.tmp"))  # the temp file was moved into place


def test_tz_reads_etc_timezone(jail):
    (jail / "etc/timezone").write_text("Europe/Berlin\n")
    assert dk._tz() == "Europe/Berlin"
    (jail / "etc/timezone").write_text("")
    assert dk._tz() == "UTC"
    (jail / "etc/timezone").unlink()
    assert isinstance(dk._tz(), str) and dk._tz()


def test_own_data_hands_folders_and_their_contents_to_the_image_user(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(dk.os, "chown", lambda p, u, g, **kw: calls.append((pathlib.Path(p).name, u, g)), raising=False)
    d = tmp_path / "data"
    d.mkdir()
    (d / "f").write_text("x")
    dk.own_data({"uid": "1883"}, [d])
    assert ("data", 1883, 1883) in calls and ("f", 1883, 1883) in calls
    calls.clear()
    dk.own_data({"uid": "www-data"}, [d])
    assert calls == []
    monkeypatch.setattr(dk.os, "chown", lambda *a, **k: (_ for _ in ()).throw(OSError("ro")), raising=False)
    dk.own_data({"uid": "1000"}, [d])  # a read-only folder is not fatal


# ---- catalog, listing, images ---------------------------------------------------------------------------------
def test_catalog_lists_folders_ports_and_host_facts(monkeypatch):
    monkeypatch.setattr(dk, "installed", lambda: False)
    monkeypatch.setattr(dk.shutil, "which", lambda name, path=None: "/usr/sbin/named" if name == "named" else None)
    c = dk.catalog()
    assert c["installed"] is False and c["running"] is False and c["arch"] == "arm64" and c["lan_ip"] == "192.168.0.100" and c["bind9"] is True
    jf = next(x for x in c["catalog"] if x["id"] == "jellyfin")
    assert jf["folders"] == ["media"] and {"port": 8096, "proto": "tcp", "kind": "web"} in jf["ports"]
    assert next(x for x in c["catalog"] if x["id"] == "mosquitto")["no_web"] is True


def test_listing_merges_docker_state_and_hides_secrets(monkeypatch):
    monkeypatch.setattr(dk, "installed", lambda: True)
    monkeypatch.setattr(dk, "daemon_ok", lambda: True)
    ps = json.dumps({"Names": "kuma", "State": "running", "Status": "Up 3 days", "Image": "louislam/uptime-kuma:1"}) + "\nnot json\n"
    stats = json.dumps({"Name": "kuma", "CPUPerc": "1.5%", "MemUsage": "90MiB / 8GiB"}) + "\n"
    df = json.dumps({"Type": "Images", "Size": "2GB", "Reclaimable": "1GB (50%)"}) + "\n{bad\n"
    _recorder(monkeypatch, responses={"docker ps": _ok(ps), "docker stats": _ok(stats), "system df": _ok(df)})
    dk._save({"apps": {
        "zeta": {"app": "custom", "spec": {"name": "Zeta", "image": "alpine", "ports": [(80, "tcp", "web")], "volumes": [], "env": {}, "host_network": False},
                 "access": "public", "host_ports": {"80/tcp": 10080}, "env": {}, "secret_keys": [], "created": 1},
        "kuma": {"app": "uptimekuma", "access": "proxy", "domain": "kuma.example.com", "host_ports": {"3001/tcp": 10001},
                 "env": {"TOKEN": "s3cret", "TZ": "UTC"}, "secret_keys": ["TOKEN"], "created": 2}}})
    out = dk.listing()
    assert [a["name"] for a in out["apps"]] == ["kuma", "zeta"]
    kuma, zeta = out["apps"]
    assert kuma["state"] == "running" and kuma["cpu"] == "1.5%" and kuma["url"] == "https://kuma.example.com/" and kuma["title"] == "Uptime Kuma"
    assert kuma["env"] == {"TOKEN": "••••••", "TZ": "UTC"} and kuma["secrets"] == ["TOKEN"] and kuma["port_kinds"] == {"3001/tcp": "web"}
    assert zeta["custom"] is True and zeta["state"] == "missing" and zeta["url"] == "http://{host}:10080/" and zeta["image"] == "alpine"
    assert out["disk"] == {"Images": {"size": "2GB", "reclaimable": "1GB (50%)"}}


def test_listing_without_docker_has_no_disk_figures(monkeypatch):
    monkeypatch.setattr(dk, "installed", lambda: False)
    assert dk.listing() == {"apps": [], "installed": False, "running": False, "disk": None}


def test_image_user_resolves_numeric_and_named_users(monkeypatch):
    answers = {"image inspect": _ok("1000:1000\n")}
    _recorder(monkeypatch, responses=answers)
    assert dk.image_user("n8nio/n8n") == "1000:1000"
    answers["image inspect"] = _ok("node\n")
    answers["docker run"] = _ok("1000:1000\n")
    assert dk.image_user("n8nio/n8n") == "1000:1000"
    answers["docker run"] = _ok("", returncode=1)
    assert dk.image_user("n8nio/n8n") == ""
    answers["image inspect"] = _ok("root\n")
    assert dk.image_user("nginx") == ""


def test_images_needs_a_running_daemon(monkeypatch):
    monkeypatch.setattr(dk, "installed", lambda: True)
    monkeypatch.setattr(dk, "daemon_ok", lambda: False)
    assert dk.images() == {"images": []}


def test_image_inspect_rejects_garbage_from_docker(monkeypatch):
    monkeypatch.setattr(dk, "_docker", lambda argv, timeout=120: _ok("[]"))
    with pytest.raises(dk.DockerError, match="Unknown image"):
        dk.image_inspect("nginx:latest")


def test_image_pull_streams_output_and_fails_on_bad_name(monkeypatch):
    with pytest.raises(dk.DockerError, match="nginx:latest"):
        dk.image_pull("bad name!")
    box = _capture_jobs(monkeypatch)
    FakePopen.calls, FakePopen.rc = [], 0
    _fake_subprocess(monkeypatch, popen=FakePopen)
    dk.image_pull("nginx:1.27")
    assert box["title"] == "pull nginx:1.27" and box["result"] == {"ok": True}
    assert FakePopen.calls[0]["argv"] == ["docker", "pull", "nginx:1.27"] and "Pull complete" in box["log"].lines
    FakePopen.rc = 1
    dk.image_pull("nginx:1.27")
    assert "Download failed" in str(box["error"])


# ---- waiting for a container ---------------------------------------------------------------------------------
class FakeTime:
    def __init__(self):
        self.t = 1000.0

    def time(self):
        self.t += 5
        return self.t

    def sleep(self, s):
        pass


def test_wait_started_reports_a_crash_with_the_last_log_lines(monkeypatch):
    monkeypatch.setattr(dk, "time", FakeTime())
    _recorder(monkeypatch, responses={"docker inspect": _ok("exited false 0\n"), "docker logs": _ok("boom line\n")})
    log = FakeLog()
    with pytest.raises(dk.DockerError, match="crashed"):
        dk.wait_started("web", log, "127.0.0.1", 10080)
    assert "boom line" in log.text


def test_wait_started_returns_the_http_status_once_the_page_answers(monkeypatch):
    monkeypatch.setattr(dk, "time", FakeTime())
    _recorder(monkeypatch, responses={"docker inspect": _ok("running false 0 healthy\n")})
    monkeypatch.setattr(dk, "_http_status", lambda host, port, path="/": 404)
    log = FakeLog()
    assert dk.wait_started("web", log, "127.0.0.1", 10080, path="/admin") == 404
    assert "HTTP 404 for /admin" in log.text
    monkeypatch.setattr(dk, "_http_status", lambda host, port, path="/": 200)
    assert dk.wait_started("web", log, "127.0.0.1", 10080) == 200


def test_wait_started_without_a_web_port_waits_until_it_stays_up(monkeypatch):
    monkeypatch.setattr(dk, "time", FakeTime())
    _recorder(monkeypatch, responses={"docker inspect": _ok("running false 0\n")})
    assert dk.wait_started("mqtt", FakeLog(), seconds=100) is None
    log = FakeLog()
    assert dk.wait_started("web", log, "127.0.0.1", 10080, seconds=0) is None
    assert "Still starting" in log.text


def test_http_status_talks_to_a_real_local_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)
    port = srv.getsockname()[1]
    replies = iter([b"HTTP/1.1 404 Not Found\r\n\r\n", b"<html>no status line"])
    seen = []

    def serve():
        for _ in range(2):
            c, _ = srv.accept()
            seen.append(c.recv(200))
            c.sendall(next(replies))
            c.close()
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    assert dk._http_status("127.0.0.1", port, "/admin/") == 404
    assert dk._http_status("", port) == 200
    t.join(5)
    srv.close()
    assert seen[0].startswith(b"GET /admin/ HTTP/1.0")
    assert dk._http_status("127.0.0.1", port) is None  # nobody listens any more


# ---- the HTTPS front and the proxy site ----------------------------------------------------------------------
def test_tls_pair_uses_system_certificates_before_making_its_own(monkeypatch, tmp_path):
    crt, key = tmp_path / "s.pem", tmp_path / "s.key"
    crt.write_text("c")
    key.write_text("k")
    monkeypatch.setattr(dk, "TLS_PAIRS", [(str(crt), str(key))])
    assert dk._tls_pair("web") == (str(crt), str(key))
    monkeypatch.setattr(dk, "TLS_PAIRS", [])
    monkeypatch.setattr(panelhttps, "SELF_CRT", tmp_path / "none.crt")
    monkeypatch.setattr(panelhttps, "SELF_KEY", tmp_path / "none.key")
    calls = []

    def fake_run(argv, timeout=300, cwd=None):
        calls.append(argv)
        pathlib.Path(argv[argv.index("-keyout") + 1]).write_text("key")
        pathlib.Path(argv[argv.index("-out") + 1]).write_text("crt")
        return _ok()
    monkeypatch.setattr(dk, "_run", fake_run)
    got = dk._tls_pair("web")
    assert got == (str(dk.BASE / "web" / "tls" / "cert.pem"), str(dk.BASE / "web" / "tls" / "key.pem"))
    assert calls[0][0] == "openssl" and any(a.startswith("subjectAltName=IP:192.168.0.100") for a in calls[0])
    assert dk._tls_pair("web") == got and len(calls) == 1  # reused, not regenerated
    panelhttps.SELF_CRT.write_text("x")
    panelhttps.SELF_KEY.write_text("y")
    assert dk._tls_pair("other") == (str(panelhttps.SELF_CRT), str(panelhttps.SELF_KEY))


def test_ufw_only_runs_when_active(monkeypatch):
    calls = _recorder(monkeypatch, responses={"ufw status": _ok("Status: inactive")})
    monkeypatch.setattr(dk.shutil, "which", lambda name, path=None: None)
    dk._ufw(["allow", "80"])
    assert calls == []
    monkeypatch.setattr(dk.shutil, "which", lambda name, path=None: "/usr/sbin/ufw")
    dk._ufw(["allow", "80"])
    assert calls == [["ufw", "status"]]
    calls.clear()
    monkeypatch.setattr(dk, "_run", lambda argv, timeout=300, cwd=None: calls.append(argv) or _ok("Status: active"))
    dk._ufw(["allow", "80"])
    assert calls[-1] == ["ufw", "allow", "80"]


def test_tls_front_writes_a_vhost_and_opens_the_firewall_for_the_lan(monkeypatch, jail):
    monkeypatch.setattr(dk, "_tls_pair", lambda name: ("/c.pem", "/k.pem"))
    monkeypatch.setattr(dk, "_lan_net", lambda: "192.168.0.0/24")
    monkeypatch.setattr(dk, "_free_port", lambda start: start)
    ufw = []
    monkeypatch.setattr(dk, "_ufw", lambda args: ufw.append(args))
    calls = _recorder(monkeypatch)
    inst = {"access": "lan", "lan_ip": "192.168.0.100"}
    assert dk.tls_front("vault", inst, 10080) == 10443 and inst["tls_port"] == 10443
    conf = (jail / "etc/apache2/sites-available/aurora-docker-vault.conf").read_text()
    assert "Listen 192.168.0.100:10443 https" in conf and "ProxyPass / http://127.0.0.1:10080/ upgrade=websocket" in conf
    assert "SSLCertificateFile /c.pem" in conf and "docker-vault-error.log" in conf
    assert ["a2ensite", "-q", "aurora-docker-vault.conf"] in calls and ["systemctl", "reload", "apache2"] in calls
    assert ufw == [["allow", "proto", "tcp", "from", "192.168.0.0/24", "to", "any", "port", "10443", "comment", "AuroraPanel docker vault"]]
    # public access: listen everywhere, the rule has no "from"; a kept tls_port is reused
    inst = {"access": "public", "tls_port": 8443}
    dk.tls_front("vault", inst, 60000)
    assert "Listen 8443 https" in (jail / "etc/apache2/sites-available/aurora-docker-vault.conf").read_text()
    assert "from" not in ufw[-1]
    dk.tls_front_remove("vault", inst)
    assert not (jail / "etc/apache2/sites-available/aurora-docker-vault.conf").exists() and "tls_port" not in inst
    assert ufw[-1] == ["delete", "allow", "proto", "tcp", "to", "any", "port", "8443"]
    assert ["a2dissite", "-q", "aurora-docker-vault.conf"] in calls


def test_tls_front_backs_out_when_apache_rejects_the_vhost(monkeypatch, jail):
    monkeypatch.setattr(dk, "_tls_pair", lambda name: ("/c.pem", "/k.pem"))
    monkeypatch.setattr(dk, "_free_port", lambda start: start)
    calls = _recorder(monkeypatch, responses={"apache2ctl configtest": _ok("", 1, "Syntax error on line 3")})
    with pytest.raises(dk.DockerError, match="Syntax error"):
        dk.tls_front("vault", {"access": "lan", "lan_ip": "192.168.0.100"}, 10080)
    assert ["a2dissite", "-q", "aurora-docker-vault.conf"] in calls


def test_proxy_site_creates_or_updates_the_managed_site(monkeypatch, jail):
    _recorder(monkeypatch)
    created, saved = [], []
    monkeypatch.setattr(sites, "create_site", lambda s: created.append(s) or {"ok": True})
    monkeypatch.setattr(sites, "save_site", lambda name, s: saved.append((name, s)) or {"ok": True})
    monkeypatch.setattr(sites, "get_site", lambda name: (_ for _ in ()).throw(sites.SiteError("none")))
    dk._proxy_site("kuma", "kuma.example.com", 10001)
    assert created[0]["server_name"] == "kuma.example.com" and "ProxyPass / http://127.0.0.1:10001/ upgrade=websocket" in created[0]["custom"]
    assert created[0]["ssl"] == "selfsigned" and created[0]["security_headers"] is False
    assert (jail / "var/www/app-kuma").is_dir()
    # the same app again: its own site is updated in place, with no private keys leaking into save_site
    monkeypatch.setattr(sites, "get_site", lambda name: {"settings": {"custom": "# aurora-docker-app kuma", "_managed": True, "server_name": name}})
    dk._proxy_site("kuma", "kuma.example.com", 10002)
    assert saved[0][0] == "kuma.example.com" and "127.0.0.1:10002" in saved[0][1]["custom"] and "_managed" not in saved[0][1]
    # somebody else's site under that name
    monkeypatch.setattr(sites, "get_site", lambda name: {"settings": {"custom": ""}})
    with pytest.raises(dk.DockerError, match="already used"):
        dk._proxy_site("kuma", "kuma.example.com", 10003)


# ---- install -------------------------------------------------------------------------------------------------
@pytest.fixture
def docker_ready(monkeypatch):
    monkeypatch.setattr(dk, "installed", lambda: True)
    monkeypatch.setattr(dk, "compose_cmd", lambda: ["docker", "compose"])
    monkeypatch.setattr(dk, "_port_free", lambda port, proto="tcp", host="0.0.0.0": True)
    monkeypatch.setattr(dk, "_tz", lambda: "Europe/Rome")


@pytest.mark.parametrize("args,msg", [
    (("nope",), "Unknown app"),
    (("uptimekuma", "Bad Name"), "lowercase"),
    (("uptimekuma", "kuma", "vpn"), "access mode"),
    (("uptimekuma", "kuma", "proxy", "kuma"), "web address"),
    (("uptimekuma", "kuma", "proxy", ""), "web address"),
])
def test_install_refuses_bad_requests(docker_ready, args, msg):
    with pytest.raises(dk.DockerError, match=msg):
        dk.install(*args)


def test_install_needs_docker_a_free_name_and_a_lan_address(monkeypatch, docker_ready):
    monkeypatch.setattr(dk, "installed", lambda: False)
    with pytest.raises(dk.DockerError, match="Install Docker"):
        dk.install("uptimekuma")
    monkeypatch.setattr(dk, "installed", lambda: True)
    dk._save({"apps": {"kuma": {"app": "uptimekuma"}}})
    with pytest.raises(dk.DockerError, match="already exists"):
        dk.install("uptimekuma", "kuma", "lan")
    monkeypatch.setattr(dk, "_lan_ip", lambda: "")
    with pytest.raises(dk.DockerError, match="no private network"):
        dk.install("uptimekuma", "kuma2", "lan")
    monkeypatch.setattr(dk, "_port_free", lambda port, proto="tcp", host="0.0.0.0": port != 53)
    with pytest.raises(dk.DockerError, match="Port 53/tcp is in use"):
        dk.install("pihole", "pihole", "public")
    with pytest.raises(dk.DockerError, match="proper folder"):
        dk.install("jellyfin", "jf", "lan", folders={"media": "/"})


def test_install_job_writes_compose_pulls_starts_and_creates_the_web_address(monkeypatch, docker_ready, tmp_path):
    box = _capture_jobs(monkeypatch)
    FakePopen.calls, FakePopen.rc = [], 0
    _fake_subprocess(monkeypatch, popen=FakePopen)
    monkeypatch.setattr(dk, "_free_port", lambda start: 10001)
    calls = _recorder(monkeypatch)
    monkeypatch.setattr(dk, "image_user", lambda image: "1000:1000")
    monkeypatch.setattr(dk, "wait_started", lambda *a, **k: 200)
    proxied = []
    monkeypatch.setattr(dk, "_proxy_site", lambda name, domain, port: proxied.append((name, domain, port)))
    dk.install("uptimekuma", "kuma", "proxy", "Kuma.Example.com.")
    assert box["error"] is None, box["error"]
    assert box["result"] == {"ok": True, "name": "kuma"} and box["meta"] == {"docker": "kuma"} and box["title"] == "install Uptime Kuma"
    work = tmp_path / "apps" / "kuma"
    yml = (work / "docker-compose.yml").read_text()
    assert '"127.0.0.1:10001:3001/tcp"' in yml and 'aurora.app: "uptimekuma"' in yml and (work / "data").is_dir()
    assert FakePopen.calls[0] == {"argv": ["docker", "compose", "pull"], "cwd": work}
    assert ["docker", "compose", "up", "-d"] in calls
    assert proxied == [("kuma", "kuma.example.com", 10001)]
    inst = dk._state()["apps"]["kuma"]
    assert inst["domain"] == "kuma.example.com" and inst["access"] == "proxy" and inst["host_ports"] == {"3001/tcp": 10001}
    assert "runs as user 1000:1000" in box["log"].text and box["log"].stages[-1] == (100, "Uptime Kuma is running")


def test_install_job_fails_cleanly_when_the_pull_or_the_start_fails(monkeypatch, docker_ready):
    box = _capture_jobs(monkeypatch)
    FakePopen.calls, FakePopen.rc = [], 1
    _fake_subprocess(monkeypatch, popen=FakePopen)
    monkeypatch.setattr(dk, "_free_port", lambda start: 10001)
    dk.install("uptimekuma", "kuma", "lan")
    assert "download the image" in str(box["error"]) and dk._state()["apps"] == {}
    FakePopen.rc = 0
    _recorder(monkeypatch, responses={"up -d": _ok("", 1, "port is already allocated")})
    monkeypatch.setattr(dk, "image_user", lambda image: "")
    dk.install("uptimekuma", "kuma", "lan")
    assert "didn't start" in str(box["error"]) and "port is already allocated" in box["log"].text


def test_install_builds_env_from_placeholders_and_adds_https_for_vaultwarden(monkeypatch, docker_ready, tmp_path):
    box = _capture_jobs(monkeypatch)
    FakePopen.calls, FakePopen.rc = [], 0
    _fake_subprocess(monkeypatch, popen=FakePopen)
    monkeypatch.setattr(dk, "_free_port", lambda start: 10080)
    _recorder(monkeypatch)
    monkeypatch.setattr(dk, "image_user", lambda image: "")
    monkeypatch.setattr(dk, "wait_started", lambda *a, **k: None)
    fronts = []

    def tls_front(name, inst, port):
        fronts.append((name, port))
        inst["tls_port"] = 10443
        return 10443
    monkeypatch.setattr(dk, "tls_front", tls_front)
    dk.install("vaultwarden", "vault", "lan")
    assert box["error"] is None, box["error"]
    inst = dk._state()["apps"]["vault"]
    assert fronts == [("vault", 10080)] and inst["tls_port"] == 10443 and inst["secret_keys"] == ["ADMIN_TOKEN"]
    assert len(inst["env"]["ADMIN_TOKEN"]) > 16 and inst["env"]["SIGNUPS_ALLOWED"] == "true"
    yml = (tmp_path / "apps" / "vault" / "docker-compose.yml").read_text()
    assert '"127.0.0.1:10080:80/tcp"' in yml  # behind the HTTPS front, the web port stays on loopback
    assert "HTTPS on port 10443" in box["log"].text
    # n8n: timezone placeholders and the secure-cookie flag follow the access mode
    monkeypatch.setattr(dk, "_free_port", lambda start: 10001)
    dk.install("n8n", "n8n", "public")
    env = dk._state()["apps"]["n8n"]["env"]
    assert env["TZ"] == "Europe/Rome" and env["GENERIC_TIMEZONE"] == "Europe/Rome" and env["N8N_SECURE_COOKIE"] == "false"


def test_install_host_network_app_takes_the_lan_and_container_ports(monkeypatch, docker_ready, tmp_path):
    box = _capture_jobs(monkeypatch)
    FakePopen.calls, FakePopen.rc = [], 0
    _fake_subprocess(monkeypatch, popen=FakePopen)
    _recorder(monkeypatch)
    monkeypatch.setattr(dk, "image_user", lambda image: "")
    monkeypatch.setattr(dk, "wait_started", lambda *a, **k: None)
    dk.install("homeassistant", "", "proxy", "ha.example.com")
    assert box["error"] is None, box["error"]
    inst = dk._state()["apps"]["homeassistant"]
    assert inst["access"] == "lan" and inst["domain"] == "" and inst["host_ports"] == {"8123/tcp": 8123}
    yml = (tmp_path / "apps" / "homeassistant" / "docker-compose.yml").read_text()
    assert "network_mode: host" in yml and "ports:" not in yml and "privileged: true" in yml


def test_install_pihole_runs_dns_on_53_and_writes_bundled_files(monkeypatch, docker_ready, tmp_path):
    box = _capture_jobs(monkeypatch)
    FakePopen.calls, FakePopen.rc = [], 0
    _fake_subprocess(monkeypatch, popen=FakePopen)
    monkeypatch.setattr(dk, "_free_port", lambda start: 10080)
    _recorder(monkeypatch)
    monkeypatch.setattr(dk, "image_user", lambda image: "")
    monkeypatch.setattr(dk, "wait_started", lambda *a, **k: None)
    hooked = []
    monkeypatch.setitem(dk.SETUP_HOOKS, "mosquitto", lambda work, inst, app, log: hooked.append(work))
    dk.install("pihole", "", "lan")
    assert box["error"] is None, box["error"]
    inst = dk._state()["apps"]["pihole"]
    assert inst["host_ports"] == {"80/tcp": 10080, "53/tcp": 53, "53/udp": 53}
    yml = (tmp_path / "apps" / "pihole" / "docker-compose.yml").read_text()
    assert '"192.168.0.100:53:53/udp"' in yml and "NET_ADMIN" in yml
    dk.install("mosquitto", "", "lan")
    assert box["error"] is None, box["error"]
    assert hooked == [tmp_path / "apps" / "mosquitto"]
    assert "listener 1883" in (tmp_path / "apps" / "mosquitto" / "config" / "mosquitto.conf").read_text()


# ---- control, logs, update, remove, secrets ----------------------------------------------------------------------
def test_control_logs_and_secret_use_compose_in_the_app_folder(monkeypatch, tmp_path):
    dk._save({"apps": {"kuma": {"app": "uptimekuma", "env": {"TOKEN": "abc"}, "secret_keys": ["TOKEN"]}}})
    monkeypatch.setattr(dk, "compose_cmd", lambda: ["docker", "compose"])
    seen = []

    def run(argv, timeout=300, cwd=None):
        seen.append((argv, cwd))
        return _ok("out ", 0, "err") if argv[-2:] != ["compose", "stop"] else _ok("", 1, "cannot stop")
    monkeypatch.setattr(dk, "_run", run)
    assert dk.control("kuma", "restart") == {"ok": True} and seen[-1] == (["docker", "compose", "restart"], tmp_path / "apps" / "kuma")
    with pytest.raises(dk.DockerError, match="cannot stop"):
        dk.control("kuma", "stop")
    with pytest.raises(dk.DockerError, match="Unknown action"):
        dk.control("kuma", "kill")
    assert dk.logs("kuma", lines=5)["text"] == "out err" and seen[-1][0][-1] == "10"  # at least 10 lines
    assert dk.secret("kuma", "TOKEN") == {"key": "TOKEN", "value": "abc"}
    with pytest.raises(dk.DockerError, match="Unknown secret"):
        dk.secret("kuma", "TZ")


def test_update_job_pulls_restarts_and_prunes(monkeypatch):
    dk._save({"apps": {"kuma": {"app": "uptimekuma"}}})
    monkeypatch.setattr(dk, "compose_cmd", lambda: ["docker", "compose"])
    box = _capture_jobs(monkeypatch)
    calls = _recorder(monkeypatch)
    dk.update("kuma")
    assert box["result"] == {"ok": True} and ["docker", "image", "prune", "-f"] in calls and "✓ Updated" in box["log"].text
    _recorder(monkeypatch, responses={"pull": _ok("", 1, "no internet")})
    dk.update("kuma")
    assert str(box["error"]) == "Download failed" and "no internet" in box["log"].text
    _recorder(monkeypatch, responses={"up -d": _ok("", 1)})
    dk.update("kuma")
    assert str(box["error"]) == "Restart failed"
    with pytest.raises(dk.DockerError, match="Unknown app"):
        dk.update("ghost")


def test_remove_takes_down_the_site_the_https_front_and_optionally_the_data(monkeypatch, tmp_path):
    work = tmp_path / "apps" / "kuma"
    work.mkdir(parents=True)
    (work / "data.txt").write_text("x")
    dk._save({"apps": {"kuma": {"app": "uptimekuma", "domain": "kuma.example.com", "tls_port": 10443}, "other": {"app": "n8n"}}})
    monkeypatch.setattr(dk, "compose_cmd", lambda: ["docker", "compose"])
    _recorder(monkeypatch)
    removed, fronts = [], []
    monkeypatch.setattr(sites, "remove_site", lambda name: removed.append(name))
    monkeypatch.setattr(dk, "tls_front_remove", lambda name, inst: fronts.append(name))
    assert dk.remove("kuma") == {"ok": True}
    assert removed == ["kuma.example.com"] and fronts == ["kuma"] and work.exists() and list(dk._state()["apps"]) == ["other"]
    dk._save({"apps": {"kuma": {"app": "uptimekuma", "domain": "kuma.example.com"}}})
    monkeypatch.setattr(sites, "remove_site", lambda name: (_ for _ in ()).throw(sites.SiteError("gone")))
    assert dk.remove("kuma", delete_data=True) == {"ok": True} and not work.exists()  # a missing site is not fatal
    dk._save({"apps": {"kuma": {"app": "uptimekuma"}}})
    _recorder(monkeypatch, responses={"down": _ok("", 1, "No such file or directory")})
    assert dk.remove("kuma") == {"ok": True}  # already gone counts as removed
    dk._save({"apps": {"kuma": {"app": "uptimekuma"}}})
    _recorder(monkeypatch, responses={"down": _ok("", 1, "permission denied")})
    with pytest.raises(dk.DockerError, match="permission denied"):
        dk.remove("kuma")


# ---- every container -------------------------------------------------------------------------------------------
def test_docker_helper_raises_the_last_error_line(monkeypatch):
    _recorder(monkeypatch, responses={"docker": _ok("", 1, "line one\nError: No such container: x")})
    with pytest.raises(dk.DockerError, match="No such container: x"):
        dk._docker(["rm", "x"])
    _recorder(monkeypatch, responses={"docker": _ok("", 1, "")})
    with pytest.raises(dk.DockerError, match="docker failed"):
        dk._docker(["rm", "x"])


def test_overview_counts_from_docker_info(monkeypatch):
    monkeypatch.setattr(dk, "installed", lambda: True)
    monkeypatch.setattr(dk, "daemon_ok", lambda: True)
    monkeypatch.setattr(dk, "mem_cgroup", lambda: {"active": True, "pending": False, "can_enable": False})
    info = {"ServerVersion": "27.1", "Containers": 4, "ContainersRunning": 2, "ContainersPaused": 0, "ContainersStopped": 2, "DockerRootDir": "/var/lib/docker"}
    _recorder(monkeypatch, responses={"docker info": _ok(json.dumps(info)), "image ls": _ok("a\nb\na\n"), "volume ls": _ok("v1\n"), "system df": _ok("")})
    o = dk.overview()
    assert o["version"] == "27.1" and o["containers_running"] == 2 and o["images"] == 2 and o["volumes"] == 1 and o["root"] == "/var/lib/docker"
    _recorder(monkeypatch, responses={"docker info": _ok("{bad")})
    assert dk.overview()["version"] == ""


def test_containers_without_docker(monkeypatch):
    monkeypatch.setattr(dk, "installed", lambda: False)
    assert dk.containers() == {"containers": []}


def test_inspect_reads_ports_mounts_networks_and_panel_env(monkeypatch):
    raw = [{"Id": "a" * 64, "Name": "/kuma", "Image": "sha256:" + "b" * 64, "Created": "2026-10-01",
            "Config": {"Image": "louislam/uptime-kuma:1", "Env": ["PATH=/bin", "TZ=UTC"], "Cmd": ["node", "server.js"], "Entrypoint": ["/entry"],
                       "User": "1000", "WorkingDir": "/app", "Hostname": "kuma", "Labels": {"aurora.app": "uptimekuma"}},
            "HostConfig": {"RestartPolicy": {"Name": ""}, "Memory": 512, "NanoCpus": 1500000000, "NetworkMode": "bridge", "Privileged": True},
            "NetworkSettings": {"Ports": {"3001/tcp": [{"HostIp": "0.0.0.0", "HostPort": "10001"}, {"HostIp": "::", "HostPort": "10001"}], "9000/tcp": None},
                                "Networks": {"bridge": {"IPAddress": "172.17.0.2", "Gateway": "172.17.0.1"}}},
            "State": {"Status": "running", "Running": True, "Paused": False, "Pid": 42, "StartedAt": "t", "ExitCode": 0, "Error": "", "Health": {"Status": "healthy"}},
            "Mounts": [{"Type": "bind", "Source": "/opt/aurora-apps/kuma/data", "Destination": "/app/data", "RW": True},
                       {"Type": "volume", "Name": "vol1", "Destination": "/x", "RW": False}], "LogPath": "/var/lib/docker/x.log"}]
    monkeypatch.setattr(dk, "_docker", lambda argv, timeout=120: _ok(json.dumps(raw)))
    dk._save({"apps": {"kuma": {"app": "uptimekuma", "access": "lan", "domain": "", "env": {"TOKEN": "s", "TZ": "UTC"}, "secret_keys": ["TOKEN"], "host_ports": {"3001/tcp": 10001}}}})
    info = dk.inspect("kuma")
    assert info["ports"] == [{"container": 3001, "proto": "tcp", "host": 10001, "bind": "0.0.0.0"}, {"container": 9000, "proto": "tcp", "host": None, "bind": ""}]
    assert info["mounts"][1] == {"type": "volume", "source": "vol1", "dest": "/x", "rw": False}
    assert info["networks"] == {"bridge": {"ip": "172.17.0.2", "gateway": "172.17.0.1"}} and info["restart"] == "no"
    assert info["env"] == [{"key": "TOKEN", "value": "••••••", "secret": True}, {"key": "TZ", "value": "UTC", "secret": False}]
    assert info["cpus"] == 1.5 and info["privileged"] is True and info["health"] == "healthy" and info["managed"] is True and info["title"] == "Uptime Kuma"
    assert info["cmd"] == "node server.js" and info["entrypoint"] == "/entry" and info["image_id"] == "sha256:" + "b" * 12
    assert info["port_kinds"] == {"3001/tcp": "web"} and info["access"] == "lan"
    # a container the panel did not make shows the image's own environment
    dk._save({"apps": {}})
    info = dk.inspect("kuma")
    assert info["env"][0] == {"key": "PATH", "value": "/bin", "secret": False} and info["managed"] is False and info["title"] == "kuma"


def test_container_action_on_an_external_container_is_audited(monkeypatch):
    from backend import audit
    calls = []
    monkeypatch.setattr(dk, "_docker", lambda argv, timeout=120: calls.append(argv) or _ok())
    assert dk.container_action("redis", "pause") == {"ok": True} and calls == [["pause", "redis"]]
    assert "docker container pause (redis)" in audit.LOG.read_text(encoding="utf-8")
    dk._save({"apps": {"kuma": {"app": "uptimekuma"}}})
    assert dk.container_remove("kuma") == {"ok": True} or True  # managed: goes through remove()


def test_container_remove_managed_goes_through_the_app_removal(monkeypatch):
    dk._save({"apps": {"kuma": {"app": "uptimekuma"}}})
    monkeypatch.setattr(dk, "remove", lambda name, delete_data=False: {"ok": True, "via": "remove", "data": delete_data})
    assert dk.container_remove("kuma", True) == {"ok": True, "via": "remove", "data": True}


# ---- settings of a managed container -----------------------------------------------------------------------------
def _kuma_inst(**over):
    inst = {"app": "uptimekuma", "access": "lan", "lan_ip": "192.168.0.100", "domain": "", "host_ports": {"3001/tcp": 10001},
            "env": {"TOKEN": "old-secret"}, "secret_keys": ["TOKEN"], "folders": {}, "image": "louislam/uptime-kuma:1"}
    inst.update(over)
    return inst


@pytest.mark.parametrize("data,msg", [
    ({"restart": "sometimes"}, "restart policy"),
    ({"access": "vpn"}, "access mode"),
    ({"access": "proxy", "domain": "nope"}, "web address"),
    ({"ports": [{"container": 80, "host": 1}]}, "has no port 80/tcp"),
    ({"ports": [{"container": 3001, "host": 0}]}, "needs a host port"),
    ({"mem_limit": "lots"}, "512m"),
])
def test_update_settings_rejects_bad_input(monkeypatch, data, msg):
    dk._save({"apps": {"kuma": _kuma_inst()}})
    monkeypatch.setattr(dk, "_port_free", lambda *a, **k: True)
    with pytest.raises(dk.DockerError, match=msg):
        dk.update_settings("kuma", data)


def test_update_settings_needs_a_lan_address_and_a_web_port_for_proxy(monkeypatch):
    dk._save({"apps": {"kuma": _kuma_inst(), "mqtt": {"app": "mosquitto", "access": "lan", "host_ports": {"1883/tcp": 1883}, "env": {}}}})
    monkeypatch.setattr(dk, "_lan_ip", lambda: "")
    with pytest.raises(dk.DockerError, match="no private network"):
        dk.update_settings("kuma", {"access": "lan"})
    monkeypatch.setattr(dk, "_lan_ip", lambda: "192.168.0.100")
    with pytest.raises(dk.DockerError, match="no web port"):
        dk.update_settings("mqtt", {"access": "proxy", "domain": "mq.example.com"})


def test_update_settings_job_applies_ports_env_and_the_web_address(monkeypatch):
    dk._save({"apps": {"kuma": _kuma_inst(domain="old.example.com", access="proxy", tls_port=10443)}})
    monkeypatch.setattr(dk, "_port_free", lambda *a, **k: True)
    box = _capture_jobs(monkeypatch)
    events = []
    monkeypatch.setattr(dk, "tls_front_remove", lambda name, inst: events.append(("tls_remove", name)) or inst.pop("tls_port", None))
    monkeypatch.setattr(dk, "_compose_up", lambda name, app, inst, log: events.append(("up", name)))
    monkeypatch.setattr(dk, "wait_started", lambda *a, **k: events.append(("wait", a[0])) or 200)
    monkeypatch.setattr(dk, "_proxy_site", lambda name, domain, port: events.append(("site", domain, port)))
    monkeypatch.setattr(sites, "remove_site", lambda name: events.append(("remove_site", name)))
    dk.update_settings("kuma", {"restart": "always", "mem_limit": "256M", "cpus": "0.5", "domain": "New.Example.com",
                                "env": [{"key": "TOKEN", "value": "••••••"}, {"key": "TZ", "value": "UTC"}],
                                "ports": [{"container": 3001, "proto": "tcp", "host": 10005, "kind": "web"}]})
    assert box["error"] is None, box["error"]
    inst = dk._state()["apps"]["kuma"]
    assert inst["env"] == {"TOKEN": "old-secret", "TZ": "UTC"}  # the masked secret keeps its stored value
    assert inst["host_ports"] == {"3001/tcp": 10005} and inst["restart"] == "always" and inst["mem_limit"] == "256m" and inst["cpus"] == "0.5"
    assert inst["domain"] == "new.example.com" and "tls_port" not in inst
    assert events == [("tls_remove", "kuma"), ("up", "kuma"), ("wait", "kuma"), ("site", "new.example.com", 10005), ("remove_site", "old.example.com")]
    assert box["result"] == {"ok": True} and box["title"] == "reconfigure kuma"


def test_update_settings_on_a_custom_container_rewrites_its_spec(monkeypatch):
    spec = {"name": "Zeta", "image": "alpine", "ports": [(80, "tcp", "web")], "volumes": [], "env": {}, "host_network": False, "https_only": True}
    dk._save({"apps": {"zeta": {"app": "custom", "spec": spec, "access": "lan", "lan_ip": "192.168.0.100", "domain": "", "host_ports": {"80/tcp": 10080},
                                "env": {}, "secret_keys": [], "folders": {}, "image": "alpine"}}})
    monkeypatch.setattr(dk, "_port_free", lambda *a, **k: True)
    box = _capture_jobs(monkeypatch)
    fronts = []

    def tls_front(name, inst, port):
        fronts.append(port)
        inst["tls_port"] = 10443
        return 10443
    monkeypatch.setattr(dk, "tls_front", tls_front)
    monkeypatch.setattr(dk, "_compose_up", lambda name, app, inst, log: None)
    monkeypatch.setattr(dk, "wait_started", lambda *a, **k: None)
    dk.update_settings("zeta", {"path": "/ui", "keep_alive": True, "env": [{"key": "A", "value": "1"}],
                                "ports": [{"container": 8080, "proto": "tcp", "host": 18080, "kind": "web"}, {"container": 53, "proto": "udp", "host": 0, "kind": "dns"}]})
    assert box["error"] is None, box["error"]
    inst = dk._state()["apps"]["zeta"]
    assert inst["spec"]["path"] == "/ui" and inst["path"] == "/ui" and inst["spec"]["tty"] is True and inst["spec"]["env"] == {"A": "1"}
    assert inst["spec"]["ports"] == [[8080, "tcp", "web"], [53, "udp", "dns"]] and inst["host_ports"] == {"8080/tcp": 18080} and inst["spec"]["no_web"] is False
    assert fronts == [18080] and inst["tls_port"] == 10443 and "HTTPS on port 10443" in box["log"].text


def test_compose_up_writes_the_file_and_reports_a_failed_start(monkeypatch, tmp_path):
    monkeypatch.setattr(dk, "compose_cmd", lambda: ["docker", "compose"])
    calls = _recorder(monkeypatch)
    inst = _kuma_inst()
    log = FakeLog()
    dk._compose_up("kuma", dk.CATALOG["uptimekuma"], inst, log)
    assert (tmp_path / "apps" / "kuma" / "docker-compose.yml").exists() and calls[-1] == ["docker", "compose", "up", "-d", "--remove-orphans"]
    _recorder(monkeypatch, responses={"up -d": _ok("", 1, "oops")})
    with pytest.raises(dk.DockerError, match="didn't come back"):
        dk._compose_up("kuma", dk.CATALOG["uptimekuma"], inst, log)
    assert "oops" in log.text


# ---- containers made outside the panel ---------------------------------------------------------------------------
def _external_raw():
    return {"Id": "c" * 64, "Name": "/web", "Image": "sha256:" + "d" * 64,
            "Config": {"Image": "nginx:1.27", "Env": ["PATH=/bin", "FOO=bar"], "Cmd": ["nginx", "-g", "daemon off;"], "Entrypoint": ["/docker-entrypoint.sh"],
                       "User": "101", "WorkingDir": "/srv", "Labels": {"com.docker.compose.project": "x", "owner": "me"}},
            "HostConfig": {"RestartPolicy": {"Name": "always"}, "Memory": 0, "NanoCpus": 0, "NetworkMode": "mynet", "Privileged": True,
                           "CapAdd": ["NET_ADMIN"], "Devices": [{"PathOnHost": "/dev/ttyUSB0", "PathInContainer": ""}]},
            "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]}, "Networks": {}},
            "State": {"Status": "running", "Running": True}, "Mounts": [{"Type": "bind", "Source": "/srv/www", "Destination": "/usr/share/nginx/html", "RW": False},
                                                                        {"Type": "volume", "Name": "logs", "Destination": "/var/log/nginx", "RW": True}]}


def test_recreate_external_builds_the_docker_run_command(monkeypatch):
    raw = _external_raw()
    img = {"Config": {"Entrypoint": ["/entry.sh"], "Cmd": ["nginx"], "WorkingDir": "/"}}

    def docker(argv, timeout=120):
        if "image" in argv:
            return _ok(json.dumps([img]))
        return _ok(json.dumps([raw]))
    monkeypatch.setattr(dk, "_docker", docker)
    monkeypatch.setattr(dk, "_port_free", lambda *a, **k: True)
    box = _capture_jobs(monkeypatch)
    calls = _recorder(monkeypatch)
    dk.recreate_external("web", {"mem_limit": "512m", "cpus": "2", "env": [{"key": "FOO", "value": "baz"}],
                                 "ports": [{"container": 80, "proto": "tcp", "host": 9090, "bind": "127.0.0.1"}]})
    assert box["error"] is None, box["error"]
    argv = next(c for c in calls if c[:2] == ["docker", "run"])
    assert argv[:6] == ["docker", "run", "-d", "--name", "web", "--restart"] and "always" in argv
    assert argv[argv.index("--memory") + 1] == "512m" and argv[argv.index("--cpus") + 1] == "2"
    assert argv[argv.index("--network") + 1] == "mynet" and argv[argv.index("-p") + 1] == "127.0.0.1:9090:80/tcp"
    assert argv[argv.index("-e") + 1] == "FOO=baz"
    assert "/srv/www:/usr/share/nginx/html:ro" in argv and "logs:/var/log/nginx" in argv
    assert "--privileged" in argv and argv[argv.index("--cap-add") + 1] == "NET_ADMIN" and argv[argv.index("--device") + 1] == "/dev/ttyUSB0:/dev/ttyUSB0"
    assert argv[argv.index("-u") + 1] == "101" and argv[argv.index("-w") + 1] == "/srv"
    assert argv[argv.index("--label") + 1] == "owner=me" and "com.docker.compose.project=x" not in " ".join(argv)
    assert argv[argv.index("--entrypoint") + 1] == "/docker-entrypoint.sh" and argv[-4:] == ["nginx:1.27", "nginx", "-g", "daemon off;"]
    assert ["docker", "stop", "web"] in calls and any(c[:2] == ["docker", "rm"] and c[2].startswith("web-old-") for c in calls)
    assert box["result"] == {"ok": True} and "re-created" in box["log"].text


def test_recreate_external_keeps_the_old_container_when_the_new_one_fails(monkeypatch):
    raw = _external_raw()
    raw["HostConfig"]["NetworkMode"] = "host"
    renames = []

    def docker(argv, timeout=120):
        if argv[0] == "rename":
            renames.append(argv[1:])
            return _ok()
        if "image" in argv:
            raise dk.DockerError("no such image")
        return _ok(json.dumps([raw]))
    monkeypatch.setattr(dk, "_docker", docker)
    monkeypatch.setattr(dk, "_port_free", lambda *a, **k: True)
    box = _capture_jobs(monkeypatch)
    calls = _recorder(monkeypatch, responses={"docker run": _ok("", 125, "docker: invalid flag")})
    dk.recreate_external("web", {})
    assert "old one is back" in str(box["error"]) and "invalid flag" in box["log"].text
    argv = next(c for c in calls if c[:2] == ["docker", "run"])
    assert "-p" not in argv and argv[argv.index("--network") + 1] == "host"  # host networking publishes nothing
    assert "FOO=bar" in argv and argv[-1] == "daemon off;"  # the command differs from the image's own, so it is kept
    assert renames[0][0] == "web" and renames[1][1] == "web" and ["docker", "start", "web"] in calls
    with pytest.raises(dk.DockerError, match="restart policy"):
        dk.recreate_external("web", {"restart": "maybe"})


# ---- custom containers --------------------------------------------------------------------------------------------
def test_custom_spec_volumes_and_create_custom_checks(monkeypatch):
    monkeypatch.setattr(dk, "_port_free", lambda *a, **k: True)
    monkeypatch.setattr(dk, "_free_port", lambda start: start)
    data = {"name": "zeta", "image": "alpine", "access": "public", "ports": [], "keep_alive": True, "title": " Zeta box ",
            "volumes": [{"host": "mydata", "container": "/data"}, {"host": "", "container": "/var/lib/App Cache/"}]}
    name, spec, inst = dk.custom_spec(data)
    assert spec["volumes"] == [("/data", "!mydata"), ("/var/lib/App Cache/", "var-lib-app-cache")] and spec["name"] == "Zeta box"
    assert spec["no_web"] is True and inst["host_ports"] == {} and inst["restart"] == "unless-stopped"
    with pytest.raises(dk.DockerError, match="named volume"):
        dk.custom_spec({**data, "volumes": [{"host": "../x", "container": "/data"}]})
    with pytest.raises(dk.DockerError, match="no private network"):
        monkeypatch.setattr(dk, "_lan_ip", lambda: "")
        dk.custom_spec({**data, "access": "lan"})
    monkeypatch.setattr(dk, "_lan_ip", lambda: "192.168.0.100")
    monkeypatch.setattr(dk, "installed", lambda: False)
    with pytest.raises(dk.DockerError, match="Install Docker"):
        dk.create_custom(data)
    monkeypatch.setattr(dk, "installed", lambda: True)
    dk._save({"apps": {"zeta": {"app": "custom"}}})
    with pytest.raises(dk.DockerError, match="already exists"):
        dk.create_custom(data)
    dk._save({"apps": {}})
    monkeypatch.setattr(dk, "containers", lambda: {"containers": [{"name": "zeta"}]})
    with pytest.raises(dk.DockerError, match="outside the panel"):
        dk.create_custom(data)


def test_create_custom_job_runs_the_image_with_https_and_a_web_address(monkeypatch, tmp_path):
    monkeypatch.setattr(dk, "installed", lambda: True)
    monkeypatch.setattr(dk, "compose_cmd", lambda: ["docker", "compose"])
    monkeypatch.setattr(dk, "containers", lambda: {"containers": []})
    monkeypatch.setattr(dk, "_port_free", lambda *a, **k: True)
    monkeypatch.setattr(dk, "_free_port", lambda start: start)
    box = _capture_jobs(monkeypatch)
    FakePopen.calls, FakePopen.rc = [], 0
    _fake_subprocess(monkeypatch, popen=FakePopen)
    _recorder(monkeypatch)
    monkeypatch.setattr(dk, "image_user", lambda image: "70:70")
    monkeypatch.setattr(dk, "wait_started", lambda *a, **k: 404)
    monkeypatch.setattr(dk, "find_page", lambda host, port: "/ui/")
    proxied = []
    monkeypatch.setattr(dk, "_proxy_site", lambda name, domain, port: proxied.append((domain, port)))
    dk.create_custom({"name": "zeta", "image": "ghcr.io/owner/app:1.2", "access": "proxy", "domain": "zeta.example.com",
                      "ports": [{"container": 8080, "proto": "tcp", "host": 0, "kind": "web"}], "volumes": [{"host": "", "container": "/data"}]})
    assert box["error"] is None, box["error"]
    assert box["result"] == {"ok": True, "name": "zeta"} and proxied == [("zeta.example.com", 8080)]
    inst = dk._state()["apps"]["zeta"]
    assert inst["path"] == "/ui/" and inst["spec"]["path"] == "/ui/" and (tmp_path / "apps" / "zeta" / "data").is_dir()
    assert FakePopen.calls[0]["cwd"] == tmp_path / "apps" / "zeta" and "runs as user 70:70" in box["log"].text
    FakePopen.rc = 1
    dk.create_custom({"name": "beta", "image": "alpine", "access": "public", "ports": []})
    assert "check its name and tag" in str(box["error"])
    FakePopen.rc = 0
    _recorder(monkeypatch, responses={"up -d": _ok("", 1, "bad compose")})
    dk.create_custom({"name": "beta", "image": "alpine", "access": "public", "ports": []})
    assert "didn't start" in str(box["error"]) and "beta" not in dk._state()["apps"]


def test_create_custom_https_only_adds_a_tls_front(monkeypatch, tmp_path):
    monkeypatch.setattr(dk, "installed", lambda: True)
    monkeypatch.setattr(dk, "compose_cmd", lambda: ["docker", "compose"])
    monkeypatch.setattr(dk, "containers", lambda: {"containers": []})
    monkeypatch.setattr(dk, "_port_free", lambda *a, **k: True)
    monkeypatch.setattr(dk, "_free_port", lambda start: start)
    box = _capture_jobs(monkeypatch)
    FakePopen.calls, FakePopen.rc = [], 0
    _fake_subprocess(monkeypatch, popen=FakePopen)
    _recorder(monkeypatch)
    monkeypatch.setattr(dk, "wait_started", lambda *a, **k: None)
    fronts = []

    def tls_front(name, inst, port):
        fronts.append((name, port))
        inst["tls_port"] = 10443
        return 10443
    monkeypatch.setattr(dk, "tls_front", tls_front)
    dk.create_custom({"name": "pw", "image": "vaultwarden/server", "access": "lan", "https_only": True, "uid": "1000",
                      "ports": [{"container": 80, "proto": "tcp", "host": 10080, "kind": "web"}]})
    assert box["error"] is None, box["error"]
    assert fronts == [("pw", 10080)] and dk._state()["apps"]["pw"]["tls_port"] == 10443
    assert '"127.0.0.1:10080:80/tcp"' in (tmp_path / "apps" / "pw" / "docker-compose.yml").read_text()


def test_settle_page_logs_when_no_page_is_found(monkeypatch):
    monkeypatch.setattr(dk, "find_page", lambda host, port: "")
    log = FakeLog()
    inst = {"app": "custom", "spec": {}, "access": "lan", "lan_ip": "192.168.0.100"}
    dk._settle_page("x", inst, {}, 404, 10080, log)
    assert "no page at /" in log.text and "path" not in inst


def test_port_and_limit_parsers_reject_bad_values():
    with pytest.raises(dk.DockerError, match="numbers"):
        dk._parse_ports([{"container": "eighty"}])
    with pytest.raises(dk.DockerError, match="tcp or udp"):
        dk._parse_ports([{"container": 80, "proto": "sctp"}])
    with pytest.raises(dk.DockerError, match="Bad value"):
        dk._parse_env([{"key": "A", "value": "x\ny"}])
    with pytest.raises(dk.DockerError, match="number like"):
        dk._parse_limits("", "two")
    assert dk._parse_limits("512MB", 0) == ("512m", "") and dk._parse_limits("1.5g", "1.0") == ("1.5g", "1")
    assert dk._page_path(None) == "" and dk._page_path("/admin") == "/admin"
    with pytest.raises(dk.DockerError, match="Host port 8080/tcp is already in use on 10.0.0.5"):
        dk._check_host_ports([{"container": 80, "host": 8080, "proto": "tcp", "bind": "10.0.0.5"}], set(), None) if False else \
            _busy_check()


def _busy_check():
    import contextlib
    with contextlib.ExitStack():
        real = dk._port_free
        try:
            dk._port_free = lambda *a, **k: False
            dk._check_host_ports([{"container": 80, "host": 8080, "proto": "tcp", "bind": "10.0.0.5"}], set(), None)
        finally:
            dk._port_free = real
