"""Dynamic DNS: provider update calls, the stored state, configuration checks and the systemd timer."""
import base64
import json
import subprocess
import urllib.error

import pytest

from backend import ddns


@pytest.fixture
def state(tmp_path, monkeypatch):
    """Config and unit files in tmp_path, systemctl recorded instead of run, no real DNS."""
    monkeypatch.setattr(ddns, "CONFIG", tmp_path / "ddns.json")
    monkeypatch.setattr(ddns, "UNIT_DIR", tmp_path / "units")
    (tmp_path / "units").mkdir()
    calls: list[list[str]] = []

    def run(argv, **kw):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "active\n" if argv[-1] == ddns.TIMER else "inactive\n", "")
    monkeypatch.setattr(ddns.subprocess, "run", run)
    monkeypatch.setattr(ddns.socket, "gethostbyname", lambda h: "203.0.113.9" if h.endswith(".duckdns.org") else (_ for _ in ()).throw(OSError("nx")))
    monkeypatch.setattr(ddns, "_public_ip", lambda: "203.0.113.9")
    return {"calls": calls, "dir": tmp_path}


@pytest.fixture
def http(monkeypatch):
    """Record every provider request; answers is a list of (code, body) consumed in order, or a callable."""
    log: list[dict] = []
    answers: list = []

    def fake(url, headers=None, data=None, method=None, auth=None):
        log.append({"url": url, "headers": headers or {}, "data": data, "method": method, "auth": auth})
        a = answers.pop(0) if answers else (200, "")
        return a(url) if callable(a) else a
    monkeypatch.setattr(ddns, "_http", fake)
    fake.log, fake.answers = log, answers
    return fake


def test_load_tolerates_missing_or_broken_config(state):
    assert ddns._load() == {}
    ddns.CONFIG.write_text("{nope", encoding="utf-8")
    assert ddns._load() == {}
    ddns._save({"provider": "duckdns", "enabled": True, "hostname": "h.duckdns.org"})
    assert json.loads(ddns.CONFIG.read_text())["provider"] == "duckdns"
    assert ddns.hostname() == "h.duckdns.org"
    ddns._save({"provider": "duckdns", "enabled": False, "hostname": "h.duckdns.org"})
    assert ddns.hostname() is None


def test_duckdns_subdomain_gets_its_suffix():
    assert ddns._full_host("duckdns", " MyHome ") == "myhome.duckdns.org"
    assert ddns._full_host("duckdns", "myhome.duckdns.org") == "myhome.duckdns.org"
    assert ddns._full_host("noip", "Home.ddns.net") == "home.ddns.net"


class Resp:
    def __init__(self, body, status=200):
        self.body, self.status = body, status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.body

    def close(self):
        pass


def test_public_ip_tries_each_service_until_one_answers_an_address(monkeypatch):
    asked = []

    def urlopen(req, timeout=0):
        asked.append(req.full_url)
        if "ipify" in req.full_url:
            raise OSError("down")
        if "ifconfig" in req.full_url:
            return Resp(b"<html>not an ip</html>")
        return Resp(b"198.51.100.7\n")
    monkeypatch.setattr(ddns.urllib.request, "urlopen", urlopen)
    assert ddns._public_ip() == "198.51.100.7"
    assert asked == ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]
    monkeypatch.setattr(ddns.urllib.request, "urlopen", lambda req, timeout=0: Resp(b"garbage"))
    with pytest.raises(ddns.DDNSError, match="public IP"):
        ddns._public_ip()


def test_http_sets_user_agent_and_basic_auth_and_maps_errors(monkeypatch):
    seen = {}

    def urlopen(req, timeout=0):
        seen.update(url=req.full_url, headers=dict(req.header_items()), method=req.get_method(), data=req.data)
        return Resp(b" good 1.2.3.4 \n", 200)
    monkeypatch.setattr(ddns.urllib.request, "urlopen", urlopen)
    assert ddns._http("https://x/u", {"X-A": "1"}, b"{}", "PUT", auth=("me", "pw")) == (200, "good 1.2.3.4")
    assert seen["method"] == "PUT" and seen["data"] == b"{}"
    assert seen["headers"]["User-agent"] == ddns.UA and seen["headers"]["X-a"] == "1"
    assert seen["headers"]["Authorization"] == "Basic " + base64.b64encode(b"me:pw").decode()

    def http_error(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 401, "nope", {}, Resp(b"badauth"))
    monkeypatch.setattr(ddns.urllib.request, "urlopen", http_error)
    assert ddns._http("https://x/u") == (401, "badauth")

    def unreachable(req, timeout=0):
        raise urllib.error.URLError("name not known")
    monkeypatch.setattr(ddns.urllib.request, "urlopen", unreachable)
    with pytest.raises(ddns.DDNSError, match="Provider unreachable"):
        ddns._http("https://x/u")


def test_duckdns_update_call(http):
    cfg = {"provider": "duckdns", "hostname": "myhome.duckdns.org", "token": "t0k"}
    http.answers.append((200, "OK"))
    assert ddns._send(cfg, "1.2.3.4") == "OK"
    assert http.log[0]["url"] == "https://www.duckdns.org/update?domains=myhome&token=t0k&ip=1.2.3.4"
    http.answers.append((200, "KO"))
    with pytest.raises(ddns.DDNSError, match="DuckDNS rejected"):
        ddns._send(cfg, "1.2.3.4")


def test_dyndns2_providers_use_basic_auth(http):
    cfg = {"provider": "noip", "hostname": "h.ddns.net", "username": "u", "password": "p"}
    http.answers.append((200, "good 1.2.3.4"))
    assert ddns._send(cfg, "1.2.3.4") == "good 1.2.3.4"
    assert http.log[0]["url"] == "https://dynupdate.no-ip.com/nic/update?hostname=h.ddns.net&myip=1.2.3.4"
    assert http.log[0]["auth"] == ("u", "p")
    http.answers.append((200, "nochg 1.2.3.4"))
    assert ddns._send({**cfg, "provider": "dynu"}, "1.2.3.4") == "nochg 1.2.3.4"
    assert http.log[1]["url"].startswith("https://api.dynu.com/nic/update?")
    http.answers.append((200, "badauth"))
    with pytest.raises(ddns.DDNSError, match="Provider said: badauth"):
        ddns._send(cfg, "1.2.3.4")
    http.answers.append((500, ""))
    with pytest.raises(ddns.DDNSError, match="Provider said: 500"):
        ddns._send(cfg, "1.2.3.4")


def test_desec_and_freedns_calls(http):
    cfg = {"provider": "desec", "hostname": "h.dedyn.io", "token": "T"}
    http.answers.append((200, "good"))
    assert ddns._send(cfg, "1.2.3.4") == "good"
    assert http.log[0]["url"] == "https://update.dedyn.io/?hostname=h.dedyn.io&myipv4=1.2.3.4"
    assert http.log[0]["headers"] == {"Authorization": "Token T"}
    http.answers.append((401, "Unauthorized"))
    with pytest.raises(ddns.DDNSError, match="deSEC said: Unauthorized"):
        ddns._send(cfg, "1.2.3.4")
    cfg = {"provider": "freedns", "hostname": "h.mooo.com", "token": "a/b c"}
    http.answers.append((200, "Updated h.mooo.com to 1.2.3.4"))
    assert ddns._send(cfg, "1.2.3.4").startswith("Updated")
    assert http.log[-1]["url"] == "https://sync.afraid.org/u/a/b%20c/?address=1.2.3.4"
    http.answers.append((200, "ERROR: bad token"))
    with pytest.raises(ddns.DDNSError, match="FreeDNS said"):
        ddns._send(cfg, "1.2.3.4")


def test_custom_url_is_filled_in_and_checked(http):
    cfg = {"provider": "custom", "hostname": "h.example.net", "url": "https://u/?h={hostname}&ip={ip}"}
    http.answers.append((200, "ok"))
    assert ddns._send(cfg, "1.2.3.4") == "ok"
    assert http.log[0]["url"] == "https://u/?h=h.example.net&ip=1.2.3.4"
    http.answers.append((204, ""))
    assert ddns._send(cfg, "1.2.3.4") == "HTTP 204"
    http.answers.append((403, "denied"))
    with pytest.raises(ddns.DDNSError, match="HTTP 403: denied"):
        ddns._send(cfg, "1.2.3.4")
    with pytest.raises(ddns.DDNSError, match="must start with http"):
        ddns._send({**cfg, "url": "ftp://x"}, "1.2.3.4")
    with pytest.raises(ddns.DDNSError, match="Unknown provider"):
        ddns._send({"provider": "nope"}, "1.2.3.4")


def test_cloudflare_finds_the_zone_and_updates_or_creates_the_record(http):
    cfg = {"provider": "cloudflare", "hostname": "home.sub.example.com", "token": "cf"}
    http.answers += [(200, json.dumps({"result": []})),                       # home.sub.example.com: no zone
                     (200, json.dumps({"result": []})),                       # sub.example.com: no zone
                     (200, json.dumps({"result": [{"id": "Z1"}]})),           # example.com
                     (200, json.dumps({"result": [{"id": "R1"}]})),           # existing A record
                     (200, json.dumps({"success": True}))]
    assert ddns._send(cfg, "1.2.3.4") == "updated"
    urls = [e["url"] for e in http.log]
    assert urls[:3] == ["https://api.cloudflare.com/client/v4/zones?name=home.sub.example.com",
                        "https://api.cloudflare.com/client/v4/zones?name=sub.example.com",
                        "https://api.cloudflare.com/client/v4/zones?name=example.com"]
    assert urls[3] == "https://api.cloudflare.com/client/v4/zones/Z1/dns_records?type=A&name=home.sub.example.com"
    assert urls[4].endswith("/dns_records/R1") and http.log[4]["method"] == "PUT"
    assert json.loads(http.log[4]["data"]) == {"type": "A", "name": "home.sub.example.com", "content": "1.2.3.4", "ttl": 120, "proxied": False}
    assert http.log[0]["headers"]["Authorization"] == "Bearer cf"

    http.answers += [(200, json.dumps({"result": [{"id": "Z1"}]})), (200, "{}"), (200, json.dumps({"success": False, "errors": ["x"]}))]
    with pytest.raises(ddns.DDNSError, match="Cloudflare:"):
        ddns._send({**cfg, "hostname": "home.example.com"}, "1.2.3.4")
    assert http.log[-1]["method"] == "POST" and http.log[-1]["url"].endswith("/zones/Z1/dns_records")

    http.answers += [(200, "{}"), (200, "{}"), (200, "{}")]
    with pytest.raises(ddns.DDNSError, match="No Cloudflare zone"):
        ddns._send({**cfg, "hostname": "a.b.c"}, "1.2.3.4")


def test_update_skips_when_recently_sent_and_records_outcomes(state, monkeypatch):
    with pytest.raises(ddns.DDNSError, match="not configured"):
        ddns.update()
    sent = []
    monkeypatch.setattr(ddns, "_send", lambda cfg, ip: sent.append(ip) or "OK")
    ddns._save({"provider": "duckdns", "hostname": "h.duckdns.org", "token": "t", "enabled": True})
    r = ddns.update()
    assert r == {"changed": True, "ip": "203.0.113.9", "message": "OK"} and sent == ["203.0.113.9"]
    last = ddns._load()["last"]
    assert last["ok"] and last["ip"] == "203.0.113.9" and last["message"] == "OK"
    assert ddns.update() == {"changed": False, "ip": "203.0.113.9", "message": "unchanged"} and len(sent) == 1
    assert ddns.update(force=True)["changed"] and len(sent) == 2
    cfg = ddns._load()
    cfg["last"]["ts"] -= ddns.FORCE_EVERY + 1   # a day old: re-sent even when unchanged
    ddns._save(cfg)
    assert ddns.update()["changed"] and len(sent) == 3

    def fail(cfg, ip):
        raise ddns.DDNSError("rejected")
    monkeypatch.setattr(ddns, "_send", fail)
    with pytest.raises(ddns.DDNSError, match="rejected"):
        ddns.update(force=True)
    last = ddns._load()["last"]
    assert last["ok"] is False and last["message"] == "rejected"


def test_status_hides_secrets_and_reports_timer_and_resolution(state):
    ddns._save({"provider": "duckdns", "hostname": "h.duckdns.org", "token": "t", "enabled": True,
                "last": {"ok": True, "ip": "203.0.113.9"}})
    s = ddns.status()
    assert "token" not in s["config"] and s["config"]["token_set"] is True
    assert s["timer_active"] is True and s["ddclient_active"] is False
    assert s["resolved_ip"] == "203.0.113.9" and s["last"]["ip"] == "203.0.113.9"
    assert ["systemctl", "is-active", ddns.TIMER] in state["calls"]
    assert set(s["providers"]) == set(ddns.PROVIDERS)
    ddns.CONFIG.unlink()
    s = ddns.status()
    assert s["config"] == {} and s["resolved_ip"] is None and s["last"] == {}


def test_unit_active_without_systemd(monkeypatch):
    def no_systemd(argv, **kw):
        raise FileNotFoundError
    monkeypatch.setattr(ddns.subprocess, "run", no_systemd)
    assert ddns._unit_active("x") is False

    def nx(host):
        raise OSError("no such host")
    monkeypatch.setattr(ddns.socket, "gethostbyname", nx)
    assert ddns._resolve("nx.example") is None
    monkeypatch.setattr(ddns.socket, "gethostbyname", lambda h: "1.2.3.4")
    assert ddns._resolve("ok.example") == "1.2.3.4"


def test_configure_validates_fields_and_hostname(state, monkeypatch):
    monkeypatch.setattr(ddns, "_send", lambda cfg, ip: "OK")
    with pytest.raises(ddns.DDNSError, match="Unknown provider"):
        ddns.configure("nope", {})
    with pytest.raises(ddns.DDNSError, match="Token is required"):
        ddns.configure("duckdns", {"hostname": "myhome"})
    with pytest.raises(ddns.DDNSError, match="valid hostname"):
        ddns.configure("noip", {"hostname": "not a host", "username": "u", "password": "p"})
    assert not ddns.CONFIG.exists()


def test_configure_writes_the_timer_and_runs_a_first_update(state, monkeypatch):
    sent = []
    monkeypatch.setattr(ddns, "_send", lambda cfg, ip: sent.append((cfg["hostname"], cfg["token"])) or "OK")
    r = ddns.configure("duckdns", {"hostname": " MyHome ", "token": "t0k"})
    assert r["ok"] and r["result"]["changed"] and sent == [("myhome.duckdns.org", "t0k")]
    assert r["config"]["hostname"] == "myhome.duckdns.org" and r["config"]["token_set"]
    unit = (state["dir"] / "units" / ddns.SERVICE).read_text()
    assert "-m backend.ddns update" in unit and f"WorkingDirectory={ddns.APP_DIR}" in unit
    timer = (state["dir"] / "units" / ddns.TIMER).read_text()
    assert "OnUnitActiveSec=5min" in timer and "WantedBy=timers.target" in timer
    assert ["systemctl", "daemon-reload"] in state["calls"]
    assert ["systemctl", "enable", "--now", ddns.TIMER] in state["calls"]
    # Editing with a blank token keeps the stored one and the last result.
    r = ddns.configure("duckdns", {"hostname": "myhome", "token": ""})
    assert sent[-1] == ("myhome.duckdns.org", "t0k") and r["last"]["ok"]
    # A different hostname starts with no history.
    r = ddns.configure("duckdns", {"hostname": "other", "token": ""}, enabled=False)
    assert r["result"] is None and r["last"] == {} and r["config"]["enabled"] is False
    assert ["systemctl", "disable", "--now", ddns.TIMER] in state["calls"]


def test_disable_and_stop_ddclient(state):
    ddns._save({"provider": "duckdns", "hostname": "h.duckdns.org", "token": "t", "enabled": True})
    s = ddns.disable()
    assert s["config"]["enabled"] is False and ddns._load()["enabled"] is False
    assert ["systemctl", "disable", "--now", ddns.TIMER] in state["calls"]
    ddns.stop_ddclient()
    assert ["systemctl", "disable", "--now", "ddclient"] in state["calls"]
