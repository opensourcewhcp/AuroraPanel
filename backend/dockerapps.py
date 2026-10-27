"""Docker apps — one-click self-hosted apps (Home Assistant, Jellyfin, Vaultwarden, Uptime Kuma…).

Every app lives in /opt/aurora-apps/<name>/ (docker-compose.yml + its data), run with `docker compose`.

Safety first: Docker publishes ports by writing its own firewall rules, which skip ufw *and* this
panel's ban list. So by default an app only listens on 127.0.0.1 and is reached through a web address
(an Apache reverse proxy site: HTTPS from AutoSSL, the WAF and IP bans apply). "Local network" binds
to this machine's private LAN address only; "public port" is possible but flagged.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path

from . import jobs

BASE = Path("/opt/aurora-apps")
PATH = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin"
_NAME = re.compile(r"^[a-z][a-z0-9-]{1,30}$")


class DockerError(RuntimeError):
    pass


# id: name, category, description, image, ports [(container port, proto, kind)], volumes [(container path, folder)],
# env {k: v ("{secret}" = generated)}, ram, extra compose keys. kind: web = the app's web page; tcp/udp = other ports.
CATALOG: dict[str, dict] = {
    "homeassistant": {"name": "Home Assistant", "cat": "Home", "desc": "Open-source home automation: lights, sensors, energy, cameras — 3,000+ integrations, runs locally.",
                      "image": "ghcr.io/home-assistant/home-assistant:stable", "ports": [(8123, "tcp", "web")], "volumes": [("/config", "config")],
                      "env": {"TZ": "{tz}"}, "ram": "≈ 300 MB", "host_network": True, "privileged": True, "home": "https://www.home-assistant.io"},
    "jellyfin": {"name": "Jellyfin", "cat": "Media", "desc": "Your own Netflix: stream your movies, shows and music to any device. No account, no tracking.",
                 "image": "jellyfin/jellyfin:latest", "ports": [(8096, "tcp", "web")], "volumes": [("/config", "config"), ("/cache", "cache"), ("/media", "@media")],
                 "env": {}, "ram": "≈ 250 MB", "home": "https://jellyfin.org"},
    "vaultwarden": {"name": "Vaultwarden", "cat": "Security", "desc": "Password manager compatible with the Bitwarden apps and browser extensions.",
                    "image": "vaultwarden/server:latest", "ports": [(80, "tcp", "web")], "volumes": [("/data", "data")],
                    "env": {"ADMIN_TOKEN": "{secret}", "SIGNUPS_ALLOWED": "true", "WEBSOCKET_ENABLED": "true"}, "ram": "≈ 30 MB", "https_only": True,
                    "note": "Needs HTTPS (the web vault and the Bitwarden apps refuse plain http) — on the local network the panel adds it for you. Turn sign-ups off in its admin page (/admin) once your account exists.",
                    "home": "https://github.com/dani-garcia/vaultwarden"},
    "uptimekuma": {"name": "Uptime Kuma", "cat": "Monitoring", "desc": "Watch your websites and services; get notified the moment one goes down.",
                   "image": "louislam/uptime-kuma:1", "ports": [(3001, "tcp", "web")], "volumes": [("/app/data", "data")], "env": {}, "ram": "≈ 100 MB",
                   "home": "https://uptime.kuma.pet"},
    "pihole": {"name": "Pi-hole", "cat": "Network", "desc": "Network-wide ad and tracker blocking: point your router's DNS at it and every device is covered.",
               "image": "pihole/pihole:latest", "ports": [(80, "tcp", "web"), (53, "tcp", "dns"), (53, "udp", "dns")],
               "volumes": [("/etc/pihole", "etc-pihole"), ("/etc/dnsmasq.d", "dnsmasq")],
               "env": {"TZ": "{tz}", "FTLCONF_webserver_api_password": "{secret}", "FTLCONF_dns_listeningMode": "all"}, "ram": "≈ 80 MB",
               "path": "/admin/", "cap_add": ["NET_ADMIN"],
               "note": "Needs port 53 — it can't run next to this server's own DNS server (BIND). The admin password is shown after install.",
               "home": "https://pi-hole.net"},
    "adguard": {"name": "AdGuard Home", "cat": "Network", "desc": "Ad blocking DNS with encrypted DNS (DoH/DoT), parental controls and a clean interface.",
                "image": "adguard/adguardhome:latest", "ports": [(3000, "tcp", "web"), (53, "tcp", "dns"), (53, "udp", "dns")],
                "volumes": [("/opt/adguardhome/work", "work"), ("/opt/adguardhome/conf", "conf")], "env": {}, "ram": "≈ 50 MB",
                "note": "Needs port 53, so not next to this server's own DNS server (BIND).", "home": "https://adguard.com/adguard-home.html"},
    "gitea": {"name": "Gitea", "cat": "Development", "desc": "Your own GitHub: Git hosting with pull requests, issues, wiki and CI.",
              "image": "gitea/gitea:latest", "ports": [(3000, "tcp", "web"), (22, "tcp", "ssh")], "volumes": [("/data", "data")],
              "env": {"USER_UID": "1000", "USER_GID": "1000"}, "ram": "≈ 150 MB", "home": "https://about.gitea.com"},
    "n8n": {"name": "n8n", "cat": "Automation", "desc": "Visual workflow automation (like Zapier) with 400+ integrations and AI steps.",
            "image": "n8nio/n8n:latest", "ports": [(5678, "tcp", "web")], "volumes": [("/home/node/.n8n", "data")],
            "env": {"TZ": "{tz}", "GENERIC_TIMEZONE": "{tz}", "N8N_SECURE_COOKIE": "{secure}", "N8N_PROXY_HOPS": "1"}, "ram": "≈ 250 MB", "uid": "1000:1000", "home": "https://n8n.io"},
    "filebrowser": {"name": "File Browser", "cat": "Files", "desc": "A simple web file manager to share and upload files from any browser.",
                    "image": "filebrowser/filebrowser:latest", "ports": [(80, "tcp", "web")], "volumes": [("/srv", "@files"), ("/database", "db"), ("/config", "config")],
                    "env": {}, "ram": "≈ 20 MB", "uid": "1000:1000", "note": "First login: admin — the password is printed in the app's log on first start (Logs).",
                    "home": "https://filebrowser.org"},
    "syncthing": {"name": "Syncthing", "cat": "Files", "desc": "Keep folders in sync between your computers and phones — peer to peer, no cloud.",
                  "image": "syncthing/syncthing:latest", "ports": [(8384, "tcp", "web"), (22000, "tcp", "sync"), (22000, "udp", "sync"), (21027, "udp", "discovery")],
                  "volumes": [("/var/syncthing", "data")], "env": {"PUID": "1000", "PGID": "1000"}, "ram": "≈ 60 MB", "home": "https://syncthing.net"},
    "navidrome": {"name": "Navidrome", "cat": "Media", "desc": "Your music collection, streamed anywhere — works with Subsonic apps on every phone.",
                  "image": "deluan/navidrome:latest", "ports": [(4533, "tcp", "web")], "volumes": [("/data", "data"), ("/music", "@music")],
                  "env": {}, "ram": "≈ 40 MB", "home": "https://www.navidrome.org"},
    "grafana": {"name": "Grafana", "cat": "Monitoring", "desc": "Beautiful dashboards for metrics from Prometheus, InfluxDB, Home Assistant and more.",
                "image": "grafana/grafana-oss:latest", "ports": [(3000, "tcp", "web")], "volumes": [("/var/lib/grafana", "data")],
                "env": {"GF_SECURITY_ADMIN_PASSWORD": "{secret}"}, "ram": "≈ 100 MB", "user": "0", "home": "https://grafana.com"},
    "codeserver": {"name": "VS Code (code-server)", "cat": "Development", "desc": "Visual Studio Code in your browser, running on this server.",
                   "image": "lscr.io/linuxserver/code-server:latest", "ports": [(8443, "tcp", "web")], "volumes": [("/config", "config")],
                   "env": {"PUID": "1000", "PGID": "1000", "TZ": "{tz}", "PASSWORD": "{secret}"}, "ram": "≈ 200 MB", "home": "https://coder.com/docs/code-server"},
    "portainer": {"name": "Portainer", "cat": "Development", "desc": "Advanced Docker management: containers, images, volumes, networks and stacks.",
                  "image": "portainer/portainer-ce:latest", "ports": [(9000, "tcp", "web")], "volumes": [("/data", "data"), ("/var/run/docker.sock", "!/var/run/docker.sock")],
                  "env": {}, "ram": "≈ 40 MB", "home": "https://www.portainer.io"},
    "mosquitto": {"name": "Mosquitto (MQTT)", "cat": "Home", "desc": "The MQTT message broker sensors, Zigbee2MQTT, Tasmota and Home Assistant talk through.",
                  "image": "eclipse-mosquitto:2", "ports": [(1883, "tcp", "mqtt")], "volumes": [("/mosquitto/config", "config"), ("/mosquitto/data", "data")],
                  "env": {}, "ram": "≈ 5 MB", "no_web": True, "uid": "1883:1883", "home": "https://mosquitto.org",
                  "files": {"config/mosquitto.conf": "listener 1883\nallow_anonymous false\npassword_file /mosquitto/config/passwd\npersistence true\npersistence_location /mosquitto/data/\n"},
                  "setup": "mosquitto", "secret_keys": ["MQTT_PASSWORD"],
                  "note": "A login is created when it's installed — see it under “Generated passwords”. Add more with: docker exec -it <app> mosquitto_passwd -b /mosquitto/config/passwd USER PASSWORD, then Restart."},
}


def _env() -> dict:
    return {**os.environ, "PATH": PATH}


def _run(argv, timeout=300, cwd=None):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=_env(), cwd=cwd)
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 1, "", str(e))


def compose_cmd() -> list[str] | None:
    if shutil.which("docker", path=PATH) and _run(["docker", "compose", "version"], 20).returncode == 0:
        return ["docker", "compose"]
    if shutil.which("docker-compose", path=PATH):
        return ["docker-compose"]
    return None


def installed() -> bool:
    return shutil.which("docker", path=PATH) is not None and compose_cmd() is not None


def daemon_ok() -> bool:
    return _run(["docker", "info", "--format", "{{.ServerVersion}}"], 20).returncode == 0


def post_install() -> list[str]:
    """Log size limits (SD cards!) and start Docker."""
    daemon = Path("/etc/docker/daemon.json")
    try:
        cfg = json.loads(daemon.read_text()) if daemon.exists() else {}
    except ValueError:
        cfg = {}
    cfg.setdefault("log-driver", "json-file")
    cfg.setdefault("log-opts", {"max-size": "10m", "max-file": "3"})
    daemon.parent.mkdir(parents=True, exist_ok=True)
    daemon.write_text(json.dumps(cfg, indent=2) + "\n")
    # Docker turns the kernel's FORWARD policy to DROP, which would cut off VPN clients (WireGuard, OpenVPN,
    # IPsec) routed through this server. Let their traffic through Docker's own hook, every time Docker starts.
    rules = [["-i", "wg+"], ["-o", "wg+"], ["-i", "tun+"], ["-o", "tun+"],
             ["-m", "policy", "--dir", "in", "--pol", "ipsec"], ["-m", "policy", "--dir", "out", "--pol", "ipsec"]]
    pre = "\n".join(f"ExecStart=-/bin/sh -c 'iptables -C DOCKER-USER {' '.join(r)} -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER {' '.join(r)} -j ACCEPT'"
                    for r in rules)
    Path("/etc/systemd/system/aurora-docker-vpn.service").write_text(
        "# Written by AuroraPanel: keep VPN clients routed when Docker is installed\n"
        "[Unit]\nDescription=AuroraPanel: let VPN traffic past Docker's forward filter\nAfter=docker.service\nBindsTo=docker.service\n\n"
        f"[Service]\nType=oneshot\nRemainAfterExit=yes\n{pre}\n\n[Install]\nWantedBy=docker.service\n")
    _run(["systemctl", "daemon-reload"], 60)
    _run(["systemctl", "enable", "docker", "aurora-docker-vpn"], 60)
    _run(["systemctl", "restart", "docker"], 120)
    _run(["systemctl", "start", "aurora-docker-vpn"], 60)
    BASE.mkdir(parents=True, exist_ok=True)
    os.chmod(BASE, 0o711)
    notes = ["• Docker started; container logs are capped at 10 MB × 3 so they can't fill the disk",
             "• VPN clients keep working (Docker's forward filter lets WireGuard/OpenVPN/IPsec traffic through)"]
    try:
        if mem_cgroup()["can_enable"] and enable_mem_cgroup()["changed"]:
            notes.append("• Memory accounting for containers turned on in cmdline.txt — RAM figures and limits work after the next reboot")
    except Exception:
        pass
    return notes


CMDLINE = [Path("/boot/firmware/cmdline.txt"), Path("/boot/cmdline.txt")]
MEM_CGROUP_FLAGS = "cgroup_enable=memory cgroup_memory=1"


def mem_cgroup() -> dict:
    """Raspberry Pi OS boots without the memory cgroup, so Docker can't report or limit a container's RAM."""
    try:
        active = "memory" in Path("/sys/fs/cgroup/cgroup.controllers").read_text().split()
    except OSError:
        active = True  # not a cgroup-v2 system we know — don't nag
    cmd = next((c for c in CMDLINE if c.exists()), None)
    pending = False
    if cmd and not active:
        try:
            pending = "cgroup_enable=memory" in cmd.read_text()
        except OSError:
            pass
    return {"active": active, "pending": pending, "can_enable": bool(cmd) and not active and not pending}


def enable_mem_cgroup() -> dict:
    cmd = next((c for c in CMDLINE if c.exists()), None)
    if not cmd:
        raise DockerError("No boot cmdline.txt found — not a Raspberry Pi?")
    text = cmd.read_text()
    if "cgroup_enable=memory" in text:
        return {"ok": True, "changed": False}
    text = text.rstrip("\n") + " " + MEM_CGROUP_FLAGS + "\n"
    cmd.write_text(text)
    try:
        from . import audit
        audit.record("system", "", "docker: memory cgroup enabled in cmdline.txt (reboot to apply)")
    except Exception:
        pass
    return {"ok": True, "changed": True}


def arch() -> str:
    return {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "arm", "armv6l": "arm"}.get(os.uname().machine, os.uname().machine)


def _lan_ip() -> str:
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            if name.startswith(("docker", "br-", "veth", "lo", "wg", "tun")):
                continue
            for a in addrs:
                if a.family == socket.AF_INET:
                    ip = ipaddress.ip_address(a.address)
                    if ip.is_private and not ip.is_loopback:
                        return a.address
    except Exception:
        pass
    return ""


def _port_free(port: int, proto: str = "tcp", host: str = "0.0.0.0") -> bool:
    """Can a socket bind host:port? Checked on the address the container will publish on, so a service
    bound to loopback only (BIND on 127.0.0.1:53) doesn't block the same port on the LAN address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
    try:
        if proto == "tcp":  # on UDP, SO_REUSEADDR lets a second bind succeed next to a live listener → false "free"
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host or "0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _free_port(start: int) -> int:
    used = {p for a in _state()["apps"].values() for p in a.get("host_ports", {}).values()}
    p = max(start, 10000)
    while p in used or not _port_free(p):
        p += 1
    return p


STATE = Path("/var/lib/aurora/docker-apps.json")


def _state() -> dict:
    try:
        d = json.loads(STATE.read_text())
    except (OSError, ValueError):
        d = {}
    d.setdefault("apps", {})
    return d


def _save(d: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_name(f".{STATE.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(d, indent=1))
    os.chmod(tmp, 0o600)  # holds generated app passwords
    tmp.replace(STATE)


def _tz() -> str:
    try:
        return Path("/etc/timezone").read_text().strip() or "UTC"
    except OSError:
        link = os.path.realpath("/etc/localtime")
        return link.split("zoneinfo/")[-1] if "zoneinfo/" in link else "UTC"


def _yaml_str(v) -> str:
    return json.dumps(str(v))  # JSON strings are valid YAML scalars


def parse_uid(uid) -> tuple[int, int] | None:
    """"1000" / "1000:1000" → (uid, gid); anything else → None."""
    u, _, g = str(uid or "").strip().partition(":")
    if not u.isdigit() or (g and not g.isdigit()):
        return None
    return int(u), int(g or u)


def own_data(app: dict, paths) -> None:
    """Images that run as a non-root user (n8n → node 1000, mosquitto 1883) can't write a folder root made —
    the container then crash-loops with EACCES. Hand the app's own data folders to that user."""
    ids = parse_uid(app.get("uid"))
    if not ids:
        return
    for p in paths:
        try:
            os.chown(p, *ids)
            for sub in Path(p).rglob("*"):
                os.chown(sub, *ids, follow_symlinks=False)
        except OSError:
            pass


RESTART_POLICIES = ("unless-stopped", "always", "on-failure", "no")


def port_bind(inst: dict, kind: str) -> str:
    """Which address a published port listens on: proxy → loopback for the web port, LAN address otherwise."""
    if inst["access"] == "proxy" or (kind == "web" and inst.get("tls_port")):
        return "127.0.0.1" if kind == "web" else (inst.get("lan_ip") or "127.0.0.1")
    if inst["access"] == "lan" or kind == "dns":
        return inst.get("lan_ip") or "0.0.0.0"
    return "0.0.0.0"


def render_compose(name: str, app: dict, inst: dict) -> str:
    lines = ["# Written by AuroraPanel (Applications → Docker Apps). Edit there — changes here are overwritten.", "services:", f"  {name}:",
             f"    image: {_yaml_str(inst.get('image') or app['image'])}", f"    container_name: {_yaml_str(name)}",
             f"    restart: {inst.get('restart') if inst.get('restart') in RESTART_POLICIES else 'unless-stopped'}"]
    if app.get("host_network"):
        lines.append("    network_mode: host")
    if app.get("privileged"):
        lines.append("    privileged: true")
    if app.get("tty"):  # keeps a shell image (kali, ubuntu…) alive so you can open a shell in it
        lines += ["    tty: true", "    stdin_open: true"]
    if app.get("user"):
        lines.append(f"    user: {_yaml_str(app['user'])}")
    if app.get("command"):
        lines.append(f"    command: {_yaml_str(app['command'])}")
    if app.get("hostname"):
        lines.append(f"    hostname: {_yaml_str(app['hostname'])}")
    if inst.get("mem_limit"):
        lines.append(f"    mem_limit: {_yaml_str(inst['mem_limit'])}")
    if inst.get("cpus"):
        lines.append(f"    cpus: {_yaml_str(inst['cpus'])}")
    if app.get("devices"):
        lines += ["    devices:"] + [f"      - {_yaml_str(d)}" for d in app["devices"]]
    if app.get("cap_add"):
        lines += ["    cap_add:"] + [f"      - {_yaml_str(c)}" for c in app["cap_add"]]
    if not app.get("host_network"):
        ports = []
        for (cport, proto, kind) in app["ports"]:
            hp = inst["host_ports"].get(f"{cport}/{proto}")
            if not hp:
                continue
            ports.append(f"      - {_yaml_str(f'{port_bind(inst, kind)}:{hp}:{cport}/{proto}')}")
        if ports:
            lines += ["    ports:"] + ports
    vols = []
    for cpath, folder in app["volumes"]:
        if folder.startswith("!"):
            host = folder[1:]
        elif folder.startswith("@"):
            host = inst["folders"].get(folder[1:]) or str(BASE / name / folder[1:])
        else:
            host = str(BASE / name / folder)
        vols.append(f"      - {_yaml_str(f'{host}:{cpath}')}")
    if vols:
        lines += ["    volumes:"] + vols
    if inst["env"]:
        lines += ["    environment:"] + [f"      {k}: {_yaml_str(v)}" for k, v in inst["env"].items()]
    lines += ["    logging:", "      driver: json-file", "      options:", '        max-size: "10m"', '        max-file: "3"',
              "    labels:", f"      aurora.app: {_yaml_str(inst['app'])}", f"      aurora.managed: {_yaml_str(name)}"]
    return "\n".join(lines) + "\n"


def app_def(inst: dict) -> dict:
    """The app definition behind an installed container: a catalog entry, or the spec of a custom container."""
    if inst.get("app") == "custom":
        return inst.get("spec") or {"name": "Custom", "image": inst.get("image", ""), "ports": [], "volumes": [], "env": {}}
    return CATALOG.get(inst["app"], {"name": inst["app"], "image": inst.get("image", ""), "ports": [], "volumes": [], "env": {}})


def catalog() -> dict:
    return {"catalog": [{"id": k, **{x: v.get(x) for x in ("name", "cat", "desc", "ram", "note", "home", "https_only", "no_web", "host_network")},
                      "ports": [{"port": p, "proto": pr, "kind": k2} for p, pr, k2 in v["ports"]],
                      "folders": [f[1:] for _, f in v["volumes"] if f.startswith("@")]} for k, v in CATALOG.items()],
            "installed": installed(), "running": daemon_ok() if installed() else False, "arch": arch(), "lan_ip": _lan_ip(),
            "bind9": shutil.which("named", path=PATH) is not None}


def listing() -> dict:
    d = _state()
    out = []
    ps = {}
    stats = {}
    if installed():
        r = _run(["docker", "ps", "-a", "--format", "{{json .}}"], 30)
        for line in r.stdout.splitlines():
            try:
                c = json.loads(line)
                ps[c["Names"]] = c
            except (ValueError, KeyError):
                pass
        r = _run(["docker", "stats", "--no-stream", "--format", "{{json .}}"], 30)
        for line in r.stdout.splitlines():
            try:
                c = json.loads(line)
                stats[c["Name"]] = c
            except (ValueError, KeyError):
                pass
    for name, inst in d["apps"].items():
        c = ps.get(name, {})
        st = stats.get(name, {})
        app = app_def(inst)
        out.append({"name": name, "app": inst["app"], "custom": inst["app"] == "custom", "title": app.get("name", inst["app"]), "access": inst["access"], "domain": inst.get("domain", ""),
                    "url": _url(inst, app), "state": c.get("State", "missing"), "status": c.get("Status", ""), "image": c.get("Image", inst.get("image") or app.get("image", "")),
                    "cpu": st.get("CPUPerc", ""), "mem": st.get("MemUsage", ""), "created": inst.get("created"), "restart": inst.get("restart", "unless-stopped"),
                    "mem_limit": inst.get("mem_limit", ""), "cpus": inst.get("cpus", ""), "host_network": bool(app.get("host_network")), "tls_port": inst.get("tls_port"),
                    "ports": inst.get("host_ports", {}), "port_kinds": {f"{p}/{pr}": k for p, pr, k in app.get("ports", [])},
                    "env": {k: ("••••••" if k in inst.get("secret_keys", []) else v) for k, v in inst.get("env", {}).items()},
                    "secrets": sorted(k for k, v in inst.get("env", {}).items() if k in inst.get("secret_keys", [])),
                    "note": app.get("note", "")})
    return {"apps": sorted(out, key=lambda a: a["name"]), "installed": installed(), "running": daemon_ok() if installed() else False,
            "disk": _disk_usage() if installed() else None}


def _disk_usage() -> dict:
    r = _run(["docker", "system", "df", "--format", "{{json .}}"], 60)
    out = {}
    for line in r.stdout.splitlines():
        try:
            x = json.loads(line)
            out[x["Type"]] = {"size": x.get("Size"), "reclaimable": x.get("Reclaimable")}
        except (ValueError, KeyError):
            pass
    return out


def _url(inst: dict, app: dict) -> str:
    if app.get("no_web"):
        return ""
    path = inst.get("path") or app.get("path") or "/"
    if inst["access"] == "proxy" and inst.get("domain"):
        return f"https://{inst['domain']}{path}"
    web = next((f"{p}/{pr}" for p, pr, k in app.get("ports", []) if k == "web"), None)
    if app.get("host_network"):
        port = next((p for p, pr, k in app["ports"] if k == "web"), None)
        return f"http://{inst.get('lan_ip') or '{host}'}:{port}{path}"
    hp = inst.get("host_ports", {}).get(web) if web else None
    if not hp:
        return ""
    host = inst.get("lan_ip") if inst["access"] == "lan" else "{host}"
    if inst.get("tls_port"):
        return f"https://{host}:{inst['tls_port']}{path}"
    return f"http://{host}:{hp}{path}"


def image_user(image: str) -> str:
    """"uid:gid" the image runs as (Config.User, names resolved inside the image), or "" for root/unknown."""
    r = _run(["docker", "image", "inspect", "--format", "{{.Config.User}}", image], 30)
    user = (r.stdout or "").strip()
    if r.returncode != 0 or not user or user in ("0", "root", "0:0"):
        return ""
    if parse_uid(user):
        return user
    r = _run(["docker", "run", "--rm", "--entrypoint", "", image, "sh", "-c", "echo $(id -u):$(id -g)"], 90)
    out = (r.stdout or "").strip().splitlines()
    return out[-1] if r.returncode == 0 and out and parse_uid(out[-1]) else ""


def _lan_net() -> str:
    """The local network in CIDR form (for firewall rules), e.g. 192.168.0.0/24."""
    ip = _lan_ip()
    if not ip:
        return ""
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == ip and a.netmask:
                    return str(ipaddress.ip_network(f"{ip}/{a.netmask}", strict=False))
    except Exception:
        pass
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def wait_started(name: str, log, web_bind: str = "", web_port: int = 0, seconds: int = 60, path: str = "/") -> int | None:
    """After `up -d`: make sure the container keeps running (no crash loop) and, if it has a web port, that it answers.
    A crash shows the last log lines instead of a silent "running" that dies a second later.
    Returns the HTTP status of the app's page (None when there was no web port or no answer)."""
    deadline = time.time() + seconds
    ok_since = None
    while time.time() < deadline:
        r = _run(["docker", "inspect", "--format", "{{.State.Status}} {{.State.Restarting}} {{.RestartCount}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", name], 20)
        parts = (r.stdout or "").split()
        status = parts[0] if parts else "missing"
        restarting = len(parts) > 1 and parts[1] == "true"
        restarts = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        health = parts[3] if len(parts) > 3 else ""
        if status in ("exited", "dead") or restarting or restarts > 0:
            tail = _run(["docker", "logs", "--tail", "25", name], 30)
            log("── last log lines ──")
            log(((tail.stdout or "") + (tail.stderr or "")).strip()[-2500:] or "(no output)")
            raise DockerError("The container crashed right after starting — see its last log lines above")
        if status == "running" and health in ("", "healthy"):
            if web_port:
                code = _http_status(web_bind, web_port, path or "/")
                if code is not None:
                    log(f"• Answering on port {web_port}" + (f" (HTTP {code} for {path or '/'})" if code >= 400 else ""))
                    return code
            else:
                ok_since = ok_since or time.time()
                if time.time() - ok_since > 8:
                    return None
        time.sleep(2)
    if web_port:
        log(f"• Still starting after {seconds} s (no answer on port {web_port} yet) — large apps can take a few minutes on a Pi")
    return None


TLS_PAIRS = [("/etc/ssl/certs/ssl-cert-snakeoil.pem", "/etc/ssl/private/ssl-cert-snakeoil.key")]


def _tls_pair(name: str) -> tuple[str, str]:
    for crt, key in TLS_PAIRS:
        if Path(crt).is_file() and Path(key).is_file():
            return crt, key
    try:
        from . import panelhttps
        if panelhttps.SELF_CRT.is_file() and panelhttps.SELF_KEY.is_file():
            return str(panelhttps.SELF_CRT), str(panelhttps.SELF_KEY)
    except Exception:
        pass
    d = BASE / name / "tls"
    d.mkdir(parents=True, exist_ok=True)
    crt, key = d / "cert.pem", d / "key.pem"
    if not crt.is_file():
        _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650", "-subj", f"/CN={socket.gethostname()}",
              "-addext", f"subjectAltName=IP:{_lan_ip() or '127.0.0.1'},DNS:{socket.gethostname()}", "-keyout", str(key), "-out", str(crt)], 120)
        os.chmod(key, 0o600)
    return str(crt), str(key)


def _ufw(args: list[str]) -> None:
    if shutil.which("ufw", path=PATH) and "active" in (_run(["ufw", "status"], 20).stdout or ""):
        _run(["ufw"] + args, 60)


def tls_front(name: str, inst: dict, web_host_port: int) -> int:
    """HTTPS on the local network for apps that refuse plain http (password managers, PWAs): an Apache vhost on its own
    port with this server's self-signed certificate, forwarding to the container. Returns the HTTPS port."""
    port = inst.get("tls_port") or _free_port(web_host_port + 363 if web_host_port + 363 < 65000 else 10443)
    bind = inst.get("lan_ip") if inst["access"] == "lan" else ""
    crt, key = _tls_pair(name)
    _run(["a2enmod", "-q", "ssl", "proxy", "proxy_http", "proxy_wstunnel", "headers"], 120)
    conf = "\n".join([
        f"# Written by AuroraPanel (Docker → {name}): HTTPS front for an app that refuses plain http. Edit in the panel.",
        f"Listen {bind + ':' if bind else ''}{port} https",
        f"<VirtualHost *:{port}>",
        "    SSLEngine on",
        f"    SSLCertificateFile {crt}",
        f"    SSLCertificateKeyFile {key}",
        "    ProxyPreserveHost On",
        f"    ProxyPass / http://127.0.0.1:{web_host_port}/ upgrade=websocket timeout=3600",
        f"    ProxyPassReverse / http://127.0.0.1:{web_host_port}/",
        '    RequestHeader set X-Forwarded-Proto "https"',
        f"    ErrorLog ${{APACHE_LOG_DIR}}/docker-{name}-error.log",
        f"    CustomLog ${{APACHE_LOG_DIR}}/docker-{name}-access.log combined",
        "</VirtualHost>", ""])
    cf = Path(f"/etc/apache2/sites-available/aurora-docker-{name}.conf")
    cf.write_text(conf)
    _run(["a2ensite", "-q", cf.name], 60)
    r = _run(["apache2ctl", "configtest"], 60)
    if r.returncode != 0:
        _run(["a2dissite", "-q", cf.name], 60)
        raise DockerError("Apache refused the HTTPS front: " + (r.stderr or r.stdout).strip()[-300:])
    _run(["systemctl", "reload", "apache2"], 60)
    net = _lan_net()
    _ufw(["allow", "proto", "tcp"] + (["from", net] if bind and net else []) + ["to", "any", "port", str(port), "comment", f"AuroraPanel docker {name}"])
    inst["tls_port"] = port
    return port


def tls_front_remove(name: str, inst: dict) -> None:
    port = inst.pop("tls_port", None)
    cf = Path(f"/etc/apache2/sites-available/aurora-docker-{name}.conf")
    if cf.exists():
        _run(["a2dissite", "-q", cf.name], 60)
        cf.unlink(missing_ok=True)
        _run(["systemctl", "reload", "apache2"], 60)
    if port:
        net = _lan_net()
        _ufw(["delete", "allow", "proto", "tcp"] + (["from", net] if inst.get("access") == "lan" and net else []) + ["to", "any", "port", str(port)])


def needs_tls_front(app: dict, inst: dict) -> bool:
    return bool(app.get("https_only")) and inst["access"] in ("lan", "public") and not app.get("host_network") \
        and any(k == "web" for _, _, k in app.get("ports", []))


def _proxy_site(name: str, domain: str, port: int) -> None:
    """A managed Apache site that forwards domain → 127.0.0.1:port (HTTPS via AutoSSL, WAF + bans apply)."""
    from . import sites
    _run(["a2enmod", "-q", "proxy", "proxy_http", "proxy_wstunnel", "headers"])
    custom = "\n".join([
        "ProxyPreserveHost On",
        "ProxyPass /.well-known/acme-challenge/ !",
        f"ProxyPass / http://127.0.0.1:{port}/ upgrade=websocket timeout=3600",
        f"ProxyPassReverse / http://127.0.0.1:{port}/",
        'RequestHeader set X-Forwarded-Proto "expr=%{REQUEST_SCHEME}"',
        f"# aurora-docker-app {name}",
    ])
    settings = {"server_name": domain, "docroot": str(Path("/var/www") / f"app-{name}"), "ssl": "selfsigned", "force_https": False,
                "custom": custom, "security_headers": False, "gzip": False}
    Path(settings["docroot"]).mkdir(parents=True, exist_ok=True)
    try:
        sites.get_site(domain)
        cur = sites.get_site(domain)["settings"]
        if f"# aurora-docker-app {name}" not in (cur.get("custom") or ""):
            raise DockerError(f"{domain} is already used by another website — pick another name")
        cur.update(custom=custom)
        sites.save_site(domain, {k: v for k, v in cur.items() if not k.startswith("_")})
    except sites.SiteError:
        sites.create_site(settings)


def install(app_id: str, name: str = "", access: str = "proxy", domain: str = "", folders: dict | None = None) -> jobs.Job:
    if app_id not in CATALOG:
        raise DockerError("Unknown app")
    if not installed():
        raise DockerError("Install Docker first")
    app = CATALOG[app_id]
    name = (name or app_id).strip().lower()
    if not _NAME.match(name):
        raise DockerError("Name: lowercase letters, digits and dashes, starting with a letter")
    d = _state()
    if name in d["apps"]:
        raise DockerError(f"An app called {name} already exists")
    if access not in ("proxy", "lan", "public"):
        raise DockerError("Unknown access mode")
    lan = _lan_ip()
    if access == "lan" and not lan:
        raise DockerError("This server has no private network address — use a web address instead")
    if access == "proxy" and not app.get("no_web") and not app.get("host_network"):
        domain = (domain or "").strip().lower().rstrip(".")
        if not re.match(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", domain):
            raise DockerError("Enter the web address for the app, e.g. jellyfin.example.com (its DNS must point here)")
    else:
        domain = ""
    if app.get("host_network") and access == "proxy":
        access = "lan" if lan else "public"
    # ports: DNS apps need the real port 53; everything else gets a free host port
    host_ports = {}
    for cport, proto, kind in app["ports"]:
        key = f"{cport}/{proto}"
        if kind == "dns":
            if not _port_free(53, proto, lan or "0.0.0.0"):
                raise DockerError(f"Port 53/{proto} is in use on {lan or 'this server'} (its own DNS server?) — Pi-hole/AdGuard need it")
            host_ports[key] = 53
        elif app.get("host_network"):
            host_ports[key] = cport
        else:
            same = next((v for k, v in host_ports.items() if k.split("/")[0] == str(cport)), None)
            host_ports[key] = same or _free_port(cport if cport >= 1024 else 10000 + cport)
    env, secret_keys = {}, []
    for k, v in app["env"].items():
        if v == "{secret}":
            env[k] = secrets.token_urlsafe(18)
            secret_keys.append(k)
        elif v == "{tz}":
            env[k] = _tz()
        elif v == "{secure}":
            env[k] = "true" if access == "proxy" else "false"
        else:
            env[k] = v
    folders_out = {}
    for _, f in app["volumes"]:
        if f.startswith("@"):
            key = f[1:]
            p = (folders or {}).get(key) or str(BASE / name / key)
            p = str(Path(p).resolve())
            if not p.startswith("/") or p in ("/", "/etc", "/root", "/usr", "/var", "/boot", "/proc", "/sys", "/dev"):
                raise DockerError(f"Choose a proper folder for {key}")
            folders_out[key] = p
    inst = {"app": app_id, "access": access, "domain": domain, "lan_ip": lan, "host_ports": host_ports, "env": env, "secret_keys": secret_keys,
            "folders": folders_out, "created": int(time.time()), "image": app["image"]}

    def fn(log):
        work = BASE / name
        work.mkdir(parents=True, exist_ok=True)
        os.chmod(work, 0o700)
        own = []
        for _, f in app["volumes"]:
            if not f.startswith("!"):
                p = Path(folders_out.get(f[1:]) if f.startswith("@") else work / f)
                p.mkdir(parents=True, exist_ok=True)
                if not f.startswith("@"):
                    own.append(p)
        for rel, text in (app.get("files") or {}).items():
            fp = work / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            if not fp.exists():
                fp.write_text(text)
        own_data(app, own)
        (work / "docker-compose.yml").write_text(render_compose(name, app, inst))
        os.chmod(work / "docker-compose.yml", 0o600)
        cc = compose_cmd()
        log.progress(5, f"Downloading {app['name']} ({app['image']})")
        log(f"• Downloading {app['image']} for {arch()} — the first time can take a few minutes on a Pi")
        p = subprocess.Popen(cc + ["pull"], cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=_env())
        pct = 5.0
        for line in p.stdout:
            line = line.rstrip()
            if line:
                log(line[-200:])
                if "Pull complete" in line or "Download complete" in line:
                    pct = min(80.0, pct + 4)
                    log.progress(pct, "Downloading")
        if p.wait() != 0:
            raise DockerError("Couldn't download the image — see the log (no internet, or no build for this processor?)")
        if not app.get("uid"):  # images that run as a non-root user can't write a folder root made
            u = image_user(app["image"])
            if u:
                log(f"• The image runs as user {u} — giving it its data folders")
                own_data({"uid": u}, own)
        hook = SETUP_HOOKS.get(app.get("setup"))
        if hook:
            log.progress(78, "Setting it up")
            hook(work, inst, app, log)
        web = next((f"{c}/{pr}" for c, pr, k in app["ports"] if k == "web"), None)
        if needs_tls_front(app, inst) and web:
            log.progress(80, "Adding HTTPS")
            tls_front(name, inst, host_ports[web])
            (work / "docker-compose.yml").write_text(render_compose(name, app, inst))
            log(f"• {app['name']} refuses plain http, so the panel serves it over HTTPS on port {inst['tls_port']} (self-signed certificate — your browser asks once to trust it)")
        log.progress(82, "Starting")
        r = _run(cc + ["up", "-d"], 600, cwd=work)
        log((r.stdout + r.stderr).strip()[-1500:])
        if r.returncode != 0:
            raise DockerError("The app didn't start — see the log")
        st = _state()
        st["apps"][name] = inst
        _save(st)
        log.progress(86, "Checking it runs")
        wport = host_ports.get(web, 0) if web and not app.get("host_network") else 0
        code = wait_started(name, log, port_bind(inst, "web") if web else "", wport, path=app.get("path") or "/")
        _settle_page(name, inst, app, code, wport, log)
        if domain and web:
            log.progress(90, f"Creating the web address {domain}")
            _proxy_site(name, domain, host_ports[web])
            log(f"• https://{domain}/ → the app (HTTPS: AutoSSL gets a trusted certificate once {domain} points to this server)")
        log.progress(100, f"{app['name']} is running")
        log(f"✓ {app['name']} is running")
        try:
            from . import audit
            audit.record("system", "", f"docker app installed ({name}: {app_id})")
        except Exception:
            pass
        return {"ok": True, "name": name}

    return jobs.launch_fn(f"install {app['name']}", fn, meta={"docker": name})


def _inst(name: str) -> dict:
    d = _state()
    if name not in d["apps"]:
        raise DockerError("Unknown app")
    return d["apps"][name]


def control(name: str, action: str) -> dict:
    _inst(name)
    if action not in ("start", "stop", "restart"):
        raise DockerError("Unknown action")
    r = _run(compose_cmd() + [action], 300, cwd=BASE / name)
    if r.returncode != 0:
        raise DockerError((r.stderr or r.stdout).strip()[-400:] or f"{action} failed")
    return {"ok": True}


def logs(name: str, lines: int = 300) -> dict:
    _inst(name)
    r = _run(compose_cmd() + ["logs", "--no-color", "--tail", str(max(10, min(3000, int(lines))))], 60, cwd=BASE / name)
    return {"text": (r.stdout + r.stderr)[-200000:]}


def update(name: str) -> jobs.Job:
    inst = _inst(name)

    def fn(log):
        cc = compose_cmd()
        log.progress(5, "Checking for a newer version")
        r = _run(cc + ["pull"], 1800, cwd=BASE / name)
        log((r.stdout + r.stderr).strip()[-2000:])
        if r.returncode != 0:
            raise DockerError("Download failed")
        log.progress(80, "Restarting with the new version")
        r = _run(cc + ["up", "-d"], 600, cwd=BASE / name)
        log((r.stdout + r.stderr).strip()[-1500:])
        if r.returncode != 0:
            raise DockerError("Restart failed")
        _run(["docker", "image", "prune", "-f"], 300)
        log.progress(100, "Up to date")
        log("✓ Updated (old images removed)")
        return {"ok": True}
    return jobs.launch_fn(f"update {name}", fn, meta={"docker": name})


def remove(name: str, delete_data: bool = False) -> dict:
    inst = _inst(name)
    cc = compose_cmd()
    r = _run(cc + ["down"], 300, cwd=BASE / name)
    if r.returncode != 0 and "no such" not in (r.stderr or "").lower():
        raise DockerError((r.stderr or r.stdout).strip()[-300:])
    if inst.get("domain"):
        try:
            from . import sites
            sites.remove_site(inst["domain"])
        except Exception:
            pass
    if inst.get("tls_port"):
        try:
            tls_front_remove(name, inst)
        except Exception:
            pass
    if delete_data:
        shutil.rmtree(BASE / name, ignore_errors=True)
    d = _state()
    d["apps"].pop(name, None)
    _save(d)
    return {"ok": True}


def setup_mosquitto(work: "Path", inst: dict, app: dict, log) -> None:
    """Mosquitto 2 refuses to start when its config names a password_file that can't be opened, and you can't
    docker-exec into a container that never stays up — so the login has to exist before the first start. Make
    one with the image's own mosquitto_passwd; if that fails, fall back to an open broker so it at least runs."""
    cfg = work / "config"
    pwfile = cfg / "passwd"
    if pwfile.exists():  # a re-install / manual setup already has one
        return
    cfg.mkdir(parents=True, exist_ok=True)
    user, pw = "aurora", secrets.token_urlsafe(15)
    r = _run(["docker", "run", "--rm", "--entrypoint", "mosquitto_passwd", "-v", f"{cfg}:/mosquitto/config",
              app["image"], "-b", "-c", "/mosquitto/config/passwd", user, pw], 90)
    if r.returncode == 0 and pwfile.exists():
        inst["env"]["MQTT_USERNAME"] = user
        inst["env"]["MQTT_PASSWORD"] = pw
        if "MQTT_PASSWORD" not in inst.get("secret_keys", []):
            inst.setdefault("secret_keys", []).append("MQTT_PASSWORD")
        own_data(app, [cfg])  # mosquitto_passwd wrote it as root; hand it back to the mosquitto user
        log(f"• Created an MQTT login — user “{user}”, password under “Generated passwords”")
    else:  # never leave it crash-looping: run open on the local network, tell the user how to lock it down
        (cfg / "mosquitto.conf").write_text("listener 1883\nallow_anonymous true\npersistence true\npersistence_location /mosquitto/data/\n")
        own_data(app, [cfg])
        log("• Couldn't create a login automatically — started open on the local network. Add one with mosquitto_passwd, then set allow_anonymous false and Restart.")


SETUP_HOOKS = {"mosquitto": setup_mosquitto}


def secret(name: str, key: str) -> dict:
    inst = _inst(name)
    if key not in inst.get("secret_keys", []):
        raise DockerError("Unknown secret")
    return {"key": key, "value": inst["env"][key]}


def prune() -> dict:
    r = _run(["docker", "system", "prune", "-f"], 600)
    m = re.search(r"Total reclaimed space:\s*(.+)", r.stdout)
    return {"ok": r.returncode == 0, "reclaimed": m.group(1).strip() if m else "0B"}


# --------------------------------------------------------------------------- #
# Every container on this machine (panel apps, custom containers, and ones made elsewhere)
# --------------------------------------------------------------------------- #
_CID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_USER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]{1,128})?(?:@sha256:[a-f0-9]{64})?$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PROTECTED_PATHS = ("/", "/etc", "/root", "/usr", "/var", "/boot", "/proc", "/sys", "/dev", "/bin", "/sbin", "/lib")


def _cid(ref: str) -> str:
    ref = (ref or "").strip()
    if not _CID.match(ref):
        raise DockerError("Unknown container")
    return ref


def _docker(argv, timeout=120):
    r = _run(["docker"] + argv, timeout)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip()
        raise DockerError(msg.splitlines()[-1][-400:] if msg else "docker failed")
    return r


def overview() -> dict:
    """Counts + versions for the page header."""
    if not installed():
        return {"installed": False, "running": False}
    if not daemon_ok():
        return {"installed": True, "running": False}
    try:
        info = json.loads(_run(["docker", "info", "--format", "{{json .}}"], 30).stdout or "{}")
    except ValueError:
        info = {}
    imgs = _run(["docker", "image", "ls", "-q"], 30).stdout.split()
    vols = _run(["docker", "volume", "ls", "-q"], 30).stdout.split()
    return {"installed": True, "running": True, "version": info.get("ServerVersion", ""), "containers": info.get("Containers", 0),
            "containers_running": info.get("ContainersRunning", 0), "containers_paused": info.get("ContainersPaused", 0),
            "containers_stopped": info.get("ContainersStopped", 0), "images": len(set(imgs)), "volumes": len(vols),
            "root": info.get("DockerRootDir", ""), "disk": _disk_usage(), "mem_cgroup": mem_cgroup()}


def _parse_ps_ports(text: str) -> list[dict]:
    out, seen = [], set()
    for m in re.finditer(r"(?:(\S+):)?(\d+)->(\d+)/(tcp|udp|sctp)", text or ""):
        k = (int(m.group(2)), int(m.group(3)), m.group(4))
        if k not in seen:  # docker lists 0.0.0.0 and :: separately
            seen.add(k)
            out.append({"host": k[0], "container": k[1], "proto": k[2], "bind": m.group(1) or ""})
    return out


def containers() -> dict:
    """All containers, with what the panel knows about the ones it created."""
    if not installed() or not daemon_ok():
        return {"containers": []}
    st = _state()["apps"]
    stats = {}
    for line in _run(["docker", "stats", "--no-stream", "--format", "{{json .}}"], 30).stdout.splitlines():
        try:
            c = json.loads(line)
            stats[c["Name"]] = c
        except (ValueError, KeyError):
            pass
    out = []
    for line in _run(["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"], 30).stdout.splitlines():
        try:
            c = json.loads(line)
        except ValueError:
            continue
        name = c.get("Names", "").split(",")[0]
        inst = st.get(name)
        app = app_def(inst) if inst else {}
        s = stats.get(name, {})
        labels = dict(kv.split("=", 1) for kv in c.get("Labels", "").split(",") if "=" in kv)
        origin = "app" if inst and inst["app"] != "custom" else "custom" if inst else "compose" if labels.get("com.docker.compose.project") else "external"
        out.append({"id": c.get("ID", "")[:12], "name": name, "image": c.get("Image", ""), "state": c.get("State", ""), "status": c.get("Status", ""),
                    "created": c.get("CreatedAt", ""), "command": c.get("Command", ""), "ports": _parse_ps_ports(c.get("Ports", "")), "origin": origin,
                    "title": app.get("name") if inst else name, "app": inst["app"] if inst else "", "url": _url(inst, app) if inst else "",
                    "cpu": s.get("CPUPerc", ""), "mem": s.get("MemUsage", ""), "mem_pct": s.get("MemPerc", ""), "net": s.get("NetIO", ""),
                    "project": labels.get("com.docker.compose.project", ""), "managed": bool(inst), "secrets": sorted(inst.get("secret_keys", [])) if inst else [],
                    "tls_port": inst.get("tls_port") if inst else None})
    order = {"running": 0, "paused": 1, "restarting": 2, "created": 3, "exited": 4, "dead": 5}
    out.sort(key=lambda x: (order.get(x["state"], 9), x["name"]))
    return {"containers": out}


def inspect(ref: str) -> dict:
    ref = _cid(ref)
    try:
        c = json.loads(_docker(["inspect", "--type", "container", ref], 30).stdout)[0]
    except (ValueError, IndexError):
        raise DockerError("Unknown container")
    cfg, host, net, state = c.get("Config", {}), c.get("HostConfig", {}), c.get("NetworkSettings", {}), c.get("State", {})
    ports = []
    for key, binds in (net.get("Ports") or {}).items():
        cport, proto = key.split("/")
        seen = set()
        for b in binds or []:
            hp = b.get("HostPort")
            if hp and hp not in seen:
                seen.add(hp)
                ports.append({"container": int(cport), "proto": proto, "host": int(hp), "bind": b.get("HostIp", "") or "0.0.0.0"})
        if not binds:
            ports.append({"container": int(cport), "proto": proto, "host": None, "bind": ""})
    mounts = [{"type": m.get("Type"), "source": m.get("Source") or m.get("Name", ""), "dest": m.get("Destination"), "rw": m.get("RW", True)} for m in c.get("Mounts", [])]
    nets = {k: {"ip": v.get("IPAddress", ""), "gateway": v.get("Gateway", "")} for k, v in (net.get("Networks") or {}).items()}
    name = c.get("Name", "").lstrip("/")
    inst = _state()["apps"].get(name)
    secret_keys = set(inst.get("secret_keys", [])) if inst else set()
    env = []
    if inst:  # the panel's own settings, not the image's built-in variables (PATH, versions…)
        for k, v in inst.get("env", {}).items():
            env.append({"key": k, "value": "••••••" if k in secret_keys else v, "secret": k in secret_keys})
    else:
        for kv in cfg.get("Env") or []:
            k, _, v = kv.partition("=")
            env.append({"key": k, "value": v, "secret": False})
    app = app_def(inst) if inst else {}
    return {"id": c.get("Id", "")[:12], "name": name, "image": cfg.get("Image", ""), "image_id": c.get("Image", "")[:19], "created": c.get("Created", ""),
            "state": state.get("Status", ""), "running": bool(state.get("Running")), "paused": bool(state.get("Paused")), "pid": state.get("Pid"),
            "started": state.get("StartedAt", ""), "exit_code": state.get("ExitCode"), "error": state.get("Error", ""), "health": (state.get("Health") or {}).get("Status", ""),
            "cmd": " ".join(cfg.get("Cmd") or []), "entrypoint": " ".join(cfg.get("Entrypoint") or []), "user": cfg.get("User", ""), "workdir": cfg.get("WorkingDir", ""),
            "hostname": cfg.get("Hostname", ""), "env": env, "ports": ports, "mounts": mounts, "networks": nets, "network_mode": host.get("NetworkMode", ""),
            "restart": (host.get("RestartPolicy") or {}).get("Name", "no") or "no", "privileged": bool(host.get("Privileged")),
            "memory": host.get("Memory", 0), "cpus": (host.get("NanoCpus") or 0) / 1e9, "labels": cfg.get("Labels") or {},
            "log_path": c.get("LogPath", ""), "managed": bool(inst), "app": inst["app"] if inst else "", "custom": bool(inst and inst["app"] == "custom"),
            "access": inst.get("access", "") if inst else "", "domain": inst.get("domain", "") if inst else "", "lan_ip": _lan_ip(),
            "port_kinds": {f"{p}/{pr}": k for p, pr, k in app.get("ports", [])}, "title": app.get("name", name), "path": (inst.get("path") if inst else "") or app.get("path", ""), "tty": bool(app.get("tty"))}


def container_action(ref: str, action: str) -> dict:
    ref = _cid(ref)
    if action not in ("start", "stop", "restart", "pause", "unpause", "kill"):
        raise DockerError("Unknown action")
    if ref in _state()["apps"] and action in ("start", "stop", "restart") and (BASE / ref / "docker-compose.yml").exists():
        return control(ref, action)  # keep compose in the loop for the panel's own apps
    _docker([action, ref], 300)
    try:
        from . import audit
        audit.record("system", "", f"docker container {action} ({ref})")
    except Exception:
        pass
    return {"ok": True}


def container_remove(ref: str, delete_data: bool = False) -> dict:
    ref = _cid(ref)
    if ref in _state()["apps"]:
        return remove(ref, delete_data)
    _docker(["rm", "-f"] + (["-v"] if delete_data else []) + [ref], 300)
    return {"ok": True}


def container_logs(ref: str, lines: int = 300) -> dict:
    ref = _cid(ref)
    r = _run(["docker", "logs", "--tail", str(max(10, min(5000, int(lines)))), "--timestamps", ref], 60)
    if r.returncode != 0:
        raise DockerError((r.stderr or "").strip()[-300:] or "No logs")
    return {"text": (r.stdout + r.stderr)[-300000:]}


def container_top(ref: str) -> dict:
    ref = _cid(ref)
    r = _run(["docker", "top", ref, "-eo", "pid,user,pcpu,pmem,etime,args"], 30)
    if r.returncode != 0:
        raise DockerError((r.stderr or "").strip()[-300:] or "Not running")
    return {"text": r.stdout[-50000:]}


def exec_cmd(ref: str, cmd: str, user: str = "", workdir: str = "", timeout: int = 60) -> dict:
    """Run one command inside a container (as root unless a user is given) and return its output."""
    ref = _cid(ref)
    cmd = (cmd or "").strip()
    if not cmd:
        raise DockerError("Enter a command")
    if user and not _USER.match(user):
        raise DockerError("Bad user")
    argv = ["docker", "exec"] + (["-u", user] if user else []) + (["-w", workdir] if workdir and workdir.startswith("/") else [])
    r = _run(argv + [ref, "sh", "-c", cmd], max(5, min(600, int(timeout))))
    return {"code": r.returncode, "output": (r.stdout + r.stderr)[-200000:]}


def shell_argv(ref: str, user: str = "") -> list[str]:
    """The interactive shell (bash if the image has it, else sh) the Terminal attaches to."""
    ref = _cid(ref)
    if user and not _USER.match(user):
        raise DockerError("Bad user")
    return ["docker", "exec", "-it"] + (["-u", user] if user else []) + ["-e", "TERM=xterm-256color", ref, "sh", "-c",
            "command -v bash >/dev/null 2>&1 && exec bash || exec sh"]


# ---- settings (ports, environment, restart policy, limits) -------------------------------------------------
def _parse_ports(ports) -> list[dict]:
    out, seen = [], set()
    for p in ports or []:
        try:
            cport, hport = int(p.get("container")), int(p.get("host") or 0)
        except (TypeError, ValueError, AttributeError):
            raise DockerError("Ports must be numbers")
        proto = (p.get("proto") or "tcp").lower()
        if proto not in ("tcp", "udp"):
            raise DockerError("Protocol must be tcp or udp")
        if not 1 <= cport <= 65535 or not 0 <= hport <= 65535:
            raise DockerError("Ports are 1–65535")
        bind = (p.get("bind") or "").strip()
        if bind:
            try:
                ipaddress.ip_address(bind)
            except ValueError:
                raise DockerError(f"Bad listen address {bind[:40]}")
        key = (hport, proto)
        if hport and key in seen:
            raise DockerError(f"Host port {hport}/{proto} is listed twice")
        seen.add(key)
        out.append({"container": cport, "host": hport, "proto": proto, "bind": bind, "kind": (p.get("kind") or "").strip()[:12] or "tcp"})
    return out


def _parse_env(env) -> dict:
    out = {}
    for item in env or []:
        if isinstance(item, dict):
            k, v = str(item.get("key", "")).strip(), str(item.get("value", ""))
        else:
            k, _, v = str(item).partition("=")
            k = k.strip()
        if not k:
            continue
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$", k):
            raise DockerError(f"Bad variable name {k[:40]}")
        if "\n" in v or len(v) > 4000:
            raise DockerError(f"Bad value for {k}")
        out[k] = v
    return out


def _parse_limits(mem, cpus) -> tuple[str, str]:
    mem = str(mem or "").strip().lower()
    if mem and not re.match(r"^\d+(\.\d+)?[kmg]?b?$", mem):
        raise DockerError("Memory limit looks like 512m or 2g")
    mem = mem.rstrip("b") if mem else ""
    c = ""
    if cpus not in (None, "", 0, "0"):
        try:
            f = float(cpus)
        except (TypeError, ValueError):
            raise DockerError("CPUs is a number like 1 or 0.5")
        if not 0.05 <= f <= 64:
            raise DockerError("CPUs between 0.05 and 64")
        c = f"{f:g}"
    return mem, c


def _check_host_ports(ports: list[dict], ignore: set, inst: dict | None = None) -> None:
    """Every requested host port must be free on the address it will listen on (see port_bind)."""
    for p in ports:
        host = p.get("bind") or (port_bind(inst, p.get("kind", "")) if inst else "0.0.0.0")
        if p["host"] and (p["host"], p["proto"]) not in ignore and not _port_free(p["host"], p["proto"], host):
            where = "" if host in ("", "0.0.0.0") else f" on {host}"
            raise DockerError(f"Host port {p['host']}/{p['proto']} is already in use{where}")


def _compose_up(name: str, app: dict, inst: dict, log) -> None:
    work = BASE / name
    work.mkdir(parents=True, exist_ok=True)
    (work / "docker-compose.yml").write_text(render_compose(name, app, inst))
    os.chmod(work / "docker-compose.yml", 0o600)
    r = _run(compose_cmd() + ["up", "-d", "--remove-orphans"], 600, cwd=work)
    log((r.stdout + r.stderr).strip()[-1500:])
    if r.returncode != 0:
        raise DockerError("The container didn't come back — see the log")


def update_settings(name: str, data: dict) -> jobs.Job:
    """Change a panel-managed container (catalog app or custom): ports, environment, restart policy, limits, access. Re-creates it."""
    inst = _inst(name)
    app = app_def(inst)
    restart = data.get("restart") or inst.get("restart", "unless-stopped")
    if restart not in RESTART_POLICIES:
        raise DockerError("Unknown restart policy")
    mem, cpus = _parse_limits(data.get("mem_limit", inst.get("mem_limit", "")), data.get("cpus", inst.get("cpus", "")))
    access = data.get("access") or inst["access"]
    if access not in ("proxy", "lan", "public"):
        raise DockerError("Unknown access mode")
    inst["lan_ip"] = _lan_ip() or inst.get("lan_ip", "")
    if access == "lan" and not inst["lan_ip"]:
        raise DockerError("This server has no private network address")
    domain = inst.get("domain", "")
    if access == "proxy":
        domain = (data.get("domain") or domain or "").strip().lower().rstrip(".")
        if not any(k == "web" for _, _, k in app.get("ports", [])):
            raise DockerError("This container has no web port — reach it on the local network or a public port instead")
        if not _DOMAIN.match(domain):
            raise DockerError("Enter the web address, e.g. app.example.com (its DNS must point here)")
    if data.get("path") is not None and inst["app"] == "custom":
        inst["spec"]["path"] = inst["path"] = _page_path(data["path"])
    if data.get("keep_alive") is not None and inst["app"] == "custom":
        inst["spec"]["tty"] = bool(data["keep_alive"])
    if data.get("env") is not None:  # secrets keep their stored value unless a new one is typed
        env = _parse_env(data["env"])
        for k in inst.get("secret_keys", []):
            if env.get(k) in ("••••••", "") and k in inst["env"]:
                env[k] = inst["env"][k]
        inst["env"] = env
        if inst["app"] == "custom":
            inst["spec"]["env"] = dict(env)
    if data.get("ports") is not None and not app.get("host_network"):
        ports = _parse_ports(data["ports"])
        old = {(hp, k.split("/")[1]) for k, hp in inst["host_ports"].items()}
        _check_host_ports(ports, old, {**inst, "access": access})
        if inst["app"] == "custom":
            inst["spec"]["ports"] = [(p["container"], p["proto"], p["kind"]) for p in ports]
            inst["host_ports"] = {f"{p['container']}/{p['proto']}": p["host"] for p in ports if p["host"]}
            inst["spec"]["no_web"] = not any(p["kind"] == "web" for p in ports)
            app = app_def(inst)
        else:  # catalog app: the container side is fixed, only the host port can change
            for p in ports:
                key = f"{p['container']}/{p['proto']}"
                if key not in inst["host_ports"]:
                    raise DockerError(f"{app.get('name')} has no port {key}")
                if not p["host"]:
                    raise DockerError("Every port of a catalog app needs a host port")
                inst["host_ports"][key] = p["host"]
    old_domain = inst.get("domain", "")
    inst.update(restart=restart, mem_limit=mem, cpus=cpus, access=access, domain=domain if access == "proxy" else "")

    def fn(log):
        web = next((f"{c}/{pr}" for c, pr, k in app.get("ports", []) if k == "web"), None)
        if needs_tls_front(app, inst) and web and inst["host_ports"].get(web):
            log.progress(10, "HTTPS front")
            tls_front(name, inst, inst["host_ports"][web])
            log(f"• HTTPS on port {inst['tls_port']} → the app")
        elif inst.get("tls_port"):
            tls_front_remove(name, inst)
        log.progress(20, "Re-creating the container with the new settings")
        _compose_up(name, app, inst, log)
        st = _state()
        st["apps"][name] = inst
        _save(st)
        wait_started(name, log, port_bind(inst, "web") if web else "", inst["host_ports"].get(web, 0) if web and not app.get("host_network") else 0, path=app.get("path") or "/")
        if inst["domain"]:
            web = next((f"{c}/{pr}" for c, pr, k in app.get("ports", []) if k == "web"), None)
            if web and inst["host_ports"].get(web):
                log.progress(80, f"Web address {inst['domain']}")
                _proxy_site(name, inst["domain"], inst["host_ports"][web])
        if old_domain and old_domain != inst["domain"]:
            try:
                from . import sites
                sites.remove_site(old_domain)
            except Exception:
                pass
        log.progress(100, "Settings applied")
        log("✓ Settings applied")
        try:
            from . import audit
            audit.record("system", "", f"docker container settings changed ({name})")
        except Exception:
            pass
        return {"ok": True}
    return jobs.launch_fn(f"reconfigure {name}", fn, meta={"docker": name})


def recreate_external(ref: str, data: dict) -> jobs.Job:
    """Change ports / env / restart policy / limits of a container the panel didn't create. Docker can't edit a running
    container, so a new one is made from the same image, command, volumes and networks; the old one is kept (renamed)
    until the new one runs, then removed."""
    info = inspect(ref)
    if info["managed"]:
        raise DockerError("Use the app's settings instead")
    name = info["name"]
    raw = json.loads(_docker(["inspect", "--type", "container", name], 30).stdout)[0]
    cfg, host = raw.get("Config", {}), raw.get("HostConfig", {})
    try:
        img = json.loads(_docker(["inspect", "--type", "image", cfg.get("Image", "")], 30).stdout)[0].get("Config", {})
    except Exception:
        img = {}
    restart = data.get("restart") or info["restart"]
    if restart not in RESTART_POLICIES:
        raise DockerError("Unknown restart policy")
    mem, cpus = _parse_limits(data.get("mem_limit", ""), data.get("cpus", ""))
    ports = _parse_ports(data["ports"]) if data.get("ports") is not None else [p for p in info["ports"] if p["host"]]
    _check_host_ports(ports, {(p["host"], p["proto"]) for p in info["ports"] if p["host"]})
    env = _parse_env(data["env"]) if data.get("env") is not None else {e["key"]: e["value"] for e in info["env"]}
    argv = ["docker", "run", "-d", "--name", name, "--restart", restart]
    if mem:
        argv += ["--memory", mem]
    if cpus:
        argv += ["--cpus", cpus]
    nm = host.get("NetworkMode", "")
    if nm and nm not in ("default", "bridge"):
        argv += ["--network", nm]
    if nm != "host":
        for p in ports:
            if p["host"]:
                argv += ["-p", f"{p['bind'] + ':' if p['bind'] else ''}{p['host']}:{p['container']}/{p['proto']}"]
    for k, v in env.items():
        argv += ["-e", f"{k}={v}"]
    for m in raw.get("Mounts", []):
        src = m.get("Source") if m.get("Type") == "bind" else m.get("Name")
        if src and m.get("Destination"):
            argv += ["-v", f"{src}:{m['Destination']}{'' if m.get('RW', True) else ':ro'}"]
    if host.get("Privileged"):
        argv.append("--privileged")
    for c in host.get("CapAdd") or []:
        argv += ["--cap-add", c]
    for d in host.get("Devices") or []:
        if d.get("PathOnHost"):
            argv += ["--device", f"{d['PathOnHost']}:{d.get('PathInContainer') or d['PathOnHost']}"]
    if cfg.get("User"):
        argv += ["-u", cfg["User"]]
    if cfg.get("WorkingDir") and cfg["WorkingDir"] != img.get("WorkingDir", ""):
        argv += ["-w", cfg["WorkingDir"]]
    for k, v in (cfg.get("Labels") or {}).items():
        if not k.startswith("com.docker.compose"):
            argv += ["--label", f"{k}={v}"]
    if cfg.get("Entrypoint") and cfg["Entrypoint"] != img.get("Entrypoint"):
        argv += ["--entrypoint", cfg["Entrypoint"][0]]
        extra = list(cfg["Entrypoint"][1:]) + list(cfg.get("Cmd") or [])
    else:
        extra = list(cfg.get("Cmd") or []) if cfg.get("Cmd") != img.get("Cmd") else []
    argv += ["--log-opt", "max-size=10m", "--log-opt", "max-file=3", cfg.get("Image", "")] + extra
    old = f"{name}-old-{int(time.time())}"

    def fn(log):
        log.progress(10, "Stopping the current container")
        _run(["docker", "stop", name], 120)
        _docker(["rename", name, old], 30)
        log.progress(40, "Creating the new container")
        r = _run(argv, 300)
        if r.returncode != 0:
            log((r.stderr or r.stdout).strip()[-1500:])
            _run(["docker", "rm", "-f", name], 60)
            _docker(["rename", old, name], 30)
            if info["running"]:
                _run(["docker", "start", name], 120)
            raise DockerError("Couldn't create the new container — the old one is back as it was")
        log.progress(85, "Removing the old container")
        _run(["docker", "rm", old], 120)
        log.progress(100, "Re-created")
        log(f"✓ {name} re-created with the new settings")
        try:
            from . import audit
            audit.record("system", "", f"docker container re-created ({name})")
        except Exception:
            pass
        return {"ok": True}
    return jobs.launch_fn(f"re-create {name}", fn, meta={"docker": name})


# ---- custom containers --------------------------------------------------------------------------------------
_PATH = re.compile(r"^/[A-Za-z0-9._~%+@:/-]*$")
# Where an app's page usually hides when the site root answers 404 (Pi-hole: /admin).
COMMON_PATHS = ("/admin/", "/admin", "/ui/", "/web/", "/app/", "/dashboard/", "/login", "/index.html")


def _page_path(raw) -> str:
    """The path of the app's page inside the container's web server ("" = the root)."""
    path = str(raw or "").strip()
    if not path or path == "/":
        return ""
    if len(path) > 200 or not _PATH.match(path) or ".." in path:
        raise DockerError("Page path looks like /admin")
    return path


def _http_status(host: str, port: int, path: str = "/") -> int | None:
    """Status code of GET path on host:port (None = no answer)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host or "127.0.0.1", port))
        s.sendall(f"GET {path or '/'} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode())
        head = s.recv(64)
        m = re.match(rb"HTTP/\d\.\d (\d{3})", head)
        return int(m.group(1)) if m else (200 if head else None)
    except OSError:
        return None
    finally:
        s.close()


def _settle_page(name: str, inst: dict, app: dict, code: int | None, wport: int, log) -> None:
    """The site root answered 404 and nobody said where the page is: look at the usual places and remember it,
    so the Open button and the health check point at the real page (Pi-hole's /admin was the first case)."""
    if code != 404 or not wport or inst.get("path") or app.get("path"):
        return
    found = find_page(port_bind(inst, "web"), wport)
    if found:
        inst["path"] = found
        if inst.get("app") == "custom":
            inst["spec"]["path"] = found
        st = _state()
        st["apps"][name] = inst
        _save(st)
        log(f"• The page isn't at / — found it at {found}; the Open button points there")
    else:
        log("• The web server answers but has no page at / — if the app's interface lives under a path (like /admin), set “Page path” in its settings")


def find_page(host: str, port: int) -> str:
    """When the site root answers 404, look for the page at the usual places ("" if none answers)."""
    for cand in COMMON_PATHS:
        if _http_status(host, port, cand) in (200, 301, 302, 303, 307, 308, 401):
            return cand
    return ""


def custom_spec(data: dict) -> tuple[str, dict, dict]:
    """Validate a custom-container form → (name, spec, inst). Shared by create and the tests."""
    name = (data.get("name") or "").strip().lower()
    if not _NAME.match(name):
        raise DockerError("Name: lowercase letters, digits and dashes, starting with a letter")
    image = (data.get("image") or "").strip()
    if not _IMAGE.match(image):
        raise DockerError("Image looks like nginx:latest or ghcr.io/owner/app:1.2")
    access = data.get("access") or "lan"
    if access not in ("proxy", "lan", "public"):
        raise DockerError("Unknown access mode")
    restart = data.get("restart") or "unless-stopped"
    if restart not in RESTART_POLICIES:
        raise DockerError("Unknown restart policy")
    host_network = bool(data.get("host_network"))
    domain, lan = "", _lan_ip()
    if access == "lan" and not lan:
        raise DockerError("This server has no private network address — use a public port or a web address")
    ports = [] if host_network else _parse_ports(data.get("ports"))
    for p in ports:
        if not p["host"]:
            p["host"] = _free_port(p["container"] if p["container"] >= 1024 else 10000 + p["container"])
    _check_host_ports(ports, set(), {"access": access, "lan_ip": lan})
    web = next((p for p in ports if p["kind"] == "web"), None)
    path = _page_path(data.get("path"))
    if access == "proxy":
        if not web:
            raise DockerError("Mark one port as the web page to reach it at a web address")
        domain = (data.get("domain") or "").strip().lower().rstrip(".")
        if not _DOMAIN.match(domain):
            raise DockerError("Enter the web address, e.g. app.example.com (its DNS must point here)")
    volumes = []
    for v in data.get("volumes") or []:
        hp, cp = str(v.get("host") or "").strip(), str(v.get("container") or "").strip()
        if not cp.startswith("/"):
            raise DockerError("Container paths start with /")
        if hp:
            if hp.startswith("/"):
                hp = str(Path(hp).resolve())
                if hp in PROTECTED_PATHS:
                    raise DockerError(f"Not {hp} — that's the server itself")
            elif not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$", hp):
                raise DockerError("Host side: a folder (/srv/data) or a named volume (mydata)")
            volumes.append((cp, "!" + hp))
        else:
            volumes.append((cp, re.sub(r"[^a-z0-9]+", "-", cp.strip("/").lower()) or "data"))
    env = _parse_env(data.get("env"))
    mem, cpus = _parse_limits(data.get("mem_limit", ""), data.get("cpus", ""))
    devices = []
    for dev in data.get("devices") or []:
        dev = str(dev).strip()
        if dev and not re.match(r"^/dev/[A-Za-z0-9_./-]+(?::/dev/[A-Za-z0-9_./-]+)?$", dev):
            raise DockerError("Devices look like /dev/ttyUSB0")
        if dev:
            devices.append(dev)
    spec = {"name": (str(data.get("title") or name)).strip()[:60] or name, "image": image, "ports": [(p["container"], p["proto"], p["kind"]) for p in ports],
            "volumes": volumes, "env": env, "host_network": host_network, "privileged": bool(data.get("privileged")), "tty": bool(data.get("keep_alive")),
            "command": str(data.get("command") or "").strip()[:2000], "devices": devices, "no_web": not web and not host_network, "home": "",
            "note": str(data.get("note") or "").strip()[:300], "uid": str(data.get("uid") or "").strip()[:12], "https_only": bool(data.get("https_only")),
            "path": path}
    if spec["uid"] and not parse_uid(spec["uid"]):
        raise DockerError("User ID is a number like 1000 (or 1000:1000)")
    inst = {"app": "custom", "spec": spec, "access": access, "domain": domain, "lan_ip": lan, "restart": restart, "mem_limit": mem, "cpus": cpus,
            "host_ports": {f"{p['container']}/{p['proto']}": p["host"] for p in ports}, "env": env, "secret_keys": [], "folders": {},
            "created": int(time.time()), "image": image}
    return name, spec, inst


def create_custom(data: dict) -> jobs.Job:
    """Run any image as a panel-managed container (compose file in /opt/aurora-apps/<name>, like the catalog apps)."""
    if not installed():
        raise DockerError("Install Docker first")
    name, spec, inst = custom_spec(data)
    if name in _state()["apps"]:
        raise DockerError(f"A container called {name} already exists")
    if name in {c["name"] for c in containers()["containers"]}:
        raise DockerError(f"A container called {name} already exists on this server (made outside the panel)")
    web = next((p for p in spec["ports"] if p[2] == "web"), None)

    def fn(log):
        work = BASE / name
        work.mkdir(parents=True, exist_ok=True)
        os.chmod(work, 0o700)
        own = []
        for _, f in spec["volumes"]:
            if not f.startswith("!"):
                (work / f).mkdir(parents=True, exist_ok=True)
                own.append(work / f)
        own_data(spec, own)
        (work / "docker-compose.yml").write_text(render_compose(name, spec, inst))
        os.chmod(work / "docker-compose.yml", 0o600)
        cc = compose_cmd()
        log.progress(5, f"Downloading {spec['image']}")
        p = subprocess.Popen(cc + ["pull"], cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=_env())
        pct = 5.0
        for line in p.stdout:
            line = line.rstrip()
            if line:
                log(line[-200:])
                if "Pull complete" in line or "Download complete" in line:
                    pct = min(80.0, pct + 4)
                    log.progress(pct, "Downloading")
        if p.wait() != 0:
            raise DockerError("Couldn't download the image — check its name and tag (and that it has a build for this processor)")
        if not spec.get("uid"):
            u = image_user(spec["image"])
            if u:
                log(f"• The image runs as user {u} — giving it its data folders")
                own_data({"uid": u}, own)
        webkey = f"{web[0]}/{web[1]}" if web else None
        if needs_tls_front(spec, inst) and webkey:
            log.progress(80, "Adding HTTPS")
            tls_front(name, inst, inst["host_ports"][webkey])
            (work / "docker-compose.yml").write_text(render_compose(name, spec, inst))
            log(f"• Served over HTTPS on port {inst['tls_port']} (self-signed certificate)")
        log.progress(82, "Starting")
        r = _run(cc + ["up", "-d"], 600, cwd=work)
        log((r.stdout + r.stderr).strip()[-1500:])
        if r.returncode != 0:
            raise DockerError("The container didn't start — see the log")
        st = _state()
        st["apps"][name] = inst
        _save(st)
        log.progress(86, "Checking it runs")
        wport = inst["host_ports"].get(webkey, 0) if webkey and not spec.get("host_network") else 0
        code = wait_started(name, log, port_bind(inst, "web") if webkey else "", wport, path=spec.get("path") or "/")
        _settle_page(name, inst, spec, code, wport, log)
        if inst["domain"] and web:
            log.progress(90, f"Creating the web address {inst['domain']}")
            _proxy_site(name, inst["domain"], inst["host_ports"][f"{web[0]}/{web[1]}"])
            log(f"• https://{inst['domain']}/ → the container")
        log.progress(100, f"{spec['name']} is running")
        log(f"✓ {spec['name']} is running")
        try:
            from . import audit
            audit.record("system", "", f"docker custom container created ({name}: {spec['image']})")
        except Exception:
            pass
        return {"ok": True, "name": name}
    return jobs.launch_fn(f"create {name}", fn, meta={"docker": name})


# ---- images --------------------------------------------------------------------------------------------------
def images() -> dict:
    if not installed() or not daemon_ok():
        return {"images": []}
    used = {}
    for line in _run(["docker", "ps", "-a", "--format", "{{.Image}}\t{{.Names}}"], 30).stdout.splitlines():
        img, _, nm = line.partition("\t")
        used.setdefault(img, []).append(nm)
    out = []
    for line in _run(["docker", "image", "ls", "--format", "{{json .}}"], 60).stdout.splitlines():
        try:
            i = json.loads(line)
        except ValueError:
            continue
        ref = f"{i.get('Repository')}:{i.get('Tag')}"
        by = list(used.get(ref, []))
        if i.get("Tag") == "latest":
            by += used.get(i.get("Repository", ""), [])
        out.append({"id": i.get("ID", ""), "repo": i.get("Repository", ""), "tag": i.get("Tag", ""), "ref": ref, "size": i.get("Size", ""),
                    "created": i.get("CreatedSince", ""), "used_by": by})
    return {"images": out}


_SHELLS = ("bash", "sh", "zsh", "ash", "dash", "fish")
_WEB_PORTS = (80, 8080, 3000, 8000, 8443, 443, 5000, 8096, 8123, 9000, 8384, 4533, 5678, 3001, 8888, 9090, 8081)


def image_inspect(ref: str) -> dict:
    """What an image is and what it expects: exposed ports, volumes, default environment, command, layers, who uses it —
    enough to pre-fill the custom-container dialog and to explain an image you just pulled."""
    ref = (ref or "").strip()
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$", ref):
        raise DockerError("Unknown image")
    try:
        c = json.loads(_docker(["image", "inspect", ref], 30).stdout)[0]
    except (ValueError, IndexError):
        raise DockerError("Unknown image")
    cfg = c.get("Config") or {}
    ports = []
    for key in sorted(cfg.get("ExposedPorts") or {}):
        p, _, pr = key.partition("/")
        if p.isdigit():
            ports.append({"port": int(p), "proto": pr or "tcp"})
    tcp = [p["port"] for p in ports if p["proto"] == "tcp"]
    web = next((p for p in _WEB_PORTS if p in tcp), tcp[0] if len(tcp) == 1 else None)
    for p in ports:
        p["kind"] = "web" if p["proto"] == "tcp" and p["port"] == web else "dns" if p["port"] == 53 else "tcp"
    env = []
    for e in cfg.get("Env") or []:
        k, _, v = e.partition("=")
        if k != "PATH":
            env.append({"key": k, "value": v})
    cmd, entry = cfg.get("Cmd") or [], cfg.get("Entrypoint") or []
    last = (cmd or entry or [""])[-1].rsplit("/", 1)[-1]
    shell = last in _SHELLS and not ports  # an interactive image (kali, ubuntu…) exits at once without a terminal
    history = []
    for line in _run(["docker", "image", "history", "--no-trunc", "--format", "{{json .}}", ref], 30).stdout.splitlines():
        try:
            h = json.loads(line)
        except ValueError:
            continue
        by = (h.get("CreatedBy") or "").replace("/bin/sh -c #(nop) ", "").replace("/bin/sh -c ", "RUN ").strip()
        history.append({"by": by[:300], "size": h.get("Size", ""), "created": h.get("CreatedSince", "")})
    used = [n for n in _run(["docker", "ps", "-a", "--filter", f"ancestor={ref}", "--format", "{{.Names}}"], 30).stdout.split() if n]
    return {"id": (c.get("Id") or "").replace("sha256:", "")[:12], "tags": c.get("RepoTags") or [], "digests": [x.split("@")[-1].replace("sha256:", "")[:12] for x in c.get("RepoDigests") or []],
            "created": (c.get("Created") or "")[:19].replace("T", " "), "size": c.get("Size", 0), "arch": c.get("Architecture", ""), "os": c.get("Os", ""),
            "ports": ports, "volumes": sorted(cfg.get("Volumes") or {}), "env": env, "cmd": cmd, "entrypoint": entry, "workdir": cfg.get("WorkingDir") or "",
            "user": cfg.get("User") or "", "labels": cfg.get("Labels") or {}, "shell": shell, "history": history[:60], "used_by": used,
            "web_port": web}


def image_remove(ref: str) -> dict:
    ref = (ref or "").strip()
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$", ref):
        raise DockerError("Unknown image")
    _docker(["image", "rm", ref], 120)
    return {"ok": True}


def image_pull(ref: str) -> jobs.Job:
    ref = (ref or "").strip()
    if not _IMAGE.match(ref):
        raise DockerError("Image looks like nginx:latest or ghcr.io/owner/app:1.2")

    def fn(log):
        log.progress(5, f"Downloading {ref}")
        p = subprocess.Popen(["docker", "pull", ref], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=_env())
        for line in p.stdout:
            if line.strip():
                log(line.rstrip()[-200:])
        if p.wait() != 0:
            raise DockerError("Download failed — check the image name")
        log.progress(100, "Downloaded")
        return {"ok": True}
    return jobs.launch_fn(f"pull {ref}", fn)
