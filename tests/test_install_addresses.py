"""The installer's closing lines: private and public addresses, and Google Cloud's external one."""
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).resolve().parent.parent / "install.sh").read_text(encoding="utf-8")
BLOCK = SCRIPT[SCRIPT.index("# --- where to open it from"):SCRIPT.index('if [ -f "$APP_DIR/aurora_initial_password" ]')]

pytestmark = pytest.mark.skipif(os.name == "nt" or not shutil.which("bash"), reason="needs a Linux shell")

IP_OUTPUT = """1: lo    inet 127.0.0.1/8 scope host lo
2: eth0    inet 10.128.0.5/32 brd 10.128.0.5 scope global dynamic eth0
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
4: br-1a2b3c    inet 172.21.0.1/16 brd 172.21.255.255 scope global br-1a2b3c
5: eth1    inet 34.56.78.90/24 brd 34.56.78.255 scope global eth1
"""


def run(tmp_path, dmi="", metadata=None, ip_output=IP_OUTPUT, avahi=False):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (tmp_path / "app" / ".venv" / "bin").mkdir(parents=True, exist_ok=True)
    py = tmp_path / "app" / ".venv" / "bin" / "python"
    if not py.exists():
        py.symlink_to(sys.executable)
    stubs = {
        "ip": f"cat <<'EOF'\n{ip_output}EOF",
        "hostname": 'if [ "$1" = -I ]; then echo; else echo vm1; fi',
        "systemctl": f"exit {0 if avahi else 3}",
    }
    for name, body in stubs.items():
        p = bin_dir / name
        p.write_text("#!/bin/bash\n" + body + "\n")
        p.chmod(0o755)
    (tmp_path / "product_name").write_text(dmi)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "AURORA_DMI_PRODUCT": str(tmp_path / "product_name"),
           "AURORA_GCP_METADATA": metadata or "http://127.0.0.1:9"}
    script = f'set -euo pipefail\nAPP_DIR="{tmp_path / "app"}"; SCHEME=https; PORT=8088; c_hi=""; c_off=""\n{BLOCK}'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)


def test_addresses_are_labelled_and_bridges_left_out(tmp_path):
    out = run(tmp_path)
    assert out.returncode == 0, out.stderr
    private = out.stdout[out.stdout.index("On your network (private):"):out.stdout.index("From the internet (public):")]
    public = out.stdout[out.stdout.index("From the internet (public):"):]
    assert "https://10.128.0.5:8088" in private and "34.56.78.90" not in private
    assert "https://34.56.78.90:8088" in public
    assert "172.17.0.1" not in out.stdout and "172.21.0.1" not in out.stdout and "Google Cloud" not in out.stdout


def test_a_home_server_with_only_a_private_address_shows_no_public_section(tmp_path):
    out = run(tmp_path, ip_output="2: wlan0    inet 192.168.0.100/24 brd 192.168.0.255 scope global wlan0\n", avahi=True)
    assert out.returncode == 0, out.stderr
    assert "https://192.168.0.100:8088" in out.stdout and "https://vm1.local:8088" in out.stdout
    assert "From the internet" not in out.stdout


class _Metadata(BaseHTTPRequestHandler):
    def do_GET(self):
        ok = self.headers.get("Metadata-Flavor") == "Google" and self.path.endswith("/access-configs/0/external-ip")
        body = b"34.120.10.20" if ok else b"refused"
        self.send_response(200 if ok else 403)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def metadata():
    srv = HTTPServer(("127.0.0.1", 0), _Metadata)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_google_cloud_shows_its_external_address_and_the_firewall_rule(tmp_path, metadata):
    out = run(tmp_path, dmi="Google Compute Engine\n", metadata=metadata,
              ip_output="2: ens4    inet 10.128.0.5/32 brd 10.128.0.5 scope global dynamic ens4\n")
    assert out.returncode == 0, out.stderr
    public = out.stdout[out.stdout.index("From the internet (public):"):]
    assert "https://34.120.10.20:8088" in public and "VPC firewall rule allows TCP 8088" in public


def test_google_cloud_without_an_external_address_suggests_ssh(tmp_path):
    out = run(tmp_path, dmi="Google Compute Engine\n", ip_output="2: ens4    inet 10.128.0.5/32 scope global ens4\n")
    assert out.returncode == 0, out.stderr
    assert "has no external IP" in out.stdout and "-L 8088:localhost:8088" in out.stdout and "From the internet" not in out.stdout


def test_only_google_machines_ask_the_metadata_server():
    assert BLOCK.count("curl ") == 1
    gcp = BLOCK[BLOCK.index("if grep -qs 'Google Compute Engine'"):]
    assert "curl " in gcp and "169.254.169.254" in gcp and "ipify" not in SCRIPT
