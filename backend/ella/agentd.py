"""Stage 5: the adapter behind a Unix socket, as its own small service with few privileges.

    python3 -m backend.ella.agentd [socket path]

One JSON object per line each way: {"op": ..., "args": {...}, "operation_id": ...}. Only processes running as root may
connect, checked with SO_PEERCRED as well as the socket's mode. Standard library only.

If the service isn't there, the panel falls back or refuses according to fail_mode: "open" runs the same adapter inside
the panel, "closed" refuses the change, so nothing changes on the firewall without the service.
"""
from __future__ import annotations

import json
import os
import socket
import socketserver
import struct
import sys
import threading
from pathlib import Path

from .adapter import AdapterError, AgentUnavailable, EllaSystemAdapter

SOCKET = "/run/aurora-ella/agent.sock"
MAX_REQUEST = 1_000_000
PROTOCOL = 1


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        creds = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        if uid != self.server.allowed_uid:
            self._send({"ok": False, "refused": True, "error": "Only root may use this service"})
            return
        line = self.rfile.readline(MAX_REQUEST + 1)
        if not line or len(line) > MAX_REQUEST:
            self._send({"ok": False, "refused": True, "error": "Bad request"})
            return
        try:
            req = json.loads(line)
            if req.get("op") == "agent_ping":
                self._send({"ok": True, "protocol": PROTOCOL, "pid": os.getpid()})
                return
            result = self.server.adapter.call(str(req.get("op")), req.get("args") or {}, str(req.get("operation_id") or ""))
            self._send({"ok": True, "result": result})
        except (AdapterError, TypeError, ValueError, AttributeError) as exc:
            self._send({"ok": False, "refused": True, "error": str(exc)[:500]})

    def _send(self, obj: dict) -> None:
        self.wfile.write(json.dumps(obj).encode() + b"\n")


class _Server(socketserver.ThreadingMixIn, getattr(socketserver, "UnixStreamServer", object)):  # the panel also imports this on Windows, where it never runs
    daemon_threads = True
    allow_reuse_address = True


def serve(path: str = SOCKET, adapter=None, allowed_uid: int | None = None) -> _Server:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.unlink(missing_ok=True)
    old = os.umask(0o177)
    try:
        srv = _Server(path, _Handler)
    finally:
        os.umask(old)
    srv.adapter = adapter or EllaSystemAdapter(Path(os.environ.get("AURORA_ELLA_DIR", "/var/lib/aurora/ella")) / "adapter.log")
    srv.allowed_uid = os.getuid() if allowed_uid is None else allowed_uid
    return srv


class SocketAdapter:
    """The same call() as EllaSystemAdapter, so nothing above it knows the difference."""

    def __init__(self, path: str = SOCKET, fallback=None, fail_mode=lambda: "open", on_fallback=None):
        self.path, self.fallback, self.fail_mode, self.on_fallback = path, fallback, fail_mode, on_fallback
        self.last_transport = "socket"

    def _ask(self, payload: dict, timeout: float) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(self.path)
            s.sendall(json.dumps(payload).encode() + b"\n")
            f = s.makefile("rb")
            line = f.readline(20_000_000)
        if not line:
            raise OSError("the service closed the connection")
        return json.loads(line)

    def ping(self) -> dict:
        try:
            return self._ask({"op": "agent_ping"}, 3)
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": str(exc)[:200]}

    def call(self, op: str, args: dict | None = None, operation_id: str = "") -> dict:
        try:
            r = self._ask({"op": op, "args": args or {}, "operation_id": operation_id}, 120)
        except (OSError, ValueError) as exc:
            return self._without_service(op, args, operation_id, exc)
        if r.get("refused"):
            raise AdapterError(r.get("error", "Refused"))
        self.last_transport = "socket"
        return r["result"]

    def _without_service(self, op, args, operation_id, exc):
        if self.fail_mode() == "closed" or self.fallback is None:
            self.last_transport = "none"
            raise AgentUnavailable(f"WAF Ella's agent service isn't answering ({exc}), and this server is set to refuse changes without it.")
        self.last_transport = "fallback"
        if self.on_fallback:
            self.on_fallback(str(exc))
        return self.fallback.call(op, args, operation_id)


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else SOCKET
    srv = serve(path)
    os.environ.setdefault("LC_ALL", "C")
    stop = threading.Event()
    threading.Thread(target=srv.serve_forever, daemon=True, name="ella-agent").start()
    print(f"WAF Ella agent listening on {path}", flush=True)
    try:
        stop.wait()
    except KeyboardInterrupt:
        pass
    srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
