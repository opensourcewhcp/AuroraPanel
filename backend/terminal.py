"""Interactive terminal over a WebSocket, backed by a real PTY (Linux only).

The FastAPI websocket route hands us an authenticated WebSocket; we fork a PTY
running the user's shell and pump bytes both directions. Client protocol:
  - client -> server: {"type":"input","data":"..."}  or  {"type":"resize","cols":N,"rows":N}
  - server -> client: {"type":"output","data":"..."} then {"type":"exit"}
"""
from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import signal
import struct

IS_LINUX = platform.system() == "Linux"


def available() -> bool:
    return IS_LINUX


async def run(websocket, argv: list[str] | None = None) -> None:
    """argv: run this command instead of the login shell (e.g. `docker exec -it <container> sh`)."""
    if not IS_LINUX:
        await websocket.send_text(json.dumps({"type": "output",
            "data": "Terminal is only available on Linux (the Pi).\r\n"}))
        await websocket.send_text(json.dumps({"type": "exit"}))
        return

    import fcntl
    import pty
    import termios

    shell = os.environ.get("SHELL") or shutil.which("bash") or "/bin/sh"
    pid, master_fd = pty.fork()
    if pid == 0:
        # Child: become the login shell.
        os.environ["TERM"] = "xterm-256color"
        try:
            if argv:
                os.environ["PATH"] = os.environ.get("PATH", "") + ":/usr/local/bin:/usr/bin:/bin"
                os.execvp(argv[0], list(argv))
            os.execvp(shell, [shell, "-l"])
        except OSError:
            os._exit(1)

    loop = asyncio.get_running_loop()

    def _set_winsize(rows: int, cols: int) -> None:
        try:
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass

    async def pty_to_ws() -> None:
        # Blocking read runs in a thread; returns b'' / raises on shell exit.
        while True:
            try:
                data = await loop.run_in_executor(None, os.read, master_fd, 4096)
            except OSError:
                break
            if not data:
                break
            try:
                await websocket.send_text(json.dumps({"type": "output",
                    "data": data.decode("utf-8", "replace")}))
            except Exception:
                break

    async def ws_to_pty() -> None:
        while True:
            try:
                raw = await websocket.receive_text()
            except Exception:
                break
            try:
                msg = json.loads(raw)
            except (ValueError, TypeError):
                continue
            mtype = msg.get("type")
            if mtype == "input":
                try:
                    os.write(master_fd, msg.get("data", "").encode("utf-8"))
                except OSError:
                    break
            elif mtype == "resize":
                _set_winsize(int(msg.get("rows", 24)), int(msg.get("cols", 80)))

    _set_winsize(24, 80)
    t_out = asyncio.create_task(pty_to_ws())
    t_in = asyncio.create_task(ws_to_pty())
    try:
        # Return as soon as either side ends (shell exit or client disconnect).
        await asyncio.wait({t_out, t_in}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        # Tear down the child + fd; closing the fd unblocks a pending os.read.
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.close(master_fd)  # unblocks pty_to_ws' os.read
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
        for t in (t_out, t_in):
            t.cancel()
        await asyncio.gather(t_out, t_in, return_exceptions=True)
        try:
            await websocket.send_text(json.dumps({"type": "exit"}))
        except Exception:
            pass
