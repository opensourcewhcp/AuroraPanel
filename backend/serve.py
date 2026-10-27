"""The panel's entry point: uvicorn, plus an http → https redirect on the same port.

uvicorn can serve TLS or plain HTTP on a port, not both. When Panel HTTPS is on, a browser
that still goes to http://pi:8088 gets a broken-looking "connection reset" because its plain
request lands on a TLS socket. Here the port is accepted by us first: the first byte tells a
TLS ClientHello (0x16) from a plain HTTP request. TLS connections are handed to uvicorn's own
protocol untouched (same socket, so the client address, ciphers and headers are exactly what
uvicorn would see); plain requests get a 307 to the same URL on https and are closed.

Started by the systemd unit as `python -m backend.serve backend.app:app --host … --port …`
with the same command line and UVICORN_* environment as `python -m uvicorn`. Without TLS it
is plain uvicorn.
"""
from __future__ import annotations

import asyncio
import html
import importlib
import logging
import os
import re
import socket
import sys

from uvicorn.server import Server

log = logging.getLogger("uvicorn.error")

METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}
_HOST = re.compile(r"^[A-Za-z0-9.\-_\[\]:]{1,255}$")
_TARGET = re.compile(r"^/[!-~]{0,2047}$")  # printable ASCII, no spaces or control characters
HEAD_LIMIT = 8192
HEAD_TIMEOUT = 5.0
TLS_HELLO = b"\x16"


def redirect_response(head: bytes, fallback_host: str) -> bytes | None:
    """The HTTP response for a plain request that arrived on the TLS port, or None for garbage.

    307 (not 301): browsers don't cache it, so turning Panel HTTPS off later just works."""
    try:
        lines = head.decode("latin-1").split("\r\n")
        method, target, proto = lines[0].split(" ")
    except ValueError:
        return None
    if method not in METHODS or not proto.startswith("HTTP/1."):
        return None
    if not _TARGET.match(target):
        target = "/"
    host = ""
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line[5:].strip()
            break
    if not _HOST.match(host):
        host = fallback_host
    loc = f"https://{host}{target}"
    body = f'<!doctype html><meta charset="utf-8"><title>Redirecting</title><a href="{html.escape(loc)}">{html.escape(loc)}</a>\n'.encode()
    return (f"HTTP/1.1 307 Temporary Redirect\r\nLocation: {loc}\r\nContent-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").encode("ascii") + body


async def _readable(sock: socket.socket, loop: asyncio.AbstractEventLoop, timeout: float) -> bool:
    if timeout <= 0:
        return False
    fut = loop.create_future()
    try:
        loop.add_reader(sock.fileno(), lambda: fut.done() or fut.set_result(True))
    except NotImplementedError:  # proactor loop (Windows): poll instead
        await asyncio.sleep(min(0.02, timeout))
        return True
    try:
        await asyncio.wait_for(fut, timeout)
        return True
    except (asyncio.TimeoutError, TimeoutError):
        return False
    finally:
        loop.remove_reader(sock.fileno())


async def _peek(sock: socket.socket, loop: asyncio.AbstractEventLoop, timeout: float = 10.0) -> bytes:
    """The first byte the client sends, left in the socket for whoever handles it next."""
    end = loop.time() + timeout
    while True:
        try:
            return sock.recv(1, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            pass
        if not await _readable(sock, loop, end - loop.time()):
            return b""


async def _answer_plain(sock: socket.socket, loop: asyncio.AbstractEventLoop) -> None:
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < HEAD_LIMIT:
        chunk = await asyncio.wait_for(loop.sock_recv(sock, 4096), HEAD_TIMEOUT)
        if not chunk:
            return
        buf += chunk
    ip, port = sock.getsockname()[:2]
    resp = redirect_response(buf, f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}")
    if resp:
        await asyncio.wait_for(loop.sock_sendall(sock, resp), HEAD_TIMEOUT)


class Front(Server):
    """uvicorn's Server; with TLS configured it owns the listening socket and sorts connections by their first byte."""

    _lsock: socket.socket | None = None
    _acceptor: asyncio.Future | None = None

    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
        if sockets is not None or self.config.ssl is None:
            return await super().startup(sockets)
        await self.lifespan.startup()
        if self.lifespan.should_exit:
            self.should_exit = True
            return
        config = self.config

        def create_protocol(_loop: asyncio.AbstractEventLoop | None = None) -> asyncio.Protocol:
            return config.http_protocol_class(config=config, server_state=self.server_state,  # type: ignore[call-arg]
                                              app_state=self.lifespan.state, _loop=_loop)

        self._lsock = config.bind_socket()  # also logs "Uvicorn running on https://…"
        self._lsock.listen(config.backlog)
        self._lsock.setblocking(False)
        self.servers = []
        self._acceptor = asyncio.ensure_future(self._accept(create_protocol))
        self.started = True

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        if self._acceptor is not None:
            self._acceptor.cancel()
            try:
                await self._acceptor
            except BaseException:
                pass
            self._acceptor = None
        if self._lsock is not None:
            self._lsock.close()
            self._lsock = None
        await super().shutdown(sockets)

    async def _accept(self, create_protocol) -> None:
        loop = asyncio.get_running_loop()
        while True:
            try:
                sock, _ = await loop.sock_accept(self._lsock)
            except asyncio.CancelledError:
                raise
            except OSError:
                await asyncio.sleep(0.1)
                continue
            sock.setblocking(False)
            asyncio.ensure_future(self._dispatch(sock, create_protocol, loop))

    async def _dispatch(self, sock: socket.socket, create_protocol, loop: asyncio.AbstractEventLoop) -> None:
        tls = False
        try:
            first = await _peek(sock, loop)
            if first == TLS_HELLO:
                tls = True  # uvicorn's protocol (and asyncio's SSL transport) own the socket from here
                await loop.connect_accepted_socket(create_protocol, sock, ssl=self.config.ssl)
            elif first:
                await _answer_plain(sock, loop)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # a client that gave up, a failed handshake, garbage
            log.debug("front: %s", e)
        finally:
            if not tls:
                try:
                    sock.close()
                except OSError:
                    pass


def main() -> None:
    os.environ["AURORA_FRONT"] = "1"  # tells the panel the redirect is in place (Security → Panel HTTPS)
    cli = importlib.import_module("uvicorn.main")  # uvicorn.main the module, not uvicorn.main the click command
    cli.Server = Front  # uvicorn.main.run() builds `Server(config=config)` from its own namespace
    sys.exit(cli.main())


if __name__ == "__main__":
    main()
