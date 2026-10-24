"""Local control socket used by `nope approve` / `nope status`.

One JSON request line, one JSON response line. The socket is created mode 0600 in
the state directory. It must not be reachable by the agent's tools (see README,
trusted computing base).
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
from pathlib import Path
from typing import Any, Awaitable, Callable

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


async def serve(path: Path, handler: Handler) -> asyncio.base_events.Server:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if _alive(path):
            raise RuntimeError(f"another proxy is already serving session socket {path}")
        path.unlink()

    async def on_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            try:
                req = json.loads(line)
                resp = await handler(req)
            except Exception as e:  # report, never crash the proxy
                resp = {"error": str(e)}
            writer.write((json.dumps(resp) + "\n").encode())
            await writer.drain()
        finally:
            writer.close()

    old = os.umask(0o177)
    try:
        server = await asyncio.start_unix_server(on_conn, path=str(path))
    finally:
        os.umask(old)
    return server


def _alive(path: Path) -> bool:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(str(path))
        return True
    except OSError:
        return False
    finally:
        s.close()


def request(path: Path, req: dict[str, Any], timeout: float = 10.0) -> dict[str, Any]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(str(path))
    except OSError as e:
        raise RuntimeError(f"no running proxy for this session ({path}): {e}") from e
    with s:
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf)
