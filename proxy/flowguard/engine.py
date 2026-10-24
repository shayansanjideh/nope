"""Client for the `flowguard-engine` JSON-lines process.

No policy logic lives here. Requests are serialized under a lock so that one
response line always belongs to one request. Any failure (engine crash, bad
output, timeout) raises EngineError, and callers must treat that as a deny.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any


class EngineError(Exception):
    pass


class EngineClient:
    def __init__(self, engine_path: str | Path, manifest_path: str | Path, timeout: float = 10.0):
        self.engine_path = str(engine_path)
        self.manifest_path = str(manifest_path)
        self.timeout = timeout
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()
        self.tool_count = 0

    async def start(self) -> None:
        try:
            self._proc = await asyncio.create_subprocess_exec(
                self.engine_path, "--manifest", self.manifest_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=16 * 1024 * 1024,
            )
        except OSError as e:
            raise EngineError(f"cannot start engine {self.engine_path}: {e}") from e
        line = await self._readline()
        if not line:
            err = (await self._proc.stderr.read()).decode(errors="replace").strip()
            raise EngineError(f"engine failed to start: {err or 'no output'}")
        ready = json.loads(line)
        if ready.get("ready") is not True:
            raise EngineError(f"unexpected engine banner: {line!r}")
        self.tool_count = ready.get("tools", 0)

    async def _readline(self) -> str:
        assert self._proc and self._proc.stdout
        try:
            raw = await asyncio.wait_for(self._proc.stdout.readline(), self.timeout)
        except asyncio.TimeoutError as e:
            raise EngineError("engine timed out") from e
        return raw.decode()

    async def request(self, obj: dict[str, Any]) -> dict[str, Any]:
        if self._proc is None or self._proc.returncode is not None:
            raise EngineError("engine is not running")
        async with self._lock:
            assert self._proc.stdin
            try:
                self._proc.stdin.write((json.dumps(obj) + "\n").encode())
                await self._proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as e:
                raise EngineError("engine pipe closed") from e
            line = await self._readline()
        if not line:
            raise EngineError("engine exited")
        try:
            resp = json.loads(line)
        except json.JSONDecodeError as e:
            raise EngineError(f"engine sent invalid JSON: {line!r}") from e
        if "error" in resp:
            raise EngineError(f"engine rejected request: {resp['error']}")
        return resp

    async def event(self, session: str, event: dict[str, Any]) -> dict[str, Any]:
        resp = await self.request({"session": session, "event": event})
        if resp.get("verdict") not in ("allow", "deny") or resp.get("session") != session:
            raise EngineError(f"malformed engine response: {resp!r}")
        return resp

    async def call(self, session: str, tool: str) -> dict[str, Any]:
        return await self.event(session, {"type": "call", "tool": tool})

    async def state(self, session: str) -> dict[str, Any]:
        return (await self.request({"op": "state", "session": session}))["state"]

    async def tools(self) -> list[str]:
        return (await self.request({"op": "tools"}))["tools"]

    async def close(self) -> None:
        if self._proc and self._proc.returncode is None:
            assert self._proc.stdin
            self._proc.stdin.close()
            try:
                await asyncio.wait_for(self._proc.wait(), 5)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()
