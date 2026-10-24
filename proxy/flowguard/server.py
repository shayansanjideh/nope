"""The MCP proxy: an MCP server to the client, an MCP client to each downstream.

On every tools/call the engine is asked first. Deny: return an error result with
the engine's reason and never contact the downstream server. Allow: forward.
"""

from __future__ import annotations

import asyncio
import getpass
import sys
from contextlib import AsyncExitStack
from typing import Any

import mcp_types as types
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from . import __version__, control
from .audit import AuditLog
from .config import SEP, Config, load_manifest_json
from .engine import EngineClient, EngineError
from .logreplay import decision_records, read_records


def log(msg: str) -> None:
    print(f"[flowguard] {msg}", file=sys.stderr, flush=True)


def text_result(text: str, is_error: bool) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=is_error)


class FlowguardProxy:
    def __init__(self, cfg: Config, session: str, fsync: bool = True):
        self.cfg = cfg
        self.session = session
        self.fsync = fsync
        self.stack = AsyncExitStack()
        self.engine = EngineClient(cfg.engine, cfg.manifest)
        self.routes: dict[str, tuple[Client, str]] = {}
        self.exposed: list[types.Tool] = []
        self.decide_lock = asyncio.Lock()
        self.broken = False

    # ---------------------------------------------------------------- setup

    async def start(self) -> None:
        manifest = load_manifest_json(self.cfg.manifest)
        await self.engine.start()
        self.stack.push_async_callback(self.engine.close)
        declared = set(await self.engine.tools())

        if control._alive(self.cfg.socket_dir / f"{self.session}.sock"):
            raise RuntimeError(f"session {self.session} is already being served by another proxy")
        log_path = self.cfg.log_dir / f"{self.session}.jsonl"
        resuming = log_path.exists() and log_path.stat().st_size > 0
        if resuming:
            await self._resume(log_path, manifest)
        self.audit = AuditLog(self.cfg.log_dir, self.session, fsync=self.fsync)
        self.stack.callback(self.audit.close)

        for spec in self.cfg.servers:
            params = StdioServerParameters(
                command=spec.command, args=spec.args, env=spec.env, cwd=spec.cwd)
            client = await self.stack.enter_async_context(Client(params))
            tools: list[types.Tool] = []
            cursor = None
            while True:
                page = await client.list_tools(cursor=cursor)
                tools += page.tools
                cursor = page.next_cursor
                if not cursor:
                    break
            for t in tools:
                name = f"{spec.name}{SEP}{t.name}"
                self.routes[name] = (client, t.name)
                if name in declared:
                    desc = f"[{spec.name}] {t.description or ''}".strip()
                    self.exposed.append(t.model_copy(update={"name": name, "description": desc}))
        undeclared = sorted(set(self.routes) - declared)
        if undeclared:
            log(f"hidden (not in manifest, will be denied): {', '.join(undeclared)}")
        missing = sorted(declared - set(self.routes))
        if missing:
            log(f"declared in manifest but no downstream provides: {', '.join(missing)}")

        self.audit.write(
            "session_resume" if resuming else "session_start",
            manifest=manifest, manifest_path=str(self.cfg.manifest), config=str(self.cfg.path),
            servers=[s.name for s in self.cfg.servers],
            exposed=[t.name for t in self.exposed], version=__version__,
            state=await self.engine.state(self.session),
        )
        sock = self.cfg.socket_dir / f"{self.session}.sock"
        srv = await control.serve(sock, self._control)
        self.stack.callback(lambda: sock.unlink(missing_ok=True))
        self.stack.callback(srv.close)
        log(f"session {self.session}: {len(self.exposed)} tools exposed, audit log {self.audit.path}")

    async def _resume(self, log_path, manifest: dict[str, Any]) -> None:
        """Restore taint after a restart by replaying the session's executed events
        through the engine. Refuse if the manifest changed."""
        records = read_records(log_path)
        starts = [r for r in records if r["kind"] in ("session_start", "session_resume")]
        if starts and starts[0]["manifest"] != manifest:
            raise RuntimeError(
                f"session {self.session} was started under a different manifest; "
                "use a new session id")
        for r in decision_records(records):
            if r["verdict"] != "allow":
                continue
            resp = await self.engine.event(self.session, r["event"])
            if resp["verdict"] != "allow" or resp["state"] != r["state"]:
                raise RuntimeError(f"resume replay diverged at seq {r['seq']}: {resp}")
        log(f"resumed session {self.session}: state {await self.engine.state(self.session)}")

    async def close(self) -> None:
        await self.stack.aclose()

    # ---------------------------------------------------------------- decisions

    async def _decide(self, event: dict[str, Any], kind: str, **extra: Any) -> dict[str, Any]:
        """Ask the engine and write the audit record under one lock, so the log order
        is exactly the engine's event order."""
        async with self.decide_lock:
            if self.broken:
                raise EngineError("engine previously failed; failing closed")
            try:
                resp = await self.engine.event(self.session, event)
            except EngineError as e:
                self.broken = True
                self.audit.write("engine_error", event=event, error=str(e), **extra)
                raise
            self.audit.write(
                kind, event=resp["event"], verdict=resp["verdict"], code=resp["code"],
                reason=resp["reason"], theorem=resp.get("theorem"), state=resp["state"], **extra)
            return resp

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        try:
            resp = await self._decide({"type": "call", "tool": name}, "call", arguments=arguments)
        except EngineError as e:
            log(f"BLOCKED {name}: engine failure ({e})")
            return text_result(f"Flowguard blocked '{name}': policy engine unavailable "
                               f"(fail closed): {e}", True)
        if resp["verdict"] != "allow":
            log(f"BLOCKED {name}: {resp['reason']}")
            return text_result(
                f"Flowguard blocked '{name}': {resp['reason']}\n"
                f"Guarantee: {resp.get('theorem')}", True)
        route = self.routes.get(name)
        if route is None:
            self.audit.write("result", tool=name, is_error=True, error="no downstream provides tool")
            return text_result(f"Flowguard: no downstream server provides '{name}'", True)
        client, orig = route
        try:
            result = await client.call_tool(orig, arguments or {})
        except Exception as e:
            self.audit.write("result", tool=name, is_error=True, error=str(e))
            return text_result(f"downstream error calling '{name}': {e}", True)
        self.audit.write("result", tool=name, is_error=bool(result.is_error))
        return result

    async def approve(self, event: dict[str, Any], approver: str, note: str) -> dict[str, Any]:
        resp = await self._decide(event, "approval", approver=approver, note=note)
        log(f"APPROVAL by {approver}: {resp['reason']}")
        return resp

    async def _control(self, req: dict[str, Any]) -> dict[str, Any]:
        op = req.get("op")
        if op == "approve":
            ev = req.get("event") or {}
            if ev.get("type") not in ("declassify", "endorse"):
                return {"error": "approve accepts only declassify/endorse events"}
            return await self.approve(ev, str(req.get("approver") or getpass.getuser()),
                                      str(req.get("note") or ""))
        if op == "status":
            return {"session": self.session, "state": await self.engine.state(self.session),
                    "log": str(self.audit.path), "tools": [t.name for t in self.exposed]}
        return {"error": f"unknown op {op!r}"}

    # ---------------------------------------------------------------- MCP face

    def mcp_server(self) -> Server:
        async def on_list_tools(ctx, params) -> types.ListToolsResult:
            return types.ListToolsResult(tools=self.exposed)

        async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
            return await self.call_tool(params.name, params.arguments)

        return Server(
            "flowguard", version=__version__,
            instructions="Tool calls pass through Flowguard, an information-flow monitor. "
                         "Blocked calls return an error explaining which label blocked them.",
            on_list_tools=on_list_tools, on_call_tool=on_call_tool,
        )


async def serve_stdio(cfg: Config, session: str) -> None:
    proxy = FlowguardProxy(cfg, session)
    try:
        await proxy.start()
        server = proxy.mcp_server()
        async with stdio_server() as (r, w):
            await server.run(r, w, server.create_initialization_options())
    finally:
        await proxy.close()
