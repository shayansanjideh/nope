"""Stub downstream MCP server for the differential tests.

  python stub_server.py RECORD_FILE TOOL [TOOL ...]

Exposes the given tools; every call it receives is appended to RECORD_FILE, so the
test can verify that denied calls never reach the downstream server.
"""

import json
import sys

import anyio
import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

record, names = sys.argv[1], sys.argv[2:]


async def on_list_tools(ctx, params):
    return types.ListToolsResult(tools=[
        types.Tool(name=n, description=f"stub {n}", input_schema={"type": "object"})
        for n in names])


async def on_call_tool(ctx, params):
    with open(record, "a") as fh:
        fh.write(json.dumps({"tool": params.name, "arguments": params.arguments}) + "\n")
    return types.CallToolResult(content=[types.TextContent(type="text", text=f"ok {params.name}")])


async def main():
    server = Server("stub", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())


anyio.run(main)
