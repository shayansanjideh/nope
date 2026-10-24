# Nope as an MCP proxy (any MCP client)

Use this for Claude Desktop, Cursor, or your own agent. Nope sits between the client and your MCP servers and checks every tool call that goes through it. (For Claude Code, `nope setup claude-code` is simpler and also covers built-in tools.)

## Setup

Needs [elan](https://github.com/leanprover/elan) (Lean), [uv](https://docs.astral.sh/uv/), and Node.js if your MCP servers use `npx`.

```sh
git clone https://github.com/shayansanjideh/nope && cd nope
(cd lean && lake build)                 # builds the engine (~1-2 min)
uv venv && uv pip install -e proxy && source .venv/bin/activate
```

**1. List your MCP servers** in `nope.toml`:

```toml
engine = "/path/to/nope/lean/.lake/build/bin/nope-engine"
manifest = "manifest.json"

[servers.fs]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem@2.0.0", "/home/me/projects"]

[servers.fetch]
command = "uvx"
args = ["mcp-server-fetch"]
```

**2. Label the tools.** This writes every tool with the strictest labels; loosen them by hand. See [`manifests/demo.json`](../manifests/demo.json) for a worked example.

```sh
nope init-manifest --config nope.toml -o manifest.json
```

Each tool gets three settings:

| setting | question it answers | example |
|---|---|---|
| `outLabel` | How sensitive / trustworthy is what this tool returns? | secrets file: `secret`; web page: `untrusted` |
| `argClearance` | How sensitive may the data I send it be? | `fetch`: `public` (the URL leaves your machine) |
| `requiresTrusted` | Is this a protected action? | `git_commit`: `true` |

**3. Point your agent at Nope** instead of the servers. For Claude Code:

```sh
claude mcp add nope -- $(which nope) serve --config $PWD/nope.toml --session my-session
```

When something is blocked, the agent sees why and the exact override command:

```sh
nope approve --config nope.toml --session my-session endorse            # trust the session again
nope approve --config nope.toml --session my-session declassify public  # let data out
nope status  --config nope.toml --session my-session
```

Every call and approval goes to an audit log, and `nope audit-check <log>` re-checks it against the Lean spec.

