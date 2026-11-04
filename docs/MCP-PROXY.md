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

Tools that return only names and metadata (directory listings, `git status`) don't need a secret label: `manifests/demo.json` labels them public and trusted, even on a secrets folder. `git diff` carries project content, so it gets the same label as reading a project file. `git log` stays `internal` because it shows commit author emails.

Project files count as trusted, as they do in the Claude Code profile. Web and fetch output stays untrusted, and taint never drops within a session. The limit: in `demo.json`, a file written after reading the web counts as trusted when a later session reads it. To close that, set `requiresTrusted: true` on the `fs_public` write tools. Writes then need an approval after any web read, which also protects agent config files such as `CLAUDE.md` in the repo.

When something is blocked, the agent sees why and the exact override command. If the override would let data leave, the message leads with what would leave and where it would go, and tells the agent not to ask for the approval unless the user asked to send that data there:

```sh
nope approve --config nope.toml --session my-session endorse            # trust the session again
nope approve --config nope.toml --session my-session declassify public  # let data out
nope status  --config nope.toml --session my-session
```

Every call and approval goes to an audit log, and `nope audit-check <log>` re-checks it against the Lean spec.

