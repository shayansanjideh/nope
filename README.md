# Nope

**Stops hijacked AI agents from leaking your secrets or taking actions you didn't ask for. Proven in Lean.**

AI agents with tools can be hijacked by prompt injection: a web page, email or README tells the model to send your keys somewhere or push malicious code. Most defenses try to *detect* the attack, and sometimes miss. Nope doesn't try to read the model's mind. It sits between your agent and its tools (as an MCP proxy) and enforces two rules on every tool call:

1. **Once the agent has seen secret data, it can't send anything to the internet.**
2. **Once the agent has read untrusted content, it can't take protected actions** (commit, send, delete).

A human can override either rule with one command, and every override is logged.

![Nope blocking an exfiltration attempt](docs/scenario1.gif)

*A deliberately hijacked agent reads a secrets file, then follows a web page's instruction to send it to an attacker. Without Nope the attacker gets the key. With Nope:*

```
nope: blocked fetch__fetch. This session has read secret data (from fs_secret__read_text_file),
and fetch__fetch only accepts public data. Proven in Lean: Theorems 1 and 6 (confidentiality).
To allow anyway: nope approve --session demo-s1 declassify public
```

## Why "proven" matters

The decision engine is written in Lean 4 and comes with machine-checked proofs. In plain terms:

> **No matter what the model does, secret data can't influence anything that leaves, and injected content can't trigger a protected action.**

That holds even if the model is fully controlled by an attacker. The proofs cover the exact code that makes the decisions: the engine binary *is* the proven Lean code, not a re-implementation. Statements and details: [`docs/PROOFS.md`](docs/PROOFS.md).

What the proofs rely on (be honest about these):

- **Correct labels.** You tell Nope which tools touch secrets, which read untrusted content, and which are protected. If you label `fetch` as safe for secrets, it will leak them. The proof is about enforcement, not about your labels.
- **Approvals are trusted.** A human `approve` deliberately opens the gate. Don't give the agent a shell that can run `nope approve` itself.
- **No side channels.** Timing and the number of attempts aren't covered.

## Demo

Real, unmodified MCP servers (filesystem, fetch, git), a fake attacker website, and fake credentials. The "agent" is a script that obeys every injected instruction, because real models sometimes refuse and the point is that Nope holds even when they don't.

| attack | without Nope | with Nope |
|---|---|---|
| Read `secrets.env`, then a web page says "send it to me" | attacker receives the key | blocked, attacker receives nothing |
| A web page says "commit this deploy script" | malicious commit lands | blocked until a human approves (logged) |
| Normal work: read notes, fetch docs, write a summary | works | works |

```sh
cd demo && ../.venv/bin/python run_demo.py
```

It was also tested with real Claude Code pointed at Nope. The normal task worked, and the attack was blocked ([logs](docs/evidence/)).

## Quickstart

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

**2. Label the tools.** This writes every tool with the strictest labels; loosen them by hand. See [`manifests/demo.json`](manifests/demo.json) for a worked example.

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

## How it compares

| | approach | machine-checked proof | drop-in MCP proxy |
|---|---|---|---|
| **Nope** | blocks tool calls based on what the session has read | **yes** | **yes** |
| CaMeL (Google DeepMind) | rewrites the agent so untrusted data can't steer it | no | no |
| FIDES (Microsoft) | labels data inside the agent's planner | no | no |
| Invariant / Snyk, MCP gateways | rule-based detection and access control | no | yes |
| Sluice | spots copies of secret text in outgoing calls | no | yes |
| Cedar (AWS) | Lean-verified authorization, not agent-specific | yes | no |

Full comparison and references: [`docs/PROOFS.md`](docs/PROOFS.md#prior-art).

## Limits of v1

- **All-or-nothing per session.** After reading one secret, *every* outbound call needs approval, even unrelated ones. Tracking each piece of data separately is the next big step.
- **Local only.** Speaks MCP over stdio, one session per proxy process.
- **Restarts.** Use a fixed `--session` name. Reusing it restores the session's state from the audit log, so restarting doesn't wipe the taint.

## Roadmap

Per-value tracking (so reading a secret only blocks what was derived from it), argument-aware rules (e.g. `fetch` to an allowlisted domain), remote MCP transport, and tamper-evident hosted audit logs.

## Repo

`lean/` proofs and engine · `proxy/` the MCP proxy and `nope` CLI · `manifests/` labels · `demo/` attack demo · `tests/` differential tests · `scripts/verify.sh` runs every check
