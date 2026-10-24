# Nope

**Your AI agent reads the internet. Nope makes sure the internet can't tell it what to do.**

Websites, READMEs, GitHub issues and emails can contain hidden instructions for AI agents ("prompt injection"). Real example, from a widely shared post in October 2026: a developer found Claude Code sending their personal details in HTTP headers, because the sites it curled *politely asked agents to identify their users*.

With Nope installed, that second request never happens:

```
nope: blocked Bash[network]. This session has read untrusted content (from Bash[network]),
and Bash[network] is a protected action that needs a trusted session.
To allow anyway: nope approve --session 3f2a… endorse
```

## How it works

Nope watches every tool call your agent makes and enforces two rules:

1. **After the agent reads something secret or personal, that data can't leave your machine.**
2. **After the agent reads untrusted content (a web page, an issue, a fetched file), it can't take risky actions** like running shell commands, pushing code or editing agent config.

It doesn't try to spot "suspicious" text. It tracks *where data came from*, so a cleverly worded attack gets the same answer as a clumsy one. You can override any block with one command, and every override is logged.

## Your workflow doesn't change

Normal coding never trips the rules:

| you ask the agent to... | with Nope |
|---|---|
| read and edit code, grep the project | ✅ runs as usual |
| run tests, `npm install`, `git pull` | ✅ runs as usual |
| look up docs on the web, then keep editing | ✅ runs as usual |
| read `.env`, then call a URL | 🛑 blocked: secrets can't leave |
| read a web page, then run `curl`, `git push` or edit `CLAUDE.md` | 🛑 blocked until you approve |
| switch Nope off or approve itself | 🛑 always blocked |

Each check takes a fraction of a second, which you won't notice next to a model's response time.

## Proven, not guessed

The part that makes the decisions is written in [Lean 4](https://lean-lang.org) and comes with machine-checked mathematical proofs:

> **No matter what the model does, secret data can't influence anything that leaves, and injected content can't trigger a protected action.**

That holds even if the model is fully hijacked. The proofs cover the exact code that runs, not a description of it. Details: [`docs/PROOFS.md`](docs/PROOFS.md).

## Install (Claude Code)

```sh
git clone https://github.com/shayansanjideh/nope && cd nope
(cd lean && lake build)        # needs elan (Lean); builds the engine in ~1 minute
uv venv && uv pip install -e proxy && source .venv/bin/activate
nope setup claude-code
```

That's it. Start a new Claude Code session. `setup` adds a hook so every tool call (built-in and MCP) is checked. It also turns on Claude Code's shell sandbox, so a single shell command can't send data to an arbitrary server on its own; shell commands can still reach package registries and GitHub. On Linux it tells you if anything is missing. Undo with `nope setup claude-code --remove`.

When Nope blocks something you actually want, run the command it prints in another terminal:

```sh
nope approve --session <id> endorse              # "I've checked; trust this session again"
nope approve --session <id> declassify public    # "this data may leave"
```

**Other AI tools:** Nope also runs as an MCP proxy, so it works with any MCP client (Claude Desktop, Cursor, custom agents) for the tools you route through it. See [`docs/MCP-PROXY.md`](docs/MCP-PROXY.md). Native integrations for more agents are next.

## See it block attacks

```sh
cd demo && ../.venv/bin/python run_demo.py
```

A deliberately hijacked agent tries to steal a (fake) API key and to commit a malicious script, with and without Nope, against real MCP servers. Without Nope both attacks succeed; with Nope both are blocked. ([recording](docs/scenario1.gif))

## What Nope doesn't cover

- **Labels are yours to trust.** Nope knows `.env`, SSH keys and cloud credentials are secret, and that web content is untrusted. Tell it about anything else sensitive in `~/.nope/claude-code.json`.
- **What's already in the conversation.** If you paste a secret into your prompt, Nope never saw it being read.
- **Files already on your disk are trusted,** unless the agent wrote them while tainted (Nope remembers those).
- **Side channels** such as timing aren't covered.
- **It's all-or-nothing per session.** After reading one secret, all outbound calls need approval, even unrelated ones. Tracking each piece of data separately is the next big step.

## How it compares

Most agent-security tools *detect* attacks (classifiers, rules). Nope *enforces* where data may flow and proves the enforcement correct. Google DeepMind's CaMeL and Microsoft's FIDES use similar ideas inside research agents; Nope is a drop-in for the agent you already use, with machine-checked proofs. Full comparison: [`docs/PROOFS.md`](docs/PROOFS.md#prior-art).
