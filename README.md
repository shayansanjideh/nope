# Nope

**Your AI agent reads the internet. Nope makes sure the internet can't tell it what to do.**

Websites, READMEs, GitHub issues and emails can contain hidden instructions for AI agents ("prompt injection"). Real example, from [a widely shared post](https://x.com/this_liss/status/2113120507289624714) in October 2026: a developer found Claude Code sending their personal details in HTTP headers, because the sites it curled *politely asked agents to identify their users*.

With Nope installed, here's that sequence run by real Claude Code. The personal data never leaves:

```
✅ curl https://pypi.org/simple/requests/          reads a web page
✅ git config user.email                           reads your email (Nope labels it personal)
🛑 curl -H "X-User-Email: dev@example.invalid" …

nope: blocked Bash[network]. This session has read internal data (from Bash[internal]),
and Bash[network] only accepts public data. Proven in Lean: Theorems 1 and 6 (confidentiality).
To allow anyway: nope approve --session 1d90d98f-… declassify public
```

([session log](docs/evidence/claude-code-personal-header.jsonl))

## How it works

Nope watches every tool call your agent makes and enforces two rules:

1. **After the agent reads something secret or personal, that data can't leave your machine.**
2. **After the agent reads untrusted content (a web page, a GitHub issue, a `curl` response), it can't take risky actions** like pushing code, publishing, deploying, fetching more from the web or editing agent config.

It doesn't try to spot "suspicious" text. It tracks *where data came from*, so a cleverly worded attack gets the same answer as a clumsy one. You can override any block with one command, and every override is logged.

## Your workflow doesn't change

Normal coding never trips the rules:

| you ask the agent to... | with Nope |
|---|---|
| read and edit code, grep the project | ✅ runs as usual |
| run tests, `npm install`, `git pull`, `git commit` | ✅ runs as usual |
| look up docs on the web, then edit and run the tests | ✅ runs as usual |
| read `.env`, then call a URL | 🛑 blocked: secrets can't leave |
| read a web page, then run `curl`, `git push` or edit `CLAUDE.md` | 🛑 blocked until you approve |
| switch Nope off or approve itself | 🛑 always blocked |

We checked this with real Claude Code on everyday tasks (write a function and its tests, look up docs then refactor, commit, explore the code): **17 of 17 tool calls went through, zero blocks.** Each check takes about a quarter of a second.

## Proven, not guessed

The part that makes the decisions is written in [Lean 4](https://lean-lang.org) and comes with machine-checked mathematical proofs:

> **No matter what the model does, secret data can't influence anything that leaves, and injected content can't trigger a protected action.**

That holds even if the model is fully hijacked, as long as Nope labels the data correctly (which files are secret, which content came from outside). The proofs cover the exact code that makes each decision, not a description of it. Labeling is done by plain rules you can read, and it's tested hard rather than proven. Details: [`docs/PROOFS.md`](docs/PROOFS.md).

## Install (Claude Code)

```sh
git clone https://github.com/shayansanjideh/nope && cd nope
(cd lean && lake build)        # needs elan (Lean); builds the engine in ~1 minute
uv venv && uv pip install -e proxy && source .venv/bin/activate
nope setup claude-code
```

That's it. Start a new Claude Code session. `setup` does three things:

- Checks every tool call before it runs (built-in tools and MCP tools).
- Checks every tool's output after it runs. If your secrets show up in it, even disguised or base64-encoded, the session counts as having read them.
- Turns on Claude Code's shell sandbox, so a shell command can only reach package registries and GitHub, not an attacker's server.

On Linux, `setup` tells you if the sandbox needs anything installed. Undo with `nope setup claude-code --remove`.

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

- **Labels are rules, not proofs.** Nope knows `.env`, SSH keys, cloud credentials and your git identity are sensitive, and that web pages, `curl` output and GitHub issues are untrusted. Tell it about anything else in `~/.nope/claude-code.json`.
- **Scrambled secrets in shell output.** Nope recognizes your secrets in a command's output even when disguised or encoded. It can't recognize one that was deliberately scrambled (reversed, split into pieces). The sandbox still stops the shell from sending anything to an unknown server, but allowed hosts (GitHub, package registries) are reachable.
- **What's already in the conversation.** If you paste a secret into your prompt, Nope never saw it being read.
- **Files on your disk are trusted,** including ones the agent edited after reading the web. Files that control the agent (`CLAUDE.md`, `.mcp.json`, Claude settings) can't be edited from an untrusted session.
- **Side channels** such as timing aren't covered.
- **It's all-or-nothing per session.** After reading one secret, all outbound calls need approval, even unrelated ones. Tracking each piece of data separately is the next big step.

## How it compares

Most agent-security tools *detect* attacks (classifiers, rules). Nope *enforces* where data may flow and proves the enforcement correct. Google DeepMind's CaMeL and Microsoft's FIDES use similar ideas inside research agents; Nope is a drop-in for the agent you already use, with machine-checked proofs. Full comparison: [`docs/PROOFS.md`](docs/PROOFS.md#prior-art).
