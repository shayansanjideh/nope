# Nope: proofs, threat model, testing, prior art

The details behind the README's claims. Everything here is checked by `scripts/verify.sh` and CI.

Contents: [The theorems](#the-theorems) · [Testing](#how-the-implementation-is-tested) · [Threat model](#threat-model-and-trusted-computing-base) · [Claude Code integration](#claude-code-integration-what-is-proven-what-is-labeling) · [Prior art](#prior-art)

## The theorems

Proofs are in [`lean/Nope/Theorems.lean`](../lean/Nope/Theorems.lean) and [`lean/Nope/Noninterference.lean`](../lean/Nope/Noninterference.lean). Lean 4.35, core + `Std` only (no Mathlib), zero `sorry`, zero `admit`, no custom axioms. The axiom audit ([`lean/Axioms.lean`](../lean/Axioms.lean), output committed in [`lean/axioms-output.txt`](../lean/axioms-output.txt)) shows every theorem depends only on a subset of `{propext, Quot.sound, Classical.choice}`.

**The spec is independent of the monitor.** [`Spec.lean`](../lean/Nope/Spec.lean) never mentions `Monitor.step`. For the call at position `i` of a trace, it scans the history backwards and joins the labels of everything read since the last relevant approval: `confSince` stops at the most recent `declassify`, and `integSince` stops at the most recent `endorse`. `step` is a forward fold over a running label. The theorems relate the two, so the soundness proof is not circular.

```lean
def ConfOK (P : Manifest) (l0 : Label) (tr : List Event) : Prop :=
  ∀ i t, tr[i]? = some (.call t) →
    ∃ tool, P t = some tool ∧ confSince P l0.conf (history tr i) ≤ tool.argClearance

def IntegOK (P : Manifest) (l0 : Label) (tr : List Event) : Prop :=
  ∀ i t tool, tr[i]? = some (.call t) → P t = some tool → tool.requiresTrusted = true →
    integSince P l0.integ (history tr i) = .trusted
```

`allAllowed P s es` means every event of `es` was allowed by the monitor starting from state `s`. `executed P s es` is the sub-trace of events that actually took effect (denied calls dropped).

### 1. Soundness (confidentiality)

```lean
theorem soundness (s : State) (es : List Event) (h : allAllowed P s es) :
    ConfOK P s.ctx es

theorem conf_between (s : State) (es B C R : List Event) (u t : String) (tu tt : Tool)
    (hex : executed P s es = B ++ .call u :: C ++ .call t :: R)
    (hu : P u = some tu) (ht : P t = some tt)
    (hlab : ¬ tu.outLabel.conf ≤ tt.argClearance) :
    ∃ c, .declassify c ∈ C
```

Every allowed trace calls only declared tools, and every call's arguments are cleared for everything read since the last declassification. In the positional form, `conf_between` holds for any trace, including ones with denied attempts. If the agent read something more confidential than a later tool's clearance, a human `declassify` happened in between. `soundness_executed` gives the same guarantee for the executed sub-trace of an arbitrary trace.

### 2. Integrity

```lean
theorem integrity (s : State) (es : List Event) (h : allAllowed P s es) :
    IntegOK P s.ctx es

theorem integrity_between (s : State) (es B C R : List Event) (u t : String) (tu tt : Tool)
    (hex : executed P s es = B ++ .call u :: C ++ .call t :: R)
    (hu : P u = some tu) (huntrusted : tu.outLabel.integ = .untrusted)
    (ht : P t = some tt) (hreq : tt.requiresTrusted = true) :
    .endorse ∈ C
```

No `requiresTrusted` tool runs after an `untrusted` read unless an `endorse` occurs in between.

### 3. Precision

```lean
theorem precision :
    ∀ (s : State) (es : List Event) (t : String),
      Spec P s.ctx (executed P s es ++ [.call t]) → (step P (run P s es).2 (.call t)).1 = .allow

theorem monitor_exact (s : State) (es : List Event) (t : String) :
    (step P (run P s es).2 (.call t)).1 = .allow ↔
      Spec P s.ctx (executed P s es ++ [.call t])
```

If the spec permits extending what has executed with `call t`, the monitor allows it. This rules out a monitor that denies everything. Combined with soundness, the monitor allows a call **exactly** when the independent spec does.

### 4. Approvals are the only downgrade

```lean
theorem call_monotone (s : State) (t : String) : s.ctx ≤ (step P s (.call t)).2.ctx

theorem downgrade_only_by_approval (s : State) (e : Event)
    (h : ¬ s.ctx ≤ (step P s e).2.ctx) : (∃ c, e = .declassify c) ∨ e = .endorse
```

A tool call never lowers the context label, allowed or denied. Any step that lowers it is a human approval. `run_calls_monotone` extends this to whole runs without approvals.

### 5. Policy monotonicity

```lean
def Manifest.AtLeastAsStrict (P' P : Manifest) : Prop :=
  ∀ t tool', P' t = some tool' → ∃ tool, P t = some tool ∧
    tool.outLabel ≤ tool'.outLabel ∧ tool'.argClearance ≤ tool.argClearance ∧
    (tool.requiresTrusted = true → tool'.requiresTrusted = true)

theorem policy_monotone {P' : Manifest} (hs : Manifest.AtLeastAsStrict P' P)
    (s : State) (es : List Event) (h : allAllowed P' s es) : allAllowed P s es
```

Tightening a manifest only ever removes behaviors: anything allowed under the stricter manifest is allowed under the looser one. You can tighten labels without fear of a strange interaction enabling something new.

### 6–7. Noninterference (end to end, over data)

Theorems 1–5 relate the monitor to a spec over labels. [`Noninterference.lean`](../lean/Nope/Noninterference.lean) proves what those labels buy, stated over the data itself. An **agent** is any function from everything it has observed (every tool, argument, result or denial) to its next call, with no assumptions, so it can be fully attacker-controlled. A **world** fixes what every tool returns. An **observer** watching a set of sinks sees the tool and argument of every call that reaches one.

```lean
theorem noninterference_conf (o : Conf) (W₁ W₂ : World D)
    (hW : ∀ i t tool a, P t = some tool → tool.outLabel.conf ≤ o → W₁ i t a = W₂ i t a)
    (A : Agent D) (n : Nat) (s : State) :
    view P (lowSink o) (exec P W₁ A n s []).1 = view P (lowSink o) (exec P W₂ A n s []).1

theorem noninterference_integ (W₁ W₂ : World D)
    (hW : ∀ i t tool a, P t = some tool → tool.outLabel.integ = .trusted → W₁ i t a = W₂ i t a)
    (A : Agent D) (n : Nat) (s : State) :
    view P protectedSink (exec P W₁ A n s []).1 = view P protectedSink (exec P W₂ A n s []).1
```

**Confidentiality.** Run any agent in two worlds that differ only in results above level `o` (for example, the contents of `secrets.env`). Every call that reaches a sink cleared for `o` is identical in both runs, tool for tool and argument for argument. Secret data cannot reach a public sink or influence what reaches one, whatever the model does.

**Integrity.** Run any agent in two worlds that differ only in untrusted results (for example, what an injected web page says). Every call that reaches a `requiresTrusted` tool is identical in both runs. Injected content cannot choose which protected action runs or with what arguments.

Both are instances of one generic theorem (`NI.noninterference`) about any barrier: reading high data blocks the session, blocking persists, and a blocked session cannot reach the observed sinks. Kernel-evaluated examples at the end of the file run an exfiltrating agent and an injected agent on the demo manifest, and also show that benign runs do reach the sinks.

Scope: runs consist of agent calls. Human approvals are the explicit, logged release valve and sit outside these theorems. A world's results depend on the step, tool and argument, so a tool whose results depend on earlier writes must be labeled to match (see the storage-laundering note in the TCB). The observer sees only calls that reach its sinks, so covert channels like timing and attempt counts are out of scope.

### 8. Decidable spec and lattice laws

`check_iff : check P l0 tr = true ↔ Spec P l0 tr` proves the Bool checker equals the Prop spec. The checker re-derives each position's history independently and is compiled into `nope-speccheck`, the oracle for the differential tests. `Conf`, `Integ` and `Label` are proven join-semilattices (`le_refl`, `le_trans`, `le_antisymm`, `le_sup_left`, `le_sup_right`, `sup_le`). [`Examples.lean`](../lean/Nope/Examples.lean) evaluates the demo scenarios in the kernel with `decide`.

## How the implementation is tested

| check | result |
|---|---|
| `lake build` | clean, no warnings |
| proof hygiene ([`tests/check_proofs.py`](../tests/check_proofs.py)), including noninterference | no `sorry`/`admit`/`axiom`; audit matches committed output |
| differential, engine tier | **12,000 random sessions, 237,697 events, 240 random manifests: 12,000/12,000 agree** |
| oracle mutation self-test | 500/500 single flipped verdicts or corrupted states caught |
| differential, MCP tier | **200 sessions, 4,154 events through `nope serve`: 0 spec disagreements, 0 denied calls reached the downstream, all 200 audit logs replay identically** |
| demo scenarios | 8/8 runs as specified, attacker log as evidence |
| audit-log replay | every demo, live-client and MCP-tier log re-checks against the spec |

The **differential test** ([`tests/differential.py`](../tests/differential.py)) generates random manifests and event sequences. Tool names and session ids include quotes, backslashes, tabs, CJK and emoji, to stress JSON. The engine tier drives sessions through the proxy's real `EngineClient`, with sessions sharing an engine running concurrently so their requests interleave. Every verdict *and every reported state* is judged by `nope-speccheck`, which uses only the independent spec. The engine tier also checks that malformed requests are never answered with a verdict.

The MCP tier runs sessions through the real `nope serve` in front of a stub MCP server that records every call it receives. It checks that verdicts agree with the spec, that the downstream received **exactly** the allowed calls (so a deny never reaches a server), and that the audit log replays to the same verdicts. Each MCP-tier session starts its own proxy, engine and stub processes, so it runs a few hundred sessions rather than 10,000.

Locally, `scripts/verify.sh` runs everything below and exits nonzero on any failure (`QUICK=1` for a fast subset).

CI ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) runs the build, proof hygiene, axiom audit, both differential tiers, and all demo scenarios against the real servers.

## Threat model and trusted computing base

**The model is fully adversarial.** The guarantees assume the model may emit any sequence of tool calls an attacker wants. They do not depend on the model noticing or refusing an injection. The demo uses a scripted agent that obeys every injection for exactly this reason.

**What you trust (TCB):**

- **The Lean kernel and compiler.** The proofs are checked by the kernel. The engine binary is the compiled monitor, so Lean's code generator and runtime are trusted.
- **The proxy plumbing (about 800 lines of Python).** It must faithfully pass each `tools/call` to the engine, forward only allowed calls, and run one session per proxy process. This is tested, not proven (see below).
- **The JSON codec** ([`Nope/Json.lean`](../lean/Nope/Json.lean)). It translates data and contains no decisions, but it is not proven.
- **The manifest labels.** Nope proves the policy is enforced, not that the policy is right. If `fetch` is labeled `argClearance = secret`, it will happily exfiltrate. A tool that writes to a store the agent can later read while tainted must label those reads `untrusted`, or taint can be laundered through storage. The demo manifest labels the writable public directory this way.
- **The approval channel.** Approvals go through a `0600` Unix socket. An agent with an unrestricted shell tool running as the same user could reach it. Do not give the agent tools that can talk to the control socket.

**Session-level taint is coarse, on purpose.** The label covers the whole session, not individual values. Once the agent reads untrusted content, every `requiresTrusted` action needs a human `endorse`. Once it reads a secret, every public sink needs a `declassify`. In scenario 1 even fetching the (harmless) attacker page is blocked after the secret is read, because the model *could* encode the secret in any URL. This tradeoff buys clean proofs and a simple mental model. Per-value tracking is v2.

**Out of scope for v1:**

- Per-value data tracking.
- Covert channels (timing, call counts, which tool is called).
- Tools that lie about their behavior.
- Side effects of a downstream tool beyond what its labels declare.
- Remote MCP transports (the proxy speaks stdio to the client).
- Taint across proxy restarts unless you pin `--session`. Reusing a session id replays its audit log into the engine to restore the label, and refuses if the manifest changed.

## Claude Code integration: what is proven, what is labeling

`nope setup claude-code` installs two hooks and turns on Claude Code's sandbox.

**Decided by the proven engine (Theorems 1-7):** every allow/deny. The `PreToolUse` hook maps each call to a manifest tool name and asks `nope-engine`, which runs `Monitor.step`. Session state is an append-only log per Claude session; each check replays it through the engine under a file lock. Every session log re-checks with `nope audit-check`.

**Labeling (trusted, tested, not proven):** the profile in [`proxy/nope/claude_code.py`](../proxy/nope/claude_code.py):

| call | label |
|---|---|
| `Read`/`Grep` of a secret file (`.env*`, keys, `~/.ssh`, `~/.aws`, ...) | secret |
| `Read` of personal identity (`~/.gitconfig`), `git config user.*`, `whoami` | internal |
| `Grep` | the label of what it would return: secret only if the pattern matches inside a secret file in scope |
| `WebFetch`, `WebSearch`, `curl`/`wget`/`gh`/`ssh`/cloud CLIs | untrusted output; public sink |
| other shell commands (tests, builds, local git) | public sink; protected unless the sandbox is on |
| `git push`, publish, deploy, `gh` writes, `sudo`, `rm -rf ~` | protected |
| writes to `CLAUDE.md`, `.mcp.json`, `.claude/`, shell rc files, `.git/hooks` | protected |
| writes to Nope's or Claude's settings, `nope approve` from the agent | always denied (manifest `deny` list) |
| unlisted tools (e.g. new MCP tools) | `defaultTool`: secret + untrusted output, public sink, protected |

**Output scan (`PostToolUse`):** after each tool runs, its output is searched for the values in your secret files and secret-looking environment variables (and for your git email at the personal level), raw and after decoding base64, hex, `xxd` dumps and URL encoding. A match records an `Output[secret]` read through the engine, raising the session label before the next call. Values stay in memory only. Limit: a value transformed so no piece of at least 8 characters survives intact (reversed, split) is not recognized. [`tests/redteam_bash.py`](../tests/redteam_bash.py) runs 28 disguised reads: 26 are caught, and the 2 deliberate scrambles are reported as known limits.

**Write memory:** if text the agent writes contains known secret values, the file is remembered as secret (in `~/.nope/claude-code/file-labels.json`) and later reads of it are secret. Files are not marked merely because the session was tainted, so ordinary edits never taint future sessions.

**Sandbox:** shell commands run in Claude Code's sandbox with a strict network allowlist (package registries, GitHub), cannot write Nope's or Claude's settings, cannot retry outside the sandbox, and Claude Code refuses to start if the sandbox is unavailable. This contains what happens *inside* one shell command, which Nope's per-call checks cannot see. Allowed hosts remain reachable from the shell.

**Evidence:** [`tests/test_claude_code.py`](../tests/test_claude_code.py) (22 scenarios, including the injection that made Claude Code send personal headers, laundering through files, parallel calls, fail-closed), [`tests/fuzz_hook.py`](../tests/fuzz_hook.py) (266 malformed and hostile payloads: never crashes, never allows what it cannot parse), and real Claude Code runs on everyday tasks with zero false blocks.

## Prior art

| | enforcement | verified? | deployment |
|---|---|---|---|
| **CaMeL** (Google DeepMind, ETH Zurich, 2025) | A privileged LLM writes a program from the user's query. An interpreter tracks per-value capabilities, and a quarantined LLM parses untrusted data. | No machine-checked proofs ("security by design" via the interpreter) | Research system; requires its own agent architecture |
| **FIDES** (Microsoft Research, 2025) | Planner tracking confidentiality and integrity labels, with primitives to hide or reveal values; deterministic policy checks | Formal model and paper proofs; no mechanized proof of the implementation that we found | Research planner and library (`microsoft/fides`) |
| **Invariant Guardrails / Gateway** (Invariant Labs, now Snyk) | Transparent LLM and MCP proxy with a rule language over traces, including flow rules from internal systems to untrusted sinks | No | Drop-in proxy, rules-based |
| **Cedar** (AWS) | Authorization language for applications | Lean models and proofs, plus differential testing against the Rust engine | Library or service; not agent- or MCP-specific |
| **Sluice** (`sluice-mcp` 0.1.0, 2026) | MCP proxy; fingerprints private tool output (winnowing) and scans sink arguments, including encoded ones | No | Drop-in MCP proxy |
| MCPKernel, MCP Shield and similar gateways | Policy rules, taint flags, approval queues | No | MCP gateways |
| **Nope** | Session-level IFC monitor over tool calls | **Enforcement core proven in Lean; the binary is that code; differential-tested end to end** | Drop-in MCP proxy for any stdio client |

What is new here is the combination: a machine-checked enforcement core that is literally the shipped decision engine, behind a drop-in proxy for unmodified MCP servers and clients. Cedar is the direct inspiration for the method (Lean proofs plus differential testing of the real system). CaMeL and FIDES are more expressive (per-value labels, quarantined parsing) but are agent architectures, not proxies, and neither ships a mechanized proof of its enforcement code. Sluice targets the same deployment point with a heuristic, value-level approach (it can catch leaks of specific content, and can miss transformed leaks); Nope is coarser but its guarantee does not depend on recognizing the data. No existing project we found ships formally verified enforcement for MCP. This survey was done in October 2026 and may be incomplete.

References:

- Debenedetti et al., *Defeating Prompt Injections by Design* (CaMeL), arXiv:2503.18813, 2025. Code: <https://github.com/google-research/camel-prompt-injection>
- Costa et al., *Securing AI Agents with Information-Flow Control* (FIDES), arXiv:2505.23643, 2025. <https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/>
- Invariant Labs, *Guardrails*. <https://invariantlabs.ai/blog/guardrails>, Gateway docs: <https://explorer.invariantlabs.ai/docs/guardrails/gateway>
- Disselkoen et al., *How We Built Cedar: A Verification-Guided Approach*, arXiv:2407.01688, 2024. <https://github.com/cedar-policy>
- Sluice: <https://pypi.org/project/sluice-mcp/>, <https://github.com/premm25/sluice>
- MCPKernel: <https://github.com/piyushptiwari1/mcpkernel>
- Willison, *CaMeL offers a promising new direction for mitigating prompt injection attacks*, 2025. <https://simonwillison.net/2025/Apr/11/camel/>

