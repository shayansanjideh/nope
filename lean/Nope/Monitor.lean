import Nope.Labels

/-!
# Monitor

The reference monitor. This exact code is compiled into `nope-engine`.
-/

namespace Nope

/-- Per-tool declarations from the manifest. -/
structure Tool where
  /-- Taint added to the context when the agent reads this tool's result. -/
  outLabel : Label
  /-- Highest confidentiality the tool's arguments may carry. -/
  argClearance : Conf
  /-- May only run while the context is trusted (untainted). -/
  requiresTrusted : Bool
  deriving DecidableEq, Repr, Inhabited

/-- A manifest maps tool names to declarations. `none` = unknown tool = denied. -/
def Manifest := String → Option Tool

inductive Event where
  /-- The agent requests tool `t`. -/
  | call (t : String)
  /-- Human approval lowering context confidentiality to `c`. -/
  | declassify (c : Conf)
  /-- Human approval resetting context integrity to `trusted`. -/
  | endorse
  deriving DecidableEq, Repr, Inhabited

inductive DenyReason where
  /-- Tool not in the manifest (deny by default). -/
  | unknownTool (t : String)
  /-- Context confidentiality exceeds the tool's argument clearance. -/
  | confTooHigh (t : String) (ctx : Conf) (clearance : Conf)
  /-- Tool requires a trusted context but the context is tainted. -/
  | untrustedContext (t : String)
  deriving DecidableEq, Repr

inductive Verdict where
  | allow
  | deny (r : DenyReason)
  deriving DecidableEq, Repr

def Verdict.isAllow : Verdict → Bool
  | .allow => true
  | .deny _ => false

structure State where
  ctx : Label
  deriving DecidableEq, Repr, Inhabited

namespace Monitor

/-- Start state of a fresh session: public, trusted. -/
def init : State := ⟨Label.bot⟩

/-- One monitor step.

`call t` is allowed iff `t` is in the manifest, `ctx.conf ≤ t.argClearance`, and
(`t.requiresTrusted → ctx.integ = trusted`). If allowed, the result is read and the
context absorbs `t.outLabel`. If denied, the state is unchanged. Approvals are the
only events that lower the context. -/
def step (P : Manifest) (s : State) : Event → Verdict × State
  | .call t =>
    match P t with
    | none => (.deny (.unknownTool t), s)
    | some tool =>
      if s.ctx.conf ≤ tool.argClearance then
        if tool.requiresTrusted = true ∧ s.ctx.integ ≠ .trusted then
          (.deny (.untrustedContext t), s)
        else
          (.allow, ⟨max s.ctx tool.outLabel⟩)
      else
        (.deny (.confTooHigh t s.ctx.conf tool.argClearance), s)
  | .declassify c => (.allow, ⟨{ s.ctx with conf := c }⟩)
  | .endorse => (.allow, ⟨{ s.ctx with integ := .trusted }⟩)

def run (P : Manifest) : State → List Event → List Verdict × State
  | s, [] => ([], s)
  | s, e :: es =>
    let r := run P (step P s e).2 es
    ((step P s e).1 :: r.1, r.2)

/-- The events that actually took effect (denied calls are dropped). -/
def executed (P : Manifest) : State → List Event → List Event
  | _, [] => []
  | s, e :: es =>
    (if (step P s e).1.isAllow then [e] else []) ++ executed P (step P s e).2 es

/-- Every event in the trace was allowed. -/
def allAllowed (P : Manifest) (s : State) (es : List Event) : Prop :=
  ∀ v ∈ (run P s es).1, v.isAllow = true

end Monitor
end Nope
