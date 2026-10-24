import Nope.Monitor

/-!
# Independent trace specification

Defined by direct recursion over the trace. Nothing here mentions `Monitor.step`,
so the soundness proofs relating the two are not circular.

For a call at position `i` of an executed trace, the *history* is the events before
`i`, most recent first. `confSince` scans that history backwards, joining the
confidentiality of every result read, and stops at the most recent `declassify`.
`integSince` does the same for integrity and stops at the most recent `endorse`.
-/

namespace Nope
namespace Spec

/-- Label of a tool's result as declared in the manifest. Unknown tools are treated
as top; they can never appear in a trace that satisfies the spec anyway. -/
def readLabel (P : Manifest) (t : String) : Label :=
  match P t with
  | some tool => tool.outLabel
  | none => ⟨.secret, .untrusted⟩

/-- Confidentiality of everything read since the last `declassify`
(history is most-recent-first; `c0` is the session's starting confidentiality). -/
def confSince (P : Manifest) (c0 : Conf) : List Event → Conf
  | [] => c0
  | .call t :: older => max (confSince P c0 older) (readLabel P t).conf
  | .declassify c :: _ => c
  | .endorse :: older => confSince P c0 older

/-- Integrity of everything read since the last `endorse`. -/
def integSince (P : Manifest) (i0 : Integ) : List Event → Integ
  | [] => i0
  | .call t :: older => max (integSince P i0 older) (readLabel P t).integ
  | .endorse :: _ => .trusted
  | .declassify _ :: older => integSince P i0 older

/-- Events strictly before position `i`, most recent first. -/
def history (tr : List Event) (i : Nat) : List Event := (tr.take i).reverse

/-- Confidentiality spec: every call is to a known tool, and everything read since
the last declassification is within the tool's argument clearance. -/
def ConfOK (P : Manifest) (l0 : Label) (tr : List Event) : Prop :=
  ∀ i t, tr[i]? = some (.call t) →
    ∃ tool, P t = some tool ∧ confSince P l0.conf (history tr i) ≤ tool.argClearance

/-- Integrity spec: a `requiresTrusted` tool only runs if nothing untrusted was read
since the last endorsement. -/
def IntegOK (P : Manifest) (l0 : Label) (tr : List Event) : Prop :=
  ∀ i t tool, tr[i]? = some (.call t) → P t = some tool → tool.requiresTrusted = true →
    integSince P l0.integ (history tr i) = .trusted

def Spec (P : Manifest) (l0 : Label) (tr : List Event) : Prop :=
  ConfOK P l0 tr ∧ IntegOK P l0 tr

/-! ## Decidable checker -/

/-- Is `call t` permitted after the given (most-recent-first) history? -/
def callOK (P : Manifest) (l0 : Label) (hist : List Event) (t : String) : Bool :=
  match P t with
  | none => false
  | some tool =>
    decide (confSince P l0.conf hist ≤ tool.argClearance) &&
      (!tool.requiresTrusted || decide (integSince P l0.integ hist = .trusted))

/-- Bool-valued spec checker: checks every position independently. -/
def check (P : Manifest) (l0 : Label) (tr : List Event) : Bool :=
  (List.range tr.length).all fun i =>
    match tr[i]? with
    | some (.call t) => callOK P l0 (history tr i) t
    | _ => true

end Spec
end Nope
