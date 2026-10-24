import Nope.Theorems
import Nope.Examples

/-!
# Noninterference

The theorems in `Theorems.lean` relate the monitor to a trace spec over labels. This
file proves the end-to-end property those labels are meant to buy, stated over
**data**:

* An *agent* is an arbitrary function from everything it has observed so far
  (tool, argument, result or denial, for every attempted call) to its next call.
  Nothing is assumed about it; it may be fully controlled by an attacker.
* A *world* fixes what every tool returns, for every step and argument.
* An observer watches a set of sinks and sees the tool and argument of every call
  that actually reached one of them.

**Confidentiality** (`noninterference_conf`): run any agent in two worlds that agree
on every result whose confidentiality is at most `o`. The calls reaching sinks with
clearance at most `o` are identical, tool for tool and argument for argument. Results
above `o` cannot influence anything an observer at level `o` sees.

**Integrity** (`noninterference_integ`): run any agent in two worlds that agree on
every trusted result. The calls reaching `requiresTrusted` tools are identical.
Untrusted content (an injected web page, email, file) cannot influence which protected
action runs or with what arguments.

Both are instances of one generic theorem (`noninterference`) about any "barrier":
reading high data blocks the session, blocking persists, and a blocked session cannot
reach the observed sinks.

Scope: runs consist of agent calls only. Human approvals (`declassify`, `endorse`) are
the explicit, logged release mechanism and are deliberately outside these theorems. A
world's results depend on the step, tool and argument; a tool whose results depend on
what was written to it earlier must be labeled accordingly (see the README's note on
laundering through storage). Covert channels (timing, the number of attempts) are out
of scope: the observer sees only calls that reach its sinks.
-/

namespace Nope
namespace NI
open Monitor

/-- What the agent sees after each attempted call. -/
structure Obs (D : Type) where
  tool : String
  arg : D
  /-- `some r` if the call was allowed and returned `r`; `none` if it was denied. -/
  res : Option D

/-- An agent: any function from its observations so far to its next call
(tool name and argument). No assumptions are made about it. -/
def Agent (D : Type) := List (Obs D) → String × D

/-- A world: the result each tool returns, given the step index and the argument. -/
def World (D : Type) := Nat → String → D → D

variable {D : Type} {P : Manifest}

/-- Run an agent for `n` steps through the monitor. Denied calls never reach the
world; the agent sees the denial. Returns the full observation history. -/
def exec (P : Manifest) (W : World D) (A : Agent D) :
    Nat → State → List (Obs D) → List (Obs D) × State
  | 0, s, h => (h, s)
  | n + 1, s, h =>
    exec P W A n (step P s (.call (A h).1)).2
      (h ++ [⟨(A h).1, (A h).2,
        if (step P s (.call (A h).1)).1.isAllow then some (W h.length (A h).1 (A h).2)
        else none⟩])

/-- Did this observation reach an observed sink? -/
def visible (P : Manifest) (sink : Tool → Bool) (o : Obs D) : Bool :=
  o.res.isSome && match P o.tool with
    | some tool => sink tool
    | none => false

/-- The observer's view: tool and argument of every call that reached a sink. -/
def view (P : Manifest) (sink : Tool → Bool) (h : List (Obs D)) : List (String × D) :=
  (h.filter (visible P sink)).map fun o => (o.tool, o.arg)

/-- Two worlds agree on everything that is not high. -/
def Agree (P : Manifest) (high : Tool → Bool) (W₁ W₂ : World D) : Prop :=
  ∀ i t tool a, P t = some tool → high tool = false → W₁ i t a = W₂ i t a

/-- A barrier: reading a high result blocks the session, blocking persists across
calls, and a blocked session cannot reach an observed sink. -/
structure Barrier (P : Manifest) (high sink : Tool → Bool) (Blocked : State → Prop) : Prop where
  taints : ∀ s t tool, P t = some tool → high tool = true →
    (step P s (.call t)).1 = .allow → Blocked (step P s (.call t)).2
  persists : ∀ s t, Blocked s → Blocked (step P s (.call t)).2
  seals : ∀ s t tool, Blocked s → P t = some tool → sink tool = true →
    (step P s (.call t)).1 ≠ .allow

theorem view_snoc (sink : Tool → Bool) (h : List (Obs D)) (o : Obs D) :
    view P sink (h ++ [o]) =
      view P sink h ++ (if visible P sink o then [(o.tool, o.arg)] else []) := by
  unfold view
  rw [List.filter_append, List.map_append]
  cases hv : visible P sink o <;> simp [hv]

theorem visible_res_irrel (sink : Tool → Bool) (t : String) (a : D) (r₁ r₂ : Option D)
    (h : r₁.isSome = r₂.isSome) :
    visible P sink ⟨t, a, r₁⟩ = visible P sink ⟨t, a, r₂⟩ := by
  simp [visible, h]

/-- **Generic noninterference.** Starting from related configurations (identical, or
both blocked with equal views), any agent produces equal views in the two worlds. -/
theorem noninterference_gen {high sink : Tool → Bool} {Blocked : State → Prop}
    (hb : Barrier P high sink Blocked) {W₁ W₂ : World D} (hW : Agree P high W₁ W₂)
    (A : Agent D) :
    ∀ (n : Nat) (s₁ s₂ : State) (h₁ h₂ : List (Obs D)),
      ((s₁ = s₂ ∧ h₁ = h₂) ∨ (Blocked s₁ ∧ Blocked s₂ ∧ view P sink h₁ = view P sink h₂)) →
      view P sink (exec P W₁ A n s₁ h₁).1 = view P sink (exec P W₂ A n s₂ h₂).1
  | 0, s₁, s₂, h₁, h₂, hr => by
    rcases hr with ⟨rfl, rfl⟩ | ⟨-, -, hv⟩
    · rfl
    · exact hv
  | n + 1, s₁, s₂, h₁, h₂, hr => by
    simp only [exec]
    rcases hr with ⟨rfl, rfl⟩ | ⟨hb₁, hb₂, hv⟩
    · -- Identical so far: same call, same verdict.
      by_cases ha : (step P s₁ (.call (A h₁).1)).1 = .allow
      · obtain ⟨tool, hP, -⟩ := (step_call_allow_iff s₁ _).mp ha
        cases hh : high tool
        · -- Low result: the two worlds return the same value.
          have hw := hW h₁.length (A h₁).1 tool (A h₁).2 hP hh
          refine noninterference_gen hb hW A n _ _ _ _ (.inl ⟨rfl, ?_⟩)
          simp [hw]
        · -- High result: the session becomes blocked; the views still agree.
          have hB := hb.taints s₁ _ tool hP hh ha
          refine noninterference_gen hb hW A n _ _ _ _ (.inr ⟨hB, hB, ?_⟩)
          rw [view_snoc, view_snoc]
          simp only [ha, Verdict.isAllow, ite_true]
          rw [visible_res_irrel sink _ _ (some (W₁ _ _ _)) (some (W₂ _ _ _)) rfl]
      · have hf : (step P s₁ (.call (A h₁).1)).1.isAllow = false := by
          cases hv : (step P s₁ (.call (A h₁).1)).1 <;> simp_all [Verdict.isAllow]
        exact noninterference_gen hb hW A n _ _ _ _ (.inl ⟨rfl, by simp [hf]⟩)
    · -- Both blocked: nothing new becomes visible, and both stay blocked.
      have hnv : ∀ (s : State) (h : List (Obs D)) (W : World D), Blocked s →
          visible P sink ⟨(A h).1, (A h).2,
            if (step P s (.call (A h).1)).1.isAllow then some (W h.length (A h).1 (A h).2)
            else none⟩ = false := by
        intro s h W hbs
        by_cases ha : (step P s (.call (A h).1)).1 = .allow
        · obtain ⟨tool, hP, -⟩ := (step_call_allow_iff s _).mp ha
          cases hs : sink tool
          · simp [visible, hP, hs]
          · exact absurd ha (hb.seals s _ tool hbs hP hs)
        · have hf : (step P s (.call (A h).1)).1.isAllow = false := by
            cases hv : (step P s (.call (A h).1)).1 <;> simp_all [Verdict.isAllow]
          simp [visible, hf]
      refine noninterference_gen hb hW A n _ _ _ _
        (.inr ⟨hb.persists s₁ _ hb₁, hb.persists s₂ _ hb₂, ?_⟩)
      rw [view_snoc, view_snoc, hnv s₁ h₁ W₁ hb₁, hnv s₂ h₂ W₂ hb₂]
      simpa using hv

/-- **Generic noninterference** from a common start. -/
theorem noninterference {high sink : Tool → Bool} {Blocked : State → Prop}
    (hb : Barrier P high sink Blocked) {W₁ W₂ : World D} (hW : Agree P high W₁ W₂)
    (A : Agent D) (n : Nat) (s : State) :
    view P sink (exec P W₁ A n s []).1 = view P sink (exec P W₂ A n s []).1 :=
  noninterference_gen hb hW A n s s [] [] (.inl ⟨rfl, rfl⟩)

/-! ## Confidentiality -/

/-- Observer at level `o` watches every sink cleared for at most `o`. -/
def lowSink (o : Conf) (tool : Tool) : Bool := decide (tool.argClearance ≤ o)

def confHigh (o : Conf) (tool : Tool) : Bool := !decide (tool.outLabel.conf ≤ o)

theorem conf_barrier (o : Conf) :
    Barrier P (confHigh o) (lowSink o) (fun s => ¬ s.ctx.conf ≤ o) where
  taints s t tool hP hh ha := by
    rw [step_call_allow_state s t tool hP ha]
    intro hle
    have : tool.outLabel.conf ≤ o :=
      Conf.le_trans (Conf.le_sup_right s.ctx.conf tool.outLabel.conf) hle
    simp [confHigh, this] at hh
  persists s t hbs hle := hbs (Conf.le_trans (call_monotone (P := P) s t).1 hle)
  seals s t tool hbs hP hs ha := by
    obtain ⟨tool', hP', hc, -⟩ := (step_call_allow_iff s t).mp ha
    rw [hP] at hP'; cases hP'
    exact hbs (Conf.le_trans hc (by simpa [lowSink] using hs))

/-- **Theorem 6 (Noninterference, confidentiality).** For any agent, however
adversarial, and any two worlds that agree on every result of confidentiality at most
`o`: the tool and argument of every call reaching a sink cleared for at most `o` are
identical in both runs. Data above `o` cannot reach, or influence, a sink at `o`. -/
theorem noninterference_conf (o : Conf) (W₁ W₂ : World D)
    (hW : ∀ i t tool a, P t = some tool → tool.outLabel.conf ≤ o → W₁ i t a = W₂ i t a)
    (A : Agent D) (n : Nat) (s : State) :
    view P (lowSink o) (exec P W₁ A n s []).1 = view P (lowSink o) (exec P W₂ A n s []).1 :=
  noninterference (conf_barrier o)
    (fun i t tool a hP hh => hW i t tool a hP (by simpa [confHigh] using hh)) A n s

/-! ## Integrity -/

def untrustedOut (tool : Tool) : Bool := decide (tool.outLabel.integ = .untrusted)

def protectedSink (tool : Tool) : Bool := tool.requiresTrusted

theorem integ_barrier :
    Barrier P untrustedOut protectedSink (fun s => s.ctx.integ = .untrusted) where
  taints s t tool hP hh ha := by
    rw [step_call_allow_state s t tool hP ha]
    have : tool.outLabel.integ = .untrusted := by simpa [untrustedOut] using hh
    show max s.ctx.integ tool.outLabel.integ = .untrusted
    rw [this, Integ.sup_untrusted]
  persists s t hbs := by
    have h := (call_monotone (P := P) s t).2
    rw [hbs] at h
    revert h
    cases (step P s (.call t)).2.ctx.integ <;> decide
  seals s t tool hbs hP hs ha := by
    obtain ⟨tool', hP', -, hi⟩ := (step_call_allow_iff s t).mp ha
    rw [hP] at hP'; cases hP'
    have := hi hs
    simp only [Spec.integSince] at this
    rw [hbs] at this
    cases this

/-- **Theorem 7 (Noninterference, integrity).** For any agent, however adversarial,
and any two worlds that agree on every trusted result: the tool and argument of every
call reaching a `requiresTrusted` tool are identical in both runs. Untrusted content
cannot influence which protected action runs or with what arguments. -/
theorem noninterference_integ (W₁ W₂ : World D)
    (hW : ∀ i t tool a, P t = some tool → tool.outLabel.integ = .trusted →
      W₁ i t a = W₂ i t a)
    (A : Agent D) (n : Nat) (s : State) :
    view P protectedSink (exec P W₁ A n s []).1 = view P protectedSink (exec P W₂ A n s []).1 :=
  noninterference integ_barrier
    (fun i t tool a hP hh => hW i t tool a hP (by
      revert hh; simp only [untrustedOut]; cases tool.outLabel.integ <;> decide))
    A n s

end NI
end Nope

/-! ## Concrete checks

Kernel-evaluated examples on the demo manifest, so the views above are visibly
non-trivial: benign runs do reach sinks, and attacking agents are cut off. -/

namespace Nope.NI.Examples

/-- The demo manifest from `Examples.lean`. -/
abbrev M : Manifest := Nope.Examples.P
open Nope.Monitor (init)

/-- An exfiltrating agent: read the secret, then put whatever came back into a fetch. -/
def exfil : Agent Nat := fun
  | [] => ("fs_secret__read_file", 0)
  | o :: _ => ("fetch__fetch", o.res.getD 999)

/-- A world whose secret file holds `k`. -/
def secretWorld (k : Nat) : World Nat := fun _ t _ => if t = "fs_secret__read_file" then k else 0

/-- Under Nope the public observer sees nothing, whatever the secret is. -/
example : view M (lowSink .pub) (exec M (secretWorld 41) exfil 2 init []).1 = [] := by decide
example : view M (lowSink .pub) (exec M (secretWorld 42) exfil 2 init []).1 = [] := by decide

/-- A benign agent that fetches first does reach the public sink. -/
def fetchFirst : Agent Nat := fun _ => ("fetch__fetch", 7)
example : view M (lowSink .pub) (exec M (secretWorld 41) fetchFirst 2 init []).1 =
    [("fetch__fetch", 7), ("fetch__fetch", 7)] := by decide

/-- An injected agent: fetch a page, then commit whatever the page said. -/
def injected : Agent Nat := fun
  | [] => ("fetch__fetch", 0)
  | o :: _ => ("git__git_commit", o.res.getD 999)

/-- A world whose fetched page says `k`. -/
def pageWorld (k : Nat) : World Nat := fun _ t _ => if t = "fetch__fetch" then k else 0

/-- The injected commit never reaches the protected tool, whatever the page says. -/
example : view M protectedSink (exec M (pageWorld 1) injected 2 init []).1 = [] := by decide
example : view M protectedSink (exec M (pageWorld 2) injected 2 init []).1 = [] := by decide

/-- A commit made before reading anything untrusted goes through. -/
def commitFirst : Agent Nat := fun _ => ("git__git_commit", 5)
example : view M protectedSink (exec M (pageWorld 1) commitFirst 1 init []).1 =
    [("git__git_commit", 5)] := by decide

end Nope.NI.Examples
