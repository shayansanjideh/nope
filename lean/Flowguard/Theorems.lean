import Flowguard.Spec

/-!
# Theorems

1. Soundness (confidentiality)      `soundness`, `soundness_executed`, `conf_between`
2. Integrity                        `integrity`, `integrity_executed`, `integrity_between`
3. Precision                        `precision`, `monitor_exact`
4. Approvals are the only downgrade `call_monotone`, `downgrade_only_by_approval`,
                                    `run_calls_monotone`
5. Policy monotonicity              `policy_monotone`
Plus: the Bool checker agrees with the Prop spec (`check_iff`).
-/

namespace Flowguard
open Spec Monitor

variable {P : Manifest}

/-! ## Spec-side lemmas -/

theorem confSince_append (P : Manifest) (c0 : Conf) (A B : List Event) :
    confSince P c0 (A ++ B) = confSince P (confSince P c0 B) A := by
  induction A with
  | nil => rfl
  | cons e A ih => cases e <;> simp [confSince, ih]

theorem integSince_append (P : Manifest) (i0 : Integ) (A B : List Event) :
    integSince P i0 (A ++ B) = integSince P (integSince P i0 B) A := by
  induction A with
  | nil => rfl
  | cons e A ih => cases e <;> simp [integSince, ih]

/-- Combined per-call obligation. -/
def CallOK (P : Manifest) (l0 : Label) (hist : List Event) (t : String) : Prop :=
  ∃ tool, P t = some tool ∧ confSince P l0.conf hist ≤ tool.argClearance ∧
    (tool.requiresTrusted = true → integSince P l0.integ hist = .trusted)

theorem spec_iff_calls (l0 : Label) (tr : List Event) :
    Spec P l0 tr ↔ ∀ i t, tr[i]? = some (.call t) → CallOK P l0 (history tr i) t := by
  constructor
  · rintro ⟨hc, hi⟩ i t h
    obtain ⟨tool, hP, hle⟩ := hc i t h
    exact ⟨tool, hP, hle, hi i t tool h hP⟩
  · intro H
    refine ⟨fun i t h => ?_, fun i t tool h hP hr => ?_⟩
    · obtain ⟨tool, hP, hle, _⟩ := H i t h
      exact ⟨tool, hP, hle⟩
    · obtain ⟨tool', hP', _, hi⟩ := H i t h
      rw [hP] at hP'
      cases hP'
      exact hi hr

/-- The spec-side label after one more event (used only to relate positions). -/
def after (P : Manifest) (l : Label) (e : Event) : Label :=
  ⟨confSince P l.conf [e], integSince P l.integ [e]⟩

theorem callOK_shift (l0 : Label) (H : List Event) (e : Event) (t : String) :
    CallOK P l0 (H ++ [e]) t ↔ CallOK P (after P l0 e) H t := by
  simp only [CallOK, confSince_append, integSince_append, after]

theorem history_zero (tr : List Event) : history tr 0 = [] := by
  simp [history]

theorem history_succ (e : Event) (tr : List Event) (i : Nat) :
    history (e :: tr) (i + 1) = history tr i ++ [e] := by
  simp [history]

theorem spec_nil (l0 : Label) : Spec P l0 [] := by
  rw [spec_iff_calls]; intro i t h; simp at h

theorem spec_cons (l0 : Label) (e : Event) (tr : List Event) :
    Spec P l0 (e :: tr) ↔
      (∀ t, e = .call t → CallOK P l0 [] t) ∧ Spec P (after P l0 e) tr := by
  simp only [spec_iff_calls]
  constructor
  · intro H
    refine ⟨fun t he => ?_, fun i t h => ?_⟩
    · have := H 0 t (by simp [he])
      rwa [history_zero] at this
    · have := H (i + 1) t (by simpa using h)
      rwa [history_succ, callOK_shift] at this
  · rintro ⟨H0, H⟩ i t h
    cases i with
    | zero =>
      rw [history_zero]
      exact H0 t (by simpa using h)
    | succ i =>
      rw [history_succ, callOK_shift]
      exact H i t (by simpa using h)

/-- Positional lemma: the obligation at the event right after prefix `A`. -/
theorem spec_at (l0 : Label) (A R : List Event) (t : String)
    (h : Spec P l0 (A ++ .call t :: R)) : CallOK P l0 A.reverse t := by
  rw [spec_iff_calls] at h
  have := h A.length t (by simp)
  simpa [history] using this

/-! ## Monitor-side lemmas -/

theorem step_call_allow_iff (s : State) (t : String) :
    (step P s (.call t)).1 = .allow ↔ CallOK P s.ctx [] t := by
  cases hP : P t with
  | none => simp [step, hP, CallOK]
  | some tool =>
    simp only [step, hP, CallOK, confSince, integSince, Option.some.injEq, exists_eq_left']
    by_cases hc : s.ctx.conf ≤ tool.argClearance
    · rw [ite_eq_left hc]
      by_cases hr : tool.requiresTrusted = true ∧ s.ctx.integ ≠ .trusted
      · rw [ite_eq_left hr]
        simp only [reduceCtorEq, false_iff, not_and]
        intro _ h; exact hr.2 (h hr.1)
      · rw [ite_eq_right hr]
        simp only [true_iff]
        exact ⟨hc, fun hreq => Classical.byContradiction fun hne => hr ⟨hreq, hne⟩⟩
    · rw [ite_eq_right hc]
      simp [hc]

theorem step_call_allow_state (s : State) (t : String) (tool : Tool) (hP : P t = some tool)
    (h : (step P s (.call t)).1 = .allow) :
    (step P s (.call t)).2.ctx = max s.ctx tool.outLabel := by
  simp only [step, hP] at h ⊢
  by_cases hc : s.ctx.conf ≤ tool.argClearance
  · rw [ite_eq_left hc] at h ⊢
    by_cases hr : tool.requiresTrusted = true ∧ s.ctx.integ ≠ .trusted
    · rw [ite_eq_left hr] at h; simp at h
    · rw [ite_eq_right hr]
  · rw [ite_eq_right hc] at h; simp at h

theorem step_allow_state (s : State) (e : Event) (h : (step P s e).1 = .allow) :
    (step P s e).2.ctx = after P s.ctx e := by
  cases e with
  | call t =>
    obtain ⟨tool, hP, -⟩ := (step_call_allow_iff s t).mp h
    rw [step_call_allow_state s t tool hP h]
    simp [after, confSince, integSince, readLabel, hP]
    rfl
  | declassify c => simp [step, after, confSince, integSince]
  | endorse => simp [step, after, confSince, integSince]

theorem step_deny_state (s : State) (e : Event) (h : (step P s e).1 ≠ .allow) :
    (step P s e).2 = s := by
  cases e with
  | call t =>
    cases hP : P t with
    | none => simp [step, hP]
    | some tool =>
      simp only [step, hP] at h ⊢
      by_cases hc : s.ctx.conf ≤ tool.argClearance
      · rw [ite_eq_left hc] at h ⊢
        by_cases hr : tool.requiresTrusted = true ∧ s.ctx.integ ≠ .trusted
        · rw [ite_eq_left hr]
        · rw [ite_eq_right hr] at h; exact absurd rfl h
      · rw [ite_eq_right hc]
  | declassify c => exact absurd rfl h
  | endorse => exact absurd rfl h

theorem isAllow_iff (v : Verdict) : v.isAllow = true ↔ v = .allow := by
  cases v <;> simp [Verdict.isAllow]

theorem allAllowed_nil (s : State) : allAllowed P s [] := by
  intro v hv; simp [run] at hv

theorem allAllowed_cons (s : State) (e : Event) (es : List Event) :
    allAllowed P s (e :: es) ↔
      (step P s e).1 = .allow ∧ allAllowed P (step P s e).2 es := by
  simp [allAllowed, run, isAllow_iff]

theorem executed_of_allAllowed :
    ∀ (s : State) (es : List Event), allAllowed P s es → executed P s es = es
  | _, [], _ => rfl
  | s, e :: es, h => by
    obtain ⟨h1, h2⟩ := (allAllowed_cons s e es).mp h
    simp [executed, h1, Verdict.isAllow, executed_of_allAllowed _ es h2]

theorem executed_append :
    ∀ (s : State) (a b : List Event),
      executed P s (a ++ b) = executed P s a ++ executed P (run P s a).2 b
  | _, [], _ => rfl
  | s, e :: a, b => by
    simp only [List.cons_append, executed, run, executed_append _ a b, List.append_assoc]

/-! ## 1. Soundness -/

/-- Core lemma: the executed trace of any run satisfies the full spec. -/
theorem executed_spec : ∀ (s : State) (es : List Event), Spec P s.ctx (executed P s es)
  | s, [] => spec_nil _
  | s, e :: es => by
    simp only [executed]
    by_cases h : (step P s e).1 = .allow
    · simp only [h, Verdict.isAllow, ite_true, List.singleton_append]
      refine (spec_cons _ _ _).mpr ⟨fun t he => ?_, ?_⟩
      · subst he; exact (step_call_allow_iff s t).mp h
      · rw [← step_allow_state s e h]; exact executed_spec _ es
    · have hf : (step P s e).1.isAllow = false := by
        cases hv : (step P s e).1 <;> simp_all [Verdict.isAllow]
      simp only [hf, Bool.false_eq_true, ite_false, List.nil_append]
      have := executed_spec (step P s e).2 es
      rw [step_deny_state s e h] at this ⊢
      exact this

/-- **Theorem 1 (Soundness).** Every trace the monitor allows satisfies the
confidentiality spec. -/
theorem soundness (s : State) (es : List Event) (h : allAllowed P s es) :
    ConfOK P s.ctx es := by
  have := (executed_spec (P := P) s es).1
  rwa [executed_of_allAllowed s es h] at this

/-- Soundness for arbitrary traces: the events that actually execute (denied calls
dropped) always satisfy the confidentiality spec. -/
theorem soundness_executed (s : State) (es : List Event) :
    ConfOK P s.ctx (executed P s es) :=
  (executed_spec s es).1

theorem conf_ge_of_no_declassify (c0 : Conf) :
    ∀ (L : List Event), (∀ c, .declassify c ∉ L) → c0 ≤ confSince P c0 L
  | [], _ => Conf.le_refl _
  | .call t :: L, h =>
    Conf.le_trans (conf_ge_of_no_declassify c0 L (fun c hc => h c (by simp [hc])))
      (Conf.le_sup_left _ _)
  | .declassify c :: _, h => absurd (by simp) (h c)
  | .endorse :: L, h => conf_ge_of_no_declassify c0 L (fun c hc => h c (by simp [hc]))

/-- Soundness, positional form: if a result is read whose confidentiality exceeds a
later tool's argument clearance, a human `declassify` happened in between. -/
theorem conf_between (s : State) (es B C R : List Event) (u t : String) (tu tt : Tool)
    (hex : executed P s es = B ++ .call u :: C ++ .call t :: R)
    (hu : P u = some tu) (ht : P t = some tt)
    (hlab : ¬ tu.outLabel.conf ≤ tt.argClearance) :
    ∃ c, .declassify c ∈ C := by
  refine Classical.byContradiction fun hno => hlab ?_
  have hspec := executed_spec (P := P) s es
  rw [hex, show B ++ .call u :: C ++ .call t :: R = (B ++ .call u :: C) ++ .call t :: R by simp]
    at hspec
  obtain ⟨tool, hP, hle, -⟩ := spec_at _ _ _ _ hspec
  rw [ht] at hP; cases hP
  simp only [List.reverse_append, List.reverse_cons, List.append_assoc, List.singleton_append,
    confSince_append] at hle
  have hno' : ∀ c, .declassify c ∉ C.reverse := by
    intro c hc; exact hno ⟨c, List.mem_reverse.mp hc⟩
  refine Conf.le_trans ?_ (Conf.le_trans (conf_ge_of_no_declassify _ _ hno') hle)
  simp only [confSince, readLabel, hu]
  exact Conf.le_sup_right _ _

/-! ## 2. Integrity -/

/-- **Theorem 2 (Integrity).** In any allowed trace, every `requiresTrusted` call
happens with nothing untrusted read since the last endorsement. -/
theorem integrity (s : State) (es : List Event) (h : allAllowed P s es) :
    IntegOK P s.ctx es := by
  have := (executed_spec (P := P) s es).2
  rwa [executed_of_allAllowed s es h] at this

theorem integrity_executed (s : State) (es : List Event) :
    IntegOK P s.ctx (executed P s es) :=
  (executed_spec s es).2

theorem integ_untrusted_of_no_endorse :
    ∀ (L : List Event), .endorse ∉ L → integSince P .untrusted L = .untrusted
  | [], _ => rfl
  | .call t :: L, h => by
    simp only [integSince, integ_untrusted_of_no_endorse L (fun hc => h (by simp [hc]))]
    rfl
  | .declassify c :: L, h => integ_untrusted_of_no_endorse L (fun hc => h (by simp [hc]))
  | .endorse :: _, h => absurd (by simp) h

/-- **Theorem 2 (Integrity), literal form.** If the executed trace reads an untrusted
result and later runs a `requiresTrusted` tool, an `endorse` occurs in between. -/
theorem integrity_between (s : State) (es B C R : List Event) (u t : String) (tu tt : Tool)
    (hex : executed P s es = B ++ .call u :: C ++ .call t :: R)
    (hu : P u = some tu) (huntrusted : tu.outLabel.integ = .untrusted)
    (ht : P t = some tt) (hreq : tt.requiresTrusted = true) :
    .endorse ∈ C := by
  refine Classical.byContradiction fun hno => ?_
  have hspec := executed_spec (P := P) s es
  rw [hex, show B ++ .call u :: C ++ .call t :: R = (B ++ .call u :: C) ++ .call t :: R by simp]
    at hspec
  obtain ⟨tool, hP, -, hi⟩ := spec_at _ _ _ _ hspec
  rw [ht] at hP; cases hP
  have hi := hi hreq
  simp only [List.reverse_append, List.reverse_cons, List.append_assoc, List.singleton_append,
    integSince_append] at hi
  have hmid : integSince P s.ctx.integ (.call u :: B.reverse) = .untrusted := by
    simp only [integSince, readLabel, hu, huntrusted]
    exact Integ.sup_untrusted _
  rw [hmid, integ_untrusted_of_no_endorse _ (fun hc => hno (List.mem_reverse.mp hc))] at hi
  cases hi

/-! ## 3. Precision -/

/-- **Theorem 3 (Precision).** If the spec permits extending the executed trace with
`call t`, the monitor allows it. -/
theorem precision :
    ∀ (s : State) (es : List Event) (t : String),
      Spec P s.ctx (executed P s es ++ [.call t]) → (step P (run P s es).2 (.call t)).1 = .allow
  | s, [], t, h => by
    have := ((spec_cons (P := P) s.ctx (.call t) []).mp h).1 t rfl
    exact (step_call_allow_iff s t).mpr this
  | s, e :: es, t, h => by
    simp only [executed, run] at h ⊢
    by_cases ha : (step P s e).1 = .allow
    · simp only [ha, Verdict.isAllow, ite_true, List.cons_append] at h
      have h' := ((spec_cons _ _ _).mp h).2
      rw [← step_allow_state s e ha] at h'
      exact precision _ es t h'
    · have hf : (step P s e).1.isAllow = false := by
        cases hv : (step P s e).1 <;> simp_all [Verdict.isAllow]
      simp only [hf, Bool.false_eq_true, ite_false, List.nil_append] at h
      rw [step_deny_state s e ha] at h ⊢
      exact precision s es t h

/-- Soundness + precision: the monitor allows the next call exactly when the
independent spec permits it. -/
theorem monitor_exact (s : State) (es : List Event) (t : String) :
    (step P (run P s es).2 (.call t)).1 = .allow ↔
      Spec P s.ctx (executed P s es ++ [.call t]) := by
  refine ⟨fun h => ?_, precision s es t⟩
  have := executed_spec (P := P) s (es ++ [.call t])
  rw [executed_append] at this
  simpa [executed, h, Verdict.isAllow] using this

/-! ## 4. Approvals are the only downgrade -/

/-- **Theorem 4.** Across any `call` step, the context label never decreases. -/
theorem call_monotone (s : State) (t : String) : s.ctx ≤ (step P s (.call t)).2.ctx := by
  by_cases h : (step P s (.call t)).1 = .allow
  · obtain ⟨tool, hP, -⟩ := (step_call_allow_iff s t).mp h
    rw [step_call_allow_state s t tool hP h]
    exact Label.le_sup_left _ _
  · rw [step_deny_state s _ h]; exact Label.le_refl _

/-- If a step lowers (or makes incomparable) the context, it was a human approval. -/
theorem downgrade_only_by_approval (s : State) (e : Event)
    (h : ¬ s.ctx ≤ (step P s e).2.ctx) : (∃ c, e = .declassify c) ∨ e = .endorse := by
  cases e with
  | call t => exact absurd (call_monotone s t) h
  | declassify c => exact .inl ⟨c, rfl⟩
  | endorse => exact .inr rfl

/-- Over any run without approvals, the context only grows. -/
theorem run_calls_monotone :
    ∀ (s : State) (es : List Event), (∀ e ∈ es, ∃ t, e = .call t) →
      s.ctx ≤ (run P s es).2.ctx
  | s, [], _ => Label.le_refl _
  | s, e :: es, h => by
    obtain ⟨t, rfl⟩ := h e (by simp)
    exact Label.le_trans (call_monotone s t)
      (run_calls_monotone _ es (fun e' he' => h e' (by simp [he'])))

/-! ## 5. Policy monotonicity -/

/-- `P'` is pointwise at least as strict as `P`: it knows no extra tools, taints at
least as much, grants no more clearance, and requires trust at least as often. -/
def Manifest.AtLeastAsStrict (P' P : Manifest) : Prop :=
  ∀ t tool', P' t = some tool' → ∃ tool, P t = some tool ∧
    tool.outLabel ≤ tool'.outLabel ∧ tool'.argClearance ≤ tool.argClearance ∧
    (tool.requiresTrusted = true → tool'.requiresTrusted = true)

theorem step_mono {P' : Manifest} (hs : Manifest.AtLeastAsStrict P' P) (s s' : State)
    (hle : s.ctx ≤ s'.ctx) (e : Event) (h : (step P' s' e).1 = .allow) :
    (step P s e).1 = .allow ∧ (step P s e).2.ctx ≤ (step P' s' e).2.ctx := by
  cases e with
  | call t =>
    obtain ⟨tool', hP', hc', hr'⟩ := (step_call_allow_iff s' t).mp h
    obtain ⟨tool, hP, hout, hclr, hreq⟩ := hs t tool' hP'
    have ha : (step P s (.call t)).1 = .allow := by
      refine (step_call_allow_iff s t).mpr ⟨tool, hP, ?_, fun hr => ?_⟩
      · exact Conf.le_trans hle.1 (Conf.le_trans hc' hclr)
      · have h1 : s'.ctx.integ = .trusted := hr' (hreq hr)
        have h2 : s.ctx.integ ≤ .trusted := h1 ▸ hle.2
        exact Integ.le_trusted h2
    refine ⟨ha, ?_⟩
    rw [step_call_allow_state s t tool hP ha, step_call_allow_state s' t tool' hP' h]
    exact Label.sup_le (Label.le_trans hle (Label.le_sup_left _ _))
      (Label.le_trans hout (Label.le_sup_right _ _))
  | declassify c => exact ⟨rfl, Conf.le_refl _, hle.2⟩
  | endorse => exact ⟨rfl, hle.1, Integ.le_refl _⟩

theorem policy_monotone_gen {P' : Manifest} (hs : Manifest.AtLeastAsStrict P' P) :
    ∀ (s s' : State) (es : List Event), s.ctx ≤ s'.ctx →
      allAllowed P' s' es → allAllowed P s es
  | s, _, [], _, _ => allAllowed_nil s
  | s, s', e :: es, hle, h => by
    obtain ⟨h1, h2⟩ := (allAllowed_cons s' e es).mp h
    obtain ⟨ha, hle'⟩ := step_mono hs s s' hle e h1
    exact (allAllowed_cons s e es).mpr ⟨ha, policy_monotone_gen hs _ _ es hle' h2⟩

/-- **Theorem 5 (Policy monotonicity).** If `P'` is pointwise at least as strict as
`P`, every trace allowed under `P'` is allowed under `P`. -/
theorem policy_monotone {P' : Manifest} (hs : Manifest.AtLeastAsStrict P' P)
    (s : State) (es : List Event) (h : allAllowed P' s es) : allAllowed P s es :=
  policy_monotone_gen hs s s es (Label.le_refl _) h

/-! ## Decidable spec -/

theorem callOK_iff (l0 : Label) (H : List Event) (t : String) :
    callOK P l0 H t = true ↔ CallOK P l0 H t := by
  unfold callOK CallOK
  cases hP : P t with
  | none => simp
  | some tool =>
    cases hr : tool.requiresTrusted <;> simp [hr]

/-- The Bool checker agrees with the Prop spec. -/
theorem check_iff (l0 : Label) (tr : List Event) : check P l0 tr = true ↔ Spec P l0 tr := by
  rw [spec_iff_calls, check, List.all_eq_true]
  constructor
  · intro H i t h
    have hi : i < tr.length := (List.getElem?_eq_some_iff.mp h).1
    have := H i (List.mem_range.mpr hi)
    rw [h] at this
    exact (callOK_iff l0 _ t).mp this
  · intro H i _
    split
    · next t h => exact (callOK_iff l0 _ t).mpr (H i t h)
    · rfl

instance (l0 : Label) (tr : List Event) : Decidable (Spec P l0 tr) :=
  decidable_of_iff _ (check_iff l0 tr)

end Flowguard
