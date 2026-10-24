/-!
# Labels

Two-dimensional security labels, combined as a product lattice.

* Confidentiality: `pub < internal < secret`
  (`public` is a reserved word in Lean 4, so the bottom element is `Conf.pub`;
  it is serialized as `"public"` everywhere outside Lean.)
* Integrity (taint): `trusted < untrusted`
-/

namespace Flowguard

inductive Conf where
  | pub
  | internal
  | secret
  deriving DecidableEq, Repr, Inhabited

inductive Integ where
  | trusted
  | untrusted
  deriving DecidableEq, Repr, Inhabited

structure Label where
  conf  : Conf
  integ : Integ
  deriving DecidableEq, Repr, Inhabited

namespace Conf

def rank : Conf → Nat
  | pub => 0
  | internal => 1
  | secret => 2

instance : LE Conf := ⟨fun a b => a.rank ≤ b.rank⟩
instance (a b : Conf) : Decidable (a ≤ b) := inferInstanceAs (Decidable (a.rank ≤ b.rank))

def sup (a b : Conf) : Conf := if a.rank ≤ b.rank then b else a
instance : Max Conf := ⟨sup⟩

def bot : Conf := pub

theorem le_refl (a : Conf) : a ≤ a := Nat.le_refl _
theorem le_trans {a b c : Conf} : a ≤ b → b ≤ c → a ≤ c := Nat.le_trans
theorem le_antisymm {a b : Conf} : a ≤ b → b ≤ a → a = b := by
  cases a <;> cases b <;> decide
theorem le_sup_left (a b : Conf) : a ≤ max a b := by cases a <;> cases b <;> decide
theorem le_sup_right (a b : Conf) : b ≤ max a b := by cases a <;> cases b <;> decide
theorem sup_le {a b c : Conf} : a ≤ c → b ≤ c → max a b ≤ c := by
  cases a <;> cases b <;> cases c <;> decide
theorem bot_le (a : Conf) : bot ≤ a := Nat.zero_le _
theorem le_total (a b : Conf) : a ≤ b ∨ b ≤ a := Nat.le_total _ _

end Conf

namespace Integ

def rank : Integ → Nat
  | trusted => 0
  | untrusted => 1

instance : LE Integ := ⟨fun a b => a.rank ≤ b.rank⟩
instance (a b : Integ) : Decidable (a ≤ b) := inferInstanceAs (Decidable (a.rank ≤ b.rank))

/-- Join: `untrusted` if either side is. -/
def sup : Integ → Integ → Integ
  | trusted, b => b
  | untrusted, _ => untrusted
instance : Max Integ := ⟨sup⟩

theorem le_refl (a : Integ) : a ≤ a := Nat.le_refl _
theorem le_trans {a b c : Integ} : a ≤ b → b ≤ c → a ≤ c := Nat.le_trans
theorem le_antisymm {a b : Integ} : a ≤ b → b ≤ a → a = b := by
  cases a <;> cases b <;> decide
theorem le_sup_left (a b : Integ) : a ≤ max a b := by cases a <;> cases b <;> decide
theorem le_sup_right (a b : Integ) : b ≤ max a b := by cases a <;> cases b <;> decide
theorem sup_le {a b c : Integ} : a ≤ c → b ≤ c → max a b ≤ c := by
  cases a <;> cases b <;> cases c <;> decide
theorem le_trusted {a : Integ} : a ≤ trusted → a = trusted := by cases a <;> decide
theorem sup_untrusted (a : Integ) : max a untrusted = untrusted := by cases a <;> rfl
theorem untrusted_sup (a : Integ) : max untrusted a = untrusted := rfl
theorem sup_eq_trusted {a b : Integ} : max a b = trusted ↔ a = trusted ∧ b = trusted := by
  cases a <;> cases b <;> decide

end Integ

namespace Label

instance : LE Label := ⟨fun a b => a.conf ≤ b.conf ∧ a.integ ≤ b.integ⟩
instance (a b : Label) : Decidable (a ≤ b) :=
  inferInstanceAs (Decidable (a.conf ≤ b.conf ∧ a.integ ≤ b.integ))

instance : Max Label := ⟨fun a b => ⟨max a.conf b.conf, max a.integ b.integ⟩⟩

/-- Bottom label: public and trusted. The start state of every session. -/
def bot : Label := ⟨.pub, .trusted⟩

@[simp] theorem sup_conf (a b : Label) : (max a b).conf = max a.conf b.conf := rfl
@[simp] theorem sup_integ (a b : Label) : (max a b).integ = max a.integ b.integ := rfl

theorem le_refl (a : Label) : a ≤ a := ⟨Conf.le_refl _, Integ.le_refl _⟩
theorem le_trans {a b c : Label} : a ≤ b → b ≤ c → a ≤ c :=
  fun h1 h2 => ⟨Conf.le_trans h1.1 h2.1, Integ.le_trans h1.2 h2.2⟩
theorem le_antisymm {a b : Label} : a ≤ b → b ≤ a → a = b := by
  intro h1 h2
  cases a; cases b
  simp only [Label.mk.injEq]
  exact ⟨Conf.le_antisymm h1.1 h2.1, Integ.le_antisymm h1.2 h2.2⟩
theorem le_sup_left (a b : Label) : a ≤ max a b := ⟨Conf.le_sup_left _ _, Integ.le_sup_left _ _⟩
theorem le_sup_right (a b : Label) : b ≤ max a b := ⟨Conf.le_sup_right _ _, Integ.le_sup_right _ _⟩
theorem sup_le {a b c : Label} : a ≤ c → b ≤ c → max a b ≤ c :=
  fun h1 h2 => ⟨Conf.sup_le h1.1 h2.1, Integ.sup_le h1.2 h2.2⟩

end Label

end Flowguard
