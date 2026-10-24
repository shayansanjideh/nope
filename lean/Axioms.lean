import Nope
open Nope

-- Lattice laws
#print axioms Conf.le_refl
#print axioms Conf.le_trans
#print axioms Conf.le_antisymm
#print axioms Conf.le_sup_left
#print axioms Conf.le_sup_right
#print axioms Conf.sup_le
#print axioms Integ.le_refl
#print axioms Integ.le_trans
#print axioms Integ.le_antisymm
#print axioms Integ.le_sup_left
#print axioms Integ.le_sup_right
#print axioms Integ.sup_le
#print axioms Label.le_refl
#print axioms Label.le_trans
#print axioms Label.le_antisymm
#print axioms Label.le_sup_left
#print axioms Label.le_sup_right
#print axioms Label.sup_le
-- 1. Soundness
#print axioms soundness
#print axioms soundness_executed
#print axioms conf_between
-- 2. Integrity
#print axioms integrity
#print axioms integrity_executed
#print axioms integrity_between
-- 3. Precision
#print axioms precision
#print axioms monitor_exact
-- 4. Approvals are the only downgrade
#print axioms call_monotone
#print axioms downgrade_only_by_approval
#print axioms run_calls_monotone
-- 5. Policy monotonicity
#print axioms policy_monotone
-- Decidable spec
#print axioms check_iff
