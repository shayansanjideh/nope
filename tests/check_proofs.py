"""Proof hygiene gate.

1. No `sorry` / `admit` / custom `axiom` in the Lean sources, and no sorry warning
   from the build log (pass the build log path as argv[1], optional).
2. `#print axioms` on every theorem (lean/Axioms.lean) reports only a subset of
   {propext, Quot.sound, Classical.choice}, and matches the committed
   lean/axioms-output.txt.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEAN = ROOT / "lean"
ALLOWED = {"propext", "Quot.sound", "Classical.choice"}
REQUIRED = ["soundness", "soundness_executed", "conf_between", "integrity", "integrity_executed",
            "integrity_between", "precision", "monitor_exact", "call_monotone",
            "downgrade_only_by_approval", "run_calls_monotone", "policy_monotone", "check_iff"]


def main() -> int:
    fail = False
    srcs = list((LEAN / "Nope").glob("*.lean")) + [LEAN / "Nope.lean"]
    for f in srcs:
        for n, line in enumerate(f.read_text().splitlines(), 1):
            code = line.split("--")[0]
            if re.search(r"\b(sorry|admit)\b", code) or re.match(r"\s*axiom\b", code):
                print(f"FORBIDDEN {f.relative_to(ROOT)}:{n}: {line.strip()}")
                fail = True
    if len(sys.argv) > 1 and "declaration uses 'sorry'" in Path(sys.argv[1]).read_text():
        print("build log contains a sorry warning")
        fail = True

    out = subprocess.run(["lake", "env", "lean", "Axioms.lean"], cwd=LEAN, capture_output=True,
                         text=True, check=True).stdout
    for line in out.splitlines():
        m = re.search(r"depends on axioms: \[(.*)\]", line)
        used = {a.strip() for a in m.group(1).split(",")} if m else set()
        if not used <= ALLOWED:
            print(f"DISALLOWED AXIOMS: {line}")
            fail = True
    for thm in REQUIRED:
        if f"'Nope.{thm}'" not in out:
            print(f"theorem {thm} missing from axiom audit")
            fail = True
    committed = (LEAN / "axioms-output.txt").read_text()
    if out != committed:
        print("axiom audit output differs from committed lean/axioms-output.txt")
        fail = True
    print("proof hygiene:", "FAIL" if fail else
          f"OK ({len(out.splitlines())} declarations audited, axioms within {sorted(ALLOWED)})")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
