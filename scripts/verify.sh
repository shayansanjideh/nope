#!/usr/bin/env bash
# One-command verification gate. Exits nonzero if anything fails.
#   scripts/verify.sh            full run (build, proofs, demo, differential tests)
#   QUICK=1 scripts/verify.sh    skip the demo and use smaller differential runs
set -uo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python
fails=()
step() {
  local name=$1; shift
  echo "==> $name"
  if "$@"; then echo "    ok: $name"; else echo "    FAILED: $name"; fails+=("$name"); fi
}
attacker_port_free() {
  # A stale attacker server from another checkout makes the demo fail confusingly.
  if (exec 3<>/dev/tcp/127.0.0.1/8666) 2>/dev/null; then
    echo "    port 8666 is in use; stop the old attacker server first"; return 1
  fi
}

step "lean build"        bash -c 'cd lean && lake build 2>&1 | tee ../.verify-build.log | tail -1'
step "proof hygiene"     $PY tests/check_proofs.py .verify-build.log
if [ -z "${QUICK:-}" ]; then
  step "attacker port"   attacker_port_free
  step "demo scenarios"  bash -c 'set -o pipefail; cd demo && ../.venv/bin/python run_demo.py 2>/dev/null | tail -9'
  step "audit replay"    bash -c '.venv/bin/nope audit-check demo/run/logs/*.jsonl docs/evidence/*.jsonl'
  step "differential (engine, 12k)" $PY tests/differential.py --tier engine --sessions 12000
  step "differential (mcp, 20)"     bash -c "$PY tests/differential.py --tier mcp --sessions 20 2>&1 | grep 'mcp tier'; exit \${PIPESTATUS[0]}"
else
  step "differential (engine, 1k)"  $PY tests/differential.py --tier engine --sessions 1000
fi
rm -f .verify-build.log
echo
if [ ${#fails[@]} -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "FAILED: ${fails[*]}"; exit 1; fi
