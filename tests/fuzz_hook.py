"""Fuzz the Claude Code hooks with malformed and hostile payloads.

Requirements: the hook never crashes (exit 0, valid JSON or nothing), never allows a
payload it cannot parse, and stays fast on huge inputs.

  python tests/fuzz_hook.py
"""

import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOPE = str(ROOT / ".venv/bin/nope")
HOME = tempfile.mkdtemp(prefix="nope-fuzz-")
ENV = {**os.environ, "NOPE_HOME": HOME}
rng = random.Random(7)


def run(sub, payload: str):
    t = time.time()
    p = subprocess.run([NOPE, "hook", sub], input=payload, capture_output=True, text=True,
                       env=ENV, timeout=60)
    return p, time.time() - t


def junk(depth=0):
    r = rng.random()
    if depth > 3 or r < 0.3:
        return rng.choice([None, True, 0, -1, 1e308, "", "x" * rng.randint(0, 50), "../../etc/passwd",
                           "\x00", "🙃", "~/.ssh/id_rsa", ".env", "$(rm -rf /)", "\\" * 9])
    if r < 0.6:
        return [junk(depth + 1) for _ in range(rng.randint(0, 4))]
    return {rng.choice(["command", "file_path", "path", "url", "pattern", "content", "x"]):
            junk(depth + 1) for _ in range(rng.randint(0, 4))}


cases = ["", "{", "null", "[]", "42", '"str"', "{}", '{"session_id": 5}',
         '{"session_id": "../../etc", "tool_name": "Read", "tool_input": {}}',
         '{"session_id": "a b", "tool_name": "Read", "tool_input": {}}',
         '{"session_id": "ok", "tool_name": null, "tool_input": {}}',
         '{"session_id": "ok", "tool_name": "Read", "tool_input": "notadict"}']
for _ in range(120):
    cases.append(json.dumps({"session_id": rng.choice(["f1", "f2", "f3"]),
                             "cwd": rng.choice(["/tmp", "/nonexistent", "", "relative"]),
                             "tool_name": rng.choice(["Read", "Write", "Edit", "Bash", "Grep",
                                                      "WebFetch", "MultiEdit", "mcp__x__y", ""]),
                             "tool_input": junk(), "tool_response": junk()}))
big = json.dumps({"session_id": "big", "cwd": "/tmp", "tool_name": "Bash",
                  "tool_input": {"command": "echo " + "A" * 2_000_000},
                  "tool_response": {"stdout": "B" * 5_000_000}})

bad = []
worst = 0.0
for i, c in enumerate(cases + [big]):
    for sub in ("claude-code", "claude-code-post"):
        p, dt = run(sub, c)
        worst = max(worst, dt)
        if p.returncode != 0 or "Traceback" in p.stderr:
            bad.append(f"case {i} {sub}: exit {p.returncode} {p.stderr[-200:]}")
            continue
        if p.stdout.strip():
            try:
                d = json.loads(p.stdout)["hookSpecificOutput"]
                assert d["permissionDecision"] == "deny"
            except Exception as e:
                bad.append(f"case {i} {sub}: bad output {p.stdout[:200]} ({e})")
        elif sub == "claude-code":
            try:
                ok = isinstance(json.loads(c), dict) and isinstance(json.loads(c).get("session_id"), str)
            except json.JSONDecodeError:
                ok = False
            if not ok:
                bad.append(f"case {i}: unparseable payload was ALLOWED: {c[:120]}")
print(f"fuzzed {2 * (len(cases) + 1)} hook invocations; slowest {worst:.2f}s; problems: {len(bad)}")
for b in bad[:15]:
    print("  " + b)
sys.exit(1 if bad else 0)
