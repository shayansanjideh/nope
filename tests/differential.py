"""Differential test: engine verdicts vs. the Lean spec checker.

Tier "engine": N random sessions over random manifests, driven through the proxy's
real EngineClient (engine process, JSON lines, per-session state). Sessions sharing a
manifest run concurrently, so their requests interleave inside one engine process.

Tier "mcp": sessions through the real `nope serve` proxy in front of a stub MCP
server. Also checks that the stub received exactly the allowed calls, and replays
the audit logs.

Every recorded session (events, verdicts, reported states) is judged by
`nope-speccheck`, which uses only Spec.check / confSince / integSince.

  python tests/differential.py --tier engine --sessions 10000
  python tests/differential.py --tier mcp --sessions 200
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "proxy"))
from nope import control  # noqa: E402
from nope.engine import EngineClient, EngineError  # noqa: E402
from nope.logreplay import read_records, speccheck_input  # noqa: E402

ENGINE = ROOT / "lean/.lake/build/bin/nope-engine"
SPECCHECK = ROOT / "lean/.lake/build/bin/nope-speccheck"
CONFS = ["public", "internal", "secret"]
INTEGS = ["trusted", "untrusted"]
WEIRD = ['quo"te', "back\\slash", "unié中", "tab\tname", "emoji\U0001F600", "sp ace"]


def rand_manifest(rng: random.Random, names: list[str]) -> dict:
    return {"version": 1, "tools": {
        n: {"outLabel": {"conf": rng.choice(CONFS), "integ": rng.choice(INTEGS)},
            "argClearance": rng.choice(CONFS), "requiresTrusted": rng.random() < 0.35}
        for n in names}}


def rand_events(rng: random.Random, declared: list[str], undeclared: list[str], n: int) -> list:
    evs = []
    for _ in range(n):
        x = rng.random()
        if x < 0.72:
            pool = undeclared if (undeclared and rng.random() < 0.08) else declared
            evs.append({"type": "call", "tool": rng.choice(pool)})
        elif x < 0.86:
            evs.append({"type": "declassify", "conf": rng.choice(CONFS)})
        else:
            evs.append({"type": "endorse"})
    return evs


def speccheck(sessions: list[dict]) -> list[dict]:
    inp = "".join(json.dumps(s) + "\n" for s in sessions)
    out = subprocess.run([str(SPECCHECK)], input=inp, capture_output=True, text=True, check=True)
    res = [json.loads(l) for l in out.stdout.splitlines()]
    assert len(res) == len(sessions), "speccheck output count mismatch"
    return res


# ------------------------------------------------------------------ engine tier

async def engine_tier(n_sessions: int, seed: int, per_manifest: int) -> int:
    rng = random.Random(seed)
    tmp = Path(tempfile.mkdtemp(prefix="fg-diff-"))
    recorded: list[dict] = []
    n_events = 0
    t0 = time.time()
    m_idx = 0
    while len(recorded) < n_sessions:
        k = rng.randint(1, 7)
        names = [f"srv__tool{i}" for i in range(k)]
        if rng.random() < 0.3:
            names.append(rng.choice(WEIRD))
        manifest = rand_manifest(rng, names)
        undeclared = ["srv__ghost", "other__x", rng.choice(WEIRD) + "_undeclared"]
        mpath = tmp / f"m{m_idx}.json"
        mpath.write_text(json.dumps(manifest))
        m_idx += 1
        eng = EngineClient(ENGINE, mpath)
        await eng.start()
        count = min(per_manifest, n_sessions - len(recorded))
        sids = [f"s{m_idx}-{j}-{rng.choice(WEIRD)}" for j in range(count)]
        plans = {sid: rand_events(rng, names, undeclared, rng.randint(0, 40)) for sid in sids}

        async def drive(sid: str, evs: list[dict], seed2: int) -> dict:
            r2 = random.Random(seed2)
            verdicts, states = [], []
            for e in evs:
                if r2.random() < 0.5:
                    await asyncio.sleep(0)  # let other sessions interleave
                resp = await eng.event(sid, e)
                verdicts.append(resp["verdict"])
                states.append(resp["state"])
            # The engine's final state for this session must match the last response.
            final = await eng.state(sid)
            if states and final != states[-1]:
                raise AssertionError(f"session {sid!r}: final state {final} != {states[-1]}")
            return {"manifest": manifest, "events": evs, "verdicts": verdicts, "states": states}

        results = await asyncio.gather(*(drive(s, plans[s], rng.random().__hash__())
                                         for s in sids))
        # Semantically malformed requests must be rejected, never answered with a verdict.
        for bad in [{"session": 1, "event": {"type": "endorse"}},
                    {"session": "x", "event": {"type": "call"}},
                    {"session": "x", "event": {"type": "declassify", "conf": "top"}},
                    {"session": "x", "event": {"type": "call", "tool": "a", "extra": 1}},
                    {"session": "x"}, {"op": "nope"}]:
            try:
                r = await eng.request(bad)
            except EngineError:
                continue
            raise AssertionError(f"engine answered malformed request {bad}: {r}")
        await eng.close()
        recorded += results
        n_events += sum(len(r["events"]) for r in results)
    garbage_check(tmp / "m0.json")
    t1 = time.time()
    res = speccheck(recorded)
    bad = [(i, r) for i, r in enumerate(res) if not r["ok"]]
    allowed = sum(v == "allow" for s in recorded for v in s["verdicts"])
    print(f"engine tier: {len(recorded)} sessions, {n_events} events "
          f"({allowed} allow / {n_events - allowed} deny), {m_idx} manifests; "
          f"engine {t1 - t0:.1f}s, speccheck {time.time() - t1:.1f}s")
    for i, r in bad[:10]:
        print("MISMATCH", json.dumps(recorded[i])[:500], r["errors"][:3])
    print(f"agreement: {len(recorded) - len(bad)}/{len(recorded)}")
    caught = mutation_check(recorded, rng)
    return 1 if (bad or not caught) else 0


def garbage_check(manifest: Path) -> None:
    """Raw garbage lines: every reply is an error object, and the engine survives."""
    lines = ["garbage", "{", "[]", "null", "\"\"", '{"session":"a","event":"call"}',
             '{"session":"a","event":{"type":"call","tool":"srv__tool0"}}']
    out = subprocess.run([str(ENGINE), "--manifest", str(manifest)], input="\n".join(lines) + "\n",
                         capture_output=True, text=True, check=True).stdout.splitlines()
    replies = [json.loads(l) for l in out[1:]]
    assert len(replies) == len(lines), replies
    assert all("error" in r for r in replies[:-1]), replies
    assert replies[-1].get("verdict") in ("allow", "deny"), replies[-1]


def mutation_check(recorded: list[dict], rng: random.Random, n: int = 500) -> bool:
    """The oracle must catch a single flipped verdict or a corrupted state."""
    mutants = []
    for s in rng.sample([s for s in recorded if s["events"]], min(n, len(recorded))):
        m = json.loads(json.dumps(s))
        i = rng.randrange(len(m["events"]))
        if m["events"][i]["type"] == "call" and rng.random() < 0.5:
            m["verdicts"][i] = "deny" if m["verdicts"][i] == "allow" else "allow"
        else:
            st = m["states"][i]
            if rng.random() < 0.5:
                st["integ"] = "untrusted" if st["integ"] == "trusted" else "trusted"
            else:
                st["conf"] = rng.choice([c for c in CONFS if c != st["conf"]])
        mutants.append(m)
    res = speccheck(mutants)
    caught = sum(not r["ok"] for r in res)
    print(f"mutation self-test: oracle caught {caught}/{len(mutants)} single-point corruptions")
    return caught == len(mutants)


# ------------------------------------------------------------------ mcp tier

async def mcp_session(rng: random.Random, tmp: Path, idx: int) -> tuple[dict, list, list, Path]:
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    k = rng.randint(1, 6)
    declared_local = [f"t{i}" for i in range(k)]
    hidden_local = ["hidden0"]
    manifest = rand_manifest(rng, [f"stub__{n}" for n in declared_local])
    d = tmp / f"run{idx}"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps(manifest))
    record = d / "stub_calls.jsonl"
    record.touch()
    (d / "nope.toml").write_text(
        f'engine = "{ENGINE}"\nmanifest = "manifest.json"\nstate_dir = "state"\n'
        f'[servers.stub]\ncommand = "{sys.executable}"\n'
        f'args = ["{Path(__file__).parent / "stub_server.py"}", "{record}", '
        + ", ".join(f'"{n}"' for n in declared_local + hidden_local) + "]\n")
    session = f"diff{idx}"
    evs = rand_events(rng, [f"stub__{n}" for n in declared_local],
                      ["stub__hidden0", "nosuch__tool"], rng.randint(5, 40))
    params = StdioServerParameters(command=str(ROOT / ".venv/bin/nope"),
                                   args=["serve", "--config", str(d / "nope.toml"),
                                         "--session", session])
    verdicts, sent = [], []
    async with Client(params) as c:
        listed = {t.name for t in (await c.list_tools()).tools}
        assert listed == {f"stub__{n}" for n in declared_local}, listed
        sock = d / "state" / "sockets" / f"{session}.sock"
        for i, e in enumerate(evs):
            if e["type"] == "call":
                args = {"i": i}
                r = await c.call_tool(e["tool"], args)
                text = r.content[0].text if r.content else ""
                denied = bool(r.is_error) and text.startswith("Nope blocked")
                verdicts.append("deny" if denied else "allow")
                if not denied:
                    sent.append((e["tool"].split("__", 1)[1], args))
            else:
                resp = await asyncio.to_thread(control.request, sock, {
                    "op": "approve", "event": e, "approver": "difftest", "note": str(i)})
                verdicts.append(resp["verdict"])
    received = [(r["tool"], r["arguments"]) for r in
                (json.loads(l) for l in record.read_text().splitlines())]
    log = d / "state" / "logs" / f"{session}.jsonl"
    return {"manifest": manifest, "events": evs, "verdicts": verdicts}, sent, received, log


async def mcp_tier(n_sessions: int, seed: int, parallel: int) -> int:
    rng = random.Random(seed)
    tmp = Path(tempfile.mkdtemp(prefix="fg-mcp-"))
    sem = asyncio.Semaphore(parallel)
    t0 = time.time()

    async def one(i, r):
        async with sem:
            return await mcp_session(r, tmp, i)

    outs = await asyncio.gather(*(one(i, random.Random(rng.random())) for i in range(n_sessions)))
    failures = 0
    sessions, replays = [], []
    for i, (sess, sent, received, log) in enumerate(outs):
        if sent != received:
            failures += 1
            print(f"session {i}: downstream received {received} but allowed calls were {sent}")
        recs = read_records(log)
        replay = speccheck_input(recs)
        if replay["events"] != sess["events"] or replay["verdicts"] != sess["verdicts"]:
            failures += 1
            print(f"session {i}: audit log disagrees with client-observed verdicts")
        sessions.append(sess)
        replays.append(replay)
    res = speccheck(sessions + replays)
    bad = [r for r in res if not r["ok"]]
    n_ev = sum(len(s["events"]) for s in sessions)
    print(f"mcp tier: {n_sessions} sessions, {n_ev} events through the MCP proxy in "
          f"{time.time() - t0:.1f}s; downstream-isolation failures: {failures}; "
          f"spec disagreements (client view + audit replay): {len(bad)}")
    for r in bad[:5]:
        print("MISMATCH", r["errors"][:3])
    return 1 if (bad or failures) else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", choices=["engine", "mcp"], default="engine")
    ap.add_argument("--sessions", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--per-manifest", type=int, default=50)
    ap.add_argument("--parallel", type=int, default=4)
    a = ap.parse_args()
    if a.tier == "engine":
        return asyncio.run(engine_tier(a.sessions, a.seed, a.per_manifest))
    return asyncio.run(mcp_tier(a.sessions, a.seed, a.parallel))


if __name__ == "__main__":
    sys.exit(main())
