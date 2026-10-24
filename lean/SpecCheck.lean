import Flowguard.Json
import Flowguard.Spec

/-!
# flowguard-speccheck

Differential-test oracle. Each input line is a recorded session:

`{"manifest": {...}, "events": [e0, e1, ...], "verdicts": ["allow"|"deny", ...],
  "states": [{"conf": .., "integ": ..}, ...]}`

Every verdict and reported state is judged against the independent spec
(`Spec.check`, `Spec.confSince`, `Spec.integSince`). `Monitor.step` is never called.
By `Flowguard.monitor_exact`, a call should be allowed iff the spec accepts the
executed trace extended with it. Approvals are always allowed.

Output: one line per input, `{"ok": true, "n": N}` or `{"ok": false, "errors": [...]}`.
-/

open Lean (Json)
open Flowguard

def specLabel (P : Manifest) (exec : List Event) : Label :=
  ⟨Spec.confSince P Label.bot.conf exec.reverse, Spec.integSince P Label.bot.integ exec.reverse⟩

def checkSession (j : Json) : Except String (Nat × List String) := do
  let tbl ← ManifestTable.ofJson (← j.getObjVal? "manifest")
  let P := tbl.toManifest
  let evs ← (← (← j.getObjVal? "events").getArr?).toList.mapM JsonIn.event
  let vs ← (← (← j.getObjVal? "verdicts").getArr?).toList.mapM Json.getStr?
  let sts ← match j.getObjVal? "states" with
    | .ok a => do
      let arr ← a.getArr?
      arr.toList.mapM fun s => (some ·) <$> JsonIn.label "state" s
    | .error _ => pure (evs.map fun _ => none)
  unless evs.length == vs.length && evs.length == sts.length do
    throw "events/verdicts/states length mismatch"
  let mut exec : List Event := []
  let mut errs : List String := []
  let mut i := 0
  for ((e, v), st) in (evs.zip vs).zip sts do
    let specAllows := match e with
      | .call _ => Spec.check P Label.bot (exec ++ [e])
      | _ => true
    let engineAllows ← match v with
      | "allow" => pure true
      | "deny" => pure false
      | other => throw s!"bad verdict '{other}'"
    if specAllows != engineAllows then
      errs := errs ++ [s!"event {i}: engine said {v}, spec says " ++
        (if specAllows then "allow" else "deny")]
    if engineAllows then exec := exec ++ [e]
    if let some reported := st then
      let expected := specLabel P exec
      if reported != expected then
        errs := errs ++ [s!"event {i}: engine state {reported.toJson.compress}, " ++
          s!"spec label {expected.toJson.compress}"]
    i := i + 1
  -- Soundness on the whole executed trace.
  unless Spec.check P Label.bot exec do
    errs := errs ++ ["executed trace violates the spec"]
  return (evs.length, errs)

partial def loop (stdin stdout : IO.FS.Stream) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then return
  let line := line.trimAscii.toString
  unless line.isEmpty do
    let out := match Json.parse line >>= checkSession with
      | .error e => Json.mkObj [("ok", false), ("errors", Json.arr #[s!"input error: {e}"])]
      | .ok (n, []) => Json.mkObj [("ok", true), ("n", n)]
      | .ok (n, errs) => Json.mkObj [("ok", false), ("n", n),
          ("errors", Json.arr (errs.toArray.map Json.str))]
    stdout.putStrLn out.compress
    stdout.flush
  loop stdin stdout

def main : IO Unit := do
  loop (← IO.getStdin) (← IO.getStdout)
