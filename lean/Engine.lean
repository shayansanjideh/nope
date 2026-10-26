import Nope.Json

/-!
# nope-engine

Long-lived decision engine speaking JSON lines on stdin/stdout. Every decision is
made by `Nope.Monitor.step`, the function the theorems are about.

Startup: `nope-engine --manifest PATH [--validate]`. Prints one line
`{"ready": true, ...}` once the manifest is loaded and validated.

Requests (one JSON object per line):
* `{"session": S, "event": {"type": "call", "tool": T}}`
* `{"session": S, "event": {"type": "declassify", "conf": C}}`
* `{"session": S, "event": {"type": "endorse"}}`
* `{"op": "state", "session": S}`
* `{"op": "tools"}`

Responses: `{"verdict": "allow"|"deny", "code": ..., "reason": ..., "state": ...}` or
`{"error": ...}` for malformed requests (never treated as an allow).
-/

open Lean (Json)
open Nope

/-- Engine-side bookkeeping for nicer deny messages. Not consulted for decisions. -/
structure Session where
  st : State := Monitor.init
  /-- Most recent tool whose result raised the context confidentiality. -/
  confSrc : Option String := none
  /-- Most recent tool whose result made the context untrusted. -/
  integSrc : Option String := none

def fromNote : Option String → String
  | some t => s!" (from {t})"
  | none => ""

/-- Deny messages: (code, plain-English text, exact theorem names). The text is what
the agent and the user see; the first line is the decision, the second the override. -/
def denyText (tbl : ManifestTable) (sid : String) (sess : Session) :
    DenyReason → String × String × String
  | .unknownTool t =>
    ("unknown_tool",
     if tbl.deny.contains t then
       s!"nope: blocked {t}. This action is on the always-blocked list (it could switch off or bypass Nope)."
     else s!"nope: blocked {t}. It is not in the manifest, and unknown tools are always blocked.",
     "Nope.soundness")
  | .confTooHigh t ctx clr =>
    -- The monitor checks confidentiality first, so a call that would also fail the
    -- integrity check needs both approvals. Name both, so one retry is enough.
    let alsoUntrusted : Bool := match tbl.toManifest t with
      | some tool => tool.requiresTrusted && decide (sess.st.ctx.integ ≠ .trusted)
      | none => false
    ("conf_too_high",
     s!"nope: blocked {t}. This session has read {ctx.toStr} data{fromNote sess.confSrc}, " ++
     s!"and {t} only accepts {clr.toStr} data. " ++
     "Proven in Lean: Theorems 1 and 6 (confidentiality).\n" ++
     (if alsoUntrusted then
       s!"It has also read untrusted content{fromNote sess.integSrc}, and {t} is a protected action. " ++
       "To allow anyway, run both:\n" ++
       s!"  nope approve --session {sid} declassify {clr.toStr}\n" ++
       s!"  nope approve --session {sid} endorse"
     else s!"To allow anyway: nope approve --session {sid} declassify {clr.toStr}"),
     "Nope.soundness, Nope.conf_between, Nope.NI.noninterference_conf")
  | .untrustedContext t =>
    ("untrusted_context",
     s!"nope: blocked {t}. This session has read untrusted content{fromNote sess.integSrc}, " ++
     s!"and {t} is a protected action that needs a trusted session. " ++
     "Proven in Lean: Theorems 2 and 7 (integrity).\n" ++
     s!"To allow anyway: nope approve --session {sid} endorse",
     "Nope.integrity_between, Nope.NI.noninterference_integ")

def stateJson (st : State) : Json := st.ctx.toJson

def eventJson : Event → Json
  | .call t => Json.mkObj [("type", "call"), ("tool", t)]
  | .declassify c => Json.mkObj [("type", "declassify"), ("conf", c.toStr)]
  | .endorse => Json.mkObj [("type", "endorse")]

def applyEvent (tbl : ManifestTable) (sid : String) (sess : Session) (e : Event) : Json × Session :=
  let (v, st') := Monitor.step tbl.toManifest sess.st e
  match v with
  | .deny r =>
    let (code, text, thm) := denyText tbl sid sess r
    (Json.mkObj [("session", sid), ("event", eventJson e), ("verdict", "deny"),
      ("code", code), ("reason", text), ("theorem", thm), ("state", stateJson st')], sess)
  | .allow =>
    let old := sess.st.ctx
    let (sess', text) : Session × String := match e with
      | .call t =>
        let s1 := { sess with st := st' }
        let s1 := if old.conf.rank < st'.ctx.conf.rank then { s1 with confSrc := some t } else s1
        let s1 := if old.integ ≠ st'.ctx.integ then { s1 with integSrc := some t } else s1
        (s1, s!"tool '{t}' permitted in context {old.conf.toStr}/{old.integ.toStr}; " ++
          s!"its result is now read, context becomes {st'.ctx.conf.toStr}/{st'.ctx.integ.toStr}")
      | .declassify c =>
        ({ sess with st := st', confSrc := none },
          s!"human approval: context confidentiality set from {old.conf.toStr} to {c.toStr}")
      | .endorse =>
        ({ sess with st := st', integSrc := none },
          s!"human approval: context integrity reset from {old.integ.toStr} to trusted")
    (Json.mkObj [("session", sid), ("event", eventJson e), ("verdict", "allow"),
      ("code", "ok"), ("reason", text), ("state", stateJson st')], sess')

def errJson (msg : String) : Json := Json.mkObj [("error", msg)]

def handle (tbl : ManifestTable) (sessions : Std.HashMap String Session) (line : String) :
    Json × Std.HashMap String Session :=
  match Json.parse line with
  | .error e => (errJson s!"invalid JSON: {e}", sessions)
  | .ok j =>
    match j.getObjValAs? String "op" with
    | .ok "tools" =>
      (Json.mkObj [("tools", Json.arr (tbl.tools.toArray.map (·.1) |>.qsort (· < ·)
        |>.map Json.str))], sessions)
    | .ok "state" =>
      match j.getObjValAs? String "session" with
      | .ok sid =>
        let sess := sessions.getD sid {}
        (Json.mkObj [("session", sid), ("state", stateJson sess.st)], sessions)
      | .error _ => (errJson "op 'state' requires a string 'session'", sessions)
    | .ok other => (errJson s!"unknown op '{other}'", sessions)
    | .error _ =>
      match j.getObjValAs? String "session", j.getObjVal? "event" with
      | .ok sid, .ok ej =>
        match JsonIn.event ej with
        | .error e => (errJson e, sessions)
        | .ok e =>
          let (resp, sess') := applyEvent tbl sid (sessions.getD sid {}) e
          (resp, sessions.insert sid sess')
      | _, _ => (errJson "request needs a string 'session' and an object 'event'", sessions)

partial def loop (tbl : ManifestTable) (stdin : IO.FS.Stream) (stdout : IO.FS.Stream)
    (sessions : Std.HashMap String Session) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then return  -- EOF
  let line := line.trimAscii.toString
  if line.isEmpty then loop tbl stdin stdout sessions else
  let (resp, sessions') := handle tbl sessions line
  stdout.putStrLn resp.compress
  stdout.flush
  loop tbl stdin stdout sessions'

def loadManifest (path : System.FilePath) : IO ManifestTable := do
  let txt ← IO.FS.readFile path
  match Json.parse txt >>= ManifestTable.ofJson with
  | .ok m => pure m
  | .error e => throw (IO.userError s!"manifest {path}: {e}")

def usage : String := "usage: nope-engine --manifest PATH [--validate]"

def main (args : List String) : IO UInt32 := do
  let stderr ← IO.getStderr
  let rec parse : List String → Option String → Bool → Option (String × Bool)
    | [], some m, v => some (m, v)
    | "--manifest" :: p :: rest, _, v => parse rest (some p) v
    | "--validate" :: rest, m, _ => parse rest m true
    | _, _, _ => none
  match parse args none false with
  | none => stderr.putStrLn usage; return 2
  | some (path, validateOnly) =>
    let tbl ← try loadManifest path catch e => do
      stderr.putStrLn s!"nope-engine: {e}"; return 2
    let stdout ← IO.getStdout
    stdout.putStrLn (Json.mkObj [("ready", true), ("tools", tbl.tools.size)]).compress
    stdout.flush
    if validateOnly then return 0
    loop tbl (← IO.getStdin) stdout {}
    return 0
