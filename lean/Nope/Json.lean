import Lean.Data.Json
import Std.Data.HashMap
import Nope.Monitor

/-!
# JSON codecs

Data conversion only: no policy decisions are made here. Shared by the engine and
the spec checker.
-/

namespace Nope
open Lean (Json)

def Conf.toStr : Conf → String
  | .pub => "public" | .internal => "internal" | .secret => "secret"

def Conf.ofStr? : String → Option Conf
  | "public" => some .pub | "internal" => some .internal | "secret" => some .secret
  | _ => none

def Integ.toStr : Integ → String
  | .trusted => "trusted" | .untrusted => "untrusted"

def Integ.ofStr? : String → Option Integ
  | "trusted" => some .trusted | "untrusted" => some .untrusted
  | _ => none

def Label.toJson (l : Label) : Json :=
  Json.mkObj [("conf", l.conf.toStr), ("integ", l.integ.toStr)]

namespace JsonIn

def expectKeys (what : String) (j : Json) (allowed : List String) : Except String Unit := do
  let obj ← j.getObj?.mapError (fun _ => s!"{what}: expected a JSON object")
  for ⟨k, _⟩ in obj.toArray do
    unless allowed.contains k do
      throw s!"{what}: unknown field '{k}' (allowed: {allowed})"

def str (what : String) (j : Json) (k : String) : Except String String := do
  let v ← (j.getObjVal? k).mapError (fun _ => s!"{what}: missing field '{k}'")
  v.getStr?.mapError (fun _ => s!"{what}: field '{k}' must be a string")

def conf (what : String) (j : Json) (k : String) : Except String Conf := do
  let s ← str what j k
  match Conf.ofStr? s with
  | some c => pure c
  | none => throw s!"{what}: '{s}' is not a confidentiality level (public|internal|secret)"

def integ (what : String) (j : Json) (k : String) : Except String Integ := do
  let s ← str what j k
  match Integ.ofStr? s with
  | some i => pure i
  | none => throw s!"{what}: '{s}' is not an integrity level (trusted|untrusted)"

def label (what : String) (j : Json) : Except String Label := do
  expectKeys what j ["conf", "integ"]
  return ⟨← conf what j "conf", ← integ what j "integ"⟩

def tool (name : String) (j : Json) : Except String Tool := do
  let what := s!"tool '{name}'"
  expectKeys what j ["outLabel", "argClearance", "requiresTrusted", "description"]
  let out ← (j.getObjVal? "outLabel").mapError (fun _ => s!"{what}: missing field 'outLabel'")
  let req ← (j.getObjVal? "requiresTrusted").mapError
    (fun _ => s!"{what}: missing field 'requiresTrusted'")
  let req ← req.getBool?.mapError (fun _ => s!"{what}: 'requiresTrusted' must be a boolean")
  return ⟨← label s!"{what}.outLabel" out, ← conf what j "argClearance", req⟩

def event (j : Json) : Except String Event := do
  match ← str "event" j "type" with
  | "call" => expectKeys "event" j ["type", "tool"]; return .call (← str "event" j "tool")
  | "declassify" =>
    expectKeys "event" j ["type", "conf"]; return .declassify (← conf "event" j "conf")
  | "endorse" => expectKeys "event" j ["type"]; return .endorse
  | other => throw s!"event: unknown type '{other}' (call|declassify|endorse)"

end JsonIn

/-- A validated manifest: a finite table of tool declarations. -/
structure ManifestTable where
  tools : Std.HashMap String Tool
  /-- Labels for tools not listed in `tools`. Absent: unknown tools are denied. -/
  defaultTool : Option Tool := none
  /-- Names that are always denied, even if `defaultTool` is set. -/
  deny : List String := []

/-- The manifest function the monitor (and every theorem) is about. -/
def ManifestTable.toManifest (m : ManifestTable) : Manifest := fun t =>
  if m.deny.contains t then none
  else match m.tools.get? t with
    | some tool => some tool
    | none => m.defaultTool

/-- Parse and validate a manifest:
`{"version": 1, "tools": {name: decl, ...}, "defaultTool"?: decl, "deny"?: [name, ...]}`.
Note: `Lean.Json.parse` keeps only the last of duplicate object keys, so the Python
loader rejects duplicate tool names before the file reaches the engine. -/
def ManifestTable.ofJson (j : Json) : Except String ManifestTable := do
  JsonIn.expectKeys "manifest" j ["version", "tools", "description", "defaultTool", "deny"]
  let ver ← (j.getObjVal? "version").mapError (fun _ => "manifest: missing field 'version'")
  unless ver == (1 : Nat) do throw "manifest: unsupported version (expected 1)"
  let tools ← (j.getObjVal? "tools").mapError (fun _ => "manifest: missing field 'tools'")
  let obj ← tools.getObj?.mapError (fun _ => "manifest: 'tools' must be an object")
  let mut m : Std.HashMap String Tool := {}
  for ⟨name, decl⟩ in obj.toArray do
    if name.isEmpty then throw "manifest: empty tool name"
    if m.contains name then throw s!"manifest: duplicate tool '{name}'"
    m := m.insert name (← JsonIn.tool name decl)
  let dflt ← match j.getObjVal? "defaultTool" with
    | .ok d => some <$> JsonIn.tool "defaultTool" d
    | .error _ => pure none
  let deny ← match j.getObjVal? "deny" with
    | .ok d => do
      let arr ← d.getArr?.mapError (fun _ => "manifest: 'deny' must be a list of strings")
      arr.toList.mapM fun x => x.getStr?.mapError (fun _ => "manifest: 'deny' must be a list of strings")
    | .error _ => pure []
  return { tools := m, defaultTool := dflt, deny := deny }

end Nope
