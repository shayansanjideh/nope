import Nope.Theorems

/-!
# Concrete sanity checks

Small closed examples evaluated by the kernel (`decide`) so the spec is visibly
non-vacuous on the demo scenarios.
-/

namespace Nope.Examples
open Spec Monitor

def secretsRead : Tool := ⟨⟨.secret, .trusted⟩, .secret, false⟩
def fetch       : Tool := ⟨⟨.pub, .untrusted⟩, .pub, false⟩
def commit      : Tool := ⟨⟨.pub, .trusted⟩, .internal, true⟩

def P : Manifest := fun
  | "fs_secret__read_file" => some secretsRead
  | "fetch__fetch" => some fetch
  | "git__git_commit" => some commit
  | _ => none

/-- Scenario 1: read secret, then fetch. The spec forbids it. -/
example : check P Label.bot [.call "fs_secret__read_file", .call "fetch__fetch"] = false := by
  decide

/-- ...and the monitor denies the fetch. -/
example : (run P init [.call "fs_secret__read_file", .call "fetch__fetch"]).1 =
    [.allow, .deny (.confTooHigh "fetch__fetch" .secret .pub)] := by decide

/-- Scenario 2: fetch, then commit: denied; after `endorse`, allowed. -/
example : (run P init [.call "fetch__fetch", .call "git__git_commit"]).1 =
    [.allow, .deny (.untrustedContext "git__git_commit")] := by decide
example : (run P init [.call "fetch__fetch", .endorse, .call "git__git_commit"]).1 =
    [.allow, .allow, .allow] := by decide

/-- Declassification makes the exfil-shaped trace satisfy the spec. -/
example : check P Label.bot
    [.call "fs_secret__read_file", .declassify .pub, .call "fetch__fetch"] = true := by decide

/-- Unknown tools are denied. -/
example : (run P init [.call "shell__exec"]).1 = [.deny (.unknownTool "shell__exec")] := by
  decide

end Nope.Examples
