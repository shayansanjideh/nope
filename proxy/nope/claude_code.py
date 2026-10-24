"""Claude Code integration: a PreToolUse hook that sends every tool call (built-in tools
like Read, Bash and WebFetch, and MCP tools) through the Lean engine.

Division of labor, same as the proxy:
  * This module LABELS calls (which file is secret, which command touches the network).
    Labels are part of the trusted computing base, like a manifest.
  * The compiled Lean monitor DECIDES. No allow/deny logic lives here.

State: one append-only JSONL log per Claude session in ~/.nope/claude-code/sessions/.
Each hook invocation takes a file lock, replays the session's executed events through
the engine, decides the new event and appends it. No daemon to manage.

Files written by the agent remember the session label at write time
(~/.nope/claude-code/file-labels.json), so a secret cannot be laundered through a file
and read back as public later, and injected text cannot be planted in a file and read
back as trusted.
"""

from __future__ import annotations

import fcntl
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .audit import now
from .config import check_session_id, default_engine

HOME = Path(os.environ.get("NOPE_HOME", Path.home() / ".nope")).expanduser()
CC_DIR = HOME / "claude-code"
OVERLAY = HOME / "claude-code.json"  # user label overrides, merged into the profile
REGISTRY = CC_DIR / "file-labels.json"

CONFS = ["public", "internal", "secret"]
INTEGS = ["trusted", "untrusted"]

# --------------------------------------------------------------------------- labels

def L(conf: str, integ: str, clearance: str, req: bool, desc: str = "") -> dict:
    d = {"outLabel": {"conf": conf, "integ": integ}, "argClearance": clearance,
         "requiresTrusted": req}
    if desc:
        d["description"] = desc
    return d


def variant(base: str, conf: str, integ: str) -> str:
    tags = [t for t in (conf if conf != "public" else "", "untrusted" if integ == "untrusted"
                        else "") if t]
    return f"{base}[{','.join(tags)}]" if tags else base


def bash_variant(conf: str, integ: str) -> str:
    tags = [t for t in ("" if conf == "public" else conf,
                        "network" if integ == "untrusted" else "") if t]
    return f"Bash[{','.join(tags)}]" if tags else "Bash"


def profile_manifest() -> dict:
    """Labels for Claude Code's tools. Reading is local (clearance secret) and taints
    with the label of what was read. Bash can reach the network and change anything, so
    it only accepts public data and is a protected action. Web tools are sources of
    untrusted content and public sinks."""
    tools: dict[str, dict] = {}
    for base in ("Read", "Grep", "NotebookRead"):
        for c in CONFS:
            for i in INTEGS:
                tools[variant(base, c, i)] = L(c, i, "secret", False)
    for base in ("Glob", "LS"):
        tools[base] = L("public", "trusted", "secret", False, "file names only")
    for base in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        tools[base] = L("public", "trusted", "secret", False, "local file write")
        tools[f"{base}[agent-config]"] = L("public", "trusted", "secret", True,
                                           "writes instructions or config the agent loads")
    for c in CONFS:
        for i in INTEGS:
            tools[bash_variant(c, i)] = L(c, i, "public", True, "shell: can reach the network")
    for base in ("WebFetch", "WebSearch"):
        tools[base] = L("public", "untrusted", "public", False, "web: untrusted source, public sink")
    for base in ("Agent", "Task", "TodoWrite", "ToolSearch", "AskUserQuestion", "ExitPlanMode",
                 "EnterPlanMode", "Skill", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet",
                 "TaskOutput", "TaskStop", "BashOutput", "KillShell", "KillBash"):
        tools[base] = L("public", "trusted", "secret", False, "local, no external effect")
    deny = [f"{b}[nope-config]" for b in ("Write", "Edit", "MultiEdit", "NotebookEdit", "Bash")]
    m = {
        "version": 1,
        "description": "Nope profile for Claude Code built-in tools",
        "tools": tools,
        "defaultTool": L("secret", "untrusted", "public", True,
                         "unlabeled tool: assume the worst; label it in ~/.nope/claude-code.json"),
        "deny": deny,
    }
    if OVERLAY.exists():
        over = json.loads(OVERLAY.read_text())
        m["tools"].update(over.get("tools", {}))
        if "defaultTool" in over:
            m["defaultTool"] = over["defaultTool"]
    return m


# --------------------------------------------------------------------------- classify

SECRET_NAMES = [".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "id_ecdsa*",
                "id_dsa*", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.kdbx", "credentials",
                "credentials.*", "*secret*", "*.secrets", ".npmrc", ".pypirc", ".netrc",
                ".git-credentials", ".htpasswd", "service-account*.json", "*.tfvars",
                "terraform.tfstate*"]
NOT_SECRET = [".env.example", ".env.sample", ".env.template", ".env.dist", "*.pub"]
SECRET_DIRS = ["~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gh", "~/.docker", "~/.kube",
               "~/.config/gcloud", "~/.azure", "~/.password-store", "~/.nope"]
# Personal identity (name, email, host). Labeled "internal": fine to use locally, but it
# may not leave through a public sink such as a web request.
PERSONAL_PATHS = ["~/.gitconfig", "~/.config/git/config", "~/.claude.json"]

NOPE_CONFIG = ["~/.nope", "~/.claude/settings.json", "~/.claude/settings.local.json",
               "~/.claude.json"]
AGENT_CONFIG_NAMES = ["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".mcp.json", ".bashrc",
                      ".zshrc", ".profile", ".bash_profile", ".zprofile", ".gitconfig"]
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target",
             ".next", ".cache", ".lake"}


def _x(p: str) -> Path:
    return Path(os.path.expanduser(p)).resolve()


def _under(p: Path, roots: list[str]) -> bool:
    for r in roots:
        rr = _x(r)
        if p == rr or rr in p.parents:
            return True
    return False


def is_secret_path(p: Path) -> bool:
    name = p.name
    if any(fnmatch.fnmatch(name, pat) for pat in NOT_SECRET):
        return False
    return any(fnmatch.fnmatch(name, pat) for pat in SECRET_NAMES) or _under(p, SECRET_DIRS)


def is_nope_config(p: Path) -> bool:
    if _under(p, NOPE_CONFIG):
        return True
    return p.parent.name == ".claude" and fnmatch.fnmatch(p.name, "settings*.json")


def is_agent_config(p: Path) -> bool:
    return (p.name in AGENT_CONFIG_NAMES or ".claude" in p.parts or _under(p, ["~/.ssh"])
            or ("hooks" in p.parts and ".git" in p.parts) or (p.name == "config" and p.parent.name == ".git"))


def _join(a: tuple[str, str], b: tuple[str, str]) -> tuple[str, str]:
    return (max(a[0], b[0], key=CONFS.index), max(a[1], b[1], key=INTEGS.index))


def load_registry() -> dict[str, dict]:
    try:
        return json.loads(REGISTRY.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def path_conf(p: Path) -> str:
    if is_secret_path(p):
        return "secret"
    if _under(p, PERSONAL_PATHS):
        return "internal"
    return "public"


def file_label(p: Path, registry: dict) -> tuple[str, str]:
    lab = (path_conf(p), "trusted")
    r = registry.get(str(p))
    if r:
        lab = _join(lab, (r["conf"], r["integ"]))
    return lab


def _resolve(path: str | None, cwd: str) -> Path:
    p = Path(os.path.expanduser(path or cwd))
    return (p if p.is_absolute() else Path(cwd) / p).resolve()


def _walk(root: Path, limit: int = 20000):
    if root.is_file():
        yield root
        return
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            n += 1
            if n > limit:
                return
            yield Path(dirpath) / f


def grep_label(inp: dict, cwd: str, registry: dict) -> tuple[str, str]:
    """Label a Grep by what it would actually return: if the pattern matches inside a
    secret (or registry-labeled) file in scope, the result carries that label. Only
    file names are returned in files_with_matches mode, so that mode stays public."""
    if inp.get("output_mode", "files_with_matches") == "files_with_matches":
        return ("public", "trusted")
    root = _resolve(inp.get("path"), cwd)
    flags = re.IGNORECASE if inp.get("-i") else 0
    if inp.get("multiline"):
        flags |= re.DOTALL | re.MULTILINE
    try:
        rx = re.compile(inp.get("pattern", ""), flags)
    except re.error:
        rx = None  # cannot tell what it matches: assume it matches
    lab = ("public", "trusted")
    labeled = {Path(k) for k in registry}
    for f in _walk(root):
        cand = file_label(f, registry) if (path_conf(f) != "public" or f in labeled) else None
        if not cand or cand == ("public", "trusted"):
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        if rx is None or rx.search(text):
            lab = _join(lab, cand)
    return lab


# Commands whose output is arbitrary outside text (web pages, API responses, issue and PR
# bodies, remote shells). Package managers and git count as trusted: their output is
# logs, and code already on disk is trusted (see README limits).
NET_RX = re.compile(
    r"(^|[\s;&|(`$])(curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|ftp|telnet|http|https|"
    r"xh|gh|glab|aws|gcloud|az|kubectl|lynx|w3m)\b|https?://|/dev/tcp/")
ENV_DUMP_RX = re.compile(
    r"(^|[;&|(`]\s*)(env|printenv|set|export\s+-p|declare\s+-x|compgen\s+-v)\s*($|[;&|)>`])|"
    r"\$\{?[A-Za-z_]*(KEY|TOKEN|SECRET|PASSW|CREDENTIAL|PRIVATE)[A-Za-z_]*|"
    r"\b(security\s+find-(generic|internet)-password|gh\s+auth\s+token|aws\s+configure\s+get|"
    r"op\s+(read|item\s+get)|pass\s+show|gcloud\s+auth\s+print-access-token|keyring\s+get)\b",
    re.IGNORECASE)
PERSONAL_RX = re.compile(
    r"\bgit\s+config\b[^;&|]*(user\.|--list|\s-l\b|--get-regexp)|"
    r"(^|[;&|(`]\s*)(whoami|id|hostname|finger|getent\s+passwd)\b|"
    r"\$\{?(USER|LOGNAME|HOSTNAME|GIT_AUTHOR_\w+|GIT_COMMITTER_\w+)\b")
CONTROL_RX = re.compile(r"(^|[\s;&|(`$/])nope(\s|$|-engine)|\.nope\b|\.claude/settings|"
                        r"\.claude\.json|claude\s+mcp\b|claude\s+config\b")


def bash_name(cmd: str, cwd: str, registry: dict) -> str:
    """Label a shell command (heuristic, documented as part of the TCB)."""
    if CONTROL_RX.search(cmd):
        return "Bash[nope-config]"
    conf = "secret" if ENV_DUMP_RX.search(cmd) else \
        "internal" if PERSONAL_RX.search(cmd) else "public"
    labeled = {Path(k): v for k, v in registry.items()}
    untrusted_file = False
    for tok in re.findall(r"[^\s;&|<>()`'\"=]+", cmd):
        if "/" not in tok and "." not in tok and not tok.startswith("~"):
            continue
        p = _resolve(tok, cwd)
        conf = max(conf, path_conf(p), key=CONFS.index)
        r = labeled.get(p)
        if r:
            conf = max(conf, r["conf"], key=CONFS.index)
            untrusted_file |= r["integ"] == "untrusted"
    net = bool(NET_RX.search(cmd)) or untrusted_file
    return bash_variant(conf, "untrusted" if net else "trusted")


def classify(tool: str, inp: dict, cwd: str, registry: dict) -> str:
    """Map a Claude Code tool call to a manifest tool name."""
    if tool in ("Read", "NotebookRead"):
        p = _resolve(inp.get("file_path") or inp.get("notebook_path"), cwd)
        return variant(tool, *file_label(p, registry))
    if tool == "Grep":
        return variant("Grep", *grep_label(inp, cwd, registry))
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = _resolve(inp.get("file_path") or inp.get("notebook_path"), cwd)
        if is_nope_config(p):
            return f"{tool}[nope-config]"
        if is_agent_config(p):
            return f"{tool}[agent-config]"
        return tool
    if tool in ("Bash", "PowerShell", "Monitor"):
        return bash_name(str(inp.get("command", "")), cwd, registry)
    return tool


def written_path(tool: str, inp: dict, cwd: str) -> Path | None:
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return _resolve(inp.get("file_path") or inp.get("notebook_path"), cwd)
    return None


# --------------------------------------------------------------------------- sessions

@contextmanager
def locked(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def engine_path() -> Path:
    env = os.environ.get("NOPE_ENGINE")
    p = Path(env) if env else default_engine()
    if p is None or not p.exists():
        raise RuntimeError("nope-engine not found (set NOPE_ENGINE or build lean/)")
    return p


def run_engine(manifest_path: Path, session: str, events: list[dict]) -> list[dict]:
    """Feed events to a fresh engine process in one batch; return its responses."""
    inp = "".join(json.dumps({"session": session, "event": e}) + "\n" for e in events)
    out = subprocess.run([str(engine_path()), "--manifest", str(manifest_path)], input=inp,
                         capture_output=True, text=True, timeout=20)
    if out.returncode != 0:
        raise RuntimeError(f"engine failed: {out.stderr.strip()}")
    lines = out.stdout.splitlines()
    if not lines or not json.loads(lines[0]).get("ready"):
        raise RuntimeError("engine did not start")
    resps = [json.loads(l) for l in lines[1:]]
    if len(resps) != len(events) or any("error" in r for r in resps):
        raise RuntimeError(f"engine protocol error: {resps[-1:] }")
    return resps


class FileSession:
    def __init__(self, session: str):
        self.session = check_session_id(session)
        self.dir = CC_DIR / "sessions"
        self.log = self.dir / f"{session}.jsonl"
        self.manifest = self.dir / f"{session}.manifest.json"
        self.lock = self.dir / f"{session}.lock"

    def exists(self) -> bool:
        return self.log.exists()

    def _records(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(l) for l in self.log.read_text().splitlines() if l.strip()]

    def _append(self, rec: dict, seq: int) -> None:
        with open(self.log, "a") as fh:
            fh.write(json.dumps({"ts": now(), "seq": seq, "session": self.session, **rec},
                                sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _ensure_started(self) -> list[dict]:
        recs = self._records()
        if not recs:
            self.dir.mkdir(parents=True, exist_ok=True)
            m = profile_manifest()
            self.manifest.write_text(json.dumps(m, indent=1))
            self._append({"kind": "session_start", "manifest": m, "client": "claude-code",
                          "state": {"conf": "public", "integ": "trusted"}}, 0)
            recs = self._records()
        return recs

    def decide(self, event: dict, kind: str, **extra: Any) -> dict:
        with locked(self.lock):
            recs = self._ensure_started()
            history = [r["event"] for r in recs
                       if r["kind"] in ("call", "approval") and r.get("verdict") == "allow"]
            resps = run_engine(self.manifest, self.session, history + [event])
            if any(r["verdict"] != "allow" for r in resps[:-1]):
                raise RuntimeError("session log replay diverged; refusing to decide")
            resp = resps[-1]
            self._append({"kind": kind, "event": resp["event"], "verdict": resp["verdict"],
                          "code": resp["code"], "reason": resp["reason"],
                          "theorem": resp.get("theorem"), "state": resp["state"], **extra},
                         len(recs))
            return resp

    def state(self) -> dict:
        recs = self._records()
        dec = [r for r in recs if r["kind"] in ("call", "approval") and "state" in r]
        return dec[-1]["state"] if dec else {"conf": "public", "integ": "trusted"}


def remember_write(path: Path, state: dict) -> None:
    lab = (state["conf"], state["integ"])
    if lab == ("public", "trusted"):
        return
    with locked(CC_DIR / "file-labels.lock"):
        reg = load_registry()
        old = reg.get(str(path))
        if old:
            lab = _join(lab, (old["conf"], old["integ"]))
        reg[str(path)] = {"conf": lab[0], "integ": lab[1]}
        REGISTRY.parent.mkdir(parents=True, exist_ok=True)
        tmp = REGISTRY.with_suffix(".tmp")
        tmp.write_text(json.dumps(reg, indent=1, sort_keys=True))
        tmp.replace(REGISTRY)


def trust_paths(paths: list[str], all_: bool = False) -> list[str]:
    with locked(CC_DIR / "file-labels.lock"):
        reg = load_registry()
        if all_:
            removed = list(reg)
            reg = {}
        else:
            keys = {str(_resolve(p, os.getcwd())) for p in paths}
            removed = [k for k in reg if k in keys]
            reg = {k: v for k, v in reg.items() if k not in keys}
        REGISTRY.parent.mkdir(parents=True, exist_ok=True)
        REGISTRY.write_text(json.dumps(reg, indent=1, sort_keys=True))
    return removed


# --------------------------------------------------------------------------- hook

def _summ(v: Any) -> Any:
    if isinstance(v, str):
        return v if len(v) <= 300 else v[:300] + f"...(+{len(v) - 300} chars)"
    if isinstance(v, dict):
        return {k: _summ(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_summ(x) for x in v[:20]]
    return v


def deny(reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))


def hook_main(stdin: str) -> int:
    """PreToolUse hook entry point. Allow: exit 0 with no output (Claude Code's normal
    permission flow continues). Deny: JSON with the engine's reason. Errors: deny."""
    try:
        data = json.loads(stdin)
        session = data["session_id"]
        tool, inp = data["tool_name"], data.get("tool_input") or {}
        cwd = data.get("cwd") or os.getcwd()
        registry = load_registry()
        name = classify(tool, inp, cwd, registry)
        resp = FileSession(session).decide(
            {"type": "call", "tool": name}, "call", tool_name=tool, tool_input=_summ(inp),
            agent_id=data.get("agent_id"), cwd=cwd)
        if resp["verdict"] != "allow":
            deny(resp["reason"])
            return 0
        wp = written_path(tool, inp, cwd)
        if wp is not None:
            remember_write(wp, resp["state"])
        return 0
    except Exception as e:  # fail closed
        deny(f"nope: blocked this call because Nope hit an internal error ({e}). "
             "Nothing runs unchecked; fix the error or remove the hook with "
             "`nope setup claude-code --remove`.")
        return 0


# --------------------------------------------------------------------------- setup

def hook_command() -> str:
    exe = shutil.which("nope") or str(Path(sys.argv[0]).resolve())
    return f"'{exe}' hook claude-code"


def _is_ours(h: dict) -> bool:
    return "hook claude-code" in str(h.get("command", ""))


# Shell commands may reach only these hosts (package registries and GitHub), so one
# command cannot read a secret and send it to an arbitrary server by itself.
SANDBOX_DOMAINS = [
    "github.com", "*.github.com", "*.githubusercontent.com", "registry.npmjs.org",
    "*.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
    "crates.io", "*.crates.io", "proxy.golang.org", "sum.golang.org", "rubygems.org",
    "repo.maven.apache.org",
]
SANDBOX_DENY_WRITE = ["~/.nope", "~/.claude/settings.json", "~/.claude/settings.local.json",
                      "~/.claude.json"]


def sandbox_missing() -> list[str]:
    """Linux needs bubblewrap and socat for Claude Code's sandbox."""
    if sys.platform.startswith("linux"):
        return [b for b in ("bwrap", "socat") if not shutil.which(b)]
    return []


def apparmor_blocks_sandbox() -> bool:
    """Ubuntu 24.04+ restricts user namespaces unless bwrap has an AppArmor profile."""
    flag = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    try:
        restricted = flag.read_text().strip() == "1"
    except OSError:
        return False
    return restricted and not Path("/etc/apparmor.d/bwrap").exists()


APPARMOR_FIX = (
    "  printf 'abi <abi/4.0>,\\ninclude <tunables/global>\\n"
    "profile bwrap /usr/bin/bwrap flags=(unconfined) {\\n  userns,\\n}\\n' "
    "| sudo tee /etc/apparmor.d/bwrap >/dev/null\n"
    "  sudo apparmor_parser -r /etc/apparmor.d/bwrap")


def apply_sandbox(data: dict) -> None:
    sb = data.setdefault("sandbox", {})
    sb["enabled"] = True
    sb["failIfUnavailable"] = True          # never silently run without the sandbox
    sb["allowUnsandboxedCommands"] = False  # no "retry outside the sandbox" escape hatch
    net = sb.setdefault("network", {})
    net["strictAllowlist"] = True
    doms = net.setdefault("allowedDomains", [])
    doms += [d for d in SANDBOX_DOMAINS if d not in doms]
    fs = sb.setdefault("filesystem", {})
    dw = fs.setdefault("denyWrite", [])
    dw += [d for d in SANDBOX_DENY_WRITE if d not in dw]


def setup(settings_path: Path, remove: bool = False, sandbox: bool = True) -> str:
    settings_path = settings_path.expanduser()
    data = json.loads(settings_path.read_text()) if settings_path.exists() and \
        settings_path.read_text().strip() else {}
    if settings_path.exists():
        shutil.copy2(settings_path, settings_path.with_suffix(".json.nope-backup"))
    pre = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    for group in pre:
        group["hooks"] = [h for h in group.get("hooks", []) if not _is_ours(h)]
    pre[:] = [g for g in pre if g.get("hooks")]
    if not remove:
        pre.insert(0, {"matcher": "*", "hooks": [{
            "type": "command", "command": hook_command(), "timeout": 30, "onFailure": "block"}]})
        if sandbox:
            apply_sandbox(data)
    if not pre:
        del data["hooks"]["PreToolUse"]
    if not data["hooks"]:
        del data["hooks"]
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(data, indent=2) + "\n")
    return hook_command()
