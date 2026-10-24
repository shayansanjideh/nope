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
import functools
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


def bash_variant(conf: str, network: bool, protected: bool) -> str:
    tags = [t for t in ("" if conf == "public" else conf, "network" if network else "",
                        "protected" if protected else "") if t]
    return f"Bash[{','.join(tags)}]" if tags else "Bash"


def sandboxed() -> bool:
    """Was `nope setup` run with Claude Code's sandbox on? Without it, every shell
    command is treated as a protected action."""
    try:
        return bool(json.loads((CC_DIR / "config.json").read_text()).get("sandbox"))
    except (OSError, json.JSONDecodeError):
        return False


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
    # Shell commands only accept public data (they could send it somewhere). Commands that
    # fetch outside content or have outside effects (push, publish, deploy, ssh) are
    # protected. Other commands (tests, builds, local git) are protected too unless Claude
    # Code's sandbox confines them.
    sb = sandboxed()
    for c in CONFS:
        for net in (False, True):
            for prot in (False, True):
                tools[bash_variant(c, net, prot)] = L(
                    c, "untrusted" if net else "trusted", "public", net or prot or not sb,
                    "shell command")
    for base in ("WebFetch", "WebSearch"):
        tools[base] = L("public", "untrusted", "public", False, "web: untrusted source, public sink")
    for base in ("Agent", "Task", "TodoWrite", "ToolSearch", "AskUserQuestion", "ExitPlanMode",
                 "EnterPlanMode", "Skill", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet",
                 "TaskOutput", "TaskStop", "BashOutput", "KillShell", "KillBash"):
        tools[base] = L("public", "trusted", "secret", False, "local, no external effect")
    # Recorded after a tool returns, when its output turns out to contain known secret or
    # personal values (however the command was disguised). Reading is always allowed; it
    # raises the session label.
    for c in ("internal", "secret"):
        tools[f"Output[{c}]"] = L(c, "trusted", "secret", False,
                                 "tool output contained known sensitive values")
    deny =[f"{b}[nope-config]" for b in ("Write", "Edit", "MultiEdit", "NotebookEdit", "Bash")]
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


@functools.lru_cache(maxsize=None)
def _x(p: str) -> Path:
    return Path(os.path.expanduser(p)).resolve()


def _under(p: Path, roots: list[str]) -> bool:
    s = str(p)
    for r in roots:
        rr = str(_x(r))
        if s == rr or s.startswith(rr.rstrip(os.sep) + os.sep):
            return True
    return False


_SECRET_NAME_RX = re.compile("|".join(fnmatch.translate(p) for p in SECRET_NAMES))
_NOT_SECRET_RX = re.compile("|".join(fnmatch.translate(p) for p in NOT_SECRET))


def is_secret_path(p: Path) -> bool:
    name = p.name
    if _NOT_SECRET_RX.match(name):
        return False
    return bool(_SECRET_NAME_RX.match(name)) or _under(p, SECRET_DIRS)


def sensitive_files(root: Path) -> list[Path]:
    """Files under root whose path marks them secret or personal. Cached for 30 seconds
    per directory (paths only, never contents), so large trees are not rescanned on
    every tool call."""
    import hashlib
    import time
    cache = CC_DIR / "cache" / (hashlib.sha256(str(root).encode()).hexdigest()[:24] + ".json")
    try:
        c = json.loads(cache.read_text())
        if time.time() - c["t"] < 30:
            return [Path(f) for f in c["files"]]
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    files = [f for f in _walk(root) if path_conf(f) != "public"]
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"t": time.time(), "files": [str(f) for f in files]}))
    except OSError:
        pass
    return files


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
    rs = str(root)
    scope = sensitive_files(root) + [f for f in labeled
                                    if str(f) == rs or str(f).startswith(rs.rstrip(os.sep) + os.sep)]
    for f in scope:
        cand = file_label(f, registry)
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
# Commands with effects outside this machine or on how the agent runs.
PROTECTED_RX = re.compile(
    r"\bgit\s+(push|config|remote\s+(add|set-url)|credential|send-email|submodule\s+add)\b|"
    r"\bgh\s+(pr|issue|release|repo|gist|api|secret|workflow|auth)\s|"
    r"\b(npm|pnpm|yarn)\s+publish\b|\bcargo\s+publish\b|\btwine\s+upload\b|"
    r"\bdocker\s+(push|login)\b|\bkubectl\s+(apply|delete|create|patch|scale|exec|edit)\b|"
    r"\bterraform\s+(apply|destroy|import)\b|\bhelm\s+(install|upgrade|uninstall)\b|"
    r"(^|[\s;&|(`])(aws|gcloud|az|ssh|scp|sftp|rsync|sudo|su|crontab|systemctl|launchctl|"
    r"vercel|netlify|fly|heroku|firebase|wrangler)\b|"
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+(/|~|\$HOME)")
MESSAGE_RX = re.compile(r"""(-[A-Za-z]*m|--message|-F)\s*(=\s*)?("(\\.|[^"\\])*"|'[^']*')""")
HEREDOC_RX = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?.*?\n.*?\n\1\b", re.S)


def _strip_text(cmd: str) -> str:
    """Drop commit messages and heredoc bodies: text, not commands."""
    return HEREDOC_RX.sub("<<HEREDOC", MESSAGE_RX.sub("-m MSG", cmd))


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
    code = _strip_text(cmd)
    conf = "secret" if ENV_DUMP_RX.search(code) else \
        "internal" if PERSONAL_RX.search(code) else "public"
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
    net = bool(NET_RX.search(code)) or untrusted_file
    return bash_variant(conf, net, bool(PROTECTED_RX.search(code)))


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


def written_text(tool: str, inp: dict) -> str:
    if tool == "Write":
        return str(inp.get("content", ""))
    if tool in ("Edit", "NotebookEdit"):
        return str(inp.get("new_string") or inp.get("new_source") or "")
    if tool == "MultiEdit":
        return "\n".join(str(e.get("new_string", "")) for e in inp.get("edits", []))
    return ""


def remember_write(path: Path, text: str, cwd: str) -> None:
    """If what the agent wrote contains known secret or personal values (in any of the
    encodings the output scan understands), remember the file at that level, so the
    value cannot be laundered through the file and read back as public later."""
    level = output_level(text, cwd, load_registry())
    if level == "public":
        return
    lab = (level, "trusted")
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


# --------------------------------------------------------------------------- output scan

HOME_SECRET_FILES = ["~/.aws/credentials", "~/.config/gh/hosts.yml", "~/.netrc", "~/.npmrc",
                     "~/.pypirc", "~/.docker/config.json", "~/.kube/config",
                     "~/.git-credentials"]
SECRET_ENV_RX = re.compile(r"KEY|TOKEN|SECRET|PASSW|CREDENTIAL|PRIVATE|AUTH|SESSION|COOKIE",
                           re.IGNORECASE)
VALUE_RX = re.compile(r"""^\s*(?:export\s+)?["']?[\w.\-]+["']?\s*[=:]\s*["']?([^"'\s#][^"'#]*?)["']?\s*,?\s*$""")
B64_RUN = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){8,}")
MIN_VALUE = 8


def _values_from_text(text: str) -> set[str]:
    vals: set[str] = set()
    for line in text.splitlines()[:5000]:
        m = VALUE_RX.match(line)
        if m and len(m.group(1).strip()) >= MIN_VALUE:
            vals.add(m.group(1).strip())
        s = line.strip()
        if len(s) >= 20 and re.fullmatch(r"[A-Za-z0-9+/=]+", s):  # PEM / key body lines
            vals.add(s)
    return vals


def _read_small(p: Path, limit: int = 256_000) -> str | None:
    try:
        if p.is_file() and p.stat().st_size <= limit:
            return p.read_text(errors="replace")
    except OSError:
        pass
    return None


def sensitive_values(cwd: str, registry: dict) -> dict[str, set[str]]:
    """Known secret and personal values on this machine, by confidentiality level.
    Kept in memory only; never written to disk or logs."""
    secret: set[str] = set()
    files = [f for f in sensitive_files(Path(cwd)) if is_secret_path(f)]
    files += [_x(p) for p in HOME_SECRET_FILES]
    ssh = _x("~/.ssh")
    if ssh.is_dir():
        files += [f for f in ssh.iterdir() if f.is_file() and not f.name.endswith(".pub")
                  and f.name not in ("known_hosts", "known_hosts.old", "config")]
    files += [Path(k) for k, v in registry.items() if v.get("conf") == "secret"]
    for f in files:
        text = _read_small(f)
        if text:
            secret |= _values_from_text(text)
    for k, v in os.environ.items():
        if SECRET_ENV_RX.search(k) and len(v) >= MIN_VALUE and k not in ("NOPE_HOME",):
            secret.add(v)
    personal: set[str] = set()
    for p in PERSONAL_PATHS[:2]:
        text = _read_small(_x(p))
        if text:
            for m in re.finditer(r"^\s*(email|name)\s*=\s*(.+?)\s*$", text, re.M):
                v = m.group(2)
                if (m.group(1) == "email" and "@" in v) or (" " in v and len(v) >= 6):
                    personal.add(v)
    return {"secret": secret, "internal": personal - secret}


def _decodings(text: str) -> list[str]:
    import base64
    import binascii
    from urllib.parse import unquote_plus
    out = [text, unquote_plus(text)]
    for run in B64_RUN.findall(text)[:2000]:
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                out.append(dec(run + "=" * (-len(run) % 4)).decode("utf-8", "replace"))
                break
            except (binascii.Error, ValueError):
                continue
    for run in HEX_RUN.findall(text)[:2000]:
        try:
            out.append(bytes.fromhex(re.sub(r"[\s:]", "", run)).decode("utf-8", "replace"))
        except ValueError:
            pass
    # xxd-style dumps: join the hex columns of consecutive lines.
    cols = re.findall(r"^[0-9a-f]{8}: ((?:[0-9a-f]{4} ?){1,8})", text, re.M)
    if cols:
        try:
            out.append(bytes.fromhex("".join(c.replace(" ", "") for c in cols))
                       .decode("utf-8", "replace"))
        except ValueError:
            pass
    return out


def output_level(response: Any, cwd: str, registry: dict) -> str:
    """Highest confidentiality of known values found in a tool's output."""
    text = response if isinstance(response, str) else json.dumps(response, ensure_ascii=False)
    if len(text) < MIN_VALUE:
        return "public"
    vals = sensitive_values(cwd, registry)
    if not vals["secret"] and not vals["internal"]:
        return "public"
    hay = "\n".join(_decodings(text))
    if any(v in hay for v in vals["secret"]):
        return "secret"
    if any(v in hay for v in vals["internal"]):
        return "internal"
    return "public"


def post_hook_main(stdin: str) -> int:
    """PostToolUse hook: if a tool's output contained known sensitive values, record that
    the session has now read them. Fails closed by marking the session secret."""
    try:
        data = json.loads(stdin)
        session, tool = data["session_id"], data["tool_name"]
        cwd = data.get("cwd") or os.getcwd()
        level = output_level(data.get("tool_response"), cwd, load_registry())
        if level != "public":
            FileSession(session).decide({"type": "call", "tool": f"Output[{level}]"}, "call",
                                        tool_name=tool, source="output-scan", cwd=cwd)
        return 0
    except Exception as e:
        try:
            FileSession(data["session_id"]).decide(  # type: ignore[possibly-undefined]
                {"type": "call", "tool": "Output[secret]"}, "call", source="output-scan-error",
                error=str(e)[:200])
        except Exception:
            pass  # the next PreToolUse will hit the same failure and block
        return 0


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
        if wp is not None and resp["state"]["conf"] != "public":
            remember_write(wp, written_text(tool, inp), cwd)
        return 0
    except Exception as e:  # fail closed
        deny(f"nope: blocked this call because Nope hit an internal error ({e}). "
             "Nothing runs unchecked; fix the error or remove the hook with "
             "`nope setup claude-code --remove`.")
        return 0


# --------------------------------------------------------------------------- setup

def hook_command(sub: str = "claude-code") -> str:
    exe = shutil.which("nope") or str(Path(sys.argv[0]).resolve())
    return f"'{exe}' hook {sub}"


def _is_ours(h: dict) -> bool:
    return re.search(r"hook claude-code(-post)?$", str(h.get("command", ""))) is not None


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
    hooks = data.setdefault("hooks", {})
    for event, sub in (("PreToolUse", "claude-code"), ("PostToolUse", "claude-code-post")):
        groups = hooks.setdefault(event, [])
        for group in groups:
            group["hooks"] = [h for h in group.get("hooks", []) if not _is_ours(h)]
        groups[:] = [g for g in groups if g.get("hooks")]
        if not remove:
            groups.insert(0, {"matcher": "*", "hooks": [{
                "type": "command", "command": hook_command(sub), "timeout": 30,
                "onFailure": "block"}]})
        if not groups:
            del hooks[event]
    if not remove and sandbox:
        apply_sandbox(data)
    if not remove:
        CC_DIR.mkdir(parents=True, exist_ok=True)
        (CC_DIR / "config.json").write_text(json.dumps({"sandbox": sandbox}) + "\n")
    if not hooks:
        del data["hooks"]
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(data, indent=2) + "\n")
    return hook_command()
