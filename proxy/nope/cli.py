"""nope command line.

  nope serve   --config nope.toml [--session ID]
  nope approve --config nope.toml --session ID endorse
  nope approve --config nope.toml --session ID declassify public|internal|secret
  nope status  --config nope.toml --session ID
  nope sessions --config nope.toml
  nope init-manifest --config nope.toml
  nope audit-check LOG.jsonl... [--speccheck PATH]
  nope setup claude-code [--settings PATH] [--remove]
  nope trust PATH... | --all
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

from .config import SEP, ConfigError, check_session_id, load_config, load_manifest_json
from .logreplay import read_records, speccheck_input


def _cfg(args):
    return load_config(args.config or os.environ.get("NOPE_CONFIG", "nope.toml"))


def cmd_serve(args) -> int:
    import asyncio  # noqa: F401  (lazy: keeps the hook fast)
    from . import control  # noqa: F401
    from .server import serve_stdio
    cfg = _cfg(args)
    session = check_session_id(
        args.session or f"{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}")
    asyncio.run(serve_stdio(cfg, session))
    return 0


def _cc_session(args):
    """A Claude Code hook session with this id, if no proxy config was given."""
    if args.config or os.environ.get("NOPE_CONFIG"):
        return None
    from .claude_code import FileSession
    s = FileSession(args.session)
    return s if s.exists() else None


def cmd_approve(args) -> int:
    import asyncio  # noqa: F401  (lazy: keeps the hook fast)
    from . import control  # noqa: F401
    check_session_id(args.session)
    if args.action == "endorse":
        event = {"type": "endorse"}
    else:
        if args.level not in ("public", "internal", "secret"):
            print("declassify needs a level: public | internal | secret", file=sys.stderr)
            return 2
        event = {"type": "declassify", "conf": args.level}
    approver = args.approver or getpass.getuser()
    cc = _cc_session(args)
    if cc:
        resp = cc.decide(event, "approval", approver=approver, note=args.note or "")
    else:
        cfg = _cfg(args)
        resp = control.request(cfg.socket_dir / f"{args.session}.sock", {
            "op": "approve", "event": event, "approver": approver, "note": args.note or ""})
    if "error" in resp:
        print(f"error: {resp['error']}", file=sys.stderr)
        return 1
    st = resp["state"]
    print(f"approved ({resp['verdict']}): {resp['reason']}")
    print(f"session {args.session} context now {st['conf']}/{st['integ']}")
    return 0


def cmd_status(args) -> int:
    import asyncio  # noqa: F401  (lazy: keeps the hook fast)
    from . import control  # noqa: F401
    cc = _cc_session(args)
    if cc:
        print(json.dumps({"session": args.session, "state": cc.state(), "log": str(cc.log)},
                         indent=2))
        return 0
    cfg = _cfg(args)
    resp = control.request(cfg.socket_dir / f"{check_session_id(args.session)}.sock",
                           {"op": "status"})
    print(json.dumps(resp, indent=2))
    return 0 if "error" not in resp else 1


def cmd_sessions(args) -> int:
    import asyncio  # noqa: F401  (lazy: keeps the hook fast)
    from . import control  # noqa: F401
    cfg = _cfg(args)
    socks = sorted(cfg.socket_dir.glob("*.sock")) if cfg.socket_dir.exists() else []
    live = [s.stem for s in socks if control._alive(s)]
    for s in live:
        print(s)
    if not live:
        print("(no running sessions)", file=sys.stderr)
    return 0


def cmd_init_manifest(args) -> int:
    import asyncio  # noqa: F401  (lazy: keeps the hook fast)
    from . import control  # noqa: F401
    """Print manifest entries for downstream tools the manifest does not declare yet,
    using the most restrictive defaults. Review and relax them by hand."""
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters
    cfg = _cfg(args)
    fresh = not cfg.manifest.exists() or not cfg.manifest.read_text().strip()
    current = {"tools": {}} if fresh else load_manifest_json(cfg.manifest)
    declared = set(current.get("tools", {}))

    async def collect():
        out = {}
        for spec in cfg.servers:
            p = StdioServerParameters(command=spec.command, args=spec.args, env=spec.env,
                                      cwd=spec.cwd)
            async with Client(p) as c:
                for t in (await c.list_tools()).tools:
                    name = f"{spec.name}{SEP}{t.name}"
                    if name not in declared:
                        out[name] = {
                            "description": (t.description or "").split("\n")[0][:120],
                            "outLabel": {"conf": "secret", "integ": "untrusted"},
                            "argClearance": "public",
                            "requiresTrusted": True,
                        }
        return out

    new = asyncio.run(collect())
    text = json.dumps({"version": 1, "tools": {**current.get("tools", {}), **new}}, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n")
    else:
        print(text)
    print(f"{len(new)} undeclared tools added with restrictive defaults", file=sys.stderr)
    return 0


def cmd_hook(args) -> int:
    from .claude_code import hook_main, post_hook_main
    fn = post_hook_main if args.client == "claude-code-post" else hook_main
    return fn(sys.stdin.read())


def cmd_setup(args) -> int:
    from .claude_code import APPARMOR_FIX, apparmor_blocks_sandbox, sandbox_missing, setup
    path = Path(args.settings or "~/.claude/settings.json").expanduser()
    cmd = setup(path, remove=args.remove, sandbox=not args.no_sandbox)
    if args.remove:
        print(f"Removed the Nope hook from {path} (sandbox settings left as they are; "
              "change them with /sandbox in Claude Code).")
        return 0
    print(f"Nope is on. Every Claude Code tool call is now checked (settings: {path}).")
    if not args.no_sandbox:
        print("Shell commands now run in Claude Code's sandbox and can only reach package "
              "registries and GitHub.\nAdd hosts under sandbox.network.allowedDomains in that file.")
        missing = sandbox_missing()
        if missing:
            print(f"\nThe sandbox needs {' and '.join(missing)} on Linux. Install with:\n"
                  "  sudo apt-get install bubblewrap socat    (Fedora: sudo dnf install ...)\n"
                  "Claude Code will refuse to start until they are installed.")
        if apparmor_blocks_sandbox():
            print("\nThis Linux (Ubuntu 24.04+) blocks the sandbox until bubblewrap may create "
                  "user namespaces. Allow just bubblewrap with:\n" + APPARMOR_FIX)
    print("Start a new Claude Code session for this to take effect.")
    return 0


def cmd_trust(args) -> int:
    from .claude_code import trust_paths
    removed = trust_paths(args.paths, all_=args.all)
    print(f"cleared remembered labels for {len(removed)} file(s)")
    for r in removed:
        print(f"  {r}")
    return 0


def default_speccheck() -> str:
    here = Path(__file__).resolve().parents[2] / "lean/.lake/build/bin/nope-speccheck"
    return str(here) if here.exists() else "nope-speccheck"


def cmd_audit_check(args) -> int:
    """Re-check logged sessions against the Lean spec checker."""
    inputs, names = [], []
    for p in args.logs:
        try:
            inputs.append(json.dumps(speccheck_input(read_records(Path(p)))))
            names.append(p)
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            print(f"{p}: cannot read: {e}")
            return 1
    out = subprocess.run([args.speccheck or default_speccheck()], input="\n".join(inputs) + "\n",
                         capture_output=True, text=True, check=True).stdout.splitlines()
    bad = 0
    for name, line in zip(names, out):
        r = json.loads(line)
        if r["ok"]:
            print(f"OK   {name} ({r['n']} events)")
        else:
            bad += 1
            print(f"FAIL {name}: {r['errors']}")
    return 1 if bad or len(out) != len(names) else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nope", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def with_config(p):
        p.add_argument("--config", help="path to nope.toml (default: $NOPE_CONFIG "
                                        "or ./nope.toml)")
        return p

    p = with_config(sub.add_parser("serve", help="run the MCP proxy on stdio"))
    p.add_argument("--session", help="session id (default: generated). Reusing an id resumes "
                                     "its taint from the audit log.")
    p.set_defaults(fn=cmd_serve)

    p = with_config(sub.add_parser("approve", help="human approval: endorse or declassify"))
    p.add_argument("--session", required=True)
    p.add_argument("--approver")
    p.add_argument("--note")
    p.add_argument("action", choices=["endorse", "declassify"])
    p.add_argument("level", nargs="?")
    p.set_defaults(fn=cmd_approve)

    p = with_config(sub.add_parser("status", help="show a running session's label"))
    p.add_argument("--session", required=True)
    p.set_defaults(fn=cmd_status)

    p = with_config(sub.add_parser("sessions", help="list running sessions"))
    p.set_defaults(fn=cmd_sessions)

    p = with_config(sub.add_parser("init-manifest",
                                   help="emit manifest skeleton for undeclared tools"))
    p.add_argument("-o", "--output", help="write here instead of stdout (may be the manifest itself)")
    p.set_defaults(fn=cmd_init_manifest)

    p = sub.add_parser("hook", help="(used by Claude Code) check one tool call from stdin")
    p.add_argument("client", choices=["claude-code", "claude-code-post"])
    p.set_defaults(fn=cmd_hook)

    p = sub.add_parser("setup", help="install the Nope hook into Claude Code")
    p.add_argument("client", choices=["claude-code"])
    p.add_argument("--settings", help="settings file (default ~/.claude/settings.json; "
                                      "use .claude/settings.json for one project)")
    p.add_argument("--remove", action="store_true", help="uninstall the hook")
    p.add_argument("--no-sandbox", action="store_true",
                   help="do not turn on Claude Code's shell sandbox (weaker: one shell command "
                        "could read and send data by itself)")
    p.set_defaults(fn=cmd_setup)

    p = sub.add_parser("trust", help="forget remembered secret/untrusted labels on files")
    p.add_argument("paths", nargs="*")
    p.add_argument("--all", action="store_true")
    p.set_defaults(fn=cmd_trust)

    p = sub.add_parser("audit-check", help="re-check audit logs against the Lean spec")
    p.add_argument("logs", nargs="+")
    p.add_argument("--speccheck")
    p.set_defaults(fn=cmd_audit_check)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except (ConfigError, RuntimeError) as e:
        print(f"nope: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
