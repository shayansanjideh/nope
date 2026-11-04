"""Block messages shown to the agent and the human.

The engine's reason text stays in the audit log unchanged. This layer rewrites what the
agent sees, adding facts only the proxy or hook has: the call's arguments. A declassify
approval lets data leave, so that message leads with what would leave and where it would
go. If the engine's text doesn't match, it is shown as is.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

CONF_RX = re.compile(r"^nope: blocked (\S+)\. This session has read (\w+) data"
                     r"(?: \(from (.+?)\))?, and \S+ only accepts \w+ data\.")
INTEG_RX = re.compile(r"^nope: blocked (\S+)\. This session has read untrusted content"
                      r"(?: \(from (.+?)\))?, and \S+ is a protected action")
PROOF_RX = re.compile(r"Proven in Lean: [^\n]*")
APPROVE_RX = re.compile(r"nope approve --session \S+ (?:endorse|declassify \w+)")
URL_RX = re.compile(r"""https?://[^\s'"<>`\\]+""")
PATH_KEYS = ("path", "file_path", "notebook_path", "destination")


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


def destination(arguments: Any, tool: str) -> tuple[str, str]:
    """(short name, full description) of where a call sends data. Query strings are
    dropped: they may hold the data itself, and this text goes back to the agent."""
    hosts: dict[str, str] = {}
    for s in _strings(arguments):
        for raw in URL_RX.findall(s):
            try:
                u = urlsplit(raw)
                host = u.hostname or ""
                if host and u.port:
                    host = f"{host}:{u.port}"
            except ValueError:
                continue
            if host:
                hosts.setdefault(host, f"{u.scheme}://{host}{u.path}")
    if hosts:
        names = list(hosts)[:3]
        return ", ".join(names), ", ".join(hosts[n] for n in names)
    if isinstance(arguments, dict):
        for k in PATH_KEYS:
            if isinstance(arguments.get(k), str):
                return arguments[k], f"the file {arguments[k]}"
    return tool, f"wherever {tool} sends it"


def explain_block(reason: str, arguments: Any) -> str:
    """Rewrite an engine deny reason for the agent."""
    cmds = APPROVE_RX.findall(reason)
    proof = PROOF_RX.search(reason)
    if not cmds or not proof:
        return reason
    conf = CONF_RX.match(reason)
    if conf:
        tool, level, source = conf.groups()
        short, full = destination(arguments, tool)
        src = f"read by {source}" if source else "read in this session"
        lines = [f"nope: blocked {tool}. WARNING: approving this lets {level} data ({src}) "
                 f"leave this machine. It would go to {full}.",
                 proof.group(0),
                 f"Agent: do not ask the user to run this unless they explicitly asked to send "
                 f"this data to {short}."]
        lines.append(f"To allow anyway: {cmds[0]}" if len(cmds) == 1
                     else "To allow anyway, run both:\n" + "\n".join(f"  {c}" for c in cmds))
        return "\n".join(lines)
    integ = INTEG_RX.match(reason)
    if integ:
        tool, source = integ.groups()
        note = f" (from {source})" if source else ""
        return (f"nope: blocked {tool}. This session read untrusted content{note}, so this "
                f"protected action needs approval. {proof.group(0)}\n"
                f"If that's expected: {cmds[0]}")
    return reason
