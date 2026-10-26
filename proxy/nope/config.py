"""Config loading. Paths in the config are relative to the config file."""

from __future__ import annotations

import json
import re
import shutil
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEP = "__"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ConfigError(Exception):
    pass


@dataclass
class ServerSpec:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    cwd: Path | None = None


@dataclass
class Config:
    path: Path
    engine: Path
    manifest: Path
    state_dir: Path
    servers: list[ServerSpec]

    @property
    def log_dir(self) -> Path:
        return self.state_dir / "logs"

    @property
    def socket_dir(self) -> Path:
        return self.state_dir / "sockets"


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ConfigError(f"duplicate key {k!r}")
        out[k] = v
    return out


def load_manifest_json(path: Path) -> dict[str, Any]:
    """Parse the manifest, rejecting duplicate keys (Lean.Json would silently keep the
    last one). All other validation is done by the engine at startup."""
    try:
        return json.loads(path.read_text(), object_pairs_hook=_no_duplicate_keys)
    except (OSError, json.JSONDecodeError, ConfigError) as e:
        raise ConfigError(f"manifest {path}: {e}") from e


def _resolve(base: Path, p: str) -> Path:
    q = Path(p).expanduser()
    return q if q.is_absolute() else (base / q).resolve()


def default_engine() -> Path | None:
    here = Path(__file__).resolve().parents[2] / "lean/.lake/build/bin/nope-engine"
    if here.exists():
        return here
    found = shutil.which("nope-engine")
    if found:
        return Path(found)
    # Where the README's prebuilt install puts it; hooks may run without ~/.local/bin on PATH.
    local = Path.home() / ".local/bin/nope-engine"
    return local if local.exists() else None


def load_config(path: str | Path) -> Config:
    path = Path(path).resolve()
    try:
        raw = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"config {path}: {e}") from e
    base = path.parent
    unknown = set(raw) - {"engine", "manifest", "state_dir", "servers"}
    if unknown:
        raise ConfigError(f"config: unknown keys {sorted(unknown)}")
    if "manifest" not in raw:
        raise ConfigError("config: 'manifest' is required")
    engine = _resolve(base, raw["engine"]) if "engine" in raw else default_engine()
    if engine is None or not engine.exists():
        raise ConfigError("config: nope-engine not found (build lean/ or set 'engine')")
    servers = []
    for name, s in (raw.get("servers") or {}).items():
        if not NAME_RE.match(name) or SEP in name:
            raise ConfigError(f"server name {name!r}: use letters, digits, '-', single '_'")
        bad = set(s) - {"command", "args", "env", "cwd"}
        if bad or "command" not in s:
            raise ConfigError(f"server {name!r}: needs 'command'; unknown keys {sorted(bad)}")
        cmd = s["command"]
        if "/" in cmd:
            cmd = str(_resolve(base, cmd))
        servers.append(ServerSpec(
            name=name, command=cmd, args=[str(a) for a in s.get("args", [])],
            env=s.get("env"), cwd=_resolve(base, s["cwd"]) if "cwd" in s else base,
        ))
    if not servers:
        raise ConfigError("config: no [servers.*] defined")
    return Config(
        path=path, engine=engine, manifest=_resolve(base, raw["manifest"]),
        state_dir=_resolve(base, raw.get("state_dir", "~/.nope")), servers=servers,
    )


def check_session_id(s: str) -> str:
    if not SESSION_RE.match(s):
        raise ConfigError(f"invalid session id {s!r} (letters, digits, '.', '_', '-'; max 64)")
    return s
