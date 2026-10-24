"""Append-only JSONL audit log, one file per session."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class AuditLog:
    def __init__(self, log_dir: Path, session: str, fsync: bool = True):
        log_dir.mkdir(parents=True, exist_ok=True)
        self.path = log_dir / f"{session}.jsonl"
        self.session = session
        self.fsync = fsync
        self._fh = open(self.path, "a", encoding="utf-8")
        self._seq = sum(1 for _ in open(self.path, encoding="utf-8"))

    def write(self, kind: str, **fields: Any) -> None:
        rec = {"ts": now(), "seq": self._seq, "session": self.session, "kind": kind, **fields}
        self._fh.write(json.dumps(rec, sort_keys=True) + "\n")
        self._fh.flush()
        if self.fsync:
            os.fsync(self._fh.fileno())
        self._seq += 1

    def close(self) -> None:
        self._fh.close()
