"""Reading audit logs back: the executed history of a session and the records the
spec checker needs. Pure data extraction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_records(path: Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def decision_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Records that correspond to one engine event each, in engine order."""
    return [r for r in records if r["kind"] in ("call", "approval") and "verdict" in r]


def manifests(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r["manifest"] for r in records if r["kind"] in ("session_start", "session_resume")]


def speccheck_input(records: list[dict[str, Any]]) -> dict[str, Any]:
    ms = manifests(records)
    if not ms:
        raise ValueError("log has no session_start record")
    if any(m != ms[0] for m in ms):
        raise ValueError("log mixes manifests")
    dec = decision_records(records)
    return {
        "manifest": ms[0],
        "events": [r["event"] for r in dec],
        "verdicts": [r["verdict"] for r in dec],
        "states": [r["state"] for r in dec],
    }
