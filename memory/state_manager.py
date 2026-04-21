"""
Dead-branch persistence layer.

Manages memory/hunt_state.json — a single JSON file keyed by target hostname.
Mirrors the jq logic used in agents/autopilot.md so the Python side and the
shell side read/write the same file interchangeably.

Shape:
    {
      "target.com": {
        "dead_branches": [
          {
            "endpoint": "...",
            "vuln_class": "idor" | null,
            "reason": "no_signal" | "rejected" | "out_of_scope",
            "ts": "2026-04-21T20:54:13Z"
          }
        ]
      }
    }

A stored `vuln_class` of `null` acts as a wildcard: the endpoint is dead for
every class (used when scope-check fails).
"""

import fcntl
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

DEFAULT_PATH = Path(__file__).parent / "hunt_state.json"
VALID_REASONS = ("no_signal", "rejected", "out_of_scope")


def _read_all(path: Path) -> dict:
    """Return the full state dict. Missing or unreadable file → empty dict."""
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f) or {}
    except (json.JSONDecodeError, OSError):
        return {}


@contextmanager
def _locked_state(path: Path) -> Iterator[dict]:
    """Exclusive-lock the state file, yield the full dict, commit on clean exit.

    Caller mutates the yielded dict in place. On normal return the dict is
    written back atomically (tmp-file + rename). On exception nothing is
    written. The lock is always released.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.parent / ".hunt_state.lock"
    lock_fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        full = _read_all(path)
        try:
            yield full
        except Exception:
            raise
        else:
            tmp = path.with_suffix(path.suffix + ".tmp")
            payload = json.dumps(full, indent=2, sort_keys=True) + "\n"
            with tmp.open("w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp, path)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def load_state(target: str, *, path: Path = DEFAULT_PATH) -> dict:
    """Return the per-target state. Missing target → {'dead_branches': []}."""
    full = _read_all(Path(path))
    return full.get(target, {"dead_branches": []})


def save_state(target: str, state: dict, *, path: Path = DEFAULT_PATH) -> None:
    """Replace the per-target state. Other targets in the file are preserved."""
    with _locked_state(Path(path)) as full:
        full[target] = state


def mark_dead_branch(
    target: str,
    endpoint: str,
    vuln_class: Optional[str],
    reason: str,
    *,
    path: Path = DEFAULT_PATH,
) -> None:
    """Record a dead branch. Dedups on (endpoint, vuln_class, reason) within target."""
    if reason not in VALID_REASONS:
        raise ValueError(f"reason must be one of {VALID_REASONS}, got {reason!r}")

    with _locked_state(Path(path)) as full:
        bucket = full.setdefault(target, {"dead_branches": []})
        branches = bucket.setdefault("dead_branches", [])

        key = (endpoint, vuln_class, reason)
        for b in branches:
            if (b.get("endpoint"), b.get("vuln_class"), b.get("reason")) == key:
                return

        branches.append({
            "endpoint": endpoint,
            "vuln_class": vuln_class,
            "reason": reason,
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })


def is_dead_branch(
    target: str,
    endpoint: str,
    vuln_class: Optional[str],
    *,
    path: Path = DEFAULT_PATH,
) -> bool:
    """True if (endpoint, vuln_class) is dead for target.

    A stored `vuln_class` of None matches any class (wildcard).
    """
    state = load_state(target, path=path)
    for b in state.get("dead_branches", []):
        if b.get("endpoint") != endpoint:
            continue
        stored = b.get("vuln_class")
        if stored is None or stored == vuln_class:
            return True
    return False
