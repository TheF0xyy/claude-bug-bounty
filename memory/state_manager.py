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
            "method": "GET" | null,
            "auth_state": "anonymous" | "authenticated" | null,
            "reason": "no_signal" | "rejected" | "out_of_scope",
            "ts": "2026-04-21T20:54:13Z"
          }
        ]
      }
    }

Context fields (`vuln_class`, `method`, `auth_state`) use `null` as a wildcard
on the *stored* side only: a stored `null` matches any probe value, but a probe
that supplies a specific value will NOT match a stored entry whose value is
different. This is what prevents false skips across contexts (e.g. anonymous
dead must not imply authenticated dead; GET dead must not imply POST dead).

Legacy entries written before the context-aware patch have no `method` /
`auth_state` keys; those missing keys are read as `null` → wildcard, which
preserves the pre-patch matching behavior for old state files.
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
VALID_AUTH_STATES = ("anonymous", "authenticated")


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


def _matches(stored: Optional[str], probe: Optional[str]) -> bool:
    """Stored-side wildcard match. stored=None → matches any probe.

    Otherwise the probe must equal the stored value exactly. A probe that
    passes None against a non-None stored value does NOT match: callers that
    want wildcard behavior on a dimension must omit that dimension on BOTH
    sides, or explicitly store a wildcard entry.
    """
    return stored is None or stored == probe


def mark_dead_branch(
    target: str,
    endpoint: str,
    vuln_class: Optional[str],
    reason: str,
    *,
    method: Optional[str] = None,
    auth_state: Optional[str] = None,
    path: Path = DEFAULT_PATH,
) -> None:
    """Record a dead branch.

    Dedups on (endpoint, vuln_class, method, auth_state, reason) within target.
    A None value for any of vuln_class/method/auth_state is stored as a
    wildcard and will match every probe value on that dimension.
    """
    if reason not in VALID_REASONS:
        raise ValueError(f"reason must be one of {VALID_REASONS}, got {reason!r}")
    if auth_state is not None and auth_state not in VALID_AUTH_STATES:
        raise ValueError(
            f"auth_state must be one of {VALID_AUTH_STATES} or None, got {auth_state!r}"
        )

    with _locked_state(Path(path)) as full:
        bucket = full.setdefault(target, {"dead_branches": []})
        branches = bucket.setdefault("dead_branches", [])

        key = (endpoint, vuln_class, method, auth_state, reason)
        for b in branches:
            existing = (
                b.get("endpoint"),
                b.get("vuln_class"),
                b.get("method"),
                b.get("auth_state"),
                b.get("reason"),
            )
            if existing == key:
                return

        branches.append({
            "endpoint": endpoint,
            "vuln_class": vuln_class,
            "method": method,
            "auth_state": auth_state,
            "reason": reason,
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })


def is_dead_branch(
    target: str,
    endpoint: str,
    vuln_class: Optional[str],
    *,
    method: Optional[str] = None,
    auth_state: Optional[str] = None,
    path: Path = DEFAULT_PATH,
) -> bool:
    """True if a stored dead branch matches the probe context.

    Matching requires endpoint equality plus a stored-side-wildcard match on
    each of vuln_class / method / auth_state (see `_matches`). Legacy entries
    written before the context-aware patch have no method/auth_state keys;
    `.get()` returns None, which is the wildcard, so they still match any
    probe — preserving pre-patch behavior.
    """
    state = load_state(target, path=path)
    for b in state.get("dead_branches", []):
        if b.get("endpoint") != endpoint:
            continue
        if not _matches(b.get("vuln_class"), vuln_class):
            continue
        if not _matches(b.get("method"), method):
            continue
        if not _matches(b.get("auth_state"), auth_state):
            continue
        return True
    return False
