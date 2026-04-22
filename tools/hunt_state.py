#!/usr/bin/env python3
"""CLI wrapper over memory.state_manager for dead-branch and candidate ops from bash.

Used by agents/autopilot.md so the markdown never has to embed Python.
Logic lives in memory/state_manager.py; this file is just argparse plumbing.

Subcommands
-----------
check      Exit 0 if (endpoint, vuln_class, method, auth_state) is a dead branch.
record     Record a dead-branch entry.
candidate  Add an endpoint to the candidates list for auto-replay testing.

Context-aware flags (check / record only):

    --vuln-class   class being tested (empty string = wildcard / null)
    --method       HTTP method being tested (empty string = wildcard / null)
    --auth-state   one of anonymous|authenticated, or empty string for wildcard

Empty strings are normalized to None at the boundary and stored as JSON null.
"""

import argparse
import sys
from pathlib import Path

# Make `from memory.state_manager import ...` resolve regardless of cwd.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from memory.state_manager import (  # noqa: E402
    DEFAULT_PATH,
    VALID_AUTH_STATES,
    VALID_REASONS,
    add_candidate,
    is_dead_branch,
    mark_dead_branch,
)


def _add_context_args(sub: argparse.ArgumentParser) -> None:
    """Flags shared by both `check` and `record`."""
    sub.add_argument("--target", required=True)
    sub.add_argument("--endpoint", required=True)
    sub.add_argument(
        "--vuln-class", default="",
        help="Vuln class; empty string = wildcard (null).",
    )
    sub.add_argument(
        "--method", default="",
        help="HTTP method (GET/POST/...); empty string = wildcard (null).",
    )
    sub.add_argument(
        "--auth-state", default="", choices=("", *VALID_AUTH_STATES),
        help="Auth context; empty string = wildcard (null).",
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hunt-state",
        description="Check or record dead-branch entries in memory/hunt_state.json.",
    )
    p.add_argument(
        "--state-file",
        default=str(DEFAULT_PATH),
        help=f"Path to hunt_state.json (default: {DEFAULT_PATH})",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser(
        "check",
        help="Exit 0 if (endpoint, vuln_class, method, auth_state) is dead, 1 otherwise.",
    )
    _add_context_args(c)

    r = sub.add_parser("record", help="Record a dead-branch entry. Always exits 0 on success.")
    _add_context_args(r)
    r.add_argument("--reason", required=True, choices=list(VALID_REASONS))

    cand = sub.add_parser(
        "candidate",
        help=(
            "Add an endpoint to the candidates list for auto-replay testing. "
            "Deduplicates by (endpoint, method) — re-adding an existing pair is a no-op."
        ),
    )
    cand.add_argument("--target", required=True, help="Target hostname key in hunt_state.json.")
    cand.add_argument("--endpoint", required=True, help="Path or URL of the candidate endpoint.")
    cand.add_argument(
        "--method", default="GET",
        help="HTTP method (default: GET).",
    )

    return p


def _normalize(value: str) -> str | None:
    """Empty string → None (wildcard). Otherwise return the string as-is."""
    return value or None


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    path = Path(args.state_file)

    if args.cmd == "candidate":
        try:
            add_candidate(args.target, args.endpoint, args.method, path=path)
            print(f"Candidate added: {args.endpoint} {args.method.upper()}")
            return 0
        except Exception as exc:  # noqa: BLE001
            print(f"Error adding candidate: {exc}", file=sys.stderr)
            return 1

    vc = _normalize(args.vuln_class)
    method = _normalize(args.method)
    auth_state = _normalize(args.auth_state)

    if args.cmd == "check":
        dead = is_dead_branch(
            args.target, args.endpoint, vc,
            method=method, auth_state=auth_state, path=path,
        )
        return 0 if dead else 1

    mark_dead_branch(
        args.target, args.endpoint, vc, args.reason,
        method=method, auth_state=auth_state, path=path,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
