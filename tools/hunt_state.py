#!/usr/bin/env python3
"""CLI wrapper over memory.state_manager for dead-branch ops from bash.

Used by agents/autopilot.md so the markdown never has to embed Python.
Logic lives in memory/state_manager.py; this file is just argparse plumbing.
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
    VALID_REASONS,
    is_dead_branch,
    mark_dead_branch,
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

    c = sub.add_parser("check", help="Exit 0 if (endpoint, vuln_class) is dead, 1 otherwise.")
    c.add_argument("--target", required=True)
    c.add_argument("--endpoint", required=True)
    c.add_argument("--vuln-class", default="", help='Vuln class; empty string = wildcard (null)')

    r = sub.add_parser("record", help="Record a dead-branch entry. Always exits 0 on success.")
    r.add_argument("--target", required=True)
    r.add_argument("--endpoint", required=True)
    r.add_argument("--vuln-class", default="", help='Vuln class; empty string = wildcard (null)')
    r.add_argument("--reason", required=True, choices=list(VALID_REASONS))

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    vc = args.vuln_class or None
    path = Path(args.state_file)

    if args.cmd == "check":
        return 0 if is_dead_branch(args.target, args.endpoint, vc, path=path) else 1

    mark_dead_branch(args.target, args.endpoint, vc, args.reason, path=path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
