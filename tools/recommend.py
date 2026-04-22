#!/usr/bin/env python3
"""CLI wrapper over tools/vuln_recommender.py for autopilot bash integration.

Reads `(endpoint, method, auth_state)` flags, prints the priority-ordered
vuln class list one-per-line on stdout. Empty output = no recommendation
(caller should skip the endpoint this cycle; this is NOT a dead-branch
mark — autopilot must not record anything in state as a result).

Example (from autopilot's inner loop):
    mapfile -t CLASSES < <(
        python3 tools/recommend.py \\
            --endpoint "$ENDPOINT" --method "$METHOD" --auth-state "$AUTH_STATE"
    )

Flags mirror tools/hunt_state.py exactly so the bash call sites look the
same:  --endpoint / --method / --auth-state  (empty string = unknown).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from vuln_recommender import recommend_vuln_classes  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recommend",
        description=(
            "Print the priority-ordered vuln classes for an endpoint. "
            "Deterministic; never writes state; empty output means no "
            "hypothesis (caller may skip, but MUST NOT record dead)."
        ),
    )
    p.add_argument("--endpoint", required=True)
    p.add_argument("--method", default="GET")
    p.add_argument(
        "--auth-state", default="", choices=("", "anonymous", "authenticated"),
        help="Auth context; empty string = unknown.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    classes = recommend_vuln_classes(
        args.endpoint,
        method=args.method,
        auth_state=(args.auth_state or None),
    )
    for c in classes:
        print(c)
    return 0


if __name__ == "__main__":
    sys.exit(main())
