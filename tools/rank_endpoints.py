#!/usr/bin/env python3
"""CLI wrapper that ranks endpoints by hunt-priority score.

Thin shell around `tools/scoring.py:score_endpoint`. Reads a TSV stream of
candidate endpoints from stdin and writes the same rows sorted by score
(descending, stable) on stdout — with the score prepended so the caller can
filter or threshold downstream.

Format:
    stdin:  <METHOD><TAB><ENDPOINT>          one row per line
    stdout: <SCORE><TAB><METHOD><TAB><ENDPOINT>   sorted DESC

Example (from autopilot):
    printf 'GET\\t/api/users/1\\nDELETE\\t/admin/users/1\\n' | \\
        python3 tools/rank_endpoints.py --auth-state authenticated

This CLI ONLY orders. It never consults dead-branch memory and never writes
state. Dead-branch skipping remains the caller's responsibility via
`tools/hunt_state.py check` right before each request.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make `from scoring import ...` work regardless of cwd — mirrors the
# tools/hunt_state.py pattern for sys.path bootstrap.
TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from scoring import score_endpoint  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rank-endpoints",
        description=(
            "Sort endpoints by hunt-priority score (reads TSV of "
            "`<method><TAB><endpoint>` from stdin)."
        ),
    )
    p.add_argument(
        "--auth-state", default="", choices=("", "anonymous", "authenticated"),
        help="Auth context applied to every endpoint (empty = unknown).",
    )
    p.add_argument(
        "--min-score", type=int, default=None,
        help=(
            "Drop rows with score < MIN_SCORE from the output. Omit to keep "
            "every row (the MVP default — scoring only ranks, never skips)."
        ),
    )
    return p


def _rank(
    lines: list[str],
    auth_state: str | None,
    min_score: int | None,
) -> list[tuple[int, str, str]]:
    rows: list[tuple[int, str, str]] = []
    for lineno, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n").rstrip("\r")
        if not line:
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            print(
                f"rank-endpoints: skipping malformed line {lineno}: {line!r}",
                file=sys.stderr,
            )
            continue
        method, endpoint = parts[0].strip(), parts[1].strip()
        if not method or not endpoint:
            print(
                f"rank-endpoints: skipping empty field on line {lineno}: {line!r}",
                file=sys.stderr,
            )
            continue
        s = score_endpoint(endpoint, method=method, auth_state=auth_state)
        rows.append((s, method, endpoint))

    if min_score is not None:
        rows = [r for r in rows if r[0] >= min_score]

    # Stable sort by score DESC preserves input order within ties, so the
    # upstream ranker's tier order is kept whenever scores match.
    rows.sort(key=lambda r: -r[0])
    return rows


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    auth = args.auth_state or None
    rows = _rank(sys.stdin.readlines(), auth, args.min_score)
    for score, method, endpoint in rows:
        print(f"{score}\t{method}\t{endpoint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
