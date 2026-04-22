#!/usr/bin/env python3
"""tools/auth_check.py — session validity gate for autopilot.

Loads sessions from memory/sessions.json, validates them with AuthManager,
and exits non-zero if any auth-bearing session (account_a, account_b or any
name that is not "no_auth") is EXPIRED_OR_UNAUTHORIZED.

"no_auth" is always allowed and never blocks.
UNCHECKED and NETWORK_ERROR are printed as warnings but do not block.

Exit codes
----------
0   all auth-bearing sessions are VALID or UNCHECKED; hunt may proceed
1   at least one session is EXPIRED_OR_UNAUTHORIZED → stop
2   usage error or unreadable sessions file

Usage
-----
    python3 tools/auth_check.py [OPTIONS]

    -s / --sessions PATH   path to sessions.json (default: memory/sessions.json)
    -t / --timeout SECS    HTTP probe timeout, default 10.0
    --skip-auth-check      skip validation entirely; print warning and exit 0

Example
-------
    if ! python3 tools/auth_check.py; then
        echo "Fix expired sessions before hunting." >&2
        exit 1
    fi
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

# Allow import from the tools/ directory when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from auth_manager import AuthManager, ValidationResult, ValidationStatus

# Sessions with this name are never treated as auth-bearing.
_NO_AUTH_NAME: str = "no_auth"

# ── public helper (importable by autopilot or other tools) ───────────────────


def load_sessions_into_auth_manager(path: Path) -> AuthManager:
    """Load a sessions.json file into a fresh AuthManager.

    Sessions loaded this way have no probe_url configured — calling
    validate_all() on the returned manager will classify all sessions as
    UNCHECKED unless probe_url values are added afterward.  UNCHECKED is
    not EXPIRED and does not block the hunt.

    Args:
        path: Path to a sessions.json file
              (e.g. ``memory/sessions.json`` or the example template).

    Returns:
        A populated AuthManager with one SessionRecord per file entry.

    Raises:
        FileNotFoundError: If path does not exist.
        ValueError:        If the file is not valid JSON or not a list.
    """
    return AuthManager.load_from_sessions_json(path)


# ── evaluation logic (pure — no I/O, fully testable) ─────────────────────────


def evaluate_results(
    names: list[str],
    results: dict[str, ValidationResult],
) -> tuple[int, str]:
    """Evaluate validation results and produce a summary.

    Only sessions whose name is NOT ``no_auth`` can block the hunt.
    EXPIRED_OR_UNAUTHORIZED is the only state that triggers an exit code 1.
    UNCHECKED / NETWORK_ERROR / UNEXPECTED_RESPONSE print as warnings but
    do not block — a missing probe_url is the common case.

    Args:
        names:   Session names in insertion order (from AuthManager.names()).
        results: Output of AuthManager.validate_all().

    Returns:
        (exit_code, summary_text) where exit_code is 0 (ok) or 1 (blocked).
    """
    lines: list[str] = ["[Auth Check]"]
    blocked = False

    for name in names:
        r = results.get(name)
        if r is None:
            lines.append(f"  {name}: (no result)")
            continue

        # Build the status string — display in uppercase for readability.
        label = r.state.upper().replace("_OR_", "/").replace("_", " ")
        if r.elapsed_ms > 0:
            status_str = f"{label} ({r.elapsed_ms:.0f}ms)"
        else:
            status_str = label

        if name == _NO_AUTH_NAME:
            # no_auth is informational only — never blocks.
            lines.append(f"  {name}: {status_str}")
            continue

        # Auth-bearing session.
        if r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED:
            lines.append(f"  {name}: EXPIRED")
            blocked = True
        elif r.state == ValidationStatus.NETWORK_ERROR:
            lines.append(f"  {name}: NETWORK_ERROR (probe failed — {r.error})")
        else:
            lines.append(f"  {name}: {status_str}")

    if blocked:
        lines.append("→ STOPPED: re-capture expired session(s) before continuing")
        return 1, "\n".join(lines)

    return 0, "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="auth_check.py",
        description="Validate sessions before the autopilot hunt loop.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--sessions", "-s",
        default="memory/sessions.json",
        metavar="PATH",
        help="Path to sessions.json (default: memory/sessions.json)",
    )
    p.add_argument(
        "--timeout", "-t",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="HTTP probe timeout per session (default: 10.0)",
    )
    p.add_argument(
        "--skip-auth-check",
        action="store_true",
        help="Skip validation entirely; print a warning and exit 0.",
    )
    return p


def main(argv: Optional[list[str]] = None) -> None:
    args = _build_parser().parse_args(argv)

    if args.skip_auth_check:
        print("[Auth Check] SKIPPED — --skip-auth-check flag is set.")
        print("             WARNING: session validity was NOT verified.")
        sys.exit(0)

    sessions_path = Path(args.sessions)
    try:
        mgr = load_sessions_into_auth_manager(sessions_path)
    except FileNotFoundError:
        print(f"[Auth Check] ERROR: sessions file not found: {sessions_path}")
        print("             Create memory/sessions.json from memory/sessions.example.json")
        sys.exit(2)
    except ValueError as exc:
        print(f"[Auth Check] ERROR: invalid sessions file — {exc}")
        sys.exit(2)

    results = mgr.validate_all(timeout=args.timeout)
    code, summary = evaluate_results(list(mgr.names()), results)
    print(summary)
    sys.exit(code)


if __name__ == "__main__":
    main()
