#!/usr/bin/env python3
"""tools/check_sessions.py — session validity gate for the hunt pipeline.

Loads sessions from memory/sessions.json, validates them via AuthManager,
and exits with a precise code the hunt loop can act on.

Differences from auth_check.py
-------------------------------
- NETWORK_ERROR → exit 3  (auth_check.py treats NETWORK_ERROR as non-blocking)
- empty sessions.json list → exit 2
- --probe-url sets the probe URL on every session before validating
- --target is accepted for display / default-path convenience
- Output is a three-column table (name / state / probe URL)

Exit codes
----------
0   All auth-bearing sessions are VALID or UNCHECKED (UNCHECKED means no
    probe_url configured — not an error, just unverified).
1   At least one auth-bearing session is EXPIRED_OR_UNAUTHORIZED.
    → Re-login in Burp and re-run /burp-bootstrap {target}.
2   sessions.json is missing, unreadable, or contains an empty list.
    → Run /burp-bootstrap {target} first.
3   At least one auth-bearing session returned NETWORK_ERROR.
    → Check target reachability and Burp proxy connectivity.

no_auth is always skipped — it is never auth-bearing and never blocks.

Usage
-----
    python3.13 tools/check_sessions.py --target target.com
    python3.13 tools/check_sessions.py --sessions memory/sessions.json
    python3.13 tools/check_sessions.py --sessions memory/sessions.json \\
        --probe-url https://target.com/api/me
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

# Allow import from the tools/ directory when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from auth_manager import AuthManager, SessionRecord, ValidationResult, ValidationStatus, TransportFn

# The special "no auth" account name — never validated, never blocks.
_NO_AUTH_NAME: str = "no_auth"


# ── helpers ───────────────────────────────────────────────────────────────────


def _set_probe_url(mgr: AuthManager, probe_url: str) -> None:
    """Override probe_url on every registered session record.

    Retrieves deep copies via list_records(), sets the probe_url, then
    re-registers with replace=True so the stored record is updated.

    Args:
        mgr:       AuthManager whose records will be updated.
        probe_url: URL to probe; replaces any existing probe_url value.
    """
    for record in mgr.list_records():
        record.probe_url = probe_url
        mgr.register(record, replace=True)


def _state_label(state: str) -> str:
    """Convert a ValidationStatus string to a human-readable label."""
    return state.upper().replace("_OR_", "/")


# ── pure evaluation / formatting (testable without I/O) ──────────────────────


def format_table(
    names: list[str],
    results: dict[str, ValidationResult],
    effective_probe_url: Optional[str],
) -> str:
    """Format validation results as a readable status table.

    no_auth rows are always rendered as "PROBE_NOT_CONFIGURED (skipped)" and
    are never included in the results dict.

    Args:
        names:               Session names in insertion order.
        results:             {name: ValidationResult} for auth-bearing sessions.
        effective_probe_url: The --probe-url value (or None if not set), used
                             as the probe-URL column for all auth-bearing rows.

    Returns:
        A multi-line string suitable for printing to stdout.
    """
    lines: list[str] = ["[Session Check]"]

    probe_display = effective_probe_url or "(no probe URL configured)"

    for name in names:
        if name == _NO_AUTH_NAME:
            lines.append(f"  {name:<14}  PROBE_NOT_CONFIGURED      (skipped)")
            continue

        r = results.get(name)
        if r is None:
            lines.append(f"  {name:<14}  (no result)")
            continue

        label = _state_label(r.state)
        timing = f"({r.elapsed_ms:.0f}ms)" if r.elapsed_ms > 0 else ""
        lines.append(f"  {name:<14}  {label:<24}  {timing:<10}  {probe_display}")

        # Append extra detail for failures.
        if r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED:
            lines.append(f"  {'':14}  → re-login in Burp and re-run /burp-bootstrap")
        elif r.state == ValidationStatus.NETWORK_ERROR and r.error:
            lines.append(f"  {'':14}  → {r.error}")

    return "\n".join(lines)


def check_sessions(
    mgr: AuthManager,
    probe_url: Optional[str] = None,
    timeout: float = 10.0,
    transport: Optional[TransportFn] = None,
) -> tuple[int, str]:
    """Validate auth-bearing sessions and return (exit_code, table_text).

    no_auth is always skipped — validate() is never called for it.

    Priority of exit codes (highest first):
    3 — NETWORK_ERROR on any auth-bearing session
    1 — EXPIRED_OR_UNAUTHORIZED on any auth-bearing session
    0 — all auth-bearing sessions VALID or UNCHECKED

    UNCHECKED (no probe_url configured) is treated as non-blocking: the
    hunter may not have a probe URL yet, which is the common state right
    after /burp-bootstrap without an --probe-url argument.

    Args:
        mgr:       AuthManager loaded from sessions.json.
        probe_url: Optional URL to set on all sessions before validating.
                   If None, each session's existing probe_url is used.
        timeout:   HTTP probe timeout in seconds.
        transport: Optional injectable HTTP backend for testing.

    Returns:
        (exit_code, table_text) where table_text is the formatted output.
    """
    if probe_url:
        _set_probe_url(mgr, probe_url)

    names = list(mgr.names())
    results: dict[str, ValidationResult] = {}

    for name in names:
        if name == _NO_AUTH_NAME:
            continue  # always skip no_auth — never validate it
        results[name] = mgr.validate(name, transport=transport, timeout=timeout)

    table = format_table(names, results, probe_url)

    # Evaluate exit code — network errors take priority over expiry.
    has_network_error = False
    has_expired = False

    for name in names:
        if name == _NO_AUTH_NAME:
            continue
        r = results.get(name)
        if r is None:
            continue
        if r.state == ValidationStatus.NETWORK_ERROR:
            has_network_error = True
        elif r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED:
            has_expired = True

    if has_network_error:
        return 3, table
    if has_expired:
        return 1, table
    return 0, table


# ── CLI ───────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check_sessions.py",
        description="Validate stored sessions before the hunt loop.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--target",
        metavar="TARGET",
        help="Target hostname (informational; does not change the sessions path).",
    )
    p.add_argument(
        "--sessions", "-s",
        default="memory/sessions.json",
        metavar="PATH",
        help="Path to sessions.json (default: memory/sessions.json).",
    )
    p.add_argument(
        "--probe-url",
        metavar="URL",
        help="Probe URL to set on every session before validating. "
             "Overrides any probe_url already stored in each session record.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="HTTP probe timeout per session in seconds (default: 10.0).",
    )
    return p


def main(argv: Optional[list[str]] = None) -> None:
    """CLI entry point.

    Loads sessions.json, validates, prints a status table, and exits with
    the appropriate code (see module docstring).
    """
    args = _build_parser().parse_args(argv)

    sessions_path = Path(args.sessions)

    try:
        mgr = AuthManager.load_from_sessions_json(sessions_path)
    except FileNotFoundError:
        print(f"[Session Check] ERROR: sessions file not found: {sessions_path}")
        print("                Run /burp-bootstrap {target} first.")
        sys.exit(2)
    except ValueError as exc:
        print(f"[Session Check] ERROR: invalid sessions file — {exc}")
        sys.exit(2)

    if not mgr.names():
        print("[Session Check] ERROR: sessions.json is empty — no sessions found.")
        print("                Run /burp-bootstrap {target} first.")
        sys.exit(2)

    code, table = check_sessions(
        mgr,
        probe_url=args.probe_url,
        timeout=args.timeout,
    )
    print(table)
    sys.exit(code)


if __name__ == "__main__":
    main()
