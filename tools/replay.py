#!/usr/bin/env python3
"""Standalone multi-account replay CLI.

Builds a RequestTemplate from CLI arguments, loads stored session contexts
from a JSON file, replays the request under account_a / account_b / no_auth,
and prints per-session status lines followed by pairwise diff summaries.

This tool produces SIGNALS, not findings.  Validate every interesting diff
through the 7-Question Gate before writing a report.

Usage
-----
    python3 tools/replay.py \\
        --url https://api.target.com/api/users/42 \\
        --method GET \\
        --header "Accept: application/json" \\
        --header "X-CSRF-Token: abc123" \\
        --sessions memory/sessions.json

Session file format (memory/sessions.json — gitignored, never commit)
----------------------------------------------------------------------
    [
      {
        "name": "account_a",
        "cookies": {"session": "TOKEN-A"},
        "auth_header": "Bearer JWT-A",
        "notes": "low-privilege user A (victim)"
      },
      {
        "name": "account_b",
        "cookies": {"session": "TOKEN-B"},
        "auth_header": "Bearer JWT-B",
        "notes": "low-privilege user B (attacker / cross-account probe)"
      },
      {
        "name": "no_auth",
        "notes": "unauthenticated probe — auth-bypass check"
      }
    ]

Required sessions: "account_a" and "account_b" (looked up by name).
Optional session:  "no_auth" (falls back to the NO_AUTH sentinel if absent).

Supported session fields: name, cookies, headers, auth_header, notes.
All fields except name are optional and default to empty / None.

Notes
-----
- Cookie and Authorization from --header are ignored; they would be
  silently stripped by build_headers in favour of session credentials.
  Set them in the session file instead.
- --body is sent as UTF-8 text; for binary payloads pipe via stdin (not
  yet implemented — deferred to a future pass).
- Exit code: 0 on successful replay (even if signals found);
             1 on input / configuration error;
             2 on total replay failure (all sessions errored).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

# ── path setup ──────────────────────────────────────────────────────────────
_TOOLS = Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from session_manager import NO_AUTH, SessionContext, build_headers  # noqa: E402
from replay_diff import (  # noqa: E402
    RequestTemplate,
    ReplayResult,
    compare_all,
    replay_all,
)


# ── session loading ──────────────────────────────────────────────────────────

def _load_sessions(path: Path) -> dict[str, SessionContext]:
    """Parse a sessions JSON file into {name: SessionContext}."""
    if not path.exists():
        _die(
            f"Session file not found: {path}\n"
            "\nCreate it with at least account_a and account_b entries.\n"
            "See the module docstring for the expected format.\n"
            f"  touch {path}   # then add your session tokens"
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _die(f"Invalid JSON in {path}: {exc}")

    if not isinstance(raw, list):
        _die(f"{path} must contain a JSON array of session objects.")

    sessions: dict[str, SessionContext] = {}
    for entry in raw:
        if not isinstance(entry, dict) or "name" not in entry:
            _die(f"Every session entry must have a 'name' field. Got: {entry!r}")
        name = entry["name"]
        sessions[name] = SessionContext(
            name=name,
            cookies=entry.get("cookies") or {},
            headers=entry.get("headers") or {},
            auth_header=entry.get("auth_header") or None,
            notes=entry.get("notes") or "",
        )
    return sessions


def _resolve_sessions(
    sessions: dict[str, SessionContext],
) -> tuple[SessionContext, SessionContext, Optional[SessionContext]]:
    """Return (account_a, account_b, no_auth_or_None) from the loaded dict."""
    missing = [n for n in ("account_a", "account_b") if n not in sessions]
    if missing:
        found = list(sessions.keys()) or ["(none)"]
        _die(
            f"Required sessions missing from file: {missing}\n"
            f"Sessions found: {found}\n"
            "Rename your entries or add the missing ones."
        )
    no_auth = sessions.get("no_auth")    # None → NO_AUTH sentinel used by replay_all
    return sessions["account_a"], sessions["account_b"], no_auth


# ── output ───────────────────────────────────────────────────────────────────

_COL = 14   # session name column width


def _status_line(r: ReplayResult, method: str, url: str) -> str:
    name = f"[{r.session_name}]".ljust(_COL)
    if r.error:
        return f"{name}  {method}  {url}  →  ERROR: {r.error}"
    return f"{name}  {method}  {url}  →  {r.status_code}  ({r.elapsed_ms:.0f}ms)"


def _print_results(
    results: dict[str, ReplayResult],
    method: str,
    url: str,
) -> None:
    for r in results.values():
        print(_status_line(r, method, url))


def _print_diffs(results: dict[str, ReplayResult]) -> None:
    diffs = compare_all(results)
    if not diffs:
        return
    print()
    print("─" * 68)
    for d in diffs:
        print(d.summary())


# ── argument parsing ──────────────────────────────────────────────────────────

def _parse_header(value: str) -> tuple[str, str]:
    """Parse 'Name: value' into (name, value). Exits on malformed input."""
    if ":" not in value:
        _die(f"--header must be in 'Name: value' format, got: {value!r}")
    name, _, val = value.partition(":")
    return name.strip(), val.strip()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="replay",
        description=(
            "Multi-account request replay. Produces SIGNALS, not findings. "
            "Validate through 7-Question Gate before reporting."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 tools/replay.py \\\n"
            "      --url https://api.target.com/api/users/42 --method GET\n\n"
            "  python3 tools/replay.py \\\n"
            "      --url https://api.target.com/api/orders/99 --method POST \\\n"
            "      --header 'Content-Type: application/json' \\\n"
            "      --body '{\"status\": \"cancelled\"}'\n"
        ),
    )
    p.add_argument("--url", required=True, help="Full URL to replay.")
    p.add_argument(
        "--method", default="GET",
        help="HTTP verb (default: GET).",
    )
    p.add_argument(
        "--header", metavar="NAME:VALUE", action="append", default=[],
        dest="headers",
        help=(
            "Base request header in 'Name: value' format. Repeatable. "
            "Do NOT put Cookie or Authorization here — set them in the "
            "session file; they would be stripped by the session engine."
        ),
    )
    p.add_argument(
        "--body", default=None,
        help="Request body as a string (UTF-8). For GET leave unset.",
    )
    p.add_argument(
        "--sessions",
        default=str(_TOOLS.parent / "memory" / "sessions.json"),
        metavar="PATH",
        help="Path to sessions JSON file (default: memory/sessions.json).",
    )
    p.add_argument(
        "--timeout", type=float, default=10.0,
        help="Per-request timeout in seconds (default: 10).",
    )
    return p


# ── helpers ───────────────────────────────────────────────────────────────────

def _die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


# ── main ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    # Build base headers dict from --header flags
    base_headers: dict[str, str] = {}
    for raw in args.headers:
        k, v = _parse_header(raw)
        if k.lower() in ("cookie", "authorization"):
            print(
                f"WARNING: --header '{k}' ignored. "
                "Credential headers must be set in the session file.",
                file=sys.stderr,
            )
            continue
        base_headers[k] = v

    template = RequestTemplate(
        method=args.method,
        url=args.url,
        headers=base_headers,
        body=args.body,
    )

    sessions = _load_sessions(Path(args.sessions))
    account_a, account_b, no_auth_session = _resolve_sessions(sessions)

    # Use the stored no_auth session if present; NO_AUTH sentinel otherwise
    no_auth: Optional[SessionContext] = no_auth_session if no_auth_session is not None else NO_AUTH

    results = replay_all(
        template,
        account_a,
        account_b,
        no_auth=no_auth,
        timeout=args.timeout,
    )

    _print_results(results, template.method, template.url)
    _print_diffs(results)

    # Exit 2 only if every single session errored (total replay failure)
    all_errored = all(r.error is not None for r in results.values())
    return 2 if all_errored else 0


if __name__ == "__main__":
    sys.exit(main())
