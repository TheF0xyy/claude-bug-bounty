"""tools/session_bootstrap.py

Build memory/sessions.json from Burp MCP history entries or pasted raw
HTTP request text.

Typical workflow
----------------
Option A — Burp MCP history (two account history entries):

    from session_bootstrap import build_sessions_from_burp_entries, write_sessions_json

    sessions = build_sessions_from_burp_entries([
        ("account_a", burp_entry_for_account_a),
        ("account_b", burp_entry_for_account_b),
    ])
    write_sessions_json(sessions, Path("memory/sessions.json"))

Option B — pasted raw requests (Burp MCP unavailable):

    from session_bootstrap import build_sessions_from_raw_text, write_sessions_json

    sessions = build_sessions_from_raw_text(raw_text_a, raw_text_b)
    write_sessions_json(sessions, Path("memory/sessions.json"))

Design notes
------------
- Tracking cookies are excluded; auth/session cookies are preserved.
- Unknown cookies (neither clearly auth nor clearly tracking) are included
  to avoid breaking replay on sites with ambiguous cookie names.
- The Authorization header becomes auth_header in the sessions.json entry.
- Structural headers (Accept, X-Domain, etc.) are NOT included in sessions.json
  because they are per-request, not per-session.  They belong in the
  RequestTemplate.required_headers produced by request_template_extractor.py.
- No credentials are written to stdout.
- The output is directly compatible with tools/replay.py and tools/auth_check.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from request_template_extractor import (
    RawRequest,
    parse_raw_request,
    from_burp_entry,
    classify_cookies,
)


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------

def extract_session_material(raw: RawRequest, name: str = "account") -> dict:
    """Extract a sessions.json-compatible record from a RawRequest.

    Included in the output:
    - name
    - cookies   (auth + unknown; tracking excluded)
    - auth_header  (Authorization header value, if present)
    - notes     (summary of source and any exclusions)

    The output dict is safe to serialise with json.dumps().
    Credentials exist only in memory; they are not printed or logged.

    Args:
        raw:  A RawRequest produced by parse_raw_request() or from_burp_entry().
        name: Account name for the sessions.json entry (e.g. "account_a").

    Returns:
        Dict compatible with the sessions.json schema expected by replay.py.
    """
    # Authorization header (session-owned — becomes auth_header).
    auth_header: Optional[str] = None
    for hkey, hval in raw.headers.items():
        if hkey.lower() == "authorization":
            auth_header = hval
            break

    # Cookie classification: auth + unknown are included; tracking excluded.
    auth_cookies, tracking_cookies, unknown_cookies = classify_cookies(raw.cookies)
    session_cookies = {**auth_cookies, **unknown_cookies}

    # Build a human-readable note (no credential values in the note).
    notes_parts = [f"Bootstrapped from {raw.host}{raw.path} ({raw.source})"]
    if auth_header:
        scheme = auth_header.split()[0] if " " in auth_header else "unknown"
        notes_parts.append(f"auth scheme: {scheme}")
    if tracking_cookies:
        excluded = ", ".join(sorted(tracking_cookies.keys()))
        notes_parts.append(f"excluded tracking cookie(s): {excluded}")
    if unknown_cookies:
        included = ", ".join(sorted(unknown_cookies.keys()))
        notes_parts.append(f"unknown (included for fidelity): {included}")

    entry: dict = {"name": name}
    if session_cookies:
        entry["cookies"] = dict(session_cookies)
    if auth_header is not None:
        entry["auth_header"] = auth_header
    entry["notes"] = " | ".join(notes_parts)

    return entry


# ---------------------------------------------------------------------------
# Public builders
# ---------------------------------------------------------------------------

def build_sessions_from_history(
    entries: list[tuple[str, RawRequest]],
    include_no_auth: bool = True,
) -> list[dict]:
    """Build a sessions.json list from named (account_name, RawRequest) pairs.

    Args:
        entries:         Pairs of (account_name, RawRequest), e.g.
                         ``[("account_a", raw_a), ("account_b", raw_b)]``.
        include_no_auth: When True (default), append a bare ``no_auth`` entry
                         for auth-bypass testing.  Matches the schema expected
                         by tools/replay.py.

    Returns:
        A list of dicts ready for ``json.dumps()`` and compatible with
        ``tools/replay.py`` and ``tools/auth_check.py``.
    """
    sessions: list[dict] = []
    for account_name, raw in entries:
        sessions.append(extract_session_material(raw, name=account_name))

    if include_no_auth:
        sessions.append({
            "name": "no_auth",
            "notes": (
                "unauthenticated probe — auth-bypass check. "
                "No cookies or auth_header. Auto-appended by session_bootstrap."
            ),
        })

    return sessions


def build_sessions_from_raw_text(
    account_a_text: str,
    account_b_text: str,
    scheme: str = "https",
    include_no_auth: bool = True,
) -> list[dict]:
    """Build a sessions.json list from two pasted raw request texts.

    This is the fallback path when Burp MCP is unavailable.  Each raw text
    should be a complete HTTP request pasted from Burp Repeater or Proxy.

    Args:
        account_a_text: Full raw HTTP request for account A.
        account_b_text: Full raw HTTP request for account B.
        scheme:         Default scheme for requests that lack an explicit one
                        (e.g. HTTP/1.1 requests with no :scheme pseudo-header).
                        Defaults to "https".
        include_no_auth: Append a bare ``no_auth`` entry when True (default).

    Returns:
        A sessions.json-compatible list of dicts.
    """
    raw_a = parse_raw_request(account_a_text, scheme=scheme)
    raw_b = parse_raw_request(account_b_text, scheme=scheme)
    return build_sessions_from_history(
        [("account_a", raw_a), ("account_b", raw_b)],
        include_no_auth=include_no_auth,
    )


def build_sessions_from_burp_entries(
    entries: list[tuple[str, dict]],
    include_no_auth: bool = True,
) -> list[dict]:
    """Build a sessions.json list from named Burp MCP history entry dicts.

    Each entry is a dict as returned by the Burp MCP HTTP history API.
    The ``"request"`` key (raw text) takes priority; individual metadata
    fields are used as a fallback.

    Args:
        entries:         List of (account_name, burp_entry_dict) pairs.
        include_no_auth: Append a bare ``no_auth`` entry when True (default).

    Returns:
        A sessions.json-compatible list of dicts.
    """
    raw_entries: list[tuple[str, RawRequest]] = [
        (name, from_burp_entry(entry)) for name, entry in entries
    ]
    return build_sessions_from_history(raw_entries, include_no_auth=include_no_auth)


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def write_sessions_json(sessions: list[dict], path: Path) -> None:
    """Write a sessions list to a JSON file.

    Creates parent directories if they do not exist.  Overwrites any existing
    file at path.  The output is formatted with 2-space indentation for
    readability.

    Args:
        sessions: Output of any ``build_sessions_*`` function.
        path:     Destination path (e.g. ``Path("memory/sessions.json")``).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sessions, indent=2), encoding="utf-8")
