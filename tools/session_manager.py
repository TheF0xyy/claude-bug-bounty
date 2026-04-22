"""Session context management for multi-account replay testing (MVP).

A SessionContext holds the stored-session credentials for a single account
used during IDOR / BAC / Auth/AuthZ replay. It is a pure data object — no
I/O, no HTTP, no state writes.

Typical use
-----------
    account_a = SessionContext(
        name="account_a",
        cookies={"session": "abc123", "csrf": "tok456"},
        auth_header="Bearer eyJhb...",
        notes="low-privilege user — test+a@example.com",
    )
    account_b = SessionContext(
        name="account_b",
        cookies={"session": "xyz789"},
        notes="separate low-privilege user — test+b@example.com",
    )
    headers = build_headers(account_a, base_headers={"Content-Type": "application/json"})

Credential-header ownership rule (critical for IDOR/BAC replay)
----------------------------------------------------------------
`Cookie` and `Authorization` are SESSION-OWNED headers.  They are NEVER
inherited from base_headers, regardless of whether the session carries its
own values.  This prevents stale tokens captured in a Burp template from
leaking into the wrong account's replay request.

    base_headers   → structural headers only (Content-Type, Accept, …)
                     Cookie / Authorization are STRIPPED before base is applied.
    session.headers → may supply any header including Authorization (custom schemes)
    auth_header     → ALWAYS wins for Authorization; beats base and session.headers
    cookies         → ALWAYS wins for Cookie; session cookie jar fully replaces base

Merge order (later wins on collision)
--------------------------------------
    1. base_headers     (credential headers stripped first)
    2. session.headers  (session-level extras/overrides)
    3. auth_header      (Authorization shorthand — always wins)
    4. cookies          (Cookie header — always wins; absent = no Cookie sent)

Deferred fields (not MVP)
--------------------------
    role / permission_level   privilege-escalation rule sets
    user_id / account_id      machine-readable identity cross-reference
    proxy_url / base_url      per-session proxy/redirect overrides (needs Burp MCP)
    token_expiry / refresh_fn auto-refresh (needs login automation)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Headers that are exclusively controlled by the session context.
# They are stripped from base_headers before any merge so that credentials
# captured in a Burp/proxy template never leak into a different account's
# replay request (including the no_auth context).
_SESSION_OWNED_HEADERS: frozenset[str] = frozenset({"authorization", "cookie"})


@dataclass
class SessionContext:
    """Stored-session context for a single account.

    Attributes:
        name:        Unique label used in diff output and audit logs.
                     Convention: "account_a", "account_b", "no_auth".
        cookies:     Cookie jar as {name: value}. All cookies are applied as
                     a single Cookie header. Include every cookie the app
                     requires (e.g. session token, CSRF cookie).
        headers:     Extra or override HTTP headers to send on every request
                     in this session. Applied after base_headers; session.headers
                     wins on collision. Use for custom auth schemes, X-User-ID,
                     X-Forwarded-For, etc.
        auth_header: Full Authorization header *value* (not name):
                     "Bearer eyJ...", "Basic dXNlcjpwYXNz", "Token abc123".
                     If set, always overrides any Authorization key already in
                     session.headers or base_headers.
        notes:       Free-text hunter note. Ignored by all logic; included in
                     DiffResult summary for readability.
    """

    name: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    auth_header: Optional[str] = None
    notes: str = ""


def build_headers(
    session: SessionContext,
    base_headers: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Build the final HTTP header dict for one replay request.

    The returned dict is a new object — neither base_headers nor session
    are mutated.

    Merge order (later key wins on collision):
        1. base_headers     (Cookie and Authorization STRIPPED before apply)
        2. session.headers  (session-level extras/overrides)
        3. auth_header      (Authorization shorthand — always wins)
        4. cookies          (Cookie — always wins; empty = no Cookie header sent)

    Credential-header ownership:
        Cookie and Authorization are unconditionally stripped from base_headers
        before the merge.  This is not optional — it prevents stale Burp-captured
        credentials from leaking into the wrong account's replay request.  If a
        session carries no cookies and no auth_header (e.g. NO_AUTH), the request
        is sent with no credential headers at all, which is the correct no_auth
        behaviour.

    Args:
        session:      The account context to apply.
        base_headers: Optional base headers from the RequestTemplate. Not mutated.

    Returns:
        A fresh dict ready to pass to an HTTP client.
    """
    result: dict[str, str] = {}

    if base_headers:
        for k, v in base_headers.items():
            if k.lower() not in _SESSION_OWNED_HEADERS:
                result[k] = v

    result.update(session.headers)

    if session.auth_header is not None:
        result["Authorization"] = session.auth_header

    if session.cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
        result["Cookie"] = cookie_str

    return result


# ---------------------------------------------------------------------------
# Convenience sentinel: unauthenticated context.
# Use when testing no_auth without constructing a new SessionContext each time.
# ---------------------------------------------------------------------------
NO_AUTH = SessionContext(
    name="no_auth",
    notes="unauthenticated — no cookies, no auth header",
)
