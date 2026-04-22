"""Unit tests for tools/session_manager.py.

All tests are pure — no I/O, no HTTP, no state.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from session_manager import NO_AUTH, SessionContext, build_headers


# ---------------------------------------------------------------------------
# SessionContext construction
# ---------------------------------------------------------------------------


def test_minimal_construction():
    s = SessionContext(name="account_a")
    assert s.name == "account_a"
    assert s.cookies == {}
    assert s.headers == {}
    assert s.auth_header is None
    assert s.notes == ""


def test_full_construction():
    s = SessionContext(
        name="account_b",
        cookies={"session": "abc"},
        headers={"X-Custom": "val"},
        auth_header="Bearer tok",
        notes="low-priv user",
    )
    assert s.name == "account_b"
    assert s.cookies == {"session": "abc"}
    assert s.headers == {"X-Custom": "val"}
    assert s.auth_header == "Bearer tok"
    assert s.notes == "low-priv user"


def test_no_auth_sentinel():
    assert NO_AUTH.name == "no_auth"
    assert NO_AUTH.cookies == {}
    assert NO_AUTH.headers == {}
    assert NO_AUTH.auth_header is None


# ---------------------------------------------------------------------------
# build_headers — merge order
# ---------------------------------------------------------------------------


def test_base_headers_applied():
    s = SessionContext(name="a")
    h = build_headers(s, base_headers={"Accept": "application/json"})
    assert h["Accept"] == "application/json"


def test_session_headers_override_base():
    s = SessionContext(name="a", headers={"X-Foo": "session"})
    h = build_headers(s, base_headers={"X-Foo": "base"})
    assert h["X-Foo"] == "session"


def test_auth_header_overrides_session_headers():
    s = SessionContext(
        name="a",
        headers={"Authorization": "Basic old"},
        auth_header="Bearer new",
    )
    h = build_headers(s)
    assert h["Authorization"] == "Bearer new"


def test_auth_header_overrides_base_headers():
    s = SessionContext(name="a", auth_header="Bearer override")
    h = build_headers(s, base_headers={"Authorization": "Basic base"})
    assert h["Authorization"] == "Bearer override"


def test_cookies_rendered_as_single_cookie_header():
    s = SessionContext(name="a", cookies={"session": "abc123", "csrf": "tok456"})
    h = build_headers(s)
    assert "Cookie" in h
    # Both cookies must be present; order is dict-insertion order (Python 3.7+)
    assert "session=abc123" in h["Cookie"]
    assert "csrf=tok456" in h["Cookie"]


def test_cookies_separated_by_semicolon():
    s = SessionContext(name="a", cookies={"a": "1", "b": "2"})
    h = build_headers(s)
    assert h["Cookie"] == "a=1; b=2"


def test_single_cookie():
    s = SessionContext(name="a", cookies={"session": "xyz"})
    h = build_headers(s)
    assert h["Cookie"] == "session=xyz"


def test_empty_cookies_no_cookie_header():
    s = SessionContext(name="a", cookies={})
    h = build_headers(s)
    assert "Cookie" not in h


def test_no_auth_header_when_not_set():
    s = SessionContext(name="a")
    h = build_headers(s)
    assert "Authorization" not in h


def test_no_base_headers_is_fine():
    s = SessionContext(name="a", auth_header="Bearer tok")
    h = build_headers(s)
    assert h["Authorization"] == "Bearer tok"


def test_empty_base_headers_is_fine():
    s = SessionContext(name="a", auth_header="Bearer tok")
    h = build_headers(s, base_headers={})
    assert h["Authorization"] == "Bearer tok"


def test_base_headers_not_mutated():
    base = {"Content-Type": "application/json"}
    s = SessionContext(name="a", headers={"X-Extra": "yes"})
    build_headers(s, base_headers=base)
    assert base == {"Content-Type": "application/json"}


def test_session_headers_not_mutated():
    s = SessionContext(name="a", headers={"X-A": "1"})
    build_headers(s, base_headers={"X-B": "2"})
    assert s.headers == {"X-A": "1"}


# ---------------------------------------------------------------------------
# Full merge scenario — all fields together
# ---------------------------------------------------------------------------


def test_full_merge_all_fields():
    """base < session.headers < auth_header, with cookies appended."""
    s = SessionContext(
        name="account_a",
        cookies={"session": "sess1", "csrf": "csrf1"},
        headers={"X-Custom": "val", "Authorization": "Basic stale"},
        auth_header="Bearer fresh",
    )
    h = build_headers(
        s,
        base_headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Basic base",
        },
    )
    # Content-Type from base, not overridden
    assert h["Content-Type"] == "application/json"
    # Accept from base, not overridden
    assert h["Accept"] == "application/json"
    # X-Custom from session.headers
    assert h["X-Custom"] == "val"
    # auth_header wins over base and session.headers
    assert h["Authorization"] == "Bearer fresh"
    # cookies present
    assert "session=sess1" in h["Cookie"]
    assert "csrf=csrf1" in h["Cookie"]


def test_no_auth_sentinel_builds_empty_headers():
    h = build_headers(NO_AUTH, base_headers={"Content-Type": "text/plain"})
    assert h == {"Content-Type": "text/plain"}
    assert "Cookie" not in h
    assert "Authorization" not in h


# ---------------------------------------------------------------------------
# HARDENING — Cookie ownership
#
# session.cookies is the sole authority for the Cookie header.
# Cookie from base_headers is ALWAYS stripped before merge so that a stale
# Burp-captured session token never leaks into the wrong account's request.
# ---------------------------------------------------------------------------


def test_base_cookie_stripped_when_session_has_cookies():
    """Session cookie jar fully replaces a Cookie header from the base template."""
    s = SessionContext(name="account_b", cookies={"session": "b-token"})
    h = build_headers(
        s,
        base_headers={
            "Content-Type": "application/json",
            "Cookie": "session=a-token-STALE",   # captured from account_a's Burp session
        },
    )
    # Only account_b's cookie present; stale cookie gone
    assert h["Cookie"] == "session=b-token"
    assert "a-token-STALE" not in h["Cookie"]


def test_base_cookie_stripped_when_session_has_no_cookies():
    """no_auth / empty-cookie session sends NO Cookie header at all.

    Gap this test guards: before the fix, the stale Cookie from base_headers
    would pass through unchanged when session.cookies was empty, effectively
    sending account_a's credentials on the no_auth replay leg.
    """
    s = SessionContext(name="no_auth")   # no cookies
    h = build_headers(
        s,
        base_headers={
            "Content-Type": "application/json",
            "Cookie": "session=victim-token-STALE",
        },
    )
    assert "Cookie" not in h, (
        "Stale Cookie from base leaked into a session with no cookies. "
        "This would silently authenticate the no_auth replay leg."
    )


def test_no_auth_sentinel_with_stale_base_cookie_sends_nothing():
    """NO_AUTH sentinel must strip both stale Cookie and Authorization."""
    h = build_headers(
        NO_AUTH,
        base_headers={
            "Accept": "application/json",
            "Cookie": "session=victim-STALE",
            "Authorization": "Bearer victim-STALE",
        },
    )
    assert "Cookie" not in h
    assert "Authorization" not in h
    assert h.get("Accept") == "application/json"   # structural headers survive


def test_multiple_session_cookies_replace_base_cookie_entirely():
    """All cookies in session.cookies are rendered; base Cookie is dropped."""
    s = SessionContext(name="a", cookies={"session": "s1", "csrf": "c1"})
    h = build_headers(
        s,
        base_headers={"Cookie": "session=OLD; csrf=OLD"},
    )
    assert "OLD" not in h["Cookie"]
    assert "session=s1" in h["Cookie"]
    assert "csrf=c1" in h["Cookie"]


# ---------------------------------------------------------------------------
# HARDENING — Authorization ownership
#
# session.auth_header is the sole authority for the Authorization header.
# Authorization from base_headers is ALWAYS stripped before merge.
# This prevents Burp-captured tokens from leaking into a different account's
# request, and ensures no_auth requests carry no auth credential.
# ---------------------------------------------------------------------------


def test_stale_base_authorization_replaced_by_session_auth_header():
    """The canonical hardening example: base template has a stale token.

    A Burp-captured request arrives with the original user's JWT.  When
    replaying under account_b, the stale token must be fully replaced.
    """
    s = SessionContext(
        name="account_b",
        auth_header="Bearer eyJ-ACCOUNT-B-TOKEN",
    )
    h = build_headers(
        s,
        base_headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer eyJ-ACCOUNT-A-STALE",   # captured from account_a
        },
    )
    # account_b's token is present
    assert h["Authorization"] == "Bearer eyJ-ACCOUNT-B-TOKEN"
    # account_a's stale token is gone
    assert "ACCOUNT-A-STALE" not in h["Authorization"]
    # structural headers survive
    assert h["Content-Type"] == "application/json"


def test_base_authorization_stripped_when_session_has_no_auth_header():
    """Gap: before fix, no-auth session would inherit base Authorization.

    A session with neither auth_header nor any Authorization in session.headers
    should produce a request with NO Authorization header.  It must not inherit
    the base template's token.
    """
    s = SessionContext(name="no_auth")   # no auth_header, no session.headers
    h = build_headers(
        s,
        base_headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer victim-STALE",
        },
    )
    assert "Authorization" not in h, (
        "Stale Authorization from base leaked into a session with no auth_header. "
        "This would silently authenticate the no_auth replay leg."
    )


def test_session_headers_authorization_not_shadowed_by_base():
    """session.headers['Authorization'] survives; base Authorization is stripped."""
    s = SessionContext(
        name="a",
        headers={"Authorization": "ApiKey custom-scheme-token"},
    )
    h = build_headers(
        s,
        base_headers={"Authorization": "Bearer stale-base"},
    )
    assert h["Authorization"] == "ApiKey custom-scheme-token"
    assert "stale-base" not in h["Authorization"]


def test_auth_header_wins_over_session_headers_and_base():
    """Three-way race: auth_header beats session.headers beats base.

    This is the full precedence chain in one assertion.
    """
    s = SessionContext(
        name="a",
        headers={"Authorization": "Basic session-level"},
        auth_header="Bearer auth_header-wins",
    )
    h = build_headers(
        s,
        base_headers={"Authorization": "Bearer base-stale"},
    )
    assert h["Authorization"] == "Bearer auth_header-wins"


# ---------------------------------------------------------------------------
# Auth header value shapes
# ---------------------------------------------------------------------------


def test_bearer_auth_header():
    s = SessionContext(name="a", auth_header="Bearer eyJhbGciOiJSUzI1")
    h = build_headers(s)
    assert h["Authorization"] == "Bearer eyJhbGciOiJSUzI1"


def test_basic_auth_header():
    s = SessionContext(name="a", auth_header="Basic dXNlcjpwYXNz")
    h = build_headers(s)
    assert h["Authorization"] == "Basic dXNlcjpwYXNz"


def test_custom_auth_header():
    s = SessionContext(name="a", auth_header="Token abc123xyz")
    h = build_headers(s)
    assert h["Authorization"] == "Token abc123xyz"
