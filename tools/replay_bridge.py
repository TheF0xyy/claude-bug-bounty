#!/usr/bin/env python3
"""Replay suggestion bridge (MVP).

Decides whether a manual A/B replay is worth running for a given
(endpoint, method, auth_state, vuln_class) combination and emits the
exact CLI command to run if so.

This module ONLY SUGGESTS.  It never executes replay, never reads or writes
hunt_state.json, and never touches the scoring or recommender modules.

Public API
----------
    should_suggest_replay(endpoint, method, auth_state, vuln_class) -> bool
    format_suggestion(endpoint, method, target_host) -> str

CLI (used by autopilot)
-----------------------
    python3 tools/replay_bridge.py \\
        --endpoint /api/orders/99 \\
        --method   GET \\
        --auth-state authenticated \\
        --vuln-class idor \\
        --target api.target.com

    Stdout: formatted suggestion if triggered, empty if not.
    Exit:   0 always (empty output = no suggestion, not an error).

Decision logic summary
----------------------
    1. Class filter  — only idor / bac / authz / business_logic.
                       api_security excluded (tests API structure, not access).
    2. Path signal   — endpoint must contain an identifier (numeric/UUID/…)
                       OR a high-value category token (admin, orders, account…).
    3. Auth context  — anonymous probes only suggested when the path itself
                       contains an auth-category token (login, token, oauth…).
                       Prevents noise on /orders/123 where no second session
                       exists yet.
    4. Dedup         — tracked by the caller (autopilot) per (endpoint, method)
                       pair; this module is stateless.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

# ── path setup ───────────────────────────────────────────────────────────────
_TOOLS = Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))


# ── constants ─────────────────────────────────────────────────────────────────

# Vuln classes where A/B cross-account comparison adds direct value.
# api_security is intentionally absent — it concerns API structure, not
# per-account access control.
REPLAY_TRIGGER_CLASSES: frozenset[str] = frozenset({
    "idor", "bac", "authz", "business_logic",
})

# Path tokens whose presence makes cross-account replay high-value.
# Deliberately duplicated from vuln_recommender.py so this module stays
# self-contained and the recommender can change independently.
_HIGH_VALUE_TOKENS: frozenset[str] = frozenset({
    # privileged surfaces
    "admin", "internal", "manage", "management", "root",
    # identity
    "account", "accounts", "user", "users", "profile", "me", "settings",
    # business objects
    "order", "orders", "payment", "payments", "billing",
    "invoice", "invoices", "cart", "checkout",
    "subscription", "subscriptions", "transaction", "transactions",
})

# Auth-category tokens — only these justify replay suggestion in anonymous
# context, where a second session is unlikely to exist yet.
_AUTH_TOKENS: frozenset[str] = frozenset({
    "auth", "login", "register", "password", "token",
    "oauth", "sso", "session", "logout", "mfa",
})

# Identifier patterns — mirrors scoring.py and vuln_recommender.py exactly.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_NUMERIC_RE = re.compile(r"^\d+$")
_PLACEHOLDER_RE = re.compile(r"^(\{[^{}]+\}|<[^<>]+>|:[A-Za-z_]\w*)$")
_LONG_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
_SEG_TOKEN_SPLIT = re.compile(r"[-_]")


# ── private helpers ───────────────────────────────────────────────────────────

def _path_segments(endpoint: str) -> list[str]:
    path = urlsplit(endpoint).path or endpoint
    return [s for s in path.split("/") if s]


def _seg_tokens(segment: str) -> list[str]:
    return [t for t in _SEG_TOKEN_SPLIT.split(segment) if t]


def _is_identifier(seg: str) -> bool:
    return bool(
        _NUMERIC_RE.match(seg)
        or _UUID_RE.match(seg)
        or _LONG_HEX_RE.match(seg)
        or _PLACEHOLDER_RE.match(seg)
    )


def _has_identifier(endpoint: str) -> bool:
    """True when a path segment or query key looks like a resource ID."""
    parts = urlsplit(endpoint)
    for seg in _path_segments(endpoint):
        if _is_identifier(seg):
            return True
    for kv in (parts.query or "").split("&"):
        if not kv:
            continue
        key = kv.split("=", 1)[0].lower()
        if key.endswith("id") or key in ("uuid", "guid"):
            return True
    return False


def _has_high_value_token(endpoint: str) -> bool:
    """True when any path segment contains a high-value category token."""
    for seg in _path_segments(endpoint):
        for tok in _seg_tokens(seg):
            if tok.lower() in _HIGH_VALUE_TOKENS:
                return True
    return False


def _has_auth_token(endpoint: str) -> bool:
    """True when any path segment contains an auth-category token."""
    for seg in _path_segments(endpoint):
        for tok in _seg_tokens(seg):
            if tok.lower() in _AUTH_TOKENS:
                return True
    return False


# ── public API ────────────────────────────────────────────────────────────────

def should_suggest_replay(
    endpoint: str,
    method: str,
    auth_state: Optional[str],
    vuln_class: str,
) -> bool:
    """Return True when a manual A/B replay would add meaningful signal.

    Args:
        endpoint:   Full path (and optional query), e.g. /api/orders/99.
        method:     HTTP verb (case-insensitive).
        auth_state: "authenticated", "anonymous", or None (unknown).
        vuln_class: The class currently being tested (e.g. "idor").

    Returns:
        True  → emit a replay suggestion before probing.
        False → no suggestion; continue testing normally.

    Decision tree:

        1. Class filter — only idor/bac/authz/business_logic.
           api_security is structural, not per-account → excluded.

        2a. Anonymous context — the hunter likely has no second session yet.
            Only worth suggesting when the endpoint contains an auth-category
            token (login, token, oauth…) making an auth-bypass probe the goal.
            All other path types are deferred until auth_state flips.

        2b. Authenticated / unknown context — suggest when the endpoint
            contains an identifier (numeric, UUID, …) OR a high-value
            category token (admin, orders, account…).  Paths with neither
            signal (e.g. /status, /health) are skipped.

    Deterministic — same inputs always produce the same output.
    Never reads or writes any state file.
    """
    # 1. Class filter.
    if vuln_class not in REPLAY_TRIGGER_CLASSES:
        return False

    # 2a. Anonymous context: auth-token in path is the only meaningful
    #     signal — it makes an auth-bypass probe the explicit goal.
    #     Everything else (even /orders/123) is deferred because the hunter
    #     does not have two sessions yet.
    if auth_state == "anonymous":
        return _has_auth_token(endpoint)

    # 2b. Authenticated / unknown: require identifier OR high-value token.
    return _has_identifier(endpoint) or _has_high_value_token(endpoint)


def format_suggestion(
    endpoint: str,
    method: str,
    target_host: str,
) -> str:
    """Return the formatted replay suggestion line for autopilot output.

    Args:
        endpoint:    Path (and optional query), e.g. /api/orders/99.
        method:      HTTP verb.
        target_host: Hostname (or full base URL).  Scheme added if absent.

    Returns:
        Multi-line string ready to print directly.
    """
    host = target_host.rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    url = f"{host}{endpoint}"
    return (
        f"→ Suggest A/B replay:\n"
        f"  python3 tools/replay.py --url {url} --method {method}"
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="replay_bridge",
        description=(
            "Print a replay suggestion if the given probe warrants A/B "
            "cross-account testing. Prints nothing if no suggestion. "
            "Exit 0 always."
        ),
    )
    p.add_argument("--endpoint", required=True)
    p.add_argument("--method", default="GET")
    p.add_argument(
        "--auth-state", default="",
        choices=("", "anonymous", "authenticated"),
        help="Empty string = unknown.",
    )
    p.add_argument("--vuln-class", required=True)
    p.add_argument(
        "--target", default="",
        help="Target hostname or base URL (e.g. api.target.com). "
             "If omitted the URL is printed with a <BASE_URL> placeholder.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    auth = args.auth_state or None

    if not should_suggest_replay(
        args.endpoint,
        args.method,
        auth,
        args.vuln_class,
    ):
        return 0

    if args.target:
        print(format_suggestion(args.endpoint, args.method, args.target))
    else:
        method = args.method.upper()
        print(
            f"→ Suggest A/B replay:\n"
            f"  python3 tools/replay.py"
            f" --url <BASE_URL>{args.endpoint} --method {method}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
