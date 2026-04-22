"""Endpoint scoring (MVP).

Assigns a small integer score to a (endpoint, method, auth_state) triple to
prioritize hunting for IDOR / Broken Access Control / Auth(Z) / Business
Logic. Higher score = more interesting. Score <= 0 = deprioritize.

Scoring is purely additive over a small fixed table:

    score = high_signal_pattern_score   (>= 0)
          + identifier_bonus            (0 or +2)
          + method_bonus                (0..+3)
          + auth_bonus                  (0 or +1)
          - low_value_penalty           (0..-25, prefix + extension stack)

Scoring only RANKS — it never skips. Dead-branch skipping lives in
memory/state_manager.py and is applied by the caller (autopilot) before any
request goes out. This module has no I/O and no dependency on memory state.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlsplit


# ---- weight tables --------------------------------------------------------

# High-signal tokens. Each category contributes its weight at most once per
# endpoint (no double-counting for repeats like /api/v1/api).
HIGH_SIGNAL_TOKENS: dict[str, int] = {
    # privileged surfaces
    "admin": 3, "internal": 3, "manage": 3, "management": 3, "root": 3,
    # API surface
    "api": 2, "graphql": 2, "rpc": 2,
    # identity routes
    "account": 2, "accounts": 2, "user": 2, "users": 2,
    "profile": 2, "me": 2, "settings": 2,
    # business logic
    "order": 2, "orders": 2, "payment": 2, "payments": 2, "billing": 2,
    "invoice": 2, "invoices": 2, "cart": 2, "checkout": 2,
    "transaction": 2, "transactions": 2,
    "subscription": 2, "subscriptions": 2,
    # auth / authn
    "auth": 2, "login": 2, "register": 2, "password": 2, "token": 2,
    "oauth": 2, "sso": 2, "session": 2, "logout": 2, "mfa": 2,
    # multi-tenant / authz boundaries
    "team": 2, "teams": 2, "org": 2, "orgs": 2,
    "organization": 2, "organizations": 2,
    "workspace": 2, "workspaces": 2, "tenant": 2, "tenants": 2,
    "project": 2, "projects": 2, "group": 2, "groups": 2,
    # file operations
    "upload": 1, "download": 1, "export": 1, "import": 1,
    "file": 1, "files": 1,
}

METHOD_WEIGHTS: dict[str, int] = {
    "GET": 0, "HEAD": 0, "OPTIONS": 0,
    "POST": 1,
    "PUT": 2, "PATCH": 2,
    "DELETE": 3,
}

AUTH_WEIGHTS: dict[str, int] = {
    "anonymous": 0,
    "authenticated": 1,
}

# Exact filenames (matched only against the LAST path segment).
LOW_VALUE_FILES: frozenset[str] = frozenset({
    "robots.txt", "sitemap.xml", "favicon.ico", "security.txt",
    "humans.txt", "ads.txt", "manifest.json",
})

# First-path-segment prefixes only. Restricting to the first segment avoids
# over-penalizing API routes that happen to contain a word like "static"
# deeper in the path (e.g. /api/v1/static-content is NOT a static asset).
LOW_VALUE_PREFIX_SEGMENTS: frozenset[str] = frozenset({
    ".well-known", "static", "assets", "public",
    "images", "img", "css", "js", "fonts", "media",
})

# File-extension match against the last segment.
LOW_VALUE_EXTENSIONS: frozenset[str] = frozenset({
    ".css", ".js", ".mjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf",
    ".pdf", ".mp4", ".webm",
})

IDENTIFIER_BONUS = 2


# ---- helpers --------------------------------------------------------------

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_NUMERIC_RE = re.compile(r"^\d+$")
# {id}, <id>, :id
_PLACEHOLDER_RE = re.compile(r"^(\{[^{}]+\}|<[^<>]+>|:[A-Za-z_]\w*)$")
# Long hex strings (e.g. MongoDB ObjectId = 24 hex chars, GitHub-style 40-char shas).
# 16+ hex chars catches the common opaque-id shapes without flagging short hex words.
_LONG_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
_SEG_TOKEN_SPLIT = re.compile(r"[-_]")


def _path_and_query(endpoint: str) -> tuple[str, str]:
    """Return (path, query) regardless of whether a full URL or a bare path is given."""
    parts = urlsplit(endpoint)
    return (parts.path or endpoint), parts.query


def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def _tokens(segment: str) -> list[str]:
    """Split a segment on '-' and '_' so 'payment-methods' -> ['payment','methods']."""
    return [t for t in _SEG_TOKEN_SPLIT.split(segment) if t]


def _is_identifier_segment(seg: str) -> bool:
    """A path segment that looks like a resource identifier."""
    return bool(
        _NUMERIC_RE.match(seg)
        or _UUID_RE.match(seg)
        or _LONG_HEX_RE.match(seg)
        or _PLACEHOLDER_RE.match(seg)
    )


def _is_id_query_key(key: str) -> bool:
    """Query keys that name an identifier (case-insensitive)."""
    k = key.lower()
    return k.endswith("id") or k in ("uuid", "guid")


def detect_high_signal_patterns(endpoint: str) -> int:
    """Sum the weights of distinct high-signal categories matched in the path.

    Each category is counted at most once. Tokens are case-insensitive and
    derived from path segments split on '/', '-', and '_'.
    """
    path, _ = _path_and_query(endpoint)
    matched: set[str] = set()
    score = 0
    for seg in _segments(path):
        for tok in _tokens(seg):
            tok_l = tok.lower()
            if tok_l in HIGH_SIGNAL_TOKENS and tok_l not in matched:
                matched.add(tok_l)
                score += HIGH_SIGNAL_TOKENS[tok_l]
    return score


def detect_low_value_patterns(endpoint: str) -> int:
    """Return the (negative or zero) penalty for known low-value endpoints.

    Only two axes are checked, both deliberately narrow:
      - first path segment is a known static/asset prefix  (-5)
      - last path segment is a known file (-10) or has a static extension (-10)

    Health/version-style endpoints are NOT penalized here because words like
    `status` or `version` are also legitimate resource names (`/api/v1/status`
    can be a real resource). Penalties stack so e.g. `/static/js/app.bundle.js`
    correctly lands at -15.
    """
    path, _ = _path_and_query(endpoint)
    segs = _segments(path)
    if not segs:
        return 0

    penalty = 0
    seg_lowers = [s.lower() for s in segs]
    last = seg_lowers[-1]

    if last in LOW_VALUE_FILES:
        penalty -= 10

    ext_dot = last.rfind(".")
    if ext_dot >= 0:
        ext = last[ext_dot:]
        if ext in LOW_VALUE_EXTENSIONS:
            penalty -= 10

    if seg_lowers[0] in LOW_VALUE_PREFIX_SEGMENTS:
        penalty -= 5

    return penalty


def _has_identifier(endpoint: str) -> bool:
    """True if the endpoint contains any identifier-shaped path segment or query key.

    Detects:
      - numeric segments         (/users/123)
      - UUID segments            (/users/550e8400-e29b-41d4-a716-446655440000)
      - long opaque hex IDs      (/users/507f1f77bcf86cd799439011)
      - templated placeholders   (/users/{id}, /users/:id, /users/<id>)
      - query keys that name an id (?id=, ?userId=, ?uuid=, ?guid=)
    """
    path, query = _path_and_query(endpoint)
    for seg in _segments(path):
        if _is_identifier_segment(seg):
            return True
    if query:
        for kv in query.split("&"):
            if not kv:
                continue
            key = kv.split("=", 1)[0]
            if _is_id_query_key(key):
                return True
    return False


def score_endpoint(
    endpoint: str,
    method: str = "GET",
    auth_state: Optional[str] = None,
) -> int:
    """Score an endpoint for IDOR / BAC / Authz / Business-Logic interest.

    Higher score = more interesting. Score <= 0 = deprioritize.

    Scoring only ranks; it never skips. Dead-branch skipping is the caller's
    responsibility (see memory/state_manager.is_dead_branch).

    Args:
        endpoint:    URL path (e.g. "/api/v2/users/123/orders") or full URL.
                     Query string is honored for identifier detection.
        method:      HTTP method. Unknown methods score 0 on the method axis.
        auth_state:  "anonymous" | "authenticated" | None. Unknown -> 0.
    """
    score = 0
    score += detect_high_signal_patterns(endpoint)
    if _has_identifier(endpoint):
        score += IDENTIFIER_BONUS
    if method:
        score += METHOD_WEIGHTS.get(method.upper(), 0)
    if auth_state:
        score += AUTH_WEIGHTS.get(auth_state.lower(), 0)
    score += detect_low_value_patterns(endpoint)
    return score
