"""Vulnerability class recommender (MVP).

Given `(endpoint, method, auth_state)`, produce a priority-ordered list of
vulnerability classes worth testing on that endpoint. Deterministic rules
only — no ML, no state, no I/O.

Classes covered:
    idor            Insecure Direct Object Reference
    bac             Broken Access Control
    authz           Auth / AuthZ (authn bypass + authz escalation)
    business_logic  Business-logic / workflow flaws
    api_security    API-specific issues (mass assignment, GraphQL, etc.)

Scoring is additive over four axes:
    1. Path-token category matches (privileged/api/identity/business/auth/tenant)
    2. Identifier presence (numeric / UUID / ObjectId / {id} / ?id=)
    3. HTTP method weight
    4. Auth context weight

Classes with a positive score are returned, sorted DESC. Ties are broken
by the canonical order below (roughly empirical bug-bounty yield).

Tokenization helpers are intentionally duplicated from tools/scoring.py:
scoring returns a single int, this module needs to know WHICH category
matched, so a tiny re-implementation is clearer than leaking private
helpers across modules.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlsplit

# ---- public class identifiers --------------------------------------------

IDOR = "idor"
BAC = "bac"
AUTHZ = "authz"
BUSINESS_LOGIC = "business_logic"
API_SECURITY = "api_security"

# Canonical priority order used as the tie-breaker. Matches the class list
# in the user-facing requirements and roughly the empirical yield order.
CANONICAL_ORDER: tuple[str, ...] = (
    IDOR, BAC, AUTHZ, BUSINESS_LOGIC, API_SECURITY,
)
_PRIORITY_INDEX = {cls: i for i, cls in enumerate(CANONICAL_ORDER)}


# ---- tokenization tables -------------------------------------------------

# Path-token -> category. Tokens are compared case-insensitively against
# path segments split on '/', '-', and '_'.
TOKEN_TO_CATEGORY: dict[str, str] = {}
_CATEGORIES: dict[str, tuple[str, ...]] = {
    "privileged": ("admin", "internal", "manage", "management", "root"),
    "api_surface": ("api", "graphql", "rpc"),
    "identity": (
        "account", "accounts", "user", "users", "profile", "me", "settings",
    ),
    "business": (
        "order", "orders", "payment", "payments", "billing",
        "invoice", "invoices", "cart", "checkout",
        "transaction", "transactions", "subscription", "subscriptions",
    ),
    "auth": (
        "auth", "login", "register", "password", "token",
        "oauth", "sso", "session", "logout", "mfa",
    ),
    "tenant": (
        "team", "teams", "org", "orgs", "organization", "organizations",
        "workspace", "workspaces", "tenant", "tenants",
        "project", "projects", "group", "groups",
    ),
}
for _cat, _toks in _CATEGORIES.items():
    for _t in _toks:
        TOKEN_TO_CATEGORY[_t] = _cat


# ---- rule weight tables --------------------------------------------------

CATEGORY_WEIGHTS: dict[str, dict[str, int]] = {
    "privileged":  {IDOR: 1, BAC: 3, AUTHZ: 2},
    "api_surface": {IDOR: 1, API_SECURITY: 3},
    "identity":    {IDOR: 2, BAC: 2, BUSINESS_LOGIC: 1},
    "business":    {IDOR: 2, BAC: 1, BUSINESS_LOGIC: 3},
    "auth":        {AUTHZ: 3, BUSINESS_LOGIC: 1},
    "tenant":      {IDOR: 2, BAC: 3, AUTHZ: 1},
}

METHOD_WEIGHTS: dict[str, dict[str, int]] = {
    "POST":   {BUSINESS_LOGIC: 1},
    "PUT":    {IDOR: 1, BUSINESS_LOGIC: 1},
    "PATCH":  {IDOR: 1, BUSINESS_LOGIC: 1},
    "DELETE": {IDOR: 1, BAC: 2},
}

AUTH_WEIGHTS: dict[str, dict[str, int]] = {
    "authenticated": {BAC: 1, AUTHZ: 1},
    "anonymous":     {AUTHZ: 1},
}

IDENTIFIER_WEIGHTS: dict[str, int] = {IDOR: 3, BAC: 1}


# ---- tokenization helpers (duplicated from scoring.py on purpose) --------

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_NUMERIC_RE = re.compile(r"^\d+$")
_PLACEHOLDER_RE = re.compile(r"^(\{[^{}]+\}|<[^<>]+>|:[A-Za-z_]\w*)$")
_LONG_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
_SEG_TOKEN_SPLIT = re.compile(r"[-_]")


def _path_and_query(endpoint: str) -> tuple[str, str]:
    parts = urlsplit(endpoint)
    return (parts.path or endpoint), parts.query


def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def _tokens(segment: str) -> list[str]:
    return [t for t in _SEG_TOKEN_SPLIT.split(segment) if t]


def _is_identifier_segment(seg: str) -> bool:
    return bool(
        _NUMERIC_RE.match(seg)
        or _UUID_RE.match(seg)
        or _LONG_HEX_RE.match(seg)
        or _PLACEHOLDER_RE.match(seg)
    )


def _is_id_query_key(key: str) -> bool:
    k = key.lower()
    return k.endswith("id") or k in ("uuid", "guid")


def _detect_categories(endpoint: str) -> set[str]:
    """Return the set of high-level path categories that match this endpoint."""
    path, _ = _path_and_query(endpoint)
    matched: set[str] = set()
    for seg in _segments(path):
        for tok in _tokens(seg):
            cat = TOKEN_TO_CATEGORY.get(tok.lower())
            if cat is not None:
                matched.add(cat)
    return matched


def _has_identifier(endpoint: str) -> bool:
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


# ---- public API ----------------------------------------------------------

def score_vuln_classes(
    endpoint: str,
    method: str = "GET",
    auth_state: Optional[str] = None,
) -> dict[str, int]:
    """Compute the raw per-class score for an endpoint.

    Returns a dict keyed by vuln-class identifier (e.g. `idor`) whose value
    is the total weight accumulated across all rule axes. Classes with a
    score of 0 are still present in the dict (caller can filter); order is
    not meaningful — see `recommend_vuln_classes` for the prioritized list.
    """
    scores: dict[str, int] = {cls: 0 for cls in CANONICAL_ORDER}
    categories = _detect_categories(endpoint)

    for cat in categories:
        for cls, w in CATEGORY_WEIGHTS.get(cat, {}).items():
            scores[cls] += w

    if _has_identifier(endpoint):
        for cls, w in IDENTIFIER_WEIGHTS.items():
            scores[cls] += w

    if method:
        for cls, w in METHOD_WEIGHTS.get(method.upper(), {}).items():
            scores[cls] += w

    if auth_state:
        state = auth_state.lower()
        weights = AUTH_WEIGHTS.get(state, {})
        # Refinement: anonymous by itself must NOT surface authz on
        # endpoints with no auth signal (e.g. /robots.txt). It may only
        # STRENGTHEN authz when the path already matches the auth category
        # (auth, login, password, token, oauth, sso, session, logout, mfa).
        if state == "anonymous" and "auth" not in categories:
            weights = {}
        for cls, w in weights.items():
            scores[cls] += w

    return scores


def recommend_vuln_classes(
    endpoint: str,
    method: str = "GET",
    auth_state: Optional[str] = None,
) -> list[str]:
    """Return vuln classes worth testing, ordered by priority (highest first).

    Classes with score == 0 are omitted. Ties are broken by the canonical
    order `(idor, bac, authz, business_logic, api_security)`. Deterministic
    — same input always yields the same list.
    """
    scores = score_vuln_classes(endpoint, method=method, auth_state=auth_state)
    positive = [(cls, s) for cls, s in scores.items() if s > 0]
    positive.sort(key=lambda pair: (-pair[1], _PRIORITY_INDEX[pair[0]]))
    return [cls for cls, _ in positive]
