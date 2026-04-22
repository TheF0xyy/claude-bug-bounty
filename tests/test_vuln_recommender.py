"""Tests for tools/vuln_recommender.py — deterministic vuln-class recommendation."""

from vuln_recommender import (  # tools/ is on sys.path via tests/conftest.py
    API_SECURITY,
    AUTHZ,
    BAC,
    BUSINESS_LOGIC,
    CANONICAL_ORDER,
    IDOR,
    recommend_vuln_classes,
    score_vuln_classes,
)


# --- Phase D reference cases ----------------------------------------------

def test_example_api_users_orders_with_id_get_auth():
    """/api/v2/users/{id}/orders GET authenticated

    Categories: api_surface, identity, business.  Identifier: yes.
    idor = api(1)+identity(2)+business(2)+id(3)                     = 8
    bac  = identity(2)+business(1)+id(1)+auth(1)                    = 5
    business_logic = identity(1)+business(3)                        = 4
    api_security = api(3)                                           = 3
    authz = auth(1)                                                 = 1
    """
    assert recommend_vuln_classes(
        "/api/v2/users/{id}/orders", method="GET", auth_state="authenticated",
    ) == [IDOR, BAC, BUSINESS_LOGIC, API_SECURITY, AUTHZ]


def test_example_admin_internal_billing_post_auth():
    """/admin/internal/billing POST authenticated

    Categories: privileged, business.  No identifier.
    bac  = privileged(3)+business(1)+auth(1)                        = 5
    business_logic = business(3)+POST(1)                            = 4
    idor = privileged(1)+business(2)                                = 3
    authz = privileged(2)+auth(1)                                   = 3
    Tie between idor and authz at 3 -> idor first (canonical order).
    """
    assert recommend_vuln_classes(
        "/admin/internal/billing", method="POST", auth_state="authenticated",
    ) == [BAC, BUSINESS_LOGIC, IDOR, AUTHZ]


def test_example_auth_password_reset_post_anon():
    """/auth/password/reset POST anonymous

    Categories: auth.  No identifier.
    authz = auth(3)+anon(1)                                         = 4
    business_logic = auth(1)+POST(1)                                = 2
    """
    assert recommend_vuln_classes(
        "/auth/password/reset", method="POST", auth_state="anonymous",
    ) == [AUTHZ, BUSINESS_LOGIC]


def test_example_orgs_member_delete_auth():
    """/api/v1/orgs/42/members/99 DELETE authenticated

    Categories: api_surface, tenant.  Identifier: yes.
    idor = api(1)+tenant(2)+id(3)+DELETE(1)                         = 7
    bac  = tenant(3)+id(1)+DELETE(2)+auth(1)                        = 7
    api_security = api(3)                                           = 3
    authz = tenant(1)+auth(1)                                       = 2
    Tie between idor and bac at 7 -> idor first (canonical order).
    """
    assert recommend_vuln_classes(
        "/api/v1/orgs/42/members/99", method="DELETE", auth_state="authenticated",
    ) == [IDOR, BAC, API_SECURITY, AUTHZ]


def test_example_robots_txt_returns_empty():
    """No category, no identifier, GET, unknown auth -> no recommendations.

    The recommender must NOT fabricate a default. Empty output is how the
    caller learns the endpoint carries no hunting hypothesis. (Note: passing
    auth_state="anonymous" would correctly add authz +1 — see the separate
    anonymous-bump test below.)
    """
    assert recommend_vuln_classes(
        "/robots.txt", method="GET", auth_state=None,
    ) == []


def test_robots_txt_with_anonymous_still_empty():
    """Refined rule: anonymous alone must NOT surface authz on unrelated paths.

    Without an auth-category signal in the path, the anonymous auth-state
    bump is suppressed — so low-value endpoints like /robots.txt stay empty
    regardless of auth context.
    """
    assert recommend_vuln_classes(
        "/robots.txt", method="GET", auth_state="anonymous",
    ) == []


# --- rule-by-rule coverage ------------------------------------------------

def test_identifier_makes_idor_top_priority():
    """Any endpoint with an identifier should have IDOR at the top."""
    for endpoint in (
        "/api/users/123",
        "/profile/550e8400-e29b-41d4-a716-446655440000",
        "/resource/{id}",
        "/things?userId=7",
        "/objects/507f1f77bcf86cd799439011",   # MongoDB ObjectId
    ):
        result = recommend_vuln_classes(endpoint, method="GET", auth_state="anonymous")
        assert result, f"expected at least one class for {endpoint!r}"
        assert result[0] == IDOR, f"IDOR not top for {endpoint!r}: got {result}"


def test_admin_prefix_surfaces_bac_and_authz():
    """Admin routes should recommend both BAC and AuthZ, with BAC leading."""
    result = recommend_vuln_classes("/admin/panel", method="GET", auth_state="authenticated")
    assert BAC in result
    assert AUTHZ in result
    assert result.index(BAC) < result.index(AUTHZ)


def test_business_routes_pull_idor_and_business_logic():
    """/account and /orders should recommend both IDOR and business_logic."""
    for endpoint in ("/account/settings", "/orders/recent"):
        result = recommend_vuln_classes(endpoint, method="GET", auth_state="authenticated")
        assert IDOR in result, f"IDOR missing for {endpoint}: {result}"
        assert BUSINESS_LOGIC in result, f"business_logic missing for {endpoint}: {result}"


def test_post_and_put_add_business_logic():
    """State-changing methods should introduce business_logic on routes where
    it wasn't otherwise present."""
    base_get = recommend_vuln_classes("/api/widgets", method="GET")
    assert BUSINESS_LOGIC not in base_get

    for m in ("POST", "PUT", "PATCH"):
        rec = recommend_vuln_classes("/api/widgets", method=m)
        assert BUSINESS_LOGIC in rec, f"{m} should surface business_logic: {rec}"


def test_put_and_patch_also_add_idor():
    """PUT/PATCH skew toward IDOR because they're classic missing-ownership targets."""
    scores_get = score_vuln_classes("/api/widgets", method="GET")
    for m in ("PUT", "PATCH"):
        scores = score_vuln_classes("/api/widgets", method=m)
        assert scores[IDOR] == scores_get[IDOR] + 1, f"{m} should add +1 idor"


def test_delete_adds_bac_and_idor():
    base = score_vuln_classes("/api/widgets", method="GET")
    d = score_vuln_classes("/api/widgets", method="DELETE")
    assert d[BAC] == base[BAC] + 2
    assert d[IDOR] == base[IDOR] + 1


def test_authenticated_adds_bac_and_authz():
    """authenticated context should lean toward privilege-escalation classes."""
    base = score_vuln_classes("/api/widgets")   # auth_state=None
    auth = score_vuln_classes("/api/widgets", auth_state="authenticated")
    assert auth[BAC] == base[BAC] + 1
    assert auth[AUTHZ] == base[AUTHZ] + 1


def test_anonymous_adds_authz_only_when_auth_category_present():
    """anonymous nudges authz (can we bypass?) only on auth-signal endpoints.

    The bump strengthens authz for paths that already match the auth
    category (login/token/oauth/…). It never creates authz from zero.
    """
    base = score_vuln_classes("/auth/login")
    anon = score_vuln_classes("/auth/login", auth_state="anonymous")
    assert anon[AUTHZ] == base[AUTHZ] + 1
    assert anon[BAC] == base[BAC]


def test_anonymous_bump_suppressed_without_auth_category():
    """Refinement guard: anonymous adds NOTHING on non-auth paths.

    A path without the `auth` category (e.g. /api/widgets) must score
    identically whether auth_state is None or 'anonymous'. This is the
    rule that keeps /robots.txt and other low-value paths from fabricating
    an authz recommendation.
    """
    for endpoint in ("/api/widgets", "/robots.txt", "/products/list"):
        unknown = score_vuln_classes(endpoint)
        anon = score_vuln_classes(endpoint, auth_state="anonymous")
        assert unknown == anon, (
            f"anonymous must not change scores on non-auth path {endpoint!r}: "
            f"before={unknown} after={anon}"
        )


def test_anonymous_strengthens_authz_on_auth_paths():
    """Positive side: every auth-category path should gain +1 authz under anonymous."""
    for endpoint in (
        "/auth/login", "/oauth/token", "/password/reset",
        "/session/refresh", "/sso/callback", "/mfa/verify",
    ):
        base = score_vuln_classes(endpoint)
        anon = score_vuln_classes(endpoint, auth_state="anonymous")
        assert anon[AUTHZ] == base[AUTHZ] + 1, (
            f"expected +1 authz for {endpoint!r}, base={base[AUTHZ]} anon={anon[AUTHZ]}"
        )


def test_api_token_surfaces_api_security_class():
    result = recommend_vuln_classes("/api/v1/things", method="GET")
    assert API_SECURITY in result


def test_graphql_token_surfaces_api_security_class():
    result = recommend_vuln_classes("/graphql", method="POST")
    assert API_SECURITY in result


# --- invariants -----------------------------------------------------------

def test_zero_score_classes_are_omitted():
    """Only classes with a positive score are returned."""
    scores = score_vuln_classes("/api/users/1", method="GET", auth_state="anonymous")
    rec = recommend_vuln_classes("/api/users/1", method="GET", auth_state="anonymous")
    assert all(s > 0 for cls, s in scores.items() if cls in rec)
    assert all(scores[cls] == 0 for cls in scores if cls not in rec)


def test_recommendation_order_is_descending_by_score():
    scores = score_vuln_classes(
        "/api/v1/orgs/42/members/99", method="DELETE", auth_state="authenticated",
    )
    rec = recommend_vuln_classes(
        "/api/v1/orgs/42/members/99", method="DELETE", auth_state="authenticated",
    )
    rec_scores = [scores[c] for c in rec]
    assert rec_scores == sorted(rec_scores, reverse=True), rec_scores


def test_tie_breaker_follows_canonical_order():
    """When two classes tie on score, the one earlier in CANONICAL_ORDER wins."""
    # /admin/billing POST authenticated produces idor=3, authz=3 (see
    # example 2 above) — idor must come first.
    rec = recommend_vuln_classes(
        "/admin/internal/billing", method="POST", auth_state="authenticated",
    )
    assert CANONICAL_ORDER.index(IDOR) < CANONICAL_ORDER.index(AUTHZ)
    assert rec.index(IDOR) < rec.index(AUTHZ)


def test_canonical_order_contains_exactly_five_classes():
    assert set(CANONICAL_ORDER) == {IDOR, BAC, AUTHZ, BUSINESS_LOGIC, API_SECURITY}
    assert len(CANONICAL_ORDER) == 5


def test_deterministic_output():
    """Same inputs -> same list, always."""
    args = ("/api/v2/users/{id}/orders", "GET", "authenticated")
    first = recommend_vuln_classes(*args)
    for _ in range(10):
        assert recommend_vuln_classes(*args) == first


def test_unknown_method_and_auth_are_ignored():
    """Unrecognized values on method/auth must not raise or warp scores."""
    a = recommend_vuln_classes("/api/users/1", method="WEIRD", auth_state="guest")
    b = recommend_vuln_classes("/api/users/1", method="GET", auth_state=None)
    assert a == b


def test_full_url_works_like_bare_path():
    a = recommend_vuln_classes(
        "https://api.target.com/api/users/1?id=99",
        method="GET", auth_state="authenticated",
    )
    b = recommend_vuln_classes(
        "/api/users/1?id=99",
        method="GET", auth_state="authenticated",
    )
    assert a == b


def test_no_state_module_import():
    """Recommender must not touch memory state at import time."""
    import sys
    assert "memory.state_manager" not in sys.modules or True  # not forced
    # More importantly: the module itself imports nothing from memory/.
    import vuln_recommender as vr
    src_imports = vr.__file__
    with open(src_imports, encoding="utf-8") as f:
        src = f.read()
    assert "from memory" not in src
    assert "import memory" not in src
