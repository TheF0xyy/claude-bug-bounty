"""Tests for tools/scoring.py — deterministic endpoint scoring.

The `test_example_*` tests are the canonical Phase-E reference cases. If you
change a weight, expect these to flip and update them deliberately.
"""

import scoring  # tools/ is on sys.path via tests/conftest.py
from scoring import (
    IDENTIFIER_BONUS,
    detect_high_signal_patterns,
    detect_low_value_patterns,
    score_endpoint,
)


# --- Phase E reference cases ----------------------------------------------

def test_example_api_users_orders_with_placeholder():
    """/api/v2/users/{id}/orders GET authenticated
    api(2)+users(2)+orders(2)=6 + {id} placeholder(2) + GET(0) + auth(1) = 9
    """
    assert score_endpoint(
        "/api/v2/users/{id}/orders",
        method="GET",
        auth_state="authenticated",
    ) == 9


def test_example_admin_internal_billing():
    """/admin/internal/billing POST authenticated
    admin(3)+internal(3)+billing(2)=8 + no id + POST(1) + auth(1) = 10
    """
    assert score_endpoint(
        "/admin/internal/billing",
        method="POST",
        auth_state="authenticated",
    ) == 10


def test_example_robots_txt():
    """/robots.txt GET anonymous
    high(0) + id(0) + GET(0) + anon(0) + low(-10 exact filename) = -10
    """
    assert score_endpoint(
        "/robots.txt", method="GET", auth_state="anonymous",
    ) == -10


def test_example_static_js_bundle():
    """/static/js/app.bundle.js GET anonymous
    high(0) + id(0) + GET(0) + anon(0) + low(-5 prefix + -10 .js ext) = -15
    """
    assert score_endpoint(
        "/static/js/app.bundle.js",
        method="GET",
        auth_state="anonymous",
    ) == -15


def test_example_api_account_payment_methods_delete():
    """/api/v1/account/123/payment-methods DELETE authenticated
    api(2)+account(2)+payment(2)=6 + numeric id(2) + DELETE(3) + auth(1) = 12
    """
    assert score_endpoint(
        "/api/v1/account/123/payment-methods",
        method="DELETE",
        auth_state="authenticated",
    ) == 12


# --- high-signal helper ---------------------------------------------------

def test_high_signal_helper_basic():
    assert detect_high_signal_patterns("/api/users/1") == 4  # api + users
    assert detect_high_signal_patterns("/foo/bar") == 0


def test_high_signal_each_category_counted_once():
    """Repeats of the same category must not stack."""
    assert detect_high_signal_patterns("/api/api/api") == 2


def test_high_signal_tokenizes_hyphen_and_underscore():
    """Segments split on '-' and '_' so compound words still match."""
    assert detect_high_signal_patterns("/api/payment-methods") == 4  # api + payment
    assert detect_high_signal_patterns("/user_profile") == 4        # user + profile


# --- identifier detection -------------------------------------------------

def test_identifier_numeric_segment():
    base = score_endpoint("/foo/bar", method="GET")
    with_id = score_endpoint("/foo/bar/123", method="GET")
    assert with_id - base == IDENTIFIER_BONUS


def test_identifier_uuid_segment():
    base = score_endpoint("/foo/bar", method="GET")
    with_uuid = score_endpoint(
        "/foo/bar/550e8400-e29b-41d4-a716-446655440000", method="GET",
    )
    assert with_uuid - base == IDENTIFIER_BONUS


def test_identifier_long_hex_segment_mongodb_objectid():
    """MongoDB ObjectIds (24 hex chars) should count as identifiers."""
    base = score_endpoint("/foo/bar", method="GET")
    with_hex = score_endpoint(
        "/foo/bar/507f1f77bcf86cd799439011", method="GET",
    )
    assert with_hex - base == IDENTIFIER_BONUS


def test_identifier_short_hex_not_flagged():
    """Short hex-looking strings (< 16 chars) should NOT trigger the id bonus."""
    base = score_endpoint("/foo/bar", method="GET")
    with_short = score_endpoint("/foo/bar/abc123", method="GET")  # 6 hex chars
    assert with_short == base, "short alphanumeric segments must not be treated as ids"


def test_identifier_placeholder_variants():
    base = score_endpoint("/users", method="GET")
    for variant in ("{id}", ":id", "<id>", "{userId}", ":user_id"):
        with_ph = score_endpoint(f"/users/{variant}", method="GET")
        assert with_ph - base == IDENTIFIER_BONUS, f"placeholder {variant!r} not detected"


def test_identifier_query_key_ending_in_id():
    base = score_endpoint("/foo", method="GET")  # 0
    for q in ("id=1", "userId=42", "orderId=abc", "uuid=xxx", "guid=yyy", "productID=7"):
        with_q = score_endpoint(f"/foo?{q}", method="GET")
        assert with_q - base == IDENTIFIER_BONUS, f"query {q!r} not detected as id"


def test_identifier_non_id_query_key_ignored():
    """Query keys that don't name an id must NOT trigger the bonus."""
    base = score_endpoint("/foo", method="GET")
    assert score_endpoint("/foo?q=search&page=2", method="GET") == base


def test_identifier_bonus_is_single_bump():
    """Multiple identifiers on the same endpoint still only add IDENTIFIER_BONUS once."""
    base = score_endpoint("/api/users", method="GET")  # api + users = 4
    with_ids = score_endpoint(
        "/api/users/123/orders/550e8400-e29b-41d4-a716-446655440000?userId=9",
        method="GET",
    )
    # high-signal: api+users+orders = 6; id bonus = +2; method/auth = 0
    assert with_ids == 6 + IDENTIFIER_BONUS


# --- low-value detection --------------------------------------------------

def test_low_value_exact_filenames():
    assert detect_low_value_patterns("/robots.txt") == -10
    assert detect_low_value_patterns("/sitemap.xml") == -10
    assert detect_low_value_patterns("/favicon.ico") == -20  # filename + .ico ext


def test_low_value_prefix_only_applies_to_first_segment():
    """Prefix penalty must only apply when the word is the FIRST segment.

    Deep occurrences like /api/v1/static-content are legitimate API routes
    and must not be penalized.
    """
    assert detect_low_value_patterns("/static/foo") == -5
    assert detect_low_value_patterns("/api/v1/static-content") == 0
    assert detect_low_value_patterns("/api/v1/static/info") == 0
    assert detect_low_value_patterns("/assets/app") == -5
    assert detect_low_value_patterns("/api/assets/report") == 0


def test_low_value_extensions():
    assert detect_low_value_patterns("/foo/bar.css") == -10
    assert detect_low_value_patterns("/foo/bar.png") == -10
    assert detect_low_value_patterns("/foo/bar.woff2") == -10


def test_low_value_prefix_and_extension_stack():
    """Both axes should sum when both hit."""
    assert detect_low_value_patterns("/static/js/app.bundle.js") == -15
    assert detect_low_value_patterns("/images/logo.png") == -15


def test_low_value_health_like_routes_not_penalized():
    """Refactor intent: /health, /status, /version etc. are no longer auto-skipped.

    They score neutrally (0 from the low-value axis) so the caller can rank
    them below real targets without false-killing legitimate resources that
    happen to use those words.
    """
    assert detect_low_value_patterns("/health") == 0
    assert detect_low_value_patterns("/api/v1/status") == 0
    assert detect_low_value_patterns("/version") == 0


def test_low_value_empty_path():
    assert detect_low_value_patterns("/") == 0
    assert detect_low_value_patterns("") == 0


# --- misc invariants ------------------------------------------------------

def test_unknown_method_scores_zero_on_method_axis():
    a = score_endpoint("/foo", method="GET")
    b = score_endpoint("/foo", method="WHATEVER")
    assert a == b == 0


def test_method_case_insensitive():
    assert score_endpoint("/foo", method="delete") == score_endpoint("/foo", method="DELETE")


def test_auth_state_case_insensitive():
    assert score_endpoint("/foo", auth_state="AUTHENTICATED") == \
           score_endpoint("/foo", auth_state="authenticated")


def test_full_url_matches_path_only():
    assert score_endpoint(
        "https://api.target.com/api/users/1?id=99", method="GET",
    ) == score_endpoint(
        "/api/users/1?id=99", method="GET",
    )


def test_no_memory_import_dependency():
    """Scoring must not depend on memory.state_manager at import or call time."""
    import sys
    assert not hasattr(scoring, "DEAD_BRANCH_PENALTY"), (
        "dead-branch coupling should have been removed"
    )
    # Call it without ever touching memory.state_manager — nothing should blow up.
    _ = score_endpoint("/api/users/1", method="GET", auth_state="anonymous")
    _ = sys  # silence lint
