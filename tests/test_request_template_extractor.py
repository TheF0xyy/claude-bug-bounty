"""Tests for tools/request_template_extractor.py.

Coverage map
------------
_parse_cookie_header          basic, multi-value, valueless
_parse_query_string           basic, encoded, multi-key
Cookie classification         tracking exclusion, auth retention, unknown inclusion
Header filtering              session-owned stripped, custom X-* kept
Identifier detection — path   numeric, UUID, hex, slug, version-excluded
Identifier detection — query  id-key match, id-value match, both, none
Identifier detection — body   JSON id key, JSON id value, nested skipped, non-JSON skipped
URL template generation       path replacement, query replacement, no-id path
Name generation               meaningful segments, boring filtered, version filtered
Vuln class suggestion         idor, bac, authz, business_logic, multi
safe_for_auto_replay          GET only
parse_raw_request             HTTP/1.1, HTTP/2, with body, cookie parsing
from_burp_entry               with raw text, with individual fields, bytes, url field
extract_template              end-to-end (customer numeric path, UUID path, POST body)
score_candidate               all scoring factors, penalty
select_candidates             order, top_n, ties stable
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from request_template_extractor import (
    # helpers
    _parse_cookie_header,
    _parse_query_string,
    _is_tracking_cookie,
    _is_auth_cookie,
    classify_cookies,
    extract_required_headers,
    # identifier detection
    detect_identifiers_in_path,
    detect_identifiers_in_query,
    detect_identifiers_in_body,
    # template helpers
    generate_url_template,
    generate_name,
    # data classes
    RawRequest,
    IdentifierCandidate,
    RequestTemplate,
    # entry points
    parse_raw_request,
    from_burp_entry,
    extract_template,
    # scoring
    score_candidate,
    select_candidates,
    # constants (for structural tests)
    TRACKING_COOKIE_PREFIXES,
    AUTH_COOKIE_PATTERNS,
    AUTH_COOKIE_EXACT,
)


# ---------------------------------------------------------------------------
# Sample request fixtures
# ---------------------------------------------------------------------------

RAW_GET_CUSTOMER = """\
GET /customer-data/api/v2/initial-ui-data/54746925 HTTP/1.1\r
Host: www.example.com\r
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig\r
Cookie: sid=abc123; MZPSID=xyz456; CHKSESSIONID=ckq99; _ga=GA1.2.3; _gid=GA1.2.4\r
X-Domain: example.com\r
X-Site-Id: 2\r
Accept: application/json, text/plain, */*\r
Referer: https://www.example.com/account/customer/overview\r
User-Agent: Mozilla/5.0\r
\r
"""

RAW_POST_ORDER = """\
POST /api/v2/orders HTTP/1.1\r
Host: api.example.com\r
Authorization: Bearer tok123\r
Cookie: session=sess_xyz\r
Content-Type: application/json\r
Accept: application/json\r
\r
{"orderId": "ORD-98765", "customerId": "54746925", "items": []}"""

RAW_GET_UUID = """\
GET /api/v1/users/550e8400-e29b-41d4-a716-446655440000/profile HTTP/1.1\r
Host: api.example.com\r
Cookie: auth_token=secret_token_here\r
Accept: application/json\r
\r
"""

RAW_GET_QUERY = """\
GET /api/v2/addresses?customerId=54746925&format=json HTTP/1.1\r
Host: api.example.com\r
Cookie: session=sess_xyz\r
\r
"""

RAW_H2_PSEUDO = """\
:method: GET\r
:path: /api/v3/accounts/12345678\r
:authority: accounts.example.com\r
:scheme: https\r
authorization: Bearer h2token\r
cookie: session=h2sess; _fbp=fb1\r
accept: application/json\r
\r
"""


def _mk_raw(
    method: str = "GET",
    host: str = "example.com",
    path: str = "/api/v1/test",
    query_params: dict | None = None,
    headers: dict | None = None,
    cookies: dict | None = None,
    body: str | None = None,
    scheme: str = "https",
) -> RawRequest:
    return RawRequest(
        method=method,
        scheme=scheme,
        host=host,
        path=path,
        query_params=query_params or {},
        headers=headers or {},
        cookies=cookies or {},
        body=body,
        source="raw_text",
    )


# ---------------------------------------------------------------------------
# _parse_cookie_header
# ---------------------------------------------------------------------------

class TestParseCookieHeader:
    def test_basic(self):
        result = _parse_cookie_header("sid=abc123; MZPSID=xyz")
        assert result == {"sid": "abc123", "MZPSID": "xyz"}

    def test_trailing_semicolon(self):
        result = _parse_cookie_header("sid=abc;")
        assert "sid" in result

    def test_valueless_cookie(self):
        result = _parse_cookie_header("flagcookie")
        assert "flagcookie" in result

    def test_equals_in_value(self):
        result = _parse_cookie_header("jwt=a.b.c==")
        assert result["jwt"] == "a.b.c=="

    def test_empty_string(self):
        result = _parse_cookie_header("")
        assert result == {}


# ---------------------------------------------------------------------------
# _parse_query_string
# ---------------------------------------------------------------------------

class TestParseQueryString:
    def test_basic(self):
        result = _parse_query_string("foo=bar&baz=qux")
        assert result == {"foo": "bar", "baz": "qux"}

    def test_url_encoded_key(self):
        result = _parse_query_string("customer%20id=123")
        assert "customer id" in result

    def test_first_value_wins(self):
        result = _parse_query_string("id=1&id=2")
        assert result["id"] == "1"

    def test_empty(self):
        assert _parse_query_string("") == {}


# ---------------------------------------------------------------------------
# Cookie classification
# ---------------------------------------------------------------------------

class TestTrackingCookieDetection:
    def test_ga_prefix(self):
        assert _is_tracking_cookie("_ga")
        assert _is_tracking_cookie("_gid")
        assert _is_tracking_cookie("_gat_UA123")

    def test_fbp_prefix(self):
        assert _is_tracking_cookie("_fbp")

    def test_optanon_prefix(self):
        assert _is_tracking_cookie("OptanonConsent")
        assert _is_tracking_cookie("OptanonAlertBoxClosed")

    def test_utma_prefix(self):
        assert _is_tracking_cookie("__utma")
        assert _is_tracking_cookie("__utmz")

    def test_non_tracking(self):
        assert not _is_tracking_cookie("sid")
        assert not _is_tracking_cookie("session")
        assert not _is_tracking_cookie("csrf_token")


class TestAuthCookieDetection:
    def test_exact_match(self):
        assert _is_auth_cookie("JSESSIONID")
        assert _is_auth_cookie("MZPSID")
        assert _is_auth_cookie("CHKSESSIONID")
        assert _is_auth_cookie("PHPSESSID")

    def test_pattern_match(self):
        assert _is_auth_cookie("auth_token")
        assert _is_auth_cookie("session_id")
        assert _is_auth_cookie("sid")
        assert _is_auth_cookie("csrfToken")

    def test_prefix_match(self):
        assert _is_auth_cookie("AWSALBSession")
        assert _is_auth_cookie("AWSALBCORS")
        assert _is_auth_cookie("TS0abc123")

    def test_non_auth(self):
        assert not _is_auth_cookie("_ga")
        assert not _is_auth_cookie("preferences")
        assert not _is_auth_cookie("language")


class TestClassifyCookies:
    def test_auth_separated(self):
        cookies = {"sid": "abc", "session": "xyz", "_ga": "GA1"}
        auth, tracking, unknown = classify_cookies(cookies)
        assert "sid" in auth
        assert "session" in auth
        assert "_ga" in tracking
        assert not unknown

    def test_tracking_excluded(self):
        cookies = {"_gid": "G1", "_fbp": "FB1"}
        auth, tracking, unknown = classify_cookies(cookies)
        assert not auth
        assert "_gid" in tracking
        assert "_fbp" in tracking

    def test_unknown_included(self):
        cookies = {"preferences": "dark", "language": "en"}
        auth, tracking, unknown = classify_cookies(cookies)
        assert not auth
        assert not tracking
        assert "preferences" in unknown
        assert "language" in unknown

    def test_mixed(self):
        cookies = {
            "sid": "s1",
            "_ga": "G1",
            "MZPSID": "m1",
            "custom_flag": "1",
        }
        auth, tracking, unknown = classify_cookies(cookies)
        assert "sid" in auth and "MZPSID" in auth
        assert "_ga" in tracking
        assert "custom_flag" in unknown


# ---------------------------------------------------------------------------
# Header filtering
# ---------------------------------------------------------------------------

class TestExtractRequiredHeaders:
    def test_strips_authorization(self):
        h = {"Authorization": "Bearer tok", "Accept": "application/json"}
        result = extract_required_headers(h)
        assert "Authorization" not in result

    def test_strips_cookie(self):
        h = {"Cookie": "sid=abc", "Accept": "*/*"}
        result = extract_required_headers(h)
        assert "Cookie" not in result

    def test_strips_content_length(self):
        h = {"Content-Length": "42", "Content-Type": "application/json"}
        result = extract_required_headers(h)
        assert "Content-Length" not in result

    def test_strips_host(self):
        h = {"Host": "example.com", "Accept": "application/json"}
        result = extract_required_headers(h)
        assert "Host" not in result

    def test_keeps_accept(self):
        h = {"Accept": "application/json"}
        assert "Accept" in extract_required_headers(h)

    def test_keeps_referer(self):
        h = {"Referer": "https://example.com/"}
        assert "Referer" in extract_required_headers(h)

    def test_keeps_custom_x_header(self):
        h = {"X-Domain": "example.com", "X-Site-Id": "2"}
        result = extract_required_headers(h)
        assert "X-Domain" in result
        assert "X-Site-Id" in result

    def test_empty(self):
        assert extract_required_headers({}) == {}


# ---------------------------------------------------------------------------
# Identifier detection — path
# ---------------------------------------------------------------------------

class TestDetectIdentifiersInPath:
    def test_numeric_id(self):
        cands = detect_identifiers_in_path("/api/v2/customers/54746925")
        assert len(cands) == 1
        c = cands[0]
        assert c.kind == "numeric_id"
        assert c.value == "54746925"
        assert c.location == "path"
        assert c.object_type == "customer"

    def test_uuid(self):
        cands = detect_identifiers_in_path(
            "/users/550e8400-e29b-41d4-a716-446655440000"
        )
        assert len(cands) == 1
        assert cands[0].kind == "uuid"
        assert cands[0].object_type == "user"

    def test_hex_id(self):
        cands = detect_identifiers_in_path("/items/507f1f77bcf86cd799439011")
        assert len(cands) == 1
        assert cands[0].kind == "hex_id"

    def test_version_segment_excluded(self):
        cands = detect_identifiers_in_path("/api/v2/test")
        assert len(cands) == 0

    def test_short_number_excluded(self):
        # Numbers < 4 digits should not match.
        cands = detect_identifiers_in_path("/api/v1/page/1")
        assert len(cands) == 0

    def test_multiple_ids(self):
        cands = detect_identifiers_in_path("/users/12345678/orders/87654321")
        assert len(cands) == 2
        locs = {c.value for c in cands}
        assert "12345678" in locs and "87654321" in locs

    def test_slug_with_numeric_suffix(self):
        cands = detect_identifiers_in_path("/products/blue-widget-54746925")
        assert len(cands) == 1
        assert cands[0].kind == "numeric_id"
        assert cands[0].value == "54746925"

    def test_no_id_path(self):
        cands = detect_identifiers_in_path("/api/v2/health")
        assert len(cands) == 0

    def test_object_type_inferred_from_context(self):
        cands = detect_identifiers_in_path("/customer-data/api/v2/initial-ui-data/54746925")
        assert len(cands) == 1
        assert cands[0].object_type == "customer"

    def test_name_generated_from_object_type(self):
        cands = detect_identifiers_in_path("/orders/12345678")
        assert cands[0].name == "orderId"


# ---------------------------------------------------------------------------
# Identifier detection — query
# ---------------------------------------------------------------------------

class TestDetectIdentifiersInQuery:
    def test_id_key_match(self):
        cands = detect_identifiers_in_query({"customerId": "54746925", "format": "json"})
        assert any(c.name == "customerId" for c in cands)

    def test_id_value_match(self):
        cands = detect_identifiers_in_query({"ref": "550e8400-e29b-41d4-a716-446655440000"})
        assert len(cands) == 1
        assert cands[0].kind == "uuid"

    def test_plain_id_key(self):
        cands = detect_identifiers_in_query({"id": "99999"})
        assert len(cands) == 1

    def test_non_id_param(self):
        cands = detect_identifiers_in_query({"format": "json", "page": "1"})
        assert len(cands) == 0

    def test_object_type_from_key(self):
        cands = detect_identifiers_in_query({"orderId": "ORD123"})
        assert cands[0].object_type == "order"


# ---------------------------------------------------------------------------
# Identifier detection — body
# ---------------------------------------------------------------------------

class TestDetectIdentifiersInBody:
    def test_json_id_key(self):
        body = '{"customerId": "54746925", "items": []}'
        cands = detect_identifiers_in_body(body)
        assert any(c.name == "customerId" for c in cands)

    def test_json_id_value(self):
        body = '{"ref": "550e8400-e29b-41d4-a716-446655440000"}'
        cands = detect_identifiers_in_body(body)
        assert len(cands) == 1 and cands[0].kind == "uuid"

    def test_non_json_skipped(self):
        assert detect_identifiers_in_body("not json at all") == []

    def test_empty_body(self):
        assert detect_identifiers_in_body(None) == []
        assert detect_identifiers_in_body("") == []

    def test_nested_not_extracted(self):
        # Only top-level keys in MVP.
        body = '{"meta": {"userId": "12345678"}}'
        cands = detect_identifiers_in_body(body)
        assert len(cands) == 0   # nested object skipped

    def test_integer_id_value(self):
        body = '{"id": 54746925}'
        cands = detect_identifiers_in_body(body)
        assert len(cands) == 1
        assert cands[0].value == "54746925"

    def test_non_dict_root_skipped(self):
        assert detect_identifiers_in_body("[1, 2, 3]") == []


# ---------------------------------------------------------------------------
# URL template generation
# ---------------------------------------------------------------------------

class TestGenerateUrlTemplate:
    def _cands(self, path: str) -> list[IdentifierCandidate]:
        return detect_identifiers_in_path(path)

    def test_numeric_id_replaced(self):
        path = "/api/v2/customers/54746925"
        cands = self._cands(path)
        result = generate_url_template(path, {}, cands)
        assert "{customerId}" in result
        assert "54746925" not in result

    def test_uuid_replaced(self):
        path = "/users/550e8400-e29b-41d4-a716-446655440000"
        cands = self._cands(path)
        result = generate_url_template(path, {}, cands)
        assert "{" in result
        assert "550e8400" not in result

    def test_query_id_replaced(self):
        query = {"customerId": "54746925", "format": "json"}
        path = "/api/addresses"
        path_cands = self._cands(path)
        query_cands = detect_identifiers_in_query(query)
        result = generate_url_template(path, query, path_cands + query_cands)
        assert "{customerId}" in result
        assert "format=json" in result

    def test_no_id_path_unchanged(self):
        path = "/api/v2/health"
        result = generate_url_template(path, {}, [])
        assert result == path

    def test_multiple_ids(self):
        path = "/users/12345678/orders/87654321"
        cands = self._cands(path)
        result = generate_url_template(path, {}, cands)
        assert "12345678" not in result
        assert "87654321" not in result


# ---------------------------------------------------------------------------
# Name generation
# ---------------------------------------------------------------------------

class TestGenerateName:
    def test_customer_path(self):
        path = "/customer-data/api/v2/initial-ui-data/54746925"
        cands = detect_identifiers_in_path(path)
        name = generate_name(path, cands)
        # Should not include the ID value or "api" or "v2".
        assert "54746925" not in name
        assert "api" not in name
        assert "v2" not in name
        assert len(name) > 0

    def test_hyphens_become_underscores(self):
        path = "/initial-ui-data/54746925"
        cands = detect_identifiers_in_path(path)
        name = generate_name(path, cands)
        assert "-" not in name
        assert "_" in name or name == "initial_ui_data"

    def test_empty_path_fallback(self):
        name = generate_name("/", [])
        assert name == "request"

    def test_uuid_path(self):
        path = "/users/550e8400-e29b-41d4-a716-446655440000/profile"
        cands = detect_identifiers_in_path(path)
        name = generate_name(path, cands)
        assert "550e8400" not in name
        assert "users" in name or "profile" in name


# ---------------------------------------------------------------------------
# safe_for_auto_replay
# ---------------------------------------------------------------------------

class TestSafeForAutoReplay:
    def test_get_is_safe(self):
        raw = _mk_raw(method="GET")
        t = extract_template(raw)
        assert t.safe_for_auto_replay is True

    def test_post_is_not_safe(self):
        raw = _mk_raw(method="POST")
        t = extract_template(raw)
        assert t.safe_for_auto_replay is False

    def test_put_is_not_safe(self):
        raw = _mk_raw(method="PUT")
        t = extract_template(raw)
        assert t.safe_for_auto_replay is False

    def test_patch_is_not_safe(self):
        raw = _mk_raw(method="PATCH")
        t = extract_template(raw)
        assert t.safe_for_auto_replay is False

    def test_delete_is_not_safe(self):
        raw = _mk_raw(method="DELETE")
        t = extract_template(raw)
        assert t.safe_for_auto_replay is False


# ---------------------------------------------------------------------------
# parse_raw_request
# ---------------------------------------------------------------------------

class TestParseRawRequest:
    def test_http11_method(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        assert raw.method == "GET"

    def test_http11_path(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        assert raw.path == "/customer-data/api/v2/initial-ui-data/54746925"

    def test_http11_host(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        assert raw.host == "www.example.com"

    def test_http11_scheme_default(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        assert raw.scheme == "https"

    def test_http11_cookies_parsed(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        assert raw.cookies.get("sid") == "abc123"
        assert raw.cookies.get("MZPSID") == "xyz456"
        assert raw.cookies.get("CHKSESSIONID") == "ckq99"

    def test_http11_authorization_in_headers(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        auth = raw.headers.get("Authorization")
        assert auth is not None
        assert auth.startswith("Bearer")

    def test_http11_query_params(self):
        raw = parse_raw_request(RAW_GET_QUERY)
        assert raw.query_params.get("customerId") == "54746925"
        assert raw.query_params.get("format") == "json"

    def test_http11_post_body(self):
        raw = parse_raw_request(RAW_POST_ORDER)
        assert raw.body is not None
        assert "orderId" in raw.body

    def test_http2_pseudo_headers(self):
        raw = parse_raw_request(RAW_H2_PSEUDO)
        assert raw.method == "GET"
        assert raw.path == "/api/v3/accounts/12345678"
        assert raw.host == "accounts.example.com"
        assert raw.scheme == "https"

    def test_http2_cookies_parsed(self):
        raw = parse_raw_request(RAW_H2_PSEUDO)
        assert raw.cookies.get("session") == "h2sess"
        assert "_fbp" in raw.cookies

    def test_source_raw_text(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        assert raw.source == "raw_text"

    def test_crlf_and_lf_equivalent(self):
        text_crlf = RAW_GET_UUID
        text_lf = text_crlf.replace("\r\n", "\n")
        raw_crlf = parse_raw_request(text_crlf)
        raw_lf = parse_raw_request(text_lf)
        assert raw_crlf.method == raw_lf.method
        assert raw_crlf.path == raw_lf.path


# ---------------------------------------------------------------------------
# from_burp_entry
# ---------------------------------------------------------------------------

class TestFromBurpEntry:
    def _entry_with_raw(self, raw_text: str, host: str = "example.com") -> dict:
        return {
            "host": host,
            "port": 443,
            "protocol": "https",
            "request": raw_text,
            "status": 200,
        }

    def test_with_raw_text_key(self):
        entry = self._entry_with_raw(RAW_GET_CUSTOMER, host="www.example.com")
        raw = from_burp_entry(entry)
        assert raw.method == "GET"
        assert raw.path == "/customer-data/api/v2/initial-ui-data/54746925"

    def test_scheme_from_entry_metadata(self):
        entry = self._entry_with_raw(RAW_GET_CUSTOMER)
        raw = from_burp_entry(entry)
        assert raw.scheme == "https"

    def test_scheme_from_protocol_field(self):
        entry = {"host": "example.com", "protocol": "http", "method": "GET", "path": "/test"}
        raw = from_burp_entry(entry)
        assert raw.scheme == "http"

    def test_scheme_inferred_from_port_443(self):
        entry = {"host": "example.com", "port": 443, "method": "GET", "path": "/test"}
        raw = from_burp_entry(entry)
        assert raw.scheme == "https"

    def test_scheme_inferred_from_port_80(self):
        entry = {"host": "example.com", "port": 80, "method": "GET", "path": "/test"}
        raw = from_burp_entry(entry)
        assert raw.scheme == "http"

    def test_source_burp_mcp(self):
        entry = self._entry_with_raw(RAW_GET_CUSTOMER)
        raw = from_burp_entry(entry)
        assert raw.source == "burp_mcp"

    def test_individual_fields_fallback(self):
        entry = {
            "host": "example.com",
            "port": 443,
            "protocol": "https",
            "method": "POST",
            "path": "/api/orders?id=12345",
            "headers": {"Accept": "application/json", "Content-Type": "application/json"},
            "cookies": {"session": "sess_abc"},
            "body": '{"orderId": "ORD-99"}',
        }
        raw = from_burp_entry(entry)
        assert raw.method == "POST"
        assert raw.path == "/api/orders"
        assert raw.query_params.get("id") == "12345"
        assert raw.cookies.get("session") == "sess_abc"
        assert raw.body is not None

    def test_raw_bytes_decoded(self):
        raw_bytes = RAW_GET_UUID.encode("utf-8")
        entry = {"host": "api.example.com", "port": 443, "protocol": "https", "request": raw_bytes}
        raw = from_burp_entry(entry)
        assert raw.path == "/api/v1/users/550e8400-e29b-41d4-a716-446655440000/profile"

    def test_url_field_used_when_path_absent(self):
        entry = {
            "host": "example.com",
            "port": 443,
            "protocol": "https",
            "method": "GET",
            "url": "https://example.com/api/users/99887766",
        }
        raw = from_burp_entry(entry)
        assert raw.path == "/api/users/99887766"


# ---------------------------------------------------------------------------
# extract_template — end-to-end
# ---------------------------------------------------------------------------

class TestExtractTemplate:
    def test_customer_numeric_path(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        t = extract_template(raw)

        assert t.method == "GET"
        assert t.path == "/customer-data/api/v2/initial-ui-data/54746925"
        assert "54746925" in t.full_url
        assert "{customerId}" in t.url_template
        assert "54746925" not in t.url_template

    def test_auth_material_summary_authorization(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        t = extract_template(raw)
        assert t.auth_material_summary["has_authorization"] is True

    def test_auth_material_summary_cookies(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        t = extract_template(raw)
        auth_names = t.auth_material_summary["auth_cookie_names"]
        assert "sid" in auth_names or "MZPSID" in auth_names or "CHKSESSIONID" in auth_names

    def test_tracking_cookies_not_in_auth_summary(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        t = extract_template(raw)
        auth_names = t.auth_material_summary["auth_cookie_names"]
        assert "_ga" not in auth_names
        assert "_gid" not in auth_names

    def test_required_headers_excludes_session_owned(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        t = extract_template(raw)
        assert "Authorization" not in t.required_headers
        assert "Cookie" not in t.required_headers

    def test_required_headers_includes_custom_x_headers(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        t = extract_template(raw)
        assert "X-Domain" in t.required_headers
        assert "X-Site-Id" in t.required_headers

    def test_identifier_candidates_path(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        t = extract_template(raw)
        path_ids = [c for c in t.identifier_candidates if c.location == "path"]
        assert len(path_ids) == 1
        assert path_ids[0].value == "54746925"
        assert path_ids[0].kind == "numeric_id"

    def test_suggested_vuln_classes_idor(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        t = extract_template(raw)
        assert "idor" in t.suggested_vuln_classes

    def test_safe_for_auto_replay_get(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        t = extract_template(raw)
        assert t.safe_for_auto_replay is True

    def test_post_order_body_identifiers(self):
        raw = parse_raw_request(RAW_POST_ORDER)
        t = extract_template(raw)
        body_ids = [c for c in t.identifier_candidates if c.location == "body"]
        body_keys = {c.name for c in body_ids}
        assert "orderId" in body_keys or "customerId" in body_keys

    def test_post_not_safe_for_auto_replay(self):
        raw = parse_raw_request(RAW_POST_ORDER)
        t = extract_template(raw)
        assert t.safe_for_auto_replay is False

    def test_uuid_path(self):
        raw = parse_raw_request(RAW_GET_UUID)
        t = extract_template(raw)
        uuid_ids = [c for c in t.identifier_candidates if c.kind == "uuid"]
        assert len(uuid_ids) == 1
        assert "550e8400" not in t.url_template

    def test_query_identifiers(self):
        raw = parse_raw_request(RAW_GET_QUERY)
        t = extract_template(raw)
        query_ids = [c for c in t.identifier_candidates if c.location == "query"]
        assert any(c.name == "customerId" for c in query_ids)

    def test_to_dict_serialisable(self):
        import json as _json
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        t = extract_template(raw)
        blob = _json.dumps(t.to_dict())   # must not raise
        parsed = _json.loads(blob)
        assert parsed["method"] == "GET"
        assert "identifier_candidates" in parsed

    def test_custom_name_override(self):
        raw = parse_raw_request(RAW_GET_CUSTOMER)
        t = extract_template(raw, name="my_custom_name")
        assert t.name == "my_custom_name"

    def test_h2_request_template(self):
        raw = parse_raw_request(RAW_H2_PSEUDO)
        t = extract_template(raw)
        assert t.method == "GET"
        assert t.auth_material_summary["has_authorization"] is True
        assert "{" in t.url_template   # identifier replaced

    def test_admin_path_suggests_bac_authz(self):
        raw = _mk_raw(path="/admin/users", headers={"Authorization": "Bearer tok"})
        t = extract_template(raw)
        assert "bac" in t.suggested_vuln_classes or "authz" in t.suggested_vuln_classes

    def test_post_suggests_business_logic(self):
        raw = _mk_raw(method="POST", path="/api/orders")
        t = extract_template(raw)
        assert "business_logic" in t.suggested_vuln_classes


# ---------------------------------------------------------------------------
# score_candidate
# ---------------------------------------------------------------------------

class TestScoreCandidate:
    def _template(self, **kwargs) -> RequestTemplate:
        """Build a minimal template for scoring tests."""
        defaults = dict(
            name="test",
            method="GET",
            full_url="https://example.com/test",
            url_template="https://example.com/test",
            path="/test",
            query_params={},
            body=None,
            required_headers={},
            auth_material_summary={"has_authorization": False, "auth_cookie_names": []},
            identifier_candidates=[],
            suggested_vuln_classes=[],
            safe_for_auto_replay=True,
        )
        defaults.update(kwargs)
        return RequestTemplate(**defaults)

    def test_get_bonus(self):
        t = self._template(method="GET")
        post_t = self._template(method="POST")
        assert score_candidate(t) > score_candidate(post_t)

    def test_identifier_bonus(self):
        c = IdentifierCandidate(location="path", name="id", value="12345", kind="numeric_id", object_type=None)
        with_id = self._template(identifier_candidates=[c], suggested_vuln_classes=["idor"])
        without_id = self._template()
        assert score_candidate(with_id) > score_candidate(without_id)

    def test_auth_bonus(self):
        with_auth = self._template(auth_material_summary={"has_authorization": True, "auth_cookie_names": []})
        without_auth = self._template()
        assert score_candidate(with_auth) > score_candidate(without_auth)

    def test_high_value_path_bonus(self):
        high = self._template(path="/customer/orders")
        low = self._template(path="/misc/settings")
        assert score_candidate(high) > score_candidate(low)

    def test_static_penalty(self):
        static_t = self._template(path="/static/app.js")
        normal_t = self._template(path="/api/test")
        assert score_candidate(static_t) < score_candidate(normal_t)

    def test_robots_penalty(self):
        t = self._template(path="/robots.txt")
        assert score_candidate(t) < 0

    def test_json_accept_bonus(self):
        with_json = self._template(required_headers={"Accept": "application/json"})
        without = self._template()
        assert score_candidate(with_json) >= score_candidate(without)

    def test_idor_class_bonus(self):
        with_idor = self._template(suggested_vuln_classes=["idor"])
        without = self._template()
        assert score_candidate(with_idor) > score_candidate(without)


# ---------------------------------------------------------------------------
# select_candidates
# ---------------------------------------------------------------------------

class TestSelectCandidates:
    def _make_templates(self) -> list[RequestTemplate]:
        """Three templates with descending expected scores."""
        raw_high = parse_raw_request(RAW_GET_CUSTOMER)   # auth + identifier → high
        raw_static = _mk_raw(path="/static/bundle.js")    # static → negative
        raw_mid = parse_raw_request(RAW_GET_UUID)          # auth + identifier, no X-headers
        return [
            extract_template(raw_static),
            extract_template(raw_mid),
            extract_template(raw_high),
        ]

    def test_descending_order(self):
        templates = self._make_templates()
        selected = select_candidates(templates)
        scores = [score_candidate(t) for t in selected]
        assert scores == sorted(scores, reverse=True)

    def test_top_n_respected(self):
        templates = self._make_templates()
        selected = select_candidates(templates, top_n=2)
        assert len(selected) <= 2

    def test_top_n_larger_than_list(self):
        templates = self._make_templates()
        selected = select_candidates(templates, top_n=100)
        assert len(selected) == len(templates)

    def test_stable_order_for_equal_scores(self):
        # Two identical templates: insertion order is preserved for ties.
        raw = _mk_raw(path="/api/test")
        t1 = extract_template(raw, name="first")
        t2 = extract_template(raw, name="second")
        selected = select_candidates([t1, t2])
        assert selected[0].name == "first"

    def test_static_not_first(self):
        templates = self._make_templates()
        selected = select_candidates(templates)
        assert "static" not in selected[0].path.lower()

    def test_authenticated_identifier_is_first(self):
        templates = self._make_templates()
        selected = select_candidates(templates)
        # Top candidate must have identifiers and some form of auth material.
        top = selected[0]
        summary = top.auth_material_summary
        has_any_auth = summary.get("has_authorization") or bool(summary.get("auth_cookie_names"))
        assert has_any_auth, "Top candidate should have auth material"
        assert len(top.identifier_candidates) > 0, "Top candidate should have identifiers"
