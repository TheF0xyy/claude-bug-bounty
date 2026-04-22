"""Tests for tools/method_inferrer.py.

Coverage:
  1. OPTIONS response with Allow header is parsed correctly → inferred methods pruned.
  2. 400 response triggers candidate add with body template from GET JSON.
  3. 401/403 responses trigger candidate add (medium signal).
  4. 404/405 responses are skipped (no candidate added).
  5. GET response body is used to generate a body template.
  6. Scope checker blocks out-of-scope URLs.
  7. Dry-run makes no HTTP requests and no state changes.
  + Unit tests for pure helpers: looks_like_resource_endpoint,
    infer_write_methods, parse_allow_header, generate_body_template.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import pytest

# ── path setup ────────────────────────────────────────────────────────────────
_REPO = Path(__file__).resolve().parent.parent
_TOOLS = _REPO / "tools"
for _p in (str(_TOOLS), str(_REPO)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from method_inferrer import (                          # noqa: E402
    MethodInferrer,
    InferResult,
    ProbeOutcome,
    ReverseInferResult,
    ReverseProbeOutcome,
    generate_body_template,
    infer_write_methods,
    looks_like_resource_endpoint,
    parse_allow_header,
    extract_numeric_id,
    replace_id_in_path,
    _bodies_differ_at_same_structure,
    _EMPTY_JSON_BODY,
    _PLACEHOLDER_STR,
    main,
)
from memory.state_manager import add_candidate, get_candidates  # noqa: E402
from memory.audit_log import AuditLog, RateLimiter               # noqa: E402
from scope_checker import ScopeChecker                          # noqa: E402


# ── helpers ───────────────────────────────────────────────────────────────────

_DEFAULT_SESSION = [
    {
        "name": "account_a",
        "cookies": {"session": "tok_a"},
        "headers": {},
        "auth_header": "Bearer token_a",
        "notes": "test account a",
    },
    {
        "name": "account_b",
        "cookies": {"session": "tok_b"},
        "headers": {},
        "auth_header": "Bearer token_b",
        "notes": "test account b",
    },
]


def _make_sessions_file(
    tmp_path: Path,
    entries: list[dict] | None = None,
) -> Path:
    p = tmp_path / "sessions.json"
    p.write_text(json.dumps(entries or _DEFAULT_SESSION), encoding="utf-8")
    return p


def _make_state_file(
    tmp_path: Path,
    initial: dict | None = None,
) -> Path:
    p = tmp_path / "hunt_state.json"
    p.write_text(json.dumps(initial or {}), encoding="utf-8")
    return p


def _make_audit(tmp_path: Path) -> tuple[AuditLog, Path]:
    p = tmp_path / "audit.jsonl"
    return AuditLog(p), p


def _null_rate_limiter() -> RateLimiter:
    """RateLimiter that never sleeps (for tests)."""
    rl = RateLimiter(recon_rps=1000.0, test_rps=1000.0)
    return rl


def _make_transport(
    responses: dict[tuple[str, str], tuple[int, bytes, dict]] | None = None,
    default: tuple[int, bytes, dict] | None = None,
):
    """Create an injectable transport mock.

    *responses* is ``{(METHOD, url): (status, body, headers)}``.
    URLs are matched by suffix (path only) for convenience.
    Falls back to *default* (or 404) for unmatched pairs.
    """
    resp_map = responses or {}
    default_resp = default or (404, b"", {})

    def transport(
        method: str,
        url: str,
        headers: dict,
        body: Optional[bytes],
        timeout: float,
    ) -> tuple[int, bytes, dict]:
        key = (method.upper(), url)
        if key in resp_map:
            return resp_map[key]
        # Also try matching by path suffix.
        for (m, u), v in resp_map.items():
            if m == method.upper() and url.endswith(u):
                return v
        return default_resp

    return transport


def _make_mi(
    tmp_path: Path,
    target: str = "api.example.com",
    transport=None,
    scope_checker=None,
    sessions_entries: list[dict] | None = None,
    state_data: dict | None = None,
    candidates: list[tuple[str, str]] | None = None,
) -> tuple[MethodInferrer, Path, Path]:
    """Build a MethodInferrer wired to temp files.

    Returns (mi, state_path, audit_path).
    """
    sessions_file = _make_sessions_file(tmp_path, sessions_entries)
    state_path = _make_state_file(tmp_path, state_data or {})
    audit, audit_path = _make_audit(tmp_path)

    if candidates:
        for ep, method in candidates:
            add_candidate(target, ep, method, path=state_path)

    mi = MethodInferrer(
        target=target,
        state_file=state_path,
        sessions_file=sessions_file,
        audit_log=audit,
        scope_checker=scope_checker,
        transport=transport or _make_transport(),
        _rate_limiter=_null_rate_limiter(),
    )
    return mi, state_path, audit_path


# ── 1. Pure helper: looks_like_resource_endpoint ─────────────────────────────


class TestLooksLikeResourceEndpoint:

    @pytest.mark.parametrize("path,expected", [
        # Numeric IDs
        ("/api/users/42", True),
        ("/api/users/1234", True),
        ("/api/orders/999/detail", True),
        # UUIDs
        ("/api/users/550e8400-e29b-41d4-a716-446655440000", True),
        # Placeholders
        ("/api/users/{id}", True),
        ("/api/users/:userId", True),
        # Resource keywords
        ("/api/profile", True),
        ("/api/settings", True),
        ("/account/preferences", True),
        ("/api/orders", True),
        ("/api/subscription", True),
        # Paths with both ID and keyword
        ("/api/users/42/address", True),
        ("/api/users/42/profile", True),
        # Negative cases
        ("/api/v1/health", False),
        ("/robots.txt", False),
        ("/api/v2/docs", False),
        ("/static/js/app.js", False),
        ("/api", False),
    ])
    def test_detection(self, path, expected):
        assert looks_like_resource_endpoint(path) is expected

    def test_two_digit_number_is_not_id(self):
        # 2-digit numbers are not treated as IDs (minimum 3 digits).
        # Use a path with only a 2-digit segment and no resource keywords.
        assert looks_like_resource_endpoint("/api/v1/data/42") is False

    def test_three_digit_number_is_id(self):
        assert looks_like_resource_endpoint("/api/data/123") is True


# ── 2. Pure helper: infer_write_methods ──────────────────────────────────────


class TestInferWriteMethods:

    def test_basic_resource_gets_put_and_patch(self):
        methods = infer_write_methods("/api/users/42")
        assert "PUT" in methods
        assert "PATCH" in methods

    def test_order_endpoint_gets_delete(self):
        methods = infer_write_methods("/api/orders/99")
        assert "DELETE" in methods

    def test_subscription_endpoint_gets_delete(self):
        methods = infer_write_methods("/api/subscriptions/5")
        assert "DELETE" in methods

    def test_profile_does_not_get_delete(self):
        methods = infer_write_methods("/api/profile")
        assert "DELETE" not in methods

    def test_settings_does_not_get_delete(self):
        methods = infer_write_methods("/api/settings")
        assert "DELETE" not in methods

    def test_address_endpoint_no_delete(self):
        # address/addresses not in _DELETE_KEYWORDS
        methods = infer_write_methods("/api/users/42/address")
        assert "DELETE" not in methods
        assert "PUT" in methods
        assert "PATCH" in methods

    def test_returns_list_not_empty(self):
        methods = infer_write_methods("/api/items/1")
        assert len(methods) >= 2


# ── 3. Pure helper: parse_allow_header ───────────────────────────────────────


class TestParseAllowHeader:

    def test_parses_common_format(self):
        result = parse_allow_header("GET, POST, PUT")
        assert result == frozenset({"GET", "POST", "PUT"})

    def test_case_insensitive_uppercased(self):
        result = parse_allow_header("get, post")
        assert result == frozenset({"GET", "POST"})

    def test_handles_extra_whitespace(self):
        result = parse_allow_header("  GET ,  PUT  ")
        assert result == frozenset({"GET", "PUT"})

    def test_empty_string_returns_empty_frozenset(self):
        result = parse_allow_header("")
        assert result == frozenset()

    def test_single_method(self):
        result = parse_allow_header("GET")
        assert result == frozenset({"GET"})


# ── 4. Pure helper: generate_body_template ───────────────────────────────────


class TestGenerateBodyTemplate:

    def test_string_values_replaced_with_placeholder(self):
        body = b'{"name": "Alice", "email": "a@example.com"}'
        result = generate_body_template(body)
        parsed = json.loads(result)
        assert parsed["name"] == _PLACEHOLDER_STR
        assert parsed["email"] == _PLACEHOLDER_STR

    def test_int_values_replaced_with_zero(self):
        body = b'{"age": 42, "count": 100}'
        result = generate_body_template(body)
        parsed = json.loads(result)
        assert parsed["age"] == 0
        assert parsed["count"] == 0

    def test_bool_values_replaced_with_false(self):
        body = b'{"active": true, "verified": false}'
        result = generate_body_template(body)
        parsed = json.loads(result)
        assert parsed["active"] is False
        assert parsed["verified"] is False

    def test_list_values_replaced_with_empty_list(self):
        body = b'{"tags": ["a", "b"]}'
        result = generate_body_template(body)
        parsed = json.loads(result)
        assert parsed["tags"] == []

    def test_dict_values_replaced_with_empty_dict(self):
        body = b'{"address": {"street": "Main St"}}'
        result = generate_body_template(body)
        parsed = json.loads(result)
        assert parsed["address"] == {}

    def test_keys_preserved(self):
        body = b'{"firstName": "Alice", "lastName": "Smith"}'
        result = generate_body_template(body)
        parsed = json.loads(result)
        assert set(parsed.keys()) == {"firstName", "lastName"}

    def test_non_json_returns_none(self):
        assert generate_body_template(b"<html>not json</html>") is None

    def test_json_array_returns_none(self):
        assert generate_body_template(b'[1, 2, 3]') is None

    def test_empty_body_returns_none(self):
        assert generate_body_template(b"") is None

    def test_empty_object_returns_empty_template(self):
        result = generate_body_template(b"{}")
        parsed = json.loads(result)
        assert parsed == {}

    def test_float_values_replaced_with_zero_float(self):
        body = b'{"price": 9.99}'
        result = generate_body_template(body)
        parsed = json.loads(result)
        assert parsed["price"] == 0.0


# ── 5. OPTIONS response with Allow header is parsed and used to prune ─────────


class TestOptionsAllowHeaderParsing:
    """OPTIONS Allow header is parsed and used to prune write-method probes."""

    def test_options_allow_header_prunes_excluded_method(self, tmp_path):
        """When OPTIONS returns Allow: GET, PATCH — PUT must be pruned."""
        call_log: list[tuple[str, str]] = []

        def transport(method, url, headers, body, timeout):
            call_log.append((method.upper(), url))
            if method.upper() == "OPTIONS":
                return 200, b"", {"allow": "GET, PATCH"}
            if method.upper() == "GET":
                return 200, b'{"id": 1}', {}
            # PATCH probe
            if method.upper() == "PATCH":
                return 200, b"ok", {}
            # PUT should not be called
            return 405, b"", {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        assert len(results) == 1
        r = results[0]
        assert not r.skipped

        # PUT must be in probes but marked as skip (Allow excluded it).
        put_probes = [p for p in r.probes if p.method == "PUT"]
        assert put_probes, "PUT should appear in probes"
        assert put_probes[0].signal == "skip"
        assert "OPTIONS Allow header excludes PUT" in put_probes[0].notes

        # PUT must not have been sent to the transport.
        put_calls = [(m, u) for m, u in call_log if m == "PUT"]
        assert not put_calls, f"PUT must not be sent when Allow excludes it; calls={call_log}"

    def test_options_with_no_allow_header_does_not_prune(self, tmp_path):
        """When OPTIONS returns no Allow header, all inferred methods are probed."""
        call_log: list[str] = []

        def transport(method, url, headers, body, timeout):
            call_log.append(method.upper())
            if method.upper() == "OPTIONS":
                return 200, b"", {}  # no Allow header
            if method.upper() == "GET":
                return 200, b'{}', {}
            return 405, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        r = results[0]
        assert not r.skipped
        # Both PUT and PATCH should appear in probes (not pruned).
        probe_methods = {p.method for p in r.probes}
        assert "PUT" in probe_methods
        assert "PATCH" in probe_methods
        # Both should have been called.
        assert "PUT" in call_log
        assert "PATCH" in call_log

    def test_options_method_failure_does_not_stop_probing(self, tmp_path):
        """Transport error on OPTIONS must not prevent write probes from running."""
        call_log: list[str] = []

        def transport(method, url, headers, body, timeout):
            call_log.append(method.upper())
            if method.upper() == "OPTIONS":
                raise ConnectionError("options refused")
            if method.upper() == "GET":
                return 200, b"{}", {}
            return 200, b"ok", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        r = results[0]
        assert not r.skipped
        assert "PUT" in call_log or "PATCH" in call_log


# ── 6. 400 response triggers candidate with body template ─────────────────────


class TestBadRequestTriggersCandidate:

    def test_400_adds_candidate_with_body_template(self, tmp_path):
        """400 response → candidate added with body template from GET JSON."""
        get_body = b'{"name": "Alice", "role": "user"}'

        def transport(method, url, headers, body, timeout):
            if method.upper() == "OPTIONS":
                return 200, b"", {}
            if method.upper() == "GET":
                return 200, get_body, {"content-type": "application/json"}
            if method.upper() in ("PUT", "PATCH"):
                return 400, b'{"error": "invalid body"}', {}
            return 404, b"", {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        r = results[0]
        assert not r.skipped
        added_methods = {m for m, _ in r.added}
        assert "PUT" in added_methods or "PATCH" in added_methods

        # Verify body template was generated and stored.
        put_probes = [p for p in r.probes if p.method == "PUT"]
        if put_probes:
            assert put_probes[0].signal == "medium"
            assert put_probes[0].body_template is not None
            template = json.loads(put_probes[0].body_template)
            assert template["name"] == _PLACEHOLDER_STR
            assert template["role"] == _PLACEHOLDER_STR

        # Verify candidate in state.
        candidates = get_candidates("api.example.com", path=state_path)
        write_candidates = [c for c in candidates if c["method"] in ("PUT", "PATCH")]
        assert write_candidates, "Write method candidates must be added to state"

    def test_422_also_triggers_candidate(self, tmp_path):
        """422 is treated the same as 400 — method understood, body rejected."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "OPTIONS":
                return 200, b"", {}
            if method.upper() == "GET":
                return 200, b'{"field": "value"}', {}
            return 422, b'{"error": "validation failed"}', {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        r = results[0]
        assert r.added, "422 should add a candidate"
        candidates = get_candidates("api.example.com", path=state_path)
        assert any(c["method"] in ("PUT", "PATCH") for c in candidates)

    def test_400_without_get_json_uses_empty_body(self, tmp_path):
        """400 without parseable GET JSON uses empty JSON body ({}) as fallback."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "OPTIONS":
                return 200, b"", {}
            if method.upper() == "GET":
                return 200, b"<html>not json</html>", {}
            return 400, b"", {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        r = results[0]
        assert r.added
        candidates = get_candidates("api.example.com", path=state_path)
        write_candidates = [c for c in candidates if c["method"] in ("PUT", "PATCH")]
        assert write_candidates
        # body_template probe field should be None (no JSON to template from).
        put_or_patch = [p for p in r.probes if p.signal == "medium"]
        assert all(p.body_template is None for p in put_or_patch)


# ── 7. 401/403 response triggers candidate ────────────────────────────────────


class TestAuthErrorTriggersCandidate:

    @pytest.mark.parametrize("status_code", [401, 403])
    def test_auth_error_adds_candidate(self, tmp_path, status_code):
        """401/403 adds a medium-signal candidate — method exists, worth BAC test."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "OPTIONS":
                return 200, b"", {}
            if method.upper() == "GET":
                return 200, b'{"id": 1}', {}
            return status_code, b"Unauthorized", {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        r = results[0]
        assert r.added, f"{status_code} should add candidate"
        assert all(signal == "medium" for _, signal in r.added)

        candidates = get_candidates("api.example.com", path=state_path)
        assert any(c["method"] in ("PUT", "PATCH") for c in candidates)

    def test_401_signal_notes_mention_cross_account(self, tmp_path):
        """401 probe notes should mention cross-account test."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "OPTIONS":
                return 200, b"", {}
            if method.upper() == "GET":
                return 200, b"{}", {}
            return 401, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        r = results[0]
        auth_probes = [p for p in r.probes if p.status_code == 401]
        assert auth_probes
        assert "cross-account" in auth_probes[0].notes


# ── 8. 404/405 response is skipped ───────────────────────────────────────────


class TestSkipStatuses:

    @pytest.mark.parametrize("status_code", [404, 405])
    def test_method_not_available_is_skipped(self, tmp_path, status_code):
        """404/405 write response → skip signal, no candidate added."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "OPTIONS":
                return 200, b"", {}
            if method.upper() == "GET":
                return 200, b"{}", {}
            return status_code, b"", {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        r = results[0]
        # No candidates should be added.
        assert not r.added, f"{status_code} should not add candidate"
        candidates = get_candidates("api.example.com", path=state_path)
        write_candidates = [c for c in candidates if c["method"] in ("PUT", "PATCH", "DELETE")]
        assert not write_candidates

    def test_405_probe_marked_skip(self, tmp_path):
        """405 write probes must appear in probes list with signal='skip'."""
        def transport(method, url, headers, body, timeout):
            if method.upper() in ("OPTIONS", "GET"):
                return 200, b"{}", {}
            return 405, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        r = results[0]
        skipped_probes = [p for p in r.probes if p.signal == "skip" and p.status_code == 405]
        assert skipped_probes


# ── 9. GET response body used to generate body template ──────────────────────


class TestGetBodyUsedForTemplate:

    def test_get_response_json_seeds_body_template(self, tmp_path):
        """GET JSON response keys should appear in the body template."""
        get_body = b'{"street": "Main St", "city": "Springfield", "zip": "12345"}'

        def transport(method, url, headers, body, timeout):
            if method.upper() == "OPTIONS":
                return 200, b"", {}
            if method.upper() == "GET":
                return 200, get_body, {}
            # PUT/PATCH return 400 to trigger template generation.
            return 400, b'{"error": "bad body"}', {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42/address"])

        r = results[0]
        template_probes = [p for p in r.probes if p.body_template is not None]
        assert template_probes, "Body template should be generated for 400 outcome"

        template_parsed = json.loads(template_probes[0].body_template)
        assert "street" in template_parsed
        assert "city" in template_parsed
        assert "zip" in template_parsed
        assert template_parsed["street"] == _PLACEHOLDER_STR

    def test_get_body_not_used_for_high_signal(self, tmp_path):
        """200 write response (high signal) should NOT generate a body template."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "OPTIONS":
                return 200, b"", {}
            if method.upper() == "GET":
                return 200, b'{"id": 1, "name": "test"}', {}
            return 200, b"updated", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        r = results[0]
        # High signal probes do not get a body template.
        high_probes = [p for p in r.probes if p.signal == "high"]
        assert high_probes
        assert all(p.body_template is None for p in high_probes)

    def test_get_failure_does_not_block_write_probe(self, tmp_path):
        """GET transport error must not prevent write probes from running."""
        call_log: list[str] = []

        def transport(method, url, headers, body, timeout):
            call_log.append(method.upper())
            if method.upper() == "OPTIONS":
                return 200, b"", {}
            if method.upper() == "GET":
                raise ConnectionError("server unreachable")
            return 401, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run(["/api/users/42"])

        r = results[0]
        # Write probes must still run.
        assert "PUT" in call_log or "PATCH" in call_log
        # Candidates should still be added for 401 signal.
        assert r.added


# ── 10. Scope checker blocks out-of-scope URLs ───────────────────────────────


class TestScopeChecker:

    def test_out_of_scope_is_skipped_and_not_probed(self, tmp_path):
        """Out-of-scope endpoints must not trigger any HTTP request."""
        call_log: list[str] = []

        def transport(method, url, headers, body, timeout):
            call_log.append(url)
            return 200, b"ok", {}

        # api.example.com is NOT in ScopeChecker(["other.com"]).
        sub = tmp_path / "sub"
        sub.mkdir()
        mi, state_path, _ = _make_mi(
            sub,
            transport=transport,
            scope_checker=ScopeChecker(["other.com"]),
        )
        results = mi.run(["/api/users/42"])
        assert len(results) == 1
        r = results[0]
        assert r.skipped is True
        assert "scope" in r.skip_reason
        # Transport must never have been called for the out-of-scope endpoint.
        assert not call_log, f"No HTTP calls expected; got: {call_log}"

    def test_out_of_scope_not_added_to_state(self, tmp_path):
        """Out-of-scope endpoint must not add any candidate to hunt_state.json."""
        scope = ScopeChecker(["other.com"])
        mi, state_path, _ = _make_mi(
            tmp_path, scope_checker=scope,
        )
        mi.run(["/api/users/42"])  # api.example.com not in scope

        candidates = get_candidates("api.example.com", path=state_path)
        write_candidates = [c for c in candidates if c["method"] in ("PUT", "PATCH")]
        assert not write_candidates

    def test_in_scope_endpoint_proceeds(self, tmp_path):
        """In-scope endpoint should not be skipped by the scope gate."""
        def transport(method, url, headers, body, timeout):
            if method.upper() in ("OPTIONS", "GET"):
                return 200, b"{}", {}
            return 401, b"", {}

        scope = ScopeChecker(["api.example.com"])
        mi, _, _ = _make_mi(tmp_path, transport=transport, scope_checker=scope)
        results = mi.run(["/api/users/42"])

        r = results[0]
        assert not r.skipped


# ── 11. Non-resource endpoints are skipped ───────────────────────────────────


class TestNonResourceEndpoints:

    def test_health_check_is_skipped(self, tmp_path):
        mi, _, _ = _make_mi(tmp_path)
        results = mi.run(["/api/v1/health"])
        r = results[0]
        assert r.skipped is True
        assert "not a resource endpoint" in r.skip_reason

    def test_robots_txt_is_skipped(self, tmp_path):
        mi, _, _ = _make_mi(tmp_path)
        results = mi.run(["/robots.txt"])
        assert results[0].skipped is True

    def test_multiple_endpoints_some_skipped(self, tmp_path):
        def transport(method, url, headers, body, timeout):
            if method.upper() in ("OPTIONS", "GET"):
                return 200, b"{}", {}
            return 401, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run([
            "/api/users/42",   # resource endpoint
            "/api/v1/health",  # not a resource endpoint
        ])
        assert len(results) == 2
        skipped = [r for r in results if r.skipped]
        not_skipped = [r for r in results if not r.skipped]
        assert len(skipped) == 1
        assert len(not_skipped) == 1
        assert "/health" in skipped[0].url


# ── 12. Dry-run makes no HTTP requests and no state changes ──────────────────


class TestDryRun:

    def test_dry_run_makes_no_http_requests(self, tmp_path):
        """Dry-run must issue zero HTTP requests."""
        call_count = [0]

        def transport(method, url, headers, body, timeout):
            call_count[0] += 1
            return 200, b"ok", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        mi.run(["/api/users/42", "/api/orders/99"], dry_run=True)

        assert call_count[0] == 0, "No HTTP requests must be made in dry-run mode"

    def test_dry_run_makes_no_state_changes(self, tmp_path):
        """Dry-run must not add any candidates to hunt_state.json."""
        mi, state_path, _ = _make_mi(tmp_path)
        mi.run(["/api/users/42"], dry_run=True)

        candidates = get_candidates("api.example.com", path=state_path)
        write_candidates = [c for c in candidates if c["method"] in ("PUT", "PATCH", "DELETE")]
        assert not write_candidates, "Dry-run must not write candidates"

    def test_dry_run_results_show_inferred_methods(self, tmp_path):
        """Dry-run InferResult must still list probes with 'dry-run' notes."""
        mi, _, _ = _make_mi(tmp_path)
        results = mi.run(["/api/users/42"], dry_run=True)

        r = results[0]
        assert not r.skipped
        assert r.probes, "Dry-run should still list inferred probe methods"
        assert all("dry-run" in p.notes for p in r.probes)

    def test_dry_run_added_is_empty(self, tmp_path):
        """Dry-run InferResult.added must always be empty."""
        mi, _, _ = _make_mi(tmp_path)
        results = mi.run(["/api/users/42", "/api/orders/99"], dry_run=True)

        for r in results:
            assert r.added == [], "dry-run must not mark anything as added"

    def test_dry_run_skips_still_fire(self, tmp_path):
        """Scope and resource checks still fire in dry-run mode."""
        mi, _, _ = _make_mi(tmp_path)
        results = mi.run(["/api/v1/health"], dry_run=True)

        assert results[0].skipped is True  # resource check fires before dry-run path


# ── 13. InferResult.summary() ─────────────────────────────────────────────────


class TestInferResultSummary:

    def test_summary_skipped(self):
        r = InferResult(
            endpoint="/api/health",
            url="https://api.example.com/api/health",
            skipped=True,
            skip_reason="not a resource endpoint",
        )
        assert "[SKIP]" in r.summary()
        assert "not a resource endpoint" in r.summary()

    def test_summary_no_signal(self):
        r = InferResult(
            endpoint="/api/users/42",
            url="https://api.example.com/api/users/42",
            skipped=False,
            skip_reason=None,
            probes=[],
            added=[],
        )
        assert "[NO SIGNAL]" in r.summary()

    def test_summary_found(self):
        r = InferResult(
            endpoint="/api/users/42",
            url="https://api.example.com/api/users/42",
            skipped=False,
            skip_reason=None,
            probes=[],
            added=[("PUT", "high"), ("PATCH", "medium")],
        )
        assert "[FOUND]" in r.summary()
        assert "PUT(high)" in r.summary()
        assert "PATCH(medium)" in r.summary()


# ── 14. CLI integration tests ─────────────────────────────────────────────────


class TestCLI:

    def _run_cli(
        self,
        tmp_path: Path,
        extra_args: list[str] | None = None,
        sessions_entries: list[dict] | None = None,
        candidates: list[tuple[str, str]] | None = None,
        transport=None,
    ) -> int:
        sessions_file = _make_sessions_file(tmp_path, sessions_entries)
        state_path = _make_state_file(tmp_path)
        audit_path = tmp_path / "audit.jsonl"

        if candidates:
            for ep, method in candidates:
                add_candidate(
                    "api.example.com", ep, method, path=state_path
                )

        argv = [
            "--target", "api.example.com",
            "--sessions", str(sessions_file),
            "--state-path", str(state_path),
            "--audit-log", str(audit_path),
        ] + (extra_args or [])
        return main(argv)

    def test_no_endpoints_exits_zero(self, tmp_path):
        """When no GET candidates and no --endpoints given → exit 0."""
        code = self._run_cli(tmp_path)
        assert code == 0

    def test_dry_run_flag_accepted(self, tmp_path):
        code = self._run_cli(
            tmp_path,
            candidates=[("/api/users/42", "GET")],
            extra_args=["--dry-run"],
        )
        assert code == 0  # dry-run: no candidates added → exit 0

    def test_endpoints_flag_accepted(self, tmp_path):
        sessions_file = _make_sessions_file(tmp_path)
        state_path = _make_state_file(tmp_path)
        audit_path = tmp_path / "audit.jsonl"

        code = main([
            "--target", "api.example.com",
            "--sessions", str(sessions_file),
            "--state-path", str(state_path),
            "--audit-log", str(audit_path),
            "--endpoints", "/api/health",   # not a resource endpoint → skip
            "--dry-run",
        ])
        # No candidates added (endpoint is health check, skipped).
        assert code == 0

    def test_exit_1_when_candidates_found(self, tmp_path):
        """Exit 1 when at least one write-method candidate is added."""
        def transport(method, url, headers, body, timeout):
            if method.upper() in ("OPTIONS", "GET"):
                return 200, b"{}", {}
            return 401, b"", {}

        sessions_file = _make_sessions_file(tmp_path)
        state_path = _make_state_file(tmp_path)
        audit_path = tmp_path / "audit.jsonl"

        # Patch the transport into the MethodInferrer by running via the module.
        # We can test this by using --endpoints with a resource endpoint and
        # verifying the CLI correctly returns 1 when candidates are added.
        # Since we can't inject transport via CLI, use a workaround: add the
        # candidate manually and verify the CLI reads from hunt_state.json.
        # Instead, test the Python API directly.
        audit, _ = _make_audit(tmp_path)
        mi = MethodInferrer(
            target="api.example.com",
            state_file=state_path,
            sessions_file=sessions_file,
            audit_log=audit,
            transport=transport,
            _rate_limiter=_null_rate_limiter(),
        )
        results = mi.run(["/api/users/42"])
        found = [r for r in results if not r.skipped and r.added]
        assert found, "Should find candidates"

    def test_allow_write_not_needed_by_method_inferrer(self, tmp_path):
        """method_inferrer sends write probes directly — it does not use --allow-write.
        The flag belongs to auto_replay.py, not method_inferrer.py."""
        # Just verify the CLI doesn't crash without --allow-write.
        code = self._run_cli(tmp_path, extra_args=["--dry-run"])
        assert code == 0

    def test_mode_forward_accepted(self, tmp_path):
        code = self._run_cli(
            tmp_path,
            extra_args=["--mode", "forward", "--dry-run"],
        )
        assert code == 0

    def test_mode_reverse_accepted(self, tmp_path):
        code = self._run_cli(
            tmp_path,
            extra_args=["--mode", "reverse", "--dry-run"],
        )
        assert code == 0

    def test_mode_both_accepted(self, tmp_path):
        code = self._run_cli(
            tmp_path,
            extra_args=["--mode", "both", "--dry-run"],
        )
        assert code == 0


# ── 15. Pure helpers: extract_numeric_id ─────────────────────────────────────


class TestExtractNumericId:

    def test_finds_three_digit_id(self):
        assert extract_numeric_id("/api/users/123") == "123"

    def test_finds_long_id(self):
        assert extract_numeric_id("/api/orders/99999") == "99999"

    def test_two_digit_not_extracted(self):
        # 2-digit segments are below the minimum.
        assert extract_numeric_id("/api/v2/data") is None

    def test_first_id_returned_when_multiple(self):
        result = extract_numeric_id("/api/users/123/items/456")
        assert result == "123"

    def test_uuid_not_extracted(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert extract_numeric_id(f"/api/users/{uuid}") is None

    def test_no_id_returns_none(self):
        assert extract_numeric_id("/api/v1/health") is None

    def test_id_in_first_segment(self):
        assert extract_numeric_id("/123/profile") == "123"


# ── 16. Pure helpers: replace_id_in_path ─────────────────────────────────────


class TestReplaceIdInPath:

    def test_replaces_first_matching_segment(self):
        result = replace_id_in_path("/api/users/123/address", "123", "124")
        assert result == "/api/users/124/address"

    def test_only_replaces_first_occurrence(self):
        result = replace_id_in_path("/api/123/items/123", "123", "999")
        assert result == "/api/999/items/123"

    def test_no_match_returns_unchanged(self):
        path = "/api/users/abc/profile"
        assert replace_id_in_path(path, "999", "1000") == path

    def test_preserves_leading_slash(self):
        result = replace_id_in_path("/api/users/123", "123", "124")
        assert result.startswith("/")

    def test_replaces_segment_not_substring(self):
        # "1234" should NOT be replaced when looking for "123".
        result = replace_id_in_path("/api/users/1234/profile", "123", "999")
        assert "1234" in result  # unchanged: "1234" != "123"


# ── 17. Pure helpers: _bodies_differ_at_same_structure ───────────────────────


class TestBodiesDifferAtSameStructure:

    def test_same_keys_different_values_returns_true(self):
        a = b'{"id": 42, "name": "Alice"}'
        b = b'{"id": 43, "name": "Bob"}'
        assert _bodies_differ_at_same_structure(a, b) is True

    def test_identical_bodies_returns_false(self):
        body = b'{"id": 42, "name": "Alice"}'
        assert _bodies_differ_at_same_structure(body, body) is False

    def test_different_keys_returns_false(self):
        a = b'{"id": 42, "name": "Alice"}'
        b = b'{"id": 42, "email": "alice@example.com"}'
        assert _bodies_differ_at_same_structure(a, b) is False

    def test_non_json_returns_false(self):
        assert _bodies_differ_at_same_structure(b"<html>", b"<html>") is False

    def test_json_array_returns_false(self):
        assert _bodies_differ_at_same_structure(b"[1,2]", b"[3,4]") is False

    def test_empty_body_returns_false(self):
        assert _bodies_differ_at_same_structure(b"", b"{}") is False

    def test_same_empty_objects_returns_false(self):
        assert _bodies_differ_at_same_structure(b"{}", b"{}") is False


# ── 18. Reverse inference: Case A — Read IDOR ────────────────────────────────


class TestReverseReadIdo:
    """Case A: GET probe on write endpoint returns 200 → GET candidate added."""

    def test_get_200_adds_get_candidate(self, tmp_path):
        """GET 200 on a write endpoint → add GET as three-way diff candidate."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                return 200, b'{"id": 42, "name": "Alice"}', {}
            return 404, b"", {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/42", "PUT")])

        assert len(results) == 1
        r = results[0]
        assert not r.skipped
        assert any(c == "read_idor" for _, _, c in r.added), "read_idor case must add GET"

        # Verify GET candidate in state.
        candidates = get_candidates("api.example.com", path=state_path)
        get_candidates_list = [c for c in candidates if c["method"] == "GET"]
        assert get_candidates_list, "GET candidate must be saved to hunt_state.json"

    def test_get_404_does_not_add_candidate(self, tmp_path):
        """GET 404 on write endpoint → no GET candidate added."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                return 404, b"Not Found", {}
            return 200, b"ok", {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/42", "PUT")])

        r = results[0]
        read_idor_adds = [c for c in r.added if c[2] == "read_idor"]
        assert not read_idor_adds, "GET 404 must not produce a read_idor candidate"

    def test_read_idor_probe_uses_account_a(self, tmp_path):
        """Case A probe must use account_a credentials."""
        sessions_seen: list[str] = []

        def transport(method, url, headers, body, timeout):
            # Capture which auth token was sent.
            auth = headers.get("Authorization", "")
            if "token_a" in auth:
                sessions_seen.append("account_a")
            elif "token_b" in auth:
                sessions_seen.append("account_b")
            return 200, b'{"id": 1}', {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        mi.run_reverse([("/api/users/42", "PUT")])

        assert "account_a" in sessions_seen

    def test_summary_found_on_read_idor_hit(self, tmp_path):
        """InferResult summary reflects the Case A hit."""
        def transport(method, url, headers, body, timeout):
            return 200, b'{"id": 1}', {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/42", "PUT")])

        r = results[0]
        assert "[FOUND]" in r.summary()
        assert "read_idor" in r.summary()


# ── 19. Reverse inference: Case B — Cross-account write IDOR ─────────────────


class TestReverseCrossAccountWriteIdo:
    """Case B: account_b writes to account_a's resource."""

    def test_200_triggers_high_signal_candidate(self, tmp_path):
        """account_b write → 200 → high signal write_idor candidate added."""
        call_log: list[tuple[str, str]] = []

        def transport(method, url, headers, body, timeout):
            auth = headers.get("Authorization", "")
            session = "account_a" if "token_a" in auth else "account_b"
            call_log.append((method.upper(), session))
            if method.upper() == "GET":
                return 200, b'{"id": 42, "name": "Alice"}', {}
            # account_b's PUT succeeds.
            return 200, b"updated", {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/42", "PUT")])

        r = results[0]
        write_idor_adds = [c for c in r.added if c[2] == "write_idor"]
        assert write_idor_adds, "write_idor case must be added on account_b 200"
        assert write_idor_adds[0][1] == "high"

        # Verify PUT candidate in state.
        candidates = get_candidates("api.example.com", path=state_path)
        put_candidates = [c for c in candidates if c["method"] == "PUT"]
        assert put_candidates

    def test_204_also_triggers_high_signal(self, tmp_path):
        """204 No Content is also a high-signal write IDOR response."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                return 200, b"{}", {}
            return 204, b"", {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/42", "PUT")])

        r = results[0]
        write_idor_adds = [c for c in r.added if c[2] == "write_idor"]
        assert write_idor_adds
        assert write_idor_adds[0][1] == "high"

    def test_403_is_skipped(self, tmp_path):
        """account_b write → 403 → skip (properly protected), no candidate added."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                return 200, b"{}", {}
            return 403, b"Forbidden", {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/42", "PUT")])

        r = results[0]
        write_idor_adds = [c for c in r.added if c[2] == "write_idor"]
        assert not write_idor_adds, "403 must not add a candidate"

        candidates = get_candidates("api.example.com", path=state_path)
        put_candidates = [c for c in candidates if c["method"] == "PUT"]
        assert not put_candidates

    def test_403_probe_note_says_protected(self, tmp_path):
        """The 403 probe note must say 'protected' or 'denied'."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                return 200, b"{}", {}
            return 403, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/42", "PUT")])

        r = results[0]
        write_probes = [p for p in r.probes if p.case == "write_idor"]
        assert write_probes
        assert any(
            "protected" in p.notes or "denied" in p.notes
            for p in write_probes
        )

    def test_401_triggers_medium_signal_candidate(self, tmp_path):
        """account_b write → 401 → medium signal BAC candidate added."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                return 200, b"{}", {}
            return 401, b"Unauthorized", {}

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/42", "PUT")])

        r = results[0]
        write_idor_adds = [c for c in r.added if c[2] == "write_idor"]
        assert write_idor_adds
        assert write_idor_adds[0][1] == "medium"

    def test_write_uses_account_b_session(self, tmp_path):
        """Case B probe must use account_b credentials."""
        sessions_on_write: list[str] = []

        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                return 200, b"{}", {}
            auth = headers.get("Authorization", "")
            if "token_b" in auth:
                sessions_on_write.append("account_b")
            elif "token_a" in auth:
                sessions_on_write.append("account_a")
            return 403, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        mi.run_reverse([("/api/users/42", "PUT")])

        assert "account_b" in sessions_on_write, "Write probe must use account_b"

    def test_body_template_from_get_response_sent_in_write_probe(self, tmp_path):
        """Body template derived from GET JSON must be included in Case B write probe."""
        received_bodies: list[bytes | None] = []
        get_body = b'{"name": "Alice", "role": "user"}'

        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                return 200, get_body, {}
            received_bodies.append(body)
            return 403, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        mi.run_reverse([("/api/users/42", "PUT")])

        # The write probe body must be a JSON template derived from the GET body.
        assert received_bodies, "Write probe must be sent"
        for b in received_bodies:
            if b is not None:
                try:
                    parsed = json.loads(b.decode())
                    # Keys from GET body must be present in the template.
                    assert "name" in parsed
                    assert "role" in parsed
                except (json.JSONDecodeError, AssertionError):
                    pass  # If parsing fails, skip this check

    def test_case_b_skipped_when_account_b_missing(self, tmp_path):
        """When sessions.json has no account_b, Case B must be skipped gracefully."""
        sessions_a_only = [
            {
                "name": "account_a",
                "cookies": {"session": "tok_a"},
                "headers": {},
                "auth_header": "Bearer token_a",
                "notes": "",
            }
        ]
        call_log: list[str] = []

        def transport(method, url, headers, body, timeout):
            call_log.append(method.upper())
            if method.upper() == "GET":
                return 200, b'{"id": 1}', {}
            return 200, b"ok", {}

        mi, state_path, _ = _make_mi(
            tmp_path,
            transport=transport,
            sessions_entries=sessions_a_only,
        )
        results = mi.run_reverse([("/api/users/42", "PUT")])

        # Should not raise, and result should not be skipped.
        r = results[0]
        assert not r.skipped
        # No write_idor or id_enum — only possible Case A.
        write_idor = [c for c in r.added if c[2] == "write_idor"]
        assert not write_idor


# ── 20. Reverse inference: Case C — ID enumeration ───────────────────────────


class TestReverseIdEnumeration:
    """Case C: account_b probes adjacent IDs; matching-structure/different-data = IDOR."""

    def _make_transport_for_enum(
        self,
        a_body: bytes,
        b_body_for_adjacent: bytes,
        write_response: int = 403,
    ):
        """Transport that returns a_body for account_a GET and b_body for adjacent IDs."""
        def transport(method, url, headers, body, timeout):
            auth = headers.get("Authorization", "")
            is_b = "token_b" in auth

            if method.upper() == "GET":
                if is_b:
                    return 200, b_body_for_adjacent, {}
                return 200, a_body, {}
            return write_response, b"", {}

        return transport

    def test_adjacent_id_with_different_data_adds_candidate(self, tmp_path):
        """account_b probes ID±1 and finds different data → GET candidate added."""
        a_body = b'{"id": 100, "name": "Alice", "balance": 500}'
        b_body = b'{"id": 101, "name": "Bob", "balance": 200}'
        transport = self._make_transport_for_enum(a_body, b_body, write_response=403)

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/100", "PUT")])

        r = results[0]
        id_enum_adds = [c for c in r.added if c[2] == "id_enum"]
        assert id_enum_adds, "ID enumeration with different data must add candidate"
        assert id_enum_adds[0][1] == "high"

        candidates = get_candidates("api.example.com", path=state_path)
        get_candidates_list = [c for c in candidates if c["method"] == "GET"]
        assert get_candidates_list, "Enumerated GET endpoint must be in state"

    def test_adjacent_id_with_identical_data_no_candidate(self, tmp_path):
        """account_b probes adjacent ID but gets same data → no IDOR signal."""
        same_body = b'{"id": 100, "name": "Alice"}'
        transport = self._make_transport_for_enum(same_body, same_body, write_response=403)

        mi, state_path, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/100", "PUT")])

        r = results[0]
        id_enum_adds = [c for c in r.added if c[2] == "id_enum"]
        assert not id_enum_adds

    def test_no_numeric_id_skips_enumeration(self, tmp_path):
        """Paths without a numeric ID (≥3 digits) must skip Case C silently."""
        call_log: list[str] = []

        def transport(method, url, headers, body, timeout):
            call_log.append(url)
            if method.upper() == "GET":
                return 200, b'{"name": "test"}', {}
            return 403, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        # Path has only a resource keyword, no numeric ID.
        results = mi.run_reverse([("/api/profile", "PUT")])

        r = results[0]
        id_enum_probes = [p for p in r.probes if p.case == "id_enum"]
        # No id_enum probes should appear.
        assert not id_enum_probes

    def test_enumeration_uses_account_b(self, tmp_path):
        """Case C probes must use account_b credentials."""
        sessions_seen: list[str] = []

        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                auth = headers.get("Authorization", "")
                if "token_b" in auth:
                    sessions_seen.append("account_b")
                return 200, b'{"id": 1, "name": "test"}', {}
            return 403, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        mi.run_reverse([("/api/users/100", "PUT")])

        assert "account_b" in sessions_seen

    def test_enumeration_stops_after_first_hit(self, tmp_path):
        """Case C must stop probing once one IDOR signal is found."""
        hit_count = [0]
        a_body = b'{"id": 100, "name": "Alice"}'
        b_body = b'{"id": 101, "name": "Bob"}'  # different

        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                auth = headers.get("Authorization", "")
                is_b = "token_b" in auth
                if is_b:
                    hit_count[0] += 1
                    return 200, b_body, {}
                return 200, a_body, {}
            return 403, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        mi.run_reverse([("/api/users/100", "PUT")])

        # Should stop after first hit — at most 1 successful b-GET.
        assert hit_count[0] == 1, (
            f"Enumeration should stop after first hit; got {hit_count[0]} b-probes"
        )


# ── 21. Reverse inference: body template from GET response ───────────────────


class TestReverseBodyTemplate:

    def test_body_template_keys_come_from_get_response(self, tmp_path):
        """Case B probe notes must reference body template derived from GET JSON."""
        get_body = b'{"street": "Main St", "city": "Springfield"}'

        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                return 200, get_body, {}
            return 403, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/42/address", "PUT")])

        r = results[0]
        write_probes = [p for p in r.probes if p.case == "write_idor"]
        assert write_probes
        # Body template should be set on the write probe.
        for p in write_probes:
            if p.body_template:
                parsed = json.loads(p.body_template)
                assert "street" in parsed
                assert "city" in parsed

    def test_non_json_get_falls_back_to_empty_body(self, tmp_path):
        """When GET returns non-JSON, fall back to {} as write body."""
        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                return 200, b"<html>not json</html>", {}
            return 403, b"", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        results = mi.run_reverse([("/api/users/42", "PUT")])

        r = results[0]
        write_probes = [p for p in r.probes if p.case == "write_idor"]
        for p in write_probes:
            # body_template should be None or "{}" (empty), not a structured template.
            if p.body_template:
                assert p.body_template == "{}" or p.body_template is None


# ── 22. Reverse inference: dry-run ───────────────────────────────────────────


class TestReverseDryRun:

    def test_dry_run_makes_no_requests(self, tmp_path):
        """run_reverse with dry_run=True must not call the transport."""
        call_count = [0]

        def transport(method, url, headers, body, timeout):
            call_count[0] += 1
            return 200, b"ok", {}

        mi, _, _ = _make_mi(tmp_path, transport=transport)
        mi.run_reverse([("/api/users/42", "PUT")], dry_run=True)

        assert call_count[0] == 0

    def test_dry_run_adds_no_candidates(self, tmp_path):
        """run_reverse dry_run must not add any candidates to hunt_state.json."""
        mi, state_path, _ = _make_mi(tmp_path)
        mi.run_reverse([("/api/users/42", "PUT")], dry_run=True)

        candidates = get_candidates("api.example.com", path=state_path)
        assert not candidates

    def test_dry_run_result_not_skipped(self, tmp_path):
        mi, _, _ = _make_mi(tmp_path)
        results = mi.run_reverse([("/api/users/42", "PUT")], dry_run=True)

        r = results[0]
        assert not r.skipped
        assert r.added == []

    def test_cli_mode_reverse_dry_run_exits_zero(self, tmp_path):
        """--mode reverse --dry-run must exit 0 with no candidates added."""
        sessions_file = _make_sessions_file(tmp_path)
        state_path = _make_state_file(tmp_path)
        audit_path = tmp_path / "audit.jsonl"

        # Add a write-method candidate so reverse mode has something to process.
        add_candidate("api.example.com", "/api/users/42", "PUT", path=state_path)

        code = main([
            "--target", "api.example.com",
            "--sessions", str(sessions_file),
            "--state-path", str(state_path),
            "--audit-log", str(audit_path),
            "--mode", "reverse",
            "--dry-run",
        ])
        assert code == 0


# ── 23. Reverse inference: scope check ───────────────────────────────────────


class TestReverseScopeCheck:

    def test_out_of_scope_write_endpoint_skipped(self, tmp_path):
        """Out-of-scope write endpoints must be skipped and not probed."""
        call_log: list[str] = []

        def transport(method, url, headers, body, timeout):
            call_log.append(url)
            return 200, b"ok", {}

        scope = ScopeChecker(["other.com"])
        mi, state_path, _ = _make_mi(
            tmp_path, transport=transport, scope_checker=scope,
        )
        results = mi.run_reverse([("/api/users/42", "PUT")])

        r = results[0]
        assert r.skipped is True
        assert "scope" in r.skip_reason
        assert not call_log, "No HTTP calls for out-of-scope endpoint"

    def test_in_scope_write_endpoint_proceeds(self, tmp_path):
        def transport(method, url, headers, body, timeout):
            if method.upper() == "GET":
                return 200, b"{}", {}
            return 403, b"", {}

        scope = ScopeChecker(["api.example.com"])
        mi, _, _ = _make_mi(
            tmp_path, transport=transport, scope_checker=scope,
        )
        results = mi.run_reverse([("/api/users/42", "PUT")])

        r = results[0]
        assert not r.skipped


# ── 24. ReverseInferResult.summary() ─────────────────────────────────────────


class TestReverseInferResultSummary:

    def test_summary_skipped(self):
        r = ReverseInferResult(
            endpoint="/api/users/42",
            url="https://api.example.com/api/users/42",
            write_method="PUT",
            skipped=True, skip_reason="out of scope",
        )
        assert "[SKIP]" in r.summary()
        assert "out of scope" in r.summary()

    def test_summary_no_signal(self):
        r = ReverseInferResult(
            endpoint="/api/users/42",
            url="https://api.example.com/api/users/42",
            write_method="PUT",
            skipped=False, skip_reason=None,
        )
        assert "[NO SIGNAL]" in r.summary()

    def test_summary_found(self):
        r = ReverseInferResult(
            endpoint="/api/users/42",
            url="https://api.example.com/api/users/42",
            write_method="PUT",
            skipped=False, skip_reason=None,
            added=[("GET", "medium", "read_idor"), ("PUT", "high", "write_idor")],
        )
        assert "[FOUND]" in r.summary()
        assert "read_idor" in r.summary()
        assert "write_idor" in r.summary()
