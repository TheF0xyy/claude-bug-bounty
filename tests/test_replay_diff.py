"""Unit tests for tools/replay_diff.py.

All tests use a mock transport — no real HTTP requests are made.
The transport callable signature is:
    (method, url, headers, body_bytes, timeout) -> (status, body_bytes, headers_dict)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from session_manager import NO_AUTH, SessionContext
from replay_diff import (
    DiffResult,
    RequestTemplate,
    ReplayResult,
    compare_all,
    diff_results,
    replay,
    replay_all,
)


# ---------------------------------------------------------------------------
# Mock transport helpers
# ---------------------------------------------------------------------------


def _make_transport(
    status: int = 200,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
):
    """Return a transport that always responds with the given values."""
    _headers = headers or {"content-type": "application/json"}

    def _transport(method, url, req_headers, body_bytes, timeout):
        return status, body, _headers

    return _transport


def _make_dispatch_transport(
    responses: dict[str, tuple[int, bytes, dict[str, str]]],
):
    """Return a transport that dispatches by the Authorization or Cookie header value.

    `responses` maps a header value substring to (status, body, resp_headers).
    Matched on the Authorization header first, then Cookie, then falls back
    to the "default" key if present.
    """

    def _transport(method, url, req_headers, body_bytes, timeout):
        auth = req_headers.get("Authorization", "")
        cookie = req_headers.get("Cookie", "")
        for key, resp in responses.items():
            if key != "default" and (key in auth or key in cookie):
                return resp
        return responses.get("default", (404, b"not found", {}))

    return _transport


# ---------------------------------------------------------------------------
# RequestTemplate
# ---------------------------------------------------------------------------


def test_method_is_upper_cased():
    t = RequestTemplate(method="get", url="https://example.com/")
    assert t.method == "GET"


def test_default_headers_empty():
    t = RequestTemplate(method="GET", url="https://example.com/")
    assert t.headers == {}


def test_default_body_none():
    t = RequestTemplate(method="POST", url="https://example.com/")
    assert t.body is None


# ---------------------------------------------------------------------------
# replay() — header injection verified via transport
# ---------------------------------------------------------------------------


def test_replay_passes_merged_headers_to_transport():
    """Session cookies and auth_header reach the transport."""
    received: dict = {}

    def _capturing_transport(method, url, headers, body, timeout):
        received.update(headers)
        return 200, b"ok", {}

    s = SessionContext(
        name="account_a",
        cookies={"session": "abc"},
        auth_header="Bearer tok",
    )
    t = RequestTemplate(
        method="GET",
        url="https://example.com/api/users/1",
        headers={"Accept": "application/json"},
    )
    replay(t, s, transport=_capturing_transport)

    assert received.get("Authorization") == "Bearer tok"
    assert "session=abc" in received.get("Cookie", "")
    assert received.get("Accept") == "application/json"


def test_replay_str_body_encoded_to_utf8():
    received_body: list[bytes] = []

    def _transport(method, url, headers, body, timeout):
        received_body.append(body)
        return 200, b"ok", {}

    t = RequestTemplate(method="POST", url="https://x.com/", body='{"x": 1}')
    replay(t, SessionContext(name="a"), transport=_transport)
    assert received_body[0] == b'{"x": 1}'


def test_replay_bytes_body_passed_through():
    received_body: list[bytes] = []

    def _transport(method, url, headers, body, timeout):
        received_body.append(body)
        return 200, b"ok", {}

    t = RequestTemplate(method="POST", url="https://x.com/", body=b"\x00\x01\x02")
    replay(t, SessionContext(name="a"), transport=_transport)
    assert received_body[0] == b"\x00\x01\x02"


def test_replay_none_body_passes_none():
    received_body: list = []

    def _transport(method, url, headers, body, timeout):
        received_body.append(body)
        return 200, b"", {}

    t = RequestTemplate(method="GET", url="https://x.com/")
    replay(t, SessionContext(name="a"), transport=_transport)
    assert received_body[0] is None


def test_replay_captures_status_and_body():
    transport = _make_transport(status=403, body=b"forbidden")
    t = RequestTemplate(method="GET", url="https://example.com/admin")
    r = replay(t, SessionContext(name="account_b"), transport=transport)
    assert r.status_code == 403
    assert r.body == b"forbidden"
    assert r.session_name == "account_b"
    assert r.error is None


def test_replay_captures_error_without_raising():
    def _failing_transport(method, url, headers, body, timeout):
        raise ConnectionError("timeout")

    t = RequestTemplate(method="GET", url="https://example.com/")
    r = replay(t, SessionContext(name="a"), transport=_failing_transport)
    assert r.status_code is None
    assert r.error == "timeout"
    assert r.body == b""


def test_replay_elapsed_ms_populated():
    transport = _make_transport(200, b"ok")
    t = RequestTemplate(method="GET", url="https://example.com/")
    r = replay(t, SessionContext(name="a"), transport=transport)
    assert r.elapsed_ms >= 0.0


# ---------------------------------------------------------------------------
# ReplayResult properties
# ---------------------------------------------------------------------------


def test_content_type_strips_parameters():
    r = ReplayResult(
        session_name="a",
        status_code=200,
        body=b"",
        response_headers={"content-type": "application/json; charset=utf-8"},
        elapsed_ms=0.0,
    )
    assert r.content_type == "application/json"


def test_content_type_absent_is_empty_string():
    r = ReplayResult(
        session_name="a",
        status_code=200,
        body=b"",
        response_headers={},
        elapsed_ms=0.0,
    )
    assert r.content_type == ""


def test_body_text_decodes_utf8():
    r = ReplayResult(
        session_name="a",
        status_code=200,
        body=b"hello",
        response_headers={},
        elapsed_ms=0.0,
    )
    assert r.body_text == "hello"


# ---------------------------------------------------------------------------
# replay_all() — session routing
# ---------------------------------------------------------------------------


def test_replay_all_two_sessions():
    transport = _make_dispatch_transport(
        {
            "token-a": (200, b'{"id":1}', {"content-type": "application/json"}),
            "token-b": (403, b"forbidden", {"content-type": "text/plain"}),
        }
    )
    t = RequestTemplate(method="GET", url="https://example.com/api/users/1")
    a = SessionContext(name="account_a", auth_header="Bearer token-a")
    b = SessionContext(name="account_b", auth_header="Bearer token-b")

    results = replay_all(t, a, b, transport=transport)

    assert set(results.keys()) == {"account_a", "account_b"}
    assert results["account_a"].status_code == 200
    assert results["account_b"].status_code == 403


def test_replay_all_with_no_auth():
    transport = _make_dispatch_transport(
        {
            "token-a": (200, b"data", {}),
            "token-b": (200, b"data", {}),
            "default": (401, b"unauthorized", {}),
        }
    )
    t = RequestTemplate(method="GET", url="https://example.com/api/orders/42")
    a = SessionContext(name="account_a", auth_header="Bearer token-a")
    b = SessionContext(name="account_b", auth_header="Bearer token-b")

    results = replay_all(t, a, b, no_auth=NO_AUTH, transport=transport)

    assert set(results.keys()) == {"account_a", "account_b", "no_auth"}
    assert results["no_auth"].status_code == 401


def test_replay_all_without_no_auth_excludes_it():
    transport = _make_transport(200, b"ok")
    t = RequestTemplate(method="GET", url="https://example.com/")
    a = SessionContext(name="account_a")
    b = SessionContext(name="account_b")
    results = replay_all(t, a, b, transport=transport)
    assert "no_auth" not in results


# ---------------------------------------------------------------------------
# diff_results() — core comparison logic
# ---------------------------------------------------------------------------


def _result(name: str, status: int, body: bytes, ct: str = "application/json") -> ReplayResult:
    return ReplayResult(
        session_name=name,
        status_code=status,
        body=body,
        response_headers={"content-type": ct},
        elapsed_ms=1.0,
    )


def test_diff_identical_responses_not_interesting():
    a = _result("account_a", 200, b'{"id":1}')
    b = _result("account_b", 200, b'{"id":1}')
    d = diff_results(a, b)
    assert d.status_match
    assert d.body_match
    assert d.length_delta == 0
    assert d.content_type_match
    assert not d.interesting


def test_diff_status_mismatch_is_interesting():
    a = _result("account_a", 200, b"ok")
    b = _result("account_b", 403, b"ok")
    d = diff_results(a, b)
    assert not d.status_match
    assert d.interesting


def test_diff_body_mismatch_is_interesting():
    a = _result("account_a", 200, b'{"id":1,"data":"secret"}')
    b = _result("account_b", 200, b'{"error":"forbidden"}')
    d = diff_results(a, b)
    assert not d.body_match
    assert d.interesting
    assert d.length_delta == abs(
        len(b'{"id":1,"data":"secret"}') - len(b'{"error":"forbidden"}')
    )


def test_diff_content_type_mismatch_is_interesting():
    a = _result("account_a", 200, b"ok", ct="application/json")
    b = _result("account_b", 200, b"ok", ct="text/html")
    d = diff_results(a, b)
    assert not d.content_type_match
    assert d.interesting


def test_diff_length_delta_computed_correctly():
    a = _result("account_a", 200, b"abcde")
    b = _result("account_b", 200, b"ab")
    d = diff_results(a, b)
    assert d.length_delta == 3


def test_diff_label():
    a = _result("account_a", 200, b"x")
    b = _result("account_b", 200, b"x")
    d = diff_results(a, b)
    assert d.label == "account_a vs account_b"


# ---------------------------------------------------------------------------
# DiffResult.summary()
# ---------------------------------------------------------------------------


def test_summary_identical():
    a = _result("account_a", 200, b"same")
    b = _result("account_b", 200, b"same")
    s = diff_results(a, b).summary()
    assert "identical" in s
    assert "no signal" in s
    assert "SIGNAL —" not in s


def test_summary_status_mismatch():
    a = _result("account_a", 200, b"x")
    b = _result("account_b", 403, b"x")
    s = diff_results(a, b).summary()
    assert "SIGNAL" in s
    assert "200≠403" in s


def test_summary_body_differs():
    a = _result("account_a", 200, b"abcde")
    b = _result("account_b", 200, b"xy")
    s = diff_results(a, b).summary()
    assert "SIGNAL" in s
    assert "body differs" in s
    assert "Δ3B" in s


def test_summary_content_type_differs():
    a = _result("account_a", 200, b"x", ct="application/json")
    b = _result("account_b", 200, b"x", ct="text/html")
    s = diff_results(a, b).summary()
    assert "SIGNAL" in s
    assert "content-type" in s


# ---------------------------------------------------------------------------
# compare_all() — priority order and completeness
# ---------------------------------------------------------------------------


def test_compare_all_two_sessions_one_diff():
    r = {
        "account_a": _result("account_a", 200, b"ok"),
        "account_b": _result("account_b", 403, b"forbidden"),
    }
    diffs = compare_all(r)
    assert len(diffs) == 1
    assert diffs[0].label == "account_a vs account_b"
    assert diffs[0].interesting


def test_compare_all_three_sessions_three_diffs():
    r = {
        "account_a": _result("account_a", 200, b'{"data":"secret"}'),
        "account_b": _result("account_b", 403, b"forbidden"),
        "no_auth":   _result("no_auth",   401, b"unauthorized"),
    }
    diffs = compare_all(r)
    assert len(diffs) == 3
    labels = [d.label for d in diffs]
    # Priority order
    assert labels[0] == "account_a vs account_b"
    assert labels[1] == "account_a vs no_auth"
    assert labels[2] == "account_b vs no_auth"


def test_compare_all_no_duplicates():
    r = {
        "account_a": _result("account_a", 200, b"x"),
        "account_b": _result("account_b", 200, b"x"),
        "no_auth":   _result("no_auth",   200, b"x"),
    }
    diffs = compare_all(r)
    labels = [d.label for d in diffs]
    assert len(labels) == len(set(labels))


def test_compare_all_missing_no_auth_skips_gracefully():
    r = {
        "account_a": _result("account_a", 200, b"x"),
        "account_b": _result("account_b", 200, b"x"),
    }
    diffs = compare_all(r)
    labels = [d.label for d in diffs]
    assert all("no_auth" not in lbl for lbl in labels)


# ---------------------------------------------------------------------------
# A vs B detection — end-to-end IDOR/BAC signal
# ---------------------------------------------------------------------------


def test_idor_signal_account_a_gets_data_account_b_denied():
    """account_a receives 200 with private data; account_b receives 403."""
    transport = _make_dispatch_transport(
        {
            "token-a": (200, b'{"user_id":1,"email":"a@test.com"}',
                        {"content-type": "application/json"}),
            "token-b": (403, b'{"error":"forbidden"}',
                        {"content-type": "application/json"}),
        }
    )
    t = RequestTemplate(method="GET", url="https://api.example.com/api/users/1")
    a = SessionContext(name="account_a", auth_header="Bearer token-a")
    b = SessionContext(name="account_b", auth_header="Bearer token-b")

    results = replay_all(t, a, b, transport=transport)
    diffs = compare_all(results)

    assert len(diffs) == 1
    d = diffs[0]
    assert d.interesting
    assert not d.status_match          # 200 vs 403
    assert not d.body_match
    assert "SIGNAL" in d.summary()


def test_bac_signal_both_get_200_but_different_bodies():
    """Both accounts get 200, but account_b sees account_a's private data."""
    transport = _make_dispatch_transport(
        {
            "token-a": (200, b'{"id":1,"email":"a@test.com","balance":500}',
                        {"content-type": "application/json"}),
            "token-b": (200, b'{"id":1,"email":"a@test.com","balance":500}',
                        {"content-type": "application/json"}),
        }
    )
    t = RequestTemplate(method="GET", url="https://api.example.com/api/users/1/profile")
    a = SessionContext(name="account_a", auth_header="Bearer token-a")
    b = SessionContext(name="account_b", auth_header="Bearer token-b")

    results = replay_all(t, a, b, transport=transport)
    diffs = compare_all(results)
    d = diffs[0]
    # Body identical → likely a confirmed IDOR (account_b can read account_a's data)
    assert d.status_match
    assert d.body_match
    # Not flagged as "interesting" by the differ — caller should flag this as IDOR
    # because the test intent was account_b reading account_a's resource
    assert not d.interesting


def test_same_response_all_sessions_not_interesting():
    """All three sessions get identical responses — no signal."""
    transport = _make_transport(200, b'{"public": true}',
                                {"content-type": "application/json"})
    t = RequestTemplate(method="GET", url="https://example.com/api/public")
    a = SessionContext(name="account_a", auth_header="Bearer token-a")
    b = SessionContext(name="account_b", auth_header="Bearer token-b")

    results = replay_all(t, a, b, no_auth=NO_AUTH, transport=transport)
    diffs = compare_all(results)
    assert all(not d.interesting for d in diffs)


def test_auth_bypass_no_auth_gets_200():
    """Auth-bypass: unauthenticated gets 200 on a route that should require login."""
    transport = _make_dispatch_transport(
        {
            "token-a": (200, b"data", {"content-type": "application/json"}),
            "token-b": (200, b"data", {"content-type": "application/json"}),
            "default": (200, b"data", {"content-type": "application/json"}),
        }
    )
    t = RequestTemplate(method="GET", url="https://api.example.com/api/admin/users")
    a = SessionContext(name="account_a", auth_header="Bearer token-a")
    b = SessionContext(name="account_b", auth_header="Bearer token-b")

    results = replay_all(t, a, b, no_auth=NO_AUTH, transport=transport)
    diffs = compare_all(results)

    a_vs_noauth = next(d for d in diffs if "no_auth" in d.label and "account_a" in d.label)
    # All get 200 with same body — caller must infer bypass from no_auth's 200
    assert a_vs_noauth.status_match
    assert a_vs_noauth.body_match
