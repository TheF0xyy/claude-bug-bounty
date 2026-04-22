"""Unit tests for tools/auth_manager.py.

All tests are pure — no real HTTP requests.  The injectable TransportFn
pattern is used throughout (same pattern as test_replay_diff.py).

Coverage map
------------
SessionRecord            construction, defaults, captured_at, new heuristic fields
AuthManager.register     happy path, duplicate rejection, replace=True
AuthManager.get          happy path, unknown name, copy isolation
AuthManager.list_records all records, copy isolation
ValidationStatus         all five state constants distinguishable
ValidationResult         state field, is_valid, is_expired, is_unchecked
AuthManager.validate     valid / 401 / 403 / unexpected / no-probe / network
_classify_probe          200+login body, 302 redirect, content match/mismatch,
                         combined heuristics, probe_status_ok=302 edge case
auto_detect_login        login keyword, clean body, JSON auth error, disabled,
                         probe_contains override, all LOGIN_BODY_INDICATORS,
                         all JSON_AUTH_INDICATORS, field defaults & export
AuthManager.validate_all all sessions, independent results
export_sessions          names filter, valid_only, management fields absent
export_sessions_json     legacy alias
export_valid_only        legacy alias
load_from_sessions_json  round-trip, unchecked, error cases
Account isolation        no bleed between records; no accidental overwrite
build_headers compat     Cookie + Authorization ownership respected in probe
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from auth_manager import (
    AuthManager,
    SessionRecord,
    ValidationResult,
    ValidationStatus,
    DETECTION_THRESHOLD,
    LOGIN_BODY_INDICATORS,
    JSON_AUTH_INDICATORS,
    EXTENDED_BODY_INDICATORS,
    _normalize_text,
    _indicator_in_text,
    _is_json_body,
)


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------

def _transport(status: int = 200, body: bytes = b"", headers: dict | None = None):
    """Always respond with the given values."""
    _h = headers or {}

    def _t(method, url, req_headers, body_bytes, timeout):
        return status, body, _h

    return _t


def _capturing_transport():
    """Record every request's headers; always respond 200."""
    received: list[dict] = []

    def _t(method, url, req_headers, body_bytes, timeout):
        received.append(dict(req_headers))
        return 200, b"ok", {}

    return _t, received


def _failing_transport(exc_type=ConnectionError, msg="simulated network failure"):
    def _t(method, url, req_headers, body_bytes, timeout):
        raise exc_type(msg)
    return _t


# ---------------------------------------------------------------------------
# SessionRecord — construction and defaults
# ---------------------------------------------------------------------------

def test_session_record_minimal():
    r = SessionRecord(name="account_a")
    assert r.name == "account_a"


def test_session_record_defaults():
    r = SessionRecord(name="account_a")
    assert r.cookies == {}
    assert r.headers == {}
    assert r.auth_header is None
    assert r.notes == ""
    assert r.probe_url is None
    assert r.probe_status_ok == 200
    assert r.probe_method == "GET"


def test_session_record_captured_at_auto_set():
    r = SessionRecord(name="account_a")
    assert r.captured_at.endswith("Z")
    assert "T" in r.captured_at


def test_session_record_full_construction():
    r = SessionRecord(
        name="account_b",
        cookies={"session": "tok-b"},
        headers={"X-Extra": "val"},
        auth_header="Bearer jwt-b",
        notes="user B",
        probe_url="https://api.target.com/api/me",
        probe_status_ok=204,
        probe_method="POST",
        captured_at="2026-01-01T00:00:00Z",
    )
    assert r.name == "account_b"
    assert r.cookies == {"session": "tok-b"}
    assert r.auth_header == "Bearer jwt-b"
    assert r.probe_url == "https://api.target.com/api/me"
    assert r.probe_status_ok == 204
    assert r.probe_method == "POST"
    assert r.captured_at == "2026-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# AuthManager — register + get
# ---------------------------------------------------------------------------

def test_register_and_get():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", notes="user A"))
    got = mgr.get("account_a")
    assert got.name == "account_a"
    assert got.notes == "user A"


def test_register_duplicate_raises():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    with pytest.raises(ValueError, match="already registered"):
        mgr.register(SessionRecord(name="account_a"))


def test_register_replace_overwrites():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", notes="old"))
    mgr.register(SessionRecord(name="account_a", notes="new"), replace=True)
    assert mgr.get("account_a").notes == "new"


def test_get_unknown_raises():
    mgr = AuthManager()
    with pytest.raises(KeyError, match="account_a"):
        mgr.get("account_a")


def test_names_returns_insertion_order():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    mgr.register(SessionRecord(name="account_b"))
    assert mgr.names() == ["account_a", "account_b"]


# ---------------------------------------------------------------------------
# AuthManager — list_records
# ---------------------------------------------------------------------------

def test_list_records_returns_all():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", notes="A"))
    mgr.register(SessionRecord(name="account_b", notes="B"))
    records = mgr.list_records()
    assert len(records) == 2
    assert {r.name for r in records} == {"account_a", "account_b"}


def test_list_records_returns_copies():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", cookies={"s": "tok"}))
    records = mgr.list_records()
    records[0].cookies["s"] = "TAMPERED"
    assert mgr.get("account_a").cookies["s"] == "tok"


def test_list_records_empty_manager():
    assert AuthManager().list_records() == []


# ---------------------------------------------------------------------------
# Account isolation — deep-copy on register and get
# ---------------------------------------------------------------------------

def test_register_deepcopies_record():
    r = SessionRecord(name="account_a", cookies={"session": "original"})
    mgr = AuthManager()
    mgr.register(r)
    r.cookies["session"] = "MUTATED"
    assert mgr.get("account_a").cookies["session"] == "original"


def test_get_returns_copy():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", cookies={"session": "tok"}))
    c1 = mgr.get("account_a")
    c1.cookies["session"] = "TAMPERED"
    assert mgr.get("account_a").cookies["session"] == "tok"


def test_account_a_b_independent():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", auth_header="Bearer A"))
    mgr.register(SessionRecord(name="account_b", auth_header="Bearer B"))
    mgr.register(SessionRecord(name="account_b", notes="updated"), replace=True)
    assert mgr.get("account_a").auth_header == "Bearer A"


def test_no_accidental_credential_overwrite_without_replace():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", auth_header="Bearer original"))
    try:
        mgr.register(SessionRecord(name="account_a", auth_header="Bearer intruder"))
    except ValueError:
        pass
    assert mgr.get("account_a").auth_header == "Bearer original"


# ---------------------------------------------------------------------------
# ValidationStatus constants
# ---------------------------------------------------------------------------

def test_validation_status_constants_are_distinct():
    statuses = [
        ValidationStatus.VALID,
        ValidationStatus.EXPIRED_OR_UNAUTHORIZED,
        ValidationStatus.UNCHECKED,
        ValidationStatus.NETWORK_ERROR,
        ValidationStatus.UNEXPECTED_RESPONSE,
    ]
    assert len(set(statuses)) == 5


def test_validation_status_are_strings():
    assert isinstance(ValidationStatus.VALID, str)
    assert isinstance(ValidationStatus.EXPIRED_OR_UNAUTHORIZED, str)
    assert isinstance(ValidationStatus.UNCHECKED, str)
    assert isinstance(ValidationStatus.NETWORK_ERROR, str)
    assert isinstance(ValidationStatus.UNEXPECTED_RESPONSE, str)


# ---------------------------------------------------------------------------
# validate / validate_one — valid session (state == VALID)
# ---------------------------------------------------------------------------

def test_validate_valid_200():
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        cookies={"session": "tok-a"},
        probe_url="https://api.target.com/api/me",
    ))
    r = mgr.validate("account_a", transport=_transport(200))
    assert r.state == ValidationStatus.VALID
    assert r.is_valid is True
    assert r.status_code == 200
    assert r.error is None
    assert not r.is_expired
    assert not r.is_unchecked


def test_validate_valid_custom_status_ok():
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
        probe_status_ok=204,
    ))
    r = mgr.validate("account_a", transport=_transport(204))
    assert r.state == ValidationStatus.VALID
    assert r.is_valid is True


def test_validate_one_alias_works():
    """validate_one is an alias for validate — must produce identical results."""
    mgr = AuthManager()
    mgr.register(SessionRecord(name="a", probe_url="https://x.com/"))
    r1 = mgr.validate("a", transport=_transport(200))
    r2 = mgr.validate_one("a", transport=_transport(200))
    assert r1.state == r2.state
    assert r1.is_valid == r2.is_valid


# ---------------------------------------------------------------------------
# validate — expired (state == EXPIRED_OR_UNAUTHORIZED)
# ---------------------------------------------------------------------------

def test_validate_expired_401():
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
    ))
    r = mgr.validate("account_a", transport=_transport(401))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
    assert r.is_valid is False
    assert r.status_code == 401
    assert r.is_expired is True


def test_validate_expired_403():
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
    ))
    r = mgr.validate("account_a", transport=_transport(403))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
    assert r.is_valid is False
    assert r.status_code == 403
    assert r.is_expired is True


# ---------------------------------------------------------------------------
# validate — unexpected response (state == UNEXPECTED_RESPONSE)
# ---------------------------------------------------------------------------

def test_validate_unexpected_500():
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
    ))
    r = mgr.validate("account_a", transport=_transport(500))
    assert r.state == ValidationStatus.UNEXPECTED_RESPONSE
    assert r.is_valid is False
    assert r.is_expired is False
    assert r.status_code == 500


def test_validate_unexpected_302():
    """302 redirect (when probe_status_ok=200) → EXPIRED_OR_UNAUTHORIZED.

    302 used to be classified as UNEXPECTED_RESPONSE.  After the heuristic
    upgrade, any 3xx that doesn't match probe_status_ok is treated as a
    credential-rejection redirect (e.g. session expired → redirect to /login).
    """
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
    ))
    r = mgr.validate("account_a", transport=_transport(302))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_validate_unexpected_404():
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
    ))
    r = mgr.validate("account_a", transport=_transport(404))
    assert r.state == ValidationStatus.UNEXPECTED_RESPONSE


# ---------------------------------------------------------------------------
# validate — unchecked (state == UNCHECKED)
# ---------------------------------------------------------------------------

def test_validate_no_probe_url():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    r = mgr.validate("account_a", transport=_transport(200))
    assert r.state == ValidationStatus.UNCHECKED
    assert r.is_valid is False
    assert r.status_code is None
    assert r.is_unchecked is True
    assert "no probe_url" in r.error


def test_validate_unchecked_is_not_expired():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    r = mgr.validate("account_a")
    assert r.is_expired is False


def test_validate_unchecked_elapsed_zero():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    r = mgr.validate("account_a")
    assert r.elapsed_ms == 0.0


# ---------------------------------------------------------------------------
# validate — network error (state == NETWORK_ERROR)
# ---------------------------------------------------------------------------

def test_validate_network_error():
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
    ))
    r = mgr.validate("account_a", transport=_failing_transport())
    assert r.state == ValidationStatus.NETWORK_ERROR
    assert r.is_valid is False
    assert r.status_code is None
    assert "network failure" in r.error
    assert r.is_expired is False
    assert r.is_unchecked is False


def test_validate_network_error_elapsed_set():
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
    ))
    r = mgr.validate("account_a", transport=_failing_transport())
    assert r.elapsed_ms >= 0.0


def test_validate_timeout_captured():
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
    ))
    r = mgr.validate("account_a",
                     transport=_failing_transport(TimeoutError, "timed out"))
    assert r.state == ValidationStatus.NETWORK_ERROR
    assert "timed out" in r.error


# ---------------------------------------------------------------------------
# validate — probe sends correct credentials (build_headers ownership)
# ---------------------------------------------------------------------------

def test_probe_sends_session_cookies():
    t, received = _capturing_transport()
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        cookies={"session": "tok-a", "csrf": "csrf-a"},
        probe_url="https://api.target.com/api/me",
    ))
    mgr.validate("account_a", transport=t)
    assert len(received) == 1
    assert "session=tok-a" in received[0].get("Cookie", "")
    assert "csrf=csrf-a" in received[0].get("Cookie", "")


def test_probe_sends_auth_header():
    t, received = _capturing_transport()
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        auth_header="Bearer probe-jwt",
        probe_url="https://api.target.com/api/me",
    ))
    mgr.validate("account_a", transport=t)
    assert received[0].get("Authorization") == "Bearer probe-jwt"


def test_probe_auth_header_wins_over_headers_key():
    """auth_header must win over any Authorization in session.headers."""
    t, received = _capturing_transport()
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        headers={"Authorization": "Basic stale"},
        auth_header="Bearer fresh",
        probe_url="https://api.target.com/api/me",
    ))
    mgr.validate("account_a", transport=t)
    assert received[0].get("Authorization") == "Bearer fresh"


def test_probe_no_auth_sends_no_credentials():
    """A session with no cookies/auth must send no credential headers."""
    t, received = _capturing_transport()
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="no_auth",
        probe_url="https://api.target.com/api/me",
    ))
    mgr.validate("no_auth", transport=t)
    assert "Cookie" not in received[0]
    assert "Authorization" not in received[0]


# ---------------------------------------------------------------------------
# Account isolation in probes — no credential bleed
# ---------------------------------------------------------------------------

def test_probe_does_not_bleed_credentials_between_accounts():
    received_by: dict[str, list[dict]] = {"account_a": [], "account_b": []}

    def _dispatch(method, url, req_headers, body, timeout):
        cookie = req_headers.get("Cookie", "")
        if "tok-a" in cookie:
            received_by["account_a"].append(dict(req_headers))
        elif "tok-b" in cookie:
            received_by["account_b"].append(dict(req_headers))
        return 200, b"ok", {}

    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", cookies={"session": "tok-a"},
                                probe_url="https://x.com/"))
    mgr.register(SessionRecord(name="account_b", cookies={"session": "tok-b"},
                                probe_url="https://x.com/"))
    mgr.validate_all(transport=_dispatch)

    assert len(received_by["account_a"]) == 1
    assert len(received_by["account_b"]) == 1
    assert "tok-b" not in received_by["account_a"][0].get("Cookie", "")
    assert "tok-a" not in received_by["account_b"][0].get("Cookie", "")


# ---------------------------------------------------------------------------
# validate_all
# ---------------------------------------------------------------------------

def test_validate_all_returns_all_names():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", probe_url="https://x.com/"))
    mgr.register(SessionRecord(name="account_b", probe_url="https://x.com/"))
    results = mgr.validate_all(transport=_transport(200))
    assert set(results.keys()) == {"account_a", "account_b"}


def test_validate_all_independent_per_session():
    def _dispatch(method, url, req_headers, body, timeout):
        cookie = req_headers.get("Cookie", "")
        if "tok-a" in cookie:
            return 200, b"", {}
        if "tok-b" in cookie:
            return 401, b"", {}
        return 200, b"", {}

    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", cookies={"session": "tok-a"},
                                probe_url="https://x.com/"))
    mgr.register(SessionRecord(name="account_b", cookies={"session": "tok-b"},
                                probe_url="https://x.com/"))
    results = mgr.validate_all(transport=_dispatch)
    assert results["account_a"].state == ValidationStatus.VALID
    assert results["account_b"].state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


# ---------------------------------------------------------------------------
# export_sessions — unified method
# ---------------------------------------------------------------------------

def test_export_sessions_all_by_default():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", notes="A"))
    mgr.register(SessionRecord(name="account_b", notes="B"))
    entries = mgr.export_sessions()
    assert len(entries) == 2
    assert [e["name"] for e in entries] == ["account_a", "account_b"]


def test_export_sessions_names_filter():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    mgr.register(SessionRecord(name="account_b"))
    mgr.register(SessionRecord(name="no_auth"))
    entries = mgr.export_sessions(names=["account_a", "no_auth"])
    assert [e["name"] for e in entries] == ["account_a", "no_auth"]


def test_export_sessions_names_filter_respects_order():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    mgr.register(SessionRecord(name="account_b"))
    entries = mgr.export_sessions(names=["account_b", "account_a"])
    assert [e["name"] for e in entries] == ["account_b", "account_a"]


def test_export_sessions_names_filter_skips_unknown():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    entries = mgr.export_sessions(names=["account_a", "nonexistent"])
    assert [e["name"] for e in entries] == ["account_a"]


def test_export_sessions_valid_only_true():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", probe_url="https://x.com/",
                                cookies={"s": "tok-a"}))
    mgr.register(SessionRecord(name="account_b", probe_url="https://x.com/",
                                cookies={"s": "tok-b"}))

    def _dispatch(method, url, req_headers, body, timeout):
        return (200, b"", {}) if "tok-a" in req_headers.get("Cookie", "") else (401, b"", {})

    results = mgr.validate_all(transport=_dispatch)
    entries = mgr.export_sessions(valid_only=True, validation_results=results)
    assert [e["name"] for e in entries] == ["account_a"]


def test_export_sessions_valid_only_requires_results():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    with pytest.raises(ValueError, match="validation_results is required"):
        mgr.export_sessions(valid_only=True)


def test_export_sessions_valid_only_false_ignores_results():
    """valid_only=False should not require validation_results."""
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    entries = mgr.export_sessions(valid_only=False)
    assert entries[0]["name"] == "account_a"


def test_export_sessions_omits_management_fields():
    """probe_url, probe_status_ok, probe_method, captured_at must not appear."""
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
        probe_status_ok=200,
        probe_method="GET",
    ))
    entry = mgr.export_sessions()[0]
    assert "probe_url" not in entry
    assert "probe_status_ok" not in entry
    assert "probe_method" not in entry
    assert "captured_at" not in entry


def test_export_sessions_includes_cookies():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", cookies={"session": "tok"}))
    assert mgr.export_sessions()[0]["cookies"] == {"session": "tok"}


def test_export_sessions_includes_auth_header():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", auth_header="Bearer jwt"))
    assert mgr.export_sessions()[0]["auth_header"] == "Bearer jwt"


def test_export_sessions_includes_notes():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", notes="victim"))
    assert mgr.export_sessions()[0]["notes"] == "victim"


def test_export_sessions_omits_empty_cookies():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="no_auth"))
    assert "cookies" not in mgr.export_sessions()[0]


def test_export_sessions_omits_empty_headers():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    assert "headers" not in mgr.export_sessions()[0]


def test_export_sessions_is_json_serialisable():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", cookies={"s": "tok"},
                                auth_header="Bearer jwt", notes="note"))
    mgr.register(SessionRecord(name="account_b"))
    payload = json.dumps(mgr.export_sessions())
    reloaded = json.loads(payload)
    assert len(reloaded) == 2


# ---------------------------------------------------------------------------
# Legacy aliases still work
# ---------------------------------------------------------------------------

def test_export_sessions_json_alias():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))
    assert mgr.export_sessions_json() == mgr.export_sessions()


def test_export_valid_only_alias():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a", probe_url="https://x.com/"))
    results = mgr.validate_all(transport=_transport(200))
    assert mgr.export_valid_only(results) == mgr.export_sessions(
        valid_only=True, validation_results=results
    )


# ---------------------------------------------------------------------------
# load_from_sessions_json
# ---------------------------------------------------------------------------

def test_load_from_sessions_json(tmp_path):
    data = [
        {"name": "account_a", "cookies": {"session": "tok-a"},
         "auth_header": "Bearer jwt-a", "notes": "user A"},
        {"name": "account_b", "cookies": {"session": "tok-b"}},
        {"name": "no_auth"},
    ]
    p = tmp_path / "sessions.json"
    p.write_text(json.dumps(data), encoding="utf-8")

    mgr = AuthManager.load_from_sessions_json(p)
    assert set(mgr.names()) == {"account_a", "account_b", "no_auth"}
    a = mgr.get("account_a")
    assert a.cookies == {"session": "tok-a"}
    assert a.auth_header == "Bearer jwt-a"
    assert a.probe_url is None


def test_load_sessions_are_unchecked(tmp_path):
    p = tmp_path / "sessions.json"
    p.write_text(json.dumps([{"name": "account_a"}]), encoding="utf-8")
    mgr = AuthManager.load_from_sessions_json(p)
    r = mgr.validate("account_a")
    assert r.state == ValidationStatus.UNCHECKED
    assert r.is_unchecked is True


def test_load_file_not_found():
    with pytest.raises(FileNotFoundError):
        AuthManager.load_from_sessions_json(Path("/no/such/sessions.json"))


def test_load_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        AuthManager.load_from_sessions_json(p)


def test_load_not_a_list(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"name": "account_a"}), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON array"):
        AuthManager.load_from_sessions_json(p)


def test_load_entry_missing_name(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps([{"cookies": {"x": "y"}}]), encoding="utf-8")
    with pytest.raises(ValueError, match="'name'"):
        AuthManager.load_from_sessions_json(p)


# ---------------------------------------------------------------------------
# Round-trip: load → add probe URLs → validate → export → reload
# ---------------------------------------------------------------------------

def test_round_trip_load_validate_export(tmp_path):
    original = [
        {"name": "account_a", "cookies": {"session": "tok-a"}, "notes": "user A"},
        {"name": "account_b", "cookies": {"session": "tok-b"}},
    ]
    p = tmp_path / "sessions.json"
    p.write_text(json.dumps(original), encoding="utf-8")

    mgr = AuthManager.load_from_sessions_json(p)

    for name in ("account_a", "account_b"):
        rec = mgr.get(name)
        rec.probe_url = "https://api.target.com/api/me"
        mgr.register(rec, replace=True)

    def _dispatch(method, url, req_headers, body, timeout):
        cookie = req_headers.get("Cookie", "")
        return (200, b"", {}) if "tok-a" in cookie else (401, b"", {})

    results = mgr.validate_all(transport=_dispatch)
    assert results["account_a"].state == ValidationStatus.VALID
    assert results["account_b"].state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED

    valid = mgr.export_sessions(valid_only=True, validation_results=results)
    out = tmp_path / "sessions_valid.json"
    out.write_text(json.dumps(valid, indent=2), encoding="utf-8")

    mgr2 = AuthManager.load_from_sessions_json(out)
    assert mgr2.names() == ["account_a"]
    assert mgr2.get("account_a").cookies == {"session": "tok-a"}
    assert mgr2.get("account_a").notes == "user A"


# ---------------------------------------------------------------------------
# Body heuristics and redirect classification (_classify_probe / validate)
# ---------------------------------------------------------------------------
# All these tests inject a mock transport — follow_redirects does not affect
# which transport is selected when a mock is provided, but the classification
# logic (_classify_probe) is always exercised.
# ---------------------------------------------------------------------------

def _mk(probe_url="https://api.target.com/api/me", **kwargs) -> SessionRecord:
    """Shorthand: build a SessionRecord with a probe_url."""
    return SessionRecord(name="account_a", probe_url=probe_url, **kwargs)


# ── 302 / 3xx redirect → EXPIRED_OR_UNAUTHORIZED ─────────────────────────────

def test_validate_302_redirect_expired():
    """302 from probe (when not following redirects) → EXPIRED_OR_UNAUTHORIZED."""
    mgr = AuthManager()
    mgr.register(_mk(follow_redirects=False))
    r = mgr.validate("account_a", transport=_transport(302))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
    assert r.is_expired is True
    assert r.status_code == 302


def test_validate_303_redirect_expired():
    """303 See Other (login page redirect) → EXPIRED_OR_UNAUTHORIZED."""
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(303))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_validate_307_redirect_expired():
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(307))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_validate_301_redirect_expired():
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(301))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_validate_redirect_when_probe_status_ok_is_302():
    """If probe_status_ok=302 AND we receive 302 → VALID (intentional redirect check)."""
    mgr = AuthManager()
    mgr.register(_mk(probe_status_ok=302))
    r = mgr.validate("account_a", transport=_transport(302))
    assert r.state == ValidationStatus.VALID


# ── probe_not_contains: 200 + login page body → EXPIRED_OR_UNAUTHORIZED ───────

def test_validate_200_login_page_body_expired():
    """200 response containing login-page marker → EXPIRED_OR_UNAUTHORIZED."""
    body = b"<html><body>Please Sign in to continue</body></html>"
    mgr = AuthManager()
    mgr.register(_mk(probe_not_contains="Sign in"))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
    assert r.status_code == 200
    assert r.is_expired is True


def test_validate_200_login_form_action_expired():
    """Login form action in body triggers EXPIRED_OR_UNAUTHORIZED."""
    body = b'<form action="/login" method="post">'
    mgr = AuthManager()
    mgr.register(_mk(probe_not_contains='action="/login"'))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_validate_200_valid_body_probe_not_contains_not_triggered():
    """200 with normal API body → probe_not_contains does NOT fire → VALID."""
    body = b'{"user_id": 42, "email": "test@example.com"}'
    mgr = AuthManager()
    mgr.register(_mk(probe_not_contains="Sign in"))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


# ── probe_contains: body must include expected string ─────────────────────────

def test_validate_200_correct_content_valid():
    """200 + probe_contains found in body → VALID."""
    body = b'{"user_id": 42, "role": "admin"}'
    mgr = AuthManager()
    mgr.register(_mk(probe_contains='"user_id"'))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


def test_validate_200_wrong_content_unexpected():
    """200 but probe_contains NOT found in body → UNEXPECTED_RESPONSE."""
    body = b'{"error": "not found"}'
    mgr = AuthManager()
    mgr.register(_mk(probe_contains='"user_id"'))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.UNEXPECTED_RESPONSE
    assert r.is_valid is False
    assert r.is_expired is False


def test_validate_200_empty_body_probe_contains_fails():
    """Empty body with probe_contains set → UNEXPECTED_RESPONSE."""
    mgr = AuthManager()
    mgr.register(_mk(probe_contains='"user_id"'))
    r = mgr.validate("account_a", transport=_transport(200, body=b""))
    assert r.state == ValidationStatus.UNEXPECTED_RESPONSE


# ── combined probe_contains + probe_not_contains ──────────────────────────────

def test_validate_both_checks_pass():
    """Both probe_contains found and probe_not_contains absent → VALID."""
    body = b'{"user_id": 42, "email": "a@b.com"}'
    mgr = AuthManager()
    mgr.register(_mk(
        probe_contains='"user_id"',
        probe_not_contains="Sign in",
    ))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


def test_validate_probe_not_contains_wins_over_contains():
    """probe_not_contains takes priority: if body has login marker, expire even
    if probe_contains is also satisfied."""
    # Pathological body: contains both expected content AND login marker
    body = b'{"user_id": 42} Please Sign in'
    mgr = AuthManager()
    mgr.register(_mk(
        probe_contains='"user_id"',
        probe_not_contains="Sign in",
    ))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    # probe_not_contains is checked first → EXPIRED
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


# ── no heuristic fields → status-code-only (backward compat) ─────────────────

def test_validate_no_heuristics_200_still_valid():
    """No probe_contains or probe_not_contains → plain status-code validation."""
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(200, body=b"anything"))
    assert r.state == ValidationStatus.VALID


def test_validate_no_heuristics_401_still_expired():
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(401, body=b"Unauthorized"))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


# ── SessionRecord new field defaults ──────────────────────────────────────────

def test_session_record_probe_contains_default_none():
    assert SessionRecord(name="x").probe_contains is None


def test_session_record_probe_not_contains_default_none():
    assert SessionRecord(name="x").probe_not_contains is None


def test_session_record_follow_redirects_default_true():
    assert SessionRecord(name="x").follow_redirects is True


def test_session_record_follow_redirects_can_be_false():
    r = SessionRecord(name="x", follow_redirects=False)
    assert r.follow_redirects is False


# ── export does NOT include new probe heuristic fields ────────────────────────

def test_export_omits_probe_heuristic_fields():
    """probe_contains, probe_not_contains, follow_redirects must not appear
    in export — they are internal validation config, not replay config."""
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
        probe_contains='"user_id"',
        probe_not_contains="Sign in",
        follow_redirects=False,
    ))
    entry = mgr.export_sessions()[0]
    assert "probe_contains" not in entry
    assert "probe_not_contains" not in entry
    assert "follow_redirects" not in entry


# ---------------------------------------------------------------------------
# auto_detect_login heuristics
# ---------------------------------------------------------------------------
# auto_detect_login=False by default — tests explicitly enable it unless
# testing the disabled case.
# ---------------------------------------------------------------------------

def _mk_auto(probe_url="https://api.target.com/api/me", **kwargs) -> SessionRecord:
    """Shorthand: SessionRecord with probe_url + auto_detect_login=True."""
    return SessionRecord(name="account_a", probe_url=probe_url,
                         auto_detect_login=True, **kwargs)


# ── LOGIN_BODY_INDICATORS coverage ───────────────────────────────────────────

def test_auto_detect_login_keyword_expired():
    """Body containing 'login' → EXPIRED_OR_UNAUTHORIZED."""
    body = b"<html>Please login to continue</html>"
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_auto_detect_sign_in_keyword_expired():
    """Body containing 'sign in' (case-insensitive) → EXPIRED_OR_UNAUTHORIZED."""
    body = b"<title>Sign In - Acme Corp</title>"
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_auto_detect_password_keyword_expired():
    body = b'<input type="password" name="pass">'
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_auto_detect_auth_keyword_alone_below_threshold():
    """'auth' has weight 1 < default threshold 2 → VALID on its own.

    This is the key difference from boolean detection: a single weak indicator
    no longer causes a false positive.
    """
    body = b"Authentication required. Please re-auth."
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


def test_auto_detect_session_expired_keyword_expired():
    body = b"Your session expired. Please sign in again."
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_auto_detect_indicators_case_insensitive():
    """LOGIN keyword in uppercase → still detected."""
    body = b"<H1>LOGIN</H1>"
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_auto_detect_strong_login_indicators_trigger_alone():
    """Every indicator with weight >= DETECTION_THRESHOLD fires on its own."""
    mgr = AuthManager()
    mgr.register(_mk_auto())
    strong = {k: w for k, w in LOGIN_BODY_INDICATORS.items()
              if w >= DETECTION_THRESHOLD}
    assert strong, "No strong login indicators found — update test"
    for indicator, weight in strong.items():
        body = indicator.encode()
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED, (
            f"Strong indicator {indicator!r} (weight={weight}) did not trigger"
        )


def test_auto_detect_weak_login_indicators_alone_do_not_trigger():
    """Every indicator with weight < DETECTION_THRESHOLD alone → VALID."""
    mgr = AuthManager()
    mgr.register(_mk_auto())
    weak = {k: w for k, w in LOGIN_BODY_INDICATORS.items()
            if w < DETECTION_THRESHOLD}
    assert weak, "No weak login indicators found — update test"
    for indicator, weight in weak.items():
        body = indicator.encode()
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.VALID, (
            f"Weak indicator {indicator!r} (weight={weight}) caused false positive"
        )


# ── JSON_AUTH_INDICATORS coverage ─────────────────────────────────────────────

def test_auto_detect_json_unauthorized_expired():
    """JSON body with 'unauthorized' key → EXPIRED_OR_UNAUTHORIZED."""
    body = b'{"unauthorized": true, "message": "token invalid"}'
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_auto_detect_json_not_authenticated_expired():
    """JSON body with 'not authenticated' value → EXPIRED_OR_UNAUTHORIZED."""
    body = b'{"message": "not authenticated"}'
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_auto_detect_json_error_key_alone_below_threshold():
    """JSON '"error"' key has weight 1 < threshold 2 → VALID on its own.

    '"error"' is a weak JSON indicator that only contributes when combined
    with other signals (e.g. "auth" in the value string).
    """
    body = b'{"error": "something_went_wrong"}'
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


def test_auto_detect_json_error_key_not_triggered_in_non_json():
    """'error' word in plain HTML must not trigger JSON indicator path."""
    # "error" appears as a word, but it's not wrapped in quotes as a JSON key
    body = b"<p>There was an error processing your request</p>"
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    # "auth" in "Authentication" in body? No. Plain body has no LOGIN indicators.
    # So we expect VALID — the JSON indicators must not fire on non-JSON.
    # (This body contains no LOGIN_BODY_INDICATOR match either.)
    assert r.state == ValidationStatus.VALID


def test_auto_detect_json_error_key_not_matched_by_errors_key():
    """'errors' key must NOT match the '"error"' indicator (note plural/quotes)."""
    body = b'{"errors": [], "count": 0}'
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


def test_auto_detect_strong_json_indicators_trigger_alone():
    """Every JSON indicator with weight >= DETECTION_THRESHOLD fires on its own."""
    mgr = AuthManager()
    mgr.register(_mk_auto())
    strong = {k: w for k, w in JSON_AUTH_INDICATORS.items()
              if w >= DETECTION_THRESHOLD}
    assert strong, "No strong JSON indicators found — update test"
    for indicator, weight in strong.items():
        body = f'{{ {indicator}: true }}'.encode()
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED, (
            f"Strong JSON indicator {indicator!r} (weight={weight}) did not trigger"
        )


def test_auto_detect_weak_json_indicators_alone_do_not_trigger():
    """Every JSON indicator with weight < DETECTION_THRESHOLD alone → VALID."""
    mgr = AuthManager()
    mgr.register(_mk_auto())
    weak = {k: w for k, w in JSON_AUTH_INDICATORS.items()
            if w < DETECTION_THRESHOLD}
    assert weak, "No weak JSON indicators found — update test"
    for indicator, weight in weak.items():
        body = f'{{ {indicator}: "something" }}'.encode()
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.VALID, (
            f"Weak JSON indicator {indicator!r} (weight={weight}) caused false positive"
        )


# ── clean body → VALID ────────────────────────────────────────────────────────

def test_auto_detect_clean_api_response_valid():
    """Normal API JSON body with no auth indicators → VALID."""
    body = b'{"user_id": 42, "email": "test@example.com", "role": "user"}'
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


def test_auto_detect_empty_json_object_valid():
    body = b"{}"
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


# ── auto_detect_login=False (default) → no effect ─────────────────────────────

def test_auto_detect_disabled_by_default():
    """auto_detect_login defaults to False — login keyword in body → VALID."""
    body = b"<html>Please login</html>"
    mgr = AuthManager()
    mgr.register(_mk())   # auto_detect_login NOT set → defaults to False
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


def test_auto_detect_explicitly_false_no_effect():
    body = b'{"error": "session_invalid"}'
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        probe_url="https://api.target.com/api/me",
        auto_detect_login=False,
    ))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


# ── probe_contains overrides auto-detection ───────────────────────────────────

def test_auto_detect_probe_contains_match_overrides_auto():
    """probe_contains set AND found → VALID even if auto-detection would fire."""
    # Body has a login indicator AND the probe_contains needle
    body = b'{"user_id": 42, "last_login": "2024-01-01"}'
    mgr = AuthManager()
    mgr.register(_mk_auto(probe_contains='"user_id"'))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    # probe_contains matches → VALID, auto-detection skipped
    assert r.state == ValidationStatus.VALID


def test_auto_detect_probe_contains_no_match_gives_unexpected():
    """probe_contains set but NOT found → UNEXPECTED_RESPONSE (auto skipped)."""
    body = b'{"error": "session_invalid"}'
    mgr = AuthManager()
    mgr.register(_mk_auto(probe_contains='"user_id"'))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    # probe_contains missing → UNEXPECTED_RESPONSE, not EXPIRED
    assert r.state == ValidationStatus.UNEXPECTED_RESPONSE


def test_auto_detect_probe_not_contains_still_fires_before_auto():
    """probe_not_contains check runs before auto-detection."""
    body = b'{"user_id": 42}'   # no auto-detect trigger, but has our marker
    mgr = AuthManager()
    mgr.register(_mk_auto(probe_not_contains='"user_id"'))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


# ── SessionRecord field defaults ──────────────────────────────────────────────

def test_auto_detect_login_field_default_false():
    assert SessionRecord(name="x").auto_detect_login is False


def test_auto_detect_login_can_be_enabled():
    r = SessionRecord(name="x", auto_detect_login=True)
    assert r.auto_detect_login is True


# ── export does NOT include auto_detect_login ─────────────────────────────────

def test_export_omits_auto_detect_login():
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        auto_detect_login=True,
        probe_url="https://api.target.com/api/me",
    ))
    entry = mgr.export_sessions()[0]
    assert "auto_detect_login" not in entry


# ---------------------------------------------------------------------------
# Weighted scoring — the new precision tests
# ---------------------------------------------------------------------------

def test_scoring_single_weak_indicator_below_threshold():
    """'auth' alone scores 1 < threshold 2 → VALID (no false positive)."""
    body = b"OAuth2 flow initiated for this resource."
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


def test_scoring_strong_indicator_exceeds_threshold():
    """'session expired' scores 3 ≥ threshold 2 → EXPIRED."""
    body = b"Your session expired. Please sign in again to continue."
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_scoring_combined_weak_indicators_meet_threshold():
    """'auth'(1) from body + '"error"'(1) from JSON key = 2 ≥ threshold 2 → EXPIRED.

    Two weak signals together cross the threshold.  This is the main advantage
    over boolean detection: individual weak indicators don't fire, but their
    combination does.
    """
    body = b'{"error": "auth token invalid"}'
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_scoring_json_strong_indicator_unauthorized():
    """'"unauthorized"' scores 3 ≥ threshold 2 → EXPIRED."""
    body = b'{"unauthorized": true, "message": "token rejected"}'
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_scoring_medium_indicator_login_exactly_at_threshold():
    """'login' scores exactly 2 == threshold 2 → EXPIRED (>= comparison)."""
    body = b"Redirected to the login page."
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_scoring_threshold_one_allows_weak_indicator():
    """Custom threshold=1 lets 'auth' alone (score=1) trigger expiry."""
    body = b"Please auth now."   # "auth" is a standalone token → score=1
    mgr = AuthManager()
    mgr.register(_mk_auto(auto_detect_threshold=1))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_scoring_threshold_three_blocks_medium_indicator():
    """Custom threshold=3 means 'login'(2) alone does NOT trigger expiry."""
    body = b"Redirected to the login page."
    mgr = AuthManager()
    mgr.register(_mk_auto(auto_detect_threshold=3))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID


def test_scoring_threshold_three_allows_strong_indicator():
    """Custom threshold=3: 'session expired'(3) still fires at threshold=3."""
    body = b"Your session expired. Please log in."
    mgr = AuthManager()
    mgr.register(_mk_auto(auto_detect_threshold=3))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_scoring_cumulative_multiple_matches():
    """Multiple indicators in one body accumulate scores correctly."""
    # "login"(2) + "password"(2) = 4 ≥ threshold 2 → EXPIRED
    body = b'<form><input type="password"><button>Login</button></form>'
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


# ── SessionRecord new field defaults ──────────────────────────────────────────

def test_auto_detect_threshold_default_is_detection_threshold():
    assert SessionRecord(name="x").auto_detect_threshold == DETECTION_THRESHOLD


def test_auto_detect_threshold_can_be_overridden():
    r = SessionRecord(name="x", auto_detect_threshold=1)
    assert r.auto_detect_threshold == 1


def test_export_omits_auto_detect_threshold():
    """auto_detect_threshold is internal config — must not appear in export."""
    mgr = AuthManager()
    mgr.register(SessionRecord(
        name="account_a",
        auto_detect_login=True,
        auto_detect_threshold=1,
        probe_url="https://api.target.com/api/me",
    ))
    entry = mgr.export_sessions()[0]
    assert "auto_detect_threshold" not in entry


# ---------------------------------------------------------------------------
# Explainability — reason, matched_indicators, score
# ---------------------------------------------------------------------------
# Every decision path must populate the three debug fields correctly.
# ---------------------------------------------------------------------------

# ── reason = "status_code" ───────────────────────────────────────────────────

def test_reason_status_code_for_valid_200():
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(200))
    assert r.reason == "status_code"
    assert r.matched_indicators == []
    assert r.score is None


def test_reason_status_code_for_401():
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(401))
    assert r.reason == "status_code"
    assert r.matched_indicators == []
    assert r.score is None


def test_reason_status_code_for_403():
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(403))
    assert r.reason == "status_code"


def test_reason_status_code_for_302_redirect():
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(302))
    assert r.reason == "status_code"
    assert r.matched_indicators == []


def test_reason_status_code_for_500_unexpected():
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(500))
    assert r.reason == "status_code"


# ── reason = "no_probe_url" ───────────────────────────────────────────────────

def test_reason_no_probe_url_for_unchecked():
    mgr = AuthManager()
    mgr.register(SessionRecord(name="account_a"))  # no probe_url
    r = mgr.validate("account_a")
    assert r.reason == "no_probe_url"
    assert r.matched_indicators == []
    assert r.score is None


# ── reason = None for network error ──────────────────────────────────────────

def test_reason_none_for_network_error():
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_failing_transport())
    assert r.reason is None
    assert r.matched_indicators == []
    assert r.score is None


# ── reason = "probe_not_contains" ────────────────────────────────────────────

def test_reason_probe_not_contains_when_triggered():
    body = b"<title>Sign In</title>"
    mgr = AuthManager()
    mgr.register(_mk(probe_not_contains="Sign In"))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.reason == "probe_not_contains"
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_matched_indicators_probe_not_contains():
    """matched_indicators contains exactly the probe_not_contains string."""
    marker = "Please log in"
    body = f"<p>{marker}</p>".encode()
    mgr = AuthManager()
    mgr.register(_mk(probe_not_contains=marker))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.matched_indicators == [marker]
    assert r.score is None


# ── reason = "probe_contains" ────────────────────────────────────────────────

def test_reason_probe_contains_when_found():
    body = b'{"user_id": 42}'
    mgr = AuthManager()
    mgr.register(_mk(probe_contains='"user_id"'))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.reason == "probe_contains"
    assert r.state == ValidationStatus.VALID


def test_matched_indicators_probe_contains_success():
    """On success, matched_indicators contains the probe_contains string."""
    needle = '"user_id"'
    body = f'{{ {needle}: 42 }}'.encode()
    mgr = AuthManager()
    mgr.register(_mk(probe_contains=needle))
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.matched_indicators == [needle]


def test_reason_probe_contains_when_missing():
    """probe_contains not found → UNEXPECTED, reason still 'probe_contains'."""
    mgr = AuthManager()
    mgr.register(_mk(probe_contains='"user_id"'))
    r = mgr.validate("account_a", transport=_transport(200, body=b"{}"))
    assert r.reason == "probe_contains"
    assert r.state == ValidationStatus.UNEXPECTED_RESPONSE
    assert r.matched_indicators == []


# ── reason = "auto_detect_login" ─────────────────────────────────────────────

def test_reason_auto_detect_login_when_triggered():
    body = b"Please login to continue."
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.reason == "auto_detect_login"
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


def test_matched_indicators_auto_detect_single():
    """'login' matches → matched_indicators = ['login']."""
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=b"login page"))
    assert r.matched_indicators == ["login"]
    assert r.score == 2


def test_matched_indicators_auto_detect_multiple():
    """'auth'(1) + '"error"' from JSON(1) = score 2; both appear in list."""
    body = b'{"error": "auth token invalid"}'
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
    assert "auth" in r.matched_indicators
    assert '"error"' in r.matched_indicators
    assert r.score == 2


def test_score_is_computed_score_on_auto_detect():
    """score reflects total weight when auto_detect fires."""
    body = b"session expired"     # weight 3
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.reason == "auto_detect_login"
    assert r.score == 3
    assert r.matched_indicators == ["session expired"]


def test_score_none_when_auto_detect_does_not_fire():
    """score=None when auto_detect is enabled but score < threshold (VALID)."""
    body = b'{"user_id": 42}'   # no indicators
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID
    assert r.reason == "status_code"
    assert r.score is None


def test_score_none_for_status_based_401():
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(401))
    assert r.score is None


def test_reason_status_code_when_auto_detect_enabled_but_below_threshold():
    """Auto-detect enabled, score < threshold → reason is 'status_code' not 'auto_detect_login'."""
    body = b"OAuth2 flow"   # no standalone "auth" token → score 0 < threshold 2
    mgr = AuthManager()
    mgr.register(_mk_auto())
    r = mgr.validate("account_a", transport=_transport(200, body=body))
    assert r.state == ValidationStatus.VALID
    assert r.reason == "status_code"
    assert r.score is None


def test_matched_indicators_empty_list_by_default():
    """When no content check runs, matched_indicators is an empty list."""
    mgr = AuthManager()
    mgr.register(_mk())
    r = mgr.validate("account_a", transport=_transport(200))
    assert r.matched_indicators == []
    assert isinstance(r.matched_indicators, list)


# ===========================================================================
# Phase A — word-boundary matching (_normalize_text / _indicator_in_text)
# ===========================================================================

class TestNormalizeText:
    def test_lowercases(self):
        assert _normalize_text("LOGIN") == "login"

    def test_replaces_punctuation_with_spaces(self):
        assert _normalize_text("sign-in!") == "sign in"

    def test_collapses_multiple_spaces(self):
        assert _normalize_text("a   b") == "a b"

    def test_html_tags_become_spaces(self):
        result = _normalize_text("<H1>Login</H1>")
        # "<", "1", ">" are removed; "h" stays; → "h login h"
        assert "login" in result.split()

    def test_json_braces_become_spaces(self):
        result = _normalize_text('{"error": "auth required"}')
        tokens = result.split()
        assert "error" in tokens
        assert "auth" in tokens
        assert "required" in tokens

    def test_unicode_alpha_preserved(self):
        # Accented / non-ASCII alphabetic characters must survive normalization.
        result = _normalize_text("Giriş")
        assert result == "giriş"

    def test_digits_removed(self):
        # "oauth2" → "oauth" because "2" is not alpha.
        result = _normalize_text("oauth2 flow")
        assert "oauth" in result.split()
        assert "2" not in result


class TestIndicatorInText:
    """Tests for the word-boundary helper used by auto-detection."""

    # ── substring-collision prevention ──────────────────────────────────────

    def test_login_does_not_match_inside_blogging(self):
        """Phase A spec: 'login' must NOT match inside 'blogging'."""
        norm = _normalize_text("This is a blogging platform.")
        assert not _indicator_in_text(norm, "login")

    def test_authenticate_does_not_trigger_auth(self):
        """'authenticate' is a single token; 'auth' is a different token."""
        norm = _normalize_text("Please authenticate yourself.")
        assert not _indicator_in_text(norm, "auth")

    def test_authorization_does_not_trigger_auth(self):
        """Phase A spec: 'authorization' alone must NOT trigger 'auth' standalone."""
        norm = _normalize_text("Authorization: Bearer abc123")
        assert not _indicator_in_text(norm, "auth")

    # ── standalone token matching ────────────────────────────────────────────

    def test_login_matches_standalone(self):
        norm = _normalize_text("Please login to continue.")
        assert _indicator_in_text(norm, "login")

    def test_auth_matches_as_standalone_token(self):
        """Phase A spec: 'auth' as its own token must trigger."""
        norm = _normalize_text("auth required")
        assert _indicator_in_text(norm, "auth")

    def test_auth_standalone_at_start(self):
        norm = _normalize_text("auth: session expired")
        assert _indicator_in_text(norm, "auth")

    # ── multi-word phrase matching ───────────────────────────────────────────

    def test_sign_in_phrase_matches(self):
        """Phase A spec: multi-word 'sign in' must match after normalization."""
        norm = _normalize_text("Please sign in to continue.")
        assert _indicator_in_text(norm, "sign in")

    def test_session_expired_phrase_matches(self):
        norm = _normalize_text("Your session expired. Please log in.")
        assert _indicator_in_text(norm, "session expired")

    def test_sign_in_with_punctuation_matches(self):
        """Punctuation around phrase should not break matching."""
        norm = _normalize_text("<title>Sign-In | Acme Corp</title>")
        assert _indicator_in_text(norm, "sign in")

    def test_mot_de_passe_phrase_matches(self):
        """French multi-word indicator works through normalization."""
        norm = _normalize_text("Votre mot de passe est incorrect.")
        assert _indicator_in_text(norm, "mot de passe")


# ===========================================================================
# Phase A — end-to-end word-boundary via validate()
# ===========================================================================

class TestWordBoundaryEndToEnd:
    """Integration: word-boundary matching surfaced through AuthManager.validate."""

    def test_blogging_body_does_not_trigger_login_indicator(self):
        """'login' must NOT appear in 'blogging'."""
        body = b"This is a blogging platform about travel."
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.VALID

    def test_authorization_header_text_does_not_trigger_auth(self):
        """'Authorization: Bearer …' contains 'authorization' not 'auth' token."""
        body = b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.VALID

    def test_login_required_string_triggers(self):
        """'login required' — 'login' is a standalone token → EXPIRED."""
        body = b"login required"
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED

    def test_re_auth_hyphenated_still_triggers_auth_token(self):
        """'re-auth' normalizes to 're auth'; 'auth' is a standalone token."""
        body = b"Session timed out. Please re-auth."
        mgr = AuthManager()
        mgr.register(_mk_auto(auto_detect_threshold=1))
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


# ===========================================================================
# Phase B — multilingual indicators (language_profile)
# ===========================================================================

class TestExtendedBodyIndicators:
    """EXTENDED_BODY_INDICATORS must be non-empty, weighted, word-boundary matched."""

    def test_extended_indicators_is_dict(self):
        assert isinstance(EXTENDED_BODY_INDICATORS, dict)

    def test_extended_indicators_have_positive_weights(self):
        for key, weight in EXTENDED_BODY_INDICATORS.items():
            assert isinstance(weight, int) and weight > 0, key


class TestLanguageProfileField:
    def test_default_language_profile(self):
        rec = SessionRecord(name="a", cookies={}, headers={})
        assert rec.language_profile == "default"

    def test_extended_language_profile(self):
        rec = SessionRecord(name="a", cookies={}, headers={}, language_profile="extended")
        assert rec.language_profile == "extended"

    def test_language_profile_not_in_export(self):
        mgr = AuthManager()
        mgr.register(SessionRecord(
            name="a", cookies={"s": "1"}, headers={}, language_profile="extended"
        ))
        export = mgr.export_sessions()
        # export_sessions returns a list[dict]; find the entry for "a"
        entry = next(e for e in export if e["name"] == "a")
        assert "language_profile" not in entry


class TestMultilingualEndToEnd:
    """Turkish / German / French indicators fire with extended profile."""

    def _run(self, body: bytes, profile: str = "extended") -> str:
        mgr = AuthManager()
        rec = _mk_auto()
        # patch language_profile via replacement (dataclass is mutable)
        from dataclasses import replace as dc_replace
        rec2 = dc_replace(rec, language_profile=profile)
        mgr.register(rec2)
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        return r.state

    def test_turkish_giris_triggers_with_extended(self):
        assert self._run(b"Giri\xc5\x9f yap\xc4\xb1n\xc4\xb1z.") == ValidationStatus.EXPIRED_OR_UNAUTHORIZED

    def test_turkish_sifre_triggers_with_extended(self):
        assert self._run("şifre gerekli".encode()) == ValidationStatus.EXPIRED_OR_UNAUTHORIZED

    def test_german_anmelden_triggers_with_extended(self):
        assert self._run(b"Bitte anmelden Sie sich ein.") == ValidationStatus.EXPIRED_OR_UNAUTHORIZED

    def test_french_connexion_triggers_with_extended(self):
        assert self._run(b"Page de connexion.") == ValidationStatus.EXPIRED_OR_UNAUTHORIZED

    def test_french_mot_de_passe_phrase_triggers_with_extended(self):
        assert self._run("Votre mot de passe a expiré.".encode()) == ValidationStatus.EXPIRED_OR_UNAUTHORIZED

    def test_same_body_does_not_trigger_with_default_profile(self):
        """Turkish body must NOT fire when language_profile='default'."""
        body = "Giriş yapınız.".encode()
        assert self._run(body, profile="default") == ValidationStatus.VALID

    def test_german_body_does_not_trigger_with_default_profile(self):
        body = b"Bitte anmelden Sie sich ein."
        assert self._run(body, profile="default") == ValidationStatus.VALID


# ===========================================================================
# Phase C — JSON detection (Content-Type header + body-prefix fallback)
# ===========================================================================

class TestIsJsonBody:
    def test_content_type_application_json_forces_json_mode(self):
        assert _is_json_body("not json at all", "application/json") is True

    def test_content_type_json_variant_forces_json_mode(self):
        assert _is_json_body("plaintext", "application/vnd.api+json") is True

    def test_body_prefix_brace_still_works_without_content_type(self):
        assert _is_json_body('{"key": "val"}', "") is True

    def test_body_prefix_bracket_still_works_without_content_type(self):
        assert _is_json_body('[1, 2, 3]', "") is True

    def test_html_body_without_content_type_is_not_json(self):
        assert _is_json_body("<html>login</html>", "") is False

    def test_content_type_text_html_body_prefix_still_fires(self):
        """text/html with a '{' body still uses fallback prefix heuristic.

        The spec only uses Content-Type to *enable* JSON mode — it does not
        use it to disable the body-prefix fallback.  So a JSON-shaped body
        under text/html is still treated as JSON (the body hint wins).
        """
        assert _is_json_body('{"x":1}', "text/html") is True


class TestContentTypeJsonDetectionE2E:
    """Validate that content-type JSON detection works through AuthManager."""

    def test_content_type_json_triggers_json_auth_indicators(self):
        """JSON content-type must activate JSON indicator set even on odd body."""
        body = b'forbidden'   # raw word, no braces
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate(
            "account_a",
            transport=_transport(200, body=body, headers={"content-type": "application/json"}),
        )
        # '"forbidden"' is a JSON indicator — but body is not JSON-like without CT header.
        # With CT header forcing JSON mode → '"forbidden"' not in 'forbidden' because
        # quotes are required for JSON_AUTH_INDICATORS. So this tests that CT header
        # alone does NOT break things when the body lacks the exact quoted form.
        assert r.state == ValidationStatus.VALID   # '"forbidden"' ≠ 'forbidden'

    def test_content_type_json_activates_json_mode_for_quoted_indicator(self):
        """Content-Type forces JSON mode; '"forbidden"' indicator fires on matching body."""
        body = b'"forbidden": true'   # has the quoted form
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate(
            "account_a",
            transport=_transport(200, body=body, headers={"content-type": "application/json"}),
        )
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
        assert r.content_mode == "json"

    def test_json_body_prefix_fallback_without_content_type(self):
        """Body starting with '{' still activates JSON mode when CT absent."""
        body = b'{"error": "not authenticated"}'
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
        assert r.content_mode == "json"


# ===========================================================================
# Phase D — new stronger JSON indicators ('"forbidden"', '"authentication"')
# ===========================================================================

class TestNewJsonAuthIndicators:
    def test_forbidden_key_triggers_expired(self):
        body = b'{"forbidden": true, "resource": "/admin"}'
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
        assert '"forbidden"' in r.matched_indicators

    def test_authentication_key_triggers_expired(self):
        body = b'{"authentication": false}'
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
        assert '"authentication"' in r.matched_indicators

    def test_forbidden_key_is_in_json_auth_indicators(self):
        assert '"forbidden"' in JSON_AUTH_INDICATORS
        assert JSON_AUTH_INDICATORS['"forbidden"'] >= 2

    def test_authentication_key_is_in_json_auth_indicators(self):
        assert '"authentication"' in JSON_AUTH_INDICATORS
        assert JSON_AUTH_INDICATORS['"authentication"'] >= 2

    def test_error_alone_below_threshold_still_valid(self):
        """Phase D: '"error"' alone (weight=1) must remain below threshold=2."""
        body = b'{"error": "something went wrong"}'
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.VALID

    def test_error_plus_auth_token_meets_threshold(self):
        """'"error"'(1) + "auth" token(1) = 2 → EXPIRED."""
        body = b'{"error": "auth token invalid"}'
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED


# ===========================================================================
# Phase E — explainability: matched_profile and content_mode
# ===========================================================================

class TestMatchedProfile:
    def test_matched_profile_none_when_auto_detect_not_triggered(self):
        """No auto_detect → matched_profile is None."""
        mgr = AuthManager()
        mgr.register(_mk())
        r = mgr.validate("account_a", transport=_transport(200))
        assert r.matched_profile is None

    def test_matched_profile_none_when_score_below_threshold(self):
        """auto_detect enabled but score < threshold → matched_profile is None."""
        body = b"clean API response body"
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.VALID
        assert r.matched_profile is None

    def test_matched_profile_default_when_default_profile_fires(self):
        """Score reaches threshold using English indicators → 'default'."""
        body = b"Please login to continue."
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
        assert r.matched_profile == "default"

    def test_matched_profile_extended_when_extended_profile_fires(self):
        """Score reaches threshold using extended (Turkish) indicator → 'extended'."""
        from dataclasses import replace as dc_replace
        body = "Giriş yapınız.".encode()   # Turkish login page
        mgr = AuthManager()
        rec = dc_replace(_mk_auto(), language_profile="extended")
        mgr.register(rec)
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
        assert r.matched_profile == "extended"

    def test_matched_profile_none_for_status_based_401(self):
        mgr = AuthManager()
        mgr.register(_mk())
        r = mgr.validate("account_a", transport=_transport(401))
        assert r.matched_profile is None


class TestContentMode:
    def test_content_mode_none_for_status_based_paths(self):
        """No body analysis on 401 → content_mode is None."""
        mgr = AuthManager()
        mgr.register(_mk())
        r = mgr.validate("account_a", transport=_transport(401))
        assert r.content_mode is None

    def test_content_mode_none_for_unchecked(self):
        mgr = AuthManager()
        mgr.register(SessionRecord(name="account_a", cookies={}, headers={}))
        r = mgr.validate("account_a")
        assert r.content_mode is None

    def test_content_mode_text_for_html_body(self):
        """HTML body with no JSON content-type → content_mode='text'."""
        body = b"<html>Please login</html>"
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.content_mode == "text"

    def test_content_mode_json_when_content_type_header_present(self):
        """Content-Type: application/json → content_mode='json'."""
        body = b'{"authentication": false}'
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate(
            "account_a",
            transport=_transport(200, body=body, headers={"content-type": "application/json"}),
        )
        assert r.content_mode == "json"

    def test_content_mode_json_for_json_prefix_body(self):
        """Body starting with '{' → content_mode='json' even without CT header."""
        body = b'{"error": "unauthorized"}'
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.content_mode == "json"

    def test_content_mode_populated_even_when_score_below_threshold(self):
        """content_mode is set from _classify_probe before auto-detect score check."""
        body = b"clean JSON body"
        mgr = AuthManager()
        mgr.register(_mk_auto())
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.VALID
        assert r.content_mode == "text"

    def test_content_mode_populated_for_probe_contains_path(self):
        from dataclasses import replace as dc_replace
        body = b"dashboard loaded"
        mgr = AuthManager()
        rec = dc_replace(_mk(), probe_url="http://t/me", probe_contains="dashboard")
        mgr.register(rec)
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.content_mode == "text"   # no JSON signals

    def test_content_mode_populated_for_probe_not_contains_path(self):
        from dataclasses import replace as dc_replace
        body = b"<title>Login</title>"
        mgr = AuthManager()
        rec = dc_replace(_mk(), probe_url="http://t/me", probe_not_contains="Login")
        mgr.register(rec)
        r = mgr.validate("account_a", transport=_transport(200, body=body))
        assert r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED
        assert r.content_mode == "text"
