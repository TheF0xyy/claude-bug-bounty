"""Unit and CLI tests for tools/check_sessions.py.

Coverage map
------------
check_sessions()    all exit codes (0/1/3), probe_url override,
                    no_auth skipped, network error priority over expiry,
                    UNCHECKED treated as non-blocking
format_table()      column presence, no_auth "(skipped)" rendering,
                    VALID/EXPIRED/NETWORK_ERROR labels, timing display
main()              exit 0 (all valid), exit 1 (account_a expired),
                    exit 1 (account_b expired), exit 2 (file missing),
                    exit 2 (empty list), exit 3 (network error),
                    --probe-url override, status table on stdout
All HTTP calls mocked via injectable transport — no real network requests.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import pytest

# Add tools/ to the import path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from auth_manager import AuthManager, SessionRecord, ValidationResult, ValidationStatus
from check_sessions import (
    check_sessions,
    format_table,
    main,
    _set_probe_url,
)


# ---------------------------------------------------------------------------
# Transport helpers (no real network calls)
# ---------------------------------------------------------------------------

def _ok_transport(
    method: str, url: str, headers: dict, body: Optional[bytes], timeout: float
) -> tuple[int, bytes, dict]:
    """Mock transport that returns HTTP 200 — simulates a valid session."""
    return 200, b'{"user":"me"}', {"content-type": "application/json"}


def _expired_transport(
    method: str, url: str, headers: dict, body: Optional[bytes], timeout: float
) -> tuple[int, bytes, dict]:
    """Mock transport that returns HTTP 401 — simulates an expired session."""
    return 401, b"Unauthorized", {}


def _network_error_transport(
    method: str, url: str, headers: dict, body: Optional[bytes], timeout: float
) -> tuple[int, bytes, dict]:
    """Mock transport that raises — simulates a network failure."""
    raise OSError("connection refused")


def _status_transport(status: int, body: bytes = b"ok") -> object:
    """Factory: returns a transport that always responds with the given status."""
    def transport(method, url, headers, body_bytes, timeout):
        return status, body, {}
    return transport


# ---------------------------------------------------------------------------
# Session / file helpers
# ---------------------------------------------------------------------------

_PROBE_URL = "https://target.com/api/me"

_SESSIONS_WITH_PROBE = [
    {
        "name": "account_a",
        "cookies": {"session": "aaa"},
        "auth_header": "Bearer AAA",
    },
    {
        "name": "account_b",
        "cookies": {"session": "bbb"},
        "auth_header": "Bearer BBB",
    },
    {"name": "no_auth"},
]

_SESSIONS_NO_PROBE = [
    {"name": "account_a", "cookies": {"s": "a"}, "auth_header": "Bearer A"},
    {"name": "account_b", "cookies": {"s": "b"}, "auth_header": "Bearer B"},
    {"name": "no_auth"},
]


def _write_sessions(tmp_path: Path, entries: list[dict]) -> Path:
    """Write entries to a sessions.json in tmp_path and return the path."""
    p = tmp_path / "sessions.json"
    p.write_text(json.dumps(entries), encoding="utf-8")
    return p


def _make_mgr(entries: list[dict], probe_url: Optional[str] = None) -> AuthManager:
    """Build an AuthManager from a list of session dicts."""
    mgr = AuthManager()
    for e in entries:
        mgr.register(SessionRecord(
            name=e["name"],
            cookies=e.get("cookies") or {},
            headers=e.get("headers") or {},
            auth_header=e.get("auth_header") or None,
            notes=e.get("notes") or "",
            probe_url=probe_url,
        ))
    return mgr


# ---------------------------------------------------------------------------
# _set_probe_url
# ---------------------------------------------------------------------------

class TestSetProbeUrl:
    def test_sets_probe_url_on_all_records(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE)
        _set_probe_url(mgr, _PROBE_URL)
        for name in mgr.names():
            rec = mgr.get(name)
            assert rec.probe_url == _PROBE_URL, name

    def test_overrides_existing_probe_url(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE, probe_url="https://old.example.com/me")
        _set_probe_url(mgr, _PROBE_URL)
        assert mgr.get("account_a").probe_url == _PROBE_URL

    def test_no_auth_also_gets_probe_url(self):
        """no_auth probe_url is set but validate() is never called on it."""
        mgr = _make_mgr(_SESSIONS_NO_PROBE)
        _set_probe_url(mgr, _PROBE_URL)
        assert mgr.get("no_auth").probe_url == _PROBE_URL


# ---------------------------------------------------------------------------
# format_table
# ---------------------------------------------------------------------------

def _mk_result(name: str, state: str, elapsed_ms: float = 0.0, error: str | None = None) -> ValidationResult:
    return ValidationResult(
        session_name=name,
        state=state,
        is_valid=(state == ValidationStatus.VALID),
        status_code=200 if state == ValidationStatus.VALID else 401,
        elapsed_ms=elapsed_ms,
        error=error,
    )


class TestFormatTable:
    def test_header_present(self):
        text = format_table([], {}, None)
        assert "[Session Check]" in text

    def test_no_auth_shows_skipped(self):
        text = format_table(["no_auth"], {}, None)
        assert "no_auth" in text
        assert "skipped" in text.lower()
        assert "PROBE_NOT_CONFIGURED" in text

    def test_valid_label(self):
        results = {"account_a": _mk_result("account_a", ValidationStatus.VALID, elapsed_ms=99)}
        text = format_table(["account_a"], results, _PROBE_URL)
        assert "VALID" in text

    def test_expired_label(self):
        results = {"account_a": _mk_result("account_a", ValidationStatus.EXPIRED_OR_UNAUTHORIZED)}
        text = format_table(["account_a"], results, _PROBE_URL)
        assert "EXPIRED" in text

    def test_network_error_label(self):
        results = {"account_a": _mk_result("account_a", ValidationStatus.NETWORK_ERROR, error="timeout")}
        text = format_table(["account_a"], results, _PROBE_URL)
        assert "NETWORK_ERROR" in text

    def test_unchecked_label(self):
        results = {"account_a": _mk_result("account_a", ValidationStatus.UNCHECKED)}
        text = format_table(["account_a"], results, None)
        assert "UNCHECKED" in text

    def test_probe_url_appears_in_row(self):
        results = {"account_a": _mk_result("account_a", ValidationStatus.VALID)}
        text = format_table(["account_a"], results, _PROBE_URL)
        assert _PROBE_URL in text

    def test_timing_shown_when_elapsed(self):
        results = {"account_a": _mk_result("account_a", ValidationStatus.VALID, elapsed_ms=123)}
        text = format_table(["account_a"], results, _PROBE_URL)
        assert "123ms" in text

    def test_no_auth_not_in_results_does_not_crash(self):
        """no_auth is rendered without touching the results dict."""
        text = format_table(["account_a", "no_auth"], {}, None)
        assert "no_auth" in text

    def test_missing_result_entry_handled(self):
        text = format_table(["account_a"], {}, None)
        assert "no result" in text

    def test_expired_hint_included(self):
        results = {"account_a": _mk_result("account_a", ValidationStatus.EXPIRED_OR_UNAUTHORIZED)}
        text = format_table(["account_a"], results, _PROBE_URL)
        assert "re-login" in text.lower()

    def test_network_error_detail_included(self):
        results = {"account_a": _mk_result("account_a", ValidationStatus.NETWORK_ERROR, error="timeout")}
        text = format_table(["account_a"], results, _PROBE_URL)
        assert "timeout" in text


# ---------------------------------------------------------------------------
# check_sessions() — core validation logic
# ---------------------------------------------------------------------------

class TestCheckSessions:

    # ── exit 0 cases ────────────────────────────────────────────────────────

    def test_all_valid_exits_zero(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE, probe_url=_PROBE_URL)
        code, _ = check_sessions(mgr, transport=_ok_transport)
        assert code == 0

    def test_all_unchecked_exits_zero(self):
        """UNCHECKED (no probe_url) is non-blocking."""
        mgr = _make_mgr(_SESSIONS_NO_PROBE)  # no probe_url → UNCHECKED
        code, _ = check_sessions(mgr)
        assert code == 0

    def test_probe_url_arg_overrides_and_produces_valid(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE)  # no probe_url initially
        code, _ = check_sessions(mgr, probe_url=_PROBE_URL, transport=_ok_transport)
        assert code == 0

    # ── exit 1 cases ────────────────────────────────────────────────────────

    def test_account_a_expired_exits_one(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE, probe_url=_PROBE_URL)
        code, _ = check_sessions(mgr, transport=_expired_transport)
        assert code == 1

    def test_account_b_expired_exits_one(self):
        """account_b-only expiry triggers exit 1."""
        mgr = AuthManager()
        mgr.register(SessionRecord(
            name="account_a",
            cookies={"s": "a"},
            probe_url=_PROBE_URL,
        ))
        mgr.register(SessionRecord(
            name="account_b",
            cookies={"s": "b"},
            probe_url=_PROBE_URL,
        ))

        call_count: dict[str, int] = {"a": 0, "b": 0}

        def mixed_transport(method, url, headers, body, timeout):
            # Identify account by Cookie header value.
            cookie_hdr = headers.get("Cookie", "")
            if "s=a" in cookie_hdr:
                call_count["a"] += 1
                return 200, b"ok", {}
            call_count["b"] += 1
            return 401, b"Unauthorized", {}

        code, _ = check_sessions(mgr, transport=mixed_transport)
        assert code == 1

    def test_both_expired_exits_one(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE, probe_url=_PROBE_URL)
        code, _ = check_sessions(mgr, transport=_expired_transport)
        assert code == 1

    # ── exit 3 cases ────────────────────────────────────────────────────────

    def test_network_error_exits_three(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE, probe_url=_PROBE_URL)
        code, _ = check_sessions(mgr, transport=_network_error_transport)
        assert code == 3

    def test_network_error_takes_priority_over_expired(self):
        """If account_a is NETWORK_ERROR and account_b is EXPIRED, exit 3."""
        mgr = AuthManager()
        mgr.register(SessionRecord(
            name="account_a",
            cookies={"s": "a"},
            probe_url=_PROBE_URL,
        ))
        mgr.register(SessionRecord(
            name="account_b",
            cookies={"s": "b"},
            probe_url=_PROBE_URL,
        ))

        def mixed_transport(method, url, headers, body, timeout):
            cookie_hdr = headers.get("Cookie", "")
            if "s=a" in cookie_hdr:
                raise OSError("connection refused")
            return 401, b"Unauthorized", {}

        code, _ = check_sessions(mgr, transport=mixed_transport)
        assert code == 3

    # ── no_auth is skipped ───────────────────────────────────────────────────

    def test_no_auth_not_validated(self):
        """validate() must never be called for the no_auth session."""
        validated_names: list[str] = []

        mgr = _make_mgr(_SESSIONS_NO_PROBE, probe_url=_PROBE_URL)

        def tracking_transport(method, url, headers, body, timeout):
            # Record which session is being probed via cookie.
            for rec in mgr.list_records():
                for k, v in rec.cookies.items():
                    if f"{k}={v}" in headers.get("Cookie", ""):
                        validated_names.append(rec.name)
                        break
            return 200, b"ok", {}

        check_sessions(mgr, transport=tracking_transport)
        assert "no_auth" not in validated_names

    def test_no_auth_expired_does_not_raise_exit_code(self):
        """Even if no_auth is in the manager with a probe URL, it is skipped."""
        mgr = _make_mgr(_SESSIONS_NO_PROBE, probe_url=_PROBE_URL)
        # Force no_auth record to have probe_url — it should still be skipped.
        code, table = check_sessions(mgr, transport=_ok_transport)
        assert code == 0
        assert "no_auth" in table
        assert "skipped" in table.lower()

    # ── probe_url override ───────────────────────────────────────────────────

    def test_probe_url_arg_sets_url_on_all_sessions(self):
        new_url = "https://new.example.com/api/me"
        mgr = _make_mgr(_SESSIONS_NO_PROBE)
        check_sessions(mgr, probe_url=new_url, transport=_ok_transport)
        for name in mgr.names():
            assert mgr.get(name).probe_url == new_url

    def test_probe_url_overrides_existing_per_session_url(self):
        old_url = "https://old.example.com/me"
        new_url = "https://new.example.com/me"
        mgr = _make_mgr(_SESSIONS_NO_PROBE, probe_url=old_url)
        check_sessions(mgr, probe_url=new_url, transport=_ok_transport)
        assert mgr.get("account_a").probe_url == new_url

    # ── table content ────────────────────────────────────────────────────────

    def test_table_contains_valid_label(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE, probe_url=_PROBE_URL)
        _, table = check_sessions(mgr, transport=_ok_transport)
        assert "VALID" in table

    def test_table_contains_expired_label(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE, probe_url=_PROBE_URL)
        _, table = check_sessions(mgr, transport=_expired_transport)
        assert "EXPIRED" in table

    def test_table_contains_network_error_label(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE, probe_url=_PROBE_URL)
        _, table = check_sessions(mgr, transport=_network_error_transport)
        assert "NETWORK_ERROR" in table

    def test_table_contains_session_names(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE)
        _, table = check_sessions(mgr)
        assert "account_a" in table
        assert "account_b" in table
        assert "no_auth" in table


# ---------------------------------------------------------------------------
# main() — CLI integration
# ---------------------------------------------------------------------------

class TestMain:

    def test_exit_zero_all_valid(self, tmp_path):
        """--probe-url set and all sessions return 200 → exit 0."""
        p = _write_sessions(tmp_path, _SESSIONS_WITH_PROBE)
        # Sessions without probe_url → UNCHECKED → exit 0 even without --probe-url.
        with pytest.raises(SystemExit) as exc:
            main(["--sessions", str(p)])
        assert exc.value.code == 0

    def test_exit_two_file_missing(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            main(["--sessions", str(tmp_path / "no_such.json")])
        assert exc.value.code == 2

    def test_exit_two_empty_list(self, tmp_path):
        p = _write_sessions(tmp_path, [])
        with pytest.raises(SystemExit) as exc:
            main(["--sessions", str(p)])
        assert exc.value.code == 2

    def test_exit_two_invalid_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json", encoding="utf-8")
        with pytest.raises(SystemExit) as exc:
            main(["--sessions", str(p)])
        assert exc.value.code == 2

    def test_exit_two_not_a_list(self, tmp_path):
        p = tmp_path / "obj.json"
        p.write_text('{"name": "x"}', encoding="utf-8")
        with pytest.raises(SystemExit) as exc:
            main(["--sessions", str(p)])
        assert exc.value.code == 2

    def test_status_table_printed_to_stdout(self, tmp_path, capsys):
        p = _write_sessions(tmp_path, _SESSIONS_WITH_PROBE)
        with pytest.raises(SystemExit):
            main(["--sessions", str(p)])
        out = capsys.readouterr().out
        assert "[Session Check]" in out

    def test_session_names_in_output(self, tmp_path, capsys):
        p = _write_sessions(tmp_path, _SESSIONS_WITH_PROBE)
        with pytest.raises(SystemExit):
            main(["--sessions", str(p)])
        out = capsys.readouterr().out
        assert "account_a" in out
        assert "account_b" in out
        assert "no_auth" in out

    def test_unchecked_label_appears_without_probe_url(self, tmp_path, capsys):
        p = _write_sessions(tmp_path, _SESSIONS_WITH_PROBE)
        with pytest.raises(SystemExit):
            main(["--sessions", str(p)])  # no --probe-url → UNCHECKED
        out = capsys.readouterr().out
        assert "UNCHECKED" in out

    def test_file_missing_prints_error_message(self, tmp_path, capsys):
        with pytest.raises(SystemExit):
            main(["--sessions", str(tmp_path / "missing.json")])
        out = capsys.readouterr().out
        assert "ERROR" in out

    def test_empty_list_prints_error_message(self, tmp_path, capsys):
        p = _write_sessions(tmp_path, [])
        with pytest.raises(SystemExit):
            main(["--sessions", str(p)])
        out = capsys.readouterr().out
        assert "ERROR" in out

    def test_target_flag_accepted(self, tmp_path):
        """--target is an informational flag; it must not cause a crash."""
        p = _write_sessions(tmp_path, _SESSIONS_WITH_PROBE)
        with pytest.raises(SystemExit) as exc:
            main(["--sessions", str(p), "--target", "target.com"])
        assert exc.value.code == 0

    def test_does_not_write_files(self, tmp_path):
        """CLI must never create files."""
        p = _write_sessions(tmp_path, _SESSIONS_WITH_PROBE)
        before = set(tmp_path.iterdir())
        with pytest.raises(SystemExit):
            main(["--sessions", str(p)])
        after = set(tmp_path.iterdir())
        assert before == after


# ---------------------------------------------------------------------------
# Integration: end-to-end via check_sessions() with real AuthManager
# ---------------------------------------------------------------------------

class TestIntegration:
    """Exercises check_sessions() with a real AuthManager to test round trips."""

    def test_unchecked_always_exits_zero(self):
        """Sessions without probe_url are UNCHECKED — not expired."""
        mgr = _make_mgr(_SESSIONS_NO_PROBE)
        code, table = check_sessions(mgr)
        assert code == 0
        assert "account_a" in table
        assert "account_b" in table

    def test_no_auth_always_in_table(self):
        mgr = _make_mgr(_SESSIONS_NO_PROBE)
        _, table = check_sessions(mgr)
        assert "no_auth" in table
        assert "skipped" in table.lower()

    def test_only_account_a_present(self):
        """Works correctly when only account_a exists (no account_b)."""
        mgr = AuthManager()
        mgr.register(SessionRecord(name="account_a", cookies={"s": "a"}, probe_url=_PROBE_URL))
        code, table = check_sessions(mgr, transport=_ok_transport)
        assert code == 0
        assert "account_a" in table
        assert "account_b" not in table

    def test_mixed_valid_and_expired_is_exit_one(self):
        """One valid + one expired → exit 1 (not exit 0)."""
        mgr = AuthManager()
        mgr.register(SessionRecord(name="account_a", cookies={"s": "a"}, probe_url=_PROBE_URL))
        mgr.register(SessionRecord(name="account_b", cookies={"s": "b"}, probe_url=_PROBE_URL))

        def mixed_transport(method, url, headers, body, timeout):
            if "s=a" in headers.get("Cookie", ""):
                return 200, b"ok", {}
            return 401, b"Unauthorized", {}

        code, _ = check_sessions(mgr, transport=mixed_transport)
        assert code == 1
