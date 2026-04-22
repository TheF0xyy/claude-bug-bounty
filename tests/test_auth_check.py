"""Unit and CLI tests for tools/auth_check.py.

Coverage map
------------
load_sessions_into_auth_manager   happy path, file not found, bad JSON
evaluate_results                  all ValidationStatus states, no_auth exemption,
                                  blocked / not-blocked, timing display,
                                  network error formatting, multiple sessions
main()                            --skip-auth-check, missing file, valid/expired
                                  output format, exit codes
No real HTTP requests — all transport calls use injected mock or sessions
without probe_url (UNCHECKED path).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from auth_check import (
    load_sessions_into_auth_manager,
    evaluate_results,
    main,
)
from auth_manager import AuthManager, SessionRecord, ValidationResult, ValidationStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mk_result(
    name: str,
    state: str,
    elapsed_ms: float = 0.0,
    error: str | None = None,
    status_code: int | None = None,
) -> ValidationResult:
    """Build a ValidationResult for testing without needing an HTTP call."""
    return ValidationResult(
        session_name=name,
        state=state,
        is_valid=(state == ValidationStatus.VALID),
        status_code=status_code,
        elapsed_ms=elapsed_ms,
        error=error,
    )


def _write_sessions(tmp_path: Path, entries: list[dict]) -> Path:
    """Write a sessions.json file to a temp dir and return its path."""
    p = tmp_path / "sessions.json"
    p.write_text(json.dumps(entries), encoding="utf-8")
    return p


_MINIMAL_SESSIONS = [
    {"name": "account_a", "cookies": {"s": "a1"}, "auth_header": "Bearer AAA"},
    {"name": "account_b", "cookies": {"s": "b1"}, "auth_header": "Bearer BBB"},
    {"name": "no_auth"},
]


# ---------------------------------------------------------------------------
# load_sessions_into_auth_manager
# ---------------------------------------------------------------------------

class TestLoadSessionsIntoAuthManager:
    def test_loads_account_a_and_b(self, tmp_path):
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        mgr = load_sessions_into_auth_manager(p)
        assert "account_a" in mgr.names()
        assert "account_b" in mgr.names()
        assert "no_auth" in mgr.names()

    def test_returns_auth_manager_instance(self, tmp_path):
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        mgr = load_sessions_into_auth_manager(p)
        assert isinstance(mgr, AuthManager)

    def test_sessions_are_unchecked_without_probe_url(self, tmp_path):
        """Sessions.json carries no probe_url → all sessions are UNCHECKED."""
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        mgr = load_sessions_into_auth_manager(p)
        results = mgr.validate_all()
        for name, r in results.items():
            assert r.state == ValidationStatus.UNCHECKED, name

    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_sessions_into_auth_manager(tmp_path / "missing.json")

    def test_invalid_json_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(ValueError):
            load_sessions_into_auth_manager(p)

    def test_not_a_list_raises(self, tmp_path):
        p = tmp_path / "obj.json"
        p.write_text('{"name": "x"}', encoding="utf-8")
        with pytest.raises(ValueError):
            load_sessions_into_auth_manager(p)

    def test_cookies_preserved(self, tmp_path):
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        mgr = load_sessions_into_auth_manager(p)
        rec = mgr.get("account_a")
        assert rec.cookies == {"s": "a1"}

    def test_auth_header_preserved(self, tmp_path):
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        mgr = load_sessions_into_auth_manager(p)
        rec = mgr.get("account_a")
        assert rec.auth_header == "Bearer AAA"


# ---------------------------------------------------------------------------
# evaluate_results — the pure evaluation/formatting function
# ---------------------------------------------------------------------------

class TestEvaluateResults:

    # ── basic exit codes ────────────────────────────────────────────────────

    def test_all_valid_exits_zero(self):
        names = ["account_a", "account_b"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.VALID, elapsed_ms=120),
            "account_b": _mk_result("account_b", ValidationStatus.VALID, elapsed_ms=98),
        }
        code, _ = evaluate_results(names, results)
        assert code == 0

    def test_account_a_expired_exits_one(self):
        names = ["account_a"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.EXPIRED_OR_UNAUTHORIZED),
        }
        code, _ = evaluate_results(names, results)
        assert code == 1

    def test_account_b_expired_exits_one(self):
        names = ["account_b"]
        results = {
            "account_b": _mk_result("account_b", ValidationStatus.EXPIRED_OR_UNAUTHORIZED),
        }
        code, _ = evaluate_results(names, results)
        assert code == 1

    def test_both_expired_exits_one(self):
        names = ["account_a", "account_b"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.EXPIRED_OR_UNAUTHORIZED),
            "account_b": _mk_result("account_b", ValidationStatus.EXPIRED_OR_UNAUTHORIZED),
        }
        code, _ = evaluate_results(names, results)
        assert code == 1

    def test_all_unchecked_exits_zero(self):
        """UNCHECKED (no probe_url) is not a blocking condition."""
        names = ["account_a", "account_b"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.UNCHECKED),
            "account_b": _mk_result("account_b", ValidationStatus.UNCHECKED),
        }
        code, _ = evaluate_results(names, results)
        assert code == 0

    def test_network_error_exits_zero(self):
        """NETWORK_ERROR prints a warning but does not block the hunt."""
        names = ["account_a"]
        results = {
            "account_a": _mk_result(
                "account_a", ValidationStatus.NETWORK_ERROR, error="connection refused"
            ),
        }
        code, _ = evaluate_results(names, results)
        assert code == 0

    def test_unexpected_response_exits_zero(self):
        names = ["account_a"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.UNEXPECTED_RESPONSE),
        }
        code, _ = evaluate_results(names, results)
        assert code == 0

    # ── no_auth exemption ───────────────────────────────────────────────────

    def test_no_auth_expired_does_not_block(self):
        """no_auth session is always allowed — even if it somehow comes back EXPIRED."""
        names = ["account_a", "no_auth"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.VALID, elapsed_ms=50),
            "no_auth": _mk_result("no_auth", ValidationStatus.EXPIRED_OR_UNAUTHORIZED),
        }
        code, _ = evaluate_results(names, results)
        assert code == 0

    def test_no_auth_unchecked_does_not_block(self):
        names = ["no_auth"]
        results = {
            "no_auth": _mk_result("no_auth", ValidationStatus.UNCHECKED),
        }
        code, _ = evaluate_results(names, results)
        assert code == 0

    # ── output format ───────────────────────────────────────────────────────

    def test_header_is_present(self):
        code, text = evaluate_results([], {})
        assert "[Auth Check]" in text

    def test_valid_session_shows_timing(self):
        names = ["account_a"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.VALID, elapsed_ms=123),
        }
        _, text = evaluate_results(names, results)
        assert "account_a" in text
        assert "123ms" in text

    def test_valid_session_zero_elapsed_no_parens(self):
        """When elapsed_ms == 0 the timing parenthesis is suppressed."""
        names = ["account_a"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.VALID, elapsed_ms=0),
        }
        _, text = evaluate_results(names, results)
        assert "(0ms)" not in text
        # State label is uppercased in output.
        assert ValidationStatus.VALID.upper() in text

    def test_expired_shows_expired_label(self):
        names = ["account_a"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.EXPIRED_OR_UNAUTHORIZED),
        }
        _, text = evaluate_results(names, results)
        assert "EXPIRED" in text

    def test_expired_shows_stopped_message(self):
        names = ["account_a"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.EXPIRED_OR_UNAUTHORIZED),
        }
        _, text = evaluate_results(names, results)
        assert "STOPPED" in text

    def test_no_auth_shown_in_summary(self):
        """no_auth must appear in the summary even though it never blocks."""
        names = ["account_a", "no_auth"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.VALID, elapsed_ms=50),
            "no_auth": _mk_result("no_auth", ValidationStatus.UNCHECKED),
        }
        _, text = evaluate_results(names, results)
        assert "no_auth" in text

    def test_network_error_shows_error_text(self):
        names = ["account_a"]
        results = {
            "account_a": _mk_result(
                "account_a", ValidationStatus.NETWORK_ERROR, error="timeout"
            ),
        }
        _, text = evaluate_results(names, results)
        assert "NETWORK_ERROR" in text
        assert "timeout" in text

    def test_all_three_sessions_in_output(self):
        names = ["account_a", "account_b", "no_auth"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.VALID, elapsed_ms=120),
            "account_b": _mk_result("account_b", ValidationStatus.VALID, elapsed_ms=98),
            "no_auth": _mk_result("no_auth", ValidationStatus.UNCHECKED),
        }
        _, text = evaluate_results(names, results)
        assert "account_a" in text
        assert "account_b" in text
        assert "no_auth" in text
        assert "120ms" in text
        assert "98ms" in text

    def test_no_stopped_message_when_all_valid(self):
        names = ["account_a", "account_b"]
        results = {
            "account_a": _mk_result("account_a", ValidationStatus.VALID, elapsed_ms=50),
            "account_b": _mk_result("account_b", ValidationStatus.VALID, elapsed_ms=60),
        }
        _, text = evaluate_results(names, results)
        assert "STOPPED" not in text

    def test_missing_result_entry_handled_gracefully(self):
        """If results dict is missing a name, print '(no result)' — no crash."""
        names = ["account_a"]
        code, text = evaluate_results(names, {})
        assert code == 0
        assert "no result" in text


# ---------------------------------------------------------------------------
# main() — CLI integration (via direct call, not subprocess)
# ---------------------------------------------------------------------------

class TestMain:
    """Tests that exercise main() directly to check exit codes and output."""

    def test_skip_flag_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--skip-auth-check"])
        assert exc.value.code == 0

    def test_skip_flag_prints_warning(self, capsys):
        with pytest.raises(SystemExit):
            main(["--skip-auth-check"])
        out = capsys.readouterr().out
        assert "SKIPPED" in out
        assert "WARNING" in out

    def test_missing_sessions_file_exits_two(self, tmp_path, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--sessions", str(tmp_path / "missing.json")])
        assert exc.value.code == 2

    def test_missing_sessions_file_prints_error(self, tmp_path, capsys):
        with pytest.raises(SystemExit):
            main(["--sessions", str(tmp_path / "missing.json")])
        out = capsys.readouterr().out
        assert "ERROR" in out
        assert "sessions.example.json" in out   # mentions the template

    def test_invalid_json_exits_two(self, tmp_path, capsys):
        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        with pytest.raises(SystemExit) as exc:
            main(["--sessions", str(bad)])
        assert exc.value.code == 2

    def test_unchecked_sessions_exit_zero(self, tmp_path, capsys):
        """sessions.json without probe_url → all UNCHECKED → exit 0."""
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        with pytest.raises(SystemExit) as exc:
            main(["--sessions", str(p)])
        assert exc.value.code == 0

    def test_unchecked_output_contains_header(self, tmp_path, capsys):
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        with pytest.raises(SystemExit):
            main(["--sessions", str(p)])
        out = capsys.readouterr().out
        assert "[Auth Check]" in out

    def test_unchecked_output_contains_session_names(self, tmp_path, capsys):
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        with pytest.raises(SystemExit):
            main(["--sessions", str(p)])
        out = capsys.readouterr().out
        assert "account_a" in out
        assert "account_b" in out
        assert "no_auth" in out

    def test_unchecked_sessions_show_unchecked_state(self, tmp_path, capsys):
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        with pytest.raises(SystemExit):
            main(["--sessions", str(p)])
        out = capsys.readouterr().out
        # State label is uppercased in output ("unchecked" → "UNCHECKED").
        assert ValidationStatus.UNCHECKED.upper() in out

    def test_does_not_create_files(self, tmp_path, capsys):
        """CLI must never write to disk."""
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        before = set(tmp_path.iterdir())
        with pytest.raises(SystemExit):
            main(["--sessions", str(p)])
        after = set(tmp_path.iterdir())
        assert before == after


# ---------------------------------------------------------------------------
# Integration: evaluate_results after real validate_all (UNCHECKED path)
# ---------------------------------------------------------------------------

class TestEvaluateWithRealValidation:
    """Uses AuthManager.validate_all() without probe URLs — always UNCHECKED."""

    def test_round_trip_unchecked_exits_zero(self, tmp_path):
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        mgr = load_sessions_into_auth_manager(p)
        results = mgr.validate_all()
        code, text = evaluate_results(list(mgr.names()), results)
        assert code == 0

    def test_round_trip_output_format(self, tmp_path):
        p = _write_sessions(tmp_path, _MINIMAL_SESSIONS)
        mgr = load_sessions_into_auth_manager(p)
        results = mgr.validate_all()
        _, text = evaluate_results(list(mgr.names()), results)
        assert "[Auth Check]" in text
        assert "account_a" in text
        assert "account_b" in text
        assert "no_auth" in text
        assert "STOPPED" not in text

    def test_only_account_a_in_file(self, tmp_path):
        p = _write_sessions(tmp_path, [{"name": "account_a", "cookies": {"s": "x"}}])
        mgr = load_sessions_into_auth_manager(p)
        results = mgr.validate_all()
        code, text = evaluate_results(list(mgr.names()), results)
        assert code == 0
        assert "account_a" in text
        assert "account_b" not in text
