"""Tests for tools/replay_bridge.py.

All tests are pure — no I/O, no HTTP, no state.  The module-level API
(should_suggest_replay, format_suggestion) and the CLI wrapper are both
tested.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from replay_bridge import (
    REPLAY_TRIGGER_CLASSES,
    format_suggestion,
    should_suggest_replay,
)

REPO = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(REPO / "tools" / "replay_bridge.py")]


def _cli(*args: str) -> str:
    r = subprocess.run(CLI + list(args), capture_output=True, text=True, check=False)
    return r.stdout.strip()


# ---------------------------------------------------------------------------
# should_suggest_replay — class filter (rule 1)
# ---------------------------------------------------------------------------


def test_idor_class_triggers():
    assert should_suggest_replay("/api/users/123", "GET", "authenticated", "idor")


def test_bac_class_triggers():
    assert should_suggest_replay("/admin/dashboard", "GET", "authenticated", "bac")


def test_authz_class_triggers():
    assert should_suggest_replay("/admin/settings", "GET", "authenticated", "authz")


def test_business_logic_class_triggers():
    assert should_suggest_replay("/account/orders", "POST", "authenticated", "business_logic")


def test_api_security_never_triggers():
    """api_security is structural, not per-account — no A/B value."""
    assert not should_suggest_replay("/api/users/123", "GET", "authenticated", "api_security")


def test_unknown_class_never_triggers():
    assert not should_suggest_replay("/api/users/123", "GET", "authenticated", "xss")


def test_all_trigger_classes_defined():
    """Ensure the trigger set matches the spec."""
    assert REPLAY_TRIGGER_CLASSES == {"idor", "bac", "authz", "business_logic"}


# ---------------------------------------------------------------------------
# should_suggest_replay — path signal (rule 2b, authenticated context)
# ---------------------------------------------------------------------------


def test_numeric_id_in_path_triggers():
    assert should_suggest_replay("/api/orders/99", "GET", "authenticated", "idor")


def test_uuid_in_path_triggers():
    assert should_suggest_replay(
        "/api/users/550e8400-e29b-41d4-a716-446655440000", "GET", "authenticated", "idor"
    )


def test_placeholder_in_path_triggers():
    assert should_suggest_replay("/api/users/{id}/profile", "GET", "authenticated", "idor")


def test_colon_placeholder_triggers():
    assert should_suggest_replay("/api/users/:id", "GET", "authenticated", "idor")


def test_query_param_ending_id_triggers():
    assert should_suggest_replay("/search?userId=42", "GET", "authenticated", "idor")


def test_admin_token_triggers():
    assert should_suggest_replay("/admin/internal", "GET", "authenticated", "bac")


def test_account_token_triggers():
    assert should_suggest_replay("/account/settings", "GET", "authenticated", "bac")


def test_orders_token_triggers():
    assert should_suggest_replay("/api/orders", "GET", "authenticated", "business_logic")


def test_billing_token_triggers():
    assert should_suggest_replay("/billing/invoices", "GET", "authenticated", "bac")


def test_no_signal_path_does_not_trigger():
    """Path with no identifier and no high-value token → no suggestion."""
    assert not should_suggest_replay("/status", "GET", "authenticated", "idor")
    assert not should_suggest_replay("/health", "GET", "authenticated", "bac")
    assert not should_suggest_replay("/favicon.ico", "GET", "authenticated", "idor")


def test_robots_txt_does_not_trigger_authenticated():
    assert not should_suggest_replay("/robots.txt", "GET", "authenticated", "bac")


# ---------------------------------------------------------------------------
# should_suggest_replay — anonymous context (rule 2a)
# ---------------------------------------------------------------------------


def test_anonymous_auth_path_triggers():
    """Anonymous + auth-category path = auth-bypass probe → suggest."""
    assert should_suggest_replay("/auth/login", "POST", "anonymous", "authz")


def test_anonymous_token_path_triggers():
    assert should_suggest_replay("/api/token/refresh", "POST", "anonymous", "authz")


def test_anonymous_oauth_path_triggers():
    assert should_suggest_replay("/oauth/callback", "GET", "anonymous", "authz")


def test_anonymous_orders_does_not_trigger():
    """Anonymous on /orders/123 → deferred; hunter has no second session yet."""
    assert not should_suggest_replay("/api/orders/99", "GET", "anonymous", "idor")


def test_anonymous_admin_does_not_trigger():
    assert not should_suggest_replay("/admin/internal", "GET", "anonymous", "bac")


def test_anonymous_robots_does_not_trigger():
    assert not should_suggest_replay("/robots.txt", "GET", "anonymous", "bac")


# ---------------------------------------------------------------------------
# should_suggest_replay — unknown / None auth_state
# ---------------------------------------------------------------------------


def test_none_auth_state_uses_authenticated_branch():
    """None auth_state is treated as authenticated (not anonymous)."""
    assert should_suggest_replay("/api/orders/99", "GET", None, "idor")


def test_none_auth_state_no_signal_path():
    assert not should_suggest_replay("/health", "GET", None, "idor")


# ---------------------------------------------------------------------------
# format_suggestion
# ---------------------------------------------------------------------------


def test_format_adds_https_scheme():
    s = format_suggestion("/api/users/1", "GET", "api.target.com")
    assert "https://api.target.com/api/users/1" in s


def test_format_does_not_double_scheme():
    s = format_suggestion("/api/users/1", "GET", "https://api.target.com")
    assert s.count("https://") == 1


def test_format_includes_method():
    s = format_suggestion("/api/users/1", "DELETE", "api.target.com")
    assert "--method DELETE" in s


def test_format_includes_replay_py():
    s = format_suggestion("/api/orders/99", "GET", "api.target.com")
    assert "tools/replay.py" in s


def test_format_has_suggestion_arrow():
    s = format_suggestion("/api/orders/99", "GET", "api.target.com")
    assert "→ Suggest A/B replay:" in s


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_deterministic_repeat_calls():
    calls = [
        should_suggest_replay("/api/orders/123", "GET", "authenticated", "idor")
        for _ in range(5)
    ]
    assert all(calls)


# ---------------------------------------------------------------------------
# CLI — output and exit code
# ---------------------------------------------------------------------------


def test_cli_prints_suggestion_for_high_signal():
    out = _cli(
        "--endpoint", "/api/orders/123",
        "--method", "GET",
        "--auth-state", "authenticated",
        "--vuln-class", "idor",
        "--target", "api.target.com",
    )
    assert "tools/replay.py" in out
    assert "https://api.target.com/api/orders/123" in out


def test_cli_prints_nothing_for_api_security():
    out = _cli(
        "--endpoint", "/api/users/1",
        "--method", "GET",
        "--auth-state", "authenticated",
        "--vuln-class", "api_security",
        "--target", "api.target.com",
    )
    assert out == ""


def test_cli_prints_nothing_for_no_signal_path():
    out = _cli(
        "--endpoint", "/robots.txt",
        "--method", "GET",
        "--auth-state", "anonymous",
        "--vuln-class", "bac",
        "--target", "api.target.com",
    )
    assert out == ""


def test_cli_exit_code_always_zero(tmp_path):
    r = subprocess.run(
        CLI + [
            "--endpoint", "/api/orders/1",
            "--method", "GET",
            "--auth-state", "authenticated",
            "--vuln-class", "idor",
        ],
        capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0


def test_cli_placeholder_url_without_target():
    """When --target is omitted, <BASE_URL> placeholder is used."""
    out = _cli(
        "--endpoint", "/api/orders/1",
        "--method", "GET",
        "--auth-state", "authenticated",
        "--vuln-class", "idor",
    )
    assert "<BASE_URL>" in out
    assert "/api/orders/1" in out


def test_cli_invalid_auth_state_exits_nonzero():
    r = subprocess.run(
        CLI + [
            "--endpoint", "/api/orders/1",
            "--method", "GET",
            "--auth-state", "bogus",
            "--vuln-class", "idor",
        ],
        capture_output=True, text=True, check=False,
    )
    assert r.returncode != 0


# ---------------------------------------------------------------------------
# No state writes
# ---------------------------------------------------------------------------


def test_no_files_written(tmp_path):
    before = set(tmp_path.iterdir())
    _cli(
        "--endpoint", "/api/orders/99",
        "--method", "GET",
        "--auth-state", "authenticated",
        "--vuln-class", "idor",
        "--target", "api.target.com",
    )
    after = set(tmp_path.iterdir())
    assert before == after
