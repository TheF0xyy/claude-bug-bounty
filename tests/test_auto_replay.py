"""Unit tests for tools/auto_replay.py.

All HTTP is mocked — no real network requests are ever made.
Tests cover every requirement in the spec:

  1.  Non-GET/HEAD methods are blocked and never sent.
  2.  Blocked URL substrings are rejected before any request.
  3.  Dead branches in hunt_state.json are skipped.
  4.  audit.jsonl is written for every request attempt.
  5.  Circuit breaker fires after 3 consecutive 4xx on same host.
  6.  Dry-run mode makes no real HTTP requests.
  7.  Scope check failure blocks the request.
  8.  idor_candidate classification when bodies differ between accounts.
  9.  dead classification when all responses are 401/403.
  10. needs_manual_review when 200 but identical bodies.
  11. Authorization and cookie values never appear in audit log entries.
  12. Rate limiter is invoked for every real request (1 req/sec enforced).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch, call

import pytest

# ── path setup ────────────────────────────────────────────────────────────────
_TESTS = Path(__file__).resolve().parent
_REPO = _TESTS.parent
_TOOLS = _REPO / "tools"
for _p in (str(_TOOLS), str(_REPO)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from auto_replay import (                                          # noqa: E402
    BLOCKED_PATH_SUBSTRINGS,
    CIRCUIT_THRESHOLD,
    CLASSIFICATION_DEAD,
    CLASSIFICATION_IDOR_CANDIDATE,
    CLASSIFICATION_NEEDS_REVIEW,
    SAFE_METHODS,
    AutoReplay,
    CandidateResult,
    ThreeWayResult,
    _build_url,
    _endpoint_path,
    _extract_host,
    _is_blocked_url,
    main,
)
from memory.state_manager import (                                 # noqa: E402
    add_candidate,
    get_candidates,
    is_dead_branch,
    get_signals,
    mark_dead_branch,
)
from memory.audit_log import AuditLog, RateLimiter                 # noqa: E402
from session_manager import SessionContext                         # noqa: E402
from replay_diff import ReplayResult, RequestTemplate              # noqa: E402


# ── fixtures and helpers ──────────────────────────────────────────────────────


def _make_sessions_file(
    tmp_path: Path,
    entries: list[dict] | None = None,
) -> Path:
    """Write a sessions.json to tmp_path and return the path."""
    if entries is None:
        entries = [
            {"name": "account_a", "auth_header": "Bearer TOKEN-A",
             "cookies": {"sid": "SESS-A"}},
            {"name": "account_b", "auth_header": "Bearer TOKEN-B",
             "cookies": {"sid": "SESS-B"}},
            {"name": "no_auth"},
        ]
    p = tmp_path / "sessions.json"
    p.write_text(json.dumps(entries), encoding="utf-8")
    return p


def _make_state_file(tmp_path: Path, data: dict | None = None) -> Path:
    """Write a hunt_state.json to tmp_path and return the path."""
    p = tmp_path / "hunt_state.json"
    if data is not None:
        p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _make_audit(tmp_path: Path) -> tuple[AuditLog, Path]:
    """Return an (AuditLog, path) pair pointing at tmp_path/audit.jsonl."""
    audit_path = tmp_path / "audit.jsonl"
    return AuditLog(audit_path), audit_path


def _read_audit(audit_path: Path) -> list[dict]:
    """Read all JSONL audit entries from *audit_path*."""
    if not audit_path.exists():
        return []
    return [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _null_rate_limiter() -> RateLimiter:
    """Return a RateLimiter that records calls without sleeping."""
    rl = MagicMock(spec=RateLimiter)
    rl.wait.return_value = 0.0
    return rl


def _make_transport(
    status: int = 200,
    body: bytes = b'{"ok": true}',
    headers: dict | None = None,
):
    """Return a transport callable that always responds with fixed values."""
    _h = headers or {"content-type": "application/json"}

    def _t(method, url, req_headers, body_bytes, timeout):
        return status, body, _h

    return _t


def _dispatch_transport(
    responses: dict[str, tuple[int, bytes, dict]],
):
    """Return a transport that dispatches on the Authorization header value.

    Keys are matched as substrings of the Authorization header.
    Falls back to the "default" key when no key matches.
    """

    def _t(method, url, req_headers, body_bytes, timeout):
        auth = req_headers.get("Authorization", "")
        cookie = req_headers.get("Cookie", "")
        for key, resp in responses.items():
            if key != "default" and (key in auth or key in cookie):
                return resp
        return responses.get("default", (404, b"not found", {}))

    return _t


def _make_ar(
    tmp_path: Path,
    target: str = "api.example.com",
    candidates: list[tuple[str, str]] | None = None,
    sessions_entries: list[dict] | None = None,
    transport=None,
    scope_checker=None,
    state_data: dict | None = None,
    use_null_rate_limiter: bool = True,
    allow_write: bool = False,
) -> tuple[AutoReplay, Path, Path]:
    """Build an AutoReplay instance wired to temp files.

    *candidates* is a list of (endpoint, method) pairs pre-populated into
    hunt_state.json with status "candidate".

    Returns (ar, state_path, audit_path).
    """
    sessions_file = _make_sessions_file(tmp_path, sessions_entries)

    initial_state: dict = state_data or {}
    state_path = _make_state_file(tmp_path, initial_state)

    audit, audit_path = _make_audit(tmp_path)

    if candidates:
        for ep, method in candidates:
            add_candidate(target, ep, method, path=state_path)

    rl = _null_rate_limiter() if use_null_rate_limiter else None

    ar = AutoReplay(
        target=target,
        state_file=state_path,
        sessions_file=sessions_file,
        audit_log=audit,
        allow_write=allow_write,
        scope_checker=scope_checker,
        transport=transport or _make_transport(),
        _rate_limiter=rl,
    )
    return ar, state_path, audit_path


# ── 1. Method gate ────────────────────────────────────────────────────────────


class TestMethodGate:
    """Non-GET/HEAD methods must be blocked before any network call."""

    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
    def test_write_method_blocked_by_default(self, tmp_path, method):
        """Write methods produce 'write method: X — rerun with --allow-write' reason."""
        call_count = [0]

        def counting(m, url, h, b, t):
            call_count[0] += 1
            return 200, b"", {}

        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", method)],
            transport=counting,
        )
        results = ar.run()
        assert len(results) == 1
        assert results[0].skipped is True
        assert "write method" in results[0].skip_reason
        assert "--allow-write" in results[0].skip_reason
        assert call_count[0] == 0, "Transport must not be called for blocked methods"

    @pytest.mark.parametrize("method", ["OPTIONS"])
    def test_exotic_method_hard_blocked(self, tmp_path, method):
        """Exotic/unknown methods are always hard-blocked regardless of allow_write.

        Only OPTIONS is used here because CONNECT/TRACE are not in the audit
        log schema's VALID_METHODS and would raise before the gate check.
        OPTIONS is representative: it is neither in SAFE_METHODS nor WRITE_METHODS.
        """
        call_count = [0]

        def counting(m, url, h, b, t):
            call_count[0] += 1
            return 200, b"", {}

        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", method)],
            transport=counting,
            allow_write=True,  # even with allow_write, exotic methods are blocked
        )
        results = ar.run()
        assert len(results) == 1
        assert results[0].skipped is True
        assert "unsafe method" in results[0].skip_reason
        assert call_count[0] == 0, "Transport must not be called for blocked methods"

    def test_get_is_allowed_through_method_gate(self, tmp_path):
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
        )
        results = ar.run()
        assert results[0].skipped is False or results[0].skip_reason != "unsafe method: GET"

    def test_head_is_allowed_through_method_gate(self, tmp_path):
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/items/5", "HEAD")],
        )
        results = ar.run()
        assert not (results[0].skipped and "unsafe method" in (results[0].skip_reason or ""))

    def test_is_safe_to_replay_post_blocked(self, tmp_path):
        ar, _, _ = _make_ar(tmp_path)
        safe, reason = ar._is_safe_to_replay("https://api.example.com/users", "POST")
        assert safe is False
        assert "write method" in reason

    def test_is_safe_to_replay_get_passes_method_gate(self, tmp_path):
        ar, _, _ = _make_ar(tmp_path)
        # Method gate passes; other gates may still fire.
        safe, reason = ar._is_safe_to_replay("https://api.example.com/users/1", "GET")
        assert reason != "unsafe method: GET"


# ── 2. Blocklist gate ─────────────────────────────────────────────────────────


class TestBlocklistGate:
    """Blocked URL strings must be rejected before any request."""

    @pytest.mark.parametrize("path_frag", [
        "payment", "admin", "password", "reset-password",
        "mfa", "2fa", "verify-email", "delete", "cancel",
        "refund", "subscribe", "unsubscribe",
    ])
    def test_blocked_substring_skips_candidate(self, tmp_path, path_frag):
        call_count = [0]

        def counting(m, url, h, b, t):
            call_count[0] += 1
            return 200, b"", {}

        endpoint = f"/{path_frag}/resource"
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[(endpoint, "GET")],
            transport=counting,
        )
        results = ar.run()
        assert results[0].skipped is True
        assert results[0].skip_reason == "blocked path substring"
        assert call_count[0] == 0

    def test_safe_api_path_not_blocked(self):
        assert _is_blocked_url("https://api.example.com/api/users/123") is False

    def test_orders_list_not_blocked(self):
        # "orders" alone is NOT blocked; only "order/place" multi-segment.
        assert _is_blocked_url("https://api.example.com/api/orders/99") is False

    def test_case_insensitive_check(self):
        assert _is_blocked_url("https://api.example.com/ADMIN/settings") is True

    def test_reset_password_blocked(self):
        assert _is_blocked_url("https://api.example.com/auth/reset-password") is True


# ── 3. Dead-branch skipping ───────────────────────────────────────────────────


class TestDeadBranchGate:
    """Endpoints already marked dead must be skipped."""

    def test_dead_branch_idor_skipped(self, tmp_path):
        """A dead (endpoint, idor, GET) entry must skip the candidate."""
        call_count = [0]

        def counting(m, url, h, b, t):
            call_count[0] += 1
            return 200, b"", {}

        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
            transport=counting,
        )
        # Mark endpoint dead before running.
        mark_dead_branch(
            "api.example.com", "/api/users/1", "idor", "no_signal",
            method="GET", path=state_path,
        )
        results = ar.run()
        assert results[0].skipped is True
        assert "dead branch" in results[0].skip_reason
        assert call_count[0] == 0

    def test_dead_for_different_method_not_skipped(self, tmp_path):
        """GET dead must NOT cause HEAD to be skipped."""
        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "HEAD")],
        )
        mark_dead_branch(
            "api.example.com", "/api/users/1", "idor", "no_signal",
            method="GET", path=state_path,
        )
        results = ar.run()
        assert not (results[0].skipped and "dead branch" in (results[0].skip_reason or ""))

    def test_no_signal_marks_dead_branch(self, tmp_path):
        """dead classification (all 401/403) must write a dead branch.

        200-identical classifies as needs_manual_review (no dead branch).
        Use 401 responses which unambiguously give CLASSIFICATION_DEAD.
        """
        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/items/99", "GET")],
            transport=_make_transport(401, b"unauthorized"),
        )
        ar.run()
        assert is_dead_branch(
            "api.example.com", "/api/items/99", "idor",
            method="GET", path=state_path,
        )


# ── 4. Audit log ──────────────────────────────────────────────────────────────


class TestAuditLog:
    """Every request attempt must be logged to audit.jsonl."""

    def test_three_sessions_produce_three_audit_entries(self, tmp_path):
        ar, _, audit_path = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
        )
        ar.run()
        entries = _read_audit(audit_path)
        session_ids = {e.get("session_id") for e in entries}
        assert "account_a" in session_ids
        assert "account_b" in session_ids
        assert "no_auth" in session_ids

    def test_blocked_candidate_is_still_logged(self, tmp_path):
        """Safety-gate blocks must appear in the audit log."""
        ar, _, audit_path = _make_ar(
            tmp_path,
            candidates=[("/admin/settings", "GET")],
        )
        ar.run()
        entries = _read_audit(audit_path)
        assert len(entries) >= 1

    def test_audit_contains_url(self, tmp_path):
        url_path = "/api/orders/42"
        ar, _, audit_path = _make_ar(
            tmp_path,
            candidates=[(url_path, "GET")],
        )
        ar.run()
        entries = _read_audit(audit_path)
        request_entries = [
            e for e in entries
            if e.get("session_id") in {"account_a", "account_b", "no_auth"}
        ]
        assert all(url_path in e.get("url", "") for e in request_entries)

    def test_audit_contains_method(self, tmp_path):
        ar, _, audit_path = _make_ar(
            tmp_path,
            candidates=[("/api/items/7", "HEAD")],
        )
        ar.run()
        entries = _read_audit(audit_path)
        request_entries = [
            e for e in entries
            if e.get("session_id") in {"account_a", "account_b", "no_auth"}
        ]
        assert all(e.get("method") == "HEAD" for e in request_entries)

    def test_audit_contains_response_status(self, tmp_path):
        ar, _, audit_path = _make_ar(
            tmp_path,
            candidates=[("/api/items/5", "GET")],
            transport=_make_transport(201, b"created"),
        )
        ar.run()
        entries = _read_audit(audit_path)
        statuses = {
            e.get("response_status") for e in entries
            if e.get("session_id") in {"account_a", "account_b", "no_auth"}
        }
        assert 201 in statuses


# ── 5. Circuit breaker ────────────────────────────────────────────────────────


class TestCircuitBreaker:
    """Circuit breaker must fire after CIRCUIT_THRESHOLD consecutive 4xx."""

    def test_circuit_trips_at_threshold(self, tmp_path):
        assert CIRCUIT_THRESHOLD == 3

        call_count = [0]

        def always_401(m, url, h, b, t):
            call_count[0] += 1
            return 401, b"unauthorized", {}

        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
            transport=always_401,
        )
        ar.run()
        # After CIRCUIT_THRESHOLD 4xx responses, host is stopped.
        assert call_count[0] == CIRCUIT_THRESHOLD
        host = "api.example.com"
        assert ar._is_host_stopped(host)

    def test_circuit_breaker_stops_second_endpoint(self, tmp_path):
        """Once tripped, the circuit breaker must block the next candidate."""
        call_count = [0]

        def always_403(m, url, h, b, t):
            call_count[0] += 1
            return 403, b"forbidden", {}

        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[
                ("/api/users/1", "GET"),
                ("/api/users/2", "GET"),
            ],
            transport=always_403,
        )
        ar.run()
        calls_total = call_count[0]
        # Second candidate should produce no additional transport calls.
        assert calls_total == CIRCUIT_THRESHOLD

    def test_circuit_breaker_trip_logged_to_audit(self, tmp_path):
        def always_401(m, url, h, b, t):
            return 401, b"", {}

        ar, _, audit_path = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
            transport=always_401,
        )
        ar.run()
        entries = _read_audit(audit_path)
        circuit_entries = [
            e for e in entries if e.get("session_id") == "circuit_breaker"
        ]
        assert len(circuit_entries) >= 1
        assert any("circuit breaker" in (e.get("error") or "") for e in circuit_entries)

    def test_2xx_resets_counter(self, tmp_path):
        """A successful 2xx response must reset the consecutive-4xx counter."""
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
            transport=_make_transport(200, b"ok"),
        )
        ar.run()
        assert ar._consec_4xx.get("api.example.com", 0) == 0

    def test_5xx_resets_counter(self, tmp_path):
        """5xx responses must reset the consecutive-4xx counter."""
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
            transport=_make_transport(500, b"error"),
        )
        ar.run()
        assert ar._consec_4xx.get("api.example.com", 0) == 0


# ── 6. Dry-run mode ───────────────────────────────────────────────────────────


class TestDryRun:
    """Dry-run mode must not make any HTTP requests or write state."""

    def test_dry_run_makes_no_http_calls(self, tmp_path):
        call_count = [0]

        def counting(m, url, h, b, t):
            call_count[0] += 1
            return 200, b"", {}

        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET"), ("/api/orders/2", "GET")],
            transport=counting,
        )
        results = ar.run(dry_run=True)
        assert call_count[0] == 0, "Transport must not be called in dry-run"

    def test_dry_run_returns_results_for_each_candidate(self, tmp_path):
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET"), ("/api/orders/2", "GET")],
        )
        results = ar.run(dry_run=True)
        assert len(results) == 2

    def test_dry_run_does_not_write_dead_branches(self, tmp_path):
        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
        )
        ar.run(dry_run=True)
        assert not is_dead_branch(
            "api.example.com", "/api/users/1", "idor",
            method="GET", path=state_path,
        )

    def test_dry_run_does_not_write_signals(self, tmp_path):
        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
        )
        ar.run(dry_run=True)
        assert get_signals("api.example.com", path=state_path) == []

    def test_dry_run_classification_is_none(self, tmp_path):
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
        )
        results = ar.run(dry_run=True)
        # Candidates that pass safety gates have classification=None in dry-run.
        non_skipped = [r for r in results if not r.skipped]
        assert all(r.classification is None for r in non_skipped)

    def test_dry_run_safety_gates_still_apply(self, tmp_path):
        """Dry-run must still skip blocked URLs and write methods."""
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[
                ("/admin/config", "GET"),   # blocked substring
                ("/api/users/1", "POST"),   # write method (blocked without allow_write)
                ("/api/orders/1", "GET"),   # should pass
            ],
        )
        results = ar.run(dry_run=True)
        skipped = [r for r in results if r.skipped]
        passed = [r for r in results if not r.skipped]
        assert len(skipped) == 2
        assert len(passed) == 1


# ── 7. Scope gate ─────────────────────────────────────────────────────────────


class TestScopeGate:
    """Out-of-scope URLs must be blocked and logged."""

    def test_out_of_scope_blocked(self, tmp_path):
        from scope_checker import ScopeChecker
        sc = ScopeChecker(["*.allowed.com"])

        ar, _, _ = _make_ar(
            tmp_path,
            target="blocked.com",
            candidates=[("/api/users/1", "GET")],
            scope_checker=sc,
        )
        results = ar.run()
        assert results[0].skipped is True
        assert results[0].skip_reason == "out of scope"

    def test_out_of_scope_logged_to_audit(self, tmp_path):
        from scope_checker import ScopeChecker
        sc = ScopeChecker(["*.allowed.com"])

        ar, _, audit_path = _make_ar(
            tmp_path,
            target="blocked.com",
            candidates=[("/api/users/1", "GET")],
            scope_checker=sc,
        )
        ar.run()
        entries = _read_audit(audit_path)
        assert any(e.get("scope_check") == "fail" for e in entries)

    def test_in_scope_url_passes(self, tmp_path):
        from scope_checker import ScopeChecker
        sc = ScopeChecker(["*.example.com"])

        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
            scope_checker=sc,
        )
        results = ar.run()
        assert not (results[0].skipped and results[0].skip_reason == "out of scope")


# ── 8. idor_candidate classification ─────────────────────────────────────────


class TestIdorCandidateClassification:
    """When response bodies differ between sessions, classify as idor_candidate."""

    def test_different_bodies_classified_idor_candidate(self, tmp_path):
        transport = _dispatch_transport({
            "TOKEN-A": (200, b'{"user": "Alice", "secret": "A"}',
                        {"content-type": "application/json"}),
            "TOKEN-B": (200, b'{"user": "Bob"}',
                        {"content-type": "application/json"}),
            "default": (401, b"", {}),
        })
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/profile/1", "GET")],
            transport=transport,
        )
        results = ar.run()
        assert results[0].classification == CLASSIFICATION_IDOR_CANDIDATE

    def test_idor_candidate_recorded_as_signal(self, tmp_path):
        transport = _dispatch_transport({
            "TOKEN-A": (200, b'{"data": "private-A"}',
                        {"content-type": "application/json"}),
            "TOKEN-B": (200, b'{"data": "private-B"}',
                        {"content-type": "application/json"}),
            "default": (200, b'{"data": "private-A"}', {}),
        })
        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/42", "GET")],
            transport=transport,
        )
        ar.run()
        signals = get_signals("api.example.com", path=state_path)
        assert len(signals) >= 1
        assert signals[0]["vuln_class"] == "idor"

    def test_status_code_diff_classified_idor(self, tmp_path):
        """Different status codes between A and B must also be idor_candidate."""
        transport = _dispatch_transport({
            "TOKEN-A": (200, b'{"ok": true}', {}),
            "TOKEN-B": (403, b"forbidden", {}),
            "default": (401, b"", {}),
        })
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/items/5", "GET")],
            transport=transport,
        )
        results = ar.run()
        assert results[0].classification == CLASSIFICATION_IDOR_CANDIDATE

    def test_no_auth_leakage_classified_idor(self, tmp_path):
        """When no_auth gets data that should require auth, it is idor_candidate."""
        transport = _dispatch_transport({
            "TOKEN-A": (200, b'{"secret": "data"}', {}),
            "TOKEN-B": (200, b'{"secret": "data"}', {}),
            "default": (200, b'{"secret": "data", "extra": "leaked"}', {}),
        })
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
            transport=transport,
        )
        results = ar.run()
        assert results[0].classification == CLASSIFICATION_IDOR_CANDIDATE


# ── 9. dead classification (all 401/403) ──────────────────────────────────────


class TestDeadClassification:
    """When all responses are 401/403, classify as dead with reason no_signal."""

    def test_all_401_classified_dead(self, tmp_path):
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/secret/1", "GET")],
            transport=_make_transport(401, b"unauthorized"),
        )
        results = ar.run()
        assert results[0].classification == CLASSIFICATION_DEAD

    def test_all_403_classified_dead(self, tmp_path):
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/secret/1", "GET")],
            transport=_make_transport(403, b"forbidden"),
        )
        results = ar.run()
        assert results[0].classification == CLASSIFICATION_DEAD

    def test_dead_writes_dead_branch(self, tmp_path):
        """dead classification must write a dead_branch for future skipping."""
        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/locked/1", "GET")],
            transport=_make_transport(401, b""),
        )
        ar.run()
        assert is_dead_branch(
            "api.example.com", "/api/locked/1", "idor",
            method="GET", path=state_path,
        )

    def test_dead_notes_describe_reason(self, tmp_path):
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/locked/1", "GET")],
            transport=_make_transport(401, b""),
        )
        results = ar.run()
        assert "401" in results[0].notes or "auth" in results[0].notes.lower()


# ── 10. needs_manual_review (200 identical) ───────────────────────────────────


class TestNeedsManualReviewClassification:
    """When all sessions return 200 with identical bodies, classify needs_manual_review."""

    def test_all_200_identical_classified_needs_review(self, tmp_path):
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/items/77", "GET")],
            transport=_make_transport(200, b'{"shared": "data"}'),
        )
        results = ar.run()
        assert results[0].classification == CLASSIFICATION_NEEDS_REVIEW

    def test_needs_review_not_marked_dead_branch(self, tmp_path):
        """needs_manual_review must NOT write a dead branch."""
        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/items/77", "GET")],
            transport=_make_transport(200, b'{"shared": "data"}'),
        )
        ar.run()
        assert not is_dead_branch(
            "api.example.com", "/api/items/77", "idor",
            method="GET", path=state_path,
        )

    def test_needs_review_candidate_status_updated(self, tmp_path):
        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/items/77", "GET")],
            transport=_make_transport(200, b'{"shared": "data"}'),
        )
        ar.run()
        candidates = get_candidates("api.example.com", path=state_path)
        updated = next(
            (c for c in candidates if c["endpoint"] == "/api/items/77"), None
        )
        assert updated is not None
        assert updated["status"] == CLASSIFICATION_NEEDS_REVIEW


# ── 11. Credential privacy ────────────────────────────────────────────────────


class TestCredentialPrivacy:
    """Authorization and cookie values must never appear in audit log entries."""

    def test_auth_token_not_in_audit(self, tmp_path):
        ar, _, audit_path = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
        )
        ar.run()
        audit_text = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
        assert "TOKEN-A" not in audit_text, "account_a Bearer token must not appear in audit"
        assert "TOKEN-B" not in audit_text, "account_b Bearer token must not appear in audit"

    def test_session_cookie_not_in_audit(self, tmp_path):
        ar, _, audit_path = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
        )
        ar.run()
        audit_text = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
        assert "SESS-A" not in audit_text, "account_a session cookie must not appear in audit"
        assert "SESS-B" not in audit_text, "account_b session cookie must not appear in audit"

    def test_audit_entries_contain_session_name_not_credentials(self, tmp_path):
        """Audit entries must use session_id (name) not any auth value."""
        ar, _, audit_path = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
        )
        ar.run()
        entries = _read_audit(audit_path)
        request_entries = [
            e for e in entries
            if e.get("session_id") in {"account_a", "account_b", "no_auth"}
        ]
        assert len(request_entries) > 0
        for e in request_entries:
            serialised = json.dumps(e)
            assert "TOKEN-A" not in serialised
            assert "TOKEN-B" not in serialised
            assert "SESS-A" not in serialised
            assert "SESS-B" not in serialised


# ── 12. Rate limiter ──────────────────────────────────────────────────────────


class TestRateLimiter:
    """Rate limiter must be invoked for every real outbound request."""

    def test_rate_limiter_called_per_session(self, tmp_path):
        """wait() must be called once for each session's request (3 sessions)."""
        mock_rl = _null_rate_limiter()

        ar, state_path, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
            use_null_rate_limiter=False,
        )
        ar._rate_limiter = mock_rl
        ar.run()

        # Three sessions: account_a, account_b, no_auth.
        assert mock_rl.wait.call_count == 3

    def test_rate_limiter_called_with_host(self, tmp_path):
        """wait() must be called with the correct hostname."""
        mock_rl = _null_rate_limiter()
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
            use_null_rate_limiter=False,
        )
        ar._rate_limiter = mock_rl
        ar.run()

        for c in mock_rl.wait.call_args_list:
            assert c[0][0] == "api.example.com"

    def test_rate_limiter_not_called_for_blocked_candidates(self, tmp_path):
        """Blocked candidates (method/blocklist/dead) must not trigger the limiter."""
        mock_rl = _null_rate_limiter()
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/admin/settings", "GET")],  # blocked path
            use_null_rate_limiter=False,
        )
        ar._rate_limiter = mock_rl
        ar.run()
        assert mock_rl.wait.call_count == 0


# ── classify_result unit tests ────────────────────────────────────────────────


class TestClassifyResult:
    """Unit tests for AutoReplay._classify_result()."""

    def _make_result(
        self,
        status_a: int, body_a: bytes,
        status_b: int, body_b: bytes,
        status_no: int = 401, body_no: bytes = b"",
    ) -> ThreeWayResult:
        """Build a ThreeWayResult from fixed status/body triples."""
        from replay_diff import compare_all, ReplayResult
        results = {
            "account_a": ReplayResult(
                session_name="account_a", status_code=status_a,
                body=body_a, response_headers={}, elapsed_ms=1.0,
            ),
            "account_b": ReplayResult(
                session_name="account_b", status_code=status_b,
                body=body_b, response_headers={}, elapsed_ms=1.0,
            ),
            "no_auth": ReplayResult(
                session_name="no_auth", status_code=status_no,
                body=body_no, response_headers={}, elapsed_ms=1.0,
            ),
        }
        diffs = compare_all(results)
        return ThreeWayResult(results=results, diffs=diffs)

    def _ar(self, tmp_path):
        _, state_path, _ = _make_ar(tmp_path)
        audit, _ = _make_audit(tmp_path)
        return AutoReplay(
            target="x.com",
            state_file=state_path,
            sessions_file=tmp_path / "sessions.json",
            audit_log=audit,
        )

    def test_diff_bodies_gives_idor_candidate(self, tmp_path):
        ar = self._ar(tmp_path)
        tw = self._make_result(200, b"Alice data", 200, b"Bob data")
        c, _ = ar._classify_result(tw)
        assert c == CLASSIFICATION_IDOR_CANDIDATE

    def test_diff_status_gives_idor_candidate(self, tmp_path):
        ar = self._ar(tmp_path)
        tw = self._make_result(200, b"data", 403, b"forbidden")
        c, _ = ar._classify_result(tw)
        assert c == CLASSIFICATION_IDOR_CANDIDATE

    def test_all_401_gives_dead(self, tmp_path):
        ar = self._ar(tmp_path)
        tw = self._make_result(401, b"", 401, b"")
        c, notes = ar._classify_result(tw)
        assert c == CLASSIFICATION_DEAD
        assert "401" in notes or "auth" in notes.lower()

    def test_all_403_gives_dead(self, tmp_path):
        ar = self._ar(tmp_path)
        # All three sessions must return the same 4xx to avoid a status diff.
        tw = self._make_result(403, b"", 403, b"", status_no=403, body_no=b"")
        c, _ = ar._classify_result(tw)
        assert c == CLASSIFICATION_DEAD

    def test_all_200_identical_gives_needs_review(self, tmp_path):
        ar = self._ar(tmp_path)
        tw = self._make_result(200, b"same", 200, b"same", 200, b"same")
        c, _ = ar._classify_result(tw)
        assert c == CLASSIFICATION_NEEDS_REVIEW

    def test_error_gives_dead(self, tmp_path):
        ar = self._ar(tmp_path)
        tw = ThreeWayResult(results={}, diffs=[], error="sessions file not found")
        c, _ = ar._classify_result(tw)
        assert c == CLASSIFICATION_DEAD

    def test_empty_results_gives_dead(self, tmp_path):
        ar = self._ar(tmp_path)
        tw = ThreeWayResult(results={}, diffs=[])
        c, _ = ar._classify_result(tw)
        assert c == CLASSIFICATION_DEAD


# ── CLI ───────────────────────────────────────────────────────────────────────


class TestCLI:
    """CLI exit codes and argument handling."""

    def _run_cli(
        self,
        tmp_path: Path,
        target: str = "api.example.com",
        extra_args: list[str] | None = None,
        transport=None,
        candidates: list[tuple[str, str]] | None = None,
        sessions_entries: list[dict] | None = None,
    ) -> int:
        """Helper that wires up files and calls main(), returning exit code."""
        sessions_file = _make_sessions_file(tmp_path, sessions_entries)
        state_path = _make_state_file(tmp_path)
        audit_path = tmp_path / "audit.jsonl"

        if candidates:
            for ep, method in candidates:
                add_candidate(target, ep, method, path=state_path)

        # Monkey-patch AutoReplay to inject mock transport.
        import auto_replay as _mod
        orig = _mod.AutoReplay

        _transport = transport or _make_transport()

        class _PatchedAR(_mod.AutoReplay):
            def __init__(self, **kwargs):
                kwargs.setdefault("_rate_limiter", _null_rate_limiter())
                kwargs["transport"] = _transport
                super().__init__(**kwargs)

        _mod.AutoReplay = _PatchedAR
        try:
            argv = [
                "--target", target,
                "--sessions", str(sessions_file),
                "--state-path", str(state_path),
                "--audit-log", str(audit_path),
            ] + (extra_args or [])
            return main(argv)
        finally:
            _mod.AutoReplay = orig

    def test_exit_0_when_no_idor_candidates(self, tmp_path):
        code = self._run_cli(
            tmp_path,
            candidates=[("/api/items/1", "GET")],
            transport=_make_transport(401, b""),  # → dead
        )
        assert code == 0

    def test_exit_1_when_idor_candidate_found(self, tmp_path):
        transport = _dispatch_transport({
            "TOKEN-A": (200, b"Alice data", {}),
            "TOKEN-B": (200, b"Bob data", {}),
            "default": (401, b"", {}),
        })
        code = self._run_cli(
            tmp_path,
            candidates=[("/api/profile/1", "GET")],
            transport=transport,
        )
        assert code == 1

    def test_exit_0_when_no_candidates(self, tmp_path):
        code = self._run_cli(tmp_path)
        assert code == 0

    def test_no_candidates_prints_helpful_message(self, tmp_path, capsys):
        """When no candidates exist, auto_replay must print a clear explanation."""
        self._run_cli(tmp_path)
        out = capsys.readouterr().out
        assert "No candidates found" in out
        assert "hunt_state.py candidate" in out

    def test_no_candidates_message_includes_target(self, tmp_path, capsys):
        self._run_cli(tmp_path, target="zooplus.com")
        out = capsys.readouterr().out
        assert "zooplus.com" in out

    def test_no_candidates_message_dry_run_also_prints(self, tmp_path, capsys):
        """Dry-run with no candidates must also print the helpful message."""
        self._run_cli(tmp_path, extra_args=["--dry-run"])
        out = capsys.readouterr().out
        assert "No candidates found" in out

    def test_with_candidates_does_not_print_no_candidates_message(self, tmp_path, capsys):
        """When candidates exist, the 'No candidates' message must NOT appear."""
        self._run_cli(
            tmp_path,
            candidates=[("/api/orders/1", "GET")],
            transport=_make_transport(401, b""),
        )
        out = capsys.readouterr().out
        assert "No candidates found" not in out

    def test_dry_run_flag_accepted(self, tmp_path):
        code = self._run_cli(
            tmp_path,
            candidates=[("/api/users/1", "GET")],
            extra_args=["--dry-run"],
        )
        # dry-run always exits 0 (no real classification).
        assert code == 0


# ── ThreeWayResult / CandidateResult data structures ─────────────────────────


class TestDataStructures:
    def test_candidate_result_summary_blocked(self):
        r = CandidateResult(
            endpoint="/admin", method="GET",
            url="https://x.com/admin",
            skipped=True, skip_reason="blocked path substring",
            classification=None,
        )
        assert "[SKIP]" in r.summary()
        assert "blocked" in r.summary()

    def test_candidate_result_summary_idor(self):
        r = CandidateResult(
            endpoint="/api/users/1", method="GET",
            url="https://x.com/api/users/1",
            skipped=False, skip_reason=None,
            classification=CLASSIFICATION_IDOR_CANDIDATE,
            notes="body differs",
        )
        assert "IDOR_CANDIDATE" in r.summary()
        assert "body differs" in r.summary()

    def test_three_way_result_fields(self):
        tw = ThreeWayResult(results={}, diffs=[])
        assert tw.error is None
        tw2 = ThreeWayResult(results={}, diffs=[], error="test")
        assert tw2.error == "test"


# ── helper function unit tests ────────────────────────────────────────────────


class TestHelpers:
    def test_build_url_full_url_unchanged(self):
        assert _build_url("https://a.com/path", "a.com") == "https://a.com/path"

    def test_build_url_path_combined(self):
        assert _build_url("/api/users/1", "a.com") == "https://a.com/api/users/1"

    def test_extract_host_full_url(self):
        assert _extract_host("https://api.example.com/path") == "api.example.com"

    def test_endpoint_path_strips_to_path(self):
        assert _endpoint_path("https://api.example.com/api/users/1") == "/api/users/1"

    def test_endpoint_path_bare_path_unchanged(self):
        assert _endpoint_path("/api/users/1") == "/api/users/1"


# ── --allow-write flag ────────────────────────────────────────────────────────


class TestAllowWriteFlag:
    """PUT/PATCH/DELETE/POST methods require allow_write=True to pass the gate."""

    @pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE", "POST"])
    def test_write_method_blocked_by_default(self, tmp_path, method):
        """Write methods must be skipped when allow_write is False (default)."""
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/address/123", method)],
        )
        results = ar.run()
        assert len(results) == 1
        r = results[0]
        assert r.skipped is True
        assert "write method" in r.skip_reason
        assert "--allow-write" in r.skip_reason

    @pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE", "POST"])
    def test_write_method_passes_with_allow_write(self, tmp_path, method):
        """Write methods must be allowed through the method gate when allow_write=True."""
        # Use a transport that returns a clear idor signal so the run completes.
        def transport_a_b_diff(m, url, h, b, t):
            if "account_a" in str(h) or "token_a" in str(h):
                return 200, b'{"owner":"a"}', {"content-type": "application/json"}
            return 200, b'{"owner":"b"}', {"content-type": "application/json"}

        # We need per-session differentiation; use a simpler transport.
        call_log: list[str] = []

        def counting_transport(m, url, h, b, t):
            call_log.append(m)
            return 200, b"ok", {}

        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/address/123", method)],
            transport=counting_transport,
            allow_write=True,
        )
        results = ar.run()
        assert len(results) == 1
        r = results[0]
        # Not skipped by method gate — may be skipped by another gate or produce a result.
        assert r.skip_reason != f"write method: {method} — rerun with --allow-write"
        # The transport was called (method gate did not block).
        assert len(call_log) > 0

    def test_body_reaches_transport(self, tmp_path):
        """Body stored in the candidate entry must be passed to the HTTP transport."""
        received_bodies: list[bytes | None] = []

        def capturing_transport(m, url, h, b, t):
            received_bodies.append(b)
            return 200, b"ok", {}

        # Add a candidate with a body directly via state_manager to bypass
        # the method gate (use GET so the method gate doesn't interfere).
        sessions_file = _make_sessions_file(tmp_path)
        state_path = _make_state_file(tmp_path, {})
        audit, _ = _make_audit(tmp_path)

        from memory.state_manager import add_candidate as _add_candidate
        _add_candidate(
            "api.example.com",
            "/api/address/123",
            "GET",
            body='{"street":"test"}',
            content_type="application/json",
            path=state_path,
        )

        ar = AutoReplay(
            target="api.example.com",
            state_file=state_path,
            sessions_file=sessions_file,
            audit_log=audit,
            allow_write=True,
            transport=capturing_transport,
            _rate_limiter=_null_rate_limiter(),
        )
        ar.run()

        # Transport must have been called with the body bytes.
        assert any(b == b'{"street":"test"}' for b in received_bodies), (
            f"Expected body not found in transport calls; got: {received_bodies}"
        )

    def test_content_type_header_set_when_candidate_has_content_type(self, tmp_path):
        """Content-Type header must be included in the request when stored in candidate."""
        received_headers: list[dict] = []

        def capturing_transport(m, url, h, b, t):
            received_headers.append(dict(h))
            return 200, b"ok", {}

        sessions_file = _make_sessions_file(tmp_path)
        state_path = _make_state_file(tmp_path, {})
        audit, _ = _make_audit(tmp_path)

        from memory.state_manager import add_candidate as _add_candidate
        _add_candidate(
            "api.example.com",
            "/api/profile/update",
            "GET",
            body='{"name":"alice"}',
            content_type="application/json",
            path=state_path,
        )

        ar = AutoReplay(
            target="api.example.com",
            state_file=state_path,
            sessions_file=sessions_file,
            audit_log=audit,
            allow_write=True,
            transport=capturing_transport,
            _rate_limiter=_null_rate_limiter(),
        )
        ar.run()

        assert received_headers, "Transport was never called"
        # Content-Type should appear in at least one call's headers (case-insensitive check).
        combined = " ".join(
            " ".join(f"{k}:{v}" for k, v in h.items()) for h in received_headers
        ).lower()
        assert "content-type" in combined
        assert "application/json" in combined

    def test_allow_write_cli_flag_accepted(self, tmp_path):
        """--allow-write flag must be accepted by the CLI without error."""
        sessions_file = _make_sessions_file(tmp_path)
        state_path = _make_state_file(tmp_path, {})
        audit_path = tmp_path / "audit.jsonl"

        code = main([
            "--target", "api.example.com",
            "--sessions", str(sessions_file),
            "--state-path", str(state_path),
            "--audit-log", str(audit_path),
            "--allow-write",
            "--dry-run",
        ])
        # No candidates → exit 0 (no error parsing the flag).
        assert code == 0

    def test_address_update_path_reachable_with_allow_write(self, tmp_path):
        """address/update path must NOT be hard-blocked (only write-method-gated)."""
        call_log: list[str] = []

        def transport(m, url, h, b, t):
            call_log.append(url)
            return 200, b"ok", {}

        # With allow_write=True and a PUT method, address/update should not be
        # in BLOCKED_PATH_SUBSTRINGS and must reach the transport.
        ar, _, _ = _make_ar(
            tmp_path,
            candidates=[("/api/address/update/456", "PUT")],
            transport=transport,
            allow_write=True,
        )
        results = ar.run()
        assert len(results) == 1
        # Must NOT be blocked by the path blocklist.
        assert results[0].skip_reason != "blocked path substring"
        # Transport was called.
        assert len(call_log) > 0
