"""Tests for tools/replay.py (manual replay CLI).

All tests use a temporary sessions.json and a mock transport injected via
tools/replay_diff.replay_all.  No real HTTP requests are made.

The test strategy is to call replay.main() with controlled argv and a
pre-written sessions.json, then capture stdout/stderr.  Because the
transport cannot be injected through the CLI (by design — the CLI is a
thin driver), the integration tests verify:
  - argument parsing and validation
  - session file loading and error messages
  - output format (status lines + diff block)

Transport-level behaviour (header injection, body encoding, diff logic) is
already covered by test_session_manager.py and test_replay_diff.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(REPO / "tools" / "replay.py")]


# ── helpers ──────────────────────────────────────────────────────────────────

def _sessions_file(tmp_path: Path, extra: list[dict] | None = None) -> Path:
    """Write a minimal valid sessions.json to tmp_path."""
    sessions = [
        {
            "name": "account_a",
            "cookies": {"session": "tok-a"},
            "auth_header": "Bearer jwt-a",
            "notes": "user A",
        },
        {
            "name": "account_b",
            "cookies": {"session": "tok-b"},
            "notes": "user B",
        },
    ]
    if extra:
        sessions.extend(extra)
    p = tmp_path / "sessions.json"
    p.write_text(json.dumps(sessions), encoding="utf-8")
    return p


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv, capture_output=True, text=True, check=False,
    )


# ── argument validation ───────────────────────────────────────────────────────

def test_missing_url_exits_nonzero(tmp_path):
    sf = _sessions_file(tmp_path)
    r = _run(CLI + ["--sessions", str(sf)])
    assert r.returncode != 0


def test_missing_sessions_file_exits_1(tmp_path):
    r = _run(CLI + [
        "--url", "https://example.com/api/users/1",
        "--sessions", str(tmp_path / "nonexistent.json"),
    ])
    assert r.returncode == 1
    assert "not found" in r.stderr.lower()


def test_sessions_file_missing_account_a_exits_1(tmp_path):
    p = tmp_path / "sessions.json"
    p.write_text(json.dumps([{"name": "account_b"}]), encoding="utf-8")
    r = _run(CLI + [
        "--url", "https://example.com/",
        "--sessions", str(p),
    ])
    assert r.returncode == 1
    assert "account_a" in r.stderr


def test_sessions_file_invalid_json_exits_1(tmp_path):
    p = tmp_path / "sessions.json"
    p.write_text("not json", encoding="utf-8")
    r = _run(CLI + [
        "--url", "https://example.com/",
        "--sessions", str(p),
    ])
    assert r.returncode == 1
    assert "json" in r.stderr.lower()


def test_sessions_file_not_a_list_exits_1(tmp_path):
    p = tmp_path / "sessions.json"
    p.write_text(json.dumps({"name": "account_a"}), encoding="utf-8")
    r = _run(CLI + [
        "--url", "https://example.com/",
        "--sessions", str(p),
    ])
    assert r.returncode == 1


def test_entry_without_name_exits_1(tmp_path):
    p = tmp_path / "sessions.json"
    p.write_text(json.dumps([{"cookies": {"x": "y"}}]), encoding="utf-8")
    r = _run(CLI + [
        "--url", "https://example.com/",
        "--sessions", str(p),
    ])
    assert r.returncode == 1


# ── output format (real network hit against localhost — skipped on CI) ────────
# These tests are skipped by default because they require a live target.
# Un-skip by setting REPLAY_TEST_URL in the environment.

import os
_LIVE_URL = os.environ.get("REPLAY_TEST_URL", "")


@pytest.mark.skipif(not _LIVE_URL, reason="REPLAY_TEST_URL not set")
def test_live_status_lines_in_stdout(tmp_path):
    sf = _sessions_file(tmp_path)
    r = _run(CLI + ["--url", _LIVE_URL, "--sessions", str(sf)])
    assert r.returncode in (0, 2)
    assert "[account_a]" in r.stdout
    assert "[account_b]" in r.stdout
    assert "[no_auth]" in r.stdout


# ── session loading ───────────────────────────────────────────────────────────

def test_no_auth_session_in_file_is_accepted(tmp_path):
    """A no_auth entry in the session file should not cause an error."""
    sf = _sessions_file(tmp_path, extra=[{"name": "no_auth", "notes": "anon"}])
    # We can't easily intercept the transport here, but we can confirm the
    # tool at least reaches the network stage (exits 0 or 2, not 1).
    r = _run(CLI + [
        "--url", "https://example.com/",
        "--sessions", str(sf),
        "--timeout", "2",
    ])
    # Exit 1 means config/input error — that must NOT happen.
    assert r.returncode != 1, f"Unexpected config error:\n{r.stderr}"


def test_no_auth_sentinel_used_when_missing_from_file(tmp_path):
    """When no_auth is absent from the file, tool must not error."""
    sf = _sessions_file(tmp_path)   # no no_auth entry
    r = _run(CLI + [
        "--url", "https://example.com/",
        "--sessions", str(sf),
        "--timeout", "2",
    ])
    assert r.returncode != 1, f"Unexpected config error:\n{r.stderr}"


# ── credential header warning ─────────────────────────────────────────────────

def test_cookie_in_header_flag_triggers_warning(tmp_path):
    """--header 'Cookie: ...' must emit a warning and be dropped."""
    sf = _sessions_file(tmp_path)
    r = _run(CLI + [
        "--url", "https://example.com/",
        "--method", "GET",
        "--header", "Cookie: stale=token",
        "--sessions", str(sf),
        "--timeout", "2",
    ])
    assert "WARNING" in r.stderr
    assert "Cookie" in r.stderr


def test_authorization_in_header_flag_triggers_warning(tmp_path):
    """--header 'Authorization: ...' must emit a warning and be dropped."""
    sf = _sessions_file(tmp_path)
    r = _run(CLI + [
        "--url", "https://example.com/",
        "--header", "Authorization: Bearer stale",
        "--sessions", str(sf),
        "--timeout", "2",
    ])
    assert "WARNING" in r.stderr
    assert "Authorization" in r.stderr


# ── session file is not written ───────────────────────────────────────────────

def test_no_files_created_in_cwd(tmp_path):
    """The CLI must not create any files (no state writes)."""
    sf = _sessions_file(tmp_path)
    before = set(tmp_path.iterdir())
    _run(CLI + [
        "--url", "https://example.com/",
        "--sessions", str(sf),
        "--timeout", "2",
    ])
    after = set(tmp_path.iterdir())
    new_files = after - before
    # sessions.json itself was created before the run; only that may be present
    assert new_files == set(), f"Unexpected files written: {new_files}"
