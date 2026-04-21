"""Tests for tools/hunt_state.py — check, record, bad reason, wildcard."""

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI = REPO_ROOT / "tools" / "hunt_state.py"


@pytest.fixture
def state_file(tmp_path):
    """Fresh per-test state file path (does not exist yet)."""
    return tmp_path / "hunt_state.json"


def run_cli(*args, state_file):
    """Invoke the CLI as a subprocess the way autopilot would."""
    return subprocess.run(
        [sys.executable, str(CLI), "--state-file", str(state_file), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def test_check_returns_1_on_fresh_state(state_file):
    result = run_cli(
        "check", "--target", "example.com",
        "--endpoint", "/api/users", "--vuln-class", "idor",
        state_file=state_file,
    )
    assert result.returncode == 1
    assert not state_file.exists()


def test_record_then_check_returns_0(state_file):
    rec = run_cli(
        "record", "--target", "example.com",
        "--endpoint", "/api/users", "--vuln-class", "idor",
        "--reason", "no_signal",
        state_file=state_file,
    )
    assert rec.returncode == 0
    assert state_file.exists()

    chk = run_cli(
        "check", "--target", "example.com",
        "--endpoint", "/api/users", "--vuln-class", "idor",
        state_file=state_file,
    )
    assert chk.returncode == 0


def test_invalid_reason_fails(state_file):
    result = run_cli(
        "record", "--target", "example.com",
        "--endpoint", "/api/users", "--vuln-class", "idor",
        "--reason", "bogus",
        state_file=state_file,
    )
    assert result.returncode != 0
    assert "invalid choice" in result.stderr.lower()
    assert not state_file.exists()


def test_empty_vuln_class_is_wildcard(state_file):
    """Recording with --vuln-class '' should match any class on re-check."""
    rec = run_cli(
        "record", "--target", "example.com",
        "--endpoint", "/admin", "--vuln-class", "",
        "--reason", "out_of_scope",
        state_file=state_file,
    )
    assert rec.returncode == 0

    for vc in ("idor", "sqli", "xss", ""):
        chk = run_cli(
            "check", "--target", "example.com",
            "--endpoint", "/admin", "--vuln-class", vc,
            state_file=state_file,
        )
        assert chk.returncode == 0, f"wildcard should match vuln_class={vc!r}"
