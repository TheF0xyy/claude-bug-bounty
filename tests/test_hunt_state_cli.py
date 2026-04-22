"""Tests for tools/hunt_state.py — check, record, bad reason, wildcard,
and context-aware matching on method / auth_state."""

import json
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


# --- context-aware matching: method ----------------------------------------

def test_get_dead_does_not_skip_post(state_file):
    """Recording a dead GET must NOT make the same endpoint look dead for POST."""
    rec = run_cli(
        "record", "--target", "example.com",
        "--endpoint", "/api/items", "--vuln-class", "idor",
        "--method", "GET", "--reason", "no_signal",
        state_file=state_file,
    )
    assert rec.returncode == 0

    chk_get = run_cli(
        "check", "--target", "example.com",
        "--endpoint", "/api/items", "--vuln-class", "idor",
        "--method", "GET",
        state_file=state_file,
    )
    assert chk_get.returncode == 0, "GET probe should match stored GET dead branch"

    chk_post = run_cli(
        "check", "--target", "example.com",
        "--endpoint", "/api/items", "--vuln-class", "idor",
        "--method", "POST",
        state_file=state_file,
    )
    assert chk_post.returncode == 1, "POST probe must NOT match a GET-only dead branch"


def test_empty_method_is_wildcard_on_stored_side(state_file):
    """Record without --method → stored null → matches any method probe."""
    rec = run_cli(
        "record", "--target", "example.com",
        "--endpoint", "/api/widgets", "--vuln-class", "idor",
        "--reason", "no_signal",
        state_file=state_file,
    )
    assert rec.returncode == 0

    for m in ("GET", "POST", "PUT", ""):
        chk = run_cli(
            "check", "--target", "example.com",
            "--endpoint", "/api/widgets", "--vuln-class", "idor",
            "--method", m,
            state_file=state_file,
        )
        assert chk.returncode == 0, f"wildcard method entry should match method={m!r}"


# --- context-aware matching: auth_state ------------------------------------

def test_anonymous_dead_does_not_skip_authenticated(state_file):
    """Anonymous dead must NOT cause a skip under authenticated context."""
    rec = run_cli(
        "record", "--target", "example.com",
        "--endpoint", "/api/me", "--vuln-class", "idor",
        "--auth-state", "anonymous", "--reason", "no_signal",
        state_file=state_file,
    )
    assert rec.returncode == 0

    chk_anon = run_cli(
        "check", "--target", "example.com",
        "--endpoint", "/api/me", "--vuln-class", "idor",
        "--auth-state", "anonymous",
        state_file=state_file,
    )
    assert chk_anon.returncode == 0, "anonymous probe should match stored anonymous dead"

    chk_auth = run_cli(
        "check", "--target", "example.com",
        "--endpoint", "/api/me", "--vuln-class", "idor",
        "--auth-state", "authenticated",
        state_file=state_file,
    )
    assert chk_auth.returncode == 1, (
        "authenticated probe must NOT match an anonymous-only dead branch"
    )


def test_invalid_auth_state_fails(state_file):
    """CLI should reject typos to prevent silent false skips."""
    result = run_cli(
        "record", "--target", "example.com",
        "--endpoint", "/api/me", "--vuln-class", "idor",
        "--auth-state", "anon", "--reason", "no_signal",
        state_file=state_file,
    )
    assert result.returncode != 0
    assert "invalid choice" in result.stderr.lower()
    assert not state_file.exists()


# --- backward compatibility ------------------------------------------------

def test_legacy_entry_without_context_fields_still_matches(state_file, tmp_path):
    """A legacy entry (no method, no auth_state keys) must still match probes.

    This preserves pre-patch behavior for already-written hunt_state.json files.
    """
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({
        "example.com": {
            "dead_branches": [
                {
                    "endpoint": "/legacy",
                    "vuln_class": "idor",
                    "reason": "no_signal",
                    "ts": "2026-04-21T00:00:00Z",
                }
            ]
        }
    }))

    for m, auth in (("GET", "anonymous"), ("POST", "authenticated"), ("", "")):
        chk = run_cli(
            "check", "--target", "example.com",
            "--endpoint", "/legacy", "--vuln-class", "idor",
            "--method", m, "--auth-state", auth,
            state_file=state_file,
        )
        assert chk.returncode == 0, (
            f"legacy entry should match probe method={m!r} auth_state={auth!r}"
        )


def test_record_persists_new_context_fields(state_file):
    """Written entries should include the new keys in the JSON on disk."""
    rec = run_cli(
        "record", "--target", "example.com",
        "--endpoint", "/api/items", "--vuln-class", "idor",
        "--method", "POST", "--auth-state", "authenticated",
        "--reason", "rejected",
        state_file=state_file,
    )
    assert rec.returncode == 0

    data = json.loads(state_file.read_text())
    branches = data["example.com"]["dead_branches"]
    assert len(branches) == 1
    b = branches[0]
    assert b["method"] == "POST"
    assert b["auth_state"] == "authenticated"
    assert b["vuln_class"] == "idor"
    assert b["reason"] == "rejected"


# --- candidate subcommand --------------------------------------------------


def test_candidate_exits_zero(state_file):
    result = run_cli(
        "candidate", "--target", "example.com",
        "--endpoint", "/account/orders/overview",
        "--method", "GET",
        state_file=state_file,
    )
    assert result.returncode == 0


def test_candidate_creates_state_file(state_file):
    run_cli(
        "candidate", "--target", "example.com",
        "--endpoint", "/account/orders/overview",
        "--method", "GET",
        state_file=state_file,
    )
    assert state_file.exists()


def test_candidate_prints_confirmation(state_file):
    result = run_cli(
        "candidate", "--target", "example.com",
        "--endpoint", "/account/orders/overview",
        "--method", "GET",
        state_file=state_file,
    )
    assert "Candidate added" in result.stdout
    assert "/account/orders/overview" in result.stdout
    assert "GET" in result.stdout


def test_candidate_method_uppercased_in_output(state_file):
    result = run_cli(
        "candidate", "--target", "example.com",
        "--endpoint", "/api/me",
        "--method", "get",
        state_file=state_file,
    )
    assert result.returncode == 0
    assert "GET" in result.stdout


def test_candidate_stored_in_json(state_file):
    run_cli(
        "candidate", "--target", "example.com",
        "--endpoint", "/api/orders/123",
        "--method", "GET",
        state_file=state_file,
    )
    data = json.loads(state_file.read_text())
    candidates = data["example.com"]["candidates"]
    assert len(candidates) == 1
    assert candidates[0]["endpoint"] == "/api/orders/123"
    assert candidates[0]["method"] == "GET"
    assert candidates[0]["status"] == "candidate"


def test_candidate_default_method_is_get(state_file):
    result = run_cli(
        "candidate", "--target", "example.com",
        "--endpoint", "/api/profile",
        state_file=state_file,
    )
    assert result.returncode == 0
    data = json.loads(state_file.read_text())
    candidates = data["example.com"]["candidates"]
    assert candidates[0]["method"] == "GET"


def test_candidate_dedup_same_endpoint_and_method(state_file):
    """Adding the same (endpoint, method) twice is a no-op — not an error."""
    for _ in range(2):
        r = run_cli(
            "candidate", "--target", "example.com",
            "--endpoint", "/api/orders/1",
            "--method", "GET",
            state_file=state_file,
        )
        assert r.returncode == 0

    data = json.loads(state_file.read_text())
    candidates = data["example.com"]["candidates"]
    assert len(candidates) == 1, "duplicate candidate must not be stored twice"


def test_candidate_different_methods_stored_separately(state_file):
    for method in ("GET", "HEAD"):
        run_cli(
            "candidate", "--target", "example.com",
            "--endpoint", "/api/orders/1",
            "--method", method,
            state_file=state_file,
        )

    data = json.loads(state_file.read_text())
    candidates = data["example.com"]["candidates"]
    methods = sorted(c["method"] for c in candidates)
    assert methods == ["GET", "HEAD"]


def test_candidate_state_file_flag_works(tmp_path):
    custom = tmp_path / "custom_state.json"
    result = run_cli(
        "candidate", "--target", "example.com",
        "--endpoint", "/api/me",
        "--method", "GET",
        state_file=custom,
    )
    assert result.returncode == 0
    assert custom.exists()


def test_candidate_multiple_targets_isolated(state_file):
    for target in ("alpha.com", "beta.com"):
        run_cli(
            "candidate", "--target", target,
            "--endpoint", "/api/data",
            "--method", "GET",
            state_file=state_file,
        )

    data = json.loads(state_file.read_text())
    assert len(data["alpha.com"]["candidates"]) == 1
    assert len(data["beta.com"]["candidates"]) == 1


# --- existing dedup test ----------------------------------------------------


def test_dedup_respects_method_and_auth_state(state_file):
    """Two records differing only in method should both be stored (not deduped)."""
    for m in ("GET", "POST"):
        rec = run_cli(
            "record", "--target", "example.com",
            "--endpoint", "/api/items", "--vuln-class", "idor",
            "--method", m, "--auth-state", "anonymous",
            "--reason", "no_signal",
            state_file=state_file,
        )
        assert rec.returncode == 0

    # Repeat the GET record — this one should dedup.
    rec = run_cli(
        "record", "--target", "example.com",
        "--endpoint", "/api/items", "--vuln-class", "idor",
        "--method", "GET", "--auth-state", "anonymous",
        "--reason", "no_signal",
        state_file=state_file,
    )
    assert rec.returncode == 0

    data = json.loads(state_file.read_text())
    branches = data["example.com"]["dead_branches"]
    methods = sorted(b["method"] for b in branches)
    assert methods == ["GET", "POST"], branches
