"""CLI tests for tools/recommend.py (vuln_recommender bash wrapper).

Mirrors the contract autopilot relies on:
    - exit code 0 always
    - stdout = priority-ordered class list, one per line
    - empty stdout = no recommendation (caller skips, must NOT mark dead)
    - never writes any state file
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(REPO / "tools" / "recommend.py")]


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        CLI + list(args),
        cwd=str(cwd or REPO),
        capture_output=True,
        text=True,
        check=False,
    )


def _classes(out: str) -> list[str]:
    return [line for line in out.splitlines() if line]


# ---- Phase D reference cases --------------------------------------------

def test_api_users_id_authenticated_lists_idor_first():
    r = _run("--endpoint", "/api/users/123", "--method", "GET",
             "--auth-state", "authenticated")
    assert r.returncode == 0
    classes = _classes(r.stdout)
    assert classes[0] == "idor"
    for c in ("bac", "api_security"):
        assert c in classes


def test_admin_internal_lists_bac_first():
    r = _run("--endpoint", "/admin/internal", "--method", "GET",
             "--auth-state", "authenticated")
    assert r.returncode == 0
    classes = _classes(r.stdout)
    assert classes[0] == "bac"
    assert "authz" in classes


def test_robots_txt_anonymous_is_empty():
    """Safety property: anonymous /robots.txt yields no recommendation."""
    r = _run("--endpoint", "/robots.txt", "--method", "GET",
             "--auth-state", "anonymous")
    assert r.returncode == 0
    assert _classes(r.stdout) == []


# ---- contract / determinism --------------------------------------------

def test_unknown_auth_state_via_empty_string():
    """Empty `--auth-state` is the documented "unknown" sentinel."""
    r = _run("--endpoint", "/api/users/123", "--method", "GET",
             "--auth-state", "")
    assert r.returncode == 0
    assert "idor" in _classes(r.stdout)


def test_method_defaults_to_get():
    r1 = _run("--endpoint", "/admin/internal", "--auth-state", "authenticated")
    r2 = _run("--endpoint", "/admin/internal", "--method", "GET",
              "--auth-state", "authenticated")
    assert r1.stdout == r2.stdout


def test_deterministic_repeat_calls_match():
    args = ("--endpoint", "/api/v1/orders/42", "--method", "PATCH",
            "--auth-state", "authenticated")
    runs = [_run(*args).stdout for _ in range(3)]
    assert len(set(runs)) == 1


def test_invalid_auth_state_rejected():
    r = _run("--endpoint", "/foo", "--auth-state", "bogus")
    assert r.returncode != 0


def test_no_state_files_written(tmp_path):
    """Recommender CLI must never touch the filesystem."""
    snapshot = sorted(p.name for p in tmp_path.iterdir())
    r = _run("--endpoint", "/api/users/123", "--method", "GET",
             "--auth-state", "authenticated", cwd=tmp_path)
    assert r.returncode == 0
    after = sorted(p.name for p in tmp_path.iterdir())
    assert snapshot == after, f"recommend.py wrote files: {set(after) - set(snapshot)}"


def test_priority_order_is_stable_across_inputs():
    """Tie-break must use canonical CANONICAL_ORDER from vuln_recommender."""
    r = _run("--endpoint", "/admin/internal", "--method", "GET",
             "--auth-state", "authenticated")
    classes = _classes(r.stdout)
    # idor / bac / authz should appear; bac wins (privileged + admin path),
    # idor before authz when scores collide because idor < authz in canonical
    # order. Just assert bac is first; the recommender unit tests cover the
    # full ordering — this one only verifies the CLI surfaces the same list.
    assert classes[0] == "bac"
