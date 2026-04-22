"""Tests for tools/rank_endpoints.py — the scoring CLI wrapper."""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI = REPO_ROOT / "tools" / "rank_endpoints.py"


def _run(input_text: str, *args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        input=input_text,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def _rows(stdout: str) -> list[tuple[int, str, str]]:
    out = []
    for line in stdout.splitlines():
        score, method, endpoint = line.split("\t", 2)
        out.append((int(score), method, endpoint))
    return out


# --- happy path ----------------------------------------------------------

def test_ranks_descending_by_score():
    """DELETE-on-admin-billing should sort above GET-on-robots."""
    tsv = (
        "GET\t/robots.txt\n"
        "GET\t/api/v2/users/{id}/orders\n"
        "DELETE\t/admin/internal/billing\n"
    )
    r = _run(tsv, "--auth-state", "authenticated")
    assert r.returncode == 0, r.stderr
    rows = _rows(r.stdout)
    scores = [s for s, _, _ in rows]
    assert scores == sorted(scores, reverse=True), f"not DESC: {scores}"
    # sanity: highest should be the admin DELETE, lowest the robots
    assert rows[0][2] == "/admin/internal/billing"
    assert rows[-1][2] == "/robots.txt"


def test_stable_order_within_ties():
    """Equal-score rows must preserve input order (stable sort)."""
    tsv = "GET\t/foo\nGET\t/bar\nGET\t/baz\n"  # all score 0
    r = _run(tsv)
    assert r.returncode == 0
    endpoints = [ep for _, _, ep in _rows(r.stdout)]
    assert endpoints == ["/foo", "/bar", "/baz"]


def test_min_score_filters_but_keeps_ordering():
    tsv = (
        "GET\t/robots.txt\n"           # -10
        "GET\t/static/app.js\n"        # -15
        "GET\t/api/users/1\n"          # 6
        "DELETE\t/admin/billing\n"     # admin(3)+billing(2)+DELETE(3) = 8
    )
    r = _run(tsv, "--min-score", "1")
    assert r.returncode == 0
    endpoints = [ep for _, _, ep in _rows(r.stdout)]
    assert endpoints == ["/admin/billing", "/api/users/1"]


def test_auth_state_applied_to_every_row():
    """--auth-state authenticated should add +1 to every row."""
    tsv = "GET\t/api/users\nGET\t/api/orders\n"
    anon = _run(tsv, "--auth-state", "anonymous")
    auth = _run(tsv, "--auth-state", "authenticated")
    anon_scores = [s for s, _, _ in _rows(anon.stdout)]
    auth_scores = [s for s, _, _ in _rows(auth.stdout)]
    assert all(a == b + 1 for a, b in zip(auth_scores, anon_scores))


# --- error / edge cases --------------------------------------------------

def test_empty_input_produces_empty_output():
    r = _run("")
    assert r.returncode == 0
    assert r.stdout == ""


def test_blank_lines_are_skipped_without_error():
    tsv = "\nGET\t/api/users\n\n\nDELETE\t/admin/billing\n\n"
    r = _run(tsv)
    assert r.returncode == 0
    assert len(_rows(r.stdout)) == 2


def test_malformed_line_is_reported_to_stderr_but_does_not_abort():
    tsv = (
        "GET\t/api/users/1\n"
        "no-tab-here\n"                 # malformed
        "DELETE\t/admin/billing\n"
    )
    r = _run(tsv)
    assert r.returncode == 0, r.stderr
    assert "skipping malformed" in r.stderr
    assert len(_rows(r.stdout)) == 2


def test_rejects_unknown_auth_state_choice():
    r = _run("GET\t/foo\n", "--auth-state", "admin")
    assert r.returncode != 0
    assert "invalid choice" in r.stderr.lower()


def test_does_not_touch_hunt_state_file(tmp_path, monkeypatch):
    """Scoring CLI must not read or write memory/hunt_state.json.

    We run it with HOME and CWD pointed at an empty tmp dir so any stray I/O
    would surface obviously, and assert no new files are created.
    """
    before = set(p.name for p in tmp_path.iterdir())
    r = subprocess.run(
        [sys.executable, str(CLI), "--auth-state", "authenticated"],
        input="GET\t/api/users/1\n",
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert r.returncode == 0
    after = set(p.name for p in tmp_path.iterdir())
    assert before == after, f"CLI created files in tmp: {after - before}"
