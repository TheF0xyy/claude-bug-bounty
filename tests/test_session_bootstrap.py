"""Tests for tools/session_bootstrap.py.

Coverage map
------------
extract_session_material   auth_header extraction, auth cookie inclusion,
                           tracking cookie exclusion, unknown cookie inclusion,
                           notes field, missing auth header/cookies
build_sessions_from_history  two entries, no_auth entry, include_no_auth=False
build_sessions_from_raw_text two raw texts → sessions list, scheme override
build_sessions_from_burp_entries  raw-text Burp entry, fields-only Burp entry
write_sessions_json        file written, valid JSON, parent dirs created,
                           overwrites existing file
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from request_template_extractor import RawRequest, parse_raw_request
from session_bootstrap import (
    extract_session_material,
    build_sessions_from_history,
    build_sessions_from_raw_text,
    build_sessions_from_burp_entries,
    write_sessions_json,
)


# ---------------------------------------------------------------------------
# Sample raw request fixtures
# ---------------------------------------------------------------------------

RAW_A = """\
GET /api/v2/users/54746925 HTTP/1.1\r
Host: api.example.com\r
Authorization: Bearer eyJtoken_a.payload.sig\r
Cookie: sid=sess_a; MZPSID=mz_a; _ga=GA1.2.3; _gid=GA1.2.4\r
X-Domain: example.com\r
Accept: application/json\r
\r
"""

RAW_B = """\
GET /api/v2/users/87654321 HTTP/1.1\r
Host: api.example.com\r
Authorization: Bearer eyJtoken_b.payload.sig\r
Cookie: sid=sess_b; MZPSID=mz_b; _fbp=fb1\r
X-Domain: example.com\r
Accept: application/json\r
\r
"""

RAW_NO_AUTH = """\
GET /api/v2/public/catalog HTTP/1.1\r
Host: api.example.com\r
Accept: application/json\r
\r
"""


def _mk_raw(
    host: str = "example.com",
    path: str = "/test",
    headers: dict | None = None,
    cookies: dict | None = None,
    method: str = "GET",
) -> RawRequest:
    return RawRequest(
        method=method,
        scheme="https",
        host=host,
        path=path,
        query_params={},
        headers=headers or {},
        cookies=cookies or {},
        body=None,
        source="raw_text",
    )


# ---------------------------------------------------------------------------
# extract_session_material
# ---------------------------------------------------------------------------

class TestExtractSessionMaterial:
    def test_name_field(self):
        raw = parse_raw_request(RAW_A)
        entry = extract_session_material(raw, name="account_a")
        assert entry["name"] == "account_a"

    def test_auth_header_extracted(self):
        raw = parse_raw_request(RAW_A)
        entry = extract_session_material(raw, name="account_a")
        assert entry.get("auth_header") is not None
        assert "Bearer" in entry["auth_header"]

    def test_auth_header_not_logged_in_test(self, capsys):
        """Smoke test: auth_header value is in the entry dict, not in stdout."""
        raw = parse_raw_request(RAW_A)
        extract_session_material(raw, name="account_a")
        captured = capsys.readouterr()
        # The function must not print the token value.
        assert "eyJtoken_a" not in captured.out

    def test_auth_cookies_included(self):
        raw = parse_raw_request(RAW_A)
        entry = extract_session_material(raw, name="account_a")
        cookies = entry.get("cookies", {})
        assert "sid" in cookies
        assert "MZPSID" in cookies

    def test_tracking_cookies_excluded(self):
        raw = parse_raw_request(RAW_A)
        entry = extract_session_material(raw, name="account_a")
        cookies = entry.get("cookies", {})
        assert "_ga" not in cookies
        assert "_gid" not in cookies

    def test_tracking_only_entry_has_no_cookies_key(self):
        raw = _mk_raw(cookies={"_ga": "G1", "_gid": "G2"})
        entry = extract_session_material(raw, name="account_a")
        # No non-tracking cookies → omit cookies key entirely (or it's empty).
        cookies = entry.get("cookies", {})
        assert not cookies

    def test_unknown_cookies_included(self):
        """Ambiguous cookies are kept to avoid breaking replay."""
        raw = _mk_raw(cookies={"preferences": "dark", "language": "en"})
        entry = extract_session_material(raw, name="account_a")
        cookies = entry.get("cookies", {})
        assert "preferences" in cookies
        assert "language" in cookies

    def test_no_auth_header_when_absent(self):
        raw = parse_raw_request(RAW_NO_AUTH)
        entry = extract_session_material(raw, name="no_auth")
        assert "auth_header" not in entry or entry.get("auth_header") is None

    def test_notes_field_present(self):
        raw = parse_raw_request(RAW_A)
        entry = extract_session_material(raw, name="account_a")
        assert "notes" in entry
        assert isinstance(entry["notes"], str)
        assert len(entry["notes"]) > 0

    def test_notes_mentions_host(self):
        raw = parse_raw_request(RAW_A)
        entry = extract_session_material(raw, name="account_a")
        assert "api.example.com" in entry["notes"]

    def test_notes_mentions_excluded_tracking(self):
        raw = parse_raw_request(RAW_A)
        entry = extract_session_material(raw, name="account_a")
        # The note should mention that tracking cookies were excluded.
        assert "tracking" in entry["notes"].lower() or "_ga" in entry["notes"]

    def test_structural_headers_not_included(self):
        """Accept, X-Domain etc. are per-request, not per-session."""
        raw = parse_raw_request(RAW_A)
        entry = extract_session_material(raw, name="account_a")
        # sessions.json has: name, cookies, auth_header, notes.
        # Must NOT have structural request headers in top-level.
        assert "X-Domain" not in entry
        assert "Accept" not in entry

    def test_entry_is_json_serialisable(self):
        raw = parse_raw_request(RAW_A)
        entry = extract_session_material(raw, name="account_a")
        blob = json.dumps(entry)   # must not raise
        assert json.loads(blob)["name"] == "account_a"

    def test_default_name(self):
        raw = _mk_raw()
        entry = extract_session_material(raw)
        assert entry["name"] == "account"


# ---------------------------------------------------------------------------
# build_sessions_from_history
# ---------------------------------------------------------------------------

class TestBuildSessionsFromHistory:
    def _build(self, include_no_auth: bool = True) -> list[dict]:
        raw_a = parse_raw_request(RAW_A)
        raw_b = parse_raw_request(RAW_B)
        return build_sessions_from_history(
            [("account_a", raw_a), ("account_b", raw_b)],
            include_no_auth=include_no_auth,
        )

    def test_account_a_present(self):
        sessions = self._build()
        names = [s["name"] for s in sessions]
        assert "account_a" in names

    def test_account_b_present(self):
        sessions = self._build()
        names = [s["name"] for s in sessions]
        assert "account_b" in names

    def test_no_auth_appended_by_default(self):
        sessions = self._build()
        names = [s["name"] for s in sessions]
        assert "no_auth" in names

    def test_no_auth_excluded_when_flag_false(self):
        sessions = self._build(include_no_auth=False)
        names = [s["name"] for s in sessions]
        assert "no_auth" not in names

    def test_no_auth_has_no_credentials(self):
        sessions = self._build()
        no_auth = next(s for s in sessions if s["name"] == "no_auth")
        assert "auth_header" not in no_auth
        assert not no_auth.get("cookies")

    def test_account_a_and_b_are_isolated(self):
        sessions = self._build()
        entry_a = next(s for s in sessions if s["name"] == "account_a")
        entry_b = next(s for s in sessions if s["name"] == "account_b")
        # Different session cookie values.
        a_sid = entry_a.get("cookies", {}).get("sid")
        b_sid = entry_b.get("cookies", {}).get("sid")
        assert a_sid != b_sid

    def test_auth_headers_are_isolated(self):
        sessions = self._build()
        entry_a = next(s for s in sessions if s["name"] == "account_a")
        entry_b = next(s for s in sessions if s["name"] == "account_b")
        assert entry_a["auth_header"] != entry_b["auth_header"]

    def test_result_is_json_serialisable(self):
        sessions = self._build()
        blob = json.dumps(sessions)
        parsed = json.loads(blob)
        assert isinstance(parsed, list)
        assert len(parsed) == 3   # account_a, account_b, no_auth


# ---------------------------------------------------------------------------
# build_sessions_from_raw_text
# ---------------------------------------------------------------------------

class TestBuildSessionsFromRawText:
    def test_account_a_and_b_names(self):
        sessions = build_sessions_from_raw_text(RAW_A, RAW_B)
        names = [s["name"] for s in sessions]
        assert "account_a" in names
        assert "account_b" in names

    def test_no_auth_appended(self):
        sessions = build_sessions_from_raw_text(RAW_A, RAW_B)
        names = [s["name"] for s in sessions]
        assert "no_auth" in names

    def test_scheme_default_https(self):
        sessions = build_sessions_from_raw_text(RAW_A, RAW_B)
        # Both should have notes referencing api.example.com (from Host header).
        entry_a = next(s for s in sessions if s["name"] == "account_a")
        assert "api.example.com" in entry_a["notes"]

    def test_scheme_override(self):
        sessions = build_sessions_from_raw_text(RAW_A, RAW_B, scheme="http")
        # scheme override shouldn't crash and sessions are produced.
        assert len(sessions) == 3

    def test_include_no_auth_false(self):
        sessions = build_sessions_from_raw_text(RAW_A, RAW_B, include_no_auth=False)
        names = [s["name"] for s in sessions]
        assert "no_auth" not in names
        assert len(sessions) == 2

    def test_cookies_extracted(self):
        sessions = build_sessions_from_raw_text(RAW_A, RAW_B)
        entry_a = next(s for s in sessions if s["name"] == "account_a")
        cookies = entry_a.get("cookies", {})
        assert "sid" in cookies or "MZPSID" in cookies

    def test_tracking_excluded_from_raw_text(self):
        sessions = build_sessions_from_raw_text(RAW_A, RAW_B)
        entry_b = next(s for s in sessions if s["name"] == "account_b")
        cookies = entry_b.get("cookies", {})
        assert "_fbp" not in cookies


# ---------------------------------------------------------------------------
# build_sessions_from_burp_entries
# ---------------------------------------------------------------------------

class TestBuildSessionsFromBurpEntries:
    def _entries(self) -> list[tuple[str, dict]]:
        return [
            ("account_a", {
                "host": "api.example.com",
                "port": 443,
                "protocol": "https",
                "request": RAW_A,
                "status": 200,
            }),
            ("account_b", {
                "host": "api.example.com",
                "port": 443,
                "protocol": "https",
                "request": RAW_B,
                "status": 200,
            }),
        ]

    def test_account_names(self):
        sessions = build_sessions_from_burp_entries(self._entries())
        names = [s["name"] for s in sessions]
        assert "account_a" in names
        assert "account_b" in names

    def test_no_auth_appended(self):
        sessions = build_sessions_from_burp_entries(self._entries())
        names = [s["name"] for s in sessions]
        assert "no_auth" in names

    def test_fields_only_burp_entry(self):
        entries = [
            ("account_a", {
                "host": "api.example.com",
                "port": 443,
                "protocol": "https",
                "method": "GET",
                "path": "/api/users/12345",
                "headers": {"Authorization": "Bearer fieldtoken"},
                "cookies": {"session": "sess_x"},
            }),
        ]
        sessions = build_sessions_from_burp_entries(entries, include_no_auth=False)
        assert len(sessions) == 1
        entry = sessions[0]
        assert entry.get("auth_header") is not None
        assert "session" in entry.get("cookies", {})

    def test_result_json_serialisable(self):
        sessions = build_sessions_from_burp_entries(self._entries())
        blob = json.dumps(sessions)
        assert json.loads(blob)


# ---------------------------------------------------------------------------
# write_sessions_json
# ---------------------------------------------------------------------------

class TestWriteSessionsJson:
    def test_file_created(self, tmp_path):
        sessions = [{"name": "account_a", "cookies": {"sid": "x"}}]
        dest = tmp_path / "sessions.json"
        write_sessions_json(sessions, dest)
        assert dest.exists()

    def test_valid_json_written(self, tmp_path):
        sessions = [{"name": "account_a", "cookies": {"sid": "x"}}]
        dest = tmp_path / "sessions.json"
        write_sessions_json(sessions, dest)
        parsed = json.loads(dest.read_text())
        assert isinstance(parsed, list)
        assert parsed[0]["name"] == "account_a"

    def test_parent_dirs_created(self, tmp_path):
        dest = tmp_path / "deep" / "nested" / "sessions.json"
        write_sessions_json([{"name": "a"}], dest)
        assert dest.exists()

    def test_overwrites_existing(self, tmp_path):
        dest = tmp_path / "sessions.json"
        dest.write_text('[{"name": "old"}]')
        write_sessions_json([{"name": "new"}], dest)
        parsed = json.loads(dest.read_text())
        assert parsed[0]["name"] == "new"

    def test_indented_output(self, tmp_path):
        dest = tmp_path / "sessions.json"
        write_sessions_json([{"name": "a"}], dest)
        content = dest.read_text()
        # Indented format should have newlines.
        assert "\n" in content

    def test_full_round_trip(self, tmp_path):
        """Parse two raw requests → build sessions → write → read back."""
        sessions = build_sessions_from_raw_text(RAW_A, RAW_B)
        dest = tmp_path / "memory" / "sessions.json"
        write_sessions_json(sessions, dest)

        loaded = json.loads(dest.read_text())
        names = [s["name"] for s in loaded]
        assert "account_a" in names
        assert "account_b" in names
        assert "no_auth" in names

        # account_a should have auth material.
        entry_a = next(s for s in loaded if s["name"] == "account_a")
        assert entry_a.get("auth_header") is not None
