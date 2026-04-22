"""Browser Auth Manager MVP.

Manages stored session credentials for account_a / account_b / no_auth,
validates whether they are still alive against a configurable probe URL,
and exports them in the sessions.json format consumed by tools/replay.py.

What this module IS
-------------------
- A structured store for manually captured session credentials.
- A session validator: probes a URL and reports a precise ValidationStatus.
- An exporter: produces the sessions.json shape that tools/replay.py loads.

What this module is NOT
-----------------------
- Browser automation.  It never launches a browser.
- Login automation.  It never performs a login flow.
- Credential rotation.  Refresh tokens and re-login are deferred.
- MFA / CAPTCHA bypass.  Out of scope entirely.

Typical workflow
----------------
1. Hunter logs into each account manually via browser.
2. Hunter copies session cookies / JWT from DevTools → builds SessionRecords.
3. Validate all sessions before hunting:

       mgr = AuthManager()
       mgr.register(SessionRecord(
           name="account_a",
           cookies={"session": "abc123"},
           auth_header="Bearer eyJ...",
           probe_url="https://api.target.com/api/me",
           notes="test+a@example.com",
       ))
       mgr.register(SessionRecord(
           name="account_b",
           cookies={"session": "xyz789"},
           probe_url="https://api.target.com/api/me",
       ))

       results = mgr.validate_all()
       for name, r in results.items():
           print(f"{name}: {r.state}")
           if r.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED:
               print("  → re-capture session before hunting")

4. Export only valid sessions for tools/replay.py:

       import json
       from pathlib import Path
       valid = mgr.export_sessions(valid_only=True, validation_results=results)
       Path("memory/sessions.json").write_text(json.dumps(valid, indent=2))

5. Run replay as normal (unchanged):

       python3 tools/replay.py --url https://api.target.com/api/users/42 --method GET

Probe URL notes
---------------
Pick a probe URL that returns the expected status directly (no redirect):
  - 200 on /api/me or /api/profile when authenticated.
  - 401 or 403 when the session is invalid / expired.
Avoid URLs that redirect to a login page — urllib follows redirects by
default, so a redirect-to-login would resolve as 200 and give a false
"valid" result.  Either pick a non-redirecting endpoint or set
probe_status_ok to the redirect status code (e.g. 302) and accept that
the probe is checking for the redirect rather than the auth state.
"""

from __future__ import annotations

import copy
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

# ── path setup ────────────────────────────────────────────────────────────────
_TOOLS = Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from session_manager import SessionContext, build_headers  # noqa: E402


# ── HTTP transport (same injectable pattern as replay_diff.py) ────────────────

_RawResponse = tuple[int, bytes, dict[str, str]]
TransportFn = Callable[
    [str, str, dict[str, str], Optional[bytes], float],
    _RawResponse,
]


def _urllib_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: Optional[bytes],
    timeout: float,
) -> _RawResponse:
    """Default transport: follows redirects (urllib default behaviour)."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url, data=body, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            resp_body = resp.read()
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp_body, resp_headers
    except urllib.error.HTTPError as exc:
        resp_body = exc.read() if exc.fp else b""
        resp_headers = (
            {k.lower(): v for k, v in exc.headers.items()}
            if exc.headers else {}
        )
        return exc.code, resp_body, resp_headers


# ── redirect-suppressing transport ────────────────────────────────────────────

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Raise HTTPError instead of following 3xx redirects.

    Used when SessionRecord.follow_redirects=False.  With a standard opener
    urllib would silently follow 302→/login, masking the expired credential
    state as a 200.  This handler surfaces the raw redirect status code so
    the validation logic can classify it as EXPIRED_OR_UNAUTHORIZED.
    """

    def http_error_302(
        self, req: urllib.request.Request, fp, code: int, msg: str, headers
    ) -> None:
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    http_error_301 = http_error_302  # type: ignore[assignment]
    http_error_303 = http_error_302  # type: ignore[assignment]
    http_error_307 = http_error_302  # type: ignore[assignment]
    http_error_308 = http_error_302  # type: ignore[assignment]


def _urllib_transport_no_redirect(
    method: str,
    url: str,
    headers: dict[str, str],
    body: Optional[bytes],
    timeout: float,
) -> _RawResponse:
    """Transport that returns redirect status codes instead of following them."""
    ctx = ssl.create_default_context()
    ssl_handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(_NoRedirectHandler, ssl_handler)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as resp:
            resp_body = resp.read()
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp_body, resp_headers
    except urllib.error.HTTPError as exc:
        resp_body = exc.read() if exc.fp else b""
        resp_headers = (
            {k.lower(): v for k, v in exc.headers.items()}
            if exc.headers else {}
        )
        return exc.code, resp_body, resp_headers


# ── helpers ───────────────────────────────────────────────────────────────────

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _body_text(body: bytes) -> str:
    """Decode response body to str for string-based heuristics."""
    return body.decode("utf-8", errors="ignore")


_REDIRECT_STATUSES: frozenset[int] = frozenset({301, 302, 303, 307, 308})

# ── auto-detection patterns and scoring ──────────────────────────────────────
#
# Used when SessionRecord.auto_detect_login=True.
# Each indicator carries an integer weight; weights are summed and compared to
# auto_detect_threshold.  LOGIN_BODY_INDICATORS use word-boundary matching
# (Phase A) to avoid substring collisions (e.g. "login" in "blogging").
# JSON_AUTH_INDICATORS use quote-wrapped substring matching — the quotes already
# act as boundaries ('"error"' ≠ '"errors"').
#
# Rationale for weights
# ---------------------
# Weight 1 — weak signal: token that appears in many valid responses.
#            Needs combination to reach the default threshold of 2.
# Weight 2 — medium signal: strongly associated with auth UI.
# Weight 3 — strong signal: unambiguous; fires alone.

DETECTION_THRESHOLD: int = 2
"""Default minimum score for auto-detection to classify a session as expired.

Override per session via SessionRecord.auto_detect_threshold.
"""

LOGIN_BODY_INDICATORS: dict[str, int] = {
    "login":           2,
    "sign in":         2,
    "password":        2,
    "session expired": 3,
    "auth":            1,   # weak — only as a standalone token (not "OAuth", "authorization")
}
"""Body-text tokens with weights for login-page detection.

Applied to ALL decoded body text when auto_detect_login=True.
Matching uses word-boundary normalization: non-alpha chars become spaces, then
single-word indicators are matched against the token list and multi-word
indicators are checked as phrases in the normalized text.
All checks are case-insensitive.
"""

JSON_AUTH_INDICATORS: dict[str, int] = {
    '"unauthorized"':      3,
    '"not authenticated"': 3,
    '"authentication"':    2,   # medium — JSON key indicating auth failure
    '"forbidden"':         2,   # medium — access-control rejection
    '"error"':             1,   # weak — needs combination to reach threshold
}
"""JSON key/value fragments with weights for auth-error detection.

Applied only when the body is detected as JSON (Content-Type header or body
prefix heuristic).  The quote-wrapped format prevents false matches on related
keys ('"error"' ≠ '"errors"', '"forbidden"' ≠ '"isForbidden"').
All checks are case-insensitive substring matches on the raw lowercased body
— the quotes already provide sufficient boundary.
"""

EXTENDED_BODY_INDICATORS: dict[str, int] = {
    # Turkish
    "giriş":    2,   # login / entry
    "şifre":    2,   # password
    "oturum":   2,   # session
    # German
    "anmelden": 2,   # sign in
    "passwort": 2,   # password
    # French
    "connexion":    2,   # login / connection
    "mot de passe": 2,   # password (multi-word)
}
"""Optional multilingual login-page indicators.

Enabled when SessionRecord.language_profile == "extended".
Same word-boundary matching as LOGIN_BODY_INDICATORS.
Keep this list short and high-signal — only add patterns that are
unambiguous login-page markers in their respective languages.
"""

# ── text normalisation helpers ────────────────────────────────────────────────

def _normalize_text(text: str) -> str:
    """Lowercase and replace non-alphabetic chars with spaces for token matching.

    Digits and punctuation (including HTML tags, JSON braces, dashes, etc.) are
    replaced with a single space.  Multiple consecutive spaces are collapsed.
    Unicode alphabetic characters (accented, CJK, etc.) are preserved so that
    multilingual indicators work correctly.

    Example: '<H1>Please Login!</H1>' → 'h please login'
    """
    parts: list[str] = []
    for ch in text.lower():
        parts.append(ch if (ch.isalpha() or ch == " ") else " ")
    return " ".join("".join(parts).split())


def _indicator_in_text(normalized: str, indicator: str) -> bool:
    """True if indicator appears with word boundaries in normalised text.

    Single-word indicators are matched as complete tokens (split on spaces).
    Multi-word indicators are matched as a phrase by padding both the
    indicator and the normalised text with a leading/trailing space.

    Examples
    --------
    _indicator_in_text("please login now", "login")        → True
    _indicator_in_text("blogging platform", "login")       → False
    _indicator_in_text("authorization header", "auth")     → False
    _indicator_in_text("auth required", "auth")            → True
    _indicator_in_text("sign in please", "sign in")        → True
    _indicator_in_text("votre mot de passe", "mot de passe") → True
    """
    if " " in indicator:
        return f" {indicator} " in f" {normalized} "
    return indicator in normalized.split()


def _is_json_body(text: str, content_type: str = "") -> bool:
    """Return True if the response body should be treated as JSON.

    Priority:
    1. Content-Type header contains "json"  (reliable, from server).
    2. Body starts with ``{`` or ``[``      (fallback prefix heuristic).
    """
    if "json" in content_type.lower():
        return True
    stripped = text.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def _auto_detect_score(
    text: str,
    is_json: bool = False,
    language_profile: str = "default",
) -> tuple[int, list[str], str]:
    """Compute expiry-likelihood score, matched indicators, and active profile.

    LOGIN_BODY_INDICATORS are matched with word-boundary normalization to avoid
    substring collisions (e.g. "login" does NOT match inside "blogging").
    JSON_AUTH_INDICATORS use quote-wrapped substring matching on raw lowercase
    text and are only applied when is_json=True.
    EXTENDED_BODY_INDICATORS are applied with word-boundary matching when
    language_profile == "extended".

    Returns:
        (score, matched_indicators, matched_profile) where:
        - score          is the total weight sum.
        - matched        lists every indicator string that was found.
        - matched_profile is "extended" when that set was consulted,
                          "default" otherwise.
    """
    normalized = _normalize_text(text)
    lower = text.lower()
    score = 0
    matched: list[str] = []

    for indicator, weight in LOGIN_BODY_INDICATORS.items():
        if _indicator_in_text(normalized, indicator):
            score += weight
            matched.append(indicator)

    if is_json:
        for indicator, weight in JSON_AUTH_INDICATORS.items():
            if indicator in lower:
                score += weight
                matched.append(indicator)

    matched_profile = "default"
    if language_profile == "extended":
        matched_profile = "extended"
        for indicator, weight in EXTENDED_BODY_INDICATORS.items():
            if _indicator_in_text(normalized, indicator):
                score += weight
                matched.append(indicator)

    return score, matched, matched_profile


@dataclass
class _ProbeDecision:
    """Internal result of _classify_probe — carries state and debug metadata.

    Not part of the public API.  Used to populate ValidationResult fields.
    """

    state: str
    reason: str
    matched_indicators: list[str] = field(default_factory=list)
    score: Optional[int] = None
    matched_profile: Optional[str] = None   # set when reason == "auto_detect_login"
    content_mode: Optional[str] = None      # "json" or "text" when body was analysed


def _classify_probe(
    status: int,
    body: bytes,
    probe_status_ok: int,
    probe_contains: Optional[str],
    probe_not_contains: Optional[str],
    auto_detect_login: bool = False,
    auto_detect_threshold: int = DETECTION_THRESHOLD,
    content_type: str = "",
    language_profile: str = "default",
) -> _ProbeDecision:
    """Translate an HTTP probe response into a _ProbeDecision with debug info.

    Decision tree (status == probe_status_ok branch)
    -------------------------------------------------
    1. probe_not_contains set AND found in body
       → EXPIRED  reason="probe_not_contains"  matched=[marker]

    2. probe_contains set AND found in body
       → VALID    reason="probe_contains"       matched=[needle]

    3. probe_contains set AND NOT found in body
       → UNEXPECTED  reason="probe_contains"   matched=[]

    4. auto_detect_login=True AND weighted score >= auto_detect_threshold
       → EXPIRED  reason="auto_detect_login"   matched=[...] score=N
                  matched_profile="default"|"extended"

    5. otherwise
       → VALID    reason="status_code"

    All branches in the status-match block populate content_mode ("json"/"text").

    Status != probe_status_ok
    -------------------------
    6. status in {301, 302, 303, 307, 308}  → EXPIRED  reason="status_code"
    7. status in {401, 403}                 → EXPIRED  reason="status_code"
    8. anything else                        → UNEXPECTED  reason="status_code"

    Note: rule 1 is evaluated before rules 6-8 so probe_status_ok=302 resolves
    to VALID (intentional redirect probe).
    """
    if status == probe_status_ok:
        text = _body_text(body)
        is_json = _is_json_body(text, content_type)
        content_mode = "json" if is_json else "text"

        if probe_not_contains is not None and probe_not_contains in text:
            return _ProbeDecision(
                state=ValidationStatus.EXPIRED_OR_UNAUTHORIZED,
                reason="probe_not_contains",
                matched_indicators=[probe_not_contains],
                content_mode=content_mode,
            )

        if probe_contains is not None:
            if probe_contains in text:
                return _ProbeDecision(
                    state=ValidationStatus.VALID,
                    reason="probe_contains",
                    matched_indicators=[probe_contains],
                    content_mode=content_mode,
                )
            return _ProbeDecision(
                state=ValidationStatus.UNEXPECTED_RESPONSE,
                reason="probe_contains",
                content_mode=content_mode,
            )

        if auto_detect_login:
            score, matched, mprofile = _auto_detect_score(
                text, is_json=is_json, language_profile=language_profile
            )
            if score >= auto_detect_threshold:
                return _ProbeDecision(
                    state=ValidationStatus.EXPIRED_OR_UNAUTHORIZED,
                    reason="auto_detect_login",
                    matched_indicators=matched,
                    score=score,
                    matched_profile=mprofile,
                    content_mode=content_mode,
                )

        return _ProbeDecision(
            state=ValidationStatus.VALID,
            reason="status_code",
            content_mode=content_mode,
        )

    if status in _REDIRECT_STATUSES:
        return _ProbeDecision(
            state=ValidationStatus.EXPIRED_OR_UNAUTHORIZED,
            reason="status_code",
        )

    if status in (401, 403):
        return _ProbeDecision(
            state=ValidationStatus.EXPIRED_OR_UNAUTHORIZED,
            reason="status_code",
        )

    return _ProbeDecision(
        state=ValidationStatus.UNEXPECTED_RESPONSE,
        reason="status_code",
    )


# ── validation status ─────────────────────────────────────────────────────────

class ValidationStatus:
    """String constants for ValidationResult.state.

    Use these for comparisons rather than raw strings:

        if result.state == ValidationStatus.VALID: ...

    States
    ------
    VALID
        The probe returned the expected HTTP status (probe_status_ok).
        The session appears active.

    EXPIRED_OR_UNAUTHORIZED
        The probe returned 401 or 403.  The server explicitly rejected the
        credentials.  Note: 403 may indicate an authorisation boundary rather
        than a true expiry — the session may be live but forbidden on the
        chosen probe URL.

    UNCHECKED
        No probe_url is configured on the SessionRecord.  The session has
        never been verified.  This is not an error state — it means the
        hunter has not yet set a probe URL.

    NETWORK_ERROR
        A network-level exception occurred (timeout, DNS failure, TLS error,
        etc.).  The session may or may not be alive.

    UNEXPECTED_RESPONSE
        The probe returned an HTTP status that is not the expected status,
        not a redirect, and not 401/403 (e.g. 500, 404).  Also returned when
        the status is expected but a probe_contains string is not found in the
        body (correct status, wrong content).  Investigate before hunting.
    """

    VALID = "valid"
    EXPIRED_OR_UNAUTHORIZED = "expired_or_unauthorized"
    UNCHECKED = "unchecked"
    NETWORK_ERROR = "network_error"
    UNEXPECTED_RESPONSE = "unexpected_response"


# ── data structures ───────────────────────────────────────────────────────────

@dataclass
class SessionRecord:
    """Stored credentials + probe config for a single account.

    This is the management-layer counterpart to session_manager.SessionContext.
    SessionContext is thin (replay only).  SessionRecord is richer: it adds
    probe configuration and a capture timestamp.

    Attributes:
        name:               Convention: "account_a", "account_b", "no_auth".
        cookies:            Cookie jar {name: value}.
        headers:            Extra HTTP headers (X-Custom-Auth, CSRF, etc.).
        auth_header:        Full Authorization value: "Bearer ...", "Basic ...".
        notes:              Free-text hunter note.
        probe_url:          URL to probe when validating the session.
                            None → session is marked unchecked (not invalid).
        probe_status_ok:    Expected HTTP status that means "session alive".
                            Default 200.
        probe_method:       HTTP verb for the probe request.  Default GET.
        probe_contains:     Optional string that MUST appear in the response
                            body for the probe to be considered valid.
                            Use to confirm the response is the expected
                            resource (e.g. '"user_id"' to verify /api/me
                            returns a user object, not a generic 200).
        probe_not_contains: Optional string that must NOT appear in the
                            response body.  If found → EXPIRED_OR_UNAUTHORIZED.
                            Use to catch login-page redirects that were
                            followed by urllib: e.g. "Sign in" or
                            'action="/login"'.
        auto_detect_login:      If True, apply the built-in weighted heuristics
                                (LOGIN_BODY_INDICATORS + JSON_AUTH_INDICATORS)
                                to detect session-expiry automatically.
                                Default False — explicit opt-in only.
                                Overridden by probe_contains: if that field is
                                set and found in the body, VALID is returned
                                without running auto-detection.
        auto_detect_threshold:  Minimum score for auto-detection to classify a
                                response as EXPIRED_OR_UNAUTHORIZED.
                                Default DETECTION_THRESHOLD (2).  Raise to
                                require stronger evidence; lower to 1 to treat
                                any single weak indicator as expiry.
        follow_redirects:   If True (default), urllib follows 3xx redirects
                            automatically.  Use probe_not_contains to detect
                            when a followed redirect landed on a login page.
                            If False, a 3xx response is classified directly as
                            EXPIRED_OR_UNAUTHORIZED without following the
                            redirect — useful when the probe endpoint returns
                            302 for expired sessions and 200 for valid ones.
        captured_at:        ISO8601 UTC timestamp when this record was created.
                            Auto-set; override only for testing.

    Deferred fields (not MVP):
        role / permission_level   privilege-escalation rule sets
        user_id / account_id      machine-readable identity cross-reference
        token_expiry / refresh_fn auto-refresh (needs login automation)
        proxy_url                 per-session proxy (needs Burp MCP integration)
    """

    name: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    auth_header: Optional[str] = None
    notes: str = ""
    probe_url: Optional[str] = None
    probe_status_ok: int = 200
    probe_method: str = "GET"
    probe_contains: Optional[str] = None
    probe_not_contains: Optional[str] = None
    auto_detect_login: bool = False
    auto_detect_threshold: int = DETECTION_THRESHOLD
    language_profile: str = "default"
    follow_redirects: bool = True
    captured_at: str = field(default_factory=_utcnow_iso)


@dataclass
class ValidationResult:
    """Outcome of probing one session.

    This is a live health-check result, not a finding.

    The primary field is `state` — a ValidationStatus string constant that
    precisely identifies what happened.  `is_valid` is a convenience bool
    derived from state for code that only needs a binary pass/fail.

    Attributes:
        session_name:        Mirrors SessionRecord.name for traceability.
        state:               One of ValidationStatus.* — the precise outcome.
        is_valid:            True when state == ValidationStatus.VALID.
        status_code:         HTTP status from the probe.  None when no HTTP
                             response was received (UNCHECKED or NETWORK_ERROR).
        elapsed_ms:          Round-trip time in milliseconds.  0.0 when
                             UNCHECKED.
        error:               Non-None for NETWORK_ERROR — describes why no
                             valid HTTP status was obtained.
        checked_at:          ISO8601 UTC timestamp of this check.
        reason:              Short string identifying which rule produced this
                             result.  One of:
                             "status_code"       — plain HTTP status check
                             "probe_not_contains"— explicit body exclusion fired
                             "probe_contains"    — explicit body confirmation
                             "auto_detect_login" — weighted heuristic fired
                             "no_probe_url"      — UNCHECKED: no probe_url set
                             None                — NETWORK_ERROR: see .error
        matched_indicators:  For "probe_not_contains" and "probe_contains":
                             the one string that matched/didn't match.
                             For "auto_detect_login": every indicator string
                             that contributed to the score.
                             Empty list for status-code or error paths.
        score:               Auto-detection score when reason ==
                             "auto_detect_login".  None for all other paths.
        matched_profile:     Indicator set used when reason ==
                             "auto_detect_login": "default" or "extended".
                             None for all other paths.
        content_mode:        How the body was interpreted when auto-detection
                             or content checks ran: "json" or "text".
                             None for status-code-only or error paths.

    Properties:
        is_expired:    True when state == EXPIRED_OR_UNAUTHORIZED.
        is_unchecked:  True when state == UNCHECKED.
    """

    session_name: str
    state: str               # ValidationStatus.*
    is_valid: bool           # convenience: state == ValidationStatus.VALID
    status_code: Optional[int]
    elapsed_ms: float
    error: Optional[str] = None
    checked_at: str = field(default_factory=_utcnow_iso)
    reason: Optional[str] = None
    matched_indicators: list = field(default_factory=list)
    score: Optional[int] = None
    matched_profile: Optional[str] = None
    content_mode: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        """True when the server explicitly rejected the credentials (401/403).

        Note: 403 may indicate an authorisation boundary, not necessarily
        session expiry.  Check session_name context before re-capturing.
        """
        return self.state == ValidationStatus.EXPIRED_OR_UNAUTHORIZED

    @property
    def is_unchecked(self) -> bool:
        """True when no probe_url was configured — session was never verified."""
        return self.state == ValidationStatus.UNCHECKED


# ── AuthManager ───────────────────────────────────────────────────────────────

class AuthManager:
    """Account-isolated session store with validation and export.

    Each account is stored as a separate SessionRecord keyed by name.
    Records are deep-copied on registration and retrieval so external
    mutations cannot affect stored state.

    Core interface
    --------------
    register(record, replace=False)
        Store a session.  Raises ValueError on duplicate name unless
        replace=True.

    get(name) -> SessionRecord
        Retrieve a copy by name.  Raises KeyError if not found.

    list_records() -> list[SessionRecord]
        Return copies of all stored records in insertion order.

    validate(name, timeout=10.0) -> ValidationResult
        Probe one session.  Alias for validate_one().

    validate_all(timeout=10.0) -> dict[str, ValidationResult]
        Probe all sessions.

    export_sessions(names, valid_only, validation_results) -> list[dict]
        Export sessions in sessions.json format for tools/replay.py.
        Never includes management fields (probe_url, captured_at, etc.).

    load_from_sessions_json(path) -> AuthManager   [classmethod]
        Load from an existing sessions.json file.
    """

    def __init__(self) -> None:
        self._records: dict[str, SessionRecord] = {}

    # ── registration ──────────────────────────────────────────────────────

    def register(self, record: SessionRecord, replace: bool = False) -> None:
        """Register a session record.

        Args:
            record:  The session to store.  Deep-copied to prevent external
                     mutation from affecting stored state.
            replace: If False (default), raises ValueError when the name is
                     already registered.  Set True to overwrite deliberately.

        Raises:
            ValueError: If name is already registered and replace=False.
        """
        if record.name in self._records and not replace:
            raise ValueError(
                f"Session '{record.name}' is already registered. "
                "Use replace=True to overwrite deliberately. "
                "This guard prevents accidental credential overwrites."
            )
        self._records[record.name] = copy.deepcopy(record)

    def get(self, name: str) -> SessionRecord:
        """Return a copy of the registered record for name.

        Returns a deep copy — mutations of the returned object do not
        affect the stored record.

        Raises:
            KeyError: If no record is registered with that name.
        """
        if name not in self._records:
            raise KeyError(
                f"No session registered with name '{name}'. "
                f"Registered: {list(self._records)}"
            )
        return copy.deepcopy(self._records[name])

    def names(self) -> list[str]:
        """Return registered session names in insertion order."""
        return list(self._records)

    def list_records(self) -> list[SessionRecord]:
        """Return copies of all stored SessionRecords in insertion order."""
        return [copy.deepcopy(r) for r in self._records.values()]

    # ── validation ────────────────────────────────────────────────────────

    def validate(
        self,
        name: str,
        transport: Optional[TransportFn] = None,
        timeout: float = 10.0,
    ) -> ValidationResult:
        """Probe one session and return its ValidationResult.

        Builds request headers using build_headers() from session_manager so
        the same credential-ownership rules (Cookie / Authorization always
        session-owned) apply to the probe.

        Args:
            name:      Session name to validate.
            transport: Optional injectable HTTP backend (for tests).
            timeout:   Network timeout in seconds.

        Returns:
            ValidationResult with a precise state (see ValidationStatus).
            Never raises — all errors are captured in the result.
        """
        record = self._records[name]

        if not record.probe_url:
            return ValidationResult(
                session_name=name,
                state=ValidationStatus.UNCHECKED,
                is_valid=False,
                status_code=None,
                elapsed_ms=0.0,
                error="no probe_url configured — session is unchecked",
                reason="no_probe_url",
            )

        # Build probe headers via session_manager so Cookie + Authorization
        # ownership rules apply: these headers are always session-owned and
        # are never leaked from a base_headers source.
        ctx = SessionContext(
            name=record.name,
            cookies=record.cookies,
            headers=record.headers,
            auth_header=record.auth_header,
        )
        probe_headers = build_headers(ctx)

        # Choose real transport based on follow_redirects when no mock is
        # injected.  Injected transports are used as-is (tests pass what they
        # want the transport to return; the classification logic is still
        # exercised regardless of the transport choice).
        if transport is not None:
            _transport = transport
        elif record.follow_redirects:
            _transport = _urllib_transport
        else:
            _transport = _urllib_transport_no_redirect

        t0 = time.monotonic()
        try:
            status, body, resp_headers = _transport(
                record.probe_method.upper(),
                record.probe_url,
                probe_headers,
                None,
                timeout,
            )
            content_type = resp_headers.get("content-type", "")
            elapsed = (time.monotonic() - t0) * 1000.0
            decision = _classify_probe(
                status=status,
                body=body,
                probe_status_ok=record.probe_status_ok,
                probe_contains=record.probe_contains,
                probe_not_contains=record.probe_not_contains,
                auto_detect_login=record.auto_detect_login,
                auto_detect_threshold=record.auto_detect_threshold,
                content_type=content_type,
                language_profile=record.language_profile,
            )
            return ValidationResult(
                session_name=name,
                state=decision.state,
                is_valid=(decision.state == ValidationStatus.VALID),
                status_code=status,
                elapsed_ms=elapsed,
                reason=decision.reason,
                matched_indicators=decision.matched_indicators,
                score=decision.score,
                matched_profile=decision.matched_profile,
                content_mode=decision.content_mode,
            )

        except Exception as exc:
            elapsed = (time.monotonic() - t0) * 1000.0
            return ValidationResult(
                session_name=name,
                state=ValidationStatus.NETWORK_ERROR,
                is_valid=False,
                status_code=None,
                elapsed_ms=elapsed,
                error=str(exc),
                reason=None,
            )

    # Alias — kept for backward compatibility with existing call sites.
    validate_one = validate

    def validate_all(
        self,
        transport: Optional[TransportFn] = None,
        timeout: float = 10.0,
    ) -> dict[str, ValidationResult]:
        """Probe all registered sessions.

        Returns:
            {session_name: ValidationResult} in registration order.
        """
        return {
            name: self.validate(name, transport=transport, timeout=timeout)
            for name in self._records
        }

    # ── export ────────────────────────────────────────────────────────────

    def export_sessions(
        self,
        names: Optional[list[str]] = None,
        valid_only: bool = False,
        validation_results: Optional[dict[str, ValidationResult]] = None,
    ) -> list[dict]:
        """Export sessions in sessions.json format for tools/replay.py.

        The exported structure matches memory/sessions.example.json exactly:
            [{"name": ..., "cookies": {...}, "auth_header": ..., "notes": ...}]

        Management-only fields (probe_url, probe_status_ok, probe_method,
        captured_at) are intentionally omitted — they are internal to the
        auth manager and not meaningful to the replay engine.

        Args:
            names:              If provided, export only these names in the
                                given order.  Unknown names are skipped
                                silently.  If None, export all registered
                                sessions in insertion order.
            valid_only:         If True, include only sessions whose
                                ValidationResult.is_valid is True.
                                Requires validation_results.
            validation_results: Output of validate_all() — required when
                                valid_only=True.

        Returns:
            A fresh list of dicts, safe to pass to json.dumps().

        Raises:
            ValueError: If valid_only=True but validation_results is None.
        """
        if valid_only and validation_results is None:
            raise ValueError(
                "validation_results is required when valid_only=True. "
                "Call validate_all() first and pass the result here."
            )

        target_names = names if names is not None else list(self._records)

        result = []
        for name in target_names:
            if name not in self._records:
                continue
            if valid_only:
                vr = validation_results.get(name)  # type: ignore[union-attr]
                if vr is None or not vr.is_valid:
                    continue
            record = self._records[name]
            entry: dict = {"name": name}
            if record.cookies:
                entry["cookies"] = dict(record.cookies)
            if record.headers:
                entry["headers"] = dict(record.headers)
            if record.auth_header is not None:
                entry["auth_header"] = record.auth_header
            if record.notes:
                entry["notes"] = record.notes
            result.append(entry)
        return result

    # Legacy helpers — thin wrappers over export_sessions for callers that
    # used the old two-method API.  Not removed to avoid breaking existing
    # tests or scripts.

    def export_sessions_json(self) -> list[dict]:
        """Export all sessions (no filtering).  Alias for export_sessions()."""
        return self.export_sessions()

    def export_valid_only(
        self, results: dict[str, ValidationResult]
    ) -> list[dict]:
        """Export valid sessions only.  Alias for export_sessions(valid_only=True, ...)."""
        return self.export_sessions(valid_only=True, validation_results=results)

    # ── loading ───────────────────────────────────────────────────────────

    @classmethod
    def load_from_sessions_json(cls, path: Path) -> "AuthManager":
        """Load sessions from an existing sessions.json file.

        Sessions loaded this way have no probe_url — they are 'unchecked'
        until you add probe URLs and call validate_all().

        Args:
            path: Path to a sessions.json file.

        Returns:
            A new AuthManager populated with the loaded sessions.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the JSON is invalid or not a list.
        """
        if not path.exists():
            raise FileNotFoundError(f"Sessions file not found: {path}")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
        if not isinstance(raw, list):
            raise ValueError(f"{path} must contain a JSON array.")

        mgr = cls()
        for entry in raw:
            if not isinstance(entry, dict) or "name" not in entry:
                raise ValueError(
                    f"Each session entry must have a 'name' field. Got: {entry!r}"
                )
            mgr.register(SessionRecord(
                name=entry["name"],
                cookies=entry.get("cookies") or {},
                headers=entry.get("headers") or {},
                auth_header=entry.get("auth_header") or None,
                notes=entry.get("notes") or "",
                # No probe_url in sessions.json → unchecked until configured.
            ))
        return mgr
