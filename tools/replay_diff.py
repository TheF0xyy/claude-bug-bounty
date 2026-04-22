"""Multi-account request replay and response diffing (MVP).

Replay a single HTTP request under two or three SessionContext objects and
compare the responses to surface IDOR / Broken Access Control / AuthZ signals.

SIGNALS ONLY — NOT FINDINGS
----------------------------
This module produces **observable differences between account contexts**
(signals), not validated vulnerability findings.

    DiffResult.interesting = True
        means: the endpoint behaved differently for two session contexts.
        It is a prompt to investigate, not a confirmed bug.

    DiffResult.interesting = False
        means: responses were identical across contexts tested.
        It does not rule out a vulnerability — it means this probe did not
        surface a measurable difference for the given (method, url, body).

The caller (autopilot, a human hunter, or a validation tool) is responsible
for interpreting signals and deciding whether to escalate to the 7-Question
Gate.  This module never writes to hunt_state.json, never marks anything dead,
and never makes a vulnerability verdict.

Architecture
------------
This module contains no session-management logic — it receives already-built
SessionContext objects from session_manager.py.  The HTTP transport is
injected as a callable (`TransportFn`) so unit tests can mock responses
without touching a real network.  The default transport uses stdlib urllib;
no external dependencies are required.

Typical use
-----------
    from tools.session_manager import SessionContext
    from tools.replay_diff import RequestTemplate, replay_all, compare_all

    template = RequestTemplate(
        method="GET",
        url="https://example.com/api/users/123",
        headers={"Accept": "application/json"},
    )
    account_a = SessionContext(name="account_a", auth_header="Bearer token-a")
    account_b = SessionContext(name="account_b", auth_header="Bearer token-b")

    results = replay_all(template, account_a, account_b)
    for diff in compare_all(results):
        print(diff.summary())
        # SIGNAL ≠ FINDING — escalate to 7-Question Gate before writing a report.
"""

from __future__ import annotations

import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

# Make session_manager importable when this module is run directly or from tests
_TOOLS = Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from session_manager import SessionContext, build_headers  # noqa: E402


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class RequestTemplate:
    """The canonical shape of a request to replay under multiple sessions.

    Attributes:
        method:  HTTP verb. Upper-cased automatically on construction.
        url:     Full URL including scheme and host.
        headers: Base headers applied to every replay before session overrides
                 (e.g. Content-Type, Accept, User-Agent, X-CSRF-Token from Burp).
        body:    Request body. str → encoded to UTF-8; bytes → used as-is;
                 None → no body.  Do not set Content-Length manually; urllib
                 computes it automatically.

    Deferred:
        follow_redirects  MVP always follows urllib's default (same-scheme redirect).
        per_request_timeout  Use the replay() `timeout` param instead.
    """

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str | bytes] = None

    def __post_init__(self) -> None:
        self.method = self.method.upper()


@dataclass
class ReplayResult:
    """Captured response for one (template, session) pair.

    Attributes:
        session_name:     Mirrors SessionContext.name for traceability.
        status_code:      HTTP status code, or None if a network/SSL error occurred.
        body:             Raw response body bytes.
        response_headers: Lower-cased response headers as a flat dict (last value wins
                          for multi-value headers, consistent with urllib).
        elapsed_ms:       Wall-clock round-trip time in milliseconds.
        error:            Non-None string describes the exception when status_code is None.
    """

    session_name: str
    status_code: Optional[int]
    body: bytes
    response_headers: dict[str, str]
    elapsed_ms: float
    error: Optional[str] = None

    @property
    def content_type(self) -> str:
        """Content-Type without parameters, lower-cased (e.g. 'application/json')."""
        ct = self.response_headers.get("content-type", "")
        return ct.split(";")[0].strip().lower()

    @property
    def body_text(self) -> str:
        """Lossy UTF-8 decode of body — for display and logging only."""
        return self.body.decode("utf-8", errors="replace")


@dataclass
class DiffResult:
    """Pairwise comparison of two ReplayResults.

    This is a SIGNAL, not a finding.  `interesting=True` means observable
    behaviour differed between two account contexts and warrants investigation.
    It does not constitute a validated vulnerability.  Run the 7-Question Gate
    before treating any signal as a reportable bug.

    Attributes:
        label:              Human-readable pair name, e.g. "account_a vs account_b".
        a / b:              The two results being compared.
        status_match:       True when both sessions received the same HTTP status.
        body_match:         True when both response bodies are byte-for-byte identical.
        length_delta:       abs(len(a.body) - len(b.body)) in bytes.
        content_type_match: True when both content-types (sans params) match.
        interesting:        True when any dimension above differs — the triage
                            trigger for IDOR / BAC / AuthZ investigation.
                            False does NOT rule out a vulnerability.
    """

    label: str
    a: ReplayResult
    b: ReplayResult
    status_match: bool
    body_match: bool
    length_delta: int
    content_type_match: bool
    interesting: bool

    def summary(self) -> str:
        """One-line human-readable signal summary for autopilot logs.

        Prefix is always 'SIGNAL' (not 'FINDING') to make clear this output
        requires human triage before any report is written.
        """
        flags: list[str] = []
        if not self.status_match:
            flags.append(f"status {self.a.status_code}≠{self.b.status_code}")
        if not self.body_match:
            flags.append(f"body differs (Δ{self.length_delta}B)")
        if not self.content_type_match:
            flags.append(
                f"content-type {self.a.content_type!r}≠{self.b.content_type!r}"
            )
        if not flags:
            return f"[{self.label}] identical — no signal"
        return f"[{self.label}] SIGNAL — {', '.join(flags)}"


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------

# Injectable transport signature.  Tests replace this with a mock; production
# code uses _urllib_transport.  No subprocess, no python -c hacks.
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
    """Default HTTP transport using stdlib urllib (no external deps).

    Returns (status_code, body_bytes, lower-cased response headers).
    On HTTP-level errors (4xx/5xx), captures the error body rather than
    raising, so callers always receive a ReplayResult, never an exception.
    """
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
            if exc.headers
            else {}
        )
        return exc.code, resp_body, resp_headers


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def replay(
    template: RequestTemplate,
    session: SessionContext,
    timeout: float = 10.0,
    transport: Optional[TransportFn] = None,
) -> ReplayResult:
    """Issue one request under a single session context.

    Args:
        template:  The request shape (method, url, base headers, body).
        session:   Account context injected into the request headers.
        timeout:   Network timeout in seconds.
        transport: Optional backend override.  Defaults to urllib.
                   Tests inject a mock here.

    Returns:
        ReplayResult.  Never raises — network errors are captured in .error.
    """
    _transport = transport or _urllib_transport
    merged = build_headers(session, base_headers=template.headers)

    body_bytes: Optional[bytes] = None
    if template.body is not None:
        body_bytes = (
            template.body.encode("utf-8")
            if isinstance(template.body, str)
            else template.body
        )

    t0 = time.monotonic()
    try:
        status, body, resp_headers = _transport(
            template.method, template.url, merged, body_bytes, timeout
        )
        elapsed = (time.monotonic() - t0) * 1000.0
        return ReplayResult(
            session_name=session.name,
            status_code=status,
            body=body,
            response_headers=resp_headers,
            elapsed_ms=elapsed,
        )
    except Exception as exc:
        elapsed = (time.monotonic() - t0) * 1000.0
        return ReplayResult(
            session_name=session.name,
            status_code=None,
            body=b"",
            response_headers={},
            elapsed_ms=elapsed,
            error=str(exc),
        )


def replay_all(
    template: RequestTemplate,
    account_a: SessionContext,
    account_b: SessionContext,
    no_auth: Optional[SessionContext] = None,
    timeout: float = 10.0,
    transport: Optional[TransportFn] = None,
) -> dict[str, ReplayResult]:
    """Replay the template under all provided session contexts.

    Always replays account_a and account_b.  Replays no_auth only when
    provided.  Results are keyed by session name in iteration order.

    Args:
        template:  The request to replay.
        account_a: First session context (primary account).
        account_b: Second session context (cross-account probe).
        no_auth:   Optional unauthenticated context (auth-bypass probe).
        timeout:   Per-request network timeout in seconds.
        transport: Optional injectable HTTP backend for testing.

    Returns:
        {session_name: ReplayResult} — a=first, b=second, no_auth=last (if given).
    """
    sessions = [account_a, account_b]
    if no_auth is not None:
        sessions.append(no_auth)
    return {
        s.name: replay(template, s, timeout=timeout, transport=transport)
        for s in sessions
    }


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------


def diff_results(a: ReplayResult, b: ReplayResult) -> DiffResult:
    """Produce a pairwise diff between two replay results.

    `interesting` is True when any comparison dimension differs.  This is the
    primary triage signal: if interesting is False across all pairings, the
    endpoint behaves identically for all session contexts — low BAC/IDOR signal.
    """
    status_match = a.status_code == b.status_code
    body_match = a.body == b.body
    length_delta = abs(len(a.body) - len(b.body))
    ct_match = a.content_type == b.content_type
    interesting = not (status_match and body_match and ct_match)
    return DiffResult(
        label=f"{a.session_name} vs {b.session_name}",
        a=a,
        b=b,
        status_match=status_match,
        body_match=body_match,
        length_delta=length_delta,
        content_type_match=ct_match,
        interesting=interesting,
    )


def compare_all(results: dict[str, ReplayResult]) -> list[DiffResult]:
    """Produce all pairwise diffs in canonical priority order.

    Priority ordering of pairs:
        1. account_a vs account_b   — core IDOR / BAC signal
        2. account_a vs no_auth     — auth-bypass signal
        3. account_b vs no_auth     — auth-bypass signal
        4. any remaining pairs      — extra sessions (future extension)

    Pairs that cannot be computed because a session name is missing from
    `results` are silently skipped.  No pair is emitted twice.
    """
    PRIORITY_PAIRS = [
        ("account_a", "account_b"),
        ("account_a", "no_auth"),
        ("account_b", "no_auth"),
    ]
    keys = list(results)
    seen: set[frozenset[str]] = set()
    diffs: list[DiffResult] = []

    def _add(a_name: str, b_name: str) -> None:
        key: frozenset[str] = frozenset({a_name, b_name})
        if key in seen:
            return
        if a_name not in results or b_name not in results:
            return
        seen.add(key)
        diffs.append(diff_results(results[a_name], results[b_name]))

    for a_name, b_name in PRIORITY_PAIRS:
        _add(a_name, b_name)

    for i, a_name in enumerate(keys):
        for b_name in keys[i + 1:]:
            _add(a_name, b_name)

    return diffs
