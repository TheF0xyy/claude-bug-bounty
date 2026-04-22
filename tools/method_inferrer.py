#!/usr/bin/env python3
"""Method inference layer — forward and reverse write-method IDOR/BAC discovery.

Two complementary modes are provided:

Forward inference (``--mode forward``, the original behaviour)
--------------------------------------------------------------
Takes known GET endpoints and probes for write-method availability.
Discovery pipeline for each GET endpoint:
1. Skip if not a resource endpoint (no ID, UUID, or resource keyword).
2. Infer write methods: PUT/PATCH for all resource paths; also DELETE for
   order/subscription/item/invoice paths.
3. OPTIONS probe → prune methods excluded by ``Allow`` header.
4. Write probe (empty JSON body, ``account_a`` only) → classify response:
   - ``high``   — 200/201/204: server accepted.
   - ``medium`` — 400/422: method exists, body rejected.
   - ``medium`` — 401/403: auth required (BAC candidate).
   - ``skip``   — 404/405: not available.
5. For 400/422 outcomes generate a body template from the GET response.
6. Add non-skip candidates to ``hunt_state.json``.

Reverse inference (``--mode reverse``)
---------------------------------------
Takes known PUT/PATCH/DELETE endpoints and probes for three IDOR cases:

  Case A — Read IDOR:
    GET the same path as ``account_a``.
    200 → endpoint is readable → add GET as three-way diff candidate.

  Case B — Cross-account write IDOR:
    Send the write method with ``account_b``'s session against the URL
    (which holds ``account_a``'s resource ID).
    - 200/201/204 → ``account_b`` modified ``account_a``'s resource → high signal.
    - 401 → method exists but auth rejected → medium signal (BAC candidate).
    - 403 → properly protected → skip.

  Case C — ID enumeration:
    If the path contains a numeric ID, probe ID±1 and ID±5 with
    ``account_b``.  Compare body structure to ``account_a``'s GET response.
    Same keys + different values = IDOR candidate.

``--mode both`` (default) runs forward then reverse using the candidates
already present in ``hunt_state.json``.

Safety constraints (all modes)
--------------------------------
- Scope check before every request.
- Rate limit: 1 req/sec per host.
- Dry-run: no HTTP requests, no state writes.
- Credential values never logged.

Usage
-----
    python3 tools/method_inferrer.py --target api.target.com
    python3 tools/method_inferrer.py --target api.target.com --dry-run
    python3 tools/method_inferrer.py --target api.target.com --mode forward
    python3 tools/method_inferrer.py --target api.target.com --mode reverse
    python3 tools/method_inferrer.py --target api.target.com \\
        --endpoints /api/users/42 --mode forward

Exit codes
----------
0 — completed; no candidates found.
1 — at least one candidate was added to hunt_state.json.
2 — configuration or runtime error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

# ── path setup ────────────────────────────────────────────────────────────────
_TOOLS = Path(__file__).resolve().parent
_REPO = _TOOLS.parent
for _p in (str(_TOOLS), str(_REPO)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from session_manager import SessionContext                       # noqa: E402
from replay_diff import RequestTemplate, replay, TransportFn    # noqa: E402
from memory.state_manager import (                              # noqa: E402
    DEFAULT_PATH as _STATE_DEFAULT,
    add_candidate,
    get_candidates,
)
from memory.audit_log import AuditLog, RateLimiter              # noqa: E402
from scope_checker import ScopeChecker                         # noqa: E402


# ── constants ─────────────────────────────────────────────────────────────────

#: UUID pattern (8-4-4-4-12).
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

#: Numeric ID — at least 3 digits (avoids matching years in paths).
_NUMERIC_ID_RE = re.compile(r"^\d{3,}$")

#: Path template placeholders: ``{id}``, ``:id``.
_PLACEHOLDER_RE = re.compile(r"^\{.+\}$|^:.+$")

#: Path segments that indicate the endpoint operates on a specific resource.
_RESOURCE_KEYWORDS: frozenset[str] = frozenset({
    "address", "addresses",
    "profile", "profiles",
    "settings",
    "preferences",
    "account", "accounts",
    "subscription", "subscriptions",
    "order", "orders",
    "payment", "payments",
    "user", "users",
    "item", "items",
    "product", "products",
    "invoice", "invoices",
    "customer", "customers",
})

#: Resource keywords that also warrant DELETE inference.
_DELETE_KEYWORDS: frozenset[str] = frozenset({
    "order", "orders",
    "subscription", "subscriptions",
    "item", "items",
    "invoice", "invoices",
})

#: Status codes indicating the server accepted the write request.
_HIGH_SIGNAL_STATUSES: frozenset[int] = frozenset({200, 201, 204})

#: Status codes indicating the method exists but the body or auth failed.
_MEDIUM_SIGNAL_STATUSES: frozenset[int] = frozenset({400, 401, 403, 422})

#: Status codes indicating the method is not available — skip.
_SKIP_STATUSES: frozenset[int] = frozenset({404, 405})

#: Empty JSON body sent with every write probe.
_EMPTY_JSON_BODY: str = "{}"

#: Placeholder string substituted for string-typed values in body templates.
_PLACEHOLDER_STR: str = "test_value"

_DEFAULT_AUDIT = _REPO / "hunt-memory" / "audit.jsonl"
_DEFAULT_SESSIONS = _REPO / "memory" / "sessions.json"


# ── data structures ───────────────────────────────────────────────────────────


@dataclass
class ProbeOutcome:
    """Result of one write-method probe issued by MethodInferrer.

    Attributes:
        url:             Full URL that was probed.
        method:          HTTP verb (upper-cased).
        status_code:     HTTP response status, or ``None`` on transport error.
        signal:          ``"high"``, ``"medium"``, or ``"skip"``.
        notes:           Human-readable classification reason.
        body_template:   JSON body template when generated (400/422 outcomes
                         where the GET response was parseable JSON).
        allowed_methods: Parsed ``Allow`` header from the OPTIONS probe.
                         Empty frozenset when OPTIONS was not helpful.
        error:           Transport error message when ``status_code`` is ``None``.
    """

    url: str
    method: str
    status_code: Optional[int]
    signal: str  # "high" | "medium" | "skip"
    notes: str
    body_template: Optional[str] = None
    allowed_methods: frozenset[str] = field(default_factory=frozenset)
    error: Optional[str] = None


@dataclass
class InferResult:
    """Result of processing one GET endpoint through method inference.

    Attributes:
        endpoint:    Original endpoint string (path or full URL).
        url:         Full URL with scheme and host.
        skipped:     True when a pre-flight check prevented probing.
        skip_reason: Human-readable reason when ``skipped=True``.
        probes:      Write-method probe outcomes.  Empty when ``skipped=True``.
        added:       ``(method, signal)`` pairs that were added as candidates.
    """

    endpoint: str
    url: str
    skipped: bool
    skip_reason: Optional[str]
    probes: list[ProbeOutcome] = field(default_factory=list)
    added: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        """One-line human-readable summary."""
        if self.skipped:
            return f"[SKIP] {self.url} — {self.skip_reason}"
        if not self.added:
            return f"[NO SIGNAL] {self.url} — no write methods found"
        parts = ", ".join(f"{m}({s})" for m, s in self.added)
        return f"[FOUND] {self.url} — candidates added: {parts}"


@dataclass
class ReverseProbeOutcome:
    """Result of one probe issued during reverse inference.

    Attributes:
        url:           Full URL that was probed.
        method:        HTTP verb (upper-cased).
        session_name:  Name of the session used (``"account_a"`` or ``"account_b"``).
        status_code:   HTTP response status, or ``None`` on transport error.
        signal:        ``"high"``, ``"medium"``, or ``"skip"``.
        case:          Which reverse-inference case produced this probe:
                       ``"read_idor"``, ``"write_idor"``, or ``"id_enum"``.
        notes:         Human-readable classification reason.
        body_template: JSON template used / generated, when available.
        error:         Transport error message when ``status_code`` is ``None``.
    """

    url: str
    method: str
    session_name: str
    status_code: Optional[int]
    signal: str   # "high" | "medium" | "skip"
    case: str     # "read_idor" | "write_idor" | "id_enum"
    notes: str
    body_template: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ReverseInferResult:
    """Result of processing one write endpoint through reverse inference.

    Attributes:
        endpoint:     Original endpoint path (or full URL).
        url:          Full URL with scheme and host.
        write_method: The write method of the original candidate (e.g. ``"PUT"``).
        skipped:      True when a pre-flight check prevented probing.
        skip_reason:  Human-readable reason when ``skipped=True``.
        probes:       All probe outcomes across Cases A, B, and C.
        added:        ``(method, signal, case)`` triples that were added as candidates.
    """

    endpoint: str
    url: str
    write_method: str
    skipped: bool
    skip_reason: Optional[str]
    probes: list[ReverseProbeOutcome] = field(default_factory=list)
    added: list[tuple[str, str, str]] = field(default_factory=list)

    def summary(self) -> str:
        """One-line human-readable summary."""
        if self.skipped:
            return f"[SKIP] {self.write_method} {self.url} — {self.skip_reason}"
        if not self.added:
            return f"[NO SIGNAL] {self.write_method} {self.url} — no reverse IDOR signal"
        parts = ", ".join(f"{m}({s}:{c})" for m, s, c in self.added)
        return f"[FOUND] {self.write_method} {self.url} — candidates: {parts}"


# ── pure helpers ──────────────────────────────────────────────────────────────


def _is_resource_segment(segment: str) -> bool:
    """Return True if *segment* is a numeric ID, UUID, or template placeholder."""
    return bool(
        _NUMERIC_ID_RE.match(segment)
        or _UUID_RE.match(segment)
        or _PLACEHOLDER_RE.match(segment)
    )


def looks_like_resource_endpoint(path: str) -> bool:
    """Return True when *path* appears to operate on a specific resource.

    A path qualifies when any segment is a numeric ID (≥3 digits), UUID,
    ``{id}``/``:id`` placeholder, or a known resource keyword.

    Args:
        path: URL path string (scheme and host must be stripped first).

    Returns:
        ``True`` when the path contains at least one qualifying segment.

    Examples:
        ``/api/users/42``          → True  (numeric ID)
        ``/api/users/42/address``  → True  (ID + resource keyword)
        ``/api/profile``           → True  (resource keyword)
        ``/api/settings``          → True  (resource keyword)
        ``/api/v1/health``         → False
        ``/robots.txt``            → False
    """
    segments = [s for s in path.lower().split("/") if s]
    for seg in segments:
        if _is_resource_segment(seg):
            return True
        if seg in _RESOURCE_KEYWORDS:
            return True
    return False


def infer_write_methods(path: str) -> list[str]:
    """Return write methods to probe for the given GET path.

    All resource endpoints get PUT and PATCH.  Paths that contain a
    DELETE-eligible resource keyword (orders, subscriptions, items,
    invoices) also get DELETE.

    Args:
        path: URL path string.

    Returns:
        List of upper-cased HTTP method strings.
    """
    methods: list[str] = ["PUT", "PATCH"]
    segments = {s for s in path.lower().split("/") if s}
    if segments & _DELETE_KEYWORDS:
        methods.append("DELETE")
    return methods


def parse_allow_header(allow_value: str) -> frozenset[str]:
    """Parse an HTTP ``Allow`` header value into a frozenset of method names.

    Args:
        allow_value: Raw header value, e.g. ``"GET, POST, PUT"``.

    Returns:
        Upper-cased frozenset.  Empty frozenset on blank/unparseable input.
    """
    return frozenset(m.strip().upper() for m in allow_value.split(",") if m.strip())


def generate_body_template(get_body: bytes) -> Optional[str]:
    """Generate a PUT/PATCH body template from a GET response body.

    Parses *get_body* as JSON.  If it is a JSON object, produces a new
    object with the same top-level keys but type-appropriate placeholder
    values:

    - ``str``   → ``"test_value"``
    - ``int``   → ``0``
    - ``float`` → ``0.0``
    - ``bool``  → ``false``
    - ``list``  → ``[]``
    - ``dict``  → ``{}``
    - ``None``  → ``null``

    Args:
        get_body: Raw response body bytes from the GET request.

    Returns:
        JSON string of the template object, or ``None`` when the body is
        not a parseable JSON object.
    """
    if not get_body:
        return None
    try:
        parsed = json.loads(get_body.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None

    template: dict = {}
    for key, value in parsed.items():
        if isinstance(value, bool):
            template[key] = False
        elif isinstance(value, int):
            template[key] = 0
        elif isinstance(value, float):
            template[key] = 0.0
        elif isinstance(value, str):
            template[key] = _PLACEHOLDER_STR
        elif isinstance(value, list):
            template[key] = []
        elif isinstance(value, dict):
            template[key] = {}
        else:
            template[key] = None
    return json.dumps(template)


def extract_numeric_id(path: str) -> Optional[str]:
    """Return the first numeric ID segment (≥3 digits) in *path*, or ``None``.

    Segments are scanned left-to-right; the first matching segment is returned.

    Args:
        path: URL path string.

    Returns:
        The numeric segment string, or ``None`` if none is found.

    Examples:
        ``/api/users/42``   → ``None``  (2 digits, below minimum)
        ``/api/users/123``  → ``"123"``
        ``/api/users/1234/address`` → ``"1234"``
    """
    for seg in path.split("/"):
        if seg and _NUMERIC_ID_RE.match(seg):
            return seg
    return None


def replace_id_in_path(path: str, old_id: str, new_id: str) -> str:
    """Replace the first occurrence of *old_id* as a path segment with *new_id*.

    Only replaces an exact segment match (not a substring match).

    Args:
        path:   URL path string (e.g. ``"/api/users/123/address"``).
        old_id: Exact segment to replace (e.g. ``"123"``).
        new_id: Replacement value (e.g. ``"124"``).

    Returns:
        Modified path string, or *path* unchanged if *old_id* is not a segment.
    """
    parts = path.split("/")
    for i, seg in enumerate(parts):
        if seg == old_id:
            parts[i] = new_id
            return "/".join(parts)
    return path


def _bodies_differ_at_same_structure(body_a: bytes, body_b: bytes) -> bool:
    """Return True when both bodies are JSON objects with identical keys but different values.

    This is the IDOR enumeration heuristic: same schema (same keys) but different
    payload content indicates that the two responses belong to different resources.

    Args:
        body_a: Response body from account_a's GET request.
        body_b: Response body from account_b's GET request on an adjacent ID.

    Returns:
        ``True`` when both parse as JSON objects with the same top-level key set
        but at least one value differs.  ``False`` in all other cases (parse
        error, non-object, different keys, or identical content).
    """
    try:
        a = json.loads(body_a.decode("utf-8", errors="replace"))
        b = json.loads(body_b.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    if set(a.keys()) != set(b.keys()):
        return False  # different schema — cannot compare meaningfully
    return a != b  # same keys, different content → potential IDOR


def _extract_host(url: str) -> str:
    """Return the netloc from a URL string, falling back to the raw string."""
    parts = urlsplit(url if "://" in url else f"https://{url}")
    return parts.netloc or url


def _build_url(endpoint: str, target: str) -> str:
    """Construct a full URL from an endpoint string and target hostname.

    If *endpoint* already has a scheme it is returned unchanged.  Otherwise
    ``https://target`` is prepended.
    """
    if "://" in endpoint:
        return endpoint
    host = target.rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return f"{host}/{endpoint.lstrip('/')}"


def _load_sessions(path: Path) -> dict[str, SessionContext]:
    """Parse a sessions JSON file into ``{name: SessionContext}``.

    Raises:
        FileNotFoundError: Sessions file does not exist.
        ValueError:        File is invalid JSON or has wrong structure.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Sessions file not found: {path}\n"
            "Create memory/sessions.json with account_a and account_b entries.\n"
            "See memory/sessions.example.json for the expected format."
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(raw, list):
        raise ValueError(f"{path} must contain a JSON array of session objects.")
    sessions: dict[str, SessionContext] = {}
    for entry in raw:
        if not isinstance(entry, dict) or "name" not in entry:
            raise ValueError(
                f"Every session entry must have a 'name' field. Got: {entry!r}"
            )
        name = entry["name"]
        sessions[name] = SessionContext(
            name=name,
            cookies=entry.get("cookies") or {},
            headers=entry.get("headers") or {},
            auth_header=entry.get("auth_header") or None,
            notes=entry.get("notes") or "",
        )
    return sessions


# ── orchestrator ──────────────────────────────────────────────────────────────


class MethodInferrer:
    """Probes GET endpoints for write-method availability and generates candidates.

    Uses ``account_a`` credentials only — this is discovery, not differential
    testing.  All discovered write-method candidates are added to
    ``hunt_state.json`` for later cross-account testing by
    ``auto_replay.py --allow-write``.

    Credential privacy guarantee:
        Authorization header values and cookie values are never passed to
        ``AuditLog.log_request()``.

    Attributes:
        target:        Hostname key used in ``hunt_state.json`` lookups.
        state_file:    Path to ``hunt_state.json``.
        sessions_file: Path to ``sessions.json``.
        audit_log:     ``AuditLog`` instance for per-request logging.
    """

    def __init__(
        self,
        target: str,
        state_file: Path,
        sessions_file: Path,
        audit_log: AuditLog,
        *,
        scope_checker: Optional[ScopeChecker] = None,
        transport: Optional[TransportFn] = None,
        _rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        """Initialise the inferrer.

        Args:
            target:        Hostname key for ``hunt_state.json``.
            state_file:    Path to ``hunt_state.json``.
            sessions_file: Path to ``sessions.json``.
            audit_log:     Pre-built ``AuditLog`` for request logging.
            scope_checker: Optional ``ScopeChecker``.  When ``None``, scope
                           checking is disabled.
            transport:     Optional injectable HTTP transport for unit tests.
            _rate_limiter: Optional injectable ``RateLimiter``.  Defaults to
                           1 req/sec.
        """
        self._target = target
        self._state_file = Path(state_file)
        self._sessions_file = Path(sessions_file)
        self._audit = audit_log
        self._scope = scope_checker
        self._transport = transport
        self._rate_limiter: RateLimiter = _rate_limiter or RateLimiter(test_rps=1.0)
        self._sessions: Optional[dict[str, SessionContext]] = None

    # ── session loading ───────────────────────────────────────────────────────

    def _get_sessions(self) -> dict[str, SessionContext]:
        """Return loaded sessions dict, loading from disk on first call."""
        if self._sessions is None:
            self._sessions = _load_sessions(self._sessions_file)
        return self._sessions

    def _get_account_a(self) -> SessionContext:
        """Return the account_a SessionContext.

        Raises:
            ValueError: account_a is not in sessions.json.
        """
        sessions = self._get_sessions()
        if "account_a" not in sessions:
            raise ValueError(
                "account_a session not found in sessions.json — "
                "add it or run /burp-bootstrap first."
            )
        return sessions["account_a"]

    def _get_account_b(self) -> SessionContext:
        """Return the account_b SessionContext.

        Raises:
            ValueError: account_b is not in sessions.json.
        """
        sessions = self._get_sessions()
        if "account_b" not in sessions:
            raise ValueError(
                "account_b session not found in sessions.json — "
                "add it or run /burp-bootstrap first."
            )
        return sessions["account_b"]

    # ── single request ────────────────────────────────────────────────────────

    def _probe_as(
        self,
        url: str,
        method: str,
        session: SessionContext,
        body: Optional[str] = None,
    ) -> tuple[Optional[int], bytes, dict[str, str], Optional[str]]:
        """Issue one request under *session* and return raw response components.

        Rate limiting is applied before the request.  The result is always
        logged to the audit log (including transport errors).  Only the session
        *name* is logged — credential values are never written.

        Args:
            url:     Full URL including scheme.
            method:  HTTP verb (any case; upper-cased internally).
            session: Session context whose credentials are applied to the request.
            body:    Optional request body string (sent as UTF-8 bytes).
                     When provided, ``Content-Type: application/json`` is added.

        Returns:
            ``(status_code, body_bytes, response_headers, error)``
        """
        host = _extract_host(url)
        self._rate_limiter.wait(host)

        base_headers: dict[str, str] = {}
        if body is not None:
            base_headers["Content-Type"] = "application/json"

        template = RequestTemplate(
            method=method, url=url, headers=base_headers, body=body
        )
        result = replay(template, session, timeout=10.0, transport=self._transport)

        self._audit.log_request(
            url=url,
            method=method.upper(),
            scope_check="pass",
            response_status=result.status_code,
            session_id=session.name,
            error=result.error,
        )

        return result.status_code, result.body, result.response_headers, result.error

    def _probe(
        self,
        url: str,
        method: str,
        body: Optional[str] = None,
    ) -> tuple[Optional[int], bytes, dict[str, str], Optional[str]]:
        """Issue one request as account_a (convenience wrapper for ``_probe_as``).

        Args:
            url:    Full URL including scheme.
            method: HTTP verb (any case; upper-cased internally).
            body:   Optional request body string.

        Returns:
            ``(status_code, body_bytes, response_headers, error)``
        """
        return self._probe_as(url, method, self._get_account_a(), body)

    # ── classification ────────────────────────────────────────────────────────

    def _classify_write_probe(
        self, status: Optional[int], error: Optional[str]
    ) -> tuple[str, str]:
        """Return ``(signal, notes)`` for a write-probe response.

        Classification:
            ``"high"``   — 200/201/204: server accepted the write.
            ``"medium"`` — 400/422: method understood, body rejected.
            ``"medium"`` — 401/403: auth required / forbidden (BAC signal).
            ``"skip"``   — 404/405: method not available.
            ``"skip"``   — transport error or any other status.
        """
        if error or status is None:
            return "skip", f"transport error: {error}"
        if status in _HIGH_SIGNAL_STATUSES:
            return "high", f"server accepted write ({status})"
        if status in (400, 422):
            return "medium", f"method understood, body rejected ({status})"
        if status in (401, 403):
            return "medium", f"auth required or forbidden ({status}) — worth cross-account test"
        if status in _SKIP_STATUSES:
            return "skip", f"method not available ({status})"
        return "skip", f"unexpected status {status}"

    # ── main entry point ──────────────────────────────────────────────────────

    def run(
        self, endpoints: list[str], dry_run: bool = False
    ) -> list[InferResult]:
        """Process a list of GET endpoint paths and discover write-method candidates.

        For each endpoint the pipeline is:

        1. Scope check → skip if out of scope.
        2. Resource check → skip if not a resource endpoint.
        3. Infer write methods.
        4. Issue OPTIONS to prune the method list (non-fatal if unhelpful).
        5. Fetch GET to seed body template generation.
        6. Issue write probes and classify responses.
        7. Add non-skip candidates to hunt_state.json.

        In dry-run mode steps 4–7 are skipped (no HTTP requests, no state
        writes) but steps 1–3 still run so the output shows what *would* be
        probed.

        Args:
            endpoints: Paths or full URLs to probe.
            dry_run:   When ``True``, skip all HTTP and state-write calls.

        Returns:
            List of ``InferResult`` objects, one per endpoint.
        """
        output: list[InferResult] = []

        for endpoint in endpoints:
            url = _build_url(endpoint, self._target)
            path = urlsplit(url).path or url

            # 1. Scope check.
            if self._scope is not None and not self._scope.is_in_scope(url):
                self._audit.log_request(
                    url=url,
                    method="GET",
                    scope_check="fail",
                    session_id="method_inferrer",
                    error="out of scope",
                )
                output.append(InferResult(
                    endpoint=endpoint, url=url,
                    skipped=True, skip_reason="out of scope",
                ))
                continue

            # 2. Resource check.
            if not looks_like_resource_endpoint(path):
                output.append(InferResult(
                    endpoint=endpoint, url=url,
                    skipped=True, skip_reason="not a resource endpoint",
                ))
                continue

            # 3. Infer write methods.
            inferred_methods = infer_write_methods(path)

            if dry_run:
                output.append(InferResult(
                    endpoint=endpoint, url=url,
                    skipped=False, skip_reason=None,
                    probes=[
                        ProbeOutcome(
                            url=url, method=m, status_code=None,
                            signal="skip",
                            notes="dry-run: no HTTP requests made",
                        )
                        for m in inferred_methods
                    ],
                ))
                continue

            # 4. OPTIONS probe — discover server-advertised allowed methods.
            allowed_methods: frozenset[str] = frozenset()
            try:
                _, _, opt_headers, opt_err = self._probe(url, "OPTIONS")
                if not opt_err:
                    allow_hdr = opt_headers.get("allow", "")
                    if allow_hdr:
                        allowed_methods = parse_allow_header(allow_hdr)
            except Exception:
                pass  # OPTIONS failure is non-fatal; proceed with all inferred methods

            # 5. GET probe — fetch body for template generation.
            get_body: bytes = b""
            try:
                get_status, get_body_raw, _, get_err = self._probe(url, "GET")
                if not get_err and get_status is not None and get_status < 400:
                    get_body = get_body_raw
            except Exception:
                get_body = b""

            # 6. Write probes.
            probes: list[ProbeOutcome] = []
            added: list[tuple[str, str]] = []

            for method in inferred_methods:
                # Prune using OPTIONS Allow header when it gave a definitive list.
                if allowed_methods and method not in allowed_methods:
                    probes.append(ProbeOutcome(
                        url=url, method=method, status_code=None,
                        signal="skip",
                        notes=f"OPTIONS Allow header excludes {method}",
                        allowed_methods=allowed_methods,
                    ))
                    continue

                # Issue the write probe with an empty JSON body.
                status, _, _, error = self._probe(url, method, body=_EMPTY_JSON_BODY)
                signal, notes = self._classify_write_probe(status, error)

                # Build body template for 400/422 (method understood, body wrong).
                body_template: Optional[str] = None
                if signal == "medium" and status in (400, 422) and get_body:
                    body_template = generate_body_template(get_body)

                probe = ProbeOutcome(
                    url=url, method=method, status_code=status,
                    signal=signal, notes=notes,
                    body_template=body_template,
                    allowed_methods=allowed_methods,
                    error=error,
                )
                probes.append(probe)

                # 7. Add as candidate when there is any signal.
                if signal != "skip":
                    add_candidate(
                        self._target,
                        endpoint,
                        method,
                        body=body_template if body_template else _EMPTY_JSON_BODY,
                        content_type="application/json",
                        path=self._state_file,
                    )
                    added.append((method, signal))

            output.append(InferResult(
                endpoint=endpoint, url=url,
                skipped=False, skip_reason=None,
                probes=probes, added=added,
            ))

        return output


    def run_reverse(
        self,
        endpoints: list[tuple[str, str]],
        dry_run: bool = False,
    ) -> list[ReverseInferResult]:
        """Process a list of known write-endpoint ``(path, method)`` pairs.

        For each pair, three reverse-inference cases are attempted:

        **Case A — Read IDOR**
            GET the same path with ``account_a``.  200 → the resource is
            readable via GET → add a GET candidate for three-way diff testing.

        **Case B — Cross-account write IDOR**
            Send the write method with ``account_b``'s credentials against
            the URL (which contains ``account_a``'s resource ID).

            - 200/201/204 → ``account_b`` modified ``account_a``'s resource
              → high signal; added as candidate.
            - 401 → method exists, auth rejected → medium signal candidate.
            - 403 → properly protected → skip (no candidate added).
            - Other / error → skip.

        **Case C — ID enumeration**
            If the path contains a numeric ID (≥3 digits), probe ID±1 and
            ID±5 with ``account_b``.  Compare body structure to ``account_a``'s
            GET response.  Same top-level JSON keys + different values →
            candidate added with ``"id_enum"`` case label.

        Cases B and C are silently skipped when ``account_b`` is not present
        in ``sessions.json`` (they degrade gracefully to Case A only).

        In dry-run mode all HTTP requests and state writes are suppressed;
        only the scope check runs.

        Args:
            endpoints: ``(path_or_url, write_method)`` pairs to probe.
            dry_run:   When ``True``, no HTTP calls or state writes are made.

        Returns:
            List of ``ReverseInferResult`` objects, one per input pair.
        """
        output: list[ReverseInferResult] = []

        for endpoint, write_method in endpoints:
            write_method = write_method.upper()
            url = _build_url(endpoint, self._target)
            path = urlsplit(url).path or url

            # Scope check.
            if self._scope is not None and not self._scope.is_in_scope(url):
                self._audit.log_request(
                    url=url,
                    method=write_method,
                    scope_check="fail",
                    session_id="method_inferrer",
                    error="out of scope",
                )
                output.append(ReverseInferResult(
                    endpoint=endpoint, url=url,
                    write_method=write_method,
                    skipped=True, skip_reason="out of scope",
                ))
                continue

            if dry_run:
                output.append(ReverseInferResult(
                    endpoint=endpoint, url=url,
                    write_method=write_method,
                    skipped=False, skip_reason=None,
                    probes=[
                        ReverseProbeOutcome(
                            url=url, method="GET", session_name="account_a",
                            status_code=None, signal="skip",
                            case="read_idor",
                            notes="dry-run: no HTTP requests made",
                        ),
                    ],
                ))
                continue

            probes: list[ReverseProbeOutcome] = []
            added: list[tuple[str, str, str]] = []

            # Resolve sessions — account_b is optional.
            try:
                account_a = self._get_account_a()
            except ValueError as exc:
                output.append(ReverseInferResult(
                    endpoint=endpoint, url=url,
                    write_method=write_method,
                    skipped=True, skip_reason=str(exc),
                ))
                continue

            try:
                account_b: Optional[SessionContext] = self._get_account_b()
            except ValueError:
                account_b = None

            # ── Case A: Read IDOR ─────────────────────────────────────────
            get_status_a, get_body_a, _, get_err_a = self._probe_as(
                url, "GET", account_a
            )

            if not get_err_a and get_status_a == 200:
                probes.append(ReverseProbeOutcome(
                    url=url, method="GET", session_name=account_a.name,
                    status_code=get_status_a, signal="medium",
                    case="read_idor",
                    notes="GET 200 on write endpoint — add for three-way diff",
                ))
                add_candidate(
                    self._target, endpoint, "GET",
                    path=self._state_file,
                )
                added.append(("GET", "medium", "read_idor"))
            else:
                _get_note = (
                    f"GET error: {get_err_a}" if get_err_a
                    else f"GET {get_status_a} — no readable endpoint"
                )
                probes.append(ReverseProbeOutcome(
                    url=url, method="GET", session_name=account_a.name,
                    status_code=get_status_a, signal="skip",
                    case="read_idor", notes=_get_note, error=get_err_a,
                ))

            if account_b is None:
                # Cases B and C require account_b — skip gracefully.
                output.append(ReverseInferResult(
                    endpoint=endpoint, url=url,
                    write_method=write_method,
                    skipped=False, skip_reason=None,
                    probes=probes, added=added,
                ))
                continue

            # Body template for write probes — derived from account_a's GET body.
            write_body_template = (
                generate_body_template(get_body_a)
                if not get_err_a and get_body_a
                else None
            )
            write_body = write_body_template or _EMPTY_JSON_BODY

            # ── Case B: Cross-account write IDOR ─────────────────────────
            b_status, _, _, b_err = self._probe_as(
                url, write_method, account_b, body=write_body
            )

            if b_err or b_status is None:
                probes.append(ReverseProbeOutcome(
                    url=url, method=write_method, session_name=account_b.name,
                    status_code=b_status, signal="skip",
                    case="write_idor",
                    notes=f"transport error: {b_err}",
                    body_template=write_body, error=b_err,
                ))
            elif b_status in _HIGH_SIGNAL_STATUSES:
                probes.append(ReverseProbeOutcome(
                    url=url, method=write_method, session_name=account_b.name,
                    status_code=b_status, signal="high",
                    case="write_idor",
                    notes=(
                        f"account_b modified account_a's resource ({b_status})"
                        " — write IDOR signal"
                    ),
                    body_template=write_body,
                ))
                add_candidate(
                    self._target, endpoint, write_method,
                    body=write_body,
                    content_type="application/json",
                    path=self._state_file,
                )
                added.append((write_method, "high", "write_idor"))
            elif b_status == 401:
                probes.append(ReverseProbeOutcome(
                    url=url, method=write_method, session_name=account_b.name,
                    status_code=b_status, signal="medium",
                    case="write_idor",
                    notes="401 — method exists, auth rejected; BAC candidate",
                    body_template=write_body,
                ))
                add_candidate(
                    self._target, endpoint, write_method,
                    body=write_body,
                    content_type="application/json",
                    path=self._state_file,
                )
                added.append((write_method, "medium", "write_idor"))
            elif b_status == 403:
                probes.append(ReverseProbeOutcome(
                    url=url, method=write_method, session_name=account_b.name,
                    status_code=b_status, signal="skip",
                    case="write_idor",
                    notes="403 — properly protected (account_b denied)",
                    body_template=write_body,
                ))
            else:
                probes.append(ReverseProbeOutcome(
                    url=url, method=write_method, session_name=account_b.name,
                    status_code=b_status, signal="skip",
                    case="write_idor",
                    notes=f"unexpected status {b_status}",
                    body_template=write_body,
                ))

            # ── Case C: ID enumeration ────────────────────────────────────
            numeric_id = extract_numeric_id(path)
            if numeric_id is not None:
                try:
                    base_int = int(numeric_id)
                except ValueError:
                    base_int = None

                if base_int is not None:
                    for offset in (-5, -1, 1, 5):
                        candidate_int = base_int + offset
                        if candidate_int <= 0:
                            continue
                        candidate_id = str(candidate_int)
                        candidate_path = replace_id_in_path(path, numeric_id, candidate_id)
                        candidate_url = _build_url(candidate_path, self._target)

                        # Per-URL scope check for enumerated IDs.
                        if (self._scope is not None
                                and not self._scope.is_in_scope(candidate_url)):
                            continue

                        enum_status, enum_body, _, enum_err = self._probe_as(
                            candidate_url, "GET", account_b
                        )

                        if (
                            not enum_err
                            and enum_status == 200
                            and _bodies_differ_at_same_structure(
                                get_body_a, enum_body
                            )
                        ):
                            probes.append(ReverseProbeOutcome(
                                url=candidate_url, method="GET",
                                session_name=account_b.name,
                                status_code=enum_status, signal="high",
                                case="id_enum",
                                notes=(
                                    f"ID enumeration: account_b accessed "
                                    f"{candidate_url} (ID {numeric_id}"
                                    f"{'+' if offset > 0 else ''}{offset}) "
                                    f"— different data, possible IDOR"
                                ),
                            ))
                            add_candidate(
                                self._target, candidate_path, "GET",
                                path=self._state_file,
                            )
                            added.append(("GET", "high", "id_enum"))
                            break  # one confirmed enumeration hit is enough
                        else:
                            probes.append(ReverseProbeOutcome(
                                url=candidate_url, method="GET",
                                session_name=account_b.name,
                                status_code=enum_status, signal="skip",
                                case="id_enum",
                                notes=(
                                    f"ID {numeric_id}{'+' if offset > 0 else ''}{offset}: "
                                    f"status {enum_status}, no IDOR signal"
                                    if not enum_err
                                    else f"ID {numeric_id}{'+' if offset > 0 else ''}{offset}: "
                                         f"transport error"
                                ),
                                error=enum_err,
                            ))

            output.append(ReverseInferResult(
                endpoint=endpoint, url=url,
                write_method=write_method,
                skipped=False, skip_reason=None,
                probes=probes, added=added,
            ))

        return output


# ── CLI ───────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    p = argparse.ArgumentParser(
        prog="method_inferrer",
        description=(
            "Probe GET endpoints for write-method (PUT/PATCH/DELETE) availability "
            "and add discovered candidates to hunt_state.json for cross-account "
            "testing via auto_replay.py --allow-write."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 tools/method_inferrer.py --target api.target.com\n"
            "  python3 tools/method_inferrer.py --target api.target.com --dry-run\n"
            "  python3 tools/method_inferrer.py --target api.target.com "
            "--endpoints /api/users/42\n"
        ),
    )
    p.add_argument(
        "--target", required=True,
        help="Target hostname key in hunt_state.json (e.g. api.target.com).",
    )
    p.add_argument(
        "--sessions",
        default=str(_DEFAULT_SESSIONS),
        metavar="PATH",
        help="Path to sessions.json (default: memory/sessions.json).",
    )
    p.add_argument(
        "--state-path",
        default=str(_STATE_DEFAULT),
        metavar="PATH",
        help="Path to hunt_state.json (default: memory/hunt_state.json).",
    )
    p.add_argument(
        "--audit-log",
        default=str(_DEFAULT_AUDIT),
        metavar="PATH",
        help="Path to audit.jsonl (default: hunt-memory/audit.jsonl).",
    )
    p.add_argument(
        "--scope-domain",
        metavar="PATTERN",
        action="append",
        default=[],
        dest="scope_domains",
        help=(
            "Scope domain pattern (e.g. '*.target.com').  Repeatable.  "
            "When omitted, scope checking is disabled."
        ),
    )
    p.add_argument(
        "--endpoints", "-e",
        metavar="ENDPOINT",
        action="append",
        default=[],
        help=(
            "Endpoint path or full URL to probe (repeatable).  "
            "When omitted, reads GET/HEAD candidates from hunt_state.json."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help=(
            "Identify resource endpoints and infer methods but make no HTTP "
            "requests and no state writes.  Useful for previewing what would "
            "be probed."
        ),
    )
    p.add_argument(
        "--mode",
        choices=["forward", "reverse", "both"],
        default="both",
        help=(
            "Inference mode: "
            "'forward' — probe GET endpoints for write methods (original); "
            "'reverse' — probe write endpoints for read IDOR and cross-account writes; "
            "'both' — run forward first, then reverse (default)."
        ),
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point.

    Returns:
        0 — completed; no candidates found.
        1 — at least one candidate was added to hunt_state.json.
        2 — configuration or runtime error.
    """
    args = _build_parser().parse_args(argv)

    audit = AuditLog(Path(args.audit_log))
    scope: Optional[ScopeChecker] = (
        ScopeChecker(args.scope_domains) if args.scope_domains else None
    )
    state_path = Path(args.state_path)

    mi = MethodInferrer(
        target=args.target,
        state_file=state_path,
        sessions_file=Path(args.sessions),
        audit_log=audit,
        scope_checker=scope,
    )

    any_found = False

    # ── Forward mode ──────────────────────────────────────────────────────────
    if args.mode in ("forward", "both"):
        if args.endpoints:
            fwd_endpoints = args.endpoints
        else:
            candidates = get_candidates(args.target, path=state_path)
            fwd_endpoints = [
                c["endpoint"]
                for c in candidates
                if c.get("method", "GET") in ("GET", "HEAD")
            ]

        if not fwd_endpoints and args.mode == "forward":
            print(
                f"[method-inferrer] No GET/HEAD candidates found for "
                f"{args.target} in {args.state_path}.\n"
                f"Add endpoints with:\n"
                f"  python3 tools/hunt_state.py candidate \\\n"
                f"    --target {args.target} "
                f"--endpoint /path/to/endpoint --method GET\n"
                f"Or run /recon {args.target} first to discover endpoints."
            )
            return 0

        if fwd_endpoints:
            try:
                fwd_results = mi.run(fwd_endpoints, dry_run=args.dry_run)
            except Exception as exc:  # noqa: BLE001
                print(f"[METHOD-INFERRER FORWARD ERROR] {exc}", file=sys.stderr)
                return 2

            fwd_found = [r for r in fwd_results if not r.skipped and r.added]
            for r in fwd_results:
                print(r.summary())
            if fwd_found:
                any_found = True
                print(
                    f"\n[method-inferrer:forward] {len(fwd_found)} endpoint(s) with "
                    f"write-method candidates added."
                )

    # ── Reverse mode ──────────────────────────────────────────────────────────
    if args.mode in ("reverse", "both"):
        if args.endpoints:
            # When --endpoints is given for reverse mode, infer write methods.
            rev_pairs: list[tuple[str, str]] = [
                (ep, m)
                for ep in args.endpoints
                for m in infer_write_methods(
                    urlsplit(_build_url(ep, args.target)).path or ep
                )
            ]
        else:
            # Read write-method candidates from hunt_state.json.
            all_candidates = get_candidates(args.target, path=state_path)
            rev_pairs = [
                (c["endpoint"], c["method"])
                for c in all_candidates
                if c.get("method", "GET") not in ("GET", "HEAD")
                and c.get("status") == "candidate"
            ]

        if not rev_pairs and args.mode == "reverse":
            print(
                f"[method-inferrer] No write-method candidates found for "
                f"{args.target} in {args.state_path}.\n"
                f"Run forward mode first to discover write endpoints:\n"
                f"  python3 tools/method_inferrer.py "
                f"--target {args.target} --mode forward"
            )
            return 0

        if rev_pairs:
            try:
                rev_results = mi.run_reverse(rev_pairs, dry_run=args.dry_run)
            except Exception as exc:  # noqa: BLE001
                print(f"[METHOD-INFERRER REVERSE ERROR] {exc}", file=sys.stderr)
                return 2

            rev_found = [r for r in rev_results if not r.skipped and r.added]
            for r in rev_results:
                print(r.summary())
            if rev_found:
                any_found = True
                print(
                    f"\n[method-inferrer:reverse] {len(rev_found)} endpoint(s) with "
                    f"reverse IDOR candidates added."
                )

    if any_found and not args.dry_run:
        print(
            f"Next: python3 tools/auto_replay.py "
            f"--target {args.target} --allow-write"
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
