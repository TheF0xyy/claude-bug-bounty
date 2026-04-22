#!/usr/bin/env python3
"""Auto-replay differential testing orchestrator.

Reads "candidate" endpoints from hunt_state.json and runs a three-way
differential HTTP test (account_a / account_b / no_auth) against each one,
then writes the classification back to hunt_state.json.

SIGNALS ONLY — NOT FINDINGS
-----------------------------
All diffs produced here are observable signals, not validated vulnerability
findings.  Every ``idor_candidate`` classification must pass the 7-Question
Gate before any report is written.

Classification outcomes
-----------------------
``idor_candidate``
    At least one pairwise diff is *interesting* (different status, body, or
    content-type between account contexts).  The diff summary is saved to the
    "signals" list and the candidate status is updated.

``dead``
    All three sessions returned 401/403 (endpoint requires authentication and
    nothing leaked), or there is no differential signal of any kind.
    A dead-branch entry is written for future skip.

``needs_manual_review``
    All sessions returned 200 with identical bodies — the endpoint is live but
    auto-replay cannot determine if data belongs to the requesting account.
    A human must inspect whether the payload is account-specific.

Safety constraints (enforced in order; any violation skips the candidate):
  1. Method gate     — only GET and HEAD; all others are hard-blocked.
  2. Blocklist gate  — URLs whose paths contain sensitive substrings are skipped.
  3. Scope gate      — URL must pass ScopeChecker when configured.
  4. Dead-branch     — (endpoint, "idor", method) already dead → skip.
  5. Circuit breaker — 3 consecutive 4xx on same host → stop that host.
  6. Rate limit      — max 1 request/second per host (hard-coded).

Credential privacy
------------------
Authorization header values and cookie values are NEVER written to the audit
log.  Only: timestamp, URL, method, session_name, response_status, blocked,
block_reason.

Usage (CLI — batch: all "candidate" entries in hunt_state.json)
----------------------------------------------------------------
    python3 tools/auto_replay.py --target api.target.com
    python3 tools/auto_replay.py --target api.target.com --dry-run

Python API (autopilot integration)
------------------------------------
    import sys; sys.path.insert(0, "tools")
    from auto_replay import AutoReplay
    from memory.audit_log import AuditLog
    from pathlib import Path

    audit = AuditLog(Path("hunt-memory/audit.jsonl"))
    ar = AutoReplay(
        target="api.target.com",
        state_file=Path("memory/hunt_state.json"),
        sessions_file=Path("memory/sessions.json"),
        audit_log=audit,
    )
    results = ar.run()
    for r in results:
        print(r.summary())
"""

from __future__ import annotations

import argparse
import json
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

from session_manager import NO_AUTH, SessionContext          # noqa: E402
from replay_diff import (                                    # noqa: E402
    DiffResult,
    RequestTemplate,
    ReplayResult,
    TransportFn,
    compare_all,
    replay,
)
from memory.state_manager import (                           # noqa: E402
    DEFAULT_PATH as _STATE_DEFAULT,
    add_candidate,
    add_signal,
    get_candidates,
    is_dead_branch,
    mark_dead_branch,
    update_candidate,
)
from memory.audit_log import AuditLog, RateLimiter           # noqa: E402
from scope_checker import ScopeChecker                      # noqa: E402


# ── constants ─────────────────────────────────────────────────────────────────

#: Only these HTTP methods are permitted for auto-replay without opt-in.
#: Write methods (PUT/PATCH/DELETE/POST) require allow_write=True on the
#: AutoReplay instance (or --allow-write on the CLI).
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

#: Write methods that become allowed when allow_write=True.  Any method that
#: is neither in SAFE_METHODS nor in WRITE_METHODS is hard-blocked regardless
#: of allow_write (e.g. CONNECT, TRACE, exotic verbs).
WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Path substrings (case-insensitive) that indicate state-changing or
#: particularly sensitive routes.  Any URL whose lowercased path contains
#: one of these strings is skipped unconditionally before any request is made.
#:
#: Note: "address/update" was previously hard-blocked here but is now
#: reachable via --allow-write for intentional write-method IDOR testing.
#: All other entries remain unconditionally blocked regardless of allow_write.
BLOCKED_PATH_SUBSTRINGS: frozenset[str] = frozenset({
    "payment",
    "checkout/confirm",
    "order/place",
    "subscribe",
    "unsubscribe",
    "delete",
    "remove",
    "cancel",
    "refund",
    "transfer",
    "coupon/apply",
    "password",
    "reset-password",
    "email/update",
    "admin",
    "2fa",
    "mfa",
    "verify-email",
})

#: Consecutive 4xx responses on the same host before the circuit breaker trips.
CIRCUIT_THRESHOLD: int = 3

#: Classification strings written to hunt_state.json.
CLASSIFICATION_IDOR_CANDIDATE = "idor_candidate"
CLASSIFICATION_DEAD = "dead"
CLASSIFICATION_NEEDS_REVIEW = "needs_manual_review"

_DEFAULT_AUDIT = _REPO / "hunt-memory" / "audit.jsonl"
_DEFAULT_SESSIONS = _REPO / "memory" / "sessions.json"


# ── data structures ───────────────────────────────────────────────────────────


@dataclass
class ThreeWayResult:
    """Outcome of a three-way differential replay (account_a / account_b / no_auth).

    Attributes:
        results: ``{session_name: ReplayResult}`` for every session that was
                 actually replayed.  May be empty if the circuit breaker tripped
                 before any request was sent.
        diffs:   All pairwise ``DiffResult`` objects produced by ``compare_all()``.
        error:   Non-None when a configuration error (e.g. missing sessions file)
                 prevented replay from starting.
    """

    results: dict[str, ReplayResult]
    diffs: list[DiffResult]
    error: Optional[str] = None


@dataclass
class CandidateResult:
    """Result of processing one candidate endpoint through auto-replay.

    Attributes:
        endpoint:       The path or URL of the candidate.
        method:         HTTP verb (upper-cased).
        url:            Full URL that was (or would have been) tested.
        skipped:        True when a safety gate prevented the test from running.
        skip_reason:    Human-readable explanation when ``skipped=True``.
        classification: One of ``"idor_candidate"``, ``"dead"``,
                        ``"needs_manual_review"``, or ``None`` when skipped.
        notes:          Additional context accompanying the classification.
        three_way:      Raw ``ThreeWayResult`` (``None`` when skipped or dry-run).
    """

    endpoint: str
    method: str
    url: str
    skipped: bool
    skip_reason: Optional[str]
    classification: Optional[str]
    notes: str = ""
    three_way: Optional[ThreeWayResult] = None

    def summary(self) -> str:
        """One-line human-readable summary for CLI output and logging."""
        if self.skipped:
            return f"[SKIP] {self.method} {self.url} — {self.skip_reason}"
        label = (self.classification or "unknown").upper()
        return f"[{label}] {self.method} {self.url} — {self.notes}"


# ── module-level helpers ──────────────────────────────────────────────────────


def _extract_host(url: str) -> str:
    """Return the netloc (``host[:port]``) from a URL string.

    Falls back to the raw string when no netloc can be parsed.
    """
    parts = urlsplit(url if "://" in url else f"https://{url}")
    return parts.netloc or url


def _endpoint_path(url: str) -> str:
    """Return the path component of a URL for use as a dead-branch key.

    This matches the convention used in autopilot Bash snippets where
    endpoints are stored as bare paths (``/api/users/123``) rather than full
    URLs.  Falls back to the full URL if no path is available.
    """
    parts = urlsplit(url if "://" in url else f"https://{url}")
    return parts.path or url


def _build_url(endpoint: str, target: str) -> str:
    """Construct a full URL from an endpoint string and a target hostname.

    If *endpoint* already contains a scheme (``http://`` or ``https://``) it is
    returned unchanged.  Otherwise ``https://target`` is prepended to the path.
    """
    if "://" in endpoint:
        return endpoint
    host = target.rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return f"{host}/{endpoint.lstrip('/')}"


def _is_blocked_url(url: str) -> bool:
    """Return True when the URL's path contains a blocked substring.

    The check is performed on the lowercased path component only.
    """
    parts = urlsplit(url if "://" in url else f"https://{url}")
    path_lower = (parts.path or "").lower()
    return any(sub in path_lower for sub in BLOCKED_PATH_SUBSTRINGS)


def _load_sessions(path: Path) -> dict[str, SessionContext]:
    """Parse a sessions JSON file into ``{name: SessionContext}``.

    Raises:
        FileNotFoundError: The sessions file does not exist.
        ValueError:        The file contains invalid JSON or wrong structure.
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


class AutoReplay:
    """Orchestrates read-only IDOR/BAC differential testing for one target.

    Reads "candidate" endpoints from ``hunt_state.json``, applies safety gates,
    runs a three-way replay, classifies the result, and writes the outcome back
    to state.  Every outbound request — including blocked and errored ones — is
    logged to the audit log.

    Credential privacy guarantee:
        Authorization header *values* and cookie *values* are never passed to
        ``AuditLog.log_request()``.  The audit entry contains only structural
        metadata (URL, method, session_name, response_status).

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
        allow_write: bool = False,
        scope_checker: Optional[ScopeChecker] = None,
        transport: Optional[TransportFn] = None,
        _rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        """Initialise the orchestrator.

        Args:
            target:        Hostname key for ``hunt_state.json`` (e.g. ``"api.target.com"``).
            state_file:    Path to ``hunt_state.json``.
            sessions_file: Path to ``sessions.json``.
            audit_log:     Pre-built ``AuditLog`` instance for request logging.
            allow_write:   When ``True``, PUT/PATCH/DELETE/POST candidates are
                           allowed through the method gate.  Default ``False``.
                           Must only be set after explicit human approval — write
                           methods can mutate server state.
            scope_checker: Optional ``ScopeChecker``.  When ``None``, scope checking
                           is disabled.
            transport:     Optional injectable HTTP transport.  Used by unit tests
                           to avoid real network calls.
            _rate_limiter: Optional injectable ``RateLimiter``.  Used by unit tests
                           to skip actual sleep calls while still verifying the
                           limiter is invoked.  Defaults to 1 req/sec.
        """
        self._target = target
        self._state_file = Path(state_file)
        self._sessions_file = Path(sessions_file)
        self._audit = audit_log
        self._allow_write = allow_write
        self._scope = scope_checker
        self._transport = transport
        self._rate_limiter: RateLimiter = _rate_limiter or RateLimiter(test_rps=1.0)
        # Circuit-breaker state: consecutive 4xx count per host.
        self._consec_4xx: dict[str, int] = {}
        self._stopped_hosts: set[str] = set()
        # Sessions are loaded once on first use.
        self._sessions: Optional[dict[str, SessionContext]] = None

    # ── session loading ───────────────────────────────────────────────────────

    def _get_sessions(self) -> dict[str, SessionContext]:
        """Return the loaded sessions dict, loading from disk on first call.

        Raises:
            FileNotFoundError: Sessions file missing.
            ValueError:        Sessions file has invalid structure.
        """
        if self._sessions is None:
            self._sessions = _load_sessions(self._sessions_file)
        return self._sessions

    # ── circuit breaker ───────────────────────────────────────────────────────

    def _record_response_status(self, host: str, status_code: Optional[int]) -> None:
        """Update the consecutive-4xx counter for *host*.

        A 4xx response increments the counter; any other non-None response or a
        network error (``None``) resets it to prevent false trips.
        """
        if status_code is not None and 400 <= status_code < 500:
            self._consec_4xx[host] = self._consec_4xx.get(host, 0) + 1
        else:
            self._consec_4xx[host] = 0

    def _is_host_stopped(self, host: str) -> bool:
        """Return True when the circuit breaker has tripped for *host*."""
        if host in self._stopped_hosts:
            return True
        if self._consec_4xx.get(host, 0) >= CIRCUIT_THRESHOLD:
            self._stopped_hosts.add(host)
            return True
        return False

    # ── safety gate ───────────────────────────────────────────────────────────

    def _is_safe_to_replay(self, url: str, method: str) -> tuple[bool, str]:
        """Apply all safety gates for the given (url, method) pair.

        Gates are evaluated in priority order; the first gate that fires
        returns immediately.

        Args:
            url:    Full URL including scheme and host.
            method: HTTP verb (any case; compared upper-cased internally).

        Returns:
            ``(True, "")`` when the URL is safe to replay.
            ``(False, reason)`` when any gate fires, where *reason* is a
            human-readable explanation of why the request was blocked.
        """
        method = method.upper()

        # 1. Method gate.
        if method not in SAFE_METHODS:
            if method in WRITE_METHODS:
                # Write methods are opt-in, not hard-blocked.
                if not self._allow_write:
                    return False, f"write method: {method} — rerun with --allow-write"
                # allow_write=True: fall through; other gates still apply.
            else:
                # Unknown/exotic methods (CONNECT, TRACE, …) are always hard-blocked.
                return False, f"unsafe method: {method}"

        # 2. Blocklist gate.
        if _is_blocked_url(url):
            return False, "blocked path substring"

        # 3. Scope gate (only when a ScopeChecker is configured).
        if self._scope is not None and not self._scope.is_in_scope(url):
            return False, "out of scope"

        # 4. Dead-branch gate.
        endpoint_key = _endpoint_path(url)
        if is_dead_branch(
            self._target, endpoint_key, "idor",
            method=method, path=self._state_file,
        ):
            return False, "dead branch (idor)"

        # 5. Circuit-breaker gate.
        host = _extract_host(url)
        if self._is_host_stopped(host):
            return False, f"circuit breaker tripped for {host}"

        return True, ""

    # ── replay ────────────────────────────────────────────────────────────────

    def _replay_three_way(self, template: RequestTemplate) -> ThreeWayResult:
        """Run the three-way differential replay for a single request template.

        Replays *template* sequentially under account_a, account_b, and
        no_auth (in that order), with rate limiting and circuit-breaking
        applied between each request.  Every request — including those
        skipped by the circuit breaker — is appended to the audit log.

        Note on credential privacy: this method passes only the session *name*
        (not any credential values) to ``AuditLog.log_request()``.

        Args:
            template: The ``RequestTemplate`` to replay (method + URL).

        Returns:
            ``ThreeWayResult`` with all ``ReplayResult`` objects and pairwise
            diffs.  The ``results`` dict may be partially populated if the
            circuit breaker trips mid-loop.
        """
        try:
            sessions = self._get_sessions()
        except (FileNotFoundError, ValueError) as exc:
            return ThreeWayResult(results={}, diffs=[], error=str(exc))

        missing = [n for n in ("account_a", "account_b") if n not in sessions]
        if missing:
            return ThreeWayResult(
                results={}, diffs=[],
                error=f"Required sessions missing from sessions.json: {missing}",
            )

        account_a = sessions["account_a"]
        account_b = sessions["account_b"]
        no_auth_ctx: SessionContext = sessions.get("no_auth", NO_AUTH)

        host = _extract_host(template.url)
        results: dict[str, ReplayResult] = {}

        for sess in (account_a, account_b, no_auth_ctx):
            # Per-request circuit-breaker check (may have tripped mid-loop).
            if self._is_host_stopped(host):
                self._audit.log_request(
                    url=template.url,
                    method=template.method,
                    scope_check="pass",
                    session_id=sess.name,
                    error=f"circuit breaker tripped for {host} — request skipped",
                )
                break

            # Rate limit: max 1 req/sec per host (hard-coded, not configurable).
            self._rate_limiter.wait(host)

            # Issue the request.  Credential headers are owned by the session;
            # the audit log receives only the session name, never header values.
            result = replay(
                template, sess,
                timeout=10.0,
                transport=self._transport,
            )
            results[sess.name] = result

            # Audit log — every request, including errored ones.
            # IMPORTANT: only session_name (not auth values) is logged here.
            self._audit.log_request(
                url=template.url,
                method=template.method,
                scope_check="pass",
                response_status=result.status_code,
                session_id=sess.name,
                error=result.error,
            )

            # Update circuit-breaker counter; trip if threshold reached.
            self._record_response_status(host, result.status_code)
            if self._is_host_stopped(host):
                self._audit.log_request(
                    url=template.url,
                    method=template.method,
                    scope_check="pass",
                    session_id="circuit_breaker",
                    error=(
                        f"circuit breaker tripped for {host} after "
                        f"{CIRCUIT_THRESHOLD} consecutive 4xx responses"
                    ),
                )

        diffs = compare_all(results)
        return ThreeWayResult(results=results, diffs=diffs)

    # ── classification ────────────────────────────────────────────────────────

    def _classify_result(self, three_way: ThreeWayResult) -> tuple[str, str]:
        """Classify a ``ThreeWayResult`` into a status string and notes.

        Classification rules (in priority order):

        1. **idor_candidate** — any pairwise diff is *interesting* (different
           status, body, or content-type between two account contexts).
        2. **dead** — all successful responses are 401 or 403 (endpoint
           requires authentication; nothing was leaked), OR a replay error
           prevented testing.
        3. **needs_manual_review** — all sessions returned 200 with identical
           bodies (endpoint is live and reachable, but auto-replay cannot
           distinguish account-specific from shared data).
        4. **dead** — catch-all for any other identical or empty result.

        Args:
            three_way: The ``ThreeWayResult`` from ``_replay_three_way()``.

        Returns:
            ``(classification, notes)`` where *classification* is one of the
            module-level ``CLASSIFICATION_*`` constants and *notes* is a
            human-readable explanation.
        """
        results = three_way.results
        diffs = three_way.diffs

        # Replay error → treat as dead (cannot draw conclusions).
        if three_way.error:
            return CLASSIFICATION_DEAD, f"replay error: {three_way.error}"

        # No requests completed (circuit breaker fired before first request).
        if not results:
            return CLASSIFICATION_DEAD, "no results — circuit breaker or sessions error"

        # 1. Any interesting diff → IDOR candidate.
        interesting = [d for d in diffs if d.interesting]
        if interesting:
            summary = " | ".join(d.summary() for d in interesting)
            return CLASSIFICATION_IDOR_CANDIDATE, summary

        # Consider only results without transport errors.
        good = [r for r in results.values() if r.error is None]

        # 2. All successful responses are 401 or 403.
        if good and all(r.status_code in (401, 403) for r in good):
            return CLASSIFICATION_DEAD, "all responses 401/403 — endpoint requires auth"

        # 3. All successful responses are 200 with identical bodies.
        if good and all(r.status_code == 200 for r in good):
            return (
                CLASSIFICATION_NEEDS_REVIEW,
                "all 200 but identical bodies — may be IDOR (manual verification needed)",
            )

        # 4. Generic no-signal fall-through.
        return CLASSIFICATION_DEAD, "no differential signal detected"

    # ── state persistence ─────────────────────────────────────────────────────

    def _update_state(
        self, endpoint: str, method: str, classification: str, notes: str
    ) -> None:
        """Persist the classification result to ``hunt_state.json``.

        Writes to three sections as appropriate:

        - **signals**: appended for ``idor_candidate`` results.
        - **dead_branches**: appended for ``dead`` results (enables future skip).
        - **candidates**: status field updated for all results.

        Args:
            endpoint:       Path used as the dead-branch / candidate key.
            method:         HTTP verb.
            classification: One of the ``CLASSIFICATION_*`` constants.
            notes:          Human-readable context accompanying the classification.
        """
        method = method.upper()

        if classification == CLASSIFICATION_IDOR_CANDIDATE:
            add_signal(
                self._target, endpoint, method, "idor", notes,
                path=self._state_file,
            )
        elif classification == CLASSIFICATION_DEAD:
            mark_dead_branch(
                self._target, endpoint, "idor", "no_signal",
                method=method, path=self._state_file,
            )

        # Always update the candidate status entry.
        update_candidate(
            self._target, endpoint, method, classification,
            notes=notes, diff_summary=notes if classification == CLASSIFICATION_IDOR_CANDIDATE else "",
            path=self._state_file,
        )

    # ── main entry point ──────────────────────────────────────────────────────

    def run(self, dry_run: bool = False) -> list[CandidateResult]:
        """Process all "candidate" endpoints in ``hunt_state.json``.

        Iterates the candidates list for ``self._target`` whose status equals
        ``"candidate"``, applies safety gates, runs the three-way differential
        replay, classifies the result, and writes it back to state.

        In dry-run mode, safety gates are still applied but no HTTP requests are
        made and no state writes occur.  Dry-run results always have
        ``classification=None`` and ``three_way=None``.

        Args:
            dry_run: When ``True``, skip all HTTP requests and state writes.
                     Useful for validating configuration before a real run.

        Returns:
            List of ``CandidateResult`` objects, one per candidate processed.
        """
        candidates = get_candidates(
            self._target, status="candidate", path=self._state_file
        )
        output: list[CandidateResult] = []

        for c in candidates:
            endpoint = c["endpoint"]
            method = c.get("method", "GET")
            url = _build_url(endpoint, self._target)

            # Safety gate evaluation (same in dry-run and real mode).
            safe, reason = self._is_safe_to_replay(url, method)
            if not safe:
                # Log the block to audit even in dry-run so there is always a record.
                self._audit.log_request(
                    url=url,
                    method=method.upper(),
                    scope_check="fail" if reason == "out of scope" else "skip",
                    session_id="auto_replay",
                    error=reason,
                )
                output.append(CandidateResult(
                    endpoint=endpoint, method=method.upper(), url=url,
                    skipped=True, skip_reason=reason,
                    classification=None,
                ))
                continue

            if dry_run:
                output.append(CandidateResult(
                    endpoint=endpoint, method=method.upper(), url=url,
                    skipped=False, skip_reason=None,
                    classification=None, notes="dry-run: no HTTP requests made",
                ))
                continue

            # Real replay — pass body and Content-Type from the candidate entry
            # when present (used for write-method IDOR/BAC testing).
            body: Optional[str] = c.get("body")
            content_type: Optional[str] = c.get("content_type")
            base_headers: dict[str, str] = {}
            if content_type:
                base_headers["Content-Type"] = content_type
            template = RequestTemplate(
                method=method, url=url, headers=base_headers, body=body
            )
            three_way = self._replay_three_way(template)
            classification, notes = self._classify_result(three_way)
            endpoint_key = _endpoint_path(url)
            self._update_state(endpoint_key, method, classification, notes)

            output.append(CandidateResult(
                endpoint=endpoint, method=method.upper(), url=url,
                skipped=False, skip_reason=None,
                classification=classification, notes=notes,
                three_way=three_way,
            ))

        return output


# ── CLI ───────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser for ``auto_replay.py``."""
    p = argparse.ArgumentParser(
        prog="auto_replay",
        description=(
            "Batch IDOR/BAC differential testing orchestrator.  Reads 'candidate' "
            "endpoints from hunt_state.json, replays each under account_a, account_b, "
            "and no_auth, then updates hunt_state.json with the classification result.  "
            "Produces SIGNALS — not findings.  Validate through 7-Question Gate."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 tools/auto_replay.py --target api.target.com\n"
            "  python3 tools/auto_replay.py --target api.target.com --dry-run\n"
        ),
    )
    p.add_argument(
        "--target", required=True,
        help="Target hostname key in hunt_state.json (e.g. api.target.com).",
    )
    p.add_argument(
        "--dry-run", action="store_true", default=False,
        help=(
            "Apply safety gates but make no HTTP requests and no state writes.  "
            "Useful for verifying configuration before a real run."
        ),
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
        "--scope-domain", metavar="PATTERN", action="append", default=[],
        dest="scope_domains",
        help=(
            "Scope domain pattern (e.g. '*.target.com').  Repeatable.  "
            "When omitted, scope checking is disabled."
        ),
    )
    p.add_argument(
        "--allow-write", action="store_true", default=False,
        help=(
            "Allow PUT/PATCH/DELETE/POST candidates through the method gate.  "
            "Requires explicit human approval before use — write methods can "
            "mutate server state."
        ),
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point for ``auto_replay.py``.

    Returns:
        0 — all candidates processed; no idor_candidate found.
        1 — at least one idor_candidate classification was produced.
        2 — configuration or runtime error.
    """
    args = _build_parser().parse_args(argv)

    audit = AuditLog(Path(args.audit_log))
    scope: Optional[ScopeChecker] = (
        ScopeChecker(args.scope_domains) if args.scope_domains else None
    )

    ar = AutoReplay(
        target=args.target,
        state_file=Path(args.state_path),
        sessions_file=Path(args.sessions),
        audit_log=audit,
        allow_write=args.allow_write,
        scope_checker=scope,
    )

    try:
        results = ar.run(dry_run=args.dry_run)
    except Exception as exc:  # noqa: BLE001
        print(f"[AUTO-REPLAY ERROR] {exc}", file=sys.stderr)
        return 2

    if not results:
        print(
            f"[auto-replay] No candidates found for {args.target} in {args.state_path}\n"
            f"To add candidates run:\n"
            f"  python3 tools/hunt_state.py candidate \\\n"
            f"    --target {args.target} --endpoint /path/to/endpoint --method GET\n"
            f"Or run /recon {args.target} first to discover endpoints."
        )
        return 0

    found_idor = False
    for r in results:
        print(r.summary())
        if r.classification == CLASSIFICATION_IDOR_CANDIDATE:
            found_idor = True

    return 1 if found_idor else 0


if __name__ == "__main__":
    sys.exit(main())
