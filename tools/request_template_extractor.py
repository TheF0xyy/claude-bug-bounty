"""tools/request_template_extractor.py

Parse HTTP requests into replay-ready RequestTemplate objects.

Two input modes
---------------
1. parse_raw_request(text, scheme="https") -> RawRequest
   Accepts pasted Burp-style raw HTTP/1.1 or HTTP/2 request text.

2. from_burp_entry(entry: dict) -> RawRequest
   Accepts a Burp MCP HTTP history entry dict.  If the entry contains a
   "request" key with raw text it is parsed as in mode 1; otherwise the
   individual fields (host, method, path, headers, …) are assembled.

Both produce a RawRequest consumed by:
   extract_template(raw, name=None) -> RequestTemplate

Additional utilities
--------------------
   score_candidate(template)               -> int
   select_candidates(templates, top_n=20)  -> list[RequestTemplate]

Identifier detection covers:
   - path segment numeric IDs (≥ 4 digits), UUIDs, long hex IDs
   - query parameter names that look like object-ID fields
   - top-level JSON body fields whose name or value suggests an identifier

Cookie classification separates auth/session cookies from tracking cookies.
When a cookie is ambiguous (neither clearly auth nor clearly tracking) it is
included in session material to avoid breaking replay.

Secrets are never written to stdout; callers are responsible for handling
auth_material_summary values safely.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import unquote

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_VERSION_SEG_RE = re.compile(r"^v\d+$", re.I)          # v1 v2 v3 — NOT identifiers
_NUMERIC_ID_RE  = re.compile(r"^\d{4,}$")               # ≥ 4 digit integers
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
_HEX_ID_RE  = re.compile(r"^[0-9a-f]{20,}$", re.I)     # MongoDB ObjectId, etc.
_SLUG_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]*-(\d{4,})$", re.I)  # slug-54746925

# ---------------------------------------------------------------------------
# Cookie classification
# ---------------------------------------------------------------------------

# Name prefixes that are almost certainly analytics / consent tracking.
# A cookie whose name starts with any of these is excluded from session material.
TRACKING_COOKIE_PREFIXES: tuple[str, ...] = (
    "_ga", "_gid", "_gat", "_fbp", "_gcl", "_hjid", "_hjsession",
    "_pk_", "__utma", "__utmb", "__utmc", "__utmz", "__cf",
    "OptanonConsent", "OptanonAlertBoxClosed",
    "cookielawinfo", "viewed_cookie_policy", "CookieConsent", "euconsent",
)

# Substrings (case-insensitive) in cookie names that signal auth/session purpose.
AUTH_COOKIE_PATTERNS: tuple[str, ...] = (
    "session", "sess", "sid", "auth", "token", "jwt", "csrf", "xsrf",
    "access", "refresh", "sso", "login", "identity", "principal",
)

# Exact cookie names that are always auth-related regardless of pattern.
AUTH_COOKIE_EXACT: frozenset[str] = frozenset({
    "JSESSIONID", "MZPSID", "CHKSESSIONID", "ASP.NET_SessionId",
    "PHPSESSID", "SSID", "CFID", "CFTOKEN",
})

# Name prefixes indicating load-balancer or cloud-provider auth cookies.
AUTH_COOKIE_PREFIXES: tuple[str, ...] = ("TS0", "AWSALB", "AWSALBCORS", "BIGipServer")


def _is_tracking_cookie(name: str) -> bool:
    """True when a cookie is almost certainly analytics or tracking."""
    for prefix in TRACKING_COOKIE_PREFIXES:
        if name.startswith(prefix):
            return True
    return False


def _is_auth_cookie(name: str) -> bool:
    """True when a cookie carries session or auth state."""
    if name in AUTH_COOKIE_EXACT:
        return True
    for prefix in AUTH_COOKIE_PREFIXES:
        if name.startswith(prefix):
            return True
    lower = name.lower()
    for pattern in AUTH_COOKIE_PATTERNS:
        if pattern in lower:
            return True
    return False


def classify_cookies(
    cookies: dict[str, str],
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Partition cookies into (auth, tracking, unknown).

    auth     — clearly session/auth-bearing; include in sessions.json.
    tracking — analytics/consent; exclude from sessions.json.
    unknown  — ambiguous; included in sessions.json by default to avoid
               breaking replay on sites that require undocumented cookies.
    """
    auth: dict[str, str] = {}
    tracking: dict[str, str] = {}
    unknown: dict[str, str] = {}
    for name, value in cookies.items():
        if _is_tracking_cookie(name):
            tracking[name] = value
        elif _is_auth_cookie(name):
            auth[name] = value
        else:
            unknown[name] = value
    return auth, tracking, unknown


# ---------------------------------------------------------------------------
# Header filtering
# ---------------------------------------------------------------------------

# Headers whose value is controlled by the session object — do NOT include in
# required_headers (they are injected by build_headers in session_manager.py).
_SESSION_OWNED_HEADERS: frozenset[str] = frozenset({"authorization", "cookie"})

# Headers auto-managed by the HTTP stack — including them adds noise without value.
_AUTO_HEADERS: frozenset[str] = frozenset({
    "content-length", "transfer-encoding", "connection",
    "host", "http2-settings", "upgrade", "expect",
})


def extract_required_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return headers needed for replay fidelity, excluding session-owned ones.

    Keeps:
    - Accept, Accept-Language, Content-Type, Referer, User-Agent, Origin
    - Custom X-* headers (site-specific API contracts)
    - Any header not in the session-owned or auto-generated exclusion sets.

    Strips:
    - Authorization  (session-owned → goes to auth_header in sessions.json)
    - Cookie         (session-owned → goes to session cookies)
    - Content-Length, Host, Transfer-Encoding, Connection  (auto-computed)
    """
    result: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _SESSION_OWNED_HEADERS or key.lower() in _AUTO_HEADERS:
            continue
        result[key] = value
    return result


# ---------------------------------------------------------------------------
# Object type vocabulary
# ---------------------------------------------------------------------------

# Tokens in path segments that indicate the type of the following identifier.
_OBJECT_TYPE_TOKENS: dict[str, str] = {
    "customer": "customer",     "customers": "customer",
    "order": "order",           "orders": "order",
    "address": "address",       "addresses": "address",
    "subscription": "subscription", "subscriptions": "subscription",
    "payment": "payment",       "payments": "payment",
    "user": "user",             "users": "user",
    "account": "account",       "accounts": "account",
    "invoice": "invoice",       "invoices": "invoice",
    "product": "product",       "products": "product",
    "item": "item",             "items": "item",
    "shop": "shop",             "shops": "shop",
    "card": "card",             "cards": "card",
    "voucher": "voucher",       "vouchers": "voucher",
    "reward": "reward",         "rewards": "reward",
    "wishlist": "wishlist",
}

# Boring segment names that add no meaning to a template name.
_BORING_SEGMENTS: frozenset[str] = frozenset({
    "api", "rest", "graphql", "rpc", "public", "private", "internal",
})

# Path tokens that indicate low-value / static / noise endpoints.
_LOW_VALUE_PATH_TOKENS: frozenset[str] = frozenset({
    "static", "assets", "images", "img", "fonts", "css", "js",
    "robots", "favicon", "health", "ping", "analytics", "tracking",
    "metrics", "telemetry", "beacon", "sw.js", "manifest",
})

# Path tokens that indicate high-value object-access endpoints.
_HIGH_VALUE_PATH_TOKENS: frozenset[str] = frozenset({
    "customer", "order", "address", "subscription", "payment",
    "user", "account", "invoice", "product", "card", "reward", "voucher",
})


def _infer_object_type_from_segments(
    segments: list[str], id_index: int
) -> Optional[str]:
    """Walk path segments backwards from id_index to find a context token."""
    for seg in reversed(segments[:id_index]):
        seg_clean = seg.lower().replace("-", "").replace("_", "")
        for token, obj_type in _OBJECT_TYPE_TOKENS.items():
            if token in seg_clean:
                return obj_type
    return None


def _infer_object_type_from_key(key: str) -> Optional[str]:
    """Infer object type from a field name like 'customerId' or 'user_id'."""
    key_clean = key.lower().replace("_", "").replace("-", "")
    for token, obj_type in _OBJECT_TYPE_TOKENS.items():
        if key_clean.startswith(token):
            return obj_type
    return None


# ---------------------------------------------------------------------------
# Identifier detection helpers
# ---------------------------------------------------------------------------

def _looks_like_id_key(key: str) -> bool:
    """True when a field/param name suggests it holds an object identifier."""
    lower = key.lower()
    return (
        lower == "id"
        or lower.endswith("id")    # customerId, userId, addressId
        or lower.endswith("_id")   # customer_id, user_id
        or lower in {"uid", "uuid", "guid", "objectid", "oid", "ref"}
    )


def _looks_like_id_value(value: str) -> bool:
    """True when a string value looks like an object identifier."""
    if not isinstance(value, str):
        return False
    return bool(
        _NUMERIC_ID_RE.match(value)
        or _UUID_RE.match(value)
        or _HEX_ID_RE.match(value)
    )


def _classify_id_kind(value: str) -> str:
    if _UUID_RE.match(value):
        return "uuid"
    if _HEX_ID_RE.match(value):
        return "hex_id"
    if _NUMERIC_ID_RE.match(value):
        return "numeric_id"
    return "named_id"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class IdentifierCandidate:
    """A possible object identifier extracted from a request."""
    location: str              # "path" | "query" | "body"
    name: Optional[str]        # field/param name if known
    value: str                 # original value
    kind: str                  # "numeric_id" | "uuid" | "hex_id" | "named_id"
    object_type: Optional[str] # inferred object category if determinable


@dataclass
class RawRequest:
    """Normalized internal representation of an HTTP request.

    Created by parse_raw_request() or from_burp_entry().
    Consumed by extract_template().
    """
    method: str
    scheme: str
    host: str
    path: str                   # path only, no query string
    query_params: dict[str, str]
    headers: dict[str, str]     # original capitalisation preserved
    cookies: dict[str, str]
    body: Optional[str]
    source: str                 # "raw_text" | "burp_mcp"


@dataclass
class RequestTemplate:
    """Replay-ready template extracted from an HTTP request.

    Produced by extract_template().  Serialise with to_dict() for JSON output.
    """
    name: str
    method: str
    full_url: str
    url_template: str
    path: str
    query_params: dict[str, str]
    body: Optional[str]
    required_headers: dict[str, str]
    auth_material_summary: dict        # {"has_authorization": bool, "auth_cookie_names": list[str]}
    identifier_candidates: list[IdentifierCandidate]
    suggested_vuln_classes: list[str]
    safe_for_auto_replay: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "method": self.method,
            "full_url": self.full_url,
            "url_template": self.url_template,
            "path": self.path,
            "query_params": self.query_params,
            "body": self.body,
            "required_headers": self.required_headers,
            "auth_material_summary": self.auth_material_summary,
            "identifier_candidates": [
                {
                    "location": c.location,
                    "name": c.name,
                    "value": c.value,
                    "kind": c.kind,
                    "object_type": c.object_type,
                }
                for c in self.identifier_candidates
            ],
            "suggested_vuln_classes": self.suggested_vuln_classes,
            "safe_for_auto_replay": self.safe_for_auto_replay,
        }


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_cookie_header(cookie_header: str) -> dict[str, str]:
    """Parse a Cookie: header value into a name → value dict."""
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            result[key.strip()] = value.strip()
        elif part:
            result[part] = ""
    return result


def _parse_query_string(qs: str) -> dict[str, str]:
    """Parse a query string into a flat name → first-value dict."""
    result: dict[str, str] = {}
    for part in qs.split("&"):
        if not part:
            continue
        if "=" in part:
            key, _, value = part.partition("=")
            key_decoded = unquote(key.strip())
            if key_decoded and key_decoded not in result:
                result[key_decoded] = unquote(value)
        else:
            key_decoded = unquote(part.strip())
            if key_decoded and key_decoded not in result:
                result[key_decoded] = ""
    return result


# ---------------------------------------------------------------------------
# Input source 1: raw HTTP request text
# ---------------------------------------------------------------------------

def parse_raw_request(text: str, scheme: str = "https") -> RawRequest:
    """Parse pasted raw HTTP request text into a RawRequest.

    Supports:
    - HTTP/1.1 request lines: ``GET /path HTTP/1.1``
    - HTTP/2 pseudo-headers:  ``:method: GET``, ``:path: /path``,
      ``:authority: host``, ``:scheme: https``

    Mixed format (HTTP/1.1 line followed by HTTP/2 pseudo-headers in the
    header block) is also handled; pseudo-headers take priority.

    Args:
        text:   Raw request text (e.g. pasted from Burp Repeater).
        scheme: Default scheme when not determinable from the text.
                Defaults to "https" as most modern targets are HTTPS.

    Returns:
        RawRequest with all parseable fields populated.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")

    method = ""
    path_with_qs = ""
    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False
    detected_scheme = scheme

    for i, line in enumerate(lines):
        if in_body:
            body_lines.append(line)
            continue

        if line == "" and i > 0:
            in_body = True
            continue

        if i == 0 and line and not line.startswith(":"):
            # HTTP/1.1 request line
            parts = line.split(None, 2)
            if parts:
                method = parts[0].upper()
            if len(parts) >= 2:
                path_with_qs = parts[1]
            continue

        if line.startswith(":"):
            # HTTP/2 pseudo-header: ":name: value"
            # line.partition(":") would split at position 0 (yielding key=""),
            # so we strip the leading colon first.
            rest = line[1:]
            if ":" in rest:
                pseudo, _, value = rest.partition(":")
                pseudo = pseudo.strip().lower()
                value = value.strip()
                if pseudo == "method":
                    method = value.upper()
                elif pseudo == "path":
                    path_with_qs = value
                elif pseudo in ("authority", "host"):
                    headers["Host"] = value
                elif pseudo == "scheme":
                    detected_scheme = value.lower()
        elif ":" in line:
            # Regular HTTP/1.1 header — last occurrence wins for duplicates.
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            headers[key] = value
            if key.lower() == "host" and not headers.get("Host"):
                headers["Host"] = value

    # Resolve host from headers.
    host = headers.get("Host") or headers.get("host") or ""

    # Separate path from query string.
    if "?" in path_with_qs:
        path, _, qs = path_with_qs.partition("?")
        query_params = _parse_query_string(qs)
    else:
        path = path_with_qs
        query_params = {}

    # Parse cookies from Cookie header.
    cookies: dict[str, str] = {}
    for hkey, hval in headers.items():
        if hkey.lower() == "cookie":
            cookies = _parse_cookie_header(hval)
            break

    body_text = "\n".join(body_lines).strip() or None

    return RawRequest(
        method=method or "GET",
        scheme=detected_scheme,
        host=host,
        path=path or "/",
        query_params=query_params,
        headers=headers,
        cookies=cookies,
        body=body_text,
        source="raw_text",
    )


# ---------------------------------------------------------------------------
# Input source 2: Burp MCP history entry dict
# ---------------------------------------------------------------------------

def from_burp_entry(entry: dict) -> RawRequest:
    """Normalise a Burp MCP HTTP history entry dict into a RawRequest.

    Tries the following in order:
    1. If ``entry["request"]`` exists, parse it as raw text and overlay
       ``host`` / ``scheme`` from the entry's metadata fields.
    2. Otherwise assemble from individual entry fields (``host``, ``method``,
       ``path``, ``headers``, ``cookies``, ``body``).

    Accepted metadata fields (all optional):
        host, port, protocol, scheme, method, path, url,
        request (raw bytes or str), headers (dict), cookies (dict), body

    This function never raises on incomplete entries — missing fields are
    substituted with safe defaults.
    """
    # Determine scheme from entry metadata.
    scheme = (
        entry.get("protocol")
        or entry.get("scheme")
        or ("https" if int(entry.get("port", 443)) == 443 else "http")
    )
    if isinstance(scheme, str):
        scheme = scheme.lower()
    host_from_entry = str(entry.get("host", ""))

    raw_text = entry.get("request", "")
    if isinstance(raw_text, bytes):
        raw_text = raw_text.decode("utf-8", errors="replace")

    if raw_text:
        raw = parse_raw_request(raw_text, scheme=scheme)
        # Overlay entry metadata where the raw text lacks it.
        resolved_host = raw.host if (raw.host and raw.host != "unknown") else host_from_entry
        return RawRequest(
            method=raw.method,
            scheme=scheme,
            host=resolved_host,
            path=raw.path,
            query_params=raw.query_params,
            headers=raw.headers,
            cookies=raw.cookies,
            body=raw.body,
            source="burp_mcp",
        )

    # Fallback: assemble from individual entry fields.
    method = str(entry.get("method", "GET")).upper()

    # Use "url" field if available when path is absent or trivially "/".
    path_with_qs = entry.get("path") or ""
    if (not path_with_qs or path_with_qs == "/") and entry.get("url"):
        from urllib.parse import urlparse as _urlparse
        _parsed = _urlparse(entry["url"])
        path_with_qs = _parsed.path
        if _parsed.query:
            path_with_qs += "?" + _parsed.query
        if not host_from_entry:
            host_from_entry = _parsed.netloc
        if _parsed.scheme:
            scheme = _parsed.scheme

    if "?" in path_with_qs:
        path, _, qs = path_with_qs.partition("?")
        query_params = _parse_query_string(qs)
    else:
        path = path_with_qs
        query_params = {}

    headers_raw = entry.get("headers") or {}
    headers: dict[str, str] = dict(headers_raw) if isinstance(headers_raw, dict) else {}

    cookies_raw = entry.get("cookies") or {}
    if isinstance(cookies_raw, dict):
        cookies: dict[str, str] = dict(cookies_raw)
    elif "Cookie" in headers:
        cookies = _parse_cookie_header(headers["Cookie"])
    else:
        cookies = {}

    body = entry.get("body") or entry.get("request_body") or None
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    body = (body.strip() or None) if body else None

    return RawRequest(
        method=method,
        scheme=scheme,
        host=host_from_entry,
        path=path or "/",
        query_params=query_params,
        headers=headers,
        cookies=cookies,
        body=body,
        source="burp_mcp",
    )


# ---------------------------------------------------------------------------
# Identifier detection
# ---------------------------------------------------------------------------

def detect_identifiers_in_path(path: str) -> list[IdentifierCandidate]:
    """Extract identifier candidates from path segments.

    Detects ≥ 4-digit integers, UUIDs, long hex strings (≥ 20 chars), and
    numeric-suffix slugs (e.g. ``product-54746925``).
    Version segments (v1, v2 …) are explicitly excluded.
    """
    path_only = path.split("?")[0]
    segments = [s for s in path_only.split("/") if s]
    candidates: list[IdentifierCandidate] = []

    for i, seg in enumerate(segments):
        if _VERSION_SEG_RE.match(seg):
            continue

        kind: Optional[str] = None
        value = seg

        if _UUID_RE.match(seg):
            kind = "uuid"
        elif _HEX_ID_RE.match(seg):
            kind = "hex_id"
        elif _NUMERIC_ID_RE.match(seg):
            kind = "numeric_id"
        else:
            m = _SLUG_ID_RE.match(seg)
            if m:
                kind = "numeric_id"
                value = m.group(1)   # use the numeric suffix as the value

        if kind:
            obj_type = _infer_object_type_from_segments(segments, i)
            name = f"{obj_type}Id" if obj_type else ("uuid" if kind == "uuid" else "id")
            candidates.append(IdentifierCandidate(
                location="path",
                name=name,
                value=value,
                kind=kind,
                object_type=obj_type,
            ))

    return candidates


def detect_identifiers_in_query(query_params: dict[str, str]) -> list[IdentifierCandidate]:
    """Extract identifier candidates from query parameters."""
    candidates: list[IdentifierCandidate] = []
    for key, value in query_params.items():
        if _looks_like_id_key(key) or _looks_like_id_value(value):
            obj_type = _infer_object_type_from_key(key)
            kind = _classify_id_kind(value) if _looks_like_id_value(value) else "named_id"
            candidates.append(IdentifierCandidate(
                location="query",
                name=key,
                value=value,
                kind=kind,
                object_type=obj_type,
            ))
    return candidates


def detect_identifiers_in_body(body: Optional[str]) -> list[IdentifierCandidate]:
    """Extract identifier candidates from a JSON request body (one level deep).

    Non-JSON bodies (form-encoded, XML, plain text) are skipped in this MVP.
    Only top-level dict keys are examined to keep complexity low.
    """
    if not body:
        return []
    try:
        parsed = json.loads(body.strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(parsed, dict):
        return []

    candidates: list[IdentifierCandidate] = []
    for key, value in parsed.items():
        if not isinstance(value, (str, int)):
            continue
        str_value = str(value)
        if _looks_like_id_key(key) or _looks_like_id_value(str_value):
            obj_type = _infer_object_type_from_key(key)
            kind = _classify_id_kind(str_value) if _looks_like_id_value(str_value) else "named_id"
            candidates.append(IdentifierCandidate(
                location="body",
                name=key,
                value=str_value,
                kind=kind,
                object_type=obj_type,
            ))
    return candidates


# ---------------------------------------------------------------------------
# Template generation helpers
# ---------------------------------------------------------------------------

def generate_url_template(
    path: str,
    query_params: dict[str, str],
    candidates: list[IdentifierCandidate],
) -> str:
    """Replace identifier values in the path with ``{name}`` placeholders.

    Query parameters that are identifiers are also templated.
    Returns the templated path (without scheme/host) including any query string.
    """
    # Build value → placeholder map for path identifiers.
    path_replacements: dict[str, str] = {}
    seen_names: dict[str, int] = {}
    for c in candidates:
        if c.location != "path":
            continue
        placeholder_name = c.name or "id"
        # Deduplicate placeholder names when multiple IDs share the same name.
        count = seen_names.get(placeholder_name, 0)
        seen_names[placeholder_name] = count + 1
        if count:
            placeholder_name = f"{placeholder_name}{count + 1}"
        if c.value not in path_replacements:
            path_replacements[c.value] = f"{{{placeholder_name}}}"

    # Apply replacements segment by segment.
    path_only = path.split("?")[0]
    segments = path_only.split("/")
    new_segments: list[str] = []
    for seg in segments:
        if seg in path_replacements:
            new_segments.append(path_replacements[seg])
        else:
            # Check slug pattern — replace the numeric suffix only.
            m = _SLUG_ID_RE.match(seg)
            if m and m.group(1) in path_replacements:
                prefix = seg[: -len(m.group(1))]
                new_segments.append(prefix + path_replacements[m.group(1)])
            else:
                new_segments.append(seg)

    new_path = "/".join(new_segments)

    # Template query params that are identifiers.
    query_id_names: set[str] = {c.name for c in candidates if c.location == "query" and c.name}
    if query_params:
        parts: list[str] = []
        for key, value in query_params.items():
            if key in query_id_names:
                parts.append(f"{key}={{{key}}}")
            else:
                parts.append(f"{key}={value}")
        new_path = new_path + "?" + "&".join(parts)

    return new_path


def generate_name(path: str, candidates: list[IdentifierCandidate]) -> str:
    """Produce a descriptive snake_case name from the request path.

    Excludes: identifier values, version segments (v1…), boring generic
    segments (api, rest, …).  Takes up to the last 4 meaningful segments.
    """
    path_only = path.split("?")[0]
    id_values = {c.value for c in candidates if c.location == "path"}

    meaningful: list[str] = []
    for seg in path_only.split("/"):
        if not seg:
            continue
        if _VERSION_SEG_RE.match(seg):
            continue
        if seg in id_values:
            continue
        if seg.lower() in _BORING_SEGMENTS:
            continue
        meaningful.append(seg.replace("-", "_"))

    name = "_".join(meaningful[-4:])
    return name or "request"


# ---------------------------------------------------------------------------
# Vuln class suggestion
# ---------------------------------------------------------------------------

_VULN_ORDER = ["idor", "bac", "authz", "business_logic", "api_security"]

_ADMIN_TOKENS: tuple[str, ...] = ("/admin", "/manage", "/internal", "/system", "/backoffice", "/staff")


def _suggest_vuln_classes(
    raw: RawRequest,
    candidates: list[IdentifierCandidate],
    has_auth: bool,
) -> list[str]:
    """Suggest ordered vulnerability classes based on endpoint shape."""
    suggestions: set[str] = set()
    path_lower = raw.path.lower()

    if candidates:
        suggestions.add("idor")

    if any(tok in path_lower for tok in _ADMIN_TOKENS):
        suggestions.update({"bac", "authz"})

    if has_auth and candidates:
        suggestions.add("bac")

    if raw.method.upper() in {"POST", "PUT", "PATCH"}:
        suggestions.add("business_logic")

    if not suggestions and has_auth:
        suggestions.add("authz")

    return [c for c in _VULN_ORDER if c in suggestions]


# ---------------------------------------------------------------------------
# Main extraction entry point
# ---------------------------------------------------------------------------

def extract_template(raw: RawRequest, name: Optional[str] = None) -> RequestTemplate:
    """Build a RequestTemplate from a RawRequest.

    Orchestrates identifier detection, auth-material extraction, header
    filtering, URL template generation, vuln-class suggestion, and name
    generation in a single deterministic pass.

    Args:
        raw:  A RawRequest produced by parse_raw_request() or from_burp_entry().
        name: Optional override for the template name.  When None, a name is
              generated from the path (see generate_name()).

    Returns:
        A RequestTemplate ready for JSON serialisation or replay.
    """
    # Identifier detection across all three locations.
    all_candidates = (
        detect_identifiers_in_path(raw.path)
        + detect_identifiers_in_query(raw.query_params)
        + detect_identifiers_in_body(raw.body)
    )

    # Auth material.
    auth_header: Optional[str] = None
    for hkey, hval in raw.headers.items():
        if hkey.lower() == "authorization":
            auth_header = hval
            break

    auth_cookies, _tracking, _unknown = classify_cookies(raw.cookies)
    # Include unknown cookies so sessions.json works even for ambiguous cookies.
    session_cookie_names = list(auth_cookies.keys())

    has_auth = bool(auth_header or auth_cookies)

    # Required headers for structural replay fidelity.
    req_headers = extract_required_headers(raw.headers)

    # URL construction.
    full_url = f"{raw.scheme}://{raw.host}{raw.path}"
    if raw.query_params:
        qs = "&".join(f"{k}={v}" for k, v in raw.query_params.items())
        full_url += f"?{qs}"

    # Templated URL.
    template_path = generate_url_template(raw.path, raw.query_params, all_candidates)
    url_template = f"{raw.scheme}://{raw.host}{template_path}"

    # Name.
    if name is None:
        name = generate_name(raw.path, all_candidates)

    # Vuln class suggestions.
    vuln_classes = _suggest_vuln_classes(raw, all_candidates, has_auth)

    # safe_for_auto_replay: GET-only in this MVP (read-only, no state changes).
    safe = raw.method.upper() == "GET"

    return RequestTemplate(
        name=name,
        method=raw.method.upper(),
        full_url=full_url,
        url_template=url_template,
        path=raw.path,
        query_params=dict(raw.query_params),
        body=raw.body,
        required_headers=req_headers,
        auth_material_summary={
            "has_authorization": bool(auth_header),
            "auth_cookie_names": session_cookie_names,
        },
        identifier_candidates=all_candidates,
        suggested_vuln_classes=vuln_classes,
        safe_for_auto_replay=safe,
    )


# ---------------------------------------------------------------------------
# Candidate scoring and selection  (Phase G)
# ---------------------------------------------------------------------------

def score_candidate(template: RequestTemplate) -> int:
    """Return a hunt-priority score for a RequestTemplate.

    Higher = better IDOR/BAC candidate for replay.
    Negative scores indicate low-value or static endpoints.

    Scoring factors
    ---------------
    +2  GET method (safe for auto-replay, lower noise)
    +3  identifier candidates present
    +2  auth material present (session/Authorization header)
    +2  object-specific path token (customer, order, …)
    +2  "idor" in suggested_vuln_classes
    +1  "bac"  in suggested_vuln_classes
    +1  JSON response preferred (Accept: application/json)
    -5  low-value / static path token (static, assets, robots, …)
    """
    score = 0
    path_lower = template.path.lower()

    if template.method == "GET":
        score += 2

    if template.identifier_candidates:
        score += 3

    summary = template.auth_material_summary
    if summary.get("has_authorization") or summary.get("auth_cookie_names"):
        score += 2

    for tok in _HIGH_VALUE_PATH_TOKENS:
        if tok in path_lower:
            score += 2
            break

    if "idor" in template.suggested_vuln_classes:
        score += 2
    if "bac" in template.suggested_vuln_classes:
        score += 1

    accept = template.required_headers.get("Accept", "")
    if "application/json" in accept.lower():
        score += 1

    for tok in _LOW_VALUE_PATH_TOKENS:
        if tok in path_lower:
            score -= 5
            break

    return score


def select_candidates(
    templates: list[RequestTemplate],
    top_n: int = 20,
) -> list[RequestTemplate]:
    """Return up to top_n templates sorted by descending hunt-priority score.

    Deterministic: ties preserve insertion order.
    """
    indexed = list(enumerate(templates))
    indexed.sort(key=lambda x: (-score_candidate(x[1]), x[0]))
    return [t for _, t in indexed[:top_n]]
