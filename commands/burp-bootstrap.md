---
description: Bootstrap sessions and candidate endpoints from Burp proxy history — automatically extracts account_a / account_b session material and IDOR-candidate URLs, writes memory/sessions.json and hunt_state.json without any manual copy-paste. Requires Burp Suite with MCP extension running. Usage: /burp-bootstrap target.com
---

# /burp-bootstrap

Automatically extract sessions and candidate endpoints from Burp proxy history
and populate `memory/sessions.json` and `hunt_state.json` for two-account
differential testing.

**Prerequisite:** Burp Suite must be running with the Burp MCP extension
enabled (port 9876), and you must have browsed `target.com` while logged in as
at least one (ideally two) accounts.

## Usage

```
/burp-bootstrap target.com
```

---

## Step 1 — Fetch Today's Proxy History (date-filtered regex)

Burp proxy history can contain tens of thousands of entries accumulated over
many sessions.  Rather than paginating through all of them, filter to
**today's traffic only** by matching on the current date string that appears in
HTTP `Date:` response headers.  Today's sessions for both accounts will always
be in this set, and the result set is small enough to process in a handful of
pages.

---

### Step 1a — Compute today's date string

Derive the date in the format used by HTTP `Date:` headers:
**`D Mon YYYY`** — day without leading zero, 3-letter month, 4-digit year.

Examples: `22 Apr 2026`, `1 Jan 2026`, `15 Dec 2025`

```
TODAY = current date formatted as "%-d %b %Y"   (Linux/macOS strftime)
      = e.g. "22 Apr 2026"
```

In Python: `from datetime import datetime; TODAY = datetime.now().strftime("%-d %b %Y")`

This string appears verbatim inside every HTTP response that Burp captured
today, e.g.: `Date: Wed, 22 Apr 2026 19:43:10 GMT`

---

### Step 1b — Fetch all matching entries (paginated)

```
all_raw = []
offset = 0
PAGE_SIZE = 200
HARD_CAP = 50   # max pages = 10 000 entries; more than enough for one day

loop (up to HARD_CAP iterations):
    Call get_proxy_http_history_regex with:
        regex:  TODAY          (e.g. "22 Apr 2026")
        count:  PAGE_SIZE
        offset: offset

    If the tool is not available (Burp MCP not connected):
        Jump to Fallback: Burp Not Connected.

    Append returned entries to all_raw.

    If fewer than PAGE_SIZE entries were returned:
        break   # last page
    Else:
        offset += PAGE_SIZE
        Continue loop.
```

Print: `[Step 1] Fetched {len(all_raw)} entries matching {TODAY} from Burp.`

---

### Step 1c — Client-side host filter

Keep only entries where the host matches the target (case-insensitive
substring match on the `host` field or the `Host:` header in the raw request):

```
target_entries = [e for e in all_raw
                  if TARGET in (e.host or "").lower()
                  or TARGET in raw_host_header(e).lower()]
```

---

### Step 1d — Fallback: try yesterday if today is sparse

If `len(target_entries) < 5`, the session may have started before midnight.
Re-run Step 1b using yesterday's date string (`YESTERDAY`), merge results with
`all_raw`, reapply the host filter.

If still `< 5` after yesterday's fallback, tell the user:

> Not enough Burp history for {target} matching {TODAY} — only {total}
> entries found.
> Browse {target} while logged in through the Burp proxy today, then
> re-run `/burp-bootstrap {target}`.

Stop here.

---

All subsequent steps (Step 2 onward) operate on `target_entries`.

---

## Step 2 — Filter to Authenticated Requests

From `target_entries`, keep only entries where **all** of the following are
true:

1. `method` is `GET`
2. `statusCode` is `200`
3. The raw `request` text contains at least one authenticated indicator:
   - `Authorization: Bearer` (case-insensitive)
   - A cookie whose name contains any of (case-insensitive substring):
     `session`, `sid`, `JSESSIONID`, `MZPSID`, `CHKSESSIONID`, `token`,
     `auth`, `jwt`, `PHPSESSID`

From the passing entries, keep the **top 30** sorted by URL length descending
(longer URL = more specific path = higher IDOR value).

Store this as `auth_entries` (used for candidate extraction in Step 6).

---

## Step 3 — Detect Distinct Accounts

Cookie-based sites (e.g. those that set `MZPSID` on login) do not use distinct
`Authorization` header values per account.  Use the following detection
strategy, in priority order.

### 3a — Primary: MZPSID Set-Cookie detection (login-event based)

Scan **all** `target_entries` (not just `auth_entries`) for login events:

```
For each entry in target_entries:
  Look in the response headers for:
    Set-Cookie: MZPSID=<value>; ...
  If found, record: { mzpsid_value: <value>, entry_index: i }
```

Collect all distinct `MZPSID` values seen in Set-Cookie response headers.

**Mapping MZPSID → account session:**

For each distinct MZPSID value discovered, find the **first subsequent request**
in `target_entries` (by index, after the login entry) whose Cookie request
header contains `MZPSID=<that value>`.  That request is the **representative
request** for that account.

| Distinct MZPSID values in Set-Cookie | Action |
|---|---|
| **2 or more** | `account_a` = first login's representative; `account_b` = second login's representative |
| **Exactly 1** | `account_a` = that session; `account_b` = EMPTY |
| **0** | Fall through to 3b |

### 3b — Fallback: Group by MZPSID cookie value in request headers

If no Set-Cookie MZPSID was found in responses (e.g. login happened in a
previous Burp session), scan Cookie headers across `auth_entries`:

```
For each entry in auth_entries:
  Parse the Cookie: header → extract MZPSID=<value>
  Group entries by their MZPSID value
```

| Distinct MZPSID values in Cookie headers | Action |
|---|---|
| **2 or more** | `account_a` = group with earliest entry; `account_b` = group with second-earliest entry |
| **Exactly 1** | `account_a` = that session; `account_b` = EMPTY |
| **0** | Fall through to 3c |

### 3c — Final fallback: Group by Authorization header

```
For each entry in auth_entries:
  Extract the Authorization: header value
  Group by exact value

account_a = first group; account_b = second group (if present)
```

If no Authorization headers either:

> No authenticated requests found in Burp history for {target}.
> Log in to {target} through the Burp proxy first, then re-run
> `/burp-bootstrap {target}`.

Stop here.

### One account only — warn and continue

If only one account was detected regardless of method:

> ⚠ Only one account found in Burp history.
> Browse {target} with a **second account** in Burp before re-running
> `/burp-bootstrap {target}` to enable A/B differential testing.
> Continuing with account_a only — account_b will be empty.

---

## Step 4 — Extract Session Material

For each detected account, select the **richest authenticated GET request**
as the representative: from all entries belonging to that account, pick the
one with the most non-tracking cookie name=value pairs.  Break ties by longest
URL (more specific path).

### Parse the representative request

**Extract and classify cookies:**

Find the `Cookie:` header line. Split by `;` to get individual name=value
pairs.

Exclude these tracking cookies (name starts with or matches exactly):

```
_ga, _gid, _gat, _fbp, _gcl, _hjid, _hjsession, _pk_,
__utma, __utmb, __utmc, __utmz, __cf, __cf_bm,
OptanonConsent, OptanonAlertBoxClosed,
cookielawinfo, viewed_cookie_policy, CookieConsent, euconsent,
ajs_*, amplitude_*, mixpanel_*
```

Include everything else — especially session identifiers:

```
MZPSID, CHKSESSIONID, session, sid, JSESSIONID,
csrfToken, cid, token, auth*, PHPSESSID, SSID, ASP.NET_SessionId
```

**Extract Authorization header (if present):**

- Find the line starting with `Authorization:` (case-insensitive)
- Store the full header value (e.g. `Bearer eyJ...`)
- This becomes the `auth_header` field
- If no Authorization header exists, use `""` for `auth_header`

**Extract structural headers for replay fidelity:**

Keep these headers if present (for the `headers` field in sessions.json):

```
X-Domain, X-Site-Id, X-Requested-With, X-CSRF-Token, Origin
```

Do NOT include these in sessions.json (they are per-request, not per-session):

```
Accept, Referer, User-Agent, Content-Type, Host, Authorization, Cookie
```

**Determine auth scheme for notes field:**

- If `auth_header` is non-empty: note the scheme (e.g. `Bearer`)
- If `auth_header` is empty and MZPSID cookie is present: note `cookie/MZPSID`
- If neither: note `cookie/<primary_session_cookie_name>`

**Build the sessions.json record:**

```json
{
  "name": "account_a",
  "cookies": { "MZPSID": "<value>", "CHKSESSIONID": "<value>", ... },
  "headers": { "X-Domain": "<value>", ... },
  "auth_header": "",
  "notes": "Bootstrapped from https://target.com/path (burp_history) | auth scheme: cookie/MZPSID"
}
```

Repeat for `account_b` if found.

---

## Step 5 — Write memory/sessions.json

Assemble the sessions list and write it directly using the Write tool.

Always append a `no_auth` entry at the end:

```json
{
  "name": "no_auth",
  "cookies": {},
  "headers": {},
  "auth_header": "",
  "notes": "unauthenticated probe — auth-bypass check"
}
```

**Final sessions.json structure:**

```json
[
  {
    "name": "account_a",
    "cookies": { "MZPSID": "<VALUE-A>", ... },
    "headers": { ... },
    "auth_header": "",
    "notes": "Bootstrapped from https://target.com/... | auth scheme: cookie/MZPSID"
  },
  {
    "name": "account_b",
    "cookies": { "MZPSID": "<VALUE-B>", ... },
    "headers": { ... },
    "auth_header": "",
    "notes": "Bootstrapped from https://target.com/... | auth scheme: cookie/MZPSID"
  },
  {
    "name": "no_auth",
    "cookies": {},
    "headers": {},
    "auth_header": "",
    "notes": "unauthenticated probe — auth-bypass check"
  }
]
```

Write to `memory/sessions.json`.

**If account_b is empty**, omit it from the list entirely; include only
`account_a` and `no_auth`.

**Validate sessions after writing:**

Run the session validity gate immediately after writing the file:

```bash
python3.13 tools/check_sessions.py \
    --sessions memory/sessions.json \
    --probe-url https://{target}/api/me
```

Handle the exit code:

| Exit code | Meaning | Action |
|---|---|---|
| 0 | All sessions valid (or unchecked) | Print: `✓ Sessions validated — both accounts active.` Proceed to Step 6. |
| 1 | One or more sessions expired | Warn: `⚠ One or more sessions are expired. Re-login in Burp and re-run /burp-bootstrap {target}.` Stop here. |
| 2 | sessions.json missing or empty | Should not happen here — indicates a write failure. Check disk permissions. |
| 3 | Network error | Warn: `⚠ Session probe failed — target unreachable or Burp proxy is not running. Verify connectivity and retry.` |

**Note:** If `--probe-url` is not known at bootstrap time, omit it. The gate
will run without probing (UNCHECKED = non-blocking) and sessions can be
re-validated later with a probe URL once one is known.

---

## Step 6 — Extract Candidate Endpoints

From `auth_entries` (top 30 from Step 2), evaluate each URL for IDOR/BAC
signal.

### Identifier detection rules

For each URL's **path**, check for any of the following:

| Pattern | Example |
|---|---|
| Numeric segment ≥ 4 digits | `/api/invoices/54746925` |
| UUID segment | `/users/550e8400-e29b-41d4-a716-446655440000` |
| Hex segment ≥ 20 chars | `/objects/507f1f77bcf86cd799439011` |
| Query param name ending in `id` or `Id` | `?userId=123`, `?orderId=99` |
| Object-type path segment | `/user/`, `/order/`, `/account/`, `/invoice/`, `/subscription/`, `/address/`, `/profile/`, `/customer/`, `/payment/` |

If any identifier pattern matches, **add this endpoint as a candidate**.

### Write candidates to hunt_state.json

For each candidate endpoint, run:

```python
python3.13 -c "
import sys; sys.path.insert(0, '.')
from memory.state_manager import add_candidate
add_candidate('<TARGET>', '<PATH>', 'GET')
print('Added candidate: <PATH>')
"
```

Where `<PATH>` is the URL path only (e.g. `/api/users/54746925`), not the full
URL.

### Score candidates for the summary

Use `extract_template` and `score_candidate` from `request_template_extractor.py`
to score each candidate for display in the summary:

```python
python3.13 -c "
import sys; sys.path.insert(0, '.')
from tools.request_template_extractor import extract_template, score_candidate, from_burp_entry
# For each candidate entry, call score_candidate(template) to get an int score
"
```

---

## Step 7 — Show Summary

Print a structured summary table:

```
✓ Burp bootstrap complete for target.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Sessions saved → memory/sessions.json

  account_a:  found  (auth scheme: cookie/MZPSID | cid: 12345678 if present)
  account_b:  found  (auth scheme: cookie/MZPSID | cid: 87654321)
  no_auth:    included (unauthenticated probe)

Candidates added → hunt_state.json: N endpoints

  Top 5 by score:
  [12] GET /api/v2/users/54746925/orders          → idor, bac
  [10] GET /api/invoices/12345/details            → idor, bac, business_logic
  [ 8] GET /api/account/settings                  → idor, business_logic
  [ 7] GET /customer-data/api/v2/initial-ui-data  → idor
  [ 5] GET /api/subscription/status               → bac

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Next steps:
  1. Validate sessions:    python3.13 tools/auth_check.py
  2. Dry-run auto-replay:  python3.13 tools/auto_replay.py --target target.com --dry-run
  3. Live auto-replay:     python3.13 tools/auto_replay.py --target target.com
  4. Full autopilot:       /autopilot target.com
```

**Account identity display:**

- If a `cid` cookie is present: display its value as the account identifier.
- If `auth_header` starts with `Bearer `, attempt to decode the JWT payload
  (middle segment, base64url-decode, parse as JSON). Display `sub` or `email`
  claim if found. If decoding fails display `"Bearer token (opaque)"`.
- Otherwise display `"cookie session (opaque)"`.

**Never display raw token values or raw cookie values.**

---

## Fallback: Burp Not Connected

If `get_proxy_http_history_regex` returns an error or is not available, ask:

> Burp MCP is not connected. How would you like to proceed?
>
> **Option 1 — Connect Burp MCP (recommended):**
> 1. Open Burp Suite Professional
> 2. Ensure the Burp MCP extension is running (port 9876)
> 3. Browse {target} while logged in as two different accounts
> 4. Re-run `/burp-bootstrap {target}`
>
> **Option 2 — Paste raw requests:**
> Paste two complete HTTP requests (from Burp Repeater/Proxy) — one for each
> account. Use the format from Burp's "Copy as raw request" option.

If the user chooses Option 2, collect both raw request texts, then run:

```python
python3.13 -c "
import sys; sys.path.insert(0, '.')
from tools.session_bootstrap import build_sessions_from_raw_text, write_sessions_json
from pathlib import Path

raw_a = '''PASTE_ACCOUNT_A_REQUEST_HERE'''
raw_b = '''PASTE_ACCOUNT_B_REQUEST_HERE'''

sessions = build_sessions_from_raw_text(raw_a, raw_b)
write_sessions_json(sessions, Path('memory/sessions.json'))
print(f'Written {len(sessions)} sessions to memory/sessions.json')
"
```

Then ask the user to provide a list of candidate URLs to add, and run Step 6
manually for each one.

---

## Error Handling

| Situation | Response |
|---|---|
| Fewer than 5 history entries for target | Ask user to browse target in Burp first |
| 0 authenticated requests | Ask user to log in through Burp proxy first |
| 1 account only | Warn, continue with account_a only |
| No MZPSID in any entry | Fall through: try Authorization header grouping |
| sessions.json already exists | Warn: "Overwriting existing sessions.json" and proceed |
| hunt_state.json already has candidates | Deduplicated automatically by `add_candidate()` |
| JWT decode fails | Show `"Bearer token (opaque)"` — never show raw token |

---

## Notes on Credential Safety

- Authorization header values are **never printed** to the terminal output.
- Cookie values are **never printed** to the terminal output.
- The `notes` field in sessions.json contains only the auth scheme name (e.g.
  `cookie/MZPSID`), not the token or cookie value.
- The `cid` cookie value (customer ID) may be displayed since it is a
  non-secret identifier, not a credential.
- JWT claims (`sub`, `email`) may be shown for identification purposes since
  they are not secrets.

---

## Why this fetch strategy

**Date regex — slices today's traffic without paging through all history:**
A Burp history with 18 000+ entries accumulated over weeks cannot be fully
paginated in a reasonable number of tool calls.  Both accounts browsed
*today*, so filtering on today's date string (which appears in every HTTP
`Date:` response header) returns only relevant entries — typically a few
hundred — regardless of total history size.

**Different offset each page — avoids Claude Code tool-call caching:**
Claude Code caches tool results for identical parameter sets.  Calling
`get_proxy_http_history_regex` with the same `regex` and `offset=0` twice in
the same session would return the cached result from the first call.  By
incrementing `offset` by 200 each page, every call has unique parameters and
is never served from cache.  The date regex itself also changes daily, so
repeated runs on different days automatically bypass any cross-session cache.

**Yesterday fallback — handles midnight-boundary sessions:**
If a testing session started before midnight and continued into today, some
entries may carry yesterday's date.  The yesterday fallback catches this edge
case without requiring the user to know which date to use.

**Hard cap of 50 pages — prevents runaway loops:**
One day's Burp traffic for a single target rarely exceeds a few thousand
entries.  The 50-page cap (10 000 entries) is a safety net that cannot be
reached in normal use but prevents an infinite loop if the date regex
unexpectedly matches many unrelated entries.

---

## Manual Test

1. Open Burp Suite Professional with the MCP extension enabled (port 9876)
2. Log in to `target.com` as **account_a** **today** — browse several API paths
3. Log in to `target.com` as **account_b** **today** — browse several API paths
   (Both sessions must have occurred today so they appear in the date-filtered
   result set.  The second login sets a new `MZPSID` cookie via Set-Cookie,
   which is the primary signal used to distinguish the two accounts.)
4. Run: `/burp-bootstrap target.com`
5. Confirm Step 1 output shows:
   - `Fetched N entries matching DD Mon YYYY from Burp` with N > 10
   - Both accounts detected in Step 3
6. Verify `memory/sessions.json` contains `account_a`, `account_b`, and
   `no_auth` entries with non-empty `cookies` (MZPSID) or `auth_header`
7. Verify `memory/hunt_state.json` has `candidates` entries for the target
8. Run: `python3.13 tools/auto_replay.py --target target.com --dry-run`
9. Confirm the dry-run output lists the expected candidate endpoints
10. Run: `python3.13 tools/auth_check.py` to verify sessions are valid
