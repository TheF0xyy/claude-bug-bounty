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

## Step 1 — Fetch Proxy History for Target

Call the MCP tool `get_proxy_http_history_regex` with:

```
tool: get_proxy_http_history_regex
params:
  regex: "target\\.com"
  count: 100
  offset: 0
```

**If the tool is not available (Burp MCP not connected):** Jump to
[Fallback: Burp Not Connected](#fallback-burp-not-connected) below.

**If fewer than 5 results are returned:** Tell the user:

> Not enough Burp history for target.com — only N entries found.
> Browse target.com while logged in through the Burp proxy, then
> re-run `/burp-bootstrap target.com`.

Stop here.

---

## Step 2 — Filter to Authenticated GET 200 Requests

From all returned history items, keep only entries where **all** of the
following are true:

1. `method` is `GET`
2. `statusCode` is `200`
3. The raw `request` text contains at least one of:
   - `Authorization: Bearer` (case-insensitive)
   - A cookie whose name matches any of: `session`, `sid`, `JSESSIONID`,
     `MZPSID`, `CHKSESSIONID`, `token`, `auth`, `jwt` (case-insensitive
     substring match on the cookie name)

From the passing entries, keep the **top 30** sorted by URL length descending
(longer URL = more specific path = higher IDOR value).

---

## Step 3 — Detect Distinct Accounts

Parse the `Authorization` header from each filtered request.

**Group entries by their exact `Authorization` header value.**

| Distinct auth values found | Action |
|---|---|
| **2 or more** | `account_a` = first group (earliest entry); `account_b` = second group |
| **Exactly 1** | `account_a` = that session; `account_b` = EMPTY |
| **0** | Stop — see message below |

**0 authenticated requests found:**

> No authenticated requests found in Burp history for target.com.
> Log in to target.com through the Burp proxy first, then re-run
> `/burp-bootstrap target.com`.

Stop here.

**Only 1 account found (warn and continue):**

> ⚠ Only one account found in Burp history.
> Browse target.com with a **second account** in Burp before re-running
> `/burp-bootstrap target.com` to enable A/B differential testing.
> Continuing with account_a only — account_b will be empty.

---

## Step 4 — Extract Session Material

For each account found, use **one representative request** (the first/earliest
entry for that Authorization value).

### Parse the raw request text

**Extract Authorization header:**
- Find the line starting with `Authorization:` (case-insensitive)
- Store the full header value (e.g. `Bearer eyJ...`)
- This becomes the `auth_header` field

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

Include everything else, especially:
```
session, sid, JSESSIONID, MZPSID, CHKSESSIONID,
csrfToken, token, auth*, PHPSESSID, SSID, ASP.NET_SessionId
```

**Extract structural headers for replay fidelity:**

Keep these headers if present (for the `headers` field in sessions.json):
```
X-Domain, X-Site-Id, X-Requested-With, X-CSRF-Token, Origin
```

Do NOT include these in sessions.json (they are per-request, not per-session):
```
Accept, Referer, User-Agent, Content-Type, Host, Authorization, Cookie
```

**Build the sessions.json record:**

```json
{
  "name": "account_a",
  "cookies": { "<name>": "<value>", ... },
  "headers": { "<name>": "<value>", ... },
  "auth_header": "Bearer eyJ...",
  "notes": "Bootstrapped from https://target.com/path (burp_history) | auth scheme: Bearer"
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
    "cookies": { ... },
    "headers": { ... },
    "auth_header": "Bearer <TOKEN-A>",
    "notes": "Bootstrapped from https://target.com/... | auth scheme: Bearer"
  },
  {
    "name": "account_b",
    "cookies": { ... },
    "headers": { ... },
    "auth_header": "Bearer <TOKEN-B>",
    "notes": "Bootstrapped from https://target.com/... | auth scheme: Bearer"
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

From all 30 filtered requests, evaluate each URL for IDOR/BAC signal.

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

  account_a:  found  (auth scheme: Bearer | sub: user@example.com if JWT decodable)
  account_b:  found  (auth scheme: Bearer | sub: other@example.com)
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

**JWT subject display:** If `auth_header` starts with `Bearer `, attempt to
decode the JWT payload (middle segment, base64url-decode, parse as JSON). If
successful, display `sub` or `email` claim. If decoding fails, display
`"Bearer token (opaque)"`.  
**Never display the raw token value.**

---

## Fallback: Burp Not Connected

If `get_proxy_http_history_regex` returns an error or is not available, ask:

> Burp MCP is not connected. How would you like to proceed?
>
> **Option 1 — Connect Burp MCP (recommended):**
> 1. Open Burp Suite Professional
> 2. Ensure the Burp MCP extension is running (port 9876)
> 3. Browse target.com while logged in as two different accounts
> 4. Re-run `/burp-bootstrap target.com`
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
| Fewer than 5 history entries | Ask user to browse target in Burp first |
| 0 authenticated requests | Ask user to log in through Burp proxy first |
| 1 account only | Warn, continue with account_a only |
| sessions.json already exists | Warn: "Overwriting existing sessions.json" and proceed |
| hunt_state.json already has candidates | Deduplicated automatically by `add_candidate()` |
| JWT decode fails | Show `"Bearer token (opaque)"` — never show raw token |

---

## Notes on Credential Safety

- Authorization header values are **never printed** to the terminal output.
- Cookie values are **never printed** to the terminal output.
- The `notes` field in sessions.json contains only the auth scheme name (e.g.
  `Bearer`), not the token value.
- JWT claims (`sub`, `email`) may be shown for identification purposes since
  they are not secrets.

---

## Manual Test

1. Open Burp Suite Professional with the MCP extension enabled (port 9876)
2. Browse `target.com` while logged in as **two different accounts** — make
   several GET requests to `/api/…` paths so history is populated
3. Run: `/burp-bootstrap target.com`
4. Verify `memory/sessions.json` contains `account_a`, `account_b`, and
   `no_auth` entries with non-empty `auth_header` or `cookies`
5. Verify `memory/hunt_state.json` has `candidates` entries for the target
6. Run: `python3.13 tools/auto_replay.py --target target.com --dry-run`
7. Confirm the dry-run output lists the expected candidate endpoints with
   `[SKIP]` or classification status
8. Run: `python3.13 tools/auth_check.py` to verify sessions are valid
