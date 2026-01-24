# Lessons Learned: Agent Efficiency & Context Management

This document summarizes procedural improvements for the Dame agent based on the analysis of session failures and context bloat.

**Source File:** `dame-tmux-logs-20260123-092056.txt`
**Last Review:** 2026-01-23

## 1. Optimize Discovery (No Recursive Listings on Assets)
*   **Status:** ✅ **IMPLEMENTED** in `GEMINI.md` (lines 209-277)
*   **Issue:** The agent performed a recursive listing that dumped hundreds of lines of static `.svg` files, wasting context space on non-executable artifacts.
*   **Evidence:** Lines 36-135.
*   **Lesson:** Avoid `ls -R` on directories likely to contain static assets (e.g., `assets/`, `img/`, `vendor/`). Use `ls -F` or `find . -maxdepth 2` to maintain structural awareness without token waste.
*   **Implementation:** "Large Output Management" section in GEMINI.md explicitly prohibits `ls -laR`, `find /` with mitigation strategies.

## 2. Targeted Source Code Analysis (Grep Before Read)
*   **Status:** ⚠️ **PARTIALLY IMPLEMENTED** - needs explicit prompt guidance
*   **Issue:** The agent read multiple entire PHP files (config, db, login, register, admin) sequentially without knowing if they contained relevant logic.
*   **Evidence:** Lines 138-185.
*   **Lesson:** Prioritize `grep -r` for high-value sinks (e.g., `eval`, `system`, `runkit`, `PDO`) to identify vulnerable files before committing to a full `ReadFile` operation.
*   **TODO:** Add "Grep Before Read" section to GEMINI.md with sink patterns for PHP, Python, JS.

## 3. Silent Brute-forcing & Iteration
*   **Status:** ✅ **IMPLEMENTED** in `GEMINI.md` (lines 225-231)
*   **Issue:** Large loops for credential testing and User ID enumeration filled the terminal and context with repetitive "Trying..." or "User ID X has items!" messages.
*   **Evidence:** Lines 407-427 (Credentials), 441-482 (User IDs), 614-635 (Testimony names).
*   **Lesson:** Redirect loop outputs to temporary files (e.g., `command > /tmp/out.log`). Read and report only the successful matches or a high-level summary to preserve context.
*   **Implementation:** Output limiting strategies in GEMINI.md include redirect-to-file patterns.

## 4. Environment-Aware Tooling
*   **Status:** ✅ **FIXED** at infrastructure level (2026-01-23)
*   **Issue:** Multiple attempts to run `nmap` failed because the agent did not account for containerized environment restrictions regarding raw sockets.
*   **Evidence:** Lines 878-897.
*   **Lesson:** If a network tool fails due to permissions (e.g., "Operation not permitted"), immediately pivot to unprivileged alternatives (e.g., `nmap -sT` or `/dev/tcp` bash loops) rather than retrying the failing command.
*   **Fix Applied:** Added `NET_RAW` capability to dame container in `docker-compose.yml`. nmap raw socket scans now work.

## 5. Aggressive Content Filtering
*   **Status:** ✅ **IMPLEMENTED** in `GEMINI.md` (lines 168-208)
*   **Issue:** Raw HTML and large MCP server responses caused the context window to overflow, leading to a session-ending `INVALID_ARGUMENT` error.
*   **Evidence:** Lines 993-1008 (Final API Error).
*   **Lesson:** Enforce strict body truncation and filtering. Always use `curl ... | html2text | head -n 100`. If an MCP response is expected to be large, request a summarized version or specific fields.
*   **Implementation:** "Web Content Filtering" section in GEMINI.md with `html2text`, `head`, `curl -I` patterns.

## 6. Session State Management
*   **Status:** ❌ **NOT IMPLEMENTED** - needs prompt guidance
*   **Issue:** The agent re-ran the full login process multiple times without checking if the existing `cookies.txt` was still valid after a perceived failure.
*   **Evidence:** Lines 712, 915.
*   **Lesson:** Verify session validity (e.g., `curl -I -b cookies.txt`) before executing re-authentication logic to minimize redundant network noise and token usage.
*   **TODO:** Add "Session Management" section to GEMINI.md with cookie validation patterns.

---

## Summary

| # | Lesson | Status |
|---|--------|--------|
| 1 | Optimize Discovery | ✅ Implemented |
| 2 | Grep Before Read | ⚠️ Needs prompt addition |
| 3 | Silent Brute-forcing | ✅ Implemented |
| 4 | Environment-Aware Tooling | ✅ Fixed (infra) |
| 5 | Aggressive Content Filtering | ✅ Implemented |
| 6 | Session State Management | ❌ Needs prompt addition |

**Remaining Work:**
- Add "Grep Before Read" section to GEMINI.md
- Add "Session Management" section to GEMINI.md
- Consider adding to memory research (blunderbussy-0we) as these are stateful concerns

---

# Lessons Learned: Faraday API Integration

**Source:** Faraday v3 API debugging session (2026-01-23/24)
**Last Review:** 2026-01-24

## 7. Faraday v3 API Endpoint Trailing Slashes
*   **Status:** ✅ **FIXED** in `faraday_client.py`
*   **Issue:** All API calls to Faraday v3 endpoints with trailing slashes returned 404 or 405 errors.
*   **Evidence:** `/hosts/` → 404, `/upload_report/` → 405 Method Not Allowed
*   **Lesson:** Faraday v3 API rejects trailing slashes on all endpoints. Always use `/hosts`, `/vulns`, `/services`, `/upload_report` without trailing slash.
*   **Fix Applied:** Removed trailing slashes from all endpoint URLs in `faraday_client.py`.

## 8. Faraday CSRF Token Extraction
*   **Status:** ✅ **FIXED** in `faraday_client.py`
*   **Issue:** Authentication succeeded but subsequent requests returned 403 Forbidden. CSRF token was not being extracted.
*   **Evidence:** Login response structure: `{"meta": {...}, "response": {"csrf_token": "...", "user": {...}}}`
*   **Lesson:** Faraday returns CSRF token in response JSON body at `response.csrf_token`, NOT in cookies. The token must be sent both as `X-CSRF-Token` header AND in form data for file uploads.
*   **Fix Applied:** Updated `authenticate()` to extract from `data.get('response', {}).get('csrf_token')` and added CSRF token to upload form data.

## 9. Faraday API Response Format Variations
*   **Status:** ✅ **FIXED** in `faraday_client.py`
*   **Issue:** List endpoints returned `'str' object has no attribute 'get'` error when iterating results.
*   **Evidence:** Vulns returns `{"vulnerabilities": [...]}`, not `{"rows": [...]}`. Services returns `{"services": [...]}`.
*   **Lesson:** Faraday v3 API uses resource-specific keys (`vulnerabilities`, `services`) instead of generic `rows`. Always check for both formats when parsing responses.
*   **Fix Applied:** Updated response parsing to check for both legacy `rows` and v3 resource-specific keys.

## 10. Workspace Name Sanitization
*   **Status:** ✅ **FIXED** in `faraday_watcher.py`
*   **Issue:** Workspace creation failed for IP-based names like `10.129.2.163`.
*   **Evidence:** Faraday requires alphanumeric + underscores only for workspace names.
*   **Lesson:** Always sanitize workspace names: replace dots/hyphens/colons with underscores, prefix with `ws_` if name starts with digit.
*   **Fix Applied:** Added `sanitize_workspace_name()` function: `10.129.2.163` → `ws_10_129_2_163`.

---

## Summary (Faraday)

| # | Lesson | Status |
|---|--------|--------|
| 7 | No Trailing Slashes | ✅ Fixed |
| 8 | CSRF in Response Body | ✅ Fixed |
| 9 | Response Key Variations | ✅ Fixed |
| 10 | Workspace Name Sanitization | ✅ Fixed |

**Key Takeaway:** When integrating with REST APIs, always test actual response formats with `curl` before assuming structure based on documentation. Documentation may be outdated or inconsistent across API versions.
