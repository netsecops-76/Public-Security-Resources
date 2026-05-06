# Q KB Explorer — Bug Tracker

> Open: 0 | Critical: 0 | High: 0 | Medium: 0 | Low: 0

## Open Bugs

_No open bugs._

## Resolved Bugs

### BUG-016: PM Patches delta sync rejected with "Invalid QQL" — RESOLVED 2026-05-06
- **Severity:** High
- **Component:** backend (`app/sync.py` `sync_pm_patches`)
- **Description:** PM Patches delta sync sent QQL `lastModified:>"<watermark>"` and Qualys returned 400 errorCode 2119 on every page for both Windows and Linux platforms. Sync aborted with zero patches ingested.
- **Root Cause:** Two errors in the QQL — the patch entity has no `lastModified` token (correct token is `modifiedDate` / `patch.updatedDate`), and date comparisons use bare `>` not `:>`.
- **Resolution:** Use `modifiedDate>"<watermark>"`. Added a one-shot fallback in the page-error handler that retries the same page without the date predicate if Qualys still returns a QQL 400 (degrades to full-list ingest, which is idempotent).

### BUG-015: Automatic Updates toggle posted to a non-existent endpoint — RESOLVED 2026-05-06
- **Severity:** High (user-visible toast on every interaction)
- **Component:** full-stack
- **Description:** The Settings → Automatic Updates checkbox and day/time form had been shipped without a backend. Toggling produced "Failed to save: Unexpected token '<', '<!doctype...' is not valid JSON" — Flask's HTML 404 page being parsed as JSON.
- **Resolution:** Implemented `/api/update/schedule` GET + POST, modeled on the existing weekly maintenance scheduler. New `auto_update_config` table (single-row, idempotent CREATE) plus `_execute_auto_update`/`_schedule_auto_update_job`/`_restore_auto_update_schedule` in scheduler.py. ALTER TABLE migration added for any existing volumes carrying a partial 9-column version of the table. Disable path is lenient (accepts any form input, always removes the job) so the user can always turn the feature off.

### BUG-014: Automatic Updates dropdown unreadable (grey on transparent) — RESOLVED 2026-05-06
- **Severity:** Low
- **Component:** frontend (templates/index.html)
- **Description:** The day-of-week select and time input under Automatic Updates rendered with grey-on-transparent text while every other dropdown rendered correctly.
- **Root Cause:** Inline `style=` attributes referenced two undefined CSS variables — `var(--bg-card)` and `var(--fg)` — that don't exist in `style.css`. Browser fell back to defaults.
- **Resolution:** Removed the inline styles entirely. The default `input, select, textarea` rule already applies `--bg-0` background and `--text-0` color.

### BUG-013: Apply Update reload window too short, no progress indicator — RESOLVED 2026-05-06
- **Severity:** Medium (UX)
- **Component:** frontend (`app/static/js/app.js` `applyUpdate`)
- **Description:** After clicking Apply Update, users got a success toast and a "refresh in a few seconds" status line. The implicit polling window (10 attempts × 2s = ~20s) frequently timed out before the container restart finished, and the lack of a visual indicator made users think the page had hung.
- **Resolution:** Non-dismissible modal with phase-tracked status (Downloading → Restarting services → Waiting for app to come back online). Reload triggers on the down→up transition (proves the master actually restarted; avoids the prior race where the still-up old worker would falsely satisfy the poll right before SIGTERM). 90s budget; manual "Refresh now" button surfaces if the timer elapses. Failsafe reload at 30s if the server stays "up" the whole time.

### BUG-012: First sync after credential save triggered re-auth modal — RESOLVED 2026-05-06
- **Severity:** High (UX, fresh-install)
- **Component:** backend (`app/main.py` `credentials_save`) + frontend (`saveCredential`)
- **Description:** After completing Test Connection + Save Credential on a fresh install, the very next protected request (typically a Full Sync click) hit the vault auth gate, returned 401, and popped the unlock modal asking for the password the user had just typed seconds earlier.
- **Root Cause:** `POST /api/credentials` persisted the credential but did not set the `qkbe-vault-unlocked` HttpOnly cookie. Only `POST /api/credentials/verify` set it.
- **Resolution:** The save endpoint now mints a session token, stores it in `_active_sessions`, and sets the same cookie verify does. Frontend passes `max_age` (so the new cookie respects the user's session timeout) and calls `markVaultAuthenticated()` so `shouldShowVaultAuth()` doesn't re-prompt on the next page load.

### BUG-011: Save Credential allowed without successful Test Connection — RESOLVED 2026-05-06
- **Severity:** High (caused confusing downstream failures)
- **Component:** frontend (`app/static/js/app.js` `saveCredential`/`testConnection`)
- **Description:** A typo in the username (or any auth field) would land in the vault unchecked and surface later as Qualys errors during sync — e.g. CODE 2002 "This account is inactive" cascading across every chunk of a Full Sync.
- **Resolution:** Save is gated on a successful Test Connection against the exact `{username, password, platform}` currently in the form. Snapshot is captured on success and invalidated on any change to those three fields (or Clear/Disconnect, or unmasking a vault-loaded password). Save button is visually disabled until a valid test exists. Editing an already-vaulted credential's metadata with a masked password remains unaffected — that's a server-side metadata patch and doesn't need a fresh test.

### BUG-010: Credential picker did not re-render after delete — RESOLVED 2026-05-06
- **Severity:** Low (UX)
- **Component:** frontend (`app/static/js/app.js` `deleteCredential`)
- **Description:** Clicking the X on a stored credential called the DELETE API and showed a toast, but the dropdown DOM kept showing the row until the user closed and reopened the picker. Users assumed the delete hadn't worked and clicked it repeatedly on the stale row.
- **Resolution:** After a successful delete, re-populate the picker if it's still open.

### BUG-009: In-app updater silently no-op'd under gunicorn `--preload` — RESOLVED 2026-05-06
- **Severity:** Critical (every auto-update appeared to succeed but didn't change running code)
- **Component:** backend (`app/updater.py` `_restart_gunicorn`) + infra (`entrypoint.sh`)
- **Description:** Apply Update returned `status: ok`, advanced `.current_version`, and reported success — but the running app behavior was unchanged. The user kept hitting bugs we'd already fixed.
- **Root Cause:** Gunicorn was launched with `--preload`, which imports `app.main` once in the master and forks workers via copy-on-write. The updater's `_restart_gunicorn` deliberately spared PID 1 and only killed workers; the master then respawned them by forking again — inheriting the OLD imported code from master memory regardless of what was now on disk.
- **Resolution:** Updater now SIGTERMs the master (PID 1) on a 2s background-thread delay so the apply response can flush. `restart: unless-stopped` brings the container back up with a fresh entrypoint and fresh import. Entrypoint dropped `--preload` as defense in depth so per-worker respawns can also pick up disk changes. UPDATING.md rewritten with explicit recovery steps for users on pre-2.2 images.

### BUG-008: QID Full Sync aborted on CORRELATION shape variations (Issue #6) — RESOLVED 2026-05-06
- **Severity:** High
- **Component:** backend (`app/database.py` `upsert_vuln`)
- **Description:** Full Sync completed the pre-count phase (~210K QIDs) and aborted on the first ingest batch with `'NoneType' object has no attribute 'get'`. Same defect class as BUG-007 but in the live ingest path instead of the init-time backfill.
- **Root Cause:** The CORRELATION walk in `upsert_vuln` (lines 1439, 1448) iterated `EXPLT_SRC` / `MW_SRC` and called `src.get(...)` without verifying `src` was a dict. xmltodict can produce four shapes for these elements — dict, list-of-dicts, bare string, None entry from an empty self-closing element — and the code only handled the first two.
- **Resolution:** Extracted `_count_correlation_exploits_and_malware` helper that tolerates all four shapes at every nesting level. Replaced the inline duplicated counting in both `upsert_vuln` and `_backfill_threat_columns` with calls to the helper, eliminating the divergence that had let two separate fixes ship for the same bug.
- **Audit:** Verified all other upsert paths (`upsert_control`, `upsert_policy`, `upsert_mandate`, `upsert_tag`, `upsert_pm_patch`) and `app/sync.py` for the same `for x in ...: x.get()` pattern. Only `upsert_vuln` was affected.
- **Defense in depth:** `app/sync.py` now wraps each per-record upsert in try/except across all six sync paths, so a single malformed record can never abort the whole batch.

### BUG-007: init_db crashloop on malformed correlation_json (Issue #5) — RESOLVED 2026-05-06
- **Severity:** Critical (container restart loop)
- **Component:** backend (`app/database.py` `_backfill_threat_columns`)
- **Description:** On container startup, `init_db()` runs `_backfill_threat_columns()` against existing rows. If any stored `correlation_json` had a bare-string `EXPLT_SRC` or `MW_SRC` (xmltodict's collapsed text-only shape), the function raised `AttributeError: 'str' object has no attribute 'get'`. Gunicorn re-imported and re-failed; the container stayed in a permanent restart loop.
- **Root Cause:** `for src in explt_srcs:` iterated over the characters of the string when the value wasn't a dict or list.
- **Resolution:** Added isinstance guards in both `EXPLT_SRC` and `MW_SRC` loops, and wrapped each row's processing in try/except so a single malformed row logs a WARNING and is skipped rather than aborting `init_db()`.

### BUG-006: QID sync crash on CVSS scores with attributes (Issue #4) — RESOLVED 2026-05-06
- **Severity:** High
- **Component:** backend (`app/database.py` `upsert_vuln`)
- **Description:** First-attempt syncs failed with `float() argument must be a string or a real number, not 'dict'`. The crash aborted the page's batch upsert; a retry that landed on attribute-less records would appear to "fix" the issue, hence the original bug title "QIDs not syncing on 1st attempt."
- **Root Cause:** Qualys returns CVSS BASE/TEMPORAL with a `source` attribute (e.g. `<BASE source="cve">5.0</BASE>`), which xmltodict parses to `{"@source": "cve", "#text": "5.0"}` — not a string. `float({...})` then raised the TypeError.
- **Resolution:** Added `_xml_text` helper that unwraps `#text` from a dict-shaped XML value, returns scalars unchanged. Routed CVSS v2/v3 base + temporal reads through it.

### BUG-005: Select mode shows regular CSV button, causing full-result export — RESOLVED 2026-03-24
- **Severity:** Medium
- **Component:** frontend (app.js)
- **Description:** When entering QID/CID select mode, the regular CSV export button remained visible. Users clicking it exported all search results instead of only the selected items.
- **Root Cause:** `enterQidSelectMode()` only hid the Select button, not the entire export actions bar
- **Resolution:** Select mode now hides the full `qidExportActions`/`cidExportActions` div and shows only the select bar with its own Export CSV button

### BUG-004: PDF export hangs on large QID content — RESOLVED 2026-03-24
- **Severity:** High
- **Component:** backend (main.py `_pdf_response`)
- **Description:** PDF generation with reportlab hung or threw `LayoutError` when QID diagnosis/solution fields contained thousands of characters. Paragraph rendering with `wordWrap="CJK"` created cells taller than the page.
- **Root Cause:** reportlab Paragraph objects with long text create table cells that exceed page height, causing infinite layout retries or LayoutError
- **Resolution:** Removed PDF export buttons from all browse tabs. PDF generation retained only for individual policy reports. Added word wrap and smart column widths to policy report PDF.

### BUG-003: PDF exports contain raw HTML tags — RESOLVED 2026-03-24
- **Severity:** Medium
- **Component:** backend (main.py)
- **Description:** QID diagnosis, consequence, and solution fields rendered with raw HTML tags in PDF output
- **Resolution:** Added `_strip_html()` helper using bleach to clean HTML while preserving remediation URLs as plain text

### BUG-002: Modal z-index stacking broken for child modals — RESOLVED 2026-03-10
- **Severity:** Medium
- **Component:** frontend (style.css)
- **Description:** Child modals (e.g., CID detail opened from Policy detail) appeared behind the parent modal
- **Resolution:** Fixed z-index stacking order so child modals always appear on top

### BUG-001: Supported modules parsing fails on string XML values — RESOLVED 2026-03-10
- **Severity:** High
- **Component:** backend (database.py upsert_vuln)
- **Description:** QID sync failed with `'str' object has no attribute 'get'` when `SUPPORTED_MODULES` was returned as a plain string by xmltodict instead of a dict
- **Root Cause:** xmltodict returns different Python types (str, dict, list) depending on XML structure; code only handled the dict case
- **Resolution:** Added type checking to handle all xmltodict return shapes (string, dict, list)
- **Regression test:** Manual verification with 5 edge case variants (dict+list, dict+str, plain str, missing, dict element)
