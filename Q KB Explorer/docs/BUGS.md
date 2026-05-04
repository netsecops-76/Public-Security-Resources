# Q KB Explorer — Bug Tracker

> Open: 0 | Critical: 0 | High: 0 | Medium: 0 | Low: 0

## Open Bugs

_No open bugs._

## Resolved Bugs

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
