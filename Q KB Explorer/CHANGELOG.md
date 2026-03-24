# Q KB Explorer — Changelog

> Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Supported modules (agent type) display and filtering on QID tab
- Module badges on QID search result cards (sky-blue)
- Supported Modules multi-select filter in QID advanced filters
- Supported Modules field in QID detail modal
- Supported Modules column in QID CSV export
- `vuln_supported_modules` database table
- Project documentation and Dependabot configuration

### Fixed
- Supported modules XML parsing handles string/dict/list variants from xmltodict

### Security
- HTML sanitization on QID diagnosis/consequence/solution fields (bleach)
- Rate limiting on credential verification endpoint (flask-limiter)
- CSRF protection via X-Requested-With header on state-changing requests
- Server-side HttpOnly auth cookie (replaces client-side cookie)
- Generic error messages (no internal stack traces exposed)
- Removed wildcard CORS (same-origin only)
- Hardened SQL fallback path in sync state updates

### Infrastructure
- GitHub Actions CI/CD workflow (pytest on push/PR) — Roadmap #49
- Dependabot configuration (pip, docker, github-actions)
- Dynamic `secure=True` cookie flag when TLS certificates detected

---

## [v1.3.0] — 2026-03-24 — Phase 4: Quality of Life

### Added
- Keyboard shortcuts: `1`-`7` tabs, `/` focus search, `?` shortcuts modal, `t` toggle theme, `b` bookmark (Roadmap #47)
- Bookmark/favorite QIDs, CIDs, and Policies with star icons on cards and detail modals, stored in localStorage (Roadmap #44)
- Recent searches history with clock icon dropdown on all search bars, max 20 entries in localStorage (Roadmap #45)
- Bulk export: Select mode on QID and CID tabs with CSV/PDF export of full details including CVEs, diagnosis, solution (Roadmap #46)
- `POST /api/qids/export-details` endpoint for bulk QID detail export (limit 200)
- `POST /api/cids/export-details` endpoint for bulk CID detail export (limit 200)
- Help tab (7th tab) with comprehensive documentation: Quick Start, Data Types, Search, Policy Migration, Bookmarks, Bulk Export, Shortcuts, Troubleshooting (Roadmap #48)
- Keyboard shortcuts modal (`?` key or via Help tab)
- 7 new tests for bulk export endpoints (82 total)

---

## [v1.2.0] — 2026-03-08

### Added
- Dashboard tab with severity breakdown charts (Chart.js)
- Sync health dashboard (last sync times, health indicators)
- Compliance coverage metrics (mandates to controls to policies)
- QID statistics (by category, patchable percentage)
- CSV export of search results (QIDs, CIDs, Policies, Mandates)
- PDF report generation (tabular export with reportlab)
- Mandate compliance mapping export (flattened hierarchy)
- Policy report view with section-based layout and PDF generation
- Technology count on policy cards in browse view
- Technology display and filtering in policy detail view
- Empty policy detection/skip during sync, ZIP export, server-side upload guard

### Fixed
- Modal z-index stacking so child modals appear on top
- Policy tech count uses XML export data instead of DB-derived count
- Policy delete, disconnect auth, and session timeout handling

---

## [v1.1.0] — 2026-03-05

### Added
- Vault-based identity gate (session cookie auth)
- before_request route protection (401 for unauthenticated API calls)
- Logout endpoint and disconnect button wiring
- Global 401 response handler (re-show auth modal)

### Security
- All API routes now require vault authentication (except credential management)

---

## [v1.0.0] — 2026-03-01

### Added
- QID sync (full and delta) with ID-range chunking for 114K+ records
- CID sync (full and delta) with truncation paging for 26K+ records
- Policy sync (full and delta)
- Mandate/compliance framework extraction from CID sync
- FTS5 full-text search across QIDs, CIDs, Policies, Mandates
- FTS5 prefix matching for type-ahead partial word search
- Multi-select filters with AND/OR toggle
- CVE type-ahead server search (debounced)
- QID detail view (CVSS, CVEs, Bugtraq, vendor refs, threat intel)
- CID detail view (technologies, rationale, linked policies, linked mandates)
- Policy detail view (linked controls, linked mandates, migration tools)
- Mandate detail view (associated controls and derived policies)
- Policy export/import (cross-environment migration)
- Stale export detection
- AES-256-GCM credential vault (two-volume Docker security)
- Multi-credential vault with platform association
- Credential verification (secrets.compare_digest)
- Server-side credential resolution (credential_id)
- Connection testing (before save and after save)
- Sync scheduling (daily/weekly/monthly with timezone)
- Persistent sync history (SQLite-backed, 20 entries per type)
- Real-time sync progress with elapsed time display
- Full sync purge warning modal
- Dark/light theme toggle
- Cache-busted static assets
- Feature tour GIF with subtitle player
- Qualys platform registry (13 regions)
- Docker deployment with optional TLS support
- Delta sync watermarks (Qualys API format)
- Cross-navigation (CID to Policy, CID to Mandate, Policy to Mandate)
- Severity/criticality color-coded cards
- Dynamic record count badges (Total, Found, percentage)
