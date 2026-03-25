# Q KB Explorer — Changelog

> Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Dynamic build ID in About section (git SHA from Docker build or auto-update)
- Contact email field in bug/feature request form for follow-up
- Build version and browser info auto-included in GitHub issue body
- Post-update reload polls /api/health until server responds (replaces fixed 5s delay)
- Dockerfile BUILD_VERSION arg bakes git SHA into image at build time
- Auto-update scheduling (weekly cron with day/time picker in Settings)
- Supported modules (agent type) display and filtering on QID tab
- Module badges on QID search result cards (sky-blue)
- Supported Modules multi-select filter in QID advanced filters
- Supported Modules field in QID detail modal
- Supported Modules column in QID CSV export
- `vuln_supported_modules` database table
- Development Foundation onboarding (CLAUDE.md, docs/, .github/dependabot.yml)
- Automatic weekly database maintenance with compressed backup, integrity check, VACUUM, ANALYZE
- `db_maintenance_config` table, `app/maintenance.py` module (backup, restore, vacuum)
- Database Maintenance card in Settings tab (day/time picker, last run status, backup info)
- Startup ad-hoc maintenance: runs automatically on first container start if no previous run exists
- Maintenance failure banner with Restore from Backup option
- Dashboard Database Health card (DB size, maintenance status, backup info)
- Application auto-update feature: check GitHub for new versions, download and apply updates
- `app/updater.py` module (check, download tarball, extract, pip install, restart Gunicorn)
- Application Updates card in Settings tab (Check for Updates, Update Now)
- `/api/health` endpoint for Docker health checks (returns sync thread status)
- Worker resilience: 30s frontend request timeout with unresponsive server banner (Retry/Dismiss)
- Stuck-sync detection: warns if sync progress unchanged for 5 minutes
- Credential (user/platform) displayed on sync status cards and delta sync modal
- Bug/feature request form in Help tab (submits to GitHub Issues)
- Sync dependency chain documented in Help tab (QIDs → CIDs → Policies → Mandates)

### Changed
- About section shows dynamic build ID (git commit SHA) instead of static "v1.0.0"
- Bug/feature request form uses radio buttons instead of dropdown for better dark theme readability
- All browse tabs now CSV-only (PDF removed due to reportlab layout issues with large content fields)
- Bulk CSV export is now unlimited (removed 200-item cap)
- Select mode now hides regular export buttons to prevent accidental full-result exports
- Mandates sync buttons removed from Settings tab (mandates auto-extracted during CID sync, not a separate API)
- Mandate status card now shows read-only extraction info with CID sync timestamp
- Policy sync now requires CIDs to be synced first (returns 400 with helpful message if not)
- CID sync completion now shows toast with mandate extraction count
- Gunicorn timeout reduced from 660s to 120s (syncs run in threads, not blocking HTTP)
- Docker health check added (polls /api/health every 30s, restarts after 3 failures)
- Sync status uses live table counts instead of cached sync_state values
- Mandate sync timestamps inherit from CID sync when more recent

### Fixed
- Supported modules XML parsing handles string/dict/list variants from xmltodict
- PDF word wrap and smart column widths for policy report PDF
- HTML tags stripped from PDF export fields, remediation URLs preserved as plain text
- Select mode export bug: regular CSV button was visible during select mode
- Dashboard sync health for mandates showing "Never synced" despite having records
- Mandate count showing 0 after CID sync (live count fix)

### Removed
- PDF export buttons from all browse tabs (CSV remains; PDF retained only for individual policy reports)
- Mandate Map export button from Mandates tab

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
- Bulk export: Select mode on QID and CID tabs with CSV export of full details including CVEs, diagnosis, solution (Roadmap #46)
- `GET /api/qids/export-details` endpoint for bulk QID detail CSV export (unlimited)
- `GET /api/cids/export-details` endpoint for bulk CID detail CSV export (unlimited)
- Help tab (7th tab) with comprehensive documentation: Quick Start, Data Types, Search, Policy Migration, Bookmarks, Bulk Export, Shortcuts, Troubleshooting (Roadmap #48)
- Keyboard shortcuts modal (`?` key or via Help tab)

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
