# Q KB Explorer — Changelog

> Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **Pre-flight collision check on migration**: checks destination for existing tag names before migration starts. Per-tag options: rename (editable suffix), skip, skip all, rename all. Renames and skip lists passed to migration thread.
- **EASM, DNS SINKHOLE, SEM added to system tag list**: EASM, EASM Confidence High/Medium/Low, DNS SINKHOLE, and SEM are now correctly classified as Qualys-provisioned system tags.
- **CLOUD_ASSET rule type → connector origin**: all tags with CLOUD_ASSET rule type are classified as connector-dependent (require matching cloud connectors in destination).
- **Schedule badges for Tags and PM Patches**: delta sync schedule badges now display on Tags and PM Patches rows in Settings.

### Fixed
- **Tag detail crash**: missing `isEditable` variable after banner rewrite caused "Failed to load tag detail" on every click.
- **Tag ownership filter**: "Qualys-managed only" filter now uses `tag_origin='system'` instead of `is_user_created=0` which was always empty.
- **SYSTEM pill accuracy**: driven by `tag_origin` (heuristic name list) instead of `is_user_created` (unreliable — Qualys API doesn't expose `reservedType`).
- **Tag classification persistence**: `_fix_tag_classification()` runs as a dedicated function with its own DB connection after `init_db`, guaranteeing the UPDATE commits regardless of `executescript` transaction state.
- **Auth-required toasts suppressed**: no more error toasts before login when vault is locked. `showToast` silently drops "Authentication required" errors since the login modal is already handling the flow.
- **Delta sync schedule date**: defaults to today when existing schedule has a past start date.
- **Migration "no tags" error**: paginated tag ID fetch (respects 500 per_page API limit).

### Changed
- **"Organizer" renamed to "Static"**: matches Qualys terminology. Tag origin values are now: `rule_based`, `static`, `connector`, `system`.
- **System tag list is exact-name only**: no prefix pattern matching (e.g. `EASM*`) — prevents false positives on user-created tags.


## [v2.1.0] — 2026-05-03 — Intelligence, Threat Intel, Tag Origin, PM Linux Fix

### Added
- **Threat Intelligence integration**: threat_active_attacks, threat_cisa_kev, threat_exploit_public, threat_rce, threat_malware, exploit_count, malware_count columns on vulns table with auto-backfill from stored JSON
- **Threat badges on QID cards**: Active Attacks, CISA KEV, Public Exploit, RCE shown at a glance in search results
- **QID detail Threat Intelligence section**: known exploit links, associated malware, threat indicator tags parsed from Qualys KB correlation data
- **QID detail Remediation section**: vendor fix status, patch published date, solution text prominently displayed with green highlight when patchable
- **QID detail PM Patch Catalog section**: linked patches shown inline grouped by platform with vendor severity, KB links, reboot indicators
- **Intelligence tab threat filters**: Active Attacks, CISA KEV, Public Exploit, RCE, Malware, Has Exploits on dedicated filter row
- **Intelligence tab clickable metrics**: clicking a stat card drills into the matching found set (additive filter refinement)
- **Intelligence tab active filter bar**: shows applied filters as removable tags with NOT toggle (click to negate — blue=include, red=exclude), expand/collapse for long filter sets
- **Intelligence tab saved searches**: save/load named filter sets to localStorage
- **Tags sub-tabs**: Browse, Library, Audit, Migration — each in its own sub-tab panel (matches Policies pattern)
- **Tag tree view**: parent-child grouping with collapsible chevrons, load-on-expand from DB, recursive sub-parent nesting. Flat card view when filters active.
- **Tag Library grouped by rule type**: collapsible sections with rule-type status pills. Read-only detail modal. Clone/Apply from detail view.
- **Tag Library seed expanded to 136 entries**: sourced from Qualys "Complete Tag List" (Colton Pepper) + AWS/Azure/GCP/OCI cloud state tags
- **Tag origin classification**: heuristic classifies tags as rule_based, static, connector, or system. Shown as badge on cards. Used in migration to group by category.
- **Tag select mode**: Select button with Select All, individual selection persists across pagination, "+ children" button on parent cards for recursive child selection
- **Tag export to JSON**: instant download from local DB (no Qualys API calls), supports select all
- **Tag import from JSON**: import shared tag collections into local DB for browse/audit/migrate
- **Tag delete from Qualys**: bulk delete user-created tags from source subscription with system tag protection
- **Tag migration origin picker**: modal shows breakdown by origin (rule_based/static/connector/system) with per-category checkboxes. System tags hard-excluded.
- **Tag migration async with progress**: runs in background thread, polls every 1.5s with progress bar, persists reports to /data/migration_reports/
- **Tag provenance tracking**: source_platform, source_subscription columns. Included in JSON export. Migration uses provenance for update-vs-create logic.
- **Tag audit improvements**: duplicate findings clustered with full tag cards, rule descriptions explaining each audit check, clean-state lists all checks passed
- **Dashboard Data Inventory section**: all 6 data types (QIDs, CIDs, Policies, Mandates, Tags, PM Patches) in consistent card format
- **Dashboard Threat Intelligence summary**: Active Attacks, CISA KEV, Public Exploits, RCE, Has Exploits counts
- **Sync Health table**: now includes Tags and PM Patches rows
- **PM API test script**: scripts/test_pm_api.py for Qualys PM v2 API exploration
- **Themed confirm/prompt dialogs**: all native browser dialogs replaced with dark/light mode matching modals

### Fixed
- **PM Linux sync returning 0 patches**: isSuperseded:false filter removed for Linux (field is null on Linux patches, not false). Full 213K Linux catalog now syncs.
- **PM pre-count always returning None**: gateway_count now reads count from response headers (where Qualys PM v2 API puts it) instead of response body.
- **Tag classification: 92 tags misclassified as system**: only tags with reservedType are system. Tags without it (imported, migrated, static) now correctly classified as user-created.
- **Intelligence filter logic AND→OR**: selecting PM Win + PM Lin now returns union (either platform) not intersection. Same for threat filters.
- **Tag migration worker timeout**: migrating 167+ tags killed gunicorn worker. Now runs in async background thread.
- **Tag "Select All" then migrate returning empty**: per_page=100000 rejected by OpenAPI validation (max 500). Now paginates correctly.
- **Toast hidden behind modals**: z-index raised to 99999 (above modal 9999).
- **Migration errors invisible**: errors now shown inside modal results area AND as toast.

### Changed
- **ASSET_INVENTORY → GLOBAL_ASSET_VIEW**: all 86 seed library entries updated. ASSET_INVENTORY marked legacy with pointer to GLOBAL_ASSET_VIEW. Rule type filter now driven by local DB content only (no static list).
- **VULN_DETECTION added as recognized rule type** alongside VULN_EXIST.
- **Rule type labels**: dropdown shows context (e.g. "GLOBAL_ASSET_VIEW (preferred)", "OS_REGEX (legacy)", "GROOVY (restricted)")
- **Rule type warnings on library cards**: legacy/restricted notices surface in card UI and Apply modal pointing to preferred replacement.
- **QID search Clear button**: moved next to Search button (matches Intelligence tab pattern)
- **color-scheme CSS property**: added for proper native form element theming in dark/light mode

### Performance
Benchmarked on a production Qualys POD3 subscription (Docker Desktop, macOS M-series):

| Data Type | Records | Full Sync | Improvement |
|-----------|---------|-----------|-------------|
| QIDs | 208,307 | **8.8 min** | 14x faster (was 125 min) |
| CIDs | 26,921 | **15.1 min** | 2x faster (was 31.8 min) |
| PM Patches | 218,050 | **3.1 min** | 5x faster (was 14.9 min) |
| QID Delta | 208,307 base | **2 seconds** | Near-instant |

Key optimisations: populated-range targeting skips empty QID id-space windows, batched SQLite transactions per page, FTS5 incremental rebuild, PM v2 cursor pagination at 1,000 items/page, and response-header count extraction (eliminates the dedicated count endpoint round-trip).


## [v2.0.0] — 2026-05-02 — Tags Phases 1-5, Sync Robustness, OpenAPI

Major release. Merged via squash from PR #12 (53 commits). Headline:
all five Tags phases (read · migrate · CRUD · library · audit), every
sync path made queue-safe and rate-limit-friendly, code-driven OpenAPI
documentation at `/api/docs`, and the caching-middleware framing
spelled out for downstream consumers.

### Fixed
- `KeyError: 'tags'` at the end of every Tags sync — `update_sync_state`'s local `table_map` was missing the `tags` entry, so the watermark update threw after page records had already been committed. Tags sync now completes cleanly and Settings shows the right count.
- `UnboundLocalError: get_db` on the tag/CID/policy/QID sync paths after the batched-transaction refactor. Inner `from app.database import get_db` lines made `get_db` a function-local name, shadowing the module-level import and breaking the new top-of-page `with get_db() as conn:` blocks. Inner imports removed.
- `init_db()` crash when upgrading from a DB without the `disabled` column — `CREATE INDEX idx_vulns_disabled` in `_SCHEMA_SQL` ran before the migration's `ALTER TABLE ADD COLUMN`. Index creation moved into the migration block.

### Sync robustness & rate-limit friendliness
This release reorganises every sync path so manually triggering a Full or Delta on multiple data types is safe and predictable. **Set them all and walk away** — no more babysitting a queue or worrying about stacking requests against the Qualys rate limit.

> See **README → Understanding sync modes** for an end-user-facing explanation of how the universe, verification, and Backfill Missing work, including the use-case difference between Backfill and Delta.

- **Manual syncs are queued, not failed fast.** A global sync mutex serialises one sync at a time. If a sync is already running and you click another, the new request is **queued** rather than rejected; you get a `200 OK` with `queued: true` and the worker thread picks it up as soon as the current sync finishes. The previous behaviour (immediate 409) forced you to wait, retry, and time-coordinate clicks; that's gone.
- **Universal 409 / 429 retry on every Qualys call.** `QualysClient` honours `Retry-After` headers and applies exponential backoff up to 3 retries on rate-limit and conflict responses, on the v4 KB API, the QPS REST API, and the PM Gateway. Logs surface `RATE_LIMIT_RETRY` events so you can see exactly what was throttled and for how long.
- **Pre-count + populated-range targeting on QIDs.** Full sync first walks the universe with `details=Basic` to enumerate every QID, then issues detail (`details=All`) requests **only against 10K windows that actually contain QIDs**. Empty regions of the QID id-space are skipped entirely. Result: roughly half the API calls a naive scan would make, and an exact denominator for the progress bar.
- **Pre-count + verify on every type.** Same pattern now applied to CIDs, Policies, Tags, and PM Patches. After each Full sync, a verification step diffs the universe against the local DB and surfaces any QIDs that didn't land. `VERIFY_OK` / `VERIFY_MISSING` events appear in the sync log.
- **Persisted KB universe.** Pre-count results write to a new `sync_universe` table keyed on `(data_type, item_id)`. Backfill no longer needs to re-walk the universe — it's a single indexed `LEFT JOIN` against the table you already have. **~10–15 fewer Qualys calls per Backfill click** after the first run.
- **Backfill button knows when there's nothing to do.** `last_missing_count` is persisted on `sync_state` after every full-sync and backfill verification. Once verified clean, the Backfill Missing button hides itself; when there's a known gap, the button shows the count inline (`Backfill Missing (12,345)`).
- **Scheduled delta syncs unchanged.** The scheduler still uses a blocking acquire on the same mutex so background deltas serialise naturally with manual work, but the existing scheduler timing/ordering is intact.

### Performance
- **Batched per-page transactions on every sync type.** Each upsert helper (`upsert_vuln`, `upsert_control`, `upsert_policy`, `upsert_tag`, `upsert_pm_patch`, `extract_mandates_from_control`) now accepts an optional `conn` so the on-page loop wraps the entire page worth of writes in a single transaction.
  - **Real-world result: marginal, not transformational.** Same QID full sync re-run on 208,307 records: **7,611s post-fix vs 7,516s pre-fix** — about flat (the new run also enabled `show_disabled_flag=1`, slightly larger payloads, so the wash isn't surprising). Per-chunk timings on the big windows shifted maybe 5–15% faster (`750000` chunk: 8:00 → was 9:11; `990000` chunk: 10:02 → was 10:55), but my hypothesis that per-commit fsync overhead dominated was wrong.
  - **What the bottleneck actually is.** Per-record cost is dominated by *per-statement SQL work + Python work*, not commit fsyncs. Each `upsert_vuln` still issues an `INSERT OR REPLACE` on the parent + `DELETE` + N `INSERT`s on five child tables (CVEs / bugtraqs / vendor refs / RTI / supported modules), plus `bleach.sanitize_html` on three fields and `json.dumps` on several others. For a 9,700-record chunk, that's ~50ms/QID of pure work regardless of how many transactions wrap it.
  - **Why the change is still worth keeping.** Single-transaction per page is the right SQLite shape independent of speedup; it eliminates a class of "sync writes interrupted mid-record" partial-state bugs and makes future bulk-write work (executemany, skip-unchanged) tractable. It's also a no-op when called from the standalone helpers, so non-sync paths are unaffected.
  - **Follow-up work** to actually move the needle: profile a single `upsert_vuln` to confirm where the milliseconds go; switch child-table writes to `executemany`; skip `DELETE`+`INSERT` on child tables when the row's data hasn't changed (compare a hash of the source payload). Tracked but not in this release.
  - Tag enrichment (per-tag GET) intentionally left per-record — HTTP latency dominates and a long-held write lock there would block UI reads.
- **SQLite concurrency hardening.** `busy_timeout` raised to 120s, `synchronous=NORMAL`, exponential-backoff retry on `database is locked`. Combined with the mutex above, the "policy + KB sync at the same time → database is locked" failure is gone.

### Smart Policy → CID dependency handling
- **Auto-queue CIDs ahead of Policies.** Clicking Policies sync when CIDs haven't synced no longer 400s with "CID data required." `trigger_sync` now checks whether the dependency is satisfied (last_sync set, currently running, or already queued) and, when it isn't, auto-spawns a CID sync first then queues Policies behind it. Response carries `auto_queued_dependencies: ["cids"]` plus a message so the UI can surface "we queued CIDs first because Policies depends on them."

### Recovery from interrupted syncs
- **Startup cleanup of unfinished sync_log_runs.** When the container is restarted while a sync is queued or in-flight, the run row gets stranded at `status='running'` with no `finished_at` — and the renderer flags every subsequent log view with "Worker was killed — sync did not complete." On startup `init_db()` now closes those rows out (`status='error'`, `finished_at=now()`) so previous logs render cleanly and the next time the user opens Last Sync Details they see "Interrupted" instead of an alarm.

### Use as a caching middleware
Q KB Explorer's documented JSON API plus its scheduled-delta auto-maintenance make it usable as a **local caching tier** between Qualys and your other tools (dashboards, ticketing, reporting, custom scripts). Multiple downstream consumers share one set of Qualys credentials, one sync schedule, and one rate-limit budget — no more N tools each making duplicate API calls. The OpenAPI 3 spec at `/api/docs/openapi.json` is the consumer-facing contract; see **README → Use as a Qualys API caching middleware** for the architecture diagram and wiring guide.

### Added
- **Intelligence tab** — single-screen QID lens with stat strip, severity multi-toggle, KB/PM/PCI quick filters, vuln-type checkboxes, category dropdown, and per-row PM patch counts (Win/Lin). Keyboard shortcut `6`; tabs after Mandates shifted accordingly.
- **PM Patch Catalog enrichment** — full sync of Qualys Patch Management catalog (Windows + Linux) via Gateway JWT. New `pm_patches`, `pm_patch_qids`, `pm_patch_cves` tables; `/api/qids/<qid>/patches` and `/api/pm/stats` endpoints; `pm_any` / `pm_win` / `pm_lin` filters on `/api/qids`; multi-select severities and vuln types.
- **QID range expansion** — bumped `QID_MAX_ID` 600K → 2M and effectively disabled empty-chunk early termination so dormant gaps in Qualys' sparse QID space don't truncate the scan.
- **Tags tab (Phase 1 — read-only browse + sync)** for Qualys Asset Tags via the QPS REST API
  - New `tags`, `tag_exports`, and `tags_fts` SQLite tables with FTS5 full-text search
  - `SyncEngine.sync_tags()` full + delta sync against `/qps/rest/2.0/search/am/tag` with cursor-based pagination
  - System-vs-user detection driven entirely by API metadata (no hard-coded name list); ambiguous tags default to system (read-only)
  - `[SYSTEM]` pill on Live Tags identifying Qualys-managed tags by `reservedType`; tooltip surfaces the raw value
  - Collapsible Qualys best-practice references panel linking articles 000005817, 000005818, 000005819 plus CSAM docs
  - Tag detail modal with parent breadcrumb, children list, color swatch, rule logic, and system banner
  - Filters: full-text query, rule type (multi-select), ownership (User-created / Qualys-managed / All)
  - Keyboard shortcut for the Tags tab (`6`); Settings shifted to `7`, Help to `8`
  - 18 new tests covering search, filter, detail, breadcrumb, system-vs-user detection, default-deny, sync wiring, and QPS helper parsing
- `QualysClient.execute_json()` for JSON-body QPS REST calls plus `qps_extract_data` / `qps_has_more` static helpers
- Dynamic build ID in About section (git SHA from Docker build or auto-update)
- Contact email field in bug/feature request form for follow-up
- Build version and browser info auto-included in GitHub issue body
- Post-update reload polls /api/health until server responds (replaces fixed 5s delay)
- Dockerfile BUILD_VERSION arg bakes git SHA into image at build time
- Auto-update scheduling (weekly cron with day/time picker in Settings)
- Sync health tooltips on dashboard status dots explaining criteria (age thresholds, recommended actions)
- Supported modules (agent type) display and filtering on QID tab
- Module badges on QID search result cards (sky-blue)
- Supported Modules multi-select filter in QID advanced filters
- Supported Modules field in QID detail modal
- Supported Modules column in QID CSV export
- `vuln_supported_modules` database table
- Development Foundation onboarding (docs/, .github/dependabot.yml)
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
- Delta sync modal body scrolls within viewport (fixed header/footer always visible)
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
