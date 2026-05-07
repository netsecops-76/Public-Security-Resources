# Q KB Explorer — Roadmap

## Completed (v1.0)

| # | Feature | Type | Status |
|---|---------|------|--------|
| 1 | QID sync (full & delta) with ID-range chunking | backend | Shipped |
| 2 | CID sync (full & delta) with truncation paging | backend | Shipped |
| 3 | Policy sync (full & delta) | backend | Shipped |
| 4 | Mandate/compliance framework extraction from CID sync | backend | Shipped |
| 5 | FTS5 full-text search across QIDs, CIDs, Policies, Mandates | backend | Shipped |
| 6 | FTS5 prefix matching for type-ahead partial word search | backend, frontend | Shipped |
| 7 | Multi-select filters with AND/OR toggle | frontend | Shipped |
| 8 | CVE type-ahead server search (debounced) | backend, frontend | Shipped |
| 9 | QID detail view (CVSS, CVEs, Bugtraq, vendor refs, threat intel) | frontend | Shipped |
| 10 | CID detail view (technologies, rationale, linked policies, linked mandates) | frontend | Shipped |
| 11 | Policy detail view (linked controls, linked mandates, migration tools) | frontend | Shipped |
| 12 | Mandate detail view (associated controls and derived policies) | frontend | Shipped |
| 13 | Policy export/import (cross-environment migration) | backend, frontend | Shipped |
| 14 | Stale export detection | backend | Shipped |
| 15 | AES-256-GCM credential vault (two-volume Docker security) | backend | Shipped |
| 16 | Multi-credential vault with platform association | backend, frontend | Shipped |
| 17 | Credential verification (secrets.compare_digest) | backend | Shipped |
| 18 | Server-side credential resolution (credential_id) | backend | Shipped |
| 19 | Connection testing (before save and after save) | backend, frontend | Shipped |
| 20 | Sync scheduling (daily/weekly/monthly with timezone) | backend, frontend | Shipped |
| 21 | Persistent sync history (SQLite-backed, 20 entries per type) | backend, frontend | Shipped |
| 22 | Real-time sync progress with elapsed time [MM:SS] | backend, frontend | Shipped |
| 23 | Full sync purge warning modal | frontend | Shipped |
| 24 | Dark/light theme toggle | frontend | Shipped |
| 25 | Cache-busted static assets | backend | Shipped |
| 26 | Feature tour GIF + subtitle player | frontend | Shipped |
| 27 | Qualys platform registry (13 regions) | backend | Shipped |
| 28 | Docker deployment with optional TLS support | infra | Shipped |
| 29 | Delta sync watermarks (Qualys API format) | backend | Shipped |
| 30 | Cross-navigation (CID ↔ Policy, CID ↔ Mandate, Policy ↔ Mandate) | frontend | Shipped |
| 31 | Severity/criticality color-coded cards | frontend | Shipped |
| 32 | Dynamic record count badges (Total | Found | %) | frontend | Shipped |

## Completed (v1.1 — Security)

| # | Feature | Type | Status |
|---|---------|------|--------|
| 33 | Vault-based identity gate (session cookie auth) | backend, frontend | Shipped |
| 34 | before_request route protection (401 for unauthed API calls) | backend | Shipped |
| 35 | Logout endpoint + disconnect button wiring | backend, frontend | Shipped |
| 36 | Global 401 response handler (re-show auth modal) | frontend | Shipped |

## Completed (v1.2 — Dashboard & Export)

| # | Feature | Type | Status |
|---|---------|------|--------|
| 37 | Dashboard tab with severity breakdown charts (Chart.js) | frontend | Shipped |
| 38 | Sync health dashboard (last sync times, health indicators) | backend, frontend | Shipped |
| 39 | Compliance coverage metrics (mandates → controls → policies) | backend, frontend | Shipped |
| 40 | QID statistics (by category, patchable %) | backend, frontend | Shipped |
| 41 | CSV export of search results (QIDs, CIDs, Policies, Mandates) | backend, frontend | Shipped |
| 42 | PDF report generation (tabular export with reportlab) | backend | Shipped |
| 43 | Mandate compliance mapping export (mandate → controls → policies) | backend | Shipped |

## Current State (v1.3)

- 4 data types: QIDs (115K+), CIDs (26K+), Policies, Mandates
- SQLite with WAL mode and FTS5 indexes
- Full & delta sync with Qualys API watermarks
- Multi-select filters with AND/OR toggle and type-ahead
- Policy migration (export/import) with stale detection
- AES-256-GCM vault with two-volume Docker security
- Vault-based identity gate with HttpOnly session cookie auth
- Dashboard with severity/criticality charts, compliance metrics, sync health
- CSV export on all tabs; PDF only for individual policy reports
- Automatic weekly DB maintenance with compressed backup
- Application auto-update from GitHub (Settings tab)
- Worker resilience: health check, stuck-sync detection, unresponsive banner
- Dashboard DB health card
- Bulk select mode for QID/CID with unlimited CSV detail export
- Mandate compliance mapping export (flattened hierarchy)
- Sync scheduling, history, and progress tracking
- Single-page app with 7 tabs (Dashboard, QIDs, CIDs, Policies, Mandates, Settings, Help)
- Keyboard shortcuts, bookmarks, recent searches
- 85 tests passing
- 60 routes (~55 unique API paths + 1 page)
- 13 Qualys platforms supported
- Docker container with Gunicorn production server
- Security hardening: HTML sanitization, rate limiting, CSRF, HttpOnly cookies
- GitHub Actions CI/CD with Dependabot

---

## Completed (v1.3 — Quality of Life)

| # | Feature | Type | Status |
|---|---------|------|--------|
| 44 | Bookmark/favorite QIDs, CIDs, Policies (localStorage) | frontend | Shipped |
| 45 | Recent searches history (localStorage, max 20) | frontend | Shipped |
| 46 | Bulk operations (select mode + unlimited CSV export) | full-stack | Shipped |
| 47 | Keyboard shortcuts (`1`-`7` tabs, `/`, `?`, `t`, `b`) | frontend | Shipped |
| 48 | Help documentation tab (7th tab with 9 sections) | frontend | Shipped |
| 49 | CI/CD with GitHub Actions (pytest on push/PR) | infra | Shipped |

---

## Completed (v2.0 — Tags Phases 1-5 + Sync Robustness + OpenAPI)

| # | Feature | Type | Status |
|---|---------|------|--------|
| 57 | Tags tab — Phase 1: browse + sync (read-only) via QPS REST | full-stack | Shipped |
| 58 | System-vs-user detection from API metadata (default-deny) | backend | Shipped |
| 59 | Qualys best-practice references panel + Help links | frontend | Shipped |
| 60 | QID range expansion (600K→2M ceiling, drop early termination) | backend | Shipped |
| 61 | PM Patch Catalog enrichment via Gateway JWT (`/pm/v2/patches`) | full-stack | Shipped |
| 62 | Intelligence tab — stat strip + chips + filter-aware aggregates | full-stack | Shipped |
| 63 | Tags tab — Phase 2: cross-environment migration (export/import) | full-stack | Shipped |
| 64 | Tags tab — Phase 3: CRUD pushed to Qualys (create/edit/delete) | full-stack | Shipped |
| 65 | Tags tab — Phase 4: custom Library + Apply | full-stack | Shipped |
| 66 | Tags tab — Phase 5: subscription audit (hierarchy/naming/RBAC impact) | full-stack | Shipped |

---

## Completed (v2.1 — Threat Intelligence + Tag Overhaul + PM Linux Fix)

| # | Feature | Type | Status |
|---|---------|------|--------|
| 67 | Threat Intelligence integration (threat badges, exploit/malware details, CISA KEV) | full-stack | Shipped |
| 68 | Intelligence tab overhaul (threat filters, clickable metrics, saved searches, NOT toggle, OR logic) | full-stack | Shipped |
| 69 | Tag origin classification (rule_based, static, connector, system) | backend | Shipped |
| 70 | Tag sub-tabs (Browse/Library/Audit/Migration) | frontend | Shipped |
| 71 | Tag tree view with parent-child hierarchy | frontend | Shipped |
| 72 | Tag Library expanded to 136 entries from Qualys Complete Tag List | backend | Shipped |
| 73 | GLOBAL_ASSET_VIEW replaces ASSET_INVENTORY as preferred rule type | full-stack | Shipped |
| 74 | Tag select mode with bulk migrate/export/delete operations | full-stack | Shipped |
| 75 | Tag provenance tracking for update-vs-create migration | backend | Shipped |
| 76 | Async tag migration with progress bar and origin picker | full-stack | Shipped |
| 77 | PM Linux sync fix (213K patches) | backend | Shipped |
| 78 | QID remediation section with PM patch linking | full-stack | Shipped |
| 79 | Dashboard Data Inventory + Threat Intelligence sections | frontend | Shipped |
| 80 | Themed confirm/prompt dialogs (dark/light mode) | frontend | Shipped |

---

## Completed (v2.2 — Sync Robustness, UX, Updater)

What v2.2 actually shipped diverged from the original v2.2 plan; the
items previously listed here have moved to v2.3.

| # | Feature | Type | Status |
|---|---------|------|--------|
| 81 | QID sync resilience: CVSS-with-attributes unwrap, CORRELATION shape variations, init_db crashloop fix, per-record errors no longer abort the whole sync (all six sync paths) | backend | Shipped |
| 82 | PM Patches delta sync — correct QQL field name (`modifiedDate`) and operator (`>`); graceful one-shot fallback to full-list ingest if QQL is rejected | backend | Shipped |
| 83 | Settings welcome tip on fresh install (auto-routes to Settings; auto-hides on first credential save) | frontend | Shipped |
| 84 | Save Credential gated on a successful Test Connection — prevents typo'd credentials from landing in the vault | full-stack | Shipped |
| 85 | Credential picker re-renders immediately after delete | frontend | Shipped |
| 86 | Vault session minted on credential save — first sync after save no longer triggers the re-auth modal | full-stack | Shipped |
| 87 | In-app updater no longer silently no-ops under gunicorn `--preload` (master-restart path + `--preload` removed from entrypoint) | backend, infra | Shipped |
| 88 | Apply Update progress modal — phase-tracked spinner, auto-reload on server down→up transition, manual fallback at 90s | frontend | Shipped |
| 89 | Automatic Updates schedule (`/api/update/schedule`) — APScheduler cron job runs `apply_update()` on a configured day/time; idempotent disable; ALTER TABLE migration on existing volumes | full-stack | Shipped |
| 90 | UPDATING.md rewritten for users hit by the v2.1 silent-update bug; explicit recovery steps and explanation of the `--preload` pitfall | docs | Shipped |

---

## Completed (v2.4 — Sync Ingest Performance)

| # | Feature | Type | Status |
|---|---------|------|--------|
| 94 | `executemany` for child-table inserts in `upsert_vuln`, `upsert_control`, `upsert_policy`, `upsert_pm_patch` — closes the v2.0 follow-up that was tracked but never shipped | backend | Shipped |
| 95 | Performance characteristics docs — side-by-side reference timings for a high-end developer Mac vs a low-end Hyper-V/Azure RHEL VM, plus hardware and code-side levers | docs | Shipped |
| 96 | Source-hash skip on Delta sync — `source_hash` column on `vulns`, `upsert_vuln(skip_unchanged=True)` short-circuits when payload hash matches | backend | Shipped |
| 97 | Pre-compiled bleach sanitizer reused across calls (was rebuilt per record). Module-level `_BLEACH_CLEANER` instance | backend | Shipped |
| 98 | FTS5 deferred indexing for Full Sync — `fts5_deferred_for_vulns()` / `fts5_deferred_for_controls()` context managers drop triggers, bulk write, then `'rebuild'` once. Eliminates the per-row trigger cost that grew with index size | backend | Shipped |
| 99 | `threat_backfill_done` marker column — `init_db` no longer re-walks tens of thousands of legacy vulns on every container start. Streaming backfill via `fetchmany()` for genuinely-needs-classification rows | backend | Shipped |

---

## Completed (v2.4.1 — init_db Migration Hot-Fix)

| # | Feature | Type | Status |
|---|---------|------|--------|
| 100 | Marker UPDATE chunked into LIMIT 5000 rowid-batched loop with per-batch commits — eliminates the v2.4 single-transaction stall that blocked SQLite checkpoints during the legacy-DB migration on slow storage. Resumable across kills via the marker column itself | backend | Shipped |
| 101 | `_backfill_threat_columns` rewritten — qid worklist + indexed PK lookups replace the v2.4 long-running cursor that hit O(N²) full-table scans on slow CPU because commit() between fetchmany() invalidated the cursor's read snapshot | backend | Shipped |
| 102 | `_init_progress()` stderr helper + `entrypoint.sh` no longer redirects pre-flight stderr to `/dev/null` — migration phase markers now visible in real time via `docker logs`, replacing the prior frozen-output indistinguishable-from-hang behavior | backend | Shipped |
| 103 | `test_marker_update_chunked_is_resumable_across_kills` regression test — proves a kill mid-loop preserves committed work and a restart picks up exactly where it left off | tests | Shipped |
| 104 | BUGS-017 incident write-up + ARCHITECTURE Performance section updated with the v2.4 in-place upgrade failure mode and the v2.4.1 fix path | docs | Shipped |

---

## Planned (v2.5)

| # | Feature | Type | Status |
|---|---------|------|--------|
| 91 | PM Patch Catalog UI — dedicated browse/search tab for the 218K+ patch catalog with filters by platform, vendor, severity, security/non-security, and KB article. Direct patch-to-QID cross-navigation. | full-stack | Planned |
| 92 | Tag migration improvements — inline rename editing in collision preflight, batch rename patterns, drag-and-drop parent reassignment, migration dry-run preview | full-stack | Planned |
| 93 | QID solution text with structured vendor links — parse vendor fix URLs, advisory links, and KB articles from the solution/diagnosis HTML into clickable structured references for macOS, Unix, and other platforms not covered by the PM API | full-stack | Planned |
| 105 | Source-hash skip extension — apply the v2.4 hash-skip pattern to `upsert_control`, `upsert_policy`, `upsert_pm_patch` so non-vuln Delta syncs benefit too | backend | Planned |
| 106 | Add an index on `threat_backfill_done` so the marker UPDATE and worklist-build queries don't scan the full table even on the v2.4.1 path. Defensive: v2.4.1 is fast enough without it on the hardware tested, but a future schema change that adds another batched migration would benefit | backend | Planned |

---

## Completed (Security Hardening)

| # | Feature | Type | Status |
|---|---------|------|--------|
| 50 | HTML sanitization on QID fields (bleach) | backend | Shipped |
| 51 | Rate limiting on credential verification | backend | Shipped |
| 52 | CSRF protection (X-Requested-With header) | full-stack | Shipped |
| 53 | Server-side HttpOnly auth cookie | full-stack | Shipped |
| 54 | Generic error messages (no stack traces) | backend | Shipped |
| 55 | Remove wildcard CORS | backend | Shipped |
| 56 | Dynamic secure cookie flag for TLS | backend | Shipped |
