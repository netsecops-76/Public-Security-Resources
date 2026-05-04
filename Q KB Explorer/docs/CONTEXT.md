# Q KB Explorer — Development Context

> Last updated: 2026-05-03
> Latest release: **v2.1.0** shipped on main

## Current State Summary
- **Active phase:** v2.1 shipped — Threat Intelligence, Tag Origin Classification, Intelligence Tab Overhaul, PM Linux Fix
- **Last completed task:** Threat Intelligence integration (threat badges, exploit/malware details, CISA KEV), Intelligence tab overhaul (threat filters, clickable metrics, saved searches, NOT toggle, OR logic), Tag origin classification + sub-tabs + tree view + library expansion to 136 entries, GLOBAL_ASSET_VIEW as preferred rule type, tag select mode with bulk operations, async tag migration with provenance tracking, PM Linux sync fix (213K patches), QID remediation with PM patch linking, Dashboard Data Inventory + Threat Intelligence sections, themed confirm/prompt dialogs.
- **Next priority:** Operator-driven — gather real-world feedback on the v2.1 surface before committing to v2.2 scope.
- **Open candidate work** (none committed yet):
  - Performance: profile a single `upsert_vuln` to find the actual per-record bottleneck (the batched-transaction change in v2.0 was flat in practice — see CHANGELOG)
  - Wider OpenAPI annotations: 35 of ~90+ endpoints fully typed; remaining are admin/auth/maintenance routes that show generic shapes
  - Custom QID-detail / tag-export PDF report templates (was deferred when reportlab hit memory walls on large QIDs)
- **Active blockers:** None
- **Open bugs:** None known beyond the dependabot moderate-severity advisory on `cryptography` (tracked at https://github.com/netsecops-76/Q_KB_Explorer/security/dependabot/3)
- **Qualys API findings:**
  - PM v2 only supports Windows/Linux platforms; macOS is not available via the PM API
  - Tag API does not expose `createdBy` or `reservedType` fields
  - Threat data comes from KB API `correlation`/`threat_intelligence` fields

## Recent Decisions & Context

### 2026-05-02 — v2.0.0 release (PR #12)
Single squash-merge into main carrying:

- **Tags Phase 1** — read-only browse + sync via QPS REST. System-vs-user classification driven by API metadata (no hardcoded list). Auto-applying rule-type filter, manual classification override per tag, raw payload viewer.
- **Tags Phase 2** — cross-environment migration. Export captures the source-env JSON; upload pushes into a destination env via `QualysClient.create_tag` with source-env metadata stripped. Bundle-import-from-disk supports cross-machine moves.
- **Tags Phase 3** — full CRUD against Qualys. New `/api/tags/create`, `/<id>/update`, `/<id>/delete`, plus pre-flight `/validate` and `/test-rule` (Qualys preview, graceful fallback when tenant doesn't expose `/evaluate/am/tag`). Pure-Python `tag_validation.py` shared between client and server.
- **Tags Phase 4** — Custom Library + Apply. `tag_library` + `tag_library_applied` schema. Eight conservative built-in starter patterns seeded automatically (RFC 1918, loopback, Windows OS, Linux OS, web/db ports, DC-by-name, manual). Built-ins re-seed across upgrades, hide-not-delete, user `is_hidden` choice survives. Apply audit log records every push.
- **Tags Phase 5** — subscription audit + best-practice rule-type guidance. Read-only `app/tag_audit.py` with 10 rules across hierarchy / naming / rule-text dedup / overrides. `OS_REGEX` + `OPERATING_SYSTEM` flagged as legacy (replacement: `ASSET_INVENTORY`); `GROOVY` flagged restricted (subscription-gated, Test on Qualys is the ground-truth check).
- **Tag editability axis** independent of system/user classification. `is_editable` auto-derived; `editability_override` per-tag manual override. Internet Facing Assets (and similar Qualys-managed-but-tunable tags) get a green editable banner instead of being read-only blocked.
- **Sync robustness:** global `threading.Lock` mutex serialises one sync at a time; manual syncs queue instead of failing fast. Universal 409/429 retry with `Retry-After` honored across v4 KB / QPS REST / PM Gateway. Pre-count + populated-range targeting for QID full sync (~half the API calls of a naïve scan, exact denominator for the progress bar). Persisted `sync_universe(data_type, item_id)` table drives Backfill (no re-walk needed) and the post-sync verify step. **Smart Policy → CID auto-queue** — clicking Policies when CIDs haven't synced auto-queues CIDs first. **Daily** added to recurring-delta cadence list for middleware consumers. Live "peek under the hood" event ticker on active syncs.
- **Performance reality check:** batched-transaction change for sync writes was **flat** in practice (7,611s vs 7,516s on 208,307 QIDs). Per-record cost is dominated by per-statement SQL work (DELETE+INSERT × 5 child tables, bleach.sanitize_html, json.dumps), not commit fsyncs. Change kept anyway — correct SQLite shape, eliminates partial-state bugs, sets up `executemany`-style follow-ups. Real follow-up profiling deferred.
- **Intelligence stats fix (urgent):** the stat strip endpoint used to run 11 separate `search_vulns` calls per tab open / filter change, repeatedly blowing past the 30s frontend timeout on 200K-row data and triggering "Server unresponsive" cascades. Replaced with a single conditional-aggregate query against a CTE. Drops endpoint latency from ~30s to hundreds of ms.
- **OpenAPI scaffolding:** SpecTree-based, code-driven. `/api/docs` (Swagger UI), `/api/docs/redoc/`, `/api/docs/scalar/`, `/api/docs/openapi.json`. 35 of 84 endpoints fully annotated with pydantic models — every search/detail/filter-values + sync ops + library + intelligence + health/platforms/schedules.
- **Caching-middleware framing in README:** explicit positioning for the "use Q KB Explorer as a local caching tier between Qualys and other tools" pattern, with architecture diagram and wiring guide.

### 2026-05-01 — Tags Feature Phase 1 (initial work, superseded by v2.0)
- Tags tab between Mandates and Settings; QPS REST search + detail; classification heuristic with manual override; Qualys best-practice articles linked. Phases 2-5 above are the follow-on work that landed on 2026-05-02.

### 2026-03-25 — Build ID, Issue Form, Post-Update Reload Fix
About section shows dynamic build ID (git SHA). Issue form uses radio buttons + Contact email + build version in body. Post-update reload polls `/api/health` instead of fixed 5s delay. Dockerfile bakes git SHA via BUILD_VERSION arg.

### 2026-03-25 — Startup Ad-Hoc Maintenance
First-run container with no maintenance history kicks off backup + VACUUM + ANALYZE in a background thread after 10s.

### 2026-03-25 — GitHub Issue Submission Form
Bug-report / feature-request form on Help tab opens a pre-filled GitHub issue against `Public-Security-Resources` with the right label.

### 2026-03-24 — Auto-Update + Dashboard DB Health + Worker Resilience + Weekly Maintenance + Sync UX + Export Cleanup + Security Hardening + CI/CD + Phase 4 QoL
Bundle of changes — full per-item history was preserved through v1.3.0; v2.0 supersedes the sync UX bullet (sync mutex + queue + retry + verify replaces the original CID-prerequisite-error pattern).

### 2026-03-10 — Supported Modules + Project Onboarding
Supported modules surfaced on QID tab. Development Foundation v4.0.0 applied.

## Conversation Continuity Notes
- **Trunk-based**, commit directly to main via squash-merged PRs (PR #12 was the v2.0 squash).
- **Docker rebuild** — local Mac dev: `git pull origin main && docker compose up -d --build`.
- **Tests** — `pip install -r requirements-dev.txt && python3 -m pytest tests/ -q` (240 tests, all passing on main).
- **OpenAPI docs** at `/api/docs` (Swagger UI), `/api/docs/openapi.json` is the spec for tooling. 35/84 endpoints fully typed; the rest still appear with generic shapes.
- **Sync dependency chain:** QIDs (independent) → CIDs (independent) → Policies (auto-queues CIDs first if needed) → Mandates (auto-extracted from CIDs) → Tags (independent) → PM Patches (independent).
- **Sync mutex** serialises one at a time; clicking another while one runs queues. Same-type click on a queued/running data type returns 409.
- **Universal 409/429 retry** with exponential backoff up to 3 attempts on every Qualys call.
- **Mandate sync buttons** still removed from UI; backend `/api/sync/mandates` still works for direct callers.
- **Tag editability** has its own axis — `is_editable` + `editability_override` separate from `is_user_created`. Internet-Facing-Assets and Business-Units are SYSTEM but EDITABLE.
- **OS_REGEX / OPERATING_SYSTEM are legacy** rule types — UI flags them with `GLOBAL_ASSET_VIEW` as the preferred replacement (replaces `ASSET_INVENTORY`). **GROOVY** is restricted; Test on Qualys is the truth.
- **reportlab PDF generation** still hangs on large HTML content — do NOT re-add PDF export to browse tabs.
- **Browser caching** still aggressive after Docker rebuild — hard refresh or incognito if the page looks stale.
- **Auto-update** pulls from `github.com/netsecops-76/Public-Security-Resources` branch `Q-KB-Explorer` (separate from this repo's main branch).
- **Worker resilience** layers: Gunicorn 660s timeout (was 120s), Docker health check, frontend 30s request timeout, stuck-sync 10min (was 5min, softened wording). Polled `loadSyncStatus` every ~20s during a sync to keep the meta line live.
- **Caching-middleware** is the recommended positioning for downstream-tool consumers; `/api/docs/openapi.json` is the importable contract.

## Architecture Snapshot
- **Key modules:**
  - `main.py` — Flask routes (~90+ paths), 35 with `@openapi.validate`
  - `database.py` — SQLite schema + helpers + idempotent migrations
  - `sync.py` — sync engine for every data type; pre-count + verify + batched on_page transactions
  - `qualys_client.py` — v4 XML + QPS REST JSON + PM Gateway JWT; `create_tag` / `update_tag` / `delete_tag` / `evaluate_tag_payload` for tag CRUD
  - `tag_validation.py` — pure-Python validator shared by client + server (legacy/restricted rule-type metadata included)
  - `tag_audit.py` — read-only Phase 5 audit rules
  - `library_seed.py` — eight built-in tag library starter patterns (re-seeded on init_db)
  - `vault.py` — AES-256-GCM credential vault
  - `scheduler.py` — APScheduler recurring delta syncs (daily / 2x_week / 1x_week / 2x_month / 1x_month)
  - `openapi.py` — SpecTree instance + shared `Error` / `Pagination[T]` / `OkMessage` models + tag groupings
  - `maintenance.py` (backup/vacuum), `updater.py` (auto-update), `sync_log.py` (event log)
- **Schema:** ~30 tables (vulns, controls, policies, mandates, tags, pm_patches, sync_state, sync_universe, tag_library, tag_library_applied, tag_exports, sync_log_runs/events + relationship + FTS5 virtual tables)
- **Endpoint count:** ~90+ unique paths
- **Tab count:** 9 (Dashboard, QIDs, CIDs, Policies, Mandates, Intelligence, Tags, Settings, Help) — Tags has 4 sub-tabs (Browse/Library/Audit/Migration)
- **Test count:** 240+ passing
- **Migration head:** inline in `_SCHEMA_SQL` + `init_db()`; idempotent ALTER TABLE / CREATE IF NOT EXISTS / data-carry blocks. The kb_universe → sync_universe migration is the largest ad-hoc carry.

## Onboarding Instructions
1. Read this file (`CONTEXT.md`) for current state
2. Read `ARCHITECTURE.md` for system design
3. Read `CHANGELOG.md` v2.0.0 entry for what shipped most recently
4. Read `TAGS_MIGRATION.md` / `TAGS_LIBRARY.md` / `TAGS_AUDIT.md` for tag-flow specifics
5. Read `BUGS.md` for the (currently empty) open-issue list
6. Hit `/api/docs/swagger/` on a running container for the live API surface
7. Resume from "Next priority" above
