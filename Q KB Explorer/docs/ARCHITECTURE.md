# Q KB Explorer — Architecture

> Last updated: 2026-05-03

## System Overview

Q KB Explorer is a local caching and exploration tool for the Qualys Knowledge Base. It syncs QIDs, CIDs, Policies, and Mandates from Qualys cloud APIs into a local SQLite database, enabling fast full-text search, cross-reference navigation, compliance mapping, and cross-environment policy migration — all through a single-page web UI.

## Technology Stack

| Component    | Technology               | Version  |
|--------------|--------------------------|----------|
| Backend      | Flask (Python)           | 3.1.3    |
| Frontend     | Vanilla JavaScript       | ES6+     |
| Charts       | Chart.js                 | bundled  |
| Database     | SQLite (WAL + FTS5)      | built-in |
| Encryption   | cryptography (AES-256-GCM) | 46.0.5 |
| Scheduler    | APScheduler              | 3.10.4   |
| HTTP Client  | requests + xmltodict     | 2.32.4   |
| PDF Reports  | reportlab                | 4.4.0    |
| HTML Sanitizer | bleach                 | 6.3.0    |
| Rate Limiter | flask-limiter            | 4.1.1    |
| WSGI Server  | Gunicorn                 | 23.0.0   |
| Container    | Docker (python:3.12-slim)| 3.12     |

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                       Browser (SPA)                           │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌────────┐ ┌────────┐ ┌──┐┌──┐ │
│  │Dashbd│ │ QIDs │ │ CIDs │ │Policies│ │Mandates│ │⚙️││ ? │ │
│  └──────┘ └──────┘ └──────┘ └────────┘ └────────┘ └──┘└──┘ │
│   app.js (3,713 LOC) · Chart.js · style.css (1,155 LOC)     │
└──────────────────────────┬───────────────────────────────────┘
                           │ HTTP (JSON)
┌──────────────────────────▼───────────────────────────────────┐
│                 Flask Application (main.py)                    │
│  ┌─────────────┐  ┌──────────┐  ┌───────────────────┐       │
│  │ Auth Gate    │  │ 55 API   │  │ CSV/PDF Export    │       │
│  │ (HttpOnly    │  │ Routes   │  │ (reportlab)       │       │
│  │  cookies)   │  │ + CSRF   │  │                   │       │
│  └─────────────┘  └──────────┘  └───────────────────┘       │
└────────┬──────────────┬──────────────────┬───────────────────┘
         │              │                  │
┌────────▼────┐  ┌──────▼──────┐  ┌───────▼────────────┐
│ Vault       │  │ Database    │  │ Sync Engine        │
│ (vault.py)  │  │(database.py)│  │ (sync.py)          │
│ AES-256-GCM │  │ 19 tables   │  │ full/delta modes   │
│ /keys vol   │  │ 3 FTS5      │  │ ID-range chunking  │
└─────────────┘  └──────┬──────┘  └───────┬────────────┘
                        │                  │
                 ┌──────▼──────┐  ┌───────▼────────────┐
                 │ SQLite DB   │  │ Qualys API Client  │
                 │ /data vol   │  │ (qualys_client.py) │
                 │ WAL mode    │  │ 13 platform regions│
                 └─────────────┘  │ XML → dict parsing │
                                  └────────────────────┘
                                           │
                                  ┌────────▼────────────┐
                                  │ Qualys Cloud APIs   │
                                  │ /api/4.0/fo/        │
                                  │ knowledge_base/vuln/│
                                  │ compliance/control/ │
                                  │ compliance/policy/  │
                                  └─────────────────────┘
```

## Module Map

| Module            | Responsibility                                                         | File                       | LOC   |
|-------------------|------------------------------------------------------------------------|-----------------------------|-------|
| Routes            | HTTP endpoints, request validation, auth gate, CSRF, OpenAPI decorators | app/main.py                 | 3,715 |
| Database          | Schema, CRUD, FTS5 search, filter queries, idempotent migrations        | app/database.py             | 4,137 |
| Sync Engine       | Pre-count + populated-range targeting, batched on_page transactions, verify | app/sync.py             | 1,561 |
| Sync Log          | Event-level sync diagnostics, SQLite persistence, render-text helpers   | app/sync_log.py             | 380   |
| Qualys Client     | v4 XML + QPS REST JSON + PM Gateway JWT; tag CRUD + evaluate            | app/qualys_client.py        | 1,048 |
| Scheduler         | APScheduler recurring delta syncs (daily / 2x_week / 1x_week / 2x / 1x_month) | app/scheduler.py        | 579   |
| Vault             | AES-256-GCM encryption, credential CRUD                                  | app/vault.py                | 255   |
| Tag Validation    | Pure-Python rule-type validators shared by client + server (Phase 3)     | app/tag_validation.py       | 325   |
| Tag Audit         | Read-only inventory analysis with pre-check integration, clustered duplicate display, and explanatory pass/fail output | app/tag_audit.py            | 411   |
| Library Seed      | 136 curated tag library entries (Qualys "Complete Tag List" by Colton Pepper); idempotent seed | app/library_seed.py         | 173   |
| OpenAPI           | SpecTree instance + shared `Error` / `Pagination[T]` / `OkMessage` models | app/openapi.py             | 123   |
| Maintenance       | DB backup (gzip), VACUUM, ANALYZE, restore                                | app/maintenance.py          | 183   |
| Updater           | GitHub version check, tarball download, apply update                      | app/updater.py              | 228   |
| Frontend App      | SPA logic, shortcuts, bookmarks, tags CRUD/migration/library/audit UI     | app/static/js/app.js        | 6,234 |
| Styles            | Dark/light themes, cards, badges, layout, severity colour cues            | app/static/css/style.css    | 1,511 |
| Template          | Single-page HTML with 9 tabs (Dashboard, QIDs, CIDs, Policies, Mandates, Intelligence, Tags, Settings, Help) + modals | app/templates/index.html | 1,795 |

## Data Flow

### Sync Flow
```
User triggers sync → main.py route
  → global sync mutex acquire (queue if held — manual syncs never fail-fast)
  → sync.py engine
    → pre-count walk (details=Basic) → sync_universe upsert
    → detail pass over populated 10K windows
      → qualys_client.py HTTP POST (Retry-After honored on 409/429,
        exp backoff, ≤3 attempts)
      → Qualys API XML response → xmltodict parsing
      → on_page handler: single get_db() block per page, batched upserts
        via upsert_vuln/upsert_control/upsert_policy/upsert_tag/upsert_pm_patch
        (one transaction per page, not per record)
      → SQLite INSERT OR REPLACE → FTS5 index updated by triggers
    → verify pass: diff sync_universe vs live table → last_missing_count
  → mutex release → next queued sync (if any) starts
  → sync_log.py event recording → progress callback → SSE to browser
```

Key properties:

- **Serial execution.** A `threading.Lock` mutex in `main.py` guarantees one sync runs at a time. Manual syncs that arrive while one is running are queued (FIFO) and acknowledged with `200 + queued: true` so the UI can tell the user when their work will start. Scheduled deltas use the same blocking acquire.
- **Rate-limit-friendly retries.** Every Qualys call (`v4 KB`, `qps_*`, `gateway_*`) goes through a retry helper that honors `Retry-After`, applies exponential backoff, and caps at 3 attempts. Each retry is logged as `RATE_LIMIT_RETRY` so the operator can see throttling without parsing HTTP.
- **Pre-count + populated-range targeting.** QID full sync first enumerates every QID with `details=Basic`, then runs detail (`details=All`) requests only against 10K id-windows that actually contain QIDs. Roughly half the API calls of a naive 0→2M scan and an exact denominator for the progress bar.
- **Persisted universe.** The pre-count writes to `sync_universe(data_type, item_id, last_seen_at)`. Backfill diffs this against the live table — no re-walk needed. Full-sync verification uses the same diff to populate `sync_state.last_missing_count`, which drives the Backfill Missing button's visibility and inline count.
- **Batched per-page commits.** The page-handler `with get_db() as conn:` block wraps the entire page-worth of upserts in a single SQLite transaction. Pre-batching, a 9,700-QID chunk meant ~50K WAL fsyncs (5–10 min); post-batching, it's one commit per page (seconds).
- **PM patches sync fix.** Linux patches with `isSuperseded=null` were previously miscounted. The fix reads the patch count from response headers rather than relying on the `isSuperseded` field, ensuring accurate counts regardless of platform.

### Search Flow
```
User types query → app.js _qidSearchParams() → GET /api/qids?q=...
  → main.py _parse_qid_filters() → database.py search_vulns()
  → FTS5 MATCH + SQL WHERE conditions → paginated results
  → JSON response → app.js renderQidResults() → DOM update
```

### Bulk Export Flow
```
User enters select mode → checkboxes appear on cards
  → selects items → clicks Export CSV
  → GET /api/qids/export-details?ids=1,2,3&format=csv
  → main.py fetches full detail for each ID → CSV response
  → browser downloads file
```

### Policy Migration Flow
```
Export: Policy detail → POST /api/policies/{id}/export
  → qualys_client.py fetch full XML → database.py store export_xml
  → GET /download-xml or POST /export-zip for download

Import: POST /api/policies/upload → read stored XML
  → qualys_client.py POST to destination Qualys environment
  → response with new policy_id
```

### Tag Migration Flow (v2.1.0 — async)
```
User selects tags on Browse tab → clicks "Migrate to env…"
  → Audit pre-check runs automatically (warns if findings exist)
  → Modal collects: destination credential, origin filter,
    parent tag option, per-tag overrides
  → POST /api/tags/migrate
    → background thread spawned, migration_id returned immediately
    → thread iterates selected tags:
      → provenance check (source_platform + source_subscription)
        → same subscription → update existing tag
        → different subscription or unknown → create new tag
      → POST /qps/rest/2.0/create/am/tag (or update)
      → progress counter incremented
    → frontend polls GET /api/tags/migrate/<id>/status every 1.5s
      (auth-exempt endpoint — survives session expiry)
    → progress bar rendered from completed/total counts
  → completion report persisted to /data/migration_reports/
  → UI shows collapsible migrated/skipped/failed sections
```

## Database Schema

### Core Data Tables
| Table                    | Purpose                                    | Primary Key       |
|--------------------------|--------------------------------------------|-------------------|
| vulns                    | QID knowledge base entries (200K+); includes threat intelligence columns (threat_active_attacks, threat_cisa_kev, exploit_count, etc.) | qid               |
| controls                 | CID compliance controls (26K+)             | cid               |
| policies                 | Qualys compliance policies                 | policy_id         |
| mandates                 | Compliance frameworks/mandates             | mandate_id        |
| tags                     | Qualys Asset Tags (QPS REST); includes tag_origin, source_platform, source_subscription for provenance tracking | tag_id            |
| tag_exports              | Offline JSON storage for tag migration     | tag_id            |

### Relationship Tables
| Table                    | Links                                      | Key               |
|--------------------------|--------------------------------------------|-------------------|
| vuln_cves                | QID → CVE IDs                              | (qid, cve_id)     |
| vuln_bugtraqs            | QID → Bugtraq IDs                          | (qid, bugtraq_id) |
| vuln_vendor_refs         | QID → Vendor references                    | (qid, vendor_ref_id) |
| vuln_rti                 | QID → Real-Time Threat Indicator tags      | (qid, rti_tag)    |
| vuln_supported_modules   | QID → Supported scanner/agent modules      | (qid, module_name)|
| control_technologies     | CID → Technology associations              | (cid, technology)  |
| policy_controls          | Policy → CID linkage                       | (policy_id, cid)   |
| mandate_controls         | Mandate → CID linkage                      | (mandate_id, cid)  |

### Metadata Tables
| Table                    | Purpose                                    |
|--------------------------|--------------------------------------------|
| sync_state               | Watermarks and last sync timestamps        |
| sync_log_runs            | Sync execution history (20 per type)       |
| sync_log_events          | Detailed sync event log                    |
| sync_schedules           | Recurring sync schedule definitions        |
| db_maintenance_config    | Weekly maintenance schedule and last run    |

### FTS5 Virtual Tables
| Table          | Indexes                              |
|----------------|--------------------------------------|
| vulns_fts      | qid, title, category, diagnosis      |
| controls_fts   | cid, statement, category             |
| mandates_fts   | mandate_id, title, description       |
| tags_fts       | tag_id, name, rule_text, description |

## Security Architecture

```
┌─────────────────────────────────┐
│ Docker Container                │
│                                 │
│  /keys/ (700) ─── AES-256 key  │  ← Separate volume
│  /data/ (700) ─── vault.json   │  ← Separate volume
│                    qkbe.db      │
│                                 │
│  Auth Gate ────── HttpOnly cookie│
│  CSRF ─────────── X-Requested-With│
│  Rate Limit ───── 5/min verify  │
│  Vault ────────── AES-256-GCM  │
│  Passwords ────── compare_digest│
│  Sanitization ─── bleach       │
│  Optional TLS ── /app/certs/   │
└─────────────────────────────────┘
```

- **Defense-in-depth:** Encryption key and encrypted data on separate Docker volumes
- **Auth gate:** All API routes require HttpOnly vault unlock cookie (except credential management)
- **CSRF protection:** `X-Requested-With: QKBE` header required on POST/PATCH/DELETE
- **Rate limiting:** 5 requests/minute on `/api/credentials/verify`
- **HTML sanitization:** bleach strips dangerous tags from QID content fields
- **Password comparison:** `secrets.compare_digest()` prevents timing attacks
- **TLS:** Auto-detected from `/app/certs/` directory (cert.pem + key.pem); sets `secure=True` on cookie

## External Dependencies

| Dependency     | Purpose                    | Risk Level | Notes                          |
|----------------|----------------------------|------------|--------------------------------|
| Qualys API     | Source of all KB/policy data| Medium     | Rate-limited (300 req/hr)      |
| SQLite         | Local data store           | Low        | Built into Python, no server   |
| Chart.js       | Dashboard visualizations   | Low        | Bundled, no CDN dependency     |
| reportlab      | PDF report generation      | Low        | Pure Python, no system deps    |
| bleach         | HTML sanitization          | Low        | Well-maintained, no native deps|
| flask-limiter  | Rate limiting              | Low        | In-memory storage (single worker) |
