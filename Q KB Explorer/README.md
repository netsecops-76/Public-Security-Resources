# Q KB Explorer

Qualys Knowledge Base & Policy Compliance explorer with local caching, full-text search, cross-referencing, and cross-environment policy migration. Doubles as a **local caching middleware** that other tools can read from instead of hitting the Qualys API directly — see [Use as a Qualys API caching middleware](#use-as-a-qualys-api-caching-middleware).

Built on the same credential vault, Docker infrastructure, and API patterns as [Qualys API Engine](https://github.com/netsecops-76/Qualys_API_Engine).

## Features

### Dashboard
- Data Inventory row showing 6 data types (QIDs, CIDs, Policies, Tags, PM Patches, Mandates) in consistent card format
- Threat Intelligence summary row
- Sync Health table includes Tags and PM Patches alongside QIDs, CIDs, and Policies

### Knowledge Base (QIDs)
- Full & delta sync of the Qualys vulnerability knowledge base (200K+ QIDs)
- ID-range chunked sync for fast initial loads (~3.5 min for full KB)
- Full-text search across titles, diagnosis, consequence, and solution fields
- Multi-select filters: CVE (type-ahead server search), Category, Severity, Patchable
- Threat Intelligence badges on search cards (Active Attacks, CISA KEV, Public Exploit, RCE)
- Detail view with CVSS v2/v3 scores, CVE links, Bugtraq refs, vendor references, and affected software
- QID detail: Threat Intelligence section with exploit links, malware details, and threat indicator tags
- QID detail: Remediation section with vendor fix status and patch published date
- QID detail: PM Patch Catalog section with linked patches by platform
- Severity color-coded cards (Critical=red, High=orange, Medium=yellow, Low=blue, Info=gray)
- Dynamic record count badge: Total | Found | % updates after each search

### Compliance Controls (CIDs)
- Full & delta sync of compliance controls (26K+ CIDs)
- Full-text search across statements, categories, and comments
- Multi-select filters: Category, Technology (type-ahead), Criticality
- Detail view with check type, technologies with rationale, and linked policies
- Cross-navigation: click a linked policy to jump to the Policies tab

### Policy Compliance
- Full & delta sync of compliance policies
- Full-text search across policy titles
- Multi-select filters: Status, Control Category, Technology, CID, Control Name
- Detail view with all linked controls
- **Policy Migration**: cross-environment export/import with offline XML storage
  - Export policies from source environment (stored as XML blobs in SQLite)
  - Import to destination environment with editable titles
  - Batch operations with per-policy progress tracking
  - Stale export warnings when policies are modified after export

### Asset Tags (Phases 1–5 shipped)
- **Tags tab split into Browse / Library / Audit / Migration sub-tabs** for organized workflows. See [TAGS_MIGRATION.md](docs/TAGS_MIGRATION.md), [TAGS_LIBRARY.md](docs/TAGS_LIBRARY.md), [TAGS_AUDIT.md](docs/TAGS_AUDIT.md) for the per-phase docs.
- **Browse + sync** (Phase 1): Full + delta sync via QPS REST, FTS over name / rule_text / description, filters by rule type and ownership. Auto-applying rule-type filter — pick a pill, list updates.
- **Parent-child tree view** with load-on-expand and recursive nesting. Tag origin classification (rule_based, static, connector, system) shown as badges.
- **Select mode with bulk operations**: Migrate to env, Export to JSON, Import JSON, Delete local, Delete from Qualys. "+ children" button for recursive child selection on parent tags.
- **Cross-environment migration** (Phase 2): Pull a tag's full JSON from one Qualys environment, stage it locally, push it into another. Bundle-from-disk import for cross-machine moves. Tag provenance tracking (source_platform, source_subscription) for update-vs-create migration logic. Async migration with progress bar, origin category picker, persistent reports.
- **CRUD pushed to Qualys** (Phase 3): Create / edit / delete tags directly from the UI. Pre-flight validation (regex compile, CIDR parse, port range bounds, etc.) and a **Test on Qualys** button that previews the rule against the asset universe before commit.
- **Tag Library expanded to 136 built-in entries** from Qualys Complete Tag List (Colton Pepper). Library grouped by rule type with legacy/restricted warnings. User entries are full CRUD; Apply pushes any entry into a destination Qualys environment. Audit log of every Apply.
- **Subscription audit** (Phase 5): Read-only inventory analysis surfaces hierarchy issues (orphans / cycles / depth > 8 / wide root branches), naming issues (whitespace / duplicates / length), duplicate rule-text, and override awareness. Export findings as CSV.
- **System-vs-user classification** is driven entirely by Qualys API metadata, never a hardcoded list. Manual `classification_override` per tag for ambiguous cases.
- **Editability is a separate axis from classification** — some Qualys-managed tags (Internet Facing Assets, Business Units) accept rule edits; `is_editable` auto-derives from the rule type, with a `Force Editable` per-tag override.
- **Best-practice rule-type guidance** in the form: `OS_REGEX` + `OPERATING_SYSTEM` + `ASSET_INVENTORY` flagged as legacy with `GLOBAL_ASSET_VIEW` as the recommended replacement; `GROOVY` flagged as restricted (subscription-gated).

### Intelligence
- Filtered KnowledgeBase intelligence dashboard with stat strip
- Threat filter chips: Active Attacks, CISA KEV, Public Exploit, RCE, Malware, Has Exploits
- Clickable metric cards for drill-down into found set
- Active filter bar with NOT toggle (blue=include, red=exclude)
- Save/load named searches
- OR logic for same-category filters (PM Win + PM Lin = union)
- All severity levels displayed with compact second row

### PM Patch Catalog
- Full Windows + Linux patch catalog sync (218K+ patches)
- Linux patches now sync correctly (isSuperseded filter fix)
- QID-to-patch linking with per-QID patch detail in QID detail view
- Patch counts from response headers (not body)

### Settings
- **Credential Vault**: AES-256-GCM encrypted credential storage with server-side decryption
  - Encryption key and vault data on separate Docker volumes for defense in depth
  - Save multiple credentials for different Qualys platforms/environments
  - Connection testing before saving
- **Platform Registry**: All 13 Qualys platform regions (US1-4, EU1-2, IN1, UAE1, KSA1, CA1, AU1, UK1, GOV)
- **Sync Management**: Trigger full/delta sync per data type with real-time progress and elapsed time [MM:SS]
  - Full sync purge warning: confirmation modal warns that all data for the type will be deleted and re-downloaded (useful when switching Qualys tenants)
  - **Set them all and walk away**: clicking Full Sync (or Delta) on multiple data types while one is running **queues** the new requests instead of failing. The worker thread runs them serially as soon as the current one finishes — you don't have to wait for each one and click the next, and you can't accidentally stack concurrent requests against the Qualys rate limit.
  - **Rate-limit-friendly retries**: every Qualys call (v4 KB, QPS REST, PM Gateway) honors `Retry-After` on 409/429 with exponential backoff up to 3 attempts. Retries appear in the sync log as `RATE_LIMIT_RETRY` events.
  - **Pre-count + populated-range targeting (QIDs)**: full sync first walks the universe with `details=Basic` to enumerate every QID, then issues detail requests only against 10K windows that actually contain QIDs. Empty regions of the QID space are skipped — about half the API calls of a naive scan and an exact denominator for the progress bar.
  - **Verify-after-sync**: every full sync diffs the universe against the local DB and surfaces any records that didn't land. `VERIFY_OK` / `VERIFY_MISSING` events appear in the sync log.
  - **Backfill Missing**: pull only the QIDs your local DB is missing without a full re-pull. The button hides itself when a verifying sync confirms zero missing; when there's a known gap, the button shows the count inline so you can decide whether to click.
  - **Batched per-page transactions**: each sync's per-page upserts now run in a single SQLite transaction. Previously thousands of records per chunk meant tens of thousands of separate WAL fsyncs (5–10 min stalls on large QID chunks); now it's one fsync per chunk.
- **Sync Log**: Persistent sync history with event-level detail (stored in SQLite)
  - Last Sync Details modal with "Show History" / "Hide History" toggle for previous runs (up to 20)
- **Theme Toggle**: Dark/light mode

### Technical
- SQLite with WAL mode and FTS5 full-text search indexes
- Delta sync using Qualys API watermarks (only fetch records modified since last sync)
- Qualys API v4 with XML response parsing via xmltodict
- Reusable multi-select dropdown component with type-ahead (client-side filtering for small sets, debounced server search for large sets)
- Cache-busted static assets
- Single gunicorn worker with 660s timeout for long-running syncs
- Optional TLS support (mount certs or set env vars)

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/netsecops-76/Q_KB_Explorer.git
cd Q_KB_Explorer
docker compose build && docker compose up -d
```

Open **http://localhost:5051** in your browser.

### Updating

After your initial setup, future updates are handled through the in-app updater (Settings → Check for Updates → Apply). No container rebuild needed for regular updates.

If you're upgrading from an older version or ran into issues, see **[UPDATING.md](UPDATING.md)** for recovery steps and details on the new manifest-driven update system.

### First Run

1. Go to the **Settings** tab
2. Select your Qualys platform region
3. Enter your Qualys API credentials and click **Test Connection**
4. Save the credential
5. Click **Sync** next to each data type (QIDs, CIDs, Policies) to populate the local database

## Understanding sync modes

The Settings tab offers three actions per data type — they do different things and are not interchangeable. The tool also runs a verification step after every Full sync so you don't have to take its word that the download was complete.

### Pre-count and the "universe"

Before downloading the heavy detail payload, every Full sync walks Qualys with a cheap **"list me what exists"** call (`details=Basic`). The result is a complete list of every item Qualys reports for that data type — every QID, CID, policy, etc. The tool calls this the **universe** and stores it in a local `sync_universe` table.

The universe drives three things:

- **Exact progress denominator.** The progress bar shows X of Y instead of "X of an unknown total" because Y is known up front.
- **Targeted detail pass.** For QIDs specifically, the detail pass only hits 10K id-windows that actually contain data. About half the API calls of a naive 0→2M scan.
- **Verification.** After the detail pass finishes, the tool diffs the universe against the local DB. Any record Qualys reported that didn't land surfaces as `VERIFY_MISSING` in the sync log; a clean run logs `VERIFY_OK`. This catches silent partial failures that would otherwise look "successful" because the HTTP requests all returned 200.

### Full Sync

Use Full Sync when you're connecting a new Qualys tenant, switching tenants, or the tool warns the existing data is stale (>30 days). It **purges the local table for that data type** and re-downloads everything via pre-count + verify.

### Delta Sync

Use Delta Sync routinely. It pulls **what changed in Qualys since the last sync** using Qualys' modified-after timestamp filter. New QIDs added by Qualys, updated policies, edited CIDs — everything Qualys flags as having changed.

Delta does not detect items that are missing from your local DB but unchanged in Qualys (e.g., something that errored mid-flight on the previous sync). For that, use Backfill.

#### Schedule Delta Syncs (set it and forget it)

Click **Delta Sync** on any data type's row and the modal offers two options: **Run once (now)** or **Schedule recurring**. Pick recurring and the tool maintains the data in the background — you don't have to log in and remember to click sync.

- **Frequencies:** Daily · Twice a week · **Once a week (recommended)** · Twice a month · Once a month. Pick **Daily** when downstream consumers need fresh data — the [caching-middleware use case](#use-as-a-qualys-api-caching-middleware) is the most common reason.
- **Start date and time** are configurable. Pick something off-hours (the modal defaults to 02:00) so the sync isn't competing with the user's interactive work.
- **Per-data-type.** QIDs, CIDs, Policies, Tags, and PM Patches each have their own schedule. You can set them all to the same cadence or stagger them.
- **Schedules persist.** They're stored in the SQLite DB and restored on container restart by the in-process APScheduler — no external cron, no Celery, no Redis required.
- **Always uses Delta semantics.** Scheduled jobs ask Qualys "what changed since the last sync" — they never trigger a Full sync (which would purge and re-download everything).
- **Visible in the UI.** When a data type has an active schedule, a badge appears on its sync row showing the next run time. The Delta Sync modal also shows the currently scheduled cadence so you can adjust or remove it from the same place you set it up.
- **Plays nicely with manual work.** Scheduled jobs use the same global sync mutex as manual syncs, so a scheduled run that fires while you're doing something interactive will queue and run when the manual sync finishes — never overlapping, never thrashing the Qualys rate limit.
- **Misfire tolerance:** if the container is offline when a scheduled run is due, it'll run on the next start within an hour of the missed slot rather than waiting for the following cadence.

A typical setup: schedule weekly Delta on QIDs/CIDs/Policies/Tags at 02:00 Sunday, point it at the credential you've stored in the vault, and walk away. The dashboard will show fresh data every Monday morning.

### Backfill Missing (currently QIDs only)

Use Backfill Missing when:

- A Full sync was interrupted (network blip, container restart, rate-limit hit before retry kicked in) and you don't want to start over from scratch.
- A Qualys API parameter changed what comes back (e.g., enabling `show_disabled_flag` exposed records that the previous sync didn't capture). You want the additional fields without re-downloading everything.
- The verification step on the last Full sync flagged `VERIFY_MISSING` and you want to recover the gap.

Backfill **does not purge**. It diffs the persisted universe against your local table, fetches only the records you're missing, and appends them. Typically it's one HTTP request per 100 items — minutes vs. hours for a fresh Full sync.

#### When the button appears

The Backfill Missing button is **only visible when the tool has determined something is missing**. Specifically:

- **Hidden** after a Full sync verifies clean (zero records missing). There's nothing to backfill, so the button would be a no-op.
- **Shown with the count inline** (`Backfill Missing (12,345)`) when verification found a gap, or when a Qualys API parameter change has expanded the universe beyond what's locally stored.
- **Shown without a count** before any verifying sync has run — the tool doesn't have a number yet, so it leaves the button available.

If you click Backfill Missing and the result is `0 records`, that means the universe and your local DB already match — exactly what the button's auto-hide is meant to communicate, but it's also a valid manual sanity check.

### Sync Performance

Real-world benchmarks from a production Qualys POD3 subscription. These numbers include pre-count, detail download, parsing, SQLite upsert, FTS index rebuild, and post-sync verification — the complete end-to-end time.

| Data Type | Records | Full Sync Time | Throughput |
|-----------|---------|---------------|------------|
| **QIDs (Knowledge Base)** | 208,307 | **8.8 minutes** | ~395 QIDs/sec |
| **CIDs (Controls)** | 26,921 | **15.1 minutes** | ~30 CIDs/sec |
| **Policies** | 82 | **3.5 minutes** | ~0.4 policies/sec (heavy XML payloads) |
| **Tags** | 167 | **25 seconds** | ~7 tags/sec |
| **PM Patches** | 218,050 | **3.1 minutes** | ~1,172 patches/sec |
| **QID Delta Sync** | 208,307 (base) | **2 seconds** | Near-instant (only changed records) |

**Why QIDs are fast:** The sync engine uses a populated-range targeting strategy — it walks the QID id-space with a cheap `details=Basic` pre-count pass, then only issues expensive `details=All` requests against 10K-wide windows that actually contain data. Empty regions of the 0→2M QID space are skipped entirely, cutting API calls roughly in half versus a naive full-range scan. Every page is committed in a single batched SQLite transaction, and the FTS5 index rebuilds incrementally.

**Why PM Patches are fast:** The Qualys PM v2 Gateway API uses `searchAfter` cursor pagination (no 10K offset cap) with 1,000-item pages. The entire Windows + Linux catalog downloads in ~5 pages of Windows data plus ~213 pages of Linux data, all streamed into batched transactions.

**Why Delta Syncs are instant:** Qualys' `modified_since` filter returns only records changed since the last watermark. On a subscription that's been synced within the last day, Delta typically returns 0–50 records in a single API call.

> **Benchmark context:** These times were observed on a Docker Desktop deployment (macOS, M-series, 16 GB RAM) talking to Qualys POD3. Your times will vary based on network latency, Qualys server load, and subscription size. The sync engine respects Qualys rate limits (409/429 with `Retry-After` backoff), so even if you hit throttling the sync completes — it just takes longer.

### Quick reference

| Use case | Action |
|---|---|
| First-ever sync, or switching Qualys tenants | **Full Sync** |
| Routine update — pick up Qualys changes since last sync | **Delta Sync** |
| Hands-off ongoing maintenance, no manual clicks | **Delta Sync → Schedule recurring** |
| Recovering from an interrupted Full sync without starting over | **Backfill Missing** |
| Adding a new field that requires re-pulling existing records | **Backfill Missing** |
| Reconciling a `VERIFY_MISSING` warning from the sync log | **Backfill Missing** |

Delta syncs run automatically on subsequent syncs, fetching only records modified since the last sync.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `production` | Flask environment |
| `QKBE_BIND` | `0.0.0.0` | Gunicorn bind address |
| `QKBE_PORT` | `5000` | Gunicorn port (mapped to 5051 externally) |
| `QKBE_WORKERS` | `1` | Gunicorn workers (keep at 1 for sync state consistency) |
| `QKBE_TLS_CERT` | `/app/certs/server.crt` | TLS certificate path |
| `QKBE_TLS_KEY` | `/app/certs/server.key` | TLS private key path |

### Docker Volumes

| Volume | Mount | Contents |
|--------|-------|----------|
| `qkbe-keys` | `/keys` | AES-256 encryption key (`.vault_key.bin`) |
| `qkbe-data` | `/data` | Encrypted vault (`vault.json`) + SQLite database (`qkbe.db`) |

The encryption key and vault data are stored on separate volumes. An attacker would need access to both volumes to decrypt stored credentials.

### TLS

Mount your certificate and key to `/app/certs/`:

```yaml
volumes:
  - ./certs/server.crt:/app/certs/server.crt:ro
  - ./certs/server.key:/app/certs/server.key:ro
```

Or set `QKBE_TLS_CERT` and `QKBE_TLS_KEY` environment variables.

## Use as a Qualys API caching middleware

Q KB Explorer isn't just an interactive UI. The same locally cached data is exposed through a documented JSON API — which means other tools in your environment can pull from **your local Q KB Explorer** instead of hitting the Qualys cloud API directly.

This is useful when you have multiple downstream consumers (dashboards, ticket integrations, vulnerability prioritization scripts, asset-mapping pipelines, custom reports) that all need Qualys data. Rather than each tool maintaining its own credentials and hammering the Qualys API on its own schedule, point them at Q KB Explorer.

### What you get

- **Single source of truth.** One scheduled Delta Sync (see [Schedule Delta Syncs](#schedule-delta-syncs-set-it-and-forget-it)) keeps the local DB current; every downstream consumer reads from that copy.
- **No duplicate Qualys API calls.** Five tools that previously each made their own catalog pulls now share one. Concurrency limits and rate-limit budgets get back the headroom that was being burned on duplicate work.
- **Faster downstream queries.** Local SQLite + FTS5 returns search results in milliseconds vs. seconds-to-minutes for a paginated Qualys API call. Bulk `GET /api/qids?...` over the local network beats remote KB pagination by 1–2 orders of magnitude.
- **Operates while Qualys is degraded.** If Qualys has a service incident or your egress is impaired, downstream tools keep working against the last successful sync. Sync resumes automatically when the API is back.
- **Vendor-neutral consumers.** Downstream tools talk to Q KB Explorer's REST/JSON API; they don't need to know the Qualys XML/v4 vs. QPS REST vs. Gateway JWT distinction.

### Architecture

```
                       ┌─────────────────────┐
                       │   Qualys Cloud API  │
                       │   (v4 KB / QPS /    │
                       │    PM Gateway)      │
                       └──────────┬──────────┘
                                  │
                          1× scheduled Delta
                          (or manual Full)
                                  │
                                  ▼
                       ┌─────────────────────┐
                       │  Q KB Explorer      │
                       │  (this app)         │
                       │                     │
                       │  • SQLite + FTS5    │
                       │  • Vault-stored     │
                       │    Qualys creds     │
                       │  • Sync engine      │
                       │  • OpenAPI surface  │
                       └──────────┬──────────┘
                                  │
                       Local LAN, no Qualys cost
                                  │
              ┌───────────────┬───┴────┬────────────────┐
              ▼               ▼        ▼                ▼
        Dashboards     Ticketing   Reporting       Custom scripts
        (Grafana,      (Jira,      (PowerBI,       (Python, Go,
         Tableau)       ServiceNow) Tableau)        bash + jq)
```

### How to wire downstream consumers

1. **Stand up Q KB Explorer once** with credentials for your Qualys subscription stored in the vault (Settings tab).
2. **Schedule weekly Delta syncs** for the data types you'll consume (typical: QIDs, CIDs, Policies, Tags). One Sunday-night cadence is enough for most reporting workflows.
3. **Point downstream tools at Q KB Explorer's API.** The OpenAPI 3 spec at `/api/docs/openapi.json` can be imported into Postman, Insomnia, OpenAPI Generator (for client SDKs in any language), or any tool that consumes a spec. Endpoints support FTS, faceted filters, pagination, and bulk export.
4. **(Optional) Front it with TLS.** Set `QKBE_TLS_CERT` / `QKBE_TLS_KEY` so internal consumers can talk to it over HTTPS. The vault session model still applies — consumers either authenticate by hitting `/api/credentials/verify` once (cookie-based session) or, if your environment doesn't need the identity gate for read-only consumers, run Q KB Explorer behind your normal LAN auth.

### What this is *not*

- **Not a Qualys API proxy.** Q KB Explorer doesn't forward arbitrary calls to Qualys. It exposes the data types it caches (QIDs, CIDs, Policies, Mandates, Tags, PM Patches) through its own search/filter API. If a consumer needs something Q KB Explorer doesn't cache, that tool still talks to Qualys directly.
- **Not real-time.** Data is as fresh as the last sync. For workloads that need second-by-second accuracy (live scans), keep talking to Qualys. For everything that's a snapshot of the catalog or compliance state — which is most of it — local cache is fine and is usually preferable.

## API Reference

The running app serves an interactive OpenAPI 3 reference at:

| URL | What it is |
|---|---|
| `/api/docs` | Redirects to Swagger UI (default) |
| `/api/docs/swagger/` | Swagger UI — try-it-out interface |
| `/api/docs/redoc/` | ReDoc — read-only, three-pane reference layout |
| `/api/docs/scalar/` | Scalar — modern alternative UI |
| `/api/docs/openapi.json` | Raw OpenAPI 3 spec (machine-readable) |

The spec is auto-generated from pydantic models attached to each route via [SpecTree](https://github.com/0b01001001/spectree), so it stays in sync with the code. Endpoint annotation is being rolled out incrementally; routes that aren't yet annotated still appear in the spec but with a generic shape until they're decorated.

### Data Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/qids?q=&cve=&severity=&category=&patchable=&page=&per_page=` | Search QIDs |
| `GET` | `/api/qids/<qid>` | QID detail |
| `GET` | `/api/qids/filter-values?field=categories\|cves&q=` | Filter dropdown values |
| `GET` | `/api/cids?q=&category=&criticality=&technology=&page=&per_page=` | Search CIDs |
| `GET` | `/api/cids/<cid>` | CID detail |
| `GET` | `/api/cids/filter-values?field=categories\|technologies&q=` | Filter dropdown values |
| `GET` | `/api/policies?q=&status=&control_category=&technology=&cid=&control_name=&page=&per_page=` | Search policies |
| `GET` | `/api/policies/<id>` | Policy detail |
| `GET` | `/api/policies/filter-values?field=control_categories\|technologies\|cids\|control_names&q=` | Filter dropdown values |
| `GET` | `/api/policies/stale-exports` | List policies modified since last export |

### Sync Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/sync/status` | Sync state for all data types |
| `POST` | `/api/sync/qids` | Trigger QID sync |
| `POST` | `/api/sync/cids` | Trigger CID sync |
| `POST` | `/api/sync/policies` | Trigger policy sync |
| `GET` | `/api/sync/<type>/progress` | Real-time sync progress |
| `GET` | `/api/sync/<type>/log` | Sync event log |

### Policy Migration Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/policies/<id>/export` | Export policy XML from Qualys |
| `POST` | `/api/policies/import` | Import policy XML to destination |

### Credential Vault Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/credentials` | List saved credentials (no passwords) |
| `POST` | `/api/credentials` | Save new credential |
| `PATCH` | `/api/credentials/<id>` | Update credential |
| `DELETE` | `/api/credentials/<id>` | Delete credential |
| `POST` | `/api/credentials/verify` | Verify credential password |
| `POST` | `/api/test-connection` | Test Qualys API connectivity |
| `GET` | `/api/platforms` | List all Qualys platform regions |

## Development

### Local Setup

```bash
python3 -m venv venv
source venv/bin/activate
# Production deps only — what ships in the Docker image:
pip install -r requirements.txt
# OR pull in pytest + production deps in one step (recommended for local dev):
# pip install -r requirements-dev.txt
flask --app app.main run --port 5051
```

### Running Tests

```bash
pip install -r requirements-dev.txt   # pytest comes from here
python3 -m pytest tests/ -v
```

48 tests covering routes, credential vault, database CRUD, FTS search, pagination, CVE cross-references, policy-control links, export storage, and sync state management.

## Project Structure

```
Q_KB_Explorer/
├── app/
│   ├── main.py              # Flask app, routes, platform registry
│   ├── vault.py             # AES-256-GCM credential vault
│   ├── database.py          # SQLite schema, CRUD, FTS search
│   ├── qualys_client.py     # Qualys API HTTP client
│   ├── sync.py              # Sync engine (full/delta for QIDs, CIDs, Policies)
│   ├── sync_log.py          # Persistent sync log (SQLite-backed)
│   ├── templates/
│   │   └── index.html       # Single-page application
│   └── static/
│       ├── css/style.css    # Dark/light theme styles
│       ├── js/app.js        # Frontend logic + MultiSelect component
│       └── img/qualys-shield.svg
├── tests/
│   └── test_app.py          # 48 tests
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh
└── requirements.txt
```

## License

Private repository. All rights reserved.
