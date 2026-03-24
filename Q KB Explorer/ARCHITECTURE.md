# Q KB Explorer — Architecture

> Last updated: 2026-03-10

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
| WSGI Server  | Gunicorn                 | 23.0.0   |
| Container    | Docker (python:3.12-slim)| 3.12     |

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Browser (SPA)                         │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌────────┐ ┌────────┐ ┌──┐│
│  │Dashbd│ │ QIDs │ │ CIDs │ │Policies│ │Mandates│ │  ││
│  └──────┘ └──────┘ └──────┘ └────────┘ └────────┘ │⚙️││
│   app.js (3,389 LOC) · Chart.js · style.css        └──┘│
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP (JSON)
┌──────────────────────▼──────────────────────────────────┐
│                Flask Application (main.py)               │
│  ┌─────────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ Auth Gate    │  │ 45 API   │  │ CSV/PDF Export    │  │
│  │ (vault      │  │ Routes   │  │ (reportlab)       │  │
│  │  cookies)   │  │          │  │                   │  │
│  └─────────────┘  └──────────┘  └───────────────────┘  │
└────────┬──────────────┬──────────────────┬──────────────┘
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

| Module            | Responsibility                                        | File               | LOC   |
|-------------------|-------------------------------------------------------|---------------------|-------|
| Routes            | HTTP endpoints, request validation, auth gate         | app/main.py         | 1,518 |
| Database          | Schema, CRUD, FTS5 search, filter queries, migrations | app/database.py     | 2,211 |
| Sync Engine       | Full/delta sync, chunking, watermarks, progress       | app/sync.py         | 449   |
| Sync Log          | Event-level sync diagnostics, SQLite persistence      | app/sync_log.py     | 380   |
| Qualys Client     | HTTP client, XML parsing, platform registry           | app/qualys_client.py| 365   |
| Scheduler         | APScheduler background jobs, recurring syncs          | app/scheduler.py    | 335   |
| Vault             | AES-256-GCM encryption, credential CRUD               | app/vault.py        | 255   |
| Frontend App      | SPA logic, search, filters, modals, charts            | app/static/js/app.js| 3,389 |
| Styles            | Dark/light themes, cards, badges, layout              | app/static/css/style.css | 1,091 |
| Template          | Single-page HTML with 6 tabs                          | app/templates/index.html | 956 |

## Data Flow

### Sync Flow
```
User triggers sync → main.py route → sync.py engine
  → qualys_client.py HTTP POST → Qualys API XML response
  → xmltodict parsing → database.py upsert_vuln/upsert_control/etc.
  → SQLite INSERT OR REPLACE → FTS5 index rebuild
  → sync_log.py event recording → progress callback → SSE to browser
```

### Search Flow
```
User types query → app.js _qidSearchParams() → GET /api/qids?q=...
  → main.py _parse_qid_filters() → database.py search_vulns()
  → FTS5 MATCH + SQL WHERE conditions → paginated results
  → JSON response → app.js renderQidResults() → DOM update
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

## Database Schema

### Core Data Tables
| Table                    | Purpose                                    | Primary Key       |
|--------------------------|--------------------------------------------|-------------------|
| vulns                    | QID knowledge base entries (114K+)         | qid               |
| controls                 | CID compliance controls (26K+)             | cid               |
| policies                 | Qualys compliance policies                 | policy_id         |
| mandates                 | Compliance frameworks/mandates             | mandate_id        |

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

### FTS5 Virtual Tables
| Table          | Indexes                              |
|----------------|--------------------------------------|
| vulns_fts      | qid, title, category, diagnosis      |
| controls_fts   | cid, statement, category             |
| mandates_fts   | mandate_id, title, description       |

## Security Architecture

```
┌─────────────────────────────────┐
│ Docker Container                │
│                                 │
│  /keys/ (700) ─── AES-256 key  │  ← Separate volume
│  /data/ (700) ─── vault.json   │  ← Separate volume
│                    qkbe.db      │
│                                 │
│  Auth Gate ────── Cookie check  │
│  Vault ────────── AES-256-GCM  │
│  Passwords ────── compare_digest│
│  Optional TLS ── /app/certs/   │
└─────────────────────────────────┘
```

- **Defense-in-depth:** Encryption key and encrypted data on separate Docker volumes
- **Auth gate:** All API routes require vault unlock cookie (except credential management)
- **Password comparison:** `secrets.compare_digest()` prevents timing attacks
- **TLS:** Auto-detected from `/app/certs/` directory (cert.pem + key.pem)

## External Dependencies

| Dependency     | Purpose                    | Risk Level | Notes                          |
|----------------|----------------------------|------------|--------------------------------|
| Qualys API     | Source of all KB/policy data| Medium     | Rate-limited (300 req/hr)      |
| SQLite         | Local data store           | Low        | Built into Python, no server   |
| Chart.js       | Dashboard visualizations   | Low        | Bundled, no CDN dependency     |
| reportlab      | PDF report generation      | Low        | Pure Python, no system deps    |
