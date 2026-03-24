# Q KB Explorer

Qualys Knowledge Base & Policy Compliance explorer with local caching, full-text search, cross-referencing, and cross-environment policy migration.

Built on the same credential vault, Docker infrastructure, and API patterns as [Qualys API Engine](https://github.com/netsecops-76/Qualys_API_Engine).

## Features

### Knowledge Base (QIDs)
- Full & delta sync of the Qualys vulnerability knowledge base (114K+ QIDs)
- ID-range chunked sync for fast initial loads (~3.5 min for full KB)
- Full-text search across titles, diagnosis, consequence, and solution fields
- Multi-select filters: CVE (type-ahead server search), Category, Severity, Patchable
- Detail view with CVSS v2/v3 scores, CVE links, Bugtraq refs, vendor references, threat intel, exploit/malware correlation, and affected software
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

### Settings
- **Credential Vault**: AES-256-GCM encrypted credential storage with server-side decryption
  - Encryption key and vault data on separate Docker volumes for defense in depth
  - Save multiple credentials for different Qualys platforms/environments
  - Connection testing before saving
- **Platform Registry**: All 13 Qualys platform regions (US1-4, EU1-2, IN1, UAE1, KSA1, CA1, AU1, UK1, GOV)
- **Sync Management**: Trigger full/delta sync per data type with real-time progress and elapsed time [MM:SS]
  - Full sync purge warning: confirmation modal warns that all data for the type will be deleted and re-downloaded (useful when switching Qualys tenants)
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

### First Run

1. Go to the **Settings** tab
2. Select your Qualys platform region
3. Enter your Qualys API credentials and click **Test Connection**
4. Save the credential
5. Click **Sync** next to each data type (QIDs, CIDs, Policies) to populate the local database

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

## API Reference

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
pip install -r requirements.txt
flask --app app.main run --port 5051
```

### Running Tests

```bash
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

Apache-2.0 — See [LICENSE](../LICENSE) in the repository root.
