# Q KB Explorer

Qualys Knowledge Base and Policy Compliance explorer with local caching, full-text search, cross-referencing, and cross-environment policy migration.

## Features

### Knowledge Base (QIDs)
- Full and delta sync of the Qualys vulnerability knowledge base (114K+ QIDs)
- ID-range chunked sync for fast initial loads (~3.5 min for full KB)
- Full-text search across titles, diagnosis, consequence, and solution fields
- Multi-select filters: CVE (type-ahead server search), Category, Severity, Patchable
- Detail view with CVSS v2/v3 scores, CVE links, Bugtraq refs, vendor references, threat intel, exploit/malware correlation, and affected software
- Severity color-coded cards (Critical=red, High=orange, Medium=yellow, Low=blue, Info=gray)
- Supported modules (agent type) display, filtering, and badges on cards
- Dynamic record count badge: Total | Found | % updates after each search
- Bulk export of full QID details (including CVEs, diagnosis, solution) as CSV/PDF

### Compliance Controls (CIDs)
- Full and delta sync of compliance controls (26K+ CIDs)
- Full-text search across statements, categories, and comments
- Multi-select filters: Category, Technology (type-ahead), Criticality
- Detail view with check type, technologies with rationale, and linked policies
- Cross-navigation: click a linked policy to jump to the Policies tab
- Bulk export of full CID details as CSV/PDF

### Policy Compliance
- Full and delta sync of compliance policies
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
- **Sync Management**: Trigger full/delta sync per data type with real-time progress and elapsed time
  - Full sync purge warning: confirmation modal warns that all data for the type will be deleted and re-downloaded (useful when switching Qualys tenants)
- **Sync Log**: Persistent sync history with event-level detail (stored in SQLite)
- **Theme Toggle**: Dark/light mode
- **Bookmarks**: Favorite QIDs, CIDs, and Policies with star icons, stored in localStorage
- **Recent Searches**: Search history dropdown on all search bars
- **Keyboard Shortcuts**: `1`-`7` tabs, `/` focus search, `?` shortcuts modal, `t` toggle theme, `b` bookmark
- **Help Tab**: Comprehensive built-in documentation

### Technical
- SQLite with WAL mode and FTS5 full-text search indexes
- Delta sync using Qualys API watermarks (only fetch records modified since last sync)
- Qualys API v4 with XML response parsing via xmltodict
- Reusable multi-select dropdown component with type-ahead
- Cache-busted static assets
- Single gunicorn worker with 660s timeout for long-running syncs
- Optional TLS support (mount certs or set env vars)
- HTML sanitization on QID fields, rate limiting, CSRF protection
- Server-side HttpOnly auth cookie, same-origin only

## Quick Start

### Docker (recommended)

```bash
# Clone this branch
git clone -b Q-KB-Explorer https://github.com/netsecops-76/Public-Security-Resources.git
cd "Public-Security-Resources/Q KB Explorer"
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

## Documentation

- [API_REFERENCE.md](API_REFERENCE.md) -- Full endpoint catalog
- [ARCHITECTURE.md](ARCHITECTURE.md) -- System design and data flow
- [CHANGELOG.md](CHANGELOG.md) -- Version history

## Project Structure

```
Q KB Explorer/
├── app/
│   ├── main.py              # Flask app, routes, platform registry
│   ├── vault.py             # AES-256-GCM credential vault
│   ├── database.py          # SQLite schema, CRUD, FTS search
│   ├── qualys_client.py     # Qualys API HTTP client
│   ├── scheduler.py         # Sync scheduling
│   ├── sync.py              # Sync engine (full/delta for QIDs, CIDs, Policies)
│   ├── sync_log.py          # Persistent sync log (SQLite-backed)
│   ├── templates/
│   │   └── index.html       # Single-page application
│   └── static/
│       ├── css/style.css    # Dark/light theme styles
│       ├── js/app.js        # Frontend logic + MultiSelect component
│       └── img/qualys-shield.svg
├── API_REFERENCE.md
├── ARCHITECTURE.md
├── CHANGELOG.md
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh
└── requirements.txt
```

## License

Apache-2.0 -- See [LICENSE](../LICENSE) in the repository root.

## Author

Brian Canaday
