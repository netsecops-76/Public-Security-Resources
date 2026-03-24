# Q KB Explorer — API Reference

> Total endpoints: 50 (49 API + 1 page) | Base URL: `/api`
> Auth: Vault-based session cookie (`qkbe-vault-unlocked`, HttpOnly)

## Quick Reference Table

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/` | Render single-page application | No |
| GET | `/api/platforms` | Qualys platform registry (13 regions) | No |
| GET | `/api/credentials` | List saved credentials (no passwords) | No |
| POST | `/api/credentials` | Save/update a credential | No |
| PATCH | `/api/credentials/<id>` | Update credential metadata | Yes |
| DELETE | `/api/credentials/<id>` | Delete a credential | Yes |
| POST | `/api/credentials/verify` | Verify password against stored credential | No |
| POST | `/api/auth/logout` | Clear vault unlock cookie | No |
| POST | `/api/test-connection` | Test Qualys platform connectivity | Yes |
| GET | `/api/sync/status` | Sync watermarks for all data types | Yes |
| POST | `/api/sync/<type>` | Trigger sync (qids/cids/policies/mandates) | Yes |
| GET | `/api/sync/<type>/progress` | Current sync progress | Yes |
| GET | `/api/sync/<type>/log` | Full diagnostic sync log | Yes |
| GET | `/api/sync/<type>/history` | Last 20 sync runs | Yes |
| GET | `/api/schedules` | List active sync schedules | Yes |
| POST | `/api/schedules/<type>` | Create/update sync schedule | Yes |
| DELETE | `/api/schedules/<type>` | Delete sync schedule | Yes |
| GET | `/api/qids` | Search QIDs (FTS + filters + pagination) | Yes |
| GET | `/api/qids/filter-values` | Distinct filter values for dropdowns | Yes |
| GET | `/api/qids/<qid>` | Full QID detail | Yes |
| GET | `/api/qids/export-details` | Bulk export full QID details (CSV) | Yes |
| GET | `/api/cids` | Search CIDs (FTS + filters + pagination) | Yes |
| GET | `/api/cids/filter-values` | Distinct filter values for dropdowns | Yes |
| GET | `/api/cids/<cid>` | Full CID detail with technologies | Yes |
| GET | `/api/cids/export-details` | Bulk export full CID details (CSV) | Yes |
| GET | `/api/policies` | Search policies (filters + pagination) | Yes |
| DELETE | `/api/policies` | Delete policies by ID | Yes |
| GET | `/api/policies/filter-values` | Distinct filter values for dropdowns | Yes |
| GET | `/api/policies/<id>` | Full policy detail with linked controls | Yes |
| POST | `/api/policies/<id>/export` | Export policy XML from Qualys | Yes |
| GET | `/api/policies/<id>/download-xml` | Download stored policy XML | Yes |
| GET | `/api/policies/<id>/report` | Structured section/control report data | Yes |
| GET | `/api/policies/<id>/report-pdf` | Generate policy PDF report | Yes |
| POST | `/api/policies/export-zip` | Bundle multiple policy XMLs into ZIP | Yes |
| POST | `/api/policies/import-xml` | Import policy XML from local upload | Yes |
| POST | `/api/policies/upload` | Upload policy to destination Qualys env | Yes |
| GET | `/api/policies/stale-exports` | List policies with outdated exports | Yes |
| GET | `/api/mandates` | Search mandates (FTS + filters + pagination) | Yes |
| GET | `/api/mandates/filter-values` | Distinct filter values for dropdowns | Yes |
| GET | `/api/mandates/<id>` | Full mandate detail with controls/policies | Yes |
| GET | `/api/dashboard/stats` | Aggregated dashboard statistics | Yes |
| GET | `/api/export/qids/csv` | Export filtered QIDs to CSV | Yes |
| GET | `/api/export/cids/csv` | Export filtered CIDs to CSV | Yes |
| GET | `/api/export/policies/csv` | Export filtered policies to CSV | Yes |
| GET | `/api/export/mandates/csv` | Export filtered mandates to CSV | Yes |
| GET | `/api/export/mandate-map/csv` | Export mandate compliance mapping CSV | Yes |
| GET | `/api/export/policies/pdf` | Export filtered policies to PDF | Yes |
| GET | `/api/export/mandates/pdf` | Export filtered mandates to PDF | Yes |

---

## Endpoint Groups

### Auth & Credentials — `/api/credentials/`, `/api/auth/`

#### GET `/api/credentials`
- **Auth:** None (needed for initial setup)
- **Response (200):** `[{ "id": "...", "label": "...", "platform": "...", "username": "..." }]`
- **Notes:** Passwords are never returned; only metadata

#### POST `/api/credentials`
- **Auth:** None (needed for initial setup)
- **Request body:** `{ "label": "...", "platform": "...", "username": "...", "password": "..." }`
- **Response (200):** `{ "status": "ok", "id": "..." }`
- **Notes:** Password encrypted server-side with AES-256-GCM

#### POST `/api/credentials/verify`
- **Auth:** None
- **Rate limit:** 5 requests per minute
- **Request body:** `{ "credential_id": "...", "password": "..." }`
- **Response (200):** `{ "verified": true/false }`
- **Notes:** Uses `secrets.compare_digest()` for timing-safe comparison

#### POST `/api/auth/logout`
- **Auth:** None
- **Response (200):** `{ "status": "ok" }`
- **Notes:** Clears the `qkbe-vault-unlocked` session cookie

---

### Connection Testing — `/api/test-connection`

#### POST `/api/test-connection`
- **Auth:** Yes
- **Request body:** `{ "credential_id": "..." }` or `{ "platform": "...", "username": "...", "password": "..." }`
- **Response (200):** `{ "success": true, "message": "..." }`
- **Errors:** `400` missing fields · `500` connection failed

---

### Sync — `/api/sync/`

#### GET `/api/sync/status`
- **Auth:** Yes
- **Response (200):** `{ "qids": { "last_sync": "...", "count": N }, "cids": {...}, "policies": {...}, "mandates": {...} }`

#### POST `/api/sync/<data_type>`
- **Auth:** Yes
- **URL params:** `data_type` = qids | cids | policies | mandates
- **Query params:** `full=1` (optional, force full sync)
- **Request body:** `{ "credential_id": "..." }`
- **Response (200):** `{ "status": "started" }`
- **Notes:** Runs async in background thread; poll `/progress` for status

#### GET `/api/sync/<data_type>/progress`
- **Auth:** Yes
- **Response (200):** `{ "status": "syncing|complete|error", "items_synced": N, ... }`

#### GET `/api/sync/<data_type>/log`
- **Auth:** Yes
- **Response (200):** Plain text diagnostic log

#### GET `/api/sync/<data_type>/history`
- **Auth:** Yes
- **Response (200):** `[{ "started": "...", "finished": "...", "items": N, "status": "..." }]`
- **Notes:** Last 20 runs per data type

---

### Schedules — `/api/schedules/`

#### GET `/api/schedules`
- **Auth:** Yes
- **Response (200):** `[{ "data_type": "qids", "frequency": "weekly", "credential_id": "..." }]`

#### POST `/api/schedules/<data_type>`
- **Auth:** Yes
- **Request body:** `{ "frequency": "weekly|biweekly|monthly", "credential_id": "...", "timezone": "..." }`
- **Response (200):** `{ "status": "ok" }`

#### DELETE `/api/schedules/<data_type>`
- **Auth:** Yes
- **Response (200):** `{ "status": "ok" }`

---

### QIDs — `/api/qids/`

#### GET `/api/qids`
- **Auth:** Yes
- **Query params:** `q`, `cve`, `cve_mode`, `severity`, `category`, `patchable`, `vuln_type`, `pci_flag`, `discovery_method`, `cvss_base_min`, `cvss3_base_min`, `published_after`, `modified_after`, `rti`, `supported_modules`, `page`, `per_page`
- **Response (200):** `{ "results": [...], "total": N, "page": N, "pages": N }`

#### GET `/api/qids/filter-values`
- **Auth:** Yes
- **Query params:** `field` = categories | cves | vuln_types | rti_tags | supported_modules
- **Response (200):** `["value1", "value2", ...]`

#### GET `/api/qids/<qid>`
- **Auth:** Yes
- **Response (200):** Full QID object with cves, bugtraqs, vendor_refs, supported_modules arrays

#### GET `/api/qids/export-details`
- **Auth:** Yes
- **Query params:** `ids` (comma-separated QID numbers), `format` (csv only)
- **Response (200):** CSV file with full QID details (severity, CVEs, bugtraqs, modules, diagnosis, solution)
- **Errors:** `400` empty or invalid IDs
- **Notes:** No item limit. HTML stripped from text fields, URLs preserved.

---

### CIDs — `/api/cids/`

#### GET `/api/cids`
- **Auth:** Yes
- **Query params:** `q`, `category`, `criticality`, `technology`, `technology_mode`, `page`, `per_page`
- **Response (200):** `{ "results": [...], "total": N, "page": N, "pages": N }`

#### GET `/api/cids/filter-values`
- **Auth:** Yes
- **Query params:** `field` = categories | technologies
- **Response (200):** `["value1", "value2", ...]`

#### GET `/api/cids/<cid>`
- **Auth:** Yes
- **Response (200):** Full CID object with technologies array and linked policies

#### GET `/api/cids/export-details`
- **Auth:** Yes
- **Query params:** `ids` (comma-separated CID numbers), `format` (csv only)
- **Response (200):** CSV file with full CID details (criticality, statement, technologies, linked policies)
- **Errors:** `400` empty or invalid IDs
- **Notes:** No item limit.

---

### Policies — `/api/policies/`

#### GET `/api/policies`
- **Auth:** Yes
- **Query params:** `q`, `status`, `control_category`, `control_category_mode`, `technology`, `technology_mode`, `cid`, `cid_mode`, `control_name`, `page`, `per_page`
- **Response (200):** `{ "results": [...], "total": N, "page": N, "pages": N }`

#### DELETE `/api/policies`
- **Auth:** Yes
- **Request body:** `{ "policy_ids": [1, 2, 3] }`
- **Response (200):** `{ "deleted": N }`

#### POST `/api/policies/<id>/export`
- **Auth:** Yes
- **Request body:** `{ "credential_id": "..." }`
- **Response (200):** `{ "status": "ok", "xml_size": N }`
- **Notes:** Fetches full policy XML from Qualys and stores locally

#### POST `/api/policies/upload`
- **Auth:** Yes
- **Request body:** `{ "policy_id": N, "credential_id": "..." }`
- **Response (200):** `{ "status": "ok", "new_policy_id": N }`
- **Notes:** Uploads stored XML to destination Qualys environment

#### GET `/api/policies/stale-exports`
- **Auth:** Yes
- **Response (200):** `[{ "policy_id": N, "title": "...", "export_date": "...", "modified_date": "..." }]`

---

### Mandates — `/api/mandates/`

#### GET `/api/mandates`
- **Auth:** Yes
- **Query params:** `q`, `publisher`, `page`, `per_page`
- **Response (200):** `{ "results": [...], "total": N, "page": N, "pages": N }`

#### GET `/api/mandates/<id>`
- **Auth:** Yes
- **Response (200):** Full mandate object with associated controls and derived policies

---

### Dashboard — `/api/dashboard/`

#### GET `/api/dashboard/stats`
- **Auth:** Yes
- **Response (200):** Aggregated counts, severity breakdowns, compliance metrics, sync health

---

### Export — `/api/export/`

All export endpoints accept the same filter params as their corresponding search endpoints.

| Endpoint | Format | Filename |
|----------|--------|----------|
| GET `/api/export/qids/csv` | CSV | qkbe-qids-export.csv |
| GET `/api/export/cids/csv` | CSV | qkbe-cids-export.csv |
| GET `/api/export/policies/csv` | CSV | qkbe-policies-export.csv |
| GET `/api/export/policies/pdf` | PDF | qkbe-policies-export.pdf |
| GET `/api/export/mandates/csv` | CSV | qkbe-mandates-export.csv |
| GET `/api/export/mandates/pdf` | PDF | qkbe-mandates-export.pdf |
| GET `/api/export/mandate-map/csv` | CSV | qkbe-mandate-mapping.csv |

**Note:** PDF export is available for Policies and Mandates only. QID and CID content fields are too large for reliable PDF generation.

---

## CSRF Protection

All state-changing requests (POST, PATCH, DELETE) require the header:
```
X-Requested-With: QKBE
```

Requests without this header receive `403 Forbidden`.

## Error Response Format

All endpoints return errors as JSON:

```json
{ "error": "Description of what went wrong" }
```

HTTP status codes: `400` (bad request), `401` (unauthorized), `403` (forbidden/CSRF), `404` (not found), `429` (rate limited), `500` (server error)

## Authentication

1. First-time users: All routes accessible (vault is empty)
2. After vault has credentials: All `/api/*` routes require the `qkbe-vault-unlocked` cookie
3. Cookie is set (HttpOnly, server-side) after successful `POST /api/credentials/verify`
4. Cookie is cleared on `POST /api/auth/logout`
5. Cookie `secure` flag auto-enabled when TLS certificates detected in `/app/certs/`
6. Exempt paths: `/api/credentials` (GET/POST), `/api/credentials/verify`, `/api/platforms`, `/api/auth/logout`
