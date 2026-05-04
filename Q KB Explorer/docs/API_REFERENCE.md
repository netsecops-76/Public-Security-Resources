# Q KB Explorer — API Reference

> **The canonical API reference is the auto-generated OpenAPI spec served by the running app:**
>
> - `/api/docs/swagger/` — Swagger UI (try-it-out)
> - `/api/docs/redoc/` — ReDoc (clean three-pane reference)
> - `/api/docs/scalar/` — Scalar (modern alt UI)
> - `/api/docs/openapi.json` — Raw OpenAPI 3 spec for tooling (Postman, Insomnia, OpenAPI Generator, etc.)
>
> The spec is generated from pydantic models attached to each route via SpecTree, so it stays in sync with the code. This Markdown reference used to be hand-maintained — that approach drifted from reality multiple times in v1.x, so v2.0 dropped the ongoing manual reference and pointed everything at the runtime spec instead.

## Base URL & Auth

- **Base URL**: `http://<host>:5051/api` (default Docker port mapping)
- **Auth model**: vault-based session cookie set by `POST /api/credentials/verify`. Most data routes 401 without an unlocked vault session. The OpenAPI spec lists `vault_session` as the security scheme on every protected operation.
- **CSRF**: every state-changing request must carry the `X-Requested-With: QKBE` header. Browser clients add it automatically; programmatic consumers set it explicitly.

## Endpoint surface (~95 paths)

For a high-level inventory by area:

| Area              | Tag in OpenAPI sidebar | Key paths |
|-------------------|------------------------|-----------|
| Knowledge Base (QIDs) | `QIDs`             | `/api/qids` (search), `/api/qids/<qid>` (detail), `/api/qids/filter-values`, `/api/qids/<qid>/patches`, `/api/qids/export-details` |
| Compliance Controls (CIDs) | `CIDs`        | `/api/cids` (search), `/api/cids/<cid>`, `/api/cids/filter-values`, `/api/cids/export-details` |
| Policies          | `Policies`             | `/api/policies` (search), `/api/policies/<id>`, `/api/policies/<id>/export`, `/api/policies/upload`, `/api/policies/import-xml`, `/api/policies/export-zip` |
| Mandates          | `Mandates`             | `/api/mandates` (search), `/api/mandates/<id>` |
| Tags — read       | `Tags`                 | `/api/tags` (search), `/api/tags/<id>`, `/api/tags/filter-values` |
| Tags — CRUD       | `Tags`                 | `/api/tags/create`, `/api/tags/<id>/update`, `/api/tags/<id>/delete`, `/api/tags/<id>/impact`, `/api/tags/validate`, `/api/tags/test-rule`, `/api/tags/<id>/classify`, `/api/tags/<id>/editability` |
| Tags — migration  | `Tags`                 | `/api/tags/<id>/export`, `/api/tags/<id>/export-download`, `/api/tags/exports`, `/api/tags/export-bundle`, `/api/tags/export-local`, `/api/tags/export-bulk`, `/api/tags/import-json`, `/api/tags/import-local`, `/api/tags/upload`, `/api/tags/migrate-direct`, `/api/tags/migrate-status`, `/api/tags/delete-local`, `/api/tags/delete-qualys` |
| Tag Library       | `Tag Library`          | `/api/library` (CRUD), `/api/library/<id>/clone`, `/api/library/<id>/unhide`, `/api/library/<id>/apply`, `/api/library/<id>/applies`, `/api/library/applies` |
| Tag Audit         | `Tag Audit`            | `/api/tags/audit`, `/api/tags/audit/<rule_id>`, `/api/tags/audit.csv` |
| Intelligence      | `Intelligence`         | `/api/intelligence/stats` |
| Dashboard         | `Dashboard`            | `/api/dashboard/stats` |
| Sync              | `Sync`                 | `/api/sync/status`, `/api/sync/active`, `/api/sync/<type>` (POST), `/api/sync/<type>/progress`, `/api/sync/<type>/log`, `/api/sync/<type>/history`, `/api/sync/<type>/events/tail` |
| Schedules         | `Schedules`            | `GET /api/schedules`, `POST/DELETE /api/schedules/<type>` |
| Health & Meta     | `Health & Meta`        | `/api/health`, `/api/platforms` |
| Credentials & Auth | `Credentials & Auth`  | `/api/credentials` (CRUD), `/api/credentials/verify`, `/api/auth/logout`, `/api/auth/session`, `/api/test-connection` |
| Maintenance       | (no tag)               | `/api/maintenance/config`, `/api/maintenance/restore` |
| Auto-update       | (no tag)               | `/api/update/check`, `/api/update/apply`, `/api/update/version` |
| PM Patch Catalog  | (no tag)               | `/api/pm/stats`, `/api/qids/<qid>/patches` |

### New in v2.1.0

| Path | Method | Purpose |
|------|--------|---------|
| `/api/tags/export-local` | GET | Export tags from local DB as JSON download (no Qualys API calls) |
| `/api/tags/export-bundle` | GET | Download multiple stored tag exports as a single JSON array |
| `/api/tags/export-bulk` | POST | Bulk export tags from Qualys API and store locally |
| `/api/tags/import-local` | POST | Import tags from a shared JSON file into local DB |
| `/api/tags/migrate-direct` | POST | Start async tag migration (source → destination) |
| `/api/tags/migrate-status` | GET | Poll migration progress (auth-exempt) |
| `/api/tags/delete-local` | POST | Delete selected tags from local cache only |
| `/api/tags/delete-qualys` | POST | Delete selected tags from Qualys subscription + local cache |

### Search filter params (v2.1.0 additions)

The `/api/qids` and `/api/intelligence/stats` endpoints now accept these additional query params:

| Param | Values | Description |
|-------|--------|-------------|
| `threat_active` | `1` / `0` | Include/exclude QIDs with active attacks |
| `threat_cisa_kev` | `1` / `0` | Include/exclude QIDs on CISA KEV list |
| `threat_exploit_public` | `1` / `0` | Include/exclude QIDs with public exploits |
| `threat_rce` | `1` / `0` | Include/exclude QIDs with RCE capability |
| `threat_malware` | `1` / `0` | Include/exclude QIDs with associated malware |
| `has_exploits` | `1` / `0` | Include/exclude QIDs with documented exploit references |
| `exclude_severities` | comma-separated ints | Exclude specific severity levels (e.g. `1,2`) |
| `exclude_q` | string | Exclude QIDs matching this FTS search term |
| `exclude_category` | string | Exclude QIDs in this category |

Value `1` = include (must match), `0` = exclude (must NOT match), absent = no filter. Multiple same-category params (e.g. `threat_active=1&threat_rce=1`) are OR'd together. Cross-category params are AND'd.

## Annotation coverage

As of v2.1.0: **~40 of ~95 endpoints** have full pydantic models attached, covering every search/detail/filter-values + sync ops + library CRUD + intelligence stats + health/platforms/schedules + tag migration. Auth, maintenance, auto-update, dashboard stats, and the bulk export endpoints still appear in the spec with generic shapes.

## Importing the spec

The spec is exportable as a single JSON file:

```bash
curl http://localhost:5051/api/docs/openapi.json -o qkbe-openapi.json
```

Common consumers:

- **Postman**: File → Import → upload `qkbe-openapi.json`
- **Insomnia**: Import → From File → choose the JSON
- **OpenAPI Generator**: `openapi-generator-cli generate -i qkbe-openapi.json -g python -o ./qkbe-client` (any of 50+ language targets)

## Caching-middleware framing

If you're integrating Q KB Explorer as a local caching tier between Qualys and your other tools, see the **Use as a Qualys API caching middleware** section in the project [README.md](../README.md) — covers the architecture, value proposition, and wiring guide.
