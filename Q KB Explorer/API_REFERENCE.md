# Q KB Explorer — API Reference

Q KB Explorer exposes a JSON HTTP API on top of the Qualys-backed local cache (QIDs, CIDs, Policies, Mandates, Tags, PM Patches). The same API powers the bundled SPA and is suitable for integration as a local caching tier between Qualys and downstream tools.

## Canonical reference is the live spec

The maintained, always-in-sync API documentation is the OpenAPI 3 spec served by the running app:

- `/api/docs/swagger/` — Swagger UI (try-it-out)
- `/api/docs/redoc/` — ReDoc (clean three-pane reference)
- `/api/docs/scalar/` — Scalar (modern alt UI)
- `/api/docs/openapi.json` — Raw OpenAPI 3 spec for tooling (Postman, Insomnia, OpenAPI Generator, etc.)

The spec is generated from pydantic models attached to each route via SpecTree, so it stays in sync with the code. This Markdown file used to enumerate every endpoint by hand and drifted from reality multiple times in v1.x — v2.0 retired that approach. Treat the live spec as the source of truth; treat this file as an entry point.

## Base URL & Auth

- **Base URL**: `http://<host>:5051/api` (default Docker port mapping; `5000` inside the container).
- **Auth model**: vault-based session cookie set by `POST /api/credentials/verify` (or by `POST /api/credentials` on first credential save). Most data routes return `401` without an unlocked vault session. The OpenAPI spec lists `vault_session` as the security scheme on protected operations.
- **CSRF**: every state-changing request must carry the `X-Requested-With: QKBE` header. Browser clients add it automatically; programmatic consumers set it explicitly.

## Endpoint surface (~95 paths)

A high-level inventory by area. For exact request/response shapes, see the live spec.

| Area               | OpenAPI tag         | Key paths                                                                 |
|--------------------|---------------------|---------------------------------------------------------------------------|
| Knowledge Base (QIDs) | `QIDs`           | `/api/qids` · `/api/qids/<qid>` · `/api/qids/filter-values` · `/api/qids/<qid>/patches` · `/api/qids/export-details` |
| Compliance Controls (CIDs) | `CIDs`      | `/api/cids` · `/api/cids/<cid>` · `/api/cids/filter-values` · `/api/cids/export-details` |
| Policies           | `Policies`          | `/api/policies` · `/api/policies/<id>` · `/api/policies/<id>/export` · `/api/policies/upload` · `/api/policies/import-xml` · `/api/policies/export-zip` |
| Mandates           | `Mandates`          | `/api/mandates` · `/api/mandates/<id>` |
| Tags               | `Tags` / `Tag Library` / `Tag Audit` | Read, CRUD, migration, library, audit (24+ paths under `/api/tags/*` and `/api/library/*`) |
| Intelligence       | `Intelligence`      | `/api/intelligence/stats` |
| Dashboard          | `Dashboard`         | `/api/dashboard/stats` |
| Sync               | `Sync`              | `/api/sync/status` · `/api/sync/<type>` (POST) · `/api/sync/<type>/progress` · `/api/sync/<type>/log` · `/api/sync/<type>/history` |
| Schedules          | `Schedules`         | `/api/schedules` (GET/POST/DELETE per data type) |
| Auto-Update        | (no tag)            | `/api/update/check` · `/api/update/apply` · `/api/update/version` · `/api/update/schedule` (GET/POST) |
| Maintenance        | (no tag)            | `/api/maintenance/config` · `/api/maintenance/restore` |
| PM Patch Catalog   | (no tag)            | `/api/pm/stats` · `/api/qids/<qid>/patches` |
| Health & Platforms | `Health & Meta`     | `/api/health` · `/api/platforms` |
| Credentials & Auth | `Credentials & Auth`| `/api/credentials` · `/api/credentials/verify` · `/api/auth/logout` · `/api/auth/session` · `/api/test-connection` |

## Importing the spec

Export the OpenAPI 3 document as a single JSON file:

```bash
curl http://localhost:5051/api/docs/openapi.json -o qkbe-openapi.json
```

Common consumers:

- **Postman**: File → Import → upload `qkbe-openapi.json`
- **Insomnia**: Import → From File → choose the JSON
- **OpenAPI Generator**: `openapi-generator-cli generate -i qkbe-openapi.json -g <lang> -o ./qkbe-client`

## Going deeper

- [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) — the same canonical-spec doctrine plus extra notes on annotation coverage, recent additions (threat-intel filter params, tag migration endpoints), and caching-middleware framing.
- [`README.md`](README.md) — feature overview, deployment, and the **Use as a Qualys API caching middleware** section if you're wiring the API into other tools.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, schema, security model.
