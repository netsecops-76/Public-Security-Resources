# Q KB Explorer — Architecture

The maintained architecture document is [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). It covers the component map, technology stack with current versions, database schema (regular + FTS5 tables), security architecture, sync flow, and the deployment model.

This top-level file used to duplicate that content and drifted out of date (last meaningful update was March 2026, before Tags / PM Patches / Intelligence / Auto-Update scheduling all shipped). v2.3 retired the duplicate. Treat `docs/ARCHITECTURE.md` as the source of truth.

## Snapshot

A one-screen orientation. For depth, follow the links.

- **Backend.** Flask + Gunicorn (single worker by default; `--preload` deliberately off so the in-app updater can reload code without rebuilding the container). SQLite with WAL mode and FTS5 indexes for full-text search.
- **Frontend.** Vanilla JavaScript SPA, no build step. Chart.js for the Dashboard.
- **Sync.** `app/sync.py` drives full and delta syncs across six data types (QIDs, CIDs, Policies, Mandates, Tags, PM Patches). Pre-count + populated-range targeting, batched per-page transactions, per-record error isolation, retry with backoff on 409/429, global mutex serializes concurrent syncs.
- **Vault.** AES-256-GCM credential storage on a separate Docker volume from the SQLite data, both with restrictive (700/600) permissions. Vault unlock is an HttpOnly cookie minted by `POST /api/credentials/verify` (or by `POST /api/credentials` on first save).
- **Scheduler.** APScheduler — recurring delta syncs per data type, weekly DB maintenance, weekly auto-update.
- **Updater.** Manifest-driven in-app update from the public branch. Master process restarts on apply (gunicorn re-imports fresh code); UPDATING.md covers recovery for users on pre-2.2 images.
- **API.** Documented at runtime via OpenAPI 3 at `/api/docs/swagger`, `/api/docs/redoc`, `/api/docs/scalar`, and `/api/docs/openapi.json`. ~95 paths.

## Diagram

A more detailed component diagram, schema listing, and security model live in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Two related references:

- [`README.md`](README.md) — feature overview, deployment, the **Use as a Qualys API caching middleware** wiring guide.
- [`API_REFERENCE.md`](API_REFERENCE.md) — entry-point pointer at the live OpenAPI spec; same canonical-source pattern this file follows.

## Operational notes

- **Container restart policy** is `unless-stopped` in `docker-compose.yml`; the in-app updater relies on this to reload after master SIGTERM.
- **Persistent volumes:** `qkbe-keys` (vault encryption key) and `qkbe-data` (encrypted vault + SQLite). No update path touches these.
- **Health check** at `/api/health` (no auth); polled by Docker every 30s.
- **Cadence:** when the architecture genuinely shifts (new table, new module, signal-handling change), update [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) in the same commit. This top-level file does not need to be edited because it carries no canonical content of its own.
