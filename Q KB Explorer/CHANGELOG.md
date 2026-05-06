# Q KB Explorer — Changelog

The full per-version history is maintained in [`docs/CHANGELOG.md`](docs/CHANGELOG.md). That file follows [Keep a Changelog](https://keepachangelog.com/) — Added / Fixed / Changed / Removed / Security / Deprecated subsections per release, version-tagged and dated.

This top-level file used to duplicate that history and drifted out of sync; v2.3 retired the duplicate. Treat `docs/CHANGELOG.md` as the source of truth.

## Recent releases

- **v2.3.0** (2026-05-06) — Automatic Updates scheduling (`/api/update/schedule` backend), Apply Update progress modal with auto-reload, vault session minted on credential save, PM Patches delta QQL fix, doc maintenance pass.
- **v2.2.0** (2026-05-06) — Sync robustness wave: CVSS attribute unwrap, CORRELATION shape variations, init_db crashloop fix, per-record errors no longer abort the whole sync. UX: welcome tip, Save Credential gated on Test Connection, credential picker re-renders on delete. Updater: master process restarts on apply (was silently no-op under `--preload`).
- **v2.1.0** (2026-05-03) — Threat Intelligence integration, Tag origin classification, Tag sub-tabs (Browse / Library / Audit / Migration), PM Linux sync fix (213K patches).
- **v2.0.0** (2026-05-02) — Tags Phases 1-5 (read · migrate · CRUD · library · audit), sync robustness across all paths, OpenAPI documentation at `/api/docs`, caching-middleware framing.

For the full timeline back to v1.0.0 (2026-03-01), see [`docs/CHANGELOG.md`](docs/CHANGELOG.md).

## Format & cadence

- Entries follow Keep a Changelog conventions.
- The CHANGELOG is updated **in the same commit** that ships the change, not as a separate catch-up pass — that was the failure mode that let this top-level copy drift in the first place.
- Bug fixes also get an entry in [`docs/BUGS.md`](docs/BUGS.md) with severity, root cause, and resolution.
- The user-facing release notes shown by the in-app updater come from `update-manifest.json`'s `notes` field.
