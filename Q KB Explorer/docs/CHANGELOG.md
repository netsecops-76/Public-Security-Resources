# Q KB Explorer — Changelog

> Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

_No changes pending release._

## [v2.4.2] — 2026-05-06 — Tag classification policy alignment with real subscription data

Hot-fix for a structural classification gap exposed by a 167-tag pull from a real Qualys subscription. The QPS Tag search endpoint was found to return `reservedType=null` AND `createdBy=null` on **every** tag in the pull — including unambiguously Qualys-shipped tags (Business Units, Cloud Agent, Internet Facing Assets, the EASM family, Passive Sensor, Unmanaged) and connector-bound tags (AWS / Azure / GCP, vpc-*, Connector Discovery variants). Pre-v2.4.2 `_is_user_created` consulted only those two fields, so it fell through to default-allow ("user-created") for all 167 tags. **24% (40 / 167) of tags were misclassified as user-created** — the operator's `only_user=1` filter was returning Qualys-shipped tags, the cards rendered without the [SYSTEM] pill, and migration tooling treated connector tags as portable when they require a destination connector to function.

The classifier already had the right answer in a different code path: `_classify_tag_origin` uses hard-coded protective name-pattern lists (`_SYSTEM_PROVISIONED_NAMES`, `_CONNECTOR_NAME_PATTERNS`) plus the `CLOUD_ASSET` rule_type heuristic to identify these tags. On the same 167-tag pull, the origin classifier scored 100% accurate on the system cluster and ~96% accurate on the connector cluster (a couple of edge cases for operator organizer tags named like Qualys connectors — operator override remains the safety valve). It was just never consulted from the classification path that drives `is_user_created`.

### Fixed
- **`upsert_tag` derives `is_user_created` from `tag_origin` first, then falls through to the reservedType / sentinel-creator logic.** When `tag_origin` is `system` or `connector`, the tag is classified as system (`is_user_created = 0`) regardless of what reservedType / createdBy contain. Otherwise the existing `_is_user_created` logic runs unchanged. No new hard-coding — this just hooks the existing protective lists into the right place. Operator override via `/api/tags/<id>/classify` still wins for the rare false positive (a custom organizer the operator named like a Qualys-shipped tag); the override is durable across syncs.
- **`search_tags` `only_user` / `only_system` filter now uses the effective `is_user_created` (override-resolved), not `tag_origin`.** Pre-v2.4.2 the filter treated connector-origin tags as "user" because the discriminator was `tag_origin = 'system'`. Post-v2.4.2 connector tags are `is_user_created = 0` and need to land in `only_system`. Pre-v2.4.2 also never consulted `classification_override` in the filter — so a tag the operator manually re-classified would render correctly on its card but slip through the wrong filter. The new CASE expression mirrors `_apply_classification_override` exactly, so the filter and the card always agree.

### Tests
- **`test_tags_origin_overrides_classification_when_qualys_strips_metadata`**: regression test pinning the exact 167-pull production behavior. Inserts five tags reproducing the four origin classes (system by name match, connector by name pattern, connector by CLOUD_ASSET rule_type, static user-organizer, rule_based user) — all with `reservedType=null` and `createdBy=null` — and asserts each lands on the right `is_user_created` and `tag_origin`.
- **`test_tag_override_forces_system_classification`**: tag name changed from "Internet Facing Assets" (now correctly caught by `_SYSTEM_PROVISIONED_NAMES` at upsert time) to a generic operator-style name so the auto classification really does land on user and the override path is exercised.

### Pre-v2.4.2 stale-test cleanup (also in this release)
- **Aligned 8 stale tag classification + validation tests with the production policy** that has been live since the v2.1 tag overhaul. Tests had encoded an older default-deny baseline ("ambiguous tag → system") and an older Qualys rule-type recommendation chain ("OS_REGEX → ASSET_INVENTORY"). Production code in `_is_user_created` (app/database.py) actually uses default-allow ("only reservedType or a system-sentinel creator classifies as system") and `RULE_TYPE_STATUS` (app/tag_validation.py) recommends `GLOBAL_ASSET_VIEW` for OS targeting because `ASSET_INVENTORY` is itself now legacy per Qualys docs. Tests were never updated as the code evolved, leaving the suite at 240/248 with 8 red across every release. Suite is now 249/249. Hard-coded protections in the classification path (sentinel creator list, `_SYSTEM_PROVISIONED_NAMES`, `_CONNECTOR_NAME_PATTERNS`, `RULE_TYPE_STATUS`, `_LOCKED_RESERVED_TYPES`) were intentionally preserved — they encode real Qualys subscription behavior tuned against live data and have no API-driven alternative.

## [v2.4.1] — 2026-05-06 — init_db Migration Hot-Fix

Hot-fix for a critical regression introduced in v2.4. On hosts with slow storage (Hyper-V virtualized disk, 2-vCPU Azure RHEL VM) and a multi-GB legacy DB from a pre-v2.4 Full Sync, the v2.4 init_db migration could hang the container's entrypoint pre-flight import for 50+ minutes with zero forward write progress and no log output. Mac M-series hosts didn't hit it because faster CPU hid the underlying quadratic-scan behavior. See BUGS.md BUG-017 for the full incident write-up.

**Measured on the low-end ops VM (RHEL 9.4 / 2 vCPU / Hyper-V on Azure) post-v2.4.1: full QID sync of 208,765 QIDs in 18 min 11 s, `VERIFY_OK`, zero errors — 11.8× faster than the same VM's pre-v2.4 baseline (3 h 34 m 46 s). Throughput stayed flat-to-improving across the run; the DB-growth slowdown curve that dominated pre-v2.4 timings is gone. Final chunk (990k-999k, 9,979 items) ingested in ~18 s versus 1,039 s pre-v2.4 — 58× tail-chunk speedup.** The cross-environment wall-time gap (Mac M-series vs the 2 vCPU VM) collapsed from ~26× pre-v2.4 to ~2.2× post-v2.4.1, with what's left dominated by Qualys API throughput rather than local hardware. See ARCHITECTURE.md Performance Characteristics for the full pre/post per-chunk table.

### Fixed
- **Marker UPDATE single-transaction stall.** `init_db`'s belt-and-suspenders UPDATE that pre-marks already-classified rows as done=1 was a single transaction over the entire `vulns` table with an 11-clause OR predicate that no index could satisfy. On 208K rows over slow storage the resulting full-table-scan transaction stayed open for 20+ minutes; no autocheckpoint could fire, so the WAL grew to ~1 GB and main DB mtime never advanced. Replaced with a `LIMIT 5000` rowid-batched loop with per-batch commits — autocheckpoint drains WAL between batches, no single transaction holds the writer for more than a few seconds. The marker is idempotent and resumable: the marker column itself is the resume signal, so a kill mid-loop costs at most one batch (5000 rows) of redo work.
- **Streaming backfill O(N²) cursor thrash.** `_backfill_threat_columns` opened a SELECT cursor on `WHERE threat_backfill_done = 0` and committed UPDATEs between `fetchmany()` calls. In Python's sqlite3 the cursor's read transaction ends on commit, the next fetchmany reopens against a fresh post-commit snapshot, and rows just marked done=1 no longer match — so the cursor's WHERE re-evaluated against the live table every batch and skipped further into the table on each iteration. With no index on the boolean marker column, every batch was a partial-or-full table scan; total work was O(N²) in unmarked rows. Hidden on Mac M-series behind per-row Python work; on the RHEL VM CPU spun on cached page reads (`rchar` climbing 1.18 GB/s, `wchar` flat) with zero forward write progress for a full hour. Rewritten to use a qid worklist (one upfront scan to collect qids — int list, not the JSON blobs that motivated v2.4's streaming) plus indexed PK lookups by `qid IN (...)` per batch. No long-running cursor across commits; no quadratic scan. Resumable across kills via the marker.
- **Pre-flight import silenced all migration progress.** `entrypoint.sh` ran `python3 -c "from app.main import app" 2>/dev/null`, intentionally redirecting stderr to suppress import-failure tracebacks. Side effect: every `logger.info` call from `init_db` (which logs to stderr by default and runs before gunicorn binds its own log handlers) was discarded. Admins watching `docker logs` during a multi-minute legacy migration saw a frozen "SQLite database found" line and no further output — indistinguishable from a hard hang. Removed the `2>/dev/null`, added a `_init_progress(msg)` helper in `database.py` that writes migration phase markers to stderr with `flush=True` so progress is visible in real time. Tracebacks on import failure are also surfaced now (useful diagnostic, not noise).

### Tests
- `test_marker_update_chunked_is_resumable_across_kills` proves a kill mid-loop preserves committed work and a restart picks up exactly where it left off. Inserts `_MARKER_BATCH_SIZE * 3 + 17` matching rows, runs one batch manually then stops (simulating a kill), verifies partial progress, calls `init_db()` to resume, and asserts every row ends up marked.
- `test_threat_backfill_done_marker_prevents_re_walk` updated for v2.4.1's always-run marker behavior — the no-JSON row now ends up `threat_backfill_done = 1` because the chunked marker runs idempotently on every init_db call (not only on column-add), and the OR predicate matches `threat_intelligence_json IS NULL`.

## [v2.4.0] — 2026-05-06 — Sync Ingest Performance + Init Backfill Hardening

Performance pass aimed at the per-record cost dominating Full Sync and the per-row work that compounds as the DB grows. Combines four ingest changes plus the init_db backfill hardening from the same release window.

**Measured: full QID sync on a 14 vCPU / 16 GiB Apple Silicon Mac dropped from 1 h 21 min (executemany-only) to 8 min 5 s (bundled) — a 10× wall-time reduction on identical hardware. The DB-growth slowdown curve, where late chunks took 12+ minutes for 9K records, is gone: chunk wall times stayed flat (2–5 s for 5K-record chunks) across the entire run.**

### Performance
- **`bleach.Cleaner` pre-compiled and reused** instead of rebuilt per call. The previous `_sanitize_html` invoked `bleach.clean(...)` per record, which constructed a sanitizer (tag/attribute filters, html5lib parser config) on every call. With ~3 sanitize calls per QID and 200K+ QIDs in a Full Sync, that was 600K+ Cleaner allocations of pure overhead. `bleach.Cleaner` instances are reusable for `clean()` calls; one module-level instance now serves the whole process.
- **FTS5 deferred indexing for Full Sync.** New `fts5_deferred_for_vulns()` and `fts5_deferred_for_controls()` context managers in `database.py` drop the FTS5 maintenance triggers for the duration of a bulk write, then issue a single `'rebuild'` command at exit. The rebuild reads the parent table once and writes FTS5 segments in optimal order, replacing 200K+ incremental trigger fires whose per-row cost grew with the index size — the dominant Full-Sync slowdown curve users observed. Wired into `sync.py`'s QID and CID Full Sync paths; Delta keeps triggers active because incremental updates are cheap on small change sets and avoid the cost of a full rebuild.
- **Source-hash skip for Delta Sync.** New `source_hash` column on `vulns` stores a SHA-256 of the canonicalized input dict from `upsert_vuln`. When the QID Delta sync calls `upsert_vuln(vuln, skip_unchanged=True)`, the function compares the hash against the row's stored value and short-circuits the entire write path — parent UPDATE, all five child-table DELETE+rewrites, FTS5 trigger maintenance — when nothing has changed. Turns a quiet-day Delta into a near-no-op on the slice of QIDs whose source content is unchanged.

### Fixed
- **`init_db` no longer re-walks tens of thousands of vulns on every container start.** The `_backfill_threat_columns` detection query treated any row with `threat_intelligence_json` populated and all flag columns at 0 as "needs backfill" — which captured legitimate rows that had no recognized threat tags inside the JSON. On a 90K-vuln DB, ~42K rows hit this false-positive every restart and the function loaded all of them into Python with `fetchall()`, allocating hundreds of MB of heap before doing any work. Symptom on a constrained host (Mac Docker memory limit, RHEL 2vCPU): WAL file mtime never advanced, container hung in the entrypoint pre-flight import for 10+ minutes with no log output. Fix is two-layered: (a) new `threat_backfill_done` column on `vulns` set to 1 by `upsert_vuln` directly (live ingest never enters the backfill code path) and by the migration UPDATE for legacy rows that already have flags set or have no JSON to derive from; (b) `_backfill_threat_columns` now streams via `cursor.fetchmany(500)` with per-batch commits, so progress is durable across kills and Python heap stays bounded. Logs every batch (`[Init] Threat-column backfill: N/M done`) so a multi-minute legacy migration is visible instead of silent.
- **Backfill Missing button no longer surfaces during an active sync.** The button is for recovery from interrupted or already-completed-but-incomplete syncs (where the post-Full-Sync verify step established a known gap). Showing it mid-sync misled users into thinking the running sync had a gap that wasn't established yet. Now hidden whenever the data type has a sync in flight; reappears once the run finishes (or if the verify step records `last_missing_count > 0`).

### Changed
- **Child-table writes in `upsert_vuln`, `upsert_control`, `upsert_policy`, and `upsert_pm_patch` switched from per-row `conn.execute()` loops to `conn.executemany()` batches.** Same `INSERT OR IGNORE` / `INSERT INTO` semantics, same DB state, idempotent under repeat upserts. Each parent record's child rows (CVEs, bugtraqs, vendor refs, RTI tags, supported modules for QIDs; technologies for CIDs; controls for policies; QID and CVE links for PM patches) are now written in a single prepared-statement call instead of one statement per row. Eliminates ~5× the Python↔SQLite roundtrip overhead per record on the child-table write phase. The v2.0 CHANGELOG had explicitly tracked this as known-pending optimization work; on a 2 vCPU Hyper-V VM where per-record SQL work was the dominant Full Sync cost, the slowdown shows up as ingest throughput dropping from 23K rec/min early in a sync to ~700 rec/min on later chunks.

### Added
- **`docs/ARCHITECTURE.md` Performance Characteristics section**: side-by-side reference numbers for a high-end developer environment (Apple Silicon Mac, NVMe SSD) and a low-end ops VM (Intel Xeon E5-2673 v4, 2 vCPU, Hyper-V on Azure). Pre-v2.4 baseline measured on the low-end VM: **3 h 34 min 46 s for 208,760 QIDs**, with ingest throughput collapsing from ~23,000 rec/min in the first chunks to ~580 rec/min in the final chunks. Documents the ~20–30× wall-time gap so users running on constrained hosts have realistic expectations and a list of hardware levers (vCPU bump, Premium SSD, swap) plus tracked code-side optimizations (payload-hash skip, pre-compiled bleach) that haven't shipped yet.

### Tests
- `test_upsert_vuln_executemany_child_tables_parity` covers (1) every dict-shaped child entry lands as exactly one row, (2) non-dict entries filtered correctly across each child path, (3) DELETE+executemany idempotency under re-upsert, (4) child-less QIDs produce zero rows in every child table.
- `test_upsert_vuln_skip_unchanged_short_circuits_on_identical_input` covers the Delta skip path: identical payload is a no-op, modified payload runs the full upsert, `source_hash` is updated on change.
- `test_fts5_deferred_for_vulns_rebuilds_index_and_reinstates_triggers` confirms triggers are dropped inside the context, the `'rebuild'` repopulates the index from the parent, triggers come back in place at exit, and post-context normal upserts incrementally update FTS5 again.
- `test_threat_backfill_done_marker_prevents_re_walk` covers the migration: legacy rows with flags already set get marked done by the belt-and-suspenders UPDATE, rows that need processing get backfilled and marked done, no-JSON rows are filtered out of the candidate query, fresh `upsert_vuln` calls set `done=1` directly.

## [v2.3.0] — 2026-05-06 — Automatic Updates Scheduling, Apply UX, PM QQL Fix

### Added
- **Automatic Updates schedule**: new `/api/update/schedule` (GET + POST) backend backed by an `auto_update_config` single-row table. APScheduler cron job invokes `apply_update()` on the configured day-of-week and time, recording last_check / last_status / last_version / last_error before the master-restart fires so the result survives the container reload. Restored from DB on `init_scheduler` startup. Fills out the previously-orphaned Settings → Automatic Updates UI that had been posting to a non-existent endpoint.
- **Apply Update progress modal**: non-dismissible modal with phase-tracked spinner — Downloading → Restarting services → Waiting for app to come back online. Auto-reload triggers on the server down→up transition (proves the master actually restarted and avoids the prior race where the still-up old worker would falsely satisfy the poll right before SIGTERM). Failsafes: reload anyway after 30s of continuous "up" responses; surface a "Refresh now" button after 90s.
- **Vault session minted on credential save**: `POST /api/credentials` now sets the `qkbe-vault-unlocked` HttpOnly cookie and stores a session token. The first sync after Save Credential no longer triggers the re-auth modal asking for the password the user just typed. `max_age` is honored from the existing session-timeout setting.
- **UPDATING.md rewrite**: leads with symptom and recovery steps for users hit by the v2.1 silent-update bug, explains the `--preload` pitfall plainly, documents the v2.2+ behavior (master SIGTERM, ~5–10s downtime, browser refresh).

### Fixed
- **PM Patches delta sync rejected with `Invalid QQL`**: the QQL `lastModified:>"<watermark>"` was wrong on two counts — the patch entity has no `lastModified` token (correct token is `modifiedDate`) and date comparisons use bare `>` not `:>`. Switched to `modifiedDate>"<watermark>"`. Added a one-shot fallback that retries the first page without the date predicate if Qualys still returns a QQL 400 on an older backend, degrading to full-list ingest (idempotent upserts) instead of aborting the whole sync.
- **Automatic Updates schedule disable robustness**: the POST handler previously 400'd when `day_of_week` / `hour` / `minute` were missing or invalid even when the user was just turning the feature OFF. Strict validation now only runs on enable; on disable we accept whatever was sent (falling back to existing config or defaults), clamp out-of-range values, and always call `remove_auto_update_schedule`. The feature can always be turned off cleanly. `_execute_auto_update` also re-checks `enabled` at fire time so a job that was already triggered when the user disabled doesn't apply an update anyway.
- **Auto-update schema migration**: if `auto_update_config` exists on a persistent volume without the `last_version` column (an earlier 9-column shape), `init_db()` now ALTER TABLE adds it.
- **Automatic Updates dropdown unreadable**: day-of-week select and time input had inline `style=` attributes referencing two undefined CSS variables (`--bg-card`, `--fg`) that don't exist in `style.css`, causing grey-on-transparent text. Removed the inline overrides; the default `input, select, textarea` rule now applies.

### Docs
- **CHANGELOG revived**: backfilled v2.2.0 and v2.3.0 entries from git history. ROADMAP's "Planned (v2.2)" section renamed to v2.3 with the original three planned items still present; new "Completed (v2.2 — Sync Robustness, UX, Updater)" section added enumerating what actually shipped.
- **BUGS.md updated**: BUG-006 through BUG-016 added covering the bugs fixed in this and the v2.2 wave.
- **ARCHITECTURE.md**: scheduler row mentions auto-update jobs, updater row notes master-restart + `--preload` removal, `auto_update_config` added to the schema list, "Last updated" bumped to 2026-05-06.
- **update-manifest.json**: 2.2.0 → 2.3.0; notes summarize the auto-update scheduling feature, apply-progress modal, vault session on save, PM QQL fix, and the auto-update toggle.


## [v2.2.0] — 2026-05-06 — Sync Robustness, UX, Updater Rewrite

### Added
- **Manifest-driven in-app updater**: each release ships an `update-manifest.json` that defines the apply steps (`copy_file`, `copy_dir`, `pip_install`, `run_command`, `restart`). The NEW version's manifest controls the update flow, so the old code running the update can adapt to whatever the new release needs without code changes to the updater itself. Replaces the prior hardcoded sequence that couldn't add/move steps without an updater rewrite.
- **Self-healing legacy updater path**: after a copy, verifies the app loads via `python3 -c "from app.main import app"`. If import fails or fewer routes than expected register, reinstalls dependencies and re-verifies before declaring success.
- **Self-healing entrypoint** (`entrypoint.sh`): on container start, runs the same import check; if it fails, runs `pip install --no-cache-dir -r requirements.txt` and retries before launching Gunicorn. Catches the case where a manifest update added a dependency the previous restart missed.
- **`UPDATING.md`**: user guide covering how the manifest-driven updater works, what's safe across updates (data on volumes, never touched), and recovery commands for users coming from the older updater that left the app in a partial state. *(Rewritten in v2.3.0 to also cover the `--preload` silent-update bug.)*
- **`README.md` Updating section** pointing to `UPDATING.md`.

### Fixed
- **QID sync crash on CVSS scores with attributes** (Issue #4): Qualys returns CVSS BASE/TEMPORAL with a `source` attribute (e.g. `<BASE source="cve">5.0</BASE>`), which xmltodict parses to `{"@source": "cve", "#text": "5.0"}`. `float({...})` raised `float() argument must be a string or a real number, not 'dict'` and aborted the page's batch upsert. Added `_xml_text` helper that unwraps `#text` from a dict-shaped XML value and routed CVSS v2/v3 base + temporal reads through it.
- **init_db crashloop on malformed correlation_json** (Issue #5): `_backfill_threat_columns` raised `'str' object has no attribute 'get'` on rows where `EXPLT_SRC` or `MW_SRC` was a bare string (xmltodict's collapsed text-only-element shape). The function ran on every gunicorn start, so a single malformed row kept the container in a permanent restart loop. Added isinstance guards inside both loops, and wrapped each row's processing in try/except so a malformed blob logs a WARNING and is skipped rather than aborting `init_db`.
- **QID Full Sync abort on CORRELATION shape variations** (Issue #6): same defect class as #5 but in the live ingest path of `upsert_vuln`. xmltodict can produce four shapes for `EXPLT_SRC` / `MW_SRC` — dict, list-of-dicts, bare string, None entry from an empty self-closing element — and the loops only handled the first two. The None-entry case was the prod-failing shape. Extracted `_count_correlation_exploits_and_malware` helper that tolerates all four shapes at every nesting level and consolidated the two duplicated implementations (in `upsert_vuln` and `_backfill_threat_columns`) into a single call site. Audited every other upsert path; only `upsert_vuln` was affected.
- **Per-record sync errors aborted whole sync**: each per-record `upsert_X` call across all six sync paths (QID main + backfill, CIDs, Policies, Tags initial + enrichment, PM Patches) is now wrapped in try/except. A single freak record logs a WARNING with its ID and is skipped; the sync now finishes with N-1 records instead of zero.
- **In-app updater silently no-op'd under gunicorn `--preload`**: Apply Update returned `status: ok` and advanced `.current_version`, but the running app behavior was unchanged. `--preload` causes the master to import `app.main` once and fork workers via copy-on-write; the updater's worker-only kill let the master respawn workers from the cached old code regardless of disk changes. Updater now SIGTERMs the master (PID 1) on a 2s background-thread delay so the apply response can flush; `restart: unless-stopped` brings the container back up with a fresh import. Entrypoint also drops `--preload` as defense in depth.

### Added
- **Welcome tip on Settings tab for fresh installs**: when no credentials are saved, the app routes the initial tab to Settings and reveals a tip walking the user through saving a credential and running their first Full Sync. Auto-hides the moment a credential is saved (and reappears if the user later deletes all credentials — same fresh-install state).
- **Save Credential gated on a successful Test Connection**: a typo in the username (or any auth field) used to land in the vault and surface later as confusing Qualys errors. Save now requires a successful Test Connection against the exact `{username, password, platform}` currently in the form. Snapshot is invalidated on any change to those three fields, on Clear/Disconnect, or when an unmasked vault password is typed into. Save button is visually disabled until a valid test exists.
- **Credential picker re-renders immediately after delete**: previously the deleted row stayed visible until the dropdown was closed and reopened.
- **Pre-flight collision check on tag migration**: checks destination for existing tag names before migration starts. Per-tag options: rename (editable suffix), skip, skip all, rename all.
- **EASM, DNS SINKHOLE, SEM in system tag list**: correctly classified as Qualys-provisioned system tags.
- **CLOUD_ASSET rule type → connector origin**: all tags with CLOUD_ASSET rule type are classified as connector-dependent (require matching cloud connectors in destination).
- **Schedule badges for Tags and PM Patches**: delta sync schedule badges now display on Tags and PM Patches rows in Settings.

### Changed
- **"Organizer" tag origin renamed to "Static"** to match Qualys terminology. Tag origin values are now: `rule_based`, `static`, `connector`, `system`.
- **System tag list is exact-name only**: no prefix pattern matching (e.g. `EASM*`) — prevents false positives on user-created tags.

### Fixed (other)
- **Updater: tarball nesting**: the public-repo tarball nests the project under `Q KB Explorer/`. The updater now finds the manifest at either the tarball root or one level deeper instead of bailing.
- **Updater: install order**: dependencies are installed **before** the `app/` directory is replaced. The previous order could leave new code on disk that imported a not-yet-installed package, breaking Gunicorn restart.
- **Updater: entrypoint executable bit**: the manifest copies `entrypoint.sh` and then runs `chmod +x /app/entrypoint.sh` so the file remains executable through the update.
- **Intelligence + QIDs `vuln_type` filter mismatch**: filter values now match the strings Qualys returns from the Knowledge Base API. Previously a casing/value mismatch caused the filter to return empty result sets.
- **Intelligence severity filter X-remove button**: clicking the × on a severity chip now actually clears the filter; previously the chip was removed visually but the filter stayed applied.
- **Tag detail crash**: missing `isEditable` variable after banner rewrite caused "Failed to load tag detail" on every click.
- **Tag ownership filter**: "Qualys-managed only" filter now uses `tag_origin='system'` instead of `is_user_created=0` which was always empty.
- **SYSTEM pill accuracy**: driven by `tag_origin` (heuristic name list) instead of `is_user_created` (unreliable — Qualys API doesn't expose `reservedType`).
- **Tag classification persistence**: `_fix_tag_classification()` runs as a dedicated function with its own DB connection after `init_db`, guaranteeing the UPDATE commits regardless of `executescript` transaction state.
- **Auth-required toasts suppressed**: no more error toasts before login when vault is locked.
- **Delta sync schedule date**: defaults to today when existing schedule has a past start date.
- **Migration "no tags" error**: paginated tag ID fetch (respects 500 per_page API limit).


## [v2.1.0] — 2026-05-03 — Intelligence, Threat Intel, Tag Origin, PM Linux Fix

### Added
- **Threat Intelligence integration**: threat_active_attacks, threat_cisa_kev, threat_exploit_public, threat_rce, threat_malware, exploit_count, malware_count columns on vulns table with auto-backfill from stored JSON
- **Threat badges on QID cards**: Active Attacks, CISA KEV, Public Exploit, RCE shown at a glance in search results
- **QID detail Threat Intelligence section**: known exploit links, associated malware, threat indicator tags parsed from Qualys KB correlation data
- **QID detail Remediation section**: vendor fix status, patch published date, solution text prominently displayed with green highlight when patchable
- **QID detail PM Patch Catalog section**: linked patches shown inline grouped by platform with vendor severity, KB links, reboot indicators
- **Intelligence tab threat filters**: Active Attacks, CISA KEV, Public Exploit, RCE, Malware, Has Exploits on dedicated filter row
- **Intelligence tab clickable metrics**: clicking a stat card drills into the matching found set (additive filter refinement)
- **Intelligence tab active filter bar**: shows applied filters as removable tags with NOT toggle (click to negate — blue=include, red=exclude), expand/collapse for long filter sets
- **Intelligence tab saved searches**: save/load named filter sets to localStorage
- **Tags sub-tabs**: Browse, Library, Audit, Migration — each in its own sub-tab panel (matches Policies pattern)
- **Tag tree view**: parent-child grouping with collapsible chevrons, load-on-expand from DB, recursive sub-parent nesting. Flat card view when filters active.
- **Tag Library grouped by rule type**: collapsible sections with rule-type status pills. Read-only detail modal. Clone/Apply from detail view.
- **Tag Library seed expanded to 136 entries**: sourced from Qualys "Complete Tag List" (Colton Pepper) + AWS/Azure/GCP/OCI cloud state tags
- **Tag origin classification**: heuristic classifies tags as rule_based, static, connector, or system. Shown as badge on cards. Used in migration to group by category.
- **Tag select mode**: Select button with Select All, individual selection persists across pagination, "+ children" button on parent cards for recursive child selection
- **Tag export to JSON**: instant download from local DB (no Qualys API calls), supports select all
- **Tag import from JSON**: import shared tag collections into local DB for browse/audit/migrate
- **Tag delete from Qualys**: bulk delete user-created tags from source subscription with system tag protection
- **Tag migration origin picker**: modal shows breakdown by origin (rule_based/static/connector/system) with per-category checkboxes. System tags hard-excluded.
- **Tag migration async with progress**: runs in background thread, polls every 1.5s with progress bar, persists reports to /data/migration_reports/
- **Tag provenance tracking**: source_platform, source_subscription columns. Included in JSON export. Migration uses provenance for update-vs-create logic.
- **Tag audit improvements**: duplicate findings clustered with full tag cards, rule descriptions explaining each audit check, clean-state lists all checks passed
- **Dashboard Data Inventory section**: all 6 data types (QIDs, CIDs, Policies, Mandates, Tags, PM Patches) in consistent card format
- **Dashboard Threat Intelligence summary**: Active Attacks, CISA KEV, Public Exploits, RCE, Has Exploits counts
- **Sync Health table**: now includes Tags and PM Patches rows
- **PM API test script**: scripts/test_pm_api.py for Qualys PM v2 API exploration
- **Themed confirm/prompt dialogs**: all native browser dialogs replaced with dark/light mode matching modals

### Fixed
- **PM Linux sync returning 0 patches**: isSuperseded:false filter removed for Linux (field is null on Linux patches, not false). Full 213K Linux catalog now syncs.
- **PM pre-count always returning None**: gateway_count now reads count from response headers (where Qualys PM v2 API puts it) instead of response body.
- **Tag classification: 92 tags misclassified as system**: only tags with reservedType are system. Tags without it (imported, migrated, static) now correctly classified as user-created.
- **Intelligence filter logic AND→OR**: selecting PM Win + PM Lin now returns union (either platform) not intersection. Same for threat filters.
- **Tag migration worker timeout**: migrating 167+ tags killed gunicorn worker. Now runs in async background thread.
- **Tag "Select All" then migrate returning empty**: per_page=100000 rejected by OpenAPI validation (max 500). Now paginates correctly.
- **Toast hidden behind modals**: z-index raised to 99999 (above modal 9999).
- **Migration errors invisible**: errors now shown inside modal results area AND as toast.

### Changed
- **ASSET_INVENTORY → GLOBAL_ASSET_VIEW**: all 86 seed library entries updated. ASSET_INVENTORY marked legacy with pointer to GLOBAL_ASSET_VIEW. Rule type filter now driven by local DB content only (no static list).
- **VULN_DETECTION added as recognized rule type** alongside VULN_EXIST.
- **Rule type labels**: dropdown shows context (e.g. "GLOBAL_ASSET_VIEW (preferred)", "OS_REGEX (legacy)", "GROOVY (restricted)")
- **Rule type warnings on library cards**: legacy/restricted notices surface in card UI and Apply modal pointing to preferred replacement.
- **QID search Clear button**: moved next to Search button (matches Intelligence tab pattern)
- **color-scheme CSS property**: added for proper native form element theming in dark/light mode

### Performance
Benchmarked on a production Qualys POD3 subscription (Docker Desktop, macOS M-series):

| Data Type | Records | Full Sync | Improvement |
|-----------|---------|-----------|-------------|
| QIDs | 208,307 | **8.8 min** | 14x faster (was 125 min) |
| CIDs | 26,921 | **15.1 min** | 2x faster (was 31.8 min) |
| PM Patches | 218,050 | **3.1 min** | 5x faster (was 14.9 min) |
| QID Delta | 208,307 base | **2 seconds** | Near-instant |

Key optimisations: populated-range targeting skips empty QID id-space windows, batched SQLite transactions per page, FTS5 incremental rebuild, PM v2 cursor pagination at 1,000 items/page, and response-header count extraction (eliminates the dedicated count endpoint round-trip).


## [v2.0.0] — 2026-05-02 — Tags Phases 1-5, Sync Robustness, OpenAPI

Major release. Merged via squash from PR #12 (53 commits). Headline:
all five Tags phases (read · migrate · CRUD · library · audit), every
sync path made queue-safe and rate-limit-friendly, code-driven OpenAPI
documentation at `/api/docs`, and the caching-middleware framing
spelled out for downstream consumers.

### Fixed
- `KeyError: 'tags'` at the end of every Tags sync — `update_sync_state`'s local `table_map` was missing the `tags` entry, so the watermark update threw after page records had already been committed. Tags sync now completes cleanly and Settings shows the right count.
- `UnboundLocalError: get_db` on the tag/CID/policy/QID sync paths after the batched-transaction refactor. Inner `from app.database import get_db` lines made `get_db` a function-local name, shadowing the module-level import and breaking the new top-of-page `with get_db() as conn:` blocks. Inner imports removed.
- `init_db()` crash when upgrading from a DB without the `disabled` column — `CREATE INDEX idx_vulns_disabled` in `_SCHEMA_SQL` ran before the migration's `ALTER TABLE ADD COLUMN`. Index creation moved into the migration block.

### Sync robustness & rate-limit friendliness
This release reorganises every sync path so manually triggering a Full or Delta on multiple data types is safe and predictable. **Set them all and walk away** — no more babysitting a queue or worrying about stacking requests against the Qualys rate limit.

> See **README → Understanding sync modes** for an end-user-facing explanation of how the universe, verification, and Backfill Missing work, including the use-case difference between Backfill and Delta.

- **Manual syncs are queued, not failed fast.** A global sync mutex serialises one sync at a time. If a sync is already running and you click another, the new request is **queued** rather than rejected; you get a `200 OK` with `queued: true` and the worker thread picks it up as soon as the current sync finishes. The previous behaviour (immediate 409) forced you to wait, retry, and time-coordinate clicks; that's gone.
- **Universal 409 / 429 retry on every Qualys call.** `QualysClient` honours `Retry-After` headers and applies exponential backoff up to 3 retries on rate-limit and conflict responses, on the v4 KB API, the QPS REST API, and the PM Gateway. Logs surface `RATE_LIMIT_RETRY` events so you can see exactly what was throttled and for how long.
- **Pre-count + populated-range targeting on QIDs.** Full sync first walks the universe with `details=Basic` to enumerate every QID, then issues detail (`details=All`) requests **only against 10K windows that actually contain QIDs**. Empty regions of the QID id-space are skipped entirely. Result: roughly half the API calls a naive scan would make, and an exact denominator for the progress bar.
- **Pre-count + verify on every type.** Same pattern now applied to CIDs, Policies, Tags, and PM Patches. After each Full sync, a verification step diffs the universe against the local DB and surfaces any QIDs that didn't land. `VERIFY_OK` / `VERIFY_MISSING` events appear in the sync log.
- **Persisted KB universe.** Pre-count results write to a new `sync_universe` table keyed on `(data_type, item_id)`. Backfill no longer needs to re-walk the universe — it's a single indexed `LEFT JOIN` against the table you already have. **~10–15 fewer Qualys calls per Backfill click** after the first run.
- **Backfill button knows when there's nothing to do.** `last_missing_count` is persisted on `sync_state` after every full-sync and backfill verification. Once verified clean, the Backfill Missing button hides itself; when there's a known gap, the button shows the count inline (`Backfill Missing (12,345)`).
- **Scheduled delta syncs unchanged.** The scheduler still uses a blocking acquire on the same mutex so background deltas serialise naturally with manual work, but the existing scheduler timing/ordering is intact.

### Performance
- **Batched per-page transactions on every sync type.** Each upsert helper (`upsert_vuln`, `upsert_control`, `upsert_policy`, `upsert_tag`, `upsert_pm_patch`, `extract_mandates_from_control`) now accepts an optional `conn` so the on-page loop wraps the entire page worth of writes in a single transaction.
  - **Real-world result: marginal, not transformational.** Same QID full sync re-run on 208,307 records: **7,611s post-fix vs 7,516s pre-fix** — about flat (the new run also enabled `show_disabled_flag=1`, slightly larger payloads, so the wash isn't surprising). Per-chunk timings on the big windows shifted maybe 5–15% faster (`750000` chunk: 8:00 → was 9:11; `990000` chunk: 10:02 → was 10:55), but my hypothesis that per-commit fsync overhead dominated was wrong.
  - **What the bottleneck actually is.** Per-record cost is dominated by *per-statement SQL work + Python work*, not commit fsyncs. Each `upsert_vuln` still issues an `INSERT OR REPLACE` on the parent + `DELETE` + N `INSERT`s on five child tables (CVEs / bugtraqs / vendor refs / RTI / supported modules), plus `bleach.sanitize_html` on three fields and `json.dumps` on several others. For a 9,700-record chunk, that's ~50ms/QID of pure work regardless of how many transactions wrap it.
  - **Why the change is still worth keeping.** Single-transaction per page is the right SQLite shape independent of speedup; it eliminates a class of "sync writes interrupted mid-record" partial-state bugs and makes future bulk-write work (executemany, skip-unchanged) tractable. It's also a no-op when called from the standalone helpers, so non-sync paths are unaffected.
  - **Follow-up work** to actually move the needle: profile a single `upsert_vuln` to confirm where the milliseconds go; switch child-table writes to `executemany`; skip `DELETE`+`INSERT` on child tables when the row's data hasn't changed (compare a hash of the source payload). Tracked but not in this release.
  - Tag enrichment (per-tag GET) intentionally left per-record — HTTP latency dominates and a long-held write lock there would block UI reads.
- **SQLite concurrency hardening.** `busy_timeout` raised to 120s, `synchronous=NORMAL`, exponential-backoff retry on `database is locked`. Combined with the mutex above, the "policy + KB sync at the same time → database is locked" failure is gone.

### Smart Policy → CID dependency handling
- **Auto-queue CIDs ahead of Policies.** Clicking Policies sync when CIDs haven't synced no longer 400s with "CID data required." `trigger_sync` now checks whether the dependency is satisfied (last_sync set, currently running, or already queued) and, when it isn't, auto-spawns a CID sync first then queues Policies behind it. Response carries `auto_queued_dependencies: ["cids"]` plus a message so the UI can surface "we queued CIDs first because Policies depends on them."

### Recovery from interrupted syncs
- **Startup cleanup of unfinished sync_log_runs.** When the container is restarted while a sync is queued or in-flight, the run row gets stranded at `status='running'` with no `finished_at` — and the renderer flags every subsequent log view with "Worker was killed — sync did not complete." On startup `init_db()` now closes those rows out (`status='error'`, `finished_at=now()`) so previous logs render cleanly and the next time the user opens Last Sync Details they see "Interrupted" instead of an alarm.

### Use as a caching middleware
Q KB Explorer's documented JSON API plus its scheduled-delta auto-maintenance make it usable as a **local caching tier** between Qualys and your other tools (dashboards, ticketing, reporting, custom scripts). Multiple downstream consumers share one set of Qualys credentials, one sync schedule, and one rate-limit budget — no more N tools each making duplicate API calls. The OpenAPI 3 spec at `/api/docs/openapi.json` is the consumer-facing contract; see **README → Use as a Qualys API caching middleware** for the architecture diagram and wiring guide.

### Added
- **Intelligence tab** — single-screen QID lens with stat strip, severity multi-toggle, KB/PM/PCI quick filters, vuln-type checkboxes, category dropdown, and per-row PM patch counts (Win/Lin). Keyboard shortcut `6`; tabs after Mandates shifted accordingly.
- **PM Patch Catalog enrichment** — full sync of Qualys Patch Management catalog (Windows + Linux) via Gateway JWT. New `pm_patches`, `pm_patch_qids`, `pm_patch_cves` tables; `/api/qids/<qid>/patches` and `/api/pm/stats` endpoints; `pm_any` / `pm_win` / `pm_lin` filters on `/api/qids`; multi-select severities and vuln types.
- **QID range expansion** — bumped `QID_MAX_ID` 600K → 2M and effectively disabled empty-chunk early termination so dormant gaps in Qualys' sparse QID space don't truncate the scan.
- **Tags tab (Phase 1 — read-only browse + sync)** for Qualys Asset Tags via the QPS REST API
  - New `tags`, `tag_exports`, and `tags_fts` SQLite tables with FTS5 full-text search
  - `SyncEngine.sync_tags()` full + delta sync against `/qps/rest/2.0/search/am/tag` with cursor-based pagination
  - System-vs-user detection driven entirely by API metadata (no hard-coded name list); ambiguous tags default to system (read-only)
  - `[SYSTEM]` pill on Live Tags identifying Qualys-managed tags by `reservedType`; tooltip surfaces the raw value
  - Collapsible Qualys best-practice references panel linking articles 000005817, 000005818, 000005819 plus CSAM docs
  - Tag detail modal with parent breadcrumb, children list, color swatch, rule logic, and system banner
  - Filters: full-text query, rule type (multi-select), ownership (User-created / Qualys-managed / All)
  - Keyboard shortcut for the Tags tab (`6`); Settings shifted to `7`, Help to `8`
  - 18 new tests covering search, filter, detail, breadcrumb, system-vs-user detection, default-deny, sync wiring, and QPS helper parsing
- `QualysClient.execute_json()` for JSON-body QPS REST calls plus `qps_extract_data` / `qps_has_more` static helpers
- Dynamic build ID in About section (git SHA from Docker build or auto-update)
- Contact email field in bug/feature request form for follow-up
- Build version and browser info auto-included in GitHub issue body
- Post-update reload polls /api/health until server responds (replaces fixed 5s delay)
- Dockerfile BUILD_VERSION arg bakes git SHA into image at build time
- Auto-update scheduling (weekly cron with day/time picker in Settings)
- Sync health tooltips on dashboard status dots explaining criteria (age thresholds, recommended actions)
- Supported modules (agent type) display and filtering on QID tab
- Module badges on QID search result cards (sky-blue)
- Supported Modules multi-select filter in QID advanced filters
- Supported Modules field in QID detail modal
- Supported Modules column in QID CSV export
- `vuln_supported_modules` database table
- Development Foundation onboarding (docs/, .github/dependabot.yml)
- Automatic weekly database maintenance with compressed backup, integrity check, VACUUM, ANALYZE
- `db_maintenance_config` table, `app/maintenance.py` module (backup, restore, vacuum)
- Database Maintenance card in Settings tab (day/time picker, last run status, backup info)
- Startup ad-hoc maintenance: runs automatically on first container start if no previous run exists
- Maintenance failure banner with Restore from Backup option
- Dashboard Database Health card (DB size, maintenance status, backup info)
- Application auto-update feature: check GitHub for new versions, download and apply updates
- `app/updater.py` module (check, download tarball, extract, pip install, restart Gunicorn)
- Application Updates card in Settings tab (Check for Updates, Update Now)
- `/api/health` endpoint for Docker health checks (returns sync thread status)
- Worker resilience: 30s frontend request timeout with unresponsive server banner (Retry/Dismiss)
- Stuck-sync detection: warns if sync progress unchanged for 5 minutes
- Credential (user/platform) displayed on sync status cards and delta sync modal
- Bug/feature request form in Help tab (submits to GitHub Issues)
- Sync dependency chain documented in Help tab (QIDs → CIDs → Policies → Mandates)

### Changed
- About section shows dynamic build ID (git commit SHA) instead of static "v1.0.0"
- Bug/feature request form uses radio buttons instead of dropdown for better dark theme readability
- Delta sync modal body scrolls within viewport (fixed header/footer always visible)
- All browse tabs now CSV-only (PDF removed due to reportlab layout issues with large content fields)
- Bulk CSV export is now unlimited (removed 200-item cap)
- Select mode now hides regular export buttons to prevent accidental full-result exports
- Mandates sync buttons removed from Settings tab (mandates auto-extracted during CID sync, not a separate API)
- Mandate status card now shows read-only extraction info with CID sync timestamp
- Policy sync now requires CIDs to be synced first (returns 400 with helpful message if not)
- CID sync completion now shows toast with mandate extraction count
- Gunicorn timeout reduced from 660s to 120s (syncs run in threads, not blocking HTTP)
- Docker health check added (polls /api/health every 30s, restarts after 3 failures)
- Sync status uses live table counts instead of cached sync_state values
- Mandate sync timestamps inherit from CID sync when more recent

### Fixed
- Supported modules XML parsing handles string/dict/list variants from xmltodict
- PDF word wrap and smart column widths for policy report PDF
- HTML tags stripped from PDF export fields, remediation URLs preserved as plain text
- Select mode export bug: regular CSV button was visible during select mode
- Dashboard sync health for mandates showing "Never synced" despite having records
- Mandate count showing 0 after CID sync (live count fix)

### Removed
- PDF export buttons from all browse tabs (CSV remains; PDF retained only for individual policy reports)
- Mandate Map export button from Mandates tab

### Security
- HTML sanitization on QID diagnosis/consequence/solution fields (bleach)
- Rate limiting on credential verification endpoint (flask-limiter)
- CSRF protection via X-Requested-With header on state-changing requests
- Server-side HttpOnly auth cookie (replaces client-side cookie)
- Generic error messages (no internal stack traces exposed)
- Removed wildcard CORS (same-origin only)
- Hardened SQL fallback path in sync state updates

### Infrastructure
- GitHub Actions CI/CD workflow (pytest on push/PR) — Roadmap #49
- Dependabot configuration (pip, docker, github-actions)
- Dynamic `secure=True` cookie flag when TLS certificates detected

---

## [v1.3.0] — 2026-03-24 — Phase 4: Quality of Life

### Added
- Keyboard shortcuts: `1`-`7` tabs, `/` focus search, `?` shortcuts modal, `t` toggle theme, `b` bookmark (Roadmap #47)
- Bookmark/favorite QIDs, CIDs, and Policies with star icons on cards and detail modals, stored in localStorage (Roadmap #44)
- Recent searches history with clock icon dropdown on all search bars, max 20 entries in localStorage (Roadmap #45)
- Bulk export: Select mode on QID and CID tabs with CSV export of full details including CVEs, diagnosis, solution (Roadmap #46)
- `GET /api/qids/export-details` endpoint for bulk QID detail CSV export (unlimited)
- `GET /api/cids/export-details` endpoint for bulk CID detail CSV export (unlimited)
- Help tab (7th tab) with comprehensive documentation: Quick Start, Data Types, Search, Policy Migration, Bookmarks, Bulk Export, Shortcuts, Troubleshooting (Roadmap #48)
- Keyboard shortcuts modal (`?` key or via Help tab)

---

## [v1.2.0] — 2026-03-08

### Added
- Dashboard tab with severity breakdown charts (Chart.js)
- Sync health dashboard (last sync times, health indicators)
- Compliance coverage metrics (mandates to controls to policies)
- QID statistics (by category, patchable percentage)
- CSV export of search results (QIDs, CIDs, Policies, Mandates)
- PDF report generation (tabular export with reportlab)
- Mandate compliance mapping export (flattened hierarchy)
- Policy report view with section-based layout and PDF generation
- Technology count on policy cards in browse view
- Technology display and filtering in policy detail view
- Empty policy detection/skip during sync, ZIP export, server-side upload guard

### Fixed
- Modal z-index stacking so child modals appear on top
- Policy tech count uses XML export data instead of DB-derived count
- Policy delete, disconnect auth, and session timeout handling

---

## [v1.1.0] — 2026-03-05

### Added
- Vault-based identity gate (session cookie auth)
- before_request route protection (401 for unauthenticated API calls)
- Logout endpoint and disconnect button wiring
- Global 401 response handler (re-show auth modal)

### Security
- All API routes now require vault authentication (except credential management)

---

## [v1.0.0] — 2026-03-01

### Added
- QID sync (full and delta) with ID-range chunking for 114K+ records
- CID sync (full and delta) with truncation paging for 26K+ records
- Policy sync (full and delta)
- Mandate/compliance framework extraction from CID sync
- FTS5 full-text search across QIDs, CIDs, Policies, Mandates
- FTS5 prefix matching for type-ahead partial word search
- Multi-select filters with AND/OR toggle
- CVE type-ahead server search (debounced)
- QID detail view (CVSS, CVEs, Bugtraq, vendor refs, threat intel)
- CID detail view (technologies, rationale, linked policies, linked mandates)
- Policy detail view (linked controls, linked mandates, migration tools)
- Mandate detail view (associated controls and derived policies)
- Policy export/import (cross-environment migration)
- Stale export detection
- AES-256-GCM credential vault (two-volume Docker security)
- Multi-credential vault with platform association
- Credential verification (secrets.compare_digest)
- Server-side credential resolution (credential_id)
- Connection testing (before save and after save)
- Sync scheduling (daily/weekly/monthly with timezone)
- Persistent sync history (SQLite-backed, 20 entries per type)
- Real-time sync progress with elapsed time display
- Full sync purge warning modal
- Dark/light theme toggle
- Cache-busted static assets
- Feature tour GIF with subtitle player
- Qualys platform registry (13 regions)
- Docker deployment with optional TLS support
- Delta sync watermarks (Qualys API format)
- Cross-navigation (CID to Policy, CID to Mandate, Policy to Mandate)
- Severity/criticality color-coded cards
- Dynamic record count badges (Total, Found, percentage)
