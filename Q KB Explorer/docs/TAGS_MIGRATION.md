# Tags — Cross-Environment Migration

Phase 2 of the Tags build, significantly overhauled in v2.1.0. Lets
an operator select tags directly from the Browse tab and migrate
them to a different Qualys environment — or export/import via JSON
for offline hand-carry.

**Only user-created tags can migrate** — Qualys's QPS REST
`create/am/tag` endpoint rejects payloads with a `reservedType`, so
system tags are blocked at the upload step (with a clear message;
see "Why system tags can't migrate" below).

## When to use it

- Promoting a curated tag set from a dev / sandbox subscription to
  prod
- Cloning a tag taxonomy into a peer subscription so reporting
  stays consistent across business units
- Sharing a custom tag with a partner / customer who runs their
  own Qualys subscription (export the JSON, hand them the file,
  they import it on their side)

## Direct migration from Browse tab

The primary workflow now starts from the **Browse** tab:

1. Select one or more tags using the checkboxes on tag cards.
2. Click the **"Migrate to env..."** button that appears in the
   selection toolbar.
3. The migration modal opens with the selected tags listed.

An **audit pre-check** runs automatically when the modal opens. If
any findings exist for the selected tags, the modal shows a warning
with "Review in Audit tab" or "Ignore and proceed" options.

## Migration modal

The modal collects:

### Destination credential
Picked from the credentials vault. Same vault, different Qualys
subscription. The credential's stored platform is used as the
destination API base.

### Tag origin picker
Controls which tag origins are included in the migration:

| Origin        | Default | Notes                                            |
|---------------|---------|--------------------------------------------------|
| `rule_based`  | on      | Tags with dynamic rules (GLOBAL_ASSET_VIEW, etc.)|
| `static`      | on      | STATIC tags — no rule, used for grouping         |
| `connector`   | off     | Warning: connector tags may not work in the destination subscription without the same connector configured |
| `system`      | excluded | Hard-excluded, shown as an info-only row explaining why system tags cannot be migrated |

### Parent tag option
Optional **"TAGs Imported YYYY-MM-DD"** grouping parent. When
enabled, the migration creates (or reuses) a parent tag with this
name in the destination and nests all migrated tags under it.

### Per-tag overrides
Collapsible section with rename, parent tag id, color, and
criticality overrides — same as the previous upload modal.

## Provenance tracking

Each tag in the local DB now carries provenance metadata:

- `source_platform` — the Qualys platform region (US1, EU1, etc.)
  the tag was originally synced from.
- `source_subscription` — the subscription identifier from which
  the tag originates.

These fields are included in JSON exports and used during migration
to determine behaviour:

- **Same subscription** → update the existing tag (if it still
  exists in the destination).
- **Different subscription** → create a new tag in the destination.
- **No provenance** (tags imported without provenance metadata
  default to `"unknown"` origin) → always create (safe default).

## Async migration with progress

Migration runs in a **background thread** so large batches don't
time out the HTTP request:

1. `POST /api/tags/migrate` returns immediately with a
   `migration_id`.
2. The frontend polls `GET /api/tags/migrate/<id>/status` every
   **1.5 seconds** and renders a **progress bar** showing
   completed / total tags.
3. The status endpoint is **auth-exempt** so polling survives
   session expiry during long migrations.

## Completion report

When migration finishes, the UI shows a **detailed completion
report** with collapsible sections:

- **Migrated** — tags successfully created or updated, with the
  new destination tag id.
- **Skipped** — tags that were skipped, with per-tag reasons (e.g.
  "tag already exists with identical rule", "excluded by origin
  filter").
- **Failed** — tags that failed, with per-tag error messages from
  Qualys.

Reports are **persisted to `/data/migration_reports/`** as JSON
files for post-hoc review, accessible via the Migration History
view.

## Delete from Qualys

The migration card includes a **Delete from Qualys** option for
bulk-deleting user-created tags from the source subscription. This
is useful after migrating tags to a new subscription and confirming
they work — clean up the source. Only user-created tags can be
deleted; system tags are excluded.

## Legacy workflows

### Export from the source environment

1. Open the Tags tab and find the tag you want to migrate. The
   detail modal has an **Export Tag** button (only shown for
   user-created tags).
2. The button hits `POST /api/tags/<id>/export` with the
   credential currently selected in the UI as the source. The
   backend pulls fresh JSON via `GET /qps/rest/2.0/get/am/tag/<id>`
   and stashes the payload in the local `tag_exports` table.
3. The export shows up immediately in the **Tags Migration** card
   below the search results.

You can also **Download JSON** from the detail modal to save the
file outside the tool — useful for moving a bundle between
machines that don't share a vault. JSON exports include provenance
fields (`source_platform`, `source_subscription`).

### Import a JSON bundle from disk

If someone hands you a tag JSON file from a different machine:

1. On the Tags tab, find the **Tags Migration** card.
2. Click **Choose File** + **Import JSON file**.
3. The file lands in the same `tag_exports` table as exports
   captured locally — there's no functional difference, the only
   filter is "where did this row come from."

The import endpoint accepts either a bare Tag object or the full
`ServiceResponse` wrapper Qualys returns.

## Why system tags can't migrate

Qualys's `create/am/tag` endpoint rejects requests where the
payload includes a `reservedType` field (the marker for
Qualys-managed tags). Even if it accepted the request, recreating
a system tag in a destination subscription is meaningless —
Qualys ships those tags by default in every subscription.

The upload endpoint catches this up front and returns a clean
error rather than letting the operator wait for Qualys to refuse.

If a tag *should* be migratable but is incorrectly auto-classified
as system, set its **classification override** to "user" in the
detail modal first — that flips the `is_user_created` effective
value and unblocks the migration path. See the editability and
classification override docs in the tag detail modal for more.

## API reference

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/tags/migrate` | Start async migration (returns `migration_id`) |
| `GET`  | `/api/tags/migrate/<id>/status` | Poll migration progress (auth-exempt) |
| `POST` | `/api/tags/<id>/export` | Pull fresh JSON from source env, stash in `tag_exports` |
| `POST` | `/api/tags/import-json` | Upload a JSON file from disk |
| `GET`  | `/api/tags/<id>/export-download` | Download the stored JSON (includes provenance) |
| `GET`  | `/api/tags/exports` | List every stored export with metadata |
| `DELETE` | `/api/tags/<id>/export` | Drop a stored export |
| `POST` | `/api/tags/upload` | Push a stored export to a destination Qualys env |
| `DELETE` | `/api/tags/bulk-delete` | Bulk delete user-created tags from source subscription |

Bodies and responses are documented in the OpenAPI spec at
`/api/docs/openapi.json`.

## Troubleshooting

**"This is a Qualys-managed system tag (reservedType: …)"** at
upload time
: The stored payload has a `reservedType` field. Either the tag is
  genuinely system-managed (no migration path), or the
  classification heuristic was wrong — set the override and re-export.

**"create-tag failed: Tag name already exists"** from Qualys
: The destination subscription already has a tag with that name.
  Pass a `new_name` on the upload modal.

**Destination tag created but at root level instead of under the
expected parent**
: `parentTagId` was either omitted on the upload or the destination's
  parent has a different id. Look it up in the destination Qualys
  console (or sync the destination credential into Q KB Explorer
  and use the Tags tab) and re-upload with the right `parent_tag_id`.

**"No stored export for this tag. Export first."** at upload time
: The export was deleted from `tag_exports` before the upload
  fired. Re-run the export from the detail modal.
