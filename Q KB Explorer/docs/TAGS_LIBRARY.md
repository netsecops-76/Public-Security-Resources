# Tags — Custom Library + Apply

Phase 4 of the Tags build. A curated bank of tag definitions that
can be applied as a new tag in any Qualys environment. Two flavors
live in the same `tag_library` table:

- **Built-in entries** (136 curated patterns) ship with the app,
  re-seed on every startup, and can be hidden but not edited or
  deleted.
- **User entries** are full CRUD and authored by the operator.

Apply re-uses the Phase 3 create-tag plumbing (validate →
`POST /qps/rest/2.0/create/am/tag` → upsert local → audit row),
so library entries hold the same quality bar as direct tag
creates and get the same Qualys-error surfacing.

## When to use it

- **Standardising tag patterns** across environments — define once,
  apply everywhere
- **Sharing curated rules with peers** — built-ins ship as starter
  patterns with a rationale + source URL
- **Bulk onboarding** a new Qualys subscription with the same tag
  taxonomy your other subscriptions use
- **Documenting "what we agreed our tags should do"** for
  auditability — the rationale field captures the why, not just
  the what

## Built-in library

The library ships **136 curated entries** sourced from the Qualys
"Complete Tag List" by Colton Pepper, expanded from the original 8
starter patterns. Entries are seeded on first boot and refreshed on
every `init_db()`.

### Categories

| Category               | Examples                                              |
|------------------------|-------------------------------------------------------|
| Informational          | Scanner appliance type, last-seen window, agent version |
| Authentication Status  | Auth success/failure, agent vs. scanner auth          |
| Authentication Details | Auth protocol (SNMP, WinRM, SSH key, etc.)            |
| Asset Type             | Physical, virtual, container, cloud instance          |
| Operating System       | Windows Server 2022, RHEL 9, macOS, ESXi              |
| Software               | Apache, OpenSSL, Java, .NET runtime                   |
| Cloud (AWS/Azure/GCP/OCI) | Region, VPC, subscription, resource group           |
| Network                | RFC 1918, DMZ, VLAN, IPv6-only                        |
| Service Profile        | Web servers, database ports, RDP exposed              |
| Business Context       | Crown jewels, PCI scope, production vs. dev           |

### Rule types

All entries that previously used `ASSET_INVENTORY` have been
migrated to `GLOBAL_ASSET_VIEW` (Qualys's preferred rule type —
better CSAM compatibility and broader asset coverage).
`VULN_DETECTION` is now also a recognized rule type in the library.

Every entry's `rationale` field tells the operator: **these are
curated patterns — review the rule before applying.** Customers'
environments differ; what counts as "internet-facing" or "Windows"
varies, and Qualys best practice for OS targeting has shifted from
`OS_REGEX` (legacy) to `GLOBAL_ASSET_VIEW` rules (preferred — see
the status pill in the entry form).

### Library UI

The Library tab groups entries **by rule type** with collapsible
sections. Each section header shows the rule type name and entry
count; click to expand/collapse.

- **Read-only detail modal.** Click any library card to open a
  detail modal showing all fields (name, category, description,
  rationale, rule type, rule text, source URL, color, criticality).
  The modal is view-only — use the Edit button to switch to the
  entry form.
- **Legacy / restricted warnings.** Cards and the Apply modal show
  inline warnings for legacy rule types:
  - `OS_REGEX` / `OPERATING_SYSTEM` — yellow badge: "Legacy —
    prefer GLOBAL_ASSET_VIEW"
  - `GROOVY` — red badge: "Restricted — backend enablement required"

## Workflow

```
   ┌────────────────────────────┐
   │  136 built-ins shipped      │
   │  (LIBRARY_BUILTINS in      │
   │   app/library_seed.py)     │
   └─────────────┬──────────────┘
                 │  init_db() seeds + refreshes
                 ▼
   ┌────────────────────────────┐
   │  tag_library table         │ ◀──── User CRUD (POST/PATCH/DELETE
   │  (built-ins + user rows)   │       /api/library)
   └─────────────┬──────────────┘
                 │  Apply
                 ▼
   ┌────────────────────────────┐
   │  Validate against          │
   │  app.tag_validation        │
   │  (same rules as direct     │
   │   tag CRUD)                │
   └─────────────┬──────────────┘
                 │
                 ▼
   ┌────────────────────────────┐
   │  QualysClient.create_tag   │
   │  → destination Qualys env  │
   └─────────────┬──────────────┘
                 │  upsert local + audit row
                 ▼
   ┌────────────────────────────┐
   │  tag_library_applied       │  audit log of every Apply
   └────────────────────────────┘
```

## Apply

1. On the **Tag Library** card on the Tags tab, find the entry
   you want to apply and click **Apply…**.
2. The modal asks for:
   - **Destination credential** — picked from the credentials vault
   - **Rename on destination (optional)** — handy if a tag with
     the source name already exists in the destination
   - **Parent tag id (optional)** — tag ids don't transfer between
     environments
   - **Per-apply overrides** (collapsible): rule_text, color,
     criticality. Useful when one customer's IP ranges differ from
     the library entry's defaults but you don't want to fork the
     entry permanently.
3. **Test on Qualys** runs the same evaluate-rule preview the Phase 3
   tag form exposes — Qualys returns an asset-match count so you can
   see what the rule will hit before committing. If your tenant
   doesn't expose the preview endpoint the button gracefully
   degrades to "client-side validation only".
4. **Apply** creates the tag, refreshes the local `tags` table from
   the destination, and appends an audit row.

## Hide vs delete

- **User entries** delete cleanly via `DELETE /api/library/<id>`.
- **Built-ins** can't be deleted — `DELETE` on a built-in just sets
  `is_hidden=1`. The next `init_db()` re-seeds the built-in but
  preserves the hidden flag, so the entry stays out of the default
  view across upgrades.
- **Unhide** flips `is_hidden=0` (toggle "Show hidden" on the
  library card to see hidden entries first).

## Cloning a built-in

Click **Clone** on a built-in row to copy it into an editable user
entry. The original built-in is unchanged. Useful for "this pattern
is 90% right, but I need to tweak the rule_text for our tenant."

## Apply audit

Every successful Apply records:
- which library entry was used
- destination credential id
- destination platform (US1, EU1, …)
- the new Qualys tag id
- timestamp

Available via:
- **Apply History** button on the library card → modal with all
  applies, newest first
- `GET /api/library/applies` — the global audit
- `GET /api/library/<id>/applies` — audit filtered to one entry

## Adding new entries

Click **+ New entry** on the library card. The form covers:

| Field | Notes |
|---|---|
| Name | Required |
| Category | Free-text; populates the category filter chips |
| Description | One-liner shown on the card |
| Rationale | Paragraph shown on the apply review screen — explain the *why* |
| Source URL | Qualys doc, internal wiki, RFC, etc. |
| Suggested parent | Human-readable name; resolved at apply time |
| Rule type | Same canonical list as the direct tag form, with status pills (legacy / restricted) |
| Rule text | Same per-type help as the direct tag form |
| Color, Criticality | Standard tag fields |

Validation runs the same `app.tag_validation.validate_tag_payload`
the direct tag form uses — bad rules are caught at create time,
not at apply time.

## API reference

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/api/library` | List entries (filters: `category`, `q`, `include_hidden`) |
| `GET`  | `/api/library/<id>` | Single entry detail |
| `POST` | `/api/library` | Create user entry |
| `PATCH` | `/api/library/<id>` | Edit user entry (built-ins refuse with 403) |
| `DELETE` | `/api/library/<id>` | Delete user entry / hide built-in |
| `POST` | `/api/library/<id>/unhide` | Restore a hidden built-in |
| `POST` | `/api/library/<id>/clone` | Copy entry into an editable user copy |
| `POST` | `/api/library/<id>/apply` | Apply to a destination Qualys env |
| `GET`  | `/api/library/<id>/applies` | Apply history for this entry |
| `GET`  | `/api/library/applies` | Apply audit across every entry |

Bodies and responses are documented in the OpenAPI spec at
`/api/docs/openapi.json`.

## Migrations

The `tag_library` and `tag_library_applied` tables ship in
`_SCHEMA_SQL` with idempotent `CREATE IF NOT EXISTS`. Existing
DBs pick them up on the next `init_db()` along with the built-in
seed.
