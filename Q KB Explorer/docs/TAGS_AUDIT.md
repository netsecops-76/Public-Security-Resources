# Tags — Subscription Audit

Phase 5 of the Tags build. A read-only inventory analysis layer
over the locally cached `tags` table that surfaces hierarchy /
naming / classification issues so the operator can clean them up
before they bite Qualys or downstream consumers.

The audit makes **no API calls to Qualys** and never modifies the
local tag rows. It runs against whatever's currently in the local
DB — sync first if you want fresh findings.

## When to use it

- **Before a tenant audit / compliance review** — find naming
  collisions, orphaned references, and overrides that need
  documentation
- **After a bulk tag import or library apply spree** — confirm
  nothing went sideways
- **Routine hygiene** on a cadence (monthly is plenty for most
  subscriptions)
- **Onboarding a new Qualys subscription** — sync once, run audit,
  see what shape the existing taxonomy is in before adding to it

## Severity levels

| Severity | What it means |
|----------|---------------|
| **error** | Already broken or guaranteed to fail at write time. Cycles, depth > 8, orphaned parent references. Fix these first. |
| **warn** | Likely a problem; an operator should review. Duplicate names, identical rule text on multiple tags, very wide root branches. |
| **info** | Awareness only, no action implied. Manual classification / editability overrides — useful for "what decisions have I made" review. |

The Audit card on the Tags tab shows a severity-coloured summary
at the top (`4 errors · 12 warnings · 3 info across 1,200 tags`)
and groups findings under collapsible per-rule headers, severity
order: errors first, then warns, then infos.

## Rules shipped

### Hierarchy

| Rule ID | Severity | What it catches |
|---------|----------|---|
| `HIERARCHY_ORPHAN` | error | `parent_tag_id` points at a tag that doesn't exist locally. Could be a stale sync — re-sync first. If the parent really is gone in Qualys, re-parent or delete the orphan. |
| `HIERARCHY_CYCLE` | error | Circular parent chain (A → B → C → A). Always operator error somewhere. Remove `parentTagId` on one of the tags in the loop to break it. |
| `HIERARCHY_TOO_DEEP` | error | Chain depth > 8 (Qualys's documented limit). Flatten by re-parenting one of the intermediate tags directly under the root. |
| `HIERARCHY_WIDE_ROOT` | warn | A root tag has 50+ direct children. Beyond that, the Qualys console becomes painful to navigate. Consider intermediate static grouping tags (by env / business unit / asset class). |

### Naming

| Rule ID | Severity | What it catches |
|---------|----------|---|
| `NAMING_EMPTY` | error | Name is blank. Should never happen — Qualys rejects it. Indicates a sync issue. |
| `NAMING_WHITESPACE` | warn | Leading or trailing whitespace in the name. Qualys console searches don't always strip it. Edit + trim. |
| `NAMING_TOO_LONG` | error | > 255 chars (Qualys hard limit). Already broken if it slipped past upstream validation. |
| `NAMING_LONG` | warn | > 80 chars. Gets truncated in many Qualys console views. |
| `NAMING_SHORT` | warn | < 3 chars. Hard to search for, easy to collide. |
| `NAMING_DUPLICATE` | warn | Two or more tags with the same name (case-insensitive). One finding per group member, with `refs` carrying the colliding sibling ids so the UI can render "collides with N other tags" without N fanout. |

### Rule text

| Rule ID | Severity | What it catches |
|---------|----------|---|
| `DUPLICATE_RULE` | warn | Two or more tags share an identical `(rule_type, rule_text)` pair. Often unintentional duplication. If both exist for a reason, leave a description explaining the difference; otherwise consolidate. STATIC / ASSET_GROUP / TAG_SET tags are excluded since empty `rule_text` is expected. |

### Override awareness

| Rule ID | Severity | What it catches |
|---------|----------|---|
| `CLASSIFICATION_OVERRIDE` | info | Tag has a manual user/system classification override. Surfaces "what decisions have I made" — useful for handover or post-mortem review. |
| `EDITABILITY_OVERRIDE` | info | Same idea for the editability axis (Force Editable / Force Locked). |

## Workflow

1. Open the Tags tab, scroll to the **Tag Audit** card.
2. Click **Run audit**. Before any checks execute, the UI shows
   **explanatory text** describing what each audit check does so the
   operator knows what to expect.
3. The backend pipes every tag through `_apply_tag_overrides` (so
   the audit sees the same effective `is_user_created` /
   `is_editable` values the rest of the app reports) and runs each
   rule in turn.
4. **Clean-state display.** If the audit finds no issues, the UI
   lists every check that passed along with a brief explanation of
   what each check looked for — confirming to the operator that
   nothing was skipped, rather than showing an empty page.
5. **Duplicate finding clusters.** For `NAMING_DUPLICATE` and
   `DUPLICATE_RULE` findings, related tags are grouped into a
   single card showing the shared name or rule. Each card contains
   the full tag cards (same layout as the Browse tab), and clicking
   any tag card opens the tag detail modal. A **rule description**
   at the top of each finding group explains why this is flagged.
6. Click any tag id / name in a finding to open the tag detail
   modal — fix from there if you want, then re-run.
7. **Export CSV** for offline review or to push findings into a
   ticketing system.

### Migration pre-check

When the user opens the **Migrate** modal (from Browse tab or
Migration card), an audit pre-check runs automatically. If the
audit surfaces any findings for the tags being migrated, the modal
shows a warning with two options:

- **Review in Audit tab** — navigates to the Audit card with the
  relevant findings highlighted.
- **Ignore and proceed** — continues the migration despite the
  findings.

## Best-practice rule-type guidance

Independent of the audit findings, the tag form (Phase 3) and
library entry form (Phase 4) carry **rule-type status pills**
that guide operators away from legacy or restricted rule types
when authoring new tags. Per the Qualys docs:

- `OS_REGEX` and `OPERATING_SYSTEM` → **legacy.** Yellow callout
  pointing at `GLOBAL_ASSET_VIEW` as the recommended replacement
  (better performance, CSAM compatible, survives Qualys OS-string
  normalisation changes). `ASSET_INVENTORY` is itself now
  considered legacy — prefer `GLOBAL_ASSET_VIEW`.
- `GROOVY` → **restricted.** Red callout explaining backend
  enablement is required. There's no public Qualys endpoint that
  reports whether GROOVY is enabled for a subscription, so
  **Test on Qualys** is the ground-truth check — the
  `/qps/rest/2.0/evaluate/am/tag` endpoint will reject if your
  subscription doesn't accept GROOVY rules.

These show up as **warnings** (not errors) in
`/api/tags/validate` so existing legacy tags can still be edited;
new tags written to those types just get the inline guidance.

## API reference

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/tags/audit` | Run every rule, return `{summary, groups, findings}` |
| `GET` | `/api/tags/audit/<rule_id>` | Findings for a single rule (e.g. `NAMING_DUPLICATE`) |
| `GET` | `/api/tags/audit.csv` | Flat findings export (severity, rule_id, tag_id, name, message, hint, refs) |

`run_audit` returns the same payload the API exposes:

```json
{
  "summary": {
    "error": 4, "warn": 12, "info": 3, "total": 19, "tag_count": 1200
  },
  "groups": [
    {
      "rule_id": "HIERARCHY_ORPHAN",
      "severity": "error",
      "count": 2,
      "findings": [
        {
          "rule_id": "HIERARCHY_ORPHAN",
          "severity": "error",
          "tag_id": 12345,
          "name": "Production EU",
          "message": "Parent tag id 9999 not found in local DB",
          "hint": "Re-sync to make sure local copy is current. If the parent was deleted in Qualys, re-parent or remove this tag.",
          "refs": [9999]
        }
      ]
    }
  ],
  "findings": [...]
}
```

Groups are ordered: errors first, then warns, then infos;
alphabetical within a severity bucket.

## Adding new rules

Each rule is a pure function in `app/tag_audit.py`:

```python
def rule_my_new_check(tags: list[dict]) -> list[dict]:
    out = []
    for t in tags:
        if some_condition(t):
            out.append(_f(
                "MY_NEW_CHECK",         # stable rule_id
                "warn",                 # severity
                t["tag_id"], t.get("name"),
                "Human-readable message",
                hint="Optional remediation guidance",
                refs=[other_tag_id, ...],  # optional related ids
            ))
    return out
```

Add the function to the `RULES` tuple at the bottom of the
module. The aggregator picks it up automatically. Add tests in
`tests/test_app.py` modelled on the existing audit tests
(`test_audit_*`). An exception in any one rule is caught by the
aggregator and doesn't kill the whole report.

## Why no automatic remediation

The audit deliberately doesn't fix anything — it's read-only by
design. Reasons:

1. **Auditability.** Operators can review the findings, decide
   the remediation, and apply via the standard tag CRUD path
   (Phase 3). Every change has an audit trail in the sync log.
2. **Cycles + orphans need human judgement.** "Which tag in the
   loop should lose its parent?" isn't algorithmically obvious.
3. **Duplicates don't always mean delete one.** Two tags with the
   same name (or rule) can coexist for legitimate reasons —
   different parents, different RBAC scopes. The audit surfaces;
   the human decides.

A future "auto-fix safe findings" mode (e.g. trim leading/trailing
whitespace from names) is on the roadmap but not in this release.
