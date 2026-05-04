"""
Q KB Explorer — Tag subscription audit (Phase 5)
Built by netsecops-76

Read-only analysis layer over the locally cached `tags` table.
Surfaces hierarchy / naming / classification issues so the operator
can clean them up before they bite — broken parent refs, depth limit
violations, duplicate names, duplicate rule logic, suspiciously wide
root branches, and overrides worth reviewing.

Each rule is a pure function from a list of tag rows → list of
finding dicts. Severities:
  * error  — already broken or guaranteed to fail at write time
             (cycle, orphan, depth > Qualys's hard limit)
  * warn   — likely a problem; an operator should review
             (duplicate names, identical rule text on multiple tags,
              very wide root branches)
  * info   — awareness only, no action implied
             (classification / editability overrides set)

Findings carry a stable ``rule_id`` so the UI can group them and
the operator can mute a specific check across audits in the future
(not implemented yet — Phase 5 ships read-only findings).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

# Qualys's documented tag hierarchy depth limit. Tags can nest up to
# 8 nodes deep (root → 7 levels of children). Going past this works
# locally but Qualys rejects it.
MAX_HIERARCHY_DEPTH = 8

# Practical thresholds for the soft warnings. Tunable; placed at
# module scope so a future "audit settings" UI can override them.
WIDE_ROOT_DIRECT_CHILDREN = 50
NAME_RECOMMENDED_MAX = 80
NAME_HARD_MAX = 255
NAME_RECOMMENDED_MIN = 3


def _f(rule_id: str, severity: str, tag_id: int | None, name: str | None,
       message: str, *, hint: str | None = None,
       refs: list[int] | None = None, tag: dict | None = None) -> dict:
    """Construct a finding dict with the standard shape so the UI
    doesn't need per-rule rendering branches."""
    result = {
        "rule_id": rule_id,
        "severity": severity,        # 'error' | 'warn' | 'info'
        "tag_id": tag_id,
        "name": name,
        "message": message,
        "hint": hint,
        "refs": refs or [],
    }
    # Include tag metadata so the UI can render full cards for duplicates
    if tag:
        result["color"] = tag.get("color")
        result["rule_type"] = tag.get("rule_type")
        result["rule_text"] = tag.get("rule_text")
        result["description"] = tag.get("description")
        result["is_user_created"] = tag.get("is_user_created")
        result["reserved_type"] = tag.get("reserved_type")
        result["parent_name"] = tag.get("parent_name")
    return result


# ── Hierarchy rules ─────────────────────────────────────────────────────

def rule_orphan_parent(tags: list[dict]) -> list[dict]:
    """parent_tag_id points at a tag that doesn't exist locally.

    Could be benign (parent simply hasn't been synced yet) or a real
    orphan (parent was deleted in Qualys but the child wasn't).
    Either way the operator should know.
    """
    by_id = {t["tag_id"]: t for t in tags}
    out = []
    for t in tags:
        p = t.get("parent_tag_id")
        if p and p not in by_id:
            out.append(_f(
                "HIERARCHY_ORPHAN", "error",
                t["tag_id"], t.get("name"),
                f"Parent tag id {p} not found in local DB",
                hint=("Re-sync to make sure local copy is current. If the "
                      "parent was deleted in Qualys, re-parent or remove "
                      "this tag."),
                refs=[p],
            ))
    return out


def rule_cycle(tags: list[dict]) -> list[dict]:
    """Walk parent pointers to detect cycles (A → B → A).

    Each tag's ancestor chain is followed up to MAX_HIERARCHY_DEPTH
    + 1; if we ever loop back to the starting tag, that's a cycle.
    """
    by_id = {t["tag_id"]: t for t in tags}
    out = []
    seen_in_cycle: set[int] = set()
    for t in tags:
        if t["tag_id"] in seen_in_cycle:
            continue
        chain: list[int] = []
        current = t.get("parent_tag_id")
        while current and current in by_id:
            if current in chain or current == t["tag_id"]:
                # Cycle. Report against this tag and remember every
                # member so we don't double-flag from each side.
                out.append(_f(
                    "HIERARCHY_CYCLE", "error",
                    t["tag_id"], t.get("name"),
                    f"Cycle in parent chain: {' → '.join(str(x) for x in [t['tag_id']] + chain + [current])}",
                    hint="Remove parentTagId on one of the tags in the loop.",
                    refs=chain + [current],
                ))
                seen_in_cycle.update(chain)
                seen_in_cycle.add(t["tag_id"])
                break
            chain.append(current)
            current = by_id[current].get("parent_tag_id")
            if len(chain) > MAX_HIERARCHY_DEPTH * 2:
                # Safety bail — chain is way past the depth limit
                # without looping back; depth-limit rule will catch it.
                break
    return out


def rule_depth_limit(tags: list[dict]) -> list[dict]:
    """Walk the ancestor chain and flag anything deeper than
    MAX_HIERARCHY_DEPTH. Skips chains that the cycle rule already
    caught (cycle = effectively infinite depth)."""
    by_id = {t["tag_id"]: t for t in tags}
    out = []
    for t in tags:
        depth = 1
        current = t.get("parent_tag_id")
        seen = {t["tag_id"]}
        while current and current in by_id and current not in seen:
            depth += 1
            seen.add(current)
            current = by_id[current].get("parent_tag_id")
            if depth > MAX_HIERARCHY_DEPTH * 2:
                break  # cycle — let rule_cycle handle it
        if depth > MAX_HIERARCHY_DEPTH:
            out.append(_f(
                "HIERARCHY_TOO_DEEP", "error",
                t["tag_id"], t.get("name"),
                f"Hierarchy depth {depth} exceeds Qualys limit of {MAX_HIERARCHY_DEPTH}",
                hint=("Flatten by re-parenting one of the intermediate "
                      "tags directly under the root."),
            ))
    return out


def rule_wide_root(tags: list[dict]) -> list[dict]:
    """Root tags (parent_tag_id = NULL/0) with too many direct
    children. Beyond ~50 the Qualys console becomes hard to navigate
    and the operator usually wants intermediate organizer tags."""
    children_of: dict[int, int] = defaultdict(int)
    for t in tags:
        p = t.get("parent_tag_id")
        if p:
            children_of[p] += 1
    out = []
    for t in tags:
        if t.get("parent_tag_id"):
            continue  # not a root
        c = children_of.get(t["tag_id"], 0)
        if c >= WIDE_ROOT_DIRECT_CHILDREN:
            out.append(_f(
                "HIERARCHY_WIDE_ROOT", "warn",
                t["tag_id"], t.get("name"),
                f"Root tag has {c} direct children",
                hint=("Consider grouping under intermediate organizer tags "
                      "by environment, business unit, or asset class."),
            ))
    return out


# ── Naming rules ────────────────────────────────────────────────────────

def rule_name_whitespace(tags: list[dict]) -> list[dict]:
    """Leading or trailing whitespace in a tag name. Always a typo,
    and Qualys console searches don't always strip it."""
    out = []
    for t in tags:
        name = t.get("name") or ""
        if name and name != name.strip():
            out.append(_f(
                "NAMING_WHITESPACE", "warn",
                t["tag_id"], name,
                "Name has leading or trailing whitespace",
                hint='Edit the tag and trim spaces around the name.',
            ))
    return out


def rule_name_length(tags: list[dict]) -> list[dict]:
    """Names that are too long or too short to be useful."""
    out = []
    for t in tags:
        name = (t.get("name") or "").strip()
        if not name:
            out.append(_f(
                "NAMING_EMPTY", "error",
                t["tag_id"], None,
                "Tag has no name",
            ))
            continue
        if len(name) > NAME_HARD_MAX:
            out.append(_f(
                "NAMING_TOO_LONG", "error",
                t["tag_id"], name,
                f"Name length {len(name)} exceeds Qualys limit of {NAME_HARD_MAX}",
            ))
        elif len(name) > NAME_RECOMMENDED_MAX:
            out.append(_f(
                "NAMING_LONG", "warn",
                t["tag_id"], name,
                f"Name is {len(name)} chars — gets truncated in many "
                f"Qualys console views (recommend ≤{NAME_RECOMMENDED_MAX}).",
            ))
        elif len(name) < NAME_RECOMMENDED_MIN:
            out.append(_f(
                "NAMING_SHORT", "warn",
                t["tag_id"], name,
                f"Name is only {len(name)} characters",
                hint="Short names collide easily and are hard to search for.",
            ))
    return out


def rule_name_duplicate(tags: list[dict]) -> list[dict]:
    """Two or more tags with the same name (case-insensitive).

    Reported once per duplicate group with refs holding the other
    tag ids in the group, so the UI can show "X collides with N
    other tags" without fanning out N findings.
    """
    groups: dict[str, list[dict]] = defaultdict(list)
    for t in tags:
        name = (t.get("name") or "").strip().lower()
        if name:
            groups[name].append(t)
    out = []
    for name, members in groups.items():
        if len(members) < 2:
            continue
        ids = sorted(m["tag_id"] for m in members)
        for m in members:
            others = [i for i in ids if i != m["tag_id"]]
            out.append(_f(
                "NAMING_DUPLICATE", "warn",
                m["tag_id"], m.get("name"),
                f'Name collides with {len(others)} other tag(s) (case-insensitive)',
                hint="Disambiguate with a prefix or merge the duplicates.",
                refs=others,
                tag=m,
            ))
    return out


# ── Rule-text duplication ──────────────────────────────────────────────

def rule_duplicate_rule_text(tags: list[dict]) -> list[dict]:
    """Identical (rule_type, rule_text) pairs — likely the same intent
    expressed twice with different names. Skip STATIC rules (no
    rule_text) and skip empty rule_text values that just mean
    'organizer'."""
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for t in tags:
        rt = (t.get("rule_type") or "").upper()
        rx = (t.get("rule_text") or "").strip()
        if not rx or rt in ("STATIC", "ASSET_GROUP", "TAG_SET"):
            continue
        groups[(rt, rx)].append(t)
    out = []
    for (rt, rx), members in groups.items():
        if len(members) < 2:
            continue
        ids = sorted(m["tag_id"] for m in members)
        sample = (rx[:60] + "…") if len(rx) > 60 else rx
        for m in members:
            others = [i for i in ids if i != m["tag_id"]]
            out.append(_f(
                "DUPLICATE_RULE", "warn",
                m["tag_id"], m.get("name"),
                f'Identical {rt} rule shared with {len(others)} other tag(s): "{sample}"',
                hint="If both tags exist for a reason, leave a description "
                     "explaining the difference; otherwise consolidate.",
                refs=others,
                tag=m,
            ))
    return out


# ── Override / classification awareness ───────────────────────────────

def rule_classification_override(tags: list[dict]) -> list[dict]:
    """Surface tags where the operator has manually overridden the
    auto user/system classification. Info-only — useful for "what
    decisions have I made" review."""
    out = []
    for t in tags:
        ov = (t.get("classification_override") or "").strip().lower()
        if ov in ("user", "system"):
            auto = "user" if t.get("is_user_created_auto") else "system"
            out.append(_f(
                "CLASSIFICATION_OVERRIDE", "info",
                t["tag_id"], t.get("name"),
                f"Classification override: auto={auto}, override={ov}",
            ))
    return out


def rule_editability_override(tags: list[dict]) -> list[dict]:
    """Same idea for the editability axis."""
    out = []
    for t in tags:
        ov = (t.get("editability_override") or "").strip().lower()
        if ov in ("editable", "locked"):
            auto = "editable" if t.get("is_editable_auto") else "locked"
            out.append(_f(
                "EDITABILITY_OVERRIDE", "info",
                t["tag_id"], t.get("name"),
                f"Editability override: auto={auto}, override={ov}",
            ))
    return out


# ── Aggregator ──────────────────────────────────────────────────────────

# Order matters: the UI renders rules in the order they appear here,
# severity-first within the dashboard summary. Keep error rules first
# so they bubble to the top.
RULES = (
    rule_orphan_parent,
    rule_cycle,
    rule_depth_limit,
    rule_name_length,
    rule_name_whitespace,
    rule_name_duplicate,
    rule_wide_root,
    rule_duplicate_rule_text,
    rule_classification_override,
    rule_editability_override,
)


def run_audit(tags: Iterable[dict]) -> dict:
    """Run every rule against the supplied tag rows and return a
    grouped + summarised result.

    Output shape:
      {
        "summary": {"error": N, "warn": N, "info": N, "total": N,
                    "tag_count": N},
        "groups": [
            {"rule_id": "HIERARCHY_ORPHAN", "severity": "error",
             "count": 2, "findings": [...]},
            ...
        ],
        "findings": [...]      // flat list, same content for export
      }
    """
    rows = list(tags)
    grouped: dict[str, list[dict]] = defaultdict(list)
    rule_severity: dict[str, str] = {}
    flat: list[dict] = []
    for fn in RULES:
        try:
            for finding in fn(rows):
                rid = finding["rule_id"]
                grouped[rid].append(finding)
                # Worst-severity-wins per rule_id (errors > warn > info).
                # Keeps the group header severity meaningful when a rule
                # emits mixed severities.
                rule_severity[rid] = _severer(rule_severity.get(rid), finding["severity"])
                flat.append(finding)
        except Exception:
            # An audit rule blowing up shouldn't kill the whole report.
            continue

    sev_count = {"error": 0, "warn": 0, "info": 0}
    for f in flat:
        s = f.get("severity", "info")
        sev_count[s] = sev_count.get(s, 0) + 1

    # Order groups by severity (errors first), then by rule_id alphabetically
    # within a severity bucket so the UI is stable between runs.
    sev_rank = {"error": 0, "warn": 1, "info": 2}
    groups = []
    for rid in sorted(grouped.keys(),
                      key=lambda r: (sev_rank.get(rule_severity.get(r), 9), r)):
        members = grouped[rid]
        groups.append({
            "rule_id": rid,
            "severity": rule_severity.get(rid, "info"),
            "count": len(members),
            "findings": members,
        })
    return {
        "summary": {
            **sev_count,
            "total": len(flat),
            "tag_count": len(rows),
        },
        "groups": groups,
        "findings": flat,
    }


def _severer(current: str | None, candidate: str) -> str:
    """Return the more severe of two severity labels."""
    rank = {"error": 0, "warn": 1, "info": 2}
    if current is None:
        return candidate
    return current if rank.get(current, 9) <= rank.get(candidate, 9) else candidate
