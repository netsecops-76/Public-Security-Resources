"""
Q KB Explorer — Tag rule validation
Built by netsecops-76

Pre-flight validation of Asset Tag definitions before they hit
Qualys. Same logic runs on the client (immediate feedback while the
operator types) and on the server (defense in depth — a misbehaving
or out-of-date frontend can't push bad data through).

The goal is to catch the obvious failure modes at the lowest cost:

  * Missing required fields per rule type
  * ruleText syntax issues (regex won't compile, CIDRs malformed,
    port range nonsense)
  * Out-of-range numbers (criticality), bad color hex, name length
  * Wholly unknown rule types

Qualys still has the final word at create/update time — this layer
just shortens the feedback loop and keeps avoidable HTTP round-trips
off the rate-limit budget.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# Canonical rule types the form / dropdown supports. Mirrors
# database.TAG_RULE_TYPES_KNOWN intentionally — we don't import it
# here to keep this module dependency-free for testing.
RULE_TYPES = (
    "STATIC",
    "NAME_CONTAINS",
    "NETWORK_RANGE",
    "NETWORK_RANGE_ENHANCED",
    "OS_REGEX",
    "OPERATING_SYSTEM",
    "INSTALLED_SOFTWARE",
    "OPEN_PORTS",
    "VULN_EXIST",
    "VULN_DETECTION",
    "ASSET_SEARCH",
    "ASSET_GROUP",
    "ASSET_INVENTORY",
    "GLOBAL_ASSET_VIEW",
    "CLOUD_ASSET",
    "BUSINESS_INFORMATION",
    "BUSINESS_INFO",
    "GROOVY",
    "TAG_SET",
)

# Rule types that don't require any ruleText — STATIC tags are
# manually assigned, the others are evaluated server-side via
# Qualys-managed inventory queries that don't need operator input.
_RULE_TEXT_OPTIONAL = {"STATIC", "ASSET_GROUP", "TAG_SET"}

# Per-type help text shown next to the ruleText field. Kept short
# enough to fit under an input — the form links out to the Qualys
# docs for the long-form examples.
RULE_TEXT_HELP = {
    "STATIC": "No rule needed — assets are assigned manually in the Qualys console.",
    "NAME_CONTAINS": "Substring matched against the asset DNS or NetBIOS name (case-insensitive).",
    "NETWORK_RANGE": 'Comma-separated IPv4 CIDRs or single IPs (e.g. "10.0.0.0/8, 192.168.1.10").',
    "NETWORK_RANGE_ENHANCED": "CIDR syntax with extended range support — see Qualys docs.",
    "OS_REGEX": 'Java regex matched against the asset OS string (e.g. "^Windows.*Server.*"). Legacy — prefer ASSET_INVENTORY.',
    "OPERATING_SYSTEM": "Exact OS name as Qualys reports it. Legacy — prefer ASSET_INVENTORY.",
    "INSTALLED_SOFTWARE": 'Software name pattern (e.g. "Apache HTTP Server" or wildcards).',
    "OPEN_PORTS": 'Comma-separated ports or ranges (e.g. "22, 80, 443, 8080-8090").',
    "VULN_EXIST": "QID number — assets with this QID detected get tagged.",
    "VULN_DETECTION": "QID detection rule — similar to VULN_EXIST with extended match options.",
    "ASSET_SEARCH": "Qualys asset search query language (QQL).",
    "ASSET_GROUP": "Qualys asset group id — Qualys handles the membership.",
    "ASSET_INVENTORY": "Asset inventory query (CSAM). Legacy — replaced by GLOBAL_ASSET_VIEW.",
    "GLOBAL_ASSET_VIEW": "Global AssetView query (preferred) — CSAM-compatible, replaces ASSET_INVENTORY.",
    "CLOUD_ASSET": "Cloud asset attribute query (AWS, Azure, GCP, OCI).",
    "BUSINESS_INFORMATION": "Business-information field expression.",
    "BUSINESS_INFO": "Business-info field expression (alias).",
    "GROOVY": "Groovy script — full programmatic access to the asset object.",
    "TAG_SET": "Membership of a set of other tag ids.",
}

# Rough length cap. Qualys accepts up to 255 chars on names but
# anything over ~80 is unwieldy in the UI and most templates.
_NAME_MAX = 255
_NAME_RECOMMENDED_MAX = 80
_DESCRIPTION_MAX = 2000


# Per-rule-type status metadata. Lets the form steer operators toward
# current best practices without locking them out of legacy types
# entirely (existing tags still need to be editable).
#
# Status values:
#   "preferred"  — recommended for new tags
#   "supported"  — works, no concerns
#   "legacy"     — still supported by Qualys but superseded by a
#                  newer rule type; operator should consider migrating
#   "restricted" — Qualys has the rule type but it's gated behind
#                  per-subscription enablement (e.g. GROOVY needs
#                  Qualys support to turn on). Operator can still
#                  build it, but Test on Qualys is the only way to
#                  know if their subscription accepts it.
RULE_TYPE_STATUS = {
    "OS_REGEX": {
        "status": "legacy",
        "replacement": "GLOBAL_ASSET_VIEW",
        "notes": (
            "OS_REGEX is still supported but no longer best practice. "
            "Qualys recommends GLOBAL_ASSET_VIEW rules for OS targeting — "
            "they perform better and integrate with CSAM."
        ),
    },
    "OPERATING_SYSTEM": {
        "status": "legacy",
        "replacement": "GLOBAL_ASSET_VIEW",
        "notes": (
            "Exact-match OS_NAME rules predate GLOBAL_ASSET_VIEW queries. "
            "Prefer GLOBAL_ASSET_VIEW for new tags so the rule survives "
            "OS-string normalisation changes in Qualys."
        ),
    },
    "ASSET_INVENTORY": {
        "status": "legacy",
        "replacement": "GLOBAL_ASSET_VIEW",
        "notes": (
            "ASSET_INVENTORY has been replaced by GLOBAL_ASSET_VIEW. "
            "Existing rules still work but new tags should use "
            "GLOBAL_ASSET_VIEW for full CSAM compatibility."
        ),
    },
    "GROOVY": {
        "status": "restricted",
        "notes": (
            "GROOVY rule support is disabled by default in most Qualys "
            "subscriptions and must be enabled by Qualys support. Use "
            "the Test on Qualys button to confirm your subscription "
            "accepts it before relying on this rule type."
        ),
    },
}


@dataclass
class ValidationResult:
    """Per-field error map plus a flat ok flag for quick gating."""

    ok: bool = True
    # Map of field name → list of human-readable error messages. The
    # frontend renders these next to the input. List instead of single
    # message because a single field can fail multiple rules at once
    # (e.g. ruleText empty AND format wrong wouldn't both fire, but
    # color could be both blank and badly formatted in odd cases).
    errors: dict[str, list[str]] = field(default_factory=dict)
    # Soft non-blocking advisories — name longer than recommended,
    # rule type uncommon for a non-power-user, etc.
    warnings: dict[str, list[str]] = field(default_factory=dict)

    def fail(self, field_name: str, msg: str) -> None:
        self.errors.setdefault(field_name, []).append(msg)
        self.ok = False

    def warn(self, field_name: str, msg: str) -> None:
        self.warnings.setdefault(field_name, []).append(msg)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "errors": self.errors, "warnings": self.warnings}


def validate_tag_payload(payload: dict) -> ValidationResult:
    """Validate a tag definition before it goes to Qualys.

    Accepts the same dict shape the create_tag / update_tag client
    methods consume (Qualys QPS Tag fields). Returns a ValidationResult
    that tells the caller exactly which fields failed and why, so the
    frontend can light up the right inputs.
    """
    r = ValidationResult()
    if not isinstance(payload, dict):
        r.fail("_root", "Payload must be a JSON object")
        return r

    _validate_name(payload, r)
    _validate_color(payload, r)
    _validate_criticality(payload, r)
    _validate_description(payload, r)
    _validate_rule_type_and_text(payload, r)
    _validate_parent(payload, r)
    return r


# ── Field-level validators ──────────────────────────────────────────────

def _validate_name(payload: dict, r: ValidationResult) -> None:
    name = (payload.get("name") or "").strip()
    if not name:
        r.fail("name", "Required")
        return
    if len(name) > _NAME_MAX:
        r.fail("name", f"Too long — Qualys max is {_NAME_MAX} characters")
    elif len(name) > _NAME_RECOMMENDED_MAX:
        r.warn("name", f"Longer than the recommended {_NAME_RECOMMENDED_MAX} characters — "
                       "tags with long names get truncated in many Qualys views.")


_HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

def _validate_color(payload: dict, r: ValidationResult) -> None:
    color = payload.get("color")
    if color in (None, ""):
        return  # color is optional
    if not isinstance(color, str) or not _HEX_RE.match(color):
        r.fail("color", 'Must be a 6-digit hex like "#22c55e".')


def _validate_criticality(payload: dict, r: ValidationResult) -> None:
    crit = payload.get("criticalityScore", payload.get("criticality"))
    if crit in (None, ""):
        return
    try:
        n = int(crit)
    except (TypeError, ValueError):
        r.fail("criticality", "Must be an integer 1-5")
        return
    if n < 1 or n > 5:
        r.fail("criticality", "Must be between 1 and 5")


def _validate_description(payload: dict, r: ValidationResult) -> None:
    desc = payload.get("description")
    if desc and len(str(desc)) > _DESCRIPTION_MAX:
        r.fail("description", f"Too long — keep under {_DESCRIPTION_MAX} characters")


def _validate_parent(payload: dict, r: ValidationResult) -> None:
    parent = payload.get("parentTagId")
    if parent in (None, ""):
        return
    try:
        n = int(parent)
    except (TypeError, ValueError):
        r.fail("parentTagId", "Must be a numeric tag id")
        return
    if n <= 0:
        r.fail("parentTagId", "Tag ids are positive integers")


def _validate_rule_type_and_text(payload: dict, r: ValidationResult) -> None:
    rule_type = payload.get("ruleType")
    rule_text = payload.get("ruleText")

    if not rule_type:
        # Allowed only on edit — caller decides whether to require it.
        # We don't fail here because update_tag may legitimately pass
        # a partial payload that doesn't touch ruleType.
        if rule_text:
            r.fail("ruleType", "Setting a ruleText requires a ruleType")
        return

    if rule_type not in RULE_TYPES:
        r.warn("ruleType", f'"{rule_type}" is not in our known rule-type list. '
                            "Qualys may still accept it; double-check the spelling.")

    # Surface best-practice / availability concerns as warnings (not
    # errors) — caller can save anyway. The form renders these next
    # to the rule-type dropdown so the operator sees them BEFORE
    # they spend time building the rule_text.
    status_info = RULE_TYPE_STATUS.get(rule_type)
    if status_info:
        st = status_info["status"]
        msg = status_info["notes"]
        if status_info.get("replacement"):
            msg += f' Recommended replacement: {status_info["replacement"]}.'
        r.warn("ruleType", f"[{st.upper()}] {msg}")

    needs_text = rule_type not in _RULE_TEXT_OPTIONAL
    if needs_text and not (rule_text and str(rule_text).strip()):
        r.fail("ruleText", f"Rule type {rule_type} requires a ruleText")
        return

    if not rule_text:
        return  # nothing more to syntax-check

    text = str(rule_text).strip()
    if rule_type in ("OS_REGEX",):
        try:
            re.compile(text)
        except re.error as e:
            r.fail("ruleText", f"Invalid regex: {e}")
    elif rule_type == "NETWORK_RANGE":
        _validate_network_range(text, r)
    elif rule_type == "OPEN_PORTS":
        _validate_open_ports(text, r)
    elif rule_type == "VULN_EXIST":
        # ruleText should be a positive integer QID
        try:
            qid = int(text)
            if qid <= 0:
                r.fail("ruleText", "QID must be a positive integer")
        except ValueError:
            r.fail("ruleText", "VULN_EXIST ruleText must be a single QID number")


def _validate_network_range(text: str, r: ValidationResult) -> None:
    """Comma-separated IPv4 CIDRs or single IPs."""
    parts = [p.strip() for p in text.split(",") if p.strip()]
    if not parts:
        r.fail("ruleText", "Provide at least one IP or CIDR")
        return
    for p in parts:
        try:
            # strict=False accepts host-bits-set forms like 10.0.0.1/8
            ipaddress.ip_network(p, strict=False)
        except ValueError as e:
            r.fail("ruleText", f'Bad CIDR or IP "{p}": {e}')


_PORT_RANGE_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")

def _validate_open_ports(text: str, r: ValidationResult) -> None:
    """Comma-separated ports or ranges, e.g. '22, 80, 8080-8090'."""
    parts = [p.strip() for p in text.split(",") if p.strip()]
    if not parts:
        r.fail("ruleText", "Provide at least one port or port range")
        return
    for p in parts:
        if not _PORT_RANGE_RE.match(p):
            r.fail("ruleText", f'Bad port spec "{p}" — use single ports or "low-high" ranges')
            continue
        nums = [int(n) for n in p.split("-")]
        for n in nums:
            if n < 1 or n > 65535:
                r.fail("ruleText", f'Port {n} out of range (1-65535)')
        if len(nums) == 2 and nums[0] > nums[1]:
            r.fail("ruleText", f'Range "{p}" is reversed — low must be <= high')
