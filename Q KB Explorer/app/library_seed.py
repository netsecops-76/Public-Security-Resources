"""
Q KB Explorer — Tag Library built-in seed
Built by netsecops-76

Comprehensive starter set of tag definitions sourced from the Qualys
"Complete Tag List" community document (Colton Pepper, updated May 2023)
plus foundational network/service patterns.

Each entry is a *pattern* — every customer's environment differs.
The operator should review rule_text and adjust before applying.

Adding to this list does not retroactively edit existing rows in a
user's DB; existing built-ins are matched by slug and updated in
place on init_db. Removing an entry from this list will NOT delete
the row from existing DBs (we don't auto-prune to avoid surprising
users who built workflows around an entry we later removed).
"""

# Each entry has:
#   slug             — stable id, snake-case kebabbed
#   name             — display name shown in the library list
#   category         — used for the filter chips
#   description      — one-liner shown on the card
#   rationale        — paragraph shown on Apply review
#   source_url       — Qualys doc, RFC, or wiki link
#   rule_type        — must be one of TAG_RULE_TYPES
#   rule_text        — example value; operator should review before applying
#   color            — hex
#   criticality      — 1 (low) to 5 (urgent)
#   suggested_parent — optional human-readable name of a parent tag

_QUALYS_TAG_DOC = "https://success.qualys.com/support/s/article/000005819"

LIBRARY_BUILTINS = [
    # ─────────────────────────────────────────────────────────────────
    # NETWORK
    # ─────────────────────────────────────────────────────────────────
    {
        "slug": "rfc1918-private-network",
        "name": "RFC 1918 Private Network",
        "category": "Network",
        "description": "All RFC 1918 private IPv4 ranges in one tag.",
        "rationale": (
            "Useful as a parent for sub-tags grouping internal asset zones, "
            "and as a quick negative filter when looking for assets with "
            "public addresses. Update the ruleText if your organisation "
            "uses a subset of these ranges."
        ),
        "source_url": "https://datatracker.ietf.org/doc/html/rfc1918",
        "rule_type": "NETWORK_RANGE",
        "rule_text": "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16",
        "color": "#3b82f6",
        "criticality": 2,
        "suggested_parent": None,
    },
    {
        "slug": "loopback-and-link-local",
        "name": "Loopback / Link-Local",
        "category": "Network",
        "description": "127.0.0.0/8 and 169.254.0.0/16.",
        "rationale": (
            "Surfaces assets being reported with non-routable addresses — "
            "usually an indication of a broken agent registration or an "
            "asset that lost its DHCP lease. Healthy environments have "
            "very few entries here."
        ),
        "source_url": "https://success.qualys.com/discussions/s/article/000005818",
        "rule_type": "NETWORK_RANGE",
        "rule_text": "127.0.0.0/8, 169.254.0.0/16",
        "color": "#94a3b8",
        "criticality": 1,
        "suggested_parent": None,
    },

    # ─────────────────────────────────────────────────────────────────
    # SERVICE PROFILE
    # ─────────────────────────────────────────────────────────────────
    {
        "slug": "web-server-ports",
        "name": "Web server ports open",
        "category": "Service Profile",
        "description": "TCP 80, 443, 8080, 8443, 8000, 8888.",
        "rationale": (
            "Catches assets exposing typical HTTP/HTTPS ports. Pair with "
            "an Internet Facing tag to scope vulnerability prioritisation. "
            "Add or remove ports based on your environment's conventions."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "OPEN_PORTS",
        "rule_text": "80, 443, 8080, 8443, 8000, 8888",
        "color": "#f59e0b",
        "criticality": 3,
        "suggested_parent": None,
    },
    {
        "slug": "database-server-ports",
        "name": "Database server ports open",
        "category": "Service Profile",
        "description": "MSSQL, MySQL, Postgres, MongoDB, Redis, Oracle.",
        "rationale": (
            "Surfaces assets exposing database service ports. Most should "
            "NOT also be on the Internet Facing list — this combination is "
            "often the highest-priority remediation queue. Adjust the port "
            "list to match the database engines actually in use."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "OPEN_PORTS",
        "rule_text": "1433, 3306, 5432, 27017, 6379, 1521",
        "color": "#a855f7",
        "criticality": 4,
        "suggested_parent": None,
    },

    # ─────────────────────────────────────────────────────────────────
    # BUSINESS CONTEXT
    # ─────────────────────────────────────────────────────────────────
    {
        "slug": "manual-business-critical",
        "name": "Business Critical (manual)",
        "category": "Business Context",
        "description": "Static tag — assign assets manually in Qualys.",
        "rationale": (
            "Operator-driven scope tag. Use for crown-jewel assets where "
            "auto-classification rules can't reliably identify the right "
            "set. Pair with PCI / HIPAA / SOX scope tags for compliance "
            "reporting."
        ),
        "source_url": None,
        "rule_type": "STATIC",
        "rule_text": None,
        "color": "#dc2626",
        "criticality": 5,
        "suggested_parent": None,
    },

    # ─────────────────────────────────────────────────────────────────
    # INFORMATIONAL TAGS
    # ─────────────────────────────────────────────────────────────────
    {
        "slug": "info-agent-correlation-used",
        "name": "Agent Correlation Used",
        "category": "Informational",
        "description": "QID 48143 — asset was correlated via Cloud Agent.",
        "rationale": (
            "Identifies assets that were discovered/correlated through the "
            "Qualys Cloud Agent rather than network scanning. Useful for "
            "tracking agent deployment coverage."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "48143",
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-agentless-tracking-errors",
        "name": "Agentless Tracking Errors",
        "category": "Informational",
        "description": "QID 45180 — agentless tracking encountered errors.",
        "rationale": (
            "Surfaces assets where the agentless tracking feature reported "
            "errors. Investigate these to ensure scan coverage is not "
            "being silently degraded."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "45180",
        "color": "#64748b",
        "criticality": 2,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-agentless-tracking-used",
        "name": "Agentless Tracking Used",
        "category": "Informational",
        "description": "QID 45179 — asset uses agentless tracking.",
        "rationale": (
            "Identifies assets using agentless tracking for persistent "
            "identification between scans (without requiring a Cloud Agent)."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "45179",
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-dhcp-enabled",
        "name": "DHCP Enabled",
        "category": "Informational",
        "description": "Asset has DHCP enabled (QID 45099, EnableDHCP = 1).",
        "rationale": (
            "DHCP-enabled assets may change IPs between scans. Important "
            "for understanding scan coverage gaps and agent tracking needs."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <DETECTION>\n"
            "  <QID_LIST><QID>45099</QID></QID_LIST>\n"
            "  <RESULTS>\n"
            "   <SEARCH_TYPE>CONTAINING</SEARCH_TYPE>\n"
            "   <SEARCH_TERM>EnableDHCP = 1</SEARCH_TERM>\n"
            "  </RESULTS>\n"
            " </DETECTION>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-dissolvable-agent-failed",
        "name": "Dissolvable Agent Failed",
        "category": "Informational",
        "description": "QID 90918 — dissolvable agent deployment failed.",
        "rationale": (
            "The dissolvable agent did not complete successfully on this "
            "asset. Investigate — this usually means authenticated scan "
            "data is incomplete."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "90918",
        "color": "#64748b",
        "criticality": 2,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-dissolvable-agent-used",
        "name": "Dissolvable Agent Used",
        "category": "Informational",
        "description": "QID 90821 — dissolvable agent was used for scanning.",
        "rationale": (
            "Tracks which assets are leveraging the dissolvable agent for "
            "deeper authenticated scanning without a persistent agent install."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "90821",
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-firewall-detected",
        "name": "Firewall Detected",
        "category": "Informational",
        "description": "QID 34011 — a host-based firewall was detected.",
        "rationale": (
            "Assets with detected firewalls may have scan interference. "
            "Use for troubleshooting incomplete scan results and verifying "
            "scan policy exceptions are configured properly."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "34011",
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-live-asset",
        "name": "Live Asset",
        "category": "Informational",
        "description": "Asset scanned within last 24 hours (multiple QIDs).",
        "rationale": (
            "Identifies assets confirmed alive in the last day. The rule "
            "checks for host discovery QIDs (70004, 82040, 12230, 90399, "
            "70038, 105296, 105297) within a 1-day window. Adjust DAYS "
            "value for your scan cadence."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <DETECTION>\n"
            "  <QID_LIST>\n"
            "   <QID>70004</QID>\n"
            "   <QID>82040</QID>\n"
            "   <QID>12230</QID>\n"
            "   <QID>90399</QID>\n"
            "   <QID>70038</QID>\n"
            "   <QID>105296</QID>\n"
            "   <QID>105297</QID>\n"
            "  </QID_LIST>\n"
            " </DETECTION>\n"
            " <LAST_SCAN_DATE>\n"
            "  <SEARCH_TYPE>WITHIN</SEARCH_TYPE>\n"
            "  <DAYS>1</DAYS>\n"
            " </LAST_SCAN_DATE>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#22c55e",
        "criticality": 1,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-new-asset",
        "name": "New Asset",
        "category": "Informational",
        "description": "First found within the last 7 days.",
        "rationale": (
            "Surfaces recently discovered assets. Useful for onboarding "
            "workflows and ensuring new assets are quickly assigned to the "
            "correct asset groups and scan policies. Adjust DAYS as needed."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <FIRST_FOUND_DATE>\n"
            "  <SEARCH_TYPE>WITHIN</SEARCH_TYPE>\n"
            "  <DAYS>7</DAYS>\n"
            " </FIRST_FOUND_DATE>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-possible-scan-interference",
        "name": "Possible Scan Interference",
        "category": "Informational",
        "description": "QID 42432 — scan results may be incomplete.",
        "rationale": (
            "Something interfered with the scanner's ability to fully "
            "assess this asset (firewall, IPS, rate limiting, etc.). "
            "Investigate and whitelist scanner IPs where appropriate."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "42432",
        "color": "#f59e0b",
        "criticality": 2,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-scan-time-over-30m",
        "name": "Scan Time (>30m)",
        "category": "Informational",
        "description": "Asset took more than 30 minutes to scan (Groovy).",
        "rationale": (
            "Long scan times can indicate network issues, heavy port "
            "exposure, or assets that need scan policy tuning. Adjust "
            "threshold_minutes in the script for your SLA. Requires "
            "Groovy Scriptlet to be enabled in your subscription."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GROOVY",
        "rule_text": (
            "// Skip testing on non-VM hosts.\n"
            "if(asset.getAssetType()!=Asset.AssetType.HOST) return false;\n"
            "// Tag if scan time for host takes longer than threshold_minutes.\n"
            "threshold_minutes = 30\n"
            "host_scan_time = asset.resultsForQid(45038L);\n"
            "if(host_scan_time == null || host_scan_time.length() <= 16)\n"
            " return false;\n"
            "host_scan_time = host_scan_time.substring(15,host_scan_time.indexOf(' seconds'));\n"
            "host_scan_time = host_scan_time.toInteger();\n"
            "return host_scan_time > (threshold_minutes*60);"
        ),
        "color": "#f59e0b",
        "criticality": 2,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-stale-asset",
        "name": "Stale Asset",
        "category": "Informational",
        "description": "Not scanned and not first-found within 90 days.",
        "rationale": (
            "Assets that haven't been scanned in 90+ days and were not "
            "recently discovered. Candidates for decommissioning or "
            "investigation. Adjust DAYS to match your organization's "
            "stale asset policy."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <LAST_SCAN_DATE>\n"
            "  <SEARCH_TYPE>NOT_WITHIN</SEARCH_TYPE>\n"
            "  <DAYS>90</DAYS>\n"
            " </LAST_SCAN_DATE>\n"
            " <FIRST_FOUND_DATE>\n"
            "  <SEARCH_TYPE>NOT_WITHIN</SEARCH_TYPE>\n"
            "  <DAYS>90</DAYS>\n"
            " </FIRST_FOUND_DATE>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#ef4444",
        "criticality": 3,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-web-server-stopped-responding",
        "name": "Web Server Stopped Responding",
        "category": "Informational",
        "description": "QID 86476 — web server no longer responding.",
        "rationale": (
            "A previously detected web server is no longer responding. "
            "Could indicate a service outage, decommission, or network "
            "change. Investigate promptly for production assets."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "86476",
        "color": "#ef4444",
        "criticality": 3,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-multiple-ips",
        "name": "Multiple IPs",
        "category": "Informational",
        "description": "Asset has multiple IP interfaces (Groovy).",
        "rationale": (
            "Multi-homed assets may appear in multiple scan results. "
            "Important for deduplication and understanding true asset "
            "count. Requires Groovy Scriptlet enabled."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GROOVY",
        "rule_text": (
            "// Skip testing on non-VM hosts.\n"
            "if(asset.getAssetType()!=Asset.AssetType.HOST) return false;\n"
            "lineMinimum = 2\n"
            "results = asset.resultsForQid(45099L)\n"
            "if(results == null) return false;\n"
            "int num = (results =~ /(?m)$/).size()\n"
            "if(results.startsWith(\"#table cols\")) num--\n"
            "if(num >= lineMinimum) return true;\n"
            "return false;"
        ),
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-no-asset-group",
        "name": "No Asset Group",
        "category": "Informational",
        "description": "Asset is not assigned to any asset group (Groovy).",
        "rationale": (
            "Assets not in any group may be missing from scan schedules "
            "and reports. Requires Groovy Scriptlet enabled."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GROOVY",
        "rule_text": (
            "if(asset.getAssetType()!=Asset.AssetType.HOST) return false;\n"
            "return asset.tags.reservedType.findAll { it.toString().equals(\"ASSET_GROUP\") }.size() < 1;"
        ),
        "color": "#f59e0b",
        "criticality": 2,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-asset-in-multiple-groups",
        "name": "Asset In Multiple Groups",
        "category": "Informational",
        "description": "Asset belongs to more than one asset group (Groovy).",
        "rationale": (
            "Assets in multiple groups may receive redundant scans. "
            "Use for scan optimization and deduplication. "
            "Requires Groovy Scriptlet enabled."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GROOVY",
        "rule_text": (
            "if(asset.getAssetType()!=Asset.AssetType.HOST) return false;\n"
            "return asset.tags.reservedType.findAll { it.toString().equals(\"ASSET_GROUP\") }.size() > 1;"
        ),
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-no-hostname",
        "name": "No Hostname",
        "category": "Informational",
        "description": "Asset has no hostname set (Groovy).",
        "rationale": (
            "Assets without hostnames are harder to identify and track. "
            "May indicate DNS issues or incomplete agent registration. "
            "Requires Groovy Scriptlet enabled."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GROOVY",
        "rule_text": (
            "if(asset.getAssetType()!=Asset.AssetType.HOST) return false;\n"
            "return asset.getHostName()==null || asset.getHostName().trim().length()<=0;"
        ),
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-no-netbios-name",
        "name": "No NetBIOS Name",
        "category": "Informational",
        "description": "Asset has no NetBIOS name (Groovy).",
        "rationale": (
            "Windows assets without a NetBIOS name may have authentication "
            "or domain membership issues. Requires Groovy Scriptlet enabled."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GROOVY",
        "rule_text": (
            "if(asset.getAssetType()!=Asset.AssetType.HOST) return false;\n"
            "return asset.getNetbiosName()==null || asset.getNetbiosName().trim().length()<=0;"
        ),
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-no-os-detected",
        "name": "No OS Detected",
        "category": "Informational",
        "description": "No operating system was identified (Groovy).",
        "rationale": (
            "Assets without OS detection may need authenticated scanning "
            "or have firewall/IPS interference. Investigate to improve "
            "vulnerability coverage. Requires Groovy Scriptlet enabled."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GROOVY",
        "rule_text": (
            "if(asset.getAssetType()!=Asset.AssetType.HOST) return false;\n"
            "return asset.getOperatingSystem()==null || asset.getOperatingSystem().trim().length()<=0;"
        ),
        "color": "#f59e0b",
        "criticality": 2,
        "suggested_parent": "Informational Tags",
    },
    {
        "slug": "info-sticky-keys-enabled",
        "name": "StickyKeys Enabled",
        "category": "Informational",
        "description": "QID 124403 — Sticky Keys enabled on system.",
        "rationale": (
            "Sticky Keys has known exploitation vectors (sethc.exe "
            "replacement for pre-login command execution). Identify "
            "and assess whether this feature is needed on each asset."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "124403",
        "color": "#f59e0b",
        "criticality": 3,
        "suggested_parent": "Informational Tags",
    },

    # ─────────────────────────────────────────────────────────────────
    # AUTHENTICATION STATUS
    # ─────────────────────────────────────────────────────────────────
    {
        "slug": "auth-status-failed",
        "name": "Authentication Failed",
        "category": "Authentication Status",
        "description": "Scan authentication failed (QID 105053, 105015).",
        "rationale": (
            "Authentication failed during the last scan. Assets with "
            "failed auth have incomplete vulnerability data — prioritize "
            "fixing authentication records for these. Works with Windows "
            "and Unix/Cisco/Network SSH record types."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <DETECTION>\n"
            "  <QID_LIST>\n"
            "   <QID>105053</QID>\n"
            "   <QID>105015</QID>\n"
            "  </QID_LIST>\n"
            " </DETECTION>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#ef4444",
        "criticality": 3,
        "suggested_parent": "Authentication Status",
    },
    {
        "slug": "auth-status-not-attempted",
        "name": "Authentication Not Attempted",
        "category": "Authentication Status",
        "description": "No authentication was attempted (QID 105296, 105297).",
        "rationale": (
            "No authentication record matched this asset during scanning. "
            "May indicate missing auth records or scope misconfiguration. "
            "Works with Windows and Unix/Cisco/Network SSH record types."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <DETECTION>\n"
            "  <QID_LIST>\n"
            "   <QID>105296</QID>\n"
            "   <QID>105297</QID>\n"
            "  </QID_LIST>\n"
            " </DETECTION>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#f59e0b",
        "criticality": 2,
        "suggested_parent": "Authentication Status",
    },
    {
        "slug": "auth-status-successful",
        "name": "Authentication Successful",
        "category": "Authentication Status",
        "description": "Scan authentication succeeded (QID 38307, 70053).",
        "rationale": (
            "Authentication was successful — this asset has full "
            "authenticated scan coverage. Works with Windows and "
            "Unix/Cisco/Network SSH record types."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <DETECTION>\n"
            "  <QID_LIST>\n"
            "   <QID>38307</QID>\n"
            "   <QID>70053</QID>\n"
            "  </QID_LIST>\n"
            " </DETECTION>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#22c55e",
        "criticality": 1,
        "suggested_parent": "Authentication Status",
    },
    {
        "slug": "auth-snmp-failed",
        "name": "SNMP Authentication Failed",
        "category": "Authentication Status",
        "description": "QID 105192 — SNMP authentication failed.",
        "rationale": (
            "SNMP auth failed on this asset. Network devices relying on "
            "SNMP for detailed inventory may have incomplete data."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "105192",
        "color": "#ef4444",
        "criticality": 3,
        "suggested_parent": "Authentication Status",
    },
    {
        "slug": "auth-snmp-not-attempted",
        "name": "SNMP Authentication Not Attempted",
        "category": "Authentication Status",
        "description": "QID 105298 — SNMP authentication was not attempted.",
        "rationale": (
            "No SNMP authentication record was attempted against this "
            "asset. If it's a network device, it may need an SNMP auth "
            "record configured."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "105298",
        "color": "#f59e0b",
        "criticality": 2,
        "suggested_parent": "Authentication Status",
    },
    {
        "slug": "auth-snmp-successful",
        "name": "SNMP Authentication Successful",
        "category": "Authentication Status",
        "description": "QID 78049 — SNMP authentication succeeded.",
        "rationale": (
            "SNMP authentication succeeded — full SNMP-based inventory "
            "data is available for this asset."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "78049",
        "color": "#22c55e",
        "criticality": 1,
        "suggested_parent": "Authentication Status",
    },

    # ─────────────────────────────────────────────────────────────────
    # AUTHENTICATION DETAILS
    # ─────────────────────────────────────────────────────────────────
    {
        "slug": "auth-detail-null-session",
        "name": "NULL Session Allowed",
        "category": "Authentication Details",
        "description": "Windows asset allows NULL session authentication.",
        "rationale": (
            "NULL sessions allow unauthenticated enumeration of users, "
            "shares, and other sensitive information. This is a security "
            "concern — investigate and remediate. Works with Windows "
            "Authentication Record types only."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <DETECTION>\n"
            "  <QID_LIST><QID>70028</QID></QID_LIST>\n"
            "  <RESULTS>\n"
            "   <SEARCH_TYPE>CONTAINING</SEARCH_TYPE>\n"
            "   <SEARCH_TERM>Authentication_Scheme NULL_session</SEARCH_TERM>\n"
            "  </RESULTS>\n"
            " </DETECTION>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#ef4444",
        "criticality": 4,
        "suggested_parent": "Authentication Details",
    },
    {
        "slug": "auth-detail-no-sudo",
        "name": "No Sudo",
        "category": "Authentication Details",
        "description": "Unix auth succeeded without sudo elevation.",
        "rationale": (
            "Authentication succeeded but sudo is not in use. The scan "
            "may miss vulnerabilities that require root-level checks. "
            "Works with Unix/Cisco/Network SSH record types only."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <DETECTION>\n"
            "  <QID_LIST><QID>38307</QID></QID_LIST>\n"
            "  <RESULTS>\n"
            "   <SEARCH_TYPE>CONTAINING</SEARCH_TYPE>\n"
            "   <SEARCH_TERM>Using_sudo No</SEARCH_TERM>\n"
            "  </RESULTS>\n"
            " </DETECTION>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#f59e0b",
        "criticality": 3,
        "suggested_parent": "Authentication Details",
    },
    {
        "slug": "auth-detail-public-key",
        "name": "Auth Scheme (Public Key)",
        "category": "Authentication Details",
        "description": "Unix/SSH auth using public key authentication.",
        "rationale": (
            "Identifies assets where public key authentication is in use "
            "for scanning rather than password-based. Works with "
            "Unix/Cisco/Network SSH record types only."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <DETECTION>\n"
            "  <QID_LIST><QID>38307</QID></QID_LIST>\n"
            "  <RESULTS>\n"
            "   <SEARCH_TYPE>CONTAINING</SEARCH_TYPE>\n"
            "   <SEARCH_TERM>Authentication_Scheme publickey</SEARCH_TERM>\n"
            "  </RESULTS>\n"
            " </DETECTION>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "Authentication Details",
    },
    {
        "slug": "auth-detail-account-locked-out",
        "name": "Account Locked Out",
        "category": "Authentication Details",
        "description": "Windows scan account is locked out (QID 105052).",
        "rationale": (
            "The service account used for authenticated scanning is "
            "locked out on this asset. Authentication will fail until "
            "the account is unlocked. Edit SEARCH_TERM to match your "
            "scan account username. Windows auth records only."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <DETECTION>\n"
            "  <QID_LIST><QID>105052</QID></QID_LIST>\n"
            "  <RESULTS>\n"
            "   <SEARCH_TYPE>CONTAINING</SEARCH_TYPE>\n"
            "   <SEARCH_TERM>username</SEARCH_TERM>\n"
            "  </RESULTS>\n"
            " </DETECTION>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#ef4444",
        "criticality": 4,
        "suggested_parent": "Authentication Details",
    },

    # ─────────────────────────────────────────────────────────────────
    # TYPE: ASSET TYPE TAGS
    # ─────────────────────────────────────────────────────────────────
    {
        "slug": "type-client",
        "name": "Type: Client",
        "category": "Asset Type",
        "description": "Any client/workstation operating system.",
        "rationale": (
            "OS-agnostic client categorization. Captures all assets where "
            "the OS is classified as a client/workstation by its publisher "
            "(Windows, macOS, Linux desktop, etc.)."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category2:`Client`",
        "color": "#0d9488",
        "criticality": 2,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-server",
        "name": "Type: Server",
        "category": "Asset Type",
        "description": "Any server operating system.",
        "rationale": (
            "OS-agnostic server categorization. Captures all assets where "
            "the OS is classified as a server by its publisher."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category2:`Server`",
        "color": "#0d9488",
        "criticality": 2,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-domain-controller",
        "name": "Type: Domain Controller",
        "category": "Asset Type",
        "description": "QID 90036 — Windows domain controller detected.",
        "rationale": (
            "Identifies domain controllers via QID detection. Domain "
            "controllers are high-value targets — prioritize patching "
            "and restrict network exposure."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "VULN_EXIST",
        "rule_text": "90036",
        "color": "#dc2626",
        "criticality": 5,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-virtual-machine",
        "name": "Type: Virtual Machine",
        "category": "Asset Type",
        "description": "Hardware classified as a virtual machine.",
        "rationale": (
            "Identifies VMs for inventory tracking, lifecycle management, "
            "and distinguishing from physical assets."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category2:`Virtual Machine`",
        "color": "#0d9488",
        "criticality": 2,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-firewall-device",
        "name": "Type: Firewall Device",
        "category": "Asset Type",
        "description": "Hardware classified as a firewall.",
        "rationale": (
            "Identifies firewall appliances for security infrastructure "
            "tracking and compliance scoping."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category2:`Firewall Device`",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-cisco-asa",
        "name": "Type: Cisco ASA",
        "category": "Asset Type",
        "description": "Cisco Systems ASA appliance.",
        "rationale": (
            "Cisco ASA firewalls — track for firmware patching and "
            "configuration compliance."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.manufacturer:`Cisco Systems` and hardware.product:\"ASA\"",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-cisco-switch",
        "name": "Type: Cisco Switch",
        "category": "Asset Type",
        "description": "Cisco Systems network switch.",
        "rationale": (
            "Identifies Cisco switches for network infrastructure "
            "inventory and firmware compliance."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.manufacturer:`Cisco Systems` and hardware.category2:`Switch`",
        "color": "#0d9488",
        "criticality": 2,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-cisco-wireless-controller",
        "name": "Type: Cisco Wireless Controller",
        "category": "Asset Type",
        "description": "Cisco wireless LAN controller.",
        "rationale": (
            "Wireless controllers manage access points — critical "
            "infrastructure for wireless network security."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.manufacturer:`Cisco Systems` and hardware.product:\"Wireless Controller\"",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-conferencing-equipment",
        "name": "Type: Conferencing Equipment",
        "category": "Asset Type",
        "description": "Video/audio conferencing hardware.",
        "rationale": (
            "Conferencing equipment often runs embedded OS and is "
            "overlooked in patch management programs."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category2:`Conferencing Equipment`",
        "color": "#0d9488",
        "criticality": 2,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-dell-drac",
        "name": "Type: Dell DRAC",
        "category": "Asset Type",
        "description": "Dell EMC DRAC management interface.",
        "rationale": (
            "Out-of-band management interfaces (iDRAC) have broad access "
            "to the host — ensure firmware is patched and access is restricted."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.manufacturer:`Dell EMC` and hardware.product:\"DRAC\"",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-hp-ilo",
        "name": "Type: HP iLO",
        "category": "Asset Type",
        "description": "HPE iLO management interface.",
        "rationale": (
            "Out-of-band management interfaces (iLO) have broad access "
            "to the host — ensure firmware is patched and access is restricted."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.manufacturer:`HPE` and hardware.product:`iLO`",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-ip-phone",
        "name": "Type: IP Phone",
        "category": "Asset Type",
        "description": "VoIP phone hardware.",
        "rationale": (
            "IP phones run embedded firmware and connect to voice VLANs — "
            "track for firmware compliance and network segmentation."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category2:`IP Phone`",
        "color": "#0d9488",
        "criticality": 1,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-load-balancer",
        "name": "Type: Load Balancer",
        "category": "Asset Type",
        "description": "Server load balancer device.",
        "rationale": (
            "Load balancers sit in the critical path — track for "
            "firmware patching and SSL/TLS certificate management."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category2:`Server Load Balancer`",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-mainframe",
        "name": "Type: Mainframe",
        "category": "Asset Type",
        "description": "Mainframe system (OS or hardware classified).",
        "rationale": (
            "Mainframes are business-critical — ensure they are in scope "
            "for vulnerability management and compliance."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Mainframe` or hardware.category2:`Mainframe`",
        "color": "#0d9488",
        "criticality": 4,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-mobile-device",
        "name": "Type: Mobile Device",
        "category": "Asset Type",
        "description": "Mobile hardware (phones, tablets).",
        "rationale": (
            "Mobile devices accessing corporate resources need OS patch "
            "tracking and compliance enforcement."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category1:`Mobile`",
        "color": "#0d9488",
        "criticality": 2,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-nas-device",
        "name": "Type: NAS Device",
        "category": "Asset Type",
        "description": "Network Attached Storage device.",
        "rationale": (
            "NAS devices store data and are often under-patched. "
            "Track for firmware updates and access control review."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category2:`Network Attached Storage (NAS) Device`",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-network-switch",
        "name": "Type: Network Switch",
        "category": "Asset Type",
        "description": "Any network switch (all vendors).",
        "rationale": (
            "Broad switch categorization across all vendors for network "
            "infrastructure tracking."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category2:`Switch`",
        "color": "#0d9488",
        "criticality": 2,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-palo-alto-device",
        "name": "Type: Palo Alto Device",
        "category": "Asset Type",
        "description": "Any Palo Alto Networks device.",
        "rationale": (
            "Track all Palo Alto devices for PAN-OS firmware patching "
            "and security policy compliance."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.manufacturer:`Palo Alto Networks`",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-palo-alto-firewall",
        "name": "Type: Palo Alto Firewall",
        "category": "Asset Type",
        "description": "Palo Alto Networks firewall device.",
        "rationale": (
            "Specifically identifies PA firewalls (vs. Panorama, etc.) "
            "for targeted firmware compliance."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.manufacturer:`Palo Alto Networks` and hardware.category2:`Firewall Device`",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-printer",
        "name": "Type: Printer",
        "category": "Asset Type",
        "description": "Printer hardware.",
        "rationale": (
            "Printers are often overlooked in vulnerability management — "
            "track for firmware patching and network segmentation."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category1:`Printers`",
        "color": "#0d9488",
        "criticality": 1,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-print-server",
        "name": "Type: Print Server",
        "category": "Asset Type",
        "description": "Network print server device.",
        "rationale": (
            "Print servers manage network printing infrastructure — "
            "track for spooler vulnerabilities (e.g. PrintNightmare)."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category1:\"Networking Device\" and hardware.category2:\"Print Server\"",
        "color": "#0d9488",
        "criticality": 2,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-router",
        "name": "Type: Router",
        "category": "Asset Type",
        "description": "Network router / bridge.",
        "rationale": (
            "Routers are core network infrastructure — track for "
            "firmware compliance and configuration auditing."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category2:`Bridges and Routers`",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-sharepoint-server",
        "name": "Type: SharePoint Server",
        "category": "Asset Type",
        "description": "Microsoft SharePoint server (active service).",
        "rationale": (
            "SharePoint servers are high-value targets with frequent "
            "critical CVEs. Tracks based on installed software AND "
            "the SPAdmin service being started."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": (
            "software:(publisher:`Microsoft` and name:\"SharePoint Server\") "
            "and services:(name:\"SPAdmin\" and status:\"started\")"
        ),
        "color": "#dc2626",
        "criticality": 4,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-sql-server",
        "name": "Type: SQL Server",
        "category": "Asset Type",
        "description": "Microsoft SQL Server (Windows or Linux, active).",
        "rationale": (
            "Database servers hold sensitive data and are high-priority "
            "patch targets. Identifies servers with MSSQL service running."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": (
            "operatingSystem.category2:`Server` and "
            "(services:(name:`MSSQLSERVER` and status:`started`) or "
            "services:(name:`mssql-server.service` and status:`running`))"
        ),
        "color": "#dc2626",
        "criticality": 4,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-terminal-server",
        "name": "Type: Terminal Server",
        "category": "Asset Type",
        "description": "Terminal server / RDS host.",
        "rationale": (
            "Terminal servers provide multi-user remote access — "
            "high-value targets for credential theft and lateral movement."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category2:`Terminal Server`",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-web-server",
        "name": "Type: Web Server",
        "category": "Asset Type",
        "description": "Server OS with web server software installed.",
        "rationale": (
            "Web servers are internet-exposed attack surface — prioritize "
            "for patching and WAF coverage."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "software:(category2:`Web Servers`) and operatingSystem.category2:`Server`",
        "color": "#0d9488",
        "criticality": 3,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-wireless-access-point",
        "name": "Type: Wireless Access Point",
        "category": "Asset Type",
        "description": "Wireless AP hardware.",
        "rationale": (
            "Wireless APs control network access — track for firmware "
            "patching and rogue AP detection."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "hardware.category2:`Wireless Access Point`",
        "color": "#0d9488",
        "criticality": 2,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-vsphere-server",
        "name": "Type: vSphere Server",
        "category": "Asset Type",
        "description": "VMware vSphere web interface detected (port 443).",
        "rationale": (
            "Identifies vSphere/vCenter web UI hosts by checking for "
            "QID 12230 (Default Web Page Found) with 'vsphere' in the "
            "results on port 443. Critical infrastructure — prioritize "
            "patching and access control."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <OPEN_PORTS>\n"
            "  <PORT>443</PORT>\n"
            " </OPEN_PORTS>\n"
            " <DETECTION>\n"
            "  <QID_LIST><QID>12230</QID></QID_LIST>\n"
            "  <RESULTS>\n"
            "   <SEARCH_TYPE>CONTAINING</SEARCH_TYPE>\n"
            "   <SEARCH_TERM>vsphere</SEARCH_TERM>\n"
            "  </RESULTS>\n"
            " </DETECTION>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#0d9488",
        "criticality": 4,
        "suggested_parent": "Type: Asset Type",
    },
    {
        "slug": "type-meraki-device",
        "name": "Type: Meraki Device",
        "category": "Asset Type",
        "description": "Cisco Meraki device detected via web page content.",
        "rationale": (
            "Meraki devices are hard to identify by OS alone. This tag "
            "detects them via QID 12230 (Default Web Page Found) "
            "containing 'cisco-meraki.png' in the page source."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "ASSET_SEARCH",
        "rule_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<TAG_CRITERIA>\n"
            " <DETECTION>\n"
            "  <QID_LIST><QID>12230</QID></QID_LIST>\n"
            "  <RESULTS>\n"
            "   <SEARCH_TYPE>CONTAINING</SEARCH_TYPE>\n"
            "   <SEARCH_TERM>cisco-meraki.png</SEARCH_TERM>\n"
            "  </RESULTS>\n"
            " </DETECTION>\n"
            "</TAG_CRITERIA>"
        ),
        "color": "#0d9488",
        "criticality": 2,
        "suggested_parent": "Type: Asset Type",
    },

    # ─────────────────────────────────────────────────────────────────
    # OS: OPERATING SYSTEM TAGS
    # ─────────────────────────────────────────────────────────────────
    # --- Windows ---
    {
        "slug": "os-windows-client-all",
        "name": "OS: Windows Client (All)",
        "category": "Operating System",
        "description": "All Microsoft Windows client operating systems.",
        "rationale": (
            "Groups all Windows client editions (XP through 11). Use as "
            "a parent for version-specific child tags."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Client`",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-windows-server-all",
        "name": "OS: Windows Server (All)",
        "category": "Operating System",
        "description": "All Microsoft Windows Server operating systems.",
        "rationale": (
            "Groups all Windows Server editions (2003 through 2022). "
            "Use as a parent for version-specific child tags."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Server`",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-windows-7",
        "name": "OS: Windows 7",
        "category": "Operating System",
        "description": "Microsoft Windows 7 (end-of-life).",
        "rationale": "Windows 7 is end-of-life — prioritize migration or isolation.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Client` and operatingSystem.marketVersion:`7`",
        "color": "#ef4444",
        "criticality": 4,
        "suggested_parent": "OS: Windows Client (All)",
    },
    {
        "slug": "os-windows-10",
        "name": "OS: Windows 10",
        "category": "Operating System",
        "description": "Microsoft Windows 10 (all editions/releases).",
        "rationale": "Windows 10 — track for build/release currency and EOL planning.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Client` and operatingSystem.marketVersion:`10`",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: Windows Client (All)",
    },
    {
        "slug": "os-windows-11",
        "name": "OS: Windows 11",
        "category": "Operating System",
        "description": "Microsoft Windows 11 (all editions/releases).",
        "rationale": "Windows 11 — current client platform.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Client` and operatingSystem.marketVersion:`11`",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: Windows Client (All)",
    },
    {
        "slug": "os-windows-server-2012",
        "name": "OS: Windows Server 2012",
        "category": "Operating System",
        "description": "Windows Server 2012 (end-of-life).",
        "rationale": "Server 2012 is end-of-life — prioritize migration or ESU enrollment.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Server` and operatingSystem.marketVersion:\"2012\"",
        "color": "#ef4444",
        "criticality": 4,
        "suggested_parent": "OS: Windows Server (All)",
    },
    {
        "slug": "os-windows-server-2016",
        "name": "OS: Windows Server 2016",
        "category": "Operating System",
        "description": "Windows Server 2016.",
        "rationale": "Server 2016 — approaching end of mainstream support.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Server` and operatingSystem.marketVersion:\"2016\"",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: Windows Server (All)",
    },
    {
        "slug": "os-windows-server-2019",
        "name": "OS: Windows Server 2019",
        "category": "Operating System",
        "description": "Windows Server 2019.",
        "rationale": "Server 2019 — current mainstream support.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Server` and operatingSystem.marketVersion:\"2019\"",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: Windows Server (All)",
    },
    {
        "slug": "os-windows-server-2022",
        "name": "OS: Windows Server 2022",
        "category": "Operating System",
        "description": "Windows Server 2022.",
        "rationale": "Server 2022 — current platform.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Server` and operatingSystem.marketVersion:\"2022\"",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: Windows Server (All)",
    },
    {
        "slug": "os-windows-server-2003",
        "name": "OS: Windows Server 2003",
        "category": "Operating System",
        "description": "Windows Server 2003 (end-of-life).",
        "rationale": "Server 2003 is long EOL — isolate or decommission urgently.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Server` and operatingSystem.marketVersion:\"2003\"",
        "color": "#dc2626",
        "criticality": 5,
        "suggested_parent": "OS: Windows Server (All)",
    },
    {
        "slug": "os-windows-server-2008",
        "name": "OS: Windows Server 2008",
        "category": "Operating System",
        "description": "Windows Server 2008 (end-of-life).",
        "rationale": "Server 2008 is EOL — isolate or migrate to a supported version.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Server` and operatingSystem.marketVersion:\"2008\"",
        "color": "#ef4444",
        "criticality": 4,
        "suggested_parent": "OS: Windows Server (All)",
    },
    {
        "slug": "os-windows-xp",
        "name": "OS: Windows XP",
        "category": "Operating System",
        "description": "Windows XP (end-of-life).",
        "rationale": "Windows XP is long EOL — isolate or decommission urgently.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Client` and operatingSystem.marketVersion:`XP`",
        "color": "#dc2626",
        "criticality": 5,
        "suggested_parent": "OS: Windows Client (All)",
    },
    {
        "slug": "os-windows-embedded",
        "name": "OS: Windows Embedded",
        "category": "Operating System",
        "description": "Windows Embedded (all editions).",
        "rationale": (
            "Embedded Windows systems (POS terminals, ATMs, kiosks) often "
            "have limited patch options — track separately."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Microsoft` and operatingSystem.category2:`Embedded`",
        "color": "#0284c7",
        "criticality": 3,
        "suggested_parent": "OS: Operating System",
    },
    # --- Linux ---
    {
        "slug": "os-linux-all",
        "name": "OS: Linux (All)",
        "category": "Operating System",
        "description": "All Linux distributions.",
        "rationale": "Broad Linux bucket — use as parent for distro-specific child tags.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Linux`",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-linux-server-all",
        "name": "OS: Linux Server (All)",
        "category": "Operating System",
        "description": "All Linux server operating systems.",
        "rationale": "Linux servers — subset of Linux (All) for server-specific policies.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Linux` and operatingSystem.category2:`Server`",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Linux (All)",
    },
    {
        "slug": "os-linux-client-all",
        "name": "OS: Linux Client (All)",
        "category": "Operating System",
        "description": "All Linux client/desktop operating systems.",
        "rationale": "Linux workstations/desktops — typically Fedora, Ubuntu Desktop, etc.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Linux` and operatingSystem.category2:`Client`",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Linux (All)",
    },
    {
        "slug": "os-rhel-server-all",
        "name": "OS: RHEL Server (All)",
        "category": "Operating System",
        "description": "All Red Hat Enterprise Linux Server versions.",
        "rationale": "RHEL is a common enterprise server platform — group for lifecycle tracking.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Red Hat` and operatingSystem.name:\"Linux Server\"",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Linux (All)",
    },
    {
        "slug": "os-rhel-server-7",
        "name": "OS: RHEL Server 7.x",
        "category": "Operating System",
        "description": "Red Hat Enterprise Linux Server 7.x.",
        "rationale": "RHEL 7 — maintenance support, plan migration to 8/9.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Red Hat` and operatingSystem.name:\"Linux Server\" and operatingSystem.marketVersion:`7`",
        "color": "#22c55e",
        "criticality": 3,
        "suggested_parent": "OS: RHEL Server (All)",
    },
    {
        "slug": "os-rhel-server-8",
        "name": "OS: RHEL Server 8.x",
        "category": "Operating System",
        "description": "Red Hat Enterprise Linux Server 8.x.",
        "rationale": "RHEL 8 — current full support.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Red Hat` and operatingSystem.name:\"Linux Server\" and operatingSystem.marketVersion:`8`",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: RHEL Server (All)",
    },
    {
        "slug": "os-rhel-server-9",
        "name": "OS: RHEL Server 9.x",
        "category": "Operating System",
        "description": "Red Hat Enterprise Linux Server 9.x.",
        "rationale": "RHEL 9 — current platform.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Red Hat` and operatingSystem.name:\"Linux Server\" and operatingSystem.marketVersion:`9`",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: RHEL Server (All)",
    },
    {
        "slug": "os-centos-all",
        "name": "OS: CentOS (All)",
        "category": "Operating System",
        "description": "All CentOS versions.",
        "rationale": "CentOS — approaching/past EOL for most versions, track for migration.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Linux` and operatingSystem.name:\"CentOS\"",
        "color": "#22c55e",
        "criticality": 3,
        "suggested_parent": "OS: Linux (All)",
    },
    {
        "slug": "os-centos-7",
        "name": "OS: CentOS 7.x",
        "category": "Operating System",
        "description": "CentOS 7.x (EOL June 2024).",
        "rationale": "CentOS 7 is EOL — plan migration to RHEL, Rocky, or Alma.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Linux` and operatingSystem.name:\"CentOS\" and operatingSystem.marketVersion:`7`",
        "color": "#ef4444",
        "criticality": 4,
        "suggested_parent": "OS: CentOS (All)",
    },
    {
        "slug": "os-centos-8",
        "name": "OS: CentOS 8.x",
        "category": "Operating System",
        "description": "CentOS 8.x (EOL Dec 2021).",
        "rationale": "CentOS 8 is EOL — migrate to Stream, Rocky, Alma, or RHEL.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Linux` and operatingSystem.name:\"CentOS\" and operatingSystem.marketVersion:`8`",
        "color": "#ef4444",
        "criticality": 4,
        "suggested_parent": "OS: CentOS (All)",
    },
    {
        "slug": "os-ubuntu-all",
        "name": "OS: Ubuntu (All)",
        "category": "Operating System",
        "description": "All Ubuntu versions.",
        "rationale": "Ubuntu — popular for both servers and desktops. Group for lifecycle tracking.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Canonical` and operatingSystem.name:\"Ubuntu\"",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Linux (All)",
    },
    {
        "slug": "os-ubuntu-20",
        "name": "OS: Ubuntu 20.x",
        "category": "Operating System",
        "description": "Ubuntu 20.04 LTS / 20.10.",
        "rationale": "Ubuntu 20.04 LTS — supported until April 2025 (standard).",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Canonical` and operatingSystem.name:\"Ubuntu\" and operatingSystem.version:\"20.\"",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Ubuntu (All)",
    },
    {
        "slug": "os-ubuntu-22",
        "name": "OS: Ubuntu 22.x",
        "category": "Operating System",
        "description": "Ubuntu 22.04 LTS / 22.10.",
        "rationale": "Ubuntu 22.04 LTS — current long-term support.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Canonical` and operatingSystem.name:\"Ubuntu\" and operatingSystem.version:\"22.\"",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Ubuntu (All)",
    },
    {
        "slug": "os-oracle-linux-all",
        "name": "OS: Oracle Linux (All)",
        "category": "Operating System",
        "description": "All Oracle Linux versions.",
        "rationale": "Oracle Linux — RHEL-compatible enterprise distribution.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Oracle` and operatingSystem.name:\"Linux\"",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Linux (All)",
    },
    {
        "slug": "os-amazon-linux",
        "name": "OS: Amazon Linux",
        "category": "Operating System",
        "description": "Amazon Linux (non-AMI).",
        "rationale": "Amazon Linux — AWS-optimized distribution for EC2 instances.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:\"Amazon Web Service\" and operatingSystem.name:\"Linux\" and not operatingSystem.name:\"AMI\"",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Linux (All)",
    },
    # --- macOS ---
    {
        "slug": "os-macos-all",
        "name": "OS: MacOS",
        "category": "Operating System",
        "description": "All macOS versions.",
        "rationale": "All Apple macOS — use as parent for version-specific tags.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Mac`",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-macos-ventura",
        "name": "OS: MacOS 13 Ventura",
        "category": "Operating System",
        "description": "macOS 13 Ventura.",
        "rationale": "macOS Ventura — track for patch currency.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Mac` and operatingSystem.marketVersion:`Ventura`",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: MacOS",
    },
    {
        "slug": "os-macos-monterey",
        "name": "OS: MacOS 12 Monterey",
        "category": "Operating System",
        "description": "macOS 12 Monterey.",
        "rationale": "macOS Monterey — track for patch currency and EOL planning.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Mac` and operatingSystem.marketVersion:`Monterey`",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: MacOS",
    },
    {
        "slug": "os-macos-big-sur",
        "name": "OS: MacOS 11 Big Sur",
        "category": "Operating System",
        "description": "macOS 11 Big Sur.",
        "rationale": "macOS Big Sur — approaching/past security update EOL.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Mac` and operatingSystem.marketVersion:`Big Sur`",
        "color": "#f59e0b",
        "criticality": 3,
        "suggested_parent": "OS: MacOS",
    },
    # --- Unix ---
    {
        "slug": "os-unix-all",
        "name": "OS: Unix (All)",
        "category": "Operating System",
        "description": "All Unix operating systems (non-Linux).",
        "rationale": "Unix family — AIX, Solaris, HP-UX, etc.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Unix`",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-nix-all",
        "name": "OS: NIX (All)",
        "category": "Operating System",
        "description": "All Linux and Unix combined.",
        "rationale": "Combined Linux + Unix bucket for broad *nix policies.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Linux` or operatingSystem.category1:`Unix`",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-oracle-solaris-all",
        "name": "OS: Oracle Solaris (All)",
        "category": "Operating System",
        "description": "All Oracle Solaris versions.",
        "rationale": "Solaris — legacy Unix platform, track for decommission planning.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Oracle` and operatingSystem.name:\"Solaris\"",
        "color": "#22c55e",
        "criticality": 3,
        "suggested_parent": "OS: Unix (All)",
    },
    {
        "slug": "os-aix-all",
        "name": "OS: AIX (All)",
        "category": "Operating System",
        "description": "All IBM AIX versions.",
        "rationale": "IBM AIX — common in financial services and mainframe-adjacent environments.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`IBM` and operatingSystem.name:`AIX`",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Unix (All)",
    },
    # --- Network OS ---
    {
        "slug": "os-cisco-ios-all",
        "name": "OS: Cisco IOS (All)",
        "category": "Operating System",
        "description": "All Cisco IOS versions.",
        "rationale": "Cisco IOS — core network infrastructure OS. Track firmware currency.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Network Operating System` and operatingSystem.publisher:`Cisco Systems` and operatingSystem.name:\"IOS\"",
        "color": "#0284c7",
        "criticality": 3,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-cisco-ios-xe",
        "name": "OS: Cisco IOS XE",
        "category": "Operating System",
        "description": "Cisco IOS XE platform.",
        "rationale": "IOS XE — modern Cisco routing/switching platform.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Network Operating System` and operatingSystem.publisher:`Cisco Systems` and operatingSystem.name:\"IOS XE\"",
        "color": "#0284c7",
        "criticality": 3,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-cisco-nxos",
        "name": "OS: Cisco NX-OS",
        "category": "Operating System",
        "description": "Cisco NX-OS (Nexus switches).",
        "rationale": "NX-OS — data center switching platform. Track for firmware compliance.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Network Operating System` and operatingSystem.publisher:`Cisco Systems` and operatingSystem.name:\"NX-OS\"",
        "color": "#0284c7",
        "criticality": 3,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-cisco-asa",
        "name": "OS: Cisco ASA",
        "category": "Operating System",
        "description": "Cisco ASA firewall OS.",
        "rationale": "Cisco ASA OS — perimeter firewall firmware. Prioritize patching.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Network Operating System` and operatingSystem.publisher:`Cisco Systems` and operatingSystem.name:\"ASA\"",
        "color": "#0284c7",
        "criticality": 3,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-palo-alto-panos-all",
        "name": "OS: Palo Alto PAN-OS (All)",
        "category": "Operating System",
        "description": "All Palo Alto Networks PAN-OS versions.",
        "rationale": "PAN-OS — next-gen firewall platform. Track for firmware currency.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Palo Alto Networks` and operatingSystem.name:\"PAN-OS\"",
        "color": "#0284c7",
        "criticality": 3,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-juniper-junos",
        "name": "OS: Juniper JUNOS",
        "category": "Operating System",
        "description": "Juniper Networks JUNOS.",
        "rationale": "JUNOS — Juniper routing/switching platform.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Juniper Networks` and operatingSystem.name:\"JUNOS\"",
        "color": "#0284c7",
        "criticality": 3,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-f5-tmos",
        "name": "OS: F5 Networks TMOS",
        "category": "Operating System",
        "description": "F5 Networks TMOS (BIG-IP).",
        "rationale": "F5 TMOS — load balancer/WAF platform. High-value target.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`F5 Networks` and operatingSystem.name:`TMOS`",
        "color": "#0284c7",
        "criticality": 3,
        "suggested_parent": "OS: Operating System",
    },
    # --- VMware ---
    {
        "slug": "os-vmware-esxi-all",
        "name": "OS: VMware ESXi (All)",
        "category": "Operating System",
        "description": "All VMware ESXi hypervisor versions.",
        "rationale": "ESXi hypervisors — a compromise here affects all hosted VMs.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`VMware` and operatingSystem.name:\"ESXi\"",
        "color": "#0284c7",
        "criticality": 4,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-vmware-vcenter-all",
        "name": "OS: vCenter Server Appliance (All)",
        "category": "Operating System",
        "description": "All VMware vCenter Server Appliance versions.",
        "rationale": "vCenter manages the entire VMware estate — critical infrastructure.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`VMware` and operatingSystem.name:\"Server Appliance\"",
        "color": "#0284c7",
        "criticality": 4,
        "suggested_parent": "OS: Operating System",
    },
    # --- Mobile ---
    {
        "slug": "os-android",
        "name": "OS: Android",
        "category": "Operating System",
        "description": "Android mobile OS.",
        "rationale": "Android devices — track for OS patch level compliance.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Mobile` and operatingSystem.name:\"Android\"",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-apple-ios",
        "name": "OS: Apple iOS",
        "category": "Operating System",
        "description": "Apple iOS mobile OS.",
        "rationale": "iOS devices — track for OS version compliance.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Mobile` and operatingSystem.publisher:`Apple` and operatingSystem.name:\"iOS\"",
        "color": "#0284c7",
        "criticality": 2,
        "suggested_parent": "OS: Operating System",
    },
    # --- Other ---
    {
        "slug": "os-unidentified",
        "name": "OS: Unidentified",
        "category": "Operating System",
        "description": "OS could not be determined.",
        "rationale": (
            "Assets with unidentified OS need investigation — usually "
            "means authenticated scanning is needed or there's network "
            "interference."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.category1:`Unidentified` or operatingSystem.category1:`Unknown`",
        "color": "#f59e0b",
        "criticality": 2,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-freebsd",
        "name": "OS: FreeBSD",
        "category": "Operating System",
        "description": "FreeBSD operating system.",
        "rationale": "FreeBSD — common in network appliances and specialized servers.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`The FreeBSD Project`",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Operating System",
    },
    {
        "slug": "os-kali-linux",
        "name": "OS: Kali Linux",
        "category": "Operating System",
        "description": "Kali Linux (penetration testing distribution).",
        "rationale": (
            "Kali Linux in production is a red flag — may indicate "
            "unauthorized pentest activity or a misclassified asset."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Offensive Security` and operatingSystem.name:\"Kali\"",
        "color": "#ef4444",
        "criticality": 4,
        "suggested_parent": "OS: Linux (All)",
    },
    {
        "slug": "os-fedora",
        "name": "OS: Fedora",
        "category": "Operating System",
        "description": "Fedora Linux (all versions).",
        "rationale": "Fedora — community/cutting-edge Linux. Short support lifecycle.",
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "operatingSystem.publisher:`Red Hat` and operatingSystem.name:\"Fedora\"",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OS: Linux (All)",
    },

    # ─────────────────────────────────────────────────────────────────
    # SW: SOFTWARE TAGS
    # ─────────────────────────────────────────────────────────────────
    {
        "slug": "sw-antivirus-installed",
        "name": "SW: Antivirus Installed",
        "category": "Software",
        "description": "Antivirus software detected on server or client.",
        "rationale": (
            "Validates endpoint protection coverage. Pair with the "
            "'Missing' variant for gap analysis."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "(operatingSystem.category2:`Server` or operatingSystem.category2:`Client`) and software:(category2:`Antivirus`)",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "SW: Software",
    },
    {
        "slug": "sw-antivirus-missing",
        "name": "SW: Antivirus Missing",
        "category": "Software",
        "description": "No antivirus detected on server or client.",
        "rationale": (
            "HIGH PRIORITY — assets without endpoint protection are at "
            "elevated risk. Investigate and remediate promptly."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "(operatingSystem.category2:`Server` or operatingSystem.category2:`Client`) and not software:(category2:`Antivirus`)",
        "color": "#ef4444",
        "criticality": 4,
        "suggested_parent": "SW: Software",
    },
    {
        "slug": "sw-crowdstrike-falcon-installed",
        "name": "SW: CS Falcon Sensor Installed",
        "category": "Software",
        "description": "CrowdStrike Falcon Sensor detected.",
        "rationale": (
            "Validates CrowdStrike EDR deployment coverage. Pair with "
            "the 'Missing' variant for gap analysis."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "(operatingSystem.category2:`Server` or operatingSystem.category2:`Client`) and software:(product:`Falcon Sensor`)",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "SW: Software",
    },
    {
        "slug": "sw-crowdstrike-falcon-missing",
        "name": "SW: CS Falcon Sensor Missing",
        "category": "Software",
        "description": "CrowdStrike Falcon Sensor NOT detected.",
        "rationale": (
            "Assets without CrowdStrike coverage — if Falcon is your "
            "EDR standard, these need agent deployment."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "(operatingSystem.category2:`Server` or operatingSystem.category2:`Client`) and not software:(product:`Falcon Sensor`)",
        "color": "#ef4444",
        "criticality": 4,
        "suggested_parent": "SW: Software",
    },
    {
        "slug": "sw-docker-engine",
        "name": "SW: Docker Engine",
        "category": "Software",
        "description": "Docker Engine installed.",
        "rationale": (
            "Docker hosts need container-specific vulnerability scanning "
            "and hardening (CIS Docker Benchmark)."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "software:(publisher:`Docker` and product:`Docker Engine`)",
        "color": "#7c3aed",
        "criticality": 2,
        "suggested_parent": "SW: Software",
    },
    {
        "slug": "sw-itunes",
        "name": "SW: iTunes",
        "category": "Software",
        "description": "Apple iTunes installed.",
        "rationale": (
            "iTunes on enterprise assets is often unauthorized software — "
            "review against your approved software policy."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "software:(product:`iTunes` and publisher:`Apple`)",
        "color": "#7c3aed",
        "criticality": 1,
        "suggested_parent": "SW: Software",
    },
    {
        "slug": "sw-quicktime",
        "name": "SW: QuickTime",
        "category": "Software",
        "description": "Apple QuickTime installed.",
        "rationale": (
            "QuickTime for Windows is end-of-life and has known "
            "unpatched vulnerabilities — remove from all Windows assets."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "software:(product:`QuickTime` and publisher:`Apple`)",
        "color": "#ef4444",
        "criticality": 4,
        "suggested_parent": "SW: Software",
    },
    {
        "slug": "sw-sharepoint-server",
        "name": "SW: SharePoint Server",
        "category": "Software",
        "description": "Microsoft SharePoint Server installed.",
        "rationale": (
            "SharePoint servers are frequent targets for critical RCE "
            "vulnerabilities — track for priority patching."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "software:(publisher:`Microsoft` and product:`SharePoint Server`)",
        "color": "#7c3aed",
        "criticality": 3,
        "suggested_parent": "SW: Software",
    },
    {
        "slug": "sw-splunk-universal-forwarder",
        "name": "SW: Splunk Universal Forwarder Installed",
        "category": "Software",
        "description": "Splunk Universal Forwarder detected.",
        "rationale": (
            "Validates log collection coverage — assets without a "
            "forwarder may have visibility gaps in your SIEM."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "GLOBAL_ASSET_VIEW",
        "rule_text": "software:(publisher:`Splunk`) and software:(product:`Universal Forwarder`)",
        "color": "#7c3aed",
        "criticality": 2,
        "suggested_parent": "SW: Software",
    },

    # ─────────────────────────────────────────────────────────────────
    # AWS CLOUD TAGS
    # ─────────────────────────────────────────────────────────────────
    {
        "slug": "aws-state-running",
        "name": "AWS: State [RUNNING]",
        "category": "Cloud",
        "description": "EC2 instance in RUNNING state.",
        "rationale": (
            "Identifies active EC2 instances. Use for scoping scan "
            "targets and excluding terminated/stopped instances from "
            "reports and dashboards."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "aws.ec2.instanceState:\"RUNNING\"",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "AWS: EC2 State",
    },
    {
        "slug": "aws-state-stopped",
        "name": "AWS: State [STOPPED]",
        "category": "Cloud",
        "description": "EC2 instance in STOPPED state.",
        "rationale": (
            "Stopped instances still have EBS volumes attached and may "
            "contain vulnerabilities. Track for lifecycle management "
            "and cost optimization."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "aws.ec2.instanceState:\"STOPPED\"",
        "color": "#f59e0b",
        "criticality": 2,
        "suggested_parent": "AWS: EC2 State",
    },
    {
        "slug": "aws-state-terminated",
        "name": "AWS: State [TERMINATED]",
        "category": "Cloud",
        "description": "EC2 instance in TERMINATED state.",
        "rationale": (
            "Terminated instances should be excluded from vulnerability "
            "reports and scan schedules. Use in the 'Do not include' "
            "section of report configurations."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "aws.ec2.instanceState:\"TERMINATED\"",
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "AWS: EC2 State",
    },
    # --- Azure VM States ---
    {
        "slug": "azure-state-running",
        "name": "Azure: State [RUNNING]",
        "category": "Cloud",
        "description": "Azure VM in Running power state.",
        "rationale": (
            "Identifies active Azure VMs. Use for scoping scan targets "
            "and excluding deallocated/stopped instances from reports."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "azure.vm.state:\"PowerState/running\"",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "Azure: VM State",
    },
    {
        "slug": "azure-state-stopped",
        "name": "Azure: State [STOPPED]",
        "category": "Cloud",
        "description": "Azure VM in Stopped power state.",
        "rationale": (
            "Stopped VMs are still allocated and incurring compute costs. "
            "Track for lifecycle management — consider deallocating or "
            "deleting if no longer needed."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "azure.vm.state:\"PowerState/stopped\"",
        "color": "#f59e0b",
        "criticality": 2,
        "suggested_parent": "Azure: VM State",
    },
    {
        "slug": "azure-state-deallocated",
        "name": "Azure: State [DEALLOCATED]",
        "category": "Cloud",
        "description": "Azure VM in Deallocated power state.",
        "rationale": (
            "Deallocated VMs are not running and not incurring compute "
            "costs but still have disks attached. Exclude from active "
            "scan schedules and vulnerability reports."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "azure.vm.state:\"PowerState/deallocated\"",
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "Azure: VM State",
    },
    # --- GCP Compute Instance States ---
    {
        "slug": "gcp-state-running",
        "name": "GCP: State [RUNNING]",
        "category": "Cloud",
        "description": "GCP Compute Engine instance in RUNNING state.",
        "rationale": (
            "Identifies active GCP instances. Use for scoping scan "
            "targets and dashboards."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "gcp.compute.instance.state:\"RUNNING\"",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "GCP: Instance State",
    },
    {
        "slug": "gcp-state-stopped",
        "name": "GCP: State [STOPPED]",
        "category": "Cloud",
        "description": "GCP Compute Engine instance in STOPPED state.",
        "rationale": (
            "Stopped GCP instances retain disks and configuration. "
            "Track for lifecycle management and cost optimization."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "gcp.compute.instance.state:\"STOPPED\"",
        "color": "#f59e0b",
        "criticality": 2,
        "suggested_parent": "GCP: Instance State",
    },
    {
        "slug": "gcp-state-terminated",
        "name": "GCP: State [TERMINATED]",
        "category": "Cloud",
        "description": "GCP Compute Engine instance in TERMINATED state.",
        "rationale": (
            "Terminated GCP instances are shut down. Exclude from "
            "active vulnerability reports and scan schedules."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "gcp.compute.instance.state:\"TERMINATED\"",
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "GCP: Instance State",
    },
    # --- OCI Compute Instance States ---
    {
        "slug": "oci-state-running",
        "name": "OCI: State [RUNNING]",
        "category": "Cloud",
        "description": "OCI Compute instance in RUNNING lifecycle state.",
        "rationale": (
            "Identifies active Oracle Cloud Infrastructure instances. "
            "Use for scoping scan targets and dashboards."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "oci.compute.instance.lifecycleState:\"RUNNING\"",
        "color": "#22c55e",
        "criticality": 2,
        "suggested_parent": "OCI: Instance State",
    },
    {
        "slug": "oci-state-stopped",
        "name": "OCI: State [STOPPED]",
        "category": "Cloud",
        "description": "OCI Compute instance in STOPPED lifecycle state.",
        "rationale": (
            "Stopped OCI instances retain boot volumes and VNICs. "
            "Track for lifecycle management and cost optimization."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "oci.compute.instance.lifecycleState:\"STOPPED\"",
        "color": "#f59e0b",
        "criticality": 2,
        "suggested_parent": "OCI: Instance State",
    },
    {
        "slug": "oci-state-terminated",
        "name": "OCI: State [TERMINATED]",
        "category": "Cloud",
        "description": "OCI Compute instance in TERMINATED lifecycle state.",
        "rationale": (
            "Terminated OCI instances are deleted. Exclude from active "
            "vulnerability reports and scan schedules."
        ),
        "source_url": _QUALYS_TAG_DOC,
        "rule_type": "CLOUD_ASSET",
        "rule_text": "oci.compute.instance.lifecycleState:\"TERMINATED\"",
        "color": "#64748b",
        "criticality": 1,
        "suggested_parent": "OCI: Instance State",
    },
]
