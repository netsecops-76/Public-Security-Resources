# Q KB Explorer — Feature Tour Narration Script

> ~60 seconds. Pair with `qkbe-feature-tour.gif` or record a screen capture.

---

**[0:00 – QIDs Tab Overview]**
Q KB Explorer is an offline-capable search tool for Qualys Knowledge Base data. Here we're looking at the QIDs tab — over 115,000 vulnerability definitions synced from Qualys, each showing severity, category, CVE count, and patchability.

**[0:10 – Type-Ahead Search]**
Typing "apache" instantly filters results — type-ahead search fires as you type with a 250-millisecond debounce. We see 3,030 matching QIDs.

**[0:17 – Detail Modal]**
Clicking any result opens a rich detail modal with severity, diagnosis, consequence, solution, CVE references, and more.

**[0:23 – Multi-Select Filters with AND/OR Toggle]**
The CVE filter supports multi-select with server-side search. When two or more items are selected, an OR/AND toggle appears — OR finds vulnerabilities matching any selected CVE, AND requires all of them. The toggle switches from blue OR to orange AND.

**[0:35 – Clear Filters]**
A Clear Filters button resets all search inputs, dropdowns, and multi-selects in one click.

**[0:38 – CIDs Tab]**
The CIDs tab holds 26,577 compliance controls with category, criticality, and technology filters.

**[0:43 – Policies Tab]**
The Policies tab has the richest filter set — status, control category, technology, CID, and control name — plus Browse and Migration sub-tabs for cross-environment policy migration.

**[0:48 – Settings & Data Sync]**
Settings manages your Qualys connection, encrypted credential vault, and data sync. You can run delta syncs, full syncs, or schedule recurring syncs — all with live progress tracking.

**[0:55 – Light/Dark Theme]**
Finally, Q KB Explorer supports both dark and light themes with a single toggle. All running in a Docker container at localhost.

---

*Built by netsecops-76. Not affiliated with Qualys, Inc.*
