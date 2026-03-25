"""
Q KB Explorer — SQLite Database Layer
Built by netsecops-76

Schema for QIDs, CIDs, Policies with FTS5 full-text search.
WAL mode for concurrent reads during sync operations.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import xml.etree.ElementTree as ET
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime

import bleach

# Allowlist for HTML tags from Qualys KB fields (diagnosis, consequence, solution)
_SAFE_TAGS = [
    "p", "br", "a", "b", "i", "u", "ul", "ol", "li",
    "table", "tr", "td", "th", "thead", "tbody",
    "strong", "em", "code", "pre", "div", "span",
    "h1", "h2", "h3", "h4", "h5", "h6", "hr", "font",
]
_SAFE_ATTRS = {"a": ["href", "target"], "font": ["color", "size"]}


def _sanitize_html(value: str | None) -> str | None:
    """Strip unsafe HTML from Qualys KB fields while preserving formatting."""
    if not value:
        return value
    return bleach.clean(value, tags=_SAFE_TAGS, attributes=_SAFE_ATTRS, strip=True)

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("QKBE_DB_PATH", "/data/qkbe.db")
_local = threading.local()


# ═══════════════════════════════════════════════════════════════════════════
# Connection Management
# ═══════════════════════════════════════════════════════════════════════════

def _get_conn() -> sqlite3.Connection:
    """Thread-local connection with WAL mode and row factory."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, timeout=30)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


@contextmanager
def get_db():
    """Yield a connection and commit on success, rollback on error."""
    conn = _get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# ═══════════════════════════════════════════════════════════════════════════
# Schema Initialization
# ═══════════════════════════════════════════════════════════════════════════

def init_db():
    """Create all tables and FTS indexes if they don't exist."""
    with get_db() as conn:
        conn.executescript(_SCHEMA_SQL)
        # ── Migrations ──
        # Add xml_tech_count column if missing (safe idempotent migration)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(policies)").fetchall()}
        if "xml_tech_count" not in cols:
            conn.execute("ALTER TABLE policies ADD COLUMN xml_tech_count INTEGER")
        # Backfill xml_tech_count for existing exports that haven't been counted yet
        uncounted = conn.execute(
            "SELECT policy_id, export_xml FROM policies WHERE export_xml IS NOT NULL AND xml_tech_count IS NULL"
        ).fetchall()
        for row in uncounted:
            count = _count_xml_technologies(row["export_xml"])
            conn.execute(
                "UPDATE policies SET xml_tech_count=? WHERE policy_id=?",
                (count, row["policy_id"]),
            )


_SCHEMA_SQL = """
-- QIDs (Knowledge Base vulnerabilities)
CREATE TABLE IF NOT EXISTS vulns (
    qid                INTEGER PRIMARY KEY,
    vuln_type          TEXT,
    severity_level     INTEGER,
    title              TEXT,
    category           TEXT,
    technology         TEXT,
    published_datetime TEXT,
    last_service_modification_datetime TEXT,
    code_modified_datetime TEXT,
    patchable          INTEGER DEFAULT 0,
    patch_published_date TEXT,
    pci_flag           INTEGER DEFAULT 0,
    diagnosis          TEXT,
    consequence        TEXT,
    solution           TEXT,
    cvss_base          REAL,
    cvss_temporal      REAL,
    cvss_vector        TEXT,
    cvss3_base         REAL,
    cvss3_temporal     REAL,
    cvss3_vector       TEXT,
    cvss3_version      TEXT,
    discovery_remote   INTEGER,
    discovery_auth_types TEXT,
    correlation_json   TEXT,
    threat_intelligence_json TEXT,
    software_list_json TEXT
);

-- CVEs linked to QIDs
CREATE TABLE IF NOT EXISTS vuln_cves (
    qid     INTEGER NOT NULL,
    cve_id  TEXT NOT NULL,
    url     TEXT,
    PRIMARY KEY (qid, cve_id),
    FOREIGN KEY (qid) REFERENCES vulns(qid) ON DELETE CASCADE
);

-- Bugtraq references
CREATE TABLE IF NOT EXISTS vuln_bugtraqs (
    qid        INTEGER NOT NULL,
    bugtraq_id TEXT NOT NULL,
    url        TEXT,
    PRIMARY KEY (qid, bugtraq_id),
    FOREIGN KEY (qid) REFERENCES vulns(qid) ON DELETE CASCADE
);

-- Vendor references
CREATE TABLE IF NOT EXISTS vuln_vendor_refs (
    qid           INTEGER NOT NULL,
    vendor_ref_id TEXT NOT NULL,
    url           TEXT,
    PRIMARY KEY (qid, vendor_ref_id),
    FOREIGN KEY (qid) REFERENCES vulns(qid) ON DELETE CASCADE
);

-- Real-Time Threat Indicators (RTI) lookup
CREATE TABLE IF NOT EXISTS vuln_rti (
    qid     INTEGER NOT NULL,
    rti_tag TEXT NOT NULL,
    PRIMARY KEY (qid, rti_tag),
    FOREIGN KEY (qid) REFERENCES vulns(qid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vuln_rti_tag ON vuln_rti(rti_tag);

-- Supported Modules (agent/scanner types that can detect each QID)
CREATE TABLE IF NOT EXISTS vuln_supported_modules (
    qid         INTEGER NOT NULL,
    module_name TEXT NOT NULL,
    PRIMARY KEY (qid, module_name),
    FOREIGN KEY (qid) REFERENCES vulns(qid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vuln_supported_modules_name ON vuln_supported_modules(module_name);

-- CIDs (Compliance Controls)
CREATE TABLE IF NOT EXISTS controls (
    cid                  INTEGER PRIMARY KEY,
    update_date          TEXT,
    created_date         TEXT,
    category             TEXT,
    sub_category         TEXT,
    statement            TEXT,
    criticality_label    TEXT,
    criticality_value    INTEGER,
    check_type           TEXT,
    comment              TEXT,
    ignore_error         INTEGER DEFAULT 0,
    ignore_item_not_found INTEGER DEFAULT 0,
    error_set_status     TEXT,
    use_agent_only       INTEGER DEFAULT 0,
    auto_update          INTEGER DEFAULT 0,
    scan_parameters_json TEXT
);

-- Technologies linked to CIDs
CREATE TABLE IF NOT EXISTS control_technologies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cid         INTEGER NOT NULL,
    tech_id     TEXT,
    tech_name   TEXT,
    rationale   TEXT,
    description TEXT,
    datapoint_json TEXT,
    FOREIGN KEY (cid) REFERENCES controls(cid) ON DELETE CASCADE
);

-- Policies
CREATE TABLE IF NOT EXISTS policies (
    policy_id               INTEGER PRIMARY KEY,
    title                   TEXT,
    created_datetime        TEXT,
    created_by              TEXT,
    last_modified_datetime  TEXT,
    last_modified_by        TEXT,
    last_evaluated_datetime TEXT,
    status                  TEXT,
    is_locked               INTEGER DEFAULT 0,
    source                  TEXT,
    export_xml              BLOB,
    export_date             TEXT,
    export_includes_udcs    INTEGER DEFAULT 0,
    xml_tech_count          INTEGER
);

-- Controls within policies
CREATE TABLE IF NOT EXISTS policy_controls (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id         INTEGER NOT NULL,
    cid               INTEGER NOT NULL,
    statement         TEXT,
    criticality_label TEXT,
    criticality_value INTEGER,
    deprecated        INTEGER DEFAULT 0,
    FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE
);

-- Sync watermarks
CREATE TABLE IF NOT EXISTS sync_state (
    data_type              TEXT PRIMARY KEY,
    last_sync_datetime     TEXT,
    last_full_sync_datetime TEXT,
    record_count           INTEGER DEFAULT 0,
    credential_id          TEXT
);

-- Insert default sync state rows
INSERT OR IGNORE INTO sync_state (data_type) VALUES ('qids');
INSERT OR IGNORE INTO sync_state (data_type) VALUES ('cids');
INSERT OR IGNORE INTO sync_state (data_type) VALUES ('policies');
INSERT OR IGNORE INTO sync_state (data_type) VALUES ('mandates');

-- Database maintenance configuration (single-row table)
CREATE TABLE IF NOT EXISTS db_maintenance_config (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    day_of_week     INTEGER DEFAULT 0,
    hour            INTEGER DEFAULT 0,
    minute          INTEGER DEFAULT 0,
    timezone        TEXT DEFAULT '',
    last_run        TEXT,
    last_status     TEXT,
    last_error      TEXT,
    last_duration_s REAL,
    enabled         INTEGER DEFAULT 1
);
INSERT OR IGNORE INTO db_maintenance_config (id) VALUES (1);

-- Auto-update configuration (singleton)
CREATE TABLE IF NOT EXISTS auto_update_config (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    enabled         INTEGER DEFAULT 0,
    day_of_week     INTEGER DEFAULT 6,
    hour            INTEGER DEFAULT 0,
    minute          INTEGER DEFAULT 0,
    timezone        TEXT DEFAULT '',
    last_check      TEXT,
    last_status     TEXT,
    last_error      TEXT
);
INSERT OR IGNORE INTO auto_update_config (id) VALUES (1);

-- FTS5 indexes for full-text search
CREATE VIRTUAL TABLE IF NOT EXISTS vulns_fts USING fts5(
    qid, title, category, diagnosis, consequence, solution,
    content=vulns, content_rowid=qid
);

CREATE VIRTUAL TABLE IF NOT EXISTS controls_fts USING fts5(
    cid, statement, category, sub_category, comment,
    content=controls, content_rowid=cid
);

-- Triggers to keep FTS in sync
CREATE TRIGGER IF NOT EXISTS vulns_ai AFTER INSERT ON vulns BEGIN
    INSERT INTO vulns_fts(rowid, qid, title, category, diagnosis, consequence, solution)
    VALUES (new.qid, new.qid, new.title, new.category, new.diagnosis, new.consequence, new.solution);
END;

CREATE TRIGGER IF NOT EXISTS vulns_ad AFTER DELETE ON vulns BEGIN
    INSERT INTO vulns_fts(vulns_fts, rowid, qid, title, category, diagnosis, consequence, solution)
    VALUES ('delete', old.qid, old.qid, old.title, old.category, old.diagnosis, old.consequence, old.solution);
END;

CREATE TRIGGER IF NOT EXISTS vulns_au AFTER UPDATE ON vulns BEGIN
    INSERT INTO vulns_fts(vulns_fts, rowid, qid, title, category, diagnosis, consequence, solution)
    VALUES ('delete', old.qid, old.qid, old.title, old.category, old.diagnosis, old.consequence, old.solution);
    INSERT INTO vulns_fts(rowid, qid, title, category, diagnosis, consequence, solution)
    VALUES (new.qid, new.qid, new.title, new.category, new.diagnosis, new.consequence, new.solution);
END;

CREATE TRIGGER IF NOT EXISTS controls_ai AFTER INSERT ON controls BEGIN
    INSERT INTO controls_fts(rowid, cid, statement, category, sub_category, comment)
    VALUES (new.cid, new.cid, new.statement, new.category, new.sub_category, new.comment);
END;

CREATE TRIGGER IF NOT EXISTS controls_ad AFTER DELETE ON controls BEGIN
    INSERT INTO controls_fts(controls_fts, rowid, cid, statement, category, sub_category, comment)
    VALUES ('delete', old.cid, old.cid, old.statement, old.category, old.sub_category, old.comment);
END;

CREATE TRIGGER IF NOT EXISTS controls_au AFTER UPDATE ON controls BEGIN
    INSERT INTO controls_fts(controls_fts, rowid, cid, statement, category, sub_category, comment)
    VALUES ('delete', old.cid, old.cid, old.statement, old.category, old.sub_category, old.comment);
    INSERT INTO controls_fts(rowid, cid, statement, category, sub_category, comment)
    VALUES (new.cid, new.cid, new.statement, new.category, new.sub_category, new.comment);
END;

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns(severity_level);
CREATE INDEX IF NOT EXISTS idx_vulns_category ON vulns(category);
CREATE INDEX IF NOT EXISTS idx_vulns_patchable ON vulns(patchable);
CREATE INDEX IF NOT EXISTS idx_vuln_cves_cve ON vuln_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_controls_category ON controls(category);
CREATE INDEX IF NOT EXISTS idx_controls_criticality ON controls(criticality_value);
CREATE INDEX IF NOT EXISTS idx_control_tech_cid ON control_technologies(cid);
CREATE INDEX IF NOT EXISTS idx_policy_controls_policy ON policy_controls(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_controls_cid ON policy_controls(cid);

-- Sync log runs (persisted to survive worker restarts)
CREATE TABLE IF NOT EXISTS sync_log_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    data_type   TEXT NOT NULL,
    full        INTEGER NOT NULL DEFAULT 0,
    api_base    TEXT,
    endpoint    TEXT,
    started_at  TEXT,
    finished_at TEXT,
    status      TEXT DEFAULT 'running'
);

-- Sync log events (individual timestamped events per run)
CREATE TABLE IF NOT EXISTS sync_log_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL,
    ts          TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    detail_json TEXT,
    FOREIGN KEY (run_id) REFERENCES sync_log_runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sync_log_events_run ON sync_log_events(run_id);
CREATE INDEX IF NOT EXISTS idx_sync_log_runs_type ON sync_log_runs(data_type);

-- Scheduled delta syncs
CREATE TABLE IF NOT EXISTS sync_schedules (
    data_type     TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL,
    platform      TEXT NOT NULL,
    frequency     TEXT NOT NULL,
    start_date    TEXT NOT NULL,
    start_time    TEXT NOT NULL DEFAULT '02:00',
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    next_run_utc  TEXT,
    last_run_utc  TEXT,
    enabled       INTEGER DEFAULT 1,
    created_at    TEXT NOT NULL
);

-- Mandates (Compliance Frameworks)
CREATE TABLE IF NOT EXISTS mandates (
    mandate_id          INTEGER PRIMARY KEY,
    title               TEXT,
    version             TEXT,
    publisher           TEXT,
    released_date       TEXT,
    last_modified_date  TEXT,
    description         TEXT
);

-- Mandate-Control junction (many-to-many: mandate <-> CID)
CREATE TABLE IF NOT EXISTS mandate_controls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mandate_id      INTEGER NOT NULL,
    cid             INTEGER NOT NULL,
    section_id      TEXT,
    section_title   TEXT,
    FOREIGN KEY (mandate_id) REFERENCES mandates(mandate_id) ON DELETE CASCADE,
    FOREIGN KEY (cid) REFERENCES controls(cid) ON DELETE CASCADE,
    UNIQUE(mandate_id, cid, section_id)
);

-- FTS5 for mandate search
CREATE VIRTUAL TABLE IF NOT EXISTS mandates_fts USING fts5(
    mandate_id, title, publisher, description,
    content=mandates, content_rowid=mandate_id
);

-- FTS triggers for mandates
CREATE TRIGGER IF NOT EXISTS mandates_ai AFTER INSERT ON mandates BEGIN
    INSERT INTO mandates_fts(rowid, mandate_id, title, publisher, description)
    VALUES (new.mandate_id, new.mandate_id, new.title, new.publisher, new.description);
END;

CREATE TRIGGER IF NOT EXISTS mandates_ad AFTER DELETE ON mandates BEGIN
    INSERT INTO mandates_fts(mandates_fts, rowid, mandate_id, title, publisher, description)
    VALUES ('delete', old.mandate_id, old.mandate_id, old.title, old.publisher, old.description);
END;

CREATE TRIGGER IF NOT EXISTS mandates_au AFTER UPDATE ON mandates BEGIN
    INSERT INTO mandates_fts(mandates_fts, rowid, mandate_id, title, publisher, description)
    VALUES ('delete', old.mandate_id, old.mandate_id, old.title, old.publisher, old.description);
    INSERT INTO mandates_fts(rowid, mandate_id, title, publisher, description)
    VALUES (new.mandate_id, new.mandate_id, new.title, new.publisher, new.description);
END;

CREATE INDEX IF NOT EXISTS idx_mandate_controls_mandate ON mandate_controls(mandate_id);
CREATE INDEX IF NOT EXISTS idx_mandate_controls_cid ON mandate_controls(cid);
CREATE INDEX IF NOT EXISTS idx_mandates_publisher ON mandates(publisher);
"""


# ═══════════════════════════════════════════════════════════════════════════
# Sync State
# ═══════════════════════════════════════════════════════════════════════════

def get_sync_status() -> dict:
    """Return sync state for all data types, including elapsed time."""
    _table_map = {"qids": "vulns", "cids": "controls", "policies": "policies", "mandates": "mandates"}
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM sync_state").fetchall()
        result = {}
        for row in rows:
            dt = row["data_type"]
            # Live count from actual table (not cached) — mandates are populated
            # during CID sync but their sync_state.record_count isn't updated then
            table = _table_map.get(dt)
            live_count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] if table else (row["record_count"] or 0)
            result[dt] = {
                "last_sync": row["last_sync_datetime"],
                "last_full_sync": row["last_full_sync_datetime"],
                "record_count": live_count,
                "credential_id": row["credential_id"],
            }
            # Get elapsed from last completed sync_log_run
            run = conn.execute(
                """SELECT started_at, finished_at FROM sync_log_runs
                   WHERE data_type = ? AND status IN ('complete', 'error')
                   ORDER BY id DESC LIMIT 1""",
                (dt,),
            ).fetchone()
            if run and run["started_at"] and run["finished_at"]:
                try:
                    t0 = datetime.fromisoformat(run["started_at"])
                    t1 = datetime.fromisoformat(run["finished_at"])
                    result[dt]["elapsed_seconds"] = round((t1 - t0).total_seconds(), 1)
                except Exception:
                    result[dt]["elapsed_seconds"] = None
            else:
                result[dt]["elapsed_seconds"] = None

        # Mandates are extracted during CID sync — use CID sync timestamp
        # if more recent than the mandate-specific timestamp
        if "mandates" in result and "cids" in result:
            m = result["mandates"]
            c = result["cids"]
            cid_ts = c.get("last_sync")
            mandate_ts = m.get("last_sync")
            if cid_ts and (not mandate_ts or cid_ts > mandate_ts):
                m["last_sync"] = cid_ts
                m["credential_id"] = m.get("credential_id") or c.get("credential_id")
            cid_full = c.get("last_full_sync")
            mandate_full = m.get("last_full_sync")
            if cid_full and (not mandate_full or cid_full > mandate_full):
                m["last_full_sync"] = cid_full

        return result


def update_sync_state(data_type: str, is_full: bool, credential_id: str | None = None):
    """Update sync watermark after a successful sync."""
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    with get_db() as conn:
        # Get current record count
        table_map = {"qids": "vulns", "cids": "controls", "policies": "policies", "mandates": "mandates"}
        table = table_map[data_type]
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

        if is_full:
            conn.execute(
                """UPDATE sync_state
                   SET last_sync_datetime=?, last_full_sync_datetime=?,
                       record_count=?, credential_id=?
                   WHERE data_type=?""",
                (now, now, count, credential_id, data_type),
            )
        else:
            conn.execute(
                """UPDATE sync_state
                   SET last_sync_datetime=?, record_count=?, credential_id=?
                   WHERE data_type=?""",
                (now, count, credential_id, data_type),
            )


def get_last_sync_datetime(data_type: str) -> str | None:
    """Get the last sync timestamp for delta queries."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT last_sync_datetime FROM sync_state WHERE data_type=?",
            (data_type,),
        ).fetchone()
        return row["last_sync_datetime"] if row else None


def purge_data(data_type: str):
    """Delete all rows for a data type before full re-sync.

    Child tables are cleaned via ON DELETE CASCADE foreign keys.
    FTS indexes are rebuilt after deletion.
    Sync-state watermarks and record count are reset.
    """
    with get_db() as conn:
        if data_type == "qids":
            conn.execute("DELETE FROM vulns")
            conn.execute("INSERT INTO vulns_fts(vulns_fts) VALUES('rebuild')")
        elif data_type == "cids":
            conn.execute("DELETE FROM controls")
            conn.execute("INSERT INTO controls_fts(controls_fts) VALUES('rebuild')")
        elif data_type == "policies":
            conn.execute("DELETE FROM policies")
        elif data_type == "mandates":
            conn.execute("DELETE FROM mandates")
            conn.execute("INSERT INTO mandates_fts(mandates_fts) VALUES('rebuild')")
        else:
            raise ValueError(f"Unknown data_type: {data_type}")

        conn.execute(
            """UPDATE sync_state
               SET last_sync_datetime=NULL, last_full_sync_datetime=NULL,
                   record_count=0
               WHERE data_type=?""",
            (data_type,),
        )


# ═══════════════════════════════════════════════════════════════════════════
# Schedule CRUD
# ═══════════════════════════════════════════════════════════════════════════

def save_schedule(data_type: str, credential_id: str, platform: str,
                  frequency: str, start_date: str, start_time: str,
                  timezone: str, next_run_utc: str | None = None) -> None:
    """Create or update a sync schedule."""
    now = datetime.utcnow().isoformat() + "Z"
    with get_db() as conn:
        conn.execute(
            """INSERT INTO sync_schedules
               (data_type, credential_id, platform, frequency, start_date,
                start_time, timezone, next_run_utc, enabled, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
               ON CONFLICT(data_type) DO UPDATE SET
                 credential_id=excluded.credential_id,
                 platform=excluded.platform,
                 frequency=excluded.frequency,
                 start_date=excluded.start_date,
                 start_time=excluded.start_time,
                 timezone=excluded.timezone,
                 next_run_utc=excluded.next_run_utc,
                 enabled=1""",
            (data_type, credential_id, platform, frequency, start_date,
             start_time, timezone, next_run_utc, now),
        )


def get_all_schedules() -> list[dict]:
    """Get all sync schedules."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM sync_schedules WHERE enabled=1").fetchall()
        return [dict(r) for r in rows]


def get_schedule(data_type: str) -> dict | None:
    """Get a single schedule by data type."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM sync_schedules WHERE data_type=? AND enabled=1",
            (data_type,),
        ).fetchone()
        return dict(row) if row else None


def delete_schedule(data_type: str) -> bool:
    """Delete a schedule."""
    with get_db() as conn:
        cur = conn.execute(
            "DELETE FROM sync_schedules WHERE data_type=?", (data_type,)
        )
        return cur.rowcount > 0


def update_schedule_last_run(data_type: str, last_run_utc: str,
                             next_run_utc: str | None = None) -> None:
    """Update last_run and optionally next_run after a scheduled sync."""
    with get_db() as conn:
        if next_run_utc:
            conn.execute(
                "UPDATE sync_schedules SET last_run_utc=?, next_run_utc=? WHERE data_type=?",
                (last_run_utc, next_run_utc, data_type),
            )
        else:
            conn.execute(
                "UPDATE sync_schedules SET last_run_utc=? WHERE data_type=?",
                (last_run_utc, data_type),
            )


# ═══════════════════════════════════════════════════════════════════════════
# QID CRUD
# ═══════════════════════════════════════════════════════════════════════════

def _ensure_list(val):
    """Normalize a value that may be a single dict or a list of dicts."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def _fts5_safe(q: str) -> str:
    """Prepare a user query for FTS5 by quoting each token individually.

    Wraps each whitespace-separated token in double quotes to prevent
    FTS5 from interpreting special characters (., &, ', etc.) as operators.
    Tokens are implicitly ANDed — all must appear in the document.
    The last token gets a * prefix-match wildcard so partial words match
    as the user types (e.g. "con" matches "control", "controls", etc.).
    """
    tokens = q.strip().split()
    if not tokens:
        return '""'
    quoted = ['"' + t.replace('"', '""') + '"' for t in tokens]
    # Append * to the last token for prefix matching (type-ahead support)
    quoted[-1] = quoted[-1] + "*"
    return " ".join(quoted)


def upsert_vuln(vuln: dict):
    """Insert or update a vulnerability from parsed Qualys XML data."""
    qid = int(vuln.get("QID", 0))
    if not qid:
        return

    # Extract CVSS data
    cvss = vuln.get("CVSS", {}) or {}
    cvss_base = cvss.get("BASE") or cvss.get("base")
    cvss_temporal = cvss.get("TEMPORAL") or cvss.get("temporal")
    cvss_vector = None
    access = cvss.get("ACCESS", {}) or {}
    if access:
        cvss_vector = f"AV:{access.get('VECTOR', '?')}"

    cvss3 = vuln.get("CVSS_V3", {}) or {}
    cvss3_base = cvss3.get("BASE") or cvss3.get("base")
    cvss3_temporal = cvss3.get("TEMPORAL") or cvss3.get("temporal")
    cvss3_vector = cvss3.get("ATTACK_VECTOR") or cvss3.get("VECTOR_STRING")
    cvss3_version = cvss3.get("CVSS3_VERSION")

    # Discovery
    discovery = vuln.get("DISCOVERY", {}) or {}
    discovery_remote = 1 if str(discovery.get("REMOTE_DETECTION", "")).lower() in ("1", "true") else 0
    auth_types = discovery.get("AUTH_TYPE_LIST", {})
    auth_list = None
    if auth_types:
        items = _ensure_list(auth_types.get("AUTH_TYPE"))
        auth_list = json.dumps(items) if items else None

    # Correlation (exploit/malware info)
    correlation = vuln.get("CORRELATION", {}) or {}
    correlation_json = json.dumps(correlation) if correlation else None

    # Threat intelligence
    threat_intel = vuln.get("THREAT_INTELLIGENCE", {}) or {}
    threat_json = json.dumps(threat_intel) if threat_intel else None

    # Software list
    software = vuln.get("SOFTWARE_LIST", {}) or {}
    software_json = json.dumps(software) if software else None

    with get_db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO vulns (
                qid, vuln_type, severity_level, title, category, technology,
                published_datetime, last_service_modification_datetime,
                code_modified_datetime, patchable, patch_published_date,
                pci_flag, diagnosis, consequence, solution,
                cvss_base, cvss_temporal, cvss_vector,
                cvss3_base, cvss3_temporal, cvss3_vector, cvss3_version,
                discovery_remote, discovery_auth_types,
                correlation_json, threat_intelligence_json, software_list_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                qid,
                vuln.get("VULN_TYPE"),
                int(vuln.get("SEVERITY_LEVEL", 0) or 0),
                vuln.get("TITLE"),
                vuln.get("CATEGORY"),
                vuln.get("TECHNOLOGY"),
                vuln.get("PUBLISHED_DATETIME"),
                vuln.get("LAST_SERVICE_MODIFICATION_DATETIME"),
                vuln.get("CODE_MODIFIED_DATETIME"),
                1 if str(vuln.get("PATCHABLE", "")).lower() in ("1", "true") else 0,
                vuln.get("PATCH_PUBLISHED_DATE"),
                1 if str(vuln.get("PCI_FLAG", "")).lower() in ("1", "true") else 0,
                _sanitize_html(vuln.get("DIAGNOSIS")),
                _sanitize_html(vuln.get("CONSEQUENCE")),
                _sanitize_html(vuln.get("SOLUTION")),
                float(cvss_base) if cvss_base else None,
                float(cvss_temporal) if cvss_temporal else None,
                cvss_vector,
                float(cvss3_base) if cvss3_base else None,
                float(cvss3_temporal) if cvss3_temporal else None,
                cvss3_vector,
                cvss3_version,
                discovery_remote,
                auth_list,
                correlation_json,
                threat_json,
                software_json,
            ),
        )

        # Upsert CVEs
        cve_list_container = vuln.get("CVE_LIST", {}) or {}
        cves = _ensure_list(cve_list_container.get("CVE"))
        conn.execute("DELETE FROM vuln_cves WHERE qid=?", (qid,))
        for cve in cves:
            if isinstance(cve, dict):
                conn.execute(
                    "INSERT OR IGNORE INTO vuln_cves (qid, cve_id, url) VALUES (?,?,?)",
                    (qid, cve.get("ID"), cve.get("URL")),
                )

        # Upsert Bugtraqs
        bt_container = vuln.get("BUGTRAQ_LIST", {}) or {}
        bts = _ensure_list(bt_container.get("BUGTRAQ"))
        conn.execute("DELETE FROM vuln_bugtraqs WHERE qid=?", (qid,))
        for bt in bts:
            if isinstance(bt, dict):
                conn.execute(
                    "INSERT OR IGNORE INTO vuln_bugtraqs (qid, bugtraq_id, url) VALUES (?,?,?)",
                    (qid, bt.get("ID"), bt.get("URL")),
                )

        # Upsert vendor refs
        vr_container = vuln.get("VENDOR_REFERENCE_LIST", {}) or {}
        vrs = _ensure_list(vr_container.get("VENDOR_REFERENCE"))
        conn.execute("DELETE FROM vuln_vendor_refs WHERE qid=?", (qid,))
        for vr in vrs:
            if isinstance(vr, dict):
                conn.execute(
                    "INSERT OR IGNORE INTO vuln_vendor_refs (qid, vendor_ref_id, url) VALUES (?,?,?)",
                    (qid, vr.get("ID"), vr.get("URL")),
                )

        # Upsert RTI tags
        conn.execute("DELETE FROM vuln_rti WHERE qid=?", (qid,))
        ti_json = threat_json
        if ti_json and ti_json not in ("{}", "null"):
            ti = json.loads(ti_json) if isinstance(ti_json, str) else ti_json
            intel_items = _ensure_list(ti.get("THREAT_INTEL")) if isinstance(ti, dict) else []
            for item in intel_items:
                if isinstance(item, dict):
                    tag = item.get("#text") or item.get("ID")
                    if tag:
                        conn.execute(
                            "INSERT OR IGNORE INTO vuln_rti (qid, rti_tag) VALUES (?,?)",
                            (qid, tag),
                        )
        # Exploit correlation → has_exploit tag
        if correlation_json and correlation_json not in ("{}", "null"):
            conn.execute(
                "INSERT OR IGNORE INTO vuln_rti (qid, rti_tag) VALUES (?,?)",
                (qid, "has_exploit"),
            )

        # Upsert supported modules (agent/scanner types)
        conn.execute("DELETE FROM vuln_supported_modules WHERE qid=?", (qid,))
        sm_raw = vuln.get("SUPPORTED_MODULES")
        if sm_raw:
            if isinstance(sm_raw, str):
                # Single module returned as plain string
                module_items = [sm_raw]
            elif isinstance(sm_raw, dict):
                module_items = _ensure_list(sm_raw.get("SUPPORTED_MODULE"))
            elif isinstance(sm_raw, list):
                module_items = sm_raw
            else:
                module_items = []
            for mod in module_items:
                mod_name = mod if isinstance(mod, str) else (
                    mod.get("#text") or mod.get("MODULE_NAME") or str(mod)
                ) if isinstance(mod, dict) else str(mod)
                if mod_name and mod_name.strip():
                    conn.execute(
                        "INSERT OR IGNORE INTO vuln_supported_modules (qid, module_name) VALUES (?,?)",
                        (qid, mod_name.strip()),
                    )


def search_vulns(
    q: str = "",
    cves: list[str] | None = None,
    cve_mode: str = "or",
    severity: int | None = None,
    categories: list[str] | None = None,
    patchable: bool | None = None,
    vuln_type: str | None = None,
    cvss_base_min: float | None = None,
    cvss3_base_min: float | None = None,
    published_after: str | None = None,
    modified_after: str | None = None,
    pci_flag: bool | None = None,
    discovery_method: str | None = None,
    rti_indicators: list[str] | None = None,
    supported_modules: list[str] | None = None,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Search vulnerabilities with FTS, filters, and pagination.

    Args:
        cves: List of CVE IDs for exact match filtering.
        cve_mode: "or" (match ANY) or "and" (match ALL) for CVE filter.
        categories: List of category names for exact match filtering.
        vuln_type: Exact match on vuln_type (e.g. "Vulnerability").
        cvss_base_min: Minimum CVSS v2 base score (>=).
        cvss3_base_min: Minimum CVSS v3.1 base score (>=).
        published_after: ISO date string — only QIDs published on/after.
        modified_after: ISO date string — only QIDs modified on/after.
        pci_flag: True for PCI vulns, False for non-PCI.
        discovery_method: "remote" or "auth" for discovery filtering.
        rti_indicators: List of RTI tags (has_exploit, has_malware, etc.).
    """
    with get_db() as conn:
        conditions = []
        params = []

        # FTS query (wrap in double quotes for phrase-literal matching)
        if q:
            conditions.append(
                "v.qid IN (SELECT qid FROM vulns_fts WHERE vulns_fts MATCH ?)"
            )
            params.append(_fts5_safe(q))

        # CVE filter (multi-value via subquery)
        if cves:
            placeholders = ",".join(["?"] * len(cves))
            if cve_mode == "and" and len(cves) > 1:
                conditions.append(
                    f"""v.qid IN (
                        SELECT qid FROM vuln_cves
                        WHERE cve_id IN ({placeholders})
                        GROUP BY qid HAVING COUNT(DISTINCT cve_id) = ?
                    )"""
                )
                params.extend(cves)
                params.append(len(cves))
            else:
                conditions.append(
                    f"v.qid IN (SELECT qid FROM vuln_cves WHERE cve_id IN ({placeholders}))"
                )
                params.extend(cves)

        # Severity filter
        if severity is not None:
            conditions.append("v.severity_level = ?")
            params.append(severity)

        # Category filter (multi-value exact match)
        if categories:
            placeholders = ",".join(["?"] * len(categories))
            conditions.append(f"v.category IN ({placeholders})")
            params.extend(categories)

        # Patchable filter
        if patchable is not None:
            conditions.append("v.patchable = ?")
            params.append(1 if patchable else 0)

        # Vuln type filter
        if vuln_type:
            conditions.append("v.vuln_type = ?")
            params.append(vuln_type)

        # CVSS v2 base score threshold
        if cvss_base_min is not None:
            conditions.append("v.cvss_base >= ?")
            params.append(cvss_base_min)

        # CVSS v3.1 base score threshold
        if cvss3_base_min is not None:
            conditions.append("v.cvss3_base >= ?")
            params.append(cvss3_base_min)

        # Published after date
        if published_after:
            conditions.append("v.published_datetime >= ?")
            params.append(published_after)

        # Modified after date
        if modified_after:
            conditions.append("v.last_service_modification_datetime >= ?")
            params.append(modified_after)

        # PCI flag filter
        if pci_flag is not None:
            conditions.append("v.pci_flag = ?")
            params.append(1 if pci_flag else 0)

        # Discovery method filter
        if discovery_method == "remote":
            conditions.append("v.discovery_remote = 1")
        elif discovery_method == "auth":
            conditions.append(
                "v.discovery_auth_types IS NOT NULL AND v.discovery_auth_types != '[]'"
            )

        # Real-Time Threat Indicator filters (ANDed — each tag must be present)
        if rti_indicators:
            for rti in rti_indicators:
                conditions.append(
                    "v.qid IN (SELECT qid FROM vuln_rti WHERE rti_tag = ?)"
                )
                params.append(rti)

        # Supported modules filter (ANDed — QID must be supported by ALL selected modules)
        if supported_modules:
            for mod in supported_modules:
                conditions.append(
                    "v.qid IN (SELECT qid FROM vuln_supported_modules WHERE module_name = ?)"
                )
                params.append(mod)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        # Count total
        count_sql = f"SELECT COUNT(*) FROM vulns v {where}"
        total = conn.execute(count_sql, params).fetchone()[0]

        # Fetch page
        data_sql = f"""
            SELECT v.*, (
                SELECT COUNT(*) FROM vuln_cves WHERE qid = v.qid
            ) AS cve_count, (
                SELECT GROUP_CONCAT(module_name, ', ')
                FROM vuln_supported_modules WHERE qid = v.qid
            ) AS supported_modules
            FROM vulns v {where}
            ORDER BY v.severity_level DESC, v.qid DESC
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(data_sql, params + [per_page, offset]).fetchall()

        return {
            "results": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        }


def get_vuln(qid: int) -> dict | None:
    """Get full vulnerability detail including all associations."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM vulns WHERE qid=?", (qid,)).fetchone()
        if not row:
            return None

        result = dict(row)

        # CVEs
        cves = conn.execute(
            "SELECT cve_id, url FROM vuln_cves WHERE qid=?", (qid,)
        ).fetchall()
        result["cves"] = [dict(c) for c in cves]

        # Bugtraqs
        bts = conn.execute(
            "SELECT bugtraq_id, url FROM vuln_bugtraqs WHERE qid=?", (qid,)
        ).fetchall()
        result["bugtraqs"] = [dict(b) for b in bts]

        # Vendor refs
        vrs = conn.execute(
            "SELECT vendor_ref_id, url FROM vuln_vendor_refs WHERE qid=?", (qid,)
        ).fetchall()
        result["vendor_refs"] = [dict(v) for v in vrs]

        # Supported modules
        mods = conn.execute(
            "SELECT module_name FROM vuln_supported_modules WHERE qid=?", (qid,)
        ).fetchall()
        result["supported_modules"] = [m["module_name"] for m in mods]

        # Parse JSON fields
        for field in ("correlation_json", "threat_intelligence_json", "software_list_json"):
            if result.get(field):
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    pass

        return result


# ═══════════════════════════════════════════════════════════════════════════
# CID CRUD
# ═══════════════════════════════════════════════════════════════════════════

# Log first framework dict keys once per process to aid mandate field discovery
_fw_keys_logged = [0]

def upsert_control(control: dict):
    """Insert or update a compliance control from parsed Qualys XML data."""
    cid = int(control.get("ID", 0))
    if not cid:
        return

    # Criticality
    crit = control.get("CRITICALITY", {}) or {}
    crit_label = crit.get("LABEL")
    crit_value = int(crit.get("VALUE", 0) or 0)

    with get_db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO controls (
                cid, update_date, created_date, category, sub_category,
                statement, criticality_label, criticality_value,
                check_type, comment, ignore_error, ignore_item_not_found,
                error_set_status, use_agent_only, auto_update,
                scan_parameters_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                cid,
                control.get("UPDATE_DATE"),
                control.get("CREATED_DATE"),
                control.get("CATEGORY"),
                control.get("SUB_CATEGORY"),
                control.get("STATEMENT"),
                crit_label,
                crit_value,
                control.get("CHECK_TYPE"),
                control.get("COMMENT"),
                1 if str(control.get("IGNORE_ERROR", "")).lower() in ("1", "true") else 0,
                1 if str(control.get("IGNORE_ITEM_NOT_FOUND", "")).lower() in ("1", "true") else 0,
                control.get("ERROR_SET_STATUS"),
                1 if str(control.get("USE_AGENT_ONLY", "")).lower() in ("1", "true") else 0,
                1 if str(control.get("AUTO_UPDATE", "")).lower() in ("1", "true") else 0,
                json.dumps(control.get("SCAN_PARAMETERS")) if control.get("SCAN_PARAMETERS") else None,
            ),
        )

        # Technologies
        tech_container = control.get("TECHNOLOGY_LIST", {}) or {}
        techs = _ensure_list(tech_container.get("TECHNOLOGY"))
        conn.execute("DELETE FROM control_technologies WHERE cid=?", (cid,))
        for tech in techs:
            if isinstance(tech, dict):
                conn.execute(
                    """INSERT INTO control_technologies
                       (cid, tech_id, tech_name, rationale, description, datapoint_json)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        cid,
                        tech.get("TECH_ID") or tech.get("ID"),
                        tech.get("TECH_NAME") or tech.get("NAME"),
                        tech.get("RATIONALE"),
                        tech.get("DESCRIPTION"),
                        json.dumps(tech.get("DATAPOINTS")) if tech.get("DATAPOINTS") else None,
                    ),
                )

        # Frameworks / Mandates — extract from control response and link
        _extract_mandates_for_cid(conn, cid, control)


def _extract_mandates_for_cid(conn, cid: int, control: dict):
    """Extract mandate/framework data from a single control and upsert.

    Internal helper: operates within an existing DB connection + transaction.
    """
    fw_container = (
        control.get("FRAMEWORK_LIST", {})
        or control.get("MANDATE_LIST", {})
        or {}
    )
    frameworks = _ensure_list(
        fw_container.get("FRAMEWORK") or fw_container.get("MANDATE")
    )
    # Log first framework's keys for mandate field discovery
    if frameworks and _fw_keys_logged[0] < 1:
        _fw_keys_logged[0] += 1
        first_fw = frameworks[0] if isinstance(frameworks[0], dict) else {}
        logger.info(
            "FRAMEWORK_DISCOVERY: keys=%s sample=%s",
            list(first_fw.keys()),
            {k: str(v)[:100] for k, v in first_fw.items()} if first_fw else "not-a-dict",
        )
    # Clear existing links for this CID so they get rebuilt
    if frameworks:
        conn.execute("DELETE FROM mandate_controls WHERE cid=?", (cid,))
    for fw in frameworks:
        if not isinstance(fw, dict):
            continue
        fw_id = int(fw.get("ID", 0) or fw.get("FRAMEWORK_ID", 0) or fw.get("MANDATE_ID", 0) or 0)
        if not fw_id:
            continue
        # Upsert the mandate/framework itself
        # Use ON CONFLICT UPDATE (not INSERT OR REPLACE) to avoid
        # triggering ON DELETE CASCADE which would wipe mandate_controls.
        # COALESCE preserves any previously populated values that
        # would otherwise be overwritten with NULL from the CID response.
        conn.execute(
            """INSERT INTO mandates
               (mandate_id, title, version, publisher,
                released_date, last_modified_date, description)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(mandate_id) DO UPDATE SET
                 title=COALESCE(excluded.title, mandates.title),
                 version=COALESCE(excluded.version, mandates.version),
                 publisher=COALESCE(excluded.publisher, mandates.publisher),
                 released_date=COALESCE(excluded.released_date, mandates.released_date),
                 last_modified_date=COALESCE(excluded.last_modified_date, mandates.last_modified_date),
                 description=COALESCE(excluded.description, mandates.description)""",
            (
                fw_id,
                fw.get("TITLE") or fw.get("NAME"),
                fw.get("VERSION"),
                fw.get("PUBLISHER"),
                fw.get("RELEASED_DATE"),
                fw.get("LAST_MODIFIED_DATE"),
                fw.get("DESCRIPTION"),
            ),
        )
        # Link this CID to the mandate with section info
        section_refs = _ensure_list(
            fw.get("REFS", {}).get("REF") if isinstance(fw.get("REFS"), dict) else None
        ) or [fw]  # Fallback: use the framework dict itself for section info
        for ref in section_refs:
            if isinstance(ref, dict):
                conn.execute(
                    """INSERT OR IGNORE INTO mandate_controls
                       (mandate_id, cid, section_id, section_title)
                       VALUES (?,?,?,?)""",
                    (
                        fw_id,
                        cid,
                        ref.get("SECTION_ID") or ref.get("SECTION") or ref.get("REF_ID"),
                        ref.get("SECTION_TITLE") or ref.get("SECTION_NAME") or ref.get("REF_TITLE"),
                    ),
                )
            else:
                # Simple string section reference
                conn.execute(
                    "INSERT OR IGNORE INTO mandate_controls (mandate_id, cid, section_id) VALUES (?,?,?)",
                    (fw_id, cid, str(ref) if ref else None),
                )


def extract_mandates_from_control(control: dict):
    """Extract mandate/framework data from a parsed Qualys control.

    Public entry point for mandate-only sync. Opens its own DB transaction.
    Used by sync_mandates() to extract mandates without upserting the full control.
    """
    cid = int(control.get("ID", 0))
    if not cid:
        return
    with get_db() as conn:
        _extract_mandates_for_cid(conn, cid, control)


def search_controls(
    q: str = "",
    categories: list[str] | None = None,
    criticality: str | None = None,
    technologies: list[str] | None = None,
    technology_mode: str = "or",
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Search controls with FTS, filters, and pagination.

    Args:
        categories: List of category names for exact match filtering.
        criticality: Criticality label (URGENT, CRITICAL, SERIOUS, MEDIUM, MINIMAL).
        technologies: List of technology names for exact match filtering.
        technology_mode: "or" (match ANY) or "and" (match ALL) for technology filter.
    """
    with get_db() as conn:
        conditions = []
        params = []

        if q:
            conditions.append(
                "c.cid IN (SELECT cid FROM controls_fts WHERE controls_fts MATCH ?)"
            )
            params.append(_fts5_safe(q))

        # Category filter (multi-value exact match)
        if categories:
            placeholders = ",".join(["?"] * len(categories))
            conditions.append(f"c.category IN ({placeholders})")
            params.extend(categories)

        # Criticality filter (by label)
        if criticality:
            conditions.append("c.criticality_label = ?")
            params.append(criticality)

        # Technology filter (multi-value via subquery)
        if technologies:
            placeholders = ",".join(["?"] * len(technologies))
            if technology_mode == "and" and len(technologies) > 1:
                conditions.append(
                    f"""c.cid IN (
                        SELECT cid FROM control_technologies
                        WHERE tech_name IN ({placeholders})
                        GROUP BY cid HAVING COUNT(DISTINCT tech_name) = ?
                    )"""
                )
                params.extend(technologies)
                params.append(len(technologies))
            else:
                conditions.append(
                    f"c.cid IN (SELECT cid FROM control_technologies WHERE tech_name IN ({placeholders}))"
                )
                params.extend(technologies)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        count_sql = f"SELECT COUNT(*) FROM controls c {where}"
        total = conn.execute(count_sql, params).fetchone()[0]

        data_sql = f"""
            SELECT c.*
            FROM controls c {where}
            ORDER BY c.criticality_value DESC, c.cid DESC
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(data_sql, params + [per_page, offset]).fetchall()

        return {
            "results": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        }


def get_control(cid: int) -> dict | None:
    """Get full control detail with technologies and linked policies."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM controls WHERE cid=?", (cid,)).fetchone()
        if not row:
            return None

        result = dict(row)

        # Technologies
        techs = conn.execute(
            "SELECT * FROM control_technologies WHERE cid=?", (cid,)
        ).fetchall()
        result["technologies"] = [dict(t) for t in techs]

        # Linked policies
        policies = conn.execute(
            """SELECT p.policy_id, p.title, p.status, pc.criticality_label
               FROM policy_controls pc
               JOIN policies p ON pc.policy_id = p.policy_id
               WHERE pc.cid=?
               ORDER BY p.title""",
            (cid,),
        ).fetchall()
        result["linked_policies"] = [dict(p) for p in policies]

        # Linked mandates
        mandates = conn.execute(
            """SELECT m.mandate_id, m.title, m.version, m.publisher,
                      mc.section_id, mc.section_title
               FROM mandate_controls mc
               JOIN mandates m ON mc.mandate_id = m.mandate_id
               WHERE mc.cid=?
               ORDER BY m.title""",
            (cid,),
        ).fetchall()
        result["linked_mandates"] = [dict(m) for m in mandates]

        if result.get("scan_parameters_json"):
            try:
                result["scan_parameters_json"] = json.loads(result["scan_parameters_json"])
            except (json.JSONDecodeError, TypeError):
                pass

        return result


# ═══════════════════════════════════════════════════════════════════════════
# Policy CRUD
# ═══════════════════════════════════════════════════════════════════════════

def delete_policies(policy_ids: list[int]) -> int:
    """Delete one or more policies by ID. Returns count deleted."""
    if not policy_ids:
        return 0
    with get_db() as conn:
        placeholders = ",".join(["?"] * len(policy_ids))
        cur = conn.execute(
            f"DELETE FROM policies WHERE policy_id IN ({placeholders})",
            policy_ids,
        )
        return cur.rowcount


def upsert_policy(policy: dict):
    """Insert or update a policy from parsed Qualys XML data."""
    policy_id = int(policy.get("ID", 0))
    if not policy_id:
        return

    with get_db() as conn:
        # Preserve existing export_xml if present
        existing = conn.execute(
            "SELECT export_xml, export_date, export_includes_udcs FROM policies WHERE policy_id=?",
            (policy_id,),
        ).fetchone()

        export_xml = existing["export_xml"] if existing else None
        export_date = existing["export_date"] if existing else None
        export_udcs = existing["export_includes_udcs"] if existing else 0

        conn.execute(
            """INSERT OR REPLACE INTO policies (
                policy_id, title, created_datetime, created_by,
                last_modified_datetime, last_modified_by,
                last_evaluated_datetime, status, is_locked, source,
                export_xml, export_date, export_includes_udcs
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                policy_id,
                policy.get("TITLE"),
                policy.get("CREATED_DATETIME"),
                policy.get("CREATED_BY"),
                policy.get("LAST_MODIFIED_DATETIME"),
                policy.get("LAST_MODIFIED_BY"),
                policy.get("LAST_EVALUATED_DATETIME"),
                policy.get("STATUS"),
                1 if str(policy.get("IS_LOCKED", "")).lower() in ("1", "true") else 0,
                policy.get("SOURCE"),
                export_xml,
                export_date,
                export_udcs,
            ),
        )

        # Policy controls
        ctrl_container = policy.get("CONTROL_LIST", {}) or {}
        ctrls = _ensure_list(ctrl_container.get("CONTROL"))
        if ctrls:
            conn.execute("DELETE FROM policy_controls WHERE policy_id=?", (policy_id,))
            for ctrl in ctrls:
                if isinstance(ctrl, dict):
                    crit = ctrl.get("CRITICALITY", {}) or {}
                    conn.execute(
                        """INSERT INTO policy_controls
                           (policy_id, cid, statement, criticality_label,
                            criticality_value, deprecated)
                           VALUES (?,?,?,?,?,?)""",
                        (
                            policy_id,
                            int(ctrl.get("CID", 0) or 0),
                            ctrl.get("STATEMENT"),
                            crit.get("LABEL"),
                            int(crit.get("VALUE", 0) or 0),
                            1 if str(ctrl.get("DEPRECATED", "")).lower() in ("1", "true") else 0,
                        ),
                    )

            # Resolve CID=0 by matching statement text against controls table.
            # The controls table stores HTML entities (&apos; etc.) while
            # the policy API returns decoded text, so we decode the controls side.
            conn.execute("""
                UPDATE policy_controls SET cid = (
                    SELECT c.cid FROM controls c
                    WHERE REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                        c.statement,
                        '&apos;', char(39)),
                        '&amp;', '&'),
                        '&lt;', '<'),
                        '&gt;', '>'),
                        '&quot;', '"')
                        = policy_controls.statement
                    ORDER BY c.cid
                    LIMIT 1
                )
                WHERE policy_id = ? AND cid = 0
            """, (policy_id,))


def resolve_policy_control_cids() -> int:
    """Bulk-resolve CID=0 in policy_controls by matching statement text.

    The Qualys policy API omits CID from control objects, so we resolve
    them by matching policy_controls.statement against controls.statement
    (accounting for HTML entity differences in CID data).

    Safe to call repeatedly — only updates rows where cid=0.
    Returns the number of rows updated.
    """
    with get_db() as conn:
        return conn.execute("""
            UPDATE policy_controls SET cid = (
                SELECT c.cid FROM controls c
                WHERE REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
                    c.statement,
                    '&apos;', char(39)),
                    '&amp;', '&'),
                    '&lt;', '<'),
                    '&gt;', '>'),
                    '&quot;', '"')
                    = policy_controls.statement
                ORDER BY c.cid
                LIMIT 1
            )
            WHERE cid = 0
        """).rowcount


def search_policies(
    q: str = "",
    status: str = "",
    control_categories: list[str] | None = None,
    control_category_mode: str = "or",
    technologies: list[str] | None = None,
    technology_mode: str = "or",
    cids: list[int] | None = None,
    cid_mode: str = "or",
    control_name: str = "",
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Search policies with filters and pagination.

    Args:
        control_categories: Filter policies containing controls in these categories.
        control_category_mode: "or" (match ANY) or "and" (match ALL).
        technologies: Filter policies containing controls with these technologies.
        technology_mode: "or" (match ANY) or "and" (match ALL).
        cids: Filter policies containing these control IDs.
        cid_mode: "or" (match ANY) or "and" (match ALL).
        control_name: Filter policies containing controls matching this statement text.
    """
    with get_db() as conn:
        conditions = []
        params = []

        if q:
            conditions.append("(p.title LIKE ? OR CAST(p.policy_id AS TEXT) = ?)")
            params.extend([f"%{q}%", q])

        if status:
            conditions.append("p.status = ?")
            params.append(status)

        # Filter by control category (via policy_controls + controls)
        if control_categories:
            ph = ",".join(["?"] * len(control_categories))
            if control_category_mode == "and" and len(control_categories) > 1:
                conditions.append(f"""p.policy_id IN (
                    SELECT pc.policy_id FROM policy_controls pc
                    JOIN controls c ON pc.cid = c.cid
                    WHERE c.category IN ({ph})
                    GROUP BY pc.policy_id HAVING COUNT(DISTINCT c.category) = ?
                )""")
                params.extend(control_categories)
                params.append(len(control_categories))
            else:
                conditions.append(f"""p.policy_id IN (
                    SELECT pc.policy_id FROM policy_controls pc
                    JOIN controls c ON pc.cid = c.cid
                    WHERE c.category IN ({ph})
                )""")
                params.extend(control_categories)

        # Filter by technology (via policy_controls + control_technologies)
        if technologies:
            ph = ",".join(["?"] * len(technologies))
            if technology_mode == "and" and len(technologies) > 1:
                conditions.append(f"""p.policy_id IN (
                    SELECT pc.policy_id FROM policy_controls pc
                    JOIN control_technologies ct ON pc.cid = ct.cid
                    WHERE ct.tech_name IN ({ph})
                    GROUP BY pc.policy_id HAVING COUNT(DISTINCT ct.tech_name) = ?
                )""")
                params.extend(technologies)
                params.append(len(technologies))
            else:
                conditions.append(f"""p.policy_id IN (
                    SELECT pc.policy_id FROM policy_controls pc
                    JOIN control_technologies ct ON pc.cid = ct.cid
                    WHERE ct.tech_name IN ({ph})
                )""")
                params.extend(technologies)

        # Filter by CID
        if cids:
            ph = ",".join(["?"] * len(cids))
            if cid_mode == "and" and len(cids) > 1:
                conditions.append(
                    f"""p.policy_id IN (
                        SELECT policy_id FROM policy_controls
                        WHERE cid IN ({ph})
                        GROUP BY policy_id HAVING COUNT(DISTINCT cid) = ?
                    )"""
                )
                params.extend(cids)
                params.append(len(cids))
            else:
                conditions.append(
                    f"p.policy_id IN (SELECT policy_id FROM policy_controls WHERE cid IN ({ph}))"
                )
                params.extend(cids)

        # Filter by control statement text
        if control_name:
            conditions.append(
                "p.policy_id IN (SELECT policy_id FROM policy_controls WHERE statement LIKE ?)"
            )
            params.append(f"%{control_name}%")

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        count_sql = f"SELECT COUNT(*) FROM policies p {where}"
        total = conn.execute(count_sql, params).fetchone()[0]

        data_sql = f"""
            SELECT p.policy_id, p.title, p.created_datetime, p.created_by,
                   p.last_modified_datetime, p.last_modified_by,
                   p.last_evaluated_datetime, p.status, p.is_locked, p.source,
                   p.export_date, p.export_includes_udcs,
                   (p.export_xml IS NOT NULL) AS has_export,
                   (SELECT COUNT(*) FROM policy_controls WHERE policy_id = p.policy_id) AS control_count,
                   COALESCE(p.xml_tech_count,
                       (SELECT COUNT(DISTINCT ct.tech_name) FROM policy_controls pc2
                        JOIN control_technologies ct ON pc2.cid = ct.cid
                        WHERE pc2.policy_id = p.policy_id)) AS tech_count
            FROM policies p {where}
            ORDER BY p.last_modified_datetime DESC, p.policy_id DESC
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(data_sql, params + [per_page, offset]).fetchall()

        return {
            "results": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        }


def get_policy(policy_id: int) -> dict | None:
    """Get full policy detail with linked controls and technologies."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM policies WHERE policy_id=?", (policy_id,)).fetchone()
        if not row:
            return None

        result = dict(row)
        # Remember whether export XML exists before removing the blob
        has_export = result.get("export_xml") is not None
        export_xml_bytes = result.get("export_xml")
        result["has_export"] = has_export
        result.pop("export_xml", None)

        # Linked controls
        ctrls = conn.execute(
            """SELECT pc.*, c.category, c.sub_category, c.check_type
               FROM policy_controls pc
               LEFT JOIN controls c ON pc.cid = c.cid
               WHERE pc.policy_id=?
               ORDER BY pc.criticality_value DESC, pc.cid""",
            (policy_id,),
        ).fetchall()

        # ── Per-control technologies (batch query) ──
        cid_list = [c["cid"] for c in ctrls if c["cid"]]
        cid_techs: dict[int, list] = defaultdict(list)
        if cid_list:
            ph = ",".join(["?"] * len(cid_list))
            tech_rows = conn.execute(
                f"""SELECT ct.cid, ct.tech_id, ct.tech_name
                    FROM control_technologies ct
                    WHERE ct.cid IN ({ph})
                    ORDER BY ct.tech_name""",
                cid_list,
            ).fetchall()
            for t in tech_rows:
                cid_techs[t["cid"]].append(
                    {"tech_id": t["tech_id"], "tech_name": t["tech_name"]}
                )

        result["controls"] = []
        for c in ctrls:
            ctrl = dict(c)
            ctrl["technologies"] = cid_techs.get(c["cid"], [])
            result["controls"].append(ctrl)

        # ── Policy-level technologies (hybrid: XML primary, DB fallback) ──
        policy_techs: list[dict] = []
        tech_source = "derived"

        if has_export and export_xml_bytes:
            try:
                root = ET.fromstring(export_xml_bytes)
                policy_el = root.find(".//POLICY")
                if policy_el is not None:
                    tech_container = policy_el.find("TECHNOLOGIES")
                    if tech_container is not None:
                        for tech_el in tech_container.findall("TECHNOLOGY"):
                            tid = tech_el.findtext("ID", "")
                            tname = tech_el.findtext("NAME", "")
                            if tname:
                                policy_techs.append(
                                    {"tech_id": tid, "tech_name": tname}
                                )
                        if policy_techs:
                            tech_source = "xml"
            except ET.ParseError:
                pass

        if not policy_techs:
            # Fallback: derive from control_technologies for all CIDs
            derived = conn.execute(
                """SELECT DISTINCT ct.tech_id, ct.tech_name
                   FROM control_technologies ct
                   JOIN policy_controls pc ON ct.cid = pc.cid
                   WHERE pc.policy_id = ?
                     AND ct.tech_name IS NOT NULL AND ct.tech_name != ''
                   ORDER BY ct.tech_name""",
                (policy_id,),
            ).fetchall()
            policy_techs = [
                {"tech_id": r["tech_id"], "tech_name": r["tech_name"]}
                for r in derived
            ]

        result["technologies"] = policy_techs
        result["technology_source"] = tech_source

        # Linked mandates (derived: policy → controls → mandate_controls)
        mandates = conn.execute(
            """SELECT DISTINCT m.mandate_id, m.title, m.version, m.publisher
               FROM policy_controls pc
               JOIN mandate_controls mc ON pc.cid = mc.cid
               JOIN mandates m ON mc.mandate_id = m.mandate_id
               WHERE pc.policy_id=?
               ORDER BY m.title""",
            (policy_id,),
        ).fetchall()
        result["linked_mandates"] = [dict(m) for m in mandates]

        return result


# ═══════════════════════════════════════════════════════════════════════════
# Policy Export Storage
# ═══════════════════════════════════════════════════════════════════════════

def _count_xml_technologies(xml_data: bytes) -> int:
    """Count technologies in a policy export XML blob."""
    try:
        root = ET.fromstring(xml_data)
        policy_el = root.find(".//POLICY")
        if policy_el is not None:
            tech_container = policy_el.find("TECHNOLOGIES")
            if tech_container is not None:
                return len(tech_container.findall("TECHNOLOGY"))
    except ET.ParseError:
        pass
    return 0


def store_policy_export(policy_id: int, xml_data: bytes, includes_udcs: bool = True):
    """Store exported policy XML blob and compute technology count."""
    now = datetime.utcnow().isoformat() + "Z"
    tech_count = _count_xml_technologies(xml_data)
    with get_db() as conn:
        conn.execute(
            """UPDATE policies
               SET export_xml=?, export_date=?, export_includes_udcs=?, xml_tech_count=?
               WHERE policy_id=?""",
            (xml_data, now, 1 if includes_udcs else 0, tech_count, policy_id),
        )


def get_policy_export_xml(policy_id: int) -> bytes | None:
    """Retrieve stored policy XML for import."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT export_xml FROM policies WHERE policy_id=?", (policy_id,)
        ).fetchone()
        if row and row["export_xml"]:
            return row["export_xml"]
        return None


def get_policy_report_data(policy_id: int) -> dict | None:
    """Parse stored policy export XML into a structured section→control hierarchy.

    Returns a dict with sections (from XML), each containing controls with
    per-control technologies.  Enriched with statement text from the DB.
    Returns None if no export XML is stored for this policy.
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM policies WHERE policy_id=?", (policy_id,)
        ).fetchone()
        if not row or not row["export_xml"]:
            return None

        xml_bytes = row["export_xml"]
        policy = dict(row)
        policy.pop("export_xml", None)

        # Build CID → statement lookup from DB for enrichment
        db_controls = conn.execute(
            """SELECT pc.cid, pc.statement, pc.criticality_label, pc.criticality_value,
                      c.check_type, c.category, c.sub_category
               FROM policy_controls pc
               LEFT JOIN controls c ON pc.cid = c.cid
               WHERE pc.policy_id=?""",
            (policy_id,),
        ).fetchall()
        cid_info = {r["cid"]: dict(r) for r in db_controls}

        # Parse XML
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError:
            return None

        # Find POLICY element (may be nested under RESPONSE)
        policy_el = root.find(".//POLICY")
        if policy_el is None:
            return None

        # Policy-level technologies
        policy_techs = []
        tech_container = policy_el.find("TECHNOLOGIES")
        if tech_container is not None:
            for tech_el in tech_container.findall("TECHNOLOGY"):
                tid = tech_el.findtext("ID", "")
                tname = tech_el.findtext("NAME", "")
                if tname:
                    policy_techs.append({"id": tid, "name": tname})

        # Parse sections
        sections = []
        total_controls = 0
        sections_el = policy_el.find("SECTIONS")
        if sections_el is not None:
            for section_el in sections_el.findall("SECTION"):
                sec_number = section_el.findtext("NUMBER", "")
                sec_heading = section_el.findtext("HEADING", "")

                controls = []
                controls_el = section_el.find("CONTROLS")
                if controls_el is not None:
                    for ctrl_el in controls_el.findall("CONTROL"):
                        cid_str = ctrl_el.findtext("ID", "0")
                        cid = int(cid_str) if cid_str.isdigit() else 0
                        ref_text = ctrl_el.findtext("REFERENCE_TEXT", "")
                        disabled_str = ctrl_el.findtext("IS_CONTROL_DISABLE", "0")
                        disabled = disabled_str == "1"

                        crit_el = ctrl_el.find("CRITICALITY")
                        crit_label = ""
                        crit_value = 0
                        if crit_el is not None:
                            crit_label = crit_el.findtext("LABEL", "")
                            cv = crit_el.findtext("VALUE", "0")
                            crit_value = int(cv) if cv.isdigit() else 0

                        # Per-control technologies
                        ctrl_techs = []
                        ctrl_tech_container = ctrl_el.find("TECHNOLOGIES")
                        if ctrl_tech_container is not None:
                            for ct_el in ctrl_tech_container.findall("TECHNOLOGY"):
                                ct_id = ct_el.findtext("ID", "")
                                ct_name = ct_el.findtext("NAME", "")
                                if ct_name:
                                    ctrl_techs.append({"id": ct_id, "name": ct_name})

                        # Enrich with DB statement
                        db_info = cid_info.get(cid, {})
                        statement = db_info.get("statement", "")
                        check_type = db_info.get("check_type", "")

                        controls.append({
                            "cid": cid,
                            "reference": ref_text,
                            "criticality_label": crit_label,
                            "criticality_value": crit_value,
                            "disabled": disabled,
                            "statement": statement,
                            "check_type": check_type,
                            "technologies": ctrl_techs,
                        })
                        total_controls += 1

                sections.append({
                    "number": sec_number,
                    "heading": sec_heading,
                    "controls": controls,
                })

        return {
            "policy_id": policy["policy_id"],
            "title": policy.get("title", ""),
            "status": policy.get("status", ""),
            "is_locked": bool(policy.get("is_locked")),
            "created_datetime": policy.get("created_datetime"),
            "last_modified_datetime": policy.get("last_modified_datetime"),
            "last_evaluated_datetime": policy.get("last_evaluated_datetime"),
            "created_by": policy.get("created_by"),
            "last_modified_by": policy.get("last_modified_by"),
            "technologies": policy_techs,
            "sections": sections,
            "total_controls": total_controls,
            "total_sections": len(sections),
        }


def get_stale_exports() -> list[dict]:
    """Find policies where the data was modified after the export."""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT policy_id, title, last_modified_datetime, export_date
               FROM policies
               WHERE export_xml IS NOT NULL
                 AND export_date IS NOT NULL
                 AND last_modified_datetime > export_date
               ORDER BY title"""
        ).fetchall()
        return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════════════
# Filter Values (for multi-select dropdowns)
# ═══════════════════════════════════════════════════════════════════════════

def get_qid_filter_values(field: str, q: str = "", limit: int = 200) -> list:
    """Get distinct filter values for QID multi-select dropdowns."""
    with get_db() as conn:
        if field == "categories":
            rows = conn.execute(
                "SELECT DISTINCT category FROM vulns "
                "WHERE category IS NOT NULL AND category != '' "
                "ORDER BY category"
            ).fetchall()
            return [r["category"] for r in rows]
        elif field == "cves":
            if q:
                rows = conn.execute(
                    "SELECT DISTINCT cve_id FROM vuln_cves "
                    "WHERE cve_id LIKE ? ORDER BY cve_id LIMIT ?",
                    (f"%{q}%", limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT DISTINCT cve_id FROM vuln_cves "
                    "ORDER BY cve_id LIMIT ?",
                    (limit,),
                ).fetchall()
            return [r["cve_id"] for r in rows]
        elif field == "vuln_types":
            rows = conn.execute(
                "SELECT DISTINCT vuln_type FROM vulns "
                "WHERE vuln_type IS NOT NULL AND vuln_type != '' "
                "ORDER BY vuln_type"
            ).fetchall()
            return [r["vuln_type"] for r in rows]
        elif field == "rti_tags":
            rows = conn.execute(
                "SELECT DISTINCT rti_tag FROM vuln_rti ORDER BY rti_tag"
            ).fetchall()
            return [r["rti_tag"] for r in rows]
        elif field == "supported_modules":
            rows = conn.execute(
                "SELECT DISTINCT module_name FROM vuln_supported_modules ORDER BY module_name"
            ).fetchall()
            return [r["module_name"] for r in rows]
        return []


def get_cid_filter_values(field: str, q: str = "", limit: int = 500) -> list:
    """Get distinct filter values for CID multi-select dropdowns."""
    with get_db() as conn:
        if field == "categories":
            rows = conn.execute(
                "SELECT DISTINCT category FROM controls "
                "WHERE category IS NOT NULL AND category != '' "
                "ORDER BY category"
            ).fetchall()
            return [r["category"] for r in rows]
        elif field == "technologies":
            if q:
                rows = conn.execute(
                    "SELECT DISTINCT tech_name FROM control_technologies "
                    "WHERE tech_name IS NOT NULL AND tech_name != '' "
                    "AND tech_name LIKE ? ORDER BY tech_name LIMIT ?",
                    (f"%{q}%", limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT DISTINCT tech_name FROM control_technologies "
                    "WHERE tech_name IS NOT NULL AND tech_name != '' "
                    "ORDER BY tech_name LIMIT ?",
                    (limit,),
                ).fetchall()
            return [r["tech_name"] for r in rows]
        return []


def get_policy_filter_values(field: str, q: str = "", limit: int = 500) -> list:
    """Get distinct filter values for Policy multi-select dropdowns."""
    with get_db() as conn:
        if field == "control_categories":
            rows = conn.execute(
                """SELECT DISTINCT c.category FROM policy_controls pc
                   JOIN controls c ON pc.cid = c.cid
                   WHERE c.category IS NOT NULL AND c.category != ''
                   ORDER BY c.category"""
            ).fetchall()
            return [r["category"] for r in rows]
        elif field == "technologies":
            base = (
                "SELECT DISTINCT ct.tech_name FROM policy_controls pc "
                "JOIN control_technologies ct ON pc.cid = ct.cid "
                "WHERE ct.tech_name IS NOT NULL AND ct.tech_name != ''"
            )
            if q:
                rows = conn.execute(
                    base + " AND ct.tech_name LIKE ? ORDER BY ct.tech_name LIMIT ?",
                    (f"%{q}%", limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    base + " ORDER BY ct.tech_name LIMIT ?", (limit,)
                ).fetchall()
            return [r["tech_name"] for r in rows]
        elif field == "cids":
            base = (
                "SELECT DISTINCT pc.cid, COALESCE(c.category, '') AS category "
                "FROM policy_controls pc "
                "LEFT JOIN controls c ON pc.cid = c.cid"
            )
            if q:
                rows = conn.execute(
                    base + " WHERE CAST(pc.cid AS TEXT) LIKE ? ORDER BY pc.cid LIMIT ?",
                    (f"{q}%", limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    base + " ORDER BY pc.cid LIMIT ?", (limit,)
                ).fetchall()
            return [f"{r['cid']} — {r['category']}" if r["category"] else str(r["cid"]) for r in rows]
        elif field == "control_names":
            base = (
                "SELECT DISTINCT pc.statement FROM policy_controls pc "
                "WHERE pc.statement IS NOT NULL AND pc.statement != ''"
            )
            if q:
                rows = conn.execute(
                    base + " AND pc.statement LIKE ? ORDER BY pc.statement LIMIT ?",
                    (f"%{q}%", limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    base + " ORDER BY pc.statement LIMIT ?", (limit,)
                ).fetchall()
            return [r["statement"] for r in rows]
        return []


# ═══════════════════════════════════════════════════════════════════════════
# Mandates (Compliance Frameworks)
# ═══════════════════════════════════════════════════════════════════════════

def upsert_mandate(mandate: dict):
    """Insert or update a mandate from parsed Qualys framework data."""
    mandate_id = int(mandate.get("ID", 0) or mandate.get("MANDATE_ID", 0))
    if not mandate_id:
        return

    with get_db() as conn:
        conn.execute(
            """INSERT INTO mandates (
                mandate_id, title, version, publisher,
                released_date, last_modified_date, description
            ) VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(mandate_id) DO UPDATE SET
              title=excluded.title,
              version=excluded.version,
              publisher=excluded.publisher,
              released_date=excluded.released_date,
              last_modified_date=excluded.last_modified_date,
              description=excluded.description""",
            (
                mandate_id,
                mandate.get("TITLE"),
                mandate.get("VERSION"),
                mandate.get("PUBLISHER"),
                mandate.get("RELEASED_DATE"),
                mandate.get("LAST_MODIFIED_DATE"),
                mandate.get("DESCRIPTION"),
            ),
        )

        # Mandate-Control associations
        ctrl_container = mandate.get("CONTROL_LIST", {}) or {}
        ctrls = _ensure_list(ctrl_container.get("CONTROL"))
        if ctrls:
            conn.execute("DELETE FROM mandate_controls WHERE mandate_id=?", (mandate_id,))
            for ctrl in ctrls:
                if isinstance(ctrl, dict):
                    cid = int(ctrl.get("CID", 0) or ctrl.get("ID", 0) or 0)
                    if cid:
                        conn.execute(
                            """INSERT INTO mandate_controls
                               (mandate_id, cid, section_id, section_title)
                               VALUES (?,?,?,?)""",
                            (
                                mandate_id,
                                cid,
                                ctrl.get("SECTION_ID") or ctrl.get("SECTION"),
                                ctrl.get("SECTION_TITLE") or ctrl.get("SECTION_NAME"),
                            ),
                        )


def upsert_mandate_control(mandate_id: int, cid: int, section_id: str | None = None,
                           section_title: str | None = None):
    """Link a single control to a mandate (used during CID sync)."""
    with get_db() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO mandate_controls
               (mandate_id, cid, section_id, section_title)
               VALUES (?,?,?,?)""",
            (mandate_id, cid, section_id, section_title),
        )



def search_mandates(
    q: str = "",
    publishers: list[str] | None = None,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Search mandates with FTS, filters, and pagination."""
    with get_db() as conn:
        conditions = []
        params: list = []

        if q:
            conditions.append(
                "m.mandate_id IN (SELECT mandate_id FROM mandates_fts WHERE mandates_fts MATCH ?)"
            )
            params.append(_fts5_safe(q))

        if publishers:
            placeholders = ",".join(["?"] * len(publishers))
            conditions.append(f"m.publisher IN ({placeholders})")
            params.extend(publishers)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        total = conn.execute(f"SELECT COUNT(*) FROM mandates m {where}", params).fetchone()[0]

        rows = conn.execute(
            f"""SELECT m.*,
                   (SELECT COUNT(*) FROM mandate_controls WHERE mandate_id = m.mandate_id) AS control_count
                FROM mandates m {where}
                ORDER BY m.title ASC, m.mandate_id DESC
                LIMIT ? OFFSET ?""",
            params + [per_page, offset],
        ).fetchall()

        return {
            "results": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        }


def get_mandate(mandate_id: int) -> dict | None:
    """Get full mandate detail with linked controls and derived policies."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM mandates WHERE mandate_id=?", (mandate_id,)).fetchone()
        if not row:
            return None

        result = dict(row)

        # Linked controls (with detail from controls table)
        ctrls = conn.execute(
            """SELECT mc.cid, mc.section_id, mc.section_title,
                      c.category, c.sub_category, c.statement,
                      c.criticality_label, c.criticality_value
               FROM mandate_controls mc
               LEFT JOIN controls c ON mc.cid = c.cid
               WHERE mc.mandate_id=?
               ORDER BY mc.section_id, mc.cid""",
            (mandate_id,),
        ).fetchall()
        result["controls"] = [dict(c) for c in ctrls]

        # Derived policies (policies that contain any of this mandate's controls)
        pols = conn.execute(
            """SELECT DISTINCT p.policy_id, p.title, p.status, p.is_locked
               FROM mandate_controls mc
               JOIN policy_controls pc ON mc.cid = pc.cid
               JOIN policies p ON pc.policy_id = p.policy_id
               WHERE mc.mandate_id=?
               ORDER BY p.title""",
            (mandate_id,),
        ).fetchall()
        result["policies"] = [dict(p) for p in pols]

        return result


def get_mandate_filter_values(field: str, q: str = "", limit: int = 200) -> list:
    """Get distinct filter values for Mandate multi-select dropdowns."""
    with get_db() as conn:
        if field == "publishers":
            rows = conn.execute(
                "SELECT DISTINCT publisher FROM mandates "
                "WHERE publisher IS NOT NULL AND publisher != '' "
                "ORDER BY publisher"
            ).fetchall()
            return [r["publisher"] for r in rows]
        return []


# ═══════════════════════════════════════════════════════════════════════════
# Dashboard & Analytics
# ═══════════════════════════════════════════════════════════════════════════

def get_dashboard_stats() -> dict:
    """Aggregate statistics for the Dashboard tab."""
    with get_db() as conn:
        # QID severity distribution
        severity = {}
        for row in conn.execute(
            "SELECT severity_level, COUNT(*) AS cnt FROM vulns GROUP BY severity_level"
        ).fetchall():
            severity[row["severity_level"]] = row["cnt"]

        # CID criticality distribution
        criticality = {}
        for row in conn.execute(
            "SELECT criticality_label, COUNT(*) AS cnt FROM controls "
            "WHERE criticality_label IS NOT NULL GROUP BY criticality_label"
        ).fetchall():
            criticality[row["criticality_label"]] = row["cnt"]

        # Patchable distribution
        patch_rows = conn.execute(
            "SELECT patchable, COUNT(*) AS cnt FROM vulns GROUP BY patchable"
        ).fetchall()
        patchable = {"yes": 0, "no": 0}
        for row in patch_rows:
            if row["patchable"] == 1:
                patchable["yes"] = row["cnt"]
            else:
                patchable["no"] = row["cnt"]

        # Top 15 QID categories
        cat_rows = conn.execute(
            "SELECT category, COUNT(*) AS cnt FROM vulns "
            "WHERE category IS NOT NULL AND category != '' "
            "GROUP BY category ORDER BY cnt DESC LIMIT 15"
        ).fetchall()
        categories_top15 = [{"name": r["category"], "count": r["cnt"]} for r in cat_rows]

        # Compliance coverage
        mandate_count = conn.execute("SELECT COUNT(*) FROM mandates").fetchone()[0]
        total_controls = conn.execute("SELECT COUNT(*) FROM controls").fetchone()[0]
        controls_in_mandates = conn.execute(
            "SELECT COUNT(DISTINCT cid) FROM mandate_controls"
        ).fetchone()[0]
        total_policies = conn.execute("SELECT COUNT(*) FROM policies").fetchone()[0]
        policies_with_controls = conn.execute(
            "SELECT COUNT(DISTINCT policy_id) FROM policy_controls"
        ).fetchone()[0]

        return {
            "severity": severity,
            "criticality": criticality,
            "patchable": patchable,
            "categories_top15": categories_top15,
            "compliance": {
                "mandate_count": mandate_count,
                "total_controls": total_controls,
                "controls_in_mandates": controls_in_mandates,
                "total_policies": total_policies,
                "policies_with_controls": policies_with_controls,
            },
        }


def get_mandate_stats() -> dict:
    """Quick mandate/framework statistics for sync log summaries."""
    with get_db() as conn:
        mandate_count = conn.execute("SELECT COUNT(*) FROM mandates").fetchone()[0]
        link_count = conn.execute("SELECT COUNT(*) FROM mandate_controls").fetchone()[0]
        unique_cids = conn.execute("SELECT COUNT(DISTINCT cid) FROM mandate_controls").fetchone()[0]
        top_mandates = conn.execute(
            """SELECT m.title, COUNT(mc.cid) AS ctrl_count
               FROM mandates m JOIN mandate_controls mc ON m.mandate_id = mc.mandate_id
               GROUP BY m.mandate_id ORDER BY ctrl_count DESC LIMIT 5"""
        ).fetchall()
        return {
            "mandate_count": mandate_count,
            "mandate_control_links": link_count,
            "unique_cids_in_mandates": unique_cids,
            "top_mandates": [{"title": r["title"], "controls": r["ctrl_count"]} for r in top_mandates],
        }


def get_mandate_compliance_map(mandate_id: int | None = None) -> list[dict]:
    """Flattened mandate → control → policy mapping for export."""
    with get_db() as conn:
        sql = """
            SELECT m.mandate_id, m.title AS mandate_title, m.publisher,
                   mc.section_id, mc.section_title,
                   c.cid, c.statement, c.criticality_label,
                   p.policy_id, p.title AS policy_title
            FROM mandates m
            JOIN mandate_controls mc ON m.mandate_id = mc.mandate_id
            JOIN controls c ON mc.cid = c.cid
            LEFT JOIN policy_controls pc ON c.cid = pc.cid
            LEFT JOIN policies p ON pc.policy_id = p.policy_id
        """
        params: list = []
        if mandate_id is not None:
            sql += " WHERE m.mandate_id = ?"
            params.append(mandate_id)
        sql += " ORDER BY m.title, mc.section_id, c.cid, p.policy_id"
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


# ═══════════════════════════════════════════════════════════════════════════
# Database Maintenance Config
# ═══════════════════════════════════════════════════════════════════════════

def get_maintenance_config() -> dict:
    """Return the single-row maintenance configuration."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM db_maintenance_config WHERE id = 1").fetchone()
        if row:
            return dict(row)
        return {"id": 1, "day_of_week": 0, "hour": 0, "minute": 0,
                "timezone": "", "enabled": 1}


def save_maintenance_config(day_of_week: int, hour: int, minute: int,
                            timezone: str) -> dict:
    """Update maintenance schedule configuration."""
    with get_db() as conn:
        conn.execute(
            """UPDATE db_maintenance_config
               SET day_of_week=?, hour=?, minute=?, timezone=?
               WHERE id=1""",
            (day_of_week, hour, minute, timezone),
        )
    return get_maintenance_config()


def update_maintenance_last_run(status: str, error: str | None,
                                duration: float) -> None:
    """Record the result of the last maintenance run."""
    from datetime import datetime
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    with get_db() as conn:
        conn.execute(
            """UPDATE db_maintenance_config
               SET last_run=?, last_status=?, last_error=?, last_duration_s=?
               WHERE id=1""",
            (now, status, error, round(duration, 1)),
        )


# ── Auto-Update Configuration ────────────────────────────────────────────

def get_auto_update_config() -> dict:
    """Get the auto-update schedule configuration."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM auto_update_config WHERE id = 1").fetchone()
        if row:
            return dict(row)
    return {"enabled": 0, "day_of_week": 6, "hour": 0, "minute": 0, "timezone": ""}


def save_auto_update_config(enabled: bool, day_of_week: int, hour: int,
                             minute: int, timezone: str) -> dict:
    """Save auto-update schedule configuration."""
    with get_db() as conn:
        conn.execute(
            """UPDATE auto_update_config
               SET enabled=?, day_of_week=?, hour=?, minute=?, timezone=?
               WHERE id=1""",
            (1 if enabled else 0, day_of_week, hour, minute, timezone),
        )
    return get_auto_update_config()


def update_auto_update_last_check(status: str, error: str | None = None) -> None:
    """Record the result of the last auto-update check."""
    from datetime import datetime
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    with get_db() as conn:
        conn.execute(
            """UPDATE auto_update_config
               SET last_check=?, last_status=?, last_error=?
               WHERE id=1""",
            (now, status, error),
        )
