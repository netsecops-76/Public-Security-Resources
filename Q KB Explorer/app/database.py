"""
Q KB Explorer — SQLite Database Layer
Built by netsecops-76

Schema for QIDs, CIDs, Policies with FTS5 full-text search.
WAL mode for concurrent reads during sync operations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
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

# Pre-compiled bleach Cleaner — built once at import, reused on every
# call. The previous implementation called `bleach.clean()` per record,
# which rebuilt the sanitizer (tag/attribute filters, html5lib parser
# config) on every call. With three sanitize calls per QID and 200K+
# QIDs in a Full Sync, that was 600K+ Cleaner allocations of pure
# overhead. `Cleaner` instances are documented as reusable and
# thread-safe for `clean()`.
_BLEACH_CLEANER = bleach.Cleaner(
    tags=_SAFE_TAGS, attributes=_SAFE_ATTRS, strip=True,
)


def _sanitize_html(value: str | None) -> str | None:
    """Strip unsafe HTML from Qualys KB fields while preserving formatting."""
    if not value:
        return value
    return _BLEACH_CLEANER.clean(value)

logger = logging.getLogger(__name__)


def _init_progress(msg: str) -> None:
    """Print init_db migration progress to stderr.

    `logger` doesn't help here: init_db runs inside the entrypoint
    pre-flight `python3 -c "from app.main import app"`, before gunicorn
    starts. The logger has no handler attached at that point, so any
    `logger.info(...)` call during init_db is silently dropped from
    `docker logs`. Admins watching `docker logs -f` see frozen output
    and can't tell whether a multi-minute migration is making progress
    or has hung. This helper bypasses logging and writes directly to
    stderr with `flush=True` so progress is visible in real time.
    """
    print(f"[QKBE init] {msg}", file=sys.stderr, flush=True)


# Marker UPDATE batch size for the v2.4 threat_backfill_done one-time
# migration. Sized so per-batch commits keep the WAL file from growing
# past a few hundred MB on a 200K-row table. Smaller batches mean more
# checkpoint overhead but better resumability across container kills;
# 5000 is a good middle ground.
_MARKER_BATCH_SIZE = 5000

DB_PATH = os.environ.get("QKBE_DB_PATH", "/data/qkbe.db")
_local = threading.local()


# ═══════════════════════════════════════════════════════════════════════════
# Connection Management
# ═══════════════════════════════════════════════════════════════════════════

# Busy timeout (seconds) for write-lock contention. Two parallel syncs
# (e.g. QIDs + Policies running at once) compete for SQLite's single
# writer; a long timeout lets the loser wait politely instead of
# erroring with 'database is locked'. 120s covers any realistic
# transaction wait under our current upsert sizes.
_SQLITE_BUSY_TIMEOUT_SEC = 120

# Retry policy for transient "database is locked" errors that slip past
# the busy timeout. Exponential backoff capped at _LOCK_RETRY_MAX.
_LOCK_RETRY_MAX = 4
_LOCK_RETRY_BASE_MS = 100


def _get_conn() -> sqlite3.Connection:
    """Thread-local connection tuned for concurrent QID + Policy syncs.

    PRAGMAs:
      journal_mode=WAL           multi-reader / single-writer concurrency
      synchronous=NORMAL         safe under WAL, ~3x faster commits
      wal_autocheckpoint=1000    keep WAL bounded during heavy syncs
      cache_size=-65536          64 MB page cache (was the SQLite default ~2 MB)
      foreign_keys=ON            enforce ON DELETE CASCADE chains
    """
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, timeout=_SQLITE_BUSY_TIMEOUT_SEC)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn.execute("PRAGMA wal_autocheckpoint=1000")
        _local.conn.execute("PRAGMA cache_size=-65536")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


@contextmanager
def get_db():
    """Yield a connection and commit on success, rollback on error.

    Wraps the body in an exponential-backoff retry loop that catches
    sqlite3.OperationalError 'database is locked'. The 120s busy_timeout
    on the connection should already absorb most contention; this retry
    is a defensive backstop for the worst-case race.
    """
    import time as _time
    attempt = 0
    while True:
        conn = _get_conn()
        try:
            yield conn
            conn.commit()
            return
        except sqlite3.OperationalError as e:
            try:
                conn.rollback()
            except Exception:
                pass
            msg = str(e).lower()
            if "database is locked" in msg or "database is busy" in msg:
                if attempt >= _LOCK_RETRY_MAX:
                    logger.warning("DB lock retry exhausted after %d attempts: %s",
                                   attempt, e)
                    raise
                delay_ms = _LOCK_RETRY_BASE_MS * (2 ** attempt)
                logger.info("DB locked — retrying in %d ms (attempt %d/%d)",
                            delay_ms, attempt + 1, _LOCK_RETRY_MAX)
                _time.sleep(delay_ms / 1000.0)
                attempt += 1
                continue
            raise
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise


@contextmanager
def _maybe_db(conn):
    """Yield the supplied connection if one is given, otherwise open a new
    transaction via get_db.

    Lets the upsert helpers be called either standalone (one txn per call)
    or batched inside an outer transaction (caller commits after many
    upserts). Batching is what makes large QID/CID/Policy/Tag/Patch sync
    chunks fast — one fsync per chunk instead of one per record.
    """
    if conn is not None:
        yield conn
        return
    with get_db() as c:
        yield c


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

        # Add disabled column to vulns if missing (idempotent migration).
        vulns_cols = {r[1] for r in conn.execute("PRAGMA table_info(vulns)").fetchall()}
        if "disabled" not in vulns_cols:
            conn.execute("ALTER TABLE vulns ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0")

        # Tag provenance columns — track where tags came from so we know
        # whether to update or create when migrating to a destination.
        tags_cols = {r[1] for r in conn.execute("PRAGMA table_info(tags)").fetchall()}
        if "source_platform" not in tags_cols:
            conn.execute("ALTER TABLE tags ADD COLUMN source_platform TEXT")
        if "source_subscription" not in tags_cols:
            conn.execute("ALTER TABLE tags ADD COLUMN source_subscription TEXT")
        # Tag origin classification: rule_based, static, connector, system
        if "tag_origin" not in tags_cols:
            conn.execute("ALTER TABLE tags ADD COLUMN tag_origin TEXT")
        # Always backfill tag_origin for tags missing it (imported, synced
        # before classification existed, or purge+re-sync)
        needs_origin = conn.execute(
            "SELECT COUNT(*) FROM tags WHERE tag_origin IS NULL"
        ).fetchone()[0]
        if needs_origin > 0:
            _backfill_tag_origin(conn)
            conn.commit()

        # Threat intelligence computed columns for fast filtering.
        # Extracted from threat_intelligence_json during upsert.
        if "threat_active_attacks" not in vulns_cols:
            conn.execute("ALTER TABLE vulns ADD COLUMN threat_active_attacks INTEGER NOT NULL DEFAULT 0")
        if "threat_exploit_public" not in vulns_cols:
            conn.execute("ALTER TABLE vulns ADD COLUMN threat_exploit_public INTEGER NOT NULL DEFAULT 0")
        if "threat_easy_exploit" not in vulns_cols:
            conn.execute("ALTER TABLE vulns ADD COLUMN threat_easy_exploit INTEGER NOT NULL DEFAULT 0")
        if "threat_malware" not in vulns_cols:
            conn.execute("ALTER TABLE vulns ADD COLUMN threat_malware INTEGER NOT NULL DEFAULT 0")
        if "threat_rce" not in vulns_cols:
            conn.execute("ALTER TABLE vulns ADD COLUMN threat_rce INTEGER NOT NULL DEFAULT 0")
        if "threat_priv_escalation" not in vulns_cols:
            conn.execute("ALTER TABLE vulns ADD COLUMN threat_priv_escalation INTEGER NOT NULL DEFAULT 0")
        if "threat_cisa_kev" not in vulns_cols:
            conn.execute("ALTER TABLE vulns ADD COLUMN threat_cisa_kev INTEGER NOT NULL DEFAULT 0")
        if "exploit_count" not in vulns_cols:
            conn.execute("ALTER TABLE vulns ADD COLUMN exploit_count INTEGER NOT NULL DEFAULT 0")
        if "malware_count" not in vulns_cols:
            conn.execute("ALTER TABLE vulns ADD COLUMN malware_count INTEGER NOT NULL DEFAULT 0")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_threat_active ON vulns(threat_active_attacks)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_threat_cisa ON vulns(threat_cisa_kev)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_exploit_public ON vulns(threat_exploit_public)")

        # threat_backfill_done — one-time marker added in v2.4 to stop
        # init_db from re-walking 40K+ rows on every container start
        # just because they have a threat_intelligence_json blob with no
        # recognized tags inside. Migration:
        #   1) ALTER TABLE adds the column on legacy DBs
        #   2) Mark rows already classified (any flag column non-zero,
        #      or no JSON to backfill from) as done. After this, only
        #      rows that genuinely need reclassification show up to the
        #      backfill detection query.
        #   3) Run the streaming backfill. New rows get done=1 directly
        #      from upsert_vuln, so this only ever loads work caused by
        #      a schema upgrade — never the steady-state cost.
        # v2.4 source_hash — see schema comment. Add on legacy DBs.
        if "source_hash" not in vulns_cols:
            conn.execute("ALTER TABLE vulns ADD COLUMN source_hash TEXT")

        if "threat_backfill_done" not in vulns_cols:
            conn.execute(
                "ALTER TABLE vulns ADD COLUMN threat_backfill_done "
                "INTEGER NOT NULL DEFAULT 0"
            )
            conn.commit()

        # Belt-and-suspenders: any row whose flag columns are already
        # populated (or has no JSON to derive from) does not need
        # backfill. Mark them so we don't waste time.
        #
        # v2.4.1: chunked into LIMIT batches with per-batch commits.
        # The pre-v2.4.1 single-transaction UPDATE on a 3.3 GB / 208K
        # row table held a multi-hundred-MB write transaction open for
        # 20+ minutes on slow storage (Hyper-V disk over Azure RHEL
        # VM). No checkpoint could fire until the UPDATE committed, so
        # the WAL grew past 900 MB before any progress flushed to the
        # main DB file and gunicorn was blocked the entire time on
        # the entrypoint pre-flight import.
        #
        # The chunked path:
        #   - LIMIT 5000 per batch — bounds WAL growth between commits
        #   - Per-batch commit — autocheckpoint fires, WAL drains
        #   - Filter on threat_backfill_done = 0 — naturally resumable
        #     across container kills (already-marked rows skip)
        #   - Loop until UPDATE matches 0 rows — drains the queue
        #     even if matched rows are interleaved across batches
        # The marker column itself is the resume signal, so a kill
        # mid-loop costs at most one batch (5000 rows) of redo work.
        _init_progress("v2.4 threat_backfill_done marker: starting batched UPDATE")
        marked = 0
        batch_num = 0
        while True:
            batch_num += 1
            rowcount = conn.execute(
                """UPDATE vulns SET threat_backfill_done = 1
                   WHERE rowid IN (
                       SELECT rowid FROM vulns
                       WHERE threat_backfill_done = 0
                         AND (
                                threat_active_attacks > 0
                             OR threat_exploit_public > 0
                             OR threat_easy_exploit > 0
                             OR threat_malware > 0
                             OR threat_rce > 0
                             OR threat_priv_escalation > 0
                             OR threat_cisa_kev > 0
                             OR exploit_count > 0
                             OR malware_count > 0
                             OR threat_intelligence_json IS NULL
                             OR threat_intelligence_json = 'null'
                         )
                       LIMIT ?
                   )""",
                (_MARKER_BATCH_SIZE,),
            ).rowcount
            conn.commit()
            if rowcount <= 0:
                break
            marked += rowcount
            _init_progress(
                f"  marker batch {batch_num}: +{rowcount} rows (total {marked})"
            )
        _init_progress(f"v2.4 marker: complete ({marked} rows marked)")

        # Now run streaming backfill for any remaining un-classified
        # rows. Only counts rows that are actually candidates — no JSON
        # → no work, marker=1 → no work, flags already set → no work.
        needs_backfill = conn.execute(
            "SELECT COUNT(*) FROM vulns "
            "WHERE threat_intelligence_json IS NOT NULL "
            "AND threat_intelligence_json != 'null' "
            "AND threat_backfill_done = 0"
        ).fetchone()[0]
        if needs_backfill > 0:
            _init_progress(
                f"streaming threat-column backfill: {needs_backfill} rows queued"
            )
            logger.info("[Init] Threat-column backfill: %d rows queued",
                        needs_backfill)
            _backfill_threat_columns(conn, total=needs_backfill)
            _init_progress("streaming threat-column backfill: complete")
            logger.info("[Init] Threat-column backfill: complete")

        # Index is created here (not in _SCHEMA_SQL) because executescript
        # runs the whole schema in order — putting CREATE INDEX next to the
        # CREATE TABLE breaks upgrades where the table exists but the
        # column doesn't yet. Idempotent IF NOT EXISTS handles both fresh
        # and upgraded databases.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_disabled ON vulns(disabled)")

        # Add last_missing_count to sync_state if missing (idempotent).
        # Populated by full-sync and backfill verification steps so the
        # UI can hide Backfill when there's nothing known to be missing.
        sync_state_cols = {r[1] for r in conn.execute("PRAGMA table_info(sync_state)").fetchall()}
        if "last_missing_count" not in sync_state_cols:
            conn.execute("ALTER TABLE sync_state ADD COLUMN last_missing_count INTEGER")

        # auto_update_config — ensure last_version exists. Some volumes
        # carry an earlier 9-column version of this table (without
        # last_version) and CREATE TABLE IF NOT EXISTS would have skipped
        # the new schema on those installs.
        au_cols = {r[1] for r in conn.execute("PRAGMA table_info(auto_update_config)").fetchall()}
        if au_cols and "last_version" not in au_cols:
            conn.execute("ALTER TABLE auto_update_config ADD COLUMN last_version TEXT")

        # Migrate any pre-existing kb_universe rows into the generalized
        # sync_universe table so the QIDs row keeps its persisted
        # universe across the schema upgrade.
        try:
            existing_universe = conn.execute(
                "SELECT COUNT(*) FROM sync_universe WHERE data_type='qids'"
            ).fetchone()[0]
            legacy_universe = conn.execute(
                "SELECT COUNT(*) FROM kb_universe"
            ).fetchone()[0]
            if existing_universe == 0 and legacy_universe > 0:
                conn.execute(
                    "INSERT OR IGNORE INTO sync_universe (data_type, item_id, last_seen_at) "
                    "SELECT 'qids', CAST(qid AS TEXT), last_seen_at FROM kb_universe"
                )
                logger.info("Migrated %d QIDs from kb_universe → sync_universe",
                            legacy_universe)
        except sqlite3.OperationalError:
            # Either table missing on the executescript pass; harmless.
            pass

        # Drop the FOREIGN KEY on tag_exports.tag_id if it's still
        # there from older databases. We need to import JSON bundles
        # for tags that were never synced into THIS local DB (the
        # cross-env migration use case), and the FK was blocking that.
        # SQLite has no DROP CONSTRAINT, so rebuild via the standard
        # rename-copy-drop dance. Idempotent: we only run when the
        # current schema actually carries the FK.
        try:
            fk_rows = conn.execute("PRAGMA foreign_key_list(tag_exports)").fetchall()
            if any(row[2] == "tags" for row in fk_rows):
                logger.info("Rebuilding tag_exports to drop legacy FK on tags(tag_id)")
                conn.executescript(
                    """
                    CREATE TABLE tag_exports_new (
                        tag_id               INTEGER PRIMARY KEY,
                        json_blob            BLOB NOT NULL,
                        exported_at          TEXT NOT NULL,
                        source_credential_id TEXT
                    );
                    INSERT INTO tag_exports_new (tag_id, json_blob, exported_at, source_credential_id)
                        SELECT tag_id, json_blob, exported_at, source_credential_id
                        FROM tag_exports;
                    DROP TABLE tag_exports;
                    ALTER TABLE tag_exports_new RENAME TO tag_exports;
                    """
                )
        except sqlite3.OperationalError:
            pass

        # ── Re-evaluate Tags.is_user_created for any existing rows ──
        # Two-step classifier:
        #   1. Baseline from direct signals (reservedType, createdBy, rule)
        #   2. Propagate user-created up to parents that hold user children
        # Pure SQL on existing rows — no re-sync required for accurate
        # classification of already-synced tags.
        try:
            # Add classification_override column on existing DBs
            tag_cols = {r[1] for r in conn.execute("PRAGMA table_info(tags)").fetchall()}
            if "classification_override" not in tag_cols:
                conn.execute("ALTER TABLE tags ADD COLUMN classification_override TEXT")
            # Editability flag and its override (separate axis from
            # classification — see _is_editable() for the derivation).
            if "is_editable" not in tag_cols:
                conn.execute("ALTER TABLE tags ADD COLUMN is_editable INTEGER NOT NULL DEFAULT 0")
            if "editability_override" not in tag_cols:
                conn.execute("ALTER TABLE tags ADD COLUMN editability_override TEXT")
            conn.execute(
                """UPDATE tags SET is_user_created = CASE
                       WHEN reserved_type IS NOT NULL AND reserved_type != '' THEN 0
                       WHEN created_by IS NOT NULL AND created_by != ''
                            AND LOWER(created_by) NOT IN ('system', 'qualys', 'auto')
                            THEN 1
                       WHEN rule_type IS NOT NULL AND rule_type != '' THEN 1
                       ELSE 0
                   END"""
            )
            _propagate_user_classification(conn)
            # Re-derive is_editable for already-synced rows so existing
            # databases get the right defaults without a re-sync.
            conn.execute(
                """UPDATE tags SET is_editable = CASE
                       WHEN is_user_created = 1 THEN 1
                       WHEN reserved_type IS NULL OR reserved_type = '' THEN 1
                       WHEN UPPER(reserved_type) IN (
                           'OPERATING_SYSTEM','OS','AWS_REGION','AZURE_REGION',
                           'GCP_PROJECT','CLOUD_PROVIDER','ASSET_TYPE',
                           'TECHNOLOGY','HARDWARE','PLATFORM',
                           'AGENT_VERSION','SCANNER','SUBSCRIPTION'
                       ) THEN 0
                       ELSE 1
                   END"""
            )
        except sqlite3.OperationalError:
            # tags table may not exist yet on a brand-new DB
            pass

        # Seed / refresh built-in tag library entries. is_hidden is
        # preserved across re-seeds so the operator's "I don't want
        # to see this one" choice survives upgrades. Failures here
        # don't block startup — the rest of the app works fine
        # without library entries; user can re-seed later.
        try:
            count = seed_library_builtins()
            if count:
                logger.info("Seeded / refreshed %d tag library built-ins", count)
        except Exception as e:
            logger.warning("Tag library seed failed (non-fatal): %s", e)

    # ── Post-init classification fix (separate connection) ──
    # Must run OUTSIDE the init_db 'with get_db()' block because
    # executescript's implicit transaction management can prevent commits.
    _fix_tag_classification()


def _fix_tag_classification():
    """Ensure all tags without reserved_type are marked user-created.

    Uses a dedicated connection with explicit commit to guarantee
    persistence regardless of how init_db's transaction state ended.
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "UPDATE tags SET is_user_created = 1 "
            "WHERE is_user_created = 0 "
            "AND (reserved_type IS NULL OR reserved_type = '') "
            "AND (created_by IS NULL OR created_by = '' "
            "     OR LOWER(created_by) NOT IN ('system','qualys','auto'))"
        )
        conn.commit()
    finally:
        conn.close()


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
    disabled           INTEGER NOT NULL DEFAULT 0,
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
    software_list_json TEXT,
    -- One-time marker: set to 1 once the row's threat flag columns have
    -- been derived from the JSON (either at upsert time, or by the
    -- _backfill_threat_columns migration for legacy rows). Detection
    -- query in init_db joins on this so rows that legitimately have no
    -- recognized threat tags don't get re-walked on every container
    -- start. Without this column, init_db would re-process tens of
    -- thousands of rows on every restart for no gain.
    threat_backfill_done INTEGER NOT NULL DEFAULT 0,
    -- v2.4: SHA-256 of the canonicalized source dict from upsert_vuln,
    -- used by Delta sync to skip the entire write path when nothing
    -- about a QID has changed since the last sync. Compares before any
    -- INSERT OR REPLACE / child-table DELETE+INSERT / FTS5 maintenance.
    -- NULL on legacy rows; the next sync that touches a row populates
    -- it.
    source_hash TEXT
);
-- Sync universe — every id Qualys reported during the most recent
-- pre-count pass for a given data type ('qids', 'cids', 'policies').
-- Source of truth for "what should exist locally". Backfill and the
-- full-sync verify step both diff this against the live tables; the
-- UI uses the diff size to drive the Backfill Missing button (count
-- inline when > 0, hidden when 0).
--
-- item_id is TEXT so the same table works for integer-keyed types
-- (QIDs, CIDs, policy IDs) and any future string-keyed type.
CREATE TABLE IF NOT EXISTS sync_universe (
    data_type    TEXT NOT NULL,
    item_id      TEXT NOT NULL,
    last_seen_at TEXT,
    PRIMARY KEY (data_type, item_id)
);
CREATE INDEX IF NOT EXISTS idx_sync_universe_dt ON sync_universe(data_type);

-- Legacy single-purpose KB universe — kept as a no-op CREATE so old
-- databases don't fail on schema run. Data has migrated into
-- sync_universe via init_db.
CREATE TABLE IF NOT EXISTS kb_universe (
    qid          INTEGER PRIMARY KEY,
    last_seen_at TEXT
);

-- NOTE: idx_vulns_disabled is created by the migration block in init_db()
-- after the ALTER TABLE that adds the disabled column on pre-existing DBs.
-- Defining it here would fail on upgrade because CREATE TABLE IF NOT EXISTS
-- is a no-op on the existing table, so the column wouldn't exist yet.

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
    credential_id          TEXT,
    last_missing_count     INTEGER
);

-- Insert default sync state rows
INSERT OR IGNORE INTO sync_state (data_type) VALUES ('qids');
INSERT OR IGNORE INTO sync_state (data_type) VALUES ('cids');
INSERT OR IGNORE INTO sync_state (data_type) VALUES ('policies');
INSERT OR IGNORE INTO sync_state (data_type) VALUES ('mandates');
INSERT OR IGNORE INTO sync_state (data_type) VALUES ('tags');

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

-- Automatic application update schedule (single-row table)
CREATE TABLE IF NOT EXISTS auto_update_config (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    enabled         INTEGER DEFAULT 0,
    day_of_week     INTEGER DEFAULT 6,  -- 0=Sunday..6=Saturday
    hour            INTEGER DEFAULT 0,
    minute          INTEGER DEFAULT 0,
    timezone        TEXT DEFAULT '',
    last_check      TEXT,
    last_status     TEXT,                -- 'up_to_date' | 'updated' | 'error'
    last_error      TEXT,
    last_version    TEXT
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

-- Tags (Qualys Asset Tags via QPS REST /qps/rest/2.0/.../am/tag)
CREATE TABLE IF NOT EXISTS tags (
    tag_id               INTEGER PRIMARY KEY,
    name                 TEXT NOT NULL,
    color                TEXT,
    parent_tag_id        INTEGER,
    rule_type            TEXT,
    rule_text            TEXT,
    criticality          INTEGER,
    description          TEXT,
    created              TEXT,
    modified             TEXT,
    reserved_type        TEXT,
    created_by           TEXT,
    is_user_created      INTEGER NOT NULL DEFAULT 0,
    classification_override TEXT,            -- NULL = auto, 'user', or 'system'
    -- Editability is a separate axis from classification: some Qualys
    -- system tags (Internet Facing Assets, Business Units, etc.)
    -- accept rule edits even though reservedType is set, while others
    -- (OS, AWS_REGION, technology taxonomies) are truly locked.
    -- Auto-derived during upsert; manual override available per-tag
    -- for cases where the API metadata is ambiguous.
    is_editable          INTEGER NOT NULL DEFAULT 0,
    editability_override TEXT,                -- NULL = auto, 'editable', or 'locked'
    source_credential_id TEXT,
    last_synced          TEXT,
    raw_json             TEXT
);

CREATE INDEX IF NOT EXISTS idx_tags_parent ON tags(parent_tag_id);
CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name);
CREATE INDEX IF NOT EXISTS idx_tags_user ON tags(is_user_created);
CREATE INDEX IF NOT EXISTS idx_tags_reserved ON tags(reserved_type);
CREATE INDEX IF NOT EXISTS idx_tags_rule_type ON tags(rule_type);

-- Tag exports (offline JSON storage for Phase 2 cross-environment
-- migration). NO foreign key on tag_id — operators must be able to
-- import a JSON bundle for a tag that was never synced into THIS
-- local DB (e.g. moving a bundle between machines). The export
-- table joins LEFT against tags for display purposes only.
CREATE TABLE IF NOT EXISTS tag_exports (
    tag_id               INTEGER PRIMARY KEY,
    json_blob            BLOB NOT NULL,
    exported_at          TEXT NOT NULL,
    source_credential_id TEXT
);

-- ── Tag library (Phase 4: Custom Library + Apply) ──
-- A curated bank of tag definitions the operator can apply into a
-- Qualys environment as a new tag. Two flavors live in the same
-- table:
--   * is_builtin = 1 — ships with the app, can be hidden but not
--                      edited or deleted. Re-seeded on startup if
--                      missing from a fresh DB; updates to seed
--                      content are applied on each init_db without
--                      clobbering user customizations to user entries.
--   * is_builtin = 0 — operator-authored, fully editable.
-- slug is a stable string id so seed updates can find the matching
-- row across versions even if the display name changes.
CREATE TABLE IF NOT EXISTS tag_library (
    library_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    slug              TEXT UNIQUE NOT NULL,
    name              TEXT NOT NULL,
    category          TEXT NOT NULL,
    description       TEXT,
    rationale         TEXT,
    source_url        TEXT,
    rule_type         TEXT NOT NULL,
    rule_text         TEXT,
    color             TEXT,
    criticality       INTEGER,
    suggested_parent  TEXT,
    is_builtin        INTEGER NOT NULL DEFAULT 0,
    is_hidden         INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT,
    updated_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_tag_library_category ON tag_library(category);
CREATE INDEX IF NOT EXISTS idx_tag_library_builtin  ON tag_library(is_builtin);

-- Audit log: every successful Apply records which library entry went
-- to which destination Qualys env and the resulting tag id, so the
-- operator can see "I applied X to envA on date Y".
CREATE TABLE IF NOT EXISTS tag_library_applied (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    library_id                  INTEGER NOT NULL,
    destination_credential_id   TEXT,
    destination_platform        TEXT,
    destination_tag_id          INTEGER,
    destination_tag_name        TEXT,
    applied_at                  TEXT NOT NULL,
    FOREIGN KEY (library_id) REFERENCES tag_library(library_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tag_library_applied_lib ON tag_library_applied(library_id);

-- FTS5 for tag search
CREATE VIRTUAL TABLE IF NOT EXISTS tags_fts USING fts5(
    tag_id, name, rule_text, description,
    content=tags, content_rowid=tag_id
);

CREATE TRIGGER IF NOT EXISTS tags_ai AFTER INSERT ON tags BEGIN
    INSERT INTO tags_fts(rowid, tag_id, name, rule_text, description)
    VALUES (new.tag_id, new.tag_id, new.name, new.rule_text, new.description);
END;

CREATE TRIGGER IF NOT EXISTS tags_ad AFTER DELETE ON tags BEGIN
    INSERT INTO tags_fts(tags_fts, rowid, tag_id, name, rule_text, description)
    VALUES ('delete', old.tag_id, old.tag_id, old.name, old.rule_text, old.description);
END;

CREATE TRIGGER IF NOT EXISTS tags_au AFTER UPDATE ON tags BEGIN
    INSERT INTO tags_fts(tags_fts, rowid, tag_id, name, rule_text, description)
    VALUES ('delete', old.tag_id, old.tag_id, old.name, old.rule_text, old.description);
    INSERT INTO tags_fts(rowid, tag_id, name, rule_text, description)
    VALUES (new.tag_id, new.tag_id, new.name, new.rule_text, new.description);
END;

-- PM Patch Catalog (Qualys Patch Management via Gateway /pm/v2/patches)
CREATE TABLE IF NOT EXISTS pm_patches (
    patch_id        TEXT PRIMARY KEY,
    platform        TEXT NOT NULL,        -- 'Windows' | 'Linux'
    title           TEXT,
    vendor          TEXT,
    download_method TEXT,
    vendor_severity TEXT,
    is_security     INTEGER NOT NULL DEFAULT 0,
    is_superseded   INTEGER NOT NULL DEFAULT 0,
    reboot_required INTEGER NOT NULL DEFAULT 0,
    kb_article      TEXT,                  -- Windows kb id (KB1234567)
    package_names   TEXT,                  -- Linux package names, semicolon-joined
    last_synced     TEXT NOT NULL,
    raw_json        TEXT
);
CREATE INDEX IF NOT EXISTS idx_pm_patches_platform ON pm_patches(platform);
CREATE INDEX IF NOT EXISTS idx_pm_patches_vendor ON pm_patches(vendor);
CREATE INDEX IF NOT EXISTS idx_pm_patches_security ON pm_patches(is_security);

CREATE TABLE IF NOT EXISTS pm_patch_qids (
    patch_id TEXT NOT NULL,
    qid      INTEGER NOT NULL,
    PRIMARY KEY (patch_id, qid),
    FOREIGN KEY (patch_id) REFERENCES pm_patches(patch_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pm_patch_qids_qid ON pm_patch_qids(qid);

CREATE TABLE IF NOT EXISTS pm_patch_cves (
    patch_id TEXT NOT NULL,
    cve_id   TEXT NOT NULL,
    PRIMARY KEY (patch_id, cve_id),
    FOREIGN KEY (patch_id) REFERENCES pm_patches(patch_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pm_patch_cves_cve ON pm_patch_cves(cve_id);

INSERT OR IGNORE INTO sync_state (data_type) VALUES ('pm_patches');
"""


_BACKFILL_BATCH_SIZE = 500


def _backfill_threat_columns(conn, total: int | None = None):
    """One-time backfill: recompute threat flags from stored JSON.

    Called during init_db for legacy rows that have threat_intelligence_json
    populated but threat_backfill_done = 0. New rows get done=1 directly
    from upsert_vuln, so this only runs after a schema upgrade — never as
    a steady-state cost.

    v2.4.1 hardening (this is the SECOND rewrite — v2.4's streaming version
    had a worse bug than the v2.3 fetchall() it replaced):

    The v2.4 implementation opened a SELECT cursor on the live predicate
    `threat_backfill_done = 0` and committed UPDATEs between fetchmany()
    calls. In Python sqlite3, commit() on a connection ends the read
    transaction the cursor was bound to; the next fetchmany() implicitly
    starts a new read transaction with a fresh post-commit snapshot. The
    cursor's WHERE clause is then re-evaluated against the new snapshot,
    in which previously-marked rows have flipped to done=1 and no longer
    match. With no index on threat_backfill_done, every fetchmany() did a
    full table scan that skipped further into the table on each iteration
    — quadratic in the number of unmarked rows.

    On the Mac M-series this was hidden behind per-row Python work
    (bleach + xmltodict). On a 2-vCPU RHEL VM with slow disk it locked
    the entrypoint pre-flight in 100% CPU spin for 48+ minutes with zero
    write progress (rchar climbing through page cache at 1+ GB/s, wchar
    flat). See incident in BUGS.md BUG-017.

    The v2.4.1 path:
    - Build a worklist of qids upfront (one full scan, ~3 MB of ints in
      memory for 200K rows). Cheap; the qid list doesn't carry the JSON
      blobs that were the original v2.4 motivation for streaming.
    - Iterate the worklist in batches. Per batch: SELECT the full rows
      by qid IN (...) — indexed PK lookup, no full scan.
    - UPDATE per row, commit per batch. No long-running cursor across
      commits, no quadratic blowup.
    - Resumable across kills via threat_backfill_done = 1 — restarts
      build a smaller worklist each time.
    """
    qids_needed = [r[0] for r in conn.execute(
        "SELECT qid FROM vulns "
        "WHERE threat_intelligence_json IS NOT NULL "
        "AND threat_intelligence_json != 'null' "
        "AND threat_backfill_done = 0"
    )]
    if total is None:
        total = len(qids_needed)
    if not qids_needed:
        return

    processed = 0
    for batch_start in range(0, len(qids_needed), _BACKFILL_BATCH_SIZE):
        batch_qids = qids_needed[batch_start:batch_start + _BACKFILL_BATCH_SIZE]
        placeholders = ",".join("?" * len(batch_qids))
        rows = conn.execute(
            f"SELECT qid, threat_intelligence_json, correlation_json "
            f"FROM vulns WHERE qid IN ({placeholders})",
            batch_qids,
        ).fetchall()

        for row in rows:
            qid = row[0]
            try:
                try:
                    ti = json.loads(row[1]) if row[1] else {}
                except (json.JSONDecodeError, TypeError):
                    ti = {}
                try:
                    corr = json.loads(row[2]) if row[2] else {}
                except (json.JSONDecodeError, TypeError):
                    corr = {}

                ti_tags_raw = ti.get("THREAT_INTEL") or []
                if isinstance(ti_tags_raw, dict):
                    ti_tags_raw = [ti_tags_raw]
                ti_tags: set[str] = set()
                for t in ti_tags_raw:
                    if isinstance(t, dict):
                        ti_tags.add(t.get("#text", ""))
                    elif isinstance(t, str):
                        ti_tags.add(t)

                exploit_count, malware_count = _count_correlation_exploits_and_malware(corr)

                conn.execute(
                    """UPDATE vulns SET
                        threat_active_attacks = ?,
                        threat_exploit_public = ?,
                        threat_easy_exploit = ?,
                        threat_malware = ?,
                        threat_rce = ?,
                        threat_priv_escalation = ?,
                        threat_cisa_kev = ?,
                        exploit_count = ?,
                        malware_count = ?,
                        threat_backfill_done = 1
                    WHERE qid = ?""",
                    (
                        1 if "Active_Attacks" in ti_tags else 0,
                        1 if "Exploit_Public" in ti_tags else 0,
                        1 if "Easy_Exploit" in ti_tags else 0,
                        1 if "Malware" in ti_tags else 0,
                        1 if "Remote_Code_Execution" in ti_tags else 0,
                        1 if "Privilege_Escalation" in ti_tags else 0,
                        1 if "Cisa_Known_Exploited_Vulns" in ti_tags else 0,
                        exploit_count,
                        malware_count,
                        qid,
                    ),
                )
            except Exception as e:
                # Mark malformed rows done anyway so we don't re-walk them
                # forever. They keep their existing flag values; a future
                # full sync will overwrite.
                logger.warning(
                    "threat-column backfill: marking QID %s done despite error (%s: %s)",
                    qid, type(e).__name__, e,
                )
                try:
                    conn.execute(
                        "UPDATE vulns SET threat_backfill_done = 1 WHERE qid = ?",
                        (qid,),
                    )
                except Exception:
                    pass

        try:
            conn.commit()
        except Exception:
            pass

        processed += len(batch_qids)
        logger.info("[Init] Threat-column backfill: %d/%d done", processed, total)
        _init_progress(f"  backfill: {processed}/{total} done")


# ═══════════════════════════════════════════════════════════════════════════
# Sync State
# ═══════════════════════════════════════════════════════════════════════════

def get_sync_status() -> dict:
    """Return sync state for all data types, including elapsed time."""
    _table_map = {"qids": "vulns", "cids": "controls", "policies": "policies", "mandates": "mandates", "tags": "tags", "pm_patches": "pm_patches"}
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM sync_state").fetchall()
        result = {}
        for row in rows:
            dt = row["data_type"]
            # Live count from actual table (not cached) — mandates are populated
            # during CID sync but their sync_state.record_count isn't updated then
            table = _table_map.get(dt)
            live_count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] if table else (row["record_count"] or 0)
            # last_missing_count is None on rows that predate the migration
            # or have never had a verifying sync run. Frontend treats null
            # as "unknown" — Backfill stays visible until we have a number.
            try:
                missing_count = row["last_missing_count"]
            except (KeyError, IndexError):
                missing_count = None
            result[dt] = {
                "last_sync": row["last_sync_datetime"],
                "last_full_sync": row["last_full_sync_datetime"],
                "record_count": live_count,
                "credential_id": row["credential_id"],
                "last_missing_count": missing_count,
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


def update_sync_state(data_type: str, is_full: bool, credential_id: str | None = None,
                      missing_count: int | None = None):
    """Update sync watermark after a successful sync.

    ``missing_count`` is persisted only when supplied (full syncs and
    backfill verification pass it). Delta syncs don't touch it because
    they don't pre-count or verify against the universe — leaving the
    last full-sync verdict in place is correct.
    """
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    with get_db() as conn:
        # Get current record count
        table_map = {"qids": "vulns", "cids": "controls", "policies": "policies", "mandates": "mandates", "tags": "tags", "pm_patches": "pm_patches"}
        table = table_map[data_type]
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

        if is_full:
            if missing_count is not None:
                conn.execute(
                    """UPDATE sync_state
                       SET last_sync_datetime=?, last_full_sync_datetime=?,
                           record_count=?, credential_id=?, last_missing_count=?
                       WHERE data_type=?""",
                    (now, now, count, credential_id, missing_count, data_type),
                )
            else:
                conn.execute(
                    """UPDATE sync_state
                       SET last_sync_datetime=?, last_full_sync_datetime=?,
                           record_count=?, credential_id=?
                       WHERE data_type=?""",
                    (now, now, count, credential_id, data_type),
                )
        else:
            if missing_count is not None:
                conn.execute(
                    """UPDATE sync_state
                       SET last_sync_datetime=?, record_count=?, credential_id=?,
                           last_missing_count=?
                       WHERE data_type=?""",
                    (now, count, credential_id, missing_count, data_type),
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


# ── Sync-universe helpers ───────────────────────────────────────────────
# sync_universe holds every id Qualys reported by the most recent
# pre-count pass for a given data type. It's the source of truth for
# "what should exist locally" so backfill and the full-sync verify step
# can find missing items with a single indexed SQL diff instead of
# re-walking the entire id space or holding the set in Python memory.

# Maps data_type → (live_table, primary_key_column). The pair tells
# get_missing_*() how to LEFT JOIN sync_universe to find gaps.
_UNIVERSE_TARGET = {
    "qids": ("vulns", "qid"),
    "cids": ("controls", "cid"),
    "policies": ("policies", "policy_id"),
}


def upsert_universe(data_type: str, ids, conn=None) -> None:
    """Insert/refresh a batch of ids into sync_universe for ``data_type``.

    Pass ``conn`` to participate in an outer transaction (pre-counts
    batch a whole window/page in one commit).
    """
    if not ids:
        return
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    rows = [(data_type, str(i), now) for i in ids]
    with _maybe_db(conn) as c:
        c.executemany(
            """INSERT INTO sync_universe (data_type, item_id, last_seen_at)
               VALUES (?, ?, ?)
               ON CONFLICT(data_type, item_id) DO UPDATE SET
                 last_seen_at=excluded.last_seen_at""",
            rows,
        )


def reset_universe(data_type: str, conn=None) -> None:
    """Wipe the universe slice for ``data_type`` before a fresh pre-count."""
    with _maybe_db(conn) as c:
        c.execute("DELETE FROM sync_universe WHERE data_type=?", (data_type,))


def get_missing_ids(data_type: str, limit: int | None = None) -> list[str]:
    """Return ids that are in sync_universe but not in the live table.

    Returns strings (item_id is TEXT). Callers that want ints (QIDs,
    CIDs, policy_ids) should ``int()`` the result.
    """
    target = _UNIVERSE_TARGET.get(data_type)
    if not target:
        return []
    table, pk = target
    sql = (
        f"SELECT u.item_id FROM sync_universe u "
        f"LEFT JOIN {table} t ON CAST(t.{pk} AS TEXT) = u.item_id "
        f"WHERE u.data_type=? AND t.{pk} IS NULL "
        f"ORDER BY u.item_id"
    )
    if limit:
        sql += f" LIMIT {int(limit)}"
    with get_db() as conn:
        return [str(r[0]) for r in conn.execute(sql, (data_type,)).fetchall()]


def get_missing_count(data_type: str) -> int:
    """Return the diff size between sync_universe and the live table."""
    target = _UNIVERSE_TARGET.get(data_type)
    if not target:
        return 0
    table, pk = target
    sql = (
        f"SELECT COUNT(*) FROM sync_universe u "
        f"LEFT JOIN {table} t ON CAST(t.{pk} AS TEXT) = u.item_id "
        f"WHERE u.data_type=? AND t.{pk} IS NULL"
    )
    with get_db() as conn:
        return int(conn.execute(sql, (data_type,)).fetchone()[0] or 0)


def get_universe_size(data_type: str) -> int:
    """Return the size of the persisted universe slice for ``data_type``."""
    with get_db() as conn:
        return int(conn.execute(
            "SELECT COUNT(*) FROM sync_universe WHERE data_type=?",
            (data_type,),
        ).fetchone()[0] or 0)


# ── Legacy QID-specific aliases ─────────────────────────────────────────
# Older callers still import these names. They forward to the generic
# helpers above so we don't have to chase down every call site at once.

def upsert_kb_universe_qids(qids, conn=None) -> None:
    upsert_universe("qids", qids, conn=conn)


def reset_kb_universe(conn=None) -> None:
    reset_universe("qids", conn=conn)


def get_missing_qids(limit: int | None = None) -> list[int]:
    return [int(i) for i in get_missing_ids("qids", limit=limit)]


def get_missing_qid_count() -> int:
    return get_missing_count("qids")


def get_kb_universe_size() -> int:
    return get_universe_size("qids")


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
        elif data_type == "tags":
            conn.execute("DELETE FROM tag_exports")
            conn.execute("DELETE FROM tags")
            conn.execute("INSERT INTO tags_fts(tags_fts) VALUES('rebuild')")
        elif data_type == "pm_patches":
            conn.execute("DELETE FROM pm_patch_qids")
            conn.execute("DELETE FROM pm_patch_cves")
            conn.execute("DELETE FROM pm_patches")
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


# ───────────────────────────────────────────────────────────────────────
# FTS5 deferred indexing — Full-Sync optimization (v2.4)
#
# vulns_fts / controls_fts are external-content FTS5 tables backed by
# triggers on the parent table. With ~209K QIDs in a Full Sync, the
# per-row trigger maintenance becomes the dominant write cost: each
# INSERT OR REPLACE fires the AFTER-UPDATE trigger which does a delete +
# reinsert into the FTS5 inverted index, and that index B-tree depth
# grows with the data so each operation gets slightly more expensive
# than the last (the slowdown curve users observe).
#
# `fts5_deferred_for_vulns(conn)` and `fts5_deferred_for_controls(conn)`
# drop those triggers for the duration of the bulk insert, then issue a
# single FTS5 'rebuild' command at the end. The rebuild reads the
# parent table once and writes the FTS5 segments in optimal order — far
# cheaper than 209K incremental updates. Triggers are recreated inside
# the same transaction so the next normal upsert path has them in
# place.
#
# Idempotent: if triggers don't exist (e.g. after this manager has
# already run and the previous rebuild's transaction is open), DROP IF
# EXISTS makes it a no-op. CREATE IF NOT EXISTS likewise.
# ───────────────────────────────────────────────────────────────────────

import contextlib as _contextlib

_VULNS_FTS_TRIGGERS = """
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
"""

_CONTROLS_FTS_TRIGGERS = """
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
"""


@_contextlib.contextmanager
def fts5_deferred_for_vulns(conn=None):
    """Drop vulns FTS5 triggers, yield, then rebuild and reinstate.

    Use this around a Full-Sync bulk write of vulns to skip per-row FTS5
    maintenance. The single 'rebuild' at exit re-creates the inverted
    index from the parent table in one pass.
    """
    with _maybe_db(conn) as c:
        c.execute("DROP TRIGGER IF EXISTS vulns_ai")
        c.execute("DROP TRIGGER IF EXISTS vulns_ad")
        c.execute("DROP TRIGGER IF EXISTS vulns_au")
        c.commit()
    try:
        yield
    finally:
        with _maybe_db(conn) as c:
            c.execute("INSERT INTO vulns_fts(vulns_fts) VALUES('rebuild')")
            c.executescript(_VULNS_FTS_TRIGGERS)
            c.commit()
        logger.info("[FTS5] vulns_fts rebuilt and triggers reinstated")


@_contextlib.contextmanager
def fts5_deferred_for_controls(conn=None):
    """Drop controls FTS5 triggers, yield, then rebuild and reinstate."""
    with _maybe_db(conn) as c:
        c.execute("DROP TRIGGER IF EXISTS controls_ai")
        c.execute("DROP TRIGGER IF EXISTS controls_ad")
        c.execute("DROP TRIGGER IF EXISTS controls_au")
        c.commit()
    try:
        yield
    finally:
        with _maybe_db(conn) as c:
            c.execute("INSERT INTO controls_fts(controls_fts) VALUES('rebuild')")
            c.executescript(_CONTROLS_FTS_TRIGGERS)
            c.commit()
        logger.info("[FTS5] controls_fts rebuilt and triggers reinstated")


def _xml_text(val):
    # xmltodict turns `<BASE source="cve">5.0</BASE>` into
    # `{"@source": "cve", "#text": "5.0"}`. Unwrap to the scalar.
    if isinstance(val, dict):
        return val.get("#text")
    return val


def _count_correlation_exploits_and_malware(correlation) -> tuple[int, int]:
    # Walks Qualys' CORRELATION block to count exploits and malware
    # entries. xmltodict can produce four shapes for each *_SRC and
    # *_LIST element — dict, list-of-dicts, bare string, or None
    # (empty self-closing element). All four are tolerated here.
    # Used by both upsert_vuln (live ingest) and
    # _backfill_threat_columns (init-time recompute) so a fix lands
    # in one place.
    if not isinstance(correlation, dict):
        return 0, 0

    def _count(section_key, src_key, list_key, leaf_key):
        section = correlation.get(section_key) or {}
        if not isinstance(section, dict):
            return 0
        srcs = section.get(src_key) or []
        if isinstance(srcs, dict):
            srcs = [srcs]
        elif not isinstance(srcs, list):
            return 0
        count = 0
        for src in srcs:
            if not isinstance(src, dict):
                continue
            container = src.get(list_key) or {}
            if not isinstance(container, dict):
                continue
            leaves = container.get(leaf_key) or []
            if isinstance(leaves, dict):
                leaves = [leaves]
            elif not isinstance(leaves, list):
                continue
            count += len(leaves)
        return count

    exploit_count = _count("EXPLOITS", "EXPLT_SRC", "EXPLT_LIST", "EXPLT")
    malware_count = _count("MALWARE", "MW_SRC", "MW_LIST", "MW_INFO")
    return exploit_count, malware_count


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


def upsert_vuln(vuln: dict, conn=None, skip_unchanged: bool = False):
    """Insert or update a vulnerability from parsed Qualys XML data.

    Pass ``conn`` to participate in an outer transaction (sync paths batch
    a whole page worth of upserts inside a single ``get_db()`` block to
    avoid one fsync per QID).

    ``skip_unchanged=True`` (Delta sync) compares a SHA-256 of the input
    dict against the row's previously-stored ``source_hash`` and returns
    early when they match, bypassing every parent + child write and the
    FTS5 trigger maintenance. Full Sync passes ``False`` because rows are
    purged before the run, so the hash will always miss and the lookup
    is wasted work.
    """
    qid = int(vuln.get("QID", 0))
    if not qid:
        return

    # Compute the source hash. Used both for skip-on-unchanged and for
    # storage in the row so the next Delta can compare. json.dumps with
    # sort_keys=True canonicalizes dict ordering; default=str handles
    # any non-JSON-native types xmltodict might surface.
    src_hash = hashlib.sha256(
        json.dumps(vuln, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()

    if skip_unchanged:
        with _maybe_db(conn) as _check_conn:
            existing = _check_conn.execute(
                "SELECT source_hash FROM vulns WHERE qid=?", (qid,)
            ).fetchone()
        if existing and existing[0] == src_hash:
            # Nothing about this QID has changed since last sync — skip
            # parent UPDATE, all five child-table rewrites, and FTS5
            # maintenance. The dominant Delta-sync win.
            return

    # Extract CVSS data
    cvss = vuln.get("CVSS", {}) or {}
    cvss_base = _xml_text(cvss.get("BASE") or cvss.get("base"))
    cvss_temporal = _xml_text(cvss.get("TEMPORAL") or cvss.get("temporal"))
    cvss_vector = None
    access = cvss.get("ACCESS", {}) or {}
    if access:
        cvss_vector = f"AV:{access.get('VECTOR', '?')}"

    cvss3 = vuln.get("CVSS_V3", {}) or {}
    cvss3_base = _xml_text(cvss3.get("BASE") or cvss3.get("base"))
    cvss3_temporal = _xml_text(cvss3.get("TEMPORAL") or cvss3.get("temporal"))
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

    # Threat intelligence — store raw JSON and compute indexed flags
    threat_intel = vuln.get("THREAT_INTELLIGENCE", {}) or {}
    threat_json = json.dumps(threat_intel) if threat_intel else None
    # Extract threat tags for fast filtering
    ti_tags_raw = threat_intel.get("THREAT_INTEL") or []
    if isinstance(ti_tags_raw, dict):
        ti_tags_raw = [ti_tags_raw]
    ti_tags = set()
    for t in ti_tags_raw:
        if isinstance(t, dict):
            ti_tags.add(t.get("#text", ""))
        elif isinstance(t, str):
            ti_tags.add(t)
    threat_active_attacks = 1 if "Active_Attacks" in ti_tags else 0
    threat_exploit_public = 1 if "Exploit_Public" in ti_tags else 0
    threat_easy_exploit = 1 if "Easy_Exploit" in ti_tags else 0
    threat_malware = 1 if "Malware" in ti_tags else 0
    threat_rce = 1 if "Remote_Code_Execution" in ti_tags else 0
    threat_priv_escalation = 1 if "Privilege_Escalation" in ti_tags else 0
    threat_cisa_kev = 1 if "Cisa_Known_Exploited_Vulns" in ti_tags else 0

    # Count exploits and malware from correlation
    exploit_count, malware_count = _count_correlation_exploits_and_malware(correlation)

    # Software list
    software = vuln.get("SOFTWARE_LIST", {}) or {}
    software_json = json.dumps(software) if software else None

    # Disabled flag — Qualys returns it via DISABLED or IS_DISABLED
    # depending on the API path, both as "1"/"0" strings.
    disabled_raw = vuln.get("DISABLED")
    if disabled_raw is None:
        disabled_raw = vuln.get("IS_DISABLED")
    disabled = 1 if str(disabled_raw or "").strip().lower() in ("1", "true", "yes") else 0

    with _maybe_db(conn) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO vulns (
                qid, vuln_type, severity_level, title, category, technology,
                published_datetime, last_service_modification_datetime,
                code_modified_datetime, patchable, patch_published_date,
                pci_flag, disabled, diagnosis, consequence, solution,
                cvss_base, cvss_temporal, cvss_vector,
                cvss3_base, cvss3_temporal, cvss3_vector, cvss3_version,
                discovery_remote, discovery_auth_types,
                correlation_json, threat_intelligence_json, software_list_json,
                threat_active_attacks, threat_exploit_public, threat_easy_exploit,
                threat_malware, threat_rce, threat_priv_escalation, threat_cisa_kev,
                exploit_count, malware_count, threat_backfill_done, source_hash
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                disabled,
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
                threat_active_attacks,
                threat_exploit_public,
                threat_easy_exploit,
                threat_malware,
                threat_rce,
                threat_priv_escalation,
                threat_cisa_kev,
                exploit_count,
                malware_count,
                # threat_backfill_done — every upsert directly classifies
                # the row's threat flags from the JSON in this same call,
                # so the row never needs the init_db backfill pass.
                1,
                # source_hash — SHA-256 of the canonicalized input dict;
                # used by future Delta-sync calls (skip_unchanged=True)
                # to decide whether anything about this QID has changed.
                src_hash,
            ),
        )

        # ── Child-table writes via executemany ──
        # Each QID can have N CVEs / bugtraqs / vendor refs / RTI tags /
        # supported modules. The pre-2.4 path issued a separate
        # `conn.execute(INSERT OR IGNORE...)` per row, costing one
        # Python↔SQLite roundtrip per child record. On low-end hosts
        # (2 vCPU / Hyper-V) per-record SQL work dominated the sync time
        # and dragged a 200K-QID Full Sync past 3 hours. `executemany`
        # batches every child of a given type into a single prepared-
        # statement call, eliminating those roundtrips. INSERT OR IGNORE
        # semantics are unchanged. Empty rows are simply not appended,
        # so executemany is a no-op when a QID has no CVEs (etc.).

        # CVEs
        cve_list_container = vuln.get("CVE_LIST", {}) or {}
        cves = _ensure_list(cve_list_container.get("CVE"))
        conn.execute("DELETE FROM vuln_cves WHERE qid=?", (qid,))
        cve_rows = [
            (qid, cve.get("ID"), cve.get("URL"))
            for cve in cves if isinstance(cve, dict)
        ]
        if cve_rows:
            conn.executemany(
                "INSERT OR IGNORE INTO vuln_cves (qid, cve_id, url) VALUES (?,?,?)",
                cve_rows,
            )

        # Bugtraqs
        bt_container = vuln.get("BUGTRAQ_LIST", {}) or {}
        bts = _ensure_list(bt_container.get("BUGTRAQ"))
        conn.execute("DELETE FROM vuln_bugtraqs WHERE qid=?", (qid,))
        bt_rows = [
            (qid, bt.get("ID"), bt.get("URL"))
            for bt in bts if isinstance(bt, dict)
        ]
        if bt_rows:
            conn.executemany(
                "INSERT OR IGNORE INTO vuln_bugtraqs (qid, bugtraq_id, url) VALUES (?,?,?)",
                bt_rows,
            )

        # Vendor refs
        vr_container = vuln.get("VENDOR_REFERENCE_LIST", {}) or {}
        vrs = _ensure_list(vr_container.get("VENDOR_REFERENCE"))
        conn.execute("DELETE FROM vuln_vendor_refs WHERE qid=?", (qid,))
        vr_rows = [
            (qid, vr.get("ID"), vr.get("URL"))
            for vr in vrs if isinstance(vr, dict)
        ]
        if vr_rows:
            conn.executemany(
                "INSERT OR IGNORE INTO vuln_vendor_refs (qid, vendor_ref_id, url) VALUES (?,?,?)",
                vr_rows,
            )

        # RTI tags — accumulate intel tags + the synthetic has_exploit tag
        # into one list, then write in a single executemany.
        conn.execute("DELETE FROM vuln_rti WHERE qid=?", (qid,))
        rti_rows: list[tuple[int, str]] = []
        if threat_json and threat_json not in ("{}", "null"):
            ti = json.loads(threat_json) if isinstance(threat_json, str) else threat_json
            intel_items = _ensure_list(ti.get("THREAT_INTEL")) if isinstance(ti, dict) else []
            for item in intel_items:
                if isinstance(item, dict):
                    tag = item.get("#text") or item.get("ID")
                    if tag:
                        rti_rows.append((qid, tag))
        if correlation_json and correlation_json not in ("{}", "null"):
            rti_rows.append((qid, "has_exploit"))
        if rti_rows:
            conn.executemany(
                "INSERT OR IGNORE INTO vuln_rti (qid, rti_tag) VALUES (?,?)",
                rti_rows,
            )

        # Supported modules (agent/scanner types)
        conn.execute("DELETE FROM vuln_supported_modules WHERE qid=?", (qid,))
        sm_raw = vuln.get("SUPPORTED_MODULES")
        module_items: list = []
        if sm_raw:
            if isinstance(sm_raw, str):
                module_items = [sm_raw]
            elif isinstance(sm_raw, dict):
                module_items = _ensure_list(sm_raw.get("SUPPORTED_MODULE"))
            elif isinstance(sm_raw, list):
                module_items = sm_raw
        sm_rows: list[tuple[int, str]] = []
        for mod in module_items:
            if isinstance(mod, str):
                mod_name = mod
            elif isinstance(mod, dict):
                mod_name = mod.get("#text") or mod.get("MODULE_NAME") or str(mod)
            else:
                mod_name = str(mod)
            if mod_name and mod_name.strip():
                sm_rows.append((qid, mod_name.strip()))
        if sm_rows:
            conn.executemany(
                "INSERT OR IGNORE INTO vuln_supported_modules (qid, module_name) VALUES (?,?)",
                sm_rows,
            )


def search_vulns(
    q: str = "",
    exclude_q: str | None = None,
    cves: list[str] | None = None,
    cve_mode: str = "or",
    severity: int | None = None,
    severities: list[int] | None = None,
    categories: list[str] | None = None,
    exclude_categories: list[str] | None = None,
    patchable: bool | None = None,
    vuln_type: str | None = None,
    vuln_types: list[str] | None = None,
    cvss_base_min: float | None = None,
    cvss3_base_min: float | None = None,
    published_after: str | None = None,
    modified_after: str | None = None,
    pci_flag: bool | None = None,
    discovery_method: str | None = None,
    rti_indicators: list[str] | None = None,
    supported_modules: list[str] | None = None,
    pm_any: bool | None = None,
    pm_win: bool | None = None,
    pm_lin: bool | None = None,
    threat_active: bool | None = None,
    threat_cisa_kev: bool | None = None,
    threat_exploit_public: bool | None = None,
    threat_rce: bool | None = None,
    threat_malware: bool | None = None,
    has_exploits: bool | None = None,
    exclude_severities: list[int] | None = None,
    disabled: bool | None = None,
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
        if exclude_q:
            conditions.append(
                "v.qid NOT IN (SELECT qid FROM vulns_fts WHERE vulns_fts MATCH ?)"
            )
            params.append(_fts5_safe(exclude_q))

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

        # Severity filter — accept either single (back-compat) or multi
        if severities:
            placeholders = ",".join(["?"] * len(severities))
            conditions.append(f"v.severity_level IN ({placeholders})")
            params.extend(severities)
        elif severity is not None:
            conditions.append("v.severity_level = ?")
            params.append(severity)
        if exclude_severities:
            placeholders = ",".join(["?"] * len(exclude_severities))
            conditions.append(f"v.severity_level NOT IN ({placeholders})")
            params.extend(exclude_severities)

        # Category filter (multi-value exact match)
        if categories:
            placeholders = ",".join(["?"] * len(categories))
            conditions.append(f"v.category IN ({placeholders})")
            params.extend(categories)
        if exclude_categories:
            placeholders = ",".join(["?"] * len(exclude_categories))
            conditions.append(f"v.category NOT IN ({placeholders})")
            params.extend(exclude_categories)

        # Patchable filter
        if patchable is not None:
            conditions.append("v.patchable = ?")
            params.append(1 if patchable else 0)

        # Vuln type filter — accept either single (back-compat) or multi
        if vuln_types:
            placeholders = ",".join(["?"] * len(vuln_types))
            conditions.append(f"v.vuln_type IN ({placeholders})")
            params.extend(vuln_types)
        elif vuln_type:
            conditions.append("v.vuln_type = ?")
            params.append(vuln_type)

        # Disabled status filter. None = no filter (show both), True =
        # only disabled, False = only enabled. By default the QIDs tab
        # passes False so disabled QIDs don't clutter the standard view
        # — users opt in via the chip.
        if disabled is True:
            conditions.append("v.disabled = 1")
        elif disabled is False:
            conditions.append("v.disabled = 0")

        # PM Catalog filters — include (True) OR'd, exclude (False) AND'd
        pm_include = []
        pm_exclude = []
        if pm_any is True:
            pm_include.append("EXISTS (SELECT 1 FROM pm_patch_qids pq WHERE pq.qid = v.qid)")
        elif pm_any is False:
            pm_exclude.append("NOT EXISTS (SELECT 1 FROM pm_patch_qids pq WHERE pq.qid = v.qid)")
        if pm_win is True:
            pm_include.append(
                "EXISTS (SELECT 1 FROM pm_patch_qids pq "
                "JOIN pm_patches p ON p.patch_id = pq.patch_id "
                "WHERE pq.qid = v.qid AND p.platform = 'Windows')"
            )
        elif pm_win is False:
            pm_exclude.append(
                "NOT EXISTS (SELECT 1 FROM pm_patch_qids pq "
                "JOIN pm_patches p ON p.patch_id = pq.patch_id "
                "WHERE pq.qid = v.qid AND p.platform = 'Windows')"
            )
        if pm_lin is True:
            pm_include.append(
                "EXISTS (SELECT 1 FROM pm_patch_qids pq "
                "JOIN pm_patches p ON p.patch_id = pq.patch_id "
                "WHERE pq.qid = v.qid AND p.platform = 'Linux')"
            )
        elif pm_lin is False:
            pm_exclude.append(
                "NOT EXISTS (SELECT 1 FROM pm_patch_qids pq "
                "JOIN pm_patches p ON p.patch_id = pq.patch_id "
                "WHERE pq.qid = v.qid AND p.platform = 'Linux')"
            )
        if pm_include:
            conditions.append("(" + " OR ".join(pm_include) + ")")
        for exc in pm_exclude:
            conditions.append(exc)

        # Threat Intelligence filters — include (True) OR'd, exclude (False) AND'd
        threat_include = []
        threat_exclude = []
        def _threat_filter(flag, col):
            if flag is True: threat_include.append(f"v.{col} = 1")
            elif flag is False: threat_exclude.append(f"v.{col} = 0")
        _threat_filter(threat_active, "threat_active_attacks")
        _threat_filter(threat_cisa_kev, "threat_cisa_kev")
        _threat_filter(threat_exploit_public, "threat_exploit_public")
        _threat_filter(threat_rce, "threat_rce")
        _threat_filter(threat_malware, "threat_malware")
        if has_exploits is True: threat_include.append("v.exploit_count > 0")
        elif has_exploits is False: threat_exclude.append("v.exploit_count = 0")
        if threat_include:
            conditions.append("(" + " OR ".join(threat_include) + ")")
        for exc in threat_exclude:
            conditions.append(exc)

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


def _build_qid_where_clause(
    *,
    q: str = "",
    exclude_q: str | None = None,
    cves: list[str] | None = None,
    cve_mode: str = "or",
    severity: int | None = None,
    severities: list[int] | None = None,
    categories: list[str] | None = None,
    exclude_categories: list[str] | None = None,
    patchable: bool | None = None,
    vuln_type: str | None = None,
    vuln_types: list[str] | None = None,
    cvss_base_min: float | None = None,
    cvss3_base_min: float | None = None,
    published_after: str | None = None,
    modified_after: str | None = None,
    pci_flag: bool | None = None,
    discovery_method: str | None = None,
    rti_indicators: list[str] | None = None,
    supported_modules: list[str] | None = None,
    pm_any: bool | None = None,
    pm_win: bool | None = None,
    pm_lin: bool | None = None,
    threat_active: bool | None = None,
    threat_cisa_kev: bool | None = None,
    threat_exploit_public: bool | None = None,
    threat_rce: bool | None = None,
    threat_malware: bool | None = None,
    has_exploits: bool | None = None,
    exclude_severities: list[int] | None = None,
    disabled: bool | None = None,
) -> tuple[str, list]:
    """Mirror of the WHERE-clause logic in search_vulns, factored out
    so the Intelligence-stats aggregator can reuse it.

    Kept as a copy rather than a wrapper around search_vulns so the
    caller doesn't have to do useless data fetching just to get a
    filtered count. Tested against search_vulns via the existing
    QID search test suite.
    """
    conditions: list[str] = []
    params: list = []

    if q:
        conditions.append(
            "v.qid IN (SELECT qid FROM vulns_fts WHERE vulns_fts MATCH ?)"
        )
        params.append(_fts5_safe(q))
    if exclude_q:
        conditions.append(
            "v.qid NOT IN (SELECT qid FROM vulns_fts WHERE vulns_fts MATCH ?)"
        )
        params.append(_fts5_safe(exclude_q))

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

    if severities:
        placeholders = ",".join(["?"] * len(severities))
        conditions.append(f"v.severity_level IN ({placeholders})")
        params.extend(severities)
    elif severity is not None:
        conditions.append("v.severity_level = ?")
        params.append(severity)
    if exclude_severities:
        placeholders = ",".join(["?"] * len(exclude_severities))
        conditions.append(f"v.severity_level NOT IN ({placeholders})")
        params.extend(exclude_severities)

    if categories:
        placeholders = ",".join(["?"] * len(categories))
        conditions.append(f"v.category IN ({placeholders})")
        params.extend(categories)
    if exclude_categories:
        placeholders = ",".join(["?"] * len(exclude_categories))
        conditions.append(f"v.category NOT IN ({placeholders})")
        params.extend(exclude_categories)

    if patchable is not None:
        conditions.append("v.patchable = ?")
        params.append(1 if patchable else 0)

    if vuln_types:
        placeholders = ",".join(["?"] * len(vuln_types))
        conditions.append(f"v.vuln_type IN ({placeholders})")
        params.extend(vuln_types)
    elif vuln_type:
        conditions.append("v.vuln_type = ?")
        params.append(vuln_type)

    if disabled is True:
        conditions.append("v.disabled = 1")
    elif disabled is False:
        conditions.append("v.disabled = 0")

    # PM Catalog filters — include (True) OR'd, exclude (False) AND'd
    pm_include = []
    pm_exclude = []
    if pm_any is True:
        pm_include.append("EXISTS (SELECT 1 FROM pm_patch_qids pq WHERE pq.qid = v.qid)")
    elif pm_any is False:
        pm_exclude.append("NOT EXISTS (SELECT 1 FROM pm_patch_qids pq WHERE pq.qid = v.qid)")
    if pm_win is True:
        pm_include.append(
            "EXISTS (SELECT 1 FROM pm_patch_qids pq "
            "JOIN pm_patches p ON p.patch_id = pq.patch_id "
            "WHERE pq.qid = v.qid AND p.platform = 'Windows')"
        )
    elif pm_win is False:
        pm_exclude.append(
            "NOT EXISTS (SELECT 1 FROM pm_patch_qids pq "
            "JOIN pm_patches p ON p.patch_id = pq.patch_id "
            "WHERE pq.qid = v.qid AND p.platform = 'Windows')"
        )
    if pm_lin is True:
        pm_include.append(
            "EXISTS (SELECT 1 FROM pm_patch_qids pq "
            "JOIN pm_patches p ON p.patch_id = pq.patch_id "
            "WHERE pq.qid = v.qid AND p.platform = 'Linux')"
        )
    elif pm_lin is False:
        pm_exclude.append(
            "NOT EXISTS (SELECT 1 FROM pm_patch_qids pq "
            "JOIN pm_patches p ON p.patch_id = pq.patch_id "
            "WHERE pq.qid = v.qid AND p.platform = 'Linux')"
        )
    if pm_include:
        conditions.append("(" + " OR ".join(pm_include) + ")")
    for exc in pm_exclude:
        conditions.append(exc)

    # Threat Intelligence filters — include (True) OR'd, exclude (False) AND'd
    threat_include = []
    threat_exclude = []
    def _tf(flag, col):
        if flag is True: threat_include.append(f"v.{col} = 1")
        elif flag is False: threat_exclude.append(f"v.{col} = 0")
    _tf(threat_active, "threat_active_attacks")
    _tf(threat_cisa_kev, "threat_cisa_kev")
    _tf(threat_exploit_public, "threat_exploit_public")
    _tf(threat_rce, "threat_rce")
    _tf(threat_malware, "threat_malware")
    if has_exploits is True: threat_include.append("v.exploit_count > 0")
    elif has_exploits is False: threat_exclude.append("v.exploit_count = 0")
    if threat_include:
        conditions.append("(" + " OR ".join(threat_include) + ")")
    for exc in threat_exclude:
        conditions.append(exc)

    if cvss_base_min is not None:
        conditions.append("v.cvss_base >= ?")
        params.append(cvss_base_min)
    if cvss3_base_min is not None:
        conditions.append("v.cvss3_base >= ?")
        params.append(cvss3_base_min)
    if published_after:
        conditions.append("v.published_datetime >= ?")
        params.append(published_after)
    if modified_after:
        conditions.append("v.last_service_modification_datetime >= ?")
        params.append(modified_after)
    if pci_flag is not None:
        conditions.append("v.pci_flag = ?")
        params.append(1 if pci_flag else 0)
    if discovery_method == "remote":
        conditions.append("v.discovery_remote = 1")
    elif discovery_method == "auth":
        conditions.append(
            "v.discovery_auth_types IS NOT NULL AND v.discovery_auth_types != '[]'"
        )
    if rti_indicators:
        for rti in rti_indicators:
            conditions.append(
                "v.qid IN (SELECT qid FROM vuln_rti WHERE rti_tag = ?)"
            )
            params.append(rti)
    if supported_modules:
        for mod in supported_modules:
            conditions.append(
                "v.qid IN (SELECT qid FROM vuln_supported_modules WHERE module_name = ?)"
            )
            params.append(mod)

    # Threat Intelligence filters
    if threat_active:
        conditions.append("v.threat_active_attacks = 1")
    if threat_cisa_kev:
        conditions.append("v.threat_cisa_kev = 1")
    if threat_exploit_public:
        conditions.append("v.threat_exploit_public = 1")
    if threat_rce:
        conditions.append("v.threat_rce = 1")
    if threat_malware:
        conditions.append("v.threat_malware = 1")
    if has_exploits:
        conditions.append("v.exploit_count > 0")

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    return where, params


def aggregate_qid_intelligence_stats(filters: dict) -> dict:
    """Single-query computation of every stat the Intelligence tab's
    stat strip needs. Replaces an 11-query-per-page implementation
    that timed out the frontend on realistic data volumes.

    The strategy:
      * Build the user's filter WHERE once.
      * Use a CTE (`filtered`) to materialise the matching qids +
        the parent-row columns we need (severity, patchable, pci).
      * LEFT JOIN against three small DISTINCT-qid CTEs for the PM
        platform flags so we don't re-evaluate per-row EXISTS for
        each row of the filtered set.
      * Single SELECT with conditional sums for every dimension.
    """
    where, params = _build_qid_where_clause(**{
        k: v for k, v in filters.items()
        if k not in ("page", "per_page")
    })
    sql = f"""
        WITH filtered AS (
            SELECT v.qid, v.severity_level, v.patchable, v.pci_flag,
                   v.threat_active_attacks, v.threat_exploit_public,
                   v.threat_cisa_kev, v.threat_rce, v.threat_malware,
                   v.exploit_count
            FROM vulns v
            {where}
        ),
        pm_any_qids AS (SELECT DISTINCT qid FROM pm_patch_qids),
        pm_win_qids AS (
            SELECT DISTINCT pq.qid
            FROM pm_patch_qids pq
            JOIN pm_patches p ON p.patch_id = pq.patch_id
            WHERE p.platform = 'Windows'
        ),
        pm_lin_qids AS (
            SELECT DISTINCT pq.qid
            FROM pm_patch_qids pq
            JOIN pm_patches p ON p.patch_id = pq.patch_id
            WHERE p.platform = 'Linux'
        ),
        cve_qids AS (SELECT DISTINCT qid FROM vuln_cves)
        SELECT
            COUNT(*)                                               AS total_qids,
            SUM(CASE WHEN f.patchable=1 THEN 1 ELSE 0 END)         AS kb_patchable,
            SUM(CASE WHEN ap.qid IS NOT NULL THEN 1 ELSE 0 END)    AS pm_any,
            SUM(CASE WHEN wp.qid IS NOT NULL THEN 1 ELSE 0 END)    AS pm_win,
            SUM(CASE WHEN lp.qid IS NOT NULL THEN 1 ELSE 0 END)    AS pm_lin,
            SUM(CASE WHEN f.pci_flag=1 THEN 1 ELSE 0 END)          AS pci,
            SUM(CASE WHEN f.severity_level=5 THEN 1 ELSE 0 END)    AS sev_5,
            SUM(CASE WHEN f.severity_level=4 THEN 1 ELSE 0 END)    AS sev_4,
            SUM(CASE WHEN f.severity_level=3 THEN 1 ELSE 0 END)    AS sev_3,
            SUM(CASE WHEN f.severity_level=2 THEN 1 ELSE 0 END)    AS sev_2,
            SUM(CASE WHEN f.severity_level=1 THEN 1 ELSE 0 END)    AS sev_1,
            SUM(CASE WHEN cv.qid IS NOT NULL THEN 1 ELSE 0 END)    AS with_cve,
            SUM(CASE WHEN f.threat_active_attacks=1 THEN 1 ELSE 0 END) AS threat_active,
            SUM(CASE WHEN f.threat_cisa_kev=1 THEN 1 ELSE 0 END)   AS threat_cisa_kev,
            SUM(CASE WHEN f.threat_exploit_public=1 THEN 1 ELSE 0 END) AS threat_exploit_public,
            SUM(CASE WHEN f.threat_rce=1 THEN 1 ELSE 0 END)        AS threat_rce,
            SUM(CASE WHEN f.threat_malware=1 THEN 1 ELSE 0 END)    AS threat_malware,
            SUM(CASE WHEN f.exploit_count>0 THEN 1 ELSE 0 END)     AS has_exploits
        FROM filtered f
        LEFT JOIN pm_any_qids ap ON ap.qid = f.qid
        LEFT JOIN pm_win_qids wp ON wp.qid = f.qid
        LEFT JOIN pm_lin_qids lp ON lp.qid = f.qid
        LEFT JOIN cve_qids    cv ON cv.qid = f.qid
    """
    with get_db() as conn:
        row = conn.execute(sql, params).fetchone()
    if not row:
        return {k: 0 for k in (
            "total_qids", "kb_patchable", "pm_any", "pm_win", "pm_lin",
            "pci", "sev_5", "sev_4", "sev_3", "sev_2", "sev_1", "with_cve",
        )}
    # sqlite3.Row supports keyed access; convert to a plain dict
    # and replace any None aggregates with 0 (happens when filtered
    # set is empty).
    return {k: int(row[k] or 0) for k in row.keys()}


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

def upsert_control(control: dict, conn=None):
    """Insert or update a compliance control from parsed Qualys XML data.

    Pass ``conn`` to batch many controls into a single transaction during
    sync (avoids one fsync per CID).
    """
    cid = int(control.get("ID", 0))
    if not cid:
        return

    # Criticality
    crit = control.get("CRITICALITY", {}) or {}
    crit_label = crit.get("LABEL")
    crit_value = int(crit.get("VALUE", 0) or 0)

    with _maybe_db(conn) as conn:
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

        # Technologies — batched via executemany.
        tech_container = control.get("TECHNOLOGY_LIST", {}) or {}
        techs = _ensure_list(tech_container.get("TECHNOLOGY"))
        conn.execute("DELETE FROM control_technologies WHERE cid=?", (cid,))
        tech_rows = [
            (
                cid,
                tech.get("TECH_ID") or tech.get("ID"),
                tech.get("TECH_NAME") or tech.get("NAME"),
                tech.get("RATIONALE"),
                tech.get("DESCRIPTION"),
                json.dumps(tech.get("DATAPOINTS")) if tech.get("DATAPOINTS") else None,
            )
            for tech in techs if isinstance(tech, dict)
        ]
        if tech_rows:
            conn.executemany(
                """INSERT INTO control_technologies
                   (cid, tech_id, tech_name, rationale, description, datapoint_json)
                   VALUES (?,?,?,?,?,?)""",
                tech_rows,
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


def extract_mandates_from_control(control: dict, conn=None):
    """Extract mandate/framework data from a parsed Qualys control.

    Public entry point for mandate-only sync. Opens its own DB transaction
    when ``conn`` is None; otherwise participates in the caller's
    transaction so the whole page can be batched.
    Used by sync_mandates() to extract mandates without upserting the full control.
    """
    cid = int(control.get("ID", 0))
    if not cid:
        return
    with _maybe_db(conn) as c:
        _extract_mandates_for_cid(c, cid, control)


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


def upsert_policy(policy: dict, conn=None):
    """Insert or update a policy from parsed Qualys XML data.

    Pass ``conn`` to batch many policies into a single transaction during
    sync (avoids one fsync per policy).
    """
    policy_id = int(policy.get("ID", 0))
    if not policy_id:
        return

    with _maybe_db(conn) as conn:
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

        # Policy controls — batched via executemany for the same reason
        # upsert_vuln batches its child tables: each policy can carry many
        # controls and per-row execute() roundtrips show up on slow hosts.
        ctrl_container = policy.get("CONTROL_LIST", {}) or {}
        ctrls = _ensure_list(ctrl_container.get("CONTROL"))
        if ctrls:
            conn.execute("DELETE FROM policy_controls WHERE policy_id=?", (policy_id,))
            ctrl_rows = []
            for ctrl in ctrls:
                if not isinstance(ctrl, dict):
                    continue
                crit = ctrl.get("CRITICALITY", {}) or {}
                ctrl_rows.append((
                    policy_id,
                    int(ctrl.get("CID", 0) or 0),
                    ctrl.get("STATEMENT"),
                    crit.get("LABEL"),
                    int(crit.get("VALUE", 0) or 0),
                    1 if str(ctrl.get("DEPRECATED", "")).lower() in ("1", "true") else 0,
                ))
            if ctrl_rows:
                conn.executemany(
                    """INSERT INTO policy_controls
                       (policy_id, cid, statement, criticality_label,
                        criticality_value, deprecated)
                       VALUES (?,?,?,?,?,?)""",
                    ctrl_rows,
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

        # Threat Intelligence summary
        threat_active = conn.execute("SELECT COUNT(*) FROM vulns WHERE threat_active_attacks=1").fetchone()[0]
        threat_cisa_kev = conn.execute("SELECT COUNT(*) FROM vulns WHERE threat_cisa_kev=1").fetchone()[0]
        threat_exploit_public = conn.execute("SELECT COUNT(*) FROM vulns WHERE threat_exploit_public=1").fetchone()[0]
        threat_rce = conn.execute("SELECT COUNT(*) FROM vulns WHERE threat_rce=1").fetchone()[0]
        has_exploits = conn.execute("SELECT COUNT(*) FROM vulns WHERE exploit_count>0").fetchone()[0]

        # PM Patch stats
        pm_total = conn.execute("SELECT COUNT(*) FROM pm_patches").fetchone()[0]
        pm_windows = conn.execute("SELECT COUNT(*) FROM pm_patches WHERE platform='Windows'").fetchone()[0]
        pm_linux = conn.execute("SELECT COUNT(*) FROM pm_patches WHERE platform='Linux'").fetchone()[0]
        pm_qids_linked = conn.execute("SELECT COUNT(DISTINCT qid) FROM pm_patch_qids").fetchone()[0]

        # Tags summary
        tag_count = conn.execute("SELECT COUNT(*) FROM tags").fetchone()[0]
        tag_user = conn.execute("SELECT COUNT(*) FROM tags WHERE is_user_created=1").fetchone()[0]
        tag_system = tag_count - tag_user

        # Tag Library count
        library_count = conn.execute("SELECT COUNT(*) FROM tag_library").fetchone()[0]

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
            "threat_intel": {
                "active_attacks": threat_active,
                "cisa_kev": threat_cisa_kev,
                "exploit_public": threat_exploit_public,
                "rce": threat_rce,
                "has_exploits": has_exploits,
            },
            "pm_patches": {
                "total": pm_total,
                "windows": pm_windows,
                "linux": pm_linux,
                "qids_linked": pm_qids_linked,
            },
            "tags": {
                "total": tag_count,
                "user_created": tag_user,
                "system": tag_system,
                "library_entries": library_count,
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


def get_auto_update_config() -> dict:
    """Return the single-row auto-update schedule configuration."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM auto_update_config WHERE id = 1").fetchone()
        if row:
            return dict(row)
        return {"id": 1, "enabled": 0, "day_of_week": 6, "hour": 0,
                "minute": 0, "timezone": "", "last_check": None,
                "last_status": None, "last_error": None, "last_version": None}


def save_auto_update_config(enabled: bool, day_of_week: int, hour: int,
                            minute: int, timezone: str) -> dict:
    """Update auto-update schedule configuration (single-row)."""
    with get_db() as conn:
        conn.execute(
            """UPDATE auto_update_config
               SET enabled=?, day_of_week=?, hour=?, minute=?, timezone=?
               WHERE id=1""",
            (1 if enabled else 0, day_of_week, hour, minute, timezone),
        )
    return get_auto_update_config()


def update_auto_update_last_check(status: str, error: str | None = None,
                                  version: str | None = None) -> None:
    """Record the result of the last auto-update check.

    status: 'up_to_date' | 'updated' | 'error'
    """
    from datetime import datetime
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    with get_db() as conn:
        conn.execute(
            """UPDATE auto_update_config
               SET last_check=?, last_status=?, last_error=?, last_version=?
               WHERE id=1""",
            (now, status, error, version),
        )


# ═══════════════════════════════════════════════════════════════════════════
# Tags (Qualys Asset Tags)
# ═══════════════════════════════════════════════════════════════════════════

_TAG_RESERVED_FIELDS = ("reservedType", "RESERVED_TYPE", "reserved_type")
_TAG_PARENT_FIELDS = ("parentTagId", "PARENT_TAG_ID", "parent_tag_id")
_TAG_RULE_TYPE_FIELDS = ("ruleType", "RULE_TYPE", "rule_type")
_TAG_RULE_TEXT_FIELDS = ("ruleText", "RULE_TEXT", "rule_text")
_TAG_CRIT_FIELDS = ("criticalityScore", "CRITICALITY_SCORE", "criticality")
_TAG_CREATED_FIELDS = ("created", "CREATED", "createdDate")
_TAG_MODIFIED_FIELDS = ("modified", "MODIFIED", "modifiedDate")


def _first(d: dict, keys: tuple) -> object:
    """Return the first non-None value for any of the candidate keys."""
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


def _coerce_int(val) -> int | None:
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _extract_creator(tag: dict) -> str | None:
    """Pull a creator identifier from any of the shapes Qualys may return."""
    creator = tag.get("createdBy") or tag.get("CREATED_BY") or tag.get("creator")
    if isinstance(creator, dict):
        return (
            creator.get("username")
            or creator.get("USERNAME")
            or creator.get("user_login")
            or (str(creator.get("id")) if creator.get("id") else None)
        )
    if isinstance(creator, str):
        return creator
    return None


# ── Tag origin classification heuristic ─────────────────────────────────
# Since Qualys doesn't expose createdBy/owner, we use naming patterns
# and structural signals to classify tags into categories that help
# operators decide what to include during migration.
_CONNECTOR_NAME_PATTERNS = [
    "connector discovery", "aws commercial", "aws government",
    "azure commercial", "azure government", "gcp connector",
]
_SYSTEM_PROVISIONED_NAMES = [
    "business units", "unassigned business unit", "internet facing assets",
    "default dashboard access tag", "cloud agent",
    "passive sensor", "unmanaged", "sem", "easm", "dns sinkhole",
    "easm confidence high", "easm confidence low", "easm confidence medium",
]


def _classify_tag_origin(name: str, rule_type: str | None,
                         reserved: object, created: str | None) -> str:
    """Classify a tag's origin for migration decision-making.

    Returns one of:
      'rule_based' — has detection logic (rule_type set), portable anywhere
      'static'     — STATIC tag, no rule, portable as hierarchy
      'connector'  — created by/dependent on a cloud connector, needs matching
                     connector in destination. Includes CLOUD_ASSET rule types.
      'system'     — Qualys-provisioned at subscription creation
    """
    if reserved:
        return "system"

    name_lower = (name or "").strip().lower()

    # System-provisioned tags (created during subscription setup)
    if name_lower in _SYSTEM_PROVISIONED_NAMES:
        return "system"

    # Connector-created tags (by name pattern)
    if any(p in name_lower for p in _CONNECTOR_NAME_PATTERNS):
        return "connector"

    # CLOUD_ASSET rule type requires cloud connectors in the destination —
    # these tags are connector-dependent even if user-created
    rt = str(rule_type or "").strip().upper()
    if rt == "CLOUD_ASSET":
        return "connector"

    # Tags with rules are user-authored
    if rule_type and rt:
        return "rule_based"

    # Everything else is a STATIC tag (no rule)
    return "static"


def _backfill_tag_origin(conn):
    """One-time: classify all existing tags."""
    rows = conn.execute(
        "SELECT tag_id, name, rule_type, reserved_type, created FROM tags"
    ).fetchall()
    for r in rows:
        origin = _classify_tag_origin(
            r[1], r[2], r[3], r[4]
        )
        conn.execute(
            "UPDATE tags SET tag_origin=? WHERE tag_id=?",
            (origin, r[0])
        )


def _is_user_created(tag: dict, reserved: object, creator: str | None) -> int:
    """Initial (baseline) classification of a tag as system (0) or user (1).

    Signal strength:
      1. reservedType set     → system (definitive — Qualys-managed type)
      2. createdBy is a system sentinel ("system", "qualys", "auto")
                              → system
      3. Everything else      → user (the absence of reservedType means
                                it was created by a user, even without
                                a createdBy field or ruleType)

    The key insight: ONLY tags with reservedType are truly system-managed.
    Tags without it — even those with no rule and no creator — are user-
    created (e.g. static organizer tags, imported tags, manual tags).
    """
    if reserved:
        return 0
    if creator:
        c = creator.strip().lower()
        if c in ("system", "qualys", "auto"):
            return 0
    # No reservedType = user-created (even without a rule or createdBy)
    return 1


# reservedType values where the tag's rule is genuinely locked to
# Qualys's internal taxonomy and can't be edited via the API. These
# tags reflect static facts about an asset (its OS, region, technology)
# rather than customer policy. Anything not in this set is assumed
# editable — including system tags like 'Internet Facing Assets' and
# 'Business Units' where customers tune the rule to fit their environment.
# Per-tag override via editability_override column handles the cases
# where this heuristic gets it wrong.
_LOCKED_RESERVED_TYPES = {
    "OPERATING_SYSTEM", "OS",
    "AWS_REGION", "AZURE_REGION", "GCP_PROJECT", "CLOUD_PROVIDER",
    "ASSET_TYPE", "TECHNOLOGY", "HARDWARE", "PLATFORM",
    "AGENT_VERSION", "SCANNER", "SUBSCRIPTION",
}


def _is_editable(tag: dict, is_user_created: int, reserved: object) -> int:
    """Initial editability of a tag.

    Editability is independent of who created it:
      - User-created tags are always editable.
      - System tags whose reservedType is a locked taxonomy
        (OS, AWS_REGION, technology, etc.) are not editable.
      - Other system tags (Internet Facing Assets, Business Units,
        custom organizers, anything Qualys hasn't pinned to a static
        attribute) are editable — customers commonly tune their rules.

    Caller can override per-tag via editability_override.
    """
    if is_user_created:
        return 1
    rt = (str(reserved).strip().upper() if reserved else "")
    if not rt:
        # System with no reservedType: probably an organizer parent.
        # Default editable; override exists for the rare exception.
        return 1
    return 0 if rt in _LOCKED_RESERVED_TYPES else 1


def _propagate_user_classification(conn) -> int:
    """Iteratively flip system-classified parents to user when any of
    their children is already user-created. Returns total rows updated.

    Run this after a sync completes so 'organizer' tags (no rule, no
    creator, but a parent of user-created tags) get correctly classified
    as user-created. Pure SQL on existing rows — no re-sync required.
    """
    total_updated = 0
    while True:
        cur = conn.execute(
            """UPDATE tags AS p SET is_user_created = 1
               WHERE p.is_user_created = 0
                 AND COALESCE(p.reserved_type, '') = ''
                 AND EXISTS (
                     SELECT 1 FROM tags c
                     WHERE c.parent_tag_id = p.tag_id
                       AND c.is_user_created = 1
                 )"""
        )
        if cur.rowcount == 0:
            break
        total_updated += cur.rowcount
    return total_updated


def upsert_tag(tag: dict, credential_id: str | None = None,
               source_platform: str | None = None,
               source_subscription: str | None = None,
               conn=None) -> int | None:
    """Insert or update a tag from a parsed Qualys QPS REST tag object.

    Captures full provenance (reservedType, createdBy, raw payload) so the
    is_user_created flag can be recomputed if detection logic evolves.
    Returns the tag_id written, or None if the payload was unusable.

    Pass ``conn`` to batch many tags into a single transaction during
    sync.
    """
    tag_id = _coerce_int(tag.get("id") or tag.get("ID") or tag.get("tag_id"))
    if not tag_id:
        return None

    reserved = _first(tag, _TAG_RESERVED_FIELDS)
    creator = _extract_creator(tag)
    parent_id = _coerce_int(_first(tag, _TAG_PARENT_FIELDS))
    crit = _coerce_int(_first(tag, _TAG_CRIT_FIELDS))
    rule_type = _first(tag, _TAG_RULE_TYPE_FIELDS)
    tag_name = tag.get("name") or tag.get("NAME") or ""
    created_dt = _first(tag, _TAG_CREATED_FIELDS)
    tag_origin = _classify_tag_origin(tag_name, rule_type, reserved, created_dt)

    # v2.4.2: classify is_user_created from tag_origin first, then fall
    # through to the reservedType / sentinel-creator logic. Real Qualys
    # subscriptions surfaced via the QPS Tag search endpoint frequently
    # arrive with reservedType=null AND createdBy=null even on tags that
    # are unambiguously Qualys-shipped (Business Units, Cloud Agent,
    # Internet Facing Assets, the EASM family) or connector-bound
    # (AWS/Azure/GCP, vpc-*, Connector Discovery, etc.). The previous
    # _is_user_created logic relied solely on those two fields and
    # therefore mis-classified ~24% of tags as user-created on a
    # representative 167-tag pull. _classify_tag_origin already uses
    # the protective hard-coded name-pattern lists (_SYSTEM_PROVISIONED_
    # NAMES, _CONNECTOR_NAME_PATTERNS) plus the CLOUD_ASSET rule_type
    # heuristic to identify these tags correctly — we just weren't
    # consulting that result here. Operator override via
    # /api/tags/<id>/classify still wins for the rare false positive.
    if tag_origin in ("system", "connector"):
        is_user = 0
    else:
        is_user = _is_user_created(tag, reserved, creator)
    is_edit = _is_editable(tag, is_user, reserved)

    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    with _maybe_db(conn) as conn:
        conn.execute(
            """INSERT INTO tags (
                tag_id, name, color, parent_tag_id, rule_type, rule_text,
                criticality, description, created, modified,
                reserved_type, created_by, is_user_created, is_editable,
                source_credential_id, source_platform, source_subscription,
                tag_origin, last_synced, raw_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(tag_id) DO UPDATE SET
              name=excluded.name,
              color=excluded.color,
              parent_tag_id=excluded.parent_tag_id,
              rule_type=excluded.rule_type,
              rule_text=excluded.rule_text,
              criticality=excluded.criticality,
              description=excluded.description,
              created=excluded.created,
              modified=excluded.modified,
              reserved_type=excluded.reserved_type,
              created_by=excluded.created_by,
              is_user_created=excluded.is_user_created,
              is_editable=excluded.is_editable,
              source_credential_id=excluded.source_credential_id,
              source_platform=excluded.source_platform,
              source_subscription=excluded.source_subscription,
              tag_origin=excluded.tag_origin,
              last_synced=excluded.last_synced,
              raw_json=excluded.raw_json""",
            (
                tag_id,
                tag.get("name") or tag.get("NAME") or "",
                tag.get("color") or tag.get("COLOR"),
                parent_id,
                _first(tag, _TAG_RULE_TYPE_FIELDS),
                _first(tag, _TAG_RULE_TEXT_FIELDS),
                crit,
                tag.get("description") or tag.get("DESCRIPTION"),
                _first(tag, _TAG_CREATED_FIELDS),
                _first(tag, _TAG_MODIFIED_FIELDS),
                reserved if isinstance(reserved, str) else (str(reserved) if reserved else None),
                creator,
                is_user,
                is_edit,
                credential_id,
                source_platform,
                source_subscription,
                tag_origin,
                now,
                json.dumps(tag, default=str),
            ),
        )
    return tag_id


def search_tags(
    q: str = "",
    rule_types: list[str] | None = None,
    parent_tag_id: int | None = None,
    only_user: bool = False,
    only_system: bool = False,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Search tags with FTS, filters, and pagination."""
    with get_db() as conn:
        conditions = []
        params: list = []

        if q:
            conditions.append(
                "t.tag_id IN (SELECT tag_id FROM tags_fts WHERE tags_fts MATCH ?)"
            )
            params.append(_fts5_safe(q))

        if rule_types:
            placeholders = ",".join(["?"] * len(rule_types))
            conditions.append(f"t.rule_type IN ({placeholders})")
            params.extend(rule_types)

        if parent_tag_id is not None:
            conditions.append("t.parent_tag_id = ?")
            params.append(parent_tag_id)

        # v2.4.2: filter by the effective is_user_created — i.e. the
        # same value the rendered card shows after override resolution.
        # Pre-v2.4.2 this used `tag_origin = 'system'` as the filter
        # discriminator, which had two problems:
        #   1) Connector tags (origin='connector') always landed in
        #      only_user even though under the v2.4.2 origin-driven
        #      classification they are is_user_created=0. The card
        #      and the filter disagreed.
        #   2) classification_override was applied to rendered rows
        #      but never to the filter, so a tag manually re-classified
        #      to 'system' stayed visible under only_user.
        # Use a CASE expression that mirrors _apply_classification_override
        # so the filter matches what the operator sees on the card.
        effective_iuc = (
            "(CASE "
            "WHEN t.classification_override = 'user' THEN 1 "
            "WHEN t.classification_override = 'system' THEN 0 "
            "ELSE t.is_user_created END)"
        )
        if only_user:
            conditions.append(f"{effective_iuc} = 1")
        elif only_system:
            conditions.append(f"{effective_iuc} = 0")

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        total = conn.execute(f"SELECT COUNT(*) FROM tags t {where}", params).fetchone()[0]

        rows = conn.execute(
            f"""SELECT t.*,
                       (SELECT COUNT(*) FROM tags WHERE parent_tag_id = t.tag_id) AS child_count,
                       (SELECT name FROM tags WHERE tag_id = t.parent_tag_id) AS parent_name
                FROM tags t {where}
                ORDER BY t.name COLLATE NOCASE ASC, t.tag_id ASC
                LIMIT ? OFFSET ?""",
            params + [per_page, offset],
        ).fetchall()

        # Apply override to the rendered rows so cards show the effective
        # is_user_created and the [SYSTEM] pill matches whatever the
        # operator chose.
        return {
            "results": [_apply_tag_overrides(dict(r)) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        }


def _apply_classification_override(row: dict) -> dict:
    """Compute the effective is_user_created flag honoring any override.

    Stored fields:
      is_user_created          → auto-derived from API metadata
      classification_override  → 'user' | 'system' | NULL (no override)

    The frontend reads is_user_created for the [SYSTEM] pill and edit
    guards. When the operator has set an override we want that value
    to win; otherwise the auto value carries through. The auto value
    is also surfaced separately so the UI can show 'Auto: system,
    Override: user' when the two disagree.
    """
    auto = int(row.get("is_user_created") or 0)
    override = (row.get("classification_override") or "").strip().lower()
    if override == "user":
        effective = 1
    elif override == "system":
        effective = 0
    else:
        effective = auto
    row["is_user_created_auto"] = auto
    row["is_user_created"] = effective
    return row


def _apply_editability_override(row: dict) -> dict:
    """Compute the effective is_editable flag honoring any override.

    Same shape as _apply_classification_override but for the
    independent editability axis. is_editable_auto is preserved so
    the UI can show 'Auto: locked, Override: editable' when they
    disagree (e.g. operator marked a normally-locked OS tag as
    editable for an internal reason).
    """
    auto = int(row.get("is_editable") or 0)
    override = (row.get("editability_override") or "").strip().lower()
    if override == "editable":
        effective = 1
    elif override == "locked":
        effective = 0
    else:
        effective = auto
    row["is_editable_auto"] = auto
    row["is_editable"] = effective
    return row


def _apply_tag_overrides(row: dict) -> dict:
    """Apply both classification and editability overrides to a tag row.

    Frontend always reads tags through this so it never has to know
    which axis the override is on — it just gets the effective values.
    """
    return _apply_editability_override(_apply_classification_override(row))


def get_tag(tag_id: int) -> dict | None:
    """Return full tag detail with parent, children, and grandparent breadcrumb."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM tags WHERE tag_id=?", (tag_id,)).fetchone()
        if not row:
            return None
        result = _apply_tag_overrides(dict(row))

        if result.get("parent_tag_id"):
            parent = conn.execute(
                "SELECT tag_id, name, reserved_type, is_user_created, classification_override, "
                "is_editable, editability_override FROM tags WHERE tag_id=?",
                (result["parent_tag_id"],),
            ).fetchone()
            result["parent"] = _apply_tag_overrides(dict(parent)) if parent else None
        else:
            result["parent"] = None

        children = conn.execute(
            """SELECT tag_id, name, color, rule_type, reserved_type, is_user_created,
                      classification_override, is_editable, editability_override,
                      (SELECT COUNT(*) FROM tags WHERE parent_tag_id=t.tag_id) AS child_count
               FROM tags t WHERE parent_tag_id=? ORDER BY name COLLATE NOCASE""",
            (tag_id,),
        ).fetchall()
        result["children"] = [_apply_tag_overrides(dict(c)) for c in children]

        # Breadcrumb path back to root (depth-bounded to Qualys' 8-level limit)
        breadcrumb = []
        current = result.get("parent_tag_id")
        for _ in range(10):
            if not current:
                break
            crumb = conn.execute(
                "SELECT tag_id, name, parent_tag_id FROM tags WHERE tag_id=?",
                (current,),
            ).fetchone()
            if not crumb:
                break
            breadcrumb.insert(0, {"tag_id": crumb["tag_id"], "name": crumb["name"]})
            current = crumb["parent_tag_id"]
        result["breadcrumb"] = breadcrumb

        return result


def set_tag_classification_override(tag_id: int, value: str | None) -> bool:
    """Persist a manual classification override. None clears the override.

    Returns True if a row was updated, False if the tag doesn't exist.
    """
    if value is not None:
        v = value.strip().lower()
        if v not in ("user", "system"):
            raise ValueError("classification_override must be 'user', 'system', or null")
        norm = v
    else:
        norm = None
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE tags SET classification_override=? WHERE tag_id=?",
            (norm, tag_id),
        )
        return cur.rowcount > 0


def set_tag_editability_override(tag_id: int, value: str | None) -> bool:
    """Persist a manual editability override. None clears the override.

    Returns True if a row was updated, False if the tag doesn't exist.
    Accepted values: 'editable' (force allow edits), 'locked' (force
    disallow), or None (use the auto-derived is_editable).
    """
    if value is not None:
        v = value.strip().lower()
        if v not in ("editable", "locked"):
            raise ValueError("editability_override must be 'editable', 'locked', or null")
        norm = v
    else:
        norm = None
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE tags SET editability_override=? WHERE tag_id=?",
            (norm, tag_id),
        )
        return cur.rowcount > 0


# Canonical Qualys QPS REST tag rule types. The dropdown always shows
# this full list (so users see every available filter even before any
# tags have been synced); any additional rule types observed in their
# data are merged in too, in case Qualys adds new ones.
TAG_RULE_TYPES_KNOWN = (
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


def get_tag_filter_values(field: str, q: str = "", limit: int = 200) -> list:
    """Distinct values for tag filter dropdowns.

    For rule_types we return only what actually exists in the local DB
    so the filter reflects the user's real data.
    """
    with get_db() as conn:
        if field == "rule_types":
            observed = conn.execute(
                "SELECT DISTINCT rule_type AS v FROM tags "
                "WHERE rule_type IS NOT NULL AND rule_type != '' "
                "ORDER BY rule_type"
            ).fetchall()
            result = [r["v"] for r in observed]
            if q:
                ql = q.lower()
                result = [v for v in result if ql in v.lower()]
            return result[:limit]
        elif field == "colors":
            base = "SELECT DISTINCT color AS v FROM tags WHERE color IS NOT NULL AND color != ''"
        elif field == "reserved_types":
            base = "SELECT DISTINCT reserved_type AS v FROM tags WHERE reserved_type IS NOT NULL AND reserved_type != ''"
        elif field == "parents":
            # Distinct parent tag names (children grouped under each)
            sql = (
                "SELECT DISTINCT p.tag_id || '|' || p.name AS v "
                "FROM tags t JOIN tags p ON t.parent_tag_id = p.tag_id "
                "WHERE p.name IS NOT NULL"
            )
            if q:
                sql += " AND p.name LIKE ?"
                rows = conn.execute(
                    sql + " ORDER BY p.name LIMIT ?", (f"%{q}%", limit),
                ).fetchall()
            else:
                rows = conn.execute(sql + " ORDER BY p.name LIMIT ?", (limit,)).fetchall()
            return [r["v"] for r in rows]
        else:
            return []

        if q:
            rows = conn.execute(
                base + " AND v LIKE ? ORDER BY v LIMIT ?", (f"%{q}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(base + " ORDER BY v LIMIT ?", (limit,)).fetchall()
        return [r["v"] for r in rows]


def store_tag_export(tag_id: int, json_blob: bytes, credential_id: str | None = None):
    """Persist an exported tag JSON payload for Phase 2 migration."""
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    with get_db() as conn:
        conn.execute(
            """INSERT INTO tag_exports (tag_id, json_blob, exported_at, source_credential_id)
               VALUES (?,?,?,?)
               ON CONFLICT(tag_id) DO UPDATE SET
                 json_blob=excluded.json_blob,
                 exported_at=excluded.exported_at,
                 source_credential_id=excluded.source_credential_id""",
            (tag_id, json_blob, now, credential_id),
        )


def get_tag_export_json(tag_id: int) -> bytes | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT json_blob FROM tag_exports WHERE tag_id=?", (tag_id,)
        ).fetchone()
        return row["json_blob"] if row else None


def list_tag_exports() -> list[dict]:
    """Return summary rows for every stored tag export.

    Joined against the tags table so the UI can show the tag's name,
    rule type, and reservedType alongside the export metadata —
    handy for picking which export to upload to a destination env.
    """
    with get_db() as conn:
        rows = conn.execute(
            """SELECT te.tag_id, te.exported_at, te.source_credential_id,
                      LENGTH(te.json_blob)            AS payload_size,
                      t.name, t.rule_type, t.reserved_type,
                      t.is_user_created
               FROM tag_exports te
               LEFT JOIN tags t ON t.tag_id = te.tag_id
               ORDER BY te.exported_at DESC"""
        ).fetchall()
        return [dict(r) for r in rows]


def delete_tag_export(tag_id: int) -> bool:
    """Remove a stored export. Returns True if a row was deleted."""
    with get_db() as conn:
        cur = conn.execute("DELETE FROM tag_exports WHERE tag_id=?", (tag_id,))
        return cur.rowcount > 0


# ═══════════════════════════════════════════════════════════════════════════
# Tag Library (Phase 4: Custom Library + Apply)
# ═══════════════════════════════════════════════════════════════════════════
# Built-ins are seeded on init_db() — see seed_library_builtins below.
# User entries are stored in the same table with is_builtin=0 so the
# UI can list and filter them uniformly.

def list_library_entries(
    *, category: str | None = None,
    include_hidden: bool = False,
    q: str | None = None,
) -> list[dict]:
    """List library entries with optional category filter, full-text-ish
    search across name + description, and the option to surface hidden
    built-ins (operator wants to un-hide one)."""
    sql = "SELECT * FROM tag_library WHERE 1=1"
    params: list = []
    if not include_hidden:
        sql += " AND is_hidden = 0"
    if category:
        sql += " AND category = ?"
        params.append(category)
    if q:
        sql += " AND (name LIKE ? OR description LIKE ? OR rationale LIKE ?)"
        like = f"%{q}%"
        params.extend([like, like, like])
    sql += " ORDER BY category, name COLLATE NOCASE"
    with get_db() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_library_entry(library_id: int) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM tag_library WHERE library_id=?", (library_id,)
        ).fetchone()
        return dict(row) if row else None


def get_library_entry_by_slug(slug: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM tag_library WHERE slug=?", (slug,)
        ).fetchone()
        return dict(row) if row else None


def create_library_entry(payload: dict) -> int:
    """Insert a user-authored library entry. Returns the new library_id.

    slug auto-generates from name if not supplied. is_builtin is forced
    to 0 — built-ins can only be added by the seed function.
    """
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    name = (payload.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    slug = (payload.get("slug") or _slugify(name)).strip().lower()
    if not slug:
        raise ValueError("slug could not be derived from name")
    # Ensure uniqueness even on slug collision — append a numeric suffix.
    with get_db() as conn:
        slug = _ensure_unique_slug(conn, slug)
        cur = conn.execute(
            """INSERT INTO tag_library (
                slug, name, category, description, rationale, source_url,
                rule_type, rule_text, color, criticality, suggested_parent,
                is_builtin, is_hidden, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,0,0,?,?)""",
            (slug, name,
             payload.get("category") or "Custom",
             payload.get("description"),
             payload.get("rationale"),
             payload.get("source_url"),
             payload.get("rule_type") or "STATIC",
             payload.get("rule_text"),
             payload.get("color"),
             _coerce_int(payload.get("criticality")),
             payload.get("suggested_parent"),
             now, now),
        )
        return cur.lastrowid


def update_library_entry(library_id: int, changes: dict) -> bool:
    """Update a user-authored entry. Refuses on built-ins (caller should
    have copy-on-edited via clone_library_entry instead). Returns True
    if a row was updated."""
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    allowed = ("name", "category", "description", "rationale", "source_url",
               "rule_type", "rule_text", "color", "criticality",
               "suggested_parent")
    sets = []
    vals: list = []
    for k in allowed:
        if k in changes:
            sets.append(f"{k}=?")
            vals.append(_coerce_int(changes[k]) if k == "criticality" else changes[k])
    if not sets:
        return False
    sets.append("updated_at=?")
    vals.append(now)
    vals.append(library_id)
    with get_db() as conn:
        # Refuse to touch built-ins via this path
        row = conn.execute(
            "SELECT is_builtin FROM tag_library WHERE library_id=?", (library_id,)
        ).fetchone()
        if not row:
            return False
        if row["is_builtin"]:
            raise PermissionError(
                "Built-in library entries are read-only. Use clone_library_entry "
                "to create an editable copy, or hide the built-in."
            )
        cur = conn.execute(
            f"UPDATE tag_library SET {', '.join(sets)} WHERE library_id=?",
            vals,
        )
        return cur.rowcount > 0


def delete_library_entry(library_id: int) -> bool:
    """Delete a user-authored entry. Hides built-ins instead of
    deleting (built-ins re-seed on every init_db, so a real DELETE
    would just come back next startup)."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT is_builtin FROM tag_library WHERE library_id=?", (library_id,)
        ).fetchone()
        if not row:
            return False
        if row["is_builtin"]:
            conn.execute(
                "UPDATE tag_library SET is_hidden=1 WHERE library_id=?",
                (library_id,),
            )
            return True
        conn.execute("DELETE FROM tag_library WHERE library_id=?", (library_id,))
        return True


def unhide_library_entry(library_id: int) -> bool:
    """Restore a hidden built-in to the visible list."""
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE tag_library SET is_hidden=0 WHERE library_id=? AND is_builtin=1",
            (library_id,),
        )
        return cur.rowcount > 0


def clone_library_entry(library_id: int, *, new_name: str | None = None) -> int:
    """Copy any entry into a new editable user entry. The cloned row
    starts with is_builtin=0 so the operator can edit freely."""
    src = get_library_entry(library_id)
    if not src:
        raise ValueError("library entry not found")
    payload = {
        "name": new_name or (src["name"] + " (copy)"),
        "category": src["category"],
        "description": src["description"],
        "rationale": src["rationale"],
        "source_url": src["source_url"],
        "rule_type": src["rule_type"],
        "rule_text": src["rule_text"],
        "color": src["color"],
        "criticality": src["criticality"],
        "suggested_parent": src["suggested_parent"],
    }
    return create_library_entry(payload)


def record_library_apply(*, library_id: int, destination_credential_id: str | None,
                         destination_platform: str | None,
                         destination_tag_id: int | None,
                         destination_tag_name: str | None) -> int:
    """Append an audit row after a successful Apply."""
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO tag_library_applied (
                library_id, destination_credential_id, destination_platform,
                destination_tag_id, destination_tag_name, applied_at
            ) VALUES (?,?,?,?,?,?)""",
            (library_id, destination_credential_id, destination_platform,
             destination_tag_id, destination_tag_name, now),
        )
        return cur.lastrowid


def list_library_applies(library_id: int | None = None,
                         limit: int = 50) -> list[dict]:
    """Return apply history, newest first. limit is hard-capped."""
    limit = max(1, min(int(limit), 500))
    with get_db() as conn:
        if library_id is not None:
            rows = conn.execute(
                """SELECT a.*, l.name AS library_name, l.slug
                   FROM tag_library_applied a
                   LEFT JOIN tag_library l ON l.library_id = a.library_id
                   WHERE a.library_id=?
                   ORDER BY a.id DESC LIMIT ?""",
                (library_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT a.*, l.name AS library_name, l.slug
                   FROM tag_library_applied a
                   LEFT JOIN tag_library l ON l.library_id = a.library_id
                   ORDER BY a.id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


_SLUG_RE = re.compile(r"[^a-z0-9]+")

def _slugify(text: str) -> str:
    """Lowercase + dash-join. Best-effort, not RFC-anything."""
    return _SLUG_RE.sub("-", text.lower()).strip("-")


def _ensure_unique_slug(conn, slug: str) -> str:
    """Append -2, -3, ... until the slug doesn't collide."""
    base = slug
    n = 1
    while conn.execute(
        "SELECT 1 FROM tag_library WHERE slug=?", (slug,)
    ).fetchone():
        n += 1
        slug = f"{base}-{n}"
    return slug


def seed_library_builtins() -> int:
    """Idempotent upsert of the LIBRARY_BUILTINS list.

    Behavior:
      * New built-in slugs get inserted.
      * Existing built-in slugs get their fields refreshed from the
        seed (operator-curated metadata stays current across upgrades).
      * is_hidden is preserved across re-seeds — operator's "I don't
        want to see this" choice survives upgrades.
      * User-authored entries (is_builtin=0) are never touched even
        if a slug happens to overlap.
    Returns the count of inserted+updated rows.
    """
    from app.library_seed import LIBRARY_BUILTINS
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    affected = 0
    with get_db() as conn:
        for entry in LIBRARY_BUILTINS:
            slug = entry["slug"]
            existing = conn.execute(
                "SELECT library_id, is_builtin FROM tag_library WHERE slug=?",
                (slug,),
            ).fetchone()
            if existing and not existing["is_builtin"]:
                # User claimed this slug — leave their copy alone.
                continue
            if existing:
                conn.execute(
                    """UPDATE tag_library SET
                        name=?, category=?, description=?, rationale=?,
                        source_url=?, rule_type=?, rule_text=?, color=?,
                        criticality=?, suggested_parent=?, updated_at=?
                       WHERE library_id=?""",
                    (entry["name"], entry["category"], entry.get("description"),
                     entry.get("rationale"), entry.get("source_url"),
                     entry["rule_type"], entry.get("rule_text"),
                     entry.get("color"), entry.get("criticality"),
                     entry.get("suggested_parent"), now,
                     existing["library_id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO tag_library (
                        slug, name, category, description, rationale,
                        source_url, rule_type, rule_text, color,
                        criticality, suggested_parent,
                        is_builtin, is_hidden, created_at, updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,1,0,?,?)""",
                    (slug, entry["name"], entry["category"],
                     entry.get("description"), entry.get("rationale"),
                     entry.get("source_url"), entry["rule_type"],
                     entry.get("rule_text"), entry.get("color"),
                     entry.get("criticality"), entry.get("suggested_parent"),
                     now, now),
                )
            affected += 1
    return affected


# ═══════════════════════════════════════════════════════════════════════════
# PM Patch Catalog
# ═══════════════════════════════════════════════════════════════════════════

def upsert_pm_patch(patch: dict, conn=None) -> str | None:
    """Insert or update a PM patch from a parsed Qualys gateway response.

    Pass ``conn`` to batch many patches into a single transaction during
    sync (avoids one fsync per patch).

    Patch JSON shape (abbreviated):
        {"id": "...", "title": "...", "vendor": "...", "kb": "KB...",
         "downloadMethod": "Automatic", "vendorSeverity": "Critical",
         "isSecurity": true, "isSuperseded": false, "rebootRequired": true,
         "qid": [12345, 67890],
         "cve": ["CVE-2024-1234"],
         "packageDetails": [{"packageName": "openssl"}, ...]}

    Linux patches typically have package details and no kb article;
    Windows patches have a kb article and no package details. Both are
    stored in the same table; the empty fields stay null/empty.
    """
    patch_id = patch.get("id") or patch.get("patchId")
    if not patch_id:
        return None
    patch_id = str(patch_id)

    platform = "Windows"
    # Heuristic: presence of kb article = Windows; package details = Linux
    if patch.get("packageDetails") and not patch.get("kb"):
        platform = "Linux"
    elif patch.get("platform"):
        platform = str(patch["platform"]).strip() or "Windows"

    title           = patch.get("title") or ""
    vendor          = patch.get("vendor") or ""
    download_method = patch.get("downloadMethod") or ""
    vendor_severity = patch.get("vendorSeverity") or ""
    is_security     = 1 if patch.get("isSecurity") else 0
    is_superseded   = 1 if patch.get("isSuperseded") else 0
    reboot_required = 1 if patch.get("rebootRequired") else 0
    kb_article      = patch.get("kb") or ""

    package_names = ""
    pkg_arr = patch.get("packageDetails") or []
    if isinstance(pkg_arr, dict):
        pkg_arr = [pkg_arr]
    if isinstance(pkg_arr, list):
        names = [str(p.get("packageName", "")) for p in pkg_arr if isinstance(p, dict) and p.get("packageName")]
        package_names = ";".join(names)

    qid_list = patch.get("qid") or []
    if isinstance(qid_list, (str, int)):
        qid_list = [qid_list]
    qid_ints: list[int] = []
    for q in qid_list:
        try:
            qid_ints.append(int(q))
        except (TypeError, ValueError):
            continue

    cve_list = patch.get("cve") or []
    if isinstance(cve_list, str):
        cve_list = [cve_list]
    cve_clean = [str(c).strip() for c in cve_list if c]

    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    with _maybe_db(conn) as conn:
        conn.execute(
            """INSERT INTO pm_patches (
                patch_id, platform, title, vendor, download_method,
                vendor_severity, is_security, is_superseded, reboot_required,
                kb_article, package_names, last_synced, raw_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(patch_id) DO UPDATE SET
              platform=excluded.platform,
              title=excluded.title,
              vendor=excluded.vendor,
              download_method=excluded.download_method,
              vendor_severity=excluded.vendor_severity,
              is_security=excluded.is_security,
              is_superseded=excluded.is_superseded,
              reboot_required=excluded.reboot_required,
              kb_article=excluded.kb_article,
              package_names=excluded.package_names,
              last_synced=excluded.last_synced,
              raw_json=excluded.raw_json""",
            (patch_id, platform, title, vendor, download_method,
             vendor_severity, is_security, is_superseded, reboot_required,
             kb_article, package_names, now, json.dumps(patch, default=str)),
        )

        # Refresh per-patch link tables — batched via executemany. Keeps
        # the relations in sync if a patch's qid or cve list is amended
        # on the Qualys side.
        conn.execute("DELETE FROM pm_patch_qids WHERE patch_id=?", (patch_id,))
        if qid_ints:
            conn.executemany(
                "INSERT OR IGNORE INTO pm_patch_qids (patch_id, qid) VALUES (?,?)",
                [(patch_id, q) for q in qid_ints],
            )
        conn.execute("DELETE FROM pm_patch_cves WHERE patch_id=?", (patch_id,))
        if cve_clean:
            conn.executemany(
                "INSERT OR IGNORE INTO pm_patch_cves (patch_id, cve_id) VALUES (?,?)",
                [(patch_id, cv) for cv in cve_clean],
            )

    return patch_id


def get_pm_patches_for_qid(qid: int) -> list[dict]:
    """Return all PM patches associated with a QID (joined across platforms)."""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT p.patch_id, p.platform, p.title, p.vendor, p.download_method,
                      p.vendor_severity, p.is_security, p.is_superseded,
                      p.reboot_required, p.kb_article, p.package_names
               FROM pm_patches p
               JOIN pm_patch_qids pq ON pq.patch_id = p.patch_id
               WHERE pq.qid = ?
               ORDER BY p.platform, p.is_security DESC, p.title""",
            (qid,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_pm_patch_qid_flags(qid: int) -> dict:
    """Return {win_patches, lin_patches, has_pm} counts for a QID."""
    with get_db() as conn:
        row = conn.execute(
            """SELECT
                 COALESCE(SUM(CASE WHEN p.platform='Windows' THEN 1 ELSE 0 END), 0) AS win_patches,
                 COALESCE(SUM(CASE WHEN p.platform='Linux'   THEN 1 ELSE 0 END), 0) AS lin_patches
               FROM pm_patches p
               JOIN pm_patch_qids pq ON pq.patch_id = p.patch_id
               WHERE pq.qid = ?""",
            (qid,),
        ).fetchone()
        wp = int(row["win_patches"] or 0)
        lp = int(row["lin_patches"] or 0)
        return {
            "win_patches": wp,
            "lin_patches": lp,
            "has_pm": wp + lp > 0,
        }


def pm_patch_stats() -> dict:
    """Aggregate counts for the dashboard / Intelligence tab."""
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM pm_patches").fetchone()[0]
        by_platform_rows = conn.execute(
            "SELECT platform, COUNT(*) AS n FROM pm_patches GROUP BY platform"
        ).fetchall()
        by_platform = {r["platform"]: r["n"] for r in by_platform_rows}
        qids_with_pm = conn.execute(
            "SELECT COUNT(DISTINCT qid) FROM pm_patch_qids"
        ).fetchone()[0]
        return {
            "total_patches": total,
            "windows_patches": by_platform.get("Windows", 0),
            "linux_patches": by_platform.get("Linux", 0),
            "qids_with_pm": qids_with_pm,
        }
