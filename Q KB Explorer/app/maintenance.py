"""
Database maintenance — backup, vacuum, analyze, restore.

Runs weekly via APScheduler. Creates a compressed backup before maintenance
so the user can restore if something goes wrong.
"""
from __future__ import annotations

import gzip
import logging
import os
import shutil
import sqlite3
import threading
import time

from app.database import DB_PATH, update_maintenance_last_run, _local

logger = logging.getLogger(__name__)

BACKUP_PATH = os.path.join(os.path.dirname(DB_PATH), "qkbe.db.bak.gz")


def _close_thread_conn():
    """Close the thread-local DB connection so VACUUM can get exclusive access."""
    if hasattr(_local, "conn") and _local.conn is not None:
        try:
            _local.conn.close()
        except Exception:
            pass
        _local.conn = None


def _create_backup() -> int:
    """Create a gzip-compressed backup of the database. Returns compressed size."""
    # Use SQLite backup API for a consistent snapshot
    src = sqlite3.connect(DB_PATH, timeout=30)
    try:
        # Write backup to temp file first, then compress
        tmp_path = DB_PATH + ".tmp_bak"
        dst = sqlite3.connect(tmp_path)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()

    # Compress the temp backup
    with open(tmp_path, "rb") as f_in:
        with gzip.open(BACKUP_PATH, "wb", compresslevel=6) as f_out:
            shutil.copyfileobj(f_in, f_out)

    # Remove uncompressed temp
    os.remove(tmp_path)

    return os.path.getsize(BACKUP_PATH)


def run_maintenance() -> dict:
    """
    Execute database maintenance:
    1. Create compressed backup
    2. PRAGMA integrity_check
    3. VACUUM
    4. ANALYZE
    5. PRAGMA optimize

    Returns result dict with status, sizes, duration.
    """
    t0 = time.time()
    size_before = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    backup_size = 0

    try:
        # Step 1: Backup
        logger.info("[Maintenance] Creating compressed backup...")
        backup_size = _create_backup()
        logger.info("[Maintenance] Backup created: %s (%.1f MB)",
                     BACKUP_PATH, backup_size / 1048576)

        # Close thread-local connection so VACUUM can get exclusive lock
        _close_thread_conn()

        # Step 2-5: Run maintenance on a fresh connection
        conn = sqlite3.connect(DB_PATH, timeout=60)
        try:
            # Integrity check
            logger.info("[Maintenance] Running integrity_check...")
            result = conn.execute("PRAGMA integrity_check").fetchone()
            if result[0] != "ok":
                raise RuntimeError(f"Integrity check failed: {result[0]}")

            # VACUUM
            logger.info("[Maintenance] Running VACUUM...")
            conn.execute("VACUUM")

            # ANALYZE
            logger.info("[Maintenance] Running ANALYZE...")
            conn.execute("ANALYZE")

            # Optimize
            logger.info("[Maintenance] Running PRAGMA optimize...")
            conn.execute("PRAGMA optimize")
        finally:
            conn.close()

        size_after = os.path.getsize(DB_PATH)
        duration = round(time.time() - t0, 1)
        saved = size_before - size_after

        logger.info("[Maintenance] Complete in %.1fs — %s → %s (saved %.1f MB)",
                     duration, _fmt_size(size_before), _fmt_size(size_after),
                     saved / 1048576)

        update_maintenance_last_run("ok", None, duration)

        return {
            "status": "ok",
            "size_before": size_before,
            "size_after": size_after,
            "backup_size": backup_size,
            "backup_path": BACKUP_PATH,
            "duration_s": duration,
        }

    except Exception as e:
        duration = round(time.time() - t0, 1)
        error_msg = str(e)
        logger.error("[Maintenance] Failed after %.1fs: %s", duration, error_msg)
        update_maintenance_last_run("error", error_msg, duration)
        return {
            "status": "error",
            "error": error_msg,
            "duration_s": duration,
            "backup_size": backup_size,
            "backup_path": BACKUP_PATH if os.path.exists(BACKUP_PATH) else None,
        }


def restore_from_backup() -> dict:
    """Restore the database from the compressed backup."""
    if not os.path.exists(BACKUP_PATH):
        return {"status": "error", "error": "No backup file found"}

    try:
        # Close thread-local connection
        _close_thread_conn()

        # Decompress backup over the current database
        with gzip.open(BACKUP_PATH, "rb") as f_in:
            with open(DB_PATH, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        size = os.path.getsize(DB_PATH)
        logger.info("[Maintenance] Database restored from backup (%.1f MB)", size / 1048576)
        return {"status": "ok", "size": size}

    except Exception as e:
        logger.error("[Maintenance] Restore failed: %s", e)
        return {"status": "error", "error": str(e)}


def get_backup_info() -> dict | None:
    """Return info about the existing backup, or None."""
    if not os.path.exists(BACKUP_PATH):
        return None
    stat = os.stat(BACKUP_PATH)
    return {
        "path": os.path.basename(BACKUP_PATH),
        "size": stat.st_size,
        "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
    }


def _fmt_size(n: int) -> str:
    """Format bytes as human-readable string."""
    if n < 1024:
        return f"{n} B"
    elif n < 1048576:
        return f"{n / 1024:.1f} KB"
    else:
        return f"{n / 1048576:.1f} MB"
