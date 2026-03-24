"""
Q KB Explorer — Sync Event Log
Built by netsecops-76

Captures timestamped diagnostic events throughout the sync lifecycle.
Events are persisted to SQLite so they survive worker restarts / OOM kills.
Designed to be copied and shared for troubleshooting.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class SyncLog:
    """Thread-safe, timestamped event log for a single sync operation.

    Events are written to both in-memory list AND SQLite for persistence.
    If the worker is killed mid-sync, the DB-persisted events survive.
    """

    def __init__(self, data_type: str, full: bool, api_base: str, endpoint: str):
        self._lock = threading.Lock()
        self.data_type = data_type
        self.full = full
        self.api_base = api_base
        self.endpoint = endpoint
        self.started_at = _now()
        self.finished_at = None
        self.events: list[dict] = []
        self.run_id: int | None = None

        # Persist the run to SQLite
        self._create_db_run()

        self.event("SYNC_START", {
            "data_type": data_type,
            "mode": "full" if full else "delta",
            "api_base": api_base,
            "endpoint": endpoint,
        })

    def _create_db_run(self):
        """Create a sync_log_runs row in SQLite and store the run_id."""
        try:
            from app.database import _get_conn
            conn = _get_conn()
            cursor = conn.execute(
                """INSERT INTO sync_log_runs (data_type, full, api_base, endpoint, started_at, status)
                   VALUES (?, ?, ?, ?, ?, 'running')""",
                (self.data_type, 1 if self.full else 0, self.api_base, self.endpoint, self.started_at),
            )
            conn.commit()
            self.run_id = cursor.lastrowid
            logger.info("Created sync log run %d for %s", self.run_id, self.data_type)
        except Exception as e:
            logger.error("Failed to create sync log run in DB: %s", e)

    def _persist_event(self, entry: dict):
        """Write a single event to SQLite."""
        if not self.run_id:
            return
        try:
            from app.database import _get_conn
            conn = _get_conn()
            conn.execute(
                "INSERT INTO sync_log_events (run_id, ts, event_type, detail_json) VALUES (?, ?, ?, ?)",
                (self.run_id, entry["ts"], entry["event"],
                 json.dumps(entry.get("detail")) if entry.get("detail") else None),
            )
            conn.commit()
        except Exception as e:
            logger.error("Failed to persist sync log event: %s", e)

    def event(self, event_type: str, detail: dict | None = None):
        """Append a timestamped event (in-memory + SQLite)."""
        entry = {
            "ts": _now(),
            "event": event_type,
        }
        if detail:
            entry["detail"] = detail
        with self._lock:
            self.events.append(entry)
        # Persist to DB outside the lock (DB has its own locking)
        self._persist_event(entry)

    def finish(self, summary: dict):
        """Mark sync complete with summary."""
        self.finished_at = _now()
        self.event("SYNC_COMPLETE", summary)
        self._update_db_status("complete")

    def finish_error(self, error: str):
        """Mark sync failed."""
        self.finished_at = _now()
        self.event("SYNC_ERROR", {"error": error})
        self._update_db_status("error")

    def _update_db_status(self, status: str):
        """Update the run's finished_at and status in SQLite."""
        if not self.run_id:
            return
        try:
            from app.database import _get_conn
            conn = _get_conn()
            conn.execute(
                "UPDATE sync_log_runs SET finished_at=?, status=? WHERE id=?",
                (self.finished_at, status, self.run_id),
            )
            conn.commit()
        except Exception as e:
            logger.error("Failed to update sync log run status: %s", e)

    def to_dict(self) -> dict:
        """Serialize for API response."""
        with self._lock:
            elapsed = None
            if self.finished_at and self.started_at:
                try:
                    t0 = datetime.fromisoformat(self.started_at)
                    t1 = datetime.fromisoformat(self.finished_at)
                    elapsed = round((t1 - t0).total_seconds(), 1)
                except Exception:
                    pass
            return {
                "data_type": self.data_type,
                "mode": "full" if self.full else "delta",
                "api_base": self.api_base,
                "endpoint": self.endpoint,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "elapsed_seconds": elapsed,
                "events": list(self.events),
            }

    def render_text(self) -> str:
        """Render a human-readable text report for copy/paste."""
        with self._lock:
            return _render_log_text(
                data_type=self.data_type,
                full=self.full,
                api_base=self.api_base,
                endpoint=self.endpoint,
                started_at=self.started_at,
                finished_at=self.finished_at,
                events=list(self.events),
            )


# ── Module-level storage ─────────────────────────────────────────────────
# In-memory cache — fast access for the current worker.
# Falls back to SQLite if not found (worker restart).

_sync_logs: dict[str, SyncLog] = {}
_logs_lock = threading.Lock()


def create_sync_log(data_type: str, full: bool, api_base: str, endpoint: str) -> SyncLog:
    """Create and register a new sync log."""
    log = SyncLog(data_type, full, api_base, endpoint)
    with _logs_lock:
        _sync_logs[data_type] = log
    return log


def get_sync_log(data_type: str) -> SyncLog | None:
    """Retrieve the last sync log for a data type.

    Tries in-memory first, falls back to reconstructing from SQLite.
    """
    with _logs_lock:
        log = _sync_logs.get(data_type)
        if log:
            return log

    # Fallback: reconstruct from SQLite (worker may have restarted)
    return _load_sync_log_from_db(data_type)


def _load_sync_log_from_db(data_type: str) -> SyncLog | None:
    """Reconstruct the last SyncLog from the database."""
    try:
        from app.database import _get_conn
        conn = _get_conn()

        # Get the most recent run for this data type
        run = conn.execute(
            """SELECT * FROM sync_log_runs
               WHERE data_type = ?
               ORDER BY id DESC LIMIT 1""",
            (data_type,),
        ).fetchone()

        if not run:
            return None

        # Load all events for this run
        events = conn.execute(
            "SELECT ts, event_type, detail_json FROM sync_log_events WHERE run_id = ? ORDER BY id",
            (run["id"],),
        ).fetchall()

        # Build a lightweight wrapper for rendering
        return _DbSyncLog(run, events)

    except Exception as e:
        logger.error("Failed to load sync log from DB: %s", e)
        return None


class _DbSyncLog:
    """Read-only SyncLog reconstructed from database rows."""

    def __init__(self, run_row, event_rows):
        self.data_type = run_row["data_type"]
        self.full = bool(run_row["full"])
        self.api_base = run_row["api_base"]
        self.endpoint = run_row["endpoint"]
        self.started_at = run_row["started_at"]
        self.finished_at = run_row["finished_at"]
        self.status = run_row["status"]

        self.events = []
        for row in event_rows:
            entry = {"ts": row["ts"], "event": row["event_type"]}
            if row["detail_json"]:
                try:
                    entry["detail"] = json.loads(row["detail_json"])
                except (json.JSONDecodeError, TypeError):
                    entry["detail"] = {"raw": row["detail_json"]}
            self.events.append(entry)

    def render_text(self) -> str:
        status_note = None
        if self.status == "running" and not self.finished_at:
            status_note = "(Worker was killed — sync did not complete)"
        return _render_log_text(
            data_type=self.data_type,
            full=self.full,
            api_base=self.api_base,
            endpoint=self.endpoint,
            started_at=self.started_at,
            finished_at=self.finished_at,
            events=self.events,
            status_note=status_note,
        )

    def to_dict(self) -> dict:
        elapsed = None
        if self.finished_at and self.started_at:
            try:
                t0 = datetime.fromisoformat(self.started_at)
                t1 = datetime.fromisoformat(self.finished_at)
                elapsed = round((t1 - t0).total_seconds(), 1)
            except Exception:
                pass
        return {
            "data_type": self.data_type,
            "mode": "full" if self.full else "delta",
            "api_base": self.api_base,
            "endpoint": self.endpoint,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": elapsed,
            "status": self.status,
            "events": self.events,
        }


# ── Shared rendering ─────────────────────────────────────────────────────

def _render_log_text(
    data_type: str,
    full: bool,
    api_base: str,
    endpoint: str,
    started_at: str,
    finished_at: str | None,
    events: list[dict],
    status_note: str | None = None,
) -> str:
    """Render a human-readable text report for copy/paste."""
    lines = []
    lines.append("=" * 64)
    label = data_type.upper()
    lines.append(f"  {label} SYNC LOG")
    lines.append("=" * 64)
    lines.append(f"Mode:      {'Full' if full else 'Delta'}")
    lines.append(f"API Base:  {api_base}")
    lines.append(f"Endpoint:  {endpoint}")
    lines.append(f"Started:   {started_at}")
    if finished_at:
        lines.append(f"Finished:  {finished_at}")
        try:
            t0 = datetime.fromisoformat(started_at)
            t1 = datetime.fromisoformat(finished_at)
            elapsed = round((t1 - t0).total_seconds(), 1)
            lines.append(f"Elapsed:   {elapsed}s")
        except Exception:
            pass
    else:
        lines.append("Status:    RUNNING")
    if status_note:
        lines.append(f"Note:      {status_note}")
    lines.append("-" * 64)
    lines.append("")

    for evt in events:
        ts = evt["ts"]
        try:
            t = datetime.fromisoformat(ts)
            ts_short = t.strftime("%H:%M:%S.%f")[:-3]
        except Exception:
            ts_short = ts
        event_type = evt["event"]
        detail = evt.get("detail", {})

        lines.append(f"[{ts_short}] {event_type}")
        if detail:
            for k, v in detail.items():
                val_str = str(v)
                if len(val_str) > 500:
                    val_str = val_str[:500] + "... (truncated)"
                lines.append(f"    {k}: {val_str}")
        lines.append("")

    lines.append("=" * 64)
    lines.append("END OF LOG")
    lines.append("=" * 64)
    return "\n".join(lines)


def get_sync_history(data_type: str, limit: int = 20) -> list[dict]:
    """Retrieve the last *limit* sync logs for a data type.

    Returns a list of dicts (most recent first), each with:
        run_id, started_at, finished_at, status, mode, text
    """
    try:
        from app.database import _get_conn
        conn = _get_conn()

        runs = conn.execute(
            """SELECT * FROM sync_log_runs
               WHERE data_type = ?
               ORDER BY id DESC LIMIT ?""",
            (data_type, limit),
        ).fetchall()

        result = []
        for run in runs:
            events = conn.execute(
                "SELECT ts, event_type, detail_json FROM sync_log_events WHERE run_id = ? ORDER BY id",
                (run["id"],),
            ).fetchall()

            db_log = _DbSyncLog(run, events)
            result.append({
                "run_id": run["id"],
                "started_at": run["started_at"],
                "finished_at": run["finished_at"],
                "status": run["status"],
                "mode": "full" if run["full"] else "delta",
                "text": db_log.render_text(),
            })

        return result
    except Exception as e:
        logger.error("Failed to load sync history: %s", e)
        return []
