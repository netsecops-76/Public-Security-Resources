"""
Q KB Explorer — Sync Scheduler
Built by netsecops-76

Background scheduler for recurring delta syncs.
Uses APScheduler with in-process BackgroundScheduler (no Redis/Celery needed).
All jobs run in UTC internally; user's local timezone is stored for display.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime

import pytz
from apscheduler.schedulers.background import BackgroundScheduler

from apscheduler.triggers.cron import CronTrigger

from app.database import (
    get_all_schedules,
    get_schedule,
    save_schedule,
    delete_schedule as db_delete_schedule,
    update_schedule_last_run,
    get_maintenance_config,
    get_auto_update_config,
    update_auto_update_last_check,
)

logger = logging.getLogger(__name__)

# Module-level scheduler instance
_scheduler: BackgroundScheduler | None = None

# Frequency → interval in days
FREQUENCY_DAYS = {
    "daily":    1,    # ← added for the middleware use case where
                      # data freshness matters; see README's
                      # caching-middleware section
    "2x_week":  3.5,
    "1x_week":  7,
    "2x_month": 15,
    "1x_month": 30,
}

FREQUENCY_LABELS = {
    "daily":    "Daily",
    "2x_week":  "Twice a week",
    "1x_week":  "Once a week",
    "2x_month": "Twice a month",
    "1x_month": "Once a month",
}


def init_scheduler(app):
    """Initialize the background scheduler and restore saved schedules.

    Must be called after init_db() so the sync_schedules table exists.
    """
    global _scheduler

    _scheduler = BackgroundScheduler(timezone=pytz.utc, daemon=True)

    # Restore saved schedules from DB
    schedules = get_all_schedules()
    for sched in schedules:
        try:
            _add_job(sched["data_type"], sched)
            logger.info("Restored schedule for %s: %s", sched["data_type"], sched["frequency"])
        except Exception as e:
            logger.warning("Failed to restore schedule for %s: %s", sched["data_type"], e)

    # Restore database maintenance schedule
    _restore_maintenance_schedule()
    # Restore automatic application update schedule
    _restore_auto_update_schedule()

    _scheduler.start()
    logger.info("Sync scheduler started with %d restored jobs", len(schedules))


def _local_to_utc(date_str: str, time_str: str, tz_name: str) -> datetime:
    """Convert a local date + time to a UTC datetime.

    Args:
        date_str: 'YYYY-MM-DD'
        time_str: 'HH:MM'
        tz_name: IANA timezone (e.g. 'America/Phoenix')
    """
    tz = pytz.timezone(tz_name)
    naive = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
    local_dt = tz.localize(naive)
    return local_dt.astimezone(pytz.utc)


def _utc_to_local(utc_dt: datetime, tz_name: str) -> datetime:
    """Convert a UTC datetime to a local datetime."""
    tz = pytz.timezone(tz_name)
    if utc_dt.tzinfo is None:
        utc_dt = pytz.utc.localize(utc_dt)
    return utc_dt.astimezone(tz)


def _add_job(data_type: str, sched: dict):
    """Add an APScheduler interval job for a sync schedule."""
    if not _scheduler:
        return

    freq = sched["frequency"]
    days = FREQUENCY_DAYS.get(freq)
    if not days:
        raise ValueError(f"Unknown frequency: {freq}")

    # Calculate UTC start time from user's local time
    utc_start = _local_to_utc(sched["start_date"], sched["start_time"], sched["timezone"])

    # If the start time is in the past, APScheduler will calculate the
    # correct next run based on the interval from that start point.
    now_utc = datetime.now(pytz.utc)
    next_run = utc_start
    if next_run < now_utc:
        # Calculate next future occurrence that aligns with the original start time
        from datetime import timedelta
        interval = timedelta(days=days)
        while next_run < now_utc:
            next_run += interval

    _scheduler.add_job(
        execute_scheduled_sync,
        "interval",
        days=days,
        args=[data_type],
        id=f"sync_{data_type}",
        next_run_time=next_run,
        replace_existing=True,
        misfire_grace_time=3600,  # Allow 1 hour of misfire tolerance
    )

    # Store next_run_utc in DB
    update_schedule_last_run(
        data_type,
        last_run_utc=sched.get("last_run_utc") or "",
        next_run_utc=next_run.isoformat(),
    )


def execute_scheduled_sync(data_type: str):
    """Execute a scheduled delta sync. Called by APScheduler.

    Reuses the same sync infrastructure as the manual trigger_sync route.
    Acquires the global sync mutex blocking, so two schedules that fire
    at the same minute run sequentially instead of contending.
    """
    # Import here to avoid circular imports
    from app.main import (
        _active_syncs, _sync_progress, _build_client, app,
        _sync_mutex, _sync_mutex_owner,
    )
    from app.sync import SyncEngine
    from app.sync_log import create_sync_log

    logger.info("Scheduled sync starting for %s", data_type)

    # Skip if same-type sync already running (idempotency for misfires)
    thread = _active_syncs.get(data_type)
    if thread and thread.is_alive():
        logger.info("Skipping scheduled %s sync — already running", data_type)
        return

    # Load schedule from DB for credentials
    sched = get_schedule(data_type)
    if not sched:
        logger.warning("No schedule found for %s — skipping", data_type)
        return

    # Block until any in-flight sync finishes (queue behaviour for
    # schedules that all fire at the same minute, e.g. weekly 02:00).
    if _sync_mutex.locked():
        running = _sync_mutex_owner.get("data_type") or "unknown"
        logger.info("Scheduled %s sync waiting — %s is running",
                    data_type, running)
    _sync_mutex.acquire()
    _sync_mutex_owner["data_type"] = data_type
    import time as _time_mod
    _sync_mutex_owner["started_at"] = _time_mod.strftime(
        "%Y-%m-%dT%H:%M:%SZ", _time_mod.gmtime())
    logger.info("Scheduled %s sync acquired mutex — proceeding", data_type)

    # Build client using stored credentials
    with app.app_context():
        client, error, cred_id = _build_client({
            "credential_id": sched["credential_id"],
            "platform": sched["platform"],
        })
        if error:
            logger.error("Scheduled %s sync failed to build client: %s", data_type, error)
            return

        # Create sync log
        endpoints = {
            "qids": "/api/4.0/fo/knowledge_base/vuln/",
            "cids": "/api/4.0/fo/compliance/control/",
            "policies": "/api/4.0/fo/compliance/policy/",
            "mandates": "/api/4.0/fo/compliance/control/",
            "tags": "/qps/rest/2.0/search/am/tag",
            "pm_patches": "/pm/v2/patches",
        }
        sync_log = create_sync_log(data_type, False, client.api_base, endpoints[data_type])
        client.sync_log = sync_log

        def on_progress(info):
            _sync_progress[data_type] = {**info, "running": True}

        def run_sync():
            try:
                engine = SyncEngine(
                    client, credential_id=cred_id,
                    on_progress=on_progress, sync_log=sync_log,
                )
                method = {
                    "qids": engine.sync_qids,
                    "cids": engine.sync_cids,
                    "policies": engine.sync_policies,
                    "mandates": engine.sync_mandates,
                    "tags": engine.sync_tags,
                    "pm_patches": engine.sync_pm_patches,
                }[data_type]
                result = method(full=False)
                _sync_progress[data_type] = result
                logger.info("Scheduled %s sync complete: %d items", data_type, result.get("items_synced", 0))
            except Exception as e:
                logger.exception("Scheduled sync %s failed", data_type)
                sync_log.finish_error(str(e))
                _sync_progress[data_type] = {"type": data_type, "error": str(e)}
            finally:
                _active_syncs.pop(data_type, None)
                # Update last_run in DB
                now_utc = datetime.now(pytz.utc).isoformat()
                # Get next_run from APScheduler
                next_utc = None
                if _scheduler:
                    job = _scheduler.get_job(f"sync_{data_type}")
                    if job and job.next_run_time:
                        next_utc = job.next_run_time.isoformat()
                update_schedule_last_run(data_type, now_utc, next_utc)
                # Release the global sync mutex so the next queued sync
                # can proceed.
                _sync_mutex_owner["data_type"] = None
                _sync_mutex_owner["started_at"] = None
                try:
                    _sync_mutex.release()
                except RuntimeError:
                    logger.warning("Sync mutex was not held when releasing in scheduled run")

        sync_thread = threading.Thread(target=run_sync, daemon=True)
        _active_syncs[data_type] = sync_thread
        _sync_progress[data_type] = {"type": data_type, "status": "started"}
        sync_thread.start()


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def add_schedule(data_type: str, credential_id: str, platform: str,
                 frequency: str, start_date: str, start_time: str,
                 timezone: str) -> dict:
    """Create or update a sync schedule.

    Returns the schedule info dict.
    """
    if frequency not in FREQUENCY_DAYS:
        raise ValueError(f"Invalid frequency: {frequency}. Use: {list(FREQUENCY_DAYS.keys())}")

    # Calculate next_run_utc
    utc_start = _local_to_utc(start_date, start_time, timezone)
    now_utc = datetime.now(pytz.utc)
    next_run = utc_start
    if next_run < now_utc:
        from datetime import timedelta
        interval = timedelta(days=FREQUENCY_DAYS[frequency])
        while next_run < now_utc:
            next_run += interval

    # Save to DB
    save_schedule(
        data_type, credential_id, platform, frequency,
        start_date, start_time, timezone, next_run.isoformat(),
    )

    # Add APScheduler job
    sched = get_schedule(data_type)
    if sched:
        _add_job(data_type, sched)

    return get_schedule_info_for_type(data_type)


def remove_schedule(data_type: str) -> bool:
    """Remove a sync schedule."""
    if _scheduler:
        try:
            _scheduler.remove_job(f"sync_{data_type}")
        except Exception:
            pass  # Job may not exist
    return db_delete_schedule(data_type)


def get_schedule_info() -> list[dict]:
    """Get all schedules with display-friendly info."""
    schedules = get_all_schedules()
    result = []
    for sched in schedules:
        result.append(_format_schedule(sched))
    return result


def get_schedule_info_for_type(data_type: str) -> dict | None:
    """Get schedule info for a single data type."""
    sched = get_schedule(data_type)
    if not sched:
        return None
    return _format_schedule(sched)


def _format_schedule(sched: dict) -> dict:
    """Format a schedule record for API response with local time display."""
    tz_name = sched.get("timezone", "UTC")
    info = {
        "data_type": sched["data_type"],
        "credential_id": sched.get("credential_id"),
        "platform": sched.get("platform"),
        "frequency": sched["frequency"],
        "frequency_label": FREQUENCY_LABELS.get(sched["frequency"], sched["frequency"]),
        "start_date": sched["start_date"],
        "start_time": sched["start_time"],
        "timezone": tz_name,
        "enabled": bool(sched.get("enabled", 1)),
    }

    # Convert next_run_utc to user's local time for display
    if sched.get("next_run_utc"):
        try:
            utc_dt = datetime.fromisoformat(sched["next_run_utc"].replace("Z", "+00:00"))
            local_dt = _utc_to_local(utc_dt, tz_name)
            info["next_run_local"] = local_dt.strftime("%Y-%m-%d %I:%M %p")
            info["next_run_utc"] = sched["next_run_utc"]
        except Exception:
            info["next_run_local"] = None
            info["next_run_utc"] = sched.get("next_run_utc")
    else:
        info["next_run_local"] = None
        info["next_run_utc"] = None

    # Convert last_run_utc to user's local time for display
    if sched.get("last_run_utc") and sched["last_run_utc"]:
        try:
            utc_dt = datetime.fromisoformat(sched["last_run_utc"].replace("Z", "+00:00"))
            local_dt = _utc_to_local(utc_dt, tz_name)
            info["last_run_local"] = local_dt.strftime("%Y-%m-%d %I:%M %p")
        except Exception:
            info["last_run_local"] = None
    else:
        info["last_run_local"] = None

    # Get actual next_run from APScheduler if available (more accurate)
    if _scheduler:
        job = _scheduler.get_job(f"sync_{sched['data_type']}")
        if job and job.next_run_time:
            try:
                local_dt = _utc_to_local(job.next_run_time, tz_name)
                info["next_run_local"] = local_dt.strftime("%Y-%m-%d %I:%M %p")
                info["next_run_utc"] = job.next_run_time.isoformat()
            except Exception:
                pass

    return info


# ═══════════════════════════════════════════════════════════════════════════
# Database Maintenance Scheduling
# ═══════════════════════════════════════════════════════════════════════════

# APScheduler day_of_week: mon=0..sun=6
# Our DB stores: 0=Sunday..6=Saturday
# Mapping: our 0(Sun)→6, 1(Mon)→0, 2(Tue)→1, ..., 6(Sat)→5
_DOW_TO_APSCHEDULER = {0: 6, 1: 0, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5}

_MAINTENANCE_JOB_ID = "db_maintenance"


def _execute_maintenance():
    """APScheduler callback — run database maintenance."""
    from app.maintenance import run_maintenance
    logger.info("[Maintenance] Starting scheduled database maintenance...")
    result = run_maintenance()
    if result["status"] == "ok":
        logger.info("[Maintenance] Completed in %.1fs", result["duration_s"])
    else:
        logger.error("[Maintenance] Failed: %s", result.get("error"))


def _restore_maintenance_schedule():
    """Restore maintenance schedule from DB on startup."""
    try:
        config = get_maintenance_config()
        if config and config.get("enabled"):
            tz_name = config.get("timezone") or _get_system_timezone()
            _schedule_maintenance_job(
                config["day_of_week"], config["hour"], config["minute"], tz_name
            )
            logger.info("[Maintenance] Restored schedule: day=%d hour=%d:%02d tz=%s",
                         config["day_of_week"], config["hour"], config["minute"], tz_name)
    except Exception as e:
        logger.warning("[Maintenance] Failed to restore schedule: %s", e)


def schedule_maintenance(day_of_week: int, hour: int, minute: int,
                         timezone: str) -> dict | None:
    """Create or update the weekly maintenance schedule.

    Args:
        day_of_week: 0=Sunday..6=Saturday
        hour: 0-23
        minute: 0-59
        timezone: IANA timezone name
    """
    _schedule_maintenance_job(day_of_week, hour, minute, timezone)
    return get_maintenance_schedule_info(timezone)


def _schedule_maintenance_job(day_of_week: int, hour: int, minute: int,
                              timezone: str):
    """Add or replace the APScheduler cron job for maintenance."""
    if not _scheduler:
        return
    # Remove existing job if any
    try:
        _scheduler.remove_job(_MAINTENANCE_JOB_ID)
    except Exception:
        pass

    ap_dow = _DOW_TO_APSCHEDULER.get(day_of_week, 6)  # default Sunday
    trigger = CronTrigger(
        day_of_week=ap_dow, hour=hour, minute=minute,
        timezone=pytz.timezone(timezone) if timezone else pytz.utc,
    )
    _scheduler.add_job(
        _execute_maintenance,
        trigger=trigger,
        id=_MAINTENANCE_JOB_ID,
        replace_existing=True,
        misfire_grace_time=3600,
    )


def remove_maintenance_schedule():
    """Remove the maintenance schedule."""
    if _scheduler:
        try:
            _scheduler.remove_job(_MAINTENANCE_JOB_ID)
        except Exception:
            pass


def get_maintenance_schedule_info(timezone: str = "") -> dict | None:
    """Get next run time for the maintenance job."""
    if not _scheduler:
        return None
    job = _scheduler.get_job(_MAINTENANCE_JOB_ID)
    if not job or not job.next_run_time:
        return None
    tz_name = timezone or "UTC"
    try:
        local_dt = _utc_to_local(job.next_run_time, tz_name)
        return {
            "next_run_local": local_dt.strftime("%Y-%m-%d %I:%M %p"),
            "next_run_utc": job.next_run_time.isoformat(),
        }
    except Exception:
        return {"next_run_utc": job.next_run_time.isoformat()}


def _get_system_timezone() -> str:
    """Get the system's local timezone name."""
    try:
        import time as _time
        return _time.tzname[0] or "UTC"
    except Exception:
        return "UTC"


# ═══════════════════════════════════════════════════════════════════════════
# Automatic Application Update Scheduling
# ═══════════════════════════════════════════════════════════════════════════

_AUTO_UPDATE_JOB_ID = "auto_update"


def _execute_auto_update():
    """APScheduler callback — invoke the in-app updater and record the result.

    apply_update() schedules a SIGTERM to PID 1 a couple of seconds after
    it returns when an update was actually applied; we record last_check
    BEFORE that fires so the result persists across the container
    restart.

    Re-checks the config on entry so a job that was already triggered
    when the user disabled auto-updates does not still apply an update.
    """
    # Re-check enabled state at fire time. A misfire grace window or a
    # disable-while-firing race must not slip through.
    cfg = get_auto_update_config()
    if not cfg or not cfg.get("enabled"):
        logger.info("[Auto-Update] Job fired but config is disabled — skipping")
        return

    from app.updater import apply_update
    logger.info("[Auto-Update] Scheduled update check starting...")
    try:
        result = apply_update()
    except Exception as e:
        logger.exception("[Auto-Update] apply_update raised")
        try:
            update_auto_update_last_check("error", str(e), None)
        except Exception:
            pass
        return

    status = result.get("status")
    if status == "ok":
        msg = result.get("message", "") or ""
        version = result.get("version_short") or result.get("version")
        if "up to date" in msg.lower():
            update_auto_update_last_check("up_to_date", None, version)
            logger.info("[Auto-Update] Already up to date (%s)", version or "?")
        else:
            update_auto_update_last_check("updated", None, version)
            logger.info("[Auto-Update] Updated to %s — container will restart", version or "?")
    else:
        err = result.get("error") or "Unknown error"
        update_auto_update_last_check("error", err, None)
        logger.error("[Auto-Update] Failed: %s", err)


def _restore_auto_update_schedule():
    """Restore the auto-update schedule from DB on startup."""
    try:
        cfg = get_auto_update_config()
        if cfg and cfg.get("enabled"):
            tz_name = cfg.get("timezone") or _get_system_timezone()
            _schedule_auto_update_job(
                cfg["day_of_week"], cfg["hour"], cfg["minute"], tz_name,
            )
            logger.info("[Auto-Update] Restored schedule: day=%d hour=%d:%02d tz=%s",
                        cfg["day_of_week"], cfg["hour"], cfg["minute"], tz_name)
    except Exception as e:
        logger.warning("[Auto-Update] Failed to restore schedule: %s", e)


def schedule_auto_update(day_of_week: int, hour: int, minute: int,
                         timezone: str) -> dict | None:
    """Create or update the weekly automatic-update schedule.

    Args:
        day_of_week: 0=Sunday..6=Saturday (matches the maintenance convention).
        hour: 0-23
        minute: 0-59
        timezone: IANA timezone name.
    """
    _schedule_auto_update_job(day_of_week, hour, minute, timezone)
    return get_auto_update_schedule_info(timezone)


def _schedule_auto_update_job(day_of_week: int, hour: int, minute: int,
                              timezone: str):
    """Add or replace the APScheduler cron job for auto-updates."""
    if not _scheduler:
        return
    try:
        _scheduler.remove_job(_AUTO_UPDATE_JOB_ID)
    except Exception:
        pass

    ap_dow = _DOW_TO_APSCHEDULER.get(day_of_week, 6)
    trigger = CronTrigger(
        day_of_week=ap_dow, hour=hour, minute=minute,
        timezone=pytz.timezone(timezone) if timezone else pytz.utc,
    )
    _scheduler.add_job(
        _execute_auto_update,
        trigger=trigger,
        id=_AUTO_UPDATE_JOB_ID,
        replace_existing=True,
        misfire_grace_time=3600,
    )


def remove_auto_update_schedule():
    """Remove the auto-update schedule."""
    if _scheduler:
        try:
            _scheduler.remove_job(_AUTO_UPDATE_JOB_ID)
        except Exception:
            pass


def get_auto_update_schedule_info(timezone: str = "") -> dict | None:
    """Return next-run info for the auto-update job, or None if not scheduled."""
    if not _scheduler:
        return None
    job = _scheduler.get_job(_AUTO_UPDATE_JOB_ID)
    if not job or not job.next_run_time:
        return None
    tz_name = timezone or "UTC"
    try:
        local_dt = _utc_to_local(job.next_run_time, tz_name)
        return {
            "next_run_local": local_dt.strftime("%Y-%m-%d %I:%M %p"),
            "next_run_utc": job.next_run_time.isoformat(),
        }
    except Exception:
        return {"next_run_utc": job.next_run_time.isoformat()}
