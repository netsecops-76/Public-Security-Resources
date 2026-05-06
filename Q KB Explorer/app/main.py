"""
Q KB Explorer - Backend Server
Built by netsecops-76
Qualys Knowledge Base & Policy Compliance explorer.
"""

from __future__ import annotations

import csv
import io
import logging
import os
import secrets
import json
import threading
import time
import requests as http_requests
from flask import Flask, render_template, request, jsonify, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.vault import (
    list_credentials, save_credential, update_credential, delete_credential,
    verify_password, get_credential_for_api,
)
from app.database import (
    init_db, get_sync_status, purge_data,
    search_vulns, get_vuln,
    search_controls, get_control,
    search_policies, get_policy, delete_policies,
    search_mandates, get_mandate, get_mandate_filter_values,
    store_policy_export, get_policy_export_xml, get_policy_report_data, get_stale_exports,
    get_qid_filter_values, get_cid_filter_values, get_policy_filter_values,
    resolve_policy_control_cids,
    get_dashboard_stats, get_mandate_compliance_map,
    search_tags, get_tag, get_tag_filter_values,
    set_tag_classification_override,
    set_tag_editability_override,
    store_tag_export, get_tag_export_json, list_tag_exports, delete_tag_export,
    get_tag, upsert_tag,
    list_library_entries, get_library_entry, create_library_entry,
    update_library_entry, delete_library_entry, unhide_library_entry,
    clone_library_entry, record_library_apply, list_library_applies,
    get_pm_patches_for_qid, get_pm_patch_qid_flags, pm_patch_stats,
)
from app.qualys_client import QualysClient
from app.sync import SyncEngine
from app.sync_log import create_sync_log, get_sync_log, get_sync_history
from app.scheduler import init_scheduler, add_schedule, remove_schedule, get_schedule_info
from app.openapi import (
    api as openapi,
    Error,
    Pagination,
    OkMessage,
    TAG_QIDS, TAG_CIDS, TAG_POLICIES, TAG_TAGS, TAG_LIBRARY, TAG_AUDIT,
    TAG_INTEL, TAG_SYNC, TAG_SCHED, TAG_HEALTH,
)
from spectree import Response as OpenApiResponse
from pydantic import BaseModel, Field, RootModel

logger = logging.getLogger(__name__)

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=[])

# Initialize SQLite on startup
with app.app_context():
    init_db()
    resolved = resolve_policy_control_cids()
    if resolved:
        logger.info("Resolved %d policy control CIDs on startup", resolved)

    # Close out any sync_log_runs that were left status='running' with
    # no finished_at — they're from a worker that was killed by a
    # container restart (the only way a Python sync exits without
    # writing finished_at). Marking them errored here means subsequent
    # log views render with a clean "Interrupted" status instead of
    # the alarming "Worker was killed — sync did not complete" note,
    # which fires every time the renderer sees a never-finished row.
    try:
        from app.database import get_db as _gdb
        with _gdb() as _conn:
            _interrupted = _conn.execute(
                """UPDATE sync_log_runs
                   SET status='error', finished_at=?
                   WHERE status='running' AND finished_at IS NULL""",
                (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),),
            ).rowcount
        if _interrupted:
            logger.info("Marked %d unfinished sync_log_runs as interrupted on startup",
                        _interrupted)
    except Exception as _e:
        logger.warning("Stale sync_log_runs cleanup failed (non-fatal): %s", _e)

    init_scheduler(app)

    # Run ad-hoc maintenance on startup if no previous run exists
    from app.database import get_maintenance_config
    maint_config = get_maintenance_config()
    if not maint_config.get("last_run"):
        import threading
        def _startup_maintenance():
            import time
            time.sleep(10)  # Let the app fully start first
            from app.maintenance import run_maintenance
            logger.info("[Startup] No previous maintenance — running ad-hoc maintenance...")
            result = run_maintenance()
            if result["status"] == "ok":
                logger.info("[Startup] Ad-hoc maintenance completed in %.1fs", result["duration_s"])
            else:
                logger.error("[Startup] Ad-hoc maintenance failed: %s", result.get("error"))
        threading.Thread(target=_startup_maintenance, daemon=True).start()

# ─── Vault Auth Gate ──────────────────────────────────────────────────────
VAULT_AUTH_COOKIE = "qkbe-vault-unlocked"
_COOKIE_SECURE = os.environ.get("QKBE_TLS_ENABLED") == "1"

# In-memory session store: token → True (sessions clear on server restart)
_active_sessions: dict[str, bool] = {}

_AUTH_EXEMPT_PATHS = {
    "/api/credentials",
    "/api/credentials/verify",
    "/api/platforms",
    "/api/auth/logout",
    "/api/auth/session",
    "/api/health",
    "/api/tags/migrate-status",
}

# Paths exempt from CSRF header requirement (credential setup before app is usable)
_CSRF_EXEMPT_PATHS = {
    "/api/credentials",
    "/api/credentials/verify",
    "/api/auth/logout",
    "/api/auth/session",
}


@app.before_request
def vault_auth_gate():
    """Require vault unlock cookie for API routes when credentials exist."""
    path = request.path

    # Static files and non-API routes — always allowed
    if path.startswith("/static/") or not path.startswith("/api/"):
        return None

    # Exempt API paths — always allowed (auth check)
    if path in _AUTH_EXEMPT_PATHS:
        pass  # skip auth check but still apply CSRF below for non-exempt
    else:
        # If vault is empty, skip the gate (first-time users)
        if len(list_credentials()) == 0:
            pass  # skip auth check
        else:
            # Validate session token from cookie
            token = request.cookies.get(VAULT_AUTH_COOKIE)
            if not token or token not in _active_sessions:
                return jsonify({"error": "Vault authentication required"}), 401

    # CSRF: Require X-Requested-With header on state-changing requests
    if request.method in ("POST", "PATCH", "DELETE"):
        if path not in _CSRF_EXEMPT_PATHS:
            if not request.headers.get("X-Requested-With"):
                return jsonify({"error": "Missing required header"}), 403

    return None


# Track active sync threads
_active_syncs: dict[str, threading.Thread] = {}
_sync_progress: dict[str, dict] = {}

# Global sync serializer. Only one sync may run at a time across all data
# types — SQLite is single-writer and Qualys imposes per-account rate
# limits, so running QID + Policy + Tags in parallel just creates pain.
#
#   Manual triggers (HTTP routes)        → tryacquire(blocking=False).
#                                          If held, return 409 with the name
#                                          of the running sync.
#   Scheduled triggers (APScheduler)     → acquire(blocking=True). If two
#                                          schedules fire at the same
#                                          minute they run back-to-back
#                                          instead of in parallel.
#
# The lock is released in the sync thread's `finally` block so an
# exception or crash won't permanently deadlock the queue.
_sync_mutex = threading.Lock()
_sync_mutex_owner: dict = {"data_type": None, "started_at": None}

# Manual + scheduler-driven sync queue (FIFO). Stores entries waiting on
# the global mutex purely for visibility — the actual ordering is
# enforced by the threading.Lock(), not the queue list. Queue entries
# are added when a sync thread is spawned but before it acquires the
# lock, and removed once that thread successfully acquires.
_sync_queue: list[dict] = []
_sync_queue_lock = threading.Lock()


def _sync_queue_snapshot() -> list[dict]:
    with _sync_queue_lock:
        return [dict(e) for e in _sync_queue]


def _enqueue_sync(data_type: str, source: str = "manual") -> int:
    """Add a sync to the visibility queue. Returns 1-indexed position."""
    with _sync_queue_lock:
        _sync_queue.append({
            "data_type": data_type,
            "source": source,
            "queued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        return len(_sync_queue)


def _dequeue_sync(data_type: str) -> None:
    with _sync_queue_lock:
        for i, entry in enumerate(_sync_queue):
            if entry["data_type"] == data_type:
                del _sync_queue[i]
                return


def _is_data_type_pending(data_type: str) -> bool:
    """True if data_type is currently running OR already queued."""
    if _sync_mutex_owner.get("data_type") == data_type:
        return True
    with _sync_queue_lock:
        return any(e["data_type"] == data_type for e in _sync_queue)


def _sync_mutex_status() -> dict:
    """Return whether a sync is currently running and which one."""
    return {
        "locked": _sync_mutex.locked(),
        "data_type": _sync_mutex_owner.get("data_type"),
        "started_at": _sync_mutex_owner.get("started_at"),
        "queue": _sync_queue_snapshot(),
    }

# ─── Cache Busting ─────────────────────────────────────────────────────────
_APP_START_TS = str(int(time.time()))


@app.context_processor
def inject_cache_bust():
    return {"cache_bust": _APP_START_TS}


# ─── Qualys Platform Registry ───────────────────────────────────────────────
QUALYS_PLATFORMS = {
    "US1": {"api": "https://qualysapi.qualys.com", "gateway": "https://gateway.qg1.apps.qualys.com"},
    "US2": {"api": "https://qualysapi.qg2.apps.qualys.com", "gateway": "https://gateway.qg2.apps.qualys.com"},
    "US3": {"api": "https://qualysapi.qg3.apps.qualys.com", "gateway": "https://gateway.qg3.apps.qualys.com"},
    "US4": {"api": "https://qualysapi.qg4.apps.qualys.com", "gateway": "https://gateway.qg4.apps.qualys.com"},
    "EU1": {"api": "https://qualysapi.qualys.eu", "gateway": "https://gateway.qg1.apps.qualys.eu"},
    "EU2": {"api": "https://qualysapi.qg2.apps.qualys.eu", "gateway": "https://gateway.qg2.apps.qualys.eu"},
    "EU3": {"api": "https://qualysapi.qg3.apps.qualys.it", "gateway": "https://gateway.qg3.apps.qualys.it"},
    "IN1": {"api": "https://qualysapi.qg1.apps.qualys.in", "gateway": "https://gateway.qg1.apps.qualys.in"},
    "CA1": {"api": "https://qualysapi.qg1.apps.qualys.ca", "gateway": "https://gateway.qg1.apps.qualys.ca"},
    "AE1": {"api": "https://qualysapi.qg1.apps.qualys.ae", "gateway": "https://gateway.qg1.apps.qualys.ae"},
    "UK1": {"api": "https://qualysapi.qg1.apps.qualys.co.uk", "gateway": "https://gateway.qg1.apps.qualys.co.uk"},
    "AU1": {"api": "https://qualysapi.qg1.apps.qualys.com.au", "gateway": "https://gateway.qg1.apps.qualys.com.au"},
    "KSA1": {"api": "https://qualysapi.qg1.apps.qualysksa.com", "gateway": "https://gateway.qg1.apps.qualysksa.com"},
}


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Pages
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


class _PlatformsResponse(RootModel[dict]):
    """Map of platform-id → metadata (api base, gateway base, label).
    The frontend's platform picker reads this directly."""


@app.route("/api/platforms")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_PlatformsResponse),
    tags=[TAG_HEALTH],
)
def get_platforms():
    """Static map of every Qualys platform region the app knows about
    (US1-4, EU1-2, IN1, UAE1, KSA1, CA1, AU1, UK1, GOV)."""
    return jsonify(QUALYS_PLATFORMS)


class _HealthResponse(BaseModel):
    status: str = Field(..., description='"ok" when the worker is alive and the DB is reachable')
    syncing: dict = Field(default_factory=dict, description="Map of in-flight sync data_type → True")


@app.route("/api/health")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_HealthResponse),
    tags=[TAG_HEALTH],
)
def health_check():
    """Lightweight health check for Docker and external monitoring.
    No auth required; safe to poll. Returns the set of currently
    in-flight syncs as a side benefit for orchestration."""
    syncing = {k: v.is_alive() for k, v in _active_syncs.items() if v}
    return jsonify({"status": "ok", "syncing": syncing})


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Credential Vault
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/credentials", methods=["GET"])
def credentials_list():
    """List all saved credentials (without passwords)."""
    try:
        return jsonify(list_credentials())
    except Exception as e:
        logger.exception("Failed to load vault")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/credentials", methods=["POST"])
def credentials_save():
    """Save or update a credential. Password is encrypted server-side."""
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    platform = data.get("platform", "")
    api_version = data.get("api_version", "v5")
    display_name = data.get("display_name", "").strip()
    max_age = data.get("max_age")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    # Validate credentials can be used with Qualys Basic Auth (latin-1)
    try:
        f"{username}:{password}".encode("latin-1")
    except UnicodeEncodeError:
        return jsonify({"error": "Password contains characters not supported by "
                        "Qualys API authentication. Please use ASCII characters only."}), 400
    try:
        result = save_credential(username, password, platform, api_version,
                                  display_name=display_name)
        # Mint a vault-unlock session right here. The user just proved
        # they know the password by typing it into the Save form, so
        # forcing them through /api/credentials/verify on their very
        # next API call (e.g. clicking Full Sync) is redundant and bad
        # UX — it pops the re-auth modal seconds after a successful
        # save, asking for the same password they just entered.
        token = secrets.token_urlsafe(32)
        _active_sessions[token] = True
        resp = jsonify(result)
        resp.set_cookie(
            VAULT_AUTH_COOKIE, token,
            httponly=True, secure=_COOKIE_SECURE,
            samesite="Strict", path="/",
            max_age=int(max_age) if max_age else None,
        )
        return resp
    except Exception as e:
        logger.exception("Failed to save credential")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/credentials/<cred_id>", methods=["PATCH"])
def credentials_update(cred_id):
    """Update metadata on an existing credential (platform, api_version)."""
    data = request.json or {}
    try:
        result = update_credential(
            cred_id,
            platform=data.get("platform"),
            api_version=data.get("api_version"),
            display_name=data.get("display_name"),
        )
        if result is None:
            return jsonify({"error": "Credential not found"}), 404
        return jsonify(result)
    except Exception as e:
        logger.exception("Failed to update credential %s", cred_id)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/credentials/<cred_id>", methods=["DELETE"])
def credentials_delete(cred_id):
    """Delete a credential by ID."""
    try:
        if delete_credential(cred_id):
            return jsonify({"deleted": True, "id": cred_id})
        return jsonify({"error": "Credential not found"}), 404
    except Exception as e:
        logger.exception("Failed to delete credential %s", cred_id)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/credentials/verify", methods=["POST"])
@limiter.limit("5/minute")
def credentials_verify():
    """Verify a password against a stored credential."""
    data = request.json or {}
    cred_id = data.get("id", "")
    password = data.get("password", "")
    max_age = data.get("max_age")  # Optional session timeout in seconds
    if not cred_id or not password:
        return jsonify({"verified": False, "error": "ID and password required"}), 400
    try:
        if verify_password(cred_id, password):
            token = secrets.token_urlsafe(32)
            _active_sessions[token] = True
            resp = jsonify({"verified": True})
            resp.set_cookie(
                VAULT_AUTH_COOKIE, token,
                httponly=True, secure=_COOKIE_SECURE,
                samesite="Strict", path="/",
                max_age=int(max_age) if max_age else None,
            )
            return resp
        return jsonify({"verified": False, "error": "Incorrect password"}), 401
    except Exception as e:
        logger.exception("Vault verification error")
        return jsonify({"verified": False, "error": "Internal server error"}), 500


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    """Clear the vault unlock cookie and invalidate session."""
    token = request.cookies.get(VAULT_AUTH_COOKIE)
    if token:
        _active_sessions.pop(token, None)
    resp = jsonify({"logged_out": True})
    resp.delete_cookie(VAULT_AUTH_COOKIE, path="/", samesite="Strict")
    return resp


@app.route("/api/auth/session", methods=["PATCH"])
def auth_session_update():
    """Update session cookie expiry (for session timeout changes)."""
    token = request.cookies.get(VAULT_AUTH_COOKIE)
    if not token or token not in _active_sessions:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.json or {}
    max_age = data.get("max_age")
    resp = jsonify({"ok": True})
    resp.set_cookie(
        VAULT_AUTH_COOKIE, token,
        httponly=True, secure=_COOKIE_SECURE,
        samesite="Strict", path="/",
        max_age=int(max_age) if max_age else None,
    )
    return resp


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Connection Test
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/test-connection", methods=["POST"])
def test_connection():
    """Test connectivity to a Qualys platform.

    Supports two modes (like QAE):
      1. Raw credentials: { username, password, platform }  — test before save
      2. Vault credentials: { credential_id, platform }     — test after save
    """
    data = request.json or {}
    platform = data.get("platform", "")
    credential_id = data.get("credential_id", "")
    username = data.get("username", "")
    password = data.get("password", "")

    if not platform:
        return jsonify({"success": False, "error": "Select a Qualys platform first"}), 400

    plat = QUALYS_PLATFORMS.get(platform)
    if not plat:
        return jsonify({"success": False, "error": f"Unknown platform: {platform}"}), 400

    # Resolve credentials — vault lookup or raw
    if credential_id:
        cred = get_credential_for_api(credential_id)
        if not cred:
            return jsonify({"success": False, "error": "Saved credential not found or decryption failed"}), 401
        username = cred["username"]
        password = cred["password"]

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400

    api_base = plat["api"]
    url = f"{api_base}/api/4.0/fo/knowledge_base/vuln/"
    try:
        resp = http_requests.post(
            url,
            auth=(username, password),
            data={"action": "list", "details": "None", "ids": "1"},
            headers={"X-Requested-With": "Q KB Explorer"},
            timeout=30,
        )
        if resp.status_code == 200:
            return jsonify({"success": True, "message": f"Connected to {platform}"})
        elif resp.status_code == 401:
            return jsonify({"success": False, "error": "Authentication failed — check username/password"}), 401
        elif resp.status_code == 403:
            return jsonify({"success": False, "error": "403 Forbidden — account may lack API access or IP not allowed"}), 403
        else:
            return jsonify({"success": False, "error": f"HTTP {resp.status_code}: {resp.reason}"}), 502
    except http_requests.exceptions.Timeout:
        return jsonify({"success": False, "error": "Connection timed out"}), 504
    except http_requests.exceptions.ConnectionError:
        return jsonify({"success": False, "error": f"Cannot reach {api_base}"}), 502
    except Exception as e:
        logger.exception("Connection test failed")
        return jsonify({"success": False, "error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Helper — Build QualysClient from request data
# ═══════════════════════════════════════════════════════════════════════════

def _build_client(data: dict) -> tuple[QualysClient | None, str | None, str]:
    """Build QualysClient from credential_id + platform.
    Returns (client, error_message, credential_id).
    If platform is not in the request, falls back to the credential's stored platform.
    """
    cred_id = data.get("credential_id", "")
    if not cred_id:
        return None, "credential_id required", cred_id
    cred = get_credential_for_api(cred_id)
    if not cred:
        return None, "Saved credential not found or decryption failed", cred_id
    # Resolve platform: request > credential's stored platform
    platform = data.get("platform", "") or cred.get("platform", "")
    if not platform:
        return None, "No platform specified and credential has no stored platform", cred_id
    plat = QUALYS_PLATFORMS.get(platform)
    if not plat:
        return None, f"Unknown platform: {platform}", cred_id
    client = QualysClient(plat["api"], cred["username"], cred["password"])
    return client, None, cred_id


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Sync
# ═══════════════════════════════════════════════════════════════════════════

class _SyncStatusResponse(RootModel[dict]):
    """Per-data-type sync state. Each value carries last_sync,
    last_full_sync, record_count, last_missing_count, syncing,
    needs_full_refresh, elapsed_seconds, and credential_id."""


@app.route("/api/sync/status")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_SyncStatusResponse, HTTP_500=Error),
    tags=[TAG_SYNC],
)
def sync_status():
    """Sync watermarks + live state for every data type. Drives the
    Settings sync card and the per-row meta lines."""
    try:
        status = get_sync_status()
        for dtype in ("qids", "cids", "policies", "mandates", "tags", "pm_patches"):
            if dtype not in status:
                status[dtype] = {"last_sync": None, "last_full_sync": None, "record_count": 0}
            thread = _active_syncs.get(dtype)
            status[dtype]["syncing"] = thread is not None and thread.is_alive()
            status[dtype]["needs_full_refresh"] = SyncEngine.needs_full_refresh(dtype)
        return jsonify(status)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


class _SyncActiveResponse(BaseModel):
    locked: bool = Field(..., description="True when a sync is currently holding the global mutex")
    data_type: str | None = Field(default=None, description="Which data type the active sync is for")
    started_at: str | None = None
    queue: list[dict] = Field(default_factory=list, description="FIFO queue of waiting syncs (data_type + queued_at + source)")


@app.route("/api/sync/active")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_SyncActiveResponse),
    tags=[TAG_SYNC],
)
def sync_active():
    """Snapshot of the global sync mutex — what's running, what's
    queued behind it. Polled by the UI's queue badge."""
    return jsonify(_sync_mutex_status())


def _is_dependency_satisfied(dep_type: str, before: str | None = None) -> bool:
    """True if ``dep_type`` is already synced, currently running, or
    already queued (optionally specifically before ``before``).

    Used by the Policy → CID auto-queue logic so we can ask "is CID
    going to be available by the time Policies runs?" — meaning it
    finished in the past, is the active sync, or is queued ahead of
    where Policies would land. Saves a useless error in cases where
    the dependency is moments away from being satisfied.
    """
    from app.database import get_last_sync_datetime
    if get_last_sync_datetime(dep_type):
        return True
    if _sync_mutex_owner.get("data_type") == dep_type:
        return True
    with _sync_queue_lock:
        for entry in _sync_queue:
            if entry["data_type"] == dep_type:
                if before is None:
                    return True
                # "ahead of before" means dep_type appears in queue
                # before the first occurrence of `before` (or before
                # `before` is appended). Since we're called pre-enqueue
                # of `before`, presence anywhere in the queue is enough.
                return True
    return False


@app.route("/api/sync/<data_type>", methods=["POST"])
def trigger_sync(data_type):
    """Trigger a sync. If another sync is already running, queue this one
    so it runs back-to-back instead of returning an error. Same-type
    duplicates are rejected (one click of QIDs is enough).

    Smart dependency handling: Policies require CIDs to be available.
    If CIDs haven't synced AND aren't running AND aren't queued, this
    handler auto-enqueues a CID sync first, then queues Policies behind
    it. Operator gets a single click → "queued CIDs + Policies" rather
    than an error telling them to do it manually."""
    if data_type not in ("qids", "cids", "policies", "mandates", "tags", "pm_patches"):
        return jsonify({"error": "Invalid data type. Use: qids, cids, policies, mandates, tags"}), 400

    # Same-type dedup: refuse if this exact data type is already running
    # or already queued. Other types fall through and queue normally.
    if _is_data_type_pending(data_type):
        running = _sync_mutex_owner.get("data_type") == data_type
        msg = (f"A {data_type} sync is already running."
               if running
               else f"A {data_type} sync is already queued.")
        return jsonify({"error": msg, "duplicate": True}), 409

    data = request.json or {}
    full = data.get("full", False)
    # Backfill mode: don't purge, fetch only missing IDs. Currently only
    # the QID sync engine implements it; other types ignore the flag.
    backfill = bool(data.get("backfill", False))
    if backfill and data_type != "qids":
        return jsonify({"error": "Backfill is currently only supported for QIDs"}), 400

    # Policy sync requires CIDs to be available (technology filters +
    # cross-references). If they aren't, auto-queue a CID delta sync
    # ahead of Policies rather than erroring out. The operator's intent
    # is clear; no reason to make them click twice.
    auto_queued: list[str] = []
    if data_type == "policies" and not _is_dependency_satisfied("cids"):
        cid_response, cid_status = _spawn_sync(
            "cids", full=False, backfill=False, data=data, source="auto_dep:policies",
        )
        if cid_status >= 400:
            # Couldn't auto-queue CIDs — surface that error rather
            # than blowing up later. Most likely cause: bad credential.
            return cid_response, cid_status
        auto_queued.append("cids")

    response, status = _spawn_sync(
        data_type, full=full, backfill=backfill, data=data, source="manual",
    )
    if auto_queued and status < 400:
        # Annotate the response so the UI can tell the operator "we
        # auto-queued CIDs ahead of your Policies sync" rather than
        # leaving them to figure it out from the queue snapshot.
        body = response.get_json() if hasattr(response, "get_json") else None
        if isinstance(body, dict):
            body["auto_queued_dependencies"] = auto_queued
            body["message"] = (body.get("message") or "")
            extra = (f" Auto-queued {', '.join(auto_queued)} first because "
                     f"{data_type} depends on them.")
            body["message"] = (body["message"] + extra).strip()
            response = jsonify(body)
    return response, status


def _spawn_sync(data_type, *, full, backfill, data, source):
    """Build the client, register the worker, and return (response, status).

    Extracted from trigger_sync so the auto-dependency path (e.g.
    Policies auto-queueing CIDs) can call it once per data type.
    Returns a Flask response + status int — caller is free to
    annotate the response payload before returning.
    """
    # Same-type dedup (defensive — also called via auto-dep path so
    # may be invoked for a type the queue already holds).
    if _is_data_type_pending(data_type):
        running = _sync_mutex_owner.get("data_type") == data_type
        msg = (f"A {data_type} sync is already running."
               if running
               else f"A {data_type} sync is already queued.")
        return jsonify({"error": msg, "duplicate": True}), 409

    client, error, cred_id = _build_client(data)
    if error:
        return jsonify({"error": error}), 400

    # Create structured sync log up front so the user can see "Queued"
    # status from the moment they click — sync_log_runs is keyed by
    # data_type so /sync/<type>/log returns this run even before the
    # mutex is acquired.
    endpoints = {"qids": "/api/4.0/fo/knowledge_base/vuln/", "cids": "/api/4.0/fo/compliance/control/", "policies": "/api/4.0/fo/compliance/policy/", "mandates": "/api/4.0/fo/compliance/control/", "tags": "/qps/rest/2.0/search/am/tag", "pm_patches": "/pm/v2/patches"}
    sync_log = create_sync_log(data_type, full, client.api_base, endpoints[data_type])
    client.sync_log = sync_log

    def on_progress(info):
        _sync_progress[data_type] = {**info, "running": True}

    # Decide queue vs immediate. We snapshot _sync_mutex.locked() here for
    # the response payload only; the worker thread always uses a blocking
    # acquire so the actual ordering can't race.
    will_queue = _sync_mutex.locked()
    queue_position = 0
    if will_queue:
        queue_position = _enqueue_sync(data_type, source=source)
        running_now = _sync_mutex_owner.get("data_type") or "another sync"
        _sync_progress[data_type] = {
            "type": data_type,
            "status": "queued",
            "queue_position": queue_position,
            "running_now": running_now,
            "running": True,  # keep frontend polling
        }
        sync_log.event("QUEUED", {
            "queue_position": queue_position,
            "running_now": running_now,
        })
    else:
        _sync_progress[data_type] = {"type": data_type, "status": "started", "running": True}

    def run_sync():
        try:
            # Block here until our turn. For the very first sync this
            # returns immediately; queued syncs wait politely.
            _sync_mutex.acquire()
            _sync_mutex_owner["data_type"] = data_type
            _sync_mutex_owner["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            _dequeue_sync(data_type)
            _sync_progress[data_type] = {
                "type": data_type, "status": "started", "running": True,
            }

            # Purge existing data before full sync so tenant switches start clean.
            # Backfill never purges — that's the whole point.
            if full and not backfill:
                try:
                    purge_data(data_type)
                    sync_log.event("DATA_PURGED", {"data_type": data_type})
                except Exception as e:
                    logger.error("Purge failed for %s: %s", data_type, e)
                    sync_log.finish_error(f"Purge failed: {e}")
                    _sync_progress[data_type] = {"type": data_type, "error": f"Purge failed: {e}"}
                    return

            engine = SyncEngine(client, credential_id=cred_id,
                               platform_id=data.get("platform", ""),
                               on_progress=on_progress, sync_log=sync_log)
            method = {"qids": engine.sync_qids, "cids": engine.sync_cids, "policies": engine.sync_policies, "mandates": engine.sync_mandates, "tags": engine.sync_tags, "pm_patches": engine.sync_pm_patches}[data_type]
            if data_type == "qids" and backfill:
                result = method(backfill=True)
            else:
                result = method(full=full)
            _sync_progress[data_type] = result
        except Exception as e:
            logger.exception("Sync %s failed", data_type)
            sync_log.finish_error(str(e))
            _sync_progress[data_type] = {"type": data_type, "error": str(e)}
        finally:
            _active_syncs.pop(data_type, None)
            # Always release the global sync mutex so the next queued
            # sync can proceed, even if the current one crashed mid-flight.
            _sync_mutex_owner["data_type"] = None
            _sync_mutex_owner["started_at"] = None
            # Defensive: if we were dequeued but never acquired (e.g.
            # exception before _sync_mutex.acquire()), the entry will
            # still be present. Clean up to avoid stuck queue entries.
            _dequeue_sync(data_type)
            try:
                _sync_mutex.release()
            except RuntimeError:
                logger.warning("Sync mutex was not held when releasing in run_sync")

    thread = threading.Thread(target=run_sync, daemon=True)
    _active_syncs[data_type] = thread
    thread.start()

    response = {"type": data_type, "full": full}
    if will_queue:
        running_now = _sync_mutex_owner.get("data_type") or "another sync"
        response.update({
            "queued": True,
            "queue_position": queue_position,
            "running_now": running_now,
            "message": f"Queued — will start automatically after {running_now} finishes "
                       f"(position {queue_position} in queue).",
        })
    else:
        response["started"] = True
    return jsonify(response), 200


class _SyncProgressResponse(BaseModel):
    """Live progress snapshot polled by the UI's progress bar.
    Fields populated depend on the sync phase (counting / syncing /
    enriching / processing / queued / complete / error)."""
    type: str | None = None
    running: bool = Field(default=False)
    status: str | None = Field(default=None, description="counting | syncing | enriching | processing | queued | started")
    items_synced: int | None = None
    page_items: int | None = None
    pages_fetched: int | None = None
    expected_total: int | None = None
    count_chunks_done: int | None = None
    count_chunks_total: int | None = None
    count_pages_done: int | None = None
    queue_position: int | None = None
    running_now: str | None = None
    error: str | None = None
    model_config = {"extra": "allow"}


@app.route("/api/sync/<data_type>/progress")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_SyncProgressResponse, HTTP_400=Error),
    tags=[TAG_SYNC],
)
def sync_progress(data_type):
    """Live progress of the most recent sync for this data type.
    Polled by the UI every ~2 s while a sync runs."""
    if data_type not in ("qids", "cids", "policies", "mandates", "tags", "pm_patches"):
        return jsonify({"error": "Invalid data type"}), 400
    thread = _active_syncs.get(data_type)
    running = thread is not None and thread.is_alive()
    progress = _sync_progress.get(data_type, {})
    progress["running"] = running
    return jsonify(progress)


@app.route("/api/sync/<data_type>/log")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=OkMessage, HTTP_400=Error, HTTP_404=Error),
    tags=[TAG_SYNC],
)
def sync_log_endpoint(data_type):
    """Full diagnostic sync log for a data type. Default is rendered
    text (`{"text": "..."}` for copy/paste); pass `?format=json` for
    structured events."""
    if data_type not in ("qids", "cids", "policies", "mandates", "tags", "pm_patches"):
        return jsonify({"error": "Invalid data type"}), 400
    log = get_sync_log(data_type)
    if not log:
        return jsonify({"error": "No sync log available. Run a sync first."}), 404
    fmt = request.args.get("format", "text")
    if fmt == "json":
        return jsonify(log.to_dict())
    return jsonify({"text": log.render_text()})


class _SyncHistoryResponse(RootModel[list[dict]]):
    """List of past sync runs (newest first), max 20."""


@app.route("/api/sync/<data_type>/history")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_SyncHistoryResponse, HTTP_400=Error),
    tags=[TAG_SYNC],
)
def sync_history_endpoint(data_type):
    """Last 20 sync runs for this data type (newest first)."""
    if data_type not in ("qids", "cids", "policies", "mandates", "tags", "pm_patches"):
        return jsonify({"error": "Invalid data type"}), 400
    history = get_sync_history(data_type, limit=20)
    return jsonify(history)


class _SyncEventsTailQuery(BaseModel):
    since_id: int = Field(default=0, ge=0, description="Only return events with id greater than this")
    limit: int = Field(default=25, ge=1, le=100, description="Max events to return per call")


class _SyncEvent(BaseModel):
    id: int
    ts: str
    event_type: str
    detail: dict = Field(default_factory=dict)


class _SyncEventsTailResponse(BaseModel):
    run_id: int | None = Field(default=None, description="None when no sync runs exist for this data type")
    run_status: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    events: list[_SyncEvent] = Field(default_factory=list, description="Newest-first")


@app.route("/api/sync/<data_type>/events/tail")
@openapi.validate(
    query=_SyncEventsTailQuery,
    resp=OpenApiResponse(HTTP_200=_SyncEventsTailResponse, HTTP_400=Error),
    tags=[TAG_SYNC],
)
def sync_events_tail(data_type):
    """Tail the most recent sync run's event log.

    Powers the "peek under the hood" modal — a rolling list of the
    last N sync_log_events the user can open while a sync is in
    flight to confirm activity. Polled-while-open: the frontend
    sends ``since_id`` so we only return events newer than what
    it has already shown, keeping the response tiny.

    Returns events newest-first so the modal can prepend them
    directly. Caller is expected to cap its visible list (we
    cap the response at ``limit`` per call regardless).
    """
    if data_type not in ("qids", "cids", "policies", "mandates", "tags", "pm_patches"):
        return jsonify({"error": "Invalid data type"}), 400
    try:
        since_id = int(request.args.get("since_id", 0) or 0)
    except (TypeError, ValueError):
        since_id = 0
    try:
        limit = int(request.args.get("limit", 25) or 25)
    except (TypeError, ValueError):
        limit = 25
    limit = max(1, min(limit, 100))  # bound it; modal shows ~10

    from app.database import get_db as _get_db
    with _get_db() as conn:
        run = conn.execute(
            "SELECT id, status, started_at, finished_at FROM sync_log_runs "
            "WHERE data_type=? ORDER BY id DESC LIMIT 1",
            (data_type,),
        ).fetchone()
        if not run:
            return jsonify({
                "run_id": None, "run_status": None,
                "events": [],
            })
        rows = conn.execute(
            "SELECT id, ts, event_type, detail_json FROM sync_log_events "
            "WHERE run_id=? AND id>? ORDER BY id DESC LIMIT ?",
            (run["id"], since_id, limit),
        ).fetchall()

    events = []
    for r in rows:
        try:
            detail = json.loads(r["detail_json"]) if r["detail_json"] else {}
        except (TypeError, ValueError):
            detail = {}
        events.append({
            "id": r["id"],
            "ts": r["ts"],
            "event_type": r["event_type"],
            "detail": detail,
        })
    return jsonify({
        "run_id": run["id"],
        "run_status": run["status"],
        "started_at": run["started_at"],
        "finished_at": run["finished_at"],
        "events": events,
    })


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Schedules
# ═══════════════════════════════════════════════════════════════════════════

class _SchedulesListResponse(RootModel[list[dict]]):
    """One entry per active schedule — `{data_type, frequency,
    next_run_at, credential_id, platform, ...}`."""


class _ScheduleCreateRequest(BaseModel):
    credential_id: str = Field(..., description="Vault credential to use for the recurring sync")
    platform: str = Field(..., description="Qualys platform region the credential targets")
    frequency: str = Field(..., description='One of "daily", "2x_week", "1x_week", "2x_month", "1x_month"')
    start_date: str = Field(..., description="ISO date the schedule kicks off (YYYY-MM-DD)")
    start_time: str = Field(..., description="24h time-of-day (HH:MM) in the supplied timezone")
    timezone: str = Field(..., description="IANA timezone (e.g. America/Los_Angeles)")


@app.route("/api/schedules")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_SchedulesListResponse, HTTP_500=Error),
    tags=[TAG_SCHED],
)
def list_schedules():
    """All active recurring sync schedules — one entry per data type
    that has a recurring delta sync configured."""
    try:
        return jsonify(get_schedule_info())
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/schedules/<data_type>", methods=["POST"])
@openapi.validate(
    json=_ScheduleCreateRequest,
    resp=OpenApiResponse(HTTP_200=OkMessage, HTTP_400=Error, HTTP_500=Error),
    tags=[TAG_SCHED],
)
def create_schedule(data_type):
    """Create or update a recurring delta-sync schedule for this data
    type. Replaces any existing schedule for the same type."""
    if data_type not in ("qids", "cids", "policies", "mandates", "tags", "pm_patches"):
        return jsonify({"error": "Invalid data type"}), 400
    data = request.json or {}
    required = ("credential_id", "platform", "frequency", "start_date", "start_time", "timezone")
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
    try:
        result = add_schedule(
            data_type,
            credential_id=data["credential_id"],
            platform=data["platform"],
            frequency=data["frequency"],
            start_date=data["start_date"],
            start_time=data["start_time"],
            timezone=data["timezone"],
        )
        return jsonify({"ok": True, "schedule": result})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/schedules/<data_type>", methods=["DELETE"])
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=OkMessage, HTTP_400=Error),
    tags=[TAG_SCHED],
)
def delete_schedule_route(data_type):
    """Cancel a recurring sync schedule for this data type."""
    if data_type not in ("qids", "cids", "policies", "mandates", "tags", "pm_patches"):
        return jsonify({"error": "Invalid data type"}), 400
    removed = remove_schedule(data_type)
    return jsonify({"ok": True, "removed": removed})


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Database Maintenance
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/maintenance/config")
def maintenance_config_get():
    """Return maintenance schedule config, last run info, and backup info."""
    from app.database import get_maintenance_config
    from app.maintenance import get_backup_info
    from app.scheduler import get_maintenance_schedule_info
    config = get_maintenance_config()
    config["backup"] = get_backup_info()
    sched_info = get_maintenance_schedule_info(config.get("timezone", ""))
    config["next_run"] = sched_info
    return jsonify(config)


@app.route("/api/maintenance/config", methods=["POST"])
def maintenance_config_save():
    """Update maintenance schedule (day, time, timezone)."""
    from app.database import save_maintenance_config
    from app.scheduler import schedule_maintenance
    data = request.json or {}
    day = int(data.get("day_of_week", 0))
    hour = int(data.get("hour", 0))
    minute = int(data.get("minute", 0))
    tz = data.get("timezone", "")
    if day < 0 or day > 6:
        return jsonify({"error": "day_of_week must be 0-6 (Sunday-Saturday)"}), 400
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return jsonify({"error": "Invalid hour or minute"}), 400
    config = save_maintenance_config(day, hour, minute, tz)
    sched_info = schedule_maintenance(day, hour, minute, tz)
    config["next_run"] = sched_info
    return jsonify(config)


@app.route("/api/maintenance/restore", methods=["POST"])
def maintenance_restore():
    """Restore database from compressed backup."""
    from app.maintenance import restore_from_backup
    result = restore_from_backup()
    if result["status"] == "ok":
        return jsonify(result)
    return jsonify(result), 500


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Application Update
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/update/check")
def update_check():
    """Check GitHub for application updates."""
    from app.updater import check_for_updates
    return jsonify(check_for_updates())


@app.route("/api/update/apply", methods=["POST"])
def update_apply():
    """Download and apply the latest version from GitHub."""
    from app.updater import apply_update
    result = apply_update()
    if result["status"] == "ok":
        return jsonify(result)
    return jsonify(result), 500


@app.route("/api/update/version")
def update_version():
    """Return current deployed version."""
    from app.updater import get_current_version
    return jsonify({"version": get_current_version()})


@app.route("/api/update/schedule", methods=["GET"])
def update_schedule_get():
    """Return the auto-update schedule config + next-run info."""
    from app.database import get_auto_update_config
    from app.scheduler import get_auto_update_schedule_info
    cfg = get_auto_update_config()
    tz = cfg.get("timezone") or "UTC"
    info = get_auto_update_schedule_info(tz) or {}
    return jsonify({
        "enabled": bool(cfg.get("enabled")),
        "day_of_week": cfg.get("day_of_week"),
        "hour": cfg.get("hour"),
        "minute": cfg.get("minute"),
        "timezone": tz,
        "last_check": cfg.get("last_check"),
        "last_status": cfg.get("last_status"),
        "last_error": cfg.get("last_error"),
        "last_version": cfg.get("last_version"),
        "next_run_local": info.get("next_run_local"),
        "next_run_utc": info.get("next_run_utc"),
    })


@app.route("/api/update/schedule", methods=["POST"])
def update_schedule_post():
    """Save the auto-update schedule and (re)schedule the APScheduler job."""
    from app.database import get_auto_update_config, save_auto_update_config
    from app.scheduler import (
        schedule_auto_update,
        remove_auto_update_schedule,
        get_auto_update_schedule_info,
    )
    data = request.json or {}
    enabled = bool(data.get("enabled"))
    try:
        day = int(data.get("day_of_week", 6))
        hour = int(data.get("hour", 0))
        minute = int(data.get("minute", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "day_of_week, hour and minute must be integers"}), 400
    if not (0 <= day <= 6 and 0 <= hour <= 23 and 0 <= minute <= 59):
        return jsonify({"error": "day_of_week 0-6, hour 0-23, minute 0-59"}), 400
    tz = (data.get("timezone") or "UTC").strip() or "UTC"

    save_auto_update_config(enabled, day, hour, minute, tz)
    if enabled:
        schedule_auto_update(day, hour, minute, tz)
    else:
        remove_auto_update_schedule()

    cfg = get_auto_update_config()
    info = get_auto_update_schedule_info(tz) or {}
    return jsonify({
        "enabled": bool(cfg.get("enabled")),
        "day_of_week": cfg.get("day_of_week"),
        "hour": cfg.get("hour"),
        "minute": cfg.get("minute"),
        "timezone": cfg.get("timezone") or "UTC",
        "last_check": cfg.get("last_check"),
        "last_status": cfg.get("last_status"),
        "last_error": cfg.get("last_error"),
        "last_version": cfg.get("last_version"),
        "next_run_local": info.get("next_run_local"),
        "next_run_utc": info.get("next_run_utc"),
    })


# ═══════════════════════════════════════════════════════════════════════════
# Routes — QIDs (Knowledge Base)
# ═══════════════════════════════════════════════════════════════════════════

# ── OpenAPI models for QID search ─────────────────────────────────────
# Lightweight Pydantic models that document the public contract of
# /api/qids without forcing every column from the vulns row to be
# enumerated. `model_config = {"extra": "allow"}` on the row model
# lets undocumented fields ride along during incremental rollout —
# we get a Swagger entry for the surface today and can tighten the
# schema when we revisit each endpoint.

class _QidSearchQuery(BaseModel):
    """Query string parameters accepted by `GET /api/qids`."""

    q: str | None = Field(default=None, description="FTS search term over title/diagnosis/consequence/solution")
    cve: str | None = Field(default=None, description="Comma-separated CVE list (e.g. CVE-2021-44228,CVE-2014-0160)")
    cve_mode: str = Field(default="or", description='Match ALL CVEs ("and") or ANY ("or")')
    severity: int | None = Field(default=None, ge=1, le=5, description="Single severity level (1-5)")
    severities: str | None = Field(default=None, description="Comma-separated severities for multi-select (e.g. 4,5)")
    category: str | None = Field(default=None, description="Comma-separated category list")
    patchable: str | None = Field(default=None, description='"1" = patchable only, "0" = not-patchable only')
    pci_flag: str | None = Field(default=None, description='"1" = PCI-relevant only, "0" = not-PCI only')
    rti: str | None = Field(default=None, description="Comma-separated real-time-intel indicators")
    supported_modules: str | None = Field(default=None, description="Comma-separated supported module list")
    vuln_types: str | None = Field(default=None, description="Comma-separated vuln type list")
    pm_any: str | None = Field(default=None, description='"1" = only QIDs with at least one PM patch (any platform)')
    pm_win: str | None = Field(default=None, description='"1" = only QIDs with a Windows PM patch')
    pm_lin: str | None = Field(default=None, description='"1" = only QIDs with a Linux PM patch')
    threat_active: str | None = Field(default=None, description='"1" = only QIDs with active attacks')
    threat_cisa_kev: str | None = Field(default=None, description='"1" = only QIDs on CISA KEV list')
    threat_exploit_public: str | None = Field(default=None, description='"1" = only QIDs with public exploits')
    threat_rce: str | None = Field(default=None, description='"1" = only QIDs with RCE capability')
    threat_malware: str | None = Field(default=None, description='"1" = only QIDs with associated malware')
    has_exploits: str | None = Field(default=None, description='"1" = only QIDs with documented exploit references')
    disabled: str | None = Field(default=None, description='"1" = only disabled, "0" = only enabled, absent = both')
    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    per_page: int = Field(default=50, ge=1, le=500, description="Items per page (max 500)")


class _QidRow(BaseModel):
    """One QID row in the search results."""

    qid: int = Field(..., description="Qualys ID")
    title: str | None = None
    severity_level: int | None = Field(default=None, ge=1, le=5)
    category: str | None = None
    vuln_type: str | None = None
    patchable: int | None = Field(default=None, description="0 / 1 flag")
    pci_flag: int | None = Field(default=None, description="0 / 1 flag")
    disabled: int | None = Field(default=None, description="0 / 1 flag")
    cvss_base: float | None = None
    cvss3_base: float | None = None
    published_datetime: str | None = None
    last_service_modification_datetime: str | None = None

    model_config = {"extra": "allow"}


class _QidSearchResponse(Pagination[_QidRow]):
    """Paginated QID search result (`results` is a list of `_QidRow`)."""


@app.route("/api/qids")
@openapi.validate(
    query=_QidSearchQuery,
    resp=OpenApiResponse(HTTP_200=_QidSearchResponse, HTTP_500=Error),
    tags=[TAG_QIDS],
)
def qids_search():
    """Search QIDs with FTS, filters, and pagination.

    Combines full-text search across title/diagnosis/consequence/
    solution with structured filters (severity, category, CVSS,
    discovery method, RTI tags, PM patch availability, disabled
    state, etc.). Returns a `Pagination` envelope.
    """
    try:
        filters = _parse_qid_filters()
        result = search_vulns(
            **filters,
            page=int(request.args.get("page", 1)),
            per_page=int(request.args.get("per_page", 50)),
        )
        return jsonify(result)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


class _FilterValuesQuery(BaseModel):
    """Shared query shape for /api/<type>/filter-values endpoints."""
    field: str = Field(..., description="Column to enumerate distinct values from (e.g. 'categories', 'rule_types')")
    q: str | None = Field(default=None, description="Optional substring filter on the values")


# Pydantic v2 RootModel — wraps a bare JSON array so Swagger shows
# the actual shape (a list of strings) rather than an envelope object.
class _FilterValuesResponse(RootModel[list[str]]):
    """Bare list of strings — no envelope. Documented as such so the
    Swagger 'Try it out' shows the actual shape clients will see."""


@app.route("/api/qids/filter-values")
@openapi.validate(
    query=_FilterValuesQuery,
    resp=OpenApiResponse(HTTP_200=_FilterValuesResponse, HTTP_500=Error),
    tags=[TAG_QIDS],
)
def qid_filter_values():
    """Distinct values for QID multi-select dropdowns (categories,
    supported_modules, etc.)."""
    try:
        field = request.args.get("field", "")
        q = request.args.get("q", "")
        return jsonify(get_qid_filter_values(field, q))
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


class _QidDetail(BaseModel):
    """Full QID record with child collections (CVEs, bugtraqs, vendor
    refs, RTI tags, supported modules, threat-intel JSON). Extras
    pass through so we don't have to enumerate every Qualys field."""

    qid: int
    title: str | None = None
    severity_level: int | None = None
    category: str | None = None
    vuln_type: str | None = None
    patchable: int | None = None
    pci_flag: int | None = None
    disabled: int | None = None
    cvss_base: float | None = None
    cvss3_base: float | None = None
    published_datetime: str | None = None
    last_service_modification_datetime: str | None = None
    diagnosis: str | None = None
    consequence: str | None = None
    solution: str | None = None
    cves: list[dict] | None = None
    bugtraqs: list[dict] | None = None
    vendor_refs: list[dict] | None = None
    supported_modules: list[str] | None = None

    model_config = {"extra": "allow"}


@app.route("/api/qids/<int:qid>")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_QidDetail, HTTP_404=Error, HTTP_500=Error),
    tags=[TAG_QIDS],
)
def qids_detail(qid):
    """Full QID detail — parent vulns row plus joined CVEs, bugtraqs,
    vendor refs, RTI tags, and supported modules."""
    try:
        vuln = get_vuln(qid)
        if not vuln:
            return jsonify({"error": "QID not found"}), 404
        return jsonify(vuln)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/qids/export-details")
def qids_export_details():
    """Bulk export full QID details (CVEs, diagnosis, solution, etc.)."""
    try:
        ids_param = request.args.get("ids", "")
        ids = [s.strip() for s in ids_param.split(",") if s.strip()]
        fmt = request.args.get("format", "csv")
        if not ids:
            return jsonify({"error": "No QIDs provided"}), 400
        try:
            ids = [int(i) for i in ids]
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid QID ID"}), 400

        text_limit = 0  # Full text for CSV
        headers = ["QID", "Title", "Severity", "Category", "Type", "Patchable",
                    "CVSS v2", "CVSS v3", "Published", "Modified", "CVEs",
                    "Bugtraqs", "Supported Modules", "Diagnosis", "Solution"]
        rows = []
        for qid in ids:
            v = get_vuln(qid)
            if not v:
                continue
            cves = ", ".join(c.get("cve_id", "") for c in (v.get("cves") or []))
            bugtraqs = ", ".join(str(b.get("bugtraq_id", "")) for b in (v.get("bugtraqs") or []))
            mods = ", ".join(v.get("supported_modules") or [])
            diag = _strip_html(v.get("diagnosis") or "")
            soln = _strip_html(v.get("solution") or "")
            if text_limit:
                diag = diag[:text_limit] + ("..." if len(diag) > text_limit else "")
                soln = soln[:text_limit] + ("..." if len(soln) > text_limit else "")
            rows.append([
                v.get("qid"), v.get("title"), v.get("severity_level"),
                v.get("category"), v.get("vuln_type"),
                "Yes" if v.get("patchable") else "No",
                v.get("cvss_base"), v.get("cvss3_base"),
                v.get("published_datetime", ""), v.get("last_service_modification_datetime", ""),
                cves, bugtraqs, mods, diag, soln,
            ])

        return _csv_response(rows, headers, "qkbe-qid-details.csv")
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Routes — CIDs (Compliance Controls)
# ═══════════════════════════════════════════════════════════════════════════

class _CidSearchQuery(BaseModel):
    q: str | None = Field(default=None, description="FTS search across statement / category / sub_category / comment")
    category: str | None = Field(default=None, description="Comma-separated category list")
    criticality: str | None = Field(default=None, description="Criticality label (URGENT/CRITICAL/SERIOUS/MEDIUM/MINIMAL)")
    technology: str | None = Field(default=None, description="Comma-separated technology list (joined via control_technologies)")
    technology_mode: str = Field(default="or", description='"or" matches ANY, "and" matches ALL technologies')
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=50, ge=1, le=500)


class _CidRow(BaseModel):
    cid: int
    statement: str | None = None
    category: str | None = None
    sub_category: str | None = None
    criticality_label: str | None = None
    criticality_value: int | None = None
    check_type: str | None = None
    use_agent_only: int | None = None
    auto_update: int | None = None

    model_config = {"extra": "allow"}


class _CidSearchResponse(Pagination[_CidRow]):
    """Paginated CID search result."""


@app.route("/api/cids")
@openapi.validate(
    query=_CidSearchQuery,
    resp=OpenApiResponse(HTTP_200=_CidSearchResponse, HTTP_500=Error),
    tags=[TAG_CIDS],
)
def cids_search():
    """Search compliance controls with FTS, filters, and pagination."""
    try:
        cat_param = request.args.get("category", "")
        categories = [c.strip() for c in cat_param.split(",") if c.strip()] if cat_param else None
        tech_param = request.args.get("technology", "")
        technologies = [t.strip() for t in tech_param.split(",") if t.strip()] if tech_param else None
        technology_mode = request.args.get("technology_mode", "or")
        result = search_controls(
            q=request.args.get("q", ""),
            categories=categories,
            criticality=request.args.get("criticality", "") or None,
            technologies=technologies,
            technology_mode=technology_mode,
            page=int(request.args.get("page", 1)),
            per_page=int(request.args.get("per_page", 50)),
        )
        return jsonify(result)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/cids/filter-values")
@openapi.validate(
    query=_FilterValuesQuery,
    resp=OpenApiResponse(HTTP_200=_FilterValuesResponse, HTTP_500=Error),
    tags=[TAG_CIDS],
)
def cid_filter_values():
    """Distinct values for CID multi-select dropdowns (categories,
    technologies)."""
    try:
        field = request.args.get("field", "")
        q = request.args.get("q", "")
        return jsonify(get_cid_filter_values(field, q))
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


class _CidDetail(_CidRow):
    """Full CID detail — adds joined technologies + linked mandates."""
    technologies: list[dict] | None = None
    mandates: list[dict] | None = None

    model_config = {"extra": "allow"}


@app.route("/api/cids/<int:cid>")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_CidDetail, HTTP_404=Error, HTTP_500=Error),
    tags=[TAG_CIDS],
)
def cids_detail(cid):
    """Full control detail — parent controls row plus joined technologies
    and mandate / framework links."""
    try:
        control = get_control(cid)
        if not control:
            return jsonify({"error": "CID not found"}), 404
        return jsonify(control)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/cids/export-details")
def cids_export_details():
    """Bulk export full CID details (technologies, linked policies, etc.)."""
    try:
        ids_param = request.args.get("ids", "")
        ids = [s.strip() for s in ids_param.split(",") if s.strip()]
        fmt = request.args.get("format", "csv")
        if not ids:
            return jsonify({"error": "No CIDs provided"}), 400
        try:
            ids = [int(i) for i in ids]
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid CID ID"}), 400

        text_limit = 0
        headers = ["CID", "Category", "Sub-Category", "Criticality", "Check Type",
                    "Statement", "Technologies", "Linked Policies", "Created", "Updated"]
        rows = []
        for cid in ids:
            c = get_control(cid)
            if not c:
                continue
            techs = ", ".join(t.get("tech_name", "") for t in (c.get("technologies") or []))
            policies_str = ", ".join(str(p.get("policy_id", "")) for p in (c.get("linked_policies") or []))
            stmt = (c.get("statement") or "")
            if text_limit:
                stmt = stmt[:text_limit] + ("..." if len(stmt) > text_limit else "")
            rows.append([
                c.get("cid"), c.get("category"), c.get("sub_category"),
                c.get("criticality_label"), c.get("check_type"),
                stmt, techs, policies_str,
                c.get("created_date", ""), c.get("update_date", ""),
            ])

        return _csv_response(rows, headers, "qkbe-cid-details.csv")
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# Routes — Policies
# ═══════════════════════════════════════════════════════════════════════════

class _PolicySearchQuery(BaseModel):
    q: str | None = Field(default=None, description="FTS search across policy title and control statements")
    status: str | None = Field(default=None, description="Policy status filter (e.g. ACTIVE, DRAFT)")
    control_category: str | None = Field(default=None, description="Comma-separated control categories")
    control_category_mode: str = Field(default="or", description='"or" matches ANY, "and" matches ALL categories')
    technology: str | None = Field(default=None, description="Comma-separated technology names")
    technology_mode: str = Field(default="or")
    cid: str | None = Field(default=None, description="Comma-separated CID list (numeric)")
    cid_mode: str = Field(default="or")
    control_name: str | None = Field(default=None, description="Substring search on linked-control statement")
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=50, ge=1, le=500)


class _PolicyRow(BaseModel):
    policy_id: int
    title: str | None = None
    status: str | None = None
    is_locked: int | None = None
    created_datetime: str | None = None
    last_modified_datetime: str | None = None
    last_evaluated_datetime: str | None = None

    model_config = {"extra": "allow"}


class _PolicySearchResponse(Pagination[_PolicyRow]):
    """Paginated policy search result."""


class _PolicyDetail(_PolicyRow):
    """Full policy detail — adds linked controls list."""
    controls: list[dict] | None = None
    model_config = {"extra": "allow"}


class _PolicyDeleteRequest(BaseModel):
    policy_ids: list[int] = Field(..., description="Policy ids to delete locally")


@app.route("/api/policies")
@openapi.validate(
    query=_PolicySearchQuery,
    resp=OpenApiResponse(HTTP_200=_PolicySearchResponse, HTTP_500=Error),
    tags=[TAG_POLICIES],
)
def policies_search():
    """Search policies with filters and pagination."""
    try:
        cc_param = request.args.get("control_category", "")
        control_categories = [c.strip() for c in cc_param.split(",") if c.strip()] if cc_param else None
        tech_param = request.args.get("technology", "")
        technologies = [t.strip() for t in tech_param.split(",") if t.strip()] if tech_param else None
        cid_param = request.args.get("cid", "")
        cids = [int(c.strip().split(" ")[0]) for c in cid_param.split(",") if c.strip()] if cid_param else None
        control_category_mode = request.args.get("control_category_mode", "or")
        technology_mode = request.args.get("technology_mode", "or")
        cid_mode = request.args.get("cid_mode", "or")
        result = search_policies(
            q=request.args.get("q", ""),
            status=request.args.get("status", ""),
            control_categories=control_categories,
            control_category_mode=control_category_mode,
            technologies=technologies,
            technology_mode=technology_mode,
            cids=cids,
            cid_mode=cid_mode,
            control_name=request.args.get("control_name", ""),
            page=int(request.args.get("page", 1)),
            per_page=int(request.args.get("per_page", 50)),
        )
        return jsonify(result)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/policies", methods=["DELETE"])
@openapi.validate(
    json=_PolicyDeleteRequest,
    resp=OpenApiResponse(HTTP_200=OkMessage, HTTP_400=Error),
    tags=[TAG_POLICIES],
)
def delete_policies_route():
    """Delete one or more policies from the local DB. Qualys is not
    affected — this only purges the cached copy."""
    data = request.json or {}
    ids = data.get("policy_ids", [])
    if not ids:
        return jsonify({"error": "No policy IDs provided"}), 400
    try:
        ids = [int(i) for i in ids]
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid policy ID"}), 400
    count = delete_policies(ids)
    return jsonify({"ok": True, "deleted": count})


@app.route("/api/policies/filter-values")
@openapi.validate(
    query=_FilterValuesQuery,
    resp=OpenApiResponse(HTTP_200=_FilterValuesResponse, HTTP_500=Error),
    tags=[TAG_POLICIES],
)
def policy_filter_values():
    """Distinct values for Policy multi-select dropdowns
    (control_categories, technologies)."""
    try:
        field = request.args.get("field", "")
        q = request.args.get("q", "")
        return jsonify(get_policy_filter_values(field, q))
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/policies/<int:policy_id>")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_PolicyDetail, HTTP_404=Error, HTTP_500=Error),
    tags=[TAG_POLICIES],
)
def policies_detail(policy_id):
    """Full policy detail — parent policies row plus linked controls."""
    try:
        policy = get_policy(policy_id)
        if not policy:
            return jsonify({"error": "Policy not found"}), 404
        return jsonify(policy)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Policy Export / Import (Migration)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/policies/<int:policy_id>/export", methods=["POST"])
def policy_export(policy_id):
    """Export a policy from Qualys and store XML in local DB."""
    data = request.json or {}
    client, error, cred_id = _build_client(data)
    if error:
        logger.warning("Policy export %d: credential error — %s", policy_id, error)
        return jsonify({"error": error}), 400

    logger.info("Policy export %d: starting export from %s", policy_id, client.api_base)
    try:
        result = client.execute(
            "/api/4.0/fo/compliance/policy/",
            params={
                "action": "export",
                "id": str(policy_id),
                "show_user_controls": "1",
                "show_appendix": "1",
            },
            timeout=120,
            keep_raw=True,  # Need full XML for policy export storage
        )
        if result.get("error"):
            logger.error("Policy export %d: API error — %s", policy_id, result.get("message"))
            return jsonify({"error": result.get("message", "Export failed")}), 502

        raw_xml = result.get("raw_text", "")
        if not raw_xml:
            logger.error("Policy export %d: empty response from API", policy_id)
            return jsonify({"error": "Empty export response"}), 502

        store_policy_export(policy_id, raw_xml.encode("utf-8"), includes_udcs=True)
        xml_size = len(raw_xml)
        logger.info("Policy export %d: success — %s bytes stored", policy_id, f"{xml_size:,}")
        return jsonify({"exported": True, "policy_id": policy_id, "xml_size": xml_size})
    except Exception as e:
        logger.exception("Policy export %d failed", policy_id)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/policies/<int:policy_id>/download-xml")
def policy_download_xml(policy_id):
    """Download stored policy XML as a file."""
    xml_data = get_policy_export_xml(policy_id)
    if not xml_data:
        return jsonify({"error": "No exported XML for this policy"}), 404

    # Build a safe filename from the policy title
    from app.database import get_policy
    policy = get_policy(policy_id)
    title = policy.get("title", f"policy_{policy_id}") if policy else f"policy_{policy_id}"
    # Sanitize filename: keep alphanumeric, spaces, hyphens, underscores
    import re
    safe_name = re.sub(r'[^\w\s\-]', '', title).strip()
    safe_name = re.sub(r'\s+', '_', safe_name)
    if not safe_name:
        safe_name = f"policy_{policy_id}"
    filename = f"{safe_name}.xml"

    resp = make_response(xml_data)
    resp.headers["Content-Type"] = "application/xml"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


@app.route("/api/policies/<int:policy_id>/report")
def policy_report(policy_id):
    """Return structured section→control report data parsed from stored XML."""
    try:
        data = get_policy_report_data(policy_id)
        if not data:
            return jsonify({"error": "No exported XML for this policy. Export it first."}), 404
        return jsonify(data)
    except Exception as e:
        logger.exception("Policy report %d failed", policy_id)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/policies/<int:policy_id>/report-pdf")
def policy_report_pdf(policy_id):
    """Generate a formatted PDF report of the policy with sections and controls."""
    data = get_policy_report_data(policy_id)
    if not data:
        return jsonify({"error": "No exported XML for this policy. Export it first."}), 404

    try:
        return _policy_report_pdf(data)
    except Exception as e:
        logger.exception("Policy report PDF %d failed", policy_id)
        return jsonify({"error": "Internal server error"}), 500


def _policy_report_pdf(report_data):
    """Build a formatted policy report PDF using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
        KeepTogether,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from datetime import datetime

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=landscape(letter),
        leftMargin=0.5 * inch, rightMargin=0.5 * inch,
        topMargin=0.5 * inch, bottomMargin=0.5 * inch,
    )
    styles = getSampleStyleSheet()
    elements = []

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"],
        fontSize=18, alignment=TA_CENTER, spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"],
        fontSize=10, alignment=TA_CENTER, textColor=colors.HexColor("#666666"),
        spaceAfter=12,
    )
    section_style = ParagraphStyle(
        "SectionHeading", parent=styles["Heading2"],
        fontSize=11, textColor=colors.white, spaceBefore=14, spaceAfter=6,
        fontName="Helvetica-Bold",
    )
    cell_style = ParagraphStyle(
        "CellText", parent=styles["Normal"],
        fontSize=7, leading=9, wordWrap="CJK",
    )
    cell_bold = ParagraphStyle(
        "CellBold", parent=cell_style,
        fontName="Helvetica-Bold",
    )

    # ── Title ──
    elements.append(Paragraph(report_data["title"] or "Untitled Policy", title_style))
    elements.append(Paragraph(
        f"Policy ID: {report_data['policy_id']} &bull; "
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        subtitle_style,
    ))

    # ── Meta summary ──
    meta_items = []
    if report_data.get("status"):
        meta_items.append(("Status", report_data["status"]))
    if report_data.get("created_datetime"):
        meta_items.append(("Created", report_data["created_datetime"][:10]))
    if report_data.get("last_modified_datetime"):
        meta_items.append(("Modified", report_data["last_modified_datetime"][:10]))
    if report_data.get("last_evaluated_datetime"):
        meta_items.append(("Evaluated", report_data["last_evaluated_datetime"][:10]))
    meta_items.append(("Sections", str(report_data["total_sections"])))
    meta_items.append(("Controls", str(report_data["total_controls"])))

    if meta_items:
        meta_data = [[Paragraph(f"<b>{k}:</b> {v}", cell_style) for k, v in meta_items]]
        meta_table = Table(meta_data)
        meta_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ]))
        elements.append(meta_table)

    # ── Technologies ──
    if report_data.get("technologies"):
        tech_names = ", ".join(t["name"] for t in report_data["technologies"])
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(f"<b>Technologies:</b> {tech_names}", cell_style))
    elements.append(Spacer(1, 10))

    # ── Sections with controls ──
    avail_width = landscape(letter)[0] - 1 * inch
    col_widths = [0.8 * inch, 0.5 * inch, 0.7 * inch, avail_width - 4.5 * inch, 2.5 * inch]

    for section in report_data.get("sections", []):
        # Section heading bar
        heading_text = f"Section {section['number']}: {section['heading']}"
        heading_table = Table(
            [[Paragraph(heading_text, section_style)]],
            colWidths=[avail_width],
        )
        heading_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#2a2f3e")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(heading_table)

        if not section.get("controls"):
            elements.append(Paragraph(
                "<i>No controls in this section.</i>",
                ParagraphStyle("Empty", parent=cell_style, textColor=colors.gray),
            ))
            elements.append(Spacer(1, 8))
            continue

        # Controls table
        header_row = [
            Paragraph("<b>Reference</b>", cell_bold),
            Paragraph("<b>CID</b>", cell_bold),
            Paragraph("<b>Criticality</b>", cell_bold),
            Paragraph("<b>Statement</b>", cell_bold),
            Paragraph("<b>Technologies</b>", cell_bold),
        ]

        data_rows = []
        for c in section["controls"]:
            tech_text = ", ".join(t["name"] for t in c.get("technologies", []))
            data_rows.append([
                Paragraph(c.get("reference", ""), cell_style),
                Paragraph(str(c.get("cid", "")), cell_style),
                Paragraph(c.get("criticality_label", ""), cell_style),
                Paragraph(c.get("statement", ""), cell_style),
                Paragraph(tech_text, cell_style),
            ])

        table_data = [header_row] + data_rows
        t = Table(table_data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3a4050")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, 0), 7),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d4dc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f4f5f7")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 8))

    doc.build(elements)
    buf.seek(0)

    # Sanitize filename
    import re as _re
    safe_title = _re.sub(r'[^\w\s\-]', '', report_data.get("title", "policy")).strip()
    safe_title = _re.sub(r'\s+', '_', safe_title) or "policy"
    filename = f"{safe_title}_report.pdf"

    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


@app.route("/api/policies/export-zip", methods=["POST"])
def policy_export_zip():
    """Bundle stored policy XMLs into a single ZIP download."""
    import re as _re
    import zipfile
    from app.database import get_policy

    data = request.json or {}
    policy_ids = data.get("policy_ids", [])
    if not policy_ids:
        return jsonify({"error": "No policy IDs provided"}), 400

    try:
        policy_ids = [int(pid) for pid in policy_ids]
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid policy ID"}), 400

    buf = io.BytesIO()
    included = 0
    skipped = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for pid in policy_ids:
            xml_data = get_policy_export_xml(pid)
            if not xml_data:
                skipped.append(pid)
                continue
            policy = get_policy(pid)
            title = policy.get("title", f"policy_{pid}") if policy else f"policy_{pid}"
            safe_name = _re.sub(r'[^\w\s\-]', '', title).strip()
            safe_name = _re.sub(r'\s+', '_', safe_name)
            if not safe_name:
                safe_name = f"policy_{pid}"
            zf.writestr(f"{safe_name}.xml", xml_data)
            included += 1

    if included == 0:
        return jsonify({"error": "No policies had stored XML to export"}), 404

    buf.seek(0)
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"policy_export_{included}_policies_{timestamp}.zip"

    resp = make_response(buf.read())
    resp.headers["Content-Type"] = "application/zip"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    if skipped:
        resp.headers["X-Skipped-Policies"] = ",".join(str(s) for s in skipped)
    logger.info("Policy ZIP export: %d policies bundled, %d skipped (no XML)", included, len(skipped))
    return resp


@app.route("/api/policies/import-xml", methods=["POST"])
def policy_import_xml():
    """Import a policy XML file from local upload and store in DB."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    xml_data = f.read()
    if not xml_data:
        return jsonify({"error": "Empty file"}), 400

    # Try to extract policy ID and title from the XML
    import re as _re
    xml_text = xml_data.decode("utf-8", errors="replace")
    # Look for <ID>123</ID> or <POLICY_ID>123</POLICY_ID>
    id_match = _re.search(r'<(?:POLICY_ID|ID)>\s*(\d+)\s*</(?:POLICY_ID|ID)>', xml_text)
    title_match = _re.search(r'<TITLE>\s*(.+?)\s*</TITLE>', xml_text)

    policy_id = int(id_match.group(1)) if id_match else None
    title = title_match.group(1) if title_match else f.filename

    if not policy_id:
        return jsonify({"error": "Could not extract policy ID from XML. "
                        "Ensure this is a valid Qualys policy export."}), 400

    store_policy_export(policy_id, xml_data, includes_udcs=True)
    xml_size = len(xml_data)
    logger.info("Policy import-xml: stored XML for policy %d (%s) — %s bytes",
                policy_id, title, f"{xml_size:,}")
    return jsonify({
        "imported": True,
        "policy_id": policy_id,
        "title": title,
        "xml_size": xml_size,
        "filename": f.filename,
    })


@app.route("/api/policies/upload", methods=["POST"])
def policy_upload():
    """Upload a policy to a destination Qualys environment using stored XML.
    Renamed from 'import' to 'upload' for clarity."""
    data = request.json or {}
    source_policy_id = data.get("source_policy_id")
    new_title = data.get("title", "")
    lock_pref = data.get("lock", "")  # "locked", "unlocked", or ""

    if not source_policy_id:
        return jsonify({"error": "source_policy_id required"}), 400

    # Get stored XML
    xml_data = get_policy_export_xml(int(source_policy_id))
    if not xml_data:
        logger.warning("Policy import %s: no exported XML found — export required first",
                        source_policy_id)
        return jsonify({"error": "No exported XML found for this policy. Export first."}), 404

    # Build client for DESTINATION environment
    client, error, _ = _build_client(data)
    if error:
        logger.warning("Policy import %s: destination credential error — %s",
                        source_policy_id, error)
        return jsonify({"error": error}), 400

    # Strip <APPENDIX>...</APPENDIX> — Qualys export includes it with
    # show_appendix=1 but the import API rejects it.
    import re as _re
    xml_text = xml_data.decode("utf-8", errors="replace")
    xml_text = _re.sub(r'<APPENDIX>.*?</APPENDIX>', '', xml_text, flags=_re.DOTALL)

    # Reject empty policies — Qualys returns error 1910 for SECTIONS total="0"
    if '<SECTIONS total="0"/>' in xml_text or '<SECTIONS total="0" />' in xml_text:
        logger.warning("Policy upload %s: rejected — empty policy (SECTIONS total=0)",
                        source_policy_id)
        return jsonify({
            "error": "Policy has no sections/controls and cannot be uploaded. "
                     "Qualys would reject it with error 1910."
        }), 422

    xml_data = xml_text.encode("utf-8")

    xml_size = len(xml_data)
    logger.info("Policy upload %s: starting upload to %s (XML %s bytes%s%s)",
                source_policy_id, client.api_base, f"{xml_size:,}",
                f", rename='{new_title}'" if new_title else "",
                f", lock={lock_pref}" if lock_pref else "")

    try:
        params = {
            "action": "import",
            "create_user_controls": "1",
        }
        if new_title:
            params["title"] = new_title

        result = client.execute_with_xml_body(
            "/api/4.0/fo/compliance/policy/",
            xml_body=xml_data,
            params=params,
            timeout=120,
        )

        if result.get("error"):
            logger.error("Policy import %s: API error — %s",
                         source_policy_id, result.get("message"))
            return jsonify({"error": result.get("message", "Import failed")}), 502

        resp_data = result.get("data", {})
        imported_id = None
        lock_result = None

        # Try to extract new policy ID from import response
        # Response may contain POLICY_ID or ID in various nested structures
        if isinstance(resp_data, dict):
            imported_id = (resp_data.get("POLICY_ID") or resp_data.get("ID")
                           or resp_data.get("policy_id") or resp_data.get("id"))

        logger.info("Policy import %s: success — new policy ID: %s",
                     source_policy_id, imported_id or "unknown")

        # If lock preference set and we have the new policy ID, try to lock/unlock
        if lock_pref and imported_id:
            logger.info("Policy import %s: applying lock=%s to new policy %s",
                         source_policy_id, lock_pref, imported_id)
            try:
                lock_val = "1" if lock_pref == "locked" else "0"
                lock_res = client.execute(
                    "/api/4.0/fo/compliance/policy/",
                    params={"action": "update", "id": str(imported_id), "is_locked": lock_val},
                    timeout=30,
                )
                if lock_res.get("error"):
                    lock_result = f"Lock/unlock failed: {lock_res.get('message', 'unknown error')}"
                    logger.warning("Policy import %s: lock failed — %s",
                                   source_policy_id, lock_result)
                else:
                    lock_result = f"Policy {'locked' if lock_pref == 'locked' else 'unlocked'} successfully"
                    logger.info("Policy import %s: %s", source_policy_id, lock_result)
            except Exception as le:
                lock_result = f"Lock/unlock failed: {str(le)}"
                logger.warning("Policy import %s: lock exception — %s",
                               source_policy_id, le)
        elif lock_pref and not imported_id:
            lock_result = "Lock/unlock skipped: could not determine new policy ID from response"
            logger.warning("Policy import %s: %s", source_policy_id, lock_result)

        return jsonify({
            "imported": True,
            "source_policy_id": source_policy_id,
            "imported_policy_id": imported_id,
            "lock_result": lock_result,
            "data": resp_data,
        })
    except Exception as e:
        logger.exception("Policy import %s failed", source_policy_id)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/policies/stale-exports")
def stale_exports():
    """List policies where export is older than last modification."""
    try:
        return jsonify(get_stale_exports())
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Mandates (Compliance Frameworks)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/mandates")
def mandates_search():
    """Search mandates with FTS + filters + pagination."""
    try:
        pub_param = request.args.get("publisher", "")
        publishers = [p.strip() for p in pub_param.split(",") if p.strip()] if pub_param else None
        result = search_mandates(
            q=request.args.get("q", ""),
            publishers=publishers,
            page=int(request.args.get("page", 1)),
            per_page=int(request.args.get("per_page", 50)),
        )
        return jsonify(result)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/mandates/filter-values")
def mandate_filter_values():
    """Get distinct filter values for Mandate multi-select dropdowns."""
    try:
        field = request.args.get("field", "")
        q = request.args.get("q", "")
        return jsonify(get_mandate_filter_values(field, q))
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/mandates/<int:mandate_id>")
def mandates_detail(mandate_id):
    """Get full mandate detail with associated controls and policies."""
    try:
        mandate = get_mandate(mandate_id)
        if not mandate:
            return jsonify({"error": "Mandate not found"}), 404
        return jsonify(mandate)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Tags (Qualys Asset Tags via QPS REST)
# ═══════════════════════════════════════════════════════════════════════════

class _TagSearchQuery(BaseModel):
    q: str | None = Field(default=None, description="FTS over name / rule_text / description")
    rule_type: str | None = Field(default=None, description="Comma-separated rule types (ASSET_INVENTORY, GROOVY, NETWORK_RANGE, …)")
    parent_tag_id: int | None = Field(default=None, description="Direct-children-of filter (numeric tag id)")
    only_user: str | None = Field(default=None, description='"1" → return only user-created tags')
    only_system: str | None = Field(default=None, description='"1" → return only Qualys-managed system tags')
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=50, ge=1, le=500)


class _TagRow(BaseModel):
    tag_id: int
    name: str | None = None
    color: str | None = None
    rule_type: str | None = None
    rule_text: str | None = None
    description: str | None = None
    criticality: int | None = None
    parent_tag_id: int | None = None
    reserved_type: str | None = None
    created_by: str | None = None
    is_user_created: int | None = Field(default=None, description="1 = user-created, 0 = Qualys-managed (effective value, override applied)")
    is_user_created_auto: int | None = Field(default=None, description="Auto-derived classification before override")
    classification_override: str | None = None
    is_editable: int | None = None
    is_editable_auto: int | None = None
    editability_override: str | None = None

    model_config = {"extra": "allow"}


class _TagSearchResponse(Pagination[_TagRow]):
    """Paginated tag search result."""


class _TagDetail(_TagRow):
    """Tag detail — parent + children + breadcrumb path."""
    parent: dict | None = None
    children: list[dict] | None = None
    breadcrumb: list[dict] | None = None
    raw_json: str | None = Field(default=None, description="The exact QPS payload Qualys returned for this tag, useful for debugging classification/editability decisions")
    model_config = {"extra": "allow"}


@app.route("/api/tags")
@openapi.validate(
    query=_TagSearchQuery,
    resp=OpenApiResponse(HTTP_200=_TagSearchResponse, HTTP_500=Error),
    tags=[TAG_TAGS],
)
def tags_search():
    """Search tags with FTS, filters, and pagination."""
    try:
        rt_param = request.args.get("rule_type", "")
        rule_types = [r.strip() for r in rt_param.split(",") if r.strip()] if rt_param else None
        parent_tag_id = request.args.get("parent_tag_id")
        parent_tag_id = int(parent_tag_id) if parent_tag_id else None
        result = search_tags(
            q=request.args.get("q", ""),
            rule_types=rule_types,
            parent_tag_id=parent_tag_id,
            only_user=request.args.get("only_user") == "1",
            only_system=request.args.get("only_system") == "1",
            page=int(request.args.get("page", 1)),
            per_page=int(request.args.get("per_page", 50)),
        )
        return jsonify(result)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/tags/filter-values")
@openapi.validate(
    query=_FilterValuesQuery,
    resp=OpenApiResponse(HTTP_200=_FilterValuesResponse, HTTP_500=Error),
    tags=[TAG_TAGS],
)
def tags_filter_values():
    """Distinct filter values for Tag multi-select dropdowns
    (rule_types is the canonical use case)."""
    try:
        field = request.args.get("field", "")
        q = request.args.get("q", "")
        return jsonify(get_tag_filter_values(field, q))
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/tags/<int:tag_id>")
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_TagDetail, HTTP_404=Error, HTTP_500=Error),
    tags=[TAG_TAGS],
)
def tags_detail(tag_id):
    """Full tag detail — parent breadcrumb + children list + raw QPS
    payload. Effective is_user_created and is_editable both reflect
    any manual override the operator has set."""
    try:
        tag = get_tag(tag_id)
        if not tag:
            return jsonify({"error": "Tag not found"}), 404
        return jsonify(tag)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/tags/<int:tag_id>/classify", methods=["POST"])
def tags_classify(tag_id):
    """Set or clear the manual classification override for a tag.

    Body: {"classification": "user" | "system" | null}
    The auto-classifier output is preserved; this stores an override
    that the read paths apply on top. Useful when the Qualys API
    metadata is ambiguous and the operator knows better.
    """
    try:
        data = request.json or {}
        value = data.get("classification")
        if value is not None and value not in ("user", "system"):
            return jsonify({"error": "classification must be 'user', 'system', or null"}), 400
        ok = set_tag_classification_override(tag_id, value)
        if not ok:
            return jsonify({"error": "Tag not found"}), 404
        return jsonify({"tag_id": tag_id, "classification_override": value})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/tags/<int:tag_id>/editability", methods=["POST"])
def tags_editability(tag_id):
    """Set or clear the manual editability override for a tag.

    Body: {"editability": "editable" | "locked" | null}
    Editability is independent of system/user classification — some
    Qualys-managed tags (Internet Facing Assets, Business Units)
    accept rule edits, while others (OS, region taxonomies) don't.
    Auto-derivation is conservative; this lets the operator override.
    """
    try:
        data = request.json or {}
        value = data.get("editability")
        if value is not None and value not in ("editable", "locked"):
            return jsonify({"error": "editability must be 'editable', 'locked', or null"}), 400
        ok = set_tag_editability_override(tag_id, value)
        if not ok:
            return jsonify({"error": "Tag not found"}), 404
        return jsonify({"tag_id": tag_id, "editability_override": value})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Tags Phase 2: cross-environment migration
# ═══════════════════════════════════════════════════════════════════════════
# Mirrors the Policy migration trio (export → store-locally → upload-to-
# destination). Tags use QPS REST + JSON instead of v4 + XML, but the
# operator workflow is identical: pull a tag from one Qualys environment,
# stage it locally, then push it into another. System tags (those with
# reservedType set) cannot be created via the API and are rejected at
# the upload step.

@app.route("/api/tags/<int:tag_id>/export", methods=["POST"])
def tag_export(tag_id):
    """Pull a tag's full JSON from the source Qualys env and stash it
    locally in tag_exports. Re-fetches even if the tag is already in the
    sync — the stored copy must reflect the source env's exact state at
    the moment of export, not a stale local cache.
    """
    data = request.json or {}
    client, error, cred_id = _build_client(data)
    if error:
        return jsonify({"error": error}), 400

    detail = client.get_tag_detail(tag_id)
    if not detail:
        return jsonify({"error": "Failed to fetch tag detail from Qualys. "
                        "Verify the tag id and your credentials for the source "
                        "environment."}), 502
    blob = json.dumps(detail).encode("utf-8")
    store_tag_export(tag_id, blob, credential_id=cred_id)
    return jsonify({
        "exported": True, "tag_id": tag_id,
        "name": detail.get("name"),
        "payload_size": len(blob),
    })


@app.route("/api/tags/import-json", methods=["POST"])
def tag_import_json():
    """Accept a tag JSON file uploaded from disk. Validates that the
    payload looks like a Qualys Tag (has an id and a name) and stores
    it in tag_exports keyed on that id.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    raw = f.read()
    if not raw:
        return jsonify({"error": "Empty file"}), 400
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        return jsonify({"error": f"Not valid JSON: {e}"}), 400

    # Accept either a bare Tag object or a wrapper that holds one
    # (some operators may save the full ServiceResponse from Qualys).
    if isinstance(payload, dict) and "ServiceResponse" in payload:
        from app.qualys_client import QualysClient
        tags = QualysClient.qps_extract_data(payload, "Tag")
        payload = tags[0] if tags else {}
    if not isinstance(payload, dict):
        return jsonify({"error": "Expected a Tag object"}), 400

    tag_id_raw = payload.get("id") or payload.get("ID") or payload.get("tag_id")
    try:
        tag_id = int(tag_id_raw) if tag_id_raw else 0
    except (TypeError, ValueError):
        tag_id = 0
    if not tag_id:
        return jsonify({"error": "Could not extract a tag id from the JSON. "
                        "Ensure this is a Qualys QPS REST tag detail payload."}), 400
    name = payload.get("name") or payload.get("NAME") or ""

    blob = json.dumps(payload).encode("utf-8")
    store_tag_export(tag_id, blob, credential_id=None)
    return jsonify({
        "imported": True, "tag_id": tag_id, "name": name,
        "payload_size": len(blob), "filename": f.filename,
    })


@app.route("/api/tags/<int:tag_id>/export-download")
def tag_export_download(tag_id):
    """Return the stored export as a downloadable JSON file so the
    operator can move it between machines or store it externally."""
    blob = get_tag_export_json(tag_id)
    if not blob:
        return jsonify({"error": "No stored export for this tag. Export first."}), 404
    resp = make_response(blob)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = f'attachment; filename="tag-{tag_id}.json"'
    return resp


@app.route("/api/tags/export-bundle")
def tag_export_bundle():
    """Download multiple stored tag exports as a single JSON array.

    Query params:
      tag_ids — comma-separated list of tag ids to include in the bundle.

    Returns a JSON array of tag payloads, suitable for import via the
    migration flow or external tooling.
    """
    raw = request.args.get("tag_ids", "")
    tag_ids = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
    if not tag_ids:
        return jsonify({"error": "tag_ids query parameter required"}), 400

    bundle = []
    for tid in tag_ids:
        blob = get_tag_export_json(tid)
        if blob:
            try:
                bundle.append(json.loads(blob.decode("utf-8")))
            except (ValueError, UnicodeDecodeError):
                pass  # skip corrupted entries

    resp = make_response(json.dumps(bundle, indent=2))
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = (
        f'attachment; filename="tags-export-{len(bundle)}-tags.json"'
    )
    return resp


@app.route("/api/tags/delete-local", methods=["POST"])
def tag_delete_local():
    """Delete selected tags from the local synced database.

    Body:
      tag_ids — list of tag ids to delete, OR the string 'all' to purge everything.

    This only removes from the local cache — does NOT delete from Qualys.
    """
    from app.database import get_db

    data = request.json or {}
    tag_ids = data.get("tag_ids")

    if not tag_ids:
        return jsonify({"error": "tag_ids required (list of ints or 'all')"}), 400

    with get_db() as conn:
        if tag_ids == "all":
            count = conn.execute("SELECT COUNT(*) FROM tags").fetchone()[0]
            conn.execute("DELETE FROM tags")
            conn.execute("INSERT INTO tags_fts(tags_fts) VALUES('rebuild')")
        else:
            if not isinstance(tag_ids, list):
                return jsonify({"error": "tag_ids must be a list or 'all'"}), 400
            placeholders = ",".join("?" * len(tag_ids))
            count = conn.execute(
                f"SELECT COUNT(*) FROM tags WHERE tag_id IN ({placeholders})",
                tag_ids,
            ).fetchone()[0]
            conn.execute(
                f"DELETE FROM tags WHERE tag_id IN ({placeholders})",
                tag_ids,
            )
            conn.execute("INSERT INTO tags_fts(tags_fts) VALUES('rebuild')")

    return jsonify({"deleted": count, "requested": len(tag_ids) if isinstance(tag_ids, list) else "all"})


@app.route("/api/tags/import-local", methods=["POST"])
def tag_import_local():
    """Import tags from a JSON file into the local database.

    Accepts a JSON array of tag objects (like the output of export-local).
    Each tag is upserted into the local tags table by tag_id. If the tag
    already exists locally, it is updated; if not, it is inserted.

    This does NOT push to Qualys — it only populates the local cache so
    the tags can be browsed, audited, and then optionally migrated.
    """
    from app.database import get_db

    if "file" not in request.files:
        # Try JSON body instead
        raw = request.get_data()
    else:
        raw = request.files["file"].read()

    if not raw:
        return jsonify({"error": "No data provided"}), 400

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        return jsonify({"error": f"Not valid JSON: {e}"}), 400

    # Accept array or single object
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        return jsonify({"error": "Expected a JSON array of tag objects"}), 400

    imported = 0
    skipped = 0
    with get_db() as conn:
        for t in payload:
            tag_id = t.get("tag_id") or t.get("id")
            if not tag_id:
                skipped += 1
                continue
            try:
                tag_id = int(tag_id)
            except (TypeError, ValueError):
                skipped += 1
                continue

            name = t.get("name", "")
            # Extract provenance — from _provenance block or top-level fields
            prov = t.get("_provenance") or {}
            src_cred = prov.get("source_credential_id") or t.get("source_credential_id")
            src_plat = prov.get("source_platform") or t.get("source_platform")
            src_sub = prov.get("source_subscription") or t.get("source_subscription")
            # If no provenance at all, mark as "unknown" so migration knows
            # this tag has no confirmed origin
            if not src_plat:
                src_plat = "unknown"

            conn.execute(
                """INSERT INTO tags (tag_id, name, description, color, criticality,
                   rule_type, rule_text, parent_tag_id, reserved_type, is_user_created,
                   source_credential_id, source_platform, source_subscription)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(tag_id) DO UPDATE SET
                     name=excluded.name, description=excluded.description,
                     color=excluded.color, criticality=excluded.criticality,
                     rule_type=excluded.rule_type, rule_text=excluded.rule_text,
                     parent_tag_id=excluded.parent_tag_id,
                     reserved_type=excluded.reserved_type,
                     is_user_created=excluded.is_user_created,
                     source_credential_id=excluded.source_credential_id,
                     source_platform=excluded.source_platform,
                     source_subscription=excluded.source_subscription""",
                (
                    tag_id,
                    name,
                    t.get("description"),
                    t.get("color"),
                    t.get("criticality"),
                    t.get("rule_type"),
                    t.get("rule_text"),
                    t.get("parent_tag_id"),
                    t.get("reserved_type"),
                    1 if t.get("is_user_created") else 0,
                    src_cred,
                    src_plat,
                    src_sub,
                ),
            )
            imported += 1
        # Rebuild FTS index
        conn.execute("INSERT INTO tags_fts(tags_fts) VALUES('rebuild')")

    return jsonify({"imported": imported, "skipped": skipped, "total": len(payload)})


@app.route("/api/tags/export-local")
def tag_export_local():
    """Export tags directly from the local synced database as a JSON download.

    Query params:
      tag_ids — comma-separated list of tag ids, OR 'all' to export everything.

    Pulls from the already-synced local SQLite — no Qualys API call needed.
    The export format matches what the migration import expects.
    """
    from app.database import get_tag, search_tags

    raw = request.args.get("tag_ids", "")
    if raw.strip().lower() == "all":
        # Export all tags from local DB
        data = search_tags(per_page=100000)
        items = data.get("results", [])
    else:
        tag_ids = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
        if not tag_ids:
            return jsonify({"error": "tag_ids parameter required (comma-separated or 'all')"}), 400
        items = []
        for tid in tag_ids:
            t = get_tag(tid)
            if t:
                items.append(t)

    # Strip internal-only fields and format for migration compatibility
    export_fields = [
        "tag_id", "name", "description", "color", "criticality",
        "rule_type", "rule_text", "parent_tag_id", "parent_name",
        "reserved_type", "is_user_created", "tag_origin",
        "child_count", "children",
        "source_credential_id", "source_platform", "source_subscription",
    ]
    bundle = []
    for t in items:
        entry = {k: t.get(k) for k in export_fields if k in t}
        # Also include as 'id' for Qualys QPS compatibility
        entry["id"] = t.get("tag_id")
        # Include provenance metadata for migration logic
        entry["_provenance"] = {
            "source_credential_id": t.get("source_credential_id"),
            "source_platform": t.get("source_platform"),
            "source_subscription": t.get("source_subscription"),
            "exported_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        }
        bundle.append(entry)

    resp = make_response(json.dumps(bundle, indent=2))
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = (
        f'attachment; filename="tags-export-{len(bundle)}-tags.json"'
    )
    return resp


@app.route("/api/tags/exports")
def tag_exports_list():
    """List every stored tag export with metadata for the migration UI."""
    return jsonify(list_tag_exports())


@app.route("/api/tags/export-bulk", methods=["POST"])
def tag_export_bulk():
    """Export multiple tags in one request for migration purposes.

    Body:
      tag_ids         — list of tag ids to export
      credential_id   — source env credential (optional, uses active if omitted)
      platform        — source Qualys platform region

    Each tag is fetched from the live Qualys API and stored locally in
    tag_exports, identical to the single-tag export. Returns a summary
    of successes and failures.
    """
    data = request.json or {}
    tag_ids = data.get("tag_ids") or []
    if not tag_ids or not isinstance(tag_ids, list):
        return jsonify({"error": "tag_ids (list of integers) required"}), 400

    client, error, cred_id = _build_client(data)
    if error:
        return jsonify({"error": error}), 400

    results = {"exported": [], "failed": []}
    for tid in tag_ids:
        try:
            tid = int(tid)
            detail = client.get_tag_detail(tid)
            if not detail:
                results["failed"].append({"tag_id": tid, "reason": "Not found or fetch failed"})
                continue
            blob = json.dumps(detail).encode("utf-8")
            store_tag_export(tid, blob, credential_id=cred_id)
            results["exported"].append({
                "tag_id": tid,
                "name": detail.get("name", ""),
                "payload_size": len(blob),
            })
        except Exception as e:
            results["failed"].append({"tag_id": tid, "reason": str(e)})

    results["total"] = len(tag_ids)
    results["success_count"] = len(results["exported"])
    results["fail_count"] = len(results["failed"])
    return jsonify(results)


@app.route("/api/tags/<int:tag_id>/export", methods=["DELETE"])
def tag_export_delete(tag_id):
    ok = delete_tag_export(tag_id)
    if not ok:
        return jsonify({"error": "No stored export for this tag"}), 404
    return jsonify({"deleted": True, "tag_id": tag_id})


@app.route("/api/tags/upload", methods=["POST"])
def tag_upload():
    """Push a stored tag export to a destination Qualys environment.

    Body:
      source_tag_id   — id of the tag whose stored export to upload
      credential_id   — destination env credential
      platform        — destination Qualys platform region
      new_name        — optional rename (avoids collisions)
      parent_tag_id   — optional destination-env parent id; if omitted
                        and the source had a parent, the parent ref is
                        dropped and the tag is created at root level.

    System tags (reservedType set in the stored payload) are rejected
    up front because the Qualys create-tag endpoint will reject them
    server-side anyway.
    """
    data = request.json or {}
    source_tag_id = data.get("source_tag_id")
    if not source_tag_id:
        return jsonify({"error": "source_tag_id required"}), 400

    blob = get_tag_export_json(int(source_tag_id))
    if not blob:
        return jsonify({"error": "No stored export for this tag. Export first."}), 404
    try:
        payload = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        return jsonify({"error": f"Stored export is not valid JSON: {e}"}), 500

    reserved = payload.get("reservedType") or payload.get("reserved_type")
    if reserved:
        return jsonify({
            "error": "This is a Qualys-managed system tag (reservedType: "
                     f"{reserved}). The QPS REST create endpoint rejects "
                     "tags with a reserved type. System tags exist by default "
                     "in every Qualys environment — no migration needed.",
            "system_tag": True,
        }), 400

    client, error, cred_id = _build_client(data)
    if error:
        return jsonify({"error": error}), 400

    parent_tag_id = data.get("parent_tag_id")
    new_name = (data.get("new_name") or "").strip() or None
    try:
        parent_int = int(parent_tag_id) if parent_tag_id else None
    except (TypeError, ValueError):
        parent_int = None

    result = client.create_tag(
        payload, new_name=new_name, parent_tag_id=parent_int, timeout=60,
    )
    if result.get("error"):
        return jsonify({
            "error": result.get("message", "create-tag failed"),
            "status_code": result.get("status_code"),
        }), 502

    return jsonify({
        "uploaded": True,
        "source_tag_id": int(source_tag_id),
        "destination_tag_id": result.get("tag_id"),
        "destination_credential_id": cred_id,
        "name": new_name or payload.get("name"),
    })


_tag_migration_status = {}  # Tracks running tag migration progress


@app.route("/api/tags/migrate-preflight", methods=["POST"])
def tag_migrate_preflight():
    """Check destination for name collisions before migration.

    Body:
      tag_ids             — list of tag ids to check
      dest_credential_id  — destination credential
      dest_platform       — destination platform

    Returns a list of tags that would collide by name in the destination.
    """
    data = request.json or {}
    tag_ids = data.get("tag_ids") or []
    if not tag_ids:
        return jsonify({"collisions": []})

    dest_client, error, _ = _build_client({
        "credential_id": data.get("dest_credential_id"),
        "platform": data.get("dest_platform"),
    })
    if error:
        return jsonify({"error": f"Destination env: {error}"}), 400

    # Get local tag names for the selected IDs
    from app.database import get_db
    local_names = {}
    with get_db() as conn:
        for tid in tag_ids:
            row = conn.execute("SELECT name FROM tags WHERE tag_id=?", (int(tid),)).fetchone()
            if row:
                local_names[int(tid)] = row[0]

    # Search destination for each name
    collisions = []
    checked = set()
    for tid, name in local_names.items():
        if name in checked:
            continue
        checked.add(name)
        try:
            # Search by exact name in destination
            result = dest_client.execute_json(
                "/qps/rest/2.0/search/am/tag",
                body={"ServiceRequest": {"filters": {"Criteria": {
                    "field": "name", "operator": "EQUALS", "value": name
                }}, "preferences": {"limitResults": 1}}},
            )
            if not result.get("error"):
                from app.qualys_client import QualysClient
                tags = QualysClient.qps_extract_data(result.get("data", {}), "Tag")
                if tags:
                    collisions.append({
                        "tag_id": tid,
                        "name": name,
                        "dest_tag_id": tags[0].get("id"),
                        "dest_tag_name": tags[0].get("name"),
                    })
        except Exception:
            pass  # skip check failures — migration will catch them

    return jsonify({"collisions": collisions, "checked": len(checked)})


@app.route("/api/tags/migrate-direct", methods=["POST"])
def tag_migrate_direct():
    """Start async tag migration: fetch from source, push to destination.

    Returns immediately with a job ID. Poll /api/tags/migrate-status
    for progress and results.
    """
    data = request.json or {}
    tag_ids = data.get("tag_ids") or []
    if not tag_ids or not isinstance(tag_ids, list):
        return jsonify({"error": "tag_ids (list of integers) required"}), 400

    # Per-tag rename overrides and skip list from collision resolution
    renames = data.get("renames") or {}  # {tag_id_str: "new name"}
    skip_ids = set(int(x) for x in (data.get("skip_ids") or []))

    # Remove skipped tags
    tag_ids = [tid for tid in tag_ids if int(tid) not in skip_ids]

    # Build clients up front (validates credentials before spawning thread)
    source_client, error, _ = _build_client({
        "credential_id": data.get("source_credential_id"),
        "platform": data.get("source_platform"),
    })
    if error:
        return jsonify({"error": f"Source env: {error}"}), 400

    dest_client, error, dest_cred_id = _build_client({
        "credential_id": data.get("dest_credential_id"),
        "platform": data.get("dest_platform"),
    })
    if error:
        return jsonify({"error": f"Destination env: {error}"}), 400

    job_id = f"migrate_{int(time.time())}"
    _tag_migration_status[job_id] = {
        "status": "running",
        "total": len(tag_ids),
        "processed": 0,
        "migrated": [],
        "skipped": [],
        "failed": [],
        "current_tag": None,
    }

    def run_migration():
        status = _tag_migration_status[job_id]
        try:
            # Optionally create parent tag
            parent_tag_id = None
            parent_name = None
            if data.get("create_parent"):
                from datetime import date
                parent_name = (data.get("parent_name") or "").strip()
                if not parent_name:
                    parent_name = f"TAGs Imported {date.today().isoformat()}"
                parent_result = dest_client.create_tag(
                    {"name": parent_name, "ruleType": "STATIC"}, timeout=60)
                if parent_result.get("error"):
                    status["status"] = "error"
                    status["error"] = f"Failed to create parent tag: {parent_result.get('message')}"
                    return
                parent_tag_id = parent_result.get("tag_id")
                status["parent_tag_id"] = parent_tag_id
                status["parent_name"] = parent_name

            for i, tid in enumerate(tag_ids):
                try:
                    tid = int(tid)
                    status["processed"] = i + 1
                    status["current_tag"] = tid

                    # Fetch from source
                    detail = source_client.get_tag_detail(tid)
                    if not detail:
                        status["failed"].append({"tag_id": tid, "reason": "Not found in source"})
                        continue

                    # Skip system tags
                    reserved = detail.get("reservedType") or detail.get("reserved_type")
                    if reserved:
                        status["skipped"].append({
                            "tag_id": tid,
                            "name": detail.get("name", ""),
                            "reason": f"System tag ({reserved})",
                        })
                        continue

                    # Check if update or create
                    from app.database import get_db
                    is_update = False
                    with get_db() as _conn:
                        local_tag = _conn.execute(
                            "SELECT source_credential_id, source_platform FROM tags WHERE tag_id=?",
                            (tid,)
                        ).fetchone()
                        if local_tag:
                            src_cred = local_tag[0] or ""
                            src_plat = local_tag[1] or "unknown"
                            if src_cred == data.get("dest_credential_id") and src_plat != "unknown":
                                is_update = True

                    # Check for a pre-configured rename from collision resolution
                    rename_to = renames.get(str(tid))

                    if is_update:
                        result = dest_client.update_tag(tid, detail, timeout=60)
                    else:
                        result = dest_client.create_tag(
                            detail,
                            new_name=rename_to or None,
                            parent_tag_id=parent_tag_id if parent_tag_id else None,
                            timeout=60,
                        )
                        # If name collision and no pre-rename was set, auto-retry with suffix
                        if result.get("error") and not rename_to:
                            err_msg = str(result.get("message", "") or "")
                            err_data = result.get("data") or {}
                            qualys_err = ""
                            if isinstance(err_data, dict):
                                qualys_err = str(err_data.get("responseErrorDetails", {}).get("errorMessage", ""))
                            if "already exists" in err_msg.lower() or "already exists" in qualys_err.lower():
                                tag_name = detail.get("name", "")
                                new_name = f"{tag_name} (migrated)"
                                result = dest_client.create_tag(
                                    detail, new_name=new_name,
                                    parent_tag_id=parent_tag_id if parent_tag_id else None,
                                    timeout=60,
                                )
                                if not result.get("error"):
                                    status["migrated"].append({
                                        "tag_id": tid,
                                        "name": f"{tag_name} → renamed to '{new_name}'",
                                        "dest_tag_id": result.get("tag_id") or tid,
                                        "operation": "create (renamed)",
                                    })
                                    continue

                    if result.get("error"):
                        error_detail = result.get("message", "failed")
                        # Include HTTP status and Qualys error code if available
                        if result.get("status_code"):
                            error_detail = f"[HTTP {result['status_code']}] {error_detail}"
                        if result.get("data") and isinstance(result["data"], dict):
                            qerr = result["data"].get("responseErrorDetails", {})
                            if isinstance(qerr, dict) and qerr.get("errorMessage"):
                                error_detail += f" — {qerr['errorMessage']}"
                        status["failed"].append({
                            "tag_id": tid,
                            "name": detail.get("name", ""),
                            "reason": error_detail[:300],
                            "operation": "update" if is_update else "create",
                        })
                    else:
                        status["migrated"].append({
                            "tag_id": tid,
                            "name": detail.get("name", ""),
                            "dest_tag_id": result.get("tag_id") or tid,
                            "operation": "update" if is_update else "create",
                        })
                except Exception as e:
                    status["failed"].append({"tag_id": tid, "reason": str(e)})

            status["status"] = "complete"
        except Exception as e:
            status["status"] = "error"
            status["error"] = str(e)
        finally:
            status["current_tag"] = None
            status["migrated_count"] = len(status["migrated"])
            status["skipped_count"] = len(status["skipped"])
            status["failed_count"] = len(status["failed"])
            status["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            # Persist report to disk for later review
            try:
                import os
                report_dir = "/data/migration_reports"
                os.makedirs(report_dir, exist_ok=True)
                report_path = os.path.join(report_dir, f"{job_id}.json")
                with open(report_path, "w") as f:
                    json.dump(status, f, indent=2, default=str)
            except Exception:
                pass  # best-effort persistence

    thread = threading.Thread(target=run_migration, daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "total": len(tag_ids), "status": "started"})


@app.route("/api/tags/delete-qualys", methods=["POST"])
def tag_delete_qualys():
    """Delete tags from the source Qualys subscription AND local cache.

    Body:
      tag_ids         — list of tag ids to delete
      credential_id   — credential for the Qualys environment
      platform        — platform region

    System tags are skipped (Qualys rejects deletion of reserved tags).
    Returns per-tag success/failure results.
    """
    data = request.json or {}
    tag_ids = data.get("tag_ids") or []
    if not tag_ids or not isinstance(tag_ids, list):
        return jsonify({"error": "tag_ids (list of integers) required"}), 400

    client, error, cred_id = _build_client(data)
    if error:
        return jsonify({"error": error}), 400

    results = {"deleted": [], "skipped": [], "failed": []}

    for tid in tag_ids:
        try:
            tid = int(tid)
            # Check if system tag locally first
            from app.database import get_db
            with get_db() as conn:
                row = conn.execute(
                    "SELECT name, reserved_type, is_user_created FROM tags WHERE tag_id=?",
                    (tid,)
                ).fetchone()

            tag_name = row["name"] if row else f"#{tid}"
            if row and row["reserved_type"]:
                results["skipped"].append({
                    "tag_id": tid,
                    "name": tag_name,
                    "reason": f"System tag (reservedType: {row['reserved_type']}) — cannot delete",
                })
                continue

            # Delete from Qualys
            result = client.delete_tag(tid, timeout=30)
            if result.get("error"):
                error_msg = result.get("message", "delete failed")
                if result.get("status_code"):
                    error_msg = f"[HTTP {result['status_code']}] {error_msg}"
                results["failed"].append({
                    "tag_id": tid,
                    "name": tag_name,
                    "reason": error_msg[:300],
                })
            else:
                results["deleted"].append({
                    "tag_id": tid,
                    "name": tag_name,
                })
                # Also remove from local DB
                with get_db() as conn:
                    conn.execute("DELETE FROM tags WHERE tag_id=?", (tid,))

        except Exception as e:
            results["failed"].append({"tag_id": tid, "reason": str(e)[:200]})

    # Rebuild FTS after local deletions
    if results["deleted"]:
        with get_db() as conn:
            conn.execute("INSERT INTO tags_fts(tags_fts) VALUES('rebuild')")

    results["total"] = len(tag_ids)
    results["deleted_count"] = len(results["deleted"])
    results["skipped_count"] = len(results["skipped"])
    results["failed_count"] = len(results["failed"])
    return jsonify(results)


@app.route("/api/tags/migrate-status")
def tag_migrate_status():
    """Poll migration progress. Also loads persisted reports if the
    in-memory state was lost (worker restart)."""
    job_id = request.args.get("job_id", "")
    if not job_id or job_id not in _tag_migration_status:
        # Return latest job if no ID specified
        if _tag_migration_status:
            job_id = max(_tag_migration_status.keys())
        else:
            # Check disk for persisted reports
            import os, glob
            report_dir = "/data/migration_reports"
            if os.path.exists(report_dir):
                reports = sorted(glob.glob(os.path.join(report_dir, "migrate_*.json")))
                if reports:
                    try:
                        with open(reports[-1]) as f:
                            return jsonify(json.load(f))
                    except Exception:
                        pass
            return jsonify({"status": "none"})
    return jsonify(_tag_migration_status.get(job_id, {"status": "not_found"}))


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Tags Phase 3: CRUD pushed to Qualys
# ═══════════════════════════════════════════════════════════════════════════
# Three write endpoints (create / update / delete) plus a validate
# endpoint and a Test-on-Qualys endpoint that previews a rule against
# the tenant's asset universe before commit. Every write path:
#
#   1. Runs the same server-side validation the frontend ran (defense
#      in depth — a misbehaving JS bundle can't push bad data).
#   2. Calls the matching QualysClient method.
#   3. Surfaces Qualys's responseErrorDetails verbatim so the operator
#      sees Qualys's reason, not a generic 502.
#   4. Refreshes local state from the destination via get_tag_detail
#      + upsert_tag so the UI shows the result of the write
#      immediately, no manual sync required.
#
# Edit + Delete refuse to touch tags whose effective is_editable is 0
# (auto-derived as locked AND no Force Editable override). Operator
# can always set the override explicitly if they know better than the
# heuristic.

def _payload_from_tag_form(data: dict) -> dict:
    """Translate the form's flat field names to the QPS Tag shape.

    Frontend posts plain {name, color, criticality, description,
    rule_type, rule_text, parent_tag_id} keys; QPS expects camelCase
    (criticalityScore, ruleType, ruleText, parentTagId). Centralising
    the rename so create / update / validate / test stay consistent.
    """
    out: dict = {}
    if "name" in data and data["name"] is not None:
        out["name"] = str(data["name"]).strip()
    if data.get("color"):
        out["color"] = data["color"]
    if data.get("description") is not None:
        out["description"] = data["description"]
    if data.get("criticality") not in (None, ""):
        out["criticalityScore"] = data["criticality"]
    if data.get("rule_type"):
        out["ruleType"] = data["rule_type"]
    if data.get("rule_text") is not None:
        out["ruleText"] = data["rule_text"]
    if data.get("parent_tag_id") not in (None, ""):
        out["parentTagId"] = data["parent_tag_id"]
    return out


@app.route("/api/tags/validate", methods=["POST"])
def tag_validate():
    """Run server-side validation on a tag definition without touching
    Qualys. Mirrors the client-side validator; the frontend hits this
    on every form change for inputs that are too expensive to check in
    JS alone."""
    from app.tag_validation import validate_tag_payload
    data = request.json or {}
    payload = _payload_from_tag_form(data) if "rule_type" in data or "name" in data else data
    result = validate_tag_payload(payload)
    return jsonify(result.to_dict())


@app.route("/api/tags/test-rule", methods=["POST"])
def tag_test_rule():
    """Preview a tag definition against the destination Qualys env's
    asset universe. Returns the asset-match count when Qualys exposes
    its evaluate endpoint, or a clear fallback message when it doesn't.
    Either way the operator can keep going — Save will get Qualys's
    final word at create/update time."""
    from app.tag_validation import validate_tag_payload
    data = request.json or {}
    payload = _payload_from_tag_form(data) if "rule_type" in data else data

    # Local validation first — no point asking Qualys to evaluate
    # something we already know is malformed.
    vresult = validate_tag_payload(payload)
    if not vresult.ok:
        return jsonify({
            "ok": False, "stage": "local",
            "errors": vresult.errors, "warnings": vresult.warnings,
        }), 400

    client, error, _cred = _build_client(data)
    if error:
        return jsonify({"error": error}), 400

    eval_result = client.evaluate_tag_payload(payload, timeout=60)
    if eval_result.get("ok"):
        return jsonify({
            "ok": True, "stage": "qualys",
            "asset_count": eval_result.get("asset_count"),
            "warnings": vresult.warnings,
        })
    if eval_result.get("fallback"):
        return jsonify({
            "ok": True, "stage": "fallback",
            "fallback_reason": eval_result.get("message"),
            "asset_count": None,
            "warnings": vresult.warnings,
        })
    return jsonify({
        "ok": False, "stage": "qualys",
        "message": eval_result.get("message", "Qualys preview failed"),
        "warnings": vresult.warnings,
    }), 502


@app.route("/api/tags/create", methods=["POST"])
def tag_create():
    """Create a new tag in the destination Qualys env, then refresh
    the local copy from Qualys so the new tag appears in the UI
    immediately."""
    from app.tag_validation import validate_tag_payload
    data = request.json or {}
    payload = _payload_from_tag_form(data)

    vresult = validate_tag_payload(payload)
    if not vresult.ok:
        return jsonify({
            "error": "Validation failed",
            "errors": vresult.errors, "warnings": vresult.warnings,
        }), 400

    client, error, cred_id = _build_client(data)
    if error:
        return jsonify({"error": error}), 400

    result = client.create_tag(payload, timeout=60)
    if result.get("error"):
        return jsonify({
            "error": result.get("message", "create-tag failed"),
            "status_code": result.get("status_code"),
        }), 502

    new_id = result.get("tag_id")
    # Pull the freshly-created tag back out of Qualys and write it
    # into the local DB so the UI's tag list and detail modal update
    # without a full re-sync.
    if new_id:
        try:
            detail = client.get_tag_detail(new_id)
            if detail:
                upsert_tag(detail, credential_id=cred_id)
        except Exception as e:
            logger.warning("Post-create refresh failed for tag %s: %s", new_id, e)

    return jsonify({
        "created": True, "tag_id": new_id,
        "name": payload.get("name"),
        "warnings": vresult.warnings,
    })


@app.route("/api/tags/<int:tag_id>/update", methods=["POST"])
def tag_update(tag_id):
    """Update an existing tag. Refuses on tags whose effective
    is_editable is 0 — operator must explicitly set Force Editable
    override (or fix the auto-classifier) before edits go through."""
    from app.tag_validation import validate_tag_payload
    data = request.json or {}

    # Local-side editability gate — prevents a client without the
    # latest UI guards from PATCHing a locked tag. Honors the operator's
    # manual override the same way the modal does.
    local = get_tag(tag_id)
    if local is None:
        return jsonify({"error": "Tag not found in local DB. Sync first or "
                        "use the Migrate flow if it lives in another env."}), 404
    if not local.get("is_editable"):
        return jsonify({
            "error": "This tag is locked. If Qualys actually allows edits to "
                     "it, set the editability override to 'Force Editable' "
                     "in the tag detail modal first.",
            "is_editable": 0,
            "is_editable_auto": local.get("is_editable_auto"),
        }), 403

    payload = _payload_from_tag_form(data)
    vresult = validate_tag_payload(payload)
    if not vresult.ok:
        return jsonify({
            "error": "Validation failed",
            "errors": vresult.errors, "warnings": vresult.warnings,
        }), 400

    client, error, cred_id = _build_client(data)
    if error:
        return jsonify({"error": error}), 400

    result = client.update_tag(tag_id, payload, timeout=60)
    if result.get("error"):
        return jsonify({
            "error": result.get("message", "update-tag failed"),
            "status_code": result.get("status_code"),
        }), 502

    # Refresh local state from Qualys so the modal reopens with the
    # values Qualys actually accepted (it normalises some fields).
    try:
        detail = client.get_tag_detail(tag_id)
        if detail:
            upsert_tag(detail, credential_id=cred_id)
    except Exception as e:
        logger.warning("Post-update refresh failed for tag %s: %s", tag_id, e)

    return jsonify({
        "updated": True, "tag_id": tag_id,
        "warnings": vresult.warnings,
    })


@app.route("/api/tags/<int:tag_id>/impact", methods=["GET"])
def tag_impact(tag_id):
    """Pre-flight count of what a delete would affect. Used by the
    delete confirmation modal so the operator sees "this also removes
    N child tags" before they click Confirm."""
    local = get_tag(tag_id)
    if local is None:
        return jsonify({"error": "Tag not found in local DB"}), 404
    children = local.get("children") or []
    return jsonify({
        "tag_id": tag_id,
        "name": local.get("name"),
        "child_count": len(children),
        "child_sample": [{"tag_id": c.get("tag_id"), "name": c.get("name")}
                         for c in children[:10]],
        "is_editable": local.get("is_editable"),
        "is_user_created": local.get("is_user_created"),
    })


@app.route("/api/tags/<int:tag_id>/delete", methods=["POST"])
def tag_delete(tag_id):
    """Delete a tag from Qualys, then remove the local copy.

    Uses the same editability gate as update — Qualys would refuse
    deletion of system-managed tags anyway, so the local refusal
    just shortens the feedback loop."""
    data = request.json or {}
    local = get_tag(tag_id)
    if local is None:
        return jsonify({"error": "Tag not found in local DB"}), 404
    if not local.get("is_editable"):
        return jsonify({
            "error": "Locked tag. Set Force Editable override first if "
                     "you're sure Qualys will accept the delete.",
            "is_editable": 0,
        }), 403

    client, error, _cred = _build_client(data)
    if error:
        return jsonify({"error": error}), 400

    result = client.delete_tag(tag_id, timeout=30)
    if result.get("error"):
        return jsonify({
            "error": result.get("message", "delete-tag failed"),
            "status_code": result.get("status_code"),
        }), 502

    # Remove from local DB. Children are NOT cascaded locally — Qualys
    # decides cascading server-side; we re-sync on the next pull.
    try:
        from app.database import get_db
        with get_db() as conn:
            conn.execute("DELETE FROM tags WHERE tag_id=?", (tag_id,))
    except Exception as e:
        logger.warning("Post-delete local cleanup failed for tag %s: %s", tag_id, e)

    return jsonify({"deleted": True, "tag_id": tag_id})


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Tags Phase 4: Custom Library + Apply
# ═══════════════════════════════════════════════════════════════════════════
# A curated bank of tag definitions the operator can apply into a
# Qualys environment as a new tag. Built-ins ship with the app and
# can be hidden but not edited; user-authored entries are full CRUD.
# Apply re-uses the Phase 3 create-tag plumbing (validation +
# create_tag + local refresh) and records an audit row so the
# operator can see "I applied X to envA on date Y".

class _LibraryListQuery(BaseModel):
    category: str | None = Field(default=None, description="Filter to one category (e.g. Network, Operating System)")
    q: str | None = Field(default=None, description="Substring search across name / description / rationale")
    include_hidden: str | None = Field(default=None, description='"1" surfaces hidden built-ins (manage-hidden view)')


class _LibraryEntry(BaseModel):
    library_id: int
    slug: str
    name: str
    category: str
    description: str | None = None
    rationale: str | None = None
    source_url: str | None = None
    rule_type: str
    rule_text: str | None = None
    color: str | None = None
    criticality: int | None = None
    suggested_parent: str | None = None
    is_builtin: int
    is_hidden: int
    created_at: str | None = None
    updated_at: str | None = None
    model_config = {"extra": "allow"}


class _LibraryListResponse(RootModel[list[_LibraryEntry]]):
    """Bare list — sorted by category then name within each category."""


@app.route("/api/library", methods=["GET"])
@openapi.validate(
    query=_LibraryListQuery,
    resp=OpenApiResponse(HTTP_200=_LibraryListResponse),
    tags=[TAG_LIBRARY],
)
def library_list():
    """List library entries. Built-ins ship pre-seeded; user entries
    layer on top. By default `is_hidden=1` rows are excluded so the
    operator's "I don't want to see this" choice is respected."""
    category = request.args.get("category") or None
    q = request.args.get("q") or None
    include_hidden = request.args.get("include_hidden") == "1"
    return jsonify(list_library_entries(
        category=category, q=q, include_hidden=include_hidden,
    ))


@app.route("/api/library/<int:library_id>", methods=["GET"])
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_LibraryEntry, HTTP_404=Error),
    tags=[TAG_LIBRARY],
)
def library_get(library_id):
    """Single library entry by id."""
    entry = get_library_entry(library_id)
    if not entry:
        return jsonify({"error": "Library entry not found"}), 404
    return jsonify(entry)


class _LibraryEntryWriteRequest(BaseModel):
    """Body for create / update of a user-authored library entry.
    All fields optional on PATCH; PATCH merges with existing row
    before validation."""
    name: str | None = Field(default=None, description="Required on create")
    category: str | None = Field(default="Custom")
    description: str | None = None
    rationale: str | None = None
    source_url: str | None = None
    rule_type: str | None = Field(default=None, description="Canonical rule type — STATIC / NETWORK_RANGE / OS_REGEX / etc.")
    rule_text: str | None = None
    color: str | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    suggested_parent: str | None = None
    slug: str | None = Field(default=None, description="Optional explicit slug; otherwise derived from name")


class _LibraryCloneRequest(BaseModel):
    name: str | None = Field(default=None, description="Optional new name; defaults to '<source name> (copy)'")


class _LibraryApplyRequest(BaseModel):
    credential_id: str = Field(..., description="Destination Qualys credential")
    platform: str | None = Field(default=None, description="Destination platform region (defaults to credential's stored platform)")
    new_name: str | None = Field(default=None, description="Optional rename for this apply only")
    parent_tag_id: int | None = Field(default=None, description="Destination parent tag id (tag ids don't transfer between envs)")
    overrides: dict | None = Field(default=None, description="Per-apply overrides — {rule_text, color, criticality}")


class _LibraryApplyHistoryEntry(BaseModel):
    id: int
    library_id: int
    library_name: str | None = None
    slug: str | None = None
    destination_credential_id: str | None = None
    destination_platform: str | None = None
    destination_tag_id: int | None = None
    destination_tag_name: str | None = None
    applied_at: str
    model_config = {"extra": "allow"}


class _LibraryApplyHistoryResponse(RootModel[list[_LibraryApplyHistoryEntry]]):
    """Newest-first audit log."""


@app.route("/api/library", methods=["POST"])
@openapi.validate(
    json=_LibraryEntryWriteRequest,
    resp=OpenApiResponse(HTTP_200=OkMessage, HTTP_400=Error),
    tags=[TAG_LIBRARY],
)
def library_create():
    """Create a user-authored library entry. Validates the tag
    definition portion server-side so a bad rule doesn't sit in the
    library waiting to fail at apply time."""
    from app.tag_validation import validate_tag_payload
    data = request.json or {}
    tag_payload = _payload_from_tag_form({
        "name": data.get("name"),
        "color": data.get("color"),
        "criticality": data.get("criticality"),
        "rule_type": data.get("rule_type"),
        "rule_text": data.get("rule_text"),
    })
    vresult = validate_tag_payload(tag_payload)
    if not vresult.ok:
        return jsonify({
            "error": "Validation failed",
            "errors": vresult.errors, "warnings": vresult.warnings,
        }), 400

    try:
        new_id = create_library_entry(data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    entry = get_library_entry(new_id)
    return jsonify({"created": True, "library_id": new_id, "entry": entry,
                    "warnings": vresult.warnings})


@app.route("/api/library/<int:library_id>", methods=["PATCH"])
@openapi.validate(
    json=_LibraryEntryWriteRequest,
    resp=OpenApiResponse(HTTP_200=OkMessage, HTTP_400=Error, HTTP_403=Error, HTTP_404=Error),
    tags=[TAG_LIBRARY],
)
def library_update(library_id):
    """Edit a user-authored entry. Built-ins refuse with 403 — caller
    should clone first if they want to customise a built-in."""
    from app.tag_validation import validate_tag_payload
    data = request.json or {}

    existing = get_library_entry(library_id)
    if not existing:
        return jsonify({"error": "Library entry not found"}), 404
    merged = {**existing, **data}
    tag_payload = _payload_from_tag_form({
        "name": merged.get("name"),
        "color": merged.get("color"),
        "criticality": merged.get("criticality"),
        "rule_type": merged.get("rule_type"),
        "rule_text": merged.get("rule_text"),
    })
    vresult = validate_tag_payload(tag_payload)
    if not vresult.ok:
        return jsonify({
            "error": "Validation failed",
            "errors": vresult.errors, "warnings": vresult.warnings,
        }), 400

    try:
        ok = update_library_entry(library_id, data)
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    if not ok:
        return jsonify({"error": "Library entry not found or no fields to update"}), 404
    return jsonify({"updated": True, "library_id": library_id,
                    "entry": get_library_entry(library_id),
                    "warnings": vresult.warnings})


@app.route("/api/library/<int:library_id>", methods=["DELETE"])
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=OkMessage, HTTP_404=Error),
    tags=[TAG_LIBRARY],
)
def library_delete(library_id):
    """Delete a user entry, or hide a built-in. Re-running init_db
    will re-seed built-ins but preserve the is_hidden flag."""
    ok = delete_library_entry(library_id)
    if not ok:
        return jsonify({"error": "Library entry not found"}), 404
    return jsonify({"deleted": True, "library_id": library_id})


@app.route("/api/library/<int:library_id>/unhide", methods=["POST"])
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=OkMessage, HTTP_404=Error),
    tags=[TAG_LIBRARY],
)
def library_unhide(library_id):
    ok = unhide_library_entry(library_id)
    if not ok:
        return jsonify({"error": "Built-in entry not found or not hidden"}), 404
    return jsonify({"unhidden": True, "library_id": library_id})


@app.route("/api/library/<int:library_id>/clone", methods=["POST"])
@openapi.validate(
    json=_LibraryCloneRequest,
    resp=OpenApiResponse(HTTP_200=OkMessage, HTTP_404=Error),
    tags=[TAG_LIBRARY],
)
def library_clone(library_id):
    """Copy an entry into an editable user copy. Convenient for
    customising a built-in without losing the original."""
    data = request.json or {}
    try:
        new_id = clone_library_entry(library_id, new_name=data.get("name") or None)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify({"cloned": True, "library_id": new_id,
                    "entry": get_library_entry(new_id)})


@app.route("/api/library/<int:library_id>/apply", methods=["POST"])
@openapi.validate(
    json=_LibraryApplyRequest,
    resp=OpenApiResponse(HTTP_200=OkMessage, HTTP_400=Error, HTTP_404=Error, HTTP_502=Error),
    tags=[TAG_LIBRARY],
)
def library_apply(library_id):
    """Apply a library entry into a destination Qualys environment.

    Body (JSON):
      credential_id     — destination credential (required)
      platform          — destination Qualys platform region
      new_name          — optional rename
      parent_tag_id     — optional destination parent tag id
      overrides         — optional {rule_text, color, criticality}
                          tweaks for this apply only

    Validates → calls QualysClient.create_tag → refreshes local tags
    table from the destination → records an audit row.
    """
    from app.tag_validation import validate_tag_payload
    entry = get_library_entry(library_id)
    if not entry:
        return jsonify({"error": "Library entry not found"}), 404

    data = request.json or {}
    overrides = data.get("overrides") or {}

    form_shape = {
        "name": data.get("new_name") or entry["name"],
        "color": overrides.get("color") or entry.get("color"),
        "criticality": overrides.get("criticality") if overrides.get("criticality") not in (None, "") else entry.get("criticality"),
        "description": entry.get("description"),
        "rule_type": entry["rule_type"],
        "rule_text": overrides.get("rule_text") if overrides.get("rule_text") is not None else entry.get("rule_text"),
        "parent_tag_id": data.get("parent_tag_id"),
    }
    payload = _payload_from_tag_form(form_shape)

    vresult = validate_tag_payload(payload)
    if not vresult.ok:
        return jsonify({
            "error": "Library entry failed validation against the destination "
                     "before apply. Edit the entry or pass overrides.",
            "errors": vresult.errors, "warnings": vresult.warnings,
        }), 400

    client, error, cred_id = _build_client(data)
    if error:
        return jsonify({"error": error}), 400

    result = client.create_tag(payload, timeout=60)
    if result.get("error"):
        return jsonify({
            "error": result.get("message", "create-tag failed"),
            "status_code": result.get("status_code"),
        }), 502

    new_tag_id = result.get("tag_id")
    new_tag_name = payload.get("name")

    if new_tag_id:
        try:
            detail = client.get_tag_detail(new_tag_id)
            if detail:
                upsert_tag(detail, credential_id=cred_id)
        except Exception as e:
            logger.warning("Post-apply refresh failed for tag %s: %s", new_tag_id, e)

    record_library_apply(
        library_id=library_id,
        destination_credential_id=cred_id,
        destination_platform=data.get("platform"),
        destination_tag_id=new_tag_id,
        destination_tag_name=new_tag_name,
    )

    return jsonify({
        "applied": True,
        "library_id": library_id,
        "destination_tag_id": new_tag_id,
        "destination_tag_name": new_tag_name,
        "warnings": vresult.warnings,
    })


@app.route("/api/library/<int:library_id>/applies", methods=["GET"])
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_LibraryApplyHistoryResponse, HTTP_404=Error),
    tags=[TAG_LIBRARY],
)
def library_apply_history(library_id):
    """Audit log of every successful Apply for this library entry."""
    if not get_library_entry(library_id):
        return jsonify({"error": "Library entry not found"}), 404
    return jsonify(list_library_applies(library_id=library_id))


@app.route("/api/library/applies", methods=["GET"])
@openapi.validate(
    resp=OpenApiResponse(HTTP_200=_LibraryApplyHistoryResponse),
    tags=[TAG_LIBRARY],
)
def library_apply_history_all():
    """Global apply audit log — every Apply across every library
    entry, newest first."""
    return jsonify(list_library_applies())


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Tags Phase 5: Subscription audit
# ═══════════════════════════════════════════════════════════════════════════
# Read-only analysis layer over the locally cached tags table.
# Surfaces hierarchy / naming / classification issues so the operator
# can clean them up before they bite Qualys or downstream consumers.
# Pure-Python rules in app/tag_audit.py — no Qualys API calls.

def _all_tag_rows_for_audit() -> list[dict]:
    """Pull every tag (visible or otherwise) plus the override columns
    so the audit rules see the same row shape as the rest of the app."""
    from app.database import get_db, _apply_tag_overrides
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM tags ORDER BY tag_id"
        ).fetchall()
    return [_apply_tag_overrides(dict(r)) for r in rows]


@app.route("/api/tags/audit", methods=["GET"])
def tags_audit():
    """Run every Phase 5 audit rule over the local tag inventory.

    Returns a grouped + summarised result the UI can render directly:
    severity counts at the top, ordered groups (errors first), each
    with its findings inline.
    """
    from app.tag_audit import run_audit
    rows = _all_tag_rows_for_audit()
    return jsonify(run_audit(rows))


@app.route("/api/tags/audit/<rule_id>", methods=["GET"])
def tags_audit_rule(rule_id):
    """Findings for a single rule_id — handy for the "view all
    duplicates" deep link without re-running every rule client-side."""
    from app.tag_audit import run_audit
    rows = _all_tag_rows_for_audit()
    full = run_audit(rows)
    matched = [g for g in full["groups"] if g["rule_id"] == rule_id]
    if not matched:
        return jsonify({"rule_id": rule_id, "severity": None,
                        "count": 0, "findings": []})
    return jsonify(matched[0])


@app.route("/api/tags/audit.csv", methods=["GET"])
def tags_audit_csv():
    """Export the flat findings list as CSV for offline review or
    ticketing-system import."""
    from app.tag_audit import run_audit
    import csv as _csv
    import io as _io
    rows = _all_tag_rows_for_audit()
    full = run_audit(rows)
    buf = _io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["severity", "rule_id", "tag_id", "name", "message", "hint", "refs"])
    for f in full["findings"]:
        w.writerow([
            f.get("severity", ""),
            f.get("rule_id", ""),
            f.get("tag_id", ""),
            f.get("name", ""),
            f.get("message", ""),
            f.get("hint", "") or "",
            ",".join(str(r) for r in (f.get("refs") or [])),
        ])
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = 'attachment; filename="qkbe-tag-audit.csv"'
    return resp


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Intelligence (filter-aware aggregate counts for the stat strip)
# ═══════════════════════════════════════════════════════════════════════════

class _IntelligenceStatsResponse(BaseModel):
    """Aggregate counts driving the Intelligence tab's stat strip.
    Same filter params as /api/qids — every count reflects the
    user's filter set."""
    total_qids: int = 0
    kb_patchable: int = 0
    pm_any: int = 0
    pm_win: int = 0
    pm_lin: int = 0
    pci: int = 0
    sev_5: int = 0
    sev_4: int = 0
    sev_3: int = 0
    sev_2: int = 0
    sev_1: int = 0
    with_cve: int = 0


@app.route("/api/intelligence/stats")
@openapi.validate(
    query=_QidSearchQuery,  # same filter shape as /api/qids
    resp=OpenApiResponse(HTTP_200=_IntelligenceStatsResponse, HTTP_500=Error),
    tags=[TAG_INTEL],
)
def intelligence_stats():
    """Aggregate counts that respect the same filter params as
    /api/qids. Used by the Intelligence tab's stat strip.

    Implementation note: this used to run 11 separate search_vulns
    calls (one per dimension), each rebuilding the entire filtered
    set + JOINs from scratch on a 200K+-row table — easily blew past
    the frontend's 30s fetch timeout under realistic data volumes.
    Now runs a single conditional-aggregate query against a CTE that
    materialises the filtered base once.
    """
    from app.database import aggregate_qid_intelligence_stats
    try:
        filters = _parse_qid_filters()
        return jsonify(aggregate_qid_intelligence_stats(filters))
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Routes — PM Patch Catalog (Qualys Patch Management via Gateway)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/pm/stats")
def pm_stats():
    """Aggregate PM patch counts (total / Win / Lin / QIDs covered)."""
    try:
        return jsonify(pm_patch_stats())
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/qids/<int:qid>/patches")
def qid_patches(qid):
    """Return PM patches associated with a specific QID."""
    try:
        patches = get_pm_patches_for_qid(qid)
        flags = get_pm_patch_qid_flags(qid)
        return jsonify({"qid": qid, "patches": patches, **flags})
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Dashboard & Analytics
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/dashboard/stats")
def dashboard_stats():
    """Aggregated statistics for the Dashboard tab."""
    try:
        stats = get_dashboard_stats()
        # Add database health info
        from app.database import DB_PATH, get_maintenance_config
        from app.maintenance import get_backup_info
        import os
        db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
        maint = get_maintenance_config()
        backup = get_backup_info()
        stats["db_health"] = {
            "size": db_size,
            "last_maintenance": maint.get("last_run"),
            "last_status": maint.get("last_status"),
            "last_duration_s": maint.get("last_duration_s"),
            "last_error": maint.get("last_error"),
            "backup_size": backup["size"] if backup else None,
            "backup_date": backup["modified"] if backup else None,
        }
        return jsonify(stats)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Export (CSV & PDF)
# ═══════════════════════════════════════════════════════════════════════════

def _csv_response(rows, headers, filename):
    """Build a CSV file download response."""
    si = io.StringIO()
    w = csv.writer(si)
    w.writerow(headers)
    w.writerows(rows)
    resp = make_response(si.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


def _strip_html(text: str) -> str:
    """Strip HTML tags from text, preserving link URLs and converting breaks to newlines."""
    if not text:
        return ""
    import re
    # Convert <a href="URL">text</a> → text (URL) to preserve patch/remediation links
    text = re.sub(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                  r'\2 (\1)', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<br\s*/?>',  '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</p>',       '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>',    '',   text)
    text = re.sub(r'\n{3,}',     '\n\n', text)
    return text.strip()


def _pdf_response(title, headers, rows, filename):
    """Build a PDF table download response using reportlab with word wrap."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from datetime import datetime

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter),
                            leftMargin=0.4 * inch, rightMargin=0.4 * inch,
                            topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    styles = getSampleStyleSheet()

    elements = []

    # Title
    elements.append(Paragraph(title, styles["Title"]))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — {len(rows)} records",
        styles["Normal"]))
    elements.append(Spacer(1, 12))

    # Column classification for width and truncation
    _WIDE_COLS = {"Title", "Diagnosis", "Solution", "Statement", "Technologies",
                  "CVEs", "Linked Policies", "Category", "Sub-Category"}
    _MEDIUM_COLS = {"Supported Modules", "Bugtraqs", "Check Type", "Description"}

    # Build table data — truncate cell text to fit column widths
    def _trunc(val, maxlen=60):
        s = str(val) if val is not None else ""
        s = s.replace("\n", " ").replace("\r", "")
        return s[:maxlen] + "..." if len(s) > maxlen else s

    char_limits = []
    for h in headers:
        if h in _WIDE_COLS:
            char_limits.append(120)
        elif h in _MEDIUM_COLS:
            char_limits.append(80)
        else:
            char_limits.append(40)

    table_data = [headers]
    for row in rows:
        table_data.append([_trunc(v, char_limits[i]) for i, v in enumerate(row)])

    # Smart column widths — assign more space to text-heavy columns
    avail_width = landscape(letter)[0] - 0.8 * inch
    weights = []
    for h in headers:
        if h in _WIDE_COLS:
            weights.append(3.0)
        elif h in _MEDIUM_COLS:
            weights.append(1.8)
        else:
            weights.append(1.0)
    total_w = sum(weights)
    col_widths = [(w / total_w) * avail_width for w in weights]

    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2a2f3e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d4dc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f5f7")]),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ])
    t.setStyle(style)
    elements.append(t)

    doc.build(elements)
    buf.seek(0)
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


def _parse_qid_filters():
    """Parse QID filter params from request.args (shared by search and export)."""
    cve_param = request.args.get("cve", "")
    cves = [c.strip() for c in cve_param.split(",") if c.strip()] if cve_param else None
    cat_param = request.args.get("category", "")
    categories = [c.strip() for c in cat_param.split(",") if c.strip()] if cat_param else None
    p_val = request.args.get("patchable", "")
    patchable = True if p_val == "1" else (False if p_val == "0" else None)
    # Advanced filters
    pci_val = request.args.get("pci_flag", "")
    pci_flag = True if pci_val == "1" else (False if pci_val == "0" else None)
    rti_param = request.args.get("rti", "")
    rti_indicators = [r.strip() for r in rti_param.split(",") if r.strip()] if rti_param else None
    mod_param = request.args.get("supported_modules", "")
    supported_modules = [m.strip() for m in mod_param.split(",") if m.strip()] if mod_param else None
    # Multi-select severity (comma-separated). Falls through to single severity if missing.
    sev_param = request.args.get("severities", "")
    severities = []
    if sev_param:
        for s in sev_param.split(","):
            s = s.strip()
            try:
                if s:
                    severities.append(int(s))
            except ValueError:
                pass
    severities = severities or None
    # Exclude severities (negated)
    exc_sev_param = request.args.get("exclude_severities", "")
    exclude_severities = []
    if exc_sev_param:
        for s in exc_sev_param.split(","):
            s = s.strip()
            try:
                if s:
                    exclude_severities.append(int(s))
            except ValueError:
                pass
    exclude_severities = exclude_severities or None
    # Multi-select vuln types
    vt_param = request.args.get("vuln_types", "")
    vuln_types = [v.strip() for v in vt_param.split(",") if v.strip()] if vt_param else None
    # PM / Threat filters: '1' = include, '0' = exclude (NOT), absent = no filter
    def _bool_filter(param):
        v = request.args.get(param, "")
        if v == "1": return True
        if v == "0": return False
        return None
    pm_any = _bool_filter("pm_any")
    pm_win = _bool_filter("pm_win")
    pm_lin = _bool_filter("pm_lin")
    threat_active = _bool_filter("threat_active")
    threat_cisa_kev = _bool_filter("threat_cisa_kev")
    threat_exploit_public = _bool_filter("threat_exploit_public")
    threat_rce = _bool_filter("threat_rce")
    threat_malware = _bool_filter("threat_malware")
    has_exploits = _bool_filter("has_exploits")
    # Disabled status: '1' = only disabled, '0' = only enabled,
    # absent/'' = no filter (show both). The default behaviour matches
    # 'show both' so the count badge reflects the full DB.
    d_val = request.args.get("disabled", "")
    if d_val == "1":
        disabled = True
    elif d_val == "0":
        disabled = False
    else:
        disabled = None
    # Exclude category/text (negated filters)
    exclude_cat = request.args.get("exclude_category", "").strip()
    exclude_categories = [exclude_cat] if exclude_cat else None
    exclude_q = request.args.get("exclude_q", "").strip()
    return {
        "q": request.args.get("q", ""),
        "exclude_q": exclude_q or None,
        "cves": cves,
        "cve_mode": request.args.get("cve_mode", "or"),
        "severity": int(request.args["severity"]) if request.args.get("severity") else None,
        "severities": severities,
        "categories": categories,
        "exclude_categories": exclude_categories,
        "patchable": patchable,
        "vuln_type": request.args.get("vuln_type", "") or None,
        "vuln_types": vuln_types,
        "cvss_base_min": float(request.args["cvss_base_min"]) if request.args.get("cvss_base_min") else None,
        "cvss3_base_min": float(request.args["cvss3_base_min"]) if request.args.get("cvss3_base_min") else None,
        "published_after": request.args.get("published_after", "") or None,
        "modified_after": request.args.get("modified_after", "") or None,
        "pci_flag": pci_flag,
        "discovery_method": request.args.get("discovery_method", "") or None,
        "rti_indicators": rti_indicators,
        "supported_modules": supported_modules,
        "pm_any": pm_any,
        "pm_win": pm_win,
        "pm_lin": pm_lin,
        "threat_active": threat_active,
        "threat_cisa_kev": threat_cisa_kev,
        "threat_exploit_public": threat_exploit_public,
        "threat_rce": threat_rce,
        "threat_malware": threat_malware,
        "has_exploits": has_exploits,
        "exclude_severities": exclude_severities,
        "disabled": disabled,
    }


def _parse_cid_filters():
    """Parse CID filter params from request.args."""
    cat_param = request.args.get("category", "")
    categories = [c.strip() for c in cat_param.split(",") if c.strip()] if cat_param else None
    tech_param = request.args.get("technology", "")
    technologies = [t.strip() for t in tech_param.split(",") if t.strip()] if tech_param else None
    return {
        "q": request.args.get("q", ""),
        "categories": categories,
        "criticality": request.args.get("criticality", "") or None,
        "technologies": technologies,
        "technology_mode": request.args.get("technology_mode", "or"),
    }


def _parse_policy_filters():
    """Parse Policy filter params from request.args."""
    cc_param = request.args.get("control_category", "")
    control_categories = [c.strip() for c in cc_param.split(",") if c.strip()] if cc_param else None
    tech_param = request.args.get("technology", "")
    technologies = [t.strip() for t in tech_param.split(",") if t.strip()] if tech_param else None
    cid_param = request.args.get("cid", "")
    cids = [int(c.strip().split(" ")[0]) for c in cid_param.split(",") if c.strip()] if cid_param else None
    return {
        "q": request.args.get("q", ""),
        "status": request.args.get("status", ""),
        "control_categories": control_categories,
        "control_category_mode": request.args.get("control_category_mode", "or"),
        "technologies": technologies,
        "technology_mode": request.args.get("technology_mode", "or"),
        "cids": cids,
        "cid_mode": request.args.get("cid_mode", "or"),
        "control_name": request.args.get("control_name", ""),
    }


def _parse_mandate_filters():
    """Parse Mandate filter params from request.args."""
    pub_param = request.args.get("publisher", "")
    publishers = [p.strip() for p in pub_param.split(",") if p.strip()] if pub_param else None
    return {
        "q": request.args.get("q", ""),
        "publishers": publishers,
    }


# ─── CSV Export Routes ─────────────────────────────────────────────────────

@app.route("/api/export/qids/csv")
def export_qids_csv():
    """Export QIDs matching current filters to CSV."""
    try:
        filters = _parse_qid_filters()
        data = search_vulns(**filters, page=1, per_page=100000)
        headers = ["QID", "Title", "Severity", "Category", "Patchable",
                    "CVE Count", "CVSS Base", "CVSS3 Base", "Published", "Modified",
                    "Supported Modules"]
        rows = []
        for r in data["results"]:
            rows.append([
                r.get("qid"), r.get("title"), r.get("severity_level"),
                r.get("category"), "Yes" if r.get("patchable") else "No",
                r.get("cve_count", 0), r.get("cvss_base"), r.get("cvss3_base"),
                r.get("published_datetime"), r.get("last_service_modification_datetime"),
                r.get("supported_modules", ""),
            ])
        return _csv_response(rows, headers, "qkbe-qids-export.csv")
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/export/cids/csv")
def export_cids_csv():
    """Export CIDs matching current filters to CSV."""
    try:
        filters = _parse_cid_filters()
        data = search_controls(**filters, page=1, per_page=100000)
        headers = ["CID", "Statement", "Category", "Sub-Category", "Criticality", "Check Type"]
        rows = []
        for r in data["results"]:
            rows.append([
                r.get("cid"), r.get("statement"), r.get("category"),
                r.get("sub_category"), r.get("criticality_label"), r.get("check_type"),
            ])
        return _csv_response(rows, headers, "qkbe-cids-export.csv")
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/export/policies/csv")
def export_policies_csv():
    """Export Policies matching current filters to CSV."""
    try:
        filters = _parse_policy_filters()
        data = search_policies(**filters, page=1, per_page=100000)
        headers = ["Policy ID", "Title", "Status", "Control Count", "Created", "Last Modified"]
        rows = []
        for r in data["results"]:
            rows.append([
                r.get("policy_id"), r.get("title"), r.get("status"),
                r.get("control_count", 0), r.get("created_datetime"),
                r.get("last_modified_datetime"),
            ])
        return _csv_response(rows, headers, "qkbe-policies-export.csv")
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/export/mandates/csv")
def export_mandates_csv():
    """Export Mandates matching current filters to CSV."""
    try:
        filters = _parse_mandate_filters()
        data = search_mandates(**filters, page=1, per_page=100000)
        headers = ["Mandate ID", "Title", "Publisher", "Version",
                    "Control Count", "Released", "Last Modified"]
        rows = []
        for r in data["results"]:
            rows.append([
                r.get("mandate_id"), r.get("title"), r.get("publisher"),
                r.get("version"), r.get("control_count", 0),
                r.get("released_date"), r.get("last_modified_date"),
            ])
        return _csv_response(rows, headers, "qkbe-mandates-export.csv")
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/export/mandate-map/csv")
def export_mandate_map_csv():
    """Export flattened mandate → control → policy compliance mapping."""
    try:
        mid = request.args.get("mandate_id")
        mandate_id = int(mid) if mid else None
        mapping = get_mandate_compliance_map(mandate_id)
        headers = ["Mandate ID", "Mandate Title", "Publisher", "Section ID",
                    "Section Title", "CID", "Control Statement", "Criticality",
                    "Policy ID", "Policy Title"]
        rows = []
        for r in mapping:
            rows.append([
                r.get("mandate_id"), r.get("mandate_title"), r.get("publisher"),
                r.get("section_id"), r.get("section_title"),
                r.get("cid"), r.get("statement"), r.get("criticality_label"),
                r.get("policy_id"), r.get("policy_title"),
            ])
        return _csv_response(rows, headers, "qkbe-mandate-compliance-map.csv")
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ─── PDF Export Routes ─────────────────────────────────────────────────────

@app.route("/api/export/qids/pdf")
def export_qids_pdf():
    """Export QIDs matching current filters to PDF."""
    try:
        filters = _parse_qid_filters()
        data = search_vulns(**filters, page=1, per_page=100000)
        headers = ["QID", "Title", "Sev", "Category", "Patch",
                    "CVEs", "CVSS", "CVSS3"]
        rows = []
        for r in data["results"]:
            rows.append([
                r.get("qid"), (r.get("title") or "")[:80],
                r.get("severity_level"), (r.get("category") or "")[:30],
                "Y" if r.get("patchable") else "N",
                r.get("cve_count", 0), r.get("cvss_base"), r.get("cvss3_base"),
            ])
        return _pdf_response("Q KB Explorer — QID Export", headers, rows,
                             "qkbe-qids-export.pdf")
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/export/cids/pdf")
def export_cids_pdf():
    """Export CIDs matching current filters to PDF."""
    try:
        filters = _parse_cid_filters()
        data = search_controls(**filters, page=1, per_page=100000)
        headers = ["CID", "Statement", "Category", "Criticality"]
        rows = []
        for r in data["results"]:
            rows.append([
                r.get("cid"), (r.get("statement") or "")[:100],
                (r.get("category") or "")[:30], r.get("criticality_label"),
            ])
        return _pdf_response("Q KB Explorer — CID Export", headers, rows,
                             "qkbe-cids-export.pdf")
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/export/policies/pdf")
def export_policies_pdf():
    """Export Policies matching current filters to PDF."""
    try:
        filters = _parse_policy_filters()
        data = search_policies(**filters, page=1, per_page=100000)
        headers = ["Policy ID", "Title", "Status", "Controls", "Last Modified"]
        rows = []
        for r in data["results"]:
            rows.append([
                r.get("policy_id"), (r.get("title") or "")[:80],
                r.get("status"), r.get("control_count", 0),
                r.get("last_modified_datetime"),
            ])
        return _pdf_response("Q KB Explorer — Policy Export", headers, rows,
                             "qkbe-policies-export.pdf")
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/export/mandates/pdf")
def export_mandates_pdf():
    """Export Mandates matching current filters to PDF."""
    try:
        filters = _parse_mandate_filters()
        data = search_mandates(**filters, page=1, per_page=100000)
        headers = ["Mandate ID", "Title", "Publisher", "Version", "Controls"]
        rows = []
        for r in data["results"]:
            rows.append([
                r.get("mandate_id"), (r.get("title") or "")[:80],
                (r.get("publisher") or "")[:30], r.get("version"),
                r.get("control_count", 0),
            ])
        return _pdf_response("Q KB Explorer — Mandate Export", headers, rows,
                             "qkbe-mandates-export.pdf")
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ── OpenAPI / Swagger UI mount ─────────────────────────────────────
# Must run *after* every @app.route is declared so SpecTree captures
# the full route set. Mounts:
#   /api/docs/swagger/      → Swagger UI
#   /api/docs/redoc/        → ReDoc
#   /api/docs/scalar/       → Scalar (modern alt UI)
#   /api/docs/openapi.json  → raw OpenAPI 3 spec
openapi.register(app)


@app.route("/api/docs")
def api_docs_index():
    """Friendly redirect from /api/docs to the Swagger UI."""
    from flask import redirect
    return redirect("/api/docs/swagger/", code=302)
