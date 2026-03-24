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
)
from app.qualys_client import QualysClient
from app.sync import SyncEngine
from app.sync_log import create_sync_log, get_sync_log, get_sync_history
from app.scheduler import init_scheduler, add_schedule, remove_schedule, get_schedule_info

logger = logging.getLogger(__name__)

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=[])

# Initialize SQLite on startup
with app.app_context():
    init_db()
    resolved = resolve_policy_control_cids()
    if resolved:
        logger.info("Resolved %d policy control CIDs on startup", resolved)
    init_scheduler(app)

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


@app.route("/api/platforms")
def get_platforms():
    return jsonify(QUALYS_PLATFORMS)


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
        return jsonify(result)
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

@app.route("/api/sync/status")
def sync_status():
    """Return sync watermarks for all data types."""
    try:
        status = get_sync_status()
        # Add active sync info
        for dtype in ("qids", "cids", "policies", "mandates"):
            if dtype not in status:
                status[dtype] = {"last_sync": None, "last_full_sync": None, "record_count": 0}
            thread = _active_syncs.get(dtype)
            status[dtype]["syncing"] = thread is not None and thread.is_alive()
            status[dtype]["needs_full_refresh"] = SyncEngine.needs_full_refresh(dtype)
        return jsonify(status)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/sync/<data_type>", methods=["POST"])
def trigger_sync(data_type):
    """Trigger a sync for qids, cids, or policies."""
    if data_type not in ("qids", "cids", "policies", "mandates"):
        return jsonify({"error": "Invalid data type. Use: qids, cids, policies"}), 400

    # Check if already syncing
    thread = _active_syncs.get(data_type)
    if thread and thread.is_alive():
        return jsonify({"error": f"{data_type} sync already in progress"}), 409

    data = request.json or {}
    full = data.get("full", False)

    client, error, cred_id = _build_client(data)
    if error:
        return jsonify({"error": error}), 400

    # Create structured sync log
    endpoints = {"qids": "/api/4.0/fo/knowledge_base/vuln/", "cids": "/api/4.0/fo/compliance/control/", "policies": "/api/4.0/fo/compliance/policy/", "mandates": "/api/4.0/fo/compliance/control/"}
    sync_log = create_sync_log(data_type, full, client.api_base, endpoints[data_type])
    client.sync_log = sync_log  # Attach to client for HTTP-level logging

    def on_progress(info):
        _sync_progress[data_type] = {**info, "running": True}

    def run_sync():
        try:
            # Purge existing data before full sync so tenant switches start clean
            if full:
                try:
                    purge_data(data_type)
                    sync_log.event("DATA_PURGED", {"data_type": data_type})
                except Exception as e:
                    logger.error("Purge failed for %s: %s", data_type, e)
                    sync_log.finish_error(f"Purge failed: {e}")
                    _sync_progress[data_type] = {"type": data_type, "error": f"Purge failed: {e}"}
                    return

            engine = SyncEngine(client, credential_id=cred_id, on_progress=on_progress, sync_log=sync_log)
            method = {"qids": engine.sync_qids, "cids": engine.sync_cids, "policies": engine.sync_policies, "mandates": engine.sync_mandates}[data_type]
            result = method(full=full)
            _sync_progress[data_type] = result
        except Exception as e:
            logger.exception("Sync %s failed", data_type)
            sync_log.finish_error(str(e))
            _sync_progress[data_type] = {"type": data_type, "error": str(e)}
        finally:
            _active_syncs.pop(data_type, None)

    thread = threading.Thread(target=run_sync, daemon=True)
    _active_syncs[data_type] = thread
    _sync_progress[data_type] = {"type": data_type, "status": "started"}
    thread.start()

    return jsonify({"started": True, "type": data_type, "full": full})


@app.route("/api/sync/<data_type>/progress")
def sync_progress(data_type):
    """Get progress of the last sync for a data type."""
    if data_type not in ("qids", "cids", "policies", "mandates"):
        return jsonify({"error": "Invalid data type"}), 400
    thread = _active_syncs.get(data_type)
    running = thread is not None and thread.is_alive()
    progress = _sync_progress.get(data_type, {})
    progress["running"] = running
    return jsonify(progress)


@app.route("/api/sync/<data_type>/log")
def sync_log_endpoint(data_type):
    """Get the full diagnostic sync log for a data type."""
    if data_type not in ("qids", "cids", "policies", "mandates"):
        return jsonify({"error": "Invalid data type"}), 400
    log = get_sync_log(data_type)
    if not log:
        return jsonify({"error": "No sync log available. Run a sync first."}), 404
    fmt = request.args.get("format", "text")
    if fmt == "json":
        return jsonify(log.to_dict())
    # Default: return pre-rendered text for copy/paste
    return jsonify({"text": log.render_text()})


@app.route("/api/sync/<data_type>/history")
def sync_history_endpoint(data_type):
    """Get the last 20 sync logs for a data type."""
    if data_type not in ("qids", "cids", "policies", "mandates"):
        return jsonify({"error": "Invalid data type"}), 400
    history = get_sync_history(data_type, limit=20)
    return jsonify(history)


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Schedules
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/schedules")
def list_schedules():
    """List all active sync schedules."""
    try:
        return jsonify(get_schedule_info())
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/schedules/<data_type>", methods=["POST"])
def create_schedule(data_type):
    """Create or update a sync schedule."""
    if data_type not in ("qids", "cids", "policies", "mandates"):
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
def delete_schedule_route(data_type):
    """Delete a sync schedule."""
    if data_type not in ("qids", "cids", "policies", "mandates"):
        return jsonify({"error": "Invalid data type"}), 400
    removed = remove_schedule(data_type)
    return jsonify({"ok": True, "removed": removed})


# ═══════════════════════════════════════════════════════════════════════════
# Routes — QIDs (Knowledge Base)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/qids")
def qids_search():
    """Search QIDs with FTS + filters + pagination."""
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


@app.route("/api/qids/filter-values")
def qid_filter_values():
    """Get distinct filter values for QID multi-select dropdowns."""
    try:
        field = request.args.get("field", "")
        q = request.args.get("q", "")
        return jsonify(get_qid_filter_values(field, q))
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/qids/<int:qid>")
def qids_detail(qid):
    """Get full QID detail with CVEs, bugtraqs, vendor refs."""
    try:
        vuln = get_vuln(qid)
        if not vuln:
            return jsonify({"error": "QID not found"}), 404
        return jsonify(vuln)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Routes — CIDs (Compliance Controls)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/cids")
def cids_search():
    """Search CIDs with FTS + filters + pagination."""
    try:
        # Parse multi-value filters (comma-separated)
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
def cid_filter_values():
    """Get distinct filter values for CID multi-select dropdowns."""
    try:
        field = request.args.get("field", "")
        q = request.args.get("q", "")
        return jsonify(get_cid_filter_values(field, q))
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/cids/<int:cid>")
def cids_detail(cid):
    """Get full CID detail with technologies and linked policies."""
    try:
        control = get_control(cid)
        if not control:
            return jsonify({"error": "CID not found"}), 404
        return jsonify(control)
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Routes — Policies
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/policies")
def policies_search():
    """Search policies with filters + pagination."""
    try:
        # Parse multi-value filters (comma-separated)
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
def delete_policies_route():
    """Delete one or more policies by ID."""
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
def policy_filter_values():
    """Get distinct filter values for Policy multi-select dropdowns."""
    try:
        field = request.args.get("field", "")
        q = request.args.get("q", "")
        return jsonify(get_policy_filter_values(field, q))
    except Exception:
        logger.exception("Request failed: %s %s", request.method, request.path)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/policies/<int:policy_id>")
def policies_detail(policy_id):
    """Get full policy detail with linked controls."""
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
# Routes — Dashboard & Analytics
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/dashboard/stats")
def dashboard_stats():
    """Aggregated statistics for the Dashboard tab."""
    try:
        return jsonify(get_dashboard_stats())
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


def _pdf_response(title, headers, rows, filename):
    """Build a PDF table download response using reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from datetime import datetime

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter),
                            leftMargin=0.5 * inch, rightMargin=0.5 * inch,
                            topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph(title, styles["Title"]))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — {len(rows)} records",
                              styles["Normal"]))
    elements.append(Spacer(1, 12))

    # Table
    table_data = [headers] + [[str(v) if v is not None else "" for v in row] for row in rows]

    # Calculate column widths proportionally
    avail_width = landscape(letter)[0] - 1 * inch
    col_width = avail_width / len(headers)
    col_widths = [col_width] * len(headers)

    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2a2f3e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d4dc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f5f7")]),
        ("WORDWRAP", (0, 0), (-1, -1), True),
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
    return {
        "q": request.args.get("q", ""),
        "cves": cves,
        "cve_mode": request.args.get("cve_mode", "or"),
        "severity": int(request.args["severity"]) if request.args.get("severity") else None,
        "categories": categories,
        "patchable": patchable,
        "vuln_type": request.args.get("vuln_type", "") or None,
        "cvss_base_min": float(request.args["cvss_base_min"]) if request.args.get("cvss_base_min") else None,
        "cvss3_base_min": float(request.args["cvss3_base_min"]) if request.args.get("cvss3_base_min") else None,
        "published_after": request.args.get("published_after", "") or None,
        "modified_after": request.args.get("modified_after", "") or None,
        "pci_flag": pci_flag,
        "discovery_method": request.args.get("discovery_method", "") or None,
        "rti_indicators": rti_indicators,
        "supported_modules": supported_modules,
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
