"""
Q KB Explorer — Sync Engine
Built by netsecops-76

Handles full and delta synchronization of QIDs, CIDs, and Policies
from Qualys v2 API into local SQLite database.
"""

from __future__ import annotations

import gc
import logging
from datetime import datetime, timedelta

from app.qualys_client import QualysClient, _ensure_list, _deep_find
from app.database import (
    upsert_vuln,
    upsert_control,
    upsert_policy,
    upsert_mandate,
    upsert_mandate_control,
    extract_mandates_from_control,
    get_last_sync_datetime,
    update_sync_state,
    get_mandate_stats,
)

logger = logging.getLogger(__name__)


def _sanitize_watermark(ts: str | None) -> str | None:
    """Strip microseconds from a stored watermark so Qualys accepts it.

    Qualys APIs reject ISO timestamps with microsecond precision
    (e.g. 2026-02-27T03:49:39.582249Z). This normalises to seconds.
    """
    if not ts:
        return ts
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, AttributeError):
        return ts

# Monthly full refresh threshold (days)
FULL_REFRESH_DAYS = 30


class SyncEngine:
    """Orchestrates data sync from Qualys API to local SQLite."""

    def __init__(self, client: QualysClient, credential_id: str | None = None,
                 on_progress: callable = None, sync_log = None):
        self.client = client
        self.credential_id = credential_id
        self.on_progress = on_progress  # callback(info_dict) for live updates
        self.sync_log = sync_log        # SyncLog instance for diagnostics

    # ═══════════════════════════════════════════════════════════════════════
    # QID Sync
    # ═══════════════════════════════════════════════════════════════════════

    # QID ID-range chunking: the KB API doesn't support truncation_limit.
    # A full sync returns ~1.5GB in one response → OOM.  We break it into
    # chunks of CHUNK_SIZE QIDs using id_min/id_max so each response is
    # ~40-80 MB — safely parseable in memory.
    QID_CHUNK_SIZE = 10000
    QID_MAX_ID = 600000       # Upper bound — scan stops earlier via consecutive-empty check
    QID_EMPTY_STOP = 5        # Stop after N consecutive empty chunks

    def sync_qids(self, full: bool = False) -> dict:
        """Sync Knowledge Base vulnerabilities.

        Full sync uses id_min/id_max chunking to avoid 1.5 GB single responses.
        Delta sync uses a single request (small result set).

        Args:
            full: If True, do a full sync. Otherwise delta from last watermark.
        Returns:
            Summary dict with counts and any errors.
        """
        base_params = {
            "action": "list",
            "details": "All",
            "show_supported_modules_info": "1",
        }

        watermark = None if full else _sanitize_watermark(get_last_sync_datetime("qids"))
        if watermark:
            base_params["last_modified_by_service_after"] = watermark
            logger.info("QID delta sync from %s", watermark)
        else:
            full = True
            logger.info("QID full sync (chunked, %d QIDs/chunk)", self.QID_CHUNK_SIZE)

        if self.sync_log:
            self.sync_log.event("SYNC_PARAMS", {
                "params": base_params,
                "watermark": watermark,
                "mode": "full" if full else "delta",
                "chunked": full,
                "chunk_size": self.QID_CHUNK_SIZE if full else None,
            })

        total_vulns = 0
        total_pages = 0
        all_errors = []

        def on_page(page_num: int, data: dict) -> int:
            nonlocal total_vulns, total_pages
            total_pages += 1
            response = _deep_find(data, "VULN_LIST") or {}
            vulns = _ensure_list(response.get("VULN") if isinstance(response, dict) else None)
            top_keys = list(data.keys()) if isinstance(data, dict) else [str(type(data))]
            for vuln in vulns:
                if isinstance(vuln, dict):
                    upsert_vuln(vuln)
                    total_vulns += 1
            logger.info("QID page: %d vulns (total: %d)", len(vulns), total_vulns)
            if self.sync_log:
                self.sync_log.event("PAGE_PROCESSED", {
                    "items_on_page": len(vulns),
                    "total_so_far": total_vulns,
                    "top_keys": top_keys,
                    "target_list_found": response is not None and response != {},
                })
            if self.on_progress:
                self.on_progress({
                    "type": "qids", "status": "syncing",
                    "items_synced": total_vulns, "page_items": len(vulns),
                    "pages_fetched": total_pages,
                })
            gc.collect()
            return len(vulns)

        if full:
            # ── Full sync: chunked by ID range ──────────────────────────
            consecutive_empty = 0

            for id_min in range(0, self.QID_MAX_ID, self.QID_CHUNK_SIZE):
                if consecutive_empty >= self.QID_EMPTY_STOP:
                    break

                id_max = id_min + self.QID_CHUNK_SIZE - 1
                chunk_params = {
                    **base_params,
                    "id_min": str(id_min),
                    "id_max": str(id_max),
                }

                if self.sync_log:
                    self.sync_log.event("CHUNK_START", {
                        "id_min": id_min,
                        "id_max": id_max,
                    })

                result = self.client.execute_all_pages(
                    "/api/4.0/fo/knowledge_base/vuln/",
                    params=chunk_params,
                    on_page=on_page,
                    timeout=120,  # Smaller chunks need less time
                )

                chunk_items = result.get("total_items", 0)

                if result.get("errors"):
                    all_errors.extend(result["errors"])
                    if self.sync_log:
                        self.sync_log.event("CHUNK_ERROR", {
                            "id_min": id_min,
                            "id_max": id_max,
                            "errors": result["errors"],
                        })
                    break

                if chunk_items == 0:
                    consecutive_empty += 1
                else:
                    consecutive_empty = 0

                if self.sync_log:
                    self.sync_log.event("CHUNK_COMPLETE", {
                        "id_min": id_min,
                        "id_max": id_max,
                        "items": chunk_items,
                        "total_so_far": total_vulns,
                    })
        else:
            # ── Delta sync: single request (typically small) ────────────
            result = self.client.execute_all_pages(
                "/api/4.0/fo/knowledge_base/vuln/",
                params=base_params,
                on_page=on_page,
                timeout=600,
            )
            if result.get("errors"):
                all_errors.extend(result["errors"])

        summary = {
            "items_synced": total_vulns,
            "pages_fetched": total_pages,
            "errors": all_errors,
        }

        if not all_errors:
            update_sync_state("qids", is_full=full, credential_id=self.credential_id)
            if self.sync_log:
                self.sync_log.finish(summary)
        else:
            if self.sync_log:
                self.sync_log.finish_error("; ".join(all_errors))

        return {
            "type": "qids",
            "full": full,
            **summary,
            "rate_limits": getattr(self.client, "rate_limits", {}),
        }

    # ═══════════════════════════════════════════════════════════════════════
    # CID Sync
    # ═══════════════════════════════════════════════════════════════════════

    def sync_cids(self, full: bool = False) -> dict:
        """Sync Compliance Controls.

        Args:
            full: If True, do a full sync. Otherwise delta from last watermark.
        """
        params = {
            "action": "list",
            "details": "All",
            "truncation_limit": "3000",
        }

        watermark = None if full else _sanitize_watermark(get_last_sync_datetime("cids"))
        if watermark:
            params["updated_after_datetime"] = watermark
            logger.info("CID delta sync from %s", watermark)
        else:
            full = True
            logger.info("CID full sync")

        if self.sync_log:
            self.sync_log.event("SYNC_PARAMS", {"params": params, "watermark": watermark, "mode": "full" if full else "delta"})

        total_controls = 0

        def on_page(page_num: int, data: dict) -> int:
            nonlocal total_controls
            response = _deep_find(data, "CONTROL_LIST") or {}
            controls = _ensure_list(response.get("CONTROL") if isinstance(response, dict) else None)
            top_keys = list(data.keys()) if isinstance(data, dict) else [str(type(data))]
            page_total = len(controls)
            # Report that we received the page and are now processing
            if self.on_progress:
                self.on_progress({"type": "cids", "status": "processing", "items_synced": total_controls, "page_items": page_total, "pages_fetched": page_num, "processing_item": 0, "processing_total": page_total})
            for i, control in enumerate(controls):
                if isinstance(control, dict):
                    upsert_control(control)
                    total_controls += 1
                    # Log first control keys for mandate/framework discovery
                    if total_controls == 1 and self.sync_log:
                        self.sync_log.event("CONTROL_KEYS_DISCOVERY", {
                            "keys": list(control.keys()),
                            "has_FRAMEWORK_LIST": "FRAMEWORK_LIST" in control,
                            "has_MANDATE_LIST": "MANDATE_LIST" in control,
                        })
                    # Per-control progress every 50 controls
                    if self.on_progress and (i + 1) % 50 == 0:
                        self.on_progress({"type": "cids", "status": "processing", "items_synced": total_controls, "page_items": page_total, "pages_fetched": page_num, "processing_item": i + 1, "processing_total": page_total})
            logger.info("CID page %d: %d controls (total: %d)", page_num, len(controls), total_controls)
            if self.sync_log:
                self.sync_log.event("PAGE_PROCESSED", {"page": page_num, "items_on_page": len(controls), "total_so_far": total_controls, "top_keys": top_keys, "target_list_found": response is not None and response != {}})
            if self.on_progress:
                self.on_progress({"type": "cids", "status": "syncing", "items_synced": total_controls, "page_items": page_total, "pages_fetched": page_num})
            gc.collect()
            return len(controls)

        result = self.client.execute_all_pages("/api/4.0/fo/compliance/control/", params=params, on_page=on_page, timeout=300)

        summary = {"items_synced": total_controls, "pages_fetched": result.get("pages_fetched", 0), "errors": result.get("errors", [])}
        if not result.get("errors"):
            update_sync_state("cids", is_full=full, credential_id=self.credential_id)
            if self.sync_log: self.sync_log.finish(summary)
        else:
            if self.sync_log: self.sync_log.finish_error("; ".join(result["errors"]))

        return {"type": "cids", "full": full, **summary, "rate_limits": result.get("rate_limits", {}), "first_response_snippet": result.get("first_response_snippet")}

    # ═══════════════════════════════════════════════════════════════════════
    # Policy Sync
    # ═══════════════════════════════════════════════════════════════════════

    def sync_policies(self, full: bool = False) -> dict:
        """Sync Policy Compliance policies.

        Args:
            full: If True, do a full sync. Otherwise delta from last watermark.
        """
        params = {
            "action": "list",
            "details": "All",
        }

        watermark = None if full else _sanitize_watermark(get_last_sync_datetime("policies"))
        if watermark:
            params["updated_after_datetime"] = watermark
            logger.info("Policy delta sync from %s", watermark)
        else:
            full = True
            logger.info("Policy full sync")

        if self.sync_log:
            self.sync_log.event("SYNC_PARAMS", {"params": params, "watermark": watermark, "mode": "full" if full else "delta"})

        total_policies = 0

        def on_page(page_num: int, data: dict) -> int:
            nonlocal total_policies
            response = _deep_find(data, "POLICY_LIST") or {}
            policies = _ensure_list(response.get("POLICY") if isinstance(response, dict) else None)
            top_keys = list(data.keys()) if isinstance(data, dict) else [str(type(data))]
            for policy in policies:
                if isinstance(policy, dict):
                    upsert_policy(policy)
                    total_policies += 1
            logger.info("Policy page %d: %d policies (total: %d)", page_num, len(policies), total_policies)
            if self.sync_log:
                self.sync_log.event("PAGE_PROCESSED", {"page": page_num, "items_on_page": len(policies), "total_so_far": total_policies, "top_keys": top_keys, "target_list_found": response is not None and response != {}})
            if self.on_progress:
                self.on_progress({"type": "policies", "status": "syncing", "items_synced": total_policies, "page_items": len(policies), "pages_fetched": page_num})
            gc.collect()
            return len(policies)

        result = self.client.execute_all_pages("/api/4.0/fo/compliance/policy/", params=params, on_page=on_page, timeout=300)

        summary = {"items_synced": total_policies, "pages_fetched": result.get("pages_fetched", 0), "errors": result.get("errors", [])}
        if not result.get("errors"):
            update_sync_state("policies", is_full=full, credential_id=self.credential_id)
            if self.sync_log: self.sync_log.finish(summary)
        else:
            if self.sync_log: self.sync_log.finish_error("; ".join(result["errors"]))

        return {"type": "policies", "full": full, **summary, "rate_limits": result.get("rate_limits", {}), "first_response_snippet": result.get("first_response_snippet")}

    # ═══════════════════════════════════════════════════════════════════════
    # Mandate Sync (via CID Control API — mandate extraction only)
    # ═══════════════════════════════════════════════════════════════════════

    def sync_mandates(self, full: bool = False) -> dict:
        """Sync mandate/framework data from the CID control API.

        Mandates are embedded in CID control responses as FRAMEWORK_LIST /
        MANDATE_LIST elements. This method calls the same CID API endpoint
        but only extracts mandate data (no control upsert), using its own
        independent watermark for delta processing.

        Args:
            full: If True, do a full sync. Otherwise delta from last watermark.
        """
        params = {
            "action": "list",
            "details": "All",
            "truncation_limit": "3000",
        }

        watermark = None if full else _sanitize_watermark(get_last_sync_datetime("mandates"))
        if watermark:
            params["updated_after_datetime"] = watermark
            logger.info("Mandate delta sync from %s", watermark)
        else:
            full = True
            logger.info("Mandate full sync")

        if self.sync_log:
            self.sync_log.event("SYNC_PARAMS", {
                "params": params,
                "watermark": watermark,
                "mode": "full" if full else "delta",
                "note": "Mandates extracted from CID control API responses",
            })

        total_controls = 0

        def on_page(page_num: int, data: dict) -> int:
            nonlocal total_controls
            response = _deep_find(data, "CONTROL_LIST") or {}
            controls = _ensure_list(response.get("CONTROL") if isinstance(response, dict) else None)
            page_total = len(controls)
            # Report that we received the page and are now processing
            if self.on_progress:
                self.on_progress({"type": "mandates", "status": "processing", "items_synced": total_controls, "page_items": page_total, "pages_fetched": page_num, "processing_item": 0, "processing_total": page_total})
            for i, control in enumerate(controls):
                if isinstance(control, dict):
                    extract_mandates_from_control(control)
                    total_controls += 1
                    # Per-control progress every 50 controls
                    if self.on_progress and (i + 1) % 50 == 0:
                        self.on_progress({"type": "mandates", "status": "processing", "items_synced": total_controls, "page_items": page_total, "pages_fetched": page_num, "processing_item": i + 1, "processing_total": page_total})
            logger.info("Mandate page %d: %d controls processed (total: %d)", page_num, len(controls), total_controls)
            if self.sync_log:
                self.sync_log.event("PAGE_PROCESSED", {"page": page_num, "items_on_page": len(controls), "total_so_far": total_controls})
            if self.on_progress:
                self.on_progress({"type": "mandates", "status": "syncing", "items_synced": total_controls, "page_items": page_total, "pages_fetched": page_num})
            gc.collect()
            return len(controls)

        result = self.client.execute_all_pages("/api/4.0/fo/compliance/control/", params=params, on_page=on_page, timeout=300)

        stats = get_mandate_stats()
        summary = {
            "items_synced": total_controls,
            "pages_fetched": result.get("pages_fetched", 0),
            "errors": result.get("errors", []),
            "mandates_total": stats["mandate_count"],
            "mandate_control_links": stats["mandate_control_links"],
        }
        if not result.get("errors"):
            update_sync_state("mandates", is_full=full, credential_id=self.credential_id)
            if self.sync_log: self.sync_log.finish(summary)
        else:
            if self.sync_log: self.sync_log.finish_error("; ".join(result["errors"]))

        return {"type": "mandates", "full": full, **summary, "rate_limits": result.get("rate_limits", {}), "first_response_snippet": result.get("first_response_snippet")}

    # ═══════════════════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def needs_full_refresh(data_type: str) -> bool:
        """Check if a full refresh is needed (>30 days since last full sync)."""
        from app.database import get_db
        with get_db() as conn:
            row = conn.execute(
                "SELECT last_full_sync_datetime FROM sync_state WHERE data_type=?",
                (data_type,),
            ).fetchone()
            if not row or not row["last_full_sync_datetime"]:
                return True
            try:
                last_full = datetime.fromisoformat(
                    row["last_full_sync_datetime"].replace("Z", "+00:00")
                )
                cutoff = datetime.now(last_full.tzinfo) - timedelta(days=FULL_REFRESH_DAYS)
                return last_full < cutoff
            except (ValueError, TypeError):
                return True
