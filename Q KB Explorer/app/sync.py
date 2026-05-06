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
    upsert_tag,
    upsert_pm_patch,
    get_last_sync_datetime,
    update_sync_state,
    get_mandate_stats,
    get_db,
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
                 platform_id: str | None = None,
                 on_progress: callable = None, sync_log = None):
        self.client = client
        self.credential_id = credential_id
        self.platform_id = platform_id  # e.g. "qg3" — identifies the source subscription
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
    # Qualys QID numbering is sparse and thematic — categories cluster QIDs
    # with very wide dormant gaps between populated ranges. An aggressive
    # early-termination heuristic risks bailing in a gap and missing whole
    # populated ranges that come after. We scan the full ceiling and only
    # bail after a very long unbroken empty stretch (200 chunks ~= 2M IDs of
    # nothing, which Qualys will never produce in practice).
    QID_MAX_ID = 2000000       # Upper bound — matches sparse QID space
    QID_EMPTY_STOP = 200       # Effectively disabled; safety against runaway

    def _sync_qids_backfill(self) -> dict:
        """Pull only QIDs the local DB is missing. Doesn't purge.

        Useful when a schema change (e.g. show_disabled_flag) reveals
        QIDs not previously included, or to recover from a sync that
        errored mid-flight. Far cheaper than a Full re-pull because
        only the missing IDs are fetched in batches via the `ids=...`
        query parameter on the KB endpoint.

        Flow:
          1. Read the persisted kb_universe (populated by the most
             recent pre-count). Fall back to a fresh pre-count walk
             only when kb_universe is empty (first-ever backfill).
          2. SQL diff kb_universe against vulns to find missing IDs.
          3. Fetch missing QIDs in batches of 100 with details=All.
          4. Verify post-sync.
        """
        from app.database import (
            get_kb_universe_size,
            get_missing_qids,
        )
        if self.sync_log:
            self.sync_log.event("BACKFILL_START", {})

        # Use the persisted kb_universe whenever it's populated. Saves
        # ~10–15 Qualys calls per click compared to re-running a
        # pre-count, and the diff itself is a single indexed JOIN.
        universe_size = get_kb_universe_size()
        if universe_size > 0:
            logger.info("QID backfill: using persisted kb_universe (%d QIDs)",
                        universe_size)
            if self.sync_log:
                self.sync_log.event("BACKFILL_SOURCE", {
                    "source": "kb_universe",
                    "universe_size": universe_size,
                })
            expected_total = universe_size
            missing = get_missing_qids()
        else:
            logger.info("QID backfill: kb_universe empty — running pre-count walk")
            if self.sync_log:
                self.sync_log.event("BACKFILL_SOURCE", {
                    "source": "precount",
                    "reason": "kb_universe empty",
                })
            expected_qid_ids, _populated = self._qid_precount()
            expected_total = len(expected_qid_ids)
            missing = get_missing_qids()
        if self.sync_log:
            self.sync_log.event("COUNT_COMPLETE", {
                "expected_total": expected_total,
                "mode": "backfill",
            })
        logger.info("QID backfill: %d expected, %d missing to fetch",
                    expected_total, len(missing))
        if self.sync_log:
            self.sync_log.event("BACKFILL_DIFF", {
                "expected_total": expected_total,
                "in_db": len(in_db),
                "missing_count": len(missing),
            })

        total_added = 0
        total_pages = 0
        all_errors: list[str] = []
        BATCH_SIZE = 100  # Qualys 'ids=' param accepts a few hundred safely

        if not missing:
            # Nothing to do — DB already matches the expected set.
            update_sync_state("qids", is_full=False, credential_id=self.credential_id)
            summary = {
                "items_synced": 0,
                "pages_fetched": 0,
                "expected_total": expected_total,
                "missing_count": 0,
                "errors": [],
            }
            if self.sync_log:
                self.sync_log.finish(summary)
            return {"type": "qids", "backfill": True, **summary,
                    "rate_limits": getattr(self.client, "rate_limits", {})}

        def on_page(page_num, data):
            nonlocal total_added, total_pages
            total_pages += 1
            response = _deep_find(data, "VULN_LIST") or {}
            vulns = _ensure_list(response.get("VULN") if isinstance(response, dict) else None)
            if self.sync_log and vulns:
                self.sync_log.event("WRITE_BATCH_START", {
                    "items": len(vulns),
                    "target": "vulns + child tables (backfill)",
                })
            # Batch the whole page into one transaction so a 100-QID
            # backfill batch is one fsync, not 100.
            with get_db() as conn:
                for v in vulns:
                    if not isinstance(v, dict):
                        continue
                    try:
                        upsert_vuln(v, conn=conn)
                        total_added += 1
                    except Exception as e:
                        logger.warning(
                            "QID backfill: skipping QID %s (%s: %s)",
                            v.get("QID"), type(e).__name__, e,
                        )
            if self.on_progress:
                self.on_progress({
                    "type": "qids", "status": "syncing",
                    "items_synced": total_added,
                    "pages_fetched": total_pages,
                    "expected_total": len(missing),  # backfill bar = missing
                })
            gc.collect()
            return len(vulns)

        for i in range(0, len(missing), BATCH_SIZE):
            batch = missing[i:i + BATCH_SIZE]
            ids_param = ",".join(str(q) for q in batch)
            if self.sync_log:
                self.sync_log.event("BACKFILL_BATCH_START", {
                    "batch_index": i // BATCH_SIZE + 1,
                    "size": len(batch),
                    "first": batch[0], "last": batch[-1],
                })
            result = self.client.execute_all_pages(
                "/api/4.0/fo/knowledge_base/vuln/",
                params={
                    "action": "list",
                    "details": "All",
                    "show_supported_modules_info": "1",
                    "show_disabled_flag": "1",
                    "ids": ids_param,
                },
                on_page=on_page,
                timeout=120,
            )
            if result.get("errors"):
                all_errors.extend(result["errors"])
                if self.sync_log:
                    self.sync_log.event("BACKFILL_BATCH_ERROR", {
                        "batch_index": i // BATCH_SIZE + 1,
                        "errors": result["errors"][:3],
                    })
                # Continue with next batch — partial backfill is better
                # than no backfill.

        # Verify
        missing_after: list[int] = []
        try:
            with get_db() as conn:
                rows = conn.execute("SELECT qid FROM vulns").fetchall()
                in_db_after = {int(r[0]) for r in rows}
            still_missing = sorted(set(expected_qid_ids) - in_db_after)[:50]
            missing_after = still_missing
            if still_missing:
                if self.sync_log:
                    self.sync_log.event("VERIFY_MISSING", {
                        "missing_count": len(still_missing),
                        "missing_sample": still_missing,
                        "expected_total": expected_total,
                        "received_total": len(in_db_after),
                    })
                logger.warning("Backfill verify: %d QIDs still missing after %d batches",
                               len(still_missing), (len(missing) + BATCH_SIZE - 1) // BATCH_SIZE)
            elif self.sync_log:
                self.sync_log.event("VERIFY_OK", {
                    "expected_total": expected_total,
                    "received_total": len(in_db_after),
                })
        except Exception as e:
            logger.warning("Backfill verify step failed: %s", e)

        summary = {
            "items_synced": total_added,
            "pages_fetched": total_pages,
            "expected_total": expected_total,
            "missing_count": len(missing_after),
            "missing_sample": missing_after,
            "errors": all_errors,
        }
        if not all_errors:
            # Persist the post-backfill verification count so the UI can
            # hide the Backfill button when there's nothing left to fetch.
            update_sync_state(
                "qids", is_full=False, credential_id=self.credential_id,
                missing_count=len(missing_after),
            )
            if self.sync_log:
                self.sync_log.finish(summary)
        else:
            if self.sync_log:
                self.sync_log.finish_error("; ".join(all_errors))

        return {"type": "qids", "backfill": True, **summary,
                "rate_limits": getattr(self.client, "rate_limits", {})}

    def _qid_precount(self) -> tuple[set, list]:
        """Run the QID pre-count walk and return (expected_qid_ids,
        populated_ranges). Shared by full sync and backfill so the same
        cheap details=Basic walk drives both.

        Side effect: every QID seen by Qualys is persisted into
        kb_universe (one transaction per 100K window). That's the
        canonical "what should exist locally" set; backfill and the
        full-sync verify step both diff against it instead of holding
        the whole id-set in memory.
        """
        from app.database import upsert_kb_universe_qids, reset_kb_universe
        # Wipe the prior universe so anything Qualys has retired isn't
        # still flagged as missing. The walk below repopulates it.
        try:
            reset_kb_universe()
        except Exception as e:
            logger.warning("kb_universe reset failed (continuing): %s", e)
        expected_qid_ids: set[int] = set()
        populated_ranges: list[tuple[int, int]] = []
        COUNT_CHUNK = 100000
        count_chunks_total = (self.QID_MAX_ID + COUNT_CHUNK - 1) // COUNT_CHUNK
        count_chunks_done = 0
        consecutive_empty = 0
        for id_min in range(0, self.QID_MAX_ID, COUNT_CHUNK):
            count_chunks_done += 1
            if consecutive_empty >= 3:
                break
            id_max = id_min + COUNT_CHUNK - 1
            chunk_ids: list[int] = []

            def _count_page(_pn, data, _bucket=chunk_ids):
                response = _deep_find(data, "VULN_LIST") or {}
                vulns = _ensure_list(response.get("VULN") if isinstance(response, dict) else None)
                for v in vulns:
                    if not isinstance(v, dict):
                        continue
                    qid_raw = v.get("QID") or v.get("@id")
                    try:
                        _bucket.append(int(qid_raw))
                    except (TypeError, ValueError):
                        pass
                return len(vulns)

            count_result = self.client.execute_all_pages(
                "/api/4.0/fo/knowledge_base/vuln/",
                params={
                    "action": "list",
                    "details": "Basic",
                    "show_disabled_flag": "1",
                    "id_min": str(id_min),
                    "id_max": str(id_max),
                },
                method="POST",
                timeout=120,
                on_page=_count_page,
            )
            if count_result.get("errors"):
                if self.sync_log:
                    self.sync_log.event("COUNT_CHUNK_ERROR", {
                        "id_min": id_min, "id_max": id_max,
                        "errors": count_result["errors"][:3],
                    })
                populated_ranges.append((id_min, id_max))
                continue

            if chunk_ids:
                expected_qid_ids.update(chunk_ids)
                # Persist this 100K window into kb_universe so the
                # diff-based backfill works without re-running this walk.
                try:
                    upsert_kb_universe_qids(chunk_ids)
                except Exception as e:
                    logger.warning("kb_universe upsert failed for [%d, %d]: %s",
                                   id_min, id_max, e)
                consecutive_empty = 0
                seen_buckets = {qid // self.QID_CHUNK_SIZE for qid in chunk_ids}
                for bucket in sorted(seen_buckets):
                    bmin = bucket * self.QID_CHUNK_SIZE
                    bmax = bmin + self.QID_CHUNK_SIZE - 1
                    populated_ranges.append((bmin, bmax))
            else:
                consecutive_empty += 1

            if self.on_progress:
                self.on_progress({
                    "type": "qids", "status": "counting",
                    "expected_total": len(expected_qid_ids),
                    "count_chunks_done": count_chunks_done,
                    "count_chunks_total": count_chunks_total,
                })
            gc.collect()
        return expected_qid_ids, populated_ranges

    def sync_qids(self, full: bool = False, backfill: bool = False) -> dict:
        """Sync Knowledge Base vulnerabilities.

        Full sync uses id_min/id_max chunking to avoid 1.5 GB single responses.
        Delta sync uses a single request (small result set).
        Backfill: pre-count + diff against DB + fetch only missing QIDs.

        Args:
            full: If True, purge + full re-pull. Mutually exclusive with backfill.
            backfill: If True, run the missing-only fetch (no purge, no
                watermark). Useful after schema changes that surface QIDs
                not previously included (e.g. show_disabled_flag).
        Returns:
            Summary dict with counts and any errors.
        """
        if backfill:
            return self._sync_qids_backfill()

        base_params = {
            "action": "list",
            "details": "All",
            "show_supported_modules_info": "1",
            # Include disabled QIDs — Qualys's KB API excludes them by
            # default, but the Qualys Console UI shows them. Without
            # this flag we miss every QID Qualys has ever marked
            # disabled (often >100K records).
            "show_disabled_flag": "1",
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
        expected_total = 0  # Populated by the pre-count pass below

        # ── Pre-count pass (full sync only) ────────────────────────────
        # Walk the QID range with details=Basic — Qualys returns just
        # QID + Title (~100 bytes per QID vs ~50 KB with details=All), so
        # we can use much bigger chunks (100 K per chunk) and finish the
        # pre-count in ~10-20 requests instead of 200.
        #
        # The output isn't just a count: we collect every QID ID that
        # exists in the subscription. The detail pass then:
        #   1. Skips chunks where the pre-count saw nothing (no point
        #      asking Qualys for an empty range).
        #   2. Cross-checks the post-sync result against the expected-id
        #      set so any QIDs that showed up in the count pass but
        #      didn't make it into the DB get surfaced as a warning.
        # Cost: ~10-20 small requests for a full subscription, well
        # within Qualys's hourly quota.
        expected_qid_ids: set[int] = set()
        populated_ranges: list[tuple[int, int]] = []
        if full:
            expected_qid_ids, populated_ranges = self._qid_precount()
            expected_total = len(expected_qid_ids)
            if self.sync_log:
                self.sync_log.event("COUNT_COMPLETE", {
                    "expected_total": expected_total,
                    "populated_10k_ranges": len(populated_ranges),
                })
            logger.info("QID pre-count complete: %d QIDs across %d populated 10K ranges",
                        expected_total, len(populated_ranges))

        def on_page(page_num: int, data: dict) -> int:
            nonlocal total_vulns, total_pages
            total_pages += 1
            response = _deep_find(data, "VULN_LIST") or {}
            vulns = _ensure_list(response.get("VULN") if isinstance(response, dict) else None)
            top_keys = list(data.keys()) if isinstance(data, dict) else [str(type(data))]
            # Emit a "WRITE_BATCH_START" event before opening the
            # transaction so the live event ticker shows DB activity
            # even for chunks that take several seconds to commit.
            # Without this the ticker has a quiet gap between
            # HTTP_RESPONSE and PAGE_PROCESSED, which makes users
            # think the sync stalled.
            if self.sync_log and vulns:
                self.sync_log.event("WRITE_BATCH_START", {
                    "items": len(vulns),
                    "target": "vulns + child tables",
                })
            # One transaction per page: a chunk with thousands of QIDs
            # used to be thousands of separate WAL fsyncs (5-9 min on
            # large windows). Batched, it's one commit per page.
            with get_db() as conn:
                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue
                    # Per-record isolation: a single malformed vuln must
                    # not abort the whole sync. Log the QID and move on.
                    try:
                        upsert_vuln(vuln, conn=conn)
                        total_vulns += 1
                    except Exception as e:
                        logger.warning(
                            "QID sync: skipping QID %s (%s: %s)",
                            vuln.get("QID"), type(e).__name__, e,
                        )
            logger.info("QID page: %d vulns (total: %d, expected: %d)",
                        len(vulns), total_vulns, expected_total)
            if self.sync_log:
                self.sync_log.event("PAGE_PROCESSED", {
                    "items_on_page": len(vulns),
                    "total_so_far": total_vulns,
                    "expected_total": expected_total,
                    "top_keys": top_keys,
                    "target_list_found": response is not None and response != {},
                })
            if self.on_progress:
                self.on_progress({
                    "type": "qids", "status": "syncing",
                    "items_synced": total_vulns, "page_items": len(vulns),
                    "pages_fetched": total_pages,
                    "expected_total": expected_total,
                })
            gc.collect()
            return len(vulns)

        if full:
            # ── Full sync: detail pass over populated ranges ────────────
            # populated_ranges came from the pre-count and lists only the
            # 10K-aligned id_min/id_max windows that actually contain QIDs.
            # If the pre-count didn't run successfully (no ranges), fall
            # back to scanning the whole space so we still pull data.
            if not populated_ranges:
                populated_ranges = [
                    (i, i + self.QID_CHUNK_SIZE - 1)
                    for i in range(0, self.QID_MAX_ID, self.QID_CHUNK_SIZE)
                ]
            # Dedup + sort (one block can cover the same 10K range twice
            # if pre-count chunks overlap)
            populated_ranges = sorted(set(populated_ranges))

            for id_min, id_max in populated_ranges:
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
                    timeout=120,
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

        # ── Verification (full sync only) ───────────────────────────────
        # Cross-check the post-sync DB state against the QID id-set we
        # collected in the pre-count pass. Any expected QID that didn't
        # land in the DB is surfaced as a warning so the operator can
        # see it instead of trusting silently.
        missing_ids: list[int] = []
        verify_missing_count: int | None = None
        if full and expected_qid_ids:
            try:
                with get_db() as conn:
                    placeholder_chunks = []
                    expected_list = list(expected_qid_ids)
                    # SQLite has a default 999-parameter cap; chunk the IN list.
                    found_ids: set[int] = set()
                    CHUNK = 500
                    for i in range(0, len(expected_list), CHUNK):
                        slice_ = expected_list[i:i + CHUNK]
                        placeholders = ",".join(["?"] * len(slice_))
                        rows = conn.execute(
                            f"SELECT qid FROM vulns WHERE qid IN ({placeholders})",
                            slice_,
                        ).fetchall()
                        for r in rows:
                            found_ids.add(int(r[0]))
                    missing = expected_qid_ids - found_ids
                    missing_ids = sorted(missing)[:50]  # cap for logging
                    verify_missing_count = len(missing)
                    if missing:
                        logger.warning("QID sync verification: %d expected QIDs missing from DB",
                                       len(missing))
                        if self.sync_log:
                            self.sync_log.event("VERIFY_MISSING", {
                                "missing_count": len(missing),
                                "missing_sample": missing_ids,
                                "expected_total": expected_total,
                                "received_total": total_vulns,
                            })
                    else:
                        if self.sync_log:
                            self.sync_log.event("VERIFY_OK", {
                                "expected_total": expected_total,
                                "received_total": total_vulns,
                            })
            except Exception as e:
                logger.warning("QID verification step failed: %s", e)

        summary = {
            "items_synced": total_vulns,
            "pages_fetched": total_pages,
            "expected_total": expected_total,
            "missing_count": len(missing_ids) if missing_ids else 0,
            "missing_sample": missing_ids,
            "errors": all_errors,
        }

        if not all_errors:
            update_sync_state(
                "qids", is_full=full, credential_id=self.credential_id,
                missing_count=verify_missing_count,
            )
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

        # ── Pre-count pass (full sync only) ────────────────────────────
        # Walk the same endpoint with details=Basic to enumerate CIDs
        # without paying for the heavy detail payload. Result: an exact
        # denominator for the progress bar + a verifiable id-set we can
        # diff against the DB after the detail pass.
        expected_cid_ids: set[int] = set()
        expected_total = 0
        if full:
            cid_count_total = [0]
            def _cid_count_page(_pn, data, _bucket=expected_cid_ids):
                response = _deep_find(data, "CONTROL_LIST") or {}
                controls = _ensure_list(response.get("CONTROL") if isinstance(response, dict) else None)
                added = 0
                for c in controls:
                    if not isinstance(c, dict):
                        continue
                    cid_raw = c.get("ID") or c.get("CID")
                    try:
                        _bucket.add(int(cid_raw))
                        added += 1
                    except (TypeError, ValueError):
                        pass
                cid_count_total[0] = len(_bucket)
                if self.on_progress:
                    self.on_progress({
                        "type": "cids", "status": "counting",
                        "expected_total": cid_count_total[0],
                        "count_pages_done": _pn,
                    })
                return added

            count_result = self.client.execute_all_pages(
                "/api/4.0/fo/compliance/control/",
                params={"action": "list", "details": "Basic",
                        "truncation_limit": "3000"},
                on_page=_cid_count_page,
                timeout=300,
            )
            if count_result.get("errors"):
                if self.sync_log:
                    self.sync_log.event("COUNT_ERROR", {
                        "errors": count_result["errors"][:3],
                    })
                # Fall through — detail pass will still run, just without
                # an exact denominator.
            expected_total = len(expected_cid_ids)
            # Persist the CID universe so the UI's missing-count and
            # any future Backfill action can diff against it without
            # re-running the pre-count.
            try:
                from app.database import upsert_universe, reset_universe
                reset_universe("cids")
                upsert_universe("cids", expected_cid_ids)
            except Exception as e:
                logger.warning("sync_universe upsert (cids) failed: %s", e)
            if self.sync_log:
                self.sync_log.event("COUNT_COMPLETE", {
                    "expected_total": expected_total,
                })
            logger.info("CID pre-count complete: %d CIDs", expected_total)

        total_controls = 0

        def on_page(page_num: int, data: dict) -> int:
            nonlocal total_controls
            response = _deep_find(data, "CONTROL_LIST") or {}
            controls = _ensure_list(response.get("CONTROL") if isinstance(response, dict) else None)
            top_keys = list(data.keys()) if isinstance(data, dict) else [str(type(data))]
            page_total = len(controls)
            # Report that we received the page and are now processing
            if self.on_progress:
                self.on_progress({"type": "cids", "status": "processing", "items_synced": total_controls, "page_items": page_total, "pages_fetched": page_num, "processing_item": 0, "processing_total": page_total, "expected_total": expected_total})
            # Surface DB activity in the event ticker — without this
            # the gap between HTTP_RESPONSE and PAGE_PROCESSED looks
            # like a stall to anyone peeking under the hood.
            if self.sync_log and controls:
                self.sync_log.event("WRITE_BATCH_START", {
                    "items": page_total,
                    "target": "controls + technologies + mandate links",
                })
            # Batch the page into one transaction (controls fan out into
            # technologies + mandate links, so per-CID commits are
            # especially expensive).
            with get_db() as conn:
                for i, control in enumerate(controls):
                    if not isinstance(control, dict):
                        continue
                    try:
                        upsert_control(control, conn=conn)
                        total_controls += 1
                    except Exception as e:
                        logger.warning(
                            "CID sync: skipping CID %s (%s: %s)",
                            control.get("ID"), type(e).__name__, e,
                        )
                        continue
                    # Log first control keys for mandate/framework discovery
                    if total_controls == 1 and self.sync_log:
                        self.sync_log.event("CONTROL_KEYS_DISCOVERY", {
                            "keys": list(control.keys()),
                            "has_FRAMEWORK_LIST": "FRAMEWORK_LIST" in control,
                            "has_MANDATE_LIST": "MANDATE_LIST" in control,
                        })
                    # Per-control progress every 50 controls
                    if self.on_progress and (i + 1) % 50 == 0:
                        self.on_progress({"type": "cids", "status": "processing", "items_synced": total_controls, "page_items": page_total, "pages_fetched": page_num, "processing_item": i + 1, "processing_total": page_total, "expected_total": expected_total})
            logger.info("CID page %d: %d controls (total: %d, expected: %d)", page_num, len(controls), total_controls, expected_total)
            if self.sync_log:
                self.sync_log.event("PAGE_PROCESSED", {"page": page_num, "items_on_page": len(controls), "total_so_far": total_controls, "expected_total": expected_total, "top_keys": top_keys, "target_list_found": response is not None and response != {}})
            if self.on_progress:
                self.on_progress({"type": "cids", "status": "syncing", "items_synced": total_controls, "page_items": page_total, "pages_fetched": page_num, "expected_total": expected_total})
            gc.collect()
            return len(controls)

        result = self.client.execute_all_pages("/api/4.0/fo/compliance/control/", params=params, on_page=on_page, timeout=300)

        # ── Verification (full sync only) ───────────────────────────────
        missing_ids: list[int] = []
        cid_verify_missing_count: int | None = None
        if full and expected_cid_ids:
            try:
                with get_db() as conn:
                    expected_list = list(expected_cid_ids)
                    found_ids: set[int] = set()
                    CHUNK = 500
                    for i in range(0, len(expected_list), CHUNK):
                        slice_ = expected_list[i:i + CHUNK]
                        placeholders = ",".join(["?"] * len(slice_))
                        rows = conn.execute(
                            f"SELECT cid FROM controls WHERE cid IN ({placeholders})",
                            slice_,
                        ).fetchall()
                        for r in rows:
                            found_ids.add(int(r[0]))
                    missing = expected_cid_ids - found_ids
                    missing_ids = sorted(missing)[:50]
                    cid_verify_missing_count = len(missing)
                    if missing:
                        logger.warning("CID sync verification: %d expected CIDs missing from DB",
                                       len(missing))
                        if self.sync_log:
                            self.sync_log.event("VERIFY_MISSING", {
                                "missing_count": len(missing),
                                "missing_sample": missing_ids,
                                "expected_total": expected_total,
                                "received_total": total_controls,
                            })
                    else:
                        if self.sync_log:
                            self.sync_log.event("VERIFY_OK", {
                                "expected_total": expected_total,
                                "received_total": total_controls,
                            })
            except Exception as e:
                logger.warning("CID verification step failed: %s", e)

        summary = {
            "items_synced": total_controls,
            "pages_fetched": result.get("pages_fetched", 0),
            "expected_total": expected_total,
            "missing_count": len(missing_ids) if missing_ids else 0,
            "missing_sample": missing_ids,
            "errors": result.get("errors", []),
        }
        if not result.get("errors"):
            update_sync_state(
                "cids", is_full=full, credential_id=self.credential_id,
                missing_count=cid_verify_missing_count,
            )
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

        # ── Pre-count pass (full sync only) ────────────────────────────
        expected_policy_ids: set[int] = set()
        expected_total = 0
        if full:
            def _policy_count_page(_pn, data, _bucket=expected_policy_ids):
                response = _deep_find(data, "POLICY_LIST") or {}
                policies = _ensure_list(response.get("POLICY") if isinstance(response, dict) else None)
                added = 0
                for p in policies:
                    if not isinstance(p, dict):
                        continue
                    pid = p.get("ID") or p.get("POLICY_ID")
                    try:
                        _bucket.add(int(pid))
                        added += 1
                    except (TypeError, ValueError):
                        pass
                if self.on_progress:
                    self.on_progress({
                        "type": "policies", "status": "counting",
                        "expected_total": len(_bucket),
                        "count_pages_done": _pn,
                    })
                return added

            count_result = self.client.execute_all_pages(
                "/api/4.0/fo/compliance/policy/",
                params={"action": "list", "details": "Basic"},
                on_page=_policy_count_page,
                timeout=300,
            )
            if count_result.get("errors") and self.sync_log:
                self.sync_log.event("COUNT_ERROR", {"errors": count_result["errors"][:3]})
            expected_total = len(expected_policy_ids)
            try:
                from app.database import upsert_universe, reset_universe
                reset_universe("policies")
                upsert_universe("policies", expected_policy_ids)
            except Exception as e:
                logger.warning("sync_universe upsert (policies) failed: %s", e)
            if self.sync_log:
                self.sync_log.event("COUNT_COMPLETE", {"expected_total": expected_total})
            logger.info("Policy pre-count complete: %d policies", expected_total)

        total_policies = 0

        def on_page(page_num: int, data: dict) -> int:
            nonlocal total_policies
            response = _deep_find(data, "POLICY_LIST") or {}
            policies = _ensure_list(response.get("POLICY") if isinstance(response, dict) else None)
            top_keys = list(data.keys()) if isinstance(data, dict) else [str(type(data))]
            if self.sync_log and policies:
                self.sync_log.event("WRITE_BATCH_START", {
                    "items": len(policies),
                    "target": "policies + policy_controls",
                })
            # Single transaction per page — each policy fans out into
            # policy_controls inserts and a CID-resolution UPDATE.
            with get_db() as conn:
                for policy in policies:
                    if not isinstance(policy, dict):
                        continue
                    try:
                        upsert_policy(policy, conn=conn)
                        total_policies += 1
                    except Exception as e:
                        logger.warning(
                            "Policy sync: skipping policy %s (%s: %s)",
                            policy.get("ID"), type(e).__name__, e,
                        )
            logger.info("Policy page %d: %d policies (total: %d, expected: %d)", page_num, len(policies), total_policies, expected_total)
            if self.sync_log:
                self.sync_log.event("PAGE_PROCESSED", {"page": page_num, "items_on_page": len(policies), "total_so_far": total_policies, "expected_total": expected_total, "top_keys": top_keys, "target_list_found": response is not None and response != {}})
            if self.on_progress:
                self.on_progress({"type": "policies", "status": "syncing", "items_synced": total_policies, "page_items": len(policies), "pages_fetched": page_num, "expected_total": expected_total})
            gc.collect()
            return len(policies)

        result = self.client.execute_all_pages("/api/4.0/fo/compliance/policy/", params=params, on_page=on_page, timeout=300)

        # ── Verification (full sync only) ───────────────────────────────
        missing_ids: list[int] = []
        policy_verify_missing_count: int | None = None
        if full and expected_policy_ids:
            try:
                with get_db() as conn:
                    expected_list = list(expected_policy_ids)
                    found_ids: set[int] = set()
                    CHUNK = 500
                    for i in range(0, len(expected_list), CHUNK):
                        slice_ = expected_list[i:i + CHUNK]
                        placeholders = ",".join(["?"] * len(slice_))
                        rows = conn.execute(
                            f"SELECT policy_id FROM policies WHERE policy_id IN ({placeholders})",
                            slice_,
                        ).fetchall()
                        for r in rows:
                            found_ids.add(int(r[0]))
                    missing = expected_policy_ids - found_ids
                    missing_ids = sorted(missing)[:50]
                    policy_verify_missing_count = len(missing)
                    if missing:
                        logger.warning("Policy sync verification: %d expected policies missing from DB",
                                       len(missing))
                        if self.sync_log:
                            self.sync_log.event("VERIFY_MISSING", {
                                "missing_count": len(missing),
                                "missing_sample": missing_ids,
                                "expected_total": expected_total,
                                "received_total": total_policies,
                            })
                    elif self.sync_log:
                        self.sync_log.event("VERIFY_OK", {
                            "expected_total": expected_total,
                            "received_total": total_policies,
                        })
            except Exception as e:
                logger.warning("Policy verification step failed: %s", e)

        summary = {
            "items_synced": total_policies,
            "pages_fetched": result.get("pages_fetched", 0),
            "expected_total": expected_total,
            "missing_count": len(missing_ids) if missing_ids else 0,
            "missing_sample": missing_ids,
            "errors": result.get("errors", []),
        }
        if not result.get("errors"):
            update_sync_state(
                "policies", is_full=full, credential_id=self.credential_id,
                missing_count=policy_verify_missing_count,
            )
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
            if self.sync_log and controls:
                self.sync_log.event("WRITE_BATCH_START", {
                    "items": page_total,
                    "target": "mandates + mandate_controls",
                })
            # Single transaction per page — mandate extraction touches
            # mandates + mandate_controls per CID, so per-control commits
            # were a real cost.
            with get_db() as conn:
                for i, control in enumerate(controls):
                    if isinstance(control, dict):
                        extract_mandates_from_control(control, conn=conn)
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
    # Tag Sync (Qualys QPS REST — JSON, cursor pagination)
    # ═══════════════════════════════════════════════════════════════════════

    TAG_PAGE_SIZE = 1000  # Max QPS REST limitResults

    def sync_tags(self, full: bool = False) -> dict:
        """Sync Asset Tags via Qualys QPS REST.

        Endpoint: POST /qps/rest/2.0/search/am/tag with JSON body.
        Pagination: cursor-based via hasMoreRecords/lastId.

        Args:
            full: If True, do a full sync. Otherwise delta from last watermark.
        """
        watermark = None if full else _sanitize_watermark(get_last_sync_datetime("tags"))
        if watermark:
            logger.info("Tag delta sync from %s", watermark)
        else:
            full = True
            logger.info("Tag full sync")

        if self.sync_log:
            self.sync_log.event("SYNC_PARAMS", {
                "watermark": watermark,
                "mode": "full" if full else "delta",
                "endpoint": "/qps/rest/2.0/search/am/tag",
                "page_size": self.TAG_PAGE_SIZE,
            })

        # ── Pre-count via QPS count endpoint (full sync only) ──────────
        # /qps/rest/2.0/count/am/tag returns ServiceResponse.count without
        # any record bodies — single small call gives us an exact total
        # to use as the progress denominator and the post-sync verify
        # comparison.
        expected_total = 0
        if full:
            count = self.client.qps_count(
                "/qps/rest/2.0/count/am/tag",
                body={"ServiceRequest": {}},
                timeout=30,
            )
            if count is not None:
                expected_total = count
                if self.sync_log:
                    self.sync_log.event("COUNT_COMPLETE", {"expected_total": expected_total})
                if self.on_progress:
                    self.on_progress({
                        "type": "tags", "status": "counting",
                        "expected_total": expected_total,
                        "count_pages_done": 1, "count_pages_total": 1,
                    })
                logger.info("Tag pre-count: %d tags expected", expected_total)
            else:
                if self.sync_log:
                    self.sync_log.event("COUNT_UNAVAILABLE", {
                        "note": "QPS count endpoint did not return a usable total",
                    })
                logger.info("Tag pre-count unavailable; proceeding without exact denominator")

        total_tags = 0
        pages_fetched = 0
        synced_tag_ids: list[int] = []  # collected for the enrichment pass
        last_id = None
        all_errors: list[str] = []

        while True:
            criteria = []
            if watermark:
                criteria.append({"field": "modified", "operator": "GREATER", "value": watermark})
            if last_id is not None:
                criteria.append({"field": "id", "operator": "GREATER", "value": str(last_id)})

            body = {
                "ServiceRequest": {
                    "preferences": {"limitResults": self.TAG_PAGE_SIZE},
                }
            }
            if criteria:
                body["ServiceRequest"]["filters"] = {"Criteria": criteria}

            result = self.client.execute_json(
                "/qps/rest/2.0/search/am/tag",
                body=body,
                method="POST",
                timeout=120,
            )
            pages_fetched += 1

            if result.get("error"):
                msg = result.get("message", "Unknown error")
                all_errors.append(msg)
                if self.sync_log:
                    self.sync_log.event("PAGE_ERROR", {"page": pages_fetched, "error": str(msg)[:500]})
                break

            parsed = result.get("data", {}) or {}
            page_tags = self.client.qps_extract_data(parsed, "Tag")
            if self.sync_log and page_tags:
                self.sync_log.event("WRITE_BATCH_START", {
                    "items": len(page_tags),
                    "target": "tags",
                })
            # Single transaction for the whole page of tags.
            with get_db() as conn:
                for tag in page_tags:
                    try:
                        tid = upsert_tag(tag, credential_id=self.credential_id,
                                        source_platform=self.platform_id,
                                        source_subscription=self.credential_id,
                                        conn=conn)
                        if tid is not None:
                            synced_tag_ids.append(tid)
                        total_tags += 1
                    except Exception as e:
                        logger.warning(
                            "Tag sync: skipping tag %s (%s: %s)",
                            (tag.get("id") if isinstance(tag, dict) else None),
                            type(e).__name__, e,
                        )

            logger.info("Tag page %d: %d tags (total: %d)", pages_fetched, len(page_tags), total_tags)
            if self.sync_log:
                self.sync_log.event("PAGE_PROCESSED", {
                    "page": pages_fetched,
                    "items_on_page": len(page_tags),
                    "total_so_far": total_tags,
                })
            if self.on_progress:
                self.on_progress({
                    "type": "tags", "status": "syncing",
                    "items_synced": total_tags, "page_items": len(page_tags),
                    "pages_fetched": pages_fetched,
                    "expected_total": expected_total,
                })
            gc.collect()

            has_more, next_last_id = self.client.qps_has_more(parsed)
            if not has_more or next_last_id is None or next_last_id == last_id:
                break
            last_id = next_last_id

        # Enrichment pass: per-tag GET on every synced tag to populate
        # reservedType / createdBy (omitted by the bulk search response).
        # We always run this pass — the user explicitly chose
        # 'caution over speed' so the classification can rely on the
        # full Qualys metadata instead of heuristics.
        if synced_tag_ids and not all_errors:
            if self.sync_log:
                self.sync_log.event("ENRICH_START", {
                    "count": len(synced_tag_ids),
                    "endpoint": "/qps/rest/2.0/get/am/tag/<id>",
                    "note": "fetching full detail per tag for accurate classification",
                })
            enriched = 0
            failed = 0
            total_to_enrich = len(synced_tag_ids)
            for idx, tid in enumerate(synced_tag_ids, start=1):
                detail = self.client.get_tag_detail(tid)
                if detail:
                    try:
                        upsert_tag(detail, credential_id=self.credential_id,
                                  source_platform=self.platform_id,
                                  source_subscription=self.credential_id)
                        enriched += 1
                    except Exception as e:
                        logger.warning(
                            "Tag enrich: skipping tag %s (%s: %s)",
                            tid, type(e).__name__, e,
                        )
                        failed += 1
                else:
                    failed += 1
                if self.on_progress and (idx % 5 == 0 or idx == total_to_enrich):
                    self.on_progress({
                        "type": "tags", "status": "enriching",
                        "items_synced": total_tags,
                        "enrich_done": idx,
                        "enrich_total": total_to_enrich,
                    })
            if self.sync_log:
                self.sync_log.event("ENRICH_DONE", {
                    "count": total_to_enrich,
                    "enriched": enriched,
                    "failed": failed,
                })
            logger.info("Tag enrichment: %d/%d enriched, %d failed",
                        enriched, total_to_enrich, failed)

        # Propagate user-created classification up to organizer/parent
        # tags that lack their own rule. Runs after enrichment so the
        # propagation sees the most accurate per-tag metadata possible.
        try:
            from app.database import _propagate_user_classification
            with get_db() as conn:
                flipped = _propagate_user_classification(conn)
            if self.sync_log and flipped:
                self.sync_log.event("CLASSIFY_PROPAGATE", {
                    "rows_flipped_to_user": flipped,
                })
        except Exception as e:
            logger.warning("Tag classification propagation failed: %s", e)

        # ── Verification ───────────────────────────────────────────────
        # If we got an expected total from the pre-count, compare it
        # against what actually landed in the DB. The QPS count endpoint
        # gives us a number, not an id list, so we just compare totals
        # — any drift becomes a VERIFY_MISMATCH event.
        verify_drift = 0
        if full and expected_total > 0 and not all_errors:
            try:
                with get_db() as conn:
                    db_total = conn.execute("SELECT COUNT(*) FROM tags").fetchone()[0]
                verify_drift = expected_total - db_total
                if verify_drift > 0:
                    logger.warning("Tag sync verification: expected %d, got %d (drift %d)",
                                   expected_total, db_total, verify_drift)
                    if self.sync_log:
                        self.sync_log.event("VERIFY_MISMATCH", {
                            "expected_total": expected_total,
                            "received_total": db_total,
                            "drift": verify_drift,
                        })
                elif self.sync_log:
                    self.sync_log.event("VERIFY_OK", {
                        "expected_total": expected_total,
                        "received_total": db_total,
                    })
            except Exception as e:
                logger.warning("Tag verification step failed: %s", e)

        summary = {
            "items_synced": total_tags,
            "pages_fetched": pages_fetched,
            "expected_total": expected_total,
            "missing_count": max(0, verify_drift),
            "errors": all_errors,
        }
        if not all_errors:
            update_sync_state("tags", is_full=full, credential_id=self.credential_id)
            if self.sync_log:
                self.sync_log.finish(summary)
        else:
            if self.sync_log:
                self.sync_log.finish_error("; ".join(all_errors))

        return {
            "type": "tags",
            "full": full,
            **summary,
            "rate_limits": getattr(self.client, "rate_limits", {}),
        }

    # ═══════════════════════════════════════════════════════════════════════
    # PM Patch Catalog Sync (Qualys Gateway — JWT, /pm/v2/patches)
    # ═══════════════════════════════════════════════════════════════════════

    PM_PAGE_SIZE = 1000

    def sync_pm_patches(self, full: bool = True) -> dict:
        """Sync the Qualys Patch Management catalog (Windows + Linux).

        Endpoint:   POST /pm/v2/patches?platform=<plat>&pageSize=<n>
        Pagination: searchAfter HTTP header cursor (no 10K cap).
        Auth:       Gateway JWT bearer (acquired lazily on first call).

        Args:
            full: When True, pulls the full catalog. When False, restricts
                  the QQL query to patches whose `lastModified` is greater
                  than the previous sync watermark — the PM catalog
                  changes as Qualys updates patch metadata, vendor
                  severities, and supersession info.
        """
        watermark = None if full else _sanitize_watermark(get_last_sync_datetime("pm_patches"))
        if not watermark:
            full = True  # First-ever sync or no watermark → force full

        if self.sync_log:
            self.sync_log.event("SYNC_PARAMS", {
                "endpoint": "/pm/v2/patches",
                "page_size": self.PM_PAGE_SIZE,
                "platforms": ["Windows", "Linux"],
                "mode": "full" if full else "delta",
                "watermark": watermark,
            })

        all_errors: list[str] = []
        platform_results: dict[str, dict] = {}
        platform_expected: dict[str, int] = {}
        grand_total = 0
        grand_pages = 0
        grand_expected = 0

        # ── Pre-count attempt (full sync only) ─────────────────────────
        # PM v2 returns the total count as a response header on any
        # search request. We issue a pageSize=1 request per platform
        # to get the count without pulling the full catalog.
        # Note: Linux patches have isSuperseded=null (not false), so
        # we use isSuperseded:false for Windows only and no supersession
        # filter for Linux.
        if full:
            for platform in ("Windows", "Linux"):
                qql_count = "isSuperseded:false" if platform == "Windows" else ""
                body_count = {"query": qql_count} if qql_count else {}
                exp = self.client.gateway_count(
                    f"/pm/v2/patches?platform={platform}&pageSize=1",
                    body=body_count,
                    timeout=30,
                )
                if exp is not None and exp >= 0:
                    platform_expected[platform] = exp
                    grand_expected += exp
            if grand_expected > 0:
                if self.sync_log:
                    self.sync_log.event("COUNT_COMPLETE", {
                        "expected_total": grand_expected,
                        "per_platform": platform_expected,
                    })
                logger.info("PM pre-count: %d patches expected (%s)",
                            grand_expected, platform_expected)
                if self.on_progress:
                    self.on_progress({
                        "type": "pm_patches", "status": "counting",
                        "expected_total": grand_expected,
                    })
            else:
                if self.sync_log:
                    self.sync_log.event("COUNT_UNAVAILABLE", {
                        "note": "PM count endpoint did not surface a usable total",
                    })

        for platform in ("Windows", "Linux"):
            plat_total = 0
            plat_pages = 0
            search_after = ""
            url_path = f"/pm/v2/patches?platform={platform}&pageSize={self.PM_PAGE_SIZE}"
            # QQL query: Windows uses isSuperseded:false; Linux patches
            # have isSuperseded=null (the field doesn't apply to Linux's
            # package-based model), so we skip that filter for Linux.
            if platform == "Windows":
                qql = "isSuperseded:false"
                if not full and watermark:
                    qql += f' and lastModified:>"{watermark}"'
            else:
                # Linux: no supersession filter. For delta, filter by lastModified.
                qql = ""
                if not full and watermark:
                    qql = f'lastModified:>"{watermark}"'
            body = {"query": qql} if qql else {}

            if self.sync_log:
                self.sync_log.event("PM_PLATFORM_START", {
                    "platform": platform,
                    "expected_total": platform_expected.get(platform),
                })

            while True:
                plat_pages += 1
                grand_pages += 1
                extra = {"searchAfter": search_after} if search_after else None

                result = self.client.execute_gateway_json(
                    url_path,
                    body=body,
                    method="POST",
                    extra_headers=extra,
                    timeout=120,
                )

                if result.get("error"):
                    msg = f"PM {platform} page {plat_pages}: {result.get('message', 'unknown error')}"
                    all_errors.append(msg)
                    if self.sync_log:
                        self.sync_log.event("PAGE_ERROR", {
                            "platform": platform,
                            "page": plat_pages,
                            "error": str(result.get("message"))[:500],
                        })
                    break

                parsed = result.get("data", {}) or {}
                # /pm/v2/patches returns a flat array; tolerate single-dict too.
                if isinstance(parsed, dict):
                    patches = [parsed]
                elif isinstance(parsed, list):
                    patches = [p for p in parsed if isinstance(p, dict)]
                else:
                    patches = []

                if self.sync_log and patches:
                    self.sync_log.event("WRITE_BATCH_START", {
                        "items": len(patches),
                        "target": "pm_patches + qid/cve link tables",
                        "platform": platform,
                    })
                # Single transaction per page — each patch fans out into
                # pm_patch_qids and pm_patch_cves inserts.
                with get_db() as conn:
                    for patch in patches:
                        if not isinstance(patch, dict):
                            continue
                        patch.setdefault("platform", platform)
                        try:
                            upsert_pm_patch(patch, conn=conn)
                            plat_total += 1
                            grand_total += 1
                        except Exception as e:
                            logger.warning(
                                "PM patch sync: skipping patch %s (%s: %s)",
                                patch.get("id") or patch.get("patchId"),
                                type(e).__name__, e,
                            )

                if self.sync_log:
                    self.sync_log.event("PAGE_PROCESSED", {
                        "platform": platform,
                        "page": plat_pages,
                        "items_on_page": len(patches),
                        "total_so_far": grand_total,
                    })
                if self.on_progress:
                    self.on_progress({
                        "type": "pm_patches", "status": "syncing",
                        "platform": platform,
                        "items_synced": grand_total,
                        "page_items": len(patches),
                        "pages_fetched": grand_pages,
                        "expected_total": grand_expected,
                    })
                gc.collect()

                # Termination: server returns no searchAfter header *or* a
                # short page → reached the end of the catalog.
                resp_headers = result.get("response_headers") or {}
                next_cursor = resp_headers.get("searchAfter") or resp_headers.get("searchafter") or ""
                if len(patches) < self.PM_PAGE_SIZE or not next_cursor:
                    break
                search_after = next_cursor

            platform_results[platform] = {
                "patches": plat_total,
                "pages": plat_pages,
                "expected": platform_expected.get(platform),
            }
            if self.sync_log:
                self.sync_log.event("PM_PLATFORM_DONE", {
                    "platform": platform,
                    "patches": plat_total,
                    "pages": plat_pages,
                    "expected": platform_expected.get(platform),
                })

        # ── Verification (full sync only, when we got a count) ─────────
        verify_drift = 0
        if full and grand_expected > 0 and not all_errors:
            verify_drift = grand_expected - grand_total
            if verify_drift > 0:
                logger.warning("PM sync verification: expected %d, got %d (drift %d)",
                               grand_expected, grand_total, verify_drift)
                if self.sync_log:
                    self.sync_log.event("VERIFY_MISMATCH", {
                        "expected_total": grand_expected,
                        "received_total": grand_total,
                        "drift": verify_drift,
                        "per_platform": {
                            p: {
                                "expected": platform_expected.get(p),
                                "received": platform_results.get(p, {}).get("patches", 0),
                            } for p in ("Windows", "Linux")
                        },
                    })
            elif self.sync_log:
                self.sync_log.event("VERIFY_OK", {
                    "expected_total": grand_expected,
                    "received_total": grand_total,
                })

        summary = {
            "items_synced": grand_total,
            "pages_fetched": grand_pages,
            "expected_total": grand_expected,
            "missing_count": max(0, verify_drift),
            "errors": all_errors,
            "platforms": platform_results,
        }
        if not all_errors:
            update_sync_state("pm_patches", is_full=full, credential_id=self.credential_id)
            if self.sync_log:
                self.sync_log.finish(summary)
        else:
            if self.sync_log:
                self.sync_log.finish_error("; ".join(all_errors))

        return {
            "type": "pm_patches",
            "full": full,
            **summary,
            "rate_limits": getattr(self.client, "rate_limits", {}),
        }

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
