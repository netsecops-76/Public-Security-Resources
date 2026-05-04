"""
Q KB Explorer — Qualys API Client
Built by netsecops-76

HTTP client for Qualys v2 API with pagination, XML parsing,
and rate limit extraction. Extracted from Qualys_API_Engine patterns.
"""

from __future__ import annotations

import json
import logging
import re
import time

import requests
import xmltodict

logger = logging.getLogger(__name__)

# Qualys truncation code — signals paginated response
_TRUNCATION_CODE = "1980"


# ═══════════════════════════════════════════════════════════════════════════
# Utility Functions (extracted from QAE)
# ═══════════════════════════════════════════════════════════════════════════

def xml_to_json(xml_string: str) -> dict:
    """Parse XML string to ordered dict via xmltodict."""
    try:
        return xmltodict.parse(xml_string)
    except Exception:
        return {"raw_response": xml_string}


def _deep_find(data: dict, target_key: str):
    """Recursively search nested dict for a key (case-insensitive)."""
    if not isinstance(data, dict):
        return None
    for key, val in data.items():
        if key.upper() == target_key.upper():
            return val
        if isinstance(val, dict):
            result = _deep_find(val, target_key)
            if result is not None:
                return result
    return None


def _detect_pagination(raw_text: str, parsed_data: dict) -> dict | None:
    """Detect Qualys API truncated responses and extract next-page URL.

    Qualys v2 APIs signal truncation via:
    1. XML: <WARNING><CODE>1980</CODE><TEXT>...</TEXT><URL>next_page_url</URL></WARNING>
    2. JSON equivalent after xmltodict: WARNING.URL key
    """
    pagination = {"truncated": False, "next_url": None, "warning_text": None}

    # Method 1: scan raw XML for WARNING URL
    if raw_text:
        url_match = re.search(
            r"<WARNING>.*?<URL>\s*(https?://[^<]+?)\s*</URL>.*?</WARNING>",
            raw_text, re.DOTALL | re.IGNORECASE,
        )
        if url_match:
            pagination["truncated"] = True
            raw_url = url_match.group(1).strip()
            pagination["next_url"] = (
                raw_url.replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
            )
        text_match = re.search(
            r"<WARNING>.*?<TEXT>\s*([^<]+?)\s*</TEXT>.*?</WARNING>",
            raw_text, re.DOTALL | re.IGNORECASE,
        )
        if text_match:
            pagination["warning_text"] = text_match.group(1).strip()

    # Method 2: check parsed dict for WARNING.URL
    if not pagination["truncated"] and isinstance(parsed_data, dict):
        warning = _deep_find(parsed_data, "WARNING")
        if warning and isinstance(warning, dict):
            url_val = warning.get("URL") or warning.get("url")
            if url_val:
                pagination["truncated"] = True
                pagination["next_url"] = url_val.strip() if isinstance(url_val, str) else None
            text_val = warning.get("TEXT") or warning.get("text")
            if text_val:
                pagination["warning_text"] = text_val.strip() if isinstance(text_val, str) else None

    return pagination if pagination["truncated"] else None


def _ensure_list(val):
    """Normalize a single-item or list value from xmltodict."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


# ═══════════════════════════════════════════════════════════════════════════
# Qualys Client
# ═══════════════════════════════════════════════════════════════════════════

class QualysClient:
    """HTTP client for Qualys v2 API."""

    USER_AGENT = "Q-KB-Explorer/1.0"

    def __init__(self, api_base: str, username: str, password: str):
        self.api_base = api_base.rstrip("/")
        # Validate credentials can be latin-1 encoded (required for HTTP Basic Auth).
        # This catches the case where masked password bullets (U+2022) were
        # accidentally saved to the vault instead of the real password.
        try:
            f"{username}:{password}".encode("latin-1")
        except UnicodeEncodeError:
            raise ValueError(
                "Stored password contains invalid characters (possibly masked "
                "bullet characters). Please disconnect, re-enter your actual "
                "password, and save again."
            )
        self.auth = (username, password)
        self.session = requests.Session()
        self.session.headers["X-Requested-With"] = self.USER_AGENT
        self.rate_limits: dict = {}
        self.sync_log = None  # Optional SyncLog for diagnostics

    def _log(self, event_type: str, detail: dict | None = None):
        """Log event to SyncLog if attached."""
        if self.sync_log:
            self.sync_log.event(event_type, detail)

    def execute(
        self,
        path: str,
        params: dict | None = None,
        method: str = "POST",
        timeout: int = 120,
        raw_url: str | None = None,
        keep_raw: bool = False,
    ) -> dict:
        """Execute a single API call. Returns parsed response + metadata."""
        url = raw_url or f"{self.api_base}{path}"

        self._log("HTTP_REQUEST", {
            "method": method.upper(),
            "url": url,
            "timeout": timeout,
            "params": {k: v for k, v in (params or {}).items()} if params else None,
        })

        try:
            t0 = time.time()
            if method.upper() == "GET":
                resp = self.session.get(
                    url, params=params, auth=self.auth, timeout=timeout,
                )
            else:
                resp = self.session.post(
                    url, data=params, auth=self.auth, timeout=timeout,
                )
            elapsed_ms = round((time.time() - t0) * 1000)

            # Extract rate limit headers
            for h_key, h_val in resp.headers.items():
                if "x-ratelimit" in h_key.lower() or "x-concurrency" in h_key.lower():
                    self.rate_limits[h_key] = h_val

            # Capture key response headers
            resp_headers = {}
            for h in ("Content-Type", "Content-Length", "X-RateLimit-Limit",
                       "X-RateLimit-Remaining", "X-RateLimit-Window-Sec",
                       "X-Concurrency-Limit-Limit", "X-Concurrency-Limit-Running"):
                val = resp.headers.get(h)
                if val:
                    resp_headers[h] = val

            self._log("HTTP_RESPONSE", {
                "status": resp.status_code,
                "elapsed_ms": elapsed_ms,
                "content_length": len(resp.content),
                "headers": resp_headers,
            })

            if resp.status_code == 409:
                retry_after = int(resp.headers.get("Retry-After", 60))
                self._log("RATE_LIMITED", {"retry_after": retry_after})
                return {
                    "error": True,
                    "status_code": 409,
                    "retry_after": retry_after,
                    "message": "Rate limited",
                }

            if resp.status_code != 200:
                body_snippet = resp.text[:2000]
                self._log("HTTP_ERROR", {
                    "status": resp.status_code,
                    "body_snippet": body_snippet,
                })
                return {
                    "error": True,
                    "status_code": resp.status_code,
                    "message": body_snippet,
                }

            raw_text = resp.text
            # Release response body to free memory
            resp.close()

            parsed = xml_to_json(raw_text)
            pagination = _detect_pagination(raw_text, parsed)

            if pagination:
                self._log("PAGINATION_DETECTED", {
                    "next_url": pagination.get("next_url", "")[:200],
                    "warning_text": pagination.get("warning_text"),
                })

            if keep_raw:
                # Caller needs full raw text (e.g. policy export)
                return {
                    "error": False,
                    "status_code": 200,
                    "data": parsed,
                    "raw_text": raw_text,
                    "pagination": pagination,
                    "rate_limits": dict(self.rate_limits),
                }

            # Keep only a snippet of raw_text for diagnostics — full text
            # can be hundreds of MB for KB syncs and cause OOM.
            raw_snippet = raw_text[:2000] if raw_text else None
            del raw_text  # Free the large string immediately

            return {
                "error": False,
                "status_code": 200,
                "data": parsed,
                "raw_snippet": raw_snippet,
                "pagination": pagination,
                "rate_limits": dict(self.rate_limits),
            }

        except requests.exceptions.Timeout:
            self._log("HTTP_TIMEOUT", {"timeout": timeout, "url": url})
            return {"error": True, "status_code": 0, "message": f"Request timed out (timeout={timeout}s)"}
        except requests.exceptions.ConnectionError as e:
            self._log("HTTP_CONNECTION_ERROR", {"error": str(e)[:500], "url": url})
            return {"error": True, "status_code": 0, "message": f"Connection error: {e}"}
        except Exception as e:
            self._log("HTTP_EXCEPTION", {"error": str(e)[:500], "url": url})
            return {"error": True, "status_code": 0, "message": str(e)}

    def execute_all_pages(
        self,
        path: str,
        params: dict | None = None,
        method: str = "POST",
        timeout: int = 120,
        max_pages: int = 100,
        on_page: callable = None,
    ) -> dict:
        """Execute API call with automatic pagination following.

        Args:
            on_page: Optional callback(page_num, parsed_data) called per page.
                     Allows callers to process/store data incrementally.
        Returns:
            Summary dict with total pages fetched and any errors.
        """
        pages_fetched = 0
        total_items = 0
        errors = []
        first_response_snippet = None

        result = self.execute(path, params, method, timeout)

        while True:
            pages_fetched += 1

            if result.get("error"):
                # Rate limited — wait and retry
                if result.get("status_code") == 409:
                    retry = result.get("retry_after", 60)
                    logger.warning("Rate limited — waiting %ds", retry)
                    time.sleep(retry)
                    result = self.execute(path, params, method, timeout)
                    continue
                errors.append(result.get("message", "Unknown error"))
                break

            # Capture first page raw response for diagnostics
            if pages_fetched == 1:
                first_response_snippet = result.get("raw_snippet")

            # Process this page
            if on_page:
                count = on_page(pages_fetched, result.get("data", {}))
                total_items += count if isinstance(count, int) else 0

            # Check for more pages
            pagination = result.get("pagination")
            if pagination and pagination.get("next_url"):
                if pages_fetched >= max_pages:
                    logger.warning("Hit max pages limit (%d)", max_pages)
                    break
                next_url = pagination["next_url"]
                logger.info("Following pagination to page %d", pages_fetched + 1)
                result = self.execute(path, raw_url=next_url, timeout=timeout)
            else:
                break

        return {
            "pages_fetched": pages_fetched,
            "total_items": total_items,
            "errors": errors,
            "rate_limits": dict(self.rate_limits),
            "first_response_snippet": first_response_snippet,
        }

    def execute_with_xml_body(
        self,
        path: str,
        xml_body: bytes,
        params: dict | None = None,
        timeout: int = 120,
    ) -> dict:
        """Execute API call with raw XML body (for policy import)."""
        url = f"{self.api_base}{path}"
        try:
            resp = self.session.post(
                url,
                params=params,
                data=xml_body,
                auth=self.auth,
                headers={
                    "Content-Type": "text/xml",
                    "X-Requested-With": self.USER_AGENT,
                },
                timeout=timeout,
            )

            if resp.status_code != 200:
                return {
                    "error": True,
                    "status_code": resp.status_code,
                    "message": resp.text[:500],
                }

            parsed = xml_to_json(resp.text)
            return {
                "error": False,
                "status_code": 200,
                "data": parsed,
                "raw_text": resp.text,
            }

        except Exception as e:
            return {"error": True, "status_code": 0, "message": str(e)}
