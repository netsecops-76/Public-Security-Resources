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

    # Maximum 409/429 retries per HTTP call. Each retry honours the
    # server's Retry-After header. Total worst-case wait ≈ 3 * 60s = 3 min.
    RATE_LIMIT_MAX_RETRIES = 3
    RATE_LIMIT_DEFAULT_BACKOFF_SEC = 60

    @staticmethod
    def _retry_after_seconds(resp) -> int:
        """Extract Retry-After header in seconds, with a sane default."""
        raw = resp.headers.get("Retry-After")
        if raw is None:
            return QualysClient.RATE_LIMIT_DEFAULT_BACKOFF_SEC
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            # Some servers return HTTP-date format; fall back to default
            return QualysClient.RATE_LIMIT_DEFAULT_BACKOFF_SEC

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
        self.username = username
        self._password = password
        self.session = requests.Session()
        self.session.headers["X-Requested-With"] = self.USER_AGENT
        self.rate_limits: dict = {}
        self.sync_log = None  # Optional SyncLog for diagnostics
        # Qualys Gateway base — used by JWT-authenticated APIs (PM, MTG).
        # Derived from api_base by replacing the leading 'qualysapi' host
        # component with 'gateway'. Works across all current PODs.
        self.gateway_base = self.api_base.replace("qualysapi", "gateway", 1)
        self._jwt_token: str | None = None

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

        attempt = 0
        try:
            while True:
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
                    "attempt": attempt + 1 if attempt else None,
                })

                # Rate-limited (409 Qualys quota, 429 standard). Honour the
                # server's Retry-After and try again, up to N attempts.
                if resp.status_code in (409, 429) and attempt < self.RATE_LIMIT_MAX_RETRIES:
                    retry_after = self._retry_after_seconds(resp)
                    self._log("RATE_LIMITED_RETRY", {
                        "status": resp.status_code,
                        "retry_after": retry_after,
                        "attempt": attempt + 1,
                        "max_attempts": self.RATE_LIMIT_MAX_RETRIES,
                    })
                    resp.close()
                    time.sleep(retry_after)
                    attempt += 1
                    continue

                # Retries exhausted while still rate-limited
                if resp.status_code in (409, 429):
                    retry_after = self._retry_after_seconds(resp)
                    self._log("RATE_LIMITED_GIVEUP", {
                        "status": resp.status_code,
                        "retry_after": retry_after,
                        "attempts": attempt + 1,
                    })
                    return {
                        "error": True,
                        "status_code": resp.status_code,
                        "retry_after": retry_after,
                        "message": f"Rate limited after {attempt + 1} attempts",
                    }

                # Non-rate-limit response — break out of the retry loop and
                # process normally below.
                break

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

    # ═══════════════════════════════════════════════════════════════════════
    # QPS REST (JSON) — Qualys Asset Management Tag API
    # ═══════════════════════════════════════════════════════════════════════
    #
    # Tags use a different API family than QIDs/CIDs/Policies:
    #   /qps/rest/2.0/{operation}/am/tag[/{id}]
    # JSON request/response, same Basic Auth credentials.
    # Supported operations: search, get, create, update, delete, count.

    def execute_json(
        self,
        path: str,
        body: dict | None = None,
        method: str = "POST",
        timeout: int = 120,
    ) -> dict:
        """Execute a QPS REST (JSON) API call.

        Returns a dict with the same shape as execute() — error/status_code/
        data/raw_snippet — so callers can branch uniformly.
        """
        url = f"{self.api_base}{path}"

        self._log("HTTP_REQUEST", {
            "method": method.upper(),
            "url": url,
            "timeout": timeout,
            "body_keys": list(body.keys()) if isinstance(body, dict) else None,
        })

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Requested-With": self.USER_AGENT,
        }

        attempt = 0
        try:
            while True:
                t0 = time.time()
                if method.upper() == "GET":
                    resp = self.session.get(url, auth=self.auth, headers=headers, timeout=timeout)
                else:
                    resp = self.session.request(
                        method.upper(), url,
                        json=body if body is not None else {},
                        auth=self.auth, headers=headers, timeout=timeout,
                    )
                elapsed_ms = round((time.time() - t0) * 1000)

                for h_key, h_val in resp.headers.items():
                    if "x-ratelimit" in h_key.lower() or "x-concurrency" in h_key.lower():
                        self.rate_limits[h_key] = h_val

                self._log("HTTP_RESPONSE", {
                    "status": resp.status_code,
                    "elapsed_ms": elapsed_ms,
                    "content_length": len(resp.content),
                    "attempt": attempt + 1 if attempt else None,
                })

                if resp.status_code in (409, 429) and attempt < self.RATE_LIMIT_MAX_RETRIES:
                    retry_after = self._retry_after_seconds(resp)
                    self._log("RATE_LIMITED_RETRY", {
                        "status": resp.status_code,
                        "retry_after": retry_after,
                        "attempt": attempt + 1,
                        "max_attempts": self.RATE_LIMIT_MAX_RETRIES,
                    })
                    resp.close()
                    time.sleep(retry_after)
                    attempt += 1
                    continue

                if resp.status_code in (409, 429):
                    retry_after = self._retry_after_seconds(resp)
                    self._log("RATE_LIMITED_GIVEUP", {
                        "status": resp.status_code,
                        "retry_after": retry_after,
                        "attempts": attempt + 1,
                    })
                    return {"error": True, "status_code": resp.status_code,
                            "retry_after": retry_after,
                            "message": f"Rate limited after {attempt + 1} attempts"}

                break

            raw_text = resp.text
            try:
                parsed = json.loads(raw_text) if raw_text else {}
            except json.JSONDecodeError:
                parsed = {"raw_response": raw_text}

            if resp.status_code != 200:
                # Surface Qualys' responseErrorDetails when present
                err_detail = None
                svc = parsed.get("ServiceResponse") if isinstance(parsed, dict) else None
                if isinstance(svc, dict):
                    err_detail = svc.get("responseErrorDetails") or svc.get("responseCode")
                self._log("HTTP_ERROR", {
                    "status": resp.status_code,
                    "body_snippet": raw_text[:2000],
                })
                return {
                    "error": True,
                    "status_code": resp.status_code,
                    "message": err_detail or raw_text[:500],
                    "data": parsed,
                }

            # Success path. QPS REST also signals errors with responseCode != "SUCCESS"
            # at HTTP 200; surface those as errors too.
            svc = parsed.get("ServiceResponse") if isinstance(parsed, dict) else None
            if isinstance(svc, dict):
                code = svc.get("responseCode")
                if code and code != "SUCCESS":
                    self._log("QPS_ERROR", {"responseCode": code,
                                            "details": svc.get("responseErrorDetails")})
                    return {
                        "error": True,
                        "status_code": 200,
                        "message": svc.get("responseErrorDetails") or code,
                        "data": parsed,
                    }

            return {
                "error": False,
                "status_code": 200,
                "data": parsed,
                "raw_snippet": raw_text[:2000] if raw_text else None,
                "rate_limits": dict(self.rate_limits),
            }

        except requests.exceptions.Timeout:
            self._log("HTTP_TIMEOUT", {"timeout": timeout, "url": url})
            return {"error": True, "status_code": 0,
                    "message": f"Request timed out (timeout={timeout}s)"}
        except requests.exceptions.ConnectionError as e:
            self._log("HTTP_CONNECTION_ERROR", {"error": str(e)[:500], "url": url})
            return {"error": True, "status_code": 0, "message": f"Connection error: {e}"}
        except Exception as e:
            self._log("HTTP_EXCEPTION", {"error": str(e)[:500], "url": url})
            return {"error": True, "status_code": 0, "message": str(e)}

    @staticmethod
    def qps_extract_data(parsed: dict, wrapper: str) -> list:
        """Extract a list of objects from a QPS ServiceResponse.data list.

        QPS returns: ServiceResponse.data = [{"Tag": {...}}, {"Tag": {...}}]
        wrapper is the per-record key ('Tag', 'Asset', etc).
        """
        if not isinstance(parsed, dict):
            return []
        svc = parsed.get("ServiceResponse")
        if not isinstance(svc, dict):
            return []
        data = svc.get("data")
        if not data:
            return []
        if isinstance(data, dict):
            data = [data]
        out = []
        for entry in data:
            if isinstance(entry, dict):
                rec = entry.get(wrapper)
                if isinstance(rec, dict):
                    out.append(rec)
                elif isinstance(rec, list):
                    out.extend(r for r in rec if isinstance(r, dict))
        return out

    # ═══════════════════════════════════════════════════════════════════════
    # Gateway JWT (used by PM Catalog, Mitigations, and other gateway APIs)
    # ═══════════════════════════════════════════════════════════════════════

    def get_jwt(self, force_refresh: bool = False, timeout: int = 30) -> str | None:
        """Acquire (and cache) a JWT bearer token for the Qualys Gateway."""
        if self._jwt_token and not force_refresh:
            return self._jwt_token

        url = f"{self.gateway_base}/auth"
        body = (
            f"username={requests.utils.quote(self.username, safe='')}"
            f"&password={requests.utils.quote(self._password, safe='')}"
            f"&token=true"
        )
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": self.USER_AGENT,
        }

        self._log("HTTP_REQUEST", {"method": "POST", "url": url, "purpose": "gateway-jwt"})
        try:
            t0 = time.time()
            resp = self.session.post(url, data=body, headers=headers, timeout=timeout)
            elapsed_ms = round((time.time() - t0) * 1000)
            self._log("HTTP_RESPONSE", {"status": resp.status_code, "elapsed_ms": elapsed_ms,
                                        "content_length": len(resp.content)})
            if resp.status_code in (200, 201):
                token = resp.text.strip()
                if token:
                    self._jwt_token = token
                    return token
            self._log("JWT_AUTH_FAILED", {"status": resp.status_code,
                                          "body_snippet": resp.text[:500]})
            return None
        except Exception as e:
            self._log("JWT_AUTH_EXCEPTION", {"error": str(e)[:500]})
            return None

    def execute_gateway_json(
        self,
        path: str,
        body: dict | None = None,
        method: str = "POST",
        extra_headers: dict | None = None,
        timeout: int = 120,
    ) -> dict:
        """Execute a Gateway JSON API call with Bearer JWT auth.

        Returns the same shape as execute() / execute_json() so callers can
        branch on result['error'] uniformly.
        """
        token = self.get_jwt()
        if not token:
            return {"error": True, "status_code": 0,
                    "message": "Gateway JWT acquisition failed"}

        url = f"{self.gateway_base}{path}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Requested-With": self.USER_AGENT,
        }
        if extra_headers:
            headers.update(extra_headers)

        self._log("HTTP_REQUEST", {"method": method.upper(), "url": url,
                                   "body_keys": list(body.keys()) if isinstance(body, dict) else None,
                                   "extra_headers": list(extra_headers.keys()) if extra_headers else None})

        attempt = 0
        try:
            while True:
                t0 = time.time()
                if method.upper() == "GET":
                    resp = self.session.get(url, headers=headers, timeout=timeout)
                else:
                    resp = self.session.request(
                        method.upper(), url,
                        json=body if body is not None else {},
                        headers=headers, timeout=timeout,
                    )
                elapsed_ms = round((time.time() - t0) * 1000)
                self._log("HTTP_RESPONSE", {"status": resp.status_code, "elapsed_ms": elapsed_ms,
                                            "content_length": len(resp.content),
                                            "attempt": attempt + 1 if attempt else None})

                # 401 → JWT may have expired; one-shot retry with a fresh token
                if resp.status_code == 401 and not extra_headers and attempt == 0:
                    self._log("JWT_RETRY", {})
                    token = self.get_jwt(force_refresh=True)
                    if token:
                        headers["Authorization"] = f"Bearer {token}"
                        if method.upper() == "GET":
                            resp = self.session.get(url, headers=headers, timeout=timeout)
                        else:
                            resp = self.session.request(
                                method.upper(), url,
                                json=body if body is not None else {},
                                headers=headers, timeout=timeout,
                            )

                # Rate-limited (409 quota, 429 too-many) → honour Retry-After
                if resp.status_code in (409, 429) and attempt < self.RATE_LIMIT_MAX_RETRIES:
                    retry_after = self._retry_after_seconds(resp)
                    self._log("RATE_LIMITED_RETRY", {
                        "status": resp.status_code,
                        "retry_after": retry_after,
                        "attempt": attempt + 1,
                        "max_attempts": self.RATE_LIMIT_MAX_RETRIES,
                    })
                    resp.close()
                    time.sleep(retry_after)
                    attempt += 1
                    continue

                if resp.status_code in (409, 429):
                    retry_after = self._retry_after_seconds(resp)
                    self._log("RATE_LIMITED_GIVEUP", {
                        "status": resp.status_code,
                        "retry_after": retry_after,
                        "attempts": attempt + 1,
                    })
                    return {"error": True, "status_code": resp.status_code,
                            "retry_after": retry_after,
                            "message": f"Rate limited after {attempt + 1} attempts"}

                break

            raw_text = resp.text
            try:
                parsed = json.loads(raw_text) if raw_text else {}
            except json.JSONDecodeError:
                parsed = {"raw_response": raw_text}

            if resp.status_code != 200:
                self._log("HTTP_ERROR", {"status": resp.status_code,
                                          "body_snippet": raw_text[:2000]})
                return {"error": True, "status_code": resp.status_code,
                        "message": raw_text[:500], "data": parsed}

            return {
                "error": False,
                "status_code": 200,
                "data": parsed,
                "raw_snippet": raw_text[:2000],
                "response_headers": dict(resp.headers),
                "rate_limits": dict(self.rate_limits),
            }
        except requests.exceptions.Timeout:
            self._log("HTTP_TIMEOUT", {"timeout": timeout, "url": url})
            return {"error": True, "status_code": 0,
                    "message": f"Request timed out (timeout={timeout}s)"}
        except Exception as e:
            self._log("HTTP_EXCEPTION", {"error": str(e)[:500], "url": url})
            return {"error": True, "status_code": 0, "message": str(e)}

    def get_tag_detail(self, tag_id: int, timeout: int = 30) -> dict | None:
        """Fetch full detail for a single tag via QPS REST GET.

        The bulk search endpoint returns a slim subset of fields (id,
        name, color, ruleType, ruleText, parent, criticalityScore). The
        per-tag GET endpoint returns the full record including
        reservedType, createdBy, srcAssetGroupId, provider — exactly
        the fields needed to tell user-created tags apart from
        Qualys-managed system tags.

        Returns the parsed Tag dict, or None if the request failed or
        the response had no Tag entry.
        """
        result = self.execute_json(
            f"/qps/rest/2.0/get/am/tag/{int(tag_id)}",
            method="GET",
            timeout=timeout,
        )
        if result.get("error"):
            return None
        parsed = result.get("data", {}) or {}
        tags = self.qps_extract_data(parsed, "Tag")
        return tags[0] if tags else None

    # Fields that must NEVER ride along on a create-tag request.
    # Qualys assigns ids/timestamps; reservedType / created* would either
    # be rejected or cause the new tag to silently inherit the source
    # environment's metadata.
    _TAG_CREATE_STRIP = {
        "id", "ID", "tag_id", "tagId",
        "created", "modified",
        "reservedType", "reserved_type",
        "createdBy", "created_by", "creator",
        "lastModifiedBy", "lastModifiedDate",
        "srcAssetGroupId", "srcOperatingSystemName",
        "provider",
        # Local-only fields the app added on top of Qualys data
        "raw_json", "is_user_created", "is_user_created_auto",
        "is_editable", "is_editable_auto",
        "classification_override", "editability_override",
        "source_credential_id", "last_synced", "child_count",
        "parent_name", "breadcrumb", "parent", "children",
    }

    def create_tag(self, source_payload: dict,
                   *, new_name: str | None = None,
                   parent_tag_id: int | None = None,
                   timeout: int = 30) -> dict:
        """Create a tag in this client's Qualys environment from a payload
        captured by an earlier export.

        ``source_payload`` is the raw Tag dict the QPS REST GET endpoint
        returned for the source tag. We strip identifiers and Qualys-
        assigned metadata, optionally rename the tag and override its
        parent (parent ids don't transfer between environments — caller
        must resolve the destination parent up front).

        Returns ``{"created": True, "tag_id": <new_id>, "raw": ...}``
        on success, or ``{"error": True, "message": ...}``.
        """
        if not isinstance(source_payload, dict):
            return {"error": True, "message": "Invalid tag payload"}

        # Build the create body by copying-then-stripping rather than
        # whitelisting — keeps every legitimate Qualys field (ruleText,
        # ruleType, color, criticalityScore, description, etc.) without
        # this client needing to know the full Qualys schema.
        tag = {k: v for k, v in source_payload.items() if k not in self._TAG_CREATE_STRIP}

        # Caller-supplied overrides win over the source payload.
        if new_name:
            tag["name"] = new_name
        if parent_tag_id is not None:
            tag["parentTagId"] = int(parent_tag_id)
        elif "parentTagId" in tag:
            # Source's parentTagId points at the SOURCE env's id-space.
            # Drop it unless the caller resolved a destination parent;
            # otherwise the tag is created as a root and the operator
            # can re-parent it after.
            tag.pop("parentTagId", None)

        body = {"ServiceRequest": {"data": {"Tag": tag}}}
        result = self.execute_json(
            "/qps/rest/2.0/create/am/tag",
            body=body, method="POST", timeout=timeout,
        )
        if result.get("error"):
            return {"error": True, "message": result.get("message", "create-tag failed"),
                    "status_code": result.get("status_code"),
                    "raw": result.get("data")}

        parsed = result.get("data") or {}
        # Qualys responds with ServiceResponse.data.Tag.id when create
        # succeeded. responseCode != "SUCCESS" means a soft failure.
        svc = parsed.get("ServiceResponse") if isinstance(parsed, dict) else None
        code = (svc or {}).get("responseCode")
        if code and code != "SUCCESS":
            return {"error": True, "message": (svc or {}).get("responseErrorDetails", {})
                    .get("errorMessage", code), "raw": parsed}
        created = self.qps_extract_data(parsed, "Tag")
        if not created:
            return {"error": True, "message": "create-tag returned no Tag in response", "raw": parsed}
        try:
            new_id = int(created[0].get("id") or 0)
        except (TypeError, ValueError):
            new_id = 0
        return {"created": True, "tag_id": new_id, "raw": created[0]}

    def update_tag(self, tag_id: int, changes: dict, *, timeout: int = 30) -> dict:
        """Update fields on an existing tag in this Qualys environment.

        ``changes`` is a flat dict of QPS Tag fields the operator wants
        to change (name, ruleText, ruleType, color, criticalityScore,
        description, parentTagId). The same _TAG_CREATE_STRIP allow-list
        applies — Qualys-assigned ids/timestamps and source-env
        provenance must never ride along.

        Returns ``{"updated": True, "tag_id": <id>, "raw": ...}`` on
        success or ``{"error": True, "message": ...}`` on failure
        (HTTP error or non-SUCCESS responseCode).
        """
        if not isinstance(changes, dict) or not changes:
            return {"error": True, "message": "No changes supplied"}
        clean = {k: v for k, v in changes.items() if k not in self._TAG_CREATE_STRIP}
        if not clean:
            return {"error": True, "message": "All supplied fields are read-only"}

        body = {"ServiceRequest": {"data": {"Tag": clean}}}
        result = self.execute_json(
            f"/qps/rest/2.0/update/am/tag/{int(tag_id)}",
            body=body, method="POST", timeout=timeout,
        )
        if result.get("error"):
            return {"error": True, "message": result.get("message", "update-tag failed"),
                    "status_code": result.get("status_code"),
                    "raw": result.get("data")}
        parsed = result.get("data") or {}
        svc = parsed.get("ServiceResponse") if isinstance(parsed, dict) else None
        code = (svc or {}).get("responseCode")
        if code and code != "SUCCESS":
            return {"error": True, "message": (svc or {}).get("responseErrorDetails", {})
                    .get("errorMessage", code), "raw": parsed}
        updated = self.qps_extract_data(parsed, "Tag")
        raw = updated[0] if updated else {}
        return {"updated": True, "tag_id": int(tag_id), "raw": raw}

    def delete_tag(self, tag_id: int, *, timeout: int = 30) -> dict:
        """Delete a tag from this Qualys environment.

        Note: Qualys uses POST (not HTTP DELETE) for QPS REST delete
        operations. The body can be empty for a single-id delete.
        Cascading effects (child tags, asset assignments) are handled
        by Qualys server-side per the subscription's settings.
        """
        result = self.execute_json(
            f"/qps/rest/2.0/delete/am/tag/{int(tag_id)}",
            body={}, method="POST", timeout=timeout,
        )
        if result.get("error"):
            return {"error": True, "message": result.get("message", "delete-tag failed"),
                    "status_code": result.get("status_code"),
                    "raw": result.get("data")}
        parsed = result.get("data") or {}
        svc = parsed.get("ServiceResponse") if isinstance(parsed, dict) else None
        code = (svc or {}).get("responseCode")
        if code and code != "SUCCESS":
            return {"error": True, "message": (svc or {}).get("responseErrorDetails", {})
                    .get("errorMessage", code), "raw": parsed}
        return {"deleted": True, "tag_id": int(tag_id)}

    def evaluate_tag_payload(self, payload: dict, *, timeout: int = 30) -> dict:
        """Best-effort preview of a tag definition against this Qualys
        environment's asset universe — the server-side equivalent of
        the console's "Test rule" button.

        Returns one of:
          * {"ok": True, "asset_count": <int>, "raw": ...} on a
            successful preview
          * {"ok": False, "fallback": True, "message": "..."} when
            this tenant doesn't expose the preview endpoint (404 /
            405 / unknown shape) — the caller should treat that as
            "client-side validation only" rather than a hard failure
          * {"ok": False, "message": "..."} on a definite Qualys-side
            error (bad regex, invalid CIDR, etc.) so the operator can
            fix it before saving
        """
        if not isinstance(payload, dict):
            return {"ok": False, "message": "Invalid payload"}

        # Same strip set as create — preview must operate on a clean
        # forward-compatible body, not a raw round-trip of source-env
        # provenance.
        clean = {k: v for k, v in payload.items() if k not in self._TAG_CREATE_STRIP}
        body = {"ServiceRequest": {"data": {"Tag": clean}}}
        result = self.execute_json(
            "/qps/rest/2.0/evaluate/am/tag",
            body=body, method="POST", timeout=timeout,
        )
        # The evaluate endpoint isn't exposed on every Qualys tenant.
        # Treat 404 / 405 / "Resource not found" as a soft fallback so
        # the operator can still proceed with client-side validation
        # only — a hard failure here would block legitimate saves.
        if result.get("error"):
            status = result.get("status_code") or 0
            msg = (result.get("message") or "").lower()
            soft_miss = (status in (404, 405)
                         or "not found" in msg
                         or "not allowed" in msg
                         or "no resource" in msg)
            return {"ok": False, "fallback": soft_miss,
                    "message": result.get("message", "evaluate-tag failed"),
                    "status_code": status}
        parsed = result.get("data") or {}
        svc = parsed.get("ServiceResponse") if isinstance(parsed, dict) else None
        code = (svc or {}).get("responseCode")
        if code and code != "SUCCESS":
            return {"ok": False, "message": (svc or {}).get("responseErrorDetails", {})
                    .get("errorMessage", code), "raw": parsed}
        # Look for an asset count in any of the shapes Qualys uses.
        count = None
        if isinstance(svc, dict):
            count = svc.get("count")
            if count is None and isinstance(svc.get("data"), list):
                count = len(svc["data"])
        try:
            count = int(count) if count is not None else None
        except (TypeError, ValueError):
            count = None
        return {"ok": True, "asset_count": count, "raw": parsed}

    def qps_count(self, path: str, body: dict | None = None,
                  timeout: int = 30) -> int | None:
        """Call a QPS REST count endpoint and return ServiceResponse.count.

        Path should be like '/qps/rest/2.0/count/am/tag'. Body is the
        optional Criteria filter. Returns the count, or None if the call
        failed or the response shape was unexpected.
        """
        result = self.execute_json(
            path,
            body=body or {},
            method="POST",
            timeout=timeout,
        )
        if result.get("error"):
            return None
        parsed = result.get("data", {}) or {}
        svc = parsed.get("ServiceResponse") if isinstance(parsed, dict) else None
        if not isinstance(svc, dict):
            return None
        try:
            return int(svc.get("count"))
        except (TypeError, ValueError):
            return None

    def gateway_count(self, path: str, body: dict | None = None,
                      params: dict | None = None,
                      timeout: int = 30) -> int | None:
        """Best-effort count for Gateway endpoints (PM Catalog).

        The PM v2 API returns the total count as a response HEADER
        named 'count' (not in the JSON body). This method checks both
        the response headers and body for count fields.

        Returns None if no count can be determined — caller should
        fall back to progressive counting during the actual sync.
        """
        url = path
        if params:
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{qs}"
        result = self.execute_gateway_json(
            url, body=body or {}, method="POST", timeout=timeout,
        )
        if result.get("error"):
            return None

        # Check response headers first (PM v2 returns count here)
        headers = result.get("response_headers") or {}
        for key in ("count", "Count", "X-Total-Count", "x-total-count"):
            if key in headers:
                try:
                    return int(headers[key])
                except (TypeError, ValueError):
                    pass

        # Fallback: check JSON body
        parsed = result.get("data")
        if isinstance(parsed, dict):
            for key in ("count", "total", "totalRecords", "totalCount"):
                if key in parsed:
                    try:
                        return int(parsed[key])
                    except (TypeError, ValueError):
                        return None
        return None

    @staticmethod
    def qps_has_more(parsed: dict) -> tuple[bool, int | None]:
        """QPS REST uses hasMoreRecords + lastId for cursor pagination."""
        if not isinstance(parsed, dict):
            return False, None
        svc = parsed.get("ServiceResponse") or {}
        if not isinstance(svc, dict):
            return False, None
        has_more = str(svc.get("hasMoreRecords", "")).lower() == "true"
        last_id = svc.get("lastId")
        try:
            last_id = int(last_id) if last_id is not None else None
        except (TypeError, ValueError):
            last_id = None
        return has_more, last_id
