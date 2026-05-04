#!/usr/bin/env python3
"""
Q KB Explorer — Patch Management API Test Script
=================================================

Purpose: Directly call the Qualys PM v2 API to understand the response
format, pagination, and data structure. Outputs raw responses so we can
verify our sync/parse logic matches reality.

Usage:
    python3 scripts/test_pm_api.py

Will prompt for credentials if not set as environment variables:
    QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_API_URL, QUALYS_GATEWAY_URL
"""

import json
import sys
import os
import time
import getpass

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.qualys_client import QualysClient


def get_client():
    """Get credentials from env vars or prompt the user."""
    api_url = os.environ.get("QUALYS_API_URL", "").strip()
    gateway_url = os.environ.get("QUALYS_GATEWAY_URL", "").strip()
    username = os.environ.get("QUALYS_USERNAME", "").strip()
    password = os.environ.get("QUALYS_PASSWORD", "").strip()

    if not api_url:
        api_url = input("Qualys API URL (e.g. https://qualysapi.qg3.apps.qualys.com): ").strip()
    if not gateway_url:
        gateway_url = input("Qualys Gateway URL (e.g. https://gateway.qg3.apps.qualys.com): ").strip()
    if not username:
        username = input("Username: ").strip()
    if not password:
        password = getpass.getpass("Password: ")

    print(f"\nConnecting to:")
    print(f"  API:     {api_url}")
    print(f"  Gateway: {gateway_url}")
    print(f"  User:    {username}")

    client = QualysClient(api_url, username, password)
    # Set gateway URL
    client.gateway_base = gateway_url
    return client


def test_jwt(client: QualysClient):
    """Test JWT acquisition for gateway APIs."""
    print("\n" + "=" * 60)
    print("TEST 1: JWT Acquisition")
    print("=" * 60)
    token = client.get_jwt()
    if token:
        print(f"  ✓ JWT acquired (length: {len(token)})")
        print(f"  Token prefix: {token[:60]}...")
        return True
    else:
        print("  ✗ JWT acquisition FAILED")
        print("  Check: gateway_url, username, password")
        return False


def test_pm_count(client: QualysClient):
    """Test the PM count endpoint."""
    print("\n" + "=" * 60)
    print("TEST 2: PM Patch Count Endpoint")
    print("=" * 60)

    for platform in ("Windows", "Linux"):
        print(f"\n  --- Platform: {platform} ---")

        # Try /pm/v2/patches/count
        count = client.gateway_count(
            "/pm/v2/patches/count",
            body={"query": "isSuperseded:false"},
            params={"platform": platform},
            timeout=30,
        )
        if count is not None:
            print(f"  ✓ Count via /pm/v2/patches/count: {count}")
        else:
            print(f"  ✗ /pm/v2/patches/count returned None")

        # Raw call to see full response
        print(f"\n  Raw count endpoint response:")
        result = client.execute_gateway_json(
            f"/pm/v2/patches/count?platform={platform}",
            body={"query": "isSuperseded:false"},
            method="POST",
            timeout=30,
        )
        if result.get("error"):
            print(f"    Error ({result.get('status_code')}): {result.get('message', 'unknown')[:300]}")
        else:
            data = result.get("data", {})
            print(f"    Status: {result.get('status_code')}")
            print(f"    Response type: {type(data).__name__}")
            if isinstance(data, dict):
                print(f"    Keys: {sorted(data.keys())}")
            print(f"    Full: {json.dumps(data, indent=2)[:500]}")


def test_pm_search_first_page(client: QualysClient):
    """Fetch the first page of PM patches to examine the response structure."""
    print("\n" + "=" * 60)
    print("TEST 3: PM Patch Search — First Page (pageSize=5)")
    print("=" * 60)

    for platform in ("Windows", "Linux"):
        print(f"\n  --- Platform: {platform} ---")
        url_path = f"/pm/v2/patches?platform={platform}&pageSize=5"
        body = {"query": "isSuperseded:false"}

        result = client.execute_gateway_json(
            url_path,
            body=body,
            method="POST",
            timeout=60,
        )

        if result.get("error"):
            print(f"  ✗ Error ({result.get('status_code')}): {result.get('message', 'unknown')[:300]}")
            if result.get("data"):
                print(f"    Error data: {json.dumps(result['data'], indent=2)[:500]}")
            continue

        data = result.get("data", {})
        headers = result.get("response_headers", {})

        print(f"  ✓ Status: {result.get('status_code')}")
        print(f"  Response type: {type(data).__name__}")

        # Determine where the patches are in the response
        patches = []
        if isinstance(data, list):
            patches = data
            print(f"  Response is a flat array: {len(data)} items")
        elif isinstance(data, dict):
            print(f"  Response keys: {sorted(data.keys())}")
            # Try common nesting patterns
            for key in ("patches", "data", "results", "items", "records", "content"):
                if key in data and isinstance(data[key], list):
                    patches = data[key]
                    print(f"  Found patches under '{key}': {len(patches)} items")
                    break
            if not patches:
                print(f"  Full response (first 2000 chars):")
                print(f"  {json.dumps(data, indent=2)[:2000]}")

        if patches:
            print(f"\n  First patch keys: {sorted(patches[0].keys())}")
            print(f"\n  === FIRST PATCH (FULL) ===")
            print(json.dumps(patches[0], indent=2))
            if len(patches) > 1:
                print(f"\n  === SECOND PATCH (FULL) ===")
                print(json.dumps(patches[1], indent=2))

        # Pagination headers
        print(f"\n  === RESPONSE HEADERS ===")
        for k, v in sorted(headers.items()):
            print(f"    {k}: {str(v)[:150]}")


def test_pm_different_queries(client: QualysClient):
    """Try different QQL queries to understand the API behavior."""
    print("\n" + "=" * 60)
    print("TEST 4: Different QQL Queries")
    print("=" * 60)

    queries = [
        ("All patches (no filter)", {}),
        ("Non-superseded", {"query": "isSuperseded:false"}),
        ("Security patches only", {"query": "isSecurity:true"}),
        ("With empty body", None),
    ]

    for label, body in queries:
        print(f"\n  --- {label} ---")
        print(f"  Body: {json.dumps(body)}")
        url_path = "/pm/v2/patches?platform=Windows&pageSize=2"

        result = client.execute_gateway_json(
            url_path,
            body=body if body is not None else {},
            method="POST",
            timeout=30,
        )

        if result.get("error"):
            print(f"  ✗ Error ({result.get('status_code')}): {result.get('message', '')[:200]}")
        else:
            data = result.get("data", {})
            if isinstance(data, list):
                print(f"  ✓ Got {len(data)} patches")
            elif isinstance(data, dict):
                for key in ("patches", "data", "results", "items", "content"):
                    if key in data and isinstance(data[key], list):
                        print(f"  ✓ Got {len(data[key])} patches (under '{key}')")
                        break
                else:
                    print(f"  ? Response keys: {sorted(data.keys())}")


def test_pm_get_vs_post(client: QualysClient):
    """Test if GET works differently than POST."""
    print("\n" + "=" * 60)
    print("TEST 5: GET vs POST")
    print("=" * 60)

    url_path = "/pm/v2/patches?platform=Windows&pageSize=2"

    for method in ("GET", "POST"):
        print(f"\n  --- Method: {method} ---")
        result = client.execute_gateway_json(
            url_path,
            body={"query": "isSuperseded:false"} if method == "POST" else None,
            method=method,
            timeout=30,
        )
        if result.get("error"):
            print(f"  ✗ Error ({result.get('status_code')}): {result.get('message', '')[:200]}")
        else:
            data = result.get("data", {})
            print(f"  ✓ Status {result.get('status_code')}, type={type(data).__name__}")
            if isinstance(data, list):
                print(f"    Items: {len(data)}")
            elif isinstance(data, dict):
                print(f"    Keys: {sorted(data.keys())}")


def save_sample_output(client: QualysClient):
    """Save a larger sample to disk for offline analysis."""
    print("\n" + "=" * 60)
    print("TEST 6: Save Full Sample to Disk (50 per platform)")
    print("=" * 60)

    output = {"windows": [], "linux": [], "metadata": {}}
    output["metadata"]["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for platform in ("Windows", "Linux"):
        url_path = f"/pm/v2/patches?platform={platform}&pageSize=50"
        body = {"query": "isSuperseded:false"}
        result = client.execute_gateway_json(url_path, body=body, method="POST", timeout=120)

        if result.get("error"):
            print(f"  ✗ {platform} fetch failed: {result.get('message')[:200]}")
            output[platform.lower()] = {"error": result.get("message")}
            continue

        data = result.get("data", {})
        if isinstance(data, list):
            patches = data
        elif isinstance(data, dict):
            patches = None
            for key in ("patches", "data", "results", "items", "content"):
                if key in data and isinstance(data[key], list):
                    patches = data[key]
                    break
            if patches is None:
                patches = [data]
        else:
            patches = []

        output[platform.lower()] = patches
        output["metadata"][f"{platform.lower()}_count"] = len(patches)
        output["metadata"][f"{platform.lower()}_headers"] = result.get("response_headers", {})
        print(f"  ✓ {platform}: {len(patches)} patches fetched")

        # Show field summary
        if patches:
            all_keys = set()
            for p in patches:
                all_keys.update(p.keys())
            print(f"    All fields across {len(patches)} patches: {sorted(all_keys)}")

            # QID linkage analysis
            qid_count = sum(1 for p in patches if p.get("qids") or p.get("qid") or p.get("vulnQids"))
            cve_count = sum(1 for p in patches if p.get("cves") or p.get("cve") or p.get("cveList"))
            print(f"    Patches with QID links: {qid_count}/{len(patches)}")
            print(f"    Patches with CVE links: {cve_count}/{len(patches)}")

    outfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pm_api_sample.json")
    with open(outfile, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Saved to: {outfile}")
    print(f"  File size: {os.path.getsize(outfile):,} bytes")


def main():
    print("Q KB Explorer — PM API Test Script")
    print("=" * 60)

    client = get_client()

    # Run tests in sequence
    if not test_jwt(client):
        print("\nABORTING: Cannot proceed without JWT.")
        sys.exit(1)

    test_pm_count(client)
    test_pm_search_first_page(client)
    test_pm_different_queries(client)
    test_pm_get_vs_post(client)
    save_sample_output(client)

    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETE")
    print("=" * 60)
    print("\nReview scripts/pm_api_sample.json for the full data structure.")
    print("Key things to look for:")
    print("  1. How QIDs are linked (field name: qids? vulnQids? qualysQids?)")
    print("  2. How CVEs are linked (field name: cves? cveList? cveIds?)")
    print("  3. Pagination cursor (searchAfter header)")
    print("  4. Platform detection (what field distinguishes Windows vs Linux)")
    print("  5. KB article field (kb? kbArticle? kbId?)")
    print("  6. Package names for Linux (packageDetails? packages?)")


if __name__ == "__main__":
    main()
