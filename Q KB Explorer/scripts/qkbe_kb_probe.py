#!/usr/bin/env python3
"""
Q KB Explorer — Knowledge Base API probe.

Runs a small set of diagnostic /api/4.0/fo/knowledge_base/vuln/ requests
to figure out why a sync count differs from the Qualys Console count.
Compares: default params vs show_disabled_flag=1 vs other relevant
flags, and probes the upper QID range to see how high the IDs actually go.

Usage:
    export QUALYS_USER='nttda3bc'
    export QUALYS_PASS='...'
    export QUALYS_API_BASE='https://qualysapi.qg3.apps.qualys.com'  # optional
    python3 scripts/qkbe_kb_probe.py

Paste the printed report back into the chat. No credentials are ever
written to disk by this script.
"""
from __future__ import annotations

import os
import re
import sys
import time
import urllib.parse
import urllib.request


def env(name: str, default: str = "") -> str:
    v = os.environ.get(name, default)
    if not v:
        sys.stderr.write(f"[!] Missing env var {name}\n")
        sys.exit(2)
    return v


USER = env("QUALYS_USER")
PASS = env("QUALYS_PASS")
BASE = os.environ.get("QUALYS_API_BASE", "https://qualysapi.qg3.apps.qualys.com").rstrip("/")
ENDPOINT = "/api/4.0/fo/knowledge_base/vuln/"


def post(form: dict, timeout: int = 120) -> tuple[int, str, dict]:
    """POST to the KB endpoint, return (status, body, response_headers)."""
    body = urllib.parse.urlencode(form).encode("utf-8")
    auth_raw = f"{USER}:{PASS}".encode("latin-1")
    import base64
    auth_hdr = "Basic " + base64.b64encode(auth_raw).decode("ascii")
    req = urllib.request.Request(
        BASE + ENDPOINT,
        data=body,
        method="POST",
        headers={
            "Authorization": auth_hdr,
            "X-Requested-With": "qkbe-kb-probe",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.getcode(), resp.read().decode("utf-8", errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace"), dict(e.headers or {})


_QID_RE = re.compile(r"<VULN>\s*<QID>(\d+)</QID>")


def count_qids(form: dict, timeout: int = 120) -> tuple[int, set, str]:
    """Run a request and return (qid_count, qid_set, warning_url_present)."""
    status, body, _ = post(form, timeout=timeout)
    if status != 200:
        snippet = body[:300].replace("\n", " ")
        return -1, set(), f"HTTP {status}: {snippet}"
    qids = set(int(m.group(1)) for m in _QID_RE.finditer(body))
    has_warn = "<WARNING>" in body and "<URL>" in body
    return len(qids), qids, ("WARNING/URL truncation present" if has_warn else "no truncation")


def banner(label: str):
    print()
    print("=" * 64)
    print(label)
    print("=" * 64)


def main():
    print(f"Q KB Explorer — KB API probe")
    print(f"  Base   : {BASE}")
    print(f"  User   : {USER}")
    print(f"  Run UTC: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print()

    # 1. Tiny range, default params (mirror current sync's pre-count without disabled flag)
    banner("PROBE 1: Default params, id_min=1..99999, details=Basic")
    n, _, note = count_qids({
        "action": "list", "details": "Basic",
        "id_min": "1", "id_max": "99999",
    })
    print(f"  QIDs returned: {n}    [{note}]")
    base_count = n

    # 2. Same range with show_disabled_flag=1
    banner("PROBE 2: show_disabled_flag=1, id_min=1..99999, details=Basic")
    n, _, note = count_qids({
        "action": "list", "details": "Basic",
        "show_disabled_flag": "1",
        "id_min": "1", "id_max": "99999",
    })
    print(f"  QIDs returned: {n}    [{note}]")
    if base_count > 0:
        delta = n - base_count
        print(f"  Δ vs default: {'+' if delta >= 0 else ''}{delta} ({delta * 100 / max(base_count,1):.1f}% change)")

    # 3. Probe high range to see if QIDs exceed our 2M ceiling
    banner("PROBE 3: high-range scan, show_disabled_flag=1, details=Basic")
    for lo, hi in [(400000, 499999), (500000, 599999), (700000, 799999),
                   (1000000, 1099999), (1500000, 1599999), (1900000, 1999999)]:
        n, ids, note = count_qids({
            "action": "list", "details": "Basic",
            "show_disabled_flag": "1",
            "id_min": str(lo), "id_max": str(hi),
        })
        sample = sorted(ids)[:3] if ids else []
        print(f"  id_min={lo:>7} id_max={hi:>7}: {n} QIDs    sample={sample}")

    # 4. Total full-range count (this is the real test)
    banner("PROBE 4: FULL RANGE 1..2,000,000, details=Basic, show_disabled_flag=1")
    print("  (this may take a while — the response is paginated by Qualys via WARNING/URL)")
    n, _, note = count_qids({
        "action": "list", "details": "Basic",
        "show_disabled_flag": "1",
        "id_min": "1", "id_max": "2000000",
    }, timeout=300)
    print(f"  QIDs in first response: {n}    [{note}]")
    print(f"  (if {note!r} mentions truncation, Qualys is paginating — full count requires")
    print(f"   following WARNING/URL links; this probe only counts the first page.)")

    # 5. Sanity probe: id range covering Qualys-known low and high QIDs
    banner("PROBE 5: targeted small ranges to confirm density")
    for lo, hi in [(38000, 38999), (90000, 90999), (380000, 380999)]:
        n, ids, _ = count_qids({
            "action": "list", "details": "Basic",
            "show_disabled_flag": "1",
            "id_min": str(lo), "id_max": str(hi),
        })
        sample = sorted(ids)[:5] if ids else []
        print(f"  id_min={lo} id_max={hi}: {n} QIDs    sample={sample}")

    print()
    print("Done. Paste this entire output back into the chat for analysis.")


if __name__ == "__main__":
    main()
