"""
Q KB Explorer — Tests
Tests Flask routes, credential vault, platform registry, database layer,
and data API routes.
"""

import json
import os
import tempfile
import pytest

# Point vault and database at temp directories so tests don't touch real data
_tmpdir = tempfile.mkdtemp()
os.environ["QAE_KEY_DIR"] = os.path.join(_tmpdir, "keys")
os.environ["QAE_DATA_DIR"] = os.path.join(_tmpdir, "data")
os.environ["QKBE_DB_PATH"] = os.path.join(_tmpdir, "data", "qkbe.db")
os.makedirs(os.environ["QAE_KEY_DIR"], exist_ok=True)
os.makedirs(os.environ["QAE_DATA_DIR"], exist_ok=True)

from app.main import app, _active_sessions  # noqa: E402

_TEST_SESSION_TOKEN = "test-session-token-for-pytest"


@pytest.fixture
def client():
    app.config["TESTING"] = True
    # Register a valid session token so auth gate passes
    _active_sessions[_TEST_SESSION_TOKEN] = True
    with app.test_client() as c:
        c.set_cookie("qkbe-vault-unlocked", _TEST_SESSION_TOKEN)
        yield c
    _active_sessions.pop(_TEST_SESSION_TOKEN, None)


@pytest.fixture
def unauthed_client():
    """Client WITHOUT the vault unlock cookie — for auth gate tests."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ── Page Routes ───────────────────────────────────────────────────────────

def test_index_returns_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Q KB Explorer" in resp.data


# ── Platform Registry ─────────────────────────────────────────────────────

def test_platforms_returns_all(client):
    resp = client.get("/api/platforms")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "US1" in data
    assert "EU1" in data
    assert "KSA1" in data
    assert len(data) == 13


def test_platform_has_api_and_gateway(client):
    resp = client.get("/api/platforms")
    data = resp.get_json()
    for key, plat in data.items():
        assert "api" in plat, f"{key} missing 'api' URL"
        assert "gateway" in plat, f"{key} missing 'gateway' URL"
        assert plat["api"].startswith("https://")
        assert plat["gateway"].startswith("https://")


# ── Sync Status Stub ──────────────────────────────────────────────────────

def test_sync_status_stub(client):
    resp = client.get("/api/sync/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "qids" in data
    assert "cids" in data
    assert "policies" in data
    assert "mandates" in data
    assert data["qids"]["record_count"] == 0
    assert data["qids"]["last_sync"] is None


# ── Credential Vault ──────────────────────────────────────────────────────

def test_credentials_list_empty(client):
    resp = client.get("/api/credentials")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)


def test_credentials_save_requires_fields(client):
    resp = client.post("/api/credentials", json={})
    assert resp.status_code == 400
    assert "required" in resp.get_json()["error"].lower()


def test_credentials_save_and_list(client):
    resp = client.post("/api/credentials", json={
        "username": "testuser",
        "password": "testpass123",
        "platform": "US1",
        "api_version": "v5",
    })
    assert resp.status_code == 200
    saved = resp.get_json()
    assert saved["username"] == "testuser"
    assert saved["platform"] == "US1"
    assert "id" in saved
    # Password should NOT be in the response
    assert "password" not in saved or saved.get("password") is None

    # Should appear in list
    resp2 = client.get("/api/credentials")
    creds = resp2.get_json()
    assert any(c["username"] == "testuser" for c in creds)


def test_credentials_update(client):
    # Save first
    resp = client.post("/api/credentials", json={
        "username": "updateuser",
        "password": "pass456",
        "platform": "US1",
    })
    cred_id = resp.get_json()["id"]

    # Update platform
    resp2 = client.patch(f"/api/credentials/{cred_id}", json={
        "platform": "EU1",
        "api_version": "v2",
    }, headers={"X-Requested-With": "QKBE"})
    assert resp2.status_code == 200
    assert resp2.get_json()["platform"] == "EU1"


def test_credentials_delete(client):
    # Save
    resp = client.post("/api/credentials", json={
        "username": "deluser",
        "password": "pass789",
    })
    cred_id = resp.get_json()["id"]

    # Delete
    resp2 = client.delete(f"/api/credentials/{cred_id}", headers={"X-Requested-With": "QKBE"})
    assert resp2.status_code == 200
    assert resp2.get_json()["deleted"] is True

    # Delete again → 404
    resp3 = client.delete(f"/api/credentials/{cred_id}", headers={"X-Requested-With": "QKBE"})
    assert resp3.status_code == 404


def test_credentials_delete_nonexistent(client):
    resp = client.delete("/api/credentials/nonexistent-id", headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 404


def test_credentials_verify(client):
    # Save
    resp = client.post("/api/credentials", json={
        "username": "verifyuser",
        "password": "correct-pass",
    })
    cred_id = resp.get_json()["id"]

    # Correct password
    resp2 = client.post("/api/credentials/verify", json={
        "id": cred_id,
        "password": "correct-pass",
    })
    assert resp2.status_code == 200
    assert resp2.get_json()["verified"] is True

    # Wrong password
    resp3 = client.post("/api/credentials/verify", json={
        "id": cred_id,
        "password": "wrong-pass",
    })
    assert resp3.status_code == 401
    assert resp3.get_json()["verified"] is False


def test_credentials_verify_missing_fields(client):
    resp = client.post("/api/credentials/verify", json={})
    assert resp.status_code == 400


# ── Test Connection ───────────────────────────────────────────────────────

def test_connection_missing_fields(client):
    resp = client.post("/api/test-connection", json={}, headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 400


def test_connection_unknown_platform(client):
    resp = client.post("/api/test-connection", json={
        "username": "fake",
        "password": "fake",
        "platform": "INVALID",
    }, headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 400
    assert "Unknown platform" in resp.get_json()["error"]


def test_connection_raw_creds_missing_password(client):
    resp = client.post("/api/test-connection", json={
        "username": "user",
        "platform": "US1",
    }, headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 400
    assert "password" in resp.get_json()["error"].lower()


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2 — Database Layer Tests
# ═══════════════════════════════════════════════════════════════════════════

from app.database import (  # noqa: E402
    upsert_vuln, search_vulns, get_vuln,
    upsert_control, search_controls, get_control,
    upsert_policy, search_policies, get_policy,
    upsert_mandate, upsert_mandate_control, search_mandates, get_mandate, get_mandate_filter_values,
    get_sync_status, update_sync_state,
    store_policy_export, get_policy_export_xml, get_stale_exports,
)


# ── QID Database Tests ────────────────────────────────────────────────────

def test_upsert_and_get_vuln():
    upsert_vuln({
        "QID": "12345",
        "VULN_TYPE": "Vulnerability",
        "SEVERITY_LEVEL": "4",
        "TITLE": "Test Vulnerability XSS in Widget",
        "CATEGORY": "CGI",
        "PATCHABLE": "1",
        "PCI_FLAG": "0",
        "DIAGNOSIS": "This is a test diagnosis.",
        "CONSEQUENCE": "Attacker can steal cookies.",
        "SOLUTION": "Update to the latest version.",
        "PUBLISHED_DATETIME": "2024-01-15T00:00:00Z",
        "CVE_LIST": {
            "CVE": [
                {"ID": "CVE-2024-1234", "URL": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234"},
                {"ID": "CVE-2024-5678", "URL": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-5678"},
            ]
        },
        "CVSS": {"BASE": "7.5", "TEMPORAL": "6.2"},
        "CVSS_V3": {"BASE": "8.1", "TEMPORAL": "7.0", "CVSS3_VERSION": "3.1"},
    })

    vuln = get_vuln(12345)
    assert vuln is not None
    assert vuln["title"] == "Test Vulnerability XSS in Widget"
    assert vuln["severity_level"] == 4
    assert vuln["patchable"] == 1
    assert len(vuln["cves"]) == 2
    assert vuln["cves"][0]["cve_id"] == "CVE-2024-1234"
    assert vuln["cvss_base"] == 7.5
    assert vuln["cvss3_base"] == 8.1


def test_upsert_vuln_handles_cvss_with_xml_attributes():
    # Qualys returns `<BASE source="cve">5.0</BASE>`, which xmltodict
    # parses into `{"@source": "cve", "#text": "5.0"}`. Regression for
    # `float() argument must be a string or a real number, not 'dict'`.
    upsert_vuln({
        "QID": "12346",
        "TITLE": "CVSS-with-attrs",
        "SEVERITY_LEVEL": "3",
        "CVSS": {
            "BASE": {"@source": "cve", "#text": "5.0"},
            "TEMPORAL": {"@source": "cve", "#text": "4.1"},
        },
        "CVSS_V3": {
            "BASE": {"@source": "nvd", "#text": "6.4"},
            "TEMPORAL": {"@source": "nvd", "#text": "5.5"},
        },
    })
    vuln = get_vuln(12346)
    assert vuln is not None
    assert vuln["cvss_base"] == 5.0
    assert vuln["cvss_temporal"] == 4.1
    assert vuln["cvss3_base"] == 6.4
    assert vuln["cvss3_temporal"] == 5.5


def test_backfill_threat_columns_tolerates_malformed_correlation_json():
    # Regression for the crashloop where _backfill_threat_columns blew up
    # on init_db() because correlation_json had EXPLT_SRC as a bare string
    # (xmltodict's collapsed text-only-element shape). One malformed row
    # must not abort the backfill — and must not crash startup.
    import json as _json
    from app.database import _backfill_threat_columns, get_db, upsert_vuln, get_vuln

    upsert_vuln({"QID": "55001", "TITLE": "Bad EXPLT_SRC", "SEVERITY_LEVEL": "3"})
    upsert_vuln({"QID": "55002", "TITLE": "Bad MW_SRC", "SEVERITY_LEVEL": "3"})
    upsert_vuln({"QID": "55003", "TITLE": "Good shape", "SEVERITY_LEVEL": "3"})

    bad_explt = _json.dumps({"EXPLOITS": {"EXPLT_SRC": "unexpected-string"}})
    bad_mw = _json.dumps({"MALWARE": {"MW_SRC": "unexpected-string"}})
    good = _json.dumps({
        "EXPLOITS": {"EXPLT_SRC": {"EXPLT_LIST": {"EXPLT": [{"REF": "EDB-1"}, {"REF": "EDB-2"}]}}},
    })
    ti = _json.dumps({"THREAT_INTEL": [{"#text": "Active_Attacks"}]})

    with get_db() as conn:
        for qid, corr in ((55001, bad_explt), (55002, bad_mw), (55003, good)):
            conn.execute(
                "UPDATE vulns SET correlation_json = ?, threat_intelligence_json = ? WHERE qid = ?",
                (corr, ti, qid),
            )
        # Must not raise.
        _backfill_threat_columns(conn)

    # Bad rows survive with zeroed exploit_count; good row is computed correctly.
    assert get_vuln(55001)["exploit_count"] == 0
    assert get_vuln(55002)["exploit_count"] == 0
    assert get_vuln(55003)["exploit_count"] == 2
    # Threat-intel flag still backfills on the bad rows.
    assert get_vuln(55001)["threat_active_attacks"] == 1


def test_upsert_vuln_handles_correlation_shape_variations():
    # Regression for the QID Full Sync abort: upsert_vuln must tolerate
    # all shapes xmltodict can produce for CORRELATION.EXPLOITS.EXPLT_SRC
    # (and the MALWARE.MW_SRC twin) — dict, list-of-dicts, bare string,
    # or None entries from empty self-closing elements.
    from app.database import upsert_vuln, get_vuln

    # Case 1: None entries mixed with valid dicts in the list
    upsert_vuln({
        "QID": "60001", "TITLE": "None in EXPLT_SRC", "SEVERITY_LEVEL": "3",
        "CORRELATION": {
            "EXPLOITS": {"EXPLT_SRC": [None, {"EXPLT_LIST": {"EXPLT": [{"REF": "EDB-1"}]}}, None]},
            "MALWARE": {"MW_SRC": [None]},
        },
    })

    # Case 2: bare-string EXPLT_SRC (the #5 shape)
    upsert_vuln({
        "QID": "60002", "TITLE": "String EXPLT_SRC", "SEVERITY_LEVEL": "3",
        "CORRELATION": {"EXPLOITS": {"EXPLT_SRC": "unexpected-string"}},
    })

    # Case 3: EXPLT_LIST itself is None (empty self-closing element)
    upsert_vuln({
        "QID": "60003", "TITLE": "None EXPLT_LIST", "SEVERITY_LEVEL": "3",
        "CORRELATION": {"EXPLOITS": {"EXPLT_SRC": {"EXPLT_LIST": None}}},
    })

    # Case 4: single dict (xmltodict's "one entry" shape) still works
    upsert_vuln({
        "QID": "60004", "TITLE": "Single dict EXPLT_SRC", "SEVERITY_LEVEL": "3",
        "CORRELATION": {
            "EXPLOITS": {"EXPLT_SRC": {"EXPLT_LIST": {"EXPLT": {"REF": "EDB-99"}}}},
            "MALWARE": {"MW_SRC": {"MW_LIST": {"MW_INFO": [{"NAME": "X"}, {"NAME": "Y"}]}}},
        },
    })

    assert get_vuln(60001)["exploit_count"] == 1
    assert get_vuln(60002)["exploit_count"] == 0
    assert get_vuln(60003)["exploit_count"] == 0
    assert get_vuln(60004)["exploit_count"] == 1
    assert get_vuln(60004)["malware_count"] == 2


def test_search_vulns_fts():
    # Insert a couple of vulns
    upsert_vuln({"QID": "100", "TITLE": "Apache Struts Remote Code Execution", "SEVERITY_LEVEL": "5", "CATEGORY": "Web Server"})
    upsert_vuln({"QID": "101", "TITLE": "OpenSSL Heartbleed Buffer Over-read", "SEVERITY_LEVEL": "4", "CATEGORY": "General"})

    # FTS search
    result = search_vulns(q="Struts")
    assert result["total"] >= 1
    assert any(r["qid"] == 100 for r in result["results"])

    # Severity filter
    result2 = search_vulns(severity=5)
    assert all(r["severity_level"] == 5 for r in result2["results"])


def test_search_vulns_cve_filter():
    # Search by CVE (from the vuln inserted in test_upsert_and_get_vuln)
    result = search_vulns(cves=["CVE-2024-1234"])
    assert result["total"] >= 1
    assert any(r["qid"] == 12345 for r in result["results"])


def test_search_vulns_pagination():
    result = search_vulns(page=1, per_page=2)
    assert result["per_page"] == 2
    assert len(result["results"]) <= 2
    assert result["pages"] >= 1


def test_get_vuln_nonexistent():
    assert get_vuln(999999) is None


# ── CID Database Tests ────────────────────────────────────────────────────

def test_upsert_and_get_control():
    upsert_control({
        "ID": "5001",
        "CATEGORY": "Access Control",
        "SUB_CATEGORY": "Authentication",
        "STATEMENT": "Verify password complexity requirements",
        "CRITICALITY": {"LABEL": "CRITICAL", "VALUE": "5"},
        "CHECK_TYPE": "Registry",
        "COMMENT": "Checks Windows password policy",
        "TECHNOLOGY_LIST": {
            "TECHNOLOGY": [
                {"TECH_ID": "1", "TECH_NAME": "Windows Server 2019", "RATIONALE": "Default policy"},
            ]
        },
    })

    ctrl = get_control(5001)
    assert ctrl is not None
    assert ctrl["category"] == "Access Control"
    assert ctrl["criticality_value"] == 5
    assert len(ctrl["technologies"]) == 1
    assert ctrl["technologies"][0]["tech_name"] == "Windows Server 2019"


def test_search_controls_fts():
    result = search_controls(q="password complexity")
    assert result["total"] >= 1
    assert any(r["cid"] == 5001 for r in result["results"])


def test_get_control_nonexistent():
    assert get_control(999999) is None


# ── Policy Database Tests ─────────────────────────────────────────────────

def test_upsert_and_get_policy():
    upsert_policy({
        "ID": "8001",
        "TITLE": "CIS Windows Server 2019 L1",
        "STATUS": "Active",
        "CREATED_DATETIME": "2024-01-01T00:00:00Z",
        "CREATED_BY": "admin",
        "LAST_MODIFIED_DATETIME": "2024-06-01T00:00:00Z",
        "LAST_MODIFIED_BY": "admin",
        "CONTROL_LIST": {
            "CONTROL": [
                {"CID": "5001", "STATEMENT": "Password policy", "CRITICALITY": {"LABEL": "CRITICAL", "VALUE": "5"}},
            ]
        },
    })

    pol = get_policy(8001)
    assert pol is not None
    assert pol["title"] == "CIS Windows Server 2019 L1"
    assert pol["status"] == "Active"
    assert len(pol["controls"]) == 1
    assert pol["controls"][0]["cid"] == 5001


def test_search_policies():
    result = search_policies(q="CIS Windows")
    assert result["total"] >= 1
    assert any(r["policy_id"] == 8001 for r in result["results"])


def test_get_policy_nonexistent():
    assert get_policy(999999) is None


# ── Policy Export Storage ─────────────────────────────────────────────────

def test_store_and_retrieve_policy_export():
    xml_data = b"<POLICY><ID>8001</ID><TITLE>Test</TITLE></POLICY>"
    store_policy_export(8001, xml_data, includes_udcs=True)

    retrieved = get_policy_export_xml(8001)
    assert retrieved == xml_data

    # Detail should show has_export=True
    pol = get_policy(8001)
    assert pol["has_export"] is True


def test_stale_exports():
    # Policy 8001 was modified 2024-06-01, export was just stored (now)
    # So it shouldn't be stale. Let's make it stale by updating modified date.
    from app.database import get_db
    with get_db() as conn:
        conn.execute(
            "UPDATE policies SET last_modified_datetime='2099-01-01T00:00:00Z' WHERE policy_id=8001"
        )
    stale = get_stale_exports()
    assert any(s["policy_id"] == 8001 for s in stale)


# ── Sync State Tests ──────────────────────────────────────────────────────

def test_sync_state():
    status = get_sync_status()
    assert "qids" in status
    assert "cids" in status
    assert "policies" in status

    update_sync_state("qids", is_full=True, credential_id="test-cred")
    status2 = get_sync_status()
    assert status2["qids"]["last_sync"] is not None
    assert status2["qids"]["last_full_sync"] is not None
    assert status2["qids"]["credential_id"] == "test-cred"


# ── CID → Policy Cross-reference ─────────────────────────────────────────

def test_control_linked_policies():
    ctrl = get_control(5001)
    assert ctrl is not None
    # CID 5001 is in policy 8001
    assert len(ctrl["linked_policies"]) >= 1
    assert any(p["policy_id"] == 8001 for p in ctrl["linked_policies"])


# ── API Route Tests (data endpoints) ─────────────────────────────────────

def test_qids_search_route(client):
    resp = client.get("/api/qids?q=XSS")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "results" in data
    assert "total" in data


def test_qids_detail_route(client):
    resp = client.get("/api/qids/12345")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["qid"] == 12345


def test_qids_detail_404(client):
    resp = client.get("/api/qids/999999")
    assert resp.status_code == 404


def test_cids_search_route(client):
    resp = client.get("/api/cids?q=password")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "results" in data


def test_cids_detail_route(client):
    resp = client.get("/api/cids/5001")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["cid"] == 5001


def test_cids_detail_404(client):
    resp = client.get("/api/cids/999999")
    assert resp.status_code == 404


def test_policies_search_route(client):
    resp = client.get("/api/policies?q=CIS")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "results" in data


def test_policies_detail_route(client):
    resp = client.get("/api/policies/8001")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["policy_id"] == 8001


def test_policies_detail_404(client):
    resp = client.get("/api/policies/999999")
    assert resp.status_code == 404


def test_sync_status_route(client):
    resp = client.get("/api/sync/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "qids" in data
    assert "syncing" in data["qids"]
    assert "needs_full_refresh" in data["qids"]


def test_sync_trigger_missing_creds(client):
    resp = client.post("/api/sync/qids", json={}, headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 400


def test_sync_trigger_invalid_type(client):
    resp = client.post("/api/sync/invalid", json={}, headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 400


def test_stale_exports_route(client):
    resp = client.get("/api/policies/stale-exports")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)


# ── Sync History API ─────────────────────────────────────────────────────

def test_sync_history_route(client):
    resp = client.get("/api/sync/qids/history")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)


def test_sync_history_invalid_type(client):
    resp = client.get("/api/sync/invalid/history")
    assert resp.status_code == 400


# ── Mandate Database Tests ────────────────────────────────────────────────

def test_upsert_and_get_mandate():
    upsert_mandate({
        "ID": "9001",
        "TITLE": "NIST Cybersecurity Framework",
        "VERSION": "2.0",
        "PUBLISHER": "NIST",
        "RELEASED_DATE": "2024-02-26",
        "DESCRIPTION": "Framework for improving critical infrastructure cybersecurity.",
        "CONTROL_LIST": {
            "CONTROL": [
                {"CID": "5001", "SECTION_ID": "PR.AC-1", "SECTION_TITLE": "Access Control"},
            ]
        },
    })

    mandate = get_mandate(9001)
    assert mandate is not None
    assert mandate["title"] == "NIST Cybersecurity Framework"
    assert mandate["publisher"] == "NIST"
    assert mandate["version"] == "2.0"
    assert len(mandate["controls"]) == 1
    assert mandate["controls"][0]["cid"] == 5001
    assert mandate["controls"][0]["section_id"] == "PR.AC-1"
    # Policy 8001 contains CID 5001 → derived policy link
    assert len(mandate["policies"]) >= 1
    assert any(p["policy_id"] == 8001 for p in mandate["policies"])


def test_upsert_mandate_control():
    upsert_mandate({
        "ID": "9002",
        "TITLE": "GLBA Financial Privacy",
        "PUBLISHER": "US Federal Government",
    })
    upsert_mandate_control(9002, 5001, "SEC-501", "Security Safeguards")
    mandate = get_mandate(9002)
    assert len(mandate["controls"]) == 1
    assert mandate["controls"][0]["section_id"] == "SEC-501"


def test_search_mandates_fts():
    result = search_mandates(q="Cybersecurity Framework")
    assert result["total"] >= 1
    assert any(r["mandate_id"] == 9001 for r in result["results"])


def test_search_mandates_publisher_filter():
    result = search_mandates(publishers=["NIST"])
    assert result["total"] >= 1
    assert all(r["publisher"] == "NIST" for r in result["results"])


def test_get_mandate_nonexistent():
    assert get_mandate(999999) is None


def test_mandate_filter_values():
    values = get_mandate_filter_values("publishers")
    assert "NIST" in values
    assert "US Federal Government" in values


def test_control_linked_mandates():
    ctrl = get_control(5001)
    assert ctrl is not None
    assert len(ctrl["linked_mandates"]) >= 1
    assert any(m["mandate_id"] == 9001 for m in ctrl["linked_mandates"])


def test_policy_linked_mandates():
    pol = get_policy(8001)
    assert pol is not None
    # Policy 8001 has CID 5001, which is linked to mandate 9001
    assert len(pol["linked_mandates"]) >= 1
    assert any(m["mandate_id"] == 9001 for m in pol["linked_mandates"])


# ── Mandate API Route Tests ──────────────────────────────────────────────

def test_mandates_search_route(client):
    resp = client.get("/api/mandates?q=NIST")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "results" in data
    assert "total" in data


def test_mandates_detail_route(client):
    resp = client.get("/api/mandates/9001")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["mandate_id"] == 9001


def test_mandates_detail_404(client):
    resp = client.get("/api/mandates/999999")
    assert resp.status_code == 404


def test_mandates_filter_values_route(client):
    resp = client.get("/api/mandates/filter-values?field=publishers")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    assert "NIST" in data


# ── Vault Auth Gate Tests ────────────────────────────────────────────────

def test_api_protected_when_vault_has_creds(unauthed_client):
    """API routes return 401 when credentials exist but no unlock cookie."""
    # Vault already has creds from earlier tests
    resp = unauthed_client.get("/api/sync/status")
    assert resp.status_code == 401
    assert "error" in resp.get_json()


def test_exempt_routes_accessible_without_cookie(unauthed_client):
    """Exempt routes work even when vault has credentials and no cookie."""
    assert unauthed_client.get("/").status_code == 200
    assert unauthed_client.get("/api/credentials").status_code == 200
    assert unauthed_client.get("/api/platforms").status_code == 200
    resp = unauthed_client.post("/api/credentials/verify", json={"id": "x", "password": "y"})
    assert resp.status_code in (400, 401)  # Bad input, not auth gate 401


def test_api_accessible_with_cookie(unauthed_client):
    """API routes work when vault has creds AND valid session token is present."""
    _active_sessions[_TEST_SESSION_TOKEN] = True
    unauthed_client.set_cookie("qkbe-vault-unlocked", _TEST_SESSION_TOKEN)
    resp = unauthed_client.get("/api/sync/status")
    assert resp.status_code == 200
    _active_sessions.pop(_TEST_SESSION_TOKEN, None)


def test_logout_endpoint(client):
    """POST /api/auth/logout returns success."""
    resp = client.post("/api/auth/logout")
    assert resp.status_code == 200
    assert resp.get_json()["logged_out"] is True


# ── Purge Data (must be LAST — destroys data other tests depend on) ──────

def test_purge_data_qids():
    from app.database import purge_data
    # Pre-condition: data exists from earlier tests
    result = search_vulns()
    assert result["total"] > 0

    purge_data("qids")

    result2 = search_vulns()
    assert result2["total"] == 0

    status = get_sync_status()
    assert status["qids"]["last_sync"] is None
    assert status["qids"]["record_count"] == 0


def test_purge_data_cids():
    from app.database import purge_data
    result = search_controls()
    assert result["total"] > 0

    purge_data("cids")

    result2 = search_controls()
    assert result2["total"] == 0

    status = get_sync_status()
    assert status["cids"]["last_sync"] is None
    assert status["cids"]["record_count"] == 0


def test_purge_data_policies():
    from app.database import purge_data
    result = search_policies()
    assert result["total"] > 0

    purge_data("policies")

    result2 = search_policies()
    assert result2["total"] == 0

    status = get_sync_status()
    assert status["policies"]["last_sync"] is None
    assert status["policies"]["record_count"] == 0


def test_purge_data_mandates():
    from app.database import purge_data
    result = search_mandates()
    assert result["total"] > 0

    purge_data("mandates")

    result2 = search_mandates()
    assert result2["total"] == 0

    status = get_sync_status()
    assert status["mandates"]["last_sync"] is None
    assert status["mandates"]["record_count"] == 0


# ── Dashboard & Analytics ─────────────────────────────────────────────────

def test_dashboard_stats_empty(client):
    """Dashboard returns zeroes with empty DB."""
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "severity" in data
    assert "criticality" in data
    assert "patchable" in data
    assert "categories_top15" in data
    assert "compliance" in data


def test_dashboard_stats_with_data(client):
    """Dashboard aggregates severity counts from sample vulns."""
    from app.database import get_db
    with get_db() as conn:
        for sev in [5, 5, 4, 3, 2, 1]:
            conn.execute(
                "INSERT OR IGNORE INTO vulns (qid, severity_level, title, patchable) "
                "VALUES (?, ?, ?, ?)",
                (90000 + sev * 10 + (sev if sev != 5 else 0), sev, f"Test QID sev {sev}", 1),
            )
    resp = client.get("/api/dashboard/stats")
    data = resp.get_json()
    # Should have at least one severity level with data
    assert sum(data["severity"].values()) > 0


def test_dashboard_requires_auth(unauthed_client):
    """Dashboard stats require vault auth when credentials exist."""
    from app.vault import save_credential
    save_credential("dashuser", "dashpass123", "US1")
    resp = unauthed_client.get("/api/dashboard/stats")
    assert resp.status_code == 401


# ── CSV Export ─────────────────────────────────────────────────────────────

def test_export_qids_csv(client):
    """QID CSV export returns CSV content-type with header row."""
    resp = client.get("/api/export/qids/csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.content_type
    lines = resp.data.decode().strip().split("\n")
    assert len(lines) >= 1  # At least header row
    assert "QID" in lines[0]
    assert "Title" in lines[0]


def test_export_cids_csv(client):
    """CID CSV export returns proper CSV."""
    resp = client.get("/api/export/cids/csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.content_type
    lines = resp.data.decode().strip().split("\n")
    assert "CID" in lines[0]


def test_export_policies_csv(client):
    """Policy CSV export returns proper CSV."""
    resp = client.get("/api/export/policies/csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.content_type
    assert "Policy ID" in resp.data.decode().split("\n")[0]


def test_export_mandates_csv(client):
    """Mandate CSV export returns proper CSV."""
    resp = client.get("/api/export/mandates/csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.content_type
    assert "Mandate ID" in resp.data.decode().split("\n")[0]


def test_export_mandate_map_csv(client):
    """Mandate compliance map CSV returns flattened mapping."""
    resp = client.get("/api/export/mandate-map/csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.content_type
    header = resp.data.decode().split("\n")[0]
    assert "Mandate ID" in header
    assert "CID" in header
    assert "Policy ID" in header


# ── PDF Export ─────────────────────────────────────────────────────────────

def test_export_qids_pdf(client):
    """QID PDF export returns PDF content-type."""
    resp = client.get("/api/export/qids/pdf")
    assert resp.status_code == 200
    assert "application/pdf" in resp.content_type
    assert resp.data[:5] == b"%PDF-"


def test_export_requires_auth(unauthed_client):
    """Export routes require vault auth when credentials exist."""
    from app.vault import save_credential
    save_credential("exportuser", "exportpass123", "US1")
    resp = unauthed_client.get("/api/export/qids/csv")
    assert resp.status_code == 401
    resp2 = unauthed_client.get("/api/export/qids/pdf")
    assert resp2.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════
# Bulk Export Details Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_qid_bulk_export_empty(client):
    """Bulk QID export with empty IDs returns 400."""
    resp = client.get("/api/qids/export-details?ids=&format=csv")
    assert resp.status_code == 400

def test_qid_bulk_export_csv(client):
    """Bulk QID export with valid IDs returns CSV."""
    resp = client.get("/api/qids/export-details?ids=1,2,3&format=csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.content_type

def test_qid_bulk_export_csv_unlimited(client):
    """Bulk QID CSV export has no limit."""
    ids = ",".join(str(i) for i in range(300))
    resp = client.get(f"/api/qids/export-details?ids={ids}&format=csv")
    assert resp.status_code == 200

def test_cid_bulk_export_empty(client):
    """Bulk CID export with empty IDs returns 400."""
    resp = client.get("/api/cids/export-details?ids=&format=csv")
    assert resp.status_code == 400

def test_cid_bulk_export_csv(client):
    """Bulk CID export with valid IDs returns CSV."""
    resp = client.get("/api/cids/export-details?ids=1,2,3&format=csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.content_type


# ═══════════════════════════════════════════════════════════════════════════
# Database Maintenance
# ═══════════════════════════════════════════════════════════════════════════

def test_maintenance_config_get(client):
    """GET maintenance config returns default values."""
    resp = client.get("/api/maintenance/config")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["day_of_week"] == 0  # Sunday
    assert data["hour"] == 0
    assert data["minute"] == 0


def test_maintenance_config_save(client):
    """POST maintenance config updates schedule."""
    resp = client.post("/api/maintenance/config",
                       data=json.dumps({"day_of_week": 3, "hour": 2, "minute": 30,
                                        "timezone": "America/Denver"}),
                       content_type="application/json",
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["day_of_week"] == 3
    assert data["hour"] == 2
    assert data["minute"] == 30


def test_maintenance_config_invalid_day(client):
    """POST with invalid day_of_week returns 400."""
    resp = client.post("/api/maintenance/config",
                       data=json.dumps({"day_of_week": 9}),
                       content_type="application/json",
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 400


def test_maintenance_restore_no_backup(client):
    """POST restore with no backup returns error."""
    resp = client.post("/api/maintenance/restore",
                       content_type="application/json",
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 500
    data = resp.get_json()
    assert "No backup" in data["error"]


def test_health_endpoint(client):
    """Health check returns ok status."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"


# ═══════════════════════════════════════════════════════════════════════════
# Tags (Phase 1: read-only browse + sync state)
# ═══════════════════════════════════════════════════════════════════════════

def _seed_test_tags():
    """Seed a small set of tags covering user-created, system, and ambiguous cases."""
    from app.database import upsert_tag
    upsert_tag({
        "id": 100,
        "name": "OS: Windows 11",
        "color": "#0066cc",
        "ruleType": "ASSET_INVENTORY",
        "ruleText": "operatingSystem.publisher:`Microsoft`",
        "parentTagId": 50,
        "createdBy": {"username": "alice"},
    }, credential_id="c1")
    upsert_tag({
        "id": 50,
        "name": "OS: Operating System",
        "createdBy": {"username": "alice"},
    })
    upsert_tag({
        "id": 1,
        "name": "Business Units",
        "reservedType": "BUSINESS_UNIT",
    })
    upsert_tag({
        "id": 999,
        "name": "Ambiguous Tag",
    })


def test_tags_search_empty_returns_zero(client):
    resp = client.get("/api/tags?q=__no_such_tag__")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 0
    assert data["results"] == []


def test_tags_detail_404_for_missing(client):
    resp = client.get("/api/tags/9999999")
    assert resp.status_code == 404


def test_tags_filter_values_returns_list(client):
    resp = client.get("/api/tags/filter-values?field=rule_types")
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)


def test_tags_search_finds_user_created(client):
    _seed_test_tags()
    resp = client.get("/api/tags?q=Windows")
    data = resp.get_json()
    # FTS hit on the user-created Windows tag
    assert data["total"] >= 1
    assert any(r["tag_id"] == 100 for r in data["results"])


def test_tags_filter_only_user(client):
    _seed_test_tags()
    resp = client.get("/api/tags?only_user=1")
    data = resp.get_json()
    # User-created: 100 (rule + creator), 50 (creator alice). Tag 1 has
    # reservedType=BUSINESS_UNIT (system); tag 999 is ambiguous and
    # defaults to system unless propagation finds a user-created child.
    assert data["total"] == 2
    assert all(r["is_user_created"] == 1 for r in data["results"])


def test_tags_filter_only_system(client):
    _seed_test_tags()
    resp = client.get("/api/tags?only_system=1")
    data = resp.get_json()
    # Tag 1 (reservedType) and tag 999 (no rule, no creator, no children
    # → system by default-deny baseline)
    assert data["total"] == 2
    assert all(r["is_user_created"] == 0 for r in data["results"])


def test_tags_filter_by_rule_type(client):
    _seed_test_tags()
    resp = client.get("/api/tags?rule_type=ASSET_INVENTORY")
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["tag_id"] == 100


def test_tags_filter_by_parent(client):
    _seed_test_tags()
    resp = client.get("/api/tags?parent_tag_id=50")
    data = resp.get_json()
    assert data["total"] == 1
    assert data["results"][0]["tag_id"] == 100


def test_tags_detail_includes_breadcrumb_and_children(client):
    _seed_test_tags()
    resp = client.get("/api/tags/100")
    body = resp.get_json()
    assert body["tag_id"] == 100
    assert body["name"] == "OS: Windows 11"
    assert body["is_user_created"] == 1
    assert body["parent"] is not None and body["parent"]["tag_id"] == 50
    assert body["breadcrumb"] == [{"tag_id": 50, "name": "OS: Operating System"}]
    assert body["children"] == []  # leaf


def test_tags_detail_system_tag_marks_is_user_created_false(client):
    _seed_test_tags()
    resp = client.get("/api/tags/1")
    body = resp.get_json()
    assert body["is_user_created"] == 0
    assert body["reserved_type"] == "BUSINESS_UNIT"


def test_tags_default_deny_for_ambiguous_leaf_tags(client):
    """A tag with no reservedType, no ruleType, no creator, and no
    children is provisionally treated as system. This catches Qualys-
    managed organizer tags like Cloud Agent and Business Units that the
    search API returns with no discriminating metadata."""
    _seed_test_tags()
    resp = client.get("/api/tags/999")
    body = resp.get_json()
    assert body["is_user_created"] == 0
    assert body["reserved_type"] is None
    assert body["created_by"] is None
    assert (body["rule_type"] or "") == ""


def test_tags_user_created_when_rule_present(client):
    """A tag with a non-empty ruleType is treated as user-created even
    when createdBy is missing."""
    from app.database import upsert_tag, get_tag
    upsert_tag({
        "id": 7777, "name": "OS: Linux",
        "ruleType": "GLOBAL_ASSET_VIEW",
        "ruleText": "operatingSystem.category1:`Linux`",
    })
    body = get_tag(7777)
    assert body["is_user_created"] == 1
    assert body["reserved_type"] is None
    assert body["created_by"] is None


def test_tags_propagation_flips_organizer_parent_to_user_created(client):
    """A rule-less parent tag whose only signal is having a user-created
    child should be flipped to user-created by the propagation step.

    This is the case where a user makes 'OS: Operating System' as a static
    parent organizer for their 'OS: Linux' (with rule) child. The parent
    has no rule itself but is clearly user-authored."""
    from app.database import (
        upsert_tag, get_tag, get_db, _propagate_user_classification,
    )
    # Parent: no rule, no creator → baseline system
    upsert_tag({"id": 8000, "name": "Operating System TAG (organizer)"})
    # Child: has a rule → baseline user
    upsert_tag({
        "id": 8001, "name": "OS: Linux", "parentTagId": 8000,
        "ruleType": "GLOBAL_ASSET_VIEW",
        "ruleText": "operatingSystem.category1:`Linux`",
    })

    parent = get_tag(8000)
    child = get_tag(8001)
    assert child["is_user_created"] == 1
    assert parent["is_user_created"] == 0  # before propagation

    with get_db() as conn:
        flipped = _propagate_user_classification(conn)
    assert flipped >= 1

    parent = get_tag(8000)
    assert parent["is_user_created"] == 1  # propagated up


def test_tags_propagation_does_not_flip_system_tag_with_user_grandchild(client):
    """Propagation must not bypass an explicit reservedType — a tag
    flagged system by reservedType stays system even if a descendant
    is user-created."""
    from app.database import (
        upsert_tag, get_tag, get_db, _propagate_user_classification,
    )
    upsert_tag({"id": 9000, "name": "Business Units",
                "reservedType": "BUSINESS_UNIT"})
    upsert_tag({"id": 9001, "name": "Custom BU", "parentTagId": 9000,
                "ruleType": "BUSINESS_INFO"})
    with get_db() as conn:
        _propagate_user_classification(conn)
    parent = get_tag(9000)
    assert parent["is_user_created"] == 0
    assert parent["reserved_type"] == "BUSINESS_UNIT"


def test_tags_filter_values_lists_observed_rule_types(client):
    _seed_test_tags()
    resp = client.get("/api/tags/filter-values?field=rule_types")
    assert "ASSET_INVENTORY" in resp.get_json()


def test_tags_filter_values_lists_observed_reserved_types(client):
    _seed_test_tags()
    resp = client.get("/api/tags/filter-values?field=reserved_types")
    assert "BUSINESS_UNIT" in resp.get_json()


def test_sync_status_includes_tags(client):
    resp = client.get("/api/sync/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "tags" in data
    assert "syncing" in data["tags"]


def test_sync_endpoints_accept_tags_data_type(client):
    """Validation routes should accept 'tags' alongside the other types."""
    resp = client.get("/api/sync/tags/progress")
    assert resp.status_code == 200
    resp = client.get("/api/sync/tags/log")
    # No log yet -> 404 (not 400)
    assert resp.status_code == 404
    resp = client.get("/api/sync/tags/history")
    assert resp.status_code == 200


def test_sync_endpoints_reject_unknown_data_type(client):
    resp = client.get("/api/sync/foo/progress")
    assert resp.status_code == 400


def test_qps_extract_data_helper_handles_shapes():
    from app.qualys_client import QualysClient
    parsed = {"ServiceResponse": {"data": [
        {"Tag": {"id": 1, "name": "a"}},
        {"Tag": {"id": 2, "name": "b"}},
    ]}}
    assert QualysClient.qps_extract_data(parsed, "Tag") == [
        {"id": 1, "name": "a"}, {"id": 2, "name": "b"},
    ]
    # Single dict (count=1)
    single = {"ServiceResponse": {"data": {"Tag": {"id": 9}}}}
    assert QualysClient.qps_extract_data(single, "Tag") == [{"id": 9}]
    # Empty
    assert QualysClient.qps_extract_data({}, "Tag") == []
    assert QualysClient.qps_extract_data({"ServiceResponse": {}}, "Tag") == []


def test_qps_has_more_helper():
    from app.qualys_client import QualysClient
    has, last = QualysClient.qps_has_more({
        "ServiceResponse": {"hasMoreRecords": "true", "lastId": 42}
    })
    assert has is True and last == 42
    has, last = QualysClient.qps_has_more({
        "ServiceResponse": {"hasMoreRecords": "false"}
    })
    assert has is False and last is None


# ═══════════════════════════════════════════════════════════════════════════
# PM Patch Catalog
# ═══════════════════════════════════════════════════════════════════════════

def _seed_test_patches():
    from app.database import upsert_pm_patch, upsert_vuln
    # Seed a couple of QIDs first so we have something to link against
    upsert_vuln({"QID": "100", "TITLE": "Critical Linux Bug", "SEVERITY_LEVEL": "5",
                 "CATEGORY": "Security", "PATCHABLE": "1"})
    upsert_vuln({"QID": "200", "TITLE": "Windows Patch", "SEVERITY_LEVEL": "4",
                 "CATEGORY": "Windows", "PATCHABLE": "1"})
    upsert_vuln({"QID": "300", "TITLE": "No Patch Available", "SEVERITY_LEVEL": "3",
                 "CATEGORY": "Security", "PATCHABLE": "0"})
    upsert_pm_patch({
        "id": "WIN-1234",
        "title": "MSRC Security Update",
        "vendor": "Microsoft",
        "kb": "KB5031234",
        "downloadMethod": "Automatic",
        "vendorSeverity": "Critical",
        "isSecurity": True,
        "isSuperseded": False,
        "rebootRequired": True,
        "qid": [200],
        "cve": ["CVE-2024-1234", "CVE-2024-1235"],
    })
    upsert_pm_patch({
        "id": "LIN-5678",
        "title": "OpenSSL update",
        "vendor": "Red Hat",
        "downloadMethod": "Default download",
        "vendorSeverity": "High",
        "isSecurity": True,
        "isSuperseded": False,
        "rebootRequired": False,
        "qid": [100],
        "cve": ["CVE-2024-9999"],
        "packageDetails": [
            {"packageName": "openssl-libs"},
            {"packageName": "openssl"},
        ],
    })


def test_upsert_pm_patch_creates_links(client):
    _seed_test_patches()
    from app.database import get_pm_patches_for_qid, get_pm_patch_qid_flags
    win = get_pm_patches_for_qid(200)
    assert len(win) == 1
    assert win[0]["platform"] == "Windows"
    assert win[0]["kb_article"] == "KB5031234"

    lin = get_pm_patches_for_qid(100)
    assert len(lin) == 1
    assert lin[0]["platform"] == "Linux"
    assert "openssl" in (lin[0]["package_names"] or "")

    flags = get_pm_patch_qid_flags(200)
    assert flags == {"win_patches": 1, "lin_patches": 0, "has_pm": True}
    flags = get_pm_patch_qid_flags(100)
    assert flags == {"win_patches": 0, "lin_patches": 1, "has_pm": True}
    flags = get_pm_patch_qid_flags(300)
    assert flags == {"win_patches": 0, "lin_patches": 0, "has_pm": False}


def test_pm_patch_stats(client):
    _seed_test_patches()
    resp = client.get("/api/pm/stats")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total_patches"] == 2
    assert data["windows_patches"] == 1
    assert data["linux_patches"] == 1
    assert data["qids_with_pm"] == 2


def test_qid_patches_route(client):
    _seed_test_patches()
    resp = client.get("/api/qids/200/patches")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["qid"] == 200
    assert body["has_pm"] is True
    assert len(body["patches"]) == 1
    assert body["patches"][0]["vendor"] == "Microsoft"


def test_qid_search_pm_filters(client):
    _seed_test_patches()
    # pm_any → returns QIDs 100 and 200, not 300
    resp = client.get("/api/qids?pm_any=1")
    body = resp.get_json()
    qids = sorted(r["qid"] for r in body["results"])
    assert qids == [100, 200]

    # pm_win → only 200
    resp = client.get("/api/qids?pm_win=1")
    body = resp.get_json()
    qids = sorted(r["qid"] for r in body["results"])
    assert qids == [200]

    # pm_lin → only 100
    resp = client.get("/api/qids?pm_lin=1")
    body = resp.get_json()
    qids = sorted(r["qid"] for r in body["results"])
    assert qids == [100]


def test_qid_search_severity_multi(client):
    _seed_test_patches()
    resp = client.get("/api/qids?severities=4,5&per_page=200")
    body = resp.get_json()
    qids = {r["qid"] for r in body["results"]}
    sevs = {r["severity_level"] for r in body["results"]}
    # Our two seeded QIDs (sev 4 and 5) are in the result set; sev 3 is not.
    assert 100 in qids and 200 in qids
    assert 300 not in qids
    assert sevs.issubset({4, 5})


def test_sync_state_includes_pm_patches(client):
    resp = client.get("/api/sync/status")
    data = resp.get_json()
    assert "pm_patches" in data


def test_sync_pm_patches_route_requires_creds(client):
    # No credential provided → 400; we just want to confirm pm_patches is
    # accepted as a valid data type (returns 400, not 'invalid data type')
    resp = client.post("/api/sync/pm_patches",
                        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
                        data="{}")
    assert resp.status_code == 400
    assert "Invalid data type" not in resp.get_json().get("error", "")


# ═══════════════════════════════════════════════════════════════════════════
# Intelligence stats endpoint
# ═══════════════════════════════════════════════════════════════════════════

def test_intelligence_stats_no_filters(client):
    _seed_test_patches()
    resp = client.get("/api/intelligence/stats")
    assert resp.status_code == 200
    s = resp.get_json()
    # Required keys for the stat strip
    for k in ("total_qids", "kb_patchable", "pm_any", "pm_win", "pm_lin",
              "pci", "sev_5", "sev_4", "sev_3", "sev_2", "sev_1", "with_cve"):
        assert k in s, f"missing key {k}"
    assert s["pm_win"] >= 1  # we seeded at least one Windows patch
    assert s["pm_lin"] >= 1
    assert s["pm_any"] >= 2


def test_intelligence_stats_respects_filters(client):
    _seed_test_patches()
    resp = client.get("/api/intelligence/stats?severities=5")
    s = resp.get_json()
    # Only QID 100 (sev 5) is in the filtered set, and it has a Linux patch
    assert s["total_qids"] >= 1
    assert s["pm_win"] == 0
    assert s["pm_lin"] >= 1


# ═══════════════════════════════════════════════════════════════════════════
# Sync serialization (global mutex) and rate-limit retry
# ═══════════════════════════════════════════════════════════════════════════

def test_sync_active_endpoint_unlocked(client):
    """When no sync is running, /api/sync/active reports unlocked."""
    resp = client.get("/api/sync/active")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["locked"] is False
    assert body["data_type"] is None


def test_second_manual_trigger_queues_while_first_holds_mutex(client):
    """When the mutex is held, a different-type manual trigger should be
    enqueued (200 + queued=true), not rejected with 409."""
    from app.main import _sync_mutex, _sync_mutex_owner, _sync_queue
    cred_resp = client.post("/api/credentials", json={
        "username": "syncuser1", "password": "p", "platform": "US1",
    })
    cred_id = cred_resp.get_json()["id"]

    _sync_mutex.acquire()
    _sync_mutex_owner["data_type"] = "qids"
    try:
        resp = client.post(
            "/api/sync/cids",
            headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
            json={"credential_id": cred_id, "platform": "US1"},
        )
        assert resp.status_code == 200, resp.get_data(as_text=True)
        body = resp.get_json()
        assert body.get("queued") is True
        assert body["queue_position"] == 1
        assert body["running_now"] == "qids"
        assert "queue" in body["message"].lower() or "after" in body["message"].lower()

        active = client.get("/api/sync/active").get_json()
        assert active["locked"] is True
        assert active["data_type"] == "qids"
        assert any(e["data_type"] == "cids" for e in active["queue"])

        # The queued sync's progress is "queued"
        prog = client.get("/api/sync/cids/progress").get_json()
        assert prog["status"] == "queued"
        assert prog["running_now"] == "qids"
    finally:
        # Clean up: drop the queued cids entry so the spawned worker
        # thread doesn't actually start a real sync against a fake
        # platform when we release.
        with _sync_queue_lock_guard():
            _sync_queue.clear()
        _sync_mutex_owner["data_type"] = None
        _sync_mutex_owner["started_at"] = None
        _sync_mutex.release()


def _sync_queue_lock_guard():
    from app.main import _sync_queue_lock
    return _sync_queue_lock


def test_same_type_duplicate_trigger_returns_409(client):
    """Same data type queued/running twice should still be rejected —
    one click of QIDs is enough."""
    from app.main import _sync_mutex, _sync_mutex_owner
    cred_resp = client.post("/api/credentials", json={
        "username": "syncuser2", "password": "p", "platform": "US1",
    })
    cred_id = cred_resp.get_json()["id"]

    _sync_mutex.acquire()
    _sync_mutex_owner["data_type"] = "qids"
    try:
        resp = client.post(
            "/api/sync/qids",
            headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
            json={"credential_id": cred_id, "platform": "US1"},
        )
        assert resp.status_code == 409
        body = resp.get_json()
        assert body.get("duplicate") is True
        assert "already running" in body["error"].lower()
    finally:
        _sync_mutex_owner["data_type"] = None
        _sync_mutex_owner["started_at"] = None
        _sync_mutex.release()


def test_credential_error_does_not_consume_queue_slot(client):
    """trigger_sync that fails credential validation must not leak a
    queue entry or hold the mutex."""
    from app.main import _sync_mutex, _sync_queue
    resp = client.post(
        "/api/sync/qids",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"credential_id": "does-not-exist", "platform": "US1"},
    )
    assert resp.status_code == 400
    assert _sync_mutex.acquire(blocking=False)
    _sync_mutex.release()
    assert all(e["data_type"] != "qids" for e in _sync_queue)


def test_qualys_client_retry_after_helper_handles_missing_header():
    from app.qualys_client import QualysClient

    class _R:
        headers = {}
    assert QualysClient._retry_after_seconds(_R()) == QualysClient.RATE_LIMIT_DEFAULT_BACKOFF_SEC


def test_qualys_client_retry_after_helper_parses_seconds():
    from app.qualys_client import QualysClient

    class _R:
        headers = {"Retry-After": "30"}
    assert QualysClient._retry_after_seconds(_R()) == 30


def test_qualys_client_retry_after_helper_falls_back_on_garbage():
    from app.qualys_client import QualysClient

    class _R:
        headers = {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}
    assert QualysClient._retry_after_seconds(_R()) == QualysClient.RATE_LIMIT_DEFAULT_BACKOFF_SEC


def test_qualys_client_get_tag_detail_extracts_first_tag(monkeypatch):
    """get_tag_detail() should call /qps/rest/2.0/get/am/tag/<id> and
    return the first Tag entry from the ServiceResponse."""
    from app.qualys_client import QualysClient

    captured = {}

    def fake_execute_json(self, path, method="POST", body=None, timeout=120):
        captured["path"] = path
        captured["method"] = method
        return {
            "error": False,
            "status_code": 200,
            "data": {
                "ServiceResponse": {
                    "responseCode": "SUCCESS",
                    "count": 1,
                    "data": [{"Tag": {
                        "id": 12345,
                        "name": "Business Units",
                        "reservedType": "BUSINESS_UNIT",
                        "createdBy": {"username": "qualys"},
                    }}],
                }
            },
        }

    monkeypatch.setattr(QualysClient, "execute_json", fake_execute_json)
    client = QualysClient("https://qualysapi.example.com", "u", "p")
    detail = client.get_tag_detail(12345)
    assert detail is not None
    assert detail["id"] == 12345
    assert detail["reservedType"] == "BUSINESS_UNIT"
    assert captured["path"] == "/qps/rest/2.0/get/am/tag/12345"
    assert captured["method"] == "GET"


def test_qualys_client_get_tag_detail_returns_none_on_error(monkeypatch):
    from app.qualys_client import QualysClient

    def fake_execute_json(self, path, method="POST", body=None, timeout=120):
        return {"error": True, "status_code": 404, "message": "not found"}

    monkeypatch.setattr(QualysClient, "execute_json", fake_execute_json)
    client = QualysClient("https://qualysapi.example.com", "u", "p")
    assert client.get_tag_detail(999) is None


# ═══════════════════════════════════════════════════════════════════════════
# Tag classification override
# ═══════════════════════════════════════════════════════════════════════════

def test_tag_override_forces_user_classification(client):
    """Manual 'user' override flips an auto-classified system tag to user
    in /api/tags/<id> and in /api/tags?only_user=1 listings."""
    from app.database import upsert_tag
    upsert_tag({"id": 4001, "name": "operations diagnostic TAGs"})

    body = client.get("/api/tags/4001").get_json()
    assert body["is_user_created"] == 0  # auto says system (no rule, no creator)
    assert body["is_user_created_auto"] == 0

    resp = client.post(
        "/api/tags/4001/classify",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"classification": "user"},
    )
    assert resp.status_code == 200

    body = client.get("/api/tags/4001").get_json()
    assert body["is_user_created"] == 1               # effective
    assert body["is_user_created_auto"] == 0          # auto unchanged
    assert body["classification_override"] == "user"

    # Filter respects the override
    listing = client.get("/api/tags?only_user=1&q=operations").get_json()
    assert any(r["tag_id"] == 4001 for r in listing["results"])


def test_tag_override_forces_system_classification(client):
    """Manual 'system' override flips an auto-classified user tag to
    system in detail and in /api/tags?only_system=1 listings."""
    from app.database import upsert_tag
    upsert_tag({"id": 4002, "name": "Internet Facing Assets",
                "ruleType": "ASSET_INVENTORY",
                "ruleText": "asset.public:true"})

    body = client.get("/api/tags/4002").get_json()
    assert body["is_user_created"] == 1  # auto says user (rule present)

    resp = client.post(
        "/api/tags/4002/classify",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"classification": "system"},
    )
    assert resp.status_code == 200

    body = client.get("/api/tags/4002").get_json()
    assert body["is_user_created"] == 0
    assert body["is_user_created_auto"] == 1
    assert body["classification_override"] == "system"

    listing = client.get("/api/tags?only_system=1&q=internet").get_json()
    assert any(r["tag_id"] == 4002 for r in listing["results"])


def test_tag_override_can_be_cleared(client):
    from app.database import upsert_tag
    upsert_tag({"id": 4003, "name": "Test Override Clear",
                "ruleType": "ASSET_INVENTORY", "ruleText": "x:1"})
    client.post(
        "/api/tags/4003/classify",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"classification": "system"},
    )
    # Now clear it
    resp = client.post(
        "/api/tags/4003/classify",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"classification": None},
    )
    assert resp.status_code == 200
    body = client.get("/api/tags/4003").get_json()
    assert body["classification_override"] is None
    assert body["is_user_created"] == 1  # back to auto


def test_tag_override_rejects_bad_values(client):
    from app.database import upsert_tag
    upsert_tag({"id": 4004, "name": "bad-value-test"})
    resp = client.post(
        "/api/tags/4004/classify",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"classification": "wat"},
    )
    assert resp.status_code == 400


def test_tag_override_404_for_missing(client):
    resp = client.post(
        "/api/tags/99999999/classify",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"classification": "user"},
    )
    assert resp.status_code == 404


# ─── Editability override tests ────────────────────────────────────────

def test_tag_user_created_is_editable_by_default(client):
    """User-created tags are always editable on the auto axis."""
    from app.database import upsert_tag
    upsert_tag({"id": 4501, "name": "user tag", "createdBy": "alice",
                "ruleType": "ASSET_INVENTORY", "ruleText": "x:1"})
    body = client.get("/api/tags/4501").get_json()
    assert body["is_user_created"] == 1
    assert body["is_editable"] == 1
    assert body["is_editable_auto"] == 1


def test_tag_locked_reserved_type_is_not_editable(client):
    """System tag with a locked taxonomy reservedType (OS) auto-derives
    is_editable=0. Internet Facing Assets (different reservedType)
    should be editable."""
    from app.database import upsert_tag
    upsert_tag({"id": 4502, "name": "Linux", "reservedType": "OPERATING_SYSTEM"})
    upsert_tag({"id": 4503, "name": "Internet Facing Assets",
                "reservedType": "INTERNET_FACING_ASSETS"})
    locked = client.get("/api/tags/4502").get_json()
    assert locked["is_user_created"] == 0
    assert locked["is_editable"] == 0
    assert locked["is_editable_auto"] == 0
    editable_sys = client.get("/api/tags/4503").get_json()
    assert editable_sys["is_user_created"] == 0  # still system
    assert editable_sys["is_editable"] == 1      # but editable


def test_tag_editability_override_force_editable(client):
    from app.database import upsert_tag
    upsert_tag({"id": 4504, "name": "Some OS", "reservedType": "OPERATING_SYSTEM"})
    body = client.get("/api/tags/4504").get_json()
    assert body["is_editable"] == 0
    resp = client.post(
        "/api/tags/4504/editability",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"editability": "editable"},
    )
    assert resp.status_code == 200
    body = client.get("/api/tags/4504").get_json()
    assert body["is_editable"] == 1
    assert body["is_editable_auto"] == 0
    assert body["editability_override"] == "editable"


def test_tag_editability_override_force_locked(client):
    from app.database import upsert_tag
    upsert_tag({"id": 4505, "name": "user thing", "createdBy": "alice",
                "ruleType": "ASSET_INVENTORY", "ruleText": "x:1"})
    resp = client.post(
        "/api/tags/4505/editability",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"editability": "locked"},
    )
    assert resp.status_code == 200
    body = client.get("/api/tags/4505").get_json()
    assert body["is_editable"] == 0
    assert body["is_editable_auto"] == 1
    assert body["editability_override"] == "locked"


def test_tag_editability_override_can_be_cleared(client):
    from app.database import upsert_tag
    upsert_tag({"id": 4506, "name": "clr test", "reservedType": "OPERATING_SYSTEM"})
    client.post(
        "/api/tags/4506/editability",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"editability": "editable"},
    )
    resp = client.post(
        "/api/tags/4506/editability",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"editability": None},
    )
    assert resp.status_code == 200
    body = client.get("/api/tags/4506").get_json()
    assert body["editability_override"] is None
    assert body["is_editable"] == 0  # back to auto (locked)


def test_tag_editability_rejects_bad_values(client):
    from app.database import upsert_tag
    upsert_tag({"id": 4507, "name": "bad val"})
    resp = client.post(
        "/api/tags/4507/editability",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"editability": "wat"},
    )
    assert resp.status_code == 400


def test_tag_editability_404_for_missing(client):
    resp = client.post(
        "/api/tags/99999998/editability",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"editability": "editable"},
    )
    assert resp.status_code == 404


def test_tags_filter_values_rule_types_includes_canonical_set(client):
    """The rule_types dropdown should always include Qualys's canonical
    rule types so users see every option even before any tag syncs.
    Observed-but-unknown types are merged in too."""
    from app.database import upsert_tag, TAG_RULE_TYPES_KNOWN
    # Add one tag with a never-before-seen rule type
    upsert_tag({"id": 5500, "name": "x", "ruleType": "EXPERIMENTAL_TYPE"})
    resp = client.get("/api/tags/filter-values?field=rule_types")
    assert resp.status_code == 200
    body = resp.get_json()
    # All canonical types present
    for known in ("ASSET_INVENTORY", "GROOVY", "NETWORK_RANGE",
                  "GLOBAL_ASSET_VIEW", "BUSINESS_INFORMATION"):
        assert known in body
    # Plus the observed novelty
    assert "EXPERIMENTAL_TYPE" in body
    # Sorted alphabetically
    assert body == sorted(body)


def test_tags_filter_values_rule_types_supports_search(client):
    resp = client.get("/api/tags/filter-values?field=rule_types&q=asset")
    body = resp.get_json()
    assert all("asset" in v.lower() for v in body)
    # Non-matching canonical types are excluded
    assert "GROOVY" not in body


# ═══════════════════════════════════════════════════════════════════════════
# Pre-count + verify across all sync types
# ═══════════════════════════════════════════════════════════════════════════

def test_qualys_client_qps_count_extracts_count_field(monkeypatch):
    """qps_count() returns the integer ServiceResponse.count field."""
    from app.qualys_client import QualysClient

    def fake_execute_json(self, path, method="POST", body=None, timeout=120):
        return {"error": False, "data": {"ServiceResponse": {
            "responseCode": "SUCCESS", "count": 42,
        }}}

    monkeypatch.setattr(QualysClient, "execute_json", fake_execute_json)
    client = QualysClient("https://qualysapi.example.com", "u", "p")
    assert client.qps_count("/qps/rest/2.0/count/am/tag") == 42


def test_qualys_client_qps_count_returns_none_on_error(monkeypatch):
    from app.qualys_client import QualysClient

    def fake_execute_json(self, path, method="POST", body=None, timeout=120):
        return {"error": True, "message": "boom"}

    monkeypatch.setattr(QualysClient, "execute_json", fake_execute_json)
    client = QualysClient("https://qualysapi.example.com", "u", "p")
    assert client.qps_count("/qps/rest/2.0/count/am/tag") is None


def test_qualys_client_gateway_count_finds_total_field(monkeypatch):
    """gateway_count() probes common count field names: count, total,
    totalRecords, totalCount."""
    from app.qualys_client import QualysClient

    def fake_execute_gateway_json(self, path, body=None, method="POST",
                                  extra_headers=None, timeout=120):
        return {"error": False, "data": {"totalRecords": 1234}}

    monkeypatch.setattr(QualysClient, "execute_gateway_json", fake_execute_gateway_json)
    client = QualysClient("https://qualysapi.example.com", "u", "p")
    assert client.gateway_count("/pm/v2/patches/count") == 1234


def test_qualys_client_gateway_count_returns_none_when_no_field(monkeypatch):
    from app.qualys_client import QualysClient

    def fake_execute_gateway_json(self, path, body=None, method="POST",
                                  extra_headers=None, timeout=120):
        return {"error": False, "data": [{"id": "WIN-1"}]}  # no count field

    monkeypatch.setattr(QualysClient, "execute_gateway_json", fake_execute_gateway_json)
    client = QualysClient("https://qualysapi.example.com", "u", "p")
    assert client.gateway_count("/pm/v2/patches") is None


# ═══════════════════════════════════════════════════════════════════════════
# Disabled QID flag
# ═══════════════════════════════════════════════════════════════════════════

def test_upsert_vuln_captures_disabled_flag(client):
    from app.database import upsert_vuln, get_vuln
    upsert_vuln({"QID": "9001", "TITLE": "Disabled QID", "SEVERITY_LEVEL": "3",
                 "CATEGORY": "Test", "DISABLED": "1"})
    upsert_vuln({"QID": "9002", "TITLE": "Active QID", "SEVERITY_LEVEL": "3",
                 "CATEGORY": "Test", "DISABLED": "0"})
    upsert_vuln({"QID": "9003", "TITLE": "Field-not-set QID", "SEVERITY_LEVEL": "3",
                 "CATEGORY": "Test"})  # default = enabled

    assert get_vuln(9001)["disabled"] == 1
    assert get_vuln(9002)["disabled"] == 0
    assert get_vuln(9003)["disabled"] == 0


def test_upsert_vuln_accepts_is_disabled_alias(client):
    """Some Qualys API paths use IS_DISABLED instead of DISABLED."""
    from app.database import upsert_vuln, get_vuln
    upsert_vuln({"QID": "9101", "TITLE": "Alt-name disabled",
                 "SEVERITY_LEVEL": "3", "CATEGORY": "Test",
                 "IS_DISABLED": "1"})
    assert get_vuln(9101)["disabled"] == 1


def test_qid_search_disabled_filter(client):
    from app.database import upsert_vuln
    upsert_vuln({"QID": "9201", "TITLE": "Active A", "SEVERITY_LEVEL": "4",
                 "CATEGORY": "Test", "DISABLED": "0"})
    upsert_vuln({"QID": "9202", "TITLE": "Active B", "SEVERITY_LEVEL": "4",
                 "CATEGORY": "Test", "DISABLED": "0"})
    upsert_vuln({"QID": "9203", "TITLE": "Disabled C", "SEVERITY_LEVEL": "4",
                 "CATEGORY": "Test", "DISABLED": "1"})

    # disabled=1 → only disabled
    resp = client.get("/api/qids?disabled=1&per_page=200")
    qids = {r["qid"] for r in resp.get_json()["results"]}
    assert 9203 in qids
    assert 9201 not in qids and 9202 not in qids

    # disabled=0 → only enabled
    resp = client.get("/api/qids?disabled=0&per_page=200")
    qids = {r["qid"] for r in resp.get_json()["results"]}
    assert 9201 in qids and 9202 in qids
    assert 9203 not in qids

    # absent → no filter (both)
    resp = client.get("/api/qids?per_page=200")
    qids = {r["qid"] for r in resp.get_json()["results"]}
    assert 9201 in qids and 9203 in qids


def test_disabled_column_exists_after_init(client):
    """The vulns table must have a disabled column even on a brand-new DB."""
    from app.database import get_db
    with get_db() as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(vulns)").fetchall()}
    assert "disabled" in cols


def test_backfill_only_supported_for_qids(client):
    """The backfill flag is currently only implemented for QIDs.
    Other types should reject it with 400."""
    cred_resp = client.post("/api/credentials", json={
        "username": "bfuser", "password": "p", "platform": "US1",
    })
    cred_id = cred_resp.get_json()["id"]
    resp = client.post(
        "/api/sync/cids",
        headers={"X-Requested-With": "QKBE", "Content-Type": "application/json"},
        json={"credential_id": cred_id, "platform": "US1", "backfill": True},
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert "Backfill" in body["error"] or "QIDs" in body["error"]


# ─── OpenAPI / Swagger tests ───────────────────────────────────────────

def test_openapi_spec_served(client):
    """Raw OpenAPI 3 spec is served at /api/docs/openapi.json with the
    expected paths and tags."""
    resp = client.get("/api/docs/openapi.json")
    assert resp.status_code == 200
    spec = resp.get_json()
    assert spec["info"]["title"] == "Q KB Explorer API"
    assert spec["openapi"].startswith("3.")
    assert "/api/qids" in spec["paths"]
    qid_get = spec["paths"]["/api/qids"]["get"]
    assert "QIDs" in qid_get["tags"]
    # Annotated route surfaces the documented response codes (200 +
    # auto-added 422 for validation + the 500 we declared explicitly)
    assert "200" in qid_get["responses"]
    assert "500" in qid_get["responses"]


def test_openapi_docs_index_redirects_to_swagger(client):
    """/api/docs (no trailing slash) redirects to the Swagger UI variant
    so users have a single memorable URL."""
    resp = client.get("/api/docs")
    assert resp.status_code in (301, 302, 308)
    assert "/api/docs/swagger/" in resp.headers.get("Location", "")


def test_openapi_swagger_ui_renders(client):
    """Swagger UI page renders with non-empty HTML."""
    resp = client.get("/api/docs/swagger/")
    assert resp.status_code == 200
    assert len(resp.data) > 0


def test_openapi_redoc_ui_renders(client):
    """ReDoc page also renders for users who prefer that view."""
    resp = client.get("/api/docs/redoc/")
    assert resp.status_code == 200
    assert len(resp.data) > 0


# ─── Sync event tail (peek-under-the-hood ticker) ──────────────────────

def test_sync_events_tail_no_runs_returns_empty(client):
    """When no sync run exists for a type, the tail endpoint returns
    an empty event list with run_id=null instead of 404 — the ticker
    poller can render that as "waiting for events" without special
    casing."""
    resp = client.get("/api/sync/qids/events/tail")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["run_id"] is None
    assert body["events"] == []


def test_sync_events_tail_returns_events_newest_first(client):
    """Once a sync run exists with events, the tail returns them
    newest-first and respects since_id for incremental polls."""
    from app.database import get_db
    with get_db() as conn:
        conn.execute(
            "INSERT INTO sync_log_runs (data_type, full, api_base, endpoint, started_at, status) "
            "VALUES ('qids', 1, 'https://test', '/api/test', '2026-05-02T00:00:00Z', 'running')"
        )
        run_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        for i, evt in enumerate(["SYNC_START", "HTTP_REQUEST", "HTTP_RESPONSE", "WRITE_BATCH_START", "PAGE_PROCESSED"]):
            conn.execute(
                "INSERT INTO sync_log_events (run_id, ts, event_type, detail_json) "
                "VALUES (?, ?, ?, ?)",
                (run_id, f"2026-05-02T00:00:0{i}Z", evt, '{"items": ' + str(i) + '}'),
            )
    resp = client.get("/api/sync/qids/events/tail?limit=10")
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["run_id"] == run_id
    assert body["run_status"] == "running"
    assert len(body["events"]) == 5
    # Newest-first
    assert body["events"][0]["event_type"] == "PAGE_PROCESSED"
    assert body["events"][-1]["event_type"] == "SYNC_START"
    # detail_json gets parsed
    assert body["events"][0]["detail"] == {"items": 4}

    # Incremental: since_id filters out everything we already saw
    last_id = body["events"][0]["id"]
    incremental = client.get(f"/api/sync/qids/events/tail?since_id={last_id}").get_json()
    assert incremental["events"] == []


def test_sync_events_tail_rejects_invalid_type(client):
    resp = client.get("/api/sync/widgets/events/tail")
    assert resp.status_code == 400


def test_sync_events_tail_caps_limit(client):
    """limit > 100 is rejected with 422 by the OpenAPI query model so
    clients can't accidentally pull giant pages. (Older lenient
    behaviour clamped server-side; the explicit rejection is clearer
    feedback.)"""
    resp = client.get("/api/sync/qids/events/tail?limit=99999")
    assert resp.status_code == 422


def test_sync_events_tail_invalid_query_params_rejected(client):
    """Non-numeric since_id / limit return 422 (validation error)
    rather than silently defaulting — operators see why their request
    was wrong."""
    resp = client.get("/api/sync/qids/events/tail?since_id=abc&limit=notanumber")
    assert resp.status_code == 422


# ─── Tag Phase 2: cross-environment migration ─────────────────────────

def test_store_and_retrieve_tag_export():
    """Round-trip a JSON blob through tag_exports."""
    from app.database import store_tag_export, get_tag_export_json
    payload = b'{"id": 5001, "name": "Test Tag"}'
    store_tag_export(5001, payload, credential_id="cred-a")
    retrieved = get_tag_export_json(5001)
    assert retrieved == payload


def test_list_tag_exports_returns_metadata():
    """list_tag_exports joins tag_exports with the tags table so the
    UI can show name + rule_type alongside export metadata."""
    from app.database import store_tag_export, list_tag_exports, upsert_tag
    upsert_tag({"id": 5101, "name": "User Org", "ruleType": "GROOVY",
                "ruleText": "x:1", "createdBy": "alice"})
    store_tag_export(5101, b'{"id":5101,"name":"User Org"}', credential_id="cred-b")
    rows = list_tag_exports()
    found = [r for r in rows if r["tag_id"] == 5101]
    assert len(found) == 1
    assert found[0]["name"] == "User Org"
    assert found[0]["rule_type"] == "GROOVY"
    assert found[0]["payload_size"] > 0


def test_delete_tag_export():
    from app.database import store_tag_export, get_tag_export_json, delete_tag_export
    store_tag_export(5201, b'{"id":5201}', credential_id=None)
    assert get_tag_export_json(5201) is not None
    assert delete_tag_export(5201) is True
    assert get_tag_export_json(5201) is None
    assert delete_tag_export(5201) is False  # idempotent on missing


def test_create_tag_strips_source_metadata(monkeypatch):
    """create_tag must strip ids, timestamps, and reservedType-style
    metadata before POSTing to the destination env. Otherwise the
    destination either rejects the request or silently inherits the
    source environment's bookkeeping."""
    from app.qualys_client import QualysClient

    captured = {}

    def fake_execute_json(self, path, body=None, method="POST", timeout=30):
        captured["path"] = path
        captured["body"] = body
        return {
            "data": {"ServiceResponse": {
                "responseCode": "SUCCESS",
                "data": [{"Tag": {"id": 99999, "name": body["ServiceRequest"]["data"]["Tag"]["name"]}}],
            }}
        }

    monkeypatch.setattr(QualysClient, "execute_json", fake_execute_json)
    client = QualysClient("https://q.example.com", "u", "p")
    source = {
        "id": 5001, "name": "Crown Jewels",
        "ruleType": "GROOVY", "ruleText": "x:1", "color": "#ff0000",
        # Fields that must NOT make it into the destination request:
        "reservedType": "BUSINESS_UNIT",
        "createdBy": {"username": "alice"},
        "created": "2026-05-01T00:00:00Z",
        "modified": "2026-05-02T00:00:00Z",
        "parentTagId": 1234,
        "raw_json": "...",
        "is_user_created": 1,
        "classification_override": None,
    }
    result = client.create_tag(source)
    assert result.get("created") is True
    assert result.get("tag_id") == 99999
    sent = captured["body"]["ServiceRequest"]["data"]["Tag"]
    # Stripped:
    for stripped in ("id", "reservedType", "createdBy", "created", "modified",
                     "parentTagId", "raw_json", "is_user_created",
                     "classification_override"):
        assert stripped not in sent, f"{stripped} should be stripped"
    # Preserved:
    assert sent["name"] == "Crown Jewels"
    assert sent["ruleType"] == "GROOVY"
    assert sent["ruleText"] == "x:1"
    assert sent["color"] == "#ff0000"


def test_create_tag_applies_overrides(monkeypatch):
    """new_name and parent_tag_id from the caller take precedence over
    whatever was in the source payload."""
    from app.qualys_client import QualysClient

    captured = {}
    def fake(self, path, body=None, method="POST", timeout=30):
        captured["body"] = body
        return {"data": {"ServiceResponse": {
            "responseCode": "SUCCESS",
            "data": [{"Tag": {"id": 7, "name": "renamed"}}],
        }}}
    monkeypatch.setattr(QualysClient, "execute_json", fake)
    client = QualysClient("https://q.example.com", "u", "p")
    client.create_tag(
        {"name": "old", "ruleType": "GROOVY"},
        new_name="renamed", parent_tag_id=4242,
    )
    sent = captured["body"]["ServiceRequest"]["data"]["Tag"]
    assert sent["name"] == "renamed"
    assert sent["parentTagId"] == 4242


def test_create_tag_surfaces_qualys_error(monkeypatch):
    """If Qualys responds with responseCode != SUCCESS, create_tag
    returns an error dict instead of pretending it worked."""
    from app.qualys_client import QualysClient

    def fake(self, path, body=None, method="POST", timeout=30):
        return {"data": {"ServiceResponse": {
            "responseCode": "INVALID_REQUEST",
            "responseErrorDetails": {"errorMessage": "Tag name already exists"},
        }}}
    monkeypatch.setattr(QualysClient, "execute_json", fake)
    client = QualysClient("https://q.example.com", "u", "p")
    result = client.create_tag({"name": "dup"})
    assert result.get("error") is True
    assert "already exists" in result.get("message", "")


def test_tag_import_json_endpoint_stores_payload(client):
    """POST a JSON file → endpoint extracts the tag id and stores it."""
    import io
    payload = b'{"id": 6001, "name": "Imported From Disk", "ruleType": "GROOVY"}'
    data = {"file": (io.BytesIO(payload), "tag-6001.json")}
    resp = client.post("/api/tags/import-json", data=data,
                       content_type="multipart/form-data",
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["imported"] is True
    assert body["tag_id"] == 6001
    # Round-trip: stored export must match what we sent
    list_resp = client.get("/api/tags/exports")
    assert any(r["tag_id"] == 6001 for r in list_resp.get_json())


def test_tag_import_json_rejects_non_json(client):
    import io
    data = {"file": (io.BytesIO(b"not json at all"), "bad.json")}
    resp = client.post("/api/tags/import-json", data=data,
                       content_type="multipart/form-data",
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 400


def test_tag_import_json_rejects_missing_id(client):
    import io
    data = {"file": (io.BytesIO(b'{"name": "no id"}'), "noid.json")}
    resp = client.post("/api/tags/import-json", data=data,
                       content_type="multipart/form-data",
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 400


def test_tag_export_download_404_when_not_exported(client):
    resp = client.get("/api/tags/9999999/export-download")
    assert resp.status_code == 404


def test_tag_upload_rejects_system_tag(client):
    """A tag with reservedType in its stored payload must not be
    pushed to a destination env — Qualys would reject it server-side
    and the error would be confusing for the operator."""
    from app.database import store_tag_export
    store_tag_export(7001, b'{"id":7001,"name":"OS","reservedType":"OPERATING_SYSTEM"}',
                     credential_id=None)
    resp = client.post("/api/tags/upload",
                       json={"source_tag_id": 7001, "credential_id": "irrelevant"},
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 400
    body = resp.get_json()
    assert body.get("system_tag") is True


def test_tag_upload_404_when_no_export(client):
    resp = client.post("/api/tags/upload",
                       json={"source_tag_id": 99999, "credential_id": "x"},
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 404


# ─── Tag Phase 3: validation ──────────────────────────────────────────

def test_validate_tag_rejects_missing_name():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"ruleType": "STATIC"})
    assert not r.ok and "name" in r.errors


def test_validate_tag_accepts_static_with_no_ruletext():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "Manual", "ruleType": "STATIC"})
    assert r.ok


def test_validate_tag_requires_ruletext_for_network_range():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "NETWORK_RANGE"})
    assert not r.ok and "ruleText" in r.errors


def test_validate_tag_catches_bad_cidr():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "NETWORK_RANGE",
                              "ruleText": "10.0.0.0/8, 999.1.1.1"})
    assert not r.ok and "ruleText" in r.errors


def test_validate_tag_accepts_good_cidr():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "NETWORK_RANGE",
                              "ruleText": "10.0.0.0/8, 192.168.1.10"})
    assert r.ok


def test_validate_tag_catches_bad_regex():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "OS_REGEX",
                              "ruleText": "Windows[unclosed"})
    assert not r.ok and "ruleText" in r.errors


def test_validate_tag_catches_port_out_of_range():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "OPEN_PORTS",
                              "ruleText": "80, 99999"})
    assert not r.ok and "ruleText" in r.errors


def test_validate_tag_catches_reversed_port_range():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "OPEN_PORTS",
                              "ruleText": "8090-8080"})
    assert not r.ok


def test_validate_tag_catches_bad_color():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "STATIC", "color": "red"})
    assert not r.ok and "color" in r.errors


def test_validate_tag_catches_criticality_out_of_range():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "STATIC", "criticalityScore": 99})
    assert not r.ok and "criticality" in r.errors


def test_validate_tag_warns_unknown_rule_type():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "UNKNOWN_X", "ruleText": "x"})
    assert "ruleType" in r.warnings


def test_validate_tag_catches_vuln_exist_not_int():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "VULN_EXIST",
                              "ruleText": "not-a-qid"})
    assert not r.ok


# ─── Tag Phase 3: API surface ─────────────────────────────────────────

def test_tag_validate_endpoint_runs_server_side(client):
    """POST /api/tags/validate echoes structured per-field errors."""
    resp = client.post("/api/tags/validate",
                       json={"name": "", "rule_type": "NETWORK_RANGE",
                             "rule_text": "bad/bad/bad"},
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is False
    assert "name" in body["errors"]
    assert "ruleText" in body["errors"]


def test_tag_update_refuses_locked_tag(client):
    """A tag whose effective is_editable is 0 cannot be edited even with
    a payload that would otherwise validate. Operator must set Force
    Editable override first."""
    from app.database import upsert_tag
    upsert_tag({"id": 12001, "name": "OS", "reservedType": "OPERATING_SYSTEM"})
    resp = client.post("/api/tags/12001/update",
                       json={"name": "OS edited", "rule_type": "STATIC",
                             "credential_id": "anything"},
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 403
    assert resp.get_json().get("is_editable") == 0


def test_tag_update_404_when_local_missing(client):
    resp = client.post("/api/tags/99999/update",
                       json={"name": "x", "credential_id": "y"},
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 404


def test_tag_impact_returns_child_count(client):
    from app.database import upsert_tag
    upsert_tag({"id": 12100, "name": "Parent", "createdBy": "alice",
                "ruleType": "GROOVY", "ruleText": "x:1"})
    upsert_tag({"id": 12101, "name": "Child A", "parentTagId": 12100,
                "createdBy": "alice", "ruleType": "GROOVY", "ruleText": "x:1"})
    upsert_tag({"id": 12102, "name": "Child B", "parentTagId": 12100,
                "createdBy": "alice", "ruleType": "GROOVY", "ruleText": "x:1"})
    resp = client.get("/api/tags/12100/impact")
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["child_count"] == 2
    assert body["name"] == "Parent"


def test_tag_delete_refuses_locked_tag(client):
    from app.database import upsert_tag
    upsert_tag({"id": 12200, "name": "OS", "reservedType": "OPERATING_SYSTEM"})
    resp = client.post("/api/tags/12200/delete",
                       json={"credential_id": "x"},
                       headers={"X-Requested-With": "QKBE"})
    assert resp.status_code == 403


def test_qualys_client_update_tag_strips_metadata(monkeypatch):
    from app.qualys_client import QualysClient
    captured = {}

    def fake_execute_json(self, path, body=None, method="POST", timeout=30):
        captured["path"] = path
        captured["body"] = body
        return {"data": {"ServiceResponse": {"responseCode": "SUCCESS",
                "data": [{"Tag": {"id": 12300}}]}}}

    monkeypatch.setattr(QualysClient, "execute_json", fake_execute_json)
    client = QualysClient("https://q.example.com", "u", "p")
    result = client.update_tag(12300, {
        "id": 12300, "name": "renamed",
        "createdBy": "alice", "reservedType": "BUSINESS_UNIT",
    })
    assert result["updated"] is True
    sent = captured["body"]["ServiceRequest"]["data"]["Tag"]
    assert "id" not in sent and "createdBy" not in sent and "reservedType" not in sent
    assert sent["name"] == "renamed"
    assert "/qps/rest/2.0/update/am/tag/12300" in captured["path"]


def test_qualys_client_update_tag_refuses_empty_payload():
    from app.qualys_client import QualysClient
    client = QualysClient("https://q.example.com", "u", "p")
    r = client.update_tag(1, {})
    assert r.get("error") is True


def test_qualys_client_delete_tag_calls_post_and_id(monkeypatch):
    from app.qualys_client import QualysClient
    captured = {}

    def fake_execute_json(self, path, body=None, method="POST", timeout=30):
        captured["path"] = path
        captured["method"] = method
        return {"data": {"ServiceResponse": {"responseCode": "SUCCESS"}}}

    monkeypatch.setattr(QualysClient, "execute_json", fake_execute_json)
    client = QualysClient("https://q.example.com", "u", "p")
    r = client.delete_tag(7777)
    assert r["deleted"] is True
    assert captured["path"].endswith("/delete/am/tag/7777")
    assert captured["method"] == "POST"


def test_qualys_client_evaluate_tag_returns_count(monkeypatch):
    from app.qualys_client import QualysClient

    def fake(self, path, body=None, method="POST", timeout=30):
        return {"data": {"ServiceResponse": {
            "responseCode": "SUCCESS", "count": 247,
        }}}

    monkeypatch.setattr(QualysClient, "execute_json", fake)
    client = QualysClient("https://q.example.com", "u", "p")
    r = client.evaluate_tag_payload({"name": "T", "ruleType": "STATIC"})
    assert r["ok"] is True and r["asset_count"] == 247


def test_qualys_client_evaluate_tag_soft_fallback_on_404(monkeypatch):
    from app.qualys_client import QualysClient

    def fake(self, path, body=None, method="POST", timeout=30):
        return {"error": True, "status_code": 404, "message": "Resource not found"}

    monkeypatch.setattr(QualysClient, "execute_json", fake)
    client = QualysClient("https://q.example.com", "u", "p")
    r = client.evaluate_tag_payload({"name": "T", "ruleType": "STATIC"})
    assert r["ok"] is False and r["fallback"] is True


# ─── Tag Phase 4: Library + Apply ────────────────────────────────────

def test_library_seeded_on_init():
    """Built-in entries should be present after init_db() runs.
    The conftest fixture already calls init_db() before this test."""
    from app.database import list_library_entries
    rows = list_library_entries()
    assert len(rows) >= 5
    assert all(r["is_builtin"] == 1 for r in rows)
    slugs = {r["slug"] for r in rows}
    assert "rfc1918-private-network" in slugs


def test_library_create_user_entry():
    from app.database import create_library_entry, get_library_entry
    new_id = create_library_entry({
        "name": "My Custom Tag",
        "category": "Custom",
        "description": "test",
        "rule_type": "STATIC",
    })
    row = get_library_entry(new_id)
    assert row["is_builtin"] == 0
    assert row["slug"] == "my-custom-tag"


def test_library_create_dedupes_slug():
    """Two entries with the same name get distinct slugs."""
    from app.database import create_library_entry, get_library_entry
    a = create_library_entry({"name": "Same Name", "rule_type": "STATIC"})
    b = create_library_entry({"name": "Same Name", "rule_type": "STATIC"})
    assert get_library_entry(a)["slug"] != get_library_entry(b)["slug"]


def test_library_update_user_entry():
    from app.database import create_library_entry, update_library_entry, get_library_entry
    nid = create_library_entry({"name": "Editable", "rule_type": "STATIC"})
    assert update_library_entry(nid, {"description": "new desc"}) is True
    assert get_library_entry(nid)["description"] == "new desc"


def test_library_update_refuses_builtin():
    from app.database import list_library_entries, update_library_entry
    builtin = next(e for e in list_library_entries() if e["is_builtin"])
    import pytest
    with pytest.raises(PermissionError):
        update_library_entry(builtin["library_id"], {"name": "hacked"})


def test_library_delete_user_entry_removes_row():
    from app.database import create_library_entry, delete_library_entry, get_library_entry
    nid = create_library_entry({"name": "ephemeral", "rule_type": "STATIC"})
    assert delete_library_entry(nid) is True
    assert get_library_entry(nid) is None


def test_library_delete_builtin_hides_only():
    from app.database import list_library_entries, delete_library_entry, get_library_entry
    builtin = next(e for e in list_library_entries() if e["is_builtin"])
    bid = builtin["library_id"]
    assert delete_library_entry(bid) is True
    after = get_library_entry(bid)
    # Row still there, just hidden
    assert after is not None
    assert after["is_hidden"] == 1


def test_library_unhide_restores_builtin():
    from app.database import list_library_entries, delete_library_entry, unhide_library_entry, get_library_entry
    builtin = next(e for e in list_library_entries() if e["is_builtin"])
    bid = builtin["library_id"]
    delete_library_entry(bid)
    assert unhide_library_entry(bid) is True
    assert get_library_entry(bid)["is_hidden"] == 0


def test_library_hidden_excluded_by_default():
    from app.database import list_library_entries, delete_library_entry
    builtin = next(e for e in list_library_entries() if e["is_builtin"])
    delete_library_entry(builtin["library_id"])
    visible = list_library_entries()
    visible_ids = {e["library_id"] for e in visible}
    assert builtin["library_id"] not in visible_ids
    all_entries = list_library_entries(include_hidden=True)
    all_ids = {e["library_id"] for e in all_entries}
    assert builtin["library_id"] in all_ids


def test_library_clone_creates_user_copy():
    from app.database import list_library_entries, clone_library_entry, get_library_entry
    builtin = next(e for e in list_library_entries() if e["is_builtin"])
    new_id = clone_library_entry(builtin["library_id"])
    cloned = get_library_entry(new_id)
    assert cloned["is_builtin"] == 0
    assert cloned["name"].startswith(builtin["name"])


def test_library_seed_preserves_user_slug_collision():
    """If a user already owns a slug a built-in wants, re-seeding must
    not clobber their entry. Construct that state by deleting the
    built-in row entirely (force-bypassing the hide-instead-of-delete
    helper) then writing a user row with that slug."""
    from app.database import (
        get_db, seed_library_builtins, get_library_entry_by_slug,
    )
    slug = "rfc1918-private-network"
    with get_db() as conn:
        conn.execute("DELETE FROM tag_library WHERE slug=?", (slug,))
        conn.execute(
            """INSERT INTO tag_library (slug, name, category, rule_type,
                is_builtin, is_hidden, created_at, updated_at)
               VALUES (?, ?, ?, ?, 0, 0, ?, ?)""",
            (slug, "User Wins", "Custom", "STATIC",
             "2026-05-02T00:00:00Z", "2026-05-02T00:00:00Z"),
        )
    seed_library_builtins()
    row = get_library_entry_by_slug(slug)
    assert row["is_builtin"] == 0
    assert row["name"] == "User Wins"


def test_library_record_apply_and_list():
    from app.database import (
        create_library_entry, record_library_apply, list_library_applies,
    )
    nid = create_library_entry({"name": "Trackable", "rule_type": "STATIC"})
    record_library_apply(library_id=nid,
                         destination_credential_id="cred-z",
                         destination_platform="US1",
                         destination_tag_id=999000,
                         destination_tag_name="Trackable")
    rows = list_library_applies(library_id=nid)
    assert len(rows) == 1
    assert rows[0]["destination_tag_id"] == 999000
    assert rows[0]["library_name"] == "Trackable"


def test_library_api_list_returns_builtins(client):
    resp = client.get("/api/library")
    assert resp.status_code == 200
    body = resp.get_json()
    assert isinstance(body, list)
    assert len(body) >= 5


def test_library_api_create_then_get(client):
    resp = client.post(
        "/api/library",
        json={"name": "API Test Entry", "rule_type": "NETWORK_RANGE",
              "rule_text": "10.0.0.0/8", "category": "Custom"},
        headers={"X-Requested-With": "QKBE"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["created"] is True
    nid = body["library_id"]
    resp2 = client.get(f"/api/library/{nid}")
    assert resp2.get_json()["name"] == "API Test Entry"


def test_library_api_create_rejects_bad_rule(client):
    resp = client.post(
        "/api/library",
        json={"name": "Bad", "rule_type": "NETWORK_RANGE",
              "rule_text": "999.999.999.999/8"},
        headers={"X-Requested-With": "QKBE"},
    )
    assert resp.status_code == 400
    assert "ruleText" in resp.get_json()["errors"]


def test_library_api_update_user_entry(client):
    create = client.post(
        "/api/library",
        json={"name": "Editable API", "rule_type": "STATIC"},
        headers={"X-Requested-With": "QKBE"},
    ).get_json()
    nid = create["library_id"]
    resp = client.patch(
        f"/api/library/{nid}",
        json={"description": "updated"},
        headers={"X-Requested-With": "QKBE"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["entry"]["description"] == "updated"


def test_library_api_update_builtin_returns_403(client):
    listing = client.get("/api/library").get_json()
    builtin = next(e for e in listing if e["is_builtin"])
    resp = client.patch(
        f"/api/library/{builtin['library_id']}",
        json={"name": "hacked"},
        headers={"X-Requested-With": "QKBE"},
    )
    assert resp.status_code == 403


def test_library_api_apply_404_unknown_entry(client):
    resp = client.post(
        "/api/library/9999999/apply",
        json={"credential_id": "x", "platform": "US1"},
        headers={"X-Requested-With": "QKBE"},
    )
    assert resp.status_code == 404


def test_library_api_apply_history_endpoint(client):
    resp = client.get("/api/library/applies")
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)


# ─── Tag Phase 5: Subscription audit ──────────────────────────────────

def _audit_rule_ids(result, rule_id):
    """Helper: pluck all findings with a given rule_id from a run_audit result."""
    return [f for f in result["findings"] if f["rule_id"] == rule_id]


def test_audit_orphan_parent_flagged():
    from app.tag_audit import run_audit
    tags = [
        {"tag_id": 1, "name": "Child", "parent_tag_id": 9999},  # parent missing
    ]
    result = run_audit(tags)
    orphans = _audit_rule_ids(result, "HIERARCHY_ORPHAN")
    assert len(orphans) == 1
    assert orphans[0]["severity"] == "error"
    assert orphans[0]["tag_id"] == 1


def test_audit_no_orphan_when_parent_exists():
    from app.tag_audit import run_audit
    tags = [
        {"tag_id": 1, "name": "Parent"},
        {"tag_id": 2, "name": "Child", "parent_tag_id": 1},
    ]
    result = run_audit(tags)
    assert _audit_rule_ids(result, "HIERARCHY_ORPHAN") == []


def test_audit_cycle_flagged():
    from app.tag_audit import run_audit
    # 1 → 2 → 3 → 1
    tags = [
        {"tag_id": 1, "name": "A", "parent_tag_id": 3},
        {"tag_id": 2, "name": "B", "parent_tag_id": 1},
        {"tag_id": 3, "name": "C", "parent_tag_id": 2},
    ]
    result = run_audit(tags)
    cycles = _audit_rule_ids(result, "HIERARCHY_CYCLE")
    assert len(cycles) >= 1
    assert all(c["severity"] == "error" for c in cycles)


def test_audit_depth_limit_flagged():
    from app.tag_audit import run_audit, MAX_HIERARCHY_DEPTH
    # Build a chain one level past the limit.
    tags = []
    chain_len = MAX_HIERARCHY_DEPTH + 2
    for i in range(1, chain_len + 1):
        tags.append({
            "tag_id": i, "name": f"L{i}",
            "parent_tag_id": i - 1 if i > 1 else None,
        })
    result = run_audit(tags)
    deep = _audit_rule_ids(result, "HIERARCHY_TOO_DEEP")
    assert len(deep) >= 1
    assert any(f["tag_id"] == chain_len for f in deep)


def test_audit_wide_root_flagged():
    from app.tag_audit import run_audit, WIDE_ROOT_DIRECT_CHILDREN
    tags = [{"tag_id": 1, "name": "Root"}]
    for i in range(2, 2 + WIDE_ROOT_DIRECT_CHILDREN + 5):
        tags.append({"tag_id": i, "name": f"C{i}", "parent_tag_id": 1})
    result = run_audit(tags)
    wide = _audit_rule_ids(result, "HIERARCHY_WIDE_ROOT")
    assert len(wide) == 1
    assert wide[0]["severity"] == "warn"


def test_audit_naming_whitespace():
    from app.tag_audit import run_audit
    tags = [{"tag_id": 1, "name": "  Padded  "}]
    result = run_audit(tags)
    assert len(_audit_rule_ids(result, "NAMING_WHITESPACE")) == 1


def test_audit_naming_short():
    from app.tag_audit import run_audit
    tags = [{"tag_id": 1, "name": "X"}]
    result = run_audit(tags)
    assert len(_audit_rule_ids(result, "NAMING_SHORT")) == 1


def test_audit_naming_long():
    from app.tag_audit import run_audit, NAME_RECOMMENDED_MAX
    tags = [{"tag_id": 1, "name": "x" * (NAME_RECOMMENDED_MAX + 1)}]
    result = run_audit(tags)
    assert len(_audit_rule_ids(result, "NAMING_LONG")) == 1


def test_audit_naming_too_long():
    from app.tag_audit import run_audit, NAME_HARD_MAX
    tags = [{"tag_id": 1, "name": "x" * (NAME_HARD_MAX + 1)}]
    result = run_audit(tags)
    assert len(_audit_rule_ids(result, "NAMING_TOO_LONG")) == 1


def test_audit_naming_empty():
    from app.tag_audit import run_audit
    tags = [{"tag_id": 1, "name": ""}]
    result = run_audit(tags)
    assert len(_audit_rule_ids(result, "NAMING_EMPTY")) == 1


def test_audit_duplicate_names_case_insensitive():
    from app.tag_audit import run_audit
    tags = [
        {"tag_id": 1, "name": "Critical"},
        {"tag_id": 2, "name": "critical"},
        {"tag_id": 3, "name": "CRITICAL"},
    ]
    result = run_audit(tags)
    dups = _audit_rule_ids(result, "NAMING_DUPLICATE")
    # One finding per member of the colliding group
    assert len(dups) == 3


def test_audit_duplicate_rule_text():
    from app.tag_audit import run_audit
    tags = [
        {"tag_id": 1, "name": "A", "rule_type": "NETWORK_RANGE",
         "rule_text": "10.0.0.0/8"},
        {"tag_id": 2, "name": "B", "rule_type": "NETWORK_RANGE",
         "rule_text": "10.0.0.0/8"},
    ]
    result = run_audit(tags)
    dups = _audit_rule_ids(result, "DUPLICATE_RULE")
    assert len(dups) == 2


def test_audit_skips_static_rule_text_dup():
    """STATIC tags share an empty rule_text — that's not a duplication
    finding, it's just how STATIC works."""
    from app.tag_audit import run_audit
    tags = [
        {"tag_id": 1, "name": "Manual A", "rule_type": "STATIC", "rule_text": ""},
        {"tag_id": 2, "name": "Manual B", "rule_type": "STATIC", "rule_text": ""},
    ]
    result = run_audit(tags)
    assert _audit_rule_ids(result, "DUPLICATE_RULE") == []


def test_audit_classification_override_info():
    from app.tag_audit import run_audit
    tags = [{
        "tag_id": 1, "name": "Edge case",
        "is_user_created": 1, "is_user_created_auto": 0,
        "classification_override": "user",
    }]
    result = run_audit(tags)
    findings = _audit_rule_ids(result, "CLASSIFICATION_OVERRIDE")
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"


def test_audit_editability_override_info():
    from app.tag_audit import run_audit
    tags = [{
        "tag_id": 1, "name": "Internet Facing",
        "is_editable": 1, "is_editable_auto": 0,
        "editability_override": "editable",
    }]
    result = run_audit(tags)
    findings = _audit_rule_ids(result, "EDITABILITY_OVERRIDE")
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"


def test_audit_summary_counts():
    from app.tag_audit import run_audit
    tags = [
        {"tag_id": 1, "name": "X"},                      # NAMING_SHORT (warn)
        {"tag_id": 2, "name": "Orphan", "parent_tag_id": 999},  # HIERARCHY_ORPHAN (error)
    ]
    result = run_audit(tags)
    assert result["summary"]["error"] >= 1
    assert result["summary"]["warn"] >= 1
    assert result["summary"]["tag_count"] == 2


def test_audit_groups_ordered_by_severity():
    from app.tag_audit import run_audit
    tags = [
        {"tag_id": 1, "name": "X"},
        {"tag_id": 2, "name": "Orphan", "parent_tag_id": 999},
    ]
    result = run_audit(tags)
    # Errors first
    severities = [g["severity"] for g in result["groups"]]
    seen_warn = False
    for s in severities:
        if s == "error":
            assert not seen_warn, "errors should sort before warns"
        elif s == "warn":
            seen_warn = True


def test_audit_endpoint_returns_findings(client):
    """End-to-end: load a couple of synthetic tags, hit /api/tags/audit,
    confirm the findings flow through."""
    from app.database import upsert_tag, get_db
    upsert_tag({"id": 80001, "name": "X"})  # too short
    upsert_tag({"id": 80002, "name": "Orphan",
                "parentTagId": 99999999})  # orphan
    resp = client.get("/api/tags/audit")
    assert resp.status_code == 200
    body = resp.get_json()
    rules_seen = {f["rule_id"] for f in body["findings"]}
    assert "NAMING_SHORT" in rules_seen
    assert "HIERARCHY_ORPHAN" in rules_seen


def test_audit_csv_export(client):
    from app.database import upsert_tag
    upsert_tag({"id": 80101, "name": "Y"})  # short → finding
    resp = client.get("/api/tags/audit.csv")
    assert resp.status_code == 200
    assert resp.headers.get("Content-Type", "").startswith("text/csv")
    body = resp.data.decode("utf-8")
    assert "severity,rule_id" in body  # header row
    assert "NAMING_SHORT" in body


def test_audit_single_rule_endpoint(client):
    from app.database import upsert_tag
    upsert_tag({"id": 80201, "name": "Q"})  # short
    resp = client.get("/api/tags/audit/NAMING_SHORT")
    body = resp.get_json()
    assert body["rule_id"] == "NAMING_SHORT"
    assert body["count"] >= 1
    assert all(f["rule_id"] == "NAMING_SHORT" for f in body["findings"])


def test_audit_single_rule_unknown_returns_empty(client):
    resp = client.get("/api/tags/audit/NOT_A_REAL_RULE")
    body = resp.get_json()
    assert body["rule_id"] == "NOT_A_REAL_RULE"
    assert body["count"] == 0
    assert body["findings"] == []


# ─── Rule-type best-practice metadata (legacy / restricted) ───────────

def test_validate_warns_on_os_regex_legacy():
    """OS_REGEX still works but should emit a 'legacy' warning that
    points operators at the ASSET_INVENTORY replacement."""
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "OS_REGEX",
                              "ruleText": "^Windows.*"})
    assert r.ok is True  # still valid, just a warning
    assert "ruleType" in r.warnings
    msgs = " ".join(r.warnings["ruleType"])
    assert "LEGACY" in msgs
    assert "ASSET_INVENTORY" in msgs


def test_validate_warns_on_groovy_restricted():
    """GROOVY rules require Qualys backend enablement — warn the
    operator up front so Test on Qualys isn't their first signal."""
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "GROOVY",
                              "ruleText": "asset.name.contains('foo')"})
    assert r.ok is True
    assert "ruleType" in r.warnings
    msgs = " ".join(r.warnings["ruleType"])
    assert "RESTRICTED" in msgs
    assert "enabled" in msgs.lower()


def test_validate_warns_on_operating_system_legacy():
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "OPERATING_SYSTEM",
                              "ruleText": "Windows Server 2019"})
    assert r.ok is True
    assert "ruleType" in r.warnings
    assert "LEGACY" in " ".join(r.warnings["ruleType"])


def test_validate_no_status_warning_for_preferred_rule_type():
    """ASSET_INVENTORY is the recommended replacement and shouldn't
    carry a status warning."""
    from app.tag_validation import validate_tag_payload
    r = validate_tag_payload({"name": "T", "ruleType": "ASSET_INVENTORY",
                              "ruleText": "operatingSystem:Windows"})
    assert r.ok is True
    # ruleType warnings array should NOT contain a [LEGACY] or [RESTRICTED] tag
    rt_warnings = r.warnings.get("ruleType", [])
    joined = " ".join(rt_warnings)
    assert "LEGACY" not in joined
    assert "RESTRICTED" not in joined


def test_validate_endpoint_emits_status_warning(client):
    """End-to-end: the /api/tags/validate response includes the
    legacy/restricted warning under warnings.ruleType."""
    resp = client.post("/api/tags/validate",
                       json={"name": "T", "rule_type": "GROOVY",
                             "rule_text": "asset.name.contains('x')"},
                       headers={"X-Requested-With": "QKBE"})
    body = resp.get_json()
    assert body["ok"] is True  # not a hard error
    assert "ruleType" in body.get("warnings", {})
    assert "RESTRICTED" in " ".join(body["warnings"]["ruleType"])


# ─── Policy → CID auto-queue dependency ──────────────────────────────

def test_policies_no_longer_400_on_missing_cid_sync(client, monkeypatch):
    """Triggering Policies when CIDs have never synced used to 400 with
    'CID data required'. New behavior: auto-enqueue CIDs first, then
    Policies. The endpoint returns 200, not 400, and the response says
    we auto-queued cids."""
    # Save a credential so _build_client succeeds
    from app.vault import save_credential
    save_credential("dep_user", "dep_pw_1234567", "US1")
    creds = client.get("/api/credentials").get_json()
    cred_id = creds[0]["id"]

    # Stub out the actual sync engine so the worker thread doesn't
    # try to hit Qualys. The point of the test is the dispatch path,
    # not real syncing.
    from app.sync import SyncEngine
    monkeypatch.setattr(SyncEngine, "sync_cids", lambda self, full=False: {"items_synced": 0})
    monkeypatch.setattr(SyncEngine, "sync_policies", lambda self, full=False: {"items_synced": 0})

    resp = client.post(
        "/api/sync/policies",
        json={"credential_id": cred_id, "platform": "US1"},
        headers={"X-Requested-With": "QKBE"},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body.get("auto_queued_dependencies") == ["cids"]
    assert "cids" in (body.get("message") or "").lower()


def test_intelligence_stats_uses_single_query_aggregate(client):
    """Intelligence stats endpoint returns the same totals the old
    11-query loop did, but in one round-trip. Smoke-test the new
    aggregate_qid_intelligence_stats function via the endpoint."""
    from app.database import upsert_vuln
    upsert_vuln({"QID": "21001", "TITLE": "Stats test 1", "SEVERITY_LEVEL": "5",
                 "CATEGORY": "X", "PATCHABLE": "1", "PCI_FLAG": "1"})
    upsert_vuln({"QID": "21002", "TITLE": "Stats test 2", "SEVERITY_LEVEL": "4",
                 "CATEGORY": "Y", "PATCHABLE": "1", "PCI_FLAG": "0"})
    upsert_vuln({"QID": "21003", "TITLE": "Stats test 3", "SEVERITY_LEVEL": "3",
                 "CATEGORY": "Y", "PATCHABLE": "0", "PCI_FLAG": "1"})

    # Filter to category Y so we know exactly what to expect
    resp = client.get("/api/intelligence/stats?category=Y")
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["total_qids"] == 2
    assert body["kb_patchable"] == 1   # only 21002
    assert body["pci"] == 1            # only 21003
    assert body["sev_4"] == 1
    assert body["sev_3"] == 1
    assert body["sev_5"] == 0


def test_intelligence_stats_empty_filtered_set(client):
    """Empty filtered set returns all-zeros, not nulls or 500."""
    resp = client.get("/api/intelligence/stats?category=NoSuchCategory")
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["total_qids"] == 0
    assert body["kb_patchable"] == 0


def test_scheduler_supports_daily_cadence():
    """The Daily delta-sync cadence is added to FREQUENCY_DAYS so the
    middleware/freshness-sensitive use case has a 1-day option."""
    from app.scheduler import FREQUENCY_DAYS, FREQUENCY_LABELS
    assert "daily" in FREQUENCY_DAYS
    assert FREQUENCY_DAYS["daily"] == 1
    assert FREQUENCY_LABELS["daily"] == "Daily"


def test_policies_with_existing_cid_sync_does_not_auto_queue(client, monkeypatch):
    """If CIDs already synced, the auto-queue path stays out of the way."""
    from app.vault import save_credential
    save_credential("dep_user2", "dep_pw_1234567", "US1")
    creds = client.get("/api/credentials").get_json()
    cred_id = creds[0]["id"]

    # Backdate the cids watermark so the dependency check sees it.
    from app.database import get_db
    with get_db() as conn:
        conn.execute(
            "UPDATE sync_state SET last_sync_datetime=? WHERE data_type='cids'",
            ("2026-05-01T00:00:00Z",),
        )

    from app.sync import SyncEngine
    monkeypatch.setattr(SyncEngine, "sync_policies", lambda self, full=False: {"items_synced": 0})

    resp = client.post(
        "/api/sync/policies",
        json={"credential_id": cred_id, "platform": "US1"},
        headers={"X-Requested-With": "QKBE"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert "auto_queued_dependencies" not in body
