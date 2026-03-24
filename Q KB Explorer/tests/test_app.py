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

from app.main import app  # noqa: E402


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        # Set vault unlock cookie so auth gate doesn't block tests
        c.set_cookie("qkbe-vault-unlocked", "1")
        yield c


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
    })
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
    resp2 = client.delete(f"/api/credentials/{cred_id}")
    assert resp2.status_code == 200
    assert resp2.get_json()["deleted"] is True

    # Delete again → 404
    resp3 = client.delete(f"/api/credentials/{cred_id}")
    assert resp3.status_code == 404


def test_credentials_delete_nonexistent(client):
    resp = client.delete("/api/credentials/nonexistent-id")
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
    resp = client.post("/api/test-connection", json={})
    assert resp.status_code == 400


def test_connection_unknown_platform(client):
    resp = client.post("/api/test-connection", json={
        "username": "fake",
        "password": "fake",
        "platform": "INVALID",
    })
    assert resp.status_code == 400
    assert "Unknown platform" in resp.get_json()["error"]


def test_connection_raw_creds_missing_password(client):
    resp = client.post("/api/test-connection", json={
        "username": "user",
        "platform": "US1",
    })
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
    resp = client.post("/api/sync/qids", json={})
    assert resp.status_code == 400


def test_sync_trigger_invalid_type(client):
    resp = client.post("/api/sync/invalid", json={})
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
    """API routes work when vault has creds AND unlock cookie is present."""
    unauthed_client.set_cookie("qkbe-vault-unlocked", "1")
    resp = unauthed_client.get("/api/sync/status")
    assert resp.status_code == 200


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
