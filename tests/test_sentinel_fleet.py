"""
Unit & integration tests for Protected Applications Fleet and Sentinel Agent extension.
"""

import pytest
from starlette.testclient import TestClient
from honeypot.server import app


@pytest.fixture
def client():
    return TestClient(app)


def test_medicare_portal_route(client):
    response = client.get("/apps/medicare")
    assert response.status_code == 200
    assert "Medicare.AI" in response.text
    assert "/api/v1/sentinel/agent.js" in response.text


def test_medicare_shortcut_route(client):
    response = client.get("/medicare")
    assert response.status_code == 200
    assert "Medicare.AI" in response.text


def test_sentinel_agent_js_route(client):
    response = client.get("/api/v1/sentinel/agent.js")
    assert response.status_code == 200
    assert "application/javascript" in response.headers.get("content-type", "")
    assert "CyberShield" in response.text
    assert "cs-sentinel-badge" in response.text


def test_sentinel_site_status_api(client):
    response = client.get("/api/v1/sentinel/site-status/medicare-ai")
    assert response.status_code == 200
    data = response.json()
    assert data["site_id"] == "medicare-ai"
    assert data["status"] == "active"
    assert "total_blocked" in data
    assert "active_tripwires" in data
    assert isinstance(data["incidents"], list)
    assert len(data["incidents"]) > 0


def test_finance_portal_has_sentinel_script(client):
    response = client.get("/finance-portal")
    assert response.status_code == 200
    assert "/api/v1/sentinel/agent.js" in response.text
    assert 'data-site-id="apex-finance"' in response.text


def test_dashboard_has_protected_apps_section(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "protected-apps-section" in response.text
    assert "Protected Applications" in response.text
    assert "Medicare.AI" in response.text
    assert "Apex Global Treasury" in response.text
    assert "OmniCloud Enterprise IAM" in response.text
    assert "btn-manage-quarantine" in response.text
    assert "quarantine-modal-overlay" in response.text


def test_protected_app_config_endpoints(client):
    get_res = client.get("/api/v1/protected/config")
    assert get_res.status_code == 200
    cfg = get_res.json()
    assert "block_score_threshold" in cfg

    post_res = client.post(
        "/api/v1/protected/config",
        json={"block_score_threshold": 78, "rate_limiting_enabled": True}
    )
    assert post_res.status_code == 200
    updated = post_res.json()
    assert updated.get("block_score_threshold") == 78


def test_protected_app_export_rules(client):
    for fmt in ["modsecurity", "nginx", "cloudflare"]:
        res = client.get(f"/api/v1/protected/export-rules?format={fmt}")
        assert res.status_code == 200
        data = res.json()
        assert data["format"] == fmt
        assert "content" in data
        assert "filename" in data


def test_protected_app_banned_ips_and_unban(client):
    res = client.get("/api/v1/protected/banned-ips")
    assert res.status_code == 200
    data = res.json()
    assert "banned_ips" in data
    assert isinstance(data["banned_ips"], list)

    unban_res = client.post("/api/v1/protected/unban-ip", json={"ip": "198.51.100.99"})
    assert unban_res.status_code == 200
    unban_data = unban_res.json()
    assert unban_data["ip"] == "198.51.100.99"


def test_protected_app_health_audit(client):
    res = client.post("/api/v1/protected/health-audit")
    assert res.status_code == 200
    data = res.json()
    assert data["target_app"] == "Medicare.AI"
    assert "health_score" in data
    assert "owasp_breakdown" in data
    assert "virtual_patches_applied" in data


def test_protected_app_simulate_attack(client):
    for attack in ["sqli", "xss", "rce", "path_traversal"]:
        res = client.post("/api/v1/protected/simulate-attack", json={"vector": attack})
        assert res.status_code == 200
        data = res.json()
        assert data["ok"] is True
        assert data["vector"] == attack
        assert "risk_score" in data
        assert "blocked" in data


def test_proxy_sqli_attack_blocked(client):
    res = client.get("/proxy/api/hospitals?specialty=' OR 1=1--")
    assert res.status_code == 403
    assert "WAF" in res.text or "Blocked" in res.text


