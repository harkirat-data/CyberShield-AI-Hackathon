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
