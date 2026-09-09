import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from fastapi.testclient import TestClient
from Ai.backend.api_server import create_app
from honeypot.store import TelemetryStore
import tempfile

@pytest.fixture
def store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = TelemetryStore(path)
    yield db
    db.close()
    try:
        os.remove(path)
    except OSError:
        pass

@pytest.fixture
def app_instance(store):
    return create_app(
        use_rag=False, 
        use_llm=False, 
        honeypot_store=store, 
        honeypot_autostart=False
    )

@pytest.fixture
def client(app_instance):
    return TestClient(app_instance)

def test_create_and_list_canary_tokens(client):
    # Create
    res = client.post("/api/v1/canary/tokens", json={
        "name": "Test URL",
        "token_type": "url",
        "metadata": {"test": "yes"}
    })
    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True
    assert "token" in data
    token_id = data["token"]["token_id"]
    secret = data["token"]["secret"]

    # List
    res = client.get("/api/v1/canary/tokens")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 1
    assert data["tokens"][0]["token_id"] == token_id

    # Retrieve
    res = client.get(f"/api/v1/canary/tokens/{token_id}")
    assert res.status_code == 200
    assert res.json()["token"]["secret"] == secret

def test_canary_trigger_flow(client):
    res = client.post("/api/v1/canary/tokens", json={
        "name": "Trigger Test",
        "token_type": "url"
    })
    secret = res.json()["token"]["secret"]
    token_id = res.json()["token"]["token_id"]

    # Initial state
    token = client.get(f"/api/v1/canary/tokens/{token_id}").json()["token"]
    assert token["trigger_count"] == 0

    # Trigger
    res = client.get(f"/t/{secret}")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

    # State after trigger
    token = client.get(f"/api/v1/canary/tokens/{token_id}").json()["token"]
    assert token["trigger_count"] == 1
    assert token["last_source_ip"] == "testclient"

def test_invalid_trigger(client):
    res = client.get("/t/invalid_secret_here")
    assert res.status_code == 404

def test_simulated_trigger(client):
    res = client.post("/api/v1/canary/tokens", json={
        "name": "Doc Test",
        "token_type": "document"
    })
    secret = res.json()["token"]["secret"]
    token_id = res.json()["token"]["token_id"]

    res = client.post("/api/v1/canary/test", json={"secret": secret})
    assert res.status_code == 200

    token = client.get(f"/api/v1/canary/tokens/{token_id}").json()["token"]
    assert token["trigger_count"] == 1

def test_disabled_token_does_not_trigger(client):
    res = client.post("/api/v1/canary/tokens", json={
        "name": "Disabled Test",
        "token_type": "url"
    })
    secret = res.json()["token"]["secret"]
    token_id = res.json()["token"]["token_id"]

    # Disable
    res = client.put(f"/api/v1/canary/tokens/{token_id}/status", json={"status": "disabled"})
    assert res.status_code == 200

    # Try trigger
    res = client.get(f"/t/{secret}")
    assert res.status_code == 404

    token = client.get(f"/api/v1/canary/tokens/{token_id}").json()["token"]
    assert token["trigger_count"] == 0
