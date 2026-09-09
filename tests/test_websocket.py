import asyncio
import pytest
from fastapi.testclient import TestClient
import sys
from pathlib import Path

# Add Ai/backend to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "Ai" / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from api_server import create_app

@pytest.fixture
def test_client():
    app = create_app(use_rag=False, use_llm=False)
    with TestClient(app) as client:
        yield client

def test_websocket_connection(test_client):
    with test_client.websocket_connect("/api/v1/ws/dashboard") as websocket:
        data = websocket.receive_json()
        assert data["type"] == "state_update"
        assert "status" in data
        assert "metrics" in data
        assert "sessions" in data
        assert "canaries" in data
