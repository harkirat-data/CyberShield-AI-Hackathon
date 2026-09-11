"""Unit and integration tests for CyberShield AI Geolocation & ASN Intelligence Engine."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "Ai"))
sys.path.insert(0, str(Path(__file__).parent.parent / "Ai" / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient

from intel.geo_tracker import (
    GeoIntel,
    GeoTracker,
    country_code_to_flag,
    get_geo_tracker,
)
from api_server import create_app


def test_country_code_to_flag():
    assert country_code_to_flag("DE") == "🇩🇪"
    assert country_code_to_flag("US") == "🇺🇸"
    assert country_code_to_flag("IN") == "🇮🇳"
    assert country_code_to_flag("CN") == "🇨🇳"
    assert country_code_to_flag("RU") == "🇷🇺"
    assert country_code_to_flag("") == "🌐"
    assert country_code_to_flag(None) == "🌐"
    assert country_code_to_flag("INVALID") == "🌐"


def test_is_private_ip():
    assert GeoTracker.is_private_ip("127.0.0.1") is True
    assert GeoTracker.is_private_ip("localhost") is True
    assert GeoTracker.is_private_ip("10.0.1.5") is True
    assert GeoTracker.is_private_ip("192.168.1.100") is True
    assert GeoTracker.is_private_ip("172.16.5.20") is True
    assert GeoTracker.is_private_ip("::1") is True
    assert GeoTracker.is_private_ip("0.0.0.0") is True

    # Public IPs
    assert GeoTracker.is_private_ip("8.8.8.8") is False
    assert GeoTracker.is_private_ip("1.1.1.1") is False
    assert GeoTracker.is_private_ip("185.220.101.5") is False
    assert GeoTracker.is_private_ip("194.26.29.112") is False


def test_lookup_private_ip():
    tracker = GeoTracker()
    intel = tracker.lookup("127.0.0.1")
    assert intel.is_private is True
    assert intel.asn == "AS-PRIVATE"
    assert intel.country_flag == "🛡️"
    assert "Internal" in intel.country or "Local" in intel.country


def test_lookup_preseeded_threat_actor():
    tracker = GeoTracker()
    intel = tracker.lookup("185.220.101.5")
    assert intel.country == "Germany"
    assert intel.country_code == "DE"
    assert intel.country_flag == "🇩🇪"
    assert intel.asn == "AS208323"
    assert intel.is_private is False
    assert intel.threat_score >= 80


def test_geo_caching():
    tracker = GeoTracker()
    first = tracker.lookup("194.26.29.112")
    second = tracker.lookup("194.26.29.112")
    assert first is second


def test_enrich_session():
    tracker = GeoTracker()
    session = {
        "session_id": "test_123",
        "source_ip": "218.92.0.198",
        "service": "ssh",
        "destination_port": 2222,
    }
    enriched = tracker.enrich_session(session)
    assert "geo" in enriched
    assert enriched["geo"]["country"] == "China"
    assert enriched["geo"]["country_code"] == "CN"
    assert enriched["geo"]["asn"] == "AS4134"


def test_get_tracked_attackers():
    tracker = GeoTracker()
    sessions = [
        {
            "session_id": "s1",
            "source_ip": "185.220.101.5",
            "service": "ssh",
            "destination_port": 2222,
            "risk_score": 85,
            "interactions": 4,
            "started_at": "2026-09-11T10:00:00Z",
            "contained": False,
        },
        {
            "session_id": "s2",
            "source_ip": "185.220.101.5",
            "service": "http",
            "destination_port": 8088,
            "risk_score": 90,
            "interactions": 8,
            "started_at": "2026-09-11T10:05:00Z",
            "contained": True,
        },
        {
            "session_id": "s3",
            "source_ip": "177.54.144.12",
            "service": "mysql",
            "destination_port": 33060,
            "risk_score": 70,
            "interactions": 2,
            "started_at": "2026-09-11T10:02:00Z",
            "contained": False,
        },
    ]
    attackers = tracker.get_tracked_attackers(sessions)
    assert len(attackers) == 2
    # First should be the highest risk score (90)
    assert attackers[0]["ip"] == "185.220.101.5"
    assert attackers[0]["session_count"] == 2
    assert attackers[0]["actions_count"] == 12
    assert 2222 in attackers[0]["probed_ports"]
    assert 8088 in attackers[0]["probed_ports"]
    assert attackers[0]["contained"] is True
    assert attackers[0]["geo"]["country"] == "Germany"

    assert attackers[1]["ip"] == "177.54.144.12"
    assert attackers[1]["geo"]["country"] == "Brazil"


@pytest.fixture
def client():
    app = create_app(use_rag=False, use_llm=False)
    with TestClient(app) as test_client:
        yield test_client


def test_api_intel_endpoints(client):
    # Test GET /api/v1/intel/ip/{ip}
    res = client.get("/api/v1/intel/ip/185.220.101.5")
    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True
    assert data["ip"] == "185.220.101.5"
    assert data["geo"]["country"] == "Germany"
    assert data["geo"]["asn"] == "AS208323"

    # Test POST /api/v1/intel/simulate-attack
    sim_res = client.post("/api/v1/intel/simulate-attack")
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["ok"] is True
    assert "session" in sim_data
    assert "actor" in sim_data

    # Test GET /api/v1/intel/attackers
    atk_res = client.get("/api/v1/intel/attackers")
    assert atk_res.status_code == 200
    atk_data = atk_res.json()
    assert atk_data["count"] >= 1
    assert len(atk_data["attackers"]) >= 1
