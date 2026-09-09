import json
import urllib.request
from unittest.mock import patch, MagicMock

import pytest

import sys
from pathlib import Path

# Mock win32evtlog and win32con
sys.modules['win32evtlog'] = MagicMock()
sys.modules['win32con'] = MagicMock()

# Add collector/win to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "collector" / "win"))

import collector
import firewall_collector


def test_collector_normalize_event():
    raw_event = {
        "event_id": 4624,
        "event_type": "LOGON_SUCCESS",
        "user": "Administrator",
        "source_ip": "192.168.1.100",
        "command": "cmd.exe",
        "message": "Successful logon."
    }
    
    normalized = collector._normalize_event(raw_event, risk_level="HIGH")
    
    assert normalized["event_type"] == "LOGON_SUCCESS"
    assert normalized["severity"] == "high"
    assert normalized["actor"]["user"] == "Administrator"
    assert normalized["actor"]["source_ip"] == "192.168.1.100"
    assert normalized["details"]["command"] == "cmd.exe"
    assert normalized["source"] == "win_auth"


def test_firewall_collector_normalize_event():
    raw_event = {
        "event_id": 5157,
        "event_type": "FIREWALL_BLOCKED",
        "source_ip": "10.0.0.5",
        "dest_port": 3389,
        "action": "BLOCK",
        "message": "Connection blocked by Windows Firewall."
    }
    
    normalized = firewall_collector._normalize_event(raw_event, risk_level="MEDIUM")
    
    assert normalized["event_type"] == "FIREWALL_BLOCKED"
    assert normalized["severity"] == "medium"
    assert normalized["actor"]["source_ip"] == "10.0.0.5"
    assert normalized["details"]["dest_port"] == 3389
    assert normalized["source"] == "win_system"


@patch("urllib.request.urlopen")
def test_post_to_api_success(mock_urlopen):
    # Mock successful API response
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b'{"ok": true}'
    mock_urlopen.return_value.__enter__.return_value = mock_response

    raw_event = {"event_type": "TEST", "message": "Test event."}
    
    # Run post_to_api
    collector.post_to_api(raw_event, risk_level="LOW", brute_force_detected=True)
    
    # Verify request was made
    mock_urlopen.assert_called_once()
    request_obj = mock_urlopen.call_args[0][0]
    assert request_obj.method == "POST"
    
    # Parse payload sent
    payload = json.loads(request_obj.data.decode("utf-8"))
    assert payload["brute_force_detected"] is True
    assert payload["event"]["event_type"] == "TEST"
    assert payload["event"]["severity"] == "low"
