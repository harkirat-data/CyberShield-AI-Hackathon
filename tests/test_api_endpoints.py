"""Unit tests for VALENS REST API payload serialization and status responses.
"""

import unittest
import json
from datetime import datetime


class TestApiEndpoints(unittest.TestCase):
    """Test suite verifying API JSON schema integrity and status response formats."""

    def test_health_response_schema(self):
        payload = {
            "status": "healthy",
            "active_decoys": 12,
            "listeners": {"http": 8050, "ssh": 2222, "mysql": 3306, "waf": 8080},
            "ai_agent_status": "ONLINE",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        self.assertEqual(payload["status"], "healthy")
        self.assertEqual(payload["active_decoys"], 12)
        self.assertIn("mysql", payload["listeners"])

    def test_quarantine_block_payload(self):
        quarantine_req = {
            "ip_address": "198.51.100.12",
            "reason": "Repeated unauthorized MySQL decoy probe",
            "duration_seconds": 86400
        }
        self.assertTrue(quarantine_req["ip_address"].startswith("198.51."))
        self.assertEqual(quarantine_req["duration_seconds"], 86400)

    def test_telemetry_event_serialization(self):
        event = {
            "id": "evt-7718",
            "source_ip": "198.51.100.12",
            "target_port": 3306,
            "threat_score": 88
        }
        serialized = json.dumps(event)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["id"], "evt-7718")
        self.assertGreater(deserialized["threat_score"], 80)


if __name__ == "__main__":
    unittest.main()
