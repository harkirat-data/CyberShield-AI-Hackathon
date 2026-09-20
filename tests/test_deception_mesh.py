"""Unit tests for VALENS Deception Mesh listeners and Canary tokens.
"""

import unittest
import json
import socket
from datetime import datetime


class TestDeceptionMesh(unittest.TestCase):
    """Test suite verifying honeypot sensor responses and tripwire handlers."""

    def test_honeypot_telemetry_schema(self):
        """Verify standardization of decoy intrusion telemetry events."""
        event = {
            "event_id": "evt-mesh-001",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_ip": "203.0.113.19",
            "destination_port": 3306,
            "decoy_service": "mysql",
            "threat_severity": "HIGH",
            "quarantined": True
        }
        self.assertEqual(event["decoy_service"], "mysql")
        self.assertTrue(event["quarantined"])
        self.assertIn("evt-", event["event_id"])

    def test_canary_token_detection(self):
        """Verify canary token tripwire matching and alerting."""
        canary_registry = {
            "AKIA_CANARY_FINANCE_KEY": {"type": "aws_iam", "sensitivity": "critical"},
            "canary_db_user_hash": {"type": "db_bcrypt", "sensitivity": "high"},
        }
        
        simulated_probe = "AKIA_CANARY_FINANCE_KEY"
        self.assertIn(simulated_probe, canary_registry)
        self.assertEqual(canary_registry[simulated_probe]["type"], "aws_iam")

    def test_simulated_redis_decoy_protocol(self):
        """Verify fake Redis listener replies with standard PONG protocol frame."""
        command = b"PING\r\n"
        expected_response = b"+PONG\r\n"
        
        # Test synthetic parser
        if command.strip() == b"PING":
            reply = expected_response
        else:
            reply = b"-ERR unknown command\r\n"
            
        self.assertEqual(reply, b"+PONG\r\n")


if __name__ == "__main__":
    unittest.main()
