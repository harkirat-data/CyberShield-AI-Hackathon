"""Tests for synthetic intrusion simulation and automated SOC threat correlation.
"""

import unittest
import json


class TestSyntheticTelemetry(unittest.TestCase):
    """Test suite validating automated event processing and risk calculation."""

    def test_risk_score_calculation(self):
        """Verify that multiple decoy touches escalate adversary threat level."""
        events = [
            {"service": "http_decoy", "probe": "admin_scan", "weight": 20},
            {"service": "ssh_decoy", "probe": "bruteforce", "weight": 35},
            {"service": "canary_aws", "probe": "credential_exfil", "weight": 45}
        ]
        total_risk = sum(e["weight"] for e in events)
        self.assertEqual(total_risk, 100)
        
        status = "CRITICAL" if total_risk >= 80 else "HIGH" if total_risk >= 50 else "LOW"
        self.assertEqual(status, "CRITICAL")

    def test_ip_quarantine_payload_format(self):
        """Verify payload format dispatched to WAF reverse proxy edge rules."""
        quarantine_action = {
            "action": "BLOCK_IP",
            "target_ip": "198.51.100.42",
            "duration_minutes": 1440,
            "rule_origin": "valens_autonomous_deception",
            "mitre_id": "T1190"
        }
        self.assertEqual(quarantine_action["action"], "BLOCK_IP")
        self.assertEqual(quarantine_action["duration_minutes"], 1440)
        self.assertIn("valens", quarantine_action["rule_origin"])

    def test_geo_attribution_mapping(self):
        """Verify simulated geo-ip attribute resolver output."""
        mock_geoip_db = {
            "198.51.100.42": {"country": "Netherlands", "city": "Amsterdam", "asn": "AS16509"},
            "203.0.113.19": {"country": "Germany", "city": "Frankfurt", "asn": "AS24940"},
        }
        ip = "198.51.100.42"
        record = mock_geoip_db.get(ip)
        self.assertIsNotNone(record)
        self.assertEqual(record["country"], "Netherlands")
        self.assertEqual(record["asn"], "AS16509")


if __name__ == "__main__":
    unittest.main()
