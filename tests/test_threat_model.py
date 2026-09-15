"""Unit tests for VALENS STRIDE threat classification and severity calculations.
"""

import unittest


class TestThreatModel(unittest.TestCase):
    """Test suite verifying threat severity scoring and classification rules."""

    def calculate_severity(self, incident):
        """Utility method mimicking the core severity evaluation logic."""
        if incident.get("canary_tripped") or incident.get("root_compromise"):
            return "SEV-1"
        elif incident.get("sqli_detected") or incident.get("probe_count", 0) > 10:
            return "SEV-2"
        elif incident.get("decoy_probe"):
            return "SEV-3"
        return "SEV-4"

    def test_canary_tripwire_triggers_sev1(self):
        incident = {"canary_tripped": True, "source_ip": "198.51.100.22"}
        sev = self.calculate_severity(incident)
        self.assertEqual(sev, "SEV-1")

    def test_sql_injection_triggers_sev2(self):
        incident = {"sqli_detected": True, "payload": "UNION SELECT 1,2,3"}
        sev = self.calculate_severity(incident)
        self.assertEqual(sev, "SEV-2")

    def test_reconnaissance_probe_triggers_sev3(self):
        incident = {"decoy_probe": True, "target_port": 2222}
        sev = self.calculate_severity(incident)
        self.assertEqual(sev, "SEV-3")

    def test_benign_traffic_triggers_sev4(self):
        incident = {"probe_count": 1}
        sev = self.calculate_severity(incident)
        self.assertEqual(sev, "SEV-4")


if __name__ == "__main__":
    unittest.main()
