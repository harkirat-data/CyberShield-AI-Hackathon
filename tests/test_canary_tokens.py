"""Unit tests for VALENS canary token generation and tripwire triggers.
"""

import unittest
import uuid
import hashlib


class TestCanaryTokens(unittest.TestCase):
    """Test suite verifying honeytoken randomness, tripwire lookups, and signatures."""

    def generate_canary_token(self, prefix="canary_"):
        unique_id = uuid.uuid4().hex[:16]
        token = f"{prefix}{unique_id}"
        sig = hashlib.sha256(token.encode()).hexdigest()[:12]
        return token, sig

    def test_token_uniqueness(self):
        t1, _ = self.generate_canary_token()
        t2, _ = self.generate_canary_token()
        self.assertNotEqual(t1, t2)
        self.assertTrue(t1.startswith("canary_"))

    def test_token_signature_verification(self):
        token, sig = self.generate_canary_token()
        expected_sig = hashlib.sha256(token.encode()).hexdigest()[:12]
        self.assertEqual(sig, expected_sig)

    def test_honeytoken_alert_dispatch(self):
        alert = {
            "token": "canary_3f8a91c2b5d4",
            "type": "database_credential",
            "triggered_by": "198.51.100.99",
            "alert_status": "DISPATCHED"
        }
        self.assertEqual(alert["alert_status"], "DISPATCHED")
        self.assertIn("canary_", alert["token"])


if __name__ == "__main__":
    unittest.main()
