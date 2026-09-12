"""
manager.py - Core logic for Canary Token Management
"""

import uuid
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

class CanaryManager:
    def __init__(self, store):
        """
        Initialize the CanaryManager with a reference to the TelemetryStore.
        """
        self.store = store

    def create_token(self, name: str, token_type: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate and persist a new canary token.
        
        token_type must be one of: 'url', 'credential', 'document'.
        """
        if token_type not in ("url", "credential", "document"):
            raise ValueError(f"Invalid token type: {token_type}")

        token_id = f"canary_{uuid.uuid4().hex[:12]}"
        
        if token_type == "url":
            secret = secrets.token_urlsafe(16)
        elif token_type == "credential":
            # Generate a fake username or access key ID
            secret = f"AKIA{secrets.token_hex(8).upper()}"
        else: # document
            # Generate a hidden embedded identifier
            secret = f"doc_{secrets.token_hex(12)}"

        token_data = {
            "token_id": token_id,
            "secret": secret,
            "token_type": token_type,
            "name": name,
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "trigger_count": 0,
            "first_triggered_at": None,
            "last_triggered_at": None,
            "last_source_ip": None,
            "metadata_json": metadata or {}
        }
        
        self.store.create_canary_token(token_data)
        return token_data

    def list_tokens(self) -> List[Dict[str, Any]]:
        return self.store.list_canary_tokens()

    def get_token_by_id(self, token_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get_canary_token_by_id(token_id)

    def get_token_by_secret(self, secret: str) -> Optional[Dict[str, Any]]:
        return self.store.get_canary_token(secret)

    def update_status(self, token_id: str, status: str) -> bool:
        if status not in ("active", "disabled"):
            raise ValueError(f"Invalid status: {status}")
        return self.store.update_canary_token_status(token_id, status)

    def record_trigger(self, secret: str, source_ip: str, trigger_metadata: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Record a token trigger if the token exists and is active.
        Returns the updated token data, or None if invalid/disabled.
        """
        token = self.store.get_canary_token(secret)
        if not token or token["status"] != "active":
            return None

        # Update the token in the store
        updated_token = self.store.record_canary_trigger(secret, source_ip, trigger_metadata)
        return updated_token
