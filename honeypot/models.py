"""Data models shared by the honeypot runtime and telemetry store."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def content_digest(content: bytes | str) -> str:
    data = content.encode("utf-8", errors="replace") if isinstance(content, str) else content
    return hashlib.sha256(data).hexdigest()


@dataclass
class DecoySession:
    session_id: str
    source_ip: str
    source_port: int
    destination_port: int
    service: str
    protocol: str
    persona: str
    started_at: str = field(default_factory=utc_now)
    ended_at: Optional[str] = None
    status: str = "active"
    bytes_in: int = 0
    bytes_out: int = 0
    interactions: int = 0
    risk_score: int = 0
    risk_level: str = "info"
    intent: str = "Reconnaissance"
    intent_confidence: float = 0.35
    client_fingerprint: str = "unknown"
    username: Optional[str] = None
    contained: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TelemetryEvent:
    session_id: str
    event_type: str
    severity: str
    direction: str
    content: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    byte_count: int = 0
    latency_ms: Optional[int] = None
    event_id: str = field(default_factory=lambda: new_id("evt"))
    timestamp: str = field(default_factory=utc_now)
    sha256: str = ""

    def __post_init__(self) -> None:
        if not self.sha256:
            self.sha256 = content_digest(self.content)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["metadata_json"] = json.dumps(self.metadata, sort_keys=True)
        return data
