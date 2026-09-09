"""
schema.py - Shared dataclasses for AI layer
"""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime
import json


@dataclass
class Event:
    """Normalized security event."""
    event_id: str
    timestamp: str
    host: str
    source: str
    event_type: str
    severity: str
    actor: Dict = field(default_factory=dict)
    target: Dict = field(default_factory=dict)
    details: Dict = field(default_factory=dict)
    raw: str = ""

    @classmethod
    def from_dict(cls, d: Dict) -> "Event":
        return cls(
            event_id=d.get("event_id", ""),
            timestamp=d.get("timestamp", ""),
            host=d.get("host", "unknown"),
            source=d.get("source", "unknown"),
            event_type=d.get("event_type", "unknown"),
            severity=d.get("severity", "info"),
            actor=d.get("actor", {}) or {},
            target=d.get("target", {}) or {},
            details=d.get("details", {}) or {},
            raw=d.get("raw", ""),
        )

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ThreatIntel:
    ip_reputation: str = "unknown"          # malicious | suspicious | clean | unknown
    is_malicious: bool = False
    abuse_score: Optional[int] = None        # 0-100 from AbuseIPDB-style scoring
    country: Optional[str] = None
    asn: Optional[str] = None
    campaigns: List[str] = field(default_factory=list)
    related_iocs: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CorrelationResult:
    related_events: List[Event] = field(default_factory=list)
    time_window_seconds: int = 0
    correlation_reasons: List[str] = field(default_factory=list)
    primary_indicator: str = ""              # the IP/user/host that ties them together

    def to_dict(self) -> Dict:
        return {
            "related_events": [e.to_dict() for e in self.related_events],
            "time_window_seconds": self.time_window_seconds,
            "correlation_reasons": self.correlation_reasons,
            "primary_indicator": self.primary_indicator,
            "count": len(self.related_events),
        }


@dataclass
class MitreMapping:
    techniques: List[str] = field(default_factory=list)  # ["T1110", "T1078"]
    tactics: List[str] = field(default_factory=list)     # ["Initial Access", "Credential Access"]
    confidence: float = 0.0
    source: str = ""                       # "rules" | "rag" | "llm" | "hybrid"
    rationale: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class RiskScore:
    score: int = 0                         # 0-100
    level: str = "low"                     # critical | high | medium | low | info
    factors: List[Dict] = field(default_factory=list)  # [{factor: "brute_force", points: 40}, ...]
    confidence: float = 0.0
    rationale: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Investigation:
    """Full AI investigation result."""
    event: Event
    threat_intel: ThreatIntel
    correlation: CorrelationResult
    mitre: MitreMapping
    risk: RiskScore
    rag_chunks: List[Dict] = field(default_factory=list)
    llm_analysis: Optional[Dict] = None
    final_severity: str = "info"
    final_remediation: Dict = field(default_factory=dict)
    latency_ms: int = 0
    pipeline_version: str = "1.0"
    model_version: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return {
            "event": self.event.to_dict(),
            "threat_intel": self.threat_intel.to_dict(),
            "correlation": self.correlation.to_dict(),
            "mitre": self.mitre.to_dict(),
            "risk": self.risk.to_dict(),
            "rag_chunks": self.rag_chunks,
            "llm_analysis": self.llm_analysis,
            "final_severity": self.final_severity,
            "final_remediation": self.final_remediation,
            "latency_ms": self.latency_ms,
            "pipeline_version": self.pipeline_version,
            "model_version": self.model_version,
            "created_at": self.created_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)
